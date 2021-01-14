#include <stdio.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include <libssh/misc.h>
#include <libssh/poll.h>
#include <libssh/bind.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <stddef.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/timers.h"
#include "esp_log.h"
#include "sshd.h"
#include "sshd_main.h"
static const char *TAG = "sshd_task";

#define REMOTE_SOFTWARE_VERSION "Hiperion-SSH"
#define IS_TIMEOUT_SEC 30

TimerHandle_t is_timerHndl;
ssh_session is_local_session;
ssh_channel is_local_channel;

static void sendtochannel(struct interactive_session *is, char *c, int len);

static void is_timeout_callback(xTimerHandle pxTimer) {
    ESP_LOGI(TAG, "interactive session timeout! disconnecting...");
    ssh_disconnect(is_local_session);
    if (pxTimer != NULL)
        xTimerDelete(pxTimer, 0);
}

static int start_is_timeout(ssh_session session) {
    is_local_session = session;

    is_timerHndl = xTimerCreate(
            "timerException",
            pdMS_TO_TICKS(IS_TIMEOUT_SEC)*1000,
            pdTRUE,
            (void*) 0,
            is_timeout_callback
            );

    if (xTimerStart(is_timerHndl, 0) != pdPASS) {
        ESP_LOGI(TAG, "ERROR STARTING IS_TIMEOUT TIMER");
        return 1;
    }
    return 0;
}

static void is_exit(void) {
    if (is_local_session != NULL && is_local_channel != NULL) {
        ssh_channel_send_eof(is_local_channel);
        ssh_channel_close(is_local_channel);
        //ssh_channel_free(is_local_channel);
    }
    if (is_timerHndl != NULL)
        xTimerDelete(is_timerHndl, 0);
}

static void is_reset_timeout(void) {
    xTimerReset(is_timerHndl, 0);
}

static int import_embedded_host_key(ssh_bind sshbind, const char *base64_key) {
    size_t ptralign = sizeof(void*);
    char buf[2048];
    char *p, *q, *e;
    ssh_key *target;
    int error;
    ssh_key probe;
    enum ssh_keytypes_e type;

    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, "");
    memcpy(buf, sshbind, sizeof(buf));
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, "0123456789ABCDEF0123456789ABCDEF");
    p = buf;
    e = p + sizeof(buf);
    q = (char*) sshbind;
    while (p < e) {
        if (memcmp(p, q, ptralign) != 0)
            break;
        p += ptralign;
        q += ptralign;
    }
    if (p >= e)
        return SSH_ERROR;
    probe = ssh_key_new();
    if (probe == NULL)
        return SSH_ERROR;
    error = ssh_pki_import_privkey_base64(base64_key, NULL, NULL, NULL, &probe);
    type = ssh_key_type(probe);
    ssh_key_free(probe);
    if (error != SSH_OK)
        return error;
    switch (type) {
    case SSH_KEYTYPE_ECDSA_P256:
    case SSH_KEYTYPE_ECDSA_P521:
        target = (ssh_key*) ((uintptr_t) sshbind + (p - buf) - 4 * ptralign);
        break;
    case SSH_KEYTYPE_DSS:
        target = (ssh_key*) ((uintptr_t) sshbind + (p - buf) - 3 * ptralign);
        break;
    case SSH_KEYTYPE_RSA:
        target = (ssh_key*) ((uintptr_t) sshbind + (p - buf) - 2 * ptralign);
        break;
    case SSH_KEYTYPE_ED25519:
        target = (ssh_key*) ((uintptr_t) sshbind + (p - buf) - 1 * ptralign);
        break;
    default:
        return SSH_ERROR;
    }
    error = ssh_pki_import_privkey_base64(base64_key, NULL, NULL, NULL, target);
    return error;
}

static struct client_ctx* lookup_client(struct server_ctx *sc, ssh_session session) {
    struct client_ctx *ret;

    SLIST_FOREACH(ret, &sc->sc_client_head, cc_client_list)
    {
        if (ret->cc_session == session)
            return ret;
    }

    return NULL;
}

static int auth_password(ssh_session session, const char *user, const char *password,
        void *userdata) {
    struct server_ctx *sc = (struct server_ctx*) userdata;
    struct client_ctx *cc;
    struct ssh_user *su;

    cc = lookup_client(sc, session);
    if (cc == NULL)
        return SSH_AUTH_DENIED;
    if (cc->cc_didauth)
        return SSH_AUTH_DENIED;
    su = sc->sc_lookup_user(sc, user);
    if (su == NULL)
        return SSH_AUTH_DENIED;
    if (strcmp(password, su->su_password) != 0)
        return SSH_AUTH_DENIED;
    cc->cc_didauth = true;

    return SSH_AUTH_SUCCESS;
}

static int auth_publickey(ssh_session session, const char *user, struct ssh_key_struct *pubkey,
        char signature_state, void *userdata) {
    struct server_ctx *sc = (struct server_ctx*) userdata;
    struct client_ctx *cc;
    struct ssh_user *su;
    ssh_key key;
    int error;

    cc = lookup_client(sc, session);
    if (cc == NULL)
        return SSH_AUTH_DENIED;
    if (signature_state == SSH_PUBLICKEY_STATE_NONE)
        return SSH_AUTH_SUCCESS;
    if (signature_state != SSH_PUBLICKEY_STATE_VALID)
        return SSH_AUTH_DENIED;
    if (cc->cc_didauth)
        return SSH_AUTH_DENIED;
    su = sc->sc_lookup_user(sc, user);
    if (su == NULL)
        return SSH_AUTH_DENIED;
    if (su->su_base64_key == NULL)
        return SSH_AUTH_DENIED;
    if (ssh_pki_import_pubkey_base64(su->su_base64_key, su->su_keytype, &key) != SSH_OK)
        return SSH_AUTH_DENIED;
    error = ssh_key_cmp(key, pubkey, SSH_KEY_CMP_PUBLIC);
    ssh_key_free(key);
    if (error != SSH_OK)
        return SSH_AUTH_DENIED;
    cc->cc_didauth = true;

    return SSH_AUTH_SUCCESS;
}

static int data_function(ssh_session session, ssh_channel channel, void *data, uint32_t len,
        int is_stderr, void *userdata) {
    struct client_ctx *cc = (struct client_ctx*) userdata;
    int i;
    char c;
    for (i = 0; i < len; i++) {
        c = ((char*) data)[i];
        if (c == 0x4) /* ^D */{
            ssh_channel_send_eof(channel);
            ssh_channel_close(channel);
            return len;
        }
        cc->cc_is.is_handle_char_from_remote(&cc->cc_is, c);
    }
    return len;
}

static int pty_request(ssh_session session, ssh_channel channel, const char *term, int cols,
        int rows, int py, int px, void *userdata) {
    struct client_ctx *cc = (struct client_ctx*) userdata;

    if (cc->cc_didpty)
        return SSH_ERROR;
    cc->cc_cols = cols;
    cc->cc_rows = rows;
    cc->cc_px = px;
    cc->cc_py = py;
    strlcpy(cc->cc_term, term, sizeof(cc->cc_term));
    cc->cc_didpty = true;

    return SSH_OK;
}

static int shell_request(ssh_session session, ssh_channel channel, void *userdata) {
    struct client_ctx *cc = (struct client_ctx*) userdata;
    if (cc->cc_didshell)
        return SSH_ERROR;
    cc->cc_didshell = true;
    cc->cc_is.is_handle_char_from_local = sendtochannel;
    cc->cc_is.is_exit = is_exit;
    cc->cc_is.is_reset_timeout = is_reset_timeout;
    cc->cc_begin_interactive_session(&cc->cc_is);
    start_is_timeout(session);
    return SSH_OK;
}

static int exec_request(ssh_session session, ssh_channel channel, const char *command,
        void *userdata) {
    struct client_ctx *cc = (struct client_ctx*) userdata;
    if (cc->cc_didshell)
        return SSH_ERROR;

    cc->cc_is.is_handle_char_from_local = sendtochannel;
    minicli_handle_command(&cc->cc_is, command);
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    return SSH_OK;
}

static int pty_resize(ssh_session session, ssh_channel channel, int cols, int rows, int py, int px,
        void *userdata) {
    struct client_ctx *cc = (struct client_ctx*) userdata;

    cc->cc_cols = cols;
    cc->cc_rows = rows;
    cc->cc_px = px;
    cc->cc_py = py;

    return SSH_OK;
}

static ssh_channel channel_open(ssh_session session, void *userdata) {
    struct server_ctx *sc = (struct server_ctx*) userdata;
    struct client_ctx *cc;

    cc = lookup_client(sc, session);
    if (cc == NULL)
        return NULL;
    if (cc->cc_didchannel)
        return NULL;
    cc->channel_cb = (struct ssh_channel_callbacks_struct ) {
                    .channel_data_function = data_function,
                    .channel_exec_request_function = exec_request,
                    .channel_pty_request_function = pty_request,
                    .channel_pty_window_change_function = pty_resize,
                    .channel_shell_request_function = shell_request,
                    .userdata = cc
    };
    cc->cc_channel = ssh_channel_new(session);
    ssh_callbacks_init(&cc->channel_cb);
    ssh_set_channel_callbacks(cc->cc_channel, &cc->channel_cb);
    cc->cc_didchannel = true;

    is_local_channel = cc->cc_channel;

    return cc->cc_channel;
}

static void incoming_connection(ssh_bind sshbind, void *userdata) {
    struct server_ctx *sc = (struct server_ctx*) userdata;
    long t = 0;
    struct client_ctx *cc = (struct client_ctx *) SSH_CALLOC(1, sizeof(struct client_ctx));

    //cc_local = cc;
    cc->cc_session = ssh_new();

    if (ssh_bind_accept(sshbind, cc->cc_session) == SSH_ERROR) {
        goto cleanup;
    }
    cc->cc_begin_interactive_session = sc->sc_begin_interactive_session;
    ssh_set_callbacks(cc->cc_session, &sc->sc_generic_cb);
    ssh_set_server_callbacks(cc->cc_session, &sc->sc_server_cb);
    ssh_set_auth_methods(cc->cc_session, sc->sc_auth_methods);
    ssh_set_blocking(cc->cc_session, 0);
    (void) ssh_options_set(cc->cc_session, SSH_OPTIONS_TIMEOUT, &t);
    (void) ssh_options_set(cc->cc_session, SSH_OPTIONS_TIMEOUT_USEC, &t);

    /////////////////////////////////////
    // availables ciphers on mbedcrypt //
    //                                 //
    //     aes256-gcm@openssh.com      //
    //     aes128-gcm@openssh.com      //
    //     aes256-ctr                  //
    //     aes192-ctr                  //
    //     aes128-ctr                  //
    //     aes256-cbc                  //
    //     aes192-cbc                  //
    //     aes128-cbc                  //
    //     3des-cbc                    //
    /////////////////////////////////////
    (void) ssh_options_set(cc->cc_session, SSH_OPTIONS_CIPHERS_C_S, "aes128-ctr, aes192-ctr, aes256-ctr,aes128-cbc");
    (void) ssh_options_set(cc->cc_session, SSH_OPTIONS_CIPHERS_S_C, "aes128-ctr, aes192-ctr, aes256-ctr,aes128-cbc");

    ////////////////////////////////////////
    // availables MAC hashes on mbedcrypt //
    //                                    //
    //     hmac-sha2-256-etm@openssh.com  //
    //     hmac-sha2-512-etm@openssh.com  //
    //     hmac-sha1-etm@openssh.com      //
    //     hmac-sha2-512                  //
    //     hmac-sha2-256                  //
    //     hmac-sha1                      //
    ////////////////////////////////////////
    /*
    (void) ssh_options_set(cc->cc_session, SSH_OPTIONS_HMAC_C_S, "");
    (void) ssh_options_set(cc->cc_session, SSH_OPTIONS_HMAC_S_C, "");
    */

    (void) ssh_options_set(cc->cc_session, SSH_OPTIONS_KEY_EXCHANGE,
            "curve25519-sha256@libssh.org, curve25519-sha256, ecdh-sha2-nistp256, diffie-hellman-group-exchange-sha256, diffie-hellman-group14-sha1, diffie-hellman-group1-sha1, diffie-hellman-group18-sha512, diffie-hellman-group16-sha512");

    (void) ssh_options_set(cc->cc_session, SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES,
            "ecdh-sha2-nistp256, ssh-rsa, rsa-sha2-256, ssh-dss");

    if (ssh_handle_key_exchange(cc->cc_session) == SSH_ERROR) {
        ssh_disconnect(cc->cc_session);
        goto cleanup;
    }

    SLIST_INSERT_HEAD(&sc->sc_client_head, cc, cc_client_list);
    ssh_event_add_session(sc->sc_sshevent, cc->cc_session);
    ESP_LOGI(TAG, "incoming connection");
    return;
    cleanup: ssh_free(cc->cc_session);
    SSH_FREE(cc);
    ESP_LOGI(TAG, "EXIT incoming_connection");
}

static void dead_eater(struct server_ctx *sc) {
    struct client_ctx *cc;
    struct client_ctx *cc_removed = NULL;
    int status;

    SLIST_FOREACH(cc, &sc->sc_client_head, cc_client_list)
    {
        if (cc_removed) {
        	SSH_FREE(cc_removed);
            cc_removed = NULL;
        }
        status = ssh_get_status(cc->cc_session);

        if (status & (SSH_CLOSED | SSH_CLOSED_ERROR)) {
            if (cc->cc_didchannel) {
                ssh_channel_free(cc->cc_channel);
            }
            ssh_event_remove_session(sc->sc_sshevent, cc->cc_session);
            ssh_free(cc->cc_session);
            SLIST_REMOVE(&sc->sc_client_head, cc, client_ctx, cc_client_list);
            cc_removed = cc;
        }
    }
    if (cc_removed) {
    	SSH_FREE(cc_removed);
        cc_removed = NULL;
        if (is_timerHndl != NULL)
            xTimerDelete(is_timerHndl, 0);
    }
}

static int create_new_server(struct server_ctx *sc) {
    SLIST_INIT(&sc->sc_client_head);
    sc->sc_server_cb = (struct ssh_server_callbacks_struct ) {
        .userdata = sc,
        .auth_password_function = auth_password,
        .auth_pubkey_function = auth_publickey,
        .channel_open_request_session_function = channel_open
    };
    sc->sc_generic_cb = (struct ssh_callbacks_struct ) {
        .userdata = sc
    };

    sc->sc_bind_cb = (struct ssh_bind_callbacks_struct ) {
        .incoming_connection = incoming_connection
    };

    ssh_callbacks_init(&sc->sc_server_cb);
    ssh_callbacks_init(&sc->sc_generic_cb);
    ssh_callbacks_init(&sc->sc_bind_cb);

    ESP_LOGI(TAG, "ssh_bind_new");
    sc->sc_sshbind = ssh_bind_new();
    if (sc->sc_sshbind == NULL) {
        return SSH_ERROR;
    }
    ssh_bind_options_set(sc->sc_sshbind, SSH_BIND_OPTIONS_BANNER, REMOTE_SOFTWARE_VERSION);
    ssh_bind_options_set(sc->sc_sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, "1");
    ssh_bind_set_callbacks(sc->sc_sshbind, &sc->sc_bind_cb, sc);
    import_embedded_host_key(sc->sc_sshbind, sc->sc_host_key);
    ssh_bind_options_set(sc->sc_sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, "22");
    ssh_bind_options_set(sc->sc_sshbind, SSH_BIND_OPTIONS_BINDADDR, "0.0.0.0");
    if (ssh_bind_listen(sc->sc_sshbind) < 0) {
        ssh_bind_free(sc->sc_sshbind);
        return SSH_ERROR;
    }
    ssh_bind_set_blocking(sc->sc_sshbind, 0);
    ssh_event_add_poll(sc->sc_sshevent, ssh_bind_get_poll(sc->sc_sshbind));

    return SSH_OK;
}

static void terminate_server(struct server_ctx *sc) {
    struct client_ctx *cc;

    ssh_event_remove_poll(sc->sc_sshevent, ssh_bind_get_poll(sc->sc_sshbind));
    close(ssh_bind_get_fd(sc->sc_sshbind));
    SLIST_FOREACH(cc, &sc->sc_client_head, cc_client_list)
    {
        ssh_silent_disconnect(cc->cc_session);
    }
    while (!SLIST_EMPTY(&sc->sc_client_head)) {
        (void) ssh_event_dopoll(sc->sc_sshevent, -1);
        dead_eater(sc);
    }
    ssh_bind_free(sc->sc_sshbind);
    SSH_FREE(sc);
}

int sshd_main(struct server_ctx *sc) {
    ESP_LOGI(TAG, "sshd_main");
    ssh_event event;

    if (ssh_init() < 0) {
        return SSH_ERROR;
    }

    event = ssh_event_new();
    if (!event)
        return SSH_ERROR;
    sc->sc_sshevent = event;

    if (create_new_server(sc) != SSH_OK)
        return SSH_ERROR;

    while (true) {
        ssh_event_dopoll(sc->sc_sshevent, 500);
        dead_eater(sc);
    }

    terminate_server(sc);
    ssh_event_free(event);
    ssh_finalize();
    ESP_LOGI(TAG, "END sshd_main");

    return SSH_OK;
}

static void sendtochannel(struct interactive_session *is, char *c, int len) {
	struct client_ctx *cc = (struct client_ctx*) ((uintptr_t) is
	            - offsetof(struct client_ctx, cc_is));
		ssh_channel_write(cc->cc_channel, c, len);
}
