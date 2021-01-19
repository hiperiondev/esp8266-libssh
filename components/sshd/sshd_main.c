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
#define PASS_TRY 3
#define PASS_TIMEOUT_SEC 30

TimerHandle_t is_timerHndl;
ssh_channel is_local_channel;
ssh_session is_local_session;
uint8_t pass_try;
bool kill_sess_chan;

static void sendtochannel(struct interactive_session *is, char *c, int len);

static void stop_is_timeout(void) {
    ESP_LOGI(TAG, "is timer stop");
    if (is_timerHndl != NULL)
        xTimerStop(is_timerHndl, 0);
}

static void start_is_timeout(void) {
    ESP_LOGI(TAG, "is timer start");
    if (is_timerHndl != NULL) {
        xTimerReset(is_timerHndl, 0);
        xTimerStart(is_timerHndl, 0);
    }
}

static void is_timeout_callback(xTimerHandle pxTimer) {
    ESP_LOGI(TAG, "is timeout. disconnecting...");
    if (kill_sess_chan) {
        ESP_LOGI(TAG, "close channel");
        if (is_local_channel != NULL) {
            ssh_channel_send_eof(is_local_channel);
            ssh_channel_close(is_local_channel);
        }
    } else {
        ESP_LOGI(TAG, "close session");
        if (is_local_session != NULL) {
            ssh_disconnect(is_local_session);
        }
    }
    stop_is_timeout();
}

static int init_is_timeout(void) {
    if (is_timerHndl != NULL) {
        ESP_LOGI(TAG, "is timer already init");
        return 0;
    }

    is_timerHndl = xTimerCreate(
            "is_timer",
            pdMS_TO_TICKS(IS_TIMEOUT_SEC)*1000,
            pdTRUE,
            (void*) 0,
            is_timeout_callback
            );

    if (xTimerStart(is_timerHndl, 0) != pdPASS) {
        ESP_LOGI(TAG, "ERROR STARTING IS TIMEOUT TIMER");
        return 1;
    }

    xTimerStop(is_timerHndl, 0);
    ESP_LOGI(TAG, "is timer created");
    return 0;
}

static void is_exit(void) {
    if (is_local_channel != NULL) {
        ssh_channel_send_eof(is_local_channel);
        ssh_channel_close(is_local_channel);
    }
    stop_is_timeout();
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
    ESP_LOGI(TAG, "auth_password");
    struct server_ctx *sc = (struct server_ctx*) userdata;
    struct client_ctx *cc;
    struct ssh_user *su;

    cc = lookup_client(sc, session);
    if (cc == NULL)
        goto denied;
    if (cc->cc_didauth)
        goto denied;
    su = sc->sc_lookup_user(sc, user);
    if (su == NULL)
        goto denied;
    if (strcmp(password, su->su_password) != 0)
        goto denied;
    cc->cc_didauth = true;

    stop_is_timeout();
    return SSH_AUTH_SUCCESS;

    denied:
    if (++pass_try >= PASS_TRY)
        ssh_disconnect(session);
    return SSH_AUTH_DENIED;
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
        goto denied;
    if (signature_state == SSH_PUBLICKEY_STATE_NONE)
        goto success;
    if (signature_state != SSH_PUBLICKEY_STATE_VALID)
        goto denied;
    if (cc->cc_didauth)
        goto denied;
    su = sc->sc_lookup_user(sc, user);
    if (su == NULL)
        goto denied;
    if (su->su_base64_key == NULL)
        goto denied;
    if (ssh_pki_import_pubkey_base64(su->su_base64_key, su->su_keytype, &key) != SSH_OK)
        goto denied;
    error = ssh_key_cmp(key, pubkey, SSH_KEY_CMP_PUBLIC);
    ssh_key_free(key);
    if (error != SSH_OK)
        goto denied;
    cc->cc_didauth = true;

    success:
    stop_is_timeout();
    return SSH_AUTH_SUCCESS;

    denied:
    if (++pass_try >= PASS_TRY)
        ssh_disconnect(session);
    return SSH_AUTH_DENIED;
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
    ESP_LOGI(TAG, "shell request");
    struct client_ctx *cc = (struct client_ctx*) userdata;
    if (cc->cc_didshell)
        return SSH_ERROR;
    cc->cc_didshell = true;
    cc->cc_is.is_handle_char_from_local = sendtochannel;
    cc->cc_is.is_exit = is_exit;
    cc->cc_is.is_reset_timeout = is_reset_timeout;
    cc->cc_begin_interactive_session(&cc->cc_is);
    kill_sess_chan = true;
    start_is_timeout();
    return SSH_OK;
}

static int exec_request(ssh_session session, ssh_channel channel, const char *command,
        void *userdata) {
    struct client_ctx *cc = (struct client_ctx*) userdata;

    if (cc->cc_didshell == false)
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

    (void) ssh_options_set(cc->cc_session, SSH_OPTIONS_CIPHERS_C_S,
            "aes128-ctr, aes192-ctr, aes256-ctr");
    (void) ssh_options_set(cc->cc_session, SSH_OPTIONS_CIPHERS_S_C,
            "aes128-ctr, aes192-ctr, aes256-ctr");

    (void) ssh_options_set(cc->cc_session, SSH_OPTIONS_HMAC_C_S,
            "ssh-ed25519, ssh-rsa, aes192-ctr, aes256-ctr, aes128-gcm@openssh.com, aes256-gcm@openssh.com, umac-128-etm@openssh.com");
    (void) ssh_options_set(cc->cc_session, SSH_OPTIONS_HMAC_S_C,
            "ssh-ed25519, ssh-rsa, aes192-ctr, aes256-ctr, aes128-gcm@openssh.com, aes256-gcm@openssh.com, umac-128-etm@openssh.com");

    (void) ssh_options_set(cc->cc_session, SSH_OPTIONS_KEY_EXCHANGE,
            "curve25519-sha256@libssh.org, curve25519-sha256, ecdh-sha2-nistp256, diffie-hellman-group-exchange-sha256, diffie-hellman-group14-sha1, diffie-hellman-group1-sha1, diffie-hellman-group18-sha512, diffie-hellman-group16-sha512");

    (void) ssh_options_set(cc->cc_session, SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES,
            "ssh-rsa-cert-v01@openssh.com ssh-dss-cert-v01@openssh.com ecdsa-sha2-nistp256-cert-v01@openssh.com ecdsa-sha2-nistp384-cert-v01@openssh.com ecdsa-sha2-nistp521-cert-v01@openssh.com ssh-ed25519-cert-v01@openssh.com ecdsa-sha2-nistp256 ecdsa-sha2-nistp384 ecdsa-sha2-nistp521 ssh-rsa ssh-dss ssh-ed25519");

    (void) ssh_options_set(cc->cc_session, SSH_OPTIONS_HOSTKEYS,
            "ssh-rsa,ssh-dss,ecdh-sha2-nistp256");

    if (ssh_handle_key_exchange(cc->cc_session) == SSH_ERROR) {
        ssh_disconnect(cc->cc_session);
        goto cleanup;
    }

    SLIST_INSERT_HEAD(&sc->sc_client_head, cc, cc_client_list);
    ssh_event_add_session(sc->sc_sshevent, cc->cc_session);
    ESP_LOGI(TAG, "incoming connection");
    pass_try = 0;
    kill_sess_chan = false;
    is_local_session = cc->cc_session;
    vTaskDelay(1000 / portTICK_PERIOD_MS);
    start_is_timeout();
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
            ESP_LOGI(TAG, "dead_eater: cc_removed 1");
            SSH_FREE(cc_removed);
            cc_removed = NULL;
            stop_is_timeout();
        }
        status = ssh_get_status(cc->cc_session);

        if (status & (SSH_CLOSED | SSH_CLOSED_ERROR)) {
            ESP_LOGI(TAG, "dead_eater: status CLOSED or CLOSED_ERROR");
            if (cc->cc_didchannel) {
                if (cc->cc_channel != NULL)
                    ESP_LOGI(TAG, "dead_eater: ssh channel free");
                    ssh_channel_free(cc->cc_channel);
            }
            ssh_event_remove_session(sc->sc_sshevent, cc->cc_session);
            ssh_free(cc->cc_session);
            SLIST_REMOVE(&sc->sc_client_head, cc, client_ctx, cc_client_list);
            cc_removed = cc;
        }
    }
    if (cc_removed) {
        ESP_LOGI(TAG, "dead_eater: cc_removed 2");
        SSH_FREE(cc_removed);
        cc_removed = NULL;
        stop_is_timeout();
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

    init_is_timeout();

    while (true) {
        ssh_event_dopoll(sc->sc_sshevent, 200);
        dead_eater(sc);
    }

    terminate_server(sc);
    ssh_event_free(event);
    ssh_finalize();
    if (is_timerHndl != NULL)
        xTimerDelete(is_timerHndl, 0);
    ESP_LOGI(TAG, "END sshd_main");

    return SSH_OK;
}

static void sendtochannel(struct interactive_session *is, char *c, int len) {
	struct client_ctx *cc = (struct client_ctx*) ((uintptr_t) is
	            - offsetof(struct client_ctx, cc_is));
		ssh_channel_write(cc->cc_channel, c, len);
}
