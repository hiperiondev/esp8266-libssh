#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/private/portable.h"
#include <sys/queue.h>
#include "esp_log.h"
#include "esp_err.h"
#include "sshd.h"
#include "sshd_main.h"
static const char *TAG = "sshd_task";

static struct ssh_user hardcoded_example_users[] = {
        {
                .su_user = "hiperion",
                .su_password = "devel",
        },
        {
                .su_user = "hiperiondevel",
                .su_keytype = SSH_KEYTYPE_ED25519,
                .su_base64_key = "AAAAC3NzaC1lZDI1NTE5AAAAILrLCwnBbitV0fhQyy7PClEDVLbtD3tzmuWX4fU6DuxI"
        },
        {

        }
};

const char *hardcoded_example_host_key =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEA0TqWksdG7YveqYeppmm+zMoKUjY9efoz74o7d2CCxUSVM0GcRBvwLa\n"
    "KH9VBcIKFYEKnuXjVRlvBZw1t2QK91DwwfHs6fRtYI0au1R3+esWTmanumL/0JPSiB9YqH\n"
    "gQadBqvM1kJdvEkWbv0gXfw8Z+UwYWnbZVC2G5PvAdV6l1Zdf3nGPpJUBrcWaA42844ZRS\n"
    "AMxmnvTG/3S1xkkHwe/jU2vkE8ceikUR9FiP9kPFWgJ6OhXRRnbqbmhIgeiCTQBWhnZqon\n"
    "xnkNRZSfacm3Favak3uHa9KENs3ZLxcjiczn2U4K+rUqOfCreMhrG7QP4R7ZjDnW6EphGG\n"
    "BHngqFfwIDAQABAoIBAQC6zSRCR8j7rTVPBuBgw2imTnyIigS5MrnL1A7jtjcLCQBskteB\n"
    "t6/oDoR0cRrPxz1pI06+rbv6lvyNfstFVWGd3aSrTK7H/7BAAp4HB9oXZ46Q43Ssw63L/K\n"
    "6LGvOALvdjTV/Eq9wkjtyIm1aakukbmXRohKps+nKcjKeHa6HYGpY23e2JXhwA2w/Ly+ji\n"
    "b0qluMpyUCxRvye5GZCpPPSNfVamXv+QIQCGIkR1aEcYXpnbV8qDQSCeORcJIOX7hU9JH1\n"
    "pldoQ7MY+yV2r1twNgNnY2ttBPUc0JHLf1KQ2D6vXlP6lGrqC8yu5F9tZvsrBhOEycUXmz\n"
    "TuWr3wtDzqUBAoGBAO/60JItR39u15AUMd/DVOrjSOmauuBW2VHJwdpz6p+w56yyCjajmA\n"
    "f/+vR8PbCwJIg4W1g6MmA9aiHr3QfLqBonN9OD93+9i1zFIh7EeSybBqBbEwC+szI7adBB\n"
    "/k6iIaTYNKPW2hO4Vqeol4u087yNtTgK+idZcQq2wk8KjXh3AoGBAN8yP+ZnEJCOHKJeYU\n"
    "Fa0brbEfBevUZkofINmn8tzKjElEs9MS+9yrFJW/4QIYznPYtTYQqBZ9s7w+uUA2+nyXTF\n"
    "sdt6LgdfAamf2O2nDlk8TMktpBFTKNtHlMCI/RlPlgIKdI2LNxvqn+qtqD45+scF852icD\n"
    "3IWoXvoco4yqU5AoGAfF8Dq052KJAcfdpJgstr/hPvHMqJIW1BUcb7hajfpwV6/CCFdI3S\n"
    "ZAsBV6XwHtsbA9IZXR9ELmaF07C2q6yboXpDz4YsRfLJADpWlZWDq19ozsCEl7U9j8IE89\n"
    "7P2pbiUtmOZn8aJHA70MZqTAhq7YSPr8zYmn4bPM884tP4P78CgYAs4hL9hz5Kg3l4oVgX\n"
    "Z2cDl2g9GSAg1r3GSjwGVTRxv84+bxjEC/uFuUXZim7kwd+bc/HwxeMXsCYO6p3iRzB43g\n"
    "SNKT22V8Gi1bUu3UhCY6DhV99FaJ6vse5U5XdYLqvwzx9vE07Ku1zbOX66vLgUa7r4uSCv\n"
    "G+owQucbHl6J6QKBgAO1aKh5kkDF/v+jZ2jp2100ipomWpHUwXc4qYrB/NrDG7bdn2uYtY\n"
    "ZJft038Y81xAzx78bzDUd8SgLZMLY2nJ1noe9BjdEwCYt6NsE055z/KpKjsy17C/dh7veE\n"
    "mkTBnMHfdTMVqAR1KZSBxJLurXGIfcSFsjzmRnkh6p03O+pH"
    "-----END RSA PRIVATE KEY-----\n";

static struct ssh_user* lookup_user(struct server_ctx *sc, const char *user) {
    struct ssh_user *su;
    for (su = hardcoded_example_users; su->su_user; su++) {
        if (strcmp(user, su->su_user) == 0) {
            ESP_LOGI(TAG, "lookup user: %s (%s)", user, su->su_user);
            return su;
        }
    }
    return NULL;

}

static void ssh_log_function(int priority, const char *function, const char *buffer, void *userdata) {
    if (function == NULL) {
        ESP_LOGI(TAG, "ssh_log: function == NULL");
        return;
    }
    if (buffer == NULL) {
        ESP_LOGI(TAG, "ssh_log: buffer == NULL (%s)", function);
        return;
    }
    if (userdata == NULL) {
        ESP_LOGI(TAG, "ssh_log: userdata == NULL (%s)", function);
        return;
    }

    ESP_LOGI(TAG, "ssh_log: (%d) %s - %s [%s]", priority, function, buffer, (const char* )userdata);
}

void sshd_task(void *arg) {
    ESP_LOGI(TAG, "sshd_task");
    esp_err_t erro;
    struct server_ctx *sc = NULL;

    for (;;) {
        erro = 0;

        if (sc != NULL) {
            vPortFree(sc);
        }
        sc = (struct server_ctx*) pvPortCalloc(1, sizeof(struct server_ctx));
        if (sc == NULL) {
            ESP_LOGI(TAG, "sshd can't alloc memory");
            return;
        }

        ssh_set_log_callback(ssh_log_function);

        sc->sc_host_key = hardcoded_example_host_key;
        sc->sc_lookup_user = lookup_user;
        sc->sc_begin_interactive_session = minicli_begin_interactive_session;
        //sc->sc_auth_methods = SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_PUBLICKEY;
        sc->sc_auth_methods = SSH_AUTH_METHOD_PASSWORD;
        erro = sshd_main(sc);
        ESP_LOGI(TAG, "sshd_main err: %d", erro);
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
}

void start_sshd(void) {
    ESP_LOGI(TAG, "start_sshd");
    xTaskCreate(
            sshd_task,
            "sshd",
            10000,
            NULL,
            10,
            NULL
            );
}
