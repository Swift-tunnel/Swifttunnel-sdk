/* SwiftTunnel SDK -- basic C example
 *
 * Build:
 *   gcc -o basic basic.c -L../target/release -lswifttunnel
 *
 * Run (Linux/macOS):
 *   LD_LIBRARY_PATH=../target/release ./basic
 *
 * Run (Windows):
 *   Copy swifttunnel.dll next to basic.exe, then run basic.exe
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Declarations (matches swifttunnel.h) ───────────────────────────────── */

/* Core */
int          swifttunnel_init(void);
void         swifttunnel_cleanup(void);
char*        swifttunnel_version(void);
void         swifttunnel_free_string(char* ptr);

/* Auth */
int          swifttunnel_auth_sign_in(const char* email, const char* password);
char*        swifttunnel_auth_start_oauth(void);
int          swifttunnel_auth_poll_oauth(void);
void         swifttunnel_auth_cancel_oauth(void);
int          swifttunnel_auth_refresh(void);
void         swifttunnel_auth_sign_out(void);
int          swifttunnel_auth_is_logged_in(void);
char*        swifttunnel_auth_get_user_json(void);

/* Servers */
int          swifttunnel_servers_fetch(void);
char*        swifttunnel_servers_get_json(void);
int          swifttunnel_servers_ping(const char* region);

/* Connection */
int          swifttunnel_connect(const char* region, const char* apps_json);
int          swifttunnel_connect_ex(const char* options_json);
int          swifttunnel_disconnect(void);
int          swifttunnel_get_state(void);
char*        swifttunnel_get_state_json(void);

/* Split Tunnel */
char*        swifttunnel_get_tunneled_processes(void);
char*        swifttunnel_get_stats_json(void);
char*        swifttunnel_get_auto_routing_json(void);
int          swifttunnel_refresh_processes(void);

/* Callbacks */
typedef void (*state_change_cb)(int state_code, void* ctx);
typedef void (*error_cb)(int error_code, const char* message, void* ctx);
typedef void (*process_detected_cb)(const char* name, int added, void* ctx);
typedef void (*auto_routing_cb)(const char* event_json, void* ctx);
void         swifttunnel_on_state_change(state_change_cb cb, void* ctx);
void         swifttunnel_on_error(error_cb cb, void* ctx);
void         swifttunnel_on_process_detected(process_detected_cb cb, void* ctx);
void         swifttunnel_on_auto_routing_event(auto_routing_cb cb, void* ctx);

/* Error */
char*        swifttunnel_get_last_error(void);
int          swifttunnel_get_last_error_code(void);
void         swifttunnel_clear_error(void);

/* ── Callbacks ──────────────────────────────────────────────────────────── */

static void on_state(int code, void* ctx) {
    (void)ctx;
    printf("[callback] state changed: %d\n", code);
}

static void on_error(int code, const char* msg, void* ctx) {
    (void)ctx;
    fprintf(stderr, "[callback] error %d: %s\n", code, msg ? msg : "(null)");
}

static void on_process(const char* name, int added, void* ctx) {
    (void)ctx;
    printf("[callback] process %s: %s\n", added ? "added" : "removed",
           name ? name : "(null)");
}

static void on_auto_routing(const char* event_json, void* ctx) {
    (void)ctx;
    printf("[callback] auto-routing: %s\n", event_json ? event_json : "(null)");
}

/* ── Helpers ────────────────────────────────────────────────────────────── */

/* Print and free an SDK string; print "(null)" if NULL. */
static void print_and_free(const char* label, char* s) {
    printf("%s: %s\n", label, s ? s : "(null)");
    if (s) swifttunnel_free_string(s);
}

/* ── Main ───────────────────────────────────────────────────────────────── */

int main(int argc, char** argv) {
    const char* email    = argc > 1 ? argv[1] : "user@example.com";
    const char* password = argc > 2 ? argv[2] : "password";
    const char* region   = argc > 3 ? argv[3] : "singapore";

    int rc;

    /* 1. Initialise */
    rc = swifttunnel_init();
    if (rc != 0) {
        fprintf(stderr, "init failed: %d\n", rc);
        return 1;
    }
    print_and_free("SDK version", swifttunnel_version());

    /* 2. Register callbacks */
    swifttunnel_on_state_change(on_state, NULL);
    swifttunnel_on_error(on_error, NULL);
    swifttunnel_on_process_detected(on_process, NULL);
    swifttunnel_on_auto_routing_event(on_auto_routing, NULL);

    /* 3. Authenticate */
    rc = swifttunnel_auth_sign_in(email, password);
    if (rc != 0) {
        print_and_free("auth error", swifttunnel_get_last_error());
        swifttunnel_cleanup();
        return 1;
    }
    printf("logged in: %s\n", swifttunnel_auth_is_logged_in() ? "yes" : "no");
    print_and_free("user", swifttunnel_auth_get_user_json());

    /* 4. Fetch servers and ping */
    rc = swifttunnel_servers_fetch();
    if (rc != 0) {
        print_and_free("servers_fetch error", swifttunnel_get_last_error());
    } else {
        print_and_free("servers", swifttunnel_servers_get_json());
        int latency = swifttunnel_servers_ping(region);
        printf("ping %s: %d ms\n", region, latency);
    }

    /* 5. Connect using connect_ex with auto-routing enabled */
    char connect_opts[512];
    snprintf(
        connect_opts,
        sizeof(connect_opts),
        "{\"region\":\"%s\",\"apps\":[\"RobloxPlayerBeta.exe\"],"
        "\"auto_routing\":{\"enabled\":true,\"whitelisted_regions\":[\"US East\",\"Tokyo\"]}}",
        region
    );
    rc = swifttunnel_connect_ex(connect_opts);
    if (rc != 0) {
        print_and_free("connect error", swifttunnel_get_last_error());
        swifttunnel_cleanup();
        return 1;
    }

    printf("state: %d\n", swifttunnel_get_state());
    print_and_free("state detail", swifttunnel_get_state_json());
    print_and_free("tunneled", swifttunnel_get_tunneled_processes());
    print_and_free("stats", swifttunnel_get_stats_json());
    print_and_free("auto routing", swifttunnel_get_auto_routing_json());

    /* 6. Disconnect */
    rc = swifttunnel_disconnect();
    if (rc != 0) {
        print_and_free("disconnect error", swifttunnel_get_last_error());
    }

    /* 7. Sign out and clean up */
    swifttunnel_auth_sign_out();
    swifttunnel_cleanup();
    printf("done\n");

    return 0;
}
