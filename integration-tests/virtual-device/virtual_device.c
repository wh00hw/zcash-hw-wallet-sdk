/*
 * Virtual HWP Device — TCP server for integration testing.
 *
 * Speaks the HWP protocol over TCP using the **same** hwp_dispatcher
 * the FlipZcash firmware uses on USB CDC. The application layer here
 * is a single main() that:
 *   1. Derives a deterministic key set from the hardcoded test seed.
 *   2. Listens on TCP, accepts one client at a time.
 *   3. Wires the client socket into hwp_dispatcher_run() via four
 *      I/O callbacks (drain / send / tick / sleep + should_exit) and
 *      headless auto-confirming UI callbacks.
 *
 * No protocol logic lives here — that's intentional. Any protocol
 * change made in libzcash-orchard-c's dispatcher is automatically
 * reflected in this fixture, keeping the SDK's integration tests
 * pinned to the canonical device-side implementation rather than a
 * drifting re-implementation.
 *
 * Usage: ./virtual-device [--port PORT]
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include "bip32.h"
#include "hwp_dispatcher.h"
#include "memzero.h"
#include "orchard.h"
#include "orchard_signer.h"
#include "redpallas.h"
#include "tcp_transport.h"
#include "wallet_test.h"

#define DEFAULT_PORT 9999

/* ── Session state passed as user_ctx to every dispatcher callback ── */

typedef struct {
    int client_fd;
    bool client_disconnected;   /* set on EOF from recv() */
    OrchardSignerCtx signer;

    /* Pre-derived key material; lifetime spans the dispatcher loop. */
    uint8_t ak[32], nk[32], rivk[32], ask[32];
    uint8_t t_sk[32], t_pubkey[33];

    uint32_t coin_type;
    bool testnet;
} Session;

/* ── I/O callbacks ────────────────────────────────────────────────── */

static size_t cb_serial_drain(uint8_t* out, size_t out_cap, void* ctx) {
    Session* s = (Session*)ctx;
    if(s->client_disconnected) return 0;
    /* Non-blocking; loop iteration handles the polling cadence. */
    ssize_t n = recv(s->client_fd, out, out_cap, MSG_DONTWAIT);
    if(n > 0) return (size_t)n;
    if(n == 0) {
        s->client_disconnected = true;
        return 0;
    }
    /* EAGAIN / EWOULDBLOCK is the steady state; anything else is a
     * real error and we treat it the same as disconnect so the loop
     * exits cleanly. */
    return 0;
}

static void cb_serial_send(const uint8_t* data, size_t len, void* ctx) {
    Session* s = (Session*)ctx;
    if(s->client_disconnected) return;
    if(tcp_send(s->client_fd, data, len) != 0) {
        s->client_disconnected = true;
    }
}

static uint32_t cb_tick_ms(void* ctx) {
    (void)ctx;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000u + ts.tv_nsec / 1000000u);
}

static void cb_sleep_ms(uint32_t ms, void* ctx) {
    (void)ctx;
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static bool cb_should_exit(void* ctx) {
    Session* s = (Session*)ctx;
    return s->client_disconnected;
}

/* ── UI callbacks (headless: auto-confirm + log) ──────────────────── */

static HwpUiResult cb_review_output(uint16_t idx, uint16_t total,
                                     const char* addr, uint64_t value,
                                     void* ctx) {
    (void)ctx;
    fprintf(stderr, "[hwp] review output %u/%u: %s  (%llu zat)\n",
            idx, total, addr, (unsigned long long)value);
    return HWP_UI_OK;
}

static HwpUiResult cb_confirm_tx(uint64_t amount, uint64_t fee,
                                  const char* recipient, void* ctx) {
    (void)ctx;
    fprintf(stderr, "[hwp] confirm tx: %llu zat → %s (fee %llu)\n",
            (unsigned long long)amount, recipient, (unsigned long long)fee);
    return HWP_UI_OK;
}

static void cb_network_error(const char* msg, bool device_testnet, void* ctx) {
    (void)ctx;
    fprintf(stderr, "[hwp] network mismatch (testnet=%d): %s\n",
            device_testnet, msg);
}

static void cb_phase(HwpPhase phase, uint16_t idx, uint16_t total, void* ctx) {
    (void)ctx;
    fprintf(stderr, "[hwp] phase=%d %u/%u\n", phase, idx, total);
}

static void cb_progress(uint8_t pct, const char* label, void* ctx) {
    (void)ctx;
    if(pct % 10 == 0) {
        fprintf(stderr, "[hwp] progress %3u%% %s\n", pct, label);
    }
}

/* ── Key material derivation (once per process) ───────────────────── */

static void derive_keys(Session* s) {
    uint8_t seed[64];
    wallet_test_get_seed(seed);

    /* Orchard ZIP-32 derivation: sk → ask/nk/rivk → ak. */
    uint8_t sk[32];
    orchard_derive_account_sk(seed, s->coin_type, 0, sk);
    orchard_derive_keys(sk, s->ask, s->nk, s->rivk);
    memzero(sk, sizeof(sk));
    redpallas_derive_ak(s->ask, s->ak);

    /* BIP-32 transparent: m/44'/coin_type'/0'/0/0. */
    bip32_derive_transparent_sk(seed, s->coin_type, s->t_sk, s->t_pubkey);

    memzero(seed, sizeof(seed));
    fprintf(stderr, "[wallet] keys derived (coin_type=%u)\n",
            (unsigned)s->coin_type);
}

/* ── Main ─────────────────────────────────────────────────────────── */

static volatile sig_atomic_t s_shutdown = 0;
static void on_sigint(int sig) { (void)sig; s_shutdown = 1; }

int main(int argc, char* argv[]) {
    uint16_t port = DEFAULT_PORT;
    /* Default to mainnet so the SDK's integration tests (which set
     * COIN_TYPE_MAINNET in the synthetic TxMeta they build for the
     * sighash KAT) work without override. Spawn a second instance with
     * --coin 1 for testnet coverage. */
    uint32_t coin_type = 133;
    for(int i = 1; i < argc; i++) {
        if(strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = (uint16_t)atoi(argv[++i]);
        } else if(strcmp(argv[i], "--coin") == 0 && i + 1 < argc) {
            coin_type = (uint32_t)atoi(argv[++i]);
        }
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    wallet_test_init();

    int server_fd = tcp_listen(port);
    if(server_fd < 0) return 1;
    fprintf(stderr, "[hwp] Virtual device listening on port %d (coin_type=%u)\n",
            port, (unsigned)coin_type);

    while(!s_shutdown) {
        int client_fd = tcp_accept(server_fd);
        if(client_fd < 0) continue;
        fprintf(stderr, "[hwp] Client connected\n");

        Session s = {
            .client_fd = client_fd,
            .client_disconnected = false,
            .coin_type = coin_type,
            .testnet = (coin_type == 1),
        };
        orchard_signer_init(&s.signer);
        s.signer.coin_type = coin_type;
        derive_keys(&s);

        HwpDispatcher d = {
            .io = {
                .serial_drain = cb_serial_drain,
                .serial_send  = cb_serial_send,
                .get_tick_ms  = cb_tick_ms,
                .sleep_ms     = cb_sleep_ms,
                .should_exit  = cb_should_exit,
            },
            .ui = {
                .review_output = cb_review_output,
                .confirm_tx    = cb_confirm_tx,
                .network_error = cb_network_error,
                .phase_update  = cb_phase,
                .progress      = cb_progress,
            },
            .keys = {
                .ak       = s.ak,
                .nk       = s.nk,
                .rivk     = s.rivk,
                .ask      = s.ask,
                .t_sk     = s.t_sk,
                .t_pubkey = s.t_pubkey,
            },
            .signer    = &s.signer,
            .testnet   = s.testnet,
            .user_ctx  = &s,
        };

        hwp_dispatcher_run(&d);

        tcp_close(client_fd);
        orchard_signer_reset(&s.signer);
        memzero(s.ask, sizeof(s.ask));
        memzero(s.t_sk, sizeof(s.t_sk));
        fprintf(stderr, "[hwp] Client disconnected\n");
    }

    tcp_close(server_fd);
    return 0;
}
