/*
 * Virtual HWP Device — TCP server for integration testing.
 *
 * Speaks the HWP protocol over TCP using the **same** hwp_dispatcher
 * the FlipZcash firmware uses on USB CDC. The application layer here
 * is a single main() that:
 *   1. Derives a deterministic key set from the hardcoded test seed.
 *   2. Listens on TCP, accepts one client at a time.
 *   3. Wires the client socket into hwp_dispatcher_run() via the I/O
 *      callbacks (drain / send / tick / sleep + should_exit) and a headless
 *      "user" that approves what it is shown and writes it down.
 *
 * No protocol logic lives here — that's intentional. Any protocol
 * change made in libzcash-ironwood-c's dispatcher is automatically
 * reflected in this fixture, keeping the SDK's integration tests
 * pinned to the canonical device-side implementation rather than a
 * drifting re-implementation. In particular nothing in this file calls
 * into the signer except through hwp_dispatcher_run(): every library check
 * runs exactly as it does on a real device.
 *
 * ── What the "screen" shows ────────────────────────────────────────────
 *
 * Every UI callback prints one line to stdout, prefixed "[ui] ", made of
 * the screen's name and space-separated key=value fields in a fixed order.
 * Values contain no space, except the two double-quoted ones (text= of a
 * memo, msg= of a network error):
 *
 *   [ui] session event=open
 *   [ui] review_output index=1 total=2 kind=external address=u1... value=500000 memo=present has_memo=1 decision=ok
 *   [ui] review_memo index=1 total=2 address=u1... type=text len=8 text="NU7 test" hex=4e55... decision=ok
 *   [ui] review_totals total_leaving=510000 fee=10000 external_shielded=500000 transparent_out=0 own_internal=490000 own_external=0 n_external=1 n_own_internal=1 n_own_external=0 n_zero_value=0 n_transparent_out=0 decision=ok
 *   [ui] confirm_tx total_leaving=510000 fee=10000 n_external=1 n_transparent_out=0 decision=ok
 *   [ui] network_error device_testnet=0 msg="..."
 *   [ui] session event=close
 *
 * kind is one of: transparent | external | own-change | own-address.
 * memo is what the device established: none | present | n/a (transparent).
 * confirm_tx carries nothing from the host: the device ignores the
 * recipient, amount and fee of SIGN_REQ.
 * decision is what the simulated user answered: ok | cancelled.
 * index/total number the outputs that are SHOWN (zero-value padding is not).
 * Memo: type=text for a ZIP-302 text memo
 * (lead byte 0x00..0xF4; text= is the UTF-8 with trailing NULs trimmed,
 * non-printable bytes, '"' and '\' escaped as \xNN), type=binary otherwise
 * (text=""); hex= is always the full 512 bytes.
 *
 * Protocol phases and progress go to stderr and are not part of the
 * contract.
 *
 * ── Test hooks ─────────────────────────────────────────────────────────
 *
 * The hooks only change what the simulated USER does (say no at a given
 * screen) and how long the device naps; none of them touches a library
 * check.
 *
 *   --reject-at STEP     (or env VDEV_REJECT_AT) the user refuses at STEP,
 *                        every time it comes up:
 *                          output:N  the N-th review_output of a review
 *                          memo:N    the N-th review_memo of a review
 *                          totals    the totals screen
 *                          confirm   the final confirmation
 *   --max-sleep-ms MS    (or env VDEV_MAX_SLEEP_MS) cap every dispatcher
 *                        sleep at MS (the dispatcher lingers 2.5 s on its
 *                        "done" screen after the last signature).
 *
 * A test suite that needs different behaviour per test, and wants to read
 * the screen back, uses the control port (TCP, loopback only; default
 * HWP port + 1, --control-port N to move it, --no-control to disable).
 * One command per line, one reply per command:
 *
 *   LOG            -> every "[ui] ..." line since the last CLEAR, then "."
 *   CLEAR          -> "OK"  (forget the lines so far)
 *   REJECT STEP    -> "OK"  (arm a ONE-SHOT refusal: it fires the next time
 *                           STEP comes up and then disarms itself)
 *   REJECT none    -> "OK"  (disarm)
 *   MAXSLEEP MS    -> "OK"  (0 = no cap)
 *
 * Usage: ./virtual-device [--port PORT] [--coin 133|1] [hooks above]
 */
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include "hwp_dispatcher.h"
#include "memzero.h"
#include "orchard.h"
#include "orchard_signer.h"
#include "redpallas.h"
#include "tcp_transport.h"
#include "wallet_test.h"

#define DEFAULT_PORT 9999

/* ── The simulated user: transcript + refusal rules ───────────────── */

typedef enum {
    STEP_NONE = 0,
    STEP_OUTPUT,   /* n-th review_output of a review */
    STEP_MEMO,     /* n-th review_memo of a review */
    STEP_TOTALS,
    STEP_CONFIRM,
} UiStep;

typedef struct {
    UiStep step;
    unsigned n;    /* 1-based ordinal for STEP_OUTPUT / STEP_MEMO */
} RejectRule;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
#define UI_LOG_MAX (1u << 20)       /* transcript cap, bytes */
static char* g_log = NULL;          /* transcript since the last CLEAR */
static size_t g_log_len = 0, g_log_cap = 0;
static RejectRule g_static_rule;    /* --reject-at: fires every time */
static RejectRule g_oneshot_rule;   /* control port REJECT: fires once */
static unsigned g_max_sleep_ms = 0; /* 0 = no cap */
/* Ordinals of the review in progress: how many output / memo screens it
 * has shown so far. They restart at the first output screen of a review
 * (index 1), and after a totals screen or a refusal. */
static unsigned g_output_calls = 0, g_memo_calls = 0;

static bool parse_step(const char* s, RejectRule* out) {
    RejectRule r = {STEP_NONE, 0};
    if(strcmp(s, "none") == 0) {
        /* disarm */
    } else if(strcmp(s, "totals") == 0) {
        r.step = STEP_TOTALS;
    } else if(strcmp(s, "confirm") == 0) {
        r.step = STEP_CONFIRM;
    } else if(strncmp(s, "output:", 7) == 0 && atoi(s + 7) > 0) {
        r.step = STEP_OUTPUT;
        r.n = (unsigned)atoi(s + 7);
    } else if(strncmp(s, "memo:", 5) == 0 && atoi(s + 5) > 0) {
        r.step = STEP_MEMO;
        r.n = (unsigned)atoi(s + 5);
    } else {
        return false;
    }
    *out = r;
    return true;
}

/* Does the user refuse this screen? Consumes a matching one-shot rule. */
static bool user_refuses(UiStep step, unsigned n) {
    bool refuse = false;
    pthread_mutex_lock(&g_lock);
    if(g_static_rule.step == step && (g_static_rule.n == 0 || g_static_rule.n == n)) {
        refuse = true;
    }
    if(g_oneshot_rule.step == step && (g_oneshot_rule.n == 0 || g_oneshot_rule.n == n)) {
        refuse = true;
        g_oneshot_rule.step = STEP_NONE;
        g_oneshot_rule.n = 0;
    }
    pthread_mutex_unlock(&g_lock);
    return refuse;
}

/* Print one "[ui] ..." line to stdout and append it to the transcript. */
static void ui_log(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
static void ui_log(const char* fmt, ...) {
    char line[4096];
    int off = snprintf(line, sizeof(line), "[ui] ");
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line + off, sizeof(line) - (size_t)off - 2, fmt, ap);
    va_end(ap);
    if(n < 0) return;
    size_t len = strlen(line);
    line[len++] = '\n';
    line[len] = '\0';

    fputs(line, stdout);
    fflush(stdout);

    pthread_mutex_lock(&g_lock);
    /* Nobody is reading (no CLEAR for a long time): start over rather than
     * grow without bound. */
    if(g_log_len > UI_LOG_MAX) g_log_len = 0;
    if(g_log_len + len + 1 > g_log_cap) {
        size_t cap = g_log_cap ? g_log_cap * 2 : 8192;
        while(cap < g_log_len + len + 1) cap *= 2;
        char* p = realloc(g_log, cap);
        if(p) {
            g_log = p;
            g_log_cap = cap;
        }
    }
    if(g_log_len + len + 1 <= g_log_cap) {
        memcpy(g_log + g_log_len, line, len + 1);
        g_log_len += len;
    }
    pthread_mutex_unlock(&g_lock);
}

/* ── Session state passed as user_ctx to every dispatcher callback ── */

typedef struct {
    int client_fd;
    bool client_disconnected;   /* set on EOF from recv() */
    OrchardSignerCtx signer;

    /* Pre-derived key material; lifetime spans the dispatcher loop. No
     * transparent key: the dispatcher does not sign transparent inputs. */
    uint8_t ak[32], nk[32], rivk[32], ask[32];

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
    pthread_mutex_lock(&g_lock);
    unsigned cap = g_max_sleep_ms;
    pthread_mutex_unlock(&g_lock);
    if(cap != 0 && ms > cap) ms = cap;
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static volatile sig_atomic_t s_shutdown = 0;

static bool cb_should_exit(void* ctx) {
    Session* s = (Session*)ctx;
    return s->client_disconnected || s_shutdown;
}

/* ── UI callbacks (headless user: log, then approve or refuse) ────── */

static const char* kind_name(HwpOutputKind kind) {
    /* The label comes from `kind` alone — the device's own decision. */
    switch(kind) {
    case HWP_OUTPUT_TRANSPARENT: return "transparent";
    case HWP_OUTPUT_EXTERNAL:    return "external";
    case HWP_OUTPUT_OWN_CHANGE:  return "own-change";
    case HWP_OUTPUT_OWN_ADDRESS: return "own-address";
    }
    return "INVALID";
}

static const char* memo_name(HwpMemoStatus memo) {
    switch(memo) {
    case HWP_MEMO_NONE:           return "none";     /* "Memo: none" */
    case HWP_MEMO_PRESENT:        return "present";  /* review_memo follows */
    case HWP_MEMO_NOT_APPLICABLE: return "n/a";      /* transparent output */
    }
    return "INVALID";
}

static HwpUiResult cb_review_output(const HwpOutputReview* out, void* ctx) {
    (void)ctx;
    if(out->index == 1) {
        g_output_calls = 0;
        g_memo_calls = 0;
    }
    unsigned n = ++g_output_calls;
    bool refuse = user_refuses(STEP_OUTPUT, n);
    ui_log("review_output index=%u total=%u kind=%s address=%s value=%llu memo=%s has_memo=%d decision=%s",
           (unsigned)out->index, (unsigned)out->total, kind_name(out->kind),
           out->address, (unsigned long long)out->value, memo_name(out->memo),
           out->has_memo ? 1 : 0, refuse ? "cancelled" : "ok");
    if(refuse) {
        g_output_calls = 0;
        g_memo_calls = 0;
        return HWP_UI_CANCELLED;
    }
    return HWP_UI_OK;
}

static HwpUiResult cb_review_memo(uint16_t index, uint16_t total,
                                   const char* recipient_addr_str,
                                   const uint8_t memo[512], void* ctx) {
    (void)ctx;
    unsigned n = ++g_memo_calls;
    bool refuse = user_refuses(STEP_MEMO, n);

    /* ZIP-302: lead byte 0x00..0xF4 is UTF-8 text, NUL padded. */
    bool is_text = memo[0] <= 0xF4;
    size_t text_len = 0;
    if(is_text) {
        text_len = 512;
        while(text_len > 0 && memo[text_len - 1] == 0) text_len--;
    }
    char text[512 * 4 + 1];
    size_t t = 0;
    for(size_t i = 0; i < text_len; i++) {
        uint8_t c = memo[i];
        if(c >= 0x20 && c < 0x7F && c != '"' && c != '\\') {
            text[t++] = (char)c;
        } else {
            t += (size_t)snprintf(text + t, 5, "\\x%02x", c);
        }
    }
    text[t] = '\0';
    char hex[1025];
    for(size_t i = 0; i < 512; i++) snprintf(hex + 2 * i, 3, "%02x", memo[i]);

    ui_log("review_memo index=%u total=%u address=%s type=%s len=%zu text=\"%s\" hex=%s decision=%s",
           (unsigned)index, (unsigned)total, recipient_addr_str,
           is_text ? "text" : "binary", text_len, text, hex,
           refuse ? "cancelled" : "ok");
    memzero(text, sizeof(text));
    memzero(hex, sizeof(hex));
    if(refuse) {
        g_output_calls = 0;
        g_memo_calls = 0;
        return HWP_UI_CANCELLED;
    }
    return HWP_UI_OK;
}

static HwpUiResult cb_review_totals(const OrchardSignerTotals* t, void* ctx) {
    (void)ctx;
    bool refuse = user_refuses(STEP_TOTALS, 0);
    g_output_calls = 0;
    g_memo_calls = 0;
    ui_log("review_totals total_leaving=%llu fee=%llu external_shielded=%llu "
           "transparent_out=%llu own_internal=%llu own_external=%llu "
           "n_external=%u n_own_internal=%u n_own_external=%u n_zero_value=%u "
           "n_transparent_out=%u decision=%s",
           (unsigned long long)t->total_leaving, (unsigned long long)t->fee,
           (unsigned long long)t->external_shielded,
           (unsigned long long)t->transparent_out,
           (unsigned long long)t->own_internal, (unsigned long long)t->own_external,
           (unsigned)t->n_external, (unsigned)t->n_own_internal,
           (unsigned)t->n_own_external, (unsigned)t->n_zero_value,
           (unsigned)t->n_transparent_out, refuse ? "cancelled" : "ok");
    return refuse ? HWP_UI_CANCELLED : HWP_UI_OK;
}

static HwpUiResult cb_confirm_tx(const OrchardSignerTotals* t, void* ctx) {
    (void)ctx;
    bool refuse = user_refuses(STEP_CONFIRM, 0);
    /* Device-computed numbers only: nothing from the host reaches this
     * screen. */
    ui_log("confirm_tx total_leaving=%llu fee=%llu n_external=%u n_transparent_out=%u decision=%s",
           (unsigned long long)t->total_leaving, (unsigned long long)t->fee,
           (unsigned)t->n_external, (unsigned)t->n_transparent_out,
           refuse ? "cancelled" : "ok");
    return refuse ? HWP_UI_CANCELLED : HWP_UI_OK;
}

static void cb_network_error(const char* msg, bool device_testnet, void* ctx) {
    (void)ctx;
    ui_log("network_error device_testnet=%d msg=\"%s\"", device_testnet ? 1 : 0, msg);
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

/* ── Key material derivation (once per session) ───────────────────── */

static void derive_keys(Session* s) {
    uint8_t seed[64];
    wallet_test_get_seed(seed);

    /* Orchard ZIP-32 derivation: sk → ask/nk/rivk → ak. These are the
     * device's own keys: FVK_RSP sends ak/nk/rivk, and the dispatcher
     * classifies every output against the very same three. */
    uint8_t sk[32];
    orchard_derive_account_sk(seed, s->coin_type, 0, sk);
    orchard_derive_keys(sk, s->ask, s->nk, s->rivk);
    memzero(sk, sizeof(sk));
    redpallas_derive_ak(s->ask, s->ak);

    memzero(seed, sizeof(seed));
    fprintf(stderr, "[wallet] keys derived (coin_type=%u)\n",
            (unsigned)s->coin_type);
}

/* ── Control port (test side channel; never touches the signer) ───── */

static int control_listen(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0) return -1;
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons(port),
    };
    if(bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0 || listen(fd, 4) < 0) {
        perror("control port");
        close(fd);
        return -1;
    }
    return fd;
}

static void control_reply(int fd, const char* s) {
    (void)tcp_send(fd, (const uint8_t*)s, strlen(s));
}

static void control_command(int fd, char* cmd) {
    if(strcmp(cmd, "LOG") == 0) {
        pthread_mutex_lock(&g_lock);
        char* copy = g_log_len ? malloc(g_log_len) : NULL;
        size_t len = copy ? g_log_len : 0;
        if(copy) memcpy(copy, g_log, len);
        pthread_mutex_unlock(&g_lock);
        if(copy) (void)tcp_send(fd, (const uint8_t*)copy, len);
        free(copy);
        control_reply(fd, ".\n");
    } else if(strcmp(cmd, "CLEAR") == 0) {
        pthread_mutex_lock(&g_lock);
        g_log_len = 0;
        pthread_mutex_unlock(&g_lock);
        control_reply(fd, "OK\n");
    } else if(strncmp(cmd, "REJECT ", 7) == 0) {
        RejectRule r;
        if(parse_step(cmd + 7, &r)) {
            pthread_mutex_lock(&g_lock);
            g_oneshot_rule = r;
            pthread_mutex_unlock(&g_lock);
            control_reply(fd, "OK\n");
        } else {
            control_reply(fd, "ERR bad step\n");
        }
    } else if(strncmp(cmd, "MAXSLEEP ", 9) == 0) {
        pthread_mutex_lock(&g_lock);
        g_max_sleep_ms = (unsigned)strtoul(cmd + 9, NULL, 10);
        pthread_mutex_unlock(&g_lock);
        control_reply(fd, "OK\n");
    } else {
        control_reply(fd, "ERR unknown command\n");
    }
}

static void* control_thread(void* arg) {
    int server_fd = *(int*)arg;
    for(;;) {
        int fd = accept(server_fd, NULL, NULL);
        if(fd < 0) continue;
        char line[128];
        size_t len = 0;
        for(;;) {
            char c;
            ssize_t n = read(fd, &c, 1);
            if(n <= 0) break;
            if(c == '\r') continue;
            if(c == '\n') {
                line[len] = '\0';
                control_command(fd, line);
                len = 0;
            } else if(len + 1 < sizeof(line)) {
                line[len++] = c;
            }
        }
        close(fd);
    }
    return NULL;
}

/* ── Main ─────────────────────────────────────────────────────────── */

static void on_sigint(int sig) { (void)sig; s_shutdown = 1; }

int main(int argc, char* argv[]) {
    uint16_t port = DEFAULT_PORT;
    int control_port = -1;      /* -1 = HWP port + 1 */
    bool control_enabled = true;
    /* Default to mainnet so the SDK's integration tests (which use
     * COIN_TYPE_MAINNET) work without override. Spawn a second instance
     * with --coin 1 for testnet coverage. */
    uint32_t coin_type = ORCHARD_SIGNER_COIN_MAINNET;

    const char* env_reject = getenv("VDEV_REJECT_AT");
    if(env_reject && !parse_step(env_reject, &g_static_rule)) {
        fprintf(stderr, "bad VDEV_REJECT_AT: %s\n", env_reject);
        return 2;
    }
    const char* env_sleep = getenv("VDEV_MAX_SLEEP_MS");
    if(env_sleep) g_max_sleep_ms = (unsigned)strtoul(env_sleep, NULL, 10);

    for(int i = 1; i < argc; i++) {
        if(strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = (uint16_t)atoi(argv[++i]);
        } else if(strcmp(argv[i], "--coin") == 0 && i + 1 < argc) {
            coin_type = (uint32_t)atoi(argv[++i]);
            if(coin_type != ORCHARD_SIGNER_COIN_MAINNET &&
               coin_type != ORCHARD_SIGNER_COIN_TESTNET) {
                fprintf(stderr, "--coin must be 133 (mainnet) or 1 (testnet)\n");
                return 2;
            }
        } else if(strcmp(argv[i], "--control-port") == 0 && i + 1 < argc) {
            control_port = atoi(argv[++i]);
        } else if(strcmp(argv[i], "--no-control") == 0) {
            control_enabled = false;
        } else if(strcmp(argv[i], "--reject-at") == 0 && i + 1 < argc) {
            if(!parse_step(argv[++i], &g_static_rule)) {
                fprintf(stderr, "bad --reject-at: %s\n", argv[i]);
                return 2;
            }
        } else if(strcmp(argv[i], "--max-sleep-ms") == 0 && i + 1 < argc) {
            g_max_sleep_ms = (unsigned)strtoul(argv[++i], NULL, 10);
        } else {
            fprintf(stderr,
                    "usage: %s [--port PORT] [--coin 133|1] [--control-port PORT | --no-control]\n"
                    "          [--reject-at output:N|memo:N|totals|confirm] [--max-sleep-ms MS]\n",
                    argv[0]);
            return 2;
        }
    }

    signal(SIGPIPE, SIG_IGN);
    /* No SA_RESTART: a signal has to interrupt the blocking accept() below,
     * or the process would only notice it at the next connection. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigint;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    wallet_test_init();

    int server_fd = tcp_listen(port);
    if(server_fd < 0) return 1;
    fprintf(stderr, "[hwp] Virtual device listening on port %d (coin_type=%u)\n",
            port, (unsigned)coin_type);

    static int control_fd = -1;
    if(control_enabled) {
        if(control_port < 0) control_port = port + 1;
        control_fd = control_listen((uint16_t)control_port);
        if(control_fd < 0) return 1;
        pthread_t th;
        if(pthread_create(&th, NULL, control_thread, &control_fd) != 0) return 1;
        pthread_detach(th);
        fprintf(stderr, "[hwp] Control port on 127.0.0.1:%d\n", control_port);
    }

    while(!s_shutdown) {
        int client_fd = tcp_accept(server_fd);
        if(client_fd < 0) continue;
        fprintf(stderr, "[hwp] Client connected\n");

        /* static: the session embeds the signer context (memo pool) and the
         * dispatcher embeds a full RX frame — keep both off the stack. */
        static Session s;
        memset(&s, 0, sizeof(s));
        s.client_fd = client_fd;
        s.coin_type = coin_type;
        s.testnet = (coin_type == 1);
        /* The network is a property of the device, fixed here once. */
        orchard_signer_init(&s.signer, coin_type);
        derive_keys(&s);
        g_output_calls = 0;
        g_memo_calls = 0;
        ui_log("session event=open");

        static HwpDispatcher d;
        memset(&d, 0, sizeof(d));
        d.io = (HwpDispatcherIo){
            .serial_drain = cb_serial_drain,
            .serial_send  = cb_serial_send,
            .get_tick_ms  = cb_tick_ms,
            .sleep_ms     = cb_sleep_ms,
            .should_exit  = cb_should_exit,
        };
        d.ui = (HwpDispatcherUi){
            .review_output = cb_review_output,
            .review_totals = cb_review_totals,
            .review_memo   = cb_review_memo,
            .confirm_tx    = cb_confirm_tx,
            .network_error = cb_network_error,
            .phase_update  = cb_phase,
            .progress      = cb_progress,
        };
        d.keys = (HwpDispatcherKeys){
            .ak       = s.ak,
            .nk       = s.nk,
            .rivk     = s.rivk,
            .ask      = s.ask,
        };
        d.signer   = &s.signer;
        d.testnet  = s.testnet;
        d.user_ctx = &s;

        HwpDispatchResult res = hwp_dispatcher_run(&d);
        if(res == HWP_DISP_FATAL) {
            fprintf(stderr, "[hwp] dispatcher refused to start (missing callback or key)\n");
        }

        tcp_close(client_fd);
        orchard_signer_reset(&s.signer);
        memzero(s.ask, sizeof(s.ask));
        ui_log("session event=close");
        fprintf(stderr, "[hwp] Client disconnected\n");
    }

    tcp_close(server_fd);
    return 0;
}
