/**
 * Virtual HWP Device — TCP server for integration testing.
 *
 * Implements the full HWP v2 protocol over TCP, using libzcash-orchard-c
 * for crypto operations. Adapted from zcash-esp32/main/main.c.
 *
 * Usage: ./virtual-device [--port PORT]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "hwp.h"
#include "orchard_signer.h"
#include "tcp_transport.h"
#include "wallet_test.h"

#define DEFAULT_PORT 9999

static uint8_t tx_buf[HWP_MAX_FRAME];
static HwpParser rx_parser;
static OrchardSignerCtx signer_ctx;

/* ── Helpers ──────────────────────────────────────────────────────── */

static void send_frame(int fd, uint8_t seq, uint8_t msg_type,
                       const uint8_t *payload, uint16_t payload_len)
{
    size_t len = hwp_encode(tx_buf, seq, msg_type, payload, payload_len);
    tcp_send(fd, tx_buf, len);
}

static void send_error(int fd, uint8_t seq, HwpErrorCode code, const char *msg)
{
    fprintf(stderr, "[hwp] ERR 0x%02x: %s\n", code, msg ? msg : "");
    size_t len = hwp_encode_error(tx_buf, seq, code, msg);
    tcp_send(fd, tx_buf, len);
}

static void send_ping(int fd)
{
    send_frame(fd, 0x01, HWP_MSG_PING, NULL, 0);
    fprintf(stderr, "[hwp] PING sent\n");
}

/* ── Handlers (adapted from zcash-esp32/main/main.c) ─────────────── */

static void handle_fvk_req(int fd, uint8_t seq, const uint8_t *payload, uint16_t payload_len)
{
    /* Parse coin_type from payload (4 bytes LE), or default */
    uint32_t coin_type = 1; /* default: testnet */
    if (payload_len >= 4) {
        coin_type = (uint32_t)payload[0]
                  | ((uint32_t)payload[1] << 8)
                  | ((uint32_t)payload[2] << 16)
                  | ((uint32_t)payload[3] << 24);
    }

    fprintf(stderr, "[hwp] FVK_REQ (seq=%d, coin_type=%u)\n", seq, (unsigned)coin_type);
    signer_ctx.coin_type = coin_type;

    uint8_t fvk[96];
    if (wallet_test_get_fvk(fvk, coin_type) != 0) {
        send_error(fd, seq, HWP_ERR_SIGN_FAILED, "key derivation failed");
        return;
    }
    send_frame(fd, seq, HWP_MSG_FVK_RSP, fvk, 96);
    fprintf(stderr, "[hwp] FVK_RSP sent (coin_type=%u)\n", (unsigned)coin_type);
}

static void handle_tx_output(int fd, uint8_t seq, const uint8_t *payload, uint16_t payload_len)
{
    HwpTxOutput out;
    if (!hwp_parse_tx_output(payload, payload_len, &out)) {
        send_error(fd, seq, HWP_ERR_BAD_FRAME, "invalid tx_output payload");
        return;
    }

    OrchardSignerError serr;

    /* Metadata message (output_index == 0xFFFF) */
    if (out.output_index == HWP_TX_META_INDEX) {
        serr = orchard_signer_feed_meta(&signer_ctx, out.output_data,
                                         out.output_data_len, out.total_outputs);
        if (serr == SIGNER_ERR_NETWORK_MISMATCH) {
            fprintf(stderr, "[hwp] Network mismatch: session=%u vs meta=%u\n",
                    (unsigned)signer_ctx.coin_type, (unsigned)signer_ctx.tx_meta.coin_type);
            send_error(fd, seq, HWP_ERR_NETWORK_MISMATCH, "coin_type mismatch");
            orchard_signer_reset(&signer_ctx);
            return;
        }
        if (serr != SIGNER_OK) {
            send_error(fd, seq, HWP_ERR_BAD_FRAME, "invalid tx metadata");
            orchard_signer_reset(&signer_ctx);
            return;
        }
        fprintf(stderr, "[hwp] TX metadata received, expecting %d actions\n", out.total_outputs);
        send_frame(fd, seq, HWP_MSG_TX_OUTPUT_ACK, NULL, 0);
        return;
    }

    /* Sentinel (output_index == total_outputs): expected sighash */
    if (out.output_index == out.total_outputs) {
        if (out.output_data_len != 32) {
            send_error(fd, seq, HWP_ERR_BAD_FRAME, "sentinel must be 32 bytes");
            orchard_signer_reset(&signer_ctx);
            return;
        }

        serr = orchard_signer_verify(&signer_ctx, out.output_data);
        if (serr == SIGNER_ERR_SIGHASH_MISMATCH) {
            fprintf(stderr, "[hwp] ZIP-244 sighash MISMATCH\n");
            send_error(fd, seq, HWP_ERR_SIGHASH_MISMATCH, "ZIP-244 sighash mismatch");
            return;
        }
        if (serr != SIGNER_OK) {
            fprintf(stderr, "[hwp] Sighash verify failed (err=%d)\n", serr);
            send_error(fd, seq, HWP_ERR_INVALID_STATE, "sighash verify failed");
            orchard_signer_reset(&signer_ctx);
            return;
        }
        fprintf(stderr, "[hwp] ZIP-244 sighash verified — signing authorized\n");
        send_frame(fd, seq, HWP_MSG_TX_OUTPUT_ACK, NULL, 0);
        return;
    }

    /* Normal action data (output_index 0..N-1) */
    serr = orchard_signer_feed_action(&signer_ctx, out.output_data, out.output_data_len);
    if (serr != SIGNER_OK) {
        const char *msg = (serr == SIGNER_ERR_BAD_STATE) ? "unexpected action" : "invalid action data";
        HwpErrorCode code = (serr == SIGNER_ERR_BAD_STATE) ? HWP_ERR_INVALID_STATE : HWP_ERR_BAD_FRAME;
        send_error(fd, seq, code, msg);
        orchard_signer_reset(&signer_ctx);
        return;
    }
    fprintf(stderr, "[hwp] Action %d/%d hashed\n", out.output_index + 1, out.total_outputs);
    send_frame(fd, seq, HWP_MSG_TX_OUTPUT_ACK, NULL, 0);
}

static void handle_sign_req(int fd, uint8_t seq, const uint8_t *payload, uint16_t payload_len)
{
    HwpSignReq req;
    if (!hwp_parse_sign_req(payload, payload_len, &req)) {
        send_error(fd, seq, HWP_ERR_BAD_FRAME, "invalid sign_req payload");
        return;
    }

    fprintf(stderr, "[hwp] SIGN_REQ (amount=%llu, fee=%llu)\n",
            (unsigned long long)req.amount, (unsigned long long)req.fee);

    /* Check ZIP-244 verification */
    OrchardSignerError chk = orchard_signer_check(&signer_ctx, req.sighash);
    if (chk == SIGNER_ERR_NOT_VERIFIED) {
        send_error(fd, seq, HWP_ERR_INVALID_STATE, "sighash not verified");
        return;
    }
    if (chk == SIGNER_ERR_WRONG_SIGHASH) {
        send_error(fd, seq, HWP_ERR_SIGHASH_MISMATCH, "SignReq sighash mismatch");
        orchard_signer_reset(&signer_ctx);
        return;
    }

    uint32_t coin_type = signer_ctx.coin_type ? signer_ctx.coin_type : 1;
    uint8_t sig[64], rk[32];
    if (wallet_test_sign(&signer_ctx, req.sighash, req.alpha, sig, rk, coin_type) != 0) {
        send_error(fd, seq, HWP_ERR_SIGN_FAILED, "signing failed");
        return;
    }

    uint8_t rsp[96];
    memcpy(rsp, sig, 64);
    memcpy(rsp + 64, rk, 32);
    send_frame(fd, seq, HWP_MSG_SIGN_RSP, rsp, 96);
    fprintf(stderr, "[hwp] SIGN_RSP sent\n");
}

static void handle_abort(void)
{
    if (signer_ctx.state != SIGNER_IDLE) {
        fprintf(stderr, "[hwp] Session aborted\n");
        orchard_signer_reset(&signer_ctx);
    }
}

/* ── Main ────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    uint16_t port = DEFAULT_PORT;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = (uint16_t)atoi(argv[++i]);
        }
    }

    signal(SIGPIPE, SIG_IGN); /* ignore broken pipe */

    wallet_test_init();
    orchard_signer_init(&signer_ctx);

    int server_fd = tcp_listen(port);
    if (server_fd < 0) return 1;
    fprintf(stderr, "[hwp] Virtual device listening on port %d\n", port);

    for (;;) {
        int client_fd = tcp_accept(server_fd);
        if (client_fd < 0) continue;
        fprintf(stderr, "[hwp] Client connected\n");

        /* Send PING on connect (like ESP32 on USB host connect) */
        orchard_signer_reset(&signer_ctx);
        send_ping(client_fd);

        /* Frame processing loop */
        for (;;) {
            HwpFeedResult res = tcp_recv_frame(client_fd, &rx_parser);
            if (res == HWP_FEED_CRC_ERROR) {
                send_error(client_fd, rx_parser.frame.seq, HWP_ERR_BAD_FRAME, "CRC mismatch");
                continue;
            }
            if (res != HWP_FEED_FRAME_READY) break; /* connection closed */

            HwpFrame *f = &rx_parser.frame;
            fprintf(stderr, "[hwp] Frame: type=0x%02x seq=%d len=%d\n", f->type, f->seq, f->payload_len);

            switch (f->type) {
            case HWP_MSG_PING:
                send_frame(client_fd, f->seq, HWP_MSG_PONG, NULL, 0);
                break;
            case HWP_MSG_PONG:
                fprintf(stderr, "[hwp] Handshake complete\n");
                break;
            case HWP_MSG_FVK_REQ:
                handle_fvk_req(client_fd, f->seq, f->payload, f->payload_len);
                break;
            case HWP_MSG_TX_OUTPUT:
                handle_tx_output(client_fd, f->seq, f->payload, f->payload_len);
                break;
            case HWP_MSG_SIGN_REQ:
                handle_sign_req(client_fd, f->seq, f->payload, f->payload_len);
                break;
            case HWP_MSG_ABORT:
                handle_abort();
                break;
            default:
                send_error(client_fd, f->seq, HWP_ERR_UNKNOWN, "unsupported msg type");
                break;
            }
        }

        tcp_close(client_fd);
        orchard_signer_reset(&signer_ctx);
        fprintf(stderr, "[hwp] Client disconnected\n");
    }

    return 0;
}
