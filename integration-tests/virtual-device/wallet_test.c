#include "wallet_test.h"
#include "pallas.h"
#include "orchard.h"
#include "redpallas.h"
#include "memzero.h"
#include "test_vectors.h"
#include "sinsemilla_s.h"
#include <string.h>
#include <stdio.h>

/* Sinsemilla S-table lookup (from embedded header) */
static bool sinsemilla_lookup(uint32_t index, uint8_t buf_out[64], void *ctx)
{
    (void)ctx;
    if (index >= 1024) return false;
    /* Decompress: SINSEMILLA_S_COMPRESSED is 32 bytes per point.
     * Copy compressed x-coordinate, pallas_point_decompress handles the rest. */
    memcpy(buf_out, SINSEMILLA_S_COMPRESSED[index], 32);
    memset(buf_out + 32, 0, 32);
    return true;
}

void wallet_test_init(void)
{
    pallas_init();
    pallas_set_sinsemilla_lookup(sinsemilla_lookup, NULL);
    fprintf(stderr, "[wallet] Initialized with hardcoded test seed\n");
}

int wallet_test_get_fvk(uint8_t fvk_out[96], uint32_t coin_type)
{
    fprintf(stderr, "[wallet] Deriving FVK (coin_type=%u)...\n", (unsigned)coin_type);

    uint8_t sk[32];
    orchard_derive_account_sk(zip32_seed, coin_type, 0, sk);

    uint8_t ask[32], nk[32], rivk[32];
    orchard_derive_keys(sk, ask, nk, rivk);
    memzero(sk, sizeof(sk));

    uint8_t ak[32];
    redpallas_derive_ak(ask, ak);
    memzero(ask, sizeof(ask));

    memcpy(fvk_out,      ak,   32);
    memcpy(fvk_out + 32, nk,   32);
    memcpy(fvk_out + 64, rivk, 32);

    memzero(ak, sizeof(ak));
    memzero(nk, sizeof(nk));
    memzero(rivk, sizeof(rivk));

    fprintf(stderr, "[wallet] FVK derived OK\n");
    return 0;
}

int wallet_test_sign(const OrchardSignerCtx *ctx,
                     const uint8_t sighash[32], const uint8_t alpha[32],
                     uint8_t sig_out[64], uint8_t rk_out[32],
                     uint32_t coin_type)
{
    fprintf(stderr, "[wallet] Signing (coin_type=%u)...\n", (unsigned)coin_type);

    uint8_t sk[32];
    orchard_derive_account_sk(zip32_seed, coin_type, 0, sk);

    uint8_t ask[32], nk_discard[32], rivk_discard[32];
    orchard_derive_keys(sk, ask, nk_discard, rivk_discard);
    memzero(sk, sizeof(sk));
    memzero(nk_discard, sizeof(nk_discard));
    memzero(rivk_discard, sizeof(rivk_discard));

    OrchardSignerError err = orchard_signer_sign(ctx, sighash, ask, alpha, sig_out, rk_out);
    memzero(ask, sizeof(ask));

    if (err != SIGNER_OK) {
        fprintf(stderr, "[wallet] Sign FAILED (err=%d)\n", err);
        return -1;
    }
    fprintf(stderr, "[wallet] Sign OK\n");
    return 0;
}
