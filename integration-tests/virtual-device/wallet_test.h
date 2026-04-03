/**
 * Test wallet — hardcoded BIP39 seed for deterministic key derivation.
 *
 * Uses the "abandon abandon ... about" mnemonic (same as test_vectors.h).
 * Replaces the NVS-based wallet.c from ESP32 firmware.
 */
#pragma once
#include <stdint.h>
#include "orchard_signer.h"

/** Initialize crypto subsystem (pallas_init + Sinsemilla S-table). */
void wallet_test_init(void);

/** Derive FVK (ak||nk||rivk, 96 bytes) for the given coin_type. */
int wallet_test_get_fvk(uint8_t fvk_out[96], uint32_t coin_type);

/** Sign via OrchardSignerCtx (enforces ZIP-244 verification). */
int wallet_test_sign(const OrchardSignerCtx *ctx,
                     const uint8_t sighash[32], const uint8_t alpha[32],
                     uint8_t sig_out[64], uint8_t rk_out[32],
                     uint32_t coin_type);
