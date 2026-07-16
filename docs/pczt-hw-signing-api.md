# PCZT Hardware Wallet Signing — Upstream API Usage

## Summary

The `zcash-hw-wallet-sdk` demonstrates that the PCZT external signing APIs published in the `pczt` crate (0.8.0-rc.1) are sufficient for complete hardware wallet integration — no additional changes to upstream crates are needed.

This document describes which APIs are used and how they enable the hardware wallet signing workflow.

## APIs Used

### 1. `Signer::shielded_sighash()` → `[u8; 32]`

**Source:** `pczt/src/roles/signer/mod.rs` (added in [`feefa606`](https://github.com/zcash/librustzcash/commit/feefa606))

Returns the ZIP-244 shielded sighash computed during `Signer::new()`. The hardware wallet needs this value to produce a RedPallas spend authorization signature.

```rust
let signer = pczt::roles::signer::Signer::new(proven_pczt)?;
let sighash = signer.shielded_sighash(); // [u8; 32]
// → sent to hardware device as part of SignRequest
```

### 2. `Signer::apply_orchard_signature(index, signature)`

**Source:** `pczt/src/roles/signer/mod.rs` (added in [`feefa606`](https://github.com/zcash/librustzcash/commit/feefa606))

Applies an externally-produced RedPallas signature to a specific Orchard action. This is the counterpart to `sign_orchard()` which signs internally with a local `ask`.

```rust
// Receive signature from hardware device
let sig_bytes: [u8; 64] = device_response.signature;
let sig = redpallas::Signature::<SpendAuth>::from(sig_bytes);

// Apply to the PCZT
signer.apply_orchard_signature(action_index, sig)?;
```

The method internally validates rk consistency and updates the transaction modifiability flags, providing the same safety guarantees as `sign_orchard()`.

### 3. `low_level_signer::Signer::sign_orchard_with(callback)`

**Source:** `pczt/src/roles/low_level_signer/mod.rs`

Provides callback access to `&mut orchard::pczt::Bundle`, enabling the SDK to read action data (alpha, rk, nullifier, cv_net, cmx, encrypted notes) through the orchard crate's public getters. This is needed for:

- Identifying which actions require hardware signatures (alpha present, sig absent)
- Extracting ZIP-244 action data for on-device sighash verification
- Reading rk values for post-signature verification

```rust
let temp_signer = low_level_signer::Signer::new(pczt);
temp_signer.sign_orchard_with(|_pczt, bundle, _tx_modifiable| {
    for action in bundle.actions() {
        let alpha = action.spend().alpha();       // Option<Scalar>
        let rk = action.spend().rk();             // VerificationKey<SpendAuth>
        let cv_net = action.cv_net();             // ValueCommitment
        let enc_note = action.output().encrypted_note(); // TransmittedNoteCiphertext
        // ... extract data for device communication
    }
    Ok(())
})?;
```

## Complete Hardware Wallet Signing Flow

Using only upstream APIs, the SDK implements this workflow:

```
1. Parse PCZT                     Pczt::parse()
2. Extract TxMeta                 Pczt::into_effects() + TxIdDigester
3. Validate network               BranchId::try_from(consensus_branch_id)
4. Generate Orchard proof          Prover::new() + create_orchard_proof()
5. Initialize Signer              Signer::new() — computes sighash
6. Read sighash                   signer.shielded_sighash()
7. Read action data                low_level_signer::sign_orchard_with()
                                   + sign_ironwood_with() (NU6.3 pool)
8. Send to device for ZIP-244      HWP TX_OUTPUT messages
   sighash verification
9. Sign on device                  HWP SIGN_REQ/SIGN_RSP
10. Verify signature               reddsa::VerificationKey::verify()
11. Apply signature to PCZT        signer.apply_orchard_signature(i, sig)
                                   / apply_ironwood_signature(i, sig)
12. Finalize                       signer.finish() → signed Pczt
```

No shadow deserialization, no `pub(crate)` workarounds, no patched crates.

## Current Situation

The external-signing APIs shipped on crates.io starting with `pczt` 0.6.0.
The **Ironwood (NU6.3) PCZT v2 support** — the `ironwood` bundle field,
`sign_ironwood_with`, `apply_ironwood_signature`, `create_ironwood_proof`,
and the v6 sighash plumbing — shipped with **`pczt` 0.8.0-rc.1**, alongside
the matching `orchard 0.15.0`, `zcash_primitives 0.29.0`, and
`zcash_protocol 0.10.0` releases of the NU6.3 activation stack (mainnet
~2026-07-21).

The SDK builds against those published releases directly: no
`[patch.crates-io]` table and no librustzcash git checkout are required.
The `librustzcash` submodule in this repository is retained for reference
only. Everything this SDK needs for complete hardware-wallet integration —
Orchard and Ironwood alike — is available on crates.io.
