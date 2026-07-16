# zcash-hw-wallet-sdk

> **WARNING: This is a Proof of Concept (POC) and is NOT production-ready.**
>
> This code has **not undergone a formal security audit**. It is published for
> educational and research purposes to demonstrate that PCZT-based hardware
> wallet signing is feasible for Zcash Orchard shielded transactions.
>
> **Before using this SDK in any production or mainnet context:**
> - A comprehensive external security audit by a qualified cryptography/blockchain
>   security firm is **required**.
> - The HWP protocol, signature verification logic, and key handling must be
>   independently reviewed.
> - Do **not** use this with real funds until it has been audited.
>
> If you are interested in sponsoring or conducting an audit, please open an issue.

Transport-agnostic Rust SDK for signing Zcash Orchard shielded + Transparent transactions via hardware wallets using the [PCZT](https://zips.z.cash/zip-0320) (Partially Created Zcash Transaction) standard.

## The Problem

Zcash Orchard has no standardized way for hardware wallets to participate in shielded transaction signing. Existing approaches are tightly coupled to specific hardware and don't use PCZT. Every new hardware wallet project has to solve this independently.

## The Insight

The **only** operations that require spending keys are the RedPallas spend authorization signature (Orchard, ~5 seconds on a microcontroller) and the ECDSA signature (Transparent, ~200ms). Everything else — proof generation, blockchain sync, transaction construction — can be done with the full viewing key alone. PCZT is the ideal vehicle for this split because it already models multi-party transaction construction.

This SDK adds the **hardware signer role** to the PCZT ecosystem.

## Architecture

```
+-----------------------------------------------------+
|                  Wallet Application                 |
|              (Zashi, YWallet, custom)               |
+-----------------------------------------------------+
|                zcash-hw-wallet-sdk                  |
|  +-------------+  +------------+  +---------------+ |
|  |    PCZT     |  | Hardware   |  | Transport     | |
|  |  Workflow   |  | Signer     |  | Serial/Ledger/| |
|  |  Manager    |  | Trait      |  | QR            | |
|  +-------------+  +------------+  +---------------+ |
+-----------------------------------------------------+
|            librustzcash (pczt, orchard)             |
+-----------------------------------------------------+
        |                              |
        v                              v
  lightwalletd                   Hardware Device
  (blockchain)              (any compatible device)
```

## Quick Start

Add the dependency:

```toml
[dependencies]
zcash-hw-wallet-sdk = "0.1"
```

### Sign a transaction with a serial device

```rust
use zcash_hw_wallet_sdk::PcztHardwareSigning;

// Connect to a hardware signing device over USB serial.
// The coin_type selects the network: 133 = mainnet, 1 = testnet.
let signer = zcash_hw_wallet_sdk::signer::connect_serial("/dev/ttyACM0", 1)?;

// Sign a PCZT (from zcash_client_backend::create_pczt_from_proposal)
let mut workflow = PcztHardwareSigning::new(signer);
let result = workflow.sign(pczt_bytes)?;

// result.signed_pczt -> extract_and_store_transaction_from_pczt()
```

### Sign a transaction with a Ledger device (PCZT/HWP Wrapper)

```toml
[dependencies]
zcash-hw-wallet-sdk = { version = "0.1", features = ["ledger"] }
```

```rust
use zcash_hw_wallet_sdk::PcztHardwareSigning;

// Auto-detect the first connected Ledger (Zcash Orchard app must be open)
let signer = zcash_hw_wallet_sdk::signer::connect_ledger(133)?;

let mut workflow = PcztHardwareSigning::new(signer);
let result = workflow.sign(pczt_bytes)?;
```

For development with the Speculos emulator:

```rust
let signer = zcash_hw_wallet_sdk::signer::connect_speculos("127.0.0.1:9999", 1)?;
```

### Implement support for your own hardware

To add Zcash Orchard support to **any** hardware wallet:

1. `cargo add zcash-hw-wallet-sdk`
2. Implement the `HardwareSigner` trait (3 required methods; 3 more have defaults)
3. Done

```rust
use zcash_hw_wallet_sdk::*;

struct MyDevice { /* your transport handle */ }

impl HardwareSigner for MyDevice {
    fn coin_type(&self) -> u32 {
        133 // mainnet (1 = testnet) — drives ZIP-32 derivation + network checks
    }

    fn export_fvk(&mut self) -> Result<ExportedFvk> {
        // Read FVK components (ak, nk, rivk) from your device
        todo!()
    }

    fn sign_action(&mut self, request: &SignRequest) -> Result<SignResponse> {
        // Send sighash + alpha to device, receive signature + rk
        todo!()
    }

    // Provided defaults you can override:
    //   confirm_transaction(details)          -> Ok(true)  (auto-confirm, headless)
    //   verify_transaction(...)               -> Ok(())    (no on-device verification)
    //   sign_transparent_input(req, input)    -> Err(UnsupportedPool)
}

// Use it
let mut workflow = PcztHardwareSigning::new(MyDevice { /* ... */ });
let result = workflow.sign(pczt_bytes)?;
```

## Signing Flow

The SDK orchestrates the full PCZT pipeline automatically:

```
1. Parse PCZT           Deserialize the PCZT created from a proposal
                        (uses FVK only, spending key not needed)
         |
2. Orchard Proof        Generate Halo2 zero-knowledge proof
                        (ProvingKey::build + create_orchard_proof)
         |
3. Compute Sighash      Initialize the Signer role, extract the
                        32-byte shielded transaction hash
         |
4. Identify Actions     Find Orchard actions that need hardware
                        signatures (alpha present, sig absent)
         |
5. On-device verify    Send each action's ZIP-244 data + full note
                        plaintext (incl. memo) to the device via
                        TxOutput messages (pool-tagged v6 payload,
                        1416 bytes per action).
                        Device independently recomputes sighash, cmx,
                        enc_ciphertext, epk, transparent digest, fee,
                        and drives per-output + fee user confirmation
                        before allowing signing.
         |
6. User Confirmation    Optional: display TxDetails on device screen
         |
7. Hardware Signing     For each action, send SignRequest to device:
                        - sighash (32 bytes, same for all actions)
                        - alpha (32 bytes, unique per action)
                        - amount, fee, recipient (for display)
                        Device returns SignResponse:
                        - signature (64 bytes, RedPallas)
                        - rk (32 bytes, verification key)
         |
8. Verify Signatures    For each response:
                        - Check rk matches PCZT action
                        - Cryptographically verify RedPallas sig
         |
9. Inject Signatures    Call apply_orchard_signature() /
                        apply_ironwood_signature() per action (by pool)
         |
10. Return Signed PCZT  Serialize and return for tx extraction
```

The caller then passes the signed PCZT to `extract_and_store_transaction_from_pczt` and broadcasts via lightwalletd.

## Modules

### `traits` -- `HardwareSigner`

The core trait any hardware device must implement:

| Method | Purpose | Called |
|---|---|---|
| `coin_type()` | SLIP-44 coin type the signer operates on (133=mainnet, 1=testnet); drives ZIP-32 derivation and network validation | Required; whenever the network matters |
| `export_fvk()` | Export Orchard full viewing key (ak, nk, rivk) for the signer's `coin_type` | Once, during pairing |
| `sign_action(request)` | Sign a single Orchard/Ironwood action given sighash + alpha | Once per action |
| `confirm_transaction(details)` | Display tx on device for user confirmation | Once per tx (optional, default: auto-confirm) |
| `verify_transaction(meta, actions, sighash, t_inputs, t_outputs)` | Send tx metadata + shielded actions + transparent flow for on-device sighash + cmx + enc_ciphertext + fee verification | Once per tx (optional, default: no-op) |
| `sign_transparent_input(request, input_data)` | Sign a transparent input on-device (ECDSA secp256k1) | Once per transparent input (optional, default: `Err(UnsupportedPool)`) |

### `workflow` -- `PcztHardwareSigning<S>`

The orchestrator that handles the full signing pipeline. Accepts any `S: HardwareSigner`.

| Method | Description |
|---|---|
| `new(signer)` | Create workflow — the network is derived from `signer.coin_type()` |
| `sign(pczt_bytes)` | Sign a PCZT, return `SigningResult` |
| `sign_with_details(pczt_bytes, details)` | Sign with device-side user confirmation |
| `signer()` / `signer_mut()` / `into_signer()` | Access or reclaim the wrapped signer |

### `signer` -- `DeviceSigner<T>`

A ready-to-use `HardwareSigner` implementation that communicates with any HWP-compatible device over any `Transport`.

| Constructor / method | Feature | Description |
|---|---|---|
| `DeviceSigner::new(transport, coin_type)` | — | Connect and handshake (if required by transport) |
| `DeviceSigner::new_no_handshake(transport, coin_type)` | — | Skip handshake (already done) |
| `DeviceSigner::new_with_pinned_pubkey(transport, coin_type, pubkey)` | — | Connect and verify the device identity against a pinned pubkey (attestation) |
| `pair()` / `attest(pinned_pubkey)` | — | First-pairing: fetch the device identity pubkey to store/pin — / — re-run a challenge-response attestation mid-session |
| `connect_serial(path, coin_type)` | `serial` | Convenience: open USB CDC serial + handshake |
| `connect_ledger(coin_type)` | `ledger` | Convenience: find first Ledger USB HID device |
| `connect_speculos(addr, coin_type)` | `ledger` | Convenience: connect to Speculos emulator via TCP |

### `transport` -- Transport Layer

Pluggable communication channels:

| Transport | Feature flag | Use case | Status |
|---|---|---|---|
| `SerialTransport` | `serial` (default) | USB CDC — microcontrollers, Arduino, ESP32 | Tested |
| `LedgerTransport` | `ledger` | USB HID — Ledger Nano S+/X/Stax/Flex | Tested |
| `SpeculosTransport` | `ledger` | TCP — Ledger Speculos emulator | Tested |
| `TcpTransport` | `tcp` | Raw TCP — virtual device, testing | Tested |
| `QrTransport` | `qr` | Animated QR codes — air-gapped devices | **Untested** |

> **Note:** The QR transport has not been tested with a real device yet. It is included as a design reference. Use at your own risk.

All transports implement the `Transport` trait:

```rust
pub trait Transport {
    fn send(&mut self, data: &[u8]) -> Result<()>;
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize>;
    fn requires_handshake(&self) -> bool { true }
    fn recv_exact(&mut self, buf: &mut [u8]) -> Result<()> { /* default: loop recv */ }
}
```

`requires_handshake()` controls whether the initial PING/PONG exchange is performed. Serial devices send a PING on boot and expect PONG before accepting commands. Ledger devices are passive (APDU request-response) and return `false`.

### `protocol` -- Hardware Wallet Protocol (HWP) v6

Binary framed protocol designed for constrained devices. v6 is the current feature tier (NU6.3 / Ironwood: pool-tagged action payloads, five-leaf sighash tree); earlier tiers layered in ZIP-244 sighash verification (v2), transparent digest verification + ECDSA signing (v3), Orchard cmx + per-action user confirmation + device attestation (v4), and on-device `enc_ciphertext` recomputation (memo binding) + explicit miner-fee confirmation (v5).

**Frame format:**

```
[MAGIC:1][VERSION:1][SEQ:1][TYPE:1][LENGTH:2 LE][PAYLOAD:N][CRC16:2 LE]
```

- Magic: `0xFB`
- Version: `0x02` (frame header version; the protocol-level "v3..v6" are feature tiers describing the payload semantics, not the byte at offset 1)
- CRC: CRC-16/CCITT (poly 0x1021, init 0xFFFF)
- Max payload: **2048 bytes** (raised in v5 to fit the memo-verifying action payload — up to 1416 B under v6 = pool tag + action + recipient + value + rseed + memo)

**Message types:**

| Type | Value | Direction | Description |
|---|---|---|---|
| `Ping` | 0x01 | Device -> Host | Keepalive / flow control |
| `Pong` | 0x02 | Host -> Device | Keepalive response |
| `FvkReq` | 0x03 | Host -> Device | Request full viewing key: `coin_type[4 LE]` (133=mainnet, 1=testnet) |
| `FvkRsp` | 0x04 | Device -> Host | FVK payload: `ak[32] \|\| nk[32] \|\| rivk[32]` |
| `SignReq` | 0x05 | Host -> Device | Sign request (see below) |
| `SignRsp` | 0x06 | Device -> Host | Signature: `sig[64] \|\| rk[32]` |
| `Error` | 0x07 | Device -> Host | Error code + message |
| `TxOutput` | 0x08 | Host -> Device | Tx metadata, action data, or sighash sentinel (discriminated by `output_index`) |
| `TxOutputAck` | 0x09 | Device -> Host | TxOutput acknowledged |
| `Abort` | 0x0A | Host -> Device | Cancel signing session |
| `TxTransparentInput` | 0x0B | Host -> Device | Transparent input for on-device digest verification |
| `TxTransparentOutput` | 0x0C | Host -> Device | Transparent output for on-device digest verification |
| `TransparentSignReq` | 0x0D | Host -> Device | Sign transparent input (ECDSA secp256k1) |
| `TransparentSignRsp` | 0x0E | Device -> Host | DER signature + sighash_type + compressed pubkey |
| `IdentityReq` | 0x0F | Host -> Device | Request device identity pubkey (first pairing) |
| `IdentityRsp` | 0x10 | Device -> Host | Identity pubkey: `device_pubkey[32]` |
| `AttestReq` | 0x11 | Host -> Device | Attestation challenge: `challenge[32]` |
| `AttestRsp` | 0x12 | Device -> Host | Attestation: `sig[64] \|\| device_pubkey[32]` (RedPallas, domain-separated) |

**FVK_REQ payload:**

```
coin_type[4 LE]    // 133 = mainnet, 1 = testnet
```

The `coin_type` tells the device which ZIP-32 derivation path to use (`m/32'/coin_type'/account'`). Empty payload accepted for backward compatibility (device uses its default).

**SIGN_REQ payload:**

```
sighash[32] || alpha[32] || amount[8 LE] || fee[8 LE] || recipient_len[1] || recipient[N]
```

**TX_OUTPUT payload — on-device sighash + cmx + enc_ciphertext + fee verification:**

```
output_index[2 LE] || total_outputs[2 LE] || action_data[N]
```

Three types of TxOutput messages are used, discriminated by `output_index`:

- `output_index = 0xFFFF` — **Transaction metadata**: `version[4] || version_group_id[4] || consensus_branch_id[4] || lock_time[4] || expiry_height[4] || orchard_flags[1] || value_balance[8 LE signed] || anchor[32] || transparent_sig_digest[32] || sapling_digest[32] || coin_type[4 LE]` (129 bytes, v5). The v6 (NU6.3/Ironwood) layout is 170 bytes — it inserts `ironwood_flags[1] || ironwood_value_balance[8 LE] || ironwood_anchor[32]` after the Orchard anchor; the device discriminates the tier by payload size.
- `output_index = 0..N-1` — **Action + full note plaintext**. For v6 transactions (the only kind produced post-NU6.3) the SDK emits the **pool-tagged 1416-byte payload**: `pool_tag[1] || cv_net[32] || nullifier[32] || rk[32] || cmx[32] || ephemeral_key[32] || enc_ciphertext[580] || out_ciphertext[80] || recipient[43] || value[8 LE] || rseed[32] || memo[512]`. The trailing 595 bytes (recipient + value + rseed + memo) let the device recompute both `cmx` (Sinsemilla) AND `enc_ciphertext` (ChaCha20-Poly1305 with `K_enc = BLAKE2b(epk‖[esk]·pk_d)`, esk derived on-chip from rseed+rho per ZIP-212). Closes both recipient-substitution and memo-substitution attacks. When the memo is not recoverable on the host side (`OVK::None` outputs) the pool-tagged **904-byte** cmx-only form is sent instead; the wallet's normal flow (`OvkPolicy::Sender`) does not use this fallback. For legacy v5 sessions the SDK sends the untagged 903-byte cmx-only payload (memo binding is exercised only under v6).
- `output_index = N` (sentinel): Expected 32-byte ZIP-244 sighash for device comparison. Triggers the per-output review loop on-device and then the fee-confirmation step (`get_fee` → user OK → `confirm_fee`) before final `verify()`.

**Error codes:**

| Code | Name | Description |
|---|---|---|
| 0x01 | `BadFrame` | CRC or format error (auto-retried) |
| 0x02 | `BadSighash` | Invalid sighash |
| 0x03 | `BadAlpha` | Invalid alpha randomizer |
| 0x04 | `BadAmount` | Invalid amount encoding |
| 0x05 | `NetworkMismatch` | Device on different network |
| 0x06 | `UserCancelled` | User rejected on device |
| 0x07 | `SignFailed` | Signing operation failed |
| 0x08 | `UnsupportedVersion` | Protocol version not supported |
| 0x09 | `SighashMismatch` | Device-computed sighash differs from companion |
| 0x0A | `InvalidState` | Unexpected message in current state |
| 0x0B | `TransparentDigestMismatch` | Device-computed transparent digest differs from companion |
| 0x0C | `SaplingNotEmpty` | `sapling_digest` ≠ ZIP-244 empty-bundle constant (Orchard-only invariant) |
| 0x0D | `NoteCommitmentMismatch` | Device-recomputed cmx ≠ action.cmx — recipient-substitution attempt |
| 0x0E | `RecipientMismatch` | SIGN_REQ.recipient (UA) does not match any action confirmed on-device |
| 0x0F | `MemoMismatch` | Device-recomputed enc_ciphertext (or epk) ≠ action — memo-substitution attempt |
| 0x10 | `BadPkD` | `pk_d` does not decode to a valid Pallas point |
| 0x11 | `FeeNotConfirmed` | `verify()` reached without user approving the on-device-computed fee |
| 0x12 | `FeeOverflow` | Transparent value sums or `value_balance` combine to an out-of-range fee |
| 0x13 | `FeeNegative` | `t_in + value_balance < t_out` — companion built an unbalanced bundle |

> The wire protocol (canonical definition in `libzcash-ironwood-c`'s `hwp.h`) defines codes `0x00` (`Unknown`) through `0x13`; the SDK's typed `ErrorCode` enum mirrors the full range. `UserCancelled`, `SighashMismatch`, `TransparentDigestMismatch`, `SaplingNotEmpty`, `NoteCommitmentMismatch`, and `RecipientMismatch` map to dedicated `HwSignerError` variants; the remaining codes surface as `HwSignerError::DeviceError` with the code name and the device's message string.

### `verify` -- Signature Verification

After receiving a signature from the device, the SDK verifies:

1. **RK match** -- the randomized verification key returned by the device matches the PCZT action's expected rk
2. **RedPallas verify** -- the signature is cryptographically valid against the sighash using `reddsa::VerificationKey<orchard::SpendAuth>`

This prevents both key confusion attacks and invalid signatures.

### `error` -- `HwSignerError`

Typed error enum covering all failure modes:

- **PCZT workflow**: `ProofFailed`, `SignerInitFailed`, `NoActionsToSign`, `ExtractionFailed`, `SaplingNotSupported`, `UnsupportedPool`
- **Signatures**: `RkMismatch`, `SignatureVerificationFailed`, `InvalidVerificationKey`, `TransparentSignatureVerificationFailed`
- **On-device verification**: `NoteCommitmentMismatch`, `RecipientMismatch`, `TransparentSighashMismatch`, `InvalidTransparentInputIndex`, `NetworkMismatch`
- **Device**: `DeviceError`, `UserCancelled`, `AttestationFailed`
- **Transport**: `TransportError`, `ConnectionFailed`, `Timeout`
- **Protocol**: `ProtocolError`, `CrcMismatch`, `UnsupportedVersion`, `UnknownMessageType`, `PayloadTooLarge`, `RecipientTooLong`, `MaxKeepaliveExceeded`, `SequenceMismatch`

## Types

### `SignRequest`

Sent to the hardware device for each Orchard action:

| Field | Type | Description |
|---|---|---|
| `sighash` | `[u8; 32]` | Transaction hash to sign (same for all actions) |
| `alpha` | `[u8; 32]` | Action randomizer for key rerandomization |
| `amount` | `u64` | Spend amount in zatoshis (for display) |
| `fee` | `u64` | Fee in zatoshis (for display) |
| `recipient` | `String` | Recipient address (for display) |
| `action_index` | `usize` | Index within the signing batch |
| `total_actions` | `usize` | Total actions to sign |

### `SignResponse`

Returned by the hardware device:

| Field | Type | Description |
|---|---|---|
| `signature` | `[u8; 64]` | RedPallas spend authorization signature |
| `rk` | `[u8; 32]` | Randomized verification key |

### `ActionData`

ZIP-244 action data + note plaintext sent to the device for on-device sighash + cmx + enc_ciphertext verification:

| Field | Type | Description |
|---|---|---|
| `pool` | `ShieldedPoolKind` | Shielded pool of the action (`Orchard = 0x00`, `Ironwood = 0x01`) — selects the digest tree and note-plaintext version on the device; emitted as the leading pool tag of the v6 wire format |
| `cv_net` | `[u8; 32]` | Value commitment |
| `nullifier` | `[u8; 32]` | Nullifier (used as `rho` for the output note's NoteCommit per Orchard's split-action design, AND as input to the on-chip esk derivation for memo verification) |
| `rk` | `[u8; 32]` | Randomized verification key |
| `cmx` | `[u8; 32]` | Extracted note commitment (the device verifies this matches `Extract_P(NoteCommit(g_d, pk_d, value, rho, psi))` recomputed from the trailing note plaintext) |
| `ephemeral_key` | `[u8; 32]` | Ephemeral public key (the device recomputes this as `[esk]·g_d` and constant-time compares against the on-action value) |
| `enc_ciphertext` | `Vec<u8>` | Encrypted note plaintext (580 bytes); the device recomputes this from the trailing plaintext via ChaCha20-Poly1305 and constant-time compares |
| `out_ciphertext` | `Vec<u8>` | Encrypted outgoing plaintext (80 bytes); used by the SDK to recover the memo via the device's OVK before transmission |
| `recipient` | `[u8; 43]` | **Output-note recipient** — raw 43-byte Orchard payment-address encoding (`d[11] || pk_d[32]`). The device recomputes `cmx` + `enc_ciphertext` from this and rejects mismatches; the UI then encodes it as a Bech32m UA via `orchard_encode_ua_raw` and shows it to the user for confirmation. |
| `value` | `u64` | **Output-note value** in zatoshis. Verified via cmx + enc_ciphertext; displayed to the user. |
| `rseed` | `[u8; 32]` | **Output-note random seed**. Required input to the device's `psi` / `rcm` derivation per Orchard `§ 4.7.3` **and** to the ZIP-212 esk derivation used for memo verification. |
| `memo` | `Option<[u8; 512]>` | **Output-note memo plaintext** (ZIP-302). Recovered on the host side by trial-decrypting `out_ciphertext` with the device's external OVK (`try_output_recovery_with_ovk`). Sent as the trailing 512 bytes of the memo-verifying wire format so the device can recompute `enc_ciphertext` and reject any host that embeds a different memo on chain than what the user is shown. `None` for `OVK::None` outputs — falls back to the cmx-only wire format for that action. |

`esk` is never part of the struct or the wire — the device derives it on-chip from `rseed + rho` per ZIP-212.

Wire formats: for v6 (NU6.3/Ironwood) transactions `ActionData::serialize_v6()` emits the pool-tagged **1416-byte** memo-verifying payload, or the pool-tagged **904-byte** cmx-only form when `memo` is `None`. For legacy v5 transactions the SDK emits the **903-byte** v4 cmx-only payload via `ActionData::serialize()`. `DeviceSigner` selects the format from `TxMeta::is_v6()`.

The trailing `(recipient, value, rseed, memo)` block is what closes both the recipient-substitution attack AND the memo-substitution attack a hostile companion would otherwise mount inside the Orchard bundle. Without `recipient/value/rseed` the device cannot verify cmx; without `memo` it cannot verify enc_ciphertext. With both, it recomputes Sinsemilla-NoteCommit + ChaCha20-Poly1305 on-device and rejects any swap.

### `ExportedFvk`

Full viewing key components from the device:

| Field | Type | Description |
|---|---|---|
| `ak` | `[u8; 32]` | Spend validating key |
| `nk` | `[u8; 32]` | Nullifier deriving key |
| `rivk` | `[u8; 32]` | Randomized internal viewing key |

## Feature Flags

| Feature | Default | Dependencies | Description |
|---|---|---|---|
| `serial` | Yes | `serialport` | USB CDC serial transport |
| `ledger` | No | `hidapi` | Ledger USB HID transport + Speculos TCP transport |
| `tcp` | No | _(none)_ | Raw TCP transport for virtual device / testing |
| `qr` | No | `qrcode`, `image`, `rqrr`, `ur` | QR code transport for air-gapped devices (untested) |

## Logging

The SDK uses [`tracing`](https://docs.rs/tracing) for structured logging. It emits events at three levels — the consuming application controls what gets displayed by installing a `tracing_subscriber`.

| Level | What is logged |
|---|---|
| `info` | High-level milestones: connection, handshake, proof generated, signing complete |
| `debug` | Protocol details: FVK components (ak/nk/rivk), ZIP-244 digests, APDU status words |
| `trace` | Raw bytes: HWP frame hex dumps, HID packets, serial I/O |

**Example — enable debug logging in your application:**

```rust
// Add to your Cargo.toml:
//   tracing-subscriber = { version = "0.3", features = ["fmt"] }

tracing_subscriber::fmt()
    .with_max_level(tracing::Level::DEBUG)
    .init();

let signer = zcash_hw_wallet_sdk::signer::connect_serial("/dev/ttyACM0")?;
// Logs will now show FVK components, digest values, APDU exchanges, etc.
```

**Filter to SDK events only:**

```rust
use tracing_subscriber::EnvFilter;

tracing_subscriber::fmt()
    .with_env_filter(EnvFilter::new("zcash_hw_wallet_sdk=debug"))
    .init();
```

Or via environment variable: `RUST_LOG=zcash_hw_wallet_sdk=debug cargo run`

## Network Discrimination (Mainnet / Testnet)

The wallet application drives network selection by passing `coin_type` in HWP protocol messages. The device uses it to derive the correct ZIP-32 keys and is stateless with respect to the network — every request is self-contained.

**How it works:**

1. **`coin_type` fixed at signer construction** — every `DeviceSigner` constructor (and the `connect_*` helpers) takes a `coin_type` (133 = mainnet, 1 = testnet), exposed through the required `HardwareSigner::coin_type()` method; the workflow derives the network from it
2. **`export_fvk()`** — the SDK sends the signer's `coin_type` in the `FvkReq` payload; the device derives keys from `m/32'/coin_type'/account'`
3. **`TxMeta`** carries `coin_type` (bytes 125-128) — the device validates that it matches the `coin_type` from `FvkReq`
4. **Pre-proof validation** — the SDK rejects branch IDs that predate the Orchard protocol (pre-Nu5) before expensive Halo2 proof generation, and rejects v6 transactions whose branch ID predates NU6.3

If a mismatch is detected (e.g., `FvkReq(coin_type=133)` followed by `TxMeta(coin_type=1)`), the device returns `NetworkMismatch` (error 0x05).

The `coin_type` extension in TxMeta (the trailing 4 bytes: 125-128 in the v5 layout, 166-169 in the v6 layout) is **not** part of the ZIP-244 sighash computation — it is appended after the core fields for network validation only.

**Note:** `consensus_branch_id` values (e.g., Nu5 = `0xc2d6d0b4`, Nu6.3 = `0x37a5165b`) are identical on mainnet and testnet. Only `coin_type` (133 vs 1) reliably distinguishes the networks, because it determines the ZIP-32 key derivation path.

### NU6.3 / Ironwood (v6 transactions)

From NU6.3 a transaction may carry actions in two Orchard-protocol pools: the
**sealed Orchard pool** (spend-only turnstile withdrawals, cross-address
transfers disabled by consensus) and the new **Ironwood pool** (ZIP 258, using
V3 quantum-recoverable note plaintexts per ZIP 2005). The SDK handles both:

- **TxMeta v6 layout (170 bytes)**: inserts `ironwood_flags[1] ||
  ironwood_value_balance[8 LE] || ironwood_anchor[32]` after the Orchard
  anchor. The device discriminates v5/v6 by payload size. Under v6 the anchors
  are *not* part of the effects digest (they move to the authorizing-data
  commitment), and the sighash tree gains a fifth leaf
  (`ZTxIdIronwd_H_v6`-personalized) after the Orchard one
  (`ZTxIdOrchardH_v6`).
- **Pool-tagged actions**: every v6 action payload is prefixed with one pool
  byte (`0x00` Orchard, `0x01` Ironwood) so the device hashes it into the
  correct pool digest tree and verifies the output note under the correct
  note-plaintext version (V2 lead byte `0x02` vs V3 lead byte `0x03`, with the
  ZIP-2005 rcm derivation for V3).
- **Signing**: spends in both pools use the same RedPallas spend-authorization
  scheme; the workflow routes signatures back via
  `apply_orchard_signature` / `apply_ironwood_signature` per pool.

## On-Device Verification — five composed invariants

The SDK + device cooperate to enforce five security invariants, in order, before any RedPallas signature is produced. Each is a library-level state-machine invariant on the device side: a hostile firmware cannot extract a signature by skipping any of them, and no component of the ZIP-244 sighash or of any output note is taken on faith from the companion.

### 1. ZIP-244 sighash recomputed on-device

Before signing, the SDK extracts transaction metadata and action data from the PCZT and sends them to the device. The device independently computes the complete ZIP-244 v5 shielded sighash and refuses to sign if it doesn't match.

A compromised companion cannot trick the device into signing an arbitrary transaction — the device recomputes the sighash from the raw transaction components.

Per-component breakdown:
- **`header_digest`** — recomputed on-device from `TxMeta` (`ZTxIdHeadersHash`)
- **`transparent_sig_digest`** — when transparent inputs/outputs are present, the SDK streams them via `TxTransparentInput` / `TxTransparentOutput` and the device recomputes the digest from those bytes; constant-time compared against the value in `TxMeta`. For transparent signing, the device also produces the per-input sighash on-device (`amounts_digest`, `scripts_digest`, `txin_sig_digest`) and signs with ECDSA secp256k1.
- **`sapling_digest`** — *Orchard-only invariant*: the SDK refuses to send any PCZT containing Sapling spends or outputs (`HwSignerError::SaplingNotSupported`); the device additionally enforces `sapling_digest == BLAKE2b-256("ZTxIdSaplingHash", [])` on `TxMeta` receipt. Either side catches a hostile companion that would otherwise siphon value via a Sapling output the device never sees in the Orchard stream.
- **`orchard_digest`** — recomputed on-device from streamed action data via three parallel BLAKE2b-256 digesters (compact / memos / non-compact)

### 2. NoteCommitment (cmx) recomputed per action

Hashing the encrypted action stream is not enough by itself: the cmx field of an action is opaque to ZIP-244 hashing, so a hostile companion could put a cmx that commits to `(attacker_address, value)` while telling the device's UI "send to <Mario>". Defence: the device recomputes the cmx from the unencrypted note plaintext the companion declares (`recipient`, `value`, `rseed` — bundled into every TX_OUTPUT action payload, see `ActionData` above), and rejects the action if the recomputation does not match the cmx in the encrypted action bytes. An attacker would have to break Sinsemilla.

The host-side fix is `HwSignerError::SaplingNotSupported` plus the per-action plaintext extraction in `workflow.rs`. The device-side fix is `orchard_signer_feed_action_with_note_and_memo()` returning `SIGNER_ERR_NOTE_COMMITMENT_MISMATCH` (HWP error `0x0D`) on mismatch, before any orchard digest hashing.

### 3. Output `enc_ciphertext` recomputed per action (memo binding)

cmx covers `(d, pk_d, value, rho, rseed)` but does **not** cover the 512-byte memo. A host that has been forced through cmx-recomputation can still embed any memo plaintext inside `enc_ciphertext` and show the user a different one on its UI — the recipient sees the attacker's memo on chain.

The SDK closes this by recovering the memo and forwarding it to the device for full ciphertext re-encryption. For each action, after the Halo2 proof step:

1. `workflow.rs` calls `signer.export_fvk()` to obtain the device's Orchard FVK and derives the external `OutgoingViewingKey` (`fvk.to_ovk(Scope::External)`)
2. For each `pczt::Action`, it calls `try_output_recovery_with_ovk` from `zcash_note_encryption`, decrypting `out_ciphertext` and then `enc_ciphertext` to recover `(note, address, memo)`
3. The memo plaintext is stored in `ActionData::memo` and shipped to the device as the trailing 512 bytes of the memo-verifying wire payload (pool-tagged v6 format, 1416 B)
4. The device recomputes `enc_ciphertext = ChaCha20-Poly1305(K_enc, IV=0, leadByte‖d‖value‖rseed‖memo)` with `K_enc = BLAKE2b("Zcash_OrchardKDF", repr_P(epk)‖repr_P([esk]·pk_d))` and `esk = ToScalar(PRF^expand(rseed,[0x04]‖ρ))` derived on-chip; ct-compares byte-for-byte against the action's `enc_ciphertext` AND `ephemeral_key`. Mismatch → `MemoMismatch` (HWP error `0x0F`).

`esk` is **not** carried on the wire — both sides derive it deterministically from `rseed + rho` per ZIP-212, removing one trust-from-companion vector.

Outputs constructed with `OVK::None` cannot be recovered by the sender; for those the SDK falls back to the cmx-only payload, and the device skips the memo check for that action. The wallet's normal flow uses `OvkPolicy::Sender` so this path is not exercised.

### 4. Per-action user confirmation (no blind signing)

cmx recomputation guarantees the cmx commits to *what the companion told the device*. For the user not to be signing blindly, the device must also display recipient + value to the user and the user must explicitly approve. The device-side library lifts that requirement from a firmware convention to a state-machine invariant:

- For each action, the device stores `(recipient, value, confirmed=false)` at index `actions_received` (capped at 16 actions per tx)
- The device's UI iterates the stored entries, encodes the recipient as a Bech32m Unified Address via `orchard_encode_ua_raw`, displays the (UA, value) pair, and waits for explicit user approval per output before calling `orchard_signer_confirm_action(idx)`
- `orchard_signer_verify()` refuses to advance to `SIGNER_VERIFIED` unless every entry has `confirmed == true` (returns `SIGNER_ERR_ACTION_NOT_CONFIRMED`); `orchard_signer_sign()` then refuses with `NOT_VERIFIED` if any output was skipped

The SDK does not need any change for this: the work is fully on the device side. The SDK just sees a longer wait for the sentinel `TxOutputAck` (during which the device drives the UI loop) and a possible `UserCancelled` (`HWP_ERR_USER_CANCELLED`) if the user rejects any output.

### 5. Per-transaction fee confirmation (no blind signing for the miner fee)

cmx + enc_ciphertext + per-action confirmation guarantee the user sees every output the transaction *creates*. The miner fee, however, is determined by `value_balance` (a `TxMeta` field) and is implicit — value that leaves the wallet but does not appear in any output. A host that inflates `value_balance` could silently overspend, siphoning the surplus to miners while displaying a small fee on its own UI.

Defence:

1. The device tracks per-input / per-output transparent value totals in `Zip244TransparentState` with overflow flags
2. After the per-action review loop, the dispatcher calls `orchard_signer_get_fee()`, which computes `fee = t_in_total − t_out_total + value_balance` with i64 overflow detection and a non-negative check (`FeeOverflow` / `FeeNegative` on hostile values)
3. The fee is rendered on the trusted screen (via a dedicated `ui.review_fee` callback if the firmware provides one, or via a backward-compat fallback to `ui.review_output` with `addr_str = "Network fee"`)
4. Only after explicit user OK does the dispatcher call `orchard_signer_confirm_fee()`, allowing `orchard_signer_verify()` to advance past `FeeNotConfirmed`

The SDK does not need any change for this either; the fee math + confirmation flow is fully device-side and is driven automatically by the HWP dispatcher in `libzcash-ironwood-c`.

### Protocol flow (integrated into `sign()`)

1. SDK extracts `TxMeta` from the PCZT (129 bytes v5 / 170 bytes v6)
2. `TxMeta` is sent as a `TxOutput` with `output_index = 0xFFFF` (metadata sentinel)
3. SDK fetches OVK from device (via `signer.export_fvk()`) and trial-decrypts each action's `out_ciphertext` → `enc_ciphertext` to recover the memo plaintext
4. SDK extracts each action's full components (pool-tagged 1416 bytes per action under v6) — including the unencrypted `recipient[43]`, `value[8]`, `rseed[32]`, and `memo[512]`. Falls back to the cmx-only payload (904 B v6 / 903 B v5) when memo recovery fails (`OVK::None` output).
5. Each action is sent as a `TxOutput` message (index 0..N-1)
6. Device recomputes cmx AND (when the full payload is sent) enc_ciphertext + epk; stores recipient/value for display
7. SDK sends the expected sighash as a sentinel `TxOutput` (index = N)
8. Device drives the per-output user-confirmation UI, then the fee-confirmation UI, before responding to the sentinel
9. Device recomputes the full ZIP-244 sighash and constant-time-matches against the sentinel
10. On subsequent `SignReq`, device verifies the sighash and `state == VERIFIED`
11. RedPallas signature produced

**Device-side implementation** is provided by [libzcash-ironwood-c](https://github.com/wh00hw/libzcash-ironwood-c) — `zip244.h`/`zip244.c` for the digest tree, `orchard.c` for `orchard_compute_cmx` + `orchard_encode_ua_raw`, `orchard_signer.c` for the state machine.

**Note:** The SDK uses `Pczt::into_effects()` and `TxIdDigester` from `zcash_primitives` to extract the transparent sub-digest. This ensures the value is identical to what the official `pczt::roles::signer::Signer` uses internally for sighash computation. The `TxMeta` is built from the `TransactionData` directly (not from PCZT Global fields) to guarantee field-level consistency (e.g., `lock_time` determined by `determine_lock_time()`). The sapling digest field in `TxMeta` is always the empty-bundle constant by SDK invariant.

**For custom `HardwareSigner` implementations:** the `verify_transaction()` trait method has a default no-op (v1 behavior: device trusts companion). Override it if your device supports on-device verification — and if it does, it MUST also implement the cmx + per-output confirmation flow, because the device-side libzcash-ironwood-c refuses to sign without them.

## Security Model

| Layer | What it protects against | Status |
|---|---|---|
| **Key isolation** | Spending key never leaves the device. Only FVK is exported. | Active |
| **Signature verification** | SDK verifies every signature before injecting into PCZT. | Active |
| **RK binding** | Each signature is bound to a specific action via the randomized verification key. | Active |
| **CRC-16 framing** | Detects corrupted data on the wire. Auto-retries on CRC errors. | Active |
| **ZIP-244 sighash verification** | Device independently computes the full ZIP-244 sighash from transaction data and refuses to sign on mismatch. | Active (via `DeviceSigner`) |
| **Transparent digest verification** | Device computes transparent txid digest from raw inputs/outputs and verifies it matches TxMeta. Prevents forged transparent digests. | Active (via `DeviceSigner`) |
| **Transparent per-input sighash** | Device computes per-input transparent sighash on-device (amounts, scripts, txin_sig digests) and signs with ECDSA secp256k1. | Active (via `DeviceSigner`) |
| **Sapling-component lockout** | SDK rejects any PCZT with Sapling spends or outputs (`HwSignerError::SaplingNotSupported`) before transmission; device additionally enforces `sapling_digest == ZIP-244 empty-bundle constant` on `TxMeta` receipt. Prevents value siphoning via a hidden Sapling output the device never sees in the Orchard stream. | Active (via `DeviceSigner` + workflow) |
| **NoteCommitment (cmx) verification** | Device recomputes `cmx = Extract_P(NoteCommit(g_d, pk_d, value, rho, psi))` for every Orchard action from the unencrypted note plaintext the SDK appends to each `TxOutput` payload, and rejects mismatches (`SIGNER_ERR_NOTE_COMMITMENT_MISMATCH`). Prevents a hostile companion from substituting the recipient between the displayed UI and the on-chain effect of the signed transaction. | Active (via `DeviceSigner`) |
| **No-blind-signing invariant (per output)** | Device-side library refuses to advance the signer state to `VERIFIED` unless every captured action has been explicitly confirmed via `orchard_signer_confirm_action()`. The firmware UI is responsible for displaying recipient + value per output and capturing user approval; the lib enforces that without that step, no signature is produced. | Active (device-enforced) |
| **Memo verification via enc_ciphertext recomputation** | SDK recovers each output's memo via the device's OVK (`try_output_recovery_with_ovk`) and ships it in the memo-verifying wire payload (pool-tagged v6). Device re-encrypts on-chip (Pallas ECDH + Orchard KDF + ChaCha20-Poly1305, esk derived from rseed+ρ per ZIP-212) and ct-compares against the action's `enc_ciphertext` + `ephemeral_key`; mismatch → `SIGNER_ERR_MEMO_MISMATCH`. Prevents a hostile companion from showing one memo on its UI and embedding another on chain. | Active (via `DeviceSigner` + workflow) |
| **Miner-fee confirmation invariant** | Device computes `fee = transparent_in − transparent_out + value_balance` on-chip with overflow + negative detection, renders it on the trusted screen, and refuses to advance `verify()` until the user explicitly approves (`orchard_signer_confirm_fee()`). Prevents `value_balance` inflation that would silently siphon the surplus to miners. | Active (device-enforced) |

**Protocol hardening:**

- **Device attestation** — first pairing stores the device's identity pubkey (`DeviceSigner::pair()`); later sessions verify a fresh RedPallas challenge-response against the pinned key (`new_with_pinned_pubkey` / `attest`), catching USB-hub MITM, TCP impostors, and reflashed devices
- **Constant-time comparisons** — RK verification uses `subtle::ConstantTimeEq` to prevent timing side-channel attacks
- **Zeroize on drop** — `SignRequest`, `SignResponse`, and `ExportedFvk` implement `Zeroize + ZeroizeOnDrop` to scrub sighash, alpha, signatures, and key material from memory
- **Recipient validation** — Recipient addresses exceeding 255 bytes are rejected (no silent truncation)
- **Keepalive limits** — All PING loops are capped to prevent infinite loops from misbehaving devices
- **Sighash log truncation** — Only first 8 bytes of sighash are logged to limit exposure

**Security boundaries to be aware of:**

- The device computes the full ZIP-244 sighash independently. A compromised companion cannot forge a valid sighash without providing the correct transaction data.
- The device additionally recomputes the per-action note commitment (cmx) from the unencrypted recipient/value/rseed and rejects mismatches. A compromised companion cannot redirect output value to a different recipient than the one displayed on the device UI.
- The device additionally recomputes each output's `enc_ciphertext` (Pallas ECDH + Orchard KDF + ChaCha20-Poly1305 over the user-shown memo plaintext) and rejects mismatches. A compromised companion cannot embed a memo on chain that differs from what the user is shown on the device UI.
- The device additionally enforces per-output user confirmation **and** per-tx fee confirmation as state-machine invariants. A compromised firmware that skipped either UI step would not be able to extract a signature.
- Orchard, Transparent, and Sapling-empty-bundle invariants all enforced on-device. The Orchard-only design means the device deliberately refuses to sign any transaction containing Sapling components — by both an SDK pre-check and a device-side `sapling_digest` constraint.
- The SDK trusts the PCZT input (produced by `zcash_client_backend`). A compromised wallet could produce a malicious PCZT — but the device will only sign if the sighash + cmx + enc_ciphertext + recipient/value + fee all match what the user confirmed on the device UI.
- The only thing the device trusts the companion for is the Halo2 proof itself — a wrong proof produces a transaction the network rejects, not one that pays an attacker.
- The SDK does not address physical security of the device (no secure element, no tamper resistance). That's the device manufacturer's responsibility.

## Integration with the Zcash Ecosystem

This SDK is designed to work with the standard Zcash Rust crates:

```rust
use zcash_client_backend::data_api::wallet::{
    create_pczt_from_proposal,
    extract_and_store_transaction_from_pczt,
};

// 1. Create proposal (standard zcash_client_backend flow)
let proposal = /* propose_transfer(...) */;

// 2. Create PCZT from proposal (FVK only, no spending key)
let pczt_bytes = create_pczt_from_proposal(&mut db, &params, account_id, OvkPolicy::Sender, &proposal)?;

// 3. Sign via hardware wallet (this SDK) — coin_type 133 = mainnet
let signer = zcash_hw_wallet_sdk::signer::connect_serial("/dev/ttyACM0", 133)?;
let mut workflow = PcztHardwareSigning::new(signer);
let result = workflow.sign(pczt_bytes.serialize())?;

// 4. Extract final transaction
let signed_pczt = pczt::Pczt::parse(&result.signed_pczt)?;
let txid = extract_and_store_transaction_from_pczt(&mut db, signed_pczt, None, Some(&orchard_vk))?;

// 5. Broadcast via lightwalletd
```

## Supported Hardware

Any device that can:

1. Store an Orchard spending key (`ask`)
2. Perform RedPallas rerandomized Schnorr signatures
3. Communicate over serial or QR codes

The SDK is **hardware-agnostic** -- implement the `HardwareSigner` trait or speak the HWP protocol.

**Tested:** Ledger Nano S+ (via `LedgerTransport`), ESP32-S3 (via `SerialTransport`).

**Other potential targets:** Ledger Stax/Flex, Trezor, air-gapped phones, RISC-V microcontrollers, DIY hardware wallets.

### Device-side: libzcash-ironwood-c

The companion library [**libzcash-ironwood-c**](https://github.com/wh00hw/libzcash-ironwood-c) (formerly `libzcash-orchard-c`) provides a pure C11 implementation of the Zcash Orchard/Ironwood primitives and the HWP protocol, designed specifically for embedded hardware wallets where Rust is not available.

It includes:

- **ZIP-244 sighash computation** — full shielded sighash with all BLAKE2b personalizations + transparent per-input sighash (amounts, scripts, txin_sig digests), enabling complete on-device transaction verification
- **ZIP-32 key derivation** (spending key, full viewing key, addresses)
- **BIP-32 transparent key derivation** — `m / 44' / coin_type' / 0' / 0 / 0` for secp256k1 spending keys
- **Pallas / RedPallas** curve arithmetic and spend authorization signing (Orchard)
- **secp256k1 / ECDSA** — curve arithmetic (constant-time Montgomery ladder), ECDSA signing with RFC 6979, DER encoding (Transparent)
- **Orchard Unified Address** generation with F4Jumble (ZIP-316) and Bech32m
- **Base58Check + transparent address rendering** — `script_to_taddr()` decodes P2PKH/P2SH `script_pubkey` to the Zcash t-address string (mainnet `t1`/`t3`, testnet `tm`/`t2`), so the device shows the actual destination of transparent outputs (shielded → t-addr sweep) instead of only the change Orchard receivers
- **HWP v2–v6 protocol** implementation matching this SDK's host-side protocol, including the memo-verifying + pool-tagged action payloads, device attestation, and the on-chip fee computation
- **Target-agnostic protocol dispatcher** (`hwp_dispatcher.h`) — the full device-side state machine (drain → parse → switch → reply, PING/PONG keepalive, IDLE detection, multi-frame drain handling, per-output review, recipient binding, fee review) lives in the library and is exposed through a callback-based API. A new device target wires up ~6 I/O + UI callbacks and gets the protocol implementation for free. The Rust SDK ↔ libzcash protocol contract is therefore mirrored on both sides by one canonical implementation each, not re-derived per device target.
- **Orchard note-encryption recomputation** — `orchard_compute_enc_ciphertext{,_from_rseed}` rebuilds the 580-byte AEAD ciphertext on-chip for memo verification (Pallas ECDH + `BLAKE2b("Zcash_OrchardKDF", ...)` + ChaCha20-Poly1305)
- **Crypto primitives**: BLAKE2b, SHA-256/512, HMAC, PBKDF2 (with optional progress callback for PIN unlock UI), AES-256 (FF1), ChaCha20-Poly1305 (RFC 7539, KAT-verified)
- **BIP39** mnemonic generation
- **Zero external dependencies** — portable to any platform with a C11 compiler

Together, the two projects form a complete plug-and-play stack: `libzcash-ironwood-c` runs on the device (firmware) and owns everything below the wire, `zcash-hw-wallet-sdk` runs on the host (wallet application) and owns everything above the wire, and the HWP protocol between them is the frozen contract that lets the two halves evolve independently. A new device firmware reduces to platform-specific I/O + UI glue; a new wallet application reduces to building PCZTs and calling `PcztHardwareSigning::sign_with_details()`.

## librustzcash Compatibility

The SDK builds against the **published NU6.3-capable releases on crates.io** — `pczt 0.8.0-rc.1`, `orchard 0.15.0`, `zcash_primitives 0.29.0`, `zcash_protocol 0.10.0`. No `[patch.crates-io]` section is needed for a standalone build. The external-signing APIs it relies on are:

- **`pczt`** — `Signer::shielded_sighash()` returns the computed sighash for external signing
- **`pczt`** — `Signer::apply_orchard_signature(index, signature)` / `apply_ironwood_signature(index, signature)` inject an externally-produced RedPallas signature per pool
- **`pczt`** — `low_level_signer::sign_orchard_with()` / `sign_ironwood_with()` provide callback access to the parsed bundle for reading alpha, rk, and action data

These first landed upstream in commit [`feefa606`](https://github.com/zcash/librustzcash/commit/feefa606) ("pczt: Support appending external signatures to inputs", Nov 2025) and have shipped on crates.io since `pczt` 0.6.0; the Ironwood (PCZT v2) APIs shipped with `pczt` 0.8. The `librustzcash` git submodule in this repo is kept for reference only and is not part of the build. (When the SDK is built as a path dependency of the `zipher-app` workspace, the workspace root may still patch the zcash crates to a pinned librustzcash revision.)

## Dependencies

| Crate | Version | Purpose |
|---|---|---|
| `pczt` | 0.8.0-rc.1 | PCZT roles (prover, signer, extractor) — Ironwood-aware (PCZT v2) |
| `orchard` | 0.15.0 | Orchard-protocol circuit keys, Ironwood pool, V3 notes |
| `zcash_primitives` | 0.29.0 | Transaction data, `TxIdDigester`, transparent sighash |
| `zcash_protocol` | 0.10.0 | Consensus parameters, branch IDs |
| `zcash_address` | 0.13 | Unified Address encoding for display |
| `reddsa` | 0.5 | RedPallas signature verification |
| `secp256k1` | 0.29 | ECDSA transparent signature parsing |
| `ff` | 0.13 | Finite field traits (alpha serialization) |
| `zcash_note_encryption` | 0.4 | Trial-decrypt `out_ciphertext` → `enc_ciphertext` via the device OVK to recover the memo plaintext for memo-verification |
| `zeroize` | 1 | Secure memory erasure for sensitive data |
| `subtle` | 2 | Constant-time cryptographic comparisons |
| `rand_core` | 0.6 | Fresh attestation challenge nonces (platform CSPRNG) |
| `serialport` | 4 | USB serial (optional, feature `serial`) |
| `hidapi` | 2 | Ledger USB HID (optional, feature `ledger`) |
| `thiserror` | 2 | Error type derivation |
| `tracing` | 0.1 | Structured logging |

## TODO

- [x] **On-device ZIP-244 sighash verification** — Device independently computes the full ZIP-244 sighash from transaction metadata + action data and verifies it matches.
- [x] **Network discrimination** — `coin_type` in FvkReq and TxMeta enables mainnet/testnet selection, with device-side validation.
- [x] **Integration tests** — Virtual HWP device (C/TCP) + 17 end-to-end Rust tests (Orchard + Transparent), running in GitHub Actions on every push.
- [x] **Transparent digest verification** — Device independently computes transparent txid digest from raw inputs/outputs and refuses to sign on mismatch. Prevents forged transparent digests from compromised companions.
- [x] **Transparent per-input signing** — Device computes per-input transparent sighash on-device (ZIP-244 S.2: amounts, scripts, txin_sig digests) and signs with ECDSA secp256k1 via BIP-32 derived keys.
- [x] **Transparent sighash hardening** — Integrated librustzcash PR #2278: `SignableInput::from_parts` validates input index at construction time, preventing out-of-range index attacks.
- [x] **Sapling-component lockout** — SDK pre-rejects PCZTs with Sapling components; device enforces `sapling_digest == empty-bundle constant`.
- [x] **NoteCommitment (cmx) verification** — Device recomputes Sinsemilla NoteCommit per action and rejects recipient-substitution attempts. KAT against `librustzcash` Note::commitment().
- [x] **No-blind-signing invariant (per output)** — Device-side library state machine refuses to sign without explicit per-output user confirmation. Reference port (ESP32) confirms via BOOT button + CDC log; FlipZcash confirms via screen + OK button.
- [x] **Memo verification via enc_ciphertext recomputation** — SDK recovers each output's memo via the device's OVK and ships it in the memo-verifying wire payload (pool-tagged v6, 1416 B). Device re-encrypts on-chip (Pallas ECDH + Orchard KDF + ChaCha20-Poly1305 RFC 7539, esk derived from rseed+ρ per ZIP-212) and ct-compares against the action's `enc_ciphertext` + `ephemeral_key`. Closes the memo-substitution attack hanh raised.
- [x] **Miner-fee confirmation invariant** — Device computes the fee on-chip from `t_in − t_out + value_balance` (with overflow + negative detection), renders it on the trusted screen, and refuses to advance `verify()` until the user explicitly approves. Closes the `value_balance`-inflation attack.
- [x] **Upstream pczt release** — Resolved: the SDK now builds against the published crates.io releases (`pczt 0.8.0-rc.1`, `orchard 0.15.0`); the librustzcash submodule and `[patch.crates-io]` table are no longer required.
- [x] **Device attestation** — First-pairing identity pinning + per-session RedPallas challenge-response (`pair()` / `attest()` / `new_with_pinned_pubkey`, HWP 0x0F–0x12). Catches device substitution between sessions (audit M1).
- [ ] **External security audit** — Required before any production/mainnet use
- [ ] **QR transport testing** — The QR transport is untested with real hardware. Needs end-to-end validation with an air-gapped device.
- [ ] **Sapling-only recipient support** — Out of scope for the Orchard-only design. Recipients with no Orchard receiver in their UA are not supported; recipients should expose a UA with an Orchard receiver. If ever needed, would require streaming sapling spends/outputs to the device for digest recomputation rather than the current empty-bundle enforcement.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
