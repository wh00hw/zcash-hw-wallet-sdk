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

Transport-agnostic Rust SDK for signing Zcash shielded + Transparent transactions via hardware wallets using the [PCZT](https://zips.z.cash/zip-0320) (Partially Created Zcash Transaction) standard. Post-NU6.3 that means the **Ironwood pool** (ZIP 258) plus turnstile withdrawals from the sealed Orchard pool; both are built on the Orchard protocol family, whose name survives in the underlying crates and primitives.

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
6. User Confirmation    Optional host-side hook (TxDetails are NOT shown by the device)
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
| `supports_transparent_inputs()` | Always `false` (default and `DeviceSigner`): transparent inputs are not supported. `PcztHardwareSigning` refuses a PCZT with transparent inputs with `HwSignerError::TransparentInputsNotSupported` before proving and before anything is sent to the device. Transparent **outputs** (shielded → t-address) are supported | — |

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

### `protocol` -- Hardware Wallet Protocol (HWP) v6 only

Binary framed protocol designed for constrained devices. **This branch is v6-only** (NU6.3 and NU7): the host emits exclusively the v6 wire tier — 170-byte TxMeta, pool-tagged 1416-byte action payloads (full note plaintext for every output), five-leaf sighash tree — and rejects any PCZT whose consensus branch ID is not NU6.3 (`0x37a5165b`) or NU7 (`0x77190ad9`), or whose transaction version is not v6, with a typed error before proof generation and before anything is sent to the device (a PCZT that does not parse, or whose effects cannot be extracted, is `InvalidPczt`). The matching strict device (`libzcash-ironwood-c`, branch `v6-only`) rejects the legacy tiers on the wire: 125/129-byte v5 TxMeta → `Error(BAD_META)`, untagged 903/1415-byte actions → `Error(BAD_FRAME)`. Earlier tiers layered in ZIP-244 sighash verification (v2), transparent digest verification + ECDSA signing (v3), Orchard cmx + per-action user confirmation + device attestation (v4), and on-device `enc_ciphertext` recomputation (memo binding) + explicit miner-fee confirmation (v5); their security features all carry forward into v6, only their wire layouts are gone.

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
| `TransparentSignReq` | 0x0D | Host -> Device | Not sent by this SDK; the device answers `TransparentInputsUnsupported` (0x18) |
| `TransparentSignRsp` | 0x0E | Device -> Host | Retired: never sent by current firmware |
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

The device uses `sighash` (it must be the one it verified) and `alpha`. `amount`, `fee` and `recipient` are **ignored by the device** — not validated, not displayed; the recipient may be empty. The final confirmation screen shows totals the device computed itself. `sign()` / `sign_with_details()` keep their signatures: the `TxDetails` passed to `sign_with_details` are handed to `HardwareSigner::confirm_transaction` (host-side logging / a custom signer's own prompt) and copied into `SIGN_REQ` for older firmware, but nothing in them reaches the HWP device's screen. The device gives at most one signature per action of the approved transaction.

**TX_OUTPUT payload — on-device sighash + cmx + enc_ciphertext + fee verification:**

```
output_index[2 LE] || total_outputs[2 LE] || action_data[N]
```

Three types of TxOutput messages are used, discriminated by `output_index`:

- `output_index = 0xFFFF` — **Transaction metadata** (v6 layout, 170 bytes — the only one this host emits): `version[4] || version_group_id[4] || consensus_branch_id[4] || lock_time[4] || expiry_height[4] || orchard_flags[1] || value_balance[8 LE signed] || anchor[32] || ironwood_flags[1] || ironwood_value_balance[8 LE signed] || ironwood_anchor[32] || transparent_sig_digest[32] || sapling_digest[32] || coin_type[4 LE]`. The legacy 129-byte v5 layout is rejected by the strict device (`Error/BAD_META`).
- `output_index = 0..N-1` — **Action + full note plaintext**. The SDK emits the **pool-tagged 1416-byte payload**: `pool_tag[1] || cv_net[32] || nullifier[32] || rk[32] || cmx[32] || ephemeral_key[32] || enc_ciphertext[580] || out_ciphertext[80] || recipient[43] || value[8 LE] || rseed[32] || memo[512]`. The trailing 595 bytes (recipient + value + rseed + memo) let the device recompute both `cmx` (Sinsemilla) AND `enc_ciphertext` (ChaCha20-Poly1305 with `K_enc = BLAKE2b(epk‖[esk]·pk_d)`, esk derived on-chip from rseed+rho per ZIP-212). **Every action must be sent in this form — payments, the wallet's own change and the builder's zero-value padding alike**: the device answers the compact (904-byte, no memo) form with `MemoRequired` (`0x14`) whatever the output. Action frames must be sent in order (`0, 1, …, N-1`), each exactly once, all with the `total_outputs` announced with the metadata; `N` must be at least 1. Untagged legacy 903/1415-byte payloads are rejected with `Error(BAD_FRAME)`.
- `output_index = N` (sentinel): Expected 32-byte ZIP-244 sighash for device comparison. Triggers the on-device review — every transparent output, every shielded output with a value or a memo (labelled by the device, from its own keys, as external, the wallet's change or one of the wallet's own addresses), then the totals (what leaves the wallet, and the fee) — and only then the sighash comparison. The host just waits for the `TxOutputAck`; a refusal at any screen comes back as `UserCancelled`.

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
| 0x0E | `RecipientMismatch` | Reserved; no longer sent (the device ignores `SIGN_REQ.recipient`) |
| 0x0F | `MemoMismatch` | Device-recomputed enc_ciphertext (or epk) ≠ action — memo-substitution attempt |
| 0x10 | `BadPkD` | `pk_d` does not decode to a valid Pallas point |
| 0x11 | `FeeNotConfirmed` | `verify()` reached without user approving the on-device-computed fee |
| 0x12 | `FeeOverflow` | Transparent value sums or `value_balance` combine to an out-of-range fee |
| 0x13 | `FeeNegative` | `t_in + value_balance < t_out` — companion built an unbalanced bundle |
| 0x14 | `MemoRequired` | An action arrived in the compact (904-byte) form: the device needs the memo-carrying body for every output, zero-value padding included |
| 0x15 | `BranchNotAllowed` | TxMeta consensus branch ID is not in the firmware's allow-list (NU6.3 `0x37a5165b`, NU7 `0x77190ad9`) |
| 0x16 | `LimitExceeded` | More actions, transparent outputs or memos than the device can review, or a memo on a device that cannot display one |
| 0x17 | `ValueOverflow` | An output value, a value balance or a total above MAX_MONEY (21,000,000 ZEC), or a sum that does not fit in 64 bits |
| 0x18 | `TransparentInputsUnsupported` | The transaction has transparent inputs, or a `TransparentSignReq` was sent: the device does not sign transparent inputs |
| 0x19 | `EmptyPoolBalance` | TxMeta declares a non-zero value balance for a shielded pool (Orchard / Ironwood) that has no action in the transaction |

> The wire protocol (canonical definition in `libzcash-ironwood-c`'s `hwp.h`) defines codes `0x00` (`Unknown`) through `0x19`; the SDK's typed `ErrorCode` enum mirrors the full range. `UserCancelled`, `SighashMismatch`, `TransparentDigestMismatch`, `SaplingNotEmpty`, `NoteCommitmentMismatch`, `RecipientMismatch`, `MemoRequired`, `BranchNotAllowed`, `LimitExceeded` (as `HwSignerError::DeviceLimitExceeded`), `ValueOverflow`, `TransparentInputsUnsupported` (as `HwSignerError::TransparentInputsNotSupported { inputs: 0 }`) and `EmptyPoolBalance` map to dedicated `HwSignerError` variants; the remaining codes surface as `HwSignerError::DeviceError` with the code name and the device's message string. Every `Error` frame ends the device's session (a verified transaction and its approvals included): the host starts again from the metadata. A new TxMeta always starts a new transaction, so the host does not have to close the previous one.
>
> With the November 2026 device firmware some conditions changed code: too many actions is `LimitExceeded` (was `BadFrame`), and a fee overflow / negative fee found during the review is `FeeOverflow` / `FeeNegative` (was `UserCancelled`). Transparent inputs are refused by the device (`TransparentInputsUnsupported`, and by this SDK before that); the device's network is fixed by its firmware and TxMeta must carry the matching `coin_type`; a transaction with no shielded action is refused; a ninth transparent output is `LimitExceeded` on the first transparent-output frame. The device also has its own branch allow-list now — the host's branch gate (above) fails earlier and with a more specific error, so `BranchNotAllowed` is only seen with a firmware built for fewer branches than the host supports.

### `verify` -- Signature Verification

After receiving a signature from the device, the SDK verifies:

1. **RK match** -- the randomized verification key returned by the device matches the PCZT action's expected rk
2. **RedPallas verify** -- the signature is cryptographically valid against the sighash using `reddsa::VerificationKey<orchard::SpendAuth>`

This prevents both key confusion attacks and invalid signatures.

### `error` -- `HwSignerError`

Typed error enum covering all failure modes:

- **PCZT workflow**: `ProofFailed`, `SignerInitFailed`, `NoActionsToSign`, `ExtractionFailed`, `SaplingNotSupported`, `UnsupportedPool`
- **Signatures**: `RkMismatch`, `SignatureVerificationFailed`, `InvalidVerificationKey`, `OutputNotRecoverable`
- **On-device verification**: `NoteCommitmentMismatch`, `MemoRequired`, `BranchNotAllowed`, `DeviceLimitExceeded`, `ValueOverflow`, `EmptyPoolBalance`, `TransparentInputsNotSupported`, `TransparentSighashMismatch`, `NetworkMismatch` (`RecipientMismatch` is kept for older firmware)
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
| `out_ciphertext` | `Vec<u8>` | Encrypted outgoing plaintext (80 bytes); hashed into the sighash, not otherwise used by the SDK |
| `recipient` | `[u8; 43]` | **Output-note recipient** — raw 43-byte Orchard payment-address encoding (`d[11] || pk_d[32]`). The device recomputes `cmx` + `enc_ciphertext` from this and rejects mismatches; the UI then encodes it as a Bech32m UA via `orchard_encode_ua_raw` and shows it to the user for confirmation. |
| `value` | `u64` | **Output-note value** in zatoshis. Verified via cmx + enc_ciphertext; displayed to the user. |
| `rseed` | `[u8; 32]` | **Output-note random seed**. Required input to the device's `psi` / `rcm` derivation per Orchard `§ 4.7.3` **and** to the ZIP-212 esk derivation used for memo verification. |
| `memo` | `Option<[u8; 512]>` | **Output-note memo plaintext** (ZIP-302). Rebuilt on the host from the PCZT alone: `(recipient, value, rseed)` and the action's nullifier (rho) determine the note and its ephemeral secret key, and `(pk_d, esk)` opens `enc_ciphertext` (`try_output_recovery_with_pkd_esk`) — no viewing key is involved, so payments, change and zero-value padding are all covered. Sent as the trailing 512 bytes of the wire format so the device can recompute `enc_ciphertext`. The workflow always sets it; an output it cannot open makes it fail with `OutputNotRecoverable`. `None` produces the compact form, which the device refuses. |

`esk` is never part of the struct or the wire — the device derives it on-chip from `rseed + rho` per ZIP-212.

Wire formats: `ActionData::serialize_v6()` — the only action wire format on this branch — emits the pool-tagged **1416-byte** memo-verifying payload. (With `memo: None` it emits the pool-tagged 904-byte compact form, which current firmware refuses for every output; the workflow never produces it.) The untagged 903-byte legacy serialization is private and never sent on the wire.

The trailing `(recipient, value, rseed, memo)` block is what the host contributes to on-device output verification: without `recipient/value/rseed` the device cannot recompute cmx; without `memo` it cannot recompute `enc_ciphertext`. The host's rule is therefore to send the full 1416-byte body for **every** output, and to refuse to start (typed error `OutputNotRecoverable`, before proving, nothing sent) when it cannot rebuild one. **One exception:** in the sealed Orchard pool the upstream `orchard` builder gives the zero-value output it pairs with an external-scope spend a *random* `enc_ciphertext` by design; it cannot be opened. For an output in the Orchard pool with value 0 that does not open, the host still sends the full body, declaring 512 zero bytes of memo; the device tolerates the non-matching ciphertext only for a zero-value sealed-Orchard output to one of its own addresses with the expected `epk` and no memo, and does not show it. Every other output that does not open (any Ironwood output, any non-zero value) is `OutputNotRecoverable`.

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
3. **`TxMeta`** carries `coin_type` (bytes 166-169) — the device validates that it matches the `coin_type` from `FvkReq`
4. **Pre-proof validation** — v6-only: the SDK accepts exactly two consensus branch IDs, NU6.3 (`0x37a5165b`) and NU7 (`0x77190ad9`), and rejects any PCZT with another branch ID (older *or* newer) or whose transaction version is not v6 (`0x80000006`) before expensive Halo2 proof generation. NU7 keeps the v6 transaction format, the ZIP-244 digest personalizations and Orchard protocol revision V3, so the wire protocol and the device are unchanged; the device binds the branch ID through the sighash it recomputes

If a mismatch is detected (e.g., `FvkReq(coin_type=133)` followed by `TxMeta(coin_type=1)`), the device returns `NetworkMismatch` (error 0x05).

The `coin_type` extension in TxMeta (the trailing 4 bytes, 166-169 in the v6 layout) is **not** part of the ZIP-244 sighash computation — it is appended after the core fields for network validation only.

**Note:** `consensus_branch_id` values (e.g., Nu5 = `0xc2d6d0b4`, Nu6.3 = `0x37a5165b`, Nu7 = `0x77190ad9`) are identical on mainnet and testnet. Only `coin_type` (133 vs 1) reliably distinguishes the networks, because it determines the ZIP-32 key derivation path.

### NU6.3 / Ironwood (v6 transactions)

From NU6.3 a transaction may carry actions in two Orchard-protocol pools: the
**sealed Orchard pool** (spend-only turnstile withdrawals, cross-address
transfers disabled by consensus) and the new **Ironwood pool** (ZIP 258, using
V3 quantum-recoverable note plaintexts per ZIP 2005). The SDK handles both:

- **TxMeta v6 layout (170 bytes)**: inserts `ironwood_flags[1] ||
  ironwood_value_balance[8 LE] || ironwood_anchor[32]` after the Orchard
  anchor. This is the only layout on the wire — the strict device rejects
  the legacy v5 sizes. Under v6 the anchors
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

**NU7** (consensus branch `0x77190ad9`; mainnet height 3,543,405, testnet
4,465,026) keeps all of the above: same v6 transaction format, same ZIP-244
personalizations, same Orchard protocol revision (V3 / post-NU6.3 circuit).
What it changes for a wallet is timing — 25 s target block spacing, a default
transaction expiry of target height + 120 blocks (was + 40), and the scaled
ZIP 318 anchor / expiry grid — all of which are decided by the host wallet
(`zcash_client_backend`), not by this SDK or the device. The only NU7-specific
value on the wire is the branch ID in TxMeta, which the device hashes into the
header digest and the sighash personalization.

## On-Device Verification — five composed invariants

The SDK + device cooperate to enforce five security invariants, in order, before any RedPallas signature is produced. Each is a library-level state-machine invariant on the device side: a hostile firmware cannot extract a signature by skipping any of them, and no component of the ZIP-244 sighash or of any output note is taken on faith from the companion.

### 1. ZIP-244 sighash recomputed on-device

Before signing, the SDK extracts transaction metadata and action data from the PCZT and sends them to the device. The device independently computes the complete ZIP-244 v6 (five-leaf) shielded sighash and refuses to sign if it doesn't match.

A compromised companion cannot trick the device into signing an arbitrary transaction — the device recomputes the sighash from the raw transaction components.

Per-component breakdown:
- **`header_digest`** — recomputed on-device from `TxMeta` (`ZTxIdHeadersHash`)
- **`transparent_sig_digest`** — when transparent inputs/outputs are present, the SDK streams them via `TxTransparentInput` / `TxTransparentOutput` and the device recomputes the digest from those bytes; constant-time compared against the value in `TxMeta`. In practice this covers transparent **outputs** (a shielded → t-address send): `DeviceSigner` does not submit transactions with transparent **inputs** — the workflow fails with `HwSignerError::TransparentInputsNotSupported` before proof generation and before any device I/O.
- **`sapling_digest`** — *Orchard-only invariant*: the SDK refuses to send any PCZT containing Sapling spends or outputs (`HwSignerError::SaplingNotSupported`); the device additionally enforces `sapling_digest == BLAKE2b-256("ZTxIdSaplingHash", [])` on `TxMeta` receipt. Either side catches a hostile companion that would otherwise siphon value via a Sapling output the device never sees in the Orchard stream.
- **`orchard_digest`** — recomputed on-device from streamed action data via three parallel BLAKE2b-256 digesters (compact / memos / non-compact)

### 2. NoteCommitment (cmx) recomputed per action

Hashing the encrypted action stream is not enough by itself: the cmx field of an action is opaque to ZIP-244 hashing, so a hostile companion could put a cmx that commits to `(attacker_address, value)` while telling the device's UI "send to <Mario>". Defence: the device recomputes the cmx from the unencrypted note plaintext the companion declares (`recipient`, `value`, `rseed` — bundled into every TX_OUTPUT action payload, see `ActionData` above), and rejects the action if the recomputation does not match the cmx in the encrypted action bytes. An attacker would have to break Sinsemilla.

The host-side fix is `HwSignerError::SaplingNotSupported` plus the per-action plaintext extraction in `workflow.rs`. The device-side fix is `orchard_signer_feed_action_with_note_and_memo()` returning `SIGNER_ERR_NOTE_COMMITMENT_MISMATCH` (HWP error `0x0D`) on mismatch, before any orchard digest hashing.

### 3. Output `enc_ciphertext` recomputed per action (memo binding)

cmx covers `(d, pk_d, value, rho, rseed)` but does **not** cover the 512-byte memo. A host that has been forced through cmx-recomputation can still embed any memo plaintext inside `enc_ciphertext` and show the user a different one on its UI — the recipient sees the attacker's memo on chain.

The SDK's part is to recover the memo and forward it to the device for full ciphertext re-encryption. For each action, before the Halo2 proof step:

1. For each `pczt::Action`, `workflow.rs` rebuilds the output note from the PCZT's `(recipient, value, rseed)` and the action's nullifier (rho) and derives its ephemeral secret key `esk`
2. It calls `try_output_recovery_with_pkd_esk` from `zcash_note_encryption`, decrypting `enc_ciphertext` with `(pk_d, esk)` to recover `(note, address, memo)` — this also checks that the ciphertext really encrypts the note the PCZT describes
3. The memo plaintext is stored in `ActionData::memo` and shipped to the device as the trailing 512 bytes of the memo-verifying wire payload (pool-tagged v6 format, 1416 B)
4. The device recomputes `enc_ciphertext = ChaCha20-Poly1305(K_enc, IV=0, leadByte‖d‖value‖rseed‖memo)` with `K_enc = BLAKE2b("Zcash_OrchardKDF", repr_P(epk)‖repr_P([esk]·pk_d))` and `esk = ToScalar(PRF^expand(rseed,[0x04]‖ρ))` derived on-chip; ct-compares byte-for-byte against the action's `enc_ciphertext` AND `ephemeral_key`. Mismatch → `MemoMismatch` (HWP error `0x0F`).

`esk` is **not** carried on the wire — both sides derive it deterministically from `rseed + rho` per ZIP-212, removing one trust-from-companion vector.

No viewing key is needed for this (the device's FVK is not requested by the workflow): the outgoing viewing key an output was built with — the account's, someone else's, or none — makes no difference. An output whose ciphertext does not match the PCZT's note fields cannot be described to the device: `sign()` returns `HwSignerError::OutputNotRecoverable` before proving and before any transaction data is sent. This applies to zero-value outputs too (the device refuses the 904-byte form for every output, `MemoRequired`), with the single exception of the sealed-Orchard zero-value output of a turnstile transaction described under `ActionData` above, which is sent with a zero memo.

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
2. At the sighash sentinel the device computes the transaction's totals itself: `fee = t_in_total − t_out_total + value_balance(Orchard) + value_balance(Ironwood)` and the total leaving the wallet (external shielded outputs + transparent outputs + fee), with overflow and non-negative checks (`FeeOverflow` / `FeeNegative` / `ValueOverflow` on hostile values, reported before any screen is shown)
3. After the per-output review, the totals are rendered on the trusted screen (a mandatory screen of the device firmware)
4. Only after explicit user OK does the device go on to compare the sighash; the final confirmation at the first `SIGN_REQ` shows the same device-computed totals again. The `amount` and `fee` fields the host puts in `SIGN_REQ` are ignored by the device

The SDK does not need any change for this either; the fee math + confirmation flow is fully device-side and is driven automatically by the HWP dispatcher in `libzcash-ironwood-c`.

### Protocol flow (integrated into `sign()`)

1. SDK extracts `TxMeta` from the PCZT (170 bytes, v6 layout only)
2. `TxMeta` is sent as a `TxOutput` with `output_index = 0xFFFF` (metadata sentinel)
3. SDK rebuilds each output note from the PCZT and opens `enc_ciphertext` with `(pk_d, esk)` to recover the memo plaintext (fails with `OutputNotRecoverable` if any output does not open)
4. SDK extracts each action's full components (pool-tagged 1416 bytes per action, for every action) — including the unencrypted `recipient[43]`, `value[8]`, `rseed[32]`, and `memo[512]`.
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
| **Transparent inputs** | Not signed through `DeviceSigner`: a PCZT that spends transparent coins is refused on the host (`TransparentInputsNotSupported`) before proving and before any device I/O. Transparent outputs are reviewed on the device like any other output. | Refused (host) |
| **Sapling-component lockout** | SDK rejects any PCZT with Sapling spends or outputs (`HwSignerError::SaplingNotSupported`) before transmission; device additionally enforces `sapling_digest == ZIP-244 empty-bundle constant` on `TxMeta` receipt. Prevents value siphoning via a hidden Sapling output the device never sees in the Orchard stream. | Active (via `DeviceSigner` + workflow) |
| **NoteCommitment (cmx) verification** | Device recomputes `cmx = Extract_P(NoteCommit(g_d, pk_d, value, rho, psi))` for every Orchard action from the unencrypted note plaintext the SDK appends to each `TxOutput` payload, and rejects mismatches (`SIGNER_ERR_NOTE_COMMITMENT_MISMATCH`). Prevents a hostile companion from substituting the recipient between the displayed UI and the on-chain effect of the signed transaction. | Active (via `DeviceSigner`) |
| **No-blind-signing invariant (per output)** | Device-side library refuses to advance the signer state to `VERIFIED` unless every captured action has been explicitly confirmed via `orchard_signer_confirm_action()`. The firmware UI is responsible for displaying recipient + value per output and capturing user approval; the lib enforces that without that step, no signature is produced. | Active (device-enforced) |
| **Memo verification via enc_ciphertext recomputation** | SDK recovers each output's memo from the PCZT (`try_output_recovery_with_pkd_esk`) and ships it in the memo-verifying wire payload (pool-tagged v6). Device re-encrypts on-chip (Pallas ECDH + Orchard KDF + ChaCha20-Poly1305, esk derived from rseed+ρ per ZIP-212) and ct-compares against the action's `enc_ciphertext` + `ephemeral_key`; mismatch → `SIGNER_ERR_MEMO_MISMATCH`. Prevents a hostile companion from showing one memo on its UI and embedding another on chain. | Active (via `DeviceSigner` + workflow) |
| **Fee and totals confirmation** | Device computes `fee = Orchard value balance + Ironwood value balance − transparent outputs` on-chip (transparent inputs are refused), refusing a non-zero balance on a pool without actions, amounts above the supply, overflow and negative fees; it shows the fee and the total leaving the wallet and refuses to advance `verify()` until the user approves the totals (total leaving the wallet + fee). Prevents `value_balance` inflation that would silently siphon the surplus to miners. | Active (device-enforced) |

**Protocol hardening:**

- **Device attestation** — first pairing stores the device's identity pubkey (`DeviceSigner::pair()`); later sessions verify a fresh RedPallas challenge-response against the pinned key (`new_with_pinned_pubkey` / `attest`), with a device that implements it (the bundled `libzcash-ironwood-c` dispatcher and FlipZcash do not yet; the ESP32 port does), catching USB-hub MITM, TCP impostors, and reflashed devices
- **Constant-time comparisons** — RK verification uses `subtle::ConstantTimeEq` to prevent timing side-channel attacks
- **Zeroize on drop** — `SignRequest`, `SignResponse`, and `ExportedFvk` implement `Zeroize + ZeroizeOnDrop` to scrub sighash, alpha, signatures, and key material from memory
- **Recipient validation** — Recipient addresses exceeding 255 bytes are rejected (no silent truncation)
- **Keepalive limits** — All PING loops are capped to prevent infinite loops from misbehaving devices
- **Sighash log truncation** — Only first 8 bytes of sighash are logged to limit exposure

**Security boundaries to be aware of:**

What the device checks, and what it does not, is defined by the device library, not by this SDK: see `libzcash-ironwood-c`'s README ("On-Device Verification — what the host is, and is not, trusted for") and SECURITY.md ("What binds each host-supplied field"). In short:

- The device recomputes the ZIP-244 sighash, every output's note commitment and (for every output that carries value) its `enc_ciphertext`; decides on its own keys which outputs are change; and computes the fee and the total leaving the wallet only from data bound by the sighash, refusing a value balance on a pool without actions.
- It does **not** verify the spend side (which notes, anchors, nullifiers) or the Halo 2 proof, and does not show expiry height or lock time. Its total is an upper bound on what the wallet loses, exact when all inputs are the wallet's.
- Earlier revisions of this README said the device trusted the companion only for the proof. That was wrong: until November 2026 a host could hide a fee in the value balance of a pool with no actions, and change outputs were not recognised by the device. Both are fixed in the device library (`17d4ee0` onward).
- The review order is enforced by the library's state machine as an ordering guard for the firmware; a firmware holds the keys and could bypass it deliberately.
- Transparent inputs are not supported by the device.
- The SDK does not address physical security of the device (no secure element, no tamper resistance).

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
- **HWP v6-only protocol** implementation matching this SDK's host-side protocol (its own `v6-only` branch rejects the legacy v2–v5 wire tiers), including the memo-verifying + pool-tagged action payloads and the on-chip fee and totals computation (device attestation is a signing primitive there, not handled by its dispatcher)
- **Target-agnostic protocol dispatcher** (`hwp_dispatcher.h`) — the full device-side state machine (drain → parse → switch → reply, PING/PONG keepalive, IDLE detection, multi-frame drain handling, per-output review, recipient binding, fee review) lives in the library and is exposed through a callback-based API. A new device target wires up ~6 I/O + UI callbacks and gets the protocol implementation for free. The Rust SDK ↔ libzcash protocol contract is therefore mirrored on both sides by one canonical implementation each, not re-derived per device target.
- **Orchard note-encryption recomputation** — `orchard_compute_enc_ciphertext{,_from_rseed}` rebuilds the 580-byte AEAD ciphertext on-chip for memo verification (Pallas ECDH + `BLAKE2b("Zcash_OrchardKDF", ...)` + ChaCha20-Poly1305)
- **Crypto primitives**: BLAKE2b, SHA-256/512, HMAC, PBKDF2 (with optional progress callback for PIN unlock UI), AES-256 (FF1), ChaCha20-Poly1305 (RFC 7539, KAT-verified)
- **BIP39** mnemonic generation
- **Zero external dependencies** — portable to any platform with a C11 compiler

Together, the two projects form a complete plug-and-play stack: `libzcash-ironwood-c` runs on the device (firmware) and owns everything below the wire, `zcash-hw-wallet-sdk` runs on the host (wallet application) and owns everything above the wire, and the HWP protocol between them is the frozen contract that lets the two halves evolve independently. A new device firmware reduces to platform-specific I/O + UI glue; a new wallet application reduces to building PCZTs and calling `PcztHardwareSigning::sign_with_details()`.

## librustzcash Compatibility

The SDK builds against the **published NU7 release set on crates.io** (2026-10-21) — `pczt 0.10.0`, `orchard 0.16.0`, `zcash_primitives 0.31.0`, `zcash_protocol 0.11.0`, `zcash_address 0.14.0` — which covers both the NU6.3 and NU7 consensus branches. MSRV is Rust 1.89 (inherited from those crates). No `[patch.crates-io]` section is needed for a standalone build. The external-signing APIs it relies on are:

- **`pczt`** — `Signer::shielded_sighash()` returns the computed sighash for external signing
- **`pczt`** — `Signer::apply_orchard_signature(index, signature)` / `apply_ironwood_signature(index, signature)` inject an externally-produced RedPallas signature per pool
- **`pczt`** — `low_level_signer::sign_orchard_with()` / `sign_ironwood_with()` provide callback access to the parsed bundle for reading alpha, rk, and action data

These first landed upstream in commit [`feefa606`](https://github.com/zcash/librustzcash/commit/feefa606) ("pczt: Support appending external signatures to inputs", Nov 2025) and have shipped on crates.io since `pczt` 0.6.0; the Ironwood (PCZT v2) APIs shipped with `pczt` 0.8. The `librustzcash` git submodule in this repo is kept for reference only and is not part of the build. (When the SDK is built as a path dependency of the `zipher-app` workspace, that workspace must be on the same crate set: `zcash_client_backend 0.25.0` / `zcash_client_sqlite 0.23.0`.)

## Dependencies

| Crate | Version | Purpose |
|---|---|---|
| `pczt` | 0.10.0 | PCZT roles (prover, signer, extractor) — Ironwood-aware (PCZT v2) |
| `orchard` | 0.16.0 | Orchard-protocol circuit keys, Ironwood pool, V3 notes |
| `zcash_primitives` | 0.31.0 | Transaction data, `TxIdDigester`, transparent sighash |
| `zcash_protocol` | 0.11.0 | Consensus parameters, branch IDs (NU6.3, NU7) |
| `zcash_address` | 0.14.0 | Unified Address encoding for display |
| `reddsa` | 0.6 | RedPallas signature verification |
| `ff` | 0.14 | Finite field traits (alpha serialization) |
| `zcash_note_encryption` | 0.5 | Open each output's `enc_ciphertext` with `(pk_d, esk)` to recover the memo plaintext for memo-verification |
| `zeroize` | 1 | Secure memory erasure for sensitive data |
| `subtle` | 2 | Constant-time cryptographic comparisons |
| `rand_core` / `rand` | 0.10 | Platform CSPRNG (`rand::rngs::SysRng`): fresh attestation challenge nonces, and the RNG handed to the `pczt` Prover role |
| `serialport` | 4 | USB serial (optional, feature `serial`) |
| `hidapi` | 2 | Ledger USB HID (optional, feature `ledger`) |
| `thiserror` | 2 | Error type derivation |
| `tracing` | 0.1 | Structured logging |

## TODO

- [x] **On-device ZIP-244 sighash verification** — Device independently computes the full ZIP-244 sighash from transaction metadata + action data and verifies it matches.
- [x] **Network discrimination** — `coin_type` in FvkReq and TxMeta enables mainnet/testnet selection, with device-side validation.
- [x] **Integration tests** — Virtual HWP device (C/TCP, built from the device library) + 55 end-to-end Rust tests (56 defined, 1 needs a second device), 34 of them security tests (`sec_*`). Run locally as described in CONTRIBUTING.md; CI runs the same suite.
- [x] **Transparent digest verification** — Device independently computes transparent txid digest from raw inputs/outputs and refuses to sign on mismatch. Prevents forged transparent digests from compromised companions.
- [ ] **Transparent per-input signing** — withdrawn (November 2026): the device-side per-input sighash was not the ZIP-244 signature hash, so `DeviceSigner` refuses PCZTs with transparent inputs (`TransparentInputsNotSupported`) until the device implements it correctly. Shielded → transparent sends (transparent outputs only) are supported.
- [x] **Transparent sighash hardening** — Integrated librustzcash PR #2278: `SignableInput::from_parts` validates input index at construction time, preventing out-of-range index attacks.
- [x] **Sapling-component lockout** — SDK pre-rejects PCZTs with Sapling components; device enforces `sapling_digest == empty-bundle constant`.
- [x] **NoteCommitment (cmx) verification** — Device recomputes Sinsemilla NoteCommit per action and rejects recipient-substitution attempts. KAT against `librustzcash` Note::commitment().
- [x] **No-blind-signing invariant (per output)** — Device-side library state machine refuses to sign without explicit per-output user confirmation. Reference port (ESP32) confirms via BOOT button + CDC log; FlipZcash confirms via screen + OK button.
- [x] **Memo verification via enc_ciphertext recomputation** — SDK recovers each output's memo from the PCZT and ships it in the memo-verifying wire payload (pool-tagged v6, 1416 B). Device re-encrypts on-chip (Pallas ECDH + Orchard KDF + ChaCha20-Poly1305 RFC 7539, esk derived from rseed+ρ per ZIP-212) and ct-compares against the action's `enc_ciphertext` + `ephemeral_key`. Closes the memo-substitution attack hanh raised.
- [x] **Fee and totals confirmation** — Device computes the fee and the total leaving the wallet on-chip from values bound by the sighash, with overflow, negative-fee, supply-limit and empty-pool-balance checks, and refuses to advance `verify()` until the user approves the totals.
- [x] **Upstream pczt release** — Resolved: the SDK now builds against the published crates.io releases (currently `pczt 0.10.0`, `orchard 0.16.0`); the librustzcash submodule and `[patch.crates-io]` table are no longer required.
- [x] **Device attestation** — First-pairing identity pinning + per-session RedPallas challenge-response (`pair()` / `attest()` / `new_with_pinned_pubkey`, HWP 0x0F–0x12). Catches device substitution between sessions (audit M1).
- [ ] **External security audit** — Required before any production/mainnet use
- [ ] **QR transport testing** — The QR transport is untested with real hardware. Needs end-to-end validation with an air-gapped device.
- [ ] **Sapling-only recipient support** — Out of scope for the Orchard-only design. Recipients with no Orchard receiver in their UA are not supported; recipients should expose a UA with an Orchard receiver. If ever needed, would require streaming sapling spends/outputs to the device for digest recomputation rather than the current empty-bundle enforcement.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
