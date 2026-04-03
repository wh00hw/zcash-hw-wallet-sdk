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

Transport-agnostic Rust SDK for signing Zcash Orchard shielded transactions via hardware wallets using the [PCZT](https://zips.z.cash/zip-0320) (Partially Created Zcash Transaction) standard.

## The Problem

Zcash Orchard has no standardized way for hardware wallets to participate in shielded transaction signing. Existing approaches are tightly coupled to specific hardware and don't use PCZT. Every new hardware wallet project has to solve this independently.

## The Insight

The **only** operation that requires the spending key (`ask`) is the RedPallas spend authorization signature (~5 seconds on a microcontroller). Everything else — proof generation, blockchain sync, transaction construction — can be done with the full viewing key alone. PCZT is the ideal vehicle for this split because it already models multi-party transaction construction.

This SDK adds the **hardware signer role** to the PCZT ecosystem.

## Architecture

```
+-----------------------------------------------------+
|                  Wallet Application                  |
|              (Zashi, YWallet, custom)                |
+-----------------------------------------------------+
|                zcash-hw-wallet-sdk                   |
|  +-------------+  +------------+  +----------------+ |
|  |    PCZT     |  | Hardware   |  | Transport      | |
|  |  Workflow   |  | Signer     |  | Serial/Ledger/ | |
|  |  Manager    |  | Trait      |  | QR             | |
|  +-------------+  +------------+  +----------------+ |
+-----------------------------------------------------+
|            librustzcash (pczt, orchard)               |
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
use zcash_hw_wallet_sdk::{DeviceSigner, PcztHardwareSigning};

// Connect to a hardware signing device over USB serial
let signer = zcash_hw_wallet_sdk::signer::connect_serial("/dev/ttyACM0")?;

// Sign a PCZT (from zcash_client_backend::create_pczt_from_proposal)
let mut workflow = PcztHardwareSigning::new(signer);
let result = workflow.sign(pczt_bytes)?;

// result.signed_pczt -> extract_and_store_transaction_from_pczt()
```

### Sign a transaction with a Ledger device

```toml
[dependencies]
zcash-hw-wallet-sdk = { version = "0.1", features = ["ledger"] }
```

```rust
use zcash_hw_wallet_sdk::{DeviceSigner, PcztHardwareSigning};

// Auto-detect the first connected Ledger (Zcash Orchard app must be open)
let signer = zcash_hw_wallet_sdk::signer::connect_ledger()?;

let mut workflow = PcztHardwareSigning::new(signer);
let result = workflow.sign(pczt_bytes)?;
```

For development with the Speculos emulator:

```rust
let signer = zcash_hw_wallet_sdk::signer::connect_speculos("127.0.0.1:9999")?;
```

### Implement support for your own hardware

To add Zcash Orchard support to **any** hardware wallet:

1. `cargo add zcash-hw-wallet-sdk`
2. Implement the `HardwareSigner` trait (4 methods, 2 have defaults)
3. Done

```rust
use zcash_hw_wallet_sdk::*;

struct MyDevice { /* your transport handle */ }

impl HardwareSigner for MyDevice {
    fn export_fvk(&mut self) -> Result<ExportedFvk> {
        // Read FVK components (ak, nk, rivk) from your device
        todo!()
    }

    fn sign_action(&mut self, request: &SignRequest) -> Result<SignResponse> {
        // Send sighash + alpha to device, receive signature + rk
        todo!()
    }

    fn confirm_transaction(&mut self, details: &TxDetails) -> Result<bool> {
        // Optional: display transaction on device screen
        Ok(true) // default: auto-confirm (headless devices)
    }
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
5. Sighash Verify (v2)  Send each action's ZIP-244 data to device
                        via TxOutput messages (820 bytes per action).
                        Device hashes independently and verifies
                        sighash match before proceeding.
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
9. Inject Signatures    Call set_external_spend_auth_sig() per action
         |
10. Return Signed PCZT  Serialize and return for tx extraction
```

The caller then passes the signed PCZT to `extract_and_store_transaction_from_pczt` and broadcasts via lightwalletd.

## Modules

### `traits` -- `HardwareSigner`

The core trait any hardware device must implement:

| Method | Purpose | Called |
|---|---|---|
| `export_fvk(coin_type)` | Export Orchard full viewing key (ak, nk, rivk) for the given network (133=mainnet, 1=testnet) | Once, during pairing |
| `sign_action(request)` | Sign a single Orchard action given sighash + alpha | Once per action |
| `confirm_transaction(details)` | Display tx on device for user confirmation | Once per tx (optional, default: auto-confirm) |
| `verify_sighash(meta, actions, sighash)` | Send tx metadata + action data for on-device sighash verification (v2) | Once per tx (optional, default: no-op) |

### `workflow` -- `PcztHardwareSigning<S>`

The orchestrator that handles the full signing pipeline. Accepts any `S: HardwareSigner`.

| Method | Description |
|---|---|
| `new(signer, network)` | Create workflow with explicit network (mainnet/testnet) |
| `sign(pczt_bytes)` | Sign a PCZT, return `SigningResult` |
| `sign_with_details(pczt_bytes, details)` | Sign with device-side user confirmation |

### `signer` -- `DeviceSigner<T>`

A ready-to-use `HardwareSigner` implementation that communicates with any HWP-compatible device over any `Transport`.

| Constructor | Feature | Description |
|---|---|---|
| `DeviceSigner::new(transport)` | — | Connect and handshake (if required by transport) |
| `DeviceSigner::new_no_handshake(transport)` | — | Skip handshake (already done) |
| `connect_serial(path)` | `serial` | Convenience: open USB CDC serial + handshake |
| `connect_ledger()` | `ledger` | Convenience: find first Ledger USB HID device |
| `connect_speculos(addr)` | `ledger` | Convenience: connect to Speculos emulator via TCP |

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

### `protocol` -- Hardware Wallet Protocol (HWP) v2

Binary framed protocol designed for constrained devices.

**Frame format:**

```
[MAGIC:1][VERSION:1][SEQ:1][TYPE:1][LENGTH:2 LE][PAYLOAD:N][CRC16:2 LE]
```

- Magic: `0xFB`
- Version: `0x02` (backward-compatible with v1)
- CRC: CRC-16/CCITT (poly 0x1021, init 0xFFFF)
- Max payload: 1024 bytes (increased from 512 to accommodate v2 action data)

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
| `TxOutput` | 0x08 | Host -> Device | Individual output for incremental hashing (v2) |
| `TxOutputAck` | 0x09 | Device -> Host | Output hash acknowledged (v2) |
| `Abort` | 0x0A | Host -> Device | Cancel signing session |

**FVK_REQ payload:**

```
coin_type[4 LE]    // 133 = mainnet, 1 = testnet
```

The `coin_type` tells the device which ZIP-32 derivation path to use (`m/32'/coin_type'/account'`). Empty payload accepted for backward compatibility (device uses its default).

**SIGN_REQ payload:**

```
sighash[32] || alpha[32] || amount[8 LE] || fee[8 LE] || recipient_len[1] || recipient[N]
```

**TX_OUTPUT payload (v2 sighash verification):**

```
output_index[2 LE] || total_outputs[2 LE] || action_data[N]
```

Three types of TxOutput messages are used for v2 sighash verification:
- `output_index = 0xFFFF`: Transaction metadata (129 bytes) — `version[4] || version_group_id[4] || consensus_branch_id[4] || lock_time[4] || expiry_height[4] || orchard_flags[1] || value_balance[8 LE signed] || anchor[32] || transparent_sig_digest[32] || sapling_digest[32] || coin_type[4 LE]`
- `output_index = 0..N-1`: Action data (820 bytes each) — `cv_net[32] || nullifier[32] || rk[32] || cmx[32] || ephemeral_key[32] || enc_ciphertext[580] || out_ciphertext[80]`
- `output_index = N` (sentinel): Expected 32-byte ZIP-244 sighash for device comparison

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
| 0x09 | `SighashMismatch` | Device-computed sighash differs from companion (v2) |
| 0x0A | `InvalidState` | Unexpected message in current state (v2) |

### `verify` -- Signature Verification

After receiving a signature from the device, the SDK verifies:

1. **RK match** -- the randomized verification key returned by the device matches the PCZT action's expected rk
2. **RedPallas verify** -- the signature is cryptographically valid against the sighash using `reddsa::VerificationKey<orchard::SpendAuth>`

This prevents both key confusion attacks and invalid signatures.

### `error` -- `HwSignerError`

Typed error enum covering all failure modes:

- **PCZT workflow**: `ProofFailed`, `SignerInitFailed`, `NoActionsToSign`, `ExtractionFailed`
- **Signatures**: `RkMismatch`, `SignatureVerificationFailed`, `InvalidVerificationKey`
- **Device**: `DeviceError`, `UserCancelled`
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

ZIP-244 action data sent to the device for on-device sighash verification (v2):

| Field | Type | Description |
|---|---|---|
| `cv_net` | `[u8; 32]` | Value commitment |
| `nullifier` | `[u8; 32]` | Nullifier |
| `rk` | `[u8; 32]` | Randomized verification key |
| `cmx` | `[u8; 32]` | Extracted note commitment |
| `ephemeral_key` | `[u8; 32]` | Ephemeral public key |
| `enc_ciphertext` | `Vec<u8>` | Encrypted note plaintext (580 bytes) |
| `out_ciphertext` | `Vec<u8>` | Encrypted outgoing plaintext (80 bytes) |

Wire format: all fields concatenated in order, **820 bytes total** per action.

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

1. **`PcztHardwareSigning::new(signer, Network::TestNetwork)`** — the workflow requires an explicit `Network` parameter
2. **`export_fvk(coin_type)`** — the SDK sends `coin_type` in `FvkReq` payload; the device derives keys from `m/32'/coin_type'/account'`
3. **`TxMeta`** carries `coin_type` (bytes 125-128) — the device validates that it matches the `coin_type` from `FvkReq`
4. **Pre-proof validation** — the SDK rejects non-Orchard branch IDs (pre-Nu5) before expensive Halo2 proof generation

If a mismatch is detected (e.g., `FvkReq(coin_type=133)` followed by `TxMeta(coin_type=1)`), the device returns `NetworkMismatch` (error 0x05).

The `coin_type` extension in TxMeta (bytes 125-128) is **not** part of the ZIP-244 sighash computation — it is appended after the 125-byte core fields for network validation only.

**Note:** `consensus_branch_id` values (e.g., Nu5 = `0xc2d6d0b4`) are identical on mainnet and testnet. Only `coin_type` (133 vs 1) reliably distinguishes the networks, because it determines the ZIP-32 key derivation path.

## On-Device ZIP-244 Sighash Verification (v2)

The SDK implements full on-device ZIP-244 sighash verification. Before signing, the SDK extracts transaction metadata and action data from the PCZT and sends them to the device. The device independently computes the complete ZIP-244 shielded sighash and **refuses to sign** if it doesn't match.

This means a compromised companion **cannot** trick the device into signing an arbitrary transaction — the device verifies the sighash from the raw transaction components.

**Protocol flow (integrated into `sign()`):**

1. SDK extracts `TxMeta` from PCZT: header fields, orchard bundle info, pre-computed transparent signature digest and sapling digest, plus coin_type (129 bytes)
2. `TxMeta` is sent as a `TxOutput` with `output_index = 0xFFFF` (metadata sentinel)
3. SDK extracts each action's ZIP-244 components (820 bytes per action):
   - `cv_net` (32B), `nullifier` (32B), `rk` (32B), `cmx` (32B), `ephemeral_key` (32B), `enc_ciphertext` (580B), `out_ciphertext` (80B)
4. Each action is sent as a `TxOutput` message (index 0..N-1)
5. Device hashes actions incrementally into three parallel BLAKE2b-256 digesters (compact, memos, non-compact) per ZIP-244
6. SDK sends the expected sighash as a sentinel `TxOutput` (index = N)
7. Device computes the full ZIP-244 sighash: `header_digest || transparent_digest || sapling_digest || orchard_digest`
8. Device compares computed sighash with received sentinel — returns `SighashMismatch` on mismatch
9. On subsequent `SignReq`, device verifies the sighash matches the one it computed
10. Only after successful verification does signing proceed

**Device-side ZIP-244 implementation** is provided by `libzcash-orchard-c` (`zip244.h`/`zip244.c`) with the full digest tree:
- Header digest (`ZTxIdHeadersHash`)
- Transparent signature digest and sapling digest — pre-computed by the SDK and included in `TxMeta`, since the device only has access to the Orchard bundle
- Orchard digest (`ZTxIdOrchardHash`) from three sub-hashes: compact (`ZTxIdOrcActCHash`), memos (`ZTxIdOrcActMHash`), non-compact (`ZTxIdOrcActNHash`)
- Root sighash (`ZcashTxHash_` + consensus_branch_id)

**Note:** The SDK uses `Pczt::into_effects()` and `TxIdDigester` from `zcash_primitives` to extract the transparent and sapling sub-digests. This ensures the values are identical to what the official `pczt::roles::signer::Signer` uses internally for sighash computation. The `TxMeta` is also built from the `TransactionData` directly (not from PCZT Global fields) to guarantee field-level consistency (e.g., `lock_time` determined by `determine_lock_time()`).

**For custom `HardwareSigner` implementations:** the `verify_sighash()` trait method has a default no-op (v1 behavior: device trusts companion). Override it if your device supports on-device verification.

## Security Model

| Layer | What it protects against | Status |
|---|---|---|
| **Key isolation** | Spending key never leaves the device. Only FVK is exported. | Active |
| **Signature verification** | SDK verifies every signature before injecting into PCZT. | Active |
| **RK binding** | Each signature is bound to a specific action via the randomized verification key. | Active |
| **CRC-16 framing** | Detects corrupted data on the wire. Auto-retries on CRC errors. | Active |
| **ZIP-244 sighash verification (v2)** | Device independently computes the full ZIP-244 sighash from transaction data and refuses to sign on mismatch. | Active (via `DeviceSigner`) |

**Protocol hardening:**

- **Constant-time comparisons** — RK verification uses `subtle::ConstantTimeEq` to prevent timing side-channel attacks
- **Zeroize on drop** — `SignRequest`, `SignResponse`, and `ExportedFvk` implement `Zeroize + ZeroizeOnDrop` to scrub sighash, alpha, signatures, and key material from memory
- **Recipient validation** — Recipient addresses exceeding 127 bytes are rejected (no silent truncation)
- **Keepalive limits** — All PING loops are capped to prevent infinite loops from misbehaving devices
- **Sighash log truncation** — Only first 8 bytes of sighash are logged to limit exposure

**Security boundaries to be aware of:**

- The device computes the full ZIP-244 sighash independently. A compromised companion cannot forge a valid sighash without providing the correct transaction data.
- The SDK trusts the PCZT input (produced by `zcash_client_backend`). A compromised wallet could produce a malicious PCZT — but the device will only sign if the sighash matches the action data it received.
- Currently only Orchard-only transactions are supported for on-device verification. Transactions with transparent or Sapling components would require extending the protocol to send those digests.
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

// 3. Sign via hardware wallet (this SDK)
let signer = zcash_hw_wallet_sdk::signer::connect_serial("/dev/ttyACM0")?;
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

### Device-side: libzcash-orchard-c

The companion library [**libzcash-orchard-c**](https://github.com/wh00hw/libzcash-orchard-c) provides a pure C11 implementation of the Zcash Orchard primitives and the HWP v2 protocol, designed specifically for embedded hardware wallets where Rust is not available.

It includes:

- **ZIP-244 sighash computation** — full shielded sighash with all BLAKE2b personalizations, enabling on-device transaction verification
- **ZIP-32 key derivation** (spending key, full viewing key, addresses)
- **Pallas / RedPallas** curve arithmetic and spend authorization signing
- **Orchard Unified Address** generation with F4Jumble (ZIP-316) and Bech32m
- **HWP v2 protocol** implementation (matching this SDK's host-side protocol)
- **Crypto primitives**: BLAKE2b, SHA-256/512, HMAC, PBKDF2, AES-256 (FF1)
- **BIP39** mnemonic generation
- **Zero external dependencies** — portable to any platform with a C11 compiler

Together, the two projects form a complete stack: `libzcash-orchard-c` runs on the device (firmware), while `zcash-hw-wallet-sdk` runs on the host (wallet application), communicating over the shared HWP v2 protocol.

## librustzcash Compatibility

This SDK uses the **librustzcash `main` branch** (included as a git submodule) because the hardware wallet signing APIs it depends on are already merged upstream but **not yet published to crates.io** as a new release:

- **`pczt`** — `Signer::shielded_sighash()` returns the computed sighash for external signing
- **`pczt`** — `Signer::apply_orchard_signature(index, signature)` injects an externally-produced RedPallas signature
- **`pczt`** — `low_level_signer::sign_orchard_with()` provides callback access to the parsed `orchard::pczt::Bundle` for reading alpha, rk, and action data

These were added in commit [`feefa606`](https://github.com/zcash/librustzcash/commit/feefa606) ("pczt: Support appending external signatures to inputs", Nov 2025) and are available in librustzcash `main` but not in the published `pczt` 0.5.1 on crates.io.

Once a new pczt release is published, the `[patch.crates-io]` section in `Cargo.toml` and the librustzcash submodule can be removed.

## Dependencies

| Crate | Version | Purpose |
|---|---|---|
| `pczt` | 0.5 | PCZT roles (prover, signer, extractor) |
| `orchard` | 0.12 | Orchard circuit proving/verifying keys |
| `reddsa` | 0.5 | RedPallas signature verification |
| `ff` | 0.13 | Finite field traits (alpha serialization) |
| `zeroize` | 1 | Secure memory erasure for sensitive data |
| `subtle` | 2 | Constant-time cryptographic comparisons |
| `serialport` | 4 | USB serial (optional, feature `serial`) |
| `hidapi` | 2 | Ledger USB HID (optional, feature `ledger`) |
| `thiserror` | 2 | Error type derivation |
| `tracing` | 0.1 | Structured logging |

## TODO

- [x] **On-device ZIP-244 sighash verification** — Device independently computes the full ZIP-244 sighash from transaction metadata + action data and verifies it matches.
- [x] **Network discrimination** — `coin_type` in FvkReq and TxMeta enables mainnet/testnet selection, with device-side validation.
- [x] **Integration tests** — Virtual HWP device (C/TCP) + 14 end-to-end Rust tests, running in GitHub Actions on every push.
- [ ] **Upstream pczt release** — The SDK depends on librustzcash `main` (git submodule + `[patch.crates-io]`) for the external signing APIs. A new pczt crates.io release would remove this dependency.
- [ ] **External security audit** — Required before any production/mainnet use
- [ ] **QR transport testing** — The QR transport is untested with real hardware. Needs end-to-end validation with an air-gapped device.
- [ ] **Hardware wallet reference firmware** — Demonstrator device firmware for ESP32 or similar

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
