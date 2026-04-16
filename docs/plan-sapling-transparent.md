# Piano: Supporto Sapling + Transparent nel Zcash HW Wallet SDK

## Contesto

L'SDK attualmente supporta solo Orchard (Pallas/RedPallas). Il PCZT standard e librustzcash supportano gia' tutti e tre i pool. L'utente vuole capire lo sforzo e avere un piano per aggiungere Sapling e Transparent.

**Verdetto: lo sbatti c'e', ma e' gestibile facendolo a fasi.** L'SDK e' la parte piu' ragionevole (~1-2 settimane). Il firmware device e' il collo di bottiglia (~3-4 settimane) perche' servono nuove curve ellittiche in C.

---

## Stato attuale

| Layer | Orchard | Sapling | Transparent |
|-------|---------|---------|-------------|
| PCZT lib (librustzcash) | Full | Full | Full |
| SDK Rust (`HardwareSigner`, workflow) | Full | - | - |
| HWP protocol | Full (v2) | - | - |
| Device C (ESP32) | Full | - | - |

**Buone notizie:** `pczt` con feature `signer` gia' compila `sapling` + `transparent`. Le API `apply_sapling_signature()`, `append_transparent_signature()`, `transparent_sighash(index)`, `SpendFinalizer` sono gia' disponibili. La sighash shielded e' condivisa tra Orchard e Sapling.

---

## Fase 1 — SDK: Tipi e Trait (2-3 giorni)

### 1.1 Pool capabilities (`src/types.rs`)
```rust
bitflags! {
    pub struct PoolCapabilities: u8 {
        const ORCHARD     = 0b001;
        const SAPLING     = 0b010;
        const TRANSPARENT = 0b100;
    }
}
```

### 1.2 Nuovi tipi sign request/response (`src/types.rs`)

**Sapling** — struttura quasi identica a `SignRequest` (stessa sighash condivisa, stesso alpha pattern):
- `SaplingSignRequest { sighash, alpha, amount, fee, recipient, spend_index, total_spends }`
- `SaplingSignResponse { signature: [u8; 64], rk: [u8; 32] }` — RedJubjub

**Transparent** — sighash PER-INPUT (differenza critica):
- `TransparentSignRequest { sighash, input_index, total_inputs, value, script_pubkey, pubkey: [u8; 33] }`
- `TransparentSignResponse { signature: Vec<u8>, pubkey: [u8; 33] }` — ECDSA DER-encoded

**FVK multi-pool:**
- `SaplingExportedFvk { ak, nk, ovk }` (3x 32 bytes)
- `TransparentExportedFvk { chain_code: [u8; 32], public_key: [u8; 33] }`
- `UnifiedExportedFvk { orchard: Option<ExportedFvk>, sapling: Option<SaplingExportedFvk>, transparent: Option<TransparentExportedFvk> }`

### 1.3 Estensione trait (`src/traits.rs`)

Nuovi metodi con **default che ritorna `UnsupportedPool`** — backward compatible, i device Orchard-only continuano a funzionare:

```rust
fn pool_capabilities(&self) -> PoolCapabilities { PoolCapabilities::ORCHARD }
fn sign_sapling_spend(&mut self, req: &SaplingSignRequest) -> Result<SaplingSignResponse> { Err(UnsupportedPool("sapling")) }
fn sign_transparent_input(&mut self, req: &TransparentSignRequest) -> Result<TransparentSignResponse> { Err(UnsupportedPool("transparent")) }
fn export_unified_fvk(&mut self) -> Result<UnifiedExportedFvk> { /* wrap orchard-only */ }
```

### 1.4 Nuovi errori (`src/error.rs`)
- `UnsupportedPool(&'static str)`
- `SaplingProofFailed(String)`
- `TransparentFinalizeFailed(String)`
- `SaplingSignatureVerificationFailed { spend_idx, reason }`
- `TransparentSignatureVerificationFailed { input_idx, reason }`

### File coinvolti
- `src/types.rs` — nuovi tipi + PoolCapabilities
- `src/traits.rs` — estensione HardwareSigner
- `src/error.rs` — nuove varianti errore

---

## Fase 2 — SDK: Workflow multi-pool (5-7 giorni)

### 2.1 Flusso signing aggiornato (`src/workflow.rs`)

```
1. Parse PCZT, valida branch_id (esistente)
2. Se ci sono Sapling spends senza proof → Groth16 prover (NUOVO)
3. Orchard prover Halo2 (esistente)
4. Init pczt::roles::signer::Signer
5. Orchard: verify_sighash + sign_action per ogni action (esistente)
6. Sapling: sign_sapling_spend per ogni spend (NUOVO, stessa shielded_sighash)
7. Transparent: transparent_sighash(i) + sign_transparent_input per ogni input (NUOVO)
8. SpendFinalizer::finalize_spends() per transparent (NUOVO)
9. Return SigningResult con contatori per pool
```

**Nota critica Sapling prover:** richiede parameter files Groth16 (~66MB). Il workflow deve accettarli come parametro opzionale o come feature flag con `zcash_proofs`.

### 2.2 Verifica firme (`src/verify.rs`)

**Sapling:** identica struttura a Orchard ma con `reddsa::sapling::SpendAuth` (Jubjub) invece di `reddsa::orchard::SpendAuth` (Pallas). Stessa logica: ct_eq su rk + verify signature.

**Transparent:** verifica ECDSA via `secp256k1::Secp256k1::verify_ecdsa()`. Defense-in-depth (il PCZT signer gia' valida internamente).

### 2.3 SigningResult aggiornato
```rust
pub struct SigningResult {
    pub signed_pczt: Vec<u8>,
    pub orchard_actions_signed: usize,
    pub sapling_spends_signed: usize,
    pub transparent_inputs_signed: usize,
}
```

### File coinvolti
- `src/workflow.rs` — orchestrazione multi-pool (cambiamento piu' complesso)
- `src/verify.rs` — verifica RedJubjub + ECDSA
- `Cargo.toml` — eventuale dep `zcash_proofs` per Sapling prover

---

## Fase 3 — Protocollo HWP (3-4 giorni)

### 3.1 Nuovi messaggi (`src/protocol/hwp.rs`)

```rust
// Sapling (0x10-0x13)
SaplingFvkReq  = 0x10,
SaplingFvkRsp  = 0x11,  // ak(32)||nk(32)||ovk(32) = 96 bytes
SaplingSignReq = 0x12,  // sighash(32)||alpha(32)||amount(8)||fee(8)||recipient
SaplingSignRsp = 0x13,  // sig(64)||rk(32) = 96 bytes

// Transparent (0x20-0x23)
TransparentFvkReq  = 0x20,
TransparentFvkRsp  = 0x21,  // chain_code(32)||pubkey(33) = 65 bytes
TransparentSignReq = 0x22,  // sighash(32)||input_idx(2)||value(8)||derivation_path
TransparentSignRsp = 0x23,  // DER_sig||sighash_type||pubkey(33)

// Capability discovery (0x30-0x31)
CapabilitiesReq = 0x30,
CapabilitiesRsp = 0x31,  // PoolCapabilities bitfield (1 byte)
```

**Backward compat:** versione frame resta 0x02. Device vecchi rispondono `Error(Unknown)` a messaggi sconosciuti → SDK assume Orchard-only.

### 3.2 DeviceSigner esteso (`src/signer.rs`)
- `request_capabilities()` al connect → fallback Orchard-only se errore
- `sign_sapling_spend()` → encode SaplingSignReq, parse SaplingSignRsp
- `sign_transparent_input()` → encode TransparentSignReq, parse TransparentSignRsp
- `export_unified_fvk()` → FvkReq per ogni pool supportato

### File coinvolti
- `src/protocol/hwp.rs` — nuovi MsgType + encode/parse functions
- `src/signer.rs` — DeviceSigner implementa nuovi trait methods

---

## Fase 4 — Firmware Device (15-25 giorni, il grosso dello sbatti)

### 4.1 Sapling: Jubjub + RedJubjub (~10-15 giorni)
- **Jubjub curve** in C: twisted Edwards su BLS12-381 scalar field. ~2500 linee, struttura simile a `pallas.c`
- **RedJubjub signing**: identico pattern a `redpallas.c` ma su Jubjub. ~200 linee
- **ZIP-32 Sapling derivation**: PRF^expand con chiavi Jubjub. ~300 linee
- **Firmware state machine**: handler per `SaplingSignReq/Rsp` in `main.c`
- **RAM:** ~25KB codice (no Sinsemilla table per Jubjub)

### 4.2 Transparent: secp256k1 + ECDSA (~8-12 giorni)
- **secp256k1 curve** in C: implementazione minimale (~3000 linee) o wrap di micro-ecc/tinysecp256k1
- **ECDSA signing**: con RFC 6979 nonce deterministici (sicurezza critica)
- **BIP-32 key derivation**: HMAC-SHA512 chain (gia' disponibili HMAC + SHA-512). ~200 linee
- **Firmware state machine**: handler per `TransparentSignReq/Rsp`
- **RAM:** ~20-25KB codice

### File coinvolti (libzcash-orchard-c → rinominare?)
- NUOVO: `src/jubjub.c` + `include/jubjub.h` — curva Jubjub
- NUOVO: `src/redjubjub.c` + `include/redjubjub.h` — firme RedJubjub
- NUOVO: `src/secp256k1.c` + `include/secp256k1.h` — curva secp256k1
- NUOVO: `src/ecdsa.c` + `include/ecdsa.h` — firme ECDSA
- NUOVO: `src/bip32.c` + `include/bip32.h` — derivazione transparent
- MODIFICA: `src/zip244.c` — opzionale: verifica on-device per Sapling digest
- MODIFICA: ESP32 `main/main.c` + `main/wallet.c` — nuovi handler messaggi

---

## Fase 5 — Test (3-5 giorni)

- Estendere `MockSigner` con capabilities configurabili
- Test mixed-pool: Orchard+Transparent, Sapling+Transparent, tutti e tre
- Test capability fallback: device Orchard-only con PCZT multi-pool
- Test vectors RedJubjub da zcash test-vectors
- Test vectors ECDSA da Bitcoin BIP-340/BIP-341
- Integration test con virtual device TCP esteso

---

## Riepilogo sforzo

| Fase | Scope | Stima | Dipende da |
|------|-------|-------|------------|
| 1. Tipi + Trait | SDK | 2-3 giorni | - |
| 2. Workflow multi-pool | SDK | 5-7 giorni | Fase 1 |
| 3. Protocollo HWP | SDK | 3-4 giorni | Fase 1 |
| 4. Firmware device | C/ESP32 | 15-25 giorni | Fase 3 |
| 5. Test | SDK+device | 3-5 giorni | Fase 2+3 |
| **Totale** | | **~28-44 giorni** | |

**Solo SDK (Fasi 1-3+5):** ~13-19 giorni — il device puo' venire dopo.

---

## Strategia consigliata

1. **SDK first** (Fasi 1-3): rende l'SDK pronto per qualsiasi hardware multi-pool. Testabile con `MockSigner` o signer software.
2. **Transparent prima di Sapling** nel device: e' il caso d'uso piu' richiesto (ricevere da exchange, spendere change) e secp256k1 e' piu' semplice di Jubjub.
3. **Sapling proofs opzionali** via feature flag `sapling-prover`: evita i 66MB di parametri Groth16 per chi non ne ha bisogno.

## Dipendenze Cargo.toml

Gia' disponibili (via `pczt` feature `signer`):
- `redjubjub` — verifica firme Sapling
- `secp256k1` — verifica firme Transparent
- `sapling-crypto` — tipi Sapling (gia' patchato)

Da aggiungere:
- `bitflags = "2"` — per PoolCapabilities
- `zcash_proofs` (opzionale) — per Sapling Groth16 prover
