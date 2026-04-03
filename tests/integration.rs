//! Integration tests — validate SDK against the virtual device (libzcash-orchard-c).
//!
//! Requires the virtual device running on TCP (default: 127.0.0.1:9999).
//! Set VIRTUAL_DEVICE_ADDR to override.
//!
//! Run: VIRTUAL_DEVICE_ADDR=127.0.0.1:9999 cargo test --test integration --features tcp -- --test-threads=1

#![cfg(feature = "tcp")]

use zcash_hw_wallet_sdk::protocol::hwp::encode_frame;
use zcash_hw_wallet_sdk::protocol::{HwpCodec, MsgType};
use zcash_hw_wallet_sdk::signer::DeviceSigner;
use zcash_hw_wallet_sdk::traits::HardwareSigner;
use zcash_hw_wallet_sdk::transport::{TcpTransport, Transport};
use zcash_hw_wallet_sdk::types::{
    ActionData, SignRequest, TxMeta, COIN_TYPE_MAINNET, COIN_TYPE_TESTNET,
};

/// Expected FVK components for coin_type=133 (mainnet), "abandon...about" mnemonic.
/// From libzcash-orchard-c/tests/test_vectors.h
const EXPECTED_AK: [u8; 32] = [
    0x4c, 0x9c, 0x06, 0x6f, 0x08, 0x1a, 0x62, 0xec, 0xeb, 0x7b, 0xf8, 0x19, 0x5e, 0x44, 0x23,
    0x52, 0xfa, 0xb1, 0xfd, 0xbe, 0x57, 0x74, 0xb3, 0xfc, 0xe5, 0xee, 0x63, 0x57, 0xe2, 0x01,
    0x79, 0x0c,
];
const EXPECTED_NK: [u8; 32] = [
    0xc5, 0x9c, 0x63, 0xef, 0x35, 0x13, 0x79, 0xe9, 0x43, 0x86, 0x26, 0xc1, 0xce, 0x72, 0x0f,
    0x32, 0x33, 0xaf, 0x7a, 0x3b, 0xef, 0x8c, 0x2f, 0x2a, 0x7f, 0xc7, 0x44, 0x71, 0xdd, 0x5b,
    0x13, 0x3a,
];
const EXPECTED_RIVK: [u8; 32] = [
    0x99, 0x45, 0xa0, 0x45, 0xcd, 0x6e, 0x9c, 0xa8, 0xd8, 0x27, 0xd0, 0x39, 0xa5, 0x9a, 0x6d,
    0xc3, 0x3d, 0x19, 0x95, 0xcc, 0x42, 0x9b, 0x3d, 0xe8, 0x87, 0xd4, 0x76, 0x94, 0xa4, 0x9f,
    0x88, 0x3e,
];

// ── Helpers ──────────────────────────────────────────────────────────

fn device_addr() -> String {
    std::env::var("VIRTUAL_DEVICE_ADDR").unwrap_or_else(|_| "127.0.0.1:9999".to_string())
}

fn connect_signer() -> DeviceSigner<TcpTransport> {
    let transport =
        TcpTransport::connect(&device_addr()).expect("Failed to connect to virtual device");
    DeviceSigner::new(transport).expect("Handshake failed")
}

fn connect_codec() -> HwpCodec<TcpTransport> {
    let transport =
        TcpTransport::connect(&device_addr()).expect("Failed to connect to virtual device");
    let mut codec = HwpCodec::new(transport);
    codec.handshake().expect("Handshake failed");
    codec
}

/// Build a synthetic TxMeta for testing.
fn build_test_tx_meta(coin_type: u32) -> TxMeta {
    TxMeta {
        version: 5,
        version_group_id: 0x26A7270A,
        consensus_branch_id: 0xc2d6d0b4, // Nu5
        lock_time: 0,
        expiry_height: 0,
        orchard_flags: 0x03, // spends + outputs enabled
        value_balance: 0,
        anchor: [0xAA; 32],
        transparent_sig_digest: blake2b_personal(b"ZTxIdTranspaHash", &[]),
        sapling_digest: blake2b_personal(b"ZTxIdSaplingHash", &[]),
        coin_type,
    }
}

/// Build a synthetic 820-byte ActionData for testing.
fn build_test_action_data() -> ActionData {
    ActionData {
        cv_net: [0x01; 32],
        nullifier: [0x02; 32],
        rk: [0x03; 32],
        cmx: [0x04; 32],
        ephemeral_key: [0x05; 32],
        enc_ciphertext: vec![0x06; 580],
        out_ciphertext: vec![0x07; 80],
    }
}

/// BLAKE2b-256 with a 16-byte personalization.
fn blake2b_personal(personal: &[u8; 16], data: &[u8]) -> [u8; 32] {
    let h = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(personal)
        .hash(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

/// Compute the ZIP-244 sighash from TxMeta + actions (Rust-side).
/// Must produce the same result as the C library's zip244_shielded_sighash().
fn compute_zip244_sighash(meta: &TxMeta, actions: &[ActionData]) -> [u8; 32] {
    // 1. Header digest
    let mut hdr_data = Vec::new();
    hdr_data.extend_from_slice(&meta.version.to_le_bytes());
    hdr_data.extend_from_slice(&meta.version_group_id.to_le_bytes());
    hdr_data.extend_from_slice(&meta.consensus_branch_id.to_le_bytes());
    hdr_data.extend_from_slice(&meta.lock_time.to_le_bytes());
    hdr_data.extend_from_slice(&meta.expiry_height.to_le_bytes());
    let header_digest = blake2b_personal(b"ZTxIdHeadersHash", &hdr_data);

    // 2. Transparent + Sapling digests (from TxMeta, pre-computed)
    let transparent_digest = meta.transparent_sig_digest;
    let sapling_digest = meta.sapling_digest;

    // 3. Orchard digest — three parallel sub-hashes
    let mut compact = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"ZTxIdOrcActCHash")
        .to_state();
    let mut memos = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"ZTxIdOrcActMHash")
        .to_state();
    let mut noncompact = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"ZTxIdOrcActNHash")
        .to_state();

    for action in actions {
        // Compact: nullifier(32) || cmx(32) || epk(32) || enc[0..52]
        compact.update(&action.nullifier);
        compact.update(&action.cmx);
        compact.update(&action.ephemeral_key);
        compact.update(&action.enc_ciphertext[..52]);

        // Memos: enc[52..564]
        memos.update(&action.enc_ciphertext[52..564]);

        // Non-compact: cv_net(32) || rk(32) || enc[564..580] || out(80)
        noncompact.update(&action.cv_net);
        noncompact.update(&action.rk);
        noncompact.update(&action.enc_ciphertext[564..580]);
        noncompact.update(&action.out_ciphertext);
    }

    let compact_digest: [u8; 32] = compact.finalize().as_bytes().try_into().unwrap();
    let memos_digest: [u8; 32] = memos.finalize().as_bytes().try_into().unwrap();
    let noncompact_digest: [u8; 32] = noncompact.finalize().as_bytes().try_into().unwrap();

    // orchard_digest = BLAKE2b("ZTxIdOrchardHash",
    //     compact || memos || noncompact || flags[1] || value_balance[8] || anchor[32])
    let mut orchard_input = Vec::new();
    orchard_input.extend_from_slice(&compact_digest);
    orchard_input.extend_from_slice(&memos_digest);
    orchard_input.extend_from_slice(&noncompact_digest);
    orchard_input.push(meta.orchard_flags);
    orchard_input.extend_from_slice(&meta.value_balance.to_le_bytes());
    orchard_input.extend_from_slice(&meta.anchor);
    let orchard_digest = blake2b_personal(b"ZTxIdOrchardHash", &orchard_input);

    // 4. Root sighash = BLAKE2b("ZcashTxHash_" || branch_id[4 LE],
    //        header || transparent || sapling || orchard)
    let mut root_personal = [0u8; 16];
    root_personal[..12].copy_from_slice(b"ZcashTxHash_");
    root_personal[12..].copy_from_slice(&meta.consensus_branch_id.to_le_bytes());

    let mut root_input = Vec::new();
    root_input.extend_from_slice(&header_digest);
    root_input.extend_from_slice(&transparent_digest);
    root_input.extend_from_slice(&sapling_digest);
    root_input.extend_from_slice(&orchard_digest);

    blake2b_personal(&root_personal, &root_input)
}

// ── Group 1: Handshake ───────────────────────────────────────────────

#[test]
fn test_handshake() {
    let _signer = connect_signer();
    // If we get here, PING/PONG succeeded
}

// ── Group 2: FVK Export ──────────────────────────────────────────────

#[test]
fn test_fvk_export_mainnet() {
    let mut signer = connect_signer();
    let fvk = signer
        .export_fvk(COIN_TYPE_MAINNET)
        .expect("FVK export failed");

    assert_eq!(fvk.ak, EXPECTED_AK, "ak mismatch");
    assert_eq!(fvk.nk, EXPECTED_NK, "nk mismatch");
    assert_eq!(fvk.rivk, EXPECTED_RIVK, "rivk mismatch");

    // Verify it parses as a valid Orchard FVK
    assert!(
        fvk.to_orchard_fvk().is_some(),
        "FVK should parse as valid Orchard FullViewingKey"
    );
}

#[test]
fn test_fvk_export_testnet() {
    let mut signer = connect_signer();
    let fvk_testnet = signer
        .export_fvk(COIN_TYPE_TESTNET)
        .expect("FVK export failed");

    assert_ne!(
        fvk_testnet.ak, EXPECTED_AK,
        "testnet ak should differ from mainnet"
    );
}

#[test]
fn test_fvk_export_twice_same_result() {
    let mut signer = connect_signer();
    let fvk1 = signer
        .export_fvk(COIN_TYPE_MAINNET)
        .expect("FVK export 1 failed");
    let fvk2 = signer
        .export_fvk(COIN_TYPE_MAINNET)
        .expect("FVK export 2 failed");
    assert_eq!(fvk1.ak, fvk2.ak, "FVK should be deterministic");
}

// ── Group 3: ZIP-244 Sighash Verification ────────────────────────────

#[test]
fn test_sighash_valid() {
    let mut codec = connect_codec();

    // Request FVK first (sets coin_type on device)
    codec.request_fvk(COIN_TYPE_MAINNET).expect("FVK failed");

    let meta = build_test_tx_meta(COIN_TYPE_MAINNET);
    let action = build_test_action_data();
    let sighash = compute_zip244_sighash(&meta, &[action.clone()]);

    // Send metadata (index=0xFFFF)
    let meta_bytes = meta.serialize();
    codec
        .send_tx_output(0xFFFF, 1, &meta_bytes)
        .expect("TxMeta send failed");

    // Send action (index=0)
    let action_bytes = action.serialize();
    codec
        .send_tx_output(0, 1, &action_bytes)
        .expect("Action send failed");

    // Send sentinel sighash (index=1=total)
    codec
        .send_tx_output(1, 1, &sighash)
        .expect("Sighash sentinel failed — Rust and C computed different sighash!");
}

#[test]
fn test_sighash_mismatch() {
    let mut codec = connect_codec();
    codec.request_fvk(COIN_TYPE_MAINNET).expect("FVK failed");

    let meta = build_test_tx_meta(COIN_TYPE_MAINNET);
    let action = build_test_action_data();

    let meta_bytes = meta.serialize();
    codec
        .send_tx_output(0xFFFF, 1, &meta_bytes)
        .expect("TxMeta send failed");

    let action_bytes = action.serialize();
    codec
        .send_tx_output(0, 1, &action_bytes)
        .expect("Action send failed");

    // Send WRONG sighash
    let bad_sighash = [0xFF; 32];
    let result = codec.send_tx_output(1, 1, &bad_sighash);
    assert!(result.is_err(), "Wrong sighash should be rejected");
}

#[test]
fn test_sighash_multi_action() {
    let mut codec = connect_codec();
    codec.request_fvk(COIN_TYPE_MAINNET).expect("FVK failed");

    let meta = build_test_tx_meta(COIN_TYPE_MAINNET);

    // Create 3 distinct actions
    let actions: Vec<ActionData> = (0..3)
        .map(|i| {
            let fill = (i + 1) as u8;
            ActionData {
                cv_net: [fill; 32],
                nullifier: [fill + 0x10; 32],
                rk: [fill + 0x20; 32],
                cmx: [fill + 0x30; 32],
                ephemeral_key: [fill + 0x40; 32],
                enc_ciphertext: vec![fill + 0x50; 580],
                out_ciphertext: vec![fill + 0x60; 80],
            }
        })
        .collect();

    let sighash = compute_zip244_sighash(&meta, &actions);

    let meta_bytes = meta.serialize();
    codec
        .send_tx_output(0xFFFF, 3, &meta_bytes)
        .expect("TxMeta failed");

    for (i, action) in actions.iter().enumerate() {
        codec
            .send_tx_output(i as u16, 3, &action.serialize())
            .expect(&format!("Action {} failed", i));
    }

    codec
        .send_tx_output(3, 3, &sighash)
        .expect("Multi-action sighash verification failed");
}

// ── Group 4: Full Signing Flow ───────────────────────────────────────

#[test]
fn test_full_sign_flow() {
    let mut codec = connect_codec();

    // 1. Export FVK
    let fvk = codec.request_fvk(COIN_TYPE_MAINNET).expect("FVK failed");
    assert_eq!(fvk.ak, EXPECTED_AK);

    // 2. Sighash verification
    let meta = build_test_tx_meta(COIN_TYPE_MAINNET);
    let action = build_test_action_data();
    let sighash = compute_zip244_sighash(&meta, &[action.clone()]);

    let meta_bytes = meta.serialize();
    codec
        .send_tx_output(0xFFFF, 1, &meta_bytes)
        .expect("TxMeta failed");
    codec
        .send_tx_output(0, 1, &action.serialize())
        .expect("Action failed");
    codec
        .send_tx_output(1, 1, &sighash)
        .expect("Sighash verification failed");

    // 3. Sign
    let sign_req = SignRequest {
        sighash,
        alpha: [0x42; 32], // arbitrary alpha
        amount: 50000,
        fee: 10000,
        recipient: "u1test".to_string(),
        action_index: 0,
        total_actions: 1,
    };
    let response = codec.sign(&sign_req).expect("Signing failed");

    // 4. Verify signature is 64 bytes and rk is 32 bytes (non-zero)
    assert_ne!(response.signature, [0u8; 64], "Signature should be non-zero");
    assert_ne!(response.rk, [0u8; 32], "rk should be non-zero");

    // 5. Verify rk is a valid verification key
    let rk_result =
        reddsa::VerificationKey::<reddsa::orchard::SpendAuth>::try_from(response.rk);
    assert!(rk_result.is_ok(), "rk should be a valid SpendAuth key");

    // 6. Verify the signature cryptographically
    let rk_vk = rk_result.unwrap();
    let sig = reddsa::Signature::<reddsa::orchard::SpendAuth>::from(response.signature);
    assert!(
        rk_vk.verify(&sighash, &sig).is_ok(),
        "Signature should verify against sighash and rk"
    );
}

// ── Group 5: Network Discrimination ──────────────────────────────────

#[test]
fn test_network_mismatch() {
    let mut codec = connect_codec();

    // FvkReq with mainnet
    codec.request_fvk(COIN_TYPE_MAINNET).expect("FVK failed");

    // TxMeta with testnet coin_type — should trigger mismatch
    let meta = build_test_tx_meta(COIN_TYPE_TESTNET); // coin_type=1 vs session=133
    let meta_bytes = meta.serialize();

    let result = codec.send_tx_output(0xFFFF, 1, &meta_bytes);
    assert!(
        result.is_err(),
        "Network mismatch should be rejected by device"
    );
}

// ── Group 6: Error Handling ──────────────────────────────────────────

#[test]
fn test_sign_without_verification_rejected() {
    let mut codec = connect_codec();

    let sign_req = SignRequest {
        sighash: [0u8; 32],
        alpha: [0u8; 32],
        amount: 0,
        fee: 0,
        recipient: String::new(),
        action_index: 0,
        total_actions: 1,
    };

    let result = codec.sign(&sign_req);
    assert!(result.is_err(), "Sign without verification should fail");
}

#[test]
fn test_crc_error_recovery() {
    let transport =
        TcpTransport::connect(&device_addr()).expect("Failed to connect to virtual device");
    let mut codec = HwpCodec::new(transport);
    codec.handshake().expect("Handshake failed");

    // Send a frame with corrupted CRC by writing raw bytes
    let mut corrupt_frame = encode_frame(0x10, MsgType::Ping, &[]);
    // Flip CRC bytes
    let len = corrupt_frame.len();
    corrupt_frame[len - 1] ^= 0xFF;
    corrupt_frame[len - 2] ^= 0xFF;
    codec
        .transport_mut()
        .send(&corrupt_frame)
        .expect("Raw send failed");

    // Read error response
    let frame = codec.read_frame().expect("Should get error frame back");
    assert_eq!(frame.msg_type, MsgType::Error, "Expected error response");

    // Now send a valid FvkReq — device should have recovered
    let fvk = codec.request_fvk(COIN_TYPE_MAINNET);
    assert!(fvk.is_ok(), "Device should recover after CRC error");
}

#[test]
fn test_abort_resets_session() {
    let mut codec = connect_codec();
    codec.request_fvk(COIN_TYPE_MAINNET).expect("FVK failed");

    // Start sighash verification
    let meta = build_test_tx_meta(COIN_TYPE_MAINNET);
    let meta_bytes = meta.serialize();
    codec
        .send_tx_output(0xFFFF, 1, &meta_bytes)
        .expect("TxMeta failed");

    // Abort the session
    let seq = 0x50;
    codec
        .write_frame(seq, MsgType::Abort, &[])
        .expect("Abort send failed");

    // Start a fresh sighash verification — should work from clean state
    let action = build_test_action_data();
    let sighash = compute_zip244_sighash(&meta, &[action.clone()]);

    codec
        .send_tx_output(0xFFFF, 1, &meta_bytes)
        .expect("TxMeta after abort should work");
    codec
        .send_tx_output(0, 1, &action.serialize())
        .expect("Action after abort should work");
    codec
        .send_tx_output(1, 1, &sighash)
        .expect("Sighash after abort should work");
}

#[test]
fn test_invalid_state_action_without_metadata() {
    let mut codec = connect_codec();
    codec.request_fvk(COIN_TYPE_MAINNET).expect("FVK failed");

    // Send action data without prior metadata — should fail
    let action = build_test_action_data();
    let result = codec.send_tx_output(0, 1, &action.serialize());
    assert!(
        result.is_err(),
        "Action without metadata should be rejected"
    );
}

// ── Group 7: Connection Lifecycle ────────────────────────────────────

#[test]
fn test_reconnect_clean_session() {
    {
        let mut signer = connect_signer();
        let _ = signer
            .export_fvk(COIN_TYPE_MAINNET)
            .expect("FVK 1 failed");
    }
    {
        let mut signer = connect_signer();
        let fvk = signer
            .export_fvk(COIN_TYPE_MAINNET)
            .expect("FVK 2 failed");
        assert_eq!(fvk.ak, EXPECTED_AK, "FVK should match after reconnect");
    }
}
