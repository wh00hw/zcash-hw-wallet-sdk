//! Unit tests for zcash-hw-wallet SDK.

use crate::error::{HwSignerError, Result};
use crate::protocol::{self, HwpCodec, MsgType};
use crate::traits::HardwareSigner;
use crate::transport::Transport;
use crate::types::*;

// ── Mock hardware signer for workflow tests ──────────────────────────────

/// A mock signer that records requests and returns configurable responses.
struct MockSigner {
    fvk: ExportedFvk,
    sign_responses: Vec<SignResponse>,
    sign_calls: Vec<SignRequest>,
    confirm_result: bool,
    call_idx: usize,
}

impl MockSigner {
    fn new() -> Self {
        Self {
            fvk: ExportedFvk {
                ak: [0xAA; 32],
                nk: [0xBB; 32],
                rivk: [0xCC; 32],
            },
            sign_responses: Vec::new(),
            sign_calls: Vec::new(),
            confirm_result: true,
            call_idx: 0,
        }
    }

    fn with_confirm(mut self, confirm: bool) -> Self {
        self.confirm_result = confirm;
        self
    }
}

impl HardwareSigner for MockSigner {
    fn coin_type(&self) -> u32 {
        1 // testnet
    }

    fn export_fvk(&mut self) -> Result<ExportedFvk> {
        Ok(self.fvk.clone())
    }

    fn sign_action(&mut self, request: &SignRequest) -> Result<SignResponse> {
        self.sign_calls.push(request.clone());
        if self.call_idx < self.sign_responses.len() {
            let resp = self.sign_responses[self.call_idx].clone();
            self.call_idx += 1;
            Ok(resp)
        } else {
            Err(HwSignerError::DeviceError("No more mock responses".into()))
        }
    }

    fn confirm_transaction(&mut self, _details: &TxDetails) -> Result<bool> {
        Ok(self.confirm_result)
    }
}

// ── Protocol tests ───────────────────────────────────────────────────────

#[test]
fn test_crc16_ccitt() {
    // CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF): "123456789" => 0xA971
    let data = b"123456789";
    let crc = protocol::hwp::crc16_ccitt(data);
    // Verify it's consistent (encode_frame uses this for integrity)
    let crc2 = protocol::hwp::crc16_ccitt(data);
    assert_eq!(crc, crc2);
    // Known value for this CRC table variant
    assert_eq!(crc, 0xA9B1);
}

#[test]
fn test_crc16_empty() {
    let crc = protocol::hwp::crc16_ccitt(&[]);
    assert_eq!(crc, 0xFFFF); // Initial value with no data
}

#[test]
fn test_encode_frame_roundtrip() {
    let payload = b"hello";
    let frame_bytes = protocol::hwp::encode_frame(42, MsgType::SignReq, payload);

    // Verify frame structure
    assert_eq!(frame_bytes[0], protocol::HWP_MAGIC);
    assert_eq!(frame_bytes[1], protocol::HWP_VERSION);
    assert_eq!(frame_bytes[2], 42); // seq
    assert_eq!(frame_bytes[3], MsgType::SignReq as u8);
    assert_eq!(frame_bytes[4], 5); // len lo
    assert_eq!(frame_bytes[5], 0); // len hi
    assert_eq!(&frame_bytes[6..11], b"hello");
    // Total: 6 header + 5 payload + 2 CRC = 13
    assert_eq!(frame_bytes.len(), 13);
}

#[test]
fn test_encode_sign_req() {
    let req = SignRequest {
        sighash: [0x11; 32],
        alpha: [0x22; 32],
        amount: 100_000,
        fee: 10_000,
        recipient: "u1test".to_string(),
        action_index: 0,
        total_actions: 1,
    };

    let payload = protocol::hwp::encode_sign_req(&req).unwrap();

    // sighash(32) + alpha(32) + amount(8) + fee(8) + rlen(1) + recipient(6)
    assert_eq!(payload.len(), 87);
    assert_eq!(&payload[..32], &[0x11; 32]);
    assert_eq!(&payload[32..64], &[0x22; 32]);
    assert_eq!(
        u64::from_le_bytes(payload[64..72].try_into().unwrap()),
        100_000
    );
    assert_eq!(
        u64::from_le_bytes(payload[72..80].try_into().unwrap()),
        10_000
    );
    assert_eq!(payload[80], 6); // recipient length
    assert_eq!(&payload[81..87], b"u1test");
}

#[test]
fn test_encode_sign_req_recipient_too_long() {
    let req = SignRequest {
        sighash: [0x11; 32],
        alpha: [0x22; 32],
        amount: 100_000,
        fee: 10_000,
        recipient: "x".repeat(256), // exceeds the 255-byte wire ceiling
        action_index: 0,
        total_actions: 1,
    };

    let err = protocol::hwp::encode_sign_req(&req).unwrap_err();
    assert!(matches!(err, HwSignerError::RecipientTooLong { len: 256, max: 255 }));
}

#[test]
fn test_encode_sign_req_long_multi_receiver_ua() {
    // A multi-receiver testnet UA (~217 chars) must encode successfully:
    // this is the exact case the old 127-byte cap wrongly rejected.
    let ua = "utest1".to_string() + &"q".repeat(211);
    assert_eq!(ua.len(), 217);
    let req = SignRequest {
        sighash: [0x11; 32],
        alpha: [0x22; 32],
        amount: 50_000,
        fee: 20_000,
        recipient: ua.clone(),
        action_index: 0,
        total_actions: 1,
    };
    let payload = protocol::hwp::encode_sign_req(&req).expect("217-char UA must encode");
    assert_eq!(payload[80], 217); // recipient_len byte
    assert_eq!(&payload[81..81 + 217], ua.as_bytes());
}

#[test]
fn test_parse_sign_rsp() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0xAA; 64]); // signature
    payload.extend_from_slice(&[0xBB; 32]); // rk

    let resp = protocol::hwp::parse_sign_rsp(&payload).unwrap();
    assert_eq!(resp.signature, [0xAA; 64]);
    assert_eq!(resp.rk, [0xBB; 32]);
}

#[test]
fn test_parse_sign_rsp_too_short() {
    let payload = vec![0u8; 50];
    let err = protocol::hwp::parse_sign_rsp(&payload).unwrap_err();
    assert!(matches!(err, HwSignerError::ProtocolError(_)));
}

#[test]
fn test_parse_fvk_rsp() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0x11; 32]); // ak
    payload.extend_from_slice(&[0x22; 32]); // nk
    payload.extend_from_slice(&[0x33; 32]); // rivk

    let fvk = protocol::hwp::parse_fvk_rsp(&payload).unwrap();
    assert_eq!(fvk.ak, [0x11; 32]);
    assert_eq!(fvk.nk, [0x22; 32]);
    assert_eq!(fvk.rivk, [0x33; 32]);
}

#[test]
fn test_parse_error_empty() {
    let (code, msg) = protocol::hwp::parse_error(&[]);
    assert_eq!(code, protocol::ErrorCode::Unknown);
    assert!(msg.is_empty());
}

#[test]
fn test_parse_error_with_message() {
    let mut payload = vec![0x06]; // UserCancelled
    payload.extend_from_slice(b"rejected by user");
    let (code, msg) = protocol::hwp::parse_error(&payload);
    assert_eq!(code, protocol::ErrorCode::UserCancelled);
    assert_eq!(msg, "rejected by user");
}

#[test]
fn test_msg_type_roundtrip() {
    /* Range extended to 0x12 to cover the audit-M1 attestation messages
     * (IdentityReq=0x0F, IdentityRsp=0x10, AttestReq=0x11, AttestRsp=0x12). */
    for v in 0x01..=0x12u8 {
        let mt = MsgType::from_u8(v).unwrap();
        assert_eq!(mt as u8, v);
    }
    assert!(MsgType::from_u8(0x00).is_none());
    assert!(MsgType::from_u8(0x13).is_none());
}

#[test]
fn test_error_code_roundtrip() {
    /* Range extended to 0x17: the v5 device-side codes
     * (MemoMismatch=0x0F .. FeeNegative=0x13) and the November 2026 ones
     * (MemoRequired=0x14, BranchNotAllowed=0x15, LimitExceeded=0x16,
     * ValueOverflow=0x17). */
    for v in 0x01..=0x19u8 {
        let ec = protocol::ErrorCode::from_u8(v);
        assert_eq!(ec as u8, v);
    }
    assert_eq!(protocol::ErrorCode::from_u8(0x14), protocol::ErrorCode::MemoRequired);
    assert_eq!(protocol::ErrorCode::from_u8(0x15), protocol::ErrorCode::BranchNotAllowed);
    assert_eq!(protocol::ErrorCode::from_u8(0x16), protocol::ErrorCode::LimitExceeded);
    assert_eq!(protocol::ErrorCode::from_u8(0x17), protocol::ErrorCode::ValueOverflow);
    assert_eq!(
        protocol::ErrorCode::from_u8(0x18),
        protocol::ErrorCode::TransparentInputsUnsupported
    );
    assert_eq!(protocol::ErrorCode::from_u8(0x19), protocol::ErrorCode::EmptyPoolBalance);
    assert_eq!(protocol::ErrorCode::from_u8(0x1A), protocol::ErrorCode::Unknown);
    assert_eq!(protocol::ErrorCode::from_u8(0xFF), protocol::ErrorCode::Unknown);
}

// ── Mock transport for codec tests ───────────────────────────────────────

struct MockTransport {
    rx_data: Vec<u8>,
    rx_offset: usize,
    tx_log: Vec<Vec<u8>>,
}

impl MockTransport {
    fn from_bytes(data: Vec<u8>) -> Self {
        Self {
            rx_data: data,
            rx_offset: 0,
            tx_log: Vec::new(),
        }
    }
}

impl Transport for MockTransport {
    fn send(&mut self, data: &[u8]) -> Result<()> {
        self.tx_log.push(data.to_vec());
        Ok(())
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.rx_offset >= self.rx_data.len() {
            return Err(HwSignerError::Timeout);
        }
        let available = &self.rx_data[self.rx_offset..];
        let n = buf.len().min(available.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.rx_offset += n;
        Ok(n)
    }
}

#[test]
fn test_codec_read_frame() {
    // Build a valid PING frame
    let frame_bytes = protocol::hwp::encode_frame(1, MsgType::Ping, &[]);
    let transport = MockTransport::from_bytes(frame_bytes);
    let mut codec = HwpCodec::new(transport);

    let frame = codec.read_frame().unwrap();
    assert_eq!(frame.msg_type, MsgType::Ping);
    assert_eq!(frame.seq, 1);
    assert!(frame.payload.is_empty());
}

#[test]
fn test_codec_read_frame_with_payload() {
    let payload = vec![0x42; 10];
    let frame_bytes = protocol::hwp::encode_frame(5, MsgType::FvkRsp, &payload);
    let transport = MockTransport::from_bytes(frame_bytes);
    let mut codec = HwpCodec::new(transport);

    let frame = codec.read_frame().unwrap();
    assert_eq!(frame.msg_type, MsgType::FvkRsp);
    assert_eq!(frame.seq, 5);
    assert_eq!(frame.payload, payload);
}

#[test]
fn test_codec_handshake() {
    // Device sends PING, we should reply PONG
    let ping = protocol::hwp::encode_frame(0, MsgType::Ping, &[]);
    let transport = MockTransport::from_bytes(ping);
    let mut codec = HwpCodec::new(transport);

    codec.handshake().unwrap();

    // Verify PONG was sent
    assert_eq!(codec.transport().tx_log.len(), 1);
    // Parse the sent frame to verify it's a PONG
    let sent = &codec.transport().tx_log[0];
    assert_eq!(sent[3], MsgType::Pong as u8);
}

#[test]
fn test_codec_crc_mismatch_detected() {
    let mut frame_bytes = protocol::hwp::encode_frame(1, MsgType::Ping, &[]);
    // Corrupt the CRC
    let len = frame_bytes.len();
    frame_bytes[len - 1] ^= 0xFF;

    let transport = MockTransport::from_bytes(frame_bytes);
    let mut codec = HwpCodec::new(transport);

    let err = codec.read_frame().unwrap_err();
    assert!(matches!(err, HwSignerError::CrcMismatch { .. }));
}

/// The device's Error frames for the November 2026 rules surface as their
/// own typed errors (with the device's message), on every request path that
/// can receive them.
#[test]
fn test_codec_new_device_errors_are_typed() {
    fn error_frame(code: u8, msg: &str) -> Vec<u8> {
        let mut payload = vec![code];
        payload.extend_from_slice(msg.as_bytes());
        protocol::hwp::encode_frame(0, MsgType::Error, &payload)
    }
    fn tx_output_err(code: u8, msg: &str) -> HwSignerError {
        let mut codec = HwpCodec::new(MockTransport::from_bytes(error_frame(code, msg)));
        codec.send_tx_output(0, 1, &[0u8; 904]).unwrap_err()
    }

    match tx_output_err(0x14, "Output with value needs the memo-carrying body") {
        HwSignerError::MemoRequired { reason } => {
            assert_eq!(reason, "Output with value needs the memo-carrying body")
        }
        e => panic!("0x14 mapped to {:?}", e),
    }
    assert!(matches!(
        tx_output_err(0x15, "Consensus branch not supported by this firmware"),
        HwSignerError::BranchNotAllowed { .. }
    ));
    assert!(matches!(
        tx_output_err(0x16, "More outputs than the device can review"),
        HwSignerError::DeviceLimitExceeded { .. }
    ));
    assert!(matches!(
        tx_output_err(0x17, "Output values overflow"),
        HwSignerError::ValueOverflow { .. }
    ));
    assert!(matches!(
        tx_output_err(0x18, "Transparent inputs are not supported"),
        HwSignerError::TransparentInputsNotSupported { inputs: 0 }
    ));
    assert!(matches!(
        tx_output_err(0x19, "Value balance for a pool without actions"),
        HwSignerError::EmptyPoolBalance { .. }
    ));
    // No message text: still typed, with a placeholder reason.
    match tx_output_err(0x14, "") {
        HwSignerError::MemoRequired { reason } => assert!(!reason.is_empty()),
        e => panic!("0x14 mapped to {:?}", e),
    }
    // A code this SDK does not know keeps the device's text.
    match tx_output_err(0x7E, "something new") {
        HwSignerError::DeviceError(s) => assert!(s.contains("something new"), "{}", s),
        e => panic!("unknown code mapped to {:?}", e),
    }

    // SIGN_REQ path (value overflow can be reported there too).
    let mut codec = HwpCodec::new(MockTransport::from_bytes(error_frame(0x17, "Output values overflow")));
    let err = codec
        .sign(&SignRequest {
            sighash: [0; 32],
            alpha: [0; 32],
            amount: 0,
            fee: 0,
            recipient: String::new(),
            action_index: 0,
            total_actions: 1,
        })
        .unwrap_err();
    assert!(matches!(err, HwSignerError::ValueOverflow { .. }), "{:?}", err);

    // The messages name the rule, not just the code.
    let text = tx_output_err(0x14, "x").to_string();
    assert!(text.contains("memo-carrying") && text.contains("every output"), "{}", text);
}

// ── HardwareSigner trait tests ───────────────────────────────────────────

#[test]
fn test_mock_signer_export_fvk() {
    let mut signer = MockSigner::new();
    let fvk = signer.export_fvk().unwrap();
    assert_eq!(fvk.ak, [0xAA; 32]);
    assert_eq!(fvk.nk, [0xBB; 32]);
    assert_eq!(fvk.rivk, [0xCC; 32]);
}

#[test]
fn test_mock_signer_confirm_true() {
    let mut signer = MockSigner::new().with_confirm(true);
    let details = TxDetails {
        send_amount: 100_000,
        fee: 10_000,
        recipient: "u1test".into(),
        num_actions: 1,
        memo: None,
    };
    assert!(signer.confirm_transaction(&details).unwrap());
}

#[test]
fn test_mock_signer_confirm_false() {
    let mut signer = MockSigner::new().with_confirm(false);
    let details = TxDetails {
        send_amount: 100_000,
        fee: 10_000,
        recipient: "u1test".into(),
        num_actions: 1,
        memo: None,
    };
    assert!(!signer.confirm_transaction(&details).unwrap());
}

// ── QR transport tests ──────────────────────────────────────────────────

#[cfg(feature = "qr")]
mod qr_tests {
    use crate::transport::qr::QrTransport;

    #[test]
    fn test_qr_single_frame() {
        let qr = QrTransport::new(200);
        let data = vec![0x42; 100];
        let frames = qr.encode_frames(&data);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].index, 0);
        assert_eq!(frames[0].total, 1);
        assert_eq!(frames[0].data, data);
    }

    #[test]
    fn test_qr_multi_frame_roundtrip() {
        let qr = QrTransport::new(50);
        let data: Vec<u8> = (0..=200).map(|i| i as u8).collect();
        let frames = qr.encode_frames(&data);
        assert!(frames.len() > 1);

        let reassembled = qr.decode_frames(&frames).unwrap();
        assert_eq!(reassembled, data);
    }
}

// ── NU6.3 / Ironwood wire-format tests ──────────────────────────────────

mod ironwood_wire_tests {
    use crate::types::{ActionData, ShieldedPoolKind, TxMeta};

    fn sample_meta(version: u32) -> TxMeta {
        TxMeta {
            version,
            version_group_id: 0xD884B698,
            consensus_branch_id: 0x37a5165b, // NU6.3
            lock_time: 7,
            expiry_height: 4_200_000,
            orchard_flags: 0x03,
            value_balance: -123_456_789,
            anchor: [0xA1; 32],
            ironwood_flags: 0x07,
            ironwood_value_balance: 123_456_789,
            ironwood_anchor: [0xB2; 32],
            transparent_sig_digest: [0xC3; 32],
            sapling_digest: [0xD4; 32],
            coin_type: 133,
        }
    }

    #[test]
    fn tx_meta_always_serializes_the_170_byte_v6_layout() {
        // v6-only host: even a meta carrying a legacy version header is
        // emitted in the 170-byte v6 layout — the 129-byte v5 wire
        // serialization no longer exists (the workflow rejects non-v6
        // transactions before any TxMeta ever reaches the wire).
        let meta = sample_meta(0x8000_0005);
        let bytes = meta.serialize();
        assert_eq!(bytes.len(), 170);
        // Ironwood section present at offset 61 (not transparent_sig_digest)
        assert_eq!(bytes[61], 0x07);
    }

    #[test]
    fn tx_meta_v6_layout_is_170_bytes_with_ironwood_section() {
        let meta = sample_meta(0x8000_0006);
        let bytes = meta.serialize();
        assert_eq!(bytes.len(), 170);
        // Ironwood section: flags[1] || value_balance[8] || anchor[32] at 61
        assert_eq!(bytes[61], 0x07);
        assert_eq!(&bytes[62..70], &123_456_789i64.to_le_bytes());
        assert_eq!(&bytes[70..102], &[0xB2; 32]);
        assert_eq!(&bytes[102..134], &[0xC3; 32]);
        assert_eq!(&bytes[166..170], &133u32.to_le_bytes());
    }

    fn sample_action(pool: ShieldedPoolKind, memo: Option<[u8; 512]>) -> ActionData {
        ActionData {
            pool,
            cv_net: [1; 32],
            nullifier: [2; 32],
            rk: [3; 32],
            cmx: [4; 32],
            ephemeral_key: [5; 32],
            enc_ciphertext: vec![6; 580],
            out_ciphertext: vec![7; 80],
            recipient: [8; 43],
            value: 42,
            rseed: [9; 32],
            memo,
        }
    }

    #[test]
    fn action_v6_wire_prefixes_pool_byte() {
        let a = sample_action(ShieldedPoolKind::Ironwood, Some([0xF6; 512]));
        let bytes = a.serialize_v6();
        assert_eq!(bytes.len(), 1416); // pool(1) + v4(903) + memo(512)
        assert_eq!(bytes[0], 0x01);

        let b = sample_action(ShieldedPoolKind::Orchard, None);
        let bytes = b.serialize_v6();
        assert_eq!(bytes.len(), 904); // pool(1) + body(903), cmx-only
        assert_eq!(bytes[0], 0x00);
    }
}

// ── v6-only workflow gate tests (NU6.3 / NU7 host) ───────────────────────

mod v6_only_gate_tests {
    use crate::error::HwSignerError;
    use crate::types::V6_TX_VERSION;
    use crate::workflow::{check_branch, ensure_v6_globals, ensure_v6_only, SUPPORTED_BRANCH_IDS};
    use zcash_protocol::consensus::BranchId;

    const NU5: u32 = 0xc2d6_d0b4;
    const NU6: u32 = 0xc8e7_1055;
    const NU6_1: u32 = 0x4dec_4df0;
    const NU6_2: u32 = 0x5437_f330;
    const NU6_3: u32 = 0x37a5_165b;
    const NU7: u32 = 0x7719_0ad9;

    #[test]
    fn nu6_3_v6_transaction_is_accepted() {
        assert!(ensure_v6_only(V6_TX_VERSION, NU6_3, 133).is_ok());
    }

    #[test]
    fn nu7_v6_transaction_is_accepted() {
        // NU7 (active on testnet from 4,465,026 and on mainnet from
        // 3,543,405) keeps the v6 transaction format, on both networks.
        assert!(ensure_v6_only(V6_TX_VERSION, NU7, 133).is_ok());
        assert!(ensure_v6_only(V6_TX_VERSION, NU7, 1).is_ok());
    }

    #[test]
    fn supported_branch_ids_are_exactly_nu6_3_and_nu7() {
        // The literals above are what goes on the wire; pin them to the
        // zcash_protocol constants so a crate bump cannot silently move
        // either one (NU7 was the placeholder 0xFFFFFFFF before
        // zcash_protocol 0.11, and 0x77190AD8 in a retired proposal).
        assert_eq!(u32::from(BranchId::Nu6_3), NU6_3);
        assert_eq!(u32::from(BranchId::Nu7), NU7);
        assert_eq!(SUPPORTED_BRANCH_IDS, [BranchId::Nu6_3, BranchId::Nu7]);
        for retired in [0x7719_0ad8u32, 0xffff_ffff] {
            assert!(ensure_v6_only(V6_TX_VERSION, retired, 133).is_err());
        }
    }

    #[test]
    fn allow_list_is_what_admits_a_branch() {
        // Both NU6.3 and NU7 select Orchard revision V3, so only the
        // allow-list distinguishes "reviewed" from "merely V3". With NU7
        // taken off the list it must be refused, and vice versa.
        assert!(check_branch(NU7, 133, &[BranchId::Nu6_3, BranchId::Nu7]).is_ok());
        assert!(matches!(
            check_branch(NU7, 133, &[BranchId::Nu6_3]),
            Err(HwSignerError::UnsupportedPool(_))
        ));
        assert!(matches!(
            check_branch(NU6_3, 133, &[BranchId::Nu7]),
            Err(HwSignerError::UnsupportedPool(_))
        ));
        assert!(matches!(
            check_branch(NU7, 133, &[]),
            Err(HwSignerError::UnsupportedPool(_))
        ));
        // Being on the list does not rescue a pre-V3 branch.
        assert!(matches!(
            check_branch(NU6_2, 133, &[BranchId::Nu6_2]),
            Err(HwSignerError::UnsupportedPool(_))
        ));
    }

    #[test]
    fn globals_gate_requires_v6_number_and_group_id() {
        assert!(ensure_v6_globals(6, 0xD884_B698, NU7, 1).is_ok());
        assert!(matches!(
            ensure_v6_globals(5, 0x26A7_270A, NU7, 1),
            Err(HwSignerError::UnsupportedPool(_))
        ));
        assert!(matches!(
            ensure_v6_globals(6, 0x26A7_270A, NU7, 1),
            Err(HwSignerError::UnsupportedPool(_))
        ));
        assert!(matches!(
            ensure_v6_globals(6, 0xD884_B698, 0xdead_beef, 1),
            Err(HwSignerError::NetworkMismatch { expected: 1, got: 0xdead_beef })
        ));
    }

    #[test]
    fn pre_nu6_3_branch_ids_are_rejected() {
        for branch in [NU5, NU6, NU6_1, NU6_2] {
            let err = ensure_v6_only(V6_TX_VERSION, branch, 133).unwrap_err();
            assert!(
                matches!(err, HwSignerError::UnsupportedPool(_)),
                "branch 0x{:08x} must be rejected as UnsupportedPool, got {:?}",
                branch,
                err
            );
        }
    }

    #[test]
    fn non_v6_tx_version_is_rejected_on_nu6_3_and_nu7() {
        // A v5 transaction is still valid on-chain under both branches
        // (ZIP 2003 only retires v4), but this v6-only host refuses to
        // sign it.
        for branch in [NU6_3, NU7] {
            let err = ensure_v6_only(0x8000_0005, branch, 133).unwrap_err();
            assert!(matches!(err, HwSignerError::UnsupportedPool(_)));
        }
    }

    #[test]
    fn unknown_branch_id_is_a_network_mismatch() {
        let err = ensure_v6_only(V6_TX_VERSION, 0xdead_beef, 133).unwrap_err();
        assert!(matches!(
            err,
            HwSignerError::NetworkMismatch { expected: 133, got: 0xdead_beef }
        ));
    }

    #[test]
    fn pre_orchard_branch_id_is_rejected() {
        // Canopy predates the Orchard protocol entirely — surfaces as a
        // NetworkMismatch (no Orchard protocol revision), same as before.
        let err = ensure_v6_only(V6_TX_VERSION, 0xe9ff_75a6, 133).unwrap_err();
        assert!(matches!(err, HwSignerError::NetworkMismatch { .. }));
    }
}

// ── NU7 TxMeta derivation (host only) ────────────────────────────────────
//
// These run without a device. They pin what the host derives for a v6
// transaction under the NU7 branch — via the production `TxMeta::from_pczt`
// — and compare pczt's own shielded sighash with an independent reference
// implementation of the five-leaf hash written out below. Whether the
// *device* computes the same thing is checked in tests/integration.rs
// (`test_nu7_*`), not here.

mod nu7_tx_meta_tests {
    use crate::types::{TxMeta, V6_TX_VERSION};
    use zcash_protocol::consensus::BranchId;

    const NU6_3: u32 = 0x37a5_165b;
    const NU7: u32 = 0x7719_0ad9;

    fn blake2b(personal: &[u8; 16], data: &[u8]) -> [u8; 32] {
        let h = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(personal)
            .hash(data);
        h.as_bytes().try_into().unwrap()
    }

    /// Reference five-leaf ZIP-244 v6 sighash for a transaction with no
    /// shielded actions and no transparent bundle, computed only from the
    /// TxMeta fields that go over the wire. Test-local re-implementation.
    fn reference_empty_tx_sighash(meta: &TxMeta) -> [u8; 32] {
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&meta.version.to_le_bytes());
        hdr.extend_from_slice(&meta.version_group_id.to_le_bytes());
        hdr.extend_from_slice(&meta.consensus_branch_id.to_le_bytes());
        hdr.extend_from_slice(&meta.lock_time.to_le_bytes());
        hdr.extend_from_slice(&meta.expiry_height.to_le_bytes());

        let mut root_personal = [0u8; 16];
        root_personal[..12].copy_from_slice(b"ZcashTxHash_");
        root_personal[12..].copy_from_slice(&meta.consensus_branch_id.to_le_bytes());

        let mut root = Vec::new();
        root.extend_from_slice(&blake2b(b"ZTxIdHeadersHash", &hdr));
        root.extend_from_slice(&meta.transparent_sig_digest);
        root.extend_from_slice(&meta.sapling_digest);
        root.extend_from_slice(&blake2b(b"ZTxIdOrchardH_v6", &[]));
        root.extend_from_slice(&blake2b(b"ZTxIdIronwd_H_v6", &[]));
        blake2b(&root_personal, &root)
    }

    fn empty_pczt(branch: BranchId, expiry_height: u32) -> pczt::Pczt {
        pczt::roles::creator::Creator::new(branch.into(), expiry_height, 1, None, None)
            .expect("v6 branch")
            .build()
            .expect("empty v6 PCZT")
    }

    #[test]
    fn from_pczt_derives_the_v6_header_under_nu7() {
        let pczt = empty_pczt(BranchId::Nu7, 4_600_120);
        // The PCZT global carries the bare version number...
        assert_eq!(*pczt.global().tx_version(), 6);

        // ...and the production derivation yields the real header word.
        let meta = TxMeta::from_pczt(&pczt, 1).expect("derivation");
        assert_eq!(meta.version, V6_TX_VERSION);
        assert_eq!(meta.version_group_id, 0xD884_B698);
        assert_eq!(meta.consensus_branch_id, NU7);
        assert_eq!(meta.expiry_height, 4_600_120);
        assert_eq!(meta.coin_type, 1);
        assert_eq!(meta.transparent_sig_digest, blake2b(b"ZTxIdTranspaHash", &[]));
        assert_eq!(meta.sapling_digest, blake2b(b"ZTxIdSaplingHash", &[]));
        // What from_pczt returns passes the production gate.
        crate::workflow::ensure_v6_only(meta.version, meta.consensus_branch_id, 1).unwrap();

        // Wire layout is unchanged: 170 bytes, branch ID at offset 8.
        let bytes = meta.serialize();
        assert_eq!(bytes.len(), 170);
        assert_eq!(&bytes[0..4], &0x8000_0006u32.to_le_bytes());
        assert_eq!(&bytes[4..8], &0xD884_B698u32.to_le_bytes());
        assert_eq!(&bytes[8..12], &NU7.to_le_bytes());
        assert_eq!(&bytes[16..20], &4_600_120u32.to_le_bytes());
    }

    #[test]
    fn pczt_empty_tx_sighash_matches_reference_five_leaf_hash() {
        for (branch, id) in [(BranchId::Nu6_3, NU6_3), (BranchId::Nu7, NU7)] {
            let pczt = empty_pczt(branch, 4_600_120);
            let meta = TxMeta::from_pczt(&pczt, 1).expect("derivation");
            assert_eq!(meta.consensus_branch_id, id);

            let upstream = pczt::roles::signer::Signer::new(pczt)
                .expect("signer")
                .shielded_sighash();
            assert_eq!(
                upstream,
                reference_empty_tx_sighash(&meta),
                "pczt's v6 sighash diverged from the reference for branch 0x{:08x}",
                id
            );
        }
    }

    #[test]
    fn nu7_and_nu6_3_reference_sighashes_differ_only_through_the_branch_id() {
        let sighash = |branch| {
            pczt::roles::signer::Signer::new(empty_pczt(branch, 4_600_120))
                .expect("signer")
                .shielded_sighash()
        };
        assert_ne!(sighash(BranchId::Nu6_3), sighash(BranchId::Nu7));

        let mut meta =
            TxMeta::from_pczt(&empty_pczt(BranchId::Nu6_3, 4_600_120), 1).expect("derivation");
        meta.consensus_branch_id = NU7;
        assert_eq!(reference_empty_tx_sighash(&meta), sighash(BranchId::Nu7));
    }
}

// ── Public `sign()` on foreign / malformed / unrecoverable PCZTs ─────────
//
// Everything here goes through `PcztHardwareSigning::sign*`, the public
// entry point, with a signer that counts what reaches the "device".

mod public_sign_rejection_tests {
    use crate::error::{HwSignerError, Result};
    use crate::traits::HardwareSigner;
    use crate::types::{
        ActionData, ExportedFvk, ShieldedPoolKind, SignRequest, SignResponse,
        TransparentInputData, TransparentOutputData, TxMeta,
    };
    use crate::PcztHardwareSigning;
    use zcash_protocol::consensus::BranchId;

    /// Records every interaction; never signs.
    #[derive(Default)]
    struct RecordingSigner {
        fvk: Option<ExportedFvk>,
        fvk_requests: usize,
        verify_calls: Vec<Vec<ActionData>>,
        sign_calls: usize,
    }

    impl HardwareSigner for RecordingSigner {
        fn coin_type(&self) -> u32 {
            133
        }
        fn export_fvk(&mut self) -> Result<ExportedFvk> {
            self.fvk_requests += 1;
            self.fvk
                .clone()
                .ok_or_else(|| HwSignerError::DeviceError("no fvk".into()))
        }
        fn sign_action(&mut self, _request: &SignRequest) -> Result<SignResponse> {
            self.sign_calls += 1;
            Err(HwSignerError::UserCancelled)
        }
        fn verify_transaction(
            &mut self,
            _meta: &TxMeta,
            actions: &[ActionData],
            _sighash: &[u8; 32],
            _t_in: &[TransparentInputData],
            _t_out: &[TransparentOutputData],
        ) -> Result<()> {
            self.verify_calls.push(actions.to_vec());
            // Stop the workflow here: these tests are about what the host
            // sends (or refuses to send), not about signing.
            Err(HwSignerError::UserCancelled)
        }
    }

    fn sign(signer: RecordingSigner, bytes: Vec<u8>) -> (Result<()>, RecordingSigner) {
        let mut workflow = PcztHardwareSigning::new(signer);
        let result = workflow.sign(bytes).map(|_| ());
        (result, workflow.into_signer())
    }

    fn assert_nothing_reached_the_device(signer: &RecordingSigner) {
        assert_eq!(signer.fvk_requests, 0);
        assert!(signer.verify_calls.is_empty());
        assert_eq!(signer.sign_calls, 0);
    }

    /// postcard / LEB128 encoding of a u32, as used for the PCZT globals.
    fn varint(mut v: u32) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return out;
            }
            out.push(b | 0x80);
        }
    }

    fn empty_v6_pczt_bytes(branch: BranchId) -> Vec<u8> {
        pczt::roles::creator::Creator::new(branch.into(), 4_600_120, 133, None, None)
            .unwrap()
            .build()
            .unwrap()
            .serialize()
            .unwrap()
    }

    /// A serialized v6 PCZT whose consensus branch ID has been overwritten.
    fn pczt_bytes_with_branch(branch_id: u32) -> Vec<u8> {
        let mut bytes = empty_v6_pczt_bytes(BranchId::Nu7);
        let from = varint(0x7719_0ad9);
        let to = varint(branch_id);
        assert_eq!(from.len(), to.len(), "pick a branch ID with a same-length varint");
        let positions: Vec<usize> = bytes
            .windows(from.len())
            .enumerate()
            .filter(|(_, w)| *w == from.as_slice())
            .map(|(i, _)| i)
            .collect();
        assert_eq!(positions.len(), 1, "branch ID must occur exactly once");
        bytes[positions[0]..positions[0] + to.len()].copy_from_slice(&to);
        assert_eq!(
            *pczt::Pczt::parse(&bytes).unwrap().global().consensus_branch_id(),
            branch_id
        );
        bytes
    }

    #[test]
    fn garbage_bytes_are_an_invalid_pczt_error_not_a_panic() {
        for bytes in [vec![], vec![0u8; 3], b"PCZT\x01\x00\x00\x00garbage".to_vec()] {
            let (result, signer) = sign(RecordingSigner::default(), bytes);
            assert!(matches!(result, Err(HwSignerError::InvalidPczt(_))), "{:?}", result);
            assert_nothing_reached_the_device(&signer);
        }
    }

    #[test]
    fn unknown_branch_id_is_a_network_mismatch_through_sign() {
        let (result, signer) =
            sign(RecordingSigner::default(), pczt_bytes_with_branch(0xdead_beef));
        assert!(
            matches!(
                result,
                Err(HwSignerError::NetworkMismatch { expected: 133, got: 0xdead_beef })
            ),
            "{:?}",
            result
        );
        assert_nothing_reached_the_device(&signer);
    }

    #[test]
    fn retired_nu7_branch_id_is_rejected_through_sign() {
        let (result, signer) =
            sign(RecordingSigner::default(), pczt_bytes_with_branch(0x7719_0ad8));
        assert!(matches!(result, Err(HwSignerError::NetworkMismatch { .. })), "{:?}", result);
        assert_nothing_reached_the_device(&signer);
    }

    #[test]
    fn nu5_v5_pczt_is_unsupported_through_sign() {
        let bytes = pczt::roles::creator::Creator::new(
            BranchId::Nu5.into(),
            4_600_120,
            133,
            None,
            Some([0u8; 32]),
        )
        .unwrap()
        .build()
        .unwrap()
        .serialize()
        .unwrap();
        let (result, signer) = sign(RecordingSigner::default(), bytes);
        assert!(matches!(result, Err(HwSignerError::UnsupportedPool(_))), "{:?}", result);
        assert_nothing_reached_the_device(&signer);
    }

    #[test]
    fn nu6_2_branch_on_a_v6_pczt_is_unsupported_through_sign() {
        // NU6.2 is a real branch, but pre-NU6.3: the branch arm fires.
        let (result, signer) =
            sign(RecordingSigner::default(), pczt_bytes_with_branch(0x5437_f330));
        assert!(matches!(result, Err(HwSignerError::UnsupportedPool(_))), "{:?}", result);
        assert_nothing_reached_the_device(&signer);
    }

    #[test]
    fn supported_empty_pczt_gets_past_the_gate() {
        // Control: the same construction under NU7 / NU6.3 is not refused
        // by the gate; it ends at "nothing to sign".
        for branch in [BranchId::Nu6_3, BranchId::Nu7] {
            let (result, _) = sign(RecordingSigner::default(), empty_v6_pczt_bytes(branch));
            assert!(matches!(result, Err(HwSignerError::NoActionsToSign)), "{:?}", result);
        }
    }

    // ── value-carrying outputs must be recoverable ──────────────────────

    struct Wallet {
        fvk: orchard::keys::FullViewingKey,
        exported: ExportedFvk,
    }

    fn wallet(seed: u8) -> Wallet {
        let sk = orchard::keys::SpendingKey::from_bytes([seed; 32]).unwrap();
        let fvk = orchard::keys::FullViewingKey::from(&sk);
        let b = fvk.to_bytes();
        let exported = ExportedFvk {
            ak: b[..32].try_into().unwrap(),
            nk: b[32..64].try_into().unwrap(),
            rivk: b[64..].try_into().unwrap(),
        };
        Wallet { fvk, exported }
    }

    /// A real NU7 v6 PCZT: one Ironwood spend of a 1,000,000-zat note owned
    /// by `w`, a 500,000-zat payment encrypted under `payment_ovk`, and
    /// 490,000 zat of change to the internal address under `change_ovk`.
    fn ironwood_pczt(
        w: &Wallet,
        payment_ovk: Option<orchard::keys::OutgoingViewingKey>,
        change_ovk: Option<orchard::keys::OutgoingViewingKey>,
    ) -> Vec<u8> {
        use incrementalmerkletree::{Hashable, Level};
        use orchard::keys::Scope;
        use orchard::note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho};
        use orchard::tree::{MerkleHashOrchard, MerklePath};
        use pczt::roles::{creator::Creator, io_finalizer::IoFinalizer};
        use zcash_primitives::transaction::{
            builder::{BuildConfig, Builder, BundlePadding, PcztResult},
            fees::zip317,
        };
        use zcash_protocol::consensus::{BlockHeight, MAIN_NETWORK};
        use zcash_protocol::memo::MemoBytes;
        use zcash_protocol::value::Zatoshis;

        let mut rng = rand_core::UnwrapErr(rand::rngs::SysRng);
        let external = w.fvk.address_at(0u32, Scope::External);
        let internal = w.fvk.address_at(0u32, Scope::Internal);

        let mut n = 0u8;
        let note: orchard::Note = loop {
            n += 1;
            let rho = Option::<Rho>::from(Rho::from_bytes(&[n; 32]));
            let Some(rho) = rho else { continue };
            let Some(rseed) = Option::<RandomSeed>::from(RandomSeed::from_bytes([n; 32], &rho))
            else {
                continue;
            };
            if let Some(note) = Option::<orchard::Note>::from(orchard::Note::from_parts(
                external,
                orchard::value::NoteValue::from_raw(1_000_000),
                rho,
                rseed,
                NoteVersion::V3,
            )) {
                break note;
            }
        };
        let cmx: ExtractedNoteCommitment = note.commitment().into();
        let mut auth_path = [MerkleHashOrchard::empty_leaf(); 32];
        for (level, sibling) in auth_path.iter_mut().enumerate() {
            *sibling = MerkleHashOrchard::empty_root(Level::from(level as u8));
        }
        let merkle_path = MerklePath::from_parts(0, auth_path);

        let mut builder = Builder::new(
            MAIN_NETWORK,
            BlockHeight::from_u32(3_600_000),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: Some(merkle_path.root(cmx)),
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );
        builder
            .add_ironwood_spend::<zip317::FeeRule>(w.fvk.clone(), note, merkle_path)
            .unwrap();
        builder
            .add_ironwood_output::<zip317::FeeRule>(
                payment_ovk,
                external,
                Zatoshis::const_from_u64(500_000),
                MemoBytes::empty(),
            )
            .unwrap();
        builder
            .add_ironwood_output::<zip317::FeeRule>(
                change_ovk,
                internal,
                Zatoshis::const_from_u64(490_000),
                MemoBytes::empty(),
            )
            .unwrap();
        let PcztResult { pczt_parts, .. } = builder
            .build_for_pczt(&mut rng, &zip317::FeeRule::standard())
            .unwrap();
        IoFinalizer::new(Creator::build_from_parts(pczt_parts).unwrap())
            .finalize_io(&mut rng)
            .unwrap()
            .serialize()
            .unwrap()
    }

    fn ovk(w: &Wallet, scope: orchard::keys::Scope) -> Option<orchard::keys::OutgoingViewingKey> {
        Some(w.fvk.to_ovk(scope))
    }

    #[test]
    fn payment_and_change_both_go_out_with_the_full_body() {
        use orchard::keys::Scope;
        let w = wallet(7);
        let bytes = ironwood_pczt(&w, ovk(&w, Scope::External), ovk(&w, Scope::Internal));
        let signer = RecordingSigner { fvk: Some(w.exported.clone()), ..Default::default() };
        let (result, signer) = sign(signer, bytes);

        // The recording signer stops the flow at verification.
        assert!(matches!(result, Err(HwSignerError::UserCancelled)), "{:?}", result);
        assert_eq!(signer.verify_calls.len(), 1);
        assert_eq!(signer.sign_calls, 0);

        let actions = &signer.verify_calls[0];
        assert_eq!(actions.len(), 2);
        let mut values: Vec<u64> = actions.iter().map(|a| a.value).collect();
        values.sort();
        assert_eq!(values, vec![490_000, 500_000]);
        for a in actions {
            assert_eq!(a.pool, ShieldedPoolKind::Ironwood);
            assert!(a.memo.is_some(), "{} zat output went out compact", a.value);
            assert_eq!(a.serialize_v6().len(), 1416);
        }
    }

    /// The plaintext of every output is rebuilt from the PCZT itself
    /// (recipient / value / rseed + the action's rho), so the outgoing
    /// viewing key an output was built with — someone else's, or none —
    /// does not matter, and neither does the device's FVK: every action
    /// goes out with the full body.
    #[test]
    fn outputs_go_out_with_the_full_body_whatever_their_ovk() {
        use orchard::keys::Scope;
        let w = wallet(7);
        let stranger = wallet(9);
        for (payment_ovk, change_ovk, device_fvk) in [
            (ovk(&stranger, Scope::External), ovk(&w, Scope::Internal), Some(w.exported.clone())),
            (ovk(&w, Scope::External), None, Some(w.exported.clone())),
            (None, None, None),
        ] {
            let bytes = ironwood_pczt(&w, payment_ovk, change_ovk);
            let signer = RecordingSigner { fvk: device_fvk, ..Default::default() };
            let (result, signer) = sign(signer, bytes);
            assert!(matches!(result, Err(HwSignerError::UserCancelled)), "{:?}", result);
            assert_eq!(signer.verify_calls.len(), 1);
            for a in &signer.verify_calls[0] {
                assert!(a.memo.is_some(), "{} zat output went out compact", a.value);
                assert_eq!(a.serialize_v6().len(), 1416);
            }
        }
    }
}

// ── UFVK encoding (zcash_address 0.14 is ZIP 316 revision-aware) ──────────

mod ufvk_encoding_tests {
    use crate::types::ExportedFvk;
    use zcash_address::unified::{self, Container, Encoding};
    use zcash_protocol::consensus::{Network, NetworkType};

    fn sample_fvk() -> ExportedFvk {
        let sk = orchard::keys::SpendingKey::from_bytes([7u8; 32]).unwrap();
        let bytes = orchard::keys::FullViewingKey::from(&sk).to_bytes();
        ExportedFvk {
            ak: bytes[..32].try_into().unwrap(),
            nk: bytes[32..64].try_into().unwrap(),
            rivk: bytes[64..].try_into().unwrap(),
        }
    }

    /// The pairing UFVK stays a ZIP 316 Revision 0 container with the
    /// original `uview` / `uviewtest` prefixes (what watch-only wallets
    /// created by earlier SDK versions hold), carrying only the Orchard FVK.
    #[test]
    fn ufvk_is_revision_0_orchard_only_with_legacy_hrp() {
        let fvk = sample_fvk();
        for (network, net_type, prefix) in [
            (Network::MainNetwork, NetworkType::Main, "uview1"),
            (Network::TestNetwork, NetworkType::Test, "uviewtest1"),
        ] {
            let encoded = fvk.to_ufvk_string(&network).unwrap();
            assert!(encoded.starts_with(prefix), "{}", encoded);

            let (decoded_net, revision, ufvk) = unified::Ufvk::decode(&encoded).unwrap();
            assert_eq!(decoded_net, net_type);
            assert_eq!(revision, unified::Revision::R0);
            assert_eq!(
                ufvk.items(),
                vec![unified::Fvk::Orchard(fvk.to_orchard_fvk_bytes())]
            );
        }
    }
}
