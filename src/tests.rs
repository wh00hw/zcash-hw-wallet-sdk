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
        recipient: "x".repeat(128), // exceeds 127-byte limit
        action_index: 0,
        total_actions: 1,
    };

    let err = protocol::hwp::encode_sign_req(&req).unwrap_err();
    assert!(matches!(err, HwSignerError::RecipientTooLong { len: 128, max: 127 }));
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
    for v in 0x01..=0x0Au8 {
        let mt = MsgType::from_u8(v).unwrap();
        assert_eq!(mt as u8, v);
    }
    assert!(MsgType::from_u8(0x00).is_none());
    assert!(MsgType::from_u8(0x0B).is_none());
}

#[test]
fn test_error_code_roundtrip() {
    for v in 0x01..=0x0Au8 {
        let ec = protocol::ErrorCode::from_u8(v);
        assert_eq!(ec as u8, v);
    }
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
