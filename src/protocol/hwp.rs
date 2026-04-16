/// Hardware Wallet Protocol (HWP) v2 — Binary framed serial protocol.
///
/// Frame: `[MAGIC:1][VERSION:1][SEQ:1][TYPE:1][LENGTH:2 LE][PAYLOAD:N][CRC16:2 LE]`
///
/// Designed for constrained hardware signing devices. Supports staged
/// transaction verification: outputs are sent individually and hashed
/// incrementally on-device to verify sighash integrity before signing.
use crate::error::{HwSignerError, Result};
use crate::transport::Transport;
use crate::types::{ExportedFvk, SignRequest, SignResponse};

pub const HWP_MAGIC: u8 = 0xFB;
pub const HWP_VERSION: u8 = 0x02;
pub const HWP_HEADER_SIZE: usize = 6;
pub const HWP_CRC_SIZE: usize = 2;
/// Maximum payload size per frame.
///
/// Set to 1024 to accommodate full action data for on-device sighash
/// verification (ZIP-244 action data is 820 bytes + 4 byte TxOutput header).
pub const HWP_MAX_PAYLOAD: usize = 1024;
pub const HWP_MAX_RECIPIENT: usize = 127;
/// Maximum number of keepalive (PING) messages tolerated before aborting.
/// Prevents infinite loops if a device keeps sending PINGs without progressing.
pub const HWP_MAX_KEEPALIVE: usize = 1000;

// ── Message types ────────────────────────────────────────────────────────

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    /// Keepalive / flow control
    Ping = 0x01,
    Pong = 0x02,
    /// Full viewing key export (one-time pairing)
    FvkReq = 0x03,
    FvkRsp = 0x04,
    /// Sign a single Orchard action
    SignReq = 0x05,
    SignRsp = 0x06,
    /// Device-side error
    Error = 0x07,
    /// Send an individual transaction output for incremental hashing (v2).
    /// Enables on-device sighash verification (inspired by zcash-ledger).
    TxOutput = 0x08,
    /// Device confirms computed sighash matches (v2)
    TxOutputAck = 0x09,
    /// Abort the signing session
    Abort = 0x0A,
    /// Send a transparent input for on-device transparent digest computation (v3)
    TxTransparentInput = 0x0B,
    /// Send a transparent output for on-device transparent digest computation (v3)
    TxTransparentOutput = 0x0C,
}

impl MsgType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Ping),
            0x02 => Some(Self::Pong),
            0x03 => Some(Self::FvkReq),
            0x04 => Some(Self::FvkRsp),
            0x05 => Some(Self::SignReq),
            0x06 => Some(Self::SignRsp),
            0x07 => Some(Self::Error),
            0x08 => Some(Self::TxOutput),
            0x09 => Some(Self::TxOutputAck),
            0x0A => Some(Self::Abort),
            0x0B => Some(Self::TxTransparentInput),
            0x0C => Some(Self::TxTransparentOutput),
            _ => None,
        }
    }
}

// ── Error codes ──────────────────────────────────────────────────────────

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    Unknown = 0x00,
    BadFrame = 0x01,
    BadSighash = 0x02,
    BadAlpha = 0x03,
    BadAmount = 0x04,
    NetworkMismatch = 0x05,
    UserCancelled = 0x06,
    SignFailed = 0x07,
    UnsupportedVersion = 0x08,
    /// Device-computed sighash does not match companion's sighash (v2)
    SighashMismatch = 0x09,
    /// Unexpected message in current protocol state (v2)
    InvalidState = 0x0A,
    /// Device-computed transparent digest does not match companion's (v3)
    TransparentDigestMismatch = 0x0B,
}

impl ErrorCode {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x01 => Self::BadFrame,
            0x02 => Self::BadSighash,
            0x03 => Self::BadAlpha,
            0x04 => Self::BadAmount,
            0x05 => Self::NetworkMismatch,
            0x06 => Self::UserCancelled,
            0x07 => Self::SignFailed,
            0x08 => Self::UnsupportedVersion,
            0x09 => Self::SighashMismatch,
            0x0A => Self::InvalidState,
            0x0B => Self::TransparentDigestMismatch,
            _ => Self::Unknown,
        }
    }
}

// ── Frame ────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Frame {
    pub seq: u8,
    pub msg_type: MsgType,
    pub payload: Vec<u8>,
}

// ── Codec ────────────────────────────────────────────────────────────────

/// HWP protocol codec: encodes/decodes frames over a [`Transport`].
///
/// Handles CRC validation, frame synchronization, and paced writes.
/// Wraps any transport implementation (serial, TCP, etc.).
///
/// # Example
///
/// ```rust,ignore
/// use zcash_hw_wallet::protocol::HwpCodec;
/// use zcash_hw_wallet::transport::SerialTransport;
///
/// let transport = SerialTransport::new("/dev/ttyACM0", 115200)?;
/// let mut codec = HwpCodec::new(transport);
///
/// // Wait for device ping
/// let frame = codec.read_frame()?;
/// assert_eq!(frame.msg_type, MsgType::Ping);
///
/// // Reply with pong
/// codec.send_pong(frame.seq)?;
/// ```
pub struct HwpCodec<T: Transport> {
    transport: T,
    seq: u8,
}

impl<T: Transport> HwpCodec<T> {
    /// Create a new codec wrapping the given transport.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            seq: 0,
        }
    }

    /// Get a reference to the underlying transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Get a mutable reference to the underlying transport.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Consume the codec and return the underlying transport.
    pub fn into_transport(self) -> T {
        self.transport
    }

    // ── High-level operations ────────────────────────────────────────

    /// Perform the initial handshake: wait for PING, reply with PONG.
    pub fn handshake(&mut self) -> Result<()> {
        let frame = self.read_frame()?;
        if frame.msg_type != MsgType::Ping {
            return Err(HwSignerError::ProtocolError(format!(
                "Expected PING, got {:?}",
                frame.msg_type
            )));
        }
        self.write_frame(frame.seq, MsgType::Pong, &[])?;
        Ok(())
    }

    /// Request the full viewing key from the device.
    ///
    /// Limits keepalive iterations to [`HWP_MAX_KEEPALIVE`] to prevent infinite loops.
    pub fn request_fvk(&mut self, coin_type: u32) -> Result<ExportedFvk> {
        let seq = self.next_seq();
        self.write_frame(seq, MsgType::FvkReq, &coin_type.to_le_bytes())?;

        let mut keepalive_count = 0usize;
        loop {
            let frame = self.read_frame()?;
            match frame.msg_type {
                MsgType::Ping => {
                    keepalive_count += 1;
                    if keepalive_count > HWP_MAX_KEEPALIVE {
                        return Err(HwSignerError::MaxKeepaliveExceeded {
                            max: HWP_MAX_KEEPALIVE,
                        });
                    }
                    self.write_frame(frame.seq, MsgType::Pong, &[])?;
                    continue;
                }
                MsgType::FvkRsp => return parse_fvk_rsp(&frame.payload),
                MsgType::Error => {
                    let (code, msg) = parse_error(&frame.payload);
                    return Err(device_error(code, &msg));
                }
                other => {
                    return Err(HwSignerError::ProtocolError(format!(
                        "Expected FVK_RSP, got {:?}",
                        other
                    )));
                }
            }
        }
    }

    /// Send a signing request and wait for the response.
    ///
    /// Handles PING keepalives and CRC error retries automatically.
    /// Limits keepalive iterations to [`HWP_MAX_KEEPALIVE`] to prevent infinite loops.
    pub fn sign(&mut self, request: &SignRequest) -> Result<SignResponse> {
        let payload = encode_sign_req(request)?;
        let seq = self.next_seq();
        self.write_frame(seq, MsgType::SignReq, &payload)?;

        const MAX_CRC_RETRIES: usize = 3;
        let mut crc_retries = 0;
        let mut keepalive_count = 0usize;

        loop {
            let frame = self.read_frame_retry(3)?;
            match frame.msg_type {
                MsgType::Ping => {
                    keepalive_count += 1;
                    if keepalive_count > HWP_MAX_KEEPALIVE {
                        return Err(HwSignerError::MaxKeepaliveExceeded {
                            max: HWP_MAX_KEEPALIVE,
                        });
                    }
                    self.write_frame(frame.seq, MsgType::Pong, &[])?;
                    continue;
                }
                MsgType::SignRsp => return parse_sign_rsp(&frame.payload),
                MsgType::Error => {
                    let (code, msg) = parse_error(&frame.payload);
                    if code == ErrorCode::BadFrame && crc_retries < MAX_CRC_RETRIES {
                        crc_retries += 1;
                        tracing::warn!(
                            "Device reported CRC error, resending ({}/{})",
                            crc_retries,
                            MAX_CRC_RETRIES
                        );
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        let retry_seq = self.next_seq();
                        self.write_frame(retry_seq, MsgType::SignReq, &payload)?;
                        continue;
                    }
                    return Err(device_error(code, &msg));
                }
                other => {
                    return Err(HwSignerError::ProtocolError(format!(
                        "Expected SIGN_RSP, got {:?}",
                        other
                    )));
                }
            }
        }
    }

    /// Send a pong reply (convenience method).
    pub fn send_pong(&mut self, seq: u8) -> Result<()> {
        self.write_frame(seq, MsgType::Pong, &[])
    }

    /// Send an abort message to cancel the signing session.
    pub fn abort(&mut self) -> Result<()> {
        let seq = self.next_seq();
        self.write_frame(seq, MsgType::Abort, &[])
    }

    /// Send a transaction output for on-device incremental hashing (v2).
    ///
    /// This implements the staged verification approach inspired by
    /// zcash-ledger: each output is sent individually so the device can
    /// hash it with ZIP-244 personalizations and build a local sighash
    /// to compare against the companion's before signing.
    ///
    /// # Payload format
    /// `[output_index:2 LE][total_outputs:2 LE][output_data:N]`
    pub fn send_tx_output(
        &mut self,
        output_index: u16,
        total_outputs: u16,
        output_data: &[u8],
    ) -> Result<()> {
        let mut payload = Vec::with_capacity(4 + output_data.len());
        payload.extend_from_slice(&output_index.to_le_bytes());
        payload.extend_from_slice(&total_outputs.to_le_bytes());
        payload.extend_from_slice(output_data);
        let seq = self.next_seq();
        self.write_frame(seq, MsgType::TxOutput, &payload)?;

        // Wait for ACK or error
        let mut keepalive_count = 0usize;
        loop {
            let frame = self.read_frame()?;
            match frame.msg_type {
                MsgType::Ping => {
                    keepalive_count += 1;
                    if keepalive_count > HWP_MAX_KEEPALIVE {
                        return Err(HwSignerError::MaxKeepaliveExceeded {
                            max: HWP_MAX_KEEPALIVE,
                        });
                    }
                    self.write_frame(frame.seq, MsgType::Pong, &[])?;
                    continue;
                }
                MsgType::TxOutputAck => return Ok(()),
                MsgType::Error => {
                    let (code, msg) = parse_error(&frame.payload);
                    return Err(device_error(code, &msg));
                }
                other => {
                    return Err(HwSignerError::ProtocolError(format!(
                        "Expected TX_OUTPUT_ACK, got {:?}",
                        other
                    )));
                }
            }
        }
    }

    /// Send a transparent input for on-device digest computation (v3).
    ///
    /// Same framing as `send_tx_output` but uses `TxTransparentInput` message type.
    ///
    /// # Payload format
    /// `[input_index:2 LE][total_inputs:2 LE][input_data:N]`
    ///
    /// The sentinel message (index == total) carries the 32-byte expected digest.
    pub fn send_transparent_input(
        &mut self,
        input_index: u16,
        total_inputs: u16,
        input_data: &[u8],
    ) -> Result<()> {
        let mut payload = Vec::with_capacity(4 + input_data.len());
        payload.extend_from_slice(&input_index.to_le_bytes());
        payload.extend_from_slice(&total_inputs.to_le_bytes());
        payload.extend_from_slice(input_data);
        let seq = self.next_seq();
        self.write_frame(seq, MsgType::TxTransparentInput, &payload)?;

        // Wait for ACK or error
        let mut keepalive_count = 0usize;
        loop {
            let frame = self.read_frame()?;
            match frame.msg_type {
                MsgType::Ping => {
                    keepalive_count += 1;
                    if keepalive_count > HWP_MAX_KEEPALIVE {
                        return Err(HwSignerError::MaxKeepaliveExceeded {
                            max: HWP_MAX_KEEPALIVE,
                        });
                    }
                    self.write_frame(frame.seq, MsgType::Pong, &[])?;
                    continue;
                }
                MsgType::TxOutputAck => return Ok(()),
                MsgType::Error => {
                    let (code, msg) = parse_error(&frame.payload);
                    return Err(device_error(code, &msg));
                }
                other => {
                    return Err(HwSignerError::ProtocolError(format!(
                        "Expected TX_OUTPUT_ACK, got {:?}",
                        other
                    )));
                }
            }
        }
    }

    /// Send a transparent output for on-device digest computation (v3).
    ///
    /// # Payload format
    /// `[output_index:2 LE][total_outputs:2 LE][output_data:N]`
    pub fn send_transparent_output(
        &mut self,
        output_index: u16,
        total_outputs: u16,
        output_data: &[u8],
    ) -> Result<()> {
        let mut payload = Vec::with_capacity(4 + output_data.len());
        payload.extend_from_slice(&output_index.to_le_bytes());
        payload.extend_from_slice(&total_outputs.to_le_bytes());
        payload.extend_from_slice(output_data);
        let seq = self.next_seq();
        self.write_frame(seq, MsgType::TxTransparentOutput, &payload)?;

        // Wait for ACK or error
        let mut keepalive_count = 0usize;
        loop {
            let frame = self.read_frame()?;
            match frame.msg_type {
                MsgType::Ping => {
                    keepalive_count += 1;
                    if keepalive_count > HWP_MAX_KEEPALIVE {
                        return Err(HwSignerError::MaxKeepaliveExceeded {
                            max: HWP_MAX_KEEPALIVE,
                        });
                    }
                    self.write_frame(frame.seq, MsgType::Pong, &[])?;
                    continue;
                }
                MsgType::TxOutputAck => return Ok(()),
                MsgType::Error => {
                    let (code, msg) = parse_error(&frame.payload);
                    return Err(device_error(code, &msg));
                }
                other => {
                    return Err(HwSignerError::ProtocolError(format!(
                        "Expected TX_OUTPUT_ACK, got {:?}",
                        other
                    )));
                }
            }
        }
    }

    // ── Low-level frame I/O ──────────────────────────────────────────

    fn next_seq(&mut self) -> u8 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    /// Encode and send a single frame.
    pub fn write_frame(&mut self, seq: u8, msg_type: MsgType, payload: &[u8]) -> Result<()> {
        let frame_bytes = encode_frame(seq, msg_type, payload);
        self.transport.send(&frame_bytes)
    }

    /// Read a single frame from the transport, scanning for magic byte.
    pub fn read_frame(&mut self) -> Result<Frame> {
        // Scan for magic byte (handles stream misalignment)
        let mut byte = [0u8; 1];
        let mut skipped = 0usize;
        loop {
            self.transport.recv_exact(&mut byte)?;
            if byte[0] == HWP_MAGIC {
                break;
            }
            skipped += 1;
            if skipped > HWP_MAX_PAYLOAD + HWP_HEADER_SIZE + HWP_CRC_SIZE {
                return Err(HwSignerError::ProtocolError(format!(
                    "No magic byte found after {} bytes",
                    skipped
                )));
            }
        }

        // Read rest of header
        let mut hdr = [0u8; HWP_HEADER_SIZE];
        hdr[0] = HWP_MAGIC;
        self.transport.recv_exact(&mut hdr[1..])?;

        let version = hdr[1];
        // Accept v1 and v2 frames for backward compatibility
        if version != 0x01 && version != HWP_VERSION {
            return Err(HwSignerError::UnsupportedVersion(version));
        }

        let seq = hdr[2];
        let msg_type = MsgType::from_u8(hdr[3])
            .ok_or(HwSignerError::UnknownMessageType(hdr[3]))?;
        let payload_len = (hdr[4] as u16) | ((hdr[5] as u16) << 8);

        if payload_len as usize > HWP_MAX_PAYLOAD {
            return Err(HwSignerError::PayloadTooLarge {
                size: payload_len as usize,
                max: HWP_MAX_PAYLOAD,
            });
        }

        // Read payload
        let mut payload = vec![0u8; payload_len as usize];
        if payload_len > 0 {
            self.transport.recv_exact(&mut payload)?;
        }

        // Read and verify CRC
        let mut crc_buf = [0u8; 2];
        self.transport.recv_exact(&mut crc_buf)?;
        let received_crc = (crc_buf[0] as u16) | ((crc_buf[1] as u16) << 8);

        let mut check_buf = Vec::with_capacity(HWP_HEADER_SIZE + payload.len());
        check_buf.extend_from_slice(&hdr);
        check_buf.extend_from_slice(&payload);
        let computed_crc = crc16_ccitt(&check_buf);

        if computed_crc != received_crc {
            return Err(HwSignerError::CrcMismatch {
                computed: computed_crc,
                received: received_crc,
            });
        }

        Ok(Frame {
            seq,
            msg_type,
            payload,
        })
    }

    /// Read a frame with automatic retry on CRC/alignment errors.
    pub fn read_frame_retry(&mut self, max_retries: usize) -> Result<Frame> {
        for attempt in 0..=max_retries {
            match self.read_frame() {
                Ok(frame) => return Ok(frame),
                Err(e) if attempt < max_retries => match &e {
                    HwSignerError::CrcMismatch { .. }
                    | HwSignerError::UnknownMessageType(_)
                    | HwSignerError::PayloadTooLarge { .. } => continue,
                    _ => return Err(e),
                },
                Err(e) => return Err(e),
            }
        }
        unreachable!()
    }
}

// ── Standalone encode/decode functions ───────────────────────────────────

/// Encode a complete HWP frame.
pub fn encode_frame(seq: u8, msg_type: MsgType, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u16;
    let mut buf = Vec::with_capacity(HWP_HEADER_SIZE + payload.len() + HWP_CRC_SIZE);
    buf.push(HWP_MAGIC);
    buf.push(HWP_VERSION);
    buf.push(seq);
    buf.push(msg_type as u8);
    buf.push((len & 0xFF) as u8);
    buf.push(((len >> 8) & 0xFF) as u8);
    buf.extend_from_slice(payload);
    let crc = crc16_ccitt(&buf);
    buf.push((crc & 0xFF) as u8);
    buf.push(((crc >> 8) & 0xFF) as u8);
    buf
}

/// Encode a SIGN_REQ payload from a [`SignRequest`].
///
/// Returns an error if the recipient address exceeds [`HWP_MAX_RECIPIENT`] bytes.
pub fn encode_sign_req(req: &SignRequest) -> Result<Vec<u8>> {
    let rlen = req.recipient.len();
    if rlen > HWP_MAX_RECIPIENT {
        return Err(HwSignerError::RecipientTooLong {
            len: rlen,
            max: HWP_MAX_RECIPIENT,
        });
    }
    let rlen_u8 = rlen as u8;
    let mut payload = Vec::with_capacity(81 + rlen);
    payload.extend_from_slice(&req.sighash);
    payload.extend_from_slice(&req.alpha);
    payload.extend_from_slice(&req.amount.to_le_bytes());
    payload.extend_from_slice(&req.fee.to_le_bytes());
    payload.push(rlen_u8);
    payload.extend_from_slice(req.recipient.as_bytes());
    Ok(payload)
}

/// Parse a SIGN_RSP payload into a [`SignResponse`].
pub fn parse_sign_rsp(payload: &[u8]) -> Result<SignResponse> {
    if payload.len() < 96 {
        return Err(HwSignerError::ProtocolError(format!(
            "SIGN_RSP too short: {} bytes (need 96)",
            payload.len()
        )));
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&payload[..64]);
    let mut rk = [0u8; 32];
    rk.copy_from_slice(&payload[64..96]);
    Ok(SignResponse { signature, rk })
}

/// Parse a FVK_RSP payload into an [`ExportedFvk`].
pub fn parse_fvk_rsp(payload: &[u8]) -> Result<ExportedFvk> {
    if payload.len() < 96 {
        return Err(HwSignerError::ProtocolError(format!(
            "FVK_RSP too short: {} bytes (need 96)",
            payload.len()
        )));
    }
    let mut ak = [0u8; 32];
    ak.copy_from_slice(&payload[..32]);
    let mut nk = [0u8; 32];
    nk.copy_from_slice(&payload[32..64]);
    let mut rivk = [0u8; 32];
    rivk.copy_from_slice(&payload[64..96]);
    Ok(ExportedFvk { ak, nk, rivk })
}

/// Parse an ERROR payload.
pub fn parse_error(payload: &[u8]) -> (ErrorCode, String) {
    if payload.is_empty() {
        return (ErrorCode::Unknown, String::new());
    }
    let code = ErrorCode::from_u8(payload[0]);
    let msg = if payload.len() > 1 {
        String::from_utf8_lossy(&payload[1..]).to_string()
    } else {
        String::new()
    };
    (code, msg)
}

/// Convert a device error code into a typed SDK error.
fn device_error(code: ErrorCode, msg: &str) -> HwSignerError {
    match code {
        ErrorCode::UserCancelled => HwSignerError::UserCancelled,
        ErrorCode::SighashMismatch => HwSignerError::SignatureVerificationFailed {
            action_idx: 0,
            reason: "Device-computed sighash does not match companion sighash".into(),
        },
        ErrorCode::TransparentDigestMismatch => HwSignerError::TransparentSighashMismatch,
        _ => HwSignerError::DeviceError(format!("{:?}: {}", code, msg)),
    }
}

// ── CRC-16/CCITT ─────────────────────────────────────────────────────────

/// CRC-16/CCITT (poly 0x1021, init 0xFFFF).
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc = (crc << 8) ^ CRC16_TABLE[((crc >> 8) as u8 ^ byte) as usize];
    }
    crc
}

#[rustfmt::skip]
static CRC16_TABLE: [u16; 256] = [
    0x0000,0x1021,0x2042,0x3063,0x4084,0x50A5,0x60C6,0x70E7,
    0x8108,0x9129,0xA14A,0xB16B,0xC18C,0xD1AD,0xE1CE,0xF1EF,
    0x1231,0x0210,0x3273,0x2252,0x52B5,0x4294,0x72F7,0x62D6,
    0x9339,0x8318,0xB37B,0xA35A,0xD3BD,0xC39C,0xF3FF,0xE3DE,
    0x2462,0x3443,0x0420,0x1401,0x64E6,0x74C7,0x44A4,0x54A5,
    0xA54A,0xB56B,0x8508,0x9529,0xE5CE,0xF5EF,0xC58C,0xD5AD,
    0x3653,0x2672,0x1611,0x0630,0x76D7,0x66F6,0x5695,0x46B4,
    0xB75B,0xA77A,0x9719,0x8738,0xF7DF,0xE7FE,0xD79D,0xC7BC,
    0x4864,0x5845,0x6826,0x7807,0x08E0,0x18C1,0x28A2,0x38A3,
    0xC94C,0xD96D,0xE90E,0xF92F,0x89C8,0x99E9,0xA98A,0xB9AB,
    0x5A55,0x4A74,0x7A17,0x6A36,0x1AD1,0x0AF0,0x3A93,0x2AB2,
    0xDB5D,0xCB7C,0xFB1F,0xEB3E,0x9BD9,0x8BF8,0xAB9B,0xABBA,
    0x6CA6,0x7C87,0x4CE4,0x5CC5,0x2C22,0x3C03,0x0C60,0x1C41,
    0xEDAE,0xFD8F,0xCDEC,0xDDCD,0xAD2A,0xBD0B,0x8D68,0x9D49,
    0x7E97,0x6EB6,0x5ED5,0x4EF4,0x3E13,0x2E32,0x1E51,0x0E70,
    0xFF9F,0xEFBE,0xDFDD,0xCFFC,0xBF1B,0xAF3A,0x9F59,0x8F78,
    0x9188,0x81A9,0xB1CA,0xA1EB,0xD10C,0xC12D,0xF14E,0xE16F,
    0x1080,0x00A1,0x30C2,0x20E3,0x5004,0x4025,0x7046,0x6067,
    0x83B9,0x9398,0xA3FB,0xB3DA,0xC33D,0xD31C,0xE37F,0xF35E,
    0x02B1,0x1290,0x22F3,0x32D2,0x4235,0x5214,0x6277,0x7256,
    0xB5EA,0xA5CB,0x95A8,0x85A9,0xF54E,0xE56F,0xD50C,0xC52D,
    0x34C2,0x24E3,0x1480,0x04A1,0x7466,0x6447,0x5424,0x4405,
    0xA7DB,0xB7FA,0x8799,0x97B8,0xE75F,0xF77E,0xC71D,0xD73C,
    0x26D3,0x36F2,0x0691,0x16B0,0x6657,0x7676,0x4615,0x5634,
    0xD94C,0xC96D,0xF90E,0xE92F,0x99C8,0x89E9,0xB98A,0xA9AB,
    0x5844,0x4865,0x7806,0x6827,0x18C0,0x08E1,0x3882,0x28A3,
    0xCB7D,0xDB5C,0xEB3F,0xFB1E,0x8BD9,0x9BF8,0xAB9B,0xBBBA,
    0x4A55,0x5A74,0x6A17,0x7A36,0x0AD1,0x1AF0,0x2A93,0x3AB2,
    0xFD2E,0xED0F,0xDD6C,0xCD4D,0xBDAA,0xAD8B,0x9DE8,0x8DC9,
    0x7C26,0x6C07,0x5C64,0x4C45,0x3CA2,0x2C83,0x1CE0,0x0CC1,
    0xEF1F,0xFF3E,0xCF5D,0xDF7C,0xAF9B,0xBFBA,0x8FD9,0x9FF8,
    0x6E17,0x7E36,0x4E55,0x5E74,0x2E93,0x3EB2,0x0ED1,0x1EF0,
];
