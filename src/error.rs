use thiserror::Error;

/// Errors that can occur during the hardware signing workflow.
#[derive(Error, Debug)]
pub enum HwSignerError {
    // ── PCZT workflow errors ────────────────────────────────────────────
    #[error("Orchard proof generation failed: {0}")]
    ProofFailed(String),

    #[error("Signer initialization failed: {0}")]
    SignerInitFailed(String),

    #[error("No Orchard actions require signing")]
    NoActionsToSign,

    #[error("Network mismatch: expected coin_type {expected}, got {got}")]
    NetworkMismatch { expected: u32, got: u32 },

    #[error("Transaction extraction failed: {0}")]
    ExtractionFailed(String),

    // ── Signature errors ────────────────────────────────────────────────
    #[error("RK mismatch on action {action_idx}: expected {expected}, got {got}. This may indicate a network mismatch (e.g., mainnet PCZT sent to testnet device)")]
    RkMismatch {
        action_idx: usize,
        expected: String,
        got: String,
    },

    #[error("Signature verification failed on action {action_idx}: {reason}")]
    SignatureVerificationFailed {
        action_idx: usize,
        reason: String,
    },

    #[error("Invalid verification key for action {action_idx}")]
    InvalidVerificationKey { action_idx: usize },

    // ── Hardware device errors ──────────────────────────────────────────
    #[error("Hardware signer error: {0}")]
    DeviceError(String),

    #[error("User cancelled signing on device")]
    UserCancelled,

    // ── Transport errors ────────────────────────────────────────────────
    #[error("Transport error: {0}")]
    TransportError(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Timeout waiting for device response")]
    Timeout,

    // ── Protocol errors ─────────────────────────────────────────────────
    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("CRC mismatch: computed 0x{computed:04X}, received 0x{received:04X}")]
    CrcMismatch { computed: u16, received: u16 },

    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    #[error("Unknown message type: 0x{0:02X}")]
    UnknownMessageType(u8),

    #[error("Payload too large: {size} bytes (max {max})")]
    PayloadTooLarge { size: usize, max: usize },

    #[error("Recipient address too long: {len} bytes (max {max})")]
    RecipientTooLong { len: usize, max: usize },

    #[error("Maximum keepalive iterations exceeded ({max})")]
    MaxKeepaliveExceeded { max: usize },

    #[error("Sequence number mismatch: expected {expected}, got {got}")]
    SequenceMismatch { expected: u8, got: u8 },
}

/// Convenience alias for `Result<T, HwSignerError>`.
pub type Result<T> = std::result::Result<T, HwSignerError>;

impl From<orchard::pczt::ParseError> for HwSignerError {
    fn from(e: orchard::pczt::ParseError) -> Self {
        HwSignerError::SignerInitFailed(format!("Orchard PCZT parse error: {:?}", e))
    }
}
