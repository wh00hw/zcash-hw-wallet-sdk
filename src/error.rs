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

    #[error("Transparent sighash verification failed: device-computed transparent digest does not match")]
    TransparentSighashMismatch,

    #[error("Invalid transparent input index {index} (bundle has {input_count} inputs)")]
    InvalidTransparentInputIndex { index: usize, input_count: usize },

    #[error("Unsupported pool: {0}")]
    UnsupportedPool(&'static str),

    /// Transparent inputs are not supported. Raised by the workflow for a
    /// PCZT that spends transparent coins — before any proof is generated
    /// and before anything is sent to the device, with the number of inputs
    /// — and for the device's own refusal (HWP 0x18, `inputs: 0`: the device
    /// does not say how many). Transparent *outputs* (shielded -> t-address)
    /// are not affected.
    #[error(
        "Transparent inputs are not supported by this device ({inputs} transparent \
         input(s) in the PCZT; 0 = refused by the device itself); only shielded spends \
         can be signed"
    )]
    TransparentInputsNotSupported { inputs: usize },

    #[error(
        "Sapling components not supported: this is an Orchard-only signer (PCZT has \
         {spends} sapling spend(s) and {outputs} sapling output(s))"
    )]
    SaplingNotSupported { spends: usize, outputs: usize },

    /// Device rejected the action because the on-device cmx recomputation
    /// from the claimed `(recipient, value, rseed)` did not match the cmx
    /// field of the action — recipient-substitution attempt (HWP 0x0D).
    #[error("Note commitment mismatch on device: {reason}")]
    NoteCommitmentMismatch { reason: String },

    /// Device rejected the SIGN_REQ because the recipient UA does not
    /// decode to any of the Orchard receivers the user just confirmed via
    /// per-output review — hostile companion lying about the destination
    /// (HWP 0x0E).
    #[error("Recipient mismatch on device: {reason}")]
    RecipientMismatch { reason: String },

    /// Device refused an action because it was sent as the compact
    /// (no-memo, 904-byte) body (HWP 0x14). The device re-encrypts the note
    /// of every output — payments, the wallet's own change and zero-value
    /// padding alike — so the host must send the full 1416-byte body with
    /// the memo plaintext for every action. The session has been reset.
    #[error(
        "Device requires the memo-carrying action body for every output \
         (compact body refused): {reason}"
    )]
    MemoRequired { reason: String },

    /// Device refused the transaction's consensus branch ID: it is not in
    /// the firmware's allow-list (HWP 0x15). A network upgrade the firmware
    /// does not know needs a firmware update.
    #[error("Consensus branch not supported by the device firmware: {reason}")]
    BranchNotAllowed { reason: String },

    /// The transaction exceeds what the device can review: too many shielded
    /// actions, transparent outputs or memos, or a memo on a device with no
    /// way to display one (HWP 0x16). Nothing was signed.
    #[error("Transaction exceeds what the device can review: {reason}")]
    DeviceLimitExceeded { reason: String },

    /// The device refused a TxMeta that declares a non-zero value balance
    /// for a shielded pool with no action in the transaction (HWP 0x19):
    /// that number is not bound by the signature hash, so the device will
    /// not fold it into the fee it shows.
    #[error("Non-zero value balance for a shielded pool without actions: {reason}")]
    EmptyPoolBalance { reason: String },

    /// An output value, a value balance or a total above MAX_MONEY, or a
    /// sum that overflows 64 bits, on the device (HWP 0x17). Nothing was
    /// signed.
    #[error("Output values overflow on device: {reason}")]
    ValueOverflow { reason: String },

    /// The PCZT handed to the workflow is malformed or internally
    /// inconsistent (it does not parse, or its transaction effects cannot be
    /// extracted). Raised before any proof is generated or any transaction
    /// data is sent to the device.
    #[error("Invalid PCZT: {0}")]
    InvalidPczt(String),

    /// The host could not reconstruct the note plaintext (memo) of a
    /// shielded output from the PCZT: the note described by the PCZT's
    /// `(recipient, value, rseed)` and the action's nullifier does not open
    /// `enc_ciphertext`. The device needs the memo-carrying action body for
    /// every output (zero-value padding included), so the transaction
    /// cannot be submitted. Raised before any proof is generated and before
    /// any transaction data is sent to the device.
    #[error("Cannot recover the plaintext of {pool} output {action_idx} ({value} zat): {reason}")]
    OutputNotRecoverable {
        pool: &'static str,
        action_idx: usize,
        value: u64,
        reason: String,
    },


    /// Device attestation failed: the connected device is not the one paired,
    /// or the response signature is invalid (audit M1).
    #[error("Device attestation failed: {reason}")]
    AttestationFailed { reason: String },

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

impl From<pczt::roles::low_level_signer::OrchardParseError> for HwSignerError {
    fn from(e: pczt::roles::low_level_signer::OrchardParseError) -> Self {
        HwSignerError::SignerInitFailed(format!("Orchard-protocol PCZT parse error: {:?}", e))
    }
}
