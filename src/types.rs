use serde::{Deserialize, Serialize};
use zcash_protocol::consensus::Network;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ZIP-32 coin type for mainnet (BIP-44 / ZIP-32 derivation path).
pub const COIN_TYPE_MAINNET: u32 = 133;

/// ZIP-32 coin type for testnet.
pub const COIN_TYPE_TESTNET: u32 = 1;

/// Map a [`Network`] to the corresponding ZIP-32 coin type.
pub fn coin_type_for_network(network: &Network) -> u32 {
    match network {
        Network::MainNetwork => COIN_TYPE_MAINNET,
        Network::TestNetwork => COIN_TYPE_TESTNET,
    }
}

/// Request sent to a hardware device for signing a single Orchard action.
///
/// Sensitive fields (`sighash`, `alpha`) are zeroized on drop to prevent
/// leaking cryptographic material in memory.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SignRequest {
    /// The transaction sighash that must be signed (32 bytes).
    /// This is the same for all actions within a single transaction.
    pub sighash: [u8; 32],

    /// The action randomizer alpha (32 bytes).
    /// Each Orchard action has a unique alpha used to rerandomize the
    /// spend authorization key before signing.
    pub alpha: [u8; 32],

    /// The spend amount in zatoshis (for device display).
    pub amount: u64,

    /// The transaction fee in zatoshis (for device display).
    pub fee: u64,

    /// The recipient address (for device display).
    pub recipient: String,

    /// Zero-based index of this action within the Orchard bundle.
    pub action_index: usize,

    /// Total number of actions requiring hardware signatures.
    pub total_actions: usize,
}

/// Response from a hardware device after signing an action.
///
/// Contains the RedPallas signature and randomized verification key.
/// Zeroized on drop to prevent leaking signature material.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SignResponse {
    /// The RedPallas spend authorization signature (64 bytes).
    pub signature: [u8; 64],

    /// The randomized verification key rk (32 bytes).
    /// Used to verify the signature matches the expected action.
    pub rk: [u8; 32],
}

/// Transaction details for user confirmation on the device display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxDetails {
    /// Total amount being sent in zatoshis.
    pub send_amount: u64,

    /// Transaction fee in zatoshis.
    pub fee: u64,

    /// Recipient address string.
    pub recipient: String,

    /// Number of Orchard actions that require signing.
    pub num_actions: usize,

    /// Optional memo text.
    pub memo: Option<String>,
}

/// Full viewing key components exported from a hardware device.
///
/// These three 32-byte components reconstruct an Orchard full viewing key:
/// - `ak`: the spend validating key (used to verify signatures)
/// - `nk`: the nullifier deriving key (used to detect spent notes)
/// - `rivk`: the randomized internal viewing key commitment
///
/// Zeroized on drop to prevent leaking key material in memory.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct ExportedFvk {
    /// Spend validating key (32 bytes).
    pub ak: [u8; 32],

    /// Nullifier deriving key (32 bytes).
    pub nk: [u8; 32],

    /// Randomized internal viewing key (32 bytes).
    pub rivk: [u8; 32],
}

impl ExportedFvk {
    /// Concatenate ak || nk || rivk into the 96-byte Orchard FVK encoding.
    pub fn to_orchard_fvk_bytes(&self) -> [u8; 96] {
        let mut bytes = [0u8; 96];
        bytes[..32].copy_from_slice(&self.ak);
        bytes[32..64].copy_from_slice(&self.nk);
        bytes[64..].copy_from_slice(&self.rivk);
        bytes
    }

    /// Parse and validate the Orchard `FullViewingKey` from the exported components.
    ///
    /// Returns `None` if the key bytes are invalid (e.g. not on the curve).
    pub fn to_orchard_fvk(&self) -> Option<orchard::keys::FullViewingKey> {
        orchard::keys::FullViewingKey::from_bytes(&self.to_orchard_fvk_bytes())
    }

    /// Encode as a Unified Full Viewing Key (UFVK) string for the given network.
    ///
    /// The UFVK contains only the Orchard component (no Sapling or transparent).
    /// This is the string you pass to `restore_from_ufvk` to create a watch-only wallet.
    ///
    /// Returns an error if the FVK bytes are invalid.
    pub fn to_ufvk_string(
        &self,
        network: &zcash_protocol::consensus::Network,
    ) -> crate::error::Result<String> {
        use zcash_address::unified::{self, Encoding};
        use zcash_protocol::consensus::Parameters;

        let fvk_bytes = self.to_orchard_fvk_bytes();

        // Validate first
        orchard::keys::FullViewingKey::from_bytes(&fvk_bytes)
            .ok_or_else(|| crate::error::HwSignerError::DeviceError(
                "Invalid Orchard FVK bytes from device".to_string(),
            ))?;

        let ufvk = unified::Ufvk::try_from_items(
            vec![unified::Fvk::Orchard(fvk_bytes)]
        ).map_err(|e| crate::error::HwSignerError::DeviceError(
            format!("UFVK encoding failed: {}", e),
        ))?;

        Ok(ufvk.encode(&network.network_type()))
    }
}

/// Serialized action data for on-device sighash verification (HWP v2).
///
/// Contains all the fields the device needs to independently compute
/// the ZIP-244 orchard actions digest and verify the sighash.
///
/// Wire format per action:
/// `cv_net(32) || nullifier(32) || rk(32) || cmx(32) || ephemeral_key(32) || enc_ciphertext(580) || out_ciphertext(80)`
/// Total: 820 bytes
#[derive(Debug, Clone)]
pub struct ActionData {
    /// Value commitment (32 bytes).
    pub cv_net: [u8; 32],
    /// Nullifier (32 bytes).
    pub nullifier: [u8; 32],
    /// Randomized verification key (32 bytes).
    pub rk: [u8; 32],
    /// Extracted note commitment (32 bytes).
    pub cmx: [u8; 32],
    /// Ephemeral public key (32 bytes).
    pub ephemeral_key: [u8; 32],
    /// Encrypted note plaintext (580 bytes).
    pub enc_ciphertext: Vec<u8>,
    /// Encrypted outgoing plaintext (80 bytes).
    pub out_ciphertext: Vec<u8>,
}

impl ActionData {
    /// Serialize to the wire format for TxOutput messages.
    ///
    /// Layout: `cv_net(32) || nullifier(32) || rk(32) || cmx(32) || ephemeral_key(32) || enc_ciphertext || out_ciphertext`
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            32 + 32 + 32 + 32 + 32 + self.enc_ciphertext.len() + self.out_ciphertext.len(),
        );
        buf.extend_from_slice(&self.cv_net);
        buf.extend_from_slice(&self.nullifier);
        buf.extend_from_slice(&self.rk);
        buf.extend_from_slice(&self.cmx);
        buf.extend_from_slice(&self.ephemeral_key);
        buf.extend_from_slice(&self.enc_ciphertext);
        buf.extend_from_slice(&self.out_ciphertext);
        buf
    }
}

/// Transaction metadata for on-device ZIP-244 sighash computation.
///
/// Contains the header fields and Orchard bundle metadata that the device
/// needs (together with action data) to independently compute the sighash.
///
/// Wire format (129 bytes):
/// `version[4 LE] || version_group_id[4 LE] || consensus_branch_id[4 LE] ||
///  lock_time[4 LE] || expiry_height[4 LE] ||
///  orchard_flags[1] || value_balance[8 LE signed] || anchor[32] ||
///  transparent_sig_digest[32] || sapling_digest[32] || coin_type[4 LE]`
///
/// The first 125 bytes are used for ZIP-244 sighash computation.
/// The trailing `coin_type` is for network discrimination (not hashed).
#[derive(Debug, Clone)]
pub struct TxMeta {
    pub version: u32,
    pub version_group_id: u32,
    pub consensus_branch_id: u32,
    pub lock_time: u32,
    pub expiry_height: u32,
    pub orchard_flags: u8,
    pub value_balance: i64,
    pub anchor: [u8; 32],
    /// Pre-computed transparent signature digest (ZIP-244 S.2).
    pub transparent_sig_digest: [u8; 32],
    /// Pre-computed sapling digest (ZIP-244 T.3).
    pub sapling_digest: [u8; 32],
    /// ZIP-32 coin type for network discrimination (133 = mainnet, 1 = testnet).
    pub coin_type: u32,
}

impl TxMeta {
    /// Serialize to the 129-byte wire format for TxOutput metadata message.
    ///
    /// Bytes 0..125 are the core ZIP-244 fields (used for sighash computation).
    /// Bytes 125..129 are the coin_type extension (network discrimination, not hashed).
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(129);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.version_group_id.to_le_bytes());
        buf.extend_from_slice(&self.consensus_branch_id.to_le_bytes());
        buf.extend_from_slice(&self.lock_time.to_le_bytes());
        buf.extend_from_slice(&self.expiry_height.to_le_bytes());
        buf.push(self.orchard_flags);
        buf.extend_from_slice(&self.value_balance.to_le_bytes());
        buf.extend_from_slice(&self.anchor);
        buf.extend_from_slice(&self.transparent_sig_digest);
        buf.extend_from_slice(&self.sapling_digest);
        buf.extend_from_slice(&self.coin_type.to_le_bytes());
        buf
    }

    /// Extract TxMeta from a parsed PCZT.
    ///
    /// Reads the global header fields and Orchard bundle metadata.
    /// The transparent_sig_digest and sapling_digest are extracted from the
    /// TxDigests computed during proof generation (set via set_digests).
    pub fn from_pczt(pczt: &pczt::Pczt) -> Self {
        let global = pczt.global();
        let orchard = pczt.orchard();
        let (magnitude, is_negative) = orchard.value_sum();
        let value_balance = if *is_negative {
            -(*magnitude as i64)
        } else {
            *magnitude as i64
        };
        Self {
            version: *global.tx_version(),
            version_group_id: *global.version_group_id(),
            consensus_branch_id: *global.consensus_branch_id(),
            lock_time: 0,
            expiry_height: *global.expiry_height(),
            orchard_flags: *orchard.flags(),
            value_balance,
            anchor: *orchard.anchor(),
            // These will be filled in by the workflow from the TxDigests
            transparent_sig_digest: [0u8; 32],
            sapling_digest: [0u8; 32],
            // Set by the workflow based on the target network
            coin_type: 0,
        }
    }

    /// Set the pre-computed digests from the signer's TxDigests.
    pub fn set_digests(&mut self, transparent_sig_digest: [u8; 32], sapling_digest: [u8; 32]) {
        self.transparent_sig_digest = transparent_sig_digest;
        self.sapling_digest = sapling_digest;
    }
}

/// Outcome of a completed hardware signing workflow.
#[derive(Debug, Clone)]
pub struct SigningResult {
    /// The fully signed PCZT bytes, ready for transaction extraction.
    pub signed_pczt: Vec<u8>,

    /// Number of Orchard actions that were signed by hardware.
    pub actions_signed: usize,
}
