//! Generic device signer — [`HardwareSigner`] implementation over HWP.
//!
//! Implements the `HardwareSigner` trait using the HWP protocol
//! to communicate with any compatible hardware signing device.
//!
//! # Example
//!
//! ```rust,ignore
//! use zcash_hw_wallet_sdk::{DeviceSigner, PcztHardwareSigning};
//! use zcash_hw_wallet_sdk::transport::SerialTransport;
//! use zcash_hw_wallet_sdk::types::COIN_TYPE_TESTNET;
//!
//! // Connect to a hardware signing device for testnet
//! let transport = SerialTransport::new("/dev/ttyACM0", 115200)?;
//! let mut signer = DeviceSigner::new(transport, COIN_TYPE_TESTNET)?;
//!
//! // Export FVK (uses the coin_type set at construction)
//! let fvk = signer.export_fvk()?;
//! println!("ak: {}", hex::encode(fvk.ak));
//!
//! // Sign — workflow reads coin_type from the signer
//! let mut workflow = PcztHardwareSigning::new(signer);
//! let result = workflow.sign(pczt_bytes)?;
//! ```

use crate::error::Result;
use crate::protocol::HwpCodec;
use crate::traits::HardwareSigner;
use crate::transport::Transport;
use crate::types::{
    ActionData, ExportedFvk, SignRequest, SignResponse, TransparentInputData,
    TransparentOutputData, TransparentSignRequest, TransparentSignResponse, TxDetails, TxMeta,
};

use tracing::{debug, info};

/// Generic hardware signer using the HWP protocol.
///
/// Wraps an [`HwpCodec`] over any [`Transport`] implementation.
/// The `coin_type` is set once at construction and used for all operations.
pub struct DeviceSigner<T: Transport> {
    codec: HwpCodec<T>,
    coin_type: u32,
}

impl<T: Transport> DeviceSigner<T> {
    /// Create a new DeviceSigner and perform the initial handshake.
    ///
    /// The `coin_type` determines the network for all subsequent operations:
    /// - `133` for mainnet, `1` for testnet (ZIP-32 derivation path)
    pub fn new(transport: T, coin_type: u32) -> Result<Self> {
        let requires_handshake = transport.requires_handshake();
        let mut codec = HwpCodec::new(transport);
        if requires_handshake {
            info!("Waiting for device handshake...");
            codec.handshake()?;
        }
        info!("Device connected (coin_type={}).", coin_type);
        Ok(Self { codec, coin_type })
    }

    /// Create a DeviceSigner without performing the handshake.
    pub fn new_no_handshake(transport: T, coin_type: u32) -> Self {
        Self {
            codec: HwpCodec::new(transport),
            coin_type,
        }
    }

    /// Get a reference to the underlying HWP codec.
    pub fn codec(&self) -> &HwpCodec<T> {
        &self.codec
    }

    /// Get a mutable reference to the underlying HWP codec.
    pub fn codec_mut(&mut self) -> &mut HwpCodec<T> {
        &mut self.codec
    }

    /// Construct a DeviceSigner and verify the device's identity against a
    /// previously-pinned pubkey before returning. Fails with
    /// [`HwSignerError::AttestationFailed`] if the device responds with an
    /// `rk` that does not match `pinned_pubkey` or with a signature that
    /// does not verify against the fresh challenge nonce.
    ///
    /// This is the recommended constructor for any application that has
    /// completed first-pairing — it catches USB-hub MITM substitution,
    /// localhost TCP impostor, and post-reflash device-key mismatch.
    /// Audit: docs/security-audit/04-host-sdk-rust.md M1.
    pub fn new_with_pinned_pubkey(
        transport: T,
        coin_type: u32,
        pinned_pubkey: &[u8; 32],
    ) -> Result<Self> {
        let mut signer = Self::new(transport, coin_type)?;
        signer.codec.attest(pinned_pubkey)?;
        info!(
            "Device attestation OK (pinned pubkey: {}...).",
            hex::encode(&pinned_pubkey[..8])
        );
        Ok(signer)
    }

    /// First-pairing: ask the device for its long-term identity pubkey.
    /// The caller is expected to STORE this value (in a config file, OS
    /// keyring, etc.) and pass it to [`Self::new_with_pinned_pubkey`] for
    /// every subsequent session. The first-pairing flow MUST run on a
    /// trusted host — typically the same one used to generate the wallet.
    ///
    /// The device also displays the same pubkey on its trusted first-boot
    /// console output; the user should compare the two values to ensure
    /// the binding is to the expected device, not a pre-flashed hostile
    /// substitute.
    pub fn pair(&mut self) -> Result<[u8; 32]> {
        info!("Pairing: requesting device identity pubkey...");
        let pk = self.codec.request_identity()?;
        info!("Device pubkey: {}", hex::encode(&pk));
        Ok(pk)
    }

    /// Run an attestation round against an already-known pubkey. Useful for
    /// re-checking session integrity mid-flight (e.g., before high-value
    /// signing); typically [`Self::new_with_pinned_pubkey`] is preferred
    /// for the once-per-session check at construction.
    pub fn attest(&mut self, pinned_pubkey: &[u8; 32]) -> Result<()> {
        self.codec.attest(pinned_pubkey)
    }
}

impl<T: Transport> HardwareSigner for DeviceSigner<T> {
    fn coin_type(&self) -> u32 {
        self.coin_type
    }

    fn export_fvk(&mut self) -> Result<ExportedFvk> {
        info!("Requesting FVK from device (coin_type={})...", self.coin_type);
        let fvk = self.codec.request_fvk(self.coin_type)?;
        debug!(ak = hex::encode(&fvk.ak), nk = hex::encode(&fvk.nk), rivk = hex::encode(&fvk.rivk), "FVK received from device");
        Ok(fvk)
    }

    fn sign_action(&mut self, request: &SignRequest) -> Result<SignResponse> {
        if request.action_index == 0 {
            info!(
                "Sending sign request to device (sighash: {}...)",
                &hex::encode(&request.sighash[..8])
            );
        } else {
            info!(
                "Sending additional sign request (action {}/{})",
                request.action_index + 1,
                request.total_actions
            );
        }

        let response = self.codec.sign(request)?;
        info!("Signature received from device.");
        Ok(response)
    }

    fn confirm_transaction(&mut self, details: &TxDetails) -> Result<bool> {
        // Devices typically show transaction details during the sign flow itself
        // (amount, fee, recipient displayed on the device screen alongside
        // the sign confirmation prompt). Log what we're about to sign.
        info!(
            "Transaction: {} zatoshis to {}, fee {} zatoshis ({} action(s))",
            details.send_amount,
            &details.recipient,
            details.fee,
            details.num_actions,
        );
        Ok(true)
    }

    fn verify_transaction(
        &mut self,
        meta: &TxMeta,
        actions: &[ActionData],
        sighash: &[u8; 32],
        transparent_inputs: &[TransparentInputData],
        transparent_outputs: &[TransparentOutputData],
    ) -> Result<()> {
        let total_actions = actions.len() as u16;
        let num_t_inputs = transparent_inputs.len() as u16;
        let num_t_outputs = transparent_outputs.len() as u16;
        let has_transparent = num_t_inputs > 0 || num_t_outputs > 0;

        info!(
            "Verifying tx on device: {} action(s), {} transparent input(s), {} transparent output(s)",
            total_actions, num_t_inputs, num_t_outputs
        );

        // 1. Send transaction metadata (index = 0xFFFF sentinel).
        //    Advances device state IDLE → RECEIVING_ACTIONS.
        let meta_data = meta.serialize();
        self.codec
            .send_tx_output(0xFFFF, total_actions, &meta_data)?;
        debug!("TxMeta sent ({} bytes), device ACK received", meta_data.len());

        // 2. Transparent flow (only if the tx has transparent components).
        //    The device's signer state machine (libzcash-orchard-c) accepts
        //    the transparent stream ONLY from RECEIVING_ACTIONS. Doing this
        //    after the shielded sighash sentinel would put it in VERIFIED and
        //    `begin_transparent` would return SIGNER_ERR_BAD_STATE; conversely
        //    skipping the flow when transparent_sig_digest is non-empty makes
        //    the shielded `verify()` fail with SIGNER_ERR_TRANSPARENT_NOT_EMPTY.
        //    So the transparent flow MUST sit between meta and the action
        //    stream — that is the contract this method enforces.
        if has_transparent {
            for (i, input) in transparent_inputs.iter().enumerate() {
                let data = input.serialize();
                self.codec
                    .send_transparent_input(i as u16, num_t_inputs, &data)?;
                debug!(
                    "TxTransparentInput {}/{} sent ({} bytes)",
                    i + 1,
                    num_t_inputs,
                    data.len()
                );
            }
            for (i, output) in transparent_outputs.iter().enumerate() {
                let data = output.serialize();
                self.codec
                    .send_transparent_output(i as u16, num_t_outputs, &data)?;
                debug!(
                    "TxTransparentOutput {}/{} sent ({} bytes)",
                    i + 1,
                    num_t_outputs,
                    data.len()
                );
            }
            // Transparent sentinel = expected digest at index == total_inputs.
            // Device recomputes the transparent digest, compares it against
            // both the sentinel and TxMeta.transparent_sig_digest, then flips
            // `transparent_verified = true` and returns to RECEIVING_ACTIONS.
            self.codec.send_transparent_input(
                num_t_inputs,
                num_t_inputs,
                &meta.transparent_sig_digest,
            )?;
            info!("Transparent digest verified — device confirmed match.");
        }

        // 3. Send each shielded action's ZIP-244 data. Prefer the memo-
        //    verifying wire format (memo + esk appended) so the device can
        //    recompute enc_ciphertext on-chip and reject any host that
        //    embeds a different memo on chain than what the user is
        //    shown. Fall back to the cmx-only payload if memo/esk were not
        //    recoverable for this action (OVK-None output).
        //
        //    v6 (NU6.3 / Ironwood) transactions prefix each payload with a
        //    pool byte (0x00 Orchard, 0x01 Ironwood) so the device hashes
        //    the action into the correct pool digest tree; v5 transactions
        //    keep the legacy untagged formats.
        let v6 = meta.is_v6();
        for (i, action) in actions.iter().enumerate() {
            let output_data = if v6 {
                action.serialize_v6()
            } else {
                action.serialize_v5().unwrap_or_else(|| action.serialize())
            };
            self.codec
                .send_tx_output(i as u16, total_actions, &output_data)?;
            debug!(
                "TxOutput {}/{} sent ({} bytes, {}), device ACK received",
                i + 1,
                total_actions,
                output_data.len(),
                match output_data.len() {
                    1447 | 1415 => "v5",
                    1416 | 904 => "v6",
                    _ => "v4",
                },
            );
        }

        // 4. Shielded sighash sentinel (index == total_actions). Device
        //    finishes the ZIP-244 shielded-bundle hash, refuses if any
        //    per-action confirmation is missing, and advances to VERIFIED —
        //    only then will SIGN_REQ produce a signature.
        self.codec
            .send_tx_output(total_actions, total_actions, sighash)?;
        info!("ZIP-244 shielded sighash verified — device VERIFIED.");

        Ok(())
    }

    fn sign_transparent_input(
        &mut self,
        request: &TransparentSignRequest,
        input_data: &TransparentInputData,
    ) -> Result<TransparentSignResponse> {
        info!(
            "Sending transparent sign request (input {}/{})",
            request.input_index + 1,
            request.total_inputs,
        );

        let response = self.codec.sign_transparent(
            request.input_index as u16,
            request.total_inputs as u16,
            &input_data.serialize(),
        )?;
        info!("Transparent signature received from device.");
        Ok(response)
    }
}

/// Create a [`DeviceSigner`] over USB serial.
///
/// Convenience function that opens the serial port and performs the handshake.
///
/// # Example
///
/// ```rust,ignore
/// use zcash_hw_wallet_sdk::types::COIN_TYPE_TESTNET;
/// let signer = zcash_hw_wallet_sdk::signer::connect_serial("/dev/ttyACM0", COIN_TYPE_TESTNET)?;
/// ```
#[cfg(feature = "serial")]
pub fn connect_serial(port_path: &str, coin_type: u32) -> Result<DeviceSigner<crate::transport::SerialTransport>> {
    let transport = crate::transport::SerialTransport::new(port_path, 115200)?;
    DeviceSigner::new(transport, coin_type)
}

/// Connect to a Ledger hardware wallet over USB HID.
///
/// ```rust,ignore
/// use zcash_hw_wallet_sdk::types::COIN_TYPE_MAINNET;
/// let signer = zcash_hw_wallet_sdk::signer::connect_ledger(COIN_TYPE_MAINNET)?;
/// ```
#[cfg(feature = "ledger")]
pub fn connect_ledger(coin_type: u32) -> Result<DeviceSigner<crate::transport::LedgerTransport>> {
    let transport = crate::transport::LedgerTransport::open()?;
    DeviceSigner::new(transport, coin_type)
}

// connect_ledger_apdu() was removed alongside the broken hhanh00-protocol
// reimplementation (see lib.rs L1 note). HWP-speaking devices use
// connect_ledger() above; Ledger users targeting hhanh00's official app
// should depend on hhanh00's own crate.

/// Connect to a Ledger app running on Speculos emulator.
///
/// ```rust,ignore
/// use zcash_hw_wallet_sdk::types::COIN_TYPE_TESTNET;
/// let signer = zcash_hw_wallet_sdk::signer::connect_speculos("127.0.0.1:9999", COIN_TYPE_TESTNET)?;
/// ```
#[cfg(feature = "ledger")]
pub fn connect_speculos(addr: &str, coin_type: u32) -> Result<DeviceSigner<crate::transport::SpeculosTransport>> {
    let transport = crate::transport::SpeculosTransport::open(addr)?;
    DeviceSigner::new(transport, coin_type)
}
