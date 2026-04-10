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
use crate::types::{ActionData, ExportedFvk, SignRequest, SignResponse, TxDetails, TxMeta};

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

    fn verify_sighash(
        &mut self,
        meta: &TxMeta,
        actions: &[ActionData],
        sighash: &[u8; 32],
    ) -> Result<()> {
        let total = actions.len() as u16;
        info!(
            "Sending tx metadata + {} action(s) to device for ZIP-244 sighash verification (v2)...",
            total
        );

        // 1. Send transaction metadata (index = 0xFFFF sentinel)
        let meta_data = meta.serialize();

        self.codec
            .send_tx_output(0xFFFF, total, &meta_data)?;
        info!("TxMeta sent ({} bytes), device ACK received", meta_data.len());

        // 2. Send each action's ZIP-244 data
        for (i, action) in actions.iter().enumerate() {
            let output_data = action.serialize();
            self.codec
                .send_tx_output(i as u16, total, &output_data)?;
            info!(
                "TxOutput {}/{} sent ({} bytes), device ACK received",
                i + 1,
                total,
                output_data.len()
            );
        }

        // 3. Send expected sighash as sentinel (index = total)
        // The device has now computed its own ZIP-244 sighash from the metadata +
        // action data. It compares with this value and returns SighashMismatch on error.
        self.codec
            .send_tx_output(total, total, sighash)?;
        info!("ZIP-244 sighash verified — device confirmed match.");

        Ok(())
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
