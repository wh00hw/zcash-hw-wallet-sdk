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
//! use zcash_protocol::consensus::Network;
//!
//! // Connect to a hardware signing device over USB serial
//! let transport = SerialTransport::new("/dev/ttyACM0", 115200)?;
//! let mut signer = DeviceSigner::new(transport)?;
//!
//! // Export FVK for wallet pairing (testnet)
//! use zcash_hw_wallet_sdk::types::coin_type_for_network;
//! let fvk = signer.export_fvk(coin_type_for_network(&Network::TestNetwork))?;
//! println!("ak: {}", hex::encode(fvk.ak));
//!
//! // Use in signing workflow
//! let mut workflow = PcztHardwareSigning::new(signer, Network::TestNetwork);
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
/// Works with any device that speaks the HWP protocol (serial, TCP, etc.).
pub struct DeviceSigner<T: Transport> {
    codec: HwpCodec<T>,
}

impl<T: Transport> DeviceSigner<T> {
    /// Create a new DeviceSigner and perform the initial handshake.
    ///
    /// Waits for a PING from the device and responds with PONG.
    pub fn new(transport: T) -> Result<Self> {
        let requires_handshake = transport.requires_handshake();
        let mut codec = HwpCodec::new(transport);
        if requires_handshake {
            info!("Waiting for device handshake...");
            codec.handshake()?;
        }
        info!("Device connected.");
        Ok(Self { codec })
    }

    /// Create a DeviceSigner without performing the handshake.
    ///
    /// Use this if you've already handled the PING/PONG exchange.
    pub fn new_no_handshake(transport: T) -> Self {
        Self {
            codec: HwpCodec::new(transport),
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
    fn export_fvk(&mut self, coin_type: u32) -> Result<ExportedFvk> {
        info!("Requesting FVK from device (coin_type={})...", coin_type);
        let fvk = self.codec.request_fvk(coin_type)?;
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
/// let signer = zcash_hw_wallet_sdk::signer::connect_serial("/dev/ttyACM0")?;
/// ```
#[cfg(feature = "serial")]
pub fn connect_serial(port_path: &str) -> Result<DeviceSigner<crate::transport::SerialTransport>> {
    let transport = crate::transport::SerialTransport::new(port_path, 115200)?;
    DeviceSigner::new(transport)
}

/// Connect to a Ledger hardware wallet over USB HID.
///
/// Automatically finds the first connected Ledger device.
/// The Zcash Orchard app must be open on the device.
///
/// ```rust,ignore
/// let signer = zcash_hw_wallet_sdk::signer::connect_ledger()?;
/// ```
#[cfg(feature = "ledger")]
pub fn connect_ledger() -> Result<DeviceSigner<crate::transport::LedgerTransport>> {
    let transport = crate::transport::LedgerTransport::open()?;
    DeviceSigner::new(transport)
}

/// Connect to a Ledger app running on Speculos emulator.
///
/// ```rust,ignore
/// let signer = zcash_hw_wallet_sdk::signer::connect_speculos("127.0.0.1:9999")?;
/// ```
#[cfg(feature = "ledger")]
pub fn connect_speculos(addr: &str) -> Result<DeviceSigner<crate::transport::SpeculosTransport>> {
    let transport = crate::transport::SpeculosTransport::open(addr)?;
    DeviceSigner::new(transport)
}
