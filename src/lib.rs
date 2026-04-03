//! # zcash-hw-wallet-sdk
//!
//! Transport-agnostic SDK for signing Zcash Orchard shielded transactions
//! via hardware wallets using the PCZT (Partially Created Zcash Transaction)
//! standard.
//!
//! ## Overview
//!
//! The only operation that requires the spending key (`ask`) is the RedPallas
//! spend authorization signature. Everything else — proof generation, blockchain
//! sync, transaction construction — can be done with the full viewing key alone.
//!
//! This crate wraps the PCZT workflow for hardware wallet use cases:
//!
//! 1. Define the [`HardwareSigner`] trait that any device can implement (4 methods, 2 have defaults)
//! 2. Provide [`PcztHardwareSigning`] to orchestrate the signing pipeline
//! 3. Ship transport implementations for Serial and QR
//! 4. Include [`DeviceSigner`] as a ready-to-use HWP-based signer
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use zcash_hw_wallet_sdk::{DeviceSigner, PcztHardwareSigning};
//! use zcash_protocol::consensus::Network;
//!
//! // Connect to a hardware signing device over USB serial
//! let signer = zcash_hw_wallet_sdk::signer::connect_serial("/dev/ttyACM0")?;
//!
//! // Sign a PCZT (from zcash_client_backend::create_pczt_from_proposal)
//! let mut workflow = PcztHardwareSigning::new(signer, Network::TestNetwork);
//! let result = workflow.sign(pczt_bytes)?;
//!
//! // Pass result.signed_pczt to extract_and_store_transaction_from_pczt
//! ```
//!
//! ## Implementing a Custom Hardware Signer
//!
//! ```rust,ignore
//! use zcash_hw_wallet_sdk::*;
//! use zcash_hw_wallet_sdk::types::COIN_TYPE_TESTNET;
//!
//! struct MyHsm { /* ... */ }
//!
//! impl HardwareSigner for MyHsm {
//!     fn export_fvk(&mut self, coin_type: u32) -> error::Result<ExportedFvk> {
//!         // Read FVK components from your HSM for the given network
//!         todo!()
//!     }
//!
//!     fn sign_action(&mut self, request: &SignRequest) -> error::Result<SignResponse> {
//!         // Send sighash + alpha to HSM, receive signature + rk
//!         todo!()
//!     }
//! }
//! ```

pub mod error;
pub mod protocol;
pub mod signer;
pub mod traits;
pub mod transport;
pub mod types;
pub mod verify;
pub mod workflow;

// Re-export primary types for ergonomic use
pub use error::{HwSignerError, Result};
pub use signer::DeviceSigner;
pub use traits::HardwareSigner;
pub use types::{
    ActionData, ExportedFvk, SignRequest, SignResponse, SigningResult, TxDetails, TxMeta,
};
pub use workflow::PcztHardwareSigning;

#[cfg(test)]
mod tests;
