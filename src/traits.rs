use crate::error::Result;
use crate::types::{ActionData, ExportedFvk, SignRequest, SignResponse, TxDetails, TxMeta};

/// Trait that any hardware wallet must implement to participate in
/// PCZT-based Zcash Orchard transaction signing.
///
/// The SDK handles the entire PCZT workflow (proof generation, sighash
/// computation, signature injection). The hardware device only needs to:
///
/// 1. Export its full viewing key (one-time, during wallet pairing)
/// 2. Sign individual Orchard actions when presented with a sighash + alpha
/// 3. Optionally display transaction details for user confirmation
///
/// # Example
///
/// ```rust,ignore
/// use zcash_hw_wallet_sdk::{HardwareSigner, SignRequest, SignResponse, ExportedFvk, TxDetails};
/// use zcash_hw_wallet_sdk::types::COIN_TYPE_TESTNET;
///
/// struct MyDevice { /* ... */ }
///
/// impl HardwareSigner for MyDevice {
///     fn export_fvk(&mut self, coin_type: u32) -> Result<ExportedFvk> {
///         // Read FVK components from hardware for the given network
///         todo!()
///     }
///
///     fn sign_action(&mut self, request: &SignRequest) -> Result<SignResponse> {
///         // Send sighash + alpha to device, receive signature + rk
///         todo!()
///     }
///
///     fn confirm_transaction(&mut self, details: &TxDetails) -> Result<bool> {
///         // Display transaction on device screen, wait for user confirmation
///         todo!()
///     }
/// }
/// ```
pub trait HardwareSigner {
    /// Export the Orchard full viewing key from the hardware device.
    ///
    /// The `coin_type` parameter specifies the ZIP-32 derivation path:
    /// - `133` for mainnet (`m/32'/133'/account'`)
    /// - `1` for testnet (`m/32'/1'/account'`)
    ///
    /// This is typically called once during initial wallet pairing. The FVK
    /// is used by the companion software to derive addresses and scan the
    /// blockchain — the spending key never leaves the device.
    fn export_fvk(&mut self, coin_type: u32) -> Result<ExportedFvk>;

    /// Sign a single Orchard action.
    ///
    /// The device receives the sighash and alpha randomizer, performs a
    /// RedPallas rerandomized Schnorr signature using its internal spending
    /// key, and returns the 64-byte signature along with the 32-byte
    /// randomized verification key (rk).
    ///
    /// This method may be called multiple times per transaction if there
    /// are multiple Orchard actions requiring hardware signatures (e.g.,
    /// when spending multiple notes).
    fn sign_action(&mut self, request: &SignRequest) -> Result<SignResponse>;

    /// Display transaction details on the device for user confirmation.
    ///
    /// Returns `Ok(true)` if the user confirmed, `Ok(false)` if declined.
    /// The default implementation always confirms (for headless devices).
    fn confirm_transaction(&mut self, _details: &TxDetails) -> Result<bool> {
        Ok(true)
    }

    /// Send transaction metadata and action data to the device for on-device
    /// ZIP-244 sighash verification (HWP v2).
    ///
    /// The SDK extracts the transaction header, Orchard bundle metadata, and
    /// each action's ZIP-244 components from the PCZT. The device uses these
    /// to independently compute the full ZIP-244 sighash and **refuses to sign**
    /// if it doesn't match the sighash in the subsequent `SignReq`.
    ///
    /// This eliminates the need for the device to blindly trust the companion's sighash.
    ///
    /// The default implementation is a no-op (v1 behavior: device trusts companion).
    /// `DeviceSigner` overrides this to send data via the HWP protocol.
    fn verify_sighash(
        &mut self,
        _meta: &TxMeta,
        _actions: &[ActionData],
        _sighash: &[u8; 32],
    ) -> Result<()> {
        Ok(())
    }
}
