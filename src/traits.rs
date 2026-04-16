use crate::error::{HwSignerError, Result};
use crate::types::{
    ActionData, ExportedFvk, SignRequest, SignResponse, TransparentInputData,
    TransparentOutputData, TransparentSignRequest, TransparentSignResponse, TxDetails, TxMeta,
};

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
/// struct MyDevice { coin_type: u32 }
///
/// impl HardwareSigner for MyDevice {
///     fn coin_type(&self) -> u32 { self.coin_type }
///
///     fn export_fvk(&mut self) -> Result<ExportedFvk> {
///         // Read FVK components from hardware (uses self.coin_type() internally)
///         todo!()
///     }
///
///     fn sign_action(&mut self, request: &SignRequest) -> Result<SignResponse> {
///         // Send sighash + alpha to device, receive signature + rk
///         todo!()
///     }
/// }
/// ```
pub trait HardwareSigner {
    /// The ZIP-32 coin type this signer is configured for.
    ///
    /// - `133` for mainnet (`m/32'/133'/account'`)
    /// - `1` for testnet (`m/32'/1'/account'`)
    ///
    /// Set once at construction time. Used by the SDK to populate TxMeta
    /// and validate network consistency throughout the signing workflow.
    fn coin_type(&self) -> u32;

    /// Export the Orchard full viewing key from the hardware device.
    ///
    /// Uses the signer's `coin_type()` to derive keys from the correct
    /// ZIP-32 path. Typically called once during initial wallet pairing.
    fn export_fvk(&mut self) -> Result<ExportedFvk>;

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

    /// Sign a single transparent input (ECDSA secp256k1).
    ///
    /// Unlike Orchard/Sapling where the shielded sighash is shared across all
    /// spends, transparent has a **per-input sighash** that commits to the
    /// specific input's script and value. The device computes this sighash
    /// on-device from its stored transparent state + the input data.
    ///
    /// The `input_data` contains the full wire-format input for on-device
    /// txin_sig_digest computation.
    ///
    /// The default implementation returns `UnsupportedPool` — Orchard-only
    /// devices don't need to implement this.
    fn sign_transparent_input(
        &mut self,
        _request: &TransparentSignRequest,
        _input_data: &TransparentInputData,
    ) -> Result<TransparentSignResponse> {
        Err(HwSignerError::UnsupportedPool("transparent"))
    }

    /// Send transparent inputs and outputs to the device for on-device
    /// transparent digest verification (HWP v3).
    ///
    /// The device independently computes the ZIP-244 transparent digest
    /// from the raw inputs/outputs and compares it with the pre-computed
    /// `transparent_sig_digest` in TxMeta. This prevents a compromised
    /// companion from providing a forged transparent digest.
    ///
    /// The default implementation is a no-op (v2 behavior: device trusts
    /// the pre-computed transparent digest from the companion).
    fn verify_transparent_digest(
        &mut self,
        _inputs: &[TransparentInputData],
        _outputs: &[TransparentOutputData],
        _expected_digest: &[u8; 32],
    ) -> Result<()> {
        Ok(())
    }
}
