//! Signature verification utilities for hardware wallet responses.
//!
//! After receiving a signature from the hardware device, the SDK verifies:
//! 1. The rk (randomized verification key) matches the PCZT action
//! 2. The RedPallas signature is cryptographically valid against the sighash
//!
//! All comparisons of cryptographic material use constant-time operations
//! to prevent timing side-channel attacks.

use crate::error::{HwSignerError, Result};
use crate::types::SignResponse;
use subtle::ConstantTimeEq;

/// Verify that a hardware signature is valid for the given sighash.
///
/// Checks:
/// - The `rk` in the response matches `expected_rk` from the PCZT action
///   (constant-time comparison to prevent timing attacks)
/// - The RedPallas signature verifies against the sighash using the rk
///
/// This prevents both:
/// - Key confusion (device returning rk for wrong action)
/// - Invalid signatures (device malfunction or attack)
pub fn verify_signature(
    response: &SignResponse,
    sighash: &[u8; 32],
    expected_rk: &[u8; 32],
    action_idx: usize,
) -> Result<()> {
    // 1. Verify rk matches the PCZT action (constant-time to prevent timing leaks)
    if response.rk.ct_eq(expected_rk).unwrap_u8() != 1 {
        return Err(HwSignerError::RkMismatch {
            action_idx,
            expected: hex::encode(&expected_rk[..8]),
            got: hex::encode(&response.rk[..8]),
        });
    }

    // 2. Verify the RedPallas signature cryptographically
    let sig = reddsa::Signature::<reddsa::orchard::SpendAuth>::from(response.signature);
    let vk = reddsa::VerificationKey::<reddsa::orchard::SpendAuth>::try_from(response.rk)
        .map_err(|_| HwSignerError::InvalidVerificationKey { action_idx })?;

    vk.verify(sighash, &sig)
        .map_err(|e| HwSignerError::SignatureVerificationFailed {
            action_idx,
            reason: format!("{:?}", e),
        })?;

    Ok(())
}
