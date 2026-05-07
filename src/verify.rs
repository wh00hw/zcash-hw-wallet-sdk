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
use tracing::warn;

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

/// Independently verify a transparent ECDSA signature returned by the device.
///
/// Mirrors the Orchard `verify_signature` defence-in-depth: even though the
/// device computes the per-input transparent sighash itself and signs against
/// it, the host re-verifies before injecting into the PCZT. This catches
/// device bugs and detects the case where the device returned a valid-DER
/// but cryptographically wrong signature (or one for a different sighash).
///
/// We additionally cross-check that the public key returned by the device
/// is the one bound to the input's `script_pubkey`. For a standard P2PKH
/// script (`OP_DUP OP_HASH160 <20> <pubkey-hash> OP_EQUALVERIFY OP_CHECKSIG`)
/// this means HASH160(pubkey) must equal the 20-byte hash embedded in the
/// script. This prevents a malicious device from signing with a different
/// key it happens to own — without this check the user's transparent input
/// would be unspendable but the host wouldn't know until the network
/// rejected the broadcast.
///
/// Audit: docs/security-audit/04-host-sdk-rust.md H2.
pub fn verify_transparent_signature(
    sighash: &[u8; 32],
    der_sig: &[u8],
    pubkey_compressed: &[u8; 33],
    script_pubkey: &[u8],
    input_idx: usize,
) -> Result<()> {
    use secp256k1::{ecdsa, Message, PublicKey, Secp256k1};

    // 1. Cryptographic verification: the signature must validate against
    //    the device-returned pubkey for the host-computed sighash.
    let secp = Secp256k1::verification_only();

    let msg = Message::from_digest_slice(sighash).map_err(|e| {
        HwSignerError::TransparentSignatureVerificationFailed {
            input_idx,
            reason: format!("invalid sighash: {}", e),
        }
    })?;

    let sig = ecdsa::Signature::from_der(der_sig).map_err(|e| {
        HwSignerError::TransparentSignatureVerificationFailed {
            input_idx,
            reason: format!("invalid DER signature: {}", e),
        }
    })?;

    let pk = PublicKey::from_slice(pubkey_compressed).map_err(|e| {
        HwSignerError::TransparentSignatureVerificationFailed {
            input_idx,
            reason: format!("invalid pubkey: {}", e),
        }
    })?;

    secp.verify_ecdsa(&msg, &sig, &pk).map_err(|e| {
        HwSignerError::TransparentSignatureVerificationFailed {
            input_idx,
            reason: format!("ECDSA verification failed: {}", e),
        }
    })?;

    // 2. Pubkey-to-script binding: parse the standard P2PKH template and
    //    verify HASH160(pubkey) matches the embedded pubkey-hash.
    //
    // P2PKH layout (25 bytes):
    //   0x76 (OP_DUP) || 0xa9 (OP_HASH160) || 0x14 (push 20) ||
    //   <hash160> (20 bytes) || 0x88 (OP_EQUALVERIFY) || 0xac (OP_CHECKSIG)
    if script_pubkey.len() == 25
        && script_pubkey[0] == 0x76
        && script_pubkey[1] == 0xa9
        && script_pubkey[2] == 0x14
        && script_pubkey[23] == 0x88
        && script_pubkey[24] == 0xac
    {
        let computed_hash = hash160(pubkey_compressed);
        if !bool::from(computed_hash[..].ct_eq(&script_pubkey[3..23])) {
            return Err(HwSignerError::TransparentSignatureVerificationFailed {
                input_idx,
                reason:
                    "pubkey returned by device does not hash to script_pubkey's pubkey-hash"
                        .to_string(),
            });
        }
    } else {
        // Non-P2PKH script (P2SH, exotic). We don't currently know how to
        // bind the pubkey to a redeem script we haven't been given; warn
        // rather than reject so the workflow doesn't break for legitimate
        // multisig/timelock inputs that the wallet doesn't natively support
        // anyway. The cryptographic check in (1) above still applies.
        warn!(
            "transparent input[{}]: non-P2PKH script_pubkey ({} bytes), \
             skipping pubkey-to-script binding check; ECDSA signature did verify",
            input_idx,
            script_pubkey.len()
        );
    }

    Ok(())
}

/// HASH160 = RIPEMD160(SHA256(data)). Compressed-pubkey-to-pubkey-hash for
/// the standard Bitcoin/Zcash P2PKH script.
///
/// Uses the `sha2` and `ripemd` crates which are already pulled in
/// transitively by orchard / zcash_primitives.
fn hash160(data: &[u8]) -> [u8; 20] {
    use ripemd::{Digest as _, Ripemd160};
    use sha2::Sha256;

    let sha = Sha256::digest(data);
    let mut hasher = Ripemd160::new();
    hasher.update(&sha);
    let out = hasher.finalize();

    let mut result = [0u8; 20];
    result.copy_from_slice(&out);
    result
}
