//! PCZT hardware signing workflow manager.
//!
//! Orchestrates the full signing pipeline:
//! 1. Generate Orchard proof (Halo2)
//! 2. Compute sighash
//! 3. Send action data to device for sighash verification (v2)
//! 4. Collect signatures from hardware device
//! 5. Verify each signature
//! 6. Inject signatures into PCZT
//! 7. Return signed PCZT for extraction

use crate::error::{HwSignerError, Result};
use crate::traits::HardwareSigner;
use crate::types::{
    ActionData, SignRequest, SigningResult, TransparentInputData, TransparentOutputData,
    TransparentSignRequest, TxDetails, TxMeta,
};
use crate::verify;

use ff::PrimeField;
use tracing::{debug, info};
use zcash_protocol::consensus::BranchId;
use zeroize::Zeroize;

/// High-level PCZT hardware signing workflow.
///
/// Takes a PCZT that has been created from a proposal (using the full viewing
/// key only — no spending key), runs the Orchard prover, sends each action
/// to the hardware signer for signature, verifies the signatures, and
/// returns the fully signed PCZT.
///
/// # Example
///
/// ```rust,ignore
/// use zcash_hw_wallet_sdk::{PcztHardwareSigning, DeviceSigner};
/// use zcash_hw_wallet_sdk::transport::SerialTransport;
/// use zcash_hw_wallet_sdk::types::COIN_TYPE_TESTNET;
///
/// // Create the signer connected to a hardware device (testnet)
/// let transport = SerialTransport::new("/dev/ttyACM0", 115200)?;
/// let signer = DeviceSigner::new(transport, COIN_TYPE_TESTNET)?;
///
/// // Sign a PCZT — the workflow reads coin_type from the signer
/// let mut workflow = PcztHardwareSigning::new(signer);
/// let result = workflow.sign(pczt_bytes)?;
///
/// // result.signed_pczt can be passed to extract_and_store_transaction_from_pczt
/// ```
pub struct PcztHardwareSigning<S: HardwareSigner> {
    signer: S,
}

impl<S: HardwareSigner> PcztHardwareSigning<S> {
    /// Create a new workflow manager wrapping a hardware signer.
    ///
    /// The signer's `coin_type()` determines the network for TxMeta
    /// and is validated against the PCZT's consensus_branch_id.
    pub fn new(signer: S) -> Self {
        Self { signer }
    }

    /// Get a reference to the underlying signer.
    pub fn signer(&self) -> &S {
        &self.signer
    }

    /// Get a mutable reference to the underlying signer.
    pub fn signer_mut(&mut self) -> &mut S {
        &mut self.signer
    }

    /// Consume the workflow and return the underlying signer.
    pub fn into_signer(self) -> S {
        self.signer
    }

    /// Sign a PCZT using the hardware wallet.
    ///
    /// The input `pczt_bytes` must be a serialized PCZT that has been created
    /// from a proposal (via `create_pczt_from_proposal`). The PCZT must contain
    /// Orchard actions — Sapling-only transactions are not yet supported.
    ///
    /// Returns a [`SigningResult`] containing the fully signed PCZT bytes
    /// and metadata about the signing process.
    pub fn sign(&mut self, pczt_bytes: Vec<u8>) -> Result<SigningResult> {
        self.sign_with_details(pczt_bytes, None)
    }

    /// Sign a PCZT with optional transaction details for device confirmation.
    ///
    /// If `details` is provided, the device's `confirm_transaction` method
    /// is called before signing begins. This allows the user to verify
    /// the transaction on the device screen.
    pub fn sign_with_details(
        &mut self,
        pczt_bytes: Vec<u8>,
        details: Option<TxDetails>,
    ) -> Result<SigningResult> {
        // Step 0: Defense-in-depth Orchard-only invariant check.
        //
        // The device enforces that sapling_digest equals the ZIP-244 empty-bundle
        // constant before signing (SIGNER_ERR_SAPLING_NOT_EMPTY). Reject locally
        // first so the user gets a clean error instead of round-tripping a PCZT
        // that the device will reject. Mirrors the on-device invariant: this
        // signer never produces a transaction with any Sapling component.
        {
            let pczt_for_check = pczt::Pczt::parse(&pczt_bytes)
                .map_err(|e| HwSignerError::SignerInitFailed(format!("PCZT parse: {:?}", e)))?;
            let sapling = pczt_for_check.sapling();
            let n_spends = sapling.spends().len();
            let n_outputs = sapling.outputs().len();
            if n_spends != 0 || n_outputs != 0 {
                return Err(HwSignerError::SaplingNotSupported {
                    spends: n_spends,
                    outputs: n_outputs,
                });
            }
        }

        // Step 1: Extract tx metadata for device verification
        // Extract TxMeta from the actual TransactionData (not from PCZT Global)
        // to ensure fields like lock_time match what zcash_primitives uses.
        let tx_meta = {
            use zcash_primitives::transaction::txid::TxIdDigester;

            let pczt_clone = pczt::Pczt::parse(&pczt_bytes).unwrap();
            let tx_data = pczt_clone.into_effects()
                .expect("PCZT effects extraction failed");
            let txid_parts = tx_data.digest(TxIdDigester);

            // transparent_sig_digest from txid parts
            let transparent_sig_digest = {
                let mut h = blake2b_simd::Params::new()
                    .hash_length(32).personal(b"ZTxIdTranspaHash").to_state();
                if let Some(ref td) = txid_parts.transparent_digests {
                    h.update(td.prevouts_digest.as_bytes());
                    h.update(td.sequence_digest.as_bytes());
                    h.update(td.outputs_digest.as_bytes());
                }
                <[u8; 32]>::try_from(h.finalize().as_bytes()).unwrap()
            };

            // sapling_digest
            let sapling_digest = match txid_parts.sapling_digest {
                Some(d) => <[u8; 32]>::try_from(d.as_bytes()).unwrap(),
                None => {
                    let h = blake2b_simd::Params::new()
                        .hash_length(32).personal(b"ZTxIdSaplingHash")
                        .to_state().finalize();
                    <[u8; 32]>::try_from(h.as_bytes()).unwrap()
                }
            };

            debug!("header_digest: {}", hex::encode(txid_parts.header_digest.as_bytes()));
            debug!("transparent_sig_digest: {}", hex::encode(transparent_sig_digest));
            debug!("sapling_digest: {}", hex::encode(sapling_digest));
            if let Some(ref od) = txid_parts.orchard_digest {
                debug!("orchard_digest: {}", hex::encode(od.as_bytes()));
            }

            // Build TxMeta from TransactionData fields
            let orchard = pczt::Pczt::parse(&pczt_bytes).unwrap();
            let orchard_bundle = orchard.orchard();
            let (magnitude, is_negative) = orchard_bundle.value_sum();
            let value_balance = if *is_negative {
                -(*magnitude as i64)
            } else {
                *magnitude as i64
            };

            TxMeta {
                version: tx_data.version().header(),
                version_group_id: tx_data.version().version_group_id(),
                consensus_branch_id: u32::from(tx_data.consensus_branch_id()),
                lock_time: tx_data.lock_time(),
                expiry_height: u32::from(tx_data.expiry_height()),
                orchard_flags: *orchard_bundle.flags(),
                value_balance,
                anchor: *orchard_bundle.anchor(),
                transparent_sig_digest,
                sapling_digest,
                coin_type: self.signer.coin_type(),
            }
        };

        // Validate consensus_branch_id is Orchard-capable (Nu5+) BEFORE expensive proof generation
        let branch_id = BranchId::try_from(tx_meta.consensus_branch_id).map_err(|_| {
            HwSignerError::NetworkMismatch {
                expected: self.signer.coin_type(),
                got: tx_meta.consensus_branch_id,
            }
        })?;
        match branch_id {
            BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 => {}
            _ => {
                return Err(HwSignerError::NetworkMismatch {
                    expected: self.signer.coin_type(),
                    got: tx_meta.consensus_branch_id,
                });
            }
        }

        info!("PCZT parsed (v{}, branch_id=0x{:08x}, {:?}, lock_time={}).",
              tx_meta.version, tx_meta.consensus_branch_id, tx_meta.coin_type, tx_meta.lock_time);

        info!("Running Orchard prover...");

        // Step 2: Generate Orchard proof (Halo2)
        let pczt_for_prover = pczt::Pczt::parse(&pczt_bytes)
            .map_err(|e| HwSignerError::SignerInitFailed(format!("PCZT reparse: {:?}", e)))?;
        let prover = pczt::roles::prover::Prover::new(pczt_for_prover);
        let orchard_pk = orchard::circuit::ProvingKey::build();
        let proven = prover
            .create_orchard_proof(&orchard_pk)
            .map_err(|e| HwSignerError::ProofFailed(format!("{:?}", e)))?;
        let proven_pczt = proven.finish();

        info!("Orchard proof generated. Initializing signer...");

        // Step 3: Initialize Signer role and extract sighash
        let mut signer_role = pczt::roles::signer::Signer::new(proven_pczt)
            .map_err(|e| HwSignerError::SignerInitFailed(format!("{:?}", e)))?;

        let mut sighash = signer_role.shielded_sighash();
        info!("Sighash: {}...", hex::encode(&sighash[..8]));

        // Step 4: Read action data from the Orchard bundle via the Signer.
        // The upstream pczt Signer exposes the orchard bundle through
        // sign_orchard / apply_orchard_signature. We read action data
        // from the Pczt directly (before it was consumed by the Signer).
        let pre_pczt = pczt::Pczt::parse(&pczt_bytes)
            .map_err(|e| HwSignerError::SignerInitFailed(format!("PCZT reparse: {:?}", e)))?;

        // Use low_level_signer to access the parsed orchard::pczt::Bundle
        // for reading alpha, rk, and action data through public getters.
        let mut actions_to_sign: Vec<(usize, [u8; 32])> = Vec::new();
        let mut all_actions_data: Vec<ActionData> = Vec::new();
        let mut rk_values: Vec<[u8; 32]> = Vec::new();

        let temp_signer = pczt::roles::low_level_signer::Signer::new(pre_pczt);
        let _ = temp_signer
            .sign_orchard_with(|_pczt, bundle, _tx_modifiable| -> std::result::Result<(), HwSignerError> {
                for (i, action) in bundle.actions().iter().enumerate() {
                    let spend = action.spend();
                    rk_values.push(<[u8; 32]>::from(spend.rk().clone()));

                    if let (Some(alpha), None) = (spend.alpha(), spend.spend_auth_sig()) {
                        actions_to_sign.push((i, alpha.to_repr()));
                    }

                    let enc_note = action.output().encrypted_note();
                    all_actions_data.push(ActionData {
                        cv_net: action.cv_net().to_bytes(),
                        nullifier: action.spend().nullifier().to_bytes(),
                        rk: <[u8; 32]>::from(action.spend().rk().clone()),
                        cmx: action.output().cmx().to_bytes(),
                        ephemeral_key: enc_note.epk_bytes,
                        enc_ciphertext: enc_note.enc_ciphertext.to_vec(),
                        out_ciphertext: enc_note.out_ciphertext.to_vec(),
                    });
                }
                Ok(())
            })
            .map_err(|e: HwSignerError| e)?;

        if actions_to_sign.is_empty() {
            return Err(HwSignerError::NoActionsToSign);
        }

        info!(
            "{} total actions, {} need hardware signing",
            all_actions_data.len(),
            actions_to_sign.len()
        );

        // Step 5: Send action data to device for on-device sighash verification (v2)
        self.signer.verify_sighash(&tx_meta, &all_actions_data, &sighash)?;

        // Step 6: Request user confirmation on device (if details provided)
        if let Some(ref details) = details {
            let confirmed = self.signer.confirm_transaction(details)?;
            if !confirmed {
                return Err(HwSignerError::UserCancelled);
            }
        }

        // Step 7: Sign each action via hardware wallet and apply signatures
        let total_to_sign = actions_to_sign.len();
        let mut actions_signed = 0usize;

        let (amount, fee, recipient) = match &details {
            Some(d) => (d.send_amount, d.fee, d.recipient.clone()),
            None => (0, 0, String::new()),
        };

        for (sign_idx, (action_idx, alpha_bytes)) in actions_to_sign.iter().enumerate() {
            let request = SignRequest {
                sighash,
                alpha: *alpha_bytes,
                amount,
                fee,
                recipient: recipient.clone(),
                action_index: sign_idx,
                total_actions: total_to_sign,
            };

            let response = self.signer.sign_action(&request)?;

            // Verify rk and signature
            let pczt_rk = rk_values[*action_idx];
            verify::verify_signature(&response, &sighash, &pczt_rk, *action_idx)?;

            // Apply the signature to the PCZT via the upstream Signer API
            let sig = orchard::primitives::redpallas::Signature::<orchard::primitives::redpallas::SpendAuth>::from(response.signature);
            signer_role
                .apply_orchard_signature(*action_idx, sig)
                .map_err(|e| HwSignerError::SignerInitFailed(format!(
                    "Failed to apply signature for action {}: {:?}", action_idx, e
                )))?;

            debug!("action[{}]: signed and verified OK", action_idx);
            actions_signed += 1;
        }

        // Step 8: Transparent signing (if transparent inputs present)
        let mut transparent_inputs_signed = 0usize;
        {
            let t_pczt = pczt::Pczt::parse(&pczt_bytes)
                .map_err(|e| HwSignerError::SignerInitFailed(format!("PCZT reparse for transparent: {:?}", e)))?;
            let t_inputs = t_pczt.transparent().inputs();
            let t_outputs = t_pczt.transparent().outputs();

            if !t_inputs.is_empty() {
                info!("{} transparent input(s), {} output(s) — starting transparent flow",
                      t_inputs.len(), t_outputs.len());

                // 8a. Extract transparent input/output data for on-device digest verification
                let input_data: Vec<TransparentInputData> = t_inputs.iter().map(|inp| {
                    TransparentInputData {
                        prevout_hash: *inp.prevout_txid(),
                        prevout_index: *inp.prevout_index(),
                        sequence: inp.sequence().unwrap_or(0xFFFFFFFF),
                        value: *inp.value(),
                        script_pubkey: inp.script_pubkey().clone(),
                    }
                }).collect();

                let output_data: Vec<TransparentOutputData> = t_outputs.iter().map(|out| {
                    TransparentOutputData {
                        value: *out.value(),
                        script_pubkey: out.script_pubkey().clone(),
                    }
                }).collect();

                // 8b. Send to device for on-device transparent digest verification (v3)
                self.signer.verify_transparent_digest(
                    &input_data,
                    &output_data,
                    &tx_meta.transparent_sig_digest,
                )?;

                // 8c. Sign each transparent input that needs a hardware signature
                for i in 0..t_inputs.len() {
                    // Get the per-input sighash from the pczt signer
                    let t_sighash = signer_role.transparent_sighash(i)
                        .map_err(|e| HwSignerError::SignerInitFailed(format!(
                            "transparent_sighash({}) failed: {:?}", i, e
                        )))?;

                    let request = TransparentSignRequest {
                        sighash: t_sighash,
                        input_index: i,
                        total_inputs: t_inputs.len(),
                        value: *t_inputs[i].value(),
                        script_pubkey: t_inputs[i].script_pubkey().clone(),
                    };

                    let response = self.signer.sign_transparent_input(&request, &input_data[i])?;

                    // Parse the ECDSA signature and inject into PCZT
                    let ecdsa_sig = secp256k1::ecdsa::Signature::from_der(&response.signature[..response.signature.len().saturating_sub(1)])
                        .map_err(|e| HwSignerError::TransparentSignatureVerificationFailed {
                            input_idx: i,
                            reason: format!("Invalid DER signature: {}", e),
                        })?;

                    signer_role
                        .append_transparent_signature(i, ecdsa_sig)
                        .map_err(|e| HwSignerError::SignerInitFailed(format!(
                            "Failed to apply transparent signature for input {}: {:?}", i, e
                        )))?;

                    debug!("transparent input[{}]: signed and applied OK", i);
                    transparent_inputs_signed += 1;
                }

                info!("{} transparent input(s) signed by hardware", transparent_inputs_signed);
            }
        }

        // Step 9: Finalize and return signed PCZT
        sighash.zeroize();

        let signed_pczt = signer_role.finish();
        let signed_bytes = signed_pczt.serialize();

        info!("PCZT signed ({} orchard action(s) + {} transparent input(s) signed by hardware)",
              actions_signed, transparent_inputs_signed);

        Ok(SigningResult {
            signed_pczt: signed_bytes,
            actions_signed,
            transparent_inputs_signed,
        })
    }
}
