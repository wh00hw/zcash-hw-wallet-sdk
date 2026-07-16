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
    ActionData, ShieldedPoolKind, SignRequest, SigningResult, TransparentInputData,
    TransparentOutputData, TransparentSignRequest, TxDetails, TxMeta,
};
use crate::verify;

use ff::PrimeField;
use tracing::{debug, info};
use zcash_protocol::consensus::{BranchId, OrchardProtocolRevision};
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
            let shielded = pczt::Pczt::parse(&pczt_bytes).unwrap();
            let orchard_bundle = shielded.orchard();
            let ironwood_bundle = shielded.ironwood();
            let signed_value_sum = |vs: &(u64, bool)| -> i64 {
                let (magnitude, is_negative) = vs;
                if *is_negative {
                    -(*magnitude as i64)
                } else {
                    *magnitude as i64
                }
            };

            TxMeta {
                version: tx_data.version().header(),
                version_group_id: tx_data.version().version_group_id(),
                consensus_branch_id: u32::from(tx_data.consensus_branch_id()),
                lock_time: tx_data.lock_time(),
                expiry_height: u32::from(tx_data.expiry_height()),
                orchard_flags: *orchard_bundle.flags(),
                value_balance: signed_value_sum(orchard_bundle.value_sum()),
                // librustzcash 292e7584: PCZT anchors are deferred (Option).
                // At signing time the bundle being signed has a populated
                // anchor; an absent one for a non-empty bundle is a malformed
                // PCZT. Empty bundles legitimately carry no anchor.
                anchor: (*orchard_bundle.anchor()).unwrap_or([0u8; 32]),
                ironwood_flags: *ironwood_bundle.flags(),
                ironwood_value_balance: signed_value_sum(ironwood_bundle.value_sum()),
                ironwood_anchor: (*ironwood_bundle.anchor()).unwrap_or([0u8; 32]),
                transparent_sig_digest,
                sapling_digest,
                coin_type: self.signer.coin_type(),
            }
        };

        // Validate consensus_branch_id is Orchard-protocol-capable (Nu5+)
        // BEFORE expensive proof generation. The Orchard protocol revision
        // also selects the Halo2 circuit version(s) used by the prover below.
        let branch_id = BranchId::try_from(tx_meta.consensus_branch_id).map_err(|_| {
            HwSignerError::NetworkMismatch {
                expected: self.signer.coin_type(),
                got: tx_meta.consensus_branch_id,
            }
        })?;
        let orchard_revision = branch_id.orchard_protocol_revision().ok_or({
            HwSignerError::NetworkMismatch {
                expected: self.signer.coin_type(),
                got: tx_meta.consensus_branch_id,
            }
        })?;
        // The Ironwood pool (v6 transactions) only exists from NU6.3 onward.
        if tx_meta.is_v6() && orchard_revision < OrchardProtocolRevision::V3 {
            return Err(HwSignerError::UnsupportedPool(
                "v6 transaction with a pre-NU6.3 consensus branch ID",
            ));
        }

        info!("PCZT parsed (v{}, branch_id=0x{:08x}, {:?}, lock_time={}).",
              tx_meta.version, tx_meta.consensus_branch_id, tx_meta.coin_type, tx_meta.lock_time);

        info!("Running Orchard-protocol prover...");

        // Step 2: Generate the Halo2 proof(s). The circuit version follows
        // the Orchard protocol revision in force under the tx's consensus
        // branch: pre-NU6.2 bundles use the historical circuit, NU6.2 the
        // fixed circuit, and NU6.3 (both the sealed Orchard pool and the
        // Ironwood pool) the circuit that enforces the cross-address
        // restriction public input.
        use orchard::circuit::OrchardCircuitVersion;
        let orchard_circuit_version = match orchard_revision {
            OrchardProtocolRevision::InsecureV1 => OrchardCircuitVersion::InsecurePreNu6_2,
            OrchardProtocolRevision::V2 => OrchardCircuitVersion::FixedPostNu6_2,
            _ => OrchardCircuitVersion::PostNu6_3,
        };

        let pczt_for_prover = pczt::Pczt::parse(&pczt_bytes)
            .map_err(|e| HwSignerError::SignerInitFailed(format!("PCZT reparse: {:?}", e)))?;
        let mut prover = pczt::roles::prover::Prover::new(pczt_for_prover);
        let need_orchard_proof = prover.requires_orchard_proof();
        let need_ironwood_proof = prover.requires_ironwood_proof();
        let mut ironwood_proven = false;
        if need_orchard_proof {
            let orchard_pk = orchard::circuit::ProvingKey::build(orchard_circuit_version);
            prover = prover
                .create_orchard_proof(&orchard_pk)
                .map_err(|e| HwSignerError::ProofFailed(format!("{:?}", e)))?;
            // Key building is expensive; when the sealed-Orchard bundle already
            // uses the post-NU6.3 circuit (migration transactions), reuse its
            // proving key for the Ironwood bundle.
            if need_ironwood_proof
                && matches!(orchard_circuit_version, OrchardCircuitVersion::PostNu6_3)
            {
                prover = prover
                    .create_ironwood_proof(&orchard_pk)
                    .map_err(|e| HwSignerError::ProofFailed(format!("{:?}", e)))?;
                ironwood_proven = true;
            }
        }
        if need_ironwood_proof && !ironwood_proven {
            let ironwood_pk =
                orchard::circuit::ProvingKey::build(OrchardCircuitVersion::PostNu6_3);
            prover = prover
                .create_ironwood_proof(&ironwood_pk)
                .map_err(|e| HwSignerError::ProofFailed(format!("{:?}", e)))?;
        }
        let proven_pczt = prover.finish();

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

        // Fetch the device's Orchard OVK for memo recovery. We use the
        // sender's OutgoingViewingKey to trial-decrypt out_ciphertext on
        // each action, which recovers the unencrypted note plaintext
        // (including memo) that we then forward to the device so it can
        // verify enc_ciphertext byte-for-byte. If the device cannot supply
        // an FVK we proceed without — the workflow falls back to v4
        // cmx-only verification for actions whose memo we can't recover.
        let ovk_for_recovery: Option<orchard::keys::OutgoingViewingKey> =
            match self.signer.export_fvk() {
                Ok(fvk) => fvk
                    .to_orchard_fvk()
                    .map(|f| f.to_ovk(orchard::keys::Scope::External)),
                Err(_) => None,
            };

        // Use low_level_signer to access the parsed orchard::pczt::Bundle(s)
        // for reading alpha, rk, and action data through public getters. Under
        // NU6.3 a transaction may carry actions in BOTH the sealed Orchard
        // pool (turnstile withdrawals) and the Ironwood pool; each bundle is
        // collected with its pool tag so the device hashes it into the right
        // ZIP-244 digest tree.
        let mut actions_to_sign: Vec<(ShieldedPoolKind, usize, [u8; 32])> = Vec::new();
        let mut all_actions_data: Vec<ActionData> = Vec::new();
        let mut orchard_rk_values: Vec<[u8; 32]> = Vec::new();
        let mut ironwood_rk_values: Vec<[u8; 32]> = Vec::new();

        // Re-parse the PCZT once more for raw access to the per-action output
        // fields (recipient / value / rseed) that the device needs to recompute
        // the NoteCommitment. low_level_signer hands us the *typed* orchard
        // bundle (via the `orchard` crate), which exposes nullifier/rk/cmx but
        // not the unencrypted output note plaintext; that lives on the PCZT
        // structure itself.
        let pczt_for_outputs = pczt::Pczt::parse(&pczt_bytes)
            .map_err(|e| HwSignerError::SignerInitFailed(format!("PCZT reparse: {:?}", e)))?;
        let orchard_pczt_actions = pczt_for_outputs.orchard().actions().clone();
        let ironwood_pczt_actions = pczt_for_outputs.ironwood().actions().clone();

        /// Collect signing inputs and device-verification data for every
        /// action of one Orchard-protocol bundle (sealed Orchard or Ironwood).
        ///
        /// The companion *must* know recipient/value/rseed — without them the
        /// device cannot verify cmx and we'd be back to the
        /// recipient-substitution attack the v4 protocol fixes. Bail early
        /// with a clear error if the PCZT has been redacted by an Updater
        /// that stripped these fields.
        fn collect_pool_actions(
            pool: ShieldedPoolKind,
            bundle: &orchard::pczt::Bundle,
            pczt_actions: &[pczt::orchard::Action],
            ovk_for_recovery: Option<&orchard::keys::OutgoingViewingKey>,
            actions_to_sign: &mut Vec<(ShieldedPoolKind, usize, [u8; 32])>,
            all_actions_data: &mut Vec<ActionData>,
            rk_values: &mut Vec<[u8; 32]>,
        ) -> std::result::Result<(), HwSignerError> {
            for (i, action) in bundle.actions().iter().enumerate() {
                let spend = action.spend();
                rk_values.push(<[u8; 32]>::from(spend.rk().clone()));

                if let (Some(alpha), None) = (spend.alpha(), spend.spend_auth_sig()) {
                    actions_to_sign.push((pool, i, alpha.to_repr()));
                }

                let pczt_output = pczt_actions
                    .get(i)
                    .ok_or_else(|| HwSignerError::SignerInitFailed(
                        format!("PCZT {:?} action {} missing", pool, i),
                    ))?
                    .output();
                let recipient: [u8; 43] = *pczt_output.recipient().as_ref().ok_or_else(|| {
                    HwSignerError::SignerInitFailed(format!(
                        "PCZT {:?} output {}: missing recipient (required for on-device cmx verification)",
                        pool, i
                    ))
                })?;
                let value: u64 = *pczt_output.value().as_ref().ok_or_else(|| {
                    HwSignerError::SignerInitFailed(format!(
                        "PCZT {:?} output {}: missing value (required for on-device cmx verification)",
                        pool, i
                    ))
                })?;
                let rseed: [u8; 32] = *pczt_output.rseed().as_ref().ok_or_else(|| {
                    HwSignerError::SignerInitFailed(format!(
                        "PCZT {:?} output {}: missing rseed (required for on-device cmx verification)",
                        pool, i
                    ))
                })?;

                let enc_note = action.output().encrypted_note();

                // Recover the 512-byte memo plaintext by trial-decrypting
                // out_ciphertext with the sender's OVK, then trial-
                // decrypting enc_ciphertext with the recovered (esk,
                // pk_d). Sent to the device alongside the action so it
                // can recompute enc_ciphertext on-chip and reject any
                // memo substitution (the cmx defence binds value/recipient
                // but is silent about memo bytes).
                //
                // The note-encryption domain is pool-versioned: Orchard
                // notes are ZIP-212 V2 plaintexts, Ironwood notes are
                // ZIP-2005 V3 plaintexts (lead byte 0x03).
                //
                // For outputs constructed with OVK::None — explicitly
                // unrecoverable by the sender — we leave memo as None
                // and fall back to cmx-only verification for that
                // action. esk is not transmitted: it is a function of
                // (rseed, rho) and the device re-derives it on-chip.
                let memo: Option<[u8; 512]> = ovk_for_recovery.and_then(|ovk| {
                    use ::zcash_note_encryption::try_output_recovery_with_ovk;
                    use orchard::note_encryption::{IronwoodDomain, OrchardDomain};
                    match pool {
                        ShieldedPoolKind::Orchard => {
                            let domain = OrchardDomain::for_pczt_action(action);
                            try_output_recovery_with_ovk(
                                &domain,
                                ovk,
                                action,
                                action.cv_net(),
                                &enc_note.out_ciphertext,
                            )
                            .map(|(_note, _addr, memo)| memo)
                        }
                        ShieldedPoolKind::Ironwood => {
                            let domain = IronwoodDomain::for_pczt_action(action);
                            try_output_recovery_with_ovk(
                                &domain,
                                ovk,
                                action,
                                action.cv_net(),
                                &enc_note.out_ciphertext,
                            )
                            .map(|(_note, _addr, memo)| memo)
                        }
                    }
                });

                all_actions_data.push(ActionData {
                    pool,
                    cv_net: action.cv_net().to_bytes(),
                    nullifier: action.spend().nullifier().to_bytes(),
                    rk: <[u8; 32]>::from(action.spend().rk().clone()),
                    cmx: action.output().cmx().to_bytes(),
                    ephemeral_key: enc_note.epk_bytes,
                    enc_ciphertext: enc_note.enc_ciphertext.to_vec(),
                    out_ciphertext: enc_note.out_ciphertext.to_vec(),
                    recipient,
                    value,
                    rseed,
                    memo,
                    // esk is derived on-device from (rseed, rho); not
                    // transmitted over the wire.
                    esk: None,
                });
            }
            Ok(())
        }

        let temp_signer = pczt::roles::low_level_signer::Signer::new(pre_pczt);
        let temp_signer = temp_signer
            .sign_orchard_with(|_pczt, bundle, _tx_modifiable| -> std::result::Result<(), HwSignerError> {
                collect_pool_actions(
                    ShieldedPoolKind::Orchard,
                    bundle,
                    &orchard_pczt_actions,
                    ovk_for_recovery.as_ref(),
                    &mut actions_to_sign,
                    &mut all_actions_data,
                    &mut orchard_rk_values,
                )
            })?;
        let _ = temp_signer
            .sign_ironwood_with(|_pczt, bundle, _tx_modifiable| -> std::result::Result<(), HwSignerError> {
                collect_pool_actions(
                    ShieldedPoolKind::Ironwood,
                    bundle,
                    &ironwood_pczt_actions,
                    ovk_for_recovery.as_ref(),
                    &mut actions_to_sign,
                    &mut all_actions_data,
                    &mut ironwood_rk_values,
                )
            })?;

        if actions_to_sign.is_empty() {
            return Err(HwSignerError::NoActionsToSign);
        }

        info!(
            "{} total actions, {} need hardware signing",
            all_actions_data.len(),
            actions_to_sign.len()
        );

        // Step 5: Collect transparent inputs/outputs up-front so we can hand
        // the FULL tx (meta + transparent + Orchard + sighash sentinel) to the
        // device in a single, correctly-ordered verification pass.
        //
        // The device's signer state machine refuses to accept the transparent
        // stream after the shielded sighash sentinel has flipped it to
        // VERIFIED, and conversely refuses to advance to VERIFIED if
        // `transparent_sig_digest` is non-empty and the transparent flow was
        // skipped. So both pieces have to be sent in one ordered batch — see
        // `HardwareSigner::verify_transaction` for the wire-order contract.
        let (t_inputs, t_outputs) = {
            let t_pczt = pczt::Pczt::parse(&pczt_bytes).map_err(|e| {
                HwSignerError::SignerInitFailed(format!(
                    "PCZT reparse for transparent: {:?}",
                    e
                ))
            })?;
            let inputs: Vec<TransparentInputData> = t_pczt
                .transparent()
                .inputs()
                .iter()
                .map(|inp| TransparentInputData {
                    prevout_hash: *inp.prevout_txid(),
                    prevout_index: *inp.prevout_index(),
                    sequence: inp.sequence().unwrap_or(0xFFFFFFFF),
                    value: *inp.value(),
                    script_pubkey: inp.script_pubkey().clone(),
                })
                .collect();
            let outputs: Vec<TransparentOutputData> = t_pczt
                .transparent()
                .outputs()
                .iter()
                .map(|out| TransparentOutputData {
                    value: *out.value(),
                    script_pubkey: out.script_pubkey().clone(),
                })
                .collect();
            (inputs, outputs)
        };
        let has_transparent = !t_inputs.is_empty();
        if has_transparent {
            info!(
                "{} transparent input(s), {} output(s) — verification will include transparent digest",
                t_inputs.len(),
                t_outputs.len()
            );
        }

        // Step 5b: Send the full tx to the device for ZIP-244 verification
        // (meta → transparent flow if any → Orchard actions → sighash sentinel).
        self.signer
            .verify_transaction(&tx_meta, &all_actions_data, &sighash, &t_inputs, &t_outputs)?;

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

        for (sign_idx, (pool, action_idx, alpha_bytes)) in actions_to_sign.iter().enumerate() {
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

            // Verify rk and signature against the pool the action belongs to
            let pczt_rk = match pool {
                ShieldedPoolKind::Orchard => orchard_rk_values[*action_idx],
                ShieldedPoolKind::Ironwood => ironwood_rk_values[*action_idx],
            };
            verify::verify_signature(&response, &sighash, &pczt_rk, *action_idx)?;

            // Apply the signature to the PCZT via the upstream Signer API
            let sig = orchard::primitives::redpallas::Signature::<orchard::primitives::redpallas::SpendAuth>::from(response.signature);
            match pool {
                ShieldedPoolKind::Orchard => signer_role.apply_orchard_signature(*action_idx, sig),
                ShieldedPoolKind::Ironwood => {
                    signer_role.apply_ironwood_signature(*action_idx, sig)
                }
            }
            .map_err(|e| {
                HwSignerError::SignerInitFailed(format!(
                    "Failed to apply signature for {:?} action {}: {:?}",
                    pool, action_idx, e
                ))
            })?;

            debug!("{:?} action[{}]: signed and verified OK", pool, action_idx);
            actions_signed += 1;
        }

        // Step 8: Transparent signing — the device already verified the
        // transparent digest as part of step 5b's `verify_transaction` call,
        // so it is in VERIFIED state with `transparent_verified = true`. We
        // only have to drive the per-input ECDSA signing requests now.
        let mut transparent_inputs_signed = 0usize;
        if has_transparent {
            let t_pczt = pczt::Pczt::parse(&pczt_bytes).map_err(|e| {
                HwSignerError::SignerInitFailed(format!(
                    "PCZT reparse for transparent: {:?}",
                    e
                ))
            })?;
            let pczt_t_inputs = t_pczt.transparent().inputs();

            for (i, t_input_data) in t_inputs.iter().enumerate() {
                // Per-input sighash comes from the pczt signer (ZIP-244 S.2)
                let t_sighash = signer_role.transparent_sighash(i).map_err(|e| {
                    HwSignerError::SignerInitFailed(format!(
                        "transparent_sighash({}) failed: {:?}",
                        i, e
                    ))
                })?;

                let request = TransparentSignRequest {
                    sighash: t_sighash,
                    input_index: i,
                    total_inputs: pczt_t_inputs.len(),
                    value: *pczt_t_inputs[i].value(),
                    script_pubkey: pczt_t_inputs[i].script_pubkey().clone(),
                };

                let response = self.signer.sign_transparent_input(&request, t_input_data)?;

                // The DER signature carries a trailing sighash_type byte
                // (Bitcoin convention); strip it before parsing the
                // ECDSA structure for both verification and PCZT injection.
                let der_sig_bytes =
                    &response.signature[..response.signature.len().saturating_sub(1)];

                // Defence-in-depth host re-verification of the ECDSA
                // signature against the host-computed sighash and the
                // device-returned pubkey, plus a HASH160 cross-check tying
                // that pubkey to the input's P2PKH script_pubkey. Mirrors
                // the Orchard verify pattern; closes the gap where a buggy
                // or hostile device could return a valid-DER but
                // cryptographically wrong signature, or sign with the wrong
                // key. Audit: docs/security-audit/04-host-sdk-rust.md H2.
                crate::verify::verify_transparent_signature(
                    &t_sighash,
                    der_sig_bytes,
                    &response.pubkey,
                    &request.script_pubkey,
                    i,
                )?;

                let ecdsa_sig = secp256k1::ecdsa::Signature::from_der(der_sig_bytes).map_err(
                    |e| HwSignerError::TransparentSignatureVerificationFailed {
                        input_idx: i,
                        reason: format!("Invalid DER signature: {}", e),
                    },
                )?;

                signer_role
                    .append_transparent_signature(i, ecdsa_sig)
                    .map_err(|e| {
                        HwSignerError::SignerInitFailed(format!(
                            "Failed to apply transparent signature for input {}: {:?}",
                            i, e
                        ))
                    })?;

                debug!("transparent input[{}]: signed and applied OK", i);
                transparent_inputs_signed += 1;
            }

            info!(
                "{} transparent input(s) signed by hardware",
                transparent_inputs_signed
            );
        }

        // Step 9: Finalize and return signed PCZT
        sighash.zeroize();

        let signed_pczt = signer_role.finish();
        let signed_bytes = signed_pczt.serialize().map_err(|e| {
            HwSignerError::SignerInitFailed(format!("PCZT serialization failed: {:?}", e))
        })?;

        info!("PCZT signed ({} orchard action(s) + {} transparent input(s) signed by hardware)",
              actions_signed, transparent_inputs_signed);

        Ok(SigningResult {
            signed_pczt: signed_bytes,
            actions_signed,
            transparent_inputs_signed,
        })
    }
}
