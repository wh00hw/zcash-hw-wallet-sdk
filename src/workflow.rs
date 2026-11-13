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
    TransparentOutputData, TxDetails, TxMeta,
};
use crate::verify;

use ff::PrimeField;
use tracing::{debug, info};
use zcash_protocol::consensus::{BranchId, OrchardProtocolRevision};
use zeroize::Zeroize;

/// Consensus branch IDs this host signs for: NU6.3 (`0x37a5165b`) and NU7
/// (`0x77190ad9`).
///
/// This is an explicit allow-list rather than a "NU6.3 or later" comparison
/// on purpose. The device recomputes the ZIP-244 v6 five-leaf sighash
/// on-chip from the streamed transaction, with the branch ID only entering
/// the header digest and the root personalization. That is exactly the
/// transaction digest structure `zcash_primitives 0.31` uses for a v6
/// transaction under both of these branches (NU7 changed the block target
/// spacing and the default expiry delta, not the v6 format, the digest
/// personalizations or the Orchard protocol revision). A future upgrade that
/// touches any of those must be reviewed against the device firmware before
/// its branch ID is added here.
pub(crate) const SUPPORTED_BRANCH_IDS: [BranchId; 2] = [BranchId::Nu6_3, BranchId::Nu7];

/// The bare v6 transaction version number and version group ID, as carried
/// in the PCZT globals (the header word adds the overwintered bit).
const V6_TX_VERSION_NUMBER: u32 = 6;
const V6_VERSION_GROUP_ID: u32 = 0xD884_B698;

/// Branch check against an explicit allow-list.
///
/// * not a consensus branch ID at all, or a pre-Orchard one →
///   [`HwSignerError::NetworkMismatch`];
/// * an Orchard-era branch older than NU6.3 → [`HwSignerError::UnsupportedPool`];
/// * anything not in `supported` (e.g. a future branch) →
///   [`HwSignerError::UnsupportedPool`].
///
/// `supported` is a parameter so that the allow-list itself is testable;
/// production code passes [`SUPPORTED_BRANCH_IDS`].
pub(crate) fn check_branch(
    consensus_branch_id: u32,
    coin_type: u32,
    supported: &[BranchId],
) -> Result<BranchId> {
    let mismatch = HwSignerError::NetworkMismatch {
        expected: coin_type,
        got: consensus_branch_id,
    };
    let Ok(branch_id) = BranchId::try_from(consensus_branch_id) else {
        return Err(mismatch);
    };
    let Some(orchard_revision) = branch_id.orchard_protocol_revision() else {
        return Err(mismatch);
    };
    if orchard_revision < OrchardProtocolRevision::V3 {
        return Err(HwSignerError::UnsupportedPool(
            "pre-NU6.3 consensus branch ID: this v6-only host signs NU6.3 and NU7 transactions exclusively",
        ));
    }
    // Every supported branch must also select Orchard protocol revision V3
    // (the post-NU6.3 circuit the prover builds). A branch this SDK was not
    // reviewed against is refused rather than signed blind.
    if !supported.contains(&branch_id) || orchard_revision != OrchardProtocolRevision::V3 {
        return Err(HwSignerError::UnsupportedPool(
            "consensus branch ID is not one this host supports (NU6.3 and NU7 only)",
        ));
    }
    Ok(branch_id)
}

/// Pre-proof v6-only gate (NU6.3 / NU7 host) on the transaction header.
///
/// Rejects any transaction whose consensus branch ID is not NU6.3
/// (`0x37a5165b`) or NU7 (`0x77190ad9`), or whose version header is not v6
/// (`0x80000006`), before any expensive Halo2 work. The strict device
/// enforces the v6 header constants at `feed_meta` time — failing here saves
/// a device round-trip that would end in `Error(BAD_META)` — and binds the
/// branch ID through the sighash it recomputes.
///
/// `coin_type` is only used to populate the [`HwSignerError::NetworkMismatch`]
/// error for branch IDs that are not valid consensus branches at all.
pub(crate) fn ensure_v6_only(
    tx_version_header: u32,
    consensus_branch_id: u32,
    coin_type: u32,
) -> Result<()> {
    check_branch(consensus_branch_id, coin_type, &SUPPORTED_BRANCH_IDS)?;
    if tx_version_header != crate::types::V6_TX_VERSION {
        return Err(HwSignerError::UnsupportedPool(
            "transaction version is not v6: this v6-only host emits only the v6 (NU6.3 / NU7) wire tier",
        ));
    }
    Ok(())
}

/// The same gate, applied to the raw PCZT globals *before* the transaction
/// effects are extracted. `Pczt::into_effects` itself fails on an unknown
/// branch ID or a branch/version pair that does not exist, so this is what
/// turns a foreign PCZT into the specific typed error instead of a generic
/// extraction failure.
pub(crate) fn ensure_v6_globals(
    tx_version: u32,
    version_group_id: u32,
    consensus_branch_id: u32,
    coin_type: u32,
) -> Result<()> {
    check_branch(consensus_branch_id, coin_type, &SUPPORTED_BRANCH_IDS)?;
    if tx_version != V6_TX_VERSION_NUMBER || version_group_id != V6_VERSION_GROUP_ID {
        return Err(HwSignerError::UnsupportedPool(
            "transaction version is not v6: this v6-only host emits only the v6 (NU6.3 / NU7) wire tier",
        ));
    }
    Ok(())
}

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

    /// Sign a PCZT, with optional transaction details.
    ///
    /// If `details` is provided, the signer's `confirm_transaction` hook is
    /// called before signing begins, and the details are copied into
    /// `SIGN_REQ`. They are NOT what the user approves on an HWP device:
    /// the device ignores the recipient, amount and fee of `SIGN_REQ` and
    /// shows only what it verified and computed itself (each output with
    /// the ownership it decided, the totals). `sign(pczt)` — no details,
    /// empty recipient — is therefore equivalent as far as the device is
    /// concerned.
    pub fn sign_with_details(
        &mut self,
        pczt_bytes: Vec<u8>,
        details: Option<TxDetails>,
    ) -> Result<SigningResult> {
        // Step 0: Parse the PCZT once. Everything below works on this value;
        // nothing in the signing path unwraps caller-supplied data.
        let pczt = pczt::Pczt::parse(&pczt_bytes)
            .map_err(|e| HwSignerError::InvalidPczt(format!("parse: {:?}", e)))?;
        let coin_type = self.signer.coin_type();

        // Defense-in-depth Orchard-only invariant check.
        //
        // The device enforces that sapling_digest equals the ZIP-244 empty-bundle
        // constant before signing (SIGNER_ERR_SAPLING_NOT_EMPTY). Reject locally
        // first so the user gets a clean error instead of round-tripping a PCZT
        // that the device will reject.
        {
            let sapling = pczt.sapling();
            let n_spends = sapling.spends().len();
            let n_outputs = sapling.outputs().len();
            if n_spends != 0 || n_outputs != 0 {
                return Err(HwSignerError::SaplingNotSupported {
                    spends: n_spends,
                    outputs: n_outputs,
                });
            }
        }

        // Transparent inputs are not supported: the device refuses them
        // (HWP 0x18) and this workflow has no transparent signing path.
        // Refuse here, with a typed error, before any proof work and before
        // anything is sent to the device. Transparent OUTPUTS (shielded ->
        // t-address) are supported.
        {
            let n_t_inputs = pczt.transparent().inputs().len();
            if n_t_inputs != 0 {
                return Err(HwSignerError::TransparentInputsNotSupported { inputs: n_t_inputs });
            }
        }

        // Step 1: v6 / branch gate on the PCZT globals, BEFORE the effects
        // are extracted and before any proof work: a PCZT for another
        // branch, another transaction version, or no known branch at all is
        // refused with its specific error here.
        {
            let global = pczt.global();
            ensure_v6_globals(
                *global.tx_version(),
                *global.version_group_id(),
                *global.consensus_branch_id(),
                coin_type,
            )?;
        }

        // Step 2: Derive the tx metadata the device verifies, from the
        // transaction effects (single source of truth: TxMeta::from_pczt),
        // and re-check the header actually derived.
        let tx_meta = TxMeta::from_pczt(&pczt, coin_type)?;
        ensure_v6_only(tx_meta.version, tx_meta.consensus_branch_id, coin_type)?;

        info!(
            "PCZT parsed (version=0x{:08x}, branch_id=0x{:08x}, coin_type={}, lock_time={}).",
            tx_meta.version, tx_meta.consensus_branch_id, tx_meta.coin_type, tx_meta.lock_time
        );

        // Step 3: Read action data from the PCZT (before proving: a PCZT the
        // host cannot fully describe to the device fails fast).
        //
        // The device accepts only the memo-carrying action body, for every
        // output including the builder's zero-value padding, so the host
        // needs the full note plaintext of every output. It is recovered
        // from the PCZT alone: `(recipient, value, rseed)` and the action's
        // nullifier (rho) determine the note and its ephemeral secret key,
        // which opens `enc_ciphertext` (no viewing key involved).

        // Use low_level_signer to access the parsed orchard::pczt::Bundle(s)
        // for reading alpha, rk, and action data through public getters. A
        // transaction may carry actions in BOTH the sealed Orchard pool
        // (turnstile withdrawals) and the Ironwood pool; each bundle is
        // collected with its pool tag so the device hashes it into the right
        // ZIP-244 digest tree.
        let mut actions_to_sign: Vec<(ShieldedPoolKind, usize, [u8; 32])> = Vec::new();
        let mut all_actions_data: Vec<ActionData> = Vec::new();
        let mut orchard_rk_values: Vec<[u8; 32]> = Vec::new();
        let mut ironwood_rk_values: Vec<[u8; 32]> = Vec::new();

        // The per-action output fields (recipient / value / rseed) that the
        // device needs to recompute the NoteCommitment live on the PCZT
        // structure itself, not on the typed orchard bundle.
        let orchard_pczt_actions = pczt.orchard().actions().clone();
        let ironwood_pczt_actions = pczt.ironwood().actions().clone();

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

                // Recover the 512-byte memo plaintext: rebuild the note from
                // the PCZT's (recipient, value, rseed) and the action's
                // nullifier (= rho), derive its ephemeral secret key
                // (a function of rseed and rho), and open enc_ciphertext
                // with (pk_d, esk). This works for every output the PCZT
                // describes truthfully — payments, the wallet's own change
                // and the builder's zero-value padding alike, whatever
                // outgoing viewing key (if any) the output was built with.
                //
                // The note-encryption domain is pool-versioned: Orchard
                // notes are ZIP-212 V2 plaintexts, Ironwood notes are
                // ZIP-2005 V3 plaintexts (lead byte 0x03). esk is not
                // transmitted: the device re-derives it the same way.
                let pool_name = match pool {
                    ShieldedPoolKind::Orchard => "Orchard",
                    ShieldedPoolKind::Ironwood => "Ironwood",
                };
                let not_recoverable = |reason: &str| HwSignerError::OutputNotRecoverable {
                    pool: pool_name,
                    action_idx: i,
                    value,
                    reason: reason.to_string(),
                };
                let memo: [u8; 512] = {
                    use ::zcash_note_encryption::{try_output_recovery_with_pkd_esk, Domain};
                    use orchard::note::{NoteVersion, RandomSeed, Rho};
                    use orchard::note_encryption::{IronwoodDomain, OrchardDomain};

                    let address = Option::<orchard::Address>::from(
                        orchard::Address::from_raw_address_bytes(&recipient),
                    )
                    .ok_or_else(|| not_recoverable("the PCZT recipient is not a valid Orchard address"))?;
                    let rho = Option::<Rho>::from(Rho::from_bytes(
                        &action.spend().nullifier().to_bytes(),
                    ))
                    .ok_or_else(|| not_recoverable("the action nullifier is not a valid rho"))?;
                    let random_seed =
                        Option::<RandomSeed>::from(RandomSeed::from_bytes(rseed, &rho))
                            .ok_or_else(|| not_recoverable("the PCZT rseed is not valid for this action"))?;
                    let version = match pool {
                        ShieldedPoolKind::Orchard => NoteVersion::V2,
                        ShieldedPoolKind::Ironwood => NoteVersion::V3,
                    };
                    let note = Option::<orchard::Note>::from(orchard::Note::from_parts(
                        address,
                        orchard::value::NoteValue::from_raw(value),
                        rho,
                        random_seed,
                        version,
                    ))
                    .ok_or_else(|| not_recoverable("the PCZT note fields do not form a valid note"))?;

                    let recovered = match pool {
                        ShieldedPoolKind::Orchard => OrchardDomain::derive_esk(&note)
                            .and_then(|esk| {
                                try_output_recovery_with_pkd_esk(
                                    &OrchardDomain::for_pczt_action(action),
                                    OrchardDomain::get_pk_d(&note),
                                    esk,
                                    action,
                                )
                            })
                            .map(|(_note, _addr, memo)| memo),
                        ShieldedPoolKind::Ironwood => IronwoodDomain::derive_esk(&note)
                            .and_then(|esk| {
                                try_output_recovery_with_pkd_esk(
                                    &IronwoodDomain::for_pczt_action(action),
                                    IronwoodDomain::get_pk_d(&note),
                                    esk,
                                    action,
                                )
                            })
                            .map(|(_note, _addr, memo)| memo),
                    };
                    match recovered {
                        Some(memo) => memo,
                        // One output cannot be opened by design: in the
                        // sealed Orchard pool (cross-address transfers
                        // disabled) the builder pairs each real spend with a
                        // zero-value output to the spent note's own
                        // receiver and, for an external-scope spend,
                        // replaces its enc_ciphertext with random bytes
                        // (orchard::builder, `fabricated_for_spend`). It
                        // still goes out with the full body, declaring the
                        // memo the builder used — 512 zero bytes. The DEVICE
                        // decides whether to tolerate it: only for a
                        // zero-value sealed-Orchard output to one of its own
                        // addresses, with the expected epk and no memo.
                        None if pool == ShieldedPoolKind::Orchard && value == 0 => [0u8; 512],
                        // Any other output that does not open — any value
                        // in Ironwood, any non-zero value — cannot be
                        // described to the device.
                        None => {
                            return Err(not_recoverable(
                                "enc_ciphertext does not decrypt with the note the PCZT describes \
                                 (recipient / value / rseed)",
                            ))
                        }
                    }
                };

                all_actions_data.push(ActionData {
                    pool,
                    cv_net: action.cv_net().to_bytes(),
                    nullifier: action.spend().nullifier().to_bytes(),
                    rk: <[u8; 32]>::from(action.spend().rk().clone()),
                    cmx: action.output().cmx().to_bytes(),
                    ephemeral_key: enc_note.epk_bytes,
                    enc_ciphertext: enc_note.enc_ciphertext.0.to_vec(),
                    out_ciphertext: enc_note.out_ciphertext.to_vec(),
                    recipient,
                    value,
                    rseed,
                    memo: Some(memo),
                });
            }
            Ok(())
        }

        let temp_signer = pczt::roles::low_level_signer::Signer::new(pczt.clone());
        let temp_signer = temp_signer
            .sign_orchard_with(|_pczt, bundle, _tx_modifiable| -> std::result::Result<(), HwSignerError> {
                collect_pool_actions(
                    ShieldedPoolKind::Orchard,
                    bundle,
                    &orchard_pczt_actions,
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

        // Step 4: Generate the Halo2 proof(s).
        info!("Running Orchard-protocol prover...");

        // v6-only: NU6.3 or NU7 is
        // guaranteed by the check above (both select Orchard protocol
        // revision V3), so both the sealed Orchard pool and the
        // Ironwood pool use the post-NU6.3 circuit (the one that enforces
        // the cross-address restriction public input) — one proving key
        // serves both bundles.
        use orchard::circuit::OrchardCircuitVersion;

        let mut prover = pczt::roles::prover::Prover::new(pczt.clone());
        let need_orchard_proof = prover.requires_orchard_proof();
        let need_ironwood_proof = prover.requires_ironwood_proof();
        if need_orchard_proof || need_ironwood_proof {
            let pk = orchard::circuit::ProvingKey::build(OrchardCircuitVersion::PostNu6_3);
            // pczt 0.10: the Prover role no longer draws OS randomness
            // itself; hand it the platform CSPRNG (the previous behaviour).
            let mut rng = rand_core::UnwrapErr(rand::rngs::SysRng);
            if need_orchard_proof {
                prover = prover
                    .create_orchard_proof(&mut rng, &pk)
                    .map_err(|e| HwSignerError::ProofFailed(format!("{:?}", e)))?;
            }
            if need_ironwood_proof {
                prover = prover
                    .create_ironwood_proof(&mut rng, &pk)
                    .map_err(|e| HwSignerError::ProofFailed(format!("{:?}", e)))?;
            }
        }
        let proven_pczt = prover.finish();

        info!("Orchard proof generated. Initializing signer...");

        // Step 5: Initialize Signer role and extract sighash
        let mut signer_role = pczt::roles::signer::Signer::new(proven_pczt)
            .map_err(|e| HwSignerError::SignerInitFailed(format!("{:?}", e)))?;

        let mut sighash = signer_role.shielded_sighash();
        info!("Sighash: {}...", hex::encode(&sighash[..8]));


        // Step 6: Collect the transparent outputs (a shielded -> t-address
        // send) so the device can recompute the transparent digest and show
        // each one. There are no transparent inputs (refused above).
        let t_inputs: Vec<TransparentInputData> = Vec::new();
        let t_outputs: Vec<TransparentOutputData> = pczt
            .transparent()
            .outputs()
            .iter()
            .map(|out| TransparentOutputData {
                value: *out.value(),
                script_pubkey: out.script_pubkey().clone(),
            })
            .collect();
        if !t_outputs.is_empty() {
            info!(
                "{} transparent output(s) — verification will include the transparent digest",
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
                ShieldedPoolKind::Orchard => orchard_rk_values.get(*action_idx),
                ShieldedPoolKind::Ironwood => ironwood_rk_values.get(*action_idx),
            }
            .copied()
            .ok_or_else(|| {
                HwSignerError::InvalidPczt(format!("{:?} action {} has no rk", pool, action_idx))
            })?;
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

        // (No transparent signing step: PCZTs with transparent inputs are
        // refused at the top of this function.)
        let transparent_inputs_signed = 0usize;

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
