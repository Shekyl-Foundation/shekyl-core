// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! AssembleEmissionClaim message handler.

use kameo::message::{Context, Message};

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::Scalar;
use rand_core::RngCore as _;
use shekyl_archival_retention::id::p_canonical_id_from_hybrid_pubkey;
use shekyl_archival_retention::{
    emission_vin_verify_auth, emission_vin_verify_backing, ArchivalRewardEmissionVin,
    MembershipOnlyBacking, RewardCommit,
};
use shekyl_bulletproofs::Bulletproof;
use shekyl_crypto_pq::derivation::hash_pqc_public_key;
use shekyl_crypto_pq::multisig::SINGLE_SIG_CANONICAL_LEN;
use shekyl_crypto_pq::output::sign_pqc_auth_for_output;
use shekyl_crypto_pq::signature::{HybridEd25519MlDsa, SignatureScheme as _};
use shekyl_scanner::extra::Extra;
use shekyl_tx_builder::{
    phase1_payload_hashes, prove_backing_membership, sign_pqc_auths, sign_transaction_with_terms,
    tx_prefix_hash_from_parts_with_extra, InputTerm, PqcAuth, TreeContext, WireEncodeInput,
};
use shekyl_types::GlobalOutputIndex;
use shekyl_units::AtomicUnits;
use shekyl_wire::Input;
use zeroize::Zeroizing;

use crate::engine::backing_set::ClaimOperands;
use crate::engine::bond_assembly::{finalize_bond_tx, BondAssemblyError, PBoundBytes};
use crate::engine::emission_claim::{
    assemble_claims, derive_claimable_epochs, self_check_claims, EmissionClaimError,
    EMISSION_CLAIMS_SIZE_BUDGET,
};

use super::actor::StakeEngine;
use super::helpers::{
    construct_vouts_to_base, derive_spend_parts, prepare_funding_inputs, ConstructedVouts,
};
use super::types::*;

// ---------------------------------------------------------------------------
// PR-3 commit 4 — AssembleEmissionClaim: the emission-claim assembly message
// ---------------------------------------------------------------------------

/// Assemble the **full, broadcast-ready** emission-claim transaction inside
/// the actor (`REWARD_EMISSION_VIN_PLAN.md` §8.0.2/§8.0.3, PR-3 commit 4) —
/// the emission sibling of [`AssembleBond`].
///
/// No [`PersistedBondTicket`](crate::engine::stake_persist::PersistedBondTicket) and
/// no entry-seam plan: the claim consumes no funding-entry seam (the bond is
/// already on-chain), and claim-broadcast timing is the GF-4 dispatch seam,
/// deliberately outside this builder (same return-bytes-only posture as the
/// bond path).
///
/// Assembly order is forced by the F-C1c hash structure (verified at
/// `blockchain.cpp:3857-3868`): fee inputs + vouts + extra → **signable
/// hash** over the vin-less prefix → membership proof + dual auths complete
/// the vin → **full prefix hash** → fee-side proof → tx PQC auths. The
/// emission vin cannot be covered by the hash its own proof and auths sign
/// over.
pub(crate) struct AssembleEmissionClaim {
    /// Operation-scoped capability proving the slot is currently held.
    pub handle: PersonaHandle,
    /// The sealed operand set — claim source, designated backing, swept fee
    /// inputs, membership paths — mintable only through
    /// [`DesignatedBacking::fee_sweep`](super::backing_set::DesignatedBacking::fee_sweep)
    /// → [`SweptFeeInputs::with_paths`](super::backing_set::SweptFeeInputs::with_paths),
    /// so possession is proof of same-tip (item 6) and Q11 backing/fee
    /// disjointness. The handler re-checks nothing (`backing_set.rs` module
    /// docs: the old step-2 runtime refusals are deleted, not relocated).
    pub operands: ClaimOperands,
    /// The curve-tree reference context all paths were assembled against.
    pub tree_ctx: TreeContext,
}

/// Reply of [`AssembleEmissionClaim`]: the persona-bound wire bytes (minted
/// at the single P-1 site, [`finalize_bond_tx`]), plus the public facts the
/// caller's reservation and dedup records need. Secrets never cross the
/// boundary.
// Staging (not tolerated dead code, `15-deletion-and-debt.mdc`): the receipt
// (`claim_dispatch::EmissionClaimReceipt`) embeds this reply whole, so the
// lib-target field readers arrive with the RPC stake entry (rule-21, the same
// retirement condition as the seam's allow); the orchestrator e2e KAT reads
// every field today.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct AssembledEmissionClaim {
    /// The fully-signed, wire-encoded emission-claim transaction.
    pub bound_tx: PBoundBytes,
    /// The spent **fee** funding records' gindexes — the reservation set.
    /// The backing's gindex is deliberately absent: the backing is proven
    /// (membership-only, no key image), not spent.
    pub fee_gindexes: Vec<GlobalOutputIndex>,
    /// The epochs this tx claims (the vin's `settlement_epochs`) — the
    /// caller's pending-dedup set.
    pub claimed_epochs: Vec<u64>,
    /// Epochs dropped by the size bound, deferred to the next claim tx.
    pub size_deferred: Vec<u64>,
    /// The loud mint this tx pays out (`Σ reward_amount_plain`).
    pub total_reward: u64,
}

impl Message<AssembleEmissionClaim> for StakeEngine {
    type Reply = Result<AssembledEmissionClaim, StakeEngineError>;

    async fn handle(
        &mut self,
        msg: AssembleEmissionClaim,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // ── Step 1: handle validation (no ticket, no entry-seam draw —
        // see the message doc). ─────────────────────────────────────────
        self.validate_handle(&msg.handle)?;
        let handle_slot = msg.handle.p_slot();

        // ── Step 2: unseal the operands. Consistency is the TYPE's, not
        // this handler's: `ClaimOperands` is mintable only through
        // `DesignatedBacking::fee_sweep` → `SweptFeeInputs::with_paths`
        // (backing_set.rs), so same-tip (item 6), Q11 backing/fee
        // disjointness, a non-empty fee set, and `fee_total >= fee` hold
        // by possession — the refusal arms that used to live here were
        // deleted with the seal, not relocated.
        let ops = msg.operands.into_parts();

        // ── Step 3: borrow the held bundle (never crosses the boundary).
        // CB-2: everything below signs with material derived from this
        // pre-derived bundle; the seed is not re-acquired anywhere.
        let keys = self
            .held
            .get(&handle_slot)
            .expect("validate_handle confirmed slot is held")
            .keys();

        // ── Step 4: derive + assemble the claims leg (single-evaluator:
        // rows and rewards ride the derivation; assembly never re-runs the
        // recompute it was admitted on).
        let claims = {
            let derived = derive_claimable_epochs(&ops.source)?;
            if !derived.skipped.is_empty() {
                // Local diagnostics only (CB-5: cause-blind toward the
                // daemon; nothing derived from these verdicts shapes
                // daemon-visible behavior).
                tracing::debug!(
                    skipped = ?derived.skipped,
                    "emission claim derivation: window epochs not selected"
                );
            }
            assemble_claims(&derived, EMISSION_CLAIMS_SIZE_BUDGET)?
        };
        let total_reward = claims.total_reward;

        // ── Step 5: fee arithmetic. The reward is fully consumed by the
        // loud vout (`vout_reward_sum == total_reward`, enforced by the
        // daemon's balance `Σ pseudoOuts + total_reward·H = Σ out_masks +
        // fee·H`), so the fee is funded by the sealed fee spends. The
        // structural refusals (empty selection, shortfall, sum overflow)
        // fired at the mint (`fee_sweep`); `fee_total` is the sweep's
        // exact checked sum and `fee_total >= fee` by its shortfall
        // refusal, so the change split is plain subtraction.
        let fee = ops.fee.to_raw();
        let change = ops.fee_total.to_raw() - fee;
        let change_lo = change / 2;
        let change_hi = change - change_lo;

        // ── Step 6: outputs. One LOUD reward vout (plaintext amount on the
        // wire, §5.5) paying the full mint to P's base address, plus two
        // confidential change vouts (daemon prunable-tx floor). The daemon's
        // ordered reward-commit set is "non-zero wire amounts, in vout
        // order" — exactly the reward vout here, so the auth digest binds
        // one commit.
        let mut tx_key_secret = Zeroizing::new([0u8; 32]);
        rand_core::OsRng.fill_bytes(tx_key_secret.as_mut());
        let tx_pubkey = &Scalar::from_bytes_mod_order(*tx_key_secret) * ED25519_BASEPOINT_TABLE;

        let mut reward_commit: Option<RewardCommit> = None;
        let ConstructedVouts {
            output_infos,
            output_keys,
            view_tags,
            kem_blobs,
            leaf_hash_blob,
        } = construct_vouts_to_base(
            keys,
            &tx_key_secret,
            &[total_reward, change_lo, change_hi],
            "claim-output construction",
            |idx, constructed| {
                if idx == 0 {
                    // The auth digest must bind the commitment the daemon
                    // reads from the tx's outPk. `construct_output`'s C =
                    // z·G + amount·H is the same formula (and mask) the
                    // signer emits; the post-sign cross-check below fails
                    // loudly if they ever diverge.
                    reward_commit = Some(RewardCommit {
                        commitment: constructed.commitment,
                        amount_plain: total_reward,
                        one_time_key: constructed.output_key,
                    });
                }
            },
        )?;
        let reward_commits =
            vec![reward_commit.expect("vout_amounts is non-empty; index 0 always constructs")];
        // The reward vout is loud (plaintext amount on the wire); the change
        // vouts stay confidential (wire amount 0).
        let output_amounts: Vec<u64> = vec![total_reward, 0, 0];

        // ── Step 7: tx_extra — tx pubkey + per-output KEM blobs + 0x07 PQC
        // leaf hashes (same shape as the bond path).
        let mut extra = Extra::for_hybrid_transfer(tx_pubkey, kem_blobs);
        extra.push_pqc_leaf_hashes(leaf_hash_blob);
        let tx_extra = extra.serialize();

        // ── Step 8: fee spend inputs — shared spend-side leg with the bond
        // path (descending key-image order).
        let prepared = prepare_funding_inputs(keys, ops.fee_funding)?;
        let key_images: Vec<[u8; 32]> = prepared.iter().map(|p| p.key_image).collect();
        let fee_gindexes: Vec<GlobalOutputIndex> = prepared.iter().map(|p| p.gindex).collect();

        // ── Step 9: the SIGNABLE hash (F-C1c) — the prefix with the
        // emission vin erased WHOLESALE. The wire encoder places ToKey key
        // images first and extra inputs after, so the emission vin sits at
        // `archival_emission_index == key_images.len()`; the daemon's
        // `classify_archival_tx` finds it there and `blockchain.cpp:3866`
        // erases exactly that entry — leaving these key images, these
        // outputs (loud amount included), and this extra: byte-identical to
        // the vin-less prefix hashed here.
        let signable_tx_hash = tx_prefix_hash_from_parts_with_extra(
            &key_images,
            &[],
            &output_keys,
            &output_amounts,
            &view_tags,
            &tx_extra,
        )
        .map_err(|e| BondAssemblyError::build("signable hash", e))?;

        // ── Step 10: backing spend input (membership-only; no key image).
        // The parts are re-derived from the designation's own record — the
        // single record owner (the `MembershipPath` doc in `backing_set.rs`:
        // paths carry no record copy) — through the SAME
        // [`derive_spend_parts`] the fee spends use (one derivation
        // definition; a divergence would fail every claim at the leaf gate
        // below).
        let rec = ops.backing.record();
        let backing_index = rec.index_in_transaction;
        let mut parts = derive_spend_parts(keys, rec, &ops.backing_path.leaf_chunk)?;
        let backing_h_pqc = parts.h_pqc;
        let backing_pubkey = std::mem::take(&mut parts.pqc_pubkey);
        // Retained for Auth-B signing after the bundle moves into the
        // proving closure.
        let backing_combined = std::mem::replace(&mut parts.combined64, Zeroizing::new([0u8; 64]));
        // Pre-flight leaf gate: the daemon's C-1 gate demands
        // hash(backing_pubkey) == leaf.h_pqc. A mismatch here means stale or
        // defective tree data (or a record that is not this persona's) —
        // fail before proving, not at the daemon.
        if hash_pqc_public_key(&backing_pubkey) != backing_h_pqc {
            return Err(BondAssemblyError::build(
                "backing leaf gate",
                "derived backing pubkey does not hash to the leaf's pqc_pk_hash \
                 (stale/defective tree data, or a record not owned by this persona)",
            )
            .into());
        }
        let backing_spend = parts.into_spend_input(
            rec,
            ops.backing_path.leaf_chunk,
            ops.backing_path.c1_layers,
            ops.backing_path.c2_layers,
        );

        // ── Step 11: membership-only proof over the signable hash (CPU-
        // bound → spawn_blocking, SP-5 pattern). The backing secrets end in
        // this closure; Auth-B below uses only the retained combined-secret
        // copy.
        let tree = msg.tree_ctx.clone();
        let membership = tokio::task::spawn_blocking(move || {
            prove_backing_membership(&backing_spend, &tree, signable_tx_hash)
        })
        .await
        .map_err(|e| BondAssemblyError::build("membership proving offload join", e))?
        .map_err(|e| BondAssemblyError::build("membership proving", e))?;

        // ── Step 12: the vin, with placeholder auths at canonical length
        // (the auth digest spans fields 1–6 + tx context, never the auth
        // legs themselves, so the placeholders don't poison it).
        let hybrid_pk_bytes = keys
            .hybrid_sign_pk
            .to_canonical_bytes()
            .map_err(|e| BondAssemblyError::build("identity encoding", e))?;
        let persona = p_canonical_id_from_hybrid_pubkey(&hybrid_pk_bytes);
        let mut vin = ArchivalRewardEmissionVin {
            p_pubkey: hybrid_pk_bytes.clone(),
            holdings: claims.holdings.clone(),
            settlement_epochs: claims.settlement_epochs.clone(),
            work_claim: claims.work_claim,
            backing: MembershipOnlyBacking {
                proof: membership.proof,
                pseudo_out: membership.pseudo_out,
                pqc_pk_hash: backing_h_pqc,
                backing_pubkey: backing_pubkey.clone(),
                tree_depth: membership.tree_depth,
            },
            reward_amount_plain: claims.reward_amount_plain,
            auth_backing: vec![0u8; SINGLE_SIG_CANONICAL_LEN],
            auth_claim: vec![0u8; SINGLE_SIG_CANONICAL_LEN],
        };

        // ── Step 13: dual auth over the role-separated binding messages
        // (Q1). Auth-B signs with the backing's OUTPUT-DERIVED hybrid key
        // (the daemon's C-1 gate checks hash(backing_pubkey) == leaf.h_pqc,
        // verified at emission_verify.rs — NOT P's identity key); Auth-P
        // signs with P's identity hybrid key (the daemon derives the vin's
        // p_canonical_id from it, blockchain.cpp:3783 id-equality).
        let auth_msgs = vin
            .auth_msgs(&reward_commits, &signable_tx_hash)
            .map_err(|e| BondAssemblyError::build("auth binding message", e))?;
        let auth_b = sign_pqc_auth_for_output(
            &backing_combined,
            backing_index,
            shekyl_crypto_pq::signature::SCHEME_DOMAIN_EMISSION_BACKING,
            &auth_msgs.backing,
        )
        .map_err(|e| BondAssemblyError::build("backing auth signing", e))?;
        if auth_b.hybrid_public_key != backing_pubkey {
            // Same derivation, same inputs — divergence is a build defect.
            debug_assert!(
                false,
                "Auth-B pubkey diverged from the vin's backing_pubkey"
            );
            return Err(BondAssemblyError::build(
                "backing auth signing",
                "Auth-B signer pubkey diverged from the vin's backing_pubkey",
            )
            .into());
        }
        vin.auth_backing = auth_b.signature;
        let claim_sig = HybridEd25519MlDsa
            .sign(
                &keys.hybrid_sign_sk,
                shekyl_crypto_pq::signature::SCHEME_DOMAIN_EMISSION_CLAIM,
                &auth_msgs.claim,
            )
            .map_err(|e| BondAssemblyError::build("claim auth signing", e))?;
        vin.auth_claim = claim_sig
            .to_canonical_bytes()
            .map_err(|e| BondAssemblyError::build("claim auth encoding", e))?;

        // ── Step 14: the completed vin joins the prefix; FULL prefix hash.
        let emission_input = Input::ArchivalRewardEmission {
            canonical_bytes: vin
                .serialize()
                .map_err(|e| BondAssemblyError::build("emission vin encoding", e))?,
        };
        let extra_inputs = vec![emission_input];
        let prefix_hash = tx_prefix_hash_from_parts_with_extra(
            &key_images,
            &extra_inputs,
            &output_keys,
            &output_amounts,
            &view_tags,
            &tx_extra,
        )
        .map_err(|e| BondAssemblyError::build("prefix hash", e))?;

        // ── Step 15: fee-side proving (Bp+ over all three vouts, loud one
        // included, + FCMP over the fee spends) with `total_reward` as the
        // INPUT-side cleartext term — the daemon's balance is
        // `Σ pseudoOuts + total_reward·H = Σ out_masks + fee·H`
        // (`verCtSemanticsEmission`, ct_semantics.cpp:364). The build-time
        // backing self-check (CPU-bound verify) rides the same closure.
        let mut spend_inputs = Vec::with_capacity(prepared.len());
        let mut pqc_pubkeys = Vec::with_capacity(prepared.len());
        for p in prepared {
            spend_inputs.push(p.spend);
            pqc_pubkeys.push(p.pqc_pubkey);
        }
        // `output_infos` and `vin` MOVE into the proving closure (no clones:
        // neither is read again until the closure returns them).
        let outputs_for_prove = output_infos;
        let tree = msg.tree_ctx.clone();
        let reward_term = InputTerm::new(AtomicUnits::from_raw(total_reward));
        let (signed, spend_inputs, vin) = tokio::task::spawn_blocking(move || {
            let signed = sign_transaction_with_terms(
                prefix_hash,
                &spend_inputs,
                &outputs_for_prove,
                AtomicUnits::from_raw(fee),
                &[reward_term],
                &[],
                &tree,
            )
            .map_err(|e| StakeEngineError::from(BondAssemblyError::build("proving", e)))?;
            // Step-7 self-check, backing leg: the landed consensus verifier
            // over the assembled vin (cause-blind on refusal, CB-5).
            if let Err(e) = emission_vin_verify_backing(
                &vin,
                &tree.tree_root,
                tree.tree_depth,
                signable_tx_hash,
            ) {
                tracing::error!(error = %e, "emission self-check: backing verification failed");
                return Err(StakeEngineError::EmissionClaim(
                    EmissionClaimError::SelfCheckFailed,
                ));
            }
            Ok((signed, spend_inputs, vin))
        })
        .await
        .map_err(|e| BondAssemblyError::build("proving offload join", e))??;

        // The auth digest bound the pre-computed reward commit; the daemon
        // verifies against the tx's outPk (the signer's commitment). Both
        // are z·G + amount·H over the same mask — divergence is a build
        // defect, failed loudly before any bytes leave the builder.
        if signed.commitments.first() != Some(&reward_commits[0].commitment) {
            debug_assert!(
                false,
                "signer reward commitment diverged from the auth-bound commit"
            );
            return Err(BondAssemblyError::build(
                "reward-commit cross-check",
                "signer commitment diverged from the auth-bound reward commit",
            )
            .into());
        }

        let bulletproof = Bulletproof::read_plus(&mut signed.bulletproof_plus.as_slice())
            .map_err(|e| BondAssemblyError::build("bulletproof parse", e))?;

        // ── Step 16: assemble the wire input; pqc_auths carries one slot
        // per prefix input — the fee spend slots (output-derived keys) then
        // the emission slot (P's identity key: the daemon derives the vin's
        // p_canonical_id from this slot's pubkey, id-equality at
        // blockchain.cpp:3783).
        let mut wire = WireEncodeInput {
            key_images,
            extra_inputs,
            output_amounts,
            output_keys,
            view_tags,
            tx_extra,
            fee,
            enc_amounts: signed.enc_amounts,
            enc_labels: signed.enc_labels,
            out_commitments: signed.commitments,
            pseudo_outs: signed.pseudo_outs,
            bulletproof,
            reference_block: signed.reference_block,
            fcmp_proof: signed.fcmp_proof,
            // Placeholder auths at real pubkeys (the phase-1 payload hash
            // reads them); the fee-slot pubkeys MOVE in — nothing reads
            // `pqc_pubkeys` again (`sign_pqc_auths` re-derives per input).
            pqc_auths: pqc_pubkeys
                .into_iter()
                .map(|pk| PqcAuth {
                    auth_version: 1,
                    signature: Vec::new(),
                    public_key: pk,
                })
                .chain(std::iter::once(PqcAuth {
                    auth_version: 1,
                    signature: Vec::new(),
                    public_key: hybrid_pk_bytes.clone(),
                }))
                .collect(),
            fcmp_layers: signed.tree_depth,
        };

        // ── Step 17: PQC auth completion (fast; inline). Fee slots sign
        // with output-derived keys; the emission slot signs with P's
        // `hybrid_sign_sk` (CB-2: derived bundle, no seed re-borrow).
        let payload_hashes = phase1_payload_hashes(&wire)
            .map_err(|e| BondAssemblyError::build("phase1 payload hash", e))?;
        if payload_hashes.len() != spend_inputs.len() + 1 {
            return Err(BondAssemblyError::build(
                "phase1 payload hash",
                format!(
                    "expected {} payload hashes, got {}",
                    spend_inputs.len() + 1,
                    payload_hashes.len()
                ),
            )
            .into());
        }
        let mut pqc_auths = sign_pqc_auths(&payload_hashes[..spend_inputs.len()], &spend_inputs)
            .map_err(|e| BondAssemblyError::build("pqc auth signing", e))?;
        let emission_payload_hash = payload_hashes[spend_inputs.len()];
        let emission_sig = HybridEd25519MlDsa
            .sign(
                &keys.hybrid_sign_sk,
                shekyl_crypto_pq::signature::SCHEME_DOMAIN_PQC_AUTH_TX,
                &emission_payload_hash,
            )
            .map_err(|e| BondAssemblyError::build("emission pqc auth signing", e))?;
        pqc_auths.push(PqcAuth {
            auth_version: 1,
            signature: emission_sig
                .to_canonical_bytes()
                .map_err(|e| BondAssemblyError::build("emission pqc auth encoding", e))?,
            public_key: hybrid_pk_bytes,
        });
        wire.pqc_auths = pqc_auths;
        drop(spend_inputs); // secrets end here; nothing below needs them

        // ── Step 18: remaining self-check legs (fast; inline). Claims leg:
        // the landed verifier's economics recompute against the paired
        // source. Auth leg: both role signatures over the recomputed
        // binding messages (cause-blind on refusal, CB-5).
        self_check_claims(&ops.source, &vin, total_reward)?;
        if let Err(e) = emission_vin_verify_auth(&vin, &reward_commits, &signable_tx_hash) {
            tracing::error!(error = %e, "emission self-check: auth verification failed");
            return Err(EmissionClaimError::SelfCheckFailed.into());
        }

        // ── Step 19: encode + mint at the P-1 site. ──────────────────────
        let bound_tx = finalize_bond_tx(persona, &wire)?;

        Ok(AssembledEmissionClaim {
            bound_tx,
            fee_gindexes,
            claimed_epochs: claims.settlement_epochs,
            size_deferred: claims.size_deferred,
            total_reward,
        })
    }
}

// ---------------------------------------------------------------------------
