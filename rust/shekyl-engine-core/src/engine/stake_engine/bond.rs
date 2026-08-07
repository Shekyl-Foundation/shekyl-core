
use kameo::message::{Context, Message};

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::Scalar;
use rand_core::RngCore as _;
use shekyl_archival_bond_builder::build_join_market_vin;
use shekyl_archival_retention::id::p_canonical_id_from_hybrid_pubkey;
use shekyl_archival_retention::{
    bond_floor,
    HoldingsDescriptor,
};
use shekyl_bulletproofs::Bulletproof;
use shekyl_crypto_pq::signature::{HybridEd25519MlDsa, SignatureScheme as _};
use shekyl_scanner::extra::Extra;
#[cfg(feature = "gf7-hooks")]
use shekyl_standoff::gf7::{BroadcastTimelineObserver, NoOpObserver, TimelineEvent};
use shekyl_tx_builder::{
    phase1_payload_hashes, sign_pqc_auths, sign_transaction_with_terms,
    tx_prefix_hash_from_parts_with_extra, PqcAuth, TreeContext, WireEncodeInput,
};
use shekyl_units::AtomicUnits;
use shekyl_wire::Input;
use zeroize::Zeroizing;

use crate::engine::bond_assembly::{
    finalize_bond_tx, wire_bond_post_input, BondAssemblyError, FundingInputContext, PBoundBytes,
};

// S6 / DQ3 — the session RNG self-cert grader (`shekyl-standoff` `conformance`)
// is gated to **`x86_64` exactly** (the guard below is `target_arch = "x86_64"`,
// matching the `x86_64`-only CI conformance lane and the standoff conformance
// lane it mirrors): its goodness-of-fit is float, which is not bit-identical
// across architectures, and `x86_64` is the only target the diagnostic is built
// and run on. Rather than silently compile the self-cert out on a non-`x86_64`
// target (which would let a `--features conformance` diagnostic build report
// "conformance passed" when the grade never ran — false assurance), fail the
// build loudly: a diagnostic build that cannot run the diagnostic must say so at
// compile time, not pretend success at runtime. With this guard, `conformance`
// implies `x86_64`, so the self-cert call below needs only `cfg(feature)`.
#[cfg(all(feature = "conformance", not(target_arch = "x86_64")))]
compile_error!(
    "the StakeEngine session RNG self-cert grader (shekyl-standoff `conformance`) \
     is `x86_64`-only — its float goodness-of-fit is not bit-identical across \
     architectures. Build the `conformance` feature on `x86_64` (where the CI \
     conformance lane runs); do not enable it on other targets (including 32-bit \
     x86)."
);


use super::actor::StakeEngine;
use super::helpers::{
    construct_vouts_to_base, prepare_funding_inputs, ConstructedVouts,
};
use super::types::*;
// ---------------------------------------------------------------------------
// WI-2 D-A3 — AssembleBond: the production bond-assembly message
// ---------------------------------------------------------------------------

/// Assemble the **full, broadcast-ready** JoinMarket bond transaction inside
/// the actor (`ARCHIVAL_BOND_WI2_ASSEMBLY.md` §3.3) — the production superset
/// of [`SignBond`] (which signs the vin only and remains for the composition
/// KAT).
///
/// Carries the same handle + ticket typed contracts as [`SignBond`], plus the
/// **public** funding contexts the Engine-side orchestrator selected (§3.2)
/// and path-assembled: records, membership paths, and the tree context. The
/// spend secrets are **not** in the message — they are re-derived from each
/// record's `(ciphertext, index)` inside the handler
/// ([`derive_p_source_secrets_bundle`], rule 36).
///
/// The reply pairs the minted [`PBoundBytes`] with the bond-post placement
/// offset from this request's entry-gap draw — the same seam discipline as
/// [`SignedBondPost`]: the caller that receives the bytes to place receives
/// where to place them.
///
/// Dead_code allow: the Engine orchestrator is wired; go-live still needs
/// SP-R0/2d-1 pruning **and** the RPC stake entry (rule-21 — neither alone;
/// half (a) landed 2026-07-18 with SP-R0 arm #1, logic-discharged — half (b)
/// is the remaining retirement, the staker-activation round).
pub(crate) struct AssembleBond {
    /// Operation-scoped capability proving the slot is currently held (typed
    /// contract #2). Must match `ticket.p_slot()`.
    pub handle: PersonaHandle,
    /// Proof that the live-bond record was durably persisted for this slot
    /// before assembly (typed contract #1). Must match `handle.p_slot()`.
    pub ticket: crate::engine::stake_persist::PersistedBondTicket,
    /// Holdings to bond; `bond_floor(holdings)` is recomputed inside.
    pub holdings: HoldingsDescriptor,
    /// The selected funding inputs (§3.2) with their assembled membership
    /// paths — public identity + public tree data only.
    pub funding: Vec<FundingInputContext>,
    /// The curve-tree reference context the paths were assembled against.
    pub tree_ctx: TreeContext,
    /// The fee the Engine-side selection was run against.
    pub fee: u64,
}

/// Reply of [`AssembleBond`]: the persona-bound wire bytes (minted at the
/// single P-1 site, [`finalize_bond_tx`]), the placement offset, and the
/// funding gindexes for the caller's reservation record (§3.5). Secrets never
/// cross the boundary.
///
/// Dead_code allow: reply type of the wired orchestrator; same dual gate as
/// [`AssembleBond`].
#[allow(dead_code)]
// rule-21: (a) SP-R0 arm #1 pruning DONE 2026-07-18 (logic-discharged); retires with (b) the RPC stake entry (#332). The placement carrier is the bare `bond_post_offset_blocks` (the entry-seam plan/order-coin was retired in the GF-7 coin retirement).
#[derive(Debug)]
pub(crate) struct AssembledBondPost {
    /// The fully-signed, wire-encoded bond transaction, persona-bound.
    pub bound_tx: PBoundBytes,
    /// Blocks from the private-intent anchor `t0` to the bond-post broadcast —
    /// the drawn entry-gap spread.
    pub bond_post_offset_blocks: u64,
    /// The spent funding records' gindexes — the §3.5 reservation set.
    pub funding_gindexes: Vec<shekyl_types::GlobalOutputIndex>,
}

impl Message<AssembleBond> for StakeEngine {
    type Reply = Result<AssembledBondPost, StakeEngineError>;

    async fn handle(
        &mut self,
        msg: AssembleBond,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // ── Steps 1–5: the shared bond-handler prologue (identical typed
        // contracts + guarded draw as `SignBond`); see
        // `validate_and_draw_bond_offset`. ──────────────────────────────────
        let (handle_slot, bond_post_offset_blocks) =
            self.validate_and_draw_bond_offset(&msg.handle, msg.ticket.p_slot())?;

        // ── Step 6: borrow the held bundle (never crosses the boundary) ──
        let keys = self
            .held
            .get(&handle_slot)
            .expect("validate_handle confirmed slot is held")
            .keys();

        // ── Step 7: funding arithmetic (§3.2 balance rule, checked) ──────
        // `funding == change + fee + credit` exactly; change splits across
        // TWO outputs (daemon prunable-tx floor: `vout.size() < 2` rejects).
        let floor = bond_floor(&msg.holdings);
        let required = floor
            .checked_add(msg.fee)
            .ok_or(BondAssemblyError::AmountOverflow)?;
        let mut available: u64 = 0;
        for ctx in &msg.funding {
            available = available
                .checked_add(ctx.record.amount.to_raw())
                .ok_or(BondAssemblyError::AmountOverflow)?;
        }
        if available < required {
            return Err(BondAssemblyError::InsufficientFunding {
                available,
                required,
            }
            .into());
        }
        let change = available - required;
        let change_lo = change / 2;
        let change_hi = change - change_lo;

        // ── Step 8: change outputs to P's own base address ────────────────
        // Both return to `P`'s base spend key (the pscan `GuaranteedScanner`
        // claims against `spend_pk` directly), so the change re-enters the
        // funding set on the next sweep.
        let mut tx_key_secret = Zeroizing::new([0u8; 32]);
        rand_core::OsRng.fill_bytes(tx_key_secret.as_mut());
        let tx_pubkey = &Scalar::from_bytes_mod_order(*tx_key_secret) * ED25519_BASEPOINT_TABLE;

        let ConstructedVouts {
            output_infos,
            output_keys,
            view_tags,
            kem_blobs,
            leaf_hash_blob,
        } = construct_vouts_to_base(
            keys,
            &tx_key_secret,
            &[change_lo, change_hi],
            "change-output construction",
            |_, _| {},
        )?;

        // ── Step 9: tx_extra — tx pubkey + per-output KEM blobs + the 0x07
        // PQC leaf hashes (without which the change outputs ingest with a
        // zero `h_pqc` leaf and are unspendable).
        let mut extra = Extra::for_hybrid_transfer(tx_pubkey, kem_blobs);
        extra.push_pqc_leaf_hashes(leaf_hash_blob);
        let tx_extra = extra.serialize();

        // ── Step 10 (§3.3 actor step 1): re-derive spend bundles, compute
        // key images, build the tx-builder SpendInputs — the shared
        // [`prepare_funding_inputs`] leg (also the emission handler's fee
        // side). Secrets stay inside this frame until they move into the
        // proving closure.
        let prepared = prepare_funding_inputs(keys, msg.funding)?;

        let key_images: Vec<[u8; 32]> = prepared.iter().map(|p| p.key_image).collect();
        let funding_gindexes: Vec<shekyl_types::GlobalOutputIndex> =
            prepared.iter().map(|p| p.gindex).collect();

        // ── Steps 11–12 (§3.3 actor step 2): the wire BondPost prefix input
        // from PUBLIC parts, then the prefix hash. No circularity: the wire
        // input carries no signature, so the prefix is fully determined
        // before the vin is signed.
        let hybrid_pk_bytes = keys
            .hybrid_sign_pk
            .to_canonical_bytes()
            .map_err(|e| BondAssemblyError::build("identity encoding", e))?;
        let bond_spend_pk_bytes = keys
            .bond_spend_pk
            .to_canonical_bytes()
            .map_err(|e| BondAssemblyError::build("identity encoding", e))?;
        let persona = p_canonical_id_from_hybrid_pubkey(&hybrid_pk_bytes);
        let expected_vin = shekyl_archival_retention::ArchivalBondPostVin {
            hybrid_public_key: hybrid_pk_bytes.clone(),
            p_canonical_id: *persona.as_bytes(),
            post_kind: shekyl_archival_retention::BondPostKind::JoinMarket,
            bond_spend_pk: bond_spend_pk_bytes,
            holdings: msg.holdings.clone(),
            bonded_total_atomic: floor,
            bond_credit: floor,
            bond_debit: 0,
        };
        let prefix_bond_input: Input = wire_bond_post_input(&expected_vin)?;
        let extra_inputs = vec![prefix_bond_input];

        let prefix_hash = tx_prefix_hash_from_parts_with_extra(
            &key_images,
            &extra_inputs,
            &output_keys,
            // Every change output is confidential (wire amount 0) — derived
            // from the count, same as the wire encode below, so the two
            // sites cannot disagree on arity.
            &vec![0; output_keys.len()],
            &view_tags,
            &tx_extra,
        )
        .map_err(|e| BondAssemblyError::build("prefix hash", e))?;

        // ── Step 13 (§3.3 actor step 3): build + sign the vin over the now-
        // fixed prefix hash.
        let built = build_join_market_vin(keys, msg.holdings.clone(), &prefix_hash)
            .map_err(StakeEngineError::BondBuild)?;

        // ── Step 14 — invariant A-1 (fail closed): the signed vin's post
        // fields must equal the prefix's BondPost input. Typed equality on
        // `ArchivalBondPostVin` implies byte-identity (its wire write is a
        // deterministic function of the value). A mismatch means the
        // signature binds a different post than the hash covered — a build
        // defect, never recoverable.
        if built.vin() != &expected_vin {
            // Loud in debug (a build defect, never a recoverable state), fail
            // closed in release. `debug_assert!(false, …)` — not
            // `debug_assert_eq!(built.vin(), &expected_vin, …)`, which would be
            // an always-false assert inside a branch that already established
            // inequality (it reads as a conditional check but can only panic).
            debug_assert!(
                false,
                "A-1: signed vin diverged from the prefix BondPost input"
            );
            return Err(BondAssemblyError::BondPostMismatch.into());
        }
        let credit_term = built.credit_term();

        // ── Step 15 (§3.3 actor step 5): offload the CPU-bound proving
        // (Bp+ + FCMP membership) to `spawn_blocking` — the SP-5 pattern.
        // The SpendInputs (owned secrets) MOVE into the closure and come
        // back for the fast inline PQC signing; `&mut self` is held across
        // the await, so the mailbox cannot interleave another message.
        let mut spend_inputs = Vec::with_capacity(prepared.len());
        let mut pqc_pubkeys = Vec::with_capacity(prepared.len());
        for p in prepared {
            spend_inputs.push(p.spend);
            pqc_pubkeys.push(p.pqc_pubkey);
        }
        let outputs_for_prove = output_infos.clone();
        let tree = msg.tree_ctx.clone();
        let fee = msg.fee;
        let (signed, spend_inputs) = tokio::task::spawn_blocking(move || {
            sign_transaction_with_terms(
                prefix_hash,
                &spend_inputs,
                &outputs_for_prove,
                AtomicUnits::from_raw(fee),
                &[],
                &[credit_term],
                &tree,
            )
            .map(|signed| (signed, spend_inputs))
        })
        .await
        .map_err(|e| BondAssemblyError::build("proving offload join", e))?
        .map_err(|e| BondAssemblyError::build("proving", e))?;

        let bulletproof = Bulletproof::read_plus(&mut signed.bulletproof_plus.as_slice())
            .map_err(|e| BondAssemblyError::build("bulletproof parse", e))?;

        // ── Step 16: assemble the wire input; pqc_auths carries one slot per
        // prefix input — the spend slots (output-derived keys) then the bond
        // slot (P's identity key), matching prefix input order.
        //
        // `signed` is a locally-owned value dropped at the end of this handler
        // and never read whole again (the only prior use, the bulletproof parse
        // above, borrowed `bulletproof_plus`). So the multi-KB owned proof
        // fields MOVE into the wire input rather than clone — the two `Copy`
        // reads below (`reference_block`, `tree_depth`) still work after a
        // partial move.
        let mut wire = WireEncodeInput {
            key_images,
            extra_inputs,
            output_amounts: vec![0; output_keys.len()],
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

        // ── Step 17: PQC auth completion (fast; stays inline). One payload
        // hash per pqc_auths slot; the spend slots sign with output-derived
        // keys, the bond slot signs with P's `hybrid_sign_sk`.
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
        let bond_payload_hash = payload_hashes[spend_inputs.len()];
        let bond_sig = HybridEd25519MlDsa
            .sign(&keys.hybrid_sign_sk, &bond_payload_hash)
            .map_err(|e| BondAssemblyError::build("bond pqc auth signing", e))?;
        pqc_auths.push(PqcAuth {
            auth_version: 1,
            signature: bond_sig
                .to_canonical_bytes()
                .map_err(|e| BondAssemblyError::build("bond pqc auth encoding", e))?,
            public_key: hybrid_pk_bytes,
        });
        wire.pqc_auths = pqc_auths;
        drop(spend_inputs); // secrets end here; nothing below needs them

        // ── Step 18 (§3.3 actor step 6): encode + mint at the P-1 site ────
        let bound_tx = finalize_bond_tx(persona, &wire)?;

        Ok(AssembledBondPost {
            bound_tx,
            bond_post_offset_blocks,
            funding_gindexes,
        })
    }
}

