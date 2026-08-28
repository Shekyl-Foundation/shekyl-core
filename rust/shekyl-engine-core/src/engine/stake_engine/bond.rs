// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! AssembleBond message handler.

use kameo::message::{Context, Message};

use shekyl_archival_bond_builder::build_join_market_vin;
use shekyl_archival_retention::id::p_canonical_id_from_hybrid_pubkey;
use shekyl_archival_retention::HoldingsDescriptor;
use shekyl_crypto_pq::signature::{HybridEd25519MlDsa, SignatureScheme as _};
use shekyl_tx_builder::TreeContext;

use crate::engine::bond_assembly::{BondAssemblyError, FundingInputContext, PBoundBytes};

use super::actor::StakeEngine;
use super::bond_post_assemble::{
    assemble_signed_bond_post, require_funding_inputs, BondPostAssembleArgs,
};
use super::types::*;

// ---------------------------------------------------------------------------
// WI-2 D-A3 — AssembleBond: the production bond-assembly message
// ---------------------------------------------------------------------------

/// Assemble the **full, broadcast-ready** JoinMarket bond transaction inside
/// the actor (`ARCHIVAL_BOND_WI2_ASSEMBLY.md` §3.3) — the production superset
/// of [`PlanBondPost`] (which constructs the vin only and remains for the composition
/// KAT).
///
/// Carries the same handle + ticket typed contracts as [`PlanBondPost`], plus the
/// **public** funding contexts the Engine-side orchestrator selected (§3.2)
/// and path-assembled: records, membership paths, and the tree context. The
/// spend secrets are **not** in the message — they are re-derived from each
/// record's `(ciphertext, index)` inside the handler
/// ([`derive_p_source_secrets_bundle`], rule 36).
///
/// The reply pairs the minted [`PBoundBytes`] with the bond-post placement
/// offset from this request's entry-gap draw — the same seam discipline as
/// [`BondPostPlacement`]: the caller that receives the constructed vin receives
/// where to place them.
///
/// Lint-visible, deliberately: the wired Engine orchestrator consumes this, so
/// no suppression applies. Go-live still needs SP-R0/2d-1 pruning **and** the
/// RPC stake entry (rule-21 — neither alone;
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
/// Lint-visible, deliberately: reply type of the wired orchestrator, so no
/// suppression applies. Same dual go-live gate as [`AssembleBond`].
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
        // contracts + guarded draw as `PlanBondPost`); see
        // `validate_and_draw_bond_offset`. ──────────────────────────────────
        let (handle_slot, bond_post_offset_blocks) =
            self.validate_and_draw_bond_offset(&msg.handle, msg.ticket.p_slot())?;

        // ── Step 6: borrow the held bundle (never crosses the boundary) ──
        let keys = self
            .held
            .get(&handle_slot)
            .expect("validate_handle confirmed slot is held")
            .keys();

        // ── Step 7: construct the bond vin (public keys only; SA-2b — no
        // on-vin signature). The constructed value is the SINGLE source of the
        // JoinMarket post: it feeds the bond floor here, the wire prefix input
        // (step 12), the credit term, and the later surface-A bond slot — so
        // the prefix and the post cannot diverge by construction. (The
        // pre-SA-2b signing circularity forced a second, public-parts
        // construction plus a runtime A-1 equality check; deleting the on-vin
        // signature deleted the circularity, and the duplicate with it.)
        let built = build_join_market_vin(keys.bond_post_keys(), msg.holdings.clone())
            .map_err(StakeEngineError::BondBuild)?;
        let hybrid_pk_bytes = built.vin().hybrid_public_key.clone();
        let persona = p_canonical_id_from_hybrid_pubkey(&hybrid_pk_bytes);
        let credit_term = built.credit_term();

        // Shape floor before any amount rule — consensus order, and the
        // name the chain uses (`FundingInputsRequired`). Without this, an
        // empty set is `InsufficientFunding` here and `FundingInputsRequired`
        // on the debit path. The shared tail repeats the check so a future
        // caller cannot skip it.
        require_funding_inputs(msg.funding.len())?;

        // ── Step 8: funding arithmetic (§3.2 balance rule, checked) ──────
        // `funding == change + fee + credit` exactly; change splits across
        // TWO outputs (daemon prunable-tx floor: `vout.size() < 2` rejects).
        let floor = built.vin().bond_credit;
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

        // Credit policy stays here: identity-key slot, credit term on the
        // output side. The prove/sign/encode tail is shared with Unbond so
        // the two cannot drift on wire shape. GF-1 is this closure — a debit
        // would close over `bond_spend_sk` instead.
        let assembled = assemble_signed_bond_post(
            BondPostAssembleArgs {
                keys,
                persona,
                funding: msg.funding,
                tree_ctx: msg.tree_ctx,
                fee: msg.fee,
                amounts: [change_lo, change_hi],
                extra_input_terms: vec![],
                extra_output_terms: vec![credit_term],
                vin: built.vin(),
                bond_auth_pk: hybrid_pk_bytes,
                output_site: "change-output construction",
            },
            |payload_hash| {
                let sig = HybridEd25519MlDsa
                    .sign(
                        &keys.hybrid_sign_sk,
                        shekyl_crypto_pq::signature::SCHEME_DOMAIN_PQC_AUTH_TX,
                        payload_hash,
                    )
                    .map_err(|e| BondAssemblyError::build("bond pqc auth signing", e))?;
                sig.to_canonical_bytes()
                    .map_err(|e| BondAssemblyError::build("bond pqc auth encoding", e))
            },
        )
        .await?;

        Ok(AssembledBondPost {
            bound_tx: assembled.bound_tx,
            bond_post_offset_blocks,
            funding_gindexes: assembled.funding_gindexes,
        })
    }
}
