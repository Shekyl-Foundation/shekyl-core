// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! AssembleBond message handler.

use kameo::message::{Context, Message};

use crate::engine::holdings_fill::FilledHoldings;
use shekyl_archival_bond_builder::build_join_market_vin;
use shekyl_archival_retention::id::p_canonical_id_from_hybrid_pubkey;
use shekyl_crypto_pq::signature::{HybridEd25519MlDsa, SignatureScheme as _};
use shekyl_tx_builder::TreeContext;
use shekyl_tx_weight::MIN_NON_COINBASE_OUTPUTS;
use shekyl_types::SigningPayloadHash;

use crate::engine::bond_assembly::{BondAssemblyError, FundingInputContext, PBoundBytes};

use super::actor::StakeEngine;
use super::bond_post_assemble::{
    assemble_signed_bond_post, require_funding_inputs, BondPostAssembleArgs,
};
use super::helpers::split_across_minimum_outputs;
use super::types::*;

// ---------------------------------------------------------------------------
// WI-2 D-A3 — AssembleBond: the production bond-assembly message
// ---------------------------------------------------------------------------

/// Assemble the **full, broadcast-ready** JoinMarket bond transaction inside
/// the actor (`ARCHIVAL_BOND_WI2_ASSEMBLY.md` §3.3), at the plan's due block
/// (`ARCHIVAL_BOND_POST_DELAY.md` BD-Q3). The request's half is
/// [`PlanBondPost`](crate::engine::stake_engine::persona::PlanBondPost),
/// which draws the delay and builds nothing.
///
/// Carries the same handle + ticket typed contracts as [`PlanBondPost`](crate::engine::stake_engine::persona::PlanBondPost), plus the
/// **public** funding contexts the Engine-side orchestrator selected (§3.2)
/// and path-assembled: records, membership paths, and the tree context. The
/// spend secrets are **not** in the message — they are re-derived from each
/// record's `(ciphertext, index)` inside the handler
/// ([`derive_p_source_secrets_bundle`](crate::engine::stake_engine::helpers::derive_p_source_secrets_bundle), rule 36).
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
    pub holdings: FilledHoldings,
    /// The selected funding inputs (§3.2) with their assembled membership
    /// paths — public identity + public tree data only.
    pub funding: Vec<FundingInputContext>,
    /// The curve-tree reference context the paths were assembled against.
    pub tree_ctx: TreeContext,
    /// The fee the Engine-side selection was run against.
    pub fee: u64,
}

/// Reply of [`AssembleBond`]: the persona-bound wire bytes (minted at the
/// single P-1 site, [`finalize_bond_tx`](crate::engine::bond_assembly::finalize_bond_tx))
/// and the funding gindexes for the caller's reservation record (§3.5).
/// Secrets never cross the boundary. No placement: the plan holds the delay
/// it drew at the request, and this reply is built at the due block.
///
/// Lint-visible, deliberately: reply type of the wired orchestrator, so no
/// suppression applies. Same dual go-live gate as [`AssembleBond`].
#[derive(Debug)]
pub(crate) struct AssembledBondPost {
    /// The fully-signed, wire-encoded bond transaction, persona-bound.
    pub bound_tx: PBoundBytes,
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
        // ── Steps 1–2: the shared typed contracts (handle + ticket). No
        // draw: the plan drew its delay once, at the request, and assembly
        // at the due block never re-draws (BD-Q2). ─────────────────────────
        let handle_slot = self.validate_bond_handle(&msg.handle, msg.ticket.p_slot())?;

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
        let endpoint = keys.onion_keypair().public_key();
        let built = build_join_market_vin(
            keys.bond_post_keys(),
            msg.holdings.descriptor().clone(),
            endpoint,
        )
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
        // the consensus minimum of outputs.
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
        let amounts =
            split_across_minimum_outputs(change).ok_or(BondAssemblyError::OutputsUnfillable {
                amount: change,
                minimum: MIN_NON_COINBASE_OUTPUTS,
            })?;

        // Credit policy stays here: identity-key slot, credit term on the
        // output side. The prove/sign/encode tail is shared with Release so
        // the two cannot drift on wire shape. GF-1 is this closure — a debit
        // would close over `bond_spend_sk` instead.
        let assembled = assemble_signed_bond_post(
            BondPostAssembleArgs {
                network: self.network,
                keys,
                persona,
                funding: msg.funding,
                tree_ctx: msg.tree_ctx,
                fee: msg.fee,
                amounts,
                extra_input_terms: vec![],
                extra_output_terms: vec![credit_term],
                vin: built.vin(),
                bond_auth_pk: hybrid_pk_bytes,
                output_site: "change-output construction",
            },
            |payload_hash: &SigningPayloadHash| {
                let sig = HybridEd25519MlDsa
                    .sign(
                        &keys.hybrid_sign_sk,
                        shekyl_crypto_pq::signature::SCHEME_DOMAIN_PQC_AUTH_TX,
                        payload_hash.as_bytes(),
                    )
                    .map_err(|e| BondAssemblyError::build("bond pqc auth signing", e))?;
                sig.to_canonical_bytes()
                    .map_err(|e| BondAssemblyError::build("bond pqc auth encoding", e))
            },
        )
        .await?;

        Ok(AssembledBondPost {
            bound_tx: assembled.bound_tx,
            funding_gindexes: assembled.funding_gindexes,
        })
    }
}
