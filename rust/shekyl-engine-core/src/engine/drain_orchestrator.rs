// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! F-D1 projection + drain planning — the drain trust boundary
//! (`ARCHIVAL_FIREWALL_GATE6.md` §12.3, the drain-amount taint-carve).
//!
//! The `P` value-out (drain) path has three stages, each reading the
//! minimum:
//!
//! - **Amount** ([`super::drain_amount::choose_drain_amount`]): `{user
//!   target, cadence, RNG}` + the aggregate scalar (affordability check
//!   only). The per-output reward vector is never in scope, so core code
//!   cannot *compute* a reward-shaped subsum from it.
//! - **Select** ([`super::drain_select::select_for_drain`]): lineage-blind
//!   coin selection over the stripped `{output_id, amount, spendable_height}`
//!   vector.
//! - **Project** (this module): the single trust boundary. It is the **only**
//!   drain-path site that holds the persisted funding-output records (the
//!   `PScanState.funding_outputs` set the caller loads) — so it is the only
//!   site *permitted to observe* their mint-lineage tag, arrival epoch, and
//!   arrival height, and it drops all three by projecting only `{output_id,
//!   amount, spendable_height}`. It reduces the records into the two operands
//!   the guarded stages consume — the aggregate spendable scalar and the
//!   stripped candidate vector — mirroring the established "orchestrator
//!   prepares operands, downstream receives prepared values" seam
//!   (`claim_orchestrator.rs`). The amount and select modules never name the
//!   record or the lineage tag; this module does, and is deliberately
//!   excluded from the F-D1 M1 import-check arm.
//!
//! [`plan_drain`] composes the three stages on an already-loaded record set:
//! the caller (the eventual drain actor/command) loads
//! `PScanState.funding_outputs` exactly as `bond_orchestrator` does and hands
//! the records in; assembling the selected outputs into a signed, broadcast
//! transaction is the downstream follow-on (the claim-assembly analog), not
//! this module. What lands here is the enforced carve: the projection is the
//! only path from records to the *guarded stages'* operands (the amount scalar
//! and the stripped candidate vector), and those stages are armed against ever
//! reading the decomposition. The aggregate balance read ([`drain_balance`]) is
//! a lineage-blind scalar sum that observes the same carve without building the
//! candidate vector.
//!
//! ## F-D2 (core-side half)
//!
//! The drain's `P`-balance surface is the **aggregate scalar**
//! ([`DrainBalance`]) — never a per-epoch/per-reward decomposition, mirroring
//! the principal `LedgerEngine::balance() -> BalanceSummary` aggregate
//! discipline (`local_ledger.rs`). The planning entry takes a single scalar
//! `target` ([`plan_drain`]), so a UI built on this surface structurally
//! cannot pre-fill or hand in a reward-shaped decomposition: the breakdown
//! never reaches it. The wallet-flow default itself — "never seed a
//! reward-derived amount; offer round-number / random-split" — is a UI
//! affordance against *user-eye* reconstruction (§12.4 coverage boundary) and
//! lands in `shekyl-gui-wallet`; it is **not** part of this PR. F-D2 is not
//! recorded as landed until that flow is built.

use std::collections::BTreeSet;

use shekyl_curve_tree::{AssembleInput, Gindex};
use shekyl_engine_state::pscan_state::PFundingOutputRecord;
use shekyl_standoff::EXIT_FEE_RESERVE_ATOMIC;
use shekyl_tx_builder::{LeafEntry, TreeContext};
use shekyl_types::{BlockHeight, GlobalOutputIndex};
use shekyl_units::AtomicUnits;

use super::bond_assembly::FundingInputContext;
use super::bond_orchestrator::anchored_reference_block;
use super::curve_tree_actor::{CurveTreeHandle, CurveTreeHandleError};
use super::drain_amount::{choose_drain_amount, DrainAmountError, DrainRequest};
use super::drain_assembly::{AssembleDrain, AssembledDrain, DrainDestination};
use super::drain_select::{select_for_drain, DrainCandidate, DrainSelectError};
use super::stake_engine::{PersonaHandle, StakeEngineError, StakeEngineHandle};

/// The drain-path `P`-balance surface: a single aggregate spendable scalar
/// (F-D2 core-side). Carries no per-output/per-epoch breakdown by
/// construction — the projection that produces it has already dropped every
/// reward-sequence coordinate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrainBalance {
    /// Sum of the provable (mature) `P` funding outputs at the reference
    /// height. A public aggregate, treated like the principal balance
    /// summary.
    pub spendable: AtomicUnits,
}

/// The output of the drain planner: the selected input identities, the drain
/// amount, and the change — none reward-decomposed.
#[derive(Clone, PartialEq, Eq)]
pub struct DrainPlan {
    /// The amount to move (proven affordable against the aggregate scalar,
    /// never a reward subsum).
    pub amount: AtomicUnits,
    /// The selected outputs' global indices (curve-tree leaf positions the
    /// downstream assembly re-maps to full records for spending).
    pub inputs: Vec<GlobalOutputIndex>,
    /// The sum of the selected inputs' amounts (`>= amount`).
    pub input_total: AtomicUnits,
    /// `input_total - amount`; the change the assembly returns to `P`.
    pub change: AtomicUnits,
}

impl std::fmt::Debug for DrainPlan {
    /// Redacted: `inputs` is the set of leaf positions `P` is about to drain
    /// together — a slice of `P`'s spend set, which the firewall keeps
    /// unenumerable, same discipline as the stripped candidates it came from.
    /// The aggregate scalars (`amount`, `input_total`, `change`) are public and
    /// render.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DrainPlan")
            .field("amount", &self.amount)
            .field("inputs", &"<redacted spend-set>")
            .field("input_total", &self.input_total)
            .field("change", &self.change)
            .finish()
    }
}

/// Why the drain planner could not produce a plan.
///
/// Public API (returned by [`plan_drain`] / [`drain_balance`]), so it carries
/// `Display` + `std::error::Error` via `thiserror` — the same discipline as the
/// other public engine errors (`PScanStartError`) — to compose with `?` and
/// surface a human-readable reason up through a UI/logging boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DrainError {
    /// The requested target was zero.
    #[error("the requested drain amount is zero")]
    EmptyRequest,
    /// The requested target exceeds the aggregate spendable scalar.
    #[error("the requested drain amount exceeds the spendable balance")]
    Unaffordable,
    /// The stripped candidate set could not cover the drain amount. **Not
    /// reachable through [`plan_drain`]**: the amount stage proves `target <=
    /// spendable`, and `spendable` is the sum of the *same* mature candidate
    /// set the select stage draws from, so a passing affordability check
    /// guarantees coverage. This variant exists for the standalone
    /// [`select_for_drain`] contract (a direct caller can hand it an amount
    /// exceeding its candidate sum); [`plan_drain`] maps it for totality only.
    #[error("the spendable outputs cannot cover the drain amount")]
    InsufficientSpendable,
    /// Atomic-unit arithmetic overflowed while aggregating or computing
    /// change (structurally unreachable under the supply cap; a corrupt state
    /// otherwise).
    #[error("atomic-unit arithmetic overflowed while planning the drain")]
    AmountOverflow,
}

impl From<DrainAmountError> for DrainError {
    fn from(e: DrainAmountError) -> Self {
        match e {
            DrainAmountError::Empty => DrainError::EmptyRequest,
            DrainAmountError::Unaffordable => DrainError::Unaffordable,
        }
    }
}

impl From<DrainSelectError> for DrainError {
    fn from(e: DrainSelectError) -> Self {
        match e {
            DrainSelectError::Insufficient => DrainError::InsufficientSpendable,
            DrainSelectError::Overflow => DrainError::AmountOverflow,
        }
    }
}

/// The prepared drain operands: the two projections the guarded stages read.
///
/// Minting this is the projection act — the record vector's `{lineage,
/// epoch, height}` are consumed here and do not survive into the operands.
struct DrainOperands {
    /// Aggregate spendable scalar (amount-stage affordability input; also the
    /// F-D2 balance surface).
    balance: DrainBalance,
    /// Stripped per-output candidates (select-stage input).
    candidates: Vec<DrainCandidate>,
}

/// The maturity predicate the projection and the balance surface share: a
/// record is provable (spendable) once its leaf is in the curve tree at the
/// reference height — the `spendable_height <= reference_height` rule the
/// backing/claim paths apply (a record whose leaf is not yet in the tree has no
/// membership path and cannot be spent). Reads only `spendable_height`, a
/// maturity axis and never a reward-sequence coordinate, so applying it outside
/// the projection discloses nothing the aggregate scalar doesn't already.
fn is_mature(record: &PFundingOutputRecord, reference_height: BlockHeight) -> bool {
    record.spendable_height <= reference_height
}

/// Project `P`'s persisted funding records into the drain operands: drop
/// `{lineage, epoch, height}`, keep only the provable (mature) subset, and
/// reduce to the aggregate scalar + the stripped candidate vector.
///
/// This is the sole site that reads the funding record's stripped-away
/// fields; the operands it returns carry none of them.
fn project_drain_operands(
    records: &[PFundingOutputRecord],
    reference_height: BlockHeight,
) -> Result<DrainOperands, DrainError> {
    let candidates: Vec<DrainCandidate> = records
        .iter()
        .filter(|r| is_mature(r, reference_height))
        .map(|r| DrainCandidate {
            output_id: r.gindex,
            amount: r.amount,
            spendable_height: r.spendable_height,
        })
        .collect();

    let spendable = AtomicUnits::checked_sum(candidates.iter().map(|c| c.amount))
        .ok_or(DrainError::AmountOverflow)?;

    Ok(DrainOperands {
        balance: DrainBalance { spendable },
        candidates,
    })
}

/// F-D2 core-side surface: the aggregate spendable `P` balance at a reference
/// height. Exposes only the scalar — no decomposition reaches the caller.
///
/// A balance read needs only the aggregate, so it sums the mature amounts
/// directly rather than routing through [`project_drain_operands`], which
/// materialises the stripped candidate vector the *select* stage consumes — a
/// heap allocation a poll-frequency query has no use for. It observes the same
/// carve: only `amount`, gated by the shared [`is_mature`] predicate, never a
/// reward-sequence coordinate.
pub fn drain_balance(
    records: &[PFundingOutputRecord],
    reference_height: BlockHeight,
) -> Result<DrainBalance, DrainError> {
    let spendable = AtomicUnits::checked_sum(
        records
            .iter()
            .filter(|r| is_mature(r, reference_height))
            .map(|r| r.amount),
    )
    .ok_or(DrainError::AmountOverflow)?;
    Ok(DrainBalance { spendable })
}

/// Plan a drain of `target` atomic units out of `P`'s spendable funding
/// outputs at `reference_height`.
///
/// Runs the three F-D1 stages in order — project (this module) → amount
/// ([`choose_drain_amount`], affordability against the aggregate scalar only)
/// → select ([`select_for_drain`], lineage-blind over the stripped vector).
/// `target` is a single scalar (F-D2 core-side contract): the caller cannot
/// hand in a reward decomposition, and the per-output reward vector never
/// reaches the amount stage — so core code cannot *compute* a reward-shaped
/// amount. Steering the returned value away from a subsum is the F-D2 UI
/// default (round-number / random-split), not built here.
pub fn plan_drain(
    records: &[PFundingOutputRecord],
    reference_height: BlockHeight,
    target: AtomicUnits,
) -> Result<DrainPlan, DrainError> {
    let operands = project_drain_operands(records, reference_height)?;
    let amount = choose_drain_amount(DrainRequest { target }, operands.balance.spendable)?;
    let selection = select_for_drain(&operands.candidates, amount, reference_height)?;
    let change = selection
        .input_total
        .checked_sub(amount.get())
        .ok_or(DrainError::AmountOverflow)?;
    Ok(DrainPlan {
        amount: amount.get(),
        inputs: selection.chosen,
        input_total: selection.input_total,
        change,
    })
}

/// Why the drain orchestration pipeline refused before (or at) the actor
/// hand-off (`ARCHIVAL_DRAIN_SEND_FD2.md` §4, DS-PR-2). Every arm is
/// caller-recoverable state, not a defect: resync, lower the payment, or
/// retry per the arm's docs.
///
/// Amount- and gindex-free by construction (the firewall's error-text
/// discipline, `bond_orchestrator::funding_refusal_detail`): the drain
/// amount is the §12.3 taint the firewall keeps dark, so no arm renders a
/// payment figure or a funding output's global index. [`Plan`]'s inner
/// [`DrainError`] arms are already scalar-free; the reference and tree arms
/// carry only public chain/tree facts.
///
/// [`Plan`]: DrainOrchestrationError::Plan
#[derive(Debug, thiserror::Error)]
pub(crate) enum DrainOrchestrationError {
    /// No submittable curve-tree reference can be anchored right now (chain
    /// too short, tree not yet ingesting, tree too far behind the tip, or the
    /// reference-height block hash is outside the wallet's header window).
    /// Resync and retry; assembling against a stale reference would produce a
    /// proof the daemon rejects. Rendered from the shared send-path anchoring
    /// helper ([`anchored_reference_block`]) — its detail strings are
    /// amount-free.
    #[error("no submittable reference can be anchored: {detail}")]
    ReferenceUnanchorable {
        /// The anchoring helper's own (scalar-free) reason.
        detail: String,
    },
    /// The drain would spend a **live** persona's pool below the exit-fee
    /// reserve ([`EXIT_FEE_RESERVE_ATOMIC`]) — draining it there strands the
    /// future terminal `Unbond` (`ARCHIVAL_DRAIN_SEND_FD2.md` DS-4,
    /// `ARCHIVAL_BOND_CONSTRUCTION.md` §7.2). Lower the payment, or retire the
    /// persona first (a post-retirement sweep has no reserve). Scalar-free: it
    /// names neither the payment nor the pool magnitude.
    #[error("drain would spend the live persona pool below the exit-fee reserve")]
    ReserveBreached,
    /// The F-D1 drain planner refused: the requested payment was zero,
    /// exceeded the spendable `P` balance, could not be covered by the
    /// spendable outputs, or the aggregate arithmetic overflowed. Lower the
    /// payment or wait for further `P` accrual (see [`DrainError`]'s arms).
    #[error(transparent)]
    Plan(#[from] DrainError),
    /// A curve-tree handle call failed while assembling membership paths (a
    /// client refusal or a stopped actor) — terminal until the engine
    /// respawns the actor, or a resync for a lagging-ingest refusal.
    #[error("curve tree unavailable or refused: {0:?}")]
    Tree(CurveTreeHandleError),
    /// The path assembly returned a set that does not match the selection
    /// (a count mismatch, or no paths for a non-empty selection) —
    /// structurally unreachable (`assemble_tx` returns exactly one path per
    /// input, and a covered plan selects ≥1 input), so it signals a defect or
    /// corrupt tree state rather than a caller-recoverable refusal. `detail`
    /// carries only public counts, never a gindex or amount.
    #[error("drain path assembly invariant broken: {detail}")]
    PathAssembly {
        /// The (scalar-free) invariant that failed.
        detail: String,
    },
    /// The stake actor refused or failed the drain assembly itself (the
    /// [`DrainAssemblyError`](super::drain_assembly::DrainAssemblyError) it
    /// wraps names the drain-specific reason).
    #[error(transparent)]
    Stake(#[from] StakeEngineError),
}

/// The read-side operands of one drain assembly, borrowed from their owners
/// (the engine's actors, the persisted P-scan state, the live reservation
/// set) plus the engine-resolved principal destination. Bundled so the
/// pipeline's signature names the flow's inputs once — the
/// [`ClaimAssemblyContext`](super::claim_orchestrator::ClaimAssemblyContext)
/// sibling for the value-out path.
///
/// The drain is a **self-initiated** `P`-spend (like a bond post, unlike a
/// claim there is no daemon-side source to fetch): the reference is anchored
/// off the wallet's own `chain_tip` ([`crate::engine::traits::LedgerEngine::synced_height`]),
/// not a fetched `chain_height`.
///
/// Dead_code allow: constructed by the dispatch seam (DS-PR-2 commit 3,
/// `drain_dispatch.rs`) — the same rule-21 staging the [`AssembleDrain`]
/// message carries; reopened when that seam builds the ctx.
#[allow(dead_code)]
pub(crate) struct DrainCtx<'a> {
    /// The stake actor — assembly and signing stay inside it (rule 36).
    pub stake: &'a StakeEngineHandle,
    /// The curve-tree actor — reference root and membership paths.
    pub tree: &'a CurveTreeHandle,
    /// The persona's persisted funding records
    /// (`PScanState::funding_outputs`). Scoped to the handle's slot and
    /// filtered against [`reserved`](Self::reserved) inside the pipeline
    /// before the F-D1 projection.
    pub funding_records: &'a [PFundingOutputRecord],
    /// Live gindex reservations (outputs already committed to in-flight txs —
    /// bond posts, claims, or other drains). Excluded from selection so a
    /// drain can never double-spend an in-flight funding input.
    pub reserved: &'a BTreeSet<GlobalOutputIndex>,
    /// The wallet's own principal destination (vout 0), resolved engine-side
    /// from the primary address (T-DS-3: never caller-supplied).
    pub dest: DrainDestination,
    /// Value to pay to the principal. The selection covers `payment + fee`;
    /// the `P`-space change (`input_total − payment − fee`) is computed by the
    /// assembly, and returns to `P` on a partial drain (T-DS-3).
    pub payment: u64,
    /// The fee the drain tx must fund from its swept `P` inputs.
    pub fee: u64,
    /// Whether the persona is **retired** (its bond has terminally unbonded).
    /// A live persona is a mid-life constructor and must retain the exit-fee
    /// reserve ([`EXIT_FEE_RESERVE_ATOMIC`], DS-4); a retired persona has no
    /// future `Unbond`, so the reserve is moot and a drain-all may sweep the
    /// pool to zero. Resolved engine-side from
    /// [`PScanState::retired_records`](shekyl_engine_state::pscan_state::PScanState::retired_records)
    /// by the dispatch seam.
    pub retired: bool,
    /// The wallet's synced chain tip — the send-path anchor input.
    pub chain_tip: u64,
}

/// The exit-fee reserve a drain of a persona in this liveness state must leave
/// in `P`'s pool (`ARCHIVAL_DRAIN_SEND_FD2.md` DS-4).
///
/// A **live** persona is a mid-life constructor: it retains one
/// pessimistically-priced `Unbond` fee ([`EXIT_FEE_RESERVE_ATOMIC`]) so the
/// terminal `Unbond` stays fundable. A **retired** persona has no future
/// `Unbond`, so the reserve is `0` and a drain-all may take the pool to zero.
fn exit_reserve_atomic(retired: bool) -> u64 {
    if retired {
        0
    } else {
        EXIT_FEE_RESERVE_ATOMIC
    }
}

/// DS-4 exit-reserve gate: does a drain of `target` (`payment + fee`) leave the
/// liveness-appropriate reserve in a pool of `scoped_spendable`?
///
/// The invariant is `target + reserve <= scoped_spendable` for a **live**
/// persona (reserve = [`EXIT_FEE_RESERVE_ATOMIC`]) and `target <=
/// scoped_spendable` for a **retired** one (reserve = 0 — the planner's own
/// affordability check subsumes it, so this is a no-op for a retired sweep).
///
/// A reserve breach is distinct from plain unaffordability: a live drain whose
/// `payment + fee` fits the balance but eats into the reserve is refused here
/// with [`ReserveBreached`](DrainOrchestrationError::ReserveBreached), before
/// the planner sees a target it would otherwise accept. Scalar-free by return
/// type (`Ok(())` / the unit-carrying arm).
fn enforce_exit_reserve(
    scoped_spendable: u64,
    target: u64,
    retired: bool,
) -> Result<(), DrainOrchestrationError> {
    let reserve = exit_reserve_atomic(retired);
    if reserve == 0 {
        return Ok(());
    }
    // `spendable − reserve` is the most a drain may move (payment + fee); a
    // spendable below the reserve leaves nothing drainable at all.
    match scoped_spendable.checked_sub(reserve) {
        Some(max_drainable) if target <= max_drainable => Ok(()),
        _ => Err(DrainOrchestrationError::ReserveBreached),
    }
}

/// Scope `records` to `slot`'s own funding outputs, dropping any whose gindex
/// is already [`reserved`](DrainCtx::reserved) for an in-flight tx.
///
/// `p_slot` and `gindex` are **public** identities (a slot ordinal and a
/// chain-wide output index), not mint-lineage coordinates, so this filter
/// runs *before* the F-D1 projection ([`plan_drain`]) without breaching the
/// §12.3 carve — the same shape the claim/bond sweeps apply their `reserved`
/// exclusion in.
fn scoped_records(
    records: &[PFundingOutputRecord],
    slot: shekyl_types::PSlot,
    reserved: &BTreeSet<GlobalOutputIndex>,
) -> Vec<PFundingOutputRecord> {
    records
        .iter()
        .filter(|r| r.p_slot == slot && !reserved.contains(&r.gindex))
        .cloned()
        .collect()
}

/// Run the full drain pipeline and return the actor's reply — the signed,
/// wire-encoded, transfer-shaped drain plus its spent-gindex reservation set
/// — **unbroadcast** (`ARCHIVAL_DRAIN_SEND_FD2.md` §4; the CB-3 discipline
/// the claim path also follows: the builder never self-schedules, dispatch is
/// the DS-PR-2 seam's).
///
/// A **free function over [`DrainCtx`]**, deliberately not an `Engine` method
/// (the composition-decomposition discipline, `ENGINE_COMPOSITION_DECOMPOSITION.md`):
/// the engine-side entry is a thin façade that resolves the destination,
/// loads the operands, and delegates here — this pipeline never names
/// `Engine`. Steps, in order:
///
/// 1. **Anchor** — one [`ReferenceBlock`](shekyl_curve_tree::ReferenceBlock)
///    via the shared send-path helper ([`anchored_reference_block`], WI-2
///    F-6): reorg-safe ∧ not-too-stale ∧ ingest-available ∧ ledger-present.
///    A drain anchors identically to a bond, so it reuses the exported helper
///    rather than re-deriving `tip − REF_ANCHOR_AGE`.
/// 2. **Scope + plan** — restrict to the handle slot's unreserved records
///    ([`scoped_records`]) and run the F-D1 planner ([`plan_drain`]: project →
///    amount → select, the lineage-blind taint-carve) for `payment + fee`.
/// 3. **Re-map** — the planner returns leaf positions (gindexes); this trust
///    boundary re-maps them to the full records the path assembly needs
///    (`output_key`, `commitment`), preserving the planner's selection order.
/// 4. **Assemble paths** — every membership path against ONE reference
///    snapshot ([`CurveTreeHandle::assemble_tx`]), zipped into
///    [`FundingInputContext`]s + a shared [`TreeContext`] (the exact
///    `assemble_bond_post` shape).
/// 5. **Hand off** — [`StakeEngineHandle::assemble_drain`]; derivation,
///    proving, and signing stay inside the actor, and the reply returns
///    unbroadcast.
///
/// `block_hash_at` resolves the reference-height block hash from the caller's
/// ledger (this pipeline has no ledger access of its own; the engine owns the
/// header window). `handle` is the operation-scoped slot capability; its slot
/// names the record filter.
///
/// Dead_code allow: the dispatch seam (DS-PR-2 commit 3, `drain_dispatch.rs`)
/// and the RPC drain entry are the remaining consumers (rule-21 — reopened
/// when the dispatch seam calls this).
#[allow(dead_code)]
pub(crate) async fn orchestrate_drain(
    handle: PersonaHandle,
    ctx: DrainCtx<'_>,
    block_hash_at: impl FnOnce(u64) -> Option<[u8; 32]>,
) -> Result<AssembledDrain, DrainOrchestrationError> {
    // 1. Anchor one ReferenceBlock via the ordinary send-path procedure
    //    (shared with the bond path — never a hand-rolled `tip − age`, WI-2
    //    F-6). Its refusals are scalar-free; render them into the drain arm.
    let reference = anchored_reference_block(ctx.tree, ctx.chain_tip, block_hash_at)
        .await
        .map_err(|e| DrainOrchestrationError::ReferenceUnanchorable {
            detail: e.to_string(),
        })?;
    let reference_height = BlockHeight::from_raw(reference.height.0);

    // 2. Scope to the persona's own unreserved records, then run the F-D1
    //    planner (project → amount → select). The selection target is
    //    `payment + fee`: both leave `P`, so the swept inputs must cover the
    //    fee as well as the payment (the residual is the change the assembly
    //    returns to `P`). `payment + fee` overflow is a corrupt-state signal,
    //    folded into the planner's own overflow arm.
    let scoped = scoped_records(ctx.funding_records, handle.p_slot(), ctx.reserved);
    let target = ctx
        .payment
        .checked_add(ctx.fee)
        .ok_or(DrainError::AmountOverflow)?;

    // DS-4 exit-reserve enforcement (before selection): a **live** persona must
    // leave `EXIT_FEE_RESERVE_ATOMIC` in the pool so its terminal `Unbond` stays
    // fundable; a **retired** persona reserves nothing and may sweep to zero. A
    // reserve breach (the payment would eat into the reserve) is distinct from
    // plain unaffordability (`plan_drain`'s `Unaffordable`), so it surfaces its
    // own arm. The projection reuses the same `drain_balance` scalar the planner
    // derives, against the same reference height.
    let scoped_spendable = drain_balance(&scoped, reference_height)?.spendable.to_raw();
    enforce_exit_reserve(scoped_spendable, target, ctx.retired)?;

    let plan = plan_drain(&scoped, reference_height, AtomicUnits::from_raw(target))?;

    // 3. Re-map the selected leaf positions to the full records the path
    //    assembly consumes, preserving the planner's (largest-first) order.
    //    Sound `expect`: `plan.inputs` is a subset of `scoped`'s gindexes by
    //    construction — the planner selects only from the candidates this
    //    same scoped set projects.
    let selected: Vec<PFundingOutputRecord> = plan
        .inputs
        .iter()
        .map(|g| {
            scoped
                .iter()
                .find(|r| r.gindex == *g)
                .cloned()
                .expect("plan_drain selects only from the scoped candidate set")
        })
        .collect();

    // 4. Assemble every membership path against ONE reference snapshot, then
    //    zip records↔paths into the funding contexts (the exact
    //    `assemble_bond_post` shape — one shared TreeContext, per-input
    //    leaf chunk + layers).
    let assemble_inputs: Vec<AssembleInput> = selected
        .iter()
        .map(|r| AssembleInput {
            gindex: Gindex(r.gindex.to_raw()),
            output_key: r.output_key,
            commitment: r.commitment,
        })
        .collect();
    let paths = ctx
        .tree
        .assemble_tx(reference, assemble_inputs)
        .await
        .map_err(DrainOrchestrationError::Tree)?;
    if paths.len() != selected.len() {
        return Err(DrainOrchestrationError::PathAssembly {
            detail: format!(
                "expected {} membership paths, got {}",
                selected.len(),
                paths.len()
            ),
        });
    }
    let first = paths
        .first()
        .ok_or_else(|| DrainOrchestrationError::PathAssembly {
            detail: "assemble_tx returned no paths for a non-empty selection".to_owned(),
        })?;
    let tree_ctx = TreeContext {
        reference_block: first.tree.reference_block,
        tree_root: first.tree.tree_root,
        tree_depth: first.tree.tree_depth,
    };
    let funding: Vec<FundingInputContext> = selected
        .into_iter()
        .zip(paths)
        .map(|(record, path)| FundingInputContext {
            record,
            leaf_chunk: path
                .leaf_chunk
                .iter()
                .map(|cl| LeafEntry {
                    output_key: cl.output_key,
                    key_image_gen: cl.key_image_gen,
                    commitment: cl.commitment,
                    h_pqc: cl.h_pqc,
                })
                .collect(),
            c1_layers: path.c1_layers,
            c2_layers: path.c2_layers,
        })
        .collect();

    // 5. Hand the operands to the actor (derivation, proving, signing stay
    //    inside it) and return the reply unbroadcast (CB-3).
    Ok(ctx
        .stake
        .assemble_drain(AssembleDrain {
            handle,
            funding,
            tree_ctx,
            dest: ctx.dest,
            payment_amount: ctx.payment,
            fee: ctx.fee,
        })
        .await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::test_support::funding_record;
    use shekyl_engine_state::pscan_state::MintLineageOutput;

    /// A mature funding record: `funding_record` derives
    /// `spendable_height = height + SPENDABLE_AGE (10)`, so a record minted at
    /// height 90 is provable from height 100 onward.
    fn mature(gindex: u64, amount: u64) -> PFundingOutputRecord {
        funding_record(0, gindex, 90, amount, MintLineageOutput::BondPostChange)
    }

    const REF: u64 = 100;

    #[test]
    fn drain_balance_sums_only_mature_outputs() {
        let mut immature = mature(3, 1_000_000);
        immature.spendable_height = BlockHeight::from_raw(REF + 1);
        let records = [mature(1, 40), mature(2, 60), immature];

        let balance = drain_balance(&records, BlockHeight::from_raw(REF)).expect("projects");

        // 40 + 60; the immature million is excluded from the spendable scalar.
        assert_eq!(balance.spendable, AtomicUnits::from_raw(100));
    }

    #[test]
    fn plan_drain_selects_largest_first_and_returns_change() {
        let records = [mature(1, 30), mature(2, 100), mature(3, 30)];

        let plan = plan_drain(
            &records,
            BlockHeight::from_raw(REF),
            AtomicUnits::from_raw(90),
        )
        .expect("affordable and coverable");

        // Largest single output (100) covers 90; change is 10.
        assert_eq!(plan.amount, AtomicUnits::from_raw(90));
        assert_eq!(plan.inputs, vec![GlobalOutputIndex::from_raw(2)]);
        assert_eq!(plan.input_total, AtomicUnits::from_raw(100));
        assert_eq!(plan.change, AtomicUnits::from_raw(10));
    }

    #[test]
    fn plan_drain_rejects_zero_target() {
        let records = [mature(1, 100)];
        let err = plan_drain(
            &records,
            BlockHeight::from_raw(REF),
            AtomicUnits::from_raw(0),
        );
        assert_eq!(err, Err(DrainError::EmptyRequest));
    }

    #[test]
    fn plan_drain_rejects_target_over_spendable_scalar() {
        // Mature spendable is 100; an immature output cannot lift the ceiling.
        let mut immature = mature(2, 1_000);
        immature.spendable_height = BlockHeight::from_raw(REF + 1);
        let records = [mature(1, 100), immature];

        let err = plan_drain(
            &records,
            BlockHeight::from_raw(REF),
            AtomicUnits::from_raw(101),
        );
        assert_eq!(err, Err(DrainError::Unaffordable));
    }

    #[test]
    fn scoped_records_keeps_own_slot_and_drops_reserved() {
        use shekyl_types::PSlot;

        let s =
            |slot: u32, g: u64| funding_record(slot, g, 90, 100, MintLineageOutput::BondPostChange);
        // slot 0: g1 (keep), g2 (reserved → drop), g4 (keep); slot 1: g3 (foreign → drop).
        let records = [s(0, 1), s(0, 2), s(1, 3), s(0, 4)];
        let reserved: BTreeSet<GlobalOutputIndex> =
            [GlobalOutputIndex::from_raw(2)].into_iter().collect();

        let kept = scoped_records(&records, PSlot::from_raw(0), &reserved);
        let gindexes: Vec<u64> = kept.iter().map(|r| r.gindex.to_raw()).collect();
        assert_eq!(
            gindexes,
            vec![1, 4],
            "keep slot-0 unreserved records; drop the reserved g2 and the foreign-slot g3"
        );
    }

    #[test]
    fn exit_reserve_maps_liveness_to_the_floor() {
        // A live persona holds the pinned reserve; a retired one holds nothing.
        assert_eq!(exit_reserve_atomic(false), EXIT_FEE_RESERVE_ATOMIC);
        assert_eq!(exit_reserve_atomic(true), 0);
    }

    #[test]
    fn live_drain_must_leave_the_reserve() {
        let r = EXIT_FEE_RESERVE_ATOMIC;
        // Pool exactly one payment above the reserve: `payment + fee == r`
        // clears (leaves the reserve on the nose); one atomic more breaches.
        let pool = 2 * r;
        assert!(
            enforce_exit_reserve(pool, r, false).is_ok(),
            "target that leaves exactly the reserve is allowed"
        );
        assert!(
            matches!(
                enforce_exit_reserve(pool, r + 1, false),
                Err(DrainOrchestrationError::ReserveBreached)
            ),
            "one atomic into the reserve is refused"
        );
    }

    #[test]
    fn live_drain_below_reserve_pool_is_wholly_undrainable() {
        // A pool that cannot even cover the reserve leaves nothing drainable:
        // every positive target breaches (the `checked_sub` underflow arm).
        assert!(matches!(
            enforce_exit_reserve(EXIT_FEE_RESERVE_ATOMIC - 1, 1, false),
            Err(DrainOrchestrationError::ReserveBreached)
        ));
    }

    #[test]
    fn retired_sweep_ignores_the_reserve() {
        // A retired persona reserves nothing: a drain-all to the last atomic is
        // allowed, and the guard defers unaffordability entirely to the planner.
        let pool = EXIT_FEE_RESERVE_ATOMIC; // below the live floor, irrelevant here
        assert!(
            enforce_exit_reserve(pool, pool, true).is_ok(),
            "retired sweep of the whole pool clears the reserve gate"
        );
        // Even an over-balance target passes *this* gate (retired ⇒ no-op); the
        // planner's `Unaffordable` is the arm that catches it downstream.
        assert!(enforce_exit_reserve(pool, pool + 1, true).is_ok());
    }

    /// Composition + firewall pins (`wire.rs`-tripwire style; the test module
    /// is split off so the needles cannot self-match):
    ///
    /// 1. the drain pipeline is a **free function** over [`DrainCtx`], not an
    ///    `Engine` method — no `self_arc`, no `Arc<RwLock<Self>>` (the
    ///    `ENGINE_COMPOSITION_DECOMPOSITION.md` discipline the engine-side
    ///    entry delegates through);
    /// 2. selection routes ONLY through the F-D1 planner ([`plan_drain`]) —
    ///    never the bond sweep (`sweep_funding_outputs`), which would bypass
    ///    the §12.3 drain-amount taint-carve.
    #[test]
    fn orchestrate_drain_is_a_free_function_over_the_fd1_carve() {
        let (src, _tests) = include_str!("drain_orchestrator.rs")
            .split_once("\n#[cfg(test)]")
            .expect("drain_orchestrator.rs has a #[cfg(test)] section to exclude from the scan");

        let free_fn = concat!("pub(crate) async fn orchestrate", "_drain(");
        assert!(
            src.contains(free_fn),
            "the drain pipeline must be a free function over DrainCtx"
        );
        assert!(
            !src.contains("self_arc"),
            "orchestrate_drain must not be an Engine method (no self_arc)"
        );
        assert!(
            !src.contains("Arc<RwLock"),
            "orchestrate_drain must not hold the Engine lock"
        );

        let carve_call = concat!("plan", "_drain(");
        assert!(
            src.contains(carve_call),
            "selection must route through the F-D1 planner (plan_drain)"
        );
        let bond_sweep = concat!("sweep", "_funding_outputs(");
        assert!(
            !src.contains(bond_sweep),
            "the drain must not select via the bond sweep (it bypasses the §12.3 carve)"
        );
    }
}
