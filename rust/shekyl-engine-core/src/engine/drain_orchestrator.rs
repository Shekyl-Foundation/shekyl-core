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
use shekyl_engine_state::pscan_state::{PFundingOutputRecord, PScanState};
use shekyl_standoff::EXIT_FEE_RESERVE_ATOMIC;
use shekyl_tx_builder::{LeafEntry, TreeContext};
use shekyl_types::{BlockHeight, GlobalOutputIndex, PCanonicalId};
use shekyl_units::AtomicUnits;

use super::bond_assembly::{FundingInputContext, SpentRecordsDurablyPruned};
use super::bond_orchestrator::anchored_reference_block;
use super::curve_tree_actor::{CurveTreeHandle, CurveTreeHandleError};
use super::drain_amount::{choose_drain_amount, DrainAmountError, DrainRequest};
use super::drain_assembly::{AssembleDrain, AssembledDrain, DrainDestination};
use super::drain_select::{
    select_for_drain, select_for_sweep, DrainCandidate, DrainSelectError, SweepSelectError,
};
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
    /// The amount is affordable against the aggregate scalar but needs more
    /// inputs than one drain transaction can spend
    /// (`shekyl_tx_builder::MAX_INPUTS`) — a fragmented pool. Reachable
    /// through [`plan_drain`] (unlike [`Self::InsufficientSpendable`]): the
    /// affordability check reads the whole spendable sum, while selection is
    /// capped. User-actionable: lower the amount and drain in more passes.
    #[error(
        "the drain amount needs more inputs than one drain can spend — \
         lower the amount and drain in more than one pass"
    )]
    InputCapExceeded,
    /// Atomic-unit arithmetic overflowed while aggregating or computing
    /// change (structurally unreachable under the supply cap; a corrupt state
    /// otherwise).
    #[error("atomic-unit arithmetic overflowed while planning the drain")]
    AmountOverflow,
    /// Terminal sweep: no candidate is mature at the reference height —
    /// nothing is provable yet. The remedy is "wait for the exit payout (or
    /// the last pass's residue) to mature", distinct from the dust arm.
    #[error("nothing in the exited persona's pool is spendable yet — wait for maturity")]
    SweepNothingSpendable,
    /// Terminal sweep: the mature pool cannot fund a valid pass — the fee
    /// plus the 2-atomic-unit minimum the zero-change two-output split can
    /// pay (T-DS-6). The named dust residual (`collect_unstaked` docs): it
    /// stays in `P`, and the funded retirement gate stays held by it, until
    /// further value matures into the slot or the fee floor moves.
    /// Scalar-free.
    #[error("the exited persona's spendable residue is too small to move")]
    SweepDustPool,
}

impl From<SweepSelectError> for DrainError {
    fn from(e: SweepSelectError) -> Self {
        match e {
            SweepSelectError::NothingSpendable => DrainError::SweepNothingSpendable,
            SweepSelectError::DustPool => DrainError::SweepDustPool,
            SweepSelectError::Overflow => DrainError::AmountOverflow,
        }
    }
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
            DrainSelectError::InputCapExceeded => DrainError::InputCapExceeded,
            DrainSelectError::Overflow => DrainError::AmountOverflow,
        }
    }
}

/// Witness that a persona's **terminal exit is already public on-chain**:
/// its confirmed `Unbond` sits in the sealed P-scan state's
/// [`pending_unbonds`](PScanState::pending_unbonds) — the same authoritative
/// "no future `Unbond` is owed" signal the dispatch seam's reserve exemption
/// reads.
///
/// Private field + the one fallible constructor, so a
/// [`DrainIntent::TerminalSweep`] is **unconstructable for a live persona**
/// at the type level (the `load_seal_basis` unconstructable-pair pattern):
/// the witness makes façade-level misuse a compile error, while the
/// AUTHORITATIVE check stays the dispatch seam's own basis re-resolution —
/// a witness minted from one seal read can be stale by the seam's, and the
/// seam refuses the divergence rather than trusting the token
/// (`submit_drain`).
#[derive(Clone, Copy)]
pub(crate) struct TerminalExitObserved {
    p_canonical_id: PCanonicalId,
}

impl TerminalExitObserved {
    /// Mint the witness iff `p_canonical_id`'s terminal `Unbond` has been
    /// observed confirmed on-chain. `None` for a live persona — the caller
    /// has no sweep to request.
    pub(crate) fn for_persona(pscan: &PScanState, p_canonical_id: PCanonicalId) -> Option<Self> {
        pscan
            .pending_unbonds()
            .contains_key(&p_canonical_id)
            .then_some(Self { p_canonical_id })
    }

    /// The exited persona the witness names.
    pub(crate) fn p_canonical_id(&self) -> PCanonicalId {
        self.p_canonical_id
    }
}

impl std::fmt::Debug for TerminalExitObserved {
    /// The exit itself is public on-chain, but the id still follows the
    /// persona-key no-clear-`Debug` discipline of the state it was minted
    /// from.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TerminalExitObserved(<redacted persona>)")
    }
}

/// What one drain moves: a user-target payment, or the terminal sweep.
///
/// The `Payment` arm is WI-RPC-5's `drain` — the amount is user intent,
/// validated by the F-D1 amount stage. The `TerminalSweep` arm is
/// `collect_unstaked`'s — no caller amount exists; the pass's payment is an
/// output of selection (`Σ selected − fee`,
/// [`select_for_sweep`]), reachable only under a [`TerminalExitObserved`]
/// witness. Exactness is the sweep's purpose: the funded retirement gate
/// needs the slot at zero, and a shaped or user-guessed amount leaves dust
/// forever (the `unstake_facade` finding).
#[derive(Debug)]
pub(crate) enum DrainIntent {
    /// Move exactly this user-requested amount to the principal; the
    /// residual returns to `P` as change.
    Payment(AtomicUnits),
    /// Sweep the exited persona's pool to the principal, one capped pass at
    /// a time, zero change by construction.
    TerminalSweep(TerminalExitObserved),
}

/// What one orchestrated drain moved — the output twin of [`DrainIntent`].
/// A payment has no remainder; a sweep's remainder is required. Flattening
/// that into `Option` made a missing completion fact representable, and
/// `collect_unstaked` then had to reconstruct the invariant at the façade.
#[derive(Debug)]
pub(crate) enum DrainMoved {
    /// User-target payment; change (if any) returns to `P`.
    Payment(AtomicUnits),
    /// Terminal sweep: `payment` is `Σ selected − fee`, `remainder` is the
    /// unfiltered slot residue (the completion fact).
    Sweep {
        payment: AtomicUnits,
        remainder: AtomicUnits,
    },
}

impl DrainMoved {
    fn payment(&self) -> AtomicUnits {
        match *self {
            Self::Payment(p) | Self::Sweep { payment: p, .. } => p,
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
/// `{lineage, epoch, height}`, keep only the provable (mature) **and
/// unreserved** subset, and reduce to the aggregate scalar + the stripped
/// candidate vector.
///
/// `reserved` is the gindex union already committed to in-flight bond posts /
/// claims / drains (`PendingPostBlock::reserved_gindexes`). Excluding it here —
/// the *same* carve [`drain_balance`] applies — keeps both operands consistent:
/// the spendable scalar the amount stage checks affordability against, and the
/// candidate set [`select_for_drain`] draws from, are one net set. That is what
/// makes the totals reconcile (a plan can never be sized against funds a live tx
/// already holds) and structurally bars the selector from choosing a reserved
/// output — a double-spend of an in-flight input — regardless of whether the
/// caller pre-scoped the records. A gindex is a public curve-tree leaf position,
/// so the filter stays lineage-blind.
///
/// This is the sole site that reads the funding record's stripped-away
/// fields; the operands it returns carry none of them.
fn project_drain_operands(
    records: &[PFundingOutputRecord],
    reference_height: BlockHeight,
    reserved: &BTreeSet<GlobalOutputIndex>,
) -> Result<DrainOperands, DrainError> {
    let candidates: Vec<DrainCandidate> = records
        .iter()
        .filter(|r| is_mature(r, reference_height) && !reserved.contains(&r.gindex))
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
/// "Spendable" is **mature ∧ unreserved** — the codebase's standing definition
/// of a persona's usable `P` funding (`bond_assembly`'s sweep sums the
/// *unreserved* mature records, and `InsufficientFunding.available` is their
/// sum). `reserved` is the union of gindexes already committed to in-flight
/// bond posts / claims / drains (`PendingPostBlock::reserved_gindexes`); an
/// output a live tx holds cannot also be drained, so counting it would
/// over-report "drainable". A gindex is a public curve-tree leaf position, so
/// the filter stays lineage-blind — never a reward-sequence coordinate.
///
/// A balance read needs only the aggregate, so it sums the eligible amounts
/// directly rather than routing through [`project_drain_operands`], which
/// materialises the stripped candidate vector the *select* stage consumes — a
/// heap allocation a poll-frequency query has no use for. It observes the same
/// carve: only `amount`, gated by the shared [`is_mature`] predicate.
///
/// Takes any borrowing iterator so a caller can chain its own scoping
/// predicate (the read path filters to the active slot) without cloning the
/// records — each carries an ML-KEM ciphertext buffer, and this runs at poll
/// frequency — while the mature ∧ unreserved definition stays here, in one
/// place.
pub fn drain_balance<'a>(
    records: impl IntoIterator<Item = &'a PFundingOutputRecord>,
    reference_height: BlockHeight,
    reserved: &BTreeSet<GlobalOutputIndex>,
) -> Result<DrainBalance, DrainError> {
    let spendable = AtomicUnits::checked_sum(
        records
            .into_iter()
            .filter(|r| is_mature(r, reference_height) && !reserved.contains(&r.gindex))
            .map(|r| r.amount),
    )
    .ok_or(DrainError::AmountOverflow)?;
    Ok(DrainBalance { spendable })
}

/// Plan a drain of `target` atomic units out of `P`'s spendable funding
/// outputs at `reference_height`.
///
/// Runs the three F-D1 stages in order — project (this module; mature ∧
/// unreserved) → amount ([`choose_drain_amount`], affordability against the
/// aggregate scalar only) → select ([`select_for_drain`], lineage-blind over the
/// stripped vector). `reserved` (the in-flight gindex union) is excluded at the
/// projection, so the spendable scalar, the affordability check, and the
/// selectable candidates are one consistent net set — a drain can neither be
/// planned against nor select an output an in-flight tx already holds, and its
/// figure reconciles with the [`drain_balance`] read.
///
/// `target` is a single scalar (F-D2 core-side contract): the caller cannot
/// hand in a reward decomposition, and the per-output reward vector never
/// reaches the amount stage — so core code cannot *compute* a reward-shaped
/// amount. Steering the returned value away from a subsum is the F-D2 UI
/// default (round-number / random-split), not built here.
pub fn plan_drain(
    records: &[PFundingOutputRecord],
    reference_height: BlockHeight,
    target: AtomicUnits,
    reserved: &BTreeSet<GlobalOutputIndex>,
) -> Result<DrainPlan, DrainError> {
    let operands = project_drain_operands(records, reference_height, reserved)?;
    plan_from_operands(&operands, reference_height, target)
}

/// Run the amount + select stages over already-projected [`DrainOperands`] —
/// the half of [`plan_drain`] that follows the projection. Split out so a
/// caller that already holds the operands (the orchestrator, which projects
/// once to feed both the reserve gate and the planner) does not re-project the
/// same records a second time.
fn plan_from_operands(
    operands: &DrainOperands,
    reference_height: BlockHeight,
    target: AtomicUnits,
) -> Result<DrainPlan, DrainError> {
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
    /// A [`DrainIntent::TerminalSweep`] arrived for a persona the pipeline's
    /// own `retired` resolution says is still live. The witness certifies an
    /// *earlier* seal read; the seam's basis re-resolution is authoritative,
    /// and a divergence fails closed here (belt to the seam's own refusal)
    /// rather than sweeping a live persona's pool through the reserve it
    /// still owes.
    #[error("terminal sweep refused: the persona's exit is not observed confirmed")]
    SweepOnLivePersona,
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
/// Constructed by the dispatch seam ([`crate::engine::drain_dispatch`]) — the
/// `claim_dispatch`/`ClaimAssemblyContext` sibling.
pub(crate) struct DrainCtx<'a> {
    /// The stake actor — assembly and signing stay inside it (rule 36).
    pub stake: &'a StakeEngineHandle,
    /// The curve-tree actor — reference root and membership paths.
    pub tree: &'a CurveTreeHandle,
    /// Witness that durable pruning of spent funding outputs has landed
    /// (SP-R0). Held to the funding-output selection site ([`scoped_records`])
    /// exactly as the bond/claim spenders hold it, so the drain's production
    /// go-live is compile-blocked on the same production mint.
    pub pruning_landed: &'a SpentRecordsDurablyPruned,
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
    /// What the drain moves. `Payment`: the selection covers `payment + fee`;
    /// the `P`-space change (`input_total − payment − fee`) is computed by the
    /// assembly, and returns to `P` on a partial drain (T-DS-3).
    /// `TerminalSweep`: the payment is an output of selection
    /// (`Σ selected − fee`), zero change by construction; legal only for a
    /// retired persona (the witness proposes, [`Self::retired`] disposes).
    pub intent: DrainIntent,
    /// The fee the drain tx must fund from its swept `P` inputs.
    pub fee: u64,
    /// Whether the persona is **retired** (its terminal `Unbond` has
    /// confirmed). A live persona is a mid-life constructor and must retain the
    /// exit-fee reserve ([`EXIT_FEE_RESERVE_ATOMIC`], DS-4); a retired persona
    /// has no future `Unbond`, so the reserve is moot and a drain-all may sweep
    /// the pool to zero. Resolved engine-side by the dispatch seam from
    /// [`PScanState::pending_unbonds`](shekyl_engine_state::pscan_state::PScanState::pending_unbonds)
    /// — the authoritative "no future `Unbond` owed" signal — deliberately not
    /// `retired_records`, which is funded-gated and omits a persona throughout
    /// the very drain-all that empties its slot (see `submit_drain` for the
    /// reserve deadlock this avoids).
    pub retired: bool,
    /// The wallet's synced chain tip — the send-path anchor input.
    pub chain_tip: u64,
}

/// The terminal sweep's pool residue: everything the pass leaves on the
/// slot — Σ over ALL of the slot's unspent records minus the pass's input
/// total. Summed over the **unfiltered** slot set on purpose: the
/// selection stage receives only the mature ∧ unreserved
/// candidates, so a residue summed there silently drops the immature class
/// — a pass emptying the mature subset would then report `0`, the CLI
/// would declare the collection complete, and the immature payouts would
/// sit in the slot holding the funded retirement gate with nothing telling
/// the caller to return. `0` from THIS sum is the genuine completion fact:
/// no record of any maturity remains beyond the pass.
///
/// A record reserved by another in-flight operation still counts — it is
/// still in the slot now, and if its holder releases rather than settles it
/// will still need collecting; the conservative figure is the honest one.
fn sweep_slot_remainder(
    records: &[PFundingOutputRecord],
    slot: super::stake_engine::PSlot,
    input_total: AtomicUnits,
) -> Result<AtomicUnits, DrainError> {
    let slot_total = AtomicUnits::checked_sum(
        records
            .iter()
            .filter(|r| r.p_slot == slot)
            .map(|r| r.amount),
    )
    .ok_or(DrainError::AmountOverflow)?;
    slot_total
        .checked_sub(input_total)
        .ok_or(DrainError::AmountOverflow)
}

/// One orchestrated drain: the actor's assembled reply plus the pipeline's
/// own resolution of what it moves ([`DrainMoved`] — the output twin of
/// [`DrainIntent`], so a sweep receipt cannot forget its remainder and a
/// payment receipt cannot carry one).
pub(crate) struct OrchestratedDrain {
    /// The actor's assembled, unbroadcast reply.
    pub assembled: AssembledDrain,
    /// What this drain moved.
    pub moved: DrainMoved,
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
/// the planner sees a target it would otherwise accept. A target that exceeds
/// the *whole* pool is plain unaffordability, **not** a reserve breach: this
/// gate defers it so the planner surfaces
/// [`Unaffordable`](DrainError::Unaffordable) — the actionable "too large" error
/// — rather than the misleading reserve arm (Copilot r3626008352). Scalar-free
/// by return type (`Ok(())` / the unit-carrying arm).
fn enforce_exit_reserve(
    scoped_spendable: u64,
    target: u64,
    retired: bool,
) -> Result<(), DrainOrchestrationError> {
    let reserve = exit_reserve_atomic(retired);
    if reserve == 0 {
        return Ok(());
    }
    // Plain unaffordability (`target` exceeds the entire pool) is the planner's
    // `Unaffordable` to name, not a reserve breach — defer it so the caller gets
    // the actionable "too-large payment/fee" error instead of a misleading
    // reserve refusal. Only a target that FITS the pool yet would eat into the
    // reserve is a breach here.
    if target > scoped_spendable {
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
///
/// Takes the [`SpentRecordsDurablyPruned`] witness for the identical reason the
/// bond sweep ([`sweep_funding_outputs`](super::bond_assembly::sweep_funding_outputs))
/// does: `reserved` covers only *live* pending posts, so a funding output spent
/// by a drain/bond/claim that has since **confirmed** is un-reserved yet still
/// present in `records` until durable pruning lands (SP-R0). Selecting it would
/// assemble a double-spend. The witness makes that sequencing compile-enforced —
/// the drain path's go-live is blocked on the same production mint the sibling
/// spenders wait for.
fn scoped_records(
    _pruning_landed: &SpentRecordsDurablyPruned,
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
///    ([`scoped_records`]) and plan per the intent: a payment runs the F-D1
///    amount+select half ([`plan_from_operands`]) for `payment + fee`; a
///    terminal sweep runs [`select_for_sweep`] (payment is an output of
///    selection; the F-D1 amount stage is not consulted).
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
/// Called by the dispatch seam ([`crate::engine::drain_dispatch`], the
/// `claim_dispatch` sibling); the RPC drain entry drives that seam.
pub(crate) async fn orchestrate_drain(
    handle: PersonaHandle,
    ctx: DrainCtx<'_>,
    block_hash_at: impl FnOnce(u64) -> Option<[u8; 32]>,
) -> Result<OrchestratedDrain, DrainOrchestrationError> {
    // 1. Anchor one ReferenceBlock via the ordinary send-path procedure
    //    (shared with the bond path — never a hand-rolled `tip − age`, WI-2
    //    F-6). Its refusals are scalar-free; render them into the drain arm.
    let reference = anchored_reference_block(ctx.tree, ctx.chain_tip, block_hash_at)
        .await
        .map_err(|e| DrainOrchestrationError::ReferenceUnanchorable {
            detail: e.to_string(),
        })?;
    let reference_height = BlockHeight::from_raw(reference.height.0);

    // 2. Scope to the persona's own unreserved records, then plan per the
    //    intent: the F-D1 planner (project → amount → select) for a payment
    //    — its selection target is `payment + fee`, both leave `P`, and the
    //    residual is the change the assembly returns to `P` — or the sweep
    //    selector for a terminal sweep, whose payment is an output of
    //    selection and whose change is zero by construction. Arithmetic
    //    overflow is a corrupt-state signal either way, folded into the
    //    planner's own overflow arm.
    let scoped = scoped_records(
        ctx.pruning_landed,
        ctx.funding_records,
        handle.p_slot(),
        ctx.reserved,
    );
    // Project the scoped records **once**: the same mature ∧ unreserved pass
    // yields both the aggregate scalar (the reserve gate's input, also the F-D2
    // balance surface) and the stripped candidate vector the planner selects
    // over — rather than summing in `drain_balance` and then re-summing inside
    // `plan_drain`'s own projection. `scoped` is already reserved-free
    // (`scoped_records`), so passing `ctx.reserved` here is defense in depth:
    // the projection is net by construction, so no caller — scoped or not — can
    // produce a plan sized against, or selecting, an in-flight-held output.
    let operands = project_drain_operands(&scoped, reference_height, ctx.reserved)?;
    let scoped_spendable = operands.balance.spendable.to_raw();

    let (plan, moved) = match ctx.intent {
        DrainIntent::Payment(payment) => {
            let target = payment
                .to_raw()
                .checked_add(ctx.fee)
                .ok_or(DrainError::AmountOverflow)?;

            // DS-4 exit-reserve enforcement (before selection): a **live**
            // persona must leave `EXIT_FEE_RESERVE_ATOMIC` in the pool so its
            // terminal `Unbond` stays fundable; a **retired** persona
            // reserves nothing and may sweep to zero. A reserve breach (the
            // payment would eat into the reserve) is distinct from plain
            // unaffordability (`plan_drain`'s `Unaffordable`), so it
            // surfaces its own arm.
            enforce_exit_reserve(scoped_spendable, target, ctx.retired)?;

            let plan =
                plan_from_operands(&operands, reference_height, AtomicUnits::from_raw(target))?;
            (plan, DrainMoved::Payment(payment))
        }
        DrainIntent::TerminalSweep(_witness) => {
            // The witness proposes; the seam's own basis resolution disposes
            // — a stale witness (exit re-orged out between the façade's read
            // and the seam's) fails closed here rather than sweeping through
            // the reserve a live persona still owes.
            if !ctx.retired {
                return Err(DrainOrchestrationError::SweepOnLivePersona);
            }
            let sweep = select_for_sweep(
                &operands.candidates,
                AtomicUnits::from_raw(ctx.fee),
                reference_height,
            )
            .map_err(DrainError::from)?;
            // The remainder is summed over the slot's UNfiltered records —
            // never the projection's mature-only candidates (its doc).
            let remainder =
                sweep_slot_remainder(ctx.funding_records, handle.p_slot(), sweep.input_total)?;
            let plan = DrainPlan {
                // `amount` is the selection target (`payment + fee`), which
                // for a sweep is exactly the pass's input total: zero change.
                amount: sweep.input_total,
                inputs: sweep.chosen,
                input_total: sweep.input_total,
                change: AtomicUnits::ZERO,
            };
            (
                plan,
                DrainMoved::Sweep {
                    payment: sweep.payment,
                    remainder,
                },
            )
        }
    };

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
    let assembled = ctx
        .stake
        .assemble_drain(AssembleDrain {
            handle,
            funding,
            tree_ctx,
            dest: ctx.dest,
            payment_amount: moved.payment().to_raw(),
            fee: ctx.fee,
        })
        .await?;
    Ok(OrchestratedDrain { assembled, moved })
}

#[cfg(test)]
#[path = "drain_orchestrator_tests.rs"]
mod tests;
