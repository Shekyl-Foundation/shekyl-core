// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The **public** exit façade (PR-C): the composed `unstake` verb, discharged
//! across two named actions on [`StakeFacade`] —
//! [`StakeFacade::unstake`] (the irreversible `Unbond` **post**) and
//! [`StakeFacade::collect_unstaked`] (the **terminal sweep** of the released
//! collateral to principal).
//!
//! ## Why two verbs, not one
//!
//! A verb overload is an ergonomics question **until its resolution ladder
//! can fall through to an irreversible action**. A single `unstake` that
//! "posts if nothing is exited, else sweeps" mis-fires exactly when the
//! caller's mental model and the engine's state have diverged: with persona
//! A exited but its payouts still immature and persona B still bonded, a
//! "finish A" call finds nothing sweepable, falls through, and posts **B's**
//! irreversible exit. Multi-bonded is a routine state (the archival model
//! rotates while bonded — `emission_source.rs`), so the fallback is a trap,
//! not an edge. Two verbs, each refusing outside its own state, cannot
//! mis-select the irreversible step. The frozen §2 method surface
//! (`PRINCIPAL_STAKE_LIFECYCLE.md`) keeps `unbond()` and `drain()` as
//! separate signatures for the same reason.
//!
//! ## The wire never names a slot
//!
//! Both verbs resolve their persona engine-side (the `first_stake`
//! precedent: the user never names a slot). `unstake` picks the **first
//! live-bonded slot** — the [`live_bonded_personas`] set (confirmed
//! JoinMarket bond, not pending-unbond, not retired) intersected with the
//! persisted slot↔id cache, lowest slot first; a multi-bonded wallet exits
//! one persona per invocation. `collect_unstaked` picks the first slot
//! whose persona has an **observed confirmed exit**
//! ([`PScanState::pending_unbonds`]). Neither verb copies
//! `drain_to_principal`'s active-persona resolution: the persona being
//! exited or collected is routinely *not* the active one, and an
//! active-only verb would strand every rotated-away persona's collateral
//! (the `submit_unbond` slot rationale, one level up).
//!
//! ## The finding this façade discharges
//!
//! Until this PR, the funded retirement gate (`pscan/task.rs`
//! `dispatch_retires` / `RetireOutcome::SkippedFunded`) had **passing
//! coverage and zero production reach**: emptying a slot requires a drain
//! of exactly `spendable − fee`, the fee is an internal quote over a live
//! daemon estimate ([`p_lane_floor_fee`]) — never a parameter, never
//! exposed by any RPC read — and `get_drain_balance` is gross-of-fee, so no
//! user path could construct the zero the gate fires on (the normal exit
//! arc always leaves outputs on the slot: the bond post's change, then the
//! exit's payout pair). The retire engine walk (#575) observed the gate
//! fire only on synthetically constructed states. The terminal sweep is
//! what makes it reachable: its payment is an **output of selection**
//! (`Σ selected − fee`, [`select_for_sweep`](super::drain_select)), zero
//! change by construction, reachable only under a [`TerminalExitObserved`]
//! witness — the carve-amendment rationale lives on that selection arm and
//! in `PRINCIPAL_STAKE_LIFECYCLE.md`.
//!
//! ## Completion is a reported fact, never an implication
//!
//! One sweep pass spends at most `MAX_INPUTS` inputs, and immature payouts
//! wait — so a pass may not finish the collection. The verb's name claims
//! collection, not completion, and [`CollectOutcome::Swept`] carries
//! `remainder`: `0` means nothing beyond this pass; nonzero means call
//! again once the residue matures or this pass confirms. The engine knows
//! the remainder; the caller cannot infer it from any payment figure.
//!
//! ## Failure disposition (the irreversible-path posture)
//!
//! `unstake` inherits the dispatch seam's contract: seal-before-send, a
//! definite first-send refusal releases the seal (retry at will), a
//! retryable/ambiguous failure HOLDS it (funds-safe; the lane stays shut
//! until the recovery slice lands — `docs/FOLLOWUPS.md`, the dispatch-driver
//! prune + resubmit, a registered SECURITY-coupled slice deliberately not
//! pulled in here). The error arms below keep those dispositions distinct
//! ([`UnstakeError::ExitRefusedAndReleased`] vs
//! [`UnstakeError::ExitFateUnknown`]) because they demand opposite caller
//! behavior.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use shekyl_engine_file::WalletFile;
use shekyl_engine_state::pscan_state::PScanState;
use shekyl_engine_state::PendingPostBlock;
use shekyl_types::{PCanonicalId, PSlot};
use shekyl_units::AtomicUnits;
use tokio::sync::RwLock;

use super::bond_assembly::SpentRecordsDurablyPruned;
use super::bond_orchestrator::p_lane_floor_fee;
use super::drain_dispatch::DrainRequestError;
use super::drain_orchestrator::{
    DrainError, DrainIntent, DrainMoved, DrainOrchestrationError, TerminalExitObserved,
};
use super::emission_source::EmissionSourceError;
use super::fee_policy::FeeEstimatorError;
use super::pending::TxHash;
use super::prpc::LocalNodeRpc;
use super::signer::EngineSignerKind;
use super::stake_engine::StakeEngineError;
use super::stake_facade::StakeFacade;
use super::staking_read::live_bonded_personas;
use super::traits::{DaemonEngine, EconomicsEngine, PendingTxEngine, RefreshEngine};
use super::transaction_submitter::{BroadcastSubmitError, SubmitSuccess, SubmitterError};
use super::unbond_dispatch::UnbondRequestError;
use super::{Engine, LocalLedger, StakingReadError};

/// The record fetch (and only the fetch) rides the loopback exit transport;
/// one bounded round trip, the serving host's claim-source shape.
const EXIT_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// What one `unstake` did: the network verdict on the dispatched exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnstakeOutcome {
    /// The exit bytes are held by the daemon and network-exposed (accepted
    /// or already pooled), not yet settled. Once its connect is observed,
    /// [`StakeFacade::collect_unstaked`] takes over.
    Broadcast {
        /// The locally computed tx id.
        tx_hash: TxHash,
    },
    /// A previously-sealed identical exit was found confirmed in the main
    /// chain at submit time.
    AlreadyInChain {
        /// The locally computed tx id.
        tx_hash: TxHash,
        /// Daemon-claimed confirming-block height (untrusted; a release-path
        /// discriminant, never settlement truth).
        height: u64,
    },
}

/// Why [`StakeFacade::unstake`] refused, flattened for the `pub` boundary
/// (the [`DrainToPrincipalError`](super::drain_facade::DrainToPrincipalError)
/// shape). Arms are cut by remedy (rule 82); renderings follow the exit
/// path's bond-parity posture (`unbond_dispatch` module docs): the exit
/// never draws the P→principal edge, so its refusals may name `P`-side
/// operands to the `P`-side caller.
#[derive(Debug, thiserror::Error)]
pub enum UnstakeError {
    /// This wallet runs no stake engine — it is not an archival staker, and
    /// the exit path does not exist here.
    #[error("this wallet is not a staker: no stake engine is running")]
    NotStaker,
    /// No persona holds a live confirmed bond, and nothing is mid-exit —
    /// there is nothing to unstake.
    #[error("nothing is staked: no persona holds a live bond")]
    NothingStaked,
    /// The only bond activity is an in-flight bond **post** — its connect
    /// sets the balance the exit must debit exactly, so wait for it to
    /// confirm, then unstake.
    #[error(
        "your stake is still confirming: a bond post is in flight — wait for it \
         to confirm, then unstake"
    )]
    BondConfirming,
    /// An exit is already in progress for every bonded persona: either a
    /// dispatched exit not yet confirmed (one live exit per persona), or a
    /// confirmed exit awaiting collection. The next step is waiting or
    /// [`StakeFacade::collect_unstaked`], never a second post.
    #[error(
        "an exit is already in progress — wait for it to confirm, then collect \
         the released collateral with collect_unstaked"
    )]
    ExitInProgress,
    /// The record refuses to exit **yet** — consensus's own readiness
    /// predicates (cooldown, slash-settlement watermark, interval log).
    /// `detail` is the predicate's own rendering, which carries the operands
    /// that say when the refusal lifts (the `UnbondNotReady` arms,
    /// `stake_engine/types.rs`) — one remedy class (wait), so one arm
    /// (rule 82).
    #[error("the exit is not ready: {detail}")]
    NotReady {
        /// The readiness predicate's own rendering.
        detail: String,
    },
    /// The daemon holds no bond record for the resolved persona — the wallet
    /// and the chain disagree about this stake; resync before exiting.
    #[error(
        "the daemon holds no bond record for this persona — the wallet and \
         chain disagree; resync and retry"
    )]
    NoBondRecord,
    /// The exit-transport constructor refused the daemon address (the ①
    /// local posture accepts loopback only).
    #[error("exit transport: {detail}")]
    Transport {
        /// The constructor's own reason.
        detail: String,
    },
    /// The exit's funding inputs are no longer current — retry against a
    /// fresh snapshot.
    #[error(
        "the exit's funding inputs are no longer current — another live record \
         holds one, or a reservation was released mid-assembly; retry"
    )]
    InputRaced,
    /// The wallet's reference view lags the chain — transient; let the
    /// wallet sync and retry.
    #[error("the wallet's reference view is still syncing: {detail}")]
    Resyncing {
        /// The assembly's own (public chain-fact) reason.
        detail: String,
    },
    /// A daemon query needed to prepare the exit failed transiently — a
    /// connection/status failure fetching the bond record, or the dispatch-tip
    /// clock read. All are pre-seal, so nothing propagated: check the daemon
    /// and retry. NOT an internal fault (review-5): every other P-lane verb
    /// keeps working over a reachable daemon, so an opaque `-32603` on exactly
    /// this one is the hard-to-diagnose shape rule 82 forbids.
    #[error("the daemon could not be reached to prepare the exit: {detail}")]
    DaemonUnreachable {
        /// Which daemon query failed, and the transport's own reason.
        detail: String,
    },
    /// The exit's floor fee cannot be funded from the persona pool **yet**
    /// (no spendable funding, an output still mid-drain, or a shortfall the
    /// assembly names). Wait for outputs to mature or land, then retry —
    /// the walk's own retry family.
    #[error("the exit cannot be funded from the persona pool yet: {detail}")]
    ExitNotFundable {
        /// The assembly's own reason (bond-parity rendering).
        detail: String,
    },
    /// The daemon fee-estimate query failed — check the daemon connection
    /// and retry (the shared `-29102` remedy shape `drain` and
    /// `collect_unstaked` already use).
    #[error("exit fee estimate failed: {detail}")]
    FeeEstimate {
        /// The query failure's rendering.
        detail: String,
    },
    /// The daemon *answered* the fee query and the wallet refused the
    /// answer (sanity ceiling) — retrying the connection does not help (the
    /// shared `-29109` remedy shape). Carries the violation's public chain
    /// facts, never wallet amounts.
    #[error("exit fee estimate refused by the wallet's sanity ceiling ({reason})")]
    FeeUnreasonable {
        /// Which interim check refused.
        reason: &'static str,
        /// Offending per-weight rate (atomic units).
        rate: u64,
        /// The violated bound (atomic units per weight).
        bound: u64,
    },
    /// The network refused the exit with a **definite first-send verdict**,
    /// and the seam has already released its seal — nothing propagated, and
    /// retrying (after addressing the named refusal) is safe.
    #[error("the daemon refused the exit and nothing was sent: {detail}")]
    ExitRefusedAndReleased {
        /// The daemon's verdict rendering.
        detail: String,
    },
    /// The exit's dispatch failed with **no definite verdict** (or a
    /// retryable one): the bytes may have reached the network, so the sealed
    /// record HOLDS — funds-safe, and the one-live-exit lane stays shut
    /// until it settles or the recovery slice disposes of it. Do NOT retry
    /// blindly; the stall alarm names the record in the operator log.
    #[error("the exit's network fate is unknown; its sealed record is held: {detail}")]
    ExitFateUnknown {
        /// The transport/verdict rendering.
        detail: String,
    },
    /// A non-transient engine fault: a sealed-state read, the fee quote, a
    /// corrupted resident key, or the assembly itself. Fail closed; not
    /// retryable by waiting.
    #[error("engine state ({context}): {detail}")]
    Engine {
        /// Which stage refused.
        context: &'static str,
        /// The stage's own rendering.
        detail: String,
    },
}

/// What one `collect_unstaked` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectOutcome {
    /// One sweep pass was dispatched.
    Swept {
        /// The locally computed tx id of the pass.
        tx_hash: TxHash,
        /// What this pass moves to the principal (`Σ selected − fee`).
        swept: AtomicUnits,
        /// What the pool still holds beyond this pass — immature payouts
        /// plus any mature overflow past the input cap. **`0` is THIS
        /// SLOT's completion fact**: nothing remains on the swept persona
        /// beyond this pass. Nonzero: call again once the residue matures
        /// or this pass confirms. Deliberately per-slot — it is the operand
        /// the funded retirement gate acts on — and therefore NOT a
        /// lane-wide claim; `another_pool_remains` carries that (review-6:
        /// a value whose scope is narrower than its reading forges
        /// completion).
        remainder: AtomicUnits,
        /// Whether any OTHER exited persona still holds an uncollected
        /// pool (a dust-skipped slot counts). The lane-wide fact: `false`
        /// plus `remainder == 0` means the exit lane is fully collected;
        /// `true` means run `collect_unstaked` again for the next persona.
        /// Normally `false` — one persona stakes at a time — and `true`
        /// only in the rotation-residue exception (sequential exits left
        /// uncollected), which must not be able to forge lane-wide
        /// completion.
        another_pool_remains: bool,
    },
    /// The exited persona's pool is already empty — collection is complete,
    /// and the funded-gated retirement proceeds on its own (`pscan/task.rs`
    /// `dispatch_retires`; an active persona retires after the next
    /// rotation).
    NothingLeft,
}

/// Why [`StakeFacade::collect_unstaked`] refused. The sweep IS the
/// firewall's P→principal value-out leg, so — unlike [`UnstakeError`] —
/// every rendering here inherits the drain path's **scalar-free** contract:
/// no amount, no gindex, no output count.
#[derive(Debug, thiserror::Error)]
pub enum CollectUnstakedError {
    /// This wallet runs no stake engine.
    #[error("this wallet is not a staker: no stake engine is running")]
    NotStaker,
    /// No persona has an observed confirmed exit — there is nothing to
    /// collect. Unstake first; a just-dispatched exit must also confirm
    /// (and be observed by the wallet's own scan) before collection.
    #[error(
        "no confirmed exit awaits collection — unstake first, or wait for the \
         exit to confirm and the wallet to observe it"
    )]
    NoExitToCollect,
    /// The exit is observed, but nothing in the pool is spendable **yet**
    /// (the payouts, or the last pass's residue, have not matured at the
    /// reference height). Wait and call again.
    #[error("the released collateral is not spendable yet — wait for maturity and retry")]
    NothingSpendableYet,
    /// The spendable residue cannot fund a valid pass — the fee plus the
    /// 2-atomic-unit minimum the zero-change two-output split can pay
    /// (T-DS-6). The named dust residual: it stays in `P` (and the funded
    /// retirement gate stays held by it) until further value matures into
    /// the slot or the fee floor moves. `fee + 1` is still dust: net 1
    /// cannot form the two nonzero outputs a drain-all pays.
    #[error(
        "the remaining residue is too small to move (it cannot fund the fee \
         plus a payable amount); it stays in the persona's pool"
    )]
    DustRemainder,
    /// A previous pass (or another drain) is still in flight for this
    /// persona — one live drain per persona; wait for it to settle.
    #[error("a sweep pass is already in flight for this persona; wait for it to settle")]
    PassInFlight,
    /// The pass's inputs are no longer current — retry against a fresh
    /// snapshot.
    #[error(
        "this pass's inputs are no longer current — another live record holds \
         one, or a reservation was released mid-assembly; retry"
    )]
    InputRaced,
    /// No submittable curve-tree reference can be anchored yet — transient;
    /// let the wallet sync and retry.
    #[error("no submittable reference can be anchored: {detail}")]
    Unanchorable {
        /// The anchoring helper's own (scalar-free) reason.
        detail: String,
    },
    /// A daemon query needed to prepare the sweep failed transiently — the
    /// dispatch-tip clock read. Pre-seal, so nothing propagated: check the
    /// daemon and retry. Distinct from `Unanchorable` (the wallet's reference
    /// is syncing) and from `Engine` (an internal fault): the remedy here is
    /// "the daemon is unreachable", not "wait for sync" (review-5).
    #[error("the daemon could not be reached to prepare the sweep: {detail}")]
    DaemonUnreachable {
        /// Which daemon query failed, and the transport's own reason.
        detail: String,
    },
    /// The daemon fee-estimate query failed — check the daemon connection
    /// and retry.
    #[error("sweep fee estimate failed: {detail}")]
    FeeEstimate {
        /// The query failure's rendering.
        detail: String,
    },
    /// The daemon *answered* the fee query and the wallet refused the
    /// answer (sanity ceiling) — retrying the connection does not help.
    #[error("sweep fee estimate refused by the wallet's sanity ceiling ({reason})")]
    FeeUnreasonable {
        /// Which interim check refused.
        reason: &'static str,
        /// Offending per-weight rate (atomic units) — a chain fact.
        rate: u64,
        /// The violated bound — a chain fact.
        bound: u64,
    },
    /// The assembled pass's dispatch failed at (or behind) the submit choke
    /// point. The sealed record stays live; do **not** re-fire blindly.
    #[error("sweep broadcast: {detail}")]
    Submit {
        /// The transport failure's rendering.
        detail: String,
    },
    /// A non-transient engine fault. Fail closed; not retryable by waiting.
    #[error("engine state ({context}): {detail}")]
    Engine {
        /// Which stage refused.
        context: &'static str,
        /// The stage's own (scalar-free) rendering.
        detail: String,
    },
}

/// The sealed evidence both resolutions read: the P-scan state (live bonds,
/// observed exits, per-slot funding), the pending-post block (in-flight
/// seals), and the persisted slot↔id cache. One read, plain (not the seam's
/// generation-coherent basis — resolution only *proposes*; every race is
/// re-checked at the seam's own seal admission).
struct ExitEvidence {
    pscan: Option<PScanState>,
    pending: Option<PendingPostBlock>,
    /// Slot↔id addressing, keyed by [`PSlot`]. The persisted cache keeps raw
    /// `u32` keys (postcard state, rule 18); [`read_exit_evidence`] converts
    /// at the boundary so everything transform-shaped speaks the typed slot.
    id_by_slot: BTreeMap<PSlot, PCanonicalId>,
}

/// The `unstake` resolution verdict, separated from I/O so the ladder is
/// unit-testable state-by-state.
#[derive(Debug, PartialEq, Eq)]
enum UnstakeTarget {
    /// Exit this slot (the first live-bonded slot).
    Post(PSlot),
    /// Nothing live-bonded, but exits are in flight or awaiting collection.
    ExitInProgress,
    /// Nothing live-bonded, but a bond post is confirming.
    BondConfirming,
    /// Nothing staked at all.
    NothingStaked,
}

/// Resolve what `unstake` should do from the sealed evidence.
///
/// The live-bond set is the authoritative derivation
/// ([`live_bonded_personas`]); the slot cache only *addresses* it. A live
/// persona missing from the cache fails closed ([`Err`]) rather than
/// reading as "nothing staked" — a bonded staker must never be told they
/// hold nothing over an incomplete index (the staking-read fail-closed
/// posture).
fn resolve_unstake_target(evidence: &ExitEvidence) -> Result<UnstakeTarget, &'static str> {
    let Some(pscan) = evidence.pscan.as_ref() else {
        // Never scanned: no confirmed bond can be observed. In-flight posts
        // can still exist (sealed before the first scan seal).
        return Ok(match evidence.pending.as_ref() {
            Some(p) if !p.posts().is_empty() => UnstakeTarget::BondConfirming,
            _ => UnstakeTarget::NothingStaked,
        });
    };

    let live = live_bonded_personas(pscan);
    // A persona whose exit is already sealed (dispatched, unconfirmed) is still
    // in the confirmed-bond set — the exit is not yet observed — but it must
    // not be an unstake target. Re-resolving it re-posts nothing (the seam
    // refuses `ExitInProgress`), and while its seal is outstanding it would
    // block every OTHER live bond from exiting; a held seal (-29522) on the
    // lowest slot would strand them with no recovery verb (Bugbot r5). Exclude
    // the mid-exit personas and target the lowest ELIGIBLE bond — the ladder's
    // order is unchanged, the candidate set is not. When every live bond is
    // already sealing, `candidates` is empty and the `sealed_exit` fall-through
    // below returns `ExitInProgress`.
    let sealing: BTreeSet<PCanonicalId> = evidence
        .pending
        .as_ref()
        .map(|p| p.unbonds().iter().map(|u| u.persona).collect())
        .unwrap_or_default();
    let candidates: BTreeSet<PCanonicalId> = live
        .iter()
        .copied()
        .filter(|id| !sealing.contains(id))
        .collect();
    let live_slots = address_personas(
        &evidence.id_by_slot,
        |id| candidates.contains(id),
        candidates.len(),
        "a live-bonded persona is missing from the slot index; refusing to \
         resolve an exit over an incomplete index",
    )?;
    if let Some((first, _)) = live_slots.first() {
        return Ok(UnstakeTarget::Post(*first));
    }

    // Nothing live-bonded. Name the in-progress states before concluding
    // "nothing staked": an observed exit (awaiting collection), a sealed
    // exit (dispatched, unconfirmed), then an in-flight bond post.
    let sealed_exit = evidence
        .pending
        .as_ref()
        .is_some_and(|p| !p.unbonds().is_empty());
    if !pscan.pending_unbonds().is_empty() || sealed_exit {
        return Ok(UnstakeTarget::ExitInProgress);
    }
    let pending_post = evidence
        .pending
        .as_ref()
        .is_some_and(|p| !p.posts().is_empty());
    if pending_post {
        return Ok(UnstakeTarget::BondConfirming);
    }
    Ok(UnstakeTarget::NothingStaked)
}

/// The `collect_unstaked` resolution verdict.
#[derive(Debug, PartialEq, Eq)]
enum CollectTarget {
    /// Sweep this slot (the first slot with an observed confirmed exit and
    /// a nonempty pool).
    Sweep(PSlot, PCanonicalId),
    /// Exits are observed but every exited slot's pool is already empty —
    /// collection is complete.
    NothingLeft,
    /// No observed confirmed exit exists.
    NoExit,
}

/// Resolve what `collect_unstaked` should do from the sealed evidence.
///
/// Exited personas come from [`PScanState::pending_unbonds`] (the observed
/// on-chain exits); the same fail-closed index rule as
/// [`resolve_unstake_target`] applies. "Pool is nonempty" reads the
/// persisted per-slot funding rows — spendability (maturity, reservations)
/// is the pipeline's call, not resolution's.
fn resolve_collect_target(
    evidence: &ExitEvidence,
    skip: &BTreeSet<PSlot>,
) -> Result<CollectTarget, &'static str> {
    let Some(pscan) = evidence.pscan.as_ref() else {
        return Ok(CollectTarget::NoExit);
    };
    let exited = pscan.pending_unbonds();
    if exited.is_empty() {
        return Ok(CollectTarget::NoExit);
    }

    let exited_slots = address_personas(
        &evidence.id_by_slot,
        |id| exited.contains_key(id),
        exited.len(),
        "an exited persona is missing from the slot index; refusing to \
         resolve a collection over an incomplete index",
    )?;

    // Lowest exited slot with a pool, skipping any the caller has proven
    // permanently unsweepable this call (a dust pool with no maturing rows).
    // Resolution stays fee-blind — it cannot tell dust from a real pool — so
    // the skip set, not a fee check here, is what lets a stuck low slot fall
    // through to a higher collectable one (Bugbot r5).
    for (slot, id) in &exited_slots {
        if skip.contains(slot) {
            continue;
        }
        let has_rows = pscan.funding_outputs().iter().any(|r| r.p_slot == *slot);
        if has_rows {
            return Ok(CollectTarget::Sweep(*slot, *id));
        }
    }
    Ok(CollectTarget::NothingLeft)
}

/// Whether `slot` still holds funding rows that are not yet spendable at the
/// scanned frontier — i.e. value is maturing into it. A dust refusal on such a
/// slot is transient (it clears when the value matures), so the collect loop
/// must **wait** on it, not skip past it. The reference is the pscan cursor,
/// which is at or behind the sweep's own anchored reference, so this errs
/// toward "maturing" (wait) and never skips a slot that was about to become
/// collectable.
fn slot_has_maturing_rows(pscan: &PScanState, slot: PSlot) -> bool {
    let reference = pscan.cursor().synced_height();
    pscan
        .funding_outputs()
        .iter()
        .any(|r| r.p_slot == slot && r.spendable_height > reference)
}

/// Whether any exited persona OTHER than `swept` still holds funding rows —
/// the lane-wide half of the completion fact (a dust-skipped slot counts:
/// its pool is uncollected even if unsweepable today). Runs only after
/// [`resolve_collect_target`] returned a sweep target, so the fail-closed
/// index-completeness check over the exited set has already passed and a
/// plain map walk cannot silently miss an exited persona.
fn other_exited_pools_remain(evidence: &ExitEvidence, swept: PSlot) -> bool {
    let Some(pscan) = evidence.pscan.as_ref() else {
        return false;
    };
    let exited = pscan.pending_unbonds();
    evidence
        .id_by_slot
        .iter()
        .filter(|(&slot, id)| slot != swept && exited.contains_key(id))
        .any(|(&slot, _)| pscan.funding_outputs().iter().any(|r| r.p_slot == slot))
}

/// Address a set of persona ids through the slot cache. Fail closed if any
/// wanted id is missing from the index (the staking-read posture: a bonded
/// staker must never be told they hold nothing over an incomplete index).
/// Returns `(slot, id)` pairs in **ascending slot order** — the lowest-slot
/// rule is explicit (`sort_unstable_by_key`), not a `BTreeMap` iteration
/// accident.
fn address_personas(
    id_by_slot: &BTreeMap<PSlot, PCanonicalId>,
    wanted: impl Fn(&PCanonicalId) -> bool,
    expected: usize,
    missing: &'static str,
) -> Result<Vec<(PSlot, PCanonicalId)>, &'static str> {
    let mut slots: Vec<(PSlot, PCanonicalId)> = id_by_slot
        .iter()
        .filter(|(_, id)| wanted(id))
        .map(|(&slot, &id)| (slot, id))
        .collect();
    if slots.len() != expected {
        return Err(missing);
    }
    slots.sort_unstable_by_key(|(slot, _)| *slot);
    Ok(slots)
}

#[allow(private_bounds, clippy::type_complexity)]
impl<S, D, E, R, P> StakeFacade<'_, S, D, LocalLedger, E, R, P, WalletFile>
where
    S: EngineSignerKind + Send + Sync + 'static,
    D: DaemonEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
    Engine<S, D, LocalLedger, E, R, P, WalletFile>: Send + Sync,
{
    /// Post the terminal `Unbond` exit for the first live-bonded persona —
    /// **the irreversible step**: once the exit connects, the bond debits to
    /// zero and the persona can never re-bond on this record.
    ///
    /// The wire carries no slot, no fee, no destination: the persona is the
    /// first live-bonded slot (engine-resolved; a multi-bonded wallet exits
    /// one persona per invocation), the fee is the canonical P-lane floor,
    /// and the exit pays `P`'s own base address (never the principal — the
    /// P↔principal edge is drawn only by the later, separate
    /// [`Self::collect_unstaked`] sweep). `daemon_address` is the
    /// embedder-held endpoint (the [`Self::start_serving_if_staker`] shape);
    /// the record fetch rides the ① local-posture transport built from it,
    /// which refuses a non-loopback URL by construction (posture *selection*
    /// remains the DQ-T2.3 slice).
    pub async fn unstake(
        engine: Arc<RwLock<Engine<S, D, LocalLedger, E, R, P, WalletFile>>>,
        daemon_address: &str,
    ) -> Result<UnstakeOutcome, UnstakeError> {
        // A wallet with no stake engine owns no exit. Answer the seam's
        // `NotStaker` (-29513) here: a non-staker's empty snapshot resolves
        // to `NothingStaked` (-29514), so without this the seam's `NotStaker`
        // arm is façade-unreachable and one state gets two names. This is the
        // same `self.stake.is_some()` predicate `submit_unbond`'s
        // `stake_handle().ok_or(NotStaker)` rests on (lifted, not restated),
        // and the drain façade rejects a non-staker before reading evidence
        // for the same reason.
        if !engine.read().await.has_stake_engine() {
            return Err(UnstakeError::NotStaker);
        }
        let evidence = read_exit_evidence(&engine)
            .await
            .map_err(|e| UnstakeError::Engine {
                context: "exit evidence",
                detail: e.to_string(),
            })?;
        let slot =
            match resolve_unstake_target(&evidence).map_err(|detail| UnstakeError::Engine {
                context: "exit resolution",
                detail: detail.to_owned(),
            })? {
                UnstakeTarget::Post(slot) => slot,
                UnstakeTarget::ExitInProgress => return Err(UnstakeError::ExitInProgress),
                UnstakeTarget::BondConfirming => return Err(UnstakeError::BondConfirming),
                UnstakeTarget::NothingStaked => return Err(UnstakeError::NothingStaked),
            };

        // ① local posture; refuses non-loopback by construction.
        let unbond_rpc = LocalNodeRpc::new(daemon_address.to_owned(), EXIT_FETCH_TIMEOUT)
            .await
            .map_err(|e| UnstakeError::Transport {
                detail: e.to_string(),
            })?;

        let witness = SpentRecordsDurablyPruned::arm1_watch_pruning_live();
        let receipt = Engine::submit_unbond(engine, &unbond_rpc, slot, &witness)
            .await
            .map_err(flatten_unstake_error)?;

        Ok(match receipt.submit {
            SubmitSuccess::Broadcast { hash, .. } => UnstakeOutcome::Broadcast { tx_hash: hash },
            SubmitSuccess::AlreadyInChain { hash, height } => UnstakeOutcome::AlreadyInChain {
                tx_hash: hash,
                height,
            },
        })
    }

    /// Sweep one pass of an exited persona's released collateral to this
    /// wallet's principal — the composed `unstake`'s second, separate,
    /// FCMP-private leg (never in the same transaction as the post).
    ///
    /// The persona is the first slot with an observed confirmed exit and a
    /// nonempty pool (engine-resolved; no wire parameter). The pass's
    /// payment is `Σ selected − fee` — exactly zero change, which is what
    /// lets the funded retirement gate finally fire — computed by the
    /// selection stage under a [`TerminalExitObserved`] witness; no caller
    /// amount exists to get wrong. The reply's `remainder` is the
    /// completion fact: see [`CollectOutcome::Swept`].
    pub async fn collect_unstaked(
        engine: Arc<RwLock<Engine<S, D, LocalLedger, E, R, P, WalletFile>>>,
    ) -> Result<CollectOutcome, CollectUnstakedError> {
        // Non-staker first, exactly as `unstake` and the drain façade do: an
        // empty snapshot otherwise resolves to `NoExitToCollect` (-29523) and
        // the seam's shared `NotStaker` (-29513) never lands. Same lifted
        // `has_stake_engine` predicate `submit_drain`'s NotStaker rests on.
        if !engine.read().await.has_stake_engine() {
            return Err(CollectUnstakedError::NotStaker);
        }
        let evidence =
            read_exit_evidence(&engine)
                .await
                .map_err(|e| CollectUnstakedError::Engine {
                    context: "exit evidence",
                    detail: e.to_string(),
                })?;
        // The fee is the canonical P-lane floor — persona-independent, so it
        // is quoted once and reused across the loop. It is memoised (quoted on
        // first need) so a `PassInFlight` answer still lands before any fee I/O
        // (review-4).
        let mut fee: Option<AtomicUnits> = None;
        // Exited slots proven permanently unsweepable this call — a dust pool
        // with no maturing rows. Skipping them lets a lower stuck slot fall
        // through to a higher collectable pool instead of stranding it.
        let mut skip: BTreeSet<PSlot> = BTreeSet::new();

        loop {
            let (slot, p_id) = match resolve_collect_target(&evidence, &skip).map_err(|detail| {
                CollectUnstakedError::Engine {
                    context: "collection resolution",
                    detail: detail.to_owned(),
                }
            })? {
                CollectTarget::Sweep(slot, id) => (slot, id),
                // Nothing left to sweep. If we skipped dust slots to get here,
                // every exited pool was permanently unsweepable dust — the
                // stranded-residual answer (-29525), not the completion one.
                CollectTarget::NothingLeft if skip.is_empty() => {
                    return Ok(CollectOutcome::NothingLeft)
                }
                CollectTarget::NothingLeft => return Err(CollectUnstakedError::DustRemainder),
                CollectTarget::NoExit => return Err(CollectUnstakedError::NoExitToCollect),
            };

            // The boundary's witness: minted from the same evidence the
            // resolution read. The seam re-resolves exited-ness from its own
            // basis load and refuses a divergence — the witness proposes, the
            // seam disposes.
            let witness = evidence
                .pscan
                .as_ref()
                .and_then(|s| TerminalExitObserved::for_persona(s, p_id))
                .ok_or(CollectUnstakedError::Engine {
                    context: "sweep witness",
                    detail: "the resolved persona lost its observed exit between reads".to_owned(),
                })?;

            // A sweep already in flight is visible in the evidence we already
            // loaded; surface `PassInFlight` (-29526) here rather than after a
            // daemon fee round trip whose failure would mask it as -29102 and
            // send the person to debug a healthy daemon. The sibling drain
            // façade prechecks the seal before its fee I/O for exactly this
            // reason; the seam still rechecks atomically under the write lock,
            // so this is an advisory fast-answer, not the authoritative
            // serialization.
            if evidence
                .pending
                .as_ref()
                .is_some_and(|b| b.has_live_drain_for(&p_id))
            {
                return Err(CollectUnstakedError::PassInFlight);
            }

            // Canonical P-lane floor fee — quoted once, memoised, no override.
            let fee = match fee {
                Some(f) => f,
                None => {
                    let daemon = { engine.read().await.daemon().clone() };
                    let quoted =
                        p_lane_floor_fee(daemon.get_fee_estimates().await.map_err(|e| {
                            CollectUnstakedError::FeeEstimate {
                                detail: e.into().to_string(),
                            }
                        })?)
                        .map_err(|e| match e {
                            FeeEstimatorError::DaemonFeeUnreasonable(v) => {
                                CollectUnstakedError::FeeUnreasonable {
                                    reason: v.reason(),
                                    rate: v.rate(),
                                    bound: v.bound(),
                                }
                            }
                            other => CollectUnstakedError::FeeEstimate {
                                detail: other.to_string(),
                            },
                        })?;
                    fee = Some(quoted);
                    quoted
                }
            };

            let pruning = SpentRecordsDurablyPruned::arm1_watch_pruning_live();
            let receipt = match Engine::submit_drain(
                engine.clone(),
                slot,
                DrainIntent::TerminalSweep(witness),
                fee,
                &pruning,
            )
            .await
            {
                Ok(receipt) => receipt,
                // This slot's mature pool is dust. If the slot still holds rows
                // maturing into it, the dust is transient — wait, do not skip
                // past a slot about to become collectable. Only permanent dust
                // (no maturing rows) is skipped, so a lower stuck slot cannot
                // strand a higher pool (Bugbot r5). DustPool refuses in
                // planning, before the seal, so a skipped attempt leaves no
                // record.
                Err(DrainRequestError::Drain(DrainOrchestrationError::Plan(
                    DrainError::SweepDustPool,
                ))) => {
                    let maturing = evidence
                        .pscan
                        .as_ref()
                        .is_some_and(|s| slot_has_maturing_rows(s, slot));
                    if maturing {
                        return Err(CollectUnstakedError::DustRemainder);
                    }
                    skip.insert(slot);
                    continue;
                }
                Err(other) => return Err(flatten_collect_error(other)),
            };

            let (SubmitSuccess::Broadcast { hash: tx_hash, .. }
            | SubmitSuccess::AlreadyInChain { hash: tx_hash, .. }) = receipt.submit;
            // The receipt's arm is the completion fact: a Payment variant here
            // means the payment path ran on a sweep intent — a defect, not a
            // missing Option to default to zero.
            let DrainMoved::Sweep { payment, remainder } = receipt.moved else {
                return Err(CollectUnstakedError::Engine {
                    context: "sweep receipt",
                    detail:
                        "the sweep receipt is a payment — the payment path ran on a sweep intent"
                            .to_owned(),
                });
            };
            return Ok(CollectOutcome::Swept {
                tx_hash,
                swept: payment,
                remainder,
                // The lane-wide half of the completion fact, from the same
                // evidence resolution read: another exited persona's pool
                // (dust-skipped included) means "run collect_unstaked
                // again", regardless of this slot's remainder.
                another_pool_remains: other_exited_pools_remain(&evidence, slot),
            });
        }
    }
}

/// Read the sealed evidence both resolutions consume: the two sibling seals
/// (the [`StakeFacade::staking_read_view`] shape) plus the persisted slot↔id
/// cache, under one brief ledger read guard each.
#[allow(clippy::type_complexity)] // the Engine generic set, the facade impls' own allow
async fn read_exit_evidence<S, D, E, R, P>(
    engine: &Arc<RwLock<Engine<S, D, LocalLedger, E, R, P, WalletFile>>>,
) -> Result<ExitEvidence, StakingReadError>
where
    S: EngineSignerKind + Send + Sync + 'static,
    D: DaemonEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
{
    let g = engine.read().await;
    // The typed-domain edge: the persisted cache's raw u32 keys become
    // `PSlot` here, once, so no downstream logic juggles raw and typed slots.
    let id_by_slot = {
        let guard = g.ledger.read();
        guard
            .ledger
            .staking
            .persona_id_cache
            .iter()
            .map(|(&slot, &id)| (PSlot::from_raw(slot), id))
            .collect()
    };
    let (pscan, pending) = g.exit_seal_snapshot()?;
    Ok(ExitEvidence {
        pscan,
        pending,
        id_by_slot,
    })
}

/// Flatten the crate-internal exit-seam error onto the `pub` boundary,
/// keeping the seal dispositions distinct (module docs).
fn flatten_unstake_error(e: UnbondRequestError) -> UnstakeError {
    match e {
        UnbondRequestError::NotStaker => UnstakeError::NotStaker,
        UnbondRequestError::NoBondRecord => UnstakeError::NoBondRecord,
        UnbondRequestError::UnbondPending => UnstakeError::ExitInProgress,
        // NOT ExitInProgress (review-1, Bugbot): a confirming bond post is
        // not an exit, and the remedies point at different verbs — wait then
        // UNSTAKE, never "wait then collect_unstaked" (a collect here answers
        // NoExit). Resolution normally catches this state first, but the
        // seam's admission is authoritative in the GC-bridge window — a
        // confirmed match whose pending-post seal has not yet retired — and
        // the seam's refusal must land on the same arm resolution would have
        // picked.
        UnbondRequestError::BondPostPending => UnstakeError::BondConfirming,
        UnbondRequestError::InputRaced => UnstakeError::InputRaced,
        UnbondRequestError::Stake(StakeEngineError::UnbondNotReady(not_ready)) => {
            UnstakeError::NotReady {
                detail: not_ready.to_string(),
            }
        }
        UnbondRequestError::Stake(StakeEngineError::Assembly(
            ref a @ super::bond_assembly::BondAssemblyError::ReferenceResyncing { .. },
        )) => UnstakeError::Resyncing {
            detail: a.to_string(),
        },
        UnbondRequestError::Stake(StakeEngineError::Assembly(
            ref a @ (super::bond_assembly::BondAssemblyError::NoSpendableFunding
            | super::bond_assembly::BondAssemblyError::OutputNotYetDrained { .. }
            | super::bond_assembly::BondAssemblyError::InsufficientFunding { .. }),
        )) => UnstakeError::ExitNotFundable {
            detail: a.to_string(),
        },
        UnbondRequestError::Stake(e) => UnstakeError::Engine {
            context: "exit assembly",
            detail: e.to_string(),
        },
        // Typed through, never Engine/-32603 (review-2): the two fee
        // failure classes keep the remedy split every other P-lane verb
        // already carries — a refused ANSWER is -29109 (reconnecting cannot
        // help), a failed QUERY is -29102 (check the daemon and retry).
        UnbondRequestError::Fee(FeeEstimatorError::DaemonFeeUnreasonable(v)) => {
            UnstakeError::FeeUnreasonable {
                reason: v.reason(),
                rate: v.rate(),
                bound: v.bound(),
            }
        }
        UnbondRequestError::Fee(e) => UnstakeError::FeeEstimate {
            detail: e.to_string(),
        },
        // The fetch's inner class decides the disposition (review-5): a
        // connection/status failure is a reachable daemon outage (retryable),
        // a malformed response is an untrusted-input rejection (internal).
        UnbondRequestError::Fetch(e) => match e {
            EmissionSourceError::Rpc(_) | EmissionSourceError::Status(_) => {
                UnstakeError::DaemonUnreachable {
                    detail: e.to_string(),
                }
            }
            EmissionSourceError::Malformed(_) => UnstakeError::Engine {
                context: "bond record fetch",
                detail: e.to_string(),
            },
        },
        // Pre-seal daemon-tip failure: retryable, never the opaque internal
        // -32603 a sealed-store read gets (review-5).
        UnbondRequestError::DaemonUnreachable { context, detail } => {
            UnstakeError::DaemonUnreachable {
                detail: format!("{context}: {detail}"),
            }
        }
        UnbondRequestError::State { context, detail } => UnstakeError::Engine { context, detail },
        UnbondRequestError::Submit(submit) => match &submit {
            BroadcastSubmitError::PersonaMismatch { .. }
            | BroadcastSubmitError::Submit(SubmitterError::RejectedTerminal { .. }) => {
                // The same two classes the seam's release predicate names
                // (`released_on_first_send_failure`): the seal is already
                // released, nothing propagated.
                UnstakeError::ExitRefusedAndReleased {
                    detail: submit.to_string(),
                }
            }
            _ => UnstakeError::ExitFateUnknown {
                detail: submit.to_string(),
            },
        },
    }
}

/// Flatten the crate-internal drain-seam error onto the collect boundary
/// (scalar-free, module docs).
fn flatten_collect_error(e: DrainRequestError) -> CollectUnstakedError {
    match e {
        DrainRequestError::NotStaker => CollectUnstakedError::NotStaker,
        DrainRequestError::DrainPending => CollectUnstakedError::PassInFlight,
        DrainRequestError::InputRaced => CollectUnstakedError::InputRaced,
        DrainRequestError::Drain(orch) => match orch {
            DrainOrchestrationError::ReferenceUnanchorable { detail } => {
                CollectUnstakedError::Unanchorable { detail }
            }
            DrainOrchestrationError::Plan(DrainError::SweepNothingSpendable) => {
                CollectUnstakedError::NothingSpendableYet
            }
            DrainOrchestrationError::Plan(DrainError::SweepDustPool) => {
                CollectUnstakedError::DustRemainder
            }
            DrainOrchestrationError::SweepOnLivePersona => CollectUnstakedError::Engine {
                context: "sweep intent",
                detail: DrainOrchestrationError::SweepOnLivePersona.to_string(),
            },
            other => CollectUnstakedError::Engine {
                context: "sweep pipeline",
                detail: other.to_string(),
            },
        },
        DrainRequestError::Stake(e) => CollectUnstakedError::Engine {
            context: "sweep assembly",
            detail: e.to_string(),
        },
        DrainRequestError::Destination { detail } => CollectUnstakedError::Engine {
            context: "principal destination",
            detail: detail.to_string(),
        },
        // Pre-seal daemon-tip failure: retryable, never the opaque internal
        // -32603 a sealed-store read gets (review-5).
        DrainRequestError::DaemonUnreachable { context, detail } => {
            CollectUnstakedError::DaemonUnreachable {
                detail: format!("{context}: {detail}"),
            }
        }
        DrainRequestError::State { context, detail } => {
            CollectUnstakedError::Engine { context, detail }
        }
        DrainRequestError::Submit(e) => CollectUnstakedError::Submit {
            detail: e.to_string(),
        },
    }
}

#[cfg(test)]
#[path = "unstake_facade_tests.rs"]
mod tests;
