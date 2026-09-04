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

use std::collections::BTreeMap;
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
    DrainError, DrainIntent, DrainOrchestrationError, TerminalExitObserved,
};
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
    /// The exit's floor fee cannot be funded from the persona pool **yet**
    /// (no spendable funding, an output still mid-drain, or a shortfall the
    /// assembly names). Wait for outputs to mature or land, then retry —
    /// the walk's own retry family.
    #[error("the exit cannot be funded from the persona pool yet: {detail}")]
    ExitNotFundable {
        /// The assembly's own reason (bond-parity rendering).
        detail: String,
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
        /// plus any mature overflow past the input cap. **`0` is the
        /// completion fact**: nothing remains beyond this pass. Nonzero:
        /// call again once the residue matures or this pass confirms.
        remainder: AtomicUnits,
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
    /// The spendable residue cannot fund the fee to move it — the named
    /// dust residual. It stays in `P` (and the funded retirement gate stays
    /// held by it) until further value matures into the slot or the fee
    /// floor moves.
    #[error(
        "the remaining residue is smaller than the fee to move it; it stays \
         in the persona's pool"
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
    id_by_slot: BTreeMap<u32, PCanonicalId>,
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
    let mut live_slots: Vec<PSlot> = Vec::new();
    let mut matched = 0usize;
    for (slot, id) in &evidence.id_by_slot {
        if live.contains(id) {
            live_slots.push(PSlot::from_raw(*slot));
            matched += 1;
        }
    }
    if matched != live.len() {
        return Err(
            "a live-bonded persona is missing from the slot index; refusing to \
             resolve an exit over an incomplete index",
        );
    }
    if let Some(first) = live_slots.first() {
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
fn resolve_collect_target(evidence: &ExitEvidence) -> Result<CollectTarget, &'static str> {
    let Some(pscan) = evidence.pscan.as_ref() else {
        return Ok(CollectTarget::NoExit);
    };
    let exited = pscan.pending_unbonds();
    if exited.is_empty() {
        return Ok(CollectTarget::NoExit);
    }

    let mut exited_slots: Vec<(PSlot, PCanonicalId)> = Vec::new();
    let mut matched = 0usize;
    for (slot, id) in &evidence.id_by_slot {
        if exited.contains_key(id) {
            exited_slots.push((PSlot::from_raw(*slot), *id));
            matched += 1;
        }
    }
    if matched != exited.len() {
        return Err(
            "an exited persona is missing from the slot index; refusing to \
             resolve a collection over an incomplete index",
        );
    }

    for (slot, id) in &exited_slots {
        let has_rows = pscan.funding_outputs().iter().any(|r| r.p_slot == *slot);
        if has_rows {
            return Ok(CollectTarget::Sweep(*slot, *id));
        }
    }
    Ok(CollectTarget::NothingLeft)
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
        let evidence =
            read_exit_evidence(&engine)
                .await
                .map_err(|e| CollectUnstakedError::Engine {
                    context: "exit evidence",
                    detail: e.to_string(),
                })?;
        let (slot, p_id) = match resolve_collect_target(&evidence).map_err(|detail| {
            CollectUnstakedError::Engine {
                context: "collection resolution",
                detail: detail.to_owned(),
            }
        })? {
            CollectTarget::Sweep(slot, id) => (slot, id),
            CollectTarget::NothingLeft => return Ok(CollectOutcome::NothingLeft),
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

        // Canonical P-lane floor fee — the same single fee decision every
        // P-lane spend quotes; no caller override exists.
        let daemon = { engine.read().await.daemon().clone() };
        let fee = p_lane_floor_fee(daemon.get_fee_estimates().await.map_err(|e| {
            CollectUnstakedError::FeeEstimate {
                detail: e.into().to_string(),
            }
        })?)
        .map_err(|e| match e {
            FeeEstimatorError::DaemonFeeUnreasonable(v) => CollectUnstakedError::FeeUnreasonable {
                reason: v.reason(),
                rate: v.rate(),
                bound: v.bound(),
            },
            other => CollectUnstakedError::FeeEstimate {
                detail: other.to_string(),
            },
        })?;

        let pruning = SpentRecordsDurablyPruned::arm1_watch_pruning_live();
        let receipt = Engine::submit_drain(
            engine,
            slot,
            DrainIntent::TerminalSweep(witness),
            fee,
            &pruning,
        )
        .await
        .map_err(flatten_collect_error)?;

        let (SubmitSuccess::Broadcast { hash: tx_hash, .. }
        | SubmitSuccess::AlreadyInChain { hash: tx_hash, .. }) = receipt.submit;
        // The remainder is the reply's completion fact; defaulting an absent
        // one to zero would forge "collection complete". Its absence means
        // the payment path ran on a sweep intent — a defect, surfaced loudly.
        let remainder = receipt
            .sweep_remainder
            .ok_or(CollectUnstakedError::Engine {
                context: "sweep receipt",
                detail: "the sweep receipt carries no remainder — the payment path ran on a \
                         sweep intent"
                    .to_owned(),
            })?;
        Ok(CollectOutcome::Swept {
            tx_hash,
            swept: receipt.payment,
            remainder,
        })
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
    let id_by_slot = {
        let guard = g.ledger.read();
        guard.ledger.staking.persona_id_cache.clone()
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
        UnbondRequestError::Fee(FeeEstimatorError::DaemonFeeUnreasonable(v)) => {
            UnstakeError::Engine {
                context: "P-lane floor fee",
                detail: format!(
                    "daemon fee refused by the wallet's sanity ceiling ({}: rate {} > bound {})",
                    v.reason(),
                    v.rate(),
                    v.bound()
                ),
            }
        }
        UnbondRequestError::Fee(e) => UnstakeError::Engine {
            context: "P-lane floor fee",
            detail: e.to_string(),
        },
        UnbondRequestError::Fetch(e) => UnstakeError::Engine {
            context: "bond record fetch",
            detail: e.to_string(),
        },
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
        DrainRequestError::State { context, detail } => {
            CollectUnstakedError::Engine { context, detail }
        }
        DrainRequestError::Submit(e) => CollectUnstakedError::Submit {
            detail: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use shekyl_engine_state::pending_post_block::{PendingUnbond, SealAdmission};
    use shekyl_engine_state::pscan_cursor::PScanCursor;
    use shekyl_engine_state::pscan_state::{
        BondPostRecord, MintLineageOutput, PFundingOutputRecord, RetiredPersonaRecord,
    };
    use shekyl_engine_state::{PendingBondPost, PendingPostState};
    use shekyl_types::{BlockHeight, GlobalOutputIndex, SettlementEpoch};

    use super::*;

    fn persona(b: u8) -> PCanonicalId {
        PCanonicalId::from_bytes([b; 32])
    }

    fn bond_match(id: u8, kind: u8) -> BondPostRecord {
        BondPostRecord {
            height: BlockHeight::from_raw(1_000),
            p_canonical_id: persona(id),
            post_kind: kind,
        }
    }

    fn funding(slot: u32, gindex: u64, amount: u64) -> PFundingOutputRecord {
        PFundingOutputRecord {
            p_slot: PSlot::from_raw(slot),
            index_in_transaction: 0,
            gindex: GlobalOutputIndex::from_raw(gindex),
            output_key: [0; 32],
            commitment: [0; 32],
            ciphertext_x25519: [0; 32],
            ciphertext_ml_kem: Vec::new(),
            amount: AtomicUnits::from_raw(amount),
            height: BlockHeight::from_raw(2_000),
            epoch: SettlementEpoch::from_raw(1),
            lineage: MintLineageOutput::BondPostChange,
            spendable_height: BlockHeight::from_raw(2_010),
        }
    }

    fn pscan(
        matches: Vec<BondPostRecord>,
        pending_unbonds: BTreeMap<PCanonicalId, SettlementEpoch>,
        retired: Vec<RetiredPersonaRecord>,
        outputs: Vec<PFundingOutputRecord>,
    ) -> PScanState {
        PScanState::new(
            PScanCursor::at(BlockHeight::from_raw(5_000), [0x11; 32]),
            BTreeMap::new(),
            pending_unbonds,
            matches,
            outputs,
            retired,
            BTreeMap::new(),
        )
    }

    fn evidence(
        pscan_state: Option<PScanState>,
        pending: Option<PendingPostBlock>,
        slots: &[(u32, u8)],
    ) -> ExitEvidence {
        ExitEvidence {
            pscan: pscan_state,
            pending,
            id_by_slot: slots.iter().map(|&(s, id)| (s, persona(id))).collect(),
        }
    }

    fn exited(id: u8) -> BTreeMap<PCanonicalId, SettlementEpoch> {
        let mut m = BTreeMap::new();
        m.insert(persona(id), SettlementEpoch::from_raw(9));
        m
    }

    /// This bites against the resolution ladder falling through to a
    /// different persona's irreversible post — the exact mis-selection the
    /// two-verb split exists to prevent: with persona 1 exited (payouts
    /// immature or not) and persona 2 still bonded, `unstake` must resolve
    /// persona 2 ONLY as a deliberate post target, and `collect` must
    /// resolve persona 1 ONLY — neither verb ever answers with the other's
    /// persona. It does NOT cover the seam's own admission races.
    #[test]
    fn the_two_resolutions_never_trade_personas() {
        let state = pscan(
            vec![bond_match(1, 0), bond_match(2, 0)],
            exited(1),
            Vec::new(),
            vec![funding(1, 7, 500)],
        );
        let ev = evidence(Some(state), None, &[(1, 1), (2, 2)]);

        // `unstake` sees persona 2 (slot 2) — the only LIVE bond; persona 1
        // is pending-unbond and excluded from the live set.
        assert_eq!(
            resolve_unstake_target(&ev).expect("resolvable"),
            UnstakeTarget::Post(PSlot::from_raw(2)),
        );
        // `collect` sees persona 1 (slot 1) — the only observed exit.
        assert_eq!(
            resolve_collect_target(&ev).expect("resolvable"),
            CollectTarget::Sweep(PSlot::from_raw(1), persona(1)),
        );
    }

    /// This bites against "nothing staked" being reported over an exit in
    /// progress (either a sealed unconfirmed exit or an observed one) — the
    /// guidance states are distinct refusals, not silence. It does NOT
    /// cover the RPC rendering of these arms.
    #[test]
    fn in_progress_states_are_named_before_nothing_staked() {
        // Observed exit, nothing else: ExitInProgress (collect's turf).
        let state = pscan(vec![bond_match(1, 0)], exited(1), Vec::new(), Vec::new());
        let ev = evidence(Some(state), None, &[(1, 1)]);
        assert_eq!(
            resolve_unstake_target(&ev).expect("resolvable"),
            UnstakeTarget::ExitInProgress
        );

        // Sealed-but-unconfirmed exit (dispatched, not yet observed): the
        // pending block's unbond seal is the evidence.
        let state = pscan(vec![bond_match(1, 0)], exited(1), Vec::new(), Vec::new());
        let mut block = PendingPostBlock::empty();
        let g = block.generation();
        assert_eq!(
            block.seal_unbond(
                PendingUnbond {
                    persona: persona(1),
                    tx_bytes: vec![0xEE; 4],
                    funding_gindexes: Vec::new(),
                    state: PendingPostState::Pending,
                },
                BlockHeight::from_raw(5_000),
                g,
            ),
            SealAdmission::Admit
        );
        let ev = evidence(Some(state), Some(block), &[(1, 1)]);
        assert_eq!(
            resolve_unstake_target(&ev).expect("resolvable"),
            UnstakeTarget::ExitInProgress
        );

        // In-flight bond post only: BondConfirming, not NothingStaked.
        let mut block = PendingPostBlock::empty();
        let g = block.generation();
        assert_eq!(
            block.seal_post(
                PendingBondPost {
                    p_slot: PSlot::from_raw(0),
                    persona: persona(9),
                    tx_bytes: vec![0xAB; 4],
                    bond_post_offset_blocks: 0,
                    anchor_t0: BlockHeight::from_raw(1),
                    funding_gindexes: Vec::new(),
                    state: PendingPostState::Pending,
                },
                g,
            ),
            SealAdmission::Admit
        );
        let ev = evidence(
            Some(pscan(Vec::new(), BTreeMap::new(), Vec::new(), Vec::new())),
            Some(block),
            &[],
        );
        assert_eq!(
            resolve_unstake_target(&ev).expect("resolvable"),
            UnstakeTarget::BondConfirming
        );

        // Truly nothing.
        let ev = evidence(
            Some(pscan(Vec::new(), BTreeMap::new(), Vec::new(), Vec::new())),
            None,
            &[],
        );
        assert_eq!(
            resolve_unstake_target(&ev).expect("resolvable"),
            UnstakeTarget::NothingStaked
        );
    }

    /// This bites against an incomplete slot index reading as "nothing
    /// staked" / "nothing to collect" — a bonded staker must never be told
    /// they hold nothing over a missing index row (the staking-read
    /// fail-closed posture, applied to resolution). It does NOT cover cache
    /// (re)population.
    #[test]
    fn a_live_or_exited_persona_missing_from_the_index_fails_closed() {
        let state = pscan(
            vec![bond_match(1, 0)],
            Vec::new().into_iter().collect(),
            Vec::new(),
            Vec::new(),
        );
        let ev = evidence(Some(state), None, &[]);
        assert!(
            resolve_unstake_target(&ev).is_err(),
            "a live bond with no index row is an error, not NothingStaked"
        );

        let state = pscan(vec![bond_match(1, 0)], exited(1), Vec::new(), Vec::new());
        let ev = evidence(Some(state), None, &[]);
        assert!(
            resolve_collect_target(&ev).is_err(),
            "an observed exit with no index row is an error, not NoExit"
        );
    }

    /// This bites against multi-exit resolution skipping an emptied slot's
    /// completion (`NothingLeft` must require EVERY exited slot empty) and
    /// against slot-order drift (lowest exited slot with rows sweeps
    /// first). It does NOT cover spendability (maturity is the pipeline's).
    #[test]
    fn collect_resolves_lowest_exited_slot_with_rows_and_completes_on_empty() {
        let mut both = exited(1);
        both.extend(exited(2));
        let state = pscan(
            Vec::new(),
            both.clone(),
            Vec::new(),
            vec![funding(2, 9, 400)], // slot 1 already swept; slot 2 holds rows
        );
        let ev = evidence(Some(state), None, &[(1, 1), (2, 2)]);
        assert_eq!(
            resolve_collect_target(&ev).expect("resolvable"),
            CollectTarget::Sweep(PSlot::from_raw(2), persona(2)),
        );

        let state = pscan(Vec::new(), both, Vec::new(), Vec::new());
        let ev = evidence(Some(state), None, &[(1, 1), (2, 2)]);
        assert_eq!(
            resolve_collect_target(&ev).expect("resolvable"),
            CollectTarget::NothingLeft
        );

        let ev = evidence(
            Some(pscan(Vec::new(), BTreeMap::new(), Vec::new(), Vec::new())),
            None,
            &[],
        );
        assert_eq!(
            resolve_collect_target(&ev).expect("resolvable"),
            CollectTarget::NoExit
        );
    }

    /// This bites against the seam's two pending refusals collapsing onto
    /// one façade arm (review-1, Bugbot: `BondPostPending` mapped to
    /// `ExitInProgress` sent a just-bonded wallet to `collect_unstaked`,
    /// which answers `NoExit` — the GC-bridge window makes the seam arm
    /// reachable past resolution). The two remedies point at different
    /// verbs, so the arms must stay distinct. It does NOT cover the RPC
    /// code mapping (error.rs's table test).
    #[test]
    fn the_two_pending_refusals_flatten_to_their_own_arms() {
        assert!(matches!(
            flatten_unstake_error(UnbondRequestError::UnbondPending),
            UnstakeError::ExitInProgress
        ));
        assert!(matches!(
            flatten_unstake_error(UnbondRequestError::BondPostPending),
            UnstakeError::BondConfirming
        ));
    }

    /// The façade's structural pins, `drain_facade`-tripwire style (comment
    /// lines stripped; the test module excluded from the scan):
    ///
    /// 1. **No slot steering and no active-persona resolution:** the
    ///    production section never takes a `p_slot:` parameter and never
    ///    calls `.active_persona()` — both verbs resolve engine-side from
    ///    the sealed evidence (the anti-shape on each side: a wire slot
    ///    would steer the exit; the active persona would strand rotated
    ///    personas).
    /// 2. **Production witness mints:** the SP-R0 witness is
    ///    `arm1_watch_pruning_live` (never `for_test`), and the sweep
    ///    intent is built ONLY from `TerminalExitObserved::for_persona` on
    ///    the same evidence the resolution read.
    /// 3. **The sweep rides the drain seam** (`submit_drain`) and the post
    ///    rides the exit seam (`submit_unbond`) — no other dispatch path.
    #[test]
    fn facade_cannot_steer_slot_or_mint_test_witnesses() {
        let (production, _tests) = include_str!("unstake_facade.rs")
            .split_once("\n#[cfg(test)]")
            .expect("unstake_facade.rs has a #[cfg(test)] section to exclude from the scan");
        let code: String = production
            .lines()
            .filter(|l| !l.trim_start().starts_with("//") && !l.trim_start().starts_with("//!"))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            !code.contains("p_slot:"),
            "the façade must not take or bind a wire slot parameter"
        );
        assert!(
            !code.contains(".active_persona()"),
            "neither verb may resolve the active persona — rotated-away \
             personas must stay exitable and collectable"
        );
        assert!(
            code.contains("SpentRecordsDurablyPruned::arm1_watch_pruning_live()")
                && !code.contains("SpentRecordsDurablyPruned::for_test()"),
            "production mints the live SP-R0 witness only"
        );
        assert!(
            code.contains("TerminalExitObserved::for_persona"),
            "the sweep intent is built only from the observed-exit witness mint"
        );
        assert!(
            code.contains("Engine::submit_unbond(") && code.contains("Engine::submit_drain("),
            "the two verbs ride exactly the two production seams"
        );
    }
}
