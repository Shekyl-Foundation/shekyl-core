// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The engine cadence driver (`docs/design/ENGINE_CADENCE_DRIVER.md`).
//!
//! One engine-owned loop that schedules the wallet's non-interactive
//! maintenance legs — the entry points that were built with no scheduler
//! (submit lifecycle, serving liveness, per-epoch claim, terminal-reject
//! prune/resubmit). The design doc §1 records why this overturns the
//! prior "cadence is the embedding runtime's" policy: none of these legs
//! is interactive, all of them fail silently when unstarted, and the
//! embedder-called-tick shape already produced exactly that failure once.
//!
//! # Tick architecture (§2)
//!
//! Two clocks. The loop polls the daemon tip on a fixed wall-clock
//! interval but **fires legs only when the observed tip height
//! advanced** — firing against a known-stale view is the failure the
//! chain-progress base exists to prevent (an eclipsed staker
//! auto-claiming against an attacker's chain view is the named hazard).
//! Because a chain-progress tick goes silent when the chain does, the
//! loop carries a wall-clock watchdog *on the tick*: no observed advance
//! past the horizon raises [`AlarmCondition::ChainProgress`] and legs
//! stay quiet; the alarm clears on the next observed advance.
//!
//! # Ownership (§1 "Ownership and close")
//!
//! The driver task holds a **`Weak`** engine reference and upgrades per
//! tick; a failed upgrade means the engine is closing and the loop
//! exits. The [`CadenceHandle`] is embedder-held (the [`PScanHandle`]
//! discipline), so `Arc::try_unwrap → close` keeps working; the pscan
//! module's "reopen engine-held storage only if the store moves to a
//! Weak upgrade-per-sweep shape" reopening criterion is exactly the
//! shape this module has.
//!
//! [`PScanHandle`]: super::pscan::start::PScanHandle
//! [`AlarmCondition::ChainProgress`]: shekyl_operator_alarm::AlarmCondition::ChainProgress

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::time::Duration;

use shekyl_operator_alarm::cadence::{apply_chain_progress, ChainProgressObservation};
use shekyl_operator_alarm::{AlarmCondition, OperatorAlarms};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use shekyl_engine_file::WalletFile;

use super::pscan::cadence::{FixedRateSchedule, ScanSchedule};
use super::signer::EngineSignerKind;
use super::stake_engine::serving::{ServingHandle, ServingPosture, ServingStartError};
use super::submit_lifecycle::WatchdogHost;
use super::traits::{
    DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, PersistenceEngine, RefreshEngine,
};
use super::Engine;

/// Wall-clock interval between tip polls (rule 75: rationale + bounds).
///
/// **Rationale.** The poll is one `get_info`-class read per tick; legs fire
/// only on an observed height advance, so the poll rate bounds *detection
/// latency*, not work rate. 60 s keeps worst-case leg latency within half a
/// block target (120 s) for one cheap RPC per minute — the same figure the
/// P-scan sweep uses ([`DEFAULT_PSCAN_CADENCE`]), deliberately, though the
/// equality is not load-bearing: the two loops poll independently and may
/// diverge without coordination.
///
/// **Bounds.** [10 s, 300 s] is safe: below wastes RPC (blocks arrive ~120 s
/// apart), above only delays leg fires and watchdog detection. Not
/// embedder-tunable (rule 81); tests inject their own schedule through
/// [`spawn_cadence_loop`].
///
/// [`DEFAULT_PSCAN_CADENCE`]: super::pscan::start::DEFAULT_PSCAN_CADENCE
pub(crate) const DEFAULT_CADENCE_POLL: Duration = Duration::from_secs(60);

/// Watchdog horizon: no observed tip advance for this long raises
/// [`AlarmCondition::ChainProgress`] (rule 75: rationale + bounds).
///
/// **Rationale.** 30 minutes = 15 blocks at the 120 s target. Block
/// intervals are exponential, so multi-minute gaps are routine; 15 missed
/// targets is P(no block) ≈ e⁻¹⁵ on a healthy chain and daemon — at that
/// point the alarm is telling the operator about a real condition (daemon
/// down/behind, or the chain itself stalled), not variance.
///
/// **Bounds.** [10 min, 2 h]: below alarm-fatigues on ordinary variance;
/// above leaves the operator blind to a dead daemon for hours while every
/// leg silently stops firing.
pub(crate) const CHAIN_STALL_HORIZON: Duration = Duration::from_secs(30 * 60);

/// One tip-poll result, as the loop consumes it.
pub(crate) enum TipPoll {
    /// The daemon answered with its current chain height.
    Height(u64),
    /// The daemon did not answer (transport error, timeout). Counts as
    /// no-advance: the watchdog accrues, which is the designed conflation —
    /// [`ChainProgressStalled`] deliberately covers "daemon unreachable"
    /// and "chain stalled" with one condition (§5; the variant doc tells
    /// renderers to name both).
    ///
    /// [`ChainProgressStalled`]: shekyl_operator_alarm::OperatorAlarm::ChainProgressStalled
    Unavailable,
    /// The engine is gone (the `Weak` upgrade failed): the wallet is
    /// closing. The loop exits.
    EngineGone,
}

/// A registered driver leg (`ENGINE_CADENCE_DRIVER.md` §3).
///
/// Legs evaluate every fire and may no-op; the *driver* decides when to
/// fire (on observed chain advance), the *leg* decides whether its
/// predicate holds. `fire` returns a `'static` boxed future because the
/// driver runs each fire inside [`tokio::spawn`] — the panic isolation
/// boundary: a panicking leg parks (with
/// [`DisarmedReason::DriverLegParked`] on its condition when it has one)
/// and the other legs keep firing.
///
/// [`DisarmedReason::DriverLegParked`]: shekyl_operator_alarm::DisarmedReason::DriverLegParked
pub(crate) trait CadenceLeg: Send + 'static {
    /// Stable name for logs and park records.
    fn name(&self) -> &'static str;

    /// The alarm condition parked when this leg panics; `None` for legs
    /// with no condition of their own yet.
    fn park_condition(&self) -> Option<AlarmCondition>;

    /// One fire at the given observed tip height.
    fn fire(&mut self, tip: u64) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

    /// Wind down anything the leg owns. Awaited by the loop after it exits
    /// (cancellation or [`TipPoll::EngineGone`]), so it completes before the
    /// embedder's [`CadenceHandle::shutdown`] returns. Runs for parked legs
    /// too: a panicked leg must not leak what it holds. Most legs own
    /// nothing; the serving-liveness leg shuts down the [`ServingHandle`] it
    /// parks, which is what keeps "stop advertising before the P-scan stops"
    /// an order the embedder's shutdown sequence still controls (§3 leg 2).
    fn teardown(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        Box::pin(async {})
    }
}

/// The one serving handle the driver parks (§3 leg 2: "restart makes the
/// driver the natural owner of the current handle"). Shared between the
/// serving-liveness leg (liveness reads, reap, restart writes), the
/// [`CadenceHandle`] (posture reads, open-time adoption), and the leg's
/// teardown. A `std` mutex, deliberately: every access is a brief
/// lock-inspect-release, and no `.await` ever runs under the guard.
pub(crate) type ServingSlot = Arc<std::sync::Mutex<Option<ServingHandle>>>;

/// The weak grip on the shared engine that every leg (and the tip poll)
/// holds — upgrade per fire, never a strong clone, so close is never
/// blocked (§1 "Ownership and close").
type WeakEngine<S, D, L, E, R, P, F> = Weak<RwLock<Engine<S, D, L, E, R, P, F>>>;

/// Leg 1 (`ENGINE_CADENCE_DRIVER.md` §3 leg 1): the submit lifecycle —
/// one [`Engine::run_submit_lifecycle_tick`] per chain advance. The tick
/// is the `DAEMON_SUBMIT_VERDICT.md` §5.3 driver step (F40 targeted
/// re-scan + escape ladder over every held tx); this leg is its
/// **production caller** — the scheduler §5.3 deferred to "the embedding
/// runtime" and no embedder ever built (design doc §0, the motivating
/// zero-caller month).
///
/// Holds the driver's `Weak`; a failed upgrade is a quiet no-op (the
/// wallet is closing and the loop is about to observe the same via
/// [`TipPoll::EngineGone`]). The engine **read** lock is held across the
/// tick's daemon round-trips — same discipline as every RPC handler; the
/// §5.3 constraint is only that no merge *write* lock is held, and the
/// driver's own overlay state has its own mutex precisely so the tick
/// never takes one (see `Engine::submit_driver`).
struct SubmitLifecycleLeg<S, D, L, E, R, P, F>
where
    S: EngineSignerKind,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine + WatchdogHost,
    F: PersistenceEngine,
{
    engine: WeakEngine<S, D, L, E, R, P, F>,
}

impl<S, D, L, E, R, P, F> CadenceLeg for SubmitLifecycleLeg<S, D, L, E, R, P, F>
where
    S: EngineSignerKind,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine + WatchdogHost,
    F: PersistenceEngine,
    Engine<S, D, L, E, R, P, F>: Send + Sync + 'static,
{
    fn name(&self) -> &'static str {
        "submit-lifecycle"
    }

    fn park_condition(&self) -> Option<AlarmCondition> {
        // The tick raises its own per-tx alarms through the watchdog host's
        // diagnostic sink; the driver has no condition to park for it.
        None
    }

    fn fire(&mut self, _tip: u64) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let weak = Weak::clone(&self.engine);
        Box::pin(async move {
            let Some(engine) = weak.upgrade() else {
                return;
            };
            engine.read().await.run_submit_lifecycle_tick().await;
        })
    }
}

/// Leg 2 (`ENGINE_CADENCE_DRIVER.md` §3 leg 2): serving liveness. The
/// predicate — **"a serving obligation exists AND the serving task is not
/// live"** — is evaluated every fire; when it holds, the leg makes one
/// [`Engine::start_serving_if_staker`] attempt. Self-arming: no unregister,
/// no session state, so one condition covers both the start that failed and
/// the serving that started and later died (a Tor drop, a task panic, a
/// lost descriptor). One attempt per chain-progress tick is the natural
/// backoff (≥ block cadence), so a broken Tor config gets no retry storm.
///
/// The *obligation* half of the predicate lives inside
/// `start_serving_if_staker` itself — a non-staker and an idle staker
/// return `Ok(None)` without claiming the serving slot — so the leg's own
/// check is only *liveness*: a parked handle whose task still runs
/// ([`ServingHandle::is_live`]) is a no-op fire.
///
/// [`ServingStartError::AlreadyRunning`] is a no-op, not a failure. The
/// engine's serving slot guard is the single-flight arbiter between this
/// leg and the embedder's own start (open, restore); the production
/// schedule's first tick is immediate, so the race is real: losing it means
/// the other starter won or is mid-start, and its handle reaches this
/// driver via [`CadenceHandle::adopt_serving`].
struct ServingLivenessLeg<S, D, L, E, R, P>
where
    S: EngineSignerKind + Send + Sync + 'static,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
{
    engine: WeakEngine<S, D, L, E, R, P, WalletFile>,
    /// The daemon address serving derives its shard set over — threaded from
    /// the embedder at driver start (`into_shared` / `start_cadence`), the
    /// same "the endpoint is the caller's" shape `start_serving_if_staker`
    /// itself documents.
    daemon_address: String,
    slot: ServingSlot,
}

impl<S, D, L, E, R, P> CadenceLeg for ServingLivenessLeg<S, D, L, E, R, P>
where
    S: EngineSignerKind + Send + Sync + 'static,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
    Engine<S, D, L, E, R, P, WalletFile>: Send + Sync + 'static,
{
    fn name(&self) -> &'static str {
        "serving-liveness"
    }

    fn park_condition(&self) -> Option<AlarmCondition> {
        // Each serving lifecycle carries its own alarm board on its handle
        // (`ServingHandle::alarms`); the driver has no condition to park.
        None
    }

    fn fire(&mut self, _tip: u64) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let weak = Weak::clone(&self.engine);
        let address = self.daemon_address.clone();
        let slot = Arc::clone(&self.slot);
        Box::pin(async move {
            // Liveness under a brief lock: a live task is the no-op fire; a
            // dead one is taken out for reaping. The `.await`s below run
            // with the guard released.
            let dead = {
                let mut held = slot.lock().expect("serving slot lock");
                match held.as_ref() {
                    Some(handle) if handle.is_live() => return,
                    Some(_) => held.take(),
                    None => None,
                }
            };
            if let Some(dead) = dead {
                // The task has already exited; this observes the exit (and
                // with it the engine slot guard's release) deterministically
                // before the restart below re-claims it.
                dead.shutdown().await;
            }
            let Some(engine) = weak.upgrade() else {
                return;
            };
            match Engine::start_serving_if_staker(engine, &address).await {
                Ok(Some(handle)) => {
                    *slot.lock().expect("serving slot lock") = Some(handle);
                }
                // `Ok(None)`: no obligation — a non-staker, or a staker with
                // no active persona; the predicate simply does not hold this
                // tick. `AlreadyRunning`: the embedder's own start is in
                // flight or won; its handle arrives via `adopt_serving`.
                Ok(None) | Err(ServingStartError::AlreadyRunning) => {}
                Err(e) => {
                    // Named rather than silent (rule 82); the leg retries on
                    // the next chain advance, and repeated failure alarms
                    // through the serving lifecycle's own board once a task
                    // does start and then faults.
                    tracing::warn!(
                        error = %e,
                        "serving-liveness leg: start attempt failed; \
                         retrying on the next chain advance"
                    );
                }
            }
        })
    }

    fn teardown(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        Box::pin(async move {
            let handle = self.slot.lock().expect("serving slot lock").take();
            if let Some(handle) = handle {
                // Awaited: the host stops tor before its listener, and this
                // completing is what lets the embedder's shutdown sequence
                // stop the P-scan only after the advertisement is gone.
                handle.shutdown().await;
            }
        })
    }
}

/// Leg 4's registered slot (`ENGINE_CADENCE_DRIVER.md` §3 leg 4): the
/// terminal-reject prune / byte-identical resubmit body is unbuilt —
/// `docs/FOLLOWUPS.md` "Drain/claim/unbond dispatch driver —
/// terminal-reject prune + byte-identical resubmit" (pre-genesis; the
/// prune half is a security item). The slot is registered **now** so the
/// body lands into proven wiring (tick, ordering, isolation) and must not
/// grow its own timer; it is a STAGED surface with a named consumer
/// (rule 23), not dead code. Its registration-and-invocation is asserted
/// by test (§7): an empty leg that no-ops must stay distinguishable from
/// a leg never registered.
pub(crate) struct TerminalRejectSlot;

impl CadenceLeg for TerminalRejectSlot {
    fn name(&self) -> &'static str {
        "terminal-reject"
    }

    fn park_condition(&self) -> Option<AlarmCondition> {
        None
    }

    fn fire(&mut self, _tip: u64) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        // Empty by design until the FOLLOWUPS body lands; see the type doc.
        Box::pin(async {})
    }
}

/// Consecutive claim-leg faults before [`AlarmCondition::EpochClaim`]
/// raises (rule 75: rationale + bounds).
///
/// **Rationale.** One fault is routine (a daemon restart, a transient
/// transport refusal); the leg retries on the next chain advance for free.
/// Three consecutive faults span ≥ 3 observed block advances — minutes of
/// wall time over distinct daemon round-trips — at which point the refusal
/// is a condition, not a blip.
///
/// **Bounds.** [2, 10]: 1 alarm-fatigues on transients; past ~10 the
/// operator has been blind to a real refusal for the better part of an
/// hour.
const CLAIM_FAULT_ALARM_THRESHOLD: u32 = 3;

/// Byte allowance for the single claim vin row, added to
/// [`EMISSION_NON_CLAIMS_RESERVE_BYTES`] when pricing the claim envelope —
/// the regtest-e2e fee model (live run 4: the bond's 32 KiB ceiling
/// underprices a claim, which carries two input proofs; overpaying is a
/// miner transfer, never a conservation term).
///
/// [`EMISSION_NON_CLAIMS_RESERVE_BYTES`]: super::emission_claim::EMISSION_NON_CLAIMS_RESERVE_BYTES
const CLAIM_VIN_ALLOWANCE_BYTES: usize = 2048;

/// Request timeout for the claim leg's loopback claim-source transport.
const CLAIM_RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// Leg 3's cross-tick state, shared between fires through an `Arc<Mutex>`
/// (a fire's future is `'static`, so it cannot borrow the leg).
/// Session-scoped, deliberately: everything durable about a claim lives in
/// the sealed [`PendingEmissionClaim`] record and the chain itself; this is
/// only the leg's memory of what it deferred and what it already looked at.
///
/// [`PendingEmissionClaim`]: shekyl_engine_state::pending_post_block::PendingEmissionClaim
#[derive(Default)]
struct ClaimLegState {
    /// The settled epoch as of the last **completed** evaluation (claimed,
    /// idle, or value-deferred). `None` until the first one — which is why
    /// a wallet closed for months evaluates its whole backlog on the first
    /// post-open tick (§4: expected; for a serving persona, liveness is
    /// already public). Not advanced by yields, faults, or a pending claim,
    /// so those retry on the next chain advance instead of waiting a close.
    evaluated_at_epoch: Option<u64>,
    /// The last `ValueDeferred` set, `(epoch, reward)` — kept because the
    /// reward is recomputed inside derivation and is no longer derivable
    /// once the window expires the epoch; pricing a forfeit honestly needs
    /// it (§4 evaluate-and-forfeit).
    held: Vec<(u64, u64)>,
    /// Consecutive faulted fires; reset by any completed evaluation.
    consecutive_faults: u32,
    /// Session-running forfeited total ([`record_forfeit`]'s contract: the
    /// standing alarm shows the full amount lost this session).
    forfeited_total: u64,
}

/// How one claim attempt resolved, classified from the dispatch seam's
/// error taxonomy into what the leg's state machine actually branches on.
enum ClaimOutcome {
    /// Policy hold (§4): the set is underwater; carry it.
    Deferred(Vec<(u64, u64)>),
    /// Nothing claimable — the idle state, not a fault.
    Idle,
    /// Not this tick, and not a fault: a live claim is already in flight
    /// (`ClaimPending`), or user work won an input race (`InputRaced` —
    /// the §3 asymmetry: user work always wins, the leg yields and the
    /// next tick selects against a fresh snapshot).
    Yield,
    /// A real refusal (transport, state read, assembly, dispatch).
    Fault,
}

/// Leg 3 (`ENGINE_CADENCE_DRIVER.md` §3 leg 3, §4): the per-epoch emission
/// claim. Un-GF-4: the "scheduling stays external (the GF-4 seam)"
/// comments deferred to a grading scheduler that was never built; this leg
/// is the scheduler, and the schedule is **uniform** — every staker wallet
/// evaluates at every settlement close (plus its own poll phase), no
/// per-wallet jitter, no grading. The *inclusion decision* is
/// value-conditional (the §4 concession): Σreward across held epochs must
/// clear [`EMISSION_CLAIM_FEE_FLOOR`] or the whole set holds
/// ([`EmissionClaimError::ValueDeferred`]), re-evaluated at every close,
/// **evaluate-and-forfeit** at the window floor — never force a claim whose
/// fee exceeds its reward.
///
/// Fire shape, in order:
///
/// 1. **Once per close:** no-op unless the settled epoch advanced past the
///    last completed evaluation (or a prior fire faulted/yielded — those
///    retry every advance).
/// 2. **Staker + active persona:** a non-staker produces no claim
///    observations at all (the board reads "not watched", honestly); an
///    idle staker has no claimant to sign as.
/// 3. **User work always wins (§3):** user-initiated pending-post
///    operations (drain / unstake / first-stake) hold the engine gate's
///    foreground gauge across their whole assemble→seal span. The leg reads
///    it twice — here, as a cheap pre-assembly skip, and authoritatively
///    inside the dispatch seam's seal critical section
///    ([`ForegroundHold`]), where the pending write lock totally orders the
///    check against every foreground registration: a user operation begun
///    before the leg seals forces the leg to yield; one begun after reads
///    the post-seal reservation set and selects around it. `InputRaced` on
///    the leg side stays a normal yield (the generation gate backstop),
///    never a fault.
///
/// [`ForegroundHold`]: super::claim_dispatch::EmissionClaimRequestError::ForegroundHold
/// 4. **Fee + transport:** the daemon's live economy estimate over the
///    claim envelope ([`CLAIM_VIN_ALLOWANCE_BYTES`]); the claim-source
///    fetch rides a fresh loopback [`LocalNodeRpc`] over the driver's
///    daemon address (a non-loopback daemon is a named, alarmable refusal:
///    claims currently require a loopback daemon).
/// 5. **Dispatch** through [`Engine::submit_emission_claim`] — the CB-3
///    seam, persist-before-dispatch and the audited submitter choke point
///    included.
///
/// [`EMISSION_CLAIM_FEE_FLOOR`]: shekyl_economics::EMISSION_CLAIM_FEE_FLOOR
/// [`EmissionClaimError::ValueDeferred`]: super::emission_claim::EmissionClaimError::ValueDeferred
/// [`LocalNodeRpc`]: super::prpc::LocalNodeRpc
struct EpochClaimLeg<S, D, L, E, R, P>
where
    S: EngineSignerKind + Send + Sync + 'static,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
{
    engine: WeakEngine<S, D, L, E, R, P, WalletFile>,
    /// The loopback daemon endpoint the claim-source fetch rides — the
    /// same embedder-supplied address leg 2 serves over.
    daemon_address: String,
    /// The driver's shared board ([`CadenceHandle::alarms`]).
    alarms: Arc<OperatorAlarms>,
    state: Arc<std::sync::Mutex<ClaimLegState>>,
}

/// Map the dispatch seam's refusal taxonomy onto the leg's branches.
fn classify_claim(error: &super::claim_dispatch::EmissionClaimRequestError) -> ClaimOutcome {
    use super::claim_dispatch::EmissionClaimRequestError as E;
    use super::claim_orchestrator::ClaimOrchestrationError as O;
    use super::emission_claim::EmissionClaimError as C;
    use super::stake_engine::StakeEngineError as SE;
    match error {
        E::ClaimPending | E::InputRaced | E::ForegroundHold => ClaimOutcome::Yield,
        E::Claim(O::Stake(SE::EmissionClaim(C::NoClaimableEpochs))) => ClaimOutcome::Idle,
        E::Claim(O::Stake(SE::EmissionClaim(C::ValueDeferred { value_deferred, .. }))) => {
            ClaimOutcome::Deferred(value_deferred.clone())
        }
        _ => ClaimOutcome::Fault,
    }
}

/// One completed evaluation (claimed / deferred / idle): sweep the
/// previously-held set for forfeits, replace it, advance the epoch
/// cursor, clear the fault streak, and read healthy on the board.
///
/// **Forfeit rule (§4):** a previously-held epoch that is in neither
/// the newly-claimed nor the newly-deferred set *and* has passed the
/// claim-window floor was let expire underwater — record it at its held
/// reward. (Missing but unexpired epochs just fell out of this
/// evaluation — a re-derivation picks them up next close; nothing to
/// record.)
fn claim_complete(
    state: &std::sync::Mutex<ClaimLegState>,
    alarms: &OperatorAlarms,
    settled: u64,
    claimed: &[u64],
    new_held: Vec<(u64, u64)>,
) {
    let mut s = state.lock().expect("claim leg state lock");
    let previously_held = std::mem::take(&mut s.held);
    for (epoch, reward) in previously_held {
        let still_present = claimed.contains(&epoch) || new_held.iter().any(|(e, _)| *e == epoch);
        if !still_present && shekyl_archival_retention::epoch_is_claim_expired(epoch, settled) {
            s.forfeited_total += reward;
            shekyl_operator_alarm::cadence::record_forfeit(alarms, epoch, s.forfeited_total);
            tracing::warn!(
                epoch,
                forfeited_atomic = reward,
                session_total = s.forfeited_total,
                "emission claim forfeited: epoch reached the window floor \
                 still below the fee floor and was let expire (§4 \
                 evaluate-and-forfeit)"
            );
        }
    }
    s.held = new_held;
    s.evaluated_at_epoch = Some(settled);
    s.consecutive_faults = 0;
    shekyl_operator_alarm::cadence::apply_claim(
        alarms,
        shekyl_operator_alarm::cadence::ClaimObservation::Current,
    );
}

/// One faulted fire: count it, and past the threshold raise the
/// backlog alarm. The oldest/outstanding figures derive from the last
/// completed evaluation — a heuristic that may **under**state the
/// backlog when the leg never completed one (it claims one outstanding
/// epoch, not the true count it cannot know without the derivation
/// that is itself faulting) — honest, never overstated.
fn claim_fault(
    state: &std::sync::Mutex<ClaimLegState>,
    alarms: &OperatorAlarms,
    settled: u64,
    detail: &dyn std::fmt::Display,
) {
    let mut s = state.lock().expect("claim leg state lock");
    s.consecutive_faults += 1;
    tracing::warn!(
        error = %detail,
        consecutive = s.consecutive_faults,
        "epoch-claim leg: attempt faulted; retrying on the next chain advance"
    );
    if s.consecutive_faults >= CLAIM_FAULT_ALARM_THRESHOLD {
        let oldest_epoch = s.evaluated_at_epoch.map_or(settled, |e| e + 1);
        let outstanding_epochs = settled.saturating_sub(oldest_epoch).max(1);
        shekyl_operator_alarm::cadence::apply_claim(
            alarms,
            shekyl_operator_alarm::cadence::ClaimObservation::Behind {
                oldest_epoch,
                outstanding_epochs,
            },
        );
    }
}

impl<S, D, L, E, R, P> CadenceLeg for EpochClaimLeg<S, D, L, E, R, P>
where
    S: EngineSignerKind + Send + Sync + 'static,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
    Engine<S, D, L, E, R, P, WalletFile>: Send + Sync + 'static,
{
    fn name(&self) -> &'static str {
        "epoch-claim"
    }

    fn park_condition(&self) -> Option<AlarmCondition> {
        Some(AlarmCondition::EpochClaim)
    }

    fn fire(&mut self, tip: u64) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let weak = Weak::clone(&self.engine);
        let address = self.daemon_address.clone();
        let alarms = Arc::clone(&self.alarms);
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            let settled = shekyl_archival_retention::settlement_epoch_at_height(tip);
            {
                let s = state.lock().expect("claim leg state lock");
                // Once per close — unless the last fire faulted or yielded,
                // which retry on every advance rather than waiting a close.
                if s.consecutive_faults == 0 && s.evaluated_at_epoch == Some(settled) {
                    return;
                }
            }
            let Some(engine) = weak.upgrade() else {
                return;
            };
            let (stake, daemon, pending_gate) = {
                let g = engine.read().await;
                let Some(stake) = g.stake_handle() else {
                    // Not a staker: no claim obligation, and deliberately no
                    // claim observation either — the board carries no
                    // EpochClaim row at all ("not watched", the honest
                    // rendering).
                    return;
                };
                (stake, g.daemon().clone(), g.pending_gate.clone())
            };
            let p_slot = match stake.active_persona().await {
                Ok(Some(identity)) => identity.p_slot,
                // An idle staker has no claimant to sign as this tick.
                Ok(None) => return,
                Err(e) => return claim_fault(&state, &alarms, settled, &e),
            };

            // §3: user work always wins. A raised foreground gauge means a
            // user-initiated pending-post operation (drain / unstake /
            // first-stake) is somewhere in its assemble→seal span; yield the
            // whole tick before spending any work. This pre-assembly read is
            // the cheap skip — the authoritative check runs inside the
            // dispatch seam's seal critical section (`ForegroundHold`), where
            // the write lock totally orders it against every foreground
            // registration. Ordinary transfers are not part of this gauge:
            // they fund from the wallet ledger under `output_locks`, a pool
            // disjoint from the persona funding gindexes claims reserve.
            if pending_gate.foreground_in_flight() {
                return;
            }

            let fee = match daemon.get_fee_estimates().await {
                Ok(estimates) => estimates.economy.calculate_fee_from_weight(
                    super::emission_claim::EMISSION_NON_CLAIMS_RESERVE_BYTES
                        + CLAIM_VIN_ALLOWANCE_BYTES,
                ),
                Err(e) => return claim_fault(&state, &alarms, settled, &e.into()),
            };
            let claim_rpc = match super::prpc::LocalNodeRpc::new(address, CLAIM_RPC_TIMEOUT).await {
                Ok(rpc) => rpc,
                Err(e) => {
                    // Named requirement (rule 82): the claim-source fetch is
                    // persona-isolated and currently loopback-only.
                    tracing::warn!(
                        error = %e,
                        "epoch-claim leg: emission claims require a loopback \
                         daemon address; claims are on hold until one is \
                         configured"
                    );
                    return claim_fault(&state, &alarms, settled, &e);
                }
            };

            match Engine::submit_emission_claim(
                engine,
                &claim_rpc,
                p_slot,
                shekyl_units::AtomicUnits::from_raw(fee),
                &super::bond_assembly::SpentRecordsDurablyPruned::arm1_watch_pruning_live(),
            )
            .await
            {
                Ok(receipt) => {
                    tracing::info!(
                        claimed = ?receipt.claim.claimed_epochs,
                        total_reward = receipt.claim.total_reward,
                        verdict = ?receipt.submit,
                        "emission claim dispatched"
                    );
                    claim_complete(
                        &state,
                        &alarms,
                        settled,
                        &receipt.claim.claimed_epochs,
                        Vec::new(),
                    );
                }
                Err(e) => match classify_claim(&e) {
                    ClaimOutcome::Idle => claim_complete(&state, &alarms, settled, &[], Vec::new()),
                    ClaimOutcome::Deferred(held) => {
                        tracing::debug!(
                            held = ?held,
                            "emission claim value-deferred: holding until the \
                             accumulated set clears the fee floor (§4)"
                        );
                        claim_complete(&state, &alarms, settled, &[], held);
                    }
                    ClaimOutcome::Yield => {}
                    ClaimOutcome::Fault => claim_fault(&state, &alarms, settled, &e),
                },
            }
        })
    }
}

/// The embedder-held driver handle: cancel-on-drop token + join handle
/// (the [`PScanHandle`] shape), parked beside the pscan/serving handles
/// for the open lifetime.
///
/// [`PScanHandle`]: super::pscan::start::PScanHandle
pub struct CadenceHandle {
    cancel_token: CancellationToken,
    // `Option` so [`shutdown`](Self::shutdown) can take the join handle out
    // for `.await` without moving a field out of a `Drop` type.
    join: Option<JoinHandle<()>>,
    alarms: Arc<OperatorAlarms>,
    serving: ServingSlot,
}

impl CadenceHandle {
    /// The operator alarm board the driver reports through
    /// (`ENGINE_CADENCE_DRIVER.md` §5): chain-progress watchdog, epoch-claim
    /// backlog, forfeit records, and parked-leg disarms. Held here because
    /// this is what the embedder holds — the [`ServingHandle::alarms`]
    /// rationale.
    ///
    /// [`ServingHandle::alarms`]: super::stake_engine::serving::ServingHandle::alarms
    #[must_use]
    pub fn alarms(&self) -> Arc<OperatorAlarms> {
        Arc::clone(&self.alarms)
    }

    /// Park an embedder-started serving lifecycle with the driver
    /// (`ENGINE_CADENCE_DRIVER.md` §3 leg 2). The embedder still makes the
    /// first start — wallet-rpc's open stays fail-closed — and then hands
    /// the handle here, so the serving-liveness leg owns restart and the
    /// driver's teardown owns the ordered shutdown.
    ///
    /// Cannot collide with a leg-started handle: the engine's serving slot
    /// guard is single-flight, so at most one live handle exists to park. A
    /// dead handle already parked is simply replaced (its token has fired or
    /// fires on drop; the task is gone either way).
    pub fn adopt_serving(&self, handle: ServingHandle) {
        *self.serving.lock().expect("serving slot lock") = Some(handle);
    }

    /// What the parked serving lifecycle is serving right now, or `None`
    /// when no host is parked — or the parked host has died, in which case
    /// the serving-liveness leg restarts it on the next chain advance and
    /// "not serving" is exactly the truth in the interim.
    ///
    /// A cheap snapshot read (brief lock, watch-channel `borrow`): a status
    /// query can never stall the thing that serves.
    #[must_use]
    pub fn serving_posture(&self) -> Option<ServingPosture> {
        self.serving
            .lock()
            .expect("serving slot lock")
            .as_ref()
            .and_then(ServingHandle::posture)
    }

    /// Fire the cancel token. Idempotent. The task observes it at the next
    /// poll (or mid-`select!`) and exits after any in-flight leg completes.
    pub fn cancel(&self) {
        self.cancel_token.cancel();
    }

    /// Cancel and await the task's exit — including the legs' teardown, so
    /// any serving lifecycle the driver parks is fully stopped (tor before
    /// listener, awaited) before this returns. Deterministically observing
    /// the stop is the step that makes a subsequent `Arc::try_unwrap` →
    /// `Engine::close` possible.
    pub async fn shutdown(mut self) {
        self.cancel_token.cancel();
        if let Some(join) = self.join.take() {
            // A `JoinError` here means the task panicked; on shutdown there
            // is nothing to recover, so we observe the result only to
            // retire it.
            let _outcome = join.await;
        }
    }
}

impl Drop for CadenceHandle {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

/// One leg plus its park state. Parking is loop-local: a parked leg is
/// never fired again this session (the panic left its state unknown;
/// re-firing it would run a leg whose invariants no longer hold), and the
/// park is rendered on the board via the leg's condition when it has one.
struct LegSlot {
    leg: Box<dyn CadenceLeg>,
    parked: bool,
}

/// Spawn the driver loop with injected schedule, tip source, and legs —
/// the test seam, and the single spawn site production goes through.
///
/// The tip source owns the engine access (a `Weak` upgrade per poll in
/// production); the loop itself is engine-generic-free so its behavior —
/// fire-on-advance, watchdog, ordering, isolation — is testable with
/// scripted polls.
/// `alarms` is caller-created (production: [`Engine::start_cadence`])
/// because the claim leg raises through the same board the loop's watchdog
/// and the handle's accessor share.
pub(crate) fn spawn_cadence_loop<Sched, TipFn, TipFut>(
    schedule: Sched,
    poll_tip: TipFn,
    legs: Vec<Box<dyn CadenceLeg>>,
    alarms: Arc<OperatorAlarms>,
    stall_horizon: Duration,
    serving: ServingSlot,
) -> CadenceHandle
where
    Sched: ScanSchedule,
    TipFn: FnMut() -> TipFut + Send + 'static,
    TipFut: Future<Output = TipPoll> + Send + 'static,
{
    let cancel_token = CancellationToken::new();
    let join = tokio::spawn(run_cadence_loop(
        schedule,
        poll_tip,
        legs,
        Arc::clone(&alarms),
        stall_horizon,
        cancel_token.clone(),
    ));
    CadenceHandle {
        cancel_token,
        join: Some(join),
        alarms,
        serving,
    }
}

/// The production leg registry, in fire order (§3: retire before
/// assemble — leg 1 releases reservations before leg 3 snapshots the
/// funding set; leg 4's prune is retire-class and precedes leg 3 too).
///
/// Complete as of commit 6: leg 1 (submit lifecycle), leg 2 (serving
/// liveness), the leg-4 slot (terminal-reject, body staged), leg 3
/// (per-epoch claim) — registered last so every retire-class leg has
/// already run when it snapshots the funding set.
///
/// `WalletFile`-specialized because legs 2 and 3's construction sites
/// (`start_serving_if_staker`, `submit_emission_claim`) are;
/// `daemon_address` is legs 2 and 3's, the shared `serving` slot is
/// leg 2's, and `alarms` is leg 3's (the driver-shared board).
pub(crate) fn production_legs<S, D, L, E, R, P>(
    engine: WeakEngine<S, D, L, E, R, P, WalletFile>,
    daemon_address: &str,
    serving: &ServingSlot,
    alarms: &Arc<OperatorAlarms>,
) -> Vec<Box<dyn CadenceLeg>>
where
    S: EngineSignerKind + Send + Sync + 'static,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine + WatchdogHost,
    Engine<S, D, L, E, R, P, WalletFile>: Send + Sync + 'static,
{
    vec![
        Box::new(SubmitLifecycleLeg {
            engine: Weak::clone(&engine),
        }),
        Box::new(ServingLivenessLeg {
            engine: Weak::clone(&engine),
            daemon_address: daemon_address.to_owned(),
            slot: Arc::clone(serving),
        }),
        Box::new(TerminalRejectSlot),
        Box::new(EpochClaimLeg {
            engine,
            daemon_address: daemon_address.to_owned(),
            alarms: Arc::clone(alarms),
            state: Arc::default(),
        }),
    ]
}

/// Convenience for production spawns: the default fixed-rate poll.
pub(crate) fn production_schedule() -> FixedRateSchedule {
    FixedRateSchedule::new(DEFAULT_CADENCE_POLL)
}

// `private_bounds`: the engine traits are deliberately `pub(crate)` behind the
// `pub` `Engine` (see the `#[allow(private_bounds)]` on the struct itself); every
// engine impl that restates them carries the same allow.
#[allow(private_bounds)]
impl<S, D, L, E, R, P> Engine<S, D, L, E, R, P, WalletFile>
where
    S: EngineSignerKind + Send + Sync + 'static,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine + WatchdogHost,
    Self: Send + Sync + 'static,
{
    /// Wrap an opened engine in its shared arc **and start the cadence
    /// driver** — the canonical wrap point (`ENGINE_CADENCE_DRIVER.md` §1
    /// "The structural start guarantee"). Replaces the bare
    /// `Arc::new(RwLock::new(engine))` in embedders so a wallet cannot be
    /// shared without its maintenance legs scheduled: a missing driver was
    /// the failure mode that left `run_submit_lifecycle_tick` with zero
    /// callers for a month.
    ///
    /// The driver task holds only a `Weak` to the returned arc (upgrade per
    /// poll; failed upgrade exits), so close is never blocked by it — but
    /// the embedder should still [`CadenceHandle::shutdown`] before
    /// `Arc::try_unwrap` so the exit is deterministic rather than
    /// next-poll.
    ///
    /// `daemon_address` is the serving-liveness leg's (§3 leg 2): serving
    /// derives its shard set over the caller's daemon endpoint, and the
    /// address lives with the embedder rather than on the `Engine` — the
    /// same shape `start_serving_if_staker` itself documents.
    ///
    /// # Panics
    ///
    /// Requires an ambient tokio runtime, because it spawns the driver task.
    /// This is not a new constraint — constructing an `Engine` already
    /// spawns the key-engine actor — but it is asserted here **by name** so
    /// a non-runtime embedder fails with the named requirement instead of a
    /// bare `tokio::spawn` panic (§1 "Runtime context").
    pub fn into_shared(self, daemon_address: &str) -> (Arc<RwLock<Self>>, CadenceHandle) {
        drop(tokio::runtime::Handle::try_current().expect(
            "Engine::into_shared spawns the cadence driver task and must be \
             called from within a tokio runtime (ENGINE_CADENCE_DRIVER.md §1)",
        ));
        let shared = Arc::new(RwLock::new(self));
        let handle = Self::start_cadence(&shared, daemon_address);
        (shared, handle)
    }

    /// Start the cadence driver against an **already-shared** engine — the
    /// restore-path re-arm (wallet-rpc's `restart_tasks` shape: a close that
    /// could not complete leaves the wallet open and must re-arm the tasks
    /// it shut down). New code wraps via [`into_shared`](Self::into_shared);
    /// this exists because the restore path structurally cannot (the engine
    /// is already inside its arc). Infallible: the driver polls its way to
    /// health rather than failing to start.
    ///
    /// # Panics
    ///
    /// Same runtime requirement as [`into_shared`](Self::into_shared).
    pub fn start_cadence(self_arc: &Arc<RwLock<Self>>, daemon_address: &str) -> CadenceHandle {
        let serving = ServingSlot::default();
        let alarms = Arc::new(OperatorAlarms::new());
        let legs = production_legs(Arc::downgrade(self_arc), daemon_address, &serving, &alarms);
        let weak = Arc::downgrade(self_arc);
        let poll = move || {
            let weak = weak.clone();
            async move {
                let Some(engine) = weak.upgrade() else {
                    return TipPoll::EngineGone;
                };
                // Clone the daemon under a brief read guard, then drop both
                // the guard and the strong arc before the round-trip: the
                // poll must never hold the engine (lock or liveness) across
                // a daemon await (§2 merge write-lock constraint).
                let daemon = engine.read().await.daemon.clone();
                drop(engine);
                match daemon.get_health().await {
                    Ok(health) => TipPoll::Height(health.height),
                    Err(_) => TipPoll::Unavailable,
                }
            }
        };
        spawn_cadence_loop(
            production_schedule(),
            poll,
            legs,
            alarms,
            CHAIN_STALL_HORIZON,
            serving,
        )
    }
}

/// The driver loop. Exits on cancellation or [`TipPoll::EngineGone`];
/// nothing else stops it — no leg error, panic, or daemon outage does
/// (§3 leg isolation).
async fn run_cadence_loop<Sched, TipFn, TipFut>(
    mut schedule: Sched,
    mut poll_tip: TipFn,
    legs: Vec<Box<dyn CadenceLeg>>,
    alarms: Arc<OperatorAlarms>,
    stall_horizon: Duration,
    cancel: CancellationToken,
) where
    Sched: ScanSchedule,
    TipFn: FnMut() -> TipFut + Send + 'static,
    TipFut: Future<Output = TipPoll> + Send + 'static,
{
    let mut slots: Vec<LegSlot> = legs
        .into_iter()
        .map(|leg| LegSlot { leg, parked: false })
        .collect();

    // The last height legs fired at, and when an advance was last observed.
    // `None` until the first successful poll: the first observation counts
    // as an advance (a wallet closed for months evaluates its backlog on
    // the first post-open tick that sees the chain, §4).
    let mut last_fired: Option<u64> = None;
    let mut last_advance = tokio::time::Instant::now();

    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            () = schedule.next_tick() => {}
        }

        let advanced_to = match poll_tip().await {
            TipPoll::EngineGone => break,
            TipPoll::Unavailable => None,
            TipPoll::Height(h) => match last_fired {
                // First reading, or a genuine advance.
                None => Some(h),
                Some(prev) if h > prev => Some(h),
                Some(_) => None,
            },
        };

        match advanced_to {
            Some(tip) => {
                last_fired = Some(tip);
                last_advance = tokio::time::Instant::now();
                apply_chain_progress(&alarms, ChainProgressObservation::Advancing);
                fire_legs(&mut slots, tip, &alarms).await;
            }
            None => {
                let stalled_for = last_advance.elapsed();
                if stalled_for >= stall_horizon {
                    apply_chain_progress(
                        &alarms,
                        ChainProgressObservation::Stalled {
                            last_height: last_fired.unwrap_or(0),
                            stalled_for_secs: stalled_for.as_secs(),
                        },
                    );
                }
                // Legs deliberately do not fire: evaluating against a
                // known-stale view is the failure the tick base prevents.
            }
        }
    }

    // The loop has exited (cancellation or engine-gone): wind down anything
    // the legs own, awaited, before the task ends — which is before
    // [`CadenceHandle::shutdown`] returns. The serving-liveness leg's
    // teardown stops the parked serving lifecycle here, so the embedder's
    // shutdown sequence (cadence first, then P-scan) preserves
    // stop-advertising-before-stop-scanning. Parked legs tear down too: a
    // panicked leg must not leak the handle it holds.
    for slot in slots {
        slot.leg.teardown().await;
    }
}

/// Fire every non-parked leg, in registration order, isolated: each fire
/// runs inside its own [`tokio::spawn`] so a panic is contained to the
/// leg — the leg parks (disarming its condition with
/// `DriverLegParked` when it has one) and the rest of the tick proceeds.
async fn fire_legs(slots: &mut [LegSlot], tip: u64, alarms: &OperatorAlarms) {
    for slot in slots.iter_mut().filter(|s| !s.parked) {
        let fut = slot.leg.fire(tip);
        match tokio::spawn(fut).await {
            Ok(()) => {}
            Err(join_error) => {
                // `is_panic` distinguishes a leg panic from a runtime
                // shutdown abort; on abort the loop is being torn down
                // anyway and parking is harmless.
                tracing::error!(
                    leg = slot.leg.name(),
                    panicked = join_error.is_panic(),
                    "cadence leg failed; parking it for this session \
                     (other legs unaffected)"
                );
                slot.parked = true;
                if let Some(condition) = slot.leg.park_condition() {
                    shekyl_operator_alarm::cadence::park_condition(alarms, condition);
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "cadence_tests.rs"]
mod tests;
