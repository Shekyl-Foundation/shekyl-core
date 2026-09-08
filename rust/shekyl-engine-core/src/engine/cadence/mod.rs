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
//! Legs live in sibling modules ([`submit`], [`serving`], [`claim`]); this
//! file is the scheduler — trait, loop, watchdog, handle, registry.
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

mod claim;
mod serving;
mod submit;

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::time::Duration;

use shekyl_engine_file::WalletFile;
use shekyl_operator_alarm::cadence::{apply_chain_progress, ChainProgressObservation};
use shekyl_operator_alarm::{AlarmCondition, OperatorAlarms};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::pscan::cadence::{FixedRateSchedule, ScanSchedule};
use super::signer::EngineSignerKind;
use super::stake_engine::serving::{ServingHandle, ServingPosture};
use super::submit_lifecycle::WatchdogHost;
use super::traits::{DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, RefreshEngine};
use super::Engine;

use self::serving::ServingLivenessLeg;
use self::submit::SubmitLifecycleLeg;

pub(crate) use self::claim::EpochClaimLeg;
#[cfg(test)]
pub(crate) use self::claim::{
    claim_complete, claim_fault, ClaimLegState, CLAIM_FAULT_ALARM_THRESHOLD,
};

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
pub(crate) type WeakEngine<S, D, L, E, R, P, F> = Weak<RwLock<Engine<S, D, L, E, R, P, F>>>;

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
#[path = "../cadence_tests.rs"]
mod tests;
