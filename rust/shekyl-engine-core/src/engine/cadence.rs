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
pub(crate) fn spawn_cadence_loop<Sched, TipFn, TipFut>(
    schedule: Sched,
    poll_tip: TipFn,
    legs: Vec<Box<dyn CadenceLeg>>,
    stall_horizon: Duration,
    serving: ServingSlot,
) -> CadenceHandle
where
    Sched: ScanSchedule,
    TipFn: FnMut() -> TipFut + Send + 'static,
    TipFut: Future<Output = TipPoll> + Send + 'static,
{
    let alarms = Arc::new(OperatorAlarms::new());
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
/// Grows with the implementation commits: leg 3 (per-epoch claim)
/// registers here as it lands, after the leg-4 slot. Today: leg 1 (submit
/// lifecycle), leg 2 (serving liveness), and the leg-4 slot.
///
/// `WalletFile`-specialized because leg 2's construction site
/// (`start_serving_if_staker`) is; `daemon_address` and the shared
/// `serving` slot are leg 2's (see [`ServingLivenessLeg`]).
pub(crate) fn production_legs<S, D, L, E, R, P>(
    engine: WeakEngine<S, D, L, E, R, P, WalletFile>,
    daemon_address: &str,
    serving: &ServingSlot,
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
            engine,
            daemon_address: daemon_address.to_owned(),
            slot: Arc::clone(serving),
        }),
        Box::new(TerminalRejectSlot),
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
        let legs = production_legs(Arc::downgrade(self_arc), daemon_address, &serving);
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
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use shekyl_operator_alarm::{Arming, OperatorAlarm};

    use super::*;

    /// A scripted tip source: pops one poll result per call and reports
    /// the engine gone when the script runs out, so the loop (and the
    /// test) terminates deterministically.
    fn scripted(
        polls: Vec<TipPoll>,
    ) -> impl FnMut() -> std::future::Ready<TipPoll> + Send + 'static {
        let mut script: VecDeque<TipPoll> = polls.into();
        move || std::future::ready(script.pop_front().unwrap_or(TipPoll::EngineGone))
    }

    /// A schedule that fires immediately, every time; the scripted tip
    /// source is what bounds the loop.
    struct EagerSchedule;
    impl ScanSchedule for EagerSchedule {
        fn next_tick(&mut self) -> impl Future<Output = ()> + Send {
            std::future::ready(())
        }
    }

    /// Records `(name, tip)` per fire into a shared log.
    struct RecordingLeg {
        name: &'static str,
        log: Arc<Mutex<Vec<(&'static str, u64)>>>,
        condition: Option<AlarmCondition>,
        panic_on_fire: bool,
    }

    impl RecordingLeg {
        fn recording(
            name: &'static str,
            log: &Arc<Mutex<Vec<(&'static str, u64)>>>,
        ) -> Box<dyn CadenceLeg> {
            Box::new(Self {
                name,
                log: Arc::clone(log),
                condition: None,
                panic_on_fire: false,
            })
        }
    }

    impl CadenceLeg for RecordingLeg {
        fn name(&self) -> &'static str {
            self.name
        }

        fn park_condition(&self) -> Option<AlarmCondition> {
            self.condition
        }

        fn fire(&mut self, tip: u64) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
            let log = Arc::clone(&self.log);
            let name = self.name;
            let panic_on_fire = self.panic_on_fire;
            Box::pin(async move {
                if panic_on_fire {
                    panic!("scripted leg panic");
                }
                log.lock().expect("test log lock").push((name, tip));
            })
        }
    }

    /// Delegating wrapper that proves a production leg is invoked — used
    /// by the leg-4 slot test so the assertion runs against the real
    /// [`production_legs`] registry, not a stand-in.
    struct Witness {
        inner: Box<dyn CadenceLeg>,
        log: Arc<Mutex<Vec<(&'static str, u64)>>>,
    }

    impl CadenceLeg for Witness {
        fn name(&self) -> &'static str {
            self.inner.name()
        }

        fn park_condition(&self) -> Option<AlarmCondition> {
            self.inner.park_condition()
        }

        fn fire(&mut self, tip: u64) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
            self.log
                .lock()
                .expect("test log lock")
                .push((self.inner.name(), tip));
            self.inner.fire(tip)
        }
    }

    fn drive(
        polls: Vec<TipPoll>,
        legs: Vec<Box<dyn CadenceLeg>>,
        stall_horizon: Duration,
    ) -> CadenceHandle {
        spawn_cadence_loop(
            EagerSchedule,
            scripted(polls),
            legs,
            stall_horizon,
            ServingSlot::default(),
        )
    }

    #[tokio::test]
    async fn fires_only_on_height_advance_first_reading_included() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let handle = drive(
            vec![
                TipPoll::Height(10),  // first reading: fires (post-open backlog)
                TipPoll::Height(10),  // no advance: quiet
                TipPoll::Unavailable, // no advance: quiet
                TipPoll::Height(9),   // below last fired (reorg view): quiet
                TipPoll::Height(11),  // advance: fires
            ],
            vec![RecordingLeg::recording("leg", &log)],
            CHAIN_STALL_HORIZON,
        );
        let mut handle = handle;
        handle.join.take().expect("join").await.expect("loop exit");
        assert_eq!(*log.lock().expect("log"), vec![("leg", 10), ("leg", 11)]);
    }

    #[tokio::test(start_paused = true)]
    async fn watchdog_raises_on_stall_and_clears_on_resume() {
        // A schedule the test can step over paused time: fixed rate at the
        // production poll, with the stall horizon set to two polls.
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut polls = vec![TipPoll::Height(5)];
        polls.extend((0..4).map(|_| TipPoll::Unavailable));
        polls.push(TipPoll::Height(6));
        polls.push(TipPoll::Unavailable); // one read of the cleared board
        let handle = spawn_cadence_loop(
            FixedRateSchedule::new(Duration::from_secs(60)),
            scripted(polls),
            vec![RecordingLeg::recording("leg", &log)],
            Duration::from_secs(120),
            ServingSlot::default(),
        );
        let alarms = handle.alarms();
        let mut handle = handle;
        handle.join.take().expect("join").await.expect("loop exit");

        // The stall alarm was raised while unavailable and cleared by the
        // resume.
        let board = alarms.board();
        let chain = board
            .condition(AlarmCondition::ChainProgress)
            .expect("chain-progress condition reported");
        assert_eq!(
            chain.arming(),
            Arming::Armed,
            "resume must leave the condition armed and clear"
        );
        assert!(
            chain.live().is_none(),
            "advance must clear the stall alarm, got {:?}",
            chain.live()
        );
        // Legs fired exactly on the two advances, never during the stall.
        assert_eq!(*log.lock().expect("log"), vec![("leg", 5), ("leg", 6)]);
    }

    #[tokio::test(start_paused = true)]
    async fn stall_alarm_carries_last_height_and_duration() {
        let handle = spawn_cadence_loop(
            FixedRateSchedule::new(Duration::from_secs(60)),
            scripted(vec![
                TipPoll::Height(42),
                TipPoll::Unavailable,
                TipPoll::Unavailable,
                TipPoll::Unavailable,
            ]),
            Vec::new(),
            Duration::from_secs(120),
            ServingSlot::default(),
        );
        let alarms = handle.alarms();
        let mut handle = handle;
        handle.join.take().expect("join").await.expect("loop exit");

        let board = alarms.board();
        let chain = board
            .condition(AlarmCondition::ChainProgress)
            .expect("condition reported");
        match chain.live().map(shekyl_operator_alarm::RaisedAlarm::alarm) {
            Some(OperatorAlarm::ChainProgressStalled {
                last_height,
                stalled_for_secs,
            }) => {
                assert_eq!(last_height, 42);
                assert!(
                    stalled_for_secs >= 120,
                    "stall duration must cover the horizon, got {stalled_for_secs}"
                );
            }
            other => panic!("expected ChainProgressStalled, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn legs_fire_in_registration_order_every_advance() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let handle = drive(
            vec![TipPoll::Height(1), TipPoll::Height(2)],
            vec![
                RecordingLeg::recording("retire", &log),
                RecordingLeg::recording("assemble", &log),
            ],
            CHAIN_STALL_HORIZON,
        );
        let mut handle = handle;
        handle.join.take().expect("join").await.expect("loop exit");
        assert_eq!(
            *log.lock().expect("log"),
            vec![
                ("retire", 1),
                ("assemble", 1),
                ("retire", 2),
                ("assemble", 2)
            ]
        );
    }

    #[tokio::test]
    async fn panicking_leg_parks_with_condition_and_others_keep_firing() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let panicker = Box::new(RecordingLeg {
            name: "panicker",
            log: Arc::clone(&log),
            condition: Some(AlarmCondition::EpochClaim),
            panic_on_fire: true,
        });
        let handle = drive(
            vec![TipPoll::Height(1), TipPoll::Height(2)],
            vec![panicker, RecordingLeg::recording("survivor", &log)],
            CHAIN_STALL_HORIZON,
        );
        let alarms = handle.alarms();
        let mut handle = handle;
        handle.join.take().expect("join").await.expect("loop exit");

        // The survivor fired on both advances; the panicker never recorded
        // (it panicked before logging) and was not re-fired.
        assert_eq!(
            *log.lock().expect("log"),
            vec![("survivor", 1), ("survivor", 2)]
        );
        let board = alarms.board();
        let claim = board
            .condition(AlarmCondition::EpochClaim)
            .expect("parked condition present on the board");
        assert!(
            matches!(
                claim.arming(),
                Arming::Disarmed(shekyl_operator_alarm::DisarmedReason::DriverLegParked)
            ),
            "panicked leg must park its condition, got {:?}",
            claim.arming()
        );
    }

    #[tokio::test]
    async fn production_legs_are_registered_and_invoked_each_tick() {
        // Against the real production registry, wrapped in witnesses: an
        // empty leg that no-ops must stay distinguishable from a leg never
        // registered (ENGINE_CADENCE_DRIVER.md §7). A dead `Weak` stands in
        // for the engine — the submit-lifecycle leg's upgrade fails and it
        // no-ops, which is exactly the closing-wallet path; the assertion
        // is registration and invocation, not tick effect.
        let dead: Weak<RwLock<Engine<super::super::signer::SoloSigner>>> = Weak::new();
        let log = Arc::new(Mutex::new(Vec::new()));
        let legs: Vec<Box<dyn CadenceLeg>> =
            production_legs(dead, "http://127.0.0.1:1", &ServingSlot::default())
                .into_iter()
                .map(|inner| {
                    Box::new(Witness {
                        inner,
                        log: Arc::clone(&log),
                    }) as Box<dyn CadenceLeg>
                })
                .collect();
        let handle = drive(
            vec![TipPoll::Height(1), TipPoll::Height(2)],
            legs,
            CHAIN_STALL_HORIZON,
        );
        let mut handle = handle;
        handle.join.take().expect("join").await.expect("loop exit");
        let fired = log.lock().expect("log").clone();
        for leg in ["submit-lifecycle", "serving-liveness", "terminal-reject"] {
            assert!(
                fired.contains(&(leg, 1)) && fired.contains(&(leg, 2)),
                "{leg} must be registered and invoked on every advance, got {fired:?}"
            );
        }
        // Fire order is the §3 retire-before-assemble registration order.
        assert_eq!(
            fired[..3],
            [
                ("submit-lifecycle", 1),
                ("serving-liveness", 1),
                ("terminal-reject", 1)
            ],
            "registration order must be preserved per tick"
        );
    }

    #[tokio::test]
    async fn engine_gone_exits_the_loop_without_cancel() {
        let handle = drive(vec![TipPoll::EngineGone], Vec::new(), CHAIN_STALL_HORIZON);
        let mut handle = handle;
        // No cancel: the failed upgrade alone must end the task.
        handle.join.take().expect("join").await.expect("loop exit");
    }

    #[tokio::test]
    async fn handle_drop_cancels_the_task() {
        // An endless script (always unavailable) — only the drop ends it.
        let handle = spawn_cadence_loop(
            EagerSchedule,
            || std::future::ready(TipPoll::Unavailable),
            Vec::new(),
            CHAIN_STALL_HORIZON,
            ServingSlot::default(),
        );
        let cancel_probe = handle.cancel_token.clone();
        drop(handle);
        assert!(cancel_probe.is_cancelled(), "drop must fire the token");
    }

    #[tokio::test]
    async fn shutdown_awaits_task_exit() {
        let handle = spawn_cadence_loop(
            EagerSchedule,
            || std::future::ready(TipPoll::Unavailable),
            Vec::new(),
            CHAIN_STALL_HORIZON,
            ServingSlot::default(),
        );
        handle.shutdown().await;
    }

    /// A leg whose only job is proving [`CadenceLeg::teardown`] runs.
    struct TeardownProbe {
        log: Arc<Mutex<Vec<&'static str>>>,
    }

    impl CadenceLeg for TeardownProbe {
        fn name(&self) -> &'static str {
            "teardown-probe"
        }

        fn park_condition(&self) -> Option<AlarmCondition> {
            None
        }

        fn fire(&mut self, _tip: u64) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
            Box::pin(async {})
        }

        fn teardown(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
            Box::pin(async move {
                self.log.lock().expect("probe log").push("torn-down");
            })
        }
    }

    #[tokio::test]
    async fn leg_teardown_runs_before_shutdown_returns() {
        // Cancellation path: shutdown must observe the teardown, not race it.
        let log = Arc::new(Mutex::new(Vec::new()));
        let handle = spawn_cadence_loop(
            EagerSchedule,
            || std::future::ready(TipPoll::Unavailable),
            vec![Box::new(TeardownProbe {
                log: Arc::clone(&log),
            }) as Box<dyn CadenceLeg>],
            CHAIN_STALL_HORIZON,
            ServingSlot::default(),
        );
        handle.shutdown().await;
        assert_eq!(*log.lock().expect("probe log"), vec!["torn-down"]);
    }

    #[tokio::test]
    async fn leg_teardown_runs_on_engine_gone_too() {
        // The close path that never calls shutdown: the failed upgrade exits
        // the loop, and anything a leg holds must still wind down.
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut handle = drive(
            vec![TipPoll::EngineGone],
            vec![Box::new(TeardownProbe {
                log: Arc::clone(&log),
            }) as Box<dyn CadenceLeg>],
            CHAIN_STALL_HORIZON,
        );
        handle.join.take().expect("join").await.expect("loop exit");
        assert_eq!(*log.lock().expect("probe log"), vec!["torn-down"]);
    }

    /// A schedule the test steps by hand: one tick per `send`, pending
    /// forever once the sender drops (the loop then ends via cancel or
    /// engine-gone). This is what lets a test interleave its own actions —
    /// killing the serving task — between ticks deterministically.
    struct StepSchedule(tokio::sync::mpsc::UnboundedReceiver<()>);

    impl ScanSchedule for StepSchedule {
        fn next_tick(&mut self) -> impl Future<Output = ()> + Send {
            let recv = self.0.recv();
            async move {
                if recv.await.is_none() {
                    std::future::pending::<()>().await;
                }
            }
        }
    }

    /// Poll `probe` until it returns true or the budget runs out. The
    /// serving task's exit and the leg's restart are both asynchronous to
    /// the test; this is the bounded wait that observes them.
    async fn eventually(mut probe: impl FnMut() -> bool, what: &str) {
        for _ in 0..500 {
            if probe() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for: {what}");
    }

    /// Leg 2 end-to-end (`ENGINE_CADENCE_DRIVER.md` §3 leg 2, §7): against a
    /// real staker engine, the serving-liveness leg starts the host when the
    /// slot is empty, no-ops while it is live, and — the fire-once fix —
    /// restarts it after the running task dies mid-session.
    #[tokio::test(flavor = "multi_thread")]
    async fn serving_liveness_leg_starts_and_restarts_a_dead_serving_task() {
        let (_tmp, engine) = crate::engine::test_support::staker_engine(3, 11);
        crate::engine::test_support::activate_persona(&engine, 3).await;
        let arc = Arc::new(RwLock::new(engine));

        let slot = ServingSlot::default();
        let legs = production_legs(Arc::downgrade(&arc), "http://127.0.0.1:1", &slot);
        let (tick, rx) = tokio::sync::mpsc::unbounded_channel();
        let heights = std::sync::atomic::AtomicU64::new(0);
        let handle = spawn_cadence_loop(
            StepSchedule(rx),
            move || {
                let h = heights.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                std::future::ready(TipPoll::Height(h))
            },
            legs,
            CHAIN_STALL_HORIZON,
            Arc::clone(&slot),
        );

        // Tick 1: the slot is empty, the predicate holds, the leg starts
        // the host.
        tick.send(()).expect("loop alive");
        eventually(
            || {
                slot.lock()
                    .expect("slot")
                    .as_ref()
                    .is_some_and(ServingHandle::is_live)
            },
            "leg 2 to start the serving host from an empty slot",
        )
        .await;

        // Kill the running task in place (a panic/Tor-drop stand-in),
        // leaving the dead handle parked — the died-later case the
        // unregister design could not recover.
        slot.lock()
            .expect("slot")
            .as_ref()
            .expect("parked handle")
            .cancel();
        eventually(
            || {
                slot.lock()
                    .expect("slot")
                    .as_ref()
                    .is_some_and(|h| !h.is_live())
            },
            "the cancelled serving task to read dead",
        )
        .await;

        // Tick 2: the predicate holds again (obligation exists, task not
        // live); the leg reaps the dead handle and starts a fresh host.
        tick.send(()).expect("loop alive");
        eventually(
            || {
                slot.lock()
                    .expect("slot")
                    .as_ref()
                    .is_some_and(ServingHandle::is_live)
            },
            "leg 2 to reap the dead handle and restart the host",
        )
        .await;

        // Shutdown tears the restarted host down via the leg's teardown and
        // releases the engine's serving slot guard.
        handle.shutdown().await;
        assert!(
            !arc.read().await.open_slots.serving.is_claimed(),
            "driver shutdown must wind the serving task down and release its slot"
        );
    }
}
