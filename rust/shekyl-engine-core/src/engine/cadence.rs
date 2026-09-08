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
use std::sync::Arc;
use std::time::Duration;

use shekyl_operator_alarm::cadence::{apply_chain_progress, ChainProgressObservation};
use shekyl_operator_alarm::{AlarmCondition, OperatorAlarms};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::pscan::cadence::{FixedRateSchedule, ScanSchedule};

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

    /// Fire the cancel token. Idempotent. The task observes it at the next
    /// poll (or mid-`select!`) and exits after any in-flight leg completes.
    pub fn cancel(&self) {
        self.cancel_token.cancel();
    }

    /// Cancel and await the task's exit: deterministically observes that the
    /// loop has stopped before returning — the step that makes a subsequent
    /// `Arc::try_unwrap` → `Engine::close` possible.
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
    }
}

/// The production leg registry, in fire order (§3: retire before
/// assemble — leg 1 releases reservations before leg 3 snapshots the
/// funding set; leg 4's prune is retire-class and precedes leg 3 too).
///
/// Grows with the implementation commits: leg 1 (submit lifecycle),
/// leg 2 (serving liveness), leg 3 (per-epoch claim) register here as
/// they land. Today: the leg-4 slot only.
pub(crate) fn production_legs() -> Vec<Box<dyn CadenceLeg>> {
    vec![Box::new(TerminalRejectSlot)]
}

/// Convenience for production spawns: the default fixed-rate poll.
pub(crate) fn production_schedule() -> FixedRateSchedule {
    FixedRateSchedule::new(DEFAULT_CADENCE_POLL)
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
        spawn_cadence_loop(EagerSchedule, scripted(polls), legs, stall_horizon)
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
    async fn terminal_reject_slot_is_registered_and_invoked_each_tick() {
        // Against the real production registry, wrapped in witnesses: an
        // empty leg that no-ops must stay distinguishable from a leg never
        // registered (ENGINE_CADENCE_DRIVER.md §7).
        let log = Arc::new(Mutex::new(Vec::new()));
        let legs: Vec<Box<dyn CadenceLeg>> = production_legs()
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
        assert!(
            fired.contains(&("terminal-reject", 1)) && fired.contains(&("terminal-reject", 2)),
            "the leg-4 slot must be registered and invoked on every advance, got {fired:?}"
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
        );
        handle.shutdown().await;
    }
}
