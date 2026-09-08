// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for the engine cadence driver (`engine/cadence.rs`).
//!
//! Wired as a `#[path]` child of `cadence::tests`, so `use super::*`
//! resolves into the driver module and private items stay testable;
//! the sibling file exists so the decomposition ratchet counts the
//! workflow file, not its test suite (the `proofs_tests.rs` pattern).

use std::collections::VecDeque;
use std::sync::Mutex;

use shekyl_operator_alarm::{Arming, OperatorAlarm};

use super::*;

/// A scripted tip source: pops one poll result per call and reports
/// the engine gone when the script runs out, so the loop (and the
/// test) terminates deterministically.
fn scripted(polls: Vec<TipPoll>) -> impl FnMut() -> std::future::Ready<TipPoll> + Send + 'static {
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
        Arc::new(OperatorAlarms::new()),
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
        Arc::new(OperatorAlarms::new()),
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
        Arc::new(OperatorAlarms::new()),
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
    let legs: Vec<Box<dyn CadenceLeg>> = production_legs(
        dead,
        "http://127.0.0.1:1",
        &ServingSlot::default(),
        &Arc::new(OperatorAlarms::new()),
    )
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
    for leg in [
        "submit-lifecycle",
        "serving-liveness",
        "terminal-reject",
        "epoch-claim",
    ] {
        assert!(
            fired.contains(&(leg, 1)) && fired.contains(&(leg, 2)),
            "{leg} must be registered and invoked on every advance, got {fired:?}"
        );
    }
    // Fire order is the §3 retire-before-assemble registration order.
    assert_eq!(
        fired[..4],
        [
            ("submit-lifecycle", 1),
            ("serving-liveness", 1),
            ("terminal-reject", 1),
            ("epoch-claim", 1)
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
        Arc::new(OperatorAlarms::new()),
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
        Arc::new(OperatorAlarms::new()),
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
        Arc::new(OperatorAlarms::new()),
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
    let alarms = Arc::new(OperatorAlarms::new());
    let legs = production_legs(Arc::downgrade(&arc), "http://127.0.0.1:1", &slot, &alarms);
    let (tick, rx) = tokio::sync::mpsc::unbounded_channel();
    let heights = std::sync::atomic::AtomicU64::new(0);
    let handle = spawn_cadence_loop(
        StepSchedule(rx),
        move || {
            let h = heights.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            std::future::ready(TipPoll::Height(h))
        },
        legs,
        alarms,
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

/// Leg 3's refusal taxonomy (`ENGINE_CADENCE_DRIVER.md` §4): yields,
/// idle, and value-deferral are policy outcomes, never faults — and
/// everything else is one.
#[test]
fn claim_classify_maps_the_refusal_taxonomy() {
    use super::super::claim_dispatch::EmissionClaimRequestError as E;
    use super::super::claim_orchestrator::ClaimOrchestrationError as O;
    use super::super::emission_claim::EmissionClaimError as C;
    use super::super::stake_engine::StakeEngineError as SE;

    assert!(matches!(
        classify_claim(&E::ClaimPending),
        ClaimOutcome::Yield
    ));
    assert!(matches!(
        classify_claim(&E::InputRaced),
        ClaimOutcome::Yield
    ));
    assert!(matches!(
        classify_claim(&E::ForegroundHold),
        ClaimOutcome::Yield
    ));
    assert!(matches!(
        classify_claim(&E::Claim(O::Stake(SE::EmissionClaim(C::NoClaimableEpochs)))),
        ClaimOutcome::Idle
    ));
    let deferred = E::Claim(O::Stake(SE::EmissionClaim(C::ValueDeferred {
        value_deferred: vec![(7, 100), (8, 200)],
        total_reward: 300,
        fee_floor: 1_000,
    })));
    match classify_claim(&deferred) {
        ClaimOutcome::Deferred(held) => assert_eq!(held, vec![(7, 100), (8, 200)]),
        _ => panic!("ValueDeferred must classify as Deferred"),
    }
    assert!(matches!(classify_claim(&E::NotStaker), ClaimOutcome::Fault));
}

/// §4 evaluate-and-forfeit: a completed evaluation forfeits a
/// previously-held epoch only when it is missing from both new sets
/// *and* expired — an unexpired missing epoch is next close's problem,
/// and a still-held epoch is never a forfeit.
#[test]
fn claim_complete_forfeits_only_expired_missing_epochs() {
    let settled = 1_000;
    let floor = shekyl_archival_retention::claim_window_floor(settled);
    assert!(floor > 1, "test needs room below the claim window");
    let expired = floor - 1;
    let unexpired = settled - 1;

    let alarms = OperatorAlarms::new();
    let state = std::sync::Mutex::new(ClaimLegState {
        evaluated_at_epoch: None,
        held: vec![(expired, 111), (unexpired, 222), (settled - 2, 333)],
        consecutive_faults: 2,
        forfeited_total: 0,
    });
    // The new evaluation claims one held epoch, re-defers nothing, and
    // drops the other two: one expired (forfeit), one not (no record).
    claim_complete(&state, &alarms, settled, &[settled - 2], Vec::new());

    let s = state.lock().expect("state");
    assert_eq!(s.forfeited_total, 111, "only the expired epoch's reward");
    assert_eq!(s.evaluated_at_epoch, Some(settled));
    assert_eq!(s.consecutive_faults, 0, "completion clears the streak");
    assert!(s.held.is_empty());
    drop(s);

    let board = alarms.board();
    match board
        .condition(AlarmCondition::ClaimForfeiture)
        .expect("forfeiture condition reported")
        .live()
        .map(shekyl_operator_alarm::RaisedAlarm::alarm)
    {
        Some(OperatorAlarm::ClaimForfeited {
            epoch,
            forfeited_atomic,
        }) => {
            assert_eq!(epoch, expired);
            assert_eq!(forfeited_atomic, 111, "priced at the held reward");
        }
        other => panic!("expected a ClaimForfeited alarm, got {other:?}"),
    }
    // The claim condition itself reads healthy: forfeiture is its own
    // latched condition, not a claim-backlog fault.
    assert!(
        board
            .condition(AlarmCondition::EpochClaim)
            .expect("claim condition reported")
            .live()
            .is_none(),
        "a completed evaluation reads current on the claim board"
    );
}

/// Fault accounting: the backlog alarm raises only at the threshold,
/// and one completed evaluation clears both the streak and the board.
#[test]
fn claim_fault_threshold_raises_and_complete_clears() {
    let alarms = OperatorAlarms::new();
    let state = std::sync::Mutex::new(ClaimLegState::default());
    let settled = 50;

    let below = CLAIM_FAULT_ALARM_THRESHOLD - 1;
    for _ in 0..below {
        claim_fault(&state, &alarms, settled, &"transport refused");
    }
    assert!(
        alarms
            .board()
            .condition(AlarmCondition::EpochClaim)
            .is_none_or(|c| c.live().is_none()),
        "below the threshold the board stays quiet"
    );

    claim_fault(&state, &alarms, settled, &"transport refused");
    match alarms
        .board()
        .condition(AlarmCondition::EpochClaim)
        .expect("condition reported")
        .live()
        .map(shekyl_operator_alarm::RaisedAlarm::alarm)
    {
        Some(OperatorAlarm::EpochUnclaimed {
            oldest_epoch,
            outstanding_epochs,
        }) => {
            // No completed evaluation yet: the leg claims one
            // outstanding epoch — honest, never overstated.
            assert_eq!(oldest_epoch, settled);
            assert_eq!(outstanding_epochs, 1);
        }
        other => panic!("expected EpochUnclaimed at the threshold, got {other:?}"),
    }

    claim_complete(&state, &alarms, settled, &[], Vec::new());
    assert!(
        alarms
            .board()
            .condition(AlarmCondition::EpochClaim)
            .expect("condition reported")
            .live()
            .is_none(),
        "a completed evaluation clears the backlog alarm"
    );
    assert_eq!(
        state.lock().expect("state").consecutive_faults,
        0,
        "and the streak"
    );
}

/// §3's asymmetry, the mirror of the stale-seal test: while a
/// user-initiated pending-post operation is registered on the foreground
/// gauge the leg yields its whole tick — no evaluation, no fault, no
/// alarm. Dropping the registration proves the yield was the gauge's
/// doing: the same fire then proceeds past the skip (and faults on this
/// rig's unreachable daemon, which is the point — the gate opened). The
/// authoritative in-seal half of the rule lives in the dispatch seam
/// (`ForegroundHold`, mapped to a yield by the classify test above).
#[tokio::test(flavor = "multi_thread")]
async fn claim_leg_yields_while_user_work_is_in_flight() {
    let (_tmp, engine) = crate::engine::test_support::staker_engine(3, 13);
    crate::engine::test_support::activate_persona(&engine, 3).await;
    let pending_gate = engine.pending_gate.clone();
    let arc = Arc::new(RwLock::new(engine));

    let alarms = Arc::new(OperatorAlarms::new());
    let state = Arc::new(std::sync::Mutex::new(ClaimLegState::default()));
    let mut leg = EpochClaimLeg {
        engine: Arc::downgrade(&arc),
        daemon_address: "http://127.0.0.1:1".to_owned(),
        alarms: Arc::clone(&alarms),
        state: Arc::clone(&state),
    };

    let tip = 10 * shekyl_archival_retention::effective_settlement_epoch_blocks();

    // User work in flight (a drain/unstake/first-stake somewhere in its
    // assemble→seal span): the leg must yield without evaluating.
    let user_op = pending_gate.begin_foreground();
    leg.fire(tip).await;
    {
        let s = state.lock().expect("state");
        assert_eq!(
            s.evaluated_at_epoch, None,
            "a yielded tick is not an evaluation"
        );
        assert_eq!(s.consecutive_faults, 0, "a yield is never a fault");
    }
    drop(user_op);

    // Registration dropped: the same fire proceeds past the skip and
    // reaches the daemon (unreachable here → fault), proving the earlier
    // yield was the foreground gauge and nothing else.
    leg.fire(tip).await;
    assert_eq!(
        state.lock().expect("state").consecutive_faults,
        1,
        "with the gauge idle the leg proceeds to the daemon round-trip"
    );
}

/// §4 policy determinism (not timing): given the same settled epoch and
/// the same leg state, the inclusion decision is the same — one
/// evaluation per settlement close, and a clean cursor never re-fires
/// within the epoch. A faulted fire does retry on the next advance.
#[tokio::test(flavor = "multi_thread")]
async fn claim_leg_evaluates_once_per_settled_epoch() {
    let (_tmp, engine) = crate::engine::test_support::staker_engine(3, 17);
    crate::engine::test_support::activate_persona(&engine, 3).await;
    let arc = Arc::new(RwLock::new(engine));

    let alarms = Arc::new(OperatorAlarms::new());
    let state = Arc::new(std::sync::Mutex::new(ClaimLegState::default()));
    let mut leg = EpochClaimLeg {
        engine: Arc::downgrade(&arc),
        daemon_address: "http://127.0.0.1:1".to_owned(),
        alarms: Arc::clone(&alarms),
        state: Arc::clone(&state),
    };

    let blocks = shekyl_archival_retention::effective_settlement_epoch_blocks();
    let tip = 10 * blocks;
    let settled = shekyl_archival_retention::settlement_epoch_at_height(tip);

    // A completed evaluation for this settled epoch already exists: any
    // tip inside the same epoch is a deterministic no-op.
    state.lock().expect("state").evaluated_at_epoch = Some(settled);
    leg.fire(tip).await;
    leg.fire(tip + 1).await;
    {
        let s = state.lock().expect("state");
        assert_eq!(s.consecutive_faults, 0, "same epoch: gated, no attempt");
        assert_eq!(s.evaluated_at_epoch, Some(settled));
    }

    // The next settlement close opens the gate (observable on this rig
    // as the daemon round-trip faulting).
    leg.fire(tip + blocks).await;
    assert_eq!(
        state.lock().expect("state").consecutive_faults,
        1,
        "a new settled epoch must re-open the evaluation gate"
    );
}
