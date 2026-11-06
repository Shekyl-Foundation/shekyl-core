// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use std::time::Duration;

use shekyl_p2p::{OriginVerdict, ProbeArrival, TorLinkTally};
use shekyl_timing_engine::Clock;
use shekyl_timing_engine::{EngineService, ManualClock, OwnerClass, Tick};
use shekyl_tor_control_client::control::{
    BootstrapState, EventReceiver, EventSink, ReplyFramer, RESUMED_AFTER,
};
use shekyl_tor_control_client::supervisor::Input;
use shekyl_tor_control_daemon::TorDeath;
use tokio::sync::{mpsc, watch};

use super::super::arm;
use super::{led, plain_inputs, slept, take_queued, wait, Live, Sources, Wake, Woken};

fn secs(seconds: u64) -> u64 {
    seconds * 1_000_000_000
}

/// One wait on fresh channels, armed at `due`, with the clock already
/// at `woke` and a dial tally waiting.
async fn wake_with_a_tally_waiting(due: u64, woke: u64) -> (Wake, TorLinkTally) {
    let clock = ManualClock::new(Tick::new(0));
    let service = EngineService::start(clock.clone());
    let owner = service
        .handle()
        .register(OwnerClass::Housekeeping)
        .expect("register");
    let (_stop_tx, stop) = watch::channel(false);
    let (_forward_tx, forward) = watch::channel(None);
    let (_origin_tx, origin) = watch::channel(OriginVerdict::Absent);
    let (tally_tx, tor_link) = watch::channel(TorLinkTally::default());
    let (_arrivals_tx, probe_arrivals) = watch::channel(None);
    let (_sink, incoming) = EventSink::bounded();
    let (_death_tx, death) = mpsc::channel(1);
    let mut stop = Live::new(stop);
    let mut forward = Live::new(forward);
    let mut origin = Live::new(origin);
    let mut tor_link = Live::new(tor_link);
    let mut probe_arrivals = Live::new(probe_arrivals);
    let mut incoming = Live::new(incoming);
    let mut death = Live::new(death);
    let mut bootstrap = None;
    clock.set(Tick::new(woke));
    arm(&owner, Some(due));
    let tally = TorLinkTally {
        opened: 0,
        unopened: 1,
        held: 0,
        last_sign_of_life: None,
        last_unopened_at: None,
    };
    tally_tx.send(tally).expect("the tally's receiver is held");
    let sources = Sources {
        stop: &mut stop,
        forward: &mut forward,
        origin: &mut origin,
        tor_link: &mut tor_link,
        probe_arrivals: &mut probe_arrivals,
        incoming: &mut incoming,
        death: &mut death,
        bootstrap: &mut bootstrap,
    };
    (wait(sources, &owner, Some(due), 0).await, tally)
}

/// At a wake the dialer's timers fire too, so a dial result is ready
/// with the late timer and wins the biased order. The wait still sees
/// the sleep, and the batch folds it before the dial result is judged
/// (§5, "Resumed from suspend"). Biasing the timer first and dropping
/// the wait's classification fails this; so does classifying only in
/// the timer branch.
#[tokio::test]
async fn a_wake_with_a_dial_result_waiting_folds_the_resume_first() {
    let due = secs(30);
    let woke = due + duration_ns_of(RESUMED_AFTER) + secs(1);
    let (wake, tally) = wake_with_a_tally_waiting(due, woke).await;
    assert!(
        matches!(wake.what, Woken::TorLink(seen) if seen == tally),
        "the dial result wins the order: {:?}",
        wake.what
    );
    assert_eq!(wake.woke, woke);
    assert_eq!(wake.resumed, Some(Duration::from_nanos(woke - due)));
    let batch = led(wake.lead(), plain_inputs(&wake.what));
    assert!(
        matches!(
            batch.as_slice(),
            [Input::Resumed { .. }, Input::DialEvidence(_)]
        ),
        "the resume is folded first: {batch:?}"
    );
}

/// The same wake inside `RESUMED_AFTER` of its deadline is an awake
/// one: the dial result is folded alone.
#[tokio::test]
async fn a_wake_on_time_folds_the_dial_result_alone() {
    let due = secs(30);
    let woke = due + duration_ns_of(RESUMED_AFTER);
    let (wake, _) = wake_with_a_tally_waiting(due, woke).await;
    assert_eq!(wake.resumed, None);
    let batch = led(wake.lead(), plain_inputs(&wake.what));
    assert!(
        matches!(batch.as_slice(), [Input::DialEvidence(_)]),
        "{batch:?}"
    );
}

/// A deadline already past when the wait began has no time left; a
/// return more than `RESUMED_AFTER` later is still a sleep. With no
/// deadline armed nothing is late.
#[test]
fn a_wait_is_late_against_the_deadline_it_was_armed_with() {
    let after = duration_ns_of(RESUMED_AFTER);
    assert_eq!(slept(Some(secs(5)), secs(10), secs(10) + after), None);
    assert_eq!(
        slept(Some(secs(5)), secs(10), secs(11) + after),
        Some(Duration::from_nanos(secs(1) + after))
    );
    assert_eq!(slept(None, 0, secs(3600)), None);
}

fn duration_ns_of(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).expect("fits")
}

fn framed_notice() -> shekyl_tor_control_client::control::ControlReply {
    let mut framer = ReplyFramer::default();
    framer.push_bytes(b"650 NOTICE queued\r\n");
    framer.next_reply().expect("frames").expect("one reply")
}

/// The timer stands ahead of a control event only when its wake is
/// already delivered. The event is queued after that, so both are
/// ready and the timer wins. The event stays for the drain. An event
/// queued before the timing thread has delivered lets that arm win,
/// and folding the deadline first fails this.
#[tokio::test]
async fn a_queued_event_is_still_held_when_the_timer_wins() {
    let due = secs(30);
    let clock = ManualClock::new(Tick::new(due));
    let service = EngineService::start(clock);
    let owner = service
        .handle()
        .register(OwnerClass::Housekeeping)
        .expect("register");
    let (_stop_tx, stop) = watch::channel(false);
    let (_forward_tx, forward) = watch::channel(None);
    let (_origin_tx, origin) = watch::channel(OriginVerdict::Absent);
    let (_tally_tx, tor_link) = watch::channel(TorLinkTally::default());
    let (_arrivals_tx, probe_arrivals) = watch::channel(None);
    let (sink, incoming) = EventSink::bounded();
    let (_death_tx, death) = mpsc::channel(1);
    let mut stop = Live::new(stop);
    let mut forward = Live::new(forward);
    let mut origin = Live::new(origin);
    let mut tor_link = Live::new(tor_link);
    let mut probe_arrivals = Live::new(probe_arrivals);
    let mut incoming = Live::new(incoming);
    let mut death = Live::new(death);
    let mut bootstrap = None;
    arm(&owner, Some(due));
    hold_until_the_deadline_is_delivered(&owner, due);
    sink.route(framed_notice());
    let sources = Sources {
        stop: &mut stop,
        forward: &mut forward,
        origin: &mut origin,
        tor_link: &mut tor_link,
        probe_arrivals: &mut probe_arrivals,
        incoming: &mut incoming,
        death: &mut death,
        bootstrap: &mut bootstrap,
    };
    let wake = wait(sources, &owner, Some(due), due).await;
    assert!(
        matches!(wake.what, Woken::Timer { closed: false }),
        "the timer did not win: {:?}",
        wake.what
    );
    let queued = take_queued(incoming.source_mut());
    assert_eq!(queued.len(), 1, "the event arm took the line");
    assert_eq!(queued[0].status(), 650);
    assert_eq!(wake.woke, due);
    assert_eq!(
        wake.resumed, None,
        "the deadline was already due, and the return was not late"
    );
}

/// Leave one delivered wake in the slot. Polling the wait takes a wake
/// that is already there, so that one is re-armed. A pending poll
/// registers a waker and waits until the timing thread delivers; the
/// wake stays in the slot.
fn hold_until_the_deadline_is_delivered(
    owner: &shekyl_timing_engine::OwnerHandle<ManualClock>,
    due: u64,
) {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::Instant;

    struct Told(AtomicBool);
    impl Wake for Told {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::Release);
        }
    }

    for _ in 0..8 {
        let told = Arc::new(Told(AtomicBool::new(false)));
        let waker = Waker::from(Arc::clone(&told));
        let mut wait = owner.wait_wake_async();
        let mut context = Context::from_waker(&waker);
        match Pin::new(&mut wait).poll(&mut context) {
            Poll::Pending => {
                let started = Instant::now();
                while !told.0.load(Ordering::Acquire) {
                    assert!(
                        started.elapsed() < Duration::from_secs(2),
                        "the timing thread did not deliver the armed deadline"
                    );
                    std::thread::yield_now();
                }
                return;
            }
            Poll::Ready(Ok(_)) => {
                owner.clear().expect("clear the consumed wake");
                owner.arm(Tick::new(due)).expect("arm the deadline again");
            }
            Poll::Ready(Err(error)) => panic!("the timing engine closed: {error:?}"),
        }
    }
    panic!("the deadline was taken before an event could be held with it");
}

/// Every source of one wait, with the senders the test can close.
struct Harness {
    clock: ManualClock,
    _service: EngineService<ManualClock>,
    owner: shekyl_timing_engine::OwnerHandle<ManualClock>,
    stop_tx: Option<watch::Sender<bool>>,
    stop: Live<watch::Receiver<bool>>,
    forward_tx: Option<watch::Sender<Option<std::net::SocketAddr>>>,
    forward: Live<watch::Receiver<Option<std::net::SocketAddr>>>,
    origin_tx: Option<watch::Sender<OriginVerdict>>,
    origin: Live<watch::Receiver<OriginVerdict>>,
    tally_tx: Option<watch::Sender<TorLinkTally>>,
    tor_link: Live<watch::Receiver<TorLinkTally>>,
    arrivals_tx: Option<watch::Sender<Option<ProbeArrival>>>,
    probe_arrivals: Live<watch::Receiver<Option<ProbeArrival>>>,
    sink: Option<EventSink>,
    incoming: Live<EventReceiver>,
    death_tx: Option<mpsc::Sender<(u64, TorDeath)>>,
    death: Live<mpsc::Receiver<(u64, TorDeath)>>,
    bootstrap: Option<watch::Receiver<BootstrapState>>,
}

impl Harness {
    fn new() -> Self {
        let clock = ManualClock::new(Tick::new(0));
        let service = EngineService::start(clock.clone());
        let owner = service
            .handle()
            .register(OwnerClass::Housekeeping)
            .expect("register");
        let (stop_tx, stop) = watch::channel(false);
        let (forward_tx, forward) = watch::channel(None);
        let (origin_tx, origin) = watch::channel(OriginVerdict::Absent);
        let (tally_tx, tor_link) = watch::channel(TorLinkTally::default());
        let (arrivals_tx, probe_arrivals) = watch::channel(None);
        let (sink, incoming) = EventSink::bounded();
        let (death_tx, death) = mpsc::channel(1);
        Self {
            clock,
            _service: service,
            owner,
            stop_tx: Some(stop_tx),
            stop: Live::new(stop),
            forward_tx: Some(forward_tx),
            forward: Live::new(forward),
            origin_tx: Some(origin_tx),
            origin: Live::new(origin),
            tally_tx: Some(tally_tx),
            tor_link: Live::new(tor_link),
            arrivals_tx: Some(arrivals_tx),
            probe_arrivals: Live::new(probe_arrivals),
            sink: Some(sink),
            incoming: Live::new(incoming),
            death_tx: Some(death_tx),
            death: Live::new(death),
            bootstrap: None,
        }
    }

    fn now(&self) -> u64 {
        self.clock.now().get()
    }

    /// One wait armed at `due`, as the driver's loop runs it.
    async fn wait(&mut self, due: Option<u64>) -> Wake {
        let entered = self.now();
        arm(&self.owner, due);
        let sources = Sources {
            stop: &mut self.stop,
            forward: &mut self.forward,
            origin: &mut self.origin,
            tor_link: &mut self.tor_link,
            probe_arrivals: &mut self.probe_arrivals,
            incoming: &mut self.incoming,
            death: &mut self.death,
            bootstrap: &mut self.bootstrap,
        };
        wait(sources, &self.owner, due, entered).await
    }

    /// The same wait, given a minute of paused time to return: `None`
    /// when it stayed pending, as a wait with nothing to do must.
    async fn wait_a_minute(&mut self, due: Option<u64>) -> Option<Wake> {
        tokio::time::timeout(Duration::from_secs(60), self.wait(due))
            .await
            .ok()
    }

    /// The armed deadline comes due: the timer ends the wait.
    async fn reach(&mut self, due: u64) -> Wake {
        self.clock.set(Tick::new(due));
        self.wait(Some(due)).await
    }
}

/// A bootstrap watch whose sender sent `state` and was dropped, as
/// `bootstrap_poll_loop` does after `Ready` or `Failed`.
fn bootstrap_ended(state: BootstrapState) -> watch::Receiver<BootstrapState> {
    let (tx, rx) = watch::channel(BootstrapState::Connecting { progress: 0 });
    tx.send(state).expect("the receiver is held");
    rx
}

/// **The spin (`TOR_SUPERVISOR.md` §10 `TSR-M15`: two threads near a
/// core each, idle).** `bootstrap_poll_loop` drops its sender after `Ready`;
/// a closed watch answers `changed()` at once, every time. The watch
/// says `Ready` once and leaves the wait; the next wait stays pending
/// until its timer. Restoring `let _changed = bootstrap.changed().await;`
/// (a wake for the closure, the watch left in) fails this.
#[tokio::test(start_paused = true)]
async fn a_bootstrap_that_said_ready_and_closed_wakes_once() {
    let mut harness = Harness::new();
    harness.bootstrap = Some(bootstrap_ended(BootstrapState::Ready));
    let due = secs(30);
    let first = harness.wait(Some(due)).await;
    assert!(
        matches!(first.what, Woken::Bootstrap(BootstrapState::Ready)),
        "{:?}",
        first.what
    );
    assert!(harness.bootstrap.is_none(), "the watch left the wait");
    assert!(
        harness.wait_a_minute(Some(due)).await.is_none(),
        "a closed watch woke the loop again"
    );
    let timer = harness.reach(due).await;
    assert!(matches!(timer.what, Woken::Timer { closed: false }));
}

/// `Failed` leaves the wait once said, even with its sender still
/// held: nothing follows it. Fails if `next_bootstrap` keeps the watch
/// after a terminal state.
#[tokio::test(start_paused = true)]
async fn a_bootstrap_that_failed_leaves_the_wait_with_its_sender_held() {
    let mut harness = Harness::new();
    let (tx, rx) = watch::channel(BootstrapState::Connecting { progress: 0 });
    tx.send(BootstrapState::Failed).expect("held");
    harness.bootstrap = Some(rx);
    let due = secs(30);
    let first = harness.wait(Some(due)).await;
    assert!(matches!(
        first.what,
        Woken::Bootstrap(BootstrapState::Failed)
    ));
    assert!(harness.bootstrap.is_none());
    assert!(harness.wait_a_minute(Some(due)).await.is_none());
    drop(tx);
}

/// A bootstrap watch whose sender closes with nothing new says
/// nothing: the closure takes it out of the wait without a wake. Its
/// progress before that is still said. Fails if `next_bootstrap`
/// returns a state for the closure, or leaves the watch in.
#[tokio::test(start_paused = true)]
async fn a_bootstrap_closed_mid_way_leaves_without_a_wake() {
    let mut harness = Harness::new();
    let (tx, rx) = watch::channel(BootstrapState::Connecting { progress: 0 });
    harness.bootstrap = Some(rx);
    tx.send(BootstrapState::Connecting { progress: 45 })
        .expect("held");
    let due = secs(30);
    let progress = harness.wait(Some(due)).await;
    assert!(matches!(
        progress.what,
        Woken::Bootstrap(BootstrapState::Connecting { progress: 45 })
    ));
    assert!(harness.bootstrap.is_some(), "progress keeps the watch");
    drop(tx);
    assert!(harness.wait_a_minute(Some(due)).await.is_none());
    assert!(harness.bootstrap.is_none(), "the closure took it out");
}

/// The stop's closure is the daemon stopping: said once, then the
/// stop is out of the wait. Fails if the stop source stays open (a
/// stop wake at every wait after).
#[tokio::test(start_paused = true)]
async fn a_closed_stop_is_said_once() {
    let mut harness = Harness::new();
    drop(harness.stop_tx.take());
    let due = secs(30);
    let first = harness.wait(Some(due)).await;
    assert!(matches!(first.what, Woken::Stop { stopping: true }));
    assert!(!harness.stop.is_open());
    assert!(harness.wait_a_minute(Some(due)).await.is_none());
}

/// A stop flag that is set is the value, and the source stays. Fails
/// if a real move is treated as the sender closing.
#[tokio::test(start_paused = true)]
async fn a_stop_flag_that_is_set_stays_in_the_wait() {
    let mut harness = Harness::new();
    harness
        .stop_tx
        .as_ref()
        .expect("held")
        .send(true)
        .expect("the receiver is held");
    let due = secs(30);
    let first = harness.wait(Some(due)).await;
    assert!(matches!(first.what, Woken::Stop { stopping: true }));
    assert!(harness.stop.is_open());
    harness
        .stop_tx
        .as_ref()
        .expect("held")
        .send(false)
        .expect("the receiver is held");
    let cleared = harness.wait(Some(due)).await;
    assert!(matches!(cleared.what, Woken::Stop { stopping: false }));
    assert!(harness.stop.is_open());
    assert!(plain_inputs(&cleared.what).is_empty());
}

/// A value sent as its sender closes is kept. The close after it
/// says nothing. Fails if the close is reported instead of the value,
/// or if the value takes the source out.
#[tokio::test(start_paused = true)]
async fn a_value_sent_as_its_sender_closes_is_kept() {
    let mut harness = Harness::new();
    let tx = harness.forward_tx.take().expect("held");
    let bound: std::net::SocketAddr = "127.0.0.1:18081".parse().expect("a socket address");
    tx.send(Some(bound)).expect("the receiver is held");
    drop(tx);
    let due = secs(30);
    let first = harness.wait(Some(due)).await;
    assert!(matches!(first.what, Woken::Forward { bound: true }));
    assert!(
        harness.forward.is_open(),
        "the value was taken for the close"
    );
    assert!(harness.wait_a_minute(Some(due)).await.is_none());
    assert!(!harness.forward.is_open(), "the close left it in the wait");
}

/// A closed source other than the stop says nothing and leaves the
/// wait; the next thing that happens, here the timer, ends it.
async fn a_closure_leaves_quietly(close: fn(&mut Harness), still_open: fn(&Harness) -> bool) {
    let mut harness = Harness::new();
    close(&mut harness);
    let due = secs(30);
    assert!(
        harness.wait_a_minute(Some(due)).await.is_none(),
        "a closed source woke the loop"
    );
    assert!(
        !still_open(&harness),
        "the closed source is still in the wait"
    );
    let timer = harness.reach(due).await;
    assert!(matches!(timer.what, Woken::Timer { closed: false }));
}

/// Fails if the forward branch breaks with a wake for its closure, or
/// leaves the source in the wait.
#[tokio::test(start_paused = true)]
async fn a_closed_forward_watch_leaves_the_wait_quietly() {
    a_closure_leaves_quietly(|h| drop(h.forward_tx.take()), |h| h.forward.is_open()).await;
}

/// Fails if the origin branch breaks with a wake for its closure, or
/// leaves the source in the wait.
#[tokio::test(start_paused = true)]
async fn a_closed_origin_watch_leaves_the_wait_quietly() {
    a_closure_leaves_quietly(|h| drop(h.origin_tx.take()), |h| h.origin.is_open()).await;
}

/// Fails if the tally branch breaks with a wake for its closure, or
/// leaves the source in the wait.
#[tokio::test(start_paused = true)]
async fn a_closed_tally_watch_leaves_the_wait_quietly() {
    a_closure_leaves_quietly(|h| drop(h.tally_tx.take()), |h| h.tor_link.is_open()).await;
}

/// Fails if the arrivals branch breaks with a wake for its closure, or
/// leaves the source in the wait.
#[tokio::test(start_paused = true)]
async fn a_closed_arrivals_watch_leaves_the_wait_quietly() {
    a_closure_leaves_quietly(
        |h| drop(h.arrivals_tx.take()),
        |h| h.probe_arrivals.is_open(),
    )
    .await;
}

/// Fails if the event sink's close is an event, or leaves the source
/// in the wait. A supervised sink's `recv` returning `None` is the
/// sender gone, and folding nothing for it would spin.
#[tokio::test(start_paused = true)]
async fn a_closed_event_sink_leaves_the_wait_quietly() {
    a_closure_leaves_quietly(|h| drop(h.sink.take()), |h| h.incoming.is_open()).await;
}

/// Fails if the death channel's close is a death, or leaves the source
/// in the wait.
#[tokio::test(start_paused = true)]
async fn a_closed_death_channel_leaves_the_wait_quietly() {
    a_closure_leaves_quietly(|h| drop(h.death_tx.take()), |h| h.death.is_open()).await;
}

/// **The loop is bounded by what it is given, not by time.** The
/// driver's wait, over ten simulated minutes: a deadline every
/// [`STEP`], a bootstrap watch that said `Ready` and closed, a dial
/// tally sent once and closed, the forward, origin and arrivals
/// watches closed, and three events fed in. Every return is a
/// deadline that came due or something fed in. The deadlines are this
/// test's, so the supervisor's sample interval is not part of the
/// bound. Restoring `let _changed = bootstrap.changed().await;` fails
/// this at the iteration cap; so does any closed branch that returns.
#[tokio::test(start_paused = true)]
async fn the_loop_wakes_for_deadlines_and_what_it_is_fed_not_for_time() {
    /// How far apart this loop arms the next deadline.
    const STEP: Duration = Duration::from_secs(30);
    /// How long the loop runs.
    const WINDOW: Duration = Duration::from_secs(10 * 60);
    /// A spin returns thousands of times a second. One extra wake
    /// across the window still passes; a closed source that keeps
    /// returning does not.
    const SPIN_CAP: u32 = 1_000;

    let mut harness = Harness::new();
    harness.bootstrap = Some(bootstrap_ended(BootstrapState::Ready));
    let tally = TorLinkTally {
        opened: 1,
        ..TorLinkTally::default()
    };
    harness
        .tally_tx
        .take()
        .expect("held")
        .send(tally)
        .expect("the receiver is held");
    drop(harness.forward_tx.take());
    drop(harness.origin_tx.take());
    drop(harness.arrivals_tx.take());
    let step = duration_ns_of(STEP);
    let end = duration_ns_of(WINDOW);
    let mut due = step;
    let feed_at = [secs(65), secs(200), secs(431)];
    let mut fed = 0;
    let (mut timers, mut events, mut ready, mut tallies) = (0_u32, 0_u32, 0_u32, 0_u32);
    let mut iterations = 0_u32;
    let mut reached = 0_u32;
    // One deadline per step, plus room for a wake the timing thread
    // had already delivered when another branch won.
    let deadline_cap = u32::try_from(WINDOW.as_secs() / STEP.as_secs()).expect("fits") + 5;
    while harness.now() < end {
        if fed < feed_at.len() && harness.now() >= feed_at[fed] {
            harness.sink.as_ref().expect("held").route(framed_notice());
            fed += 1;
        }
        // A deadline already due is waited for outright: the timing
        // thread delivers it in real time while tokio's clock is
        // paused, so a timeout here would only race that delivery.
        let wake = if due <= harness.now() {
            harness.wait(Some(due)).await
        } else if let Some(wake) = harness.wait_a_minute(Some(due)).await {
            wake
        } else {
            // Nothing to do before it: time passes to the deadline.
            harness.clock.set(Tick::new(due));
            reached += 1;
            continue;
        };
        iterations += 1;
        assert!(iterations < SPIN_CAP, "the loop is spinning");
        match wake.what {
            Woken::Timer { closed } => {
                assert!(!closed);
                timers += 1;
                // As `after_timer`: events already queued fold with it.
                events +=
                    u32::try_from(take_queued(harness.incoming.source_mut()).len()).expect("a few");
                if harness.now() >= due {
                    due = due.saturating_add(step);
                }
            }
            Woken::Event(_) => {
                events += 1;
            }
            Woken::Bootstrap(BootstrapState::Ready) => ready += 1,
            Woken::TorLink(_) => tallies += 1,
            other => panic!("nothing else was fed in: {other:?}"),
        }
    }
    let others = ready + tallies;
    assert_eq!(fed, feed_at.len());
    assert_eq!(events, 3, "each event fed in is folded once");
    assert_eq!(ready, 1, "Ready once");
    assert_eq!(tallies, 1, "the tally once");
    assert!(!harness.forward.is_open());
    assert!(!harness.origin.is_open());
    assert!(!harness.probe_arrivals.is_open());
    assert!(!harness.tor_link.is_open());
    assert!(harness.bootstrap.is_none());
    assert!(harness.stop.is_open());
    assert!(harness.incoming.is_open());
    assert!(harness.death.is_open());
    assert!(
        iterations <= timers + events + others,
        "{iterations} wakes for {timers} timers, {events} events, {others} other inputs"
    );
    // Each deadline reached gives its own wake, and at most one more: a
    // wake already delivered when another branch won is handed out on
    // the next pass (`arm` clears the engine's queue, not the owner's
    // slot), and is folded as a deadline not yet due.
    assert!(timers > 0, "the deadlines came due");
    assert!(
        timers <= 2 * reached + events + others,
        "{timers} timer wakes for {reached} deadlines reached"
    );
    assert!(
        reached <= deadline_cap,
        "{reached} deadlines in ten minutes, bound {deadline_cap}"
    );
}
