// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What ends one wait of the Tor supervisor's loop (`TOR_SUPERVISOR.md` §5).
//!
//! The wait classifies a sleep after it returns, whichever branch won. The
//! timer stands ahead of control events, so a stream of events cannot hold
//! a deadline off. Events already queued when the timer wins are drained
//! here and folded before that deadline.
//!
//! **A closed channel disarms its own branch.** A watch whose sender is
//! gone answers `changed()` at once, every time; a branch that returned
//! for it would end every wait with nothing to fold, and the loop would
//! spin (the bootstrap watch did, at about 1.7 cores on the floor device:
//! its sender drops after `Ready`). So a closed sender takes its source
//! out of the wait and the wait goes on: it never returns for a closure
//! alone. The stop's closure is the one that says something, the daemon
//! stopping, and is said once. The bootstrap watch also leaves the wait
//! once it has said `Ready` or `Failed`: nothing follows either. The event
//! sink and the death channel cannot close while the driver lives: it
//! holds both senders.

use std::net::SocketAddr;
use std::time::Duration;

use shekyl_ffi::origin_verdict::OriginVerdict;
use shekyl_ffi::tor_link::{ProbeArrival, TorLinkTally};
use shekyl_timing_engine::{Clock, OwnerHandle};
use shekyl_tor_control_client::control::{
    resume_lateness, BootstrapState, ControlReply, EventReceiver, Resume,
};
use shekyl_tor_control_client::supervisor::Input;
use shekyl_tor_control_daemon::TorDeath;
use tokio::sync::{mpsc, watch};

/// Which of the process-lived watches are still in the wait. A branch
/// whose sender has closed is taken out here and never comes back: the
/// senders do not reopen.
#[derive(Debug, Clone, Copy)]
pub(super) struct Open {
    pub(super) stop: bool,
    pub(super) forward: bool,
    pub(super) origin: bool,
    pub(super) tor_link: bool,
    pub(super) probe_arrivals: bool,
}

impl Open {
    pub(super) const ALL: Self = Self {
        stop: true,
        forward: true,
        origin: true,
        tor_link: true,
        probe_arrivals: true,
    };
}

/// What the loop waits on, borrowed from the driver for one wait.
pub(super) struct Sources<'a> {
    pub(super) open: &'a mut Open,
    pub(super) stop: &'a mut watch::Receiver<bool>,
    pub(super) forward: &'a mut watch::Receiver<Option<SocketAddr>>,
    pub(super) origin: &'a mut watch::Receiver<OriginVerdict>,
    pub(super) tor_link: &'a mut watch::Receiver<TorLinkTally>,
    pub(super) probe_arrivals: &'a mut watch::Receiver<Option<ProbeArrival>>,
    pub(super) incoming: &'a mut EventReceiver,
    pub(super) death: &'a mut mpsc::Receiver<(u64, TorDeath)>,
    pub(super) bootstrap: &'a mut Option<watch::Receiver<BootstrapState>>,
}

/// What ended a wait. Each branch reads its value and nothing more; the
/// driver folds it after the sleep check.
#[derive(Debug)]
pub(super) enum Woken {
    /// The stop flag moved. `stopping` when the daemon is stopping, or the
    /// sender is gone, which is said once (the module's rule).
    Stop { stopping: bool },
    /// The forward listener moved. `bound` when it is bound. The first wait
    /// also sees a forward bound before the loop: the receiver has not
    /// marked the current value seen.
    Forward { bound: bool },
    /// The relay's hop-0 verdict moved.
    Origin(OriginVerdict),
    /// The Tor dial tally moved.
    TorLink(TorLinkTally),
    /// A probe's nonce came back. Biased ahead of the timer, so a take
    /// already in the cell is folded before a bound that has also elapsed;
    /// the core still compares the take's own time with the bound.
    ProbeArrived(Option<ProbeArrival>),
    /// The armed deadline fired, or the scheduler closed.
    Timer { closed: bool },
    /// An event from Tor, or nothing when the sink closed.
    Event(Option<ControlReply>),
    /// A Tor process ended.
    Death(Option<(u64, TorDeath)>),
    /// The bootstrap watch moved, to this state. After `Ready` or
    /// `Failed` the watch has left the wait.
    Bootstrap(BootstrapState),
}

/// A wait that returned: what woke it, when, and the sleep it observed.
#[derive(Debug)]
pub(super) struct Wake {
    pub(super) what: Woken,
    pub(super) woke: u64,
    resumed: Option<Duration>,
}

impl Wake {
    /// The sleep the wait observed, as the input folded ahead of what woke it.
    pub(super) fn lead(&self) -> Option<Input> {
        self.resumed.map(|late_by| Input::Resumed { late_by })
    }
}

/// Wait for the next thing to do. The wait itself says whether the machine
/// slept (§5, "Resumed from suspend"): it returned at `woke`, and a return
/// more than `control::RESUMED_AFTER` past the deadline it was armed with
/// means the process did not run, whatever woke it. At a wake the dialer's
/// timers fire too, so a dial result can be ready with the late timer and
/// win the biased order; it is judged after the sleep is folded, on windows
/// that start at the wake. With no deadline armed nothing can be late.
pub(super) async fn wait<C: Clock>(
    sources: Sources<'_>,
    owner: &OwnerHandle<C>,
    armed: Option<u64>,
    entered: u64,
) -> Wake {
    let open = sources.open;
    // Each pass either returns what woke it or has taken a closed source
    // out of the wait (the module's rule). The timer stays in, so the
    // select always has a branch.
    let what = loop {
        tokio::select! {
            biased;
            changed = sources.stop.changed(), if open.stop => {
                if changed.is_err() {
                    open.stop = false;
                }
                break Woken::Stop {
                    stopping: changed.is_err() || *sources.stop.borrow(),
                };
            }
            changed = sources.forward.changed(), if open.forward => {
                if changed.is_err() {
                    open.forward = false;
                    continue;
                }
                break Woken::Forward {
                    bound: sources.forward.borrow().is_some(),
                };
            }
            changed = sources.origin.changed(), if open.origin => {
                if changed.is_err() {
                    open.origin = false;
                    continue;
                }
                break Woken::Origin(*sources.origin.borrow_and_update());
            }
            changed = sources.tor_link.changed(), if open.tor_link => {
                if changed.is_err() {
                    open.tor_link = false;
                    continue;
                }
                break Woken::TorLink(*sources.tor_link.borrow_and_update());
            }
            changed = sources.probe_arrivals.changed(), if open.probe_arrivals => {
                if changed.is_err() {
                    open.probe_arrivals = false;
                    continue;
                }
                break Woken::ProbeArrived(*sources.probe_arrivals.borrow_and_update());
            }
            wake = owner.wait_wake_async() => break Woken::Timer { closed: wake.is_err() },
            event = sources.incoming.recv() => break Woken::Event(event),
            death = sources.death.recv() => break Woken::Death(death),
            state = next_bootstrap(sources.bootstrap) => {
                if let Some(state) = state {
                    break Woken::Bootstrap(state);
                }
            }
        }
    };
    let woke = super::now(owner);
    Wake {
        what,
        woke,
        resumed: slept(armed, entered, woke),
    }
}

/// How late a wait armed with `armed` at `entered` returned at `woke`, when
/// that is a sleep ([`resume_lateness`]). A deadline already past when the
/// wait began has no time left: a return more than `RESUMED_AFTER` later
/// is still a sleep.
fn slept(armed: Option<u64>, entered: u64, woke: u64) -> Option<Duration> {
    let due = armed?;
    let until_due = Duration::from_nanos(due.saturating_sub(entered));
    let waited = Duration::from_nanos(woke.saturating_sub(entered));
    match resume_lateness(until_due, waited) {
        Resume::Slept { late_by } => Some(late_by),
        Resume::Awake => None,
    }
}

/// The batch a wait folds: the sleep it observed first, then what woke it.
pub(super) fn led(lead: Option<Input>, inputs: Vec<Input>) -> Vec<Input> {
    lead.into_iter().chain(inputs).collect()
}

/// The inputs of a wake that needs none of the driver's state. The timer,
/// an event, a death and the bootstrap watch are the driver's to read
/// and give nothing here.
pub(super) fn plain_inputs(what: &Woken) -> Vec<Input> {
    match what {
        Woken::Stop { stopping } => stopping.then_some(Input::Shutdown).into_iter().collect(),
        Woken::Forward { bound } => bound.then_some(Input::EndpointReady).into_iter().collect(),
        Woken::Origin(verdict) => vec![super::verdict_input(*verdict)],
        Woken::TorLink(tally) => vec![super::tally_input(*tally)],
        Woken::ProbeArrived(arrival) => arrival
            .map(|arrival| {
                tracing::info!(target: "tor", "this node's onion probe arrived");
                Input::ProbeArrived {
                    minted_at: arrival.minted_at.get(),
                    arrived_at: arrival.arrived_at.get(),
                }
            })
            .into_iter()
            .collect(),
        Woken::Timer { .. } | Woken::Event(_) | Woken::Death(_) | Woken::Bootstrap(_) => Vec::new(),
    }
}

/// The bootstrap watch's next state. `None` when its sender closed with
/// nothing new to say: the watch has left the wait. After `Ready` or
/// `Failed` it leaves the wait too; nothing follows either. With no watch
/// in hand this never resolves.
async fn next_bootstrap(
    bootstrap: &mut Option<watch::Receiver<BootstrapState>>,
) -> Option<BootstrapState> {
    let Some(watch) = bootstrap else {
        return std::future::pending().await;
    };
    if watch.changed().await.is_err() {
        *bootstrap = None;
        return None;
    }
    let state = *watch.borrow_and_update();
    if matches!(state, BootstrapState::Ready | BootstrapState::Failed) {
        *bootstrap = None;
    }
    Some(state)
}

/// Events already held when a wait ends. The first empty read stops it, so
/// an event that arrives while this runs waits for the next loop: the timer
/// that won this wait is not held off by a stream of new ones.
pub(super) fn take_queued(incoming: &mut EventReceiver) -> Vec<ControlReply> {
    let mut queued = Vec::new();
    while let Ok(reply) = incoming.try_recv() {
        queued.push(reply);
    }
    queued
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use shekyl_ffi::origin_verdict::OriginVerdict;
    use shekyl_ffi::tor_link::TorLinkTally;
    use shekyl_timing_engine::Clock;
    use shekyl_timing_engine::{EngineService, ManualClock, OwnerClass, Tick};
    use shekyl_tor_control_client::control::{
        BootstrapState, EventSink, ReplyFramer, RESUMED_AFTER,
    };
    use shekyl_tor_control_client::supervisor::Input;
    use tokio::sync::{mpsc, watch};

    use super::super::arm;
    use super::{led, plain_inputs, slept, take_queued, wait, Open, Sources, Wake, Woken};

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
        let (_stop_tx, mut stop) = watch::channel(false);
        let (_forward_tx, mut forward) = watch::channel(None);
        let (_origin_tx, mut origin) = watch::channel(OriginVerdict::Absent);
        let (tally_tx, mut tor_link) = watch::channel(TorLinkTally::default());
        let (_arrivals_tx, mut probe_arrivals) = watch::channel(None);
        let (_sink, mut incoming) = EventSink::bounded();
        let (_death_tx, mut death) = mpsc::channel(1);
        let mut bootstrap = None;
        let mut open = Open::ALL;
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
            open: &mut open,
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
        let (_stop_tx, mut stop) = watch::channel(false);
        let (_forward_tx, mut forward) = watch::channel(None);
        let (_origin_tx, mut origin) = watch::channel(OriginVerdict::Absent);
        let (_tally_tx, mut tor_link) = watch::channel(TorLinkTally::default());
        let (_arrivals_tx, mut probe_arrivals) = watch::channel(None);
        let (sink, mut incoming) = EventSink::bounded();
        let (_death_tx, mut death) = mpsc::channel(1);
        let mut bootstrap = None;
        let mut open = Open::ALL;
        arm(&owner, Some(due));
        hold_until_the_deadline_is_delivered(&owner, due);
        sink.route(framed_notice());
        let sources = Sources {
            open: &mut open,
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
        let queued = take_queued(&mut incoming);
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
        open: Open,
        stop_tx: Option<watch::Sender<bool>>,
        stop: watch::Receiver<bool>,
        forward_tx: Option<watch::Sender<Option<std::net::SocketAddr>>>,
        forward: watch::Receiver<Option<std::net::SocketAddr>>,
        origin_tx: Option<watch::Sender<OriginVerdict>>,
        origin: watch::Receiver<OriginVerdict>,
        tally_tx: Option<watch::Sender<TorLinkTally>>,
        tor_link: watch::Receiver<TorLinkTally>,
        arrivals_tx: Option<watch::Sender<Option<shekyl_ffi::tor_link::ProbeArrival>>>,
        probe_arrivals: watch::Receiver<Option<shekyl_ffi::tor_link::ProbeArrival>>,
        sink: EventSink,
        incoming: shekyl_tor_control_client::control::EventReceiver,
        _death_tx: mpsc::Sender<(u64, shekyl_tor_control_daemon::TorDeath)>,
        death: mpsc::Receiver<(u64, shekyl_tor_control_daemon::TorDeath)>,
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
                open: Open::ALL,
                stop_tx: Some(stop_tx),
                stop,
                forward_tx: Some(forward_tx),
                forward,
                origin_tx: Some(origin_tx),
                origin,
                tally_tx: Some(tally_tx),
                tor_link,
                arrivals_tx: Some(arrivals_tx),
                probe_arrivals,
                sink,
                incoming,
                _death_tx: death_tx,
                death,
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
                open: &mut self.open,
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
    /// stop is out of the wait. Fails if the stop branch leaves `open.stop`
    /// set (a stop wake at every wait after).
    #[tokio::test(start_paused = true)]
    async fn a_closed_stop_is_said_once() {
        let mut harness = Harness::new();
        drop(harness.stop_tx.take());
        let due = secs(30);
        let first = harness.wait(Some(due)).await;
        assert!(matches!(first.what, Woken::Stop { stopping: true }));
        assert!(!harness.open.stop);
        assert!(harness.wait_a_minute(Some(due)).await.is_none());
    }

    /// A closed watch other than the stop says nothing and leaves the
    /// wait; the next thing that happens, here the timer, ends it.
    async fn a_closure_leaves_quietly(close: fn(&mut Harness), open: fn(&Open) -> bool) {
        let mut harness = Harness::new();
        close(&mut harness);
        let due = secs(30);
        assert!(
            harness.wait_a_minute(Some(due)).await.is_none(),
            "a closed watch woke the loop"
        );
        assert!(
            !open(&harness.open),
            "the closed watch is still in the wait"
        );
        let timer = harness.reach(due).await;
        assert!(matches!(timer.what, Woken::Timer { closed: false }));
    }

    /// Fails if the forward branch breaks with a wake for its closure, or
    /// leaves `open.forward` set.
    #[tokio::test(start_paused = true)]
    async fn a_closed_forward_watch_leaves_the_wait_quietly() {
        a_closure_leaves_quietly(|h| drop(h.forward_tx.take()), |o| o.forward).await;
    }

    /// Fails if the origin branch breaks with a wake for its closure, or
    /// leaves `open.origin` set.
    #[tokio::test(start_paused = true)]
    async fn a_closed_origin_watch_leaves_the_wait_quietly() {
        a_closure_leaves_quietly(|h| drop(h.origin_tx.take()), |o| o.origin).await;
    }

    /// Fails if the tally branch breaks with a wake for its closure, or
    /// leaves `open.tor_link` set.
    #[tokio::test(start_paused = true)]
    async fn a_closed_tally_watch_leaves_the_wait_quietly() {
        a_closure_leaves_quietly(|h| drop(h.tally_tx.take()), |o| o.tor_link).await;
    }

    /// Fails if the arrivals branch breaks with a wake for its closure, or
    /// leaves `open.probe_arrivals` set.
    #[tokio::test(start_paused = true)]
    async fn a_closed_arrivals_watch_leaves_the_wait_quietly() {
        a_closure_leaves_quietly(|h| drop(h.arrivals_tx.take()), |o| o.probe_arrivals).await;
    }

    /// **The loop is bounded by what it is given, not by time.** The
    /// driver's wait, in a loop, over ten simulated minutes of a core in
    /// Running: the core's own deadlines armed, its samples answered, a
    /// bootstrap watch that said `Ready` and closed, a dial tally sent once
    /// and closed, the forward, origin and arrivals watches closed, and
    /// three events fed in. Every return is a deadline that came due or
    /// something fed in: the timers, the events (each a wake of its own or
    /// drained with a timer, as `after_timer` does), `Ready` and the tally.
    /// The core's actions are answered as the driver answers them with Tor
    /// up (its state file is there; a sample reads a full bootstrap). The
    /// Tor process's own I/O is not here (the driver needs a Tor to run);
    /// every wait-side source is. Restoring
    /// `let _changed = bootstrap.changed().await;` fails this at the
    /// iteration cap; so does any closed branch that returns.
    #[tokio::test(start_paused = true)]
    async fn the_loop_wakes_for_deadlines_and_what_it_is_fed_not_for_time() {
        use shekyl_tor_control_client::supervisor::{Action, Connectors, Core, TorSetting};
        let mut harness = Harness::new();
        let socks: std::net::SocketAddr = "127.0.0.1:9150".parse().expect("socks");
        let connectors = Connectors {
            tor: TorSetting::Managed,
            clearnet_on: true,
        };
        let (mut core, started) = Core::start(super::super::policy(), connectors, 0);
        // The driver arms the latest step's deadline; so does this loop.
        let mut deadline = started.deadline;
        for input in [
            Input::PinAccepted,
            Input::Spawned,
            Input::DirectorySample {
                progress: Some(10),
                socks: Some(socks),
                read: None,
            },
            Input::BootstrapComplete,
            Input::RouteInstalled,
            Input::OnionPublished,
        ] {
            deadline = core.on(input, 0).deadline;
        }
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
        let end = secs(10 * 60);
        let feed_at = [secs(65), secs(200), secs(431)];
        let mut fed = 0;
        let (mut timers, mut events, mut others) = (0_u32, 0_u32, 0_u32);
        let mut iterations = 0_u32;
        let mut reached = 0_u32;
        while harness.now() < end {
            if fed < feed_at.len() && harness.now() >= feed_at[fed] {
                harness.sink.route(framed_notice());
                fed += 1;
            }
            let due = deadline.expect("a core in Running has a deadline");
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
            assert!(iterations < 1_000, "the loop is spinning");
            let now = harness.now();
            let step = match wake.what {
                Woken::Timer { closed } => {
                    assert!(!closed);
                    timers += 1;
                    // As `after_timer`: events already queued fold with it.
                    events +=
                        u32::try_from(take_queued(&mut harness.incoming).len()).expect("a few");
                    core.on_deadline(now)
                }
                Woken::Event(_) => {
                    events += 1;
                    continue;
                }
                Woken::Bootstrap(BootstrapState::Ready) => {
                    others += 1;
                    core.on(Input::BootstrapComplete, now)
                }
                Woken::TorLink(seen) => {
                    others += 1;
                    core.on(super::super::tally_input(seen), now)
                }
                other => panic!("nothing else was fed in: {other:?}"),
            };
            deadline = step.deadline;
            // Answered as the driver answers them, with Tor up: its state
            // file is there, and a sample reads a full bootstrap.
            if step.actions.contains(&Action::WatchState) {
                deadline = core.on(Input::StateFileAppeared, now).deadline;
            }
            if step.actions.contains(&Action::Sample) {
                deadline = core
                    .on(
                        Input::DirectorySample {
                            progress: Some(100),
                            socks: Some(socks),
                            read: None,
                        },
                        now,
                    )
                    .deadline;
            }
        }
        assert_eq!(fed, feed_at.len());
        assert_eq!(events, 3, "each event fed in is folded once");
        assert_eq!(others, 2, "Ready once, the tally once");
        assert!(
            iterations <= timers + events + others,
            "{iterations} wakes for {timers} timers, {events} events, {others} other inputs"
        );
        // Each deadline reached gives its own wake, and at most one more: a
        // wake already delivered when another branch won is handed out on
        // the next pass (`arm` clears the engine's queue, not the owner's
        // slot), and is folded as a deadline not yet due.
        assert!(timers > 0, "the core's deadlines came due");
        assert!(
            timers <= 2 * reached + events + others,
            "{timers} timer wakes for {reached} deadlines reached"
        );
        // Ten minutes of Running: the liveness sample every 30 s
        // (`Policy::alive_every`) and little else; a spin is thousands a
        // second.
        assert!(reached <= 25, "{reached} deadlines in ten minutes");
    }
}
