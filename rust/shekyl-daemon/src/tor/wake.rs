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

/// What the loop waits on, borrowed from the driver for one wait.
pub(super) struct Sources<'a> {
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
    /// The stop flag moved. `stopping` when the daemon is stopping or the
    /// sender is gone.
    Stop { stopping: bool },
    /// The forward listener moved. `bound` when it is bound. The first wait
    /// also sees a forward bound before the loop: the receiver has not
    /// marked the current value seen.
    Forward { bound: bool },
    /// The relay's hop-0 verdict. The sender is process-static, so a closed
    /// channel does not happen; it reads as nothing, so it cannot spin here.
    Origin(Option<OriginVerdict>),
    /// The Tor dial tally. Process-static like the verdict.
    TorLink(Option<TorLinkTally>),
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
    /// The bootstrap watch moved.
    Bootstrap,
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
    let what = tokio::select! {
        biased;
        changed = sources.stop.changed() => Woken::Stop {
            stopping: changed.is_err() || *sources.stop.borrow(),
        },
        changed = sources.forward.changed() => Woken::Forward {
            bound: changed.is_ok() && sources.forward.borrow().is_some(),
        },
        changed = sources.origin.changed() => {
            Woken::Origin(changed.is_ok().then(|| *sources.origin.borrow_and_update()))
        }
        changed = sources.tor_link.changed() => {
            Woken::TorLink(changed.is_ok().then(|| *sources.tor_link.borrow_and_update()))
        }
        changed = sources.probe_arrivals.changed() => Woken::ProbeArrived(
            changed
                .is_ok()
                .then(|| *sources.probe_arrivals.borrow_and_update())
                .flatten(),
        ),
        wake = owner.wait_wake_async() => Woken::Timer { closed: wake.is_err() },
        event = sources.incoming.recv() => Woken::Event(event),
        death = sources.death.recv() => Woken::Death(death),
        () = wait_bootstrap(sources.bootstrap) => Woken::Bootstrap,
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
        Woken::Origin(verdict) => verdict.map(super::verdict_input).into_iter().collect(),
        Woken::TorLink(tally) => tally.map(super::tally_input).into_iter().collect(),
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
        Woken::Timer { .. } | Woken::Event(_) | Woken::Death(_) | Woken::Bootstrap => Vec::new(),
    }
}

async fn wait_bootstrap(bootstrap: &mut Option<watch::Receiver<BootstrapState>>) {
    if let Some(bootstrap) = bootstrap {
        let _changed = bootstrap.changed().await;
    } else {
        std::future::pending::<()>().await;
    }
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
    use shekyl_timing_engine::{EngineService, ManualClock, OwnerClass, Tick};
    use shekyl_tor_control_client::control::{EventSink, ReplyFramer, RESUMED_AFTER};
    use shekyl_tor_control_client::supervisor::Input;
    use tokio::sync::{mpsc, watch};

    use super::super::arm;
    use super::{led, plain_inputs, slept, take_queued, wait, Sources, Wake, Woken};

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
        clock.set(Tick::new(woke));
        arm(&owner, Some(due));
        let tally = TorLinkTally {
            opened: 0,
            unopened: 1,
            held: 0,
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
            matches!(wake.what, Woken::TorLink(Some(seen)) if seen == tally),
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

    /// The timer stands ahead of a control event, and the event stays
    /// queued for the drain. Folding the deadline first, or letting the
    /// event arm take a line that was already held, fails this.
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
        arm(&owner, Some(due));
        let mut wake = None;
        for _ in 0..8 {
            sink.route(framed_notice());
            tokio::task::yield_now().await;
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
            let got = wait(sources, &owner, Some(due), due).await;
            match got.what {
                Woken::Timer { closed: false } => {
                    let queued = take_queued(&mut incoming);
                    assert_eq!(queued.len(), 1, "the event arm did not take it");
                    assert_eq!(queued[0].status(), 650);
                    wake = Some(got);
                    break;
                }
                Woken::Event(Some(_)) => {}
                other => panic!("the wait ended on {other:?}"),
            }
        }
        let wake = wake.expect("the timer won a wait that also held an event");
        assert_eq!(wake.woke, due);
        assert_eq!(
            wake.resumed, None,
            "the deadline was already due, and the return was not late"
        );
    }
}
