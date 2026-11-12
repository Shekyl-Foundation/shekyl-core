// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The inbox: producers that end, the deadline's generation, the event
//! bound, and the loop's passes bounded by what it is fed.
//!
//! The engine's thread delivers a wake in real time while tokio's clock is
//! paused. A test therefore waits outright for a deadline it has made due,
//! and asks "does the wait stay pending?" only when no deadline is due, so
//! a paused-time timeout cannot race a delivery.

use std::net::SocketAddr;
use std::time::Duration;

use shekyl_p2p::{OriginVerdict, PerConnector, ProbeArrival, SupervisorFeeds, TorLinkTally};
use shekyl_timing_engine::{EngineService, ManualClock, OwnerClass, Tick};
use shekyl_tor_control_client::control::{
    BootstrapState, ControlReply, EventSink, ReplyFramer, EVENT_QUEUE_EVENTS,
};
use shekyl_tor_control_daemon::TorDeath;
use tokio::sync::{oneshot, watch};

use super::super::incarnation;
use super::{inbox, Arrival, Changed, Inbox, Owner, Poster, Timer, Woken};

fn secs(seconds: u64) -> u64 {
    seconds * 1_000_000_000
}

fn framed_notice() -> ControlReply {
    let mut framer = ReplyFramer::default();
    framer.push_bytes(b"650 NOTICE queued\r\n");
    framer.next_reply().expect("frames").expect("one reply")
}

fn forward() -> SocketAddr {
    "127.0.0.1:18081".parse().expect("a socket address")
}

/// The wait, given a minute of paused time: `None` when it stayed pending,
/// as a wait with nothing to do must.
async fn pending_a_minute(inbox: &mut Inbox) -> Option<Woken> {
    tokio::time::timeout(Duration::from_secs(60), inbox.wait())
        .await
        .ok()
}

/// A clock, its engine, and a timer posting into `poster`.
///
/// A hand clock does not tell the engine it moved, and the engine checks
/// what is due only after a command. [`Self::set`] moves the clock and
/// sends one through a spare owner, as the production clock's own sleep
/// would end on time.
struct Clocked {
    clock: ManualClock,
    nudge: shekyl_timing_engine::OwnerHandle<ManualClock>,
    service: Option<EngineService<ManualClock>>,
    timer: Option<Timer>,
}

impl Clocked {
    fn new(poster: Poster) -> Self {
        let clock = ManualClock::new(Tick::new(0));
        let service = EngineService::start(clock.clone());
        let owner = service
            .handle()
            .register(OwnerClass::Housekeeping)
            .expect("register");
        let nudge = service
            .handle()
            .register(OwnerClass::Housekeeping)
            .expect("register");
        Self {
            clock,
            nudge,
            service: Some(service),
            timer: Some(Timer::start(owner, poster)),
        }
    }

    /// Move the clock to `at`, and have the engine look.
    fn set(&self, at: u64) {
        self.clock.set(Tick::new(at));
        let _looked = self.nudge.clear();
    }

    fn timer(&mut self) -> &mut Timer {
        self.timer.as_mut().expect("the timer is held")
    }
}

/// Wait for the next arrival outright, skipping rings.
async fn next_arrival(inbox: &mut Inbox) -> Arrival {
    loop {
        if let Woken::Arrived(arrival) = inbox.wait().await {
            return arrival;
        }
    }
}

// ---------------------------------------------------------------------
// Producers that end
// ---------------------------------------------------------------------

/// **The owner's stop is said once.** Closing the queue is the stop. A
/// closed queue answers at once, every time, so it is not read again: the
/// next wait stays pending. Posting a stop and then closing would say it
/// twice and fail that pending check.
#[tokio::test(start_paused = true)]
async fn the_owners_stop_is_said_once() {
    let (mut owner, mut inbox, _feeds) = inbox();
    owner.stop();
    assert!(matches!(inbox.wait().await, Woken::Arrived(Arrival::Stop)));
    assert!(pending_a_minute(&mut inbox).await.is_none(), "it spun");
}

/// **The RPC's asking end posts asks and never holds off the stop**: a
/// `hiding` ask and a status ask arrive as asks, the owner's stop still
/// closes the queue though the asker is held, and an ask after it is
/// refused. Fails if the asker keeps the queue open (the stop would never
/// come) or posts after the inbox is gone.
#[tokio::test(start_paused = true)]
async fn the_rpcs_asker_never_holds_off_the_stop() {
    let (mut owner, mut inbox, _feeds) = inbox();
    let asker = owner.asker().expect("the queue is open");
    let _hiding = asker.ask_hiding().expect("posted");
    assert!(matches!(
        inbox.wait().await,
        Woken::Arrived(Arrival::Hiding(_))
    ));
    let _status = asker.ask_status().expect("posted");
    assert!(matches!(
        inbox.wait().await,
        Woken::Arrived(Arrival::Status(_))
    ));
    owner.stop();
    assert!(matches!(inbox.wait().await, Woken::Arrived(Arrival::Stop)));
    drop(inbox);
    assert!(asker.ask_hiding().is_none(), "an ask after the stop");
    assert!(asker.ask_status().is_none(), "an ask after the stop");
}

/// **An owner dropped without a stop closes the queue, which is the
/// stop**: said once, then nothing. Treating the close as nothing would
/// leave a loop that never stops; reading it again would spin.
#[tokio::test(start_paused = true)]
async fn an_owner_dropped_is_the_stop_said_once() {
    let (owner, mut inbox, _feeds) = inbox();
    drop(owner);
    assert!(matches!(inbox.wait().await, Woken::Arrived(Arrival::Stop)));
    assert!(pending_a_minute(&mut inbox).await.is_none());
}

/// **The network's producers ending wake nothing**: the feeds dropped
/// leave the cells as they were, and no wait returns for the drop. A value
/// set just before is kept and taken once. A feed that rang for its own
/// drop fails the second half.
#[tokio::test(start_paused = true)]
async fn the_networks_feeds_ending_wake_nothing_and_keep_their_last_value() {
    let (_owner, mut inbox, feeds) = inbox();
    let tally = TorLinkTally {
        opened: 2,
        ..TorLinkTally::default()
    };
    (feeds.tally)(tally);
    (feeds.verdict)(OriginVerdict::Connected);
    (feeds.sessions)(PerConnector {
        clearnet: 0,
        tor: 2,
    });
    drop(feeds);
    assert!(matches!(inbox.wait().await, Woken::Rang));
    assert_eq!(
        inbox.take_changed(),
        Changed {
            tally: Some(tally),
            verdict: Some(OriginVerdict::Connected),
            sessions: Some(PerConnector {
                clearnet: 0,
                tor: 2
            }),
            forward: None,
        },
        "the last values are kept"
    );
    assert!(pending_a_minute(&mut inbox).await.is_none());
    assert_eq!(inbox.take_changed(), Changed::default(), "taken once");
}

/// A cell holds the latest value only: two tallies before a pass are one
/// change, the later. Queuing every value fails this.
#[tokio::test(start_paused = true)]
async fn a_cell_holds_the_latest_value_only() {
    let (_owner, mut inbox, feeds) = inbox();
    let first = TorLinkTally {
        unopened: 1,
        ..TorLinkTally::default()
    };
    let second = TorLinkTally {
        unopened: 2,
        ..TorLinkTally::default()
    };
    (feeds.tally)(first);
    (feeds.tally)(second);
    assert!(matches!(inbox.wait().await, Woken::Rang));
    assert_eq!(inbox.take_changed().tally, Some(second));
    assert!(pending_a_minute(&mut inbox).await.is_none(), "one ring");
}

/// **Tor's event sink ending wakes nothing**: an event routed before the
/// drop arrives once, and the drop itself is not an event. A sink whose
/// end posted an arrival fails this.
#[tokio::test(start_paused = true)]
async fn the_event_sink_ending_wakes_nothing() {
    let (_owner, mut inbox, _feeds) = inbox();
    let sink = inbox.poster().events();
    sink.route(framed_notice());
    drop(sink);
    assert!(matches!(
        inbox.wait().await,
        Woken::Arrived(Arrival::Event(_))
    ));
    assert!(pending_a_minute(&mut inbox).await.is_none());
}

/// A probe's arrival is discrete: two arrivals are two, in order. A cell
/// for it would keep only the second.
#[tokio::test(start_paused = true)]
async fn each_probe_arrival_is_its_own() {
    let (_owner, mut inbox, feeds) = inbox();
    for minted in [1, 2] {
        feeds.probes.probe_arrived(ProbeArrival {
            minted_at: Tick::new(minted),
            arrived_at: Tick::new(minted + 10),
        });
    }
    for minted in [1, 2] {
        let Woken::Arrived(Arrival::Probe(arrival)) = inbox.wait().await else {
            panic!("a probe arrival");
        };
        assert_eq!(arrival.minted_at, Tick::new(minted));
    }
}

/// **An incarnation's producer ends with its process**: its bootstrap
/// transitions, then its death, each once, with its generation. After the
/// death nothing more is posted. A producer that kept watching the
/// bootstrap after the death fails the pending check.
#[tokio::test(start_paused = true)]
async fn an_incarnation_posts_its_bootstrap_then_its_death_and_ends() {
    let (_owner, mut inbox, _feeds) = inbox();
    let (died, death) = oneshot::channel::<TorDeath>();
    let (boot, bootstrap) = watch::channel(BootstrapState::Connecting { progress: 0 });
    let producer = tokio::spawn(incarnation(
        7,
        async move { death.await.unwrap_or(TorDeath::Stopped) },
        bootstrap,
        inbox.poster(),
    ));
    boot.send(BootstrapState::Connecting { progress: 45 })
        .expect("held");
    assert!(matches!(
        next_arrival(&mut inbox).await,
        Arrival::Bootstrap {
            generation: 7,
            state: BootstrapState::Connecting { progress: 45 }
        }
    ));
    died.send(TorDeath::Exited { code: Some(1) })
        .expect("the producer waits");
    assert!(matches!(
        next_arrival(&mut inbox).await,
        Arrival::Death {
            generation: 7,
            how: TorDeath::Exited { code: Some(1) }
        }
    ));
    producer.await.expect("the producer ended");
    assert!(
        boot.send(BootstrapState::Ready).is_err(),
        "the producer ended and let its watch go"
    );
    assert!(pending_a_minute(&mut inbox).await.is_none());
}

/// **`Ready` and `Failed` are said once, with the sender still held**:
/// nothing follows either, so the producer stops reading the watch. A
/// producer that read on fails nothing here only because the watch stays
/// quiet; one that took a closed watch's answer as a state would post
/// again, which the next case pins.
#[tokio::test(start_paused = true)]
async fn a_terminal_bootstrap_is_said_once() {
    for terminal in [BootstrapState::Ready, BootstrapState::Failed] {
        let (_owner, mut inbox, _feeds) = inbox();
        let (_died, death) = oneshot::channel::<TorDeath>();
        let (boot, bootstrap) = watch::channel(BootstrapState::Connecting { progress: 0 });
        let producer = tokio::spawn(incarnation(
            1,
            async move { death.await.unwrap_or(TorDeath::Stopped) },
            bootstrap,
            inbox.poster(),
        ));
        boot.send(terminal).expect("held");
        assert!(matches!(
            next_arrival(&mut inbox).await,
            Arrival::Bootstrap { state, .. } if state == terminal
        ));
        drop(boot);
        assert!(
            pending_a_minute(&mut inbox).await.is_none(),
            "{terminal:?} is said once"
        );
        producer.abort();
    }
}

/// **The spin (`TOR_SUPERVISOR.md` §10 `TSR-M15`).** A bootstrap watch
/// whose sender closed answers `changed()` at once, every time. The
/// producer stops reading it and posts nothing for the close; it then
/// waits on the death alone. Reading the watch after its close fails the
/// pending check, with the producer spinning.
#[tokio::test(start_paused = true)]
async fn a_closed_bootstrap_watch_posts_nothing_and_does_not_spin() {
    let (_owner, mut inbox, _feeds) = inbox();
    let (died, death) = oneshot::channel::<TorDeath>();
    let (boot, bootstrap) = watch::channel(BootstrapState::Connecting { progress: 0 });
    let producer = tokio::spawn(incarnation(
        2,
        async move { death.await.unwrap_or(TorDeath::Stopped) },
        bootstrap,
        inbox.poster(),
    ));
    drop(boot);
    assert!(pending_a_minute(&mut inbox).await.is_none());
    assert!(!producer.is_finished(), "it still waits on the death");
    died.send(TorDeath::Stopped).expect("held");
    assert!(matches!(
        next_arrival(&mut inbox).await,
        Arrival::Death { generation: 2, .. }
    ));
}

/// **The timer ends with its handle**: the loop that owned it is gone, so
/// nothing posts a deadline after, even one that comes due. A timer that
/// kept its last deadline armed past its handle fails this.
#[tokio::test(start_paused = true)]
async fn the_timer_ends_with_its_handle() {
    let (_owner, mut inbox, _feeds) = inbox();
    let mut clocked = Clocked::new(inbox.poster());
    clocked.timer().want(Some(secs(30)));
    tokio::task::yield_now().await;
    drop(clocked.timer.take());
    tokio::task::yield_now().await;
    clocked.set(secs(30));
    assert!(pending_a_minute(&mut inbox).await.is_none());
}

/// **The timer ends with the engine**: a closed engine delivers nothing,
/// and the timer posts nothing for its close. A close posted as a
/// deadline fails this.
#[tokio::test(start_paused = true)]
async fn the_timer_ends_with_the_engine() {
    let (_owner, mut inbox, _feeds) = inbox();
    let mut clocked = Clocked::new(inbox.poster());
    clocked.timer().want(Some(secs(30)));
    if let Some(service) = clocked.service.take() {
        service.close();
    }
    clocked.set(secs(30));
    assert!(pending_a_minute(&mut inbox).await.is_none());
}

// ---------------------------------------------------------------------
// The deadline and its generation
// ---------------------------------------------------------------------

/// **A deadline moved later is posted once, when the later one is due,
/// with the new generation.** The engine keeps the earlier hint and fires
/// it first; the clock is short of the deadline wanted, so nothing is
/// posted and the later one is armed. No arm is cleared. A timer that
/// posted on any wake fails the pending check; one that kept the old
/// generation fails the last assertion.
#[tokio::test(start_paused = true)]
async fn a_deadline_moved_later_is_posted_once_with_its_new_generation() {
    let (_owner, mut inbox, _feeds) = inbox();
    let mut clocked = Clocked::new(inbox.poster());
    let early = clocked.timer().want(Some(secs(10))).expect("wanted");
    let late = clocked.timer().want(Some(secs(40))).expect("wanted");
    assert_ne!(early.generation, late.generation);
    clocked.set(secs(10));
    assert!(
        pending_a_minute(&mut inbox).await.is_none(),
        "the old hint fired short of the deadline wanted"
    );
    clocked.set(secs(40));
    let Arrival::Deadline { generation } = next_arrival(&mut inbox).await else {
        panic!("the deadline");
    };
    assert_eq!(generation, late.generation);
}

/// A deadline wanted again unchanged keeps its generation, and a cleared
/// one is posted by nothing. A timer that renumbered every pass would
/// make a deadline in flight look stale.
#[tokio::test(start_paused = true)]
async fn an_unchanged_deadline_keeps_its_generation_and_a_cleared_one_is_not_posted() {
    let (_owner, mut inbox, _feeds) = inbox();
    let mut clocked = Clocked::new(inbox.poster());
    let first = clocked.timer().want(Some(secs(10))).expect("wanted");
    let again = clocked.timer().want(Some(secs(10))).expect("wanted");
    assert_eq!(first, again);
    assert_eq!(clocked.timer().want(None), None);
    clocked.set(secs(10));
    assert!(pending_a_minute(&mut inbox).await.is_none());
}

// ---------------------------------------------------------------------
// The event bound
// ---------------------------------------------------------------------

/// **Tor's events are bounded at [`EVENT_QUEUE_EVENTS`] not yet taken**
/// (`TSR-F2`): one more is dropped and counted, and taking one makes room.
/// An unbounded feed fails the count; one that never frees a place fails
/// the last route.
#[tokio::test(start_paused = true)]
async fn tor_events_are_bounded_and_a_taken_one_makes_room() {
    let (_owner, mut inbox, _feeds) = inbox();
    let sink: EventSink = inbox.poster().events();
    for _ in 0..EVENT_QUEUE_EVENTS {
        sink.route(framed_notice());
    }
    assert_eq!(sink.dropped(), 0);
    sink.route(framed_notice());
    assert_eq!(sink.dropped(), 1, "the one past the bound");
    assert!(matches!(
        inbox.wait().await,
        Woken::Arrived(Arrival::Event(_))
    ));
    sink.route(framed_notice());
    assert_eq!(sink.dropped(), 1, "a taken event made room");
}

/// **A deadline goes after the arrivals already queued behind it** (#1283
/// review). The loop judges a deadline at the moment it takes it, and a
/// probe's nonce queued behind it was taken before that moment: folded
/// after the deadline, it would find the probe already timed out. Only what
/// is queued when the deadline is taken goes ahead, so arrivals posted later
/// stay behind it and a stream cannot hold it back; the Tor events moved
/// ahead free their places. Handing the deadline out in queue order fails
/// the first assertion; moving events ahead without counting them taken
/// fails the bound.
#[tokio::test(start_paused = true)]
async fn a_deadline_goes_after_the_arrivals_already_queued_behind_it() {
    let (_owner, mut inbox, feeds) = inbox();
    let poster = inbox.poster();
    let sink: EventSink = poster.events();
    poster.post(Arrival::Deadline { generation: 7 });
    feeds.probes.probe_arrived(ProbeArrival {
        minted_at: Tick::new(1),
        arrived_at: Tick::new(secs(45)),
    });
    for _ in 0..EVENT_QUEUE_EVENTS {
        sink.route(framed_notice());
    }
    assert!(
        matches!(next_arrival(&mut inbox).await, Arrival::Probe(_)),
        "the probe's answer is folded before the deadline"
    );
    sink.route(framed_notice());
    assert_eq!(sink.dropped(), 0, "the events moved ahead made room");
    feeds.probes.probe_arrived(ProbeArrival {
        minted_at: Tick::new(2),
        arrived_at: Tick::new(secs(70)),
    });
    for _ in 0..EVENT_QUEUE_EVENTS {
        assert!(matches!(next_arrival(&mut inbox).await, Arrival::Event(_)));
    }
    assert!(matches!(
        next_arrival(&mut inbox).await,
        Arrival::Deadline { generation: 7 }
    ));
    assert!(
        matches!(next_arrival(&mut inbox).await, Arrival::Event(_)),
        "an event routed after the deadline was taken stays behind it"
    );
    let Arrival::Probe(late) = next_arrival(&mut inbox).await else {
        panic!("the later probe answer, behind the deadline");
    };
    assert_eq!(late.minted_at, Tick::new(2));
    assert!(
        pending_a_minute(&mut inbox).await.is_none(),
        "nothing else was queued"
    );
}

// ---------------------------------------------------------------------
// The bound on passes
// ---------------------------------------------------------------------

/// The six producers of the inbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Producer {
    /// The supervisor's handle: the forward listener, a status ask, and the
    /// stop.
    Owner,
    /// A request to Tor run off the loop: its answer (`super::requests`).
    Request,
    /// The network: the tally, the verdict, the sessions, probe arrivals.
    Network,
    /// Tor's control connection: its events.
    Events,
    /// One process: its bootstrap transitions and its death.
    Incarnation,
    /// The deadline.
    Timer,
}

const PRODUCERS: [Producer; 6] = [
    Producer::Owner,
    Producer::Request,
    Producer::Network,
    Producer::Events,
    Producer::Incarnation,
    Producer::Timer,
];

/// Every order of `items`.
fn orders(items: &[Producer]) -> Vec<Vec<Producer>> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut all = Vec::new();
    for (index, first) in items.iter().enumerate() {
        let mut rest = items.to_vec();
        rest.remove(index);
        for mut tail in orders(&rest) {
            tail.insert(0, *first);
            all.push(tail);
        }
    }
    all
}

/// The producers, live, as one run holds them.
struct Live {
    owner: Option<Owner>,
    request: Option<Poster>,
    feeds: Option<SupervisorFeeds>,
    events: Option<EventSink>,
    boot: Option<watch::Sender<BootstrapState>>,
    died: Option<oneshot::Sender<TorDeath>>,
    clocked: Clocked,
    /// Arrivals posted and cell values set: what the loop is fed.
    fed: usize,
    /// The next deadline this run makes due.
    due: u64,
}

impl Live {
    /// Feed one input from `producer`, if it is still live. A deadline is
    /// made due here and waited for outright, so a later "pending" check
    /// races no delivery.
    async fn feed(&mut self, producer: Producer, inbox: &mut Inbox, passes: &mut usize) {
        match producer {
            Producer::Owner => {
                if let Some(owner) = &self.owner {
                    owner.forward(forward());
                    drop(owner.ask_status());
                    self.fed += 2;
                }
            }
            Producer::Request => {
                if let Some(request) = &self.request {
                    request.post(Arrival::Reply {
                        number: u64::try_from(self.fed).expect("small"),
                        answer: Box::new(super::super::requests::Answer::Inputs(Vec::new())),
                    });
                    self.fed += 1;
                }
            }
            Producer::Network => {
                if let Some(feeds) = &self.feeds {
                    (feeds.tally)(TorLinkTally {
                        opened: u64::try_from(self.fed).expect("small"),
                        ..TorLinkTally::default()
                    });
                    feeds.probes.probe_arrived(ProbeArrival {
                        minted_at: Tick::new(1),
                        arrived_at: Tick::new(2),
                    });
                    self.fed += 2;
                }
            }
            Producer::Events => {
                if let Some(events) = &self.events {
                    events.route(framed_notice());
                    self.fed += 1;
                }
            }
            Producer::Incarnation => {
                if let Some(boot) = &self.boot {
                    let progress = u8::try_from(self.fed % 100).expect("small");
                    if boot.send(BootstrapState::Connecting { progress }).is_ok() {
                        self.fed += 1;
                    }
                }
            }
            Producer::Timer => {
                let Clocked {
                    clock,
                    nudge,
                    timer,
                    ..
                } = &mut self.clocked;
                if let Some(timer) = timer.as_mut() {
                    self.due += secs(30);
                    timer.want(Some(self.due));
                    clock.set(Tick::new(self.due));
                    let _looked = nudge.clear();
                    self.fed += 1;
                    // With the queue open the deadline is posted: wait for it
                    // outright. With it closed nothing can be posted, and the
                    // engine's delivery reaches no one.
                    if self.owner.is_some() {
                        loop {
                            let woken = next_counted(inbox, passes).await;
                            if matches!(woken, Woken::Arrived(Arrival::Deadline { .. })) {
                                timer.spent();
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    /// End `producer`. The owner's end closes the queue, which is the stop:
    /// one more arrival.
    fn close(&mut self, producer: Producer) {
        match producer {
            Producer::Owner => {
                if self.owner.take().is_some() {
                    self.fed += 1;
                }
            }
            Producer::Request => drop(self.request.take()),
            Producer::Network => drop(self.feeds.take()),
            Producer::Events => drop(self.events.take()),
            Producer::Incarnation => {
                drop(self.boot.take());
                if let Some(died) = self.died.take() {
                    if died.send(TorDeath::Stopped).is_ok() {
                        self.fed += 1;
                    }
                }
            }
            Producer::Timer => drop(self.clocked.timer.take()),
        }
    }
}

/// The next wait's return, counted as a pass.
async fn next_counted(inbox: &mut Inbox, passes: &mut usize) -> Woken {
    let woken = inbox.wait().await;
    *passes += 1;
    if matches!(woken, Woken::Rang) {
        let _ = inbox.take_changed();
    }
    woken
}

/// Wait until the inbox has nothing to do, counting the passes.
async fn drain(inbox: &mut Inbox, passes: &mut usize) {
    while let Some(woken) = pending_a_minute(inbox).await {
        *passes += 1;
        if matches!(woken, Woken::Rang) {
            let _ = inbox.take_changed();
        }
        assert!(*passes < 10_000, "the loop is spinning");
    }
}

/// **One property: for any order of producers closing, the loop's passes
/// are bounded by the inputs and deadlines fed in** (Rick, 2026-11-05).
/// Every one of the 720 orders: each live producer feeds an input, one
/// closes, each still live feeds again, and so on until all have closed.
/// Every wait that returns is a pass. The passes never exceed what was fed.
/// The owner's close is one of those inputs, the stop said once; a second
/// stop from that close would pass the bound. Once every producer has
/// ended, the wait stays pending. A closed source that answers a wait
/// fails the bound with the spin cap.
#[tokio::test(start_paused = true)]
async fn for_any_order_of_producers_closing_the_passes_are_bounded_by_the_inputs() {
    for order in orders(&PRODUCERS) {
        let (owner, mut inbox, feeds) = inbox();
        let events = inbox.poster().events();
        let (died, death) = oneshot::channel::<TorDeath>();
        let (boot, bootstrap) = watch::channel(BootstrapState::Connecting { progress: 0 });
        tokio::spawn(incarnation(
            1,
            async move { death.await.unwrap_or(TorDeath::Stopped) },
            bootstrap,
            inbox.poster(),
        ));
        let clocked = Clocked::new(inbox.poster());
        let mut live = Live {
            owner: Some(owner),
            request: Some(inbox.poster()),
            feeds: Some(feeds),
            events: Some(events),
            boot: Some(boot),
            died: Some(died),
            clocked,
            fed: 0,
            due: 0,
        };
        let mut passes = 0usize;
        for closing in &order {
            for producer in PRODUCERS {
                live.feed(producer, &mut inbox, &mut passes).await;
            }
            live.close(*closing);
            drain(&mut inbox, &mut passes).await;
        }
        assert!(
            passes <= live.fed,
            "{order:?}: {passes} passes for {} inputs fed",
            live.fed
        );
        assert!(
            pending_a_minute(&mut inbox).await.is_none(),
            "{order:?}: every producer ended, and the wait still returned"
        );
    }
}

/// **The loop is bounded by what it is given, not by time** (the ten-minute
/// loop count). Ten simulated minutes, as the driver waits: a deadline
/// every [`STEP`], a bootstrap that says `Ready` and closes, a tally set
/// once by a network that then ends, and three of Tor's events. Every
/// return is a deadline that came due or something fed in, and each
/// deadline is its own pass: no delivered wake is handed out a second
/// time, as `arm`'s clear-and-re-arm used to allow.
#[tokio::test(start_paused = true)]
async fn the_loop_wakes_for_deadlines_and_what_it_is_fed_not_for_time() {
    /// How far apart the loop wants its next deadline.
    const STEP: u64 = 30;
    /// How long the loop runs.
    const WINDOW: u64 = 10 * 60;
    let (_owner, mut inbox, feeds) = inbox();
    let events = inbox.poster().events();
    let mut clocked = Clocked::new(inbox.poster());
    let (_died, death) = oneshot::channel::<TorDeath>();
    let (boot, bootstrap) = watch::channel(BootstrapState::Connecting { progress: 0 });
    tokio::spawn(incarnation(
        1,
        async move { death.await.unwrap_or(TorDeath::Stopped) },
        bootstrap,
        inbox.poster(),
    ));
    boot.send(BootstrapState::Ready).expect("held");
    drop(boot);
    (feeds.tally)(TorLinkTally {
        unopened: 1,
        ..TorLinkTally::default()
    });
    drop(feeds);
    let feed_at = [secs(45), secs(200), secs(410)];
    let mut fed_events = 0;
    let (mut deadlines, mut seen_events, mut ready, mut rings, mut passes) = (0, 0, 0, 0, 0);
    let mut now = 0;
    let mut wanted = clocked.timer().want(Some(secs(STEP)));
    while now < secs(WINDOW) {
        // What has come in: wait until nothing is left.
        while let Some(woken) = pending_a_minute(&mut inbox).await {
            passes += 1;
            match woken {
                Woken::Rang => {
                    let _ = inbox.take_changed();
                    rings += 1;
                }
                Woken::Arrived(Arrival::Event(_)) => seen_events += 1,
                Woken::Arrived(Arrival::Bootstrap {
                    state: BootstrapState::Ready,
                    ..
                }) => ready += 1,
                Woken::Arrived(other) => panic!("nothing else was fed in: {other:?}"),
            }
            assert!(passes < 10_000, "the loop is spinning");
        }
        // Time passes to the next deadline; it comes due.
        let due = wanted.expect("a deadline is wanted").at;
        if fed_events < feed_at.len() && feed_at[fed_events] <= due {
            events.route(framed_notice());
            fed_events += 1;
        }
        now = due;
        clocked.set(now);
        loop {
            let woken = inbox.wait().await;
            passes += 1;
            match woken {
                Woken::Arrived(Arrival::Deadline { generation }) => {
                    assert_eq!(Some(generation), wanted.map(|wanted| wanted.generation));
                    deadlines += 1;
                    clocked.timer().spent();
                    break;
                }
                Woken::Arrived(Arrival::Event(_)) => seen_events += 1,
                other => panic!("only the deadline and an event were due: {other:?}"),
            }
        }
        wanted = clocked.timer().want(Some(now + secs(STEP)));
    }
    assert_eq!(seen_events, 3, "each event fed in is folded once");
    assert_eq!(ready, 1, "Ready once");
    assert_eq!(rings, 1, "the tally once");
    assert_eq!(deadlines, WINDOW / STEP, "each deadline is one pass");
    assert_eq!(
        passes,
        deadlines + seen_events + ready + rings,
        "every pass is a deadline or something fed in"
    );
}
