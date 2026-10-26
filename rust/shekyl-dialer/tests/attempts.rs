// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Dial attempts off the loop thread (the dialer in-flight bound, revision 2,
//! Rick 2026-10-25): the brief's tests 1 and 6 to 9, and a stop that wins
//! before the insert. Each attempt is a task; the loop launches it and
//! applies its result, and never waits on a dial. A waited dial runs on
//! the caller. Revision 4's tests 12 to 16: a Tor timeout at or after the
//! managed Tor's window is final within its test (Rick, 2026-10-26).

#[path = "support/log_capture.rs"]
mod log_capture;

use log_capture::log_text;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::thread;
use std::time::{Duration, Instant};

use shekyl_capped_stream::{ByteQueue, InboundEnd, QueueHold, Session, StreamEnds};
use shekyl_dialer::{Dialer, Launch, WAKE_BASE_NANOS, WAKE_JITTER_NANOS};
use shekyl_draw_rng::SplitMix64;
use shekyl_levin::{
    response, BasicNodeData, BucketReader, CoreSyncData, HandshakeRequest, HandshakeResponse,
    PeerlistEntry, PortableMap, Received, COMMAND_HANDSHAKE,
};
use shekyl_peer_policy::InboundCeiling;
use shekyl_peerlist::{CloseCause, CloseKind, ConnectorId, NetworkAddress, RefusedSet, Tick};
use shekyl_seam::{
    admit, drive_inbound, Channel, ConnectFuture, Dial, Endpoint, Hub, Route, RoutePublish,
    SocketId, SyncPayload,
};
use shekyl_timing_engine::{Clock, EngineService, ManualClock, OwnerClass};
use shekyl_transport_layer::Sockets;

const CLEARNET: ConnectorId = ConnectorId::Clearnet;
const TOR: ConnectorId = ConnectorId::Tor;
const NETWORK: [u8; 16] = [7; 16];
const SEND_CAP: usize = 64 * 1024;

fn peer(n: u16) -> NetworkAddress {
    let [hi, lo] = n.to_be_bytes();
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 17, hi, lo),
        port: 18080,
    }
}

/// `count` distinct onions whose keys are valid points.
fn onions(count: usize) -> Vec<NetworkAddress> {
    (1u8..=255)
        .map(|n| shekyl_onion_v3::v3_onion_hostname(&[n; 32]))
        .filter(|host| shekyl_onion_v3::v3_pubkey(host).is_some())
        .take(count)
        .map(|host| NetworkAddress::Tor { host, port: 18080 })
        .collect()
}

fn reply(network_id: [u8; 16]) -> Vec<u8> {
    let body = HandshakeResponse {
        node_data: BasicNodeData { network_id },
        payload_data: CoreSyncData {
            current_height: 20,
            cumulative_difficulty: 200,
            cumulative_difficulty_top64: 0,
            top_id: [2; 32],
        },
        local_peerlist_new: Vec::<PeerlistEntry>::new(),
    };
    response(COMMAND_HANDSHAKE, &body.store().expect("encode"))
}

fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let start = Instant::now();
    while !condition() {
        assert!(start.elapsed() < Duration::from_secs(5), "{what}");
        thread::sleep(Duration::from_millis(2));
    }
}

/// The ends of one channel the held dial opened.
struct Held {
    inbound: InboundEnd,
    writer: ByteQueue,
    _hold: QueueHold,
}

/// Opens each channel through the transport layer's admission, answers it
/// with the next queued handshake (or nothing), and keeps its ends: the
/// test reads what the dialer wrote and can close a session as the peer.
struct HeldDial {
    sockets: Sockets,
    answers: Mutex<VecDeque<Vec<u8>>>,
    held: Mutex<HashMap<SocketId, Held>>,
    /// Causes the next connects fail with, in order, before any answer: the
    /// connector refusing the dial, after the nanoseconds it took.
    refusals: Mutex<VecDeque<(CloseCause, u64)>>,
    /// The clock a refusal moves by the time it took.
    clock: Mutex<Option<ManualClock>>,
    /// Every connect, refused or not.
    connects: AtomicUsize,
}

impl HeldDial {
    fn answering(sockets: Sockets, answers: Vec<Vec<u8>>) -> Self {
        Self {
            sockets,
            answers: Mutex::new(answers.into()),
            held: Mutex::new(HashMap::new()),
            refusals: Mutex::new(VecDeque::new()),
            clock: Mutex::new(None),
            connects: AtomicUsize::new(0),
        }
    }

    /// The next connect fails with `cause` after `took` on `clock`.
    fn refuse_after(&self, clock: &ManualClock, cause: CloseCause, took: Duration) {
        *self.clock.lock().expect("clock") = Some(clock.clone());
        let took = u64::try_from(took.as_nanos()).expect("a short wait");
        self.refusals
            .lock()
            .expect("refusals")
            .push_back((cause, took));
    }

    /// The peer closes `id`'s session: the connector stores its cause.
    fn close_as_peer(&self, id: SocketId) {
        if let Some(held) = self.held.lock().expect("held").get(&id) {
            held.inbound.close(CloseCause::new(CloseKind::PeerClosed));
        }
    }

    /// The handshake request the dialer wrote on `id`, decoded.
    fn request(&self, id: SocketId) -> HandshakeRequest {
        let bytes = {
            let held = self.held.lock().expect("held");
            let held = held.get(&id).expect("a held channel");
            held.writer.try_pop().expect("the request was written")
        };
        let mut reader = BucketReader::new();
        reader.feed(&bytes).expect("a levin frame");
        match reader.next_message().expect("one message") {
            Some(Received::Request { command, payload }) if command == COMMAND_HANDSHAKE => {
                HandshakeRequest::load(&payload).expect("a handshake request")
            }
            other => panic!("not a handshake request: {other:?}"),
        }
    }

    fn opened(&self) -> Vec<SocketId> {
        let mut ids: Vec<SocketId> = self.held.lock().expect("held").keys().copied().collect();
        ids.sort_by_key(|id| id.get());
        ids
    }
}

impl Dial for HeldDial {
    fn connect(
        &self,
        endpoint: &Endpoint,
        ceiling: InboundCeiling,
        now: Tick,
    ) -> Result<Channel, CloseCause> {
        self.connects.fetch_add(1, Ordering::AcqRel);
        let refusal = self.refusals.lock().expect("refusals").pop_front();
        if let Some((cause, took)) = refusal {
            if let Some(clock) = self.clock.lock().expect("clock").as_ref() {
                clock.set(Tick::new(clock.now().get() + took));
            }
            return Err(cause);
        }
        let open = admit(&self.sockets, endpoint, now, ceiling)?;
        let ends = StreamEnds::open(SEND_CAP);
        if let Some(answer) = self.answers.lock().expect("answers").pop_front() {
            ends.inbound
                .blocking_send(answer)
                .expect("room for the answer");
        }
        self.held.lock().expect("held").insert(
            open.id(),
            Held {
                inbound: ends.inbound.clone(),
                writer: ends.writer_queue,
                _hold: ends.hold,
            },
        );
        Ok(Channel {
            open,
            session: ends.session,
            endpoint: *endpoint,
            gap: None,
        })
    }

    fn retired(&self, id: SocketId) {
        self.held.lock().expect("held").remove(&id);
    }

    fn drive(&self, hub: &Hub, id: SocketId, session: Session) {
        let hub = hub.clone();
        thread::spawn(move || drive_inbound(&hub, id, session));
    }
}

/// A connect that never resolves, counted while it is alive.
struct Stalled {
    alive: Arc<AtomicUsize>,
}

impl Future for Stalled {
    type Output = Result<Channel, CloseCause>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

impl Drop for Stalled {
    fn drop(&mut self) {
        self.alive.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Every other connect never resolves (an onion that never answers); the
/// rest are admitted and never answered (a peer silent after the channel).
struct StallDial {
    held: HeldDial,
    connects: AtomicUsize,
    stalled_alive: Arc<AtomicUsize>,
    all_stall: bool,
}

impl StallDial {
    fn new(sockets: Sockets, all_stall: bool) -> Self {
        Self {
            held: HeldDial::answering(sockets, Vec::new()),
            connects: AtomicUsize::new(0),
            stalled_alive: Arc::new(AtomicUsize::new(0)),
            all_stall,
        }
    }
}

impl Dial for StallDial {
    fn connect(
        &self,
        endpoint: &Endpoint,
        ceiling: InboundCeiling,
        now: Tick,
    ) -> Result<Channel, CloseCause> {
        self.held.connect(endpoint, ceiling, now)
    }

    fn connect_async(
        &self,
        endpoint: &Endpoint,
        ceiling: InboundCeiling,
        now: Tick,
    ) -> ConnectFuture {
        let n = self.connects.fetch_add(1, Ordering::AcqRel);
        if self.all_stall || n.is_multiple_of(2) {
            self.stalled_alive.fetch_add(1, Ordering::AcqRel);
            return Box::pin(Stalled {
                alive: Arc::clone(&self.stalled_alive),
            });
        }
        let result = self.held.connect(endpoint, ceiling, now);
        Box::pin(std::future::ready(result))
    }

    fn retired(&self, id: SocketId) {
        self.held.retired(id);
    }

    fn drive(&self, hub: &Hub, id: SocketId, session: Session) {
        self.held.drive(hub, id, session);
    }
}

fn dialer_on(clock: &ManualClock, sockets: &Sockets, dial: Arc<dyn Dial>) -> (Hub, Arc<Dialer>) {
    let hub = Hub::new(
        sockets.clone(),
        InboundCeiling::Bounded(64),
        Arc::new(|_post| {}),
        Arc::new(clock.clone()),
    );
    hub.install_dial(dial);
    let dialer = Arc::new(Dialer::new(
        hub.clone(),
        RefusedSet::NON_GLOBAL,
        Arc::new(|| {
            Some(SyncPayload {
                current_height: 1,
                cumulative_difficulty: 1,
                cumulative_difficulty_top64: 0,
                top_id: [0; 32],
            })
        }),
    ));
    dialer.set_network_id(NETWORK);
    for (connector, route) in [
        (CLEARNET, Route::Direct),
        (
            TOR,
            Route::Socks(std::net::SocketAddr::from(([127, 0, 0, 1], 9050))),
        ),
    ] {
        assert!(matches!(
            hub.links().publish_usable(connector, route, Tick::new(1)),
            RoutePublish::Installed { .. }
        ));
    }
    (hub, dialer)
}

/// **Stop with B dials in flight on Tor** (the brief's test 6). Two of the
/// four attempts are mid-connect (an onion that never answers), two are
/// mid-handshake (a channel the peer never answers). The loop, waiting on
/// its wake, exits at the bell, with the engine still open; every attempt
/// is cancelled, every connect is dropped, every channel is released, and
/// nothing is left in flight. No dial outlives the stop.
#[test]
fn stop_cancels_every_attempt_in_flight_and_the_loop_exits_at_the_bell() {
    const BOUND: usize = 4;
    let clock = ManualClock::new(Tick::new(1));
    let service = EngineService::start(clock.clone());
    let sockets = Sockets::new();
    let dial = Arc::new(StallDial::new(sockets.clone(), false));
    let (_hub, dialer) = dialer_on(&clock, &sockets, Arc::clone(&dial) as Arc<dyn Dial>);
    dialer.set_in_flight_bound(TOR, BOUND);
    let mut rng = SplitMix64::new(1);
    for onion in onions(BOUND) {
        dialer
            .admit_operator(&onion, Tick::new(1), &mut rng)
            .expect("admitted");
    }
    for n in 0..BOUND {
        assert!(
            matches!(dialer.launch(TOR, &mut rng), Launch::Running(_)),
            "launch {n}"
        );
    }
    wait_until("every attempt reached its stall", || {
        dial.connects.load(Ordering::Acquire) == BOUND && dial.held.opened().len() == BOUND / 2
    });
    assert_eq!(dialer.in_flight(TOR), BOUND);
    assert_eq!(dial.stalled_alive.load(Ordering::Acquire), BOUND / 2);
    assert_eq!(sockets.live(), u64::try_from(BOUND / 2).expect("small"));

    let owner = service
        .handle()
        .register(OwnerClass::Discovery)
        .expect("register");
    let running = Arc::clone(&dialer);
    let (ended_tx, ended_rx) = std::sync::mpsc::channel();
    let loop_thread = thread::spawn(move || {
        running.run(TOR, &owner, &mut SplitMix64::new(2));
        let _sent = ended_tx.send(());
    });
    thread::sleep(Duration::from_millis(50));

    dialer.stop();
    assert!(
        ended_rx.recv_timeout(Duration::from_secs(2)).is_ok(),
        "the loop exits at the bell, not when a dial ends or the engine closes"
    );
    loop_thread.join().expect("the loop thread");
    wait_until(
        "every connect was dropped and every channel released",
        || dial.stalled_alive.load(Ordering::Acquire) == 0 && sockets.live() == 0,
    );
    assert_eq!(dialer.in_flight(TOR), 0, "nothing is left in flight");
    service.close();
}

/// One admitted gray address on a dialer that can dial, then stopped
/// before anything is launched. The held dial would answer; an attempt
/// that opened a socket shows up in `opened`.
fn stopped_after_one_gray(
    seed: u64,
    n: u16,
) -> (Sockets, Arc<HeldDial>, Arc<Dialer>, NetworkAddress) {
    let clock = ManualClock::new(Tick::new(1));
    let sockets = Sockets::new();
    let dial = Arc::new(HeldDial::answering(sockets.clone(), vec![reply(NETWORK)]));
    let (_hub, dialer) = dialer_on(&clock, &sockets, Arc::clone(&dial) as Arc<dyn Dial>);
    let mut rng = SplitMix64::new(seed);
    let address = peer(n);
    dialer
        .admit_operator(&address, Tick::new(1), &mut rng)
        .expect("admitted");
    assert!(dialer.shared().lists.is_gray(&address));
    dialer.stop();
    (sockets, dial, dialer, address)
}

/// The draw stayed seated: still gray, not white, nothing in flight, and
/// the held dial opened no socket.
fn assert_draw_stays_seated(
    sockets: &Sockets,
    dial: &HeldDial,
    dialer: &Dialer,
    address: &NetworkAddress,
) {
    assert_eq!(dialer.in_flight(CLEARNET), 0);
    assert!(
        dialer.shared().lists.is_gray(address),
        "a cancelled draw stays seated"
    );
    // A failed test would cool the seat and step the ladder. A cancel
    // records no outcome, so the draw stays outstanding.
    assert!(!dialer.shared().lists.is_cooling(address));
    assert_eq!(dialer.shared().lists.failed_tests(address), 0);
    assert!(!dialer.shared().lists.is_white(address));
    assert_eq!(dialer.shared().lists.gray_count(CLEARNET), 1);
    assert!(dial.opened().is_empty(), "no socket was opened");
    assert_eq!(sockets.live(), 0);
}

/// **Stop, then launch, with no loop running.** The insert reads the stop
/// flag under the same lock. The begun draw is cancelled with no outcome,
/// so it stays gray, and nothing is spawned.
#[test]
fn a_launch_after_stop_cancels_the_draw_and_opens_nothing() {
    let (sockets, dial, dialer, address) = stopped_after_one_gray(11, 11);
    let mut rng = SplitMix64::new(12);
    assert_eq!(dialer.launch(CLEARNET, &mut rng), Launch::Stopped);
    assert_draw_stays_seated(&sockets, &dial, &dialer, &address);
}

/// **Stop, then wake, with no loop running.** The wake runs on the caller
/// and records nothing: the same cancel as launch, and no socket.
#[test]
fn a_wake_after_stop_records_nothing_and_opens_nothing() {
    let (sockets, dial, dialer, address) = stopped_after_one_gray(13, 13);
    let mut rng = SplitMix64::new(14);
    assert!(!dialer.wake(CLEARNET, &mut rng));
    assert_draw_stays_seated(&sockets, &dial, &dialer, &address);
}

/// **A finished `Keep` not yet applied still counts** (the brief's test 7).
/// Target two, one session kept, bound four, gray over the floor so rule
/// (b) keeps. A `Keep` is launched and its result posted but not applied;
/// the next launches do not keep past the target. Applying everything
/// leaves exactly the target kept.
#[test]
fn a_finished_keep_not_yet_applied_still_counts_toward_the_target() {
    let clock = ManualClock::new(Tick::new(1));
    let sockets = Sockets::new();
    let gray = u16::try_from(shekyl_peerlist::white_diversity_floor() + 12).expect("small");
    let dial = Arc::new(HeldDial::answering(
        sockets.clone(),
        std::iter::repeat_n(reply(NETWORK), usize::from(gray) + 8).collect(),
    ));
    let (_hub, dialer) = dialer_on(&clock, &sockets, Arc::clone(&dial) as Arc<dyn Dial>);
    let mut rng = SplitMix64::new(7);
    dialer.set_in_flight_bound(CLEARNET, 4);
    dialer.set_target(CLEARNET, 2, &mut rng);
    for n in 0..gray {
        dialer
            .admit_operator(&peer(n), Tick::new(1), &mut rng)
            .expect("admitted");
    }
    assert!(dialer.wake(CLEARNET, &mut rng), "the first keep");
    assert_eq!(dialer.kept_sessions(CLEARNET), 1);

    let Launch::Running(id) = dialer.launch(CLEARNET, &mut rng) else {
        panic!("rule (b) keeps the second");
    };
    dialer.wait_posted(id);
    assert!(dialer.completed(id), "the result is posted, not applied");
    assert_eq!(
        dialer.kept_sessions(CLEARNET),
        2,
        "the unapplied keep still counts"
    );
    // The remaining slots launch, but none of them is a keep.
    for _ in 0..3 {
        if let Launch::Running(next) = dialer.launch(CLEARNET, &mut rng) {
            dialer.wait_posted(next);
        }
    }
    dialer.apply_completions(CLEARNET, &mut rng);
    assert_eq!(dialer.in_flight(CLEARNET), 0);
    assert_eq!(
        dialer.kept_sessions(CLEARNET),
        2,
        "exactly the target is kept"
    );
}

/// **The nonce stays in flight until the result is applied** (the brief's
/// test 8). With the handshake answered and its result posted but not
/// applied, an inbound handshake carrying the request's nonce is a
/// self-connection: the nonce is still in the set. Once applied, it is not.
#[test]
fn the_nonce_stays_in_flight_until_the_result_is_applied() {
    let clock = ManualClock::new(Tick::new(1));
    let sockets = Sockets::new();
    let dial = Arc::new(HeldDial::answering(
        sockets.clone(),
        vec![reply(NETWORK), reply(NETWORK)],
    ));
    let (_hub, dialer) = dialer_on(&clock, &sockets, Arc::clone(&dial) as Arc<dyn Dial>);
    let mut rng = SplitMix64::new(8);
    for n in 0..2 {
        dialer
            .admit_operator(&peer(100 + n), Tick::new(1), &mut rng)
            .expect("admitted");
    }

    let Launch::Running(id) = dialer.launch(CLEARNET, &mut rng) else {
        panic!("a draw");
    };
    dialer.wait_posted(id);
    let socket = dial.opened()[0];
    let nonce = dial.request(socket).nonce;
    assert!(
        dialer.take_nonce(CLEARNET, &nonce),
        "posted but not applied: the nonce is still in flight"
    );
    dialer.apply_completions(CLEARNET, &mut rng);

    // A second attempt: once its result is applied, its nonce is gone.
    let Launch::Running(id) = dialer.launch(CLEARNET, &mut rng) else {
        panic!("a second draw");
    };
    dialer.wait_posted(id);
    let socket = *dial.opened().last().expect("the second channel");
    let nonce = dial.request(socket).nonce;
    dialer.apply_completions(CLEARNET, &mut rng);
    assert!(
        !dialer.take_nonce(CLEARNET, &nonce),
        "applied: the nonce left the set"
    );
}

/// **A close between the response and adoption** (the brief's test 9). The
/// handshake is answered and posted; the peer closes before the loop
/// applies it. The attempt ends as a failure with the peer's cause, and
/// nothing is kept: no kept session, no board row, the channel released.
#[test]
fn a_close_between_the_response_and_adoption_keeps_nothing() {
    let clock = ManualClock::new(Tick::new(1));
    let sockets = Sockets::new();
    let dial = Arc::new(HeldDial::answering(sockets.clone(), vec![reply(NETWORK)]));
    let (hub, dialer) = dialer_on(&clock, &sockets, Arc::clone(&dial) as Arc<dyn Dial>);
    let mut rng = SplitMix64::new(9);
    dialer
        .admit_operator(&peer(200), Tick::new(1), &mut rng)
        .expect("admitted");

    let Launch::Running(id) = dialer.launch(CLEARNET, &mut rng) else {
        panic!("a draw");
    };
    dialer.wait_posted(id);
    let socket = dial.opened()[0];
    dial.close_as_peer(socket);
    let applied = dialer.apply_completions(CLEARNET, &mut rng);
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].kept, None, "nothing is kept");
    assert_eq!(dialer.kept_sessions(CLEARNET), 0);
    assert!(hub.board().rows().is_empty(), "no board row");
    assert!(!dialer.shared().lists.is_white(&peer(200)), "not white");
    wait_until("the channel was released", || sockets.live() == 0);
}

/// Count the wakes the loop ran and the dials it launched, from its debug
/// log: every wake either launches (`aim`) or plans nothing.
fn wakes_and_launches(text: &str) -> (usize, usize) {
    let launches = text.matches(" aim Keep").count() + text.matches(" aim Confirm").count();
    let idle = text.matches("wake: no rule applies").count();
    (launches + idle, launches)
}

/// Run the Tor loop for `steps` wake intervals with every dial stalled, at
/// `bound`. Returns the wakes and launches it logged, and the dials it
/// had in flight at the end.
fn run_stalled(bound: usize, steps: u64) -> (usize, usize, usize) {
    let clock = ManualClock::new(Tick::new(1_000_000_000));
    let service = EngineService::start(clock.clone());
    let sockets = Sockets::new();
    let dial = Arc::new(StallDial::new(sockets.clone(), true));
    let (_hub, dialer) = dialer_on(&clock, &sockets, Arc::clone(&dial) as Arc<dyn Dial>);
    dialer.set_in_flight_bound(TOR, bound);
    let mut rng = SplitMix64::new(3);
    for onion in onions(bound + 4) {
        dialer
            .admit_operator(&onion, Tick::new(1), &mut rng)
            .expect("admitted");
    }
    let owner = service
        .handle()
        .register(OwnerClass::Discovery)
        .expect("register");
    let running = Arc::clone(&dialer);
    let loop_thread = thread::spawn(move || {
        log_text(tracing::Level::DEBUG, || {
            running.run(TOR, &owner, &mut SplitMix64::new(4));
        })
    });
    // Let the loop arm its first wake at the start time before the clock
    // moves, so every interval holds exactly one due wake.
    thread::sleep(Duration::from_millis(200));
    let start = clock.now().get();
    for step in 1..=steps {
        clock.set(Tick::new(
            start + step * (WAKE_BASE_NANOS + WAKE_JITTER_NANOS + 1),
        ));
        // The engine parks until a command when the manual clock is not
        // yet due; a throwaway registration nudges it.
        drop(service.handle().register(OwnerClass::Interim));
        thread::sleep(Duration::from_millis(60));
    }
    let in_flight = dialer.in_flight(TOR);
    dialer.stop();
    let text = loop_thread.join().expect("the loop thread");
    service.close();
    let (wakes, launches) = wakes_and_launches(&text);
    (wakes, launches, in_flight)
}

/// **With bound B on Tor and every draw a dead onion, the connector keeps
/// B dials in flight and its wake rate is unchanged** (the brief's test
/// 1). Every connect stalls. Over the same number of wake intervals, at
/// bound one and at bound four, the loop runs one wake per interval: it
/// launches up to its bound and plans nothing on the other wakes. A loop
/// that waited on its dial would run one wake in all.
#[test]
fn stalled_dials_hold_the_bound_in_flight_and_the_wake_rate_is_unchanged() {
    const STEPS: u64 = 8;
    let (wakes_one, launches_one, in_flight_one) = run_stalled(1, STEPS);
    let (wakes_four, launches_four, in_flight_four) = run_stalled(4, STEPS);
    assert_eq!((launches_one, in_flight_one), (1, 1), "bound one");
    assert_eq!((launches_four, in_flight_four), (4, 4), "bound four");
    let steps = usize::try_from(STEPS).expect("small");
    assert_eq!(wakes_one, steps, "one wake per interval at bound one");
    assert_eq!(wakes_four, steps, "one wake per interval at bound four");
}

/// **A due `Keep` retry does not take the connector past its target**
/// (#1190's item 4 under the gray lifecycle's retries). Tor, target two,
/// bound two, gray at the floor so the planner keeps. The first `Keep` is
/// refused with `0xF0`, which is worth a retry: its test waits. Two more
/// wakes fill the target. When the wait ends, the retry must not keep a
/// third session: a `Keep` test holds its target slot from its draw to its
/// outcome, waits included, as a pending `Keep` does.
#[test]
fn a_due_keep_retry_does_not_take_the_connector_past_its_target() {
    const TARGET: usize = 2;
    let clock = ManualClock::new(Tick::new(1));
    let sockets = Sockets::new();
    let gray = onions(shekyl_peerlist::white_diversity_floor() + 4);
    let dial = Arc::new(HeldDial::answering(
        sockets.clone(),
        std::iter::repeat_n(reply(NETWORK), gray.len()).collect(),
    ));
    dial.refuse_after(&clock, shekyl_tor::refused(0xF0), Duration::ZERO);
    let (_hub, dialer) = dialer_on(&clock, &sockets, Arc::clone(&dial) as Arc<dyn Dial>);
    let mut rng = SplitMix64::new(31);
    dialer.set_in_flight_bound(TOR, 2);
    dialer.set_target(TOR, TARGET, &mut rng);
    for onion in &gray {
        dialer
            .admit_operator(onion, Tick::new(1), &mut rng)
            .expect("admitted");
    }

    // The first keep is refused, worth a retry: its test waits.
    assert!(dialer.wake(TOR, &mut rng), "the first draw");
    assert_eq!(dialer.in_flight(TOR), 0, "the wait holds no in-flight slot");
    // The planner fills the target around the waiting test.
    for _ in 0..4 {
        dialer.wake(TOR, &mut rng);
    }
    assert!(dialer.kept_sessions(TOR) <= TARGET);

    // The retry's wait ends; every wake after it stays within the target.
    clock.set(Tick::new(clock.now().get() + 60 * 1_000_000_000));
    for _ in 0..4 {
        dialer.wake(TOR, &mut rng);
    }
    let kept_sessions = dialer
        .hub()
        .board()
        .rows()
        .iter()
        .filter(|row| matches!(row.endpoint(), Endpoint::Tor { .. }))
        .count();
    assert!(
        kept_sessions <= TARGET,
        "kept {kept_sessions} Tor sessions against a target of {TARGET}"
    );
}

/// The managed Tor's window in these tests: the daemon's `SocksTimeout`,
/// 105 s (`shekyl_ffi::tor_link::TOR_SOCKS_TIMEOUT`).
const TOR_WINDOW: Duration = Duration::from_secs(105);

/// One Tor attempt at one gray onion, refused with `cause` after `took`,
/// on a dialer that knows the Tor window. Returns the dialer, the dial and
/// the onion, after the attempt's result is applied.
fn one_tor_attempt(seed: u64, cause: CloseCause, took: Duration) -> TorAttempt {
    let clock = ManualClock::new(Tick::new(1_000_000_000));
    let sockets = Sockets::new();
    let dial = Arc::new(HeldDial::answering(sockets.clone(), Vec::new()));
    dial.refuse_after(&clock, cause, took);
    let (_hub, dialer) = dialer_on(&clock, &sockets, Arc::clone(&dial) as Arc<dyn Dial>);
    dialer.set_tor_window(Some(TOR_WINDOW));
    let mut rng = SplitMix64::new(seed);
    let onion = onions(1).remove(0);
    dialer
        .admit_operator(&onion, Tick::new(1), &mut rng)
        .expect("admitted");
    dialer.wake(TOR, &mut rng);
    assert_eq!(dial.connects.load(Ordering::Acquire), 1, "one attempt");
    TorAttempt {
        clock,
        dial,
        dialer,
        onion,
        rng,
    }
}

struct TorAttempt {
    clock: ManualClock,
    dial: Arc<HeldDial>,
    dialer: Arc<Dialer>,
    onion: NetworkAddress,
    rng: SplitMix64,
}

impl TorAttempt {
    /// The test ended on its first attempt: the onion cools, its ladder
    /// stepped once, and no wake after any retry wait dials it again.
    fn assert_final(mut self) {
        assert!(
            self.dialer.shared().lists.is_cooling(&self.onion),
            "the onion cools"
        );
        assert_eq!(self.dialer.shared().lists.failed_tests(&self.onion), 1);
        self.wake_after_every_wait();
        assert_eq!(
            self.dial.connects.load(Ordering::Acquire),
            1,
            "no further attempt in its test"
        );
    }

    /// The test waits for its next attempt: the onion is not cooling, its
    /// ladder has not stepped, and the wake after the wait dials it again.
    fn assert_retries(mut self) {
        assert!(
            !self.dialer.shared().lists.is_cooling(&self.onion),
            "a deferred attempt records no outcome"
        );
        assert_eq!(self.dialer.shared().lists.failed_tests(&self.onion), 0);
        self.wake_after_every_wait();
        assert_eq!(
            self.dial.connects.load(Ordering::Acquire),
            2,
            "the second attempt of the test"
        );
    }

    /// Move the clock past the second attempt's longest wait (10 s) and
    /// wake once. The second attempt, if the test has one, is refused at
    /// once.
    fn wake_after_every_wait(&mut self) {
        self.clock
            .set(Tick::new(self.clock.now().get() + 11 * 1_000_000_000));
        self.dial
            .refuse_after(&self.clock, shekyl_tor::refused(0xF0), Duration::ZERO);
        self.dialer.wake(TOR, &mut self.rng);
    }
}

/// **A `0x06` at Tor's window cools after one attempt** (revision 4, test
/// 12). Tor has already retried introduction points and descriptor
/// fetches inside the window; a second attempt would spend another
/// window on a destination Tor could not reach.
#[test]
fn a_ttl_expiry_at_the_tor_window_cools_after_one_attempt() {
    one_tor_attempt(41, shekyl_tor::refused(0x06), TOR_WINDOW).assert_final();
}

/// **An early `0x06` retries** (test 13): inside the window it is the
/// service's own connect timing out, or a circuit that failed fast, and
/// the test keeps its attempts.
#[test]
fn an_early_ttl_expiry_keeps_its_retries() {
    one_tor_attempt(42, shekyl_tor::refused(0x06), Duration::from_secs(30)).assert_retries();
}

/// **`0xF0` retries, even past the window** (test 14). A descriptor not
/// found is not a timeout: the window does not read it.
#[test]
fn a_descriptor_not_found_keeps_its_retries_past_the_window() {
    one_tor_attempt(
        43,
        shekyl_tor::refused(0xF0),
        TOR_WINDOW + Duration::from_secs(5),
    )
    .assert_retries();
}

/// **Our own timeout at or past the window is final** (test 15): the dial
/// deadline (120 s) is past the window, so a dial that ran to it ran a
/// whole window. A gap timeout inside the window keeps its retries.
#[test]
fn a_transport_timeout_past_the_window_is_final_and_one_inside_retries() {
    let timeout = CloseCause::new(CloseKind::TransportTimeout);
    one_tor_attempt(44, timeout, Duration::from_secs(120)).assert_final();
    one_tor_attempt(45, timeout, Duration::from_secs(20)).assert_retries();
}

/// **The tally counts a failed attempt deferred for a retry** (test 16).
/// The attempt ended without a stream whether or not its test goes on.
#[test]
fn the_tally_counts_a_failed_attempt_deferred_for_a_retry() {
    let attempt = one_tor_attempt(46, shekyl_tor::refused(0xF0), Duration::ZERO);
    assert_eq!(attempt.dialer.tor_link_tally().unopened, 1);
    attempt.assert_retries();
}
