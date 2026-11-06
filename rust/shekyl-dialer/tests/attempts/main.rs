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

#[path = "../support/life.rs"]
mod life;
#[path = "../support/log_capture.rs"]
mod log_capture;
#[path = "../support/rig.rs"]
mod rig;
#[path = "../support/tables.rs"]
mod tables;

mod judge;
mod white;

use log_capture::log_text;
use rig::{wait_until, Answer, Rig, NETWORK};
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use shekyl_dialer::Launch;
use shekyl_draw_rng::SplitMix64;
use shekyl_p2p_session::{Endpoint, NonceTake};
use shekyl_peerlist::{ConnectorId, NetworkAddress, Tick};
use shekyl_timing_engine::{Clock, ManualClock, OwnerClass};
use shekyl_transport_layer::{DialEnd, Direction};

const CLEARNET: ConnectorId = ConnectorId::Clearnet;
const TOR: ConnectorId = ConnectorId::Tor;

/// The wake spacing this file's connector dials at: its dial profile's.
const WAKE_BASE_NANOS: u64 = shekyl_peerlist::dial_profile(ConnectorId::Tor)
    .wake
    .base_nanos;
const WAKE_JITTER_NANOS: u64 = shekyl_peerlist::dial_profile(ConnectorId::Tor)
    .wake
    .jitter_nanos;

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
    rig::reply(network_id, Vec::new())
}

/// A rig on `clock` whose peer answers every unqueued dial with `answer`.
fn rig_answering(clock: &ManualClock, answer: Answer) -> Rig {
    let rig = Rig::on(clock);
    rig.peer.answer_unqueued(answer);
    rig
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
    let rig = Rig::on(&clock);
    // Every other connect never resolves (an onion that never answers);
    // the rest are admitted and never answered (a peer silent after the
    // channel).
    for n in 0..BOUND {
        rig.peer.answer_next(if n % 2 == 0 {
            Answer::Stall
        } else {
            Answer::Connect
        });
    }
    let dialer = &rig.dialer;
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
        rig.peer.connects() == BOUND && rig.opened().len() == BOUND / 2
    });
    assert_eq!(dialer.in_flight(TOR), BOUND);
    assert_eq!(rig.peer.stalled_alive.load(Ordering::Acquire), BOUND / 2);
    assert_eq!(rig.sockets.live(), u64::try_from(BOUND / 2).expect("small"));

    let owner = rig
        .timing
        .register(OwnerClass::Discovery)
        .expect("register");
    let running = Arc::clone(dialer);
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
        || rig.peer.stalled_alive.load(Ordering::Acquire) == 0 && rig.sockets.live() == 0,
    );
    assert_eq!(dialer.in_flight(TOR), 0, "nothing is left in flight");
    rig.close_engine();
}

/// **Stop joins the loops between the cancel and the file** (revision 4,
/// item 3: flag, bell, cancel, join both loops, write the file). A Tor
/// loop runs with one attempt stalled in flight. The join `stop_joining`
/// runs finds nothing in flight and no file yet, and joins the loop; the
/// file is written after it, with the cancelled draw still seated.
#[test]
fn stop_joins_the_loops_after_the_cancel_and_before_the_file() {
    let clock = ManualClock::new(Tick::new(1));
    let rig = rig_answering(&clock, Answer::Stall);
    let dialer = &rig.dialer;
    let dir = tempfile::tempdir().expect("a directory");
    let path = dir.path().join("p2pstate.bin");
    let mut rng = SplitMix64::new(21);
    assert_eq!(
        dialer
            .open_address_file(path.clone(), &mut rng)
            .expect("a first start"),
        0
    );
    let onion = onions(1).remove(0);
    dialer
        .admit_operator(&onion, Tick::new(1), &mut rng)
        .expect("admitted");
    assert!(matches!(dialer.launch(TOR, &mut rng), Launch::Running(_)));
    wait_until("the attempt reached its stall", || {
        rig.peer.stalled_alive.load(Ordering::Acquire) == 1
    });

    let owner = rig
        .timing
        .register(OwnerClass::Discovery)
        .expect("register");
    let running = Arc::clone(dialer);
    let loop_thread = thread::spawn(move || {
        running.run(TOR, &owner, &mut SplitMix64::new(22));
    });
    thread::sleep(Duration::from_millis(50));

    let mut joined = false;
    dialer.stop_joining(|| {
        assert_eq!(dialer.in_flight(TOR), 0, "the cancel came first");
        assert!(!path.exists(), "the file is written after the join");
        loop_thread.join().expect("the loop thread");
        joined = true;
    });
    assert!(joined);
    assert_eq!(
        shekyl_dialer::AddressStore::new(path)
            .load()
            .expect("written"),
        vec![onion],
        "the cancelled draw is written, still seated"
    );
    rig.close_engine();
}

/// One admitted gray address on a dialer that can dial, then stopped
/// before anything is launched. The peer would answer; an attempt that
/// opened a socket shows up in the rig's `opened`.
fn stopped_after_one_gray(seed: u64, n: u16) -> (Rig, NetworkAddress) {
    let rig = Rig::new();
    rig.peer.answer_next(Answer::Answered(reply(NETWORK)));
    let mut rng = SplitMix64::new(seed);
    let address = peer(n);
    rig.dialer
        .admit_operator(&address, Tick::new(1), &mut rng)
        .expect("admitted");
    assert!(rig.dialer.shared().lists.is_gray(&address));
    rig.dialer.stop();
    (rig, address)
}

/// The draw stayed seated: still gray, not white, nothing in flight, and
/// no socket was opened.
fn assert_draw_stays_seated(rig: &Rig, address: &NetworkAddress) {
    let dialer = &rig.dialer;
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
    assert!(rig.opened().is_empty(), "no socket was opened");
    assert_eq!(rig.sockets.live(), 0);
}

/// **Stop, then launch, with no loop running.** The insert reads the stop
/// flag under the same lock. The begun draw is cancelled with no outcome,
/// so it stays gray, and nothing is spawned.
#[test]
fn a_launch_after_stop_cancels_the_draw_and_opens_nothing() {
    let (rig, address) = stopped_after_one_gray(11, 11);
    let mut rng = SplitMix64::new(12);
    assert_eq!(rig.dialer.launch(CLEARNET, &mut rng), Launch::Stopped);
    assert_draw_stays_seated(&rig, &address);
}

/// **Stop, then wake, with no loop running.** The wake runs on the caller
/// and records nothing: the same cancel as launch, and no socket.
#[test]
fn a_wake_after_stop_records_nothing_and_opens_nothing() {
    let (rig, address) = stopped_after_one_gray(13, 13);
    let mut rng = SplitMix64::new(14);
    assert!(!rig.dialer.wake(CLEARNET, &mut rng));
    assert_draw_stays_seated(&rig, &address);
}

/// **A finished `Keep` not yet applied still counts** (the brief's test 7).
/// Target two, one session kept, bound four, gray over the floor so rule
/// (b) keeps. A `Keep` is launched and its result posted but not applied;
/// the next launches do not keep past the target. Applying everything
/// leaves exactly the target kept.
#[test]
fn a_finished_keep_not_yet_applied_still_counts_toward_the_target() {
    let gray = u16::try_from(shekyl_peerlist::white_diversity_floor() + 12).expect("small");
    let rig = rig_answering(
        &ManualClock::new(Tick::new(1)),
        Answer::Answered(reply(NETWORK)),
    );
    let dialer = &rig.dialer;
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

/// **The nonce stays in flight until the handshake resolves** (the brief's
/// test 8, on the session layer's set). While the request is out and
/// unanswered, an inbound handshake carrying its nonce is a
/// self-connection: the nonce is in the set. Once the layer has resolved
/// the handshake and the result is applied, it is not. *Records-was (to
/// the cutover): the dialer held the set, and the nonce stayed in flight
/// from the posted result to its application.*
#[test]
fn the_nonce_stays_in_flight_until_the_handshake_resolves() {
    let rig = Rig::new();
    let dialer = &rig.dialer;
    let mut rng = SplitMix64::new(8);
    for n in 0..2 {
        dialer
            .admit_operator(&peer(100 + n), Tick::new(1), &mut rng)
            .expect("admitted");
    }

    // The first dial is connected and left unanswered.
    rig.peer.answer_next(Answer::Connect);
    let Launch::Running(id) = dialer.launch(CLEARNET, &mut rng) else {
        panic!("a draw");
    };
    wait_until("the channel opened", || rig.opened().len() == 1);
    let socket = rig.opened()[0];
    let nonce = rig.request(socket).nonce;
    assert_eq!(
        rig.layer.nonces().take(CLEARNET, &nonce),
        NonceTake::SelfConnection,
        "unanswered: the nonce is in flight"
    );
    rig.answer(socket, reply(NETWORK));
    dialer.wait_posted(id);
    dialer.apply_completions(CLEARNET, &mut rng);

    // A second attempt, answered: once the layer resolved it, its nonce
    // is gone. The request is read before the peer answers, as a peer
    // answers only what it has read: an answer injected at connect can
    // resolve the dial and discard the unsent request first.
    rig.peer.answer_next(Answer::Connect);
    let Launch::Running(id) = dialer.launch(CLEARNET, &mut rng) else {
        panic!("a second draw");
    };
    wait_until("the second channel opened", || rig.opened().len() == 2);
    let socket = rig.opened()[1];
    let nonce = rig.request(socket).nonce;
    rig.answer(socket, reply(NETWORK));
    dialer.wait_posted(id);
    dialer.apply_completions(CLEARNET, &mut rng);
    assert_eq!(
        rig.layer.nonces().take(CLEARNET, &nonce),
        NonceTake::NotOurs,
        "resolved: the nonce left the set"
    );
}

/// **A close between the response and adoption** (the brief's test 9). The
/// handshake is answered and posted; the peer closes before the loop
/// applies it. The attempt ends as a failure with the peer's cause, and
/// nothing is kept: no kept session, no board row, the channel released.
#[test]
fn a_close_between_the_response_and_adoption_keeps_nothing() {
    let rig = Rig::new();
    rig.peer.answer_next(Answer::Answered(reply(NETWORK)));
    let dialer = &rig.dialer;
    let mut rng = SplitMix64::new(9);
    dialer
        .admit_operator(&peer(200), Tick::new(1), &mut rng)
        .expect("admitted");

    let Launch::Running(id) = dialer.launch(CLEARNET, &mut rng) else {
        panic!("a draw");
    };
    dialer.wait_posted(id);
    let socket = rig.opened()[0];
    rig.close_as_peer(socket);
    let applied = dialer.apply_completions(CLEARNET, &mut rng);
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].kept, None, "nothing is kept");
    assert_eq!(dialer.kept_sessions(CLEARNET), 0);
    rig.wait_closed(socket);
    assert!(rig.layer.board().is_empty(), "no board row");
    assert!(!dialer.shared().lists.is_white(&peer(200)), "not white");
    wait_until("the channel was released", || rig.sockets.live() == 0);
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
    let rig = rig_answering(&clock, Answer::Stall);
    let dialer = &rig.dialer;
    dialer.set_in_flight_bound(TOR, bound);
    let mut rng = SplitMix64::new(3);
    for onion in onions(bound + 4) {
        dialer
            .admit_operator(&onion, Tick::new(1), &mut rng)
            .expect("admitted");
    }
    let owner = rig
        .timing
        .register(OwnerClass::Discovery)
        .expect("register");
    let running = Arc::clone(dialer);
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
        drop(rig.timing.register(OwnerClass::Interim));
        thread::sleep(Duration::from_millis(60));
    }
    let in_flight = dialer.in_flight(TOR);
    dialer.stop();
    let text = loop_thread.join().expect("the loop thread");
    rig.close_engine();
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
    let gray = onions(shekyl_peerlist::white_diversity_floor() + 4);
    let rig = rig_answering(&clock, Answer::Answered(reply(NETWORK)));
    rig.peer
        .refuse_after(shekyl_tor::reply_end(0xF0), Duration::ZERO);
    let dialer = &rig.dialer;
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
    let kept_sessions = rig
        .layer
        .board()
        .established_sessions(TOR, Direction::Outbound);
    assert!(
        kept_sessions <= TARGET,
        "kept {kept_sessions} Tor sessions against a target of {TARGET}"
    );
}

/// The window the dialer reads in these tests: the earliest the daemon's
/// 105 s `SocksTimeout` can expire, since Tor counts a stream's age in
/// whole seconds (`shekyl_ffi::tor_link::TOR_SOCKS_TIMEOUT.earliest_expiry()`).
const TOR_WINDOW: Duration = Duration::from_secs(104);

/// One Tor attempt at one gray onion, refused with `cause` after `took`,
/// on a dialer that knows the Tor window. Returns the dialer, the dial and
/// the onion, after the attempt's result is applied.
fn one_tor_attempt(seed: u64, cause: DialEnd, took: Duration) -> TorAttempt {
    one_tor_attempt_under(seed, cause, took, Some(TOR_WINDOW))
}

/// [`one_tor_attempt`], with `window` the window the Tor connector
/// published: `None` for an operator's Tor, whose timeout is unknown.
fn one_tor_attempt_under(
    seed: u64,
    cause: DialEnd,
    took: Duration,
    window: Option<Duration>,
) -> TorAttempt {
    let clock = ManualClock::new(Tick::new(1_000_000_000));
    let rig = Rig::on(&clock);
    let dialer = &rig.dialer;
    dialer.set_window(TOR, window);
    // The link works: an inbound Tor session receives throughout, so the
    // judge counts the attempt's failure once its bracket closes.
    let mut held = rig.accept(Endpoint::TorInbound);
    rig.establish_inbound(&mut held);
    rig.peer.reset_connects();
    life::Life::install(dialer, &clock).keep_alive();
    rig.peer.refuse_after(cause, took);
    let mut rng = SplitMix64::new(seed);
    let onion = onions(1).remove(0);
    dialer
        .admit_operator(&onion, Tick::new(1), &mut rng)
        .expect("admitted");
    dialer.wake(TOR, &mut rng);
    assert_eq!(rig.peer.connects(), 1, "one attempt");
    TorAttempt {
        rig,
        onion,
        rng,
        _held: held,
    }
}

struct TorAttempt {
    rig: Rig,
    onion: NetworkAddress,
    rng: SplitMix64,
    /// The inbound session's far side, open for the test.
    _held: shekyl_p2p_session::harness::Wire,
}

impl TorAttempt {
    /// The test ended on its first attempt: once its bracket closes the
    /// onion cools, its ladder stepped once, and no wake after any retry
    /// wait dials it again.
    fn assert_final(mut self) {
        let (clock, dialer) = (self.rig.clock.clone(), Arc::clone(&self.rig.dialer));
        assert_eq!(
            dialer.pending_verdicts(TOR),
            1,
            "the verdict waits for its bracket"
        );
        // A wake inside the bracket sees the live link and counts it; the
        // rest of the bracket then passes.
        let bracket = shekyl_peerlist::dial_profile(TOR).judging.bracket_nanos;
        clock.set(Tick::new(clock.now().get() + 1_000_000_000));
        dialer.apply_verdicts(&mut self.rng);
        clock.set(Tick::new(clock.now().get() + bracket));
        dialer.apply_verdicts(&mut self.rng);
        assert!(
            dialer.shared().lists.is_cooling(&self.onion),
            "the onion cools"
        );
        assert_eq!(dialer.shared().lists.failed_tests(&self.onion), 1);
        self.wake_after_every_wait();
        assert_eq!(
            self.rig.peer.connects(),
            1,
            "no further attempt in its test"
        );
    }

    /// The test waits for its next attempt: the onion is not cooling, its
    /// ladder has not stepped, and the wake after the wait dials it again.
    fn assert_retries(mut self) {
        let dialer = Arc::clone(&self.rig.dialer);
        assert!(
            !dialer.shared().lists.is_cooling(&self.onion),
            "a deferred attempt records no outcome"
        );
        assert_eq!(dialer.pending_verdicts(TOR), 0, "nor a verdict");
        assert_eq!(dialer.shared().lists.failed_tests(&self.onion), 0);
        self.wake_after_every_wait();
        assert_eq!(
            self.rig.peer.connects(),
            2,
            "the second attempt of the test"
        );
    }

    /// Move the clock past the second attempt's longest wait (10 s) and
    /// wake once. The second attempt, if the test has one, is refused at
    /// once.
    fn wake_after_every_wait(&mut self) {
        let clock = &self.rig.clock;
        clock.set(Tick::new(clock.now().get() + 11 * 1_000_000_000));
        self.rig
            .peer
            .refuse_after(shekyl_tor::reply_end(0xF0), Duration::ZERO);
        self.rig.dialer.wake(TOR, &mut self.rng);
    }
}

/// **A `0x06` at Tor's window cools after one attempt** (revision 4, test
/// 12). Tor has already retried introduction points and descriptor
/// fetches inside the window; a second attempt would spend another
/// window on a destination Tor could not reach. At the window's earliest
/// expiry, and at 104.97 s, where the floor device saw a 105 s timeout's
/// `0x06` arrive (2026-10-26).
#[test]
fn a_ttl_expiry_at_the_tor_window_cools_after_one_attempt() {
    one_tor_attempt(41, shekyl_tor::reply_end(0x06), TOR_WINDOW).assert_final();
    one_tor_attempt(
        48,
        shekyl_tor::reply_end(0x06),
        Duration::from_millis(104_970),
    )
    .assert_final();
}

/// **An early `0x06` retries** (test 13): inside the window it is the
/// service's own connect timing out, or a circuit that failed fast, and
/// the test keeps its attempts.
#[test]
fn an_early_ttl_expiry_keeps_its_retries() {
    one_tor_attempt(42, shekyl_tor::reply_end(0x06), Duration::from_secs(30)).assert_retries();
}

/// **An early `0xF0` retries** (test 14): a descriptor not found on this
/// try, inside the window.
#[test]
fn an_early_descriptor_not_found_keeps_its_retries() {
    one_tor_attempt(43, shekyl_tor::reply_end(0xF0), Duration::from_secs(5)).assert_retries();
}

/// **An `0xF0` at the window is final** (the short floor series,
/// 2026-10-26: nine `0xF0` at 104 to 110 s were retried). With
/// `ExtendedErrors` on, Tor answers an expired onion stream with the code
/// it recorded on it, `0xF0` after a descriptor fetch came back not found
/// and Tor retried at another directory: Tor's own timeout, after its own
/// retries. The other onion codes Tor records on a stream likewise.
#[test]
fn an_onion_code_at_the_window_is_final() {
    for (seed, reply) in [(58, 0xF0), (59, 0xF2), (60, 0xF3), (61, 0xF7)] {
        one_tor_attempt(
            seed,
            shekyl_tor::reply_end(reply),
            Duration::from_millis(104_740),
        )
        .assert_final();
    }
}

/// **Our own timeout at or past the window is final** (test 15): the dial
/// deadline (120 s) is past the window, so a dial that ran to it ran a
/// whole window. A gap timeout inside the window keeps its retries.
#[test]
fn a_transport_timeout_past_the_window_is_final_and_one_inside_retries() {
    let timeout = shekyl_tor::Observed::Deadline.end();
    one_tor_attempt(44, timeout, Duration::from_secs(120)).assert_final();
    one_tor_attempt(45, timeout, Duration::from_secs(20)).assert_retries();
}

/// **The tally counts a failed attempt deferred for a retry** (test 16).
/// The attempt ended without a stream whether or not its test goes on.
#[test]
fn the_tally_counts_a_failed_attempt_deferred_for_a_retry() {
    let attempt = one_tor_attempt(46, shekyl_tor::reply_end(0xF0), Duration::ZERO);
    assert_eq!(attempt.rig.dialer.tor_link_tally().unopened, 1);
    attempt.assert_retries();
}

/// **An attempt's place against the window is its own** (Copilot's review
/// of `cbdb91d03`). An `0x06` at 103 s, inside the window, is posted and
/// then waits 5 s in the completion queue before the loop applies it. The
/// attempt ran 103 s, timed inside its task, so its test retries; measured
/// to the application it would read 108 s and cool.
#[test]
fn a_timeout_inside_the_window_retries_however_late_it_is_applied() {
    let clock = ManualClock::new(Tick::new(1_000_000_000));
    let rig = Rig::on(&clock);
    rig.peer
        .refuse_after(shekyl_tor::reply_end(0x06), Duration::from_secs(103));
    let dialer = &rig.dialer;
    dialer.set_window(TOR, Some(TOR_WINDOW));
    let mut rng = SplitMix64::new(47);
    let onion = onions(1).remove(0);
    dialer
        .admit_operator(&onion, Tick::new(1), &mut rng)
        .expect("admitted");
    let Launch::Running(id) = dialer.launch(TOR, &mut rng) else {
        panic!("a draw");
    };
    dialer.wait_posted(id);
    clock.set(Tick::new(clock.now().get() + 5 * 1_000_000_000));
    dialer.apply_completions(TOR, &mut rng);
    assert!(
        !dialer.shared().lists.is_cooling(&onion),
        "the queue's wait is not the attempt's"
    );
    assert_eq!(dialer.shared().lists.failed_tests(&onion), 0);
}

/// **With no window published, a full-window timeout retries as before**
/// (the dial profile brief, test 3). An operator's Tor publishes none: its
/// `SocksTimeout` is unknown, so even a `0x06` at 110 s keeps its retries.
#[test]
fn with_no_window_published_a_tor_timeout_keeps_its_retries() {
    one_tor_attempt_under(
        66,
        shekyl_tor::reply_end(0x06),
        Duration::from_secs(110),
        None,
    )
    .assert_retries();
}
