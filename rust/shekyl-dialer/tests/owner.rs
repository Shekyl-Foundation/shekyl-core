// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The peers owner's dial, over the session layer on its loopback
//! connector (dialer brief, "The dial" and "`DialOutcome`";
//! `P2P_3_REMNANT_CUTOVER_BRIEF.md` §2.1).
//!
//! The test plays the peer: it reads the handshake request off the dialed
//! channel's far side, injects the response, and reads what the other
//! owners were told. The dialer runs its dial on its own thread, as in the
//! daemon; the session layer resolves the handshake and hands the dialer
//! the outcome.
//!
//! *Records-was (to the remnant cutover): these tests read the seam's
//! posts and drove the C++ strand's arming of the handler. The strand, the
//! posts and the gap sender's test are the session layer's now
//! (`shekyl-p2p-session/tests/sessions.rs`); what stays here is what the
//! peers owner does with each outcome.*

#[path = "support/log_capture.rs"]
mod log_capture;
#[path = "support/rig.rs"]
mod rig;
#[path = "support/tables.rs"]
mod tables;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use log_capture::log_text;
use rig::{peer, reply, reply_at, wait_until, Answer, Rig, Told, NETWORK};
use shekyl_dialer::{session_of, DialAim, TorLinkTally};
use shekyl_draw_rng::SplitMix64;
use shekyl_onion_v3::v3_onion_hostname;
use shekyl_p2p_session::harness::new_transactions;
use shekyl_p2p_session::ClaimCarrier;
use shekyl_peerlist::{ConnectorId, Direction, NetworkAddress, Tick};
use shekyl_timing_engine::{Clock, ManualClock};
use shekyl_transport_layer::DialEnd;

const CLEARNET: ConnectorId = ConnectorId::Clearnet;
const TOR: ConnectorId = ConnectorId::Tor;

/// Everything the owners have been told so far, once `done` holds of it.
fn told_until(rig: &Rig, what: &str, done: impl Fn(&[Told]) -> bool) -> Vec<Told> {
    let mut told = Vec::new();
    let start = Instant::now();
    loop {
        told.extend(rig.recorder.take());
        if done(&told) {
            return told;
        }
        assert!(start.elapsed() < Duration::from_secs(5), "{what}: {told:?}");
        thread::sleep(Duration::from_millis(2));
    }
}

fn handshake_claims(told: &[Told]) -> usize {
    told.iter()
        .filter(|told| matches!(told, Told::Claim(_, _, ClaimCarrier::Handshake)))
        .count()
}

fn was_established(told: &[Told]) -> bool {
    told.iter().any(|told| matches!(told, Told::Established(_)))
}

fn admit(rig: &Rig, address: &NetworkAddress, seed: u64) -> SplitMix64 {
    let mut rng = SplitMix64::new(seed);
    rig.dialer
        .admit_operator(address, Tick::new(1), &mut rng)
        .expect("admitted");
    rng
}

#[test]
fn a_well_formed_response_is_adopted_and_its_claim_precedes_any_frame() {
    let rig = Rig::new();
    admit(&rig, &peer(1), 2);

    // The peer answers, then sends a frame straight after. The layer
    // establishes the session on the response; the frame follows it to
    // the relay owner, whatever the timing.
    let (id, _wire) = rig.dial_with(
        CLEARNET,
        &peer(1),
        DialAim::Keep,
        vec![reply(NETWORK, vec![peer(2), peer(3)]), new_transactions(2)],
    );
    let id = id.expect("adopted");

    let told = told_until(&rig, "the frame reached the relay owner", |told| {
        told.iter().any(|told| matches!(told, Told::Relay(..)))
    });
    let order: Vec<&str> = told
        .iter()
        .map(|told| match told {
            Told::Established(_) => "established",
            Told::Claim(..) => "claim",
            Told::Relay(..) => "relay",
            other => panic!("not expected here: {other:?}"),
        })
        .collect();
    assert_eq!(order, vec!["established", "claim", "relay"]);
    let Told::Claim(claimed, height, ClaimCarrier::Handshake) = &told[1] else {
        panic!("the second is the handshake's claim: {told:?}");
    };
    assert_eq!(*claimed, id);
    assert_eq!(*height, 20);
    assert!(matches!(told[2], Told::Relay(relayed, 2) if relayed == id));

    // The kept session is on the board, established and outbound, by the
    // time the dial returned.
    let row = rig.layer.board().get(id).copied().expect("adopted row");
    assert_eq!(row.direction(), Direction::Outbound);
    assert!(row.established());

    // The peer's sample entered gray. The drawn address is white: the
    // dialer recorded SessionAccepted before it returned.
    let shared = rig.dialer.shared();
    assert!(shared.lists.is_gray(&peer(2)) && shared.lists.is_gray(&peer(3)));
    assert!(shared.lists.is_white(&peer(1)));
    drop(shared);
    assert_eq!(rig.dialer.in_flight(CLEARNET), 0);
    assert_eq!(rig.dialer.kept_sessions(CLEARNET), 1);
}

#[test]
fn an_accepted_keep_is_session_accepted_and_the_session_stays() {
    let rig = Rig::new();
    admit(&rig, &peer(1), 3);
    let (id, _wire) = rig.dial_with(
        CLEARNET,
        &peer(1),
        DialAim::Keep,
        vec![reply(NETWORK, vec![])],
    );
    let id = id.expect("adopted");

    let shared = rig.dialer.shared();
    assert!(
        shared.lists.is_white(&peer(1)),
        "SessionAccepted wrote white before the dial returned"
    );
    drop(shared);
    assert_eq!(rig.dialer.in_flight(CLEARNET), 0);
    assert_eq!(rig.dialer.kept_sessions(CLEARNET), 1);
    assert!(
        rig.layer.board().get(id).is_some(),
        "the session was not closed"
    );
    assert!(!rig.recorder.was_told_closed(id));
}

#[test]
fn a_confirm_of_a_peer_far_ahead_records_white_and_establishes_nothing() {
    let rig = Rig::new();
    admit(&rig, &peer(1), 4);
    // Far ahead of our height 10. The dialer does not ask the chain about
    // the height, so nothing is adopted and nothing requests the chain.
    let (id, _wire) = rig.dial_with(
        CLEARNET,
        &peer(1),
        DialAim::Confirm,
        vec![reply_at(NETWORK, vec![], 1_000_000)],
    );
    assert!(id.is_none(), "a confirm dial finishes in the peers owner");
    wait_until("the confirm's row to leave the board", || {
        rig.layer.board().is_empty()
    });
    assert!(
        !was_established(&rig.recorder.take()),
        "a confirm dial establishes no session"
    );
    let shared = rig.dialer.shared();
    assert!(shared.lists.is_white(&peer(1)), "Confirmed wrote white");
    drop(shared);
    assert_eq!(rig.dialer.in_flight(CLEARNET), 0);
}

/// The payload owner's refusal comes to the dialer as the layer's close
/// with `SessionRefused`: the kept row goes, white stays. The close is made
/// from another thread while the layer's owners run; it returns.
#[test]
fn a_session_refused_close_drops_the_kept_row_and_leaves_white() {
    let rig = Rig::new();
    admit(&rig, &peer(1), 5);
    let (id, _wire) = rig.dial_with(
        CLEARNET,
        &peer(1),
        DialAim::Keep,
        vec![reply(NETWORK, vec![])],
    );
    let id = id.expect("adopted");
    assert!(rig.dialer.shared().lists.is_white(&peer(1)));
    assert_eq!(rig.dialer.kept_sessions(CLEARNET), 1);

    let layer = rig.layer.clone();
    let closer = thread::spawn(move || layer.close(id, tables::session_refused()));
    wait_until("the owners were told of the close", || {
        rig.recorder.was_told_closed(id)
    });
    closer.join().expect("closer");
    let shared = rig.dialer.shared();
    assert!(
        shared.lists.is_white(&peer(1)),
        "PayloadRefused does not demote white"
    );
    drop(shared);
    assert_eq!(rig.dialer.kept_sessions(CLEARNET), 0);
    assert_eq!(rig.dialer.in_flight(CLEARNET), 0);
}

/// A closed session's intake ledger goes with it. Every confirm and keep
/// dial, and every timed sync, admits a list under its session id, and ids
/// never repeat: a ledger the close leaves behind stays for the life of the
/// process.
#[test]
fn a_closed_sessions_intake_ledger_is_forgotten() {
    let rig = Rig::new();
    admit(&rig, &peer(1), 6);
    let (id, _wire) = rig.dial_with(
        CLEARNET,
        &peer(1),
        DialAim::Keep,
        vec![reply(NETWORK, vec![peer(2), peer(3)])],
    );
    let id = id.expect("adopted");
    let charged = |rig: &Rig| {
        let now = rig.dialer.now();
        rig.dialer
            .shared()
            .lists
            .intake_count(CLEARNET, session_of(id), now)
    };
    assert_eq!(charged(&rig), 2, "the reply's two addresses were charged");

    let layer = rig.layer.clone();
    let closer = thread::spawn(move || layer.close(id, tables::session_refused()));
    wait_until("the owners were told of the close", || {
        rig.recorder.was_told_closed(id)
    });
    closer.join().expect("closer");
    assert_eq!(charged(&rig), 0, "the closed session's ledger was kept");
}

#[test]
fn another_network_is_a_rejected_handshake_with_no_row_and_no_session() {
    let rig = Rig::new();
    admit(&rig, &peer(1), 6);
    let (adopted, _wire) = rig.dial_with(
        CLEARNET,
        &peer(1),
        DialAim::Keep,
        vec![reply([9; 16], vec![])],
    );
    assert!(adopted.is_none());
    wait_until("the refused row to leave the board", || {
        rig.layer.board().is_empty()
    });
    assert!(!was_established(&rig.recorder.take()));
    let shared = rig.dialer.shared();
    // A clearnet rejection proves nothing (no authenticated destination), so
    // the draw returns to gray and cools (the gray lifecycle). *Records-was
    // (to 2026-10-24): DialFailed dropped the outstanding draw.*
    assert!(shared.lists.is_gray(&peer(1)), "the draw stays gray");
    assert!(shared.lists.is_cooling(&peer(1)), "and cools");
    assert!(!shared.lists.is_white(&peer(1)));
}

#[test]
fn a_refused_peerlist_is_peerlist_refused_with_no_row() {
    let rig = Rig::new();
    admit(&rig, &peer(1), 7);
    let private = NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(192, 168, 1, 1),
        port: 18080,
    };
    let (adopted, _wire) = rig.dial_with(
        CLEARNET,
        &peer(1),
        DialAim::Keep,
        vec![reply(NETWORK, vec![peer(2), private])],
    );
    assert!(adopted.is_none());
    wait_until("the refused row to leave the board", || {
        rig.layer.board().is_empty()
    });
    let shared = rig.dialer.shared();
    assert!(
        !shared.lists.is_gray(&peer(2)),
        "R4: none of the list entered gray"
    );
    // On clearnet a refused list proves nothing, so the draw cools in gray.
    // *Records-was (to 2026-10-24): the draw was dropped.*
    assert!(shared.lists.is_cooling(&peer(1)), "the draw cools");
}

#[test]
fn a_dial_that_cannot_open_is_dial_failed_with_the_cause() {
    let rig = Rig::new();
    // The connector refuses every dial before a channel opens: a local
    // close. The tip is published, so the failure is that connector.
    rig.peer.refuse_unqueued(DialEnd::local_close());
    let mut rng = admit(&rig, &peer(1), 8);
    assert!(rig
        .dialer
        .dial(CLEARNET, &peer(1), DialAim::Keep, &mut rng)
        .is_none());
    assert!(rig.layer.board().is_empty());
    // A local close is a connection problem: the draw cools in gray.
    // *Records-was (to 2026-10-24): the draw was dropped.*
    assert!(
        rig.dialer.shared().lists.is_cooling(&peer(1)),
        "the draw cools"
    );
}

fn info_text(run: impl FnOnce()) -> String {
    log_text(tracing::Level::INFO, run)
}

fn warn_text(run: impl FnOnce()) -> String {
    log_text(tracing::Level::WARN, run)
}

fn count(text: &str, needle: &str) -> usize {
    text.matches(needle).count()
}

/// The idle report is an info line: every reason is a state the connector
/// leaves without the operator. The first under-target spell's sixtieth
/// idle wake says it; leaving the spell (a target of zero) starts another.
#[test]
fn an_idle_connector_says_so_once_at_sixty_wakes_and_again_in_a_new_spell() {
    let rig = Rig::new();
    assert!(rig.dialer.target(CLEARNET) > 0);
    let mut rng = SplitMix64::new(14);
    let text = info_text(|| {
        for _ in 0..59 {
            assert!(!rig.dialer.wake(CLEARNET, &mut rng));
        }
    });
    assert_eq!(
        count(&text, "dialed nothing"),
        0,
        "59 under-target wakes stay quiet: {text}"
    );
    let warned = warn_text(|| {
        let text = info_text(|| {
            assert!(!rig.dialer.wake(CLEARNET, &mut rng));
        });
        assert_eq!(
            count(&text, "dialed nothing for 60 wakes: it knows no address"),
            1,
            "the 60th wake says it once: {text}"
        );
    });
    assert_eq!(
        count(&warned, "dialed nothing"),
        0,
        "the line is not a warning: {warned}"
    );
    let text = info_text(|| {
        for _ in 0..120 {
            assert!(!rig.dialer.wake(CLEARNET, &mut rng));
        }
    });
    assert_eq!(
        count(&text, "dialed nothing"),
        0,
        "a further run with the same reason stays quiet: {text}"
    );

    let target = rig.dialer.target(CLEARNET);
    rig.dialer.set_target(CLEARNET, 0, &mut rng);
    assert!(!rig.dialer.wake(CLEARNET, &mut rng));
    rig.dialer.set_target(CLEARNET, target, &mut rng);
    let text = info_text(|| {
        for _ in 0..59 {
            assert!(!rig.dialer.wake(CLEARNET, &mut rng));
        }
    });
    assert_eq!(
        count(&text, "dialed nothing"),
        0,
        "leaving the spell restarts the count: {text}"
    );
    let text = info_text(|| {
        assert!(!rig.dialer.wake(CLEARNET, &mut rng));
    });
    assert_eq!(
        count(&text, "dialed nothing for 60 wakes: it knows no address"),
        1
    );
}

/// An address the filter refuses (here this node's own) is named as in
/// use, apart from an empty list.
#[test]
fn an_address_in_use_is_named_apart_from_an_empty_list() {
    let rig = Rig::new();
    rig.dialer.set_own_addresses(CLEARNET, vec![peer(1)]);
    let mut rng = admit(&rig, &peer(1), 15);
    let text = info_text(|| {
        for _ in 0..60 {
            assert!(!rig.dialer.wake(CLEARNET, &mut rng));
        }
    });
    assert_eq!(
        count(
            &text,
            "every address it knows is connected, on a host it already reaches, or its own"
        ),
        1,
        "{text}"
    );
    assert_eq!(count(&text, "it knows no address"), 0, "{text}");
}

/// A cooling address is named in the off-draw line. That line is the
/// union of a counted cooldown and an excusal, so a cooling seat is not
/// reported as cooling alone, nor as an address already in use
/// (A7, the alpha.11 fleet).
#[test]
fn a_cooling_address_is_named_as_off_the_draw() {
    let rig = Rig::new();
    rig.peer.refuse_unqueued(DialEnd::local_close());
    let mut rng = admit(&rig, &peer(1), 18);
    assert!(rig
        .dialer
        .dial(CLEARNET, &peer(1), DialAim::Keep, &mut rng)
        .is_none());
    assert!(rig.dialer.shared().lists.is_cooling(&peer(1)));
    let text = info_text(|| {
        for _ in 0..60 {
            assert!(!rig.dialer.wake(CLEARNET, &mut rng));
        }
    });
    assert_eq!(
        count(
            &text,
            "the addresses it is not using are cooling after a failed dial, or held by an excusal"
        ),
        1,
        "{text}"
    );
    assert_eq!(count(&text, "connected"), 0, "{text}");
    assert_eq!(count(&text, "it knows no address"), 0, "{text}");
}

/// A draw ends a run of idle wakes, not the spell: a dead address that
/// thaws, is drawn and fails again does not repeat the line. Before, each
/// draw re-armed it, and the gaps between the lines followed the cooldown
/// ladder (A7, the alpha.11 fleet: about 47 a day on each public seed).
#[test]
fn a_draw_inside_one_spell_does_not_repeat_the_line() {
    /// Past the longest cooldown and its jitter.
    const PAST_COOLDOWN_NANOS: u64 = 2 * shekyl_peerlist::dial_profile(CLEARNET).cooldown.cap_nanos;
    let rig = Rig::new();
    rig.peer.refuse_unqueued(DialEnd::local_close());
    let mut rng = admit(&rig, &peer(1), 19);
    assert!(rig
        .dialer
        .dial(CLEARNET, &peer(1), DialAim::Keep, &mut rng)
        .is_none());
    let text = info_text(|| {
        for _ in 0..3 {
            for _ in 0..60 {
                assert!(!rig.dialer.wake(CLEARNET, &mut rng));
            }
            rig.clock.set(Tick::new(
                rig.clock.now().get().saturating_add(PAST_COOLDOWN_NANOS),
            ));
            assert!(
                rig.dialer.wake(CLEARNET, &mut rng),
                "past its cooldown the address is drawn, and fails again"
            );
            assert!(rig.dialer.shared().lists.is_cooling(&peer(1)));
        }
    });
    assert_eq!(count(&text, "dialed nothing"), 1, "{text}");
}

#[test]
fn an_in_flight_dial_is_named_ahead_of_an_empty_draw() {
    let rig = Rig::new();
    let mut rng = admit(&rig, &peer(1), 16);
    let dialer = Arc::clone(&rig.dialer);
    let owner = thread::spawn(move || {
        dialer.dial(CLEARNET, &peer(1), DialAim::Keep, &mut SplitMix64::new(17))
    });
    let mut wire = rig.dialed();
    wait_until("the dial to be in flight", || {
        rig.dialer.in_flight(CLEARNET) > 0
    });
    let text = info_text(|| {
        for _ in 0..60 {
            assert!(!rig.dialer.wake(CLEARNET, &mut rng));
        }
    });
    assert_eq!(count(&text, "a dial is in flight"), 1, "{text}");
    assert_eq!(count(&text, "it knows no address"), 0, "{text}");
    let _request = wire.read_blocking();
    wire.inject_blocking(reply(NETWORK, vec![]));
    owner.join().expect("dial").expect("kept");
}

/// Below its bound, a dial in flight with nothing else drawable is named as
/// in flight. Its address is an outstanding draw, not a filtered one (A7:
/// on Tor, one dial of five read "a filter holds every address").
#[test]
fn a_dial_in_flight_below_the_bound_is_named_in_flight() {
    let rig = Rig::new();
    rig.dialer.set_in_flight_bound(CLEARNET, 2);
    let mut rng = admit(&rig, &peer(1), 20);
    let dialer = Arc::clone(&rig.dialer);
    let owner = thread::spawn(move || {
        dialer.dial(CLEARNET, &peer(1), DialAim::Keep, &mut SplitMix64::new(21))
    });
    let mut wire = rig.dialed();
    wait_until("the dial to be in flight", || {
        rig.dialer.in_flight(CLEARNET) == 1
    });
    let text = info_text(|| {
        for _ in 0..60 {
            assert!(!rig.dialer.wake(CLEARNET, &mut rng));
        }
    });
    assert_eq!(count(&text, "a dial is in flight"), 1, "{text}");
    assert_eq!(count(&text, "connected"), 0, "{text}");
    let _request = wire.read_blocking();
    wire.inject_blocking(reply(NETWORK, vec![]));
    owner.join().expect("dial").expect("kept");
}

/// **Every dial the dialer does not keep leaves the board** (Copilot,
/// #1092). A confirm and a refused handshake each end their session: the
/// layer closes it and its row goes. A kept dial's row is live.
#[test]
fn every_dial_the_dialer_does_not_keep_leaves_the_board() {
    let rig = Rig::new();
    for frame in [
        reply(NETWORK, vec![]),
        reply([9; 16], vec![]),
        reply(NETWORK, vec![]),
    ] {
        rig.peer.answer_next(Answer::Answered(frame));
    }
    for n in 1..=3 {
        admit(&rig, &peer(n), 3);
    }
    let dial_once = |n: u8, aim: DialAim| {
        rig.dialer
            .dial(CLEARNET, &peer(n), aim, &mut SplitMix64::new(1))
    };

    assert_eq!(
        dial_once(1, DialAim::Confirm),
        None,
        "a confirm is not kept"
    );
    wait_until("the confirm's row to go", || rig.layer.board().is_empty());

    assert_eq!(
        dial_once(2, DialAim::Keep),
        None,
        "another network's handshake is refused"
    );
    wait_until("the refused row to go", || rig.layer.board().is_empty());

    let kept = dial_once(3, DialAim::Keep).expect("kept");
    assert!(
        rig.layer
            .board()
            .get(kept)
            .is_some_and(|row| row.established()),
        "a kept dial's row is live"
    );
    assert_eq!(rig.layer.board().len(), 1);
}

fn onion() -> NetworkAddress {
    NetworkAddress::Tor {
        host: v3_onion_hostname(&[0x11; 32]),
        port: 12021,
    }
}

/// The payload owner declines a delivery on a session whose dial already
/// counted as opened. The close must not count as another open. The fold
/// test holds the unopened count across that outcome; this one holds the
/// close path.
#[test]
fn a_refused_payload_on_a_kept_tor_session_is_not_another_open() {
    let rig = Rig::new();
    let peer = onion();
    admit(&rig, &peer, 9);
    let (id, _wire) = rig.dial_with(TOR, &peer, DialAim::Keep, vec![reply(NETWORK, vec![])]);
    let id = id.expect("adopted");
    let opened = rig.dialer.tor_link_tally();
    assert!(
        opened.last_sign_of_life.is_some(),
        "the stream that opened is a sign of life"
    );
    assert_eq!(
        opened,
        TorLinkTally {
            opened: 1,
            unopened: 0,
            last_sign_of_life: opened.last_sign_of_life,
            failed_attempt_began: None,
        }
    );

    rig.layer.close(id, tables::session_refused());
    wait_until("the owners were told of the close", || {
        rig.recorder.was_told_closed(id)
    });
    assert_eq!(
        rig.dialer.tor_link_tally(),
        TorLinkTally {
            opened: 1,
            unopened: 0,
            last_sign_of_life: opened.last_sign_of_life,
            failed_attempt_began: None,
        },
        "the close is not a new stream"
    );
    assert!(
        rig.dialer.shared().lists.is_white(&peer),
        "PayloadRefused does not demote white"
    );
}

/// **A Tor peer sending a list over D3 is dropped** (the gray lifecycle,
/// test 6c). The onion is the peer's key, so a refused list on Tor is
/// authenticated misbehaviour: the Levin layer stamps the refusal as proof,
/// and the lists drop the address instead of cooling it. The same list on
/// clearnet proves nothing and only cools.
#[test]
fn a_tor_peer_sending_a_list_over_d3_is_dropped() {
    let onion = |n: u8| NetworkAddress::Tor {
        host: v3_onion_hostname(&[n; 32]),
        port: 18080,
    };
    let peer_onion = onion(1);
    // Thirteen entries: one over DISCLOSE_COUNT.
    let over_d3: Vec<NetworkAddress> = (10u8..23).map(onion).collect();
    assert_eq!(over_d3.len(), shekyl_peerlist::DISCLOSE_COUNT + 1);

    let rig = Rig::new();
    rig.peer
        .answer_next(Answer::Answered(reply(NETWORK, over_d3.clone())));
    let mut rng = admit(&rig, &peer_onion, 13);
    assert!(rig.dialer.shared().lists.is_gray(&peer_onion));

    assert_eq!(
        rig.dialer.dial(TOR, &peer_onion, DialAim::Keep, &mut rng),
        None,
        "the list is refused"
    );
    let shared = rig.dialer.shared();
    assert!(
        !shared.lists.is_gray(&peer_onion) && !shared.lists.is_white(&peer_onion),
        "proven misbehaviour on Tor: the address is dropped"
    );
    for entry in &over_d3 {
        assert!(
            !shared.lists.is_gray(entry),
            "nothing of the list entered gray"
        );
    }
    drop(shared);

    // A list within the frame bound that the lists refuse: a clearnet entry
    // on a Tor session is the foreign-connector rule. It reaches the lists,
    // and the refusal is stamped as proof the same way.
    let rig = Rig::new();
    let foreign: Vec<NetworkAddress> = vec![onion(30), peer(31)];
    rig.peer
        .answer_next(Answer::Answered(reply(NETWORK, foreign)));
    // The same onion as above: `[1; 32]` is a valid key, and this rig is
    // fresh. (An arbitrary 32 bytes is not a point; `endpoint_of` would
    // refuse it before the dial, a local close that proves nothing.)
    let peer_onion = onion(1);
    admit(&rig, &peer_onion, 13);
    assert_eq!(
        rig.dialer.dial(TOR, &peer_onion, DialAim::Keep, &mut rng),
        None
    );
    {
        let shared = rig.dialer.shared();
        assert!(
            !shared.lists.is_gray(&peer_onion) && !shared.lists.is_white(&peer_onion),
            "a list the lists refuse, on Tor, drops the address"
        );
    }

    // The control: the same list from a clearnet peer proves nothing, and
    // the draw cools instead.
    let rig = Rig::new();
    let over_d3_v4: Vec<NetworkAddress> = (10u8..23).map(peer).collect();
    rig.peer
        .answer_next(Answer::Answered(reply(NETWORK, over_d3_v4)));
    admit(&rig, &peer(1), 13);
    assert_eq!(
        rig.dialer.dial(CLEARNET, &peer(1), DialAim::Keep, &mut rng),
        None
    );
    assert!(
        rig.dialer.shared().lists.is_cooling(&peer(1)),
        "clearnet: cooled, not dropped"
    );
}

/// **A Tor address failing with 0xF0 twice, then succeeding, ends white
/// after three attempts in one test** (the gray lifecycle, test 6a'). The
/// first two connects are refused with the missing-descriptor reply, which
/// the Tor connector's table marks worth a retry; each waits its turn
/// without holding the in-flight slot, the address stays the outstanding
/// draw meanwhile, nothing is recorded for the failed attempts (no
/// cooldown, no failed-test count), and the third attempt keeps the
/// session: one `SessionAccepted`, the address white. A fourth refusal would
/// have been the test's outcome instead.
#[test]
fn a_tor_address_failing_twice_with_a_missing_descriptor_then_succeeding_ends_white() {
    let clock = ManualClock::new(Tick::new(1));
    let rig = Rig::on(&clock);
    rig.peer
        .refuse_after(shekyl_tor::reply_end(0xF0), Duration::ZERO);
    rig.peer
        .refuse_after(shekyl_tor::reply_end(0xF0), Duration::ZERO);
    rig.peer
        .answer_next(Answer::Answered(reply(NETWORK, vec![])));
    let onion = NetworkAddress::Tor {
        host: v3_onion_hostname(&[1; 32]),
        port: 18080,
    };
    let mut rng = admit(&rig, &onion, 21);

    // Attempt 1: refused, worth a retry. Nothing is recorded, the address
    // is still the outstanding draw, and no slot is held while it waits.
    assert!(rig.dialer.wake(TOR, &mut rng), "attempt 1 dialed");
    {
        let shared = rig.dialer.shared();
        assert!(shared.lists.is_gray(&onion) && !shared.lists.is_cooling(&onion));
        assert_eq!(shared.lists.failed_tests(&onion), 0);
    }
    assert_eq!(rig.dialer.in_flight(TOR), 0, "the wait holds no slot");
    // A wake before the due tick draws nothing: the address is outstanding
    // and nothing else is gray.
    assert!(!rig.dialer.wake(TOR, &mut rng), "too early for attempt 2");

    // Attempt 2, past the first wait (5 s + up to 5 s): refused again.
    clock.set(Tick::new(clock.now().get() + 10 * 1_000_000_000 + 1));
    assert!(rig.dialer.wake(TOR, &mut rng), "attempt 2 dialed");
    assert_eq!(rig.dialer.shared().lists.failed_tests(&onion), 0);
    assert!(rig.layer.board().is_empty(), "nothing is kept yet");
    assert_eq!(
        rig.dialer.kept_sessions(TOR),
        1,
        "the waiting keep test holds its target place"
    );

    // Attempt 3, past the second wait (20 s + up to 10 s): kept.
    clock.set(Tick::new(clock.now().get() + 30 * 1_000_000_000 + 1));
    assert!(rig.dialer.wake(TOR, &mut rng), "attempt 3 dialed");
    assert_eq!(rig.dialer.kept_sessions(TOR), 1);
    let shared = rig.dialer.shared();
    assert!(
        shared.lists.is_white(&onion),
        "one test, three attempts, white"
    );
    assert_eq!(shared.lists.failed_tests(&onion), 0);
    drop(shared);
    assert_eq!(
        handshake_claims(&rig.recorder.take()),
        1,
        "one handshake claim, for the kept attempt"
    );
}
