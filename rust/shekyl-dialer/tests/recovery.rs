// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Recovery (Rick, 2026-10-14; amended 2026-10-24): a connector whose wake
//! finds it under its target, nothing in flight and no drawable white or
//! gray candidate re-admits its configured addresses to gray as
//! operator-named: the compiled seeds and `--add-peer`, or, when a closed
//! network is declared, that list alone. The wake that re-admits dials
//! nothing; the next draws.
//!
//! Cases with no kept session use a hub with no connector, so every dial
//! fails at once as a local close: the failed draw leaves gray, and a
//! local close marks nothing in the failed-address memory. Cases with a
//! kept session install an answering dial. The handshake it is given
//! decides whether that dial is kept.

#[path = "support/log_capture.rs"]
mod log_capture;

use log_capture::log_text;
use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use shekyl_capped_stream::Session;
use shekyl_dialer::{DialAim, Dialer};
use shekyl_draw_rng::SplitMix64;
use shekyl_levin::{
    response, BasicNodeData, CoreSyncData, HandshakeResponse, PeerlistEntry, PortableMap,
    COMMAND_HANDSHAKE,
};
use shekyl_peer_policy::InboundCeiling;
use shekyl_peerlist::{CloseCause, ConnectorId, ListName, NetworkAddress, RefusedSet, Tick};
use shekyl_seam::{
    Channel, Dial, Endpoint, Hub, Loopback, Route, RoutePublish, SocketId, SyncPayload,
};
use shekyl_timing_engine::ManualClock;
use shekyl_transport_layer::Sockets;

const CLEARNET: ConnectorId = ConnectorId::Clearnet;
const NETWORK: [u8; 16] = [7; 16];
const OTHER_NETWORK: [u8; 16] = [9; 16];
/// The loopback's outbound byte cap. The handshake frames in these tests
/// sit far under it.
const SEND_CAP: usize = 64 * 1024;

fn peer(n: u8) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 15, 0, n),
        port: 18080,
    }
}

fn hub() -> Hub {
    Hub::new(
        Sockets::new(),
        InboundCeiling::Bounded(8),
        Arc::new(|_post| {}),
        Arc::new(ManualClock::new(Tick::new(1))),
    )
}

fn open_dialer(hub: Hub) -> Arc<Dialer> {
    let dialer = Arc::new(Dialer::new(
        hub,
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
    // The link is usable: the plan draws only then (TSR-F1).
    assert!(
        matches!(
            dialer
                .hub()
                .links()
                .publish_usable(CLEARNET, Route::Direct, Tick::new(1),),
            RoutePublish::Installed { .. }
        ),
        "the test route was not already usable"
    );
    dialer
}

/// No connector. Every dial fails at once as a local close.
fn dialer() -> Arc<Dialer> {
    open_dialer(hub())
}

/// A connector that answers each dial with the next handshake, in order.
/// A dial with no answer left blocks in the read, so a test queues one
/// handshake per dial it will make.
fn keeping(answers: Vec<Vec<u8>>) -> (Hub, Arc<Dialer>) {
    let hub = hub();
    hub.install_dial(Arc::new(AnswerDial::answering(answers)));
    let dialer = open_dialer(hub.clone());
    (hub, dialer)
}

/// The loopback, handing the next queued handshake to each channel it opens.
struct AnswerDial {
    inner: Loopback,
    answers: Mutex<VecDeque<Vec<u8>>>,
}

impl AnswerDial {
    fn answering(answers: Vec<Vec<u8>>) -> Self {
        Self {
            inner: Loopback::new(Sockets::new(), SEND_CAP),
            answers: Mutex::new(answers.into()),
        }
    }
}

impl Dial for AnswerDial {
    fn connect(
        &self,
        endpoint: &Endpoint,
        ceiling: InboundCeiling,
        now: Tick,
    ) -> Result<Channel, CloseCause> {
        let channel = self.inner.connect(endpoint, ceiling, now)?;
        if let Some(answer) = self.answers.lock().expect("answers").pop_front() {
            assert!(
                self.inner.inject(channel.open.id(), answer),
                "the handshake was not waiting in the channel"
            );
        }
        Ok(channel)
    }

    fn inject(&self, id: SocketId, frame: Vec<u8>) -> bool {
        self.inner.inject(id, frame)
    }

    fn reader_stopped(&self, id: SocketId) {
        self.inner.reader_stopped(id);
    }

    fn retired(&self, id: SocketId) {
        self.inner.retired(id);
    }

    fn drive(&self, hub: &Hub, id: SocketId, session: Session) {
        self.inner.drive(hub, id, session);
    }
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

/// The clearnet gray list, as addresses.
fn gray(dialer: &Dialer) -> Vec<NetworkAddress> {
    dialer
        .shared()
        .lists
        .snapshot()
        .into_iter()
        .filter(|(address, list)| {
            *list == ListName::Gray
                && shekyl_peerlist::Peerlist::connector_of(address) == Some(CLEARNET)
        })
        .map(|(address, _)| address)
        .collect()
}

/// Dial `address` once: with no connector it fails, and leaves gray.
fn fail_out(dialer: &Dialer, address: &NetworkAddress, rng: &mut SplitMix64) {
    assert!(
        gray(dialer).contains(address),
        "{address:?} is in gray to fail"
    );
    assert!(
        dialer.dial(CLEARNET, address, DialAim::Keep, rng).is_none(),
        "no connector: the dial fails at once"
    );
    assert!(!gray(dialer).contains(address), "{address:?} left gray");
}

#[test]
fn a_stranded_connector_re_admits_its_configured_addresses_and_dials() {
    let dialer = dialer();
    let mut rng = SplitMix64::new(1);
    let named = peer(1);
    dialer
        .admit_operator(&named, Tick::new(1), &mut rng)
        .expect("admitted");
    fail_out(&dialer, &named, &mut rng);
    assert!(gray(&dialer).is_empty(), "the failed draw left gray");

    // Stranded: this wake re-admits and dials nothing.
    assert!(dialer.choose(CLEARNET, &mut rng).is_none());
    assert_eq!(
        gray(&dialer),
        vec![named.clone()],
        "re-admitted as configured"
    );

    // The next wake draws it.
    let (drawn, _aim, _nonce) = dialer
        .choose(CLEARNET, &mut rng)
        .expect("a stranded connector dials what it re-admitted");
    assert_eq!(drawn, named);
}

#[test]
fn a_healthy_connector_does_not_re_admit_a_dead_add_peer() {
    let dialer = dialer();
    let mut rng = SplitMix64::new(2);
    let dead = peer(1);
    dialer
        .admit_operator(&dead, Tick::new(1), &mut rng)
        .expect("admitted");
    fail_out(&dialer, &dead, &mut rng);

    // A candidate is drawable, so the connector is not stranded.
    let live = peer(2);
    dialer
        .admit_operator(&live, Tick::new(1), &mut rng)
        .expect("admitted");
    let (drawn, _aim, _nonce) = dialer.choose(CLEARNET, &mut rng).expect("a draw");
    assert_eq!(drawn, live);
    assert!(
        !gray(&dialer).contains(&dead),
        "a healthy connector leaves a dead --add-peer out"
    );
}

#[test]
fn a_declared_closed_network_re_admits_only_its_list() {
    let dialer = dialer();
    let mut rng = SplitMix64::new(3);
    // Named before the declaration, and failed out of gray.
    let outside = peer(9);
    dialer
        .admit_operator(&outside, Tick::new(1), &mut rng)
        .expect("admitted");
    fail_out(&dialer, &outside, &mut rng);

    let population = vec![peer(1), peer(2)];
    dialer.set_exclusive(population.clone(), Tick::new(1), &mut rng);
    for address in &population {
        fail_out(&dialer, address, &mut rng);
    }
    assert!(gray(&dialer).is_empty());

    assert!(
        dialer.choose(CLEARNET, &mut rng).is_none(),
        "the stranded wake re-admits"
    );
    let mut readmitted = gray(&dialer);
    readmitted.sort();
    assert_eq!(
        readmitted, population,
        "the closed network's list, and not the address named outside it"
    );
}

/// **Recovery runs under the target, not only at zero kept sessions**
/// (the alpha.10 fleet report's problem 11; the 2026-10-14 recovery ruling
/// as amended 2026-10-24). A connector with one kept session under a target
/// of two, whose other configured address failed and was dropped, holds
/// nothing drawable: its one white address is a session, gray is empty. The
/// next wake re-admits the configured addresses, and the wake after draws
/// the one that failed. Red with the old condition (`kept == 0`): the first
/// wake dials nothing and re-admits nothing, so gray stays empty.
#[test]
fn a_connector_under_target_with_nothing_drawable_re_admits_its_configured_addresses() {
    let (_hub, dialer) = keeping(vec![reply(NETWORK), reply(OTHER_NETWORK)]);
    let mut rng = SplitMix64::new(5);
    dialer.set_target(CLEARNET, 2, &mut rng);
    for n in [1, 2] {
        dialer
            .admit_operator(&peer(n), Tick::new(1), &mut rng)
            .expect("admitted");
    }

    dialer
        .dial(CLEARNET, &peer(1), DialAim::Keep, &mut rng)
        .expect("the first dial is kept");
    assert_eq!(dialer.kept_sessions(CLEARNET), 1);
    assert_eq!(
        dialer.dial(CLEARNET, &peer(2), DialAim::Keep, &mut rng),
        None,
        "the second dial is refused"
    );
    assert!(gray(&dialer).is_empty(), "the failed draw left gray");

    // Under the target with nothing drawable: this wake re-admits and
    // dials nothing.
    assert!(dialer.choose(CLEARNET, &mut rng).is_none());
    assert_eq!(
        gray(&dialer),
        vec![peer(2)],
        "the dropped configured address is re-admitted; the kept one stays white"
    );

    // The next wake draws it.
    let (drawn, _aim, _nonce) = dialer
        .choose(CLEARNET, &mut rng)
        .expect("the connector draws what it re-admitted");
    assert_eq!(drawn, peer(2));
    assert_eq!(
        dialer.kept_sessions(CLEARNET),
        1,
        "the kept session is untouched"
    );
}

/// **The recovery log does not cycle on a dead configured address** (Rick's
/// review of #1174, 2026-10-24). One kept session under a target of two;
/// one dead configured address, which every wake re-admits, draws, fails
/// and drops; one configured address under a ban, refused at every
/// re-admission. Over twenty wakes: recovery is entered once, never left
/// (the kept count did not rise, and nothing was drawn that the episode
/// did not re-admit), and the banned address is refused aloud once.
#[test]
fn the_recovery_log_is_one_episode_while_a_dead_configured_address_cycles() {
    const WAKES: usize = 20;
    // The keep, then another network's handshake for the opening draw and
    // every redial of the dead address.
    let mut answers = vec![reply(NETWORK)];
    answers.extend(std::iter::repeat_n(reply(OTHER_NETWORK), WAKES));
    let (hub, dialer) = keeping(answers);
    let mut rng = SplitMix64::new(11);
    dialer.set_target(CLEARNET, 2, &mut rng);
    for n in [1, 2] {
        dialer
            .admit_operator(&peer(n), Tick::new(1), &mut rng)
            .expect("admitted");
    }
    // The clock does not advance, so a ban one tick ahead lasts the run.
    // peer(3) is configured and never admitted.
    let until = Tick::new(hub.now().get().saturating_add(1));
    let banned = peer(3).ip().expect("clearnet address");
    hub.ban_host(banned, until);
    assert!(matches!(
        dialer.admit_operator(&peer(3), Tick::new(1), &mut rng),
        Err(shekyl_peerlist::Refusal::Banned)
    ));
    dialer
        .dial(CLEARNET, &peer(1), DialAim::Keep, &mut rng)
        .expect("the first dial is kept");
    assert_eq!(dialer.kept_sessions(CLEARNET), 1);

    let text = log_text(tracing::Level::INFO, || {
        for _ in 0..WAKES {
            dialer.wake(CLEARNET, &mut rng);
        }
    });
    assert_eq!(
        text.matches("no drawable candidate; re-admitted").count(),
        1,
        "recovery is entered once:\n{text}"
    );
    assert_eq!(
        text.matches("no longer stranded").count(),
        0,
        "recovery is never left: nothing it did not re-admit was drawn:\n{text}"
    );
    assert_eq!(
        text.matches("was not re-admitted").count(),
        1,
        "the banned configured address is refused aloud once:\n{text}"
    );
    assert_eq!(dialer.kept_sessions(CLEARNET), 1);
    assert!(
        !gray(&dialer).contains(&peer(3)),
        "the banned address stays out"
    );
}

/// **A gained session closes the episode on the following wake** (the
/// exit runs on a stranded wake, not only on a draw). Target three, one
/// session kept. Recovery re-admits the other configured address, and a
/// keep of that address brings the connector to two: still under target,
/// and the new session is not a candidate, so the following wake is
/// stranded. That wake says the kept count rose and opens the next
/// episode. A dead configured address added after that, and a banned one,
/// then cycle inside the new episode: one more refusal, and no further
/// enter or leave.
///
/// The gain is a keep dial, not a fill draw. One gray address sits under
/// the diversity floor, so the fill would confirm it and the kept count
/// would not move.
#[test]
fn a_gained_session_closes_the_episode_on_the_following_wake() {
    /// Draws of the dead address after the gain. Each is one wake that
    /// dials, between wakes that only re-admit.
    const DEAD_DRAWS: usize = 4;
    const TARGET: usize = 3;
    // Dial order: keep peer 1, fail peer 2 out of gray, keep peer 2 once
    // recovery has re-admitted it, fail peer 3 out of gray, then each
    // dead draw.
    let mut answers = vec![
        reply(NETWORK),
        reply(OTHER_NETWORK),
        reply(NETWORK),
        reply(OTHER_NETWORK),
    ];
    answers.extend(std::iter::repeat_n(reply(OTHER_NETWORK), DEAD_DRAWS));
    let (hub, dialer) = keeping(answers);
    let mut rng = SplitMix64::new(17);
    dialer.set_target(CLEARNET, TARGET, &mut rng);
    for n in [1, 2] {
        dialer
            .admit_operator(&peer(n), Tick::new(1), &mut rng)
            .expect("admitted");
    }
    let until = Tick::new(hub.now().get().saturating_add(1));
    hub.ban_host(peer(4).ip().expect("clearnet address"), until);
    assert!(matches!(
        dialer.admit_operator(&peer(4), Tick::new(1), &mut rng),
        Err(shekyl_peerlist::Refusal::Banned)
    ));
    dialer
        .dial(CLEARNET, &peer(1), DialAim::Keep, &mut rng)
        .expect("the first dial is kept");
    assert_eq!(
        dialer.dial(CLEARNET, &peer(2), DialAim::Keep, &mut rng),
        None,
        "peer 2 leaves gray"
    );
    assert!(gray(&dialer).is_empty(), "nothing drawable before recovery");
    assert_eq!(dialer.kept_sessions(CLEARNET), 1);

    let text = log_text(tracing::Level::INFO, || {
        assert!(
            !dialer.wake(CLEARNET, &mut rng),
            "the stranded wake re-admits and dials nothing"
        );
        dialer
            .dial(CLEARNET, &peer(2), DialAim::Keep, &mut rng)
            .expect("the re-admitted address is kept");
        assert_eq!(dialer.kept_sessions(CLEARNET), 2);
        assert!(
            !dialer.wake(CLEARNET, &mut rng),
            "still under target with nothing drawable: this wake sees the gain"
        );
        dialer
            .admit_operator(&peer(3), Tick::new(1), &mut rng)
            .expect("the dead address is configured");
        assert_eq!(
            dialer.dial(CLEARNET, &peer(3), DialAim::Keep, &mut rng),
            None,
            "the dead address leaves gray"
        );
        for _ in 0..DEAD_DRAWS {
            assert!(!dialer.wake(CLEARNET, &mut rng), "re-admit dials nothing");
            assert!(dialer.wake(CLEARNET, &mut rng), "the dead address is drawn");
        }
    });

    let enters: Vec<usize> = text
        .match_indices("no drawable candidate; re-admitted")
        .map(|(at, _)| at)
        .collect();
    let leave = text
        .find("a kept session was added")
        .expect("the gain closed the episode");
    assert_eq!(
        enters.len(),
        2,
        "entered once, then once more when the gain left the connector stranded:\n{text}"
    );
    assert!(
        enters[0] < leave && leave < enters[1],
        "the leave sits between the two enters:\n{text}"
    );
    assert_eq!(
        text.matches("no longer stranded").count(),
        1,
        "the dead address does not close the next episode:\n{text}"
    );
    assert_eq!(
        text.matches("was not re-admitted").count(),
        2,
        "the banned address is refused once per episode:\n{text}"
    );
    assert_eq!(
        text.matches("at its target").count(),
        0,
        "the connector is still under its target:\n{text}"
    );
    assert_eq!(
        text.matches("did not re-admit").count(),
        0,
        "no foreign candidate was drawn:\n{text}"
    );
    assert_eq!(dialer.kept_sessions(CLEARNET), 2);
    assert!(
        !gray(&dialer).contains(&peer(4)),
        "the banned address stays out"
    );
}
