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
//! fails at once as a local close. Cases with a kept session install an
//! answering dial; the handshake it is given decides whether that dial is
//! kept. Every case runs on a hand-moved clock.
//!
//! Under the gray lifecycle (Rick, 2026-10-24) a failed test that proves
//! no misbehaviour keeps the address in gray with a cooldown, so it stays
//! seated and is not drawable until the cooldown ends: a connector whose
//! every address is cooling is stranded, and recovery re-admits nothing new
//! for it; the clock is what frees the address, no faster than its
//! cooldown. A configured address recovery finds already seated counts as
//! covered by the episode, so drawing it once it thaws does not end the
//! episode. *Records-was (2026-10-14 to 2026-10-24): the failed draw left
//! gray, and the stranded wake re-admitted it.*

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
use shekyl_timing_engine::{Clock, ManualClock};
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

/// Past the longest cooldown and its jitter.
const PAST_COOLDOWN_NANOS: u64 = 2 * shekyl_peerlist::COOLDOWN_CAP_NANOS;

fn hub_on(clock: &ManualClock) -> Hub {
    Hub::new(
        Sockets::new(),
        InboundCeiling::Bounded(8),
        Arc::new(|_post| {}),
        Arc::new(clock.clone()),
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
    dialer_on(&ManualClock::new(Tick::new(1)))
}

/// No connector, on `clock`.
fn dialer_on(clock: &ManualClock) -> Arc<Dialer> {
    open_dialer(hub_on(clock))
}

/// A connector that answers each dial with the next handshake, in order,
/// on `clock`. A dial with no answer left blocks in the read, so a test
/// queues one handshake per dial it will make.
fn keeping_on(clock: &ManualClock, answers: Vec<Vec<u8>>) -> (Hub, Arc<Dialer>) {
    let hub = hub_on(clock);
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

/// Dial `address` once: with no connector it fails, and cools in gray.
fn fail_out(dialer: &Dialer, address: &NetworkAddress, rng: &mut SplitMix64) {
    assert!(
        gray(dialer).contains(address),
        "{address:?} is in gray to fail"
    );
    assert!(
        dialer.dial(CLEARNET, address, DialAim::Keep, rng).is_none(),
        "no connector: the dial fails at once"
    );
    assert!(
        gray(dialer).contains(address),
        "{address:?} stays gray: a connection problem drops nothing"
    );
    assert!(
        dialer.shared().lists.is_cooling(address),
        "{address:?} cools after the failed test"
    );
}

/// Move the clock past every cooldown, so what cooled is drawable again.
fn past_cooldowns(clock: &ManualClock) {
    clock.set(Tick::new(clock.now().get() + PAST_COOLDOWN_NANOS));
}

/// A configured dead address under recovery is redialled no faster than
/// its cooldown (the gray lifecycle, test 6e). The failed address cools in
/// gray; the connector, with nothing drawable, is stranded and re-admits
/// nothing it does not already hold; wakes inside the cooldown draw
/// nothing; the first wake past it draws the address again.
#[test]
fn a_stranded_connector_redials_a_cooling_configured_address_no_faster_than_its_cooldown() {
    let clock = ManualClock::new(Tick::new(1));
    let dialer = dialer_on(&clock);
    let mut rng = SplitMix64::new(1);
    let named = peer(1);
    dialer
        .admit_operator(&named, Tick::new(1), &mut rng)
        .expect("admitted");
    fail_out(&dialer, &named, &mut rng);

    // Stranded, inside the cooldown: every wake re-admits nothing new and
    // draws nothing.
    for _ in 0..5 {
        assert!(dialer.choose(CLEARNET, &mut rng).is_none());
        assert_eq!(
            gray(&dialer),
            vec![named.clone()],
            "still seated, still cooling"
        );
        assert!(dialer.shared().lists.is_cooling(&named));
    }

    // Past the cooldown the address is drawable, and the wake draws it.
    past_cooldowns(&clock);
    let (drawn, _aim, _nonce) = dialer
        .choose(CLEARNET, &mut rng)
        .expect("the cooled address is drawn once its cooldown ends");
    assert_eq!(drawn, named);
}

#[test]
fn a_healthy_connector_leaves_a_dead_add_peer_cooling() {
    let dialer = dialer();
    let mut rng = SplitMix64::new(2);
    let dead = peer(1);
    dialer
        .admit_operator(&dead, Tick::new(1), &mut rng)
        .expect("admitted");
    fail_out(&dialer, &dead, &mut rng);

    // A candidate is drawable, so the connector is not stranded, and the
    // dead address is left where its failed test put it: cooling.
    let live = peer(2);
    dialer
        .admit_operator(&live, Tick::new(1), &mut rng)
        .expect("admitted");
    let (drawn, _aim, _nonce) = dialer.choose(CLEARNET, &mut rng).expect("a draw");
    assert_eq!(drawn, live);
    assert!(
        dialer.shared().lists.is_cooling(&dead),
        "a healthy connector leaves a dead --add-peer cooling, not redrawn"
    );
}

#[test]
fn a_declared_closed_network_draws_only_its_list_once_its_cooldowns_end() {
    let clock = ManualClock::new(Tick::new(1));
    let dialer = dialer_on(&clock);
    let mut rng = SplitMix64::new(3);
    // Named before the declaration, and failed: it cools in gray.
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
    // Everything is seated and cooling: the stranded wake has nothing to
    // re-admit and draws nothing.
    assert!(dialer.choose(CLEARNET, &mut rng).is_none());
    assert_eq!(gray(&dialer).len(), 3, "nothing left gray");

    // Past the cooldowns, every wake draws from the declared list: the
    // address named outside it is seated and drawable, and never drawn.
    // A wake's dial fails at once (no connector), so what it drew is the
    // one address cooling again. The connector holds nothing and opens
    // nothing, so past the quiet stretch a failure does not climb the
    // ladder (Rick, 2026-10-26): the count cannot tell the draws apart.
    let cooling = |address: &NetworkAddress| dialer.shared().lists.is_cooling(address);
    for _ in 1..=4u32 {
        past_cooldowns(&clock);
        assert!(dialer.wake(CLEARNET, &mut rng), "the closed network dials");
        assert!(!cooling(&outside), "the outside address is never drawn");
        assert_eq!(
            population.iter().filter(|address| cooling(address)).count(),
            1,
            "one member of the list was drawn and failed again"
        );
    }
}

/// **Recovery runs under the target, not only at zero kept sessions**
/// (the alpha.10 fleet report's problem 11; the 2026-10-14 recovery ruling
/// as amended 2026-10-24), and **a configured dead address under recovery
/// is redialled no faster than its cooldown** (the gray lifecycle, test
/// 6e). A connector with one kept session under a target of two, whose
/// other configured address failed, holds nothing drawable: its one white
/// address is a session, and the failed address cools in gray. Wakes inside
/// the cooldown draw nothing; the first wake past it draws that address.
/// *Records-was (to 2026-10-24): the failed draw left gray, and the
/// stranded wake re-admitted it before the next wake drew it.*
#[test]
fn a_connector_under_target_redials_its_cooling_configured_address_no_faster_than_its_cooldown() {
    let clock = ManualClock::new(Tick::new(1));
    let (_hub, dialer) = keeping_on(&clock, vec![reply(NETWORK), reply(OTHER_NETWORK)]);
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
    assert_eq!(gray(&dialer), vec![peer(2)], "the failed draw stays gray");
    assert!(dialer.shared().lists.is_cooling(&peer(2)), "and cools");

    // Under the target with nothing drawable: every wake inside the
    // cooldown is recovery, re-admits nothing new, and draws nothing.
    for _ in 0..5 {
        assert!(dialer.choose(CLEARNET, &mut rng).is_none());
        assert!(dialer.shared().lists.is_cooling(&peer(2)));
    }

    // The first wake past the cooldown draws it.
    past_cooldowns(&clock);
    let (drawn, _aim, _nonce) = dialer
        .choose(CLEARNET, &mut rng)
        .expect("the cooled address is drawn once its cooldown ends");
    assert_eq!(drawn, peer(2));
    assert_eq!(
        dialer.kept_sessions(CLEARNET),
        1,
        "the kept session is untouched"
    );
}

/// **The recovery log is one episode while a dead configured address
/// cools** (Rick's review of #1174, 2026-10-24). One kept session under a
/// target of two; one dead configured address, drawn once, failed, and
/// cooling for the rest of the run; one configured address under a ban,
/// refused at every re-admission. Over twenty wakes: recovery is entered
/// once, never left (the kept count did not rise, and nothing was drawn
/// that the episode does not cover), and the banned address is refused
/// aloud once. *Records-was (to 2026-10-24): the dead address was
/// re-admitted, drawn, failed and dropped every two wakes, and the test was
/// named for that cycle.*
#[test]
fn the_recovery_log_is_one_episode_while_a_dead_configured_address_cools() {
    const WAKES: usize = 20;
    // The keep, then another network's handshake for the dead address.
    let clock = ManualClock::new(Tick::new(1));
    let (hub, dialer) = keeping_on(&clock, vec![reply(NETWORK), reply(OTHER_NETWORK)]);
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
    assert!(
        dialer.shared().lists.is_cooling(&peer(2)),
        "the dead address was drawn, failed, and cools"
    );
    assert_eq!(
        text.matches("no drawable candidate; re-admitted").count(),
        1,
        "recovery is entered once:\n{text}"
    );
    assert_eq!(
        text.matches("no longer stranded").count(),
        0,
        "recovery is never left: nothing the episode does not cover was drawn:\n{text}"
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
/// session kept, the other configured address failed and cooling. Past its
/// cooldown a keep of that address brings the connector to two: still under
/// target, and the new session is not a candidate, so the following wake is
/// stranded. That wake says the kept count rose and opens the next episode.
/// A dead configured address added after that, and a banned one, then
/// cycle inside the new episode: the dead one is drawn each time its
/// cooldown ends, fails and cools again, and as a configured address the
/// episode found seated it is covered, so its draw does not end the
/// episode; one more refusal, and no further enter or leave.
///
/// The gain is a keep dial, not a fill draw. One gray address sits under
/// the diversity floor, so the fill would confirm it and the kept count
/// would not move. *Records-was (to 2026-10-24): each failed address left
/// gray and was re-admitted by the next stranded wake, with no clock.*
#[test]
fn a_gained_session_closes_the_episode_on_the_following_wake() {
    /// Draws of the dead address after the gain, one per cooldown.
    const DEAD_DRAWS: usize = 4;
    const TARGET: usize = 3;
    // Dial order: keep peer 1, fail peer 2, keep peer 2 past its cooldown,
    // fail peer 3, then each dead draw.
    let mut answers = vec![
        reply(NETWORK),
        reply(OTHER_NETWORK),
        reply(NETWORK),
        reply(OTHER_NETWORK),
    ];
    answers.extend(std::iter::repeat_n(reply(OTHER_NETWORK), DEAD_DRAWS));
    let clock = ManualClock::new(Tick::new(1));
    let (hub, dialer) = keeping_on(&clock, answers);
    let mut rng = SplitMix64::new(17);
    dialer.set_target(CLEARNET, TARGET, &mut rng);
    for n in [1, 2] {
        dialer
            .admit_operator(&peer(n), Tick::new(1), &mut rng)
            .expect("admitted");
    }
    // A ban that outlasts every cooldown this test moves the clock past.
    let until = Tick::new(
        hub.now()
            .get()
            .saturating_add((DEAD_DRAWS as u64 + 2) * PAST_COOLDOWN_NANOS),
    );
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
        "peer 2 fails its test"
    );
    assert!(
        dialer.shared().lists.is_cooling(&peer(2)),
        "nothing drawable before recovery: peer 2 cools"
    );
    assert_eq!(dialer.kept_sessions(CLEARNET), 1);

    let text = log_text(tracing::Level::INFO, || {
        assert!(
            !dialer.wake(CLEARNET, &mut rng),
            "the stranded wake re-admits and dials nothing"
        );
        past_cooldowns(&clock);
        dialer
            .dial(CLEARNET, &peer(2), DialAim::Keep, &mut rng)
            .expect("past its cooldown the configured address is kept");
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
            "the dead address fails its test and cools"
        );
        for _ in 0..DEAD_DRAWS {
            assert!(
                !dialer.wake(CLEARNET, &mut rng),
                "inside the cooldown: recovery, nothing dialed"
            );
            past_cooldowns(&clock);
            assert!(
                dialer.wake(CLEARNET, &mut rng),
                "past the cooldown the dead address is drawn"
            );
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
