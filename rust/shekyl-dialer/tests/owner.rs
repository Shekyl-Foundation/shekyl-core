// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The handshake owner, over the seam's loopback dialer (dialer brief,
//! "The dial" and "`DialOutcome`").
//!
//! The test plays the peer: it injects the handshake response into the
//! dialed channel and reads what the owner posts. The owner runs on its
//! own thread, as in the daemon; `Hub::dial_channel` blocks it until the
//! loopback opens the channel, and the read blocks it until the response
//! arrives.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use tracing_subscriber::fmt::MakeWriter;

use shekyl_dialer::{DialAim, Dialer};
use shekyl_draw_rng::SplitMix64;
use shekyl_levin::{
    response, BasicNodeData, CoreSyncData, HandshakeResponse, PeerlistEntry, PortableMap,
    SupportFlags, COMMAND_HANDSHAKE,
};
use shekyl_peer_policy::InboundCeiling;
use shekyl_peerlist::{
    CloseCause, CloseKind, ConnectorId, Direction, NetworkAddress, RefusedSet, Tick,
};
use shekyl_seam::{Hub, Post, Route, RoutePublish, SocketId, SyncPayload};
use shekyl_timing_engine::ManualClock;
use shekyl_transport_layer::Sockets;

const NETWORK: [u8; 16] = [7; 16];
const SEND_CAP: usize = 64 * 1024;

struct Rig {
    hub: Hub,
    posts: Arc<Mutex<VecDeque<Post>>>,
    dialer: Arc<Dialer>,
}

/// A hub whose adapter arms the handler on `established`, as the daemon's
/// does, from another thread: the post is made under the hub's lock.
fn hub_with_arming(posts: &Arc<Mutex<VecDeque<Post>>>) -> Hub {
    let queue = Arc::clone(posts);
    let armer: Arc<Mutex<Option<Hub>>> = Arc::new(Mutex::new(None));
    let armer_in_post = Arc::clone(&armer);
    let hub = Hub::new(
        Sockets::new(),
        InboundCeiling::Bounded(8),
        Arc::new(move |post| {
            if let Post::Established { id, .. } = &post {
                let id = *id;
                let hub = armer_in_post.lock().expect("armer").clone();
                thread::spawn(move || {
                    if let Some(hub) = hub {
                        hub.handler_armed(id, true);
                    }
                });
            }
            queue.lock().expect("posts").push_back(post);
        }),
        Arc::new(ManualClock::new(Tick::new(1))),
    );
    *armer.lock().expect("armer") = Some(hub.clone());
    hub
}

fn dialer_for(hub: &Hub) -> Arc<Dialer> {
    let dialer = Arc::new(Dialer::new(
        hub.clone(),
        RefusedSet::NON_GLOBAL,
        SupportFlags::ADVERTISED.bits(),
        Arc::new(|| {
            Some(SyncPayload {
                current_height: 10,
                cumulative_difficulty: 100,
                cumulative_difficulty_top64: 0,
                top_id: [1; 32],
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
                .publish_usable(ConnectorId::Clearnet, Route::Direct, Tick::new(1),),
            RoutePublish::Installed { .. }
        ),
        "the test route was not already usable"
    );
    dialer
}

fn rig() -> Rig {
    let posts = Arc::new(Mutex::new(VecDeque::new()));
    let hub = hub_with_arming(&posts);
    hub.install_loopback(SEND_CAP);
    let dialer = dialer_for(&hub);
    Rig { hub, posts, dialer }
}

fn peer(n: u8) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 12, 0, n),
        port: 18080,
    }
}

fn reply(network_id: [u8; 16], peers: Vec<NetworkAddress>) -> Vec<u8> {
    reply_at(network_id, peers, 20)
}

fn reply_at(network_id: [u8; 16], peers: Vec<NetworkAddress>, height: u64) -> Vec<u8> {
    let body = HandshakeResponse {
        node_data: BasicNodeData {
            network_id,
            support_flags: SupportFlags::ADVERTISED,
        },
        payload_data: CoreSyncData {
            current_height: height,
            cumulative_difficulty: 200,
            cumulative_difficulty_top64: 0,
            top_id: [2; 32],
        },
        local_peerlist_new: peers.into_iter().map(|adr| PeerlistEntry { adr }).collect(),
    };
    response(COMMAND_HANDSHAKE, &body.store().expect("encode"))
}

/// Inject `frames` into the first dialed channel as soon as it exists,
/// in order. The loopback's first admission is id 1.
fn inject_when_open(hub: &Hub, frames: Vec<Vec<u8>>) {
    let id = SocketId::from_ffi(1).expect("the first admission");
    let start = Instant::now();
    let mut frames = frames.into_iter();
    let first = frames.next().expect("one frame");
    while !hub.inject(id, first.clone()) {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the channel never opened"
        );
        thread::sleep(Duration::from_millis(2));
    }
    for frame in frames {
        assert!(hub.inject(id, frame));
    }
}

/// Run one dial on the owner's thread while the peer injects `frames`.
fn dial_with(
    rig: &Rig,
    address: &NetworkAddress,
    aim: DialAim,
    frames: Vec<Vec<u8>>,
) -> Option<SocketId> {
    let dialer = Arc::clone(&rig.dialer);
    let target = address.clone();
    let owner = thread::spawn(move || {
        dialer.dial(ConnectorId::Clearnet, &target, aim, &mut SplitMix64::new(1))
    });
    inject_when_open(&rig.hub, frames);
    owner.join().expect("owner thread")
}

fn kinds(posts: &VecDeque<Post>) -> Vec<&'static str> {
    posts
        .iter()
        .map(|post| match post {
            Post::Established { .. } => "established",
            Post::HandshakeResult { .. } => "handshake",
            Post::Deliver { .. } => "deliver",
            Post::Closed { .. } => "closed",
        })
        .collect()
}

#[test]
fn a_well_formed_response_is_adopted_and_its_result_is_posted_before_any_frame() {
    let rig = rig();
    let mut rng = SplitMix64::new(2);
    rig.dialer
        .admit_operator(&peer(1), Tick::new(1), &mut rng)
        .expect("admitted");

    // The peer answers, then sends a frame straight after. The owner
    // reads the response on the channel; the frame waits for the pump.
    let later_frame = shekyl_levin::notify(2002, b"later");
    let id = dial_with(
        &rig,
        &peer(1),
        DialAim::Keep,
        vec![reply(NETWORK, vec![peer(2), peer(3)]), later_frame],
    )
    .expect("adopted");

    // The adapter armed the handler on `established`; the pump delivers
    // the later frame only after the result post, whatever the timing.
    let start = Instant::now();
    while rig.hub.posted_deliveries(id).unwrap_or(0) == 0 {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the frame was never delivered"
        );
        thread::sleep(Duration::from_millis(2));
    }
    let posts = rig.posts.lock().expect("posts");
    assert_eq!(kinds(&posts), vec!["established", "handshake", "deliver"]);
    let Some(Post::HandshakeResult {
        id: posted,
        keep,
        support_flags,
        sync,
        ..
    }) = posts.get(1)
    else {
        panic!("the second post is the handshake result");
    };
    assert_eq!(*posted, id);
    assert!(keep);
    assert_eq!(*support_flags, SupportFlags::ADVERTISED.bits());
    assert_eq!(sync.current_height, 20);
    assert_eq!(sync.top_id, [2; 32]);
    drop(posts);

    // The seam's established flag is the strand's. This poster arms the
    // handler and does not run on_outbound_handshake, so the flag stays
    // clear. The dialer has already accepted.
    let row = rig.hub.board().get(id).copied().expect("adopted row");
    assert_eq!(row.direction(), Direction::Outbound);
    assert!(!row.established());

    // The peer's sample entered gray. The drawn address is white: the
    // dialer recorded SessionAccepted before it returned.
    let shared = rig.dialer.shared();
    assert!(shared.lists.is_gray(&peer(2)) && shared.lists.is_gray(&peer(3)));
    assert!(shared.lists.is_white(&peer(1)));
    drop(shared);
    assert_eq!(rig.dialer.in_flight(ConnectorId::Clearnet), 0);
    assert_eq!(rig.dialer.kept_sessions(ConnectorId::Clearnet), 1);
}

#[test]
fn an_accepted_keep_is_session_accepted_and_the_session_stays() {
    let rig = rig();
    let mut rng = SplitMix64::new(3);
    rig.dialer
        .admit_operator(&peer(1), Tick::new(1), &mut rng)
        .expect("admitted");
    let id =
        dial_with(&rig, &peer(1), DialAim::Keep, vec![reply(NETWORK, vec![])]).expect("adopted");

    let shared = rig.dialer.shared();
    assert!(
        shared.lists.is_white(&peer(1)),
        "SessionAccepted wrote white before the dial returned"
    );
    drop(shared);
    assert_eq!(rig.dialer.in_flight(ConnectorId::Clearnet), 0);
    assert_eq!(rig.dialer.kept_sessions(ConnectorId::Clearnet), 1);
    assert!(rig.hub.cause(id).is_none(), "the session was not closed");
    assert!(!kinds(&rig.posts.lock().expect("posts")).contains(&"closed"));
}

#[test]
fn a_confirm_of_a_peer_far_ahead_records_white_and_posts_nothing() {
    let rig = rig();
    let mut rng = SplitMix64::new(4);
    rig.dialer
        .admit_operator(&peer(1), Tick::new(1), &mut rng)
        .expect("admitted");
    // Far ahead of our height 10. Rust does not ask C++ about the height,
    // so nothing is adopted and nothing requests the chain.
    let id = dial_with(
        &rig,
        &peer(1),
        DialAim::Confirm,
        vec![reply_at(NETWORK, vec![], 1_000_000)],
    );
    assert!(id.is_none(), "a confirm dial finishes in Rust");
    assert!(rig.hub.board().is_empty(), "a confirm dial is not adopted");
    assert!(
        rig.posts.lock().expect("posts").is_empty(),
        "a confirm dial posts nothing"
    );
    let shared = rig.dialer.shared();
    assert!(shared.lists.is_white(&peer(1)), "Confirmed wrote white");
    drop(shared);
    assert_eq!(
        rig.dialer.in_flight(ConnectorId::Clearnet),
        0,
        "the in-flight count is 0 before any strand turn"
    );
}

#[test]
fn a_session_refused_close_drops_the_kept_row_and_leaves_white() {
    let rig = rig();
    let mut rng = SplitMix64::new(5);
    rig.dialer
        .admit_operator(&peer(1), Tick::new(1), &mut rng)
        .expect("admitted");
    let id =
        dial_with(&rig, &peer(1), DialAim::Keep, vec![reply(NETWORK, vec![])]).expect("adopted");
    assert!(rig.dialer.shared().lists.is_white(&peer(1)));
    assert_eq!(rig.dialer.kept_sessions(ConnectorId::Clearnet), 1);

    // The payload owner closes with SessionRefused. That close is the
    // lists' PayloadRefused. White was written when the dial returned.
    rig.dialer
        .session_closed(id, CloseCause::new(CloseKind::SessionRefused), &mut rng);
    let shared = rig.dialer.shared();
    assert!(
        shared.lists.is_white(&peer(1)),
        "PayloadRefused does not demote white"
    );
    drop(shared);
    assert_eq!(rig.dialer.kept_sessions(ConnectorId::Clearnet), 0);
    assert_eq!(rig.dialer.in_flight(ConnectorId::Clearnet), 0);
}

#[test]
fn another_network_is_a_rejected_handshake_with_no_row_and_no_post() {
    let rig = rig();
    let mut rng = SplitMix64::new(6);
    rig.dialer
        .admit_operator(&peer(1), Tick::new(1), &mut rng)
        .expect("admitted");
    let adopted = dial_with(&rig, &peer(1), DialAim::Keep, vec![reply([9; 16], vec![])]);
    assert!(adopted.is_none());
    assert!(rig.hub.board().is_empty(), "nothing was adopted");
    assert!(
        rig.posts.lock().expect("posts").is_empty(),
        "nothing was posted"
    );
    let shared = rig.dialer.shared();
    assert!(
        !shared.lists.is_gray(&peer(1)),
        "DialFailed drops the outstanding draw"
    );
    assert!(!shared.lists.is_white(&peer(1)));
    assert!(
        !shared.memory.is_recently_failed(&peer(1), Tick::new(1)),
        "a clearnet rejection writes no memory (R2)"
    );
}

#[test]
fn a_refused_peerlist_is_peerlist_refused_with_no_row() {
    let rig = rig();
    let mut rng = SplitMix64::new(7);
    rig.dialer
        .admit_operator(&peer(1), Tick::new(1), &mut rng)
        .expect("admitted");
    let private = NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(192, 168, 1, 1),
        port: 18080,
    };
    let adopted = dial_with(
        &rig,
        &peer(1),
        DialAim::Keep,
        vec![reply(NETWORK, vec![peer(2), private])],
    );
    assert!(adopted.is_none());
    assert!(rig.hub.board().is_empty());
    let shared = rig.dialer.shared();
    assert!(
        !shared.lists.is_gray(&peer(2)),
        "R4: none of the list entered gray"
    );
    assert!(!shared.lists.is_gray(&peer(1)), "the draw was dropped");
}

#[test]
fn a_dial_that_cannot_open_is_dial_failed_with_the_cause() {
    let posts = Arc::new(Mutex::new(VecDeque::new()));
    let queue = Arc::clone(&posts);
    // No connector is installed on this hub: a dial that is made is
    // LocalClose. The tip is published, so the failure is that missing
    // connector. Without a tip the dial would return before the draw.
    let hub = Hub::new(
        Sockets::new(),
        InboundCeiling::Bounded(8),
        Arc::new(move |post| queue.lock().expect("posts").push_back(post)),
        Arc::new(ManualClock::new(Tick::new(1))),
    );
    let dialer = Dialer::new(
        hub.clone(),
        RefusedSet::NON_GLOBAL,
        SupportFlags::ADVERTISED.bits(),
        Arc::new(|| {
            Some(SyncPayload {
                current_height: 10,
                cumulative_difficulty: 100,
                cumulative_difficulty_top64: 0,
                top_id: [1; 32],
            })
        }),
    );
    dialer.set_network_id(NETWORK);
    // The link is usable: the plan draws only then (TSR-F1).
    assert!(
        matches!(
            dialer
                .hub()
                .links()
                .publish_usable(ConnectorId::Clearnet, Route::Direct, Tick::new(1),),
            RoutePublish::Installed { .. }
        ),
        "the test route was not already usable"
    );
    let mut rng = SplitMix64::new(8);
    dialer
        .admit_operator(&peer(1), Tick::new(1), &mut rng)
        .expect("admitted");
    assert!(dialer
        .dial(ConnectorId::Clearnet, &peer(1), DialAim::Keep, &mut rng)
        .is_none());
    assert!(hub.board().is_empty());
    assert!(
        !dialer.shared().lists.is_gray(&peer(1)),
        "the draw was dropped"
    );
}

#[test]
fn a_synchronous_handshake_post_sees_the_kept_session_and_follows_established() {
    let seen = Arc::new(Mutex::new(None));
    let seen_post = Arc::clone(&seen);
    let slot: Arc<Mutex<Option<Arc<Dialer>>>> = Arc::new(Mutex::new(None));
    let slot_post = Arc::clone(&slot);
    let posts = Arc::new(Mutex::new(VecDeque::new()));
    let posts_in = Arc::clone(&posts);
    let armer: Arc<Mutex<Option<Hub>>> = Arc::new(Mutex::new(None));
    let armer_in = Arc::clone(&armer);
    let hub = Hub::new(
        Sockets::new(),
        InboundCeiling::Bounded(8),
        Arc::new(move |post| {
            if let Post::Established { id, .. } = &post {
                let id = *id;
                let hub = armer_in.lock().expect("armer").clone();
                thread::spawn(move || {
                    if let Some(hub) = hub {
                        hub.handler_armed(id, true);
                    }
                });
            }
            if let Post::HandshakeResult { .. } = &post {
                if let Some(dialer) = slot_post.lock().expect("slot").clone() {
                    *seen_post.lock().expect("seen") = Some((
                        dialer.in_flight(ConnectorId::Clearnet),
                        dialer.kept_sessions(ConnectorId::Clearnet),
                    ));
                }
            }
            posts_in.lock().expect("posts").push_back(post);
        }),
        Arc::new(ManualClock::new(Tick::new(1))),
    );
    *armer.lock().expect("armer") = Some(hub.clone());
    hub.install_loopback(SEND_CAP);
    let dialer = dialer_for(&hub);
    *slot.lock().expect("slot") = Some(Arc::clone(&dialer));
    let mut rng = SplitMix64::new(11);
    dialer
        .admit_operator(&peer(1), Tick::new(1), &mut rng)
        .expect("admitted");
    let rig = Rig { hub, posts, dialer };
    dial_with(&rig, &peer(1), DialAim::Keep, vec![reply(NETWORK, vec![])]).expect("kept");
    assert_eq!(
        *seen.lock().expect("seen"),
        Some((0, 1)),
        "the handshake notification already sees the kept session"
    );
    let posts = rig.posts.lock().expect("posts");
    let order = kinds(&posts);
    let established = order.iter().position(|kind| *kind == "established");
    let handshake = order.iter().position(|kind| *kind == "handshake");
    assert!(
        established < handshake,
        "established precedes the handshake notification: {order:?}"
    );
}

#[test]
fn a_synchronous_close_notification_finishes() {
    let slot: Arc<Mutex<Option<Arc<Dialer>>>> = Arc::new(Mutex::new(None));
    let slot_post = Arc::clone(&slot);
    let hub_slot: Arc<Mutex<Option<Hub>>> = Arc::new(Mutex::new(None));
    let hub_in_post = Arc::clone(&hub_slot);
    let (done_tx, done_rx) = mpsc::channel();
    let hub = Hub::new(
        Sockets::new(),
        InboundCeiling::Bounded(8),
        Arc::new(move |post| {
            if let Post::Closed { id, cause, .. } = &post {
                if let Some(dialer) = slot_post.lock().expect("slot").clone() {
                    dialer.session_closed(*id, *cause, &mut SplitMix64::new(12));
                }
                // The strand's closed path locks the table again
                // (`shekyl_seam_handler_gone`). A poster that runs under
                // that lock does not return.
                if let Some(hub) = hub_in_post.lock().expect("hub").clone() {
                    hub.handler_gone(*id);
                }
                let _sent = done_tx.send(());
            }
        }),
        Arc::new(ManualClock::new(Tick::new(1))),
    );
    *hub_slot.lock().expect("hub") = Some(hub.clone());
    hub.install_loopback(SEND_CAP);
    let dialer = dialer_for(&hub);
    *slot.lock().expect("slot") = Some(Arc::clone(&dialer));
    let mut rng = SplitMix64::new(13);
    dialer
        .admit_operator(&peer(1), Tick::new(1), &mut rng)
        .expect("admitted");
    let posts = Arc::new(Mutex::new(VecDeque::new()));
    let rig = Rig {
        hub: hub.clone(),
        posts,
        dialer: Arc::clone(&dialer),
    };
    let id = dial_with(&rig, &peer(1), DialAim::Keep, vec![reply(NETWORK, vec![])]).expect("kept");
    let closer = thread::spawn(move || hub.close(id));
    if done_rx.recv_timeout(Duration::from_secs(5)).is_err() {
        eprintln!("a synchronous close notification did not finish within 5s");
        std::process::exit(1);
    }
    closer.join().expect("closer");
    assert_eq!(dialer.kept_sessions(ConnectorId::Clearnet), 0);
}

struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("log").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl MakeWriter<'_> for LogBuf {
    type Writer = LogBuf;

    fn make_writer(&self) -> Self::Writer {
        LogBuf(Arc::clone(&self.0))
    }
}

fn warn_text(run: impl FnOnce()) -> String {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .with_writer(LogBuf(Arc::clone(&buf)))
        .finish();
    tracing::subscriber::with_default(subscriber, run);
    let bytes = buf.lock().expect("log").clone();
    String::from_utf8(bytes).expect("utf-8")
}

fn warn_count(text: &str, needle: &str) -> usize {
    text.matches(needle).count()
}

#[test]
fn an_idle_connector_warns_once_at_sixty_wakes_and_again_after_the_reason_changes() {
    let rig = rig();
    assert!(rig.dialer.target(ConnectorId::Clearnet) > 0);
    let mut rng = SplitMix64::new(14);
    let text = warn_text(|| {
        for _ in 0..59 {
            assert!(!rig.dialer.wake(ConnectorId::Clearnet, &mut rng));
        }
    });
    assert_eq!(
        warn_count(&text, "nothing dialed"),
        0,
        "59 under-target wakes stay quiet: {text}"
    );
    let text = warn_text(|| {
        for _ in 0..60 {
            assert!(!rig.dialer.wake(ConnectorId::Clearnet, &mut rng));
        }
    });
    assert_eq!(
        warn_count(&text, "nothing dialed: no candidate"),
        1,
        "the 60th wake warns once: {text}"
    );
    let text = warn_text(|| {
        assert!(!rig.dialer.wake(ConnectorId::Clearnet, &mut rng));
    });
    assert_eq!(
        warn_count(&text, "nothing dialed"),
        0,
        "a further wake with the same reason stays quiet: {text}"
    );

    let target = rig.dialer.target(ConnectorId::Clearnet);
    rig.dialer.set_target(ConnectorId::Clearnet, 0, &mut rng);
    assert!(!rig.dialer.wake(ConnectorId::Clearnet, &mut rng));
    rig.dialer
        .set_target(ConnectorId::Clearnet, target, &mut rng);
    let text = warn_text(|| {
        for _ in 0..59 {
            assert!(!rig.dialer.wake(ConnectorId::Clearnet, &mut rng));
        }
    });
    assert_eq!(
        warn_count(&text, "nothing dialed"),
        0,
        "leaving the idle state resets the count: {text}"
    );
    let text = warn_text(|| {
        assert!(!rig.dialer.wake(ConnectorId::Clearnet, &mut rng));
    });
    assert_eq!(warn_count(&text, "nothing dialed: no candidate"), 1);
}

#[test]
fn a_filter_is_named_apart_from_an_empty_list() {
    let rig = rig();
    let mut rng = SplitMix64::new(15);
    rig.dialer
        .set_own_addresses(ConnectorId::Clearnet, vec![peer(1)]);
    rig.dialer
        .admit_operator(&peer(1), Tick::new(1), &mut rng)
        .expect("admitted");
    let text = warn_text(|| {
        for _ in 0..60 {
            assert!(!rig.dialer.wake(ConnectorId::Clearnet, &mut rng));
        }
    });
    assert_eq!(
        warn_count(&text, "a filter holds every address"),
        1,
        "{text}"
    );
    assert_eq!(warn_count(&text, "no candidate"), 0, "{text}");
}

#[test]
fn an_in_flight_dial_is_named_ahead_of_an_empty_draw() {
    let rig = rig();
    let mut rng = SplitMix64::new(16);
    rig.dialer
        .admit_operator(&peer(1), Tick::new(1), &mut rng)
        .expect("admitted");
    let dialer = Arc::clone(&rig.dialer);
    let owner = thread::spawn(move || {
        dialer.dial(
            ConnectorId::Clearnet,
            &peer(1),
            DialAim::Keep,
            &mut SplitMix64::new(17),
        )
    });
    let start = Instant::now();
    while rig.dialer.in_flight(ConnectorId::Clearnet) == 0 {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the dial never started"
        );
        thread::sleep(Duration::from_millis(2));
    }
    let text = warn_text(|| {
        for _ in 0..60 {
            assert!(!rig.dialer.wake(ConnectorId::Clearnet, &mut rng));
        }
    });
    assert_eq!(warn_count(&text, "a dial is in flight"), 1, "{text}");
    assert_eq!(warn_count(&text, "no candidate"), 0, "{text}");
    inject_when_open(&rig.hub, vec![reply(NETWORK, vec![])]);
    owner.join().expect("dial").expect("kept");
}
