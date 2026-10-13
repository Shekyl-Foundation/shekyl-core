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
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use shekyl_dialer::{DialAim, Dialer};
use shekyl_draw_rng::SplitMix64;
use shekyl_levin::{
    response, BasicNodeData, CoreSyncData, HandshakeResponse, PeerlistEntry, PortableMap,
    SupportFlags, COMMAND_HANDSHAKE,
};
use shekyl_peer_policy::InboundCeiling;
use shekyl_peerlist::{ConnectorId, Direction, NetworkAddress, RefusedSet, Tick};
use shekyl_seam::{Hub, Post, SocketId, SyncPayload};
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

fn rig() -> Rig {
    let posts = Arc::new(Mutex::new(VecDeque::new()));
    let hub = hub_with_arming(&posts);
    hub.install_loopback(SEND_CAP);
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
    Rig { hub, posts, dialer }
}

fn peer(n: u8) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 12, 0, n),
        port: 18080,
    }
}

fn reply(network_id: [u8; 16], peers: Vec<NetworkAddress>) -> Vec<u8> {
    let body = HandshakeResponse {
        node_data: BasicNodeData {
            network_id,
            support_flags: SupportFlags::ADVERTISED,
        },
        payload_data: CoreSyncData {
            current_height: 20,
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

    // The row exists and is not yet established: the strand decides.
    let row = rig.hub.board().get(id).copied().expect("adopted row");
    assert_eq!(row.direction(), Direction::Outbound);
    assert!(!row.established());

    // The peer's sample entered gray; the drawn address is still gray.
    let shared = rig.dialer.shared();
    assert!(shared.lists.is_gray(&peer(2)) && shared.lists.is_gray(&peer(3)));
    assert!(
        !shared.lists.is_white(&peer(1)),
        "white waits for the verdict"
    );
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

    rig.dialer.verdict(id, true, &mut rng);
    let shared = rig.dialer.shared();
    assert!(
        shared.lists.is_white(&peer(1)),
        "SessionAccepted wrote white"
    );
    drop(shared);
    assert!(rig.hub.cause(id).is_none(), "the session was not closed");
    assert!(!kinds(&rig.posts.lock().expect("posts")).contains(&"closed"));
}

#[test]
fn an_accepted_confirm_is_confirmed_and_closed_in_that_turn() {
    let rig = rig();
    let mut rng = SplitMix64::new(4);
    rig.dialer
        .admit_operator(&peer(1), Tick::new(1), &mut rng)
        .expect("admitted");
    let id = dial_with(
        &rig,
        &peer(1),
        DialAim::Confirm,
        vec![reply(NETWORK, vec![])],
    )
    .expect("adopted");
    let posts = rig.posts.lock().expect("posts");
    let Some(Post::HandshakeResult { keep, .. }) = posts.get(1) else {
        panic!("the result was posted");
    };
    assert!(!keep, "a confirm dial says so in its post");
    drop(posts);

    rig.dialer.verdict(id, true, &mut rng);
    let shared = rig.dialer.shared();
    assert!(shared.lists.is_white(&peer(1)), "Confirmed wrote white");
    drop(shared);
    assert!(rig.hub.cause(id).is_some(), "the owner closed the session");
}

#[test]
fn a_refused_payload_leaves_the_draw_on_gray_and_closes() {
    let rig = rig();
    let mut rng = SplitMix64::new(5);
    rig.dialer
        .admit_operator(&peer(1), Tick::new(1), &mut rng)
        .expect("admitted");
    let id =
        dial_with(&rig, &peer(1), DialAim::Keep, vec![reply(NETWORK, vec![])]).expect("adopted");

    rig.dialer.verdict(id, false, &mut rng);
    let shared = rig.dialer.shared();
    assert!(
        shared.lists.is_gray(&peer(1)),
        "PayloadRefused leaves the address on gray"
    );
    assert!(!shared.lists.is_white(&peer(1)));
    drop(shared);
    assert!(rig.hub.cause(id).is_some(), "the session was closed");
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
    // No dialer installed on this hub: every dial is LocalClose.
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
        Arc::new(|| None),
    );
    dialer.set_network_id(NETWORK);
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
