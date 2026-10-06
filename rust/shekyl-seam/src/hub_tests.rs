// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use shekyl_capped_stream::{FrameSender, StreamEnds};
use shekyl_peer_policy::InboundCeiling;
use shekyl_timing_engine::{Clock, ManualClock, Tick};
use shekyl_transport_layer::{CloseCause, CloseKind, CloseResult, ConnectorId, Direction, Sockets};

use super::{Hub, Phase, Post};
use crate::drive_inbound;
use crate::endpoint::{admit, Endpoint};

fn endpoint(ip: Ipv4Addr, direction: Direction) -> Endpoint {
    Endpoint::Clearnet {
        ip: IpAddr::V4(ip),
        port: 18080,
        direction,
    }
}

struct Rig {
    hub: Hub,
    posts: Arc<Mutex<VecDeque<Post>>>,
    clock: ManualClock,
}

fn rig() -> Rig {
    let posts = Arc::new(Mutex::new(VecDeque::new()));
    let clock = ManualClock::new(Tick::new(1));
    let hub = Hub::new(
        Sockets::new(),
        InboundCeiling::Bounded(8),
        queue_poster(&posts),
        Arc::new(clock.clone()),
    );
    Rig { hub, posts, clock }
}

fn queue_poster(queue: &Arc<Mutex<VecDeque<Post>>>) -> Arc<dyn Fn(Post) + Send + Sync> {
    let queue = Arc::clone(queue);
    Arc::new(move |post| {
        queue.lock().expect("posts").push_back(post);
    })
}

fn doc_ip() -> Ipv4Addr {
    Ipv4Addr::new(203, 0, 113, 10)
}

struct Opened {
    id: shekyl_transport_layer::SocketId,
    inbound: FrameSender,
    writer: shekyl_capped_stream::ByteQueue,
    _hold: shekyl_capped_stream::QueueHold,
    session: Option<shekyl_capped_stream::Session>,
}

fn adopt(rig: &Rig, direction: Direction, cap: usize) -> Opened {
    let ends = StreamEnds::open(cap);
    let inbound = ends.inbound.clone();
    let writer = ends.writer_queue.clone();
    let hold = ends.hold;
    let endpoint = endpoint(doc_ip(), direction);
    let now = rig.clock.now();
    let ceiling = rig.hub.lock().ceiling;
    let sockets = rig.hub.lock().sockets.clone();
    let open = admit(&sockets, &endpoint, now, ceiling).expect("admit");
    let attached = rig
        .hub
        .adopt(open, ends.session, endpoint, None)
        .expect("adopt");
    Opened {
        id: attached.id,
        inbound,
        writer,
        _hold: hold,
        session: Some(attached.session),
    }
}

fn service(rig: &Rig, accepted: bool) {
    let next = rig.posts.lock().expect("posts").pop_front();
    let Some(post) = next else {
        return;
    };
    match post {
        Post::Established { id, .. } => rig.hub.handler_armed(id, true),
        Post::Deliver { id, .. } => rig.hub.delivery_finished(id, accepted),
        Post::Closed { id, .. } => {
            rig.hub.handler_gone(id);
            rig.hub.reap(id);
        }
    }
}

#[test]
fn a_delivery_posted_before_closed_is_parsed() {
    let rig = rig();
    let mut opened = adopt(&rig, Direction::Outbound, 32);
    service(&rig, true);
    let session = opened.session.take().expect("session");
    let hub = rig.hub.clone();
    let id = opened.id;
    let pump = thread::spawn(move || drive_inbound(&hub, id, session));
    opened
        .inbound
        .blocking_send(b"hello".to_vec())
        .expect("inject");
    let before = 0;
    assert!(rig.hub.wait_delivery_posted(id, before));
    rig.hub.close(id);
    let kinds: Vec<_> = rig
        .posts
        .lock()
        .expect("posts")
        .iter()
        .map(|post| match post {
            Post::Deliver { .. } => Phase::Delivering,
            Post::Closed { .. } => Phase::Closed,
            Post::Established { .. } => Phase::Arming,
        })
        .collect();
    assert_eq!(kinds, vec![Phase::Delivering, Phase::Closed]);
    service(&rig, true);
    service(&rig, true);
    pump.join().expect("pump");
    assert!(rig.hub.cause(id).is_none());
}

/// The adapter routes every post by connector. A Tor row's deliveries
/// and close must say Tor, or they land on the clearnet binding and
/// vanish after `Established` — which is how an inbound onion
/// connection sat silent until its gap timer fired.
#[test]
fn a_tor_row_posts_deliver_and_closed_with_the_tor_connector() {
    let rig = rig();
    let ends = StreamEnds::open(32);
    let inbound = ends.inbound.clone();
    let _hold = ends.hold;
    let endpoint = Endpoint::TorInbound;
    let ceiling = rig.hub.lock().ceiling;
    let sockets = rig.hub.lock().sockets.clone();
    let open = admit(&sockets, &endpoint, rig.clock.now(), ceiling).expect("admit");
    let attached = rig
        .hub
        .adopt(open, ends.session, endpoint, None)
        .expect("adopt");
    let id = attached.id;
    service(&rig, true);
    let hub = rig.hub.clone();
    let pump = thread::spawn(move || drive_inbound(&hub, id, attached.session));
    inbound.blocking_send(b"onion".to_vec()).expect("inject");
    assert!(rig.hub.wait_delivery_posted(id, 0));
    rig.hub.close(id);
    let connectors: Vec<_> = rig
        .posts
        .lock()
        .expect("posts")
        .iter()
        .map(|post| match post {
            Post::Deliver { connector, .. } | Post::Closed { connector, .. } => *connector,
            Post::Established { .. } => unreachable!("serviced above"),
        })
        .collect();
    assert_eq!(connectors, vec![ConnectorId::Tor, ConnectorId::Tor]);
    service(&rig, true);
    service(&rig, true);
    pump.join().expect("pump");
}

/// The zone hands its runtime one blocking lane. A blocking drive per
/// connection filled that lane with the first connection and left the
/// second deaf until the first closed; the async drive holds no thread,
/// so both deliver on a runtime with one worker and one blocking lane.
#[test]
fn two_connections_deliver_on_one_blocking_lane() {
    let rig = rig();
    let first = adopt(&rig, Direction::Inbound, 32);
    let second = adopt(&rig, Direction::Outbound, 32);
    service(&rig, true);
    service(&rig, true);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .max_blocking_threads(1)
        .build()
        .expect("runtime");
    let mut drivers = Vec::new();
    let mut first = first;
    let mut second = second;
    for (id, session) in [
        (first.id, first.session.take().expect("first session")),
        (second.id, second.session.take().expect("second session")),
    ] {
        let hub = rig.hub.clone();
        drivers.push(runtime.spawn(async move {
            crate::drive_inbound_async(&hub, id, session).await;
        }));
    }
    first
        .inbound
        .blocking_send(b"one".to_vec())
        .expect("inject first");
    second
        .inbound
        .blocking_send(b"two".to_vec())
        .expect("inject second");
    // Both Deliver posts must be queued while neither strand has answered:
    // the first driver is waiting on its strand, and the second still ran.
    assert!(rig.hub.wait_delivery_posted(first.id, 0));
    assert!(rig.hub.wait_delivery_posted(second.id, 0));
    let posted: Vec<_> = rig
        .posts
        .lock()
        .expect("posts")
        .iter()
        .filter_map(|post| match post {
            Post::Deliver { id, .. } => Some(*id),
            _ => None,
        })
        .collect();
    assert_eq!(posted.len(), 2);
    assert!(posted.contains(&first.id) && posted.contains(&second.id));
    rig.hub.close(first.id);
    rig.hub.close(second.id);
    while rig.posts.lock().expect("posts").front().is_some() {
        service(&rig, true);
    }
    for driver in drivers {
        runtime.block_on(driver).expect("driver");
    }
}

#[test]
fn send_after_close_keeps_the_first_cause() {
    let rig = rig();
    let opened = adopt(&rig, Direction::Outbound, 32);
    rig.hub.close(opened.id);
    assert!(!rig.hub.send(opened.id, b"more".to_vec()));
    rig.hub.close(opened.id);
    assert_eq!(
        rig.hub.cause(opened.id).map(CloseCause::kind),
        Some(CloseKind::LocalClose)
    );
}

#[test]
fn a_message_that_does_not_fit_is_send_queue_full() {
    let rig = rig();
    let opened = adopt(&rig, Direction::Outbound, 4);
    assert!(rig.hub.send(opened.id, b"ab".to_vec()));
    assert!(!rig.hub.send(opened.id, b"cdef".to_vec()));
    assert_eq!(
        rig.hub.cause(opened.id).map(CloseCause::kind),
        Some(CloseKind::SendQueueFull)
    );
    rig.hub.delivery_finished(opened.id, false);
    assert_eq!(
        rig.hub.cause(opened.id).map(CloseCause::kind),
        Some(CloseKind::SendQueueFull)
    );
}

#[test]
fn a_refused_delivery_is_session_refused() {
    let rig = rig();
    let mut opened = adopt(&rig, Direction::Inbound, 32);
    service(&rig, true);
    let session = opened.session.take().expect("session");
    let hub = rig.hub.clone();
    let id = opened.id;
    let pump = thread::spawn(move || drive_inbound(&hub, id, session));
    opened
        .inbound
        .blocking_send(b"no".to_vec())
        .expect("inject");
    assert!(rig.hub.wait_delivery_posted(id, 0));
    service(&rig, false);
    pump.join().expect("pump");
    assert_eq!(
        rig.hub.cause(id).map(CloseCause::kind),
        Some(CloseKind::SessionRefused)
    );
}

#[test]
fn socket_count_is_outbound_and_inbound_held_leaves_it_out() {
    let rig = rig();
    let _opened = adopt(&rig, Direction::Outbound, 32);
    assert_eq!(
        rig.hub
            .socket_count(ConnectorId::Clearnet, Direction::Outbound),
        1
    );
    assert_eq!(rig.hub.inbound_held(), 0);
}

#[test]
fn a_relay_send_reaches_the_seam_connection() {
    let rig = rig();
    let opened = adopt(&rig, Direction::Outbound, 64);
    let report = rig.hub.send_report(opened.id, b"relay-send".to_vec());
    assert!(report.found);
    assert!(report.accepted);
    assert!(report.cause.is_none());
    let missing = shekyl_transport_layer::SocketId::from_ffi(9).expect("id");
    let absent = rig.hub.send_report(missing, b"relay-send".to_vec());
    assert!(!absent.found);
    assert!(!absent.accepted);
}

#[test]
fn a_zero_ceiling_refuses_inbound() {
    let rig = rig();
    rig.hub.set_ceiling(InboundCeiling::Bounded(0));
    let ends = StreamEnds::open(32);
    let endpoint = endpoint(doc_ip(), Direction::Inbound);
    let now = rig.clock.now();
    let err = admit(
        &rig.hub.lock().sockets,
        &endpoint,
        now,
        InboundCeiling::Bounded(0),
    )
    .expect_err("ceiling");
    assert_eq!(err.kind(), CloseKind::InboundNotAccepted);
    drop(ends);
}

#[test]
fn replacing_the_dialer_joins_the_pump_and_the_next_hub_keeps_the_id() {
    let sockets = Sockets::new();
    let posts = Arc::new(Mutex::new(VecDeque::new()));
    let clock = ManualClock::new(Tick::new(1));
    let first = Hub::new(
        sockets.clone(),
        InboundCeiling::Bounded(8),
        queue_poster(&posts),
        Arc::new(clock.clone()),
    );
    first.install_loopback(32);
    let endpoint = endpoint(doc_ip(), Direction::Outbound);
    let attached = first.connect(&endpoint).expect("open");
    let id = attached.id;
    let hub = first.clone();
    let pump = thread::spawn(move || drive_inbound(&hub, id, attached.session));
    first.track_pump(id, pump);
    first.install_loopback(32);
    first.shutdown();
    assert!(first.cause(id).is_none());
    let second = Hub::new(
        sockets,
        InboundCeiling::Bounded(8),
        queue_poster(&posts),
        Arc::new(clock),
    );
    second.install_loopback(32);
    let again = second.connect(&endpoint).expect("next id");
    assert_ne!(again.id, id);
    drop(again);
    second.shutdown();
}

#[test]
fn a_banned_clearnet_host_is_admission_refused_until_the_deadline() {
    let rig = rig();
    rig.hub.install_loopback(32);
    let endpoint = endpoint(doc_ip(), Direction::Outbound);
    let first = rig.hub.connect(&endpoint).expect("open");
    let closed = rig.hub.ban_host(IpAddr::V4(doc_ip()), Tick::new(50));
    assert_eq!(closed, vec![first.id]);
    drop(first);
    let Err(banned) = rig.hub.connect(&endpoint) else {
        panic!("a banned host was admitted");
    };
    assert_eq!(banned.kind(), CloseKind::AdmissionRefused);
    rig.clock.set(Tick::new(50));
    let again = rig.hub.connect(&endpoint).expect("expired");
    drop(again);
}

#[test]
fn a_transport_close_does_not_ban_the_host() {
    let host = doc_ip();
    for kind in CloseKind::ALL {
        let rig = rig();
        let opened = adopt(&rig, Direction::Outbound, 32);
        let cause = if *kind == CloseKind::ProxyRefused {
            CloseCause::proxy_refused(1)
        } else {
            CloseCause::new(*kind)
        };
        assert!(matches!(
            rig.hub.finish(opened.id, cause),
            CloseResult::Recorded(_)
        ));
        assert!(
            !rig.hub.is_banned(IpAddr::V4(host)),
            "{kind:?} banned the host"
        );
    }
}

#[test]
fn established_carries_the_endpoint() {
    let rig = rig();
    let _opened = adopt(&rig, Direction::Outbound, 32);
    let post = rig.posts.lock().expect("posts").pop_front().expect("post");
    let Post::Established {
        endpoint: observed, ..
    } = post
    else {
        panic!("established is the first post");
    };
    assert_eq!(observed, endpoint(doc_ip(), Direction::Outbound));
}

#[test]
fn send_is_readable_by_the_connector_writer() {
    let rig = rig();
    let opened = adopt(&rig, Direction::Outbound, 32);
    assert!(rig.hub.send(opened.id, b"hello".to_vec()));
    let bytes = opened.writer.try_pop().expect("queued");
    opened.writer.release(bytes.len());
    assert_eq!(bytes, b"hello");
}

#[test]
fn a_failed_arm_unblocks_the_waiter() {
    let rig = rig();
    let opened = adopt(&rig, Direction::Outbound, 32);
    let hub = rig.hub.clone();
    let id = opened.id;
    let waiter = thread::spawn(move || hub.await_armed(id));
    let post = rig.posts.lock().expect("posts").pop_front().expect("post");
    let Post::Established { id, .. } = post else {
        panic!("established");
    };
    rig.hub.handler_armed(id, false);
    assert!(!waiter.join().expect("waiter"));
    assert_eq!(
        rig.hub.cause(id).map(CloseCause::kind),
        Some(CloseKind::LocalClose)
    );
}

/// A close that starts on the caller's side reaches the connector's
/// writer: its next pop is the local-close reason at once — the queued
/// tail is discarded, not drained — so the connection task ends and the socket
/// is dropped. Before this the writer parked until the peer sent a
/// frame; on the wire the socket stayed open for the whole interval.
#[test]
fn a_local_close_ends_the_writer() {
    let rig = rig();
    let opened = adopt(&rig, Direction::Outbound, 32);
    service(&rig, true);
    assert!(rig.hub.send(opened.id, b"reply".to_vec()));
    rig.hub.close(opened.id);
    let writer = opened.writer.clone();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        drop(done_tx.send(writer.pop_blocking()));
    });
    let ended = done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("writer still parked after a local close");
    assert!(
        matches!(ended, Err(shekyl_capped_stream::CloseReason::Local)),
        "queued tail not discarded on a local close: {ended:?}"
    );
    assert_eq!(
        rig.hub.cause(opened.id).map(CloseCause::kind),
        Some(CloseKind::LocalClose)
    );
}

#[test]
fn reap_forgets_the_row() {
    let rig = rig();
    let opened = adopt(&rig, Direction::Outbound, 32);
    rig.hub.close(opened.id);
    rig.hub.reap(opened.id);
    assert!(rig.hub.cause(opened.id).is_none());
    assert!(!rig.hub.send(opened.id, b"late".to_vec()));
}

#[test]
fn connect_without_a_dialer_is_dial_failed() {
    let rig = rig();
    let Err(err) = rig.hub.connect(&endpoint(doc_ip(), Direction::Outbound)) else {
        panic!("connect without a dialer admitted a channel");
    };
    assert_eq!(err.kind(), CloseKind::DialFailed);
}

#[test]
fn the_board_is_the_sessions_and_a_held_board_does_not_move() {
    let rig = rig();
    assert!(rig.hub.board().is_empty());
    let inbound = adopt(&rig, Direction::Inbound, 32);
    let outbound = adopt(&rig, Direction::Outbound, 32);
    let held = rig.hub.board();
    assert_eq!(held.len(), 2);
    assert_eq!(held.direction_count(Direction::Inbound), 1);
    assert_eq!(held.direction_count(Direction::Outbound), 1);
    let inbound_row = held.get(inbound.id).expect("inbound");
    assert_eq!(inbound_row.connector(), ConnectorId::Clearnet);
    assert_eq!(inbound_row.direction(), Direction::Inbound);
    assert!(!inbound_row.established());
    assert_eq!(
        inbound_row.endpoint(),
        endpoint(doc_ip(), Direction::Inbound)
    );

    rig.hub.session_established(inbound.id);
    assert!(!held.get(inbound.id).expect("held").established());
    let live = rig.hub.board();
    assert!(live.get(inbound.id).expect("live").established());
    // The handshake flag is not the dial-cap count.
    assert_eq!(live.direction_count(Direction::Inbound), 1);

    rig.hub.close(inbound.id);
    assert!(rig.hub.board().get(inbound.id).is_none());
    assert_eq!(rig.hub.board().len(), 1);
    assert_eq!(rig.hub.board().direction_count(Direction::Inbound), 0);
    assert_eq!(rig.hub.board().direction_count(Direction::Outbound), 1);
    assert_eq!(
        rig.hub.board().get(outbound.id).map(|row| row.id()),
        Some(outbound.id)
    );
    assert_eq!(held.len(), 2);

    rig.hub.session_established(inbound.id);
    assert!(rig.hub.board().get(inbound.id).is_none());
    assert_eq!(rig.hub.board().len(), 1);
}

#[test]
fn published_rows_follow_admission_order() {
    let rig = rig();
    let opened: Vec<_> = (0..8)
        .map(|_| adopt(&rig, Direction::Outbound, 32))
        .collect();
    let board = rig.hub.board();
    let published: Vec<_> = board.rows().iter().map(|row| row.id().get()).collect();
    let admitted: Vec<_> = opened.iter().map(|row| row.id.get()).collect();
    assert_eq!(published, admitted);
    assert!(published.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(board.direction_count(Direction::Outbound), 8);
    assert_eq!(board.direction_count(Direction::Inbound), 0);
}

/// `Board::count` for one connector. The handshake does not change it.
/// `shekyl_seam_board_count` is the integer the dial cap reads.
#[test]
fn an_unestablished_outbound_row_still_counts_toward_the_dial_cap() {
    let rig = rig();
    let opened: Vec<_> = (0..12)
        .map(|_| adopt(&rig, Direction::Outbound, 32))
        .collect();
    let board = rig.hub.board();
    assert_eq!(board.len(), 12);
    assert!(board.rows().iter().all(|row| !row.established()));
    assert_eq!(board.count(ConnectorId::Clearnet, Direction::Outbound), 12);
    assert_eq!(board.count(ConnectorId::Tor, Direction::Outbound), 0);
    assert_eq!(board.count(ConnectorId::Clearnet, Direction::Inbound), 0);
    assert_eq!(
        board.direction_count(Direction::Outbound),
        board.count(ConnectorId::Clearnet, Direction::Outbound)
            + board.count(ConnectorId::Tor, Direction::Outbound)
    );
    rig.hub.session_established(opened[0].id);
    let after = rig.hub.board();
    assert!(after.get(opened[0].id).expect("row").established());
    assert_eq!(after.count(ConnectorId::Clearnet, Direction::Outbound), 12);
    assert_eq!(after.direction_count(Direction::Outbound), 12);
}
