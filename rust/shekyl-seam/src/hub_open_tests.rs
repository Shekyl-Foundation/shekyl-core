// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! When a row posts `Opened`: at establish for an outbound row, and after
//! the handshake delivery finishes for an inbound one.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use shekyl_peer_policy::InboundCeiling;
use shekyl_timing_engine::{ManualClock, Tick};
use shekyl_transport_layer::{CloseCause, CloseKind, ConnectorId, Direction, SocketId, Sockets};

use super::super::{Hub, Post};
use super::{adopt, rig, service, Rig};
use crate::drive_inbound;

/// The `opened` posts for `id`, in order.
fn opened_posts(rig: &Rig, id: SocketId) -> Vec<ConnectorId> {
    rig.posts
        .lock()
        .expect("posts")
        .iter()
        .filter_map(|post| match post {
            Post::Opened { id: at, connector } if *at == id => Some(*connector),
            _ => None,
        })
        .collect()
}

/// An outbound row opens when the dialer marks it established: the dialer
/// read the peer's reply before it kept the session. Once only.
#[test]
fn an_outbound_row_opens_when_it_is_established() {
    let rig = rig();
    let opened = adopt(&rig, Direction::Outbound, 32);
    service(&rig, true);
    assert!(opened_posts(&rig, opened.id).is_empty(), "opened at attach");
    rig.hub.session_established(opened.id);
    assert_eq!(opened_posts(&rig, opened.id), vec![ConnectorId::Clearnet]);
    rig.hub.session_established(opened.id);
    rig.hub.delivery_finished(opened.id, true);
    assert_eq!(opened_posts(&rig, opened.id).len(), 1, "opened twice");
}

/// An inbound row opens when the handler finishes the delivery that
/// carried the handshake, not when the handler marks it established: the
/// handler marks it before it queues its reply, and a frame sent ahead of
/// that reply is refused by the dialing peer. A delivery finished before
/// the handshake opens nothing, and neither does a refused one. Red edit:
/// open an inbound row in `session_established`.
#[test]
fn an_inbound_row_opens_after_its_handshake_delivery_finishes() {
    let rig = rig();
    let opened = adopt(&rig, Direction::Inbound, 32);
    service(&rig, true);
    rig.hub.delivery_finished(opened.id, true);
    assert!(
        opened_posts(&rig, opened.id).is_empty(),
        "opened before the handshake"
    );
    rig.hub.session_established(opened.id);
    assert!(
        opened_posts(&rig, opened.id).is_empty(),
        "opened before the handshake reply was queued"
    );
    rig.hub.delivery_finished(opened.id, true);
    assert_eq!(opened_posts(&rig, opened.id), vec![ConnectorId::Clearnet]);
    rig.hub.delivery_finished(opened.id, true);
    assert_eq!(opened_posts(&rig, opened.id).len(), 1, "opened twice");
}

/// A refused handshake delivery opens nothing: the row closes.
#[test]
fn a_refused_inbound_handshake_opens_nothing() {
    let rig = rig();
    let opened = adopt(&rig, Direction::Inbound, 32);
    service(&rig, true);
    rig.hub.session_established(opened.id);
    rig.hub.delivery_finished(opened.id, false);
    assert!(opened_posts(&rig, opened.id).is_empty());
    assert_eq!(
        rig.hub.cause(opened.id).map(CloseCause::kind),
        Some(CloseKind::SessionRefused)
    );
}

/// An inbound row's open is posted before its pump is woken for the next
/// frame, so the owner hears `Opened` ahead of anything the peer sends
/// after reading the handshake reply. The poster stalls on `Opened`: a hub
/// that woke the pump first would let the next frame's `Deliver` land
/// while the open is still being posted. Red edit: wake the row before
/// posting the open in `delivery_finished`.
#[test]
fn an_inbound_open_is_posted_before_the_next_frame_is_delivered() {
    let posts = Arc::new(Mutex::new(VecDeque::new()));
    let clock = ManualClock::new(Tick::new(1));
    let recorded = Arc::clone(&posts);
    let poster: Arc<dyn Fn(Post) + Send + Sync> = Arc::new(move |post| {
        if matches!(post, Post::Opened { .. }) {
            thread::sleep(Duration::from_millis(200));
        }
        recorded.lock().expect("posts").push_back(post);
    });
    let sockets = Sockets::new();
    let hub = Hub::new(
        sockets.clone(),
        InboundCeiling::Bounded(8),
        poster,
        Arc::new(clock.clone()),
    );
    let rig = Rig {
        hub,
        sockets,
        posts,
        clock,
    };
    let mut opened = adopt(&rig, Direction::Inbound, 32);
    service(&rig, true);
    let session = opened.session.take().expect("session");
    let hub = rig.hub.clone();
    let id = opened.id;
    let pump = thread::spawn(move || drive_inbound(&hub, id, session));
    opened
        .inbound
        .blocking_send(b"handshake".to_vec())
        .expect("inject");
    assert!(rig.hub.wait_delivery_posted(id, 0));
    // The peer's next frame is waiting while the handler holds the first.
    opened
        .inbound
        .blocking_send(b"after the reply".to_vec())
        .expect("inject");
    rig.hub.session_established(id);
    rig.hub.delivery_finished(id, true);
    assert!(rig.hub.wait_delivery_posted(id, 1));
    let kinds: Vec<&'static str> = rig
        .posts
        .lock()
        .expect("posts")
        .iter()
        .map(|post| match post {
            Post::Opened { .. } => "opened",
            Post::Deliver { .. } => "deliver",
            Post::Established { .. } => "established",
            Post::HandshakeResult { .. } => "handshake",
            Post::Closed { .. } => "closed",
        })
        .collect();
    assert_eq!(kinds, vec!["deliver", "opened", "deliver"]);
    rig.hub.close(id);
    for _ in 0..4 {
        service(&rig, true);
    }
    pump.join().expect("pump");
}
