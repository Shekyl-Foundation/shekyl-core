// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The inbound handshake: the answer, the refusals, and the connector's end.

use std::time::Duration;

use crate::common::{
    self, handshake_request, inbound_clearnet, kind, new_transactions, timed_sync_request, within,
    Event, Rig, Settings, NETWORK, OTHER_NETWORK, OUR_HEIGHT, PEER_HEIGHT, SETTLE,
};
use crate::session_test;
use shekyl_levin::{HandshakeResponse, PortableMap, Received};
use shekyl_p2p_session::{
    ClaimCarrier, CloseCause, CloseKind, Command, ConnectorId, DialEnd, Direction,
};
use shekyl_transport_layer::{Evidence, Reached, Retry};

session_test!(inbound_handshake_is_answered_and_establishes, async {
    let mut rig = Rig::new(Settings::default());
    let (mut wire, gap) = rig.accept(inbound_clearnet(1));
    assert_eq!(rig.layer.len(), 1);
    let row = rig.layer.board();
    assert!(!row.get(wire.id).expect("placed at adoption").established());

    wire.inject(handshake_request(NETWORK, [9; 32])).await;

    let Received::Response { command, payload } = wire.read().await else {
        panic!("expected a response");
    };
    assert_eq!(command, Command::Handshake.wire_id());
    let reply = HandshakeResponse::load(&payload).expect("our response decodes");
    assert_eq!(reply.node_data.network_id, NETWORK);
    assert_eq!(reply.payload_data.current_height, OUR_HEIGHT);
    assert_eq!(
        reply.local_peerlist_new.len(),
        2,
        "the peers owner's disclosure"
    );

    within("the gap to fire", gap)
        .await
        .expect("fired, not dropped");
    let Event::Established(session) = rig.event().await else {
        panic!("the owners are told first");
    };
    assert_eq!(session.id(), wire.id);
    assert_eq!(session.connector(), ConnectorId::Clearnet);
    assert_eq!(session.direction(), Direction::Inbound);
    let Event::Claim(id, height, ClaimCarrier::Handshake) = rig.event().await else {
        panic!("the claim goes to the sync owner");
    };
    assert_eq!((id, height), (wire.id, PEER_HEIGHT));
    assert_eq!(
        rig.recorder
            .established_told
            .load(std::sync::atomic::Ordering::SeqCst),
        3
    );
    assert!(rig.layer.board().get(wire.id).expect("row").established());
});

session_test!(
    inbound_handshake_on_another_network_is_dropped_not_banned,
    async {
        let mut rig = Rig::new(Settings::default());
        let (mut wire, gap) = rig.accept(inbound_clearnet(2));
        wire.inject(handshake_request(OTHER_NETWORK, [9; 32])).await;

        let (facts, end) = rig.closed(wire.id).await;
        assert!(!facts.established);
        assert_eq!(kind(end), CloseKind::NetworkMismatch);
        assert_eq!(end.failure().retry(), Retry::Final);
        assert!(matches!(end.failure().evidence(), Evidence::Destination(_)));
        assert!(
            !rig.sockets.is_banned(common::ip(2)),
            "a mismatch is never a ban"
        );
        assert!(wire.drained().await, "no response was written");
        assert!(gap.await.is_err(), "the gap sender dropped unfired");
        assert!(rig.layer.is_empty());
    }
);

session_test!(
    inbound_handshake_deadline_closes_as_levin_handshake_timeout,
    async {
        let mut rig = Rig::new(Settings {
            handshake_within: Duration::from_millis(200),
            ..Settings::default()
        });
        let (wire, _gap) = rig.accept(inbound_clearnet(3));
        let started = std::time::Instant::now();
        let (facts, end) = rig.closed(wire.id).await;
        assert!(started.elapsed() >= Duration::from_millis(150));
        assert!(!facts.established);
        assert_eq!(kind(end), CloseKind::LevinHandshakeTimeout);
    }
);

session_test!(a_bucket_before_the_handshake_is_refused, async {
    let mut rig = Rig::new(Settings::default());
    let (wire, _gap) = rig.accept(inbound_clearnet(4));
    wire.inject(new_transactions(1)).await;
    let (facts, end) = rig.closed(wire.id).await;
    assert!(!facts.established);
    assert_eq!(kind(end), CloseKind::SessionRefused);
    assert!(rig.no_event().await, "no owner saw the batch");
});

session_test!(a_second_handshake_is_refused, async {
    let mut rig = Rig::new(Settings::default());
    let (mut wire, _gap) = rig.accept(inbound_clearnet(5));
    let _session = rig.establish_inbound(&mut wire).await;
    wire.inject(handshake_request(NETWORK, [8; 32])).await;
    let (facts, end) = rig.closed(wire.id).await;
    assert!(facts.established);
    assert_eq!(kind(end), CloseKind::SessionRefused);
});

session_test!(a_malformed_bucket_is_refused, async {
    let mut rig = Rig::new(Settings::default());
    let (wire, _gap) = rig.accept(inbound_clearnet(6));
    wire.inject(vec![0xff; 64]).await;
    let (_, end) = rig.closed(wire.id).await;
    assert_eq!(kind(end), CloseKind::SessionRefused);
});

session_test!(the_peer_closing_before_the_handshake_is_its_end, async {
    let mut rig = Rig::new(Settings::default());
    let (mut wire, _gap) = rig.accept(inbound_clearnet(7));
    wire.peer_closes();
    let (facts, end) = rig.closed(wire.id).await;
    assert!(!facts.established);
    assert_eq!(kind(end), CloseKind::PeerClosed);
    assert!(
        matches!(end.failure().evidence(), Evidence::Uncertain),
        "the loopback's stamp"
    );
});

// The connector's write fails: it closes the queue, then seals the
// inbound end with its stamped end. A send the session makes in between is
// refused, and the session's end is still the connector's, not this
// node's own close.
session_test!(a_failed_writer_ends_with_the_connectors_end, async {
    let mut rig = Rig::new(Settings::default());
    let (mut wire, _gap) = rig.accept(inbound_clearnet(9));
    let _session = rig.establish_inbound(&mut wire).await;
    let failed = DialEnd::new(
        shekyl_transport_layer::DialFailure::local(Retry::Again, Reached::StreamOpened),
        CloseCause::new(CloseKind::IoError),
    );
    wire.writer_fails(failed);
    // The peer's timed sync asks for a response, which the session cannot
    // queue.
    wire.inject(timed_sync_request()).await;
    tokio::time::sleep(SETTLE).await;
    wire.connector_ends(failed);
    let (facts, end) = rig.closed(wire.id).await;
    assert!(facts.established);
    assert_eq!(kind(end), CloseKind::IoError, "the connector's end");
});

session_test!(a_connector_stored_end_is_the_sessions_end, async {
    let mut rig = Rig::new(Settings::default());
    let (mut wire, _gap) = rig.accept(inbound_clearnet(8));
    let _session = rig.establish_inbound(&mut wire).await;
    wire.connector_ends(DialEnd::new(
        shekyl_transport_layer::DialFailure::local(Retry::Again, Reached::StreamOpened),
        CloseCause::new(CloseKind::IoError),
    ));
    let (facts, end) = rig.closed(wire.id).await;
    assert!(facts.established);
    assert_eq!(kind(end), CloseKind::IoError);
});
