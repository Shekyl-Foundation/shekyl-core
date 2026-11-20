// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The outbound handshake, and the packet ceiling it lifts once the session is established.

use std::time::Duration;

use crate::common::{
    self, handshake_request, handshake_response, kind, outbound_clearnet, within, Answer, Event,
    Rig, Settings, NETWORK, OTHER_NETWORK, OUR_HEIGHT, PEER_HEIGHT,
};
use crate::session_test;
use shekyl_levin::{notify, NewTransactions, PortableMap, Received, INITIAL_MAX_PACKET_SIZE};
use shekyl_p2p_session::{
    ClaimCarrier, CloseCause, CloseKind, Command, ConnectorId, DialAim, DialEnd, DialOutcome,
    Direction, Intervals,
};
use shekyl_transport_layer::{Evidence, Reached, Retry};

session_test!(
    an_outbound_dial_kept_is_established_with_the_response,
    async {
        let mut rig = Rig::new(Settings::default());
        let layer = rig.layer.clone();
        let dial =
            tokio::spawn(async move { layer.dial(outbound_clearnet(1), DialAim::Keep).await });
        let mut wire = within("the dialed wire", rig.dialed.recv())
            .await
            .expect("loopback");
        assert_eq!(rig.layer.nonces().in_flight(ConnectorId::Clearnet), 1);

        let Received::Request { command, payload } = wire.read().await else {
            panic!("the request goes first");
        };
        assert_eq!(command, Command::Handshake.wire_id());
        let request = shekyl_levin::HandshakeRequest::load(&payload).expect("decodes");
        assert_eq!(request.node_data.network_id, NETWORK);
        assert_eq!(request.payload_data.current_height, OUR_HEIGHT);
        assert_ne!(request.nonce, [0; 32]);

        wire.inject(handshake_response(
            NETWORK,
            vec![common::entry(5), common::entry(6)],
        ))
        .await;
        let outcome = within("the outcome", dial)
            .await
            .expect("task")
            .expect("kept");
        let DialOutcome::Kept {
            session,
            node_data,
            list,
            sync,
        } = outcome
        else {
            panic!("expected Kept, got {outcome:?}");
        };
        assert_eq!(session.id(), wire.id);
        assert_eq!(session.direction(), Direction::Outbound);
        assert_eq!(node_data.network_id, NETWORK);
        assert_eq!(
            list.len(),
            2,
            "the response's list goes to the dialer, once"
        );
        assert_eq!(sync.current_height, PEER_HEIGHT);
        assert_eq!(rig.layer.nonces().in_flight(ConnectorId::Clearnet), 0);

        let Event::Established(told) = rig.event().await else {
            panic!("owners told");
        };
        assert_eq!(told.id(), wire.id);
        let Event::Claim(_, height, ClaimCarrier::Handshake) = rig.event().await else {
            panic!("claim");
        };
        assert_eq!(height, PEER_HEIGHT);
        assert!(
            rig.no_event().await,
            "the list did not also go to list_received"
        );
    }
);

session_test!(
    an_outbound_dial_to_confirm_closes_after_the_response,
    async {
        let mut rig = Rig::new(Settings::default());
        let layer = rig.layer.clone();
        let dial =
            tokio::spawn(async move { layer.dial(outbound_clearnet(2), DialAim::Confirm).await });
        let mut wire = within("the dialed wire", rig.dialed.recv())
            .await
            .expect("loopback");
        let _ = wire.read().await;
        wire.inject(handshake_response(NETWORK, vec![common::entry(5)]))
            .await;
        let outcome = within("the outcome", dial)
            .await
            .expect("task")
            .expect("confirmed");
        let DialOutcome::Confirmed { list, sync, .. } = outcome else {
            panic!("expected Confirmed, got {outcome:?}");
        };
        assert_eq!(list.len(), 1);
        assert_eq!(sync.current_height, PEER_HEIGHT);
        let (facts, end) = rig.closed(wire.id).await;
        assert!(!facts.established, "a confirm never establishes");
        assert_eq!(kind(end), CloseKind::LocalClose);
        assert_eq!(end.failure().reached(), Reached::StreamOpened);
        assert!(wire.drained().await);
    }
);

session_test!(
    a_response_from_another_network_is_final_for_the_dialer,
    async {
        let mut rig = Rig::new(Settings::default());
        let layer = rig.layer.clone();
        let dial =
            tokio::spawn(async move { layer.dial(outbound_clearnet(3), DialAim::Keep).await });
        let mut wire = within("the dialed wire", rig.dialed.recv())
            .await
            .expect("loopback");
        let _ = wire.read().await;
        wire.inject(handshake_response(OTHER_NETWORK, Vec::new()))
            .await;
        let end = within("the outcome", dial)
            .await
            .expect("task")
            .expect_err("refused");
        assert_eq!(kind(end), CloseKind::NetworkMismatch);
        assert_eq!(end.failure().retry(), Retry::Final);
        let (_, recorded) = rig.closed(wire.id).await;
        assert_eq!(kind(recorded), CloseKind::NetworkMismatch);
    }
);

session_test!(
    no_response_within_the_invoke_deadline_fails_the_dial,
    async {
        let mut rig = Rig::new(Settings {
            intervals: Intervals {
                invoke_timeout: Duration::from_millis(200),
                timed_sync_min: Duration::from_secs(30),
                timed_sync_jitter: Duration::from_secs(1),
            },
            ..Settings::default()
        });
        let layer = rig.layer.clone();
        let dial =
            tokio::spawn(async move { layer.dial(outbound_clearnet(4), DialAim::Keep).await });
        let mut wire = within("the dialed wire", rig.dialed.recv())
            .await
            .expect("loopback");
        let _ = wire.read().await;
        let end = within("the outcome", dial)
            .await
            .expect("task")
            .expect_err("timed out");
        assert_eq!(kind(end), CloseKind::InvokeTimeout);
        assert!(matches!(end.failure().evidence(), Evidence::Uncertain));
        assert_eq!(end.failure().retry(), Retry::AgainInsideWindow);
    }
);

session_test!(a_connector_refusal_is_the_dials_end, async {
    let mut rig = Rig::new(Settings::default());
    let refused = DialEnd::new(
        shekyl_transport_layer::DialFailure::local(Retry::Again, Reached::NoStream),
        CloseCause::new(CloseKind::AdmissionRefused),
    );
    rig.next_dial(Answer::Refuse(refused));
    let end = rig
        .layer
        .dial(outbound_clearnet(5), DialAim::Keep)
        .await
        .expect_err("refused before I/O");
    assert_eq!(kind(end), CloseKind::AdmissionRefused);
    assert!(rig.layer.is_empty(), "no row was placed");
    assert!(rig.no_event().await, "no owner heard of it");
});

session_test!(
    the_peer_closing_during_the_dial_fails_it_with_its_end,
    async {
        let mut rig = Rig::new(Settings::default());
        let layer = rig.layer.clone();
        let dial =
            tokio::spawn(async move { layer.dial(outbound_clearnet(6), DialAim::Keep).await });
        let mut wire = within("the dialed wire", rig.dialed.recv())
            .await
            .expect("loopback");
        let _ = wire.read().await;
        wire.peer_closes();
        let end = within("the outcome", dial)
            .await
            .expect("task")
            .expect_err("the peer closed");
        assert_eq!(kind(end), CloseKind::PeerClosed);
        let (facts, recorded) = rig.closed(wire.id).await;
        assert!(!facts.established);
        assert_eq!(kind(recorded), CloseKind::PeerClosed);
    }
);

// A dialed peer that answers this node's 1001 with anything but its
// response has refused the handshake: the Levin layer's refusal, judged
// against the address (the gray lifecycle, test 6c), not a local form
// failure. The edit that makes this red: closing it as `form_failure`.
session_test!(
    a_request_on_an_outbound_session_before_the_response_is_the_peers_refusal,
    async {
        let mut rig = Rig::new(Settings::default());
        let layer = rig.layer.clone();
        let dial =
            tokio::spawn(async move { layer.dial(outbound_clearnet(7), DialAim::Keep).await });
        let mut wire = within("the dialed wire", rig.dialed.recv())
            .await
            .expect("loopback");
        let _ = wire.read().await;
        wire.inject(handshake_request(NETWORK, [1; 32])).await;
        let end = within("the outcome", dial)
            .await
            .expect("task")
            .expect_err("a request is not a response");
        assert_eq!(kind(end), CloseKind::LevinHandshakeRejected);
        assert!(matches!(end.failure().evidence(), Evidence::Destination(_)));
        assert_eq!(end.failure().retry(), Retry::Final);
    }
);

// The same over a frame the peer broke: the framing error during this
// node's own handshake is the dialed peer's refusal too.
session_test!(
    a_malformed_answer_to_an_outbound_handshake_is_the_peers_refusal,
    async {
        let mut rig = Rig::new(Settings::default());
        let layer = rig.layer.clone();
        let dial =
            tokio::spawn(async move { layer.dial(outbound_clearnet(8), DialAim::Keep).await });
        let mut wire = within("the dialed wire", rig.dialed.recv())
            .await
            .expect("loopback");
        let _ = wire.read().await;
        wire.inject(vec![0xff; 64]).await;
        let end = within("the outcome", dial)
            .await
            .expect("task")
            .expect_err("garbage is not a response");
        assert_eq!(kind(end), CloseKind::LevinHandshakeRejected);
        assert!(matches!(end.failure().evidence(), Evidence::Destination(_)));
    }
);

/// A 2002 carrying one blob, framed so the whole bucket is larger than
/// the pre-handshake packet limit.
fn new_transactions_above_the_initial_limit() -> Vec<u8> {
    let blob = usize::try_from(INITIAL_MAX_PACKET_SIZE).expect("fits usize") + 1024;
    let payload = NewTransactions {
        txs: vec![vec![7; blob]],
        padding: Vec::new(),
        dandelionpp_fluff: true,
    }
    .store()
    .expect("batch stores");
    let frame = notify(Command::NewTransactions.wire_id(), &payload);
    assert!(
        u64::try_from(frame.len()).expect("fits u64") > INITIAL_MAX_PACKET_SIZE,
        "the frame is above the pre-handshake limit"
    );
    frame
}

// **A session this node dialed reads frames above the pre-handshake
// limit once it is established.** The alpha.11 fleet binary stalled a
// dial-only node at one height for ever: its C++ connection raised the
// 256 KiB ceiling at three handshake sites, none on the path an outbound
// handshake took, so every object response above that size was refused
// (shekyl-dev `4fab39a`). Here the ceiling moves in `establish()`, the
// one place either direction becomes `Established`; the dialed side is
// the side to pin.
session_test!(
    a_dialed_session_reads_a_frame_above_the_pre_handshake_limit,
    async {
        let mut rig = Rig::new(Settings::default());
        let (session, wire) = rig.dial_kept(outbound_clearnet(40)).await;
        assert_eq!(session.direction(), Direction::Outbound);
        wire.inject(new_transactions_above_the_initial_limit())
            .await;
        let Event::Relay(id, count, _taken) = rig.event().await else {
            panic!("the batch reaches the relay owner");
        };
        assert_eq!((id, count), (wire.id, 1));
        assert!(rig.no_event().await, "the session stays open");
    }
);

// The same frame in place of the handshake response is refused at the
// pre-handshake limit: the ceiling is lifted by the handshake, not by
// the direction.
session_test!(
    a_frame_above_the_pre_handshake_limit_before_the_response_ends_the_dial,
    async {
        let mut rig = Rig::new(Settings::default());
        let layer = rig.layer.clone();
        let dial =
            tokio::spawn(async move { layer.dial(outbound_clearnet(41), DialAim::Keep).await });
        let mut wire = within("the dialed wire", rig.dialed.recv())
            .await
            .expect("loopback");
        let _ = wire.read().await;
        wire.inject(new_transactions_above_the_initial_limit())
            .await;
        let end = within("the outcome", dial)
            .await
            .expect("task")
            .expect_err("a bucket above the limit is not a response");
        assert_eq!(kind(end), CloseKind::LevinHandshakeRejected);
        let (facts, recorded) = rig.closed(wire.id).await;
        assert!(!facts.established);
        assert_eq!(kind(recorded), CloseKind::LevinHandshakeRejected);
        assert!(rig.no_event().await, "no owner saw the batch");
    }
);
