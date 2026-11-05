// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The session layer, driven from the far side of the wire and the near
//! side of the owners (`P2P_3_REMNANT_CUTOVER_BRIEF.md` §7): the
//! handshake both ways, the nonces, timed sync, the dispatch table, the
//! board, backpressure, and the ends a session can reach.

mod common;

use std::time::Duration;

use common::{
    handshake_request, handshake_response, inbound_clearnet, kind, new_transactions,
    outbound_clearnet, request_headers, timed_sync_request, timed_sync_response, txpool_complement,
    within, Answer, Event, Rig, Settings, NETWORK, OTHER_NETWORK, OUR_HEIGHT, PEER_HEIGHT,
    SEND_CAP, SETTLE,
};
use shekyl_levin::{
    invoke, notify, HandshakeResponse, NewTransactions, PortableMap, Received, RequestHeaders,
    TimedSyncRequest, TimedSyncResponse, INITIAL_MAX_PACKET_SIZE,
};
use shekyl_p2p_session::{
    ClaimCarrier, CloseCause, CloseKind, Command, ConnectorId, DialAim, DialEnd, DialOutcome,
    Direction, Endpoint, Intervals, Message,
};
use shekyl_timing_engine::{Clock, Tick};
use shekyl_transport_layer::{Evidence, Reached, Retry};

fn multi() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
}

macro_rules! session_test {
    ($name:ident, $body:expr) => {
        #[test]
        fn $name() {
            multi().block_on(async { $body.await });
        }
    };
}

// ---------------------------------------------------------------- inbound

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

// ----------------------------------------------------------------- nonces

session_test!(this_nodes_own_dial_arriving_is_dropped_silently, async {
    let mut rig = Rig::new(Settings::default());
    let nonce = {
        let mut rng = shekyl_draw_rng::SplitMix64::new(3);
        rig.layer.nonces().mint(ConnectorId::Clearnet, &mut rng)
    };
    assert_eq!(rig.layer.nonces().in_flight(ConnectorId::Clearnet), 1);
    let (mut wire, _gap) = rig.accept(inbound_clearnet(9));
    wire.inject(handshake_request(NETWORK, *nonce.bytes()))
        .await;
    let (facts, end) = rig.closed(wire.id).await;
    assert!(!facts.established);
    assert_eq!(kind(end), CloseKind::LocalClose);
    assert!(wire.drained().await, "no response: the drop is silent");
    assert_eq!(
        rig.layer.nonces().in_flight(ConnectorId::Clearnet),
        0,
        "the nonce is taken"
    );
});

session_test!(a_probe_of_this_nodes_onion_reaches_the_sink, async {
    let mut rig = Rig::new(Settings::default());
    let before = rig.timing.clock().now();
    let probe = rig.layer.mint_probe().expect("the probe request builds");
    assert!(probe.minted_at >= before);
    let mut reader = shekyl_levin::BucketReader::new();
    reader.complete_handshake(shekyl_levin::DEFAULT_MAX_PACKET_SIZE);
    reader
        .feed(&probe.request)
        .expect("the probe request frames");
    let Ok(Some(Received::Request { command, payload })) = reader.next_message() else {
        panic!("the probe request is one invoke");
    };
    assert_eq!(command, Command::Handshake.wire_id());
    let request =
        shekyl_levin::HandshakeRequest::load(&payload).expect("the probe request is a 1001");
    assert_eq!(request.nonce, *probe.nonce.bytes());
    assert_eq!(request.node_data.network_id, NETWORK);
    assert_eq!(request.payload_data.current_height, OUR_HEIGHT);
    let (wire, _gap) = rig.accept(Endpoint::TorInbound);
    wire.inject(handshake_request(NETWORK, *probe.nonce.bytes()))
        .await;
    let Event::Probe(arrival) = rig.event().await else {
        panic!("the sink hears the probe before the close");
    };
    assert_eq!(arrival.minted_at, probe.minted_at);
    assert!(arrival.arrived_at >= probe.minted_at);
    let (facts, end) = rig.closed(wire.id).await;
    assert!(!facts.established);
    assert_eq!(kind(end), CloseKind::LocalClose);
});

session_test!(
    a_dialed_channel_dropped_before_its_handshake_is_closed_rowless,
    async {
        let mut rig = Rig::new(Settings::default());
        let dialed = rig
            .layer
            .connect(outbound_clearnet(31))
            .await
            .expect("the loopback connects");
        assert_eq!(rig.layer.nonces().in_flight(ConnectorId::Clearnet), 1);
        let mut wire = within("the dialed wire", rig.dialed.recv())
            .await
            .expect("the loopback is alive");
        assert_eq!(wire.id, dialed.id());
        assert!(
            rig.layer.board().get(wire.id).is_none(),
            "no row before the handshake"
        );
        assert!(
            wire.is_quiet().await,
            "nothing written before the handshake"
        );
        drop(dialed);
        assert!(wire.drained().await, "the channel is closed");
        assert_eq!(rig.layer.nonces().in_flight(ConnectorId::Clearnet), 0);
        assert!(rig.no_event().await, "no owner was told: no row was placed");
        assert!(rig.layer.board().is_empty());
    }
);

session_test!(a_probe_on_clearnet_is_misrouted_and_refused, async {
    let mut rig = Rig::new(Settings::default());
    let nonce = {
        let mut rng = shekyl_draw_rng::SplitMix64::new(5);
        rig.layer
            .nonces()
            .mint_probe(ConnectorId::Tor, Tick::new(1), &mut rng)
    };
    let (wire, _gap) = rig.accept(inbound_clearnet(10));
    wire.inject(handshake_request(NETWORK, *nonce.bytes()))
        .await;
    let (_, end) = rig.closed(wire.id).await;
    assert_eq!(kind(end), CloseKind::SessionRefused);
    assert!(rig.no_event().await, "not a probe arrival");
});

// --------------------------------------------------------------- outbound

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

// ------------------------------------------------------------- timed sync

fn quick_sync() -> Settings {
    Settings {
        intervals: Intervals {
            invoke_timeout: Duration::from_secs(30),
            timed_sync_min: Duration::from_millis(150),
            timed_sync_jitter: Duration::from_millis(50),
        },
        ..Settings::default()
    }
}

session_test!(
    this_node_sends_timed_sync_on_its_draw_and_reads_the_response,
    async {
        let mut rig = Rig::new(quick_sync());
        let (mut wire, _gap) = rig.accept(inbound_clearnet(11));
        let _session = rig.establish_inbound(&mut wire).await;

        let Received::Request { command, payload } = wire.read().await else {
            panic!("our timed sync");
        };
        assert_eq!(command, Command::TimedSync.wire_id());
        let request = TimedSyncRequest::load(&payload).expect("decodes");
        assert_eq!(request.payload_data.current_height, OUR_HEIGHT);

        wire.inject(timed_sync_response(vec![
            common::entry(7),
            common::entry(8),
            common::entry(9),
        ]))
        .await;
        let Event::Claim(id, height, ClaimCarrier::TimedSync) = rig.event().await else {
            panic!("the claim to the sync owner");
        };
        assert_eq!((id, height), (wire.id, PEER_HEIGHT));
        let Event::ListReceived(id, count) = rig.event().await else {
            panic!("the list to the peers owner");
        };
        assert_eq!((id, count), (wire.id, 3));

        // The next draw follows the response.
        let Received::Request { command, .. } = wire.read().await else {
            panic!("the second timed sync");
        };
        assert_eq!(command, Command::TimedSync.wire_id());
    }
);

// Our timed sync is outstanding while an owner holds the session's
// permit, and the peer's response waits unread past the invoke deadline.
// The stall is this node's: the session stays, and the response is read
// once the permit is back.
session_test!(
    an_owner_holding_the_session_is_not_the_peers_timeout,
    async {
        let mut rig = Rig::new(Settings {
            intervals: Intervals {
                invoke_timeout: Duration::from_millis(200),
                timed_sync_min: Duration::from_millis(150),
                timed_sync_jitter: Duration::from_millis(0),
            },
            ..Settings::default()
        });
        let (mut wire, _gap) = rig.accept(inbound_clearnet(28));
        let _session = rig.establish_inbound(&mut wire).await;
        wire.inject(new_transactions(1)).await;
        let Event::Relay(_, _, taken) = rig.event().await else {
            panic!("relay");
        };
        let Received::Request { command, .. } = wire.read().await else {
            panic!("our timed sync");
        };
        assert_eq!(command, Command::TimedSync.wire_id());
        wire.inject(timed_sync_response(vec![common::entry(7)]))
            .await;
        // Three invoke deadlines pass with the permit held.
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert_eq!(
            rig.layer.len(),
            1,
            "the session was closed for this node's stall"
        );
        drop(taken);
        let Event::Claim(id, _, ClaimCarrier::TimedSync) = rig.event().await else {
            panic!("the response, read once the permit is back");
        };
        assert_eq!(id, wire.id);
        assert_eq!(rig.layer.len(), 1);
    }
);

// A peer's 1002s queue no faster than the sync owner takes their claims:
// the claim carries the frame's permit, so a second 1002 is not read, and
// not answered, until the owner has taken the first claim.
session_test!(
    a_peers_timed_syncs_wait_for_the_owner_to_take_each_claim,
    async {
        let mut rig = Rig::new(Settings::default());
        let (mut wire, _gap) = rig.accept(inbound_clearnet(29));
        let _session = rig.establish_inbound(&mut wire).await;
        rig.recorder
            .hold_claims
            .store(true, std::sync::atomic::Ordering::SeqCst);
        wire.inject(timed_sync_request()).await;
        wire.inject(timed_sync_request()).await;
        let Received::Response { command, .. } = wire.read().await else {
            panic!("the first 1002 is answered");
        };
        assert_eq!(command, Command::TimedSync.wire_id());
        assert!(
            wire.is_quiet().await,
            "the second 1002 was answered while the owner still held the first claim"
        );
        rig.recorder
            .held_claims
            .lock()
            .expect("held claims")
            .clear();
        let Received::Response { command, .. } = wire.read().await else {
            panic!("the second 1002, once the claim is taken");
        };
        assert_eq!(command, Command::TimedSync.wire_id());
    }
);

session_test!(the_tip_read_at_each_timed_sync_is_the_current_one, async {
    let mut rig = Rig::new(quick_sync());
    let (mut wire, _gap) = rig.accept(inbound_clearnet(12));
    let _session = rig.establish_inbound(&mut wire).await;
    let mut tip = common::our_tip();
    tip.current_height = 99;
    rig.tip.send(tip).expect("the layer holds the receiver");
    let Received::Request { payload, .. } = wire.read().await else {
        panic!("our timed sync");
    };
    let request = TimedSyncRequest::load(&payload).expect("decodes");
    assert_eq!(request.payload_data.current_height, 99);
});

session_test!(
    a_peers_timed_sync_is_answered_with_our_tip_and_disclosure,
    async {
        let mut rig = Rig::new(Settings::default());
        let (mut wire, _gap) = rig.accept(inbound_clearnet(13));
        let _session = rig.establish_inbound(&mut wire).await;
        wire.inject(timed_sync_request()).await;
        let Received::Response { command, payload } = wire.read().await else {
            panic!("our response");
        };
        assert_eq!(command, Command::TimedSync.wire_id());
        let reply = TimedSyncResponse::load(&payload).expect("decodes");
        assert_eq!(reply.payload_data.current_height, OUR_HEIGHT);
        assert_eq!(reply.local_peerlist_new.len(), 2);
        let Event::Claim(id, height, ClaimCarrier::TimedSync) = rig.event().await else {
            panic!("claim");
        };
        assert_eq!((id, height), (wire.id, PEER_HEIGHT));
    }
);

session_test!(
    a_timed_sync_response_with_no_request_outstanding_is_refused,
    async {
        let mut rig = Rig::new(Settings::default());
        let (mut wire, _gap) = rig.accept(inbound_clearnet(14));
        let _session = rig.establish_inbound(&mut wire).await;
        wire.inject(timed_sync_response(Vec::new())).await;
        let (_, end) = rig.closed(wire.id).await;
        assert_eq!(kind(end), CloseKind::SessionRefused);
    }
);

session_test!(a_timed_sync_unanswered_is_the_invoke_timeout, async {
    let mut rig = Rig::new(Settings {
        intervals: Intervals {
            invoke_timeout: Duration::from_millis(200),
            timed_sync_min: Duration::from_millis(100),
            timed_sync_jitter: Duration::from_millis(10),
        },
        ..Settings::default()
    });
    let (mut wire, _gap) = rig.accept(inbound_clearnet(15));
    let _session = rig.establish_inbound(&mut wire).await;
    let Received::Request { .. } = wire.read().await else {
        panic!("our timed sync");
    };
    let (facts, end) = rig.closed(wire.id).await;
    assert!(facts.established);
    assert_eq!(kind(end), CloseKind::InvokeTimeout);
});

// --------------------------------------------------------------- dispatch

session_test!(
    the_relay_and_sync_owners_receive_their_commands_in_turn,
    async {
        let mut rig = Rig::new(Settings::default());
        let (mut wire, _gap) = rig.accept(inbound_clearnet(16));
        let _session = rig.establish_inbound(&mut wire).await;

        wire.inject(new_transactions(3)).await;
        let Event::Relay(id, count, taken) = rig.event().await else {
            panic!("2002 to the relay owner");
        };
        assert_eq!((id, count), (wire.id, 3));

        // The next frame waits on the permit the relay owner holds.
        wire.inject(request_headers()).await;
        assert!(rig.no_event().await, "one message in flight per session");
        drop(taken);
        let Event::Sync(id, command, taken) = rig.event().await else {
            panic!("2011 to the sync owner once the permit is back");
        };
        assert_eq!((id, command), (wire.id, Command::RequestHeaders));
        drop(taken);

        wire.inject(txpool_complement(2)).await;
        let Event::Complement(id, count, _taken) = rig.event().await else {
            panic!("2010 to the relay owner");
        };
        assert_eq!((id, count), (wire.id, 2));
    }
);

session_test!(
    a_notification_command_framed_as_an_invoke_is_refused,
    async {
        let mut rig = Rig::new(Settings::default());
        let (mut wire, _gap) = rig.accept(inbound_clearnet(17));
        let _session = rig.establish_inbound(&mut wire).await;
        let payload = RequestHeaders {
            block_ids: vec![[3; 32]],
        }
        .store()
        .expect("stores");
        wire.inject(invoke(Command::RequestHeaders.wire_id(), &payload))
            .await;
        let (_, end) = rig.closed(wire.id).await;
        assert_eq!(kind(end), CloseKind::SessionRefused);
        assert!(rig.no_event().await);
    }
);

session_test!(a_relay_payload_that_does_not_decode_is_refused, async {
    let mut rig = Rig::new(Settings::default());
    let (mut wire, _gap) = rig.accept(inbound_clearnet(18));
    let _session = rig.establish_inbound(&mut wire).await;
    wire.inject(notify(Command::NewTransactions.wire_id(), &[1, 2, 3]))
        .await;
    let (_, end) = rig.closed(wire.id).await;
    assert_eq!(kind(end), CloseKind::SessionRefused);
});

session_test!(
    a_timed_sync_request_waits_for_the_permit_an_owner_holds,
    async {
        let mut rig = Rig::new(Settings::default());
        let (mut wire, _gap) = rig.accept(inbound_clearnet(19));
        let _session = rig.establish_inbound(&mut wire).await;
        wire.inject(new_transactions(1)).await;
        let Event::Relay(_, _, taken) = rig.event().await else {
            panic!("relay");
        };
        // 1002 is the session's own: it is answered while the owner still
        // holds the batch only once the permit is back, since the parse
        // waits on it. The peer's bytes wait in the stream, unread.
        wire.inject(timed_sync_request()).await;
        assert!(wire.is_quiet().await, "the stall is visible to the peer");
        drop(taken);
        let Received::Response { command, .. } = wire.read().await else {
            panic!("the response once the permit is back");
        };
        assert_eq!(command, Command::TimedSync.wire_id());
    }
);

// ----------------------------------------------------------------- handle

session_test!(an_owner_sends_through_the_handle, async {
    let mut rig = Rig::new(Settings::default());
    let (session, mut wire) = rig.dial_kept(outbound_clearnet(8)).await;
    session
        .send(&Message::RequestHeaders(RequestHeaders {
            block_ids: vec![[5; 32], [6; 32]],
        }))
        .expect("queued");
    let Received::Notification { command, payload } = wire.read().await else {
        panic!("a notification");
    };
    assert_eq!(command, Command::RequestHeaders.wire_id());
    let request = RequestHeaders::load(&payload).expect("decodes");
    assert_eq!(request.block_ids.len(), 2);

    let encoded = Message::GetTxpoolComplement(shekyl_levin::GetTxpoolComplement {
        hashes: vec![[1; 32]],
    })
    .encode()
    .expect("encodes");
    assert_eq!(encoded.command(), Command::GetTxpoolComplement);
    session.send_encoded(&encoded).expect("queued");
    let Received::Notification { command, .. } = wire.read().await else {
        panic!("a notification");
    };
    assert_eq!(command, Command::GetTxpoolComplement.wire_id());
});

session_test!(an_owner_closes_through_the_handle_with_its_cause, async {
    let mut rig = Rig::new(Settings::default());
    let (session, wire) = rig.dial_kept(outbound_clearnet(9)).await;
    session.close(CloseCause::new(CloseKind::SessionRefused));
    let (facts, end) = rig.closed(wire.id).await;
    assert!(facts.established);
    assert_eq!(kind(end), CloseKind::SessionRefused);
    assert_eq!(end.failure().reached(), Reached::StreamOpened);
    assert!(matches!(end.failure().evidence(), Evidence::Local));
    assert!(
        session
            .send(&Message::RequestHeaders(RequestHeaders {
                block_ids: Vec::new()
            }))
            .is_err(),
        "a closed session refuses the send"
    );
    // The peers owner's hook sent the event; the other two run after it.
    tokio::time::sleep(SETTLE).await;
    assert_eq!(
        rig.recorder
            .closed_told
            .load(std::sync::atomic::Ordering::SeqCst),
        3
    );
});

session_test!(a_send_the_queue_cannot_take_closes_the_session, async {
    let mut rig = Rig::new(Settings::default());
    // A cap the handshake response does not fit, and no writer draining.
    let (wire, _gap) = rig.accept_with_cap(inbound_clearnet(20), 16, false);
    wire.inject(handshake_request(NETWORK, [2; 32])).await;
    let (facts, end) = rig.closed(wire.id).await;
    assert!(!facts.established);
    assert_eq!(kind(end), CloseKind::SendQueueFull);
});

// ------------------------------------------------------------------ board

session_test!(the_board_follows_the_rows, async {
    let mut rig = Rig::new(Settings::default());
    let (mut a, _ga) = rig.accept(inbound_clearnet(21));
    let (_session, b) = rig.dial_kept(outbound_clearnet(22)).await;
    let board = rig.layer.board();
    assert_eq!(board.len(), 2);
    assert_eq!(board.count(ConnectorId::Clearnet, Direction::Inbound), 1);
    assert_eq!(board.count(ConnectorId::Clearnet, Direction::Outbound), 1);
    assert_eq!(board.established_count(Direction::Inbound), 0);
    assert_eq!(board.established_count(Direction::Outbound), 1);

    let _session = rig.establish_inbound(&mut a).await;
    assert_eq!(rig.layer.board().established_count(Direction::Inbound), 1);

    rig.layer.close(a.id, DialEnd::local_close_after_channel());
    let _ = rig.closed(a.id).await;
    let board = rig.layer.board();
    assert_eq!(board.len(), 1);
    assert!(board.get(a.id).is_none());
    assert!(board.get(b.id).is_some());
});

session_test!(shutdown_closes_every_session_as_this_nodes_own, async {
    let mut rig = Rig::new(Settings::default());
    let (mut a, _ga) = rig.accept(inbound_clearnet(23));
    let _sa = rig.establish_inbound(&mut a).await;
    let (b, _gb) = rig.accept(inbound_clearnet(24));
    rig.layer.shutdown();
    let mut ended = Vec::new();
    for _ in 0..2 {
        loop {
            if let Event::Closed(facts, end) = rig.event().await {
                assert_eq!(kind(end), CloseKind::LocalClose);
                ended.push(facts.id);
                break;
            }
        }
    }
    assert_eq!(ended.len(), 2);
    assert!(ended.contains(&a.id) && ended.contains(&b.id));
    assert!(rig.layer.is_empty());
    assert!(a.drained().await);
});

session_test!(a_ban_drops_the_hosts_sessions_and_refuses_the_next, async {
    let mut rig = Rig::new(Settings::default());
    let (mut wire, _gap) = rig.accept(inbound_clearnet(25));
    let _session = rig.establish_inbound(&mut wire).await;
    let far = Tick::new(rig.timing.clock().now().get() + 60_000_000_000);
    let dropped = rig.layer.ban_host(common::ip(25), far);
    assert_eq!(dropped, vec![wire.id]);
    let (facts, end) = rig.closed(wire.id).await;
    assert!(facts.established);
    assert_eq!(kind(end), CloseKind::LocalClose);
    assert!(rig.sockets.is_banned(common::ip(25)));
    assert!(
        shekyl_p2p_session::harness::admit(
            &rig.sockets,
            &inbound_clearnet(25),
            Tick::new(0),
            common::CEILING
        )
        .is_err(),
        "admission refuses the banned host"
    );
    assert!(rig.layer.sockets().lift_host(common::ip(25)));
});

session_test!(
    a_host_banned_before_its_channel_is_adopted_gets_no_session,
    async {
        let mut rig = Rig::new(Settings::default());
        // The connector admitted the host and the channel waits for its row
        // when the ban lands: there is no session yet for the ban to close.
        let (mut wire, channel) = rig.loopback.accept(inbound_clearnet(26), SEND_CAP, true);
        let far = Tick::new(rig.timing.clock().now().get() + 60_000_000_000);
        rig.layer.ban_host(common::ip(26), far);
        rig.layer.adopt(channel);
        assert!(
            rig.layer.is_empty(),
            "the banned host's channel was adopted"
        );
        assert!(wire.drained().await, "the banned host's socket stayed open");
        assert!(rig.no_event().await, "an owner heard of the banned host");
        assert!(rig.layer.sockets().lift_host(common::ip(26)));
    }
);

// A connector hands over a channel after the stop: it is dropped, and no
// owner hears of a session that never was.
session_test!(nothing_is_placed_after_shutdown, async {
    let mut rig = Rig::new(Settings::default());
    rig.layer.shutdown();
    let (mut wire, _gap) = rig.accept(inbound_clearnet(27));
    assert!(rig.layer.is_empty(), "a channel was placed after the stop");
    assert!(wire.drained().await, "its socket stayed open");
    assert!(rig.no_event().await, "an owner heard of it");
});

session_test!(a_second_close_does_not_replace_the_first_end, async {
    let mut rig = Rig::new(Settings::default());
    let (session, wire) = rig.dial_kept(outbound_clearnet(10)).await;
    session.close(CloseCause::new(CloseKind::SessionRefused));
    rig.layer
        .close(wire.id, DialEnd::local_close_after_channel());
    let (_, end) = rig.closed(wire.id).await;
    assert_eq!(kind(end), CloseKind::SessionRefused);
    tokio::time::sleep(SETTLE).await;
    assert!(rig.layer.is_empty());
});
