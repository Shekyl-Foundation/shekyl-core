// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Nonces and probes: this node's own dial, the onion probe, and a misrouted clearnet probe.

use crate::common::{
    handshake_request, inbound_clearnet, kind, outbound_clearnet, within, Event, Rig, Settings,
    NETWORK, OUR_HEIGHT,
};
use crate::session_test;
use shekyl_levin::{PortableMap, Received};
use shekyl_p2p_session::{CloseKind, Command, ConnectorId, Endpoint};
use shekyl_timing_engine::{Clock, Tick};

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
