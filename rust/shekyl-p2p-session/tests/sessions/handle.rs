// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The established handle: an owner sends and closes, and a full queue ends the session.

use crate::common::{
    handshake_request, inbound_clearnet, kind, outbound_clearnet, Rig, Settings, NETWORK, SETTLE,
};
use crate::session_test;
use shekyl_levin::{PortableMap, Received, RequestHeaders};
use shekyl_p2p_session::{CloseCause, CloseKind, Command, Message};
use shekyl_transport_layer::{Evidence, Reached};

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
