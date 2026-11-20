// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The dispatch table: each command reaches its owner, and a bad frame is refused.

use crate::common::{
    inbound_clearnet, kind, new_transactions, request_headers, timed_sync_request,
    txpool_complement, Event, Rig, Settings,
};
use crate::session_test;
use shekyl_levin::{invoke, notify, PortableMap, Received, RequestHeaders};
use shekyl_p2p_session::{CloseKind, Command};

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
