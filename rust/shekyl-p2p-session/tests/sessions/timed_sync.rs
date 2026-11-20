// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Timed sync: this node's draw, a peer's request, and the permit that paces both.

use std::time::Duration;

use crate::common::{
    self, inbound_clearnet, kind, new_transactions, timed_sync_request, timed_sync_response, Event,
    Rig, Settings, OUR_HEIGHT, PEER_HEIGHT,
};
use crate::session_test;
use shekyl_levin::{PortableMap, Received, TimedSyncRequest, TimedSyncResponse};
use shekyl_p2p_session::{ClaimCarrier, CloseKind, Command, Intervals};

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
