// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The board follows the rows, and a ban or a stop drops what must not stay.

use crate::common::{
    self, inbound_clearnet, kind, outbound_clearnet, Event, Rig, Settings, SEND_CAP, SETTLE,
};
use crate::session_test;
use shekyl_p2p_session::{
    CloseCause, CloseKind, ConnectorId, DialEnd, Direction, Endpoint, PerConnector,
};
use shekyl_timing_engine::{Clock, Tick};

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

// **The sessions each connector holds** (`TSR-Q12`, alpha.11 finding 9):
// the layer reports a row once its handshake has finished, in either
// direction, and again when it leaves. A handshake still open is not a
// session: the probe of this node's own onion is dropped there. Counting
// every row instead of established ones fails the second assertion.
session_test!(
    the_sessions_each_connector_holds_follow_established_rows,
    async {
        let mut rig = Rig::new(Settings::default());
        let log = std::sync::Arc::clone(&rig.held);
        let reports = move || log.lock().expect("held reports").clone();
        let held = |clearnet, tor| PerConnector { clearnet, tor };
        assert_eq!(reports(), vec![held(0, 0)], "the count at construction");

        let (mut tor, _gt) = rig.accept(Endpoint::TorInbound);
        tokio::time::sleep(SETTLE).await;
        assert_eq!(
            reports(),
            vec![held(0, 0)],
            "a handshake still open is not a session"
        );

        let (_out, _wire) = rig.dial_kept(outbound_clearnet(24)).await;
        let _in = rig.establish_inbound(&mut tor).await;
        assert_eq!(reports(), vec![held(0, 0), held(1, 0), held(1, 1)]);

        rig.layer
            .close(tor.id, DialEnd::local_close_after_channel());
        let _ = rig.closed(tor.id).await;
        assert_eq!(
            reports(),
            vec![held(0, 0), held(1, 0), held(1, 1), held(1, 0)],
            "a close is reported once, and an unchanged count is not"
        );
    }
);

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
