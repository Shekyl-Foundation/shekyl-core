// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The relay owner on live sessions (`P2P_3_REMNANT_CUTOVER_BRIEF.md`
//! §2.1, §5): 2002 while the node is not synchronised is held and admitted
//! at the turn, otherwise admitted and relayed; a bad batch severs; 2010 is served from the pool; a local
//! origin waits for sync; a slow pool holds the session's reads.

mod support;

use std::thread;
use std::time::Duration;

use shekyl_p2p_session::harness::Wire;
use shekyl_p2p_session::CloseKind;
use shekyl_relay::owner::Admit;
use shekyl_relay::{transit_ms, ConnectorId, NodeSync, TxId};
use shekyl_relay_privacy::params::DandelionParams;
use shekyl_relay_privacy::schedule::EmbargoTimer;
use support::{
    blob, id_of, new_transactions, txpool_complement, Asked, Build, Draws, FixedDraw, Rig, SETTLE,
};

/// Wait until `wire`'s session has handled every frame injected so far. A
/// session reads one frame at a time, so a 2010 sent after them is answered
/// only once they are done; `mark` names this request. The empty reply is
/// read off the wire.
fn handled_so_far(rig: &Rig, wire: &mut Wire, mark: u8) {
    wire.inject_blocking(txpool_complement(vec![[mark; 32]]));
    support::wait_until("the session reached the marker", || {
        rig.pool.asked().iter().any(|asked| {
            matches!(asked, Asked::Complement(known) if *known == [TxId::from_bytes([mark; 32])])
        })
    });
    assert!(rig.read_batch(wire).txs.is_empty(), "the marker's reply");
}

/// A node behind a block holds what arrives and admits it when it is
/// synchronised again: nothing reaches the pool or a peer before the turn,
/// the session stays and reads on, and after the turn every stem is stemmed.
///
/// The sequence is the one a live walk lost: three stem batches on one
/// session inside one behind window, a second before the node reached the
/// new tip. Each was ignored, their sender heard nothing, and each waited
/// out its whole embargo.
/// Red edit: return from `new_transactions` while unsynchronised, as it did.
#[test]
fn stems_received_while_behind_are_held_and_stemmed_at_sync() {
    let rig = Rig::build(Build {
        node_sync: NodeSync::Unsynchronised,
        ..Build::default()
    });
    let mut successor = rig.outbound(1);
    let mut sender = rig.inbound(1);
    for tag in [1, 2, 3] {
        sender.inject_blocking(new_transactions(vec![blob(tag)], false));
    }
    handled_so_far(&rig, &mut sender, 0xE1);
    assert!(
        rig.pool.admits().is_empty(),
        "nothing is offered to the pool while the node is behind"
    );
    assert!(
        rig.layer.board().get(sender.id).is_some(),
        "an unsynchronised node keeps the session"
    );
    assert!(
        rig.quiet(&mut successor),
        "nothing held is relayed before the turn"
    );
    assert!(rig.quiet(&mut sender));

    rig.node_sync
        .send(NodeSync::Synchronised)
        .expect("the owner listens");
    support::wait_until("all three were admitted", || rig.pool.admits().len() == 3);
    assert_eq!(
        rig.pool.admits(),
        vec![blob(1), blob(2), blob(3)],
        "in the order they arrived"
    );
    let stemmed: Vec<Vec<u8>> = rig
        .batches(&mut successor)
        .into_iter()
        .inspect(|batch| assert!(!batch.dandelionpp_fluff, "a held stem is still a stem"))
        .flat_map(|batch| batch.txs)
        .collect();
    assert_eq!(stemmed, vec![blob(1), blob(2), blob(3)]);
    assert!(rig.quiet(&mut sender));
}

/// A fluff that arrives while the node is behind is held too, and counted
/// when the node is synchronised: it is shown and fluffed on. A fluff
/// dropped at a node that is behind is a missed return for a stem that
/// node sent.
/// Red edit: hold only batches whose flag is stem.
#[test]
fn a_fluff_received_while_behind_is_shown_at_sync() {
    let rig = Rig::build(Build {
        node_sync: NodeSync::Unsynchronised,
        ..Build::default()
    });
    let mut sender = rig.inbound(1);
    let mut other = rig.inbound(2);
    sender.inject_blocking(new_transactions(vec![blob(5)], true));
    handled_so_far(&rig, &mut sender, 0xE2);
    assert!(rig.pool.admits().is_empty());
    assert!(rig.pool.shown().is_empty());

    rig.node_sync
        .send(NodeSync::Synchronised)
        .expect("the owner listens");
    support::wait_until("it was shown", || rig.pool.shown().len() == 1);
    assert_eq!(rig.pool.shown(), vec![id_of(&blob(5))]);
    let batch = rig.read_batch_within(&mut other, 10);
    assert!(batch.dandelionpp_fluff);
    assert_eq!(batch.txs, vec![blob(5)]);
}

/// A session that closes takes its held batches with it: nothing of them
/// reaches the pool at the turn.
/// Red edit: leave the session's entry in the hold when it closes.
#[test]
fn a_session_that_closes_takes_its_held_batches() {
    let rig = Rig::build(Build {
        node_sync: NodeSync::Unsynchronised,
        ..Build::default()
    });
    let mut leaver = rig.inbound(1);
    let mut stayer = rig.inbound(2);
    leaver.inject_blocking(new_transactions(vec![blob(7)], false));
    stayer.inject_blocking(new_transactions(vec![blob(8)], false));
    handled_so_far(&rig, &mut leaver, 0xE5);
    handled_so_far(&rig, &mut stayer, 0xE6);
    leaver.peer_closes();
    rig.wait_closed(leaver.id);

    rig.node_sync
        .send(NodeSync::Synchronised)
        .expect("the owner listens");
    support::wait_until("the staying session's batch was admitted", || {
        !rig.pool.admits().is_empty()
    });
    thread::sleep(SETTLE);
    assert_eq!(rig.pool.admits(), vec![blob(8)]);
}

/// A node that falls behind again holds again: the hold is for every gap,
/// not only the first sync.
/// Red edit: admit held batches once, at the first turn only.
#[test]
fn a_node_that_falls_behind_again_holds_again() {
    let rig = Rig::build(Build::default());
    let mut sender = rig.inbound(1);
    sender.inject_blocking(new_transactions(vec![blob(9)], true));
    support::wait_until("a synchronised node admits at once", || {
        rig.pool.admits().len() == 1
    });

    rig.node_sync
        .send(NodeSync::Unsynchronised)
        .expect("the owner listens");
    sender.inject_blocking(new_transactions(vec![blob(10)], true));
    handled_so_far(&rig, &mut sender, 0xE7);
    assert_eq!(rig.pool.admits().len(), 1, "held while behind");

    rig.node_sync
        .send(NodeSync::Synchronised)
        .expect("the owner listens");
    support::wait_until("admitted at the second turn", || {
        rig.pool.admits().len() == 2
    });
    assert_eq!(rig.pool.admits(), vec![blob(9), blob(10)]);
}

#[test]
fn a_fluff_batch_is_admitted_shown_and_fluffed_to_the_other_peers() {
    let rig = Rig::build(Build::default());
    let mut sender = rig.inbound(1);
    let mut other = rig.inbound(2);
    sender.inject_blocking(new_transactions(vec![blob(1), blob(2)], true));
    support::wait_until("both blobs were admitted", || rig.pool.admits().len() == 2);
    support::wait_until("both were shown", || rig.pool.shown().len() == 2);
    assert_eq!(rig.pool.shown(), vec![id_of(&blob(1)), id_of(&blob(2))]);
    // The fluff release sits on the zone's grid: advance until it fires.
    let batch = rig.read_batch_within(&mut other, 10);
    assert!(batch.dandelionpp_fluff, "a fluff release is flagged fluff");
    assert_eq!(batch.txs, vec![blob(1), blob(2)]);
    assert!(
        rig.quiet(&mut sender),
        "the source does not get its own batch back"
    );
}

#[test]
fn a_stem_batch_goes_to_an_outbound_successor_as_a_stem() {
    let rig = Rig::build(Build::default());
    let mut successor = rig.outbound(1);
    let mut sender = rig.inbound(1);
    sender.inject_blocking(new_transactions(vec![blob(3)], false));
    support::wait_until("the blob was admitted", || rig.pool.admits().len() == 1);
    let batch = rig.read_batch_within(&mut successor, 1);
    assert!(!batch.dandelionpp_fluff, "a stem is flagged stem");
    assert_eq!(batch.txs, vec![blob(3)]);
    assert!(
        rig.pool.shown().is_empty(),
        "a stemmed transaction is not shown until its embargo resolves"
    );
    assert!(rig.quiet(&mut sender));
    assert_eq!(rig.relay.snapshot().stem_in_flight, 1);
}

/// A node with no outbound session has no stem successor, so a stem it
/// receives takes the retry-then-fluff fallback and goes to its other
/// peers as a fluff. This is the designed path, taken for every stem such
/// a node holds; its log line is a debug line (the alpha.11 fleet: an
/// ERROR per stem on an inbound-only node).
#[test]
fn a_stem_with_no_outbound_successor_is_fluffed_to_the_other_peers() {
    let rig = Rig::build(Build::default());
    let mut sender = rig.inbound(1);
    let mut other = rig.inbound(2);
    sender.inject_blocking(new_transactions(vec![blob(4)], false));
    support::wait_until("the blob was admitted", || rig.pool.admits().len() == 1);
    support::wait_until("it was shown", || rig.pool.shown().len() == 1);
    let batch = rig.read_batch_within(&mut other, 10);
    assert!(batch.dandelionpp_fluff, "with no successor the stem fluffs");
    assert_eq!(batch.txs, vec![blob(4)]);
    assert!(
        rig.quiet(&mut sender),
        "the source does not get its own batch back"
    );
    assert_eq!(rig.relay.snapshot().stem_in_flight, 0);
}

#[test]
fn a_batch_that_repeats_a_blob_closes_the_session_before_the_pool_sees_it() {
    let rig = Rig::build(Build::default());
    let peer = rig.inbound(1);
    peer.inject_blocking(new_transactions(vec![blob(1), blob(1)], true));
    rig.wait_closed(peer.id);
    assert!(rig.pool.admits().is_empty());
    let told = rig.others.told.lock().expect("told");
    let closed = told.iter().find_map(|told| match told {
        support::Told::Closed(id, end) if *id == peer.id => Some(end.cause().kind()),
        _ => None,
    });
    assert_eq!(closed, Some(CloseKind::SessionRefused));
}

#[test]
fn a_malformed_blob_closes_the_session() {
    let rig = Rig::build(Build::default());
    rig.pool.script(&blob(9), Admit::RefusedForm);
    let peer = rig.inbound(1);
    peer.inject_blocking(new_transactions(vec![blob(9), blob(1)], true));
    rig.wait_closed(peer.id);
    assert_eq!(
        rig.pool.admits(),
        vec![blob(9)],
        "admission stops at the malformed blob"
    );
}

#[test]
fn a_state_refusal_keeps_the_session_and_records_the_arrival() {
    let rig = Rig::build(Build::default());
    rig.pool
        .script(&blob(5), Admit::RefusedState(id_of(&blob(5))));
    let mut peer = rig.inbound(1);
    peer.inject_blocking(new_transactions(vec![blob(5)], true));
    support::wait_until("the blob was offered", || rig.pool.admits().len() == 1);
    thread::sleep(SETTLE);
    assert!(rig.layer.board().get(peer.id).is_some());
    assert!(
        rig.pool.shown().is_empty(),
        "nothing admitted, nothing shown"
    );
    assert!(rig.quiet(&mut peer));
}

#[test]
fn a_complement_request_is_answered_from_the_pool() {
    let rig = Rig::build(Build::default());
    rig.pool.set_complement(vec![blob(7), blob(8)]);
    let mut peer = rig.inbound(1);
    peer.inject_blocking(txpool_complement(vec![[1; 32], [2; 32]]));
    let batch = rig.read_batch(&mut peer);
    assert_eq!(batch.txs, vec![blob(7), blob(8)]);
    assert!(!batch.dandelionpp_fluff);
    assert!(rig.pool.asked().iter().any(|asked| matches!(
        asked,
        Asked::Complement(known) if known.len() == 2
    )));
}

#[test]
fn a_local_origin_waits_for_sync_then_leaves() {
    let rig = Rig::build(Build {
        node_sync: NodeSync::Unsynchronised,
        ..Build::default()
    });
    let mut successor = rig.outbound(1);
    let tx = id_of(&blob(4));
    assert!(rig.relay.relay_local(tx, blob(4)), "the owner took it");
    thread::sleep(SETTLE);
    assert!(
        rig.quiet(&mut successor),
        "nothing leaves an unsynchronised node"
    );
    assert!(rig.pool.shown().is_empty());
    rig.node_sync
        .send(NodeSync::Synchronised)
        .expect("the owner listens");
    let batch = rig.read_batch_within(&mut successor, 1);
    assert_eq!(batch.txs, vec![blob(4)]);
    assert!(!batch.dandelionpp_fluff, "an origin stems");
}

#[test]
fn a_slow_pool_holds_the_sessions_reads() {
    let rig = Rig::build(Build::default());
    let peer = rig.inbound(1);
    rig.pool.close_gate();
    peer.inject_blocking(new_transactions(vec![blob(1)], true));
    peer.inject_blocking(new_transactions(vec![blob(2)], true));
    support::wait_until("the first blob reached the pool", || {
        rig.pool.admits().len() == 1
    });
    thread::sleep(SETTLE);
    assert_eq!(
        rig.pool.admits().len(),
        1,
        "the second batch waits on the first batch's permit"
    );
    rig.pool.open_gate();
    support::wait_until("the second blob reached the pool", || {
        rig.pool.admits().len() == 2
    });
    drop(peer);
}

#[test]
fn a_held_origin_that_departs_is_not_sent_after_sync() {
    let rig = Rig::build(Build {
        node_sync: NodeSync::Unsynchronised,
        ..Build::default()
    });
    let mut successor = rig.outbound(1);
    assert!(rig.relay.relay_local(id_of(&blob(4)), blob(4)));
    thread::sleep(SETTLE);
    // Mined meanwhile: the pool dropped it, the zone forgets it.
    rig.relay.departed(vec![id_of(&blob(4))]);
    thread::sleep(SETTLE);
    rig.node_sync
        .send(NodeSync::Synchronised)
        .expect("the owner listens");
    thread::sleep(SETTLE);
    assert!(
        rig.quiet(&mut successor),
        "a departed origin does not leave"
    );
}

/// **A node built with no connector shows its own transaction at once.** It
/// has no network: there is no stem to send and no peer to hide it from, and
/// its own blocks can carry the transaction only once it is shown. The
/// clock does not move in this test, so no retry or embargo shows it.
///
/// What edit reds this: hold a local origin whose plan is still `NoRoute`
/// after `dispatch`'s refresh, where it fluffs today (the transaction is
/// held and never shown).
#[test]
fn a_node_with_no_connector_shows_its_own_transaction_at_once() {
    let rig = Rig::build(Build {
        offline: true,
        ..Build::default()
    });
    let tx = id_of(&blob(4));
    assert!(rig.relay.relay_local(tx, blob(4)), "the owner took it");
    support::wait_until("its own transaction was shown", || {
        rig.pool.shown().contains(&tx)
    });
    assert!(
        rig.relay.snapshot().stem_in_flight == 0,
        "nothing was stemmed: there is nowhere to send it"
    );
}

/// The word the embargo tests fix every draw at: a quarter of the way up
/// the range, so the deadline it draws is well inside the first epoch and
/// far from zero. Its remainder by 100 is 54, above the epoch's fluff
/// percentage, so the epoch this node draws is a stem epoch and a relayed
/// stem is forwarded as one.
const FIXED_WORD: u64 = (1 << 62) + 50;

/// How long after a stem's write the clearnet embargo drawn from
/// [`FIXED_WORD`] fires: the production timer's own draw, from time zero.
fn fixed_embargo() -> Duration {
    let transit = transit_ms(ConnectorId::Clearnet).expect("clearnet is a stem path");
    let timer = EmbargoTimer::adopted(&DandelionParams::adopted_for_transit_ms(transit));
    Duration::from_millis(timer.deadline(0, &mut FixedDraw(FIXED_WORD)))
}

/// One transaction through the running owner, its clock moved by the test
/// alone: stemmed once, held unseen until its embargo's deadline, re-stemmed
/// to the alternate when the deadline passes. `own` submits it as this
/// node's own; otherwise it arrives as a stem from an inbound peer.
fn a_stem_is_held_to_its_deadline_then_re_stemmed(own: bool) {
    let rig = Rig::build(Build {
        draws: Draws::Fixed(FIXED_WORD),
        ..Build::default()
    });
    let mut one = rig.outbound(1);
    let mut two = rig.outbound(2);
    let mut sender = rig.inbound(1);
    let embargo = fixed_embargo();
    assert!(
        embargo > Duration::from_secs(1),
        "the fixed draw is a real wait: {embargo:?}"
    );
    let tx = id_of(&blob(6));
    if own {
        assert!(rig.relay.relay_local(tx, blob(6)), "the owner took it");
    } else {
        sender.inject_blocking(new_transactions(vec![blob(6)], false));
        support::wait_until("the blob was admitted", || rig.pool.admits().len() == 1);
    }

    // The clock has not moved: stemmed once, to one successor.
    support::wait_until("the stem was recorded", || {
        rig.relay.snapshot().stem_in_flight == 1
    });
    let (first, second) = (rig.batches(&mut one), rig.batches(&mut two));
    let (mut first_took, mut alternate) = match (first.len(), second.len()) {
        (1, 0) => (first, two),
        (0, 1) => (second, one),
        other => panic!("one stem to one successor, read {other:?}"),
    };
    let stem = first_took.pop().expect("one batch");
    assert!(!stem.dandelionpp_fluff, "the first send is a stem");
    assert_eq!(stem.txs, vec![blob(6)]);

    // Still frozen, then one millisecond short of the deadline: nothing more
    // leaves, and the pool does not show it.
    let unseen = |when: &str, alternate: &mut Wire, sender: &mut Wire| {
        assert!(
            rig.quiet(alternate),
            "{when}: nothing reaches the alternate"
        );
        assert!(rig.quiet(sender), "{when}: nothing reaches the other peer");
        assert!(
            rig.pool.shown().is_empty(),
            "{when}: the pool shows nothing"
        );
        assert_eq!(
            rig.relay.snapshot().stem_in_flight,
            1,
            "{when}: still in flight"
        );
    };
    unseen("with the clock frozen", &mut alternate, &mut sender);
    let short = embargo
        .checked_sub(Duration::from_millis(1))
        .expect("the embargo is longer than a millisecond");
    rig.advance(short);
    unseen(
        "a millisecond before the deadline",
        &mut alternate,
        &mut sender,
    );

    // At the deadline: one re-stem to the alternate, and still not shown.
    rig.advance(Duration::from_millis(1));
    let again = rig.read_batch(&mut alternate);
    assert!(!again.dandelionpp_fluff, "the first fire re-stems");
    assert_eq!(again.txs, vec![blob(6)]);
    assert!(rig.quiet(&mut sender), "the first fire broadcasts nothing");
    assert!(
        rig.pool.shown().is_empty(),
        "a re-stemmed transaction is still not shown"
    );
}

/// **The running owner holds this node's own transaction for the embargo it
/// drew.** The graph's tests prove the draw and the live walks prove the
/// order (stem, then broadcast); this proves the owner arms the engine with
/// that draw, on its own clock. The draw is fixed, so the deadline is known
/// to the millisecond and the test never waits on chance.
///
/// What edit reds this: in the owner, pass a clock value other than the
/// write's where a stem is recorded (`record_stem`, `commit_stem`). With `0`
/// for `now` the deadline is one millisecond early, and this test and the
/// relayed one both fail at "a millisecond before the deadline".
#[test]
fn an_own_transaction_is_held_to_its_embargo_deadline_then_re_stemmed() {
    a_stem_is_held_to_its_deadline_then_re_stemmed(true);
}

/// The same steps for a stem this node relays: through the running owner an
/// own transaction and a relayed one are held alike and re-stemmed alike.
#[test]
fn a_relayed_stem_is_held_to_its_embargo_deadline_then_re_stemmed() {
    a_stem_is_held_to_its_deadline_then_re_stemmed(false);
}

#[test]
fn stopping_the_owner_refuses_a_local_origin() {
    let rig = Rig::build(Build::default());
    rig.relay.stop();
    support::wait_until("the owner stopped", || {
        !rig.relay.relay_local(id_of(&blob(1)), blob(1))
    });
}
