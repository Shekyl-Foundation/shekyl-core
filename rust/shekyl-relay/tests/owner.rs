// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The relay owner on live sessions (`P2P_3_REMNANT_CUTOVER_BRIEF.md`
//! §2.1, §5): 2002 before sync is ignored, after sync admitted and
//! relayed; a bad batch severs; 2010 is served from the pool; a local
//! origin waits for sync; a slow pool holds the session's reads.

mod support;

use std::thread;

use shekyl_p2p_session::CloseKind;
use shekyl_relay::owner::Admit;
use shekyl_relay::NodeSync;
use support::{blob, id_of, new_transactions, txpool_complement, Asked, Build, Rig, SETTLE};

#[test]
fn a_batch_before_sync_is_ignored_and_the_session_stays() {
    let rig = Rig::build(Build {
        node_sync: NodeSync::Unsynchronised,
        ..Build::default()
    });
    let mut peer = rig.inbound(1);
    peer.inject_blocking(new_transactions(vec![blob(1), blob(2)], true));
    thread::sleep(SETTLE);
    assert!(
        rig.pool.admits().is_empty(),
        "nothing was offered to the pool"
    );
    assert!(
        rig.layer.board().get(peer.id).is_some(),
        "an unsynchronised node keeps the session"
    );
    assert!(rig.quiet(&mut peer));
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

#[test]
fn stopping_the_owner_refuses_a_local_origin() {
    let rig = Rig::build(Build::default());
    rig.relay.stop();
    support::wait_until("the owner stopped", || {
        !rig.relay.relay_local(id_of(&blob(1)), blob(1))
    });
}
