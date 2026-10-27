// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The inbound claim and the relay fan-out (CS-Q10, CS-Q2 step 7).
//!
//! An inbound session's claim arrives in its handshake request, which the
//! router's claim tap copies to the owner. A block that connects is sent
//! compact to every established session but the one that supplied it.

use std::sync::Arc;
use std::time::Duration;

use shekyl_chain_sync::SyncState;
use shekyl_levin::{
    invoke, BasicNodeData, CoreSyncData, HandshakeRequest, PortableMap, COMMAND_HANDSHAKE,
};
use shekyl_p2p_harness::sync::{announcement, Bodies, Node, ServingPeer};

#[path = "chain_sync/support.rs"]
mod support;

use support::{claim, claim_of, logs, rng, source, spend, wait_synced, LIMIT};

/// An inbound session's claim arrives in its handshake request, which the
/// router's claim tap copies to the owner (CS-Q10, Rick 2026-10-24):
/// before it the session is no source; after it the session serves the
/// headers and the bodies, with no outbound dial.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_inbound_session_serves_the_sync_after_its_handshake_request() {
    logs();
    let (corpus, steps) = spend();
    let held = source("inbound-src", &corpus, &steps).await;
    let (count, _, _) = held.tip().expect("a chain");
    let mut node = Node::start("inbound", corpus.rules(), &steps[..1], 2, rng()).await;
    let (peer, seen) = ServingPeer::new(Arc::clone(&held.store), Bodies::Honest);
    let id = node.accept(Box::new(peer));
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        seen.headers(),
        0,
        "an inbound session with no claim is no source"
    );
    let claim = claim_of(&held);
    let request = HandshakeRequest {
        node_data: BasicNodeData {
            network_id: [0; 16],
        },
        payload_data: CoreSyncData {
            current_height: claim.current_height,
            cumulative_difficulty: claim.cumulative_difficulty,
            cumulative_difficulty_top64: claim.cumulative_difficulty_top64,
            top_id: claim.top_id,
        },
        nonce: [0; 32],
    }
    .store()
    .expect("the request encodes");
    assert!(node.inject(id, invoke(COMMAND_HANDSHAKE, &request)).await);
    wait_synced(&node, count).await;
    assert!(seen.headers() >= 1 && seen.bodies() >= 1);
    assert!(
        node.stub
            .lock()
            .expect("stub")
            .commands
            .contains(&(id, COMMAND_HANDSHAKE)),
        "the C++ handler still receives the handshake"
    );
    node.stop().await;
    held.stop().await;
}

/// A connected announcement is relayed (CS-Q2 step 7): to
/// every established session but the one that announced it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connected_announcement_is_relayed_to_every_other_session() {
    logs();
    let (corpus, steps) = spend();
    let held = source("relay-src", &corpus, &steps).await;
    let (count, _, _) = held.tip().expect("a chain");
    // The node holds every block but the last.
    let mut node = Node::start("relay", corpus.rules(), &steps[..steps.len() - 1], 2, rng()).await;
    let (_, work, top) = node.chain.tip().expect("a chain");
    let mut seen = Vec::new();
    let mut ids = Vec::new();
    for _ in 0..3 {
        let (peer, asked) = ServingPeer::new(Arc::clone(&held.store), Bodies::Honest);
        seen.push(asked);
        ids.push(node.connect(Box::new(peer), Some(claim(count - 1, work, top))));
    }
    assert!(
        node.wait(LIMIT, |node| node.state() == SyncState::Synced)
            .await,
        "state {:?}",
        node.state()
    );
    assert!(
        node.inject(ids[0], announcement(&held.store, count - 1))
            .await
    );
    assert!(
        node.wait(LIMIT, |node| node.count() == count).await,
        "the announcement did not connect"
    );
    assert!(
        node.wait(LIMIT, |_| seen[1].announced() == 1
            && seen[2].announced() == 1)
            .await,
        "relayed {:?}",
        seen.iter().map(|seen| seen.announced()).collect::<Vec<_>>()
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(seen[0].announced(), 0, "not back to the announcer");
    node.stop().await;
    held.stop().await;
}

/// A synced node that fetches the next block by sync relays it once it
/// connects, to every established session but the one that supplied it
/// (CS-Q2 step 7, amended 2026-10-24). Two peers hold the node's own tip;
/// a third claims one block more, serves its header and body, and never
/// receives that block back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_block_fetched_by_sync_is_relayed_to_all_but_its_supplier() {
    logs();
    let (corpus, steps) = spend();
    let held = source("sync-relay-src", &corpus, &steps).await;
    let full = claim_of(&held);
    let (count, _, _) = held.tip().expect("a chain");
    let mut node = Node::start(
        "sync-relay",
        corpus.rules(),
        &steps[..steps.len() - 1],
        2,
        rng(),
    )
    .await;
    let (_, work, top) = node.chain.tip().expect("a chain");
    let mut level = Vec::new();
    for _ in 0..2 {
        let (peer, seen) = ServingPeer::new(Arc::clone(&held.store), Bodies::Honest);
        node.connect(Box::new(peer), Some(claim(count - 1, work, top)));
        level.push(seen);
    }
    assert!(
        node.wait(LIMIT, |node| node.state() == SyncState::Synced)
            .await,
        "state {:?}",
        node.state()
    );
    let (peer, supplier) = ServingPeer::new(Arc::clone(&held.store), Bodies::Honest);
    node.connect(Box::new(peer), Some(full));
    assert!(
        node.wait(LIMIT, |node| node.count() == count).await,
        "the next block was not fetched"
    );
    assert!(supplier.bodies() >= 1, "the block came by sync");
    assert!(
        node.wait(LIMIT, |_| level.iter().all(|seen| seen.announced() == 1))
            .await,
        "relayed {:?}",
        level
            .iter()
            .map(|seen| seen.announced())
            .collect::<Vec<_>>()
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(supplier.announced(), 0, "not back to the supplier");
    node.stop().await;
    held.stop().await;
}
