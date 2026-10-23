// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CS-Q11 end to end (`P2P_3_CHAIN_SYNC_BRIEF.md`, CS-3 §5): the sync
//! model, driven by real Levin frames over the seam, with real RandomX
//! under the hasher budget, syncing a real store through the real ingest
//! entry, against each scripted peer.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use shekyl_chain_sync::SyncState;
use shekyl_hash_budget::Budget;
use shekyl_p2p_harness::sync::{substrate, Bodies, Chain, Corpus, Node, ServingPeer, Step};
use shekyl_seam::SyncPayload;
use shekyl_types::BlockHash;

const SYNC_LIMIT: Duration = Duration::from_secs(120);

/// The owner's log lines, under `RUST_LOG`.
fn logs() {
    let _installed = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

/// A peer's handshake claim: its block count and cumulative work.
fn claim(count: u64, work: u128, top: BlockHash) -> SyncPayload {
    SyncPayload {
        current_height: count,
        cumulative_difficulty: u64::try_from(work & u128::from(u64::MAX)).expect("low"),
        cumulative_difficulty_top64: u64::try_from(work >> 64).expect("high"),
        top_id: *top.as_bytes(),
    }
}

/// A store holding `steps`, connected from its own node.
async fn source(tag: &str, corpus: &Corpus, steps: &[Step]) -> Chain {
    let (substrate, _) = substrate();
    let chain = Chain::empty(
        tag,
        corpus.rules(),
        Arc::new(substrate),
        Budget::new(NonZeroUsize::new(4).expect("four")),
    );
    chain.apply(steps).await;
    chain
}

/// A fresh node syncs a captured corpus from two honest peers and reaches
/// `Synced`. Every block connects through `form_judged`: the substrate
/// hashes each header once, and nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fresh_node_syncs_a_corpus_from_two_honest_peers_hashing_headers_only() {
    logs();
    let corpus = Corpus::open("spend-1in-2out");
    let steps = corpus.steps();
    let held = source("honest-src", &corpus, &steps).await;
    let (count, work, top) = held.tip().expect("a chain");
    let mut node = Node::start("fresh", corpus.rules(), &steps[..1], 2).await;
    let before = node.hashes();
    for _ in 0..2 {
        let (peer, _) = ServingPeer::new(Arc::clone(&held.store), Bodies::Honest);
        node.connect(Box::new(peer), Some(claim(count, work, top)));
    }
    let synced = node
        .wait(SYNC_LIMIT, |node| {
            node.state() == SyncState::Synced && node.count() == count
        })
        .await;
    assert!(
        synced,
        "state {:?}, count {} of {count}",
        node.state(),
        node.count()
    );
    assert_eq!(
        node.hashes() - before,
        count - 1,
        "one hash per header and none in the entry"
    );
    node.stop().await;
    held.stop().await;
}
