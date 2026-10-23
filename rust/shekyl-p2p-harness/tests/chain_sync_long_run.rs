// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The floor-device job's loopback sync (CS-Q11; `.github/workflows/
//! cs2-long-run.yml`): a captured corpus synced whole, then 50,000
//! headers at fixed target 1, each over real Levin framing into the real
//! owner, executor and RandomX. `cargo test` does not build it.
//!
//! It records what CS-Q11 replaces the Assumptions from: headers per
//! second, bodies per second, peak memory, and the time per request.
//! Transit on loopback is not a network's; the time per request is the
//! node's own turnaround, the floor under any network's.

#![cfg(feature = "cs2-long-run")]
// The figures are this job's output.
#![allow(clippy::print_stderr)]

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use shekyl_chain_sync::SyncState;
use shekyl_hash_budget::Budget;
use shekyl_p2p_harness::sync::{
    fork_headers, substrate, Bodies, Chain, Corpus, HeaderChainPeer, Node, ServingPeer,
};
use shekyl_seam::SyncPayload;
use shekyl_types::BlockHash;

const HEADERS: u64 = 50_000;
const LIMIT: Duration = Duration::from_secs(48 * 60 * 60);

fn claim(count: u64, work: u128, top: BlockHash) -> SyncPayload {
    SyncPayload {
        current_height: count,
        cumulative_difficulty: u64::try_from(work & u128::from(u64::MAX)).expect("low"),
        cumulative_difficulty_top64: u64::try_from(work >> 64).expect("high"),
        top_id: *top.as_bytes(),
    }
}

/// The process's peak resident set, from `/proc/self/status` (`VmHWM`).
fn peak_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse().ok())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn loopback_sync_of_a_corpus_and_fifty_thousand_headers() {
    let corpus = Corpus::open("spend-1in-2out");
    let steps = corpus.steps();
    let (substrate, _) = substrate();
    let held = Chain::empty(
        "long-src",
        corpus.rules(),
        Arc::new(substrate),
        Budget::new(NonZeroUsize::new(4).expect("four")),
    );
    held.apply(&steps).await;
    let (count, work, top) = held.tip().expect("a chain");

    // Bodies: the corpus, whole.
    let mut node = Node::start("long-bodies", corpus.rules(), &steps[..1], 4).await;
    let started = Instant::now();
    let (peer, seen) = ServingPeer::new(Arc::clone(&held.store), Bodies::Honest);
    node.connect(Box::new(peer), Some(claim(count, work, top)));
    assert!(
        node.wait(LIMIT, |node| node.state() == SyncState::Synced
            && node.count() == count)
            .await
    );
    let bodies = started.elapsed();
    eprintln!(
        "corpus: {} blocks in {bodies:?}: {:.2} bodies/s, {} header and {} body requests",
        count - 1,
        f64::from(u32::try_from(count - 1).expect("a corpus")) / bodies.as_secs_f64(),
        seen.headers(),
        seen.bodies()
    );
    node.stop().await;

    // Headers: 50,000 at target 1 over genesis, never offered as bodies.
    let mut chain = vec![(held.block(0).hash(), held.block(0).pow_blob())];
    chain.extend(fork_headers(&held, 0, HEADERS));
    let tip = chain.last().expect("headers").0;
    let tip_work = u128::from(HEADERS + 1);
    let mut node = Node::start("long-headers", corpus.rules(), &steps[..1], 4).await;
    let started = Instant::now();
    let (peer, seen) = HeaderChainPeer::new(chain, tip_work);
    node.connect(Box::new(peer), Some(claim(HEADERS + 1, tip_work, tip)));
    let verified = node
        .wait(LIMIT, |node| {
            matches!(node.state(), SyncState::Behind { best, .. } if best.to_raw() == tip_work)
        })
        .await;
    let headers = started.elapsed();
    assert!(verified, "state {:?}", node.state());
    let requests = seen.headers().max(1);
    eprintln!(
        "headers: {HEADERS} in {headers:?}: {:.1} headers/s, {} requests, {:?} per request",
        f64::from(u32::try_from(HEADERS).expect("fits")) / headers.as_secs_f64(),
        seen.headers(),
        headers / u32::try_from(requests).unwrap_or(u32::MAX)
    );
    eprintln!("peak resident set: {:?} KiB", peak_kib());
    node.stop().await;
    held.stop().await;
}
