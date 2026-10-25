// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The floor-device job's loopback figures (CS-Q11; `.github/workflows/
//! cs2-long-run.yml`). `cargo test` does not build it.
//!
//! It records what loopback can measure on the floor device, and nothing
//! a network decides:
//!
//! - **Hash rate per slot.** Header proofs through the executor under the
//!   hasher budget: one slot, then every slot, after the branch cache is
//!   built, so the figure is RandomX's and not the derivation's. The cache
//!   build is timed on its own.
//! - **The body phase.** Each captured corpus synced by a fresh node from
//!   two honest peers over real Levin framing, through the owner, the
//!   entry and the store: bodies per second, bytes per second, the
//!   requests, and peak memory.
//!
//! The owner's cost per header is the model's long run
//! (`shekyl-chain-sync`, `long_run.rs`). The rate floor and the spans in
//! flight are a network's and are measured after the cutover, on regtest
//! over a real Tor path (CS-Q11).

#![cfg(feature = "cs2-long-run")]
// The figures are this job's output.
#![allow(clippy::print_stderr)]

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use shekyl_chain_rules::{target_claim, FormAttempt};
use shekyl_chain_store::store::SnapshotView;
use shekyl_chain_sync::{CachePlan, HashClass, ProveItem, Proved, SyncState};
use shekyl_chain_sync_runtime::executor::{prove, Executor};
use shekyl_draw_rng::SplitMix64;
use shekyl_hash_budget::Budget;
use shekyl_p2p_harness::sync::{substrate, Bodies, Chain, Corpus, Node, ServingPeer, Step};
use shekyl_seam::SyncPayload;
use shekyl_types::{BlockHash, BlockHeight};

const LIMIT: Duration = Duration::from_secs(48 * 60 * 60);

/// Proofs per slot in one timed job.
const PROOFS_PER_SLOT: usize = 32;

/// The captured corpora, smallest first, and the last height read when
/// not the tip. A block at 98 in `bond-post` and in `emission-claim`
/// carries a transaction kind that is retired, which the reader refuses:
/// `bond-post` is read through 97, as the loopback suite reads it, and
/// `emission-claim` is left out, since its first 97 blocks add nothing the
/// others do not.
const CORPORA: [(&str, Option<u64>); 5] = [
    ("spend-1in-2out", None),
    ("bond-post", Some(97)),
    ("limit-full", None),
    ("median-full", None),
    ("spend-depth3", None),
];

/// The node's draw source: seeded, so a run repeats.
fn rng() -> SplitMix64 {
    SplitMix64::new(0x5EED)
}

fn claim_of(chain: &Chain) -> SyncPayload {
    let (count, work, top) = chain.tip().expect("a chain");
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

/// A store holding `corpus`, connected from its own node.
async fn source(corpus: &Corpus, steps: &[Step]) -> Chain {
    let (substrate, _) = substrate();
    let chain = Chain::empty(
        &format!("long-{}", corpus.shape),
        corpus.rules(),
        Arc::new(substrate),
        Budget::new(NonZeroUsize::new(4).expect("four")),
    );
    chain.apply(steps).await;
    chain
}

/// Hash rate per slot: header proofs under a budget of one slot, then of
/// every slot this host has, each after the branch cache is built.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hash_rate_per_slot() {
    let corpus = Corpus::open("spend-1in-2out");
    let steps = corpus.steps();
    let held = source(&corpus, &steps).await;
    let rules = corpus.rules();
    let (count, _, _) = held.tip().expect("a chain");
    // Each proof is one of the corpus's own headers, claimed under its
    // target, so the work is a header proof's and nothing else.
    let items: Vec<ProveItem> = {
        let snap = held.store.begin_read().expect("a read");
        let view = SnapshotView::new(&snap);
        (1..count)
            .map(|height| {
                let at = BlockHeight::from_raw(height);
                let rule_set = rules.in_force(at);
                let target = target_claim(&view, at, &rule_set)
                    .expect("a read")
                    .expect("a target");
                ProveItem {
                    pow: held.block(height).pow_blob(),
                    seed: BlockHash::from_bytes([0x5e; 32]),
                    target,
                    attempt: FormAttempt::FIRST,
                    rule_set,
                }
            })
            .collect()
    };
    let slots = std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN);
    for permits in [NonZeroUsize::MIN, slots] {
        let (prover, _) = substrate();
        let executor = Arc::new(Executor::new(Budget::new(permits), prover));
        let seed = BlockHash::from_bytes([u8::try_from(permits.get() % 251).unwrap_or(1); 32]);
        let plan = CachePlan::Branch(seed);
        let job = |n: usize| -> Vec<ProveItem> {
            items
                .iter()
                .cycle()
                .take(n)
                .cloned()
                .map(|item| ProveItem { seed, ..item })
                .collect()
        };
        // A job with no items still prepares the cache and hashes nothing,
        // so this interval is the derivation. The one-proof warm-up is
        // outside it: folding that proof in overstates the derivation,
        // most on the floor device where one hash dominates the build.
        let started = Instant::now();
        let derived = prove(Arc::clone(&executor), HashClass::HeaderPow, plan, job(0)).await;
        let derive = started.elapsed();
        assert!(derived.is_empty(), "{derived:?}");
        let warm = prove(Arc::clone(&executor), HashClass::HeaderPow, plan, job(1)).await;
        assert!(matches!(warm.as_slice(), [Proved::Formed(_)]), "{warm:?}");
        let n = PROOFS_PER_SLOT * permits.get();
        let started = Instant::now();
        let proved = prove(Arc::clone(&executor), HashClass::HeaderPow, plan, job(n)).await;
        let hashing = started.elapsed();
        assert_eq!(proved.len(), n, "every proof formed");
        let rate = f64::from(u32::try_from(n).expect("a count")) / hashing.as_secs_f64();
        eprintln!(
            "slots {permits}: {n} proofs in {hashing:?}: {rate:.2} proofs/s, {:.2} per slot \
             (branch cache built in {derive:?})",
            rate / f64::from(u32::try_from(permits.get()).expect("a count"))
        );
    }
    held.stop().await;
}

/// The body phase: each captured corpus synced by a fresh node from two
/// honest peers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn body_phase_on_the_captured_corpora() {
    let _installed = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    for (shape, last) in CORPORA {
        let corpus = Corpus::open(shape);
        let steps = last.map_or_else(|| corpus.steps(), |last| corpus.steps_through(last));
        let held = source(&corpus, &steps).await;
        let (count, _, _) = held.tip().expect("a chain");
        let bytes: usize = steps
            .iter()
            .skip(1)
            .map(|step| match step {
                Step::Block { block, bodies } => {
                    block.len() + bodies.iter().map(Vec::len).sum::<usize>()
                }
                Step::Inject(_) => 0,
            })
            .sum();
        let mut node = Node::start(
            &format!("long-bodies-{shape}"),
            corpus.rules(),
            &steps[..1],
            4,
            rng(),
        )
        .await;
        let started = Instant::now();
        let mut seen = Vec::new();
        for _ in 0..2 {
            let (peer, asked) = ServingPeer::new(Arc::clone(&held.store), Bodies::Honest);
            node.connect(Box::new(peer), Some(claim_of(&held)));
            seen.push(asked);
        }
        assert!(
            node.wait(LIMIT, |node| node.state() == SyncState::Synced
                && node.count() == count)
                .await,
            "{shape}: state {:?}, count {} of {count}",
            node.state(),
            node.count()
        );
        let took = started.elapsed();
        let blocks = f64::from(u32::try_from(count - 1).expect("a corpus"));
        let kib = f64::from(u32::try_from(bytes / 1024).expect("a corpus"));
        eprintln!(
            "{shape}: {} blocks, {kib:.0} KiB, in {took:?}: {:.2} bodies/s, {:.1} KiB/s; \
             {} header and {} body requests; peak resident set {:?} KiB",
            count - 1,
            blocks / took.as_secs_f64(),
            kib / took.as_secs_f64(),
            seen.iter().map(|asked| asked.headers()).sum::<usize>(),
            seen.iter().map(|asked| asked.bodies()).sum::<usize>(),
            peak_kib()
        );
        node.stop().await;
        held.stop().await;
    }
}
