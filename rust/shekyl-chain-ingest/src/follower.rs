// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The tip follower: the ingest service's one consumer of [`TipChanged`]
//! that acts on the store's side (`DRS_X_STORE_FLIP.md` DX-Q2 item 5).
//!
//! Per tip it publishes, in order:
//! 1. the miner's next job, while the node is synced: the template for the
//!    block after the tip, from the [`TemplateSource`]; the seed it is
//!    hashed under, `seed(tip + 1)`, pinned through the substrate **before**
//!    [`JobBoard::publish`]; the target the miner must meet. While the node
//!    is behind, the board is withdrawn.
//!
//! The miner hashes only under a held cache, and nothing else pins the seed
//! a new epoch's first block is hashed under — the genesis hash, for height
//! 1 — so without the pin the first block of every seed epoch could not be
//! mined here. The pin is the pipeline's own seed: the one derivation the
//! hasher budget allows (PR2-Q3).
//!
//! **The template source is a seam.** The block a job carries is the
//! source's: in tests the scenario driver's template; at the flip, PR 3b's
//! `get_block_template` assembler (`shekyl-block-template` with the pool's
//! selection), which this producer then shares with the RPC. The producer
//! claims the seed and the target itself, on one snapshot, through the
//! router's derivation.
//!
//! **The found-block sink.** A found block enters through the service's
//! one door as a local arrival, with the listed bodies its job carried.

use std::collections::BTreeMap;
use std::sync::{mpsc, Arc, Mutex};

use shekyl_chain_rules::Substrate;
use shekyl_miner::{Found, Generation, Job, JobBoard};
use shekyl_wire::{Block, Transaction};
use tokio::sync::watch;

use crate::connector::{ChainFacts, TemplateFacts, TipChanged};
use crate::router::claim_next;
use crate::service::{Arrival, ArrivalTag, Door, Origin, Shared};

/// Where the miner's blocks come from (module docs).
pub trait TemplateSource: Send + Sync + 'static {
    /// The block to mine after the tip `facts` describes, and its listed
    /// bodies; `None` when it cannot build one now.
    fn template(&self, facts: &ChainFacts) -> Option<(Block, Vec<Transaction>)>;
}

/// The miner, as the follower feeds it.
pub struct MinerFeed {
    /// The board the miner's workers read.
    pub board: Arc<JobBoard>,
    /// What each job's block is.
    pub source: Arc<dyn TemplateSource>,
    /// Whether the node is synced: the sync owner's. While it reads
    /// `false`, the board is withdrawn.
    pub synced: watch::Receiver<bool>,
    /// The miner's found-block channel.
    pub found: mpsc::Receiver<Found>,
}

/// Jobs kept for the found-block sink: a found block's generation names
/// the bodies it was built with. A miner finds for the newest posting, so
/// only the last few are ever asked for.
const KEPT_JOBS: usize = 8;

/// Each posted generation's listed bodies.
type Postings = Arc<Mutex<BTreeMap<Generation, Vec<Transaction>>>>;

/// Run the follower until the service stops (module docs).
pub(crate) async fn follow<S>(
    shared: Arc<Shared<S>>,
    door: Door,
    mut tips: watch::Receiver<TipChanged>,
    feed: MinerFeed,
) where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    let MinerFeed {
        board,
        source,
        mut synced,
        found,
    } = feed;
    let postings: Postings = Arc::new(Mutex::new(BTreeMap::new()));
    let sink = spawn_sink(found, door, Arc::clone(&postings));
    let mut stopping = shared.stop_signal();
    loop {
        let tip = *tips.borrow_and_update();
        if *synced.borrow_and_update() {
            post(&shared, &board, source.as_ref(), &postings).await;
        } else {
            board.withdraw();
        }
        shared.followed(tip.seq);
        tokio::select! {
            changed = tips.changed() => if changed.is_err() { break },
            changed = synced.changed() => if changed.is_err() { break },
            _ = stopping.wait_for(|stop| *stop) => break,
        }
    }
    board.withdraw();
    // The sink ends when the miner's sender goes; it is not joined here.
    drop(sink);
}

/// Build, pin and post the job for the block after the tip. A tip that
/// moves under the build is left for the next publication.
async fn post<S>(
    shared: &Arc<Shared<S>>,
    board: &JobBoard,
    source: &dyn TemplateSource,
    postings: &Postings,
) where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    let Ok(facts) = shared.connector().ask(TemplateFacts).await else {
        board.withdraw();
        return;
    };
    let store = Arc::clone(shared.store());
    let rules = shared.rules();
    let claimed = tokio::task::spawn_blocking(move || claim_next(&store, rules))
        .await
        .expect("the claim reader does not panic");
    let Ok((height, seed, target)) = claimed else {
        board.withdraw();
        return;
    };
    if height != facts.connecting {
        // The tip moved between the two reads; its publication follows.
        return;
    }
    let Some((block, transactions)) = source.template(&facts) else {
        board.withdraw();
        return;
    };
    // seed(tip + 1) held before the job is: the miner looks seeds up only.
    let substrate = Arc::clone(shared.substrate());
    tokio::task::spawn_blocking(move || substrate.pin_seed(&seed))
        .await
        .expect("a pin does not panic");
    shared.pinned_now(seed);
    let generation = board.publish(Job {
        block,
        height,
        seed,
        difficulty: target.difficulty(),
    });
    let mut kept = postings
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    kept.insert(generation, transactions);
    while kept.len() > KEPT_JOBS {
        kept.pop_first();
    }
}

/// The found-block sink: each found block offered through the door as a
/// local arrival with its job's bodies. On a thread of its own, because the
/// miner's channel blocks; it ends when the miner's sender is dropped.
fn spawn_sink(
    found: mpsc::Receiver<Found>,
    door: Door,
    postings: Postings,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        while let Ok(found) = found.recv() {
            let bodies = postings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&found.generation)
                .cloned()
                .unwrap_or_default();
            let arrival = Arrival {
                tag: ArrivalTag(found.generation.to_raw()),
                origin: Origin::Local,
                block: found.block.serialize(),
                bodies: bodies.iter().map(Transaction::serialize).collect(),
            };
            // The reply has no reader here: the tip the connect publishes
            // is what the follower acts on.
            let _ticket = door.offer(arrival);
        }
    })
}
