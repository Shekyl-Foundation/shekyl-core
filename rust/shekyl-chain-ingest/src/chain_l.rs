// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A scenario resumed on Chain L at a named event (`CHAIN_FORGE.md` §8,
//! `CF-4b`): the store a production replay left there, through
//! [`crate::snapshot`], instead of connecting the prefix again.
//!
//! The driver's verdict fields ([`Mined`]) exist only for blocks it
//! connected itself, so a resumed chain's [`Mined`] list starts at the first
//! block mined after the snapshot. The prefix comes back as the bodies a
//! wallet-side [`Spender`](shekyl_harness_spender::Spender) scans.

use std::fs::File;
use std::io::BufReader;
use std::num::{NonZeroU128, NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};

use shekyl_chain_forge::hosted;
use shekyl_chain_forge::is_close_event;
use shekyl_chain_rules::{CappedEpoch, SettlementEpochBlocks};
use shekyl_harness_spender::Linked;
use shekyl_network::Network;
use shekyl_types::{BlockCount, BlockHeight, ShardId, Timestamp};
use shekyl_wire::block::Block;
use shekyl_wire::Transaction;

use crate::corpus::CorpusSource;
use crate::scenario::{FreeHash, Scenario};
use crate::scenario_shard::ClosedShard;
use crate::schedule::ChainRules;
use crate::snapshot::{ensure, open_copy, ChainFiles, SnapshotKey};
use crate::source::{IngestEvent, SequenceNo, Source};

/// The hosted chain's name.
pub const CHAIN: &str = "chain-l";

/// Where snapshots are cached when `SHEKYL_CHAIN_SNAPSHOTS` does not say:
/// under the build's target directory, never in the tree.
fn cache_root() -> PathBuf {
    std::env::var_os("SHEKYL_CHAIN_SNAPSHOTS").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/chain-snapshots"),
        PathBuf::from,
    )
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// One block of a resumed chain's prefix.
pub struct PrefixBlock {
    /// The block.
    pub block: Block,
    /// Its listed bodies.
    pub listed: Vec<Transaction>,
}

impl PrefixBlock {
    /// This block as a spender scans it.
    #[must_use]
    pub fn linked(&self) -> Linked<'_> {
        Linked::new(&self.block, &self.listed)
    }
}

/// A scenario on Chain L at one event.
pub struct Resumed {
    /// The driver, its store the event's snapshot.
    pub scenario: Scenario<FreeHash>,
    /// The chain through the event, from block 0.
    pub prefix: Vec<PrefixBlock>,
    /// The rules the chain runs.
    pub rules: ChainRules,
    /// The shards closed at the event, as the manifest names them.
    pub closed: Vec<ClosedShard>,
}

/// The main chain through corpus record `last`: extends and rewinds as
/// written, and an offered branch taking over once it is the longer, which
/// at a fixed difficulty is the fork choice's switch.
fn main_chain_through(corpus: &Path, last: SequenceNo) -> Vec<PrefixBlock> {
    let mut source = CorpusSource::open(BufReader::new(
        File::open(corpus).expect("the fetched corpus opens"),
    ))
    .unwrap_or_else(|fault| panic!("the forged corpus: {fault}"));
    let mut main: Vec<PrefixBlock> = Vec::new();
    let mut branch: Vec<PrefixBlock> = Vec::new();
    let mut fork = 0usize;
    while let Some(next) = source
        .next()
        .unwrap_or_else(|fault| panic!("the forged corpus: {fault}"))
    {
        match next.event {
            IngestEvent::Extend(candidate) => {
                let candidate = *candidate;
                main.push(PrefixBlock {
                    block: candidate.block,
                    listed: candidate.transactions,
                });
            }
            IngestEvent::Rewind { to } => {
                main.truncate(usize::try_from(to.to_raw()).expect("a height fits") + 1);
            }
            IngestEvent::Offer(candidate) => {
                let candidate = *candidate;
                let parent = candidate.block.header.previous;
                if branch.last().is_none_or(|tip| tip.block.hash() != parent) {
                    fork = main
                        .iter()
                        .position(|held| held.block.hash() == parent)
                        .expect("an offer's parent is on the chain");
                    branch.clear();
                }
                branch.push(PrefixBlock {
                    block: candidate.block,
                    listed: candidate.transactions,
                });
                if fork + 1 + branch.len() > main.len() {
                    main.truncate(fork + 1);
                    main.append(&mut branch);
                }
            }
        }
        if next.seq >= last {
            break;
        }
    }
    main
}

/// A scenario named `name` on Chain L at `event`.
///
/// # Panics
///
/// If the chain is not fetched or does not match its pin, if its manifest
/// names no such event, or if the snapshot is refused.
pub async fn resume_at(name: &str, event: &str) -> Resumed {
    let fetched = hosted::open(CHAIN).unwrap_or_else(|fault| panic!("{fault}"));
    let manifest = fetched.manifest().unwrap_or_else(|fault| panic!("{fault}"));
    let at = manifest
        .events
        .iter()
        .find(|named| named.name == event)
        .unwrap_or_else(|| panic!("Chain L's manifest records no `{event}`"));
    let record = SequenceNo::from_raw(at.record);
    let closed: Vec<ClosedShard> = manifest
        .events
        .iter()
        .filter(|named| is_close_event(&named.name) && named.record <= at.record)
        .enumerate()
        .map(|(shard, named)| ClosedShard {
            shard: ShardId::from_raw(u64::try_from(shard).expect("a count fits")),
            close_height: BlockHeight::from_raw(named.height),
        })
        .collect();
    let epoch = CappedEpoch::new(
        SettlementEpochBlocks::new(manifest.schedule.settlement_epoch_blocks)
            .expect("the manifest's epoch is not zero"),
        BlockCount::from_raw(manifest.schedule.reorg_cap_blocks),
    )
    .unwrap_or_else(|refused| panic!("the manifest's schedule: {refused:?}"));
    let rules = ChainRules::new(Network::Regtest, Some(NonZeroU128::MIN), epoch)
        .unwrap_or_else(|refused| panic!("regtest's row permits every lever: {refused}"));

    let (corpus, trace) = (fetched.corpus(), fetched.trace());
    let files = ChainFiles {
        corpus: &corpus,
        trace: &trace,
        record,
        rules,
    };
    let key = SnapshotKey::at(&fetched.pin().digest, event, &repo_root())
        .unwrap_or_else(|fault| panic!("the consensus trees: {fault}"));
    let hashers = std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN);
    let dir = ensure(&cache_root(), files, &key, hashers)
        .await
        .unwrap_or_else(|fault| panic!("the `{event}` snapshot: {fault}"));
    let expected = files
        .expected_digest()
        .unwrap_or_else(|fault| panic!("the `{event}` snapshot: {fault}"));
    let prefix = main_chain_through(&corpus, record);
    let tip = prefix.last().expect("the chain has a genesis");
    let tip_hash = tip.block.hash();
    let tip_timestamp = Timestamp::from_raw(tip.block.header.timestamp);
    let (mut scenario, _genesis) = Scenario::open_regtest_mined(name, FreeHash, epoch).await;
    let spacing = NonZeroU64::new(manifest.schedule.block_seconds)
        .expect("a manifest's spacing is at least 1");
    scenario.space_blocks(spacing);
    scenario
        .adopt_store(
            |path| {
                open_copy(&dir, &key, &expected, &rules, path)
                    .unwrap_or_else(|fault| panic!("the `{event}` snapshot: {fault}"));
            },
            tip_timestamp,
        )
        .await;
    // The walk reads the corpus and the store came from a replay of it: the
    // same chain, or the spender would scan another one.
    let stored = scenario
        .read_chain(|view, _| {
            shekyl_chain_rules::HeaderView::tip(view)
                .expect("the tip reads")
                .expect("the snapshot has a tip")
                .hash
        })
        .await;
    assert_eq!(stored, tip_hash, "the walked chain is the snapshot's");
    Resumed {
        scenario,
        prefix,
        rules,
        closed,
    }
}
