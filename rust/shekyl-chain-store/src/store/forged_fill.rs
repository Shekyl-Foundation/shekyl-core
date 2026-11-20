// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The forged shard-fill chain, connected into a store (`CHAIN_FORGE.md`
//! `CF-4a`, `CF-R28`): the chain the store's boundary, prune and slash
//! tests start from, forged from `shekyl-chain-forge/plans/shard-fill.toml`,
//! hosted, and pinned by digest (§10.4).
//!
//! Every archival byte in it is a real spend, verified by every landed
//! rule: one-input spends of coinbases, sixteen a block, from the block
//! where enough coinbases have matured, until three shards have closed. A
//! test connects the prefix it needs ([`store_with_prefix`]) and extends it
//! with blocks of its own, on the same chain record ([`Grown`], carrying
//! regtest's identity, so a spend or a post it builds signs under the same
//! id the forged ones did).
//!
//! The close heights are the manifest's `shard-<k>-closed` events
//! ([`ForgedChain::close_height`]), never numbers written here: a re-forge
//! moves them (`CF-3` re-forges this chain), and a test that takes them
//! from the manifest moves with it. A test whose subject needs an epoch
//! pattern (a shard closing in the epoch after another's, a boundary that
//! names nothing yet) asserts that pattern from these heights itself.
//!
//! Every block is judged as forged ([`Grown::judge_as_built`]): nothing is
//! priced or rebuilt, so the store connects the corpus's own blocks or
//! refuses, and each connected hash is held to the corpus's.

// A whole-file test module: the parent gates it with `#[cfg(test)]`.
#![cfg(test)]

use std::fs::File;
use std::io::BufReader;
use std::num::NonZeroU128;
use std::sync::OnceLock;

use shekyl_chain_forge::{close_event, hosted};
use shekyl_chain_rules::{Candidate, RuleSet};
use shekyl_corpus::{CorpusReader, Record};
use shekyl_types::BlockHeight;
use shekyl_wire::Transaction;

use super::connect_fixtures::{Grown, Identity};
use super::store_tests::TestErr;
use super::*;

/// The hosted chain's name (`chains/hosted.toml`).
pub(super) const CHAIN: &str = "shard-fill";

/// The difficulty every reader's rule set fixes: the forged chain's own,
/// regtest's fixed one (the manifest's `fixed_difficulty`, held equal at
/// load). Its blocks are a second apart, and LWMA over that spacing ramps
/// the difficulty until the cumulative sum overflows; the fixtures'
/// longhash passes any fixed target, so a fixed one judges every block.
pub(super) const FORGED_DIFFICULTY: Option<NonZeroU128> = Some(NonZeroU128::MIN);

/// The forged chain as the corpus lists it, and the closes its manifest
/// records.
pub(super) struct ForgedChain {
    /// Each block from genesis, with its listed bodies and its bundle
    /// section, as forged.
    blocks: Vec<Candidate>,
    /// Shard `k`'s close height at index `k`, from the manifest.
    closes: Vec<BlockHeight>,
    /// The shekyl-core commit the chain was forged at (the pin's).
    commit: String,
}

impl ForgedChain {
    /// Open the pinned chain, read every record and the manifest's closes.
    ///
    /// # Panics
    ///
    /// If the chain is not fetched or does not match its pin (the message
    /// names the fetch command), if its corpus does not decode, if it lists
    /// a rewind, or if its manifest names no close.
    fn load() -> Self {
        let fetched = hosted::open(CHAIN).unwrap_or_else(|fault| panic!("{fault}"));
        let manifest = fetched.manifest().unwrap_or_else(|fault| panic!("{fault}"));
        assert_eq!(
            manifest
                .schedule
                .fixed_difficulty
                .and_then(|d| NonZeroU128::new(d.into())),
            FORGED_DIFFICULTY,
            "the readers fix the forged chain's own difficulty"
        );
        let closes: Vec<BlockHeight> = (0..)
            .map_while(|k| {
                let name = close_event(k);
                manifest
                    .events
                    .iter()
                    .find(|event| event.name == name)
                    .map(|event| BlockHeight::from_raw(event.height))
            })
            .collect();
        assert!(
            !closes.is_empty(),
            "the forged chain's manifest records no close"
        );
        let mut corpus = CorpusReader::open(BufReader::new(
            File::open(fetched.corpus()).expect("the fetched corpus opens"),
        ))
        .unwrap_or_else(|fault| panic!("the forged corpus: {fault}"));
        let mut blocks = Vec::new();
        while let Some(record) = corpus
            .next_record()
            .unwrap_or_else(|fault| panic!("the forged corpus: {fault}"))
        {
            let Record::Extend(extend) = record else {
                panic!("the forged fill lists no rewind");
            };
            let extend = *extend;
            assert_eq!(
                extend.height.to_raw(),
                u64::try_from(blocks.len()).expect("small"),
                "the forged corpus lists every height from genesis in order"
            );
            blocks.push(
                Candidate::new(extend.block, extend.transactions)
                    .with_bundle_references(extend.bundle_references)
                    .with_bundle_bodies(extend.bundle_bodies),
            );
        }
        Self {
            blocks,
            closes,
            commit: fetched.pin().commit.clone(),
        }
    }

    /// The height of the block that closes shard `k`, as the manifest
    /// records it.
    pub(super) fn close_height(&self, k: u64) -> BlockHeight {
        *self
            .closes
            .get(usize::try_from(k).expect("small"))
            .unwrap_or_else(|| {
                panic!(
                    "the forged chain closes {} shards; shard {k} is not among them",
                    self.closes.len()
                )
            })
    }

    /// The prefix through the block that closes shard `k`, as a block
    /// count.
    pub(super) fn blocks_closing(&self, k: u64) -> usize {
        usize::try_from(self.close_height(k).to_raw()).expect("small") + 1
    }

    /// The blocks the corpus holds.
    pub(super) fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Block `h`'s listed bodies.
    pub(super) fn listed(&self, h: usize) -> &[Transaction] {
        &self.blocks[h].transactions
    }

    /// Each listed body's archival length, per height: what a model of the
    /// chain's partition is computed from.
    pub(super) fn archival_lengths(&self) -> Vec<Vec<u64>> {
        self.blocks
            .iter()
            .map(|block| {
                block
                    .transactions
                    .iter()
                    .map(|tx| tx.archival_len().to_raw())
                    .collect()
            })
            .collect()
    }
}

/// The pinned chain, read once per process.
pub(super) fn forged() -> &'static ForgedChain {
    static CHAIN_ONCE: OnceLock<ForgedChain> = OnceLock::new();
    CHAIN_ONCE.get_or_init(ForgedChain::load)
}

/// A store at `path` under `rules` and `horizons`, holding the forged
/// chain's first `blocks` blocks, each judged as forged, and the chain
/// record over them, carrying regtest's identity.
///
/// # Panics
///
/// If a block does not connect under `rules`, or connects as a block other
/// than the corpus's.
pub(super) fn store_with_prefix(
    path: impl AsRef<std::path::Path>,
    rules: RuleSet,
    horizons: Horizons,
    blocks: usize,
) -> (ChainStore, Grown) {
    let store = ChainStore::with_horizons(
        path.as_ref(),
        crate::apply_policy::ApplyPolicy::default(),
        horizons,
    )
    .expect("create the prefix store");
    let mut grown = Grown::carrying(Identity::Regtest);
    connect_forged(&store, &mut grown, rules, blocks);
    (store, grown)
}

/// Connect the forged blocks from `grown`'s next height through the first
/// `blocks`, each judged as forged and held to the corpus's hash; returns
/// each connect's outcome.
pub(super) fn connect_forged(
    store: &ChainStore,
    grown: &mut Grown,
    rules: RuleSet,
    blocks: usize,
) -> Vec<Connected> {
    let chain = forged();
    let from = usize::try_from(grown.height().to_raw()).expect("small");
    let out: Result<Vec<Connected>, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let mut out = Vec::new();
        for forged in &chain.blocks[from..blocks] {
            let judged = grown.judge_as_built(&view, &rules, forged.clone())?;
            out.push(batch.connect(judged, rules)?);
            assert_eq!(
                grown.tip(),
                forged.block.hash(),
                "the forged block (forged at {})",
                chain.commit
            );
        }
        Ok(out)
    });
    out.expect("the forged prefix connects")
}
