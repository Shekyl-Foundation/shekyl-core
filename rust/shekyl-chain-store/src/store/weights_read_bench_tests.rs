// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! E6 slice 7 commit 2 (c): **the weights-read bench** that decides Q2
//! (`CHAIN_RULES_SLICE_7.md` §3.6, §8 Q2). CEN-G6 needs, at every connect,
//! the last 100 `weight`s and the last `min(100 000, h)` `long_term_weight`s
//! — one median each. The plan refused to choose the read shape from
//! intuition (B9): this bench measures the two candidate shapes over a
//! store of `N` connected blocks and prints the three numbers §5.1's budget
//! cell is waiting for.
//!
//! - **(a)** `N` point reads through the production
//!   [`ReadSnapshot::block_info`] — one table open and one lookup per
//!   height, the full record decoded each time. Q2 (a)'s shape.
//! - **(b)** one range cursor over `block_info` for the same `N` rows,
//!   decoding each once — what a `ChainView::weights_window` read would do
//!   inside the store. Q2 (b)'s shape.
//! - the two medians over what was read (`select_nth_unstable`).
//!
//! `#[ignore]`: it builds a store of `N` blocks first (`N` from
//! `SHEKYL_WEIGHTS_BENCH_BLOCKS`, default 100 000 — the long-term window),
//! which is not a unit test's budget. Rule 76: the figure that decides Q2
//! is the **Pi 4 floor's**; a desktop run is the reference the floor
//! multiplier is read against, and the plan says which it is recording.
//!
//! Run: `SHEKYL_WEIGHTS_BENCH_BLOCKS=100000 cargo test -p shekyl-chain-store
//! --release weights_read_bench -- --ignored --nocapture`.

// A whole-file test module: the parent gates it with `#[cfg(test)]`, and
// this self-declaration is what the debug-macro lint keys on — the bench
// prints its figures, which is its job, not a debug leftover.
#![cfg(test)]

use core::convert::Infallible;
use std::time::Instant;

use shekyl_chain_rules::harness::fixture;
use shekyl_chain_rules::{
    form, seed_height, validate, AtHeight, Candidate, ChainValid, ChainView, Fault, FormAttempt,
    RuleSet, Substrate, Trust,
};
use shekyl_types::{AttestationRoot, BlockHash, BlockHeight, CurveTreeRoot, PowHash, Timestamp};
use shekyl_units::AtomicUnits;
use shekyl_wire::{Block, BlockHeader};

use super::connect_fixtures::batch_root_going_into;
use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::view::BatchView;
use super::*;
use crate::schema::BLOCK_INFO;

/// The C++'s block target, spelled as the bench's spacing: at 120 s a block
/// LWMA holds the difficulty flat, so 100 000 blocks neither overflow the
/// cumulative sum (1 s spacing did, within a second of wall time) nor run
/// past the clock. The shared `FixtureSubstrate`'s clock is fixed at
/// 1 000 000 and would meet C1's future limit near height 8 300 at this
/// spacing, so the bench judges under its own clock, set past the chain.
const SPACING: u64 = 120;

/// A fixed difficulty, as the ingest's regtest schedule fixes it: at a
/// constant 120 s spacing the live LWMA floors a small difficulty to zero
/// over enough blocks (D6 refused at height ~8 000), and off-target spacing
/// drifts it without bound. The bench measures a read, not the DAA.
const RULES: RuleSet =
    RuleSet::fakechain(core::num::NonZeroU128::new(7), shekyl_chain_rules::D_MAX);

struct BenchSubstrate {
    clock: Timestamp,
}

impl Substrate for BenchSubstrate {
    type Fault = Infallible;

    fn local_clock(&self) -> Result<Timestamp, Infallible> {
        Ok(self.clock)
    }

    fn longhash(&self, _: &[u8], _: &BlockHash) -> Result<PowHash, Infallible> {
        Ok(PowHash::from_bytes([0; 32]))
    }
}

/// The fixtures' `judge`, under the bench's substrate: the seed an honest
/// driver claims, `form`, then `validate` — a refusal is a bench bug.
fn judge<'b, 'id>(
    view: &BatchView<'b, 'id>,
    candidate: Candidate,
    substrate: &BenchSubstrate,
) -> Result<ChainValid<'id, BatchView<'b, 'id>>, StoreError> {
    let connecting = match view.tip()? {
        None => BlockHeight::from_raw(0),
        Some(tip) => BlockHeight::from_raw(tip.height.to_raw() + 1),
    };
    let seed = match seed_height(connecting) {
        None => BlockHash::NULL,
        Some(at) => match view.block_at(at)? {
            AtHeight::Recorded(block) => block.hash,
            AtHeight::AboveTip => panic!("the seed height is below the tip"),
        },
    };
    let formed = match form(candidate, &RULES, substrate, seed, FormAttempt::FIRST) {
        Ok(Ok(formed)) => formed,
        Ok(Err(refused)) => panic!("the bench chain satisfies every stateless rule: {refused}"),
        Err(never) => match never {},
    };
    match validate(formed, view, &RULES, &Trust::UNANCHORED) {
        Ok(verdict) => Ok(verdict.expect("the bench chain satisfies every landed rule")),
        Err(Fault::View(fault)) => Err(fault),
        Err(Fault::Stale(stale)) => panic!("bench claim went stale: {stale}"),
        Err(Fault::Corrupt(corrupt)) => panic!("bench view is corrupt: {corrupt}"),
    }
}

/// The one fact `connect` is still handed (E6 slice 7). *Records-was:* until
/// commit 5 this handed weights spread per height (`300_000 + (h · 7919)
/// mod 200 000`) so the medians were "of something"; the weights are the
/// verdict's now — a coinbase-only bench block's, uniform — which changes
/// nothing the bench measures: the subject is the **read** of `N` rows,
/// (a) per height against (b) one cursor, and a median's selection is
/// `O(n)` whatever the values.
fn facts(_height: u64) -> ConnectFacts {
    ConnectFacts {
        burned: Fact::passed_through(AtomicUnits::ZERO),
    }
}

/// A candidate whose header carries `root` — [`batch_root_going_into`] at
/// this height (CEN-B5).
fn candidate(height: u64, previous: BlockHash, root: CurveTreeRoot) -> Candidate {
    let block = Block {
        header: BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: 1_000 + height * SPACING,
            previous,
            nonce: 7,
            curve_tree_root: root,
            attestation_root: AttestationRoot::from_bytes([0x33; 32]),
        },
        miner_transaction: fixture::coinbase(height),
        transaction_hashes: Vec::new(),
    };
    Candidate::new(block, Vec::new())
}

/// Connect `n` empty blocks through the production `judge` + `connect`, in
/// batches of `per_batch` so one write transaction is not the whole chain.
fn build_chain(store: &ChainStore, n: u64, per_batch: u64) {
    let substrate = BenchSubstrate {
        clock: Timestamp::from_raw(1_000 + n * SPACING + 1),
    };
    let mut previous = BlockHash::NULL;
    let mut height = 0u64;
    while height < n {
        let end = (height + per_batch).min(n);
        let out: Result<(), TestErr> = store.write(|batch| {
            let view = batch.chain_view();
            for h in height..end {
                let root = batch_root_going_into(&view, h)?;
                let cand = candidate(h, previous, root);
                previous = cand.block.hash();
                batch.connect(judge(&view, cand, &substrate)?, facts(h), RULES)?;
            }
            Ok(())
        });
        out.expect("chain connects");
        height = end;
    }
}

/// The C++'s windows, spelled here as the bench's own operands; commit 4
/// generates them from `consensus_constants.json` (Q6) and this file then
/// reads those.
const LONG_TERM_WINDOW: u64 = 100_000;
const SHORT_TERM_WINDOW: u64 = 100;

fn median(mut values: Vec<u64>) -> u64 {
    assert!(!values.is_empty());
    let mid = values.len() / 2;
    *values.select_nth_unstable(mid).1
}

#[test]
#[ignore = "builds an N-block store then times the two G6 read shapes; run with --ignored --nocapture"]
fn weights_read_bench() {
    let n: u64 = std::env::var("SHEKYL_WEIGHTS_BENCH_BLOCKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(LONG_TERM_WINDOW);
    let path = tmp(&format!("weights-bench-{n}"));
    let store = ChainStore::create(&path, EPOCH).expect("create");

    let build = Instant::now();
    build_chain(&store, n, 1_000);
    let built = build.elapsed();

    let snap = store.begin_read().expect("read");
    let tip = n - 1;
    let long_from = tip.saturating_sub(LONG_TERM_WINDOW - 1);
    let short_from = tip.saturating_sub(SHORT_TERM_WINDOW - 1);

    // (a) point reads through the production API, full decode each.
    let t = Instant::now();
    let mut long_a: Vec<u64> =
        Vec::with_capacity(usize::try_from(tip - long_from + 1).expect("fits"));
    for height in long_from..=tip {
        match snap
            .block_info(BlockHeight::from_raw(height))
            .expect("block_info")
        {
            AtHeight::Recorded(info) => long_a.push(info.long_term_weight.to_raw()),
            AtHeight::AboveTip => panic!("{height} is below the tip"),
        }
    }
    let point_long = t.elapsed();
    let t = Instant::now();
    let mut short_a: Vec<u64> = Vec::new();
    for height in short_from..=tip {
        match snap
            .block_info(BlockHeight::from_raw(height))
            .expect("block_info")
        {
            AtHeight::Recorded(info) => short_a.push(info.weight.to_raw()),
            AtHeight::AboveTip => panic!("{height} is below the tip"),
        }
    }
    let point_short = t.elapsed();

    // (b) one range cursor over the same rows, decoded once each.
    let t = Instant::now();
    let table = snap.open_table(BLOCK_INFO).expect("block_info table");
    let mut long_b: Vec<u64> = Vec::with_capacity(long_a.len());
    let mut short_b: Vec<u64> = Vec::with_capacity(short_a.len());
    for row in table.range(long_from..=tip).expect("range") {
        let (key, value) = row.expect("row");
        let info = value.value().decode().expect("decodes");
        long_b.push(info.long_term_weight.to_raw());
        if key.value() >= short_from {
            short_b.push(info.weight.to_raw());
        }
    }
    let range_both = t.elapsed();

    assert_eq!(long_a, long_b, "the two shapes read the same rows");
    assert_eq!(short_a, short_b);

    let t = Instant::now();
    let ltm = median(long_a.clone());
    let stm = median(short_a.clone());
    let medians = t.elapsed();

    eprintln!(
        "weights-read bench: N={n} blocks (built in {built:.1?})\n\
         long window rows={} short window rows={}\n\
         (a) point reads via block_info: long {point_long:.2?}, short {point_short:.2?}\n\
         (b) one range cursor, both windows: {range_both:.2?}\n\
         medians (select_nth): {medians:.2?}  ltm={ltm} stm={stm}",
        long_a.len(),
        short_a.len(),
    );
    drop(snap);
    drop(store);
    cleanup(&path);
}
