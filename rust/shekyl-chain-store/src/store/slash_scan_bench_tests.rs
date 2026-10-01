// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! DRS-E4 commit 5 (B9): **the slash-scan bench** — the measurement §3.1
//! owes for "the scan runs once per epoch on the floor", and the **one
//! path** in the tree to the writer's 9b arm (`write_slashes`): the slash
//! deadline is `last_block(E) + CHALLENGE_RESOLUTION_BLOCKS` (ten thousand
//! blocks, not levered by the schedule), and a persona is slashable only
//! after `ARCHIVAL_FAILURE_WINDOW_M` consecutive challengeable misses, so no
//! chain a unit test would build reaches a slash. This one does.
//!
//! The chain, under `RuleSet::fakechain(fixed 7, SEB 100 / cap 50)`:
//! `P` complete-tree personas join in epoch 0 (four per block from height
//! 10), then thirty-one blocks each carrying a 100 KB spend close shard 0,
//! so the scan's universe is one shard. Nobody serves. Each epoch's
//! deadline connect (`10_099`, `10_199`, …) settles that epoch: epoch 0
//! is not challengeable (`good_through` starts the epoch after the join),
//! epochs `1..M-1` are misses that do not yet fill the window, and the
//! epoch-`M` deadline connect (`last_block(M) + 10_000`) slashes every
//! persona on shard 0. The bench asserts that — the watermark, the log,
//! `slash_applied`, the emptied records, the burn — and prints:
//!
//! - the judge and connect times of an ordinary connect (the mean over the
//!   thousand blocks before the first deadline),
//! - the judge and connect times of every deadline connect, the slashing
//!   one marked,
//! - the ratio of the slashing connect's judge to the ordinary judge.
//!
//! `#[ignore]`: it connects `last_block(M) + 10_001` blocks. What ARW-Q1
//! reads is the **ratio** — the slashing judge against the ordinary one —
//! because both sides run the same code on the same machine and the floor
//! device (rule 76) scales both; §3.1 records the figures with the machine
//! they were taken on. ARW-Q1 reopens if a run on the floor device shows
//! the slashing connect dominating the ordinary one, which is also how the
//! §3.1 reading is falsified.
//!
//! Run: `SHEKYL_SLASH_BENCH_PERSONAS=64 cargo test -p shekyl-chain-store
//! --release slash_scan_bench -- --ignored --nocapture`.

// A whole-file test module: the parent gates it with `#[cfg(test)]`, and
// this self-declaration is what the debug-macro lint keys on — the bench
// prints its figures, which is its job, not a debug leftover.
#![cfg(test)]

use core::num::NonZeroU128;
use std::time::{Duration, Instant};

use shekyl_archival_retention::{ARCHIVAL_BOND_FLOOR_ATOMIC, FAILURE_WINDOW_M, FAILURE_WINDOW_N};
use shekyl_chain_rules::harness::fixture;
use shekyl_chain_rules::{FakechainSchedule, RuleSet};
use shekyl_types::{BlockCount, BlockHash, BlockHeight, PCanonicalId, SettlementEpoch, ShardId};
use shekyl_units::AtomicUnits;
use shekyl_wire::{Ct, Transaction};

use super::connect_fixtures::{
    anchor, batch_root_going_into, candidate_over, judge_under, FIRST_SPEND_HEIGHT,
};
use super::store_tests::{cleanup, tmp, TestErr};
use super::*;
use crate::codec::SettlementEpochBlocks;

const SEB: u64 = 100;
const RETENTION: u64 = 50;
/// Fixed difficulty: over eleven thousand blocks at the fixture's constant
/// spacing LWMA would floor the difficulty, and the fixture's zero longhash
/// passes any fixed target.
const RULES: RuleSet = RuleSet::fakechain(NonZeroU128::new(7), pair(SEB, RETENTION));

const fn pair(seb: u64, cap: u64) -> FakechainSchedule {
    let Some(epoch) = SettlementEpochBlocks::new(seb) else {
        panic!("a zero epoch");
    };
    match FakechainSchedule::new(epoch, BlockCount::from_raw(cap)) {
        Ok(pair) => pair,
        Err(_) => panic!("the cap is not inside the epoch"),
    }
}

/// Joins per block: four keeps `P` personas inside epoch 0 for any `P` the
/// bench admits.
const JOINS_PER_BLOCK: u64 = 4;
/// Blocks carrying a padded spend; thirty-one × 100 KB is past one shard.
const SPEND_BLOCKS: u64 = 31;
const SPEND_PAD: usize = 100_000;
/// Blocks per `store.write`: the bench measures the judge and the connect,
/// not redb's commit.
const PER_BATCH: u64 = 50;

fn personas() -> u64 {
    std::env::var("SHEKYL_SLASH_BENCH_PERSONAS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64)
}

fn persona(i: u64) -> [u8; 32] {
    let mut p = [0x50; 32];
    p[..8].copy_from_slice(&i.to_le_bytes());
    p
}

/// A spend whose opaque proof is padded to `SPEND_PAD` bytes: no landed
/// rule reads the proof's bytes, so its length is the fixture's free
/// variable, and thirty-one of them close shard 0.
fn padded_spend(key: u64) -> Transaction {
    let mut tx = fixture::spend(fixture::point_at(key), 2);
    let Ct::Fcmp {
        prunable: Some(prunable),
        ..
    } = &mut tx.ct
    else {
        unreachable!("fixture::spend with outputs carries a prunable region");
    };
    prunable.fcmp_proof = vec![0xF0; SPEND_PAD];
    tx
}

/// What block `h` lists.
fn listing(h: u64, personas: u64) -> Vec<Transaction> {
    if h < FIRST_SPEND_HEIGHT {
        return Vec::new();
    }
    let join_blocks = personas.div_ceil(JOINS_PER_BLOCK);
    let first_spend_block = FIRST_SPEND_HEIGHT + join_blocks;
    if h < first_spend_block {
        let first = (h - FIRST_SPEND_HEIGHT) * JOINS_PER_BLOCK;
        return (first..(first + JOINS_PER_BLOCK).min(personas))
            .map(|i| fixture::join_market(fixture::point_at(1_000 + i), persona(i)))
            .collect();
    }
    if h < first_spend_block + SPEND_BLOCKS {
        return vec![padded_spend(1_000_000 + h)];
    }
    Vec::new()
}

#[derive(Clone, Copy, Default)]
struct Timing {
    judge: Duration,
    connect: Duration,
}

fn mean(timings: &[Timing]) -> Timing {
    let n = u32::try_from(timings.len()).expect("fits");
    Timing {
        judge: timings.iter().map(|t| t.judge).sum::<Duration>() / n,
        connect: timings.iter().map(|t| t.connect).sum::<Duration>() / n,
    }
}

#[test]
#[ignore = "B9: connects last_block(M) + 10_001 blocks; run with --release --ignored --nocapture"]
fn slash_scan_bench() {
    let personas = personas();
    let join_blocks = personas.div_ceil(JOINS_PER_BLOCK);
    assert!(
        FIRST_SPEND_HEIGHT + join_blocks + SPEND_BLOCKS <= SEB,
        "{personas} personas: the joins and the shard must close inside epoch 0"
    );
    let schedule = RULES.settlement_schedule();
    let m = u64::from(FAILURE_WINDOW_M);
    let slashing_epoch = SettlementEpoch::from_raw(m);
    let deadline_of = |e: u64| schedule.slash_deadline_height(e);
    let slashing_height = deadline_of(m);
    let total = slashing_height + 1;
    let first_deadline = deadline_of(0);

    let path = tmp("slash-scan-bench");
    let horizons = Horizons::new(
        schedule.blocks(),
        BlockCount::from_raw(RETENTION),
        RULES.reorg_cap(),
    )
    .expect("cap ≤ retention < epoch");
    let store = ChainStore::with_horizons(&path, ApplyPolicy::Full, horizons).expect("create");

    let mut hashes: Vec<BlockHash> = Vec::with_capacity(usize::try_from(total).expect("fits"));
    let mut timings: Vec<Timing> = Vec::with_capacity(hashes.capacity());
    let wall = Instant::now();
    let mut h = 0u64;
    while h < total {
        let end = (h + PER_BATCH).min(total);
        let out: Result<(), TestErr> = store.write(|batch| {
            let view = batch.chain_view();
            for height in h..end {
                let previous = hashes.last().copied().unwrap_or(BlockHash::NULL);
                let listed: Vec<Transaction> = listing(height, personas)
                    .into_iter()
                    .map(|tx| anchor(&hashes, height, tx))
                    .collect();
                let root = batch_root_going_into(&view, height)?;
                let cand = candidate_over(root, height, previous, listed);
                let started = Instant::now();
                let judged = judge_under(&view, cand, &RULES)?;
                let judge = started.elapsed();
                hashes.push(judged.block().hash());
                let started = Instant::now();
                batch.connect(judged, RULES)?;
                timings.push(Timing {
                    judge,
                    connect: started.elapsed(),
                });
            }
            Ok(())
        });
        out.expect("the chain connects");
        h = end;
    }
    let built = wall.elapsed();

    // ---- the slash landed: the only witness of the 9b writes.
    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.last_settled_slash_epoch().expect("read"),
        Some(slashing_epoch),
        "the watermark is the slashing epoch"
    );
    let floor = AtomicUnits::from_raw(ARCHIVAL_BOND_FLOOR_ATOMIC);
    let mut burned = AtomicUnits::ZERO;
    for i in 0..personas {
        let p = PCanonicalId::from_bytes(persona(i));
        let record = snap
            .bond_record(&p)
            .expect("read")
            .expect("the record outlives its slash");
        assert!(!record.is_complete_tree(), "the complete tree was emptied");
        assert_eq!(
            record.bonded_total,
            AtomicUnits::ZERO,
            "one floor left the bond"
        );
        assert!(
            snap.slash_applied(&p, ShardId::from_raw(0), slashing_epoch)
                .expect("read"),
            "slash_applied({i}, 0, {m})"
        );
        let log = snap
            .slash_log_after(&p, BlockHeight::from_raw(0))
            .expect("read");
        assert_eq!(log.len(), 1, "one slash logged for {i}: {log:?}");
        assert_eq!(log[0].shard, ShardId::from_raw(0));
        assert_eq!(log[0].epoch, slashing_epoch);
        assert!(
            record
                .bad_intervals
                .iter()
                .any(|iv| iv.start_epoch == m && iv.end_exclusive == u64::MAX),
            "the open bad interval [M, ∞) was appended: {:?}",
            record.bad_intervals
        );
        burned = burned.checked_add(floor).expect("fits");
    }
    assert_eq!(
        snap.total_burned().expect("read"),
        burned,
        "SI-8: the burns folded"
    );
    drop(snap);

    // ---- the figures.
    let ordinary_from = usize::try_from(first_deadline - 1_000).expect("fits");
    let ordinary_to = usize::try_from(first_deadline).expect("fits");
    let ordinary = mean(&timings[ordinary_from..ordinary_to]);
    eprintln!(
        "slash_scan_bench: {personas} personas, {total} blocks built in {built:?} \
         (M = {m}, N = {FAILURE_WINDOW_N})"
    );
    eprintln!(
        "  ordinary connect (mean of heights {}..{}): judge {:?}, connect {:?}",
        ordinary_from, ordinary_to, ordinary.judge, ordinary.connect
    );
    for e in 0..=m {
        let height = deadline_of(e);
        let t = timings[usize::try_from(height).expect("fits")];
        let mark = if height == slashing_height {
            "  <- slashes"
        } else {
            ""
        };
        eprintln!(
            "  deadline connect for epoch {e:>2} at height {height}: judge {:?}, connect {:?}{mark}",
            t.judge, t.connect
        );
    }
    let slashing = timings[usize::try_from(slashing_height).expect("fits")];
    eprintln!(
        "  slashing judge / ordinary judge = {:.2}",
        slashing.judge.as_secs_f64() / ordinary.judge.as_secs_f64().max(f64::EPSILON)
    );
    drop(store);
    cleanup(&path);
}
