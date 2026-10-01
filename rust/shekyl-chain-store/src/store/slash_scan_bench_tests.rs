// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! DRS-E4 commit 5 (B9): **the slash witness and the slash-scan bench** —
//! one chain, two tests. The chain is the only path in the tree to the
//! writer's 9b arm (`write_slashes`), because a slash is expensive by
//! design: the predicate is `M` misses inside the last `N` observations,
//! one observation per `(P, shard, epoch)` settled 2-of-3, so no deadline
//! scan has a slash to write before `M` epochs of settled misses exist, and
//! the scan for epoch `E` runs only past `last_block(E + SLASH_GRACE_EPOCHS)`
//! — one more epoch of grace. The cost of a slash is `M + 1` epochs, plus
//! one, whatever the epoch is.
//!
//! The chain, under `RuleSet::fakechain(fixed 7, SEB 100 / cap 50)`:
//! `P` complete-tree personas join in epoch 0 (four per block from height
//! 10), then thirty-one blocks each carrying a 100 KB spend close shard 0,
//! so the scan's universe is one shard. Nobody serves — which is how every
//! observation settles as a miss 2-of-3: with no attestation, every
//! challenge of the epoch is missed. Each epoch's deadline connect (`199`,
//! `299`, …) settles that epoch: epoch 0 is not challengeable
//! (`good_through` starts the epoch after the join), epochs `1..M-1` are
//! misses that do not yet fill the window, and the epoch-`M` deadline
//! connect (`last_block(M + 1) = 1_299`) slashes every persona on shard 0.
//! Both tests assert that — the watermark, the log, `slash_applied`, the
//! emptied records, the burn (SI-8).
//!
//! **`slash_writes_land_at_the_m_epoch_deadline`** is the witness: four
//! personas, 1 300 connects, in the unit lane of every run. Until the
//! grace was derived from the epoch (DRS-E4 commit 5's ruling on §6 row
//! 5) it was a fixed ten thousand blocks that the schedule lever did not
//! shorten — 11 200 connects for the same slash, nine times the eleven
//! epochs the predicate needs, and out of the unit lane — so the 9b arm
//! had only the ignored bench for a witness.
//!
//! **`slash_scan_bench`** (`#[ignore]`) is the measurement §3.1 owes for
//! "the scan runs once per epoch on the floor": sixty-four personas by
//! default, and it prints
//!
//! - the judge and connect times of an ordinary connect (the mean over the
//!   empty blocks between the shard's close and the first deadline),
//! - the judge and connect times of every deadline connect, the slashing
//!   one marked,
//! - the ratio of the slashing connect's judge to the ordinary judge.
//!
//! What ARW-Q1 reads is the **ratio** — the slashing judge against the
//! ordinary one — because both sides run the same code on the same machine
//! and the floor device (rule 76) scales both; §3.1 records the figures
//! with the machine they were taken on. ARW-Q1 reopens if a run on the
//! floor device shows the slashing connect dominating the ordinary one,
//! which is also how the §3.1 reading is falsified. It stays ignored for
//! its persona count and its `--release` reading, not its length.
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
/// Fixed difficulty: over a thousand blocks at the fixture's constant
/// spacing LWMA would floor the difficulty, and the fixture's zero longhash
/// passes any fixed target.
const RULES: RuleSet = RuleSet::fakechain(NonZeroU128::new(7), pair(SEB, RETENTION));
/// The witness's persona count: enough that the per-persona loop is a loop,
/// few enough that the chain builds in the unit lane in debug.
const WITNESS_PERSONAS: u64 = 4;

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

/// A chain built to the epoch-`M` slashing deadline, with every connect
/// timed. Both tests build one; the witness asserts over it, the bench
/// asserts and then reads the timings.
struct SlashedChain {
    store: ChainStore,
    path: std::path::PathBuf,
    personas: u64,
    /// `M`, the slashing epoch's raw value.
    m: u64,
    /// `last_block(M + SLASH_GRACE_EPOCHS)`: the connect that slashes.
    slashing_height: u64,
    /// Epoch 0's deadline: the first deadline connect.
    first_deadline: u64,
    /// The first empty block after the shard closes — the ordinary
    /// connects begin here.
    shard_closed: u64,
    timings: Vec<Timing>,
    built: Duration,
}

impl SlashedChain {
    fn build(label: &str, personas: u64) -> Self {
        let join_blocks = personas.div_ceil(JOINS_PER_BLOCK);
        assert!(
            FIRST_SPEND_HEIGHT + join_blocks + SPEND_BLOCKS <= SEB,
            "{personas} personas: the joins and the shard must close inside epoch 0"
        );
        let schedule = RULES.settlement_schedule();
        let m = u64::from(FAILURE_WINDOW_M);
        let slashing_height = schedule.slash_deadline_height(m);
        let total = slashing_height + 1;

        let path = tmp(label);
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
        Self {
            store,
            path,
            personas,
            m,
            slashing_height,
            first_deadline: schedule.slash_deadline_height(0),
            shard_closed: FIRST_SPEND_HEIGHT + join_blocks + SPEND_BLOCKS,
            timings,
            built: wall.elapsed(),
        }
    }

    /// The 9b writes landed: the watermark, every persona's emptied record,
    /// `slash_applied`, one log row each, the open `[M, ∞)` interval, and
    /// the folded burn (SI-8).
    fn assert_slashed(&self) {
        let m = self.m;
        let slashing_epoch = SettlementEpoch::from_raw(m);
        let snap = self.store.begin_read().expect("read");
        assert_eq!(
            snap.last_settled_slash_epoch().expect("read"),
            Some(slashing_epoch),
            "the watermark is the slashing epoch"
        );
        let floor = AtomicUnits::from_raw(ARCHIVAL_BOND_FLOOR_ATOMIC);
        let mut burned = AtomicUnits::ZERO;
        for i in 0..self.personas {
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
    }

    /// Before the slashing epoch, no deadline wrote anything: the window
    /// was filling, not full.
    fn assert_nothing_slashed_before_m(&self) {
        let snap = self.store.begin_read().expect("read");
        for i in 0..self.personas {
            let p = PCanonicalId::from_bytes(persona(i));
            for e in 0..self.m {
                assert!(
                    !snap
                        .slash_applied(&p, ShardId::from_raw(0), SettlementEpoch::from_raw(e))
                        .expect("read"),
                    "epoch {e} < M slashed persona {i}: the window was not yet full"
                );
            }
        }
    }

    fn finish(self) {
        drop(self.store);
        cleanup(&self.path);
    }
}

/// The 9b slash writes, witnessed in the unit lane: `M` epochs of misses
/// settled by absence, one epoch of grace, and the epoch-`M` deadline
/// connect slashes every persona on the shard — nothing before it does.
#[test]
fn slash_writes_land_at_the_m_epoch_deadline() {
    let chain = SlashedChain::build("slash-writes-witness", WITNESS_PERSONAS);
    assert_eq!(
        chain.slashing_height,
        (chain.m + 2) * SEB - 1,
        "the slashing connect is last_block(M + 1) under a one-epoch grace"
    );
    chain.assert_nothing_slashed_before_m();
    chain.assert_slashed();
    chain.finish();
}

#[test]
#[ignore = "B9: the §3.1 measurement; run with --release --ignored --nocapture"]
fn slash_scan_bench() {
    let chain = SlashedChain::build("slash-scan-bench", personas());
    chain.assert_slashed();

    // ---- the figures.
    let m = chain.m;
    let schedule = RULES.settlement_schedule();
    let ordinary_from = usize::try_from(chain.shard_closed).expect("fits");
    let ordinary_to = usize::try_from(chain.first_deadline).expect("fits");
    let ordinary = mean(&chain.timings[ordinary_from..ordinary_to]);
    eprintln!(
        "slash_scan_bench: {} personas, {} blocks built in {:?} (M = {m}, N = {FAILURE_WINDOW_N})",
        chain.personas,
        chain.slashing_height + 1,
        chain.built
    );
    eprintln!(
        "  ordinary connect (mean of heights {}..{}): judge {:?}, connect {:?}",
        ordinary_from, ordinary_to, ordinary.judge, ordinary.connect
    );
    for e in 0..=m {
        let height = schedule.slash_deadline_height(e);
        let t = chain.timings[usize::try_from(height).expect("fits")];
        let mark = if height == chain.slashing_height {
            "  <- slashes"
        } else {
            ""
        };
        eprintln!(
            "  deadline connect for epoch {e:>2} at height {height}: judge {:?}, connect {:?}{mark}",
            t.judge, t.connect
        );
    }
    let slashing = chain.timings[usize::try_from(chain.slashing_height).expect("fits")];
    eprintln!(
        "  slashing judge / ordinary judge = {:.2}",
        slashing.judge.as_secs_f64() / ordinary.judge.as_secs_f64().max(f64::EPSILON)
    );
    chain.finish();
}
