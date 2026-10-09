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
//! so every persona holds one closed shard. Each pair is issued three
//! draws in every epoch from 1 through the regtest door
//! ([`ChainStore::regtest_issue_draws`], `SO-D10f`: nothing admits a draw
//! yet), none passed — which is how every observation settles Missed.
//! Each epoch's deadline connect (`199`, `299`, …) settles that epoch:
//! epoch 0 has no draw and is not in standing either (`good_through`
//! starts the epoch after the join), epochs `1..M-1` are misses that do not
//! yet fill the window, and the epoch-`M` deadline connect
//! (`last_block(M + 1) = 1_299`) slashes every persona on shard 0.
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
//! The witness also **pins the `0x04` archival snapshot at the slashing
//! tip** (`ARW-Q18`, ruled 2026-10-02): the three slash families' bytes
//! spelled from the facts — `n_rows ‖ (len ‖ height ‖ seq ‖ persona ‖
//! shard ‖ epoch ‖ 0x01)*` and the rest — against the body
//! `ReadSnapshot::archival_snapshot` encodes, and the whole body by hash.
//! Every captured corpus chain carries those families **empty**
//! (`ARW-13`), so until this pin the record's slash encoding had been
//! serialized only in its degenerate case and only in a writer-reader
//! round trip a symmetric change passes. This is the state a slash-bearing
//! capture would have exported, produced by the production writer in a
//! test that already runs — the cheaper instrument `ARW-Q18` was closed
//! with, in place of a seventh chain captured against a departing C++
//! walker. A change to these bytes is a §3.8.1 / codec change and is
//! re-pinned with its version bump, never silently.
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

use shekyl_archival_retention::settlement_select::issued_draw_term;
use shekyl_archival_retention::{ARCHIVAL_BOND_FLOOR_ATOMIC, FAILURE_WINDOW_M, FAILURE_WINDOW_N};
use shekyl_chain_rules::harness::fixture;
use shekyl_chain_rules::{Corrupt, FakechainSchedule, RuleSet, SettlementCheck, Trust};
use shekyl_crypto_hash::keccak256;
use shekyl_types::archival::{
    IndexedDraw, IssuedDigest, IssuedDraw, SettlementOutcome, SettlementRow, SlashedHolding,
};
use shekyl_types::{BlockCount, BlockHash, BlockHeight, PCanonicalId, SettlementEpoch, ShardId};
use shekyl_units::AtomicUnits;
use shekyl_wire::{Ct, Transaction};

use super::connect_fixtures::{
    anchor, batch_root_going_into, candidate_over, judge_or_corrupt, judge_under,
    FIRST_SPEND_HEIGHT,
};
use super::store_tests::{cleanup, tmp, TestErr};
use super::*;
use crate::archival_snapshot::{hex, ArchivalSnapshot, SnapshotFamily};
use crate::codec::{Canonical, SettlementEpochBlocks, SlashLogEntry};

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

/// The fixture-persona **tag** of the `i`-th bench persona: what the
/// joins are built with ([`fixture::persona`] derives the keys and the id).
fn persona(i: u64) -> [u8; 32] {
    let mut p = [0x50; 32];
    p[..8].copy_from_slice(&i.to_le_bytes());
    p
}

/// The `personas` bench personas' ids **in bond-table order** — the order
/// the deadline scan walks them, so the order the slash log's `seq` and
/// the snapshot's rows are in. Ids are recomputes over derived keys
/// (CEN-J11), so tag order and id order are unrelated; *records-was:*
/// until E6 slice 8 row 4 the tag *was* the id, and `i` order was table
/// order.
fn ids_in_table_order(personas: u64) -> Vec<PCanonicalId> {
    let mut ids: Vec<PCanonicalId> = (0..personas)
        .map(|i| fixture::persona(persona(i)).id)
        .collect();
    ids.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    ids
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

/// What one pair is issued in one epoch: `None` is no draw at all, and
/// `Some(passes)` is one draw per entry, passed or not.
type Plan = fn(epoch: u64, persona: u64) -> Option<&'static [bool]>;

/// Three draws, none passed: a Missed epoch.
const MISSED: &[bool] = &[false, false, false];
/// Three draws, two passed: a Served epoch, whichever three are selected.
const SERVED: &[bool] = &[true, true, false];
/// Two draws: below the floor of three, so not an observation.
const SHORT: &[bool] = &[false, false];

/// The witness's plan: every pair misses every epoch from 1.
fn every_epoch_missed(epoch: u64, _persona: u64) -> Option<&'static [bool]> {
    (epoch >= 1).then_some(MISSED)
}

/// The draws `plan` issues in `epoch`, each pair's on shard 0 at
/// consecutive heights inside the epoch, in index order.
fn planned_draws(epoch: u64, personas: u64, plan: Plan) -> Vec<IndexedDraw> {
    let open = RULES.settlement_schedule().open_height(epoch);
    let mut draws = Vec::new();
    for id in ids_in_table_order(personas) {
        let i = (0..personas)
            .find(|i| fixture::persona(persona(*i)).id == id)
            .expect("an id of the list");
        let Some(passes) = plan(epoch, i) else {
            continue;
        };
        for (k, &passed) in (0u64..).zip(passes) {
            let issuing_height = BlockHeight::from_raw(open + 60 + k);
            draws.push(IndexedDraw {
                persona: id,
                shard: ShardId::from_raw(0),
                issuing_height,
                draw: 0,
                state: IssuedDraw {
                    revealed_at: BlockHeight::from_raw(open + 61 + k),
                    passed,
                },
            });
        }
    }
    draws
}

/// The digest of `draws` folded onto `digest`: what admission would have
/// left in the epoch's cell.
fn folded(mut digest: IssuedDigest, epoch: SettlementEpoch, draws: &[IndexedDraw]) -> IssuedDigest {
    for draw in draws {
        digest.fold(&issued_draw_term(
            &draw.persona,
            draw.shard,
            epoch,
            draw.issuing_height,
            draw.draw,
        ));
    }
    digest
}

/// Issue `epoch`'s planned draws through the regtest door, with the
/// digest they fold to.
fn issue(store: &ChainStore, epoch: u64, personas: u64, plan: Plan) {
    let draws = planned_draws(epoch, personas, plan);
    if draws.is_empty() {
        return;
    }
    let epoch = SettlementEpoch::from_raw(epoch);
    let digest = store
        .begin_read()
        .expect("read")
        .issued_digest(epoch)
        .expect("read");
    store
        .regtest_issue_draws(
            Trust::UNANCHORED,
            epoch,
            &draws,
            folded(digest, epoch, &draws),
        )
        .expect("the draws are issued");
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
    /// The hash of the last block connected.
    tip: BlockHash,
    timings: Vec<Timing>,
    built: Duration,
}

impl SlashedChain {
    /// The witness's chain: every pair misses every epoch from 1, built to
    /// the epoch-`M` slashing connect.
    fn build(label: &str, personas: u64) -> Self {
        let m = u64::from(FAILURE_WINDOW_M);
        let through = RULES.settlement_schedule().slash_deadline_height(m);
        Self::build_with(label, personas, through, every_epoch_missed)
    }

    /// A chain through height `through`, each epoch's draws issued by
    /// `plan` once the epoch's blocks are connected — an epoch ahead of the
    /// deadline connect that settles it.
    fn build_with(label: &str, personas: u64, through: u64, plan: Plan) -> Self {
        assert!(
            SEB.is_multiple_of(PER_BATCH),
            "an epoch ends on a batch boundary"
        );
        let join_blocks = personas.div_ceil(JOINS_PER_BLOCK);
        assert!(
            FIRST_SPEND_HEIGHT + join_blocks + SPEND_BLOCKS <= SEB,
            "{personas} personas: the joins and the shard must close inside epoch 0"
        );
        let schedule = RULES.settlement_schedule();
        let m = u64::from(FAILURE_WINDOW_M);
        let slashing_height = schedule.slash_deadline_height(m);
        let total = through + 1;

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
            if h.is_multiple_of(SEB) {
                issue(&store, h / SEB - 1, personas, plan);
            }
        }
        Self {
            store,
            path,
            personas,
            m,
            slashing_height,
            first_deadline: schedule.slash_deadline_height(0),
            shard_closed: FIRST_SPEND_HEIGHT + join_blocks + SPEND_BLOCKS,
            tip: *hashes.last().expect("the chain has a block"),
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
        for p in ids_in_table_order(self.personas) {
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
                "slash_applied({p:?}, 0, {m})"
            );
            let log = snap
                .slash_log_after(&p, BlockHeight::from_raw(0))
                .expect("read");
            assert_eq!(log.len(), 1, "one slash logged for {p:?}: {log:?}");
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

    /// The rows the pass settled (`SO-D7`: written ahead of the slash they
    /// decide): Missed on no pass of three for every epoch from 1 through
    /// `M`, and none for epoch 0, in which no draw was issued.
    fn assert_settled_missed_from_epoch_one(&self) {
        let snap = self.store.begin_read().expect("read");
        let shard = ShardId::from_raw(0);
        let missed = SettlementRow::settle(0, 3).expect("a row");
        assert_eq!(missed.outcome(), SettlementOutcome::Missed);
        for p in ids_in_table_order(self.personas) {
            assert_eq!(
                snap.settlement_row(&p, shard, SettlementEpoch::from_raw(0))
                    .expect("read"),
                None,
                "no draw, no row"
            );
            for e in 1..=self.m {
                assert_eq!(
                    snap.settlement_row(&p, shard, SettlementEpoch::from_raw(e))
                        .expect("read"),
                    Some(missed),
                    "epoch {e} of {p:?}"
                );
            }
        }
    }

    /// Before the slashing epoch, no deadline wrote anything: the window
    /// was filling, not full.
    fn assert_nothing_slashed_before_m(&self) {
        let snap = self.store.begin_read().expect("read");
        for p in ids_in_table_order(self.personas) {
            for e in 0..self.m {
                assert!(
                    !snap
                        .slash_applied(&p, ShardId::from_raw(0), SettlementEpoch::from_raw(e))
                        .expect("read"),
                    "epoch {e} < M slashed persona {p:?}: the window was not yet full"
                );
            }
        }
    }

    /// The `0x04` record at the slashing tip (`ARW-Q18`): the slash
    /// families' bytes spelled from the facts — not read back through the
    /// codec — against the body the read encodes, and the whole body
    /// pinned by hash. The structural half first, so a failure names the
    /// row before it names the byte.
    fn assert_snapshot_pins_the_slash_families(&self) {
        let m = SettlementEpoch::from_raw(self.m);
        let at = BlockHeight::from_raw(self.slashing_height);
        let shard = ShardId::from_raw(0);
        let snap = self.store.begin_read().expect("read");
        let got = snap
            .archival_snapshot()
            .expect("the slashed state snapshots");

        // The rows, as the constructors spell them: one log row per persona
        // at the connecting height (`ARW-Q17`), `seq` in bond-table order —
        // the deadline scan walks the bond table — one `slash_applied`
        // member each, and the watermark at the slashing epoch.
        let ids = ids_in_table_order(self.personas);
        let mut want = ArchivalSnapshot::empty();
        for (i, persona) in ids.iter().copied().enumerate() {
            let seq = u32::try_from(i).expect("fits");
            want.push_slash_log(
                at,
                seq,
                &SlashLogEntry {
                    persona,
                    shard,
                    epoch: m,
                    holding: SlashedHolding::CompleteTree,
                },
            )
            .expect("distinct keys");
            want.push_slash_applied(&persona, shard, m)
                .expect("distinct keys");
        }
        want.set_last_slash_epoch(m).expect("the one row");
        for family in [
            SnapshotFamily::SlashLog,
            SnapshotFamily::SlashApplied,
            SnapshotFamily::LastSlashEpoch,
        ] {
            assert_eq!(got.rows(family), want.rows(family), "{family}");
        }
        assert!(
            got.rows(SnapshotFamily::ServeCredit).is_empty(),
            "nobody served"
        );

        // The bytes, spelled: `n_rows u64 ‖ (len u32 ‖ key ‖ value)*`, little-
        // endian throughout, `Canonical(SlashLogEntry)` as `persona[32] ‖
        // shard u64 ‖ epoch u64 ‖ 0x01` for a complete-tree demotion.
        let n = self.personas.to_le_bytes();
        let mut slash_log = n.to_vec();
        let mut slash_applied = n.to_vec();
        for (i, persona) in ids.iter().enumerate() {
            slash_log.extend_from_slice(&(8u32 + 4 + 32 + 8 + 8 + 1).to_le_bytes());
            slash_log.extend_from_slice(&at.to_raw().to_le_bytes());
            slash_log.extend_from_slice(&u32::try_from(i).expect("fits").to_le_bytes());
            slash_log.extend_from_slice(persona.as_bytes());
            slash_log.extend_from_slice(&0u64.to_le_bytes());
            slash_log.extend_from_slice(&self.m.to_le_bytes());
            slash_log.push(0x01);
            slash_applied.extend_from_slice(&(32u32 + 8 + 8).to_le_bytes());
            slash_applied.extend_from_slice(persona.as_bytes());
            slash_applied.extend_from_slice(&0u64.to_le_bytes());
            slash_applied.extend_from_slice(&self.m.to_le_bytes());
        }
        let mut last_slash_epoch = 1u64.to_le_bytes().to_vec();
        last_slash_epoch.extend_from_slice(&8u32.to_le_bytes());
        last_slash_epoch.extend_from_slice(&self.m.to_le_bytes());

        let body = got.body();
        let sections = body_sections(&body);
        assert_eq!(sections.len(), SnapshotFamily::ALL.len());
        let section = |family: SnapshotFamily| &body[sections[family as usize].clone()];
        assert_eq!(
            hex(section(SnapshotFamily::SlashLog)),
            hex(&slash_log),
            "archival_slash_log section"
        );
        assert_eq!(
            hex(section(SnapshotFamily::SlashApplied)),
            hex(&slash_applied),
            "archival_slash_applied section"
        );
        assert_eq!(
            hex(section(SnapshotFamily::LastSlashEpoch)),
            hex(&last_slash_epoch),
            "archival_last_slash_epoch section"
        );

        // The whole record, pinned: the only `0x04` body in the tree with
        // the slash families populated.
        let got_hash = hex(&keccak256(&body));
        assert_eq!(
            got_hash, SLASHED_SNAPSHOT_BODY_KECCAK,
            "the 0x04 body at the slashing tip ({} bytes, {} rows) moved — a §3.8.1 / codec change re-pins it with its version bump",
            body.len(),
            got.row_count()
        );
        // And the trace's reader decodes exactly what the read encoded.
        let back = ArchivalSnapshot::read_body(&mut body.as_slice()).expect("reads");
        assert_eq!(back, got);
    }

    fn finish(self) {
        drop(self.store);
        cleanup(&self.path);
    }
}

/// `keccak256(body)` of the `0x04` body at the witness's slashing tip
/// under `RULES`, `WITNESS_PERSONAS` personas: 17 536 bytes, 39 rows — four
/// bonds, thirteen closed epochs' budget and Σwork rows, the open epoch's
/// accrual, and the slash families above. A fingerprint of bytes, not a
/// domain: the plain hash, so the pin registers nothing in
/// `CRYPTO_DOMAIN_REGISTRY.tsv` and moves no cSHAKE count-pin. Pinned
/// 2026-10-02 (`ARW-Q18`). Re-pinned twice on 2026-10-04 with no layout
/// change, and once more at their merge: the emission speed factor became
/// per block (22, the design's, where the per-minute convention had run
/// 21), which halves the emission each closed epoch's budget row records;
/// and the fixture personas gained derived keys and recomputed ids (E6
/// slice 8 row 4) — same byte count, same row count, the bond rows' keys
/// and ids moved, the codec did not. *Records-was:*
/// `6b1d14e89834bee02ad080ca3e9809ef3bd39e4411513d9ee474c1f2c501f76a`
/// (ARW-Q18); `2af8d16279df18ccd9dde4d8e889150e68679634d87e71791970cef8167fba11`
/// (speed factor alone); `283d9d1e126bfed44003d412e2e93b65652e56929038ddb549d56e30db7a1e2d`
/// (derived keys alone).
const SLASHED_SNAPSHOT_BODY_KECCAK: &str =
    "8723491ad1cd242eb2c49a7ebdc6e72fe0d7bf04c6fa569098f7bc86a20effd1";

/// Each family's byte range inside a body, walked by the record framing
/// alone (`n_rows u64`, then `len u32 ‖ row` each) — the test's own
/// reading of the layout, so a framing drift in the reader cannot hide one
/// in the writer.
fn body_sections(body: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut at = 0usize;
    let mut sections = Vec::with_capacity(SnapshotFamily::ALL.len());
    for _ in SnapshotFamily::ALL {
        let start = at;
        let n_rows = u64::from_le_bytes(body[at..at + 8].try_into().expect("8 bytes"));
        at += 8;
        for _ in 0..n_rows {
            let len = u32::from_le_bytes(body[at..at + 4].try_into().expect("4 bytes"));
            at += 4 + usize::try_from(len).expect("fits");
        }
        sections.push(start..at);
    }
    assert_eq!(at, body.len(), "the ten families are the whole body");
    sections
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
    chain.assert_settled_missed_from_epoch_one();
    chain.assert_nothing_slashed_before_m();
    chain.assert_slashed();
    chain.assert_snapshot_pins_the_slash_families();
    chain.finish();
}

/// With no draw issued, the slash pass settles nothing and slashes nothing
/// (`SO-D10a`): the state of every chain until the secret draw lands. The
/// witness's chain with an empty index, through three deadline connects.
#[test]
fn an_empty_index_settles_nothing_and_slashes_nothing() {
    fn nothing(_: u64, _: u64) -> Option<&'static [bool]> {
        None
    }
    let last = 2u64;
    let through = RULES.settlement_schedule().slash_deadline_height(last);
    let chain = SlashedChain::build_with("slash-empty-index", WITNESS_PERSONAS, through, nothing);
    let snap = chain.store.begin_read().expect("read");
    assert_eq!(
        snap.last_settled_slash_epoch().expect("read"),
        Some(SettlementEpoch::from_raw(last)),
        "the pass ran: the watermark moved"
    );
    assert_eq!(snap.total_burned().expect("read"), AtomicUnits::ZERO);
    for p in ids_in_table_order(chain.personas) {
        assert!(snap
            .slash_log_after(&p, BlockHeight::from_raw(0))
            .expect("read")
            .is_empty());
        assert!(snap
            .bond_record(&p)
            .expect("read")
            .expect("bonded")
            .is_complete_tree());
        for e in 0..=last {
            assert_eq!(
                snap.settlement_row(&p, ShardId::from_raw(0), SettlementEpoch::from_raw(e))
                    .expect("read"),
                None
            );
        }
    }
    drop(snap);
    chain.finish();
}

/// The window passes over an epoch that is not an observation and does
/// not stop at it (`SO-D10b`). Four pairs, one more epoch than the witness:
///
/// - persona 0 misses every epoch: slashed at epoch `M`, as the witness is.
/// - persona 1 is issued two draws in epoch 5, a NonObservation row. At `M`
///   it has `M − 1` misses and is not slashed. At `M + 1` it has `M`, with
///   epoch 5 passed over, and is. A walk that stopped at epoch 5 would
///   count the epochs above it only and never slash.
/// - persona 2 is issued nothing in epoch 5, so it has no row there. Same
///   verdict as persona 1: an absent row and a NonObservation row are one
///   case to the window.
/// - persona 3 is Served in epochs 3, 7 and 9. Three served epochs are
///   past the window's serve budget, so the walk ends at the third and
///   never gathers `m` misses: not slashed.
///
/// The chain runs one epoch past `M + 1` to show which draws count: a
/// pair is charged only for draws issued while it held the shard. Persona
/// 0's draws of `M + 2` were issued after its slash emptied the record, so
/// that epoch has no row for it; its draws of `M + 1` were issued before,
/// and do.
#[test]
fn the_window_passes_over_an_unobserved_epoch_and_counts_a_served_one() {
    fn plan(epoch: u64, persona: u64) -> Option<&'static [bool]> {
        match (persona, epoch) {
            (_, 0) | (2, 5) => None,
            (1, 5) => Some(SHORT),
            (3, 3 | 7 | 9) => Some(SERVED),
            _ => Some(MISSED),
        }
    }
    let m = u64::from(FAILURE_WINDOW_M);
    let schedule = RULES.settlement_schedule();
    let chain = SlashedChain::build_with(
        "slash-window-skip",
        4,
        schedule.slash_deadline_height(m + 2),
        plan,
    );
    let id = |i: u64| fixture::persona(persona(i)).id;
    let shard = ShardId::from_raw(0);
    let epoch = SettlementEpoch::from_raw;
    let snap = chain.store.begin_read().expect("read");
    let slashed_at = |i: u64| -> Vec<u64> {
        (0..=m + 2)
            .filter(|e| snap.slash_applied(&id(i), shard, epoch(*e)).expect("read"))
            .collect()
    };
    assert_eq!(slashed_at(0), [m], "every epoch missed: slashed at M");
    assert_eq!(
        slashed_at(1),
        [m + 1],
        "a NonObservation epoch is passed over"
    );
    assert_eq!(
        slashed_at(2),
        [m + 1],
        "an epoch with no row is passed over"
    );
    assert_eq!(slashed_at(3), [0u64; 0], "three served epochs end the walk");

    // The rows the verdicts were read from.
    let outcome = |i: u64, e: u64| {
        snap.settlement_row(&id(i), shard, epoch(e))
            .expect("read")
            .map(SettlementRow::outcome)
    };
    assert_eq!(outcome(1, 5), Some(SettlementOutcome::NonObservation));
    assert_eq!(outcome(2, 5), None);
    assert_eq!(outcome(3, 3), Some(SettlementOutcome::Served));
    assert_eq!(outcome(3, 7), Some(SettlementOutcome::Served));
    assert_eq!(outcome(3, 9), Some(SettlementOutcome::Served));
    assert_eq!(outcome(3, 4), Some(SettlementOutcome::Missed));
    // Persona 0 was slashed out of the shard by the connect at
    // `last_block(M + 1)`. Its draws of M + 1 were issued below that
    // height, so they count and the epoch has its row; the slash is not
    // repeated, because the open interval ends its standing. Its draws of
    // M + 2 were issued above it: issued, folded into the digest the pass
    // checked, and not counted.
    assert_eq!(outcome(0, m + 1), Some(SettlementOutcome::Missed));
    assert_eq!(outcome(0, m + 2), None);
    assert_eq!(
        snap.issued_draws(epoch(m + 2))
            .expect("read")
            .iter()
            .filter(|d| d.persona == id(0))
            .count(),
        3,
        "the draws were issued"
    );
    // Personas 1 and 2 were slashed one epoch later, by the connect at
    // `last_block(M + 2)`, so their draws of M + 2 still count.
    assert_eq!(outcome(1, m + 2), Some(SettlementOutcome::Missed));
    drop(snap);
    chain.finish();
}

/// The window reads no epoch below the retention horizon. A walk that
/// passes over unobserved epochs could otherwise reach rows a store may
/// have deleted, and the verdict would depend on what a node had pruned
/// (`slash.rs` module docs, *The window*).
///
/// Two pairs with the same shape — ten misses, a long unobserved gap, one
/// more miss at epoch 28 — placed two epochs apart. At epoch 28's pass the
/// tip is in epoch 29 and the horizon is `29 − MAX_CLAIM_AGE_W_EPOCHS = 3`.
/// Persona 1's ten misses are epochs 3–12, all at or above it: eleven
/// misses, slashed. Persona 0's are epochs 1–10, two of them below it:
/// nine, not slashed. Without the bound both would be.
///
/// Ignored on two counts. The bound is as built and not yet ruled
/// (`ARCHIVAL_SETTLEMENT_WRITER.md` §14.4 step 3), so this is its witness
/// and not a pin of a ratified rule. And the chain is thirty epochs.
#[test]
#[ignore = "pins the unruled retention-horizon bound (SO-D10b, awaiting ratification) over 3 000 connects, minutes in debug. Run: cargo test -p shekyl-chain-store --lib -- --ignored the_window_stops_at_the_retention_horizon"]
fn the_window_stops_at_the_retention_horizon() {
    fn plan(epoch: u64, persona: u64) -> Option<&'static [bool]> {
        let first = if persona == 0 { 1 } else { 3 };
        ((first..first + 10).contains(&epoch) || epoch == 28).then_some(MISSED)
    }
    let schedule = RULES.settlement_schedule();
    let through = schedule.slash_deadline_height(28);
    assert_eq!(
        schedule
            .prune_below_epoch_at_height(through, shekyl_types::archival::MAX_CLAIM_AGE_W_EPOCHS),
        Some(3),
        "the horizon at epoch 28's pass"
    );
    let chain = SlashedChain::build_with("slash-window-horizon", 2, through, plan);
    let id = |i: u64| fixture::persona(persona(i)).id;
    let snap = chain.store.begin_read().expect("read");
    let slashed_at = |i: u64| -> Vec<u64> {
        (0..=28)
            .filter(|e| {
                snap.slash_applied(&id(i), ShardId::from_raw(0), SettlementEpoch::from_raw(*e))
                    .expect("read")
            })
            .collect()
    };
    assert_eq!(
        slashed_at(1),
        [28],
        "ten misses inside the horizon, and one"
    );
    assert_eq!(slashed_at(0), [0u64; 0], "two of its misses are below it");
    drop(snap);
    chain.finish();
}

/// Settlement of an epoch whose stored draws do not fold to its digest is
/// the validator's `Corrupt`, and the store's SI-25 — never a slash and
/// never a refusal of the block (specification §9.5 check 1). Each of the
/// three ways the index can drift from the digest admission left.
#[test]
fn an_index_that_does_not_fold_to_its_digest_halts_the_slash_pass() {
    type Tamper = fn(&ChainStore, SettlementEpoch);
    // A draw the digest never folded.
    fn a_draw_gained(store: &ChainStore, epoch: SettlementEpoch) {
        let mut extra = planned_draws(epoch.to_raw(), 1, every_epoch_missed)[0];
        extra.draw = 9;
        let digest = store.begin_read().unwrap().issued_digest(epoch).unwrap();
        store
            .regtest_issue_draws(Trust::UNANCHORED, epoch, &[extra], digest)
            .expect("issued");
    }
    // The digest cell changed under its rows.
    fn the_digest_changed(store: &ChainStore, epoch: SettlementEpoch) {
        store
            .regtest_issue_draws(Trust::UNANCHORED, epoch, &[], IssuedDigest::ZERO)
            .expect("written");
    }
    // A row lost: removed beneath the door.
    fn a_draw_lost(store: &ChainStore, epoch: SettlementEpoch) {
        let lost = planned_draws(epoch.to_raw(), 1, every_epoch_missed)[0];
        let out: Result<(), TestErr> = store.write(|batch| {
            // Bound to a row no check names: the fixture knows the key is
            // there, so the bound row is never armed.
            let mut index = batch.open_remove_table(
                crate::schema::ARCHIVAL_ISSUED_DRAW,
                StoreInvariant::TipMismatch,
            )?;
            let key = crate::ids::IssuedDrawKey::new(
                epoch,
                lost.persona,
                lost.shard,
                lost.issuing_height,
                lost.draw,
            );
            index.remove(key.key())?;
            Ok(())
        });
        out.expect("removed");
    }
    for (label, tamper) in [
        ("slash-drift-gained", a_draw_gained as Tamper),
        ("slash-drift-digest", the_digest_changed as Tamper),
        ("slash-drift-lost", a_draw_lost as Tamper),
    ] {
        let epoch = SettlementEpoch::from_raw(1);
        let deadline = RULES.settlement_schedule().slash_deadline_height(1);
        let chain = SlashedChain::build_with(label, 1, deadline - 1, every_epoch_missed);
        tamper(&chain.store, epoch);
        let out: Result<(), TestErr> = chain.store.write(|batch| {
            let view = batch.chain_view();
            let previous = chain.tip;
            let root = batch_root_going_into(&view, deadline)?;
            let cand = candidate_over(root, deadline, previous, Vec::new());
            let Err(corrupt) = judge_or_corrupt(&view, cand, &RULES)? else {
                panic!("{label}: the pass settled a drifted index");
            };
            assert_eq!(
                corrupt,
                Corrupt::SettlementIntegrity {
                    epoch,
                    check: SettlementCheck::IssuedIndexDigest,
                },
                "{label}"
            );
            Err(batch.refuse_corrupt(corrupt).into())
        });
        let TestErr::Store(message) = out.expect_err("the batch is refused") else {
            panic!("{label}: aborted, not refused");
        };
        assert!(
            message.contains("do not fold to archival_issued_digest"),
            "{label}: {message}"
        );
        chain.finish();
    }
}

/// The rows are journaled with the block that settled them: popping the
/// deadline connect takes the epoch's rows and the watermark back, and
/// leaves the draws, which the door wrote outside any block.
#[test]
fn popping_the_deadline_connect_unsettles_the_epoch() {
    let epoch = SettlementEpoch::from_raw(1);
    let deadline = RULES.settlement_schedule().slash_deadline_height(1);
    let chain = SlashedChain::build_with("slash-pop-settlement", 2, deadline, every_epoch_missed);
    let shard = ShardId::from_raw(0);
    let rows = |store: &ChainStore| -> Vec<Option<SettlementRow>> {
        let snap = store.begin_read().expect("read");
        ids_in_table_order(2)
            .iter()
            .map(|p| snap.settlement_row(p, shard, epoch).expect("read"))
            .collect()
    };
    let missed = Some(SettlementRow::settle(0, 3).expect("a row"));
    assert_eq!(rows(&chain.store), [missed, missed]);
    let popped: Result<Popped, TestErr> = chain.store.write(|batch| Ok(batch.pop()?));
    assert_eq!(
        popped.expect("pops").height,
        BlockHeight::from_raw(deadline)
    );
    assert_eq!(
        rows(&chain.store),
        [None, None],
        "the rows went with the block"
    );
    let snap = chain.store.begin_read().expect("read");
    assert_eq!(
        snap.last_settled_slash_epoch().expect("read"),
        Some(SettlementEpoch::from_raw(0)),
        "the watermark is the epoch before"
    );
    assert_eq!(snap.issued_draws(epoch).expect("read").len(), 6);
    drop(snap);
    chain.finish();
}

/// An epoch settles once. A row already under a pair's key when the pass
/// writes it is SI-25 at the insert, before any journal entry.
#[test]
fn a_settlement_row_already_recorded_refuses_the_second_write() {
    let epoch = SettlementEpoch::from_raw(1);
    let deadline = RULES.settlement_schedule().slash_deadline_height(1);
    let chain =
        SlashedChain::build_with("slash-settled-twice", 1, deadline - 1, every_epoch_missed);
    let p = fixture::persona(persona(0)).id;
    let planted: Result<(), TestErr> = chain.store.write(|batch| {
        batch
            .open_upsert_table(crate::schema::ARCHIVAL_SETTLEMENT)?
            .upsert(
                crate::ids::SettlementKey::new(p, ShardId::from_raw(0), epoch).key(),
                SettlementRow::settle(2, 3)
                    .expect("a row")
                    .encoded()
                    .as_encoded(),
            )?;
        Ok(())
    });
    planted.expect("planted");
    let out: Result<(), TestErr> = chain.store.write(|batch| {
        let view = batch.chain_view();
        let previous = chain.tip;
        let root = batch_root_going_into(&view, deadline)?;
        let cand = candidate_over(root, deadline, previous, Vec::new());
        let judged = judge_under(&view, cand, &RULES)?;
        batch.connect(judged, RULES)?;
        Ok(())
    });
    let TestErr::Store(message) = out.expect_err("the connect is refused") else {
        panic!("aborted, not refused");
    };
    assert!(
        message.contains("an epoch settles once"),
        "the insert names SI-25: {message}"
    );
    assert_eq!(
        StoreInvariant::SettlementNotSound {
            epoch,
            observed: SettlementFault::AlreadySettled {
                persona: p,
                shard: ShardId::from_raw(0),
            },
        }
        .row(),
        25
    );
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
