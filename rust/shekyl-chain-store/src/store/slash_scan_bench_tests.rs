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
//! The chain, under `RuleSet::GENESIS.with_levers(fixed 7, SEB 100 / cap 50)`:
//! the captured shard-fill chain's prefix closes shard 0 with real spends
//! (`store/shard_fill.rs`, height 131, in epoch 1), so the scan's universe
//! is one shard; then `P` complete-tree personas join in the same epoch,
//! [`JOIN_EPOCH`] — one **real** bond post per block from the block after
//! the close, each spending the lowest coinbase matured and unspent
//! (CEN-J27: a bond post is judged by I13/I15 over its `ToKey` inputs, so a
//! listed join is a proof over a coinbase the chain mined, built by the
//! harness spender over [`Grown`]'s tree). Every epoch below is counted
//! from the join's ([`shifted`]). *Records-was:* until the switch's C7 the
//! joins came first, in epoch 0, and padded serve credits on shard 1 closed
//! shard 0 in the same epoch; the serve-credit input is deleted, and real
//! spends close a shard no sooner than height 131.
//! Each pair on shard 0 is planted three draws in every epoch from the
//! join's plus one
//! (`store_tests::plant_issued_draws`), none passed — which is how every
//! observation settles Missed. Each epoch's deadline connect settles that
//! epoch: the join's has no draw and is not in standing either
//! (`good_through` starts the epoch after the join), the next `M − 1` are
//! misses that do not yet fill the window, and the deadline connect of the
//! `M`-th (`last_block` one epoch of grace later) slashes every
//! persona on shard 0. Both tests assert that — the watermark, the log,
//! `slash_applied`, the emptied records, the burn (SI-8).
//!
//! One join per block is the rate the chain sustains, not a choice: a
//! join spends the lowest matured coinbase, and past the ten the captured
//! chain leaves unspent one coinbase matures per block. With the joins
//! inside epoch 0, the personas a chain admits are [`max_personas`] — the
//! bench's default. *Records-was:* until CEN-J27 the joins were fixture
//! bodies over a 1-byte height, four per block from height 10 and
//! sixty-four by default; the sixty-four already overran epoch 0 once the
//! first spending height became the harness's, which the ignored bench did
//! not report.
//!
//! **`slash_writes_land_at_the_m_epoch_deadline`** is the witness: four
//! personas, `(M + 2)·SEB` connects, in the unit lane of every run. Until the
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
//! **The chain and the slash log's window** (`SLK-5`,
//! `DRS_E4_SLASH_LOG_ROUND.md`). The log is retired below
//! `tip − ((k + n)·SEB + reorg_cap)` at every boundary (`prune.rs`), so a
//! retiring node's `0x04` `slash_log` family is *rows at or above the
//! floor*, and a reader of the log hands A2 the floor (SI-26). The
//! witness runs to [`WITNESS_TIP`], `slash_deadline_height(SLASHING_EPOCH)`
//! = `(SLASHING_EPOCH + 2)·SEB − 1`, which sits under [`WINDOW`], `(k + n)·SEB + cap`
//! under the same pair ([`SlashLogFloor::window`]) — a relation asserted
//! at compile time where both are declared, not a header claim: the floor
//! is `None` and the family is the whole log. Nothing here assumes that:
//! every read of the log starts from the floor at the snapshot's tip
//! ([`whole_log_from`]), so a witness that grows past the window reads
//! from the floor, not from `0`, and the snapshot pin spells rows at the
//! slashing height, above any floor. The two accidental passes this file
//! has carried — the ignored bench's sixty-four joins overrunning epoch 0,
//! and a from-`0` read sound only because the chain was short — are the
//! reason both lengths are derived and the read is not a literal.
//!
//! **`slash_scan_bench`** (`#[ignore]`) is the measurement §3.1 owes for
//! "the scan runs once per epoch on the floor": [`max_personas`] personas
//! by default, and it prints
//!
//! - the judge and connect times of an ordinary connect (the mean over the
//!   empty blocks between the first deadline and the second — after the
//!   shard closed, before anything settles),
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
//! Run: `SHEKYL_SLASH_BENCH_PERSONAS=23 cargo test -p shekyl-chain-store
//! --release slash_scan_bench -- --ignored --nocapture`.

//! Settlement's own wiring — an empty index, the window on a real chain,
//! a drifted digest, a popped deadline, a second write — lives in
//! [`settlement_slash_tests`]. The retention floor is specified on
//! `settlement_window_slashable`, not by a chain of thirty epochs.
//!
// A whole-file test module: the parent gates it with `#[cfg(test)]`, and
// this self-declaration is what the debug-macro lint keys on — the bench
// prints its figures, which is its job, not a debug leftover.
#![cfg(test)]

use core::num::NonZeroU128;
use std::time::{Duration, Instant};

use shekyl_archival_retention::settlement_select::issued_draw_term;
use shekyl_archival_retention::{ARCHIVAL_BOND_FLOOR_ATOMIC, FAILURE_WINDOW_M, FAILURE_WINDOW_N};
use shekyl_chain_rules::{CappedEpoch, Corrupt, RuleSet, SettlementCheck, SlashLogFloor};
use shekyl_crypto_hash::keccak256;
use shekyl_harness_spender::Persona;
use shekyl_types::archival::{
    IndexedDraw, IssuedDigest, IssuedDraw, SettlementOutcome, SettlementRow, SlashedHolding,
};
use shekyl_types::{BlockCount, BlockHeight, PCanonicalId, SettlementEpoch, ShardId};
use shekyl_units::AtomicUnits;

use super::connect_fixtures::{Grown, Listed};
use super::shard_fill;
use super::store_tests::{tmp, TestErr};
use super::*;
use crate::archival_snapshot::{hex, ArchivalSnapshot, SnapshotFamily};
use crate::codec::{Canonical, SettlementEpochBlocks, SlashLogEntry};
use crate::test_paths::TestPath;
use shekyl_chain_rules::EpochFloor;

const SEB: u64 = 100;
const RETENTION: u64 = 50;
/// Fixed difficulty: over a thousand blocks at the fixture's constant
/// spacing LWMA would floor the difficulty, and the fixture's zero longhash
/// passes any fixed target.
const RULES: RuleSet = RuleSet::GENESIS.with_levers(NonZeroU128::new(7), pair(SEB, RETENTION));
/// The rule set and undo retention a bench chain is built under, and the
/// name its captured-prefix snapshots go by (`shard_fill::store_with_prefix`:
/// one name, one pair).
#[derive(Clone, Copy)]
struct Under {
    rules: RuleSet,
    retention: u64,
    schedule_key: &'static str,
}

impl Under {
    /// [`RULES`] with [`RETENTION`]: every chain here unless a test says.
    const BENCH: Self = Self {
        rules: RULES,
        retention: RETENTION,
        schedule_key: "d7-seb100-cap50",
    };

    /// The bench pair with a 90-block reorg cap and retention: a shard is
    /// final 90 blocks after it closes, so shard 0 (closed at height 131)
    /// is final only at 221, after epoch 2 opens. A test that needs an
    /// epoch whose members exist while its archive is still width 0 runs
    /// here.
    const LATE_FINAL: Self = Self {
        rules: RuleSet::GENESIS.with_levers(NonZeroU128::new(7), pair(SEB, 90)),
        retention: 90,
        schedule_key: "d7-seb100-cap90",
    };
}

/// The witness's persona count: enough that the per-persona loop is a loop,
/// few enough that the chain builds in the unit lane in debug.
const WITNESS_PERSONAS: u64 = 4;

const fn pair(seb: u64, cap: u64) -> CappedEpoch {
    let Some(epoch) = SettlementEpochBlocks::new(seb) else {
        panic!("a zero epoch");
    };
    match CappedEpoch::new(epoch, BlockCount::from_raw(cap)) {
        Ok(pair) => pair,
        Err(_) => panic!("the cap is not inside the epoch"),
    }
}

/// The epoch the personas join in: the one the captured prefix closes
/// shard 0 in, which `SlashedChain::build_with` asserts against the chain.
const JOIN_EPOCH: u64 = 1;

/// Epoch `n` of the layout these tests were written against, where the
/// personas joined in epoch 0: the chain's epoch `JOIN_EPOCH + n`.
const fn shifted(n: u64) -> u64 {
    JOIN_EPOCH + n
}

/// The slashing epoch: the `M`-th after the join's (`u64::from` is not
/// `const`).
#[allow(clippy::cast_lossless)]
const SLASHING_EPOCH: u64 = shifted(FAILURE_WINDOW_M as u64);

/// The witness's tip: the slashing connect, `(SLASHING_EPOCH + 2)·SEB − 1`
/// under the schedule — the schedule's expression, not a literal.
const WITNESS_TIP: u64 = RULES
    .settlement_schedule()
    .slash_deadline_height(SLASHING_EPOCH);
/// The slash log's window under the same pair, `(k + n)·SEB + cap`
/// ([`SlashLogFloor::window`], `SLK-5`).
const WINDOW: u64 =
    match SlashLogFloor::window(RULES.settlement_schedule().blocks(), RULES.reorg_cap()) {
        Some(window) => window.to_raw(),
        None => panic!("the window fits"),
    };
/// Where the witness sits against the window, stated where both are
/// declared rather than in a header a reader has to recompute: under it,
/// so the floor at the tip is `None` and the `0x04` family pinned below is
/// the whole log. If a constant moves this past the window, every read
/// here already starts from the floor ([`whole_log_from`]) and the pin's
/// rows sit at the slashing height, above any floor — re-read the header's
/// claim and this assertion's message, then move the assertion to the
/// side the witness is now on.
const _: () = assert!(
    WITNESS_TIP < WINDOW,
    "the witness has crossed the slash log's window: its tip's floor is Some, and the header's \
     'the floor is None' claim is false"
);

/// The personas a chain admits with every join inside [`JOIN_EPOCH`]: one
/// join per block from the block after shard 0's close. The bench's
/// default, and its ceiling.
fn max_personas() -> u64 {
    (JOIN_EPOCH + 1) * SEB - u64::try_from(prefix()).expect("small")
}

/// Blocks per `store.write`: the bench measures the judge and the connect,
/// not redb's commit.
const PER_BATCH: u64 = 50;

fn personas() -> u64 {
    std::env::var("SHEKYL_SLASH_BENCH_PERSONAS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(max_personas)
}

/// The `i`-th bench persona is the harness persona at slot `i`
/// ([`Persona::at`] derives the keys and the id), the one [`Grown::join`]
/// posts the bond for.
fn slot(i: u64) -> u32 {
    u32::try_from(i).expect("a persona slot")
}

/// The captured prefix the chain starts from: through the block that
/// closes shard 0.
fn prefix() -> usize {
    shard_fill::blocks_closing(shard_fill::shard_fill(), 0)
}

/// The height the `i`-th persona's join connects at: one per block from
/// the block after the captured prefix, in slot order.
fn join_height(i: u64) -> BlockHeight {
    BlockHeight::from_raw(u64::try_from(prefix()).expect("small") + i)
}

/// The slash log's retirement floor at `snap`'s tip under `RULES` — the
/// operand a reader of the log hands A2 (SI-26), and the height every
/// whole-log read here starts from ([`whole_log_from`]). `None` while the
/// chain is under the window (`SLK-5`); carried rather than
/// `SlashLogFloor::NONE` so a chain that crosses it reads from the floor.
fn slash_floor_at(snap: &ReadSnapshot<'_>) -> SlashLogFloor {
    let tip = snap
        .tip()
        .expect("read")
        .recorded
        .expect("a built chain has a tip")
        .height;
    SlashLogFloor::under(tip, RULES.settlement_schedule().blocks(), RULES.reorg_cap())
}

/// The height a whole-log A2 read starts strictly above: one under the
/// floor when there is one — the rows below it are retired, so the read
/// starts at the first retained — else `0`. The lowest `height` SI-26
/// admits, derived from the floor rather than written as `0`.
fn whole_log_from(floor: SlashLogFloor) -> BlockHeight {
    floor.height().map_or(BlockHeight::ZERO, |first_kept| {
        BlockHeight::from_raw(first_kept.to_raw().saturating_sub(1))
    })
}

/// The `personas` bench personas' ids **in bond-table order** — the order
/// the deadline scan walks them, so the order the slash log's `seq` and
/// the snapshot's rows are in. Ids are recomputes over derived keys
/// (CEN-J11), so slot order and id order are unrelated; *records-was:*
/// until E6 slice 8 row 4 the tag *was* the id, and `i` order was table
/// order.
fn ids_in_table_order(personas: u64) -> Vec<PCanonicalId> {
    let mut ids: Vec<PCanonicalId> = (0..personas).map(|i| Persona::at(slot(i)).id()).collect();
    ids.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    ids
}

/// What block `h` lists past the captured prefix: the `i`-th persona's
/// join at [`join_height`]`(i)`, and nothing else.
fn listing(h: u64, personas: u64) -> Vec<Listed> {
    let k = h - join_height(0).to_raw();
    if k < personas {
        return vec![Listed::Join { slot: slot(k) }];
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

/// The witness's plan: every pair misses every epoch after the join's.
fn every_epoch_missed(epoch: u64, _persona: u64) -> Option<&'static [bool]> {
    (epoch >= shifted(1)).then_some(MISSED)
}

/// The draws `plan` issues in `epoch`, each pair's on shard 0 at
/// consecutive heights inside the epoch, in index order.
fn planned_draws(epoch: u64, personas: u64, plan: Plan) -> Vec<IndexedDraw> {
    let open = RULES.settlement_schedule().open_height(epoch);
    let mut draws = Vec::new();
    for id in ids_in_table_order(personas) {
        let i = (0..personas)
            .find(|i| Persona::at(slot(*i)).id() == id)
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

/// Plant `epoch`'s planned draws, with the digest they fold to.
fn issue(store: &ChainStore, epoch: u64, personas: u64, plan: Plan) {
    let draws = planned_draws(epoch, personas, plan);
    if draws.is_empty() {
        return;
    }
    let epoch = SettlementEpoch::from_raw(epoch);
    let digest = store
        .begin_read()
        .expect("read")
        .issued_digest(epoch, EpochFloor::NONE)
        .expect("read");
    super::store_tests::plant_issued_draws(store, epoch, &draws, folded(digest, epoch, &draws));
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
    /// The store's directory, removed when this drops (after the store).
    _path: TestPath,
    personas: u64,
    /// The slashing epoch's raw value, [`SLASHING_EPOCH`].
    m: u64,
    /// What the captured prefix burned: its spends' fees.
    prefix_burned: AtomicUnits,
    /// `last_block(M + SLASH_GRACE_EPOCHS)`: the connect that slashes.
    slashing_height: u64,
    /// The join epoch's deadline: the first deadline connect after the
    /// joins.
    first_deadline: u64,
    /// The height whose listed bodies carried the running archival total
    /// past `W` — where shard 0 closed, read off the chain as it was built.
    shard_closed: u64,
    /// The chain as built, for a test that connects one more block by hand.
    grown: Grown,
    /// The rule set the chain was built and is connected under: [`RULES`],
    /// or a test's own pair ([`Self::build_under`]).
    rules: RuleSet,
    /// The undo retention its store was opened with.
    retention: u64,
    timings: Vec<Timing>,
    built: Duration,
}

impl SlashedChain {
    /// Close the store and open it again over the same file, as a restart
    /// does. Nothing rules-side survives: a connector's drawable memo is
    /// not persisted, so the caller's next memo is cold.
    fn reopen(&mut self) {
        let schedule = self.rules.settlement_schedule();
        let horizons = Horizons::new(
            schedule.blocks(),
            BlockCount::from_raw(self.retention),
            self.rules.reorg_cap(),
        )
        .expect("cap ≤ retention < epoch");
        // The file's lock is held while the old handle lives, so a scratch
        // store stands in the field while the real one closes and reopens.
        let scratch = tmp("reopen-scratch");
        let closing = std::mem::replace(
            &mut self.store,
            ChainStore::with_horizons(&scratch, ApplyPolicy::Full, horizons).expect("scratch"),
        );
        drop(closing);
        let reopened =
            ChainStore::with_horizons(&self._path, ApplyPolicy::Full, horizons).expect("reopen");
        drop(std::mem::replace(&mut self.store, reopened));
        drop(scratch);
    }

    /// The witness's chain: every pair misses every epoch from 1, built to
    /// the epoch-`M` slashing connect.
    fn build(label: &str, personas: u64) -> Self {
        Self::build_with(label, personas, WITNESS_TIP, every_epoch_missed)
    }

    /// A chain through height `through`, each epoch's draws issued by
    /// `plan` once the epoch's blocks are connected — an epoch ahead of the
    /// deadline connect that settles it.
    fn build_with(label: &str, personas: u64, through: u64, plan: Plan) -> Self {
        Self::build_under(label, personas, through, plan, Under::BENCH)
    }

    /// [`Self::build_with`] under `under`'s rule set and retention: a test
    /// whose subject turns on the reorg cap (finality is the close height
    /// plus the cap, `closed_and_final`) states its own pair. The epoch is
    /// [`SEB`] whatever the pair.
    fn build_under(label: &str, personas: u64, through: u64, plan: Plan, under: Under) -> Self {
        let Under {
            rules,
            retention,
            schedule_key,
        } = under;
        assert_eq!(rules.settlement_schedule().blocks().get(), SEB);
        assert!(
            SEB.is_multiple_of(PER_BATCH),
            "an epoch ends on a batch boundary"
        );
        let max = max_personas();
        assert!(
            (1..=max).contains(&personas),
            "{personas} personas: the joins must land inside the join epoch (at most {max})"
        );
        let schedule = rules.settlement_schedule();
        let m = SLASHING_EPOCH;
        let slashing_height = schedule.slash_deadline_height(m);
        let total = through + 1;

        let path = tmp(label);
        let horizons = Horizons::new(
            schedule.blocks(),
            BlockCount::from_raw(retention),
            rules.reorg_cap(),
        )
        .expect("cap ≤ retention < epoch");
        // The captured prefix closes shard 0 (`shard_fill`); it is loaded,
        // not timed, and its slots in `timings` are zero.
        let (store, mut grown) =
            shard_fill::store_with_prefix(&path, schedule_key, rules, horizons, prefix());
        let shard_closed = u64::try_from(prefix()).expect("small") - 1;
        assert_eq!(
            (
                schedule.epoch_at_height(shard_closed),
                schedule.epoch_at_height(join_height(0).to_raw())
            ),
            (JOIN_EPOCH, JOIN_EPOCH),
            "shard 0 closes, and the personas join, in the join epoch"
        );
        // The captured spends pay fees, and fees burn (CEN-F17): what the
        // prefix burned is the baseline the slash's burns fold onto.
        let prefix_burned = store
            .begin_read()
            .expect("read")
            .total_burned()
            .expect("read");
        drop(store);
        let store = ChainStore::with_horizons(&path, ApplyPolicy::Full, horizons).expect("reopen");
        let mut timings: Vec<Timing> = vec![Timing::default(); prefix()];
        let wall = Instant::now();
        let mut h = u64::try_from(prefix()).expect("small");
        while h < total {
            // Batches end on multiples of `PER_BATCH`, so an epoch ends on
            // one whatever height the prefix leaves.
            let end = ((h / PER_BATCH + 1) * PER_BATCH).min(total);
            let out: Result<(), TestErr> = store.write(|batch| {
                let view = batch.chain_view();
                for height in h..end {
                    assert_eq!(grown.height().to_raw(), height);
                    let txs = grown.realise(&listing(height, personas));
                    let started = Instant::now();
                    // `record` rides inside the judge interval. It is the
                    // wallet-tree insert, microseconds beside the proof
                    // `realise` already spent outside this timer.
                    let judged = grown.judge_listing(&view, &rules, &txs)?;
                    let judge = started.elapsed();
                    let started = Instant::now();
                    batch.connect(judged, rules)?;
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
            _path: path,
            personas,
            m,
            slashing_height,
            first_deadline: schedule.slash_deadline_height(shifted(0)),
            prefix_burned,
            shard_closed,
            grown,
            rules,
            retention,
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
        let mut burned = self.prefix_burned;
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
                snap.slash_applied(&p, ShardId::from_raw(0), slashing_epoch, EpochFloor::NONE)
                    .expect("read"),
                "slash_applied({p:?}, 0, {m})"
            );
            let log_floor = slash_floor_at(&snap);
            let log = snap
                .slash_log_after(&p, whole_log_from(log_floor), log_floor)
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
    /// decide): Missed on no pass of three for every epoch after the join's
    /// through the slashing one, and none for the join's, in which no draw
    /// was issued.
    fn assert_settled_missed_from_epoch_one(&self) {
        let snap = self.store.begin_read().expect("read");
        let shard = ShardId::from_raw(0);
        let missed = SettlementRow::settle(0, 3).expect("a row");
        assert_eq!(missed.outcome(), SettlementOutcome::Missed);
        for p in ids_in_table_order(self.personas) {
            assert_eq!(
                snap.settlement_row(
                    &p,
                    shard,
                    SettlementEpoch::from_raw(shifted(0)),
                    EpochFloor::NONE
                )
                .expect("read"),
                None,
                "no draw, no row"
            );
            for e in shifted(1)..=self.m {
                assert_eq!(
                    snap.settlement_row(&p, shard, SettlementEpoch::from_raw(e), EpochFloor::NONE)
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
                        .slash_applied(
                            &p,
                            ShardId::from_raw(0),
                            SettlementEpoch::from_raw(e),
                            EpochFloor::NONE
                        )
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
        let per_family: Vec<String> = SnapshotFamily::ALL
            .iter()
            .map(|f| format!("{f}: {}", got.rows(*f).len()))
            .collect();
        assert_eq!(
            got_hash,
            SLASHED_SNAPSHOT_BODY_KECCAK,
            "the 0x04 body at the slashing tip ({} bytes, {} rows: {}) moved — a §3.8.1 / codec change re-pins it with its version bump",
            body.len(),
            got.row_count(),
            per_family.join(", ")
        );
        // And the trace's reader decodes exactly what the read encoded.
        let back = ArchivalSnapshot::read_body(&mut body.as_slice()).expect("reads");
        assert_eq!(back, got);
    }
}

/// `keccak256(body)` of the `0x04` body at the witness's slashing tip
/// under `RULES`, `WITNESS_PERSONAS` personas: 24 896 bytes, 40 rows — four
/// bonds, fourteen closed epochs' budget rows and the thirteen settled
/// epochs' Σwork rows, and the slash families above. A fingerprint of bytes,
/// not a domain: the plain hash, so the pin registers nothing in
/// `CRYPTO_DOMAIN_REGISTRY.tsv` and moves no cSHAKE count-pin. Pinned
/// 2026-10-02 (`ARW-Q18`). Re-pinned twice on 2026-10-04 with no layout
/// change, and once more at their merge: the emission speed factor became
/// per block (22, the design's, where the per-minute convention had run
/// 21), which halves the emission each closed epoch's budget row records;
/// and the fixture personas gained derived keys and recomputed ids (E6
/// slice 8 row 4) — same byte count, same row count, the bond rows' keys
/// and ids moved, the codec did not. Re-pinned 2026-10-08 at the CEN-I13
/// flip: the thirty-one padding bodies became serve credits
/// ([`padded_credit`]), which the record carries as thirty-one
/// `ServeCredit` rows — 31 × (4 + 56) = 1 860 bytes, the whole delta from
/// 17 536 — and nothing else moved: the slash families are spelled and
/// asserted above; the bond rows are the same joins; the budget rows are
/// inflow; and every Σwork row is zero and no `R_market` row exists, as
/// before, because a complete-tree persona is not a market member
/// (`shekyl_archival_retention::market_member_at_epoch`:
/// `is_support_complete_tree ⇒ false`),
/// so its credits earn no work and count in no shard. Re-pinned
/// 2026-10-08 again at CEN-J27: the joins became real bond posts, so the
/// four personas are the harness's (`Persona::at(0..4)`, whose keys and
/// ids differ from the fixture tag personas') — the bond, slash-log and
/// slash-applied rows carry the new ids at the same widths — and the
/// padding became twenty-two credits on eleven heights by personas 0 and
/// 1 in place of thirty-one by persona 0: nine `ServeCredit` rows fewer,
/// 9 × 60 = 540 bytes, the whole delta from 19 396. The budget rows are
/// emission inflow and a join pays no fee, so they did not move; the
/// Σwork rows are zero as before. Re-pinned 2026-10-09 at `SO-D11`: an
/// epoch's Σwork row is written by its slash pass, an epoch after its
/// close, so the tip holds thirteen budget rows (epochs 0–12) and twelve
/// Σwork rows (epochs 0–11) where it held thirteen of each — one row
/// fewer, 4 + 16 = 20 bytes, the whole delta from 18 856. Nothing else
/// moved. Re-pinned 2026-10-12 with the receipt key (FN-DSA increment 3,
/// `FN_DSA_HYBRID.md` `FND-17`): every bond record carries its persona's
/// receipt key, 1 837 bytes fixed-width with no length prefix, and the four
/// personas' joins commit theirs — 4 × 1 837 = 7 348 bytes, the whole delta
/// from 18 836, the row count unchanged at 60. Nothing else moved: the slash
/// families are spelled and asserted above, and the credit, budget and
/// Σwork rows do not read a bond's keys. Re-pinned 2026-11-03 with the
/// wallet derivation change (`NI-R7` / `NI-R10`, `NETWORK_IDENTITY.md`:
/// the HKDF salt is the network's tag with no seed-format component), so
/// `Persona::at` derives new keys and ids from the same master seed. No
/// codec changed: same 26 184 bytes, same 60 rows in every family. The
/// parent's body maps onto this one byte for byte by substituting each
/// persona's id, identity key, bond-spend key and receipt key; the only
/// other movement is order — the bond and slash-applied rows sort by the
/// new ids, and the slash-log `seq` follows bond-table order, so it
/// renumbers. The budget and Σwork rows are byte-identical. *Records-was:*
/// `6b1d14e89834bee02ad080ca3e9809ef3bd39e4411513d9ee474c1f2c501f76a`
/// (ARW-Q18); `2af8d16279df18ccd9dde4d8e889150e68679634d87e71791970cef8167fba11`
/// (speed factor alone); `283d9d1e126bfed44003d412e2e93b65652e56929038ddb549d56e30db7a1e2d`
/// (derived keys alone); `8723491ad1cd242eb2c49a7ebdc6e72fe0d7bf04c6fa569098f7bc86a20effd1`
/// (both, 17 536 bytes, 39 rows, until the I13 flip);
/// `d765602075af61f158b360063e38595dfc967138fc4b83d8a3dbf499e75fc42b`
/// (the I13 flip, 19 396 bytes, 70 rows, until CEN-J27);
/// `4d44488217508fac2d48422da0312ef31fdbe958935d0903832e05edb3fcb0a4`
/// (CEN-J27, 18 856 bytes, 61 rows, until `SO-D11`);
/// `ec2d0b760803781c389d97d7e019933ca84e5b7e01c3f067e5c8510fd797f001`
/// (`SO-D11`, 18 836 bytes, 60 rows, until the receipt key);
/// `937f578b349f5815e27b2a6f8228a7338478b39b1ecd7556122a4b732dcafb2f`
/// (the receipt key, 26 184 bytes, 60 rows, until `NI-R7` / `NI-R10`);
/// `ae8dc7a86f9a1a1597dd7805221da8ebb9dc36de3c4364b2388036de9db81a71`
/// (`NI-R7` / `NI-R10`, 26 184 bytes, 60 rows, until the salt
/// `name_id ‖ shekyl-master-derive-v3`, 2026-11-04: again only the persona
/// keys and ids moved, with the same size and row counts, and every
/// family's section still equal to its own derivation above);
/// `2a73b959226a3ad761c596d21355b090e4ad39ab7d5cdc6c00657d6da181f5c8`
/// (the salt, 26 184 bytes, 60 rows, until the switch's C7). Re-pinned
/// 2026-11-11 at the switch's C7, the last step of the bench's epoch shift
/// (Rick's bench ruling, option 1): the serve-credit input and its
/// `archival_serve_credit` family are deleted, so the twenty-two padding
/// credits go — 22 × 60 = 1 320 bytes — with the family's eight-byte row
/// count; the chain now starts from the captured shard fill and the joins
/// land in epoch [`JOIN_EPOCH`], so the slashing tip is one epoch later
/// and holds one more budget row and one more Σwork row, 2 × 20 = 40
/// bytes. 26 184 − 1 320 − 8 + 40 = 24 896, the whole delta; 60 − 22 + 2
/// = 40 rows. The slash families are spelled and asserted above.
const SLASHED_SNAPSHOT_BODY_KECCAK: &str =
    "88fdad5b8f041428de75c0583f9a3e85f4de2f3c11001c4472c618ea155626c8";

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
    assert_eq!(at, body.len(), "the families are the whole body");
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
}

#[test]
#[ignore = "B9: the §3.1 measurement; run with --release --ignored --nocapture"]
fn slash_scan_bench() {
    let chain = SlashedChain::build("slash-scan-bench", personas());
    chain.assert_slashed();

    // ---- the figures. The ordinary connects are the empty blocks between
    // the first deadline and the second: the shard has closed, nothing
    // settles, and no block in the range lists a body.
    let m = chain.m;
    let schedule = RULES.settlement_schedule();
    let ordinary_from = usize::try_from(chain.first_deadline + 1).expect("fits");
    let ordinary_to = usize::try_from(schedule.slash_deadline_height(shifted(1))).expect("fits");
    let ordinary = mean(&chain.timings[ordinary_from..ordinary_to]);
    eprintln!(
        "slash_scan_bench: {} personas, {} blocks built in {:?} (M = {m}, N = {FAILURE_WINDOW_N}); shard 0 closed at {}",
        chain.personas,
        chain.slashing_height + 1,
        chain.built,
        chain.shard_closed
    );
    eprintln!(
        "  ordinary connect (mean of heights {}..{}): judge {:?}, connect {:?}",
        ordinary_from, ordinary_to, ordinary.judge, ordinary.connect
    );
    for e in shifted(0)..=m {
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
}

#[path = "settlement_slash_tests.rs"]
mod settlement_slash_tests;

#[path = "drawable_walk_tests.rs"]
mod drawable_walk_tests;
