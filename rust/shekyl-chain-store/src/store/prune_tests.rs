// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! S-PRUNE: the boundary batch is named by the epoch, discards whole shards,
//! retires undo rows, and is idempotent across a boundary reorg; the pop
//! floor it leaves is a refusal, not a fault.
//!
//! Shards are cut by archival length (`SHT-Q2`): `W` is a production
//! constant, three million bytes, so a shard closes only after three
//! million bytes of prunable and `pqc_auths` segments. Every archival byte
//! here is a **real spend**: the chains start from the captured shard-fill
//! chain (`store/shard_fill.rs`, Rick's shard-fill ruling, 2026-11-11),
//! 161 blocks of one-input spends whose bytes every landed rule verifies,
//! closing shard 0 at height 131, shard 1 at 147 and shard 2 at 160. A
//! test connects the prefix it needs ([`Builder::captured`]) and extends it
//! with empty blocks, or with spends it builds. *Records-was:* until the
//! switch's C7 the bodies were serve credits whose pruned pass records
//! were padded to the lengths a table asked for; the serve-credit input is
//! deleted, and the exact-length properties those tables pinned (a
//! transaction starting at `k·W`, a straddle) are tests of `shard_of` with
//! any lengths (`shekyl-types`).
//!
//! The chains run under a 100-block epoch with a 50-block undo retention,
//! or a 10-block epoch with a 3-block retention (`Horizons::new`, the
//! regtest knob — the production pair would need ten thousand blocks per
//! boundary). The expected partition is computed by [`Model`], a separate
//! derivation from the lengths the store was handed, measured off the
//! bodies.
//!
//! The last section is the slash log's retirement (`SLK-Q1`,
//! `DRS_E4_SLASH_LOG_ROUND.md`): a `10 / 5` pair whose window
//! ([`WINDOW`], derived from [`SlashLogFloor::window`]) a chain of empty
//! blocks crosses, rows planted on both sides of the first floor, the read
//! that asserts the floor (SI-26), a pop across the boundary, a store
//! whose undo retention is deeper than the cap (`SLK-2`), and a session
//! that stubs `SlashLog` and therefore deletes none (`ARW-9`).

// A whole-file test module: the parent gates it with `#[cfg(test)]`, and
// this self-declaration is what the debug-macro lint keys on — the
// `#[ignore]`d recapture check prints its measurement (spends, close
// heights, wall time) for the nightly lane to read, which is its job, not
// a debug leftover.
#![cfg(test)]

use redb::ReadableTable;
use shekyl_chain_rules::{
    BlockDrawsFloor, Candidate, CappedEpoch, EpochFloor, ReleaseJournalFloor, RuleSet,
    SlashLogFloor,
};
use shekyl_types::{ArchivalLength, BlockCount, BlockHash, BlockHeight, ShardId, SHARD_LENGTH};
use shekyl_wire::Transaction;

use super::archival_read_tests::{persona, plant, plant_slash, record, slash_entry};
use super::connect_fixtures::{
    candidate, candidate_over, judge_under, root_going_into, Grown, Listed,
};
use super::shard_fill::{self, blocks_closing, shard_fill, store_with_prefix};
use super::store_tests::{tmp, TestErr};
use super::*;
use crate::codec::{
    Canonical, PropertyCell, PropertyCellBytes, Raw, SettlementEpochBlocks, UndoLogFloorCell,
};
use crate::ids::{SlashLogTuple, TxStorageId};
use crate::schema::{ARCHIVAL_SLASH_LOG, BLOCK_INFO, PROPERTIES, TXS_ARCHIVAL_LEN, UNDO_LOG};

const SEB: u64 = 100;
const RETENTION: u64 = 50;
/// The levered rule set this schedule runs: the genesis rules under a
/// 100-block epoch with a reorg cap that fits the retention (SCW-7) — a
/// regtest wanting a 50-block retention gets a rule set whose cap is at
/// most 50, not a store field the validator defers to (PR #861 review),
/// and one whose epoch is the store's, or `connect` refuses it (SCW-2,
/// `ARW-15`). The captured chain is built under the same pair
/// (`shard_fill::CAPTURE_RULES`).
const RULES: RuleSet = RuleSet::GENESIS.with_levers(None, pair(SEB, RETENTION));

/// A `(SEB, cap)` pair at compile time; a bad one is a compile error.
const fn pair(seb: u64, cap: u64) -> CappedEpoch {
    let Some(epoch) = SettlementEpochBlocks::new(seb) else {
        panic!("a zero epoch");
    };
    match CappedEpoch::new(epoch, BlockCount::from_raw(cap)) {
        Ok(pair) => pair,
        Err(_) => panic!("the cap is not inside the epoch"),
    }
}

fn horizons() -> Horizons {
    Horizons::new(
        RULES.settlement_schedule().blocks(),
        BlockCount::from_raw(RETENTION),
        RULES.reorg_cap(),
    )
    .expect("cap ≤ retention < epoch")
}

/// The fee a spend a test builds pays. Not a consensus figure.
const FEE: u64 = 1_000;

/// A candidate for `height` on the committed `store`: its header carries
/// the root the store recorded going into `height` (CEN-B5; the derived
/// root since DRS-E3, so no function of the height can supply it).
fn candidate_on(
    store: &ChainStore,
    height: u64,
    previous: BlockHash,
    listed: Vec<Transaction>,
) -> Candidate {
    candidate_over(root_going_into(store, height), height, previous, listed)
}

/// The captured chain's prefix through the block that closes shard `k`,
/// as a block count: shard 0 closes at height 131, so 132.
fn closing(k: u64) -> usize {
    blocks_closing(shard_fill(), k)
}

/// The height of the block that closes shard `k` in the captured chain.
fn close_height(k: u64) -> u64 {
    u64::try_from(closing(k)).expect("small") - 1
}

/// A chain under construction: the blocks so far ([`Grown`], which builds
/// a spend over the chain as it stands), and the listed transactions
/// handed each height.
struct Builder {
    grown: Grown,
    listed: Vec<Vec<Transaction>>,
    /// The archival length of each listed transaction, per height, read
    /// off the body: the model's input.
    lens: Vec<Vec<u64>>,
    /// The rule set every block is judged under and handed to `connect`.
    rules: RuleSet,
}

impl Builder {
    fn new() -> Self {
        Self::under(RULES)
    }

    fn under(rules: RuleSet) -> Self {
        Self {
            grown: Grown::new(),
            listed: Vec::new(),
            lens: Vec::new(),
            rules,
        }
    }

    /// A store at `path` under `rules` and `horizons` holding the captured
    /// chain's first `blocks` blocks, and the builder over it
    /// ([`store_with_prefix`]: the capture is verified once per schedule per
    /// process, and each test copies the store it starts from). `schedule`
    /// names the pair.
    fn captured(
        path: impl AsRef<std::path::Path>,
        schedule: &'static str,
        rules: RuleSet,
        horizons: Horizons,
        blocks: usize,
    ) -> (ChainStore, Self) {
        let (store, grown) = store_with_prefix(path, schedule, rules, horizons, blocks);
        let chain = shard_fill();
        let listed: Vec<Vec<Transaction>> = chain.blocks[..blocks]
            .iter()
            .map(|captured| captured.listed.clone())
            .collect();
        let lens = chain.archival_lengths()[..blocks].to_vec();
        (
            store,
            Self {
                grown,
                listed,
                lens,
                rules,
            },
        )
    }

    /// Each connected block's hash — the priced block's identity.
    fn hashes(&self) -> &[BlockHash] {
        &self.grown.hashes
    }

    /// Forget the top `n` heights after popping them from the store: the
    /// chain record pops with them ([`Grown::pop`]).
    fn forget(&mut self, n: usize) {
        for _ in 0..n {
            self.grown.pop();
            self.listed.pop();
            self.lens.pop();
        }
    }

    /// The model of the chain as built.
    fn model(&self) -> Model {
        Model {
            lens: self.lens.clone(),
        }
    }

    /// Connect heights `from..=to` in one batch, handing `listed(h)` at each;
    /// returns each connect's outcome. Every entry is **realised** on the
    /// chain as built ([`Grown::realise`]: a spend is proved over the tree
    /// as it stands), so a caller lists entries and reads the bodies back
    /// through [`Self::listed`].
    fn connect(
        &mut self,
        store: &ChainStore,
        from: u64,
        to: u64,
        listed: impl Fn(u64) -> Vec<Listed>,
    ) -> Vec<Connected> {
        let out: Result<Vec<Connected>, TestErr> = store.write(|batch| {
            let view = batch.chain_view();
            let mut out = Vec::new();
            for h in from..=to {
                assert_eq!(
                    self.grown.height().to_raw(),
                    h,
                    "the chain connects in height order"
                );
                let txs = self.grown.realise(&listed(h));
                // The identity is the priced block's (`judge_under`).
                let judged = self.grown.judge_listing(&view, &self.rules, &txs)?;
                self.record(txs);
                out.push(batch.connect(judged, self.rules)?);
            }
            Ok(out)
        });
        out.expect("chain connects")
    }

    /// Connect the next height listing `txs` as given: bodies already
    /// built, such as captured spends.
    fn connect_bodies(&mut self, store: &ChainStore, txs: Vec<Transaction>) -> Connected {
        let out: Result<Connected, TestErr> = store.write(|batch| {
            let view = batch.chain_view();
            let judged = self.grown.judge_listing(&view, &self.rules, &txs)?;
            self.record(txs.clone());
            Ok(batch.connect(judged, self.rules)?)
        });
        out.expect("the block connects")
    }

    /// Connect the captured chain's blocks from the next height through
    /// the first `blocks`.
    fn connect_captured(&mut self, store: &ChainStore, blocks: usize) -> Vec<Connected> {
        let chain = shard_fill();
        let from = self.listed.len();
        chain.blocks[from..blocks]
            .iter()
            .map(|captured| self.connect_bodies(store, captured.listed.clone()))
            .collect()
    }

    /// Record a judged block's bodies and their measured lengths.
    fn record(&mut self, txs: Vec<Transaction>) {
        self.lens
            .push(txs.iter().map(|tx| tx.archival_len().to_raw()).collect());
        self.listed.push(txs);
    }
}

/// `SHT-Q2` computed the slow way, from the lengths measured off the bodies:
/// every transaction's offset in id order (coinbase first at each height,
/// length `0`), its shard `⌊offset / W⌋`, each shard's close height (the
/// first height whose running total reaches `(k+1)·W`), and the calendar's
/// discard rule per shard — never `⌊C/W⌋` over two samples, which is the
/// store's algebra.
struct Model {
    lens: Vec<Vec<u64>>,
}

impl Model {
    const W: u64 = SHARD_LENGTH.to_raw();

    /// `(height, offset, len)` for every storage id, in id order.
    fn txs(&self) -> Vec<(u64, u64, u64)> {
        let mut out = Vec::new();
        let mut at = 0;
        for (h, listed) in self.lens.iter().enumerate() {
            let h = u64::try_from(h).expect("fits");
            out.push((h, at, 0));
            for &len in listed {
                assert_ne!(len, u64::MAX, "height {h} was listed bare, not sized");
                out.push((h, at, len));
                at += len;
            }
        }
        out
    }

    /// The running archival total through block `h`.
    fn cumulative_through(&self, h: u64) -> u64 {
        self.lens[..=usize::try_from(h).expect("small")]
            .iter()
            .flatten()
            .sum()
    }

    /// The listed bodies through block `h` (coinbases not counted).
    fn listed_through(&self, h: u64) -> u64 {
        self.lens[..=usize::try_from(h).expect("small")]
            .iter()
            .map(|listed| u64::try_from(listed.len()).expect("small"))
            .sum()
    }

    /// The shard each storage id belongs to.
    fn shard_of_id(&self) -> Vec<u64> {
        self.txs().iter().map(|&(_, at, _)| at / Self::W).collect()
    }

    /// Shard `k`'s close height, if the chain has reached `(k+1)·W`.
    fn close_height(&self, k: u64) -> Option<u64> {
        let mut through = 0;
        for (h, listed) in self.lens.iter().enumerate() {
            through += listed.iter().sum::<u64>();
            if through >= (k + 1) * Self::W {
                return Some(u64::try_from(h).expect("fits"));
            }
        }
        None
    }

    /// The shards a boundary at epoch `e` discards under schedule `seb`:
    /// `close_epoch(k) + 2 ≤ e ≤ close_epoch(k) + 3`.
    fn discards_at(&self, seb: u64, e: u64) -> Vec<u64> {
        (0..)
            .map_while(|k| self.close_height(k).map(|c| (k, c / seb)))
            .filter(|&(_, ce)| ce + 2 <= e && e <= ce + 3)
            .map(|(k, _)| k)
            .collect()
    }

    /// Whether each storage id's bodies are discarded at `tip`: its shard
    /// was in some boundary's discard set at or below `tip`.
    fn discarded(&self, seb: u64, tip: u64) -> Vec<bool> {
        let gone: Vec<u64> = (2..=tip / seb)
            .flat_map(|e| self.discards_at(seb, e))
            .collect();
        self.shard_of_id()
            .into_iter()
            .map(|k| gone.contains(&k))
            .collect()
    }

    /// `h_scarce` at `tip`: the close height of the last shard with
    /// `close_epoch + 2 ≤ E`.
    fn h_scarce(&self, seb: u64, tip: u64) -> Option<u64> {
        let e = tip / seb;
        (0..)
            .map_while(|k| self.close_height(k))
            .filter(|c| c / seb + 2 <= e)
            .last()
    }

    /// The storage ids of shard `k`.
    fn ids_of(&self, k: u64) -> core::ops::Range<u64> {
        let shards = self.shard_of_id();
        let first = shards.iter().position(|&s| s >= k).unwrap_or(shards.len());
        let end = shards.iter().position(|&s| s > k).unwrap_or(shards.len());
        u64::try_from(first).expect("fits")..u64::try_from(end).expect("fits")
    }
}

/// Every storage id's body state on `store`: `true` retained, `false`
/// discarded.
fn body_states(store: &ChainStore) -> Vec<bool> {
    let count = store.begin_read().expect("read").tx_count().expect("count");
    (0..count)
        .map(|id| prunable_state(store, id).expect("recorded"))
        .collect()
}

fn undo_floor_cell(store: &ChainStore) -> Option<u64> {
    store
        .begin_read()
        .expect("read")
        .get_property::<UndoLogFloorCell>()
        .expect("cell")
        .map(BlockHeight::to_raw)
}

fn undo_rows(store: &ChainStore) -> Vec<u64> {
    let snap = store.begin_read().expect("read");
    let table = snap.open_table(UNDO_LOG).expect("table");
    table
        .range::<u64>(..)
        .expect("range")
        .map(|item| item.expect("row").0.value())
        .collect()
}

fn prunable_state(store: &ChainStore, id: u64) -> Option<bool> {
    match store
        .begin_read()
        .expect("read")
        .tx_archival_good(TxStorageId::from_raw(id))
        .expect("read")
    {
        AtIndex::Recorded(ArchivalGood::Retained { .. }) => Some(true),
        AtIndex::Recorded(ArchivalGood::Discarded) => Some(false),
        AtIndex::BeyondCount => None,
    }
}

/// The archival good of the recorded transaction `hash` — one read, so a
/// prune that took the prunable region and not the `pqc_auths` region (or
/// the reverse) is SI-42 here, not a `Discarded` that hides the half.
fn good_of(snap: &ReadSnapshot<'_>, record: &TxRecord) -> ArchivalGood {
    match snap.tx_archival_good(record.location.id).expect("read") {
        AtIndex::Recorded(good) => good,
        AtIndex::BeyondCount => panic!("a recorded id is within the count"),
    }
}

/// `tx_carries_archival_good` at `id` — the `SHT-Q1` domain answer from the
/// **stored rows**, `None` beyond the count.
fn good_state(store: &ChainStore, id: u64) -> Option<bool> {
    match store
        .begin_read()
        .expect("read")
        .tx_carries_archival_good(TxStorageId::from_raw(id))
        .expect("read")
    {
        AtIndex::Recorded(good) => Some(good),
        AtIndex::BeyondCount => None,
    }
}

fn tip(store: &ChainStore) -> u64 {
    store
        .begin_read()
        .expect("read")
        .tip()
        .expect("tip")
        .recorded
        .expect("a chain")
        .height
        .to_raw()
}

/// The chain every 100-block test here starts from: the captured chain
/// through the block that closes shard 0 ([`close_height`]`(0)`, 131, in
/// epoch 1), then empty blocks to 400. Shard 0 closes in epoch 1, so the
/// epoch-2 boundary at 200 names nothing (`close_epoch + 2 ≤ e` fails) and
/// the epoch-3 and epoch-4 boundaries at 300 and 400 name shard 0. Shard 1
/// is open throughout: the closing block's last spend runs past `W`, and
/// nothing after it is listed. Returns the boundaries at 300 and 400.
fn chain_to_400(path: impl AsRef<std::path::Path>) -> (ChainStore, Builder, Connected, Connected) {
    let (store, mut b) = Builder::captured(path, "seb100", RULES, horizons(), closing(0));
    assert_eq!(
        RULES.settlement_schedule().epoch_at_height(close_height(0)),
        1,
        "shard 0 closes in epoch 1"
    );
    let first = close_height(0) + 1;
    let to_299 = b.connect(&store, first, 299, |_| Vec::new());
    assert_eq!(
        to_299[usize::try_from(200 - first).expect("small")]
            .pruned
            .expect("a boundary")
            .shards(),
        0..0,
        "epoch 2's boundary discards nothing: shard 0 closed in epoch 1"
    );
    let at_300 = b.connect(&store, 300, 300, |_| Vec::new()).remove(0);
    b.connect(&store, 301, 399, |_| Vec::new());
    let at_400 = b.connect(&store, 400, 400, |_| Vec::new()).remove(0);
    (store, b, at_300, at_400)
}

/// The listed body storage id `id` names, `None` for a coinbase: the
/// model's `(height, offset)` order is the store's id order.
fn body_of_id(b: &Builder, id: u64) -> Option<&Transaction> {
    let mut next = 0u64;
    for (listed, _) in b.listed.iter().zip(&b.lens) {
        // The coinbase first, then the listed bodies.
        if next == id {
            return None;
        }
        next += 1;
        for tx in listed {
            if next == id {
                return Some(tx);
            }
            next += 1;
        }
    }
    panic!("id {id} is past the chain")
}

#[test]
fn the_boundary_batch_discards_closed_shards_and_retires_undo_rows() {
    let path = tmp("prune-boundary");
    let (store, b, at_300, at_400) = chain_to_400(&path);
    let model = b.model();

    // Epoch 3's boundary: shard 0 closed in `[100, 200)`, so `D(3)` is
    // shard 0; the undo floor rises to 300 − 50.
    let pruned_300 = at_300.pruned.expect("a boundary");
    assert_eq!(pruned_300.shards(), 0..1, "D(3) is shard 0");
    assert_eq!(pruned_300.undo_floor, BlockHeight::from_raw(250));

    // Epoch 4's boundary: `[100, 300)` names shard 0 again — already empty —
    // and shard 1 has not closed.
    let pruned_400 = at_400.pruned.expect("a boundary");
    assert_eq!(pruned_400.shards(), 0..1, "D(4) is shard 0");
    assert_eq!(pruned_400.undo_floor, BlockHeight::from_raw(350));

    // Shard 0's bodies are gone — every transaction starting below `W`, the
    // coinbases among them — and shard 1's are held; the hash rows stand (a
    // read answers *discarded*, never a fault).
    let shard_0 = model.ids_of(0);
    let shard_1 = model.ids_of(1);
    assert_eq!(shard_0.start, 0);
    for id in [shard_0.start, shard_0.start + 1, shard_0.end - 1] {
        assert_eq!(prunable_state(&store, id), Some(false), "id {id} discarded");
    }
    for id in [shard_1.start, shard_1.end - 1] {
        assert_eq!(prunable_state(&store, id), Some(true), "id {id} retained");
    }
    assert_eq!(body_states(&store), not(&model.discarded(SEB, 400)));
    {
        let snap = store.begin_read().expect("read");
        // The chain's first spend: 4-part, so it has the pqc region the
        // prune discards by shard.
        let first_spend = b
            .listed
            .iter()
            .flatten()
            .next()
            .expect("the captured chain lists spends");
        let early = snap
            .tx_record(&first_spend.hash())
            .expect("read")
            .expect("recorded");
        assert_eq!(
            good_of(&snap, &early),
            ArchivalGood::Discarded,
            "shard 0's pqc region went with its prunable one"
        );
        assert!(early.pqc_auth_hash.is_some(), "the hash row is permanent");
        // Shard 1's first listed body is held whole: both regions.
        let opener = (shard_1.start..shard_1.end)
            .find_map(|id| body_of_id(&b, id))
            .expect("shard 1 holds a listed body");
        let late = snap
            .tx_record(&opener.hash())
            .expect("read")
            .expect("recorded");
        assert!(
            matches!(
                good_of(&snap, &late),
                ArchivalGood::Retained {
                    pqc_auths: Some(_),
                    ..
                }
            ),
            "shard 1's spend is held with its pqc region"
        );
        assert_eq!(late.archival_len, opener.archival_len(), "as measured");
    }

    // The undo journal keeps exactly `[floor, tip]`.
    assert_eq!(undo_floor_cell(&store), Some(350));
    let rows = undo_rows(&store);
    assert_eq!(rows.first(), Some(&350));
    assert_eq!(rows.last(), Some(&400));
    assert_eq!(rows.len(), 51);
    assert!(store.connect_state().is_live());
}

/// Retained-ness from the model's discarded-ness.
fn not(discarded: &[bool]) -> Vec<bool> {
    discarded.iter().map(|d| !d).collect()
}

/// **The recapture check** (Rick's shard-fill ruling, 2026-11-11): build
/// the shard-fill chain afresh with the production prover and hold each
/// block's archival lengths to the checked-in chain's
/// ([`shard_fill::shard_fill`]). Proving draws fresh randomness, so the
/// bytes move between builds and the lengths do not; lengths that moved
/// mean the builder or a rule changed what the chain is, and the vector is
/// recaptured under a decision (`capture_the_shard_fill_chain`), never in
/// place. Then the boundary test above on the fresh chain's bytes: every
/// shard it closed in epoch 1 is discarded at the epoch-3 boundary and
/// again, already empty, at epoch 4.
///
/// `#[ignore]`d: proving 844 spends is minutes — 461 s in release on the
/// dev box. **The lane that runs it is `.github/workflows/nightly.yml`,
/// job `store-ignored`, on the 03:00 UTC daily schedule**, which lists the
/// crate's ignored set and refuses to pass unless this test's name is in it
/// (rule 47).
#[test]
#[ignore = "builds the shard-fill chain afresh (844 real spends; ~8 min release) and holds its lengths to the checked-in chain; the nightly lane (nightly.yml `store-ignored`, 03:00 UTC daily) runs it"]
fn the_boundary_batch_discards_closed_shards_on_real_spends() {
    use std::time::Instant;

    let path = tmp("prune-boundary-real");
    let store = shard_fill::capture_store(&path);
    let started = Instant::now();
    let (grown, listings) = shard_fill::build_capture(&store);
    let built = started.elapsed();
    let lens: Vec<Vec<u64>> = listings
        .iter()
        .map(|listed| listed.iter().map(|tx| tx.archival_len().to_raw()).collect())
        .collect();
    let checked_in = shard_fill().archival_lengths();
    let first_moved = lens
        .iter()
        .zip(&checked_in)
        .position(|(fresh, kept)| fresh != kept);
    assert_eq!(
        (lens.len(), first_moved),
        (checked_in.len(), None),
        "a fresh build's archival lengths are not the checked-in chain's: if the builder \
         or a rule moved them on purpose, recapture under a decision \
         (capture_the_shard_fill_chain); otherwise the chain drifted"
    );

    let mut b = Builder {
        grown,
        listed: listings,
        lens,
        rules: RULES,
    };
    let model = b.model();
    let tip = u64::try_from(b.listed.len()).expect("small") - 1;
    let shards: Vec<u64> = (0..shard_fill::SHARDS)
        .map(|k| model.close_height(k).expect("closed"))
        .collect();
    eprintln!(
        "prune-boundary-real: {} spends built in {built:?}; shards close at {shards:?}; tip {tip}",
        b.listed.iter().map(Vec::len).sum::<usize>()
    );
    assert!(
        shards.iter().all(|c| c / SEB == 1),
        "every shard closes in epoch 1: {shards:?}"
    );
    b.connect(&store, tip + 1, 299, |_| Vec::new());
    let at_300 = b.connect(&store, 300, 300, |_| Vec::new()).remove(0);
    b.connect(&store, 301, 399, |_| Vec::new());
    let at_400 = b.connect(&store, 400, 400, |_| Vec::new()).remove(0);
    let all = 0..shard_fill::SHARDS;
    assert_eq!(at_300.pruned.expect("a boundary").shards(), all.clone());
    assert_eq!(at_400.pruned.expect("a boundary").shards(), all);
    assert_eq!(body_states(&store), not(&b.model().discarded(SEB, 400)));
    assert_eq!(undo_floor_cell(&store), Some(350));
    let rows = undo_rows(&store);
    assert_eq!((rows.first(), rows.last()), (Some(&350), Some(&400)));
    assert!(store.connect_state().is_live());
}

#[test]
fn epochs_zero_and_one_run_no_batch() {
    let path = tmp("prune-early");
    let store =
        ChainStore::with_horizons(&path, ApplyPolicy::default(), horizons()).expect("create");
    let mut b = Builder::new();
    let out = b.connect(&store, 0, 150, |_| Vec::new());
    assert!(
        out.iter().all(|c| c.pruned.is_none()),
        "no boundary before epoch 2"
    );
    assert_eq!(
        undo_floor_cell(&store),
        None,
        "nothing retired: the floor is genesis"
    );
    assert_eq!(undo_rows(&store).len(), 151);
}

#[test]
fn a_pop_below_the_undo_floor_is_a_refusal_not_si6() {
    let path = tmp("prune-pop-floor");
    let (store, _b, _, _) = chain_to_400(&path);
    // 400 down to 350 have rows: fifty-one pops land.
    for expected in (350..=400).rev() {
        let out: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
        assert_eq!(out.map(|p| p.height.to_raw()), Ok(expected));
    }
    assert_eq!(tip(&store), 349);
    let out: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
    assert_eq!(
        out,
        Err(TestErr::Store(
            StoreError::from(StoreCannot::PopBelowFloor {
                tip: 349,
                floor: 350
            })
            .to_string()
        )),
        "below the retained journal is a capability limit, loud"
    );
    assert!(store.connect_state().is_live(), "a refusal is not a halt");
}

/// §4, §8: a reorg across the boundary block reconnects some block at
/// `E·SEB`, and the hook fires again. The ranges are already empty and the
/// floor is monotone, so the store is the same store.
#[test]
fn the_hook_is_idempotent_across_a_boundary_reorg() {
    let path = tmp("prune-idempotent");
    let (store, mut b, _, _) = chain_to_400(&path);
    let before = (undo_floor_cell(&store), undo_rows(&store));
    let shard_1 = b.model().ids_of(1);

    let out: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
    assert_eq!(out.map(|p| p.height.to_raw()), Ok(400));
    b.forget(1);
    // A different block at 400: a real spend of a coinbase the captured
    // chain leaves unspent makes its hash differ.
    let again = b
        .connect(&store, 400, 400, |_| vec![Listed::Spend { fee: FEE }])
        .remove(0);
    let pruned = again.pruned.expect("the boundary fires again");
    assert_eq!(pruned.shards(), 0..1, "the same D(4), already empty");
    assert_eq!(pruned.undo_floor, BlockHeight::from_raw(350), "monotone");
    assert_eq!((undo_floor_cell(&store), undo_rows(&store)), before);
    assert_eq!(prunable_state(&store, 0), Some(false));
    assert_eq!(prunable_state(&store, shard_1.start), Some(true));
}

/// `h_scarce` (§4): the `close_height` of the last shard the calendar has
/// discarded at `tip` — `PDM-Q5`'s band-2 edge, chain-named, no presence
/// read. `None` in epochs 0–1 and before any shard has closed.
#[test]
fn h_scarce_is_the_last_discarded_shards_close_height() {
    let path = tmp("prune-h-scarce");
    let (store, b, _, _) = chain_to_400(&path);
    type Edges = (Option<u64>, Option<u64>, Option<u64>);
    let out: Result<Edges, TestErr> = store.write(|batch| {
        Ok((
            batch.h_scarce(250)?,
            batch.h_scarce(350)?,
            batch.h_scarce(400)?,
        ))
    });
    let (e1, e2, e3) = out.expect("reads");
    let closed = close_height(0);
    assert_eq!(
        store.begin_read().expect("read").h_scarce().expect("read"),
        Some(BlockHeight::from_raw(closed)),
        "the snapshot's read at the recorded tip agrees"
    );
    // Shard 0 closed in epoch 1, so the first epoch that can have
    // discarded it is 3 (`close_epoch + 2 ≤ E`).
    assert_eq!(e1, None, "epoch 2: nothing can have discarded");
    assert_eq!(e2, Some(closed), "epoch 3: shard 0, closed at {closed}");
    assert_eq!(e3, Some(closed), "epoch 4: still shard 0, shard 1 is open");
    let model = b.model();
    assert_eq!(
        (e1, e2, e3),
        (
            model.h_scarce(SEB, 250),
            model.h_scarce(SEB, 350),
            model.h_scarce(SEB, 400)
        )
    );
}

/// The levered set for the ten-block schedule the `SHT-Q2` boundary and
/// SI-13 / SI-24 tests run.
const SHORT: RuleSet = RuleSet::GENESIS.with_levers(None, pair(SHORT_SEB, 3));

/// The ten-block schedule's epoch.
const SHORT_SEB: u64 = 10;

fn short_horizons() -> Horizons {
    Horizons::new(
        SettlementEpochBlocks::new(SHORT_SEB).expect("non-zero"),
        BlockCount::from_raw(3),
        SHORT.reorg_cap(),
    )
    .expect("cap ≤ retention < epoch")
}

/// The captured chain's first `blocks` blocks under the ten-block
/// schedule. Its shards close at heights 131, 147 and 160, in epochs 13, 14
/// and 16, so the boundaries discard: `D(15)` at 150 shard 0, `D(16)` at
/// 160 shards 0 **and** 1 (two in one batch), `D(17)` at 170 shard 1, and
/// `D(18)` and `D(19)` shard 2 — read off the model, never spelled.
fn short_captured(path: impl AsRef<std::path::Path>, blocks: usize) -> (ChainStore, Builder) {
    Builder::captured(path, "short", SHORT, short_horizons(), blocks)
}

/// The first boundary under the ten-block schedule that discards: the one
/// at `close_epoch(0) + 2`.
fn first_discarding_boundary() -> u64 {
    (close_height(0) / SHORT_SEB + 2) * SHORT_SEB
}

/// Every stored length is the one measured off the body — the model's
/// input is the store's — and the cumulative cell is the running total at
/// each height. The coinbase carries no archival good and writes no row.
#[test]
fn the_store_records_each_length_and_the_running_total() {
    let path = tmp("prune-lengths");
    let (store, b) = short_captured(&path, closing(0));
    let model = b.model();
    {
        let snap = store.begin_read().expect("read");
        let rows = snap.open_table(TXS_ARCHIVAL_LEN).expect("table");
        for (id, &(_, _, len)) in model.txs().iter().enumerate() {
            let id = u64::try_from(id).expect("fits");
            let row = rows
                .get(id)
                .expect("get")
                .map(|g| g.value().decode().expect("decodes"));
            let expected = (len > 0).then(|| ArchivalLength::from_raw(len));
            assert_eq!(
                row, expected,
                "id {id}: present ⇔ > 0, and the length measured"
            );
        }
        let infos = snap.open_table(BLOCK_INFO).expect("table");
        let mut through = 0;
        for (h, listed) in model.lens.iter().enumerate() {
            through += listed.iter().sum::<u64>();
            let info: crate::codec::BlockInfo = infos
                .get(u64::try_from(h).expect("fits"))
                .expect("get")
                .expect("row")
                .value()
                .decode()
                .expect("decodes");
            assert_eq!(info.cumulative_archival_len.to_raw(), through, "height {h}");
        }
        assert!(
            through >= SHARD_LENGTH.to_raw(),
            "the prefix closes shard 0: {through}"
        );
    }
}

/// Shard 0 has closed by its close height and shard 1 is the open shard.
/// The fold is the indexed cell, not a scan from genesis.
#[test]
fn a_closed_shard_is_the_indexed_fold_and_the_next_is_open() {
    let path = tmp("shard-fold");
    let (store, b) = short_captured(&path, closing(0));
    let through = b.model().cumulative_through(close_height(0));
    let snap = store.begin_read().expect("read");
    match snap.shard_fold(ShardId::from_raw(0)).expect("shard 0") {
        ShardFold::Closed(rows) => {
            assert!(
                !rows.txs.is_empty(),
                "a closed shard names its transactions"
            );
            assert_eq!(rows.cum_before_first, ArchivalLength::ZERO);
            let sum: u64 = rows.txs.iter().map(|tx| tx.archival_len.to_raw()).sum();
            assert!(
                sum >= SHARD_LENGTH.to_raw(),
                "in-domain lengths close the shard, summed {sum}"
            );
            assert!(rows.last >= rows.first);
        }
        ShardFold::Open { .. } => panic!("shard 0 is closed through its close height"),
    }
    match snap.shard_fold(ShardId::from_raw(1)).expect("shard 1") {
        ShardFold::Open {
            open_shard,
            archival_through_tip,
        } => {
            assert_eq!(open_shard, ShardId::from_raw(1));
            assert_eq!(archival_through_tip, ArchivalLength::from_raw(through));
        }
        ShardFold::Closed(_) => panic!("shard 1 is still open"),
    }
    drop(snap);
}

/// A transaction straddling `W` belongs to the shard it **starts** in and
/// closes that shard; the next one opens shard 1. The straddle is the
/// captured chain's own: no spend's length divides `W`, so the block that
/// closes shard 0 lists a spend that starts below `W` and ends past it,
/// read off the measured lengths. The rule itself, with any lengths, is
/// `shard_of`'s test in `shekyl-types`.
#[test]
fn a_transaction_straddling_a_boundary_belongs_to_the_shard_it_starts_in() {
    let path = tmp("prune-straddle");
    let (store, mut b) = short_captured(&path, closing(0));
    let w = SHARD_LENGTH.to_raw();
    let txs = b.model().txs();
    let straddler = txs
        .iter()
        .position(|&(_, start, len)| start < w && start + len > w)
        .expect("a spend straddles W");
    let (height, start, len) = txs[straddler];
    assert_eq!(height, close_height(0), "it closes shard 0");
    let straddler = u64::try_from(straddler).expect("small");
    let boundary = first_discarding_boundary();
    b.connect(&store, close_height(0) + 1, boundary, |_| Vec::new());
    let model = b.model();
    assert_eq!(
        model.shard_of_id()[usize::try_from(straddler).expect("small")],
        0,
        "it starts at {start} and ends at {}: shard 0",
        start + len
    );
    assert_eq!(
        prunable_state(&store, straddler),
        Some(false),
        "discarded with shard 0"
    );
    assert_eq!(
        model.shard_of_id()[usize::try_from(straddler + 1).expect("small")],
        1,
        "the next transaction starts past W"
    );
    assert_eq!(
        prunable_state(&store, straddler + 1),
        Some(true),
        "shard 1's"
    );
    let out: Result<Option<u64>, TestErr> = store.write(|batch| Ok(batch.h_scarce(boundary)?));
    assert_eq!(
        out,
        Ok(Some(close_height(0))),
        "shard 0 closed at the straddler's height"
    );
    assert_eq!(
        body_states(&store),
        not(&model.discarded(SHORT_SEB, boundary))
    );
}

/// Scope 4 (c): two shards closing inside one boundary's window are one
/// batch — `D(16)` is shards 0 and 1, contiguous ids — and every boundary
/// from the first that discards to the last that names shard 2 matches the
/// model: the discard set, every id's body, and `h_scarce`. The chain
/// starts one block before the first discarding boundary and connects the
/// rest of the capture, then empty blocks.
#[test]
fn consecutive_boundaries_and_every_batch_match_the_model() {
    let path = tmp("prune-consecutive");
    let first = first_discarding_boundary();
    let (store, mut b) = short_captured(&path, usize::try_from(first).expect("small"));
    let captured = shard_fill().blocks.len();
    let last = (close_height(2) / SHORT_SEB + 3) * SHORT_SEB;
    for boundary in (first..=last).step_by(usize::try_from(SHORT_SEB).expect("small")) {
        let mut pruned = None;
        for h in u64::try_from(b.listed.len()).expect("small")..=boundary {
            let connected = if usize::try_from(h).expect("small") < captured {
                b.connect_captured(&store, usize::try_from(h + 1).expect("small"))
                    .remove(0)
            } else {
                b.connect(&store, h, h, |_| Vec::new()).remove(0)
            };
            pruned = connected.pruned;
        }
        let pruned = pruned.expect("a boundary");
        let model = b.model();
        let expected = model.discards_at(SHORT_SEB, boundary / SHORT_SEB);
        let expected = expected
            .first()
            .map_or(pruned.shard_start..pruned.shard_start, |&k| {
                k..expected.last().expect("non-empty") + 1
            });
        assert_eq!(pruned.shards(), expected, "D at {boundary}");
        assert_eq!(
            body_states(&store),
            not(&model.discarded(SHORT_SEB, boundary)),
            "bodies at {boundary}"
        );
        let out: Result<Option<u64>, TestErr> = store.write(|batch| Ok(batch.h_scarce(boundary)?));
        assert_eq!(
            out,
            Ok(model.h_scarce(SHORT_SEB, boundary)),
            "h_scarce at {boundary}"
        );
    }
    let model = b.model();
    let two_in_one = first / SHORT_SEB + 1;
    assert_eq!(
        model.discards_at(SHORT_SEB, two_in_one),
        vec![0, 1],
        "consecutive: shards 0 and 1 in the batch at {}",
        two_in_one * SHORT_SEB
    );
}

/// The captured block that closes shard 2, split in two: the spends that
/// keep the running total below `3·W`, and the rest. Listed at its height
/// and the next, the split closes shard 2 one block later with the same
/// spends: each references a block at least `REFERENCE_BLOCK_MIN_AGE`
/// below its own height either way.
fn closing_block_split(b: &Builder) -> (Vec<Transaction>, Vec<Transaction>) {
    let h = close_height(2);
    let before = b.model().cumulative_through(h - 1);
    let listed = &shard_fill().blocks[usize::try_from(h).expect("small")].listed;
    let mut total = before;
    let keep = listed
        .iter()
        .take_while(|tx| {
            total += tx.archival_len().to_raw();
            total < 3 * SHARD_LENGTH.to_raw()
        })
        .count();
    assert!(
        keep > 0 && keep < listed.len(),
        "the split leaves both halves"
    );
    (listed[..keep].to_vec(), listed[keep..].to_vec())
}

/// Scope 4 (d): a reorg that pops back across a shard boundary and connects
/// a different branch leaves the store exactly as a store that only ever
/// saw the new branch: same discard sets, same bodies, same `h_scarce`. The
/// popped heights' length rows and cumulative cells go with their blocks
/// (journaled inserts). The new branch lists the captured closing block's
/// spends over two blocks ([`closing_block_split`]), so shard 2 closes one
/// block later.
#[test]
fn a_reorg_back_across_a_shard_boundary_is_the_new_branchs_partition() {
    let close = close_height(2);
    let boundaries: Vec<u64> = (close / SHORT_SEB * SHORT_SEB..)
        .step_by(usize::try_from(SHORT_SEB).expect("small"))
        .skip_while(|&x| x < close)
        .take(4)
        .collect();
    let path = tmp("prune-reorg");
    let (store, mut b) = short_captured(&path, closing(2));
    b.connect(&store, close + 1, close + 2, |_| Vec::new());
    assert_eq!(b.model().close_height(2), Some(close));
    // Pop `close + 2`, `+ 1` and `close`: the running total drops back
    // below `3·W`.
    for expected in [close + 2, close + 1, close] {
        let out: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
        assert_eq!(out.map(|p| p.height.to_raw()), Ok(expected));
    }
    b.forget(3);
    assert_eq!(b.model().close_height(2), None, "shard 2 is open again");
    let (head, tail) = closing_block_split(&b);
    let branch = |b: &mut Builder, store: &ChainStore| -> Vec<Pruned> {
        let mut pruned = Vec::new();
        for connected in [
            b.connect_bodies(store, head.clone()),
            b.connect_bodies(store, tail.clone()),
        ] {
            pruned.extend(connected.pruned);
        }
        for &boundary in &boundaries {
            let from = u64::try_from(b.listed.len()).expect("small");
            if from <= boundary {
                let out = b.connect(store, from, boundary, |_| Vec::new());
                pruned.push(out.last().expect("connected").pruned.expect("a boundary"));
            }
        }
        pruned
    };
    let reorged = branch(&mut b, &store);
    let reorged_states = body_states(&store);
    let reorged_scarce = store.begin_read().expect("read").h_scarce().expect("read");

    let fresh_path = tmp("prune-reorg-fresh");
    let (fresh, mut f) = short_captured(&fresh_path, closing(2) - 1);
    let straight = branch(&mut f, &fresh);
    assert_eq!(b.hashes(), f.hashes(), "the same chain");
    assert_eq!(reorged, straight, "the same discard sets and floors");
    assert_eq!(reorged_states, body_states(&fresh), "the same bodies");
    assert_eq!(
        reorged_scarce,
        fresh.begin_read().expect("read").h_scarce().expect("read")
    );
    assert_eq!(f.model().close_height(2), Some(close + 1));
    let discarding = (close + 1) / SHORT_SEB + 2;
    assert_eq!(
        f.model().discards_at(SHORT_SEB, discarding),
        vec![2],
        "D({discarding}) is the new branch's shard 2"
    );
    assert_eq!(reorged_scarce, Some(BlockHeight::from_raw(close + 1)));
    let tip = u64::try_from(f.listed.len()).expect("small") - 1;
    assert_eq!(reorged_states, not(&f.model().discarded(SHORT_SEB, tip)));
}

/// Scope 4 (e): membership is the same question on a pruned store and an
/// unpruned one. Every shard's id range is read off the cumulative cell and
/// the length rows, which no prune deletes, so the answer before the
/// boundary that discards shard 1 and after it is one answer — and the
/// model's. Two shards: shard 1 is the one whose first id is not zero.
#[test]
fn pruned_and_unpruned_stores_place_every_shard_alike() {
    let path = tmp("prune-membership");
    let (store, mut b) = short_captured(&path, closing(1));
    let discards_1 = (close_height(1) / SHORT_SEB + 2) * SHORT_SEB;
    b.connect(&store, close_height(1) + 1, discards_1 - 1, |_| Vec::new());
    let ranges = |store: &ChainStore| -> Vec<core::ops::Range<u64>> {
        let snap = store.begin_read().expect("read");
        (0..2)
            .map(|k| snap.shard_storage_ids(k..k + 1).expect("read"))
            .collect()
    };
    let unpruned = ranges(&store);
    let shard_1 = unpruned[1].clone();
    assert_ne!(shard_1.start, 0, "shard 1 starts past the chain's first id");
    assert!(
        shard_1
            .clone()
            .all(|id| prunable_state(&store, id) == Some(true)),
        "shard 1 is held before {discards_1}"
    );
    b.connect(&store, discards_1, discards_1, |_| Vec::new());
    assert!(
        shard_1
            .clone()
            .all(|id| prunable_state(&store, id) == Some(false)),
        "and discarded at {discards_1}, or this test compares two unpruned stores"
    );
    assert_eq!(
        ranges(&store),
        unpruned,
        "the pruned store places every shard alike"
    );
    let model = b.model();
    assert_eq!(
        unpruned,
        (0..2).map(|k| model.ids_of(k)).collect::<Vec<_>>()
    );
}

/// The ten-block chain through the block that closes shard 0, then empty
/// blocks to `to`, with the store closed for a raw plant.
fn short_chain_to(path: impl AsRef<std::path::Path>, to: u64) -> Builder {
    let (store, mut b) = short_captured(path, closing(0));
    b.connect(&store, close_height(0) + 1, to, |_| Vec::new());
    b
}

/// Connect `height` on the reopened ten-block store with nothing listed.
fn connect_short(
    path: impl AsRef<std::path::Path>,
    b: &Builder,
    height: u64,
) -> (ChainStore, Result<Connected, TestErr>) {
    let path: &std::path::Path = path.as_ref();
    let store =
        ChainStore::with_horizons(path, ApplyPolicy::default(), short_horizons()).expect("open");
    let previous = b.hashes().last().copied().expect("parent");
    let cand = candidate_on(&store, height, previous, Vec::new());
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge_under(&view, cand, &SHORT)?, SHORT)?)
    });
    (store, out)
}

/// The first block the boundary's descent checks: block `hi − 1`, where
/// `hi = (E − 1)·SEB` is the top of the discard window.
fn descent_top(boundary: u64) -> u64 {
    boundary - SHORT_SEB - 1
}

/// A later `block_info` row whose listed total is below an earlier one's is
/// SI-13. The boundary's descent checks every block against its parent
/// before it passes it, from the window's top down to the crossing; a
/// decrease at the first block it checks must not commit the boundary with
/// `D(E)` skipped.
#[test]
fn a_decreasing_listed_total_refuses_the_boundary() {
    let path = tmp("prune-monotone");
    let boundary = first_discarding_boundary();
    let top = descent_top(boundary);
    let b = short_chain_to(&path, boundary - 1);
    let listed_before = b.model().listed_through(top - 1);
    assert!(listed_before >= 5, "a decrease of five is a decrease");
    plant_listed(&path, BlockHeight::from_raw(top), listed_before - 5);
    let (store, out) = connect_short(&path, &b, boundary);
    assert!(
        out.is_err(),
        "the boundary does not commit over a decreasing total"
    );
    assert_eq!(tip(&store), boundary - 1);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(boundary),
            row: StoreInvariant::FoldNotMonotone {
                cell: "block_info.cumulative_tx_count",
                height: top,
            },
        }
    );
}

/// The decrease the coinbase term can mask: the listed total one below its
/// parent's derives to the parent's storage-id count (the block's own
/// coinbase adds the one back) — an empty block, not an inverted one. SI-13
/// is a property of the listed fold and is checked on the raw samples
/// (Copilot, PR #861).
#[test]
fn a_decrease_smaller_than_the_coinbase_term_still_refuses_the_boundary() {
    let path = tmp("prune-monotone-masked");
    let boundary = first_discarding_boundary();
    let top = descent_top(boundary);
    let b = short_chain_to(&path, boundary - 1);
    let listed_before = b.model().listed_through(top - 1);
    plant_listed(&path, BlockHeight::from_raw(top), listed_before - 1);
    let (store, out) = connect_short(&path, &b, boundary);
    assert!(
        out.is_err(),
        "an unchanged storage-id count hides a decrease of one in the fold"
    );
    assert_eq!(tip(&store), boundary - 1);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(boundary),
            row: StoreInvariant::FoldNotMonotone {
                cell: "block_info.cumulative_tx_count",
                height: top,
            },
        }
    );
}

/// SI-13 on the archival fold: the boundary at `E·SEB` samples
/// `C((E−3)·SEB)` and `C((E−1)·SEB)` — rows `(E−3)·SEB − 1` and
/// `(E−1)·SEB − 1` — and the later row zeroed is below the earlier one.
/// The fault names the row that decreased, as the listed fold's does.
#[test]
fn a_decreasing_archival_total_refuses_the_boundary() {
    let path = tmp("prune-archival-monotone");
    let boundary = first_discarding_boundary() + SHORT_SEB;
    let later_row = boundary - SHORT_SEB - 1;
    let b = short_chain_to(&path, boundary - 1);
    plant_archival(&path, BlockHeight::from_raw(later_row), 0);
    let (store, out) = connect_short(&path, &b, boundary);
    assert!(out.is_err());
    assert_eq!(tip(&store), boundary - 1);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(boundary),
            row: StoreInvariant::FoldNotMonotone {
                cell: "block_info.cumulative_archival_len",
                height: later_row,
            },
        }
    );
}

/// SI-13 across the whole run the boundary reads, not at its samples
/// (Copilot, PR #910). Cells `a` to `b`, below the block that closes shard
/// 0, are raised together by `R` with their length rows untouched: each
/// shifted cell still equals its parent plus its rows, so SI-24 holds at
/// every block inside the run, and the fold now reaches `W` twice — at `a`
/// (a spurious crossing, `R` chosen to make it one) and at the real close.
/// The endpoints the boundary samples are true. A search that trusts
/// monotonicity can settle on `a` and place shard 1's first id inside that
/// block. The first discarding boundary must halt on the decrease at
/// `b + 1` instead, before any discard.
#[test]
fn a_shifted_run_between_two_samples_refuses_the_boundary() {
    let path = tmp("prune-archival-run");
    let boundary = first_discarding_boundary();
    let closed = close_height(0);
    let b = short_chain_to(&path, boundary - 1);
    let model = b.model();
    let w = SHARD_LENGTH.to_raw();
    let (first, last) = (closed - 6, closed - 4);
    let raise = w - model.cumulative_through(first) + 1;
    assert!(
        model.cumulative_through(last + 1) < model.cumulative_through(last) + raise,
        "the block after the run reads below the raised cell"
    );
    assert!(
        first > boundary - 3 * SHORT_SEB,
        "the run sits between the samples"
    );
    for height in first..=last {
        plant_info(&path, height, |info| {
            info.cumulative_archival_len =
                ArchivalLength::from_raw(info.cumulative_archival_len.to_raw() + raise);
        });
    }
    let (store, out) = connect_short(&path, &b, boundary);
    assert!(out.is_err(), "the boundary does not commit over the run");
    assert_eq!(tip(&store), boundary - 1);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(boundary),
            row: StoreInvariant::FoldNotMonotone {
                cell: "block_info.cumulative_archival_len",
                height: last + 1,
            },
        }
    );
    assert!(
        body_states(&store).iter().all(|&held| held),
        "no body was discarded"
    );
}

/// SI-24 at every block the descent passes (Copilot, PR #910): a shift
/// that starts at one block and persists through the tip keeps the fold
/// monotone everywhere and agrees with the rows at every block above its
/// start. Cells from two blocks below shard 1's close to the tip are
/// raised by `W`, rows untouched, so the later sample reads a shard past
/// the true one and the boundary would discard shards still held. The
/// descent checks the run's first block against its parent before
/// anything is discarded.
#[test]
fn a_shift_that_persists_through_the_window_refuses_the_boundary() {
    let path = tmp("prune-archival-persist");
    let boundary = first_discarding_boundary() + SHORT_SEB;
    let b = short_chain_to(&path, boundary - 1);
    let model = b.model();
    let start = close_height(1) - 2;
    let raise = SHARD_LENGTH.to_raw();
    for height in start..boundary {
        plant_info(&path, height, |info| {
            info.cumulative_archival_len =
                ArchivalLength::from_raw(info.cumulative_archival_len.to_raw() + raise);
        });
    }
    let (store, out) = connect_short(&path, &b, boundary);
    assert!(out.is_err(), "the boundary does not commit over the shift");
    assert_eq!(tip(&store), boundary - 1);
    let rows = model.cumulative_through(start);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(boundary),
            row: StoreInvariant::ArchivalLengthsDisagree {
                height: start,
                rows,
                cell: rows + raise,
            },
        }
    );
    for id in model.ids_of(1) {
        assert_eq!(prunable_state(&store, id), Some(true), "id {id} is held");
    }
}

/// SI-24: the first discarding boundary sums the length rows of the block
/// that closes shard 0 to place `W`, and a row that no longer adds up to
/// the block's cell refuses the boundary rather than place it by numbers
/// the fold does not support.
#[test]
fn a_length_row_that_disagrees_with_the_fold_refuses_the_boundary() {
    let path = tmp("prune-archival-rows");
    let boundary = first_discarding_boundary();
    let closed = close_height(0);
    let b = short_chain_to(&path, boundary - 1);
    let model = b.model();
    let (id, len) = model
        .txs()
        .iter()
        .enumerate()
        .find(|&(_, &(h, _, len))| h == closed && len > 0)
        .map(|(id, &(_, _, len))| (u64::try_from(id).expect("small"), len))
        .expect("the closing block lists a spend");
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        {
            let mut table = txn.open_table(TXS_ARCHIVAL_LEN).expect("table");
            let encoded = ArchivalLength::from_raw(len - 1).encoded();
            table.insert(id, encoded.as_encoded()).expect("plant");
        }
        txn.commit().expect("commit");
    }
    let (store, out) = connect_short(&path, &b, boundary);
    assert!(out.is_err());
    assert_eq!(tip(&store), boundary - 1);
    let cell = model.cumulative_through(closed);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(boundary),
            row: StoreInvariant::ArchivalLengthsDisagree {
                height: closed,
                rows: cell - 1,
                cell,
            },
        }
    );
}

/// Replace `block_info[height].cumulative_tx_count`. A raw write: the
/// store's own connect never records a decrease. `height` is the block
/// the row belongs to; the redb key is that height's raw word.
fn plant_listed(path: impl AsRef<std::path::Path>, height: BlockHeight, listed: u64) {
    let path: &std::path::Path = path.as_ref();
    plant_info(path, height.to_raw(), |info| {
        info.cumulative_tx_count = listed;
    });
}

/// Replace `block_info[height].cumulative_archival_len`, likewise.
fn plant_archival(path: impl AsRef<std::path::Path>, height: BlockHeight, len: u64) {
    let path: &std::path::Path = path.as_ref();
    plant_info(path, height.to_raw(), |info| {
        info.cumulative_archival_len = ArchivalLength::from_raw(len);
    });
}

fn plant_info(
    path: impl AsRef<std::path::Path>,
    height: u64,
    edit: impl FnOnce(&mut crate::codec::BlockInfo),
) {
    let path: &std::path::Path = path.as_ref();
    let db = redb::Database::open(path).expect("open raw");
    let txn = db.begin_write().expect("write");
    {
        let mut table = txn.open_table(BLOCK_INFO).expect("block_info");
        let info = {
            let guard = table.get(height).expect("get").expect("row");
            let mut info = guard.value().decode().expect("decodes");
            edit(&mut info);
            info
        };
        let encoded = info.encoded();
        table.insert(height, encoded.as_encoded()).expect("plant");
    }
    txn.commit().expect("commit");
}

/// A malformed `undo_log_floor` cell is SI-7 and arms the batch's latch like
/// every other typed cell read through the batch: `pop` does not leave the
/// writer live over a floor it cannot read, and a closure that swallows the
/// error cannot commit (Copilot, PR #861).
#[test]
fn a_malformed_undo_floor_cell_poisons_the_batch() {
    let path = tmp("prune-floor-corrupt");
    let store =
        ChainStore::with_horizons(&path, ApplyPolicy::default(), horizons()).expect("create");
    let mut b = Builder::new();
    b.connect(&store, 0, 3, |_| Vec::new());
    drop(store);
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        {
            let mut table = txn.open_table(PROPERTIES).expect("properties");
            table
                .insert(
                    UndoLogFloorCell::KEY,
                    Raw::<PropertyCellBytes>::new(&[0xFF; 3]),
                )
                .expect("plant");
        }
        txn.commit().expect("commit");
    }
    let store =
        ChainStore::with_horizons(&path, ApplyPolicy::default(), horizons()).expect("reopen");
    let out: Result<(), TestErr> = store.write(|batch| {
        let err = batch.pop().expect_err("the floor does not decode");
        assert!(
            matches!(
                err,
                StoreError::InvariantViolated(StoreInvariant::CellCorrupt {
                    key: "undo_log_floor",
                    fault: CellFault::Undecodable(_),
                })
            ),
            "got {err:?}"
        );
        // The closure swallows the error: the poisoned batch must still
        // refuse to commit.
        Ok(())
    });
    assert!(
        out.is_err(),
        "a poisoned batch does not commit on a swallowed SI-7"
    );
    assert_eq!(tip(&store), 3, "nothing popped");
    assert!(
        !store.connect_state().is_live(),
        "pop noted the tip as chain work, so the writer halts on the latch"
    );
}

/// SPR-4: the persisted floor and the journal's first key record one fact,
/// and the redundancy is a check that can fail. A journal whose lowest row
/// is not the floor's is SI-6 at `pop` — before any refusal is read off
/// either — and at the next boundary after the retire.
#[test]
fn a_journal_whose_first_row_is_not_the_floor_is_si6_at_pop_and_at_the_boundary() {
    let path = tmp("prune-floor-mismatch");
    let (store, _b, _, _) = chain_to_400(&path);
    // Rows [350, 400] stand and the cell says 350. Remove row 350 by
    // hand.
    drop(store);
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        {
            let mut table = txn.open_table(UNDO_LOG).expect("undo_log");
            table
                .remove(350u64)
                .expect("remove")
                .expect("row 350 stood");
        }
        txn.commit().expect("commit");
    }
    let store =
        ChainStore::with_horizons(&path, ApplyPolicy::default(), horizons()).expect("reopen");
    let out: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
    assert_eq!(
        out,
        Err(TestErr::Store(
            StoreError::from(StoreInvariant::UndoLogIncoherent {
                height: 400,
                fault: UndoFault::FloorMismatch {
                    first: 351,
                    floor: 350
                },
            })
            .to_string()
        )),
        "the cell and the table disagree: SI-6, not a capability limit"
    );
    assert!(!store.connect_state().is_live(), "the writer halts on SI-6");

    // The same gap, met by the boundary batch: connect to `499`
    // under a clean journal, open the gap at the floor that `500`
    // will establish (450), then connect `500`.
    let path = tmp("prune-floor-mismatch-boundary");
    let (store, mut b2, _, _) = chain_to_400(&path);
    b2.connect(&store, 401, 499, |_| Vec::new());
    drop(store);
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        {
            let mut table = txn.open_table(UNDO_LOG).expect("undo_log");
            table
                .remove(450u64)
                .expect("remove")
                .expect("row 450 stood");
        }
        txn.commit().expect("commit");
    }
    let store =
        ChainStore::with_horizons(&path, ApplyPolicy::default(), horizons()).expect("reopen");
    let previous = *b2.hashes().last().expect("499 connected");
    let cand = candidate_on(&store, 500, previous, Vec::new());
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge_under(&view, cand, &RULES)?, RULES)?)
    });
    assert_eq!(
        out,
        Err(TestErr::Store(
            StoreError::from(StoreInvariant::UndoLogIncoherent {
                height: 500,
                fault: UndoFault::FloorMismatch {
                    first: 451,
                    floor: 450
                },
            })
            .to_string()
        )),
        "the retire leaves a first key that is not the floor: SI-6"
    );
    assert_eq!(tip(&store), 499, "the boundary block did not connect");
    assert!(!store.connect_state().is_live());
}

/// SCW-7 as a refusal on both sides: `Horizons::new` refuses a retention
/// below the cap it is handed, and `connect` refuses a block whose in-force
/// set names a cap the retention does not cover — at the block, live, with
/// nothing connected — never a `PopBelowFloor` on a legal reorg later.
#[test]
fn a_retention_below_the_in_force_cap_is_refused_at_open_and_at_connect() {
    let epoch = SettlementEpochBlocks::new(SEB).expect("non-zero");
    assert_eq!(
        Horizons::new(epoch, BlockCount::from_raw(49), BlockCount::from_raw(50)),
        Err(StoreCannot::RetentionBelowReorgCap {
            retention: BlockCount::from_raw(49),
            reorg_cap: BlockCount::from_raw(50),
        })
    );
    assert!(Horizons::new(epoch, BlockCount::from_raw(50), BlockCount::from_raw(50)).is_ok());
    // The production cap does not fit a 100-block schedule at all.
    assert!(matches!(
        Horizons::production(epoch),
        Err(StoreCannot::RetentionNotInsideEpoch { .. })
    ));

    // A store admitted under RULES (cap 50) is handed GENESIS (cap 720).
    let path = tmp("prune-cap-at-connect");
    let store =
        ChainStore::with_horizons(&path, ApplyPolicy::default(), horizons()).expect("create");
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let cand = candidate(0, BlockHash::NULL, Vec::new());
        Ok(batch.connect(
            judge_under(&view, cand, &RuleSet::GENESIS)?,
            RuleSet::GENESIS,
        )?)
    });
    assert_eq!(
        out,
        Err(TestErr::Store(
            StoreError::from(StoreCannot::RetentionBelowReorgCap {
                retention: BlockCount::from_raw(RETENTION),
                reorg_cap: shekyl_chain_rules::D_MAX,
            })
            .to_string()
        ))
    );
    assert!(store.connect_state().is_live(), "a refusal is not a halt");
    assert!(
        store
            .begin_read()
            .expect("read")
            .tip()
            .expect("tip")
            .recorded
            .is_none(),
        "nothing connected"
    );
}

/// SCW-2 at connect (DRS-E4 `ARW-15`): the in-force set's settlement epoch
/// is the pinned one, or the verdict's archival rows — join epochs,
/// serve-credit windows, the close — were judged under a geometry the file
/// does not hold. A set whose cap the retention covers but whose epoch is
/// another is refused at its first block with the pair named; the header
/// open refused the same mismatch against the epoch the caller named.
#[test]
fn a_set_naming_another_epoch_is_refused_at_connect() {
    let other = RuleSet::GENESIS.with_levers(None, pair(200, RETENTION));
    assert_eq!(other.reorg_cap(), RULES.reorg_cap(), "the cap is covered");
    let path = tmp("prune-epoch-at-connect");
    let store =
        ChainStore::with_horizons(&path, ApplyPolicy::default(), horizons()).expect("create");
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let cand = candidate(0, BlockHash::NULL, Vec::new());
        Ok(batch.connect(judge_under(&view, cand, &other)?, other)?)
    });
    assert_eq!(
        out,
        Err(TestErr::Store(
            StoreError::from(StoreCannot::SettlementEpochMismatch {
                pinned: SettlementEpochBlocks::new(SEB).expect("non-zero"),
                session: SettlementEpochBlocks::new(200).expect("non-zero"),
            })
            .to_string()
        ))
    );
    assert!(store.connect_state().is_live(), "a refusal is not a halt");
}

/// `Horizons::under` is the set's own pair read back: the genesis set gives
/// the production horizons, and a levered set under a shortened schedule
/// gives horizons `connect` accepts under that set — the one way a replay
/// driver and a test open a store, off the set rather than off a second
/// copy of its numbers.
#[test]
fn horizons_under_a_set_are_the_ones_its_connect_accepts() {
    let epoch = SettlementEpochBlocks::new(10_000).expect("non-zero");
    assert_eq!(
        Horizons::under(&RuleSet::GENESIS),
        Horizons::production(epoch),
    );
    let short = RuleSet::GENESIS.with_levers(None, pair(512, 64));
    let under = Horizons::under(&short).expect("a well-formed pair");
    assert_eq!(
        under.epoch(),
        SettlementEpochBlocks::new(512).expect("non-zero")
    );
    assert_eq!(under.check_against(&short), Ok(()));
    assert!(
        under.check_against(&RuleSet::GENESIS).is_err(),
        "the genesis set names another cap and another epoch"
    );
}

/// **`SHT-Q1` leg (f): the domain answer is stable across a prune.**
///
/// The ruling's predicate is decidable from the skeleton, which is only true if
/// the digests it reads are the ones **recorded at ingest**. The store keeps both
/// permanently — `txs_prunable_hash` and `txs_pqc_auth_hash` — and a prune
/// deletes the *regions*, never the rows. So a node that has discarded a shard
/// must still place its transactions **inside** the domain, exactly as it did
/// while it held them.
///
/// The hazard this pins is the opposite: recomputing the digests from a pruned
/// body yields `keccak256("")` and no component, which would place a node's own
/// discarded spends *outside* the domain and split shard boundaries against an
/// archival peer. `shekyl-wire` therefore exposes the predicate only over
/// explicit row values, and [`ReadSnapshot::tx_carries_archival_good`] is the
/// only production path.
///
/// Every id is recorded before the boundary that discards shard 0 and compared
/// after it — the whole vector, not a sample — so a flip anywhere fails.
#[test]
fn the_predicate_survives_a_prune_on_the_stored_rows() {
    let path = tmp("prune-domain-stability");
    // The captured chain through shard 0's close, then empty blocks — the
    // coinbase-only case — to 299: spends (4-part) fill shard 0 (discarded
    // at the epoch-3 boundary), and the closing block's last spends start
    // shard 1 (retained). Recorded at 299, before the first discard.
    let (store, mut b) = Builder::captured(&path, "seb100", RULES, horizons(), closing(0));
    b.connect(&store, close_height(0) + 1, 299, |_| Vec::new());

    let count = store.begin_read().expect("read").tx_count().expect("count");
    let before: Vec<Option<bool>> = (0..count).map(|id| good_state(&store, id)).collect();

    // On the unpruned store the accessor agrees with the whole-body predicate:
    // the rows are the body's own digests until a prune takes the regions.
    {
        let snap = store.begin_read().expect("read");
        for txs in &b.listed {
            for tx in txs {
                let record = snap.tx_record(&tx.hash()).expect("read").expect("recorded");
                let parts = tx.txid_parts();
                assert_eq!(
                    shekyl_wire::carries_archival_good(record.pqc_auth_hash, record.prunable_hash),
                    shekyl_wire::carries_archival_good(parts.pqc_auth_hash, parts.prunable_hash),
                    "the stored rows and the body's digests disagree before any prune"
                );
                assert_eq!(
                    good_state(&store, record.location.id.to_raw()),
                    Some(true),
                    "a listed spend carries archival good"
                );
            }
        }
    }

    // The boundary that discards shard 0.
    let at_300 = b.connect(&store, 300, 300, |_| Vec::new()).remove(0);
    assert_eq!(
        at_300.pruned.expect("a boundary").shards(),
        0..1,
        "D(3) is shard 0"
    );
    let first_spend = b
        .model()
        .txs()
        .iter()
        .position(|&(_, _, len)| len > 0)
        .map(|id| u64::try_from(id).expect("small"))
        .expect("the chain lists a spend");
    assert_eq!(
        prunable_state(&store, first_spend),
        Some(false),
        "the chain's first spend must actually be discarded, or this test proves nothing"
    );

    // Leg (f): every answer is unchanged, the discarded bodies included.
    let after: Vec<Option<bool>> = (0..count).map(|id| good_state(&store, id)).collect();
    assert_eq!(
        before, after,
        "the domain answer moved across a prune — nodes either side of the boundary \
         would disagree on shard boundaries"
    );
    assert_eq!(
        good_state(&store, first_spend),
        Some(true),
        "a DISCARDED spend is still in the domain: its rows outlive its regions"
    );
    assert_eq!(
        good_state(&store, 0),
        Some(false),
        "a coinbase is outside the domain, before and after"
    );

    // Both rows survived the prune — the premise leg (f) rests on. Read through
    // the record so a deleted row shows up as the absence it would be.
    {
        let snap = store.begin_read().expect("read");
        let spend = body_of_id(&b, first_spend).expect("a listed body");
        let discarded = snap
            .tx_record(&spend.hash())
            .expect("read")
            .expect("recorded");
        assert_eq!(
            good_of(&snap, &discarded),
            ArchivalGood::Discarded,
            "the region went with the shard"
        );
        assert!(
            discarded.pqc_auth_hash.is_some(),
            "the pqc hash row is permanent"
        );
        assert_ne!(
            discarded.prunable_hash,
            shekyl_wire::empty_region_prunable_hash(),
            "the prunable hash row still records the non-empty region it had"
        );
    }
}

// ---------------------------------------------------------------------------
// The slash log's retirement (`SLK-Q1`): a window the unit lane can cross
// ---------------------------------------------------------------------------

/// `SEB 10 / cap 5`: the pair whose window — `(k + n)·SEB + cap`,
/// [`SlashLogFloor::window`] — a chain of empty blocks crosses in the unit
/// lane (`DRS_E4_SLASH_LOG_ROUND.md` §1.1, build commit 3: "window 145").
/// Nothing below spells the expression again: the chain's length, the
/// floor and the heights planted around it are all read off the window.
const WINDOW_SEB: u64 = 10;
const WINDOW_CAP: u64 = 5;
const WINDOW_RULES: RuleSet = RuleSet::GENESIS.with_levers(None, pair(WINDOW_SEB, WINDOW_CAP));
/// The window under the pair, in blocks.
const WINDOW: u64 = match SlashLogFloor::window(
    WINDOW_RULES.settlement_schedule().blocks(),
    WINDOW_RULES.reorg_cap(),
) {
    Some(window) => window.to_raw(),
    None => panic!("the window fits"),
};
/// The first boundary with a floor: the first multiple of `SEB` at or past
/// the window. The boundary before it has none.
const FIRST_FLOORED_BOUNDARY: u64 = WINDOW.div_ceil(WINDOW_SEB) * WINDOW_SEB;
/// The floor at that boundary: the rows planted below are retired there,
/// the rows planted at and above it kept.
const FIRST_FLOOR: u64 = FIRST_FLOORED_BOUNDARY - WINDOW;
const _: () = assert!(
    FIRST_FLOOR > 2 && FIRST_FLOOR + 1 < FIRST_FLOORED_BOUNDARY - WINDOW_CAP,
    "the planted heights sit on both sides of the floor and under the undo floor"
);

/// The floor the batch at `boundary` derives, as the rule set states it.
fn floor_at(boundary: u64) -> SlashLogFloor {
    SlashLogFloor::under(
        BlockHeight::from_raw(boundary),
        WINDOW_RULES.settlement_schedule().blocks(),
        WINDOW_RULES.reorg_cap(),
    )
}

/// A store under the pair with the given undo retention — the cap, or
/// deeper for `SLK-2`'s falsifier.
fn window_store(path: impl AsRef<std::path::Path>, retention: u64) -> ChainStore {
    let path: &std::path::Path = path.as_ref();
    let horizons = Horizons::new(
        WINDOW_RULES.settlement_schedule().blocks(),
        BlockCount::from_raw(retention),
        WINDOW_RULES.reorg_cap(),
    )
    .expect("cap ≤ retention < epoch");
    ChainStore::with_horizons(path, ApplyPolicy::default(), horizons).expect("open")
}

/// Empty blocks to height `to` under the pair. The store is closed on
/// return, for a raw plant; the connects are returned for the boundaries'
/// `Pruned`. A test that re-connects a block at a boundary lists a real
/// spend there ([`Listed::Spend`]) so it hashes apart from the popped one.
fn window_chain_to(
    path: impl AsRef<std::path::Path>,
    retention: u64,
    to: u64,
) -> (Builder, Vec<Connected>) {
    let path: &std::path::Path = path.as_ref();
    let store = window_store(path, retention);
    let mut b = Builder::under(WINDOW_RULES);
    let connects = b.connect(&store, 0, to, |_| Vec::new());
    (b, connects)
}

/// Every `archival_slash_log` key, in table order.
fn slash_rows(store: &ChainStore) -> Vec<SlashLogTuple> {
    let snap = store.begin_read().expect("read");
    let table = snap.open_table(ARCHIVAL_SLASH_LOG).expect("table");
    table
        .range::<SlashLogTuple>(..)
        .expect("range")
        .map(|item| item.expect("row").0.value())
        .collect()
}

/// The window is the round's: the first boundary with a floor is the one
/// the pre-flight tabled, and the boundary before it has none — in the
/// rule set's expression and in the store's `Pruned`.
#[test]
fn the_window_is_the_rounds_and_the_boundary_before_it_has_no_floor() {
    assert_eq!(WINDOW, 145, "SEB 10 / cap 5: (k + n)·10 + 5");
    assert_eq!(FIRST_FLOORED_BOUNDARY, 150);
    assert_eq!(FIRST_FLOOR, 5);
    assert_eq!(
        floor_at(FIRST_FLOORED_BOUNDARY - WINDOW_SEB),
        SlashLogFloor::NONE
    );
    assert_eq!(
        floor_at(FIRST_FLOORED_BOUNDARY).height(),
        Some(BlockHeight::from_raw(FIRST_FLOOR)),
        "the first floor is the boundary less the window"
    );

    let path = tmp("slk-window");
    let (_, connects) = window_chain_to(&path, WINDOW_CAP, FIRST_FLOORED_BOUNDARY - 1);
    let boundaries: Vec<(u64, SlashLogFloor)> = connects
        .iter()
        .filter_map(|c| c.pruned.map(|p| (c.height.to_raw(), p.slash_floor)))
        .collect();
    assert_eq!(
        boundaries,
        (super::prune::FIRST_PRUNING_EPOCH..FIRST_FLOORED_BOUNDARY / WINDOW_SEB)
            .map(|e| (e * WINDOW_SEB, SlashLogFloor::NONE))
            .collect::<Vec<_>>(),
        "every boundary under the window ran, and none had a floor"
    );
}

/// The first enforcement of `journal_horizon` (`PDM-Q-F19`): at the first
/// boundary with a floor, rows below it are gone and rows at and above it
/// stay; the batch reports the floor it used; the one reader asserts the
/// same floor (SI-26) — a read starting at the floor is sound and returns
/// the kept rows, a read starting one below is the fault, with the asked
/// height and the floor in it. Then a pop across the boundary and a
/// different block reconnected at it: the pop restores nothing (the
/// retirement is not journaled, like the body discards), and the batch
/// re-derives the same floor and deletes the same, already empty, range.
/// Both connects run the slash pass with that floor in hand; it never
/// trips the arm, because every height it can ask about is inside the
/// settling epoch, `(k + 1)` epochs below the connecting height, while the
/// floor is `(k + n)` epochs and a cap below it (the margin;
/// `slash.rs`, `slashed_after`). On this chain the pass has no draw to
/// read for, so the margin is stated, not exercised; the bench witness
/// exercises the read with a floor in hand.
///
/// **The check's falsifier:** delete the SI-26 arm in
/// `archival_reads::slash_log_after` and the `unwrap_err` below panics on
/// an `Ok` of two rows — the read would return the rows above the retired
/// range as if they were the log. Delete `retire_slash_rows` and the first
/// `slash_rows` assertion fails with the planted rows intact.
#[test]
fn the_boundary_retires_slash_rows_below_the_floor_and_the_read_asserts_it() {
    let path = tmp("slk-retire");
    let boundary = FIRST_FLOORED_BOUNDARY;
    let floor = FIRST_FLOOR;
    let (mut b, _) = window_chain_to(&path, WINDOW_CAP, boundary - 1);

    // Rows two below, one below (two personas), at, and one above the floor.
    let p = persona(0x51);
    let q = persona(0x52);
    plant(&path, |txn| {
        plant_slash(txn, floor - 2, 0, &slash_entry(&p, 0, 1, 1));
        plant_slash(txn, floor - 1, 0, &slash_entry(&p, 0, 1, 1));
        plant_slash(txn, floor - 1, 1, &slash_entry(&q, 0, 1, 1));
        plant_slash(txn, floor, 0, &slash_entry(&p, 0, 1, 1));
        plant_slash(txn, floor + 1, 0, &slash_entry(&p, 0, 1, 1));
    });
    let kept = vec![(floor, 0), (floor + 1, 0)];

    let store = window_store(&path, WINDOW_CAP);
    let first = b
        .connect(&store, boundary, boundary, |_| Vec::new())
        .remove(0);
    let pruned = first.pruned.expect("the first floored boundary");
    assert_eq!(pruned.slash_floor, floor_at(boundary));
    assert_eq!(
        pruned.slash_floor.height(),
        Some(BlockHeight::from_raw(floor))
    );
    assert_eq!(
        slash_rows(&store),
        kept,
        "below the floor gone, at and above it kept"
    );

    // The read, with the floor the batch used.
    let snap = store.begin_read().expect("read");
    let from_the_floor = snap
        .slash_log_after(&p, BlockHeight::from_raw(floor - 1), pruned.slash_floor)
        .expect("a read starting at the floor is sound");
    assert_eq!(from_the_floor.len(), 2, "both kept rows are {p:?}'s");
    let err = snap
        .slash_log_after(&p, BlockHeight::from_raw(floor - 2), pruned.slash_floor)
        .unwrap_err();
    assert!(
        matches!(
            err,
            StoreError::InvariantViolated(StoreInvariant::SlashLogReadBelowFloor {
                asked,
                floor: at
            }) if asked == BlockHeight::from_raw(floor - 2) && at == BlockHeight::from_raw(floor)
        ),
        "a read starting below the floor is SI-26, not an empty prefix: {err}"
    );
    drop(snap);

    // Across the boundary and back, on another block: the re-connected one
    // lists a real spend, so it hashes apart from the popped one.
    let popped_hash = *b.hashes().last().expect("the boundary's block");
    let out: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
    assert_eq!(out.map(|popped| popped.height.to_raw()), Ok(boundary));
    b.forget(1);
    assert_eq!(
        slash_rows(&store),
        kept,
        "a pop restores no retired row: the retirement is not journaled"
    );
    let again = b
        .connect(&store, boundary, boundary, |_| {
            vec![Listed::Spend { fee: FEE }]
        })
        .remove(0);
    assert_ne!(
        *b.hashes().last().expect("re-connected"),
        popped_hash,
        "a different block at the boundary"
    );
    assert_eq!(
        again.pruned.expect("the boundary fires again").slash_floor,
        pruned.slash_floor,
        "the same expression at the same height"
    );
    assert_eq!(slash_rows(&store), kept, "the same, already empty, range");
}

/// A boundary past the first slash floor: the Release journal retires
/// at the settling family's horizon, and drawable digests retire below
/// that family's epoch floor, at the same height.
const DIGEST_RETIRING_BOUNDARY: u64 = FIRST_FLOORED_BOUNDARY + 2 * WINDOW_SEB;

/// **The Release journal and the drawable digests retire with the settling
/// family** (`SO-D12h`): at a floored boundary, journal rows at or below
/// `h_open` of the oldest kept settling epoch are gone and rows above it
/// stay, and the journal's reader asserts that height (SI-28). Drawable
/// digests retire below the same family's epoch floor. Both horizons sit
/// inside the slash log's floor.
///
/// **Falsifiers:** delete `retire_release_rows` and the journal assertion
/// fails with the planted rows intact; delete the drawable-digest arm of
/// `retire_epoch_rows` and the digest assertion fails with the epochs below
/// the settling floor still present; delete the SI-28 arm in
/// `archival_reads::release_journal_after` and the `unwrap_err` panics on an
/// `Ok`.
#[test]
fn the_boundary_retires_release_rows_and_settled_digests_below_the_floor() {
    let path = tmp("release-retire");
    let boundary = DIGEST_RETIRING_BOUNDARY;
    let schedule = WINDOW_RULES.settlement_schedule();
    let slash = floor_at(boundary)
        .height()
        .expect("a floored boundary")
        .to_raw();
    let settling = epoch_floors_at(boundary).settling;
    let journal = ReleaseJournalFloor::of(settling, schedule);
    let floor = journal
        .height()
        .expect("the settling family has retired an epoch")
        .to_raw();
    assert!(
        floor > slash,
        "the journal horizon is inside the slash log's floor"
    );
    let first_kept = settling
        .kept_from()
        .expect("the settling floor is above zero")
        .to_raw();
    assert_eq!(
        floor,
        schedule.open_height(first_kept) + 1,
        "the journal keeps rows strictly above the oldest kept epoch's open"
    );
    let (mut b, _) = window_chain_to(&path, WINDOW_CAP, boundary - 1);

    // A pre-image one below, at, and one above the floor.
    let p = persona(0x61);
    plant(&path, |txn| {
        let mut journal = txn
            .open_table(crate::schema::ARCHIVAL_RELEASE_JOURNAL)
            .expect("t");
        for h in [floor - 1, floor, floor + 1] {
            journal
                .insert(
                    crate::ids::ReleaseJournalKey::new(BlockHeight::from_raw(h), p).key(),
                    record().encoded().as_encoded(),
                )
                .expect("insert");
        }
    });
    let digests = |store: &ChainStore| -> Vec<u64> {
        let snap = store.begin_read().expect("read");
        let table = snap
            .open_table(crate::schema::ARCHIVAL_DRAWABLE_DIGEST)
            .expect("table");
        table
            .range::<u64>(..)
            .expect("range")
            .map(|item| item.expect("row").0.value())
            .collect()
    };
    let store = window_store(&path, WINDOW_CAP);
    let opened = schedule.epoch_at_height(boundary - 1);
    let already_kept = epoch_floors_at(boundary - WINDOW_SEB)
        .settling
        .kept_from()
        .expect("the previous boundary retired drawable digests")
        .to_raw();
    assert_eq!(
        digests(&store),
        (already_kept..=opened).collect::<Vec<_>>(),
        "earlier boundaries retired below their settling floor; later opens remain"
    );

    assert!(
        b.connect(&store, boundary, boundary, |_| Vec::new())
            .remove(0)
            .pruned
            .is_some(),
        "a floored boundary"
    );
    let snap = store.begin_read().expect("read");
    let kept = snap
        .release_journal_after(BlockHeight::from_raw(floor - 1), journal)
        .expect("a read starting at the floor is sound");
    assert_eq!(
        kept.iter().map(|r| r.height.to_raw()).collect::<Vec<_>>(),
        [floor, floor + 1],
        "below the floor gone, at and above it kept"
    );
    let err = snap
        .release_journal_after(BlockHeight::from_raw(floor - 2), journal)
        .unwrap_err();
    assert!(
        matches!(
            err,
            StoreError::InvariantViolated(StoreInvariant::ReleaseJournalReadBelowFloor {
                asked,
                floor: at
            }) if asked == BlockHeight::from_raw(floor - 2) && at == BlockHeight::from_raw(floor)
        ),
        "a read starting below the floor is SI-28: {err}"
    );
    drop(snap);
    assert_eq!(
        digests(&store),
        (first_kept..=schedule.epoch_at_height(boundary)).collect::<Vec<_>>(),
        "drawable digests retire below the settling floor; the epoch at it stays"
    );
}

/// A session that stubs `SlashLog` does not retire it (`ARW-9`). The
/// boundary still runs — bodies and the undo journal are not that family —
/// and reports no slash floor, because none was enforced. The planted rows
/// below the floor stay. Opening the table would delete rows the session
/// was told not to apply; refusing the connect would stop the session at
/// the first floored epoch.
#[test]
fn a_stubbed_slash_log_is_not_retired_at_the_boundary() {
    let path = tmp("slk-stub-retire");
    let boundary = FIRST_FLOORED_BOUNDARY;
    let floor = FIRST_FLOOR;
    let (mut b, _) = window_chain_to(&path, WINDOW_CAP, boundary - 1);
    let p = persona(0x54);
    plant(&path, |txn| {
        plant_slash(txn, floor - 1, 0, &slash_entry(&p, 0, 1, 1));
        plant_slash(txn, floor, 0, &slash_entry(&p, 0, 1, 1));
    });
    let planted = vec![(floor - 1, 0), (floor, 0)];

    let policy = ApplyPolicy::stubbed(&[crate::apply_policy::ArchivalFamily::SlashLog])
        .expect("a named family");
    let horizons = Horizons::new(
        WINDOW_RULES.settlement_schedule().blocks(),
        BlockCount::from_raw(WINDOW_CAP),
        WINDOW_RULES.reorg_cap(),
    )
    .expect("cap ≤ retention < epoch");
    let store = ChainStore::with_horizons(&path, policy, horizons).expect("reopen stubbed");
    let connected = b
        .connect(&store, boundary, boundary, |_| Vec::new())
        .remove(0);
    assert_eq!(
        connected
            .pruned
            .expect("the boundary still runs")
            .slash_floor,
        SlashLogFloor::NONE,
        "a skipped apply enforced no floor"
    );
    assert_eq!(
        slash_rows(&store),
        planted,
        "rows below the floor stay when the family is stubbed"
    );
}

/// `SLK-2`'s falsifier: the floor is the rule set's cap, not the store's
/// retention. A store opened with `undo_retention` deeper than the cap
/// moves its undo floor by the difference and the slash floor not at all —
/// rows a retention-derived floor would have kept are retired. One value
/// was doing two jobs; this is the seam where they are two.
#[test]
fn a_deeper_undo_retention_moves_the_undo_floor_and_not_the_slash_floor() {
    let path = tmp("slk-retention");
    let boundary = FIRST_FLOORED_BOUNDARY;
    let floor = FIRST_FLOOR;
    let deeper = WINDOW_CAP + 2;
    assert!(deeper < WINDOW_SEB, "inside the epoch, so the store opens");
    let (mut b, _) = window_chain_to(&path, deeper, boundary - 1);

    // The rows a floor that followed the retention would keep: at
    // `floor − 2` and `floor − 1`, which `boundary − (window + 2)` sits
    // below.
    let p = persona(0x53);
    plant(&path, |txn| {
        plant_slash(txn, floor - 2, 0, &slash_entry(&p, 0, 1, 1));
        plant_slash(txn, floor - 1, 0, &slash_entry(&p, 0, 1, 1));
        plant_slash(txn, floor, 0, &slash_entry(&p, 0, 1, 1));
    });

    let store = window_store(&path, deeper);
    let pruned = b
        .connect(&store, boundary, boundary, |_| Vec::new())
        .remove(0)
        .pruned
        .expect("a boundary");
    assert_eq!(
        pruned.undo_floor,
        BlockHeight::from_raw(boundary - deeper),
        "the retention is the undo floor's"
    );
    assert_eq!(
        pruned.slash_floor,
        floor_at(boundary),
        "and not the slash floor's: the cap is the rule set's"
    );
    assert_eq!(slash_rows(&store), vec![(floor, 0)]);
}

// ---------------------------------------------------------------------------
// The per-epoch retirement (`ARCHIVAL_SETTLEMENT_WRITER.md` §17, `SO-D12h`)
// ---------------------------------------------------------------------------

/// The boundary whose batch first retires a claimable row under the window
/// pair: `(B − 1) − W = 2`. Every family's floor is above zero there.
const EPOCH_RETIRING_BOUNDARY: u64 = (shekyl_archival_retention::MAX_CLAIM_AGE_W + 3) * WINDOW_SEB;

/// Each family's floor at that boundary, as the rule set states it.
fn epoch_floors_at(boundary: u64) -> super::prune::EpochFloors {
    let at = BlockHeight::from_raw(boundary);
    let schedule = WINDOW_RULES.settlement_schedule();
    super::prune::EpochFloors {
        claimable: EpochFloor::at_boundary(at, schedule),
        settling: EpochFloor::at_boundary(at, schedule),
        pricing: EpochFloor::at_boundary(at, schedule),
        draws: BlockDrawsFloor::retired_by(schedule.epoch_at_height(boundary), schedule),
    }
}

/// The epochs a `u64`-keyed table holds, ascending.
fn epochs_of<V: redb::Value + 'static>(
    store: &ChainStore,
    table: redb::TableDefinition<'static, u64, V>,
) -> Vec<u64> {
    let snap = store.begin_read().expect("read");
    let table = snap.open_table(table).expect("table");
    table
        .range::<u64>(..)
        .expect("range")
        .map(|item| item.expect("row").0.value())
        .collect()
}

/// The epochs `archival_settlement`, `archival_slash_applied`,
/// `archival_issued_draw` and `archival_r_market` hold, each ascending.
fn keyed_epochs(store: &ChainStore) -> [Vec<u64>; 4] {
    let snap = store.begin_read().expect("read");
    let mut settlement: Vec<u64> = snap
        .open_table(crate::schema::ARCHIVAL_SETTLEMENT)
        .expect("table")
        .iter()
        .expect("iter")
        .map(|item| item.expect("row").0.value().2)
        .collect();
    let mut applied: Vec<u64> = snap
        .open_table(crate::schema::ARCHIVAL_SLASH_APPLIED)
        .expect("table")
        .iter()
        .expect("iter")
        .map(|item| item.expect("row").0.value().2)
        .collect();
    let mut issued: Vec<u64> = snap
        .open_table(crate::schema::ARCHIVAL_ISSUED_DRAW)
        .expect("table")
        .iter()
        .expect("iter")
        .map(|item| item.expect("row").0.value().0)
        .collect();
    let mut priced: Vec<u64> = snap
        .open_table(crate::schema::ARCHIVAL_R_MARKET)
        .expect("table")
        .iter()
        .expect("iter")
        .map(|item| item.expect("row").0.value().1)
        .collect();
    for v in [&mut settlement, &mut applied, &mut issued, &mut priced] {
        v.sort_unstable();
    }
    [settlement, applied, issued, priced]
}

/// Each per-epoch table retires at its family's floor (`SO-D12h`, §17): at
/// the first boundary that retires a claimable row, every family loses the
/// epochs below its floor and keeps the one at it. The rows the chain's
/// own passes and closes wrote (`Σwork`, the complete-tree sets, the
/// budgets) start at the claimable floor afterwards; the rows planted on
/// either side of each floor keep only the side at or above it. A read
/// below a family's floor is SI-32, with the table and both epochs in it;
/// a read at the floor answers. Then a pop across the boundary and a
/// different block reconnected: nothing comes back (the retirement is not
/// journaled), and the batch re-derives the same floors.
///
/// **Falsifiers:** delete `retire_epoch_rows` and the first table assertion
/// fails with every row intact; delete the `kept` check in
/// `archival_reads` and the reads below the floor answer `None` or empty —
/// "never written" for rows that were.
#[test]
fn each_per_epoch_table_retires_at_its_familys_floor_and_the_read_asserts_it() {
    use crate::codec::{IssuedDigest, IssuedDraw, Present, RMarket, SettlementRow};
    use crate::ids::{IssuedDrawKey, SettlementKey, SlashAppliedKey};
    use crate::schema::{
        ARCHIVAL_BUDGET, ARCHIVAL_DRAWABLE_DIGEST, ARCHIVAL_ISSUED_DIGEST, ARCHIVAL_ISSUED_DRAW,
        ARCHIVAL_R_MARKET, ARCHIVAL_SETTLEMENT, ARCHIVAL_SIGMA_WORK, ARCHIVAL_SLASH_APPLIED,
    };
    use shekyl_types::archival::DrawableDigest;
    use shekyl_types::SettlementEpoch;

    let path = tmp("epoch-retire");
    let boundary = EPOCH_RETIRING_BOUNDARY;
    let floors = epoch_floors_at(boundary);
    let raw = |f: Option<SettlementEpoch>| f.expect("a floor above zero").to_raw();
    let (claim, settle, price) = (
        raw(floors.claimable.kept_from()),
        raw(floors.settling.kept_from()),
        raw(floors.pricing.kept_from()),
    );
    assert_eq!((claim, settle, price), (2, 27, 26), "W = 26, k = 1, B = 29");
    let (mut b, _) = window_chain_to(&path, WINDOW_CAP, boundary - 1);

    let p = persona(0x61);
    let s0 = ShardId::from_raw(0);
    let e = SettlementEpoch::from_raw;
    plant(&path, |txn| {
        let mut t = txn.open_table(ARCHIVAL_SETTLEMENT).expect("t");
        for epoch in [claim - 1, claim] {
            t.insert(
                SettlementKey::new(p, s0, e(epoch)).key(),
                SettlementRow::settle(2, 3)
                    .expect("a row")
                    .encoded()
                    .as_encoded(),
            )
            .expect("insert");
        }
        let mut t = txn.open_table(ARCHIVAL_SLASH_APPLIED).expect("t");
        for epoch in [settle - 1, settle] {
            t.insert(SlashAppliedKey::new(p, s0, e(epoch)).key(), Present)
                .expect("insert");
        }
        let mut t = txn.open_table(ARCHIVAL_ISSUED_DRAW).expect("t");
        for epoch in [settle - 1, settle] {
            let draw = IssuedDraw {
                revealed_at: BlockHeight::from_raw(1),
                passed: true,
            };
            t.insert(
                IssuedDrawKey::new(e(epoch), p, s0, BlockHeight::ZERO, 0).key(),
                draw.encoded().as_encoded(),
            )
            .expect("insert");
        }
        let mut t = txn.open_table(ARCHIVAL_ISSUED_DIGEST).expect("t");
        for epoch in [settle - 1, settle] {
            t.insert(epoch, IssuedDigest::ZERO.encoded().as_encoded())
                .expect("insert");
        }
        let mut t = txn.open_table(ARCHIVAL_DRAWABLE_DIGEST).expect("t");
        for epoch in [settle - 1, settle] {
            t.insert(
                epoch,
                DrawableDigest::from_bytes([7; 32]).encoded().as_encoded(),
            )
            .expect("insert");
        }
        let mut t = txn.open_table(ARCHIVAL_R_MARKET).expect("t");
        for epoch in [price - 1, price] {
            t.insert((0, epoch), RMarket::from_raw(1).encoded().as_encoded())
                .expect("insert");
        }
    });

    let store = window_store(&path, WINDOW_CAP);
    let before = epochs_of(&store, ARCHIVAL_SIGMA_WORK);
    assert_eq!(
        before.first(),
        Some(&(claim - 1)),
        "every pass wrote its Σwork, and the boundary before retired below claim − 1"
    );
    let first = b
        .connect(&store, boundary, boundary, |_| Vec::new())
        .remove(0);
    let pruned = first.pruned.expect("a boundary");
    assert_eq!(
        pruned.epochs, floors,
        "the batch's floors are the rule set's"
    );

    let retained = |store: &ChainStore| {
        (
            epochs_of(store, ARCHIVAL_SIGMA_WORK),
            epochs_of(store, ARCHIVAL_BUDGET),
            epochs_of(store, ARCHIVAL_ISSUED_DIGEST),
            epochs_of(store, ARCHIVAL_DRAWABLE_DIGEST),
            keyed_epochs(store),
        )
    };
    let after = retained(&store);
    assert_eq!(
        after.0.first(),
        Some(&claim),
        "Σwork kept from the claimable floor"
    );
    assert_eq!(
        after.0,
        before[1..],
        "exactly the one epoch below the floor went"
    );
    assert_eq!(
        after.1.first(),
        Some(&claim),
        "budgets kept from the claimable floor"
    );
    assert_eq!(after.2, vec![settle]);
    assert_eq!(
        after.3,
        (settle..=WINDOW_RULES.settlement_schedule().epoch_at_height(boundary)).collect::<Vec<_>>(),
        "the chain's opens at or above the settling floor stay; the planted epoch below it does not"
    );
    assert_eq!(
        after.4,
        [vec![claim], vec![settle], vec![settle], vec![price]],
        "settlement, slash-applied, issued draws, R_market: each at its floor"
    );

    // The reads, with the floors the batch used.
    let snap = store.begin_read().expect("read");
    let below = |err: StoreError, table: &str, asked: u64, floor: u64| {
        assert!(
            matches!(
                err,
                StoreError::InvariantViolated(StoreInvariant::EpochReadBelowFloor {
                    table: t, asked: a, floor: f
                }) if t == table && a == e(asked) && f == e(floor)
            ),
            "{table} at {asked} is SI-32, not an absent row: {err}"
        );
    };
    assert!(snap
        .sigma_work(e(claim), floors.claimable)
        .expect("at the floor")
        .is_some());
    below(
        snap.sigma_work(e(claim - 1), floors.claimable).unwrap_err(),
        "archival_sigma_work",
        claim - 1,
        claim,
    );
    below(
        snap.settlement_row(&p, s0, e(claim - 1), floors.claimable)
            .unwrap_err(),
        "archival_settlement",
        claim - 1,
        claim,
    );
    assert_eq!(
        snap.issued_draws(e(settle), floors.settling)
            .expect("at the floor")
            .len(),
        1
    );
    below(
        snap.issued_draws(e(settle - 1), floors.settling)
            .unwrap_err(),
        "archival_issued_draw",
        settle - 1,
        settle,
    );
    below(
        snap.issued_digest(e(settle - 1), floors.settling)
            .unwrap_err(),
        "archival_issued_digest",
        settle - 1,
        settle,
    );
    below(
        snap.slash_applied(&p, s0, e(settle - 1), floors.settling)
            .unwrap_err(),
        "archival_slash_applied",
        settle - 1,
        settle,
    );
    assert_eq!(
        snap.r_market(s0, e(price), floors.pricing)
            .expect("at the floor"),
        Some(RMarket::from_raw(1))
    );
    below(
        snap.r_market(s0, e(price - 1), floors.pricing).unwrap_err(),
        "archival_r_market",
        price - 1,
        price,
    );
    drop(snap);

    // Across the boundary and back, on another block.
    let popped_hash = *b.hashes().last().expect("the boundary's block");
    let out: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
    assert_eq!(out.map(|popped| popped.height.to_raw()), Ok(boundary));
    b.forget(1);
    // Retirement is not journaled. The boundary block's own open writes
    // its epoch's drawable digest through the journal, and pop removes
    // that insert. Nothing the batch retired comes back.
    let mut popped_rows = after.clone();
    let opened_here = WINDOW_RULES.settlement_schedule().epoch_at_height(boundary);
    assert_eq!(popped_rows.3.pop(), Some(opened_here));
    assert_eq!(
        retained(&store),
        popped_rows,
        "pop undoes the boundary's digest and restores no retired row"
    );
    let again = b
        .connect(&store, boundary, boundary, |_| {
            vec![Listed::Spend { fee: FEE }]
        })
        .remove(0);
    assert_ne!(*b.hashes().last().expect("re-connected"), popped_hash);
    assert_eq!(
        again.pruned.expect("the boundary fires again").epochs,
        floors
    );
    assert_eq!(retained(&store), after, "the same, already empty, ranges");
}

/// A session that stubs a per-epoch table's family does not retire it
/// (`ARW-9`), as the slash log: `R_market` planted below its floor stays
/// under a stubbed `RMarket`, while the families the session applies are
/// retired as ever.
#[test]
fn a_stubbed_per_epoch_family_is_not_retired_at_the_boundary() {
    use crate::codec::RMarket;
    use crate::schema::{ARCHIVAL_R_MARKET, ARCHIVAL_SIGMA_WORK};

    let path = tmp("epoch-retire-stub");
    let boundary = EPOCH_RETIRING_BOUNDARY;
    let floors = epoch_floors_at(boundary);
    let price = floors.pricing.kept_from().expect("a floor").to_raw();
    let claim = floors.claimable.kept_from().expect("a floor").to_raw();
    let (mut b, _) = window_chain_to(&path, WINDOW_CAP, boundary - 1);
    plant(&path, |txn| {
        let mut t = txn.open_table(ARCHIVAL_R_MARKET).expect("t");
        t.insert((0, price - 1), RMarket::from_raw(1).encoded().as_encoded())
            .expect("insert");
    });
    let policy = ApplyPolicy::stubbed(&[crate::apply_policy::ArchivalFamily::RMarket])
        .expect("a named family");
    let horizons = Horizons::new(
        WINDOW_RULES.settlement_schedule().blocks(),
        BlockCount::from_raw(WINDOW_CAP),
        WINDOW_RULES.reorg_cap(),
    )
    .expect("cap ≤ retention < epoch");
    let store = ChainStore::with_horizons(&path, policy, horizons).expect("reopen stubbed");
    b.connect(&store, boundary, boundary, |_| Vec::new());
    assert_eq!(
        keyed_epochs(&store)[3],
        vec![price - 1],
        "a stubbed family's rows below its floor stay"
    );
    assert_eq!(
        epochs_of(&store, ARCHIVAL_SIGMA_WORK).first(),
        Some(&claim),
        "an applied family is retired"
    );
}
