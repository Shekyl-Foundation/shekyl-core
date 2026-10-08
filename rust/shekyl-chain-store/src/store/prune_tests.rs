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
//! million bytes of prunable and `pqc_auths` segments. The chains here list
//! **serve credits** whose archival length the fixture sets exactly
//! ([`sized_credit`]: the credit's pruned pass record padded — the one
//! archival region no landed rule reads; CEN-J8/J9/J10, Slice C's verifier,
//! will, and the padding is recorded as debt against them in
//! `docs/FOLLOWUPS.md`, "Padded serve-credit records in the store's prune
//! and bench tests"). Each credit names a persona a [`Sized::Join`] opened
//! in an earlier block (CEN-J4). *Records-was:* until the CEN-I13 flip the
//! bodies were fixture spends with the opaque `fcmp_proof` padded; I13
//! refuses a spend whose declared depth is not the chain's, and a padded
//! proof is nothing I15 verifies, so the free variable moved to the one
//! region still opaque. The chains run under a 100-block epoch with a
//! 50-block undo retention, or a 10-block epoch with a 3-block retention
//! (`Horizons::new`, the regtest knob — the production pair would need ten
//! thousand blocks per boundary). The expected partition is computed by
//! [`Model`], a separate derivation from the lengths the fixture asked for.
//! The fixtures in `connect_fixtures` bound their heights to a `u8`, so this
//! module carries its own header for long chains, with the same shape.

use redb::ReadableTable;
use shekyl_chain_rules::harness::fixture;
use shekyl_chain_rules::{Candidate, FakechainSchedule, RuleSet};
use shekyl_types::{ArchivalLength, BlockCount, BlockHash, BlockHeight, SHARD_LENGTH};
use shekyl_wire::{Ct, Transaction};

use super::connect_fixtures::{
    anchor, batch_root_going_into, candidate, candidate_over, judge_under, root_going_into,
};
use super::store_tests::{cleanup, tmp, TestErr};
use super::*;
use crate::codec::{
    Canonical, PropertyCell, PropertyCellBytes, Raw, SettlementEpochBlocks, UndoLogFloorCell,
};
use crate::ids::TxStorageId;
use crate::schema::{BLOCK_INFO, PROPERTIES, TXS_ARCHIVAL_LEN, UNDO_LOG};

const SEB: u64 = 100;
const RETENTION: u64 = 50;
/// The Fakechain rule set this schedule runs: the genesis rules under a
/// 100-block epoch with a reorg cap that fits the retention (SCW-7) — a
/// regtest wanting a 50-block retention gets a rule set whose cap is at
/// most 50, not a store field the validator defers to (PR #861 review),
/// and one whose epoch is the store's, or `connect` refuses it (SCW-2,
/// `ARW-15`).
const RULES: RuleSet = RuleSet::fakechain(None, pair(SEB, RETENTION));

/// A `(SEB, cap)` pair at compile time; a bad one is a compile error.
const fn pair(seb: u64, cap: u64) -> FakechainSchedule {
    let Some(epoch) = SettlementEpochBlocks::new(seb) else {
        panic!("a zero epoch");
    };
    match FakechainSchedule::new(epoch, BlockCount::from_raw(cap)) {
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

/// A chain under construction: the hashes so far, and the listed
/// transactions to hand each height.
struct Builder {
    hashes: Vec<BlockHash>,
    listed: Vec<Vec<Transaction>>,
    /// The archival length each listed transaction was **asked** for, per
    /// height — the model's input, never re-measured off the bodies. A
    /// join's is [`JOIN_LEN`], the fixture's own, pinned once.
    lens: Vec<Vec<u64>>,
    /// How many personas each height's joins opened: slot `i`'s join opens
    /// [`padder`]`(i)`, and a credit in slot `i` at a later height needs it
    /// (CEN-J4 reads the record off the view the block is judged against,
    /// which a join in the same block has not yet written).
    joins: Vec<usize>,
    /// The rule set every block is judged under and handed to `connect`.
    rules: RuleSet,
}

impl Builder {
    fn new() -> Self {
        Self::under(RULES)
    }

    fn under(rules: RuleSet) -> Self {
        Self {
            hashes: Vec::new(),
            listed: Vec::new(),
            lens: Vec::new(),
            joins: Vec::new(),
            rules,
        }
    }

    /// The personas with a join at a connected height: slots `0..opened`.
    fn opened(&self) -> usize {
        self.joins.iter().sum()
    }

    /// [`Self::connect`] with each height's bodies given by [`Sized`]:
    /// `spec(h)` lists them slot by slot, and `salt` keeps the bodies of two
    /// chains over the same heights apart (a join's key image, a credit's
    /// record head — two identical credits would be one txid).
    fn connect_sized(
        &mut self,
        store: &ChainStore,
        from: u64,
        to: u64,
        salt: u64,
        spec: impl Fn(u64) -> Vec<Sized>,
    ) -> Vec<Connected> {
        let mut opened = self.opened();
        let mut txs: Vec<Vec<Transaction>> = Vec::new();
        let mut lens: Vec<Vec<u64>> = Vec::new();
        let mut joins: Vec<usize> = Vec::new();
        for h in from..=to {
            let listed = spec(h);
            let mut here = 0;
            let bodies = listed
                .iter()
                .enumerate()
                .map(|(i, body)| match *body {
                    Sized::Join => {
                        here += 1;
                        fixture::join_market(fixture::point_at(key_of(salt, h, i)), padder(i))
                    }
                    Sized::Credit(len) => {
                        assert!(
                            i < opened,
                            "height {h} slot {i}: a credit needs its persona's join in an \
                             earlier block (CEN-J4)"
                        );
                        sized_credit(key_of(salt, h, i), i, len)
                    }
                })
                .collect();
            opened += here;
            txs.push(bodies);
            lens.push(listed.iter().map(|body| body.len()).collect());
            joins.push(here);
        }
        let out = self.connect(store, from, to, |h| {
            txs[usize::try_from(h - from).expect("fits")].clone()
        });
        let at = self.lens.len() - txs.len();
        for (i, (lens, joins)) in lens.into_iter().zip(joins).enumerate() {
            self.lens[at + i] = lens;
            self.joins[at + i] = joins;
        }
        out
    }

    /// Forget the top `n` heights after popping them from the store.
    fn forget(&mut self, n: usize) {
        for _ in 0..n {
            self.hashes.pop();
            self.listed.pop();
            self.lens.pop();
            self.joins.pop();
        }
    }

    /// The model of the chain as built.
    fn model(&self) -> Model {
        Model {
            lens: self.lens.clone(),
        }
    }

    /// Connect heights `from..=to` in one batch, handing `listed(h)` at each;
    /// returns each connect's outcome. Every listed transaction is
    /// **anchored** on the chain as built (`connect_fixtures::anchor`: a
    /// recorded reference inside CEN-I11's window, and its slots signed —
    /// a join's; a credit has neither and is listed as given), so a caller
    /// lists bare bodies and reads them back through [`Self::listed`].
    fn connect(
        &mut self,
        store: &ChainStore,
        from: u64,
        to: u64,
        listed: impl Fn(u64) -> Vec<Transaction>,
    ) -> Vec<Connected> {
        let out: Result<Vec<Connected>, TestErr> = store.write(|batch| {
            let view = batch.chain_view();
            let mut out = Vec::new();
            for h in from..=to {
                let previous = self.hashes.last().copied().unwrap_or(BlockHash::NULL);
                let txs: Vec<Transaction> = listed(h)
                    .into_iter()
                    .map(|tx| anchor(&self.hashes, h, tx))
                    .collect();
                let root = batch_root_going_into(&view, h)?;
                let cand = candidate_over(root, h, previous, txs.clone());
                // The identity is the priced block's (`judge_under`).
                let judged = judge_under(&view, cand, &self.rules)?;
                self.hashes.push(judged.block().hash());
                // A bare listing records no asked-for lengths and opens no
                // persona; `connect_sized` overwrites both with the spec it
                // built from.
                self.lens.push(vec![u64::MAX; txs.len()]);
                self.joins.push(0);
                self.listed.push(txs);
                out.push(batch.connect(judged, self.rules)?);
            }
            Ok(out)
        });
        out.expect("chain connects")
    }
}

/// A key no other body in these chains draws, built from the chain's salt,
/// the height and the slot: a join's key image is `k·G` over it, and a
/// credit's pass record opens with its bytes.
fn key_of(salt: u64, height: u64, index: usize) -> u64 {
    1_000 + salt * 1_000_000 + height * 8 + u64::try_from(index).expect("fits")
}

/// What a sized height lists, slot by slot. Slot `i`'s persona is
/// [`padder`]`(i)`: a `Join` there opens it, a `Credit` there names it.
#[derive(Clone, Copy)]
enum Sized {
    /// The slot's persona joins ([`fixture::join_market`], a bond post
    /// funded by a fixture spend — CEN-I13 judges the Spend class, not the
    /// BondPost one, so the post connects as it did before the flip): the
    /// record a credit in a **later** block names (CEN-J4). Its archival
    /// length is the fixture's, [`JOIN_LEN`], not a free variable.
    Join,
    /// A serve credit for the slot's persona whose archival length is
    /// exactly this ([`sized_credit`]).
    Credit(u64),
}

impl Sized {
    /// The archival length the model takes for this body.
    const fn len(self) -> u64 {
        match self {
            Self::Join => JOIN_LEN,
            Self::Credit(len) => len,
        }
    }
}

const fn credit(len: u64) -> Sized {
    Sized::Credit(len)
}

/// The fixture-persona tag of slot `i`. Two slots is the widest listing
/// here, and two credits in one block must name two personas (CEN-G7, one
/// `(P, shard, E)` per block).
fn padder(slot: usize) -> [u8; 32] {
    [0x50 + u8::try_from(slot).expect("a slot index"); 32]
}

/// The archival length of a [`Sized::Join`] once anchored and signed as the
/// builder will — `|pqc_auths| + |prunable|` of the fixture's bond post —
/// pinned here and read off the probe once
/// ([`the_join_length_the_model_assumes_is_the_fixtures`]). The specs are
/// derived from it: a join stands where a 100 000-byte spend stood before
/// the CEN-I13 flip, and [`GIVEBACK`] is what the spend's successors carry
/// so every running total from block 9 on is unchanged.
const JOIN_LEN: u64 = 11_456;

/// Per credit, what the four credits after a join carry over 100 000 bytes
/// to give back the join's shortfall: `(100 000 − JOIN_LEN) / 4`, exact.
const GIVEBACK: u64 = (100_000 - JOIN_LEN) / 4;
const _: () = assert!(
    (100_000 - JOIN_LEN).is_multiple_of(4),
    "the join's shortfall must split evenly over four credits"
);

/// Where the probe anchors a join: any height with a reference beneath it,
/// over a chain of null hashes. Anchoring signs the `pqc_auths` slots,
/// which is why the length is measured after it.
const PROBE_HEIGHT: u64 = 20;

fn anchored(tx: &Transaction) -> Transaction {
    let hashes = [BlockHash::NULL; 21];
    anchor(&hashes, PROBE_HEIGHT, tx.clone())
}

#[test]
fn the_join_length_the_model_assumes_is_the_fixtures() {
    let join = anchored(&fixture::join_market(fixture::point_at(1), padder(0)));
    assert_eq!(
        join.archival_len().to_raw(),
        JOIN_LEN,
        "the fixture join's archival length moved — re-derive every table in this module"
    );
}

/// A serve credit for `padder(slot)` whose archival length is exactly
/// `len`: [`fixture::serve_credit_only`] with its one pruned pass record
/// padded until the length is `len`. The record opens with `key`'s bytes
/// so no two credits in these chains are one txid. **The record is what
/// CEN-J8/J9/J10 will verify** (Slice C); until they land its bytes are the
/// fixture's free variable, and the debt is recorded against them
/// (`docs/FOLLOWUPS.md`, "Padded serve-credit records in the store's prune
/// and bench tests"). A credit has no reference and no `pqc_auths`
/// (CEN-H20), so anchoring leaves it as it is and the length is read off
/// the body itself.
fn sized_credit(key: u64, slot: usize, len: u64) -> Transaction {
    let mut tx = fixture::serve_credit_only(padder(slot));
    let head = key.to_le_bytes();
    let mut pad: u64 = 1;
    // The record's length prefix is a varint, so a pad change can move the
    // total by one more byte than asked; two corrections always land a
    // length this far from a width edge.
    for _ in 0..4 {
        let Ct::Fcmp {
            prunable: Some(prunable),
            ..
        } = &mut tx.ct
        else {
            unreachable!("fixture::serve_credit_only carries its RF-D1 region");
        };
        let mut record = head.to_vec();
        record.resize(head.len() + usize::try_from(pad).expect("fits"), 0xA5);
        prunable.serve_credit_pruned = vec![record];
        let got = tx.archival_len().to_raw();
        if got == len {
            return tx;
        }
        pad = (pad + len)
            .checked_sub(got)
            .expect("the asked length is above the unpadded credit's");
    }
    panic!("no padding lands archival length {len}");
}

/// The archival length of the credit with the largest archival length
/// CEN-H3 admits: its weight is exactly [`fixture::max_tx_weight`]. A
/// credit's weight is its serialized length (no Bp+ clawback: no outputs),
/// and the prefix does not move with the record's length, so the gap to the
/// bound is all archival. One probe, shared by the specs. The per-record
/// ceiling (`ARCHIVAL_SERVE_CREDIT_PRUNED_MAX_BYTES`, 1 053 185) is a
/// decode bound the H3 weight bound sits far under.
fn max_len() -> u64 {
    let base: u64 = 100_000;
    let weight = sized_credit(1, 0, base).weight();
    let len = base
        + u64::try_from(fixture::max_tx_weight() - weight).expect("under the bound at the base");
    assert_eq!(
        sized_credit(1, 0, len).weight(),
        fixture::max_tx_weight(),
        "the maximal credit sits exactly on CEN-H3's bound"
    );
    len
}

/// `SHT-Q2` computed the slow way, from the lengths the fixture asked for:
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
        .tx_prunable(TxStorageId::from_raw(id))
        .expect("read")
    {
        AtIndex::Recorded(Prunable::Retained(_)) => Some(true),
        AtIndex::Recorded(Prunable::Discarded) => Some(false),
        AtIndex::BeyondCount => None,
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

/// The bodies of the 100-block chain, one per height at 5–34 and 250:
/// slot 0's join at 5 (the earliest a referencing body can sit,
/// `FCMP_REFERENCE_BLOCK_MIN_AGE`), then credits for it. Thirty bodies at
/// heights 5–34 total exactly `W` — `JOIN_LEN + 4·(100 000 + GIVEBACK) +
/// 25·100 000 = 3 000 000` — so shard 0 closes at 34, as it did when all
/// thirty were 100 000-byte spends; the running total is the old one from
/// block 9 on. One more credit at 250 opens shard 1, which has not closed
/// by 300.
fn spec_300(h: u64) -> Vec<Sized> {
    match h {
        5 => vec![Sized::Join],
        6..=9 => vec![credit(100_000 + GIVEBACK)],
        10..=34 | 250 => vec![credit(100_000)],
        _ => Vec::new(),
    }
}

/// The chain every test here starts from: heights `0..=300` under a
/// 100-block epoch, listed by [`spec_300`]. Storage ids: one coinbase at each
/// of 0–4 (ids 0–4), a coinbase and a body at each of 5–34 (ids 5–64),
/// coinbases from 35 (id 65 on), block 250's credit is id 281.
fn chain_to_300(path: &std::path::Path) -> (ChainStore, Builder, Connected, Connected) {
    let store =
        ChainStore::with_horizons(path, ApplyPolicy::default(), horizons()).expect("create");
    let mut b = Builder::new();
    b.connect_sized(&store, 0, 199, 0, spec_300);
    let at_200 = b.connect_sized(&store, 200, 200, 0, spec_300).remove(0);
    b.connect_sized(&store, 201, 299, 0, spec_300);
    let at_300 = b.connect_sized(&store, 300, 300, 0, spec_300).remove(0);
    (store, b, at_200, at_300)
}

#[test]
fn the_boundary_batch_discards_closed_shards_and_retires_undo_rows() {
    let path = tmp("prune-boundary");
    let (store, b, at_200, at_300) = chain_to_300(&path);

    // Epoch 2's boundary: shard 0 closed at 34 (the running total reached
    // `W` there), inside `[0, 100)`, so `D(2)` is shard 0; the undo floor
    // rises to 200 − 50.
    let pruned_200 = at_200.pruned.expect("a boundary");
    assert_eq!(pruned_200.shards(), 0..1, "D(2) is shard 0");
    assert_eq!(pruned_200.undo_floor, BlockHeight::from_raw(150));

    // Epoch 3's boundary: `[0, 200)` names shard 0 again — already empty —
    // and shard 1 has not closed.
    let pruned_300 = at_300.pruned.expect("a boundary");
    assert_eq!(pruned_300.shards(), 0..1, "D(3) is shard 0");
    assert_eq!(pruned_300.undo_floor, BlockHeight::from_raw(250));

    // Shard 0's bodies are gone — every transaction starting below `W`, the
    // coinbases among them — and shard 1's are held; the hash rows stand (a
    // read answers *discarded*, never a fault). Id 65 is block 35's
    // coinbase, the first transaction starting at `W`.
    for id in [0, 5, 6, 64] {
        assert_eq!(prunable_state(&store, id), Some(false), "id {id} discarded");
    }
    for id in [65, 66, 281, 300] {
        assert_eq!(prunable_state(&store, id), Some(true), "id {id} retained");
    }
    assert_eq!(body_states(&store), not(&b.model().discarded(SEB, 300)));
    {
        let snap = store.begin_read().expect("read");
        // Block 5's join as listed — anchored and signed by the builder —
        // not the bare fixture, whose hash it no longer shares. A join is
        // 4-part, so it has the pqc region the prune discards by shard.
        let early = snap
            .tx_record(&b.listed[5][0].hash())
            .expect("read")
            .expect("recorded");
        assert_eq!(
            early.pqc_auths,
            Some(PqcAuths::Discarded),
            "shard 0's pqc region went with it"
        );
        assert!(early.pqc_auth_hash.is_some(), "the hash row is permanent");
        // Block 250's credit is 3-part (CEN-H20): no pqc region to hold or
        // discard; its archival good is the prunable region alone, held
        // (id 281 above).
        let late = snap
            .tx_record(&b.listed[250][0].hash())
            .expect("read")
            .expect("recorded");
        assert_eq!(late.pqc_auths, None, "a credit carries no pqc region");
        assert_eq!(late.pqc_auth_hash, None, "and no hash row for one");
        assert_eq!(late.archival_len.to_raw(), 100_000, "as asked");
    }

    // The undo journal keeps exactly `[floor, tip]`.
    assert_eq!(undo_floor_cell(&store), Some(250));
    let rows = undo_rows(&store);
    assert_eq!(rows.first(), Some(&250));
    assert_eq!(rows.last(), Some(&300));
    assert_eq!(rows.len(), 51);
    assert!(store.connect_state().is_live());
    cleanup(&path);
}

/// Retained-ness from the model's discarded-ness.
fn not(discarded: &[bool]) -> Vec<bool> {
    discarded.iter().map(|d| !d).collect()
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
    cleanup(&path);
}

#[test]
fn a_pop_below_the_undo_floor_is_a_refusal_not_si6() {
    let path = tmp("prune-pop-floor");
    let (store, _b, _, _) = chain_to_300(&path);
    // 300 down to 250 have rows: fifty-one pops land.
    for expected in (250..=300).rev() {
        let out: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
        assert_eq!(out.map(|p| p.height.to_raw()), Ok(expected));
    }
    assert_eq!(tip(&store), 249);
    let out: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
    assert_eq!(
        out,
        Err(TestErr::Store(
            StoreError::from(StoreCannot::PopBelowFloor {
                tip: 249,
                floor: 250
            })
            .to_string()
        )),
        "below the retained journal is a capability limit, loud"
    );
    assert!(store.connect_state().is_live(), "a refusal is not a halt");
    cleanup(&path);
}

/// §4, §8: a reorg across the boundary block reconnects some block at
/// `E·SEB`, and the hook fires again. The ranges are already empty and the
/// floor is monotone, so the store is the same store.
#[test]
fn the_hook_is_idempotent_across_a_boundary_reorg() {
    let path = tmp("prune-idempotent");
    let (store, mut b, _, _) = chain_to_300(&path);
    let before = (undo_floor_cell(&store), undo_rows(&store));

    let out: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
    assert_eq!(out.map(|p| p.height.to_raw()), Ok(300));
    b.forget(1);
    // A different block at 300: a small credit (slot 0's persona joined at
    // 5) makes its hash differ.
    let again = b
        .connect_sized(&store, 300, 300, 0, |_| vec![credit(1_000)])
        .remove(0);
    let pruned = again.pruned.expect("the boundary fires again");
    assert_eq!(pruned.shards(), 0..1, "the same D(3), already empty");
    assert_eq!(pruned.undo_floor, BlockHeight::from_raw(250), "monotone");
    assert_eq!((undo_floor_cell(&store), undo_rows(&store)), before);
    assert_eq!(prunable_state(&store, 0), Some(false));
    assert_eq!(prunable_state(&store, 65), Some(true));
    cleanup(&path);
}

/// `h_scarce` (§4): the `close_height` of the last shard the calendar has
/// discarded at `tip` — `PDM-Q5`'s band-2 edge, chain-named, no presence
/// read. `None` in epochs 0–1 and before any shard has closed.
#[test]
fn h_scarce_is_the_last_discarded_shards_close_height() {
    let path = tmp("prune-h-scarce");
    let (store, b, _, _) = chain_to_300(&path);
    type Edges = (Option<u64>, Option<u64>, Option<u64>);
    let out: Result<Edges, TestErr> = store.write(|batch| {
        Ok((
            batch.h_scarce(150)?,
            batch.h_scarce(250)?,
            batch.h_scarce(300)?,
        ))
    });
    let (e1, e2, e3) = out.expect("reads");
    assert_eq!(
        store.begin_read().expect("read").h_scarce().expect("read"),
        Some(BlockHeight::from_raw(34)),
        "the snapshot's read at the recorded tip agrees"
    );
    assert_eq!(e1, None, "epoch 1: nothing can have discarded");
    // Shard 0's running total reaches `W` at height 34, whose credit ends
    // exactly on it.
    assert_eq!(e2, Some(34), "epoch 2: shard 0 closed at height 34");
    assert_eq!(e3, Some(34), "epoch 3: still shard 0, shard 1 is open");
    let model = b.model();
    assert_eq!(
        (e1, e2, e3),
        (
            model.h_scarce(SEB, 150),
            model.h_scarce(SEB, 250),
            model.h_scarce(SEB, 300)
        )
    );
    cleanup(&path);
}

/// The Fakechain set for the ten-block schedule the `SHT-Q2` boundary and
/// SI-13 / SI-24 tests run.
const SHORT: RuleSet = RuleSet::fakechain(None, pair(SHORT_SEB, 3));

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

fn short_store(path: &std::path::Path) -> ChainStore {
    ChainStore::with_horizons(path, ApplyPolicy::default(), short_horizons()).expect("open")
}

/// The ten-block chain's bodies, two slots wide, `max` the [`max_len`]
/// length. Block 5 opens both slots' personas; blocks 6–9 give back the two
/// joins' shortfall — `2·(100 000 − JOIN_LEN) = 8·GIVEBACK` — so the
/// running total through 9 is `1 000 000`, the same as when every body was
/// a 100 000-byte spend, and every total below is the one it was:
///
/// | Heights | Bodies | Running total through the last | |
/// | --- | --- | --- | --- |
/// | 5 | 2 joins | 2 × `JOIN_LEN` | |
/// | 6–9 | 2 × (100 000 + `GIVEBACK`) | 1 000 000 | |
/// | 10–19 | 2 × 100 000 | 3 000 000 = `W` | shard 0 closes at 19, exactly on the boundary |
/// | 20 | 1 × 100 000 | 3 100 000 | starts **exactly at** `W`: shard 1 |
/// | 21–34 | 2 × 100 000 | 5 900 000 | |
/// | 35 | 1 × `max` | 5 900 000 + `max` | starts in shard 1, ends past `2·W`: shard 1 closes at 35 |
/// | 36–46 | 2 × 140 000 | 8 980 000 + `max` | shard 2 closes at 46 |
///
/// Storage ids: blocks 0–4 one each (0–4); 5–19 three each (block 19:
/// 47–49); block 20: 50, 51; 21–34 three each (block 34: 91–93); block 35:
/// 94 and the maximal credit 95; block 36's coinbase is 96.
///
/// Boundaries every ten blocks: `D(3)` at 30 is shard 0, `D(5)` at 50
/// shard 1, `D(6)` at 60 shards 1 **and** 2 — two boundaries in one batch.
fn short_spec(max: u64) -> impl Fn(u64) -> Vec<Sized> {
    move |h| match h {
        5 => vec![Sized::Join, Sized::Join],
        6..=9 => vec![credit(100_000 + GIVEBACK); 2],
        10..=19 | 21..=34 => vec![credit(100_000); 2],
        20 => vec![credit(100_000)],
        35 => vec![credit(max)],
        36..=46 => vec![credit(140_000); 2],
        _ => Vec::new(),
    }
}

/// Every stored length is the one asked for — the model's input is the
/// store's — and the cumulative cell is the running total at each height.
/// The coinbase carries no archival good and writes no row.
#[test]
fn the_store_records_each_length_and_the_running_total() {
    let path = tmp("prune-lengths");
    let store = short_store(&path);
    let mut b = Builder::under(SHORT);
    b.connect_sized(&store, 0, 21, 0, short_spec(0));
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
                "id {id}: present ⇔ > 0, and the length asked"
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
        // Through 21: `W`, block 20's credit, block 21's two.
        assert_eq!(through, 3_300_000);
    }
    cleanup(&path);
}

/// Scope 4 (a): a transaction starting **exactly** at `k·W` opens shard
/// `k`. Block 19's credits end on `W`; block 20's coinbase and credit start
/// on it. `D(3)` discards the first and keeps the second.
#[test]
fn a_transaction_starting_exactly_at_k_w_opens_shard_k() {
    let path = tmp("prune-exact-kw");
    let store = short_store(&path);
    let mut b = Builder::under(SHORT);
    let out = b.connect_sized(&store, 0, 30, 0, short_spec(0));
    let pruned = out[30].pruned.expect("a boundary");
    assert_eq!(pruned.shards(), 0..1, "D(3) is shard 0");
    for id in [47, 48, 49] {
        assert_eq!(prunable_state(&store, id), Some(false), "id {id}: below W");
    }
    for id in [50, 51] {
        assert_eq!(
            prunable_state(&store, id),
            Some(true),
            "id {id}: starts at W"
        );
    }
    let snap = store.begin_read().expect("read");
    assert_eq!(snap.shard_storage_ids(0..1).expect("read"), 0..50);
    assert_eq!(
        snap.shard_storage_ids(0..1).expect("read"),
        b.model().ids_of(0)
    );
    drop(snap);
    assert_eq!(
        body_states(&store),
        not(&b.model().discarded(SHORT_SEB, 30))
    );
    cleanup(&path);
}

/// Scope 4 (b): the largest transaction CEN-H3 admits, straddling `2·W`,
/// belongs to the shard it **starts** in and closes that shard; the overshoot
/// is under one transaction, so under `W`.
#[test]
fn a_maximal_transaction_straddling_a_boundary_belongs_to_the_shard_it_starts_in() {
    let path = tmp("prune-straddle");
    let store = short_store(&path);
    let max = max_len();
    let mut b = Builder::under(SHORT);
    let out = b.connect_sized(&store, 0, 50, 0, short_spec(max));
    let model = b.model();
    // It starts at 5 900 000 and ends past 6 000 000.
    let (_, start, len) = model.txs()[95];
    assert_eq!((start, len), (5_900_000, max));
    assert!(
        start < 2 * Model::W && start + len > 2 * Model::W,
        "it straddles 2·W"
    );
    let pruned = out[50].pruned.expect("a boundary");
    assert_eq!(pruned.shards(), 1..2, "D(5) is shard 1");
    assert_eq!(
        prunable_state(&store, 95),
        Some(false),
        "discarded with shard 1"
    );
    assert_eq!(
        prunable_state(&store, 96),
        Some(true),
        "block 36 opens shard 2"
    );
    let out: Result<Option<u64>, TestErr> = store.write(|batch| Ok(batch.h_scarce(50)?));
    assert_eq!(
        out,
        Ok(Some(35)),
        "shard 1 closed at the maximal credit's height"
    );
    assert_eq!(body_states(&store), not(&model.discarded(SHORT_SEB, 50)));
    cleanup(&path);
}

/// Scope 4 (c): two shards closing inside one boundary's window are one
/// batch — `D(6)` is shards 1 and 2, contiguous ids — and every boundary
/// from 20 to 70 matches the model: the discard set, every id's body, and
/// `h_scarce`.
#[test]
fn consecutive_boundaries_and_every_batch_match_the_model() {
    let path = tmp("prune-consecutive");
    let store = short_store(&path);
    let max = max_len();
    let mut b = Builder::under(SHORT);
    b.connect_sized(&store, 0, 19, 0, short_spec(max));
    for boundary in (20..=70).step_by(10) {
        let from = boundary - 9;
        let out = b.connect_sized(&store, from.max(20), boundary, 0, short_spec(max));
        let pruned = out.last().expect("connected").pruned.expect("a boundary");
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
    // The hand-read rows of the table above.
    let model = b.model();
    assert_eq!(
        (
            model.close_height(0),
            model.close_height(1),
            model.close_height(2)
        ),
        (Some(19), Some(35), Some(46))
    );
    assert_eq!(model.discards_at(SHORT_SEB, 6), vec![1, 2], "consecutive");
    cleanup(&path);
}

/// Scope 4 (d): a reorg that pops back across a shard boundary and connects
/// a different branch leaves the store exactly as a store that only ever
/// saw the new branch: same discard sets, same bodies, same `h_scarce`. The
/// popped heights' length rows and cumulative cells go with their blocks
/// (journaled inserts).
#[test]
fn a_reorg_back_across_a_shard_boundary_is_the_new_branchs_partition() {
    let max = max_len();
    let spec = short_spec(max);
    // The new branch: shard 2 closes at 47 instead of 46.
    let branch = |h: u64| match h {
        46 => vec![credit(100_000)],
        47 => vec![credit(100_000); 2],
        _ => Vec::new(),
    };

    let path = tmp("prune-reorg");
    let store = short_store(&path);
    let mut b = Builder::under(SHORT);
    b.connect_sized(&store, 0, 48, 0, &spec);
    assert_eq!(b.model().close_height(2), Some(46));
    // Pop 48, 47, 46: the running total drops back below 3·W.
    for expected in [48, 47, 46] {
        let out: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
        assert_eq!(out.map(|p| p.height.to_raw()), Ok(expected));
    }
    b.forget(3);
    assert_eq!(b.model().close_height(2), None, "shard 2 is open again");
    let mut reorged = Vec::new();
    for boundary in [50, 60, 70] {
        let from = if boundary == 50 { 46 } else { boundary - 9 };
        let out = b.connect_sized(&store, from, boundary, 1, branch);
        reorged.push(out.last().expect("connected").pruned.expect("a boundary"));
    }
    let reorged_states = body_states(&store);
    let reorged_scarce = store.begin_read().expect("read").h_scarce().expect("read");

    let fresh_path = tmp("prune-reorg-fresh");
    let fresh = short_store(&fresh_path);
    let mut f = Builder::under(SHORT);
    f.connect_sized(&fresh, 0, 45, 0, &spec);
    let mut straight = Vec::new();
    for boundary in [50, 60, 70] {
        let from = if boundary == 50 { 46 } else { boundary - 9 };
        let out = f.connect_sized(&fresh, from, boundary, 1, branch);
        straight.push(out.last().expect("connected").pruned.expect("a boundary"));
    }
    assert_eq!(b.hashes, f.hashes, "the same chain");
    assert_eq!(reorged, straight, "the same discard sets and floors");
    assert_eq!(reorged_states, body_states(&fresh), "the same bodies");
    assert_eq!(
        reorged_scarce,
        fresh.begin_read().expect("read").h_scarce().expect("read")
    );
    assert_eq!(f.model().close_height(2), Some(47));
    assert_eq!(
        reorged[2].shards(),
        2..3,
        "D(7) is the new branch's shard 2"
    );
    assert_eq!(reorged_scarce, Some(BlockHeight::from_raw(47)));
    assert_eq!(reorged_states, not(&f.model().discarded(SHORT_SEB, 70)));
    cleanup(&path);
    cleanup(&fresh_path);
}

/// Scope 4 (e): membership is the same question on a pruned store and an
/// unpruned one. Every shard's id range is read off the cumulative cell and
/// the length rows, which no prune deletes, so the answer before the
/// boundary that discards shard 2 and after it is one answer — and the
/// model's.
#[test]
fn pruned_and_unpruned_stores_place_every_shard_alike() {
    let path = tmp("prune-membership");
    let store = short_store(&path);
    let max = max_len();
    let mut b = Builder::under(SHORT);
    b.connect_sized(&store, 0, 59, 0, short_spec(max));
    let ranges = |store: &ChainStore| -> Vec<core::ops::Range<u64>> {
        let snap = store.begin_read().expect("read");
        (0..3)
            .map(|k| snap.shard_storage_ids(k..k + 1).expect("read"))
            .collect()
    };
    let unpruned = ranges(&store);
    let shard_2 = unpruned[2].clone();
    assert!(
        shard_2
            .clone()
            .all(|id| prunable_state(&store, id) == Some(true)),
        "shard 2 is held before 60"
    );
    b.connect_sized(&store, 60, 60, 0, short_spec(max));
    assert!(
        shard_2
            .clone()
            .all(|id| prunable_state(&store, id) == Some(false)),
        "and discarded at 60, or this test compares two unpruned stores"
    );
    assert_eq!(
        ranges(&store),
        unpruned,
        "the pruned store places every shard alike"
    );
    let model = b.model();
    assert_eq!(
        unpruned,
        (0..3).map(|k| model.ids_of(k)).collect::<Vec<_>>()
    );
    cleanup(&path);
}

/// Build the ten-block chain to `to` and close the store, for a raw plant.
/// The corruption tests do not need the exact maximal credit, so height 35
/// lists a 140 000-byte one and skips the probe.
fn short_chain_to(path: &std::path::Path, to: u64) -> Builder {
    let store = short_store(path);
    let mut b = Builder::under(SHORT);
    b.connect_sized(&store, 0, to, 0, short_spec(140_000));
    b
}

/// Connect `height` on the reopened ten-block store with nothing listed.
fn connect_short(
    path: &std::path::Path,
    b: &Builder,
    height: u64,
) -> (ChainStore, Result<Connected, TestErr>) {
    let store = short_store(path);
    let previous = b.hashes.last().copied().expect("parent");
    let cand = candidate_on(&store, height, previous, Vec::new());
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge_under(&view, cand, &SHORT)?, SHORT)?)
    });
    (store, out)
}

/// A later `block_info` row whose listed total is below an earlier one's is
/// SI-13. The boundary at 30 walks block 19 to find where shard 1 opens; a
/// decrease there must not commit the boundary with `D(E)` skipped.
#[test]
fn a_decreasing_listed_total_refuses_the_boundary() {
    let path = tmp("prune-monotone");
    let b = short_chain_to(&path, 29);
    // Listed through 18: 14 blocks of two bodies.
    plant_listed(&path, 19, 28 - 5);
    let (store, out) = connect_short(&path, &b, 30);
    assert!(
        out.is_err(),
        "the boundary does not commit over a decreasing total"
    );
    assert_eq!(tip(&store), 29);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(30),
            row: StoreInvariant::FoldNotMonotone {
                cell: "block_info.cumulative_tx_count",
                height: 19,
            },
        }
    );
    cleanup(&path);
}

/// The decrease the coinbase term can mask: listed `28 → 27` from height
/// 18 to 19 derives to storage ids `47 → 47` — an empty block, not an
/// inverted one. SI-13 is a property of the listed fold and is checked on
/// the raw samples (Copilot, PR #861).
#[test]
fn a_decrease_smaller_than_the_coinbase_term_still_refuses_the_boundary() {
    let path = tmp("prune-monotone-masked");
    let b = short_chain_to(&path, 29);
    plant_listed(&path, 19, 27);
    let (store, out) = connect_short(&path, &b, 30);
    assert!(
        out.is_err(),
        "47 → 47 in storage ids hides 28 → 27 in the fold"
    );
    assert_eq!(tip(&store), 29);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(30),
            row: StoreInvariant::FoldNotMonotone {
                cell: "block_info.cumulative_tx_count",
                height: 19,
            },
        }
    );
    cleanup(&path);
}

/// SI-13 on the archival fold: `D(4)` at 40 samples `C(10)` and `C(30)` —
/// rows 9 and 29 — and row 29 zeroed is below row 9. The fault names the
/// row that decreased, as the listed fold's does.
#[test]
fn a_decreasing_archival_total_refuses_the_boundary() {
    let path = tmp("prune-archival-monotone");
    let b = short_chain_to(&path, 39);
    plant_archival(&path, 29, 0);
    let (store, out) = connect_short(&path, &b, 40);
    assert!(out.is_err());
    assert_eq!(tip(&store), 39);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(40),
            row: StoreInvariant::FoldNotMonotone {
                cell: "block_info.cumulative_archival_len",
                height: 29,
            },
        }
    );
    cleanup(&path);
}

/// SI-13 across the whole run the boundary reads, not at its samples
/// (Copilot, PR #910). Cells 13–16 are raised together by 900 000 with
/// their length rows untouched: each shifted cell still equals its parent
/// plus its rows, so SI-24 holds at every block inside the run, and the
/// fold now reaches `W` twice — at 15 (`2 900 000 → 3 100 000`, a second,
/// spurious crossing) and at 19. The endpoints `C(0)` and `C(20)` are
/// true. A search that trusts monotonicity can settle on 15 and place
/// shard 1's first id inside block 15. The boundary at 30 must halt on the
/// decrease at 17 (`3 300 000 → 2 600 000`) instead, before any discard.
#[test]
fn a_shifted_run_between_two_samples_refuses_the_boundary() {
    let path = tmp("prune-archival-run");
    let b = short_chain_to(&path, 29);
    for height in 13..=16 {
        plant_info(&path, height, |info| {
            info.cumulative_archival_len =
                ArchivalLength::from_raw(info.cumulative_archival_len.to_raw() + 900_000);
        });
    }
    let (store, out) = connect_short(&path, &b, 30);
    assert!(out.is_err(), "the boundary does not commit over the run");
    assert_eq!(tip(&store), 29);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(30),
            row: StoreInvariant::FoldNotMonotone {
                cell: "block_info.cumulative_archival_len",
                height: 17,
            },
        }
    );
    assert!(
        body_states(&store).iter().all(|&held| held),
        "no body was discarded"
    );
    cleanup(&path);
}

/// SI-24 at every block the descent passes (Copilot, PR #910): a shift
/// that starts at one block and persists through `hi` keeps the fold
/// monotone everywhere and agrees with the rows at every block above its
/// start. Cells 25–39 are raised by 1 200 000, rows untouched, so `C(30)`
/// reads 6 100 000 instead of 4 900 000 and `D(4)` at 40 would name shards
/// `0..2` — discarding blocks 20–29, which are in shard 1, still open. The
/// descent checks block 25 against its parent: `3 900 000 + 200 000 =
/// 4 100 000` against a cell of 5 300 000, before anything is discarded.
#[test]
fn a_shift_that_persists_through_the_window_refuses_the_boundary() {
    let path = tmp("prune-archival-persist");
    let b = short_chain_to(&path, 39);
    for height in 25..=39 {
        plant_info(&path, height, |info| {
            info.cumulative_archival_len =
                ArchivalLength::from_raw(info.cumulative_archival_len.to_raw() + 1_200_000);
        });
    }
    let (store, out) = connect_short(&path, &b, 40);
    assert!(out.is_err(), "the boundary does not commit over the shift");
    assert_eq!(tip(&store), 39);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(40),
            row: StoreInvariant::ArchivalLengthsDisagree {
                height: 25,
                rows: 4_100_000,
                cell: 5_300_000,
            },
        }
    );
    // Blocks 20–29: ids 50–78, shard 1.
    for id in 50..79 {
        assert_eq!(prunable_state(&store, id), Some(true), "id {id} is held");
    }
    cleanup(&path);
}

/// SI-24: the boundary at 30 sums block 19's length rows to place `W`, and
/// a row that no longer adds up to the block's cell refuses the boundary
/// rather than place it by numbers the fold does not support.
#[test]
fn a_length_row_that_disagrees_with_the_fold_refuses_the_boundary() {
    let path = tmp("prune-archival-rows");
    let b = short_chain_to(&path, 29);
    // Id 48 is block 19's first credit.
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        {
            let mut table = txn.open_table(TXS_ARCHIVAL_LEN).expect("table");
            let encoded = ArchivalLength::from_raw(99_999).encoded();
            table.insert(48u64, encoded.as_encoded()).expect("plant");
        }
        txn.commit().expect("commit");
    }
    let (store, out) = connect_short(&path, &b, 30);
    assert!(out.is_err());
    assert_eq!(tip(&store), 29);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(30),
            row: StoreInvariant::ArchivalLengthsDisagree {
                height: 19,
                rows: 2_999_999,
                cell: 3_000_000,
            },
        }
    );
    cleanup(&path);
}

/// Replace `block_info[height].cumulative_tx_count`. A raw write: the
/// store's own connect never records a decrease.
fn plant_listed(path: &std::path::Path, height: u64, listed: u64) {
    plant_info(path, height, |info| info.cumulative_tx_count = listed);
}

/// Replace `block_info[height].cumulative_archival_len`, likewise.
fn plant_archival(path: &std::path::Path, height: u64, len: u64) {
    plant_info(path, height, |info| {
        info.cumulative_archival_len = ArchivalLength::from_raw(len);
    });
}

fn plant_info(
    path: &std::path::Path,
    height: u64,
    edit: impl FnOnce(&mut crate::codec::BlockInfo),
) {
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
    cleanup(&path);
}

/// SPR-4: the persisted floor and the journal's first key record one fact,
/// and the redundancy is a check that can fail. A journal whose lowest row
/// is not the floor's is SI-6 at `pop` — before any refusal is read off
/// either — and at the next boundary after the retire.
#[test]
fn a_journal_whose_first_row_is_not_the_floor_is_si6_at_pop_and_at_the_boundary() {
    let path = tmp("prune-floor-mismatch");
    let (store, _b, _, _) = chain_to_300(&path);
    // Rows [250, 300] stand and the cell says 250. Remove row 250 by hand.
    drop(store);
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        {
            let mut table = txn.open_table(UNDO_LOG).expect("undo_log");
            table
                .remove(250u64)
                .expect("remove")
                .expect("row 250 stood");
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
                height: 300,
                fault: UndoFault::FloorMismatch {
                    first: 251,
                    floor: 250
                },
            })
            .to_string()
        )),
        "the cell and the table disagree: SI-6, not a capability limit"
    );
    assert!(!store.connect_state().is_live(), "the writer halts on SI-6");
    cleanup(&path);

    // The same gap, met by the boundary batch: connect to 399 under a
    // clean journal, open the gap at the floor that 400 will establish
    // (350), then connect 400.
    let path = tmp("prune-floor-mismatch-boundary");
    let (store, mut b2, _, _) = chain_to_300(&path);
    b2.connect(&store, 301, 399, |_| Vec::new());
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
    let previous = *b2.hashes.last().expect("399 connected");
    let cand = candidate_on(&store, 400, previous, Vec::new());
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge_under(&view, cand, &RULES)?, RULES)?)
    });
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
        "the retire leaves a first key that is not the floor: SI-6"
    );
    assert_eq!(tip(&store), 399, "the boundary block did not connect");
    assert!(!store.connect_state().is_live());
    cleanup(&path);
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
    cleanup(&path);
}

/// SCW-2 at connect (DRS-E4 `ARW-15`): the in-force set's settlement epoch
/// is the pinned one, or the verdict's archival rows — join epochs,
/// serve-credit windows, the close — were judged under a geometry the file
/// does not hold. A set whose cap the retention covers but whose epoch is
/// another is refused at its first block with the pair named; the header
/// open refused the same mismatch against the epoch the caller named.
#[test]
fn a_set_naming_another_epoch_is_refused_at_connect() {
    let other = RuleSet::fakechain(None, pair(200, RETENTION));
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
    cleanup(&path);
}

/// `Horizons::under` is the set's own pair read back: the genesis set gives
/// the production horizons, and a Fakechain set under a shortened schedule
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
    let short = RuleSet::fakechain(None, pair(512, 64));
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
/// must still place its transactions **inside** the domain, exactly as an
/// archival node does.
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
    let store =
        ChainStore::with_horizons(&path, ApplyPolicy::default(), horizons()).expect("create");
    let mut b = Builder::new();
    // A mixed chain ([`spec_300`] to 200): a join (4-part) and credits
    // (3-part) filling shard 0 (discarded at the epoch-2 boundary) and empty
    // blocks — the coinbase-only case — everywhere else, those from 35 in
    // shard 1 (retained). Recorded at 199, before the first discard.
    b.connect_sized(&store, 0, 199, 0, spec_300);

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
                    "a listed join or credit carries archival good"
                );
            }
        }
    }

    // The boundary that discards shard 0.
    let at_200 = b.connect_sized(&store, 200, 200, 0, spec_300).remove(0);
    assert_eq!(
        at_200.pruned.expect("a boundary").shards(),
        0..1,
        "D(2) is shard 0"
    );
    assert_eq!(
        prunable_state(&store, 6),
        Some(false),
        "the join at block 5 must actually be discarded, or this test proves nothing"
    );

    // Leg (f): every answer is unchanged, the discarded bodies included.
    let after: Vec<Option<bool>> = (0..count).map(|id| good_state(&store, id)).collect();
    assert_eq!(
        before, after,
        "the domain answer moved across a prune — pruned and archival nodes would \
         disagree on shard boundaries"
    );
    assert_eq!(
        good_state(&store, 6),
        Some(true),
        "a DISCARDED join is still in the domain: its rows outlive its regions"
    );
    assert_eq!(
        good_state(&store, 5),
        Some(false),
        "a coinbase is outside the domain, before and after"
    );

    // Both rows survived the prune — the premise leg (f) rests on. Read through
    // the record so a deleted row shows up as the absence it would be.
    {
        let snap = store.begin_read().expect("read");
        let discarded = snap
            .tx_record(&b.listed[5][0].hash())
            .expect("read")
            .expect("recorded");
        assert_eq!(
            discarded.pqc_auths,
            Some(PqcAuths::Discarded),
            "the region went with the shard"
        );
        assert!(
            discarded.pqc_auth_hash.is_some(),
            "the pqc hash row is permanent"
        );
        assert_ne!(
            discarded.prunable_hash,
            shekyl_wire::empty_region_prunable_hash(),
            "the prunable hash row still records a non-empty region — this row alone \
             is what keeps a 3-part transaction with a region (a serve-credit form) \
             in the domain after a prune"
        );
    }

    cleanup(&path);
}

/// **`SHT-Q1` leg (f) for the serve-credit form, named.** The test above
/// compares the whole vector, and since the CEN-I13 flip its bodies are
/// credits already; its last assertion states that a 3-part transaction
/// with a region stays in the domain on its `txs_prunable_hash` row alone.
/// This pins that for one credit by name: one block behind its join, in
/// shard 0, carried through the boundary that discards shard 0.
///
/// It is also `SHT-9`'s falsifier. A credit with no prunable region — the
/// shape CEN-H20 admitted until it required `RF-D1`'s — connected and then
/// halted the store on SI-7 at `tx_spendable_age`, ten heights later. This
/// one is connected two hundred heights before the chain ends.
#[test]
fn a_connected_serve_credit_stays_in_the_domain_across_a_prune() {
    let path = tmp("prune-domain-serve-credit");
    let store =
        ChainStore::with_horizons(&path, ApplyPolicy::default(), horizons()).expect("create");
    let mut b = Builder::new();
    // Shard 0 is the join at height 5 and a small credit at 6 (one block
    // behind the record it names, as CEN-J4 reads it), then thirty
    // 100 000-byte credits at 7–36: past `W` with the pair's bytes added,
    // so the shard closes inside that run and the epoch-2 boundary discards
    // it.
    let spec = |h: u64| match h {
        5 => vec![Sized::Join],
        6 => vec![credit(1_000)],
        7..=36 => vec![credit(100_000)],
        _ => Vec::new(),
    };
    b.connect_sized(&store, 0, 199, 0, spec);

    let credit_hash = b.listed[6][0].hash();
    let id_of = |hash: &shekyl_types::TxHash| {
        store
            .begin_read()
            .expect("read")
            .tx_record(hash)
            .expect("read")
            .expect("recorded")
            .location
            .id
            .to_raw()
    };
    let credit = id_of(&credit_hash);
    assert!(
        matches!(
            b.listed[6][0].ct,
            Ct::Fcmp {
                prunable: Some(_),
                ..
            }
        ),
        "the credit carries its RF-D1 region"
    );
    assert_eq!(
        good_state(&store, credit),
        Some(true),
        "a connected serve credit carries archival good"
    );
    assert_eq!(prunable_state(&store, credit), Some(true), "not yet pruned");

    // The boundary that discards shard 0.
    let at_200 = b.connect_sized(&store, 200, 200, 0, spec).remove(0);
    assert_eq!(
        at_200.pruned.expect("a boundary").shards(),
        0..1,
        "D(2) is shard 0"
    );
    assert_eq!(
        prunable_state(&store, credit),
        Some(false),
        "the credit's region must actually be discarded, or this test proves nothing"
    );
    assert_eq!(
        good_state(&store, credit),
        Some(true),
        "a DISCARDED serve credit is still in the domain: its row outlives its region"
    );
    let record = store
        .begin_read()
        .expect("read")
        .tx_record(&credit_hash)
        .expect("read")
        .expect("recorded");
    assert_eq!(
        record.pqc_auth_hash, None,
        "a serve credit has no pqc_auths"
    );
    assert_ne!(
        record.prunable_hash,
        shekyl_wire::empty_region_prunable_hash(),
        "its prunable hash row records the region it had"
    );

    cleanup(&path);
}
