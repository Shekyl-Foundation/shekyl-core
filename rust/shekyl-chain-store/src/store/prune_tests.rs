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
//! region still opaque. Since CEN-J27 the join is a **real** one too — a
//! spend of a matured coinbase funding the bond, built over the chain by
//! `connect_fixtures::Grown` — so every chain here opens with [`BASE`]
//! coinbase-only blocks, enough for the join's coinbase to mature, and
//! each listed height sits `BASE` above where it sat; every storage id
//! is `BASE` above its old number and every archival total is unchanged
//! (a coinbase carries no archival good). The chains run under a 100-block
//! epoch with a 50-block undo retention, or a 10-block epoch with a
//! 3-block retention (`Horizons::new`, the regtest knob — the production
//! pair would need ten thousand blocks per boundary). The expected
//! partition is computed by [`Model`], a separate derivation from the
//! lengths the fixture asked for.

// A whole-file test module: the parent gates it with `#[cfg(test)]`, and
// this self-declaration is what the debug-macro lint keys on — the
// `#[ignore]`d boundary test prints its measurement (bodies, close
// height, wall time) for the nightly lane to read, which is its job, not a
// debug leftover.
#![cfg(test)]

use redb::ReadableTable;
use shekyl_chain_rules::harness::fixture;
use shekyl_chain_rules::{Candidate, FakechainSchedule, RuleSet};
use shekyl_types::{ArchivalLength, BlockCount, BlockHash, BlockHeight, SHARD_LENGTH};
use shekyl_wire::{Ct, Transaction};

use super::connect_fixtures::{
    at, batch_root_going_into, candidate, candidate_over, endow_genesis, judge_under,
    root_going_into, serve_credit, Grown, Listed, FIRST_SPEND_HEIGHT,
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

/// The coinbase-only prefix every sized chain here opens with, and the
/// shift of every listed height, boundary, floor and storage id against
/// the tables as they were written when the join was a fixture body.
///
/// A join is a spend ([`Listed::Join`]), so the first height that can
/// list one is [`FIRST_SPEND_HEIGHT`] (66: the coinbase it spends must
/// have matured). The tables below list their first join five blocks into
/// the chain and are read under two schedules — a 100-block epoch and a
/// 10-block one — so the shift is the smallest multiple of both epochs
/// past 66: `BASE = 100`, and the join sits at `BASE + 5`. Shifting by a
/// multiple of each epoch keeps every height's offset inside its epoch, so
/// each boundary moves by exactly one epoch under the 100-block schedule
/// and ten under the 10-block one, and the discard calendar reads the
/// same one epoch (ten epochs) later. Shifting by a coinbase-only prefix
/// keeps every archival total — a coinbase writes no length row — and
/// raises every storage id by exactly `BASE`, one coinbase per prefix
/// height.
const BASE: u64 = 100;
const _: () = assert!(
    BASE > FIRST_SPEND_HEIGHT,
    "a join spends a matured coinbase"
);
const _: () = assert!(
    BASE.is_multiple_of(SEB) && BASE.is_multiple_of(SHORT_SEB),
    "the shift keeps every height's offset inside its epoch under both schedules"
);

/// A chain under construction: the blocks so far ([`Grown`], which builds
/// each join's spend over the chain as it stands), and the listed
/// transactions handed each height.
struct Builder {
    grown: Grown,
    listed: Vec<Vec<Transaction>>,
    /// The archival length each listed transaction was **asked** for, per
    /// height — the model's input, never re-measured off the bodies. A
    /// join's is [`JOIN_LEN`], the chain's own, pinned once.
    lens: Vec<Vec<u64>>,
    /// The height at which each slot's persona joined, if a connected
    /// block listed its join: a credit in slot `i` at a later height needs
    /// it (CEN-J4 reads the record off the view the block is judged
    /// against, which a join in the same block has not yet written), and
    /// names the epoch after the join's (CEN-J5, [`credit_epoch`]).
    joined: Vec<Option<u64>>,
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
            joined: Vec::new(),
            rules,
        }
    }

    /// Each connected block's hash — the priced block's identity.
    fn hashes(&self) -> &[BlockHash] {
        &self.grown.hashes
    }

    /// [`Self::connect`] with each height's bodies given by [`Sized`]:
    /// `spec(h)` lists them slot by slot, and `salt` keeps the credits of
    /// two chains over the same heights apart (a credit's record head —
    /// two identical credits would be one txid). A join takes no salt: it
    /// spends a coinbase of the chain it is built over, and two chains that
    /// agree below it list the same join (its proof is memoised by the
    /// reference block's hash, `Grown::spend_posting`, so the two builds
    /// are one body).
    fn connect_sized(
        &mut self,
        store: &ChainStore,
        from: u64,
        to: u64,
        salt: u64,
        spec: impl Fn(u64) -> Vec<Sized>,
    ) -> Vec<Connected> {
        let mut joined = self.joined.clone();
        let mut entries: Vec<Vec<Listed>> = Vec::new();
        let mut lens: Vec<Vec<u64>> = Vec::new();
        let mut joins: Vec<Vec<usize>> = Vec::new();
        for h in from..=to {
            let listed = spec(h);
            let mut here = Vec::new();
            let bodies = listed
                .iter()
                .enumerate()
                .map(|(i, body)| match *body {
                    Sized::Join => {
                        assert!(
                            joined.get(i).is_none_or(Option::is_none),
                            "height {h} slot {i}: the slot's persona already joined (CEN-J14)"
                        );
                        if joined.len() <= i {
                            joined.resize(i + 1, None);
                        }
                        joined[i] = Some(h);
                        here.push(i);
                        Listed::Join {
                            slot: u32::try_from(i).expect("a slot index"),
                        }
                    }
                    Sized::Credit(len) => {
                        let opened = joined.get(i).copied().flatten().filter(|&at| at < h);
                        let Some(opened) = opened else {
                            panic!(
                                "height {h} slot {i}: a credit needs its persona's join in an \
                                 earlier block (CEN-J4)"
                            );
                        };
                        Listed::Body(sized_credit(
                            key_of(salt, h, i),
                            i,
                            len,
                            credit_epoch(&self.rules, opened),
                        ))
                    }
                })
                .collect();
            entries.push(bodies);
            lens.push(listed.iter().map(|body| body.len()).collect());
            joins.push(here);
        }
        let out = self.connect(store, from, to, |h| {
            entries[usize::try_from(h - from).expect("fits")].clone()
        });
        let first = self.lens.len() - entries.len();
        for (i, lens) in lens.into_iter().enumerate() {
            self.lens[first + i] = lens;
        }
        self.joined = joined;
        // The model's input is the store's: a join's length is the chain's
        // own, read off the body the block listed.
        for (h, slots) in (from..=to).zip(joins) {
            for i in slots {
                assert_eq!(
                    self.listed[at(h)][i].archival_len().to_raw(),
                    JOIN_LEN,
                    "height {h} slot {i}: the chain's join length moved — re-derive every \
                     table in this module"
                );
            }
        }
        out
    }

    /// Forget the top `n` heights after popping them from the store: the
    /// chain record pops with them ([`Grown::pop`]), and a persona whose
    /// join was at a popped height has not joined.
    fn forget(&mut self, n: usize) {
        for _ in 0..n {
            self.grown.pop();
            self.listed.pop();
            self.lens.pop();
        }
        let height = self.grown.height().to_raw();
        for slot in &mut self.joined {
            if slot.is_some_and(|at| at >= height) {
                *slot = None;
            }
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
    /// chain as built ([`Grown::realise`]: a join is a spend of a matured
    /// coinbase carrying the persona's post, proved over the tree as it
    /// stands; a body is anchored — a credit has no reference and is
    /// listed as given), so a caller lists entries and reads the bodies
    /// back through [`Self::listed`]. Genesis is endowed
    /// ([`endow_genesis`]) so its coinbase is one a join can spend.
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
                let root = batch_root_going_into(&view, h)?;
                let mut cand = candidate_over(root, h, self.grown.tip(), txs.clone());
                if h == 0 {
                    endow_genesis(&mut cand);
                }
                // The identity is the priced block's (`judge_under`).
                let judged = judge_under(&view, cand, &self.rules)?;
                self.grown.record(judged.block().block(), &txs);
                // A bare listing records no asked-for lengths;
                // `connect_sized` overwrites them with the spec it built
                // from.
                self.lens.push(vec![u64::MAX; txs.len()]);
                self.listed.push(txs);
                out.push(batch.connect(judged, self.rules)?);
            }
            Ok(out)
        });
        out.expect("chain connects")
    }
}

/// The settlement epoch a credit names for a persona that joined at
/// height `joined` under `rules`: the first CEN-J5 admits, the join's
/// epoch plus one (`serve_credit_epoch_ok`; CEN-J6 bounds nothing above it
/// for a record with no bad interval, and the credit window, CEN-J7, is
/// Slice C's).
fn credit_epoch(rules: &RuleSet, joined: u64) -> u64 {
    rules.settlement_schedule().epoch_at_height(joined) + 1
}

/// A key no other credit in these chains draws, built from the chain's
/// salt, the height and the slot: a credit's pass record opens with its
/// bytes.
fn key_of(salt: u64, height: u64, index: usize) -> u64 {
    1_000 + salt * 1_000_000 + height * 8 + u64::try_from(index).expect("fits")
}

/// What a sized height lists, slot by slot. Slot `i`'s persona is the
/// spender harness's `Persona::at(i)`: a `Join` there opens it, a `Credit`
/// there names it. Two slots is the widest listing here, and two credits
/// in one block must name two personas (CEN-G7, one `(P, shard, E)` per
/// block).
#[derive(Clone, Copy)]
enum Sized {
    /// The slot's persona joins ([`Listed::Join`]: a real spend of a
    /// matured coinbase funding a complete-tree `JoinMarket` post, judged
    /// as a spend under CEN-J27): the record a credit in a **later** block
    /// names (CEN-J4). Its archival length is the chain's, [`JOIN_LEN`],
    /// not a free variable.
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

/// The archival length of a [`Sized::Join`] as the chain lists it —
/// `|pqc_auths| + |prunable|` of a real spend of one coinbase, two outputs
/// back to the miner, with the complete-tree post riding it: two signed
/// slots, the FCMP++ proof over the tree at `BASE + 5` and the outputs'
/// range proof — pinned here and read off the chain once
/// ([`the_join_length_the_model_assumes_is_the_chains`]), and checked at
/// every join `connect_sized` lists. The specs are derived from it: a join
/// stands where a 100 000-byte spend stood before the CEN-I13 flip, and
/// the four credits after it give the shortfall back ([`repaid`]) so every
/// running total from the fourth credit on is unchanged. The length is a
/// function of the tree the proof is made over, which is the same under
/// both schedules: `BASE + 5` coinbase-only blocks and nothing else.
const JOIN_LEN: u64 = 15_968;

/// The join's shortfall against the 100 000-byte spend it replaced, split
/// over the four credits that follow it: each carries a quarter over
/// 100 000, and the first carries the remainder too, so the four give back
/// exactly `100 000 − JOIN_LEN` whatever the join's parity.
const SHORTFALL: u64 = 100_000 - JOIN_LEN;
const GIVEBACK: u64 = SHORTFALL / 4;
const REMAINDER: u64 = SHORTFALL % 4;
const _: () = assert!(
    4 * GIVEBACK + REMAINDER == SHORTFALL,
    "the four credits give back the whole shortfall"
);

/// The credit `k` blocks after a join (`k` in `1..=4`), carrying its share
/// of the join's shortfall over 100 000 bytes.
const fn repaid(k: u64) -> Sized {
    assert!(1 <= k && k <= 4, "four credits give the shortfall back");
    credit(100_000 + GIVEBACK + if k == 1 { REMAINDER } else { 0 })
}
const _: () = assert!(
    repaid(1).len() + repaid(2).len() + repaid(3).len() + repaid(4).len() == 400_000 + SHORTFALL,
    "a join and its four credits total what five 100 000-byte spends did"
);

#[test]
fn the_join_length_the_model_assumes_is_the_chains() {
    let path = tmp("prune-join-len");
    let store = short_store(&path);
    let mut b = Builder::under(SHORT);
    b.connect_sized(&store, 0, BASE + 5, 0, |h| {
        if h == BASE + 5 {
            vec![Sized::Join]
        } else {
            Vec::new()
        }
    });
    assert_eq!(
        b.listed[at(BASE + 5)][0].archival_len().to_raw(),
        JOIN_LEN,
        "the chain's join length moved — re-derive every table in this module"
    );
    cleanup(&path);
}

/// A serve credit for slot `slot`'s persona, in `settlement_epoch`, whose
/// archival length is exactly `len`: [`serve_credit`] with its one pruned
/// pass record padded until the length is `len`. The record opens with
/// `key`'s bytes so no two credits in these chains are one txid. **The
/// record is what CEN-J8/J9/J10 will verify** (Slice C); until they land
/// its bytes are the fixture's free variable, and the debt is recorded
/// against them (`docs/FOLLOWUPS.md`, "Padded serve-credit records in the
/// store's prune and bench tests"). A credit has no reference and no
/// `pqc_auths` (CEN-H20), so anchoring leaves it as it is and the length
/// is read off the body itself.
fn sized_credit(key: u64, slot: usize, len: u64, settlement_epoch: u64) -> Transaction {
    let mut tx = serve_credit(u32::try_from(slot).expect("a slot index"), settlement_epoch);
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
/// bound is all archival. One probe, shared by the specs that list the
/// maximal credit — the ten-block schedule's, so the probe names the epoch
/// a credit there names ([`credit_epoch`] of a join at `BASE + 5`): the
/// epoch is a varint in the prefix, so its width is part of the weight.
/// The per-record ceiling (`ARCHIVAL_SERVE_CREDIT_PRUNED_MAX_BYTES`,
/// 1 053 185) is a decode bound the H3 weight bound sits far under.
fn max_len() -> u64 {
    let epoch = credit_epoch(&SHORT, BASE + 5);
    let base: u64 = 100_000;
    let weight = sized_credit(1, 0, base, epoch).weight();
    let len = base
        + u64::try_from(fixture::max_tx_weight() - weight).expect("under the bound at the base");
    assert_eq!(
        sized_credit(1, 0, len, epoch).weight(),
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

/// The bodies of the 100-block chain, one per height at `BASE + 5` to
/// `BASE + 34` and `BASE + 250`: slot 0's join at `BASE + 5` (the join
/// spends genesis's coinbase, the lowest matured), then credits for it.
/// Thirty bodies at heights `BASE + 5` to `BASE + 34` total exactly `W` —
/// `JOIN_LEN + (400 000 + SHORTFALL) + 25·100 000 = 3 000 000` — so shard 0
/// closes at `BASE + 34`, in epoch 1, as it closed at 34 in epoch 0 when
/// the chain had no prefix; the running total is the old one from the
/// fourth credit on. One more credit at `BASE + 250` opens shard 1, which
/// has not closed by `BASE + 300`.
fn spec_300(h: u64) -> Vec<Sized> {
    match h.checked_sub(BASE) {
        Some(5) => vec![Sized::Join],
        Some(k @ 6..=9) => vec![repaid(k - 5)],
        Some(10..=34 | 250) => vec![credit(100_000)],
        _ => Vec::new(),
    }
}

/// The chain every test here starts from: heights `0..=BASE + 300` under
/// a 100-block epoch, listed by [`spec_300`]. Storage ids: one coinbase at
/// each of `0..=BASE + 4` (ids `0..=BASE + 4`), a coinbase and a body at
/// each of `BASE + 5` to `BASE + 34` (ids `BASE + 5` to `BASE + 64`),
/// coinbases from `BASE + 35` (id `BASE + 65` on), block `BASE + 250`'s
/// credit is id `BASE + 281` — every id its old number plus `BASE`, one
/// coinbase per prefix block. The two boundaries handed back are the ones
/// that discard: shard 0 closes in epoch 1, so the epoch-2 boundary at
/// 200 names nothing (`close_epoch + 2 ≤ e` fails) and the epoch-3 and
/// epoch-4 boundaries at 300 and 400 name shard 0, as the epoch-2 and
/// epoch-3 boundaries did at 200 and 300 over the unshifted chain.
fn chain_to_300(path: &std::path::Path) -> (ChainStore, Builder, Connected, Connected) {
    let store =
        ChainStore::with_horizons(path, ApplyPolicy::default(), horizons()).expect("create");
    let mut b = Builder::new();
    let to_299 = b.connect_sized(&store, 0, BASE + 199, 0, spec_300);
    assert_eq!(
        to_299[at(200)].pruned.expect("a boundary").shards(),
        0..0,
        "epoch 2's boundary discards nothing: shard 0 closed in epoch 1"
    );
    let at_300 = b
        .connect_sized(&store, BASE + 200, BASE + 200, 0, spec_300)
        .remove(0);
    b.connect_sized(&store, BASE + 201, BASE + 299, 0, spec_300);
    let at_400 = b
        .connect_sized(&store, BASE + 300, BASE + 300, 0, spec_300)
        .remove(0);
    (store, b, at_300, at_400)
}

#[test]
fn the_boundary_batch_discards_closed_shards_and_retires_undo_rows() {
    let path = tmp("prune-boundary");
    let (store, b, at_300, at_400) = chain_to_300(&path);

    // Epoch 3's boundary: shard 0 closed at `BASE + 34` (the running total
    // reached `W` there), inside `[100, 200)`, so `D(3)` is shard 0; the
    // undo floor rises to 300 − 50.
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
    // read answers *discarded*, never a fault). Id `BASE + 65` is block
    // `BASE + 35`'s coinbase, the first transaction starting at `W`.
    for id in [0, BASE + 5, BASE + 6, BASE + 64] {
        assert_eq!(prunable_state(&store, id), Some(false), "id {id} discarded");
    }
    for id in [BASE + 65, BASE + 66, BASE + 281, BASE + 300] {
        assert_eq!(prunable_state(&store, id), Some(true), "id {id} retained");
    }
    assert_eq!(
        body_states(&store),
        not(&b.model().discarded(SEB, BASE + 300))
    );
    {
        let snap = store.begin_read().expect("read");
        // Block `BASE + 5`'s join as listed — the spend the chain built. A
        // join is 4-part, so it has the pqc region the prune discards by
        // shard.
        let early = snap
            .tx_record(&b.listed[at(BASE + 5)][0].hash())
            .expect("read")
            .expect("recorded");
        assert_eq!(
            early.pqc_auths,
            Some(PqcAuths::Discarded),
            "shard 0's pqc region went with it"
        );
        assert!(early.pqc_auth_hash.is_some(), "the hash row is permanent");
        // Block `BASE + 250`'s credit is 3-part (CEN-H20): no pqc region to
        // hold or discard; its archival good is the prunable region alone,
        // held (id `BASE + 281` above).
        let late = snap
            .tx_record(&b.listed[at(BASE + 250)][0].hash())
            .expect("read")
            .expect("recorded");
        assert_eq!(late.pqc_auths, None, "a credit carries no pqc region");
        assert_eq!(late.pqc_auth_hash, None, "and no hash row for one");
        assert_eq!(late.archival_len.to_raw(), 100_000, "as asked");
    }

    // The undo journal keeps exactly `[floor, tip]`.
    assert_eq!(undo_floor_cell(&store), Some(350));
    let rows = undo_rows(&store);
    assert_eq!(rows.first(), Some(&350));
    assert_eq!(rows.last(), Some(&(BASE + 300)));
    assert_eq!(rows.len(), 51);
    assert!(store.connect_state().is_live());
    cleanup(&path);
}

/// Retained-ness from the model's discarded-ness.
fn not(discarded: &[bool]) -> Vec<bool> {
    discarded.iter().map(|d| !d).collect()
}

/// The boundary test above with every archival byte a real spend: the
/// padded serve-credit records are the unit lane's stand-in for a shard's
/// bytes (slice 6 row 8 ruling, a1), and this is the deletion-correctness
/// test that gets valid bytes instead (a3) — the same discard set, undo
/// floor, body states and pqc-region outcome, read off a chain of
/// `MAX_INPUTS`-input spends ([`Grown::spend_many`]) run through both
/// boundaries that name shard 0 (`close_epoch + 2` and `+ 3`).
///
/// `#[ignore]`d: proving fifty-four 8-input spends is minutes — 140 s in
/// release, 714 s in debug on the measuring box — not a unit test's budget. **The lane that runs it is `.github/workflows/nightly.yml`,
/// job `store-ignored`, on the 03:00 UTC daily schedule**, which lists the
/// crate's ignored set and refuses to pass unless this test's name is in
/// it (rule 47). An `#[ignore]`d test no scheduled lane invokes is a
/// deleted test with a comment on it; that lane exists because the
/// crate's two `#[ignore]`d benches had none, and `slash_scan_bench`'s
/// default persona count overran epoch 0 with nobody running it to see.
///
/// The a1 arithmetic, asserted rather than restated: a shard closes in at
/// least `⌈W / max_tx_weight⌉` bodies, since no body is heavier than H3's
/// bound — **21** at `W = 3 000 000`, `max_tx_weight() = 149 400`, each
/// needing its own (P, shard, E) triple under G7. Not 3: the 1 053 185-byte
/// per-record ceiling is a decode bound, and a body of that size fails H3.
#[test]
#[ignore = "54 real 8-input spends to a shard boundary: ~140 s release, ~12 min debug; the nightly lane (nightly.yml `store-ignored`, 03:00 UTC daily) runs it"]
fn the_boundary_batch_discards_closed_shards_on_real_spends() {
    use std::time::Instant;

    let path = tmp("prune-boundary-real");
    let store =
        ChainStore::with_horizons(&path, ApplyPolicy::default(), horizons()).expect("create");
    let inputs = shekyl_fcmp::MAX_INPUTS;
    let w = SHARD_LENGTH.to_raw();
    let fewest_bodies = w.div_ceil(u64::try_from(fixture::max_tx_weight()).expect("fits"));
    assert_eq!(
        fewest_bodies, 21,
        "⌈W / max_tx_weight⌉ at the pinned constants"
    );

    let mut grown = Grown::new();
    let mut lens: Vec<Vec<u64>> = Vec::new();
    let mut spends: Vec<Transaction> = Vec::new();
    let mut close: Option<u64> = None;
    let mut boundaries: Vec<(u64, Vec<u64>, u64)> = Vec::new();
    let started = Instant::now();
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        loop {
            let h = grown.height().to_raw();
            if close.is_some_and(|c| h > (c / SEB + 3) * SEB) {
                break;
            }
            // As many spends as the matured coinbases allow until shard 0
            // closes; coinbase-only blocks from there to the second boundary
            // that names it.
            let mut txs = Vec::new();
            while close.is_none() && grown.matured().len() >= inputs * (txs.len() + 1) {
                let tx = grown.spend_many(inputs, 1_000);
                assert!(
                    tx.weight() <= fixture::max_tx_weight(),
                    "an {inputs}-input spend sits under H3's bound"
                );
                txs.push(tx);
                let total: u64 = lens.iter().flatten().sum::<u64>()
                    + txs.iter().map(|t| t.archival_len().to_raw()).sum::<u64>();
                if total >= w {
                    close = Some(h);
                }
            }
            lens.push(txs.iter().map(|t| t.archival_len().to_raw()).collect());
            let root = batch_root_going_into(&view, h)?;
            let mut cand = candidate_over(root, h, grown.tip(), txs.clone());
            if h == 0 {
                endow_genesis(&mut cand);
            }
            let judged = judge_under(&view, cand, &RULES)?;
            grown.record(judged.block().block(), &txs);
            spends.extend(txs);
            let connected = batch.connect(judged, RULES)?;
            if let Some(pruned) = connected.pruned {
                boundaries.push((h, pruned.shards().collect(), pruned.undo_floor.to_raw()));
            }
        }
        Ok(())
    });
    out.expect("connects");
    let model = Model { lens };
    let close = close.expect("shard 0 closed");
    let tip = grown.height().to_raw() - 1;
    eprintln!(
        "prune-boundary-real: {} spends of {inputs} inputs (first archival_len {}, weight {}) \
         closed shard 0 at h={close}; ran to h={tip} through the boundaries at {:?} in {:?}",
        spends.len(),
        spends[0].archival_len().to_raw(),
        spends[0].weight(),
        boundaries.iter().map(|b| b.0).collect::<Vec<_>>(),
        started.elapsed()
    );

    // The model's close height is the store's, and the chain used at least
    // the fewest bodies any chain can.
    assert_eq!(model.close_height(0), Some(close));
    assert!(spends.len() >= usize::try_from(fewest_bodies).expect("fits"));
    assert_eq!(model.close_height(1), None, "shard 1 never closed");

    // Every boundary from epoch 2 on ran, each discarding what the calendar
    // names — nothing until `close_epoch + 2`, shard 0 at `+ 2` and `+ 3` —
    // and each retiring undo rows to `boundary − RETENTION`.
    let close_epoch = close / SEB;
    let expected: Vec<(u64, Vec<u64>, u64)> = (2..=close_epoch + 3)
        .map(|e| (e * SEB, model.discards_at(SEB, e), e * SEB - RETENTION))
        .collect();
    assert_eq!(boundaries, expected);
    assert_eq!(
        boundaries.iter().filter(|b| b.1 == [0]).count(),
        2,
        "two boundaries named shard 0"
    );

    // Shard 0's bodies are gone — every spend, and every coinbase starting
    // below `W` — and the coinbases from `W` on are held; the hash rows
    // stand.
    assert_eq!(body_states(&store), not(&model.discarded(SEB, tip)));
    let ids_0 = model.ids_of(0);
    assert!(ids_0.contains(&0), "genesis's coinbase opens shard 0");
    assert!(
        ids_0.end < u64::try_from(model.shard_of_id().len()).expect("fits"),
        "shard 1 has ids"
    );
    assert_eq!(prunable_state(&store, ids_0.end - 1), Some(false));
    assert_eq!(prunable_state(&store, ids_0.end), Some(true));
    {
        let snap = store.begin_read().expect("read");
        for spend in [&spends[0], spends.last().expect("a spend")] {
            let record = snap
                .tx_record(&spend.hash())
                .expect("read")
                .expect("recorded");
            assert_eq!(record.pqc_auths, Some(PqcAuths::Discarded));
            assert!(record.pqc_auth_hash.is_some(), "the hash row is permanent");
            assert_eq!(record.archival_len.to_raw(), spend.archival_len().to_raw());
        }
    }

    // The undo journal keeps exactly `[floor, tip]`.
    let floor = (close_epoch + 3) * SEB - RETENTION;
    assert_eq!(undo_floor_cell(&store), Some(floor));
    let rows = undo_rows(&store);
    assert_eq!((rows.first(), rows.last()), (Some(&floor), Some(&tip)));
    assert_eq!(rows.len(), usize::try_from(RETENTION + 1).expect("fits"));
    assert!(store.connect_state().is_live());
    cleanup(&path);
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
    // 400 down to 350 have rows: fifty-one pops land.
    for expected in (350..=BASE + 300).rev() {
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
    assert_eq!(out.map(|p| p.height.to_raw()), Ok(BASE + 300));
    b.forget(1);
    // A different block at 400: a small credit (slot 0's persona joined at
    // `BASE + 5`) makes its hash differ.
    let again = b
        .connect_sized(&store, BASE + 300, BASE + 300, 0, |_| vec![credit(1_000)])
        .remove(0);
    let pruned = again.pruned.expect("the boundary fires again");
    assert_eq!(pruned.shards(), 0..1, "the same D(4), already empty");
    assert_eq!(pruned.undo_floor, BlockHeight::from_raw(350), "monotone");
    assert_eq!((undo_floor_cell(&store), undo_rows(&store)), before);
    assert_eq!(prunable_state(&store, 0), Some(false));
    assert_eq!(prunable_state(&store, BASE + 65), Some(true));
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
            batch.h_scarce(250)?,
            batch.h_scarce(350)?,
            batch.h_scarce(BASE + 300)?,
        ))
    });
    let (e1, e2, e3) = out.expect("reads");
    assert_eq!(
        store.begin_read().expect("read").h_scarce().expect("read"),
        Some(BlockHeight::from_raw(BASE + 34)),
        "the snapshot's read at the recorded tip agrees"
    );
    // Shard 0 closed in epoch 1, so the first epoch that can have
    // discarded it is 3 (`close_epoch + 2 ≤ E`).
    assert_eq!(e1, None, "epoch 2: nothing can have discarded");
    // Shard 0's running total reaches `W` at height `BASE + 34`, whose
    // credit ends exactly on it.
    assert_eq!(e2, Some(BASE + 34), "epoch 3: shard 0 closed at BASE + 34");
    assert_eq!(
        e3,
        Some(BASE + 34),
        "epoch 4: still shard 0, shard 1 is open"
    );
    let model = b.model();
    assert_eq!(
        (e1, e2, e3),
        (
            model.h_scarce(SEB, 250),
            model.h_scarce(SEB, 350),
            model.h_scarce(SEB, BASE + 300)
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
/// length; every height below is `BASE` above the one written. Block
/// `BASE + 5` opens both slots' personas (two joins, spending genesis's
/// coinbase and block 1's — `BASE + 5 − 66 + 1 = 40` have matured); blocks
/// `BASE + 6` to `BASE + 9` give back the two joins' shortfall —
/// `2·(100 000 − JOIN_LEN) = 2·SHORTFALL` — so the running total through
/// `BASE + 9` is `1 000 000`, the same as when every body was a
/// 100 000-byte spend, and every total below is the one it was:
///
/// | Heights (`BASE +`) | Bodies | Running total through the last | |
/// | --- | --- | --- | --- |
/// | 5 | 2 joins | 2 × `JOIN_LEN` | |
/// | 6–9 | 2 × [`repaid`] | 1 000 000 | |
/// | 10–19 | 2 × 100 000 | 3 000 000 = `W` | shard 0 closes at `BASE + 19`, exactly on the boundary |
/// | 20 | 1 × 100 000 | 3 100 000 | starts **exactly at** `W`: shard 1 |
/// | 21–34 | 2 × 100 000 | 5 900 000 | |
/// | 35 | 1 × `max` | 5 900 000 + `max` | starts in shard 1, ends past `2·W`: shard 1 closes at `BASE + 35` |
/// | 36–46 | 2 × 140 000 | 8 980 000 + `max` | shard 2 closes at `BASE + 46` |
///
/// Storage ids, each `BASE` above the unshifted chain's: blocks `0` to
/// `BASE + 4` one each (`0` to `BASE + 4`); `BASE + 5` to `BASE + 19`
/// three each (block `BASE + 19`: `BASE + 47` to `BASE + 49`); block
/// `BASE + 20`: `BASE + 50`, `BASE + 51`; `BASE + 21` to `BASE + 34` three
/// each (block `BASE + 34`: `BASE + 91` to `BASE + 93`); block `BASE + 35`:
/// `BASE + 94` and the maximal credit `BASE + 95`; block `BASE + 36`'s
/// coinbase is `BASE + 96`.
///
/// Boundaries every ten blocks, each ten epochs after the one written
/// (`BASE` is ten epochs): shard 0 closes in epoch 11, so `D(13)` at
/// `BASE + 30` is shard 0; shard 1 closes in epoch 13, so `D(15)` at
/// `BASE + 50` is shard 1; shard 2 closes in epoch 14, so `D(16)` at
/// `BASE + 60` is shards 1 **and** 2 — two boundaries in one batch.
fn short_spec(max: u64) -> impl Fn(u64) -> Vec<Sized> {
    move |h| match h.checked_sub(BASE) {
        Some(5) => vec![Sized::Join, Sized::Join],
        Some(k @ 6..=9) => vec![repaid(k - 5); 2],
        Some(10..=19 | 21..=34) => vec![credit(100_000); 2],
        Some(20) => vec![credit(100_000)],
        Some(35) => vec![credit(max)],
        Some(36..=46) => vec![credit(140_000); 2],
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
    b.connect_sized(&store, 0, BASE + 21, 0, short_spec(0));
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
        // Through `BASE + 21`: `W`, block `BASE + 20`'s credit, block
        // `BASE + 21`'s two — the prefix's coinbases add nothing.
        assert_eq!(through, 3_300_000);
    }
    cleanup(&path);
}

/// Scope 4 (a): a transaction starting **exactly** at `k·W` opens shard
/// `k`. Block `BASE + 19`'s credits end on `W`; block `BASE + 20`'s
/// coinbase and credit start on it. `D(13)` discards the first and keeps
/// the second.
#[test]
fn a_transaction_starting_exactly_at_k_w_opens_shard_k() {
    let path = tmp("prune-exact-kw");
    let store = short_store(&path);
    let mut b = Builder::under(SHORT);
    let out = b.connect_sized(&store, 0, BASE + 30, 0, short_spec(0));
    let pruned = out[at(BASE + 30)].pruned.expect("a boundary");
    assert_eq!(pruned.shards(), 0..1, "D(13) is shard 0");
    for id in [BASE + 47, BASE + 48, BASE + 49] {
        assert_eq!(prunable_state(&store, id), Some(false), "id {id}: below W");
    }
    for id in [BASE + 50, BASE + 51] {
        assert_eq!(
            prunable_state(&store, id),
            Some(true),
            "id {id}: starts at W"
        );
    }
    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.shard_storage_ids(0..1).expect("read"),
        0..BASE + 50,
        "the prefix's coinbases are shard 0's too"
    );
    assert_eq!(
        snap.shard_storage_ids(0..1).expect("read"),
        b.model().ids_of(0)
    );
    drop(snap);
    assert_eq!(
        body_states(&store),
        not(&b.model().discarded(SHORT_SEB, BASE + 30))
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
    let out = b.connect_sized(&store, 0, BASE + 50, 0, short_spec(max));
    let model = b.model();
    // It starts at 5 900 000 and ends past 6 000 000.
    let (_, start, len) = model.txs()[at(BASE + 95)];
    assert_eq!((start, len), (5_900_000, max));
    assert!(
        start < 2 * Model::W && start + len > 2 * Model::W,
        "it straddles 2·W"
    );
    let pruned = out[at(BASE + 50)].pruned.expect("a boundary");
    assert_eq!(pruned.shards(), 1..2, "D(15) is shard 1");
    assert_eq!(
        prunable_state(&store, BASE + 95),
        Some(false),
        "discarded with shard 1"
    );
    assert_eq!(
        prunable_state(&store, BASE + 96),
        Some(true),
        "block BASE + 36 opens shard 2"
    );
    let out: Result<Option<u64>, TestErr> = store.write(|batch| Ok(batch.h_scarce(BASE + 50)?));
    assert_eq!(
        out,
        Ok(Some(BASE + 35)),
        "shard 1 closed at the maximal credit's height"
    );
    assert_eq!(
        body_states(&store),
        not(&model.discarded(SHORT_SEB, BASE + 50))
    );
    cleanup(&path);
}

/// Scope 4 (c): two shards closing inside one boundary's window are one
/// batch — `D(16)` is shards 1 and 2, contiguous ids — and every boundary
/// from `BASE + 20` to `BASE + 70` matches the model: the discard set,
/// every id's body, and `h_scarce`.
#[test]
fn consecutive_boundaries_and_every_batch_match_the_model() {
    let path = tmp("prune-consecutive");
    let store = short_store(&path);
    let max = max_len();
    let mut b = Builder::under(SHORT);
    b.connect_sized(&store, 0, BASE + 19, 0, short_spec(max));
    for boundary in (BASE + 20..=BASE + 70).step_by(10) {
        let from = boundary - 9;
        let out = b.connect_sized(&store, from.max(BASE + 20), boundary, 0, short_spec(max));
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
        (Some(BASE + 19), Some(BASE + 35), Some(BASE + 46))
    );
    assert_eq!(
        model.discards_at(SHORT_SEB, (BASE + 60) / SHORT_SEB),
        vec![1, 2],
        "consecutive"
    );
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
    // The new branch: shard 2 closes at `BASE + 47` instead of `BASE + 46`.
    let branch = |h: u64| match h.checked_sub(BASE) {
        Some(46) => vec![credit(100_000)],
        Some(47) => vec![credit(100_000); 2],
        _ => Vec::new(),
    };

    let path = tmp("prune-reorg");
    let store = short_store(&path);
    let mut b = Builder::under(SHORT);
    b.connect_sized(&store, 0, BASE + 48, 0, &spec);
    assert_eq!(b.model().close_height(2), Some(BASE + 46));
    // Pop `BASE + 48`, `+ 47`, `+ 46`: the running total drops back below
    // `3·W`.
    for expected in [BASE + 48, BASE + 47, BASE + 46] {
        let out: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
        assert_eq!(out.map(|p| p.height.to_raw()), Ok(expected));
    }
    b.forget(3);
    assert_eq!(b.model().close_height(2), None, "shard 2 is open again");
    let mut reorged = Vec::new();
    for boundary in [BASE + 50, BASE + 60, BASE + 70] {
        let from = if boundary == BASE + 50 {
            BASE + 46
        } else {
            boundary - 9
        };
        let out = b.connect_sized(&store, from, boundary, 1, branch);
        reorged.push(out.last().expect("connected").pruned.expect("a boundary"));
    }
    let reorged_states = body_states(&store);
    let reorged_scarce = store.begin_read().expect("read").h_scarce().expect("read");

    let fresh_path = tmp("prune-reorg-fresh");
    let fresh = short_store(&fresh_path);
    let mut f = Builder::under(SHORT);
    f.connect_sized(&fresh, 0, BASE + 45, 0, &spec);
    let mut straight = Vec::new();
    for boundary in [BASE + 50, BASE + 60, BASE + 70] {
        let from = if boundary == BASE + 50 {
            BASE + 46
        } else {
            boundary - 9
        };
        let out = f.connect_sized(&fresh, from, boundary, 1, branch);
        straight.push(out.last().expect("connected").pruned.expect("a boundary"));
    }
    // One chain: the two builds list the same joins (memoised by the
    // reference block's hash, which the two chains share below the joins)
    // and the same salted credits.
    assert_eq!(b.hashes(), f.hashes(), "the same chain");
    assert_eq!(reorged, straight, "the same discard sets and floors");
    assert_eq!(reorged_states, body_states(&fresh), "the same bodies");
    assert_eq!(
        reorged_scarce,
        fresh.begin_read().expect("read").h_scarce().expect("read")
    );
    assert_eq!(f.model().close_height(2), Some(BASE + 47));
    assert_eq!(
        reorged[2].shards(),
        2..3,
        "D(17) is the new branch's shard 2"
    );
    assert_eq!(reorged_scarce, Some(BlockHeight::from_raw(BASE + 47)));
    assert_eq!(
        reorged_states,
        not(&f.model().discarded(SHORT_SEB, BASE + 70))
    );
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
    b.connect_sized(&store, 0, BASE + 59, 0, short_spec(max));
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
        "shard 2 is held before BASE + 60"
    );
    b.connect_sized(&store, BASE + 60, BASE + 60, 0, short_spec(max));
    assert!(
        shard_2
            .clone()
            .all(|id| prunable_state(&store, id) == Some(false)),
        "and discarded at BASE + 60, or this test compares two unpruned stores"
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

/// Build the ten-block chain to `BASE + to` and close the store, for a raw
/// plant. The corruption tests do not need the exact maximal credit, so
/// height `BASE + 35` lists a 140 000-byte one and skips the probe.
fn short_chain_to(path: &std::path::Path, to: u64) -> Builder {
    let store = short_store(path);
    let mut b = Builder::under(SHORT);
    b.connect_sized(&store, 0, BASE + to, 0, short_spec(140_000));
    b
}

/// Connect `BASE + height` on the reopened ten-block store with nothing
/// listed.
fn connect_short(
    path: &std::path::Path,
    b: &Builder,
    height: u64,
) -> (ChainStore, Result<Connected, TestErr>) {
    let store = short_store(path);
    let previous = b.hashes().last().copied().expect("parent");
    let cand = candidate_on(&store, BASE + height, previous, Vec::new());
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge_under(&view, cand, &SHORT)?, SHORT)?)
    });
    (store, out)
}

/// A later `block_info` row whose listed total is below an earlier one's is
/// SI-13. The boundary at `BASE + 30` walks block `BASE + 19` to find
/// where shard 1 opens; a decrease there must not commit the boundary with
/// `D(E)` skipped. The listed fold counts listed bodies only, so the
/// prefix's coinbases leave every count the one it was.
#[test]
fn a_decreasing_listed_total_refuses_the_boundary() {
    let path = tmp("prune-monotone");
    let b = short_chain_to(&path, 29);
    // Listed through `BASE + 18`: 14 blocks of two bodies.
    plant_listed(&path, BASE + 19, 28 - 5);
    let (store, out) = connect_short(&path, &b, 30);
    assert!(
        out.is_err(),
        "the boundary does not commit over a decreasing total"
    );
    assert_eq!(tip(&store), BASE + 29);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(BASE + 30),
            row: StoreInvariant::FoldNotMonotone {
                cell: "block_info.cumulative_tx_count",
                height: BASE + 19,
            },
        }
    );
    cleanup(&path);
}

/// The decrease the coinbase term can mask: listed `28 → 27` from height
/// `BASE + 18` to `BASE + 19` derives to storage ids `BASE + 47 → BASE +
/// 47` — an empty block, not an inverted one. SI-13 is a property of the
/// listed fold and is checked on the raw samples (Copilot, PR #861).
#[test]
fn a_decrease_smaller_than_the_coinbase_term_still_refuses_the_boundary() {
    let path = tmp("prune-monotone-masked");
    let b = short_chain_to(&path, 29);
    plant_listed(&path, BASE + 19, 27);
    let (store, out) = connect_short(&path, &b, 30);
    assert!(
        out.is_err(),
        "BASE + 47 → BASE + 47 in storage ids hides 28 → 27 in the fold"
    );
    assert_eq!(tip(&store), BASE + 29);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(BASE + 30),
            row: StoreInvariant::FoldNotMonotone {
                cell: "block_info.cumulative_tx_count",
                height: BASE + 19,
            },
        }
    );
    cleanup(&path);
}

/// SI-13 on the archival fold: `D(14)` at `BASE + 40` samples `C(BASE +
/// 10)` and `C(BASE + 30)` — rows `BASE + 9` and `BASE + 29` — and row
/// `BASE + 29` zeroed is below row `BASE + 9`. The fault names the row
/// that decreased, as the listed fold's does.
#[test]
fn a_decreasing_archival_total_refuses_the_boundary() {
    let path = tmp("prune-archival-monotone");
    let b = short_chain_to(&path, 39);
    plant_archival(&path, BASE + 29, 0);
    let (store, out) = connect_short(&path, &b, 40);
    assert!(out.is_err());
    assert_eq!(tip(&store), BASE + 39);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(BASE + 40),
            row: StoreInvariant::FoldNotMonotone {
                cell: "block_info.cumulative_archival_len",
                height: BASE + 29,
            },
        }
    );
    cleanup(&path);
}

/// SI-13 across the whole run the boundary reads, not at its samples
/// (Copilot, PR #910). Cells `BASE + 13` to `BASE + 16` are raised
/// together by 900 000 with their length rows untouched: each shifted cell
/// still equals its parent plus its rows, so SI-24 holds at every block
/// inside the run, and the fold now reaches `W` twice — at `BASE + 15`
/// (`2 900 000 → 3 100 000`, a second, spurious crossing) and at `BASE +
/// 19`. The endpoints `C(BASE)` and `C(BASE + 20)` are true. A search that
/// trusts monotonicity can settle on `BASE + 15` and place shard 1's first
/// id inside that block. The boundary at `BASE + 30` must halt on the
/// decrease at `BASE + 17` (`3 300 000 → 2 600 000`) instead, before any
/// discard.
#[test]
fn a_shifted_run_between_two_samples_refuses_the_boundary() {
    let path = tmp("prune-archival-run");
    let b = short_chain_to(&path, 29);
    for height in BASE + 13..=BASE + 16 {
        plant_info(&path, height, |info| {
            info.cumulative_archival_len =
                ArchivalLength::from_raw(info.cumulative_archival_len.to_raw() + 900_000);
        });
    }
    let (store, out) = connect_short(&path, &b, 30);
    assert!(out.is_err(), "the boundary does not commit over the run");
    assert_eq!(tip(&store), BASE + 29);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(BASE + 30),
            row: StoreInvariant::FoldNotMonotone {
                cell: "block_info.cumulative_archival_len",
                height: BASE + 17,
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
/// start. Cells `BASE + 25` to `BASE + 39` are raised by 1 200 000, rows
/// untouched, so `C(BASE + 30)` reads 6 100 000 instead of 4 900 000 and
/// `D(14)` at `BASE + 40` would name shards `0..2` — discarding blocks
/// `BASE + 20` to `BASE + 29`, which are in shard 1, still open. The
/// descent checks block `BASE + 25` against its parent: `3 900 000 +
/// 200 000 = 4 100 000` against a cell of 5 300 000, before anything is
/// discarded.
#[test]
fn a_shift_that_persists_through_the_window_refuses_the_boundary() {
    let path = tmp("prune-archival-persist");
    let b = short_chain_to(&path, 39);
    for height in BASE + 25..=BASE + 39 {
        plant_info(&path, height, |info| {
            info.cumulative_archival_len =
                ArchivalLength::from_raw(info.cumulative_archival_len.to_raw() + 1_200_000);
        });
    }
    let (store, out) = connect_short(&path, &b, 40);
    assert!(out.is_err(), "the boundary does not commit over the shift");
    assert_eq!(tip(&store), BASE + 39);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(BASE + 40),
            row: StoreInvariant::ArchivalLengthsDisagree {
                height: BASE + 25,
                rows: 4_100_000,
                cell: 5_300_000,
            },
        }
    );
    // Blocks `BASE + 20` to `BASE + 29`: ids `BASE + 50` to `BASE + 78`,
    // shard 1.
    for id in BASE + 50..BASE + 79 {
        assert_eq!(prunable_state(&store, id), Some(true), "id {id} is held");
    }
    cleanup(&path);
}

/// SI-24: the boundary at `BASE + 30` sums block `BASE + 19`'s length rows
/// to place `W`, and a row that no longer adds up to the block's cell
/// refuses the boundary rather than place it by numbers the fold does not
/// support.
#[test]
fn a_length_row_that_disagrees_with_the_fold_refuses_the_boundary() {
    let path = tmp("prune-archival-rows");
    let b = short_chain_to(&path, 29);
    // Id `BASE + 48` is block `BASE + 19`'s first credit.
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        {
            let mut table = txn.open_table(TXS_ARCHIVAL_LEN).expect("table");
            let encoded = ArchivalLength::from_raw(99_999).encoded();
            table
                .insert(BASE + 48, encoded.as_encoded())
                .expect("plant");
        }
        txn.commit().expect("commit");
    }
    let (store, out) = connect_short(&path, &b, 30);
    assert!(out.is_err());
    assert_eq!(tip(&store), BASE + 29);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(BASE + 30),
            row: StoreInvariant::ArchivalLengthsDisagree {
                height: BASE + 19,
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
    // Rows [350, BASE + 300] stand and the cell says 350. Remove row 350 by
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
                height: BASE + 300,
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
    cleanup(&path);

    // The same gap, met by the boundary batch: connect to `BASE + 399`
    // under a clean journal, open the gap at the floor that `BASE + 400`
    // will establish (450), then connect `BASE + 400`.
    let path = tmp("prune-floor-mismatch-boundary");
    let (store, mut b2, _, _) = chain_to_300(&path);
    b2.connect(&store, BASE + 301, BASE + 399, |_| Vec::new());
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
    let previous = *b2.hashes().last().expect("BASE + 399 connected");
    let cand = candidate_on(&store, BASE + 400, previous, Vec::new());
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge_under(&view, cand, &RULES)?, RULES)?)
    });
    assert_eq!(
        out,
        Err(TestErr::Store(
            StoreError::from(StoreInvariant::UndoLogIncoherent {
                height: BASE + 400,
                fault: UndoFault::FloorMismatch {
                    first: 451,
                    floor: 450
                },
            })
            .to_string()
        )),
        "the retire leaves a first key that is not the floor: SI-6"
    );
    assert_eq!(
        tip(&store),
        BASE + 399,
        "the boundary block did not connect"
    );
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
    // A mixed chain ([`spec_300`] to `BASE + 200`): a join (4-part) and
    // credits (3-part) filling shard 0 (discarded at the epoch-3 boundary)
    // and empty blocks — the coinbase-only case — everywhere else, those
    // from `BASE + 35` in shard 1 (retained). Recorded at `BASE + 199`,
    // before the first discard.
    b.connect_sized(&store, 0, BASE + 199, 0, spec_300);

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
    let at_300 = b
        .connect_sized(&store, BASE + 200, BASE + 200, 0, spec_300)
        .remove(0);
    assert_eq!(
        at_300.pruned.expect("a boundary").shards(),
        0..1,
        "D(3) is shard 0"
    );
    assert_eq!(
        prunable_state(&store, BASE + 6),
        Some(false),
        "the join at block BASE + 5 must actually be discarded, or this test proves nothing"
    );

    // Leg (f): every answer is unchanged, the discarded bodies included.
    let after: Vec<Option<bool>> = (0..count).map(|id| good_state(&store, id)).collect();
    assert_eq!(
        before, after,
        "the domain answer moved across a prune — pruned and archival nodes would \
         disagree on shard boundaries"
    );
    assert_eq!(
        good_state(&store, BASE + 6),
        Some(true),
        "a DISCARDED join is still in the domain: its rows outlive its regions"
    );
    assert_eq!(
        good_state(&store, BASE + 5),
        Some(false),
        "a coinbase is outside the domain, before and after"
    );

    // Both rows survived the prune — the premise leg (f) rests on. Read through
    // the record so a deleted row shows up as the absence it would be.
    {
        let snap = store.begin_read().expect("read");
        let discarded = snap
            .tx_record(&b.listed[at(BASE + 5)][0].hash())
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
    // Shard 0 is the join at height `BASE + 5` and a small credit at
    // `BASE + 6` (one block behind the record it names, as CEN-J4 reads
    // it), then thirty 100 000-byte credits at `BASE + 7` to `BASE + 36`:
    // past `W` with the pair's bytes added, so the shard closes inside that
    // run and the epoch-3 boundary discards it.
    let spec = |h: u64| match h.checked_sub(BASE) {
        Some(5) => vec![Sized::Join],
        Some(6) => vec![credit(1_000)],
        Some(7..=36) => vec![credit(100_000)],
        _ => Vec::new(),
    };
    b.connect_sized(&store, 0, BASE + 199, 0, spec);

    let credit_hash = b.listed[at(BASE + 6)][0].hash();
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
            b.listed[at(BASE + 6)][0].ct,
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
    let at_300 = b
        .connect_sized(&store, BASE + 200, BASE + 200, 0, spec)
        .remove(0);
    assert_eq!(
        at_300.pruned.expect("a boundary").shards(),
        0..1,
        "D(3) is shard 0"
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
