// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! S-PRUNE: the boundary batch is named by the epoch, discards whole shards,
//! retires undo rows, and is idempotent across a boundary reorg; the pop
//! floor it leaves is a refusal, not a fault.
//!
//! `T = 200` transactions per shard is a production constant, so a shard
//! closes only after two hundred transactions: these chains run three
//! hundred blocks under a 100-block epoch and a 50-block undo retention
//! (`Horizons::new`, the regtest knob — the production pair would need ten
//! thousand blocks per boundary). The fixtures in `connect_fixtures` bound
//! their heights to a `u8`, so this module carries its own header and facts
//! for long chains, with the same shape.

use redb::ReadableTable;
use shekyl_chain_rules::{Candidate, RuleSet};
use shekyl_types::{BlockCount, BlockHash, BlockHeight, SHARD_TX_COUNT};
use shekyl_units::AtomicUnits;
use shekyl_wire::Transaction;

use super::connect_fixtures::{
    anchor, batch_root_going_into, candidate, candidate_over, judge_under, root_going_into, spend,
};
use super::store_tests::{cleanup, tmp, TestErr};
use super::*;
use crate::codec::{
    Canonical, PropertyCell, PropertyCellBytes, Raw, SettlementEpochBlocks, UndoLogFloorCell,
};
use crate::ids::TxStorageId;
use crate::schema::{BLOCK_INFO, PROPERTIES, UNDO_LOG};

const SEB: u64 = 100;
const RETENTION: u64 = 50;
/// The Fakechain rule set this schedule runs: the genesis rules with a
/// reorg cap that fits the retention (SCW-7) — a regtest wanting a 50-block
/// retention gets a rule set whose cap is at most 50, not a store field the
/// validator defers to (PR #861 review).
const RULES: RuleSet = RuleSet::fakechain(None, BlockCount::from_raw(RETENTION));

fn horizons() -> Horizons {
    Horizons::new(
        SettlementEpochBlocks::new(SEB).expect("non-zero"),
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

/// The one fact `connect` is still handed (E6 slice 7): no burn.
fn facts(_height: u64) -> ConnectFacts {
    ConnectFacts {
        burned: Fact::passed_through(AtomicUnits::from_raw(0)),
    }
}

/// A chain under construction: the hashes so far, and the listed
/// transactions to hand each height.
struct Builder {
    hashes: Vec<BlockHash>,
    listed: Vec<Vec<Transaction>>,
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
            rules,
        }
    }

    /// Connect heights `from..=to` in one batch, handing `listed(h)` at each;
    /// returns each connect's outcome. Every listed transaction is
    /// **anchored** on the chain as built (`connect_fixtures::anchor`: a
    /// recorded reference inside CEN-I11's window, and its slots signed), so
    /// a caller lists bare `spend`s and reads them back through
    /// [`Self::listed`].
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
                self.hashes.push(cand.block.hash());
                self.listed.push(txs);
                out.push(batch.connect(
                    judge_under(&view, cand, &self.rules)?,
                    facts(h),
                    self.rules,
                )?);
            }
            Ok(out)
        });
        out.expect("chain connects")
    }
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

/// The chain every test here starts from: heights `0..=300` under a
/// 100-block epoch. Block 5 carries a 4-part spend (shard 0); block 250
/// carries another (shard 1, which has not closed by 300).
fn chain_to_300(path: &std::path::Path) -> (ChainStore, Builder, Connected, Connected) {
    let store =
        ChainStore::with_horizons(path, ApplyPolicy::default(), horizons()).expect("create");
    let mut b = Builder::new();
    let listed = |h: u64| match h {
        5 => vec![spend(1, 2)],
        250 => vec![spend(2, 2)],
        _ => Vec::new(),
    };
    b.connect(&store, 0, 199, listed);
    let at_200 = b.connect(&store, 200, 200, listed).remove(0);
    b.connect(&store, 201, 299, listed);
    let at_300 = b.connect(&store, 300, 300, listed).remove(0);
    (store, b, at_200, at_300)
}

#[test]
fn the_boundary_batch_discards_closed_shards_and_retires_undo_rows() {
    let path = tmp("prune-boundary");
    let (store, b, at_200, at_300) = chain_to_300(&path);

    // Epoch 2's boundary: no shard has closed before height 100 (100
    // coinbases < T), so the discard set is empty, and the undo floor rises
    // to 200 − 50.
    let pruned_200 = at_200.pruned.expect("a boundary");
    assert!(pruned_200.shards().is_empty(), "{pruned_200:?}");
    assert_eq!(pruned_200.undo_floor, BlockHeight::from_raw(150));

    // Epoch 3's boundary: transactions with ids below first_tx_id(200) =
    // 201 (200 coinbases and the spend at block 5) — shard 0 (ids 0..200)
    // has closed; shard 1 has not.
    let pruned_300 = at_300.pruned.expect("a boundary");
    assert_eq!(pruned_300.shards(), 0..1, "D(3) is shard 0");
    assert_eq!(pruned_300.undo_floor, BlockHeight::from_raw(250));

    // Shard 0's bodies are gone, shard 1's are held, and the hash rows
    // stand (a read answers *discarded*, never a fault).
    for id in [0, 5, 6, SHARD_TX_COUNT - 1] {
        assert_eq!(prunable_state(&store, id), Some(false), "id {id} discarded");
    }
    for id in [SHARD_TX_COUNT, SHARD_TX_COUNT + 1, 300] {
        assert_eq!(prunable_state(&store, id), Some(true), "id {id} retained");
    }
    {
        let snap = store.begin_read().expect("read");
        // The spends as listed — anchored and signed by the builder — not
        // the bare fixture, whose hash they no longer share.
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
        let late = snap
            .tx_record(&b.listed[250][0].hash())
            .expect("read")
            .expect("recorded");
        assert!(
            matches!(late.pqc_auths, Some(PqcAuths::Retained(_))),
            "shard 1 is held"
        );
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
    b.hashes.pop();
    b.listed.pop();
    // A different block at 300: the spend makes its hash differ.
    let again = b.connect(&store, 300, 300, |_| vec![spend(3, 2)]).remove(0);
    let pruned = again.pruned.expect("the boundary fires again");
    assert_eq!(pruned.shards(), 0..1, "the same D(3), already empty");
    assert_eq!(pruned.undo_floor, BlockHeight::from_raw(250), "monotone");
    assert_eq!((undo_floor_cell(&store), undo_rows(&store)), before);
    assert_eq!(prunable_state(&store, 0), Some(false));
    assert_eq!(prunable_state(&store, SHARD_TX_COUNT), Some(true));
    cleanup(&path);
}

/// `h_scarce` (§4): the `close_height` of the last shard the calendar has
/// discarded at `tip` — `PDM-Q5`'s band-2 edge, chain-named, no presence
/// read. `None` in epochs 0–1 and before any shard has closed.
#[test]
fn h_scarce_is_the_last_discarded_shards_close_height() {
    let path = tmp("prune-h-scarce");
    let (store, _b, _, _) = chain_to_300(&path);
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
        Some(BlockHeight::from_raw(198)),
        "the snapshot's read at the recorded tip agrees"
    );
    assert_eq!(e1, None, "epoch 1: nothing can have discarded");
    assert_eq!(e2, None, "epoch 2: no shard closed before height 100");
    // Shard 0's last transaction is id 199; ids 0..=5 are blocks 0..=4's
    // coinbases and block 5's coinbase, id 6 is block 5's spend, so id 199
    // is block 198's coinbase.
    assert_eq!(e3, Some(198), "epoch 3: shard 0 closed at height 198");
    cleanup(&path);
}

/// The Fakechain set for the ten-block schedule the SI-13 tests run.
const SHORT: RuleSet = RuleSet::fakechain(None, BlockCount::from_raw(3));

/// A later `block_info` row whose storage-id total is below an earlier
/// one's is SI-13. The boundary connect must not commit with `D(E)` skipped.
#[test]
fn a_decreasing_storage_id_total_refuses_the_boundary() {
    let path = tmp("prune-monotone");
    let horizons = Horizons::new(
        SettlementEpochBlocks::new(10).expect("non-zero"),
        BlockCount::from_raw(3),
        SHORT.reorg_cap(),
    )
    .expect("cap ≤ retention < epoch");
    let store = ChainStore::with_horizons(&path, ApplyPolicy::default(), horizons).expect("create");
    let mut b = Builder::under(SHORT);
    // Height 40 is epoch 4, the first boundary whose window starts above
    // genesis: `D(4)` reads `first_tx_id(10)` and `first_tx_id(30)`.
    b.connect(&store, 0, 39, |_| Vec::new());
    drop(store);
    plant_listed(&path, 9, 5_000);
    let store = ChainStore::with_horizons(&path, ApplyPolicy::default(), horizons).expect("reopen");
    let previous = b.hashes.last().copied().expect("parent");
    let cand = candidate_on(&store, 40, previous, Vec::new());
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge_under(&view, cand, &SHORT)?, facts(40), SHORT)?)
    });
    assert!(
        out.is_err(),
        "the boundary does not commit over a decreasing total"
    );
    assert_eq!(tip(&store), 39);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(40),
            row: StoreInvariant::FoldNotMonotone {
                cell: "block_info.cumulative_tx_count",
                height: 30,
            },
        }
    );
    cleanup(&path);
}

/// The decrease the coinbase term can mask: listed `30 → 25` between
/// heights 9 and 29 derives to storage totals `40 → 55`, so a check on the
/// derived sums would pass. SI-13 is a property of the listed fold and is
/// checked on the raw samples (Copilot, PR #861).
#[test]
fn a_decrease_smaller_than_the_coinbase_term_still_refuses_the_boundary() {
    let path = tmp("prune-monotone-masked");
    let horizons = Horizons::new(
        SettlementEpochBlocks::new(10).expect("non-zero"),
        BlockCount::from_raw(3),
        SHORT.reorg_cap(),
    )
    .expect("cap ≤ retention < epoch");
    let store = ChainStore::with_horizons(&path, ApplyPolicy::default(), horizons).expect("create");
    let mut b = Builder::under(SHORT);
    b.connect(&store, 0, 39, |_| Vec::new());
    drop(store);
    plant_listed(&path, 9, 30);
    plant_listed(&path, 29, 25);
    let store = ChainStore::with_horizons(&path, ApplyPolicy::default(), horizons).expect("reopen");
    let previous = b.hashes.last().copied().expect("parent");
    let cand = candidate_on(&store, 40, previous, Vec::new());
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge_under(&view, cand, &SHORT)?, facts(40), SHORT)?)
    });
    assert!(
        out.is_err(),
        "40 → 55 in storage ids hides 30 → 25 in the fold"
    );
    assert_eq!(tip(&store), 39);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(40),
            row: StoreInvariant::FoldNotMonotone {
                cell: "block_info.cumulative_tx_count",
                height: 30,
            },
        }
    );
    cleanup(&path);
}

/// Replace `block_info[height].cumulative_tx_count`. A raw write: the
/// store's own connect never records a decrease.
fn plant_listed(path: &std::path::Path, height: u64, listed: u64) {
    let db = redb::Database::open(path).expect("open raw");
    let txn = db.begin_write().expect("write");
    {
        let mut table = txn.open_table(BLOCK_INFO).expect("block_info");
        let info = {
            let guard = table.get(height).expect("get").expect("row");
            let mut info = guard.value().decode().expect("decodes");
            info.cumulative_tx_count = listed;
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
        Ok(batch.connect(judge_under(&view, cand, &RULES)?, facts(400), RULES)?)
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
            facts(0),
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
    // A mixed chain: spends in shard 0 (discarded at the epoch-3 boundary), a
    // spend in shard 1 (retained), and empty blocks — the coinbase-only case —
    // everywhere else.
    let listed = |h: u64| match h {
        5 => vec![spend(1, 2)],
        7 => vec![spend(3, 2)],
        250 => vec![spend(2, 2)],
        _ => Vec::new(),
    };
    b.connect(&store, 0, 199, listed);
    b.connect(&store, 200, 200, listed);
    b.connect(&store, 201, 299, listed);

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
    let at_300 = b.connect(&store, 300, 300, listed).remove(0);
    assert_eq!(
        at_300.pruned.expect("a boundary").shards(),
        0..1,
        "D(3) is shard 0"
    );
    assert_eq!(
        prunable_state(&store, 6),
        Some(false),
        "the spend at block 5 must actually be discarded, or this test proves nothing"
    );

    // Leg (f): every answer is unchanged, the discarded spend included.
    let after: Vec<Option<bool>> = (0..count).map(|id| good_state(&store, id)).collect();
    assert_eq!(
        before, after,
        "the domain answer moved across a prune — pruned and archival nodes would \
         disagree on shard boundaries"
    );
    assert_eq!(
        good_state(&store, 6),
        Some(true),
        "a DISCARDED spend is still in the domain: its rows outlive its regions"
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
