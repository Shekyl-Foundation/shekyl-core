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
use shekyl_types::{
    AttestationRoot, BlockCount, BlockHash, BlockHeight, BlockWeight, CurveTreeRoot,
    LongTermWeight, SHARD_TX_COUNT,
};
use shekyl_units::AtomicUnits;
use shekyl_wire::{Block, BlockHeader, Transaction};

use super::connect_fixtures::{coinbase, judge, spend};
use super::store_tests::{cleanup, tmp, TestErr};
use super::*;
use crate::codec::{Canonical, SettlementEpochBlocks, UndoLogFloorCell};
use crate::ids::TxStorageId;
use crate::schema::{BLOCK_INFO, UNDO_LOG};

const SEB: u64 = 100;
const RETENTION: u64 = 50;

fn horizons() -> Horizons {
    Horizons::new(
        SettlementEpochBlocks::new(SEB).expect("non-zero"),
        BlockCount::from_raw(RETENTION),
    )
    .expect("0 < retention < epoch")
}

/// A curve root that is a function of the height, wide enough for long
/// chains (the shared fixture packs the height into one byte).
fn root_of(height: u64) -> CurveTreeRoot {
    let mut bytes = [0xc0; 32];
    bytes[..8].copy_from_slice(&height.to_le_bytes());
    CurveTreeRoot::from_bytes(bytes)
}

fn root_before(height: u64) -> CurveTreeRoot {
    match height.checked_sub(1) {
        None => CurveTreeRoot::EMPTY,
        Some(parent) => root_of(parent),
    }
}

fn candidate(height: u64, previous: BlockHash, listed: Vec<Transaction>) -> Candidate {
    let block = Block {
        header: BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: 1_000 + height * 60,
            previous,
            nonce: 7,
            curve_tree_root: root_before(height),
            attestation_root: AttestationRoot::from_bytes([0x33; 32]),
        },
        miner_transaction: coinbase(height),
        transaction_hashes: listed.iter().map(Transaction::hash).collect(),
    };
    Candidate::new(block, listed)
}

fn facts(height: u64) -> ConnectFacts {
    ConnectFacts {
        weight: Fact::passed_through(BlockWeight::from_raw(1_000 + height)),
        long_term_weight: Fact::passed_through(LongTermWeight::from_raw(900 + height)),
        coins_generated: Fact::passed_through(AtomicUnits::from_raw((height + 1) * 1_000_000)),
        burned: Fact::passed_through(AtomicUnits::from_raw(0)),
        root_after: Fact::passed_through(root_of(height)),
        long_term_effective_median: Fact::passed_through(LongTermWeight::from_raw(
            300_000 + 7 * height,
        )),
    }
}

/// A chain under construction: the hashes so far, and the listed
/// transactions to hand each height.
struct Builder {
    hashes: Vec<BlockHash>,
    listed: Vec<Vec<Transaction>>,
}

impl Builder {
    fn new() -> Self {
        Self {
            hashes: Vec::new(),
            listed: Vec::new(),
        }
    }

    /// Connect heights `from..=to` in one batch, handing `listed(h)` at each;
    /// returns each connect's outcome.
    fn connect(
        &mut self,
        store: &ChainStore,
        from: u64,
        to: u64,
        listed: impl Fn(u64) -> Vec<Transaction>,
    ) -> Vec<Connected> {
        let mut cands = Vec::new();
        for h in from..=to {
            let previous = self.hashes.last().copied().unwrap_or(BlockHash::NULL);
            let txs = listed(h);
            let cand = candidate(h, previous, txs.clone());
            self.hashes.push(cand.block.hash());
            self.listed.push(txs);
            cands.push(cand);
        }
        let out: Result<Vec<Connected>, TestErr> = store.write(|batch| {
            let view = batch.chain_view();
            let mut out = Vec::new();
            for (h, cand) in (from..=to).zip(cands) {
                out.push(batch.connect(judge(&view, cand)?, facts(h), RuleSet::GENESIS)?);
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
    let (store, _b, at_200, at_300) = chain_to_300(&path);

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
        let early = snap
            .tx_record(&spend(1, 2).hash())
            .expect("read")
            .expect("recorded");
        assert_eq!(
            early.pqc_auths,
            Some(PqcAuths::Discarded),
            "shard 0's pqc region went with it"
        );
        assert!(early.pqc_auth_hash.is_some(), "the hash row is permanent");
        let late = snap
            .tx_record(&spend(2, 2).hash())
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

/// A later `block_info` row whose storage-id total is below an earlier
/// one's is SI-13. The boundary connect must not commit with `D(E)` skipped.
#[test]
fn a_decreasing_storage_id_total_refuses_the_boundary() {
    let path = tmp("prune-monotone");
    let horizons = Horizons::new(
        SettlementEpochBlocks::new(10).expect("non-zero"),
        BlockCount::from_raw(3),
    )
    .expect("0 < retention < epoch");
    let store = ChainStore::with_horizons(&path, ApplyPolicy::default(), horizons).expect("create");
    let mut b = Builder::new();
    // Height 40 is epoch 4, the first boundary whose window starts above
    // genesis: `D(4)` reads `first_tx_id(10)` and `first_tx_id(30)`.
    b.connect(&store, 0, 39, |_| Vec::new());
    drop(store);
    plant_listed(&path, 9, 5_000);
    let store = ChainStore::with_horizons(&path, ApplyPolicy::default(), horizons).expect("reopen");
    let previous = b.hashes.last().copied().expect("parent");
    let cand = candidate(40, previous, Vec::new());
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge(&view, cand)?, facts(40), RuleSet::GENESIS)?)
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
