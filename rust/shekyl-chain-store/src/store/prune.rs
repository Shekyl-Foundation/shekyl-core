// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The retention prune (DRS-E1 S-PRUNE, `DRS_E1_SPRUNE.md`): the boundary
//! batch that runs **inside the connect transaction** of the block at
//! `E·SEB`, and the pop floor it establishes.
//!
//! # Two horizons and a floor (§3)
//!
//! | Horizon | Retires | When |
//! | --- | --- | --- |
//! | Bodies (`txs_prunable`, `txs_pqc_auths`) | shard `k`, whole | the epoch boundary after `k`'s freeze epoch: `close_epoch(k) + 2 ≤ E` |
//! | Pop-undo journal (`undo_log`) | rows below `tip − retention` | every boundary; `retention` is `D_max` in production |
//!
//! The body horizon is a rule of the epoch calendar — there is no constant
//! to name and no watermark to store. The undo floor is the one number the
//! store keeps ([`UndoLogFloorCell`]), because `pop` must tell *pruned
//! below* from *lost* and nothing else records what was retired.
//!
//! # The batch is named by the epoch; nothing is searched (§4)
//!
//! At the connect of height `E·SEB`, `E ≥ 2`, the shards to discard are
//!
//! > `D(E) = { k : close_epoch(k) + 2 ≤ E ≤ close_epoch(k) + 3 }`
//!
//! — the shards whose `close_height` falls in `[max(E−3, 0)·SEB, (E−1)·SEB)`.
//! A shard's last transaction is id `(k+1)·T − 1`; a height interval is a
//! `cumulative_tx_count` interval; so `D(E)` is a contiguous `k` range read
//! off **two `block_info` rows**, and the division `⌊id / T⌋` places every
//! boundary. No table of boundaries, no length rows, no read of what is
//! present — a presence read that *selected* what to discard would be a
//! second, node-local source (§8), and the whole point is that every node
//! computes the same `D(E)` whether it discarded last epoch, skeleton-synced
//! or just booted. Every epoch comparison is a branch or an addition, never
//! `E − 2` on a `u64` (§4, Bugbot 2026-09-23).
//!
//! Running inside the boundary block's own transaction makes "connected
//! past `E·SEB` with `D(E)` un-run" unrepresentable: a batch that dies
//! takes its connect with it. The hook can fire twice for one `E` only
//! through a reorg across the boundary block; both halves are idempotent
//! (the ranges are already empty; the floor is monotone), and §8 makes that
//! a test.
//!
//! # Not journaled, by design (§4, §7)
//!
//! A discard is not pop-reversible: the bytes are gone from every node at
//! the same boundary, and `Prunable::Discarded` is the one state for
//! *discarded* and *never held* (§7.7 leg iii). So the batch writes through
//! the raw tables after the connect's recording is sealed, and the undo row
//! for the boundary block carries the block's writes and none of the
//! prune's. The hash rows (`txs_prunable_hash`, `txs_pqc_auth_hash`) are
//! permanent and outside every prune surface (§5).
//!
//! # The pop floor (§7), and the belt that was not minted
//!
//! One refusal, `StoreCannot::PopBelowFloor`: the undo floor — rows below
//! it are gone, a capability limit, loud, never a verdict. The skeleton
//! also asked for a second arm, the body-horizon belt `h_scarce + 1` (block
//! `h_scarce` is mixed — some of its transactions discarded — so it is not
//! poppable), and said it was unreachable while `SEB > retention`. Read at
//! the definitions, it is unreachable **by arithmetic alone**: `h_scarce` is
//! a `close_height` below `(E − 1)·SEB ≤ tip − SEB < tip`, so `tip ≤
//! h_scarce` has no instance under any retention — there is no case to
//! build by hand. A defence that cannot fail consumes the attention that
//! would find the gap (rule 16), so the arm is not minted; the
//! `SEB > retention` inequality is still refused at open
//! ([`StoreCannot::RetentionNotInsideEpoch`]) and const-asserted on the
//! production pair (`shekyl_chain_rules::D_MAX`), because it is what keeps
//! the undo floor above the body horizon. [`h_scarce`] itself stays, as
//! `PDM-Q5`'s band-2 edge: chain-named, no presence read, the same number
//! on every node.

use core::ops::Range;

use redb::WriteTransaction;
use shekyl_chain_rules::D_MAX;
use shekyl_types::{BlockCount, BlockHeight, SHARD_TX_COUNT};

use crate::codec::{BlockInfo, SettlementEpochBlocks, UndoLogFloorCell};
use crate::schema::{BLOCK_INFO, PROPERTIES, TXS_PQC_AUTHS, TXS_PRUNABLE, UNDO_LOG};

use super::chain_reads::{self, ReadFault, ReadTables};
use super::error::{EngineError, StoreCannot, StoreError};
use super::header;
use super::write::WriteBatch;

/// The `block_info` cell as faults name it.
const BLOCK_INFO_CELL: &str = "block_info";

/// The pop floor before anything has been retired: genesis is never
/// poppable, so the lowest poppable height is `1`.
const GENESIS_FLOOR: u64 = 1;

/// The first epoch at which a shard can have crossed its boundary: a shard
/// closing in epoch `c` is discarded at `c + 2`, so epochs `0` and `1` run
/// no batch (§2's genesis guard — a branch, never `E − 2`).
const FIRST_PRUNING_EPOCH: u64 = 2;

/// The two horizons the store runs under: the settlement schedule the file
/// is pinned to, and how many undo rows below the tip it keeps.
///
/// `0 < undo_retention < epoch` is the one invariant, checked at
/// construction and refused at open (`DRS_E1_SPRUNE.md` §3, §12): the pop
/// floor's belt depends on the undo floor sitting above the body horizon.
/// Production runs `D_max`; a regtest override that shortens the epoch
/// shortens the retention with it, so the invariant holds on every nettype
/// (rule 71).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Horizons {
    epoch: SettlementEpochBlocks,
    undo_retention: BlockCount,
}

impl Horizons {
    /// The schedule with an explicit undo retention.
    ///
    /// # Errors
    ///
    /// [`StoreCannot::RetentionNotInsideEpoch`] unless `0 < undo_retention < epoch`.
    pub fn new(
        epoch: SettlementEpochBlocks,
        undo_retention: BlockCount,
    ) -> Result<Self, StoreCannot> {
        let retention = undo_retention.to_raw();
        if retention == 0 || retention >= epoch.get() {
            return Err(StoreCannot::RetentionNotInsideEpoch {
                retention: undo_retention,
                epoch,
            });
        }
        Ok(Self {
            epoch,
            undo_retention,
        })
    }

    /// The schedule with the production retention, `D_max`.
    ///
    /// # Errors
    ///
    /// [`StoreCannot::RetentionNotInsideEpoch`] if `epoch ≤ D_max` — a
    /// shortened schedule must name its own retention.
    pub fn production(epoch: SettlementEpochBlocks) -> Result<Self, StoreCannot> {
        Self::new(epoch, D_MAX)
    }

    /// For a read-only handle, which retires nothing: the schedule with the
    /// production retention, **unchecked** — no write can run under it.
    pub(super) const fn read_only(epoch: SettlementEpochBlocks) -> Self {
        Self {
            epoch,
            undo_retention: D_MAX,
        }
    }

    /// The settlement schedule.
    #[must_use]
    pub const fn epoch(&self) -> SettlementEpochBlocks {
        self.epoch
    }

    /// Undo rows kept below the tip.
    #[must_use]
    pub const fn undo_retention(&self) -> BlockCount {
        self.undo_retention
    }

    /// `settlement_epoch_at_height(h) = h / SEB`.
    const fn epoch_of(&self, height: u64) -> u64 {
        height / self.epoch.get()
    }

    /// The first height of epoch `e`.
    const fn first_height_of(&self, e: u64) -> u64 {
        e * self.epoch.get()
    }

    /// Whether `height` is a boundary at which the batch runs: `E·SEB` with
    /// `E ≥ 2`.
    const fn is_pruning_boundary(&self, height: u64) -> bool {
        height.is_multiple_of(self.epoch.get()) && self.epoch_of(height) >= FIRST_PRUNING_EPOCH
    }
}

/// What a boundary connect retired (§4): the shard range whose bodies were
/// discarded — empty when no shard closed in the window — and the undo
/// floor the store now keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pruned {
    /// The first shard `k` whose `txs_prunable` and `txs_pqc_auths` rows
    /// were discarded (`[k·T, (k+1)·T)`); equal to `shard_end` when the
    /// window held no closed shard.
    pub shard_start: u64,
    /// One past the last discarded shard.
    pub shard_end: u64,
    /// The lowest height whose `undo_log` row is kept after this boundary.
    pub undo_floor: BlockHeight,
}

impl Pruned {
    /// The discarded shards as a range, empty when nothing closed.
    #[must_use]
    pub const fn shards(&self) -> Range<u64> {
        self.shard_start..self.shard_end
    }
}

impl WriteBatch<'_, '_> {
    /// **The boundary batch.** Called by `connect` after the block's undo
    /// row is sealed; a no-op unless `height` is `E·SEB` with `E ≥ 2`.
    ///
    /// # Errors
    ///
    /// SI-7 (poisons) if a `block_info` row the calendar names is absent or
    /// does not decode; engine faults.
    pub(super) fn prune_at_boundary(&self, height: u64) -> Result<Option<Pruned>, StoreError> {
        let horizons = self.horizons();
        if !horizons.is_pruning_boundary(height) {
            return Ok(None);
        }
        let e = horizons.epoch_of(height);
        let shards = self.discard_set(e)?;
        if !shards.is_empty() {
            let ids = shards.start * SHARD_TX_COUNT..shards.end * SHARD_TX_COUNT;
            discard_range(self.txn(), TXS_PRUNABLE, ids.clone())?;
            discard_range(self.txn(), TXS_PQC_AUTHS, ids)?;
        }
        let undo_floor = self.retire_undo_rows(height)?;
        Ok(Some(Pruned {
            shard_start: shards.start,
            shard_end: shards.end,
            undo_floor,
        }))
    }

    /// `D(E)` as a shard range (module docs). SI-7 poisons the batch.
    fn discard_set(&self, e: u64) -> Result<Range<u64>, StoreError> {
        discard_set(self.txn(), self.horizons(), e).map_err(|f| self.arm_read_fault(f))
    }

    /// Delete `undo_log` rows below `height − retention` and raise the
    /// persisted floor to it (monotone). Returns the floor now in force.
    fn retire_undo_rows(&self, height: u64) -> Result<BlockHeight, StoreError> {
        let retention = self.horizons().undo_retention().to_raw();
        // `height ≥ 2·SEB > retention` at every call: the subtraction cannot
        // wrap, and saying so as a branch keeps it from being a claim.
        let Some(floor) = height.checked_sub(retention) else {
            return self.undo_floor();
        };
        let floor = floor.max(GENESIS_FLOOR);
        let current = self.undo_floor()?.to_raw();
        if floor <= current {
            return Ok(BlockHeight::from_raw(current));
        }
        {
            let mut undo = self
                .txn()
                .open_table(UNDO_LOG)
                .map_err(EngineError::Table)?;
            undo.retain_in::<u64, _>(..floor, |_, _| false)
                .map_err(EngineError::Storage)?;
        }
        let floor = BlockHeight::from_raw(floor);
        header::put::<UndoLogFloorCell>(self.txn(), &floor)?;
        Ok(floor)
    }

    /// The lowest height whose `undo_log` row is kept: the persisted floor,
    /// or genesis's `1` when nothing has been retired.
    pub(super) fn undo_floor(&self) -> Result<BlockHeight, StoreError> {
        let table = self
            .txn()
            .open_table(PROPERTIES)
            .map_err(EngineError::Table)?;
        Ok(
            header::get::<UndoLogFloorCell>(&table)?
                .unwrap_or(BlockHeight::from_raw(GENESIS_FLOOR)),
        )
    }

    /// [`h_scarce`] at `tip`, through this batch. SI-7 poisons the batch.
    pub fn h_scarce(&self, tip: u64) -> Result<Option<u64>, StoreError> {
        h_scarce(self.txn(), self.horizons(), tip).map_err(|f| self.arm_read_fault(f))
    }
}

/// `D(E)` as a shard range: the shards whose last transaction has an id in
/// `[first_tx_id(lo), first_tx_id(hi))` for the heights `lo = max(E−3, 0)·SEB`,
/// `hi = (E−1)·SEB` (module docs). `e ≥ 2`.
fn discard_set<T: ReadTables>(
    txn: &T,
    horizons: Horizons,
    e: u64,
) -> Result<Range<u64>, ReadFault> {
    // `E ≥ 2` here, so `E − 1 ≥ 1` cannot wrap; `E − 3` is a branch.
    let lo_height = if e >= 3 {
        horizons.first_height_of(e - 3)
    } else {
        0
    };
    let hi_height = horizons.first_height_of(e - 1);
    let lo_id = first_tx_id(txn, lo_height)?;
    let hi_id = first_tx_id(txn, hi_height)?;
    // The last id of shard `k` is `(k+1)·T − 1`. It is `≥ lo_id` iff
    // `k ≥ ⌊lo_id / T⌋`, and `< hi_id` iff `k < ⌊hi_id / T⌋`.
    let start = lo_id / SHARD_TX_COUNT;
    let end = hi_id / SHARD_TX_COUNT;
    Ok(start..end.max(start))
}

/// `first_tx_id(h)`: the storage id of the first transaction at height `h`
/// — every transaction recorded through height `h − 1`, and `0` at genesis.
///
/// **Not** `block_info[h − 1].cumulative_tx_count` alone, as the S-PRUNE
/// skeleton wrote it (§2): that running total counts the block's **listed**
/// transactions (`connect.rs`, "the parent's plus this block's listed
/// transactions"), while storage ids are dense over **every** recorded
/// transaction, coinbase included (`record_tx` runs for the miner
/// transaction first). One coinbase per block (CEN-F), so the ids through
/// height `h − 1` are the listed total plus `h` coinbases. Read at the
/// code, not the plan — the rule-16 corollary.
fn first_tx_id<T: ReadTables>(txn: &T, height: u64) -> Result<u64, ReadFault> {
    let Some(parent) = height.checked_sub(1) else {
        return Ok(0);
    };
    ids_through(txn, parent)
}

/// How many storage ids the chain has issued through height `h` inclusive:
/// `block_info[h].cumulative_tx_count` listed transactions plus `h + 1`
/// coinbases. Every id below the value is at a height `≤ h`.
fn ids_through<T: ReadTables>(txn: &T, height: u64) -> Result<u64, ReadFault> {
    let listed = block_info_at(txn, height)?.cumulative_tx_count;
    listed
        .checked_add(height)
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| {
            ReadFault::Invariant(super::error::StoreInvariant::FoldOverflow {
                cell: "block_info.cumulative_tx_count",
            })
        })
}

/// A `block_info` row the calendar says exists: absent is SI-7 (the table
/// is dense below the tip), as is a row that does not decode.
fn block_info_at<T: ReadTables>(txn: &T, height: u64) -> Result<BlockInfo, ReadFault> {
    chain_reads::cell(txn, BLOCK_INFO, height, BLOCK_INFO_CELL)?
        .ok_or_else(|| chain_reads::absent(BLOCK_INFO_CELL))
}

/// `h_scarce` at `tip` (§4, §7): the `close_height` of the last shard with
/// `close_epoch(k) + 2 ≤ current_epoch` — the highest block some of whose
/// transactions the calendar has discarded, `PDM-Q5`'s band-2 edge. `None`
/// in epochs `0` and `1`, and before any shard has closed. Chain-named: the
/// same number on a node that discarded and on one that never held a body.
pub(super) fn h_scarce<T: ReadTables>(
    txn: &T,
    horizons: Horizons,
    tip: u64,
) -> Result<Option<u64>, ReadFault> {
    let e = horizons.epoch_of(tip);
    if e < FIRST_PRUNING_EPOCH {
        return Ok(None);
    }
    // Every shard whose last id is below `first_tx_id((E−1)·SEB)` has
    // `close_epoch + 2 ≤ E`; the last of them is `⌊hi_id / T⌋ − 1`.
    let hi_id = first_tx_id(txn, horizons.first_height_of(e - 1))?;
    let Some(last_closed) = (hi_id / SHARD_TX_COUNT).checked_sub(1) else {
        return Ok(None);
    };
    let last_tx_id = (last_closed + 1) * SHARD_TX_COUNT - 1;
    height_of_tx_id(txn, last_tx_id, tip).map(Some)
}

/// The height that recorded transaction id `id`: the smallest `h ≤ tip`
/// with [`ids_through`]`(h) > id`, by binary search over the running total
/// (dense, monotone — SI-2, SI-9).
fn height_of_tx_id<T: ReadTables>(txn: &T, id: u64, tip: u64) -> Result<u64, ReadFault> {
    let (mut lo, mut hi) = (0u64, tip);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if ids_through(txn, mid)? > id {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    Ok(lo)
}

/// Delete every row of a `u64`-keyed table in `ids` — the discard's one
/// verb, on the raw table (module docs, *Not journaled, by design*).
fn discard_range<V: redb::Value + 'static>(
    txn: &WriteTransaction,
    table: redb::TableDefinition<'static, u64, V>,
    ids: Range<u64>,
) -> Result<(), StoreError> {
    let mut table = txn.open_table(table).map_err(EngineError::Table)?;
    table
        .retain_in::<u64, _>(ids, |_, _| false)
        .map_err(EngineError::Storage)?;
    Ok(())
}

#[cfg(test)]
mod horizon_tests {
    use super::*;

    fn seb(n: u64) -> SettlementEpochBlocks {
        SettlementEpochBlocks::new(n).expect("non-zero")
    }

    #[test]
    fn horizons_hold_zero_lt_retention_lt_epoch() {
        assert!(Horizons::new(seb(10), BlockCount::from_raw(3)).is_ok());
        assert!(matches!(
            Horizons::new(seb(10), BlockCount::from_raw(0)),
            Err(StoreCannot::RetentionNotInsideEpoch { .. })
        ));
        assert!(matches!(
            Horizons::new(seb(10), BlockCount::from_raw(10)),
            Err(StoreCannot::RetentionNotInsideEpoch { .. })
        ));
        assert!(
            Horizons::production(seb(10_000)).is_ok(),
            "the production pair"
        );
        assert!(
            matches!(
                Horizons::production(seb(50)),
                Err(StoreCannot::RetentionNotInsideEpoch { .. })
            ),
            "a shortened epoch must name its own retention"
        );
    }

    #[test]
    fn the_batch_runs_at_boundaries_from_epoch_two() {
        let h = Horizons::new(seb(10), BlockCount::from_raw(3)).expect("ok");
        for height in [0, 10, 5, 15, 21] {
            assert!(!h.is_pruning_boundary(height), "{height}");
        }
        for height in [20, 30, 100] {
            assert!(h.is_pruning_boundary(height), "{height}");
        }
    }
}
