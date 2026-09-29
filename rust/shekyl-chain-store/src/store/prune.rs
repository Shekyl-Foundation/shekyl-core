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
//! below* from *lost* and nothing else records what was retired: S-CHAIN-W
//! §5.4 read the floor as the journal's first key, and that reading holds
//! while a row stands — but a `pop` sequence past the retention empties the
//! journal, and `pop` also removes the `block_info` rows that would date
//! the last boundary, so at that point no table can say whether the row
//! for the new tip was retired or lost (SPR-4). The cell can. It is
//! **checked** against the table's first key at `pop` and at every
//! boundary ([`UndoFault::FloorMismatch`](super::UndoFault::FloorMismatch),
//! SI-6), so the redundancy can fail rather than drift (rule 16).
//!
//! # The batch is named by the epoch; nothing is searched (§4)
//!
//! At the connect of height `E·SEB`, `E ≥ 2`, the shards to discard are
//!
//! > `D(E) = { k : close_epoch(k) + 2 ≤ E ≤ close_epoch(k) + 3 }`
//!
//! — the shards whose `close_height` falls in `[max(E−3, 0)·SEB, (E−1)·SEB)`.
//! Shards are cut by **archival length** (`SHT-Q2` RULED, Rick 2026-09-29):
//! a transaction starting at archival offset `c` — the lengths of every
//! transaction recorded before it — belongs to shard `⌊c / W⌋`
//! ([`shekyl_types::shard_of`]), global multiples of `W`, no table. Shard
//! `k` closes at the first height whose cumulative length reaches
//! `(k+1)·W`: no later transaction can start below it. With `C(h)` the
//! cumulative length **before** `h` (the parent's
//! `block_info.cumulative_archival_len`, `0` at genesis), a close height in
//! `[lo, hi)` is `C(lo) < (k+1)·W ≤ C(hi)`, so `D(E)` is the contiguous
//! range `⌊C(lo)/W⌋ .. ⌊C(hi)/W⌋`, read off **two `block_info` rows**.
//!
//! The rows to delete are storage ids, and the offset `k·W` names one: the
//! first transaction starting at or past it. [`first_id_at_offset`] finds
//! the height by binary search over the cumulative cell, then walks that
//! block's ids reading `txs_archival_len` (absent ⇔ `0`) — permanent
//! skeleton rows no prune deletes. No table of boundaries and no read of
//! what is present — a presence read that *selected* what to discard would
//! be a second, node-local source (§8), and the whole point is that every
//! node computes the same `D(E)` whether it discarded last epoch,
//! skeleton-synced or just booted: the cell and the length rows are what a
//! pruned node and an archival node both hold. Every epoch comparison is a
//! branch or an addition, never `E − 2` on a `u64` (§4, Bugbot 2026-09-23).
//!
//! Running inside the boundary block's own transaction makes "connected
//! past `E·SEB` with `D(E)` un-run" unrepresentable: a batch that dies
//! takes its connect with it. The hook can fire twice for one `E` only
//! through a reorg across the boundary block; both halves are idempotent
//! (the ranges are already empty; the floor is monotone), and §8 makes that
//! a test. The second run names the same ranges: every row it reads —
//! `C(lo)`, `C(hi)`, and the blocks the offset walk visits — sits below
//! `(E−1)·SEB`, under the pop floor `E·SEB − retention` because
//! `retention < SEB`, so no pop can have moved it.
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
//! poppable). The belt guards pop *targets*, and every target is at or
//! above the undo floor, which at the boundary `E·SEB` is `E·SEB −
//! retention`; that floor is `> (E − 1)·SEB > h_scarce` **exactly when
//! `retention < SEB`** — the inequality [`Horizons::new`] refuses at open
//! ([`StoreCannot::RetentionNotInsideEpoch`]) and the production pair
//! const-asserts (`shekyl_chain_rules::D_MAX`). Under that refusal the arm
//! has no instance to fire on, and a defence that cannot fail consumes the
//! attention that would find the gap (rule 16), so it is not minted.
//! Relax the refusal and the belt is reachable: the dependency is the
//! reason, not "arithmetic alone" (a first landing said the latter, and
//! `h_scarce < tip` is true and beside the point — SPR-7). [`h_scarce`]
//! itself stays, as `PDM-Q5`'s band-2 edge: chain-named, no presence read,
//! the same number on every node.

use core::ops::Range;

use redb::{ReadableTable, WriteTransaction};
use shekyl_chain_rules::RuleSet;
use shekyl_types::{
    shard_of, shard_start, storage_ids_through, ArchivalLength, BlockCount, BlockHeight, ShardId,
};

use crate::codec::{BlockInfo, SettlementEpochBlocks, UndoLogFloorCell};
use crate::schema::{
    BLOCK_INFO, PROPERTIES, TXS_ARCHIVAL_LEN, TXS_PQC_AUTHS, TXS_PRUNABLE, UNDO_LOG,
};

use super::chain_reads::{self, ReadFault, ReadTables};
use super::error::{EngineError, StoreCannot, StoreError, StoreInvariant, UndoFault};
use super::header;
use super::write::WriteBatch;

/// The `block_info` cell as faults name it.
const BLOCK_INFO_CELL: &str = "block_info";

/// The listed-transaction fold inside that cell. SI-8 and SI-13 name it.
const TX_COUNT_CELL: &str = "block_info.cumulative_tx_count";

/// The archival-length fold inside that cell (`SHT-Q2`). SI-8, SI-13 and
/// SI-19 name it.
const ARCHIVAL_LEN_CELL: &str = "block_info.cumulative_archival_len";

/// The per-transaction length rows, as a decode fault names them.
const ARCHIVAL_LEN_ROW: &str = "txs_archival_len";

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
/// The retention is boxed between two numbers that are not the store's:
/// **at least the in-force rule set's reorg cap** (`RuleSet::reorg_cap`,
/// S-CHAIN-W SCW-7 — below it a legal reorg meets `PopBelowFloor`) and
/// **strictly inside the epoch** (`DRS_E1_SPRUNE.md` §3, §12 — the pop
/// floor sits above the body horizon *because* `retention < SEB`, SPR-7).
/// Both are checked at construction and refused at open; the cap is
/// re-checked by `connect` against the set in force at every height, so a
/// schedule step that raises the cap is refused at the block it applies
/// to. The store holds no rule set and no schedule (rule 71): the caller
/// hands the cap here as it hands the set to `connect`. Production runs
/// `D_max` on both sides; a regtest under a shortened epoch runs a
/// Fakechain rule set whose cap fits inside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Horizons {
    epoch: SettlementEpochBlocks,
    undo_retention: BlockCount,
}

impl Horizons {
    /// The schedule with an explicit undo retention, under a rule set whose
    /// reorg cap is `reorg_cap`.
    ///
    /// # Errors
    ///
    /// [`StoreCannot::RetentionBelowReorgCap`] if `undo_retention < reorg_cap`;
    /// [`StoreCannot::RetentionNotInsideEpoch`] unless `0 < undo_retention < epoch`.
    pub fn new(
        epoch: SettlementEpochBlocks,
        undo_retention: BlockCount,
        reorg_cap: BlockCount,
    ) -> Result<Self, StoreCannot> {
        let retention = undo_retention.to_raw();
        if retention < reorg_cap.to_raw() {
            return Err(StoreCannot::RetentionBelowReorgCap {
                retention: undo_retention,
                reorg_cap,
            });
        }
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

    /// The schedule with the production retention: the genesis rule set's
    /// cap, `D_max`, on both sides.
    ///
    /// # Errors
    ///
    /// [`StoreCannot::RetentionNotInsideEpoch`] if `epoch ≤ D_max` — a
    /// shortened schedule runs a Fakechain rule set and names its retention
    /// against that set's cap.
    pub fn production(epoch: SettlementEpochBlocks) -> Result<Self, StoreCannot> {
        let cap = RuleSet::GENESIS.reorg_cap();
        Self::new(epoch, cap, cap)
    }

    /// Whether this retention covers `in_force`'s reorg cap (SCW-7) —
    /// `connect`'s per-height belt.
    ///
    /// # Errors
    ///
    /// [`StoreCannot::RetentionBelowReorgCap`] if it does not.
    pub(super) fn check_covers(&self, in_force: &RuleSet) -> Result<(), StoreCannot> {
        let reorg_cap = in_force.reorg_cap();
        if self.undo_retention.to_raw() < reorg_cap.to_raw() {
            return Err(StoreCannot::RetentionBelowReorgCap {
                retention: self.undo_retention,
                reorg_cap,
            });
        }
        Ok(())
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
    /// were discarded — the transactions starting at archival offsets in
    /// `[k·W, (k+1)·W)`; equal to `shard_end` when the window held no
    /// closed shard.
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
            let ids = shard_ids(self.txn(), shards.clone(), height)
                .map_err(|f| self.arm_read_fault(f))?;
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
    /// persisted floor to it (monotone). Returns the floor now in force,
    /// after checking that the journal's first key **is** that floor: the
    /// block at `height` sealed its row before this ran and every row from
    /// the floor up is kept, so a first key elsewhere is a journal with a
    /// gap (SI-6, [`UndoFault::FloorMismatch`](super::UndoFault::FloorMismatch)).
    fn retire_undo_rows(&self, height: u64) -> Result<BlockHeight, StoreError> {
        let retention = self.horizons().undo_retention().to_raw();
        let current = self.undo_floor()?.to_raw();
        // `height ≥ 2·SEB > retention` at every call: the subtraction cannot
        // wrap, and saying so as a branch keeps it from being a claim. The
        // floor never lowers: a reorg across the boundary re-runs this with
        // the same `height`.
        let floor = height
            .checked_sub(retention)
            .map_or(current, |f| f.max(GENESIS_FLOOR).max(current));
        let first = {
            let mut undo = self
                .txn()
                .open_table(UNDO_LOG)
                .map_err(EngineError::Table)?;
            if floor > current {
                undo.retain_in::<u64, _>(..floor, |_, _| false)
                    .map_err(EngineError::Storage)?;
            }
            let first = undo
                .first()
                .map_err(EngineError::Storage)?
                .map(|(h, _)| h.value());
            first
        };
        if floor > current {
            header::put::<UndoLogFloorCell>(self.txn(), &BlockHeight::from_raw(floor))?;
        }
        // The block at `height` sealed its row before this ran, so an empty
        // journal here is a lost one; a first key that is not the floor just
        // written is a gap.
        if first.is_none() {
            return Err(self.poison().arm(StoreInvariant::UndoLogIncoherent {
                height,
                fault: UndoFault::NoRowForTip,
            }));
        }
        self.check_journal_first(first, height)?;
        Ok(BlockHeight::from_raw(floor))
    }

    /// The persisted floor cell: `None` while nothing has been retired.
    fn undo_floor_cell(&self) -> Result<Option<BlockHeight>, StoreError> {
        let table = self
            .txn()
            .open_table(PROPERTIES)
            .map_err(EngineError::Table)?;
        // A malformed cell is SI-7 and must arm the latch like every other
        // typed cell read through the batch: `pop` must not leave the
        // writer live over a floor it cannot read, and a boundary connect
        // whose caller swallows the error must not commit with the prune
        // skipped (Copilot, PR #861).
        header::get::<UndoLogFloorCell>(&table).map_err(|e| self.arm_if_invariant(e))
    }

    /// The lowest **poppable** height: the persisted floor, or `1` when
    /// nothing has been retired (genesis has a row and is never poppable).
    pub(super) fn undo_floor(&self) -> Result<BlockHeight, StoreError> {
        Ok(self
            .undo_floor_cell()?
            .unwrap_or(BlockHeight::from_raw(GENESIS_FLOOR)))
    }

    /// The key the journal's lowest row must carry (SPR-4): the persisted
    /// floor, or genesis's own row, `0`, while nothing has been retired.
    /// Every connect writes its row and the prune deletes only below the
    /// floor, so whenever the journal has a row at all its first key is
    /// this — a different first key is a journal with a gap, SI-6
    /// ([`UndoFault::FloorMismatch`]).
    pub(super) fn check_journal_first(
        &self,
        first: Option<u64>,
        height: u64,
    ) -> Result<(), StoreError> {
        let expected = self.undo_floor_cell()?.map_or(0, BlockHeight::to_raw);
        match first {
            Some(first) if first != expected => {
                Err(self.poison().arm(StoreInvariant::UndoLogIncoherent {
                    height,
                    fault: UndoFault::FloorMismatch {
                        first,
                        floor: expected,
                    },
                }))
            }
            _ => Ok(()),
        }
    }

    /// [`h_scarce`] at `tip`, through this batch. SI-7 poisons the batch.
    pub fn h_scarce(&self, tip: u64) -> Result<Option<u64>, StoreError> {
        h_scarce(self.txn(), self.horizons(), tip).map_err(|f| self.arm_read_fault(f))
    }
}

/// `D(E)` as a shard range: the shards whose close height lies in
/// `[lo, hi)` for `lo = max(E−3, 0)·SEB`, `hi = (E−1)·SEB` —
/// `⌊C(lo)/W⌋ .. ⌊C(hi)/W⌋` (module docs). `e ≥ 2`.
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
    // SI-13 on the two raw samples: a decreasing fold would name an
    // inverted range, and an empty window is `start == end`. An inversion
    // poisons and rolls the boundary connect back.
    let lo = archival_before(txn, lo_height)?;
    let hi = archival_before(txn, hi_height)?;
    if hi < lo {
        return Err(archival_not_monotone(hi_height));
    }
    Ok(shard_of(lo).to_raw()..shard_of(hi).to_raw())
}

/// The storage ids of the transactions in `shards`: from the first
/// transaction starting at or past `start·W` to the first starting at or
/// past `end·W`. `tip` bounds the search; both offsets are at most
/// `C((E−1)·SEB)`, which the tip's row covers.
fn shard_ids<T: ReadTables>(
    txn: &T,
    shards: Range<u64>,
    tip: u64,
) -> Result<Range<u64>, ReadFault> {
    let first = first_id_at_offset(txn, offset_of(shards.start)?, tip)?;
    let end = first_id_at_offset(txn, offset_of(shards.end)?, tip)?;
    Ok(first..end)
}

/// `k·W` — the archival offset shard `k` opens at.
fn offset_of(k: u64) -> Result<ArchivalLength, ReadFault> {
    shard_start(ShardId::from_raw(k)).ok_or(ReadFault::Invariant(StoreInvariant::FoldOverflow {
        cell: ARCHIVAL_LEN_CELL,
    }))
}

/// Archival length recorded **before** height `h`: `C(h)`, the parent's
/// `cumulative_archival_len`, and `0` at genesis.
fn archival_before<T: ReadTables>(txn: &T, height: u64) -> Result<ArchivalLength, ReadFault> {
    let Some(parent) = height.checked_sub(1) else {
        return Ok(ArchivalLength::ZERO);
    };
    Ok(block_info_at(txn, parent)?.cumulative_archival_len)
}

/// Archival length recorded **through** height `h` inclusive.
fn archival_through<T: ReadTables>(txn: &T, height: u64) -> Result<ArchivalLength, ReadFault> {
    Ok(block_info_at(txn, height)?.cumulative_archival_len)
}

/// SI-13 on the archival fold. `height` is the later sample.
fn archival_not_monotone(height: u64) -> ReadFault {
    ReadFault::Invariant(StoreInvariant::FoldNotMonotone {
        cell: ARCHIVAL_LEN_CELL,
        height,
    })
}

/// The smallest `h ≤ tip` whose cumulative archival length reaches
/// `offset`, by binary search over the cell (dense, monotone). Every caller
/// asks for an offset the tip's row covers, so a search that ends on a
/// height below `offset`, or on one whose parent already reached it, is a
/// fold the rows do not support (SI-13) — never a height to act on.
fn first_height_reaching<T: ReadTables>(
    txn: &T,
    offset: ArchivalLength,
    tip: u64,
) -> Result<u64, ReadFault> {
    let (mut lo, mut hi) = (0u64, tip);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if archival_through(txn, mid)? >= offset {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    if archival_through(txn, lo)? < offset {
        return Err(archival_not_monotone(lo));
    }
    if lo > 0 && archival_through(txn, lo - 1)? >= offset {
        return Err(archival_not_monotone(lo));
    }
    Ok(lo)
}

/// The storage id of the first transaction whose archival offset is at or
/// past `offset` — the id shard `offset / W` opens at when `offset` is a
/// multiple of `W` (module docs). The height is [`first_height_reaching`];
/// no earlier height holds such a transaction. Its ids are walked in
/// issue order from `C(h)`, adding each `txs_archival_len` row (absent ⇔
/// `0`); when every transaction of `h` starts below `offset`, the answer is
/// the next height's first id. The whole block is walked either way, and
/// the sum must land on the block's own cumulative cell: a disagreement is
/// SI-19, a length row and the fold that was built from it no longer
/// agreeing.
fn first_id_at_offset<T: ReadTables>(
    txn: &T,
    offset: ArchivalLength,
    tip: u64,
) -> Result<u64, ReadFault> {
    let height = first_height_reaching(txn, offset, tip)?;
    let info = block_info_at(txn, height)?;
    // SI-13 on the raw listed samples, before the coinbase term is added:
    // a decrease of one derives to an empty id range, not an inverted one,
    // and would read as a block with no transactions (Copilot, PR #861).
    let listed_before = listed_before(txn, height)?;
    if info.cumulative_tx_count < listed_before {
        return Err(fold_not_monotone(height));
    }
    let first = first_tx_id(height, listed_before)?;
    let end = ids_from(info.cumulative_tx_count, height)?;
    let through = info.cumulative_archival_len;
    let lens = txn.table(TXS_ARCHIVAL_LEN)?;
    let mut at = archival_before(txn, height)?;
    let mut found = None;
    for id in first..end {
        if found.is_none() && at >= offset {
            found = Some(id);
        }
        let len = match lens.get(id)? {
            Some(guard) => guard
                .value()
                .decode()
                .map_err(|cause| chain_reads::undecodable(ARCHIVAL_LEN_ROW, cause))?,
            None => ArchivalLength::ZERO,
        };
        at = at
            .checked_add(len)
            .ok_or(ReadFault::Invariant(StoreInvariant::FoldOverflow {
                cell: ARCHIVAL_LEN_CELL,
            }))?;
    }
    if at != through {
        return Err(ReadFault::Invariant(
            StoreInvariant::ArchivalLengthsDisagree {
                height,
                rows: at.to_raw(),
                cell: through.to_raw(),
            },
        ));
    }
    Ok(found.unwrap_or(end))
}

/// Listed (non-coinbase) transactions recorded **before** height `h`: the
/// raw `cumulative_tx_count` fold at `h − 1`, and `0` at genesis. The
/// sample SI-13 is stated over; the coinbase term is added by
/// [`first_tx_id`], after the check.
fn listed_before<T: ReadTables>(txn: &T, height: u64) -> Result<u64, ReadFault> {
    let Some(parent) = height.checked_sub(1) else {
        return Ok(0);
    };
    Ok(block_info_at(txn, parent)?.cumulative_tx_count)
}

/// `first_tx_id(h)`: the storage id of the first transaction at height `h`,
/// from the listed total before it — `0` at genesis; otherwise
/// [`storage_ids_through`] at `h − 1` (every id issued before `h`).
fn first_tx_id(height: u64, listed_before: u64) -> Result<u64, ReadFault> {
    let Some(parent) = height.checked_sub(1) else {
        return Ok(0);
    };
    ids_from(listed_before, parent)
}

/// Storage ids issued through height `h` inclusive, given the listed total
/// at `h`: the coinbase term is [`storage_ids_through`].
fn ids_from(listed: u64, height: u64) -> Result<u64, ReadFault> {
    storage_ids_through(listed, height).ok_or_else(|| {
        ReadFault::Invariant(StoreInvariant::FoldOverflow {
            cell: TX_COUNT_CELL,
        })
    })
}

/// SI-13: the listed-transaction fold decreased. `height` is the later sample.
fn fold_not_monotone(height: u64) -> ReadFault {
    ReadFault::Invariant(StoreInvariant::FoldNotMonotone {
        cell: TX_COUNT_CELL,
        height,
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
    // Every shard below `⌊C((E−1)·SEB) / W⌋` has `close_epoch + 2 ≤ E`; the
    // last of them, `k`, closes at the first height reaching `(k+1)·W`.
    let hi = archival_before(txn, horizons.first_height_of(e - 1))?;
    let reached = shard_of(hi).to_raw();
    if reached == 0 {
        return Ok(None);
    }
    first_height_reaching(txn, offset_of(reached)?, tip).map(Some)
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

impl super::read::ReadSnapshot<'_> {
    /// `h_scarce` at the recorded tip: the `close_height` of the last shard
    /// the calendar has discarded — `PDM-Q5`'s band-2 edge, the same number
    /// on every node. `None` on an empty chain, in epochs 0–1, and before
    /// any shard has closed.
    ///
    /// # Errors
    ///
    /// SI-7 if a `block_info` row the calendar names is absent or does not
    /// decode; SI-13 if the storage-id total decreases across the search.
    /// A snapshot returns the fault plain — it does not halt the writer.
    pub fn h_scarce(&self) -> Result<Option<BlockHeight>, StoreError> {
        let Some((tip, _)) = chain_reads::tip_of(self.txn()).map_err(ReadFault::into_plain)? else {
            return Ok(None);
        };
        h_scarce(self.txn(), self.horizons(), tip)
            .map(|height| height.map(BlockHeight::from_raw))
            .map_err(ReadFault::into_plain)
    }

    /// The storage ids of `shards` on the recorded chain — the range the
    /// boundary batch would discard for them. Test-only: it lets a test put
    /// the same question to a store before and after a prune.
    #[cfg(test)]
    pub(super) fn shard_storage_ids(&self, shards: Range<u64>) -> Result<Range<u64>, StoreError> {
        let Some((tip, _)) = chain_reads::tip_of(self.txn()).map_err(ReadFault::into_plain)? else {
            return Ok(0..0);
        };
        shard_ids(self.txn(), shards, tip).map_err(ReadFault::into_plain)
    }
}

#[cfg(test)]
mod horizon_tests {
    use super::*;

    fn seb(n: u64) -> SettlementEpochBlocks {
        SettlementEpochBlocks::new(n).expect("non-zero")
    }

    #[test]
    fn horizons_hold_cap_le_retention_lt_epoch() {
        let cap = BlockCount::from_raw(3);
        assert!(Horizons::new(seb(10), BlockCount::from_raw(3), cap).is_ok());
        assert!(matches!(
            Horizons::new(seb(10), BlockCount::from_raw(2), cap),
            Err(StoreCannot::RetentionBelowReorgCap { .. })
        ));
        assert!(matches!(
            Horizons::new(seb(10), BlockCount::from_raw(0), BlockCount::from_raw(0)),
            Err(StoreCannot::RetentionNotInsideEpoch { .. })
        ));
        assert!(matches!(
            Horizons::new(seb(10), BlockCount::from_raw(10), cap),
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
            "a shortened epoch runs a Fakechain set and names its retention against its cap"
        );
    }

    #[test]
    fn the_batch_runs_at_boundaries_from_epoch_two() {
        let h =
            Horizons::new(seb(10), BlockCount::from_raw(3), BlockCount::from_raw(3)).expect("ok");
        for height in [0, 10, 5, 15, 21] {
            assert!(!h.is_pruning_boundary(height), "{height}");
        }
        for height in [20, 30, 100] {
            assert!(h.is_pruning_boundary(height), "{height}");
        }
    }
}
