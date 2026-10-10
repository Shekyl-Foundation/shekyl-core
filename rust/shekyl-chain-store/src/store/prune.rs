// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The retention prune (DRS-E1 S-PRUNE, `DRS_E1_SPRUNE.md`): the boundary
//! batch that runs **inside the connect transaction** of the block at
//! `E·SEB`, and the pop floor it establishes.
//!
//! # Three horizons and a floor (§3)
//!
//! | Horizon | Retires | When |
//! | --- | --- | --- |
//! | Bodies (`txs_prunable`, `txs_pqc_auths`) | shard `k`, whole | the epoch boundary after `k`'s freeze epoch: `close_epoch(k) + 2 ≤ E` |
//! | Pop-undo journal (`undo_log`) | rows below `tip − retention` | every boundary; `retention` is `D_max` in production |
//! | Slash log (`archival_slash_log`) | rows below `tip − ((k + n)·SEB + reorg_cap)` | every boundary; the cap is the in-force rule set's (`SLK-Q1`) |
//!
//! The body horizon is a rule of the epoch calendar — there is no constant
//! to name and no watermark to store. The slash log's horizon is a
//! consensus expression ([`SlashLogFloor`], `DRS_E4_SLASH_LOG_ROUND.md`):
//! the batch computes it from the rule set `connect` holds — its epoch and
//! its **reorg cap**, never the store's `undo_retention`, which an operator
//! may set deeper (`SLK-2`) — and keeps no cell for it (`SLK-3`): a reorg
//! across the boundary re-runs the same expression at the same height and
//! the deletion is idempotent, and the reader asserts the same floor at
//! the read (SI-26) rather than trusting a watermark. The undo floor is the
//! one number the store keeps ([`UndoLogFloorCell`]), because `pop` must tell *pruned
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
//! first transaction starting at or past it. A [`Descent`] walks
//! `block_info` down from `(E−1)·SEB`, walking each block's ids over its
//! `txs_archival_len` rows (absent ⇔ `0`) — permanent skeleton rows no
//! prune deletes — and stops on the block where the fold first reaches the
//! offset, with the id. No table of boundaries and no read of what is present — a
//! presence read that *selected* what to discard would be a second,
//! node-local source (§8), and the whole point is that every node computes
//! the same `D(E)` whether it discarded last epoch, skeleton-synced or just
//! booted: the cell and the length rows are what a pruned node and an
//! archival node both hold. Every epoch comparison is a branch or an
//! addition, never `E − 2` on a `u64` (§4, Bugbot 2026-09-23).
//!
//! # Every block the discard rests on is checked (SI-13, SI-24)
//!
//! A search over the cell is only as sound as the cell, and a discard
//! cannot be taken back. A binary search checks the rows it probes; a run
//! of cells shifted together passes every probe, and a shift that starts at
//! one block and persists above it keeps the fold monotone everywhere
//! (Copilot, PR #910, twice). So the descent reads **every** block from
//! `(E−1)·SEB − 1` down to where `D(E)`'s first shard opens and checks each
//! against its parent: both folds non-decreasing (SI-13) and its length
//! rows summing from the parent's cell to its own (SI-24). The crossings it
//! returns are then placed by the rows, not by a cell that could have
//! moved. That opening can lie below the window — a shard spans as many
//! epochs as it takes to fill `W` — but the windows of consecutive
//! boundaries overlap and each descent reaches the opening of the first
//! shard it discards, so the checked spans chain down to genesis (the first
//! discard's shard `0` opens there), and each block and its rows are read
//! a bounded number of times over their life, not once per boundary. What
//! no boundary re-reads is a block below its descent after an earlier
//! boundary checked it: a store-wide audit re-summing from genesis is that
//! instrument, not the per-boundary batch.
//!
//! Running inside the boundary block's own transaction makes "connected
//! past `E·SEB` with `D(E)` un-run" unrepresentable: a batch that dies
//! takes its connect with it. The hook can fire twice for one `E` only
//! through a reorg across the boundary block; both halves are idempotent
//! (the ranges are already empty; the floor is monotone), and §8 makes that
//! a test. The second run names the same ranges: every row it reads —
//! `C(lo)`, `C(hi)`, the descent and the blocks the offset walk visits —
//! sits below `(E−1)·SEB`, under the pop floor `E·SEB − retention` because
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
use shekyl_chain_rules::{RuleSet, SlashLogFloor};
use shekyl_types::{
    shard_floor, shard_of, storage_ids_through, ArchivalLength, BlockCount, BlockHeight,
};

use crate::codec::{BlockInfo, SettlementEpochBlocks, UndoLogFloorCell};
use crate::ids::{SlashLogKey, SlashLogTuple};
use crate::schema::{
    ARCHIVAL_SLASH_LOG, BLOCK_INFO, PROPERTIES, TXS_ARCHIVAL_LEN, TXS_PQC_AUTHS, TXS_PRUNABLE,
    UNDO_LOG,
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
/// SI-24 name it.
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
/// Both are checked at construction and refused at open; `connect`
/// re-checks the cap **and the epoch** against the set in force at every
/// height ([`Self::check_against`]), so a schedule step that raises the
/// cap or moves the epoch is refused at the block it applies to. The
/// store holds no rule set and no schedule (rule 71): the caller hands the
/// pair here as it hands the set to `connect`, and the set carries the
/// same pair (`RuleSet::settlement_schedule`, `RuleSet::reorg_cap`).
/// Production runs `D_max` on both sides; a regtest under a shortened
/// epoch runs a Fakechain rule set naming that epoch and a cap inside it.
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

    /// The horizons a store runs under a given rule set: that set's
    /// settlement epoch, and an undo retention of exactly its reorg cap —
    /// the least retention `connect` accepts under it
    /// ([`Self::check_against`]). `under(&RuleSet::GENESIS)` is
    /// [`production`](Self::production) at the genesis epoch; a Fakechain
    /// set under a shortened schedule gets the horizons that schedule
    /// implies, so a replay driver and a test open a store the same way a
    /// daemon does — off the set, not off a second copy of its numbers.
    ///
    /// # Errors
    ///
    /// As [`new`](Self::new); a well-formed set's pair
    /// (`FakechainSchedule` holds `0 < cap < SEB`) does not fail it.
    pub fn under(in_force: &RuleSet) -> Result<Self, StoreCannot> {
        let cap = in_force.reorg_cap();
        Self::new(in_force.settlement_schedule().blocks(), cap, cap)
    }

    /// Whether these horizons fit the set in force — `connect`'s
    /// per-height belt, both halves of the schedule: the retention covers
    /// `in_force`'s reorg cap (SCW-7), and the pinned epoch **is**
    /// `in_force`'s settlement epoch (SCW-2). The file's join epochs and
    /// serve-credit windows were written under the pinned geometry; a
    /// verdict judged under another would carry rows the file mislabels,
    /// so it is refused at the block it applies to rather than found by a
    /// later read.
    ///
    /// # Errors
    ///
    /// [`StoreCannot::RetentionBelowReorgCap`] if the retention is under
    /// the cap; [`StoreCannot::SettlementEpochMismatch`] if the epochs
    /// differ.
    pub(super) fn check_against(&self, in_force: &RuleSet) -> Result<(), StoreCannot> {
        let reorg_cap = in_force.reorg_cap();
        if self.undo_retention.to_raw() < reorg_cap.to_raw() {
            return Err(StoreCannot::RetentionBelowReorgCap {
                retention: self.undo_retention,
                reorg_cap,
            });
        }
        let session = in_force.settlement_schedule().blocks();
        if self.epoch != session {
            return Err(StoreCannot::SettlementEpochMismatch {
                pinned: self.epoch,
                session,
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

    /// The heights `[lo, hi)` a shard closing in is discarded at the
    /// boundary of epoch `e ≥ 2`: `lo = max(E−3, 0)·SEB`, `hi = (E−1)·SEB`.
    /// `E − 1` cannot wrap; `E − 3` is a branch.
    const fn discard_window(&self, e: u64) -> Range<u64> {
        let lo = if e >= 3 {
            self.first_height_of(e - 3)
        } else {
            0
        };
        lo..self.first_height_of(e - 1)
    }

    /// Whether `height` is a boundary at which the batch runs: `E·SEB` with
    /// `E ≥ 2`.
    const fn is_pruning_boundary(&self, height: u64) -> bool {
        height.is_multiple_of(self.epoch.get()) && self.epoch_of(height) >= FIRST_PRUNING_EPOCH
    }
}

/// What a boundary connect retired (§4): the shard range whose bodies were
/// discarded — empty when no shard closed in the window — the undo floor
/// the store now keeps, and the slash log's floor it retired below.
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
    /// The slash log's retirement floor at this boundary under the in-force
    /// rule set: rows below it are gone, rows at or above it kept. `NONE`
    /// while the chain is shorter than the window.
    pub slash_floor: SlashLogFloor,
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
    /// `in_force` is the rule set the block was judged under — the slash
    /// log's floor is its expression (`SLK-2`), not the store's.
    ///
    /// # Errors
    ///
    /// SI-7 (poisons) if a `block_info` row the calendar names is absent or
    /// does not decode; engine faults.
    pub(super) fn prune_at_boundary(
        &self,
        height: BlockHeight,
        in_force: &RuleSet,
    ) -> Result<Option<Pruned>, StoreError> {
        let horizons = self.horizons();
        if !horizons.is_pruning_boundary(height.to_raw()) {
            return Ok(None);
        }
        let discard = discard_at(self.txn(), horizons, horizons.epoch_of(height.to_raw()))
            .map_err(|f| self.arm_read_fault(f))?;
        if !discard.ids.is_empty() {
            discard_range(self.txn(), TXS_PRUNABLE, discard.ids.clone())?;
            discard_range(self.txn(), TXS_PQC_AUTHS, discard.ids)?;
        }
        let undo_floor = self.retire_undo_rows(height.to_raw())?;
        // Both operands are the rule set's (SLK-2); `check_against` has
        // already held its epoch equal to the pinned one at this height.
        let slash_floor = SlashLogFloor::under(
            height,
            in_force.settlement_schedule().blocks(),
            in_force.reorg_cap(),
        );
        self.retire_slash_rows(slash_floor)?;
        Ok(Some(Pruned {
            shard_start: discard.shards.start,
            shard_end: discard.shards.end,
            undo_floor,
            slash_floor,
        }))
    }

    /// Delete `archival_slash_log` rows below the floor — the slash log's
    /// retirement (`PDM-Q-F19`; `DRS_E4_SLASH_LOG_ROUND.md` `SLK-Q1`), the
    /// first enforcement of the horizon `journal_horizon` has stated since
    /// the writer landed. Nothing while the chain is under the window.
    ///
    /// No floor is persisted and none is checked here (`SLK-3`): the
    /// expression is the floor, a re-run at the same height deletes the
    /// same empty range, and the one reader of the log asserts the floor
    /// where it reads (SI-26, `archival_reads::slash_log_after`) — a
    /// derived floor and an asserting read, rather than a watermark the
    /// read would trust. Not pop-reversible, like the body discards: the
    /// row for the boundary block was sealed before this ran, and `pop`
    /// cannot reach a height this retires — the undo floor is `retention`
    /// below the tip with `retention < SEB` ([`Horizons::new`]), the slash
    /// floor at least `SEB + reorg_cap` below it, and a pop below the undo
    /// floor is `PopBelowFloor`.
    fn retire_slash_rows(&self, floor: SlashLogFloor) -> Result<(), StoreError> {
        let Some(floor) = floor.height() else {
            return Ok(());
        };
        let mut log = self
            .txn()
            .open_table(ARCHIVAL_SLASH_LOG)
            .map_err(EngineError::Table)?;
        log.retain_in::<SlashLogTuple, _>(SlashLogKey::below(floor), |_, _| false)
            .map_err(EngineError::Storage)?;
        Ok(())
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

/// What the boundary of one epoch discards: `D(E)` and the storage ids of
/// its transactions — both empty when no shard closed in the window.
struct Discard {
    shards: Range<u64>,
    ids: Range<u64>,
}

/// `D(E)` and its storage ids (module docs). `D(E)` is `⌊C(lo)/W⌋ ..
/// ⌊C(hi)/W⌋` over the window `[lo, hi)`; its ids run from the first
/// transaction at or past `start·W` to the first at or past `end·W`, both
/// placed by one [`Descent`] from block `hi − 1`. `e ≥ 2`.
fn discard_at<T: ReadTables>(txn: &T, horizons: Horizons, e: u64) -> Result<Discard, ReadFault> {
    let window = horizons.discard_window(e);
    let before_lo = archival_before(txn, window.start)?;
    // `hi = (E−1)·SEB ≥ SEB ≥ 1`: block `hi − 1` exists and its cell is `C(hi)`.
    let top = Descent::from_block(txn, window.end - 1)?;
    let before_hi = top.through();
    // SI-13 on the two samples. When a shard closed, the descent re-reads
    // and checks every block between them; when none did, nothing is
    // discarded and this is the one check the boundary makes.
    if before_hi < before_lo {
        return Err(archival_not_monotone(window.end - 1));
    }
    let shards = shard_of(before_lo).to_raw()..shard_of(before_hi).to_raw();
    if shards.is_empty() {
        return Ok(Discard { shards, ids: 0..0 });
    }
    let ids = top.ids_at(shard_floor(before_lo)..shard_floor(before_hi))?;
    Ok(Discard { shards, ids })
}

/// Archival length recorded **before** height `h`: `C(h)`, the parent's
/// `cumulative_archival_len`, and `0` at genesis.
fn archival_before<T: ReadTables>(txn: &T, height: u64) -> Result<ArchivalLength, ReadFault> {
    let Some(parent) = height.checked_sub(1) else {
        return Ok(ArchivalLength::ZERO);
    };
    Ok(block_info_at(txn, parent)?.cumulative_archival_len)
}

/// SI-13 on the archival fold: the row at `height` is below the one before
/// it — the same reading the listed fold's [`fold_not_monotone`] names.
fn archival_not_monotone(height: u64) -> ReadFault {
    ReadFault::Invariant(StoreInvariant::FoldNotMonotone {
        cell: ARCHIVAL_LEN_CELL,
        height,
    })
}

/// The archival fold read **downward**, one block per step, each block
/// **checked against its parent** before the descent passes it: both folds
/// do not decrease (SI-13), and the block's `txs_archival_len` rows sum
/// from the parent's cell to its own (SI-24). The first catches a decrease
/// cheaply; the second catches what monotonicity cannot — a shift that
/// starts at one block and persists above it (Copilot, PR #910). With every
/// block between checked, the crossing the descent finds is the fold's
/// only one, placed by the rows themselves (module docs, *Every row the
/// discard rests on is checked*).
struct Descent<'t, T> {
    txn: &'t T,
    /// The block the next step checks, and its row.
    height: u64,
    info: BlockInfo,
}

/// Where the fold first reaches an offset: the block holding the crossing,
/// and the storage id of the first transaction starting at or past the
/// offset — the next block's first id when every transaction of the block
/// starts below it.
#[derive(Clone, Copy)]
struct Crossing {
    height: u64,
    first_id: u64,
}

impl<'t, T: ReadTables> Descent<'t, T> {
    /// Stand on block `height`, reading its row.
    fn from_block(txn: &'t T, height: u64) -> Result<Self, ReadFault> {
        Ok(Self {
            txn,
            height,
            info: block_info_at(txn, height)?,
        })
    }

    /// The fold through the block the descent started on — `C` of the
    /// height above it.
    const fn through(&self) -> ArchivalLength {
        self.info.cumulative_archival_len
    }

    /// The storage ids of the transactions starting at archival offsets in
    /// `offsets`, both ends placed by this descent — the higher first.
    fn ids_at(mut self, offsets: Range<ArchivalLength>) -> Result<Range<u64>, ReadFault> {
        let end = self.first_reaching(offsets.end)?.first_id;
        let start = self.first_reaching(offsets.start)?.first_id;
        Ok(start..end)
    }

    /// The lowest block whose cumulative archival length reaches `offset`:
    /// the `h` with `C(h) < offset ≤ C(h + 1)`, or genesis when `offset` is
    /// `0`. `offset` is at most the fold where the descent stands, and a
    /// descent is asked non-increasing offsets — it only goes down. It
    /// stops **on** the crossing block, so the next, lower offset resumes
    /// there.
    fn first_reaching(&mut self, offset: ArchivalLength) -> Result<Crossing, ReadFault> {
        debug_assert!(offset <= self.through(), "asked above where it stands");
        loop {
            let parent = match self.height.checked_sub(1) {
                Some(below) => Some(block_info_at(self.txn, below)?),
                None => None,
            };
            let first_id = walk_block(self.txn, self.height, &self.info, parent.as_ref(), offset)?;
            match parent {
                Some(parent) if parent.cumulative_archival_len >= offset => {
                    self.height -= 1;
                    self.info = parent;
                }
                _ => {
                    return Ok(Crossing {
                        height: self.height,
                        first_id,
                    })
                }
            }
        }
    }
}

/// Check block `height` against its parent's row (`None` at genesis) and
/// place `offset` in it. SI-13 on both folds — on the raw listed samples,
/// before the coinbase term is added, because a decrease of one derives to
/// an empty id range rather than an inverted one (Copilot, PR #861). Then
/// its ids are walked in issue order from the parent's archival cell,
/// adding each `txs_archival_len` row (absent ⇔ `0`), and the sum must land
/// on the block's own cell: a disagreement is SI-24, a length row and the
/// fold built from it no longer agreeing. Returns the first id at or past
/// `offset`, or the block's end id when every transaction starts below it.
fn walk_block<T: ReadTables>(
    txn: &T,
    height: u64,
    info: &BlockInfo,
    parent: Option<&BlockInfo>,
    offset: ArchivalLength,
) -> Result<u64, ReadFault> {
    let (before, listed_before) = parent.map_or((ArchivalLength::ZERO, 0), |p| {
        (p.cumulative_archival_len, p.cumulative_tx_count)
    });
    if info.cumulative_archival_len < before {
        return Err(archival_not_monotone(height));
    }
    if info.cumulative_tx_count < listed_before {
        return Err(fold_not_monotone(height));
    }
    let first = first_tx_id(height, listed_before)?;
    let end = ids_from(info.cumulative_tx_count, height)?;
    let lens = txn.table(TXS_ARCHIVAL_LEN)?;
    let mut at = before;
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
    if at != info.cumulative_archival_len {
        return Err(ReadFault::Invariant(
            StoreInvariant::ArchivalLengthsDisagree {
                height,
                rows: at.to_raw(),
                cell: info.cumulative_archival_len.to_raw(),
            },
        ));
    }
    Ok(found.unwrap_or(end))
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
///
/// The same [`Descent`] as the boundary's, from `(E−1)·SEB` down to that
/// close height, every block checked: a read costs the span of the shard
/// open at `(E−1)·SEB` and its length rows, which on a quiet chain is many
/// epochs. `PDM-Q5`'s consumer, when it
/// lands, decides whether to cache it — it changes once per epoch.
pub(super) fn h_scarce<T: ReadTables>(
    txn: &T,
    horizons: Horizons,
    tip: u64,
) -> Result<Option<u64>, ReadFault> {
    let e = horizons.epoch_of(tip);
    if e < FIRST_PRUNING_EPOCH {
        return Ok(None);
    }
    // Every shard below `⌊C(hi) / W⌋` has `close_epoch + 2 ≤ E`; the last
    // of them, `k`, closes at the first height reaching `(k+1)·W` — where
    // `⌊C(hi) / W⌋·W` is crossed.
    // `hi ≥ SEB ≥ 1`, as at the boundary.
    let mut top = Descent::from_block(txn, horizons.discard_window(e).end - 1)?;
    let before_hi = top.through();
    if shard_of(before_hi).to_raw() == 0 {
        return Ok(None);
    }
    top.first_reaching(shard_floor(before_hi))
        .map(|crossing| Some(crossing.height))
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
    /// decode; SI-13 if the archival fold decreases across the descent.
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
    /// boundary batch would discard for them, by the same descent, from
    /// the tip. Test-only: it lets a test put the same question to a store
    /// before and after a prune. `shards.end` must have opened by the tip.
    #[cfg(test)]
    pub(super) fn shard_storage_ids(&self, shards: Range<u64>) -> Result<Range<u64>, StoreError> {
        let Some((tip, _)) = chain_reads::tip_of(self.txn()).map_err(ReadFault::into_plain)? else {
            return Ok(0..0);
        };
        let offset = |k| shekyl_types::shard_start(shekyl_types::ShardId::from_raw(k));
        let offsets =
            offset(shards.start).expect("k·W fits")..offset(shards.end).expect("k·W fits");
        Descent::from_block(self.txn(), tip)
            .and_then(|top| top.ids_at(offsets))
            .map_err(ReadFault::into_plain)
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
