// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `SI-` register's code form.
//!
//! One variant per **`built`** row of `STORE_INVARIANT_REGISTER.md` §2;
//! `check_store_invariant_register.py` holds the two to a bijection in both
//! directions, so a variant with no row and a `built` row with no variant
//! are each red. A `ruled` row has no variant until the increment that first
//! enforces it lands (rule 23: no symbol before its producer).
//!
//! A value of this type is the payload of
//! [`StoreError::InvariantViolated`](super::StoreError::InvariantViolated):
//! the store was handed something that breaks its own coherence, so either
//! the validator has a hole or the file is corrupt. It is **fatal** (register
//! §1) and it **never** becomes a consensus verdict — C2-R8 Q2's conversion
//! ban, gated by `check_store_error_conversion_ban.py`. Once S-CHAIN-W's
//! writer refuses one, the tip carries it (`ChainTip.connect`,
//! `DAEMON_REDB_STORE.md` §3.6.2) so an operator can read which belt caught
//! the hole; that is why the type is `Copy + Eq` and names its row.

use crate::codec::CodecError;

/// A store invariant that the store itself enforces at the write, named by
/// its register row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreInvariant {
    /// **SI-1** — `spent_keys` is a set: inserting a key image already
    /// present is fatal.
    ///
    /// The belt beneath CEN-L1 / CEN-I7. A validator that admits a
    /// double spend has a hole; this is the store refusing to record what
    /// the rule should have refused, not a second copy of the rule.
    KeyImageNotFresh,
    /// **SI-2** — a connecting block's parent is the block recorded at
    /// height−1, that block is the tip, and there is one block per height.
    ///
    /// Armed by the parent-is-tip pre-check in `connect` and by the
    /// insert-once handles on `blocks` / `block_heights` / `block_info` /
    /// `hf_versions` / `block_burn`.
    TipMismatch,
    /// **SI-3** — `tx_indices` is keyed by tx hash: inserting a hash already
    /// present is fatal (CEN-G1's belt; CEN-F5's corollary for the miner
    /// tx).
    TxHashNotFresh,
    /// **SI-4** — the curve-tree root at height *h*+1 is written exactly
    /// once per connect and is the root the consensus transition handed
    /// `connect` (`ConnectFacts::root_after`).
    RootRewritten,
    /// **SI-6** — the undo log's top entry is the tip height, and a pop
    /// consumes exactly that entry.
    ///
    /// Armed at the two places the journal and the tables can disagree:
    /// sealing a height's journal row when one is already recorded there
    /// (the tip moved without its row being consumed), and replaying an
    /// entry whose target is not in the state the entry says it left
    /// (something wrote around the journal). Either way the file's
    /// pre-images no longer describe its tables, so no pop can be trusted
    /// to land on a coherent state; the writer halts (DRS §3.6.2).
    UndoLogIncoherent {
        /// The height whose journal row is at issue.
        height: u64,
        /// Which disagreement was found.
        fault: UndoFault,
    },
    /// **SI-7** — every cell read decodes under its canonical codec; an
    /// undecodable or missing sealed cell is fatal.
    ///
    /// Codecs are strict (`codec` module docs), so this is never "an older
    /// layout" — that is
    /// [`StoreCannot::SchemaVersionMismatch`](super::StoreCannot::SchemaVersionMismatch),
    /// a refusal. Both header cells land in the seal's one transaction, so a
    /// store with a valid `schema_version` and a broken `apply_policy` was
    /// modified by something other than this crate. The same row covers
    /// every typed cell the store reads back, `undo_log` rows included.
    /// Rebuild from the block corpus; there is no repair.
    CellCorrupt {
        /// The cell's key — a `properties` key, or the table name for a
        /// table-valued cell.
        key: &'static str,
        /// What is wrong with it.
        fault: CellFault,
    },
    /// **SI-8** — accumulator arithmetic never wraps: every fold uses
    /// checked arithmetic and an overflow is fatal, never a saturate or a
    /// mint. `total_burned` is the fold this increment writes.
    FoldOverflow {
        /// The `properties` key of the cell whose fold overflowed.
        cell: &'static str,
    },
    /// **SI-10** — recorded cumulative work strictly increases with height:
    /// `block_info[h].cumulative_difficulty > block_info[h−1].cumulative_difficulty`
    /// for every recorded `h ≥ 1`, because every block's target is at least
    /// one (CEN-D6, `Target` is `NonZeroU128`).
    ///
    /// The belt beneath CEN-D4. Unlike the rows above it is **not armed by a
    /// store write site** — the store records the work the verdict carries
    /// and computes none (C2-R8 Q4) — but by the **validator reading the
    /// store**: `D4`'s window walk over `BatchView` observes a height whose
    /// work is not above its parent's — a decrease or an equal pair
    /// (`Corrupt::CumulativeDifficultyNotMonotone { at }`) — and returns a
    /// `Fault::Corrupt`, which the ingest pipeline hands to
    /// [`WriteBatch::refuse_corrupt`](super::WriteBatch::refuse_corrupt) to
    /// arm this row. The validator saw what a belt would have seen; the
    /// store's halt is the consequence (DRS-E2 RD-Q4).
    WorkNotIncreasing {
        /// The recorded height whose cumulative work is not above its
        /// parent's — or, for a window that derived zero, the connecting
        /// height whose window it was.
        height: u64,
    },
    /// **SI-9** — store-derived ids are dense and fresh: `tx_id`,
    /// `output_id` and the per-amount `amount_index` are the owning table's
    /// entry count at write time, and the slot an insert targets under one
    /// is absent.
    ///
    /// Pure storage integrity — no consensus twin (SCW-4), which is why it
    /// is not folded into SI-3: R8-Q1's three-arm test needs rule-twinned
    /// belts and pure invariants to stay distinguishable.
    IdNotFresh,
    /// **SI-11** — `curve_tree_leaves` is dense over `[0, leaf_count)`:
    /// the summary row's count (`curve_tree_meta`, `CurveTreeState`) is the
    /// leaf table's entry count, and every position below it has a row.
    /// The C++ wrote the count and the leaves in one grow
    /// (`db_lmdb.cpp:8936–8966`) and every reader took the count as the
    /// bound; here the reads assert it instead of assuming it (DRS-E1
    /// S-CURVE §3.3, SCU-3).
    ///
    /// Armed by the reads, since the grow path (DRS-E3) is not yet built:
    /// the summary read compares the count with the table's length, and the
    /// leaf walk names the first position in range with no row.
    LeavesNotDense {
        /// The position that breaks density: the first in `[0, leaf_count)`
        /// with no row, or `leaf_count` itself when the table's length and
        /// the count disagree without a hole having been walked.
        position: u64,
    },
}

impl StoreInvariant {
    /// The register row this invariant is, as the `n` of `SI-n`.
    #[must_use]
    pub const fn row(&self) -> u32 {
        match self {
            Self::KeyImageNotFresh => 1,
            Self::TipMismatch => 2,
            Self::TxHashNotFresh => 3,
            Self::RootRewritten => 4,
            Self::UndoLogIncoherent { .. } => 6,
            Self::WorkNotIncreasing { .. } => 10,
            Self::LeavesNotDense { .. } => 11,
            Self::CellCorrupt { .. } => 7,
            Self::FoldOverflow { .. } => 8,
            Self::IdNotFresh => 9,
        }
    }
}

impl core::fmt::Display for StoreInvariant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SI-{} violated: ", self.row())?;
        match self {
            Self::KeyImageNotFresh => f.write_str(
                "a key image handed to connect is already in spent_keys; the validator admitted \
                 a double spend",
            ),
            Self::TipMismatch => f.write_str(
                "the connecting block's parent is not the recorded tip, or its height is already \
                 recorded",
            ),
            Self::TxHashNotFresh => f.write_str(
                "a transaction hash handed to connect is already in tx_indices; the validator \
                 admitted a duplicate",
            ),
            Self::RootRewritten => f.write_str(
                "the curve-tree root at the connecting height is already recorded; a root is \
                 written exactly once",
            ),
            Self::FoldOverflow { cell } => write!(
                f,
                "the `{cell}` fold overflowed u64; a fold never saturates and never mints"
            ),
            Self::IdNotFresh => f.write_str(
                "a store-derived id (tx_id / output_id / amount_index) names an occupied slot; \
                 the table's count and its keys disagree",
            ),
            Self::WorkNotIncreasing { height } => write!(
                f,
                "recorded cumulative work does not increase at height {height}; the validator \
                 read a store whose block_info rows contradict CEN-D4/D6, rebuild from the \
                 block corpus"
            ),
            Self::UndoLogIncoherent { height, fault } => write!(
                f,
                "undo log at height {height}: {fault}; the journal no longer describes the \
                 tables, rebuild from the block corpus"
            ),
            Self::LeavesNotDense { position } => write!(
                f,
                "curve_tree_leaves is not dense at position {position}; the summary's leaf \
                 count and the leaf table disagree, rebuild from the block corpus"
            ),
            Self::CellCorrupt { key, fault } => write!(
                f,
                "typed cell `{key}` is {fault}; the file was modified outside this crate, \
                 rebuild from the block corpus"
            ),
        }
    }
}

impl core::error::Error for StoreInvariant {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::CellCorrupt {
                fault: CellFault::Undecodable(e),
                ..
            } => Some(e),
            Self::CellCorrupt {
                fault: CellFault::Absent,
                ..
            }
            | Self::KeyImageNotFresh
            | Self::WorkNotIncreasing { .. }
            | Self::TipMismatch
            | Self::TxHashNotFresh
            | Self::RootRewritten
            | Self::FoldOverflow { .. }
            | Self::IdNotFresh
            | Self::LeavesNotDense { .. }
            | Self::UndoLogIncoherent { .. } => None,
        }
    }
}

/// How the undo log and the tables disagreed (SI-6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UndoFault {
    /// Sealing this height's journal found a row already recorded there.
    RowAlreadyRecorded,
    /// `pop` found the journal's top row at `top`, not at the tip.
    TopIsNotTip {
        /// The height of the journal's highest row.
        top: u64,
    },
    /// `pop` found a block recorded at the tip and **no** journal row for
    /// it. Nothing deletes undo rows until S-PRUNE lands (which persists
    /// the floor it establishes), so this is a journal that does not
    /// describe its tables, not a retention limit.
    NoRowForTip,
    /// Replaying entry `index` (in write order) found its target key or
    /// member not in the state the entry left it in — absent where the
    /// entry inserted, or, for a restore, absent where it replaced.
    EntryNotReversible {
        /// Position of the entry in the row, in write order.
        index: u32,
    },
    /// Replaying entry `index` found its key present but holding a value
    /// whose post-image digest is not the one the journaled write left —
    /// something wrote around the journal, or the file is corrupt. Found
    /// after the inverse displaced the value, inside the poisoned
    /// transaction, so nothing lands.
    PostImageMismatch {
        /// Position of the entry in the row, in write order.
        index: u32,
    },
}

impl core::fmt::Display for UndoFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RowAlreadyRecorded => {
                f.write_str("a journal row is already recorded for this height")
            }
            Self::TopIsNotTip { top } => write!(
                f,
                "the journal's top row is at height {top}, not at the tip"
            ),
            Self::NoRowForTip => f.write_str(
                "a block is recorded at the tip but the journal has no row for it (nothing prunes \
                 undo rows yet)",
            ),
            Self::EntryNotReversible { index } => write!(
                f,
                "entry {index} cannot be reversed: its target is not in the state the entry left"
            ),
            Self::PostImageMismatch { index } => write!(
                f,
                "entry {index} cannot be reversed: the value under its key is not the one the journaled write left"
            ),
        }
    }
}

/// What is wrong with a typed `properties` cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellFault {
    /// The cell is not in the table.
    Absent,
    /// The cell's bytes are not an encoding of its value type.
    Undecodable(CodecError),
}

impl core::fmt::Display for CellFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Absent => f.write_str("absent"),
            Self::Undecodable(e) => write!(f, "undecodable ({e})"),
        }
    }
}
