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

use shekyl_chain_rules::Corrupt;

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
    /// **SI-9** — store-derived ids are dense and fresh: `tx_id`,
    /// `output_id` and the per-amount `amount_index` are the owning table's
    /// entry count at write time, and the slot an insert targets under one
    /// is absent.
    ///
    /// Pure storage integrity — no consensus twin (SCW-4), which is why it
    /// is not folded into SI-3: R8-Q1's three-arm test needs rule-twinned
    /// belts and pure invariants to stay distinguishable.
    IdNotFresh,
    /// **SI-10** — the recorded difficulty accumulator is coherent as the
    /// validator reads it: cumulative difficulty is monotone across
    /// recorded heights, the parent's plus the connecting target fits the
    /// type, and a target derived from the recorded window is nonzero.
    ///
    /// The one row whose **observer is the validator**, not a write site:
    /// D4's window walk and D6 read the record inside the batch's branded
    /// view and, finding it incoherent, return `Fault::Corrupt` — an
    /// `InvariantViolated` the store did not see itself. The pipeline hands
    /// that observation back through
    /// [`WriteBatch::refuse_corrupt`](super::WriteBatch::refuse_corrupt),
    /// which arms this batch's poison exactly as a belt would (DRS-E2
    /// RD-Q4): the store cannot detect it and must not connect onto it. The
    /// validator's own value is carried, not re-described — its three arms
    /// are the finding, and a store enum mirroring them would say nothing
    /// the value does not.
    DifficultyRecordIncoherent(Corrupt),
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
            Self::CellCorrupt { .. } => 7,
            Self::FoldOverflow { .. } => 8,
            Self::IdNotFresh => 9,
            Self::DifficultyRecordIncoherent(_) => 10,
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
            Self::UndoLogIncoherent { height, fault } => write!(
                f,
                "undo log at height {height}: {fault}; the journal no longer describes the \
                 tables, rebuild from the block corpus"
            ),
            Self::CellCorrupt { key, fault } => write!(
                f,
                "typed cell `{key}` is {fault}; the file was modified outside this crate, \
                 rebuild from the block corpus"
            ),
            Self::DifficultyRecordIncoherent(observed) => {
                f.write_str(
                    "the validator found the recorded difficulty accumulator incoherent: ",
                )?;
                match observed {
                    Corrupt::CumulativeDifficultyNotMonotone { at } => write!(
                        f,
                        "cumulative difficulty at height {} is below its parent's",
                        at.to_raw()
                    ),
                    Corrupt::CumulativeDifficultyOverflow => f.write_str(
                        "the parent's cumulative difficulty plus the connecting target overflows",
                    ),
                    Corrupt::ZeroTarget => {
                        f.write_str("the target derived from the recorded window is zero")
                    }
                }?;
                f.write_str("; the writer halts, rebuild from the block corpus")
            }
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
            | Self::TipMismatch
            | Self::TxHashNotFresh
            | Self::RootRewritten
            | Self::FoldOverflow { .. }
            | Self::IdNotFresh
            | Self::DifficultyRecordIncoherent(_)
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
