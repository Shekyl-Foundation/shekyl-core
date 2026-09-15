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
}

impl StoreInvariant {
    /// The register row this invariant is, as the `n` of `SI-n`.
    #[must_use]
    pub const fn row(&self) -> u32 {
        match self {
            Self::UndoLogIncoherent { .. } => 6,
            Self::CellCorrupt { .. } => 7,
        }
    }
}

impl core::fmt::Display for StoreInvariant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SI-{} violated: ", self.row())?;
        match self {
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
            | Self::UndoLogIncoherent { .. } => None,
        }
    }
}

/// How the undo log and the tables disagreed (SI-6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UndoFault {
    /// Sealing this height's journal found a row already recorded there.
    RowAlreadyRecorded,
    /// Replaying entry `index` (in write order) found its target key or
    /// member not in the state the entry left it in — absent where the
    /// entry inserted, or, for a restore, absent where it replaced.
    EntryNotReversible {
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
            Self::EntryNotReversible { index } => write!(
                f,
                "entry {index} cannot be reversed: its target is not in the state the entry left"
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
