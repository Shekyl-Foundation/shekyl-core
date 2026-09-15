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
    /// **SI-7** — every cell read decodes under its canonical codec; an
    /// undecodable or missing sealed cell is fatal.
    ///
    /// Codecs are strict (`codec` module docs), so this is never "an older
    /// layout" — that is
    /// [`StoreCannot::SchemaVersionMismatch`](super::StoreCannot::SchemaVersionMismatch),
    /// a refusal. Both header cells land in the seal's one transaction, so a
    /// store with a valid `schema_version` and a broken `apply_policy` was
    /// modified by something other than this crate. Rebuild from the block
    /// corpus; there is no repair.
    CellCorrupt {
        /// The cell's key.
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
            Self::CellCorrupt { .. } => 7,
        }
    }
}

impl core::fmt::Display for StoreInvariant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SI-{} violated: ", self.row())?;
        match self {
            Self::CellCorrupt { key, fault } => write!(
                f,
                "properties cell `{key}` is {fault}; the file was modified outside this crate, \
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
            } => None,
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
