// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The archival state at a covered tip, as rows (DRS-E4 `ARW-25`,
//! `DRS_E4_ARCHIVAL_WRITER.md` §3.8.1 "The archival snapshot").
//!
//! The E2 trace's `0x02` checkpoint hashes three chain families (v0,
//! [`crate::digest_v0`]) and names none of the archival tables. This module
//! is the archival half, and it is **not a hash**: at one checkpoint per
//! chain a digest answers "same or not" and nothing else, while the rows
//! answer *which family, which key, which value* — so the state travels as
//! canonical rows and the grader diffs ([`ArchivalSnapshot::diff`]). The
//! reversion condition is cadence: were a snapshot ever taken per block, a
//! hash re-enters (`ARW-25`).
//!
//! # Ten families, positional
//!
//! [`SnapshotFamily`] fixes the order the record carries them in; the family
//! tag is the position, not a byte. Every row is `key ‖ value`, little-endian
//! throughout — including key components the stores hold big-endian, because
//! the snapshot is layout-independent by charter and the stored key form is
//! the store's business (`lmdb_order`). Values are the store codec's
//! [`Canonical`] encoding: both legs encode in Rust (the C++ walker marshals
//! decoded fields across the FFI, `ARW-Q10` (a); the redb read encodes its
//! own rows), so the two sides cannot have encoded differently.
//!
//! | Family | Row (`key ‖ value`) | Projection |
//! |---|---|---|
//! | [`Bond`](SnapshotFamily::Bond) | `p[32] ‖ Canonical(BondRecord)` | — |
//! | [`ServeCredit`](SnapshotFamily::ServeCredit) | `p[32] ‖ shard ‖ epoch ‖ height` | set table, no value |
//! | [`RMarket`](SnapshotFamily::RMarket) | `shard ‖ epoch ‖ r` | `r = 0` rows are **not emitted** (§3.6) |
//! | [`SigmaWork`](SnapshotFamily::SigmaWork) | `E ‖ Σwork_milli` | — |
//! | [`Budget`](SnapshotFamily::Budget) | `E ‖ budget` | — |
//! | [`AttestationWitness`](SnapshotFamily::AttestationWitness) | `h ‖ witness bytes` | an empty set is no row |
//! | [`SlashLog`](SnapshotFamily::SlashLog) | `height ‖ seq u32 ‖ Canonical(SlashLogEntry)` | C++ epoch markers not emitted; the slashed amount projected out (`ARW-Q2`) |
//! | [`SlashApplied`](SnapshotFamily::SlashApplied) | `p[32] ‖ shard ‖ epoch` | set table, no value |
//! | [`BudgetAccruing`](SnapshotFamily::BudgetAccruing) | `E_open ‖ total` | zero or one row |
//! | [`LastSlashEpoch`](SnapshotFamily::LastSlashEpoch) | `E` | zero or one row; the C++ `u64::MAX` sentinel is no row (`ARW-Q11`) |
//!
//! The two singletons are families of cardinality `≤ 1`, not presence-tagged
//! fields: one framing for everything, and "absent" is the zero-row shape
//! everywhere.
//!
//! # Body framing
//!
//! [`ArchivalSnapshot::write_body`] emits, per family in order, `n_rows u64`
//! then each row as `len u32 ‖ bytes`; the record tag and the height are the
//! trace's (`shekyl-chain-ingest::trace`). An empty state is ten zero
//! counts — [`EMPTY_BODY_LEN`] bytes — never an omitted record.
//!
//! # What is not here, by name
//!
//! `archival_settlement` (held, SO-D8), the seven `NOT_PORTED` journals (no
//! state to compare), `archival_alt_attestation_witness` (alt-chain,
//! excluded as v0 excludes alt-chain), the txpool. [`disposition`] is the
//! exhaustive `match` over [`ArchivalFamily`] that says so, so a family
//! added to the X-macro without a snapshot disposition is a compile error.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Read, Write};

use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch, ShardId};
use shekyl_units::AtomicUnits;

use crate::apply_policy::ArchivalFamily;
use crate::codec::{
    AttestationWitnessBytes, BlobKind, BondRecord, Canonical, RMarket, SigmaWorkMilli,
    SlashLogEntry,
};

/// The families the snapshot carries, in record order. The discriminant
/// is the position in the record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SnapshotFamily {
    /// `archival_bond`.
    Bond,
    /// `archival_serve_credit`.
    ServeCredit,
    /// `archival_r_market`, non-zero rows.
    RMarket,
    /// `archival_sigma_work`.
    SigmaWork,
    /// `archival_budget`.
    Budget,
    /// `archival_attestation_witness`.
    AttestationWitness,
    /// `archival_slash_log`, slash rows only.
    SlashLog,
    /// `archival_slash_applied`.
    SlashApplied,
    /// The open epoch's accrued staker inflow — redb's one
    /// `archival_budget_accruing` row, the C++'s sum over
    /// `archival_budget_accrual` for the open epoch.
    BudgetAccruing,
    /// The slash watermark — redb's `ArchivalLastSlashEpochCell`, the C++'s
    /// `archival_last_slash_epoch` property.
    LastSlashEpoch,
}

/// How many families the record carries.
pub const FAMILY_COUNT: usize = SnapshotFamily::ALL.len();

/// Bytes of an empty snapshot's body: ten zero counts.
pub const EMPTY_BODY_LEN: usize = FAMILY_COUNT * 8;

/// Reader allocation bound on one row. A format fact only in the sense that
/// a reader refuses above it; the largest real row (a `BondRecord` at every
/// cap, or a witness at [`MAX_ATTESTATION_WITNESS_BYTES`]) is well under it.
///
/// [`MAX_ATTESTATION_WITNESS_BYTES`]: shekyl_types::archival::MAX_ATTESTATION_WITNESS_BYTES
pub const MAX_ROW_BYTES: usize = 1 << 20;

impl SnapshotFamily {
    /// Every family, in record order.
    pub const ALL: [Self; 10] = [
        Self::Bond,
        Self::ServeCredit,
        Self::RMarket,
        Self::SigmaWork,
        Self::Budget,
        Self::AttestationWitness,
        Self::SlashLog,
        Self::SlashApplied,
        Self::BudgetAccruing,
        Self::LastSlashEpoch,
    ];

    /// The table (or cell) the family is read from, as reports name it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bond => "archival_bond",
            Self::ServeCredit => "archival_serve_credit",
            Self::RMarket => "archival_r_market",
            Self::SigmaWork => "archival_sigma_work",
            Self::Budget => "archival_budget",
            Self::AttestationWitness => "archival_attestation_witness",
            Self::SlashLog => "archival_slash_log",
            Self::SlashApplied => "archival_slash_applied",
            Self::BudgetAccruing => "archival_budget_accruing",
            Self::LastSlashEpoch => "archival_last_slash_epoch",
        }
    }

    /// Width of the row's key part, which is what the comparison is keyed
    /// by and how a reader splits a row.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Bond => 32,
            Self::ServeCredit => 32 + 8 + 8 + 8,
            Self::SlashApplied => 32 + 8 + 8,
            Self::RMarket => 8 + 8,
            Self::SlashLog => 8 + 4,
            Self::SigmaWork
            | Self::Budget
            | Self::AttestationWitness
            | Self::BudgetAccruing
            | Self::LastSlashEpoch => 8,
        }
    }

    /// Width of the row's value part where it is fixed; `None` for the
    /// variable-width families.
    #[must_use]
    pub const fn value_len(self) -> Option<usize> {
        match self {
            Self::Bond | Self::AttestationWitness | Self::SlashLog => None,
            Self::ServeCredit | Self::SlashApplied | Self::LastSlashEpoch => Some(0),
            Self::RMarket | Self::SigmaWork | Self::Budget | Self::BudgetAccruing => Some(8),
        }
    }

    /// Whether the family holds at most one row.
    #[must_use]
    pub const fn is_singleton(self) -> bool {
        matches!(self, Self::BudgetAccruing | Self::LastSlashEpoch)
    }

    /// The family at record position `index`.
    #[must_use]
    pub const fn at(index: usize) -> Option<Self> {
        if index < Self::ALL.len() {
            Some(Self::ALL[index])
        } else {
            None
        }
    }
}

impl fmt::Display for SnapshotFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What the snapshot does with an [`ArchivalFamily`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Carried, as this family's rows.
    Rows(SnapshotFamily),
    /// Not carried, for the named reason (§3.8.1 "Not in the snapshot").
    Excluded(&'static str),
}

/// The §3.8.1 row table as an exhaustive `match`: a family added to the
/// X-macro without a snapshot disposition does not compile.
///
/// [`SnapshotFamily::LastSlashEpoch`] is a `properties` cell, not an
/// X-macro family, so it has no arm here; it is the one snapshot family
/// with no [`ArchivalFamily`], which `ALL`'s length test accounts for.
#[must_use]
pub const fn disposition(family: ArchivalFamily) -> Disposition {
    match family {
        ArchivalFamily::Bond => Disposition::Rows(SnapshotFamily::Bond),
        ArchivalFamily::ServeCredit => Disposition::Rows(SnapshotFamily::ServeCredit),
        ArchivalFamily::RMarket => Disposition::Rows(SnapshotFamily::RMarket),
        ArchivalFamily::SigmaWork => Disposition::Rows(SnapshotFamily::SigmaWork),
        ArchivalFamily::Budget => Disposition::Rows(SnapshotFamily::Budget),
        ArchivalFamily::AttestationWitness => Disposition::Rows(SnapshotFamily::AttestationWitness),
        ArchivalFamily::SlashLog => Disposition::Rows(SnapshotFamily::SlashLog),
        ArchivalFamily::SlashApplied => Disposition::Rows(SnapshotFamily::SlashApplied),
        ArchivalFamily::BudgetAccrual => Disposition::Rows(SnapshotFamily::BudgetAccruing),
        ArchivalFamily::Settlement => {
            Disposition::Excluded("archival_settlement is held (SO-D8); no writer on either side")
        }
        ArchivalFamily::AltAttestationWitness => {
            Disposition::Excluded("alt-chain state, excluded as v0 excludes alt-chain")
        }
        ArchivalFamily::ShardSegment
        | ArchivalFamily::EmissionClaimLog
        | ArchivalFamily::BondUnbondLog
        | ArchivalFamily::BondHoldingsUpdateLog
        | ArchivalFamily::BondReinstateLog
        | ArchivalFamily::EpochCloseLog => {
            Disposition::Excluded("NOT_PORTED journal: a revert pre-image, no state to compare")
        }
    }
}

/// Why a row was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotFault {
    /// The row's key part is not the family's key width.
    KeyWidth {
        /// Which family.
        family: SnapshotFamily,
        /// The width the key had.
        found: usize,
    },
    /// The row's value part is not the family's fixed value width.
    ValueWidth {
        /// Which family.
        family: SnapshotFamily,
        /// The width the value had.
        found: usize,
    },
    /// A key the family already holds — a set emitted an element twice.
    DuplicateKey {
        /// Which family.
        family: SnapshotFamily,
        /// The key.
        key: Vec<u8>,
    },
    /// A second row for a family of cardinality `≤ 1`.
    SecondSingletonRow {
        /// Which singleton.
        family: SnapshotFamily,
    },
    /// A slash-log row at the C++ epoch-marker sequence: the walker was to
    /// skip these, not marshal them.
    EpochMarkerSeq {
        /// The height the marker sat at.
        height: u64,
    },
    /// A witness row the writer could not have stored: empty or over
    /// `MAX_ATTESTATION_WITNESS_BYTES`.
    WitnessShape {
        /// The height.
        height: u64,
        /// The length offered.
        len: usize,
    },
    /// A row longer than [`MAX_ROW_BYTES`].
    RowTooLong {
        /// Which family.
        family: SnapshotFamily,
        /// The length declared.
        len: usize,
    },
    /// A row shorter than its family's key.
    RowTooShort {
        /// Which family.
        family: SnapshotFamily,
        /// The length declared.
        len: usize,
    },
    /// The body ended before its ten families did.
    Truncated,
    /// The underlying reader or writer failed.
    Io(io::ErrorKind),
}

impl fmt::Display for SnapshotFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyWidth { family, found } => {
                write!(
                    f,
                    "{family}: key is {found} bytes, not {}",
                    family.key_len()
                )
            }
            Self::ValueWidth { family, found } => {
                write!(
                    f,
                    "{family}: value is {found} bytes, not the family's fixed width"
                )
            }
            Self::DuplicateKey { family, key } => {
                write!(f, "{family}: key {} emitted twice", hex(key))
            }
            Self::SecondSingletonRow { family } => {
                write!(f, "{family}: a second row for a family of at most one")
            }
            Self::EpochMarkerSeq { height } => write!(
                f,
                "archival_slash_log: epoch-marker row at height {height} is not a slash"
            ),
            Self::WitnessShape { height, len } => write!(
                f,
                "archival_attestation_witness: {len}-byte row at height {height} is not storable"
            ),
            Self::RowTooLong { family, len } => {
                write!(f, "{family}: row of {len} bytes exceeds {MAX_ROW_BYTES}")
            }
            Self::RowTooShort { family, len } => {
                write!(f, "{family}: row of {len} bytes is shorter than its key")
            }
            Self::Truncated => f.write_str("snapshot body ends before its families do"),
            Self::Io(kind) => write!(f, "snapshot I/O: {kind:?}"),
        }
    }
}

impl std::error::Error for SnapshotFault {}

impl From<io::Error> for SnapshotFault {
    fn from(e: io::Error) -> Self {
        Self::Io(e.kind())
    }
}

/// Lowercase hex of a key, for messages and reports.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").expect("writing to a String does not fail");
    }
    s
}

/// The archival state at one tip: per family, the rows keyed by their key
/// part. Built by the redb read ([`crate::store::ReadSnapshot::archival_snapshot`])
/// and by the C++ walker through the FFI; carried by the trace; compared by
/// the grader.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ArchivalSnapshot {
    families: [BTreeMap<Vec<u8>, Vec<u8>>; FAMILY_COUNT],
}

impl ArchivalSnapshot {
    /// The empty state: ten families, no rows.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// The rows of `family`, keyed by key part.
    #[must_use]
    pub fn rows(&self, family: SnapshotFamily) -> &BTreeMap<Vec<u8>, Vec<u8>> {
        &self.families[family as usize]
    }

    /// Rows over every family.
    #[must_use]
    pub fn row_count(&self) -> usize {
        self.families.iter().map(BTreeMap::len).sum()
    }

    /// Insert one row given as its parts, checking the family's shape.
    ///
    /// # Errors
    ///
    /// [`SnapshotFault::KeyWidth`], [`SnapshotFault::ValueWidth`],
    /// [`SnapshotFault::DuplicateKey`], [`SnapshotFault::SecondSingletonRow`].
    pub fn insert(
        &mut self,
        family: SnapshotFamily,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<(), SnapshotFault> {
        if key.len() != family.key_len() {
            return Err(SnapshotFault::KeyWidth {
                family,
                found: key.len(),
            });
        }
        if let Some(width) = family.value_len() {
            if value.len() != width {
                return Err(SnapshotFault::ValueWidth {
                    family,
                    found: value.len(),
                });
            }
        }
        let rows = &mut self.families[family as usize];
        if family.is_singleton() && !rows.is_empty() {
            return Err(SnapshotFault::SecondSingletonRow { family });
        }
        if rows.contains_key(&key) {
            return Err(SnapshotFault::DuplicateKey { family, key });
        }
        rows.insert(key, value);
        Ok(())
    }

    /// Insert one row given whole, split at the family's key width.
    ///
    /// # Errors
    ///
    /// [`SnapshotFault::RowTooShort`] and [`Self::insert`]'s.
    pub fn insert_row(&mut self, family: SnapshotFamily, row: &[u8]) -> Result<(), SnapshotFault> {
        if row.len() < family.key_len() {
            return Err(SnapshotFault::RowTooShort {
                family,
                len: row.len(),
            });
        }
        let (key, value) = row.split_at(family.key_len());
        self.insert(family, key.to_vec(), value.to_vec())
    }

    // ---- typed row constructors: the one encoding for both legs ---------

    /// `archival_bond[p]`.
    ///
    /// # Errors
    ///
    /// [`Self::insert`]'s.
    pub fn push_bond(
        &mut self,
        persona: &PCanonicalId,
        record: &BondRecord,
    ) -> Result<(), SnapshotFault> {
        self.insert(
            SnapshotFamily::Bond,
            persona.as_bytes().to_vec(),
            record.encode(),
        )
    }

    /// One `archival_serve_credit` pass bit.
    ///
    /// # Errors
    ///
    /// [`Self::insert`]'s.
    pub fn push_serve_credit(
        &mut self,
        persona: &PCanonicalId,
        shard: ShardId,
        epoch: SettlementEpoch,
        height: BlockHeight,
    ) -> Result<(), SnapshotFault> {
        let mut key = Vec::with_capacity(SnapshotFamily::ServeCredit.key_len());
        key.extend_from_slice(persona.as_bytes());
        key.extend_from_slice(&shard.to_raw().to_le_bytes());
        key.extend_from_slice(&epoch.to_raw().to_le_bytes());
        key.extend_from_slice(&height.to_raw().to_le_bytes());
        self.insert(SnapshotFamily::ServeCredit, key, Vec::new())
    }

    /// `archival_r_market[(shard, epoch)]`. **A zero count is not a row**
    /// (§3.6: the C++ close writes zeros the redb close does not; the
    /// snapshot is the logical non-zero set) — this constructor applies the
    /// projection so neither walker can forget it.
    ///
    /// # Errors
    ///
    /// [`Self::insert`]'s.
    pub fn push_r_market(
        &mut self,
        shard: ShardId,
        epoch: SettlementEpoch,
        r: RMarket,
    ) -> Result<(), SnapshotFault> {
        if r.to_raw() == 0 {
            return Ok(());
        }
        let mut key = Vec::with_capacity(SnapshotFamily::RMarket.key_len());
        key.extend_from_slice(&shard.to_raw().to_le_bytes());
        key.extend_from_slice(&epoch.to_raw().to_le_bytes());
        self.insert(SnapshotFamily::RMarket, key, r.encode())
    }

    /// `archival_sigma_work[E]`.
    ///
    /// # Errors
    ///
    /// [`Self::insert`]'s.
    pub fn push_sigma_work(
        &mut self,
        epoch: SettlementEpoch,
        sigma: SigmaWorkMilli,
    ) -> Result<(), SnapshotFault> {
        self.insert(
            SnapshotFamily::SigmaWork,
            epoch.to_raw().to_le_bytes().to_vec(),
            sigma.encode(),
        )
    }

    /// `archival_budget[E]`.
    ///
    /// # Errors
    ///
    /// [`Self::insert`]'s.
    pub fn push_budget(
        &mut self,
        epoch: SettlementEpoch,
        budget: AtomicUnits,
    ) -> Result<(), SnapshotFault> {
        self.insert(
            SnapshotFamily::Budget,
            epoch.to_raw().to_le_bytes().to_vec(),
            budget.encode(),
        )
    }

    /// `archival_attestation_witness[h]`. An empty attestation set is no
    /// row on either side; an empty or over-cap `bytes` is refused as a row
    /// the writer could not have stored.
    ///
    /// # Errors
    ///
    /// [`SnapshotFault::WitnessShape`] and [`Self::insert`]'s.
    pub fn push_attestation_witness(
        &mut self,
        height: BlockHeight,
        bytes: &[u8],
    ) -> Result<(), SnapshotFault> {
        if AttestationWitnessBytes::well_formed(bytes).is_err() {
            return Err(SnapshotFault::WitnessShape {
                height: height.to_raw(),
                len: bytes.len(),
            });
        }
        self.insert(
            SnapshotFamily::AttestationWitness,
            height.to_raw().to_le_bytes().to_vec(),
            bytes.to_vec(),
        )
    }

    /// `archival_slash_log[(height, seq)]`. The C++ epoch-marker rows
    /// (`seq = u32::MAX`) are not slashes and are refused here, so a walker
    /// that marshalled one is caught rather than compared.
    ///
    /// # Errors
    ///
    /// [`SnapshotFault::EpochMarkerSeq`] and [`Self::insert`]'s.
    pub fn push_slash_log(
        &mut self,
        height: BlockHeight,
        seq: u32,
        entry: &SlashLogEntry,
    ) -> Result<(), SnapshotFault> {
        if seq == u32::MAX {
            return Err(SnapshotFault::EpochMarkerSeq {
                height: height.to_raw(),
            });
        }
        let mut key = Vec::with_capacity(SnapshotFamily::SlashLog.key_len());
        key.extend_from_slice(&height.to_raw().to_le_bytes());
        key.extend_from_slice(&seq.to_le_bytes());
        self.insert(SnapshotFamily::SlashLog, key, entry.encode())
    }

    /// One `archival_slash_applied` member.
    ///
    /// # Errors
    ///
    /// [`Self::insert`]'s.
    pub fn push_slash_applied(
        &mut self,
        persona: &PCanonicalId,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<(), SnapshotFault> {
        let mut key = Vec::with_capacity(SnapshotFamily::SlashApplied.key_len());
        key.extend_from_slice(persona.as_bytes());
        key.extend_from_slice(&shard.to_raw().to_le_bytes());
        key.extend_from_slice(&epoch.to_raw().to_le_bytes());
        self.insert(SnapshotFamily::SlashApplied, key, Vec::new())
    }

    /// The open epoch's accrued total — the one row of its family.
    ///
    /// # Errors
    ///
    /// [`SnapshotFault::SecondSingletonRow`] and [`Self::insert`]'s.
    pub fn set_budget_accruing(
        &mut self,
        epoch: SettlementEpoch,
        total: AtomicUnits,
    ) -> Result<(), SnapshotFault> {
        self.insert(
            SnapshotFamily::BudgetAccruing,
            epoch.to_raw().to_le_bytes().to_vec(),
            total.encode(),
        )
    }

    /// The slash watermark — the one row of its family. A side with no
    /// watermark (redb `None`; the C++ `u64::MAX` sentinel) calls nothing.
    ///
    /// # Errors
    ///
    /// [`SnapshotFault::SecondSingletonRow`] and [`Self::insert`]'s.
    pub fn set_last_slash_epoch(&mut self, epoch: SettlementEpoch) -> Result<(), SnapshotFault> {
        self.insert(
            SnapshotFamily::LastSlashEpoch,
            epoch.to_raw().to_le_bytes().to_vec(),
            Vec::new(),
        )
    }

    // ---- body codec ------------------------------------------------------

    /// The body after the record's height: per family in order, `n_rows
    /// u64` then each row as `len u32 ‖ key ‖ value`, rows in key order.
    ///
    /// # Errors
    ///
    /// I/O only; every row was shape-checked at insert.
    pub fn write_body<W: Write>(&self, out: &mut W) -> io::Result<()> {
        for rows in &self.families {
            out.write_all(&(rows.len() as u64).to_le_bytes())?;
            for (key, value) in rows {
                let len = u32::try_from(key.len() + value.len())
                    .expect("a row was bounded by MAX_ROW_BYTES at insert");
                out.write_all(&len.to_le_bytes())?;
                out.write_all(key)?;
                out.write_all(value)?;
            }
        }
        Ok(())
    }

    /// Read one body ([`Self::write_body`]'s inverse). Reads exactly the
    /// body's bytes and no more, so a caller streaming a trace can continue
    /// after it.
    ///
    /// # Errors
    ///
    /// [`SnapshotFault::Truncated`] when the input ends inside the body;
    /// [`SnapshotFault::RowTooLong`]; every shape fault of [`Self::insert_row`];
    /// I/O.
    pub fn read_body<R: Read>(input: &mut R) -> Result<Self, SnapshotFault> {
        let mut out = Self::empty();
        for family in SnapshotFamily::ALL {
            let n_rows = read_u64(input)?;
            for _ in 0..n_rows {
                let len = read_u32(input)? as usize;
                if len > MAX_ROW_BYTES {
                    return Err(SnapshotFault::RowTooLong { family, len });
                }
                let mut row = vec![0u8; len];
                input
                    .read_exact(&mut row)
                    .map_err(|e| eof_is_truncated(&e))?;
                out.insert_row(family, &row)?;
            }
        }
        Ok(out)
    }

    /// The body as bytes.
    #[must_use]
    pub fn body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_body(&mut out)
            .expect("writing to a Vec does not fail");
        out
    }

    // ---- comparison ------------------------------------------------------

    /// Compare as sets keyed by row key, per family: rows on both sides and
    /// equal; on both sides and unequal (the key, both values); keys on one
    /// side only. An emission-order difference is not a divergence (the
    /// state carries no order).
    #[must_use]
    pub fn diff(&self, theirs: &Self) -> SnapshotDiff {
        let families = SnapshotFamily::ALL.map(|family| {
            let ours = self.rows(family);
            let theirs = theirs.rows(family);
            let mut d = FamilyDiff {
                family,
                equal: 0,
                unequal: Vec::new(),
                only_ours: Vec::new(),
                only_theirs: Vec::new(),
            };
            for (key, value) in ours {
                match theirs.get(key) {
                    Some(other) if other == value => d.equal += 1,
                    Some(other) => d.unequal.push(UnequalRow {
                        key: key.clone(),
                        ours: value.clone(),
                        theirs: other.clone(),
                    }),
                    None => d.only_ours.push(key.clone()),
                }
            }
            for key in theirs.keys() {
                if !ours.contains_key(key) {
                    d.only_theirs.push(key.clone());
                }
            }
            d
        });
        SnapshotDiff { families }
    }
}

fn eof_is_truncated(e: &io::Error) -> SnapshotFault {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        SnapshotFault::Truncated
    } else {
        SnapshotFault::Io(e.kind())
    }
}

fn read_u64<R: Read>(r: &mut R) -> Result<u64, SnapshotFault> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b).map_err(|e| eof_is_truncated(&e))?;
    Ok(u64::from_le_bytes(b))
}

fn read_u32<R: Read>(r: &mut R) -> Result<u32, SnapshotFault> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b).map_err(|e| eof_is_truncated(&e))?;
    Ok(u32::from_le_bytes(b))
}

/// One key present on both sides with different values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnequalRow {
    /// The row key.
    pub key: Vec<u8>,
    /// Our value (the redb side).
    pub ours: Vec<u8>,
    /// Their value (the trace's, the LMDB side).
    pub theirs: Vec<u8>,
}

/// One family's comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FamilyDiff {
    /// Which family.
    pub family: SnapshotFamily,
    /// Keys on both sides with equal values.
    pub equal: u64,
    /// Keys on both sides with unequal values.
    pub unequal: Vec<UnequalRow>,
    /// Keys only on our side.
    pub only_ours: Vec<Vec<u8>>,
    /// Keys only on their side.
    pub only_theirs: Vec<Vec<u8>>,
}

impl FamilyDiff {
    /// Whether the family agreed.
    #[must_use]
    pub fn is_identical(&self) -> bool {
        self.unequal.is_empty() && self.only_ours.is_empty() && self.only_theirs.is_empty()
    }
}

/// The whole comparison, one entry per family in record order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotDiff {
    /// Per family.
    pub families: [FamilyDiff; FAMILY_COUNT],
}

impl SnapshotDiff {
    /// Whether every family agreed.
    #[must_use]
    pub fn is_identical(&self) -> bool {
        self.families.iter().all(FamilyDiff::is_identical)
    }

    /// The families that did not agree.
    pub fn diverged(&self) -> impl Iterator<Item = &FamilyDiff> + '_ {
        self.families.iter().filter(|d| !d.is_identical())
    }

    /// Rows present on both sides with equal values, across all families.
    #[must_use]
    pub fn rows_equal(&self) -> u64 {
        self.families.iter().map(|d| d.equal).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{Holdings, SlashedHolding};

    fn persona(i: u8) -> PCanonicalId {
        let mut b = [0x50u8; 32];
        b[0] = i;
        PCanonicalId::from_bytes(b)
    }

    fn bond(bonded: u64) -> BondRecord {
        BondRecord {
            hybrid_pubkey: vec![0x0A],
            bond_spend_pk: Vec::new(),
            endpoint: [0; 32],
            join_settlement_epoch: SettlementEpoch::ZERO,
            bonded_total: AtomicUnits::from_raw(bonded),
            holdings: Holdings::CompleteTree,
            bad_intervals: Vec::new(),
            claimed_settlement_epochs: Vec::new(),
            first_paying_emission_height: None,
        }
    }

    #[test]
    fn every_x_macro_family_has_a_disposition_and_the_record_has_ten() {
        let carried: Vec<SnapshotFamily> = ArchivalFamily::ALL
            .iter()
            .filter_map(|f| match disposition(*f) {
                Disposition::Rows(s) => Some(s),
                Disposition::Excluded(_) => None,
            })
            .collect();
        // Nine from the X-macro plus the properties cell.
        assert_eq!(carried.len() + 1, FAMILY_COUNT);
        assert_eq!(FAMILY_COUNT, 10);
        for (i, f) in SnapshotFamily::ALL.iter().enumerate() {
            assert_eq!(*f as usize, i, "positional discriminant");
            assert_eq!(SnapshotFamily::at(i), Some(*f));
        }
        assert_eq!(SnapshotFamily::at(FAMILY_COUNT), None);
        for f in carried {
            assert!(SnapshotFamily::ALL.contains(&f));
        }
        assert_eq!(EMPTY_BODY_LEN, 80);
    }

    #[test]
    fn empty_body_is_ten_zero_counts_and_reads_back() {
        let s = ArchivalSnapshot::empty();
        let body = s.body();
        assert_eq!(body.len(), EMPTY_BODY_LEN);
        assert!(body.iter().all(|&b| b == 0));
        let back = ArchivalSnapshot::read_body(&mut body.as_slice()).expect("reads");
        assert_eq!(back, s);
        assert!(back.diff(&s).is_identical());
    }

    #[test]
    fn rows_round_trip_through_the_body_and_the_reader_stops_at_its_end() {
        let mut s = ArchivalSnapshot::empty();
        s.push_bond(&persona(1), &bond(7)).unwrap();
        s.push_serve_credit(
            &persona(1),
            ShardId::from_raw(7),
            SettlementEpoch::from_raw(3),
            BlockHeight::from_raw(1000),
        )
        .unwrap();
        s.push_r_market(
            ShardId::from_raw(7),
            SettlementEpoch::from_raw(2),
            RMarket::from_raw(2),
        )
        .unwrap();
        s.push_sigma_work(SettlementEpoch::from_raw(2), SigmaWorkMilli::from_raw(5))
            .unwrap();
        s.push_budget(SettlementEpoch::from_raw(2), AtomicUnits::from_raw(9))
            .unwrap();
        s.push_attestation_witness(BlockHeight::from_raw(4), &[1, 2, 3, 4, 5, 6, 7, 8, 9])
            .unwrap();
        s.push_slash_log(
            BlockHeight::from_raw(1299),
            0,
            &SlashLogEntry {
                persona: persona(1),
                shard: ShardId::from_raw(0),
                epoch: SettlementEpoch::from_raw(3),
                holding: SlashedHolding::CompleteTree,
            },
        )
        .unwrap();
        s.push_slash_applied(
            &persona(1),
            ShardId::from_raw(0),
            SettlementEpoch::from_raw(3),
        )
        .unwrap();
        s.set_budget_accruing(SettlementEpoch::from_raw(12), AtomicUnits::from_raw(1))
            .unwrap();
        s.set_last_slash_epoch(SettlementEpoch::from_raw(3))
            .unwrap();
        assert_eq!(s.row_count(), 10);

        let mut bytes = s.body();
        bytes.extend_from_slice(b"tail");
        let mut cursor = bytes.as_slice();
        let back = ArchivalSnapshot::read_body(&mut cursor).expect("reads");
        assert_eq!(back, s);
        assert_eq!(cursor, b"tail", "the reader consumed exactly the body");
    }

    #[test]
    fn the_projections_are_in_the_constructors() {
        let mut s = ArchivalSnapshot::empty();
        s.push_r_market(
            ShardId::from_raw(1),
            SettlementEpoch::from_raw(1),
            RMarket::from_raw(0),
        )
        .unwrap();
        assert_eq!(
            s.rows(SnapshotFamily::RMarket).len(),
            0,
            "a zero count is not a row"
        );
        assert_eq!(
            s.push_slash_log(
                BlockHeight::from_raw(5),
                u32::MAX,
                &SlashLogEntry {
                    persona: persona(2),
                    shard: ShardId::from_raw(0),
                    epoch: SettlementEpoch::ZERO,
                    holding: SlashedHolding::CompleteTree,
                },
            ),
            Err(SnapshotFault::EpochMarkerSeq { height: 5 })
        );
        assert_eq!(
            s.push_attestation_witness(BlockHeight::from_raw(1), &[]),
            Err(SnapshotFault::WitnessShape { height: 1, len: 0 })
        );
        s.set_last_slash_epoch(SettlementEpoch::from_raw(1))
            .unwrap();
        assert_eq!(
            s.set_last_slash_epoch(SettlementEpoch::from_raw(2)),
            Err(SnapshotFault::SecondSingletonRow {
                family: SnapshotFamily::LastSlashEpoch
            })
        );
        s.push_slash_applied(
            &persona(3),
            ShardId::from_raw(1),
            SettlementEpoch::from_raw(1),
        )
        .unwrap();
        assert!(matches!(
            s.push_slash_applied(
                &persona(3),
                ShardId::from_raw(1),
                SettlementEpoch::from_raw(1)
            ),
            Err(SnapshotFault::DuplicateKey {
                family: SnapshotFamily::SlashApplied,
                ..
            })
        ));
        assert_eq!(
            s.insert(SnapshotFamily::Budget, vec![0; 8], vec![0; 7]),
            Err(SnapshotFault::ValueWidth {
                family: SnapshotFamily::Budget,
                found: 7
            })
        );
        assert_eq!(
            s.insert(SnapshotFamily::Bond, vec![0; 31], vec![]),
            Err(SnapshotFault::KeyWidth {
                family: SnapshotFamily::Bond,
                found: 31
            })
        );
    }

    #[test]
    fn the_diff_names_the_family_and_the_key() {
        let mut ours = ArchivalSnapshot::empty();
        let mut theirs = ArchivalSnapshot::empty();
        ours.push_bond(&persona(1), &bond(7)).unwrap();
        theirs.push_bond(&persona(1), &bond(8)).unwrap();
        ours.push_sigma_work(SettlementEpoch::from_raw(1), SigmaWorkMilli::from_raw(1))
            .unwrap();
        theirs
            .push_sigma_work(SettlementEpoch::from_raw(1), SigmaWorkMilli::from_raw(1))
            .unwrap();
        ours.set_last_slash_epoch(SettlementEpoch::from_raw(3))
            .unwrap();
        theirs
            .push_budget(SettlementEpoch::from_raw(1), AtomicUnits::from_raw(1))
            .unwrap();

        let d = ours.diff(&theirs);
        assert!(!d.is_identical());
        let diverged: Vec<SnapshotFamily> = d.diverged().map(|f| f.family).collect();
        assert_eq!(
            diverged,
            [
                SnapshotFamily::Bond,
                SnapshotFamily::Budget,
                SnapshotFamily::LastSlashEpoch
            ]
        );
        let bond = &d.families[SnapshotFamily::Bond as usize];
        assert_eq!(bond.unequal.len(), 1);
        assert_eq!(bond.unequal[0].key, persona(1).as_bytes().to_vec());
        assert_ne!(bond.unequal[0].ours, bond.unequal[0].theirs);
        assert_eq!(d.families[SnapshotFamily::SigmaWork as usize].equal, 1);
        assert_eq!(
            d.families[SnapshotFamily::Budget as usize]
                .only_theirs
                .len(),
            1
        );
        assert_eq!(
            d.families[SnapshotFamily::LastSlashEpoch as usize].only_ours,
            vec![3u64.to_le_bytes().to_vec()]
        );
        // Symmetric in which side is "ours".
        let back = theirs.diff(&ours);
        assert_eq!(
            back.families[SnapshotFamily::Budget as usize]
                .only_ours
                .len(),
            1
        );
    }

    #[test]
    fn a_truncated_or_oversized_body_is_refused() {
        let mut s = ArchivalSnapshot::empty();
        s.push_budget(SettlementEpoch::from_raw(1), AtomicUnits::from_raw(1))
            .unwrap();
        let body = s.body();
        for cut in [0, 8, 40, body.len() - 1] {
            assert_eq!(
                ArchivalSnapshot::read_body(&mut &body[..cut]).unwrap_err(),
                SnapshotFault::Truncated,
                "cut at {cut}"
            );
        }
        let mut huge = Vec::new();
        huge.extend_from_slice(&1u64.to_le_bytes());
        huge.extend_from_slice(&(u32::MAX).to_le_bytes());
        assert!(matches!(
            ArchivalSnapshot::read_body(&mut huge.as_slice()).unwrap_err(),
            SnapshotFault::RowTooLong {
                family: SnapshotFamily::Bond,
                ..
            }
        ));
    }
}
