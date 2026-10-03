// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The trace artifact: the LMDB-only facts and one checkpoint in two
//! encodings — the v0 digest and the archival snapshot's rows
//! (`DRS_E2_REPLAY_DRIVER.md` §3.9, RD-Q2, RD-F18;
//! `DRS_E4_ARCHIVAL_WRITER.md` §3.8.1, `ARW-25`).
//!
//! Produced by **one** C++ exporter walking LMDB and handing bytes across
//! the FFI to [`TraceWriter`] — the whole of that C++ dies with the daemon
//! (§1.3). Rust-minted and versioned (RD-F9), fixed layout, little-endian.
//!
//! ```text
//! header      magic "SHKTRAC\0" ‖ version u8 ‖ reserved[7] = 0
//! facts       0x01 ‖ height u64 ‖ weight u64 ‖ long_term_weight u64 ‖ coins_generated u64
//!                  ‖ burned u64 ‖ root_after[32] ‖ long_term_effective_median u64
//!                  ‖ cumulative_difficulty u128                       (88 bytes after height)
//! checkpoint  0x02 ‖ height u64 ‖ digest[32]                          (32 bytes after height)
//! snapshot    0x04 ‖ height u64 ‖ for each of the ten archival families, in
//!                  §3.8.1's order: n_rows u64 ‖ (len u32 ‖ row bytes)*   (80 bytes after height
//!                                                                         when every family is empty)
//! trailer     0xFF ‖ facts u64 ‖ checkpoints u64
//! ```
//!
//! At most one checkpoint, at the **covered tip** (the last facts row):
//! LMDB's spent set is tip-only (RD-F18), so a checkpoint at any other
//! height would pair a past chain with the present set. The writer takes
//! no height — it uses the last facts row — and refuses a second one and
//! any facts after it. The on-disk height is that tip, so a reader can
//! still name the expectation.
//!
//! # The checkpoint's two encodings (version `0x01`)
//!
//! The `0x02` record is the v0 digest — the chain / spent-set / curve-root
//! state, unchanged. The `0x04` record is the **archival snapshot**
//! (`DRS_E4_ARCHIVAL_WRITER.md` §3.8.1): the archival state at the same
//! tip as canonical rows, ten positional families, which the grader
//! compares row by row rather than through a hash (`ARW-25`: at one
//! checkpoint per chain a diff names the family and the key a hash would
//! only say differed). Under `TRACE_VERSION` `0x01` the two records are
//! one checkpoint: a trace carrying the `0x02` record carries the `0x04`
//! record at the same height, the writer refuses a `finish` with one and
//! not the other ([`TraceFault::MissingSnapshot`]) and the reader refuses
//! the file. An empty archival state is a `0x04` record of ten zero
//! counts, never an omitted record.
//!
//! The reader accepts [`TRACE_VERSION`] alone. The `0x00` layout — no
//! `0x04` record — was readable through DRS-E4 commit 6 while the six
//! committed corpus traces still carried it; commit 7 re-captured them and
//! the arm went with the last file that needed it (rule 15). A trace with
//! a checkpoint and no snapshot is now a defect of the file, not a
//! version.
//!
//! # The two doors (RD-Q2, RULED)
//!
//! A trace is read through exactly two typed doors, and the types are the
//! grader's law:
//!
//! - [`Trace::borrow`] yields [`Borrowed<Facts>`] — the recorded values as
//!   **comparison inputs** for the replay's oracles (roots, weights, the
//!   accumulator and the burn), never as anything `connect` is handed.
//!   Until E6 slice 7 wave B the `Borrowed` converted into the store's
//!   `ConnectFacts` with every origin `PassedThrough` — the one door for a
//!   fact Rust did not yet derive, and the file's `Provenance` stayed
//!   NOT-PARITY-EVIDENCE while any came this way (§5). The last such fact
//!   became the verdict's on 2026-09-29, and the conversion went with the
//!   type; `borrow` feeds the oracles alone.
//! - [`Trace::expect`] yields [`Expected<Digest>`] for the **grader
//!   only**: the LMDB side's logical-state digest at a checkpoint. It is
//!   deliberately not convertible into anything `connect` accepts.
//!   [`Trace::archival_snapshot`] is the same door for the archival rows:
//!   `Expected<&ArchivalSnapshot>`, the grader's comparison partner and
//!   nothing a connect can read.
//!
//! A grader that read a borrowed fact as evidence, or a connect that read an
//! expectation as a fact, is a type error, not a review catch.
//!
//! # Checkpoints are computed in Rust
//!
//! The exporter asks the daemon's own LMDB digest walker
//! (`BlockchainLMDB::logical_state_digest_v0`, one read snapshot across
//! the three families) and hands the writer the finished 32 bytes through
//! [`TraceWriter::push_checkpoint`]. That walker hashes through the FFI
//! with `digest_v0` — the same function the redb read
//! (`ReadSnapshot::logical_state_digest_v0`, commit 2) applies to its own
//! families. The C++ never hashes; the two sides cannot have hashed
//! differently. The checkpoint is the **outer** digest only: the redb read
//! returns no components, so a DIVERGE names the height and not the
//! family; if a real chain ever diverges, widening both sides to carry the
//! three components is the diagnosis step (rule 21 reopener: the first
//! DIVERGE at a checkpoint on a real chain).
//!
//! # Reserved
//!
//! Tag `0x03` (**Verdict**, the mutation family, §3.8) is refused as
//! [`TraceFault::ReservedTag`]: the family landed with its verdicts as
//! code and the byte stays reserved so it is not re-minted (rule 23) —
//! the archival snapshot is `0x04` for that reason.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::ops::RangeInclusive;

use shekyl_chain_store::archival_snapshot::{ArchivalSnapshot, SnapshotFault};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockHeight, BlockWeight, CurveTreeRoot, LongTermWeight};
use shekyl_units::AtomicUnits;

/// The file's first eight bytes.
pub const TRACE_MAGIC: [u8; 8] = *b"SHKTRAC\0";
/// The layout this module writes and the only one it reads; bumped on any
/// change. `0x01` added the archival snapshot record (DRS-E4 commit 6);
/// `0x00`, the layout without it, is no longer read (commit 7).
pub const TRACE_VERSION: u8 = 0x01;

mod tag {
    pub const FACTS: u8 = 0x01;
    pub const CHECKPOINT: u8 = 0x02;
    pub const RESERVED_VERDICT: u8 = 0x03;
    pub const ARCHIVAL_SNAPSHOT: u8 = 0x04;
    pub const TRAILER: u8 = 0xFF;
}

/// The header: magic ‖ version ‖ reserved.
mod header {
    use core::ops::Range;
    pub const MAGIC: Range<usize> = 0..8;
    pub const VERSION: usize = MAGIC.end;
    pub const RESERVED_LEN: usize = 7;
    pub const RESERVED: Range<usize> = VERSION + 1..VERSION + 1 + RESERVED_LEN;
    pub const LEN: usize = RESERVED.end;
}

/// The facts row's field offsets (§3.9): every field is fixed-width and the
/// offsets are the cumulative widths, so the writer and the reader share
/// one table and neither can drift from the other.
mod facts_layout {
    use core::ops::Range;
    const fn field(start: usize, width: usize) -> Range<usize> {
        start..start + width
    }
    pub const WEIGHT: Range<usize> = field(0, 8);
    pub const LONG_TERM_WEIGHT: Range<usize> = field(WEIGHT.end, 8);
    pub const COINS_GENERATED: Range<usize> = field(LONG_TERM_WEIGHT.end, 8);
    pub const BURNED: Range<usize> = field(COINS_GENERATED.end, 8);
    pub const ROOT_AFTER: Range<usize> = field(BURNED.end, 32);
    pub const LONG_TERM_EFFECTIVE_MEDIAN: Range<usize> = field(ROOT_AFTER.end, 8);
    pub const CUMULATIVE_DIFFICULTY: Range<usize> = field(LONG_TERM_EFFECTIVE_MEDIAN.end, 16);
    pub const LEN: usize = CUMULATIVE_DIFFICULTY.end;
}

/// A logical-state digest (`digest_v0`'s output), as the trace carries it.
pub type Digest = [u8; 32];

/// Bytes of a facts record after its height (the layout table's length).
pub const FACTS_LEN: usize = facts_layout::LEN;
/// Bytes of a checkpoint record after its height: the outer digest.
pub const CHECKPOINT_LEN: usize = core::mem::size_of::<Digest>();

/// Why a trace could not be written or read.
#[derive(Debug, thiserror::Error)]
pub enum TraceFault {
    /// The underlying reader or writer failed.
    #[error("trace I/O: {0}")]
    Io(#[from] io::Error),
    /// The file does not start with [`TRACE_MAGIC`].
    #[error("not a trace: bad magic")]
    BadMagic,
    /// A version other than [`TRACE_VERSION`].
    #[error("trace version {found}: this reader accepts {TRACE_VERSION}")]
    UnsupportedVersion {
        /// The version byte found.
        found: u8,
    },
    /// The reserved header bytes are not zero.
    #[error("trace header reserved bytes are not zero")]
    ReservedNonZero,
    /// A record tag this reader does not know.
    #[error("unknown record tag {0:#04x}")]
    UnknownTag(u8),
    /// The `Verdict` tag, reserved for the mutation family.
    #[error("record tag {0:#04x} is reserved (Verdict, §3.8) and not yet readable")]
    ReservedTag(u8),
    /// Facts records must be consecutive by height.
    #[error("facts height gap: expected {expected}, found {found}")]
    HeightGap {
        /// The height the next facts record had to carry.
        expected: u64,
        /// The height it carried.
        found: u64,
    },
    /// A facts record after height `u64::MAX`: no height follows it. Not
    /// a representable chain; refused as a fault on both sides rather than
    /// letting a crafted record take a reader down.
    #[error("no height follows {after}; the trace cannot carry another facts record")]
    HeightExhausted {
        /// The last height a trace can carry.
        after: u64,
    },
    /// A checkpoint with no facts row to hang it on.
    #[error("checkpoint has no facts record to anchor to")]
    UnanchoredCheckpoint,
    /// A checkpoint naming a height that is not the last facts row
    /// (RD-F18: the spent set is tip-only, so the expectation is the
    /// covered tip).
    #[error("checkpoint at height {height} is not the covered tip {tip}")]
    CheckpointNotTip {
        /// The checkpoint's height.
        height: u64,
        /// The last facts height.
        tip: u64,
    },
    /// A second checkpoint: a trace carries one, at the covered tip.
    #[error("a second checkpoint (the first was at height {height})")]
    DuplicateCheckpoint {
        /// The height of the checkpoint already recorded.
        height: u64,
    },
    /// A facts row after the checkpoint: the checkpoint is the covered
    /// tip, so later facts would leave it behind.
    #[error("facts at height {height} after the checkpoint; the checkpoint is the covered tip")]
    FactsAfterCheckpoint {
        /// The facts height that arrived too late.
        height: u64,
    },
    /// An archival snapshot with no checkpoint to pair with: the two
    /// records are one checkpoint's two encodings, and the digest's
    /// `0x02` record names the height the snapshot is anchored at.
    #[error("archival snapshot has no checkpoint to pair with")]
    UnanchoredSnapshot,
    /// An archival snapshot naming a height other than the checkpoint's.
    #[error("archival snapshot at height {height} is not the checkpoint's tip {tip}")]
    SnapshotNotTip {
        /// The snapshot's height.
        height: u64,
        /// The checkpoint's height.
        tip: u64,
    },
    /// A second archival snapshot: a trace carries one, with the checkpoint.
    #[error("a second archival snapshot (the first was at height {height})")]
    DuplicateSnapshot {
        /// The height of the snapshot already recorded.
        height: u64,
    },
    /// A checkpoint with no archival snapshot beside it — §3.8.1: an empty
    /// archival state is a record of ten zero counts, never an omitted
    /// record.
    #[error(
        "the checkpoint at height {height} has no archival snapshot; \
         a trace carries both or neither"
    )]
    MissingSnapshot {
        /// The checkpoint's height.
        height: u64,
    },
    /// The snapshot's rows could not be read back as §3.8.1 rows.
    #[error("archival snapshot: {0}")]
    Snapshot(#[from] SnapshotFault),
    /// The trailer's counts disagree with the records read.
    #[error("trace trailer disagrees with the records: {what}")]
    TrailerMismatch {
        /// Which count.
        what: &'static str,
    },
    /// The file ended without a trailer.
    #[error("trace is truncated: no trailer")]
    Truncated,
    /// Bytes after the trailer: two traces concatenated, or a file written
    /// past its end. The trailer is the end of a trace, not a marker
    /// inside one.
    #[error("bytes after the trailer")]
    TrailingBytes,
}

/// The five passed-through facts for one height, plus the two values LMDB
/// recorded that Rust now derives and the replay holds it to (§3.4): the
/// accumulator D4 reads (SI-10's observer) and the root after the drain
/// (DRS-E3's oracle, CTW-5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Facts {
    /// `block_info.bi_weight`.
    pub weight: BlockWeight,
    /// `block_info.bi_long_term_block_weight`.
    pub long_term_weight: LongTermWeight,
    /// `block_info.bi_coins`.
    pub coins_generated: AtomicUnits,
    /// `block_burn[h]`, zero when the row is absent.
    pub burned: AtomicUnits,
    /// `curve_tree_roots[h + 1]` — the root the C++ grower left after this
    /// block's drain. **Not passed through** since DRS-E3: `validate`
    /// derives the root and `connect` records the verdict's. Kept in the
    /// record as the comparison input for the derived-vs-trace oracle
    /// (`DRS_E3_CURVE_WRITER.md` §3.8, CTW-5), and read by CEN-B5 through
    /// the next captured header regardless.
    pub root_after: CurveTreeRoot,
    /// The long-term effective median in force for the block (S-CHAIN-R
    /// A1, SCR-19). LMDB stores no such row: the exporter re-derives it
    /// over the recorded long-term weights with the daemon's own rolling
    /// median, exactly as `add_block` did; the weights oracle compares the
    /// verdict's (CEN-G6) against it.
    pub long_term_effective_median: LongTermWeight,
    /// `block_info.bi_diff` — the accumulator D4 reads; recorded so the
    /// SI-10 observer has the LMDB value to compare against.
    pub cumulative_difficulty: CumulativeDifficulty,
}

impl Facts {
    fn write_to<W: Write>(&self, out: &mut W) -> io::Result<()> {
        out.write_all(&self.weight.to_raw().to_le_bytes())?;
        out.write_all(&self.long_term_weight.to_raw().to_le_bytes())?;
        out.write_all(&self.coins_generated.to_raw().to_le_bytes())?;
        out.write_all(&self.burned.to_raw().to_le_bytes())?;
        out.write_all(self.root_after.as_bytes())?;
        out.write_all(&self.long_term_effective_median.to_raw().to_le_bytes())?;
        out.write_all(&self.cumulative_difficulty.to_raw().to_le_bytes())
    }

    fn read_from(bytes: &[u8; FACTS_LEN]) -> Self {
        use facts_layout as at;
        let u64_at = |r: core::ops::Range<usize>| {
            u64::from_le_bytes(bytes[r].try_into().expect("an 8-byte field"))
        };
        Self {
            weight: BlockWeight::from_raw(u64_at(at::WEIGHT)),
            long_term_weight: LongTermWeight::from_raw(u64_at(at::LONG_TERM_WEIGHT)),
            coins_generated: AtomicUnits::from_raw(u64_at(at::COINS_GENERATED)),
            burned: AtomicUnits::from_raw(u64_at(at::BURNED)),
            root_after: CurveTreeRoot::from_bytes(
                bytes[at::ROOT_AFTER].try_into().expect("a 32-byte field"),
            ),
            long_term_effective_median: LongTermWeight::from_raw(u64_at(
                at::LONG_TERM_EFFECTIVE_MEDIAN,
            )),
            cumulative_difficulty: CumulativeDifficulty::from_raw(u128::from_le_bytes(
                bytes[at::CUMULATIVE_DIFFICULTY]
                    .try_into()
                    .expect("a 16-byte field"),
            )),
        }
    }
}

/// Facts read through the `borrow` door: usable by `connect`, and only as
/// passed-through (module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Borrowed<T>(T);

impl<T> Borrowed<T> {
    /// The value, for a reader that must see it (a log, an artifact).
    /// Not for the grader: an expectation comes through [`Trace::expect`].
    #[must_use]
    pub const fn value(&self) -> &T {
        &self.0
    }
}

/// A checkpoint read through the `expect` door: the LMDB side's logical
/// state after a height, for the grader alone. Not convertible into a
/// connect input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expected<T>(T);

impl<T> Expected<T> {
    /// The expectation, for the grader.
    #[must_use]
    pub const fn value(&self) -> &T {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// Writes a trace as the exporter hands facts and families across.
#[derive(Debug)]
pub struct TraceWriter<W: Write> {
    out: W,
    /// The heights with a facts row so far — consecutive from the first,
    /// so a range is exact. The checkpoint, if any, is the covered tip
    /// (`end`).
    covered: Option<RangeInclusive<u64>>,
    facts: u64,
    /// The covered-tip height of the one checkpoint, once written.
    checkpointed: Option<u64>,
    /// The height of the one archival snapshot, once written — the
    /// checkpoint's.
    snapshotted: Option<u64>,
}

impl<W: Write> TraceWriter<W> {
    /// Start a trace; writes the header. The first facts record sets the
    /// first height.
    ///
    /// # Errors
    ///
    /// I/O.
    pub fn new(mut out: W) -> Result<Self, TraceFault> {
        out.write_all(&TRACE_MAGIC)?;
        out.write_all(&[TRACE_VERSION])?;
        out.write_all(&[0u8; header::RESERVED_LEN])?;
        Ok(Self {
            out,
            covered: None,
            facts: 0,
            checkpointed: None,
            snapshotted: None,
        })
    }

    /// The facts for `height`, which must be the next consecutive height
    /// (the first call sets the start).
    ///
    /// # Errors
    ///
    /// [`TraceFault::HeightGap`], [`TraceFault::HeightExhausted`],
    /// [`TraceFault::FactsAfterCheckpoint`]; I/O.
    pub fn push_facts(&mut self, height: BlockHeight, facts: &Facts) -> Result<(), TraceFault> {
        let h = height.to_raw();
        if self.checkpointed.is_some() {
            return Err(TraceFault::FactsAfterCheckpoint { height: h });
        }
        if let Some(covered) = &self.covered {
            let expected = successor(*covered.end())?;
            if h != expected {
                return Err(TraceFault::HeightGap { expected, found: h });
            }
        }
        self.out.write_all(&[tag::FACTS])?;
        self.out.write_all(&h.to_le_bytes())?;
        facts.write_to(&mut self.out)?;
        self.covered = Some(match &self.covered {
            Some(covered) => *covered.start()..=h,
            None => h..=h,
        });
        self.facts += 1;
        Ok(())
    }

    /// The logical state after the covered tip — the LMDB walker's digest
    /// (module docs), or a redb-side state being recorded as an expectation
    /// when re-baselining from Rust after cutover. Written at the last facts
    /// height.
    ///
    /// # Errors
    ///
    /// [`TraceFault::UnanchoredCheckpoint`], [`TraceFault::DuplicateCheckpoint`];
    /// I/O.
    pub fn push_checkpoint(&mut self, state: &Digest) -> Result<(), TraceFault> {
        let h = match &self.covered {
            Some(covered) => *covered.end(),
            None => return Err(TraceFault::UnanchoredCheckpoint),
        };
        if let Some(first) = self.checkpointed {
            return Err(TraceFault::DuplicateCheckpoint { height: first });
        }
        self.out.write_all(&[tag::CHECKPOINT])?;
        self.out.write_all(&h.to_le_bytes())?;
        self.out.write_all(state)?;
        self.checkpointed = Some(h);
        Ok(())
    }

    /// The archival state at the checkpoint's height, as §3.8.1's rows —
    /// the LMDB walker's marshal, or the redb read when re-baselining.
    /// Written after [`push_checkpoint`](Self::push_checkpoint), at its
    /// height: the two records are one checkpoint's two encodings.
    ///
    /// # Errors
    ///
    /// [`TraceFault::UnanchoredSnapshot`] before a checkpoint,
    /// [`TraceFault::DuplicateSnapshot`]; I/O.
    pub fn push_archival_snapshot(
        &mut self,
        snapshot: &ArchivalSnapshot,
    ) -> Result<(), TraceFault> {
        let Some(h) = self.checkpointed else {
            return Err(TraceFault::UnanchoredSnapshot);
        };
        if let Some(first) = self.snapshotted {
            return Err(TraceFault::DuplicateSnapshot { height: first });
        }
        self.out.write_all(&[tag::ARCHIVAL_SNAPSHOT])?;
        self.out.write_all(&h.to_le_bytes())?;
        snapshot.write_body(&mut self.out)?;
        self.snapshotted = Some(h);
        Ok(())
    }

    /// Write the trailer and hand the sink back.
    ///
    /// # Errors
    ///
    /// [`TraceFault::MissingSnapshot`] when a checkpoint was written and
    /// its archival snapshot was not; I/O.
    pub fn finish(mut self) -> Result<W, TraceFault> {
        if let (Some(height), None) = (self.checkpointed, self.snapshotted) {
            return Err(TraceFault::MissingSnapshot { height });
        }
        self.out.write_all(&[tag::TRAILER])?;
        self.out.write_all(&self.facts.to_le_bytes())?;
        let n_checkpoints = u64::from(self.checkpointed.is_some());
        self.out.write_all(&n_checkpoints.to_le_bytes())?;
        self.out.flush()?;
        Ok(self.out)
    }
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// A trace, read whole (88 bytes a height: a million heights is 84 MiB),
/// exposing the two doors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trace {
    facts: BTreeMap<u64, Facts>,
    /// At most one, at the covered tip.
    checkpoint: Option<(u64, Digest)>,
    /// With the checkpoint, at its height: `Some` iff `checkpoint` is.
    snapshot: Option<(u64, ArchivalSnapshot)>,
}

fn read_u64<R: Read>(r: &mut R) -> Result<u64, io::Error> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

/// The height after `last`, or [`TraceFault::HeightExhausted`] past
/// `u64::MAX` — the same refusal on the writer and the reader.
fn successor(last: u64) -> Result<u64, TraceFault> {
    last.checked_add(1)
        .ok_or(TraceFault::HeightExhausted { after: last })
}

impl Trace {
    /// Read and check a whole trace.
    ///
    /// # Errors
    ///
    /// Any [`TraceFault`].
    pub fn read<R: Read>(mut input: R) -> Result<Self, TraceFault> {
        let mut head = [0u8; header::LEN];
        input.read_exact(&mut head)?;
        if head[header::MAGIC] != TRACE_MAGIC {
            return Err(TraceFault::BadMagic);
        }
        let version = head[header::VERSION];
        if version != TRACE_VERSION {
            return Err(TraceFault::UnsupportedVersion { found: version });
        }
        if head[header::RESERVED].iter().any(|&b| b != 0) {
            return Err(TraceFault::ReservedNonZero);
        }
        let mut facts = BTreeMap::new();
        let mut checkpoint: Option<(u64, Digest)> = None;
        let mut snapshot: Option<(u64, ArchivalSnapshot)> = None;
        let mut last_height: Option<u64> = None;
        loop {
            let mut t = [0u8; 1];
            match input.read_exact(&mut t) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    return Err(TraceFault::Truncated)
                }
                Err(e) => return Err(e.into()),
            }
            match t[0] {
                tag::FACTS => {
                    let h = read_u64(&mut input)?;
                    if let Some(last) = last_height {
                        let expected = successor(last)?;
                        if h != expected {
                            return Err(TraceFault::HeightGap { expected, found: h });
                        }
                    }
                    let mut body = [0u8; FACTS_LEN];
                    input.read_exact(&mut body)?;
                    facts.insert(h, Facts::read_from(&body));
                    last_height = Some(h);
                }
                tag::CHECKPOINT => {
                    let h = read_u64(&mut input)?;
                    if !facts.contains_key(&h) {
                        return Err(TraceFault::UnanchoredCheckpoint);
                    }
                    let mut state = [0u8; CHECKPOINT_LEN];
                    input.read_exact(&mut state)?;
                    if let Some((first, _)) = checkpoint {
                        return Err(TraceFault::DuplicateCheckpoint { height: first });
                    }
                    checkpoint = Some((h, state));
                }
                tag::ARCHIVAL_SNAPSHOT => {
                    let h = read_u64(&mut input)?;
                    let Some((tip, _)) = checkpoint else {
                        return Err(TraceFault::UnanchoredSnapshot);
                    };
                    if h != tip {
                        return Err(TraceFault::SnapshotNotTip { height: h, tip });
                    }
                    if let Some((first, _)) = &snapshot {
                        return Err(TraceFault::DuplicateSnapshot { height: *first });
                    }
                    snapshot = Some((h, ArchivalSnapshot::read_body(&mut input)?));
                }
                tag::TRAILER => {
                    let n_facts = read_u64(&mut input)?;
                    let n_checkpoints = read_u64(&mut input)?;
                    if n_facts != facts.len() as u64 {
                        return Err(TraceFault::TrailerMismatch { what: "facts" });
                    }
                    if n_checkpoints != u64::from(checkpoint.is_some()) {
                        return Err(TraceFault::TrailerMismatch {
                            what: "checkpoints",
                        });
                    }
                    if let Some((h, _)) = checkpoint {
                        let tip = *facts.keys().next_back().expect("a checkpoint is anchored");
                        if h != tip {
                            return Err(TraceFault::CheckpointNotTip { height: h, tip });
                        }
                        if snapshot.is_none() {
                            return Err(TraceFault::MissingSnapshot { height: h });
                        }
                    }
                    // The trailer ends a trace: one probe byte tells a
                    // clean end from bytes written past it.
                    let mut probe = [0u8; 1];
                    if input.read(&mut probe)? != 0 {
                        return Err(TraceFault::TrailingBytes);
                    }
                    return Ok(Self {
                        facts,
                        checkpoint,
                        snapshot,
                    });
                }
                tag::RESERVED_VERDICT => return Err(TraceFault::ReservedTag(t[0])),
                other => return Err(TraceFault::UnknownTag(other)),
            }
        }
    }

    /// The `borrow` door: the facts `connect` needs at `height`, as
    /// passed-through. `None` where the trace does not reach.
    #[must_use]
    pub fn borrow(&self, height: BlockHeight) -> Option<Borrowed<Facts>> {
        self.facts.get(&height.to_raw()).copied().map(Borrowed)
    }

    /// The `expect` door: the LMDB logical state after `height`, for the
    /// grader. `None` where that height is not the covered-tip checkpoint.
    #[must_use]
    pub fn expect(&self, height: BlockHeight) -> Option<Expected<Digest>> {
        match self.checkpoint {
            Some((h, d)) if h == height.to_raw() => Some(Expected(d)),
            _ => None,
        }
    }

    /// The one checkpoint: the logical state after the covered tip.
    #[must_use]
    pub fn checkpoint(&self) -> Option<(BlockHeight, Expected<Digest>)> {
        self.checkpoint
            .map(|(h, d)| (BlockHeight::from_raw(h), Expected(d)))
    }

    /// The checkpoint's other encoding: the archival state after the
    /// covered tip as §3.8.1's rows, for the grader. `None` exactly when
    /// the trace carries no checkpoint.
    #[must_use]
    pub fn archival_snapshot(&self) -> Option<(BlockHeight, Expected<&ArchivalSnapshot>)> {
        self.snapshot
            .as_ref()
            .map(|(h, s)| (BlockHeight::from_raw(*h), Expected(s)))
    }

    /// The heights this trace has facts for, as an inclusive range; `None`
    /// when empty.
    #[must_use]
    pub fn covered(&self) -> Option<(BlockHeight, BlockHeight)> {
        let first = *self.facts.keys().next()?;
        let last = *self.facts.keys().next_back()?;
        Some((BlockHeight::from_raw(first), BlockHeight::from_raw(last)))
    }
}
