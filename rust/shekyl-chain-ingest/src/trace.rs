// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The trace artifact: the LMDB-only facts and the digest checkpoints
//! (`DRS_E2_REPLAY_DRIVER.md` §3.9, RD-Q2).
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
//! checkpoint  0x02 ‖ height u64 ‖ n_blocks u64 ‖ n_spent u64 ‖ chain[32] ‖ spent[32]
//!                  ‖ curve_root[32] ‖ digest[32]                     (144 bytes after height)
//! trailer     0xFF ‖ facts u64 ‖ checkpoints u64
//! ```
//!
//! # The two doors (RD-Q2, RULED)
//!
//! A trace is read through exactly two typed doors, and the types are the
//! grader's law:
//!
//! - [`Trace::borrow`] yields [`Borrowed<Facts>`], which converts into
//!   [`ConnectFacts`] with every `Fact::origin` **`PassedThrough`** — by
//!   construction: the conversion is the only way out of a `Borrowed`, and
//!   it cannot mint a `Derived`. `connect` records the borrow honestly and
//!   the file's `Provenance` stays NOT-PARITY-EVIDENCE for as long as any
//!   fact comes this way (§5).
//! - [`Trace::expect`] yields [`Expected<LogicalStateDigestV0>`] for the
//!   **grader only**: the LMDB side's logical state at a checkpoint, by
//!   component, so RD-Q9's two clauses apply per component. It is
//!   deliberately not convertible into anything `connect` accepts.
//!
//! A grader that read a borrowed fact as evidence, or a connect that read an
//! expectation as a fact, is a type error, not a review catch.
//!
//! # Checkpoints are computed in Rust
//!
//! The exporter hands the writer the three **families** (block hashes, spent
//! keys, root) and [`TraceWriter::push_checkpoint_families`] assembles the
//! checkpoint with [`LogicalStateDigestV0::from_families`] — the same
//! function the redb read uses (commit 2). The C++ never hashes; the two
//! sides cannot have hashed differently.
//!
//! # Reserved
//!
//! Tag `0x03` (**Verdict**, the mutation family, §3.8) is refused as
//! [`TraceFault::ReservedTag`] until that family lands.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};

use shekyl_chain_store::digest_v0::LogicalStateDigestV0;
use shekyl_chain_store::store::{ConnectFacts, Fact};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockHeight, BlockWeight, CurveTreeRoot, LongTermWeight};
use shekyl_units::AtomicUnits;

/// The file's first eight bytes.
pub const TRACE_MAGIC: [u8; 8] = *b"SHKTRAC\0";
/// The layout this module reads and writes; bumped on any change.
pub const TRACE_VERSION: u8 = 0x00;

mod tag {
    pub const FACTS: u8 = 0x01;
    pub const CHECKPOINT: u8 = 0x02;
    pub const RESERVED_VERDICT: u8 = 0x03;
    pub const TRAILER: u8 = 0xFF;
}

const HEADER_LEN: usize = 8 + 1 + 7;
const RESERVED_LEN: usize = 7;
/// Bytes of a facts record after its height: 5 × u64 + 32 + u128.
pub const FACTS_LEN: usize = 5 * 8 + 32 + 16;
/// Bytes of a checkpoint record after its height: 2 × u64 + 4 × 32.
pub const CHECKPOINT_LEN: usize = 2 * 8 + 4 * 32;

/// Why a trace could not be written or read.
#[derive(Debug, thiserror::Error)]
pub enum TraceFault {
    /// The underlying reader or writer failed.
    #[error("trace I/O: {0}")]
    Io(#[from] io::Error),
    /// The file does not start with [`TRACE_MAGIC`].
    #[error("not a trace: bad magic")]
    BadMagic,
    /// A version this reader does not know.
    #[error("trace version {found} is not {TRACE_VERSION}")]
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
    /// A checkpoint names a height with no facts record.
    #[error("checkpoint at height {height} has no facts record to anchor to")]
    UnanchoredCheckpoint {
        /// The checkpoint's height.
        height: u64,
    },
    /// Two checkpoints at one height.
    #[error("a second checkpoint at height {height}")]
    DuplicateCheckpoint {
        /// The height.
        height: u64,
    },
    /// The trailer's counts disagree with the records read.
    #[error("trace trailer disagrees with the records: {what}")]
    TrailerMismatch {
        /// Which count.
        what: &'static str,
    },
    /// The file ended without a trailer.
    #[error("trace is truncated: no trailer")]
    Truncated,
}

/// The six passed-through facts for one height, plus the accumulator D4
/// reads — what LMDB recorded and Rust does not derive yet (§3.4).
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
    /// `curve_tree_roots[h + 1]`.
    pub root_after: CurveTreeRoot,
    /// `block_info`'s long-term effective median (S-CHAIN-R A1).
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
        let u64_at = |o: usize| u64::from_le_bytes(bytes[o..o + 8].try_into().expect("8 bytes"));
        let mut root = [0u8; 32];
        root.copy_from_slice(&bytes[32..64]);
        let mut cd = [0u8; 16];
        cd.copy_from_slice(&bytes[72..88]);
        Self {
            weight: BlockWeight::from_raw(u64_at(0)),
            long_term_weight: LongTermWeight::from_raw(u64_at(8)),
            coins_generated: AtomicUnits::from_raw(u64_at(16)),
            burned: AtomicUnits::from_raw(u64_at(24)),
            root_after: CurveTreeRoot::from_bytes(root),
            long_term_effective_median: LongTermWeight::from_raw(u64_at(64)),
            cumulative_difficulty: CumulativeDifficulty::from_raw(u128::from_le_bytes(cd)),
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

impl From<Borrowed<Facts>> for ConnectFacts {
    /// The one way a borrowed fact reaches `connect`: every origin is
    /// `PassedThrough`. `cumulative_difficulty` is not a connect fact (the
    /// verdict carries it since #785) and stays behind.
    fn from(b: Borrowed<Facts>) -> Self {
        let f = b.0;
        Self {
            weight: Fact::passed_through(f.weight),
            long_term_weight: Fact::passed_through(f.long_term_weight),
            coins_generated: Fact::passed_through(f.coins_generated),
            burned: Fact::passed_through(f.burned),
            root_after: Fact::passed_through(f.root_after),
            long_term_effective_median: Fact::passed_through(f.long_term_effective_median),
        }
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
    next_height: Option<u64>,
    last_height: Option<u64>,
    facts: u64,
    checkpoints: u64,
    checkpointed: BTreeSet<u64>,
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
        out.write_all(&[0u8; RESERVED_LEN])?;
        Ok(Self {
            out,
            next_height: None,
            last_height: None,
            facts: 0,
            checkpoints: 0,
            checkpointed: BTreeSet::new(),
        })
    }

    /// The facts for `height`, which must be the next consecutive height
    /// (the first call sets the start).
    ///
    /// # Errors
    ///
    /// [`TraceFault::HeightGap`]; I/O.
    pub fn push_facts(&mut self, height: BlockHeight, facts: &Facts) -> Result<(), TraceFault> {
        let h = height.to_raw();
        if let Some(expected) = self.next_height {
            if h != expected {
                return Err(TraceFault::HeightGap { expected, found: h });
            }
        }
        self.out.write_all(&[tag::FACTS])?;
        self.out.write_all(&h.to_le_bytes())?;
        facts.write_to(&mut self.out)?;
        self.next_height = Some(h.checked_add(1).expect("height fits u64"));
        self.last_height = Some(h);
        self.facts += 1;
        Ok(())
    }

    /// The LMDB logical state after `height`, assembled here from the
    /// families the exporter walked (module docs). `height` must have a
    /// facts record already.
    ///
    /// # Errors
    ///
    /// [`TraceFault::UnanchoredCheckpoint`], [`TraceFault::DuplicateCheckpoint`];
    /// I/O.
    pub fn push_checkpoint_families(
        &mut self,
        height: BlockHeight,
        block_hashes: &[[u8; 32]],
        spent_keys: &[[u8; 32]],
        curve_root: CurveTreeRoot,
    ) -> Result<LogicalStateDigestV0, TraceFault> {
        let state = LogicalStateDigestV0::from_families(block_hashes, spent_keys, curve_root);
        self.push_checkpoint(height, &state)?;
        Ok(state)
    }

    /// A checkpoint already assembled (a redb-side state being recorded as
    /// an expectation, e.g. when re-baselining from Rust after cutover).
    ///
    /// # Errors
    ///
    /// As [`push_checkpoint_families`](Self::push_checkpoint_families).
    pub fn push_checkpoint(
        &mut self,
        height: BlockHeight,
        state: &LogicalStateDigestV0,
    ) -> Result<(), TraceFault> {
        let h = height.to_raw();
        if self.last_height.is_none_or(|last| h > last) {
            return Err(TraceFault::UnanchoredCheckpoint { height: h });
        }
        if !self.checkpointed.insert(h) {
            return Err(TraceFault::DuplicateCheckpoint { height: h });
        }
        self.out.write_all(&[tag::CHECKPOINT])?;
        self.out.write_all(&h.to_le_bytes())?;
        self.out.write_all(&state.n_blocks.to_le_bytes())?;
        self.out.write_all(&state.n_spent.to_le_bytes())?;
        self.out.write_all(&state.chain)?;
        self.out.write_all(&state.spent)?;
        self.out.write_all(state.curve_root.as_bytes())?;
        self.out.write_all(&state.digest)?;
        self.checkpoints += 1;
        Ok(())
    }

    /// Write the trailer and hand the sink back.
    ///
    /// # Errors
    ///
    /// I/O.
    pub fn finish(mut self) -> Result<W, TraceFault> {
        self.out.write_all(&[tag::TRAILER])?;
        self.out.write_all(&self.facts.to_le_bytes())?;
        self.out.write_all(&self.checkpoints.to_le_bytes())?;
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
    checkpoints: BTreeMap<u64, LogicalStateDigestV0>,
}

fn read_u64<R: Read>(r: &mut R) -> Result<u64, io::Error> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

impl Trace {
    /// Read and check a whole trace.
    ///
    /// # Errors
    ///
    /// Any [`TraceFault`].
    pub fn read<R: Read>(mut input: R) -> Result<Self, TraceFault> {
        let mut header = [0u8; HEADER_LEN];
        input.read_exact(&mut header)?;
        if header[..8] != TRACE_MAGIC {
            return Err(TraceFault::BadMagic);
        }
        if header[8] != TRACE_VERSION {
            return Err(TraceFault::UnsupportedVersion { found: header[8] });
        }
        if header[9..16].iter().any(|&b| b != 0) {
            return Err(TraceFault::ReservedNonZero);
        }
        let mut facts = BTreeMap::new();
        let mut checkpoints = BTreeMap::new();
        let mut next_height: Option<u64> = None;
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
                    if let Some(expected) = next_height {
                        if h != expected {
                            return Err(TraceFault::HeightGap { expected, found: h });
                        }
                    }
                    let mut body = [0u8; FACTS_LEN];
                    input.read_exact(&mut body)?;
                    facts.insert(h, Facts::read_from(&body));
                    next_height = Some(h.checked_add(1).expect("height fits u64"));
                }
                tag::CHECKPOINT => {
                    let h = read_u64(&mut input)?;
                    if !facts.contains_key(&h) {
                        return Err(TraceFault::UnanchoredCheckpoint { height: h });
                    }
                    let mut body = [0u8; CHECKPOINT_LEN];
                    input.read_exact(&mut body)?;
                    let u64_at =
                        |o: usize| u64::from_le_bytes(body[o..o + 8].try_into().expect("8 bytes"));
                    let arr = |o: usize| -> [u8; 32] {
                        let mut a = [0u8; 32];
                        a.copy_from_slice(&body[o..o + 32]);
                        a
                    };
                    let state = LogicalStateDigestV0 {
                        n_blocks: u64_at(0),
                        n_spent: u64_at(8),
                        chain: arr(16),
                        spent: arr(48),
                        curve_root: CurveTreeRoot::from_bytes(arr(80)),
                        digest: arr(112),
                    };
                    if checkpoints.insert(h, state).is_some() {
                        return Err(TraceFault::DuplicateCheckpoint { height: h });
                    }
                }
                tag::TRAILER => {
                    let n_facts = read_u64(&mut input)?;
                    let n_checkpoints = read_u64(&mut input)?;
                    if n_facts != facts.len() as u64 {
                        return Err(TraceFault::TrailerMismatch { what: "facts" });
                    }
                    if n_checkpoints != checkpoints.len() as u64 {
                        return Err(TraceFault::TrailerMismatch {
                            what: "checkpoints",
                        });
                    }
                    return Ok(Self { facts, checkpoints });
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
    /// grader. `None` where no checkpoint was recorded.
    #[must_use]
    pub fn expect(&self, height: BlockHeight) -> Option<Expected<LogicalStateDigestV0>> {
        self.checkpoints
            .get(&height.to_raw())
            .cloned()
            .map(Expected)
    }

    /// The heights this trace has facts for, as an inclusive range; `None`
    /// when empty.
    #[must_use]
    pub fn covered(&self) -> Option<(BlockHeight, BlockHeight)> {
        let first = *self.facts.keys().next()?;
        let last = *self.facts.keys().next_back()?;
        Some((BlockHeight::from_raw(first), BlockHeight::from_raw(last)))
    }

    /// The heights with a checkpoint, ascending.
    pub fn checkpoint_heights(&self) -> impl Iterator<Item = BlockHeight> + '_ {
        self.checkpoints.keys().map(|&h| BlockHeight::from_raw(h))
    }
}
