// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The corpus artifact: what the network carries, as a file
//! (`DRS_E2_REPLAY_DRIVER.md` §3.9).
//!
//! A sequence-ordered run of records: `Extend`, a block with the full
//! bodies of its listed transactions in header order — exactly what a
//! [`Candidate`] consumes and nothing else (RD-Q2: network-shaped; the
//! passed-through facts travel in the trace, never here) — and `Rewind`,
//! the reorg family's switch (RD-Q13, commit 8c). Rust-minted and
//! versioned (RD-F9), fixed layout, little-endian throughout.
//!
//! ```text
//! header   magic "SHKCORP\0" ‖ version u8 ‖ reserved[7] = 0 ‖ first_height u64
//! extend   0x01 ‖ height u64 ‖ block_len u32 ‖ block ‖ tx_count u32 ‖ (tx_len u32 ‖ body)*
//! rewind   0x02 ‖ to u64
//! trailer  0xFF ‖ count u64 ‖ tip_hash[32]
//! ```
//!
//! `count` is records of both kinds; `tip_hash` is the hash at the lineage's
//! tip after the last record. An `Extend`'s height is the lineage's next
//! (`first_height` at the start, `to + 1` after a `Rewind`); a `Rewind`'s
//! `to` lies in `[first_height, tip)` — a rewind to the current tip is a
//! no-op the format refuses ([`CorpusFault::RewindNotBackward`]), and one
//! below the first height would leave the next block's `previous`
//! unverifiable ([`CorpusFault::RewindOutOfCorpus`]). Writer and reader
//! keep the **lineage** — every height's hash since `first_height`,
//! truncated by a rewind — so chaining is re-established across a switch
//! exactly as within a straight run.
//!
//! # Verified, never declared (RD-F15)
//!
//! A pruned node answers `/get_blocks_by_height.bin` with a block whose
//! header lists more transactions than the bodies it returns, and no
//! signal. So there is no "unpruned" field in this format: the property is
//! **re-established on every record, by writer and reader alike** —
//! parse the block, parse each body, require the count, the order and the
//! hashes to match the header's list, and require each block's `previous`
//! to be the prior record's hash. A record that fails is refused **naming
//! the height** ([`CorpusFault::Incomplete`], [`CorpusFault::WrongBody`],
//! [`CorpusFault::Unchained`]); an artifact the reader cannot re-verify is
//! refused whatever its writer believed.
//!
//! # Checkpoints under reorgs
//!
//! The trace keys checkpoints by height and the pipeline compares the
//! first time a height is the tip. A reorg corpus whose checkpoint height
//! was reached before the switch would compare the wrong chain; a C++
//! trace cannot do this (RD-F16: tip-only, after every reorg) and a fixture
//! puts its checkpoint beyond every pre-switch tip. Digests **after each
//! switch** are the pipeline's own record (`RunReport::switches`), not
//! trace checkpoints.

use std::io::{self, BufRead, Read, Write};

use shekyl_chain_rules::Candidate;
use shekyl_types::{BlockHash, BlockHeight};
use shekyl_wire::{Block, Transaction};

use crate::source::{CorpusBlock, IngestEvent, Seq, Sequenced, Source};

/// The file's first eight bytes.
pub const CORPUS_MAGIC: [u8; 8] = *b"SHKCORP\0";
/// The layout this module reads and writes. Any change to the field set,
/// order or widths bumps it; a reader refuses every other value.
pub const CORPUS_VERSION: u8 = 0x00;

/// Record tags.
mod tag {
    pub const EXTEND: u8 = 0x01;
    pub const REWIND: u8 = 0x02;
    pub const TRAILER: u8 = 0xFF;
}

const HEADER_LEN: usize = 8 + 1 + 7 + 8;
const RESERVED_LEN: usize = 7;

/// Why a corpus could not be written or read. Every arm that concerns one
/// record names its height.
#[derive(Debug, thiserror::Error)]
pub enum CorpusFault {
    /// The underlying reader or writer failed.
    #[error("corpus I/O: {0}")]
    Io(#[from] io::Error),
    /// The file does not start with [`CORPUS_MAGIC`].
    #[error("not a corpus: bad magic")]
    BadMagic,
    /// A version this reader does not know.
    #[error("corpus version {found} is not {CORPUS_VERSION}")]
    UnsupportedVersion {
        /// The version byte found.
        found: u8,
    },
    /// The reserved header bytes are not zero.
    #[error("corpus header reserved bytes are not zero")]
    ReservedNonZero,
    /// A record tag this reader does not know.
    #[error("unknown record tag {0:#04x}")]
    UnknownTag(u8),
    /// A `Rewind` to the tip or above it: nothing to pop.
    #[error("rewind to {to} is not backward from tip {tip}")]
    RewindNotBackward {
        /// Where the rewind wanted the tip.
        to: u64,
        /// Where the tip was.
        tip: u64,
    },
    /// A `Rewind` below the corpus's first height: the block the next
    /// `Extend` chains to is not in the corpus, so it cannot be verified.
    #[error("rewind to {to} is below the corpus's first height {first_height}")]
    RewindOutOfCorpus {
        /// Where the rewind wanted the tip.
        to: u64,
        /// The corpus's first height.
        first_height: u64,
    },
    /// A `Rewind` before any `Extend`: there is no tip.
    #[error("rewind before any block")]
    RewindOnEmpty,
    /// Records must be consecutive from the first height.
    #[error("height gap: expected {expected}, found {found}")]
    HeightGap {
        /// The height the next record had to carry.
        expected: u64,
        /// The height it carried.
        found: u64,
    },
    /// The block bytes at `height` are not one block.
    #[error("height {height}: block does not parse: {cause}")]
    BlockUnparseable {
        /// The record's height.
        height: u64,
        /// The parser's reason.
        cause: io::Error,
    },
    /// Body `index` at `height` is not one transaction.
    #[error("height {height}: body {index} does not parse: {cause}")]
    BodyUnparseable {
        /// The record's height.
        height: u64,
        /// The body's position in the record.
        index: usize,
        /// The parser's reason.
        cause: io::Error,
    },
    /// The record carries a different number of bodies than the header
    /// lists — a pruned source's signature (RD-F15).
    #[error(
        "height {height}: the header lists {listed} transactions, the record carries {carried} \
         bodies (a pruned source returns fewer than the header lists and does not say so)"
    )]
    Incomplete {
        /// The record's height.
        height: u64,
        /// `block.transaction_hashes.len()`.
        listed: usize,
        /// Bodies in the record.
        carried: usize,
    },
    /// Body `index` at `height` hashes to something other than the header's
    /// `index`-th listed hash — a reorder or a substitution.
    #[error("height {height}: body {index} is not the transaction the header lists there")]
    WrongBody {
        /// The record's height.
        height: u64,
        /// The body's position.
        index: usize,
    },
    /// The block's `previous` is not the prior record's hash (or, at
    /// height 0, not the null hash).
    #[error("height {height}: the block's previous hash is not the prior record's")]
    Unchained {
        /// The record's height.
        height: u64,
    },
    /// The trailer's count or tip hash disagrees with the records read.
    #[error("corpus trailer disagrees with the records: {what}")]
    TrailerMismatch {
        /// Which field.
        what: &'static str,
    },
    /// The file ended without a trailer.
    #[error("corpus is truncated after {records} record(s): no trailer")]
    Truncated {
        /// Records read before the end.
        records: u64,
    },
    /// A length field exceeds what a record may carry.
    #[error("height {height}: a length field ({len}) is not representable")]
    LengthOutOfRange {
        /// The record's height.
        height: u64,
        /// The offending length.
        len: u64,
    },
}

/// One record, verified: the parsed block and its bodies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRecord {
    /// The record's height.
    pub height: BlockHeight,
    /// The block.
    pub block: Block,
    /// Its listed transactions' bodies, in header order.
    pub transactions: Vec<Transaction>,
}

impl VerifiedRecord {
    /// This block's hash — the next record's `previous`.
    #[must_use]
    pub fn hash(&self) -> BlockHash {
        self.block.hash()
    }

    /// As the pipeline consumes it.
    #[must_use]
    pub fn into_corpus_block(self) -> CorpusBlock {
        CorpusBlock {
            height: self.height,
            candidate: Candidate::new(self.block, self.transactions),
        }
    }
}

/// The one verification, shared by the writer and the reader (module docs).
/// `previous` is the prior record's hash; `None` for the first record,
/// which is chained only when it is genesis (`previous == NULL`).
fn verify(
    height: u64,
    block_bytes: &[u8],
    bodies: &[Vec<u8>],
    previous: Option<BlockHash>,
) -> Result<VerifiedRecord, CorpusFault> {
    let block = Block::from_bytes(block_bytes)
        .map_err(|cause| CorpusFault::BlockUnparseable { height, cause })?;
    let listed = block.transaction_hashes.len();
    if bodies.len() != listed {
        return Err(CorpusFault::Incomplete {
            height,
            listed,
            carried: bodies.len(),
        });
    }
    let mut transactions = Vec::with_capacity(listed);
    for (index, body) in bodies.iter().enumerate() {
        let tx = Transaction::from_bytes(body).map_err(|cause| CorpusFault::BodyUnparseable {
            height,
            index,
            cause,
        })?;
        if tx.hash() != block.transaction_hashes[index] {
            return Err(CorpusFault::WrongBody { height, index });
        }
        transactions.push(tx);
    }
    let chained = match previous {
        Some(prev) => block.header.previous == prev,
        None => height != 0 || block.header.previous == BlockHash::NULL,
    };
    if !chained {
        return Err(CorpusFault::Unchained { height });
    }
    Ok(VerifiedRecord {
        height: BlockHeight::from_raw(height),
        block,
        transactions,
    })
}

fn u32_len(height: u64, len: usize) -> Result<u32, CorpusFault> {
    u32::try_from(len).map_err(|_| CorpusFault::LengthOutOfRange {
        height,
        len: len as u64,
    })
}

// ---------------------------------------------------------------------------
// Lineage — shared by writer and reader
// ---------------------------------------------------------------------------

/// Every height's hash since `first_height`, as the records so far leave
/// it. The one place the two ends of the format agree on what "next" and
/// "previous" mean across a rewind.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Lineage {
    first_height: u64,
    hashes: Vec<BlockHash>,
}

impl Lineage {
    const fn new(first_height: u64) -> Self {
        Self {
            first_height,
            hashes: Vec::new(),
        }
    }

    /// The height the next `Extend` must carry.
    fn next_height(&self) -> u64 {
        self.first_height
            .checked_add(self.hashes.len() as u64)
            .expect("height fits u64")
    }

    /// The tip's hash — the next `Extend`'s `previous`.
    fn previous(&self) -> Option<BlockHash> {
        self.hashes.last().copied()
    }

    fn extend(&mut self, hash: BlockHash) {
        self.hashes.push(hash);
    }

    /// Apply `Rewind { to }`, checking it is backward and in the corpus.
    fn rewind(&mut self, to: u64) -> Result<(), CorpusFault> {
        if self.hashes.is_empty() {
            return Err(CorpusFault::RewindOnEmpty);
        }
        let tip = self.next_height() - 1;
        if to >= tip {
            return Err(CorpusFault::RewindNotBackward { to, tip });
        }
        if to < self.first_height {
            return Err(CorpusFault::RewindOutOfCorpus {
                to,
                first_height: self.first_height,
            });
        }
        let keep = usize::try_from(to - self.first_height + 1).expect("fits: bounded by len");
        self.hashes.truncate(keep);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// Writes a corpus, verifying every record before it lands.
#[derive(Debug)]
pub struct CorpusWriter<W: Write> {
    out: W,
    lineage: Lineage,
    count: u64,
}

impl<W: Write> CorpusWriter<W> {
    /// Start a corpus whose first record is `first_height`; writes the
    /// header.
    ///
    /// # Errors
    ///
    /// I/O.
    pub fn new(mut out: W, first_height: BlockHeight) -> Result<Self, CorpusFault> {
        out.write_all(&CORPUS_MAGIC)?;
        out.write_all(&[CORPUS_VERSION])?;
        out.write_all(&[0u8; RESERVED_LEN])?;
        out.write_all(&first_height.to_raw().to_le_bytes())?;
        Ok(Self {
            out,
            lineage: Lineage::new(first_height.to_raw()),
            count: 0,
        })
    }

    /// Append `Rewind { to }`: the reader will pop to `to` and expect the
    /// next block at `to + 1`, chained to the block at `to`.
    ///
    /// # Errors
    ///
    /// [`CorpusFault::RewindNotBackward`], [`CorpusFault::RewindOutOfCorpus`],
    /// [`CorpusFault::RewindOnEmpty`]; I/O.
    pub fn rewind(&mut self, to: BlockHeight) -> Result<(), CorpusFault> {
        self.lineage.rewind(to.to_raw())?;
        self.out.write_all(&[tag::REWIND])?;
        self.out.write_all(&to.to_raw().to_le_bytes())?;
        self.count += 1;
        Ok(())
    }

    /// Verify and write the next record: `block_bytes` and its `bodies` as
    /// the network carried them (RD-F15's check runs here first).
    ///
    /// # Errors
    ///
    /// Any [`CorpusFault`] the verification names; I/O.
    pub fn push(
        &mut self,
        block_bytes: &[u8],
        bodies: &[Vec<u8>],
    ) -> Result<BlockHash, CorpusFault> {
        let height = self.lineage.next_height();
        let record = verify(height, block_bytes, bodies, self.lineage.previous())?;
        let hash = record.hash();
        self.out.write_all(&[tag::EXTEND])?;
        self.out.write_all(&height.to_le_bytes())?;
        self.out
            .write_all(&u32_len(height, block_bytes.len())?.to_le_bytes())?;
        self.out.write_all(block_bytes)?;
        self.out
            .write_all(&u32_len(height, bodies.len())?.to_le_bytes())?;
        for body in bodies {
            self.out
                .write_all(&u32_len(height, body.len())?.to_le_bytes())?;
            self.out.write_all(body)?;
        }
        self.lineage.extend(hash);
        self.count += 1;
        Ok(hash)
    }

    /// Write the trailer and hand the sink back.
    ///
    /// # Errors
    ///
    /// I/O.
    pub fn finish(mut self) -> Result<W, CorpusFault> {
        self.out.write_all(&[tag::TRAILER])?;
        self.out.write_all(&self.count.to_le_bytes())?;
        let tip = self.lineage.previous().unwrap_or(BlockHash::NULL);
        self.out.write_all(tip.as_bytes())?;
        self.out.flush()?;
        Ok(self.out)
    }

    /// Records written so far.
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// Reads a corpus, re-verifying every record, and is the pipeline's
/// corpus [`Source`] (Extend-only; sequence numbers from [`Seq::FIRST`]).
#[derive(Debug)]
pub struct CorpusReader<R: BufRead> {
    input: R,
    lineage: Lineage,
    count: u64,
    seq: Seq,
    done: bool,
}

/// One verified record, either kind.
#[derive(Debug)]
pub enum CorpusRecord {
    /// A block, verified and chained. Boxed for the same reason
    /// `IngestEvent::Extend` is: a rewind is eight bytes.
    Extend(Box<VerifiedRecord>),
    /// Pop to `to`.
    Rewind(BlockHeight),
}

fn read_exact<R: Read, const N: usize>(r: &mut R) -> Result<Option<[u8; N]>, io::Error> {
    let mut buf = [0u8; N];
    match r.read_exact(&mut buf) {
        Ok(()) => Ok(Some(buf)),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(e),
    }
}

fn read_u32<R: Read>(r: &mut R) -> Result<u32, io::Error> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64<R: Read>(r: &mut R) -> Result<u64, io::Error> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

fn read_vec<R: Read>(r: &mut R, len: usize) -> Result<Vec<u8>, io::Error> {
    let mut v = vec![0u8; len];
    r.read_exact(&mut v)?;
    Ok(v)
}

impl<R: BufRead> CorpusReader<R> {
    /// Open a corpus: reads and checks the header.
    ///
    /// # Errors
    ///
    /// [`CorpusFault::BadMagic`], [`CorpusFault::UnsupportedVersion`],
    /// [`CorpusFault::ReservedNonZero`]; I/O.
    pub fn open(mut input: R) -> Result<Self, CorpusFault> {
        let mut header = [0u8; HEADER_LEN];
        input.read_exact(&mut header)?;
        if header[..8] != CORPUS_MAGIC {
            return Err(CorpusFault::BadMagic);
        }
        if header[8] != CORPUS_VERSION {
            return Err(CorpusFault::UnsupportedVersion { found: header[8] });
        }
        if header[9..16].iter().any(|&b| b != 0) {
            return Err(CorpusFault::ReservedNonZero);
        }
        let first = u64::from_le_bytes(header[16..24].try_into().expect("8 bytes"));
        Ok(Self {
            input,
            lineage: Lineage::new(first),
            count: 0,
            seq: Seq::FIRST,
            done: false,
        })
    }

    /// The height the next `Extend` must carry.
    #[must_use]
    pub fn next_height(&self) -> BlockHeight {
        BlockHeight::from_raw(self.lineage.next_height())
    }

    /// The next verified record, `None` once the trailer has been read and
    /// checked.
    ///
    /// # Errors
    ///
    /// Any [`CorpusFault`]; after an error the reader is exhausted.
    pub fn next_record(&mut self) -> Result<Option<CorpusRecord>, CorpusFault> {
        if self.done {
            return Ok(None);
        }
        let out = self.read_one();
        if !matches!(out, Ok(Some(_))) {
            self.done = true;
        }
        out
    }

    fn read_one(&mut self) -> Result<Option<CorpusRecord>, CorpusFault> {
        let Some([t]) = read_exact::<_, 1>(&mut self.input)? else {
            return Err(CorpusFault::Truncated {
                records: self.count,
            });
        };
        match t {
            tag::EXTEND => {}
            tag::REWIND => {
                let to = read_u64(&mut self.input)?;
                self.lineage.rewind(to)?;
                self.count += 1;
                return Ok(Some(CorpusRecord::Rewind(BlockHeight::from_raw(to))));
            }
            tag::TRAILER => {
                self.check_trailer()?;
                return Ok(None);
            }
            other => return Err(CorpusFault::UnknownTag(other)),
        }
        let height = read_u64(&mut self.input)?;
        if height != self.lineage.next_height() {
            return Err(CorpusFault::HeightGap {
                expected: self.lineage.next_height(),
                found: height,
            });
        }
        let block_len = read_u32(&mut self.input)? as usize;
        let block_bytes = read_vec(&mut self.input, block_len)?;
        let tx_count = read_u32(&mut self.input)? as usize;
        let mut bodies = Vec::with_capacity(tx_count);
        for _ in 0..tx_count {
            let len = read_u32(&mut self.input)? as usize;
            bodies.push(read_vec(&mut self.input, len)?);
        }
        let record = verify(height, &block_bytes, &bodies, self.lineage.previous())?;
        self.lineage.extend(record.hash());
        self.count += 1;
        Ok(Some(CorpusRecord::Extend(Box::new(record))))
    }

    fn check_trailer(&mut self) -> Result<(), CorpusFault> {
        let count = read_u64(&mut self.input)?;
        let mut tip = [0u8; 32];
        self.input.read_exact(&mut tip)?;
        if count != self.count {
            return Err(CorpusFault::TrailerMismatch { what: "count" });
        }
        let expected = self.lineage.previous().unwrap_or(BlockHash::NULL);
        if BlockHash::from_bytes(tip) != expected {
            return Err(CorpusFault::TrailerMismatch { what: "tip_hash" });
        }
        Ok(())
    }
}

impl<R: BufRead> Source for CorpusReader<R> {
    type Fault = CorpusFault;

    fn next(&mut self) -> Result<Option<Sequenced<IngestEvent>>, Self::Fault> {
        let Some(record) = self.next_record()? else {
            return Ok(None);
        };
        let seq = self.seq;
        self.seq = seq.next();
        let event = match record {
            CorpusRecord::Extend(r) => IngestEvent::Extend(Box::new((*r).into_corpus_block())),
            CorpusRecord::Rewind(to) => IngestEvent::Rewind { to },
        };
        Ok(Some(Sequenced::new(seq, event)))
    }
}
