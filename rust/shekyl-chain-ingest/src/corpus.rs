// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The **corpus**: a chain's blocks with their full transaction bodies, as
//! one versioned artifact — the replay driver's first [`Source`]
//! (`DRS_E2_REPLAY_DRIVER.md` RD-Q2, RD-F8, RD-F15).
//!
//! # Network-shaped only
//!
//! A record is what the validator consumes and nothing else: the block
//! blob and the bodies of its listed transactions in header order —
//! [`Candidate`]'s two fields. No facts, no verdicts, no digests; those are
//! the **trace**'s (RD-Q2), and the two artifacts have different doors into
//! the pipeline so a grader can never read a borrowed fact as evidence.
//!
//! # The format is minted here, not inherited
//!
//! Round 0 defaulted to extending `blockchain_export`'s bootstrap file;
//! that container is Monero's, serialized with epee, and a Rust reader of
//! it would be a second parser of an inherited format (rule 16, RD-F9). So
//! this file: a fixed magic, a version constant, little-endian fixed-width
//! lengths, and one serializer shared by writer and reader. Changing the
//! layout bumps [`CORPUS_FORMAT_VERSION`] and the reader refuses the old
//! number — rebuild the artifact, never migrate it (rule 15).
//!
//! ```text
//! header  = MAGIC(8) ‖ version u32 ‖ net u8 ‖ first_height u64 ‖ count u64
//! record  = height u64 ‖ block_len u32 ‖ block ‖ tx_count u32 ‖ (tx_len u32 ‖ tx)*
//! ```
//!
//! `count` is written at [`CorpusWriter::finish`]; a file whose header
//! count disagrees with its records was not finished and is refused.
//!
//! # Verified, not declared (RD-F15)
//!
//! A pruned RPC source fails **silently**: `/get_blocks_by_height.bin`
//! returns a block with fewer bodies than its header lists and no flag
//! (`BlockEntry { block, txs }`; the handler drops `missed`). So the writer
//! does not record what the source *said* about pruning — it parses the
//! block and requires the bodies to match `block.transaction_hashes` in
//! **count, order and hash** before a height is written; a shortfall is
//! [`CorpusFault::IncompleteBodies`] naming the height. The reader
//! re-derives the same check on every record it yields, so an artifact
//! edited after writing is refused for the same reason. Completeness is a
//! property the artifact demonstrates on read, never a byte it asserts.
//!
//! # What the corpus's `net` tag is, and is not
//!
//! [`CorpusNet`] is the artifact's own tag with **four** arms, including
//! `Fakechain` — `shekyl_address::Network` has three and no regtest witness
//! (slice 2 F10, still owed). The tag says what chain the blocks came from
//! so the driver can pick a schedule; it is not a `Network` and does not
//! pretend to be one.

use std::io::{self, BufRead, Read, Seek, SeekFrom, Write};

use shekyl_chain_rules::Candidate;
use shekyl_types::{BlockCount, BlockHeight, TxHash};
use shekyl_wire::block::MAX_BLOCK_BLOB_SIZE;
use shekyl_wire::transaction::MAX_TX_SIZE;
use shekyl_wire::{Block, Transaction};

use crate::source::{IngestEvent, SequenceNo, Sequenced, Source};

/// The artifact's magic: eight bytes no other Shekyl artifact starts with.
pub const CORPUS_MAGIC: [u8; 8] = *b"SHKCORPS";

/// The layout version this module writes and the only one it reads.
/// A layout change bumps it; the reader refuses every other value.
pub const CORPUS_FORMAT_VERSION: u32 = 1;

/// Which chain the corpus was taken from — the artifact's own tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CorpusNet {
    /// The public main network.
    Mainnet = 0,
    /// The public test network.
    Testnet = 1,
    /// The public stage network.
    Stagenet = 2,
    /// A single-operator regtest chain (`--regtest`); the one nettype whose
    /// rule set may carry a fixed difficulty (RD-Q7).
    Fakechain = 3,
}

impl CorpusNet {
    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Mainnet),
            1 => Some(Self::Testnet),
            2 => Some(Self::Stagenet),
            3 => Some(Self::Fakechain),
            _ => None,
        }
    }
}

/// Why a corpus could not be written or read.
#[derive(Debug)]
pub enum CorpusFault {
    /// The bytes do not start with [`CORPUS_MAGIC`].
    BadMagic,
    /// The header names a layout this module does not read.
    UnsupportedVersion {
        /// What the header said.
        found: u32,
    },
    /// The header's network tag is none of [`CorpusNet`]'s arms.
    UnknownNet(u8),
    /// A block arrived with fewer (or more) bodies than its header lists.
    /// **The pruned-source signature** (RD-F15): a pruned node drops bodies
    /// silently, so this is how it is caught.
    IncompleteBodies {
        /// The block's height.
        height: BlockHeight,
        /// How many the header lists.
        listed: usize,
        /// How many bodies were present.
        present: usize,
    },
    /// The body at `index` does not hash to the header's `index`th listed
    /// transaction — wrong order, wrong transaction, or a tampered record.
    BodyMismatch {
        /// The block's height.
        height: BlockHeight,
        /// Position in the header's list.
        index: usize,
        /// What the header lists there.
        listed: TxHash,
        /// What the body hashes to.
        present: TxHash,
    },
    /// Records must be contiguous and ascending from the header's
    /// `first_height`.
    HeightGap {
        /// The height the next record had to carry.
        expected: BlockHeight,
        /// The height it carried.
        found: BlockHeight,
    },
    /// The next record would need a height past `u64::MAX`. Not a
    /// representable chain; refused before anything is written or read, so
    /// a header claiming `first_height = u64::MAX` with two records is
    /// refused at `open`, and a writer at the last height refuses the next
    /// `append` with no record landed.
    HeightExhausted {
        /// The last height this corpus can carry.
        after: BlockHeight,
    },
    /// A length prefix exceeds the wire's own cap; the record is not a
    /// block or a transaction.
    Oversized {
        /// Which field.
        what: &'static str,
        /// The length claimed.
        len: u64,
    },
    /// A block or transaction blob did not parse under `shekyl-wire`.
    Malformed {
        /// The record's height.
        height: BlockHeight,
        /// What failed to parse.
        what: &'static str,
        /// The parser's error.
        cause: io::Error,
    },
    /// The header's `count` disagrees with the records present: the file
    /// was not finished, or was truncated.
    CountMismatch {
        /// What the header said.
        declared: u64,
        /// How many records were read.
        present: u64,
    },
    /// An I/O failure on the underlying reader or writer.
    Io(io::Error),
}

impl core::fmt::Display for CorpusFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadMagic => f.write_str("not a Shekyl corpus (bad magic)"),
            Self::UnsupportedVersion { found } => write!(
                f,
                "corpus layout version {found} is not {CORPUS_FORMAT_VERSION}; rebuild the artifact"
            ),
            Self::UnknownNet(tag) => write!(f, "corpus network tag {tag} is not a known chain"),
            Self::IncompleteBodies {
                height,
                listed,
                present,
            } => write!(
                f,
                "block {height}: header lists {listed} transactions, {present} bodies present — \
                 a pruned source, or a truncated record"
            ),
            Self::BodyMismatch {
                height,
                index,
                listed,
                present,
            } => write!(
                f,
                "block {height}: body {index} hashes to {present:?}, header lists {listed:?}"
            ),
            Self::HeightExhausted { after } => write!(
                f,
                "no height follows {after}; the corpus cannot carry another record"
            ),
            Self::HeightGap { expected, found } => {
                write!(
                    f,
                    "records are not contiguous: expected {expected}, found {found}"
                )
            }
            Self::Oversized { what, len } => {
                write!(f, "{what} length {len} exceeds the wire cap; not a {what}")
            }
            Self::Malformed {
                height,
                what,
                cause,
            } => write!(f, "block {height}: {what} does not parse: {cause}"),
            Self::CountMismatch { declared, present } => write!(
                f,
                "header declares {declared} records, {present} present; the corpus was not finished"
            ),
            Self::Io(e) => write!(f, "corpus i/o: {e}"),
        }
    }
}

impl core::error::Error for CorpusFault {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Io(e) | Self::Malformed { cause: e, .. } => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for CorpusFault {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

fn parse_block(height: BlockHeight, blob: &[u8]) -> Result<Block, CorpusFault> {
    // Complete length-delimited blob: exact consumption (§12). `read` would
    // drop trailing bytes inside the prefix and store them as if verified.
    Block::from_bytes(blob).map_err(|cause| CorpusFault::Malformed {
        height,
        what: "block",
        cause,
    })
}

fn parse_tx(height: BlockHeight, blob: &[u8]) -> Result<Transaction, CorpusFault> {
    Transaction::from_bytes(blob).map_err(|cause| CorpusFault::Malformed {
        height,
        what: "transaction",
        cause,
    })
}

/// One listed body, hashed against the header's `index`th hash (RD-F15).
fn verified_tx(
    height: BlockHeight,
    index: usize,
    want: TxHash,
    blob: &[u8],
) -> Result<Transaction, CorpusFault> {
    let tx = parse_tx(height, blob)?;
    let got = tx.hash();
    if got != want {
        return Err(CorpusFault::BodyMismatch {
            height,
            index,
            listed: want,
            present: got,
        });
    }
    Ok(tx)
}

/// The check the writer runs before a height is written: the bodies match
/// the header's list in count, order and hash (RD-F15). Returns the parsed
/// block and bodies as the [`Candidate`] the validator consumes.
fn verified_candidate(
    height: BlockHeight,
    block_blob: &[u8],
    tx_blobs: &[Vec<u8>],
) -> Result<Candidate, CorpusFault> {
    let block = parse_block(height, block_blob)?;
    let listed = block.transaction_hashes.len();
    if tx_blobs.len() != listed {
        return Err(CorpusFault::IncompleteBodies {
            height,
            listed,
            present: tx_blobs.len(),
        });
    }
    let mut transactions = Vec::with_capacity(listed);
    for (index, (blob, want)) in tx_blobs.iter().zip(&block.transaction_hashes).enumerate() {
        transactions.push(verified_tx(height, index, *want, blob)?);
    }
    Ok(Candidate::new(block, transactions))
}

/// The next height a contiguous corpus records, or `None` past `u64::MAX`.
/// Exhausting the height space is not a representable chain; saturating
/// would write the same height twice, and panicking would let a crafted
/// header (`first_height = u64::MAX`) take the reader down after one valid
/// record. `None` is carried as [`CorpusFault::HeightExhausted`] by whoever
/// needed the successor, before it writes or reads anything.
fn successor(height: BlockHeight) -> Option<BlockHeight> {
    height.checked_add(BlockCount::ONE)
}

/// Byte offset of the header's `count` field: `MAGIC(8) ‖ version(4) ‖ net(1) ‖ first_height(8)`.
const COUNT_OFFSET: u64 = 8 + 4 + 1 + 8;

/// Writes a corpus, verifying every record before it lands (RD-F15).
///
/// `finish` consumes the writer and patches the header count, so "append
/// after finish" is unrepresentable — there is no finished flag.
pub struct CorpusWriter<W: Write + Seek> {
    out: W,
    /// The height the next `append` records; `None` once `u64::MAX` has
    /// been written.
    next: Option<BlockHeight>,
    count: u64,
}

impl<W: Write + Seek> CorpusWriter<W> {
    /// Start a corpus for `net` whose first record is at `first_height`.
    /// Writes the header with a zero count; [`finish`](Self::finish) fills
    /// it in.
    ///
    /// # Errors
    ///
    /// I/O.
    pub fn create(
        mut out: W,
        net: CorpusNet,
        first_height: BlockHeight,
    ) -> Result<Self, CorpusFault> {
        out.write_all(&CORPUS_MAGIC)?;
        out.write_all(&CORPUS_FORMAT_VERSION.to_le_bytes())?;
        out.write_all(&[net as u8])?;
        out.write_all(&first_height.to_raw().to_le_bytes())?;
        out.write_all(&0u64.to_le_bytes())?;
        Ok(Self {
            out,
            next: Some(first_height),
            count: 0,
        })
    }

    /// Append the block at the next height with the bodies of its listed
    /// transactions, **as the source handed them** — this method does the
    /// verifying. A shortfall, a reorder or a foreign body is refused by
    /// height and nothing is written for it.
    ///
    /// # Errors
    ///
    /// [`CorpusFault::IncompleteBodies`] / [`CorpusFault::BodyMismatch`] /
    /// [`CorpusFault::Malformed`] for the record; [`CorpusFault::Oversized`]
    /// if a blob exceeds the wire cap; I/O.
    pub fn append(&mut self, block_blob: &[u8], tx_blobs: &[Vec<u8>]) -> Result<(), CorpusFault> {
        let height = self.next.ok_or(CorpusFault::HeightExhausted {
            after: BlockHeight::from_raw(u64::MAX),
        })?;
        verified_candidate(height, block_blob, tx_blobs)?;
        // One buffer, one write: a verify failure writes nothing, and an
        // I/O error cannot leave a torn prefix the next append would
        // continue after.
        let record = encode_record(height, block_blob, tx_blobs)?;
        self.out.write_all(&record)?;
        self.next = successor(height);
        // `count` cannot outrun the height space: every record occupies one
        // height, so `count ≤ u64::MAX − first_height + 1` fits.
        self.count = self
            .count
            .checked_add(1)
            .expect("corpus record count exhausted");
        Ok(())
    }

    /// Patch the record count into the header and hand the writer back.
    /// Consumes the writer: there is no append-after-finish.
    ///
    /// # Errors
    ///
    /// I/O.
    pub fn finish(mut self) -> Result<W, CorpusFault> {
        self.out.seek(SeekFrom::Start(COUNT_OFFSET))?;
        self.out.write_all(&self.count.to_le_bytes())?;
        self.out.seek(SeekFrom::End(0))?;
        self.out.flush()?;
        Ok(self.out)
    }
}

/// One record as the on-disk layout: `height ‖ block_len ‖ block ‖ tx_count ‖ (tx_len ‖ tx)*`.
fn encode_record(
    height: BlockHeight,
    block_blob: &[u8],
    tx_blobs: &[Vec<u8>],
) -> Result<Vec<u8>, CorpusFault> {
    let mut buf = Vec::new();
    write_len(
        &mut buf,
        "block",
        block_blob.len(),
        MAX_BLOCK_BLOB_SIZE,
        height.to_raw(),
    )?;
    buf.write_all(block_blob)?;
    let tx_count = u32::try_from(tx_blobs.len()).map_err(|_| CorpusFault::Oversized {
        what: "transaction count",
        len: tx_blobs.len() as u64,
    })?;
    buf.write_all(&tx_count.to_le_bytes())?;
    for blob in tx_blobs {
        write_len_only(&mut buf, "transaction", blob.len(), MAX_TX_SIZE)?;
        buf.write_all(blob)?;
    }
    Ok(buf)
}

/// `height u64 ‖ len u32` for a block record.
fn write_len<W: Write>(
    out: &mut W,
    what: &'static str,
    len: usize,
    cap: usize,
    height: u64,
) -> Result<(), CorpusFault> {
    out.write_all(&height.to_le_bytes())?;
    write_len_only(out, what, len, cap)
}

fn write_len_only<W: Write>(
    out: &mut W,
    what: &'static str,
    len: usize,
    cap: usize,
) -> Result<(), CorpusFault> {
    if len > cap {
        return Err(CorpusFault::Oversized {
            what,
            len: len as u64,
        });
    }
    let len = u32::try_from(len).map_err(|_| CorpusFault::Oversized {
        what,
        len: len as u64,
    })?;
    out.write_all(&len.to_le_bytes())?;
    Ok(())
}

/// Reads a corpus as an Extend-only [`Source`], re-verifying every record.
pub struct CorpusReader<R: BufRead> {
    input: R,
    net: CorpusNet,
    /// The height the next record must carry; `None` once `u64::MAX` has
    /// been read (a header that needs more is refused at `open`).
    next: Option<BlockHeight>,
    declared: u64,
    read: u64,
    seq: SequenceNo,
}

impl<R: BufRead> CorpusReader<R> {
    /// Open a corpus: refuses a bad magic, a foreign layout version, or an
    /// unknown network tag before yielding anything.
    ///
    /// # Errors
    ///
    /// [`CorpusFault::BadMagic`], [`CorpusFault::UnsupportedVersion`],
    /// [`CorpusFault::UnknownNet`]; I/O.
    pub fn open(mut input: R) -> Result<Self, CorpusFault> {
        let mut magic = [0u8; 8];
        input.read_exact(&mut magic)?;
        if magic != CORPUS_MAGIC {
            return Err(CorpusFault::BadMagic);
        }
        let version = read_u32(&mut input)?;
        if version != CORPUS_FORMAT_VERSION {
            return Err(CorpusFault::UnsupportedVersion { found: version });
        }
        let mut tag = [0u8; 1];
        input.read_exact(&mut tag)?;
        let net = CorpusNet::from_tag(tag[0]).ok_or(CorpusFault::UnknownNet(tag[0]))?;
        let first = BlockHeight::from_raw(read_u64(&mut input)?);
        let declared = read_u64(&mut input)?;
        // The header's own arithmetic must fit: `declared` records from
        // `first` occupy `first ..= first + declared − 1`. A header that
        // claims more than the height space holds is refused here, before
        // any record is read, rather than after the last representable one.
        if let Some(span) = declared.checked_sub(1) {
            if first.to_raw().checked_add(span).is_none() {
                return Err(CorpusFault::HeightExhausted {
                    after: BlockHeight::from_raw(u64::MAX),
                });
            }
        }
        Ok(Self {
            input,
            net,
            next: Some(first),
            declared,
            read: 0,
            seq: SequenceNo::FIRST,
        })
    }

    /// The chain the corpus was taken from.
    #[must_use]
    pub const fn net(&self) -> CorpusNet {
        self.net
    }

    /// The header's record count.
    #[must_use]
    pub const fn declared(&self) -> u64 {
        self.declared
    }

    /// One record, re-verified, or `None` at the declared end. Refuses a
    /// record count that disagrees with the header.
    fn record(&mut self) -> Result<Option<Candidate>, CorpusFault> {
        if self.read == self.declared {
            // The declared end. Anything past it is a count mismatch: read
            // one byte to tell "clean EOF" from "more records".
            let mut probe = [0u8; 1];
            return match self.input.read(&mut probe)? {
                0 => Ok(None),
                _ => Err(CorpusFault::CountMismatch {
                    declared: self.declared,
                    present: self.declared.saturating_add(1),
                }),
            };
        }
        let height = match read_u64(&mut self.input) {
            Ok(h) => BlockHeight::from_raw(h),
            Err(CorpusFault::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(CorpusFault::CountMismatch {
                    declared: self.declared,
                    present: self.read,
                });
            }
            Err(e) => return Err(e),
        };
        let expected = self.next.ok_or(CorpusFault::HeightExhausted {
            after: BlockHeight::from_raw(u64::MAX),
        })?;
        if height != expected {
            return Err(CorpusFault::HeightGap {
                expected,
                found: height,
            });
        }
        let block_blob = read_blob(&mut self.input, "block", MAX_BLOCK_BLOB_SIZE)?;
        // The header is the bound: parse it before trusting the file's
        // `tx_count`. `Block::read` caps the hash list at `READ_LEN_CAP`
        // and does not pre-allocate against it; a crafted `tx_count =
        // u32::MAX` must not `Vec::with_capacity` before this check.
        let block = parse_block(height, &block_blob)?;
        let listed = block.transaction_hashes.len();
        let claimed = read_u32(&mut self.input)? as usize;
        if claimed != listed {
            return Err(CorpusFault::IncompleteBodies {
                height,
                listed,
                present: claimed,
            });
        }
        let mut transactions = Vec::with_capacity(listed);
        for (index, want) in block.transaction_hashes.iter().enumerate() {
            let blob = read_blob(&mut self.input, "transaction", MAX_TX_SIZE)?;
            transactions.push(verified_tx(height, index, *want, &blob)?);
        }
        self.next = successor(height);
        // Bounded by `declared`, which `open` proved fits the height space.
        self.read = self
            .read
            .checked_add(1)
            .expect("corpus record count exhausted");
        Ok(Some(Candidate::new(block, transactions)))
    }
}

impl<R: BufRead> Source for CorpusReader<R> {
    type Fault = CorpusFault;

    fn next(&mut self) -> Result<Option<Sequenced<IngestEvent>>, CorpusFault> {
        Ok(self.record()?.map(|candidate| {
            let seq = self.seq;
            self.seq = seq.next();
            Sequenced {
                seq,
                event: IngestEvent::Extend(Box::new(candidate)),
            }
        }))
    }
}

fn read_u32<R: Read>(r: &mut R) -> Result<u32, CorpusFault> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64<R: Read>(r: &mut R) -> Result<u64, CorpusFault> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

fn read_blob<R: Read>(r: &mut R, what: &'static str, cap: usize) -> Result<Vec<u8>, CorpusFault> {
    let len = read_u32(r)? as usize;
    if len > cap {
        return Err(CorpusFault::Oversized {
            what,
            len: len as u64,
        });
    }
    let mut blob = vec![0u8; len];
    r.read_exact(&mut blob)?;
    Ok(blob)
}

#[cfg(test)]
#[path = "corpus_tests.rs"]
mod corpus_tests;
