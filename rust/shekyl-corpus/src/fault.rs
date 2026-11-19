// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Every refusal of the corpus codec, by name.
//!
//! A writer returns one before it lands a record. A reader returns the
//! same one when it re-derives the check. I/O is [`CorpusFault::Io`].

use std::io;

use shekyl_types::{BlockHeight, TxHash};

use crate::CORPUS_FORMAT_VERSION;

/// Why a corpus could not be written or read.
#[derive(Debug)]
pub enum CorpusFault {
    /// The bytes do not start with [`crate::CORPUS_MAGIC`].
    BadMagic,
    /// A block's bundle section is not one: its references do not form a
    /// section, or a body is missing or is not its reference's.
    BadSection {
        /// The block's height.
        height: BlockHeight,
    },
    /// The header names a layout this crate does not read.
    UnsupportedVersion {
        /// What the header said.
        found: u32,
    },
    /// The header's network tag is no network's code.
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
    /// refused at the second, and a writer at the last height refuses the
    /// next `append` with no record landed.
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
    /// A record tag neither `extend` nor `rewind`.
    UnknownTag(u8),
    /// A `rewind` to the tip or above it: nothing to pop.
    RewindNotBackward {
        /// Where the rewind wanted the tip.
        to: BlockHeight,
        /// Where the tip was.
        tip: BlockHeight,
    },
    /// A `rewind` below the corpus's first height.
    RewindOutOfCorpus {
        /// Where the rewind wanted the tip.
        to: BlockHeight,
        /// The corpus's first height.
        first_height: BlockHeight,
    },
    /// A `rewind` before any block: there is no tip.
    RewindOnEmpty,
    /// The header's `count` disagrees with the records present, or the
    /// file ends inside a record: the corpus was not finished, or was
    /// truncated.
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
            Self::BadSection { height } => write!(
                f,
                "the bundle section at height {} is not one: its references or a body do not hold",
                height.to_raw()
            ),
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
            Self::UnknownTag(t) => write!(f, "unknown record tag {t:#04x}"),
            Self::RewindNotBackward { to, tip } => {
                write!(f, "rewind to {to} is not backward from tip {tip}")
            }
            Self::RewindOutOfCorpus { to, first_height } => write!(
                f,
                "rewind to {to} is below the corpus's first height {first_height}"
            ),
            Self::RewindOnEmpty => write!(f, "rewind before any block"),
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
