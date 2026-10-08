// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The archival shard body frame — what `P` serves for `/shard/{k}` and the
//! fetch client reads (`ARCHIVAL_SHARD_FETCH.md`, `SF-D8` amendment
//! 2026-10-08; `SV-D8`).
//!
//! The body is the shard's **archival good** and nothing else: for each
//! in-domain transaction of `[b_k, b_{k+1})` in storage order, its
//! `pqc_auths` segment and its prunable region — the two rows a body store
//! holds (`txs_pqc_auths`, `txs_prunable`) and a pruned node lacks
//! (`SHT-Q1`, `SHT-Q2`). The prefix and base are the skeleton every node
//! keeps, so they travel on no body.
//!
//! ```text
//! version:  u8 = SHARD_FRAME_VERSION
//! tx_count: varint
//! per transaction, range order:
//!   pqc_auth_count: varint
//!   pqc_auths_len:  varint ‖ pqc_auths bytes
//!   prunable_len:   varint ‖ prunable bytes
//! ```
//!
//! No txid, no digest and no shard id are on the wire: order is the
//! range's and identity is the requester's expectation (a [`TxidParts`]
//! per entry, from skeleton rows). Anything `P` could put there would be a
//! claim about the body. The varints are this crate's canonical LEB128
//! ([`crate::varint`]), so the frame has one encoding per content.
//!
//! The codec is shared by both ends (`SF-D4`: shared, not mirrored):
//! [`write_frame`] is the serve side's, [`VarintDecoder`] and
//! [`check_lengths`] / [`check_components`] are what the client's streaming
//! reader drives. The reader itself lives with the transport
//! (`shekyl-p-fetch`), because what is here must stay free of sockets and
//! timeouts; this module is the grammar and the two checks.

use std::io::{self, Write};

use shekyl_types::{ArchivalLength, PqcAuthHash, PrunableHash};

use crate::transaction::{pqc_auth_hash_of, prunable_hash_of, TxidParts};
use crate::varint::write_varint;

/// The frame's leading byte. Bumps when the grammar changes; a reader
/// refuses any other value before reading a length.
pub const SHARD_FRAME_VERSION: u8 = 1;

/// The widest canonical LEB128 `u64`: ten bytes. The bound a streaming
/// reader puts on one varint, and the per-field term of
/// [`frame_len_ceiling`].
pub const MAX_VARINT_LEN: usize = 10;

/// Varints ahead of each entry's bytes: the auth count and the two lengths.
const ENTRY_VARINTS: u64 = 3;

/// One transaction's archival good, as the serve side holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameTx<'a> {
    /// How many authorizations [`Self::pqc_auths`] holds — the count the
    /// retained `txs_pqc_auth_hash` row mixed in ahead of the segment
    /// ([`pqc_auth_hash_of`]). Zero when the segment is empty.
    pub pqc_auth_count: u64,
    /// The tx-level `pqc_auths` segment as stored (`txs_pqc_auths`), with
    /// no count prefix. Empty for a transaction with none.
    pub pqc_auths: &'a [u8],
    /// The prunable region as stored (`txs_prunable`). Empty when absent.
    pub prunable: &'a [u8],
}

/// Write one shard body frame: the version byte, `txs.len()`, and each
/// entry in order.
///
/// # Errors
///
/// Only what `w` raises.
pub fn write_frame<W: Write>(txs: &[FrameTx<'_>], w: &mut W) -> io::Result<()> {
    w.write_all(&[SHARD_FRAME_VERSION])?;
    write_varint(txs.len(), w)?;
    for tx in txs {
        write_varint(tx.pqc_auth_count, w)?;
        write_varint(tx.pqc_auths.len(), w)?;
        w.write_all(tx.pqc_auths)?;
        write_varint(tx.prunable.len(), w)?;
        w.write_all(tx.prunable)?;
    }
    Ok(())
}

/// [`write_frame`] into a fresh `Vec`.
#[must_use]
pub fn encode_frame(txs: &[FrameTx<'_>]) -> Vec<u8> {
    let bytes: usize = txs
        .iter()
        .map(|tx| tx.pqc_auths.len() + tx.prunable.len() + 3 * MAX_VARINT_LEN)
        .sum();
    let mut out = Vec::with_capacity(1 + MAX_VARINT_LEN + bytes);
    write_frame(txs, &mut out).expect("Vec write is infallible");
    out
}

/// The most bytes a well-formed frame over `tx_count` entries whose
/// archival lengths sum to `archival_total` can occupy: the version byte,
/// the count varint, and per entry three varints and the entry's bytes,
/// every varint at its ten-byte maximum. `None` on overflow.
///
/// This is the figure the client's pre-read `content-length` refusal uses
/// (`SF-D6`): the requester knows both inputs from skeleton rows before
/// the dial, so a hostile length is refused from the head. Exactness is
/// the reader's — a frame that does not end where the declared length
/// says is malformed — so a ceiling slack of a few varint widths per
/// entry costs nothing.
#[must_use]
pub fn frame_len_ceiling(tx_count: u64, archival_total: ArchivalLength) -> Option<u64> {
    let varint = u64::try_from(MAX_VARINT_LEN).expect("ten fits u64");
    let per_entry = tx_count.checked_mul(ENTRY_VARINTS.checked_mul(varint)?)?;
    1u64.checked_add(varint)?
        .checked_add(per_entry)?
        .checked_add(archival_total.to_raw())
}

/// A streaming canonical-LEB128 `u64` decoder: feed it the body bytes one
/// at a time until it yields the value. Refuses what [`crate::varint::read_varint`]
/// refuses — a redundant trailing zero, a group whose bits fall off the
/// `u64` — and additionally a varint still unterminated after
/// [`MAX_VARINT_LEN`] bytes, so a reader never waits on an endless
/// continuation.
#[derive(Debug, Default)]
pub struct VarintDecoder {
    value: u64,
    shift: u32,
    bytes: usize,
}

impl VarintDecoder {
    const CONTINUATION: u8 = 0b1000_0000;
    const PAYLOAD: u8 = !Self::CONTINUATION;

    /// A decoder with nothing fed.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed the next byte. `Ok(Some(v))` when the varint terminated on it,
    /// `Ok(None)` when more bytes are needed.
    ///
    /// # Errors
    ///
    /// [`FrameError::Varint`] on a non-canonical, overflowing or over-long
    /// encoding. The decoder is spent after an error.
    pub fn push(&mut self, byte: u8) -> Result<Option<u64>, FrameError> {
        if self.bytes >= MAX_VARINT_LEN {
            return Err(FrameError::Varint(VarintFault::TooLong));
        }
        self.bytes += 1;
        if self.shift != 0 && byte == 0 {
            return Err(FrameError::Varint(VarintFault::NonCanonical));
        }
        let payload = u64::from(byte & Self::PAYLOAD);
        if self.shift >= u64::BITS || (payload << self.shift) >> self.shift != payload {
            return Err(FrameError::Varint(VarintFault::Overflow));
        }
        self.value |= payload << self.shift;
        self.shift += 7;
        if byte & Self::CONTINUATION == Self::CONTINUATION {
            return Ok(None);
        }
        Ok(Some(self.value))
    }
}

/// How a varint on the wire failed to decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VarintFault {
    /// A redundant trailing zero group — the encoding is not canonical.
    NonCanonical,
    /// A group whose bits fall off the `u64`.
    Overflow,
    /// Still unterminated after [`MAX_VARINT_LEN`] bytes.
    TooLong,
}

/// The frame is not the grammar: `P` is not speaking the protocol. Distinct
/// from [`ContentMismatch`], which is a well-formed frame carrying the
/// wrong content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The leading byte is not [`SHARD_FRAME_VERSION`].
    Version(u8),
    /// A varint did not decode.
    Varint(VarintFault),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Version(v) => write!(f, "frame version {v} is not {SHARD_FRAME_VERSION}"),
            Self::Varint(VarintFault::NonCanonical) => {
                f.write_str("frame varint is not canonical (redundant trailing zero)")
            }
            Self::Varint(VarintFault::Overflow) => f.write_str("frame varint overflows u64"),
            Self::Varint(VarintFault::TooLong) => {
                write!(f, "frame varint exceeds {MAX_VARINT_LEN} bytes")
            }
        }
    }
}

impl std::error::Error for FrameError {}

/// Check the leading byte.
///
/// # Errors
///
/// [`FrameError::Version`] unless it is [`SHARD_FRAME_VERSION`].
pub fn check_version(byte: u8) -> Result<(), FrameError> {
    if byte == SHARD_FRAME_VERSION {
        Ok(())
    } else {
        Err(FrameError::Version(byte))
    }
}

/// A well-formed frame whose content is not the shard the requester
/// expected. Every variant names the entry (its index in the range) so a
/// scheduler's log can say which transaction `P` got wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentMismatch {
    /// The frame declares a different number of transactions than the
    /// range holds.
    TxCount {
        /// In-domain transactions in the range.
        expected: u64,
        /// What the frame declared.
        declared: u64,
    },
    /// The entry's two declared lengths do not sum to the retained
    /// `txs_archival_len`, or a `pqc_auths` segment was declared for a
    /// transaction whose retained `txs_pqc_auth_hash` is `None`. Decided
    /// before a segment byte is read.
    Lengths {
        /// Position in the range.
        index: u64,
        /// The retained archival length.
        expected: ArchivalLength,
        /// Declared `pqc_auths` length.
        pqc_auths_len: u64,
        /// Declared prunable length.
        prunable_len: u64,
    },
    /// `pqc_auth_hash_of(count, pqc_auths)` is not the retained row.
    PqcAuthHash {
        /// Position in the range.
        index: u64,
    },
    /// `prunable_hash_of(prunable)` is not the retained row.
    PrunableHash {
        /// Position in the range.
        index: u64,
    },
}

impl std::fmt::Display for ContentMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TxCount { expected, declared } => {
                write!(
                    f,
                    "frame declares {declared} transactions, range holds {expected}"
                )
            }
            Self::Lengths {
                index,
                expected,
                pqc_auths_len,
                prunable_len,
            } => write!(
                f,
                "entry {index}: declared lengths {pqc_auths_len} + {prunable_len} \
                 are not the retained archival length {expected}"
            ),
            Self::PqcAuthHash { index } => {
                write!(
                    f,
                    "entry {index}: pqc_auths segment is not the retained row"
                )
            }
            Self::PrunableHash { index } => {
                write!(f, "entry {index}: prunable region is not the retained row")
            }
        }
    }
}

impl std::error::Error for ContentMismatch {}

/// The pre-read check on one entry: do the declared lengths fit the
/// retained rows? Run **before** reading the segments, so a `P` that
/// declares a length the rows do not allow is refused without the client
/// allocating for it.
///
/// # Errors
///
/// [`ContentMismatch::Lengths`] unless `pqc_auths_len + prunable_len`
/// equals `expected.archival_len`, and `pqc_auths_len == 0` whenever
/// `expected.pqc_auth_hash` is `None` (a transaction the chain hashes
/// 3-part has no `pqc_auths` component to carry).
pub fn check_lengths(
    index: u64,
    expected: &TxidParts,
    pqc_auths_len: u64,
    prunable_len: u64,
) -> Result<(), ContentMismatch> {
    let mismatch = ContentMismatch::Lengths {
        index,
        expected: expected.archival_len,
        pqc_auths_len,
        prunable_len,
    };
    if expected.pqc_auth_hash.is_none() && pqc_auths_len != 0 {
        return Err(mismatch);
    }
    match pqc_auths_len.checked_add(prunable_len) {
        Some(total) if total == expected.archival_len.to_raw() => Ok(()),
        _ => Err(mismatch),
    }
}

/// The content check on one entry whose lengths already passed
/// [`check_lengths`]: the two segments hash to the retained rows.
///
/// `pqc_auth_hash` is checked only when the row is `Some`; a `None` row
/// with an empty segment (which [`check_lengths`] guaranteed) has nothing
/// to compare. The prunable row is always compared — an empty region
/// hashes to [`crate::empty_region_prunable_hash`], which is what the row
/// of a transaction without one holds.
///
/// # Errors
///
/// [`ContentMismatch::PqcAuthHash`] or [`ContentMismatch::PrunableHash`],
/// the first that fails, in that order.
pub fn check_components(
    index: u64,
    expected: &TxidParts,
    pqc_auth_count: u64,
    pqc_auths: &[u8],
    prunable: &[u8],
) -> Result<(), ContentMismatch> {
    if let Some(row) = expected.pqc_auth_hash {
        let count =
            usize::try_from(pqc_auth_count).map_err(|_| ContentMismatch::PqcAuthHash { index })?;
        if pqc_auth_hash_of(count, pqc_auths) != row {
            return Err(ContentMismatch::PqcAuthHash { index });
        }
    }
    if prunable_hash_of(prunable) != expected.prunable_hash {
        return Err(ContentMismatch::PrunableHash { index });
    }
    Ok(())
}

/// The retained rows an entry is checked against, from the components
/// themselves — the serve side of [`check_components`], for fixtures and
/// for a holder deriving its own expectation from bytes it has.
#[must_use]
pub fn rows_of(tx: &FrameTx<'_>) -> (Option<PqcAuthHash>, PrunableHash, ArchivalLength) {
    let pqc_auth_hash = (!tx.pqc_auths.is_empty()).then(|| {
        pqc_auth_hash_of(
            usize::try_from(tx.pqc_auth_count).expect("a count on this host fits usize"),
            tx.pqc_auths,
        )
    });
    let archival_len = ArchivalLength::from_raw(
        u64::try_from(tx.pqc_auths.len() + tx.prunable.len()).expect("a length fits u64"),
    );
    (pqc_auth_hash, prunable_hash_of(tx.prunable), archival_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::varint::read_varint;
    use shekyl_types::TxHash;

    fn parts(tx: &FrameTx<'_>, seed: u8) -> TxidParts {
        let (pqc_auth_hash, prunable_hash, archival_len) = rows_of(tx);
        TxidParts {
            hash: TxHash::from_bytes([seed; 32]),
            pqc_auth_hash,
            prunable_hash,
            archival_len,
        }
    }

    /// `(pqc_auth_count, pqc_auths, prunable)` as decoded.
    type Entry = (u64, Vec<u8>, Vec<u8>);

    fn decode(bytes: &[u8]) -> (u64, Vec<Entry>) {
        let mut cursor = bytes;
        let (version, rest) = cursor.split_first().expect("version byte");
        check_version(*version).expect("version");
        cursor = rest;
        let tx_count: u64 = read_varint(&mut cursor).unwrap();
        let mut entries = Vec::new();
        for _ in 0..tx_count {
            let count: u64 = read_varint(&mut cursor).unwrap();
            let pqc_len: usize = read_varint(&mut cursor).unwrap();
            let (pqc, rest) = cursor.split_at(pqc_len);
            cursor = rest;
            let prunable_len: usize = read_varint(&mut cursor).unwrap();
            let (prunable, rest) = cursor.split_at(prunable_len);
            cursor = rest;
            entries.push((count, pqc.to_vec(), prunable.to_vec()));
        }
        assert!(cursor.is_empty(), "trailing bytes");
        (tx_count, entries)
    }

    #[test]
    fn the_frame_round_trips_and_pins_its_layout() {
        let a = FrameTx {
            pqc_auth_count: 2,
            pqc_auths: &[0xAA; 8],
            prunable: &[1, 2, 3],
        };
        let b = FrameTx {
            pqc_auth_count: 0,
            pqc_auths: &[],
            prunable: &[9; 300],
        };
        let bytes = encode_frame(&[a, b]);
        // version, count, then entry a: count 2, len 8, 8 bytes, len 3, 3 bytes.
        let mut expected = vec![SHARD_FRAME_VERSION, 2, 2, 8];
        expected.extend_from_slice(&[0xAA; 8]);
        expected.push(3);
        expected.extend_from_slice(&[1, 2, 3]);
        // entry b: count 0, len 0, no bytes, len 300 as LEB128 (0xAC 0x02).
        expected.extend_from_slice(&[0, 0, 0xAC, 0x02]);
        expected.extend_from_slice(&[9; 300]);
        assert_eq!(bytes, expected);
        let (count, entries) = decode(&bytes);
        assert_eq!(count, 2);
        assert_eq!(entries[0], (2, vec![0xAA; 8], vec![1, 2, 3]));
        assert_eq!(entries[1], (0, vec![], vec![9; 300]));
    }

    #[test]
    fn the_ceiling_holds_for_every_frame_and_is_tight_to_varint_slack() {
        let txs = [
            FrameTx {
                pqc_auth_count: 1,
                pqc_auths: &[7; 40],
                prunable: &[8; 1000],
            },
            FrameTx {
                pqc_auth_count: 0,
                pqc_auths: &[],
                prunable: &[5; 10],
            },
        ];
        let bytes = encode_frame(&txs);
        let total = ArchivalLength::from_raw(40 + 1000 + 10);
        let ceiling = frame_len_ceiling(2, total).unwrap();
        assert!(u64::try_from(bytes.len()).unwrap() <= ceiling);
        // Slack is only the varint widths: 1 + 10 + 2 × 30 fixed, versus the
        // 1 + 1 + (1+1+1) + (1+1+2) actually spent.
        assert_eq!(ceiling - total.to_raw(), 1 + 10 + 2 * 30);
        assert_eq!(frame_len_ceiling(u64::MAX, total), None);
    }

    #[test]
    fn the_streaming_decoder_agrees_with_read_varint() {
        for value in [0u64, 1, 127, 128, 300, 16_383, 16_384, u64::MAX] {
            let mut bytes = Vec::new();
            write_varint(value, &mut bytes).unwrap();
            let mut decoder = VarintDecoder::new();
            let mut out = None;
            for (i, byte) in bytes.iter().enumerate() {
                out = decoder.push(*byte).unwrap();
                if i + 1 < bytes.len() {
                    assert_eq!(out, None, "terminated early for {value}");
                }
            }
            assert_eq!(out, Some(value));
        }
    }

    #[test]
    fn the_streaming_decoder_refuses_what_the_reader_refuses() {
        // Redundant trailing zero.
        let mut d = VarintDecoder::new();
        assert_eq!(d.push(0x80).unwrap(), None);
        assert_eq!(
            d.push(0x00).unwrap_err(),
            FrameError::Varint(VarintFault::NonCanonical)
        );
        // Ten continuation bytes then one more: too long before overflow
        // can be judged on the eleventh.
        let mut d = VarintDecoder::new();
        for _ in 0..9 {
            assert_eq!(d.push(0x81).unwrap(), None);
        }
        // The tenth byte may carry only one bit; 0x02 overflows.
        assert_eq!(
            d.push(0x02).unwrap_err(),
            FrameError::Varint(VarintFault::Overflow)
        );
        let mut d = VarintDecoder::new();
        for _ in 0..9 {
            assert_eq!(d.push(0x81).unwrap(), None);
        }
        // Still continuing on the tenth byte with an in-range group.
        assert_eq!(d.push(0x81).unwrap(), None);
        assert_eq!(
            d.push(0x01).unwrap_err(),
            FrameError::Varint(VarintFault::TooLong)
        );
        assert_eq!(check_version(2).unwrap_err(), FrameError::Version(2));
        assert_eq!(check_version(SHARD_FRAME_VERSION), Ok(()));
    }

    #[test]
    fn lengths_are_judged_before_bytes_and_against_the_arity() {
        let with_auths = FrameTx {
            pqc_auth_count: 1,
            pqc_auths: &[3; 16],
            prunable: &[4; 24],
        };
        let expected = parts(&with_auths, 1);
        assert_eq!(check_lengths(0, &expected, 16, 24), Ok(()));
        // The same total split differently passes the length check (the
        // hash check decides), a different total does not.
        assert_eq!(check_lengths(0, &expected, 10, 30), Ok(()));
        assert!(matches!(
            check_lengths(0, &expected, 16, 25),
            Err(ContentMismatch::Lengths { index: 0, .. })
        ));
        assert!(matches!(
            check_lengths(0, &expected, u64::MAX, 1),
            Err(ContentMismatch::Lengths { .. })
        ));
        // A 3-part transaction may not be sent a pqc_auths segment.
        let three_part = FrameTx {
            pqc_auth_count: 0,
            pqc_auths: &[],
            prunable: &[4; 24],
        };
        let expected = parts(&three_part, 2);
        assert_eq!(expected.pqc_auth_hash, None);
        assert_eq!(check_lengths(3, &expected, 0, 24), Ok(()));
        assert!(matches!(
            check_lengths(3, &expected, 8, 16),
            Err(ContentMismatch::Lengths { index: 3, .. })
        ));
    }

    #[test]
    fn components_are_checked_against_the_rows_in_order() {
        let tx = FrameTx {
            pqc_auth_count: 2,
            pqc_auths: &[0x11; 32],
            prunable: &[0x22; 64],
        };
        let expected = parts(&tx, 5);
        assert_eq!(
            check_components(1, &expected, 2, tx.pqc_auths, tx.prunable),
            Ok(())
        );
        // Same bytes, wrong count: the count is in the row's preimage.
        assert_eq!(
            check_components(1, &expected, 3, tx.pqc_auths, tx.prunable),
            Err(ContentMismatch::PqcAuthHash { index: 1 })
        );
        let mut wrong = [0x11; 32];
        wrong[0] ^= 1;
        assert_eq!(
            check_components(1, &expected, 2, &wrong, tx.prunable),
            Err(ContentMismatch::PqcAuthHash { index: 1 })
        );
        let mut wrong = [0x22; 64];
        wrong[63] ^= 1;
        assert_eq!(
            check_components(1, &expected, 2, tx.pqc_auths, &wrong),
            Err(ContentMismatch::PrunableHash { index: 1 })
        );
        // A 3-part entry: only the prunable row is compared, and an empty
        // region is the empty-region row.
        let bare = FrameTx {
            pqc_auth_count: 0,
            pqc_auths: &[],
            prunable: &[],
        };
        let expected = parts(&bare, 6);
        assert_eq!(expected.prunable_hash, crate::empty_region_prunable_hash());
        assert_eq!(check_components(0, &expected, 0, &[], &[]), Ok(()));
    }
}
