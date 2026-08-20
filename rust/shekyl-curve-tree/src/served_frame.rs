// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The served shard response frame — `RF-D4` / `RF-D7`
//! (`docs/design/ARCHIVAL_RESPONSE_FORMAT.md` §3.5).
//!
//! A serving persona answers a challenge with one frozen segment's leaf
//! bytes; the witness hashes what it received through
//! [`recompute_segment_r_k`](crate::store::recompute_segment_r_k) and
//! compares against its **local** `R_k`. Self-authentication is therefore by
//! *reconstruction*, not by delimiter — any trailing byte changes the hash
//! input — so the response needs a frame that says where the segment stops
//! and anything else starts.
//!
//! ```text
//! served response := leaf_count  varint    (<= leaves_per_segment)
//!                  ‖ padding_len varint
//!                  ‖ segment_bytes         (leaf_count x LEAF_BYTES, exactly)
//!                  ‖ padding_bytes         (padding_len, exactly)
//!
//! hashed against R_k: segment_bytes ONLY
//! ```
//!
//! **Varint is the workspace encoding** — [`shekyl_curve_io::write_varint`] /
//! [`shekyl_curve_io::read_varint`]: unsigned little-endian base-128, seven
//! payload bits per byte, high bit set on every byte but the last, and
//! **canonical** (the reader rejects a continuation followed by a zero
//! byte). Named rather than left to "varint" because there is no fetcher
//! yet: the first one is written from this grammar, not from this encoder,
//! and "varint" alone does not determine bytes.
//!
//! # Why the frame lives here and not in the serving crate
//!
//! A reader cannot verify a response without `recompute_segment_r_k`, so
//! `shekyl-curve-tree` is already in every fetcher's dependency graph. Any
//! other home either adds an edge or declares a second [`LEAF_BYTES`]. The
//! frame is a property of the *segment format* — hence the crate root beside
//! [`crate::segment`], not `store/`, which a fetcher never touches.
//!
//! # Why the lengths lead
//!
//! Both are in a leading header so the response head can go out before any
//! store read, preserving the property
//! [`FrozenSegmentBody::remaining_bytes`](crate::store::FrozenSegmentBody::remaining_bytes)
//! exists to give: `content-length` is exact before a single leaf is touched,
//! so a store that fails mid-body can only truncate a response, never change
//! which response was chosen.

use std::io::{self, Read, Write};

use shekyl_curve_io::{read_varint, varint_len, write_varint};

use crate::segment::{leaves_per_segment, LEAF_BYTES};

/// [`LEAF_BYTES`] where the arithmetic is in `u64`.
const LEAF_BYTES_U64: u64 = LEAF_BYTES as u64;

/// Why a frame header was refused.
///
/// Both bounds are checked **before** the header is constructed, so a
/// [`ServedFrameHeader`] in hand is one whose declared lengths are already
/// within range — a reader cannot allocate against an unchecked number
/// because the check is what produces the value it would allocate from.
#[derive(Debug)]
pub enum ServedFrameError {
    /// `leaf_count` exceeds one segment. A response larger than a segment
    /// cannot be a segment, so this is refused at the header rather than
    /// after the bytes arrive.
    LeafCountTooLarge {
        /// The declared leaf count.
        leaf_count: u64,
        /// `leaves_per_segment()`.
        max: u64,
    },
    /// `padding_len` exceeds `leaf_count x LEAF_BYTES` — see the field's
    /// documentation on [`ServedFrameHeader::padding_len`] for why the cap
    /// is one segment's worth and not something larger.
    PaddingTooLarge {
        /// The declared padding length.
        padding_len: u64,
        /// `leaf_count x LEAF_BYTES` for the same header.
        max: u64,
    },
    /// The header could not be read (short read, or a non-canonical varint).
    Io(io::Error),
}

impl From<io::Error> for ServedFrameError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl std::fmt::Display for ServedFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LeafCountTooLarge { leaf_count, max } => write!(
                f,
                "served frame declares {leaf_count} leaves; a segment holds at most {max}"
            ),
            Self::PaddingTooLarge { padding_len, max } => write!(
                f,
                "served frame declares {padding_len} padding bytes; at most {max} (one segment's \
                 worth) is accepted"
            ),
            Self::Io(e) => write!(f, "served frame header unreadable: {e}"),
        }
    }
}

impl std::error::Error for ServedFrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// The two leading lengths of a served response.
///
/// Fields are private and both constructors validate, so **every value of
/// this type is a frame whose lengths are in range**. That is the point of
/// the type: the read-side bound of `RF-D7` is not a check a caller may
/// forget, it is the only way to obtain the numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServedFrameHeader {
    leaf_count: u64,
    padding_len: u64,
}

impl ServedFrameHeader {
    /// The header for an unpadded segment body of `leaf_count` leaves.
    ///
    /// **There is no padding parameter, and that is the write-zero rule.**
    /// `RF-D4` rules that writers MUST emit `padding_len == 0` until a
    /// padding scheme is specified; expressing that as a parameter every
    /// caller must remember to pass `0` for would make a rule out of what
    /// can instead be a fact. When a scheme lands, its PR adds the
    /// parameter — that change *is* the reopening criterion
    /// ([rule 21](../../../.cursor/rules/21-reversion-clause-discipline.mdc)),
    /// rather than a flexibility provisioned ahead of the decision.
    ///
    /// # Errors
    ///
    /// [`ServedFrameError::LeafCountTooLarge`] if `leaf_count` exceeds
    /// [`leaves_per_segment`].
    pub fn for_segment(leaf_count: usize) -> Result<Self, ServedFrameError> {
        let leaf_count = u64::try_from(leaf_count).expect("leaf count fits u64");
        let max = u64::try_from(leaves_per_segment()).expect("segment size fits u64");
        if leaf_count > max {
            return Err(ServedFrameError::LeafCountTooLarge { leaf_count, max });
        }
        Ok(Self {
            leaf_count,
            padding_len: 0,
        })
    }

    /// Leaves in the segment portion of the body.
    #[must_use]
    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Padding bytes following the segment portion — **never** part of the
    /// `R_k` hash input.
    ///
    /// Zero on every response this codebase writes today
    /// ([`Self::for_segment`]). Two constraints bind whatever scheme fills
    /// it later, and both are properties of *this field*, not of the
    /// current implementation:
    ///
    /// - **The value must be decidable without a store read.** It is
    ///   encoded in the leading header, which goes out before the first
    ///   body chunk, so a padding decision that needed to look at leaves
    ///   could not be made in time. A scheme requiring one is a format
    ///   change, not an implementation detail.
    /// - **It is bounded** at `leaf_count x LEAF_BYTES`, so a body never
    ///   exceeds twice a segment. The declaration comes from a potentially
    ///   adversarial server, and an unbounded one is a
    ///   resource-exhaustion path against a fetcher that expects ~3.33 MB.
    ///   A scheme wanting more than 100% overhead is arguing against
    ///   TJ-H's own cost analysis (every padded byte crosses two Tor legs
    ///   and inflates W2) and should reopen the cap deliberately.
    #[must_use]
    pub fn padding_len(&self) -> u64 {
        self.padding_len
    }

    /// Bytes of segment payload the header declares — the `R_k` hash input's
    /// length.
    #[must_use]
    pub fn segment_bytes(&self) -> u64 {
        self.leaf_count * LEAF_BYTES_U64
    }

    /// Total body length: header ‖ segment ‖ padding.
    ///
    /// This is the transport `content-length`, and it is exact before any
    /// leaf is read.
    #[must_use]
    pub fn framed_len(&self) -> u64 {
        u64::try_from(self.encoded_len()).expect("header length fits u64")
            + self.segment_bytes()
            + self.padding_len
    }

    /// Encoded size of the header itself, in bytes.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        varint_len(self.leaf_count) + varint_len(self.padding_len)
    }

    /// Write the header.
    ///
    /// # Errors
    ///
    /// Propagates the writer's failure.
    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        write_varint(&self.leaf_count, w)?;
        write_varint(&self.padding_len, w)
    }

    /// The header as bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.write_to(&mut out)
            .expect("writing a header into a Vec cannot fail");
        out
    }

    /// Read and validate a header.
    ///
    /// Both bounds are enforced here, **before the caller can see a
    /// length** — which is what makes `RF-D7`'s cap a pre-allocation test
    /// rather than a complaint filed after the bytes have already been
    /// drained.
    ///
    /// # Errors
    ///
    /// [`ServedFrameError::Io`] on a short read or a non-canonical varint,
    /// [`ServedFrameError::LeafCountTooLarge`] past one segment, and
    /// [`ServedFrameError::PaddingTooLarge`] past one segment's worth of
    /// padding.
    pub fn read<R: Read>(r: &mut R) -> Result<Self, ServedFrameError> {
        let leaf_count: u64 = read_varint(r)?;
        let max_leaves = u64::try_from(leaves_per_segment()).expect("segment size fits u64");
        if leaf_count > max_leaves {
            return Err(ServedFrameError::LeafCountTooLarge {
                leaf_count,
                max: max_leaves,
            });
        }
        let padding_len: u64 = read_varint(r)?;
        // Safe only because `leaf_count` was bounded above: at
        // `leaves_per_segment()` this product is ~3.3e6, and an unbounded
        // `leaf_count` would overflow it (panicking in debug, wrapping in
        // release). The dependency is on the *order* of these two checks, so
        // it is stated here rather than left for a reader to reconstruct.
        let max_padding = leaf_count * LEAF_BYTES_U64;
        if padding_len > max_padding {
            return Err(ServedFrameError::PaddingTooLarge {
                padding_len,
                max: max_padding,
            });
        }
        Ok(Self {
            leaf_count,
            padding_len,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a header by hand, so the read side can be given lengths
    /// [`ServedFrameHeader::for_segment`] cannot produce (any non-zero
    /// padding, and out-of-range values).
    fn raw_header(leaf_count: u64, padding_len: u64) -> Vec<u8> {
        let mut out = Vec::new();
        write_varint(&leaf_count, &mut out).expect("vec write");
        write_varint(&padding_len, &mut out).expect("vec write");
        out
    }

    /// The premise every pinned vector below rests on. Asserted rather than
    /// assumed: if the segment size ever moves, these vectors are stale
    /// fixtures and must say so here, not fail three tests down with an
    /// arithmetic mismatch (rule 47 — a gate asserts its own subject).
    #[test]
    fn pinned_vectors_are_pinned_against_the_current_segment_size() {
        assert_eq!(leaves_per_segment(), 25_992);
        assert_eq!(LEAF_BYTES, 128);
    }

    /// **Hand-derived from the grammar, not from the encoder.**
    ///
    /// A round-trip test proves the encoder agrees with itself; only a
    /// vector computed independently proves it agrees with the *spec* — and
    /// with no fetcher in existence, the spec is the only counterparty this
    /// format has.
    ///
    /// `leaf_count = 25 992`, base-128 little-endian:
    ///   25 992 = 8 + 75·128 + 1·16 384
    ///   low group 8 -> 0x08 | 0x80 = 0x88 (more follows)
    ///   next group 75 -> 0x4B | 0x80 = 0xCB (more follows)
    ///   last group 1 -> 0x01          (high bit clear, terminates)
    /// `padding_len = 0` -> a single 0x00.
    #[test]
    fn full_segment_header_matches_the_hand_derived_bytes() {
        let header = ServedFrameHeader::for_segment(25_992).expect("a full segment is in range");
        assert_eq!(header.to_bytes(), vec![0x88, 0xCB, 0x01, 0x00]);
        assert_eq!(header.encoded_len(), 4);
        assert_eq!(header.segment_bytes(), 3_326_976);
        assert_eq!(header.framed_len(), 4 + 3_326_976);
    }

    /// The smallest non-empty frame, likewise hand-derived: one group each.
    #[test]
    fn single_leaf_header_matches_the_hand_derived_bytes() {
        let header = ServedFrameHeader::for_segment(1).expect("one leaf is in range");
        assert_eq!(header.to_bytes(), vec![0x01, 0x00]);
        assert_eq!(header.framed_len(), 2 + 128);
    }

    #[test]
    fn header_round_trips() {
        for leaves in [0, 1, 127, 128, 25_991, 25_992] {
            let written = ServedFrameHeader::for_segment(leaves).expect("in range");
            let bytes = written.to_bytes();
            let read = ServedFrameHeader::read(&mut bytes.as_slice()).expect("round trip");
            assert_eq!(read, written, "leaf_count {leaves}");
            assert_eq!(read.padding_len(), 0);
        }
    }

    #[test]
    fn writers_emit_zero_padding_by_construction() {
        let header = ServedFrameHeader::for_segment(25_992).expect("in range");
        assert_eq!(header.padding_len(), 0);
    }

    /// The cap is `<=`, not `<`: exactly one segment's worth of padding is
    /// legal, because that is the bound `RF-D7` derives — a body of at most
    /// twice a segment.
    #[test]
    fn read_accepts_padding_exactly_at_the_cap() {
        let bytes = raw_header(25_992, 3_326_976);
        let header = ServedFrameHeader::read(&mut bytes.as_slice()).expect("at the cap is legal");
        assert_eq!(header.padding_len(), 3_326_976);
        assert_eq!(
            header.framed_len(),
            header.encoded_len() as u64 + 2 * 3_326_976
        );
    }

    #[test]
    fn read_rejects_padding_one_byte_past_the_cap() {
        let bytes = raw_header(25_992, 3_326_977);
        match ServedFrameHeader::read(&mut bytes.as_slice()) {
            Err(ServedFrameError::PaddingTooLarge { padding_len, max }) => {
                assert_eq!(padding_len, 3_326_977);
                assert_eq!(max, 3_326_976);
            }
            other => panic!("expected PaddingTooLarge, got {other:?}"),
        }
    }

    /// The exhaustion shape the cap exists for: a server declaring 256 MB of
    /// padding to a fetcher that expects ~3.33 MB.
    #[test]
    fn read_rejects_a_resource_exhaustion_sized_padding_declaration() {
        let bytes = raw_header(25_992, 256 * 1024 * 1024);
        assert!(matches!(
            ServedFrameHeader::read(&mut bytes.as_slice()),
            Err(ServedFrameError::PaddingTooLarge { .. })
        ));
    }

    /// An empty segment admits **no** padding: the cap is a multiple of the
    /// declared leaf count, so a zero-leaf frame cannot smuggle bytes.
    #[test]
    fn read_rejects_padding_on_an_empty_segment() {
        assert!(matches!(
            ServedFrameHeader::read(&mut raw_header(0, 1).as_slice()),
            Err(ServedFrameError::PaddingTooLarge {
                padding_len: 1,
                max: 0
            })
        ));
    }

    #[test]
    fn read_rejects_leaf_count_past_one_segment() {
        let bytes = raw_header(25_993, 0);
        match ServedFrameHeader::read(&mut bytes.as_slice()) {
            Err(ServedFrameError::LeafCountTooLarge { leaf_count, max }) => {
                assert_eq!(leaf_count, 25_993);
                assert_eq!(max, 25_992);
            }
            other => panic!("expected LeafCountTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn for_segment_rejects_leaf_count_past_one_segment() {
        assert!(matches!(
            ServedFrameHeader::for_segment(25_993),
            Err(ServedFrameError::LeafCountTooLarge {
                leaf_count: 25_993,
                max: 25_992
            })
        ));
    }

    /// `leaf_count` is bounded **before** `padding_len` is even read, so an
    /// oversized leaf count is named as such rather than reported as a
    /// padding failure derived from a length that was never legal.
    #[test]
    fn leaf_count_is_rejected_before_padding_is_considered() {
        let bytes = raw_header(u64::MAX, 0);
        assert!(matches!(
            ServedFrameHeader::read(&mut bytes.as_slice()),
            Err(ServedFrameError::LeafCountTooLarge { .. })
        ));
    }

    /// The workspace varint is canonical, and the frame inherits that: a
    /// continuation byte followed by a zero group is refused, so one length
    /// has exactly one encoding.
    #[test]
    fn read_rejects_a_non_canonical_varint() {
        let bytes = [0x80u8, 0x00];
        assert!(matches!(
            ServedFrameHeader::read(&mut bytes.as_slice()),
            Err(ServedFrameError::Io(_))
        ));
    }

    #[test]
    fn read_rejects_a_truncated_header() {
        // `leaf_count` present, `padding_len` missing entirely.
        let bytes = [0x01u8];
        assert!(matches!(
            ServedFrameHeader::read(&mut bytes.as_slice()),
            Err(ServedFrameError::Io(_))
        ));
    }
}
