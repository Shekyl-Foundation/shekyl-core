// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Canonical value codecs (DRS-E1 increment 2).
//!
//! # One encoding, two consumers
//!
//! DRS-0 slice A ruled that the accumulator folds *"a canonical encoding of
//! the decoded logical value, never storage bytes"*, and
//! [`DAEMON_REDB_STORE.md`](../../../../docs/design/DAEMON_REDB_STORE.md)
//! §11.1(b) ruled that the redb value codec **is** that canonical encoding —
//! so a codec change is digest-visible, not a refactor, and bumps
//! [`SCHEMA_VERSION`]. This module is where both rulings become one trait:
//! [`Canonical`] is the encoding a value is *stored* under and the encoding
//! the digest *folds*. There is no second function to drift from the first.
//!
//! # Strictness is the contract
//!
//! [`Canonical::decode`] is total over its input and refuses anything that
//! is not exactly one encoding: wrong length, trailing bytes, and bit
//! patterns that name nothing are all [`CodecError`], never a lenient
//! read. A consensus store that tolerated a malformed cell would be
//! accepting a state it cannot reproduce, which is the failure the digest
//! exists to detect — so the codecs refuse first.
//!
//! # The gate
//!
//! Every `impl Canonical` has a committed fixture snapshot under
//! `rust/shekyl-chain-store/schemas/`, asserted by the `codec_snapshot`
//! tests in [`snapshot_tests`](self) and paired against [`SCHEMA_VERSION`]
//! by `.github/workflows/schema-snapshot.yml`. That is the rule-42 ratchet
//! §11.1(e) recorded as owed: an encoding cannot move without the version
//! moving in the same PR.

mod primitives;
mod property;
mod schema_version;
mod undo;

#[cfg(test)]
#[path = "snapshot_tests.rs"]
mod snapshot_tests;

#[cfg(test)]
pub(crate) use property::ProbeCell;
pub use property::{
    ApplyPolicyCell, CellScope, ChainState, EngineLocal, PropertyCell, PropertyCellSpec,
    SchemaVersionCell, Scope, PROPERTY_CELLS,
};
pub use schema_version::{SchemaVersion, SCHEMA_VERSION};
pub use undo::{UndoEntry, UndoLog};

/// A value with exactly one byte encoding.
///
/// The encoding is the stored form **and** the digest's fold input
/// (module docs). Implementations are strict both ways: `encode` produces
/// the one encoding, `decode` accepts only that encoding.
pub trait Canonical: Sized {
    /// Stable identifier of this codec. It names the snapshot file
    /// (`schemas/<NAME>.snap`) and appears in every [`CodecError`], so it
    /// is lowercase `snake_case` and never reused for a different layout.
    const NAME: &'static str;

    /// `Some(n)` when every encoding is exactly `n` bytes; `None` for a
    /// variable-width codec. Part of the snapshot.
    const FIXED_WIDTH: Option<usize>;

    /// Append this value's canonical encoding to `out`.
    fn encode_into(&self, out: &mut Vec<u8>);

    /// Decode exactly one value from `bytes`.
    ///
    /// # Errors
    ///
    /// [`CodecError`] if `bytes` is not precisely one encoding of a value
    /// of this type. Nothing is read leniently.
    fn decode(bytes: &[u8]) -> Result<Self, CodecError>;

    /// The canonical encoding as an owned buffer.
    #[must_use]
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::FIXED_WIDTH.unwrap_or(0));
        self.encode_into(&mut out);
        out
    }
}

/// Why bytes are not an encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodecError {
    /// The input is not the width this codec requires.
    Length {
        /// [`Canonical::NAME`] of the refusing codec.
        codec: &'static str,
        /// Bytes the codec required.
        expected: usize,
        /// Bytes it was given.
        actual: usize,
    },
    /// The input has the right shape but names no value.
    Invalid {
        /// [`Canonical::NAME`] of the refusing codec.
        codec: &'static str,
        /// What was wrong, in the codec's own vocabulary.
        reason: &'static str,
    },
}

impl core::fmt::Display for CodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Length {
                codec,
                expected,
                actual,
            } => write!(
                f,
                "{codec}: expected exactly {expected} byte(s), got {actual}"
            ),
            Self::Invalid { codec, reason } => write!(f, "{codec}: {reason}"),
        }
    }
}

impl core::error::Error for CodecError {}

impl CodecError {
    /// Relabel this error as coming from `codec`.
    ///
    /// Wrapping codecs (`SchemaVersion` over `u64`, …) decode via the inner
    /// impl and then rename the failure so the cell names the codec the
    /// caller asked for, not the scalar it is stored as.
    pub(crate) fn in_codec(self, codec: &'static str) -> Self {
        match self {
            Self::Length {
                expected, actual, ..
            } => Self::Length {
                codec,
                expected,
                actual,
            },
            Self::Invalid { reason, .. } => Self::Invalid { codec, reason },
        }
    }
}

/// Take exactly `N` bytes or refuse with [`CodecError::Length`].
///
/// The one length check every fixed-width codec shares, so no codec grows
/// its own tolerant variant.
pub(crate) fn exact<const N: usize>(
    codec: &'static str,
    bytes: &[u8],
) -> Result<[u8; N], CodecError> {
    <[u8; N]>::try_from(bytes).map_err(|_| CodecError::Length {
        codec,
        expected: N,
        actual: bytes.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_refuses_both_short_and_long_inputs() {
        assert_eq!(exact::<4>("t", &[1, 2, 3, 4]), Ok([1, 2, 3, 4]));
        assert_eq!(
            exact::<4>("t", &[1, 2, 3]),
            Err(CodecError::Length {
                codec: "t",
                expected: 4,
                actual: 3
            })
        );
        assert_eq!(
            exact::<4>("t", &[1, 2, 3, 4, 5]),
            Err(CodecError::Length {
                codec: "t",
                expected: 4,
                actual: 5
            })
        );
    }

    #[test]
    fn in_codec_renames_the_codec_and_keeps_the_fault() {
        let length = CodecError::Length {
            codec: "u64",
            expected: 8,
            actual: 2,
        };
        assert_eq!(
            length.in_codec("schema_version"),
            CodecError::Length {
                codec: "schema_version",
                expected: 8,
                actual: 2
            }
        );
        let invalid = CodecError::Invalid {
            codec: "u64",
            reason: "never",
        };
        assert_eq!(
            invalid.in_codec("schema_version"),
            CodecError::Invalid {
                codec: "schema_version",
                reason: "never"
            }
        );
    }

    #[test]
    fn errors_name_the_codec_in_their_display() {
        let e = CodecError::Invalid {
            codec: "family_set",
            reason: "bit names no family",
        };
        assert_eq!(e.to_string(), "family_set: bit names no family");
        let e = CodecError::Length {
            codec: "u64",
            expected: 8,
            actual: 7,
        };
        assert_eq!(e.to_string(), "u64: expected exactly 8 byte(s), got 7");
    }
}
