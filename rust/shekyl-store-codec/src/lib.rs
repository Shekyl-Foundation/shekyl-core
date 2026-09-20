// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The redb value contract both Shekyl stores share.
//!
//! # One encoding, two consumers
//!
//! DRS-0 slice A ruled that the daemon's logical-state accumulator folds
//! *"a canonical encoding of the decoded logical value, never storage
//! bytes"*, and `DAEMON_REDB_STORE.md` §11.1(b) ruled that the redb value
//! codec **is** that canonical encoding — so a codec change is
//! digest-visible, not a refactor. [`Canonical`] is where both rulings
//! become one trait: the encoding a value is *stored* under and the
//! encoding the digest *folds*. There is no second function to drift from
//! the first.
//!
//! # What lives here, and what deliberately does not
//!
//! This crate holds the contract and the codecs for types **neither store
//! owns**: the scalars (`u8`, `u64`) and the `shekyl-types` /
//! `shekyl-units` vocabulary. It holds them because the orphan rule leaves
//! nowhere else — once [`Canonical`] is foreign to a store crate, an impl
//! for a foreign type can live only where the trait lives, and the
//! vocabulary crates are `no_std` and must not learn about `redb`
//! (`CURVE_TREE_STORE_SHAPES.md` CTS-13, CTS-Q6).
//!
//! What does **not** live here is as load-bearing as what does. Each
//! store's own column codecs stay in that store. So does the daemon's
//! rule-42 apparatus — the committed fixture snapshots, the
//! `impl Canonical` source scan, and §11.1(b)'s obligation to bump
//! `SCHEMA_VERSION` when stored bytes move. That obligation is a property
//! of the daemon store's implementations, not of a general-purpose trait:
//! the consensus rule lives where the digest is, and a shared trait must
//! not look like the thing someone could later relax for the other
//! store's convenience (§11.1(f), last bullet).
//!
//! # Strictness is the contract
//!
//! [`Canonical::decode`] is total over its input and refuses anything that
//! is not exactly one encoding: wrong length, trailing bytes, and bit
//! patterns that name nothing are all [`CodecError`], never a lenient
//! read. A consensus store that tolerated a malformed cell would be
//! accepting a state it cannot reproduce, which is the failure the digest
//! exists to detect — so the codecs refuse first.

#![deny(unsafe_code)]

mod primitives;
mod shape;
mod vocabulary;

pub use shape::{Blob, BlobKind, Coded, Encoded, EncodedBuf, NoRow, Present, Raw, Unshaped};

/// A value with exactly one byte encoding.
///
/// The encoding is the stored form **and** the digest's fold input
/// (crate docs). Implementations are strict both ways: `encode` produces
/// the one encoding, `decode` accepts only that encoding.
pub trait Canonical: Sized {
    /// Stable identifier of this codec's layout. It is the `{NAME}` in a
    /// `Coded<V>` table's `TypeName`, it names the codec in every
    /// [`CodecError`], and a store that pins bytes keys its fixture by it
    /// (the daemon store: `schemas/<NAME>.snap`) — so it is lowercase
    /// `snake_case` and never reused for a different layout. Which codecs
    /// carry a fixture, and under which version constant, is each
    /// consuming store's decision, not this trait's.
    const NAME: &'static str;

    /// `Some(n)` when every encoding is exactly `n` bytes; `None` for a
    /// variable-width codec. Reported to the engine by `Coded<V>` and held
    /// by a store's fixture where one is pinned.
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

    /// The canonical encoding as the row a `Coded<Self>` table inserts.
    ///
    /// The ergonomic constructor of an [`Encoded`] (via
    /// [`EncodedBuf::as_encoded`]), and the only one this crate offers —
    /// but not the guarantee. `redb::Value::from_bytes` is a public trait
    /// method and produces an `Encoded` over any bytes. What holds a
    /// `Coded<V>` table's rows to `V::encode` is each store's validated
    /// insertion boundary — the daemon store's `check_row` and
    /// `Restorable::well_formed` (`shape` module docs, *Two guards*).
    #[must_use]
    fn encoded(&self) -> EncodedBuf<Self> {
        EncodedBuf::of(self)
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
    /// caller asked for, not the scalar it is stored as. `pub` because the
    /// wrapping codecs live in the stores, not here.
    #[must_use]
    pub fn in_codec(self, codec: &'static str) -> Self {
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
/// its own tolerant variant. `pub` because most fixed-width codecs are a
/// store's own and are written against this.
///
/// # Errors
///
/// [`CodecError::Length`] if `bytes` is not exactly `N` bytes.
pub fn exact<const N: usize>(codec: &'static str, bytes: &[u8]) -> Result<[u8; N], CodecError> {
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
