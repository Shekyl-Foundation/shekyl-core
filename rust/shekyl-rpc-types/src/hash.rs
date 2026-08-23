// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`HashHex`] — the wire rendering of a 32-byte hash.
//!
//! Every hash this RPC carries is 32 bytes rendered as 64 lowercase hex
//! characters (epee's `pod_to_hex`). Before RK-3 each such field was a
//! `String`, which made "not a hash at all" a value the type admitted and
//! left every consumer to parse hex for itself. `HashHex` moves that parse
//! to the deserializer, once.
//!
//! **It is deliberately not a wrapper over a domain hash newtype.** A single
//! `block_header` carries hashes of four different kinds — a block identity,
//! a transaction identity, two Merkle-ish roots, and a proof-of-work hash —
//! so typing the wire field as any one of them (`BlockHash`, say) would
//! recreate on the wire exactly the confusion `shekyl-types`' `hash32!`
//! newtypes exist to prevent. Rule 18 already settles this: wire structs
//! store the raw bytes and convert at their edge, which is why
//! `shekyl-wire::BlockHeader` types both roots as `[u8; 32]`. A consumer that
//! knows which kind it is holding names it there — `BlockHash::from_bytes(h.to_bytes())`
//! — and that knowledge stays where it is actually available.
//!
//! Keeping this crate's production dependency surface at serde alone is the
//! other half of the same decision: no domain crate is needed to describe a
//! wire field.

use core::fmt;
use std::borrow::Cow;

use serde::de::{Error as DeError, Unexpected};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A 32-byte hash as it appears on the daemon RPC wire.
///
/// Serializes as 64 **lowercase** hex characters. Deserialization accepts
/// either case — an in-tree client that upper-cases is readable without
/// ambiguity, and the value re-emits lowercase — but rejects anything that
/// is not exactly 32 bytes of hex.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct HashHex([u8; 32]);

impl HashHex {
    /// The all-zero hash — what a genesis block's `prev_hash` is.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Wrap raw bytes (from a domain newtype's `to_bytes`, or from FFI).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw bytes, for the edge conversion into whichever domain hash the
    /// caller knows this to be.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Whether this is [`Self::ZERO`].
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Parse 64 hex characters of either case.
    ///
    /// # Errors
    ///
    /// Returns [`HashHexError`] if the input is not exactly 64 characters or
    /// contains a non-hex character.
    pub fn from_hex(s: &str) -> Result<Self, HashHexError> {
        let bytes = s.as_bytes();
        if bytes.len() != 64 {
            return Err(HashHexError::Length(bytes.len()));
        }
        let mut out = [0u8; 32];
        for (i, pair) in bytes.chunks_exact(2).enumerate() {
            let hi = hex_nibble(pair[0])?;
            let lo = hex_nibble(pair[1])?;
            out[i] = (hi << 4) | lo;
        }
        Ok(Self(out))
    }
}

/// Why a string was not a [`HashHex`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashHexError {
    /// Not 64 characters; carries the length seen.
    Length(usize),
    /// A character outside `[0-9a-fA-F]`; carries the byte seen.
    NotHex(u8),
}

impl fmt::Display for HashHexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length(n) => {
                write!(f, "expected 64 hex characters (32 bytes), got {n} bytes")
            }
            Self::NotHex(b) => write!(
                f,
                "expected 64 hex characters (32 bytes), got non-hex byte {b:#04x}"
            ),
        }
    }
}

impl core::error::Error for HashHexError {}

fn hex_nibble(b: u8) -> Result<u8, HashHexError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        other => Err(HashHexError::NotHex(other)),
    }
}

impl fmt::Display for HashHex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for HashHex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The hex, not 32 numbered bytes; `format_args!` keeps the single
        // field represented so `missing_fields_in_debug` is satisfied.
        f.debug_tuple("HashHex")
            .field(&format_args!("{self}"))
            .finish()
    }
}

impl Serialize for HashHex {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for HashHex {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // `Cow`, not `&str`: a deserializer that cannot hand out a borrow
        // (`serde_json::Value`, or a reader with escapes) must still be able
        // to produce a hash.
        let s = Cow::<'de, str>::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(|e| {
            let expected = e.to_string();
            DeError::invalid_value(Unexpected::Str(&s), &expected.as_str())
        })
    }
}

/// Serde for a hash field whose *absent* form on this wire is the empty
/// string rather than a missing key or `null` — `block_header.pow_hash`,
/// which epee emits as `""` unless the caller asked for it and was entitled
/// to ask.
///
/// Modelling it as `Option<HashHex>` keeps the daemon's "was it filled?" flag
/// (`shekyl_rpc_block_header_facts.pow_hash_filled`) alive all the way to the
/// wire instead of collapsing it into a string that might or might not be
/// empty. The emitted bytes are unchanged, which the oracle vectors check.
///
/// RK-W is where `""`-as-absent should become a real absence; until then this
/// is the honest type for the shape epee produces.
pub mod empty_string_as_absent {
    use std::borrow::Cow;

    use serde::de::{Error, Unexpected};
    use serde::{Deserialize, Deserializer, Serializer};

    use super::HashHex;

    /// Serialize `Some` as hex and `None` as `""`.
    ///
    /// # Errors
    ///
    /// Propagates the serializer's own error.
    pub fn serialize<S: Serializer>(
        value: &Option<HashHex>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(hash) => serializer.collect_str(hash),
            None => serializer.serialize_str(""),
        }
    }

    /// Deserialize `""` as `None` and 64 hex characters as `Some`.
    ///
    /// # Errors
    ///
    /// Returns the deserializer's error if the value is neither.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<HashHex>, D::Error> {
        let s = Cow::<'de, str>::deserialize(deserializer)?;
        if s.is_empty() {
            return Ok(None);
        }
        HashHex::from_hex(&s).map(Some).map_err(|e| {
            let expected = e.to_string();
            Error::invalid_value(Unexpected::Str(&s), &expected.as_str())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{empty_string_as_absent, HashHex, HashHexError};
    use serde::{Deserialize, Serialize};

    /// A field shaped like `block_header.pow_hash`, so the `""`-as-absent
    /// serde is exercised where it actually sits: inside a struct field.
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct PowField {
        #[serde(with = "empty_string_as_absent")]
        pow_hash: Option<HashHex>,
    }

    fn sample() -> HashHex {
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::try_from(i).expect("32 fits u8").wrapping_mul(7);
        }
        HashHex::from_bytes(bytes)
    }

    /// Emitting anything but 64 lowercase hex characters turns this red —
    /// including reverting `Display` to a byte-array dump.
    #[test]
    fn serializes_as_64_lowercase_hex() {
        let json = serde_json::to_string(&sample()).expect("serialize");
        assert_eq!(
            json, "\"00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9\"",
            "the wire form is the lowercase hex of the bytes"
        );
        assert_eq!(json.len(), 66, "64 hex characters plus the two quotes");
        assert!(
            !json.chars().any(|c| c.is_ascii_uppercase()),
            "epee emits lowercase; so must we"
        );
    }

    /// Dropping the `A..=F` arm of `hex_nibble` turns this red.
    #[test]
    fn accepts_either_case_and_re_emits_lowercase() {
        let lower = sample().to_string();
        let upper = lower.to_uppercase();
        let from_lower = HashHex::from_hex(&lower).expect("lowercase parses");
        let from_upper = HashHex::from_hex(&upper).expect("uppercase parses");
        assert_eq!(from_lower, from_upper, "case is not part of the value");
        assert_eq!(from_upper.to_string(), lower, "output is always lowercase");
    }

    /// The whole point of the type: these were all valid `String`s before.
    /// Making `from_hex` lenient about length or alphabet turns this red.
    #[test]
    fn rejects_everything_that_is_not_32_bytes_of_hex() {
        let good = sample().to_string();
        assert_eq!(HashHexError::Length(0), HashHex::from_hex("").unwrap_err());
        assert_eq!(
            HashHexError::Length(63),
            HashHex::from_hex(&good[..63]).unwrap_err()
        );
        assert_eq!(
            HashHexError::Length(65),
            HashHex::from_hex(&(good.clone() + "0")).unwrap_err()
        );
        let non_hex = "g".to_owned() + &good[1..];
        assert_eq!(
            HashHexError::NotHex(b'g'),
            HashHex::from_hex(&non_hex).unwrap_err()
        );
        // And the deserializer refuses them too, rather than only `from_hex`.
        assert!(
            serde_json::from_str::<HashHex>("\"deadbeef\"").is_err(),
            "a short hex string is not a hash"
        );
        assert!(
            serde_json::from_str::<HashHex>("123").is_err(),
            "a number is not a hash"
        );
    }

    /// Deserializing from a `serde_json::Value` rather than from a borrowed
    /// slice: `Cow` handles it, a `&str` deserializer would not. The engine's
    /// daemon double builds replies through `Value`.
    #[test]
    fn deserializes_from_an_owned_value() {
        let value = serde_json::to_value(sample()).expect("to value");
        let back: HashHex = serde_json::from_value(value).expect("from value");
        assert_eq!(back, sample());
    }

    /// Both directions of the `""` sentinel. Rendering `None` as `null`, or
    /// reading `""` as an all-zero hash, turns this red.
    #[test]
    fn absent_pow_hash_is_the_empty_string_both_ways() {
        let absent = PowField { pow_hash: None };
        let json = serde_json::to_string(&absent).expect("serialize");
        assert_eq!(json, r#"{"pow_hash":""}"#);
        assert_eq!(
            absent,
            serde_json::from_str(&json).expect("deserialize"),
            "`\"\"` reads back as absent, not as the zero hash"
        );
        assert_ne!(
            absent,
            PowField {
                pow_hash: Some(HashHex::ZERO)
            },
            "absent and all-zero are different values"
        );

        let present = PowField {
            pow_hash: Some(sample()),
        };
        let json = serde_json::to_string(&present).expect("serialize");
        assert_eq!(json, format!(r#"{{"pow_hash":"{}"}}"#, sample()));
        assert_eq!(present, serde_json::from_str(&json).expect("deserialize"));

        assert!(
            serde_json::from_str::<PowField>(r#"{"pow_hash":"nope"}"#).is_err(),
            "a non-empty non-hash is still refused"
        );
    }

    #[test]
    fn zero_is_the_genesis_prev_hash_and_knows_it() {
        assert_eq!(HashHex::ZERO.to_string(), "0".repeat(64));
        assert!(HashHex::ZERO.is_zero());
        assert!(!sample().is_zero());
        assert_eq!(HashHex::from_bytes(sample().to_bytes()), sample());
        assert_eq!(sample().as_bytes(), &sample().to_bytes());
    }

    /// `Debug` renders the hex, not 32 numbered bytes.
    #[test]
    fn debug_is_the_hex() {
        assert_eq!(
            format!("{:?}", HashHex::ZERO),
            format!("HashHex({})", "0".repeat(64))
        );
    }
}
