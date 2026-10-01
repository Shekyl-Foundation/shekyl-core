// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`AtomicUnitsString`]: an [`AtomicUnits`] amount as it crosses a JSON
//! edge — the wallet contract's `AtomicUnits` schema
//! (`docs/api/wallet_rpc.yaml`), a decimal string, never a JSON number.
//!
//! JavaScript's `number` is an IEEE double and loses integers above 2^53,
//! so a `u64` amount serialized as a number arrives rounded — and a rounded
//! fee or amount defeats the send flow's one invariant, that the fee the
//! user confirms is the fee that ships. Every wallet front end therefore
//! carries amounts as decimal strings, parsed on the JS side with `BigInt`.
//! A JSON number is *rejected* on input rather than accepted leniently,
//! because a number that reached us has already been rounded by the sender.
//!
//! The parse error never echoes the input: an attacker-sized value would
//! otherwise ride into an error response and the server's logs.
//!
//! This is the one home for that rule. Wallet RPC's results and params and
//! the desktop wallet's Tauri edge all serialize this type, so the two front
//! ends cannot disagree about it.

use alloc::string::String;
use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::AtomicUnits;

/// The contract's `AtomicUnits` schema: an amount carried as a decimal
/// string of atomic units.
///
/// Built from an [`AtomicUnits`] (never from a bare `u64`, so the typed
/// domain's edge stays [`AtomicUnits::from_raw`]) and read back with
/// [`Self::to_atomic_units`]. [`fmt::Display`] is the wire text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct AtomicUnitsString(AtomicUnits);

impl AtomicUnitsString {
    /// The amount this string carries.
    pub const fn to_atomic_units(self) -> AtomicUnits {
        self.0
    }
}

impl From<AtomicUnits> for AtomicUnitsString {
    fn from(amount: AtomicUnits) -> Self {
        Self(amount)
    }
}

impl From<AtomicUnitsString> for AtomicUnits {
    fn from(wire: AtomicUnitsString) -> Self {
        wire.0
    }
}

/// The text was not a decimal `u64` of atomic units. Deliberately carries
/// nothing of the rejected input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseAtomicUnitsStringError;

impl fmt::Display for ParseAtomicUnitsStringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected a decimal string of atomic units")
    }
}

impl core::error::Error for ParseAtomicUnitsStringError {}

impl fmt::Display for AtomicUnitsString {
    /// The wire text: the raw atomic-unit integer, no unit marker.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.to_raw())
    }
}

impl FromStr for AtomicUnitsString {
    type Err = ParseAtomicUnitsStringError;

    /// A bare decimal `u64`: digits only — no sign (Rust's integer parser
    /// would accept a leading `+`), no point, no exponent, no whitespace.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ParseAtomicUnitsStringError);
        }
        text.parse::<u64>()
            .map(|raw| Self(AtomicUnits::from_raw(raw)))
            .map_err(|_| ParseAtomicUnitsStringError)
    }
}

impl Serialize for AtomicUnitsString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for AtomicUnitsString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // `String`, not `&str`: this must also deserialize from an owned
        // `serde_json::Value`, which cannot lend a borrowed string.
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::string::ToString;

    use super::*;

    /// The first integer a JS `number` cannot hold.
    const BEYOND_DOUBLE: u64 = (1u64 << 53) + 1;

    fn wire(raw: u64) -> AtomicUnitsString {
        AtomicUnits::from_raw(raw).into()
    }

    #[test]
    fn serializes_as_a_decimal_string_not_a_number() {
        let v = serde_json::to_value(wire(BEYOND_DOUBLE)).unwrap();
        assert_eq!(v, serde_json::Value::String("9007199254740993".into()));
        assert_eq!(
            serde_json::to_string(&wire(u64::MAX)).unwrap(),
            "\"18446744073709551615\""
        );
        assert_eq!(wire(0).to_string(), "0", "no unit marker on the wire");
    }

    #[test]
    fn deserializes_the_decimal_string_losslessly() {
        let parsed: AtomicUnitsString = serde_json::from_str("\"9007199254740993\"").unwrap();
        assert_eq!(
            parsed.to_atomic_units(),
            AtomicUnits::from_raw(BEYOND_DOUBLE)
        );
        let owned: AtomicUnitsString =
            serde_json::from_value(serde_json::json!("9007199254740993")).unwrap();
        assert_eq!(owned, parsed);
        assert_eq!("42".parse::<AtomicUnitsString>().unwrap(), wire(42));
        assert_eq!(AtomicUnits::from(wire(7)), AtomicUnits::from_raw(7));
    }

    #[test]
    fn rejects_a_json_number_and_anything_not_a_u64_decimal() {
        for bad in [
            "9007199254740993",
            "\"1.5\"",
            "\"-1\"",
            "\"+1\"",
            "\"\"",
            "\" 1\"",
            "\"1e9\"",
            "\"18446744073709551616\"",
            "null",
        ] {
            assert!(
                serde_json::from_str::<AtomicUnitsString>(bad).is_err(),
                "accepted {bad}"
            );
        }
    }

    #[test]
    fn the_parse_error_never_echoes_the_input() {
        let secret = "18446744073709551616";
        let err = secret.parse::<AtomicUnitsString>().unwrap_err();
        assert!(!err.to_string().contains(secret));
        let err = serde_json::from_str::<AtomicUnitsString>(&format!("\"{secret}\"")).unwrap_err();
        assert!(!err.to_string().contains(secret), "{err}");
    }
}
