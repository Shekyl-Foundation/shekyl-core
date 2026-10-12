// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`HexU128`]: a 128-bit quantity on the wire, as `0x`-prefixed hex.
//!
//! A difficulty does not fit a JSON number, so the wire carries it as a
//! string: `0x`, then the value's hex digits. `get_info` carries its two
//! difficulties this way and no other (RK-Q1). The block headers still
//! carry a triple — the low 64 bits, this string, and the high 64 bits —
//! and adopt this type when that triple retires (RK-W).
//!
//! # Why the parser is strict
//!
//! While the triple stood, the string was checked against the two numbers
//! beside it, and a string that parsed to something else was refused by the
//! disagreement. With the numbers gone the string is the only copy, so
//! whatever the parser accepts **is** the value. `u128::from_str_radix`
//! accepts a leading `+` (`"+ff"` is 255); that leniency had been hidden by
//! the comparison and would now be the contract. So the form is checked
//! here, character by character, before any number is made:
//!
//! - the prefix is exactly `0x`;
//! - at least one digit follows, and at most 32, which is all a `u128`
//!   holds, so nothing that reaches the conversion can overflow;
//! - every digit is `0-9`, `a-f` or `A-F`. No sign, no space, no separator.
//!
//! Leading zeros are accepted, up to the 32-digit bound: `0x00ff` is 255.
//! The form written is always minimal and lowercase.
//!
//! # Two kinds of quantity, one encoding each
//!
//! A difficulty is `0x` hex, here. An amount of coin is a **decimal**
//! string (RK-Q2). They are different quantities and they keep different
//! encodings on purpose: hex is what the block headers and the mining RPCs
//! already write for difficulty, and decimal is what the wallet RPC writes
//! for amounts. Do not unify them.

use serde::de::{Deserialize, Deserializer, Visitor};
use serde::{Serialize, Serializer};

/// The digits a `u128` can hold in hex.
const MAX_DIGITS: usize = 32;
const PREFIX: &str = "0x";

/// A 128-bit quantity whose wire form is `0x`-prefixed hex. See the module
/// docs for the form and why its parser is strict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HexU128(pub u128);

/// Why a string is not a [`HexU128`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexU128Error {
    /// It does not start with `0x`.
    MissingPrefix,
    /// Nothing follows the `0x`.
    NoDigits,
    /// More than 32 digits follow: more than a 128-bit value holds.
    TooManyDigits,
    /// A character after the `0x` is not a hex digit. A sign is one.
    NotAHexDigit,
}

impl std::fmt::Display for HexU128Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::MissingPrefix => "a 128-bit hex value starts with `0x`",
            Self::NoDigits => "a 128-bit hex value has at least one digit after `0x`",
            Self::TooManyDigits => "a 128-bit hex value has at most 32 digits after `0x`",
            Self::NotAHexDigit => {
                "a 128-bit hex value has only the digits 0-9 and a-f after `0x`, and no sign"
            }
        })
    }
}

impl std::error::Error for HexU128Error {}

impl HexU128 {
    /// Parse the wire form.
    ///
    /// # Errors
    ///
    /// A [`HexU128Error`] naming the first rule the string breaks.
    pub fn parse(text: &str) -> Result<Self, HexU128Error> {
        let digits = text
            .strip_prefix(PREFIX)
            .ok_or(HexU128Error::MissingPrefix)?;
        if digits.is_empty() {
            return Err(HexU128Error::NoDigits);
        }
        // The form first, on the bytes: `from_str_radix` would take a sign,
        // and a multi-byte character must not be counted as one digit.
        if !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(HexU128Error::NotAHexDigit);
        }
        if digits.len() > MAX_DIGITS {
            return Err(HexU128Error::TooManyDigits);
        }
        // At most 32 hex digits and nothing else: this cannot fail.
        u128::from_str_radix(digits, 16)
            .map(Self)
            .map_err(|_| HexU128Error::NotAHexDigit)
    }

    /// The value.
    #[must_use]
    pub const fn get(self) -> u128 {
        self.0
    }
}

impl From<u128> for HexU128 {
    fn from(value: u128) -> Self {
        Self(value)
    }
}

impl From<HexU128> for u128 {
    fn from(value: HexU128) -> Self {
        value.0
    }
}

/// The wire form: `0x`, then minimal lowercase hex.
impl std::fmt::Display for HexU128 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{PREFIX}{:x}", self.0)
    }
}

impl Serialize for HexU128 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for HexU128 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(HexU128Visitor)
    }
}

struct HexU128Visitor;

impl Visitor<'_> for HexU128Visitor {
    type Value = HexU128;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a string holding `0x` and 1 to 32 hex digits")
    }

    fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<HexU128, E> {
        HexU128::parse(text).map_err(E::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The four values the ruling names, and the forms they are written in.
    const ROUND_TRIPS: [(u128, &str); 4] = [
        (0, "0x0"),
        (u64::MAX as u128, "0xffffffffffffffff"),
        (u64::MAX as u128 + 1, "0x10000000000000000"),
        (u128::MAX, "0xffffffffffffffffffffffffffffffff"),
    ];

    #[test]
    fn it_round_trips_at_zero_and_at_each_64_bit_boundary() {
        for (value, wire) in ROUND_TRIPS {
            assert_eq!(HexU128(value).to_string(), wire);
            assert_eq!(HexU128::parse(wire), Ok(HexU128(value)));
            assert_eq!(serde_json::to_value(HexU128(value)).unwrap(), json!(wire));
            assert_eq!(
                serde_json::from_value::<HexU128>(json!(wire)).unwrap(),
                HexU128(value)
            );
        }
    }

    #[test]
    fn a_missing_prefix_is_refused() {
        for text in ["ff", "0Xff", "x0ff", " 0xff", "", "0", "Oxff", "#ff"] {
            assert_eq!(
                HexU128::parse(text),
                Err(HexU128Error::MissingPrefix),
                "{text:?}"
            );
        }
    }

    #[test]
    fn an_empty_digit_string_is_refused() {
        assert_eq!(HexU128::parse("0x"), Err(HexU128Error::NoDigits));
    }

    /// The case that made the parser strict: `from_str_radix` reads `+ff`
    /// as 255.
    #[test]
    fn a_sign_is_refused() {
        assert_eq!(u128::from_str_radix("+ff", 16), Ok(255), "the leniency");
        for text in ["0x+ff", "0x-ff", "0x+0", "0x-0", "0x+"] {
            assert_eq!(
                HexU128::parse(text),
                Err(HexU128Error::NotAHexDigit),
                "{text:?}"
            );
        }
    }

    #[test]
    fn a_character_outside_the_hex_digits_is_refused() {
        for text in [
            "0xg", "0xfg", "0x ff", "0xff ", "0xf_f", "0x0x1", "0xff\n", "0x1.0", "0x１", "0xé",
        ] {
            assert_eq!(
                HexU128::parse(text),
                Err(HexU128Error::NotAHexDigit),
                "{text:?}"
            );
        }
    }

    /// 33 digits is more than a `u128` holds, whatever the digits are: a
    /// value over `u128::MAX` and a small value padded past the bound are
    /// both refused, and neither reaches the conversion.
    #[test]
    fn more_than_thirty_two_digits_is_refused() {
        let over = format!("0x1{}", "0".repeat(32));
        let padded = format!("0x{}1", "0".repeat(32));
        let long = format!("0x{}", "f".repeat(64));
        for text in [over, padded, long] {
            assert_eq!(
                HexU128::parse(&text),
                Err(HexU128Error::TooManyDigits),
                "{text:?}"
            );
        }
        // Exactly 32 is the bound, and is the largest value.
        assert_eq!(
            HexU128::parse(&format!("0x{}", "f".repeat(32))),
            Ok(HexU128(u128::MAX))
        );
    }

    /// Accepted beyond the written form: upper-case digits and leading
    /// zeros, both of which name one value. What is written is minimal and
    /// lower-case.
    #[test]
    fn upper_case_digits_and_leading_zeros_are_read_and_not_written() {
        assert_eq!(HexU128::parse("0xFF"), Ok(HexU128(255)));
        assert_eq!(HexU128::parse("0x00ff"), Ok(HexU128(255)));
        assert_eq!(
            HexU128::parse(&format!("0x{}", "0".repeat(32))),
            Ok(HexU128(0))
        );
        assert_eq!(HexU128(255).to_string(), "0xff");
    }

    /// On the wire it is a string. A number is not it.
    #[test]
    fn it_is_a_string_on_the_wire() {
        for not_it in [json!(255), json!(null), json!(["0xff"]), json!(true)] {
            assert!(
                serde_json::from_value::<HexU128>(not_it.clone()).is_err(),
                "{not_it}"
            );
        }
        let refusal = serde_json::from_value::<HexU128>(json!("0x+ff"))
            .expect_err("a sign is refused through serde too")
            .to_string();
        assert!(refusal.contains("no sign"), "{refusal}");
    }
}
