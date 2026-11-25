// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! f64 fields of the whole-economy summary, decoded from the decimal text
//! serde_json wrote.
//!
//! serde_json's default f64 parse can land one ULP off a number it just
//! wrote. The narration prints fee variances past an f64's precision, so
//! that ULP changes a recorded summary's narration. Parsing the decimal
//! with [`f64::from_str`] reads the bits back. The `float_roundtrip`
//! feature would do this inside serde_json and change f64 parsing for
//! every crate in a workspace build that includes this binary.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Deserializer, Visitor};
use serde::Deserialize;
use serde_json::value::RawValue;

/// `text` as an f64, or why it is not one.
fn parse_number(text: &str) -> Result<f64, String> {
    f64::from_str(text).map_err(|_| format!("a summary number reads as an f64: {text}"))
}

/// One JSON number, from its decimal text.
pub(crate) fn de_f64<'de, D>(deserializer: D) -> Result<f64, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Box::<RawValue>::deserialize(deserializer)?;
    parse_number(raw.get()).map_err(de::Error::custom)
}

/// `N` JSON numbers, each from its decimal text.
fn de_n<'de, D, const N: usize>(deserializer: D) -> Result<[f64; N], D::Error>
where
    D: Deserializer<'de>,
{
    let raws = Vec::<Box<RawValue>>::deserialize(deserializer)?;
    if raws.len() != N {
        return Err(de::Error::custom(format!(
            "a summary array has {N} numbers, and this one has {}",
            raws.len()
        )));
    }
    let mut out = [0.0; N];
    for (slot, raw) in out.iter_mut().zip(raws) {
        *slot = parse_number(raw.get()).map_err(de::Error::custom)?;
    }
    Ok(out)
}

/// Two JSON numbers.
pub(crate) fn de_f64_2<'de, D>(deserializer: D) -> Result<[f64; 2], D::Error>
where
    D: Deserializer<'de>,
{
    de_n(deserializer)
}

/// Three JSON numbers.
pub(crate) fn de_f64_3<'de, D>(deserializer: D) -> Result<[f64; 3], D::Error>
where
    D: Deserializer<'de>,
{
    de_n(deserializer)
}

/// Four JSON numbers.
pub(crate) fn de_f64_4<'de, D>(deserializer: D) -> Result<[f64; 4], D::Error>
where
    D: Deserializer<'de>,
{
    de_n(deserializer)
}

/// A JSON number or null.
pub(crate) fn de_opt_f64<'de, D>(deserializer: D) -> Result<Option<f64>, D::Error>
where
    D: Deserializer<'de>,
{
    struct V;

    impl<'de> Visitor<'de> for V {
        type Value = Option<f64>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a summary number or null")
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D2>(self, deserializer: D2) -> Result<Self::Value, D2::Error>
        where
            D2: Deserializer<'de>,
        {
            de_f64(deserializer).map(Some)
        }
    }

    deserializer.deserialize_option(V)
}

/// Nine JSON numbers or null.
pub(crate) fn de_opt_f64_9<'de, D>(deserializer: D) -> Result<Option<[f64; 9]>, D::Error>
where
    D: Deserializer<'de>,
{
    struct V;

    impl<'de> Visitor<'de> for V {
        type Value = Option<[f64; 9]>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("nine summary numbers or null")
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D2>(self, deserializer: D2) -> Result<Self::Value, D2::Error>
        where
            D2: Deserializer<'de>,
        {
            de_n(deserializer).map(Some)
        }
    }

    deserializer.deserialize_option(V)
}

/// A pair of JSON numbers or null.
pub(crate) fn de_opt_pair<'de, D>(deserializer: D) -> Result<Option<(f64, f64)>, D::Error>
where
    D: Deserializer<'de>,
{
    struct V;

    impl<'de> Visitor<'de> for V {
        type Value = Option<(f64, f64)>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("two summary numbers or null")
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D2>(self, deserializer: D2) -> Result<Self::Value, D2::Error>
        where
            D2: Deserializer<'de>,
        {
            let (left, right) = <(Box<RawValue>, Box<RawValue>)>::deserialize(deserializer)?;
            let pair = (
                parse_number(left.get()).map_err(de::Error::custom)?,
                parse_number(right.get()).map_err(de::Error::custom)?,
            );
            Ok(Some(pair))
        }
    }

    deserializer.deserialize_option(V)
}
