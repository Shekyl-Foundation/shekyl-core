// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The wire's kinds, as types (`RPC_WIRE.md` RW-Q4; `INPUT_GRAMMAR.md`
//! IG-Q54).
//!
//! Each kind in the registry is one type with one encoding, and its unit
//! lives here, never in a field's name. A field typed `u64` would say
//! only "a number": the schema gate could not tell a height from a count
//! or an endpoint from an address, so a wire object's field is one of
//! these, [`HashHex`](crate::hash::HashHex), [`HexU128`](crate::hex128::HexU128),
//! `AtomicUnitsString`, or another wire object.

use crate::schema::{Schema, Shape};
use serde::{Deserialize, Serialize};

macro_rules! number_kind {
    ($(#[$meta:meta])* $name:ident($inner:ty) = $kind:literal) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize,
            Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub $inner);

        impl Schema for $name {
            fn shape() -> Shape {
                Shape::Scalar($kind)
            }
        }
    };
}

number_kind! {
    /// A block height: an ordinal. Never a count (`HEIGHT_SEMANTICS.md`).
    Height(u64) = "height"
}
number_kind! {
    /// How many: a count. Never a height.
    Count(u64) = "count"
}
number_kind! {
    /// A plain integer that is neither a height nor a count: a nonce, a
    /// version, an index, a shard's id.
    Integer(u64) = "integer"
}
number_kind! {
    /// A signed integer, where the row allows the sign.
    Signed(i64) = "signed"
}
number_kind! {
    /// A point in time: unix seconds.
    Time(u64) = "time"
}
number_kind! {
    /// A duration: whole seconds.
    Duration(u64) = "duration"
}
number_kind! {
    /// A size or a weight: bytes.
    Size(u64) = "size"
}
number_kind! {
    /// A rate: units per second (bytes under download and upload).
    Rate(u64) = "rate"
}
number_kind! {
    /// A ratio in millionths.
    Micro(u64) = "micro"
}
number_kind! {
    /// A ratio in thousandths.
    Milli(u64) = "milli"
}

impl Schema for bool {
    fn shape() -> Shape {
        Shape::Scalar("switch")
    }
}

macro_rules! text_kind {
    ($(#[$meta:meta])* $name:ident = $kind:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl Schema for $name {
            fn shape() -> Shape {
                Shape::Scalar($kind)
            }
        }
    };
}

text_kind! {
    /// Free text, verbatim: a diagnostic's message, a build's revision.
    Text = "text"
}
text_kind! {
    /// A Shekyl address. Never a network location.
    Address = "address"
}
text_kind! {
    /// A network location: a literal IP and a port, or an onion and a
    /// port. Never a Shekyl address.
    Endpoint = "endpoint"
}
text_kind! {
    /// An absolute path.
    Path = "path"
}
/// A block's or transaction's serialized bytes. On the wire, base64
/// (RFC 4648 §4, padded): the one encoding of the `bytes` kind (RW-Q4,
/// IG-6). Read at the boundary, so text that is not base64 is refused
/// there, never carried inward.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Bytes(pub Vec<u8>);

impl Bytes {
    /// The bytes, as owned.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl Serialize for Bytes {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use base64::Engine as _;
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use base64::Engine as _;
        let text = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(text.as_bytes())
            .map(Self)
            .map_err(|e| serde::de::Error::custom(format!("not base64 (RFC 4648 §4, padded): {e}")))
    }
}

impl Schema for Bytes {
    fn shape() -> Shape {
        Shape::Scalar("bytes")
    }
}

impl Schema for crate::hash::HashHex {
    fn shape() -> Shape {
        Shape::Scalar("hash")
    }
}

impl Schema for crate::hex128::HexU128 {
    fn shape() -> Shape {
        Shape::Scalar("hex128")
    }
}

impl Schema for shekyl_units::wire::AtomicUnitsString {
    fn shape() -> Shape {
        Shape::Scalar("amount")
    }
}

/// Reads `{}` and nothing else: not `null`, not a list, not an object
/// with a key.
fn empty_object<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
    what: &'static str,
) -> Result<(), D::Error> {
    struct Empty(&'static str);
    impl<'de> serde::de::Visitor<'de> for Empty {
        type Value = ();
        fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "an object with no key ({})", self.0)
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
            match map.next_key::<String>()? {
                None => Ok(()),
                Some(key) => Err(serde::de::Error::custom(format!(
                    "`{key}` is not a key here: {} is an object with no key",
                    self.0
                ))),
            }
        }
    }
    deserializer.deserialize_map(Empty(what))
}

fn write_empty<S: serde::Serializer>(serializer: S) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;
    serializer.serialize_map(Some(0))?.end()
}

/// A method's parameters when it takes none: `{}`.
///
/// `()` is JSON `null` in serde, and `null` is not an object of named
/// parameters (RW-Q2). On the envelope, an omitted `params` is the same
/// request ([`Self::from_params`]); `null`, `[]` and any key are refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NoParams;

impl NoParams {
    /// The parameters of a call whose envelope carried `params`, or did
    /// not.
    ///
    /// # Errors
    ///
    /// What was wrong with a `params` that is not `{}`.
    pub fn from_params(params: Option<&serde_json::Value>) -> Result<Self, String> {
        match params {
            None => Ok(Self),
            Some(value) => Self::deserialize(value).map_err(|e| e.to_string()),
        }
    }
}

impl Serialize for NoParams {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        write_empty(serializer)
    }
}

impl<'de> Deserialize<'de> for NoParams {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        empty_object(deserializer, "no parameters").map(|()| Self)
    }
}

impl Schema for NoParams {
    fn shape() -> Shape {
        Shape::Empty
    }
}

/// A reply that says the call succeeded and nothing more: `{}`.
///
/// Not `null`: `null` means no answer (RK-D23), and this is an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Done;

impl Serialize for Done {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        write_empty(serializer)
    }
}

impl<'de> Deserialize<'de> for Done {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        empty_object(deserializer, "a bare success").map(|()| Self)
    }
}

impl Schema for Done {
    fn shape() -> Shape {
        Shape::Empty
    }
}

/// A field shown only under a grant (`RPC_CHANNEL.md` §6.1): the value,
/// or withheld. Withheld is absent on the wire, never `null` and never
/// zero (RK-D23).
///
/// The field carries `#[serde(default, skip_serializing_if =
/// "Withheld::is_withheld")]`. Serializing a withheld value is an error,
/// so a field that forgets the attribute fails the first time it is
/// written rather than sending `null`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Withheld<T> {
    /// The caller is shown the value.
    Shown(T),
    /// The caller's grant does not show it.
    #[default]
    Withheld,
}

impl<T> Withheld<T> {
    /// Whether the value is withheld.
    pub const fn is_withheld(&self) -> bool {
        matches!(self, Self::Withheld)
    }

    /// The value, if shown.
    pub fn shown(self) -> Option<T> {
        match self {
            Self::Shown(value) => Some(value),
            Self::Withheld => None,
        }
    }
}

impl<T: Serialize> Serialize for Withheld<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Shown(value) => value.serialize(serializer),
            Self::Withheld => Err(serde::ser::Error::custom(
                "a withheld field is absent, not written: the field lacks \
                 skip_serializing_if = \"Withheld::is_withheld\"",
            )),
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Withheld<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(Self::Shown)
    }
}

/// The shape of what a [`Withheld`] field holds when shown. `Withheld`
/// has no [`Schema`] of its own, so it cannot be a field without the
/// `[shown …]` bracket that names who is shown it.
pub trait WithheldShape {
    /// The shown value's shape.
    fn inner_shape() -> Shape;
}

impl<T: Schema> WithheldShape for Withheld<T> {
    fn inner_shape() -> Shape {
        T::shape()
    }
}

/// The shape of an optional request parameter when given. A reply field
/// is never optional, so neither `Option<T>` nor a defaulted `bool` has a
/// [`Schema`] of its own: they are fields only with the `[optional]`
/// bracket.
pub trait OptionalShape {
    /// The given value's shape.
    fn inner_shape() -> Shape;
}

impl<T: Schema> OptionalShape for Option<T> {
    fn inner_shape() -> Shape {
        T::shape()
    }
}

impl OptionalShape for bool {
    fn inner_shape() -> Shape {
        Shape::Scalar("switch")
    }
}
