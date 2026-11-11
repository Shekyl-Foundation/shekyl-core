// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What several methods share: keywords, one-key states, the list slot,
//! open maps, the selector, and the parted object `daemon_status` uses.

use crate::schema::{Field, Schema, Shape};
use serde::{Deserialize, Serialize};

/// Refuse, at compile time, a keyword that is not lowercase segments
/// joined with `-` (`INPUT_GRAMMAR.md` IG-Q86).
///
/// # Panics
///
/// In a const context, which fails the build.
pub const fn assert_keyword(word: &str) {
    let bytes = word.as_bytes();
    assert!(!bytes.is_empty(), "a keyword is not empty");
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let ok = if b == b'-' {
            i > 0 && i + 1 < bytes.len() && bytes[i - 1] != b'-'
        } else {
            b.is_ascii_lowercase() || (b.is_ascii_digit() && i > 0)
        };
        assert!(
            ok,
            "a keyword is lowercase segments joined with `-` (IG-Q86)"
        );
        i += 1;
    }
}

/// A closed keyword set, one Rust variant per keyword.
#[macro_export]
macro_rules! wire_keywords {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $($(#[$vmeta:meta])* $variant:ident = $word:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, Hash, ::serde::Serialize, ::serde::Deserialize,
        )]
        $vis enum $name {
            $($(#[$vmeta])* #[serde(rename = $word)] $variant),+
        }

        impl $crate::schema::Schema for $name {
            fn shape() -> $crate::schema::Shape {
                $crate::schema::Shape::OneOf(&[$($word),+])
            }
        }

        const _: () = { $($crate::wire::shared::assert_keyword($word);)+ };
    };
}

/// One-key states (`INPUT_GRAMMAR.md` IG-Q70): each variant is written as
/// an object with one key, its keyword, whose value is its payload, or
/// `null` when the payload is [`Null`].
#[macro_export]
macro_rules! wire_states {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $($(#[$vmeta:meta])* $variant:ident($payload:ty) = $word:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, ::serde::Serialize, ::serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        $vis enum $name {
            $($(#[$vmeta])* #[serde(rename = $word)] $variant($payload)),+
        }

        impl $crate::schema::Schema for $name {
            fn shape() -> $crate::schema::Shape {
                $crate::schema::Shape::States(::std::vec![
                    $(($word, <$payload as $crate::wire::shared::Payload>::payload())),+
                ])
            }
        }

        const _: () = { $($crate::wire::shared::assert_keyword($word);)+ };
    };
}

/// A state with no payload: written `null`, and read only from `null`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Null;

impl Serialize for Null {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_unit()
    }
}

impl<'de> Deserialize<'de> for Null {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <()>::deserialize(deserializer).map(|()| Self)
    }
}

/// Read a `tip` key that is present: its value must be `null`. An absent
/// key is the field's `default`, `None`.
///
/// # Errors
///
/// The value is not `null`.
pub fn tip_given<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Null>, D::Error> {
    Null::deserialize(deserializer).map(Some)
}

/// A state's payload shape: `None` for [`Null`].
pub trait Payload {
    /// The payload's shape, if it has one.
    fn payload() -> Option<Shape>;
}

impl Payload for Null {
    fn payload() -> Option<Shape> {
        None
    }
}

impl<T: Schema> Payload for T {
    fn payload() -> Option<Shape> {
        Some(T::shape())
    }
}

/// A map whose keys come from a runtime table (an option's name, a
/// diagnostic's parameter), each key once.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OpenMap<V>(pub std::collections::BTreeMap<String, V>);

impl<V: Schema> Schema for OpenMap<V> {
    fn shape() -> Shape {
        Shape::Map {
            keys: None,
            value: Box::new(V::shape()),
        }
    }
}

crate::wire_object! {
    /// A body discarded with its shard at the archival horizon: the
    /// archive serves it (`DRS_SB_BELOW_HORIZON.md` SB-Q2).
    ["tx"]
    pub struct Archived {
        pub id: crate::hash::HashHex,
        pub shard: crate::kinds::Integer,
    }
}

crate::wire_states! {
    /// What stands in a list reply's slot when the item does not
    /// (`INPUT_GRAMMAR.md` IG-Q73).
    pub enum SlotState {
        /// The node was asked and holds no such item.
        Missing(Null) = "missing",
        /// The body was discarded with its shard; the archive serves it.
        Archived(Archived) = "archived",
    }
}

/// One slot of a `list` reply (IG-Q73): the item, a state, or `null` where
/// the item's source could not be asked (RK-D23).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Slot<T> {
    /// The item.
    Item(T),
    /// A state in the item's place.
    State(SlotState),
    /// The item's source could not be asked.
    Unasked,
}

impl<T: Schema> Schema for Slot<T> {
    fn shape() -> Shape {
        Shape::Either(
            Box::new(T::shape()),
            Box::new(Shape::Nullable(Box::new(SlotState::shape()))),
        )
    }
}

/// An item, or the archived state in its place: a `show` of a body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OrArchived<T> {
    /// The item.
    Item(T),
    /// The body was discarded with its shard.
    Archived(ArchivedState),
}

crate::wire_states! {
    /// The one state a `show` of a body may answer in its item's place.
    pub enum ArchivedState {
        /// The body was discarded with its shard.
        Archived(Archived) = "archived",
    }
}

impl<T: Schema> Schema for OrArchived<T> {
    fn shape() -> Shape {
        Shape::Either(Box::new(T::shape()), Box::new(ArchivedState::shape()))
    }
}

/// Which block a selector names (IG-Q94): exactly one of a height, a hash,
/// or the tip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selector {
    /// The block at this height.
    Height(crate::kinds::Height),
    /// The block with this hash.
    Hash(crate::hash::HashHex),
    /// The chain's last block.
    Tip,
}

/// A selector's keys, read before one is chosen. Each is a key that may
/// be absent; `tip` is present when it is `null`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SelectorKeys {
    #[serde(default)]
    pub height: Option<crate::kinds::Height>,
    #[serde(default)]
    pub hash: Option<crate::hash::HashHex>,
    #[serde(default, deserialize_with = "crate::wire::shared::tip_given")]
    pub tip: Option<Null>,
}

impl Selector {
    /// The one selector `keys` name.
    ///
    /// # Errors
    ///
    /// None named, or more than one.
    pub(crate) fn one(
        height: Option<crate::kinds::Height>,
        hash: Option<crate::hash::HashHex>,
        tip: Option<Null>,
        hash_allowed: bool,
    ) -> Result<Self, String> {
        let keys = if hash_allowed {
            "height, hash or tip"
        } else {
            "height or tip"
        };
        match (height, hash, tip) {
            (Some(height), None, None) => Ok(Self::Height(height)),
            (None, Some(hash), None) if hash_allowed => Ok(Self::Hash(hash)),
            (None, None, Some(Null)) => Ok(Self::Tip),
            (None, None, None) => Err(format!("name exactly one of {keys}; none was given")),
            _ => Err(format!(
                "name exactly one of {keys}; more than one was given"
            )),
        }
    }

    /// Write the selector's one key into `map`.
    pub(crate) fn write<M: serde::ser::SerializeMap>(&self, map: &mut M) -> Result<(), M::Error> {
        match self {
            Self::Height(height) => map.serialize_entry("height", height),
            Self::Hash(hash) => map.serialize_entry("hash", hash),
            Self::Tip => map.serialize_entry("tip", &Null),
        }
    }

    /// The selector's choice fields.
    pub(crate) fn choice(hash_allowed: bool) -> Vec<Field> {
        let mut choice = vec![Field {
            name: "height",
            under: None,
            shape: crate::kinds::Height::shape(),
        }];
        if hash_allowed {
            choice.push(Field {
                name: "hash",
                under: None,
                shape: crate::hash::HashHex::shape(),
            });
        }
        choice.push(Field {
            name: "tip",
            under: None,
            shape: Shape::Nullable(Box::new(Shape::Empty)),
        });
        choice
    }
}

/// An object some of whose fields are shown in parts, each whole or not at
/// all (`RPC_CHANNEL.md` §6.1; RK-D23).
///
/// Every part field is a [`Withheld`](crate::kinds::Withheld). The macro
/// writes the struct, a reader that refuses a part partly present, and a
/// [`Schema`] whose parts name who is shown each.
#[macro_export]
macro_rules! wire_parted {
    (
        $(#[$meta:meta])*
        [$holder:literal]
        $vis:vis struct $name:ident {
            $($(#[$fmeta:meta])* $field:ident : $fty:ty),* $(,)?
            ;
            $(
                part $policy:expr => {
                    $($(#[$pmeta:meta])* $pfield:ident : $pty:ty),+ $(,)?
                }
            )+
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, ::serde::Serialize, ::serde::Deserialize)]
        #[serde(deny_unknown_fields, try_from = "Raw")]
        $vis struct $name {
            $($(#[$fmeta])* pub $field: $fty,)*
            $($(
                $(#[$pmeta])*
                #[serde(default, skip_serializing_if = "crate::kinds::Withheld::is_withheld")]
                pub $pfield: $crate::kinds::Withheld<$pty>,
            )+)+
        }

        #[derive(::serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            $($field: $fty,)*
            $($(
                #[serde(default)]
                $pfield: $crate::kinds::Withheld<$pty>,
            )+)+
        }

        impl ::core::convert::TryFrom<Raw> for $name {
            type Error = ::std::string::String;
            fn try_from(raw: Raw) -> ::core::result::Result<Self, Self::Error> {
                $({
                    let present = [$(!raw.$pfield.is_withheld()),+];
                    if present.iter().any(|p| *p) && !present.iter().all(|p| *p) {
                        return ::core::result::Result::Err(::std::format!(
                            "the part shown to {} is partly present",
                            $crate::schema::policy_word($policy)
                        ));
                    }
                })+
                ::core::result::Result::Ok(Self {
                    $($field: raw.$field,)*
                    $($($pfield: raw.$pfield,)+)+
                })
            }
        }

        const _: () = {
            $($crate::method::assert_name(::core::stringify!($field));)*
            $($($crate::method::assert_name(::core::stringify!($pfield));)+)+
        };

        impl $crate::schema::Schema for $name {
            fn shape() -> $crate::schema::Shape {
                $crate::schema::Shape::Object {
                    holder: $holder,
                    fields: ::std::vec![$($crate::schema::Field {
                        name: ::core::stringify!($field),
                        under: ::core::option::Option::None,
                        shape: <$fty as $crate::schema::Schema>::shape(),
                    }),*],
                    parts: ::std::vec![$($crate::schema::Part {
                        shown_to: $policy,
                        fields: ::std::vec![$($crate::schema::Field {
                            name: ::core::stringify!($pfield),
                            under: ::core::option::Option::None,
                            shape: <$pty as $crate::schema::Schema>::shape(),
                        }),+],
                    }),+],
                    choice: ::std::vec::Vec::new(),
                }
            }
        }
    };
}
