// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What several methods share: keywords, one-key states, the list slot,
//! open maps, the selector, and the parted object `daemon_status` uses.

use crate::schema::{Schema, Shape};
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

/// A key whose only value is JSON `null`, and which may be left out.
///
/// [`Default`] is absent: serde uses it when the key is missing. A present
/// key is read only from `null` ([`Null`]). This is a selector's `tip`
/// (`INPUT_GRAMMAR.md` IG-Q94). `Option<Null>` cannot say it, because
/// serde reads a present `null` as `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum NullKey {
    /// The key was not in the object.
    #[default]
    Absent,
    /// The key was present and its value was `null`.
    Present,
}

impl NullKey {
    /// The key was in the object.
    pub(crate) const fn is_present(self) -> bool {
        matches!(self, Self::Present)
    }
}

impl<'de> Deserialize<'de> for NullKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Null::deserialize(deserializer).map(|Null| Self::Present)
    }
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

impl Selector {
    /// Write the selector's one key into `map`.
    pub(crate) fn write<M: serde::ser::SerializeMap>(&self, map: &mut M) -> Result<(), M::Error> {
        match self {
            Self::Height(height) => map.serialize_entry("height", height),
            Self::Hash(hash) => map.serialize_entry("hash", hash),
            Self::Tip => map.serialize_entry("tip", &Null),
        }
    }
}

/// An object that is exactly one alternative, plus switches that may be
/// left out. The alternatives are the reader and the [`Schema`]: one list,
/// so a selector or a range cannot admit in one what the other refuses.
///
/// A key written `tip: null` is JSON null and nothing else ([`NullKey`]).
/// Any other key is its type. Every key of the chosen alternative is
/// present, and no key of another alternative is. A switch is a `bool`
/// that defaults off, and the schema records it optional.
///
/// `build` receives the chosen alternative and then each switch, and is the
/// value the type stores. Eight alternatives is the ceiling; a ninth does
/// not match the reader, so the build fails.
#[macro_export]
macro_rules! wire_exclusive {
    (
        $name:ident [$holder:literal] keys $keys:ident {
            $($body:tt)*
        }
    ) => {
        $crate::wire_exclusive!(@go $name [$holder] $keys
            typed()
            nulls()
            alts()
            switches()
            $($body)*
        );
    };

    // One alternative. Its keys stay inside `[]`, so a repeated token tree
    // ends on a delimiter and `Vec<HashHex>` is read as a type.
    (@go $name:ident [$holder:literal] $keys:ident
        typed($($typed:tt)*)
        nulls($($nulls:tt)*)
        alts($($alts:tt)*)
        switches($($switches:tt)*)
        [ $($inner:tt)* ] => $build:expr;
        $($rest:tt)*
    ) => {
        $crate::wire_exclusive!(@alt $name [$holder] $keys
            typed($($typed)*)
            nulls($($nulls)*)
            alts($($alts)*)
            switches($($switches)*)
            this()
            [ $($inner)* ]
            => $build;
            $($rest)*
        );
    };

    (@go $name:ident [$holder:literal] $keys:ident
        typed($($typed:tt)*)
        nulls($($nulls:tt)*)
        alts($($alts:tt)*)
        switches($($switches:tt)*)
        switch $sw:ident [$under:literal];
        $($rest:tt)*
    ) => {
        $crate::wire_exclusive!(@go $name [$holder] $keys
            typed($($typed)*)
            nulls($($nulls)*)
            alts($($alts)*)
            switches($($switches)* $sw [$under];)
            $($rest)*
        );
    };

    (@go $name:ident [$holder:literal] $keys:ident
        typed($($typed:tt)*)
        nulls($($nulls:tt)*)
        alts($($alts:tt)*)
        switches($($switches:tt)*)
        build ( $select:ident $(, $arg:ident)* ) $body:expr
    ) => {
        $crate::wire_exclusive!(@emit $name [$holder] $keys
            typed($($typed)*)
            nulls($($nulls)*)
            alts($($alts)*)
            switches($($switches)*)
            build($select $(, $arg)*) $body
        );
    };

    (@alt $name:ident [$holder:literal] $keys:ident
        typed($($typed:tt)*)
        nulls($($nulls:tt)*)
        alts($($alts:tt)*)
        switches($($switches:tt)*)
        this($($this:tt)*)
        [ $key:ident : null, $($more:tt)* ]
        => $build:expr;
        $($rest:tt)*
    ) => {
        $crate::wire_exclusive!(@alt $name [$holder] $keys
            typed($($typed)*)
            nulls($($nulls)* $key,)
            alts($($alts)*)
            switches($($switches)*)
            this($($this)* $key : null,)
            [ $($more)* ]
            => $build;
            $($rest)*
        );
    };

    (@alt $name:ident [$holder:literal] $keys:ident
        typed($($typed:tt)*)
        nulls($($nulls:tt)*)
        alts($($alts:tt)*)
        switches($($switches:tt)*)
        this($($this:tt)*)
        [ $key:ident : null ]
        => $build:expr;
        $($rest:tt)*
    ) => {
        $crate::wire_exclusive!(@go $name [$holder] $keys
            typed($($typed)*)
            nulls($($nulls)* $key,)
            alts($($alts)* alt ( $($this)* $key : null, ) => $build;)
            switches($($switches)*)
            $($rest)*
        );
    };

    (@alt $name:ident [$holder:literal] $keys:ident
        typed($($typed:tt)*)
        nulls($($nulls:tt)*)
        alts($($alts:tt)*)
        switches($($switches:tt)*)
        this($($this:tt)*)
        [ $key:ident : $ty:ty, $($more:tt)* ]
        => $build:expr;
        $($rest:tt)*
    ) => {
        $crate::wire_exclusive!(@alt $name [$holder] $keys
            typed($($typed)* $key : $ty,)
            nulls($($nulls)*)
            alts($($alts)*)
            switches($($switches)*)
            this($($this)* $key : ($ty),)
            [ $($more)* ]
            => $build;
            $($rest)*
        );
    };

    (@alt $name:ident [$holder:literal] $keys:ident
        typed($($typed:tt)*)
        nulls($($nulls:tt)*)
        alts($($alts:tt)*)
        switches($($switches:tt)*)
        this($($this:tt)*)
        [ $key:ident : $ty:ty ]
        => $build:expr;
        $($rest:tt)*
    ) => {
        $crate::wire_exclusive!(@go $name [$holder] $keys
            typed($($typed)* $key : $ty,)
            nulls($($nulls)*)
            alts($($alts)* alt ( $($this)* $key : ($ty), ) => $build;)
            switches($($switches)*)
            $($rest)*
        );
    };

    (@emit $name:ident [$holder:literal] $keys:ident
        typed( $($tkey:ident : $tty:ty,)* )
        nulls( $($nkey:ident,)* )
        alts( $( alt ( $($key:ident : $kind:tt),* $(,)? ) => $build:expr ; )* )
        switches( $( $sw:ident [$under:literal] ; )* )
        build( $select:ident $(, $arg:ident)* ) $body:expr
    ) => {
        #[derive(::serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct $keys {
            $(
                #[serde(default)]
                $tkey: ::core::option::Option<$tty>,
            )*
            $(
                #[serde(default)]
                $nkey: $crate::wire::shared::NullKey,
            )*
            $(
                #[serde(default)]
                $sw: bool,
            )*
        }

        const _: () = {
            $($crate::method::assert_name(::core::stringify!($tkey));)*
            $($crate::method::assert_name(::core::stringify!($nkey));)*
            $($crate::method::assert_name(::core::stringify!($sw));)*
        };

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> ::core::result::Result<Self, D::Error> {
                let mut keys = $keys::deserialize(deserializer)?;
                let states = [$(
                    {
                        let present = [$($crate::wire_exclusive!(@flag keys.$key : $kind)),*];
                        $crate::schema::group_presence(
                            present.iter().filter(|flag| **flag).count(),
                            present.len(),
                        )
                    },
                )*];
                if $crate::schema::exclusive_index(&states).is_err() {
                    let alternatives = $crate::schema::format_alternatives(&[
                        $( &[ $(::core::stringify!($key)),* ] ),*
                    ]);
                    return ::core::result::Result::Err(::serde::de::Error::custom(
                        ::std::format!("name exactly one of {alternatives}"),
                    ));
                }
                let $select = $crate::wire_exclusive!(@pick keys states
                    [ $( alt ( $($key : $kind),* ) => $build ; )* ]
                    0 1 2 3 4 5 6 7
                );
                $(let $arg = keys.$arg;)*
                ::core::result::Result::Ok($body)
            }
        }

        impl $crate::schema::Schema for $name {
            fn shape() -> $crate::schema::Shape {
                $crate::schema::Shape::Object {
                    holder: $holder,
                    fields: ::std::vec![$(
                        $crate::schema::Field {
                            name: ::core::stringify!($sw),
                            under: ::core::option::Option::Some($under),
                            shape: $crate::schema::Shape::Optional(::std::boxed::Box::new(
                                <bool as $crate::schema::Schema>::shape(),
                            )),
                        },
                    )*],
                    parts: ::std::vec::Vec::new(),
                    choice: ::std::vec![$(
                        ::std::vec![$(
                            $crate::wire_exclusive!(@shape $key : $kind),
                        )*],
                    )*],
                }
            }
        }
    };

    (@flag $keys:ident . $key:ident : null) => {
        $keys.$key.is_present()
    };
    (@flag $keys:ident . $key:ident : ($ty:ty)) => {
        $keys.$key.is_some()
    };

    (@shape $key:ident : null) => {
        $crate::schema::Field {
            name: ::core::stringify!($key),
            under: ::core::option::Option::None,
            shape: $crate::schema::Shape::Null,
        }
    };
    (@shape $key:ident : ($ty:ty)) => {
        $crate::schema::Field {
            name: ::core::stringify!($key),
            under: ::core::option::Option::None,
            shape: <$ty as $crate::schema::Schema>::shape(),
        }
    };

    // Eight alternatives is the ceiling. The index tokens are peeled one
    // literal at a time; a ninth alternative does not match.
    (@pick $var:ident $states:ident
        [
            alt ( $($key:ident : $kind:tt),* $(,)? ) => $build:expr ;
            $($more:tt)*
        ]
        $n:tt $($rest:tt)*
    ) => {
        if ::core::matches!($states[$n], $crate::schema::GroupPresence::Complete) {
            $($crate::wire_exclusive!(@bind $var, $key : $kind);)*
            $build
        } else {
            $crate::wire_exclusive!(@pick $var $states [ $($more)* ] $($rest)*)
        }
    };
    (@pick $var:ident $states:ident [ ] $($rest:tt)*) => {
        ::core::unreachable!("exclusive_index found a complete alternative")
    };

    (@bind $var:ident, $key:ident : null) => {};
    (@bind $var:ident, $key:ident : ($ty:ty)) => {
        let $key: $ty = $var.$key.take().expect("this alternative is complete");
    };
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
