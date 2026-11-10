// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The wire's schema, read from its types (`RPC_WIRE.md` RW-Q7).
//!
//! Every request and reply type states what it is: the object it describes
//! (its *holder*, a glossary path: `block header`, `peer connection`) and
//! each field's name and kind. The method table lists each method's two
//! types, so every method, parameter and reply-field name on the wire is
//! reachable from the table, with the holder its walk starts from
//! (`INPUT_GRAMMAR.md` IG-Q42). [`names`] is that list. The grammar's walk
//! gate reads it; no table of names is kept by hand.
//!
//! A type joins the schema through [`wire_object!`](crate::wire_object),
//! which writes the struct and its [`Schema`] together, so a field cannot
//! exist on the wire without a row here. A field's wire name is its Rust
//! identifier: the macro has no rename.

/// What a wire value is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Shape {
    /// A scalar of one kind (`RPC_WIRE.md` RW-Q4's registry: `integer`,
    /// `switch`, `hash`, `bytes`, `amount`, …).
    Scalar(&'static str),
    /// One keyword of a closed set.
    OneOf(&'static [&'static str]),
    /// An object: its holder, and its fields.
    Object {
        /// The glossary path of what the object describes.
        holder: &'static str,
        /// Its fields, in declaration order.
        fields: Vec<Field>,
    },
    /// A list of one shape.
    List(Box<Shape>),
    /// The shape, or `null`: no answer (RK-D23).
    Nullable(Box<Shape>),
    /// A map from a closed keyword set to one shape (IG-6's map).
    Map(Box<Shape>),
    /// Exactly one of several one-key objects, each a named state with its
    /// payload (`INPUT_GRAMMAR.md` IG-Q70). `None` is a state with no
    /// payload, written `null`.
    States(Vec<(&'static str, Option<Shape>)>),
    /// Either shape: an item, or what stands in its slot.
    Either(Box<Shape>, Box<Shape>),
    /// Nothing: a method with no parameters, or no reply beyond success.
    Empty,
}

/// One field of an object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    /// The name on the wire.
    pub name: &'static str,
    /// The holder this name walks under, when it is not the object's own:
    /// a modifier names what it modifies (`tx` for `prune`, IG-Q42).
    pub under: Option<&'static str>,
    /// What it holds.
    pub shape: Shape,
}

/// A type that states its wire shape.
pub trait Schema {
    /// The shape of this type on the wire.
    fn shape() -> Shape;
}

macro_rules! scalar {
    ($kind:literal: $($ty:ty),+ $(,)?) => {
        $(impl Schema for $ty {
            fn shape() -> Shape {
                Shape::Scalar($kind)
            }
        })+
    };
}

scalar!("integer": u8, u16, u32, u64, i64, core::num::NonZeroU32);
scalar!("switch": bool);
scalar!("text": String);
scalar!("hash": crate::hash::HashHex);
scalar!("hex128": crate::hex128::HexU128);
scalar!("amount": shekyl_units::wire::AtomicUnitsString);

impl Schema for () {
    fn shape() -> Shape {
        Shape::Empty
    }
}

impl<T: Schema> Schema for Vec<T> {
    fn shape() -> Shape {
        Shape::List(Box::new(T::shape()))
    }
}

// `Option<T>` has no shape, on purpose: serde reads a missing key into
// `None`, and a reply field is never optional (RW-Q4). No answer is
// [`Nullable`](crate::nullable::Nullable), whose key is required.

impl<T: Schema> Schema for crate::nullable::Nullable<T> {
    fn shape() -> Shape {
        Shape::Nullable(Box::new(T::shape()))
    }
}

/// Which kind of name a walked name is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NameKind {
    /// A method's name: it walks from a subject and ends in a command.
    Method,
    /// A parameter of a method's request.
    Parameter,
    /// A field of a method's reply, or of an object nested in either.
    Field,
}

impl NameKind {
    /// The word the generated schema file carries.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Method => "method",
            Self::Parameter => "parameter",
            Self::Field => "field",
        }
    }
}

/// One name the wire carries, with where its walk starts.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WalkName {
    /// The method whose request or reply carries the name.
    pub method: &'static str,
    /// What kind of name it is.
    pub kind: NameKind,
    /// The holder's glossary path; empty for a method name.
    pub holder: &'static str,
    /// The name.
    pub name: &'static str,
    /// The field's kind, as the schema file shows it.
    pub shape: String,
}

/// A short rendering of a shape, for the generated schema file.
#[must_use]
pub fn describe(shape: &Shape) -> String {
    match shape {
        Shape::Scalar(kind) => (*kind).to_owned(),
        Shape::OneOf(words) => format!("one-of {}", words.join("|")),
        Shape::Object { holder, .. } => format!("object ({holder})"),
        Shape::List(inner) => format!("list of {}", describe(inner)),
        Shape::Nullable(inner) => format!("{} or null", describe(inner)),
        Shape::Map(inner) => format!("map to {}", describe(inner)),
        Shape::States(states) => {
            let keys: Vec<&str> = states.iter().map(|(key, _)| *key).collect();
            format!("state {}", keys.join("|"))
        }
        Shape::Either(item, slot) => format!("{}, or {}", describe(item), describe(slot)),
        Shape::Empty => "nothing".to_owned(),
    }
}

fn walk(method: &'static str, kind: NameKind, shape: &Shape, out: &mut Vec<WalkName>) {
    match shape {
        Shape::Object { holder, fields } => {
            for field in fields {
                out.push(WalkName {
                    method,
                    kind,
                    holder: field.under.unwrap_or(holder),
                    name: field.name,
                    shape: describe(&field.shape),
                });
                // What a parameter holds is described like a reply's
                // fields: only the request's own keys are parameters.
                walk(method, NameKind::Field, &field.shape, out);
            }
        }
        Shape::List(inner) | Shape::Nullable(inner) | Shape::Map(inner) => {
            walk(method, kind, inner, out);
        }
        Shape::States(states) => {
            for (_, payload) in states {
                if let Some(payload) = payload {
                    walk(method, kind, payload, out);
                }
            }
        }
        Shape::Either(item, slot) => {
            walk(method, kind, item, out);
            walk(method, kind, slot, out);
        }
        Shape::Scalar(_) | Shape::OneOf(_) | Shape::Empty => {}
    }
}

/// Every name `rows` put on the wire: each method's name, each parameter
/// and each reply field, with the holder its walk starts from.
#[must_use]
pub fn names(rows: &[crate::method::Row]) -> Vec<WalkName> {
    let mut out = Vec::new();
    for row in rows {
        out.push(WalkName {
            method: row.name,
            kind: NameKind::Method,
            holder: "",
            name: row.name,
            shape: String::new(),
        });
        walk(row.name, NameKind::Parameter, &(row.request)(), &mut out);
        walk(row.name, NameKind::Field, &(row.reply)(), &mut out);
    }
    out
}

/// The generated schema file: one tab-separated line for each name, in
/// table order. The docs gate holds the committed file equal to this, and
/// the grammar's walk gate reads the file.
#[must_use]
pub fn render(rows: &[crate::method::Row]) -> String {
    let mut text = String::from("# method\tkind\tholder\tname\tshape\n");
    for name in names(rows) {
        text.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            name.method,
            name.kind.word(),
            name.holder,
            name.name,
            name.shape
        ));
    }
    text
}

/// A wire object: the struct, its serde derives and its [`Schema`], written
/// together.
///
/// The holder is the glossary path of what the object describes. A field
/// that walks under another holder says so in brackets (a modifier,
/// IG-Q42). Every field is required on the wire and unknown keys are
/// refused; a field with no answer is `Nullable`, written `null` (RK-D23).
/// `Option` is not a wire shape: serde would read a missing key into it.
///
/// ```
/// shekyl_rpc_types::wire_object! {
///     /// The chain's tip.
///     ["chain"]
///     pub struct Tip {
///         /// The tip's height.
///         pub height: u64,
///     }
/// }
/// ```
#[macro_export]
macro_rules! wire_object {
    (
        $(#[$meta:meta])*
        [$holder:literal]
        $vis:vis struct $name:ident {
            $(
                $(#[$fmeta:meta])*
                $fvis:vis $field:ident $([$under:literal])? : $fty:ty
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, ::serde::Serialize, ::serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        $vis struct $name {
            $(
                $(#[$fmeta])*
                $fvis $field: $fty,
            )*
        }

        impl $crate::schema::Schema for $name {
            fn shape() -> $crate::schema::Shape {
                $crate::schema::Shape::Object {
                    holder: $holder,
                    fields: ::std::vec![
                        $($crate::schema::Field {
                            name: ::core::stringify!($field),
                            under: $crate::wire_object!(@under $($under)?),
                            shape: <$fty as $crate::schema::Schema>::shape(),
                        },)*
                    ],
                }
            }
        }
    };
    (@under) => { ::core::option::Option::None };
    (@under $under:literal) => { ::core::option::Option::Some($under) };
}

#[cfg(test)]
mod tests {
    use super::*;

    wire_object! {
        /// A header, as a test sees it.
        ["block header"]
        pub struct Header {
            pub height: u64,
            pub hash: crate::hash::HashHex,
            pub pow: crate::nullable::Nullable<crate::hash::HashHex>,
        }
    }

    wire_object! {
        ["block"]
        pub struct Select {
            pub height: Vec<u64>,
            pub prune ["tx"]: bool,
        }
    }

    fn row() -> crate::method::Row {
        crate::method::Row {
            name: "block_header_list",
            policy: crate::method::Policy::Grant(shekyl_rpc_grants::Grant::Chain),
            request: Select::shape,
            reply: <Vec<Header>>::shape,
        }
    }

    /// A field's name is its identifier, its holder is the object's, and a
    /// modifier walks under the holder it names. Red edit: drop `under`
    /// from the walk and `prune` walks under `block`.
    #[test]
    fn every_name_carries_the_holder_its_walk_starts_from() {
        let walked: Vec<(NameKind, &str, &str)> = names(&[row()])
            .into_iter()
            .map(|name| (name.kind, name.holder, name.name))
            .collect();
        assert_eq!(
            walked,
            [
                (NameKind::Method, "", "block_header_list"),
                (NameKind::Parameter, "block", "height"),
                (NameKind::Parameter, "tx", "prune"),
                (NameKind::Field, "block header", "height"),
                (NameKind::Field, "block header", "hash"),
                (NameKind::Field, "block header", "pow"),
            ]
        );
    }

    /// The struct the macro writes refuses an unknown key and a missing
    /// one, and writes an unanswered field as `null`.
    #[test]
    fn a_wire_object_is_strict_and_writes_null_for_no_answer() {
        let header: Header = serde_json::from_value(serde_json::json!({
            "height": 7,
            "hash": "00".repeat(32),
            "pow": null,
        }))
        .expect("a header");
        assert_eq!(
            serde_json::to_value(&header).unwrap()["pow"],
            serde_json::Value::Null
        );
        assert!(serde_json::from_value::<Header>(serde_json::json!({
            "height": 7, "hash": "00".repeat(32), "pow": null, "extra": 1,
        }))
        .is_err());
        assert!(serde_json::from_value::<Header>(serde_json::json!({
            "height": 7, "hash": "00".repeat(32),
        }))
        .is_err());
    }

    #[test]
    fn the_rendered_schema_is_one_line_for_each_name() {
        let text = render(&[row()]);
        assert_eq!(text.lines().count(), 7);
        assert!(text.contains("block_header_list\tparameter\ttx\tprune\tswitch\n"));
        assert!(text.contains("block_header_list\tfield\tblock header\tpow\thash or null\n"));
    }
}
