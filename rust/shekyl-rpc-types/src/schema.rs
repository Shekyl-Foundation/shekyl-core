// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The wire's schema, read from its types (`RPC_WIRE.md` RW-Q7).
//!
//! Every request and reply type states what it is: the object it describes
//! (its *holder*, a glossary path: `block header`, `peer connection`),
//! each field's name and kind, and who is shown it. The method table lists
//! each method's two types, so every method, parameter and reply-field
//! name on the wire is reachable from the table, with the holder its walk
//! starts from (`INPUT_GRAMMAR.md` IG-Q42). [`names`] is that list. The
//! grammar's walk gate reads it; no table of names is kept by hand.
//!
//! A type joins the schema through [`wire_object!`](crate::wire_object),
//! which writes the struct and its [`Schema`] together, so a field cannot
//! exist on the wire without a row here. A field's wire name is its Rust
//! identifier: the macro has no rename.
//!
//! A shape written by hand (a state, a map, a reply with grant-withheld
//! parts) can drift from what serde writes. [`conforms`] checks a JSON
//! value against a shape; run over every method's vectors in both
//! directions, it makes the schema the contract and not a description.

use crate::method::Policy;

/// What a wire value is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Shape {
    /// A scalar of one kind (`RPC_WIRE.md` RW-Q4's registry). The kinds
    /// are [`crate::kinds`]' types, and the names are theirs.
    Scalar(&'static str),
    /// One keyword of a closed set.
    OneOf(&'static [&'static str]),
    /// An object: its holder, its fields, and its grant-withheld parts.
    Object {
        /// The glossary path of what the object describes.
        holder: &'static str,
        /// Its fields, in declaration order.
        fields: Vec<Field>,
        /// Fields flattened into the object and shown together or not at
        /// all: a part the caller's grant does not show is absent whole.
        parts: Vec<Part>,
    },
    /// A list of one shape.
    List(Box<Shape>),
    /// The shape, or `null`: no answer (RK-D23).
    Nullable(Box<Shape>),
    /// A map from a closed keyword set to one shape (IG-6's map). A key
    /// may be absent; no key appears twice.
    Map {
        /// The keys a document may carry.
        keys: &'static [&'static str],
        /// What each key holds.
        value: Box<Shape>,
    },
    /// Exactly one of several one-key objects, each a named state with its
    /// payload (`INPUT_GRAMMAR.md` IG-Q70). `None` is a state with no
    /// payload, written `null`.
    States(Vec<(&'static str, Option<Shape>)>),
    /// Either shape: an item, or what stands in its slot.
    Either(Box<Shape>, Box<Shape>),
    /// A field shown only to a caller `shown_to` admits; to any other it
    /// is absent, never emptied (RK-D23).
    Hidden {
        /// Who is shown it.
        shown_to: Policy,
        /// What it holds when shown.
        inner: Box<Shape>,
    },
    /// An object with no key: a method with no parameters, or a reply
    /// that says only that the call succeeded.
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

/// Fields flattened into an object and shown as one (`RPC_CHANNEL.md`
/// §6.1): all present to a caller `shown_to` admits, all absent otherwise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    /// Who is shown the part.
    pub shown_to: Policy,
    /// Its fields.
    pub fields: Vec<Field>,
}

/// A type that states its wire shape.
pub trait Schema {
    /// The shape of this type on the wire.
    fn shape() -> Shape;
}

impl<T: Schema> Schema for Vec<T> {
    fn shape() -> Shape {
        Shape::List(Box::new(T::shape()))
    }
}

// `Option<T>` and `()` have no shape, on purpose. Serde reads a missing
// key into `None`, and a reply field is never optional (RW-Q4): no answer
// is [`Nullable`](crate::nullable::Nullable), whose key is required. `()`
// is JSON `null`, which means no answer: no parameters is
// [`NoParams`](crate::kinds::NoParams) and bare success is
// [`Done`](crate::kinds::Done).

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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalkName {
    /// The method whose request or reply carries the name.
    pub method: &'static str,
    /// What kind of name it is.
    pub kind: NameKind,
    /// The holder's glossary path; empty for a method name.
    pub holder: &'static str,
    /// The name.
    pub name: &'static str,
    /// Who is shown it: the method's own policy, or the narrower one of
    /// the hidden field or part that carries it.
    pub shown_to: Policy,
    /// What it holds. [`Shape::Empty`] for a method name.
    pub shape: Shape,
}

/// The word a policy takes in the generated schema file.
#[must_use]
pub fn policy_word(policy: Policy) -> String {
    match policy {
        Policy::Grant(grant) => grant.name().to_owned(),
        Policy::HostOnly => "host-only".to_owned(),
        Policy::Armed => "armed".to_owned(),
        Policy::Authenticated => "authenticated".to_owned(),
        Policy::Endpoint => "endpoint".to_owned(),
    }
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
        Shape::Map { keys, value } => format!("map {} to {}", keys.join("|"), describe(value)),
        Shape::States(states) => {
            let keys: Vec<&str> = states.iter().map(|(key, _)| *key).collect();
            format!("state {}", keys.join("|"))
        }
        Shape::Either(item, slot) => format!("{}, or {}", describe(item), describe(slot)),
        Shape::Hidden { inner, .. } => describe(inner),
        Shape::Empty => "nothing".to_owned(),
    }
}

/// The scalar kind a shape ends in, through lists, nulls and hiding.
fn scalar_kind(shape: &Shape) -> Option<&'static str> {
    match shape {
        Shape::Scalar(kind) => Some(kind),
        Shape::List(inner) | Shape::Nullable(inner) | Shape::Hidden { inner, .. } => {
            scalar_kind(inner)
        }
        _ => None,
    }
}

fn walk_fields(
    method: &'static str,
    kind: NameKind,
    holder: &'static str,
    shown_to: Policy,
    fields: &[Field],
    out: &mut Vec<WalkName>,
) {
    for field in fields {
        let shown = match &field.shape {
            Shape::Hidden { shown_to, .. } => *shown_to,
            _ => shown_to,
        };
        out.push(WalkName {
            method,
            kind,
            holder: field.under.unwrap_or(holder),
            name: field.name,
            shown_to: shown,
            shape: field.shape.clone(),
        });
        // What a parameter holds is described like a reply's fields: only
        // the request's own keys are parameters.
        walk(method, NameKind::Field, shown, &field.shape, out);
    }
}

fn walk(
    method: &'static str,
    kind: NameKind,
    shown_to: Policy,
    shape: &Shape,
    out: &mut Vec<WalkName>,
) {
    match shape {
        Shape::Object {
            holder,
            fields,
            parts,
        } => {
            walk_fields(method, kind, holder, shown_to, fields, out);
            for part in parts {
                walk_fields(method, kind, holder, part.shown_to, &part.fields, out);
            }
        }
        Shape::List(inner) | Shape::Nullable(inner) | Shape::Map { value: inner, .. } => {
            walk(method, kind, shown_to, inner, out);
        }
        Shape::Hidden { shown_to, inner } => walk(method, kind, *shown_to, inner, out),
        Shape::States(states) => {
            for (_, payload) in states {
                if let Some(payload) = payload {
                    walk(method, kind, shown_to, payload, out);
                }
            }
        }
        Shape::Either(item, slot) => {
            walk(method, kind, shown_to, item, out);
            walk(method, kind, shown_to, slot, out);
        }
        Shape::Scalar(_) | Shape::OneOf(_) | Shape::Empty => {}
    }
}

/// Every name `rows` put on the wire: each method's name, each parameter
/// and each reply field, with the holder its walk starts from and who is
/// shown it.
#[must_use]
pub fn names(rows: &[crate::method::Row]) -> Vec<WalkName> {
    let mut out = Vec::new();
    for row in rows {
        out.push(WalkName {
            method: row.name,
            kind: NameKind::Method,
            holder: "",
            name: row.name,
            shown_to: row.policy,
            shape: Shape::Empty,
        });
        walk(
            row.name,
            NameKind::Parameter,
            row.policy,
            &(row.request)(),
            &mut out,
        );
        walk(
            row.name,
            NameKind::Field,
            row.policy,
            &(row.reply)(),
            &mut out,
        );
    }
    out
}

/// The generated schema file: one tab-separated line for each name, in
/// table order. The docs gate holds the committed file equal to this, and
/// the grammar's walk gate reads the file.
#[must_use]
pub fn render(rows: &[crate::method::Row]) -> String {
    let mut text = String::from("# method\tkind\tholder\tname\tshown-to\tshape\n");
    for name in names(rows) {
        let shape = match name.kind {
            NameKind::Method => String::new(),
            _ => describe(&name.shape),
        };
        text.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\n",
            name.method,
            name.kind.word(),
            name.holder,
            name.name,
            policy_word(name.shown_to),
            shape
        ));
    }
    text
}

/// The kind a name's last term requires, where the term fixes one
/// (RW-Q4, RW-Q10): a name states what it holds, so what it holds must be
/// that. `None` when the term fixes no kind.
#[must_use]
pub fn kind_of_term(term: &str) -> Option<&'static [&'static str]> {
    Some(match term {
        // A height is an ordinal and is never a count, and the reverse
        // (`HEIGHT_SEMANTICS.md`, IG-Q45).
        "height" | "from" | "to" => &["height"],
        "count" | "blocks" | "confirmations" | "depth" | "layers" | "threads" => &["count"],
        // A Shekyl address only; a network location is an endpoint (§3).
        "address" => &["address"],
        "endpoint" => &["endpoint"],
        "time" | "started" | "adjusted" => &["time"],
        "age" | "due" | "idle" | "duration" | "spacing" | "window" => &["duration"],
        "hash" | "id" | "parent" | "root" | "seed" | "next" | "coinbase" | "genesis" | "digest"
        | "pow" | "image" | "persona" | "fingerprint" => &["hash", "integer", "text"],
        "body" | "hashing" | "bundle" => &["bytes"],
        "size" | "free" | "weight" | "median" | "longterm" | "download" | "upload" => &["size"],
        "speed" | "average" | "current" => &["rate", "object"],
        "reward" | "emission" | "fee" | "budget" | "profit" | "total" | "economy" | "standard"
        | "high" => &["amount", "object"],
        "difficulty" | "cumulative" => &["hex128"],
        _ => return None,
    })
}

/// A name whose kind is not the one its last term requires.
///
/// The edits this refuses: a field `address` holding an endpoint, a
/// `…_height` holding a count, a `time` holding plain text.
#[must_use]
pub fn kind_faults(rows: &[crate::method::Row]) -> Vec<String> {
    let mut faults = Vec::new();
    for name in names(rows) {
        if name.kind == NameKind::Method {
            continue;
        }
        let term = name.name.rsplit('_').next().unwrap_or(name.name);
        let Some(allowed) = kind_of_term(term) else {
            continue;
        };
        // An object, a state or a map named by a term that also fixes a
        // scalar kind (`speed`, a fee's tiers) is allowed where the term's
        // row lists `object`.
        let held = scalar_kind(&name.shape).unwrap_or("object");
        if !allowed.contains(&held) {
            faults.push(format!(
                "{}: `{}` (under `{}`) holds {held}; a name ending in `{term}` holds {}",
                name.method,
                name.name,
                name.holder,
                allowed.join(" or ")
            ));
        }
    }
    faults
}

fn conforms_scalar(kind: &str, value: &serde_json::Value) -> Result<(), String> {
    use serde_json::Value;
    let hex = |text: &str| text.bytes().all(|b| b.is_ascii_hexdigit());
    let ok = match (kind, value) {
        ("switch", Value::Bool(_))
        | ("text" | "address" | "endpoint" | "path" | "name", Value::String(_)) => true,
        (
            "integer" | "height" | "count" | "time" | "duration" | "size" | "rate" | "micro"
            | "milli",
            Value::Number(n),
        ) => n.is_u64(),
        ("signed", Value::Number(n)) => n.is_i64() || n.is_u64(),
        ("hash", Value::String(text)) => text.len() == 64 && hex(text),
        ("hex128", Value::String(text)) => text
            .strip_prefix("0x")
            .is_some_and(|digits| !digits.is_empty() && digits.len() <= 32 && hex(digits)),
        ("amount", Value::String(text)) => {
            !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
        }
        ("bytes", Value::String(text)) => {
            text.len() % 4 == 0
                && text
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        }
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(format!("{value} is not a {kind}"))
    }
}

fn conforms_fields(
    object: &serde_json::Map<String, serde_json::Value>,
    fields: &[Field],
    seen: &mut Vec<&'static str>,
) -> Result<(), String> {
    for field in fields {
        seen.push(field.name);
        match (object.get(field.name), &field.shape) {
            // A hidden field is absent to a caller it is not shown to.
            (None, Shape::Hidden { .. }) => {}
            (None, _) => return Err(format!("`{}` is missing", field.name)),
            (Some(value), shape) => {
                conforms(value, shape).map_err(|e| format!("`{}`: {e}", field.name))?;
            }
        }
    }
    Ok(())
}

/// Whether `value` is a document of `shape`.
///
/// Strict in the ways the wire is: every field present unless hidden, no
/// unknown key, a part present whole or absent whole, a state exactly one
/// key, `null` only where the shape says no answer.
///
/// # Errors
///
/// The first place `value` departs from `shape`, as a path and a reason.
pub fn conforms(value: &serde_json::Value, shape: &Shape) -> Result<(), String> {
    use serde_json::Value;
    match (shape, value) {
        (Shape::Scalar(kind), _) => conforms_scalar(kind, value),
        (Shape::OneOf(words), Value::String(text)) if words.contains(&text.as_str()) => Ok(()),
        (Shape::OneOf(words), _) => Err(format!("{value} is not one of {}", words.join("|"))),
        (Shape::Nullable(_), Value::Null) => Ok(()),
        (Shape::Nullable(inner) | Shape::Hidden { inner, .. }, _) => conforms(value, inner),
        (Shape::List(inner), Value::Array(items)) => {
            for (index, item) in items.iter().enumerate() {
                conforms(item, inner).map_err(|e| format!("[{index}]: {e}"))?;
            }
            Ok(())
        }
        (Shape::Empty, Value::Object(object)) if object.is_empty() => Ok(()),
        (Shape::Map { keys, value: inner }, Value::Object(object)) => {
            for (key, item) in object {
                if !keys.contains(&key.as_str()) {
                    return Err(format!("`{key}` is not a key of this map"));
                }
                conforms(item, inner).map_err(|e| format!("`{key}`: {e}"))?;
            }
            Ok(())
        }
        (Shape::States(states), Value::Object(object)) if object.len() == 1 => {
            let (key, payload) = object.iter().next().expect("one key");
            let Some((_, shape)) = states.iter().find(|(name, _)| name == key) else {
                return Err(format!("`{key}` is not a state"));
            };
            match (shape, payload) {
                (None, Value::Null) => Ok(()),
                (None, _) => Err(format!("`{key}` carries no payload")),
                (Some(shape), _) => conforms(payload, shape).map_err(|e| format!("`{key}`: {e}")),
            }
        }
        (Shape::Either(item, slot), _) => conforms(value, item).or_else(|first| {
            conforms(value, slot).map_err(|second| format!("neither ({first}) nor ({second})"))
        }),
        (
            Shape::Object {
                fields,
                parts,
                holder: _,
            },
            Value::Object(object),
        ) => {
            let mut seen = Vec::new();
            conforms_fields(object, fields, &mut seen)?;
            for part in parts {
                let present = part
                    .fields
                    .iter()
                    .filter(|field| object.contains_key(field.name))
                    .count();
                if present == 0 {
                    seen.extend(part.fields.iter().map(|field| field.name));
                } else if present == part.fields.len() {
                    conforms_fields(object, &part.fields, &mut seen)?;
                } else {
                    return Err(format!(
                        "the part shown to {} is partly present",
                        policy_word(part.shown_to)
                    ));
                }
            }
            match object.keys().find(|key| !seen.contains(&key.as_str())) {
                Some(key) => Err(format!("`{key}` is not a field")),
                None => Ok(()),
            }
        }
        _ => Err(format!("{value} is not {}", describe(shape))),
    }
}

/// A wire object: the struct, its serde derives and its [`Schema`], written
/// together.
///
/// The holder is the glossary path of what the object describes. A field
/// may carry one bracket after its name:
///
/// - `["tx"]`: the name walks under another holder (a modifier, IG-Q42);
/// - `[shown POLICY]`: the field is shown only to a caller that policy
///   admits. Its type is [`Withheld<T>`](crate::kinds::Withheld), and it
///   carries `#[serde(default, skip_serializing_if =
///   "Withheld::is_withheld")]`; a withheld field that is not skipped
///   fails to serialize, so the attribute cannot be forgotten.
///
/// Every other field is required on the wire and unknown keys are refused;
/// a field with no answer is `Nullable`, written `null` (RK-D23). A field's
/// name is checked at compile time to be `[a-z][a-z0-9_]*`.
///
/// ```
/// shekyl_rpc_types::wire_object! {
///     /// The chain's tip.
///     ["chain"]
///     pub struct Tip {
///         /// The tip's height.
///         pub height: shekyl_rpc_types::kinds::Height,
///     }
/// }
/// ```
///
/// A raw identifier is not a wire name, and does not compile:
///
/// ```compile_fail
/// shekyl_rpc_types::wire_object! {
///     ["chain"]
///     pub struct Tip {
///         pub r#type: shekyl_rpc_types::kinds::Height,
///     }
/// }
/// ```
///
/// Nor does a field of a type with no kind, such as `u64` or `Option`:
///
/// ```compile_fail
/// shekyl_rpc_types::wire_object! {
///     ["chain"]
///     pub struct Tip {
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
                $fvis:vis $field:ident $([$($modifier:tt)+])? : $fty:ty
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

        const _: () = {
            $($crate::method::assert_name(::core::stringify!($field));)*
        };

        impl $crate::schema::Schema for $name {
            fn shape() -> $crate::schema::Shape {
                $crate::schema::Shape::Object {
                    holder: $holder,
                    fields: ::std::vec![
                        $($crate::schema::Field {
                            name: ::core::stringify!($field),
                            under: $crate::wire_object!(@under $($($modifier)+)?),
                            shape: $crate::wire_object!(@shape $fty; $($($modifier)+)?),
                        },)*
                    ],
                    parts: ::std::vec::Vec::new(),
                }
            }
        }
    };
    (@under) => { ::core::option::Option::None };
    (@under $under:literal) => { ::core::option::Option::Some($under) };
    (@under shown $policy:expr) => { ::core::option::Option::None };
    (@shape $fty:ty;) => { <$fty as $crate::schema::Schema>::shape() };
    (@shape $fty:ty; $under:literal) => { <$fty as $crate::schema::Schema>::shape() };
    (@shape $fty:ty; shown $policy:expr) => {
        $crate::schema::Shape::Hidden {
            shown_to: $policy,
            inner: ::std::boxed::Box::new(
                <$fty as $crate::kinds::WithheldShape>::inner_shape(),
            ),
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kinds::{Count, Done, Endpoint, Height, NoParams, Withheld};
    use crate::nullable::Nullable;
    use serde_json::json;
    use shekyl_rpc_grants::Grant;

    wire_object! {
        /// A header, as a test sees it.
        ["block header"]
        pub struct Header {
            pub height: Height,
            pub hash: crate::hash::HashHex,
            pub pow: Nullable<crate::hash::HashHex>,
        }
    }

    wire_object! {
        ["block"]
        pub struct Select {
            pub height: Vec<Height>,
            pub prune ["tx"]: bool,
        }
    }

    wire_object! {
        ["txpool"]
        pub struct Pool {
            pub count: Count,
            #[serde(default, skip_serializing_if = "Withheld::is_withheld")]
            pub private_count [shown Policy::HostOnly]: Withheld<Count>,
        }
    }

    fn row() -> crate::method::Row {
        crate::method::Row {
            name: "block_header_list",
            policy: Policy::Grant(Grant::Chain),
            request: Select::shape,
            reply: <Vec<Header>>::shape,
        }
    }

    fn pool_row() -> crate::method::Row {
        crate::method::Row {
            name: "txpool_stats",
            policy: Policy::Grant(Grant::Pool),
            request: NoParams::shape,
            reply: Pool::shape,
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

    /// The schema records who is shown each field: the method's policy,
    /// or the hidden field's own. Red edit: walk a hidden field with the
    /// method's policy.
    #[test]
    fn a_hidden_field_names_who_is_shown_it() {
        let text = render(&[pool_row()]);
        assert!(
            text.contains("txpool_stats\tfield\ttxpool\tcount\tpool\tcount\n"),
            "{text}"
        );
        assert!(
            text.contains("txpool_stats\tfield\ttxpool\tprivate_count\thost-only\tcount\n"),
            "{text}"
        );
    }

    /// A withheld field is absent, a shown one is written, and both read
    /// back; the shape admits both documents and refuses a `null` in the
    /// field's place.
    #[test]
    fn a_withheld_field_is_absent_and_never_null() {
        let withheld = Pool {
            count: Count(3),
            private_count: Withheld::Withheld,
        };
        let shown = Pool {
            count: Count(3),
            private_count: Withheld::Shown(Count(1)),
        };
        let withheld_doc = serde_json::to_value(&withheld).unwrap();
        let shown_doc = serde_json::to_value(&shown).unwrap();
        assert_eq!(withheld_doc, json!({"count": 3}));
        assert_eq!(shown_doc, json!({"count": 3, "private_count": 1}));
        assert_eq!(
            serde_json::from_value::<Pool>(withheld_doc.clone()).unwrap(),
            withheld
        );
        assert_eq!(
            serde_json::from_value::<Pool>(shown_doc.clone()).unwrap(),
            shown
        );
        conforms(&withheld_doc, &Pool::shape()).unwrap();
        conforms(&shown_doc, &Pool::shape()).unwrap();
        assert!(conforms(&json!({"count": 3, "private_count": null}), &Pool::shape()).is_err());
    }

    /// The struct the macro writes refuses an unknown key and a missing
    /// one, and writes an unanswered field as `null`.
    #[test]
    fn a_wire_object_is_strict_and_writes_null_for_no_answer() {
        let header: Header = serde_json::from_value(json!({
            "height": 7,
            "hash": "00".repeat(32),
            "pow": null,
        }))
        .expect("a header");
        assert_eq!(
            serde_json::to_value(&header).unwrap()["pow"],
            serde_json::Value::Null
        );
        assert!(serde_json::from_value::<Header>(json!({
            "height": 7, "hash": "00".repeat(32), "pow": null, "extra": 1,
        }))
        .is_err());
        assert!(serde_json::from_value::<Header>(json!({
            "height": 7, "hash": "00".repeat(32),
        }))
        .is_err());
    }

    /// What serde writes for a wire object conforms to its shape, and the
    /// shape refuses what serde refuses. Both directions.
    #[test]
    fn a_shape_and_its_serde_agree_in_both_directions() {
        let shape = Header::shape();
        let good = json!({"height": 7, "hash": "ab".repeat(32), "pow": null});
        conforms(&good, &shape).unwrap();
        assert!(serde_json::from_value::<Header>(good).is_ok());
        for bad in [
            json!({"height": 7, "hash": "ab".repeat(32)}),
            json!({"height": 7, "hash": "ab".repeat(32), "pow": null, "extra": 1}),
            json!({"height": "7", "hash": "ab".repeat(32), "pow": null}),
            json!({"height": 7, "hash": "ab", "pow": null}),
            json!([7]),
            json!(null),
        ] {
            assert!(conforms(&bad, &shape).is_err(), "{bad}");
            assert!(
                serde_json::from_value::<Header>(bad.clone()).is_err(),
                "{bad}"
            );
        }
    }

    /// The hand-written shapes: a state is exactly one key, a map's keys
    /// are closed, a part is whole or absent, a slot is the item or its
    /// stand-in.
    #[test]
    fn conforms_holds_states_maps_parts_and_slots() {
        let states = Shape::States(vec![("live", None), ("halted", Some(Header::shape()))]);
        conforms(&json!({"live": null}), &states).unwrap();
        assert!(conforms(&json!({"live": 1}), &states).is_err());
        assert!(conforms(&json!({"live": null, "halted": null}), &states).is_err());
        assert!(conforms(&json!({"dead": null}), &states).is_err());
        assert!(conforms(&json!("live"), &states).is_err());

        let map = Shape::Map {
            keys: &["clearnet", "tor"],
            value: Box::new(Shape::Scalar("count")),
        };
        conforms(&json!({"tor": 2}), &map).unwrap();
        conforms(&json!({}), &map).unwrap();
        assert!(conforms(&json!({"i2p": 2}), &map).is_err());

        let parted = Shape::Object {
            holder: "daemon",
            fields: vec![Field {
                name: "height",
                under: None,
                shape: Shape::Scalar("height"),
            }],
            parts: vec![Part {
                shown_to: Policy::Grant(Grant::Status),
                fields: vec![
                    Field {
                        name: "started",
                        under: None,
                        shape: Shape::Scalar("time"),
                    },
                    Field {
                        name: "revision",
                        under: None,
                        shape: Shape::Scalar("text"),
                    },
                ],
            }],
        };
        conforms(&json!({"height": 1}), &parted).unwrap();
        conforms(
            &json!({"height": 1, "started": 5, "revision": "x"}),
            &parted,
        )
        .unwrap();
        assert!(conforms(&json!({"height": 1, "started": 5}), &parted).is_err());

        let slot = Shape::Either(
            Box::new(Shape::Scalar("hash")),
            Box::new(Shape::Nullable(Box::new(Shape::States(vec![(
                "missing", None,
            )])))),
        );
        conforms(&json!("cd".repeat(32)), &slot).unwrap();
        conforms(&json!({"missing": null}), &slot).unwrap();
        conforms(&json!(null), &slot).unwrap();
        assert!(conforms(&json!({"lost": null}), &slot).is_err());
    }

    /// No parameters is `{}`, and bare success is `{}`: never `null`,
    /// which means no answer, never a list, never a key.
    #[test]
    fn no_parameters_and_bare_success_are_empty_objects() {
        assert_eq!(serde_json::to_value(NoParams).unwrap(), json!({}));
        assert_eq!(serde_json::to_value(Done).unwrap(), json!({}));
        assert!(serde_json::from_value::<NoParams>(json!({})).is_ok());
        assert!(serde_json::from_value::<Done>(json!({})).is_ok());
        for bad in [json!(null), json!([]), json!({"a": 1}), json!(0)] {
            assert!(
                serde_json::from_value::<NoParams>(bad.clone()).is_err(),
                "{bad}"
            );
            assert!(
                serde_json::from_value::<Done>(bad.clone()).is_err(),
                "{bad}"
            );
            assert!(conforms(&bad, &NoParams::shape()).is_err(), "{bad}");
        }
        assert_eq!(NoParams::from_params(None), Ok(NoParams));
        assert_eq!(NoParams::from_params(Some(&json!({}))), Ok(NoParams));
        assert!(NoParams::from_params(Some(&json!(null))).is_err());
    }

    wire_object! {
        ["peer connection"]
        pub struct WrongAddress {
            pub address: Endpoint,
        }
    }

    wire_object! {
        ["sync session"]
        pub struct WrongHeight {
            pub claimed_height: Count,
        }
    }

    /// A name states what it holds. The red edits the brief names: an
    /// `address` holding an endpoint, and a `…_height` holding a count.
    #[test]
    fn a_name_whose_kind_is_not_its_terms_is_refused() {
        assert!(kind_faults(&[row(), pool_row()]).is_empty());
        let wrong = |reply: fn() -> Shape| crate::method::Row {
            name: "peer_connections",
            policy: Policy::Grant(Grant::Peers),
            request: NoParams::shape,
            reply,
        };
        let address = kind_faults(&[wrong(WrongAddress::shape)]);
        assert_eq!(address.len(), 1, "{address:?}");
        assert!(address[0].contains("`address`") && address[0].contains("endpoint"));
        let height = kind_faults(&[wrong(WrongHeight::shape)]);
        assert_eq!(height.len(), 1, "{height:?}");
        assert!(height[0].contains("`claimed_height`") && height[0].contains("holds count"));
    }
}
