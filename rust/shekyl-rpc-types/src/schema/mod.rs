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
//! parts) can drift from what serde writes. An exclusive object — a
//! selector, a header range — is not one of those: [`crate::wire_exclusive`]
//! writes its reader and its shape from the one list of alternatives.
//! [`conforms`] checks a JSON value against a shape; run over every
//! method's vectors in both directions, it makes the schema the contract
//! and not a description.

use crate::method::Policy;

pub mod object;
mod switches;

pub use switches::{request_switches, switches, switches_on};

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
        /// Alternatives of which exactly one is wholly present. Each
        /// alternative is the fields that arrive together: `from` and `to`,
        /// or one selector key (`INPUT_GRAMMAR.md` IG-Q94). Empty when the
        /// object has none.
        choice: Vec<Vec<Field>>,
    },
    /// JSON `null` and nothing else. A selector's `tip` (`INPUT_GRAMMAR.md`
    /// IG-Q94). Distinct from [`Nullable`](Self::Nullable), which is this
    /// or another shape, and from [`Empty`](Self::Empty), which is `{}`.
    Null,
    /// A list of one shape.
    List(Box<Shape>),
    /// The shape, or `null`: no answer (RK-D23).
    Nullable(Box<Shape>),
    /// A map to one shape (IG-6's map). A key may be absent; no key appears
    /// twice.
    Map {
        /// The keys a document may carry, when they are a fixed set. Each
        /// is a subject, and an object value walks under the key it sits
        /// under (a connector's counts under `clearnet`, IG-Q82). `None`
        /// for keys from a runtime table (an option's name, a diagnostic's
        /// parameter), whose value is a scalar.
        keys: Option<&'static [&'static str]>,
        /// What each key holds.
        value: Box<Shape>,
    },
    /// An object one of whose fields, the tag, names which of several
    /// field sets the rest is (a submission's `verdict`).
    Tagged {
        /// The glossary path of what the object describes.
        holder: &'static str,
        /// The tag's field name.
        tag: &'static str,
        /// Each tag value and the fields that come with it.
        variants: Vec<(&'static str, Vec<Field>)>,
    },
    /// A request parameter that may be left out; its default is stated by
    /// its method. Never in a reply (RW-Q4).
    Optional(Box<Shape>),
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
    /// A reply field present exactly when the request turned `switch` on,
    /// and absent otherwise (`RPC_WIRE.md` RW-Q4, amended 2026-11-12).
    Asked {
        /// The request's switch that selects it.
        switch: &'static str,
        /// What it holds when selected.
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
    /// What it holds. For a method name, the reply's shape, so a list
    /// reply's slot states are visible to the grammar's walk.
    pub shape: Shape,
    /// Whether the name is in the method's reply (or nested in it), not
    /// its request.
    pub in_reply: bool,
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
        Shape::Map { keys, value } => match keys {
            Some(keys) => format!("map {} to {}", keys.join("|"), describe(value)),
            None => format!("map to {}", describe(value)),
        },
        Shape::Tagged {
            holder,
            tag,
            variants,
        } => {
            let tags: Vec<&str> = variants.iter().map(|(name, _)| *name).collect();
            format!("object ({holder}) by {tag} {}", tags.join("|"))
        }
        Shape::Optional(inner) => format!("{}, optional", describe(inner)),
        Shape::States(states) => {
            let keys: Vec<&str> = states.iter().map(|(key, _)| *key).collect();
            format!("state {}", keys.join("|"))
        }
        Shape::Either(item, slot) => format!("{}, or {}", describe(item), describe(slot)),
        Shape::Hidden { inner, .. } => describe(inner),
        Shape::Asked { switch, inner } => format!("{}, when asked by {switch}", describe(inner)),
        Shape::Empty => "nothing".to_owned(),
        Shape::Null => "null".to_owned(),
    }
}

/// The scalar kind a shape ends in, through lists, nulls and hiding.
fn scalar_kind(shape: &Shape) -> Option<&'static str> {
    match shape {
        Shape::Scalar(kind) => Some(kind),
        Shape::List(inner)
        | Shape::Nullable(inner)
        | Shape::Optional(inner)
        | Shape::Either(inner, _)
        | Shape::Hidden { inner, .. }
        | Shape::Asked { inner, .. } => scalar_kind(inner),
        _ => None,
    }
}

struct Walk<'a> {
    method: &'static str,
    in_reply: bool,
    out: &'a mut Vec<WalkName>,
}

fn walk_fields(
    w: &mut Walk<'_>,
    kind: NameKind,
    holder: &'static str,
    shown_to: Policy,
    fields: &[Field],
) {
    for field in fields {
        let shown = match &field.shape {
            Shape::Hidden { shown_to, .. } => *shown_to,
            _ => shown_to,
        };
        w.out.push(WalkName {
            method: w.method,
            kind,
            holder: field.under.unwrap_or(holder),
            name: field.name,
            shown_to: shown,
            shape: field.shape.clone(),
            in_reply: w.in_reply,
        });
        // What a parameter holds is described like a reply's fields: only
        // the request's own keys are parameters.
        walk(w, NameKind::Field, shown, &field.shape);
    }
}

fn walk(w: &mut Walk<'_>, kind: NameKind, shown_to: Policy, shape: &Shape) {
    match shape {
        Shape::Object {
            holder,
            fields,
            parts,
            choice,
        } => {
            walk_fields(w, kind, holder, shown_to, fields);
            for group in choice {
                walk_fields(w, kind, holder, shown_to, group);
            }
            for part in parts {
                walk_fields(w, kind, holder, part.shown_to, &part.fields);
            }
        }
        Shape::Map {
            keys: Some(keys),
            value,
        } => match value.as_ref() {
            // A subject-keyed map: the value's fields walk under each key.
            Shape::Object { fields, .. } => {
                for key in *keys {
                    walk_fields(w, kind, key, shown_to, fields);
                }
            }
            other => walk(w, kind, shown_to, other),
        },
        Shape::Tagged {
            holder,
            tag,
            variants,
        } => {
            let tag_field = Field {
                name: tag,
                under: None,
                shape: Shape::OneOf(&[]),
            };
            walk_fields(w, kind, holder, shown_to, std::slice::from_ref(&tag_field));
            for (_, fields) in variants {
                walk_fields(w, kind, holder, shown_to, fields);
            }
        }
        Shape::List(inner)
        | Shape::Nullable(inner)
        | Shape::Optional(inner)
        | Shape::Map { value: inner, .. } => {
            walk(w, kind, shown_to, inner);
        }
        Shape::Hidden { shown_to, inner } => walk(w, kind, *shown_to, inner),
        Shape::Asked { inner, .. } => walk(w, kind, shown_to, inner),
        Shape::States(states) => {
            for (_, payload) in states {
                if let Some(payload) = payload {
                    walk(w, kind, shown_to, payload);
                }
            }
        }
        Shape::Either(item, slot) => {
            walk(w, kind, shown_to, item);
            walk(w, kind, shown_to, slot);
        }
        Shape::Scalar(_) | Shape::OneOf(_) | Shape::Empty | Shape::Null => {}
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
            shape: (row.reply)(),
            in_reply: false,
        });
        let mut request = Walk {
            method: row.name,
            in_reply: false,
            out: &mut out,
        };
        walk(
            &mut request,
            NameKind::Parameter,
            row.policy,
            &(row.request)(),
        );
        let mut reply = Walk {
            method: row.name,
            in_reply: true,
            out: &mut out,
        };
        walk(&mut reply, NameKind::Field, row.policy, &(row.reply)());
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
        // A method's shape is its reply. A list of slots then carries
        // `state missing|archived`, which the grammar's walk reads back
        // (`check_input_grammar_walk.py`, `state_keys`). The shape is the
        // last cell, and `describe` writes no tab.
        let shape = describe(&name.shape);
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
        "height" => &["height"],
        // A range's ends: heights, or settlement epochs (a bond's failures).
        "from" | "to" => &["height", "integer"],
        "count" | "blocks" | "confirmations" | "depth" | "layers" | "threads" => &["count"],
        // A Shekyl address only; a network location is an endpoint (§3).
        "address" => &["address"],
        "endpoint" => &["endpoint"],
        "time" | "started" | "adjusted" => &["time"],
        "age" | "due" | "idle" | "duration" | "spacing" | "window" => &["duration"],
        "hash" | "id" | "parent" | "root" | "seed" | "next" | "coinbase" | "genesis" | "digest"
        | "image" | "persona" | "fingerprint" => &["hash", "integer", "text"],
        // The header's hash, and the switch that asks for it (IG-Q56).
        "pow" => &["hash", "switch"],
        "body" | "hashing" | "bundle" => &["bytes"],
        "size" | "free" | "needed" | "weight" | "download" | "upload" => &["size", "object"],
        "speed" => &["rate", "object"],
        "reward" | "emission" | "fee" | "budget" | "profit" | "economy" | "standard" | "high" => {
            &["amount", "object"]
        }
        "difficulty" => &["hex128"],
        _ => return None,
    })
}

/// Terms that qualify the term before them and fix no kind of their own.
const QUALIFIERS: &[&str] = &[
    "total",
    "median",
    "min",
    "max",
    "average",
    "current",
    "longterm",
    "cumulative",
];

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
        if !name.in_reply && matches!(name.shape, Shape::Asked { .. }) {
            faults.push(format!(
                "{}: `{}` (under `{}`) is selected by a switch in a request; only a reply's fields are selected (RW-Q4)",
                name.method, name.name, name.holder
            ));
            continue;
        }
        if name.in_reply && matches!(name.shape, Shape::Optional(_)) {
            faults.push(format!(
                "{}: `{}` (under `{}`) is optional in a reply; a reply field is always present (RW-Q4)",
                name.method, name.name, name.holder
            ));
            continue;
        }
        // A qualifier takes its kind from the term it qualifies:
        // `weight_total` is a weight, `fee_total` an amount.
        let term = name
            .name
            .rsplit('_')
            .find(|term| !QUALIFIERS.contains(term))
            .unwrap_or(name.name);
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

/// How far [`conforms_in`] reads a value.
#[derive(Clone, Copy)]
enum Check<'a> {
    /// The value is the shape. `asked` names the switches that are on;
    /// `None` means no request is in hand, so a selected field may be absent.
    Shape { asked: Option<&'a [&'a str]> },
    /// A field a switch selects is present exactly when that switch is on.
    /// A scalar is not read, and a value that is not this shape is not a fault.
    Presence { on: &'a [&'a str] },
}

impl<'a> Check<'a> {
    fn presence(self) -> bool {
        matches!(self, Self::Presence { .. })
    }

    /// The switches that are on, when a request is in hand.
    fn on(self) -> Option<&'a [&'a str]> {
        match self {
            Self::Shape { asked } => asked,
            Self::Presence { on } => Some(on),
        }
    }
}

fn conforms_fields(
    object: &serde_json::Map<String, serde_json::Value>,
    fields: &[Field],
    seen: &mut Vec<&'static str>,
    check: Check<'_>,
) -> Result<(), String> {
    for field in fields {
        seen.push(field.name);
        let value = object.get(field.name);
        selected(field.name, &field.shape, value.is_some(), check)?;
        match value {
            Some(value) => {
                conforms_in(value, &field.shape, check)
                    .map_err(|e| format!("`{}`: {e}", field.name))?;
            }
            None if may_omit(&field.shape, check) => {}
            None => return Err(format!("`{}` is missing", field.name)),
        }
    }
    Ok(())
}

/// A selected field is present exactly when its switch is on (RW-Q4).
fn selected(name: &str, shape: &Shape, present: bool, check: Check<'_>) -> Result<(), String> {
    let Shape::Asked { switch, .. } = shape else {
        return Ok(());
    };
    let on = check.on();
    if !present && is_on(on, switch) {
        return Err(format!(
            "`{name}` is missing: the request asked for it with `{switch}`"
        ));
    }
    if present && is_off(on, switch) {
        return Err(format!(
            "`{name}` is present: the request did not ask for it with `{switch}`"
        ));
    }
    Ok(())
}

/// A missing field is allowed: a hidden field, an optional parameter, a
/// field the request did not select, or any absence when only presence is
/// being read.
fn may_omit(shape: &Shape, check: Check<'_>) -> bool {
    check.presence()
        || matches!(
            shape,
            Shape::Hidden { .. } | Shape::Optional(_) | Shape::Asked { .. }
        )
}

/// Whether the request turned `switch` on; `false` with no request.
fn is_on(asked: Option<&[&str]>, switch: &str) -> bool {
    asked.is_some_and(|on| on.contains(&switch))
}

/// Whether the request left `switch` off; `false` with no request.
fn is_off(asked: Option<&[&str]>, switch: &str) -> bool {
    asked.is_some_and(|on| !on.contains(&switch))
}

/// How much of one alternative a document carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GroupPresence {
    /// None of its fields.
    Absent,
    /// Some of its fields and not all of them.
    Partial,
    /// Every one of its fields.
    Complete,
}

/// `present` fields of an alternative that has `len` fields.
///
/// `len` is the alternative's own field count. The caller counts how many
/// of those fields the document carries. The reader and [`conforms`] both
/// decide through this, so a partial range cannot be complete in one and
/// absent in the other.
pub(crate) fn group_presence(present: usize, len: usize) -> GroupPresence {
    if present == len {
        GroupPresence::Complete
    } else if present == 0 {
        GroupPresence::Absent
    } else {
        GroupPresence::Partial
    }
}

/// The index of the one complete alternative.
///
/// # Errors
///
/// None is complete, more than one is, or any alternative is only partly
/// present.
pub(crate) fn exclusive_index(states: &[GroupPresence]) -> Result<usize, ()> {
    let mut found = None;
    for (index, state) in states.iter().enumerate() {
        match (state, found) {
            (GroupPresence::Absent, _) => {}
            (GroupPresence::Complete, None) => found = Some(index),
            (GroupPresence::Complete | GroupPresence::Partial, _) => return Err(()),
        }
    }
    found.ok_or(())
}

/// `height, hash, tip` or `(from and to), hash`: how an exclusive object's
/// alternatives are named in a refusal.
pub(crate) fn format_alternatives(groups: &[&[&str]]) -> String {
    groups
        .iter()
        .map(|group| {
            if group.len() == 1 {
                (*group)[0].to_owned()
            } else {
                format!("({})", group.join(" and "))
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
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
    conforms_in(value, shape, Check::Shape { asked: None })
}

/// [`conforms`], against the switches a request turned on: a field the
/// request selected must be present, and one it did not select must be
/// absent (`RPC_WIRE.md` RW-Q4, amended 2026-11-12). `asked` names the
/// switches that were on.
///
/// # Errors
///
/// The first place `value` departs from `shape` read for that request.
pub fn conforms_asked(
    value: &serde_json::Value,
    shape: &Shape,
    asked: &[&str],
) -> Result<(), String> {
    conforms_in(value, shape, Check::Shape { asked: Some(asked) })
}

/// Whether every field of `value` that a switch selects is present exactly
/// when `on` holds that switch (RW-Q4). Presence only: no scalar is read,
/// so a client checks a large reply against its request without decoding
/// it twice. [`conforms_asked`] is the full check. The descent is
/// [`conforms_in`]'s.
///
/// # Errors
///
/// The first selected field present unasked, or asked and missing.
pub fn conforms_presence(
    value: &serde_json::Value,
    shape: &Shape,
    on: &[&str],
) -> Result<(), String> {
    conforms_in(value, shape, Check::Presence { on })
}

fn conforms_in(value: &serde_json::Value, shape: &Shape, check: Check<'_>) -> Result<(), String> {
    use serde_json::Value;
    match (shape, value) {
        (Shape::Scalar(kind), _) if !check.presence() => conforms_scalar(kind, value),
        (Shape::OneOf(words), Value::String(text)) if words.contains(&text.as_str()) => Ok(()),
        (Shape::OneOf(words), _) if !check.presence() => {
            Err(format!("{value} is not one of {}", words.join("|")))
        }
        (Shape::Null | Shape::Nullable(_), Value::Null) => Ok(()),
        (
            Shape::Nullable(inner)
            | Shape::Hidden { inner, .. }
            | Shape::Optional(inner)
            | Shape::Asked { inner, .. },
            _,
        ) => {
            if check.presence() && value.is_null() {
                Ok(())
            } else {
                conforms_in(value, inner, check)
            }
        }
        (Shape::List(inner), Value::Array(items)) => {
            for (index, item) in items.iter().enumerate() {
                conforms_in(item, inner, check).map_err(|e| format!("[{index}]: {e}"))?;
            }
            Ok(())
        }
        (Shape::Empty, Value::Object(object)) if object.is_empty() => Ok(()),
        (Shape::Map { keys, value: inner }, Value::Object(object)) => {
            for (key, item) in object {
                if !check.presence() && keys.is_some_and(|keys| !keys.contains(&key.as_str())) {
                    return Err(format!("`{key}` is not a key of this map"));
                }
                conforms_in(item, inner, check).map_err(|e| format!("`{key}`: {e}"))?;
            }
            Ok(())
        }
        (Shape::States(states), Value::Object(object)) if check.presence() => {
            for (key, payload) in object {
                if let Some((_, Some(shape))) = states.iter().find(|(state, _)| state == key) {
                    conforms_in(payload, shape, check).map_err(|e| format!("`{key}`: {e}"))?;
                }
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
                (Some(shape), _) => {
                    conforms_in(payload, shape, check).map_err(|e| format!("`{key}`: {e}"))
                }
            }
        }
        (Shape::Either(item, slot), _) => {
            let first = conforms_in(value, item, check);
            match (first, check.presence()) {
                (Ok(()), _) => Ok(()),
                (Err(first), true) => conforms_in(value, slot, check).map_err(|_| first),
                (Err(first), false) => conforms_in(value, slot, check)
                    .map_err(|second| format!("neither ({first}) nor ({second})")),
            }
        }
        (
            Shape::Object {
                fields,
                parts,
                choice,
                ..
            },
            Value::Object(object),
        ) if check.presence() => {
            let mut seen = Vec::new();
            conforms_fields(object, fields, &mut seen, check)?;
            for part in parts {
                conforms_fields(object, &part.fields, &mut seen, check)?;
            }
            for group in choice {
                conforms_fields(object, group, &mut seen, check)?;
            }
            Ok(())
        }
        (
            Shape::Object {
                fields,
                parts,
                choice,
                holder: _,
            },
            Value::Object(object),
        ) => {
            let mut seen = Vec::new();
            conforms_fields(object, fields, &mut seen, check)?;
            if !choice.is_empty() {
                let states: Vec<GroupPresence> = choice
                    .iter()
                    .map(|group| {
                        let present = group
                            .iter()
                            .filter(|field| object.contains_key(field.name))
                            .count();
                        group_presence(present, group.len())
                    })
                    .collect();
                let names: Vec<Vec<&str>> = choice
                    .iter()
                    .map(|group| group.iter().map(|field| field.name).collect())
                    .collect();
                let shown: Vec<&[&str]> = names.iter().map(Vec::as_slice).collect();
                let Ok(index) = exclusive_index(&states) else {
                    return Err(format!(
                        "name exactly one of {}",
                        format_alternatives(&shown)
                    ));
                };
                for field in &choice[index] {
                    seen.push(field.name);
                    conforms_in(&object[field.name], &field.shape, check)
                        .map_err(|e| format!("`{}`: {e}", field.name))?;
                }
                for group in choice {
                    for field in group {
                        if !seen.contains(&field.name) {
                            seen.push(field.name);
                        }
                    }
                }
            }
            for part in parts {
                let present = part
                    .fields
                    .iter()
                    .filter(|field| object.contains_key(field.name))
                    .count();
                if present == 0 {
                    seen.extend(part.fields.iter().map(|field| field.name));
                } else if present == part.fields.len() {
                    conforms_fields(object, &part.fields, &mut seen, check)?;
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
        (Shape::Tagged { tag, variants, .. }, Value::Object(object)) if check.presence() => {
            let Some(Value::String(name)) = object.get(*tag) else {
                return Ok(());
            };
            let fields = variants
                .iter()
                .find(|(variant, _)| variant == name)
                .map_or(&[][..], |(_, fields)| fields.as_slice());
            let mut seen = Vec::new();
            conforms_fields(object, fields, &mut seen, check)
        }
        (Shape::Tagged { tag, variants, .. }, Value::Object(object)) => {
            let Some(Value::String(name)) = object.get(*tag) else {
                return Err(format!("`{tag}` is missing or not a keyword"));
            };
            let Some((_, fields)) = variants.iter().find(|(variant, _)| variant == name) else {
                return Err(format!("`{name}` is not a {tag}"));
            };
            let mut seen = vec![*tag];
            conforms_fields(object, fields, &mut seen, check)?;
            match object.keys().find(|key| !seen.contains(&key.as_str())) {
                Some(key) => Err(format!("`{key}` is not a field of `{name}`")),
                None => Ok(()),
            }
        }
        _ if check.presence() => Ok(()),
        _ => Err(format!("{value} is not {}", describe(shape))),
    }
}

#[cfg(test)]
#[path = "../schema_tests.rs"]
mod tests;
