// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `option_set` and `option_show` on the wire (RT-O25).
//!
//! One definition, in this crate (RK-D1). The daemon's options handle
//! builds these values; a client only reads them.

use serde::{Deserialize, Serialize};

/// One row as `option_show` reports it and `option_set` echoes it
/// (RT-O25). A value row carries the grammar text, or `null` when the
/// value is unset. A secret row carries whether it is set and never the
/// text. The two forms do not overlap: a document that has both, or
/// neither, is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShownRow {
    /// A row whose value is text in the grammar's syntax, or unset.
    Value {
        /// The option's name.
        name: String,
        /// `default`, `file`, `cli` or `runtime`.
        source: String,
        /// Whether `option_set` accepts it.
        runtime: bool,
        /// The value as text. `None` is the wire's `null`: unset.
        value: Option<String>,
    },
    /// A secret row. The text never leaves the process.
    Secret {
        /// The option's name.
        name: String,
        /// `default`, `file`, `cli` or `runtime`.
        source: String,
        /// Whether the secret holds a value.
        set: bool,
    },
}

/// The document serde reads before it becomes a [`ShownRow`]. `value` uses
/// [`present`] so a JSON `null` stays an unset value row rather than an
/// absent member, which is the secret form.
#[derive(Deserialize)]
struct ShownWire {
    name: String,
    source: String,
    runtime: bool,
    #[serde(default, deserialize_with = "present")]
    value: Option<Option<String>>,
    #[serde(default)]
    secret: Option<bool>,
    #[serde(default)]
    set: Option<bool>,
}

/// A `value` member that is present, `null` included: serde reads `null`
/// into the outer `Option` otherwise, which would make an unset value row
/// read as a row with no `value` member (RT-O25's secret form).
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(d).map(Some)
}

impl ShownRow {
    /// A value row: the grammar text, or unset.
    #[must_use]
    pub fn text(name: &str, source: &str, runtime: bool, value: Option<String>) -> Self {
        Self::Value {
            name: name.to_owned(),
            source: source.to_owned(),
            runtime,
            value,
        }
    }

    /// A secret row: no text, only whether it is set. A secret is never a
    /// runtime row.
    #[must_use]
    pub fn secret(name: &str, source: &str, set: bool) -> Self {
        Self::Secret {
            name: name.to_owned(),
            source: source.to_owned(),
            set,
        }
    }

    /// The option's name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Value { name, .. } | Self::Secret { name, .. } => name,
        }
    }

    /// Where the value came from: `default`, `file`, `cli` or `runtime`.
    #[must_use]
    pub fn source(&self) -> &str {
        match self {
            Self::Value { source, .. } | Self::Secret { source, .. } => source,
        }
    }

    /// Whether `option_set` accepts the row. A secret row is never runtime.
    #[must_use]
    pub const fn runtime(&self) -> bool {
        match self {
            Self::Value { runtime, .. } => *runtime,
            Self::Secret { .. } => false,
        }
    }

    /// The value text. `Some(None)` is an unset value row; `None` is a
    /// secret row, which carries no text.
    #[must_use]
    pub fn value(&self) -> Option<Option<&str>> {
        match self {
            Self::Value { value, .. } => Some(value.as_deref()),
            Self::Secret { .. } => None,
        }
    }

    /// Whether this is a secret row.
    #[must_use]
    pub const fn is_secret(&self) -> bool {
        matches!(self, Self::Secret { .. })
    }

    /// Whether a secret row holds a value. `None` on a value row.
    #[must_use]
    pub const fn set(&self) -> Option<bool> {
        match self {
            Self::Secret { set, .. } => Some(*set),
            Self::Value { .. } => None,
        }
    }
}

impl Serialize for ShownRow {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        match self {
            Self::Value {
                name,
                source,
                runtime,
                value,
            } => {
                let mut row = serializer.serialize_struct("ShownRow", 4)?;
                row.serialize_field("name", name)?;
                row.serialize_field("source", source)?;
                row.serialize_field("runtime", runtime)?;
                row.serialize_field("value", value)?;
                row.end()
            }
            Self::Secret { name, source, set } => {
                let mut row = serializer.serialize_struct("ShownRow", 5)?;
                row.serialize_field("name", name)?;
                row.serialize_field("source", source)?;
                row.serialize_field("runtime", &false)?;
                row.serialize_field("secret", &true)?;
                row.serialize_field("set", set)?;
                row.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for ShownRow {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = ShownWire::deserialize(deserializer)?;
        let secret_marked = wire.secret.is_some() || wire.set.is_some();
        match (wire.value, wire.secret, wire.set) {
            (Some(value), None, None) => Ok(Self::Value {
                name: wire.name,
                source: wire.source,
                runtime: wire.runtime,
                value,
            }),
            (None, Some(true), Some(set)) if !wire.runtime => Ok(Self::Secret {
                name: wire.name,
                source: wire.source,
                set,
            }),
            (None, Some(true), Some(_)) => Err(serde::de::Error::custom(
                "a secret row is not a runtime row",
            )),
            (None, Some(false), _) => Err(serde::de::Error::custom(
                "a secret row has `secret: true`; `false` is not a form",
            )),
            (None, Some(true), None) | (None, None, Some(_)) => Err(serde::de::Error::custom(
                "a secret row carries `secret: true` and `set`, and no `value`",
            )),
            (Some(_), _, _) if secret_marked => Err(serde::de::Error::custom(
                "a row is a value or a secret, not both",
            )),
            (None, None, None) => Err(serde::de::Error::custom(
                "a row carries `value` or `secret` and `set`",
            )),
            (Some(_), _, _) => Err(serde::de::Error::custom(
                "a row is a value or a secret, not both",
            )),
        }
    }
}

/// One IG-11 diagnostic on the wire: the `data` member of a configuration
/// refusal (RT-O25). The fields are the diagnostic's, rendered to strings;
/// `message` is the one IG-11 renderer's text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    /// The stable code, such as `config.value.range`.
    pub code: String,
    /// The option the refusal is about, when it is about one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub option: Option<String>,
    /// Where the refused value came from: `runtime` here.
    pub source: String,
    /// The named facts the message is built from.
    pub params: Vec<(String, String)>,
    /// What was wrong and what to do, as the startup parse would print it.
    pub message: String,
}

/// `option_set`'s request (RT-O25).
#[derive(Debug, Serialize, Deserialize)]
pub struct OptionSetRequest {
    /// The pairs, each value text in the grammar's syntax.
    pub options: Vec<OptionPair>,
}

/// One name and value pair.
#[derive(Debug, Serialize, Deserialize)]
pub struct OptionPair {
    /// The option's name.
    pub name: String,
    /// The value as text.
    pub value: String,
}

/// `option_show`'s request (RT-O25).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct OptionShowRequest {
    /// The names asked for; absent is every row.
    #[serde(default)]
    pub names: Option<Vec<String>>,
}

/// `option_set`'s and `option_show`'s reply: the rows.
#[derive(Debug, Serialize, Deserialize)]
pub struct OptionsResponse {
    /// The rows, in table order.
    pub options: Vec<ShownRow>,
}
