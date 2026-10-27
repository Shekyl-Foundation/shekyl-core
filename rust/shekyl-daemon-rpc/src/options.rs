// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `option_set` and `option_show` (`RPC_CHANNEL.md` §6.4, RT-O23…RT-O27;
//! `DAEMON_CONFIG_CUTOVER.md` §2.7): the two runtime option methods,
//! served natively over an options handle the composition root supplies
//! ([`OptionsFacts`]), in the shape `request_archival_shard`'s facts have.
//! This crate depends on the interface, never on the grammar or the
//! subsystems: the wire types here are the IG-11 diagnostic's fields
//! rendered to strings, and the root converts.
//!
//! `option_set` is all or nothing under the handle's one lock: every value
//! is built first, every refusal is reported, and nothing is applied when
//! one is refused. `option_show` reads under the same lock and discloses
//! each row under the grant the row names.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::info::Disclosure;
use crate::methods::{RpcFault, RpcRefusal};

use shekyl_rpc_types::methods::Grant;

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

/// The visibility of a row for `option_show`, as the handle reports each.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisibleRow {
    /// The row, rendered.
    pub row: ShownRow,
    /// The grant the row names.
    pub grant: Grant,
}

/// Why `option_show` could not answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShowRefusal {
    /// A name the table refuses: unknown, rejected, reserved, or a
    /// development lever off its networks; carries the diagnostic the
    /// startup parse would give.
    Refused(Refusal),
    /// No handle was supplied: this daemon serves no options.
    Absent,
}

/// The options handle: the composition root wires each runtime row to its
/// owner behind this interface (RT-O26). Both calls run under the handle's
/// one lock (RT-O27).
pub trait OptionsFacts: Send + Sync {
    /// Build every pair, then apply all or none. `Ok` echoes each row set,
    /// with source `runtime`; `Err` is every refusal, with nothing applied.
    fn set(&self, pairs: &[(String, String)]) -> Result<Vec<ShownRow>, Vec<Refusal>>;

    /// Every row, or the named rows, in table order, each with its grant.
    /// An unknown name is refused; the caller's grant filter is applied by
    /// [`option_show`], not here.
    fn show(&self, names: Option<&[String]>) -> Result<Vec<VisibleRow>, ShowRefusal>;
}

/// The facts of a daemon with no options handle: every request is refused.
/// The default when no composition root supplied another implementation.
pub struct OptionsAbsent;

impl OptionsFacts for OptionsAbsent {
    fn set(&self, _pairs: &[(String, String)]) -> Result<Vec<ShownRow>, Vec<Refusal>> {
        Err(vec![absent_refusal()])
    }

    fn show(&self, _names: Option<&[String]>) -> Result<Vec<VisibleRow>, ShowRefusal> {
        Err(ShowRefusal::Absent)
    }
}

fn absent_refusal() -> Refusal {
    Refusal {
        code: "config.runtime.absent".to_owned(),
        option: None,
        source: "runtime".to_owned(),
        params: Vec::new(),
        message: "this daemon serves no options: no options handle was supplied".to_owned(),
    }
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

/// The JSON-RPC code of a configuration refusal (RT-O25), whose `data`
/// member carries the diagnostics.
pub const CONFIG_REFUSED_CODE: i64 = shekyl_rpc_types::CORE_RPC_ERROR_CODE_CONFIG_REFUSED;

/// Parses `option_set`'s params. A malformed request, an empty list and a
/// name given twice are request-shape faults, refused with the
/// wrong-parameter code; a configuration refusal is the handle's.
///
/// # Errors
/// [`RpcFault::Refused`] with the wrong-parameter code.
pub fn option_set_request(params: &serde_json::Value) -> Result<Vec<(String, String)>, RpcFault> {
    let request: OptionSetRequest = serde_json::from_value(params.clone())
        .map_err(|e| RpcFault::Refused(RpcRefusal::wrong_param(&format!("option_set: {e}"))))?;
    if request.options.is_empty() {
        return Err(RpcFault::Refused(RpcRefusal::wrong_param(
            "option_set: the list of options is empty",
        )));
    }
    let mut seen = std::collections::BTreeSet::new();
    for pair in &request.options {
        if !seen.insert(pair.name.as_str()) {
            return Err(RpcFault::Refused(RpcRefusal::wrong_param(&format!(
                "option_set: `{}` is given more than once",
                pair.name
            ))));
        }
    }
    Ok(request
        .options
        .into_iter()
        .map(|p| (p.name, p.value))
        .collect())
}

/// Parses `option_show`'s params; absent params mean every row.
///
/// # Errors
/// [`RpcFault::Refused`] with the wrong-parameter code.
pub fn option_show_request(params: &serde_json::Value) -> Result<Option<Vec<String>>, RpcFault> {
    if params.is_null() {
        return Ok(None);
    }
    let request: OptionShowRequest = serde_json::from_value(params.clone())
        .map_err(|e| RpcFault::Refused(RpcRefusal::wrong_param(&format!("option_show: {e}"))))?;
    Ok(request.names)
}

/// `option_set` (RT-O23): builds every pair and applies all or none.
///
/// # Errors
/// [`RpcFault::Refused`] with [`CONFIG_REFUSED_CODE`] carrying every
/// diagnostic in `data`.
pub fn option_set(
    facts: &dyn OptionsFacts,
    pairs: &[(String, String)],
) -> Result<OptionsResponse, RpcFault> {
    match facts.set(pairs) {
        Ok(options) => Ok(OptionsResponse { options }),
        Err(refusals) => Err(RpcFault::Refused(config_refused(refusals))),
    }
}

/// `option_show` (RT-O23): each row the caller may see, in table order. A
/// named row the caller may not see is absent from the reply; an unknown
/// name is refused.
///
/// # Errors
/// [`RpcFault::Refused`].
pub fn option_show(
    facts: &dyn OptionsFacts,
    names: Option<&[String]>,
    disclosure: Disclosure,
) -> Result<OptionsResponse, RpcFault> {
    match facts.show(names) {
        Ok(rows) => Ok(OptionsResponse {
            options: rows
                .into_iter()
                .filter(|r| disclosure.shows(r.grant))
                .map(|r| r.row)
                .collect(),
        }),
        Err(ShowRefusal::Refused(refusal)) => Err(RpcFault::Refused(config_refused(vec![refusal]))),
        Err(ShowRefusal::Absent) => Err(RpcFault::Refused(config_refused(vec![absent_refusal()]))),
    }
}

/// The JSON-RPC error of a configuration refusal: one code, the first
/// diagnostic's text as the message, every diagnostic in `data`.
fn config_refused(refusals: Vec<Refusal>) -> RpcRefusal {
    let message = match refusals.as_slice() {
        [one] => one.message.clone(),
        many => format!(
            "{} configuration refusals; the first: {}",
            many.len(),
            many.first().map_or("", |r| r.message.as_str())
        ),
    };
    RpcRefusal {
        code: CONFIG_REFUSED_CODE,
        message,
        data: serde_json::to_value(refusals).ok(),
    }
}

/// An options handle shared by every listener.
pub type OptionsHandle = Arc<dyn OptionsFacts>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A handle with two rows: a runtime `status` row and a `config` secret.
    struct TwoRows {
        value: Mutex<String>,
    }

    impl OptionsFacts for TwoRows {
        fn set(&self, pairs: &[(String, String)]) -> Result<Vec<ShownRow>, Vec<Refusal>> {
            let mut refusals = Vec::new();
            for (name, value) in pairs {
                if name != "log-level" {
                    refusals.push(Refusal {
                        code: "config.runtime.startup-only".to_owned(),
                        option: Some(name.clone()),
                        source: "runtime".to_owned(),
                        params: Vec::new(),
                        message: format!("`{name}` can only be set at startup"),
                    });
                } else if !["warn", "info"].contains(&value.as_str()) {
                    refusals.push(Refusal {
                        code: "config.value.word".to_owned(),
                        option: Some(name.clone()),
                        source: "runtime".to_owned(),
                        params: vec![("value".to_owned(), value.clone())],
                        message: format!("the value '{value}' is not a level"),
                    });
                }
            }
            if !refusals.is_empty() {
                return Err(refusals);
            }
            let mut rows = Vec::new();
            for (name, value) in pairs {
                *self.value.lock().unwrap() = value.clone();
                rows.push(ShownRow::text(name, "runtime", true, Some(value.clone())));
            }
            Ok(rows)
        }

        fn show(&self, names: Option<&[String]>) -> Result<Vec<VisibleRow>, ShowRefusal> {
            let all = vec![
                VisibleRow {
                    row: ShownRow::text(
                        "log-level",
                        "default",
                        true,
                        Some(self.value.lock().unwrap().clone()),
                    ),
                    grant: Grant::Status,
                },
                VisibleRow {
                    row: ShownRow::secret("tor-socks-password", "default", false),
                    grant: Grant::Config,
                },
            ];
            match names {
                None => Ok(all),
                Some(names) => {
                    let mut picked = Vec::new();
                    for name in names {
                        match all.iter().find(|r| r.row.name() == name) {
                            Some(r) => picked.push(r.clone()),
                            None => {
                                return Err(ShowRefusal::Refused(Refusal {
                                    code: "config.name.unknown".to_owned(),
                                    option: Some(name.clone()),
                                    source: "runtime".to_owned(),
                                    params: Vec::new(),
                                    message: format!("there is no option `{name}`"),
                                }))
                            }
                        }
                    }
                    Ok(picked)
                }
            }
        }
    }

    fn handle() -> TwoRows {
        TwoRows {
            value: Mutex::new("warn".to_owned()),
        }
    }

    /// The request shape: an empty list and a repeated name are
    /// wrong-parameter refusals, not configuration refusals.
    #[test]
    fn an_empty_list_and_a_repeated_name_are_request_faults() {
        let empty = option_set_request(&serde_json::json!({"options": []})).unwrap_err();
        let twice = option_set_request(&serde_json::json!({"options": [
            {"name": "log-level", "value": "info"}, {"name": "log-level", "value": "warn"}]}))
        .unwrap_err();
        for fault in [empty, twice] {
            match fault {
                RpcFault::Refused(r) => assert_eq!(r.code, RpcRefusal::wrong_param("").code),
                other => panic!("{other:?}"),
            }
        }
        let ok = option_set_request(
            &serde_json::json!({"options": [{"name": "log-level", "value": "info"}]}),
        )
        .unwrap();
        assert_eq!(ok, vec![("log-level".to_owned(), "info".to_owned())]);
    }

    /// All or nothing: one refused pair refuses the set, every refusal is
    /// reported in `data` under the configuration code, and the handle's
    /// value is unchanged.
    #[test]
    fn a_refused_pair_refuses_the_whole_set_and_reports_every_refusal() {
        let h = handle();
        let pairs = vec![
            ("log-level".to_owned(), "bogus".to_owned()),
            ("data-dir".to_owned(), "/x".to_owned()),
        ];
        let RpcFault::Refused(refusal) = option_set(&h, &pairs).unwrap_err() else {
            panic!("not a refusal")
        };
        assert_eq!(refusal.code, CONFIG_REFUSED_CODE);
        let data: Vec<Refusal> = serde_json::from_value(refusal.data.unwrap()).unwrap();
        assert_eq!(data.len(), 2);
        assert_eq!(data[0].code, "config.value.word");
        assert_eq!(data[1].code, "config.runtime.startup-only");
        assert_eq!(*h.value.lock().unwrap(), "warn", "nothing applied");
        let set = option_set(&h, &[("log-level".to_owned(), "info".to_owned())]).unwrap();
        assert_eq!(set.options[0].source(), "runtime");
        assert_eq!(set.options[0].value(), Some(Some("info")));
    }

    /// Each row is shown under the grant it names: the view listener sees
    /// no `status` and no `config` row, the admin listener both; a named
    /// row the caller may not see is absent, an unknown name refused.
    #[test]
    fn show_discloses_each_row_under_its_grant() {
        let h = handle();
        let full = option_show(&h, None, Disclosure::FULL).unwrap();
        assert_eq!(full.options.len(), 2);
        assert!(full.options[1].is_secret());
        assert_eq!(
            full.options[1].value(),
            None,
            "a secret carries no value member"
        );
        let view = option_show(&h, None, Disclosure::VIEW).unwrap();
        assert!(view.options.is_empty());
        let named = option_show(
            &h,
            Some(&["tor-socks-password".to_owned()]),
            Disclosure::VIEW,
        )
        .unwrap();
        assert!(named.options.is_empty(), "absent, not refused");
        let RpcFault::Refused(unknown) =
            option_show(&h, Some(&["nope".to_owned()]), Disclosure::FULL).unwrap_err()
        else {
            panic!()
        };
        assert_eq!(unknown.code, CONFIG_REFUSED_CODE);
    }

    /// The secret and value forms serialize as RT-O25 says: a value row has
    /// `value` (text or null) and no `secret`; a secret row has `secret`
    /// and `set` and no `value`.
    #[test]
    fn the_two_row_forms_serialize_apart() {
        let v = serde_json::to_value(ShownRow::text(
            "p2p-upload-max",
            "default",
            true,
            Some("unlimited".into()),
        ))
        .unwrap();
        assert_eq!(v["value"], "unlimited");
        assert!(v.get("secret").is_none());
        let unset =
            serde_json::to_value(ShownRow::text("mine-address", "default", false, None)).unwrap();
        assert!(unset["value"].is_null());
        let s = serde_json::to_value(ShownRow::secret("tor-socks-password", "file", true)).unwrap();
        assert!(s.get("value").is_none());
        assert_eq!(s["secret"], true);
        assert_eq!(s["set"], true);
        assert_eq!(s["runtime"], false);

        let back: ShownRow = serde_json::from_value(v).unwrap();
        assert_eq!(back.value(), Some(Some("unlimited")));
        let unset_back: ShownRow = serde_json::from_value(unset).unwrap();
        assert_eq!(unset_back.value(), Some(None));
        let secret_back: ShownRow = serde_json::from_value(s).unwrap();
        assert_eq!(secret_back.set(), Some(true));

        for bad in [
            serde_json::json!({"name": "a", "source": "default", "runtime": false}),
            serde_json::json!({"name": "a", "source": "default", "runtime": false, "value": "x", "secret": true, "set": true}),
            serde_json::json!({"name": "a", "source": "default", "runtime": false, "secret": false, "set": true}),
            serde_json::json!({"name": "a", "source": "default", "runtime": true, "secret": true, "set": false}),
        ] {
            assert!(
                serde_json::from_value::<ShownRow>(bad).is_err(),
                "an ambiguous or incomplete row is refused"
            );
        }
    }
}
