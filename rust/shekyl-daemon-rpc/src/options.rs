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

/// The grant a row names (`RPC_CHANNEL.md` RT-O24).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowGrant {
    /// What a client needs to decide whether it can use the node now.
    Health,
    /// This node's own settings that say nothing lasting about it.
    Status,
    /// The peer, closed-peer and ban rows.
    Peers,
    /// Everything else; the admin preset only.
    Config,
}

impl RowGrant {
    /// Whether a caller with `disclosure` is shown a row of this grant.
    #[must_use]
    pub const fn shown_to(self, disclosure: Disclosure) -> bool {
        match self {
            Self::Health => true,
            Self::Status => disclosure.status(),
            Self::Peers => disclosure.peers(),
            Self::Config => disclosure.config(),
        }
    }
}

/// One row as `option_show` reports it and `option_set` echoes it
/// (RT-O25): the value as text in the grammar's syntax, or the secret
/// form with no value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShownRow {
    /// The option's name.
    pub name: String,
    /// `default`, `file`, `cli` or `runtime`.
    pub source: String,
    /// Whether `option_set` accepts it.
    pub runtime: bool,
    /// The value as text, or `null` when unset; absent on a secret row.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub value: Option<Option<String>>,
    /// Present, and true, on a secret row only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<bool>,
    /// Whether a secret row holds a value; present on a secret row only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set: Option<bool>,
}

/// A `value` member that is present, `null` included: serde reads `null`
/// into the outer `Option` otherwise, which would make an unset value row
/// read as a row with no `value` member (RT-O25's secret form).
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(d).map(Some)
}

impl ShownRow {
    /// A value row.
    #[must_use]
    pub fn value(name: &str, source: &str, runtime: bool, value: Option<String>) -> Self {
        Self {
            name: name.to_owned(),
            source: source.to_owned(),
            runtime,
            value: Some(value),
            secret: None,
            set: None,
        }
    }

    /// A secret row: no text, only whether it is set.
    #[must_use]
    pub fn secret(name: &str, source: &str, set: bool) -> Self {
        Self {
            name: name.to_owned(),
            source: source.to_owned(),
            runtime: false,
            value: None,
            secret: Some(true),
            set: Some(set),
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
    pub grant: RowGrant,
}

/// Why `option_show` could not answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShowRefusal {
    /// A name the table lacks; carries the diagnostic the startup parse
    /// would give.
    UnknownName(Refusal),
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
                .filter(|r| r.grant.shown_to(disclosure))
                .map(|r| r.row)
                .collect(),
        }),
        Err(ShowRefusal::UnknownName(refusal)) => {
            Err(RpcFault::Refused(config_refused(vec![refusal])))
        }
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
                rows.push(ShownRow::value(name, "runtime", true, Some(value.clone())));
            }
            Ok(rows)
        }

        fn show(&self, names: Option<&[String]>) -> Result<Vec<VisibleRow>, ShowRefusal> {
            let all = vec![
                VisibleRow {
                    row: ShownRow::value(
                        "log-level",
                        "default",
                        true,
                        Some(self.value.lock().unwrap().clone()),
                    ),
                    grant: RowGrant::Status,
                },
                VisibleRow {
                    row: ShownRow::secret("tor-socks-password", "default", false),
                    grant: RowGrant::Config,
                },
            ];
            match names {
                None => Ok(all),
                Some(names) => {
                    let mut picked = Vec::new();
                    for name in names {
                        match all.iter().find(|r| r.row.name == *name) {
                            Some(r) => picked.push(r.clone()),
                            None => {
                                return Err(ShowRefusal::UnknownName(Refusal {
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
        assert_eq!(set.options[0].source, "runtime");
        assert_eq!(set.options[0].value, Some(Some("info".to_owned())));
    }

    /// Each row is shown under the grant it names: the view listener sees
    /// no `status` and no `config` row, the admin listener both; a named
    /// row the caller may not see is absent, an unknown name refused.
    #[test]
    fn show_discloses_each_row_under_its_grant() {
        let h = handle();
        let full = option_show(&h, None, Disclosure::FULL).unwrap();
        assert_eq!(full.options.len(), 2);
        assert_eq!(full.options[1].secret, Some(true));
        assert_eq!(
            full.options[1].value, None,
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
        let v = serde_json::to_value(ShownRow::value(
            "p2p-upload-max",
            "default",
            true,
            Some("unlimited".into()),
        ))
        .unwrap();
        assert_eq!(v["value"], "unlimited");
        assert!(v.get("secret").is_none());
        let unset =
            serde_json::to_value(ShownRow::value("mine-address", "default", false, None)).unwrap();
        assert!(unset["value"].is_null());
        let s = serde_json::to_value(ShownRow::secret("tor-socks-password", "file", true)).unwrap();
        assert!(s.get("value").is_none());
        assert_eq!(s["secret"], true);
        assert_eq!(s["set"], true);
    }
}
