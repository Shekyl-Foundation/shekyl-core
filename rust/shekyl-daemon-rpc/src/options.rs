// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `option_set` and `option_show` (`RPC_CHANNEL.md` §6.4, RT-O23…RT-O27;
//! `DAEMON_CONFIG_CUTOVER.md` §2.7): the two runtime option methods,
//! served natively over an options handle the composition root supplies
//! ([`OptionsFacts`]), in the shape `shard_fetch`'s facts have.
//! This crate depends on the interface, never on the grammar or the
//! subsystems. The wire types live in `shekyl-rpc-types::options` (RK-D1)
//! and are re-exported here; the root converts.
//!
//! `option_set` is all or nothing under the handle's one lock: every value
//! is built first, every refusal is reported, and nothing is applied when
//! one is refused. `option_show` reads under the same lock and discloses
//! each row under the grant the row names.

use std::sync::Arc;

use crate::info::Disclosure;

use shekyl_rpc_types::errors::{Diagnostic, ErrorClass, RpcError};
use shekyl_rpc_types::method::Grant;
use shekyl_rpc_types::wire::node;

pub use shekyl_rpc_types::options::Refusal;
pub use shekyl_rpc_types::wire::node::{OptionRow as ShownRow, OptionSource};

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
        option: shekyl_rpc_types::Nullable(None),
        source: "runtime".to_owned(),
        parameter: std::collections::BTreeMap::new(),
        message: "this daemon serves no options: no options handle was supplied".to_owned(),
    }
}

/// Why an options method did not answer: a configuration refusal, every
/// diagnostic the table gave (RT-O25), or the call itself refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OptionsFault {
    /// The table refused: class `RefusedByMethod`, and `data` is the list.
    Config(Vec<Refusal>),
    /// The request was refused before the table was asked.
    Refused(RpcError),
}

impl OptionsFault {
    /// The error object's class, its message, and its `data`.
    #[must_use]
    pub fn into_parts(self) -> (ErrorClass, String, serde_json::Value) {
        match self {
            Self::Config(refusals) => {
                let message = match refusals.as_slice() {
                    [one] => one.message.clone(),
                    many => format!(
                        "{} configuration refusals; the first: {}",
                        many.len(),
                        many.first().map_or("", |r| r.message.as_str())
                    ),
                };
                let data = serde_json::to_value(&refusals).unwrap_or(serde_json::Value::Null);
                (ErrorClass::RefusedByMethod, message, data)
            }
            Self::Refused(error) => {
                let data =
                    serde_json::to_value(&error.diagnostic).unwrap_or(serde_json::Value::Null);
                (error.class, error.diagnostic.message, data)
            }
        }
    }
}

/// `option_set { value }` (RT-O23, IG-Q42): every named row set at once,
/// or none. A row a name cannot appear twice in: the request is a map.
///
/// # Errors
///
/// `option.value-empty` for a map with no row; the table's refusals, with
/// nothing applied.
pub fn option_set(
    facts: &dyn OptionsFacts,
    request: &node::OptionSet,
) -> Result<Vec<ShownRow>, OptionsFault> {
    if request.value.0.is_empty() {
        return Err(OptionsFault::Refused(RpcError::new(
            ErrorClass::BadParams,
            Diagnostic::new("option.value-empty", "option_set names no option"),
        )));
    }
    let pairs: Vec<(String, String)> = request
        .value
        .0
        .iter()
        .map(|(name, value)| (name.clone(), value.0.clone()))
        .collect();
    facts.set(&pairs).map_err(OptionsFault::Config)
}

/// `option_show { name }` (RT-O23): each row the caller may see, in table
/// order, or every such row when no name is given. A named row the caller
/// may not see is absent; an unknown name is refused.
///
/// # Errors
///
/// The table's refusal.
pub fn option_show(
    facts: &dyn OptionsFacts,
    request: &node::OptionShow,
    disclosure: Disclosure,
) -> Result<Vec<ShownRow>, OptionsFault> {
    let names: Option<Vec<String>> = request
        .name
        .as_ref()
        .map(|names| names.iter().map(|name| name.0.clone()).collect());
    match facts.show(names.as_deref()) {
        Ok(rows) => Ok(rows
            .into_iter()
            .filter(|r| disclosure.shows(r.grant))
            .map(|r| r.row)
            .collect()),
        Err(ShowRefusal::Refused(refusal)) => Err(OptionsFault::Config(vec![refusal])),
        Err(ShowRefusal::Absent) => Err(OptionsFault::Config(vec![absent_refusal()])),
    }
}

/// An options handle shared by every listener.
pub type OptionsHandle = Arc<dyn OptionsFacts>;

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_rpc_types::kinds::Text;
    use shekyl_rpc_types::wire::shared::OpenMap;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    fn refusal(code: &str, name: &str, message: String) -> Refusal {
        Refusal {
            code: code.to_owned(),
            option: shekyl_rpc_types::Nullable(Some(name.to_owned())),
            source: "runtime".to_owned(),
            parameter: BTreeMap::new(),
            message,
        }
    }

    /// A handle with two rows: a runtime `status` row and a `config` secret.
    struct TwoRows {
        value: Mutex<String>,
    }

    impl OptionsFacts for TwoRows {
        fn set(&self, pairs: &[(String, String)]) -> Result<Vec<ShownRow>, Vec<Refusal>> {
            let mut refusals = Vec::new();
            for (name, value) in pairs {
                if name != "log-level" {
                    refusals.push(refusal(
                        "config.runtime.startup-only",
                        name,
                        format!("`{name}` can only be set at startup"),
                    ));
                } else if !["warn", "info"].contains(&value.as_str()) {
                    let mut r = refusal(
                        "config.value.word",
                        name,
                        format!("the value '{value}' is not a level"),
                    );
                    r.parameter.insert("value".to_owned(), value.clone());
                    refusals.push(r);
                }
            }
            if !refusals.is_empty() {
                return Err(refusals);
            }
            let mut rows = Vec::new();
            for (name, value) in pairs {
                *self.value.lock().unwrap() = value.clone();
                rows.push(ShownRow::text(
                    name,
                    OptionSource::Runtime,
                    true,
                    Some(value.clone()),
                ));
            }
            Ok(rows)
        }

        fn show(&self, names: Option<&[String]>) -> Result<Vec<VisibleRow>, ShowRefusal> {
            let all = vec![
                VisibleRow {
                    row: ShownRow::text(
                        "log-level",
                        OptionSource::Default,
                        true,
                        Some(self.value.lock().unwrap().clone()),
                    ),
                    grant: Grant::Status,
                },
                VisibleRow {
                    row: ShownRow::secret("tor-socks-password", OptionSource::Default, false),
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
                                return Err(ShowRefusal::Refused(refusal(
                                    "config.name.unknown",
                                    name,
                                    format!("there is no option `{name}`"),
                                )))
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

    fn set(pairs: &[(&str, &str)]) -> node::OptionSet {
        node::OptionSet {
            value: OpenMap(
                pairs
                    .iter()
                    .map(|(n, v)| ((*n).to_owned(), Text((*v).to_owned())))
                    .collect(),
            ),
        }
    }

    /// The request shape: an empty map is `option.value-empty`, a request
    /// fault and not a configuration refusal; a name cannot repeat, because
    /// the request is a map (IG-Q42).
    #[test]
    fn an_empty_map_is_a_request_fault_and_a_name_cannot_repeat() {
        let h = handle();
        let OptionsFault::Refused(empty) = option_set(&h, &set(&[])).unwrap_err() else {
            panic!("a request fault")
        };
        assert_eq!(empty.class, ErrorClass::BadParams);
        assert_eq!(empty.diagnostic.code, "option.value-empty");
        let twice: Result<node::OptionSet, _> =
            serde_json::from_str(r#"{"value": {"log-level": "info", "log-level": "warn"}}"#);
        assert!(
            twice.is_err() || twice.unwrap().value.0.len() == 1,
            "a repeated name is one row or no request, never two"
        );
    }

    /// All or nothing: one refused pair refuses the set, every refusal is
    /// reported in `data` (RT-O25), and the handle's value is unchanged.
    #[test]
    fn a_refused_pair_refuses_the_whole_set_and_reports_every_refusal() {
        let h = handle();
        let OptionsFault::Config(refusals) =
            option_set(&h, &set(&[("log-level", "bogus"), ("data-dir", "/x")])).unwrap_err()
        else {
            panic!("a configuration refusal")
        };
        assert_eq!(refusals.len(), 2);
        let (class, _, data) = OptionsFault::Config(refusals).into_parts();
        assert_eq!(class, ErrorClass::RefusedByMethod);
        let data: Vec<Refusal> = serde_json::from_value(data).unwrap();
        let mut codes: Vec<&str> = data.iter().map(|r| r.code.as_str()).collect();
        codes.sort_unstable();
        assert_eq!(codes, ["config.runtime.startup-only", "config.value.word"]);
        assert_eq!(*h.value.lock().unwrap(), "warn", "nothing applied");
        let rows = option_set(&h, &set(&[("log-level", "info")])).unwrap();
        assert_eq!(rows[0].source(), OptionSource::Runtime);
        assert_eq!(rows[0].value(), Some(Some("info")));
    }

    /// Each row is shown under the grant it names: a view caller sees no
    /// `status` and no `config` row, the host both; a named row the caller
    /// may not see is absent, an unknown name refused.
    #[test]
    fn show_discloses_each_row_under_its_grant() {
        let h = handle();
        let all = node::OptionShow { name: None };
        let full = option_show(&h, &all, Disclosure::FULL).unwrap();
        assert_eq!(full.len(), 2);
        assert!(full[1].is_secret());
        assert_eq!(full[1].value(), None, "a secret carries no value member");
        assert!(option_show(&h, &all, Disclosure::VIEW).unwrap().is_empty());
        let named = option_show(
            &h,
            &node::OptionShow {
                name: Some(vec![Text("tor-socks-password".to_owned())]),
            },
            Disclosure::VIEW,
        )
        .unwrap();
        assert!(named.is_empty(), "absent, not refused");
        let unknown = option_show(
            &h,
            &node::OptionShow {
                name: Some(vec![Text("nope".to_owned())]),
            },
            Disclosure::FULL,
        )
        .unwrap_err();
        assert!(matches!(unknown, OptionsFault::Config(r) if r[0].code == "config.name.unknown"));
    }

    /// A daemon with no options handle refuses both methods with
    /// `config.runtime.absent`, never an empty list.
    #[test]
    fn an_absent_handle_refuses_both_methods() {
        for fault in [
            option_set(&OptionsAbsent, &set(&[("log-level", "info")])).unwrap_err(),
            option_show(
                &OptionsAbsent,
                &node::OptionShow { name: None },
                Disclosure::FULL,
            )
            .unwrap_err(),
        ] {
            assert!(
                matches!(fault, OptionsFault::Config(r) if r[0].code == "config.runtime.absent")
            );
        }
    }

    /// The secret and value forms serialize apart (RT-O25): a value row has
    /// `value` (text or null) and `secret: false`; a secret row has
    /// `secret: true` and `assigned`, and no `value`.
    #[test]
    fn the_two_row_forms_serialize_apart() {
        let v = serde_json::to_value(ShownRow::text(
            "p2p-upload-max",
            OptionSource::Default,
            true,
            Some("unlimited".into()),
        ))
        .unwrap();
        assert_eq!(v["value"], "unlimited");
        assert_eq!(v["secret"], false);
        let unset = serde_json::to_value(ShownRow::text(
            "mine-address",
            OptionSource::Default,
            false,
            None,
        ))
        .unwrap();
        assert!(unset["value"].is_null());
        let s = serde_json::to_value(ShownRow::secret(
            "tor-socks-password",
            OptionSource::File,
            true,
        ))
        .unwrap();
        assert!(s.get("value").is_none());
        assert_eq!(s["secret"], true);
        assert_eq!(s["runtime"], false);
        assert_eq!(s["assigned"], true);

        let back: ShownRow = serde_json::from_value(v).unwrap();
        assert_eq!(back.value(), Some(Some("unlimited")));
        let unset_back: ShownRow = serde_json::from_value(unset).unwrap();
        assert_eq!(unset_back.value(), Some(None));
        assert!(serde_json::from_value::<ShownRow>(s).unwrap().is_secret());

        for bad in [
            serde_json::json!({"name": "a", "source": "default", "runtime": false}),
            serde_json::json!({"name": "a", "source": "nowhere", "runtime": false, "secret": false, "value": null}),
        ] {
            assert!(
                serde_json::from_value::<ShownRow>(bad).is_err(),
                "an incomplete or misnamed row is refused"
            );
        }
    }
}
