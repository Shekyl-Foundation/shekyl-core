// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Precedence: the command line over the file over the defaults, per key
//! (`INPUT_GRAMMAR.md` R6, IG-7), and the development levers' network gate
//! (IG-8).

use std::collections::BTreeMap;

use shekyl_options::{Cli, Code, Default, Diagnostic, Given, Source, Table, Value, Visibility};

use crate::network::Network;
use crate::platform::RunMode;

/// Every row's value after precedence, with where it came from.
#[derive(Clone, Debug)]
pub struct Resolved {
    /// The value of each row that has one: given, or the row's default
    /// value. A row with no default and no value is absent.
    pub values: BTreeMap<&'static str, (Value, Source)>,
    /// The words that are not options.
    pub positional: Vec<String>,
}

impl Resolved {
    /// The value of a row, if it has one.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.values.get(name).map(|(v, _)| v)
    }

    /// Where a row's value came from, if it has one.
    #[must_use]
    pub fn source(&self, name: &str) -> Option<&Source> {
        self.values.get(name).map(|(_, s)| s)
    }

    /// Whether a switch is on.
    #[must_use]
    pub fn switch(&self, name: &str) -> bool {
        matches!(self.get(name), Some(Value::Switch(true)))
    }
}

/// The two command-line-only choosers the file cannot change: the network
/// and the run mode (DC-Q18). Read before the file is located.
#[must_use]
pub fn choosers(cli: &Cli) -> (Network, RunMode) {
    let network = cli
        .given
        .iter()
        .find(|g| g.row.name == "network")
        .and_then(|g| match &g.value {
            Value::Word(w) => Network::from_word(w),
            _ => None,
        })
        .unwrap_or(Network::Mainnet);
    let mode = if cli.given.iter().any(|g| g.row.name == "service") {
        RunMode::Service
    } else {
        RunMode::User
    };
    (network, mode)
}

/// Applies precedence and the network gate.
///
/// # Errors
/// Every development lever given on a network its row does not name
/// (`config.dev.network`), and every default the table cannot build, which
/// `Table::defects` already refuses.
pub fn resolve(
    table: &Table,
    network: Network,
    cli: Cli,
    file: Vec<Given>,
) -> Result<Resolved, Vec<Diagnostic>> {
    let mut faults = Vec::new();
    let mut values: BTreeMap<&'static str, (Value, Source)> = BTreeMap::new();
    for row in table.rows.iter().filter(|r| r.is_live()) {
        if let Default::Value(text) = row.default {
            let built = if row.kind.is_collection() || row.kind.is_switch() {
                row.kind.parse_cli(&[text.to_owned()])
            } else {
                row.kind.parse_text(text)
            };
            match built {
                Ok(v) => {
                    values.insert(row.name, (v, Source::Default));
                }
                Err(f) => faults.push(f.at(row.name, Source::Default)),
            }
        }
    }
    for given in file.into_iter().chain(cli.given) {
        if let Visibility::Dev { networks } = given.row.visibility {
            if !networks.contains(&network.name()) {
                faults.push(
                    Diagnostic::new(Code::DevNetwork, given.source.clone())
                        .option(given.row.name)
                        .param("networks", networks.join(", "))
                        .param("network", network.name()),
                );
                continue;
            }
        }
        values.insert(given.row.name, (given.value, given.source));
    }
    if faults.is_empty() {
        Ok(Resolved {
            values,
            positional: cli.positional,
        })
    } else {
        Err(faults)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::table::TABLE;
    use std::ffi::OsString;
    use std::path::Path;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    #[test]
    fn the_cli_wins_per_key_over_the_file_over_the_default() {
        let cli = shekyl_options::read_cli(
            &TABLE,
            args(&["--log-level", "debug", "--network", "regtest"]),
        )
        .unwrap();
        let (network, mode) = choosers(&cli);
        assert_eq!(network, Network::Regtest);
        assert_eq!(mode, RunMode::User);
        let file = shekyl_options::read_file(
            &TABLE,
            Path::new("/x.toml"),
            "log-level = \"trace\"\nmine-threads = 3\n",
        )
        .unwrap();
        let r = resolve(&TABLE, network, cli, file).unwrap();
        assert_eq!(r.get("log-level"), Some(&Value::Word("debug")));
        assert_eq!(r.source("log-level"), Some(&Source::Cli));
        assert_eq!(r.get("mine-threads"), Some(&Value::Integer(3)));
        assert!(matches!(
            r.source("mine-threads"),
            Some(Source::File { line: 2, .. })
        ));
        assert_eq!(r.get("p2p-upload-max"), Some(&Value::Word("unlimited")));
        assert_eq!(r.source("p2p-upload-max"), Some(&Source::Default));
        assert_eq!(r.get("dev-difficulty"), None);
        assert_eq!(r.get("tor"), Some(&Value::Word("managed")));
    }

    #[test]
    fn a_cli_list_replaces_the_files_list_whole() {
        let cli = shekyl_options::read_cli(&TABLE, args(&["--p2p-peer", "8.8.8.8:1"])).unwrap();
        let file = shekyl_options::read_file(
            &TABLE,
            Path::new("/x.toml"),
            "p2p-peer = [\"9.9.9.9:2\", \"7.7.7.7:3\"]\n",
        )
        .unwrap();
        let r = resolve(&TABLE, Network::Mainnet, cli, file).unwrap();
        assert!(matches!(r.get("p2p-peer"), Some(Value::List(v)) if v.len() == 1));
    }

    #[test]
    fn a_development_lever_is_refused_off_its_networks_and_always_on_mainnet() {
        let cli = shekyl_options::read_cli(&TABLE, args(&["--dev-difficulty", "1"])).unwrap();
        let d = resolve(&TABLE, Network::Mainnet, cli, Vec::new()).unwrap_err();
        assert_eq!(d[0].code, Code::DevNetwork);
        assert!(d[0].render().contains("regtest"));
        let cli = shekyl_options::read_cli(&TABLE, args(&["--dev-difficulty", "1"])).unwrap();
        let d = resolve(&TABLE, Network::Testnet, cli, Vec::new()).unwrap_err();
        assert_eq!(d[0].code, Code::DevNetwork);
        let cli = shekyl_options::read_cli(&TABLE, args(&["--dev-difficulty", "1"])).unwrap();
        assert!(resolve(&TABLE, Network::Regtest, cli, Vec::new()).is_ok());
    }
}
