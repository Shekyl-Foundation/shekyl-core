// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The options handle: the daemon's runtime rows behind the RPC's
//! [`OptionsFacts`] (`DAEMON_CONFIG_CUTOVER.md` §2.7, `RPC_CHANNEL.md`
//! §6.4, RT-O23…RT-O27).
//!
//! The handle holds the resolved values the start read, under one lock. A
//! set builds every pair through the table's own constructor, the one the
//! startup parse ran, and refuses the whole request if any pair is refused;
//! then each owner takes its built values in one step that cannot fail: the
//! link budget takes both rates at once, and the logging owner's typed
//! apply takes the base level and the overrides. A show renders each row in
//! table order with its source and the grant the row names; the RPC applies
//! the caller's grants. What show prints, set accepts.

use std::sync::Mutex;

use shekyl_daemon_config::resolve::Resolved;
use shekyl_daemon_config::{Network, TABLE};
use shekyl_daemon_rpc::options::{
    OptionsFacts, Refusal, RowGrant, ShowRefusal, ShownRow, VisibleRow,
};
use shekyl_options::{Code, Diagnostic, Grant, Kind, Row, Source, Value, Visibility};

/// The daemon's options handle.
pub struct DaemonOptions {
    live: Mutex<Resolved>,
    network: Network,
}

impl DaemonOptions {
    /// A handle over the values the start resolved, on `network`.
    #[must_use]
    pub fn new(resolved: Resolved, network: Network) -> Self {
        Self {
            live: Mutex::new(resolved),
            network,
        }
    }

    /// Whether a row exists on this network: a development lever only on
    /// the networks its row names (IG-8).
    fn exists(&self, row: &Row) -> bool {
        match row.visibility {
            Visibility::Dev { networks } => networks.contains(&self.network.name()),
            Visibility::Public => true,
            Visibility::Rejected { .. } | Visibility::Reserved { .. } => false,
        }
    }
}

/// The source word on the wire (RT-O25): one of four, with no path or line.
fn source_word(source: &Source) -> &'static str {
    match source {
        Source::Cli => "cli",
        Source::File { .. } => "file",
        Source::Runtime => "runtime",
        // A machine source is a derived fact, never a row of the table.
        Source::Default | Source::Machine => "default",
    }
}

fn grant_of(row: &Row) -> RowGrant {
    match row.grant {
        Grant::Health => RowGrant::Health,
        Grant::Status => RowGrant::Status,
        Grant::Peers => RowGrant::Peers,
        Grant::Config => RowGrant::Config,
    }
}

/// The wire form of one refusal: the diagnostic's fields and its one
/// rendered message.
fn refusal(d: &Diagnostic) -> Refusal {
    Refusal {
        code: d.code.to_string(),
        option: d.option.clone(),
        source: source_word(&d.source).to_owned(),
        params: d
            .params
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect(),
        message: d.render(),
    }
}

/// One row as `option_show` prints it, from the live values.
fn shown(row: &Row, live: &Resolved) -> ShownRow {
    let source = live.source(row.name).map_or("default", source_word);
    let value = live.get(row.name);
    if matches!(row.kind, Kind::Secret) {
        ShownRow::secret(row.name, source, value.is_some())
    } else {
        ShownRow::text(row.name, source, row.runtime, value.map(Value::render))
    }
}

/// The words `parse_cli` takes for the text `render` printed: a collection
/// renders its entries joined by one space and `none` for empty, a scalar is
/// one word.
fn words_of(kind: &Kind, text: &str) -> Vec<String> {
    if kind.is_collection() {
        text.split_whitespace().map(str::to_owned).collect()
    } else {
        vec![text.to_owned()]
    }
}

/// Builds one pair: the live row, marked runtime, and its value through the
/// constructor.
fn build(name: &str, text: &str) -> Result<(&'static Row, Value), Diagnostic> {
    let row = TABLE.live(name, &Source::Runtime)?;
    // No runtime row is a development lever today, and the table gate
    // keeps `dev-` rows off `option_set` by the runtime mark; a lever
    // marked runtime later would be refused on a network its row does not
    // name at the same place.
    if !row.runtime {
        return Err(Diagnostic::new(Code::RuntimeStartupOnly, Source::Runtime).option(name));
    }
    let value = row
        .kind
        .parse_cli(&words_of(&row.kind, text))
        .map_err(|f| f.at(name, Source::Runtime))?;
    Ok((row, value))
}

/// The link owner's two rates from the live values: a word (`unlimited`)
/// is no bound.
fn rate(live: &Resolved, name: &str) -> Option<u64> {
    match live.get(name) {
        Some(Value::Rate(n)) => Some(*n),
        _ => None,
    }
}

/// The logging owner's words from the live values: the base level and the
/// per-subsystem overrides, as the table admitted them.
fn logging_words(
    live: &Resolved,
) -> (
    tracing::Level,
    Vec<(shekyl_logging::subsystem::Subsystem, tracing::Level)>,
) {
    use shekyl_logging::subsystem::{level_from_word, Subsystem};
    let base = match live.get("log-level") {
        Some(Value::Word(w)) => level_from_word(w),
        _ => None,
    }
    .unwrap_or(tracing::Level::WARN);
    let mut overrides = Vec::new();
    if let Some(Value::Map(map)) = live.get("log-category") {
        for (subsystem, level) in map {
            if let (Some(s), Value::Word(w)) = (Subsystem::from_name(subsystem), level) {
                if let Some(l) = level_from_word(w) {
                    overrides.push((s, l));
                }
            }
        }
    }
    (base, overrides)
}

impl OptionsFacts for DaemonOptions {
    fn set(&self, pairs: &[(String, String)]) -> Result<Vec<ShownRow>, Vec<Refusal>> {
        let mut live = self
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Build: every pair through its constructor, every refusal kept.
        let mut built: Vec<(&'static Row, Value)> = Vec::new();
        let mut refusals = Vec::new();
        for (name, text) in pairs {
            match build(name, text) {
                Ok(b) => built.push(b),
                Err(d) => refusals.push(refusal(&d)),
            }
        }
        if !refusals.is_empty() {
            return Err(refusals);
        }

        // Apply: the values first, then each owner from the live map in one
        // step; the audit line carries each row's old and new text.
        let mut audit = Vec::with_capacity(built.len());
        let mut link = false;
        let mut logging = false;
        for (row, value) in built {
            let old = live
                .get(row.name)
                .map_or_else(|| "unset".to_owned(), Value::render);
            audit.push(format!("{}: {old} -> {}", row.name, value.render()));
            live.values.insert(row.name, (value, Source::Runtime));
            match row.name {
                "p2p-upload-max" | "p2p-download-max" => link = true,
                "log-level" | "log-category" => logging = true,
                _ => {}
            }
        }
        if link {
            shekyl_ffi::link_ffi::set_limits(
                rate(&live, "p2p-upload-max"),
                rate(&live, "p2p-download-max"),
            );
        }
        if logging {
            let (base, overrides) = logging_words(&live);
            shekyl_logging::subsystem::apply(base, &overrides);
        }
        // The caller: the admin listener, the one that serves `option_set`
        // until RT-W10 names connections (RPC_CHANNEL §6.4).
        tracing::info!(
            target: "daemon",
            "option set by the admin listener: {}",
            audit.join("; ")
        );

        Ok(pairs
            .iter()
            .filter_map(|(name, _)| TABLE.row(name).map(|row| shown(row, &live)))
            .collect())
    }

    fn show(&self, names: Option<&[String]>) -> Result<Vec<VisibleRow>, ShowRefusal> {
        let live = self
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let rows: Vec<&'static Row> = match names {
            None => TABLE.rows.iter().filter(|r| self.exists(r)).collect(),
            Some(names) => {
                let mut rows = Vec::with_capacity(names.len());
                for name in names {
                    let row = TABLE
                        .live(name, &Source::Runtime)
                        .map_err(|d| ShowRefusal::Refused(refusal(&d)))?;
                    if !self.exists(row) {
                        // Off its networks the lever does not exist: the
                        // same refusal a startup parse gives (IG-8).
                        let d = Diagnostic::new(Code::DevNetwork, Source::Runtime)
                            .option(name)
                            .param(
                                "networks",
                                match row.visibility {
                                    Visibility::Dev { networks } => networks.join(", "),
                                    _ => String::new(),
                                },
                            )
                            .param("network", self.network.name());
                        return Err(ShowRefusal::Refused(refusal(&d)));
                    }
                    rows.push(row);
                }
                // Table order, whatever order the names came in.
                rows.sort_by_key(|r| TABLE.rows.iter().position(|t| t.name == r.name));
                rows
            }
        };
        Ok(rows
            .into_iter()
            .map(|row| VisibleRow {
                row: shown(row, &live),
                grant: grant_of(row),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_daemon_config::{choosers, resolve};
    use shekyl_options::read_cli;

    fn handle(args: &[&str]) -> DaemonOptions {
        let cli = read_cli(&TABLE, args.iter().map(std::ffi::OsString::from)).unwrap();
        let (network, _mode) = choosers(&cli);
        DaemonOptions::new(resolve(&TABLE, network, cli, Vec::new()).unwrap(), network)
    }

    /// IG-8: on mainnet no development lever exists, so none is shown and a
    /// named one is refused as off its networks; on regtest they are shown.
    #[test]
    fn development_levers_exist_only_on_their_networks() {
        let mainnet = handle(&["--network", "mainnet"]);
        let all = mainnet.show(None).unwrap();
        assert!(all.iter().all(|v| !v.row.name().starts_with("dev-")));
        let refused = mainnet.show(Some(&["dev-sync".to_owned()])).unwrap_err();
        assert!(matches!(refused, ShowRefusal::Refused(r) if r.code == "config.dev.network"));
        let regtest = handle(&["--network", "regtest"]);
        let all = regtest.show(None).unwrap();
        let sync = all.iter().find(|v| v.row.name() == "dev-sync").unwrap();
        assert_eq!(sync.row.value(), Some(Some("on")));
    }

    fn pair(name: &str, value: &str) -> (String, String) {
        (name.to_owned(), value.to_owned())
    }

    fn text_of(handle: &DaemonOptions, name: &str) -> Option<String> {
        let rows = handle.show(Some(&[name.to_owned()])).unwrap();
        rows[0].row.value().and_then(|text| text.map(str::to_owned))
    }

    /// RT-O25: what `option_show` prints, `option_set` accepts, and builds
    /// the same value. Every runtime row's default, then every value a set
    /// applied, fed back.
    #[test]
    fn every_runtime_row_round_trips_its_shown_text_through_set() {
        let h = handle(&["--network", "regtest"]);
        let runtime: Vec<&Row> = TABLE.rows.iter().filter(|r| r.runtime).collect();
        assert_eq!(runtime.len(), 4);
        for row in &runtime {
            let shown = text_of(&h, row.name).expect("a runtime row is never null");
            let before = h.live.lock().unwrap().get(row.name).cloned().unwrap();
            h.set(&[pair(row.name, &shown)]).unwrap();
            let after = h.live.lock().unwrap().get(row.name).cloned().unwrap();
            assert_eq!(before, after, "{}", row.name);
            assert_eq!(text_of(&h, row.name).unwrap(), shown, "{}", row.name);
        }
        // Values that are not defaults, round-tripped the same way.
        for (name, value) in [
            ("p2p-upload-max", "512KiB/s"),
            ("p2p-download-max", "2MiB/s"),
            ("log-level", "debug"),
            ("log-category", "p2p=trace sync=info"),
        ] {
            h.set(&[pair(name, value)]).unwrap();
            let shown = text_of(&h, name).unwrap();
            let first = h.live.lock().unwrap().get(name).cloned().unwrap();
            h.set(&[pair(name, &shown)]).unwrap();
            let second = h.live.lock().unwrap().get(name).cloned().unwrap();
            assert_eq!(first, second, "{name}: {shown}");
            assert_eq!(shown, value, "{name}");
        }
    }

    #[test]
    fn a_set_row_reads_as_runtime_and_a_default_is_written_back() {
        let h = handle(&["--network", "regtest"]);
        let rows = h.set(&[pair("p2p-upload-max", "1MiB/s")]).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].source(), "runtime");
        assert!(rows[0].runtime());
        assert_eq!(rows[0].value(), Some(Some("1MiB/s")));
        h.set(&[pair("p2p-upload-max", "unlimited")]).unwrap();
        assert_eq!(text_of(&h, "p2p-upload-max").as_deref(), Some("unlimited"));
        h.set(&[pair("log-category", "none")]).unwrap();
        assert_eq!(text_of(&h, "log-category").as_deref(), Some("none"));
    }

    /// §6: a set for a row not marked runtime, an unknown name, a rejected
    /// name and a value its constructor refuses, each with its code; and
    /// all or nothing: one refusal applies nothing.
    #[test]
    fn refusals_carry_their_codes_and_nothing_applies_beside_one() {
        let h = handle(&["--network", "regtest"]);
        let err = h
            .set(&[
                pair("log-level", "debug"),
                pair("data-dir", "/elsewhere"),
                pair("no-such-row", "1"),
                pair("upnp", "on"),
                pair("p2p-upload-max", "fast"),
            ])
            .unwrap_err();
        let codes: Vec<&str> = err.iter().map(|r| r.code.as_str()).collect();
        assert_eq!(
            codes,
            [
                "config.runtime.startup-only",
                "config.name.unknown",
                "config.name.rejected",
                "config.value.syntax"
            ]
        );
        assert!(err.iter().all(|r| r.source == "runtime"));
        assert!(
            err[0].message.contains("can only be set at startup"),
            "{}",
            err[0].message
        );
        assert_eq!(
            text_of(&h, "log-level").as_deref(),
            Some("warn"),
            "nothing applied"
        );
    }

    #[test]
    fn show_lists_live_rows_in_table_order_with_their_grants_and_sources() {
        let h = handle(&["--network", "regtest", "--log-level", "info"]);
        let all = h.show(None).unwrap();
        let names: Vec<&str> = all.iter().map(|v| v.row.name()).collect();
        let table: Vec<&str> = TABLE
            .rows
            .iter()
            .filter(|r| r.is_live())
            .map(|r| r.name)
            .collect();
        assert_eq!(names, table);
        let level = all.iter().find(|v| v.row.name() == "log-level").unwrap();
        assert_eq!(level.grant, RowGrant::Status);
        assert_eq!(level.row.source(), "cli");
        let onion = all.iter().find(|v| v.row.name() == "tor-onion").unwrap();
        assert_eq!(onion.grant, RowGrant::Config);
        assert_eq!(
            onion.row.value(),
            Some(None),
            "unset and not runtime is null"
        );
        let secret = all
            .iter()
            .find(|v| matches!(TABLE.row(v.row.name()).unwrap().kind, Kind::Secret))
            .expect("the table has a secret row");
        assert_eq!(secret.row.value(), None);
        assert!(secret.row.is_secret());
        assert_eq!(secret.row.set(), Some(false));

        // Named rows come back in table order whatever the order asked.
        let two = h
            .show(Some(&["p2p-upload-max".to_owned(), "log-level".to_owned()]))
            .unwrap();
        assert_eq!(two[0].row.name(), "log-level");
        assert_eq!(two[1].row.name(), "p2p-upload-max");
        let unknown = h.show(Some(&["nope".to_owned()])).unwrap_err();
        assert!(matches!(unknown, ShowRefusal::Refused(r) if r.code == "config.name.unknown"));
    }
}
