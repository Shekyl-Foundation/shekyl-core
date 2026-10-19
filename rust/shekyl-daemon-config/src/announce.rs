// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The required announcements (IG-14): the effective-configuration line,
//! every development lever set, and the posture line. They reach the log
//! and standard error at every start whatever the level; they are not log
//! events.

use std::path::Path;

use shekyl_options::{Source, Table, Visibility};

use crate::resolve::Resolved;
use crate::sections::{Clearnet, DaemonConfig, Tor};

/// Every value and its source, in table order, as one line. A secret shows
/// as `set`, never its text. The configuration file read, or the default
/// path at which none was found, leads.
#[must_use]
pub fn effective_configuration(
    table: &Table,
    resolved: &Resolved,
    config_file: Option<&Path>,
    default_path: &Path,
) -> String {
    let mut parts = Vec::with_capacity(resolved.values.len() + 1);
    parts.push(match config_file {
        Some(p) => format!("config-file={} (cli)", p.display()),
        None => format!("config-file=none-at:{} (default)", default_path.display()),
    });
    // The config-file row is the first part above, with the path's fate.
    for row in table
        .rows
        .iter()
        .filter(|r| r.is_live() && r.name != "config-file")
    {
        if let Some((value, source)) = resolved.values.get(row.name) {
            let shown = match source {
                Source::Cli => "cli".to_owned(),
                Source::File { line, .. } => format!("file:{line}"),
                Source::Default => "default".to_owned(),
                Source::Runtime => "runtime".to_owned(),
                Source::Machine => "machine".to_owned(),
            };
            parts.push(format!("{}={} ({shown})", row.name, value.render()));
        }
    }
    format!("effective configuration: {}", parts.join(" "))
}

/// One line per development lever set (IG-8).
#[must_use]
pub fn dev_levers(table: &Table, resolved: &Resolved) -> Vec<String> {
    table
        .rows
        .iter()
        .filter(|r| matches!(r.visibility, Visibility::Dev { .. }))
        .filter(|r| !matches!(resolved.source(r.name), None | Some(Source::Default)))
        .filter_map(|r| {
            resolved
                .get(r.name)
                .map(|v| format!("development lever set: {}={}", r.name, v.render()))
        })
        .collect()
}

/// The posture line: offline, clearnet-only, Tor-only, or both; whether
/// clearnet is dial-only; and a plaintext listener beyond loopback, which
/// the table refuses and so never appears.
#[must_use]
pub fn posture(config: &DaemonConfig) -> String {
    let mut parts = Vec::new();
    match (&config.clearnet, &config.tor) {
        (Clearnet::Off, Tor::Off) => parts.push("offline: no clearnet and no Tor".to_owned()),
        (Clearnet::Off, _) => parts.push("Tor-only: clearnet is off".to_owned()),
        (Clearnet::On { listen, .. }, Tor::Off) => {
            parts.push("clearnet-only: Tor is off".to_owned());
            if listen.is_empty() {
                parts.push("clearnet dial-only: no listener".to_owned());
            }
        }
        (Clearnet::On { listen, .. }, _) => {
            parts.push("clearnet and Tor".to_owned());
            if listen.is_empty() {
                parts.push("clearnet dial-only: no listener".to_owned());
            }
        }
    }
    if let Clearnet::On { advertise, .. } = &config.clearnet {
        if advertise.is_empty() {
            parts.push("clearnet address not advertised".to_owned());
        }
    }
    match &config.tor {
        Tor::Managed { .. } => parts.push("Tor managed: a per-boot onion".to_owned()),
        Tor::Operator { onion: Some(_), .. } => parts.push("Tor operator: an onion".to_owned()),
        Tor::Operator { onion: None, .. } => parts.push("Tor operator: dial-only".to_owned()),
        Tor::Off => {}
    }
    format!("posture: {}", parts.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::Network;
    use crate::platform::{Platform, RunMode};
    use crate::resolve::{choosers, resolve};
    use crate::sections::build;
    use crate::table::TABLE;
    use std::ffi::OsString;
    use std::path::PathBuf;

    fn resolved_only(cli: &[&str], file: &str) -> Resolved {
        let args: Vec<OsString> = cli.iter().map(OsString::from).collect();
        let cli = shekyl_options::read_cli(&TABLE, args).unwrap();
        let (network, _mode) = choosers(&cli);
        let given =
            shekyl_options::read_file(&TABLE, Path::new("/etc/shekyl/x.toml"), file).unwrap();
        resolve(&TABLE, network, cli, given).unwrap()
    }

    fn setup(cli: &[&str], file: &str) -> (Resolved, DaemonConfig) {
        let args: Vec<OsString> = cli.iter().map(OsString::from).collect();
        let cli = shekyl_options::read_cli(&TABLE, args).unwrap();
        let (network, mode) = choosers(&cli);
        let given =
            shekyl_options::read_file(&TABLE, Path::new("/etc/shekyl/x.toml"), file).unwrap();
        let mut resolved = resolve(&TABLE, network, cli, given).unwrap();
        let platform = Platform {
            home: Some(PathBuf::from("/srv/op")),
            program_data: None,
        };
        let config = build(&mut resolved, network, mode, &platform, None).unwrap();
        (resolved, config)
    }

    /// The line is rendered from the resolved values after the build has
    /// named every derived default. A secret row shows as `set` and its
    /// value never prints (DC-Q7: the SOCKS pair).
    #[test]
    fn the_line_shows_every_value_with_its_source_and_never_a_secret() {
        let mut resolved = resolved_only(
            &[
                "--network",
                "regtest",
                "--dev-difficulty",
                "7",
                "--tor",
                "operator",
                "--tor-socks",
                "127.0.0.1:9050",
            ],
            "tor-socks-username = \"u\"\ntor-socks-password = \"hunter2\"\nlog-level = \"info\"\n",
        );
        let platform = Platform {
            home: Some(PathBuf::from("/srv/op")),
            program_data: None,
        };
        let built = build(
            &mut resolved,
            Network::Regtest,
            RunMode::User,
            &platform,
            None,
        );
        assert!(built.is_ok(), "a SOCKS pair with its proxy builds");
        let line = effective_configuration(
            &TABLE,
            &resolved,
            None,
            Path::new("/etc/shekyl/shekyld-regtest.toml"),
        );
        assert!(line.starts_with("effective configuration: config-file=none-at:/etc/shekyl/shekyld-regtest.toml (default)"), "{line}");
        assert!(line.contains("dev-difficulty=7 (cli)"), "{line}");
        assert!(line.contains("log-level=info (file:3)"), "{line}");
        assert!(line.contains("tor-socks-username=set (file:1)"), "{line}");
        assert!(line.contains("tor-socks-password=set (file:2)"), "{line}");
        assert!(!line.contains("hunter2"), "{line}");
        assert!(
            line.contains("p2p-upload-max=unlimited (default)"),
            "{line}"
        );
        let root = crate::paths::root(&platform, RunMode::User, "data-dir").unwrap();
        let data = crate::paths::data_dir_default(&root, Network::Regtest);
        let log = crate::paths::log_file_default(&root, Network::Regtest);
        assert!(
            line.contains(&format!("data-dir={} (default)", data.display())),
            "{line}"
        );
        assert!(
            line.contains(&format!("log-file={} (default)", log.display())),
            "{line}"
        );
        assert!(
            line.contains("clearnet-listen=0.0.0.0:11021 (default)"),
            "{line}"
        );
        assert!(
            line.contains("rpc-admin-listen=127.0.0.1:11029 (default)"),
            "{line}"
        );
        assert!(!line.contains("tor-file="), "{line}");
        assert!(resolved.get("tor-file").is_none());
        let levers = dev_levers(&TABLE, &resolved);
        assert_eq!(
            levers,
            vec!["development lever set: dev-difficulty=7".to_owned()]
        );
    }

    #[test]
    fn the_posture_names_the_connectors_and_dial_only() {
        let (_, c) = setup(&[], "");
        assert_eq!(posture(&c), "posture: clearnet and Tor; clearnet address not advertised; Tor managed: a per-boot onion");
        let (_, c) = setup(&["--clearnet", "off", "--tor", "off"], "");
        assert_eq!(posture(&c), "posture: offline: no clearnet and no Tor");
        let (_, c) = setup(&["--clearnet-listen", "none", "--tor", "off"], "");
        assert_eq!(posture(&c), "posture: clearnet-only: Tor is off; clearnet dial-only: no listener; clearnet address not advertised");
        let _ = RunMode::User;
        let _ = Network::Mainnet;
    }
}
