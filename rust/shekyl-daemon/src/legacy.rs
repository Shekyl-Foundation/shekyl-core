// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Today's spellings, rendered from the typed configuration for the C++
//! readers that survive until commit (e) of the cutover deletes them
//! (`DAEMON_CONFIG_CUTOVER_AUDIT.md` §7, "the daemon at each intermediate
//! commit"). The remnant's `run` parses this vector as `main.cpp` parsed
//! `argv`; when the readers go, this module goes with them.
//!
//! Where today's options cannot say what the grammar says, the nearest
//! spelling is rendered and the gap is named here: a Tor-only posture
//! (clearnet off with Tor on) renders as no clearnet listener, which stops
//! inbound but not outbound clearnet dials; `rpc-admin-listen none`
//! renders nothing, so the C++ binds its default admin listener. Commit (c)
//! moves those readers to their Rust owners and closes both.

use std::ffi::OsStr;

use shekyl_daemon_config::sections::DaemonConfig;
use shekyl_daemon_config::Network;

/// The vector under construction.
struct Args(Vec<String>);

impl Args {
    fn flag(&mut self, name: &str) {
        self.0.push(format!("--{name}"));
    }

    fn pair(&mut self, name: &str, value: String) {
        self.0.push(format!("--{name}"));
        self.0.push(value);
    }
}

/// The argument vector, the program name first, as the C++ parses it.
#[must_use]
pub fn argv(program: &OsStr, config: &DaemonConfig) -> Vec<String> {
    let mut a = Args(vec![program.to_string_lossy().into_owned()]);
    match config.network {
        Network::Mainnet => {}
        Network::Testnet => a.flag("testnet"),
        Network::Stagenet => a.flag("stagenet"),
        Network::Regtest => a.flag("regtest"),
    }
    a.pair("data-dir", config.data_dir.display().to_string());
    if config.offline() {
        a.flag("offline");
    }
    if !config.session.console {
        a.flag("non-interactive");
    }
    a.pair("max-txpool-weight", config.txpool_weight_max.to_string());
    // The connectors, the peers, the link bounds, the RPC and the relay's
    // cover read their sections in Rust; nothing of theirs is rendered.
    if let Some(address) = &config.mine.address {
        a.pair("start-mining", address.clone());
    }
    if let Some(threads) = config.mine.threads {
        a.pair("mining-threads", threads.to_string());
    }
    if let Some(d) = config.dev.difficulty {
        a.pair("fixed-difficulty", d.to_string());
    }
    if !config.dev.sync {
        a.flag("no-sync");
    }
    a.0
}

/// The four levers today's C++ reads from the environment
/// (`DAEMON_CONFIG_CUTOVER.md` §4.2, the environment levers): until commit
/// (e) deletes those reads, the configuration sets them for the C++ that
/// follows in this process. Returned as pairs so the caller sets them; the
/// configuration itself reads none (IG-13).
#[must_use]
pub fn environment(config: &DaemonConfig) -> Vec<(&'static str, String)> {
    let dev = &config.dev;
    [
        ("SEEDHASH_EPOCH_BLOCKS", dev.pow_seed_epoch_blocks),
        ("SEEDHASH_EPOCH_LAG", dev.pow_seed_epoch_lag),
        (
            "SHEKYL_SETTLEMENT_EPOCH_BLOCKS",
            dev.settlement_epoch_blocks,
        ),
        (
            "SHEKYL_ARCHIVAL_REORG_DEPTH_BLOCKS",
            dev.archival_reorg_depth,
        ),
    ]
    .into_iter()
    .filter_map(|(key, value)| value.map(|v| (key, v.to_string())))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_daemon_config::platform::Platform;
    use shekyl_daemon_config::sections::build;
    use shekyl_daemon_config::{choosers, resolve, TABLE};
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    fn config(cli: &[&str]) -> DaemonConfig {
        let args: Vec<OsString> = cli.iter().map(OsString::from).collect();
        let cli = shekyl_options::read_cli(&TABLE, args).unwrap();
        let (network, mode) = choosers(&cli);
        let resolved = resolve(&TABLE, network, cli, Vec::new()).unwrap();
        let platform = Platform {
            home: Some(PathBuf::from("/srv/op")),
            program_data: None,
        };
        build(&resolved, network, mode, &platform, None::<&Path>).unwrap()
    }

    fn render(cli: &[&str]) -> Vec<String> {
        argv(OsStr::new("shekyld"), &config(cli))
    }

    fn value_of<'a>(v: &'a [String], flag: &str) -> Option<&'a str> {
        v.iter().position(|a| a == flag).map(|i| v[i + 1].as_str())
    }

    #[test]
    fn the_defaults_render_todays_default_spellings() {
        let v = render(&[]);
        assert_eq!(v[0], "shekyld");
        assert!(v.contains(&"--non-interactive".to_owned()));
        assert!(!v.contains(&"--offline".to_owned()));
        assert_eq!(value_of(&v, "--data-dir"), Some("/srv/op/.shekyl"));
        // The connectors, the peers, the link, the RPC and the relay read
        // their sections in Rust: none of their spellings is rendered.
        for gone in [
            "--p2p-",
            "--rpc-",
            "--in-peers",
            "--out-peers",
            "--tx-proxy",
            "--add-",
            "--limit-rate",
            "--no-ephemeral-tor",
            "--anonymous-inbound",
            "--proxy",
            "--allow-local-ip",
            "--ban-list",
            "--carrier-development",
            "--clearnet-transport-encrypt",
        ] {
            assert!(
                !v.iter().any(|a| a.starts_with(gone)),
                "{gone} rendered: {v:?}"
            );
        }
    }

    #[test]
    fn postures_and_levers_render_to_their_nearest_spellings() {
        let v = render(&[
            "--network",
            "regtest",
            "--clearnet",
            "off",
            "--tor",
            "off",
            "--dev-difficulty",
            "3",
            "--dev-sync",
            "off",
            "--console",
        ]);
        assert!(v.contains(&"--regtest".to_owned()));
        assert!(v.contains(&"--offline".to_owned()));
        assert!(v.contains(&"--no-sync".to_owned()));
        assert!(!v.contains(&"--non-interactive".to_owned()));
        assert_eq!(value_of(&v, "--fixed-difficulty"), Some("3"));
        let v = render(&["--mine-threads", "2"]);
        assert_eq!(value_of(&v, "--mining-threads"), Some("2"));
    }

    #[test]
    fn the_environment_levers_are_returned_not_set() {
        let c = config(&[
            "--network",
            "regtest",
            "--dev-settlement-epoch-blocks",
            "40",
        ]);
        assert_eq!(
            environment(&c),
            vec![("SHEKYL_SETTLEMENT_EPOCH_BLOCKS", "40".to_owned())]
        );
        assert!(environment(&config(&[])).is_empty());
    }
}
