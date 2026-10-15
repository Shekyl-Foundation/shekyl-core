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
use std::net::SocketAddr;

use shekyl_daemon_config::sections::{Clearnet, DaemonConfig, Tor};
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

    fn listener(&mut self, ip_flag: &str, ipv6_flag: &str, port_flag: &str, endpoint: &SocketAddr) {
        if endpoint.is_ipv6() {
            self.pair(ipv6_flag, endpoint.ip().to_string());
        } else {
            self.pair(ip_flag, endpoint.ip().to_string());
        }
        self.pair(port_flag, endpoint.port().to_string());
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
    match &config.clearnet {
        Clearnet::On {
            listen,
            socks,
            advertise,
        } => {
            if let Some(v4) = listen.iter().find(|e| e.is_ipv4()) {
                a.pair("p2p-bind-ip", v4.ip().to_string());
                a.pair("p2p-bind-port", v4.port().to_string());
            }
            if let Some(v6) = listen.iter().find(|e| e.is_ipv6()) {
                a.flag("p2p-use-ipv6");
                a.pair("p2p-bind-ipv6-address", v6.ip().to_string());
                a.pair("p2p-bind-port-ipv6", v6.port().to_string());
            }
            if listen.is_empty() {
                a.pair("in-peers", "0".to_owned());
            }
            if let Some(socks) = socks {
                a.pair("proxy", socks.endpoint.to_string());
            }
            if let Some(first) = advertise.first() {
                a.pair("p2p-external-port", first.port().to_string());
            }
        }
        // No clearnet option exists today (IG-F6); dial-only is the
        // nearest spelling. Commit (c) closes this.
        Clearnet::Off => a.pair("in-peers", "0".to_owned()),
    }
    match &config.tor {
        Tor::Managed { .. } => {}
        Tor::Off => a.flag("no-ephemeral-tor"),
        Tor::Operator { socks, onion } => {
            a.flag("no-ephemeral-tor");
            a.pair("tx-proxy", format!("tor,{}", socks.endpoint));
            if let Some(onion) = onion {
                a.pair(
                    "anonymous-inbound",
                    format!("{}:{},{}", onion.host, onion.virtual_port, onion.listen),
                );
            }
        }
    }
    for peer in &config.p2p.peers {
        a.pair("add-peer", peer.to_string());
    }
    for peer in &config.p2p.closed_peers {
        a.pair("add-exclusive-node", peer.to_string());
    }
    if config.p2p.local {
        a.flag("allow-local-ip");
    }
    if config.p2p.disclose_early {
        a.flag("p2p-disclose-early");
    }
    // Today's rates are integer kB/s; a rate under one kB/s rounds up to it.
    if let Some(up) = config.p2p.upload_max {
        a.pair("limit-rate-up", up.div_ceil(1024).max(1).to_string());
    }
    if let Some(down) = config.p2p.download_max {
        a.pair("limit-rate-down", down.div_ceil(1024).max(1).to_string());
    }
    if let Some(admin) = config.rpc.admin_listen.first() {
        a.listener(
            "rpc-bind-ip",
            "rpc-bind-ipv6-address",
            "rpc-bind-port",
            admin,
        );
    }
    if let Some(view) = config.rpc.view_listen.first() {
        a.listener(
            "rpc-restricted-bind-ip",
            "rpc-restricted-bind-ipv6-address",
            "rpc-restricted-bind-port",
            view,
        );
    }
    if !config.rpc.cors_origins.is_empty() {
        a.pair(
            "rpc-access-control-origins",
            config.rpc.cors_origins.join(","),
        );
    }
    a.pair(
        "rpc-max-connections",
        config.rpc.connections_max.to_string(),
    );
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
    if config.dev.clearnet_encrypt {
        a.flag("clearnet-transport-encrypt");
    }
    if config.dev.relay_cover {
        a.flag("carrier-development");
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
        assert_eq!(value_of(&v, "--p2p-bind-ip"), Some("0.0.0.0"));
        assert_eq!(value_of(&v, "--p2p-bind-port"), Some("11021"));
        assert_eq!(value_of(&v, "--rpc-bind-port"), Some("11029"));
        assert_eq!(value_of(&v, "--rpc-max-connections"), Some("25"));
        assert!(!v.iter().any(|a| a == "--no-ephemeral-tor"));
        assert!(!v.iter().any(|a| a == "--in-peers"));
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
        assert!(v.contains(&"--no-ephemeral-tor".to_owned()));
        assert!(v.contains(&"--no-sync".to_owned()));
        assert!(!v.contains(&"--non-interactive".to_owned()));
        assert_eq!(value_of(&v, "--fixed-difficulty"), Some("3"));
        let v = render(&[
            "--tor",
            "operator",
            "--tor-socks",
            "127.0.0.1:9050",
            "--p2p-upload-max",
            "1KiB/s",
            "--p2p-peer",
            "8.8.8.8:11021",
        ]);
        assert_eq!(value_of(&v, "--tx-proxy"), Some("tor,127.0.0.1:9050"));
        assert_eq!(value_of(&v, "--limit-rate-up"), Some("1"));
        assert_eq!(value_of(&v, "--add-peer"), Some("8.8.8.8:11021"));
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
