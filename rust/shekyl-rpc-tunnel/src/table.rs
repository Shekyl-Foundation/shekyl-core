// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The tunnel's option table (`INPUT_GRAMMAR.md` IG-Q108…IG-Q111, ruled
//! 2026-11-15). One table shared in meaning with the CLI's channel rows:
//! `daemon-endpoint`, `daemon-socks`, `daemon-bundle-file` and `rpc-key-file`
//! mean the same thing in both. The logging rows are the daemon's, of the
//! same kinds, read by the same mapping (`shekyl_daemon_config::logging`).

use shekyl_daemon_config::{BYTES, LEVEL, LOG_CATEGORY, NETWORKS};
use shekyl_options::{
    Default, EndpointRule, Grant, Kind, PeerRule, Row, Surface, Table, Visibility,
};
use shekyl_rpc_types::wire::rpc::CeilingWord;

const fn row(
    name: &'static str,
    kind: Kind,
    default: Default,
    surface: Surface,
    help: &'static str,
) -> Row {
    Row {
        name,
        kind,
        default,
        surface,
        runtime: false,
        grant: Grant::Config,
        visibility: Visibility::Public,
        help,
    }
}

const CEILING_WORD: Kind = Kind::OneOf(CeilingWord::WORDS);

const ROWS: &[Row] = &[
    row("help", Kind::Switch, Default::Unset, Surface::Cli, "Print the options and exit."),
    row("version", Kind::Switch, Default::Unset, Surface::Cli, "Print the version and the operating system, and exit."),
    row("rpc-key-create", Kind::Switch, Default::Unset, Surface::Cli, "Make this tunnel's key at rpc-key-file, readable by this account alone, print its fingerprint for the node's `rpc client add`, and exit. Refused if a key is there."),
    row("rpc-key-show", Kind::Switch, Default::Unset, Surface::Cli, "Print this tunnel's fingerprint and exit."),
    row("network", Kind::OneOf(NETWORKS), Default::Value("mainnet"), Surface::Cli, "The node's network: mainnet, testnet, stagenet or regtest. Chooses the configuration file."),
    row("config-file", Kind::PATH, Default::Derived("this account's root and shekyl-rpc-tunnel-<network>.toml"), Surface::Cli, "The configuration file. A missing file at the default path means the defaults; a missing file at a named path is refused."),
    row("daemon-endpoint", Kind::PeerEndpoint(PeerRule::Any), Default::Unset, Surface::Both, "The node's channel listener: an IP address and a port, or an onion and a port (reached through daemon-socks). Required."),
    row("daemon-socks", Kind::Endpoint(EndpointRule::Any), Default::Unset, Surface::Both, "A SOCKS5 proxy to reach the node through; the proxy resolves its name. Required for an onion."),
    row("daemon-bundle-file", Kind::PATH, Default::Unset, Surface::Both, "The node's public bundle, as `rpc bundle show` prints it on that node. Required."),
    row("rpc-key-file", Kind::PATH, Default::Derived("this account's root and rpc-shekyl-rpc-tunnel-<network>.key"), Surface::Both, "This tunnel's channel key, readable by this account alone (make it with rpc-key-create)."),
    row("rpc-grant", Kind::List(&CEILING_WORD), Default::Value("view"), Surface::Both, "The grants the tunnel's sessions ask for, as grant and preset words, the option repeated. The node clamps it to this tunnel's ceiling; the tunnel reports what it received."),
    row("listen", Kind::Endpoint(EndpointRule::Loopback), Default::Unset, Surface::Both, "The local listener consumers reach the node through: a loopback address and a port, never a wildcard (RT-14). Required unless listen-socket-file is set."),
    row("listen-socket-file", Kind::PATH, Default::Unset, Surface::Both, "A socket for local consumers, in a directory only this account can enter, in place of listen. Not on Windows."),
    row("log-file", Kind::PATH, Default::Derived("this account's root, logs/shekyl-rpc-tunnel-<network>.log"), Surface::Both, "The log file."),
    row("log-level", LEVEL, Default::Value("warn"), Surface::Both, "The log level: error, warn, info, debug or trace."),
    row("log-category", LOG_CATEGORY, Default::Value("none"), Surface::Both, "A log level for one subsystem, as subsystem=level; `none` is no overrides."),
    row("log-size-max", BYTES, Default::Value("1GiB"), Surface::Both, "The disk the log may use, live file and archives together."),
];

/// The tunnel's table.
pub const TABLE: Table = Table {
    binary: "shekyl-rpc-tunnel",
    rows: ROWS,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// The table is well formed by the grammar's own checks, and the rows it
    /// shares with the daemon are the daemon's kinds. Red edit: give
    /// `log-level` its own one-of list here, and it differs from the
    /// daemon's.
    #[test]
    fn the_table_is_well_formed_and_shares_the_daemons_kinds() {
        assert!(TABLE.defects().is_empty(), "{:?}", TABLE.defects());
        for name in ["log-level", "log-category", "log-size-max", "network"] {
            let ours = TABLE.row(name).expect("our row");
            let daemons = shekyl_daemon_config::TABLE
                .row(name)
                .expect("the daemon's row");
            assert_eq!(
                format!("{:?}", ours.kind),
                format!("{:?}", daemons.kind),
                "{name}"
            );
        }
    }
}
