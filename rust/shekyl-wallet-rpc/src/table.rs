// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `shekyl-wallet-rpc`'s option table (`INPUT_GRAMMAR.md` §12.4). The
//! logging rows are the daemon's kinds, read by the same mapping
//! (`shekyl_daemon_config::logging_to_named_file`), and the daemon-connection
//! rows mean what they mean in `shekyl-cli`.

use shekyl_daemon_config::{log_category, BYTES, LEVEL, NETWORKS};
use shekyl_logging::subsystem::{names, Subsystem};
use shekyl_options::{
    Default, EndpointRule, Grant, Kind, PeerRule, Row, Surface, Table, Visibility,
};

use crate::server::TOR_FILE_OPTION;

/// The subsystems `shekyl-wallet-rpc` logs under: the wallet's crates, `shekyl-
/// fcmp`'s proof checks (`chain`), the RPC transport (`rpc`) and the process
/// (`daemon`). The audit of the workspace's source holds this list to the code
/// (`the_log_category_keys_are_what_it_logs_under`).
const LOG_SUBSYSTEMS: [Subsystem; 4] = [
    Subsystem::Daemon,
    Subsystem::Chain,
    Subsystem::Rpc,
    Subsystem::Wallet,
];
const LOG_KEYS: [&str; LOG_SUBSYSTEMS.len()] = names(LOG_SUBSYSTEMS);
const LOG_CATEGORY: Kind = log_category("shekyl-wallet-rpc", &LOG_KEYS);

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

const fn rejected(name: &'static str, reason: &'static str) -> Row {
    Row {
        name,
        kind: Kind::Switch,
        default: Default::Unset,
        surface: Surface::Both,
        runtime: false,
        grant: Grant::Config,
        visibility: Visibility::Rejected { reason },
        help: "",
    }
}

/// Why a client names no socket of the daemon's.
pub const NO_DAEMON_SOCKET: &str = "a client names \"this computer\" by its network alone, so it cannot name a wrong socket (RPC_CHANNEL.md RT-15; Rick, 2026-11-18): leave daemon-endpoint unset to reach this account's node";

const ROWS: &[Row] = &[
    row("help", Kind::Switch, Default::Unset, Surface::Cli, "Print the options and exit."),
    row("version", Kind::Switch, Default::Unset, Surface::Cli, "Print the version and exit."),
    row("config-verify", Kind::Switch, Default::Unset, Surface::Cli, "Check the configuration as a start would, print the effective configuration, and exit. Creates nothing and binds nothing."),
    row("network", Kind::OneOf(NETWORKS), Default::Value("mainnet"), Surface::Cli, "The network every wallet binds to: mainnet, testnet, stagenet or regtest. Chooses the configuration file."),
    row("config-file", Kind::PATH, Default::Derived("this account's root and shekyl-wallet-rpc-<network>.toml"), Surface::Cli, "The configuration file. A missing file at the default path means the defaults; a missing file at a named path is refused."),
    row("wallet-dir", Kind::PATH, Default::Derived("this account's root and wallets/<network>"), Surface::Both, "The directory of wallet files."),
    row("rpc-listen", Kind::Endpoint(EndpointRule::Any), Default::Value("127.0.0.1:29500"), Surface::Both, "A loopback IP address and port. For remote access, forward the local listener over your own encrypted transport."),
    row("rpc-socket-file", Kind::PATH, Default::Unset, Surface::Both, "A Unix socket to listen on in place of rpc-listen, in a directory only this account can enter. Not on Windows."),
    row("rpc-username", Kind::Secret, Default::Unset, Surface::File, "The HTTP basic user clients must give. Set with rpc-password, or neither."),
    row("rpc-password", Kind::Secret, Default::Unset, Surface::File, "The HTTP basic password clients must give. Set with rpc-username, or neither."),
    rejected("daemon-address", "use daemon-endpoint and daemon-bundle-file for the node’s authenticated channel"),
    rejected("proxy", "use daemon-socks with daemon-endpoint to reach the node through SOCKS5"),
    row("daemon-bundle-file", Kind::PATH, Default::Unset, Surface::Both, "The node's public bundle exported by shekyl-cli rpc bundle show. Required with daemon-endpoint."),
    row("rpc-key-file", Kind::PATH, Default::Derived("this account's root and rpc-client.key"), Surface::Both, "The owner-only account key, created on first channel use."),
    row("daemon-endpoint", Kind::PeerEndpoint(PeerRule::Any), Default::Unset, Surface::Both, "The daemon on another computer: an IP address and a port, or an onion and a port (reached through daemon-socks). Unset is this computer's node."),
    rejected("daemon-socket-file", NO_DAEMON_SOCKET),
    row("daemon-socks", Kind::Endpoint(EndpointRule::Any), Default::Unset, Surface::Both, "A SOCKS5 proxy to reach daemon-endpoint through; the proxy resolves its name. Required for an onion."),
    row("log-file", Kind::PATH, Default::Unset, Surface::Both, "A log file. Unset, the server logs to standard error and writes no file."),
    row("log-level", LEVEL, Default::Value("warn"), Surface::Both, "The log level: error, warn, info, debug or trace."),
    row("log-category", LOG_CATEGORY, Default::Value("none"), Surface::Both, "A log level for one subsystem, as subsystem=level; `none` is no overrides."),
    row("log-size-max", BYTES, Default::Value("1GiB"), Surface::Both, "The disk a named log file may use, live file and archives together."),
    row(TOR_FILE_OPTION, Kind::PATH, Default::Unset, Surface::Both, "The Tor binary a serving wallet runs. Unset, the bundled one is found. Either way it must match the pinned build."),
];

/// `shekyl-wallet-rpc`'s table.
pub const TABLE: Table = Table {
    binary: "shekyl-wallet-rpc",
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
        for name in ["log-level", "log-size-max", "network"] {
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
    /// `shekyl-wallet-rpc`'s `log-category` keys are the subsystems its code and its
    /// dependencies log under, no more and no fewer; a subsystem it writes
    /// nothing under is refused naming `shekyl-wallet-rpc`. Red edit: add or drop a
    /// subsystem in `LOG_SUBSYSTEMS`.
    #[test]
    fn the_log_category_keys_are_what_it_logs_under() {
        assert_eq!(TABLE.binary, "shekyl-wallet-rpc");
        shekyl_logging::audit::assert_keys_are_what_it_logs(TABLE.binary, &LOG_SUBSYSTEMS);
        let row = TABLE.row("log-category").expect("the row");
        for key in LOG_KEYS {
            assert!(
                row.kind.parse_cli(&[format!("{key}=debug")]).is_ok(),
                "{key}"
            );
        }
        let refusal = row
            .kind
            .parse_cli(&["store=debug".into()])
            .unwrap_err()
            .at("log-category", shekyl_options::Source::Cli);
        assert_eq!(refusal.code, shekyl_options::Code::ValueKeyNotTaken);
        assert_eq!(refusal.get("binary"), Some("shekyl-wallet-rpc"));
    }
}
