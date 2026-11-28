// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `shekyl-cli`'s option table (`INPUT_GRAMMAR.md` §12.1). Options come
//! before the first command word; what follows is the command, read by the
//! catalog. The logging rows are the daemon's kinds, and the daemon-connection
//! rows mean what they mean in `shekyl-wallet-rpc`.

use shekyl_daemon_config::{log_category, BYTES, LEVEL, NETWORKS};
use shekyl_logging::subsystem::{names, Subsystem};
use shekyl_options::{
    Default, EndpointRule, Grant, Kind, PeerRule, Row, Surface, Table, Visibility,
};
use shekyl_wallet_rpc::server::TOR_FILE_OPTION;

use crate::commands::FOUNDATION_PHRASE;

/// The subsystems `shekyl-cli` logs under: the wallet's crates, `shekyl-fcmp`'s
/// proof checks (`chain`), the peer list it reads (`p2p`), the RPC transport
/// (`rpc`) and the process (`daemon`). The audit of the workspace's source
/// holds this list to the code
/// (`the_log_category_keys_are_what_it_logs_under`).
const LOG_SUBSYSTEMS: [Subsystem; 5] = [
    Subsystem::Daemon,
    Subsystem::P2p,
    Subsystem::Chain,
    Subsystem::Rpc,
    Subsystem::Wallet,
];
const LOG_KEYS: [&str; LOG_SUBSYSTEMS.len()] = names(LOG_SUBSYSTEMS);
const LOG_CATEGORY: Kind = log_category("shekyl-cli", &LOG_KEYS);

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

/// The keyword `wallet-password-file` takes for standard input.
pub const PASSWORD_STDIN: &str = "stdin";

const ROWS: &[Row] = &[
    row("help", Kind::Switch, Default::Unset, Surface::Cli, "Print the options and exit."),
    row("version", Kind::Switch, Default::Unset, Surface::Cli, "Print the version and exit."),
    row("config-verify", Kind::Switch, Default::Unset, Surface::Cli, "Check the configuration as a start would, print the effective configuration, and exit. Creates nothing and connects to nothing."),
    row("network", Kind::OneOf(NETWORKS), Default::Value("mainnet"), Surface::Cli, "The network: mainnet, testnet, stagenet or regtest. Chooses the configuration file."),
    row("config-file", Kind::PATH, Default::Derived("this account's root and shekyl-cli-<network>.toml"), Surface::Cli, "The configuration file. A missing file at the default path means the defaults; a missing file at a named path is refused."),
    row("wallet-dir", Kind::PATH, Default::Derived("this account's root and wallets/<network>"), Surface::Both, "The directory of wallet files, for the wallet server this program hosts."),
    row("wallet-file", Kind::PATH, Default::Unset, Surface::Both, "The wallet to open at start, as the absolute path of its <name>.wallet file. Its folder is the wallet directory. Not with wallet-rpc-endpoint or wallet-rpc-socket-file: that server's wallets are on its computer, so use `wallet open <name>`."),
    rejected("daemon-address", "use daemon-endpoint and daemon-bundle-file for the node’s authenticated channel"),
    rejected("proxy", "use daemon-socks with daemon-endpoint to reach the node through SOCKS5"),
    row("daemon-endpoint", Kind::PeerEndpoint(PeerRule::Any), Default::Unset, Surface::Both, "The daemon on another computer: an IP address and a port, or an onion and a port (reached through daemon-socks). Unset is this computer's node."),
    rejected("daemon-socket-file", shekyl_wallet_rpc::table::NO_DAEMON_SOCKET),
    row("daemon-bundle-file", Kind::PATH, Default::Unset, Surface::Both, "The node's public bundle, as `rpc bundle show` prints it on that node. Set, the enrollment words reach the node at daemon-endpoint over the channel, and daemon-endpoint is required."),
    row("rpc-key-file", Kind::PATH, Default::Derived("this account's root and rpc-client.key"), Surface::Both, "This client's channel key, readable by this account alone."),
    row("wallet-rpc-endpoint", Kind::PeerEndpoint(PeerRule::Any), Default::Unset, Surface::Both, "An external shekyl-wallet-rpc to use instead of hosting one: an IP address and a port, or an onion and a port (reached through daemon-socks)."),
    row("wallet-rpc-socket-file", Kind::PATH, Default::Unset, Surface::Both, "An external shekyl-wallet-rpc's Unix socket, in place of wallet-rpc-endpoint. Not on Windows."),
    row("daemon-socks", Kind::Endpoint(EndpointRule::Any), Default::Unset, Surface::Both, "A SOCKS5 proxy for the connections to another computer; the proxy resolves names. Required for an onion."),
    rejected("daemon-ca-cert", "the https arm is removed: the RPC channel replaces TLS (RPC_TRANSPORT_POSTURE.md RT-O8)"),
    row("debug", Kind::Switch, Default::Unset, Surface::Both, "Print the machine detail of a failure."),
    row("wallet-password-file", Kind::Path { keywords: &[PASSWORD_STDIN] }, Default::Unset, Surface::Both, "The wallet password: a file only this account can read, or `stdin` for one line of standard input. Required when standard input is not a terminal."),
    row("archival-complete-tree", Kind::Switch, Default::Unset, Surface::Both, "Post a Foundation CompleteTree bond before the first command: unbounded disk, no reward. Needs wallet-file."),
    row("archival-acknowledge", Kind::OneOf(&[FOUNDATION_PHRASE]), Default::Unset, Surface::Cli, "The exact phrase that accepts archival-complete-tree's terms when standard input is not a terminal."),
    row("json", Kind::Switch, Default::Unset, Surface::Cli, "Print one JSON object per command. Seeds and passwords are never included."),
    row("script-file", Kind::PATH, Default::Unset, Surface::Cli, "Run the commands in this file as one session. `#` starts a comment. The first failure stops the file."),
    row("log-file", Kind::PATH, Default::Unset, Surface::Both, "A log file. Unset, logs go to standard error and no file is written."),
    row("log-level", LEVEL, Default::Value("warn"), Surface::Both, "The log level: error, warn, info, debug or trace."),
    row("log-category", LOG_CATEGORY, Default::Value("none"), Surface::Both, "A log level for one subsystem, as subsystem=level; `none` is no overrides."),
    row("log-size-max", BYTES, Default::Value("1GiB"), Surface::Both, "The disk a named log file may use, live file and archives together."),
    row(TOR_FILE_OPTION, Kind::PATH, Default::Unset, Surface::Both, "The Tor binary the wallet server this program hosts runs when it serves. Unset, the bundled one is found. Either way it must match the pinned build. Not with wallet-rpc-endpoint or wallet-rpc-socket-file."),
];

/// `shekyl-cli`'s table.
pub const TABLE: Table = Table {
    binary: "shekyl-cli",
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

    /// The ruled phrase has spaces, so the one-of row has to take it whole
    /// as a single argument.
    #[test]
    fn the_acknowledgement_is_the_ruled_phrase() {
        let row = TABLE.row("archival-acknowledge").expect("the row");
        assert!(row.kind.parse_text(FOUNDATION_PHRASE).is_ok());
        assert!(row.kind.parse_text("serve").is_err());
    }
    /// `shekyl-cli`'s `log-category` keys are the subsystems its code and its
    /// dependencies log under, no more and no fewer; a subsystem it writes
    /// nothing under is refused naming `shekyl-cli`. Red edit: add or drop a
    /// subsystem in `LOG_SUBSYSTEMS`.
    #[test]
    fn the_log_category_keys_are_what_it_logs_under() {
        assert_eq!(TABLE.binary, "shekyl-cli");
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
        assert_eq!(refusal.get("binary"), Some("shekyl-cli"));
    }
}
