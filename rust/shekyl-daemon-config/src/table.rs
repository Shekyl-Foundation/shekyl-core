// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon's name table: `docs/design/INPUT_GRAMMAR.md` §5, row for row.
//!
//! Names, kinds, defaults, surfaces, runtime marks and grants are the
//! grammar's. A name the grammar lacks is a row brought to the maintainer,
//! never added here (rule 83). The REJECTED and RESERVED rows are contract
//! entries (IG-10): never accepted, never in help, and never deleted as dead.

use shekyl_options::{
    Default, Dimension, EndpointRule, Grant, KeyRule, Kind, PeerRule, Row, Surface, Table,
    Visibility,
};

/// The five log levels, as `log-level` and `log-category` spell them.
pub const LEVELS: &[&str] = &["error", "warn", "info", "debug", "trace"];

/// The four networks, as `network` spells them.
pub const NETWORKS: &[&str] = &["mainnet", "testnet", "stagenet", "regtest"];

/// The owner that applies a runtime row after `option set` admits it.
///
/// The owner lives beside the table. The shared grammar does not know
/// which part of the daemon a row belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeOwner {
    /// `log-level` and `log-category`.
    Logging,
    /// `p2p-upload-max` and `p2p-download-max`.
    Link,
}

/// The owner of a runtime row. Every other name, including a row the
/// table has not marked runtime, is `None`.
#[must_use]
pub fn runtime_owner(name: &str) -> Option<RuntimeOwner> {
    match name {
        "log-level" | "log-category" => Some(RuntimeOwner::Logging),
        "p2p-upload-max" | "p2p-download-max" => Some(RuntimeOwner::Link),
        _ => None,
    }
}

const LEVEL: Kind = Kind::OneOf(LEVELS);
const ENDPOINT: Kind = Kind::Endpoint(EndpointRule::Any);
const LOOPBACK: Kind = Kind::Endpoint(EndpointRule::Loopback);
const GLOBAL: Kind = Kind::Endpoint(EndpointRule::GlobalUnicast);
const PEER: Kind = Kind::PeerEndpoint(PeerRule::Any);
const ORIGIN: Kind = Kind::Origin;
const RATE: Kind = Kind::Quantity {
    dimension: Dimension::Rate,
    min: 1,
    keywords: &["unlimited"],
};
const BYTES: Kind = Kind::Quantity {
    dimension: Dimension::Bytes,
    min: 1,
    keywords: &[],
};
const COUNT: Kind = Kind::Integer {
    min: 1,
    keywords: &[],
};

const TEST_NETWORKS: &[&str] = &["testnet", "stagenet", "regtest"];
const REGTEST: &[&str] = &["regtest"];

const fn public(
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

const fn runtime(name: &'static str, kind: Kind, default: &'static str, help: &'static str) -> Row {
    Row {
        name,
        kind,
        default: Default::Value(default),
        surface: Surface::Both,
        runtime: true,
        grant: Grant::Status,
        visibility: Visibility::Public,
        help,
    }
}

const fn dev(
    name: &'static str,
    kind: Kind,
    default: Default,
    networks: &'static [&'static str],
    help: &'static str,
) -> Row {
    Row {
        name,
        kind,
        default,
        surface: Surface::Both,
        runtime: false,
        grant: Grant::Config,
        visibility: Visibility::Dev { networks },
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

const NO_DAEMONIZE: &str = "shekyld never daemonizes or registers itself; installing is the installer's and shekyl-cli's, and on Windows shekyld answers the service manager through `service` (RPC_CHANNEL.md RT-16)";
const NO_TLS: &str = "the RPC channel replaces TLS and HTTP authentication (RPC_CHANNEL.md RT-11)";
const NO_BOOTSTRAP: &str = "no proxying to a third-party daemon";
const NO_BG_MINING: &str =
    "background mining was Monero's; the daemon mines when told to (DAEMON_CONFIG_CUTOVER.md §4)";

const ROWS: &[Row] = &[
    // Network, paths, logging
    public("help", Kind::Switch, Default::Unset, Surface::Cli, "Print the options and exit."),
    public("version", Kind::Switch, Default::Unset, Surface::Cli, "Print the version and the operating system, and exit."),
    public("network", Kind::OneOf(NETWORKS), Default::Value("mainnet"), Surface::Cli, "The network to run: mainnet, testnet, stagenet or regtest. Chooses the configuration file."),
    Row {
        name: "service",
        kind: Kind::Switch,
        default: Default::Unset,
        surface: Surface::Cli,
        runtime: false,
        grant: Grant::Config,
        visibility: Visibility::Reserved {
            reason: "the Windows service run mode (RPC_CHANNEL.md RT-16), accepted once RT-W14 builds the service-manager dispatcher",
        },
        help: "",
    },
    public("config-file", Kind::Path, Default::Derived("/etc/shekyl/shekyld-<network>.toml on Linux, FreeBSD and macOS; the daemon's root and shekyld-<network>.toml on Windows"), Surface::Cli, "The configuration file. A missing file at the default path means the defaults; a missing file at a named path is refused."),
    public("data-dir", Kind::Path, Default::Derived("the daemon's root and the network's subdirectory"), Surface::Both, "The data directory. An explicit path is used as given."),
    public("log-file", Kind::Path, Default::Derived("the daemon's root, logs/shekyld-<network>.log"), Surface::Both, "The log file."),
    runtime("log-level", LEVEL, "warn", "The log level: error, warn, info, debug or trace."),
    runtime(
        "log-category",
        Kind::Map {
            keys: KeyRule {
                describe: "a log subsystem: daemon, p2p, sync, chain, store, txpool, relay, rpc, tor, miner, notify or archival",
                check: shekyl_logging::subsystem::is_subsystem,
            },
            value: &LEVEL,
        },
        "none",
        "A log level for one subsystem, as subsystem=level; `none` is no overrides.",
    ),
    public("log-size-max", BYTES, Default::Value("1GiB"), Surface::Both, "The disk the log may use, live file and archives together."),
    // Connectors and P2P
    public("clearnet", Kind::OneOf(&["on", "off"]), Default::Value("on"), Surface::Both, "The clearnet connector."),
    public("tor", Kind::OneOf(&["managed", "operator", "off"]), Default::Value("managed"), Surface::Both, "The Tor connector: a managed Tor, the operator's own Tor, or off."),
    public("tor-socks", ENDPOINT, Default::Unset, Surface::Both, "The operator's Tor SOCKS endpoint; required with tor = operator."),
    public("tor-socks-username", Kind::Secret, Default::Unset, Surface::File, "The SOCKS username for tor-socks."),
    public("tor-socks-password", Kind::Secret, Default::Unset, Surface::File, "The SOCKS password for tor-socks."),
    public("tor-onion", Kind::PeerEndpoint(PeerRule::OnionOnly), Default::Unset, Surface::Both, "This node's onion service and virtual port, on the operator's Tor."),
    public("tor-onion-listen", ENDPOINT, Default::Unset, Surface::Both, "The local endpoint the operator's Tor forwards tor-onion to; required with it."),
    public("tor-file", Kind::Path, Default::Derived("tor/tor beside the executable, else the version-exact bundle directory under /opt/shekyl/ on Unix"), Surface::Both, "The managed Tor binary; tor = managed only. It is verified against the pin wherever it is."),
    public("clearnet-socks", ENDPOINT, Default::Unset, Surface::Both, "A SOCKS proxy for clearnet dials."),
    public("clearnet-socks-username", Kind::Secret, Default::Unset, Surface::File, "The SOCKS username for clearnet-socks."),
    public("clearnet-socks-password", Kind::Secret, Default::Unset, Surface::File, "The SOCKS password for clearnet-socks."),
    public("clearnet-listen", Kind::List(&ENDPOINT), Default::Derived("0.0.0.0 and the network's p2p port"), Surface::Both, "The clearnet listen endpoints; `none` is dial-only on clearnet."),
    public("clearnet-advertise", Kind::List(&GLOBAL), Default::Unset, Surface::Both, "The clearnet endpoints peers can reach this node at; at most one per address family."),
    public("p2p-local", Kind::Switch, Default::Unset, Surface::Both, "Accept peers at private addresses, for a private test network."),
    Row {
        name: "p2p-peer",
        kind: Kind::List(&PEER),
        default: Default::Value("none"),
        surface: Surface::Both,
        runtime: false,
        grant: Grant::Peers,
        visibility: Visibility::Public,
        help: "Peers to connect to, by IP or onion.",
    },
    Row {
        name: "p2p-closed-peer",
        kind: Kind::List(&PEER),
        default: Default::Value("none"),
        surface: Surface::Both,
        runtime: false,
        grant: Grant::Peers,
        visibility: Visibility::Public,
        help: "The only peers to connect to; non-empty declares a closed network.",
    },
    public("p2p-disclose-early", Kind::Switch, Default::Unset, Surface::Both, "Disclose known peers and this node's address below the white-diversity floor, for bootstrapping a small network."),
    Row {
        name: "p2p-ban-file",
        kind: Kind::Path,
        default: Default::Unset,
        surface: Surface::Both,
        runtime: false,
        grant: Grant::Peers,
        visibility: Visibility::Public,
        help: "A file of addresses to refuse, one per line.",
    },
    runtime("p2p-upload-max", RATE, "unlimited", "The upload rate limit, or `unlimited`."),
    runtime("p2p-download-max", RATE, "unlimited", "The download rate limit, or `unlimited`."),
    rejected("upnp", "no UPnP: an attack surface the managed onion makes unnecessary for inbound (DAEMON_CONFIG_CUTOVER.md §8)"),
    rejected("igd", "no UPnP: an attack surface the managed onion makes unnecessary for inbound (DAEMON_CONFIG_CUTOVER.md §8)"),
    rejected("add-priority-node", "it bypasses the identity protections; removed by P2P PR-3"),
    rejected("out-peers", "the outbound degree is a protocol constant"),
    rejected("in-peers", "no operator inbound cap: the descriptor safety bound is the only inbound bound, and the rate rows bound what an operator pays (INPUT_GRAMMAR.md IG-Q40)"),
    rejected("tos-flag", "a traffic-class marking is a label any on-path observer can classify Shekyl traffic by"),
    dev("dev-clearnet-encrypt", Kind::Switch, Default::Unset, TEST_NETWORKS, "Encrypt the clearnet transport; deleted at the Noise flip."),
    dev("dev-sync", Kind::OneOf(&["on", "off"]), Default::Value("on"), REGTEST, "Chain synchronisation with peers."),
    dev("dev-relay-cover", Kind::Switch, Default::Unset, TEST_NETWORKS, "The relay's development cover carrier."),
    // Core, pool, notify, mine
    dev("dev-difficulty", COUNT, Default::Unset, REGTEST, "A fixed difficulty."),
    public("txpool-weight-max", BYTES, Default::Value("648000000B"), Surface::Both, "The transaction pool's weight bound."),
    public("notify-block", Kind::Command { placeholders: &["height", "hash"] }, Default::Unset, Surface::File, "A command to run on a new block, with {height} and {hash}."),
    public("notify-reorg", Kind::Command { placeholders: &["split-height", "height", "added", "removed"] }, Default::Unset, Surface::File, "A command to run on a reorganization, with {split-height}, {height}, {added} and {removed}."),
    public("notify-block-rate", Kind::Command { placeholders: &["window", "observed", "expected"] }, Default::Unset, Surface::File, "A command to run on a block-rate warning, with {window}, {observed} and {expected}."),
    public("mine-address", Kind::Address, Default::Unset, Surface::Both, "Mine to this address from start."),
    public("mine-threads", Kind::Integer { min: 1, keywords: &["auto"] }, Default::Value("auto"), Surface::Both, "The mining thread count, or `auto`."),
    rejected("bg-mining-enable", NO_BG_MINING),
    rejected("bg-mining-ignore-battery", NO_BG_MINING),
    rejected("bg-mining-min-idle-interval", NO_BG_MINING),
    rejected("bg-mining-idle-threshold", NO_BG_MINING),
    rejected("bg-mining-miner-target", NO_BG_MINING),
    // RPC
    Row {
        name: "rpc-listen",
        kind: Kind::List(&ENDPOINT),
        default: Default::Unset,
        surface: Surface::Both,
        runtime: false,
        grant: Grant::Config,
        visibility: Visibility::Reserved {
            reason: "the authenticated channel listener (RPC_CHANNEL.md RT-W10)",
        },
        help: "",
    },
    public("rpc-admin-listen", Kind::List(&LOOPBACK), Default::Derived("127.0.0.1 and the network's rpc port"), Surface::Both, "The plaintext full-access listeners, loopback only; `none` is no admin listener."),
    public("rpc-view-listen", Kind::List(&LOOPBACK), Default::Value("none"), Surface::Both, "The plaintext view listeners, loopback only."),
    public("rpc-cors-origin", Kind::List(&ORIGIN), Default::Value("none"), Surface::Both, "Web origins allowed to call the RPC; `none` denies all. `*` is refused."),
    public("rpc-connections-max", COUNT, Default::Value("25"), Surface::Both, "The RPC connection cap."),
    rejected("rpc-login", NO_TLS),
    rejected("rpc-ssl", NO_TLS),
    rejected("rpc-ssl-private-key", NO_TLS),
    rejected("rpc-ssl-certificate", NO_TLS),
    rejected("rpc-ssl-ca-certificates", NO_TLS),
    rejected("rpc-ssl-allowed-fingerprints", NO_TLS),
    rejected("rpc-ssl-allow-chained", NO_TLS),
    rejected("rpc-ssl-allow-any-cert", NO_TLS),
    rejected("bootstrap-daemon-address", NO_BOOTSTRAP),
    rejected("bootstrap-daemon-login", NO_BOOTSTRAP),
    rejected("bootstrap-daemon-proxy", NO_BOOTSTRAP),
    rejected("public-node", "no public-node advertisement"),
    rejected("max-connections-per-ip", "no per-host inbound cap: a host is not an operator, and the measured inbound adversary opens one edge per victim (SHEKYL_P2P_PROTOCOL.md PWD-I7)"),
    // Session
    public("console", Kind::Switch, Default::Unset, Surface::Cli, "Run the interactive console."),
    // Development levers that were environment variables (IG-8)
    dev("dev-pow-seed-epoch-blocks", COUNT, Default::Unset, REGTEST, "The RandomX seed epoch length, in blocks."),
    dev("dev-pow-seed-epoch-lag", COUNT, Default::Unset, REGTEST, "The RandomX seed epoch lag, in blocks."),
    dev("dev-settlement-epoch-blocks", COUNT, Default::Unset, REGTEST, "The settlement epoch length, in blocks."),
    dev("dev-archival-reorg-depth", COUNT, Default::Unset, REGTEST, "The archival reorg depth, in blocks."),
    rejected("detach", NO_DAEMONIZE),
    rejected("pidfile", NO_DAEMONIZE),
    rejected("install-service", NO_DAEMONIZE),
    rejected("uninstall-service", NO_DAEMONIZE),
    rejected("start-service", NO_DAEMONIZE),
    rejected("stop-service", NO_DAEMONIZE),
    rejected("run-as-service", NO_DAEMONIZE),
];

/// The daemon's table.
pub const TABLE: Table = Table {
    binary: "shekyld",
    rows: ROWS,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// The relay's development cover carrier is a `dev-` lever: absent from
    /// the public help (only `Public` rows render), refused on mainnet,
    /// never an operator setting (COVER_TRAFFIC_RESTORATION.md §3.1). This
    /// is the gate `scripts/ci/check_carrier_flag_hidden.sh` was for the
    /// C++ flag.
    #[test]
    fn the_relay_cover_lever_is_a_dev_row_off_mainnet() {
        let row = TABLE
            .rows
            .iter()
            .find(|r| r.name == "dev-relay-cover")
            .expect("the row");
        match row.visibility {
            shekyl_options::Visibility::Dev { networks } => {
                assert!(!networks.contains(&"mainnet"), "{networks:?}");
                assert!(!networks.is_empty());
            }
            other => panic!("dev-relay-cover is a dev row, not {other:?}"),
        }
    }

    #[test]
    fn the_table_has_no_defects() {
        assert_eq!(TABLE.defects(), Vec::<String>::new());
    }

    /// `INPUT_GRAMMAR.md` §5 counts 48 live names, the four levers among
    /// them. A row added or removed without the grammar fails here first.
    #[test]
    fn the_live_count_is_the_grammars() {
        let live = TABLE.rows.iter().filter(|r| r.is_live()).count();
        assert_eq!(live, 48);
        let levers = TABLE
            .rows
            .iter()
            .filter(|r| matches!(r.visibility, Visibility::Dev { .. }))
            .count();
        assert_eq!(levers, 8);
    }

    #[test]
    fn the_runtime_rows_are_the_four_status_rows() {
        let runtime: Vec<&str> = TABLE
            .rows
            .iter()
            .filter(|r| r.runtime)
            .map(|r| r.name)
            .collect();
        assert_eq!(
            runtime,
            [
                "log-level",
                "log-category",
                "p2p-upload-max",
                "p2p-download-max"
            ]
        );
        assert!(TABLE
            .rows
            .iter()
            .filter(|r| r.runtime)
            .all(|r| r.grant == Grant::Status));
        assert!(TABLE
            .rows
            .iter()
            .filter(|r| r.runtime)
            .all(|r| !matches!(r.kind, Kind::Secret)));
    }

    /// A runtime row has one owner, and a name this function owns is a
    /// runtime row. A fifth runtime row fails here until its owner is named.
    #[test]
    fn every_runtime_row_has_an_owner_and_every_owner_is_runtime() {
        for row in TABLE.rows.iter().filter(|r| r.is_live()) {
            assert_eq!(
                runtime_owner(row.name).is_some(),
                row.runtime,
                "{}",
                row.name
            );
        }
    }

    #[test]
    fn secrets_and_commands_are_file_only_and_the_file_choosers_are_cli_only() {
        for r in TABLE.rows.iter().filter(|r| r.is_live()) {
            if matches!(r.kind, Kind::Secret | Kind::Command { .. }) {
                assert_eq!(r.surface, Surface::File, "{}", r.name);
            }
        }
        for name in ["help", "version", "network", "config-file", "console"] {
            assert_eq!(TABLE.row(name).unwrap().surface, Surface::Cli, "{name}");
        }
    }

    #[test]
    fn a_log_category_key_is_a_subsystem_and_a_level_is_one_of_five() {
        let row = TABLE.row("log-category").unwrap();
        let v = row.kind.parse_cli(&["p2p=debug".into()]).unwrap();
        assert_eq!(v.render(), "p2p=debug");
        assert!(row.kind.parse_cli(&["net=debug".into()]).is_err());
        assert!(row.kind.parse_cli(&["p2p=loud".into()]).is_err());
    }

    #[test]
    fn mainnet_never_accepts_a_development_lever() {
        for r in TABLE.rows {
            if let Visibility::Dev { networks } = r.visibility {
                assert!(!networks.contains(&"mainnet"), "{}", r.name);
                assert!(r.name.starts_with("dev-"), "{}", r.name);
            }
        }
    }
}
