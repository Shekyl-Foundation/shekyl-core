// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The typed configuration, by section (`DAEMON_CONFIG_CUTOVER.md` §3).
//!
//! Each section is what its Rust owner needs, designed for that owner, and
//! taken at construction. Cross-row constraints are types, not checks
//! (`INPUT_GRAMMAR.md` §4): the clearnet posture is `Off` or `On` with its
//! listeners, the Tor posture is `Off`, `Managed` or `Operator` with its
//! SOCKS endpoint, so a SOCKS endpoint for a connector that is off cannot
//! be constructed, and a peer whose connector is off is refused here.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use shekyl_options::{Code, Diagnostic, PeerEndpoint, Secret, Source, Value};

use crate::network::Network;
use crate::paths;
use crate::platform::{Platform, RunMode};
use crate::resolve::Resolved;

/// A SOCKS5 proxy and its credentials (RFC 1929), held only in Rust.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Socks {
    /// The proxy.
    pub endpoint: SocketAddr,
    /// The username, when the proxy authenticates.
    pub username: Option<Secret>,
    /// The password, when the proxy authenticates.
    pub password: Option<Secret>,
}

/// The clearnet connector's posture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Clearnet {
    /// No clearnet.
    Off,
    /// Clearnet on.
    On {
        /// The listen endpoints; empty is dial-only.
        listen: Vec<SocketAddr>,
        /// A proxy for dials.
        socks: Option<Socks>,
        /// The endpoints peers can reach this node at; at most one per
        /// address family.
        advertise: Vec<SocketAddr>,
    },
}

/// This node's onion service on the operator's Tor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Onion {
    /// The service's hostname, `<56 base32>.onion`.
    pub host: String,
    /// The virtual port peers dial.
    pub virtual_port: u16,
    /// The local endpoint the operator's Tor forwards to.
    pub listen: SocketAddr,
}

/// The Tor connector's posture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tor {
    /// No Tor.
    Off,
    /// A Tor this daemon starts and supervises.
    Managed {
        /// The binary, when the operator names one; otherwise discovered.
        binary: Option<PathBuf>,
    },
    /// The operator's own Tor.
    Operator {
        /// Its SOCKS endpoint.
        socks: Socks,
        /// This node's onion on it, when published.
        onion: Option<Onion>,
    },
}

/// One ban-file entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ban {
    /// An IPv4 subnet, `a.b.c.d/n`.
    Subnet(Ipv4Addr, u8),
    /// One host, any port.
    Host(IpAddr),
    /// One peer endpoint.
    Peer(PeerEndpoint),
}

/// The dialer's and the peer lists' section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P2p {
    /// Peers to connect to.
    pub peers: Vec<PeerEndpoint>,
    /// The only peers to connect to; non-empty declares a closed network.
    pub closed_peers: Vec<PeerEndpoint>,
    /// Accept peers at private addresses.
    pub local: bool,
    /// Disclose below the white-diversity floor.
    pub disclose_early: bool,
    /// The ban file's entries, read at parse.
    pub bans: Vec<Ban>,
    /// The upload rate limit in bytes per second; `None` is unlimited.
    pub upload_max: Option<u64>,
    /// The download rate limit in bytes per second; `None` is unlimited.
    pub download_max: Option<u64>,
}

/// The RPC service's section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rpc {
    /// The plaintext full-access listeners, loopback only.
    pub admin_listen: Vec<SocketAddr>,
    /// The plaintext view listeners, loopback only.
    pub view_listen: Vec<SocketAddr>,
    /// The web origins allowed; empty denies all.
    pub cors_origins: Vec<String>,
    /// The connection cap.
    pub connections_max: NonZeroU32,
}

/// The logging owner's section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Logging {
    /// The log file.
    pub file: PathBuf,
    /// The base level word.
    pub level: &'static str,
    /// Per-subsystem level words.
    pub categories: Vec<(String, &'static str)>,
    /// The disk the log may use, live file and archives together.
    pub size_max: u64,
}

impl Logging {
    /// The `EnvFilter` directive the logging owner installs.
    #[must_use]
    pub fn directive(&self) -> String {
        let overrides: Vec<(&str, &str)> = self
            .categories
            .iter()
            .map(|(s, l)| (s.as_str(), *l))
            .collect();
        shekyl_logging::subsystem::directive_from_words(self.level, &overrides)
            .expect("the table admits only level words and subsystem keys")
    }

    /// The file sink, sized within the budget by the logging owner.
    #[must_use]
    pub fn file_sink(&self) -> shekyl_logging::FileSink {
        let dir = self
            .file
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        let prefix = self.file.file_name().map_or_else(
            || "shekyld.log".to_owned(),
            |n| n.to_string_lossy().into_owned(),
        );
        shekyl_logging::FileSink::within_budget(dir, prefix, self.size_max)
    }
}

/// The notify runner's three commands.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Notify {
    /// On a new block: `{height}`, `{hash}`.
    pub block: Option<Vec<String>>,
    /// On a reorganization: `{split-height}`, `{height}`, `{added}`, `{removed}`.
    pub reorg: Option<Vec<String>>,
    /// On a block-rate warning: `{window}`, `{observed}`, `{expected}`.
    pub block_rate: Option<Vec<String>>,
}

/// The miner's section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mine {
    /// Mine to this address from start; checked against the network.
    pub address: Option<String>,
    /// The thread count; `None` is `auto`, the miner's own default.
    pub threads: Option<NonZeroU32>,
}

/// The development levers (IG-8), each accepted only on its networks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dev {
    /// A fixed difficulty.
    pub difficulty: Option<u64>,
    /// Chain synchronisation with peers.
    pub sync: bool,
    /// Encrypt the clearnet transport.
    pub clearnet_encrypt: bool,
    /// The relay's development cover carrier.
    pub relay_cover: bool,
    /// The RandomX seed epoch length.
    pub pow_seed_epoch_blocks: Option<u64>,
    /// The RandomX seed epoch lag.
    pub pow_seed_epoch_lag: Option<u64>,
    /// The settlement epoch length.
    pub settlement_epoch_blocks: Option<u64>,
    /// The archival reorg depth.
    pub archival_reorg_depth: Option<u64>,
}

/// The interim C++ console's section, until `shekyl-cli` serves it (R8).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Session {
    /// Run the interactive console.
    pub console: bool,
    /// The positional words: a client-mode command, empty for a daemon
    /// start.
    pub command: Vec<String>,
    /// The admin endpoint a client-mode command reaches; present only in
    /// client mode.
    pub client_endpoint: Option<SocketAddr>,
}

/// The whole configuration, by section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonConfig {
    /// The network.
    pub network: Network,
    /// The run mode.
    pub run_mode: RunMode,
    /// The configuration file read, if one was.
    pub config_file: Option<PathBuf>,
    /// The resolved data directory.
    pub data_dir: PathBuf,
    /// The logging section.
    pub logging: Logging,
    /// The clearnet connector.
    pub clearnet: Clearnet,
    /// The Tor connector.
    pub tor: Tor,
    /// The dialer and the peer lists.
    pub p2p: P2p,
    /// The RPC service.
    pub rpc: Rpc,
    /// The transaction pool's weight bound.
    pub txpool_weight_max: u64,
    /// The notify runner.
    pub notify: Notify,
    /// The miner.
    pub mine: Mine,
    /// The development levers.
    pub dev: Dev,
    /// The console.
    pub session: Session,
}

impl DaemonConfig {
    /// Offline: both connectors off (IG-Q3).
    #[must_use]
    pub fn offline(&self) -> bool {
        self.clearnet == Clearnet::Off && self.tor == Tor::Off
    }

    /// Whether this process is a client of a running daemon (§2.2, client
    /// mode).
    #[must_use]
    pub fn is_client(&self) -> bool {
        !self.session.command.is_empty()
    }
}

/// The address network a daemon network's addresses belong to: regtest
/// runs mainnet's genesis and prefixes.
fn address_network(network: Network) -> shekyl_address::Network {
    match network {
        Network::Mainnet | Network::Regtest => shekyl_address::Network::Mainnet,
        Network::Testnet => shekyl_address::Network::Testnet,
        Network::Stagenet => shekyl_address::Network::Stagenet,
    }
}

struct Reader<'a> {
    resolved: &'a Resolved,
    faults: Vec<Diagnostic>,
}

impl<'a> Reader<'a> {
    fn source(&self, name: &str) -> Source {
        self.resolved
            .source(name)
            .cloned()
            .unwrap_or(Source::Default)
    }

    fn given(&self, name: &str) -> bool {
        !matches!(self.resolved.source(name), None | Some(Source::Default))
    }

    fn word(&self, name: &str) -> Option<&'static str> {
        match self.resolved.get(name) {
            Some(Value::Word(w)) => Some(w),
            _ => None,
        }
    }

    fn integer(&self, name: &str) -> Option<u64> {
        match self.resolved.get(name) {
            Some(Value::Integer(n)) => Some(*n),
            _ => None,
        }
    }

    fn bytes(&self, name: &str) -> Option<u64> {
        match self.resolved.get(name) {
            Some(Value::Bytes(n)) => Some(*n),
            _ => None,
        }
    }

    /// A rate, or `None` for `unlimited` and unset.
    fn rate(&self, name: &str) -> Option<u64> {
        match self.resolved.get(name) {
            Some(Value::Rate(n)) => Some(*n),
            _ => None,
        }
    }

    fn endpoint(&self, name: &str) -> Option<SocketAddr> {
        match self.resolved.get(name) {
            Some(Value::Endpoint(e)) => Some(*e),
            _ => None,
        }
    }

    fn endpoints(&self, name: &str) -> Vec<SocketAddr> {
        match self.resolved.get(name) {
            Some(Value::List(items)) => items
                .iter()
                .filter_map(|v| match v {
                    Value::Endpoint(e) => Some(*e),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    fn peers(&self, name: &str) -> Vec<PeerEndpoint> {
        match self.resolved.get(name) {
            Some(Value::List(items)) => items
                .iter()
                .filter_map(|v| match v {
                    Value::Peer(p) => Some(p.clone()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    fn onion(&self, name: &str) -> Option<(String, u16)> {
        match self.resolved.get(name) {
            Some(Value::Peer(PeerEndpoint::Onion { host, port })) => Some((host.clone(), *port)),
            _ => None,
        }
    }

    fn path(&self, name: &str) -> Option<PathBuf> {
        match self.resolved.get(name) {
            Some(Value::Path(p)) => Some(p.clone()),
            _ => None,
        }
    }

    fn secret(&self, name: &str) -> Option<Secret> {
        match self.resolved.get(name) {
            Some(Value::Secret(s)) => Some(s.clone()),
            _ => None,
        }
    }

    fn command(&self, name: &str) -> Option<Vec<String>> {
        match self.resolved.get(name) {
            Some(Value::Command(args)) => Some(args.clone()),
            _ => None,
        }
    }

    fn origins(&self, name: &str) -> Vec<String> {
        match self.resolved.get(name) {
            Some(Value::List(items)) => items
                .iter()
                .filter_map(|v| match v {
                    Value::Origin(o) => Some(o.clone()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    fn conflict(&mut self, name: &str, conflict: &str) {
        self.faults.push(
            Diagnostic::new(Code::ValueConflict, self.source(name))
                .option(name)
                .param("conflict", conflict),
        );
    }

    fn requires(&mut self, name: &str, requires: &str) {
        self.faults.push(
            Diagnostic::new(Code::ValueRequires, self.source(name))
                .option(name)
                .param("requires", requires),
        );
    }

    /// A SOCKS proxy under `prefix` (`tor-socks`, `clearnet-socks`) with
    /// its credentials, which need each other and the endpoint.
    fn socks(&mut self, prefix: &str) -> Option<Socks> {
        let user_key = format!("{prefix}-username");
        let pass_key = format!("{prefix}-password");
        let endpoint = self.endpoint(prefix);
        let username = self.secret(&user_key);
        let password = self.secret(&pass_key);
        let Some(endpoint) = endpoint else {
            for key in [&user_key, &pass_key] {
                if self.given(key) {
                    self.conflict(key, &format!("`{prefix}` is not set"));
                }
            }
            return None;
        };
        match (&username, &password) {
            (Some(_), None) => self.requires(&user_key, &format!("`{pass_key}`")),
            (None, Some(_)) => self.requires(&pass_key, &format!("`{user_key}`")),
            _ => {}
        }
        Some(Socks {
            endpoint,
            username,
            password,
        })
    }
}

/// Builds the sections from the resolved values.
///
/// `config_file` is the file read, if one was. The ban file is read here,
/// at parse. The log location is checked by [`log_location_writable`] when
/// logging starts, not here.
///
/// # Errors
/// Every cross-row refusal, every path that needs a home the account lacks,
/// a mining address off the network, and a ban file that cannot be read or
/// holds a line that does not parse.
pub fn build(
    resolved: &Resolved,
    network: Network,
    run_mode: RunMode,
    platform: &Platform,
    config_file: Option<&Path>,
) -> Result<DaemonConfig, Vec<Diagnostic>> {
    let mut r = Reader {
        resolved,
        faults: Vec::new(),
    };

    // Paths: an explicit path is taken as given; a default needs the root.
    let root_for = |r: &mut Reader<'_>, option: &str| match paths::root(platform, run_mode, option)
    {
        Ok(root) => Some(root),
        Err(d) => {
            r.faults.push(d);
            None
        }
    };
    let data_dir = match r.path("data-dir") {
        Some(p) => p,
        None => root_for(&mut r, "data-dir")
            .map(|root| paths::data_dir_default(&root, network))
            .unwrap_or_default(),
    };
    let log_file = match r.path("log-file") {
        Some(p) => p,
        None => root_for(&mut r, "log-file")
            .map(|root| paths::log_file_default(&root, network))
            .unwrap_or_default(),
    };

    // Logging.
    let level = r.word("log-level").unwrap_or("warn");
    let categories: Vec<(String, &'static str)> = match r.resolved.get("log-category") {
        Some(Value::Map(map)) => map
            .iter()
            .filter_map(|(k, v)| match v {
                Value::Word(w) => Some((k.clone(), *w)),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    let logging = Logging {
        file: log_file,
        level,
        categories,
        size_max: r.bytes("log-size-max").unwrap_or(1 << 30),
    };

    // Clearnet.
    let clearnet_on = r.word("clearnet") != Some("off");
    let clearnet = if clearnet_on {
        let listen = if r.given("clearnet-listen") {
            r.endpoints("clearnet-listen")
        } else {
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                network.p2p_port(),
            )]
        };
        let advertise = r.endpoints("clearnet-advertise");
        let v4 = advertise.iter().filter(|a| a.is_ipv4()).count();
        let v6 = advertise.iter().filter(|a| a.is_ipv6()).count();
        if v4 > 1 || v6 > 1 {
            r.faults.push(
                Diagnostic::new(Code::ValueRange, r.source("clearnet-advertise"))
                    .option("clearnet-advertise")
                    .param(
                        "value",
                        advertise
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(" "),
                    )
                    .param("rule", "at most one endpoint per address family"),
            );
        }
        let socks = r.socks("clearnet-socks");
        Clearnet::On {
            listen,
            socks,
            advertise,
        }
    } else {
        for key in [
            "clearnet-listen",
            "clearnet-advertise",
            "clearnet-socks",
            "clearnet-socks-username",
            "clearnet-socks-password",
        ] {
            if r.given(key) {
                r.conflict(key, "`clearnet` is `off`");
            }
        }
        Clearnet::Off
    };

    // Tor.
    let tor_word = r.word("tor").unwrap_or("managed");
    let tor = match tor_word {
        "operator" => {
            if r.given("tor-file") {
                r.conflict("tor-file", "`tor` is not `managed`");
            }
            let socks = r.socks("tor-socks");
            let onion = match (r.onion("tor-onion"), r.endpoint("tor-onion-listen")) {
                (Some((host, virtual_port)), Some(listen)) => Some(Onion {
                    host,
                    virtual_port,
                    listen,
                }),
                (Some(_), None) => {
                    r.requires("tor-onion", "`tor-onion-listen`");
                    None
                }
                (None, Some(_)) => {
                    r.requires("tor-onion-listen", "`tor-onion`");
                    None
                }
                (None, None) => None,
            };
            match socks {
                Some(socks) => Tor::Operator { socks, onion },
                None => {
                    r.requires("tor", "`tor-socks` when it is `operator`");
                    Tor::Off
                }
            }
        }
        "off" => {
            for key in [
                "tor-socks",
                "tor-socks-username",
                "tor-socks-password",
                "tor-onion",
                "tor-onion-listen",
                "tor-file",
            ] {
                if r.given(key) {
                    r.conflict(key, "`tor` is `off`");
                }
            }
            Tor::Off
        }
        _ => {
            for key in [
                "tor-socks",
                "tor-socks-username",
                "tor-socks-password",
                "tor-onion",
                "tor-onion-listen",
            ] {
                if r.given(key) {
                    r.conflict(key, "`tor` is `managed`, which has its own Tor and onion");
                }
            }
            Tor::Managed {
                binary: r.path("tor-file"),
            }
        }
    };

    // P2P.
    let tor_on = tor != Tor::Off;
    for key in ["p2p-peer", "p2p-closed-peer"] {
        for peer in r.peers(key) {
            match peer {
                PeerEndpoint::Ip(_) if !clearnet_on => {
                    r.conflict(
                        key,
                        &format!("`clearnet` is `off` and {peer} is a clearnet peer"),
                    );
                }
                PeerEndpoint::Onion { .. } if !tor_on => {
                    r.conflict(key, &format!("`tor` is `off` and {peer} is an onion"));
                }
                _ => {}
            }
        }
    }
    let bans = match r.path("p2p-ban-file") {
        Some(path) => match read_ban_file(&path) {
            Ok(bans) => bans,
            Err(d) => {
                r.faults.push(d);
                Vec::new()
            }
        },
        None => Vec::new(),
    };
    let p2p = P2p {
        peers: r.peers("p2p-peer"),
        closed_peers: r.peers("p2p-closed-peer"),
        local: r.resolved.switch("p2p-local"),
        disclose_early: r.resolved.switch("p2p-disclose-early"),
        bans,
        upload_max: r.rate("p2p-upload-max"),
        download_max: r.rate("p2p-download-max"),
    };

    // RPC.
    let admin_listen = if r.given("rpc-admin-listen") {
        r.endpoints("rpc-admin-listen")
    } else {
        vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            network.rpc_port(),
        )]
    };
    let rpc = Rpc {
        admin_listen,
        view_listen: r.endpoints("rpc-view-listen"),
        cors_origins: r.origins("rpc-cors-origin"),
        connections_max: r
            .integer("rpc-connections-max")
            .and_then(|n| u32::try_from(n).ok())
            .and_then(NonZeroU32::new)
            .unwrap_or(NonZeroU32::MIN),
    };

    // Mine.
    let address = match r.resolved.get("mine-address") {
        Some(Value::Address(a)) => {
            match shekyl_address::ShekylAddress::decode_for_network(a, address_network(network)) {
                Ok(_) => Some(a.clone()),
                Err(e) => {
                    r.faults.push(
                        Diagnostic::new(Code::ValueSyntax, r.source("mine-address"))
                            .option("mine-address")
                            .param("value", a.clone())
                            .param("expected", format!("a {} address: {e}", network.name())),
                    );
                    None
                }
            }
        }
        _ => None,
    };
    let mine = Mine {
        address,
        threads: r
            .integer("mine-threads")
            .and_then(|n| u32::try_from(n).ok())
            .and_then(NonZeroU32::new),
    };

    // Dev.
    let dev = Dev {
        difficulty: r.integer("dev-difficulty"),
        sync: r.word("dev-sync") != Some("off"),
        clearnet_encrypt: r.resolved.switch("dev-clearnet-encrypt"),
        relay_cover: r.resolved.switch("dev-relay-cover"),
        pow_seed_epoch_blocks: r.integer("dev-pow-seed-epoch-blocks"),
        pow_seed_epoch_lag: r.integer("dev-pow-seed-epoch-lag"),
        settlement_epoch_blocks: r.integer("dev-settlement-epoch-blocks"),
        archival_reorg_depth: r.integer("dev-archival-reorg-depth"),
    };

    // Session: positional words make this process a client.
    let command = r.resolved.positional.clone();
    let client_endpoint = if command.is_empty() {
        None
    } else {
        match rpc.admin_listen.first() {
            Some(e) => Some(*e),
            None => {
                r.faults.push(
                    Diagnostic::new(Code::ClientNoEndpoint, Source::Cli).option("rpc-admin-listen"),
                );
                None
            }
        }
    };
    let session = Session {
        console: r.resolved.switch("console"),
        command,
        client_endpoint,
    };

    let notify = Notify {
        block: r.command("notify-block"),
        reorg: r.command("notify-reorg"),
        block_rate: r.command("notify-block-rate"),
    };
    let txpool_weight_max = r.bytes("txpool-weight-max").unwrap_or(648_000_000);

    if !r.faults.is_empty() {
        return Err(r.faults);
    }
    Ok(DaemonConfig {
        network,
        run_mode,
        config_file: config_file.map(Path::to_path_buf),
        data_dir,
        logging,
        clearnet,
        tor,
        p2p,
        rpc,
        txpool_weight_max,
        notify,
        mine,
        dev,
        session,
    })
}

/// Reads the ban file: one entry per line, `#` starts a comment, blank
/// lines are skipped; an entry is an IPv4 subnet `a.b.c.d/n`, an IP, an
/// IP with a port, or an onion with a port.
///
/// # Errors
/// `config.ban-file.unreadable` naming the path and the error, or
/// `config.ban-file.line` naming the path, the line and its text.
pub fn read_ban_file(path: &Path) -> Result<Vec<Ban>, Diagnostic> {
    let shown = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|e| {
        Diagnostic::new(Code::BanFileUnreadable, Source::Machine)
            .option("p2p-ban-file")
            .param("path", shown.clone())
            .param("error", e.to_string())
    })?;
    let mut bans = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let entry = parse_ban(line).ok_or_else(|| {
            Diagnostic::new(Code::BanFileLine, Source::Machine)
                .option("p2p-ban-file")
                .param("path", shown.clone())
                .param("line", (i + 1).to_string())
                .param("text", line)
        })?;
        bans.push(entry);
    }
    Ok(bans)
}

fn parse_ban(line: &str) -> Option<Ban> {
    if let Some((ip, prefix)) = line.split_once('/') {
        let ip: Ipv4Addr = ip.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        return (prefix <= 32).then_some(Ban::Subnet(ip, prefix));
    }
    if let Ok(ip) = line.parse::<IpAddr>() {
        return Some(Ban::Host(ip));
    }
    match shekyl_options::Kind::PeerEndpoint(shekyl_options::PeerRule::Any).parse_text(line) {
        Ok(Value::Peer(p)) => Some(Ban::Peer(p)),
        _ => None,
    }
}

/// Refuses if the log file's directory cannot be created or the file
/// cannot be opened for appending (`config.log.unwritable`).
///
/// # Errors
/// The typed refusal, naming the path and the error.
pub fn log_location_writable(file: &Path) -> Result<(), Diagnostic> {
    let fail = |e: std::io::Error| {
        Diagnostic::new(Code::LogUnwritable, Source::Machine)
            .option("log-file")
            .param("path", file.display().to_string())
            .param("error", e.to_string())
    };
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir).map_err(fail)?;
    }
    std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(file)
        .map(|_| ())
        .map_err(fail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::{choosers, resolve};
    use crate::table::TABLE;
    use std::ffi::OsString;

    fn platform() -> Platform {
        Platform {
            home: Some(PathBuf::from("/srv/op")),
            program_data: None,
        }
    }

    fn build_from(cli: &[&str], file: &str) -> Result<DaemonConfig, Vec<Diagnostic>> {
        let args: Vec<OsString> = cli.iter().map(OsString::from).collect();
        let cli = shekyl_options::read_cli(&TABLE, args)?;
        let (network, mode) = choosers(&cli);
        let given = shekyl_options::read_file(&TABLE, Path::new("/etc/shekyl/x.toml"), file)?;
        let resolved = resolve(&TABLE, network, cli, given)?;
        build(&resolved, network, mode, &platform(), None)
    }

    fn codes(r: Result<DaemonConfig, Vec<Diagnostic>>) -> Vec<(Code, String)> {
        r.expect_err("expected refusals")
            .into_iter()
            .map(|d| (d.code, d.option.unwrap_or_default()))
            .collect()
    }

    #[test]
    fn the_defaults_build_a_managed_tor_clearnet_node_on_mainnet() {
        let c = build_from(&[], "").unwrap();
        assert_eq!(c.network, Network::Mainnet);
        assert_eq!(c.data_dir, PathBuf::from("/srv/op/.shekyl"));
        assert_eq!(
            c.logging.file,
            PathBuf::from("/srv/op/.shekyl/logs/shekyld-mainnet.log")
        );
        assert_eq!(c.logging.directive(), "warn");
        assert_eq!(c.tor, Tor::Managed { binary: None });
        assert!(
            matches!(&c.clearnet, Clearnet::On { listen, socks: None, advertise } if listen.len() == 1 && listen[0].port() == 11021 && advertise.is_empty())
        );
        assert_eq!(c.rpc.admin_listen, vec!["127.0.0.1:11029".parse().unwrap()]);
        assert!(c.rpc.view_listen.is_empty());
        assert_eq!(c.rpc.connections_max.get(), 25);
        assert_eq!(c.txpool_weight_max, 648_000_000);
        assert_eq!(c.p2p.upload_max, None);
        assert!(c.dev.sync);
        assert!(!c.offline());
        assert!(!c.is_client());
    }

    #[test]
    fn explicit_paths_are_taken_as_given_and_defaults_follow_the_network() {
        let c = build_from(
            &["--network", "testnet", "--data-dir", "/srv/chain"],
            "log-file = \"/var/log/s.log\"\n",
        )
        .unwrap();
        assert_eq!(c.data_dir, PathBuf::from("/srv/chain"));
        assert_eq!(c.logging.file, PathBuf::from("/var/log/s.log"));
        assert!(matches!(&c.clearnet, Clearnet::On { listen, .. } if listen[0].port() == 12021));
        assert_eq!(c.rpc.admin_listen[0].port(), 12029);
    }

    #[test]
    fn no_home_refuses_each_path_that_needs_it_and_not_an_explicit_one() {
        let args: Vec<OsString> = ["--data-dir", "/srv/chain"]
            .iter()
            .map(OsString::from)
            .collect();
        let cli = shekyl_options::read_cli(&TABLE, args).unwrap();
        let resolved = resolve(&TABLE, Network::Mainnet, cli, Vec::new()).unwrap();
        let d = build(
            &resolved,
            Network::Mainnet,
            RunMode::User,
            &Platform::default(),
            None,
        )
        .unwrap_err();
        assert_eq!(d.len(), 1);
        assert_eq!(
            (d[0].code, d[0].option.as_deref()),
            (Code::PathNoHome, Some("log-file"))
        );
    }

    #[test]
    fn an_operator_tor_needs_its_socks_and_an_onion_needs_its_listener() {
        assert_eq!(
            codes(build_from(&["--tor", "operator"], "")),
            vec![(Code::ValueRequires, "tor".into())]
        );
        let c = build_from(&["--tor", "operator", "--tor-socks", "127.0.0.1:9050"], "").unwrap();
        assert!(matches!(c.tor, Tor::Operator { onion: None, .. }));
        let host = shekyl_onion_v3_hostname();
        let d = codes(build_from(
            &[
                "--tor",
                "operator",
                "--tor-socks",
                "127.0.0.1:9050",
                "--tor-onion",
                &format!("{host}:11021"),
            ],
            "",
        ));
        assert_eq!(d, vec![(Code::ValueRequires, "tor-onion".into())]);
        let c = build_from(
            &[
                "--tor",
                "operator",
                "--tor-socks",
                "127.0.0.1:9050",
                "--tor-onion",
                &format!("{host}:11021"),
                "--tor-onion-listen",
                "127.0.0.1:41021",
            ],
            "",
        )
        .unwrap();
        assert!(matches!(
            c.tor,
            Tor::Operator {
                onion: Some(Onion {
                    virtual_port: 11021,
                    ..
                }),
                ..
            }
        ));
    }

    /// A valid v3 onion: the Ed25519 base point's hostname.
    fn shekyl_onion_v3_hostname() -> String {
        let mut b = [0x66u8; 32];
        b[0] = 0x58;
        shekyl_onion_v3::v3_onion_hostname(&b)
    }

    #[test]
    fn a_connector_that_is_off_cannot_carry_its_endpoints_or_its_peers() {
        let d = codes(build_from(
            &["--tor", "off", "--tor-socks", "127.0.0.1:9050"],
            "",
        ));
        assert_eq!(d, vec![(Code::ValueConflict, "tor-socks".into())]);
        let d = codes(build_from(
            &["--clearnet", "off", "--clearnet-listen", "0.0.0.0:11021"],
            "",
        ));
        assert_eq!(d, vec![(Code::ValueConflict, "clearnet-listen".into())]);
        let d = codes(build_from(
            &["--clearnet", "off", "--p2p-peer", "8.8.8.8:11021"],
            "",
        ));
        assert_eq!(d, vec![(Code::ValueConflict, "p2p-peer".into())]);
        let d = codes(build_from(&["--tor-file", "/opt/tor", "--tor", "off"], ""));
        assert_eq!(d, vec![(Code::ValueConflict, "tor-file".into())]);
        let c = build_from(&["--clearnet", "off", "--tor", "off"], "").unwrap();
        assert!(c.offline());
    }

    #[test]
    fn socks_credentials_need_each_other_and_their_endpoint() {
        let d = codes(build_from(
            &["--clearnet-socks", "127.0.0.1:1080"],
            "clearnet-socks-username = \"u\"\n",
        ));
        assert_eq!(
            d,
            vec![(Code::ValueRequires, "clearnet-socks-username".into())]
        );
        let d = codes(build_from(&[], "clearnet-socks-password = \"p\"\n"));
        assert_eq!(
            d,
            vec![(Code::ValueConflict, "clearnet-socks-password".into())]
        );
        let c = build_from(
            &["--clearnet-socks", "127.0.0.1:1080"],
            "clearnet-socks-username = \"u\"\nclearnet-socks-password = \"hunter2\"\n",
        )
        .unwrap();
        let Clearnet::On {
            socks: Some(socks), ..
        } = c.clearnet
        else {
            panic!("no socks")
        };
        assert_eq!(socks.password.as_ref().map(Secret::expose), Some("hunter2"));
        assert!(
            !format!("{socks:?}").contains("hunter2"),
            "a secret never prints"
        );
    }

    #[test]
    fn advertise_takes_one_endpoint_per_family() {
        let d = codes(build_from(
            &[
                "--clearnet-advertise",
                "8.8.8.8:1",
                "--clearnet-advertise",
                "9.9.9.9:1",
            ],
            "",
        ));
        assert_eq!(d, vec![(Code::ValueRange, "clearnet-advertise".into())]);
        assert!(build_from(
            &[
                "--clearnet-advertise",
                "8.8.8.8:1",
                "--clearnet-advertise",
                "[2a01:4f8::1]:1"
            ],
            ""
        )
        .is_ok());
    }

    #[test]
    fn a_mining_address_is_checked_against_the_network() {
        let d = codes(build_from(&["--mine-address", "shekyl1notanaddress"], ""));
        assert_eq!(d, vec![(Code::ValueSyntax, "mine-address".into())]);
    }

    #[test]
    fn log_categories_become_the_owners_directive() {
        let c = build_from(
            &[
                "--log-level",
                "info",
                "--log-category",
                "p2p=debug",
                "--log-category",
                "rpc=trace",
            ],
            "",
        )
        .unwrap();
        let d = c.logging.directive();
        assert!(d.starts_with("info,"), "{d}");
        assert!(
            d.contains("shekyl_dialer=debug") && d.contains("shekyl_daemon_rpc=trace"),
            "{d}"
        );
        let sink = c.logging.file_sink();
        assert_eq!(sink.filename_prefix, "shekyld-mainnet.log");
    }

    #[test]
    fn positional_words_make_a_client_that_needs_an_admin_endpoint() {
        let c = build_from(&["status"], "").unwrap();
        assert!(c.is_client());
        assert_eq!(
            c.session.client_endpoint,
            Some("127.0.0.1:11029".parse().unwrap())
        );
        let d = codes(build_from(&["--rpc-admin-listen", "none", "status"], ""));
        assert_eq!(d, vec![(Code::ClientNoEndpoint, "rpc-admin-listen".into())]);
    }

    #[test]
    fn the_ban_file_is_read_at_parse_and_a_bad_line_is_named() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("bans");
        std::fs::write(
            &p,
            "# comment\n10.0.0.0/8 # a subnet\n8.8.8.8\n9.9.9.9:11021\n\n",
        )
        .unwrap();
        let c = build_from(&["--p2p-ban-file", p.to_str().unwrap()], "").unwrap();
        assert_eq!(c.p2p.bans.len(), 3);
        assert_eq!(c.p2p.bans[0], Ban::Subnet(Ipv4Addr::new(10, 0, 0, 0), 8));
        std::fs::write(&p, "8.8.8.8\nnot an address\n").unwrap();
        let e = read_ban_file(&p).unwrap_err();
        assert_eq!(e.code, Code::BanFileLine);
        assert_eq!(e.get("line"), Some("2"));
        let e = read_ban_file(&d.path().join("missing")).unwrap_err();
        assert_eq!(e.code, Code::BanFileUnreadable);
    }

    #[test]
    fn the_log_location_is_created_or_refused() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("logs").join("shekyld-mainnet.log");
        log_location_writable(&f).unwrap();
        assert!(f.is_file());
        let blocked = d.path().join("file");
        std::fs::write(&blocked, "").unwrap();
        let e = log_location_writable(&blocked.join("x.log")).unwrap_err();
        assert_eq!(e.code, Code::LogUnwritable);
    }

    #[test]
    fn notify_commands_and_levers_are_carried() {
        let c = build_from(
            &[
                "--network",
                "regtest",
                "--dev-difficulty",
                "1",
                "--dev-sync",
                "off",
            ],
            "notify-block = [\"/usr/bin/logger\", \"{height}\"]\n",
        )
        .unwrap();
        assert_eq!(
            c.notify.block.as_deref(),
            Some(&["/usr/bin/logger".to_owned(), "{height}".to_owned()][..])
        );
        assert_eq!(c.dev.difficulty, Some(1));
        assert!(!c.dev.sync);
        assert_eq!(c.mine.threads, None, "auto");
    }
}
