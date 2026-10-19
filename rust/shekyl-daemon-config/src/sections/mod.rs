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
//!
//! The build is an orchestration. [`materialize`] writes each derived
//! default into the resolved map, and [`read`] then only reads that map: a
//! wrong value arm is a fault, never a second default. [`posture`] holds
//! the one child-row table. [`ban`] reads the ban file. A row the table
//! fills with a literal is required: its default is not restated here.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use shekyl_options::{Code, Diagnostic, PeerEndpoint, Secret, Source};

use crate::network::Network;
use crate::platform::{Platform, RunMode};
use crate::resolve::Resolved;
use crate::LEVELS;

mod ban;
mod materialize;
mod posture;
mod read;

pub use ban::read_ban_file;

#[cfg(test)]
mod tests;

use read::{RateBound, Read, Reader, ThreadCount};

/// A SOCKS5 proxy the operator runs, and the RFC 1929 pair it asks for
/// when the operator gave one (DC-Q7). The pair authenticates this node to
/// that proxy and nothing else: the daemon sets no isolation key and dials
/// onions only, and personas live in the wallet's own Tor (PWD-E9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Socks {
    /// The proxy.
    pub endpoint: SocketAddr,
    /// The username and password, given together or not at all.
    pub credential: Option<SocksCredential>,
}

/// An RFC 1929 username and password, each 1 to 255 bytes, as RFC 1929's
/// message carries them. Built only by the sections, which refuse anything
/// else at parse, so a dial never meets a pair it cannot send. Both halves
/// are secrets: wiped on drop, and `Debug` shows neither.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocksCredential {
    username: Secret,
    password: Secret,
}

impl SocksCredential {
    /// The longest field RFC 1929 carries: its length is one byte.
    pub const MAX_BYTES: usize = 255;

    /// The username's bytes, for the one dial that sends them.
    #[must_use]
    pub fn username(&self) -> &[u8] {
        self.username.expose().as_bytes()
    }

    /// The password's bytes, for the one dial that sends them.
    #[must_use]
    pub fn password(&self) -> &[u8] {
        self.password.expose().as_bytes()
    }
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

/// One ban-file entry. A peer ban is the host of an IP endpoint: an onion
/// cannot be represented, because the ban table is keyed by IP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ban {
    /// An IPv4 subnet, `a.b.c.d/n`.
    Subnet(Ipv4Addr, u8),
    /// One host, any port.
    Host(IpAddr),
    /// One IP peer. The ban is the host; the port selects the line.
    Peer(SocketAddr),
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
    ///
    /// # Panics
    /// The table admits only level words and subsystem keys, and [`build`]
    /// refuses anything else, so a built section's words are in that set.
    #[must_use]
    pub fn directive(&self) -> String {
        let overrides: Vec<(&str, &str)> = self
            .categories
            .iter()
            .map(|(subsystem, level)| (subsystem.as_str(), *level))
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
            |name| name.to_string_lossy().into_owned(),
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

/// A mining address the configuration decode accepted.
///
/// The text is what the operator wrote, for display. The keys are what the
/// miner assembles into an account address. The miner does not parse the
/// text, and this type does not carry the C++ layout: the X25519 prefix is
/// derived there, from the view key, beside the ML-KEM encapsulation key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MineAddress {
    /// The address the operator wrote.
    pub text: String,
    /// The spend public key.
    pub spend: [u8; 32],
    /// The view public key.
    pub view: [u8; 32],
    /// The ML-KEM encapsulation key.
    pub ml_kem: Vec<u8>,
}

/// The miner's section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mine {
    /// Mine to this address from start.
    pub address: Option<MineAddress>,
    /// The thread count; `None` is `auto`, which the miner receives as 0
    /// and resolves itself.
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
    /// The admin endpoint a client-mode command reaches. Present only in
    /// client mode, and only when that endpoint is IPv4: the console dials
    /// four octets and a port. A daemon may still bind IPv6.
    pub client_endpoint: Option<SocketAddrV4>,
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

/// Builds the sections from the resolved values.
///
/// Derived defaults are written into `resolved` first, with source
/// `default`, so the map this returns through is the map the announcement
/// and `option show` read. `config_file` is the file read, if one was. The
/// ban file is read here, at parse. The log location is checked by
/// [`log_location_writable`] when logging starts, not here.
///
/// # Errors
/// Every cross-row refusal, a row the table fills when it is absent, a
/// value of the wrong arm, every path that needs a home the account lacks,
/// a mining address off the network, and a ban file that cannot be read or
/// holds a line that does not parse.
pub fn build(
    resolved: &mut Resolved,
    network: Network,
    run_mode: RunMode,
    platform: &Platform,
    config_file: Option<&Path>,
) -> Result<DaemonConfig, Vec<Diagnostic>> {
    let mut faults = materialize::fill(resolved, network, run_mode, platform);
    let mut r = Reader::new(resolved);
    let data_dir = taken_path(&mut r, "data-dir");
    let log_file = taken_path(&mut r, "log-file");
    let logging = logging_section(&mut r, log_file);
    let clearnet = posture::clearnet(&mut r);
    let tor = posture::tor(&mut r);
    let peers = r.peer_list("p2p-peer");
    let closed_peers = r.peer_list("p2p-closed-peer");
    let clearnet_on = clearnet != Clearnet::Off;
    let tor_on = tor != Tor::Off;
    posture::peers_follow(&mut r, "p2p-peer", &peers, clearnet_on, tor_on);
    posture::peers_follow(
        &mut r,
        "p2p-closed-peer",
        &closed_peers,
        clearnet_on,
        tor_on,
    );
    let p2p = p2p_section(&mut r, peers, closed_peers);
    let rpc = rpc_section(&mut r);
    let mine = mine_section(&mut r, network);
    let dev = dev_section(&mut r);
    let session = session_section(&mut r, &rpc.admin_listen);
    let notify = notify_section(&mut r);
    let txpool_weight_max = r.required_bytes("txpool-weight-max");

    faults.append(&mut r.faults);
    if !faults.is_empty() {
        return Err(faults);
    }
    Ok(DaemonConfig {
        network,
        run_mode,
        config_file: config_file.map(Path::to_path_buf),
        data_dir,
        logging: logging.expect("log rows were read or a fault was recorded"),
        clearnet,
        tor,
        p2p,
        rpc: Rpc {
            admin_listen: rpc.admin_listen,
            view_listen: rpc.view_listen,
            cors_origins: rpc.cors_origins,
            connections_max: rpc
                .connections_max
                .expect("rpc-connections-max was read or a fault was recorded"),
        },
        txpool_weight_max: txpool_weight_max
            .expect("txpool-weight-max was read or a fault was recorded"),
        notify,
        mine,
        dev,
        session,
    })
}

/// The path [`materialize`] wrote, or the path the operator gave. Absence
/// means that write already recorded why (no home, no service root); a
/// wrong arm is already a fault. Neither invents a path here.
fn taken_path(r: &mut Reader<'_>, option: &str) -> PathBuf {
    match r.optional_path(option) {
        Read::Present(path) => path,
        Read::Absent | Read::Unreadable => PathBuf::new(),
    }
}

fn logging_section(r: &mut Reader<'_>, file: PathBuf) -> Option<Logging> {
    let words = read_log_words(r);
    let size_max = r.required_bytes("log-size-max");
    let (level, categories) = words?;
    Some(Logging {
        file,
        level,
        categories,
        size_max: size_max?,
    })
}

/// The base level and the per-subsystem overrides, through the same reader
/// the section uses. Both are read before either is required, so one bad
/// row does not hide the other.
fn read_log_words(r: &mut Reader<'_>) -> Option<(&'static str, Vec<(String, &'static str)>)> {
    let level = match r.required_word("log-level") {
        Some(word) if LEVELS.contains(&word) => Some(word),
        Some(word) => {
            r.word_choice("log-level", word, "error, warn, info, debug, trace");
            None
        }
        None => None,
    };
    let categories = r.level_map("log-category");
    Some((level?, categories))
}

/// Installs the logging rows on the live filter.
///
/// The directive is [`shekyl_logging::subsystem::directive_from_words`], the
/// conversion [`Logging::directive`] uses at start. A word the reader
/// admitted and that conversion refuses is a defect in the table, not a
/// quieter level.
///
/// # Errors
/// A logging row absent where the table fills it, or of the wrong arm.
pub fn apply_logging(resolved: &Resolved) -> Result<(), Vec<Diagnostic>> {
    let mut r = Reader::new(resolved);
    let words = read_log_words(&mut r);
    if !r.faults.is_empty() {
        return Err(r.faults);
    }
    let (level, categories) = words.expect("the logging rows were read or a fault was recorded");
    let overrides: Vec<(&str, &str)> = categories
        .iter()
        .map(|(subsystem, word)| (subsystem.as_str(), *word))
        .collect();
    let directive = shekyl_logging::subsystem::directive_from_words(level, &overrides)
        .expect("the table admits only level words and subsystem keys");
    shekyl_logging::subsystem::apply_directive(directive);
    Ok(())
}

fn p2p_section(
    r: &mut Reader<'_>,
    peers: Vec<PeerEndpoint>,
    closed_peers: Vec<PeerEndpoint>,
) -> P2p {
    let bans = match r.optional_path("p2p-ban-file") {
        Read::Present(path) => match read_ban_file(&path) {
            Ok(bans) => bans,
            Err(diagnostic) => {
                r.faults.push(diagnostic);
                Vec::new()
            }
        },
        Read::Absent | Read::Unreadable => Vec::new(),
    };
    let (upload_max, download_max) = read_rates(r);
    P2p {
        peers,
        closed_peers,
        local: r.switch("p2p-local"),
        disclose_early: r.switch("p2p-disclose-early"),
        bans,
        upload_max,
        download_max,
    }
}

/// The two link rates, through the same reader the section uses.
fn read_rates(r: &mut Reader<'_>) -> (Option<u64>, Option<u64>) {
    (
        rate_cap(r.rate("p2p-upload-max")),
        rate_cap(r.rate("p2p-download-max")),
    )
}

/// The link budget from the resolved rates: `(upload, download)`, each
/// `None` when the row is `unlimited`.
///
/// # Errors
/// A rate row absent where the table fills it, or of the wrong arm. An
/// unreadable row is not treated as unlimited.
pub fn link_limits(resolved: &Resolved) -> Result<(Option<u64>, Option<u64>), Vec<Diagnostic>> {
    let mut r = Reader::new(resolved);
    let limits = read_rates(&mut r);
    if r.faults.is_empty() {
        Ok(limits)
    } else {
        Err(r.faults)
    }
}

/// `None` is unlimited. An unreadable row also yields `None`, and its fault
/// keeps the build from succeeding on that reading.
fn rate_cap(bound: RateBound) -> Option<u64> {
    match bound {
        RateBound::Capped(bytes_per_second) => Some(bytes_per_second),
        RateBound::Unlimited | RateBound::Unreadable => None,
    }
}

/// The RPC rows. `connections_max` is `None` only after a fault, so the
/// listeners stay available for the client-endpoint check.
struct RpcRead {
    admin_listen: Vec<SocketAddr>,
    view_listen: Vec<SocketAddr>,
    cors_origins: Vec<String>,
    connections_max: Option<NonZeroU32>,
}

fn rpc_section(r: &mut Reader<'_>) -> RpcRead {
    RpcRead {
        admin_listen: r.endpoint_list("rpc-admin-listen", true),
        view_listen: r.endpoint_list("rpc-view-listen", true),
        cors_origins: r.origin_list("rpc-cors-origin"),
        connections_max: r.required_count("rpc-connections-max"),
    }
}

fn mine_section(r: &mut Reader<'_>, network: Network) -> Mine {
    let address = match r.address("mine-address") {
        Read::Present(text) => {
            match shekyl_address::ShekylAddress::decode_for_network(&text, address_network(network))
            {
                Ok(decoded) => Some(MineAddress {
                    text,
                    spend: decoded.spend_key,
                    view: decoded.view_key,
                    ml_kem: decoded.ml_kem_encap_key,
                }),
                Err(error) => {
                    r.faults.push(
                        Diagnostic::new(Code::ValueSyntax, r.source("mine-address"))
                            .option("mine-address")
                            .param("value", text)
                            .param("expected", format!("a {} address: {error}", network.name())),
                    );
                    None
                }
            }
        }
        Read::Absent | Read::Unreadable => None,
    };
    Mine {
        address,
        threads: match r.thread_count("mine-threads") {
            ThreadCount::Counted(count) => Some(count),
            ThreadCount::Auto | ThreadCount::Unreadable => None,
        },
    }
}

fn dev_section(r: &mut Reader<'_>) -> Dev {
    let sync = match r.optional_word("dev-sync") {
        // Absent is the table's default, on. Unreadable already recorded
        // its fault; the posture stays on so the rest of the section builds.
        Read::Absent | Read::Present("on") | Read::Unreadable => true,
        Read::Present("off") => false,
        Read::Present(other) => {
            r.word_choice("dev-sync", other, "on, off");
            true
        }
    };
    Dev {
        difficulty: r.dev_integer("dev-difficulty"),
        sync,
        clearnet_encrypt: r.switch("dev-clearnet-encrypt"),
        relay_cover: r.switch("dev-relay-cover"),
        pow_seed_epoch_blocks: r.dev_integer("dev-pow-seed-epoch-blocks"),
        pow_seed_epoch_lag: r.dev_integer("dev-pow-seed-epoch-lag"),
        settlement_epoch_blocks: r.dev_integer("dev-settlement-epoch-blocks"),
        archival_reorg_depth: r.dev_integer("dev-archival-reorg-depth"),
    }
}

fn session_section(r: &mut Reader<'_>, admin_listen: &[SocketAddr]) -> Session {
    let command = r.positional().to_vec();
    let client_endpoint = if command.is_empty() {
        None
    } else {
        match admin_listen.first() {
            Some(SocketAddr::V4(endpoint)) => Some(*endpoint),
            Some(endpoint) => {
                r.faults.push(
                    Diagnostic::new(Code::ValueRange, r.source("rpc-admin-listen"))
                        .option("rpc-admin-listen")
                        .param("value", endpoint.to_string())
                        .param("rule", "the console client reaches an IPv4 admin endpoint"),
                );
                None
            }
            None => {
                r.faults.push(
                    Diagnostic::new(Code::ClientNoEndpoint, Source::Cli).option("rpc-admin-listen"),
                );
                None
            }
        }
    };
    Session {
        console: r.switch("console"),
        command,
        client_endpoint,
    }
}

fn notify_section(r: &mut Reader<'_>) -> Notify {
    Notify {
        block: r.command("notify-block"),
        reorg: r.command("notify-reorg"),
        block_rate: r.command("notify-block-rate"),
    }
}

/// Refuses if the log file's directory cannot be created or the file
/// cannot be opened for appending (`config.log.unwritable`).
///
/// # Errors
/// The typed refusal, naming the path and the error.
pub fn log_location_writable(file: &Path) -> Result<(), Diagnostic> {
    let fail = |error: std::io::Error| {
        Diagnostic::new(Code::LogUnwritable, Source::Machine)
            .option("log-file")
            .param("path", file.display().to_string())
            .param("error", error.to_string())
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
