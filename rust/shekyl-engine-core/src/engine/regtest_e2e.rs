// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Track-2 end-to-end FAKECHAIN regtest: C++↔Rust FCMP++ verify parity.
//!
//! These tests spawn a real `shekyld --network regtest` daemon and drive the production
//! [`Engine`] against it over the real RPC transport ([`DaemonClient`] /
//! [`HttpRpc`]). Unlike the rest of the engine test suite (which uses
//! the in-memory `TestDaemon` mock), the point here is the **submit/verify
//! direction**: a wallet-built FCMP++ proof, serialized into a tx and sent over
//! the wire, must be accepted by the daemon's consensus `shekyl_fcmp_verify`
//! against the daemon's own per-height curve-tree root.
//!
//! The ingest/reconstruct direction is already proven offline by
//! `shekyl-curve-tree`'s `recon_kat.rs` (Tier-A, generated from a live regtest):
//! wallet `build_layers` root == daemon header root at every height. Track 2
//! closes the other half.
//!
//! The file also carries the PR-4 staker harness (`EMISSION_CLAIM_BUILDER.md`
//! §8 PR-4): a staker wallet funds its persona on-chain, the production P-scan
//! discovers the funding, and the production bond path assembles + dispatches
//! the bond post over the same live-daemon boundary, up to the daemon's
//! (pinned) submit-legs gap — the substrate the emission-claim e2e builds on
//! once the PR-4b daemon batteries land.
//!
//! All tests are `#[ignore]`d: they require a `shekyld` binary, located via the
//! `SHEKYLD_BIN` env var. Run with:
//!
//! ```bash
//! SHEKYLD_BIN=/path/to/build/bin/shekyld \
//!   cargo test -p shekyl-engine-core --lib regtest_e2e -- --ignored --nocapture
//! ```

#![cfg(test)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// What a wallet requires of the `shekyld --network regtest` daemon these
/// tests spawn: the same as on any network. Regtest has its own genesis,
/// prefixes and network id (`NETWORK_IDENTITY.md` NI-Q8), so a regtest
/// wallet is `Network::Regtest` and checks a regtest daemon exactly as a
/// mainnet wallet checks a mainnet one.
fn regtest_expectation() -> super::DaemonExpectation {
    super::DaemonExpectation {
        network: shekyl_address::Network::Regtest,
    }
}

use serde_json::json;
use shekyl_rpc_client::{wire, Rpc};
use shekyl_rpc_transport::HttpRpc;
use shekyl_rpc_types::hash::HashHex;
use shekyl_rpc_types::kinds::{Count, NoParams};
use shekyl_rpc_types::wire::block::{BlockSelect, BlockShowSelect, HeaderSelect};
use shekyl_rpc_types::wire::daemon::DaemonStatus;
use shekyl_rpc_types::wire::shared::Selector;
use shekyl_types::{BlockCount, ShardId, TxHash};
use tokio::sync::{Mutex, OwnedMutexGuard, RwLock};

/// `cargo test` runs tests in parallel; spawning multiple daemons concurrently
/// races on the RPC port and is resource-heavy (each mines blocks). Serialize all
/// regtest e2e tests through one async lock — held for the daemon's lifetime via
/// [`RegtestDaemon`], released on drop.
///
/// The lock is in-process only. Each daemon takes a fresh ephemeral port and
/// temp datadir and removes both on drop, so nothing sweeps the process table:
/// a `pkill` of `shekyl-regtest-` would also kill another `cargo test`
/// process's daemon, and this lock cannot see that process.
static SERIAL: OnceLock<Arc<Mutex<()>>> = OnceLock::new();

fn serial_lock() -> Arc<Mutex<()>> {
    SERIAL.get_or_init(|| Arc::new(Mutex::new(()))).clone()
}

/// Route the wallet's own `tracing` events into this test's captured
/// output. Without a subscriber they are dropped, and a wallet-side
/// refusal that never reaches the daemon (the `submit_transaction`
/// round-trip guard, for one) leaves no trace anywhere. `warn` by
/// default; `RUST_LOG` overrides. Idempotent across the binary: a second
/// install is a no-op, never a panic.
fn install_wallet_tracing() {
    use tracing_subscriber::EnvFilter;
    drop(
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
            .with_test_writer()
            .with_ansi(false)
            .try_init(),
    );
}

/// The line a daemon started with `--dev-rpc` writes at start (IG-8),
/// pinned by `shekyl-daemon-config`'s
/// `the_armed_lever_switch_announces_itself`.
/// `scripts/ci/check_armed_lever_launchers.py` holds this text equal to
/// `scripts/armed_lever.py` and to that test.
const ARMED_ROW_ANNOUNCEMENT: &str = "development lever set: dev-rpc=true";

/// A live `shekyld --network regtest` daemon spawned for one test, with an ephemeral
/// data dir and RPC port. Killed on drop. The data dir goes with it, unless
/// this spawn is the DX-Q8 capture (`start_keeping_data`).
/// Last 40 lines of the daemon's captured log, inlined into panics:
/// on the deleting path `Drop` removes the datadir (log included) as a panic
/// unwinds, so a "see the log file" pointer would name a deleted file.
fn log_tail(log_path: &std::path::Path) -> String {
    std::fs::read_to_string(log_path)
        .map(|s| {
            let lines: Vec<&str> = s.lines().collect();
            let start = lines.len().saturating_sub(40);
            lines[start..].join("\n")
        })
        .unwrap_or_else(|e| format!("(daemon log unreadable: {e})"))
}

/// The regtest-only schedule levers, as one value so the pair cannot be
/// set apart: the daemon's `dev-settlement-epoch-blocks` and
/// `dev-archival-reorg-depth` rows, which the wallet process still reads
/// as `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` and `SHEKYL_ARCHIVAL_REORG_DEPTH_BLOCKS`
/// (FOLLOWUPS: the wallet engine's lever). The daemon refuses
/// `seb ≤ reorg_cap` at arm (`SEB > D_max` on every nettype); a harness
/// that shortens the epoch lowers the cap with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RegtestSchedule {
    pub(super) seb: u64,
    pub(super) reorg_cap: u64,
}

impl RegtestSchedule {
    /// Set both levers on this process's environment, for the wallet's
    /// in-process arm that must match the spawned daemon's schedule. The
    /// daemon itself takes the pair as rows (`spawn`).
    pub(super) fn set_in_process_env(self) {
        std::env::set_var("SHEKYL_SETTLEMENT_EPOCH_BLOCKS", self.seb.to_string());
        std::env::set_var(
            "SHEKYL_ARCHIVAL_REORG_DEPTH_BLOCKS",
            self.reorg_cap.to_string(),
        );
    }
}

pub(super) struct RegtestDaemon {
    child: Child,
    /// The daemon's `data-dir`. The full-disk gate, Linux only, names
    /// another directory for the chain and keeps the logs in [`Self::data_dir`].
    chain_dir: PathBuf,
    /// Where the logs are, and the chain too unless the spawn moved it.
    data_dir: PathBuf,
    /// The private directory that holds this daemon's empty configuration
    /// file (`private_config_dir`). Removed with the daemon.
    config_dir: PathBuf,
    rpc_port: u16,
    rpc: HttpRpc,
    /// Base URL of the second, restricted listener, when one was
    /// asked for. `None` for the ordinary spawn, so no existing test grows a
    /// listener it did not ask for.
    restricted_url: Option<String>,
    /// The network `shekyl-cli` is given when a test runs a §13 word: the
    /// daemon's own, regtest included (NI-R1, NI-R4).
    cli_network: &'static str,
    /// Whether this daemon was given `--dev-rpc` (regtest only, NI-R8).
    armed: bool,
    /// The schedule levers this daemon was spawned under, if any — recorded
    /// so a captured chain's manifest states the `(SEB, cap)` its blocks
    /// were mined under (`DRS_E4_ARCHIVAL_WRITER.md` `ARW-15`: the replay
    /// judges the chain under a rule set naming that pair, not the
    /// production one).
    schedule: Option<RegtestSchedule>,
    /// Whether this daemon was started offline (both connectors off). Its
    /// `daemon_status` must then report that state, not a count of zero.
    offline: bool,
    /// Whether this daemon posts a template at open: an offline daemon is
    /// synced from open on any network (`Declaration::Offline`, CS-Q2 step
    /// 8) and posts once its follower has looped. Readiness then includes
    /// that post: a `dev_block_generate` sent before it is honestly refused by
    /// a daemon whose RPC is already up.
    posts_at_open: bool,
    /// When true, `Drop` leaves `data_dir` in place. Set only by
    /// `start_keeping_data`. Every other spawn deletes the directory.
    keep_data: bool,
    /// Held for the daemon's lifetime to serialize e2e tests; released on drop.
    /// `None` on the sink of a [`origin::StemSinkPair`], whose origin holds
    /// the one guard for both.
    _serial: Option<OwnedMutexGuard<()>>,
    /// The daemon's own command line, kept so
    /// [`Self::restart_keeping_chain`] starts the same daemon on the same
    /// data directory, ports and rows.
    recipe: Vec<std::ffi::OsString>,
    /// How long [`Self::wait_shown_pool_in_template`] waits:
    /// [`SHOWN_POOL_LIMIT`], or [`TOR_SHOWN_POOL_LIMIT`] for a daemon on a
    /// Tor, which also waits for the transactions it originated to come back
    /// as a fluff before it reads the job.
    shown_pool_limit: Duration,
    /// Whether the wait also covers this daemon's unbroadcast entries: the
    /// Tor trio's miner, whose relays return each origin as a fluff
    /// ([`Self::start_tor_trio`]). A linked daemon that holds a stem through
    /// its embargo does not wait for it (the origin rig).
    waits_for_stems: bool,
    /// The draws [`Self::generate_blocks`] gives a read window to: the walk
    /// that reads over Tor sets it over the epoch whose draws its persona
    /// must serve ([`Self::watch_draws`]).
    watch: std::sync::Mutex<Option<DrawWatch>>,
    /// The unanswered loopback port a [`Peering::Listening`] daemon dials.
    /// Held for the daemon's life, including a restart on the same recipe,
    /// so the closed-peer address in that recipe is still this socket.
    /// `None` for every other peering.
    unanswered: Option<UnansweredPort>,
    /// The Tor trio's relays, on the miner only ([`Self::start_tor_trio`]):
    /// what [`Self::wait_shown_pool_in_template`] reads when an origin has
    /// not come back, to tell a relay that kept it from a path that was
    /// not there.
    relays: Option<TrioRelays>,
}

/// The Tor trio's two relays, as the miner's harness reads them: each
/// relay's own `daemon_status` and `peer_connections`, the operator's
/// reads, over its admin listener.
struct TrioRelays {
    b: HttpRpc,
    b_onion: OnionPeer,
    c: HttpRpc,
    c_onion: OnionPeer,
}

/// One reading of the trio's sessions and tips. A stem the miner
/// originates comes back as a fluff only over this whole mesh
/// ([`RegtestDaemon::start_tor_trio`]); with a session missing it
/// dead-ends, and the miner's own embargo shows it ([`ORIGIN_RETRY`]).
#[derive(Debug)]
struct MeshReading {
    a_to_b: bool,
    a_to_c: bool,
    b_to_c: bool,
    a_height: u64,
    b_height: u64,
    c_height: u64,
}

impl MeshReading {
    /// Every session up, and both relays at the miner's tip as it was read
    /// first: a relay behind the miner cannot admit a spend of an output it
    /// has not seen.
    fn whole(&self) -> bool {
        self.a_to_b
            && self.a_to_c
            && self.b_to_c
            && self.b_height >= self.a_height
            && self.c_height >= self.a_height
    }
}

impl std::fmt::Display for MeshReading {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let up = |held: bool| if held { "up" } else { "down" };
        write!(
            f,
            "A→B {}, A→C {}, B→C {}; tips A {}, B {}, C {}",
            up(self.a_to_b),
            up(self.a_to_c),
            up(self.b_to_c),
            self.a_height,
            self.b_height,
            self.c_height,
        )
    }
}

/// Whether `rpc`'s node holds an outbound Tor session to `onion`
/// (`peer_connections`: an outbound Tor session names the onion it
/// dialed; an inbound one names no host).
async fn holds_outbound_to(rpc: &HttpRpc, onion: OnionPeer) -> bool {
    rpc.call::<wire::PeerConnections>(NoParams)
        .await
        .expect("peer_connections")
        .iter()
        .any(|session| {
            !session.inbound
                && session.connector == wire::p2p::Connector::Tor
                && OnionPeer::parse(&session.endpoint.0).is_some_and(|peer| peer.host == onion.host)
        })
}

/// `rpc`'s node's tip height (`daemon_status`).
async fn tip_height(rpc: &HttpRpc) -> u64 {
    rpc.call::<wire::DaemonStatus>(NoParams)
        .await
        .expect("daemon_status")
        .height
        .0
}

/// How many times a port probe may draw `:0` before the reserved set is
/// treated as exhausted. The kernel can hand back a number already reserved.
const PORT_DRAW_LIMIT: u32 = 64;

/// A loopback TCP port this harness bound and never accepts.
///
/// A [`Peering::Listening`] daemon's closed peer is this port, on
/// `127.0.0.1`, the same host as the daemon and as the partner that dials
/// it. The first dial completes its TCP handshake into the backlog and
/// fails at the dial deadline. Once the partner's session is up, the host
/// is held and the refused port is not dialed again (Rick, 2026-11-09).
struct UnansweredPort {
    listener: std::net::TcpListener,
}

impl UnansweredPort {
    /// Bind `127.0.0.1:0` on a port that is none of `reserved`, and keep
    /// the listener. A draw that lands in `reserved` is dropped and tried
    /// again.
    fn bind_excluding(reserved: &[u16]) -> Self {
        for _ in 0..PORT_DRAW_LIMIT {
            let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .expect("bind an unanswered loopback port");
            let port = listener.local_addr().expect("local_addr").port();
            if !reserved.contains(&port) {
                return Self { listener };
            }
        }
        panic!("could not bind an unanswered port distinct from {reserved:?}");
    }

    fn port(&self) -> u16 {
        self.listener.local_addr().expect("local_addr").port()
    }

    /// The closed-peer spelling the daemon is given: loopback, this port.
    fn peer(&self) -> String {
        std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, self.port()).to_string()
    }
}

/// How a spawned daemon takes part in peer-to-peer.
#[derive(Clone, Copy, Debug)]
enum Peering {
    /// `--clearnet off --tor off`: no listener and no dial. Both
    /// connectors off is the operator's declaration that the node has no
    /// network to be behind (`Declaration::Offline`, CS-Q2 step 8), so
    /// chain sync reads `Synced` from open on any network, and a submitted
    /// transaction finds no route and is broadcast-recorded within
    /// milliseconds.
    Offline,
    /// Bound on loopback and dialling exactly one peer.
    ///
    /// `--p2p-closed-peer` is what keeps the daemon off the public
    /// network: a closed list is the condition under which it dials no
    /// seed. It is also the operator naming the node's whole network
    /// (`Declaration::Closed`, CS-Q2 step 8): with its peer down the node
    /// reads `Synced` and mines alone, and when the peer is up its opening
    /// runs. `--tor off` declines the managed Tor, so the node is
    /// clearnet-only and a local origin takes the stem slot, not a hidden
    /// own-edge.
    Linked { p2p_port: u16, peer_p2p_port: u16 },
    /// Bound on loopback, the far side of a [`Peering::Linked`] daemon.
    ///
    /// Every daemon here is on `127.0.0.1`, one host, and the dialer dials
    /// no host it already holds a session with (Rick, 2026-11-09). Two
    /// daemons that each dial the other therefore hold one session, in the
    /// direction of whichever dial lands first, a start-up race. A rig
    /// that needs the session's direction, a stem successor or a fresh
    /// incoming handshake, makes one end listen. Its closed list names an
    /// [`UnansweredPort`] on `127.0.0.1`, so it is still the operator
    /// naming a closed network (`Declaration::Closed`, CS-Q2 step 8) and
    /// dials no seed. Once the partner's session is up, that host is held
    /// and the unanswered port is not dialed again.
    Listening {
        p2p_port: u16,
        /// `false` is `--dev-sync off`: the daemon requests nothing
        /// (`Requesting::Off`) and follows its peer by announcements alone,
        /// which keeps it at its peer's tip. It still admits a transaction
        /// a peer sends it.
        requests: bool,
    },
    /// Bound on loopback and dialling exactly `peers`, two simulated
    /// peers' listening addresses (the stem width) (`regtest_e2e_peer.rs`): the closed list
    /// keeps it off every other peer, and each dial is an outbound
    /// session, so each peer can take a stem slot.
    Closed {
        p2p_port: u16,
        peers: [std::net::SocketAddrV4; 2],
    },
    /// Clearnet off, and the closed peers named by their onions: the
    /// daemon's managed Tor dials each, so the node has outbound sessions
    /// that hide its address and its relay originates its own transactions
    /// (`DAEMON_RELAY_PRIVACY.md` §98.5). The emission walk's miner and its
    /// first relay ([`RegtestDaemon::start_tor_trio`]).
    TorPeers {
        first: OnionPeer,
        second: Option<OnionPeer>,
    },
}

/// A v3 onion endpoint, `<56 base32 characters>.onion:<port>`, held by
/// value so [`Peering`] stays `Copy`.
#[derive(Clone, Copy, Debug)]
struct OnionPeer {
    host: [u8; 56],
    port: u16,
}

impl OnionPeer {
    /// The endpoint in `text`, the `<host>.onion:<port>` a managed Tor
    /// logs when its inbound is published.
    fn parse(text: &str) -> Option<Self> {
        let (host, port) = text
            .strip_suffix('.')
            .unwrap_or(text)
            .split_once(".onion:")?;
        let host: [u8; 56] = host.as_bytes().try_into().ok()?;
        host.iter()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(b))
            .then_some(())?;
        Some(Self {
            host,
            port: port.parse().ok()?,
        })
    }
}

#[test]
fn a_published_onion_line_parses_and_prints_back() {
    // The line a managed Tor logged in a walk run (2026-11-14).
    let line = " Tor is up: overlay inbound is published at \
                gj56z5xbxm7mi6iucpe3apa3raxkkiwub4vbc2who5sm6slpzikuqiyd.onion:14021, \
                forwarded from 127.0.0.1:35287";
    let (_, rest) = line
        .split_once("overlay inbound is published at ")
        .expect("the marker");
    let onion = OnionPeer::parse(
        rest.split_whitespace()
            .next()
            .expect("a word")
            .trim_end_matches(','),
    )
    .expect("a v3 onion endpoint");
    assert_eq!(
        onion.to_string(),
        "gj56z5xbxm7mi6iucpe3apa3raxkkiwub4vbc2who5sm6slpzikuqiyd.onion:14021"
    );
    // A host that is not 56 base32 characters, or no port, is not one.
    assert!(OnionPeer::parse(
        "gj56z5xbxm7mi6iucpe3apa3raxkkiwub4vbc2who5sm6slpzikuqiy1.onion:14021"
    )
    .is_none());
    assert!(OnionPeer::parse("short.onion:14021").is_none());
    assert!(
        OnionPeer::parse("gj56z5xbxm7mi6iucpe3apa3raxkkiwub4vbc2who5sm6slpzikuqiyd.onion")
            .is_none()
    );
}

impl std::fmt::Display for OnionPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let host = std::str::from_utf8(&self.host).expect("base32 is ASCII");
        write!(f, "{host}.onion:{}", self.port)
    }
}

/// What a `dev_block_generate` reports, in the harness's terms.
#[derive(Debug)]
pub(super) struct GenerateBlocksResp {
    /// The chain's block count after the generate.
    height: u64,
    /// The new blocks' hashes, lowercase hex.
    blocks: Vec<String>,
}

/// The network a test daemon runs on. Regtest for every spawn but the one
/// that shows what the armed switch serves on a shared test network.
#[derive(Clone, Copy)]
enum SpawnNetwork {
    Regtest,
    Testnet,
}

/// A full address on `network`, from `seed`. Same derivation the wallet
/// uses for its primary address, so a spawn can pay coinbase to that wallet.
pub(super) fn mine_address_from_seed(
    seed: &[u8; shekyl_crypto_pq::account::SEED_BYTES],
    network: shekyl_address::Network,
) -> String {
    shekyl_crypto_pq::account::account_from_seed(seed, network)
        .expect("the keys")
        .1
        .to_address(network)
        .encode()
        .expect("encodes")
}

fn default_mine_address(network: SpawnNetwork) -> String {
    let address_network = match network {
        SpawnNetwork::Regtest => shekyl_address::Network::Regtest,
        SpawnNetwork::Testnet => shekyl_address::Network::Testnet,
    };
    mine_address_from_seed(&[0x5a; 32], address_network)
}

/// How one regtest daemon is spawned.
///
/// The fields are the postures a caller can ask for, named at the call
/// site. The serial guard stays with the caller: one daemon takes it, and
/// a stem/sink pair takes it once, on the origin.
struct RegtestSpawn {
    serial: Option<OwnedMutexGuard<()>>,
    network: SpawnNetwork,
    schedule: Option<RegtestSchedule>,
    restricted_listener: bool,
    peering: Peering,
    mine_address: Option<String>,
    /// Leave the data directory in place when the daemon is dropped.
    /// The DX-Q8 capture is the caller. The default deletes, except under
    /// a failing test (`Drop` keeps the directory while its thread panics).
    keep_data: bool,
    /// Another daemon binary than `SHEKYLD_BIN`: a released version, for a
    /// mixed-version walk.
    binary: Option<PathBuf>,
    /// Ports already claimed by daemons this spawn must not bind. A
    /// partner port allocated with [`RegtestDaemon::free_port`] and not
    /// yet bound can otherwise come back as this daemon's RPC port, its
    /// view listener, or the unanswered closed peer.
    taken: Vec<u16>,
    /// A directory for the chain and pool files, apart from the logs. The
    /// full-disk gate puts it on a small filesystem and keeps the daemon's
    /// log off it, so the line that says the disk filled has somewhere to
    /// be written.
    chain_dir: Option<PathBuf>,
    /// The pinned Tor binary a managed Tor runs (`tor-file`), or `None` for
    /// `--tor off`. The emission walk is the caller: its mining daemon's
    /// bundle producer reads through this node's Tor, and a node with Tor
    /// off seats no producer.
    tor_file: Option<PathBuf>,
}

impl RegtestSpawn {
    /// Offline, non-interactive, one listener, the genesis-pinned schedule.
    fn new(serial: Option<OwnedMutexGuard<()>>) -> Self {
        Self {
            serial,
            network: SpawnNetwork::Regtest,
            schedule: None,
            restricted_listener: false,
            peering: Peering::Offline,
            mine_address: None,
            keep_data: false,
            binary: None,
            taken: Vec::new(),
            chain_dir: None,
            tor_file: None,
        }
    }

    /// Keep the chain and pool files under `dir`, and the logs where every
    /// spawn keeps them. The full-disk gate is the caller, and it is
    /// Linux-only, so the method is too: a Windows build has no caller.
    #[cfg(target_os = "linux")]
    fn with_chain_dir(mut self, dir: PathBuf) -> Self {
        self.chain_dir = Some(dir);
        self
    }

    /// Ports this spawn must not draw. A later partner's p2p port,
    /// allocated and released before this spawn, belongs here.
    fn with_ports_taken(mut self, ports: impl IntoIterator<Item = u16>) -> Self {
        self.taken.extend(ports);
        self
    }

    /// Spawn `binary` instead of `SHEKYLD_BIN`.
    fn with_binary(mut self, binary: PathBuf) -> Self {
        self.binary = Some(binary);
        self
    }

    fn with_mine_address(mut self, address: String) -> Self {
        self.mine_address = Some(address);
        self
    }

    /// Spawn on `network` instead of regtest. The regtest-only rows
    /// (`dev-difficulty`, the schedule) are not passed off regtest, where the
    /// daemon refuses them, so such a daemon cannot mine quickly.
    fn on_network(mut self, network: SpawnNetwork) -> Self {
        self.network = network;
        self
    }

    fn with_restricted_listener(mut self) -> Self {
        self.restricted_listener = true;
        self
    }

    fn with_schedule(mut self, schedule: Option<RegtestSchedule>) -> Self {
        self.schedule = schedule;
        self
    }

    fn with_peering(mut self, peering: Peering) -> Self {
        self.peering = peering;
        self
    }

    /// Run a managed Tor from `tor_file`, the pinned binary
    /// ([`live_tor_binary`]), in place of `--tor off`. The daemon verifies
    /// the file against the pin as it would any `tor-file` row.
    fn with_managed_tor(mut self, tor_file: PathBuf) -> Self {
        self.tor_file = Some(tor_file);
        self
    }

    /// Keep the data directory when the daemon is dropped.
    ///
    /// [`RegtestDaemon::start_keeping_data`] is the caller. Every other
    /// spawn deletes.
    fn keeping_data(mut self) -> Self {
        self.keep_data = true;
        self
    }
}

/// How long an offline daemon's posted job may take to list its shown pool:
/// the relay fluffs at once, and the follower rebuilds on the wake.
const SHOWN_POOL_LIMIT: Duration = Duration::from_secs(30);

/// The same wait on a daemon with a Tor: on the three-daemon rig
/// ([`RegtestDaemon::start_tor_trio`]) a transaction the miner originates is
/// unbroadcast until a fluff of it comes back, and the wait covers that. The longest path is A → C (stem), C → B (fluff), B → A
/// (fluff), or A → B → C (stems) and C → A (fluff): at most two stem hops,
/// each waiting at most one carrier slot (`NOISE_MIN_DELAY_MS` +
/// `NOISE_DELAY_JITTER_MS`, 6.67 s), and at most two fluff flushes toward an
/// inbound peer, each a Poisson draw over quarter-seconds with λ = 20
/// (`FLUFF_AVERAGE_IN_QUARTER_SECS`), 8.75 s at its 99.9th percentile, plus
/// three onion circuits at 5 s each: 13.3 + 17.5 + 15 ≈ 46 s, so 60 s.
///
/// The derivation assumes the whole mesh. A Tor session can close on the
/// public network mid-walk; an origin found unbroadcast at this limit with
/// a session down is waited for once more, to the miner's embargo fire
/// ([`ORIGIN_RETRY`]), and the walk's log names it. With the mesh whole,
/// the limit is the verdict.
const TOR_SHOWN_POOL_LIMIT: Duration = Duration::from_secs(60);

/// How long a managed Tor may take to bootstrap and publish its inbound
/// onion.
const TOR_PUBLISH_LIMIT: Duration = Duration::from_secs(300);

/// How long a published onion may take to read `reachable`, its own probe
/// arriving (`TOR_SUPERVISOR.md` §4.5): one judgment's worst case, 300 s
/// (`TSR-M14`: the round's wait, the probe's delay and bound, then the
/// refetch's probe, its delay and bound), and one republish judged the
/// same way, 300 s. The live tests allow at most one republish; needing
/// more is a finding (`TSR-M3`).
///
/// A trio daemon is spawned only once the onions it dials read
/// `reachable`. A dial made before the descriptor is fetchable waits out
/// Tor's whole window and fails (run 3, 2026-11-14: "waiting for
/// rendezvous desc", 105 s), and the address then goes off the dialer's
/// draw ("cooling after a failed dial").
const ONION_REACHABLE_LIMIT: Duration = Duration::from_secs(600);

/// How long the trio's sessions may take to form once every onion reads
/// `reachable` ([`RegtestDaemon::await_trio_mesh`]): one Tor test of an
/// address, its three attempts each up to the 120 s dial deadline, with
/// the longest retry waits between them, 10 s and 30 s (`shekyl-transport-
/// layer` `dial_profile(Tor)`, `RETRY_WAITS`): 3 × 120 + 10 + 30 = 400 s.
const TRIO_MESH_LIMIT: Duration = Duration::from_secs(400);

/// The origin's shipped retry, spelled here for the harness only: at its
/// first fire an origin with no alternate fluffs as the last resort (W3b).
///
/// The relay crate owns the derivation. The submit watchdog does not
/// read this duration: overdue is the daemon's judgment, and this
/// harness waits out the same interval the origin's embargo fires on.
const ORIGIN_RETRY: Duration = Duration::from_secs(1_148);

/// The draws [`RegtestDaemon::generate_blocks`] waits on, as a peer sees
/// them: a block's `draws` (`count(h)`, 4.4) and the references its
/// section admits ([`RegtestDaemon::watch_draws`]).
#[derive(Clone)]
struct DrawWatch {
    /// The heights whose draws are given a read window.
    drawn_in: std::ops::Range<u64>,
    /// `W₂`: a drawn block's bundle is admitted by `h + W₂ − 1` or not at
    /// all.
    w2: u64,
    /// The wait after each block while a window is open.
    per_block: Duration,
    /// The drawn heights whose bundle has not been admitted, each with the
    /// last height that can admit it.
    open: Vec<(u64, u64)>,
}

/// A directory only this account can enter, holding one daemon's empty
/// configuration file, `<base>/.shekyl-regtest/<rpc port>/shekyld.toml`:
/// mode 0700 on the directories and 0600 on the file. The daemon refuses a
/// configuration file with a directory above it that another account could
/// write (owned by neither root nor the daemon's account, or with a group or
/// other write bit), which rules out `TMPDIR` and a checkout built under a
/// group umask, and in a CI container the home directory too (owned by a
/// different uid). The base is the first candidate whose every directory
/// passes that same rule, from [`config_base`]; the parent stays, and each
/// daemon's directory goes with it.
fn private_config_dir(rpc_port: u16) -> PathBuf {
    let parent = config_base()
        .unwrap_or_else(|tried| {
            panic!(
                "no directory this account owns the whole way up for the daemon's empty \
                 configuration file (the daemon refuses one with a writable directory \
                 above it outside root and its own account); tried {tried:?}"
            )
        })
        .join(".shekyl-regtest");
    let dir = parent.join(rpc_port.to_string());
    drop(std::fs::remove_dir_all(&dir));
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(&dir)
        .expect("create the private config directory");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    drop(
        options
            .open(dir.join("shekyld.toml"))
            .expect("create the empty config file"),
    );
    dir
}

/// The first candidate base directory whose every directory, itself and up
/// to the root, is owned by root or by this account and carries no group or
/// other write bit: the daemon's rule for a configuration file's place. The
/// candidates, in order: the account's runtime directory (`XDG_RUNTIME_DIR`,
/// 0700 by contract), its home, and `/run` (writable by root alone, which is
/// what a CI container runs as). `Err` lists what was tried.
fn config_base() -> Result<PathBuf, Vec<PathBuf>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let me = std::fs::metadata("/proc/self")
            .map(|m| m.uid())
            .expect("this process's uid");
        let candidates: Vec<PathBuf> = [
            std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
            std::env::var_os("HOME").map(PathBuf::from),
            Some(PathBuf::from("/run")),
        ]
        .into_iter()
        .flatten()
        .collect();
        let owned_the_whole_way_up = |base: &Path| {
            base.ancestors().all(|dir| {
                std::fs::metadata(dir)
                    .map(|m| (m.uid() == 0 || m.uid() == me) && m.mode() & 0o022 == 0)
                    .unwrap_or(false)
            })
        };
        let writable_by_me = |base: &Path| {
            let probe = base.join(format!(".shekyl-regtest-probe-{}", std::process::id()));
            let ok = std::fs::create_dir(&probe).is_ok();
            drop(std::fs::remove_dir(&probe));
            ok
        };
        for base in &candidates {
            if base.is_dir() && owned_the_whole_way_up(base) && writable_by_me(base) {
                return Ok(base.clone());
            }
        }
        Err(candidates)
    }
    #[cfg(not(unix))]
    {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(Vec::new)
    }
}

impl RegtestDaemon {
    /// The pinned Tor binary a walk that reads over Tor runs, from
    /// `SHEKYL_TEST_TOR_BINARY`: the variable the live-Tor lane sets
    /// (`tor-pin-verify.yml`) to the bundle it fetched, checked against the
    /// pin and staged. Panics naming how to stage one when it is unset.
    fn live_tor_binary() -> PathBuf {
        match std::env::var_os("SHEKYL_TEST_TOR_BINARY") {
            Some(path) => PathBuf::from(path),
            None => panic!(
                "SHEKYL_TEST_TOR_BINARY not set: stage the pinned Tor bundle \
                 (scripts/release/tor_bundle.py fetch --host <triple> --sources <dir>; \
                 tor_bundle.py stage --host <triple> --sources <dir> --dest <stage>/tor) \
                 and set it to <stage>/tor/tor"
            ),
        }
    }

    /// Resolve the daemon binary from `SHEKYLD_BIN`. Panics with a clear message
    /// if unset — these tests are `#[ignore]`d and only run when explicitly
    /// invoked, so requiring the env var is the contract, not a surprise.
    fn binary() -> PathBuf {
        match std::env::var_os("SHEKYLD_BIN") {
            Some(p) => PathBuf::from(p),
            None => panic!(
                "SHEKYLD_BIN not set. Build the daemon (cmake --build build --target shekyl_rust_bins) \
                 and run e.g. SHEKYLD_BIN=/abs/path/build/bin/shekyld cargo test ... -- --ignored"
            ),
        }
    }

    /// Grab an ephemeral localhost port by binding :0 and releasing it. Small
    /// TOCTOU window before the daemon binds, acceptable for a serial test.
    fn free_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        l.local_addr().expect("local_addr").port()
    }

    /// A free port that is none of `taken`. Each probe binds :0 and releases
    /// immediately, so the kernel is free to hand back the same number twice
    /// — and a daemon given one number for two listeners dies at startup,
    /// intermittently. (The TOCTOU window between releasing a probe and the
    /// daemon binding is unchanged; this only removes the self-collision,
    /// which is the part we create.)
    fn free_port_excluding(taken: &[u16]) -> u16 {
        for _ in 0..PORT_DRAW_LIMIT {
            let port = Self::free_port();
            if !taken.contains(&port) {
                return port;
            }
        }
        panic!("could not obtain a port distinct from {taken:?}");
    }

    /// Spawn the daemon and wait until its RPC answers `daemon_status`.
    ///
    /// Coinbase goes to a dummy address. A walk that funds a wallet
    /// uses [`Self::start_for_seed`]: N2 pays `--mine-address`, not the
    /// `dev_block_generate` request's address.
    pub(super) async fn start() -> RegtestDaemon {
        Self::start_with_regtest_schedule(None).await
    }

    /// Spawn mining coinbase to `seed`'s primary address.
    pub(super) async fn start_for_seed(
        seed: &[u8; shekyl_crypto_pq::account::SEED_BYTES],
    ) -> RegtestDaemon {
        Self::start_for_seed_with_schedule(seed, None).await
    }

    /// [`Self::start_for_seed`] with the restricted listener bound as well:
    /// an offline daemon mining to `seed`'s address, whose own transactions
    /// are shown at once (no route, RD's NoRoute fluff at the origin).
    pub(super) async fn start_for_seed_with_restricted_listener(
        seed: &[u8; shekyl_crypto_pq::account::SEED_BYTES],
    ) -> RegtestDaemon {
        let serial = serial_lock().lock_owned().await;
        let mine_address = mine_address_from_seed(seed, shekyl_address::Network::Regtest);
        Self::spawn(
            RegtestSpawn::new(Some(serial))
                .with_mine_address(mine_address)
                .with_restricted_listener(),
        )
        .await
    }

    /// [`Self::start_for_seed`] with a levered regtest schedule.
    pub(super) async fn start_for_seed_with_schedule(
        seed: &[u8; shekyl_crypto_pq::account::SEED_BYTES],
        schedule: Option<RegtestSchedule>,
    ) -> RegtestDaemon {
        let serial = serial_lock().lock_owned().await;
        let mine_address = mine_address_from_seed(seed, shekyl_address::Network::Regtest);
        Self::spawn(
            RegtestSpawn::new(Some(serial))
                .with_schedule(schedule)
                .with_mine_address(mine_address),
        )
        .await
    }

    /// The emission walk's three daemons, all on a managed Tor running the
    /// pinned binary `tor_file` (Rick, 2026-11-14). A, returned first, is
    /// the miner: it pays `seed`'s address, seats its bundle producer (a
    /// mining address and a Tor, `shekyl-node` `producer::seat`), and is the
    /// daemon the wallet uses. B and C are relays. **A dials B and C; B
    /// dials C; C dials nobody.**
    ///
    /// **Why three.** A daemon with a Tor holds a transaction it originates
    /// until an outbound session hides its address
    /// (`DAEMON_RELAY_PRIVACY.md` §98.5), so A needs an outbound peer. With
    /// two daemons the stem dead-ends: the relay's only session is A's, the
    /// one the stem arrived on, a stem goes out on an outbound session
    /// other than its source and a fluff to every peer but its source, so
    /// the relay sends it nowhere, and A's transaction waits out A's own
    /// embargo (a draw, mean about 190 s, no lever) before it is shown. That
    /// is the origin rig's hold (`origin::StemSinkPair`), and a walk that
    /// mines hundreds of transactions cannot wait it out each time. With
    /// three, every stem A originates ends at a node that fluffs back to A:
    /// stemmed to B, it goes on to C, which has no outbound session and
    /// fluffs to every peer but B, A among them; stemmed to C, C fluffs to
    /// B, and B relays the fluff to A.
    ///
    /// C names one unanswered loopback port as its whole network, so it is
    /// synced from open and dials nobody; B's one closed peer is C's onion.
    /// Neither mines; both follow A over the sessions A opens.
    ///
    /// **When it is ready.** A daemon is spawned only once the onions it
    /// dials read `reachable` ([`ONION_REACHABLE_LIMIT`]), and the trio is
    /// returned only once its mesh is whole: A holds sessions to B and C, B
    /// to C, and both relays are at A's tip ([`Self::await_trio_mesh`]).
    /// Run 3 (2026-11-14) spawned A while C's descriptor was not yet
    /// fetchable: A's dial to C failed, so a stem A sent B went on to C,
    /// whose one other peer was the source, and A's first transaction was
    /// still unbroadcast at the limit. Each daemon logs `p2p` and `tor` at
    /// `debug`, so a session that closes says why.
    pub(super) async fn start_tor_trio(
        seed: &[u8; shekyl_crypto_pq::account::SEED_BYTES],
        schedule: Option<RegtestSchedule>,
        tor_file: PathBuf,
    ) -> (RegtestDaemon, RegtestDaemon, RegtestDaemon) {
        let serial = serial_lock().lock_owned().await;
        let c = Self::spawn(
            RegtestSpawn::new(None)
                .with_schedule(schedule)
                .with_peering(Peering::Listening {
                    p2p_port: Self::free_port(),
                    requests: true,
                })
                .with_managed_tor(tor_file.clone()),
        )
        .await;
        let c_onion = c.published_onion(TOR_PUBLISH_LIMIT).await;
        c.await_onion_reachable(ONION_REACHABLE_LIMIT).await;
        let b = Self::spawn(
            RegtestSpawn::new(None)
                .with_schedule(schedule)
                .with_peering(Peering::TorPeers {
                    first: c_onion,
                    second: None,
                })
                .with_managed_tor(tor_file.clone())
                .with_ports_taken([c.rpc_port]),
        )
        .await;
        let b_onion = b.published_onion(TOR_PUBLISH_LIMIT).await;
        b.await_onion_reachable(ONION_REACHABLE_LIMIT).await;
        let mine_address = mine_address_from_seed(seed, shekyl_address::Network::Regtest);
        let mut a = Self::spawn(
            RegtestSpawn::new(Some(serial))
                .with_schedule(schedule)
                .with_mine_address(mine_address)
                .with_peering(Peering::TorPeers {
                    first: b_onion,
                    second: Some(c_onion),
                })
                .with_managed_tor(tor_file)
                .with_ports_taken([b.rpc_port, c.rpc_port]),
        )
        .await;
        a.relays = Some(TrioRelays {
            b: b.rpc.clone(),
            b_onion,
            c: c.rpc.clone(),
            c_onion,
        });
        a.await_trio_mesh(TRIO_MESH_LIMIT).await;
        (a, b, c)
    }

    /// The trio's mesh as it reads now, from A (this daemon); `None` on a
    /// daemon that is not the trio's miner. A's tip is read first, so a
    /// relay at or past it has every block A had then.
    async fn read_mesh(&self) -> Option<MeshReading> {
        let relays = self.relays.as_ref()?;
        let a_height = tip_height(&self.rpc).await;
        Some(MeshReading {
            a_to_b: holds_outbound_to(&self.rpc, relays.b_onion).await,
            a_to_c: holds_outbound_to(&self.rpc, relays.c_onion).await,
            b_to_c: holds_outbound_to(&relays.b, relays.c_onion).await,
            a_height,
            b_height: tip_height(&relays.b).await,
            c_height: tip_height(&relays.c).await,
        })
    }

    /// Wait until the trio's mesh is whole ([`MeshReading::whole`]), within
    /// `limit`; at once on a daemon that is not the trio's miner.
    async fn await_trio_mesh(&self, limit: Duration) {
        let deadline = Instant::now() + limit;
        loop {
            let Some(reading) = self.read_mesh().await else {
                return;
            };
            if reading.whole() {
                eprintln!("tor trio: the mesh is whole ({reading})");
                return;
            }
            if Instant::now() >= deadline {
                self.panic_with_log(
                    "the Tor trio's mesh did not form",
                    format!("within {limit:?}: {reading}"),
                );
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Wait until this daemon's own onion reads `reachable`, its probe
    /// having arrived (`TOR_SUPERVISOR.md` §4.5), within `limit`.
    async fn await_onion_reachable(&self, limit: Duration) {
        let deadline = Instant::now() + limit;
        loop {
            let onion = self
                .status()
                .await
                .tor_status()
                .and_then(|status| status.tor)
                .and_then(|managed| managed.onion);
            if onion
                .as_ref()
                .is_some_and(|onion| onion.state.keyword() == "reachable")
            {
                return;
            }
            if Instant::now() >= deadline {
                self.panic_with_log(
                    "the managed Tor's onion did not read reachable",
                    format!("after {limit:?}: {onion:?}"),
                );
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// The onion this daemon's managed Tor published its inbound at, read
    /// from the line the daemon logs when it does (`shekyl-p2p`,
    /// `Network::note_own_onion`), within `limit`.
    async fn published_onion(&self, limit: Duration) -> OnionPeer {
        const LINE: &str = "overlay inbound is published at ";
        let deadline = Instant::now() + limit;
        let log_path = self.data_dir.join("daemon.log");
        loop {
            let log = std::fs::read_to_string(&log_path).unwrap_or_default();
            if let Some(onion) = log.lines().find_map(|line| {
                let (_, rest) = line.split_once(LINE)?;
                OnionPeer::parse(rest.split_whitespace().next()?.trim_end_matches(','))
            }) {
                return onion;
            }
            if Instant::now() >= deadline {
                self.panic_with_log(
                    "the managed Tor published no inbound onion",
                    format!("within {limit:?}"),
                );
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Spawn a daemon whose data directory survives [`Drop`].
    ///
    /// The DX-Q8 column (`scripts/bench/capture_kept_chain.py`) reads the
    /// directory after the generator exits. Every other spawn still deletes
    /// its directory, unless its test is failing: `Drop` keeps a panicking
    /// test's daemon directory, since its logs are what the failure needs.
    /// `Drop` reads nothing from the environment (#1221).
    pub(super) async fn start_keeping_data() -> RegtestDaemon {
        let serial = serial_lock().lock_owned().await;
        Self::spawn(RegtestSpawn::new(Some(serial)).keeping_data()).await
    }

    /// Spawn the daemon with a second, restricted listener, so one daemon serves
    /// both postures and a test can put the same request to each.
    ///
    /// The second listener comes from `--rpc-view-listen`, which binds an
    /// additional server in the view posture (`RPC_CHANNEL.md` §6.1). The
    /// admin listener keeps its own posture — and it has to stay admin
    /// here, both because the harness drives mining through it and because
    /// it is the blast-radius control.
    ///
    /// The restricted listener is opt-in rather than always-on: this harness is
    /// `#[ignore]`d, so CI would not catch a regression it introduced into the
    /// spawn that every other e2e test shares.
    pub(super) async fn start_with_restricted_listener() -> RegtestDaemon {
        let serial = serial_lock().lock_owned().await;
        Self::spawn(RegtestSpawn::new(Some(serial)).with_restricted_listener()).await
    }

    /// Spawn the daemon offline on testnet. It is not armed: only regtest's
    /// row permits `dev-rpc` (NI-R8), and it has no fixed difficulty, which
    /// is regtest's too. A test that needs a lever runs on regtest.
    pub(super) async fn start_on_testnet() -> RegtestDaemon {
        let serial = serial_lock().lock_owned().await;
        Self::spawn(RegtestSpawn::new(Some(serial)).on_network(SpawnNetwork::Testnet)).await
    }

    /// Spawn the daemon with an optional regtest schedule on its command
    /// line — `--dev-settlement-epoch-blocks` and
    /// `--dev-archival-reorg-depth`, the regtest-only rows the daemon arms
    /// at startup (DAEMON_CONFIG_CUTOVER.md §2.2 step 6, before the genesis
    /// add). The pair moves together: the daemon refuses
    /// an epoch that is not strictly above the reorg cap (`SEB > D_max` is
    /// an invariant of every valid configuration; a shortened epoch runs a
    /// levered rule set whose cap fits inside it). The emission e2e
    /// passes `Some(schedule)` so epoch closes land in minutes; the wallet
    /// process arms the same pair in-process (it does its own epoch
    /// arithmetic when it assembles a claim, and gates on the lever —
    /// `lifecycle.rs`). `None` runs the genesis-pinned schedule.
    pub(super) async fn start_with_regtest_schedule(
        schedule: Option<RegtestSchedule>,
    ) -> RegtestDaemon {
        let serial = serial_lock().lock_owned().await;
        Self::spawn(RegtestSpawn::new(Some(serial)).with_schedule(schedule)).await
    }

    /// Spawn one daemon. The caller owns the serial guard, so a test that
    /// spawns two daemons takes it once.
    async fn spawn(spec: RegtestSpawn) -> RegtestDaemon {
        let RegtestSpawn {
            serial,
            network,
            schedule,
            restricted_listener,
            peering,
            mine_address,
            keep_data,
            binary,
            taken,
            chain_dir,
            tor_file,
        } = spec;
        install_wallet_tracing();

        // A released binary named here (the mixed-version test's alpha.11)
        // predates `rpc-socket-dir`, and refuses a row it does not know.
        let released = binary.is_some();
        let bin = binary.unwrap_or_else(Self::binary);
        let offline = matches!(peering, Peering::Offline);
        let tor_on = tor_file.is_some();
        let p2p_ports: Vec<u16> = match &peering {
            // Neither binds a loopback port: no listener, or Tor's alone.
            Peering::Offline | Peering::TorPeers { .. } => Vec::new(),
            Peering::Linked {
                p2p_port,
                peer_p2p_port,
            } => vec![*p2p_port, *peer_p2p_port],
            Peering::Listening { p2p_port, .. } => vec![*p2p_port],
            Peering::Closed { p2p_port, peers } => {
                let mut ports = vec![*p2p_port];
                ports.extend(peers.iter().map(std::net::SocketAddrV4::port));
                ports
            }
        };
        let mut reserved = taken;
        reserved.extend(p2p_ports);
        // A listening daemon dials an unanswered port on this host. Bind
        // it before the RPC ports are drawn, and keep it out of that draw:
        // the kernel would otherwise hand the closed-peer port back as
        // the RPC listener.
        let unanswered = matches!(peering, Peering::Listening { .. })
            .then(|| UnansweredPort::bind_excluding(&reserved));
        if let Some(held) = unanswered.as_ref() {
            reserved.push(held.port());
        }
        let closed_peer = unanswered.as_ref().map(UnansweredPort::peer);
        let rpc_port = Self::free_port_excluding(&reserved);
        let data_dir = std::env::temp_dir().join(format!("shekyl-regtest-{rpc_port}"));
        drop(std::fs::remove_dir_all(&data_dir));
        std::fs::create_dir_all(&data_dir).expect("create data dir");
        // The daemon reads `/etc/shekyl/shekyld-<network>.toml` by default,
        // and a fleet host's own testnet file (its `p2p-peer` rows against
        // the `clearnet off` below) is not a test daemon's: a test's result
        // must not depend on the host it runs on. A named empty file means
        // the defaults and nothing else. The daemon refuses a configuration
        // file that any other account could write, on the file or on any
        // directory above it, so the file cannot sit under the data
        // directory (`TMPDIR` is world-writable) nor in the checkout (a
        // group umask makes it group-writable); it sits in a private
        // directory under a base this account owns the whole way up.
        let config_dir = private_config_dir(rpc_port);
        let config_file = config_dir.join("shekyld.toml");

        let log = std::fs::File::create(data_dir.join("daemon.log")).expect("daemon log");
        // The chain's directory is the daemon's `data-dir`. The logs stay
        // in `data_dir` either way.
        let chain_dir = chain_dir.unwrap_or_else(|| data_dir.clone());
        std::fs::create_dir_all(&chain_dir).expect("create the chain's directory");
        let mut cmd = Command::new(&bin);
        // The grammar's spellings (INPUT_GRAMMAR.md §5). Tor is off unless
        // the spawn names the pinned binary: regtest's default is the
        // managed Tor, and only the walk that reads over Tor launches one.
        //
        // The armed test levers (`dev_block_generate`, `dev_chain_pop`) are
        // served only with `--dev-rpc` set (`RPC_CHANNEL.md` §6.1), and only
        // regtest's row permits it (NI-R8): a testnet daemon given it
        // refuses to start, so a testnet spawn never passes it. The daemon
        // announces the lever at start, and `await_ready` holds it to that.
        match network {
            SpawnNetwork::Regtest => {
                cmd.args(["--network", "regtest", "--dev-difficulty", "1", "--dev-rpc"])
            }
            SpawnNetwork::Testnet => cmd.args(["--network", "testnet"]),
        };
        // A daemon on the live Tor also logs `p2p` and `tor` at `debug`: its
        // sessions cross the public Tor network, and a session that closes
        // mid-walk is logged with its cause only there.
        match &tor_file {
            Some(tor) => cmd.args([
                "--tor",
                "managed",
                "--tor-file",
                tor.to_str().expect("utf8 tor path"),
                "--log-category",
                "p2p=debug",
                "--log-category",
                "tor=debug",
            ]),
            None => cmd.args(["--tor", "off"]),
        };
        cmd.args([
            "--rpc-admin-listen",
            &format!("127.0.0.1:{rpc_port}"),
            "--data-dir",
            chain_dir.to_str().expect("utf8 data dir"),
            "--config-file",
            config_file.to_str().expect("utf8 config path"),
            // Under the data dir, as the old default was; the account's
            // own `logs/` is not a test's to fill. The daemon logs to
            // stderr too, which `daemon.log` below captures.
            "--log-file",
            &data_dir.join("shekyld.log").display().to_string(),
            // `info`: the submit engine records a Phase C refusal at
            // `info`, so the log tail a panic inlines names what the
            // daemon rejected instead of a bare `Malformed`.
            "--log-level",
            "info",
        ]);
        // The owner's socket goes in the same private directory: this
        // account's, mode 0700, one per spawn. A harness names it, so a test
        // daemon never meets another's at the default rendezvous and needs no
        // session directory (`RPC_CHANNEL.md` §7.1, IG-Q104).
        if !released {
            cmd.args([
                "--rpc-socket-dir",
                config_dir.to_str().expect("utf8 config path"),
            ]);
        }
        let mine_address = mine_address.unwrap_or_else(|| default_mine_address(network));
        cmd.args(["--mine-address", &mine_address]);
        match peering {
            Peering::Offline => {
                cmd.args(["--clearnet", "off"]);
            }
            Peering::Linked {
                p2p_port,
                peer_p2p_port,
            } => {
                cmd.args([
                    "--clearnet-listen",
                    &format!("127.0.0.1:{p2p_port}"),
                    "--p2p-closed-peer",
                    &format!("127.0.0.1:{peer_p2p_port}"),
                ]);
            }
            Peering::Listening { p2p_port, requests } => {
                cmd.args([
                    "--clearnet-listen",
                    &format!("127.0.0.1:{p2p_port}"),
                    "--p2p-closed-peer",
                    closed_peer
                        .as_deref()
                        .expect("a listening spawn holds its unanswered port"),
                ]);
                if !requests {
                    cmd.args(["--dev-sync", "off"]);
                }
            }
            Peering::Closed { p2p_port, peers } => {
                cmd.args(["--clearnet-listen", &format!("127.0.0.1:{p2p_port}")]);
                for peer in peers {
                    cmd.args(["--p2p-closed-peer", &peer.to_string()]);
                }
            }
            Peering::TorPeers { first, second } => {
                cmd.args(["--clearnet", "off"]);
                for onion in std::iter::once(first).chain(second) {
                    cmd.args(["--p2p-closed-peer", &onion.to_string()]);
                }
            }
        }
        let restricted_port = restricted_listener.then(|| {
            let mut taken = reserved.clone();
            taken.push(rpc_port);
            Self::free_port_excluding(&taken)
        });
        if let Some(port) = restricted_port {
            // A second listener on the same daemon, in the view posture;
            // the admin listener keeps its own. Same handlers behind both —
            // only the posture differs, which is the whole point: one
            // process, two answers.
            cmd.args(["--rpc-view-listen", &format!("127.0.0.1:{port}")]);
        }
        cmd.stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .stdin(Stdio::null());
        // The schedule rides the command line as the two regtest rows (the
        // daemon arms them at startup and refuses loudly on a bad pair).
        // The daemon reads no environment, so `None` has nothing to scrub:
        // a lever in the developer's or CI's shell cannot reach it.
        if let Some(schedule) = schedule {
            cmd.args([
                "--dev-settlement-epoch-blocks",
                &schedule.seb.to_string(),
                "--dev-archival-reorg-depth",
                &schedule.reorg_cap.to_string(),
            ]);
        }
        let recipe: Vec<std::ffi::OsString> = cmd.get_args().map(ToOwned::to_owned).collect();
        let child = shekyl_tor_control_client::spawn_lock::spawn(&mut cmd)
            .unwrap_or_else(|e| panic!("spawn {}: {e}", bin.display()));

        // Base URL only — `Rpc::call` appends the `json_rpc` route itself.
        // Long timeout: `generate_blocks` late in a deep-tree mine takes well over
        // the 30s default (each block ~2.5s; the depth-3 mine is ~750 blocks).
        let rpc = HttpRpc::with_custom_timeout(
            format!("http://127.0.0.1:{rpc_port}"),
            Duration::from_secs(180),
        )
        .await
        .expect("construct rpc client");

        let mut daemon = RegtestDaemon {
            child,
            chain_dir,
            data_dir,
            config_dir,
            rpc_port,
            rpc,
            restricted_url: restricted_port.map(|p| format!("http://127.0.0.1:{p}")),
            schedule,
            cli_network: match network {
                SpawnNetwork::Regtest => "regtest",
                SpawnNetwork::Testnet => "testnet",
            },
            armed: matches!(network, SpawnNetwork::Regtest),
            offline,
            // Synced from open: offline, or the Tor spawn's closed network
            // of one unanswered port or of onions (`start_tor_trio`).
            posts_at_open: offline || tor_on,
            keep_data,
            _serial: serial,
            recipe,
            unanswered,
            watch: std::sync::Mutex::new(None),
            shown_pool_limit: if tor_on {
                TOR_SHOWN_POOL_LIMIT
            } else {
                SHOWN_POOL_LIMIT
            },
            waits_for_stems: tor_on,
            relays: None,
        };
        daemon.await_ready().await;
        daemon
    }

    /// Poll `block_template` until the daemon has posted a job (or time
    /// out). An offline daemon posts a template once its follower has read
    /// `Synced`; until then `dev_block_generate` is refused, which is the
    /// daemon's honest answer and not a test's finding. Ready is the first
    /// posted job.
    async fn await_posted(&self, deadline: Instant, log_path: &std::path::Path) {
        let mut last = String::new();
        while Instant::now() < deadline {
            match self.rpc.call::<wire::BlockTemplate>(NoParams).await {
                Ok(_) => return,
                Err(e) => last = format!("{e:?}"),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!(
            "the daemon posted no template within the readiness window; last answer: {last}; log tail:\n{}",
            log_tail(log_path)
        );
    }

    async fn await_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut last_err = String::new();
        let log_path = self.data_dir.join("daemon.log");
        while Instant::now() < deadline {
            // Fail fast if the daemon process already exited (bad SHEKYLD_BIN,
            // missing runtime deps, port-bind failure): polling for the full 60s
            // would only delay an unhelpful timeout. Point at the captured log so
            // the real cause is one `cat` away.
            if let Ok(Some(status)) = self.child.try_wait() {
                let tail = log_tail(&log_path);
                panic!("daemon exited early ({status}) before RPC became ready; log tail:\n{tail}");
            }
            match self.rpc.call::<wire::DaemonStatus>(NoParams).await {
                Ok(status) => {
                    // The harness reads the P2P state, not a count: a daemon
                    // started offline says so, and one whose P2P runs
                    // says whether it has a peer (Rick, 2026-10-14).
                    assert_eq!(
                        status.offline, self.offline,
                        "daemon_status's P2P state must be the daemon's configuration"
                    );
                    assert_eq!(status.peered.0.is_none(), self.offline);
                    // The armed row is set on regtest and the daemon said so
                    // at start (IG-8's announcement, written before RPC
                    // binds); a testnet daemon is not armed and says nothing.
                    let log = std::fs::read_to_string(&log_path).unwrap_or_default();
                    assert_eq!(
                        log.contains(ARMED_ROW_ANNOUNCEMENT),
                        self.armed,
                        "the daemon's `{ARMED_ROW_ANNOUNCEMENT}` announcement must match \
                         its spawn (armed: {}); log tail:\n{}",
                        self.armed,
                        log_tail(&log_path)
                    );
                    if self.posts_at_open {
                        self.await_posted(deadline, &log_path).await;
                    }
                    return;
                }
                Err(e) => last_err = format!("{e:?}"),
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let tail = log_tail(&log_path);
        panic!(
            "daemon RPC never became ready (port {}) after 60s: {last_err}; log tail:\n{tail}",
            self.rpc_port,
        );
    }

    /// The daemon's state, as the harness's listener is told it.
    pub(super) async fn status(&self) -> DaemonStatus {
        self.rpc
            .call::<wire::DaemonStatus>(NoParams)
            .await
            .expect("daemon_status")
    }

    /// The chain's block **count**: the tip's height plus one.
    pub(super) async fn height(&self) -> u64 {
        self.status().await.height.0 + 1
    }

    /// The tip's hash, from `daemon_status`: what the chain holds, read
    /// whether or not the node is synchronized. `block_header_show` of the
    /// tip refuses a node that is catching up to a peer's claim, which a
    /// node taking a relayed block is for the moment between the claim and
    /// the block.
    pub(super) async fn top_block_hash(&self) -> String {
        self.status().await.hash.to_string()
    }

    /// The accepting daemon's own revision (`daemon_status.revision`).
    ///
    /// Recorded into the live-oracle capture as provenance: a chain-attested
    /// fixture is only as meaningful as the identity of the node that attested
    /// it, and this crate's version is not that identity.
    pub(super) async fn version(&self) -> String {
        self.status()
            .await
            .revision
            .shown()
            .expect("the harness's own listener is shown Status")
            .0
    }

    /// Every transaction this daemon holds in its pool, broadcast or not —
    /// the drain loop's condition and the pop legs' return-to-pool
    /// observable.
    ///
    /// The tip's hash, from `block_header_show` of the tip.
    pub(super) async fn last_block_hash(&self) -> String {
        self.rpc
            .call::<wire::BlockHeaderShow>(HeaderSelect(BlockSelect {
                select: Selector::Tip,
                pow: false,
                prune: None,
            }))
            .await
            .expect("block_header_show")
            .hash
            .to_string()
    }

    /// Every transaction this daemon holds in its pool, public or not —
    /// the drain loop's condition and the pop legs' return-to-pool
    /// observable.
    ///
    /// `daemon_status` reports the pool as two counts: the entries the node
    /// has made public, told to every caller, and the entries it has not,
    /// told only to the host (RT-O9.3). Both callers of this mean
    /// "everything", and a transaction a wallet has just submitted sits in
    /// the second count until its stem ends, so this is their sum. The
    /// harness talks to the daemon as its host; a reply without the host
    /// part would mean it was answered as someone else, and is a failure,
    /// never a zero.
    pub(super) async fn tx_pool_size(&self) -> u64 {
        let status = self.status().await;
        let private = status
            .txpool_private_count
            .shown()
            .expect("the harness is the host, and is told the host-only part")
            .0
            .expect("the harness's pool is live")
            .0;
        status
            .txpool_count
            .shown()
            .expect("the harness is the host, and is told the pool part")
            .0
            .expect("the harness's pool is live")
            .0
            .checked_add(private)
            .expect("two pool counts fit a u64")
    }

    /// The `(median, block-weight limit)` in force for the next block, as
    /// `daemon_status` reports them.
    pub(super) async fn weight_limit(&self) -> (u64, u64) {
        let status = self.status().await;
        (
            status
                .block_weight_median
                .shown()
                .expect("the chain part is shown")
                .0,
            status
                .block_weight_max
                .shown()
                .expect("the chain part is shown")
                .0,
        )
    }

    /// The block at `height`, whole.
    pub(super) async fn block_at(&self, height: u64) -> wire::block::Block {
        self.rpc
            .call::<wire::BlockShow>(BlockShowSelect(BlockSelect {
                select: Selector::Height(shekyl_rpc_types::kinds::Height(height)),
                pow: false,
                prune: Some(false),
            }))
            .await
            .unwrap_or_else(|e| panic!("block_show {height}: {e:?}"))
    }

    /// The bundle references the block at `height` admitted (its
    /// section), decoded: each names its `h`, its draw count and its pass
    /// bitmap (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §7.5). Empty for a block that
    /// admitted none.
    pub(super) async fn section_at(
        &self,
        height: u64,
    ) -> Vec<shekyl_archival_retention::BundleRef> {
        self.block_at(height)
            .await
            .section
            .into_iter()
            .map(|reference| {
                shekyl_archival_retention::BundleRef::decode(&reference.into_vec())
                    .unwrap_or_else(|e| panic!("block {height}'s section decodes: {e:?}"))
            })
            .collect()
    }

    /// Wait until the managed Tor reports `usable` (`TOR_SUPERVISOR.md`
    /// §4.3), within `limit`: the bundle producer reads through it.
    pub(super) async fn await_tor_usable(&self, limit: Duration) {
        let deadline = Instant::now() + limit;
        loop {
            let tor = self
                .status()
                .await
                .tor_status()
                .and_then(|status| status.tor);
            if tor
                .as_ref()
                .is_some_and(|managed| managed.state.keyword() == "usable")
            {
                return;
            }
            if Instant::now() >= deadline {
                self.panic_with_log(
                    "the managed Tor did not become usable",
                    format!("after {limit:?}: {tor:?}"),
                );
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// The block named by `hash`, whole.
    async fn block_by_hash(&self, hash: &str) -> wire::block::Block {
        self.rpc
            .call::<wire::BlockShow>(BlockShowSelect(BlockSelect {
                select: Selector::Hash(HashHex::from_hex(hash).expect("a block hash")),
                pow: false,
                prune: Some(false),
            }))
            .await
            .expect("block_show")
    }

    /// Non-coinbase transaction hashes carried by the block named by `hash`
    /// (lowercase hex, as `dev_block_generate` returns them).
    ///
    /// Keyed by hash rather than by height on purpose: `dev_block_generate`
    /// hands back the hashes of the blocks it actually connected, so this
    /// asks about *that* block instead of re-deriving its index from a
    /// chain count that would be one off.
    ///
    /// Reads the production [`wire::block::Block`] — the type `block_fetch`
    /// reads — so a renamed member fails here the same way it fails the
    /// wallet, instead of looking like "a block connected without the
    /// spend".
    pub(super) async fn block_tx_hashes(&self, hash: &str) -> Vec<HashHex> {
        self.block_by_hash(hash)
            .await
            .tx
            .into_iter()
            .map(|slot| match slot {
                wire::shared::OrArchived::Item(tx) => tx.id,
                wire::shared::OrArchived::Archived(wire::shared::ArchivedState::Archived(
                    archived,
                )) => archived.id,
            })
            .collect()
    }

    /// The weight the daemon recorded for the block named by `hash` and the
    /// listed transactions it carries — the daemon's own account of how
    /// full the block it built is.
    pub(super) async fn block_weight_of(&self, hash: &str) -> (u64, usize) {
        let block = self.block_by_hash(hash).await;
        (block.header.weight.0, block.tx.len())
    }

    /// Cumulative fee burn — the destroyed half of the §9.5 fee partition.
    /// The emission e2e samples it once, at epoch close, and pins it to 0
    /// (A6 pool-half disposition).
    pub(super) async fn total_burned(&self) -> shekyl_units::AtomicUnits {
        self.status()
            .await
            .burn_total
            .shown()
            .expect("the chain part is shown")
            .to_atomic_units()
    }

    /// The ephemeral RPC port the daemon bound. Observability harnesses open
    /// their own independent per-persona clients against it (each a distinct
    /// TCP connection), rather than sharing this instance's `rpc` client.
    pub(super) fn rpc_port(&self) -> u16 {
        self.rpc_port
    }

    /// Last lines of the daemon's log, for inlining into a test's own
    /// panic. Read it *before* panicking: the unwind drops this fixture,
    /// which kills the daemon and removes the datadir, log included.
    pub(super) fn log_tail(&self) -> String {
        log_tail(&self.data_dir.join("daemon.log"))
    }

    /// Panic with the daemon log inlined. Call on a submit/dispatch
    /// failure: `Drop` removes the datadir (log included) as the unwind
    /// proceeds, so a "see the log file" pointer would name a deleted file.
    pub(super) fn panic_with_log(&self, context: &str, err: impl std::fmt::Display) -> ! {
        panic!("{context}: {err}; daemon log tail:\n{}", self.log_tail());
    }

    /// Run one §13 word through `shekyl-cli` against this daemon.
    ///
    /// The C++ console is gone, so the harness spawns the binary. The
    /// binary is `SHEKYL_CLI_BIN`, given the daemon's own network with
    /// `--network`, regtest included (NI-R1, NI-R4).
    pub(super) fn console(&self, command: &str) -> String {
        let network = self.cli_network;
        let bin = std::env::var_os("SHEKYL_CLI_BIN").unwrap_or_else(|| {
            panic!(
                "SHEKYL_CLI_BIN not set. Build shekyl-cli and pass the binary, \
                 beside SHEKYLD_BIN"
            );
        });
        let mut cmd = std::process::Command::new(bin);
        cmd.args([
            "--daemon-address",
            &format!("http://127.0.0.1:{}", self.rpc_port),
            "--network",
            network,
        ])
        .args(command.split_whitespace())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
        let child =
            shekyl_tor_control_client::spawn_lock::spawn(&mut cmd).expect("spawn shekyl-cli");
        let output = child.wait_with_output().expect("wait for shekyl-cli");
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        if !output.stderr.is_empty() {
            text.push('\n');
            text.push_str(&String::from_utf8_lossy(&output.stderr));
        }
        if text.trim().is_empty() {
            panic!(
                "shekyl-cli {command:?} exited {} with no output",
                output.status
            );
        }
        text
    }

    /// Base URL of the restricted listener, for a daemon spawned by
    /// [`RegtestDaemon::start_with_restricted_listener`].
    pub(super) fn restricted_url(&self) -> &str {
        self.restricted_url
            .as_deref()
            .expect("daemon was not spawned with a restricted listener")
    }

    /// Mine `n` blocks (an armed test lever: `--dev-rpc`). Coinbase pays
    /// `--mine-address` from spawn (N2): a funding walk names the wallet
    /// at [`Self::start_for_seed`], the one place the address is given.
    ///
    /// Waits until every pool entry is shown and listed on the posted
    /// job (`DRS_X_STORE_FLIP.md` Q9) before asking the miner to move the
    /// tip. A local submit is stem until the relay fluffs it; mining
    /// before that posts a coinbase-only job and the spend never lands.
    ///
    /// One call per [`Self::MINE_CHUNK`] blocks: a block costs a few
    /// seconds on a disk where each of its two syncs takes most of a
    /// second, and a long stretch asked for in one call would outlive the
    /// harness's 180 s HTTP timeout there while fitting on a fast disk,
    /// which would make the test's result depend on its host.
    pub(super) async fn generate_blocks(&self, n: u64) -> GenerateBlocksResp {
        self.wait_shown_pool_in_template().await;
        let mut mined = 0u64;
        let mut blocks = Vec::new();
        loop {
            let watch = self.watch.lock().expect("the watch lock").clone();
            // Under a watch, a block whose draws or admissions it reads is
            // mined alone; the chain's block count is the height the next
            // block connects at.
            let (chunk, watched) = match watch {
                None => ((n - mined).min(Self::MINE_CHUNK), false),
                Some(watch) => {
                    let next = self.height().await;
                    if !watch.open.is_empty() || watch.drawn_in.contains(&next) {
                        (1, true)
                    } else {
                        let before = if next < watch.drawn_in.start {
                            watch.drawn_in.start - next
                        } else {
                            u64::MAX
                        };
                        ((n - mined).min(Self::MINE_CHUNK).min(before), false)
                    }
                }
            };
            let resp = try_generate_blocks(&self.rpc, chunk)
                .await
                .expect("dev_block_generate");
            blocks.extend(resp.blocks);
            mined += chunk;
            if watched {
                if let Some(wait) = self.after_watched_block(resp.height - 1).await {
                    tokio::time::sleep(wait).await;
                }
            }
            if mined >= n {
                return GenerateBlocksResp {
                    height: resp.height,
                    blocks,
                };
            }
        }
    }

    /// Give each block in `drawn_in` that drew a read window, wherever
    /// [`Self::generate_blocks`] is called from: a helper that mines a
    /// confirmation, the settlement loop or a pop leg's re-mine (Rick,
    /// 2026-11-14). The window runs from the block until its bundle is
    /// admitted, or until `h + W₂ − 1`, the last block that can admit it;
    /// while one is open each block is mined alone and followed by
    /// `per_block`. The producer's reads come due at heights it alone
    /// knows, so the chain has to reach them: mining stops for none of
    /// them. A window already open stays open.
    pub(super) fn watch_draws(&self, drawn_in: std::ops::Range<u64>, w2: u64, per_block: Duration) {
        let mut slot = self.watch.lock().expect("the watch lock");
        let open = slot.take().map(|watch| watch.open).unwrap_or_default();
        *slot = Some(DrawWatch {
            drawn_in,
            w2,
            per_block,
            open,
        });
    }

    /// Read the block at `height` as a peer would: open a window when it
    /// drew inside the watched range, and close each window its section
    /// admits a bundle for or whose last admitting height it is. The wait
    /// before the next block, while a window is open.
    async fn after_watched_block(&self, height: u64) -> Option<Duration> {
        let mut watch = self.watch.lock().expect("the watch lock").clone()?;
        let block = self.block_at(height).await;
        let drew = block.draws.0.map_or(0, |count| count.0);
        if watch.drawn_in.contains(&height) && drew > 0 {
            eprintln!(
                "block {height} drew {drew}: its read window runs to {}",
                height + watch.w2 - 1
            );
            watch.open.push((height, height + watch.w2 - 1));
        }
        if !watch.open.is_empty() {
            let admitted: Vec<u64> = block
                .section
                .into_iter()
                .map(|reference| {
                    shekyl_archival_retention::BundleRef::decode(&reference.into_vec())
                        .unwrap_or_else(|e| panic!("block {height}'s section decodes: {e:?}"))
                        .h()
                        .to_raw()
                })
                .collect();
            watch.open.retain(|&(h, last)| {
                if admitted.contains(&h) {
                    eprintln!("the bundle for block {h} was admitted at {height}");
                    false
                } else if height >= last {
                    eprintln!("block {h}'s read window closed at {height} with no bundle admitted");
                    false
                } else {
                    true
                }
            });
        }
        let wait = (!watch.open.is_empty()).then_some(watch.per_block);
        *self.watch.lock().expect("the watch lock") = Some(watch);
        wait
    }

    /// Blocks per `dev_block_generate` call in [`Self::generate_blocks`].
    const MINE_CHUNK: u64 = 32;

    /// Q9: once the relay marks the pool shown, the next template lists
    /// it. A shown pool whose backlog is short means the follower has not
    /// rebuilt the posted job yet, unless the job is full: the fill is
    /// reward-aware and stops within one body of the median
    /// (`Fill::admit`), so an overfilled pool is listed as far as the
    /// policy allows and no further. An unbroadcast entry is in its stem
    /// phase and is not a candidate (the template lists what the node
    /// shows, criterion 2), so it is not waited for: a linked node holds
    /// one through its embargo, and a block mined meanwhile leaves it in
    /// the pool.
    ///
    /// What the job lists is read from the template's own bytes (its
    /// block's transaction ids); the shown pool and each entry's weight are
    /// `txpool_list`'s (IG-Q46).
    async fn wait_shown_pool_in_template(&self) {
        let limit = self.shown_pool_limit;
        let mut deadline = Instant::now() + limit;
        // On the Tor trio: the reading taken when the origin had not come
        // back at the limit with a session down, after which the wait runs
        // to the miner's own embargo fire.
        let mut short: Option<MeshReading> = None;
        loop {
            // The host is told both counts: the entries this node has
            // broadcast, and those it holds and has not (`daemon_status`,
            // RT-O9.3). `txpool_list` answers the host from both, so the job
            // is compared with the broadcast count alone.
            let status = self.status().await;
            let unbroadcast = status
                .txpool_private_count
                .shown()
                .expect("the harness is the host, and is told the host-only part")
                .0
                .expect("the harness's pool is live")
                .0;
            let broadcast = status
                .txpool_count
                .shown()
                .expect("the harness is the host, and is told the pool part")
                .0
                .expect("the harness's pool is live")
                .0;
            let returned = !self.waits_for_stems || unbroadcast == 0;
            if returned && broadcast == 0 {
                return;
            }
            if Instant::now() >= deadline {
                // The trio's derived limit holds over a whole mesh. With a
                // session down the stem can dead-end, and the origin is
                // shown at its own embargo fire instead: a Tor session that
                // closed is the public network's, not the relay's fault.
                // That wait is taken once, and the run reports it.
                let reading = if returned {
                    None
                } else {
                    self.read_mesh().await
                };
                let reading = match reading {
                    Some(found) if short.is_none() && !found.whole() => {
                        eprintln!(
                            "tor trio: an origin was unbroadcast at {limit:?} with the mesh \
                             short ({found}); waiting for the miner's embargo fire \
                             ({ORIGIN_RETRY:?})"
                        );
                        deadline = Instant::now() + ORIGIN_RETRY + limit;
                        short = Some(found);
                        continue;
                    }
                    reading => reading,
                };
                panic!(
                    "the posted job did not list the shown pool within {limit:?} \
                     ({broadcast} shown, {unbroadcast} unbroadcast); the relay's fluff \
                     event must mark the entry shown and wake the tip follower \
                     (DRS_X_STORE_FLIP.md Q9){}{}",
                    if returned {
                        String::new()
                    } else {
                        "; on the Tor trio an origin is shown when its fluff comes back".to_owned()
                    },
                    match (&reading, &short) {
                        (Some(now), None) => format!(" (mesh: {now})"),
                        (Some(now), Some(then)) => format!(
                            " (mesh at the limit: {then}; and after the embargo wait: {now})"
                        ),
                        _ => String::new(),
                    }
                );
            }
            if returned {
                let shown = self
                    .rpc
                    .call::<wire::TxpoolList>(NoParams)
                    .await
                    .expect("txpool_list");
                if let Ok(job) = self.rpc.call::<wire::BlockTemplate>(NoParams).await {
                    let listed = shekyl_wire::Block::from_bytes(&job.body.0)
                        .expect("the posted job's body is a block")
                        .transaction_hashes;
                    if listed.len() as u64 == broadcast || job_is_full(&job, &listed, &shown) {
                        return;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// The curve tree at the tip (`curve_show`). `layers` is the tree's
    /// depth (the grammar's rename of `depth`).
    pub(super) async fn curve(&self) -> wire::chain::Curve {
        self.rpc
            .call::<wire::CurveShow>(wire::chain::CurveSelect(Selector::Tip))
            .await
            .expect("curve_show")
    }

    /// `shard_coverage`: the shards a compact join can hold as of the next
    /// connecting height — `ClosedUniverse::final_before` under the in-force
    /// reorg cap, the predicate CEN-J15 applies at the admitting block's
    /// parent (`store_read_facts.rs` `shard_coverage`). The reply also
    /// carries the slash watermark (`settled_epoch`) with the settled
    /// epoch's budget, which is how a caller tells "epoch 0 settled" from
    /// "no pass yet": the wire epoch is 0 in both cases, the budget `null`
    /// only in the second.
    pub(super) async fn shard_coverage(&self) -> wire::archival::Coverage {
        self.rpc
            .call::<wire::ShardCoverage>(NoParams)
            .await
            .expect("shard_coverage")
    }

    /// Stop the daemon and start it again on the same data directory,
    /// ports and rows: the chain it mined is the chain it comes back
    /// with. The stop is the node's own (`daemon_stop`), so the store
    /// closes as it does on an operator's stop, with a kill as the
    /// fallback if the process is still there after 30 s.
    ///
    /// The dialer's tip test is the caller: a restarted node has no
    /// session, reads its tip from the store, and must carry that tip on
    /// its first outbound handshake (`DRS_X_STORE_FLIP.md` DX-Q2 item 5:
    /// the connector publishes the tip once at start).
    pub(super) async fn restart_keeping_chain(&mut self) {
        let height_before = self.height().await;
        // The reply is sent before the node goes; a transport error here
        // means it went first, which is the same outcome.
        drop(self.rpc.call::<wire::DaemonStop>(NoParams).await);
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Ok(None) => {
                    eprintln!("the daemon did not stop on daemon_stop within 30 s; killing it");
                    drop(self.child.kill());
                    drop(self.child.wait());
                    break;
                }
                Err(e) => panic!("waiting for the stopped daemon: {e}"),
            }
        }
        let log = std::fs::File::create(self.data_dir.join("daemon.log")).expect("daemon log");
        let bin = Self::binary();
        let mut cmd = Command::new(&bin);
        cmd.args(&self.recipe)
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .stdin(Stdio::null());
        self.child = shekyl_tor_control_client::spawn_lock::spawn(&mut cmd)
            .unwrap_or_else(|e| panic!("respawn {}: {e}", bin.display()));
        self.await_ready().await;
        let height_after = self.height().await;
        assert_eq!(
            height_after, height_before,
            "the restarted daemon must come back with the chain it stopped on"
        );
    }

    /// Roll the chain back `n` blocks (`dev_chain_pop`, an armed test
    /// lever). Exercises the daemon's `pop_block` deferred-insertion tree
    /// rollback (popping `H` removes the leaves of outputs created at
    /// `H − maturity`).
    pub(super) async fn pop_blocks(&self, n: u64) {
        self.rpc
            .call::<wire::DevChainPop>(wire::block::PopCount { count: Count(n) })
            .await
            .expect("dev_chain_pop");
    }

    /// Whole-chain emission and fee legs of `chain_coinbase_sum`, in
    /// atomic units.
    pub(super) async fn coinbase_tx_sum(&self) -> (u64, u64) {
        let tip = self.status().await.height;
        let sum = self
            .rpc
            .call::<wire::ChainCoinbaseSum>(wire::chain::CoinbaseSumRange {
                from: shekyl_rpc_types::kinds::Height(0),
                to: tip,
            })
            .await
            .expect("chain_coinbase_sum");
        (
            sum.emission.to_atomic_units().to_raw(),
            sum.fee.to_atomic_units().to_raw(),
        )
    }

    /// `chain_spent`, one state per image, in request order. A popped
    /// spend that returned to the pool is `txpool`, not `unspent`.
    pub(super) async fn key_image_statuses(
        &self,
        key_images: &[[u8; 32]],
    ) -> Vec<wire::chain::Spent> {
        let spent = self
            .rpc
            .call::<wire::ChainSpent>(wire::chain::SpentQuery {
                key_image: key_images
                    .iter()
                    .copied()
                    .map(HashHex::from_bytes)
                    .collect(),
            })
            .await
            .expect("chain_spent");
        assert_eq!(
            spent.len(),
            key_images.len(),
            "chain_spent is positional; a short reply is unreadable"
        );
        spent
    }
}

impl Drop for RegtestDaemon {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
        // The unanswered port outlives the process: the recipe's closed
        // peer is this socket until the daemon has exited.
        drop(self.unanswered.take());
        drop(std::fs::remove_dir_all(&self.config_dir));
        // A chain directory of its own is on a filesystem the gate was
        // given for this run; it is emptied whatever the outcome, and the
        // logs, which are the evidence, are not in it.
        if self.chain_dir != self.data_dir {
            drop(std::fs::remove_dir_all(&self.chain_dir));
        }
        // The DX-Q8 capture asks to keep the directory (`start_keeping_data`).
        // A failing test keeps it too: the daemon's logs are the evidence
        // the failure needs, and that is decided here, in the code, not by
        // an environment toggle any run could pick up (#1221). Every other
        // spawn deletes it.
        if self.keep_data || std::thread::panicking() {
            eprintln!("keeping regtest data dir {}", self.data_dir.display());
            return;
        }
        drop(std::fs::remove_dir_all(&self.data_dir));
    }
}

/// The DX-Q8 chain generator.
///
/// Spawns one regtest daemon and leaves its data directory when the daemon
/// is dropped. `scripts/bench/capture_kept_chain.py` opens that directory.
/// The assertion is the keep: if `Drop` deleted the directory, this fails.
/// The directory is the product; remove it when the capture is done. The
/// path is printed as the daemon drops.
///
/// `RegtestDaemon::height` counts the genesis block as 1. That chain is what the
/// column's reads ask for. The generator does not mine past it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "DX-Q8 chain generator: requires SHEKYLD_BIN; keeps the datadir"]
async fn capture_chain_keeps_its_datadir() {
    const GENESIS_CHAIN_HEIGHT: u64 = 1;
    let data_dir = {
        let daemon = RegtestDaemon::start_keeping_data().await;
        let data_dir = daemon.data_dir.clone();
        assert!(
            daemon.height().await >= GENESIS_CHAIN_HEIGHT,
            "a kept chain has a genesis block"
        );
        data_dir
    };
    assert!(
        data_dir.is_dir(),
        "Drop keeps the data directory the capture reads"
    );
}

/// A fresh accept, not `AlreadyInPool` / `AlreadyInChain`. Those also return
/// `Ok`, and either would mean this run proved nothing about the bytes it
/// just built — the daemon would be reporting on something it already had.
///
/// Takes the whole receipt so every real-daemon send also checks the
/// verdict save (A19): an accept the wallet did not save is a failure.
fn require_fresh_accept(receipt: super::submit::SubmitReceipt, what: &str) -> TxHash {
    assert!(
        receipt.verdict_saved,
        "the wallet must save the verdict on {what}"
    );
    match receipt.outcome {
        super::pending::SubmitOutcome::Accepted { hash } => hash,
        other => panic!("the daemon must freshly accept {what}, got {other:?}"),
    }
}

/// Mine one block and assert that block carries `txid`.
///
/// Three observables, three assertions. `generate_blocks` only `.expect`s
/// that the *RPC* succeeded, so on its own it cannot tell a block that
/// carried the spend from a block that excluded it at template time, nor
/// from no block at all.
///
/// The order is load-bearing. Height is checked first so that "no block
/// appeared" fails here and stops; inclusion is checked second so that "a
/// block appeared without the spend" is reported as exactly that. Checking
/// inclusion first would report a missing spend for both faults, which is
/// one assertion wearing two names.
///
/// The pool check is corroborating, never sufficient: the pool also empties
/// when a transaction is *dropped*, so this distinguishes nothing on its
/// own.
async fn assert_tx_confirmed(daemon: &RegtestDaemon, txid: TxHash) -> u64 {
    let before = daemon.height().await;
    let mined = daemon.generate_blocks(1).await;
    let after = daemon.height().await;

    assert_eq!(
        mined.blocks.len(),
        1,
        "dev_block_generate must report the one block it connected, got {:?}",
        mined.blocks
    );
    assert_eq!(
        after,
        before + 1,
        "the chain must advance by exactly one block ({before} -> {after})"
    );

    let carried = daemon.block_tx_hashes(&mined.blocks[0]).await;
    assert!(
        carried.iter().any(|h| h.as_bytes() == txid.as_bytes()),
        "the accepted spend {txid} must be carried by the block that \
         connected at height {after}; that block carries {carried:?}"
    );

    // `dev_block_generate` answers when the connector's tip reaches the
    // target; the tip follower reconciles the pool after that commit, so
    // the pool is read until it drains, within a bound.
    let reconciled = Instant::now() + Duration::from_secs(30);
    loop {
        let size = daemon.tx_pool_size().await;
        if size == 0 {
            break;
        }
        assert!(
            Instant::now() < reconciled,
            "the mined spend must leave the pool: {size} transaction(s) still there 30 s \
             after its block connected"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    eprintln!("spend confirmed in the block that connected at height {after}");
    after
}

/// Opt-in live-oracle capture. Ordinary runs of the north-star gate assert
/// without rewriting a committed fixture; set `SHEKYL_CAPTURE_SPEND_KAT` to
/// regenerate `shekyl-wire`'s `live_oracle_spend_v1.json`.
///
/// Only the bytes and the txid are recorded. Every other identity in the
/// parity legs (the prunable digest, the `serialize_base` framing) is
/// *derived* from these bytes by each language's production code —
/// recording them here as well would let a fixture disagree with itself,
/// and would pin values this test never independently checked.
async fn maybe_capture_live_oracle(
    daemon: &RegtestDaemon,
    tx_bytes: &[u8],
    txid: TxHash,
    connected_at_height: u64,
) {
    if std::env::var_os("SHEKYL_CAPTURE_SPEND_KAT").is_none() {
        return;
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../shekyl-wire/tests/fixtures/live_oracle_spend_v1.json");
    let json = serde_json::json!({
        "description":
            "Live-oracle FCMP++/PQC spend KAT: the exact bytes a running shekyld \
             accepted (consensus verify) and then connected in a block. Sibling to \
             pruned_tx_hash_parity_v1.json, which is hand-built, deterministic and \
             daemon-free and binds Rust to C++; this one binds both to a chain. \
             Neither subsumes the other — do not consolidate them. Regenerate with \
             SHEKYL_CAPTURE_SPEND_KAT=1 and SHEKYLD_BIN set, running \
             engine::regtest_e2e::e2e_fcmp_spend_accepted_by_daemon --ignored.",
        "format_version": 1,
        // The daemon's own version string, read from the node that accepted
        // these bytes — not this crate's version, which says nothing about
        // the binary that did the accepting.
        "accepted_by_daemon_version": daemon.version().await,
        "connected_at_height": connected_at_height,
        "tx_hash_hex": txid.to_string(),
        "tx_hex": hex::encode(tx_bytes),
    });
    std::fs::write(
        &path,
        format!("{}\n", serde_json::to_string_pretty(&json).unwrap()),
    )
    .expect("write live-oracle spend fixture");
    eprintln!("captured live-oracle spend KAT -> {}", path.display());
}

/// Whether the posted job is bounded by the fill policy rather than by the
/// pool: one more of its lightest listed bodies would pass the median, which
/// is where `Fill::admit` stops (the median-fill walk asserts the same bound
/// on the mined block). The sum is of the listed bodies' weights, read from
/// `txpool_list`; the fill also counts the coinbase reserve, which no reply
/// reports. The reserve is a few hundred bytes against spends of about
/// 13 KB, so a job this predicate calls full is one the fill stopped, not
/// one the follower has yet to rebuild.
fn job_is_full(
    job: &wire::block::BlockTemplate,
    listed: &[TxHash],
    pool: &[wire::tx::PoolEntry],
) -> bool {
    let weight_of = |id: &TxHash| {
        pool.iter()
            .find(|entry| entry.id.to_bytes() == id.to_bytes())
            .map_or(0, |entry| entry.weight.0)
    };
    let listed_weight: u64 = listed.iter().map(weight_of).sum();
    let lightest = pool.iter().map(|entry| entry.weight.0).min();
    matches!(lightest, Some(lightest) if listed_weight + lightest > job.weight_median.0)
}

/// Mine `n` blocks (`dev_block_generate`, an armed lever). The daemon pays
/// its configured `mine-address` (N2); the request names no address.
pub(super) async fn try_generate_blocks(
    rpc: &HttpRpc,
    n: u64,
) -> Result<GenerateBlocksResp, shekyl_rpc_client::RpcError> {
    let generated = rpc
        .call::<wire::DevBlockGenerate>(wire::block::GenerateCount { count: Count(n) })
        .await?;
    Ok(GenerateBlocksResp {
        // The chain's count after the blocks: the new tip plus one.
        height: generated.height.0 + 1,
        blocks: generated.hash.iter().map(ToString::to_string).collect(),
    })
}

/// Send the daemon SIGTERM, the operator's stop, and wait for its exit.
#[cfg(unix)]
async fn terminate(daemon: &mut RegtestDaemon) -> std::process::ExitStatus {
    const STOP_WITHIN: Duration = Duration::from_secs(60);
    let pid = daemon.child.id().to_string();
    let sent = shekyl_tor_control_client::spawn_lock::status(
        std::process::Command::new("kill").args(["-TERM", &pid]),
    )
    .expect("run kill");
    assert!(sent.success(), "SIGTERM delivered");
    let deadline = std::time::Instant::now() + STOP_WITHIN;
    loop {
        if let Some(status) = daemon.child.try_wait().expect("wait for the daemon") {
            return status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the daemon did not stop within {STOP_WITHIN:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// **A stop the operator asked for is not a failure:** no line at `error`,
/// no word that the daemon stops on a task's end, and exit 0. The other
/// half of [`full_disk::a_full_disk_stops_the_daemon_with_an_error_line_and_a_failed_exit`]:
/// the node's end watch must stay silent for a task that was asked to
/// stop. The daemon mines first, so the ingest service and the miner have
/// worked.
///
/// The daemon's standard error is read, where every level is written.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; spawns a live daemon"]
async fn a_requested_stop_logs_no_error_and_exits_0() {
    let mut daemon = RegtestDaemon::start().await;
    let mined = daemon.generate_blocks(3).await;
    assert!(
        mined.height >= 3,
        "the daemon mined: height {}",
        mined.height
    );
    let status = terminate(&mut daemon).await;
    let log =
        std::fs::read_to_string(daemon.data_dir.join("daemon.log")).expect("the daemon's log");
    assert!(
        log.contains("stop requested by SIGTERM"),
        "the log does not hold the stop, so it cannot show the stop was clean; its tail:\n{}",
        log_tail(&daemon.data_dir.join("daemon.log"))
    );
    let errors: Vec<&str> = log
        .lines()
        .filter(|line| line.contains(" ERROR ") || line.contains("; the daemon stops"))
        .collect();
    assert!(errors.is_empty(), "a requested stop logged: {errors:#?}");
    assert!(status.success(), "a requested stop exits 0: {status}");
}

/// A stop's last lines reach the log file: the daemon flushes its queued
/// sinks last, after the lock's release, before it exits (`shekyl-logging`'s
/// `flush`; Rick's ruling of 2026-10-17, item 7). "the node closed in …;
/// the daemon exits" is the last line the stop logs (`shekyl-daemon`'s
/// `run.rs`, `finish`; it was the C++ remnant's `Deinitializing core...`
/// until the p2p remnant cutover); SIGTERM is the operator's stop.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; spawns a live daemon"]
async fn a_stops_last_line_reaches_the_log_file() {
    const LAST_LINE: &str = "; the daemon exits";
    let mut daemon = RegtestDaemon::start().await;
    let status = terminate(&mut daemon).await;
    assert!(status.success(), "a requested stop exits 0: {status}");
    let log = std::fs::read_to_string(daemon.data_dir.join("shekyld.log")).expect("the log file");
    assert!(
        log.contains("stop requested by"),
        "the stop's first line is in the log file"
    );
    assert!(
        log.contains(LAST_LINE),
        "the stop's last line is in the log file; its tail:\n{}",
        log.lines().rev().take(10).collect::<Vec<_>>().join("\n")
    );
}

/// Smoke test: the harness spawns a daemon, a fresh wallet's address is mineable,
/// and `dev_block_generate` advances the chain. De-risks the Phase-0 foundation
/// (spawn, RPC, wallet creation, address-format match) before layering the spend
/// path on top.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; spawns a live daemon"]
async fn regtest_daemon_spawns_and_mines_to_wallet_address() {
    use super::lifecycle::{CapabilityInput, Credentials, EngineCreateParams};
    use super::{DaemonClient, Engine, SoloSigner};
    use shekyl_address::Network;
    use shekyl_crypto_pq::account::SEED_BYTES;
    use shekyl_crypto_pq::wallet_envelope::KdfParams;
    use shekyl_engine_file::SafetyOverrides;
    use shekyl_engine_prefs::WalletPrefs;

    let seed = [0x11u8; SEED_BYTES];
    let mine_address = mine_address_from_seed(&seed, Network::Regtest);
    let serial = serial_lock().lock_owned().await;
    let daemon =
        RegtestDaemon::spawn(RegtestSpawn::new(Some(serial)).with_mine_address(mine_address)).await;
    let rpc = HttpRpc::new(format!("http://127.0.0.1:{}", daemon.rpc_port))
        .await
        .expect("wallet rpc");
    let daemon_client = DaemonClient::verifying(rpc, regtest_expectation());

    let tmp = tempfile::tempdir().expect("wallet tempdir");
    let wallet_path = tmp.path().join("wallet");
    let creds = Credentials::password_only(b"track2-test");

    // Regtest is its own network row (`shekyl-network`), so the wallet is
    // created on `Network::Regtest`.
    let params = EngineCreateParams {
        base_path: &wallet_path,
        credentials: &creds,
        network: Network::Regtest,
        capability: CapabilityInput::Full { seed: &seed },
        creation_timestamp: 0,
        restore_height_hint: 0,
        kdf: KdfParams {
            m_log2: 0x08,
            t: 1,
            p: 1,
        },
        overrides: SafetyOverrides::none(),
        prefs: WalletPrefs::default(),
    };
    let wallet = Engine::<SoloSigner>::create(params, daemon_client).expect("create wallet");
    let address = wallet
        .primary_address()
        .encode()
        .expect("encode wallet address");
    eprintln!("wallet address: {address}");

    let before = daemon.height().await;
    let resp = daemon.generate_blocks(3).await;
    let after = daemon.height().await;
    eprintln!(
        "height {before} -> {after}; dev_block_generate returned height={}, {} blocks",
        resp.height,
        resp.blocks.len()
    );

    assert_eq!(
        resp.blocks.len(),
        3,
        "dev_block_generate should return 3 hashes"
    );
    assert!(after >= before + 3, "chain should advance by >= 3 blocks");
}

/// The armed switch (`RPC_CHANNEL.md` §6.1, RT-O36). On regtest, the one
/// network whose row permits `dev-rpc` (NI-R8; a testnet daemon given it is
/// refused at load, `dev_rpc_is_refused_on_every_network_but_regtest`),
/// `dev_block_generate` and `dev_chain_pop` pass the armed gate and are
/// served. The third lever the C++ served, `inject_archival_serve_credit`,
/// was deleted with the C++ chain (`DRS_X_STORE_FLIP.md` DX-Q3): the daemon
/// knows no such method, armed or not.
///
/// Zero blocks keeps the probes cheap: the claim is about admission, not
/// mining. A gate refusal would be the grant class (-32002); what is
/// asserted is the handler's own answer, after the gate:
/// `dev_block_generate` refuses a zero count as `BadParams` (-32602) with
/// the diagnostic `block.count-zero`, before it reads the node's mining
/// refusal, so the answer is the same on a daemon that is not synced or has
/// no mine address (`mining_methods::dev_block_generate`).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; spawns a live daemon"]
async fn the_armed_switch_serves_two_levers_and_knows_no_third() {
    use shekyl_rpc_client::ErrorClass;
    let daemon = RegtestDaemon::start().await;

    let generated = daemon
        .rpc
        .call_or_refusal::<wire::DevBlockGenerate>(wire::block::GenerateCount { count: Count(0) })
        .await
        .expect("dev_block_generate answers");
    let refusal = generated.expect_err("a zero count is refused");
    assert_eq!(
        refusal.class,
        ErrorClass::BadParams,
        "dev_block_generate is served on armed regtest and refuses a zero count as its own \
         BadParams: {refusal:?}"
    );
    assert_eq!(refusal.diagnostic.code, "block.count-zero", "{refusal:?}");

    daemon
        .rpc
        .call::<wire::DevChainPop>(wire::block::PopCount { count: Count(0) })
        .await
        .expect("dev_chain_pop is served on armed regtest");

    // The deleted lever, by its old name: no method, not a gate refusal.
    let injected = raw_call(
        &daemon.rpc,
        "inject_archival_serve_credit",
        json!({ "persona": "11".repeat(32), "shard": 0, "epoch": 0 }),
    )
    .await;
    assert!(
        shekyl_rpc_types::errors::is_method_not_found(&injected["error"]),
        "the deleted lever is unknown to the daemon, not gated: {injected}"
    );
}

/// One JSON-RPC request by a name this build's table does not hold — an
/// old or deleted name a test probes — returning the reply envelope whole.
pub(super) async fn raw_call(
    rpc: &HttpRpc,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    let body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0", "id": 0, "method": method, "params": params,
    }))
    .expect("a request encodes");
    let reply = rpc
        .post(shekyl_rpc_client::json_rpc_route(), body)
        .await
        .unwrap_or_else(|e| panic!("{method}: {e:?}"));
    serde_json::from_slice(&reply).unwrap_or_else(|e| panic!("{method} reply: {e}"))
}

/// Acceptance gate for the §8 step-4 scanner migration (shekyl-oxide → shekyl-wire
/// block/tx parse). Mine coinbase blocks to the wallet's own address, drive the
/// production [`Engine::start_refresh`] against the live daemon, and assert the
/// wallet reflects a real, matured (unlocked) coinbase balance.
///
/// This is the *refresh half* of [`e2e_fcmp_spend_accepted_by_daemon`], isolated so
/// it can pass independently of the (separate) tx-builder→shekyl-wire format work the
/// spend half still needs. Run before this migration, `start_refresh` failed at block
/// fetch with `RpcError::InvalidNode("invalid block")`: the legacy shekyl-oxide parse
/// dropped the coinbase `Null` committed base, so live daemon blocks would not
/// deserialize. Routing the fetch through the daemon-KAT'd shekyl-wire parse
/// (`DaemonEngine::fetch_scannable_block`) is what makes this green.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; spawns a live daemon"]
async fn e2e_refresh_scans_coinbase_balance() {
    use super::refresh::RefreshOptions;
    use super::{DaemonClient, Engine, SoloSigner};
    use shekyl_scanner::WalletLedgerExt;
    use shekyl_units::AtomicUnits;

    let seed = [0x44u8; shekyl_crypto_pq::account::SEED_BYTES];
    let daemon = RegtestDaemon::start_for_seed(&seed).await;

    // Create the wallet (FAKECHAIN = mainnet address format; see the get_curve_tree test).
    let rpc = HttpRpc::new(format!("http://127.0.0.1:{}", daemon.rpc_port))
        .await
        .expect("wallet rpc");
    let tmp = tempfile::tempdir().expect("wallet tempdir");
    let wallet_path = tmp.path().join("wallet");
    let creds = super::lifecycle::Credentials::password_only(b"track2-refresh");
    let params = super::lifecycle::EngineCreateParams {
        base_path: &wallet_path,
        credentials: &creds,
        network: shekyl_address::Network::Regtest,
        capability: super::lifecycle::CapabilityInput::Full { seed: &seed },
        creation_timestamp: 0,
        restore_height_hint: 0,
        kdf: shekyl_crypto_pq::wallet_envelope::KdfParams {
            m_log2: 0x08,
            t: 1,
            p: 1,
        },
        overrides: shekyl_engine_file::SafetyOverrides::none(),
        prefs: shekyl_engine_prefs::WalletPrefs::default(),
    };
    let wallet =
        Engine::<SoloSigner>::create(params, DaemonClient::verifying(rpc, regtest_expectation()))
            .expect("create wallet");

    // Mine in batches past coinbase maturity, refreshing after each batch. The
    // `.expect("start_refresh")` / `.expect("refresh joins")` below are the load-bearing
    // assertions for this gate: that is where the pre-migration `InvalidNode` surfaced.
    const MINE_BATCH_BLOCKS: u64 = 10;
    const MAX_MINE_BATCHES: usize = 24; // ~240 blocks; well past the coinbase unlock window

    let arc = Arc::new(RwLock::new(wallet));
    let mut unlocked = AtomicUnits::ZERO;
    let mut total_height = 0u64;
    for _ in 0..MAX_MINE_BATCHES {
        daemon.generate_blocks(MINE_BATCH_BLOCKS).await;
        Engine::start_refresh(arc.clone(), RefreshOptions::default())
            .await
            .expect("start_refresh")
            .join()
            .await
            .expect("refresh joins");
        {
            let g = arc.read().await;
            let ledger = g.ledger();
            total_height = ledger.ledger.height().to_raw();
            unlocked = ledger
                .balance_at(shekyl_types::BlockHeight::from_raw(total_height))
                .unlocked;
        }
        if unlocked > AtomicUnits::ZERO {
            break;
        }
    }

    assert!(
        unlocked > AtomicUnits::ZERO,
        "wallet must reflect a matured coinbase balance after mining + refresh \
         (was InvalidNode pre-migration); got {unlocked:?} at height {total_height}"
    );
    eprintln!("scanned unlocked coinbase balance: {unlocked:?} at height {total_height}");
}

/// The §1.1 closure: a real FCMP++ spend built by the production Engine, submitted to a
/// live shekyld, and accepted by its consensus verify. submit_pending_tx returning Ok is
/// the proof — the daemon's mempool verify ran the FCMP++ membership/SAL proof, the PQC
/// auths, and the CT balance against the wallet-built, wire-serialized spend. This is the
/// live oracle the spec (FCMP_SPEND_SIGNING_PREIMAGE.md §5) names as the residual: it
/// validates the tx-builder→shekyl-wire serialization + PQC signing-preimage byte-for-byte
/// against the C++ daemon (no other test crosses the wallet→daemon spend boundary).
///
/// NORTH STAR (gated) — committed as the acceptance gate for the end-to-end
/// wallet→daemon spend: open (from disk, via an explicit close → `open_full`) →
/// refresh → build → submit → confirm, so the arc starts where every production
/// spend session starts. The two migrations it once waited on have both landed: (1)
/// the §8 step-4 scanner block-parsing migration onto the daemon-KAT'd `shekyl-wire`
/// parser, and (2) the tx-builder→`shekyl-wire` spend-format migration (the
/// `shekyl-oxide` serializers that originally diverged are dissolved). It remains
/// `#[ignore]`d on the live-daemon harness (`SHEKYLD_BIN` + a running regtest
/// daemon). CI provides that binary in the live-daemon gates step and runs this
/// test there; a local run still needs `SHEKYLD_BIN`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Track-2 north-star spend gate; needs SHEKYLD_BIN + a running regtest daemon (the scanner/tx-builder shekyl-wire migrations have landed)"]
async fn e2e_fcmp_spend_accepted_by_daemon() {
    use super::pending::{FeePriority, TxDestination, TxRecipient, TxRequest};
    use super::refresh::RefreshOptions;
    use super::{DaemonClient, Engine, SoloSigner};
    use shekyl_scanner::WalletLedgerExt;
    use shekyl_units::AtomicUnits;

    let seed = [0x33u8; shekyl_crypto_pq::account::SEED_BYTES];
    let daemon = RegtestDaemon::start_for_seed(&seed).await;

    // Create the wallet (FAKECHAIN = mainnet address format; see the get_curve_tree
    // test), close it, and reopen from disk — the same shape as `staker_wallet`. The
    // arc this gate carries is open → refresh → build → submit → confirm: a spend from
    // the still-in-memory created engine would skip the open path (envelope decrypt,
    // ledger load, scan-state restore) that every production spend session starts from.
    let creds = super::lifecycle::Credentials::password_only(b"track2-spend");
    let (created, tmp) = create_wallet(daemon.rpc_port, &seed, b"track2-spend").await;
    let wallet_path = tmp.path().join("wallet");
    created.close(&creds).await.expect("close created wallet");

    let rpc = HttpRpc::new(format!("http://127.0.0.1:{}", daemon.rpc_port))
        .await
        .expect("wallet rpc (reopen)");
    let wallet = Engine::<SoloSigner>::open_full(
        &wallet_path,
        &creds,
        shekyl_address::Network::Regtest,
        DaemonClient::verifying(rpc, regtest_expectation()),
        shekyl_engine_file::SafetyOverrides::none(),
    )
    .expect("reopen wallet from disk")
    .into_wallet();
    let address = wallet.primary_address().encode().expect("encode address");

    // Fund: mine in batches past coinbase maturity + tree drain so an output is spendable.
    const MINE_BATCH_BLOCKS: u64 = 10;
    const MAX_MINE_BATCHES: usize = 24;

    // refresh + balance + build + submit go through Arc<RwLock<Engine>> (start_refresh
    // owns the wallet for the async scan).
    let arc = Arc::new(RwLock::new(wallet));
    let mut unlocked = AtomicUnits::ZERO;
    for _ in 0..MAX_MINE_BATCHES {
        daemon.generate_blocks(MINE_BATCH_BLOCKS).await;
        Engine::start_refresh(arc.clone(), RefreshOptions::default())
            .await
            .expect("start_refresh")
            .join()
            .await
            .expect("refresh joins");
        unlocked = {
            let g = arc.read().await;
            let ledger = g.ledger();
            ledger.balance().unlocked
        };
        if unlocked > AtomicUnits::ZERO {
            break;
        }
    }
    assert!(
        unlocked > AtomicUnits::ZERO,
        "a matured coinbase must be spendable after mining + refresh; got {unlocked:?}"
    );
    eprintln!("spendable balance: {unlocked:?}");

    // Build a real FCMP++ spend (self-send half the balance; the engine adds change + fee).
    let request = TxRequest {
        recipients: vec![TxRecipient {
            destination: TxDestination::Address(address.clone()),
            amount_atomic_units: AtomicUnits::from_raw(unlocked.to_raw() / 2),
            rid: None,
        }],
        priority: FeePriority::Standard,
    };

    // The output is spendable at the TIP (`unlocked > 0`), but the FCMP++ spend
    // selects against the REFERENCE block (tip − REF_ANCHOR_AGE) and the selected
    // output must be spendable THERE — which lags tip-maturity by a few blocks.
    // Build until the C2 reference-spendability gate clears (OutputNotYetSpendable
    // ⇒ mine more so the reference catches up).
    let mut pending = None;
    for _ in 0..MAX_MINE_BATCHES {
        let attempt = {
            // Build/submit take `&self` — use a read guard so the harness
            // matches production wallet-RPC locking and cannot mask
            // exclusive-lock regressions.
            let g = arc.read().await;
            g.build_pending_tx(&request).await
        };
        match attempt {
            Ok(p) => {
                pending = Some(p);
                break;
            }
            Err(super::error::SendError::OutputNotYetSpendable { wait_blocks, .. }) => {
                eprintln!("output not reference-spendable yet ({wait_blocks} blocks); mining more");
                daemon.generate_blocks(MINE_BATCH_BLOCKS).await;
                Engine::start_refresh(arc.clone(), RefreshOptions::default())
                    .await
                    .expect("start_refresh")
                    .join()
                    .await
                    .expect("refresh joins");
            }
            Err(e) => panic!("build pending FCMP++ spend: {e:?}"),
        }
    }
    let pending = pending.expect("FCMP++ spend must build once the output is reference-spendable");
    eprintln!(
        "built spend: fee={:?}, tx_bytes={} B",
        pending.fee_atomic_units,
        pending.tx_bytes.len()
    );
    assert!(
        !pending.tx_bytes.is_empty(),
        "spend must serialize to bytes"
    );

    // Submit to the live daemon. Ok == the daemon's consensus verify ACCEPTED the spend
    // (FCMP++ proof + PQC auths + CT balance + wire format). This is the §1.1 proof.
    let outcome = {
        let g = arc.read().await;
        g.submit_pending_tx(pending.id, pending.content_gen)
            .await
            .expect("daemon must accept the FCMP++ spend (consensus verify)")
    };
    let accepted = require_fresh_accept(outcome, "the FCMP++ spend");
    eprintln!("daemon accepted spend: {accepted}");

    let after = assert_tx_confirmed(&daemon, accepted).await;
    maybe_capture_live_oracle(&daemon, &pending.tx_bytes, accepted, after).await;
    // The shape is read off the transaction, not assumed: a self-send of half
    // the balance is 1-in with a recipient AND a change output.
    let outputs = shekyl_wire::Transaction::from_bytes(&pending.tx_bytes)
        .expect("the accepted spend parses")
        .prefix
        .outputs
        .len();
    maybe_capture_chain_vector(
        &daemon,
        &format!("spend-1in-{outputs}out"),
        "e2e_fcmp_spend_accepted_by_daemon",
        Some(accepted),
    )
    .await;
}

/// A daemon-accepted user spend, mined, popped, and mined again.
///
/// This bites the live daemon across one tx-conserving pop: the spend's
/// key images go 1 (in a block) → 2 (back in the pool) → 1, and
/// `chain_coinbase_sum`'s fee leg moves by the spend's `txnFee` and
/// back. It does NOT cover the image going free (that needs a pool
/// flush), an integer-overflow amount, an alt-chain split, E2 grading,
/// or the Rust validator. Those census rows are still `pending`; this
/// test is the holder they can cite, not their implementation.
///
/// It also does not assert pool-spent *before* the first mine.
/// `chain_spent` reports a pool image only for
/// `relay_category::broadcasted` (`tx_pool::check_for_key_images`). A
/// wallet submit lands at `relay_method::local` until the fire-and-forget
/// relay nudge promotes it, so that status races. A pop puts the spend
/// back with `relay_method::block`, which is broadcast-visible, and that
/// is the status this test checks.
///
/// The north-star test stops at "mined into a block". The disabled
/// chaingen chain-switch / block-reward regime is what this replaces
/// for one pop.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; spawns a live daemon"]
async fn e2e_fcmp_spend_reorg_restores_pool_and_fee() {
    use super::pending::{FeePriority, TxDestination, TxRecipient, TxRequest};
    use super::refresh::RefreshOptions;
    use super::{DaemonClient, Engine, SoloSigner};
    use shekyl_rpc_types::wire::chain::Spent;
    use shekyl_scanner::WalletLedgerExt;
    use shekyl_units::AtomicUnits;
    use shekyl_wire::{Input, Transaction};

    let seed = [0x35u8; shekyl_crypto_pq::account::SEED_BYTES];
    let daemon = RegtestDaemon::start_for_seed(&seed).await;
    let creds = super::lifecycle::Credentials::password_only(b"track2-spend-reorg");
    let (created, tmp) = create_wallet(daemon.rpc_port, &seed, b"track2-spend-reorg").await;
    let wallet_path = tmp.path().join("wallet");
    created.close(&creds).await.expect("close created wallet");

    let rpc = HttpRpc::new(format!("http://127.0.0.1:{}", daemon.rpc_port))
        .await
        .expect("wallet rpc (reopen)");
    let wallet = Engine::<SoloSigner>::open_full(
        &wallet_path,
        &creds,
        shekyl_address::Network::Regtest,
        DaemonClient::verifying(rpc, regtest_expectation()),
        shekyl_engine_file::SafetyOverrides::none(),
    )
    .expect("reopen wallet from disk")
    .into_wallet();
    let address = wallet.primary_address().encode().expect("encode address");

    const MINE_BATCH_BLOCKS: u64 = 10;
    const MAX_MINE_BATCHES: usize = 24;

    let arc = Arc::new(RwLock::new(wallet));
    let mut unlocked = AtomicUnits::ZERO;
    for _ in 0..MAX_MINE_BATCHES {
        daemon.generate_blocks(MINE_BATCH_BLOCKS).await;
        Engine::start_refresh(arc.clone(), RefreshOptions::default())
            .await
            .expect("start_refresh")
            .join()
            .await
            .expect("refresh joins");
        unlocked = {
            let g = arc.read().await;
            let ledger = g.ledger();
            ledger.balance().unlocked
        };
        if unlocked > AtomicUnits::ZERO {
            break;
        }
    }
    assert!(
        unlocked > AtomicUnits::ZERO,
        "a matured coinbase must be spendable after mining + refresh; got {unlocked:?}"
    );

    let request = TxRequest {
        recipients: vec![TxRecipient {
            destination: TxDestination::Address(address.clone()),
            amount_atomic_units: AtomicUnits::from_raw(unlocked.to_raw() / 2),
            rid: None,
        }],
        priority: FeePriority::Standard,
    };

    let mut pending = None;
    for _ in 0..MAX_MINE_BATCHES {
        let attempt = {
            let g = arc.read().await;
            g.build_pending_tx(&request).await
        };
        match attempt {
            Ok(p) => {
                pending = Some(p);
                break;
            }
            Err(super::error::SendError::OutputNotYetSpendable { wait_blocks, .. }) => {
                eprintln!("output not reference-spendable yet ({wait_blocks} blocks); mining more");
                daemon.generate_blocks(MINE_BATCH_BLOCKS).await;
                Engine::start_refresh(arc.clone(), RefreshOptions::default())
                    .await
                    .expect("start_refresh")
                    .join()
                    .await
                    .expect("refresh joins");
            }
            Err(e) => panic!("build pending FCMP++ spend: {e:?}"),
        }
    }
    let pending = pending.expect("FCMP++ spend must build once the output is reference-spendable");

    let txn_fee = pending.fee_atomic_units.to_raw();
    assert!(
        txn_fee > 0,
        "a zero fee cannot move the fee leg, so this test would be green by construction"
    );
    let key_images: Vec<[u8; 32]> = Transaction::from_bytes(&pending.tx_bytes)
        .expect("the built spend must parse")
        .prefix
        .inputs
        .iter()
        .filter_map(|input| match input {
            Input::ToKey { key_image, .. } => Some(*key_image),
            _ => None,
        })
        .collect();
    assert!(
        !key_images.is_empty(),
        "the spend must publish a key image; without one the status checks have no subject"
    );

    let outcome = {
        let g = arc.read().await;
        g.submit_pending_tx(pending.id, pending.content_gen)
            .await
            .expect("daemon must accept the FCMP++ spend")
    };
    let accepted = require_fresh_accept(outcome, "the FCMP++ spend");

    let (emission_before, fee_before) = daemon.coinbase_tx_sum().await;
    let height_before = daemon.height().await;

    let height_mined = assert_tx_confirmed(&daemon, accepted).await;
    assert_eq!(height_mined, height_before + 1);
    assert_eq!(
        daemon.key_image_statuses(&key_images).await,
        vec![Spent::Chain; key_images.len()],
        "mining the spend must move its key images from the pool into the chain"
    );
    let (emission_mined, fee_mined) = daemon.coinbase_tx_sum().await;
    assert_eq!(
        fee_mined,
        fee_before + txn_fee,
        "the mined block's fee leg must grow by the spend's txnFee"
    );
    assert_ne!(
        emission_mined, emission_before,
        "connecting a block must move the emission leg; a sum that ignores the new coinbase is not this check"
    );

    daemon.pop_blocks(1).await;
    assert_eq!(
        daemon.height().await,
        height_before,
        "popping the spend's block must return the chain to the pre-mine height"
    );
    assert_eq!(
        daemon.tx_pool_size().await,
        1,
        "a tx-conserving pop must return the spend to the pool"
    );
    assert_eq!(
        daemon.key_image_statuses(&key_images).await,
        vec![Spent::Txpool; key_images.len()],
        "the popped spend is back in the pool, so its key images stay reserved (status 2, not free)"
    );
    let (emission_popped, fee_popped) = daemon.coinbase_tx_sum().await;
    assert_eq!(
        (emission_popped, fee_popped),
        (emission_before, fee_before),
        "popping the spend's block must restore both coinbase-sum legs"
    );

    daemon.generate_blocks(1).await;
    assert_eq!(daemon.height().await, height_mined);
    assert_eq!(
        daemon.tx_pool_size().await,
        0,
        "re-mining must take the spend back out of the pool"
    );
    assert_eq!(
        daemon.key_image_statuses(&key_images).await,
        vec![Spent::Chain; key_images.len()],
        "re-mining the spend must mark its key images spent in the chain again"
    );
    let (emission_remined, fee_remined) = daemon.coinbase_tx_sum().await;
    assert_eq!(
        (emission_remined, fee_remined),
        (emission_mined, fee_mined),
        "re-mining the same spend must restore both coinbase-sum legs"
    );
}

/// Regtest [`EngineCreateParams`](super::lifecycle::EngineCreateParams) for
/// the regtest wallets; the KDF is the minimum-wall-clock relaxation the
/// wallet-file tests share.
fn regtest_params<'a>(
    base_path: &'a std::path::Path,
    creds: &'a super::lifecycle::Credentials<'a>,
    seed: &'a [u8; shekyl_crypto_pq::account::SEED_BYTES],
) -> super::lifecycle::EngineCreateParams<'a> {
    super::lifecycle::EngineCreateParams {
        base_path,
        credentials: creds,
        network: shekyl_address::Network::Regtest,
        capability: super::lifecycle::CapabilityInput::Full { seed },
        creation_timestamp: 0,
        restore_height_hint: 0,
        kdf: shekyl_crypto_pq::wallet_envelope::KdfParams {
            m_log2: 0x08,
            t: 1,
            p: 1,
        },
        overrides: shekyl_engine_file::SafetyOverrides::none(),
        prefs: shekyl_engine_prefs::WalletPrefs::default(),
    }
}

/// Create a Mainnet wallet (FAKECHAIN uses the mainnet address format) pointed at
/// the daemon RPC. Returns the engine, its tempdir (caller keeps it alive — it owns
/// the wallet files), and the encoded primary address.
async fn mainnet_wallet(
    rpc_port: u16,
    seed_byte: u8,
) -> (super::Engine<super::SoloSigner>, tempfile::TempDir, String) {
    let seed = [seed_byte; shekyl_crypto_pq::account::SEED_BYTES];
    let (wallet, tmp) = create_wallet(rpc_port, &seed, b"track2").await;
    let address = wallet.primary_address().encode().expect("encode address");
    (wallet, tmp, address)
}

/// The shared create step behind [`mainnet_wallet`] and [`staker_wallet`]:
/// tempdir, credentials, wallet RPC against the daemon port, and
/// `Engine::create` over [`regtest_params`]. Callers layer their own
/// follow-ons (address derivation; the staker's persist → close → reopen).
/// The wallet base path is `tmp.path().join("wallet")`.
async fn create_wallet(
    rpc_port: u16,
    seed: &[u8; shekyl_crypto_pq::account::SEED_BYTES],
    password: &'static [u8],
) -> (super::Engine<super::SoloSigner>, tempfile::TempDir) {
    let rpc = HttpRpc::new(format!("http://127.0.0.1:{rpc_port}"))
        .await
        .expect("wallet rpc");
    let tmp = tempfile::tempdir().expect("wallet tempdir");
    let wallet_path = tmp.path().join("wallet");
    let creds = super::lifecycle::Credentials::password_only(password);
    let params = regtest_params(&wallet_path, &creds, seed);
    let wallet = super::Engine::<super::SoloSigner>::create(
        params,
        super::DaemonClient::verifying(rpc, regtest_expectation()),
    )
    .expect("create wallet");
    (wallet, tmp)
}

/// Depth-3+ FCMP++ verify (CT-5 / #162 reopening trigger). The partial-branch-chunk
/// fix and CT-2 Tier-A both cover only **depth-2** (a single Helios branch). This
/// grows the curve tree past depth-2 — to a real **Selene** branch layer — and
/// proves a wallet-built spend over it is accepted by the daemon's consensus verify.
///
/// Drives by the daemon's **observed tree depth** (`curve_show.layers`,
/// which is `fcmp_layers - 1`, so depth-3 = daemon depth 2), not a hardcoded
/// height: depth-3 needs `SELENE_CHUNK_WIDTH × HELIOS_CHUNK_WIDTH = 38 × 18`… in
/// practice ~684–701 drained leaves (~750 blocks, several minutes — a slow gate).
///
/// **Validates the depth-3 fix (was the #162 reopening trigger).** Before the
/// `db_lmdb::grow_curve_tree` → `shekyl_curve_tree_grow_upper_layers` rewiring, the
/// wallet `refresh` at depth-3 died with `CurveTreeIngest: curve-tree root mismatch
/// vs header`: the daemon's in-place incremental upper-layer deepening dropped the
/// pre-existing sibling when it created the first layer-2 Selene root, so its header
/// root diverged from the wallet's narrow `build_layers`. With the producer-side fix
/// the daemon recomposes every upper layer narrow (== `build_layers`), so the
/// refresh succeeds and a spend over the depth-3 tree is daemon-accepted. (Confirmed
/// 2026-06-27 against a locally-built fixed `shekyld`: daemon depth 2 / 701 leaves,
/// refresh OK, spend accepted.)
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; slow (~750 blocks, several min)"]
async fn e2e_fcmp_spend_over_depth3_tree() {
    use super::pending::{FeePriority, TxDestination, TxRecipient, TxRequest};
    use super::refresh::RefreshOptions;
    use super::Engine;
    use shekyl_scanner::WalletLedgerExt;
    use shekyl_units::AtomicUnits;

    // The daemon's `get_curve_tree_depth` reports `fcmp_layers − 1`
    // (`blockchain.cpp`: `fcmp_layers = depth + 1`). A 3-layer tree — leaf Selene +
    // Helios branch + a real **Selene** branch (the #162 "depth-3+" target) — is
    // therefore daemon depth **2**, reached only at
    // `SELENE_CHUNK_WIDTH × HELIOS_CHUNK_WIDTH = 38 × 18 = 684` drained leaves
    // (~684 + COINBASE_LOCK blocks). This is intentionally a **slow** gate
    // (~750 blocks, several minutes); in-process depth-3 is already covered by
    // `shekyl-wire`'s `fcmp_spend_e2e` (a 700-output depth-3 tree). Daemon depth 1
    // (one Helios branch, the #162 "depth-2") is exercised by the keystone.
    const TARGET_DAEMON_DEPTH: u8 = 2; // = fcmp_layers 3 (a Selene branch layer)
    const MINE_BATCH_BLOCKS: u64 = 20;
    const MAX_MINE_BATCHES: usize = 60; // up to 1200 blocks (684 leaves ≈ 745)

    let daemon =
        RegtestDaemon::start_for_seed(&[0x44u8; shekyl_crypto_pq::account::SEED_BYTES]).await;
    let (wallet, _tmp, address) = mainnet_wallet(daemon.rpc_port, 0x44).await;

    // Mine (no refresh needed — depth is the daemon's, not the wallet's) until the
    // tree reaches the target depth, then one more batch so the REFERENCE block
    // (tip − REF_ANCHOR_AGE) the spend selects against is also past the transition.
    let mut tree_depth = 0u8;
    for _ in 0..MAX_MINE_BATCHES {
        daemon.generate_blocks(MINE_BATCH_BLOCKS).await;
        let info = daemon.curve().await;
        tree_depth = u8::try_from(info.layers.0).unwrap_or(u8::MAX);
        if tree_depth >= TARGET_DAEMON_DEPTH {
            eprintln!(
                "curve tree reached daemon depth {tree_depth} (= {} layers): {info:?}",
                tree_depth + 1
            );
            break;
        }
    }
    assert!(
        tree_depth >= TARGET_DAEMON_DEPTH,
        "curve tree must reach daemon depth >= {TARGET_DAEMON_DEPTH} ({} layers); got {tree_depth}",
        TARGET_DAEMON_DEPTH + 1
    );
    daemon.generate_blocks(MINE_BATCH_BLOCKS).await;

    // Refresh so the wallet's local tree matches the daemon's depth-3 tree.
    let arc = Arc::new(RwLock::new(wallet));
    Engine::start_refresh(arc.clone(), RefreshOptions::default())
        .await
        .expect("start_refresh")
        .join()
        .await
        .expect("refresh joins");
    let unlocked = {
        let g = arc.read().await;
        let ledger = g.ledger();
        ledger.balance().unlocked
    };
    assert!(
        unlocked > AtomicUnits::ZERO,
        "a matured coinbase must be spendable over the depth-3 tree; got {unlocked:?}"
    );
    eprintln!("spendable balance over depth-{tree_depth} tree: {unlocked:?}");

    // Build + submit an FCMP++ spend over the depth-3 tree (retry until the C2
    // reference-spendability gate clears). A depth-3 tree here holds ~700 small
    // coinbase outputs, so a large self-send would select more inputs than
    // FCMP_MAX_INPUTS (8). Spend a small amount so the input count stays bounded —
    // the spend AMOUNT is irrelevant to what this gate validates (a daemon-accepted
    // spend over a depth-3 tree); the depth is.
    // `unlocked` is far above the fee/dust floor (a depth-2+ tree means ~700 matured
    // coinbase outputs), so /500 is non-zero in practice; assert it so a degenerate
    // 0-amount request can never silently fail for a reason unrelated to the depth-3
    // gate. (Clamping to 1 au instead, as suggested, would build an invalid sub-fee
    // spend.)
    let spend_amount = unlocked.to_raw() / 500;
    assert!(
        spend_amount > 0,
        "depth-3 tree must yield a non-trivial spendable balance; got unlocked={unlocked:?}"
    );
    let request = TxRequest {
        recipients: vec![TxRecipient {
            destination: TxDestination::Address(address.clone()),
            amount_atomic_units: AtomicUnits::from_raw(spend_amount),
            rid: None,
        }],
        priority: FeePriority::Standard,
    };
    let mut pending = None;
    for _ in 0..MAX_MINE_BATCHES {
        let attempt = {
            let g = arc.read().await;
            g.build_pending_tx(&request).await
        };
        match attempt {
            Ok(p) => {
                pending = Some(p);
                break;
            }
            Err(super::error::SendError::OutputNotYetSpendable { .. }) => {
                daemon.generate_blocks(MINE_BATCH_BLOCKS).await;
                Engine::start_refresh(arc.clone(), RefreshOptions::default())
                    .await
                    .expect("start_refresh")
                    .join()
                    .await
                    .expect("refresh joins");
            }
            Err(e) => panic!("build pending FCMP++ spend over depth-3 tree: {e:?}"),
        }
    }
    let pending = pending.expect("FCMP++ spend must build over the depth-3 tree");
    eprintln!(
        "built depth-{tree_depth} spend: fee={:?}, tx_bytes={} B",
        pending.fee_atomic_units,
        pending.tx_bytes.len()
    );

    let outcome = {
        let g = arc.read().await;
        g.submit_pending_tx(pending.id, pending.content_gen)
            .await
            .expect("daemon must accept the FCMP++ spend over a depth-3 tree (consensus verify)")
    };
    let accepted = require_fresh_accept(outcome, "the FCMP++ spend over a depth-3 tree");
    eprintln!("daemon accepted depth-{tree_depth} spend: {accepted}");
    assert_tx_confirmed(&daemon, accepted).await;
    maybe_capture_chain_vector(
        &daemon,
        "spend-depth3",
        "e2e_fcmp_spend_over_depth3_tree",
        Some(accepted),
    )
    .await;
}

/// What [`overfill_pool`] left: the C++'s `(M, 2·M)` in force and the
/// weight of every spend it put in the pool, in submission order.
struct Overfilled {
    /// The C++'s effective median in force for the next block.
    median: u64,
    /// The C++'s consensus limit for it — `2 · M`
    /// (`blockchain.cpp:6099`), read back from `daemon_status`.
    limit: u64,
    /// Each pool spend's wire weight (`Transaction::weight`).
    weights: Vec<u64>,
}

/// Mine a wallet enough matured coinbases, then build and submit one-input
/// spends without mining between them until the pool's weight exceeds the
/// C++'s consensus limit with a margin of spends — so whatever bounds a
/// block built from that pool is a bound, never the pool running dry. Each
/// build reserves its inputs (F14's lock), so the next picks other
/// outputs; a spend of a small fixed amount takes one input (≈ 13.2 KB,
/// the I4 measurement).
///
/// Asserts the regime it leaves the daemon in: a young, light chain, so
/// the effective median is the zone (the floor arm) and the limit twice
/// it.
async fn overfill_pool(
    daemon: &RegtestDaemon,
    arc: &Arc<RwLock<super::Engine<super::SoloSigner>>>,
    address: &str,
) -> Overfilled {
    use super::pending::{FeePriority, TxDestination, TxRecipient, TxRequest};
    use shekyl_economics::FULL_REWARD_ZONE;
    use shekyl_units::AtomicUnits;
    use shekyl_wire::Transaction;

    const MINE_BATCH_BLOCKS: u64 = 10;
    const MAX_MINE_BATCHES: usize = 24;
    /// Matured coinbase outputs to spend, one per pool transaction — more
    /// than the ≈ 45 that fill a limit of twice the zone at ≈ 13.2 KB
    /// each.
    const POOL_SPENDS: usize = 60;

    // Enough matured coinbases to spend one per transaction: the unlock
    // window, then `POOL_SPENDS` more blocks, then the window again so the
    // last of them has matured too.
    mine_until_spendable(daemon, arc, MINE_BATCH_BLOCKS, MAX_MINE_BATCHES).await;
    let extra = u64::try_from(POOL_SPENDS).expect("fits") + MINE_BATCH_BLOCKS * 8;
    daemon.generate_blocks(extra).await;
    refresh(arc).await;

    let (median, limit) = daemon.weight_limit().await;
    assert_eq!(
        median, FULL_REWARD_ZONE,
        "a young, light chain's effective median is the zone (the floor arm)"
    );
    assert_eq!(limit, 2 * median, "the C++'s limit is twice its median");
    eprintln!("C++ weight limit in force: {limit} (median {median})");

    let mut pool_weight = 0u64;
    let mut weights: Vec<u64> = Vec::new();
    for n in 0..POOL_SPENDS {
        let request = TxRequest {
            recipients: vec![TxRecipient {
                destination: TxDestination::Address(address.to_owned()),
                amount_atomic_units: AtomicUnits::from_raw(1_000_000),
                rid: None,
            }],
            priority: FeePriority::Standard,
        };
        let pending = {
            let g = arc.read().await;
            g.build_pending_tx(&request)
                .await
                .unwrap_or_else(|e| panic!("build pool spend {n}: {e:?}"))
        };
        let weight = u64::try_from(
            Transaction::from_bytes(&pending.tx_bytes)
                .expect("a built spend parses")
                .weight(),
        )
        .expect("fits");
        let outcome = {
            let g = arc.read().await;
            g.submit_pending_tx(pending.id, pending.content_gen)
                .await
                .unwrap_or_else(|e| panic!("daemon must accept pool spend {n}: {e:?}"))
        };
        let txid = require_fresh_accept(outcome, "a pool spend");
        pool_weight += weight;
        weights.push(weight);
        eprintln!("pool spend {n}: {txid}, weight {weight}, pool weight {pool_weight}");
        // Enough once the pool overfills the limit by a margin of spends.
        if pool_weight > limit + 4 * weight {
            break;
        }
    }
    assert!(
        pool_weight > limit,
        "the pool ({pool_weight}) must overfill the limit ({limit}) so a block built from it \
         is bounded by the limit and not by the pool running dry"
    );
    assert_eq!(
        daemon.tx_pool_size().await,
        u64::try_from(weights.len()).expect("fits")
    );
    Overfilled {
        median,
        limit,
        weights,
    }
}

/// CEN-F14's live-lane parity test (`CHAIN_RULES_SLICE_7.md` §5 row 5;
/// Q9 (iii) as amended): **the Rust producer builds a block at the
/// consensus weight bound and the C++ daemon judges it.** The heaviest
/// block the pool allows under the bound is accepted; the same block
/// naming one more body — over the bound — is refused. The judgement the
/// C++ gives is the one the Rust validator gives under F14
/// (`reward_tests`: exactly `2 · M` accepted at zero subsidy, one over
/// refused at `Locus::Block`), so the two implementations meet at the same
/// point on the same object.
///
/// **The bound is a relationship, not a figure.** `2 · M` is the C++'s
/// `m_current_block_cumul_weight_limit = m_current_block_cumul_weight_median
/// * 2` (`blockchain.cpp:6099`; `:1718` and `:4330` read it back as
/// `limit / 2`), read here from `daemon_status` rather than computed, and its
/// value follows the zone and the penalty rulings —
/// `CONSENSUS_C2_R2_WEIGHT_FEES.md` treats the zone, the surge factor and
/// the quadratic penalty as one control system (`:214–215`) and examined
/// the ceiling's behaviour as a system (`:347–366`). **What this test
/// claims is that the C++ agrees with Shekyl's ratified bound**, not that
/// Shekyl matches the C++: if the zone round moves `M` or a penalty round
/// moves the multiplier, the expected values here move with the ruling,
/// and a C++ built against the old value would be the side that diverges.
/// That sentence is for whoever finds this after the C++ is gone.
///
/// Why the C++ producer cannot build the object (§3.5): its template stops
/// at its fee/penalty equilibrium just past `M`, so a block at the bound
/// exists only as a Rust-built one. The Rust template is built against the
/// C++'s own state — its template's header (parent, curve-tree root,
/// section root, versions, timestamp), `block_template`'s median and
/// accumulator, the pool's bodies, the F20 volume window from the headers
/// — so the only thing that differs between the two blocks submitted is
/// one listed hash, and the only rule that can tell them apart is F14.
/// Regtest difficulty is one, so the PoW is moot and no nonce search is
/// needed.
///
/// Over the bound **no reward is defined**, so there is no coinbase that
/// is right for the over-bound block: the Rust producer refuses to build
/// it (`TemplateError::Emission(BlockTooBig)` — F14 on the producing
/// side), and the negative control is the accepted block's list naming
/// one more body, coinbase unchanged. The C++ finds the same absence
/// (`get_block_reward` fails on the cumulative weight inside
/// `validate_miner_transaction`) and refuses.
///
/// The accepted block is also F14b's and F18's live parity: the C++
/// refuses a coinbase that does not pay exactly the penalised miner leg
/// plus the fee income, so a Rust template whose penalty or split differed
/// from the C++'s is refused here for the *right* reason before F14 could
/// accept it. The over-bound block is not distinguishable from an F18
/// refusal by the RPC's generic error alone; the accepted block one body
/// lighter is what says the refusal was the weight's.
///
/// **What the first run found (2026-09-28).** The over-bound block was
/// refused for its weight (`Block cumulative weight is too big: 610143,
/// expected at most 600000`) and the block at the bound was refused for
/// its coinbase: the miner leg differed by `33 595` atomic units — one
/// unit of the staker share in `10⁶` — because the C++ *regtest* measured
/// CEN-F21's decay from height 0 while every issued network measures it
/// from block 1. The share now starts at `shekyl_economics::EMISSION_SPLIT_EPOCH`
/// on every network, read by the split itself. This test is the falsifier
/// that the two producers agree on that share. Fee income agreed to the
/// unit both times.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; ~50 spends into the pool, several min"]
async fn e2e_a_rust_block_at_the_consensus_bound_is_judged_by_the_cxx() {
    use curve25519_dalek::{EdwardsPoint, Scalar};
    use shekyl_block_template::{
        build, EmissionOperands, MinerKeys, TemplateContext, TemplateError,
    };
    use shekyl_chain_rules::RuleSet;
    use shekyl_crypto_pq::kem::{HybridX25519MlKem, KeyEncapsulation};
    use shekyl_economics::params::TX_VOLUME_WINDOW;
    use shekyl_economics::{ClosedShardCount, EconomicParams, EmissionError, TxVolume};
    use shekyl_types::{BlockCount, BlockHeight, SectionRoot, Timestamp};
    use shekyl_wire::{Block, Transaction};
    use zeroize::Zeroizing;

    let daemon =
        RegtestDaemon::start_for_seed(&[0x79u8; shekyl_crypto_pq::account::SEED_BYTES]).await;
    let (wallet, _tmp, address) = mainnet_wallet(daemon.rpc_port, 0x79).await;
    let arc = Arc::new(RwLock::new(wallet));
    let Overfilled {
        median,
        limit,
        weights: _,
    } = overfill_pool(&daemon, &arc, &address).await;

    // --- the daemon's state for the next block, read rather than assumed ---
    // The daemon's own template supplies the header a block at this height
    // must carry: parent, curve-tree root (B5), section root, the
    // version pair, and a timestamp past the MTP (C2).
    let job = daemon
        .rpc
        .call::<wire::BlockTemplate>(NoParams)
        .await
        .expect("block_template");
    let cxx_block = Block::from_bytes(&job.body.0).expect("the daemon's template parses");
    let height = job.height.0;
    assert_eq!(
        job.weight_median.0, median,
        "block_template's median is daemon_status's"
    );
    let already_generated = job.emission.to_atomic_units().to_raw();
    let total_burned = daemon.total_burned().await;
    // CEN-F20's operand over the daemon's headers: the listed-transaction
    // count over the prior `min(height, W)` blocks.
    let window = height.min(TX_VOLUME_WINDOW);
    let headers = daemon
        .rpc
        .call::<wire::BlockHeaderList>(wire::block::HeaderRange {
            select: wire::block::HeaderRangeSelect::Range {
                from: shekyl_rpc_types::kinds::Height(height - window),
                to: shekyl_rpc_types::kinds::Height(height - 1),
            },
            pow: false,
        })
        .await
        .expect("block_header_list");
    assert_eq!(headers.len() as u64, window);
    let tx_volume = TxVolume::window(
        headers
            .iter()
            .map(|slot| match slot {
                wire::shared::Slot::Item(header) => header.tx_count.0,
                other => panic!("a header below the tip is held: {other:?}"),
            })
            .sum(),
        window,
    );

    // The pool's bodies, as the daemon holds them: the ids from
    // `txpool_list`, the bodies from `tx_list`.
    let pool = daemon
        .rpc
        .call::<wire::TxpoolList>(NoParams)
        .await
        .expect("txpool_list");
    let listed = daemon
        .rpc
        .call::<wire::TxList>(wire::tx::TxListQuery {
            id: pool.iter().map(|entry| entry.id).collect(),
            prune: false,
        })
        .await
        .expect("tx_list");
    let mut bodies: Vec<Transaction> = listed
        .into_iter()
        .map(|slot| match slot {
            wire::shared::Slot::Item(entry) => {
                Transaction::from_bytes(&entry.body.0).expect("a pool body parses")
            }
            other => panic!("a listed pool entry is held: {other:?}"),
        })
        .collect();
    // Heaviest first, so the block fills to the bound with the fewest
    // bodies and the one-body step is as large as it can be.
    bodies.sort_by_key(|b| std::cmp::Reverse(b.weight()));
    assert!(bodies.len() >= 46, "the pool holds {} bodies", bodies.len());

    // --- the Rust producer's template against that state ---
    let spend_secret = Scalar::from_bytes_mod_order([0x5d; 32]);
    let (kem_pk, _kem_sk) = HybridX25519MlKem
        .keypair_generate()
        .expect("hybrid KEM keypair generation");
    let miner = MinerKeys {
        spend_public: EdwardsPoint::mul_base(&spend_secret).compress().to_bytes(),
        x25519_pk: kem_pk.x25519,
        ml_kem_ek: kem_pk.ml_kem,
    };
    let params = EconomicParams::default();
    let rule_set = RuleSet::GENESIS;
    // The daemon drew this template's commitment; the Rust producer is
    // handed the same one, as it is handed the same header operands.
    let draw_commitment = shekyl_wire::tx_extra::parse(&cxx_block.miner_transaction.prefix.extra)
        .expect("the daemon's coinbase extra parses")
        .into_iter()
        .find_map(|field| match field {
            shekyl_wire::tx_extra::TxExtraField::DrawCommitment(c) => Some(c),
            _ => None,
        })
        .expect("the daemon's coinbase carries a 0x0C draw commitment");
    let build_with = |listed: &[Transaction]| {
        build(&TemplateContext {
            height: BlockHeight::from_raw(height),
            previous: cxx_block.header.previous,
            curve_tree_root: cxx_block.header.curve_tree_root,
            section_root: SectionRoot::from_bytes(*cxx_block.header.section_root.as_bytes()),
            major_version: cxx_block.header.major_version,
            // The C++'s template timestamp is already `max(now, MTP + 1)`;
            // claiming it with no median reproduces it exactly.
            now: Timestamp::from_raw(cxx_block.header.timestamp),
            median_timestamp: None,
            unlock_window: BlockCount::from_raw(rule_set.mined_money_unlock_window().to_raw()),
            emission: EmissionOperands {
                already_generated_coins: shekyl_units::AtomicUnits::from_raw(already_generated),
                total_burned,
                median_weight: median,
                tx_volume,
                closed_shards: ClosedShardCount::ZERO,
            },
            params: &params,
            miner: &miner,
            tx_key_secret: Zeroizing::new([0x42; 32]),
            extra_nonce: [0; shekyl_wire::tx_extra::COINBASE_NONCE_BYTES],
            draw_commitment,
            listed,
        })
    };

    // The heaviest body count the producer will price. Over the bound no
    // reward is defined, so the Rust producer refuses to build at all —
    // `TemplateError::Emission(BlockTooBig)` is F14 on the producing side,
    // the same absence the C++ validator finds below — and the search
    // steps down until it prices.
    let mut under = bodies.len();
    let at_bound = loop {
        match build_with(&bodies[..under]) {
            Ok(template) => break template,
            Err(TemplateError::Emission(EmissionError::BlockTooBig)) => {
                assert!(under > 0, "even the empty block is over the bound");
                under -= 1;
            }
            Err(e) => panic!("the Rust template builds against the C++'s state: {e}"),
        }
    };
    assert!(
        under < bodies.len(),
        "the pool must overfill the bound: the search priced all {} bodies",
        bodies.len()
    );
    assert_eq!(
        at_bound.transactions.len(),
        under,
        "a priced listing is the listing that was supplied"
    );
    assert!(at_bound.block_weight <= limit);
    assert!(
        at_bound.block_weight + bodies[under].weight() as u64 > limit,
        "one more body crosses the bound"
    );
    assert!(
        at_bound.block_weight > median,
        "the accepted block is over the median: the penalty is live on it"
    );
    // The negative control: the same block naming one more body. Its
    // coinbase is the at-bound one — no coinbase is *right* for a block
    // over the bound, which is what the refusal says.
    let mut over = at_bound.block.clone();
    over.transaction_hashes.push(bodies[under].hash());
    eprintln!(
        "Rust-built block at height {height}: {under} bodies / {} B under 2·M = {limit}; the \
         producer refused the next body (BlockTooBig); penalised reward {}",
        at_bound.block_weight,
        at_bound.block_reward.to_raw()
    );
    eprintln!(
        "operands: already_generated={already_generated} total_burned={total_burned} \
         tx_volume={tx_volume:?}; coinbase pays miner_emission={} + miner_fee_income={}",
        at_bound.miner_emission.to_raw(),
        at_bound.miner_fee_income.to_raw(),
    );

    // --- the C++ judges both, on the same parent ---
    let submit = |block: &Block| {
        let body = wire::block::BlockBody {
            body: shekyl_rpc_types::kinds::Bytes(block.serialize()),
        };
        let rpc = &daemon.rpc;
        async move { rpc.call::<wire::BlockSubmit>(body).await }
    };
    // The over-limit block first, so both are judged against one parent.
    let refused = submit(&over).await;
    assert!(
        refused.is_err(),
        "the C++ must refuse a block over twice its median (F14); it accepted {refused:?}"
    );
    let before = daemon.height().await;
    let accepted = submit(&at_bound.block).await.unwrap_or_else(|e| {
        panic!(
            "the C++ accepts the Rust-built block at the bound (F14, F14b, F18 at parity): \
             {e:?}\n--- daemon log tail ---\n{}",
            daemon.log_tail()
        )
    });
    assert_eq!(daemon.height().await, before + 1, "the block connected");
    let block_id = accepted.hash.to_string();
    let (recorded_weight, carried) = daemon.block_weight_of(&block_id).await;
    assert_eq!(
        recorded_weight, at_bound.block_weight,
        "the C++ weighs it as we did"
    );
    assert_eq!(carried, under);
    let (median_after, _) = daemon.weight_limit().await;
    eprintln!(
        "C++ accepted the Rust block at {recorded_weight} B carrying {carried} bodies; median \
         now {median_after}"
    );

    // Drain the pool and capture the chain: the block at the bound is on
    // record for the replay, where the Rust validator judges it under F14
    // and the emission oracle holds the penalised reward to the C++'s.
    for _ in 0..8 {
        if daemon.tx_pool_size().await == 0 {
            break;
        }
        daemon.generate_blocks(1).await;
    }
    assert_eq!(daemon.tx_pool_size().await, 0, "the pool drains");
    daemon.generate_blocks(1).await;
    maybe_capture_chain_vector(
        &daemon,
        "limit-full",
        "e2e_a_rust_block_at_the_consensus_bound_is_judged_by_the_cxx",
        None,
    )
    .await;
}

/// CEN-G6/G6b's parity capture (`CHAIN_RULES_SLICE_7.md` §3.5, Q9 (iii)):
/// **the fullest block the C++ producer builds**, taken while both
/// implementations exist — the same reasoning and the same window as
/// I17's signing-preimage KAT, opposite sign (a parity pin, not a
/// divergence pin).
///
/// The pool is overfilled with daemon-accepted spends (each ≈ 13.2 KB at
/// one input, the I4 measurement) to more than the C++'s consensus limit
/// (`daemon_status.block_weight_max` = 2 × the effective median = 600 000 on
/// a young chain, the zone's floor arm), then one block is mined.
///
/// **What the first run found (2026-09-28), and what this therefore
/// captures.** The premise was a block *at the limit*. The C++ producer
/// does not build one: `tx_pool::fill_block_template` lists bodies in fee
/// order, lets one body cross the median, refuses a body that would pass
/// 13/10 of the median less the coinbase reserve, and then stops. The
/// reward-aware rule, `shekyl_block_template::Fill`, is not this scan and
/// does not run here, so the template stops one transaction past the
/// **median**
/// — 305 738 bytes, 23 spends, 27 left in the pool, against a limit of
/// 600 000. The 2 × median bound is the *validator's* refusal (CEN-F14); no
/// C++ producer reaches it, and a block at it is a Rust-producer-built
/// object for F14's own live-lane test (slice 7 row 5). What the C++ does
/// build is sharper for G6 than the limit would have been: a block whose
/// weight sits at the C++'s **median** — the stopping rule is a function
/// of `M` — so a Rust median that differed would price a
/// different penalty on this very block (F14b, F18). Held here by the
/// daemon's own account: the weight is under the limit, the pool is not
/// dry (the template was bounded by its policy, not by the pool), and the
/// block crossed the median by less than two more spends would reach.
/// Then the pool is drained by further blocks so the captured chain is
/// whole.
///
/// Captured under `SHEKYL_CAPTURE_CHAIN_VECTORS` as the `median-full`
/// vector: the replay (`vectors_tests`) holds the Rust validator to it —
/// the G6/G6b medians against the trace's at every height now, the
/// penalty and the paid reward on a block over the median once F14b/F18
/// land. None of the other captured chains carries a block over the
/// median, or more than one listed body; this is the one on record.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; ~50 spends into the pool, several min"]
async fn e2e_cxx_template_fills_to_its_median() {
    let daemon =
        RegtestDaemon::start_for_seed(&[0x77u8; shekyl_crypto_pq::account::SEED_BYTES]).await;
    let (wallet, _tmp, address) = mainnet_wallet(daemon.rpc_port, 0x77).await;
    let arc = Arc::new(RwLock::new(wallet));
    let Overfilled {
        median,
        limit,
        weights,
    } = overfill_pool(&daemon, &arc, &address).await;

    // `block_template` reports what the template pays its miner. With
    // the pool full the template lists transactions, and the figure is the
    // coinbase the template carries: not zero, and not the pre-split
    // emission.
    assert_template_reports_its_coinbase(&daemon, &address, true).await;

    // The fullest block the C++ producer builds from that pool.
    let mined = daemon.generate_blocks(1).await;
    assert_eq!(mined.blocks.len(), 1);
    let (block_weight, carried) = daemon.block_weight_of(&mined.blocks[0]).await;
    let pool_after = daemon.tx_pool_size().await;
    let lightest_left = *weights.iter().min().expect("at least one spend");
    eprintln!(
        "C++ built a block of weight {block_weight} carrying {carried} spends against median \
         {median} / limit {limit}; {pool_after} spend(s) left in the pool"
    );
    assert!(
        block_weight <= limit,
        "the C++ never exceeds its own limit: {block_weight} > {limit}"
    );
    assert!(
        pool_after >= 1,
        "the template must have been bounded by its own policy: the pool ran dry instead"
    );
    // The producer stops once the listed weight passes the median (the
    // doc above), so the block is within two spends of `M` on the heavy
    // side — not at the limit, and not under the median with room to
    // spare.
    assert!(
        block_weight + lightest_left > median,
        "one more spend ({lightest_left}) would have kept the block under the median: \
         {block_weight} + {lightest_left} <= {median} — the pool, not the policy, bounded it"
    );
    assert!(
        block_weight < median + 2 * lightest_left,
        "the C++ producer took the block {block_weight} more than two spends past its median \
         {median}: the fill does not stop where `fill_block_template` says it does"
    );
    assert!(
        carried >= 20,
        "a 300 000-byte median carries ≈ 23 spends of ≈ 13.2 KB; {carried} means the spends are \
         not the shape the I4 measurement pinned"
    );

    // Drain the pool so the captured chain carries every spend, then one
    // empty block so the tip is a plain coinbase block like the others.
    for _ in 0..8 {
        if daemon.tx_pool_size().await == 0 {
            break;
        }
        daemon.generate_blocks(1).await;
    }
    assert_eq!(daemon.tx_pool_size().await, 0, "the pool drains");
    // The same holds for a template that lists nothing.
    assert_template_reports_its_coinbase(&daemon, &address, false).await;
    daemon.generate_blocks(1).await;
    maybe_capture_chain_vector(
        &daemon,
        "median-full",
        "e2e_cxx_template_fills_to_its_median",
        None,
    )
    .await;
}

/// `block_template.reward` is the sum of the coinbase outputs of
/// the template it returns. `lists_transactions` states which template the
/// caller set up, so a pool that did not fill (or did not drain) fails here
/// and not as a vacuous pass.
#[cfg(test)]
async fn assert_template_reports_its_coinbase(
    daemon: &RegtestDaemon,
    _address: &str,
    lists_transactions: bool,
) {
    use shekyl_wire::Block;

    // Between a tip change and the follower's next post there is no job
    // (one template per tip, N2): wait for the one built at this tip.
    let deadline = Instant::now() + Duration::from_secs(30);
    let template = loop {
        if let Ok(template) = daemon.rpc.call::<wire::BlockTemplate>(NoParams).await {
            break template;
        }
        assert!(
            Instant::now() < deadline,
            "no job was posted at the tip within 30 s"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let block = Block::from_bytes(&template.body.0).expect("the daemon's template parses");
    assert_eq!(
        !block.transaction_hashes.is_empty(),
        lists_transactions,
        "the template lists {} transaction(s)",
        block.transaction_hashes.len()
    );
    let coinbase: u64 = block
        .miner_transaction
        .prefix
        .outputs
        .iter()
        .map(|output| output.amount)
        .sum();
    assert!(coinbase > 0, "a template pays its miner");
    assert_eq!(
        template.reward.to_atomic_units().to_raw(),
        coinbase,
        "reward is the coinbase the template carries"
    );
}

/// Trim (reorg) self-consistency: popping the chain back to an earlier height must
/// restore the EXACT curve-tree root that growing to that height produced. Grow is
/// validated as consensus-correct (`e2e_fcmp_spend_over_depth3_tree`), so a trim that
/// reproduces the grow root is itself correct — `trim == grow⁻¹`. The reorg crosses a
/// Selene leaf-chunk boundary, so the pop-back recomposes the upper layer rather than
/// only trimming a partial leaf chunk — exercising the `db_lmdb::trim_curve_tree` →
/// `shekyl_curve_tree_grow_upper_layers` rewiring (the reorg twin of the grow fix:
/// the old in-place incremental upper propagation had the same drop-the-sibling
/// defect). Runs at depth-2 (a few minutes); the depth-3 deepening uses the identical
/// FFI already validated by the grow gate.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; slow (depth-2 mine, a few min)"]
async fn e2e_trim_curve_tree_restores_grow_root() {
    // SELENE_CHUNK_WIDTH — outputs per Selene leaf node (a leaf-chunk boundary).
    const SELENE_CHUNK_WIDTH: u64 = 38;
    const MINE_BATCH_BLOCKS: u64 = 20;
    const MAX_MINE_BATCHES: usize = 30;

    async fn tree_info(daemon: &RegtestDaemon) -> (u8, u64, String) {
        let info = daemon.curve().await;
        let depth = u8::try_from(info.layers.0).unwrap_or(u8::MAX);
        (depth, info.leaf_count.0, info.root.to_string())
    }

    let daemon =
        RegtestDaemon::start_for_seed(&[0x44u8; shekyl_crypto_pq::account::SEED_BYTES]).await;

    // Grow to depth-2 with >= 2 Selene leaf chunks, then record the anchor state.
    let mut anchor = None;
    for _ in 0..MAX_MINE_BATCHES {
        daemon.generate_blocks(MINE_BATCH_BLOCKS).await;
        let (depth, leaf_count, root) = tree_info(&daemon).await;
        if depth >= 1 && leaf_count >= 2 * SELENE_CHUNK_WIDTH {
            anchor = Some((daemon.height().await, depth, leaf_count, root));
            break;
        }
    }
    let (anchor_height, anchor_depth, anchor_leaf, anchor_root) =
        anchor.expect("tree must reach depth-2 with >= 2 leaf chunks");
    eprintln!(
        "anchor: height={anchor_height} depth={anchor_depth} leaf_count={anchor_leaf} root={anchor_root}"
    );

    // Grow >= 1 more leaf-chunk boundary so the pop-back must recompose the upper
    // layer (not merely trim a single partial leaf chunk).
    let target_leaf = anchor_leaf + SELENE_CHUNK_WIDTH;
    let mut grew = false;
    for _ in 0..MAX_MINE_BATCHES {
        daemon.generate_blocks(MINE_BATCH_BLOCKS).await;
        if tree_info(&daemon).await.1 >= target_leaf {
            grew = true;
            break;
        }
    }
    assert!(grew, "tree must grow >= 1 more leaf chunk past the anchor");
    let grown_height = daemon.height().await;
    assert!(grown_height > anchor_height, "chain must have advanced");

    // Reorg back to the anchor height: trim must restore the grow state exactly.
    daemon.pop_blocks(grown_height - anchor_height).await;
    let (depth, leaf_count, root) = tree_info(&daemon).await;
    eprintln!(
        "after pop to height {anchor_height}: depth={depth} leaf_count={leaf_count} root={root}"
    );
    assert_eq!(
        leaf_count, anchor_leaf,
        "trim must restore the anchor leaf count"
    );
    assert_eq!(depth, anchor_depth, "trim must restore the anchor depth");
    assert_eq!(
        root, anchor_root,
        "trim must restore the EXACT grow root (consensus-critical: trim == grow⁻¹)"
    );
}

// ===========================================================================
// CT-2 Tier-B fixture generator
// ===========================================================================

/// Mines the CT-2 Tier-B scenarios — a **multi-tx block** (coinbase + spend), a
/// **mixed-maturity collision** (a spend's `+10` regular outputs interleaving
/// with `+60` coinbases at the same drain height), and a **reorg-with-spend**
/// (rollback below a spend, re-mine + re-spend) — on a live regtest via the
/// proven keystone spend path, then writes
/// `shekyl-curve-tree/tests/fixtures/ct2_tier_b.json`.
///
/// It captures only the **deterministic projection** the reconstruct path needs
/// — per-height curve-tree root + per-output leaf identity (`output_key`,
/// `commitment`, `0x07`→`h_pqc`, `target`) — never raw tx blobs (random blinds /
/// one-time keys are not reproducible across runs; `shiny-prancing-flute.md`
/// amendment 11). The captured values ARE the on-chain ones, so `recon_tier_b.rs`
/// reconstructs each height's root deterministically and asserts it equals the
/// recorded consensus root.
///
/// Not a pass/fail gate — it regenerates the committed oracle. Run on demand:
/// ```bash
/// SHEKYLD_BIN=/path/to/build/bin/shekyld \
///   cargo test -p shekyl-engine-core --lib generate_ct2_tier_b_fixture -- --ignored --nocapture
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "regenerates ct2_tier_b.json; needs SHEKYLD_BIN + a live regtest"]
async fn generate_ct2_tier_b_fixture() {
    const MINE_BATCH_BLOCKS: u64 = 10;
    const MAX_MINE_BATCHES: usize = 24;
    // Roll back fewer blocks than separate the spend from the tip (the spend
    // confirms, then MINE_BATCH_BLOCKS more are mined), so the spend survives the
    // reorg and the re-mined tail still diverges (fresh coinbase output keys).
    const REORG_DEPTH: u64 = 8;

    let daemon =
        RegtestDaemon::start_for_seed(&[0x44u8; shekyl_crypto_pq::account::SEED_BYTES]).await;
    let (wallet, _tmp, _) = mainnet_wallet(daemon.rpc_port, 0x44).await;
    // A second wallet for its address only — the spend recipient (a real
    // non-change regular output, distinct from the self-send change).
    let (_recipient_wallet, _tmp2, recipient) = mainnet_wallet(daemon.rpc_port, 0x55).await;
    let arc = Arc::new(RwLock::new(wallet));

    // --- fund + spend (main chain): a transfer to `recipient` yields a multi-tx
    //     block (coinbase + spend) whose +10 regular outputs (recipient + change)
    //     are the mixed-maturity classes vs the +60 coinbases. ---
    mine_until_spendable(&daemon, &arc, MINE_BATCH_BLOCKS, MAX_MINE_BATCHES).await;
    submit_tier_b_spend(
        &daemon,
        &arc,
        &recipient,
        MINE_BATCH_BLOCKS,
        MAX_MINE_BATCHES,
    )
    .await;
    // Mine on so the spend's regular outputs mature + drain alongside later
    // coinbases (the collision the recon orders by (maturity, gindex)).
    daemon.generate_blocks(MINE_BATCH_BLOCKS).await;
    let main_tip = daemon.height().await - 1;
    let main_chain = capture_chain(&daemon, "main", main_tip).await;
    eprintln!("captured main chain through height {main_tip}");

    // --- reorg-with-spend: roll the daemon back (shallower than the spend, which
    //     survives), refresh the wallet across the rollback, then re-mine + re-spend
    //     a divergent tail. The post-pop `refresh` is the exact path that surfaced
    //     the optimistic-spend state bug — it scans the block carrying the wallet's
    //     own (optimistically-marked) spend; with that fixed (in-flight `spent`
    //     without `spent_height` is now a valid shape, and `handle_reorg` un-marks
    //     orphaned confirmed spends) it completes, confirming the spend and re-mining
    //     a fresh-keyed tail whose per-height roots diverge from `main`. This drives
    //     the wallet's reorg-refresh end-to-end (the bug #2 e2e), and the captured
    //     chain carries both the surviving and the re-mined spend's mixed leaves. ---
    daemon.pop_blocks(REORG_DEPTH).await;
    refresh(&arc).await;
    mine_until_spendable(&daemon, &arc, MINE_BATCH_BLOCKS, MAX_MINE_BATCHES).await;
    submit_tier_b_spend(
        &daemon,
        &arc,
        &recipient,
        MINE_BATCH_BLOCKS,
        MAX_MINE_BATCHES,
    )
    .await;
    daemon.generate_blocks(MINE_BATCH_BLOCKS).await;
    let reorg_tip = daemon.height().await - 1;
    let reorg_chain = capture_chain(&daemon, "reorg", reorg_tip).await;
    eprintln!("captured reorg chain through height {reorg_tip}");

    let fixture = json!({
        "_comment": "CT-2 Tier-B reconstruct-root oracle (multi-tx / mixed-maturity / \
            reorg-with-spend). Generated by generate_ct2_tier_b_fixture from a live \
            regtest shekyld via the keystone spend path. Each chain's \
            block[h].curve_tree_root is the C++ consensus header root; recon_tier_b.rs \
            reconstructs it from the per-tx leaf inputs (coinbase + spend) in drain \
            order (maturity, gindex). Deterministic projection only — no raw tx blobs.",
        "chains": [main_chain, reorg_chain],
    });
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../shekyl-curve-tree/tests/fixtures/ct2_tier_b.json"
    );
    std::fs::write(path, serde_json::to_string_pretty(&fixture).unwrap())
        .expect("write ct2_tier_b.json");
    eprintln!("wrote {path}");
}

/// Mine + refresh in batches until the wallet's unlocked balance reaches
/// `target`. Panics after `max_batches` batches.
async fn mine_until_unlocked_at_least(
    daemon: &RegtestDaemon,
    arc: &Arc<RwLock<super::Engine<super::SoloSigner>>>,
    target: shekyl_units::AtomicUnits,
    batch: u64,
    max_batches: usize,
) {
    for _ in 0..max_batches {
        daemon.generate_blocks(batch).await;
        refresh(arc).await;
        if unlocked_balance(arc).await >= target {
            return;
        }
    }
    panic!("unlocked balance must reach {target:?} after mining + refresh");
}

/// Mine + refresh in batches until the wallet has a spendable (unlocked) balance.
async fn mine_until_spendable(
    daemon: &RegtestDaemon,
    arc: &Arc<RwLock<super::Engine<super::SoloSigner>>>,
    batch: u64,
    max_batches: usize,
) {
    use shekyl_units::AtomicUnits;
    mine_until_unlocked_at_least(daemon, arc, AtomicUnits::from_raw(1), batch, max_batches).await;
}

/// Build (retrying past the C2 reference-spendability gate) + submit a transfer
/// to `recipient` for a quarter of the unlocked balance, then mine one
/// confirming block.
async fn submit_tier_b_spend(
    daemon: &RegtestDaemon,
    arc: &Arc<RwLock<super::Engine<super::SoloSigner>>>,
    recipient: &str,
    batch: u64,
    max_batches: usize,
) {
    use shekyl_units::AtomicUnits;
    let amount = AtomicUnits::from_raw(unlocked_balance(arc).await.to_raw() / 4);
    transfer_to(
        daemon,
        arc,
        super::pending::TxDestination::Address(recipient.to_string()),
        amount,
        batch,
        max_batches,
    )
    .await;
}

/// Build (retrying past the C2 reference-spendability gate) + submit a transfer
/// of exactly `amount` to `recipient`, then mine one confirming block.
async fn transfer_to(
    daemon: &RegtestDaemon,
    arc: &Arc<RwLock<super::Engine<super::SoloSigner>>>,
    recipient: super::pending::TxDestination,
    amount: shekyl_units::AtomicUnits,
    batch: u64,
    max_batches: usize,
) {
    submit_transfer(daemon, arc, recipient, amount, batch, max_batches).await;
    daemon.generate_blocks(1).await;
}

/// Build (retrying past the C2 reference-spendability gate) + submit a transfer
/// of exactly `amount` to `recipient`, and leave it in the pool. Returns the
/// hash of a fresh accept.
async fn submit_transfer(
    daemon: &RegtestDaemon,
    arc: &Arc<RwLock<super::Engine<super::SoloSigner>>>,
    recipient: super::pending::TxDestination,
    amount: shekyl_units::AtomicUnits,
    batch: u64,
    max_batches: usize,
) -> TxHash {
    use super::pending::{FeePriority, TxRecipient, TxRequest};
    let request = TxRequest {
        recipients: vec![TxRecipient {
            destination: recipient,
            amount_atomic_units: amount,
            rid: None,
        }],
        priority: FeePriority::Standard,
    };
    let mut pending = None;
    for _ in 0..max_batches {
        let attempt = {
            let g = arc.read().await;
            g.build_pending_tx(&request).await
        };
        match attempt {
            Ok(p) => {
                pending = Some(p);
                break;
            }
            Err(super::error::SendError::OutputNotYetSpendable { .. }) => {
                daemon.generate_blocks(batch).await;
                refresh(arc).await;
            }
            Err(e) => panic!("build transfer: {e:?}"),
        }
    }
    let pending = pending.expect("transfer must build once reference-spendable");
    submit_built(arc, &pending, "the transfer").await
}

/// Fund the active persona with `amount` through the production
/// `stake_in` (the wallet-RPC and GUI entry: `Engine::stake`), retrying
/// past the C2 reference-spendability gate, then submit it and mine one
/// confirming block. The transfer carries `amount` plus the system cover
/// draw, so callers size by `amount` and never assert the exact funded
/// figure.
async fn stake_in_and_confirm(
    daemon: &RegtestDaemon,
    arc: &Arc<RwLock<super::Engine<super::SoloSigner>>>,
    amount: shekyl_units::AtomicUnits,
    batch: u64,
    max_batches: usize,
) {
    use super::principal_stake::StakeInError;
    let mut pending = None;
    for _ in 0..max_batches {
        let attempt = {
            let g = arc.read().await;
            g.stake().stake_in(amount).await
        };
        match attempt {
            Ok(p) => {
                pending = Some(p);
                break;
            }
            Err(StakeInError::Send(super::error::SendError::OutputNotYetSpendable { .. })) => {
                daemon.generate_blocks(batch).await;
                refresh(arc).await;
            }
            Err(e) => panic!("stake_in: {e:?}"),
        }
    }
    let pending = pending.expect("stake_in must build once reference-spendable");
    submit_built(arc, &pending, "the stake_in funding").await;
    daemon.generate_blocks(1).await;
}

/// Submit a built pending transaction and require the daemon's fresh accept.
async fn submit_built(
    arc: &Arc<RwLock<super::Engine<super::SoloSigner>>>,
    pending: &super::pending::PendingTx,
    what: &str,
) -> TxHash {
    let outcome = {
        let g = arc.read().await;
        g.submit_pending_tx(pending.id, pending.content_gen)
            .await
            .unwrap_or_else(|e| panic!("daemon must accept {what} (consensus verify): {e:?}"))
    };
    let tx_hash = require_fresh_accept(outcome, what);
    eprintln!("daemon accepted {what}: {tx_hash}");
    tx_hash
}

async fn refresh(arc: &Arc<RwLock<super::Engine<super::SoloSigner>>>) {
    use super::refresh::RefreshOptions;
    super::Engine::start_refresh(arc.clone(), RefreshOptions::default())
        .await
        .expect("start_refresh")
        .join()
        .await
        .expect("refresh joins");
}

async fn unlocked_balance(
    arc: &Arc<RwLock<super::Engine<super::SoloSigner>>>,
) -> shekyl_units::AtomicUnits {
    use shekyl_scanner::WalletLedgerExt;
    let g = arc.read().await;
    let ledger = g.ledger();
    ledger.balance().unlocked
}

// ---------------------------------------------------------------------------
// PR-4 staker harness (EMISSION_CLAIM_BUILDER.md §8 PR-4): staker wallet
// lifecycle + persona funding + production P-scan against the live daemon.
// ---------------------------------------------------------------------------

/// Test finality horizon for the P-scan. Production is the consensus
/// `ARCHIVAL_REORG_DEPTH_BLOCKS`; a shallow horizon (injected through the
/// crate-visible [`Engine::start_pscan_with`](super::Engine::start_pscan_with)
/// seam, which exists for exactly this) lets the harness reach scan finality
/// in blocks it can afford to mine.
const PSCAN_TEST_REORG_DEPTH: u64 = 4;

/// What [`staker_wallet`] hands back: the arc'd engine, its tempdir (the
/// caller keeps it alive — it owns the wallet files) and the principal's
/// encoded primary address.
type StakerWallet = (
    Arc<RwLock<super::Engine<super::SoloSigner>>>,
    tempfile::TempDir,
    String,
);

/// Create a STAKER Mainnet wallet against the daemon RPC: create → persist the
/// slot's bond record (flips `staking_enabled`) → close → reopen (`open_full`
/// spawns the `StakeEngine` for a staker — the same create/reopen shape as the
/// pscan auto-start lifecycle test). Returns the arc'd engine, its tempdir
/// (caller keeps it alive — it owns the wallet files), and the principal's
/// encoded primary address.
pub(super) async fn staker_wallet(
    rpc_port: u16,
    seed: &[u8; shekyl_crypto_pq::account::SEED_BYTES],
    slot: super::stake_engine::PSlot,
) -> StakerWallet {
    let creds = super::lifecycle::Credentials::password_only(b"pr4-staker");
    let (engine, tmp) = create_wallet(rpc_port, seed, b"pr4-staker").await;
    let base_path = tmp.path().join("wallet");
    engine
        .persist_bond_record(slot)
        .expect("persist bond record");
    engine.close(&creds).await.expect("close created wallet");

    let rpc = HttpRpc::new(format!("http://127.0.0.1:{rpc_port}"))
        .await
        .expect("wallet rpc (reopen)");
    let opened = super::Engine::<super::SoloSigner>::open_full(
        &base_path,
        &creds,
        shekyl_address::Network::Regtest,
        super::DaemonClient::verifying(rpc, regtest_expectation()),
        shekyl_engine_file::SafetyOverrides::none(),
    )
    .expect("reopen staker wallet");
    let engine = opened.into_wallet();
    assert!(
        engine.stake_handle().is_some(),
        "a staker reopen spawns the StakeEngine"
    );
    let address = engine.primary_address().encode().expect("encode address");
    (Arc::new(RwLock::new(engine)), tmp, address)
}

/// The persona's payment destination, derived in-test from the master seed
/// the wallet expands its seed into. The production wallet derives the identical bundle
/// at open (`prepare_stake_engine_if_staker` → `derive_archival_p_keys`); the
/// harness takes only its public keys, for the one walk that pays a persona
/// outside `stake_in` (the emission claim's post-bond fee input).
pub(super) fn persona_destination(
    seed: &[u8; shekyl_crypto_pq::account::SEED_BYTES],
    slot: u32,
) -> super::pending::TxDestination {
    use shekyl_crypto_pq::account::{normalize_seed, Network};
    use shekyl_crypto_pq::archival_p::derive_archival_p_keys;
    let keys = derive_archival_p_keys(&normalize_seed(seed), Network::Regtest, slot)
        .expect("derive persona keys");
    super::pending::TxDestination::OwnPersona(keys.payment_destination())
}

/// Run the production P-scan (tight cadence + the shallow
/// [`PSCAN_TEST_REORG_DEPTH`] horizon, via the injectable
/// [`Engine::start_pscan_with`](super::Engine::start_pscan_with) seam) until
/// the sealed `.wallet.pscan` state satisfies `pred`, then shut the task down
/// and return that state. The caller mines the finality horizon past the
/// blocks under test *before* calling; the scan then only has to catch up to
/// `tip − horizon`. Panics if no satisfying seal appears within the deadline.
async fn pscan_until(
    arc: &Arc<RwLock<super::Engine<super::SoloSigner>>>,
    pscan_seal: &std::path::Path,
    what: &str,
    pred: impl Fn(&shekyl_engine_state::pscan_state::PScanState) -> bool,
) -> shekyl_engine_state::pscan_state::PScanState {
    pscan_until_within(arc, pscan_seal, what, pred, Duration::from_secs(300)).await
}

/// [`pscan_until`] under the caller's deadline: a scan over a long stretch
/// of full-bodied blocks (the shard fill, some three hundred spends) is a
/// debug-build cost the default does not fit.
async fn pscan_until_within(
    arc: &Arc<RwLock<super::Engine<super::SoloSigner>>>,
    pscan_seal: &std::path::Path,
    what: &str,
    pred: impl Fn(&shekyl_engine_state::pscan_state::PScanState) -> bool,
    within: Duration,
) -> shekyl_engine_state::pscan_state::PScanState {
    use super::pscan::start::load_pscan_state_for_engine;
    use super::pscan::task::PScanConfig;

    let handle = super::Engine::start_pscan_with(
        arc.clone(),
        PScanConfig {
            reorg_depth: BlockCount::from_raw(PSCAN_TEST_REORG_DEPTH),
            // Small batches so each seal lands quickly: the sweep persists state
            // only at batch boundaries, and a debug-build scan-step is slow
            // enough that a whole-backlog batch could outlive the deadline
            // without ever sealing.
            batch_blocks: 16,
        },
        Duration::from_millis(150),
    )
    .await
    .expect("start pscan");

    let deadline = Instant::now() + within;
    let mut last_report = Instant::now();
    let mut last_seal_mtime: Option<std::time::SystemTime> = None;
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        // Cheap change gate: the seal lands by atomic rename, so a changed
        // mtime is exactly "a new batch sealed" — only then pay the full
        // decrypt + decode of the sealed state (up to 1 500 polls fit in
        // the deadline; re-loading an unchanged seal every 200 ms is pure
        // waste). An absent/unreadable file falls through to the loader,
        // which reports the no-seal-yet state.
        let seal_mtime = std::fs::metadata(pscan_seal)
            .ok()
            .and_then(|m| m.modified().ok());
        if seal_mtime.is_some() && seal_mtime == last_seal_mtime {
            assert!(
                Instant::now() < deadline,
                "pscan did not observe {what} within the deadline"
            );
            continue;
        }
        last_seal_mtime = seal_mtime;
        if let Some(state) = load_pscan_state_for_engine(arc.clone())
            .await
            .expect("load pscan state")
        {
            if pred(&state) {
                handle.shutdown().await;
                return state;
            }
            if last_report.elapsed() > Duration::from_secs(2) {
                last_report = Instant::now();
                eprintln!(
                    "pscan progress: synced={:?}, funding={}, matches={}",
                    state.synced_height(),
                    state.funding_outputs().len(),
                    state.bond_post_matches().len(),
                );
            }
        } else if last_report.elapsed() > Duration::from_secs(2) {
            last_report = Instant::now();
            eprintln!("pscan progress: no seal yet");
        }
        assert!(
            Instant::now() < deadline,
            "pscan did not observe {what} within the deadline"
        );
    }
}

/// Mine in `blocks_per_batch` batches until the tx pool drains.
///
/// The submit path inserts at `relay_method::local` under the Dandelion++
/// embargo. On FAKECHAIN the template admits every *relayable* pool tx
/// (`fill_block_template`'s `m_mine_relayable_txes` opt-in), so a
/// locally-submitted tx is includable immediately and the pool normally
/// drains on the first batch; the loop stays as the fill-policy-agnostic
/// shape (a tx skipped by a readiness check retries rather than failing the
/// caller). Pass `blocks_per_batch = 1` when the caller needs the tx's block
/// to be the tip at return (the emission e2e's depth-1 pop leg pops exactly
/// it).
async fn mine_until_pool_drains(daemon: &RegtestDaemon, what: &str, blocks_per_batch: u64) {
    let mine_deadline = Instant::now() + Duration::from_secs(240);
    // Condition checked BEFORE every batch: an already-drained pool must
    // not advance the chain. Callers passing `blocks_per_batch = 1` rely on
    // the tx's block being the tip when this returns (the A5a depth-1 pop
    // pops exactly it), and an unconditional first batch would bury it
    // under an empty block.
    while daemon.tx_pool_size().await > 0 {
        assert!(
            Instant::now() < mine_deadline,
            "{what} never left the pool (embargo/template gap?)"
        );
        daemon.generate_blocks(blocks_per_batch).await;
        // A tx deferred by a wall-clock condition (not block height) would
        // spin the miner without this pause; retries are not expected under
        // the FAKECHAIN relayable-template opt-in, but stay cheap.
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// The confirmed-bond substrate [`stake_persona_to_confirmed_bond`] hands
/// back: the wallet handles plus the **block geography** the emission-claim
/// e2e derives its epoch arithmetic from. The geography is returned
/// explicitly — the helper mines a variable number of blocks (funding
/// maturity + reference-spendability + embargo drain are all
/// retry-until-ready), so callers must never re-derive heights from mined
/// counts.
struct ConfirmedBondFixture {
    /// The staker wallet engine (persona bonded and confirmed).
    arc: Arc<RwLock<super::Engine<super::SoloSigner>>>,
    /// The wallet's backing tempdir — an RAII guard, never read: hold the
    /// fixture or the wallet files vanish.
    _tmp: tempfile::TempDir,
    /// The principal's mining/funding address.
    principal: String,
    /// The bonded persona's canonical id (the bond post's identity).
    persona_id: shekyl_types::PCanonicalId,
    /// The sealed P-scan state path (for follow-on `pscan_until` calls).
    pscan_seal: std::path::PathBuf,
    /// The sealed scan state at confirmation: carries the bond-post match
    /// and the persona's surviving funding set (the `BondPostChange`
    /// change — the emission claim's fee-input substrate).
    state: shekyl_engine_state::pscan_state::PScanState,
    /// The pre-post funding gindexes `first_stake` swept (pruned from the
    /// sealed set by the arm-1 key-image watch).
    swept_gindexes: Vec<u64>,
    /// How many pre-post funding records the discovery scan found.
    pre_post_discovered: usize,
    /// Tip height when the confirmation scan sealed — the geography anchor
    /// for the emission e2e's epoch-close/claim layout.
    confirmed_tip_height: u64,
}

/// What `stake_persona_and_submit_bond` hands back: the staker wallet with
/// its persona funded, discovered and bonded as far as the **submit**, plus
/// the submit verdict itself, un-judged. `stake_persona_to_confirmed_bond`
/// judges it (accepted, then confirmed on chain); the FND-20 tripwire
/// judges it the other way (refused, at the C++ parser).
struct SubmittedBondPost {
    /// The staker wallet engine (persona funded; bond post sealed and sent).
    arc: Arc<RwLock<super::Engine<super::SoloSigner>>>,
    /// The wallet's backing tempdir — an RAII guard, never read.
    _tmp: tempfile::TempDir,
    /// The principal's mining/funding address.
    principal: String,
    /// The bonded persona's canonical id (the bond post's identity).
    persona_id: shekyl_types::PCanonicalId,
    /// The sealed P-scan state path (for follow-on `pscan_until` calls).
    pscan_seal: std::path::PathBuf,
    /// The pre-post funding gindexes `first_stake` swept.
    swept_gindexes: Vec<u64>,
    /// How many pre-post funding records the discovery scan found.
    pre_post_discovered: usize,
    /// The daemon's answer to the wallet-built post, through the audited
    /// posture→submitter choke point.
    verdict: Result<
        super::transaction_submitter::SubmitSuccess,
        super::transaction_submitter::BroadcastSubmitError,
    >,
}

/// How the confirmed-bond fixture enters the stake.
enum FixtureStake {
    /// The production [`Engine::first_stake`] entry (SP-R0 arm-#1
    /// production discharge) — the SA-R1 genesis posture: JoinMarket
    /// **CompleteTree** holdings. A complete-tree bond is foundation-shaped
    /// and market-EXCLUDED (`ARCHIVAL_CONSENSUS_STATE.md` §3.3 E-2;
    /// `market_member_at_epoch` returns false), so this arm's bond can
    /// never carry Σwork — it exercises the stake entry, not the reward
    /// market.
    FirstStake,
    /// The composed production steps — `mint_handle` →
    /// `persist_bond_record` → [`Engine::assemble_bond_post`] (which seals
    /// the pending post exactly as `first_stake` does) — with
    /// caller-chosen holdings: the **market** bond shape
    /// (`ShardSetCompact`) the emission-claim e2e earns from. Named
    /// deviation (PR-4c finding): no wallet entry posts a market bond
    /// today — `first_stake` hardcodes the CompleteTree genesis posture —
    /// so the market-bond wallet entry is a named follow-on, and until it
    /// lands this composition of the same production functions is the
    /// claimable-bond path.
    MarketBond(shekyl_archival_retention::HoldingsDescriptor),
}

/// Fund → stake → dispatch → confirm: the production staking sequence both
/// PR-4 e2e legs share (rule 19: one definition — the bond e2e asserts on
/// the returned fixture, the emission e2e builds its claim on it). The
/// caller owns the daemon spawn (and with it the SEB lever decision), the
/// stake entry (see [`FixtureStake`] — the emission e2e needs a market
/// bond), and the funding cushion: the cushion is (approximately) the
/// persona's `BondPostChange` change output, so the emission caller sizes
/// it to fund real ToKey claim-fee inputs where the bond caller only needs
/// it non-zero.
///
/// Every step retries-until-ready (funding maturity, reference
/// spendability, the Dandelion++ embargo), so the block geography is a
/// *result*, not an input — read it from the returned fixture.
///
/// `wallet` is the staker wallet to stake from when the caller opened it
/// already — the market-bond walks open it before the shard fill, so its
/// scans cover the fill ahead of the retention prune
/// ([`shard::close_shard_through_the_daemon`]); `None` opens one here.
///
/// The post this builds is a kind-5 JoinMarket (`FN_DSA_HYBRID.md` §8),
/// which the Rust daemon admits. Every caller runs in
/// `scripts/ci/run_live_daemon_gates.sh`'s slow lane. A caller naming a
/// market bond (`FixtureStake::MarketBond`) closes and prices the shard
/// it names first ([`shard::close_shard_through_the_daemon`]): CEN-J15 refuses a
/// compact join onto a shard that is not closed, final and priced at the
/// parent, and the pool door judges it at commit.
async fn stake_persona_to_confirmed_bond(
    daemon: &RegtestDaemon,
    seed: &[u8; shekyl_crypto_pq::account::SEED_BYTES],
    slot_raw: u32,
    funding_cushion: u64,
    stake_entry: FixtureStake,
    wallet: Option<StakerWallet>,
) -> ConfirmedBondFixture {
    use super::stake_engine::PSlot;
    use shekyl_engine_state::pscan_state::MintLineageOutput;

    let slot = PSlot::from_raw(slot_raw);
    let SubmittedBondPost {
        arc,
        _tmp: tmp,
        principal,
        persona_id,
        pscan_seal,
        swept_gindexes,
        pre_post_discovered,
        verdict,
    } = stake_persona_and_submit_bond(daemon, seed, slot_raw, funding_cushion, stake_entry, wallet)
        .await;

    // Accepted-and-applied (the promoted PR-4a tripwire): the daemon's
    // PR-4b bond-post Phase-C battery verifies the wallet-built post over
    // real RPC. Any rejection — Phase A, Phase C, transport — fails loudly.
    let receipt = verdict.unwrap_or_else(|e| {
        daemon.panic_with_log(
            "daemon must accept the wallet-built bond post (PR-4b battery landed)",
            format!("{e:?}"),
        )
    });
    eprintln!("bond post accepted by the daemon submit engine: {receipt:?}");

    // Applied: mine the accepted post into a block, then past the scan
    // horizon, and re-run the production P-scan — the sealed state must
    // carry the persona's bond-post match (rung-2 substrate) and a
    // `BondPostChange` change-funding output beyond the pre-post set (the
    // outputs the emission-claim e2e, PR-4c, spends from).
    //
    mine_until_pool_drains(daemon, "accepted bond post", 5).await;
    daemon.generate_blocks(PSCAN_TEST_REORG_DEPTH + 2).await;
    refresh(&arc).await;
    let state = pscan_until(
        &arc,
        &pscan_seal,
        "the bond-post match + BondPostChange change funding + swept-record prune",
        |s| {
            // The swept-prune leg makes the wait deterministic: the arm-1
            // prune can land a seal batch AFTER the match does, and a
            // fixture snapshot taken between the two would carry the swept
            // pre-post record alongside the change — a phantom extra row
            // that would flake any consumer counting the slot's records
            // (the bond e2e's own prune assertion included). Wait for all
            // three writes before snapshotting.
            s.bond_post_matches()
                .iter()
                .any(|m| m.p_canonical_id == persona_id)
                && s.funding_outputs()
                    .iter()
                    .any(|r| r.p_slot == slot && r.lineage == MintLineageOutput::BondPostChange)
                && s.funding_outputs()
                    .iter()
                    .all(|r| !swept_gindexes.contains(&r.gindex.to_raw()))
        },
    )
    .await;
    let confirmed_tip_height = daemon.height().await;

    ConfirmedBondFixture {
        arc,
        _tmp: tmp,
        principal,
        persona_id,
        pscan_seal,
        state,
        swept_gindexes,
        pre_post_discovered,
        confirmed_tip_height,
    }
}

/// The first half of [`stake_persona_to_confirmed_bond`], up to and
/// including the submit: fund the principal, fund the persona, discover the
/// funding through the production P-scan, enter the stake (the production
/// `first_stake` entry or the market-bond assembly), re-lift the sealed
/// pending post and dispatch it through the audited posture→submitter
/// choke point. The verdict is returned, not judged, so one body serves
/// the confirmed-bond fixture and the FND-20 tripwire.
async fn stake_persona_and_submit_bond(
    daemon: &RegtestDaemon,
    seed: &[u8; shekyl_crypto_pq::account::SEED_BYTES],
    slot_raw: u32,
    funding_cushion: u64,
    stake_entry: FixtureStake,
    wallet: Option<StakerWallet>,
) -> SubmittedBondPost {
    use super::bond_assembly::{BondAssemblyError, PBoundBytes, SpentRecordsDurablyPruned};
    use super::bond_orchestrator::p_lane_weight_ceiling_bytes;
    use super::bond_orchestrator::FirstStakeError;
    use super::pscan::start::pending_post_store_for_engine;
    use super::stake_engine::{PSlot, StakeEngineError};
    use super::traits::DaemonEngine;
    use super::transaction_submitter::BroadcastSubmitter;
    use shekyl_archival_retention::{bond_floor, HoldingsDescriptor, HoldingsKind, ShardSet};
    use shekyl_units::AtomicUnits;

    const MINE_BATCH_BLOCKS: u64 = 10;
    const MAX_MINE_BATCHES: usize = 24;

    let slot = PSlot::from_raw(slot_raw);
    let (arc, tmp, principal) = match wallet {
        Some(opened) => opened,
        None => staker_wallet(daemon.rpc_port, seed, slot).await,
    };

    // The bond fee is caller-chosen at this seam (the RPC stake entry's
    // contract), but a hardcoded constant is wrong on regtest: the daemon's
    // per-byte floor tracks the block reward, which is enormous on a young
    // chain (~69 000/byte at these heights ⇒ ~1.55e9 for a 22.5 KB post).
    // Derive the fee from the daemon's live estimate over the size ceiling;
    // the reward only decays as the test mines, so an early estimate stays
    // sufficient, and overpaying is harmless (the fee is a miner transfer,
    // not a conservation term).
    let bond_fee = {
        let estimates = arc
            .read()
            .await
            .daemon()
            .get_fee_estimates()
            .await
            .expect("daemon fee estimates");
        estimates
            .economy
            .calculate_fee_from_weight(p_lane_weight_ceiling_bytes())
    };
    eprintln!("bond fee from daemon estimate: {bond_fee}");

    // Fund the principal past the persona's needs (2×: the transfer's own fee
    // + selection churn), then fund the persona with one `stake_in`. The
    // floor follows the entry's holdings shape.
    let floor_holdings = match &stake_entry {
        FixtureStake::FirstStake => HoldingsDescriptor {
            kind: HoldingsKind::CompleteTree,
            shard_ids: ShardSet::empty(),
        },
        FixtureStake::MarketBond(h) => h.clone(),
    };
    let funding = AtomicUnits::from_raw(
        bond_floor(
            &floor_holdings,
            shekyl_archival_retention::archival_params(),
        ) + bond_fee
            + funding_cushion,
    );
    mine_until_unlocked_at_least(
        daemon,
        &arc,
        AtomicUnits::from_raw(funding.to_raw() * 2),
        MINE_BATCH_BLOCKS,
        MAX_MINE_BATCHES,
    )
    .await;
    // The production funding: activate the persona (nothing activates one in
    // production yet — the test helper drives the actor's own activation),
    // then `stake_in`, which pays the active persona's handed-over keys.
    super::test_support::activate_persona(&*arc.read().await, slot_raw).await;
    stake_in_and_confirm(daemon, &arc, funding, MINE_BATCH_BLOCKS, MAX_MINE_BATCHES).await;

    // Discovery: push the shallow finality horizon past the funding block,
    // then run the production P-scan until the sealed state carries the
    // persona's funding output.
    daemon.generate_blocks(PSCAN_TEST_REORG_DEPTH + 2).await;
    refresh(&arc).await;
    let pscan_seal = shekyl_engine_file::paths::pscan_state_path_from(&tmp.path().join("wallet"));
    let state = pscan_until(&arc, &pscan_seal, "the persona funding output", |s| {
        s.funding_outputs().iter().any(|r| r.p_slot == slot)
    })
    .await;
    let pre_post_discovered = state
        .funding_outputs()
        .iter()
        .filter(|r| r.p_slot == slot)
        .count();
    eprintln!("pscan discovered {pre_post_discovered} persona funding output(s)");

    // The stake entry (both arms end at the same `.wallet.pending` seal —
    // `assemble_bond_post`'s seal_post — so everything downstream is
    // shared). The funding must be spendable at the anchored REFERENCE
    // block (tip − REF_ANCHOR_AGE), which lags tip maturity, so each arm
    // retries its typed not-ready refusals while mining.
    match &stake_entry {
        // Production SA-R1 entry (SP-R0 arm-#1 PRODUCTION-DISCHARGE leg):
        // preflight funding sweep → durable `persist_bond_record` → sign +
        // assemble → seal, driven exactly as the credentialed `stake` RPC
        // drives it; the `arm1_watch_pruning_live` witness is minted
        // inside the entry, so no `for_test` deviation remains here.
        FixtureStake::FirstStake => {
            let mut outcome = None;
            for _ in 0..MAX_MINE_BATCHES {
                // The fixture drives the production entry exactly as the RPC
                // does, and states its posture explicitly (D-3): this lane
                // exercises the Foundation CompleteTree bond. The
                // acknowledgment D-4 requires is an RPC-layer fact and is
                // deliberately not an engine parameter, so it has no place
                // here.
                match super::Engine::first_stake(
                    arc.clone(),
                    slot_raw,
                    super::StakePosture::SupportCompleteTree,
                )
                .await
                {
                    Ok(o) => {
                        outcome = Some(o);
                        break;
                    }
                    Err(FirstStakeError::Funding(detail)) => {
                        eprintln!("first-stake funding not ready ({detail}); mining more");
                        daemon.generate_blocks(MINE_BATCH_BLOCKS).await;
                        refresh(&arc).await;
                    }
                    // Post-persist mid-flow failure — the documented W2
                    // window (e.g. the funding output cleared the preflight
                    // sweep but is not yet drained into the REFERENCE curve
                    // tree). The production recovery is re-invoking `stake`
                    // (`persist_bond_record` is re-entrant; the resume path
                    // re-mints the ticket), so the retry exercises the W2
                    // resume exactly as a wallet would.
                    Err(FirstStakeError::Engine(detail)) => {
                        eprintln!(
                            "first-stake W2 mid-flow failure ({detail}); mining and resuming"
                        );
                        daemon.generate_blocks(MINE_BATCH_BLOCKS).await;
                        refresh(&arc).await;
                    }
                    Err(e) => daemon.panic_with_log("first_stake", e),
                }
            }
            let outcome =
                outcome.expect("first_stake must succeed once the funding is reference-spendable");
            eprintln!(
                "first_stake sealed the bond post: slot {}, {} swept input(s), resumed={}",
                outcome.p_slot, outcome.swept_inputs, outcome.resumed
            );
        }
        // Market bond: the same production functions `first_stake`
        // composes, with the holdings the entry does not yet parameterize
        // (see [`FixtureStake::MarketBond`]). Assembly authorizes on the
        // handle alone; `persist_bond_record` is idempotent, so each retry
        // re-mints a fresh ticket.
        FixtureStake::MarketBond(holdings) => {
            let fee = AtomicUnits::from_raw(bond_fee);
            let mut sealed = false;
            for _ in 0..MAX_MINE_BATCHES {
                let (handle, ticket) = {
                    let g = arc.read().await;
                    let stake = g.stake_handle().expect("staker wallet has a stake engine");
                    let handle = stake.mint_handle(slot).await.expect("mint handle");
                    let ticket = g.persist_bond_record(slot).expect("persist bond record");
                    (handle, ticket)
                };
                match super::Engine::assemble_bond_post(
                    arc.clone(),
                    handle,
                    ticket,
                    holdings.clone(),
                    fee,
                    &SpentRecordsDurablyPruned::for_test(),
                )
                .await
                {
                    Ok(a) => {
                        eprintln!(
                            "assembled market bond post: {} B, {} funding input(s)",
                            a.bound_tx.bytes().len(),
                            a.funding_gindexes.len(),
                        );
                        sealed = true;
                        break;
                    }
                    // The reference-spendability ladder, one typed arm per
                    // stage: value shortfall at the reference, empty
                    // eligible set, and swept-but-not-yet-drained into the
                    // reference tree.
                    Err(StakeEngineError::Assembly(BondAssemblyError::InsufficientFunding {
                        available,
                        required,
                    })) => {
                        eprintln!(
                            "persona funding not yet reference-spendable \
                             ({available}/{required}); mining more"
                        );
                        daemon.generate_blocks(MINE_BATCH_BLOCKS).await;
                        refresh(&arc).await;
                    }
                    Err(StakeEngineError::Assembly(BondAssemblyError::NoSpendableFunding)) => {
                        eprintln!("persona funding set empty at the reference height; mining more");
                        daemon.generate_blocks(MINE_BATCH_BLOCKS).await;
                        refresh(&arc).await;
                    }
                    Err(StakeEngineError::Assembly(BondAssemblyError::OutputNotYetDrained {
                        gindex,
                    })) => {
                        eprintln!(
                            "funding output {gindex} not yet in the reference tree; mining more"
                        );
                        daemon.generate_blocks(MINE_BATCH_BLOCKS).await;
                        refresh(&arc).await;
                    }
                    Err(e) => daemon.panic_with_log("assemble market bond post", format!("{e:?}")),
                }
            }
            assert!(
                sealed,
                "the market bond post must assemble once the funding is reference-spendable"
            );
        }
    }

    // Re-lift the sealed pending post (SA-DQ-5: `first_stake` never
    // broadcasts) and dispatch through the audited posture→submitter choke
    // point — exactly what WI-3's block-timed driver does when the post
    // comes due (see the module docs for why the driver's decorrelation
    // timing is deliberately not exercised here).
    let post = {
        let pending_gate = { arc.read().await.pending_gate.clone() };
        let store = pending_post_store_for_engine(arc.clone(), pending_gate);
        store
            .read(|block| block.posts().first().cloned())
            .await
            .expect("pending-post read")
            .expect("first_stake seals exactly one pending post")
    };
    let bound = PBoundBytes::from_pending(&post);
    let persona_id = *bound.persona();
    let swept_gindexes: Vec<u64> = post.funding_gindexes.iter().map(|g| g.to_raw()).collect();
    let daemon_client = { arc.read().await.daemon().clone() };
    let submitter = BroadcastSubmitter::local(persona_id, Arc::new(daemon_client));
    let verdict = submitter
        .submit_bound(super::transaction_submitter::BoundForSend::Loaded(bound))
        .await;

    SubmittedBondPost {
        arc,
        _tmp: tmp,
        principal,
        persona_id,
        pscan_seal,
        swept_gindexes,
        pre_post_discovered,
        verdict,
    }
}

/// PR-4 staker harness (`EMISSION_CLAIM_BUILDER.md` §8 PR-4): a staker wallet
/// funds its persona on-chain (the production `stake_in`: a wallet-built
/// FCMP++ transfer to the active persona's payment keys — rung-1
/// `ExternalTransfer` funding),
/// the production P-scan discovers the funding, and the production bond path
/// ([`Engine::assemble_bond_post`](super::Engine::assemble_bond_post) →
/// posture→submitter choke point) dispatches the bond post over real RPC.
///
/// **Accepted-and-applied (the promoted PR-4a tripwire).** The daemon's
/// PR-4b bond-post Phase-C battery (`DAEMON_SUBMIT_VERDICT.md` §8.7.1 BP
/// rows; `shekyl-daemon-rpc/src/submit/verifier.rs::verify_bond_post`)
/// verifies the wallet-built post over real RPC. The trailing assertions
/// pin the full loop: submit accepted, bond mined, and the rung-2
/// bond-post match + `BondPostChange` change funding re-discovered by this
/// same production scan, with the swept pre-post funding records PRUNED
/// from the sealed state — the SP-R0 arm-#1 **production fire** (DQ-F):
/// the stake enters through [`Engine::first_stake`], whose preflight sweep
/// mints the `arm1_watch_pruning_live` witness, so the whole
/// persist → assemble → seal → dispatch → confirm → prune loop runs on
/// production code. The surviving funding set is the `BondPostChange`
/// change — the substrate the emission-claim e2e (PR-4c) spends from.
/// (This test was the PR-4a daemon-gap tripwire pinning the old
/// unimplemented-arm `Malformed` refusal; PR-4b promoted it.)
///
/// Bounded deviations from production, each named:
/// - The sealed pending post is re-lifted (`PBoundBytes::from_pending`) and
///   dispatched directly through the audited posture→submitter choke point
///   rather than by WI-3's block-timed dispatch driver: the driver's
///   decorrelation offsets span up to ~600 blocks (its timing law has its
///   own KATs); the harness proves the chain-facing contract.
/// - A shallow P-scan finality horizon + tight cadence via the injectable
///   `start_pscan_with` seam (see [`PSCAN_TEST_REORG_DEPTH`]).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow lane (run_live_daemon_gates.sh ARMED_SLOW): requires SHEKYLD_BIN; a bonded walk (mine, fund, stake, confirm)"]
async fn e2e_staker_bond_post_accepted_and_applied() {
    use super::stake_engine::PSlot;
    use shekyl_engine_state::pscan_state::MintLineageOutput;

    const SLOT: u32 = 0;
    /// Extra persona funding above `floor + fee`, so the sweep-all bond leaves
    /// a non-zero change output — the persona's rung-2 `BondPostChange` funding
    /// (the emission-claim e2e sizes its own, larger cushion).
    const FUNDING_CUSHION: u64 = 200_000_000;

    let seed = [0x44u8; shekyl_crypto_pq::account::SEED_BYTES];
    let daemon = RegtestDaemon::start_for_seed(&seed).await;
    // Schedule guard (serial lock now held): this test's wallet epoch
    // arithmetic must run on the genesis pin. A sibling e2e that armed the
    // SEB lever in this process would otherwise bleed its schedule in
    // silently (the `OnceLock` is irreversible) — fail loudly instead.
    assert_eq!(
        shekyl_archival_retention::effective_settlement_epoch_blocks(),
        shekyl_archival_retention::SETTLEMENT_EPOCH_BLOCKS,
        "another test latched a levered settlement-epoch schedule in this process; \
         run the regtest e2es in separate processes"
    );
    let slot = PSlot::from_raw(SLOT);
    let fixture = stake_persona_to_confirmed_bond(
        &daemon,
        &seed,
        SLOT,
        FUNDING_CUSHION,
        FixtureStake::FirstStake,
        None,
    )
    .await;

    let post_change = fixture
        .state
        .funding_outputs()
        .iter()
        .filter(|r| r.p_slot == slot && r.lineage == MintLineageOutput::BondPostChange)
        .count();
    let total = fixture
        .state
        .funding_outputs()
        .iter()
        .filter(|r| r.p_slot == slot)
        .count();
    // The swept pre-post funding records are PRUNED at scan time (SP-R0
    // arm 1: the key-image watch fires on the bond post's own funding
    // spends), so the persona's surviving funding set is the bond-post
    // change — the rung-2 substrate PR-4c spends from — not a superset of
    // the pre-post record(s).
    assert!(
        fixture
            .state
            .funding_outputs()
            .iter()
            .all(|r| !fixture.swept_gindexes.contains(&r.gindex.to_raw())),
        "the swept funding record must be pruned from the sealed set (SP-R0 arm 1)"
    );
    eprintln!(
        "bond post accepted-and-applied: match re-discovered; {post_change} \
         BondPostChange output(s), {total} persona funding output(s) \
         ({} pre-post record(s) swept+pruned)",
        fixture.pre_post_discovered
    );
    // The bond post is located by its vin class at load; the fixture does
    // not surface its txid.
    maybe_capture_chain_vector(
        &daemon,
        "bond-post",
        "e2e_staker_bond_post_accepted_and_applied",
        None,
    )
    .await;
}

/// PR-4c emission-claim harness (`EMISSION_CLAIM_BUILDER.md` §8 PR-4c): the
/// full staker reward loop over real RPC — serve credit earned by the
/// persona's admitted draws (SO-D12), the epoch closed by mining under the
/// settlement-epoch lever, the
/// claim built by the production CB-3 path ([`Engine::submit_emission_claim`]
/// — no parallel builder), accepted by the daemon's PR-4b emission battery
/// (`DAEMON_SUBMIT_VERDICT.md` §8.7.2 E-rows), and **applied**: the
/// claimed-set row lands, the loud reward vout pays exactly the epoch's
/// accrued budget, and the production P-scan re-discovers the reward as the
/// persona's rung-1 [`MintLineageOutput::EmissionReward`] funding.
///
/// **Block geography.** The bond is a market bond onto shard 0, and
/// CEN-J15 admits that join only after the shard is closed, final and
/// priced by a slash pass, so the walk opens by closing the shard with
/// real wallet spends and mining through the pass that prices it
/// ([`shard::close_shard_through_the_daemon`]). The confirmed-bond fixture then
/// runs, and the epoch its join lands in — `J`, read back from the
/// daemon's bond record, at least two epochs past the pricing epoch
/// (the pass of epoch `w` is the last block of `w + 1`) — is the walk's
/// datum: the onset stagger (`good_through`: a bond is a market member
/// from `join_epoch + 1`, never in its join epoch) makes **`J + 1` the
/// first claimable epoch**. The persona earns serve credit in `J + 1`,
/// `J + 1` is mined closed, and the claim targets it. `J` closes
/// zero-work along the way — the no-staker epoch whose budget is never
/// minted (claims are wallet-timed mints; an unclaimable epoch's accrual
/// simply never enters supply) — and the claim builder must EXCLUDE it
/// and every epoch before it (`claimed_epochs == [J + 1]`), which is the
/// no-staker leg's e2e observable. The epoch is `SEB = 128` so that the
/// credit and the claim fit between the join and `J + 1`'s close wherever
/// in `J` the join lands (the claim needs `REF_ANCHOR_AGE` of room before
/// the close). The pinned ordering
/// `referenceBlock < epoch_close < claim ≤ tip` follows from
/// claiming within `REF_ANCHOR_AGE` blocks of the close (the close-detect
/// loop mines in 3-block steps so the overshoot stays inside that
/// window). Blocks between the close and the claim carry no `J + 2`
/// serve credit — the zero-staker stretch the A5b pop leg straddles.
///
/// **Conservation (A6, `§9.5 item 8`).** The claim's reward vout must equal
/// `budget_atomic(1)` byte-exactly — the daemon's per-block accrual
/// `staker_emission + staker_pool_amount` (blockchain.cpp) summed over the
/// epoch, i.e. the staker-inflow identity over real RPC. At regtest e2e
/// activity the fee-pool half is **genuinely zero by the law**, and the
/// test pins that executably. Since FL-R24 the volume operand is the exact
/// window `tx_count_sum : blocks` (no longer floored to whole tx/block), so
/// a handful of e2e txs gives a small but NONZERO `sqrt(V/B)` — the arm that
/// used to zero the burn is gone. What zeroes `burn_pct` here is the supply
/// ratio: `calc_burn_pct` forms `circulating · 10⁶ / asymptote` in SCALE
/// fixed point, which is 0 until ~4.3e15 has been emitted (≈ 2 600+ blocks
/// of the young curve), and this e2e closes `J + 1` at ~770 blocks. So
/// `compute_burn_split` legitimately yields `staker_pool_amount = 0`
/// (asserted via `total_burned == 0`, the tied observable) — and the
/// assertion is the falsifier: a longer chain or a fatter curve moves it.
/// Driving the pool half positive needs supply an e2e cannot reach;
/// the positive-pool split coverage is the B5 unit KAT family. The claim
/// itself still carries real `ToKey` fee inputs (`fee_gindexes`
/// non-empty), not the Q11 zero-fee form, so the fee-subset battery leg
/// runs live.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live Tor, about two hours: needs SHEKYLD_BIN and SHEKYL_TEST_TOR_BINARY (the pinned bundle); the persona serves its shard on an onion and the mining daemon's producer reads it over the daemon's managed Tor"]
async fn e2e_emission_claim_accepted_and_applied() {
    use super::bond_assembly::SpentRecordsDurablyPruned;
    use super::claim_dispatch::EmissionClaimRequestError;
    use super::claim_orchestrator::ClaimOrchestrationError;
    use super::emission_source::fetch_emission_claim_source;
    use super::prpc::LocalNodeRpc;
    use super::stake_engine::PSlot;
    use super::traits::DaemonEngine;
    use shekyl_curve_tree::reference::REF_ANCHOR_AGE;
    use shekyl_engine_state::pscan_state::MintLineageOutput;
    use shekyl_units::AtomicUnits;

    const SLOT: u32 = 0;
    /// The wait after each block while a drawn block's read window is open
    /// (`RegtestDaemon::watch_draws`; Rick, 2026-11-14). The producer
    /// plans up to three reads of a draw, at least `READ_SPACING` (30)
    /// blocks apart, and each waits a start delay drawn below
    /// `READ_START_SPREAD` (one target block interval, 120 s) before it
    /// dials (`shekyl-bundle-producer`). 120 s and an honest read of about
    /// 30 s over the 30 blocks between reads is 5 s a block. The read's
    /// ceiling (three fetches at their timeouts, about 38 minutes) is not
    /// paced for: a read slower than this is a miss, which the settled row
    /// shows.
    const READ_WINDOW_PACE: Duration = Duration::from_secs(5);
    /// Blocks the bond needs to confirm before its epoch ends, so the
    /// serving host is up before the epoch it serves begins.
    const BOND_ROOM: u64 = 48;
    /// How long the daemon's managed Tor may take to become usable, and the
    /// persona's serving host to pin its serve set.
    const TOR_READY: Duration = Duration::from_secs(300);
    /// Wall-clock time for the persona's onion descriptor to reach the
    /// directories before the first read of the served epoch.
    const DESCRIPTOR_SETTLE: Duration = Duration::from_secs(60);
    /// Settlement-epoch size under the lever (Rick, 2026-11-13). The
    /// producer plans a drawn block's reads in `(h, h + W₂ − M]`, at
    /// least `READ_SPACING` apart, up to `CHALLENGE_READS` of them
    /// (`shekyl-bundle-producer` `plan.rs`): three reads need
    /// `W₂ ≥ M + 2·30 + 1 = 91` with `M = FILING_MARGIN` 30, and
    /// `W₂ = SEB / 20`. At 2,000, `W₂` is 100 and every draw gets its three
    /// reads. A smaller epoch collapses the plan to one read at `h + 1`,
    /// which no producer test is written for (`scenario_shard.rs`).
    const SEB: u64 = 2_000;
    /// The reorg cap this schedule runs: strictly below the epoch (the
    /// daemon refuses `SEB ≤ cap`). It is also the shard's finality wait
    /// (J15's `closed_and_final`), so it is kept small; the walk's pops
    /// never reach it.
    const REORG_CAP: u64 = 16;
    const SCHEDULE: RegtestSchedule = RegtestSchedule {
        seb: SEB,
        reorg_cap: REORG_CAP,
    };
    const SHARD_ID: u64 = 0;
    /// Persona funding above `floor + bond fee`: becomes the sweep-all
    /// bond's `BondPostChange` change output (and the size of the second,
    /// post-bond transfer). The claim's fee must be covered by the single
    /// non-backing record alone (Q11 excludes the designated backing from
    /// the fee set), and the claim fee rides the ~48 KiB non-claims
    /// envelope at the young chain's ~69k/byte floor ≈ 3.4e9 — 12e9 gives
    /// each record standalone headroom.
    const CLAIM_FUNDING_CUSHION: u64 = 12_000_000_000;

    // (A1) Spawn the daemon FIRST — `start_with_regtest_schedule`
    // takes the e2e serial lock, so sibling `--ignored` tests cannot
    // interleave with the arming below — then arm the settlement-epoch
    // lever in THIS process before any of ITS epoch arithmetic latches
    // the genesis schedule (the daemon child is a separate process; its
    // FAKECHAIN arming reads the env at startup and is not in this race).
    //
    // Containment is honest, not perfect: the schedule is a process-wide
    // irreversible `OnceLock`, so serialization cannot UNDO a latch — if a
    // sibling ran first and did epoch arithmetic, `arm` refuses loudly
    // (`ArmedTooLate`), and if THIS test ran first, siblings that need the
    // genesis pin fail their own schedule guard (see the bond e2e) —
    // either direction is a loud named failure, never silent bleed. Run
    // the regtest e2es in separate processes (the module docs' one-test
    // invocation) for green runs.
    let seed = [0x55u8; shekyl_crypto_pq::account::SEED_BYTES];
    // Three daemons on the pinned Tor (`RegtestDaemon::start_tor_trio`):
    // the miner, which the wallet uses and whose producer reads each drawn
    // pair's shard over its Tor, and two relays, so a transaction the miner
    // originates leaves on an address-hiding session and comes back as a
    // fluff in seconds.
    let tor = RegtestDaemon::live_tor_binary();
    let (daemon, _relay_b, _relay_c) =
        RegtestDaemon::start_tor_trio(&seed, Some(SCHEDULE), tor.clone()).await;
    // The levers are set and deliberately NOT restored afterwards: they are the
    // only input `arm` reads, and once armed the schedule latch is
    // irreversible, so leaving the variable set keeps the process's two
    // views of the schedule CONSISTENT (env says levered, latch is
    // levered). Scrubbing it on the way out would leave the more dangerous
    // state — a levered process that reports no lever. Child processes do
    // not inherit it by accident: the spawn seam sets it explicitly for
    // `Some(schedule)` and `env_remove`s them for `None`.
    SCHEDULE.set_in_process_env();
    let armed = shekyl_archival_retention::arm_settlement_epoch_override_for_regtest()
        .expect("the schedule levers must arm before any epoch arithmetic latches the schedule");
    assert_eq!(armed, SEB, "armed schedule must be the lever value");

    // The shard the market bond names must be closed, final and priced
    // before the join (CEN-J15, `shekyl-chain-rules` `tx_bond.rs`): fill
    // it now, on the empty chain, and mine through the pass that prices
    // it. Everything below follows that pass, so the join epoch is read
    // from the record rather than assumed.
    let slot = PSlot::from_raw(SLOT);
    // The staker wallet opens before the fill and is the fill's spender:
    // its refresh and its P-scan then cover the fill blocks ahead of the
    // retention prune that discards their bodies two epochs after the
    // shard closes; a wallet opened after that prune cannot scan them from
    // this node (the helper's docs).
    let wallet = staker_wallet(daemon.rpc_port, &seed, slot).await;
    let pscan_seal =
        shekyl_engine_file::paths::pscan_state_path_from(&wallet.1.path().join("wallet"));
    let closed = shard::close_shard_through_the_daemon(
        &daemon,
        &wallet.0,
        &wallet.2,
        &pscan_seal,
        ShardId::from_raw(SHARD_ID),
        SCHEDULE,
    )
    .await;

    // The claimable bond must be a MARKET bond (`ShardSetCompact`): the
    // `first_stake` genesis posture (CompleteTree) is foundation-shaped and
    // market-excluded (E-2), so its Σwork is zero forever — surfaced by
    // this e2e's first close. A chain this walk captures now carries the
    // fill, the close and the pricing pass before the join, so the Rust
    // validator admits it whole.
    // The epoch after the bond's is the one the persona serves (`J + 1`).
    // Its draws are watched from here, before `J` is known: the bond lands
    // in the tip's epoch, given room to confirm in it. A block at one of
    // those heights that drew gets a read window, whichever helper mines it.
    let into_epoch = daemon.height().await % SEB;
    if SEB - into_epoch < BOND_ROOM {
        daemon.generate_blocks(SEB - into_epoch).await;
    }
    let bond_epoch = daemon.height().await / SEB;
    let w2 = SEB / shekyl_archival_retention::constants::W2_EPOCH_DIVISOR;
    daemon.watch_draws((bond_epoch + 1) * SEB..u64::MAX, w2, READ_WINDOW_PACE);
    let market_holdings = shekyl_archival_retention::HoldingsDescriptor {
        kind: shekyl_archival_retention::HoldingsKind::ShardSetCompact,
        shard_ids: shekyl_archival_retention::ShardSet::new(vec![SHARD_ID])
            .expect("one-shard holdings"),
    };
    let fixture = stake_persona_to_confirmed_bond(
        &daemon,
        &seed,
        SLOT,
        CLAIM_FUNDING_CUSHION,
        FixtureStake::MarketBond(market_holdings),
        Some(wallet),
    )
    .await;
    // The persona serves its shard on its onion, through the same pinned
    // Tor, from the bond on: its endpoint is the bond record's.
    fixture.arc.write().await.prefs_mut().device.tor_binary_path = tor.display().to_string();
    let serving = super::Engine::start_serving_if_staker(
        fixture.arc.clone(),
        &format!("http://127.0.0.1:{}", daemon.rpc_port),
    )
    .await
    .unwrap_or_else(|e| daemon.panic_with_log("start_serving_if_staker", format!("{e:?}")))
    .expect("a staker with a confirmed bond starts a serving host");
    let serving_up = Instant::now() + TOR_READY;
    while serving.posture().is_none() {
        assert!(
            Instant::now() < serving_up,
            "the persona's serving host did not pin its serve set within {TOR_READY:?}"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    daemon.await_tor_usable(TOR_READY).await;
    tokio::time::sleep(DESCRIPTOR_SETTLE).await;
    eprintln!(
        "serving: {:?}; the daemon's managed Tor is usable",
        serving.posture()
    );
    // The join epoch, from the daemon's own record: `J`. The claim targets
    // `J + 1`, the first epoch the onset stagger lets the bond serve.
    let p_id_bytes = fixture.persona_id.to_bytes();
    let join_epoch = fetch_emission_claim_source(&daemon.rpc, &p_id_bytes)
        .await
        .expect("claim-source fetch after the bond")
        .bond
        .expect("the confirmed bond has a daemon-side record")
        .join_settlement_epoch;
    let target_epoch = join_epoch + 1;
    // `J + 1`'s draws are the ones its claim is priced on: the watch
    // narrows to its blocks. A window opened at its last blocks runs on into
    // `J + 2` until that bundle is admitted.
    assert!(
        join_epoch >= bond_epoch,
        "the bond joined in epoch {join_epoch}, before the tip's epoch {bond_epoch} when it was posted"
    );
    assert!(
        daemon.height().await <= target_epoch * SEB,
        "the serving host must be up before epoch {target_epoch} begins at {}",
        target_epoch * SEB
    );
    daemon.watch_draws(
        target_epoch * SEB..(target_epoch + 1) * SEB,
        w2,
        READ_WINDOW_PACE,
    );
    // The pass of epoch `w` is the last block of `w + 1` (the grace
    // epoch), so a join J15 admits sits two epochs past the pricing
    // epoch at the earliest; and the fixture's confirmation must have
    // read a tip past the pass, or the join it reports was not judged
    // under the priced shard.
    assert!(
        join_epoch >= closed.priced_by_epoch + 2,
        "the join (epoch {join_epoch}) must follow the pass that priced the shard (epoch {}, \
         the block at {}) by the grace epoch",
        closed.priced_by_epoch,
        closed.pass_height
    );
    assert!(
        fixture.confirmed_tip_height > closed.pass_height,
        "the bond confirmed at tip {} must sit above the pricing pass at {}",
        fixture.confirmed_tip_height,
        closed.pass_height
    );
    eprintln!(
        "market bond joined in epoch {join_epoch} (shard {} closed at {} by {} spends, {} \
         archival bytes, priced by epoch {}); the claim targets epoch {target_epoch}",
        closed.shard.to_raw(),
        closed.close_height,
        closed.spends,
        closed.archival_bytes,
        closed.priced_by_epoch
    );

    // The claim spends TWO distinct persona outputs: the designated backing
    // (the membership proof — Q11 excludes it from the fee set
    // structurally, `BackingSet::fee_sweep`) and at least one fee input.
    // The sweep-all bond leaves exactly ONE (the `BondPostChange` change),
    // so fund the persona once more post-bond — an ordinary rung-1
    // ExternalTransfer to the persona's payment keys, not `stake_in`: a bonded
    // persona's funding is the one event before its bond, and `stake_in` is to
    // refuse a bonded persona once the production activation path lands
    // (`docs/FOLLOWUPS.md`). Then re-run the production P-scan so the sealed
    // state carries both records before the claim reads it.
    transfer_to(
        &daemon,
        &fixture.arc,
        persona_destination(&seed, SLOT),
        shekyl_units::AtomicUnits::from_raw(CLAIM_FUNDING_CUSHION),
        10,
        24,
    )
    .await;
    daemon.generate_blocks(PSCAN_TEST_REORG_DEPTH + 2).await;
    refresh(&fixture.arc).await;
    let state = pscan_until(
        &fixture.arc,
        &fixture.pscan_seal,
        "the post-bond fee funding (2 spendable persona records)",
        |s| {
            s.funding_outputs()
                .iter()
                .filter(|r| r.p_slot == slot)
                .count()
                >= 2
        },
    )
    .await;
    eprintln!(
        "persona holds {} funding record(s) pre-claim (backing + fee substrate)",
        state
            .funding_outputs()
            .iter()
            .filter(|r| r.p_slot == slot)
            .count()
    );

    // (A1 settle) `J + 1` is claimable once it is settled: its credits are
    // the Served settlement rows its slash pass writes, while connecting
    // the last block of `J + 2` (`EmissionEpochStanding::Settled`; the
    // claim source shows a budget only then). Mine to just short of that
    // block, then one block at a time, so the claim is made inside
    // `REF_ANCHOR_AGE` of the pass and its reference block lies before it
    // (the A5c geometry).
    let settle_height = (target_epoch + 2) * SEB - 1;
    let short_of_pass = daemon.height().await;
    if short_of_pass + 3 < settle_height {
        daemon
            .generate_blocks(settle_height - 3 - short_of_pass)
            .await;
    }
    let epoch_row = loop {
        let src = fetch_emission_claim_source(&daemon.rpc, &p_id_bytes)
            .await
            .expect("claim-source fetch");
        if let Some(row) = src
            .epochs
            .iter()
            .find(|e| e.settlement_epoch == target_epoch && e.has_budget_row)
        {
            break row.clone();
        }
        let h = daemon.height().await;
        assert!(
            h < settle_height + 64,
            "epoch {target_epoch} was not settled by height {h} (its pass connects at \
             {settle_height}; SEB {SEB})"
        );
        daemon.generate_blocks(1).await;
    };
    let total_burned_at_close = daemon.total_burned().await;
    eprintln!(
        "epoch {target_epoch} closed at {}: budget {} atomic, sigma-work {} milli, \
         {} credit pair(s); total_burned {}",
        epoch_row.close_block_height,
        epoch_row.budget_atomic,
        epoch_row.sigma_work_milli,
        epoch_row.credit_pairs.len(),
        total_burned_at_close.to_raw(),
    );
    // What the persona's serving earned: each bundle for a block of
    // `J + 1`, as the block that admitted it recorded it.
    let mut drawn = 0u32;
    let mut passed = 0u32;
    let mut first_pass_height = None;
    for height in target_epoch * SEB..daemon.height().await {
        for reference in daemon.section_at(height).await {
            if reference.h().to_raw() / SEB != target_epoch {
                continue;
            }
            drawn += reference.count();
            passed += reference.passes().popcount();
            if reference.passes().popcount() > 0 && first_pass_height.is_none() {
                first_pass_height = Some(height);
            }
        }
    }
    eprintln!(
        "epoch {target_epoch}: {drawn} draw(s) admitted, {passed} passed; the first pass \
         admitted at {first_pass_height:?}"
    );
    let first_pass_height = first_pass_height.unwrap_or_else(|| {
        daemon.panic_with_log(
            "no draw of the served epoch passed",
            format!("{drawn} draw(s) admitted in epoch {target_epoch}"),
        )
    });
    assert!(
        !epoch_row.credit_pairs.is_empty(),
        "the served pair must surface in the closed epoch's credit pairs"
    );
    assert!(
        epoch_row.sigma_work_milli > 0,
        "the closed epoch must carry the served work (membership from join+1)"
    );
    assert!(
        epoch_row.budget_atomic > 0,
        "the closed epoch must have accrued a positive budget"
    );
    assert!(
        epoch_row.claimant_bond_idx.is_some(),
        "the fixture's bond must be a claimant in the closed epoch"
    );
    // A6 pool-half disposition (module docs): at e2e activity the integer
    // per-block volume mean floors to 0, a zero volume operand zeroes
    // `burn_pct`, and `compute_burn_split` then yields a zero pool half AND
    // a zero destroyed half from the same `burned` product — `total_burned`
    // is the tied observable, pinned here so an operand-law change
    // re-surfaces this disposition instead of silently shifting the budget.
    assert_eq!(
        total_burned_at_close,
        shekyl_units::AtomicUnits::ZERO,
        "regtest e2e activity must floor the volume mean to 0 ⇒ zero fee burn \
         (pool-half disposition, §9.5 item 8; positive-pool coverage is the B5 KATs)"
    );
    // The no-staker epoch: `J` (the join epoch) closed zero-work — its
    // budget row exists but Σwork is 0, so nothing of it is claimable and
    // its accrual never mints (never enters supply).
    let src_now = fetch_emission_claim_source(&daemon.rpc, &p_id_bytes)
        .await
        .expect("claim-source fetch");
    let join_epoch_row = src_now
        .epochs
        .iter()
        .find(|e| e.settlement_epoch == join_epoch && e.has_budget_row)
        .expect("the join epoch must have closed with a budget row");
    assert_eq!(
        join_epoch_row.sigma_work_milli, 0,
        "the join epoch must close zero-work (onset stagger: no membership in the join epoch)"
    );

    // (A3) Build and dispatch the claim through the production CB-3 path.
    // The fee rides swept `ToKey` inputs; derive it from the daemon's live
    // estimate over the claim's own production envelope — the ~48 KiB
    // `EMISSION_NON_CLAIMS_RESERVE_BYTES` (two fee-side FCMP++ proofs +
    // hybrid PQC auths + 16-vout worst case + Bp+ clawback) plus a small
    // vin allowance for the single claim row. The bond's 32 KiB ceiling is
    // too small here — a claim carries TWO input proofs where the bond
    // carries one (live run 4's daemon-side `FeeTooLow`); overpaying is a
    // miner transfer, never a conservation term.
    use super::emission_claim::EMISSION_NON_CLAIMS_RESERVE_BYTES;
    refresh(&fixture.arc).await;
    let claim_fee = {
        let estimates = fixture
            .arc
            .read()
            .await
            .daemon()
            .get_fee_estimates()
            .await
            .expect("daemon fee estimates");
        estimates
            .economy
            .calculate_fee_from_weight(EMISSION_NON_CLAIMS_RESERVE_BYTES + 2048)
    };
    let claim_rpc = LocalNodeRpc::new(
        format!("http://127.0.0.1:{}", daemon.rpc_port),
        Duration::from_secs(10),
    )
    .await
    .expect("loopback claim transport");
    let pruning_landed = SpentRecordsDurablyPruned::for_test();
    let mut receipt = None;
    let mut tip_before_claim = 0;
    for attempt in 0..4 {
        tip_before_claim = daemon.height().await;
        match super::Engine::submit_emission_claim(
            fixture.arc.clone(),
            &claim_rpc,
            slot,
            AtomicUnits::from_raw(claim_fee),
            &pruning_landed,
        )
        .await
        {
            Ok(r) => {
                receipt = Some(r);
                break;
            }
            // Resync-and-retry arms (the wallet's own docs): the tree or
            // header window lags the tip. Mine ONE block per retry — the
            // pinned ordering needs the successful attempt's reference to
            // stay below the close.
            Err(EmissionClaimRequestError::Claim(
                e @ (ClaimOrchestrationError::ReferenceUnanchorable { .. }
                | ClaimOrchestrationError::MissingBlockHash { .. }),
            )) => {
                eprintln!("claim attempt {attempt}: {e}; resyncing");
                daemon.generate_blocks(1).await;
                refresh(&fixture.arc).await;
            }
            Err(e) => daemon.panic_with_log("submit_emission_claim", e),
        }
    }
    let receipt = receipt.expect("claim must assemble and dispatch within the retry budget");
    eprintln!(
        "emission claim accepted: epochs {:?}, reward {}, {} fee input(s)",
        receipt.claim.claimed_epochs,
        receipt.claim.total_reward,
        receipt.claim.fee_gindexes.len(),
    );

    // (A4/A6) The dispatched claim's shape: `J + 1` claimed, real ToKey fee
    // inputs (not the Q11 zero-fee form), and the loud vout equal to the
    // epoch's whole budget byte-exactly (single claimant holding all Σwork
    // ⇒ `floor(budget·capped/Σwork) = budget`) — the staker-inflow
    // conservation identity `inflow = staker_emission + staker_pool_amount`
    // over real RPC.
    assert_eq!(
        receipt.claim.claimed_epochs,
        vec![target_epoch],
        "the claim must claim exactly the work-bearing epoch — the zero-work join epoch \
         is EXCLUDED (the no-staker leg: unclaimable accrual never mints)"
    );
    assert!(
        !receipt.claim.fee_gindexes.is_empty(),
        "the claim must carry real ToKey fee inputs (A6)"
    );
    assert_eq!(
        receipt.claim.total_reward, epoch_row.budget_atomic,
        "single-claimant reward must equal the epoch's accrued budget byte-exactly \
         (conservation, both inflow halves)"
    );
    // Pinned geography: first pass < referenceBlock < epoch_close < claim tip.
    // The wallet anchors at `synced_tip − REF_ANCHOR_AGE`; `tip_before_claim`
    // is the daemon height the successful attempt saw.
    let reference_est =
        (shekyl_types::BlockHeight::from_raw(tip_before_claim) - REF_ANCHOR_AGE).to_raw();
    assert!(
        first_pass_height < reference_est,
        "the first pass ({first_pass_height}) must precede the claim reference (~{reference_est})"
    );
    assert!(
        epoch_row.close_block_height < reference_est && reference_est < settle_height,
        "the claim reference (~{reference_est}) must lie after the close ({}) and before \
         the settlement pass ({settle_height}) — the A5c pop-through-reference geometry",
        epoch_row.close_block_height
    );

    // Applied: mine the claim in, then past the scan horizon; the daemon's
    // claimed-set row must land and the production P-scan must re-discover
    // the reward as the persona's rung-1 EmissionReward funding, amount
    // equal to the loud vout.
    mine_until_pool_drains(&daemon, "accepted emission claim", 1).await;
    // Capture HERE, with the claim connected and before the A5 pops below —
    // the chain the validator's fixtures need is the one that carries the
    // claim, not the one that stranded it.
    maybe_capture_chain_vector(
        &daemon,
        "emission-claim",
        "e2e_emission_claim_accepted_and_applied",
        None,
    )
    .await;
    let claim_mined_by_height = daemon.height().await;
    assert!(
        epoch_row.close_block_height < claim_mined_by_height,
        "claim mined ({claim_mined_by_height}) after the close ({})",
        epoch_row.close_block_height
    );
    let src = fetch_emission_claim_source(&daemon.rpc, &p_id_bytes)
        .await
        .expect("claim-source refetch");
    let claimed = src
        .bond
        .as_ref()
        .expect("bond context after claim")
        .claimed_settlement_epochs
        .clone();
    assert!(
        claimed.contains(&target_epoch),
        "the daemon's claimed-set row for epoch {target_epoch} must land (got {claimed:?})"
    );

    // ── (A5a) Depth-1 pop: undo exactly the claim block ──
    // The batch-1 drain left the claim block as the tip. Popping it must
    // clear the daemon's claimed-set row and return the claim tx to the
    // pool (`pop_block_from_blockchain` is tx-conserving), with the budget
    // row untouched (the pop stays above the close); re-mining must
    // re-include the identical bytes (popped txs re-enter at
    // `relay_method::block`, broadcast-visible — no embargo) and re-apply
    // the claimed-set row, the conservation operands byte-identical.
    let tip_with_claim = daemon.height().await;
    daemon.pop_blocks(1).await;
    let src_popped = fetch_emission_claim_source(&daemon.rpc, &p_id_bytes)
        .await
        .expect("claim-source after depth-1 pop");
    let claimed_after_pop = &src_popped
        .bond
        .as_ref()
        .expect("bond context after depth-1 pop")
        .claimed_settlement_epochs;
    assert!(
        !claimed_after_pop.contains(&target_epoch),
        "depth-1 pop must clear the claimed-set row (got {claimed_after_pop:?})"
    );
    let row_popped = src_popped
        .epochs
        .iter()
        .find(|e| e.settlement_epoch == target_epoch && e.has_budget_row)
        .expect("the budget row must survive a pop above the close");
    assert_eq!(
        row_popped.budget_atomic, epoch_row.budget_atomic,
        "the budget row must be untouched by a pop above the close"
    );
    let pool_after_pop = daemon.tx_pool_size().await;
    assert_eq!(
        pool_after_pop, 1,
        "the popped claim tx must return to the pool"
    );
    daemon.generate_blocks(1).await;
    let pool_after_remine = daemon.tx_pool_size().await;
    assert_eq!(
        pool_after_remine, 0,
        "the re-mined block must re-include the claim"
    );
    assert_eq!(daemon.height().await, tip_with_claim);
    let src_remined = fetch_emission_claim_source(&daemon.rpc, &p_id_bytes)
        .await
        .expect("claim-source after depth-1 re-mine");
    assert!(
        src_remined
            .bond
            .as_ref()
            .expect("bond context after re-mine")
            .claimed_settlement_epochs
            .contains(&target_epoch),
        "re-mining the identical claim must re-apply the claimed-set row"
    );
    let row_remined = src_remined
        .epochs
        .iter()
        .find(|e| e.settlement_epoch == target_epoch && e.has_budget_row)
        .expect("budget row after re-mine");
    assert_eq!(
        (row_remined.budget_atomic, row_remined.sigma_work_milli),
        (epoch_row.budget_atomic, epoch_row.sigma_work_milli),
        "conservation operands must hold byte-identically across pop + re-mine (A5a)"
    );
    eprintln!("A5a depth-1 pop/re-mine: claimed-set cleared and re-applied byte-identically");

    // ── (A5b) Settlement-straddling pop: undo the pass that settled `J + 1` ──
    // `J + 1`'s settlement rows are written while connecting the last block
    // of `J + 2` (`settle_height`), and the claim is admitted only against
    // them. Popping that block and the ones after it must withdraw the
    // settlement and the claimed-set row together; re-mining must settle
    // `J + 1` again from the same passes byte-identically, then re-apply
    // the claim. No block of `J + 1` is popped, so no draw is made again.
    let tip = daemon.height().await;
    let straddle_depth = tip - settle_height;
    daemon.pop_blocks(straddle_depth).await;
    let src_straddle = fetch_emission_claim_source(&daemon.rpc, &p_id_bytes)
        .await
        .expect("claim-source after straddling pop");
    assert!(
        !src_straddle
            .epochs
            .iter()
            .any(|e| e.settlement_epoch == target_epoch && e.has_budget_row),
        "the straddling pop must withdraw the settlement (no budget shown)"
    );
    if let Some(bond) = src_straddle.bond.as_ref() {
        assert!(
            !bond.claimed_settlement_epochs.contains(&target_epoch),
            "the straddling pop must clear the claimed-set row"
        );
    }
    mine_until_pool_drains(&daemon, "re-applied emission claim (A5b)", 1).await;
    let src_resettled = fetch_emission_claim_source(&daemon.rpc, &p_id_bytes)
        .await
        .expect("claim-source after re-settlement");
    let row_resettled = src_resettled
        .epochs
        .iter()
        .find(|e| e.settlement_epoch == target_epoch && e.has_budget_row)
        .expect("the epoch must settle again from the same passes");
    assert_eq!(
        (row_resettled.budget_atomic, row_resettled.sigma_work_milli),
        (epoch_row.budget_atomic, epoch_row.sigma_work_milli),
        "the re-settled epoch must be byte-identical (no block of the served epoch \
         was popped)"
    );
    assert!(
        src_resettled
            .bond
            .as_ref()
            .expect("bond context after re-settlement")
            .claimed_settlement_epochs
            .contains(&target_epoch),
        "the claim must re-apply after the re-settlement (A5b)"
    );
    eprintln!(
        "A5b straddling pop (depth {straddle_depth}, floor {settle_height}): settlement \
         withdrawn and made again byte-identically, claim re-applied"
    );

    daemon.generate_blocks(PSCAN_TEST_REORG_DEPTH + 2).await;
    refresh(&fixture.arc).await;
    let expected_reward = receipt.claim.total_reward;
    let state = pscan_until(
        &fixture.arc,
        &fixture.pscan_seal,
        "the EmissionReward funding output",
        |s| {
            s.funding_outputs().iter().any(|r| {
                r.p_slot == slot
                    && r.lineage == MintLineageOutput::EmissionReward
                    && r.amount.to_raw() == expected_reward
            })
        },
    )
    .await;
    let rewards = state
        .funding_outputs()
        .iter()
        .filter(|r| r.p_slot == slot && r.lineage == MintLineageOutput::EmissionReward)
        .count();
    eprintln!(
        "emission claim accepted-and-applied: claimed-set {claimed:?}; {rewards} \
         EmissionReward output(s) of {expected_reward} atomic re-discovered by the \
         production P-scan (first pass {first_pass_height} < close {} < ref ~{reference_est} < \
         settlement pass {settle_height} < claim ≤ {claim_mined_by_height})",
        epoch_row.close_block_height,
    );

    // ── (A5c) Deep pop through the claim's reference block ──
    // The pop floor sits just below the claim's reference anchor, above
    // `J + 1`'s blocks, so the pop undoes the claim, the settlement pass,
    // and the block the claim's FCMP++ membership proof anchors to.
    // Re-mined blocks carry new hashes, so the popped claim tx is
    // structurally stranded — its proof binds a reference root that no
    // longer exists on the rebuilt chain. The correct terminal state: the
    // chain re-converges to the same height (the stranded tx must never
    // re-apply or wedge the miner), the claimed epoch settles again
    // byte-identically from the same passes, and the
    // claimed-set stays EMPTY. Building the replacement claim against the
    // rebuilt root is the retire/resubmit slice (the named B2 follow-on,
    // matching the bond precedent): the wallet's one-live-claim-per-persona
    // rule holds the pending record until that slice retires it.
    let tip_c = daemon.height().await;
    let pop_floor_c = reference_est - 1;
    assert!(
        pop_floor_c >= (target_epoch + 1) * SEB,
        "the A5c floor ({pop_floor_c}) must stay above the served epoch's blocks (to {})",
        (target_epoch + 1) * SEB - 1
    );
    let depth_c = tip_c - pop_floor_c;
    daemon.pop_blocks(depth_c).await;
    daemon.generate_blocks(depth_c).await;
    assert_eq!(
        daemon.height().await,
        tip_c,
        "the chain must re-converge past the stranded claim (no miner wedge)"
    );
    let src_c = fetch_emission_claim_source(&daemon.rpc, &p_id_bytes)
        .await
        .expect("claim-source after deep-pop re-mine");
    let row_c = src_c
        .epochs
        .iter()
        .find(|e| e.settlement_epoch == target_epoch && e.has_budget_row)
        .expect("the claimed epoch must settle again on the rebuilt chain");
    assert_eq!(
        (row_c.budget_atomic, row_c.sigma_work_milli),
        (epoch_row.budget_atomic, epoch_row.sigma_work_milli),
        "the rebuilt settlement must be byte-identical (no block of the served epoch was popped)"
    );
    if let Some(bond) = src_c.bond.as_ref() {
        assert!(
            !bond.claimed_settlement_epochs.contains(&target_epoch),
            "the stranded claim must NOT re-apply against the rebuilt root (its proof \
             binds a popped reference)"
        );
    }
    eprintln!(
        "A5c deep pop (depth {depth_c}, floor {pop_floor_c} < ref): chain re-converged, \
         epoch settled again byte-identically, claimed-set empty (stranded claim inert) — \
         replacement claim is the B2 retire/resubmit slice"
    );
}

/// DS-PR-2 **T-DS-6 ∧ T-DS-7 composite wire-shape arm — the full
/// transfer-vs-drain byte-diff over real end-to-end txs**
/// (`ARCHIVAL_DRAIN_SEND_FD2.md` §5 composite arm; the in-slice
/// drain-vs-drain normalized diff rode DS-PR-1, and the design pins the
/// "against a real transfer" byte-diff to this DS-PR-2 regtest e2e — "a real
/// end-to-end transfer tx must exist to diff against").
///
/// A real 1-in/2-out confidential **transfer** (the ordinary `sign_tx` send
/// path) and a real 1-in/2-out `P`→principal **drain** ([`Engine::submit_drain`])
/// must serialize byte-identically once their hidden/committed/priced leaves
/// are flattened: the drain wears the modal transfer's wire skeleton — no
/// output-count (T-DS-6), no `tx_extra` / `unlock_time` / `ct_type`
/// distinguisher (T-DS-7), no proof-arity tell. Parity is already
/// compile-time by construction (both build their `WireEncodeInput` through
/// the single shared [`assemble_transfer_wire`](super::sign_bridge) constructor);
/// this e2e is the final confirmation over the live boundary, and both txs are
/// **daemon-accepted** (consensus verify at submit), so the arm is proven on
/// real, on-chain-valid bytes rather than a builder artifact.
///
/// The transfer is a small principal self-send (one large coinbase input, two
/// confidential outputs: recipient + change). The drain is a PARTIAL sweep of
/// the persona's single `BondPostChange` funding record (one input, principal
/// payment + `P`-space change), sized so change ≥ [`EXIT_FEE_RESERVE_ATOMIC`]
/// — a live persona keeps its exit-fee reserve (DS-4). Fees differ (transfer
/// weight-priced, drain caller-priced), so [`normalize_fcmp_wire_shape`]
/// flattens the public `fee` alongside the hidden leaves; the raw bytes are
/// asserted distinct first, so the normalized equality is not vacuous.
///
/// [`normalize_fcmp_wire_shape`]: super::test_support::normalize_fcmp_wire_shape
///
/// [`EXIT_FEE_RESERVE_ATOMIC`]: shekyl_standoff::EXIT_FEE_RESERVE_ATOMIC
#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow lane (run_live_daemon_gates.sh ARMED_SLOW): requires SHEKYLD_BIN; a bonded walk (mine, fund, stake, confirm)"]
async fn e2e_drain_wire_shape_matches_a_real_transfer() {
    use super::drain_dispatch::DrainRequestError;
    use super::drain_orchestrator::DrainOrchestrationError;
    use super::pending::{FeePriority, TxDestination, TxRecipient, TxRequest};
    use super::stake_engine::PSlot;
    use super::traits::DaemonEngine;
    use shekyl_standoff::EXIT_FEE_RESERVE_ATOMIC;
    use shekyl_units::AtomicUnits;
    use shekyl_wire::{Ct, Input, Transaction};

    const SLOT: u32 = 0;
    /// The bond's change — ≈ this cushion — returns to `P` as **two** split
    /// halves (`bond.rs` `change_lo`/`change_hi`: every tx carries two
    /// nonzero outputs, and the bond post's non-change vout is the bond vin's
    /// side, not a spendable output). Sized so the LARGER half alone covers
    /// `payment + fee + reserve`: largest-first selection then takes exactly
    /// one input and the drain stays a 1-in/2-out partial — the shape the
    /// byte-diff below compares against the 1-in/2-out transfer.
    const FUNDING_CUSHION: u64 = 40_000_000_000;

    let seed = [0x66u8; shekyl_crypto_pq::account::SEED_BYTES];
    let daemon = RegtestDaemon::start_for_seed(&seed).await;
    // Schedule guard (serial lock now held): a sibling e2e that armed the SEB
    // lever in this process would bleed its schedule in silently (the
    // `OnceLock` is irreversible) — fail loudly instead.
    assert_eq!(
        shekyl_archival_retention::effective_settlement_epoch_blocks(),
        shekyl_archival_retention::SETTLEMENT_EPOCH_BLOCKS,
        "another test latched a levered settlement-epoch schedule in this process; \
         run the regtest e2es in separate processes"
    );
    let slot = PSlot::from_raw(SLOT);
    let fixture = stake_persona_to_confirmed_bond(
        &daemon,
        &seed,
        SLOT,
        FUNDING_CUSHION,
        FixtureStake::FirstStake,
        None,
    )
    .await;
    let principal = fixture.principal.clone();

    // The confirmed sweep-all bond leaves exactly TWO persona funding
    // records — the change's split halves (`change_lo`/`change_hi`). This
    // assertion said "exactly one" from its birth (2026-07-21) against an
    // assembly that has split the change since 2026-07-05, so the count it
    // pinned was never this fixture's real state — the mismatch surfaced
    // only when this walk was next run (2026-09-03, the PR-C battery).
    // Corrected to the assembly's actual invariant; the 1-in/2-out drain
    // shape below is preserved by the cushion sizing (the larger half alone
    // covers payment + fee, so largest-first selection takes one input).
    let persona_records = fixture
        .state
        .funding_outputs()
        .iter()
        .filter(|r| r.p_slot == slot)
        .count();
    assert_eq!(
        persona_records, 2,
        "the confirmed sweep-all bond must leave exactly the two split \
         change halves as persona funding records"
    );

    // ── A real 1-in/2-out transfer: capture its build-time wire bytes ──
    // A small principal self-send covered by a single coinbase output. Retry
    // past the C2 reference-spendability gate exactly as `transfer_to` does;
    // `PendingTx::tx_bytes` carries the signed bytes (build-time reference; the
    // skeleton diff zeroes `reference_block`, so a submit-time re-anchor is
    // irrelevant to the shape).
    refresh(&fixture.arc).await;
    let request = TxRequest {
        recipients: vec![TxRecipient {
            destination: TxDestination::Address(principal.clone()),
            amount_atomic_units: AtomicUnits::from_raw(100_000_000),
            rid: None,
        }],
        priority: FeePriority::Standard,
    };
    let mut built = None;
    for _ in 0..24 {
        let attempt = {
            let g = fixture.arc.read().await;
            g.build_pending_tx(&request).await
        };
        match attempt {
            Ok(p) => {
                built = Some(p);
                break;
            }
            Err(super::error::SendError::OutputNotYetSpendable { .. }) => {
                daemon.generate_blocks(10).await;
                refresh(&fixture.arc).await;
            }
            Err(e) => panic!("build transfer: {e:?}"),
        }
    }
    let built = built.expect("transfer must build once reference-spendable");
    let transfer_bytes = built.tx_bytes.clone();
    {
        let g = fixture.arc.read().await;
        g.submit_pending_tx(built.id, built.content_gen)
            .await
            .expect("daemon must accept the transfer (consensus verify)");
    }
    mine_until_pool_drains(&daemon, "accepted transfer", 1).await;
    refresh(&fixture.arc).await;

    // ── A real 1-in/2-out drain: assemble + dispatch through submit_drain ──
    // Caller-priced fee over a generous envelope (overpay is a miner transfer,
    // never a conservation term); the daemon's acceptance at submit is the
    // real-bytes proof. Payment + fee + reserve < record ⇒ change > 0 and ≥
    // the exit-fee reserve (live persona), so the drain stays a partial
    // 1-in/2-out sweep.
    let drain_fee = {
        let estimates = fixture
            .arc
            .read()
            .await
            .daemon()
            .get_fee_estimates()
            .await
            .expect("daemon fee estimates");
        estimates.economy.calculate_fee_from_weight(32_768)
    };
    let drain_payment = AtomicUnits::from_raw(2_000_000_000);
    // The 1-input guarantee: the LARGER change half (≥ cushion/2) must alone
    // cover payment + fee (+ the reserve headroom the whole pool keeps).
    assert!(
        FUNDING_CUSHION / 2 > drain_payment.to_raw() + drain_fee + EXIT_FEE_RESERVE_ATOMIC,
        "fixture must keep the partial drain's change ≥ the exit-fee reserve \
         (payment {} + fee {drain_fee} + reserve {EXIT_FEE_RESERVE_ATOMIC} < cushion \
         {FUNDING_CUSHION})",
        drain_payment.to_raw(),
    );
    let mut receipt = None;
    for attempt in 0..24 {
        match super::Engine::submit_drain(
            fixture.arc.clone(),
            slot,
            super::drain_orchestrator::DrainIntent::Payment(drain_payment),
            AtomicUnits::from_raw(drain_fee),
            &super::bond_assembly::SpentRecordsDurablyPruned::for_test(),
        )
        .await
        {
            Ok(r) => {
                receipt = Some(r);
                break;
            }
            // Resync-and-retry: the tree or header window lags the tip, OR
            // the change halves are not yet mature/provable at the anchored
            // reference — the aggregate the affordability check reads is the
            // MATURE subset, so `Unaffordable` is transient here exactly
            // like the reference lag (the same maturity ladder every other
            // walk stage runs).
            Err(DrainRequestError::Drain(
                e @ (DrainOrchestrationError::ReferenceUnanchorable { .. }
                | DrainOrchestrationError::Plan(
                    super::drain_orchestrator::DrainError::Unaffordable,
                )),
            )) => {
                eprintln!("drain attempt {attempt}: {e}; mining and resyncing");
                daemon.generate_blocks(3).await;
                refresh(&fixture.arc).await;
            }
            Err(e) => daemon.panic_with_log("submit_drain", e),
        }
    }
    let receipt = receipt.expect("drain must assemble and dispatch within the retry budget");
    let drain_bytes = receipt.drain.bound_tx.bytes().to_vec();
    eprintln!(
        "drain accepted by daemon: {} swept input(s), payment {}",
        receipt.drain.funding_gindexes.len(),
        drain_payment.to_raw(),
    );
    mine_until_pool_drains(&daemon, "accepted drain", 1).await;

    // ── The byte-diff: normalized skeletons identical, raw bytes distinct ──
    let mut cursor: &[u8] = &transfer_bytes;
    let transfer_tx = Transaction::read(&mut cursor).expect("transfer parses whole");
    assert!(cursor.is_empty(), "transfer bytes fully consumed");
    let mut cursor: &[u8] = &drain_bytes;
    let drain_tx = Transaction::read(&mut cursor).expect("drain parses whole");
    assert!(cursor.is_empty(), "drain bytes fully consumed");

    // Structural variables the normalizer does NOT flatten — a count delta
    // would survive the normalized diff, but pin them explicitly so a harness
    // change (a 2-in coinbase spend, a builder dummy output) fails loudly here
    // rather than as an opaque byte mismatch below.
    for (label, tx) in [("transfer", &transfer_tx), ("drain", &drain_tx)] {
        assert_eq!(
            tx.prefix.outputs.len(),
            2,
            "{label} must be the modal 2-out shape"
        );
        let tokey = tx
            .prefix
            .inputs
            .iter()
            .filter(|i| matches!(i, Input::ToKey { .. }))
            .count();
        assert_eq!(tokey, 1, "{label} must spend exactly one ToKey input");
        assert_eq!(
            tx.prefix.unlock_time, 0,
            "{label} unlock_time must be builder-zeroed"
        );
        assert!(
            matches!(tx.ct, Ct::Fcmp { .. }),
            "{label} must be an FCMP++ spend"
        );
    }

    // Non-vacuous: the raw bytes genuinely differ (distinct hidden amounts,
    // fees, keys) — otherwise the normalized equality below proves nothing.
    assert_ne!(
        super::test_support::whole_tx_wire_bytes(&transfer_tx),
        super::test_support::whole_tx_wire_bytes(&drain_tx),
        "raw transfer/drain bytes must differ"
    );

    let mut transfer_norm = transfer_tx;
    let mut drain_norm = drain_tx;
    super::test_support::normalize_fcmp_wire_shape(&mut transfer_norm);
    super::test_support::normalize_fcmp_wire_shape(&mut drain_norm);
    assert_eq!(
        super::test_support::whole_tx_wire_bytes(&transfer_norm),
        super::test_support::whole_tx_wire_bytes(&drain_norm),
        "a real drain is wire-identical to a real modal 2-out transfer modulo \
         hidden/committed/priced leaves — no output-count (T-DS-6), tx_extra / \
         unlock_time / ct_type (T-DS-7), or proof-arity distinguisher"
    );

    eprintln!(
        "T-DS-6 ∧ T-DS-7 e2e: a real drain is byte-identical to a real transfer \
         (normalized skeleton), both daemon-accepted"
    );
}

/// The **daemon walk** (`PRINCIPAL_STAKE_LIFECYCLE.md` PR-P4; the FOLLOWUPS
/// registration this discharges): the byte-level proposition the engine walk
/// (`retire_walk.rs`) structurally cannot judge — *the `Release` bytes the
/// wallet assembles are the bytes consensus accepts*. Before this test,
/// nothing had ever put a `Release` on a wire; `RF-D9` is the precedent for
/// why that is a proposition only building can settle (a serve-credit wire
/// that round-tripped in Rust and had never been through the C++ oracle
/// failed on first contact, twice, with misattributed errors).
///
/// The walk drives the **production dispatch seam**
/// ([`Engine::submit_release`]) — never a test shim: record fetch over the
/// persona-isolated transport, readiness via consensus's own predicates,
/// sweep-all funding, `AssembleRelease` in the actor, the `PendingRelease`
/// persist-before-dispatch seal, and the posture→submitter choke point —
/// against a real daemon over real RPC. Two assertions ARE the proposition:
///
/// - **submit-accept**: native `tx_submit` (the §8.7.1.1 UB
///   battery, `verify_release_bond_post` — the same function the block path
///   calls) admits the wallet-built exit;
/// - **block-connect**: after mining, the daemon's bond-record row is
///   **present with `bonded_total == 0`** — presence plus zero, the
///   connect's own write (`apply_archival_release` preserves the row and
///   zeroes the balance; the debit arm's terminal fact is the *balance*,
///   never row absence), observed as a transition from the pre-submit
///   read's positive balance.
///
/// **The cooldown predicates are vacuous on this walk, by design.** The
/// persona never serves (serve credit comes only from admitted draws, and
/// this walk files no bundle), so
/// `release_cooldown_elapsed(None, _)` and `slashes_settled_through(_, None)`
/// are both `true`. A *served* persona's exit waits on the slash
/// watermark, which advances one settlement epoch
/// (`SLASH_GRACE_EPOCHS · SEB`) past the anchor epoch's close — denominated
/// in epochs since DRS-E4 commit 5, so a levered SEB shortens it with the
/// epoch and the L16 pin (`RELEASE_COOLDOWN_EPOCHS > SLASH_GRACE_EPOCHS`)
/// holds on every schedule. The served-exit arms (cooldown, watermark,
/// interval log) are PR-A's unit battery (`submit_verifier.rs`), NOT this
/// walk — "the walk ran" must never be read as "the served-exit arc is
/// covered".
///
/// **The schedule is levered (`SEB = 32`), for the join and not for the
/// exit.** The bond is a market bond, and CEN-J15 admits a compact join
/// only onto a shard that is closed, final and priced by a slash pass
/// ([`shard::close_shard_through_the_daemon`]); the production epoch never
/// settles inside a test, so the walk takes a short one and arms the
/// wallet to match; an unserved persona's exit itself needs no lever.
///
/// Reachability history: when this walk landed (PR-B) the seam's only
/// caller was this test and wallet-RPC `unstake` was RESERVED; PR-C's
/// composed verb (`StakeFacade::unstake` / `collect_unstaked`) lifted that
/// gate, and the composed-arc walk below
/// (`e2e_unstake_collect_retire_composed_arc`) drives those product
/// façades end-to-end. This walk keeps the seam-level byte proposition:
/// it exists so a façade-layer regression can never mask a wire one.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow lane (run_live_daemon_gates.sh ARMED_SLOW): requires SHEKYLD_BIN; a market-bond walk (close and price the shard, fund, stake, release)"]
async fn e2e_release_accepted_and_connected() {
    use super::bond_assembly::{BondAssemblyError, SpentRecordsDurablyPruned};
    use super::emission_source::fetch_claim_source_for;
    use super::prpc::LocalNodeRpc;
    use super::release_dispatch::ReleaseRequestError;
    use super::stake_engine::{PSlot, StakeEngineError};
    use shekyl_archival_retention::bond_floor;

    const SLOT: u32 = 0;
    const SHARD_ID: u64 = 0;
    /// Persona funding above `floor + bond fee`: becomes the sweep-all bond's
    /// `BondPostChange` change output — the funding record the exit then
    /// sweeps (its fee is covered by the released collateral, so the cushion
    /// only needs to exist, not to price anything).
    const FUNDING_CUSHION: u64 = 12_000_000_000;
    /// A short epoch so the shard's pricing pass is a few dozen blocks
    /// away (doc comment); the cap sits inside it and is the shard's
    /// finality wait.
    const SEB: u64 = 32;
    const SCHEDULE: RegtestSchedule = RegtestSchedule {
        seb: SEB,
        reorg_cap: 8,
    };

    // Arm the levered schedule BEFORE any wallet-side epoch arithmetic
    // (the claim e2e's arming shape and its containment caveats: the
    // latch is irreversible and per-process — run this walk alone).
    let seed = [0x66u8; shekyl_crypto_pq::account::SEED_BYTES];
    let daemon = RegtestDaemon::start_for_seed_with_schedule(&seed, Some(SCHEDULE)).await;
    SCHEDULE.set_in_process_env();
    let armed = shekyl_archival_retention::arm_settlement_epoch_override_for_regtest()
        .expect("the schedule levers must arm before any epoch arithmetic latches the schedule");
    assert_eq!(armed, SEB, "armed schedule must be the lever value");
    let slot = PSlot::from_raw(SLOT);

    // The shard the market bond names must be closed, final and priced
    // before the join (CEN-J15): fill it on the empty chain and mine
    // through the pass that prices it.
    // The staker wallet opens before the fill and is the fill's spender:
    // its refresh and its P-scan then cover the fill blocks ahead of the
    // retention prune that discards their bodies two epochs after the
    // shard closes; a wallet opened after that prune cannot scan them from
    // this node (the helper's docs).
    let wallet = staker_wallet(daemon.rpc_port, &seed, slot).await;
    let pscan_seal =
        shekyl_engine_file::paths::pscan_state_path_from(&wallet.1.path().join("wallet"));
    let closed = shard::close_shard_through_the_daemon(
        &daemon,
        &wallet.0,
        &wallet.2,
        &pscan_seal,
        ShardId::from_raw(SHARD_ID),
        SCHEDULE,
    )
    .await;
    eprintln!(
        "shard {} closed at {} by {} spends ({} archival bytes) and priced by epoch {}; \
         staking onto it",
        closed.shard.to_raw(),
        closed.close_height,
        closed.spends,
        closed.archival_bytes,
        closed.priced_by_epoch
    );

    // A MARKET bond (the ordinary staker shape); the persona never serves,
    // so its exit is cooldown-vacuous (doc comment) and the record's bonded
    // total is exactly the holdings floor.
    let market_holdings = shekyl_archival_retention::HoldingsDescriptor {
        kind: shekyl_archival_retention::HoldingsKind::ShardSetCompact,
        shard_ids: shekyl_archival_retention::ShardSet::new(vec![SHARD_ID])
            .expect("one-shard holdings"),
    };
    let expected_bonded = bond_floor(
        &market_holdings,
        shekyl_archival_retention::archival_params(),
    );
    let fixture = stake_persona_to_confirmed_bond(
        &daemon,
        &seed,
        SLOT,
        FUNDING_CUSHION,
        FixtureStake::MarketBond(market_holdings),
        Some(wallet),
    )
    .await;

    // Pre-read: the daemon's bond-record row over the persona-isolated
    // transport — the SAME fetch the seam rides. The positive balance here
    // is what makes the post-connect zero an observed *transition* rather
    // than a state that could have held all along.
    let release_rpc = LocalNodeRpc::new(
        format!("http://127.0.0.1:{}", daemon.rpc_port),
        Duration::from_secs(10),
    )
    .await
    .expect("loopback exit transport");
    let before = fetch_claim_source_for(&release_rpc, fixture.persona_id)
        .await
        .expect("pre-submit record fetch");
    let bonded_before = before
        .source()
        .bond
        .as_ref()
        .expect("the confirmed bond must have a daemon-side record")
        .bonded_total_atomic;
    assert_eq!(
        bonded_before, expected_bonded,
        "the confirmed market bond's record must hold exactly the holdings floor"
    );

    // Dispatch through the production seam, with the bond path's own
    // reference-spendability retry ladder (the BondPostChange output must be
    // in the curve tree at the anchored reference, which lags the tip).
    let pruning_landed = SpentRecordsDurablyPruned::for_test();
    let mut receipt = None;
    for attempt in 0..24 {
        match super::Engine::submit_release(
            fixture.arc.clone(),
            &release_rpc,
            slot,
            &pruning_landed,
        )
        .await
        {
            Ok(r) => {
                receipt = Some(r);
                break;
            }
            Err(ReleaseRequestError::Stake(StakeEngineError::Assembly(
                e @ (BondAssemblyError::ReferenceResyncing { .. }
                | BondAssemblyError::NoSpendableFunding
                | BondAssemblyError::OutputNotYetDrained { .. }
                | BondAssemblyError::InsufficientFunding { .. }),
            ))) => {
                eprintln!("release attempt {attempt}: {e}; mining more");
                daemon.generate_blocks(10).await;
                refresh(&fixture.arc).await;
            }
            Err(e) => daemon.panic_with_log("submit_release", e),
        }
    }
    let receipt = receipt.expect("the exit must assemble and dispatch within the retry budget");
    eprintln!(
        "release exit ACCEPTED by the daemon submit engine: {} B, {} funding input(s), {:?}",
        receipt.release.bound_tx.bytes().len(),
        receipt.release.funding_gindexes.len(),
        receipt.submit,
    );

    // Block-connect: mine the accepted exit out of the pool, then read the
    // terminal fact back from the daemon. Pool-drain alone proves only that
    // the tx LEFT the pool (a terminal reject leaves it too); the
    // discriminating observable is the connect's own write.
    mine_until_pool_drains(&daemon, "accepted release exit", 1).await;
    let after = fetch_claim_source_for(&release_rpc, fixture.persona_id)
        .await
        .expect("post-connect record fetch");
    let bond_after = after
        .source()
        .bond
        .as_ref()
        .expect("the exit PRESERVES the record row — presence plus zero, never absence");
    assert_eq!(
        bond_after.bonded_total_atomic, 0,
        "block-connect must zero the record's bonded total (apply_archival_release); \
         a positive balance here means the exit left the pool WITHOUT connecting"
    );
    eprintln!(
        "release exit CONNECTED: bonded total {bonded_before} → 0, row preserved — \
         the assembled bytes are the bytes consensus accepts (the RF-D9 proposition \
         for the exit wire)"
    );
}

/// The **composed-arc walk** (PR-C): the retire-on-a-real-chain arm the
/// PR-B ruling deferred here by its recorded conditional, driven through
/// the PRODUCT façades — [`StakeFacade::unstake`] posts the exit,
/// [`StakeFacade::collect_unstaked`]'s terminal sweep empties the slot, and
/// the pscan task's funded-gated retirement fires on **real-chain
/// evidence**. Until PR-C that gate had passing coverage and zero
/// production reach (the engine walk #575 constructed its trigger states
/// synthetically; no user path could produce the exact-zero pool) — this
/// walk is the reachability check the synthetic one structurally could not
/// be: every state it retires from was produced by the shipped verbs
/// against a real daemon.
///
/// The bond is a market bond onto shard 0, so the walk opens by closing
/// and pricing that shard ([`shard::close_shard_through_the_daemon`]): CEN-J15
/// admits the join only after a slash pass has priced the shard, and
/// under an eight-block epoch that pass is within two epochs of the
/// close. Every height below is relative to the exit, so the fill moves
/// nothing else.
///
/// The `SHEKYL_SETTLEMENT_EPOCH_BLOCKS = 8` lever is what makes the claim
/// window affordable (`MAX_CLAIM_AGE_W` = 26 epochs ⇒ ~250 blocks; at the
/// genesis SEB the wait would be tens of thousands). Eight rather than
/// two: the retention prune discards the filled shard's bodies two epochs
/// after its close, and the staker wallet's P-scan must cover the fill
/// before that boundary connects; under a two-block epoch that boundary
/// lands inside the scan's finality lag (the helper refuses it). The
/// lever is legitimate here
/// because the persona never serves: the cooldown predicates are vacuous
/// exactly as on the PR-B walk, and the claim-window expiry the retire
/// waits on is epoch-denominated (the lever's own unit), not the
/// block-denominated slash watermark the PR-B doc warns the lever cannot
/// faithfully shorten. Run in its own process (the schedule latch is
/// irreversible; sibling e2es guard the genesis pin).
///
/// Sequenced observables, each a distinct write:
/// 1. `unstake` → Broadcast; an immediate second `unstake` refuses
///    `ExitInProgress` (the one-live-exit lane, through the public verb).
/// 2. Connect: the daemon row reads back present with `bonded_total == 0`.
/// 3. The production P-scan observes the exit (`pending_releases`) and the
///    payout pair as slot funding.
/// 4. `collect_unstaked` → `Swept` with **`remainder == 0`** (the pool is
///    exactly the payout pair, one pass) and a nonzero `swept`.
/// 5. After the pass confirms and its spent rows prune, `collect_unstaked`
///    again → `NothingLeft` (the completion contract, end-to-end).
/// 6. Active moves away (slot 1 activation — retirement skips the active
///    slot by design), the claim window expires on-chain, and the sweep
///    retires the persona: `pending_releases` empties into
///    `retired_records`, and the wipe is observed through a DIFFERENT
///    handler (`persona_canonical_id` refuses) — never graded by the
///    retire call's own return.
/// 7. The daemon row is STILL present with `bonded_total == 0`:
///    retirement is a wallet-side act; the chain record outlives it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow lane (run_live_daemon_gates.sh ARMED_SLOW): requires SHEKYLD_BIN; a market-bond walk (close and price the shard, fund, stake, unstake, collect, retire)"]
async fn e2e_unstake_collect_retire_composed_arc() {
    use super::emission_source::fetch_claim_source_for;
    use super::prpc::LocalNodeRpc;
    use super::stake_engine::PSlot;
    use super::unstake_facade::{
        CollectOutcome, CollectUnstakedError, UnstakeError, UnstakeOutcome,
    };
    use crate::StakeFacade;
    use shekyl_archival_retention::bond_floor;

    const SLOT: u32 = 0;
    const SHARD_ID: u64 = 0;
    const SEB: u64 = 8;
    /// The cap sits inside the epoch and is the shard's finality wait.
    const SCHEDULE: RegtestSchedule = RegtestSchedule {
        seb: SEB,
        reorg_cap: 2,
    };
    /// Cushion above `floor + bond fee` (the PR-B walk's shape): becomes the
    /// bond's `BondPostChange` output, which the exit sweeps.
    const FUNDING_CUSHION: u64 = 12_000_000_000;

    // Arm the levered schedule BEFORE any wallet-side epoch arithmetic (the
    // claim e2e's arming shape, and its containment caveats verbatim: the
    // latch is irreversible and per-process — run this walk alone).
    let seed = [0x77u8; shekyl_crypto_pq::account::SEED_BYTES];
    let daemon = RegtestDaemon::start_for_seed_with_schedule(&seed, Some(SCHEDULE)).await;
    SCHEDULE.set_in_process_env();
    let armed = shekyl_archival_retention::arm_settlement_epoch_override_for_regtest()
        .expect("the schedule levers must arm before any epoch arithmetic latches the schedule");
    assert_eq!(armed, SEB, "armed schedule must be the lever value");
    let slot = PSlot::from_raw(SLOT);

    // The shard the market bond names must be closed, final and priced
    // before the join (CEN-J15): fill it on the empty chain and mine
    // through the pass that prices it.
    // The staker wallet opens before the fill and is the fill's spender:
    // its refresh and its P-scan then cover the fill blocks ahead of the
    // retention prune that discards their bodies two epochs after the
    // shard closes; a wallet opened after that prune cannot scan them from
    // this node (the helper's docs).
    let wallet = staker_wallet(daemon.rpc_port, &seed, slot).await;
    let pscan_seal =
        shekyl_engine_file::paths::pscan_state_path_from(&wallet.1.path().join("wallet"));
    let closed = shard::close_shard_through_the_daemon(
        &daemon,
        &wallet.0,
        &wallet.2,
        &pscan_seal,
        ShardId::from_raw(SHARD_ID),
        SCHEDULE,
    )
    .await;
    eprintln!(
        "shard {} closed at {} by {} spends ({} archival bytes) and priced by epoch {}; \
         staking onto it",
        closed.shard.to_raw(),
        closed.close_height,
        closed.spends,
        closed.archival_bytes,
        closed.priced_by_epoch
    );
    let market_holdings = shekyl_archival_retention::HoldingsDescriptor {
        kind: shekyl_archival_retention::HoldingsKind::ShardSetCompact,
        shard_ids: shekyl_archival_retention::ShardSet::new(vec![SHARD_ID])
            .expect("one-shard holdings"),
    };
    let expected_bonded = bond_floor(
        &market_holdings,
        shekyl_archival_retention::archival_params(),
    );
    let fixture = stake_persona_to_confirmed_bond(
        &daemon,
        &seed,
        SLOT,
        FUNDING_CUSHION,
        FixtureStake::MarketBond(market_holdings),
        Some(wallet),
    )
    .await;
    let daemon_address = format!("http://127.0.0.1:{}", daemon.rpc_port);

    // Pre-read: the positive balance that makes the post-connect zero a
    // transition (the PR-B walk's discipline).
    let record_rpc = LocalNodeRpc::new(daemon_address.clone(), Duration::from_secs(10))
        .await
        .expect("loopback record transport");
    let before = fetch_claim_source_for(&record_rpc, fixture.persona_id)
        .await
        .expect("pre-unstake record fetch");
    assert_eq!(
        before
            .source()
            .bond
            .as_ref()
            .expect("confirmed bond row")
            .bonded_total_atomic,
        expected_bonded,
        "fixture must start at the holdings floor"
    );

    // 1. The PRODUCT verb posts the exit, with the bond path's own
    //    reference-spendability retry ladder (mining until the wallet's
    //    reference view can prove the funding).
    let mut posted = None;
    for attempt in 0..24 {
        match StakeFacade::unstake(fixture.arc.clone(), &daemon_address).await {
            Ok(outcome) => {
                posted = Some(outcome);
                break;
            }
            Err(e @ (UnstakeError::Resyncing { .. } | UnstakeError::ExitNotFundable { .. })) => {
                eprintln!("unstake attempt {attempt}: {e}; mining more");
                daemon.generate_blocks(3).await;
                refresh(&fixture.arc).await;
            }
            Err(e) => daemon.panic_with_log("unstake", e),
        }
    }
    let posted = posted.expect("unstake must post within the retry ladder");
    let (UnstakeOutcome::Broadcast { tx_hash: exit_hash }
    | UnstakeOutcome::AlreadyInChain {
        tx_hash: exit_hash, ..
    }) = posted;
    eprintln!("unstake POSTED via the product facade: {exit_hash:?}");

    // The one-live-exit lane, observed through the public verb: a second
    // unstake refuses with guidance, never a second irreversible post.
    match StakeFacade::unstake(fixture.arc.clone(), &daemon_address).await {
        Err(UnstakeError::ExitInProgress) => {}
        other => panic!("a second unstake must refuse ExitInProgress, got {other:?}"),
    }

    // 2. Connect: presence + zero (the PR-B observable, now behind the verb).
    mine_until_pool_drains(&daemon, "posted exit", 1).await;
    let after = fetch_claim_source_for(&record_rpc, fixture.persona_id)
        .await
        .expect("post-connect record fetch");
    assert_eq!(
        after
            .source()
            .bond
            .as_ref()
            .expect("the exit PRESERVES the record row")
            .bonded_total_atomic,
        0,
        "block-connect must zero the bonded total"
    );

    // 3. The production P-scan observes the exit and the payout pair.
    daemon.generate_blocks(PSCAN_TEST_REORG_DEPTH + 2).await;
    refresh(&fixture.arc).await;
    let state = pscan_until(
        &fixture.arc,
        &fixture.pscan_seal,
        "the observed exit + payout funding",
        |s| {
            s.pending_releases().contains_key(&fixture.persona_id)
                && s.funding_outputs().iter().any(|r| r.p_slot == slot)
        },
    )
    .await;
    let payout_rows = state
        .funding_outputs()
        .iter()
        .filter(|r| r.p_slot == slot)
        .count();
    eprintln!("exit observed by pscan; {payout_rows} payout funding row(s) on the slot");

    // 4. The terminal sweep, through the product verb, with its own
    //    maturity ladder (payouts must enter the reference tree).
    let mut swept_outcome = None;
    for attempt in 0..24 {
        match StakeFacade::collect_unstaked(fixture.arc.clone()).await {
            Ok(outcome) => {
                swept_outcome = Some(outcome);
                break;
            }
            Err(
                e @ (CollectUnstakedError::NothingSpendableYet
                | CollectUnstakedError::Unanchorable { .. }),
            ) => {
                eprintln!("collect attempt {attempt}: {e}; mining more");
                daemon.generate_blocks(3).await;
                refresh(&fixture.arc).await;
            }
            Err(e) => daemon.panic_with_log("collect_unstaked", e),
        }
    }
    let CollectOutcome::Swept {
        tx_hash: sweep_hash,
        swept,
        remainder,
        another_pool_remains,
    } = swept_outcome.expect("collect must sweep within the ladder")
    else {
        panic!("the first collection over a funded exited pool must be Swept");
    };
    assert!(!swept.is_zero(), "the sweep moves the released collateral");
    assert!(
        remainder.is_zero(),
        "the pool is exactly the payout pair: one pass collects everything, \
         and the reply's remainder — the completion fact — must say 0"
    );
    assert!(
        !another_pool_remains,
        "one persona exited: the lane-wide half of the completion fact must \
         say no other exited pool remains"
    );
    eprintln!("collect SWEPT {swept:?} to principal ({sweep_hash:?}), remainder 0");

    // 5. Pass confirms; spent rows prune; the completion arm answers.
    mine_until_pool_drains(&daemon, "sweep pass", 1).await;
    daemon.generate_blocks(PSCAN_TEST_REORG_DEPTH + 2).await;
    refresh(&fixture.arc).await;
    pscan_until(
        &fixture.arc,
        &fixture.pscan_seal,
        "the swept rows pruned (empty slot)",
        |s| !s.funding_outputs().iter().any(|r| r.p_slot == slot),
    )
    .await;
    match StakeFacade::collect_unstaked(fixture.arc.clone()).await {
        Ok(CollectOutcome::NothingLeft) => {}
        other => panic!("an emptied exited pool must answer NothingLeft, got {other:?}"),
    }

    // 6. Move active away (retirement skips the active slot by design),
    //    expire the claim window on-chain, and let the production sweep
    //    retire the persona on real evidence.
    {
        let g = fixture.arc.read().await;
        let stake = g.stake_handle().expect("staker fixture");
        let h = stake
            .mint_handle(PSlot::from_raw(1))
            .await
            .expect("slot 1 within the lookahead");
        stake
            .activate_persona(h)
            .await
            .expect("activate the successor persona");
    }
    // MAX_CLAIM_AGE_W (26) epochs past the exit epoch, plus settlement lag
    // and the pscan horizon; at SEB=8 this is a few hundred empty blocks —
    // the recorded conditional that routed this arm to PR-C.
    let window_blocks =
        (shekyl_archival_retention::MAX_CLAIM_AGE_W + 4) * SEB + PSCAN_TEST_REORG_DEPTH + 4;
    daemon.generate_blocks(window_blocks).await;
    refresh(&fixture.arc).await;
    let retired_state = pscan_until(
        &fixture.arc,
        &fixture.pscan_seal,
        "the funded-gated retirement on real-chain evidence",
        |s| {
            s.retired_records()
                .iter()
                .any(|r| r.p_canonical_id == fixture.persona_id)
        },
    )
    .await;
    assert!(
        !retired_state
            .pending_releases()
            .contains_key(&fixture.persona_id),
        "retirement must move the exit out of pending_releases"
    );

    // The wipe, observed through a DIFFERENT handler than the retire path
    // (the retire_walk discipline): the slot no longer resolves an id.
    {
        let g = fixture.arc.read().await;
        let stake = g.stake_handle().expect("staker fixture");
        assert!(
            stake.persona_canonical_id(slot).await.is_err(),
            "the retired slot's persona must be wiped from the held union"
        );
    }

    // 7. Retirement is wallet-side: the chain record outlives it.
    let final_read = fetch_claim_source_for(&record_rpc, fixture.persona_id)
        .await
        .expect("post-retire record fetch");
    assert_eq!(
        final_read
            .source()
            .bond
            .as_ref()
            .expect("the record row persists past wallet retirement")
            .bonded_total_atomic,
        0,
    );
    eprintln!(
        "composed arc COMPLETE: unstake -> connect -> collect (remainder 0) -> \
         NothingLeft -> funded-gated retire on real-chain evidence — the gate \
         that had coverage without reach is now reached by the shipped verbs"
    );
}

/// SP-R0 **arm #3 — PRODUCTION-DISCHARGE leg** (DQ-F): the SA-DQ-3
/// activation-induced **persist-then-no-broadcast crash**, driven against the
/// live regtest chain. `persist_bond_record` runs (the activation's durable
/// point — the W2 crash form: no assemble, no pending post, no broadcast),
/// the **production P-scan** exhaustively covers the real chain (the persona
/// posted nothing anywhere in `covered`), and the next **production open**
/// collects the phantom through the assemble-time sweep: the wallet reverts
/// to a clean non-staker. The W3 guard is exercised by construction — no
/// pending post exists, so the pending-record bridge does not veto.
///
/// This is the same fixture the in-tree CI lane
/// (`tests/sp_r0_arm3_fire.rs`) drives over fixture blocks; here the
/// evidence is the live daemon's chain through the real scan — the
/// production-discharge form.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "SP-R0 arm-#3 production discharge; needs SHEKYLD_BIN + a built regtest daemon"]
async fn e2e_arm3_phantom_slot_collected_at_open() {
    use super::stake_engine::PSlot;

    const SLOT: u32 = 0;
    let seed = [0x45u8; shekyl_crypto_pq::account::SEED_BYTES];
    let daemon = RegtestDaemon::start_for_seed(&seed).await;
    // Schedule guard (see the bond e2e): wallet epoch arithmetic here must
    // run on the genesis pin; a sibling-armed levered schedule fails loudly.
    assert_eq!(
        shekyl_archival_retention::effective_settlement_epoch_blocks(),
        shekyl_archival_retention::SETTLEMENT_EPOCH_BLOCKS,
        "another test latched a levered settlement-epoch schedule in this process; \
         run the regtest e2es in separate processes"
    );
    let slot = PSlot::from_raw(SLOT);
    // `staker_wallet` IS the crash fixture: it persists the bond record (the
    // durable point) and reopens — no assemble, no pending post, no
    // broadcast ever happens. The reopened wallet is the W2 phantom staker.
    let (arc, tmp, _) = staker_wallet(daemon.rpc_port, &seed, slot).await;
    {
        let g = arc.read().await;
        assert!(g.ledger().staking.staking_enabled);
        assert!(g.has_stake_engine(), "the phantom staker derives + spawns");
    }

    // Give the chain a body and let the production scan exhaustively cover
    // it — the persona posted nothing, so the sealed evidence carries
    // confirmed absence over `covered`.
    daemon.generate_blocks(PSCAN_TEST_REORG_DEPTH + 12).await;
    refresh(&arc).await;
    let pscan_seal = shekyl_engine_file::paths::pscan_state_path_from(&tmp.path().join("wallet"));
    let state = pscan_until(&arc, &pscan_seal, "a non-trivial covered range", |s| {
        s.cursor().synced_height().to_raw() >= 8
    })
    .await;
    assert!(
        state.bond_post_matches().is_empty(),
        "the phantom persona posted nothing"
    );

    // Close, reopen: the arm-#3 sweep runs at open, before derive.
    //
    // Sole-ownership reclaim is deliberate and deterministic here, not
    // brittle: `Engine::close(self, ..)` CONSUMES the engine (a lock-guard
    // close is not type-possible), and every clone-holder has provably
    // exited by this point — `pscan_until` shut its task down before
    // returning (the WI-1 shutdown contract releases the task's engine-arc
    // clone) and `refresh` joins to completion. This is the same fail-loud
    // posture as `close_wallet`'s production reclaim: if a future edit
    // leaves a task holding a clone, the panic below names the bug rather
    // than letting the test proceed against a still-live wallet.
    let creds = super::lifecycle::Credentials::password_only(b"pr4-staker");
    let lock = Arc::try_unwrap(arc).unwrap_or_else(|_| {
        panic!(
            "engine arc still has co-owners at close: a spawned task \
             (scan/refresh) was not shut down before the reopen step"
        )
    });
    lock.into_inner()
        .close(&creds)
        .await
        .expect("close phantom staker");
    let rpc = HttpRpc::new(format!("http://127.0.0.1:{}", daemon.rpc_port))
        .await
        .expect("wallet rpc (reopen)");
    let reopened = super::Engine::<super::SoloSigner>::open_full(
        &tmp.path().join("wallet"),
        &creds,
        shekyl_address::Network::Regtest,
        super::DaemonClient::verifying(rpc, regtest_expectation()),
        shekyl_engine_file::SafetyOverrides::none(),
    )
    .expect("reopen after the scan sealed confirmed absence")
    .into_wallet();
    assert!(
        !reopened.ledger().staking.staking_enabled,
        "arm #3 (production discharge): the phantom slot is collected and the \
         wallet reverts to a non-staker"
    );
    assert!(reopened.ledger().staking.bonded_slots.is_empty());
    assert!(
        !reopened.has_stake_engine(),
        "no actor spawns for the collected phantom"
    );
    eprintln!("arm #3 production discharge: phantom bonded_slots[{SLOT}] collected at open");
    reopened.close(&creds).await.expect("close");
}

/// The build a captured chain names: the daemon's own, held to the checkout
/// the replay tests compile against.
///
/// The checkout's `HEAD` alone says nothing about the binary in
/// `SHEKYLD_BIN`: a daemon built from another tree, or from this tree before
/// its change was committed (cmake fixes the version tag at configure time),
/// would stamp a corpus with a commit that did not mine it. The daemon
/// reports `<version>-<sha9>`; that SHA is the build. A capture refuses
/// unless it is the checkout's `HEAD` and the checkout is clean outside the
/// vectors being written, so the record cannot name code that is not what
/// ran.
fn capture_build_identity(daemon_version: &str) -> String {
    let git = |args: &[&str]| -> String {
        let out = shekyl_tor_control_client::spawn_lock::output(
            Command::new("git")
                .args(args)
                .current_dir(env!("CARGO_MANIFEST_DIR")),
        )
        .expect("git runs in the checkout");
        assert!(out.status.success(), "git {args:?} failed in the checkout");
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    let built = daemon_version.rsplit_once('-').map_or("", |(_, sha)| sha);
    assert!(
        built.len() == 9 && built.chars().all(|c| c.is_ascii_hexdigit()),
        "the daemon reports version `{daemon_version}`, which names no commit; a capture is \
         a development artifact and must come from a daemon built at a commit"
    );
    let head = git(&["rev-parse", "--short=9", "HEAD"]);
    assert_eq!(
        built, head,
        "SHEKYLD_BIN was built at {built} but the checkout is at {head}: re-run cmake \
         (the version tag is fixed at configure time) and rebuild the daemon at HEAD \
         before capturing, so the vector names the code that mined it"
    );
    let dirty = git(&[
        "status",
        "--porcelain",
        "--",
        ":(top)",
        ":(top,exclude)rust/shekyl-chain-ingest/tests/vectors",
    ]);
    assert!(
        dirty.is_empty(),
        "the checkout has uncommitted or untracked files, so HEAD does not describe what \
         was built; commit or remove them and rebuild the daemon before capturing:\n{dirty}"
    );
    head
}

/// `YYYY-MM-DD <rationale>`: the shape rule 50 requires of
/// [`CAPTURE_REGEN_DECISION_ENV`]. A date with no rationale, and a rationale
/// with no date, are both silence.
fn cited_regen_decision(decision: &str) -> bool {
    let bytes = decision.as_bytes();
    bytes.len() > 11
        && bytes[..10].iter().enumerate().all(|(i, byte)| match i {
            4 | 7 => *byte == b'-',
            _ => byte.is_ascii_digit(),
        })
        && bytes[10] == b' '
}

/// The variable that arms this capture. The same name the wallet
/// regenerators use; the citation this one records is
/// `docs/design/DAEMON_REDB_STORE.md` §12.1, so the refusal is local rather
/// than the wallet log's.
const CAPTURE_REGEN_DECISION_ENV: &str = "SHEKYL_PINNED_REGEN_DECISION";

/// The decision that authorizes rewriting the E2 corpus. Called before the
/// committed vector is deleted.
fn capture_regen_decision() -> String {
    let decision = std::env::var(CAPTURE_REGEN_DECISION_ENV).unwrap_or_default();
    assert!(
        cited_regen_decision(&decision),
        "refusing to regenerate the E2 corpus: set \
         {CAPTURE_REGEN_DECISION_ENV}=\"YYYY-MM-DD <rationale>\" citing the \
         docs/design/DAEMON_REDB_STORE.md §12.1 entry that authorizes the move \
         (got: {decision:?}). Moving a pinned vector is a decision, not a test \
         fix — see 50-testing.mdc."
    );
    decision
}

/// The commit a `shekyl-chain-replay --version` line names: its last
/// whitespace-separated token, when that token is nine hex digits.
fn commit_named_by_version(version: &str) -> Option<&str> {
    let token = version.split_whitespace().next_back()?;
    (token.len() == 9 && token.bytes().all(|b| b.is_ascii_hexdigit())).then_some(token)
}

/// The replay binary's own build, held to the checkout the daemon was
/// built at. A binary that names no commit, or another commit, is refused
/// before the committed vector is touched.
fn replay_build_identity(replay_bin: &Path, head: &str) -> String {
    let out =
        shekyl_tor_control_client::spawn_lock::output(Command::new(replay_bin).arg("--version"))
            .expect("spawn shekyl-chain-replay --version");
    assert!(
        out.status.success(),
        "shekyl-chain-replay --version failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let reported = String::from_utf8_lossy(&out.stdout);
    let named = commit_named_by_version(&reported).unwrap_or_else(|| {
        panic!(
            "SHEKYL_CHAIN_REPLAY_BIN reports `{reported}`, which names no commit; rebuild \
             shekyl-chain-replay at HEAD before capturing, so the trace names the code that \
             wrote it"
        )
    });
    assert_eq!(
        named, head,
        "SHEKYL_CHAIN_REPLAY_BIN was built at {named} but the checkout is at {head}: rebuild \
         the replay binary at HEAD before capturing, so the trace names the code that wrote it"
    );
    named.to_owned()
}

/// A daemon whose version names no commit cannot vouch for a capture. No
/// daemon needed: the refusal precedes every probe of the checkout.
#[test]
#[should_panic(expected = "names no commit")]
fn a_capture_refuses_a_daemon_version_naming_no_commit() {
    capture_build_identity("3.1.0-release");
}

/// A daemon built at another commit than the checkout's `HEAD` would stamp
/// the vector with code that did not mine it.
#[test]
#[should_panic(expected = "but the checkout is at")]
fn a_capture_refuses_a_daemon_built_at_another_commit() {
    capture_build_identity("3.1.0-000000000");
}

#[test]
fn a_cited_decision_is_a_date_then_a_rationale() {
    assert!(cited_regen_decision("2026-11-01 the E2 corpus moves"));
    assert!(!cited_regen_decision(""));
    assert!(!cited_regen_decision("2026-11-01"));
    assert!(!cited_regen_decision("2026-11-1 the E2 corpus moves"));
}

#[test]
fn a_version_line_names_its_last_nine_hex_digits() {
    assert_eq!(
        commit_named_by_version("shekyl-chain-replay aad0d0c7e\n"),
        Some("aad0d0c7e")
    );
    assert_eq!(
        commit_named_by_version("shekyl-chain-replay unknown\n"),
        None
    );
}

/// Capture the regtest chain as the **E2 replay pair** — a corpus and a
/// trace — for the consensus validator's verification-era fixtures
/// (`CHAIN_RULES_SLICE_6.md` §5.2, Q1 (ii)), under
/// `rust/shekyl-chain-ingest/tests/vectors/<shape>/`. Gated on
/// `SHEKYL_CAPTURE_CHAIN_VECTORS`; a no-op otherwise, so the generators run
/// unchanged in CI's live-daemon step.
///
/// The artifacts are the production replay driver's own, produced by its
/// own tools rather than a layout minted here (RD-Q1: nothing lives only in
/// a binary; RD-F15: the corpus writer verifies every body against its
/// header). `shekyl-chain-replay fetch` builds the corpus from the live
/// daemon over `block_list` — every block and every listed
/// transaction's **full** bytes. `shekyl-chain-replay baseline` replays
/// that corpus against a fresh store and writes the trace from the rows
/// the store recorded (`DAEMON_REDB_STORE.md` §12.1). The binary is located
/// by env var, like the daemon itself, and its `--version` must name the
/// same commit the daemon was built at: a stale replay binary would stamp
/// the daemon's sha onto a trace it did not write.
///
/// A capture rewrites pinned vectors, so it is a decision (rule 50).
/// `SHEKYL_PINNED_REGEN_DECISION` must cite the §12.1 entry that authorizes
/// the move, in the `YYYY-MM-DD <rationale>` shape, before the committed
/// vector is touched. The citation is recorded on the new manifest.
///
/// Blocks, not transactions, because the consumer is a **replay**:
/// `shekyl-chain-ingest` connects the chain against a real store, so the
/// spent set and the reference heights the 4.I rules read are derived by
/// the code that derives them in production (`50-testing.mdc`: *a fixture
/// that constructs the state a rule reads back is not a test of the
/// rule*).
///
/// `spend_txid` is recorded when the generator knows it; the archival
/// shapes are located by their vin class at load, so it is `None` there.
///
/// **Why the manifest stamps `genesis_hash` and `built_at_dev_sha`.** These
/// blobs are consensus-pinned test data: valid against one genesis and one
/// rule set, and a change of TXE-Q6′'s class (a grammar closure, a constant
/// regeneration, a row that alters what a valid block is) invalidates every
/// captured chain at once. Without the pin in the data, that arrives as
/// 1,979 blocks refusing at block 1 for a reason that reads as a validator
/// bug; with it, the replay test holds the genesis to the current build's
/// pin *before* judging a block and says "these vectors predate the current
/// genesis". "The daemon must enforce the current rules" gets the right
/// binary; "these vectors are pinned to a genesis" gets the right
/// **artifact**, and only the second survives whoever made the decision —
/// the same reason a citation carries its era. They are not boilerplate.
async fn maybe_capture_chain_vector(
    daemon: &RegtestDaemon,
    shape: &str,
    generator: &str,
    spend_txid: Option<TxHash>,
) {
    if std::env::var_os("SHEKYL_CAPTURE_CHAIN_VECTORS").is_none() {
        return;
    }
    let tool = |var: &str| -> PathBuf {
        match std::env::var_os(var) {
            Some(p) => PathBuf::from(p),
            None => panic!(
                "{var} not set: the chain-vector capture drives shekyl-chain-replay \
                 (`cargo build -p shekyl-chain-ingest --release`)"
            ),
        }
    };
    let replay_bin = tool("SHEKYL_CHAIN_REPLAY_BIN");
    // `height()` is the block COUNT; the top block is one below it.
    let count = daemon.height().await;
    let tip = count.checked_sub(1).expect("a chain with a genesis");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../shekyl-chain-ingest/tests/vectors")
        .join(shape);
    // The decision and both build identities, before the committed vector
    // is touched: a missing citation, a daemon that names no commit, or a
    // replay binary built at another commit leaves the old capture whole.
    let regen_decision = capture_regen_decision();
    let daemon_version = daemon.version().await;
    let built_at_dev_sha = capture_build_identity(&daemon_version);
    let baseline_built_at_dev_sha = replay_build_identity(&replay_bin, &built_at_dev_sha);
    if root.exists() {
        std::fs::remove_dir_all(&root).expect("clear a stale capture");
    }
    std::fs::create_dir_all(&root).expect("create capture dir");
    let corpus = root.join("corpus.e2");

    let mut fetch = Command::new(&replay_bin);
    fetch
        .args(["fetch", "--daemon"])
        .arg(format!("http://127.0.0.1:{}", daemon.rpc_port))
        .args(["--chain", "regtest", "--from", "0", "--to"])
        .arg(count.to_string())
        .arg("--out")
        .arg(&corpus);
    let fetch = shekyl_tor_control_client::spawn_lock::output(&mut fetch)
        .expect("spawn shekyl-chain-replay fetch");
    assert!(
        fetch.status.success(),
        "shekyl-chain-replay fetch failed: {}\n{}",
        String::from_utf8_lossy(&fetch.stdout),
        String::from_utf8_lossy(&fetch.stderr)
    );

    // Every listed transaction's full bytes as
    // `txs/<txid>.tx`, for the validator crate's per-rule fixtures. That
    // crate may not reach the ingest crate (G1), so it cannot read the
    // corpus; it reads a real transaction's bytes and mutates ONE field —
    // the same shape its fixtures have always had, now over a spend a
    // daemon accepted rather than a hand-built skeleton.
    let txs_dir = root.join("txs");
    std::fs::create_dir_all(&txs_dir).expect("create txs dir");
    let mut tx_count = 0usize;
    for height in 0..=tip {
        let shown = daemon.block_at(height).await;
        for slot in shown.tx {
            let bytes = match slot {
                wire::shared::OrArchived::Item(tx) => tx.body.0,
                wire::shared::OrArchived::Archived(state) => {
                    panic!("a capture chain discards no body: {state:?}")
                }
            };
            let tx = shekyl_wire::Transaction::from_bytes(&bytes)
                .expect("a daemon-served full tx parses");
            std::fs::write(
                txs_dir.join(format!("{}.tx", hex::encode(tx.hash()))),
                &bytes,
            )
            .expect("write tx blob");
            tx_count += 1;
        }
    }

    // The consensus pin, made visible: block 0's hash as the daemon
    // reports it, and the tree the daemon was built at. The replay test
    // holds the former to the genesis the current build pins BEFORE judging
    // any block, so a regeneration fails there, not as 1,979 refusals.
    let genesis_hash = daemon.block_at(0).await.header.hash.to_string();

    // The schedule the chain was mined under — the daemon's levers when the
    // harness pulled them, the genesis pair otherwise. The replay opens
    // its store and judges every block under a rule set naming exactly
    // this pair (`ARW-15`); recorded, not remembered, like the difficulty.
    let production = shekyl_chain_rules::CappedEpoch::PRODUCTION;
    let (settlement_epoch_blocks, reorg_cap_blocks) = match daemon.schedule {
        Some(levers) => (levers.seb, levers.reorg_cap),
        None => (
            production.settlement().blocks().get(),
            production.reorg_cap().to_raw(),
        ),
    };

    // The trace is the Rust baseline (`DAEMON_REDB_STORE.md` §12.1): the
    // corpus replayed against a fresh store under the production substrate
    // and the rules this chain was mined under, then the store's chain
    // written out. A chain the replay refuses is no baseline, and the
    // capture fails here rather than pinning a half-chain.
    let trace = root.join("trace.e2");
    let baseline_store = std::env::temp_dir().join(format!(
        "shekyl-capture-baseline-{shape}-{}",
        std::process::id()
    ));
    // A redb store is one file.
    if baseline_store.exists() {
        std::fs::remove_file(&baseline_store).expect("clear a stale baseline store");
    }
    let mut baseline = Command::new(&replay_bin);
    baseline
        .args(["baseline", "--chain", "regtest", "--fixed-difficulty", "1"])
        .arg("--corpus")
        .arg(&corpus)
        .arg("--store")
        .arg(&baseline_store)
        .arg("--settlement-epoch-blocks")
        .arg(settlement_epoch_blocks.to_string())
        .arg("--reorg-cap")
        .arg(reorg_cap_blocks.to_string())
        .arg("--out")
        .arg(&trace);
    let baseline = shekyl_tor_control_client::spawn_lock::output(&mut baseline)
        .expect("spawn shekyl-chain-replay baseline");
    assert!(
        baseline.status.success(),
        "shekyl-chain-replay baseline failed (its store is kept at {}): {}\n{}",
        baseline_store.display(),
        String::from_utf8_lossy(&baseline.stdout),
        String::from_utf8_lossy(&baseline.stderr)
    );
    std::fs::remove_file(&baseline_store).expect("remove the baseline store");

    // Format 5: every row of the captured state is block-produced, so the
    // manifest carries no out-of-band rows.
    let manifest = json!({
        "format_version": 5,
        "tx_count": tx_count,
        "genesis_hash": genesis_hash,
        "built_at_dev_sha": built_at_dev_sha,
        "description":
            "A regtest chain captured whole as the DRS-E2 replay pair. \
             corpus.e2: every block 0..=tip_height with the FULL bytes of \
             every listed transaction (shekyl-chain-replay fetch, \
             RD-F15-verified). trace.e2: the Rust baseline \
             (shekyl-chain-replay baseline): the corpus replayed against a \
             fresh store, then each height's facts and the tip's digest and \
             archival rows read off it, pinned at built_at_dev_sha. A \
             regression gate, not a conformance oracle. Consumed by replay: \
             shekyl-chain-ingest connects the chain against a real store, so \
             the state the 4.I rules read is derived, not asserted. \
             Regenerate with SHEKYL_CAPTURE_CHAIN_VECTORS=1, \
             SHEKYL_PINNED_REGEN_DECISION=\"YYYY-MM-DD <rationale>\" citing \
             DAEMON_REDB_STORE.md §12.1, SHEKYLD_BIN and SHEKYL_CHAIN_REPLAY_BIN \
             set to binaries built at that same HEAD, running the named \
             generator --ignored.",
        "shape": shape,
        "generator": generator,
        "captured_by_daemon_version": daemon_version,
        "regen_decision": regen_decision,
        "baseline_built_at_dev_sha": baseline_built_at_dev_sha,
        "tip_height": tip,
        "block_count": count,
        "spend_txid": spend_txid.map(|h| h.to_string()),
        // What `replay --chain regtest --fixed-difficulty n` must be given:
        // the value this harness spawned the daemon with, recorded rather
        // than remembered.
        "fixed_difficulty": 1,
        // The `(SEB, cap)` pair the daemon ran — `--dev-settlement-epoch-blocks`
        // and `--dev-archival-reorg-depth` when levered, the genesis
        // pair when not. What `replay --chain regtest --settlement-epoch-blocks
        // n --reorg-cap m` must be given.
        "settlement_epoch_blocks": settlement_epoch_blocks,
        "reorg_cap_blocks": reorg_cap_blocks,
    });
    std::fs::write(
        root.join("manifest.json"),
        format!("{}\n", serde_json::to_string_pretty(&manifest).unwrap()),
    )
    .expect("write capture manifest");
    eprintln!(
        "captured chain vector `{shape}` -> {} ({count} blocks; corpus {} B, trace {} B)",
        root.display(),
        std::fs::metadata(&corpus).map(|m| m.len()).unwrap_or(0),
        std::fs::metadata(&trace).map(|m| m.len()).unwrap_or(0),
    );
}

/// Capture blocks `0..=tip` as one fixture chain (deterministic projection only).
///
/// Fetches each block + its **full** (unpruned) non-miner txs directly — not the
/// engine's `default_fetch_scannable_block`, so the fixture records the bodies as
/// the chain carries them rather than the skeletons the engine binds. The fixture
/// needs only the prefix outputs + ct-base commitments + `0x07`, all of which a
/// full tx carries and `shekyl_wire::Transaction::from_bytes` parses.
async fn capture_chain(daemon: &RegtestDaemon, name: &str, tip: u64) -> serde_json::Value {
    let mut blocks = Vec::new();
    for height in 0..=tip {
        let shown = daemon.block_at(height).await;
        let block = shekyl_wire::Block::from_bytes(&shown.body.0)
            .unwrap_or_else(|e| panic!("parse block {height}: {e:?}"));
        let regular: Vec<shekyl_wire::Transaction> = shown
            .tx
            .into_iter()
            .map(|slot| match slot {
                wire::shared::OrArchived::Item(tx) => {
                    shekyl_wire::Transaction::from_bytes(&tx.body.0).expect("parse full regular tx")
                }
                wire::shared::OrArchived::Archived(state) => {
                    panic!("a capture chain discards no body: {state:?}")
                }
            })
            .collect();
        blocks.push(capture_block(&block, &regular, height));
    }
    json!({ "name": name, "blocks": blocks })
}

/// One block's deterministic projection: per-height root + every tx's outputs
/// (coinbase first, then non-miner txs in block order), each output carrying the
/// leaf identity the reconstruct path needs.
fn capture_block(
    block: &shekyl_wire::Block,
    regular: &[shekyl_wire::Transaction],
    height: u64,
) -> serde_json::Value {
    use shekyl_wire::tx_extra::TxExtraField;
    use shekyl_wire::Ct;

    let txs: Vec<serde_json::Value> = std::iter::once((true, &block.miner_transaction))
        .chain(regular.iter().map(|tx| (false, tx)))
        .map(|(is_miner, tx)| {
            let base = match &tx.ct {
                Ct::Null(b) => b,
                Ct::Fcmp { base, .. } => base,
            };
            let outputs: Vec<serde_json::Value> = tx
                .prefix
                .outputs
                .iter()
                .enumerate()
                .map(|(i, o)| {
                    // Every output has a tree-leaf commitment (CtBase carries one
                    // per output for both Null and Fcmp).
                    let commitment = base
                        .commitments
                        .get(i)
                        .expect("ct base has a commitment per output");
                    json!({
                        "output_key": hex::encode(o.key),
                        "commitment": hex::encode(commitment),
                        // shekyl-wire only emits tagged-key outputs (Output::write).
                        "target": "tagged_key",
                    })
                })
                .collect();
            // The `0x07` per-output leaf-hash blob (empty if the tx carries none).
            let blob = tx
                .prefix
                .parse_extra()
                .ok()
                .and_then(|fields| {
                    fields.into_iter().find_map(|f| match f {
                        TxExtraField::PqcLeafEntries(b) => Some(b),
                        _ => None,
                    })
                })
                .unwrap_or_default();
            json!({
                "is_miner": is_miner,
                "pqc_leaf_hashes": hex::encode(&blob),
                "outputs": outputs,
            })
        })
        .collect();

    json!({
        "height": height,
        "curve_tree_root": hex::encode(block.header.curve_tree_root),
        "txs": txs,
    })
}

/// A range past the tip is the method's refusal, an error object, never a
/// result carrying a refusal word.
///
/// `chain_coinbase_sum` over a range whose end is above the tip refuses
/// `block.missing` (RefusedByMethod); the genesis block alone is summed.
#[tokio::test]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; spawns a live daemon"]
async fn chain_coinbase_sum_refuses_a_range_past_the_tip() {
    use shekyl_rpc_client::ErrorClass;
    use shekyl_rpc_types::kinds::Height;

    let daemon = RegtestDaemon::start().await;
    let range = |to: u64| wire::chain::CoinbaseSumRange {
        from: Height(0),
        to: Height(to),
    };

    let over = daemon
        .rpc
        .call_or_refusal::<wire::ChainCoinbaseSum>(range(1_000_000))
        .await
        .expect("chain_coinbase_sum answers")
        .expect_err("a range past the tip is refused");
    assert_eq!(over.class, ErrorClass::RefusedByMethod, "{over:?}");
    assert_eq!(over.diagnostic.code, "block.missing", "{over:?}");

    daemon
        .rpc
        .call::<wire::ChainCoinbaseSum>(range(0))
        .await
        .expect("the genesis block alone is summed");
}

/// `get_output_histogram` stays unrouted on both listeners (SOK-Q3 B).
///
/// A method re-minted under the old name turns this red before it can serve
/// a histogram (rule 47).
#[tokio::test]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; spawns a live daemon"]
async fn get_output_histogram_stays_unrouted() {
    const DELETED_METHOD: &str = "get_output_histogram";

    let daemon = RegtestDaemon::start_with_restricted_listener().await;
    let restricted = HttpRpc::new(daemon.restricted_url().to_owned())
        .await
        .expect("restricted rpc client");
    let admin = HttpRpc::new(format!("http://127.0.0.1:{}", daemon.rpc_port()))
        .await
        .expect("admin rpc client");

    for (name, listener) in [("restricted", &restricted), ("admin", &admin)] {
        let gone = raw_call(listener, DELETED_METHOD, json!({ "amounts": [] })).await;
        assert!(
            shekyl_rpc_types::errors::is_method_not_found(&gone["error"]),
            "{DELETED_METHOD} was deleted (SOK-Q3) and must stay unrouted on the {name} \
             listener: {gone}"
        );
    }
}

/// The handlers apply their own request caps to a bounded caller
/// (`RPC_CHANNEL.md` §6.3): `tx_list` at `bound.tx`, `chain_spent` at
/// `bound.key-image`, each refused as OverResourceBound one past the cap
/// and served at it; the host is not bounded.
#[tokio::test]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; spawns a live daemon"]
async fn handlers_apply_their_own_request_caps() {
    use shekyl_rpc_client::ErrorClass;
    /// `RESTRICTED_TRANSACTIONS_COUNT`.
    const TX_CAP: usize = 100;
    /// `RESTRICTED_SPENT_KEY_IMAGES_COUNT`.
    const KI_CAP: usize = 5000;

    let daemon = RegtestDaemon::start_with_restricted_listener().await;
    let restricted = HttpRpc::new(daemon.restricted_url().to_owned())
        .await
        .expect("restricted rpc client");
    let unrestricted = HttpRpc::new(format!("http://127.0.0.1:{}", daemon.rpc_port()))
        .await
        .expect("unrestricted rpc client");

    // Ids that resolve to nothing: the cap is a request-shape refusal and
    // fires before any lookup, so the chain's contents are irrelevant.
    let ids = |n: usize| -> Vec<HashHex> {
        (0..n)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[24..].copy_from_slice(&(i as u64).to_be_bytes());
                HashHex::from_bytes(bytes)
            })
            .collect()
    };
    let txs = |n: usize| wire::tx::TxListQuery {
        id: ids(n),
        prune: false,
    };

    let over = restricted
        .call_or_refusal::<wire::TxList>(txs(TX_CAP + 1))
        .await
        .expect("tx_list answers")
        .expect_err("a bounded caller over the cap is refused");
    assert_eq!(over.class, ErrorClass::OverResourceBound, "{over:?}");
    assert_eq!(over.diagnostic.code, "bound.tx", "{over:?}");

    // At the cap: served. Pins the boundary rather than "refuses
    // everything", which a broken-in-the-other-direction change would pass.
    restricted
        .call::<wire::TxList>(txs(TX_CAP))
        .await
        .expect("exactly the cap is within it");

    // The key-image cap is a second, independently-numbered site.
    let ki_over = restricted
        .call_or_refusal::<wire::ChainSpent>(wire::chain::SpentQuery {
            key_image: ids(KI_CAP + 1),
        })
        .await
        .expect("chain_spent answers")
        .expect_err("a bounded caller over the cap is refused");
    assert_eq!(ki_over.class, ErrorClass::OverResourceBound, "{ki_over:?}");
    assert_eq!(ki_over.diagnostic.code, "bound.key-image", "{ki_over:?}");

    // Blast radius: the same over-cap request from the host is served; the
    // caps bound a caller, not the node.
    unrestricted
        .call::<wire::TxList>(txs(TX_CAP + 1))
        .await
        .expect("the host is not bounded");
}

/// `tx show` and `chain spent` answer through `shekyl-cli`.
///
/// The daemon's own console is deleted. The words run as a one-shot
/// `shekyl-cli` against this daemon (`SHEKYL_CLI_BIN`), given
/// `--network regtest` (NI-R1, NI-R4).
#[tokio::test]
#[ignore = "requires SHEKYLD_BIN and SHEKYL_CLI_BIN; spawns a live daemon"]
async fn tx_show_and_chain_spent_answer_through_shekyl_cli() {
    let daemon = RegtestDaemon::start().await;

    // The genesis coinbase is the one transaction a fresh regtest chain has,
    // and it is reachable without mining or spending.
    let txid = daemon.block_at(0).await.header.coinbase.to_string();

    let out = daemon.console(&format!("tx show {txid}"));
    assert!(
        out.contains("Found in blockchain at block 0"),
        "tx show must locate the genesis coinbase; got:\n{out}"
    );

    let out = daemon
        .console("chain spent 0000000000000000000000000000000000000000000000000000000000000003");
    assert!(
        out.contains("unspent"),
        "chain spent must answer; got:\n{out}"
    );
}

/// The peer words answer through `shekyl-cli` on an offline regtest daemon.
#[tokio::test]
#[ignore = "requires SHEKYLD_BIN and SHEKYL_CLI_BIN; spawns a live daemon"]
async fn peer_words_answer_through_shekyl_cli() {
    let daemon = RegtestDaemon::start().await;

    // This daemon runs offline, so each peer command prints the state,
    // not an empty table (Rick, 2026-10-14).
    for command in ["sync status", "peer connections", "peer list", "peer stats"] {
        let out = daemon.console(command);
        // The log tail echoes the command and carries the log line; the
        // state is the line the console printed, and no table follows it.
        assert!(
            out.lines().any(|line| line.trim() == "P2P: offline")
                && !out.contains("Remote Host")
                && !out.contains("list size"),
            "{command} must render the live core's P2P state; got:\n{out}"
        );
    }

    // The limit leg. `/get_limit` was replaced by the link rows
    // (`RPC_CHANNEL.md` §6.4); the console reads them through the option
    // show. This daemon runs the default, unlimited, so each line ends in
    // the limit clause's unlimited form, and a leg that did not answer
    // would leave the clause out.
    let out = daemon.console("p2p stats");
    let limited: Vec<&str> = out
        .lines()
        .filter(|line| {
            (line.starts_with("Received") || line.starts_with("Sent"))
                && line.contains("bytes")
                && line.ends_with("no limit")
        })
        .collect();
    assert!(
        limited.iter().any(|l| l.starts_with("Received"))
            && limited.iter().any(|l| l.starts_with("Sent")),
        "p2p stats must render both lines with the limit clause the \
         link rows give; got:\n{out}"
    );
}

#[path = "regtest_e2e_bench_source.rs"]
mod bench_source;

#[path = "regtest_e2e_full_disk.rs"]
mod full_disk;

#[path = "regtest_e2e_origin.rs"]
mod origin;

#[path = "regtest_e2e_peer.rs"]
mod peer;

#[path = "regtest_e2e_rt_p5.rs"]
mod rt_p5;

#[path = "regtest_e2e_send_durable.rs"]
mod send_durable;

#[path = "regtest_e2e_shard.rs"]
mod shard;

#[path = "regtest_e2e_sync.rs"]
mod sync;
