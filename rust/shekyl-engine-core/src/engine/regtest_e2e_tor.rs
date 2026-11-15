// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The emission walk's Tor trio.
//!
//! A `#[path]` child of the regtest harness. The shared miner stays in the
//! parent: this module owns the mesh, the onion endpoint, and the one
//! daemon that originates on it.

#![cfg(test)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use shekyl_rpc_client::{wire, Rpc};
use shekyl_rpc_transport::HttpRpc;
use shekyl_rpc_types::kinds::NoParams;

use super::{
    mine_address_from_seed, serial_lock, Peering, RegtestDaemon, RegtestSchedule, RegtestSpawn,
    ShownPool,
};

/// The Tor trio's two relays, as the miner's harness reads them: each
/// relay's own `daemon_status` and `peer_connections`, the operator's
/// reads, over its admin listener.
pub(super) struct TrioRelays {
    b: HttpRpc,
    b_onion: OnionPeer,
    c: HttpRpc,
    c_onion: OnionPeer,
}

/// One reading of the trio's sessions and tips. A stem the miner
/// originates comes back as a fluff only over this whole mesh
/// ([`RegtestDaemon::start_tor_trio`]). A session missing at the miner's
/// pool limit fails that wait: the walk is rerun, and the origin's embargo
/// is not a second deadline.
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

/// A v3 onion endpoint, `<56 base32 characters>.onion:<port>`, held by
/// value so [`Peering`] stays `Copy`.
#[derive(Clone, Copy, Debug)]
pub(super) struct OnionPeer {
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

impl std::fmt::Display for OnionPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let host = std::str::from_utf8(&self.host).expect("base32 is ASCII");
        write!(f, "{host}.onion:{}", self.port)
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
/// `reachable` ([`RegtestDaemon::await_trio_mesh`]): Tor's re-query gap,
/// then one Tor test of the address (Rick, 2026-11-14).
///
/// A lookup that reaches directories without the descriptor fails, and the
/// client's Tor does not ask those directories again for 15 minutes
/// (`REND_HID_SERV_DIR_REQUERY_PERIOD`), so a dial inside that gap waits on
/// the same failed lookup; run 4 (2026-11-14) failed three dials to one
/// fresh onion inside 400 s while its owner read it reachable. After the
/// gap, one Tor test is three attempts each up to the 120 s dial deadline,
/// with the longest retry waits between them, 10 s and 30 s
/// (`shekyl-transport-layer` `dial_profile(Tor)`, `RETRY_WAITS`): 400 s.
/// 900 + 400 = 1,300 s.
const TRIO_MESH_LIMIT: Duration = Duration::from_secs(1_300);

impl RegtestDaemon {
    /// The pinned Tor binary a walk that reads over Tor runs, from
    /// `SHEKYL_TEST_TOR_BINARY`: the variable the live-Tor lane sets
    /// (`tor-pin-verify.yml`) to the bundle it fetched, checked against the
    /// pin and staged. Panics naming how to stage one when it is unset.
    pub(super) fn live_tor_binary() -> PathBuf {
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
    /// embargo before it is shown. That is the origin rig's hold
    /// (`origin::StemSinkPair`), and a walk that mines hundreds of
    /// transactions cannot wait it out each time. With three, every stem A
    /// originates ends at a node that fluffs back to A: stemmed to B, it
    /// goes on to C, which has no outbound session and fluffs to every peer
    /// but B, A among them; stemmed to C, C fluffs to B, and B relays the
    /// fluff to A.
    ///
    /// C is [`Peering::Listening`]: one unanswered loopback port is its
    /// whole clearnet, so it is synced from open and dials nobody. Its
    /// managed Tor publishes the onion B dials. B's one closed peer is that
    /// onion. Neither mines; both follow A over the sessions A opens.
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
    ///
    /// Only A covers its own origins in the pool wait. B and C do not
    /// originate. A short mesh during the walk fails that wait; propagation
    /// is a rerun (`docs/FOLLOWUPS.md`, the emission walk).
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
        a.shown_pool = ShownPool::covering_origins();
        a.await_trio_mesh(TRIO_MESH_LIMIT).await;
        (a, b, c)
    }

    /// The mesh, rendered for a pool-wait failure. Empty when this daemon
    /// is not the trio's miner.
    pub(super) async fn mesh_at_failure(&self) -> String {
        match self.read_mesh().await {
            Some(reading) => format!(" (mesh: {reading})"),
            None => String::new(),
        }
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
    /// from the line the daemon logs when it does.
    ///
    /// `daemon_status` names the onion's reachability and not its endpoint
    /// (`shekyl-tor-status::Onion` is state, age and cause). The endpoint
    /// is the line `shekyl-p2p`'s `Network::note_own_onion` writes, and the
    /// closed-peer row is that endpoint.
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
}
