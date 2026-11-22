// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The emission walk's Tor mesh.
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

/// The emission walk's mesh: five daemons, each connected to the others
/// (Rick, 2026-11-22). A node stems a transaction it originates to at
/// most two peers, its successor and, after an embargo fire, its
/// alternate, and no arrival from either counts as the transaction coming
/// back (F-10). A third peer is the least that leaves the origin a return
/// it can trust; five leaves one when a peer is slow. A test mesh is sized
/// to the production shape, not to the smallest that passes.
const MESH_NODES: usize = 5;

/// The mesh's relays: every node but the miner.
const MESH_RELAYS: usize = MESH_NODES - 1;

/// The mesh's sessions: one for each pair of nodes.
const MESH_DIALS: usize = MESH_NODES * (MESH_NODES - 1) / 2;

/// The mesh's node names, by node index: A, the miner, is 0, then its
/// relays in dial order ([`RegtestDaemon::start_tor_mesh`]).
const NODE_NAMES: [char; MESH_NODES] = ['A', 'B', 'C', 'D', 'E'];

/// Every session the mesh is made of, as (dialer, dialed) node indices:
/// each node dials every node after it, so each pair is one session and
/// the miner, node 0, is dialed by none.
const DIALS: [(usize, usize); MESH_DIALS] = {
    let mut dials = [(0, 0); MESH_DIALS];
    let mut next = 0;
    let mut from = 0;
    while from < MESH_NODES {
        let mut to = from + 1;
        while to < MESH_NODES {
            dials[next] = (from, to);
            next += 1;
            to += 1;
        }
        from += 1;
    }
    dials
};

/// One of the mesh's relays, as the miner's harness reads it: its own
/// `daemon_status` and `peer_connections`, the operator's reads, over its
/// admin listener.
struct MeshRelay {
    rpc: HttpRpc,
    onion: OnionPeer,
}

/// The mesh's relays in dial order, B to E: relay `i` is node `i + 1`.
pub(super) struct MeshRelays([MeshRelay; MESH_RELAYS]);

/// One of the mesh's sessions, as the dialer reads it.
#[derive(Clone, Copy, Debug)]
struct Dial {
    from: char,
    to: char,
    held: bool,
}

/// One node's tip.
#[derive(Clone, Copy, Debug)]
struct Tip {
    node: char,
    height: u64,
}

/// One reading of the mesh's sessions and tips, every dial and every node
/// in it. A stem the miner originates comes back as a fluff only over this
/// whole mesh ([`RegtestDaemon::start_tor_mesh`]). A session missing at
/// the miner's pool limit fails that wait: the walk is rerun, and the
/// origin's embargo is not a second deadline.
#[derive(Debug)]
struct MeshReading {
    /// Each dial in [`DIALS`]' order.
    sessions: [Dial; MESH_DIALS],
    /// Each node's tip, in [`NODE_NAMES`]' order: the miner's first.
    tips: [Tip; MESH_NODES],
}

impl MeshReading {
    /// Every session up, and every relay at the miner's tip as it was read
    /// first: a relay behind the miner cannot admit a spend of an output it
    /// has not seen.
    fn whole(&self) -> bool {
        let [miner, relays @ ..] = &self.tips;
        self.sessions.iter().all(|dial| dial.held)
            && relays.iter().all(|relay| relay.height >= miner.height)
    }
}

impl std::fmt::Display for MeshReading {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, dial) in self.sessions.iter().enumerate() {
            let sep = if i == 0 { "" } else { ", " };
            let state = if dial.held { "up" } else { "down" };
            write!(f, "{sep}{}→{} {state}", dial.from, dial.to)?;
        }
        f.write_str("; tips")?;
        for (i, tip) in self.tips.iter().enumerate() {
            let sep = if i == 0 { " " } else { ", " };
            write!(f, "{sep}{} {}", tip.node, tip.height)?;
        }
        Ok(())
    }
}

#[test]
fn the_mesh_dials_each_pair_of_nodes_once_and_never_the_miner() {
    for from in 0..MESH_NODES {
        for to in 0..MESH_NODES {
            let dialed = DIALS
                .iter()
                .filter(|&&dial| dial == (from, to) || dial == (to, from))
                .count();
            let expected = usize::from(from != to);
            assert_eq!(
                dialed, expected,
                "nodes {from} and {to} share {dialed} dials"
            );
        }
    }
    assert!(DIALS.iter().all(|&(from, to)| from < to && to != 0));
}

#[test]
fn a_mesh_reads_whole_only_with_every_session_up_and_every_relay_at_the_tip() {
    let sessions = DIALS.map(|(from, to)| Dial {
        from: NODE_NAMES[from],
        to: NODE_NAMES[to],
        held: true,
    });
    let tips = NODE_NAMES.map(|node| Tip { node, height: 390 });
    let whole = MeshReading { sessions, tips };
    assert!(whole.whole());
    assert!(whole
        .to_string()
        .starts_with("A→B up, A→C up, A→D up, A→E up, B→C up"));
    assert!(whole
        .to_string()
        .ends_with("; tips A 390, B 390, C 390, D 390, E 390"));

    // Each session down, one at a time, anywhere in the mesh.
    for down in 0..MESH_DIALS {
        let mut short = sessions;
        short[down].held = false;
        let reading = MeshReading {
            sessions: short,
            tips,
        };
        assert!(!reading.whole(), "dial {down} down reads whole");
        let Dial { from, to, .. } = short[down];
        assert!(reading.to_string().contains(&format!("{from}→{to} down")));
    }

    // Each relay behind the miner's tip, one at a time; a relay past the
    // tip is at it.
    for behind in 1..MESH_NODES {
        let mut lagging = tips;
        lagging[behind].height = 389;
        assert!(
            !MeshReading {
                sessions,
                tips: lagging,
            }
            .whole(),
            "relay {behind} behind reads whole"
        );
    }
    let mut ahead = tips;
    ahead[MESH_RELAYS].height = 391;
    assert!(MeshReading {
        sessions,
        tips: ahead,
    }
    .whole());
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
/// value.
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
/// A mesh daemon is spawned only once the onions it dials read
/// `reachable`. A dial made before the descriptor is fetchable waits out
/// Tor's whole window and fails (run 3, 2026-11-14: "waiting for
/// rendezvous desc", 105 s), and the address then goes off the dialer's
/// draw ("cooling after a failed dial").
const ONION_REACHABLE_LIMIT: Duration = Duration::from_secs(600);

/// How long the mesh's sessions may take to form once every onion reads
/// `reachable` ([`RegtestDaemon::await_mesh`]): Tor's re-query gap, then
/// one Tor test of the address (Rick, 2026-11-14). Each dial is its own
/// and they run at once, so the limit is one dial's.
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
const MESH_LIMIT: Duration = Duration::from_secs(1_300);

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

    /// The emission walk's mesh of [`MESH_NODES`] daemons, all on a
    /// managed Tor running the pinned binary `tor_file` (Rick, 2026-11-14),
    /// each connected to every other (Rick, 2026-11-22). A, returned first,
    /// is the miner: it pays `seed`'s address, seats its bundle producer (a
    /// mining address and a Tor, `shekyl-node` `producer::seat`), and is the
    /// daemon the wallet uses. B, C, D and E are relays, returned in that
    /// order. **Each node dials every node named after it: A dials B to E,
    /// B dials C to E, and so on; E dials nobody.** Each pair is then one
    /// session, and the dialer never dials a node that holds a session to
    /// it.
    ///
    /// **Why five** ([`MESH_NODES`]). A daemon with a Tor holds a
    /// transaction it originates until an outbound session hides its
    /// address (`DAEMON_RELAY_PRIVACY.md` §98.5), and marks it shown when
    /// its fluff comes back from a peer it did not hand it to (F-10). It
    /// hands it to at most two: its stem successor, and the alternate it
    /// re-stems to when an embargo fires. On three nodes an origin that has
    /// re-stemmed has handed the transaction to both its peers, no return
    /// counts, and the entry waits for the second fire, past the pool wait.
    /// On five a third and a fourth peer can bring it back. A stem goes out
    /// on an outbound session other than its source and a fluff to every
    /// peer but its source; E has no outbound session, so a stem that
    /// reaches it is fluffed, and every node holds a session to A.
    ///
    /// E is [`Peering::Listening`]: one unanswered loopback port is its
    /// whole clearnet, so it is synced from open and dials nobody. Its
    /// managed Tor publishes the onion the others dial. Each other relay's
    /// closed peers are the onions of the relays named after it. None of
    /// them mines; each follows A over the session A opens.
    ///
    /// **When it is ready.** A daemon is spawned only once the onions it
    /// dials read `reachable` ([`ONION_REACHABLE_LIMIT`]), and the mesh is
    /// returned only once it is whole: every session up and every relay at
    /// A's tip ([`Self::await_mesh`]). Run 3 (2026-11-14) spawned A while
    /// a relay's descriptor was not yet fetchable: A's dial to it failed,
    /// and A's first transaction was still unbroadcast at the limit. Each
    /// daemon logs `p2p` and `tor` at `debug`, so a session that closes
    /// says why.
    ///
    /// Only A covers its own origins in the pool wait. The relays do not
    /// originate. A short mesh during the walk fails that wait; propagation
    /// is a rerun (`docs/FOLLOWUPS.md`, the emission walk).
    pub(super) async fn start_tor_mesh(
        seed: &[u8; shekyl_crypto_pq::account::SEED_BYTES],
        schedule: Option<RegtestSchedule>,
        tor_file: PathBuf,
    ) -> (RegtestDaemon, [RegtestDaemon; MESH_RELAYS]) {
        let serial = serial_lock().lock_owned().await;
        // The relays start from the last named, E, to B: each dials the
        // relays started before it ([`DIALS`]), so their onions are
        // published and reachable first.
        let mut started: Vec<(RegtestDaemon, OnionPeer)> = Vec::with_capacity(MESH_RELAYS);
        for _ in 0..MESH_RELAYS {
            let peering = if started.is_empty() {
                Peering::Listening {
                    p2p_port: Self::free_port(),
                    requests: true,
                }
            } else {
                Peering::TorPeers {
                    peers: started.iter().map(|(_, onion)| *onion).collect(),
                }
            };
            let relay = Self::spawn(
                RegtestSpawn::new(None)
                    .with_schedule(schedule)
                    .with_peering(peering)
                    .with_managed_tor(tor_file.clone())
                    .with_ports_taken(started.iter().map(|(relay, _)| relay.rpc_port)),
            )
            .await;
            let onion = relay.published_onion(TOR_PUBLISH_LIMIT).await;
            relay.await_onion_reachable(ONION_REACHABLE_LIMIT).await;
            started.push((relay, onion));
        }
        let mine_address = mine_address_from_seed(seed, shekyl_address::Network::Regtest);
        let mut a = Self::spawn(
            RegtestSpawn::new(Some(serial))
                .with_schedule(schedule)
                .with_mine_address(mine_address)
                .with_peering(Peering::TorPeers {
                    peers: started.iter().map(|(_, onion)| *onion).collect(),
                })
                .with_managed_tor(tor_file)
                .with_ports_taken(started.iter().map(|(relay, _)| relay.rpc_port)),
        )
        .await;
        // Node order: B, the last started, first.
        started.reverse();
        let relays: [(RegtestDaemon, OnionPeer); MESH_RELAYS] =
            started.try_into().unwrap_or_else(|started: Vec<_>| {
                panic!(
                    "the mesh started {} of its {MESH_RELAYS} relays",
                    started.len()
                )
            });
        a.relays = Some(MeshRelays(relays.each_ref().map(|(relay, onion)| {
            MeshRelay {
                rpc: relay.rpc.clone(),
                onion: *onion,
            }
        })));
        a.shown_pool = ShownPool::covering_origins();
        a.await_mesh(MESH_LIMIT).await;
        (a, relays.map(|(relay, _)| relay))
    }

    /// The mesh, rendered for a pool-wait failure. Empty when this daemon
    /// is not the mesh's miner.
    pub(super) async fn mesh_at_failure(&self) -> String {
        match self.read_mesh().await {
            Some(reading) => format!(" (mesh: {reading})"),
            None => String::new(),
        }
    }

    /// The mesh as it reads now, from A (this daemon); `None` on a daemon
    /// that is not the mesh's miner. A's tip is read first, so a relay at
    /// or past it has every block A had then.
    async fn read_mesh(&self) -> Option<MeshReading> {
        let MeshRelays(relays) = self.relays.as_ref()?;
        let mut tips = NODE_NAMES.map(|node| Tip { node, height: 0 });
        tips[0].height = tip_height(&self.rpc).await;
        for (tip, relay) in tips[1..].iter_mut().zip(relays) {
            tip.height = tip_height(&relay.rpc).await;
        }
        let mut sessions = DIALS.map(|(from, to)| Dial {
            from: NODE_NAMES[from],
            to: NODE_NAMES[to],
            held: false,
        });
        // The miner is node 0 and relay `i` node `i + 1`; no dial is to
        // the miner.
        for (dial, &(from, to)) in sessions.iter_mut().zip(&DIALS) {
            let dialer = if from == 0 {
                &self.rpc
            } else {
                &relays[from - 1].rpc
            };
            dial.held = holds_outbound_to(dialer, relays[to - 1].onion).await;
        }
        Some(MeshReading { sessions, tips })
    }

    /// Wait until the mesh is whole ([`MeshReading::whole`]), within
    /// `limit`; at once on a daemon that is not the mesh's miner.
    async fn await_mesh(&self, limit: Duration) {
        let deadline = Instant::now() + limit;
        loop {
            let Some(reading) = self.read_mesh().await else {
                return;
            };
            if reading.whole() {
                eprintln!("tor mesh: the mesh is whole ({reading})");
                return;
            }
            if Instant::now() >= deadline {
                self.panic_with_log(
                    "the Tor mesh did not form",
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
