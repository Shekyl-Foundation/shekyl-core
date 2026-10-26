// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The dialer's owner: one loop per connector that wakes, plans and draws.
//! The handshake module opens the channel, reads the response, and either
//! adopts a kept session or closes a confirm dial in Rust (dialer brief,
//! "The fill", "The dial", "`DialOutcome`").
//!
//! The loop runs on a thread of its own. Its wake is a timing-engine owner:
//! each gap is armed on the engine and the thread waits for that wake or
//! for the bell. The daemon has one scheduler and the dialer brings no
//! second one. A dial does not run on this thread. Each wake launches at
//! most one attempt ([`flight`]); the attempt task does the I/O and posts
//! its result, and the loop applies it. The pace is the wake spacing, and
//! a slow dial skips no wake. No p2p io worker is held.
//!
//! [`Dialer::wake`] and [`Dialer::dial`] are the caller's own attempt.
//! They run it on the calling thread and apply the result before they
//! return. They do not post into the loop's queue.
//!
//! A connection problem does not end the test. The attempt waits and tries
//! again ([`crate::pace`]); the wait holds no in-flight slot, and this loop
//! does not run it.
//!
//! A wake draws only when the connector can dial: its link is usable and the
//! tip and the network id are known (`TSR-F1`; the `ready` module). While one
//! is missing the loop does not arm its timer. It waits on the change that
//! could supply it, and the wake spacing resumes when the connector is ready.
//! The `tor_tally` module publishes how many Tor sessions are held. An
//! inbound accept counts there and is not a dial.

mod address;
mod flight;
mod handshake;
mod ready;
mod recovery;
mod tor_tally;
mod wake;

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

use shekyl_draw_rng::RelayRng;
use shekyl_peerlist::{
    white_diversity_floor, CloseCause, CloseKind, ConnectionId, ConnectorId, DialOutcome,
    NetworkAddress, Peerlist, Refusal, RefusedSet, Source, Tick,
};
use shekyl_relay_privacy::params::{MIN_PROVISIONED_OUT_PEERS, P2P_DEFAULT_OUT_PEERS};
use shekyl_seam::{Hub, SocketId, Subscription, SyncPayload};
use shekyl_timing_engine::{Clock, OwnerHandle};

use self::address::live_sessions;
pub use self::flight::{Applied, Launch};
use self::flight::{Completions, InFlight};
use self::handshake::KeptDial;
pub use self::ready::NotReady;
use self::ready::{park, wait_wake_or_bell, Bell, Waited};
use self::wake::{plan_wake, Wake};
use crate::attempts::Attempts;
use crate::bans::BanSnapshot;
use crate::fill::{in_flight_bound, DialAim};
use crate::link_tally::{LinkFold, TallySink, TorLinkTally};
use crate::nonce::{HandshakeNonce, HandshakeNonceSet, InFlightNonce};
use crate::pace::{attempts_per_test, next_wake_nanos, retry_wait_nanos};
use crate::store::{AddressStore, LoadError, STORE_INTERVAL_NANOS};

/// This node's sync payload, read at each handshake. `None` when the core
/// has not published a tip yet: the dialer then dials nothing, because a
/// handshake without the chain's height is not one.
pub type SnapshotSource = Arc<dyn Fn() -> Option<SyncPayload> + Send + Sync>;

/// The state the owner loops and the FFI calls share.
pub struct Shared {
    /// The peer lists. [`Peerlist::apply`] stays the only writer of gray
    /// and white; this struct is where the dialer keeps them.
    pub lists: Peerlist,
    /// Open tests and kept sessions, one [`Attempts`] per connector. A
    /// test is in flight or waiting; the waiting record is the retry.
    attempts: Vec<Attempts>,
    targets: Vec<usize>,
    own: Vec<Vec<NetworkAddress>>,
    /// Kept sessions by id, so a close can name the address.
    kept: BTreeMap<u64, NetworkAddress>,
    /// Kept dials from just before `adopt` until their kept row is written,
    /// by socket id. A close in that window finds no kept row; it records
    /// its cause here instead, and the kept row is never written for it.
    adopting: BTreeMap<u64, Option<CloseCause>>,
    /// Under-target wakes that dialed nothing, one slot per connector.
    idle: [Option<wake::IdleWatch>; ConnectorId::COUNT],
    /// A closed network (`--add-exclusive-node`): the candidate
    /// population, when set. Not a dialer arm.
    exclusive: Option<BTreeSet<NetworkAddress>>,
    /// Every operator-named address this dialer was given (the compiled
    /// seeds, `--add-peer`), in the order given: what a stranded connector
    /// re-admits when no closed network is declared.
    configured: Vec<NetworkAddress>,
    /// The recovery episode each connector is in, if any. [`recovery`]
    /// opens it on a stranded wake and closes it when recovery worked.
    recovery: [Option<recovery::Recovery>; ConnectorId::COUNT],
    /// When the address file was last written or read; `None` until
    /// then, so the first due store is one interval after the open.
    last_store: Option<Tick>,
    /// Every enlisted attempt whose result has not been applied, by
    /// attempt id. The stop flag and the insert share one lock section
    /// ([`flight`]): once the flag is set, nothing more is inserted, and
    /// an application that has not yet removed its row leaves it for the
    /// drain. The row holds the attempt's nonce until the result is
    /// applied or the attempt is cancelled, and the attempt stays pending
    /// in [`Attempts`] until one of those.
    in_flight: BTreeMap<u64, InFlight>,
    /// Applications that have removed their row and not yet finished.
    /// [`Dialer::stop`] waits for zero, after it has refused every new
    /// application, before it writes the address file. The wait releases
    /// this lock; the hub is never called under it.
    applying: usize,
    /// The next attempt id.
    next_attempt: u64,
    /// Each connector's in-flight bound ([`in_flight_bound`]): protocol
    /// data, the same on every node.
    bounds: [usize; ConnectorId::COUNT],
    /// The managed Tor's `SocksTimeout`, in nanoseconds, once the daemon
    /// sets it ([`Dialer::set_tor_window`]). A Tor attempt that times out
    /// at or after it is final within its test.
    tor_window: Option<u64>,
    /// What the Tor dials show, for the managed-Tor supervisor's posture
    /// line (`TOR_SUPERVISOR.md` §4.2). Display only (`TSR-Q14`).
    tor_link: LinkFold,
    /// Inbound Tor rows last read off the board. [`Dialer::session_closed`]
    /// does not read the board: the adopt poster calls it while holding
    /// the table lock. The seam's close poster refreshes this first.
    inbound_tor: usize,
}

impl Shared {
    fn attempts(&mut self, connector: ConnectorId) -> &mut Attempts {
        &mut self.attempts[connector.index()]
    }

    fn view(&self, connector: ConnectorId) -> &Attempts {
        &self.attempts[connector.index()]
    }

    /// The addresses whose kept session expiry skips, and whose close
    /// moves the white clock. The same set [`Dialer::session_closed`]
    /// removes. [`Dialer::kept_sessions`] is the count, and it also
    /// includes an in-flight `Keep`.
    #[must_use]
    pub fn kept_addresses(&self, connector: ConnectorId) -> BTreeSet<NetworkAddress> {
        self.view(connector).kept_addresses().clone()
    }

    /// Begin `address`'s test. When the test does not start, an outstanding
    /// gray seat goes back to drawable on the same rung: the draw moved it
    /// and this call did not take it. A white re-contact was not drawn, so
    /// the release changes nothing there.
    fn begin_or_release(
        &mut self,
        connector: ConnectorId,
        address: &NetworkAddress,
        aim: DialAim,
    ) -> bool {
        if self.attempts(connector).begin(address, aim) {
            return true;
        }
        self.lists.release_draw(address);
        false
    }
}

/// The outbound dialer for every connector of one process.
pub struct Dialer {
    hub: Hub,
    shared: Arc<Mutex<Shared>>,
    nonces: HandshakeNonceSet,
    stop: Arc<AtomicBool>,
    /// Set when the zone host starts; the lists exist before it does.
    network_id: Mutex<Option<[u8; 16]>>,
    snapshot: SnapshotSource,
    /// The address file, once [`Self::open_address_file`] named it.
    store: Mutex<Option<AddressStore>>,
    /// Which connectors have an owner loop. One per connector: a second
    /// start is refused, not stacked (the ephemeral-tor path and the
    /// proxy-only zone branch both asked for Tor's, 2026-10-13).
    owners: Mutex<[bool; ConnectorId::COUNT]>,
    /// What a parked owner loop waits on. The hub's links ring it on every
    /// change; so do the tip, the network id and the stop.
    bell: Arc<Bell>,
    /// The hub's links ring [`Self::bell`] while this is held. Dropped with
    /// the dialer, so a dialer rebuilt on the same hub leaves no watcher.
    _links_watch: Subscription,
    /// The results the attempt tasks posted; each also rings the bell.
    completions: Arc<Completions>,
    /// Wakes [`Self::stop`] when the last application that started before
    /// the stop flag was seen has finished.
    apply_idle: Condvar,
}

/// The peerlist's name for a seam session: the socket id, little-endian,
/// in the first eight bytes.
#[must_use]
pub fn session_of(id: SocketId) -> ConnectionId {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&id.get().to_le_bytes());
    ConnectionId(bytes)
}

impl Dialer {
    /// A dialer over `hub`, with empty lists built over `refused`.
    ///
    /// Every handshake request carries the network id given later by
    /// [`Self::set_network_id`]. `snapshot` is the core's latest published
    /// tip, and [`Self::tip_published`] says
    /// when it changes. Until both are known, and the connector's link on
    /// `hub` is usable, the owner loops draw nothing.
    #[must_use]
    pub fn new(hub: Hub, refused: RefusedSet, snapshot: SnapshotSource) -> Self {
        let mut targets = vec![0usize; ConnectorId::COUNT];
        targets[ConnectorId::Clearnet.index()] = P2P_DEFAULT_OUT_PEERS as usize;
        targets[ConnectorId::Tor.index()] = MIN_PROVISIONED_OUT_PEERS as usize;
        let bell = Arc::new(Bell::new());
        let ringing = Arc::clone(&bell);
        let links_watch = hub.links().subscribe(Arc::new(move |_| ringing.ring()));
        Self {
            hub,
            shared: Arc::new(Mutex::new(Shared {
                lists: Peerlist::new(refused),
                attempts: (0..ConnectorId::COUNT).map(|_| Attempts::new()).collect(),
                targets,
                own: vec![Vec::new(); ConnectorId::COUNT],
                kept: BTreeMap::new(),
                adopting: BTreeMap::new(),
                idle: [None; ConnectorId::COUNT],
                exclusive: None,
                configured: Vec::new(),
                recovery: std::array::from_fn(|_| None),
                last_store: None,
                in_flight: BTreeMap::new(),
                applying: 0,
                next_attempt: 0,
                bounds: [
                    in_flight_bound(ConnectorId::Clearnet),
                    in_flight_bound(ConnectorId::Tor),
                ],
                tor_window: None,
                tor_link: LinkFold::new(),
                inbound_tor: 0,
            })),
            nonces: HandshakeNonceSet::new(),
            stop: Arc::new(AtomicBool::new(false)),
            network_id: Mutex::new(None),
            snapshot,
            store: Mutex::new(None),
            owners: Mutex::new([false; ConnectorId::COUNT]),
            bell,
            _links_watch: links_watch,
            completions: Arc::new(Completions::default()),
            apply_idle: Condvar::new(),
        }
    }

    /// Claim `connector`'s owner loop. `true` the first time; `false` when
    /// it already has one, and the caller starts nothing. A loop ends only
    /// with the dialer. A start that fails after this claim releases it
    /// with [`Self::release_owner`]: a failed start is not a running loop,
    /// and the other path that asks for the same connector must be able
    /// to take it.
    #[must_use]
    pub fn claim_owner(&self, connector: ConnectorId) -> bool {
        let mut owners = self.owners.lock().expect("owners");
        let slot = &mut owners[connector.index()];
        !std::mem::replace(slot, true)
    }

    /// Give back a claim that never became a running loop.
    pub fn release_owner(&self, connector: ConnectorId) {
        self.owners.lock().expect("owners")[connector.index()] = false;
    }

    /// The network every handshake names. Set once, when the zone host
    /// starts.
    pub fn set_network_id(&self, network_id: [u8; 16]) {
        *self.network_id.lock().expect("network id") = Some(network_id);
        self.bell.ring();
    }

    /// The window the managed Tor gives one onion connect before it answers
    /// `0x06` (its `SocksTimeout`). Tor has already retried introduction
    /// points and descriptor fetches inside it, so a Tor attempt that
    /// times out at or after it, measured from the attempt's own start, is
    /// final within its test: the address cools (Rick, 2026-10-26). A
    /// timeout inside the window keeps its retries. `None`, the default,
    /// leaves every timeout worth its retries: an operator's Tor sets its
    /// own `SocksTimeout`, which this node does not know, and with no Tor
    /// there is nothing to read. Set where the managed Tor's route is
    /// published.
    pub fn set_tor_window(&self, window: Option<std::time::Duration>) {
        let nanos = window.map(|window| u64::try_from(window.as_nanos()).unwrap_or(u64::MAX));
        self.shared().tor_window = nanos;
    }

    /// The Tor window [`Self::set_tor_window`] set.
    #[must_use]
    pub fn tor_window(&self) -> Option<std::time::Duration> {
        self.shared()
            .tor_window
            .map(std::time::Duration::from_nanos)
    }

    /// Send what the Tor dials show to `sink`: the tally now, then each
    /// change. The sink runs under the dialer's lock and must
    /// not block.
    pub fn report_tor_link(&self, sink: TallySink) {
        self.shared().tor_link.set_sink(sink);
    }

    /// The Tor link tally now.
    #[must_use]
    pub fn tor_link_tally(&self) -> TorLinkTally {
        self.shared().tor_link.tally()
    }

    /// The core published a tip: a loop parked for want of one looks again.
    pub fn tip_published(&self) {
        self.bell.ring();
    }

    /// Whether `connector` can dial now, or the first thing it lacks. The
    /// plan reads this before it draws, and the owner loop parks on it.
    pub fn readiness(&self, connector: ConnectorId) -> Result<(), NotReady> {
        if let Some(missing) = NotReady::from_outbound(self.hub.links().get(connector).outbound) {
            return Err(missing);
        }
        if (self.snapshot)().is_none() {
            return Err(NotReady::NoTip);
        }
        if self.network_id().is_none() {
            return Err(NotReady::NoNetworkId);
        }
        Ok(())
    }

    fn network_id(&self) -> Option<[u8; 16]> {
        *self.network_id.lock().expect("network id")
    }

    /// The shared state, for the calls that read or write the lists.
    pub fn shared(&self) -> MutexGuard<'_, Shared> {
        self.shared.lock().expect("dialer state")
    }

    /// The hub this dialer dials through.
    #[must_use]
    pub fn hub(&self) -> &Hub {
        &self.hub
    }

    /// The connector's outbound target as it stands.
    #[must_use]
    pub fn target(&self, connector: ConnectorId) -> usize {
        self.shared().targets[connector.index()]
    }

    /// Dials in flight on `connector`, of either aim.
    #[must_use]
    pub fn in_flight(&self, connector: ConnectorId) -> usize {
        self.shared().view(connector).in_flight()
    }

    /// Run `connector` at `bound` dials in flight. A test seam: the bound is
    /// protocol data ([`in_flight_bound`]), and no production crate turns
    /// on the feature that compiles this.
    #[cfg(feature = "test-seams")]
    pub fn set_in_flight_bound(&self, connector: ConnectorId, bound: usize) {
        self.shared().bounds[connector.index()] = bound;
    }

    /// Kept sessions on `connector`, pending `Keep` attempts included.
    #[must_use]
    pub fn kept_sessions(&self, connector: ConnectorId) -> usize {
        self.shared().view(connector).kept_count()
    }

    /// The connector's outbound target. A cap of 0 is legal and dials
    /// nothing. Lowering it closes kept sessions only, uniformly, and
    /// returns the ids closed; a pending attempt and a confirm row are
    /// never what the cap closes.
    pub fn set_target<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        target: usize,
        rng: &mut R,
    ) -> Vec<SocketId> {
        let mut shared = self.shared();
        shared.targets[connector.index()] = target;
        let closing = shared.attempts(connector).over_target(target, rng);
        let ids: Vec<SocketId> = shared
            .kept
            .iter()
            .filter(|(_, address)| closing.contains(address))
            .filter_map(|(id, _)| SocketId::from_ffi(*id))
            .collect();
        drop(shared);
        for id in &ids {
            self.hub.close(*id);
        }
        ids
    }

    /// This node's own addresses on `connector`: never dial candidates,
    /// and the disclosure population's own member (slice 1 §5a).
    pub fn set_own_addresses(&self, connector: ConnectorId, addresses: Vec<NetworkAddress>) {
        tracing::info!("{connector:?}: this node's own address(es) are {addresses:?}");
        let mut shared = self.shared();
        if let Some(first) = addresses.first() {
            // An address of another connector is refused by the lists and
            // kept here for the filter only. The filter skips every address
            // in the vec; the lists store one, the disclosure member.
            if let Err(refusal) = shared.lists.set_own_address(connector, Some(first.clone())) {
                tracing::warn!(
                    "{connector:?}: own address {first:?} is not stored on the lists ({refusal:?}); the dial filter still skips it"
                );
            }
        }
        shared.own[connector.index()] = addresses;
    }

    /// Declare a closed network: the candidate population is exactly
    /// these addresses, which are admitted as operator-named. An empty
    /// declaration is no declaration: the population is open again. (The
    /// C++ option parser hands an empty list on every boot that names no
    /// exclusive node; read as a population of nothing, it stopped every
    /// dial of every daemon — found by the §4 run, 2026-10-13.)
    pub fn set_exclusive<R: RelayRng + ?Sized>(
        &self,
        addresses: Vec<NetworkAddress>,
        now: Tick,
        rng: &mut R,
    ) {
        let mut bans = BanSnapshot::take(&self.hub);
        let mut shared = self.shared();
        for address in &addresses {
            // Already seated: the population is the declaration either way.
            // A refusal is not "already seated" and is said.
            if let Err(refusal) =
                shared
                    .lists
                    .admit_gray(address, Source::Operator, now, &mut bans, rng)
            {
                tracing::warn!("closed-network address {address:?} was not admitted: {refusal:?}");
            }
        }
        shared.exclusive = if addresses.is_empty() {
            None
        } else {
            Some(addresses.into_iter().collect())
        };
    }

    /// `--p2p-disclose-early` (brief revision 3 §2.6): the lists disclose below
    /// the floor on every connector until the span or the floor ends it
    /// there. Logged here, once, with when it ends (rule 82).
    pub fn set_disclose_early(&self, now: Tick) {
        self.shared().lists.set_disclose_early(now);
        tracing::info!(
            "--p2p-disclose-early is on: this node discloses its known peers and its own address below the floor of {}; on each connector the flag ends after {} hours or when that connector's white count reaches the floor, whichever comes first, and a flagged node is recognisable while it holds",
            white_diversity_floor(),
            shekyl_peerlist::P2P_DISCLOSE_EARLY_SPAN_NANOS / 3_600_000_000_000
        );
    }

    /// An operator-named address (`--add-peer`, a seed): into gray, and
    /// remembered as configured, so a stranded connector can re-admit it.
    pub fn admit_operator<R: RelayRng + ?Sized>(
        &self,
        address: &NetworkAddress,
        now: Tick,
        rng: &mut R,
    ) -> Result<bool, Refusal> {
        let mut bans = BanSnapshot::take(&self.hub);
        let mut shared = self.shared();
        if !shared.configured.contains(address) {
            shared.configured.push(address.clone());
        }
        shared
            .lists
            .admit_gray(address, Source::Operator, now, &mut bans, rng)
    }

    /// The inbound handshake's question: is `nonce` one of ours in flight
    /// on `connector`? Erases it.
    #[must_use]
    pub fn take_nonce(&self, connector: ConnectorId, nonce: &HandshakeNonce) -> bool {
        self.nonces.take(connector, nonce)
    }

    /// The session `id` closed, with the cause that won.
    ///
    /// A kept session leaves the kept count. `CloseKind::SessionRefused`
    /// is the lists' `PayloadRefused`: the payload owner declined a
    /// delivery. The address stays as `SessionAccepted` left it, which is
    /// white. That close is not a dial. The stream was counted when the
    /// session was accepted, and folding the refusal as one would clear
    /// the failed dials since that open. Any other cause only drops the
    /// kept row. An id this dialer is not keeping has no row here: a dial
    /// still in the handshake, a confirm dial, or an inbound Tor session,
    /// which has no list address. The board is not read. The adopt poster
    /// calls this while it holds the table lock, so the held count uses
    /// the inbound rows last read by [`Self::note_inbound_tor`]. The seam's
    /// close poster reads the board first
    /// ([`Self::session_closed_from_seam`]).
    pub fn session_closed<R: RelayRng + ?Sized>(
        &self,
        id: SocketId,
        cause: CloseCause,
        rng: &mut R,
    ) {
        let now = self.hub.now();
        let mut shared = self.shared();
        if let Some(adopting) = shared.adopting.get_mut(&id.get()) {
            *adopting = Some(cause);
        } else if let Some(address) = shared.kept.remove(&id.get()) {
            if let Some(connector) = Peerlist::connector_of(&address) {
                if cause.kind() == CloseKind::SessionRefused {
                    // Not a dial. The stream was counted when the session
                    // was accepted, so this does not finish a test and does
                    // not fold the tally.
                    let outcome = DialOutcome::PayloadRefused(address.clone());
                    shared.lists.apply(&outcome, now, rng);
                }
                // White expiry follows the connection (the gray lifecycle,
                // item 1): the clock moves to the close.
                shared.lists.session_ended(&address, now);
                shared.attempts(connector).session_closed(&address);
            }
        }
        Self::publish_tor_held(&mut shared);
    }

    /// Stop every owner loop at its next bell, cancel every attempt in
    /// flight, and write the address file once more.
    ///
    /// The flag is set before the drain. [`flight`] reads that flag in the
    /// same lock section as the insert, so an attempt begun and not yet
    /// inserted is cancelled there with no outcome, and an attempt already
    /// inserted is in the drain. Either way the outstanding gray draw stays
    /// seated and is written. Cancel senders are dropped after the dialer
    /// lock, so a task ends at its next poll and releases what it holds: a
    /// connect is aborted, a channel is released. The queue is then closed
    /// and every posted result is dropped. A task that posts after the
    /// close is handed the result back and drops it, which releases the
    /// channel. An application that had already taken its row finishes
    /// first: this waits for it, and that wait does not hold the dialer
    /// lock across the hub calls, so a session it keeps is in the lists
    /// when the file is written and nothing is adopted afterwards. The
    /// file is written last. All of this is before the zone's runtime
    /// stops and before the managed Tor is torn down
    /// (`TOR_SUPERVISOR.md`, `TSR-F13`: the dialer stops first).
    ///
    /// A caller that started the owner loops on threads of its own uses
    /// [`Self::stop_joining`], which joins them before the file is written.
    pub fn stop(&self) {
        self.stop_joining(|| {});
    }

    /// [`Self::stop`], with `join_loops` run after every attempt is
    /// cancelled and every application has finished, and before the
    /// address file is written. The caller that started the owner loops
    /// joins them there: each exits at the bell, and none applies a result
    /// once the flag is set, so the file is written with no loop running.
    /// It must not be called from an owner loop's own thread.
    pub fn stop_joining(&self, join_loops: impl FnOnce()) {
        self.stop.store(true, Ordering::Release);
        self.bell.ring();
        let count = self.abandon_flight();
        if count > 0 {
            tracing::debug!("the dialer cancelled {count} attempt(s) in flight at stop");
        }
        self.wait_for_applications();
        join_loops();
        if let Err(err) = self.store_addresses() {
            tracing::warn!("the address file was not written at stop: {err}");
        }
    }

    /// Block until every application that removed its row before seeing
    /// the stop flag has finished. The condvar wait releases the dialer
    /// lock. Nothing increments the count once the flag is set.
    fn wait_for_applications(&self) {
        let mut shared = self.shared();
        while shared.applying > 0 {
            shared = self.apply_idle.wait(shared).expect("dialer state");
        }
    }

    /// Name the address file and load it: every address it holds enters
    /// gray (slice 1 brief §7). No file is a first start. A file this
    /// build cannot read is dropped whole and the lists are left as they
    /// were; the path is kept either way, so the next store replaces it.
    /// Returns how many addresses entered gray.
    pub fn open_address_file<R: RelayRng + ?Sized>(
        &self,
        path: PathBuf,
        rng: &mut R,
    ) -> Result<usize, LoadError> {
        let store = AddressStore::new(path);
        let loaded = store.load();
        *self.store.lock().expect("address store") = Some(store);
        let addresses = loaded?;
        let now = self.hub.now();
        let mut shared = self.shared();
        shared.last_store = Some(now);
        Ok(shared.lists.restore(addresses, rng))
    }

    /// Write the address file now: every list address, by range only,
    /// less those under an active ban at this moment (the hub's bans, the
    /// snapshot the draws read). `Ok(false)` when no file was named.
    ///
    /// The ban snapshot and the clock are read before the store lock, so no
    /// hub call is made under it. Two stores that overlap may therefore
    /// write in either order: the later write can carry the earlier
    /// snapshot. Each is a whole file of the lists at its own moment, and
    /// the next store, at most one interval later, replaces it.
    pub fn store_addresses(&self) -> io::Result<bool> {
        let mut bans = BanSnapshot::take(&self.hub);
        let now = self.hub.now();
        let store = self.store.lock().expect("address store");
        let Some(store) = store.as_ref() else {
            return Ok(false);
        };
        let addresses = self.shared().lists.persistable(&mut bans, now);
        store.write(&addresses)?;
        self.shared().last_store = Some(now);
        Ok(true)
    }

    /// Write the address file when [`STORE_INTERVAL_NANOS`] has passed
    /// since it was last written or read. `Ok(false)` when it is not due
    /// or no file was named.
    pub fn store_if_due(&self, now: Tick) -> io::Result<bool> {
        let due = self
            .shared()
            .last_store
            .is_none_or(|last| now.get().saturating_sub(last.get()) >= STORE_INTERVAL_NANOS);
        if !due {
            return Ok(false);
        }
        self.store_addresses()
    }

    fn record<R: RelayRng + ?Sized>(
        shared: &mut Shared,
        connector: ConnectorId,
        outcome: &DialOutcome,
        now: Tick,
        rng: &mut R,
    ) {
        shared.attempts(connector).finish(outcome);
        shared.lists.apply(outcome, now, rng);
        let held = Self::tor_held(shared);
        shared.tor_link.observe(connector, outcome, held);
    }

    /// A finished attempt's outcome, or its deferral. A `DialFailed` whose
    /// cause is worth a retry, with attempts left in this test, is not
    /// recorded: the open test waits its [`retry_wait_nanos`] and the
    /// address stays an outstanding draw. The wake at or after the due
    /// tick makes the next attempt. A Tor timeout whose attempt ran
    /// `ran_nanos` (timed inside its task) at or past the Tor window is
    /// not worth one
    /// ([`Self::set_tor_window`]). Anything else, including a test that is
    /// not in flight, is the test's one outcome and is recorded. A
    /// deferred Tor failure still counts in the tally: the stream did not
    /// open. The inbound count is taken under the table lock, across the
    /// dialer's.
    fn settle_or_retry<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        outcome: &DialOutcome,
        ran_nanos: u64,
        rng: &mut R,
    ) {
        let now = self.hub.now();
        self.with_inbound(|shared| {
            let address = outcome.address();
            if let DialOutcome::DialFailed(_, cause) = outcome {
                let outlasted_tor = connector == ConnectorId::Tor
                    && cause.window_timeout()
                    && shared.tor_window.is_some_and(|window| ran_nanos >= window);
                if cause.retry_worthy() && !outlasted_tor {
                    let cause = *cause;
                    let mut wait = 0u64;
                    let next = shared.attempts(connector).defer_retry(
                        address,
                        attempts_per_test(connector),
                        |next| {
                            wait = retry_wait_nanos(next, rng);
                            Tick::new(now.get().saturating_add(wait))
                        },
                    );
                    if let Some(next) = next {
                        tracing::debug!(
                            "{connector:?} dial {address:?} attempt {} ended {:?} after {} ms; attempt {next} in {} ms",
                            next - 1,
                            cause.kind(),
                            ran_nanos / 1_000_000,
                            wait / 1_000_000
                        );
                        let held = Self::tor_held(shared);
                        shared.tor_link.observe(connector, outcome, held);
                        return;
                    }
                }
            }
            Self::record(shared, connector, outcome, now, rng);
        });
    }

    /// Record `SessionAccepted` and the kept row in one lock section, mark
    /// the session established on the hub, then notify the strand and start
    /// the pump. The poster of that notification already sees the kept
    /// session, an empty in-flight count, and an established row whose gap
    /// sender has fired. `Post::Established` was posted by `adopt`, before
    /// this runs.
    ///
    /// A close that reached the dialer after `adopt` and before this lock
    /// section left its cause in `adopting`. The dial is then
    /// `DialFailed` with that cause, no kept row is written, nothing is
    /// posted, and this returns `false`: the hub posts a close once, so a
    /// kept row written after it would never leave.
    fn accept_and_notify<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        address: &NetworkAddress,
        kept: KeptDial,
        rng: &mut R,
    ) -> bool {
        let now = self.hub.now();
        let closed = self.with_inbound(|shared| {
            let closed = shared.adopting.remove(&kept.id.get()).flatten();
            let outcome = match closed {
                Some(cause) => DialOutcome::DialFailed(address.clone(), cause),
                None => DialOutcome::SessionAccepted(address.clone()),
            };
            Self::record(shared, connector, &outcome, now, rng);
            if closed.is_none() {
                shared.kept.insert(kept.id.get(), address.clone());
            }
            closed
        });
        if let Some(cause) = closed {
            tracing::debug!(
                "{connector:?} dial {address:?} closed before it was kept ({:?})",
                cause.kind()
            );
            return false;
        }
        tracing::debug!("{connector:?} dial {address:?} kept as {:?}", kept.id);
        self.hub.session_established(kept.id);
        self.hub
            .post_handshake_result(kept.id, connector, kept.sync);
        self.hub.drive(kept.id, kept.session);
        true
    }

    /// Run the owner loop for `connector` on the calling thread, until
    /// [`Self::stop`], the owner's deregistration, or the engine's close.
    ///
    /// `owner` is this loop's registration on the timing engine. Each
    /// wake is armed at the engine's clock plus the gap of
    /// [`next_wake_nanos`], drawn per wake from `rng`, the daemon's CSPRNG.
    /// The loop never waits on a dial: it waits on its wake or the bell
    /// together. A bell applies the results attempt tasks posted and waits
    /// again on the same armed wake; only a wake launches, one attempt per
    /// wake, so the pace (R3) is unchanged and a slow dial skips no wake.
    pub fn run<C: Clock, R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        owner: &OwnerHandle<C>,
        rng: &mut R,
    ) {
        let mut parked: Option<NotReady> = None;
        loop {
            // The bell first, then the stop, then readiness. `stop` sets its
            // flag before it rings, so a ring already counted in `seen` is a
            // stop this check sees; and a ring after the read ends the wait.
            let seen = self.bell.rung();
            if self.stop.load(Ordering::Acquire) {
                break;
            }
            self.apply_completions(connector, rng);
            match self.readiness(connector) {
                Err(missing) => {
                    if parked != Some(missing) {
                        tracing::info!("{connector:?}: the dialer waits: {}", missing.describe());
                        parked = Some(missing);
                    }
                    if !park(&self.bell, owner, seen) {
                        break;
                    }
                    continue;
                }
                Ok(()) => {
                    if parked.take().is_some() {
                        tracing::info!("{connector:?}: the dialer resumes");
                    }
                }
            }
            let deadline = Tick::new(
                owner
                    .clock()
                    .now()
                    .get()
                    .saturating_add(next_wake_nanos(rng)),
            );
            if owner.arm(deadline).is_err() {
                break;
            }
            // Wait for the armed wake. A bell meanwhile is a posted result
            // or a stop: apply, and wait again on the same wake.
            let mut seen = seen;
            loop {
                match wait_wake_or_bell(&self.bell, owner, seen) {
                    Waited::Wake => break,
                    Waited::Ended => return,
                    Waited::Bell => {
                        // The bell, then the stop, as above: a stop's ring
                        // counted in `seen` is a stop this check sees.
                        seen = self.bell.rung();
                        if self.stop.load(Ordering::Acquire) {
                            return;
                        }
                        self.apply_completions(connector, rng);
                    }
                }
            }
            if self.stop.load(Ordering::Acquire) {
                break;
            }
            if let Err(err) = self.store_if_due(self.hub.now()) {
                tracing::warn!("the address file was not written: {err}");
            }
            self.apply_completions(connector, rng);
            self.launch(connector, rng);
        }
    }

    /// One wake's plan and draw. `None` when this wake dials nothing.
    ///
    /// Readiness comes first (`TSR-F1`). A connector that cannot dial returns
    /// here, before the lists are settled or a stranded connector is
    /// re-admitted: a draw it cannot dial ends as `DialFailed(LocalClose)`,
    /// and that cause carries no proof, so the outstanding gray address
    /// cools. The lists are then
    /// demoted and expired once ([`Peerlist::settle`]), counted and drawn
    /// from that view. A stranded connector re-admits its configured
    /// addresses and dials nothing this wake; the next wake draws from what
    /// was admitted. The nonce is minted after the lists lock drops: it does
    /// not depend on the lists, and the nonce set is its own lock. It stays
    /// in flight until it is dropped. Public so a test can read the draw
    /// without running the loop.
    pub fn choose<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        rng: &mut R,
    ) -> Option<(NetworkAddress, DialAim, InFlightNonce)> {
        let now = self.hub.now();
        if let Err(missing) = self.readiness(connector) {
            tracing::debug!("{connector:?} wake: nothing drawn: {}", missing.describe());
            return None;
        }
        let live = live_sessions(&self.hub, connector);
        let mut bans = BanSnapshot::take(&self.hub);
        let mut shared = self.shared();
        let wake = plan_wake(&mut shared, &mut bans, connector, &live, now, rng);
        let (address, aim) = match wake {
            Wake::Recover => {
                // `plan_wake` already reported this wake. A report that
                // closed the episode opens the next one here.
                recovery::re_admit(&mut shared, &mut bans, connector, now, rng);
                return None;
            }
            Wake::Idle => return None,
            Wake::Drawn { address, aim } => (address, aim),
        };
        drop(shared);
        Some((address, aim, self.nonces.mint(connector, rng)))
    }
}
