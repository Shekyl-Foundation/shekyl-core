// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The dialer's owner: one loop per connector that wakes, plans and draws.
//! The handshake module opens the channel, reads the response, and either
//! adopts a kept session or closes a confirm dial in Rust (dialer brief,
//! "The fill", "The dial", "`DialOutcome`").
//!
//! The loop runs on a thread of its own. Its wake is a timing-engine owner
//! (Rick, 2026-10-13): each gap is armed on the engine and the thread
//! waits for the wake; the daemon has one scheduler and the dialer brings
//! no second one. `Hub::dial_channel` blocks that thread while the
//! connector opens the channel, and the handshake reads the channel's
//! frames on it. No p2p io worker is held.
//!
//! A wake draws only when the connector can dial: its link is usable and the
//! tip and the network id are known (`TSR-F1`; the `ready` module). While one
//! is missing the loop does not arm its timer. It waits on the change that
//! could supply it, and the wake spacing resumes when the connector is ready.

mod address;
pub(crate) use address::address_of;
mod handshake;
mod ready;
mod recovery;

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use shekyl_draw_rng::RelayRng;
use shekyl_peerlist::{
    white_diversity_floor, CloseCause, CloseKind, ConnectionId, ConnectorId, DialOutcome,
    NetworkAddress, Peerlist, Refusal, RefusedSet, Source, Tick, WHITE_REFILL_LINE,
};
use shekyl_relay_privacy::params::{MIN_PROVISIONED_OUT_PEERS, P2P_DEFAULT_OUT_PEERS};
use shekyl_seam::{Hub, SocketId, Subscription, SyncPayload};
use shekyl_timing_engine::{Clock, OwnerHandle};

use self::address::{live_sessions, LiveSessions};
use self::handshake::{Attempt, KeptDial};
pub use self::ready::NotReady;
use self::ready::{park, Bell};
use crate::attempts::Attempts;
use crate::bans::BanSnapshot;
use crate::candidate::CandidateFilter;
use crate::fill::{plan, Census, DialAim, DrawList, IN_FLIGHT_BOUND};
use crate::nonce::{HandshakeNonce, HandshakeNonceSet, InFlightNonce};
use crate::pace::{attempts_per_test, next_wake_nanos, retry_wait_nanos};
use crate::store::{AddressStore, LoadError, STORE_INTERVAL_NANOS};

/// This node's sync payload, read at each handshake. `None` when the core
/// has not published a tip yet: the dialer then dials nothing, because a
/// handshake without the chain's height is not one.
pub type SnapshotSource = Arc<dyn Fn() -> Option<SyncPayload> + Send + Sync>;

/// Why a connector under its target dialed nothing on one wake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdleWhy {
    /// A dial is already in flight, so the fill draws nothing.
    InFlight,
    /// A test is waiting for its next attempt, and nothing else is drawable.
    RetryWaiting,
    /// The lists have nothing the fill can draw.
    NoCandidate,
    /// Gray or white holds addresses, and every one is filtered out.
    Filtered,
}

impl IdleWhy {
    fn reason(self) -> &'static str {
        match self {
            Self::InFlight => "a dial is in flight",
            Self::RetryWaiting => "a retry is waiting",
            Self::NoCandidate => "no candidate",
            Self::Filtered => "a filter holds every address",
        }
    }
}

/// Consecutive wakes of one [`IdleWhy`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IdleWatch {
    why: IdleWhy,
    wakes: u32,
    warned: bool,
}

/// How many wakes a connector may sit under its target with nothing dialed
/// before the owner says so. One warning, then silence until the reason
/// changes, the connector draws, or it is no longer under its target.
const IDLE_WARN_WAKES: u32 = 60;

/// One test's next attempt, waiting for its tick.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Retry {
    address: NetworkAddress,
    aim: DialAim,
    /// The attempt this will be, 2 or 3.
    attempt: u8,
    due: Tick,
}

/// The state the owner loops and the FFI calls share.
pub struct Shared {
    /// The peer lists. [`Peerlist::apply`] stays the only writer of gray
    /// and white; this struct is where the dialer keeps them.
    pub lists: Peerlist,
    /// Tests waiting for their next attempt, per connector (the gray
    /// lifecycle, item 3). The address stays an outstanding draw on the
    /// lists meanwhile, and the wait holds no in-flight slot.
    retries: [Vec<Retry>; ConnectorId::COUNT],
    /// Which attempt of its test each in-flight or waiting address is on.
    /// Absent is the first attempt.
    attempt_of: BTreeMap<NetworkAddress, u8>,
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
    idle: [Option<IdleWatch>; ConnectorId::COUNT],
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
}

impl Shared {
    fn attempts(&mut self, connector: ConnectorId) -> &mut Attempts {
        &mut self.attempts[connector.index()]
    }

    fn view(&self, connector: ConnectorId) -> &Attempts {
        &self.attempts[connector.index()]
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
                retries: [Vec::new(), Vec::new()],
                attempt_of: BTreeMap::new(),
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
            })),
            nonces: HandshakeNonceSet::new(),
            stop: Arc::new(AtomicBool::new(false)),
            network_id: Mutex::new(None),
            snapshot,
            store: Mutex::new(None),
            owners: Mutex::new([false; ConnectorId::COUNT]),
            bell,
            _links_watch: links_watch,
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
    /// white. Any other cause only drops the kept row. An id this dialer
    /// is not keeping is a no-op: a dial still in the handshake has no row
    /// here yet, and a confirm dial never has one.
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
            return;
        }
        let Some(address) = shared.kept.remove(&id.get()) else {
            return;
        };
        let Some(connector) = Peerlist::connector_of(&address) else {
            return;
        };
        if cause.kind() == CloseKind::SessionRefused {
            let outcome = DialOutcome::PayloadRefused(address.clone());
            Self::record(&mut shared, connector, &outcome, now, rng);
        }
        // White expiry follows the connection (the gray lifecycle, item 1):
        // the clock moves to the close, so the 24 hours count from here.
        shared.lists.session_ended(&address, now);
        shared.attempts(connector).session_closed(&address);
    }

    /// Stop every owner loop at its next wake, and write the address file
    /// once more. A loop blocked in the engine's wait returns when its
    /// owner is deregistered or the engine closes, which zone shutdown
    /// does.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        self.bell.ring();
        if let Err(err) = self.store_addresses() {
            tracing::warn!("the address file was not written at stop: {err}");
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
    pub fn store_addresses(&self) -> io::Result<bool> {
        let store = self.store.lock().expect("address store");
        let Some(store) = store.as_ref() else {
            return Ok(false);
        };
        let mut bans = BanSnapshot::take(&self.hub);
        let now = self.hub.now();
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
        shared.attempt_of.remove(outcome.address());
        shared.lists.apply(outcome, now, rng);
    }

    /// A finished attempt's outcome, or its deferral: a `DialFailed` whose
    /// cause is worth a retry, with attempts left in this test, is not
    /// recorded. The attempt leaves the pending set and waits its
    /// [`retry_wait_nanos`]; the address stays an outstanding draw. The
    /// wake at or after the due tick makes the next attempt. Anything else
    /// is the test's one outcome and is recorded.
    fn settle_or_retry<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        outcome: &DialOutcome,
        rng: &mut R,
    ) {
        let now = self.hub.now();
        let mut shared = self.shared();
        let address = outcome.address();
        let attempt = shared.attempt_of.get(address).copied().unwrap_or(1);
        let retry = match outcome {
            DialOutcome::DialFailed(_, cause)
                if cause.retry_worthy() && attempt < attempts_per_test(connector) =>
            {
                Some(cause)
            }
            _ => None,
        };
        let Some(cause) = retry else {
            Self::record(&mut shared, connector, outcome, now, rng);
            return;
        };
        let next = attempt.saturating_add(1);
        let wait = retry_wait_nanos(next, rng);
        let aim = shared
            .attempts(connector)
            .aim_of(address)
            .unwrap_or(DialAim::Keep);
        shared.attempts(connector).defer(address);
        shared.attempt_of.insert(address.clone(), next);
        shared.retries[connector.index()].push(Retry {
            address: address.clone(),
            aim,
            attempt: next,
            due: Tick::new(now.get().saturating_add(wait)),
        });
        tracing::debug!(
            "{connector:?} dial {address:?} attempt {attempt} ended {:?}; attempt {next} in {} ms",
            cause.kind(),
            wait / 1_000_000
        );
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
        let closed = {
            let mut shared = self.shared();
            let closed = shared.adopting.remove(&kept.id.get()).flatten();
            let outcome = match closed {
                Some(cause) => DialOutcome::DialFailed(address.clone(), cause),
                None => DialOutcome::SessionAccepted(address.clone()),
            };
            Self::record(&mut shared, connector, &outcome, now, rng);
            if closed.is_none() {
                shared.kept.insert(kept.id.get(), address.clone());
            }
            closed
        };
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
    /// [`next_wake_nanos`], drawn per dial from `rng`, the daemon's CSPRNG.
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
            if owner.wait_wake().is_err() {
                break;
            }
            if self.stop.load(Ordering::Acquire) {
                break;
            }
            if let Err(err) = self.store_if_due(self.hub.now()) {
                tracing::warn!("the address file was not written: {err}");
            }
            self.wake(connector, rng);
        }
    }

    /// One wake's work: the plan, and the dial it chose. Returns whether a
    /// dial was made. The owner loop calls this when its timer fires; a test
    /// calls it directly to run wakes without the clock.
    pub fn wake<R: RelayRng + ?Sized>(&self, connector: ConnectorId, rng: &mut R) -> bool {
        let Some((address, aim, nonce)) = self.choose(connector, rng) else {
            return false;
        };
        tracing::debug!("{connector:?} dial {address:?} aim {aim:?}");
        match self.exchange(connector, &address, aim, &nonce, rng) {
            Attempt::Done(outcome) => {
                tracing::debug!("{connector:?} dial {address:?} ended: {outcome:?}");
                self.settle_or_retry(connector, &outcome, rng);
            }
            Attempt::Kept(kept) => {
                self.accept_and_notify(connector, &address, kept, rng);
            }
        }
        // The nonce leaves the set here: the attempt ended, by any path.
        drop(nonce);
        true
    }

    /// One dial of `address` with `aim`, outside the wake loop: the draw
    /// of that address, the pending attempt, the nonce and the handshake.
    /// Returns the kept session's id. A confirm dial, a refusal and a
    /// failure return [`None`]: each is recorded before this returns, and
    /// a confirm dial posts nothing. The owner loop draws through
    /// [`Self::choose`]; a test dials one named address here.
    ///
    /// Readiness comes first, as in [`Self::choose`]. A connector that
    /// cannot dial returns [`None`] before any draw: a draw it cannot dial
    /// ends as `DialFailed(LocalClose)`, and the list rule drops a drawn
    /// gray address.
    ///
    /// A gray address is drawn here, so the outcome resolves an
    /// outstanding draw as the lists require. A white address is a
    /// re-contact and is not drawn. An address on neither list is not
    /// dialed.
    pub fn dial<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        address: &NetworkAddress,
        aim: DialAim,
        rng: &mut R,
    ) -> Option<SocketId> {
        if let Err(missing) = self.readiness(connector) {
            tracing::debug!(
                "{connector:?} dial {address:?} not made: {}",
                missing.describe()
            );
            return None;
        }
        {
            let mut shared = self.shared();
            if shared.lists.is_gray(address) {
                let drawn = shared
                    .lists
                    .draw_gray_where(connector, &mut |a| a == address, rng)?;
                debug_assert_eq!(&drawn, address);
            } else if !shared.lists.is_white(address) {
                return None;
            }
            if !shared.attempts(connector).begin(address, aim) {
                return None;
            }
        }
        let nonce = self.nonces.mint(connector, rng);
        match self.exchange(connector, address, aim, &nonce, rng) {
            Attempt::Done(outcome) => {
                self.settle_or_retry(connector, &outcome, rng);
                None
            }
            Attempt::Kept(kept) => {
                let id = kept.id;
                self.accept_and_notify(connector, address, kept, rng)
                    .then_some(id)
            }
        }
    }

    /// One wake's plan and draw. `None` when this wake dials nothing.
    ///
    /// Readiness comes first (`TSR-F1`). A connector that cannot dial returns
    /// here, before the lists are settled or a stranded connector is
    /// re-admitted: a draw it cannot dial ends as `DialFailed(LocalClose)`,
    /// and the list rule drops a drawn gray address. The lists are then
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

/// What one settled wake decided.
enum Wake {
    /// Under the target, nothing in flight, and no drawable candidate.
    /// The caller re-admits the configured population and dials nothing.
    Recover,
    /// This wake dials nothing.
    Idle,
    /// An attempt was begun. The nonce is minted after the lists lock drops.
    Drawn {
        address: NetworkAddress,
        aim: DialAim,
    },
}

/// What the census says about an under-target wake that does not draw.
/// `None` when the connector is not under its target: the watch clears.
fn idle_if_undrawn(census: &Census) -> Option<IdleWhy> {
    if census.target == 0 || census.kept >= census.target {
        return None;
    }
    if census.in_flight >= IN_FLIGHT_BOUND {
        return Some(IdleWhy::InFlight);
    }
    if census
        .white_candidates
        .saturating_add(census.gray_candidates)
        > 0
    {
        // The lists hold a drawable address and no rule took it.
        return Some(IdleWhy::NoCandidate);
    }
    if census.white.saturating_add(census.gray) > 0 {
        return Some(IdleWhy::Filtered);
    }
    Some(IdleWhy::NoCandidate)
}

/// Settle once, count once, and either recover, idle, or begin one attempt.
/// [`Dialer::choose`] has already returned when the connector cannot dial.
/// `bans` was copied out of the hub before the lists lock was taken.
fn plan_wake<R: RelayRng + ?Sized>(
    shared: &mut Shared,
    bans: &mut BanSnapshot,
    connector: ConnectorId,
    live: &LiveSessions,
    now: Tick,
    rng: &mut R,
) -> Wake {
    let index = connector.index();
    let target = shared.targets[index];
    // A test whose next attempt is due makes it now, ahead of any draw: the
    // address is still the outstanding draw, so nothing draws it twice.
    if shared.attempts[index].in_flight() < IN_FLIGHT_BOUND {
        let due = shared.retries[index]
            .iter()
            .position(|retry| retry.due.get() <= now.get());
        if let Some(at) = due {
            let retry = shared.retries[index].remove(at);
            if shared.attempts[index].begin(&retry.address, retry.aim) {
                note_idle(shared, connector, None);
                return Wake::Drawn {
                    address: retry.address,
                    aim: retry.aim,
                };
            }
            // The address is already pending or kept: the test is over.
            shared.attempt_of.remove(&retry.address);
        }
    }
    let waiting = !shared.retries[index].is_empty();
    let own = shared.own[index].clone();
    let exclusive = shared.exclusive.clone();
    let (wake, undrawn, kept) = {
        let Shared {
            lists, attempts, ..
        } = &mut *shared;
        let kept = attempts[index].kept_count();
        let in_flight = attempts[index].in_flight();
        let mut settled = lists.settle(connector, now, bans, rng);
        let mut filter = CandidateFilter {
            own: &own,
            sessions: &live.addresses,
            outbound_hosts: &live.outbound_hosts,
            attempts: &attempts[index],
            bans: &mut *bans,
            now,
        };
        let mut eligible = |address: &NetworkAddress| {
            exclusive
                .as_ref()
                .is_none_or(|population| population.contains(address))
                && filter.admits(address)
        };
        let seats = settled.census(&mut eligible);
        let census = Census {
            kept,
            in_flight,
            target,
            white: seats.white,
            white_candidates: seats.white_candidates,
            gray: seats.gray,
            gray_candidates: seats.gray_candidates,
        };
        let undrawn = idle_if_undrawn(&census);
        // Stranded: under the target, nothing in flight, nothing drawable.
        // The lists cannot yield another peer, so this wake re-admits and
        // dials nothing. One kept session is not a healthy connector
        // (dialer brief, "Recovery").
        let stranded = kept < target
            && in_flight == 0
            && !waiting
            && census.white_candidates == 0
            && census.gray_candidates == 0;
        let wake = if stranded {
            Wake::Recover
        } else {
            match plan(&census, white_diversity_floor(), WHITE_REFILL_LINE) {
                None => {
                    tracing::debug!("{connector:?} wake: no rule applies ({census:?})");
                    Wake::Idle
                }
                Some(chosen) => {
                    let drawn = match chosen.list {
                        DrawList::Gray => settled.draw_gray(&mut eligible, rng),
                        DrawList::White => settled.draw_white(&mut eligible, rng),
                    };
                    match drawn {
                        Some(address) => Wake::Drawn {
                            address,
                            aim: chosen.aim,
                        },
                        None => {
                            tracing::debug!(
                                "{connector:?} wake: {:?} chose {:?}, nothing drawn ({census:?})",
                                chosen.rule,
                                chosen.list
                            );
                            Wake::Idle
                        }
                    }
                }
            }
        };
        (wake, undrawn, kept)
    };
    // `kept` is the count before this wake's dial. A session the previous
    // wake kept is visible here, including when this wake is stranded.
    let drawn = match &wake {
        Wake::Drawn { address, .. } => Some(address),
        Wake::Recover | Wake::Idle => None,
    };
    recovery::report_wake(&mut shared.recovery[index], connector, kept, target, drawn);
    let wake = match wake {
        Wake::Recover | Wake::Idle => wake,
        Wake::Drawn { address, aim } => {
            if shared.attempts[index].begin(&address, aim) {
                Wake::Drawn { address, aim }
            } else {
                tracing::debug!("{connector:?} wake: {address:?} already has an attempt");
                Wake::Idle
            }
        }
    };
    let idle = match wake {
        Wake::Drawn { .. } => None,
        Wake::Recover | Wake::Idle => undrawn.map(|why| {
            if waiting && why == IdleWhy::NoCandidate {
                IdleWhy::RetryWaiting
            } else {
                why
            }
        }),
    };
    note_idle(shared, connector, idle);
    wake
}

/// Count an under-target wake that dialed nothing. The first time the
/// same reason reaches [`IDLE_WARN_WAKES`], say so once. A draw, a change
/// of reason, or leaving the under-target state clears the count.
fn note_idle(shared: &mut Shared, connector: ConnectorId, why: Option<IdleWhy>) {
    let slot = &mut shared.idle[connector.index()];
    let Some(why) = why else {
        *slot = None;
        return;
    };
    match slot {
        Some(watch) if watch.why == why => {
            watch.wakes = watch.wakes.saturating_add(1);
            if watch.wakes == IDLE_WARN_WAKES && !watch.warned {
                watch.warned = true;
                let reason = why.reason();
                tracing::warn!(
                    "{connector:?}: under its target for {IDLE_WARN_WAKES} wakes with nothing dialed: {reason}"
                );
            }
        }
        _ => {
            *slot = Some(IdleWatch {
                why,
                wakes: 1,
                warned: false,
            })
        }
    }
}
