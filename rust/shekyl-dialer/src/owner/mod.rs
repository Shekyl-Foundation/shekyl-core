// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The dialer's owner: one loop per connector that wakes, plans and draws.
//! The handshake module opens the channel, reads the response, adopts the
//! session and posts the result (dialer brief, "The fill", "The dial",
//! "`DialOutcome`").
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
mod handshake;
mod ready;

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
use shekyl_seam::{Hub, SocketId, SyncPayload};
use shekyl_timing_engine::{Clock, OwnerHandle};

use self::address::{live_sessions, LiveSessions};
use self::handshake::Attempt;
use self::ready::Bell;
pub use self::ready::NotReady;
use crate::attempts::Attempts;
use crate::bans::HubBans;
use crate::candidate::CandidateFilter;
use crate::fill::{plan, Census, DialAim, DrawList};
use crate::memory::FailedAddresses;
use crate::nonce::{HandshakeNonce, HandshakeNonceSet, InFlightNonce};
use crate::pace::next_wake_nanos;
use crate::store::{AddressStore, LoadError, STORE_INTERVAL_NANOS};

/// This node's sync payload, read at each handshake. `None` when the core
/// has not published a tip yet: the dialer then dials nothing, because a
/// handshake without the chain's height is not one.
pub type SnapshotSource = Arc<dyn Fn() -> Option<SyncPayload> + Send + Sync>;

/// A dial the strand has not yet answered.
#[derive(Debug, Clone)]
struct Pending {
    connector: ConnectorId,
    address: NetworkAddress,
    keep: bool,
}

/// The state the owner loops and the FFI calls share.
pub struct Shared {
    /// The peer lists. [`Peerlist::apply`] stays the only writer of gray
    /// and white; this struct is where the dialer keeps them.
    pub lists: Peerlist,
    /// The failed-address memory.
    pub memory: FailedAddresses,
    attempts: Vec<Attempts>,
    targets: Vec<usize>,
    own: Vec<Vec<NetworkAddress>>,
    /// Dials adopted and posted, awaiting the strand's verdict.
    pending: BTreeMap<u64, Pending>,
    /// Kept sessions by id, so a close can name the address.
    kept: BTreeMap<u64, NetworkAddress>,
    /// A closed network (`--add-exclusive-node`): the candidate
    /// population, when set. Not a dialer arm.
    exclusive: Option<BTreeSet<NetworkAddress>>,
    /// Every operator-named address this dialer was given (the compiled
    /// seeds, `--add-peer`), in the order given: what a stranded connector
    /// re-admits when no closed network is declared.
    configured: Vec<NetworkAddress>,
    /// Which connectors are stranded: no kept session, nothing in flight,
    /// and no drawable candidate at their last wake.
    stranded: [bool; ConnectorId::COUNT],
    /// When the address file was last written or read; `None` until
    /// then, so the first due store is one interval after the open.
    last_store: Option<Tick>,
}

impl Shared {
    fn attempts(&mut self, connector: ConnectorId) -> &mut Attempts {
        &mut self.attempts[connector.index()]
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
    support_flags: u32,
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
    /// `support_flags` is what every handshake request carries, with the
    /// network id given later by [`Self::set_network_id`]. `snapshot` is
    /// the core's latest published tip, and [`Self::tip_published`] says
    /// when it changes. Until both are known, and the connector's link on
    /// `hub` is usable, the owner loops draw nothing.
    #[must_use]
    pub fn new(
        hub: Hub,
        refused: RefusedSet,
        support_flags: u32,
        snapshot: SnapshotSource,
    ) -> Self {
        let mut targets = vec![0usize; ConnectorId::COUNT];
        targets[ConnectorId::Clearnet.index()] = P2P_DEFAULT_OUT_PEERS as usize;
        targets[ConnectorId::Tor.index()] = MIN_PROVISIONED_OUT_PEERS as usize;
        let bell = Arc::new(Bell::new());
        let heard = Arc::downgrade(&bell);
        hub.links().subscribe(Arc::new(move |_| {
            if let Some(bell) = heard.upgrade() {
                bell.ring();
            }
        }));
        Self {
            hub,
            shared: Arc::new(Mutex::new(Shared {
                lists: Peerlist::new(refused),
                memory: FailedAddresses::new(),
                attempts: (0..ConnectorId::COUNT).map(|_| Attempts::new()).collect(),
                targets,
                own: vec![Vec::new(); ConnectorId::COUNT],
                pending: BTreeMap::new(),
                kept: BTreeMap::new(),
                exclusive: None,
                configured: Vec::new(),
                stranded: [false; ConnectorId::COUNT],
                last_store: None,
            })),
            nonces: HandshakeNonceSet::new(),
            stop: Arc::new(AtomicBool::new(false)),
            network_id: Mutex::new(None),
            support_flags,
            snapshot,
            store: Mutex::new(None),
            owners: Mutex::new([false; ConnectorId::COUNT]),
            bell,
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
        let mut shared = self.shared();
        for address in &addresses {
            // Already seated: the population is the declaration either way.
            // A refusal is not "already seated" and is said.
            if let Err(refusal) = shared.lists.admit_gray(
                address,
                Source::Operator,
                now,
                &mut HubBans(&self.hub),
                rng,
            ) {
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
        let mut shared = self.shared();
        if !shared.configured.contains(address) {
            shared.configured.push(address.clone());
        }
        shared
            .lists
            .admit_gray(address, Source::Operator, now, &mut HubBans(&self.hub), rng)
    }

    /// The inbound handshake's question: is `nonce` one of ours in flight
    /// on `connector`? Erases it.
    #[must_use]
    pub fn take_nonce(&self, connector: ConnectorId, nonce: &HandshakeNonce) -> bool {
        self.nonces.take(connector, nonce)
    }

    /// The strand accepted or refused the sync payload of the handshake
    /// posted for `id`. A kept dial that was accepted stays; a confirm
    /// dial that was accepted is closed here; a refused dial of either
    /// aim is closed here. The outcome reaches the lists and the memory.
    pub fn verdict<R: RelayRng + ?Sized>(&self, id: SocketId, accepted: bool, rng: &mut R) {
        let pending = self.shared().pending.remove(&id.get());
        let Some(pending) = pending else {
            return;
        };
        let outcome = match (accepted, pending.keep) {
            (true, true) => DialOutcome::SessionAccepted(pending.address.clone()),
            (true, false) => DialOutcome::Confirmed(pending.address.clone()),
            (false, _) => DialOutcome::PayloadRefused(pending.address.clone()),
        };
        tracing::info!(
            "{:?} dial {:?}: {outcome:?}",
            pending.connector,
            pending.address
        );
        if !matches!(outcome, DialOutcome::SessionAccepted(_)) {
            self.hub.close(id);
        }
        let mut shared = self.shared();
        if matches!(outcome, DialOutcome::SessionAccepted(_)) {
            shared.kept.insert(id.get(), pending.address.clone());
        }
        Self::record(
            &mut shared,
            pending.connector,
            &outcome,
            self.hub.now(),
            rng,
        );
    }

    /// The session `id` closed. A kept session leaves the kept count; a
    /// dial still awaiting its verdict is a failure with the cause the
    /// connector stored.
    pub fn session_closed<R: RelayRng + ?Sized>(&self, id: SocketId, rng: &mut R) {
        let mut shared = self.shared();
        if let Some(address) = shared.kept.remove(&id.get()) {
            let connector = Peerlist::connector_of(&address);
            if let Some(connector) = connector {
                shared.attempts(connector).session_closed(&address);
            }
            return;
        }
        if let Some(pending) = shared.pending.remove(&id.get()) {
            let cause = self
                .hub
                .cause(id)
                .unwrap_or_else(|| CloseCause::new(CloseKind::LocalClose));
            let outcome = DialOutcome::DialFailed(pending.address, cause);
            Self::record(
                &mut shared,
                pending.connector,
                &outcome,
                self.hub.now(),
                rng,
            );
        }
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
        let mut shared = self.shared();
        shared.last_store = Some(self.hub.now());
        Ok(shared.lists.restore(addresses, rng))
    }

    /// Write the address file now: every list address, by range only.
    /// `Ok(false)` when no file was named.
    pub fn store_addresses(&self) -> io::Result<bool> {
        let store = self.store.lock().expect("address store");
        let Some(store) = store.as_ref() else {
            return Ok(false);
        };
        let addresses = self.shared().lists.persistable();
        store.write(&addresses)?;
        self.shared().last_store = Some(self.hub.now());
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
        shared.memory.observe(outcome, now);
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
        while !self.stop.load(Ordering::Acquire) {
            // Read the bell before the check: a ring between the two still
            // ends the wait.
            let seen = self.bell.rung();
            match self.readiness(connector) {
                Err(missing) => {
                    if parked != Some(missing) {
                        tracing::info!("{connector:?}: the dialer waits: {}", missing.describe());
                        parked = Some(missing);
                    }
                    self.bell.wait_past(seen);
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
                let mut shared = self.shared();
                Self::record(&mut shared, connector, &outcome, self.hub.now(), rng);
            }
            Attempt::Posted(id) => {
                tracing::debug!("{connector:?} dial {address:?} handshake posted as {id:?}");
                self.shared().pending.insert(
                    id.get(),
                    Pending {
                        connector,
                        address,
                        keep: aim == DialAim::Keep,
                    },
                );
            }
        }
        // The nonce leaves the set here: the attempt ended, by any path.
        drop(nonce);
        true
    }

    /// One dial of `address` with `aim`, outside the wake loop: the draw
    /// of that address, the pending entry, the nonce, the handshake, the
    /// adopt and the post, or the total outcome. Returns the adopted id
    /// when the strand's verdict is still owed. The owner loop does this
    /// after its own draw; a test does it directly.
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
                let mut shared = self.shared();
                Self::record(&mut shared, connector, &outcome, self.hub.now(), rng);
                None
            }
            Attempt::Posted(id) => {
                self.shared().pending.insert(
                    id.get(),
                    Pending {
                        connector,
                        address: address.clone(),
                        keep: aim == DialAim::Keep,
                    },
                );
                Some(id)
            }
        }
    }

    /// One wake's plan and draw. `None` when this wake dials nothing.
    ///
    /// The lists are demoted and expired once ([`Peerlist::settle`]), then
    /// counted and drawn from that view. A stranded connector re-admits its
    /// configured addresses and dials nothing this wake; the next wake draws
    /// from what was admitted. The nonce is minted after the lists lock
    /// drops: it does not depend on the lists, and the nonce set is its own
    /// lock. It stays in flight until it is dropped. Public so a test can
    /// read the draw without running the loop.
    pub fn choose<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        rng: &mut R,
    ) -> Option<(NetworkAddress, DialAim, InFlightNonce)> {
        let now = self.hub.now();
        let ready = self.readiness(connector);
        let live = live_sessions(&self.hub, connector);
        let mut shared = self.shared();
        let wake = plan_wake(&mut shared, &self.hub, connector, ready, &live, now, rng);
        let (address, aim) = match wake {
            Wake::Recover => {
                re_admit(&mut shared, &self.hub, connector, now, rng);
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
    /// No kept session, nothing in flight, and no drawable candidate.
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

/// Check readiness, then settle once, count once, and either recover, idle,
/// or begin one attempt.
fn plan_wake<R: RelayRng + ?Sized>(
    shared: &mut Shared,
    hub: &Hub,
    connector: ConnectorId,
    ready: Result<(), NotReady>,
    live: &LiveSessions,
    now: Tick,
    rng: &mut R,
) -> Wake {
    // Ahead of every draw (`TSR-F1`): a draw the connector cannot dial ends
    // as `DialFailed(LocalClose)`, and the list rule drops a drawn gray
    // address on that outcome. Nothing is settled, counted or re-admitted.
    if let Err(missing) = ready {
        tracing::debug!("{connector:?} wake: nothing drawn: {}", missing.describe());
        return Wake::Idle;
    }
    let index = connector.index();
    let target = shared.targets[index];
    let own = shared.own[index].clone();
    let exclusive = shared.exclusive.clone();
    let wake = {
        let Shared {
            lists,
            attempts,
            memory,
            ..
        } = &mut *shared;
        let kept = attempts[index].kept_count();
        let in_flight = attempts[index].in_flight();
        let mut bans = HubBans(hub);
        let mut settled = lists.settle(connector, now, &mut bans, rng);
        let mut filter = CandidateFilter {
            own: &own,
            sessions: &live.addresses,
            outbound_hosts: &live.outbound_hosts,
            attempts: &attempts[index],
            failed: memory,
            bans: &mut bans,
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
        // A connector with a target, no kept session, nothing in flight and
        // no drawable candidate cannot get itself a peer. Recovery re-admits
        // after this borrow ends; this wake dials nothing.
        let stranded = target > 0
            && kept == 0
            && in_flight == 0
            && census.white_candidates == 0
            && census.gray_candidates == 0;
        if stranded {
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
        }
    };
    match wake {
        Wake::Recover => Wake::Recover,
        Wake::Idle => {
            note_recovered(shared, connector);
            Wake::Idle
        }
        Wake::Drawn { address, aim } => {
            note_recovered(shared, connector);
            if shared.attempts[index].begin(&address, aim) {
                Wake::Drawn { address, aim }
            } else {
                tracing::debug!("{connector:?} wake: {address:?} already has an attempt");
                Wake::Idle
            }
        }
    }
}

/// Re-admit the closed network, or the configured seeds and `--add-peer`,
/// as operator-named gray. Already seated is quiet. A refusal is said.
fn re_admit<R: RelayRng + ?Sized>(
    shared: &mut Shared,
    hub: &Hub,
    connector: ConnectorId,
    now: Tick,
    rng: &mut R,
) {
    let population: Vec<NetworkAddress> = match &shared.exclusive {
        Some(population) => population.iter().cloned().collect(),
        None => shared.configured.clone(),
    };
    let mut admitted = 0usize;
    for address in population
        .iter()
        .filter(|address| Peerlist::connector_of(address) == Some(connector))
    {
        match shared
            .lists
            .admit_gray(address, Source::Operator, now, &mut HubBans(hub), rng)
        {
            Ok(true) => admitted += 1,
            Ok(false) => {}
            Err(refusal) => tracing::warn!(
                "{connector:?}: configured address {address:?} was not re-admitted: {refusal:?}"
            ),
        }
    }
    let index = connector.index();
    if !shared.stranded[index] {
        shared.stranded[index] = true;
        tracing::info!(
            "{connector:?}: no kept session, nothing in flight and no drawable candidate; re-admitted {admitted} configured address(es) to gray"
        );
    }
}

/// The connector drew, or a dial is in flight, after a stranded wake.
fn note_recovered(shared: &mut Shared, connector: ConnectorId) {
    let index = connector.index();
    if shared.stranded[index] {
        shared.stranded[index] = false;
        tracing::info!(
            "{connector:?}: no longer stranded; a candidate is drawable or a dial is in flight"
        );
    }
}
