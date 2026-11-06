// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The dialer's owner: one loop per connector that wakes, plans and draws.
//! The handshake module asks the session layer for the dial and applies
//! what it returns: a kept session's list is admitted, a confirm dial is
//! recorded (dialer brief, "The fill", "The dial", "`DialOutcome`";
//! `P2P_3_REMNANT_CUTOVER_BRIEF.md` §2.1).
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
//! A wake draws only when the connector can dial: its link is usable
//! (`TSR-F1`; the `ready` module). While it is not the loop does not arm its
//! timer. It waits on the change that could supply it, and the wake spacing
//! resumes when the connector is ready. The tip and the network id are the
//! session layer's: it does not exist before they do.
//! The `tor_tally` module publishes how many Tor sessions are held. The
//! count refreshes when a Tor handshake finishes or a Tor session closes.
//! An inbound session is not a dial.
//!
//! The [`peers`] module is the session layer's peers owner: the layer asks
//! it for the list a handshake or timed sync discloses, hands it the lists
//! peers send, and tells it when a session is established or closed. The
//! two reference each other for the life of the process: the layer is
//! built with the dialer among its owners, then attached to the dialer
//! ([`Dialer::attach`]), which dials through it afterwards.

mod address;
mod flight;
mod handshake;
mod judging;
mod peers;
mod ready;
mod recovery;
mod tor_tally;
mod wake;

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};

use shekyl_draw_rng::RelayRng;
use shekyl_p2p_session::{Board, SessionLayer};
use shekyl_peerlist::{
    dial_profile, white_diversity_floor, ConnectionId, ConnectorId, DialOutcome, ListName,
    NetworkAddress, Peerlist, Refusal, RefusedSet, Source, Tick, Verdict,
};
use shekyl_timing_engine::{Clock, Handle, OwnerHandle};
use shekyl_transport_layer::{
    BanEvent, BanFeed, CloseKind, DialEnd, Links, Retry, SocketId, Sockets, Subscription,
};

use self::address::live_sessions;
pub use self::flight::{Applied, Launch};
use self::flight::{Completions, InFlight};
use self::handshake::KeptDial;
pub use self::ready::NotReady;
use self::ready::{park, wait_wake_or_bell, Bell, Waited};
use self::wake::{plan_wake, Wake};
use crate::attempts::Attempts;
use crate::fill::DialAim;
use crate::link_tally::{LinkFold, TallySink, TorLinkTally};
use crate::pace::{attempts_per_test, next_wake_nanos, retry_wait_nanos};
use crate::store::{AddressStore, LoadError, STORE_INTERVAL_NANOS};

/// The random numbers the owner's own calls draw: the hooks the session
/// layer calls ([`shekyl_p2p_session::PeerOwner`]) carry no generator of
/// the caller's.
pub type OwnerRng = Box<dyn RelayRng + Send>;

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
    /// Kept dials from their channel's open until their kept row is
    /// written, by socket id ([`handshake::Window`]). A close in that window
    /// finds no kept row; it records its cause here instead, and the kept
    /// row is never written for it.
    adopting: BTreeMap<u64, Option<DialEnd>>,
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
    /// drain. The row holds the attempt's cancel until the result is
    /// applied or the attempt is cancelled, and the attempt stays pending
    /// in [`Attempts`] until one of those.
    in_flight: BTreeMap<u64, InFlight>,
    /// Applications that have removed their row and not yet finished.
    /// [`Dialer::stop`] waits for zero, after it has refused every new
    /// application, before it writes the address file. The wait releases
    /// this lock; the session layer is never called under it.
    applying: usize,
    /// The next attempt id.
    next_attempt: u64,
    /// Each connector's in-flight bound, from its dial profile: protocol
    /// data, the same on every node.
    bounds: [usize; ConnectorId::COUNT],
    /// The retry window each connector published with its route, in
    /// nanoseconds ([`Dialer::set_window`]). A connector whose cutoff is its
    /// dial deadline does not read this: the profile's `retry_cutoff_nanos`
    /// answers from the row. `None` while a published window is unknown.
    published_windows: [Option<u64>; ConnectorId::COUNT],
    /// What the Tor dials show, for the managed-Tor supervisor's posture
    /// line (`TOR_SUPERVISOR.md` §4.2). Display only (`TSR-Q14`).
    tor_link: LinkFold,
    /// Each connector's inbound rows last read off the board
    /// ([`Dialer::with_inbound`]).
    inbound: [usize; ConnectorId::COUNT],
    /// What the judge has seen of each connector's link ([`judging`]).
    evidence: [judging::LinkEvidence; ConnectorId::COUNT],
    /// Failed tests whose verdict waits for its bracket to close.
    pending: Vec<judging::PendingVerdict>,
    /// The clock the judge reads, and the sessions' received bytes on it.
    life_clock: judging::LifeClock,
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

/// The outbound dialer for every connector of one process, and the session
/// layer's peers owner.
pub struct Dialer<C: Clock + Clone + Send + Sync + 'static> {
    /// The session layer this dialer dials through, once
    /// [`Self::attach`] gave it. The layer is built with this dialer among
    /// its owners, so it cannot exist first.
    layer: OnceLock<SessionLayer<C>>,
    /// The daemon's one timing engine: the dialer's clock, and the engine
    /// its wakes are owners of.
    timing: Handle<C>,
    /// Each connector's link, whose change rings the bell.
    links: Arc<Links>,
    shared: Arc<Mutex<Shared>>,
    /// The generator the session layer's hooks draw from.
    rng: Mutex<OwnerRng>,
    stop: Arc<AtomicBool>,
    /// The address file, once [`Self::open_address_file`] named it.
    store: Mutex<Option<AddressStore>>,
    /// Which connectors have an owner loop. One per connector: a second
    /// start is refused, not stacked (the ephemeral-tor path and the
    /// proxy-only zone branch both asked for Tor's, 2026-10-13).
    owners: Mutex<[bool; ConnectorId::COUNT]>,
    /// What a parked owner loop waits on. The links ring it on every
    /// change; so do the posted results and the stop.
    bell: Arc<Bell>,
    /// The links ring [`Self::bell`] while this is held. Dropped with the
    /// dialer, so a dialer rebuilt on the same links leaves no watcher.
    _links_watch: Subscription,
    /// The ban list's events, starting with every entry in force when the
    /// dialer was built; each rings [`Self::bell`]. Drained in order under
    /// the dialer's lock, by every [`Self::shared`]. Dropped with the dialer.
    bans: BanFeed,
    /// The results the attempt tasks posted; each also rings the bell.
    completions: Arc<Completions>,
    /// Wakes [`Self::stop`] when the last application that started before
    /// the stop flag was seen has finished.
    apply_idle: Condvar,
}

/// The peerlist's name for a session: the socket id, little-endian, in the
/// first eight bytes.
#[must_use]
pub fn session_of(id: SocketId) -> ConnectionId {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&id.get().to_le_bytes());
    ConnectionId(bytes)
}

impl<C: Clock + Clone + Send + Sync + 'static> Dialer<C> {
    /// A dialer on `timing`'s clock, watching `links` and `sockets`' bans,
    /// with empty lists built over `refused`. `rng` is what the session
    /// layer's hooks draw from.
    ///
    /// It dials nothing until [`Self::attach`] gives it the session layer,
    /// and a connector's owner loop draws nothing while that connector's
    /// link is not usable.
    #[must_use]
    pub fn new(
        timing: Handle<C>,
        links: Arc<Links>,
        sockets: &Sockets,
        refused: RefusedSet,
        rng: OwnerRng,
    ) -> Self {
        let targets: Vec<usize> = ConnectorId::ALL
            .iter()
            .map(|connector| dial_profile(*connector).target as usize)
            .collect();
        let bell = Arc::new(Bell::new());
        let ringing = Arc::clone(&bell);
        let links_watch = links.subscribe(Arc::new(move |_| ringing.ring()));
        let ringing = Arc::clone(&bell);
        let bans = sockets.subscribe_bans(Arc::new(move || ringing.ring()));
        Self {
            layer: OnceLock::new(),
            timing,
            links,
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
                bounds: std::array::from_fn(|index| {
                    dial_profile(ConnectorId::ALL[index]).in_flight_bound
                }),
                published_windows: [None; ConnectorId::COUNT],
                tor_link: LinkFold::new(),
                inbound: [0; ConnectorId::COUNT],
                evidence: [judging::LinkEvidence::default(); ConnectorId::COUNT],
                pending: Vec::new(),
                life_clock: judging::LifeClock::production(),
            })),
            rng: Mutex::new(rng),
            stop: Arc::new(AtomicBool::new(false)),
            store: Mutex::new(None),
            owners: Mutex::new([false; ConnectorId::COUNT]),
            bell,
            _links_watch: links_watch,
            bans,
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

    /// Give the dialer the session layer it dials through. Once: the
    /// composition builds the layer with this dialer among its owners and
    /// attaches it before anything dials.
    ///
    /// # Panics
    ///
    /// When a layer is already attached.
    pub fn attach(&self, layer: SessionLayer<C>) {
        assert!(
            self.layer.set(layer).is_ok(),
            "the dialer's session layer is attached once"
        );
        self.bell.ring();
    }

    /// The attached session layer.
    ///
    /// # Panics
    ///
    /// Before [`Self::attach`]: the composition attaches the layer before
    /// anything dials, and a dial before that is a construction-order bug.
    fn layer(&self) -> &SessionLayer<C> {
        self.layer
            .get()
            .expect("the composition attaches the session layer before anything dials")
    }

    /// The board now: the session layer's rows, or none before a layer is
    /// attached.
    fn board(&self) -> Board {
        self.layer
            .get()
            .map_or_else(Board::empty, SessionLayer::board)
    }

    /// The engine's clock now.
    #[must_use]
    pub fn now(&self) -> Tick {
        self.timing.clock().now()
    }

    /// Store the retry window `connector` published with its route.
    ///
    /// `None` means this node does not know a window, so every timeout on a
    /// connector that reads the publish keeps its retries. A connector whose
    /// cutoff is its dial deadline does not read this store: [`Self::window`]
    /// answers from the profile (rule 71), and a publish does not move it.
    pub fn set_window(&self, connector: ConnectorId, window: Option<std::time::Duration>) {
        let nanos = window.map(|window| u64::try_from(window.as_nanos()).unwrap_or(u64::MAX));
        self.shared().published_windows[connector.index()] = nanos;
    }

    /// `connector`'s retry cutoff now: its dial deadline, the window it
    /// published ([`Self::set_window`]), or `None` while a published window
    /// is unknown.
    #[must_use]
    pub fn window(&self, connector: ConnectorId) -> Option<std::time::Duration> {
        let shared = self.shared();
        dial_profile(connector)
            .retry_cutoff_nanos(shared.published_windows[connector.index()])
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

    /// Whether `connector` can dial now, or the first thing it lacks. The
    /// plan reads this before it draws, and the owner loop parks on it.
    pub fn readiness(&self, connector: ConnectorId) -> Result<(), NotReady> {
        if let Some(missing) = NotReady::from_outbound(self.links.get(connector).outbound) {
            return Err(missing);
        }
        if self.layer.get().is_none() {
            return Err(NotReady::NoLayer);
        }
        Ok(())
    }

    /// The shared state, for the calls that read or write the lists, with
    /// the ban list's queued events applied first, in the order it made
    /// them: a ban bars every seat its entry covers, a lift frees those no
    /// remaining entry covers (Rick, 2026-10-31). Every caller takes the
    /// lists through here, so whatever it reads reflects every ban and
    /// lift posted before it, and the queue is taken under the lock, so
    /// the owner loops apply one order between them.
    pub fn shared(&self) -> MutexGuard<'_, Shared> {
        let mut shared = self.shared.lock().expect("dialer state");
        for event in self.bans.take() {
            match event {
                BanEvent::Banned(entry) => {
                    shared.lists.ban(entry);
                }
                BanEvent::Lifted(entry) => {
                    shared.lists.lift(entry);
                }
            }
        }
        shared
    }

    /// Each connector's link, as the readiness reads it.
    #[must_use]
    pub fn links(&self) -> &Arc<Links> {
        &self.links
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
    /// protocol data (`dial_profile(connector).in_flight_bound`), and no
    /// production crate turns on the feature that compiles this.
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
            self.layer()
                .close(*id, DialEnd::local_close_after_channel());
        }
        ids
    }

    /// This node's own addresses on `connector`: never dial candidates,
    /// and the disclosure population's own member (slice 1 §5a). Logs what
    /// this node now discloses there, or that it is dial-only: the line is
    /// said when the fact is set, so a managed Tor's comes when its onion
    /// is published, not when the connector starts.
    pub fn set_own_addresses(&self, connector: ConnectorId, addresses: Vec<NetworkAddress>) {
        tracing::info!("{}", address::disclosure(connector, &addresses));
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
            if let Err(refusal) = shared.lists.admit_gray(address, Source::Operator, now, rng) {
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
        shared.lists.admit_gray(address, Source::Operator, now, rng)
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
    /// which has no list address. The board is not read: the held count
    /// uses the inbound rows last read by [`Self::note_inbound_tor`], which
    /// the layer's close hook ([`shekyl_p2p_session::PeerOwner::on_closed`])
    /// calls first.
    pub fn session_closed<R: RelayRng + ?Sized>(&self, id: SocketId, end: DialEnd, rng: &mut R) {
        let now = self.now();
        let mut shared = self.shared();
        if let Some(adopting) = shared.adopting.get_mut(&id.get()) {
            *adopting = Some(end);
        } else if let Some(address) = shared.kept.remove(&id.get()) {
            if let Some(connector) = Peerlist::connector_of(&address) {
                if end.cause().kind() == CloseKind::SessionRefused {
                    // A payload refusal is not a dial. The stream was
                    // counted when the session was accepted, so this does
                    // not finish a test and does not fold the tally. It
                    // settles an outstanding draw; the verdict is not read.
                    let outcome = DialOutcome::PayloadRefused(address.clone());
                    shared.lists.apply(&outcome, now, Verdict::Counted, rng);
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
    /// lock across the session-layer calls, so a session it keeps is in the
    /// lists when the file is written and nothing is kept afterwards. The
    /// file is written last. All of this is before the session layer shuts
    /// down and before the managed Tor is torn down
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
        let now = self.now();
        let mut shared = self.shared();
        shared.last_store = Some(now);
        Ok(shared.lists.restore(addresses, rng))
    }

    /// Write the address file now: every list address, by range only,
    /// less those a ban covers. `Ok(false)` when no file was named.
    ///
    /// The clock is read before the store lock. Two stores that overlap may
    /// write in either order: each is a whole file of the lists at its own
    /// moment, and the next store, at most one interval later, replaces it.
    pub fn store_addresses(&self) -> io::Result<bool> {
        let now = self.now();
        let store = self.store.lock().expect("address store");
        let Some(store) = store.as_ref() else {
            return Ok(false);
        };
        let addresses = self.shared().lists.persistable();
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

    /// Record a test's outcome. `opened_ms` is when its final attempt's
    /// stream opened, on the judge's clock, when one did. `ended_ms` is
    /// when that attempt resolved, on the same clock: the failure is judged
    /// then, not when this record runs. The stream is dated at its open,
    /// and never later than `ended_ms`, so it is never after its own failure.
    fn record<R: RelayRng + ?Sized>(
        shared: &mut Shared,
        connector: ConnectorId,
        outcome: &DialOutcome,
        opened_ms: Option<u64>,
        ended_ms: u64,
        now: Tick,
        rng: &mut R,
    ) {
        Self::apply_due_verdicts(shared, now, rng);
        // The attempt frees its slot whatever the verdict: a deferred one
        // holds only the outstanding seat.
        shared.attempts(connector).finish(outcome);
        Self::judge_outcome(shared, connector, outcome, ended_ms, now, rng);
        let opened = opened_ms.map_or(ended_ms, |opened| opened.min(ended_ms));
        Self::note_stream(shared, connector, outcome, opened, now);
        let held = Self::tor_held(shared);
        shared.tor_link.observe(connector, outcome, held, now);
    }

    /// A finished attempt's outcome, or its deferral. A `DialFailed` whose
    /// cause is worth a retry, with attempts left in this test, is not
    /// recorded: the open test waits its [`retry_wait_nanos`] and the
    /// address stays an outstanding draw. The wake at or after the due
    /// tick makes the next attempt. A timeout whose attempt ran `ran_nanos`
    /// (timed inside its task) at or past the connector's window is not
    /// worth one ([`Self::window`]). Anything else, including a test that is
    /// not in flight, is the test's one outcome and is recorded. A
    /// deferred Tor failure still counts in the tally: the stream did not
    /// open. The inbound count is taken under the table lock, across the
    /// dialer's.
    fn settle_or_retry<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        outcome: &DialOutcome,
        ran_nanos: u64,
        opened_ms: Option<u64>,
        ended_ms: u64,
        rng: &mut R,
    ) {
        let now = self.now();
        self.with_inbound(|shared| {
            let address = outcome.address();
            if let DialOutcome::DialFailed(_, failure) = outcome {
                let cutoff = dial_profile(connector)
                    .retry_cutoff_nanos(shared.published_windows[connector.index()]);
                // Retry follows the failure's meaning (§3): a timeout of the
                // dial's own window that ran to the cutoff ends its test.
                let worth = match failure.retry() {
                    Retry::Final => false,
                    Retry::Again => true,
                    Retry::AgainInsideWindow => cutoff.is_none_or(|cutoff| ran_nanos < cutoff),
                };
                if worth {
                    let failure = *failure;
                    let list = if shared.lists.is_white(address) {
                        ListName::White
                    } else {
                        ListName::Gray
                    };
                    let mut wait = 0u64;
                    let next = shared.attempts(connector).defer_retry(
                        address,
                        attempts_per_test(dial_profile(connector).attempts, list),
                        |next| {
                            wait = retry_wait_nanos(&dial_profile(connector).retry_waits, next, rng);
                            Tick::new(now.get().saturating_add(wait))
                        },
                    );
                    if let Some(next) = next {
                        tracing::debug!(
                            "{connector:?} dial {address:?} attempt {} ended {:?} after {} ms; attempt {next} in {} ms",
                            next - 1,
                            failure.evidence(),
                            ran_nanos / 1_000_000,
                            wait / 1_000_000
                        );
                        let opened = opened_ms.map_or(ended_ms, |opened| opened.min(ended_ms));
                        Self::note_stream(shared, connector, outcome, opened, now);
                        let held = Self::tor_held(shared);
                        shared.tor_link.observe(connector, outcome, held, now);
                        return;
                    }
                }
            }
            Self::record(shared, connector, outcome, opened_ms, ended_ms, now, rng);
        });
    }

    /// Record `SessionAccepted` and the kept row in one lock section. The
    /// session layer established the session and told the other owners
    /// before the dial's outcome reached this loop.
    ///
    /// A close that reached the dialer between the channel's open and this
    /// lock section left its cause in the dial's window. The dial is then
    /// `DialFailed` with that cause, no kept row is written, and this
    /// returns `false`: the layer reports a close once, so a kept row
    /// written after it would never leave.
    fn accept_kept<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        address: &NetworkAddress,
        kept: KeptDial,
        opened_ms: Option<u64>,
        ended_ms: u64,
        rng: &mut R,
    ) -> bool {
        let KeptDial { id, mut window } = kept;
        let now = self.now();
        let closed = self.with_inbound(|shared| {
            let closed = window.settle(shared);
            let outcome = match closed {
                Some(end) => DialOutcome::DialFailed(address.clone(), end.failure()),
                None => DialOutcome::SessionAccepted(address.clone()),
            };
            Self::record(shared, connector, &outcome, opened_ms, ended_ms, now, rng);
            if closed.is_none() {
                shared.kept.insert(id.get(), address.clone());
            }
            closed
        });
        if let Some(end) = closed {
            tracing::debug!(
                "{connector:?} dial {address:?} closed before it was kept ({:?})",
                end.cause().kind()
            );
            return false;
        }
        tracing::debug!("{connector:?} dial {address:?} kept as {id:?}");
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
    pub fn run<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        owner: &OwnerHandle<C>,
        rng: &mut R,
    ) {
        let mut parked: Option<NotReady> = None;
        let mut dial_at: Option<Tick> = None;
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
            let wake = *dial_at.get_or_insert_with(|| {
                Tick::new(
                    owner
                        .clock()
                        .now()
                        .get()
                        .saturating_add(next_wake_nanos(dial_profile(connector).wake, rng)),
                )
            });
            // A deferred verdict due first wakes the loop for it alone.
            let deadline = self
                .next_verdict_due(connector)
                .map_or(wake, |due| due.min(wake));
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
            self.apply_verdicts(rng);
            if owner.clock().now() < wake {
                continue;
            }
            dial_at = None;
            if let Err(err) = self.store_if_due(self.now()) {
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
    /// was admitted. The nonce is the session layer's, minted when the dial
    /// opens. Public so a test can read the draw without running the loop.
    pub fn choose<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        rng: &mut R,
    ) -> Option<(NetworkAddress, DialAim)> {
        let now = self.now();
        if let Err(missing) = self.readiness(connector) {
            tracing::debug!("{connector:?} wake: nothing drawn: {}", missing.describe());
            return None;
        }
        let live = live_sessions(&self.board(), connector);
        let mut shared = self.shared();
        let wake = plan_wake(&mut shared, connector, &live, now, rng);
        let (address, aim) = match wake {
            Wake::Recover => {
                // `plan_wake` already reported this wake. A report that
                // closed the episode opens the next one here.
                recovery::re_admit(&mut shared, connector, now, rng);
                return None;
            }
            Wake::Idle => return None,
            Wake::Drawn { address, aim } => (address, aim),
        };
        drop(shared);
        Some((address, aim))
    }
}
