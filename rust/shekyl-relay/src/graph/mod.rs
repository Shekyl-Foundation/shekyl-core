// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One Dandelion++ relay: every established session, and the steps that
//! schedule them.
//!
//! The network is a property of a session's connector, read at hop 0, at the
//! stem embargo, and at cover. It is not a property of this type. The type
//! owns the state §18.5 assigned to Rust: peer fluff queues, the stem map,
//! the epoch role, and whether the zone carries. The carrier's schedule and
//! buffers run in their own task (`crate::carrier`, `CVR-R6`), told the
//! slots and the covered sessions by [`Relay::carrier_view`]. Cover goes only to a
//! session that is encrypted and whose connector declares its timing visible
//! to an observer at this node's end (`CVR-R3`), Tor included.
//! A transaction body is still an opaque blob here. See
//! `DAEMON_RELAY_PRIVACY.md` criterion 4 and `TOR_COVER_POSTURE.md`.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, OnceLock};

use shekyl_draw_rng::RelayRng;
use shekyl_relay_privacy::basis::DerivationMs;
use shekyl_relay_privacy::params::{inherited, DandelionParams};
use shekyl_relay_privacy::schedule::{
    DelayFamily, EmbargoTimer, EpochScheduler, FluffScheduler, Millis, PeerDirection,
};
use shekyl_relay_privacy::stem_map::{ConnectionId, SlotIndex};
pub use shekyl_transport_layer::ConnectorId;
use shekyl_transport_layer::{declaration, Assessment, Declaration, NativeEncryption, YesNo};
use shekyl_types::relay::RelayMethod;

use crate::carrier::CarrierView;
use crate::stem_watch::{StemTally, StemTallySnapshot, StemWatch, TxId};

mod cover;
mod embargo;
mod epoch_map;
mod hidden_slot;
mod origin;

pub use embargo::{
    origin_publication_budget_ms, origin_retry_ms, origin_retry_secs, EmbargoWork,
    OriginPublication, StemWork, NEVER_SENT_RETRY_MS,
};
pub use origin::OriginVerdict;

use epoch_map::EpochMap;

pub use cover::{timing_visible, transit_ms};

/// One opaque transaction blob shared across every peer that accepted a fluff
/// batch.
///
/// Fan-out clones the [`Arc`], not the bytes. The FFI maps each inbound span
/// into one of these once; per-peer queues hold cheap handles. Sorting and
/// de-duplication on flush compare by content (`Arc<[u8]>: Ord`).
pub type TxBlob = Arc<[u8]>;

/// The longest declared connector transit.
///
/// The origin retry does not know which connector carried the stem — the
/// pool does not store one — so it waits this long rather than naming a
/// connector. A connector with no assessed transit is not in the max. A
/// later connector with a longer transit raises the wait without a new call
/// site. *Records-was: `longest_measured_transit`, an `f64`; the values
/// were never measurements (§97).*
#[must_use]
pub fn longest_transit() -> DerivationMs {
    ConnectorId::ALL
        .iter()
        .copied()
        .filter_map(transit_ms)
        .max_by_key(|transit| transit.ms())
        .expect("a connector with an assessed transit")
}

/// One embargo table per assessed transit, for the life of the process.
///
/// The table is a pure function of that cell's milliseconds. Building it
/// walks a geometric mass until the tail cutoff, and the stem path asks
/// the question once per peer per decision. The first ask for a transit
/// builds the table; every later ask clones the [`Arc`].
type EmbargoTables = Mutex<Vec<(u32, Arc<EmbargoTimer>)>>;

fn embargo_tables() -> &'static EmbargoTables {
    static TABLES: OnceLock<EmbargoTables> = OnceLock::new();
    TABLES.get_or_init(|| Mutex::new(Vec::new()))
}

/// The observation window for `declaration`, when its transit cell is assessed.
fn embargo_timer(declaration: &Declaration) -> Option<Arc<EmbargoTimer>> {
    let Assessment::Assessed(transit) = declaration.transit_ms() else {
        return None;
    };
    let tables = embargo_tables();
    let mut guard = tables
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((_, timer)) = guard.iter().find(|(key, _)| *key == transit.ms()) {
        return Some(Arc::clone(timer));
    }
    // The shipped embargo: every stem hop carrier-paced (`CVR-R5`).
    let timer = Arc::new(EmbargoTimer::shipped(
        &shekyl_relay_privacy::params::DandelionParams::adopted_for_transit_ms(transit),
    ));
    guard.push((transit.ms(), Arc::clone(&timer)));
    Some(timer)
}

fn hides_address(declaration: &Declaration) -> bool {
    declaration.address_hidden_from_peer() == Assessment::Assessed(YesNo::Yes)
}

/// This connector's declaration says the peer does not learn this node's address.
///
/// The cell is the connector's description. A connector that has not assessed
/// the cell is not eligible.
#[must_use]
pub fn address_hidden_from_peer(connector: ConnectorId) -> bool {
    hides_address(&declaration(connector.column()))
}

/// True when any configured connector declares that the peer does not learn
/// this node's address. Computed once, at construction.
#[must_use]
pub fn any_hides_address_from_peer(configured: &[ConnectorId]) -> bool {
    configured.iter().copied().any(address_hidden_from_peer)
}

/// This connector's native encryption cell says a network observer cannot
/// read the byte stream.
///
/// [`NativeEncryption::Classical`] is encrypted.
/// [`NativeEncryption::NoneNative`] is not: an added layer is a transport
/// plan, not this cell. [`Assessment::NotAssessed`] is not presumed encrypted.
///
/// Anonymity is [`address_hidden_from_peer`]. The two cells agree on the
/// connectors that exist today, and a later connector may set only one.
///
/// A session can still be encrypted when this is false: the transport adds
/// a layer where the network has none (`AddedLayer::Noise` on clearnet).
/// That is this node's construction, not the column, so [`Relay`] reads it
/// beside this cell when it decides cover.
#[must_use]
pub fn link_encrypted(connector: ConnectorId) -> bool {
    matches!(
        declaration(connector.column()).encryption(),
        Assessment::Assessed(NativeEncryption::Classical)
    )
}

// The seam's byte contract. C++ `static_assert`s the same literals; neither
// compiler sees the other, so both pins are what make a renumbering fail
// on the side that renumbered. `NetZone` pins live with that type.
const _: () = {
    assert!(RelayMethod::None as u8 == 0);
    assert!(RelayMethod::Local as u8 == 1);
    assert!(RelayMethod::Stem as u8 == 2);
    assert!(RelayMethod::Fluff as u8 == 3);
    assert!(RelayMethod::Block as u8 == 4);
};

/// What the zone knows about one connected peer's pending fluff batch.
///
/// The inherited `context_t` carries the same three facts. `queued` holds
/// transaction blobs the zone has accepted but not yet released to transport;
/// they are opaque here by design — this crate schedules, it does not serialize
/// (see the crate docs on why the framing stays C++).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerFluff {
    /// Blobs waiting for this peer's flush deadline.
    ///
    /// Shared handles ([`TxBlob`]) so a fluff to N peers does not make
    /// N full payload copies of every accepted batch. The deadline itself is
    /// **not** here — `FluffScheduler` owns pending deadlines, and a copy in
    /// this struct would be a second owner of the same fact (§18.5).
    pub queued: Vec<TxBlob>,
    /// Who dialed whom — the inherited code gives outbound peers half the
    /// inbound fluff delay, and [`shekyl_relay_privacy::schedule::FluffScheduler`]
    /// keeps that asymmetry.
    pub direction: PeerDirection,
    /// The connector that carried this session. A partition key. Behaviour
    /// reads [`Self::declaration`], not this identity.
    pub connector: ConnectorId,
    /// The declaration copied when the session was admitted.
    declaration: Declaration,
}

impl PeerFluff {
    fn new(direction: PeerDirection, connector: ConnectorId) -> Self {
        Self {
            queued: Vec::new(),
            direction,
            connector,
            declaration: declaration(connector.column()),
        }
    }
}

/// Whether this node has finished synchronizing its chain.
///
/// Origination reads this once, as its own type, so it cannot be transposed
/// with `local_origin`. The FFI boundary is a `bool`; the conversion happens
/// once, there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeSync {
    /// The node may originate. A local transaction enters the stem graph.
    Synchronised,
    /// The node is still synchronizing. A local origin is withheld.
    Unsynchronised,
}

/// What the relay path should do with a batch of transactions.
///
/// The zone decides; the caller performs. Framing and the socket stay C++,
/// so this returns a destination rather than sending to one.
///
/// # Why the non-stem outcomes are distinct
///
/// They differ in what the caller must do next, so collapsing them to one
/// "fluff" answer would lose the distinction the relay path is built on:
///
/// - [`RelayPlan::NoRoute`] is *transient*. The zone would stem, but no slot is
///   currently backed by a live peer — the caller may refresh its connection
///   set and re-plan before accepting the fallback.
/// - [`RelayPlan::FluffEpoch`] is *settled for the epoch*. Refreshing changes
///   nothing, so a retry would be wasted work.
/// - [`RelayPlan::AwaitSync`] is a *hold*. The batch is this node's own and
///   the node has not caught up. Nothing is sent and nothing is recorded, so
///   the pool retries after sync. A refresh cannot make it routable, and
///   falling through to fluff would publish it early.
/// - [`RelayPlan::OwnEdge`] is the first hop of a local origin whose address
///   a peer must not learn: the hidden stem slot's peer, or the live
///   alternate of the origin's pin (§95.3, §98). One ordinary send. A failed
///   write is terminal: no stem-map refresh, no second plan, no fluff.
///   Success records `relay_method::local`.
/// - [`RelayPlan::NoOwnEdge`] is that plan with no address-hiding session
///   slotted, or with the origin's pin exhausted for the epoch. Send nothing
///   and record nothing. Refreshing the stem map cannot manufacture a
///   session that hides this node's address.
///
/// The daemon also reports the routable outcomes differently: the inherited
/// `dandelionpp_notify` emits `relay_method::stem` on *entering* the
/// stem-eligible branch, before any routing is attempted, and
/// `relay_method::fluff` only on falling through. A caller holding one bool
/// cannot reconstruct which event to emit, and would have to re-evaluate
/// `!fluffing || local_origin` itself — a second copy of the RD-4 predicate
/// this type exists to keep single-owned. `AwaitSync` emits nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayPlan {
    /// Forward to this stem successor.
    Stem(ConnectionId),
    /// Stem-eligible, but no stem slot is routable right now. Refresh the
    /// connection set and re-plan, then fluff if it is still unroutable.
    NoRoute,
    /// This zone is fluffing this epoch and the transaction is not locally
    /// originated. Fluff: batch to every peer but the source.
    FluffEpoch,
    /// Locally originated while this node is unsynchronised. Send nothing
    /// and record nothing.
    ///
    /// The plan is the refusal. [`Relay::carrier_for`] still names an ordinary
    /// carrier so the match stays total, and the caller must not read it:
    /// there is no send.
    AwaitSync,
    /// First hop of a local origin whose address a peer must not learn.
    ///
    /// Not a stem-map slot. The caller sends once, on the ordinary
    /// connection, and records `relay_method::local`. A failed write returns
    /// without a refresh and without a fluff.
    OwnEdge(ConnectionId),
    /// No address-hiding session is slotted, or the origin's pin is
    /// exhausted for the epoch.
    ///
    /// Send nothing and record nothing. Not a stem-map refresh, and not a
    /// fluff: either would publish the origin on a link whose peer learns
    /// this node's address. [`OriginVerdict::Absent`] is the empty class.
    /// [`OriginVerdict::Connected`] is the exhausted pin. The dispatch
    /// warning names which one it read.
    NoOwnEdge,
}

/// Why [`Relay::new`] refused a configuration.
///
/// Each refusal is its own variant — collapsing them to `None` would be the
/// same axis-merge this type exists to prevent. The FFI maps every variant
/// to a null handle; a future in-process caller matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayNewError {
    /// `stems` doubles as the channel count. Noise is
    /// [`inherited::NOISE_CHANNELS`] wide; a mismatch sizes the schedule
    /// against a width the rest of the stack does not share.
    NoiseChannelCount {
        /// The stem/channel count that was requested.
        got: usize,
    },
    /// A configured connector hides this node's address and `stems < 2`.
    /// Slot 0 is reserved for the sessions that hide it (§95.3), so the
    /// origin's pin needs one alternate and relayed traffic needs a slot of
    /// its own; a narrower map has neither.
    HiddenSlotWidth {
        /// The stem count that was requested.
        got: usize,
    },
}

impl fmt::Display for RelayNewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoiseChannelCount { got } => write!(
                f,
                "noise channel count must equal inherited::NOISE_CHANNELS (got {got})"
            ),
            Self::HiddenSlotWidth { got } => write!(
                f,
                "a connector that hides this node's address reserves stem slot 0 and \
                 needs a stem width of at least 2 (got {got})"
            ),
        }
    }
}

/// One relay zone's owned state.
///
/// Single-owner by construction: every field is private and reachable only
/// through `&mut self`, which is the whole of §18.5's cost bound on the second
/// reactor. There is no interior mutability and no `Sync` shared state here —
/// the boundary publishes what C++ needs to read rather than sharing it.
#[derive(Debug)]
pub struct Relay {
    /// Per-peer pending fluff batches, keyed by connection.
    contexts: BTreeMap<ConnectionId, PeerFluff>,
    /// Stem routing for this epoch. Already Rust-backed since RP-2a; RP-3a
    /// takes ownership of it rather than reaching it through a C++ wrapper.
    /// The variant is whether slot 0 is reserved.
    map: EpochMap,
    /// Per-peer fluff batching deadlines.
    ///
    /// **The corrected draw (F-4/F-5).** Constructed `memoryless()`, never
    /// `inherited()` — the latter is `DelayFamily::Poisson`, which *is* the F-4
    /// defect, at identical means. The difference is one identifier and no
    /// routing test can see it, so `fluff_draws_are_memoryless_not_the_inherited_poisson`
    /// witnesses it rather than trusting this line (§18.4 item 3).
    fluff: FluffScheduler,
    /// True when this zone spends the epoch fluffing everything it receives.
    fluffing: bool,
    /// When the current epoch ends and roles are re-drawn.
    epoch_ends_at: Millis,
    /// Frozen relay parameters (`q`, epoch length, jitter).
    params: DandelionParams,
    /// Configured stem width — how many slots the map keeps.
    ///
    /// When noise is enabled this is also the noise channel count (channel
    /// `i` ↔ slot `i`). Production pins it to [`inherited::NOISE_CHANNELS`].
    stems: usize,
    /// Whether this zone runs the cover carrier.
    ///
    /// **Single owner of the enable fact** (§20.4). The carrier's schedule,
    /// bindings and queue run in their own task (`crate::carrier`,
    /// `owner::carrier`), so a busy zone delays what it hands the carrier,
    /// never a window (`CVR-R6`); this zone decides whether there is a
    /// carrier, and tells it the slots and the covered sessions
    /// ([`Self::carrier_view`]).
    noise: bool,
    /// Epochs begun since construction. The carrier starts its tails when
    /// this moves ([`Self::epochs_started`]).
    epochs: u64,
    /// Per-successor stem outcomes — §12.11's signal, **derived here rather
    /// than imported from `tx_pool`** (§38.1). Records; never judges.
    stem_watch: StemWatch,
    /// The address-hiding class's report (`hidden_slot`). Unarmed until the
    /// first epoch rebuild. Only a reserved map arms one.
    hidden_class_watch: hidden_slot::HiddenClassWatch,
    /// Every stem's embargo state and every held origin (`embargo`).
    embargoes: embargo::Embargoes,
    /// The node's sync state, as last reported. Unsynchronised until the
    /// first report, so an origin held before it waits.
    node_sync: NodeSync,
    /// Connectors whose sessions this node wraps in a layer the transport
    /// adds for encryption (`AddedLayer::Noise` on clearnet when this node
    /// chose it). With [`link_encrypted`], the connector's native cell, it
    /// is whether a session is encrypted ([`Self::session_encrypted`]).
    added_encryption: Vec<ConnectorId>,
}

impl Relay {
    /// Open a relay at `now` with no sessions yet, or [`Err`] when the
    /// requested configuration is one the design forbids.
    ///
    /// The first epoch is drawn immediately, matching the inherited
    /// `start_epoch` running once at construction.
    ///
    /// # Refusals
    ///
    /// `added_encryption` names the connectors whose sessions this node
    /// wraps in an encryption layer the transport adds. Cover runs per
    /// channel, on a session that is encrypted and whose connector declares
    /// its timing visible (`noise_destination`); a configuration
    /// with no such connector is not refused, its channels simply carry
    /// nothing until a covered session holds their slot.
    ///
    /// **A noise carrier's channel count must equal
    /// [`inherited::NOISE_CHANNELS`].** `stems` is that width. This was a
    /// `debug_assert!`, which compiles out in release.
    ///
    /// **A hidden connector needs a stem width of at least two.** Slot 0 is
    /// then reserved for the sessions that hide this node's address, and the
    /// origin's pin needs `stems − 1 ≥ 1` alternates; at width one relayed
    /// traffic would have no slot of its own. Production width is
    /// [`inherited::NOISE_CHANNELS`]; width one is reachable only from tests.
    ///
    /// The refusals are distinct [`RelayNewError`] variants. The FFI
    /// maps every one to null. C++ passes the noise flag only behind the
    /// development opt-in and does not pre-decide which connector can carry
    /// it. The flag defaults off, so a shipped construction does not hit
    /// the noise refusals.
    pub fn new<R: RelayRng + ?Sized>(
        params: DandelionParams,
        stems: usize,
        noise_requested: bool,
        configured: &[ConnectorId],
        added_encryption: &[ConnectorId],
        now: Millis,
        rng: &mut R,
    ) -> Result<Self, RelayNewError> {
        if noise_requested && stems != inherited::NOISE_CHANNELS {
            return Err(RelayNewError::NoiseChannelCount { got: stems });
        }
        let reserves_slot = any_hides_address_from_peer(configured);
        if reserves_slot && stems < 2 {
            return Err(RelayNewError::HiddenSlotWidth { got: stems });
        }
        let epoch = EpochScheduler::new(params).start(now, rng);
        // Built at full width with no peers rather than an empty map, so
        // `update_stems` can grow into it. An empty map has no slots to
        // fill, which is what forced the first-population special case that
        // then swallowed the epoch rebuild. Under a hidden connector slot 0
        // is reserved from the start; neither constructor draws on no peers.
        let map = if reserves_slot {
            EpochMap::reserved(Vec::new(), Vec::new(), stems, rng)
        } else {
            EpochMap::uniform(Vec::new(), stems, rng)
        };
        Ok(Self {
            stem_watch: StemWatch::default(),
            contexts: BTreeMap::new(),
            map,
            fluff: FluffScheduler::memoryless(),
            fluffing: epoch.fluffing,
            epoch_ends_at: epoch.ends_at,
            params,
            stems,
            noise: noise_requested,
            epochs: 0,
            hidden_class_watch: hidden_slot::HiddenClassWatch::BeforeRebuild,
            embargoes: embargo::Embargoes::default(),
            node_sync: NodeSync::Unsynchronised,
            added_encryption: added_encryption.to_vec(),
        })
    }

    /// What the carrier needs to know from this zone: the session in each
    /// stem slot, and which sessions carry cover (`noise_destination`).
    /// The relay owner hands it over whenever it changes.
    #[must_use]
    pub fn carrier_view(&self) -> CarrierView {
        CarrierView {
            slots: self.map.slots().to_vec(),
            covered: self
                .contexts
                .keys()
                .copied()
                .filter(|peer| self.noise_destination(*peer))
                .collect(),
        }
    }

    /// Epochs begun since construction: the carrier begins its tails each
    /// time this moves.
    #[must_use]
    pub fn epochs_started(&self) -> u64 {
        self.epochs
    }

    /// Whether `peer`'s session carries cover (`CVR-R3`; Rick,
    /// 2026-11-15): the session is encrypted ([`Self::session_encrypted`])
    /// and its connector declares that an observer at this node's end sees
    /// its timing ([`timing_visible`]). No other condition: a Tor session
    /// carries cover, the own-origin slot 0 included, and a plaintext
    /// clearnet session does not. Encryption hides what a send says; cover
    /// hides when one happens and how big it is, which is all such an
    /// observer has left. A session that is gone is not a destination.
    pub(crate) fn noise_destination(&self, peer: ConnectionId) -> bool {
        self.contexts.get(&peer).is_some_and(|session| {
            self.session_encrypted(session.connector) && timing_visible(&session.declaration)
        })
    }

    /// Whether this node's sessions on `connector` are encrypted: the
    /// connector's native cell ([`link_encrypted`]) or a layer this node
    /// adds to it (`added_encryption` at [`Self::new`]).
    #[must_use]
    pub fn session_encrypted(&self, connector: ConnectorId) -> bool {
        link_encrypted(connector) || self.added_encryption.contains(&connector)
    }

    /// Whether this zone runs noise channels.
    ///
    /// The single owner of the fact (§20.4). C++ reads it back through
    /// `shekyl_relay_zone_noise_enabled` rather than re-deriving it from the
    /// payload it happens to hold, so there is exactly one place the answer
    /// comes from.
    #[must_use]
    pub fn noise_enabled(&self) -> bool {
        self.noise
    }

    /// Configured stem width (slot count). When noise is on, also the channel
    /// count — channel `i` follows slot `i`.
    #[must_use]
    pub fn stem_width(&self) -> usize {
        self.stems
    }

    /// A peer's Levin handshake finished (session established) and it may
    /// now carry relay traffic.
    ///
    /// Idempotent on the context: [`BTreeMap::entry`] keeps the first
    /// direction and any queued batch. An **outbound** handshake also merges
    /// the stem map, including a repeat: re-offering the survivor after a
    /// close fills a hole, and a map that is already full returns unchanged
    /// and draws nothing. An inbound handshake does not merge. Inbound peers
    /// are not stem candidates, and a repeat of an outbound peer that arrives
    /// as inbound must not consume `rng`.
    ///
    /// A close does not merge. A dead slot stays until the next outbound
    /// handshake or an explicit [`Relay::update_stems`].
    pub fn on_session_established<R: RelayRng + ?Sized>(
        &mut self,
        id: ConnectionId,
        direction: PeerDirection,
        connector: ConnectorId,
        rng: &mut R,
    ) {
        self.contexts
            .entry(id)
            .or_insert_with(|| PeerFluff::new(direction, connector));
        if direction == PeerDirection::Outbound {
            self.update_stems(rng);
            // A new outbound session may be the own edge a held origin waits
            // for (RX-2): plan it on the next poll rather than the grid.
            self.unsent_due_now(0);
        }
        // The class is the registry, not the stem merge. An inbound session
        // is not a stem candidate; noting it changes nothing once the count
        // is taken.
        self.note_hidden_class();
    }

    /// Mean of the embargo drawn for `connector`, when that connector has an
    /// assessed transit.
    #[cfg(test)]
    pub fn embargo_mean_secs(&self, connector: ConnectorId) -> Option<u32> {
        let _ = self;
        embargo_timer(&declaration(connector.column())).map(|timer| timer.mean_secs())
    }

    /// The connector recorded for a still-pending stem.
    #[cfg(test)]
    pub fn stem_connector(&self, tx: TxId) -> Option<ConnectorId> {
        self.stem_watch.pending_connector(tx)
    }

    /// Record stems with an explicit observation deadline.
    ///
    /// **Test / deterministic-drive only.** Production always goes through
    /// [`Relay::record_stem`], which draws from the cached embargo timer. Fixed
    /// deadlines let the poll-clock and next-wake witnesses assert without
    /// sampling the geometric table.
    #[cfg(test)]
    pub fn record_stem_at(
        &mut self,
        txs: &[TxId],
        successor: ConnectionId,
        source: Option<ConnectionId>,
        deadline: Millis,
    ) {
        let Some(connector) = self.contexts.get(&successor).map(|peer| peer.connector) else {
            return;
        };
        for tx in txs {
            self.stem_watch
                .stemmed(*tx, successor, source, connector, deadline);
        }
    }

    /// Earliest in-flight stem-observation deadline, if any.
    #[must_use]
    pub fn stem_observation_deadline(&self) -> Option<Millis> {
        self.stem_watch.next_deadline()
    }

    /// Record that `txs` arrived `from` a peer (`None` when the arrival has
    /// no peer). Any zone, any path — but **not** any peer: an arrival from
    /// the successor an observation is charged to resolves nothing (F-10,
    /// §49).
    ///
    /// This is the *only* input the outcome needs from outside, and it is
    /// **data, not a decision** (§38.1).
    /// Returns the subset of `txs` whose observation this arrival RESOLVED as
    /// propagated — the transactions for which *"it came back from somewhere
    /// other than where I sent it"* just became true — and, from a peer, any
    /// of `txs` this node held unsent: each now circulates, its embargo is
    /// disarmed, and the FFI marks it shown.
    ///
    /// **A decision leaving, not an input crossing.** The caller does not get
    /// the watch, the pending map, or a query surface over them; it gets the
    /// verdicts that fired on this call and nothing else. The alternative —
    /// retaining a per-transaction outcome for a consumer to poll — would put
    /// a second copy of a fact the txpool already owns beside the txpool, with
    /// no invalidation tied to the pool entry's own lifetime. That is the
    /// shape that produced the `transit_for` literal and the `DEGRADED_FLOOR`
    /// pin: a duplicate nothing forces to agree, going stale in silence.
    ///
    /// Usually empty, and allocating only when it is not: an arrival that
    /// resolves nothing is the common case.
    pub fn record_arrival(&mut self, txs: &[TxId], from: Option<ConnectionId>) -> Vec<TxId> {
        let mut propagated = Vec::new();
        for tx in txs {
            if self.stem_watch.seen(tx, from) {
                propagated.push(*tx);
            }
        }
        // The verdict disarms the embargo the stem armed (§92.5c item 1): no
        // fire follows, and the state goes.
        self.disarm(propagated, txs, from)
    }

    /// Every successor with resolved observations — the §55 telemetry
    /// readout. See [`StemWatch::snapshot`] for why the counts stay raw.
    #[must_use]
    pub fn stem_snapshot(&self) -> Vec<(ConnectionId, StemTallySnapshot)> {
        self.stem_watch.snapshot()
    }

    /// Per-successor stem outcomes, for a future selection consumer.
    #[must_use]
    pub fn stem_tally(&self, successor: &ConnectionId) -> Option<&StemTally> {
        self.stem_watch.tally(successor)
    }

    /// Observations still in flight — liveness witness for the drive.
    #[must_use]
    pub fn stem_observations_in_flight(&self) -> usize {
        self.stem_watch.in_flight()
    }

    /// A peer disconnected.
    ///
    /// Mirrors `notify::on_connection_close`. Anything still queued for that
    /// peer goes with it — the inherited code drops the context wholesale, and
    /// re-routing a batch to a different peer would be a routing decision this
    /// step is not entitled to make.
    pub fn on_connection_close(&mut self, id: &ConnectionId) {
        self.contexts.remove(id);
        self.note_hidden_class();
        // F-8 (§39): dropping the tally is the intentional answer to §33.6's
        // persistence question under a per-connection key — "no". In-flight
        // observations go too (a disconnected peer was not given its deadline).
        // Retention across reconnect needs a durable peer key from p2p, not a
        // quiet keep of connection-scoped state here.
        self.stem_watch.forget(id);
        // The scheduler holds its own pending-deadline map; leaving the peer
        // there would keep waking the driver for a connection that is gone.
        self.fluff.forget(*id);
    }

    /// Outbound, and the connector has an assessed transit. A connector
    /// without one is not a stem candidate. The cell is the question; the
    /// embargo table is built when a stem is recorded, not while listing.
    fn stem_candidate(peer: &PeerFluff) -> bool {
        peer.direction == PeerDirection::Outbound
            && matches!(peer.declaration.transit_ms(), Assessment::Assessed(_))
    }

    /// Established outbound sessions. Inbound peers are not stem candidates.
    ///
    /// The set is this zone's session registry. A handshake-complete peer
    /// that is still synchronizing is included: recorded height is not a
    /// filter, and neither is `state_normal`. A connector with no assessed
    /// transit is not included.
    fn outbound_ids(&self) -> Vec<ConnectionId> {
        self.contexts
            .iter()
            .filter(|(_, peer)| Self::stem_candidate(peer))
            .map(|(id, _)| *id)
            .collect()
    }

    /// Drop every outbound session. Tests use this where a stem refresh
    /// used to be handed an empty candidate list.
    #[cfg(test)]
    pub fn drop_outbound_for_test(&mut self) {
        let ids = self.outbound_ids();
        for id in ids {
            self.on_connection_close(&id);
        }
    }

    /// Merge the currently live outbound connections into the stem map,
    /// **keeping** slots whose peer is still connected.
    ///
    /// The mid-epoch refresh: the inherited `connection_map::update`. An
    /// outbound handshake calls it. So does a stem-send failure. When every
    /// slot is live and the map is at full width, the merge returns unchanged
    /// and draws nothing: a bound slot is taken out of the candidate pool
    /// rather than re-drawn, so the call cannot re-point an existing stem.
    /// Post-inversion (§20.3) nothing else re-points either: a rebound channel
    /// picks up its new peer at the next send, and a channel the merge leaves
    /// unbound clears at its next due tick — both read from the map itself
    /// via [`Driver::poll`].
    ///
    /// **Not what an epoch boundary does.** See [`Relay::rebuild_stems`]; the two
    /// are separate methods because collapsing them freezes the stem graph, and
    /// nothing about the merged result looks wrong when it happens. A close
    /// does not call this. The dead slot stays until the next merge.
    pub fn update_stems<R: RelayRng + ?Sized>(&mut self, rng: &mut R) {
        let (class, rest) = self.partitioned_outbound_ids();
        self.map.merge_outbound(class, rest, rng);
    }

    /// Draw a wholly new stem set over `outbound` — what an epoch rollover does.
    ///
    /// The inherited `start_epoch` constructed a fresh
    /// `connection_map{connections, count}` and `change_channels` assigned it
    /// over the old one, so **both** the successors and every source's pinning
    /// were re-drawn. That rotation is the reason epochs exist: it is what stops
    /// a long-lived observer from correlating on a stable source -> successor
    /// mapping, and the embargo derivation assumes it happens.
    ///
    /// Post-inversion (§20.3) nothing re-points on this signal — a rebound
    /// channel picks up its new peer at the next send, and a channel the redraw
    /// leaves unbound clears at its next due tick, both read from the map itself.
    pub fn rebuild_stems<R: RelayRng + ?Sized>(&mut self, rng: &mut R) {
        // Every pin goes with the map, the local origin's included: the next
        // origination pins afresh (§98.3). A reserved epoch keeps slot 0 for
        // the address-hiding sessions; a uniform epoch is the paper's draw.
        if self.map.reserves_slot() {
            // Arm from the registry, then draw. The map constructor does not
            // report: a rebuild is the only arm, and the constructor stays
            // a pure function of the census.
            self.arm_hidden_class();
            self.map = self.reserved_stem_map(rng);
        } else {
            let outbound = self.outbound_ids();
            self.map = EpochMap::uniform(outbound, self.stems, rng);
        }
    }

    /// Begin a new epoch at `now`: re-draw the fluff/stem role and the end time.
    ///
    /// This is what `notify::run_epoch()` forces in tests and what the driver
    /// calls when [`Relay::epoch_deadline`] elapses. Both paths run the same
    /// code, which is why forcing it in a test is not a special case.
    ///
    /// The carrier starts its epoch tails when it sees the count move
    /// ([`Self::epochs_started`]): each channel keeps sending to its peer for
    /// `EPOCH_TAIL_WINDOWS` windows, starting no message, before it takes its
    /// slot's new peer (`crate::carrier`).
    pub fn start_epoch<R: RelayRng + ?Sized>(&mut self, now: Millis, rng: &mut R) {
        let epoch = EpochScheduler::new(self.params).start(now, rng);
        self.fluffing = epoch.fluffing;
        self.epoch_ends_at = epoch.ends_at;
        self.epochs = self.epochs.wrapping_add(1);
    }

    /// When the current epoch ends.
    pub fn epoch_deadline(&self) -> Millis {
        self.epoch_ends_at
    }

    /// True when this zone is fluffing rather than stemming this epoch.
    pub fn is_fluffing(&self) -> bool {
        self.fluffing
    }

    /// The raw stem decision for `source`, bypassing the epoch role — a
    /// **test-only** window on the pinning mechanics that [`Relay::plan_relay`]
    /// wraps.
    ///
    /// Production never calls this: it routes through `plan_relay`, which applies
    /// the RD-4 predicate (`!fluffing || local_origin`) before consulting the
    /// map. This forwarder lets the pinning tests drive `stem_map::stem_for`
    /// directly, without a redraw loop to force a stem epoch. It is `#[cfg(test)]`
    /// — compiled out of production — so a maintainer reading the type cannot
    /// mistake it for a second live routing entry point (unlike the deliberately
    /// `pub` observation witnesses such as [`Relay::pinned_sources`], which only
    /// read state and never decide a route).
    #[cfg(test)]
    fn stem_for<R: RelayRng + ?Sized>(
        &mut self,
        source: Option<ConnectionId>,
        rng: &mut R,
    ) -> Option<ConnectionId> {
        self.map.stem_for(source, rng)
    }

    /// Decide whether a batch stems or fluffs, and to whom.
    ///
    /// Ports `dandelionpp_notify`. Two properties the inherited condition
    /// `if (!zone_->fluffing || tx_relay == relay_method::local)` encodes, both
    /// preserved deliberately:
    ///
    /// 1. During a **stem epoch** everything stems (subject to a routable slot).
    /// 2. **The origin always stems** — a locally originated transaction stems
    ///    *even during a fluff epoch*. This is RD-4, and it is the reason the
    ///    adopted embargo is 144 s rather than the 31 s an origin-may-fluff
    ///    model gives (§10.5). Reading `|| local` cold, it looks like a
    ///    redundant clause on a fluff check; deleting it silently reverts a
    ///    correction four rounds old, so
    ///    `a_local_tx_stems_during_a_fluff_epoch_rd4` asserts the stem-vs-fluff
    ///    axis the reversion would show on — not merely that the batch went
    ///    somewhere.
    ///
    /// Reporting [`RelayPlan::NoRoute`] rather than a bare fluff when no slot is
    /// routable is what lets the caller mirror the inherited retry-then-fluff:
    /// re-offer connections, ask again, and only then accept the fallback.
    ///
    /// [`NodeSync::Unsynchronised`] combined with `local_origin` is checked
    /// *before* that predicate. The hold must not draw a stem, pin a source,
    /// or consume `rng`. A fluff epoch does not override it: publishing now
    /// is the outcome the hold exists to prevent.
    pub fn plan_relay<R: RelayRng + ?Sized>(
        &mut self,
        source: Option<ConnectionId>,
        local_origin: bool,
        node_sync: NodeSync,
        rng: &mut R,
    ) -> RelayPlan {
        if local_origin && node_sync == NodeSync::Unsynchronised {
            return RelayPlan::AwaitSync;
        }
        if local_origin && self.map.reserves_slot() {
            return self.hidden_slot_plan(rng);
        }
        // No hidden-address connector: the origin's first hop is an
        // ordinary stem slot. On a cover-bearing link that is the channel's
        // cadence. A node with a hidden connector does not take this path.
        // The inherited predicate, transcribed rather than restated:
        // `if (!zone_->fluffing || tx_relay == relay_method::local)`.
        if !self.fluffing || local_origin {
            return match self.map.stem_for(source, rng) {
                Some(destination) => RelayPlan::Stem(destination),
                None => RelayPlan::NoRoute,
            };
        }
        RelayPlan::FluffEpoch
    }

    /// Plan a relay; on a transient [`RelayPlan::NoRoute`], merge this zone's
    /// established outbound sessions into the stem map once and re-plan.
    ///
    /// The candidates are the session registry, not a snapshot the shim
    /// passes in. Keeping the refresh here means the shim performs transport
    /// and does not own "empty map ⇒ refresh", which is zone logic the
    /// gtest oracle cannot see through the FFI (§18.4a).
    ///
    /// A settled [`RelayPlan::FluffEpoch`] does not refresh: retrying cannot
    /// change an epoch decision. [`RelayPlan::AwaitSync`] does not either.
    /// [`RelayPlan::OwnEdge`] does not: the hidden-origin arm has already
    /// merged when its slot was dead. [`RelayPlan::NoOwnEdge`] does not: a
    /// refresh cannot manufacture a session that hides this node's address,
    /// and a second plan would let it fall through to fluff on a clear link.
    pub fn plan_relay_with_refresh<R: RelayRng + ?Sized>(
        &mut self,
        source: Option<ConnectionId>,
        local_origin: bool,
        node_sync: NodeSync,
        rng: &mut R,
    ) -> RelayPlan {
        match self.plan_relay(source, local_origin, node_sync, rng) {
            RelayPlan::NoRoute => {
                self.update_stems(rng);
                self.plan_relay(source, local_origin, node_sync, rng)
            }
            plan => plan,
        }
    }

    /// Accept transaction blobs for fluffing to every peer except `source`.
    ///
    /// Mirrors `fluff_notify`: each peer that has no batch in flight draws a
    /// fresh flush deadline; peers already batching keep theirs, so a burst
    /// does not repeatedly push a peer's flush into the future.
    ///
    /// Returns **how many peers accepted the batch**, so a caller can report
    /// the inherited "no available connections" warning. Deliberately not the
    /// resulting deadline: the scheduler owns that, and returning it invites a
    /// caller to store what it should be asking [`Relay::fluff_deadline`] for —
    /// the mistake `PeerFluff::flush_at` already made once.
    ///
    /// Each blob is mapped to a shared [`TxBlob`] once; peer queues clone the
    /// handle. Blobs are opaque — this crate schedules, transport frames.
    pub fn queue_fluff<T, R>(
        &mut self,
        txs: &[T],
        source: Option<ConnectionId>,
        now: Millis,
        rng: &mut R,
    ) -> usize
    where
        T: AsRef<[u8]>,
        R: RelayRng + ?Sized,
    {
        // Share each payload once across the fan-out. Cloning `Arc` per peer is
        // O(1); cloning `Vec<u8>` was O(payload × peers).
        let shared: Vec<TxBlob> = txs.iter().map(|t| TxBlob::from(t.as_ref())).collect();
        let mut accepted = 0;
        for (id, peer) in &mut self.contexts {
            if Some(*id) == source {
                continue;
            }
            // `queue` draws only when the peer has no pending deadline, so a
            // burst cannot re-draw and defer an open batch. That idempotence
            // lives in the scheduler; the zone does not second-guess it with a
            // duplicate flag. Note the return is the scheduler's *earliest*
            // deadline, not this peer's — storing it per peer would be wrong.
            let _ = self.fluff.queue(now, *id, peer.direction, rng);
            peer.queued.extend(shared.iter().cloned());
            accepted += 1;
        }
        accepted
    }

    /// Release every batch whose deadline has passed, and any batch at all when
    /// `force` is set.
    ///
    /// `force` is what the daemon's `run_fluff()` test hook drives. It runs the
    /// same release path as the deadline, which is why forcing a flush in a
    /// test is not a special case — the only difference is which batches are
    /// considered due.
    pub fn flush_fluff(&mut self, now: Millis, force: bool) -> Vec<(ConnectionId, Vec<TxBlob>)> {
        let due = if force {
            self.fluff.drain()
        } else {
            self.fluff.due(now)
        };
        let mut released = Vec::with_capacity(due.len());
        for id in due {
            if let Some(peer) = self.contexts.get_mut(&id) {
                let mut batch = std::mem::take(&mut peer.queued);
                if !batch.is_empty() {
                    // Sort and de-duplicate before release. The inherited code
                    // does this at the send site with the comment "don't leak
                    // receive order" — which makes it a privacy property of the
                    // batch, not a transport detail, so it belongs on this side
                    // of the boundary with the rest of the relay's observables.
                    // Byte-lexicographic here and in `std::sort` over
                    // `blobdata`, so the emitted order is unchanged.
                    batch.sort_unstable();
                    batch.dedup();
                    released.push((id, batch));
                }
            }
        }
        released
    }

    /// The earliest pending fluff deadline, if any batch is in flight.
    pub fn fluff_deadline(&self) -> Option<Millis> {
        self.fluff.next_deadline()
    }

    /// The distribution family the fluff delay is drawn from.
    ///
    /// Exposed so the correction can be *witnessed* rather than assumed — see
    /// the acceptance note on [`Relay::fluff`].
    pub fn fluff_family(&self) -> DelayFamily {
        self.fluff.family()
    }

    /// Number of stem slots backed by a live peer.
    ///
    /// This is the value the inherited code cached in `connection_count`, the
    /// one piece of state that straddled the strand boundary (*"only update in
    /// strand, can be read at any time"*). Here it stays **derived** — there is
    /// no second copy to fall out of step. The boundary publishes it as a
    /// single-writer atomic for off-task readers (§18.5, finding 1).
    pub fn live_stems(&self) -> usize {
        self.map.live_stems()
    }

    /// The stem slots in index order, `None` for an emptied slot.
    ///
    /// Owned here. The carrier task is handed a copy when the slots change
    /// ([`Self::carrier_view`]), never a reference: a caller-initiated read
    /// would race this zone's mutations — §18.5 finding 3.
    pub fn stem_slots(&self) -> &[Option<ConnectionId>] {
        self.map.slots()
    }

    /// How many sources are currently pinned to a stem slot.
    ///
    /// Derived from the map's per-slot usage counts, so it is a read rather than
    /// a second copy. Exists to witness that an epoch rollover *resets* pinning:
    /// nothing else distinguishes a rebuilt map from a merged one when the peer
    /// set has not changed, and that difference is the whole point of an epoch.
    pub fn pinned_sources(&self) -> usize {
        self.map.usage().iter().sum()
    }

    /// Peers currently known to the zone.
    pub fn peer_count(&self) -> usize {
        self.contexts.len()
    }

    /// A peer's pending batch, if the zone knows the peer.
    pub fn peer(&self, id: &ConnectionId) -> Option<&PeerFluff> {
        self.contexts.get(id)
    }
}

/// Which wire carries a planned batch.
///
/// **§42.3's split, as a type.** Noise channels carry the **stem phase**;
/// fluff takes the zone's ordinary connection. The inherited C++ chose a
/// carrier *instead of* a phase — the covert branch sat above the phase switch
/// and downgraded a stem to `local` (§42.5a) — so carrier and phase were
/// mutually exclusive answers to the same question. Here the carrier is a
/// **function of** the phase, which is what makes the two composable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayCarrier {
    /// The zone's ordinary connection.
    Ordinary,
    /// A noise channel, bound to the stem slot the plan chose.
    ///
    /// `channel` **is** the slot index: the carrier binds channel `i` to
    /// stem slot `i` (§20.3). Carried as [`SlotIndex`] so a crate-boundary
    /// caller cannot swap it with a walk cursor — the property the newtype
    /// exists for. The send loop must respect that binding rather than
    /// broadcasting to every channel (§42.5a).
    Noise { channel: SlotIndex },
    /// The destination's session carries cover but holds no stem slot, so
    /// no window can carry the stem (`CVR-R6`). A relayed stem ends its stem
    /// phase; this node's own transaction waits. Never a bare send: on a
    /// covered session a stem leaves only inside a window.
    NoWindow,
}

/// A plan together with the wire that carries it — the whole answer in one
/// value.
///
/// Returned as a unit so a caller cannot obtain a phase and then choose a
/// carrier for it independently, which is the shape that let the covert branch
/// substitute one for the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayDispatch {
    /// Stem (with destination), no-route, or fluff epoch.
    pub plan: RelayPlan,
    /// The wire.
    pub carrier: RelayCarrier,
}

impl Relay {
    /// Attach a carrier to a plan, per §42.3.
    ///
    /// A stem and an own edge take [`Self::carrier_to`] their destination.
    /// A fluff epoch, a no-route, and the refusals take
    /// [`RelayCarrier::Ordinary`] so the match is total: a fluff epoch ends
    /// the stem phase, a no-route has nothing to carry, and on a refusal the
    /// caller returns before any send.
    fn carrier_for(&self, plan: RelayPlan) -> RelayCarrier {
        match plan {
            RelayPlan::Stem(destination) | RelayPlan::OwnEdge(destination) => {
                self.carrier_to(destination)
            }
            RelayPlan::NoOwnEdge
            | RelayPlan::AwaitSync
            | RelayPlan::NoRoute
            | RelayPlan::FluffEpoch => RelayCarrier::Ordinary,
        }
    }

    /// How a stem to `destination` leaves this node (`CVR-R6`; Rick,
    /// 2026-11-15, restated 2026-11-18).
    ///
    /// On a session that carries cover (`noise_destination`, with
    /// the carrier on), the stem leaves only inside a window: its slot's
    /// channel, or [`RelayCarrier::NoWindow`] when the session holds no
    /// slot. On a session that carries none — a plaintext link, or a node
    /// with the carrier off — there is no window to wait for and the stem
    /// takes the ordinary connection.
    #[must_use]
    pub fn carrier_to(&self, destination: ConnectionId) -> RelayCarrier {
        if !(self.noise && self.noise_destination(destination)) {
            return RelayCarrier::Ordinary;
        }
        match self.map.slot_of(destination) {
            Some(channel) => RelayCarrier::Noise { channel },
            None => RelayCarrier::NoWindow,
        }
    }

    /// [`Self::plan_relay`] plus the carrier that serves it (§42.3).
    pub fn plan_dispatch<R: RelayRng + ?Sized>(
        &mut self,
        source: Option<ConnectionId>,
        local_origin: bool,
        node_sync: NodeSync,
        rng: &mut R,
    ) -> RelayDispatch {
        let plan = self.plan_relay(source, local_origin, node_sync, rng);
        RelayDispatch {
            carrier: self.carrier_for(plan),
            plan,
        }
    }

    /// [`Self::plan_relay_with_refresh`] plus the carrier that serves it.
    ///
    /// The production shape: **one** call yielding phase *and* carrier *and*
    /// slot, so no caller assembles the three.
    pub fn plan_dispatch_with_refresh<R: RelayRng + ?Sized>(
        &mut self,
        source: Option<ConnectionId>,
        local_origin: bool,
        node_sync: NodeSync,
        rng: &mut R,
    ) -> RelayDispatch {
        let plan = self.plan_relay_with_refresh(source, local_origin, node_sync, rng);
        RelayDispatch {
            carrier: self.carrier_for(plan),
            plan,
        }
    }

    /// Admit a session whose declaration is not its connector's column.
    ///
    /// The guard's third column. Production admission copies
    /// [`declaration`]`(connector.column())`.
    #[cfg(test)]
    pub fn admit_synthetic(
        &mut self,
        id: ConnectionId,
        direction: PeerDirection,
        connector: ConnectorId,
        column: Declaration,
    ) {
        self.contexts.insert(
            id,
            PeerFluff {
                queued: Vec::new(),
                direction,
                connector,
                declaration: column,
            },
        );
        self.note_hidden_class();
    }
}

#[cfg(test)]
mod edge;
#[cfg(test)]
mod embargo_tests;
#[cfg(test)]
mod hidden_class_tests;
#[cfg(test)]
mod hidden_slot_tests;
#[cfg(test)]
mod stem_draw;
#[cfg(test)]
mod synthetic;
#[cfg(test)]
mod tests;

#[cfg(test)]
mod embargo_cache {
    use std::sync::Arc;

    use super::{declaration, embargo_timer};
    use shekyl_transport_layer::ConnectorId;

    #[test]
    fn one_table_per_assessed_transit() {
        let clearnet = declaration(ConnectorId::Clearnet.column());
        let first = embargo_timer(&clearnet).expect("clearnet transit is assessed");
        let second = embargo_timer(&clearnet).expect("clearnet transit is assessed");
        assert!(Arc::ptr_eq(&first, &second));
        let hidden = declaration(ConnectorId::Tor.column());
        let tor = embargo_timer(&hidden).expect("tor transit is assessed");
        assert!(!Arc::ptr_eq(&first, &tor));
    }
}
