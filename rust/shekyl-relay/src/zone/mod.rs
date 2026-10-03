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
//! the epoch role, and the noise **schedule** (enable bit, cadence,
//! per-channel deadlines). Noise **buffers** live in [`crate::NoiseQueues`]
//! (`COVER_TRAFFIC_RESTORATION.md` §2.9 step 2). C++ is transport. The
//! development opt-in can ask for cover; Rust refuses that ask unless a
//! configured connector is an open link, and it sends cover only to a
//! session on such a connector. Tor is volume cover and takes no envelope.
//! A transaction body is still an opaque blob here. See
//! `DAEMON_RELAY_PRIVACY.md` criterion 4 and `TOR_COVER_POSTURE.md`.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use shekyl_relay_privacy::params::{carrier, inherited, DandelionParams};
use shekyl_relay_privacy::rng::RelayRng;
use shekyl_relay_privacy::schedule::{
    DelayFamily, EmbargoTimer, EpochScheduler, FluffScheduler, Millis, NoiseCadence, PeerDirection,
};
use shekyl_relay_privacy::stem_map::{ConnectionId, SlotIndex, StemMap};
pub use shekyl_transport_layer::ConnectorId;
use shekyl_transport_layer::{declaration, Assessment, NativeEncryption, YesNo};
use shekyl_types::relay::RelayMethod;

use crate::stem_watch::{StemTally, StemTallySnapshot, StemWatch, TxId};

mod cover;
mod own_edge;

pub use cover::{any_open_link, cover_class, measured_transit_ms, CoverClass};

/// One opaque transaction blob shared across every peer that accepted a fluff
/// batch.
///
/// Fan-out clones the [`Arc`], not the bytes. The FFI maps each inbound span
/// into one of these once; per-peer queues hold cheap handles. Sorting and
/// de-duplication on flush compare by content (`Arc<[u8]>: Ord`).
pub type TxBlob = Arc<[u8]>;

const _: () = {
    assert!(ConnectorId::Clearnet.index() == 0);
    assert!(ConnectorId::Tor.index() == 1);
};

/// The longest measured connector transit, in milliseconds.
///
/// The origin retry does not know which connector carried the stem — the
/// pool does not store one — so it waits this long rather than naming a
/// connector. An unmeasured connector is not in the max. A later connector
/// with a longer measurement raises the wait without a new call site.
#[must_use]
pub fn longest_measured_transit() -> f64 {
    ConnectorId::ALL
        .iter()
        .copied()
        .filter_map(measured_transit_ms)
        .max_by(f64::total_cmp)
        .expect("a connector with a measured transit")
}

/// This connector's declaration says the peer does not learn this node's address.
///
/// The cell is the connector's description. A connector that has not assessed
/// the cell is not eligible.
#[must_use]
pub fn address_hidden_from_peer(connector: ConnectorId) -> bool {
    declaration(connector.column()).address_hidden_from_peer() == Assessment::Assessed(YesNo::Yes)
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
#[must_use]
pub fn link_encrypted(connector: ConnectorId) -> bool {
    matches!(
        declaration(connector.column()).encryption(),
        Assessment::Assessed(NativeEncryption::Classical)
    )
}

/// True when any configured connector's link is encrypted.
///
/// The encryption cell. Cover eligibility is [`cover_class`], which
/// disagrees with this on Tor: the link is encrypted and still takes no
/// envelope.
#[must_use]
pub fn any_link_encrypted(configured: &[ConnectorId]) -> bool {
    configured.iter().copied().any(link_encrypted)
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
    /// The connector that carried this session.
    pub connector: ConnectorId,
}

impl PeerFluff {
    fn new(direction: PeerDirection, connector: ConnectorId) -> Self {
        Self {
            queued: Vec::new(),
            direction,
            connector,
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
///   a peer must not learn. One ordinary send. A failed write is terminal:
///   no stem-map refresh, no second plan, no fluff. Success records
///   `relay_method::local`.
/// - [`RelayPlan::NoOwnEdge`] is that draw with an empty pool. Send nothing
///   and record nothing. Refreshing the stem map cannot manufacture an
///   edge that hides this node's address.
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
    /// without a refresh and without a fluff. No cover on Tor by ruling; on
    /// a cover-bearing link the own-edge is [`RelayPlan::Stem`], and that
    /// slot is the channel.
    OwnEdge(ConnectionId),
    /// The hidden-address pool is empty.
    ///
    /// Send nothing and record nothing. Not a stem-map refresh, and not a
    /// fluff: either would publish the origin on a link whose peer learns
    /// this node's address.
    NoOwnEdge,
}

/// Why [`Relay::new`] refused a configuration.
///
/// Three refusals, three variants — collapsing them to `None` would be the
/// same axis-merge this type exists to prevent. The FFI maps every variant
/// to a null handle; a future in-process caller matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayNewError {
    /// The carrier was requested and no configured connector is an open link.
    ///
    /// Tor is volume cover: an envelope there buys nothing the network does
    /// not already provide, and a Tor-only node has nowhere to put one.
    /// Requesting the carrier is the NNhfs pipe on an open link, not padding
    /// on a volume-cover connector.
    NoiseWithoutOpenLink,
    /// `stems` doubles as the channel count. Noise is
    /// [`inherited::NOISE_CHANNELS`] wide; a mismatch sizes the schedule
    /// against a width the rest of the stack does not share.
    NoiseChannelCount {
        /// The stem/channel count that was requested.
        got: usize,
    },
    /// The epoch cannot carry a full-size message, so the message may never
    /// arrive: it cannot finish within one epoch, and any roll that hands its
    /// slot to a different peer restarts it from the first fragment (CV-1).
    ///
    /// Budget is [`carrier::noise_windows_in_epoch`] against
    /// [`carrier::MAX_FRAGMENTS`]. Runtime, not `const`, because the
    /// epoch crosses as `min_epoch_secs`.
    NoiseCannotCrossOneEpoch {
        /// Windows a full-size message needs.
        needs: u32,
        /// Windows the epoch affords.
        affords: u32,
    },
}

impl fmt::Display for RelayNewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoiseWithoutOpenLink => {
                write!(f, "noise carrier requires an open link")
            }
            Self::NoiseChannelCount { got } => write!(
                f,
                "noise channel count must equal inherited::NOISE_CHANNELS (got {got})"
            ),
            Self::NoiseCannotCrossOneEpoch { needs, affords } => write!(
                f,
                "noise epoch carries {affords} windows but a full message needs \
                 {needs}; a roll that rebinds the slot restarts it from the first \
                 fragment, so it may never finish"
            ),
        }
    }
}

/// Noise-channel schedule for a zone — or its deliberate absence.
///
/// One type so "enabled" and "has deadlines" cannot disagree: a disabled zone
/// has no schedule; an enabled zone always has one deadline per stem slot.
/// Channel `i` is bound to stem slot `i` (§20.3), so the deadline vector's
/// length is the stem width, which production pins to
/// [`inherited::NOISE_CHANNELS`] (`CRYPTONOTE_NOISE_CHANNELS` on the C++ side).
///
/// **CV-3 lives in how deadlines are mutated.** Each entry is drawn once and
/// re-drawn only when *that* channel fires. A wake caused by the fluff
/// scheduler, an epoch rollover, or another channel coming due must leave every
/// other entry untouched. Re-drawing on a foreign wake resamples
/// `min + U(0, jitter)` and keeps the minimum, which biases the effective
/// noise interval **short** — a privacy defect no count assertion and no
/// goodness-of-fit grade can see (§20.2a).
#[derive(Debug)]
enum NoiseSchedule {
    Off,
    On {
        cadence: NoiseCadence,
        /// Next send deadline per channel, indexed by channel.
        deadlines: Vec<Millis>,
    },
}

impl NoiseSchedule {
    fn on<R: RelayRng + ?Sized>(channels: usize, now: Millis, rng: &mut R) -> Self {
        let cadence = NoiseCadence::shipped();
        let deadlines = (0..channels).map(|_| cadence.next_send(now, rng)).collect();
        Self::On { cadence, deadlines }
    }

    fn enabled(&self) -> bool {
        matches!(self, Self::On { .. })
    }

    fn earliest(&self) -> Option<Millis> {
        match self {
            Self::Off => None,
            Self::On { deadlines, .. } => deadlines.iter().copied().min(),
        }
    }

    /// The single earliest channel due at `now`, re-armed from **`now`**.
    ///
    /// At most one channel per call: multi-channel emission in one poll is a
    /// synchronized burst — the soundness defect constant-rate cover exists to
    /// deny. A late poll that finds several deadlines past still surfaces them
    /// one wake at a time (`next_wake` re-arms immediately for the remainder).
    ///
    /// Re-armed from `now`, not the old deadline: arming from a past deadline
    /// catch-up-bursts after a stall; arming from `now` preserves inter-send
    /// spacing under load (phase may lag; rate does not). Only the fired entry
    /// is touched — CV-3.
    fn due_one<R: RelayRng + ?Sized>(&mut self, now: Millis, rng: &mut R) -> Option<usize> {
        let Self::On { cadence, deadlines } = self else {
            return None;
        };
        let (idx, _) = deadlines
            .iter()
            .copied()
            .enumerate()
            .filter(|&(_, d)| d <= now)
            .min_by_key(|&(_, d)| d)?;
        deadlines[idx] = cadence.next_send(now, rng);
        Some(idx)
    }

    #[cfg(test)]
    fn deadline_at(&self, channel: usize) -> Option<Millis> {
        match self {
            Self::Off => None,
            Self::On { deadlines, .. } => deadlines.get(channel).copied(),
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
    map: StemMap,
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
    /// A configured connector hides this node's address, so a local origin
    /// draws [`RelayPlan::OwnEdge`] rather than a stem slot.
    origin_address_hidden: bool,
    /// This epoch's own-edge, once a non-empty hidden-address pool has been
    /// drawn. Not a stem-map slot. Kept while that peer is live; a dead peer
    /// is replaced on the next origination. Cleared by [`Relay::rebuild_stems`].
    hop0_edge: Option<ConnectionId>,
    /// Noise schedule (enable + cadence + per-channel deadlines), or off.
    ///
    /// **Single owner of the enable fact** (§20.4). Before RP-3b it lived only
    /// in C++, encoded as `!zone::noise.empty()` — the byte payload doing
    /// double duty as its own enable flag. The payload buffers moved to
    /// [`crate::NoiseQueues`] with the executor port, as this module's own
    /// header says; Rust owns the buffers, *whether* and *when*.
    noise: NoiseSchedule,
    /// Per-successor stem outcomes — §12.11's signal, **derived here rather
    /// than imported from `tx_pool`** (§38.1). Records; never judges.
    stem_watch: StemWatch,
    /// One observation window per connector index, drawn when a stem is
    /// forwarded on that connector. `None` is a connector with no measured
    /// transit; its sessions are not stem candidates. Each timer is a pure
    /// function of that connector's transit term and does not change for the
    /// life of the relay.
    embargo: Vec<Option<EmbargoTimer>>,
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
    /// **Cover traffic requires a configured connector whose [`CoverClass`]
    /// is [`CoverClass::OpenLink`].** Tor is volume cover: no envelope, and
    /// a Tor-only ask has nowhere to put one. Clearnet with the carrier
    /// requested is the NNhfs pipe, which encrypts the open link and is the
    /// envelope. This is a refusal rather than a silent downgrade: a node
    /// that asked for a protection it is not getting is the failure worth
    /// being loud about.
    ///
    /// The predicate is [`any_open_link`]. It is not [`link_encrypted`] and
    /// it is not hop 0. [`address_hidden_from_peer`] says whether the peer
    /// learns this node's address. [`link_encrypted`] says whether a network
    /// observer can read the byte stream. Cover is the ruling on top of
    /// both, and it disagrees with both on the connectors that exist today.
    ///
    /// **A noise carrier's channel count must equal
    /// [`inherited::NOISE_CHANNELS`].** `stems` is that width. This was a
    /// `debug_assert!`, which compiles out in release.
    ///
    /// **A noise epoch must carry a full-size message.** Otherwise it cannot
    /// finish inside one epoch, and a roll that rebinds its slot restarts it
    /// from the first fragment (CV-1). The budget is
    /// [`carrier::noise_windows_in_epoch`] against
    /// [`carrier::MAX_FRAGMENTS`].
    ///
    /// The three refusals are distinct [`RelayNewError`] variants. The FFI
    /// maps every one to null. C++ passes the noise flag only behind the
    /// development opt-in and does not pre-decide which connector can carry
    /// it. The flag defaults off, so a shipped construction does not hit
    /// these.
    pub fn new<R: RelayRng + ?Sized>(
        params: DandelionParams,
        stems: usize,
        noise_requested: bool,
        configured: &[ConnectorId],
        now: Millis,
        rng: &mut R,
    ) -> Result<Self, RelayNewError> {
        if noise_requested {
            if !any_open_link(configured) {
                return Err(RelayNewError::NoiseWithoutOpenLink);
            }
            if stems != inherited::NOISE_CHANNELS {
                return Err(RelayNewError::NoiseChannelCount { got: stems });
            }
            let affords = carrier::noise_windows_in_epoch(params.min_epoch_secs);
            if affords < carrier::MAX_FRAGMENTS {
                return Err(RelayNewError::NoiseCannotCrossOneEpoch {
                    needs: carrier::MAX_FRAGMENTS,
                    affords,
                });
            }
        }
        let epoch = EpochScheduler::new(params).start(now, rng);
        let noise = if noise_requested {
            NoiseSchedule::on(stems, now, rng)
        } else {
            NoiseSchedule::Off
        };
        // One embargo timer per measured connector. The draw at stem time
        // reads the successor's connector, not the relay-wide parameter set.
        let embargo = ConnectorId::ALL
            .iter()
            .map(|connector| {
                measured_transit_ms(*connector)
                    .map(|ms| EmbargoTimer::adopted(&DandelionParams::adopted_for_transit_ms(ms)))
            })
            .collect();
        Ok(Self {
            stem_watch: StemWatch::default(),
            embargo,
            contexts: BTreeMap::new(),
            // Built at full width with no peers rather than `StemMap::empty()`,
            // so `update_stems` can grow into it. An empty map has no slots to
            // fill, which is what forced the first-population special case that
            // then swallowed the epoch rebuild.
            map: StemMap::new(Vec::new(), stems, rng),
            fluff: FluffScheduler::memoryless(),
            fluffing: epoch.fluffing,
            epoch_ends_at: epoch.ends_at,
            params,
            stems,
            origin_address_hidden: any_hides_address_from_peer(configured),
            hop0_edge: None,
            noise,
        })
    }

    /// The earliest noise send deadline, or `None` when noise is disabled.
    pub fn noise_deadline(&self) -> Option<Millis> {
        self.noise.earliest()
    }

    /// The single earliest channel due at `now`, re-armed from `now` (CV-3).
    ///
    /// See [`NoiseSchedule::due_one`]: at most one channel per call so a late
    /// poll cannot emit a multi-channel burst.
    pub fn due_noise_channel<R: RelayRng + ?Sized>(
        &mut self,
        now: Millis,
        rng: &mut R,
    ) -> Option<usize> {
        self.noise.due_one(now, rng)
    }

    /// A channel's armed deadline, for CV-3's witness.
    #[cfg(test)]
    pub(crate) fn noise_deadline_at(&self, channel: usize) -> Option<Millis> {
        self.noise.deadline_at(channel)
    }

    /// Whether a substitution envelope may be sent to `peer`.
    ///
    /// The destination's connector must be [`CoverClass::OpenLink`]. Tor is
    /// volume cover: no envelope, including when the peer also occupies a
    /// stem slot. A session that is gone is not a destination.
    pub(crate) fn noise_destination(&self, peer: ConnectionId) -> bool {
        self.contexts
            .get(&peer)
            .is_some_and(|session| matches!(cover_class(session.connector), CoverClass::OpenLink))
    }

    /// Whether this zone runs noise channels.
    ///
    /// The single owner of the fact (§20.4). C++ reads it back through
    /// `shekyl_relay_zone_noise_enabled` rather than re-deriving it from the
    /// payload it happens to hold, so there is exactly one place the answer
    /// comes from.
    #[must_use]
    pub fn noise_enabled(&self) -> bool {
        self.noise.enabled()
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
        }
    }

    /// Record that `txs` were stemmed to `successor`, keyed under `source`
    /// (`None` = locally originated, matching `in_mapping_[nil]`).
    ///
    /// The observation window is drawn from the successor's connector at
    /// `now`. A connector with no measured transit records nothing. The
    /// question is the one the pool's embargo asks of the same peer (*did
    /// you propagate this?*). Domain ownership stays in this crate (rule 20):
    /// the FFI only marshals bytes and a clock.
    pub fn record_stem<R: RelayRng + ?Sized>(
        &mut self,
        txs: &[TxId],
        successor: ConnectionId,
        source: Option<ConnectionId>,
        now: Millis,
        rng: &mut R,
    ) {
        let Some(connector) = self.contexts.get(&successor).map(|peer| peer.connector) else {
            return;
        };
        let Some(deadline) = self.embargo_deadline(connector, now, rng) else {
            return;
        };
        for tx in txs {
            self.stem_watch
                .stemmed(*tx, successor, source, connector, deadline);
        }
    }

    fn embargo_deadline<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        now: Millis,
        rng: &mut R,
    ) -> Option<Millis> {
        self.embargo
            .get(connector.index())
            .and_then(|timer| timer.as_ref())
            .map(|timer| timer.deadline(now, rng))
    }

    /// Mean of the embargo drawn for `connector`, when that connector has a
    /// measured transit.
    #[cfg(test)]
    pub fn embargo_mean_secs(&self, connector: ConnectorId) -> Option<u32> {
        self.embargo
            .get(connector.index())
            .and_then(|timer| timer.as_ref())
            .map(EmbargoTimer::mean_secs)
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

    /// Resolve every stem observation whose deadline has passed as *silent*.
    ///
    /// Driven from [`crate::Driver::poll`]'s `now`, so the outcome is a
    /// function of the same clock every other relay decision uses — no second
    /// reactor. The earliest pending deadline is also folded into
    /// [`crate::Driver::next_wake`], so the asio timer wakes for silences on
    /// time rather than only when fluff/epoch/noise happen to fire. Returns
    /// how many resolved, so a witness can assert the drive ran.
    pub fn expire_stem_observations(&mut self, now: Millis) -> usize {
        self.stem_watch.expire(now)
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
    /// other than where I sent it"* just became true.
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
        propagated
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

    /// Outbound, and the connector has a measured transit. An unmeasured
    /// connector is not a stem candidate.
    fn stem_candidate(peer: &PeerFluff) -> bool {
        peer.direction == PeerDirection::Outbound && measured_transit_ms(peer.connector).is_some()
    }

    /// Established outbound sessions. Inbound peers are not stem candidates.
    ///
    /// The set is this zone's session registry. A handshake-complete peer
    /// that is still synchronizing is included: recorded height is not a
    /// filter, and neither is `state_normal`. A connector with no measured
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
        // `StemMap::update` still returns `StemSetChange` for its own callers
        // and tests; the zone no longer surfaces it — nothing re-points on push.
        // Named bind: the value is `Copy + must_use`, so neither `drop` nor
        // `let _ =` is available under the workspace lint table.
        let _change = self.map.update(self.outbound_ids(), rng);
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
        // Class-blind. A hidden-address peer is one outbound candidate among
        // the rest, not a reserved slot. The own-edge is drawn separately,
        // on the next local origin, from the hidden-address pool.
        self.map = StemMap::new(self.outbound_ids(), self.stems, rng);
        self.hop0_edge = None;
    }

    /// Begin a new epoch at `now`: re-draw the fluff/stem role and the end time.
    ///
    /// This is what `notify::run_epoch()` forces in tests and what the driver
    /// calls when [`Relay::epoch_deadline`] elapses. Both paths run the same
    /// code, which is why forcing it in a test is not a special case.
    pub fn start_epoch<R: RelayRng + ?Sized>(&mut self, now: Millis, rng: &mut R) {
        let epoch = EpochScheduler::new(self.params).start(now, rng);
        self.fluffing = epoch.fluffing;
        self.epoch_ends_at = epoch.ends_at;
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
        if local_origin && self.origin_address_hidden {
            return self.own_edge(rng);
        }
        // No hidden-address connector: the own-edge is this stem slot. On a
        // cover-bearing link that is the channel's cadence. Tor does not
        // take this path.
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
    /// [`RelayPlan::NoOwnEdge`] and [`RelayPlan::OwnEdge`] do not: the stem
    /// map is not the pool those plans draw from, and a second plan would
    /// let an empty own-edge fall through to fluff.
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
    /// Owned here; never pushed as an array and never pulled by C++ on its own
    /// schedule. Post-§20.3 the binding travels with each [`crate::Effect::NoiseSend`]
    /// (or [`crate::Effect::NoiseUnbind`] when unbound). A caller-initiated
    /// read would race this zone's mutations — §18.5 finding 3.
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
    /// `channel` **is** the slot index: `NoiseSchedule` binds channel `i` to
    /// stem slot `i` (§20.3). Carried as [`SlotIndex`] so a crate-boundary
    /// caller cannot swap it with a walk cursor — the property the newtype
    /// exists for. The send loop must respect that binding rather than
    /// broadcasting to every channel (§42.5a).
    Noise { channel: SlotIndex },
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
    /// Noise carries a **stem** and only a stem, and only when noise is
    /// enabled on this zone. A fluff epoch and a no-route both take the
    /// ordinary connection: fluff by §42.3's design, no-route because there is
    /// nothing to carry.
    ///
    /// [`RelayPlan::AwaitSync`] and [`RelayPlan::NoOwnEdge`] name
    /// [`RelayCarrier::Ordinary`] so the match is total. That carrier is
    /// unread: the plan is the refusal, and the caller returns before any
    /// send.
    ///
    /// No cover on Tor by ruling; on cover-bearing links the own-edge is
    /// slot-aligned. [`RelayPlan::OwnEdge`] is the volume path and always
    /// leaves immediately. [`RelayPlan::Stem`] on an open link, while noise
    /// is on, is that slot's channel — including a clearnet local origin,
    /// whose first hop is the slot. A relayed stem with no slot is map
    /// corruption. In release that arm still returns
    /// [`RelayCarrier::Ordinary`]: the stem goes out. That is a cover
    /// degradation, not a routing one.
    fn carrier_for(&self, plan: RelayPlan) -> RelayCarrier {
        match plan {
            RelayPlan::Stem(destination) if self.noise.enabled() => {
                match self.map.slot_of(destination) {
                    Some(slot) if self.noise_destination(destination) => {
                        RelayCarrier::Noise { channel: slot }
                    }
                    Some(_) => RelayCarrier::Ordinary,
                    None => {
                        debug_assert!(
                            false,
                            "planned a relayed stem to a peer with no slot: the destination came \
                         from this map in this call, so this is map corruption, not a posture"
                        );
                        RelayCarrier::Ordinary
                    }
                }
            }
            // No cover on Tor by ruling. OwnEdge leaves on the ordinary
            // connection. On a cover-bearing link the own-edge is
            // [`RelayPlan::Stem`] and the arm above is its channel. The
            // other plans are a refusal or have nothing to carry.
            RelayPlan::OwnEdge(_)
            | RelayPlan::NoOwnEdge
            | RelayPlan::AwaitSync
            | RelayPlan::NoRoute
            | RelayPlan::FluffEpoch
            | RelayPlan::Stem(_) => RelayCarrier::Ordinary,
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
    /// slot, per rule 40's coarse-call rule.
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
}

#[cfg(test)]
mod edge;
#[cfg(test)]
mod stem_draw;
#[cfg(test)]
mod tests;
