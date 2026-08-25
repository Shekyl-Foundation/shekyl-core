// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The zone: one Dandelion++ relay domain's state and its scheduled steps.
//!
//! A zone is the unit the inherited C++ calls `detail::zone` — public,
//! or i2p/tor. This type owns the state §18.5's inventory assigned to Rust:
//! peer fluff queues, the stem map, the epoch role, and the noise **schedule**
//! (enable bit, cadence, per-channel deadlines). Noise **buffers** live in
//! [`crate::NoiseQueues`] (`COVER_TRAFFIC_RESTORATION.md` §2.9 step 2).
//! C++ is transport until step 5; it cannot enable the carrier. A
//! transaction body is still an opaque blob here. See
//! `DAEMON_RELAY_PRIVACY.md` §20.2 / §20.4 for the post-RP-3b inventory.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use shekyl_relay_privacy::params::{carrier, inherited, DandelionParams};
use shekyl_relay_privacy::rng::RelayRng;
use shekyl_relay_privacy::schedule::{
    DelayFamily, EmbargoTimer, EpochScheduler, FluffScheduler, Millis, NoiseCadence, PeerDirection,
};
use shekyl_relay_privacy::stem_map::{ConnectionId, SlotIndex, StemMap};
use shekyl_relay_privacy::LinkSecrecy;

use crate::stem_watch::{StemTally, StemTallySnapshot, StemWatch, TxId};

/// One opaque transaction blob shared across every peer that accepted a fluff
/// batch.
///
/// Fan-out clones the [`Arc`], not the bytes. The FFI maps each inbound span
/// into one of these once; per-peer queues hold cheap handles. Sorting and
/// de-duplication on flush compare by content (`Arc<[u8]>: Ord`).
pub type TxBlob = Arc<[u8]>;

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
    /// Shared handles ([`TxBlob`]) so a public zone with N peers does not make
    /// N full payload copies of every accepted batch. The deadline itself is
    /// **not** here — `FluffScheduler` owns pending deadlines, and a copy in
    /// this struct would be a second owner of the same fact (§18.5).
    pub queued: Vec<TxBlob>,
    /// Who dialed whom — the inherited code gives outbound peers half the
    /// inbound fluff delay, and [`shekyl_relay_privacy::schedule::FluffScheduler`]
    /// keeps that asymmetry.
    pub direction: PeerDirection,
}

impl PeerFluff {
    fn new(direction: PeerDirection) -> Self {
        Self {
            queued: Vec::new(),
            direction,
        }
    }
}

/// What the relay path should do with a batch of transactions.
///
/// The zone decides; the caller performs. Framing and the socket stay C++,
/// so this returns a destination rather than sending to one.
///
/// # Why the two non-stem outcomes are distinct
///
/// They differ in what the caller must do next, so collapsing them to one
/// "fluff" answer would lose the distinction the relay path is built on:
///
/// - [`RelayPlan::NoRoute`] is *transient*. The zone would stem, but no slot is
///   currently backed by a live peer — the caller may refresh its connection
///   set and re-plan before accepting the fallback.
/// - [`RelayPlan::FluffEpoch`] is *settled for the epoch*. Refreshing changes
///   nothing, so a retry would be wasted work.
///
/// The daemon also reports them differently: the inherited `dandelionpp_notify`
/// emits `relay_method::stem` on *entering* the stem-eligible branch, before any
/// routing is attempted, and `relay_method::fluff` only on falling through. A
/// caller holding one bool cannot reconstruct which event to emit, and would
/// have to re-evaluate `!fluffing || local_origin` itself — a second copy of the
/// RD-4 predicate this type exists to keep single-owned.
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
}

/// Why [`Zone::new`] refused a configuration.
///
/// Three refusals, three variants — collapsing them to `None` would be the
/// same axis-merge this type exists to prevent. The FFI maps every variant
/// to a null handle; a future in-process caller matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneNewError {
    /// Noise conceals packet sizing. On a cleartext link the observer reads
    /// the contents outright, so padding sizes conceals nothing.
    NoiseOnCleartext,
    /// `stems` doubles as the channel count. Noise is
    /// [`inherited::NOISE_CHANNELS`] wide; a mismatch sizes the schedule
    /// against a width the rest of the stack does not share.
    NoiseChannelCount {
        /// The stem/channel count that was requested.
        got: usize,
    },
    /// The epoch cannot carry a full-size message, so the message can never
    /// arrive: CV-1 discards the in-flight remainder at every epoch roll.
    ///
    /// Budget is [`inherited::noise_windows_in_epoch`] against
    /// [`carrier::MAX_FRAGMENTS`]. Runtime, not `const`, because the
    /// epoch crosses as `min_epoch_secs`.
    NoiseCannotCrossOneEpoch {
        /// Windows a full-size message needs.
        needs: u32,
        /// Windows the epoch affords.
        affords: u32,
    },
}

impl fmt::Display for ZoneNewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoiseOnCleartext => {
                write!(f, "noise carrier requires an encrypted link")
            }
            Self::NoiseChannelCount { got } => write!(
                f,
                "noise channel count must equal inherited::NOISE_CHANNELS (got {got})"
            ),
            Self::NoiseCannotCrossOneEpoch { needs, affords } => write!(
                f,
                "noise epoch carries {affords} windows but a full message needs \
                 {needs}; the remainder is discarded at every epoch roll"
            ),
        }
    }
}

/// Which peers a fluff batch may reach in this zone.
///
/// A zone-lifetime policy, not a per-batch choice, which is why it is set at
/// construction and never passed to [`Zone::queue_fluff`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FluffReach {
    /// Every connected peer except the source. Public ipv4/ipv6 zones.
    EveryPeer,
    /// Outbound connections only — **i2p/tor**.
    ///
    /// The mechanism is inherited — one line in `fluff_notify` under *"When
    /// i2p/tor, only fluff to outbound connections"* — but **its Shekyl
    /// justification is not, and the inherited one was wrong.**
    ///
    /// > **Retracted rationale (2026-08-17).** This doc previously read *"it is
    /// > why noise-mode networks can substitute for Dandelion++'s sybil
    /// > resistance at all"*. That is the sybil-substitution fallacy §64
    /// > already named, and it conflates two different observers: **noise**
    /// > masks the node↔proxy wire against an *external* observer, while
    /// > **Dandelion++** defends against an *internal* adversarial peer.
    /// > Neither substitutes for the other, and minting onion addresses is
    /// > free, so the anonymity network never supplied sybil resistance —
    /// > this rule did.
    ///
    /// Two justifications, both standing on their own:
    ///
    /// 1. **A node relays only to peers it chose.** An inbound connection on a
    ///    hidden service is an unauthenticated stranger who dialled *us*, so
    ///    relaying to it hands a transaction to a peer we did not select. That
    ///    is a genuine partial sybil mitigation and it needs no cover traffic
    ///    to be true.
    /// 2. **It is the leg that makes anonymity-zone emit attribution
    ///    impossible** (§91.4). To receive a fluff from node `Y`, an adversary
    ///    must be `Y`'s *outbound* — i.e. `Y` dialled it — which is exactly the
    ///    direction where the adversary holds `tor_address::unknown()` and
    ///    `ANON_ZONE_SENTINEL_PEER_ID`. On the reverse link, where the
    ///    adversary does know `Y`'s onion because it chose it, this rule skips
    ///    the send. **There is no direction carrying both the emit and the
    ///    name**, and §91 (Design A) now depends on that.
    ///
    /// Point 2 makes this rule load-bearing rather than merely inherited:
    /// widening the reach to inbound peers would hand an active marker the
    /// attribution it currently cannot obtain. Do not relax it without
    /// reopening §91.4.
    OutboundOnly,
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
        let cadence = NoiseCadence::inherited();
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
pub struct Zone {
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
    /// Which peers a fluff batch may reach. See [`FluffReach`].
    reach: FluffReach,
    /// Noise schedule (enable + cadence + per-channel deadlines), or off.
    ///
    /// **Single owner of the enable fact** (§20.4). Before RP-3b it lived only
    /// in C++, encoded as `!zone::noise.empty()` — the byte payload doing
    /// double duty as its own enable flag. C++ still holds the payload buffers;
    /// Rust owns *whether* and *when* channels fire.
    noise: NoiseSchedule,
    /// Per-successor stem outcomes — §12.11's signal, **derived here rather
    /// than imported from `tx_pool`** (§38.1). Records; never judges.
    stem_watch: StemWatch,
    /// Observation window for stem outcomes. Built once from this zone's
    /// [`DandelionParams`] at construction — the adopted embargo draw, because
    /// both questions ask the same peer the same thing (*did you propagate
    /// this?*). Cached here rather than rebuilt on every stem: the timer is a
    /// pure function of params and never changes for the life of the zone.
    ///
    /// If §12.11's decision window ever diverges from the embargo, this is the
    /// one field that changes — not an FFI export and not a C++ call site.
    observation_timer: EmbargoTimer,
}

impl Zone {
    /// Open a zone at `now` with no connections yet, or [`Err`] when the
    /// requested configuration is one the design forbids.
    ///
    /// The first epoch is drawn immediately, matching the inherited
    /// `start_epoch` running once at construction.
    ///
    /// # Refusals
    ///
    /// **A noise carrier requires an encrypted zone** (ruling of 2026-08-19).
    /// Noise conceals *packet sizing*, and sizing is the only thing left for a
    /// network observer to read once the link is encrypted. On a cleartext
    /// link that observer reads the contents, so padding the sizes conceals
    /// nothing and the bandwidth buys nothing. This is a refusal rather than a
    /// silent downgrade to carrier-off, because a node configured
    /// for a protection it is not getting is the failure mode worth being loud
    /// about.
    ///
    /// The predicate is [`LinkSecrecy`] and nothing else. It is **not** reach,
    /// and it is **not** anonymity: reach says who receives a fluff, anonymity
    /// says who can be identified, and neither is the question. Encrypting
    /// ordinary internet traffic would make a clearnet zone eligible for noise
    /// without making it anonymous, and `RelayZone::is_encrypted` is the one
    /// place that would change. [`LinkSecrecy`] can only be constructed from a
    /// [`shekyl_relay_privacy::RelayZone`], so a caller cannot mint "encrypted"
    /// beside a cleartext identity. This constructor still takes secrecy as a
    /// **parameter**, not a [`shekyl_relay_privacy::RelayZone`]: Design A is
    /// that transport is a parameter, not a topology, and handing the
    /// scheduler the overlay identity would recouple the axes this type exists
    /// to keep apart. The FFI (and the carrier's Rust-side caller) derives
    /// params, reach, and secrecy from one discriminant at the adapter.
    ///
    /// **A noise carrier's channel count must equal
    /// [`inherited::NOISE_CHANNELS`]** — `stems` doubles as the channel count
    /// and the schedule is that wide. This was a `debug_assert!`, which
    /// compiles out in release and therefore let the mismatched zone be
    /// built in exactly the configuration that ships.
    ///
    /// **A noise epoch must carry a full-size message** — otherwise CV-1
    /// discards the remainder at every roll. The budget is
    /// [`inherited::noise_windows_in_epoch`] against
    /// [`carrier::MAX_FRAGMENTS`]; the epoch is a runtime argument, so
    /// this is a refusal rather than a `const` assertion.
    ///
    /// The three refusals are distinct [`ZoneNewError`] variants. The FFI
    /// maps every one to null because that is the only channel a C ABI has;
    /// an in-process caller after the daemon cutover matches.
    ///
    /// # Who can reach the refusals
    ///
    /// C++ never sets the noise flag, so no production construction hits
    /// these. Tests do. The carrier's Rust-side caller will: it forms the
    /// pair in Rust and stops routing it through `make_relay_zone` — which
    /// is why the checks are here and not at the FFI edge. That caller is
    /// not the daemon cutover's to provide (`COVER_TRAFFIC_RESTORATION.md`
    /// §3, step 2, corrected 2026-08-25); C++ keeps performing transport.
    pub fn new<R: RelayRng + ?Sized>(
        params: DandelionParams,
        stems: usize,
        reach: FluffReach,
        secrecy: LinkSecrecy,
        noise_enabled: bool,
        now: Millis,
        rng: &mut R,
    ) -> Result<Self, ZoneNewError> {
        if noise_enabled {
            if !secrecy.is_encrypted() {
                return Err(ZoneNewError::NoiseOnCleartext);
            }
            if stems != inherited::NOISE_CHANNELS {
                return Err(ZoneNewError::NoiseChannelCount { got: stems });
            }
            let affords = inherited::noise_windows_in_epoch(params.min_epoch_secs);
            if affords < carrier::MAX_FRAGMENTS {
                return Err(ZoneNewError::NoiseCannotCrossOneEpoch {
                    needs: carrier::MAX_FRAGMENTS,
                    affords,
                });
            }
        }
        let epoch = EpochScheduler::new(params).start(now, rng);
        let noise = if noise_enabled {
            NoiseSchedule::on(stems, now, rng)
        } else {
            NoiseSchedule::Off
        };
        // Observation window shares the zone's params, not a second
        // `DandelionParams::inherited()` rebuild at the FFI edge.
        let observation_timer = EmbargoTimer::adopted(&params);
        Ok(Self {
            stem_watch: StemWatch::default(),
            observation_timer,
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
            reach,
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

    /// A peer finished its handshake and may now carry relay traffic.
    ///
    /// Mirrors `notify::on_handshake_complete`. Idempotent: a repeated
    /// handshake for a live connection keeps the existing batch rather than
    /// discarding queued transactions.
    pub fn on_handshake_complete(&mut self, id: ConnectionId, direction: PeerDirection) {
        self.contexts
            .entry(id)
            .or_insert_with(|| PeerFluff::new(direction));
    }

    /// Record that `txs` were stemmed to `successor`, keyed under `source`
    /// (`None` = locally originated, matching `in_mapping_[nil]`).
    ///
    /// The observation window is drawn here from the zone's cached adopted
    /// embargo timer at `now` — the same question the pool's embargo asks of
    /// the same peer (*did you propagate this?*). Domain ownership stays in
    /// this crate (rule 20): the FFI only marshals bytes and a clock.
    pub fn record_stem<R: RelayRng + ?Sized>(
        &mut self,
        txs: &[TxId],
        successor: ConnectionId,
        source: Option<ConnectionId>,
        now: Millis,
        rng: &mut R,
    ) {
        let deadline = self.observation_timer.deadline(now, rng);
        for tx in txs {
            self.stem_watch.stemmed(*tx, successor, source, deadline);
        }
    }

    /// Record stems with an explicit observation deadline.
    ///
    /// **Test / deterministic-drive only.** Production always goes through
    /// [`Zone::record_stem`], which draws from the cached embargo timer. Fixed
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
        for tx in txs {
            self.stem_watch.stemmed(*tx, successor, source, deadline);
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
    pub fn record_arrival(&mut self, txs: &[TxId], from: Option<ConnectionId>) {
        for tx in txs {
            self.stem_watch.seen(tx, from);
        }
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

    /// Merge the currently live outbound connections into the stem map,
    /// **keeping** slots whose peer is still connected.
    ///
    /// The mid-epoch refresh: the inherited `connection_map::update`, reached
    /// through `update_channels::run`. Post-inversion (§20.3) the stem-set
    /// change predicate has no consumer: a rebound channel picks up its new
    /// peer at the next send, and a channel the merge leaves unbound clears at
    /// its next due tick — both read from the map itself via [`Driver::poll`].
    ///
    /// **Not what an epoch boundary does.** See [`Zone::rebuild_stems`]; the two
    /// are separate methods because collapsing them freezes the stem graph, and
    /// nothing about the merged result looks wrong when it happens.
    pub fn update_stems<R: RelayRng + ?Sized>(&mut self, outbound: Vec<ConnectionId>, rng: &mut R) {
        // `StemMap::update` still returns `StemSetChange` for its own callers
        // and tests; the zone no longer surfaces it — nothing re-points on push.
        // Named bind: the value is `Copy + must_use`, so neither `drop` nor
        // `let _ =` is available under the workspace lint table.
        let _change = self.map.update(outbound, rng);
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
    pub fn rebuild_stems<R: RelayRng + ?Sized>(
        &mut self,
        outbound: Vec<ConnectionId>,
        rng: &mut R,
    ) {
        self.map = StemMap::new(outbound, self.stems, rng);
    }

    /// Begin a new epoch at `now`: re-draw the fluff/stem role and the end time.
    ///
    /// This is what `notify::run_epoch()` forces in tests and what the driver
    /// calls when [`Zone::epoch_deadline`] elapses. Both paths run the same
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
    /// **test-only** window on the pinning mechanics that [`Zone::plan_relay`]
    /// wraps.
    ///
    /// Production never calls this: it routes through `plan_relay`, which applies
    /// the RD-4 predicate (`!fluffing || local_origin`) before consulting the
    /// map. This forwarder lets the pinning tests drive `stem_map::stem_for`
    /// directly, without a redraw loop to force a stem epoch. It is `#[cfg(test)]`
    /// — compiled out of production — so a maintainer reading the type cannot
    /// mistake it for a second live routing entry point (unlike the deliberately
    /// `pub` observation witnesses such as [`Zone::pinned_sources`], which only
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
    pub fn plan_relay<R: RelayRng + ?Sized>(
        &mut self,
        source: Option<ConnectionId>,
        local_origin: bool,
        rng: &mut R,
    ) -> RelayPlan {
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

    /// Plan a relay; on a transient [`RelayPlan::NoRoute`], merge `outbound`
    /// into the stem map once and re-plan.
    ///
    /// This is the refresh policy the inherited `dandelionpp_notify` looped in
    /// C++ (`plan` → empty map → `update` → `plan`). Keeping it here means the
    /// shim only offers the connection snapshot and performs transport — it does
    /// not own "empty / stale map ⇒ refresh" scheduling, which is zone logic the
    /// 33-gtest oracle cannot see through the FFI (§18.4a).
    ///
    /// A settled [`RelayPlan::FluffEpoch`] does **not** refresh: retrying cannot
    /// change an epoch decision.
    pub fn plan_relay_with_refresh<R: RelayRng + ?Sized>(
        &mut self,
        source: Option<ConnectionId>,
        local_origin: bool,
        outbound: Vec<ConnectionId>,
        rng: &mut R,
    ) -> RelayPlan {
        match self.plan_relay(source, local_origin, rng) {
            RelayPlan::NoRoute => {
                self.update_stems(outbound, rng);
                self.plan_relay(source, local_origin, rng)
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
    /// caller to store what it should be asking [`Zone::fluff_deadline`] for —
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
        let outbound_only = self.reach == FluffReach::OutboundOnly;
        for (id, peer) in &mut self.contexts {
            if Some(*id) == source {
                continue;
            }
            // See `FluffReach::OutboundOnly`: on i2p/tor an inbound peer is a
            // stranger who dialled us, and relaying to it defeats the sybil
            // resistance the hidden-service network is standing in for.
            if outbound_only && peer.direction == PeerDirection::Inbound {
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
    /// the acceptance note on [`Zone::fluff`].
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

impl Zone {
    /// Attach a carrier to a plan, per §42.3.
    ///
    /// Noise carries a **stem** and only a stem, and only when noise is
    /// enabled on this zone. A fluff epoch and a no-route both take the
    /// ordinary connection: fluff by §42.3's design, no-route because there is
    /// nothing to carry.
    ///
    /// The slot lookup is consistent by construction — the destination came
    /// from this same map in this same call, so `slot_of` cannot miss it, and
    /// the `None` arm is unreachable rather than a fallback.
    ///
    /// **What it does when reached, stated exactly.** It `debug_assert!`s, and
    /// in release it returns [`RelayCarrier::Ordinary`] — so the stem still
    /// goes out, over the ordinary connection. That is a **cover** degradation,
    /// not a routing one, and it is deliberate: §92.4's rule is that carrier
    /// unavailability must never travel as a routing verdict. Dropping the send
    /// would convert a map inconsistency into a routing failure, which is the
    /// inversion the inherited covert branch made in the other direction —
    /// keeping the carrier and degrading the phase (§42.5a).
    fn carrier_for(&self, plan: RelayPlan) -> RelayCarrier {
        match plan {
            RelayPlan::Stem(destination) if self.noise_enabled() => {
                match self.map.slot_of(destination) {
                    Some(slot) => RelayCarrier::Noise { channel: slot },
                    None => {
                        debug_assert!(
                            false,
                            "planned a stem to a peer with no slot: the destination came from \
                             this map in this call, so this is map corruption, not a posture"
                        );
                        RelayCarrier::Ordinary
                    }
                }
            }
            _ => RelayCarrier::Ordinary,
        }
    }

    /// [`Self::plan_relay`] plus the carrier that serves it (§42.3).
    pub fn plan_dispatch<R: RelayRng + ?Sized>(
        &mut self,
        source: Option<ConnectionId>,
        local_origin: bool,
        rng: &mut R,
    ) -> RelayDispatch {
        let plan = self.plan_relay(source, local_origin, rng);
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
        outbound: Vec<ConnectionId>,
        rng: &mut R,
    ) -> RelayDispatch {
        let plan = self.plan_relay_with_refresh(source, local_origin, outbound, rng);
        RelayDispatch {
            carrier: self.carrier_for(plan),
            plan,
        }
    }
}

#[cfg(test)]
mod tests;
