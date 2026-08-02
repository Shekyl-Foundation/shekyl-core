// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The zone: one Dandelion++ relay domain's state and its scheduled steps.
//!
//! A zone is the unit the inherited C++ calls `detail::zone` — public,
//! or i2p/tor. This type owns the state §18.5's inventory assigned to Rust:
//! peer fluff queues, the stem map, the epoch role, and the covert **schedule**
//! (enable bit, cadence, per-channel deadlines). Covert **buffers** and
//! transport (framing, padding, the socket) stay C++ permanently, so a
//! transaction body crosses the boundary only as an opaque blob. See
//! `DAEMON_RELAY_PRIVACY.md` §20.2 / §20.4 for the post-RP-3b inventory.

use std::collections::BTreeMap;
use std::sync::Arc;

use shekyl_relay_privacy::params::{inherited, DandelionParams};
use shekyl_relay_privacy::rng::RelayRng;
use shekyl_relay_privacy::schedule::{
    DelayFamily, EpochScheduler, FluffScheduler, Millis, NoiseCadence, PeerDirection,
};
use shekyl_relay_privacy::stem_map::{ConnectionId, StemMap};

use crate::stem_watch::{StemTally, StemWatch, TxId};

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
    /// The inherited rule, one line in `fluff_notify` under the comment *"When
    /// i2p/tor, only fluff to outbound connections"*. It is why noise-mode
    /// networks can substitute for Dandelion++'s sybil resistance at all: an
    /// inbound connection on a hidden service is an unauthenticated stranger who
    /// dialled *us*, so relaying to it hands a transaction to a peer we did not
    /// choose. Only outbound connections are ones this node selected.
    OutboundOnly,
}

/// Covert-channel schedule for a zone — or its deliberate absence.
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
/// covert interval **short** — a privacy defect no count assertion and no
/// goodness-of-fit grade can see (§20.2a).
#[derive(Debug)]
enum CovertSchedule {
    Off,
    On {
        cadence: NoiseCadence,
        /// Next send deadline per channel, indexed by channel.
        deadlines: Vec<Millis>,
    },
}

impl CovertSchedule {
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
    /// When covert is enabled this is also the covert channel count (channel
    /// `i` ↔ slot `i`). Production pins it to [`inherited::NOISE_CHANNELS`].
    stems: usize,
    /// Which peers a fluff batch may reach. See [`FluffReach`].
    reach: FluffReach,
    /// Covert schedule (enable + cadence + per-channel deadlines), or off.
    ///
    /// **Single owner of the enable fact** (§20.4). Before RP-3b it lived only
    /// in C++, encoded as `!zone::noise.empty()` — the byte payload doing
    /// double duty as its own enable flag. C++ still holds the payload buffers;
    /// Rust owns *whether* and *when* channels fire.
    covert: CovertSchedule,
    /// Per-successor stem outcomes — §12.11's signal, **derived here rather
    /// than imported from `tx_pool`** (§38.1). Records; never judges.
    stem_watch: StemWatch,
}

impl Zone {
    /// Open a zone at `now` with no connections yet.
    ///
    /// The first epoch is drawn immediately, matching the inherited
    /// `start_epoch` running once at construction.
    ///
    /// When `covert_enabled`, `stems` is also the covert channel count and
    /// must equal [`inherited::NOISE_CHANNELS`] in production (C++ sizes its
    /// channel deque from `CRYPTONOTE_NOISE_CHANNELS`). A mismatch is a
    /// debug assertion here and a silent OOB drop on the C++ side.
    pub fn new<R: RelayRng + ?Sized>(
        params: DandelionParams,
        stems: usize,
        reach: FluffReach,
        covert_enabled: bool,
        now: Millis,
        rng: &mut R,
    ) -> Self {
        debug_assert!(
            !covert_enabled || stems == inherited::NOISE_CHANNELS,
            "covert channel count must equal inherited::NOISE_CHANNELS \
             (CRYPTONOTE_NOISE_CHANNELS); got stems={stems}"
        );
        let epoch = EpochScheduler::new(params).start(now, rng);
        let covert = if covert_enabled {
            CovertSchedule::on(stems, now, rng)
        } else {
            CovertSchedule::Off
        };
        Self {
            stem_watch: StemWatch::default(),
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
            covert,
        }
    }

    /// The earliest covert send deadline, or `None` when covert is disabled.
    pub fn covert_deadline(&self) -> Option<Millis> {
        self.covert.earliest()
    }

    /// The single earliest channel due at `now`, re-armed from `now` (CV-3).
    ///
    /// See [`CovertSchedule::due_one`]: at most one channel per call so a late
    /// poll cannot emit a multi-channel burst.
    pub fn due_covert_channel<R: RelayRng + ?Sized>(
        &mut self,
        now: Millis,
        rng: &mut R,
    ) -> Option<usize> {
        self.covert.due_one(now, rng)
    }

    /// A channel's armed deadline, for CV-3's witness.
    #[cfg(test)]
    pub(crate) fn covert_deadline_at(&self, channel: usize) -> Option<Millis> {
        self.covert.deadline_at(channel)
    }

    /// Whether this zone runs covert (noise) channels.
    ///
    /// The single owner of the fact (§20.4). C++ reads it back through
    /// `shekyl_relay_zone_covert_enabled` rather than re-deriving it from the
    /// payload it happens to hold, so there is exactly one place the answer
    /// comes from.
    #[must_use]
    pub fn covert_enabled(&self) -> bool {
        self.covert.enabled()
    }

    /// Configured stem width (slot count). When covert is on, also the channel
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
    /// (`None` = locally originated, matching `in_mapping_[nil]`), and must be
    /// seen again by `deadline`.
    ///
    /// **The caller supplies the window rather than this type choosing it.**
    /// Today it is the adopted embargo draw, because that is the same question
    /// (*did my successor propagate this?*); but §12.11's decision window is an
    /// open parameter and need not equal the embargo, so freezing them
    /// together here would decide something the round has left open.
    pub fn record_stem(
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
    /// timer, no reactor, and the force hooks exercise it for free. Returns
    /// how many resolved, so a witness can assert the drive ran.
    pub fn expire_stem_observations(&mut self, now: Millis) -> usize {
        self.stem_watch.expire(now)
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
    pub fn stem_snapshot(&self) -> Vec<(ConnectionId, StemTally)> {
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
        // Reputation and in-flight observations go with the peer. Retention
        // across a disconnect is §33.6's open question — a *requirement* if
        // warm-up exceeds mean uptime, a forensic artifact either way — and
        // this must not decide it by quietly keeping state.
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
        let _ = self.map.update(outbound, rng);
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
    /// schedule. Post-§20.3 the binding travels with each [`crate::Effect::CovertSend`]
    /// (or [`crate::Effect::CovertUnbind`] when unbound). A caller-initiated
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

#[cfg(test)]
mod tests;
