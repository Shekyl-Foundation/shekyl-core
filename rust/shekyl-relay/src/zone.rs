// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The zone: one Dandelion++ relay domain's state and its scheduled steps.
//!
//! A zone is the unit the inherited C++ calls `detail::zone` — public,
//! or i2p/tor. This type owns the state §18.5's inventory assigned to Rust and
//! nothing else; the covert-traffic channels remain C++-owned until RP-3b, and
//! transport (framing, padding, the socket) stays C++ permanently, so a
//! transaction body crosses the boundary only as an opaque blob.

use std::collections::BTreeMap;

use shekyl_relay_privacy::params::DandelionParams;
use shekyl_relay_privacy::rng::RelayRng;
use shekyl_relay_privacy::schedule::{
    DelayFamily, EpochScheduler, FluffScheduler, Millis, PeerDirection,
};
use shekyl_relay_privacy::stem_map::{ConnectionId, StemMap, StemSetChange};

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
    /// The deadline itself is **not** here. `FluffScheduler` owns pending
    /// deadlines, and a copy in this struct would be a second owner of the
    /// same fact — the duplicate-state pattern `connection_count` was designed
    /// out of (§18.5). Ask the scheduler; do not mirror it.
    pub queued: Vec<Vec<u8>>,
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
    stems: usize,
}

impl Zone {
    /// Open a zone at `now` with no connections yet.
    ///
    /// The first epoch is drawn immediately, matching the inherited
    /// `start_epoch` running once at construction.
    pub fn new<R: RelayRng + ?Sized>(
        params: DandelionParams,
        stems: usize,
        now: Millis,
        rng: &mut R,
    ) -> Self {
        let epoch = EpochScheduler::new(params).start(now, rng);
        Self {
            contexts: BTreeMap::new(),
            map: StemMap::empty(),
            fluff: FluffScheduler::memoryless(),
            fluffing: epoch.fluffing,
            epoch_ends_at: epoch.ends_at,
            params,
            stems,
        }
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

    /// A peer disconnected.
    ///
    /// Mirrors `notify::on_connection_close`. Anything still queued for that
    /// peer goes with it — the inherited code drops the context wholesale, and
    /// re-routing a batch to a different peer would be a routing decision this
    /// step is not entitled to make.
    pub fn on_connection_close(&mut self, id: &ConnectionId) {
        self.contexts.remove(id);
        // The scheduler holds its own pending-deadline map; leaving the peer
        // there would keep waking the driver for a connection that is gone.
        self.fluff.forget(*id);
    }

    /// Re-point the stem map at the currently live outbound connections.
    ///
    /// Returns whether downstream channels must be re-armed — the exact
    /// predicate the inherited `connection_map::update` returned, carried
    /// through as a type rather than a bare `bool`.
    pub fn update_stems<R: RelayRng + ?Sized>(
        &mut self,
        outbound: Vec<ConnectionId>,
        rng: &mut R,
    ) -> StemSetChange {
        if self.map.width() == 0 {
            // First population: the map is built rather than merged, mirroring
            // the inherited construction at epoch start.
            self.map = StemMap::new(outbound, self.stems, rng);
            return StemSetChange::Changed;
        }
        self.map.update(outbound, rng)
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

    /// The stem peer for `source`, or `None` when none is routable.
    ///
    /// `source` is `None` for locally originated transactions. Mutates the
    /// map's source pinning, as the inherited `get_stem` does.
    pub fn stem_for<R: RelayRng + ?Sized>(
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

    /// Accept transaction blobs for fluffing to every peer except `source`.    /// Accept transaction blobs for fluffing to every peer except `source`.
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
    /// Blobs are opaque — this crate schedules, transport frames.
    pub fn queue_fluff<R: RelayRng + ?Sized>(
        &mut self,
        txs: &[Vec<u8>],
        source: Option<ConnectionId>,
        now: Millis,
        rng: &mut R,
    ) -> usize {
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
            peer.queued.extend(txs.iter().cloned());
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
    pub fn flush_fluff(&mut self, now: Millis, force: bool) -> Vec<(ConnectionId, Vec<Vec<u8>>)> {
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
    /// Pushed outward when it changes; never pulled by C++. With the zone
    /// strand gone, a caller-initiated read would race this zone's mutations —
    /// §18.5 finding 3, the call whose direction the inventory reversed.
    pub fn stem_slots(&self) -> &[Option<ConnectionId>] {
        self.map.slots()
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
mod tests {
    use super::*;
    use shekyl_relay_privacy::rng::SplitMix64;

    /// Frozen draws from seed `0xF1FF` for the wired fluff path. Not chosen —
    /// observed, then pinned. Note the shape is memoryless: a 250 ms draw sits
    /// beside a 23.5 s one, which is the variance a Poisson at these means
    /// cannot produce (`CV ~ 0.2` vs ~1). That is F-4 visible in four numbers.
    const PINNED_INBOUND: [Millis; 4] = [23_500, 2_250, 9_000, 2_250];
    const PINNED_OUTBOUND: [Millis; 4] = [1_750, 3_000, 250, 750];

    fn id(byte: u8) -> ConnectionId {
        let mut b = [0u8; 16];
        b[0] = byte;
        ConnectionId::from_bytes(b)
    }

    fn zone(rng: &mut SplitMix64) -> Zone {
        Zone::new(DandelionParams::inherited(), 2, 0, rng)
    }

    #[test]
    fn a_new_zone_owns_nothing_and_routes_nothing() {
        let mut rng = SplitMix64::new(1);
        let mut z = zone(&mut rng);
        assert_eq!(z.peer_count(), 0);
        assert_eq!(z.live_stems(), 0);
        assert_eq!(z.stem_for(None, &mut rng), None, "no stem before peers");
    }

    #[test]
    fn handshake_is_idempotent_and_does_not_discard_a_batch() {
        // A repeated handshake for a live connection must not reset the peer's
        // queued transactions — dropping them would silently lose relay work.
        let mut rng = SplitMix64::new(2);
        let mut z = zone(&mut rng);
        z.on_handshake_complete(id(1), PeerDirection::Outbound);
        z.contexts
            .get_mut(&id(1))
            .expect("peer present")
            .queued
            .push(vec![0xAA]);

        z.on_handshake_complete(id(1), PeerDirection::Inbound);
        assert_eq!(z.peer_count(), 1, "no duplicate peer");
        assert_eq!(
            z.peer(&id(1)).expect("peer present").queued.len(),
            1,
            "a repeat handshake kept the pending batch"
        );
    }

    #[test]
    fn close_removes_the_peer_and_its_queue() {
        let mut rng = SplitMix64::new(3);
        let mut z = zone(&mut rng);
        z.on_handshake_complete(id(1), PeerDirection::Inbound);
        z.on_handshake_complete(id(2), PeerDirection::Outbound);
        z.on_connection_close(&id(1));
        assert_eq!(z.peer_count(), 1);
        assert!(z.peer(&id(1)).is_none());
        assert!(z.peer(&id(2)).is_some());
    }

    #[test]
    fn live_stems_is_derived_not_cached() {
        // The inherited code cached this in `connection_count` and had to
        // declare "only update in strand, can be read at any time". Derived
        // here, there is no second copy to fall out of step (§18.5 finding 1).
        let mut rng = SplitMix64::new(4);
        let mut z = zone(&mut rng);
        assert_eq!(z.live_stems(), 0);

        assert_eq!(
            z.update_stems(vec![id(1), id(2), id(3)], &mut rng),
            StemSetChange::Changed
        );
        assert_eq!(z.live_stems(), 2, "two stem slots at the configured width");
        assert_eq!(z.stem_slots().len(), 2);

        // Losing every outbound peer empties the slots, and the derived count
        // follows immediately with no separate update step.
        assert_eq!(z.update_stems(Vec::new(), &mut rng), StemSetChange::Changed);
        assert_eq!(z.live_stems(), 0);
    }

    #[test]
    fn a_new_epoch_redraws_the_role_and_the_deadline() {
        let mut rng = SplitMix64::new(5);
        let mut z = zone(&mut rng);
        let first_deadline = z.epoch_deadline();
        assert!(first_deadline > 0, "an epoch has a future end");

        // Forcing the step is the same code the driver runs on the deadline —
        // which is what makes the daemon's run_epoch() hook honest.
        z.start_epoch(first_deadline, &mut rng);
        assert!(
            z.epoch_deadline() > first_deadline,
            "the new epoch ends after the old one"
        );
    }

    // --- F-4/F-5: the correction must be WITNESSED, not merely wired ---------
    //
    // §18.4 item 3. `FluffScheduler::inherited()` is `DelayFamily::Poisson` —
    // the F-4 defect — and `memoryless()` is `Geometric`, at identical means.
    // A wire to the wrong one compiles, fluffs, and passes every routing test
    // in `levin.cpp` (blind to timing) and any "does it fluff" test (blind to
    // distribution). These three close that gap from different directions.

    #[test]
    fn fluff_draws_are_memoryless_not_the_inherited_poisson() {
        // Structural: the family the zone actually draws from. Named against
        // the defect so a rewire reads as a regression, not a preference.
        let mut rng = SplitMix64::new(20);
        let z = zone(&mut rng);
        assert_eq!(
            z.fluff_family(),
            DelayFamily::Geometric,
            "the fluff delay must be the corrected memoryless draw (F-4)"
        );
        assert_ne!(
            z.fluff_family(),
            DelayFamily::Poisson,
            "FluffScheduler::inherited() is the F-4 defect and is one identifier away"
        );
    }

    /// One peer of one direction, so the scheduler's earliest deadline *is*
    /// that peer's draw. Measuring with two peers queued would sample
    /// `min(inbound, outbound)` instead — the mistake this test caught.
    fn mean_delay(direction: PeerDirection, seed: u64, n: u64) -> u64 {
        let mut rng = SplitMix64::new(seed);
        let mut total = 0_u64;
        for _ in 0..n {
            let mut z = zone(&mut rng);
            z.on_handshake_complete(id(1), direction);
            assert_eq!(z.queue_fluff(&[vec![1]], None, 0, &mut rng), 1);
            total += z.fluff_deadline().expect("a batch is in flight");
        }
        total / n
    }

    #[test]
    fn fluff_delay_means_match_the_configured_averages_with_outbound_halved() {
        // Behavioural: a right family with a wrong mean passes the structural
        // check above. The inherited asymmetry — outbound gets half the inbound
        // delay, because a node chooses who it dials — is a privacy property,
        // so it is pinned too.
        const N: u64 = 4_000;
        let inbound = mean_delay(PeerDirection::Inbound, 21, N);
        let outbound = mean_delay(PeerDirection::Outbound, 22, N);

        // Inherited means: 20 and 10 quarter-seconds = 5000ms and 2500ms.
        assert!(
            (4_600..=5_400).contains(&inbound),
            "inbound fluff mean {inbound}ms is not the configured 5000ms"
        );
        assert!(
            (2_300..=2_700).contains(&outbound),
            "outbound fluff mean {outbound}ms is not the configured 2500ms"
        );
        assert!(
            outbound < inbound,
            "outbound must stay the shorter delay: {outbound} vs {inbound}"
        );
    }

    #[test]
    fn fluff_deadlines_are_pinned_for_a_fixed_seed() {
        // Golden-vector shape on the *wired* path: any change to the draw the
        // zone uses — family, mean, or table — moves this sequence. This is the
        // assertion that fails if someone swaps in `inherited()`/Poisson, which
        // nothing else in the tree would notice.
        let mut rng = SplitMix64::new(0xF1FF);
        let inbound: Vec<Millis> = (0..4)
            .map(|_| {
                let mut z = zone(&mut rng);
                z.on_handshake_complete(id(1), PeerDirection::Inbound);
                z.queue_fluff(&[vec![0xAB]], None, 0, &mut rng);
                z.fluff_deadline().unwrap()
            })
            .collect();
        let outbound: Vec<Millis> = (0..4)
            .map(|_| {
                let mut z = zone(&mut rng);
                z.on_handshake_complete(id(1), PeerDirection::Outbound);
                z.queue_fluff(&[vec![0xAB]], None, 0, &mut rng);
                z.fluff_deadline().unwrap()
            })
            .collect();
        assert_eq!(
            (inbound.as_slice(), outbound.as_slice()),
            (PINNED_INBOUND.as_slice(), PINNED_OUTBOUND.as_slice()),
            "the wired fluff draw changed — if deliberate, re-derive it; if not, \
             check whether the scheduler was rewired to inherited()/Poisson"
        );
    }

    #[test]
    fn a_burst_does_not_push_a_peers_flush_further_out() {
        // The scheduler only draws when a peer has no pending deadline. If a
        // later queue re-drew, an adversary could hold a batch open by
        // trickling transactions and defer the fluff indefinitely.
        let mut rng = SplitMix64::new(23);
        let mut z = zone(&mut rng);
        z.on_handshake_complete(id(1), PeerDirection::Inbound);

        z.queue_fluff(&[vec![1]], None, 0, &mut rng);
        let first = z.fluff_deadline().unwrap();
        for _ in 0..16 {
            let _ = z.queue_fluff(&[vec![2]], None, 0, &mut rng);
        }
        assert_eq!(
            z.fluff_deadline(),
            Some(first),
            "a burst must not re-draw and defer the flush"
        );
        assert_eq!(
            z.peer(&id(1)).unwrap().queued.len(),
            17,
            "all blobs batched"
        );
    }

    #[test]
    fn fluff_skips_the_source_and_releases_on_deadline() {
        let mut rng = SplitMix64::new(24);
        let mut z = zone(&mut rng);
        z.on_handshake_complete(id(1), PeerDirection::Inbound);
        z.on_handshake_complete(id(2), PeerDirection::Outbound);

        let accepted = z.queue_fluff(&[vec![7]], Some(id(1)), 0, &mut rng);
        assert_eq!(accepted, 1, "one peer took it; the source is skipped");
        assert!(
            z.peer(&id(1)).unwrap().queued.is_empty(),
            "the source never gets its own transaction back"
        );
        assert_eq!(z.peer(&id(2)).unwrap().queued.len(), 1);

        let deadline = z.fluff_deadline().expect("a batch is in flight");
        if deadline > 0 {
            assert!(z.flush_fluff(deadline - 1, false).is_empty(), "not due yet");
        }
        let released = z.flush_fluff(deadline, false);
        assert_eq!(released, vec![(id(2), vec![vec![7]])]);
        assert!(z.fluff_deadline().is_none(), "nothing left pending");
    }

    #[test]
    fn forcing_a_flush_runs_the_same_release_path() {
        // What `run_fluff()` drives. Same release code as the deadline path —
        // only which batches count as due differs, which is what keeps the
        // daemon's force-step hook honest rather than a special case.
        let mut rng = SplitMix64::new(25);
        let mut z = zone(&mut rng);
        z.on_handshake_complete(id(1), PeerDirection::Inbound);
        z.queue_fluff(&[vec![9]], None, 0, &mut rng);
        let deadline = z.fluff_deadline().unwrap();

        if deadline > 0 {
            assert!(z.flush_fluff(0, false).is_empty(), "not due at t=0");
        }
        let released = z.flush_fluff(0, true);
        assert_eq!(
            released,
            vec![(id(1), vec![vec![9]])],
            "force releases regardless of deadline"
        );
    }

    /// A zone whose epoch role is known, found by seed search rather than by a
    /// test-only setter — the role must come from the same draw production
    /// uses, or the fixture would not exercise the real path.
    fn zone_with_role(fluffing: bool, rng: &mut SplitMix64) -> Zone {
        for _ in 0..10_000 {
            let z = Zone::new(DandelionParams::inherited(), 2, 0, rng);
            if z.is_fluffing() == fluffing {
                return z;
            }
        }
        panic!("no epoch with fluffing={fluffing} in 10k draws");
    }

    #[test]
    fn a_local_tx_stems_during_a_fluff_epoch_rd4() {
        // RD-4, and the test is shaped against the REVERSION, not the feature.
        // The inherited condition is `!fluffing || local`. Delete `|| local` —
        // which reads like a redundant clause on a fluff check — and a local
        // transaction fluffs instead of stemming, silently reverting the
        // correction that makes the adopted embargo 144 s instead of 31 s.
        //
        // So this asserts the stem-vs-fluff axis the reversion shows on. A test
        // that merely checked "the batch went somewhere" would pass on both
        // wirings: it goes somewhere either way. That is the mean-check trap in
        // the routing domain.
        let mut rng = SplitMix64::new(30);
        let mut z = zone_with_role(true, &mut rng);
        assert!(z.is_fluffing(), "fixture must be in a fluff epoch");
        let _ = z.update_stems(vec![id(1), id(2), id(3)], &mut rng);

        assert!(
            matches!(z.plan_relay(None, true, &mut rng), RelayPlan::Stem(_)),
            "RD-4: the origin stems even during a fluff epoch — if this fails, \
             check whether the `local_origin` arm was removed as redundant"
        );
    }

    #[test]
    fn a_relayed_tx_fluffs_during_a_fluff_epoch() {
        // The other half of the discriminator. Without this, the RD-4 test
        // above could pass on a zone that stems *everything* — which would also
        // be wrong, and in the other direction.
        let mut rng = SplitMix64::new(31);
        let mut z = zone_with_role(true, &mut rng);
        let _ = z.update_stems(vec![id(1), id(2), id(3)], &mut rng);

        assert_eq!(
            z.plan_relay(Some(id(7)), false, &mut rng),
            RelayPlan::FluffEpoch,
            "a relayed tx must fluff during a fluff epoch"
        );
    }

    #[test]
    fn everything_stems_during_a_stem_epoch() {
        let mut rng = SplitMix64::new(32);
        let mut z = zone_with_role(false, &mut rng);
        let _ = z.update_stems(vec![id(1), id(2), id(3)], &mut rng);

        assert!(matches!(
            z.plan_relay(Some(id(7)), false, &mut rng),
            RelayPlan::Stem(_)
        ));
        assert!(matches!(
            z.plan_relay(None, true, &mut rng),
            RelayPlan::Stem(_)
        ));
    }

    #[test]
    fn no_routable_slot_reports_no_route_not_a_fluff_epoch() {
        // The discriminator between the two non-stem outcomes, and the reason
        // `RelayPlan` is three-way rather than a bool. Both mean "did not
        // stem", and a caller that cannot tell them apart gets two things
        // wrong: it retries an epoch decision that refreshing cannot change,
        // and it emits the wrong `relay_method` event — the inherited code
        // reports `stem` for an unroutable stem-epoch transaction, because it
        // entered the stem branch before discovering there was nowhere to send.
        let mut rng = SplitMix64::new(33);
        let mut z = zone_with_role(false, &mut rng);
        assert_eq!(
            z.plan_relay(None, true, &mut rng),
            RelayPlan::NoRoute,
            "a stem epoch with no slots is unroutable, not a fluff epoch"
        );

        // And the converse, so the two are pinned apart from both sides: a
        // fluff epoch reports `FluffEpoch` even with slots available, which is
        // the case where a retry would be wasted work.
        let mut z = zone_with_role(true, &mut rng);
        let _ = z.update_stems(vec![id(1), id(2), id(3)], &mut rng);
        assert_eq!(
            z.plan_relay(Some(id(7)), false, &mut rng),
            RelayPlan::FluffEpoch,
            "a routable fluff epoch is settled, not merely unroutable"
        );
    }

    #[test]
    fn a_source_pins_to_one_stem_for_the_epoch() {
        let mut rng = SplitMix64::new(6);
        let mut z = zone(&mut rng);
        let _ = z.update_stems(vec![id(1), id(2), id(3), id(4)], &mut rng);

        let source = Some(id(9));
        let first = z.stem_for(source, &mut rng).expect("a stem is available");
        for _ in 0..32 {
            assert_eq!(z.stem_for(source, &mut rng), Some(first));
        }
    }
}
