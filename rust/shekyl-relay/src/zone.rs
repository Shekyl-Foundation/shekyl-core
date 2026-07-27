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
use shekyl_relay_privacy::schedule::{EpochScheduler, Millis, PeerDirection};
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
    pub queued: Vec<Vec<u8>>,
    /// When the batch flushes. `None` means no batch is in flight.
    pub flush_at: Option<Millis>,
    /// Who dialed whom — the inherited code gives outbound peers half the
    /// inbound fluff delay, and [`shekyl_relay_privacy::schedule::FluffScheduler`]
    /// keeps that asymmetry.
    pub direction: PeerDirection,
}

impl PeerFluff {
    fn new(direction: PeerDirection) -> Self {
        Self {
            queued: Vec::new(),
            flush_at: None,
            direction,
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
