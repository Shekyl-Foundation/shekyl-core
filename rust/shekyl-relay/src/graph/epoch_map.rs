// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Which stem map an epoch holds.
//!
//! [`EpochMap::Uniform`] is the paper's map. [`EpochMap::Reserved`] keeps
//! slot 0 for the class the relay names. The variant is the only record of
//! that choice. A flag beside an untyped map can name a merge the map does
//! not have.

use shekyl_relay_privacy::rng::RelayRng;
use shekyl_relay_privacy::stem_map::{
    ConnectionId, ReservedSlot, SlotIndex, SourceId, StemMap, UniformSlots,
};

/// The epoch's stem map.
#[derive(Debug)]
pub(super) enum EpochMap {
    /// Every slot draws from the same live set.
    Uniform(StemMap<UniformSlots>),
    /// Slot 0 draws from the class the relay names.
    Reserved(StemMap<ReservedSlot>),
}

impl EpochMap {
    /// A uniform map over `outbound`, width `stems`.
    pub(super) fn uniform<R: RelayRng + ?Sized>(
        outbound: Vec<ConnectionId>,
        stems: usize,
        rng: &mut R,
    ) -> Self {
        Self::Uniform(StemMap::new(outbound, stems, rng))
    }

    /// A map whose slot 0 is reserved for `class`.
    pub(super) fn reserved<R: RelayRng + ?Sized>(
        class: Vec<ConnectionId>,
        rest: Vec<ConnectionId>,
        stems: usize,
        rng: &mut R,
    ) -> Self {
        Self::Reserved(StemMap::new_with_reserved_slot(class, rest, stems, rng))
    }

    /// Slot 0 is reserved for a class the relay names.
    #[must_use]
    pub(super) fn reserves_slot(&self) -> bool {
        matches!(self, Self::Reserved(_))
    }

    /// The stem slots in index order.
    #[must_use]
    pub(super) fn slots(&self) -> &[Option<ConnectionId>] {
        match self {
            Self::Uniform(map) => map.slots(),
            Self::Reserved(map) => map.slots(),
        }
    }

    /// Stem slots backed by a live peer.
    #[must_use]
    pub(super) fn live_stems(&self) -> usize {
        match self {
            Self::Uniform(map) => map.live_stems(),
            Self::Reserved(map) => map.live_stems(),
        }
    }

    /// Per-slot source counts.
    #[must_use]
    pub(super) fn usage(&self) -> &[usize] {
        match self {
            Self::Uniform(map) => map.usage(),
            Self::Reserved(map) => map.usage(),
        }
    }

    /// The slot currently holding `peer`, if any.
    #[must_use]
    pub(super) fn slot_of(&self, peer: ConnectionId) -> Option<SlotIndex> {
        match self {
            Self::Uniform(map) => map.slot_of(peer),
            Self::Reserved(map) => map.slot_of(peer),
        }
    }

    /// The stem peer for `source`, assigning one on the first call this epoch.
    pub(super) fn stem_for<R: RelayRng + ?Sized>(
        &mut self,
        source: SourceId,
        rng: &mut R,
    ) -> Option<ConnectionId> {
        match self {
            Self::Uniform(map) => map.stem_for(source, rng),
            Self::Reserved(map) => map.stem_for(source, rng),
        }
    }

    /// Merge the live outbound partition. A uniform epoch draws every slot
    /// from the whole set. A reserved epoch gives slot 0 the class and the
    /// other slots the whole set. The variant is the mode, so each arm calls
    /// the merge that exists on that map.
    ///
    /// `StemSetChange` stays on the map for its own tests. Nothing in the
    /// zone re-points on it, so the bind is named and dropped.
    pub(super) fn merge_outbound<R: RelayRng + ?Sized>(
        &mut self,
        class: Vec<ConnectionId>,
        rest: Vec<ConnectionId>,
        rng: &mut R,
    ) {
        match self {
            Self::Uniform(map) => {
                let mut all = class;
                all.extend(rest);
                let _change = map.update(all, rng);
            }
            Self::Reserved(map) => {
                let _change = map.update_with_reserved(class, rest, rng);
            }
        }
    }

    /// The hidden origin's route. A uniform epoch has none, and answers
    /// `None`: the caller sends nothing rather than stemming onto a clear
    /// link.
    #[must_use]
    pub(super) fn route_local_origin<R: RelayRng + ?Sized>(
        &mut self,
        class: &[ConnectionId],
        rest: &[ConnectionId],
        rng: &mut R,
    ) -> Option<ConnectionId> {
        match self {
            Self::Reserved(map) => map.route_local_origin(class, rest, rng),
            Self::Uniform(_) => None,
        }
    }
}
