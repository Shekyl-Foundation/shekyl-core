// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The local origin's route, as one decision and the commit of it.
//!
//! [`StemMap::local_origin_leaves`] answers whether a local origin leaves.
//! [`StemMap::route_local_origin`] commits that answer: the same merge, then
//! the same walk. A publish reads the decision, so it cannot get ahead of
//! the next plan.
//!
//! The origin's merge seats the pin's in-class candidates into open holes
//! before the uniform backfill, and holds the rest of the pin out of that
//! draw. A handshake merge does not. Preferring the origin's alternates on
//! every handshake would bias the stem slots.

use super::{
    assert_partition, remove_sorted, usize_from_u64, ConnectionId, RelayRng, ReservedSlot, StemMap,
    RESERVED_SLOT_INDEX,
};
use shekyl_draw_rng::bounded_uniform;

/// What [`StemMap::open_reserved_slots`] leaves for a fill.
///
/// `unslotted` is every live peer that occupies no slot. `class_open` is the
/// class members among them. Both are sorted. `existing_outs` is the slot
/// count after an empty map has grown its reserved cell and after a full map
/// of live peers has already returned.
pub(super) struct OpenSlots {
    /// A live peer left, or a nil slot was re-marked.
    pub(super) replaced: bool,
    /// `out.len()` at the moment the fill starts.
    pub(super) existing_outs: usize,
    /// Live peers that occupy no slot.
    pub(super) unslotted: Vec<ConnectionId>,
    /// Class members that occupy no slot.
    pub(super) class_open: Vec<ConnectionId>,
}

impl StemMap<ReservedSlot> {
    /// Release departed peers and report the holes, or `None` when the map
    /// has no slots or nothing to fill.
    ///
    /// The same prelude as a handshake merge. `class` and `rest` are the
    /// caller's partition; this sorts its own copies.
    pub(super) fn open_reserved_slots(
        &mut self,
        class: &[ConnectionId],
        rest: &[ConnectionId],
    ) -> Option<OpenSlots> {
        if self.usage.is_empty() {
            return None;
        }
        let mut class_open = sorted_ids(class);
        let mut unslotted = class_open.clone();
        unslotted.extend(rest);
        unslotted.sort_unstable();
        unslotted.dedup();

        let mut replaced = self.release_departed(&mut unslotted);
        class_open.retain(|peer| unslotted.binary_search(peer).is_ok());
        // The reserved cell exists even when nothing has filled it. A uniform
        // map grows from an empty `out` inside `backfill`; this one does not.
        if self.out.is_empty() {
            self.out.push(None);
            replaced = true;
        }
        if !replaced && self.out.len() == self.usage.len() {
            return None;
        }
        Some(OpenSlots {
            replaced,
            existing_outs: self.out.len(),
            unslotted,
            class_open,
        })
    }

    /// The local pin's next candidate, from its cursor, that is in `among`
    /// (sorted). `None` when the local source has no pin or none of its
    /// remaining candidates is there.
    pub(super) fn local_pin_next_among(&self, among: &[ConnectionId]) -> Option<ConnectionId> {
        let pin = self.inbound.get(&None)?;
        pin.candidates[pin.cursor..]
            .iter()
            .copied()
            .find(|candidate| among.binary_search(candidate).is_ok())
    }

    /// Whether a local origin leaves on `class`, read without routing.
    ///
    /// The decision [`Self::route_local_origin`] commits. Nothing on `self`
    /// is merged, pinned or drawn. An exhausted pin reads `false` until the
    /// epoch rebuilds the map. A map with no slots routes nothing.
    ///
    /// `class` and `rest` are the live partition. Membership is a sorted
    /// search; the caller's order is kept for the route's alternate draw.
    #[must_use]
    pub fn local_origin_leaves(&self, class: &[ConnectionId], rest: &[ConnectionId]) -> bool {
        let class = sorted_ids(class);
        let rest = sorted_ids(rest);
        self.leaves_from_partition(&class, &rest)
    }

    fn leaves_from_partition(&self, class: &[ConnectionId], rest: &[ConnectionId]) -> bool {
        assert_partition(class, rest);
        if self.usage.is_empty() {
            return false;
        }
        let mut projected = self.clone();
        if projected.origin_merge_due(class, rest, projected.is_pinned(None)) {
            projected.merge_origin_deterministic(class, rest);
        }
        projected.slotted_pin_in_class(class)
    }

    /// The local origin's one route. The merge runs before the pin walk, and
    /// the relay cannot call them in the other order.
    ///
    /// The merge runs when slot 0 needs its fill, or the local pin's current
    /// hop has left the class. It seats each later in-class pin candidate
    /// into an open hole, in pin order, and holds every still-unslotted pin
    /// candidate out of the uniform backfill, so the draw cannot put a peer
    /// in front of the walk after the decision was read. A handshake merge
    /// does neither.
    ///
    /// Unpinned: the primary is slot 0's peer when the class contains it,
    /// otherwise a class member occupying a later slot (uniform when several
    /// do). Then `stems − 1` alternates, drawn uniformly from the other class
    /// members live now. Pinned: the walk, and a chosen peer the class does
    /// not contain is not a route. `None` pins nothing.
    #[must_use]
    pub fn route_local_origin<R: RelayRng + ?Sized>(
        &mut self,
        class: &[ConnectionId],
        rest: &[ConnectionId],
        rng: &mut R,
    ) -> Option<ConnectionId> {
        assert_partition(class, rest);
        let class_sorted = sorted_ids(class);
        let rest_sorted = sorted_ids(rest);
        let leaves = self.leaves_from_partition(&class_sorted, &rest_sorted);
        let pinned = self.is_pinned(None);
        if self.origin_merge_due(&class_sorted, &rest_sorted, pinned) {
            self.merge_for_local_origin(class, rest, rng);
        }
        let hop = if pinned {
            let chosen = self.resolve_pin(None)?;
            class_sorted
                .binary_search(&chosen)
                .is_ok()
                .then_some(chosen)
        } else if leaves {
            let candidates = self.local_origin_candidates(class, &class_sorted, rng);
            self.pin_over(None, candidates)
        } else {
            None
        };
        debug_assert_eq!(hop.is_some(), leaves);
        hop
    }

    /// The origin route's merge. Slot 0 keeps the handshake's draw. Later
    /// holes take the pin's in-class candidates, in pin order, and what
    /// remains of the pin stays out of the uniform backfill.
    fn merge_for_local_origin<R: RelayRng + ?Sized>(
        &mut self,
        class: &[ConnectionId],
        rest: &[ConnectionId],
        rng: &mut R,
    ) {
        let Some(mut open) = self.open_reserved_slots(class, rest) else {
            return;
        };
        self.fill_reserved_slot(&mut open.class_open, &mut open.unslotted, rng);
        self.seat_pin_candidates(&mut open);
        self.withdraw_unseated_pin(&mut open.unslotted);
        self.backfill(RESERVED_SLOT_INDEX + 1, &mut open.unslotted, rng);
    }

    /// [`Self::merge_for_local_origin`] with slot 0 named instead of drawn.
    ///
    /// The walk does not depend on which class member a uniform draw would
    /// have placed: the pin's own next candidate is preferred by both, and a
    /// draw runs only when no remaining pin candidate is in the class.
    fn merge_origin_deterministic(&mut self, class: &[ConnectionId], rest: &[ConnectionId]) {
        let Some(mut open) = self.open_reserved_slots(class, rest) else {
            return;
        };
        self.place_slot_zero_named(&mut open);
        self.seat_pin_candidates(&mut open);
    }

    /// The peer an empty slot 0 takes when the route is only being read: the
    /// pin's next in-class candidate, else the first open class member.
    fn place_slot_zero_named(&mut self, open: &mut OpenSlots) {
        if self.out[RESERVED_SLOT_INDEX].is_some() {
            return;
        }
        let Some(peer) = self
            .local_pin_next_among(&open.class_open)
            .or_else(|| open.class_open.first().copied())
        else {
            return;
        };
        remove_sorted(&mut open.class_open, peer);
        remove_sorted(&mut open.unslotted, peer);
        self.out[RESERVED_SLOT_INDEX] = Some(peer);
    }

    /// Seat each remaining in-class pin candidate into the next open hole
    /// after slot 0, in pin order. A hole is filled and never skipped. A
    /// candidate the class does not contain is left for the walk to pass.
    fn seat_pin_candidates(&mut self, open: &mut OpenSlots) {
        let Some(pin) = self.inbound.get(&None) else {
            return;
        };
        let waiting: Vec<ConnectionId> = pin.candidates[pin.cursor..]
            .iter()
            .copied()
            .filter(|peer| open.class_open.binary_search(peer).is_ok())
            .collect();
        for peer in waiting {
            if !self.place_in_later_hole(peer) {
                break;
            }
            remove_sorted(&mut open.unslotted, peer);
            remove_sorted(&mut open.class_open, peer);
        }
    }

    /// Place `peer` in the first open slot after slot 0. `out` grows only
    /// into the next index, so a gap is filled and never skipped.
    fn place_in_later_hole(&mut self, peer: ConnectionId) -> bool {
        let first_later = RESERVED_SLOT_INDEX + 1;
        for index in first_later..self.usage.len() {
            if self.out.len() == index {
                self.out.push(Some(peer));
                return true;
            }
            if self.out[index].is_none() {
                self.out[index] = Some(peer);
                return true;
            }
        }
        false
    }

    /// Take every still-unslotted pin candidate out of the backfill pool.
    ///
    /// The walk is pin order, not slot order. A candidate the class does not
    /// contain, slotted into a spare hole, would stand in front of an
    /// in-class candidate the route had already decided to use.
    fn withdraw_unseated_pin(&self, unslotted: &mut Vec<ConnectionId>) {
        let Some(pin) = self.inbound.get(&None) else {
            return;
        };
        for candidate in &pin.candidates[pin.cursor..] {
            remove_sorted(unslotted, *candidate);
        }
    }

    /// The hop the walk would return, and whether the class contains it.
    ///
    /// Pinned: the first candidate from the cursor that occupies a slot.
    /// Unpinned: whether any slot holds a class member. The cursor does not
    /// move.
    fn slotted_pin_in_class(&self, class: &[ConnectionId]) -> bool {
        if let Some(pin) = self.inbound.get(&None) {
            for candidate in &pin.candidates[pin.cursor..] {
                if self.slot_of(*candidate).is_some() {
                    return class.binary_search(candidate).is_ok();
                }
            }
            return false;
        }
        self.out
            .iter()
            .flatten()
            .any(|peer| class.binary_search(peer).is_ok())
    }

    /// Slot 0 needs its fill, or this route is about to walk a hop that has
    /// left the class. `class` and `rest` are sorted. Captured `pinned` is
    /// the state from before the merge.
    fn origin_merge_due(
        &self,
        class: &[ConnectionId],
        rest: &[ConnectionId],
        pinned: bool,
    ) -> bool {
        self.slot_zero_needs_fill(class, rest) || (pinned && self.pinned_hop_has_left(class))
    }

    /// The local pin's current hop is absent from `class` (sorted).
    ///
    /// No pin, or a cursor past the frozen list, is not this case: there is
    /// no hop to release. A hop still in the class is not this case either.
    fn pinned_hop_has_left(&self, class: &[ConnectionId]) -> bool {
        let Some(pin) = self.inbound.get(&None) else {
            return false;
        };
        match pin.candidates.get(pin.cursor) {
            Some(hop) => class.binary_search(hop).is_err(),
            None => false,
        }
    }

    /// Slot 0's peer has left the live partition, or the slot is empty and a
    /// class member is still unslotted. `class` and `rest` are sorted.
    fn slot_zero_needs_fill(&self, class: &[ConnectionId], rest: &[ConnectionId]) -> bool {
        match self.out.get(RESERVED_SLOT_INDEX).copied().flatten() {
            Some(peer) => class.binary_search(&peer).is_err() && rest.binary_search(&peer).is_err(),
            None => class.iter().any(|peer| self.slot_of(*peer).is_none()),
        }
    }

    /// The local source's pin: primary, then `stems − 1` alternates drawn by
    /// the same partial Fisher-Yates as [`StemMap::new`].
    ///
    /// Slot 0's peer is the primary only when the class contains it. A peer
    /// sitting there from outside the class is not an origin hop; the draw
    /// falls through to class members in later slots. Empty when no slot
    /// holds a class member, so [`StemMap::pin_over`] pins nothing.
    /// `class_live` keeps the caller's order for the draw. `class_sorted` is
    /// that set, sorted, for membership.
    fn local_origin_candidates<R: RelayRng + ?Sized>(
        &self,
        class_live: &[ConnectionId],
        class_sorted: &[ConnectionId],
        rng: &mut R,
    ) -> Vec<ConnectionId> {
        let primary = match self.out.get(RESERVED_SLOT_INDEX).copied().flatten() {
            Some(peer) if class_sorted.binary_search(&peer).is_ok() => peer,
            _ => {
                let slotted: Vec<ConnectionId> = self
                    .out
                    .iter()
                    .skip(RESERVED_SLOT_INDEX + 1)
                    .flatten()
                    .copied()
                    .filter(|peer| class_sorted.binary_search(peer).is_ok())
                    .collect();
                match slotted.len() {
                    0 => return Vec::new(),
                    1 => slotted[0],
                    n => slotted[usize_from_u64(bounded_uniform(rng, (n - 1) as u64))],
                }
            }
        };
        let mut alternates: Vec<ConnectionId> = class_live
            .iter()
            .copied()
            .filter(|peer| *peer != primary)
            .collect();
        let take = self.usage.len().saturating_sub(1).min(alternates.len());
        super::partial_shuffle(&mut alternates, take, rng);
        let mut candidates = Vec::with_capacity(1 + take);
        candidates.push(primary);
        candidates.extend(alternates);
        candidates
    }
}

/// `peers` as a sorted set. Membership searches this; a draw keeps the
/// caller's order, which the shuffle consumes.
fn sorted_ids(peers: &[ConnectionId]) -> Vec<ConnectionId> {
    let mut owned = peers.to_vec();
    owned.sort_unstable();
    owned.dedup();
    owned
}
