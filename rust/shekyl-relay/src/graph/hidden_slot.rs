// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The hidden stem slot (`DAEMON_RELAY_PRIVACY.md` §95.3, §98).
//!
//! When a configured connector hides this node's address from the peer,
//! slot 0 of the stem map is **reserved** for the outbound sessions whose
//! declaration says so, and a local origin's first hop is a pin over those
//! sessions: slot 0's peer, then `stems − 1` alternates drawn uniformly from
//! the rest of them at the first origination of the epoch (D-PR1-1 (c′)).
//! The pin is walked as every other source's pin is (W3c); when the slot's
//! peer drops, the merge moves the live alternate into slot 0; once the pin
//! is exhausted the plan is [`RelayPlan::NoOwnEdge`] until the epoch ends.
//!
//! No connector is named here. The class is `address_hidden_from_peer`,
//! read off each session's declaration; the stem map never learns what the
//! class is (`StemMap::new_with_reserved_slot`, `update_with_reserved`).
//! The class's target size is
//! [`shekyl_relay_privacy::params::MIN_PROVISIONED_OUT_PEERS`]. A class of
//! one still reports `hop-0 edge cannot rotate` at each rebuild. No cover on
//! Tor by ruling: the plan kind stays [`RelayPlan::OwnEdge`], one ordinary
//! send, terminal on write failure, so a failed hidden write is never
//! fluffed on a clear link.

use shekyl_relay_privacy::rng::{bounded_uniform, RelayRng};
use shekyl_relay_privacy::stem_map::{ConnectionId, StemMap};

use super::{hides_address, Relay, RelayPlan};

impl Relay {
    /// Outbound stem candidates split by the declaration cell: sessions
    /// whose peer does not learn this node's address, then the rest. Both in
    /// connection-id order.
    fn partitioned_outbound_ids(&self) -> (Vec<ConnectionId>, Vec<ConnectionId>) {
        let mut hidden = Vec::new();
        let mut rest = Vec::new();
        for (id, peer) in &self.contexts {
            if !Self::stem_candidate(peer) {
                continue;
            }
            if hides_address(&peer.declaration) {
                hidden.push(*id);
            } else {
                rest.push(*id);
            }
        }
        (hidden, rest)
    }

    /// The epoch's stem map under a hidden connector: slot 0 reserved for
    /// the address-hiding sessions. The body of [`Relay::rebuild_stems`] on
    /// that path.
    pub(super) fn reserved_stem_map<R: RelayRng + ?Sized>(&self, rng: &mut R) -> StemMap {
        let (hidden, rest) = self.partitioned_outbound_ids();
        if hidden.len() == 1 {
            tracing::error!(
                "hop-0 edge cannot rotate: one outbound connection hides this node's address, so every transaction this node originates uses that connection until another such peer connects"
            );
        }
        StemMap::new_with_reserved_slot(hidden, rest, self.stems, rng)
    }

    /// The mid-epoch merge under a hidden connector. The body of
    /// [`Relay::update_stems`] on that path.
    pub(super) fn merge_reserved<R: RelayRng + ?Sized>(&mut self, rng: &mut R) {
        let (hidden, rest) = self.partitioned_outbound_ids();
        // Named bind: `StemSetChange` is `Copy + must_use`; nothing re-points
        // on push (§20.3), as in `update_stems`.
        let _change = self.map.update_with_reserved(hidden, rest, rng);
    }

    /// Plan a local origin's first hop over the hidden stem slot.
    ///
    /// A close does not merge ([`Relay::on_connection_close`]), so a slot 0
    /// whose peer is gone is merged here first: the hidden-slot fill is what
    /// moves the pin's live alternate into the slot before the pin is walked.
    /// An empty slot 0 with an address-hiding session up is merged for the
    /// same reason (rule 3: it fills at the next merge, not the next epoch).
    ///
    /// Then the pin. Unpinned this epoch: slot 0's peer and `stems − 1`
    /// alternates drawn uniformly from the other address-hiding sessions,
    /// frozen as supplied; an origination that finds slot 0 empty makes no
    /// pin and the next one may. Pinned: the walk, with the address-hiding
    /// sessions as the allowed set. `None` either way is
    /// [`RelayPlan::NoOwnEdge`]: the caller sends nothing, records nothing,
    /// and does not refresh the stem map — a refresh cannot manufacture a
    /// session that hides this node's address, and falling through to fluff
    /// would publish the origin on a clear link.
    pub(super) fn hidden_slot_plan<R: RelayRng + ?Sized>(&mut self, rng: &mut R) -> RelayPlan {
        let (hidden_live, _) = self.partitioned_outbound_ids();
        let slot0 = self.map.slots().first().copied().flatten();
        let needs_merge = match slot0 {
            Some(peer) => !self.contexts.contains_key(&peer),
            None => !hidden_live.is_empty(),
        };
        if needs_merge {
            self.merge_reserved(rng);
        }
        let chosen = if self.map.is_pinned(None) {
            self.map.stem_for_among(None, &hidden_live, rng)
        } else {
            let candidates = self.local_pin_candidates(&hidden_live, rng);
            self.map.pin_over(None, candidates)
        };
        match chosen {
            Some(destination) => RelayPlan::OwnEdge(destination),
            None => RelayPlan::NoOwnEdge,
        }
    }

    /// The local source's pin (D-PR1-1 (c′)): slot 0's peer first, then
    /// `stems − 1` alternates drawn uniformly — a partial Fisher-Yates, as
    /// `StemMap::new` draws — from the other address-hiding sessions live
    /// now. Empty when slot 0 is empty, so [`StemMap::pin_over`] pins
    /// nothing.
    fn local_pin_candidates<R: RelayRng + ?Sized>(
        &self,
        hidden_live: &[ConnectionId],
        rng: &mut R,
    ) -> Vec<ConnectionId> {
        let Some(primary) = self.map.slots().first().copied().flatten() else {
            return Vec::new();
        };
        let mut alternates: Vec<ConnectionId> = hidden_live
            .iter()
            .copied()
            .filter(|peer| *peer != primary)
            .collect();
        let take = self.stems.saturating_sub(1).min(alternates.len());
        for i in 0..take {
            let remaining = alternates.len() - i;
            let pick = i + usize::try_from(bounded_uniform(rng, (remaining - 1) as u64))
                .expect("the draw is bounded by the candidate count");
            alternates.swap(i, pick);
        }
        alternates.truncate(take);
        let mut candidates = Vec::with_capacity(1 + take);
        candidates.push(primary);
        candidates.extend(alternates);
        candidates
    }
}
