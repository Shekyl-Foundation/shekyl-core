// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The hidden stem slot (`DAEMON_RELAY_PRIVACY.md` §95.3, §98).
//!
//! When a configured connector hides this node's address from the peer, the
//! epoch's map is [`super::epoch_map::EpochMap::Reserved`]. Slot 0 is
//! reserved for the outbound sessions whose declaration says so, and a local
//! origin's first hop is that map's route over the class. This module names
//! the class. It does not sequence the fill and the walk.
//!
//! Peers are never moved between slots (§20.3). When slot 0 is empty and
//! every address-hiding session already occupies another slot, the route's
//! merge does not run, and the origin pins on one of them where it sits.
//!
//! No connector is named here. The class is `address_hidden_from_peer` on
//! each session's declaration. A class of one still reports `hop-0 edge
//! cannot rotate` at each rebuild. No cover on Tor by ruling: the plan kind
//! stays [`RelayPlan::OwnEdge`], one ordinary send, terminal on write
//! failure, so a failed hidden write is never fluffed on a clear link.

use shekyl_relay_privacy::rng::RelayRng;
use shekyl_relay_privacy::stem_map::ConnectionId;

use super::epoch_map::EpochMap;
use super::{hides_address, Relay, RelayPlan};

impl Relay {
    /// Outbound stem candidates split by the declaration cell: sessions
    /// whose peer does not learn this node's address, then the rest. Both in
    /// connection-id order. Their union is the outbound stem-candidate set.
    pub(super) fn partitioned_outbound_ids(&self) -> (Vec<ConnectionId>, Vec<ConnectionId>) {
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
    pub(super) fn reserved_stem_map<R: RelayRng + ?Sized>(&self, rng: &mut R) -> EpochMap {
        let (hidden, rest) = self.partitioned_outbound_ids();
        if hidden.len() == 1 {
            tracing::error!(
                "hop-0 edge cannot rotate: one outbound connection hides this node's address, so every transaction this node originates uses that connection until another such peer connects"
            );
        }
        EpochMap::reserved(hidden, rest, self.stems, rng)
    }

    /// Plan a local origin's first hop over the hidden stem slot.
    ///
    /// The map fills slot 0 before it walks the pin, and only when that fill
    /// would change the slot. `None` is [`RelayPlan::NoOwnEdge`]: the caller
    /// sends nothing, records nothing, and does not refresh the stem map. A
    /// refresh cannot manufacture a session that hides this node's address,
    /// and falling through to fluff would publish the origin on a clear link.
    pub(super) fn hidden_slot_plan<R: RelayRng + ?Sized>(&mut self, rng: &mut R) -> RelayPlan {
        let (hidden, rest) = self.partitioned_outbound_ids();
        match self.map.route_local_origin(&hidden, &rest, rng) {
            Some(destination) => RelayPlan::OwnEdge(destination),
            None => RelayPlan::NoOwnEdge,
        }
    }
}
