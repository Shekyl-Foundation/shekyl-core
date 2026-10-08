// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The own-edge of a local origin whose address a peer must not learn.
//!
//! Relayed stems draw over every outbound session. This draw is the other
//! one: uniform over the hidden-address outbound sessions, and not a
//! stem-map slot. The pool's target size is
//! [`shekyl_relay_privacy::params::MIN_PROVISIONED_OUT_PEERS`]. A pool of
//! one still reports `hop-0 edge cannot rotate`. That report does not name
//! a target of 4. *Records-was: `HOP0_OUTBOUND_TARGET`.* No cover on Tor by
//! ruling. On a cover-bearing link the own-edge is a stem slot, drawn by
//! [`super::Relay::plan_relay`] when no configured connector hides the
//! address, and that slot is the channel.

use shekyl_relay_privacy::rng::{bounded_uniform, RelayRng};
use shekyl_relay_privacy::stem_map::ConnectionId;

use super::{hides_address, Relay, RelayPlan};

impl Relay {
    /// Draw or reuse this epoch's own-edge.
    ///
    /// A live edge is not re-pointed. A dead one is replaced from the pool
    /// that is still up. [`Relay::rebuild_stems`] clears the edge so the
    /// next epoch draws again. A pool of one is the same edge every epoch;
    /// that is reported, and the transaction still leaves. Empty is
    /// [`RelayPlan::NoOwnEdge`]: the caller sends nothing, records nothing,
    /// and does not refresh the stem map. Refreshing that map cannot
    /// manufacture an edge that hides this node's address, and falling
    /// through to fluff would publish the origin on a clear link.
    pub(super) fn own_edge<R: RelayRng + ?Sized>(&mut self, rng: &mut R) -> RelayPlan {
        if let Some(id) = self.hop0_edge {
            if self.hop0_peer_live(id) {
                return RelayPlan::OwnEdge(id);
            }
        }
        let pool = self.hidden_outbound_ids();
        if pool.is_empty() {
            self.hop0_edge = None;
            return RelayPlan::NoOwnEdge;
        }
        if pool.len() == 1 {
            tracing::error!(
                "hop-0 edge cannot rotate: one outbound connection hides this node's address, so every transaction this node originates uses that connection until another such peer connects"
            );
        }
        let index = usize::try_from(bounded_uniform(rng, (pool.len() - 1) as u64))
            .expect("the draw is bounded by the pool length");
        let edge = pool[index];
        self.hop0_edge = Some(edge);
        RelayPlan::OwnEdge(edge)
    }

    fn hop0_peer_live(&self, id: ConnectionId) -> bool {
        self.contexts
            .get(&id)
            .is_some_and(|peer| Self::stem_candidate(peer) && hides_address(&peer.declaration))
    }

    /// Hidden-address outbound sessions, in connection-id order.
    fn hidden_outbound_ids(&self) -> Vec<ConnectionId> {
        self.contexts
            .iter()
            .filter(|(_, peer)| Self::stem_candidate(peer) && hides_address(&peer.declaration))
            .map(|(id, _)| *id)
            .collect()
    }
}
