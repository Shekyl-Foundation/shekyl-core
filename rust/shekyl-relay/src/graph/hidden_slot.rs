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
//! each session's declaration. Its size is reported to the operator when it
//! changes between empty, one and several ([`HiddenClass`]): empty and one
//! are degraded states and are warned, a return to several is noted. No cover on
//! Tor by ruling: the plan kind
//! stays [`RelayPlan::OwnEdge`], one ordinary send, terminal on write
//! failure, so a failed hidden write is never fluffed on a clear link.

use shekyl_draw_rng::RelayRng;
use shekyl_relay_privacy::stem_map::ConnectionId;

use super::epoch_map::EpochMap;
use super::{hides_address, Relay, RelayPlan};

/// How many outbound sessions hide this node's address, in the three states
/// the operator is told about.
///
/// The count itself is not reported: between two and the dialer's target the
/// node's own transactions rotate over the class as designed, and a log line
/// per session would say nothing an operator can act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HiddenClass {
    /// No such session. Every transaction this node originates is held
    /// ([`RelayPlan::NoOwnEdge`]) until one connects.
    Empty,
    /// One session. Every transaction this node originates uses it.
    One,
    /// Two or more. The hop-0 edge rotates over them.
    Several,
}

impl HiddenClass {
    fn of(sessions: usize) -> Self {
        match sessions {
            0 => Self::Empty,
            1 => Self::One,
            _ => Self::Several,
        }
    }
}

/// Whether the class just observed is reported, and from which state.
///
/// `reported` is the class last reported, `None` before the first report.
/// The first report waits for the first epoch rebuild (`at_rebuild`): the
/// dialer opens its sessions in the first seconds after start, and a report
/// made then would describe that order rather than the node's state. After
/// the first, a report is made on every change and on nothing else.
pub(crate) fn hidden_class_report(
    reported: Option<HiddenClass>,
    observed: HiddenClass,
    at_rebuild: bool,
) -> Option<HiddenClass> {
    match reported {
        None if !at_rebuild => None,
        Some(previous) if previous == observed => None,
        _ => Some(observed),
    }
}

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

    /// How many outbound stem candidates hide this node's address: the
    /// length of [`Relay::partitioned_outbound_ids`]'s first half, counted
    /// without building either list.
    pub(super) fn hidden_outbound_count(&self) -> usize {
        self.contexts
            .values()
            .filter(|peer| Self::stem_candidate(peer) && hides_address(&peer.declaration))
            .count()
    }

    /// The epoch's stem map under a hidden connector: slot 0 reserved for
    /// the address-hiding sessions. The body of [`Relay::rebuild_stems`] on
    /// that path.
    pub(super) fn reserved_stem_map<R: RelayRng + ?Sized>(&mut self, rng: &mut R) -> EpochMap {
        let (hidden, rest) = self.partitioned_outbound_ids();
        self.observe_hidden_class(hidden.len(), true);
        EpochMap::reserved(hidden, rest, self.stems, rng)
    }

    /// Record the hidden class's size after a change to the session set or
    /// at an epoch rebuild, and tell the operator when its state changes.
    ///
    /// A uniform map (no configured connector hides the address) has no
    /// class and reports nothing.
    pub(super) fn observe_hidden_class(&mut self, sessions: usize, at_rebuild: bool) {
        if !self.map.reserves_slot() {
            return;
        }
        let observed = HiddenClass::of(sessions);
        let Some(class) = hidden_class_report(self.hidden_class, observed, at_rebuild) else {
            return;
        };
        let recovered = self.hidden_class.is_some();
        self.hidden_class = Some(class);
        match class {
            HiddenClass::Empty => tracing::warn!(
                "no outbound connection hides this node's address, so every transaction this node originates is held until one connects"
            ),
            HiddenClass::One => tracing::warn!(
                "hop-0 edge cannot rotate: one outbound connection hides this node's address, so every transaction this node originates uses that connection until another such peer connects"
            ),
            HiddenClass::Several if recovered => tracing::info!(
                "hop-0 edge rotates again: {sessions} outbound connections hide this node's address"
            ),
            HiddenClass::Several => {}
        }
    }

    /// The hidden class as last reported to the operator, `None` before the
    /// first report.
    #[cfg(test)]
    pub(crate) fn reported_hidden_class(&self) -> Option<HiddenClass> {
        self.hidden_class
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
