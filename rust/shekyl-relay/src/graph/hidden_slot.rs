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
//! each session's declaration. [`HiddenClassWatch`] records it. The watch
//! arms at the first epoch rebuild and thereafter reports a change of
//! [`HiddenClass`]. The notice names the class. It does not name the origin
//! pin: a pin whose frozen set is exhausted stays [`RelayPlan::NoOwnEdge`]
//! until the epoch ends. No cover on Tor by ruling: the plan kind stays
//! [`RelayPlan::OwnEdge`], one ordinary send, terminal on write failure, so
//! a failed hidden write is never fluffed on a clear link.

use shekyl_draw_rng::RelayRng;
use shekyl_relay_privacy::stem_map::ConnectionId;

use super::epoch_map::EpochMap;
use super::{hides_address, Relay, RelayPlan};

/// How many outbound sessions hide this node's address, in the three states
/// the operator is told about.
///
/// The count itself is not a state: between two and the dialer's target the
/// node's own transactions rotate over the class as designed, and a log line
/// per session would say nothing an operator can act on. A return to
/// [`HiddenClass::Several`] carries the count in its notice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HiddenClass {
    /// No such session.
    Empty,
    /// One session. The hop-0 edge cannot rotate over the class.
    One,
    /// Two or more. The hop-0 edge can rotate over the class.
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

/// A hidden class the operator is warned about.
///
/// [`HiddenClass::Several`] is not one of these: a rotating class is the
/// steady state, and the first time it is seen it is recorded in silence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DegradedHiddenClass {
    /// [`HiddenClass::Empty`].
    Empty,
    /// [`HiddenClass::One`].
    One,
}

impl DegradedHiddenClass {
    /// The warning for this degraded class.
    ///
    /// The words name the sessions that exist. They do not say when a held
    /// origin will leave, and they do not say which session an origin pin
    /// is using. An exhausted pin stays [`RelayPlan::NoOwnEdge`] until the
    /// epoch ends, whatever this class does meanwhile (§98.5).
    fn warning(self) -> &'static str {
        match self {
            Self::Empty => {
                "no outbound connection hides this node's address, so a transaction this node originates has no address-hiding session to leave on"
            }
            Self::One => {
                "hop-0 edge cannot rotate: one outbound connection hides this node's address"
            }
        }
    }
}

/// What the operator is told when the watch records a class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HiddenClassNotice {
    /// The first rebuild found [`HiddenClass::Several`]. Record it. No line.
    Quiet,
    /// The class is degraded. A warning.
    Warn(DegradedHiddenClass),
    /// A recorded class became [`HiddenClass::Several`]. `sessions` is the
    /// census, two or more. An info line. Not a claim that an origin pin
    /// resumed.
    Recovered { sessions: usize },
}

impl HiddenClassNotice {
    fn on_arm(observed: HiddenClass) -> Self {
        match observed {
            HiddenClass::Several => Self::Quiet,
            HiddenClass::Empty => Self::Warn(DegradedHiddenClass::Empty),
            HiddenClass::One => Self::Warn(DegradedHiddenClass::One),
        }
    }

    fn on_change(observed: HiddenClass, sessions: usize) -> Self {
        match observed {
            HiddenClass::Several => Self::Recovered { sessions },
            HiddenClass::Empty => Self::Warn(DegradedHiddenClass::Empty),
            HiddenClass::One => Self::Warn(DegradedHiddenClass::One),
        }
    }

    /// The log line for this notice, or `None` when the notice is
    /// [`HiddenClassNotice::Quiet`].
    pub(crate) fn line(self) -> Option<HiddenClassLine> {
        match self {
            Self::Quiet => None,
            Self::Warn(class) => Some(HiddenClassLine {
                level: HiddenClassLevel::Warn,
                text: class.warning().to_string(),
            }),
            Self::Recovered { sessions } => Some(HiddenClassLine {
                level: HiddenClassLevel::Info,
                text: format!("{sessions} outbound connections hide this node's address"),
            }),
        }
    }
}

/// Warn or info. The two levels this report uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HiddenClassLevel {
    Warn,
    Info,
}

/// One operator line: a level and the text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HiddenClassLine {
    pub(crate) level: HiddenClassLevel,
    pub(crate) text: String,
}

/// The hidden class as last recorded, or still waiting for the first epoch
/// rebuild.
///
/// The dialer opens its sessions in the first seconds after start. A report
/// made then would describe that order. [`HiddenClassWatch::note`] is a no-op
/// until [`HiddenClassWatch::arm`], which an epoch rebuild calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HiddenClassWatch {
    /// No class recorded. Session changes are not reported.
    BeforeRebuild,
    /// The class last recorded.
    Reported(HiddenClass),
}

impl HiddenClassWatch {
    /// A session was added or removed. No report before [`Self::arm`].
    ///
    /// `sessions` is the address-hiding outbound census after the change.
    pub(crate) fn note(&mut self, sessions: usize) -> Option<HiddenClassNotice> {
        let Self::Reported(previous) = *self else {
            return None;
        };
        self.changed(previous, sessions)
    }

    /// An epoch rebuild. The first call records the census and is the first
    /// report. Later calls report only a change since the recorded class.
    ///
    /// `sessions` is the address-hiding outbound census at the rebuild.
    pub(crate) fn arm(&mut self, sessions: usize) -> Option<HiddenClassNotice> {
        match *self {
            Self::BeforeRebuild => {
                let observed = HiddenClass::of(sessions);
                *self = Self::Reported(observed);
                Some(HiddenClassNotice::on_arm(observed))
            }
            Self::Reported(previous) => self.changed(previous, sessions),
        }
    }

    fn changed(&mut self, previous: HiddenClass, sessions: usize) -> Option<HiddenClassNotice> {
        let observed = HiddenClass::of(sessions);
        if observed == previous {
            return None;
        }
        *self = Self::Reported(observed);
        Some(HiddenClassNotice::on_change(observed, sessions))
    }

    #[cfg(test)]
    fn recorded(self) -> Option<HiddenClass> {
        match self {
            Self::BeforeRebuild => None,
            Self::Reported(class) => Some(class),
        }
    }
}

/// Which half of the outbound stem-candidate set a session belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutboundStem {
    /// The peer does not learn this node's address.
    AddressHidden,
    /// An outbound stem candidate that does not hide the address.
    Rest,
}

fn log_hidden_class(notice: HiddenClassNotice) {
    let Some(line) = notice.line() else {
        return;
    };
    match line.level {
        HiddenClassLevel::Warn => tracing::warn!("{}", line.text),
        HiddenClassLevel::Info => tracing::info!("{}", line.text),
    }
}

impl Relay {
    /// Outbound stem candidates, connection-id order, tagged by whether the
    /// peer hides this node's address.
    ///
    /// The partition and the class census both read this. A second walk of
    /// `stem_candidate` and `hides_address` would be a second definition of
    /// the class.
    fn outbound_stem_candidates(&self) -> impl Iterator<Item = (ConnectionId, OutboundStem)> + '_ {
        self.contexts.iter().filter_map(|(id, peer)| {
            if !Self::stem_candidate(peer) {
                return None;
            }
            let side = if hides_address(&peer.declaration) {
                OutboundStem::AddressHidden
            } else {
                OutboundStem::Rest
            };
            Some((*id, side))
        })
    }

    /// Outbound stem candidates split by the declaration cell: sessions
    /// whose peer does not learn this node's address, then the rest. Both in
    /// connection-id order. Their union is the outbound stem-candidate set.
    pub(super) fn partitioned_outbound_ids(&self) -> (Vec<ConnectionId>, Vec<ConnectionId>) {
        let mut hidden = Vec::new();
        let mut rest = Vec::new();
        for (id, side) in self.outbound_stem_candidates() {
            match side {
                OutboundStem::AddressHidden => hidden.push(id),
                OutboundStem::Rest => rest.push(id),
            }
        }
        (hidden, rest)
    }

    /// How many outbound stem candidates hide this node's address.
    ///
    /// The same census as [`Relay::partitioned_outbound_ids`]'s first half,
    /// counted from [`Relay::outbound_stem_candidates`] without building
    /// either list.
    fn hidden_session_count(&self) -> usize {
        self.outbound_stem_candidates()
            .filter(|(_, side)| *side == OutboundStem::AddressHidden)
            .count()
    }

    /// The epoch's stem map under a hidden connector: slot 0 reserved for
    /// the address-hiding sessions. The body of [`Relay::rebuild_stems`] on
    /// that path. The class report is not this map's job; the rebuild arms
    /// the watch beside it.
    pub(super) fn reserved_stem_map<R: RelayRng + ?Sized>(&self, rng: &mut R) -> EpochMap {
        let (hidden, rest) = self.partitioned_outbound_ids();
        EpochMap::reserved(hidden, rest, self.stems, rng)
    }

    /// Record the hidden class after a change to the session registry.
    ///
    /// A uniform map has no class. Before the first epoch rebuild the watch
    /// is unarmed and this reports nothing.
    pub(super) fn note_hidden_class(&mut self) {
        self.advance_hidden_class(HiddenClassWatch::note);
    }

    /// Arm the hidden class at an epoch rebuild.
    ///
    /// The first arm is the first report. A uniform map has no class.
    pub(super) fn arm_hidden_class(&mut self) {
        self.advance_hidden_class(HiddenClassWatch::arm);
    }

    fn advance_hidden_class(
        &mut self,
        advance: fn(&mut HiddenClassWatch, usize) -> Option<HiddenClassNotice>,
    ) {
        if !self.map.reserves_slot() {
            return;
        }
        let sessions = self.hidden_session_count();
        if let Some(notice) = advance(&mut self.hidden_class_watch, sessions) {
            log_hidden_class(notice);
        }
    }

    /// The hidden class as last recorded, `None` before the watch arms.
    #[cfg(test)]
    pub(crate) fn reported_hidden_class(&self) -> Option<HiddenClass> {
        self.hidden_class_watch.recorded()
    }

    /// The relay's hop-0 verdict for a local origin: whether a transaction
    /// this node originates leaves on an address-hiding session now.
    ///
    /// The fact `OwnTx` and Health project (`TOR_SUPERVISOR.md` posture
    /// table, `GS-Q3`): the class is non-empty and the epoch's origin pin is
    /// not exhausted. Read-only: nothing is merged, pinned or drawn. The
    /// link being usable is not this fact; a Tor whose link is up and whose
    /// first address-hiding peer has not handshaken reads `false`. A node
    /// with no address-hiding connector reads `false`. Exactness against
    /// the next plan:
    /// [`shekyl_relay_privacy::stem_map::StemMap::local_origin_routable`].
    #[must_use]
    pub fn originates_address_hiding(&self) -> bool {
        if !self.map.reserves_slot() {
            return false;
        }
        let (hidden, _rest) = self.partitioned_outbound_ids();
        self.map.local_origin_routable(&hidden)
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
