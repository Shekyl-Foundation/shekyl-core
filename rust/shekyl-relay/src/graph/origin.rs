// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The hop-0 verdict for a local origin (`GS-Q3`).
//!
//! Three states, because the class and the pin are not two independent
//! booleans. A local origin leaves only while an outbound session hides this
//! node's address, so [`OriginVerdict::Routable`] is that fact and the class
//! together. Health is every state but [`OriginVerdict::Absent`]. `OwnTx`
//! reads [`OriginVerdict::Routable`].
//!
//! The pin stays off health (`RPC_CHANNEL.md` §6.1). It moves when this
//! node's own-edge peers disconnect, and a peer who held `health` while being
//! the own edge would otherwise watch the boolean flip on its own disconnect.

/// Whether a local origin leaves on a session that hides this node's address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OriginVerdict {
    /// No outbound session hides this node's address, or the epoch does not
    /// reserve a slot.
    #[default]
    Absent,
    /// An outbound session hides this node's address, and a local origin
    /// does not leave on it.
    Connected,
    /// A local origin leaves on a session that hides this node's address.
    Routable,
}

impl OriginVerdict {
    /// An outbound session hides this node's address now.
    ///
    /// The `health` grant's boolean (`TSR-Q4`).
    #[must_use]
    pub const fn hides_address(self) -> bool {
        !matches!(self, Self::Absent)
    }

    /// A local origin leaves on such a session now.
    ///
    /// The relay fact `OwnTx` reads, under the `status` grant.
    #[must_use]
    pub const fn origin_leaves(self) -> bool {
        matches!(self, Self::Routable)
    }

    /// Why a [`crate::graph::RelayPlan::NoOwnEdge`] plan holds the origin.
    ///
    /// [`Self::Routable`] is not a hold. A plan that refuses an own edge
    /// while this verdict still says the origin leaves has disagreed with
    /// itself; the caller holds the origin and does not invent a cause.
    #[must_use]
    pub(crate) const fn origin_hold(self) -> Option<OriginHold> {
        match self {
            Self::Absent => Some(OriginHold::NoHidingSession),
            Self::Connected => Some(OriginHold::PinExhausted),
            Self::Routable => None,
        }
    }
}

/// Why this node's own transaction is held instead of sent.
///
/// The two states of a [`crate::graph::RelayPlan::NoOwnEdge`] plan.
/// [`OriginHold::NoHidingSession`] is [`OriginVerdict::Absent`]: nothing
/// hides this node's address. [`OriginHold::PinExhausted`] is
/// [`OriginVerdict::Connected`]: a hiding session is live, and this
/// origin's pin will not use it until the epoch ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OriginHold {
    /// No outbound session hides this node's address.
    NoHidingSession,
    /// A hiding session is live. This origin's route is exhausted for the epoch.
    PinExhausted,
}

impl OriginHold {
    /// The warning for this hold. The words name the verdict, so an
    /// exhausted pin is not reported as an empty class.
    #[must_use]
    pub(crate) const fn line(self) -> &'static str {
        match self {
            Self::NoHidingSession => {
                "this node's transaction is held: no outbound connection hides this node's address"
            }
            Self::PinExhausted => {
                "this node's transaction is held: an address-hiding session is up, and this origin's pin is exhausted until the epoch ends"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{OriginHold, OriginVerdict};

    #[test]
    fn a_hold_names_the_verdict_and_a_routable_origin_is_not_one() {
        assert_eq!(
            OriginVerdict::Absent.origin_hold(),
            Some(OriginHold::NoHidingSession)
        );
        assert_eq!(
            OriginVerdict::Connected.origin_hold(),
            Some(OriginHold::PinExhausted)
        );
        assert_eq!(OriginVerdict::Routable.origin_hold(), None);

        let empty = OriginHold::NoHidingSession.line();
        let exhausted = OriginHold::PinExhausted.line();
        assert!(empty.contains("no outbound connection hides this node's address"));
        assert!(
            !exhausted.contains("no outbound connection hides"),
            "an exhausted pin still has a hiding session"
        );
        assert!(exhausted.contains("pin is exhausted"));
    }
}
