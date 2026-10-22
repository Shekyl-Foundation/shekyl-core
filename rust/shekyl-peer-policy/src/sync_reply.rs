// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What sync does with one entry outcome (CS-Q4, CS-2 §4.13).
//!
//! The entry's `Reply` lives in `shekyl-chain-ingest`, which this crate
//! does not depend on. CS-3 converts that reply into [`SyncReply`] with
//! an exhaustive match. Only a refusal of the block the header commits
//! to severs; everything else is our state, a hint, or a retry.

/// The entry's outcome, minus the types that crate would have to name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncReply {
    /// The block connected.
    Connected,
    /// The body matched its header, and the block was refused.
    Refused,
    /// A promotion of an already-stored block was refused.
    PromotionRefused,
    /// The parent chain reaches nothing this node holds.
    Unlinked,
    /// This node already holds it.
    AlreadyHeld,
    /// Stored beside the incumbent.
    Held,
    /// The chain switched. The new tip arrives on its own.
    Switched,
    /// The door's hint: deeper than the cap, nothing stored.
    BeyondCap,
    /// Ingest stored a heavier chain this node cannot follow.
    CannotFollow,
    /// An announced block is missing transactions.
    MissingBodies,
    /// The service cancelled the span.
    Cancelled,
    /// The service stopped.
    Stopped,
    /// The door had no room.
    NoRoom,
    /// An announce hit the unsolicited share. Local policy.
    Throttled,
    /// Larger than any valid block. The bound body makes that the block.
    Oversize,
}

/// What the sync model does. `severs` is true only for a refusal of the
/// block, or an oversize solicited body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncReplyAction {
    /// Advance along the chain. `relay` is an announce that connected.
    Advance {
        /// Whether to relay the block.
        relay: bool,
    },
    /// Mark the header and its subtree invalid, and close the supplier.
    Invalidate,
    /// Ask that session for headers from the missing parent.
    Relocate,
    /// A hint only: request headers. Never the alarm.
    RequestHeaders,
    /// An announce is short transactions.
    RequestMissing,
    /// Want the block again. Not a fault.
    Again,
    /// Hold the span until the door reports room.
    Hold,
    /// Drop an announce unverified. Keep the session.
    DropUnverified,
    /// Nothing to do. The new tip, or the latch, arrives separately.
    None,
}

impl SyncReply {
    /// `solicited` is a body this node requested. An oversize announce
    /// closes the session; an oversize solicited body also invalidates
    /// the header, because the body was bound to it.
    #[must_use]
    pub const fn action(self, solicited: bool) -> SyncReplyAction {
        match self {
            Self::Connected => SyncReplyAction::Advance { relay: !solicited },
            Self::Refused | Self::PromotionRefused | Self::Oversize => SyncReplyAction::Invalidate,
            Self::Unlinked => SyncReplyAction::Relocate,
            Self::BeyondCap => SyncReplyAction::RequestHeaders,
            Self::MissingBodies => SyncReplyAction::RequestMissing,
            Self::Cancelled | Self::Stopped => SyncReplyAction::Again,
            Self::NoRoom => SyncReplyAction::Hold,
            Self::Throttled => SyncReplyAction::DropUnverified,
            // Solicited or announced: the body was bound to the header,
            // or the announce is the block. Either way the header is invalid.
            Self::AlreadyHeld | Self::Held | Self::Switched | Self::CannotFollow => {
                SyncReplyAction::None
            }
        }
    }

    /// Whether this outcome severs the session. A refusal does. An
    /// oversize body does, solicited or announced. Nothing else does.
    #[must_use]
    pub const fn severs(self) -> bool {
        matches!(
            self,
            Self::Refused | Self::PromotionRefused | Self::Oversize
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPLIES: [SyncReply; 15] = [
        SyncReply::Connected,
        SyncReply::Refused,
        SyncReply::PromotionRefused,
        SyncReply::Unlinked,
        SyncReply::AlreadyHeld,
        SyncReply::Held,
        SyncReply::Switched,
        SyncReply::BeyondCap,
        SyncReply::CannotFollow,
        SyncReply::MissingBodies,
        SyncReply::Cancelled,
        SyncReply::Stopped,
        SyncReply::NoRoom,
        SyncReply::Throttled,
        SyncReply::Oversize,
    ];

    #[test]
    fn only_a_refusal_or_an_oversize_body_severs() {
        for reply in REPLIES {
            let severs = matches!(
                reply,
                SyncReply::Refused | SyncReply::PromotionRefused | SyncReply::Oversize
            );
            assert_eq!(reply.severs(), severs, "{reply:?}");
            assert_eq!(reply.action(true).severs_action(), severs, "{reply:?}");
        }
    }

    impl SyncReplyAction {
        const fn severs_action(self) -> bool {
            matches!(self, Self::Invalidate)
        }
    }

    #[test]
    fn a_connected_announce_is_relayed_and_a_solicited_one_is_not() {
        assert_eq!(
            SyncReply::Connected.action(false),
            SyncReplyAction::Advance { relay: true }
        );
        assert_eq!(
            SyncReply::Connected.action(true),
            SyncReplyAction::Advance { relay: false }
        );
    }

    #[test]
    fn beyond_cap_requests_headers_and_does_not_sever() {
        assert_eq!(
            SyncReply::BeyondCap.action(true),
            SyncReplyAction::RequestHeaders
        );
        assert!(!SyncReply::BeyondCap.severs());
    }

    #[test]
    fn a_missed_deadline_is_not_an_entry_outcome() {
        // The deadline is the model's, not the entry's. No reply severs
        // for being late: throttled keeps the session, cancelled retries.
        assert!(!SyncReply::Throttled.severs());
        assert_eq!(SyncReply::Cancelled.action(true), SyncReplyAction::Again);
    }
}
