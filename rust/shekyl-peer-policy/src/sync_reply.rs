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

/// Why the entry's refusal invalidates. An oversize announce closes the
/// session and leaves the header. An oversize solicited body also
/// invalidates the header it was bound to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invalidate {
    /// The body matched its header, and the block was refused.
    Refused,
    /// A promotion of an already-stored block was refused.
    PromotionRefused,
    /// Larger than any valid block.
    Oversize {
        /// Whether the header the body was bound to is invalid.
        invalidate_header: bool,
    },
}

/// What the sync model does. `severs` is true only for a refusal of the
/// block, or an oversize body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncReplyAction {
    /// Advance along the chain. Whether the block is relayed is the sync
    /// model's, from its state and the height the block took, whichever
    /// path the block came by.
    Advance,
    /// Close the supplier. The payload says whether the header is invalid.
    Invalidate(Invalidate),
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
            Self::Connected => SyncReplyAction::Advance,
            Self::Refused => SyncReplyAction::Invalidate(Invalidate::Refused),
            Self::PromotionRefused => SyncReplyAction::Invalidate(Invalidate::PromotionRefused),
            Self::Oversize => SyncReplyAction::Invalidate(Invalidate::Oversize {
                invalidate_header: solicited,
            }),
            Self::Unlinked => SyncReplyAction::Relocate,
            Self::BeyondCap => SyncReplyAction::RequestHeaders,
            Self::MissingBodies => SyncReplyAction::RequestMissing,
            Self::Cancelled | Self::Stopped => SyncReplyAction::Again,
            Self::NoRoom => SyncReplyAction::Hold,
            Self::Throttled => SyncReplyAction::DropUnverified,
            // Already held, stored beside the incumbent, switched, or a
            // heavier chain this node cannot follow. The header stays.
            // The new tip, or the latch, arrives on its own.
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
            matches!(self, Self::Invalidate(_))
        }
    }

    #[test]
    fn a_connected_block_advances_however_it_arrived() {
        assert_eq!(SyncReply::Connected.action(false), SyncReplyAction::Advance);
        assert_eq!(SyncReply::Connected.action(true), SyncReplyAction::Advance);
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
    fn an_oversize_solicited_body_invalidates_the_header_and_an_announce_does_not() {
        assert_eq!(
            SyncReply::Oversize.action(true),
            SyncReplyAction::Invalidate(Invalidate::Oversize {
                invalidate_header: true,
            })
        );
        assert_eq!(
            SyncReply::Oversize.action(false),
            SyncReplyAction::Invalidate(Invalidate::Oversize {
                invalidate_header: false,
            })
        );
        assert!(SyncReply::Oversize.severs());
    }

    #[test]
    fn a_missed_deadline_is_not_an_entry_outcome() {
        // The deadline is the model's, not the entry's. No reply severs
        // for being late: throttled keeps the session, cancelled retries.
        assert!(!SyncReply::Throttled.severs());
        assert_eq!(SyncReply::Cancelled.action(true), SyncReplyAction::Again);
    }
}
