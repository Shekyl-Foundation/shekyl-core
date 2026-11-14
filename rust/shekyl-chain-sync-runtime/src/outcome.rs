// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! An entry reply, or a door refusal, as the model's [`Outcome`].

use shekyl_chain_ingest::service::{Refusal, Reply};
use shekyl_chain_sync::{Outcome, Proved};
use shekyl_peer_policy::{Invalidate, SyncReply, SyncReplyAction};
use shekyl_types::BlockHash;

/// A prove result's kind, for the trace.
pub(crate) fn proved_kind(proved: &Proved) -> &'static str {
    match proved {
        Proved::Formed(_) => "formed",
        Proved::Refused(_) => "refused",
    }
}

/// The outcome the model is told when the door refuses an offer of `bytes`.
///
/// No room waits for a seat. An unreadable store does not: the service
/// stops on that read, and a later seat report must not offer the body
/// again. A dry bucket is the session's, not the door's: the model takes
/// the seat back and asks for the body. A bound span is seated as
/// solicited and takes no token, so the door does not answer one
/// `Throttled`; the arm still maps that refusal, which the door's contract
/// names. A body larger than the door's bound invalidates its header when
/// this node asked for it, never when it was announced. A body within the
/// bound that the door still called oversize is offered again.
pub(crate) fn of_refusal(
    refusal: Refusal,
    solicited: bool,
    bytes: usize,
    max: Option<usize>,
) -> Outcome {
    match refusal {
        Refusal::NoRoom => Outcome::NoRoom,
        Refusal::Throttled => Outcome::Throttled,
        Refusal::StoreUnreadable => Outcome::StoreUnreadable,
        Refusal::Oversize if max.is_some_and(|max| bytes > max) => Outcome::Oversize {
            invalidate: solicited,
        },
        Refusal::Oversize => Outcome::Again,
    }
}

/// The entry's reply as the model's outcome.
///
/// [`SyncReply::action`] is the authority for what the reply means.
/// `solicited` is a body this node requested. A bound body is; an
/// announcement is not. `arrival` is the block the offer named, and it is
/// absent when that offer is already gone. A switch is a connect when
/// `arrival` is the promoted tip, and [`Outcome::Noted`] otherwise. A
/// promoted tip that is some other block has no supplier this offer can
/// name; the model relays it from the tip event.
pub(crate) fn of_reply(reply: Reply, solicited: bool, arrival: Option<BlockHash>) -> Outcome {
    let action = sync_reply(&reply).action(solicited);
    match (action, reply) {
        (SyncReplyAction::Advance, Reply::Connected { height, .. }) => {
            Outcome::Connected { height }
        }
        (SyncReplyAction::Invalidate(Invalidate::Refused), Reply::Refused(verdict)) => {
            Outcome::Refused { verdict }
        }
        (
            SyncReplyAction::Invalidate(Invalidate::PromotionRefused),
            Reply::PromotionRefused { hash, refused, .. },
        ) => Outcome::PromotionRefused {
            verdict: refused,
            block: hash,
        },
        (SyncReplyAction::Relocate, Reply::Unlinked { at }) => Outcome::Unlinked { at },
        (SyncReplyAction::RequestHeaders, Reply::BeyondCap(_)) => Outcome::BeyondCap,
        (SyncReplyAction::RequestMissing, Reply::MissingBodies { indices, .. }) => {
            Outcome::MissingBodies {
                indices: indices
                    .into_iter()
                    .map(|index| u64::try_from(index).unwrap_or(u64::MAX))
                    .collect(),
            }
        }
        (SyncReplyAction::Again, Reply::Cancelled { .. } | Reply::Stopped) => Outcome::Again,
        (
            SyncReplyAction::None,
            Reply::AlreadyHeld | Reply::Held { .. } | Reply::CannotFollow(_),
        ) => Outcome::Noted,
        // The promoted blocks ascend, so the last is main's new tip. It is
        // a connect only when that tip is the arrival this offer named.
        (SyncReplyAction::None, Reply::Switched { promoted, .. }) => {
            match (promoted.last(), arrival) {
                (Some(&(height, tip)), Some(arrival)) if tip == arrival => {
                    Outcome::Connected { height }
                }
                _ => Outcome::Noted,
            }
        }
        (action, reply) => {
            tracing::error!(?action, ?reply, "an entry reply and its action disagree");
            Outcome::Noted
        }
    }
}

/// The peer-policy name of an entry reply. Exhaustive, so a new reply
/// cannot arrive here unnamed.
fn sync_reply(reply: &Reply) -> SyncReply {
    match reply {
        Reply::Connected { .. } => SyncReply::Connected,
        Reply::Refused(_) => SyncReply::Refused,
        Reply::PromotionRefused { .. } => SyncReply::PromotionRefused,
        Reply::Unlinked { .. } => SyncReply::Unlinked,
        Reply::AlreadyHeld => SyncReply::AlreadyHeld,
        Reply::Held { .. } => SyncReply::Held,
        Reply::Switched { .. } => SyncReply::Switched,
        Reply::BeyondCap(_) => SyncReply::BeyondCap,
        Reply::CannotFollow(_) => SyncReply::CannotFollow,
        Reply::MissingBodies { .. } => SyncReply::MissingBodies,
        Reply::Cancelled { .. } => SyncReply::Cancelled,
        Reply::Stopped => SyncReply::Stopped,
    }
}
