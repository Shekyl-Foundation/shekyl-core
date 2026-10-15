// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The fill rule (R1, Rick, 2026-10-12; dialer brief, "The fill").
//!
//! Each wake, for one connector, the dialer takes the first of four rules
//! that applies. [`plan`] is that choice as a pure function of what the
//! dialer can count, so each rule's condition is tested without a socket.
//!
//! The rule decides the list and the aim. It does not pick the address:
//! the draw is the peer lists', uniform over the candidates.

/// The most dials one connector has in flight at once.
///
/// **Assumption** (`DAEMON_RELAY_PRIVACY.md` §97): the interim bound, one
/// dial per connector (2026-10-08). The fill is one dial per wake, so the
/// interim needs no measurement. It is measured and raised on the Rust
/// path after the cutover.
pub const IN_FLIGHT_BOUND: usize = 1;

/// What a dial is for. The aim is input; the outcome is what the dial
/// became. The handshake owner does not infer one from the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialAim {
    /// Keep the session if the strand accepts the payload.
    Keep,
    /// Confirm the address and close in that turn. The row does not count
    /// toward the outbound target and the relay is not flipped.
    Confirm,
}

/// Which list the draw is from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrawList {
    /// A re-contact of a white address this node is not connected to.
    White,
    /// An unconfirmed address.
    Gray,
}

/// Which of the four rules chose the dial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FillRule {
    /// (a) No kept outbound session on the connector: the next success is
    /// kept, whatever the draw.
    NoKeptSession,
    /// (b) One or more kept sessions and under the target: keep from a
    /// list that holds at least the floor.
    UnderTarget,
    /// (c) White is below the refill line and gray holds a drawable
    /// address: confirm-and-close from gray.
    Refill,
    /// (d) Under target with gray empty: keep from white.
    GrayEmpty,
}

/// What the dialer counts on one connector before a wake's choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Census {
    /// The dialer's `Keep` count: adopted `Keep` rows plus pending `Keep`
    /// attempts. Not the board's outbound count, which includes a
    /// `Confirm` row and knows nothing of a pending attempt.
    pub kept: usize,
    /// Dials in flight on this connector, of either aim.
    pub in_flight: usize,
    /// The connector's outbound target.
    pub target: usize,
    /// White addresses, after expiry and ban demotion. The floor and the
    /// refill line are read against this.
    pub white: usize,
    /// White addresses the draw may return: they pass the candidate
    /// filter and are neither an outbound session nor a pending attempt.
    pub white_candidates: usize,
    /// Drawable gray addresses. The floor is read against this.
    pub gray: usize,
    /// Gray addresses the draw may return, as for white.
    pub gray_candidates: usize,
}

/// One wake's choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    /// The rule that applied.
    pub rule: FillRule,
    /// The list to draw from.
    pub list: DrawList,
    /// What the dial is for.
    pub aim: DialAim,
}

/// The first fill rule that applies, or `None` when this wake dials
/// nothing.
///
/// `floor` is the white diversity floor and `refill_line` the refill
/// line; both are `shekyl-peerlist`'s.
///
/// A list "holds at least the floor" by its size, and is drawn only when
/// it has a candidate. A white list at the floor whose every address is
/// already a session offers nothing to draw, so the rule moves on to
/// gray; it never re-dials a live white peer.
///
/// A target of zero dials nothing, by any rule. `--out-peers 0` is a
/// legal cap, and an operator who sets it asked for no outbound sessions;
/// a confirm-and-close dial under (c) is still an outbound connection.
#[must_use]
pub fn plan(census: &Census, floor: usize, refill_line: usize) -> Option<Plan> {
    if census.target == 0 || census.in_flight >= IN_FLIGHT_BOUND {
        return None;
    }
    let white_at_floor = census.white >= floor && census.white_candidates > 0;
    let gray_at_floor = census.gray >= floor && census.gray_candidates > 0;
    let keep = |rule, list| {
        Some(Plan {
            rule,
            list,
            aim: DialAim::Keep,
        })
    };

    // (a) The draw is (b)'s; when neither list reaches the floor, gray if
    // it holds a drawable address, otherwise white. Kept either way.
    if census.kept == 0 {
        let list = if white_at_floor {
            DrawList::White
        } else if gray_at_floor || census.gray_candidates > 0 {
            DrawList::Gray
        } else if census.white_candidates > 0 {
            DrawList::White
        } else {
            return None;
        };
        return keep(FillRule::NoKeptSession, list);
    }

    let under_target = census.kept < census.target;

    // (b)
    if under_target {
        if white_at_floor {
            return keep(FillRule::UnderTarget, DrawList::White);
        }
        if gray_at_floor {
            return keep(FillRule::UnderTarget, DrawList::Gray);
        }
    }

    // (c) Reached under target when no floor admits a keep, and at target.
    if census.white < refill_line && census.gray_candidates > 0 {
        return Some(Plan {
            rule: FillRule::Refill,
            list: DrawList::Gray,
            aim: DialAim::Confirm,
        });
    }

    // (d) A network smaller than the floor: genesis, a private testnet.
    if under_target && census.gray_candidates == 0 && census.white_candidates > 0 {
        return keep(FillRule::GrayEmpty, DrawList::White);
    }

    None
}
