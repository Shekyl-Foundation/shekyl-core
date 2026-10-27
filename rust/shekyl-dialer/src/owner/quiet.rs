// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The quiet stretch (Rick, 2026-10-26; counted as evidence, 2026-10-27):
//! while a connector holds no session, its last K attempts all ended
//! without opening a stream, and at least S has passed since one last
//! opened there, a failed test cools at the first step and does not climb.
//! K and S are the connector's dial profile's quiet threshold, derived from
//! its measured failure rate on the floor device, so the guard switches on
//! once the evidence is in on each connector: 10 attempts and 29.15 s on
//! clearnet, 13 attempts and 364.5 s on Tor.
//!
//! The condition is the dialer's own evidence, read when a test cools. On
//! a link that carries nothing every failure says as much about this
//! node's reach as about the address, so a long block must not walk every
//! candidate up the ladder toward the hour. Outside the condition the
//! ladder steps as it always does. Both connectors, one mechanism. It is
//! not a verdict on the link, and nothing is announced (`TSR-Q14`).
//!
//! Wargame (`P2P_3_SLICE_3_DIALER_BRIEF.md`, the gray lifecycle): an
//! attacker's dead addresses cannot produce the condition while the node
//! holds any session; a node that is fully isolated cycles faster, which
//! helps it find an honest address; and white survives a block, because a
//! failed white test does not demote in the stretch (white is
//! known-working, Rick 2026-10-26: outside the stretch it moves to gray).

use shekyl_peerlist::{dial_profile, ConnectorId, DialOutcome, Ladder, Tick};

use super::{Dialer, Shared};
use crate::reach::{attempt_stream, AttemptStream};

impl Dialer {
    /// Fold one attempt's end into `connector`'s evidence: an attempt that
    /// opened a stream resets the count of unopened attempts and starts the
    /// span again; one that ended without a stream adds to the count. Not a
    /// dial, neither moves.
    pub(super) fn note_attempt(
        shared: &mut Shared,
        connector: ConnectorId,
        outcome: &DialOutcome,
        now: Tick,
    ) {
        let index = connector.index();
        match attempt_stream(outcome) {
            AttemptStream::Opened => {
                shared.last_opened[index] = now;
                shared.unopened[index] = 0;
            }
            AttemptStream::Unopened => {
                shared.unopened[index] = shared.unopened[index].saturating_add(1);
            }
            AttemptStream::NotADial => {}
        }
    }

    /// The ladder a failed test on `connector` takes at `now`: the first
    /// step while the connector holds no session, outbound or inbound, its
    /// last K attempts all ended without opening a stream, and at least S
    /// has passed since a stream last opened there (K and S are its dial
    /// profile's quiet threshold); the climb otherwise.
    pub(super) fn ladder(shared: &Shared, connector: ConnectorId, now: Tick) -> Ladder {
        let index = connector.index();
        let threshold = dial_profile(connector).quiet;
        let held = shared
            .view(connector)
            .held()
            .saturating_add(shared.inbound[index]);
        let span = now.get().saturating_sub(shared.last_opened[index].get());
        if held == 0 && shared.unopened[index] >= threshold.attempts && span >= threshold.span_nanos
        {
            Ladder::FirstStep
        } else {
            Ladder::Climb
        }
    }
}
