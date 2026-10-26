// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The quiet stretch (Rick, 2026-10-26): while a connector holds no
//! session and no stream has opened there for [`QUIET_AFTER_NANOS`], a
//! failed test cools at the first step and does not climb.
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
//! helps it find an honest address; white is never cooled, so a block
//! shorter than the white expiry (24 h) already refills from white.

use shekyl_peerlist::{ConnectorId, DialOutcome, Ladder, Tick};

use super::{Dialer, Shared};
use crate::link_tally::opened_a_stream;
use crate::pace::QUIET_AFTER_NANOS;

impl Dialer {
    /// An attempt on `connector` that opened a stream starts the quiet
    /// stretch again.
    pub(super) fn note_opened(
        shared: &mut Shared,
        connector: ConnectorId,
        outcome: &DialOutcome,
        now: Tick,
    ) {
        if opened_a_stream(outcome) {
            shared.last_opened[connector.index()] = now;
        }
    }

    /// The ladder a failed test on `connector` takes at `now`: the first
    /// step while the connector holds no session, outbound or inbound, and
    /// no stream has opened there for [`QUIET_AFTER_NANOS`]; the climb
    /// otherwise.
    pub(super) fn ladder(shared: &Shared, connector: ConnectorId, now: Tick) -> Ladder {
        let held = shared
            .view(connector)
            .held()
            .saturating_add(shared.inbound[connector.index()]);
        let quiet = now
            .get()
            .saturating_sub(shared.last_opened[connector.index()].get());
        if held == 0 && quiet >= QUIET_AFTER_NANOS {
            Ladder::FirstStep
        } else {
            Ladder::Climb
        }
    }
}
