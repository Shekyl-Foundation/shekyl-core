// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The wake spacing (R3, Rick, 2026-10-12).
//!
//! One wake, one dial. The gap to the next wake is `0.5 s + U(0, 1.0 s)`,
//! mean 1 s, drawn per dial. The shape is the same on every connector:
//! the connector changes which list is drawn, not the clock.

use shekyl_draw_rng::{bounded_uniform, RelayRng};
use shekyl_peerlist::ConnectorId;

/// The fixed part of the gap, in nanoseconds.
///
/// **Assumption** (`DAEMON_RELAY_PRIVACY.md` §97, "Dial wake spacing"):
/// re-measured on the Rust dialer after PR-3.
pub const WAKE_BASE_NANOS: u64 = 500_000_000;

/// The width of the uniform part of the gap, in nanoseconds.
///
/// **Assumption** (§97), as [`WAKE_BASE_NANOS`].
pub const WAKE_JITTER_NANOS: u64 = 1_000_000_000;

/// The gap to the next wake, in nanoseconds: [`WAKE_BASE_NANOS`] plus a
/// uniform draw over `[0, WAKE_JITTER_NANOS]`.
pub fn next_wake_nanos<R: RelayRng + ?Sized>(rng: &mut R) -> u64 {
    WAKE_BASE_NANOS + bounded_uniform(rng, WAKE_JITTER_NANOS)
}

/// Nanoseconds in one second.
const SECOND_NANOS: u64 = 1_000_000_000;

/// The quiet stretch: how long a connector holds no session and no stream
/// opens there before a failed test cools at the first step and does not
/// climb (the dialer, Rick 2026-10-26), and before the managed-Tor
/// supervisor's posture line says no Tor connection has opened
/// (`TOR_SUPERVISOR.md` §4.2: the daemon builds its `Policy` from this).
/// One number for both.
///
/// **Assumption** (`DAEMON_RELAY_PRIVACY.md` §97): five minutes,
/// provisional until the floor-device soak.
pub const QUIET_AFTER_NANOS: u64 = 300 * SECOND_NANOS;

/// How many attempts one test of an address makes on `connector` (the gray
/// lifecycle, Rick 2026-10-24): three on Tor, where a failed dial is often
/// a descriptor that has not propagated against a peer that is up, and one
/// on clearnet. Each attempt after the first follows a wait
/// ([`retry_wait_nanos`]) that holds no in-flight slot.
#[must_use]
pub const fn attempts_per_test(connector: ConnectorId) -> u8 {
    match connector {
        ConnectorId::Clearnet => 1,
        ConnectorId::Tor => 3,
    }
}

/// The wait before attempt `next` of a test (2 or 3), in nanoseconds:
/// 5 s + U(0, 5 s) before the second, 20 s + U(0, 10 s) before the third.
///
/// **Assumption** (`DAEMON_RELAY_PRIVACY.md` §97): starting values,
/// re-derived from testnet runs. A `next` outside 2 and 3 is the third
/// wait, which never happens: [`attempts_per_test`] caps at three.
pub fn retry_wait_nanos<R: RelayRng + ?Sized>(next: u8, rng: &mut R) -> u64 {
    if next <= 2 {
        5 * SECOND_NANOS + bounded_uniform(rng, 5 * SECOND_NANOS)
    } else {
        20 * SECOND_NANOS + bounded_uniform(rng, 10 * SECOND_NANOS)
    }
}
