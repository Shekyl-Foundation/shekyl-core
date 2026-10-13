// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The wake spacing (R3, Rick, 2026-10-12).
//!
//! One wake, one dial. The gap to the next wake is `0.5 s + U(0, 1.0 s)`,
//! mean 1 s, drawn per dial. The shape is the same on every connector:
//! the connector changes which list is drawn, not the clock.

use shekyl_relay_privacy::rng::{bounded_uniform, RelayRng};

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
