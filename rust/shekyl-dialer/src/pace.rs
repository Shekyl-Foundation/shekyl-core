// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pace mechanisms: the wake spacing (R3, Rick, 2026-10-12) and the
//! retry ladder within a test. One mechanism each; the numbers are the
//! dialing connector's ([`shekyl_peerlist::dial_profile`]).
//!
//! One wake, one dial. The gap to the next wake is drawn per dial from the
//! connector's wake span. The connector changes which list is drawn and
//! its numbers, not the shape.

use shekyl_draw_rng::{bounded_uniform, RelayRng};
use shekyl_peerlist::ListName;
use shekyl_transport_layer::{AttemptsPerTest, JitteredSpan, RetryWaits};

/// One draw from `span`: its base plus a uniform draw over its jitter.
pub fn draw<R: RelayRng + ?Sized>(span: JitteredSpan, rng: &mut R) -> u64 {
    span.base_nanos
        .saturating_add(bounded_uniform(rng, span.jitter_nanos))
}

/// The gap to the next wake, in nanoseconds: one draw from the connector's
/// wake span.
pub fn next_wake_nanos<R: RelayRng + ?Sized>(wake: JitteredSpan, rng: &mut R) -> u64 {
    draw(wake, rng)
}

/// How many attempts one test makes of an address drawn from `list`, on
/// the connector's `attempts` (the gray lifecycle, Rick 2026-10-24 and
/// 2026-10-26: a white address is known-working, so its test may give it
/// a redial before it demotes). Each attempt after the first follows a
/// wait ([`retry_wait_nanos`]) that holds no in-flight slot.
#[must_use]
pub const fn attempts_per_test(attempts: AttemptsPerTest, list: ListName) -> u8 {
    match list {
        ListName::Gray => attempts.gray,
        ListName::White => attempts.white,
    }
}

/// The wait before attempt `next` of a test, in nanoseconds, on the
/// connector's `waits`: its second-attempt span before the second, its
/// third-attempt span before the third and any later one.
pub fn retry_wait_nanos<R: RelayRng + ?Sized>(waits: &RetryWaits, next: u8, rng: &mut R) -> u64 {
    if next <= 2 {
        draw(waits.before_second, rng)
    } else {
        draw(waits.before_third, rng)
    }
}
