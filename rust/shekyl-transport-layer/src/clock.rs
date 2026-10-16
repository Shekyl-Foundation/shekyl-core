// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The monotonic clock the byte stamps and the stall check share.
//!
//! [`monotonic_ms`] is never zero: zero means no byte has moved yet.
//! An NTP step does not move it. [`unix_ms_of`] is that instant on the
//! operator's clock. [`recv_mark_ms`] is the instant a stall check
//! compares: a receive of zero is measured from admission.

use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Milliseconds of a monotonic clock that starts at the first call.
///
/// Never zero. Not unix time. The C stall check calls the same function
/// for "now", so the two sides share this epoch.
#[must_use]
pub fn monotonic_ms() -> u64 {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    let origin = ORIGIN.get_or_init(Instant::now);
    // One, not zero. Zero is "no byte yet" on the stamp.
    u64::try_from(origin.elapsed().as_millis())
        .unwrap_or(u64::MAX)
        .saturating_add(1)
}

/// `mark` as unix milliseconds, using the clocks at the call.
///
/// Zero stays zero. The stall check does not call this: it compares
/// monotonic stamps to [`monotonic_ms`].
#[must_use]
pub fn unix_ms_of(mark: u64) -> u64 {
    if mark == 0 {
        return 0;
    }
    let now_m = monotonic_ms();
    let now_u = unix_ms();
    now_u.saturating_sub(now_m.saturating_sub(mark))
}

/// Unix milliseconds. Zero when the clock is before the epoch.
fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// The instant a stall check compares, in monotonic milliseconds.
///
/// `recv_ms` is the last received byte. Zero means none has arrived, and
/// the mark is `started_ms` on the same clock.
#[must_use]
pub const fn recv_mark_ms(recv_ms: u64, started_ms: u64) -> u64 {
    if recv_ms == 0 {
        started_ms
    } else {
        recv_ms
    }
}

#[cfg(test)]
mod tests {
    use super::{monotonic_ms, recv_mark_ms, unix_ms_of};

    #[test]
    fn a_quiet_session_is_measured_from_admission() {
        assert_eq!(recv_mark_ms(0, 1_000), 1_000);
        assert_eq!(recv_mark_ms(2_500, 1_000), 2_500);
    }

    #[test]
    fn unix_of_zero_stays_zero_and_the_clock_never_is() {
        assert_eq!(unix_ms_of(0), 0);
        let first = monotonic_ms();
        assert!(first > 0);
        assert!(monotonic_ms() >= first);
        let unix = unix_ms_of(first);
        assert!(unix > 0);
    }
}
