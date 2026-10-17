// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The hash rate over a stated window: one ring of one-second buckets per
//! worker, written by that worker alone and summed by the status reader.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// The window the reported rate is measured over: the last ten complete
/// seconds (fewer before the miner has run that long).
pub const RATE_WINDOW: Duration = Duration::from_secs(WINDOW_SECS);

const WINDOW_SECS: u64 = 10;
/// One bucket per second of the window, and one for the second in progress.
const BUCKETS: usize = 11;
const _: () = assert!(BUCKETS as u64 == WINDOW_SECS + 1);

/// Hashes counted over a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HashRate {
    /// Hashes computed in the window.
    pub hashes: u64,
    /// The window: complete seconds counted, at most [`RATE_WINDOW`].
    pub window: Duration,
}

impl HashRate {
    /// Hashes per second over the window; zero before a second completes.
    #[must_use]
    pub fn per_second(&self) -> f64 {
        let secs = self.window.as_secs_f64();
        if secs == 0.0 {
            0.0
        } else {
            // A count of hashes in ten seconds is far inside f64's exact range.
            #[allow(clippy::cast_precision_loss)]
            let hashes = self.hashes as f64;
            hashes / secs
        }
    }
}

/// One worker's buckets. `stamps[i]` is the second (plus one; zero is
/// empty) whose hashes `counts[i]` holds.
pub(crate) struct RateRing {
    stamps: [AtomicU64; BUCKETS],
    counts: [AtomicU64; BUCKETS],
}

impl RateRing {
    pub(crate) fn new() -> Self {
        Self {
            stamps: std::array::from_fn(|_| AtomicU64::new(0)),
            counts: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    fn slot(second: u64) -> usize {
        usize::try_from(second % BUCKETS as u64).expect("below the bucket count")
    }

    /// One hash in `second` (seconds since the miner started). The owning
    /// worker is the only writer.
    pub(crate) fn record(&self, second: u64) {
        let i = Self::slot(second);
        let stamp = second + 1;
        if self.stamps[i].load(Ordering::Relaxed) != stamp {
            self.counts[i].store(0, Ordering::Relaxed);
            self.stamps[i].store(stamp, Ordering::Release);
        }
        self.counts[i].fetch_add(1, Ordering::Relaxed);
    }

    /// The hashes of the complete seconds in the window ending before
    /// `now` (the second in progress is not counted).
    pub(crate) fn rate(&self, now: u64) -> HashRate {
        let first = now.saturating_sub(WINDOW_SECS);
        let mut hashes = 0;
        for i in 0..BUCKETS {
            let stamp = self.stamps[i].load(Ordering::Acquire);
            if stamp == 0 {
                continue;
            }
            let second = stamp - 1;
            if second >= first && second < now {
                hashes += self.counts[i].load(Ordering::Relaxed);
            }
        }
        HashRate {
            hashes,
            window: Duration::from_secs(now - first),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_counts_complete_seconds_and_forgets_older_ones() {
        let ring = RateRing::new();
        for second in 0..15u64 {
            for _ in 0..=second {
                ring.record(second);
            }
        }
        // At second 15 the window is seconds 5..=14: 6 + 7 + … + 15.
        let rate = ring.rate(15);
        assert_eq!(rate.window, RATE_WINDOW);
        assert_eq!(rate.hashes, (6..=15).sum::<u64>());
        // The second in progress is not counted.
        ring.record(15);
        assert_eq!(ring.rate(15).hashes, (6..=15).sum::<u64>());
        // Before ten seconds, the window is what has completed.
        let young = RateRing::new();
        young.record(0);
        young.record(1);
        young.record(1);
        assert_eq!(
            young.rate(2),
            HashRate {
                hashes: 3,
                window: Duration::from_secs(2)
            }
        );
        assert!((young.rate(2).per_second() - 1.5).abs() < f64::EPSILON);
    }
}
