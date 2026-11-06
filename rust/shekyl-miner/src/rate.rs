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

/// One worker's buckets, each one word: the second it counts in the high
/// 32 bits (plus one, so zero is an empty bucket) and that second's hashes
/// in the low 32. The owning worker is the only writer and replaces a word
/// whole, so a reader always sees a second paired with its own count —
/// never a stamp read before the bucket was reused and a count read after.
pub(crate) struct RateRing {
    buckets: [AtomicU64; BUCKETS],
}

/// The low half of a bucket word: its hash count.
const COUNT_MASK: u64 = u32::MAX as u64;

/// A bucket word's second and count; `None` for an empty bucket.
const fn unpack(word: u64) -> Option<(u64, u64)> {
    let stamp = word >> 32;
    if stamp == 0 {
        None
    } else {
        Some((stamp - 1, word & COUNT_MASK))
    }
}

impl RateRing {
    pub(crate) fn new() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    fn slot(second: u64) -> usize {
        usize::try_from(second % BUCKETS as u64).expect("below the bucket count")
    }

    /// One hash in `second` (seconds since the miner started). The owning
    /// worker is the only writer. A second past `u32::MAX - 1` (136 years
    /// of mining) is not counted, and a count saturates at `u32::MAX` hashes
    /// in one second, far beyond any RandomX worker.
    pub(crate) fn record(&self, second: u64) {
        let Ok(stamp) = u32::try_from(second.saturating_add(1)) else {
            return;
        };
        let stamp = u64::from(stamp);
        let bucket = &self.buckets[Self::slot(second)];
        let word = bucket.load(Ordering::Relaxed);
        let count = if word >> 32 == stamp {
            ((word & COUNT_MASK) + 1).min(COUNT_MASK)
        } else {
            1
        };
        bucket.store(stamp << 32 | count, Ordering::Release);
    }

    /// Every non-empty bucket's second and count, each read whole.
    fn buckets(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.buckets
            .iter()
            .filter_map(|bucket| unpack(bucket.load(Ordering::Acquire)))
    }

    /// The hashes of the complete seconds in the window ending before
    /// `now` (the second in progress is not counted).
    pub(crate) fn rate(&self, now: u64) -> HashRate {
        let first = now.saturating_sub(WINDOW_SECS);
        let hashes = self
            .buckets()
            .filter(|&(second, _)| second >= first && second < now)
            .map(|(_, count)| count)
            .sum();
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

    /// A bucket's second and count are read as one pair while its worker
    /// reuses it. The writer gives even seconds one hash and odd seconds a
    /// thousand; eleven buckets alternate parity in each slot (second `s`
    /// and `s + 11`), so a reader that took an even second's stamp and the
    /// next occupant's count would see more than one hash for it.
    #[test]
    fn a_reader_never_pairs_a_second_with_a_later_seconds_count() {
        const SECONDS: u64 = 20_000;
        let hashes_in = |second: u64| if second.is_multiple_of(2) { 1 } else { 1_000 };
        let ring = RateRing::new();
        let done = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for second in 0..SECONDS {
                    for _ in 0..hashes_in(second) {
                        ring.record(second);
                    }
                }
                done.store(true, Ordering::Release);
            });
            let mut reads = 0u64;
            while !done.load(Ordering::Acquire) {
                for (second, count) in ring.buckets() {
                    assert!(
                        count <= hashes_in(second),
                        "second {second} read with {count} hashes"
                    );
                }
                reads += 1;
            }
            assert!(reads > 0, "the reader ran beside the writer");
        });
    }
}
