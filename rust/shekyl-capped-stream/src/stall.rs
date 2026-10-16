// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One session's socket-write histogram, folded once when its writer ends.
//!
//! The copy loop calls [`WriteStall::begin`], [`WriteStall::complete`],
//! and [`WriteStall::cancel`]. Nothing on that path takes the process
//! lock. [`WriteStall::fold`] adds the buckets to the process histogram,
//! and [`Drop`] folds a writer the pool cancelled while a write was in
//! flight. The record is the distribution. It is not a threshold.

use std::fmt;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// One bucket per bit of a nanosecond sample.
///
/// Bucket `i` is `[2^i, 2^(i+1))` nanoseconds. Zero nanoseconds is bucket 0.
const STALL_BUCKETS: usize = u64::BITS as usize;

/// Power-of-two nanosecond buckets for one session's socket writes.
///
/// The longest completed sample is [`Self::max_ns`]. A write cancelled
/// before it returned is [`Self::in_flight_at_close_ns`], not a bucket:
/// it did not finish.
pub struct WriteStall {
    conn: u64,
    buckets: [u64; STALL_BUCKETS],
    max_ns: u64,
    in_flight_at_close_ns: Option<u64>,
    started: Option<Instant>,
    folded: bool,
}

impl WriteStall {
    #[must_use]
    pub fn new(conn: u64) -> Self {
        Self {
            conn,
            buckets: [0; STALL_BUCKETS],
            max_ns: 0,
            in_flight_at_close_ns: None,
            started: None,
            folded: false,
        }
    }

    #[must_use]
    pub fn conn(&self) -> u64 {
        self.conn
    }

    #[must_use]
    pub fn max_ns(&self) -> u64 {
        self.max_ns
    }

    #[must_use]
    pub fn buckets(&self) -> &[u64; STALL_BUCKETS] {
        &self.buckets
    }

    #[must_use]
    pub fn in_flight_at_close_ns(&self) -> Option<u64> {
        self.in_flight_at_close_ns
    }

    pub(crate) fn begin(&mut self) {
        self.started = Some(Instant::now());
    }

    pub(crate) fn complete(&mut self) {
        if let Some(started) = self.started.take() {
            self.record_ns(ns_of(started.elapsed()));
        }
    }

    pub(crate) fn cancel(&mut self) {
        if let Some(started) = self.started.take() {
            self.in_flight_at_close_ns = Some(ns_of(started.elapsed()));
        }
    }

    fn record_ns(&mut self, ns: u64) {
        let bucket = bucket_of(ns);
        self.buckets[bucket] = self.buckets[bucket].saturating_add(1);
        if ns > self.max_ns {
            self.max_ns = ns;
        }
    }

    /// Add this session's buckets to the process histogram. A second call
    /// does not add them again.
    pub fn fold(&mut self) {
        if self.folded {
            return;
        }
        self.cancel();
        self.folded = true;
        process_stalls()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .add(self);
    }
}

impl Drop for WriteStall {
    fn drop(&mut self) {
        self.fold();
    }
}

impl fmt::Display for WriteStall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "max_ns={} in_flight_ns={}",
            self.max_ns,
            self.in_flight_at_close_ns.unwrap_or(0)
        )?;
        for (index, count) in self.buckets.iter().copied().enumerate() {
            if count != 0 {
                write!(f, " {index}:{count}")?;
            }
        }
        Ok(())
    }
}

/// The process-wide fold of every session histogram.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessWriteStall {
    pub buckets: [u64; STALL_BUCKETS],
    pub max_ns: u64,
    pub closes: u64,
    pub in_flight_at_close: u64,
    pub in_flight_at_close_max_ns: u64,
}

impl ProcessWriteStall {
    fn add(&mut self, stall: &WriteStall) {
        for (into, from) in self.buckets.iter_mut().zip(stall.buckets) {
            *into = into.saturating_add(from);
        }
        if stall.max_ns > self.max_ns {
            self.max_ns = stall.max_ns;
        }
        self.closes = self.closes.saturating_add(1);
        if let Some(ns) = stall.in_flight_at_close_ns {
            self.in_flight_at_close = self.in_flight_at_close.saturating_add(1);
            if ns > self.in_flight_at_close_max_ns {
                self.in_flight_at_close_max_ns = ns;
            }
        }
    }
}

fn process_stalls() -> &'static Mutex<ProcessWriteStall> {
    static STALLS: OnceLock<Mutex<ProcessWriteStall>> = OnceLock::new();
    STALLS.get_or_init(|| {
        Mutex::new(ProcessWriteStall {
            buckets: [0; STALL_BUCKETS],
            max_ns: 0,
            closes: 0,
            in_flight_at_close: 0,
            in_flight_at_close_max_ns: 0,
        })
    })
}

/// The histograms folded so far. A reader takes this after a session's
/// writer has finished; the per-session record is still on that
/// [`WriteStall`].
#[must_use]
pub fn process_write_stall() -> ProcessWriteStall {
    process_stalls()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

fn ns_of(elapsed: std::time::Duration) -> u64 {
    u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
}

/// Bucket `i` is `[2^i, 2^(i+1))` nanoseconds. Zero is bucket 0.
fn bucket_of(ns: u64) -> usize {
    if ns == 0 {
        0
    } else {
        (u64::BITS - 1 - ns.leading_zeros()) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::WriteStall;

    #[test]
    fn buckets_are_powers_of_two() {
        let mut stall = WriteStall::new(0);
        stall.record_ns(0);
        stall.record_ns(1);
        stall.record_ns(2);
        stall.record_ns(1 << 10);
        assert_eq!(stall.buckets()[0], 2);
        assert_eq!(stall.buckets()[1], 1);
        assert_eq!(stall.buckets()[10], 1);
        assert_eq!(stall.max_ns(), 1 << 10);
        // Not folded: this stall is the table, not a session close.
        stall.folded = true;
    }
}
