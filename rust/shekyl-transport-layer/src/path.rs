// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Whether a connector's path works: what the dialer's judge asks the
//! connector that made a dial (`DIALER_OUTAGE_EVIDENCE.md` §3.3, Rick,
//! 2026-11-15).
//!
//! The judge is decoupled from every connector. For an uncertain failure it
//! asks the dialing connector's [`PathSource`] for a reading taken after the
//! failure, and waits at most [`PathSource::wait_nanos`] for one:
//!
//! - [`PathReading::Working`]: the failure counts against its address;
//! - [`PathReading::Impaired`], or no reading within the wait: it is excused.
//!
//! What a reading is made of is the connector's own business. The judge
//! knows nothing about bytes, streams, probes or checks, and a new connector
//! supplies its own source with no change to the judge.

use std::fmt;
use std::sync::Arc;

use shekyl_timing_engine::Stamp;

/// What a connector says about its path at some instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathReading {
    /// The path worked: a failure on it was the address's.
    Working,
    /// The path did not work: a failure on it is not the address's.
    Impaired,
}

/// Rung by a source when it has a reading a waiting failure may want, so
/// the asker reads again. Calling it must not block.
pub type PathReady = Arc<dyn Fn() + Send + Sync>;

/// A connector's source of path readings.
pub trait PathSource: Send + Sync {
    /// A reading this connector took after `failed`, if it has one at `now`.
    ///
    /// Both instants are on the process clock. Asking is the request: a
    /// source with no such reading may start its own work toward one, and
    /// rings `ready` when a reading arrives. Asking again for the same
    /// failure starts nothing new.
    fn reading_after(&self, failed: Stamp, now: Stamp, ready: &PathReady) -> Option<PathReading>;

    /// The longest the judge waits, from the failure, for a reading. With
    /// none by then the failure is excused. In nanoseconds.
    fn wait_nanos(&self) -> u64;
}

/// The source of a connector that has none: it never has a reading, and
/// the judge excuses every uncertain failure on it at once. What a dialer
/// holds for a connector until the network supplies that connector's own.
#[derive(Clone, Copy, Default)]
pub struct NoReadings;

impl PathSource for NoReadings {
    fn reading_after(&self, _: Stamp, _: Stamp, _: &PathReady) -> Option<PathReading> {
        None
    }

    fn wait_nanos(&self) -> u64 {
        0
    }
}

impl fmt::Debug for dyn PathSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PathSource")
            .field("wait_nanos", &self.wait_nanos())
            .finish_non_exhaustive()
    }
}
