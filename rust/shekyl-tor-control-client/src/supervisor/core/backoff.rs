// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Respawn backoff (`TOR_SUPERVISOR.md` §4.4).
//!
//! Each process fault doubles the wait, up to the cap. A usable interval
//! that lasted one cap restarts that count at the next fault, including
//! when the facet left usable before the fault. Time spent degraded does
//! not serve the cap. The threshold is the cap itself, so a crash rate
//! that never serves one gains no faster re-roll.

/// Shifts past this saturate a doubling backoff for any base of at least one
/// nanosecond. The cap is what the operator waits.
const SHIFT_LIMIT: u32 = 16;

/// How many process faults are outstanding, and whether a usable cap is
/// already served.
#[derive(Debug)]
pub(super) struct Backoff {
    failures: u32,
    /// A usable interval already lasted a cap. The next fault consumes it.
    restart: bool,
}

impl Backoff {
    pub(super) const fn new() -> Self {
        Self {
            failures: 0,
            restart: false,
        }
    }

    /// The outbound facet closed a usable interval that lasted a cap.
    pub(super) fn note_usable_cap(&mut self) {
        self.restart = true;
    }

    /// One process fault. A served cap restarts the count first, so this
    /// fault waits the base and the one after it doubles.
    pub(super) fn on_fault(&mut self, base: u64, cap: u64) -> u64 {
        if self.restart {
            self.failures = 0;
            self.restart = false;
        }
        self.failures = self.failures.saturating_add(1);
        delay(self.failures, base, cap)
    }
}

fn delay(failures: u32, base: u64, cap: u64) -> u64 {
    let exp = failures.saturating_sub(1).min(SHIFT_LIMIT);
    let factor = 1u64.checked_shl(exp).unwrap_or(u64::MAX);
    base.saturating_mul(factor).min(cap)
}
