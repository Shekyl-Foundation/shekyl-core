// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SP-5 (PR-B) — [`ScanSchedule`]: the P-scan loop's **injectable** cadence.
//!
//! ## Why injectable (don't foreclose the third fetch-layer leak)
//!
//! SP-0 closed output-*selectivity* and the forward-note closed fetch-*order*;
//! the third fetch-layer side channel is *when and how often* `P` scans
//! (`docs/design/ARCHIVAL_BOND_2D1_PSCAN_PLAN.md` DQ6 / `TM-6`). A task that bakes
//! a `tokio::time::interval` or a scan-on-open trigger has a fixed cadence on the
//! wire. So the loop takes its cadence as an **injected** [`ScanSchedule`]; 2d-2
//! can later make it constant-rate or jittered (transport-aware) without touching
//! the loop. 2d-1's obligation is only to keep it injectable.
//!
//! ## Why FIXED-RATE, not sleep-after-completion (load-bearing for the firewall)
//!
//! [`FixedRateSchedule`] fires every `period` of **wall-clock**, regardless of how
//! long a scan cycle took — *not* a sleep measured from when the cycle finished.
//! That distinction matters: only a fixed rate decouples the cadence from the
//! **scan-set size**. With the [`BlockSource`](super::block_source) fetching
//! *everything*, the scan-set size never changes what is fetched (content is
//! already invisible to a network observer); a fixed rate makes it invisible on
//! the **timing** axis too. So dropping a persona (the DQ8 retire) cannot be seen
//! either way — a sleep-after-completion schedule, by contrast, would speed up
//! once the set shrank and leak the wipe.
//!
//! **Honest caveat.** Fixed-rate pacing holds only when the wallet is *caught up*
//! (per-cycle work < `period`). During cold-start catch-up the loop is
//! work-bottlenecked and effectively work-paced — but there the observable pattern
//! is already a saturated bulk-fetch, so the retire's marginal speedup is lost in
//! it and reintroduces nothing. Steady state, where the cadence channel actually
//! matters, is fixed-rate and clean.

use std::future::Future;
use std::time::Duration;

use tokio::time::{interval, Interval, MissedTickBehavior};

/// The P-scan loop's cadence. The task awaits [`next_tick`](ScanSchedule::next_tick)
/// between scan cycles; the impl decides the rhythm.
///
/// `Send + 'static`: the schedule is moved into the spawned P-scan task and held
/// across its `await` points.
pub(crate) trait ScanSchedule: Send + 'static {
    /// Resolves when the next scan cycle should run.
    fn next_tick(&mut self) -> impl Future<Output = ()> + Send;
}

/// A fixed-rate schedule anchored to wall-clock: the `i`-th tick fires at
/// `start + i·period`, regardless of how long each cycle took.
///
/// Built on [`tokio::time::interval`] with [`MissedTickBehavior::Skip`] — if a
/// cycle overran a tick, the missed tick is **skipped** (not burst-replayed, not
/// drifted), so the schedule stays anchored to the original wall-clock cadence.
/// See the module docs for why fixed-rate (not sleep-after-completion) is what
/// keeps the DQ8 retire invisible. 2d-2 replaces this with a transport-aware
/// constant-rate-or-jittered schedule.
pub(crate) struct FixedRateSchedule {
    interval: Interval,
}

impl FixedRateSchedule {
    /// A fixed-rate schedule firing every `period`. The first tick resolves
    /// immediately (the first scan cycle runs at once), then every `period`.
    pub(crate) fn new(period: Duration) -> Self {
        let mut interval = interval(period);
        // Skip — maintain the original wall-clock schedule across an overrun,
        // rather than bursting to catch up (which would be work-paced) or delaying
        // (which would drift the rate).
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        Self { interval }
    }
}

impl ScanSchedule for FixedRateSchedule {
    async fn next_tick(&mut self) {
        self.interval.tick().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first tick is immediate; subsequent ticks are paced at `period` of
    /// wall-clock (verified under tokio's paused clock).
    #[tokio::test(start_paused = true)]
    async fn fixed_rate_paces_at_the_period() {
        let period = Duration::from_secs(10);
        let mut sched = FixedRateSchedule::new(period);

        // First tick: immediate.
        sched.next_tick().await;

        // The second tick is not ready until ~period has elapsed.
        tokio::select! {
            biased;
            () = sched.next_tick() => panic!("second tick fired before the period elapsed"),
            () = tokio::time::sleep(period.saturating_sub(Duration::from_millis(1))) => {}
        }

        // After the full period, it fires.
        tokio::time::advance(Duration::from_millis(1)).await;
        sched.next_tick().await;
    }

    /// Fixed-rate, not sleep-after-completion: a cycle that overruns one period
    /// does not push the schedule out — the next tick is already due (Skip keeps
    /// the wall-clock anchor), so it fires immediately rather than waiting another
    /// full period from when the slow cycle ended.
    #[tokio::test(start_paused = true)]
    async fn an_overrun_does_not_delay_the_next_tick() {
        let period = Duration::from_secs(10);
        let mut sched = FixedRateSchedule::new(period);
        sched.next_tick().await; // immediate first tick

        // Simulate a scan cycle that took longer than one period.
        tokio::time::advance(period + Duration::from_secs(1)).await;

        // The next tick is already overdue ⇒ resolves without further waiting.
        tokio::select! {
            biased;
            () = sched.next_tick() => {}
            () = tokio::time::sleep(Duration::from_secs(1)) => {
                panic!("an overdue fixed-rate tick must fire immediately, not wait another period")
            }
        }
    }
}
