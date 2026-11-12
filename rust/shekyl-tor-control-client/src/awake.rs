// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Waits that count the process clock.
//!
//! A tokio timer follows tokio's clock. On Windows that clock runs through
//! every sleep. These waits sleep on that timer and, each time it returns,
//! read [`MonotonicClock`]. They end only once that clock says so. S3 sleep
//! and hibernation count for nothing on it. Modern Standby does not: the
//! clock keeps running, so a standby still ends a wait at the wake.
//!
//! The timing engine's thread does not use them. It sleeps on
//! [`Clock::wait_for`], and linking
//! tokio there would pull a runtime into the transport layer. This crate is
//! the one both Tor supervisors already run their asks on. A production
//! caller outside it that has to wait the same way is when this module
//! moves next to the clock.
//!
//! A guard's expiry is not this clock. It is a `SystemTime` on the vanguard
//! state, and the arm that waits for it stays on tokio's timer.

use std::future::Future;
use std::pin::pin;
use std::task::Poll;
use std::time::Duration;

use shekyl_timing_engine::{Clock, MonotonicClock, Tick};

/// The deadline `within` from now on the process clock.
#[must_use]
pub fn deadline_after(within: Duration) -> Tick {
    deadline_on(&MonotonicClock::new(), within)
}

/// Wait until `deadline` has passed on the process clock.
pub async fn sleep_until(deadline: Tick) {
    sleep_until_on(&MonotonicClock::new(), deadline).await;
}

/// Wait `within` of process-clock time.
///
/// The deadline is read when this is called, not when the future is first
/// polled. Work done before that poll still counts, which is what a budget
/// passed across other awaits means.
#[must_use = "the wait does nothing unless it is awaited"]
pub fn sleep(within: Duration) -> impl Future<Output = ()> + Send {
    let deadline = deadline_after(within);
    async move {
        let clock = MonotonicClock::new();
        sleep_until_on(&clock, deadline).await;
    }
}

/// `within` of the process clock passed before the future finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Elapsed;

impl std::fmt::Display for Elapsed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the wait's time passed")
    }
}

impl std::error::Error for Elapsed {}

/// The future's output, or [`Elapsed`] once `within` of process-clock time
/// has passed. The future is polled first, so an output ready at the
/// deadline is kept.
///
/// The deadline is read when this is called, not when the future is first
/// polled, the same as [`sleep`].
///
/// # Errors
///
/// [`Elapsed`] when the time passed first.
#[must_use = "the bound does nothing unless it is awaited"]
pub fn timeout<F>(within: Duration, future: F) -> impl Future<Output = Result<F::Output, Elapsed>>
where
    F: Future,
{
    let deadline = deadline_after(within);
    async move {
        let clock = MonotonicClock::new();
        wait_for(deadline, &clock, future).await
    }
}

/// The deadline `within` from now on `clock`.
fn deadline_on<C: Clock + ?Sized>(clock: &C, within: Duration) -> Tick {
    let within = u64::try_from(within.as_nanos()).unwrap_or(u64::MAX);
    Tick::new(clock.now().get().saturating_add(within))
}

/// Wait until `deadline` has passed on `clock`.
///
/// The gap is slept on tokio's timer, then the clock is read again. The
/// process clock's `wait_for` returns that same gap. A test clock that does
/// not move returns `None` from `wait_for` until the deadline is due, so
/// this loop reads the tick gap itself and the test can jump tokio's time
/// without the wait ending.
async fn sleep_until_on<C: Clock + ?Sized>(clock: &C, deadline: Tick) {
    loop {
        let now = clock.now().get();
        if now >= deadline.get() {
            return;
        }
        tokio::time::sleep(Duration::from_nanos(deadline.get() - now)).await;
    }
}

/// Wait `within` of `clock`'s time. The deadline is read when this is
/// polled, which the hand-clock tests do at once.
#[cfg(test)]
async fn sleep_on<C: Clock + ?Sized>(clock: &C, within: Duration) {
    sleep_until_on(clock, deadline_on(clock, within)).await;
}

/// `future`'s output, or [`Elapsed`] once `within` of `clock`'s time has
/// passed. The deadline is read when this is polled, which the hand-clock
/// tests do at once.
#[cfg(test)]
async fn timeout_on<C, F>(clock: &C, within: Duration, future: F) -> Result<F::Output, Elapsed>
where
    C: Clock + ?Sized,
    F: Future,
{
    wait_for(deadline_on(clock, within), clock, future).await
}

/// `future`'s output, or [`Elapsed`] once `deadline` has passed on `clock`.
async fn wait_for<C, F>(deadline: Tick, clock: &C, future: F) -> Result<F::Output, Elapsed>
where
    C: Clock + ?Sized,
    F: Future,
{
    let mut future = pin!(future);
    let mut waited = pin!(sleep_until_on(clock, deadline));
    std::future::poll_fn(|cx| {
        if let Poll::Ready(output) = future.as_mut().poll(cx) {
            return Poll::Ready(Ok(output));
        }
        if waited.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(Elapsed));
        }
        Poll::Pending
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use shekyl_timing_engine::{Clock, ManualClock, Tick};

    use super::{sleep, sleep_on, timeout, timeout_on, Elapsed};

    const SECOND: u64 = 1_000_000_000;

    /// Let spawned tasks run at the paused time.
    async fn settle() {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

    /// **A wall jump does not end the wait; awake time does.** A 10 s wait
    /// on a clock that does not move while tokio's time jumps a minute, as
    /// Windows' timer does across a sleep, is still waiting; once the clock
    /// has moved 10 s it ends. Fails if the wait trusts tokio's timer.
    #[tokio::test(start_paused = true)]
    async fn a_wall_jump_does_not_end_the_wait_and_awake_time_does() {
        let clock = ManualClock::new(Tick::new(0));
        let waiting = {
            let clock = clock.clone();
            tokio::spawn(async move { sleep_on(&clock, Duration::from_secs(10)).await })
        };
        settle().await;
        tokio::time::advance(Duration::from_secs(60)).await;
        settle().await;
        assert!(!waiting.is_finished(), "the wall jump ended the wait");
        clock.set(Tick::new(10 * SECOND));
        tokio::time::advance(Duration::from_secs(10)).await;
        settle().await;
        assert!(waiting.is_finished(), "awake time did not end the wait");
    }

    /// **A timeout counts awake time too.** A future that never finishes,
    /// bounded at 5 s: a minute of tokio's time with the clock still is no
    /// timeout; 5 s on the clock is. Fails if `timeout` ends on tokio's
    /// timer alone.
    #[tokio::test(start_paused = true)]
    async fn a_timeout_counts_awake_time() {
        let clock = ManualClock::new(Tick::new(0));
        let bounded = {
            let clock = clock.clone();
            tokio::spawn(async move {
                timeout_on(&clock, Duration::from_secs(5), std::future::pending::<()>()).await
            })
        };
        settle().await;
        tokio::time::advance(Duration::from_secs(60)).await;
        settle().await;
        assert!(!bounded.is_finished(), "the wall jump ended the timeout");
        clock.set(Tick::new(5 * SECOND));
        tokio::time::advance(Duration::from_secs(5)).await;
        settle().await;
        assert_eq!(bounded.await.expect("joined"), Err(Elapsed));
    }

    /// **An output ready in time is kept.** Fails if the timeout drops a
    /// finished future.
    #[tokio::test(start_paused = true)]
    async fn an_output_in_time_is_kept() {
        let clock = ManualClock::new(Tick::new(0));
        assert_eq!(
            timeout_on(&clock, Duration::from_secs(5), async { 7 }).await,
            Ok(7)
        );
        assert_eq!(clock.now(), Tick::new(0));
    }

    /// **A budget starts when the wait is built.** An unpolled `sleep` of
    /// 40 ms, held across 80 ms of awake time, is already done. Fails if
    /// the deadline is read at the first poll, which would wait another
    /// 40 ms here.
    #[tokio::test]
    async fn a_budget_starts_when_the_wait_is_built() {
        let waiting = sleep(Duration::from_millis(40));
        std::thread::sleep(Duration::from_millis(80));
        let started = std::time::Instant::now();
        waiting.await;
        assert!(
            started.elapsed() < Duration::from_millis(30),
            "the deadline was read at the first poll"
        );
    }

    /// **A timeout budget starts when the bound is built.** Same failure
    /// as the sleep budget: the deadline is read at the call.
    #[tokio::test]
    async fn a_timeout_budget_starts_when_the_bound_is_built() {
        let bounded = timeout(Duration::from_millis(40), std::future::pending::<()>());
        std::thread::sleep(Duration::from_millis(80));
        let started = std::time::Instant::now();
        assert_eq!(bounded.await, Err(Elapsed));
        assert!(
            started.elapsed() < Duration::from_millis(30),
            "the deadline was read at the first poll"
        );
    }
}
