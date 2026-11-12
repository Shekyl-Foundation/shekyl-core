// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Waits that count awake time (Rick, 2026-11-11).
//!
//! A tokio timer counts from tokio's clock, which on Windows runs through a
//! machine's sleep: a wait armed before the sleep ends at the wake whatever
//! is left of it. These waits sleep on tokio's timer and, each time it
//! returns, read the [`Clock`] they were given. They end only once the
//! deadline has passed on that clock, so with the process clock
//! ([`crate::MonotonicClock`]) a sleep counts for nothing. Code that has no
//! timing engine uses them where a timer's end would tear something down.

use std::future::Future;
use std::pin::pin;
use std::task::Poll;
use std::time::Duration;

use crate::{Clock, Tick};

/// The deadline `within` from now on `clock`.
pub fn deadline_after<C: Clock + ?Sized>(clock: &C, within: Duration) -> Tick {
    let within = u64::try_from(within.as_nanos()).unwrap_or(u64::MAX);
    Tick::new(clock.now().get().saturating_add(within))
}

/// Wait until `deadline` has passed on `clock`.
pub async fn sleep_until<C: Clock + ?Sized>(clock: &C, deadline: Tick) {
    loop {
        let now = clock.now().get();
        if now >= deadline.get() {
            return;
        }
        tokio::time::sleep(Duration::from_nanos(deadline.get() - now)).await;
    }
}

/// Wait `within` of `clock`'s time.
pub async fn sleep<C: Clock + ?Sized>(clock: &C, within: Duration) {
    sleep_until(clock, deadline_after(clock, within)).await;
}

/// `within` of the clock's time passed before the future finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Elapsed;

impl std::fmt::Display for Elapsed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the wait's time passed")
    }
}

impl std::error::Error for Elapsed {}

/// `future`'s output, or [`Elapsed`] once `within` of `clock`'s time has
/// passed. The future is polled first, so an output ready at the deadline
/// is kept.
///
/// # Errors
/// [`Elapsed`] when the time passed first.
pub async fn timeout<C, F>(clock: &C, within: Duration, future: F) -> Result<F::Output, Elapsed>
where
    C: Clock + ?Sized,
    F: Future,
{
    let deadline = deadline_after(clock, within);
    let mut future = pin!(future);
    let mut waited = pin!(sleep_until(clock, deadline));
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

    use super::{sleep, timeout, Elapsed};
    use crate::{Clock, ManualClock, Tick};

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
            tokio::spawn(async move { sleep(&clock, Duration::from_secs(10)).await })
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
                timeout(&clock, Duration::from_secs(5), std::future::pending::<()>()).await
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
            timeout(&clock, Duration::from_secs(5), async { 7 }).await,
            Ok(7)
        );
        assert_eq!(clock.now(), Tick::new(0));
    }
}
