// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared bootstrap-gate and sleep-classification helpers (PWD-E9:
//! protocol-lifecycle shape, not instance identity).
//!
//! Both supervisors wait for [`BootstrapState::Ready`]. Duplicating that
//! loop is the ruled-against error
//! (`parse_socks_listeners` already moved for the same reason). Wallet-only
//! concerns (shutdown select, connecting telemetry) stay in the wallet
//! supervisor.

use std::time::Duration;

use kameo::actor::ActorRef;
use tokio::sync::watch;

use super::actor::TorControlClient;
use super::bootstrap::BootstrapState;

/// Why [`wait_until_ready`] did not observe [`BootstrapState::Ready`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitReadyError {
    /// The deadline elapsed with no `Ready`.
    Timeout,
    /// The actor stopped (or the readiness sender closed) before `Ready`.
    Died,
    /// Bootstrap published [`BootstrapState::Failed`].
    Failed,
}

/// Drive `ready_rx` until [`BootstrapState::Ready`], the actor dies, bootstrap
/// fails, or `deadline` elapses. Connecting progress is ignored — it is
/// telemetry, not a gate. The **current** value is examined first: a
/// subscriber that attaches after `Ready` or `Failed` must not wait for a
/// further change that will never come.
pub async fn wait_until_ready(
    actor: &ActorRef<TorControlClient>,
    ready_rx: &mut watch::Receiver<BootstrapState>,
    deadline: tokio::time::Instant,
) -> Result<(), WaitReadyError> {
    loop {
        match *ready_rx.borrow_and_update() {
            BootstrapState::Ready => return Ok(()),
            BootstrapState::Failed => return Err(WaitReadyError::Failed),
            BootstrapState::Connecting { .. } => {}
        }
        tokio::select! {
            () = actor.wait_for_shutdown() => return Err(WaitReadyError::Died),
            () = tokio::time::sleep_until(deadline) => return Err(WaitReadyError::Timeout),
            changed = ready_rx.changed() => {
                if changed.is_err() {
                    return Err(WaitReadyError::Died);
                }
            }
        }
    }
}

/// How late a waited timer must fire to mean the machine slept
/// (`TOR_SUPERVISOR.md` §5, "Resumed from suspend"; Rick, 2026-10-30).
/// Rust's `Instant` counts through a sleep on Windows and stops on Linux
/// and macOS (`TSR-M8`), so on Windows a timer armed before a sleep fires
/// late at the wake. The scheduler's own lateness is milliseconds, even on
/// the floor device. Twice the bootstrap's sample interval (5 s) is far
/// past that, and a sleep shorter than it adds under a third of the
/// shortest bound it protects, the 30 s reply bound.
pub const RESUMED_AFTER: Duration = Duration::from_secs(10);

/// What a timer the caller was actually waiting on says about the machine.
///
/// A deadline found late because the driver was busy in another ask is not
/// this. The wait has to be the thing that returned.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Resume {
    /// The timer fired within [`RESUMED_AFTER`] of its deadline, or the
    /// deadline was already past when the wait began. Overdue work, not a
    /// sleep.
    #[default]
    Awake,
    /// The process did not run. `late_by` is how far past the deadline the
    /// timer was found.
    Slept {
        /// How far past the deadline the waited timer fired.
        late_by: Duration,
    },
}

/// Classify a wait that has returned.
///
/// `until_due` is how far the deadline was when the wait began. Zero means
/// the deadline was already past: an immediate return is overdue work.
/// `waited` is how long the wait actually ran. `Slept` when it ran more
/// than [`RESUMED_AFTER`] past the deadline.
///
/// Not `const`: `Duration`'s ordering is not a const operation on this
/// toolchain.
#[must_use]
pub fn resume_lateness(until_due: Duration, waited: Duration) -> Resume {
    let limit = until_due.saturating_add(RESUMED_AFTER);
    if waited > limit {
        Resume::Slept {
            late_by: waited.saturating_sub(until_due),
        }
    } else {
        Resume::Awake
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{resume_lateness, Resume, RESUMED_AFTER};

    /// The select wake and the reply bound share this. A deadline already
    /// past when the wait begins is overdue work. A wait that returns more
    /// than [`RESUMED_AFTER`] after its deadline is a sleep.
    #[test]
    fn a_wait_classifies_a_sleep_and_leaves_overdue_work_awake() {
        let ten = RESUMED_AFTER;
        let five = Duration::from_secs(5);
        assert_eq!(resume_lateness(five, five), Resume::Awake);
        assert_eq!(resume_lateness(five, five + ten), Resume::Awake);
        assert_eq!(
            resume_lateness(five, five + ten + Duration::from_nanos(1)),
            Resume::Slept {
                late_by: ten + Duration::from_nanos(1)
            }
        );
        assert_eq!(
            resume_lateness(Duration::ZERO, Duration::ZERO),
            Resume::Awake
        );
        assert_eq!(
            resume_lateness(Duration::from_secs(30), Duration::from_secs(20)),
            Resume::Awake,
            "a 20 s reply inside a 30 s bound"
        );
    }
}
