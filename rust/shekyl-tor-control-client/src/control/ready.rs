// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared bootstrap-gate and bounded-ask helpers (PWD-E9: protocol-lifecycle
//! shape, not instance identity).
//!
//! Both supervisors wait for [`BootstrapState::Ready`] and issue bounded
//! control round-trips. Duplicating those loops is the ruled-against error
//! (`parse_socks_listeners` already moved for the same reason). Wallet-only
//! concerns (shutdown select, connecting telemetry) stay in the wallet
//! supervisor.

use std::time::Duration;

use kameo::actor::ActorRef;
use kameo::error::SendError;
use tokio::sync::watch;

use super::actor::{Command, ControlError, TorControlClient};
use super::bootstrap::BootstrapState;
use super::framing::ControlReply;

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

/// Why a bounded control round-trip failed.
///
/// A failure is still a wait that ended. [`Self::resume`] is what that wait
/// says about the machine, so a connection that dies across a sleep does not
/// throw the sleep away with the reply.
#[derive(Debug)]
pub enum AskError {
    /// The deadline elapsed with no reply, and it elapsed on time. A bound
    /// found late is not this: the wait starts again ([`ask_timed`]).
    Timeout,
    /// The command handler returned a control-level error.
    Control {
        /// The control fault.
        error: ControlError,
        /// Whether the machine slept while the ask was outstanding.
        resume: Resume,
    },
    /// The actor was stopped or not running — a death, not a control fault.
    ActorGone {
        /// Whether the machine slept before the actor went away.
        resume: Resume,
    },
}

impl AskError {
    /// Whether the machine slept during the wait that failed.
    ///
    /// A timeout is an on-time bound. The sleep re-arms that bound instead
    /// of failing it, so a timeout has nothing to report.
    #[must_use]
    pub const fn resume(&self) -> Resume {
        match self {
            Self::Timeout => Resume::Awake,
            Self::Control { resume, .. } | Self::ActorGone { resume } => *resume,
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

impl Resume {
    /// The later sleep. An awake observation leaves `self` as it was, so a
    /// republish's delete and add keep one sleep between them.
    #[must_use]
    pub const fn later(self, later: Self) -> Self {
        match later {
            Self::Slept { .. } => later,
            Self::Awake => self,
        }
    }
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

/// A bounded ask that finished, and whether the machine slept during it.
pub struct Asked {
    reply: ControlReply,
    resume: Resume,
}

impl Asked {
    /// The control reply.
    #[must_use]
    pub fn reply(&self) -> &ControlReply {
        &self.reply
    }

    /// The reply, dropping the sleep observation. A caller that has already
    /// recorded [`Self::resume`] uses this.
    #[must_use]
    pub fn into_reply(self) -> ControlReply {
        self.reply
    }

    /// Whether the machine slept with this ask outstanding.
    #[must_use]
    pub const fn resume(&self) -> Resume {
        self.resume
    }

    /// The reply's status code.
    #[must_use]
    pub fn status(&self) -> u16 {
        self.reply.status()
    }

    /// The reply's text lines.
    #[must_use]
    pub fn lines(&self) -> &[String] {
        self.reply.lines()
    }
}

impl std::fmt::Debug for Asked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // [`ControlReply`]'s `Debug` already withholds the lines.
        f.debug_struct("Asked")
            .field("reply", &self.reply)
            .field("resume", &self.resume)
            .finish()
    }
}

/// One bounded control round-trip. A stall is [`AskError::Timeout`] rather than
/// hanging the caller.
///
/// The bound counts awake time on every platform. [`resume_lateness`] on this
/// wait is how a sleep is told from a slow Tor: a bound found more than
/// [`RESUMED_AFTER`] late means the machine slept with the ask outstanding,
/// and Tor, asleep too, never had the chance to answer. The bound starts
/// again from the wake, the same reply is still awaited, and [`Asked::resume`]
/// carries the lateness so the supervisor can restart its own windows before
/// it folds the reply. A wedged Tor still times out after one awake bound.
pub async fn ask_timed(
    actor: &ActorRef<TorControlClient>,
    command: Command,
    deadline: Duration,
) -> Result<Asked, AskError> {
    let answer = std::future::IntoFuture::into_future(actor.ask(command));
    tokio::pin!(answer);
    let mut started = tokio::time::Instant::now();
    let mut due = started + deadline;
    let mut resume = Resume::Awake;
    let reply = loop {
        tokio::select! {
            reply = &mut answer => {
                let now = tokio::time::Instant::now();
                resume = resume.later(resume_lateness(
                    due.saturating_duration_since(started),
                    now.saturating_duration_since(started),
                ));
                break reply;
            }
            () = tokio::time::sleep_until(due) => {
                let now = tokio::time::Instant::now();
                let observed = resume_lateness(
                    due.saturating_duration_since(started),
                    now.saturating_duration_since(started),
                );
                match observed {
                    Resume::Slept { .. } => {
                        resume = resume.later(observed);
                        started = now;
                        due = now + deadline;
                    }
                    Resume::Awake => return Err(AskError::Timeout),
                }
            }
        }
    };
    match reply {
        Ok(reply) => Ok(Asked { reply, resume }),
        Err(SendError::HandlerError(error)) => Err(AskError::Control { error, resume }),
        Err(_send) => Err(AskError::ActorGone { resume }),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use kameo::actor::Spawn;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};

    use super::{ask_timed, resume_lateness, AskError, Resume, RESUMED_AFTER};
    use crate::control::actor::{
        BootstrapReadiness, Command, EventSink, TorControlClient, TorControlClientConfig, TorLaunch,
    };

    const BOUND: Duration = Duration::from_secs(30);

    /// A Tor that answers every command in order. Before it answers the
    /// first `GETINFO version` it lets `before_reply` time pass on the
    /// paused clock, or, with `None`, never answers it.
    async fn tor(stream: DuplexStream, before_reply: Option<Duration>) {
        let (read, mut write) = tokio::io::split(stream);
        let mut lines = BufReader::new(read).lines();
        let mut held = false;
        while let Ok(Some(command)) = lines.next_line().await {
            if command == "GETINFO version" && !held {
                held = true;
                let Some(slept) = before_reply else {
                    std::future::pending::<()>().await;
                    return;
                };
                tokio::time::advance(slept).await;
                if write
                    .write_all(b"250-version=0.4.9.14\r\n250 OK\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                continue;
            }
            if write.write_all(b"250 OK\r\n").await.is_err() {
                return;
            }
        }
    }

    fn client(stream: DuplexStream) -> kameo::actor::ActorRef<TorControlClient> {
        let (read, write) = tokio::io::split(stream);
        let (events, _received) = EventSink::bounded();
        let (readiness, _ready) = BootstrapReadiness::new();
        TorControlClient::spawn(TorControlClientConfig {
            launch: TorLaunch::Connected {
                read: Box::pin(read),
                write: Box::pin(write),
            },
            events,
            readiness,
        })
    }

    fn version() -> Command {
        Command::GetInfo(vec!["version".to_owned()])
    }

    /// A ten-minute sleep with the ask outstanding (the paused clock jumps,
    /// as Windows' `Instant` does across Modern Standby, `TSR-M8`) is not a
    /// late reply: the bound starts again at the wake, and Tor's answer
    /// arrives inside it. Timing the bound on the raw clock fails this.
    #[tokio::test(start_paused = true)]
    async fn a_sleep_with_an_ask_outstanding_is_not_a_late_reply() {
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        let peer = tokio::spawn(tor(theirs, Some(Duration::from_secs(600))));
        let actor = client(ours);
        let reply = ask_timed(&actor, version(), BOUND)
            .await
            .expect("answered after the wake");
        assert_eq!(reply.status(), 250);
        assert_eq!(
            reply.resume(),
            Resume::Slept {
                late_by: Duration::from_secs(570)
            },
            "the bound was 30 s; the clock jumped 600 s"
        );
        peer.abort();
    }

    /// A reply inside the bound is an awake wait, however long it took.
    /// The supervisor's sample interval is 5 s and its resume threshold is
    /// 10 s, so a 20 s reply is past both and still not a sleep: the bound
    /// being waited on is 30 s. Reading the sample interval's deadline as
    /// the wait fails this.
    #[tokio::test(start_paused = true)]
    async fn a_slow_reply_inside_the_bound_is_awake() {
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        let peer = tokio::spawn(tor(theirs, Some(Duration::from_secs(20))));
        let actor = client(ours);
        let reply = ask_timed(&actor, version(), BOUND)
            .await
            .expect("answered inside the bound");
        assert_eq!(reply.status(), 250);
        assert_eq!(reply.resume(), Resume::Awake);
        peer.abort();
    }

    /// A Tor that never answers still times out after one awake bound: the
    /// bound found expired on time is a wedge, not a sleep.
    #[tokio::test(start_paused = true)]
    async fn a_wedged_tor_times_out_after_one_bound() {
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        let peer = tokio::spawn(tor(theirs, None));
        let actor = client(ours);
        let started = tokio::time::Instant::now();
        let outcome = ask_timed(&actor, version(), BOUND).await;
        assert!(matches!(outcome, Err(AskError::Timeout)), "{outcome:?}");
        assert_eq!(started.elapsed(), BOUND);
        peer.abort();
    }

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
