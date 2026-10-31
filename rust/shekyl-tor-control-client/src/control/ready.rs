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
#[derive(Debug)]
pub enum AskError {
    /// The deadline elapsed with no reply.
    Timeout,
    /// The command handler returned a control-level error.
    Control(ControlError),
    /// The actor was stopped or not running — a death, not a control fault.
    ActorGone,
}

/// How late a timer must fire to mean the machine slept (`TOR_SUPERVISOR.md`
/// §5, "Resumed from suspend"; Rick, 2026-10-30). Rust's `Instant` counts
/// through a sleep on Windows and stops on Linux and macOS (`TSR-M8`), so on
/// Windows every deadline armed before a sleep comes due at once on wake.
/// A timer is late only when the process could not run: the scheduler's
/// lateness is milliseconds, even on the floor device. Twice the bootstrap's
/// sample interval (5 s) is far past that, and a sleep shorter than it adds
/// under a third of the shortest bound it protects, the 30 s reply bound.
/// The supervisor's own deadlines use the same value
/// (`Policy::resumed_after`).
pub const RESUMED_AFTER: Duration = Duration::from_secs(10);

/// One bounded control round-trip. A stall is [`AskError::Timeout`] rather than
/// hanging the caller.
///
/// The bound counts awake time on every platform: a bound found expired more
/// than [`RESUMED_AFTER`] late means the machine slept with the ask
/// outstanding, and Tor, asleep too, never had the chance to answer. The
/// bound starts again from the wake, and the same reply is still awaited.
/// A wedged Tor still times out after a full awake bound.
pub async fn ask_timed(
    actor: &ActorRef<TorControlClient>,
    command: Command,
    deadline: Duration,
) -> Result<ControlReply, AskError> {
    let answer = std::future::IntoFuture::into_future(actor.ask(command));
    tokio::pin!(answer);
    let mut due = tokio::time::Instant::now() + deadline;
    let reply = loop {
        tokio::select! {
            reply = &mut answer => break reply,
            () = tokio::time::sleep_until(due) => {
                let now = tokio::time::Instant::now();
                if now.saturating_duration_since(due) <= RESUMED_AFTER {
                    return Err(AskError::Timeout);
                }
                due = now + deadline;
            }
        }
    };
    match reply {
        Ok(reply) => Ok(reply),
        Err(SendError::HandlerError(control)) => Err(AskError::Control(control)),
        Err(_send) => Err(AskError::ActorGone),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use kameo::actor::Spawn;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};

    use super::{ask_timed, AskError};
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
}
