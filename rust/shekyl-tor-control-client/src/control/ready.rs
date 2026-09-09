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
/// telemetry, not a gate.
pub async fn wait_until_ready(
    actor: &ActorRef<TorControlClient>,
    ready_rx: &mut watch::Receiver<BootstrapState>,
    deadline: tokio::time::Instant,
) -> Result<(), WaitReadyError> {
    loop {
        tokio::select! {
            () = actor.wait_for_shutdown() => return Err(WaitReadyError::Died),
            () = tokio::time::sleep_until(deadline) => return Err(WaitReadyError::Timeout),
            changed = ready_rx.changed() => {
                if changed.is_err() {
                    return Err(WaitReadyError::Died);
                }
                match *ready_rx.borrow_and_update() {
                    BootstrapState::Ready => return Ok(()),
                    BootstrapState::Failed => return Err(WaitReadyError::Failed),
                    BootstrapState::Connecting { .. } => {}
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

/// One bounded control round-trip. A stall is [`AskError::Timeout`] rather than
/// hanging the caller.
pub async fn ask_timed(
    actor: &ActorRef<TorControlClient>,
    command: Command,
    deadline: Duration,
) -> Result<ControlReply, AskError> {
    match tokio::time::timeout(deadline, actor.ask(command)).await {
        Err(_elapsed) => Err(AskError::Timeout),
        Ok(Ok(reply)) => Ok(reply),
        Ok(Err(SendError::HandlerError(control))) => Err(AskError::Control(control)),
        Ok(Err(_send)) => Err(AskError::ActorGone),
    }
}
