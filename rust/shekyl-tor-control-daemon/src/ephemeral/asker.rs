// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The asks a supervisor sends and does not await (`TOR_SUPERVISOR.md`
//! §4.11; Rick, 2026-11-10: the supervisor never awaits Tor).
//!
//! A [`ControlAsker`] is a clone of one incarnation's control actor. The
//! supervisor hands it to a task that runs one request and posts the reply,
//! and goes straight back to its inbox. Nothing here holds a bound: the
//! supervisor's core holds it, one per request in flight. An ask still
//! waiting when the incarnation ends fails as the actor stops, so no task
//! outlives its Tor.
//!
//! [`DaemonTorControl`]'s own `publish`, `republish`, `ask` and
//! `defer_disk_writes` are these asks under the reply deadline, for a caller
//! that does await.
//!
//! [`DaemonTorControl`]: super::DaemonTorControl

use std::net::SocketAddr;

use kameo::actor::ActorRef;
use kameo::error::SendError;
use shekyl_tor_control_client::control::{
    evaluate_add_onion_reply, AddOnion, AddOnionReplyError, Command, ControlError, ControlReply,
    DiskWrites, OnionFlags, OnionPort, OnionPow, ServiceId, TorControlClient,
};
use shekyl_tor_control_client::onion_identity::OnionIdentity;

use super::{
    pow_refusal, DaemonTorPublishError, DaemonTorStartError, DEL_ONION_REMOVED, DEL_ONION_UNKNOWN,
};

/// One incarnation's control actor, cloned for a request run off the loop.
#[derive(Clone)]
pub struct ControlAsker {
    actor: ActorRef<TorControlClient>,
}

/// Why an ask did not come back with a reply.
enum Unanswered {
    /// Tor answered with a control error.
    Control(ControlError),
    /// The actor ended: this incarnation is gone.
    Gone,
}

impl ControlAsker {
    pub(super) fn new(actor: ActorRef<TorControlClient>) -> Self {
        Self { actor }
    }

    async fn send(&self, command: Command) -> Result<ControlReply, Unanswered> {
        match self.actor.ask(command).await {
            Ok(reply) => Ok(reply),
            Err(SendError::HandlerError(error)) => Err(Unanswered::Control(error)),
            Err(_gone) => Err(Unanswered::Gone),
        }
    }

    /// One control command, answered when Tor answers.
    ///
    /// # Errors
    /// [`DaemonTorStartError::Control`] for a control error, and
    /// [`DaemonTorStartError::Died`] when the incarnation has ended.
    pub async fn ask(&self, command: Command) -> Result<ControlReply, DaemonTorStartError> {
        self.send(command)
            .await
            .map_err(|unanswered| match unanswered {
                Unanswered::Control(error) => DaemonTorStartError::Control(error),
                Unanswered::Gone => DaemonTorStartError::Died(None),
            })
    }

    /// `SETCONF AvoidDiskWrites=1` on the owning connection.
    ///
    /// # Errors
    /// As [`Self::ask`].
    pub async fn defer_disk_writes(&self) -> Result<(), DaemonTorStartError> {
        self.ask(Command::SetConfDiskWrites(DiskWrites::Deferred))
            .await
            .map(|_| ())
    }

    /// `DEL_ONION` for `identity`'s service, the first half of a republish.
    /// Tor refuses an `ADD_ONION` for a service it still holds, so a
    /// republish deletes first. The delete's `552` (no such service: a fresh
    /// Tor, or one that lost it) is the same as a `250`: nothing of ours is
    /// loaded.
    ///
    /// # Errors
    /// [`DaemonTorPublishError::Publish`] for any other status, and the
    /// control and death errors of [`Self::add_onion`].
    pub async fn delete_onion(
        &self,
        identity: &OnionIdentity,
    ) -> Result<(), DaemonTorPublishError> {
        let reply = self
            .send(Command::DelOnion(identity.service_id().clone()))
            .await
            .map_err(publish_error)?;
        match reply.status() {
            DEL_ONION_REMOVED | DEL_ONION_UNKNOWN => Ok(()),
            status => Err(DaemonTorPublishError::Publish(
                AddOnionReplyError::Rejected { status },
            )),
        }
    }

    /// `ADD_ONION` for `identity`, which stays with the caller, on
    /// `local_target` (loopback only, enforced by [`OnionPort::loopback`]).
    /// One key is minted from `identity` for this ask. A 512 or 513 whose
    /// reply names a proof-of-work argument is
    /// [`DaemonTorPublishError::PowRefused`].
    ///
    /// # Errors
    /// [`DaemonTorPublishError::TargetNotLoopback`], a refusal, a control
    /// error, or [`DaemonTorPublishError::Died`].
    pub async fn add_onion(
        &self,
        identity: &OnionIdentity,
        virtual_port: u16,
        local_target: SocketAddr,
        max_streams: u16,
        pow: OnionPow,
    ) -> Result<ServiceId, DaemonTorPublishError> {
        let port = OnionPort::loopback(virtual_port, local_target).ok_or(
            DaemonTorPublishError::TargetNotLoopback {
                target: local_target,
            },
        )?;
        let expected = identity.service_id().clone();
        let request = AddOnion::new(identity.mint_onion_key(), port, max_streams)
            .with_flags(OnionFlags { discard_pk: true })
            .with_pow(pow);
        let reply = self
            .send(Command::AddOnion(request))
            .await
            .map_err(publish_error)?;
        if let Some(refused) = pow_refusal(pow, reply.status(), reply.lines()) {
            return Err(refused);
        }
        evaluate_add_onion_reply(&reply, &expected).map_err(DaemonTorPublishError::Publish)?;
        Ok(expected)
    }
}

fn publish_error(unanswered: Unanswered) -> DaemonTorPublishError {
    match unanswered {
        Unanswered::Control(error) => DaemonTorPublishError::Control(error),
        Unanswered::Gone => DaemonTorPublishError::Died,
    }
}
