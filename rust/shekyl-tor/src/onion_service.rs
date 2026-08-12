// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Persona onion-service publish surface for the wallet-owned Tor supervisor.
//!
//! This module owns the **configuration** and **per-incarnation publish
//! orchestration** for a serving persona's v3 onion:
//!
//! - [`OnionServiceSpec`] — the least-privilege credential + port map the
//!   supervisor holds across incarnations (an [`OnionIdentity`], never a seed).
//! - [`OnionPublishError`] / [`publish_onion`] — drive `ADD_ONION` on a live
//!   control actor, map control faults, and surface protocol verdicts from
//!   [`crate::control::onion::evaluate_add_onion_reply`].
//!
//! The pure reply→verdict decision lives in [`crate::control::onion`] (it is
//! control-protocol knowledge, next to
//! [`parse_service_id`](crate::control::onion::parse_service_id)). The supervisor
//! loop in [`crate::service`] only asks *when* to publish and how a failure
//! classifies into the retry/degrade policy.

use std::net::SocketAddr;
use std::time::Duration;

use kameo::error::SendError;
use tokio::sync::oneshot;

use crate::control::onion::{
    evaluate_add_onion_reply, AddOnion, AddOnionReplyError, OnionFlags, OnionPort, OnionPow,
    ServiceId,
};
use crate::control::{Command, ControlError, TorControl};
use crate::onion_identity::OnionIdentity;

/// Why publishing the configured onion service failed.
///
/// Protocol verdicts ([`Self::Rejected`], [`Self::NoServiceId`],
/// [`Self::ServiceIdMismatch`]) come from [`evaluate_add_onion_reply`];
/// [`Self::Control`] is the transport/actor path that never produced a usable
/// reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnionPublishError {
    /// The control channel failed (or the reply timed out) during `ADD_ONION`.
    Control(ControlError),
    /// Tor answered with a non-250 status.
    Rejected {
        /// The status tor returned.
        status: u16,
    },
    /// A 250 reply with no parseable `ServiceID=` line.
    NoServiceId,
    /// Tor published a **different address** than the one the held
    /// [`OnionIdentity`] implies — serving at an address the persona does not
    /// advertise is an unreachable service that looks healthy from the inside.
    /// (Both ids redact under `Debug`.)
    ServiceIdMismatch {
        /// The address derived from the held identity.
        expected: ServiceId,
        /// The address tor reported.
        published: ServiceId,
    },
}

impl From<AddOnionReplyError> for OnionPublishError {
    fn from(err: AddOnionReplyError) -> Self {
        match err {
            AddOnionReplyError::Rejected { status } => Self::Rejected { status },
            AddOnionReplyError::NoServiceId => Self::NoServiceId,
            AddOnionReplyError::ServiceIdMismatch {
                expected,
                published,
            } => Self::ServiceIdMismatch {
                expected,
                published,
            },
        }
    }
}

/// Why a per-incarnation publish aborted before a successful `ADD_ONION`.
///
/// Separated from [`OnionPublishError`] so the supervisor can map
/// shutdown/actor-death onto its own incarnation-end vocabulary without
/// stuffing those into the publish-failure diagnostic.
#[derive(Debug)]
pub enum OnionPublishAbort {
    /// Caller requested supervisor shutdown mid-publish.
    Shutdown,
    /// The control actor died (or was not running) while the command was in
    /// flight — not a protocol-level publish fault.
    ActorGone,
    /// Publish failed with a diagnosable cause (control fault or reply verdict).
    Failed(OnionPublishError),
}

/// The persona's onion service, as supervisor configuration: everything the
/// supervisor needs to (re-)publish the service on **every** incarnation.
///
/// `Detach` is unrepresentable in the `ADD_ONION` surface, so a published
/// onion dies with its incarnation; the supervisor mints a fresh one-shot
/// key from the held [`OnionIdentity`] and republishes at the *same* address
/// on each Ready transition.
///
/// **The boundary is an [`OnionIdentity`], never a seed** — the least-
/// privilege credential (the expanded onion key authorizes exactly one
/// thing, publishing this onion), derived once in the wallet context. A
/// serving config that cannot hold a seed cannot hold `master_seed`, so the
/// cold/hot bond-authority separation (§7.2(iii)) is structural here rather
/// than a wiring convention. See [`crate::onion_identity::OnionIdentity`].
///
/// **One `Option` on the supervisor config, not a `Vec`, deliberately:** one
/// persona on the wire per wallet is the Model D co-activation rule, and the
/// SP-T3 spike priced multi-persona co-serving as a forbidden layout. A
/// service instance that can hold at most one onion makes that layout
/// unrepresentable; a second persona is a second wallet process with its own
/// `TorService` (and its own guard identity).
pub struct OnionServiceSpec {
    /// The wallet-derived serving identity (expanded key + address); the
    /// supervisor mints a one-shot `OnionKey` from it per incarnation.
    identity: OnionIdentity,
    /// The virtual-port → loopback-target mapping (loopback enforced at
    /// construction by [`OnionPort::loopback`]).
    port: OnionPort,
    /// Per-rendezvous-circuit stream cap (`MaxStreams`, with
    /// `MaxStreamsCloseCircuit` always on — the wire assembly pins that).
    ///
    /// **Carried placeholder (SPIKE-PIN-1), not a derivation.** A witness
    /// drawn for several of one `P`'s shards in the same block opens
    /// concurrent streams on *one* rendezvous circuit, so this interacts
    /// with the λ=3 per-pair concurrency finding; the W₂ rig derives the
    /// real value. Parameterized (not hardcoded) so the rig chooses it.
    max_streams: u16,
    /// PoW defense posture; defaults to [`OnionPow::Enabled`].
    pow: OnionPow,
}

impl OnionServiceSpec {
    /// A spec publishing `virtual_port` onto the loopback `target`, keyed by
    /// the wallet-derived `identity`. Returns `None` when `target` is not
    /// loopback (hard invariant 4, enforced where the mapping is created).
    ///
    /// Takes an [`OnionIdentity`] — the expanded credential, never a seed
    /// (see the type doc's custody boundary). `HiddenServicePoW` defaults
    /// **on** ([`OnionPow::Enabled`]) — the TJ-H ruling pins PoW for serving
    /// personas as part of the guard-discovery mitigation set;
    /// [`Self::with_pow`] exists for measurement arms that price the other
    /// postures, not as a production opt-out.
    #[must_use]
    pub fn new(
        identity: OnionIdentity,
        virtual_port: u16,
        target: SocketAddr,
        max_streams: u16,
    ) -> Option<Self> {
        let port = OnionPort::loopback(virtual_port, target)?;
        Some(Self {
            identity,
            port,
            max_streams,
            pow: OnionPow::Enabled,
        })
    }

    /// Override the PoW posture (measurement arms; production keeps the
    /// default).
    #[must_use]
    pub fn with_pow(mut self, pow: OnionPow) -> Self {
        self.pow = pow;
        self
    }

    /// The `.onion` address this spec publishes at — so the caller can
    /// advertise it (and dial it) without waiting for a Ready posture. The
    /// supervisor fail-stops any incarnation where tor reports a different
    /// id.
    #[must_use]
    pub fn service_id(&self) -> &ServiceId {
        self.identity.service_id()
    }

    /// PoW posture this spec will request on every `ADD_ONION`.
    #[must_use]
    pub fn pow(&self) -> OnionPow {
        self.pow
    }
}

// The identity is the persona's serving key; redact wholesale.
impl std::fmt::Debug for OnionServiceSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnionServiceSpec").finish_non_exhaustive()
    }
}

/// Publish `spec`'s onion service on the current incarnation: mint a fresh
/// one-shot key from the held [`OnionIdentity`], `ADD_ONION`, and **fail-stop
/// unless tor reports exactly the held address** (the spike's
/// published-vs-derived cross-check, kept — a mismatch means the persona
/// would serve at an address it does not advertise). Teardown needs no
/// pairing: the actor's `on_stop` already `DEL_ONION`s everything it
/// published.
///
/// `reply_deadline` bounds the control reply only — `ADD_ONION` loads the key
/// and answers immediately; descriptor publication is asynchronous and is
/// **not** awaited here. A stall means a wedged control port, not a slow
/// network.
pub async fn publish_onion(
    actor: &kameo::actor::ActorRef<TorControl>,
    spec: &OnionServiceSpec,
    reply_deadline: Duration,
    shutdown: &mut oneshot::Receiver<()>,
) -> Result<(), OnionPublishAbort> {
    let expected = spec.identity.service_id().clone();
    // `discard_pk` always: the key is re-mintable from the held identity on
    // demand, so tor has no reason to keep a copy it could be asked to hand
    // back.
    let request = AddOnion::new(spec.identity.mint_onion_key(), spec.port, spec.max_streams)
        .with_flags(OnionFlags { discard_pk: true })
        .with_pow(spec.pow);

    let reply = tokio::select! {
        _ = &mut *shutdown => return Err(OnionPublishAbort::Shutdown),
        () = tokio::time::sleep(reply_deadline) => {
            return Err(OnionPublishAbort::Failed(OnionPublishError::Control(
                ControlError::Timeout,
            )));
        }
        r = actor.ask(Command::AddOnion(request)) => r,
    };
    let reply = match reply {
        Ok(reply) => reply,
        // Preserve the control-level cause; an actor-stopped send error is a
        // death, not a publish fault.
        Err(SendError::HandlerError(e)) => {
            return Err(OnionPublishAbort::Failed(OnionPublishError::Control(e)));
        }
        Err(_) => return Err(OnionPublishAbort::ActorGone),
    };
    evaluate_add_onion_reply(&reply, &expected)
        .map_err(|e| OnionPublishAbort::Failed(OnionPublishError::from(e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::onion::evaluate_add_onion_reply;
    use crate::control::ReplyFramer;

    fn identity_and_id() -> (OnionIdentity, ServiceId) {
        let identity = OnionIdentity::from_hs_id_seed(&[0x24u8; 32]);
        let id = identity.service_id().clone();
        (identity, id)
    }

    fn reply_from(payload: &str) -> crate::control::ControlReply {
        let mut framer = ReplyFramer::new();
        framer.push_bytes(format!("250-{payload}\r\n250 OK\r\n").as_bytes());
        framer
            .next_reply()
            .expect("well-formed")
            .expect("one reply")
    }

    #[test]
    fn add_onion_reply_accepts_the_derived_address() {
        let (_identity, id) = identity_and_id();
        let reply = reply_from(&format!("ServiceID={}", id.as_str()));
        assert_eq!(evaluate_add_onion_reply(&reply, &id), Ok(()));
    }

    #[test]
    fn add_onion_reply_fail_stops_on_a_different_address() {
        // The load-bearing check: tor published *a* service, but not the
        // persona's. Publishing Ready here would advertise an address no
        // witness can reach.
        let (_identity, expected) = identity_and_id();
        let other = OnionIdentity::from_hs_id_seed(&[0x99u8; 32])
            .service_id()
            .clone();
        let reply = reply_from(&format!("ServiceID={}", other.as_str()));
        assert_eq!(
            evaluate_add_onion_reply(&reply, &expected),
            Err(AddOnionReplyError::ServiceIdMismatch {
                expected,
                published: other,
            })
        );
    }

    #[test]
    fn add_onion_reply_without_a_service_id_is_a_publish_failure() {
        let (_identity, expected) = identity_and_id();
        let reply = reply_from("version=0.4.9.11");
        assert_eq!(
            evaluate_add_onion_reply(&reply, &expected),
            Err(AddOnionReplyError::NoServiceId)
        );
    }

    #[test]
    fn add_onion_non_250_carries_the_status() {
        let mut framer = ReplyFramer::new();
        framer.push_bytes(b"550 Onion address collision\r\n");
        let reply = framer
            .next_reply()
            .expect("well-formed")
            .expect("one reply");
        let (_identity, expected) = identity_and_id();
        assert_eq!(
            evaluate_add_onion_reply(&reply, &expected),
            Err(AddOnionReplyError::Rejected { status: 550 })
        );
    }

    #[test]
    fn reply_error_maps_into_publish_error() {
        let (_identity, expected) = identity_and_id();
        let published = OnionIdentity::from_hs_id_seed(&[0x99u8; 32])
            .service_id()
            .clone();
        assert_eq!(
            OnionPublishError::from(AddOnionReplyError::NoServiceId),
            OnionPublishError::NoServiceId
        );
        assert_eq!(
            OnionPublishError::from(AddOnionReplyError::Rejected { status: 551 }),
            OnionPublishError::Rejected { status: 551 }
        );
        assert_eq!(
            OnionPublishError::from(AddOnionReplyError::ServiceIdMismatch {
                expected: expected.clone(),
                published: published.clone(),
            }),
            OnionPublishError::ServiceIdMismatch {
                expected,
                published,
            }
        );
    }

    #[test]
    fn onion_spec_refuses_a_non_loopback_target() {
        let (identity, _id) = identity_and_id();
        // A routable target would make the endpoint reachable off the onion.
        assert!(OnionServiceSpec::new(identity, 80, "8.8.8.8:1234".parse().unwrap(), 8).is_none());
    }

    #[test]
    fn onion_spec_advertises_the_derived_address_and_defaults_pow_on() {
        let (identity, id) = identity_and_id();
        let spec = OnionServiceSpec::new(identity, 80, "127.0.0.1:9000".parse().unwrap(), 8)
            .expect("loopback target");
        assert_eq!(spec.service_id(), &id, "advertised == derived, pre-Ready");
        assert_eq!(
            spec.pow(),
            OnionPow::Enabled,
            "HiddenServicePoW on by default"
        );
    }

    #[test]
    fn onion_spec_debug_redacts() {
        let (identity, id) = identity_and_id();
        let spec = OnionServiceSpec::new(identity, 80, "127.0.0.1:9000".parse().unwrap(), 8)
            .expect("loopback");
        let rendered = format!("{spec:?}");
        assert!(!rendered.contains(id.as_str()));
        assert!(rendered.contains("OnionServiceSpec"));
    }
}
