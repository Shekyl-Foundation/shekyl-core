// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What an owner holds of a session (brief §7.3).
//!
//! [`Established`] is minted by the session layer alone, after the
//! handshake completes, and is the only way an owner reaches a session.
//! It dereferences to a [`SessionHandle`]: the facts observed at admission
//! and two verbs, [`SessionHandle::send`] and [`SessionHandle::close`].
//! There is no constructor an owner can reach, so a handler that takes
//! `&Established` cannot be called on a handshaking session: PWD-B1/B2
//! held by type (brief §2 rule 2).
//!
//! [`Message`] is the typed outbound set. The handshake and timed-sync
//! forms are not in it: those are the session layer's own, and the handle
//! refuses to send one on an owner's behalf by having no arm for it.

use std::fmt;
use std::ops::Deref;
use std::sync::Arc;

use shekyl_levin::{
    notify, Command, GetTxpoolComplement, NewBundle, NewCompactBlock, NewTransactions,
    PayloadError, PortableMap, RequestBodies, RequestBundleBodies, RequestCompactMissingTx,
    RequestHeaders, ResponseBodies, ResponseBundleBodies, ResponseHeaders,
};
use shekyl_transport_layer::{CloseCause, ConnectorId, Direction, SocketId};

use crate::endpoint::Endpoint;

/// One notification an owner sends. Each arm is a [`Command`] whose owner
/// is not the session layer; the Levin codec is `shekyl-levin`'s.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// 2002: a batch of transactions. The padding field stays empty on the
    /// wire (brief F1: the C++ never padded).
    NewTransactions(NewTransactions),
    /// 2008: an announced block.
    NewCompactBlock(NewCompactBlock),
    /// 2009: the transactions an announced block was missing.
    RequestCompactMissingTx(RequestCompactMissingTx),
    /// 2010: the pool hashes this node holds, asking for the rest.
    GetTxpoolComplement(GetTxpoolComplement),
    /// 2011: a header request.
    RequestHeaders(RequestHeaders),
    /// 2012: a header response.
    ResponseHeaders(ResponseHeaders),
    /// 2013: a body request.
    RequestBodies(RequestBodies),
    /// 2014: a body response.
    ResponseBodies(ResponseBodies),
    /// 2015: a bundle relayed between queues.
    NewBundle(NewBundle),
    /// 2016: bundle bodies asked for by hash.
    RequestBundleBodies(RequestBundleBodies),
    /// 2017: the bundle bodies held.
    ResponseBundleBodies(ResponseBundleBodies),
}

impl Message {
    /// The command this message is sent as.
    #[must_use]
    pub const fn command(&self) -> Command {
        match self {
            Self::NewTransactions(_) => Command::NewTransactions,
            Self::NewCompactBlock(_) => Command::NewCompactBlock,
            Self::RequestCompactMissingTx(_) => Command::RequestCompactMissingTx,
            Self::GetTxpoolComplement(_) => Command::GetTxpoolComplement,
            Self::RequestHeaders(_) => Command::RequestHeaders,
            Self::ResponseHeaders(_) => Command::ResponseHeaders,
            Self::RequestBodies(_) => Command::RequestBodies,
            Self::ResponseBodies(_) => Command::ResponseBodies,
            Self::NewBundle(_) => Command::NewBundle,
            Self::RequestBundleBodies(_) => Command::RequestBundleBodies,
            Self::ResponseBundleBodies(_) => Command::ResponseBundleBodies,
        }
    }

    /// The bucket, framed as a notification. Encode once and send the
    /// same [`Encoded`] to every session that gets it.
    ///
    /// # Errors
    /// The payload did not serialize: a value the codec's bounds refuse,
    /// or a payload over its command's cap
    /// ([`PayloadError::OverCap`]), which the peer's ingress refuses and
    /// closes the session for, so it is never queued.
    pub fn encode(&self) -> Result<Encoded, PayloadError> {
        let payload = match self {
            Self::NewTransactions(m) => m.store()?,
            Self::NewCompactBlock(m) => m.store()?,
            Self::RequestCompactMissingTx(m) => m.store()?,
            Self::GetTxpoolComplement(m) => m.store()?,
            Self::RequestHeaders(m) => m.store()?,
            Self::ResponseHeaders(m) => m.store()?,
            Self::RequestBodies(m) => m.store()?,
            Self::ResponseBodies(m) => m.store()?,
            Self::NewBundle(m) => m.store()?,
            Self::RequestBundleBodies(m) => m.store()?,
            Self::ResponseBundleBodies(m) => m.store()?,
        };
        let command = self.command();
        let max = usize::try_from(command.payload_cap()).unwrap_or(usize::MAX);
        if payload.len() > max {
            return Err(PayloadError::OverCap {
                got: payload.len(),
                max,
            });
        }
        Ok(Encoded {
            command,
            bytes: notify(command.wire_id(), &payload),
        })
    }
}

/// A [`Message`] framed as its bucket. Minted by [`Message::encode`] only,
/// so an owner cannot send bytes the typed set does not name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encoded {
    command: Command,
    bytes: Vec<u8>,
}

impl Encoded {
    /// The command the bucket carries.
    #[must_use]
    pub const fn command(&self) -> Command {
        self.command
    }

    /// The bucket's length on the wire, header included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// A bucket is never empty: it has a header.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Why a send did not queue.
#[derive(Debug)]
pub enum SendRefused {
    /// The connector's send queue is past its byte bound. The session
    /// layer has closed the session with the stamped end.
    QueueFull,
    /// The session has an end recorded, or its row is gone.
    Closed,
    /// The message did not serialize. Nothing was sent.
    Encoding(PayloadError),
}

impl fmt::Display for SendRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueueFull => f.write_str("the session's send queue is full; it is closing"),
            Self::Closed => f.write_str("the session is closed"),
            Self::Encoding(err) => write!(f, "the message did not encode: {err}"),
        }
    }
}

impl std::error::Error for SendRefused {}

/// The two verbs a handle reaches the layer with. Implemented by the
/// layer's shared state; never by an owner.
pub(crate) trait Control: Send + Sync {
    fn send(&self, id: SocketId, bytes: Vec<u8>) -> Result<(), SendRefused>;
    fn close(&self, id: SocketId, cause: CloseCause);
}

/// One session, as an owner addresses it.
///
/// Clones name the same session. The facts are the admission's and do not
/// change; the verbs reach the session layer, which alone moves the
/// session's state (brief §2 rules 3 and 4).
#[derive(Clone)]
pub struct SessionHandle {
    id: SocketId,
    endpoint: Endpoint,
    control: Arc<dyn Control>,
}

impl fmt::Debug for SessionHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionHandle")
            .field("id", &self.id)
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl SessionHandle {
    pub(crate) fn new(id: SocketId, endpoint: Endpoint, control: Arc<dyn Control>) -> Self {
        Self {
            id,
            endpoint,
            control,
        }
    }

    /// The admission id. There is no second id.
    #[must_use]
    pub const fn id(&self) -> SocketId {
        self.id
    }

    /// The connector that carries this session.
    #[must_use]
    pub const fn connector(&self) -> ConnectorId {
        self.endpoint.connector()
    }

    /// Accepted or dialed.
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.endpoint.direction()
    }

    /// The endpoint observed at admission.
    #[must_use]
    pub const fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Encode `message` and queue it on the connector's send queue.
    ///
    /// # Errors
    /// [`SendRefused`]: the queue is full (the session is then closing),
    /// the session is closed, or the message did not encode.
    pub fn send(&self, message: &Message) -> Result<(), SendRefused> {
        let encoded = message.encode().map_err(SendRefused::Encoding)?;
        self.send_encoded(&encoded)
    }

    /// Queue an already-encoded message. The bytes are copied: one
    /// [`Encoded`] goes to many sessions.
    ///
    /// # Errors
    /// [`SendRefused::QueueFull`] or [`SendRefused::Closed`].
    pub fn send_encoded(&self, encoded: &Encoded) -> Result<(), SendRefused> {
        self.control.send(self.id, encoded.bytes().to_vec())
    }

    /// Queue one window of the relay's covert carrier
    /// (`DAEMON_RELAY_PRIVACY.md` §42): a Levin frame the carrier built in
    /// `shekyl-levin`, a dummy (`noise_notify`) or one fragment of a stem
    /// (`fragmented_notify`), every window the same length. Not a
    /// [`Message`]: the typed set names what a message means, and a
    /// window's property is that nothing can be read from it.
    ///
    /// # Errors
    /// [`SendRefused::QueueFull`] or [`SendRefused::Closed`].
    pub fn send_window(&self, window: &[u8]) -> Result<(), SendRefused> {
        self.control.send(self.id, window.to_vec())
    }

    /// Ask the session layer to close this session with `cause`. The
    /// cause is recorded as the first end if none is recorded yet; only
    /// the session layer closes the socket.
    pub fn close(&self, cause: CloseCause) {
        self.control.close(self.id, cause);
    }
}

/// Proof that a session's handshake completed: the only form in which an
/// owner receives a session. Minted by the session layer alone.
#[derive(Clone, Debug)]
pub struct Established(SessionHandle);

impl Established {
    pub(crate) const fn mint(handle: SessionHandle) -> Self {
        Self(handle)
    }

    /// The handle this proof carries.
    #[must_use]
    pub const fn handle(&self) -> &SessionHandle {
        &self.0
    }
}

impl Deref for Established {
    type Target = SessionHandle;

    fn deref(&self) -> &SessionHandle {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use shekyl_levin::{Command, GetTxpoolComplement, PayloadError};

    use super::Message;

    /// A payload over its command's cap is refused at encode, so nothing
    /// the peer's ingress would close the session for is ever queued.
    #[test]
    fn a_payload_over_its_commands_cap_is_not_encoded() {
        let cap = usize::try_from(Command::GetTxpoolComplement.payload_cap()).expect("fits");
        let over = Message::GetTxpoolComplement(GetTxpoolComplement {
            hashes: vec![[7u8; 32]; cap / 32 + 1],
        });
        assert!(matches!(
            over.encode(),
            Err(PayloadError::OverCap { got, max }) if got > max && max == cap
        ));
        let under = Message::GetTxpoolComplement(GetTxpoolComplement {
            hashes: vec![[7u8; 32]; 16],
        });
        assert!(under.encode().is_ok());
    }
}
