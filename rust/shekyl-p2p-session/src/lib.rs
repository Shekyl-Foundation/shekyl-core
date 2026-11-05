// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The session layer (`P2P_3_REMNANT_CUTOVER_BRIEF.md` §7).
//!
//! One task per admitted connection, on the transport runtime. The task
//! owns the connection's [`shekyl_capped_stream::Session`], feeds its
//! bytes to one [`shekyl_levin::BucketReader`], runs the Levin handshake
//! in whichever direction the connection was made, takes the self-connection
//! nonces, sends and answers timed sync, correlates requests with
//! responses, and dispatches every other bucket by its [`Command`] to the
//! one owner that holds it (`Owners`). Every wake it needs is an owner
//! of the daemon's one timing engine.
//!
//! What sits above sees two things: an [`Established`] handle, minted here
//! after the handshake and the only form in which a session reaches an
//! owner; and the [`Board`], the rows at one moment. What sits below is
//! the admission table and the connectors, through [`Dial`]. The layer
//! never opens a socket, never parses an address, and never judges a
//! peer's claim.
//!
//! Boundary rules this crate holds (brief §2): one owner per command,
//! the `match` over [`Command`] exhaustive; nothing but a 1001 before
//! the handshake, held by type ([`Established`] has no public
//! constructor); owners get typed messages and a handle, and only this
//! layer closes a socket; one writer per session's state, the session's
//! own task; dependencies point down; one unread frame per session, the
//! owner's [`Taken`] being the session's permit to read the next.

#![forbid(unsafe_code)]

mod board;
mod dial;
mod endpoint;
mod handle;
mod handshake;
mod layer;
mod nonce;
mod owners;
mod session;
mod timing;

pub use board::{Board, Row};
pub use dial::{Channel, ConnectFuture, Dial};
pub use endpoint::{admit, Endpoint, TOR_HOST_MAX};
pub use handle::{Encoded, Established, Message, SendRefused, SessionHandle};
pub use layer::{
    DialAim, DialOutcome, Parts, PerConnector, SessionConfig, SessionLayer, SESSION_QUEUE_DEPTH,
};
pub use nonce::{HandshakeNonce, HandshakeNonceSet, InFlightNonce, NonceTake};
pub use owners::{
    ClaimCarrier, Owners, PeerOwner, ProbeArrival, ProbeSink, RelayOwner, SessionFacts,
    SyncInbound, SyncOwner, Taken,
};
pub use timing::{Intervals, OwnerClass, INVOKE_TIMEOUT, TIMED_SYNC_JITTER, TIMED_SYNC_MIN};

pub use shekyl_levin::{Command, CoreSyncData};
pub use shekyl_transport_layer::{
    CloseCause, CloseKind, ConnectorId, DialEnd, Direction, SocketId,
};
