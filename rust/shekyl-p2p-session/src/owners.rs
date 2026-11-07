// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The three owners the dispatch table routes to (brief §7.2).
//!
//! The session layer defines these traits and never implements them. The
//! composition hands one [`Owners`] value to the layer at construction;
//! the traits are the whole of what the layer knows about an owner (brief
//! §2 rule 5). Every method is called from a session's own task, on the
//! transport runtime, with the layer holding no lock: an owner that
//! enqueues returns at once, and an owner that does work there stalls that
//! one session only.
//!
//! A message an owner receives arrives with a [`Taken`]. Dropping it is
//! the owner's acknowledgement that the message has been taken into the
//! owner's own state; the session reads its next frame only then (brief
//! §7.7). An owner that holds the `Taken` holds the session's reader.

use std::fmt;
use std::sync::Arc;

use shekyl_levin::{Command, CoreSyncData, GetTxpoolComplement, NewTransactions, PeerlistEntry};
use shekyl_timing_engine::Tick;
use shekyl_transport_layer::{ConnectorId, DialEnd, SocketId};
use tokio::sync::OwnedSemaphorePermit;

use crate::endpoint::Endpoint;
use crate::handle::Established;
use crate::layer::PerConnector;

/// The session's permit for one owner-bound message. Dropping it lets the
/// session read its next frame.
pub struct Taken {
    _permit: OwnedSemaphorePermit,
}

impl Taken {
    pub(crate) const fn new(permit: OwnedSemaphorePermit) -> Self {
        Self { _permit: permit }
    }
}

impl fmt::Debug for Taken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Taken")
    }
}

/// The facts of a session that is no longer [`Established`]: what
/// [`PeerOwner::on_closed`] and its siblings receive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionFacts {
    /// The admission id.
    pub id: SocketId,
    /// The endpoint observed at admission.
    pub endpoint: Endpoint,
    /// Whether the handshake had completed before the close.
    pub established: bool,
}

impl SessionFacts {
    /// The connector that carried the session.
    #[must_use]
    pub const fn connector(&self) -> ConnectorId {
        self.endpoint.connector()
    }
}

/// Which message carried a peer's sync payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimCarrier {
    /// The handshake (1001).
    Handshake,
    /// A timed sync (1002), request or response.
    TimedSync,
}

/// The peers owner: the lists and the dialer.
pub trait PeerOwner: Send + Sync {
    /// The addresses this node discloses to a peer on `connector`, in a
    /// handshake response and in a timed-sync response.
    fn disclosure(&self, connector: ConnectorId) -> Vec<PeerlistEntry>;

    /// A list a peer sent in a timed-sync response. The list of a
    /// handshake response is returned to the dialer in its
    /// [`crate::DialOutcome`] instead, so it is admitted once.
    fn list_received(&self, session: &Established, list: Vec<PeerlistEntry>);

    /// A session completed its handshake.
    fn on_established(&self, session: &Established) {
        let _ = session;
    }

    /// A session closed with `end` as its first recorded end.
    fn on_closed(&self, facts: &SessionFacts, end: DialEnd) {
        let _ = (facts, end);
    }
}

/// One message the sync owner receives: the payload as the wire carried
/// it, under the arm that names its command. Decoding is the owner's,
/// as it was the router's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncInbound {
    /// 2008.
    NewCompactBlock(Vec<u8>),
    /// 2009.
    RequestCompactMissingTx(Vec<u8>),
    /// 2011.
    RequestHeaders(Vec<u8>),
    /// 2012.
    ResponseHeaders(Vec<u8>),
    /// 2013.
    RequestBodies(Vec<u8>),
    /// 2014.
    ResponseBodies(Vec<u8>),
}

impl SyncInbound {
    /// The command the payload arrived under.
    #[must_use]
    pub const fn command(&self) -> Command {
        match self {
            Self::NewCompactBlock(_) => Command::NewCompactBlock,
            Self::RequestCompactMissingTx(_) => Command::RequestCompactMissingTx,
            Self::RequestHeaders(_) => Command::RequestHeaders,
            Self::ResponseHeaders(_) => Command::ResponseHeaders,
            Self::RequestBodies(_) => Command::RequestBodies,
            Self::ResponseBodies(_) => Command::ResponseBodies,
        }
    }

    /// The payload, still encoded.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        match self {
            Self::NewCompactBlock(p)
            | Self::RequestCompactMissingTx(p)
            | Self::RequestHeaders(p)
            | Self::ResponseHeaders(p)
            | Self::RequestBodies(p)
            | Self::ResponseBodies(p) => p,
        }
    }
}

/// The sync owner: chain sync and block relay.
pub trait SyncOwner: Send + Sync {
    /// A peer's sync payload, read as a claim and not judged here. From
    /// both handshake directions and both timed-sync directions. `taken`
    /// is the permit of the frame that carried it: the session reads its
    /// next frame once the owner has taken the claim (§7.7), so a peer's
    /// claims queue no faster than the owner takes them.
    fn claim(&self, session: &Established, sync: CoreSyncData, carrier: ClaimCarrier, taken: Taken);

    /// One of the owner's six commands arrived.
    fn message(&self, session: &Established, message: SyncInbound, taken: Taken);

    /// A session completed its handshake.
    fn on_established(&self, session: &Established) {
        let _ = session;
    }

    /// A session closed with `end` as its first recorded end.
    fn on_closed(&self, facts: &SessionFacts, end: DialEnd) {
        let _ = (facts, end);
    }
}

/// The relay owner: transaction relay and the pool complement.
pub trait RelayOwner: Send + Sync {
    /// 2002 arrived and decoded.
    fn new_transactions(&self, session: &Established, batch: NewTransactions, taken: Taken);

    /// 2010 arrived and decoded.
    fn txpool_complement(&self, session: &Established, request: GetTxpoolComplement, taken: Taken);

    /// A session completed its handshake.
    fn on_established(&self, session: &Established) {
        let _ = session;
    }

    /// A session closed with `end` as its first recorded end.
    fn on_closed(&self, facts: &SessionFacts, end: DialEnd) {
        let _ = (facts, end);
    }
}

/// A reachability probe of this node's own onion arrived
/// (`TOR_SUPERVISOR.md` §4.5): the inbound handshake carried a nonce the
/// managed Tor minted with [`crate::HandshakeNonceSet::mint_probe`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeArrival {
    /// When the probe's nonce was minted, on the engine clock.
    pub minted_at: Tick,
    /// When the handshake carrying it was read, on the same clock.
    pub arrived_at: Tick,
}

/// Who hears a probe arrive: the managed Tor supervisor. Not a command's
/// owner; a probe is a handshake this node sent itself and the session is
/// closed as soon as the nonce is read.
pub trait ProbeSink: Send + Sync {
    /// A probe arrived. Called from the inbound session's task.
    fn probe_arrived(&self, arrival: ProbeArrival);
}

/// Where the layer reports how many sessions each connector holds: every
/// row whose handshake has finished, outbound and inbound. A handshake
/// still open is not a session: the probe of this node's own onion is
/// dropped in that handshake, so it never counts (`TOR_SUPERVISOR.md`
/// §4.5).
///
/// Called with the count at construction, before the layer is shared, and
/// after each change. The count is taken under the session table's lock
/// and delivered after that lock is dropped, so the call does not stall
/// the table. A later count is never overtaken by an earlier one; a count
/// that lost the race is skipped, and the sink keeps the latest. The call
/// must return without waiting, and must not re-enter the session layer:
/// the report gate is held across it.
pub type SessionsSink = Arc<dyn Fn(PerConnector<u32>) + Send + Sync>;

/// The three owners, as the composition hands them to the layer, and what
/// the managed Tor supervisor hears from it.
#[derive(Clone)]
pub struct Owners {
    /// The lists and the dialer.
    pub peers: Arc<dyn PeerOwner>,
    /// Chain sync and block relay.
    pub sync: Arc<dyn SyncOwner>,
    /// Transaction relay.
    pub relay: Arc<dyn RelayOwner>,
    /// The managed Tor supervisor's reachability probe. `None` when no
    /// supervisor runs: then no probe is minted, and none can arrive.
    pub probes: Option<Arc<dyn ProbeSink>>,
    /// The sessions each connector holds, for the supervisor's posture
    /// line (`TSR-Q12`). `None` when no supervisor runs.
    pub sessions: Option<SessionsSink>,
}

impl Owners {
    pub(crate) fn established(&self, session: &Established) {
        self.peers.on_established(session);
        self.sync.on_established(session);
        self.relay.on_established(session);
    }

    pub(crate) fn closed(&self, facts: &SessionFacts, end: DialEnd) {
        self.peers.on_closed(facts, end);
        self.sync.on_closed(facts, end);
        self.relay.on_closed(facts, end);
    }
}

impl fmt::Debug for Owners {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Owners")
    }
}
