// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One outbound handshake, in two halves (the dialer in-flight bound,
//! Rick, 2026-10-25: decisions 1 and 2).
//!
//! The owner loop decides the address and the aim and launches the
//! attempt. The **attempt task** ([`attempt_task`]) runs on the dialer's
//! runtime and does only the I/O and the Levin layer's checks, which need
//! no random numbers: it opens the channel, writes the request, reads until
//! the peer's handshake response, decodes it and checks the network id.
//! It decides nothing else and holds no lock of the dialer's. The **loop**
//! applies its result ([`Dialer::apply_result`]) by calling the layer that
//! owns each decision: the peer list admits or refuses the received list,
//! the aim chooses confirm or keep, the hub adopts a kept channel.
//!
//! A channel the dial does not adopt is released, and the dialer that built
//! it retires the id, on every path ([`Unadopted`]), including a cancelled
//! task and a result dropped at stop; the outcome carries the cause the
//! connector stored. The handshake's only clock is the connector's
//! transport gap, armed before the channel is returned.
//!
//! The response carries no nonce. The request's nonce is the inbound
//! self-connection check, not a value the peer echoes, so the response
//! has nothing to match it against. Rust refuses three things: a frame
//! that is not a well-formed `COMMAND_HANDSHAKE` response, a network id
//! that is not ours, and a peerlist the lists refuse. A later refusal of
//! a kept session is the payload owner closing it.

use shekyl_capped_stream::Session;
use shekyl_draw_rng::RelayRng;
use shekyl_levin::{
    invoke, BasicNodeData, BucketReader, CoreSyncData, HandshakeRequest, HandshakeResponse,
    PortableMap, Received, COMMAND_HANDSHAKE,
};
use shekyl_peerlist::{
    CloseCause, CloseKind, ConnectorId, DialOutcome, NetworkAddress, SessionRow,
};
use shekyl_seam::{Channel, Endpoint, Hub, SocketId, SyncPayload};
use shekyl_transport_layer::{DialEnd, DialFailure, Reached, Retry};

use super::address::endpoint_of;
use super::{session_of, Dialer};
use crate::fill::DialAim;
use crate::nonce::InFlightNonce;

/// How one attempt ended, once the loop has applied it.
pub(super) enum Attempt {
    /// A total outcome. The owner records it. Nothing was adopted, and
    /// nothing is posted.
    Done(DialOutcome),
    /// Adopted, and not already closed. The owner records `SessionAccepted`
    /// and then notifies the strand.
    Kept(KeptDial),
}

/// A kept dial the owner has not yet recorded.
pub(super) struct KeptDial {
    pub(super) id: SocketId,
    /// The peer's sync payload.
    pub(super) sync: SyncPayload,
    /// The pump's end of the session. The owner starts the pump after it
    /// records the kept row and posts the notification.
    pub(super) session: Session,
}

/// What the attempt task hands the loop.
pub(super) enum TaskResult {
    /// A well-formed handshake response on our network, and the channel it
    /// came on, still unadopted.
    Response {
        channel: Unadopted,
        response: Box<HandshakeResponse>,
    },
    /// The channel never reached a well-formed response on our network:
    /// the end the connector stamped, the Levin layer's rejection, or this
    /// dialer's own failure.
    Failed(DialEnd),
}

/// The peer list's outcome for a failed attempt. The one place a
/// [`DialEnd`] becomes the peer list's input, until the peer list takes the
/// judge's (`DIALER_OUTAGE_EVIDENCE.md` §8, step 4).
pub(super) fn failed_outcome(address: NetworkAddress, end: DialEnd) -> DialOutcome {
    DialOutcome::DialFailed(address, end.cause())
}

/// The Levin layer's refusal on `connector`, after the stream opened: the
/// peer rejected the handshake, answered on another network, or sent a
/// peer list the lists refuse. Proof of misbehaviour only where the
/// connector authenticates the destination (§2.2), and always final.
fn refused_by_peer(connector: ConnectorId) -> DialEnd {
    DialEnd::new(
        DialFailure::refused_by_peer(connector, Reached::StreamOpened),
        CloseCause::new(CloseKind::LevinHandshakeRejected).proving_misbehaviour_on(connector),
    )
}

/// What the task needs, worked out on the loop before launch.
pub(super) struct Prepared {
    endpoint: Endpoint,
    request: Vec<u8>,
    network_id: [u8; 16],
}

/// Why no well-formed handshake response was read.
enum Rejected {
    /// The connector closed the session; its cause is on the session.
    Closed,
    /// The peer sent something that is not the handshake response.
    ByLevin,
}

impl Dialer {
    /// The attempt's inputs: the endpoint, the network id and the request
    /// frame carrying `nonce`. An address with no endpoint, or no published
    /// tip or network id yet, is a local failure the loop records at once.
    pub(super) fn prepare(
        &self,
        connector: ConnectorId,
        address: &NetworkAddress,
        nonce: &InFlightNonce,
    ) -> Result<Prepared, DialEnd> {
        let local = DialEnd::local_close;
        let endpoint = endpoint_of(address).ok_or_else(local)?;
        let (Some(snapshot), Some(network_id)) = ((self.snapshot)(), self.network_id()) else {
            tracing::debug!(
                "{connector:?} dial {address:?} not made: no published tip or network id yet"
            );
            return Err(local());
        };
        let request = request_frame(network_id, &snapshot, nonce).ok_or_else(local)?;
        Ok(Prepared {
            endpoint,
            request,
            network_id,
        })
    }

    /// Apply one task result, on the loop, through the layer that owns each
    /// decision. The shared lock is taken only to admit the received list;
    /// no hub call is made under it (#1092).
    pub(super) fn apply_result<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        address: &NetworkAddress,
        aim: DialAim,
        result: TaskResult,
        rng: &mut R,
    ) -> Attempt {
        let failed = |end: DialEnd| Attempt::Done(failed_outcome(address.clone(), end));
        let (mut channel, response) = match result {
            TaskResult::Failed(end) => return failed(end),
            TaskResult::Response { channel, response } => (channel, response),
        };

        let id = channel.held().open.id();
        let now = self.hub.now();
        let addresses: Vec<NetworkAddress> = response
            .local_peerlist_new
            .iter()
            .map(|entry| entry.adr.clone())
            .collect();
        let admitted = self.shared().lists.admit_received_list(
            &addresses,
            SessionRow {
                id: session_of(id),
                connector,
            },
            now,
            rng,
        );
        if admitted.is_err() {
            // A list the lists refuse (D3, D-S1, the foreign-connector rule,
            // R4) is the peer's doing: the same stamp as a rejection.
            return Attempt::Done(DialOutcome::PeerlistRefused(
                address.clone(),
                refused_by_peer(connector).cause(),
            ));
        }

        if aim == DialAim::Confirm {
            return Attempt::Done(DialOutcome::Confirmed(address.clone()));
        }

        // A peer that closed while the result waited in the queue: the
        // session already holds the connector's cause. Nothing is adopted.
        if let Some(end) = channel.closed() {
            return failed(end);
        }

        // From here until the kept row is written, a close that reaches the
        // dialer finds no kept row. It records its cause under this id
        // instead, and the owner does not keep the dial.
        self.shared().adopting.insert(id.get(), None);
        let Channel {
            open,
            session,
            endpoint,
            gap,
        } = channel.into_adopted();
        let attached = match self.hub.adopt(open, session, endpoint, gap) {
            Ok(attached) => attached,
            Err(end) => {
                self.shared().adopting.remove(&id.get());
                // The hub made no row, so nothing else retires the id.
                self.hub.reap(id);
                return failed(end);
            }
        };
        // `Established` runs its poster before `adopt` returns. A poster
        // that closed the session has already won: recording a kept row
        // would resurrect it.
        if let Some(end) = self.hub.end(id) {
            self.shared().adopting.remove(&id.get());
            drop(attached);
            return failed(end);
        }
        Attempt::Kept(KeptDial {
            id,
            sync: SyncPayload {
                current_height: response.payload_data.current_height,
                cumulative_difficulty: response.payload_data.cumulative_difficulty,
                cumulative_difficulty_top64: response.payload_data.cumulative_difficulty_top64,
                top_id: response.payload_data.top_id,
            },
            session: attached.session,
        })
    }
}

/// The attempt task: the I/O and the Levin layer's checks, nothing else.
///
/// It opens the channel through the hub's dialer, writes the request,
/// reads until one whole handshake response decodes, and checks the
/// network id. It takes no lock of the dialer's and draws no random
/// number. Dropped before it resolves (a cancelled attempt), it releases
/// whatever it holds: the connect future aborts the connector's dial, and
/// a held channel is released by [`Unadopted`]'s drop.
pub(super) async fn attempt_task(
    hub: Hub,
    connector: ConnectorId,
    address: NetworkAddress,
    prepared: Prepared,
) -> TaskResult {
    let Prepared {
        endpoint,
        request,
        network_id,
    } = prepared;
    let channel = match hub.dial_channel_async(&endpoint).await {
        Ok(channel) => Unadopted::new(hub, channel),
        Err(end) => return TaskResult::Failed(end),
    };
    let mut channel = channel;
    let connected_at = std::time::Instant::now();
    if let Err(kind) = channel.held().session.try_send(request) {
        // A closed queue is a session the connector already ended, with its
        // end on the session; a request over the cap is this node's own.
        return TaskResult::Failed(if kind == CloseKind::SendQueueFull {
            DialEnd::new(
                DialFailure::local(Retry::Again, Reached::StreamOpened),
                CloseCause::new(kind),
            )
        } else {
            channel.held().session.close_end()
        });
    }
    tracing::debug!(
        "{connector:?} dial {address:?}: handshake queued {} ns after the channel opened",
        u64::try_from(connected_at.elapsed().as_nanos()).unwrap_or(u64::MAX)
    );
    let response = match read_response(&mut channel.held().session).await {
        Ok(response) => response,
        Err(Rejected::Closed) => {
            return TaskResult::Failed(channel.held().session.close_end());
        }
        Err(Rejected::ByLevin) => return TaskResult::Failed(refused_by_peer(connector)),
    };
    if response.node_data.network_id != network_id {
        return TaskResult::Failed(refused_by_peer(connector));
    }
    TaskResult::Response {
        channel,
        response: Box::new(response),
    }
}

/// A dialed channel the dialer holds until it adopts it. Every other end
/// (a refusal, a failed read, a confirm, a cancelled task, a result dropped
/// at stop) releases it on drop: the session's drop closes the queue, the
/// gap's drop ends the connector's wait, and the admission closes with the
/// dialer's own cause. There is no row, so no `Closed` post. Then the
/// dialer that built the channel retires what it holds for the id
/// ([`Hub::reap`]; the loopback joins its writer thread). Only
/// [`Self::into_adopted`] takes the channel out. It owns its hub handle, so
/// it can cross from the attempt task to the loop.
pub(super) struct Unadopted {
    hub: Hub,
    channel: Option<Channel>,
}

impl Unadopted {
    const fn new(hub: Hub, channel: Channel) -> Self {
        Self {
            hub,
            channel: Some(channel),
        }
    }

    fn held(&mut self) -> &mut Channel {
        self.channel
            .as_mut()
            .expect("a channel is held until it is adopted")
    }

    /// The connector's end, when it has already closed the session.
    fn closed(&mut self) -> Option<DialEnd> {
        self.held().session.stored_end()
    }

    /// The channel, for `adopt`. Nothing is released.
    fn into_adopted(mut self) -> Channel {
        self.channel
            .take()
            .expect("a channel is held until it is adopted")
    }
}

impl Drop for Unadopted {
    fn drop(&mut self) {
        let Some(Channel {
            open, session, gap, ..
        }) = self.channel.take()
        else {
            return;
        };
        let id = open.id();
        drop(session);
        drop(gap);
        let _ = open.close(CloseCause::new(CloseKind::LocalClose));
        self.hub.reap(id);
    }
}

/// The `COMMAND_HANDSHAKE` request frame carrying `nonce`: a peer dial's,
/// and the probe's (`Dialer::mint_probe`). `None` when the payload does not
/// encode.
pub(super) fn request_frame(
    network_id: [u8; 16],
    snapshot: &SyncPayload,
    nonce: &InFlightNonce,
) -> Option<Vec<u8>> {
    let request = HandshakeRequest {
        node_data: BasicNodeData { network_id },
        payload_data: sync_data(snapshot),
        nonce: *nonce.bytes(),
    };
    let payload = request.store().ok()?;
    Some(invoke(COMMAND_HANDSHAKE, &payload))
}

fn sync_data(snapshot: &SyncPayload) -> CoreSyncData {
    CoreSyncData {
        current_height: snapshot.current_height,
        cumulative_difficulty: snapshot.cumulative_difficulty,
        cumulative_difficulty_top64: snapshot.cumulative_difficulty_top64,
        top_id: snapshot.top_id,
    }
}

/// Read frames until one whole `COMMAND_HANDSHAKE` response decodes.
async fn read_response(session: &mut Session) -> Result<HandshakeResponse, Rejected> {
    let mut reader = BucketReader::new();
    loop {
        let Some(frame) = session.recv().await else {
            return Err(Rejected::Closed);
        };
        if reader.feed(&frame).is_err() {
            return Err(Rejected::ByLevin);
        }
        match reader.next_message() {
            Ok(None) => {}
            Ok(Some(Received::Response { command, payload })) if command == COMMAND_HANDSHAKE => {
                return HandshakeResponse::load(&payload).map_err(|_| Rejected::ByLevin);
            }
            Ok(Some(_)) | Err(_) => return Err(Rejected::ByLevin),
        }
    }
}

#[cfg(test)]
mod tests {
    use shekyl_peerlist::{CloseKind, ConnectorId};
    use shekyl_transport_layer::{Evidence, Reached, Retry};

    use super::refused_by_peer;

    /// The Levin layer's refusal (§2.2): after the stream opened, final, and
    /// proof of misbehaviour only on the connector that authenticates the
    /// destination. The edit that makes this red is building it as
    /// Uncertain, or proving misbehaviour on clearnet.
    #[test]
    fn a_peers_refusal_is_the_levin_layers_and_proves_only_where_authenticated() {
        for (connector, proves) in [(ConnectorId::Tor, true), (ConnectorId::Clearnet, false)] {
            let end = refused_by_peer(connector);
            assert!(matches!(end.failure().evidence(), Evidence::Destination(_)));
            assert_eq!(end.failure().proves_misbehaviour(), proves, "{connector:?}");
            assert_eq!(end.failure().retry(), Retry::Final);
            assert_eq!(end.failure().reached(), Reached::StreamOpened);
            assert_eq!(end.cause().kind(), CloseKind::LevinHandshakeRejected);
        }
    }
}
