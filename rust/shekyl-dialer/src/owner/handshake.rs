// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One outbound handshake.
//!
//! The owner loop decides the address and the aim. This module opens the
//! channel, writes the request, reads until the peer's handshake response,
//! and admits the list the response carries. A `Keep` dial then adopts the
//! channel. A `Confirm` dial closes it here, with no adopt and no post.
//! A channel the dial does not adopt is released, and the dialer that built
//! it retires the id, on every path ([`Unadopted`]); the outcome carries the
//! cause the connector stored. The handshake's only clock is the connector's
//! transport gap, armed before `dial_channel` returns.
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
use shekyl_seam::{Channel, Hub, SocketId, SyncPayload};

use super::address::endpoint_of;
use super::{session_of, Dialer};
use crate::bans::BanSnapshot;
use crate::fill::DialAim;
use crate::nonce::InFlightNonce;

/// How one attempt ended on the owner's thread.
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

/// Why no well-formed handshake response was read.
enum Rejected {
    /// The connector closed the session; its cause is on the session.
    Closed,
    /// The peer sent something that is not the handshake response.
    ByLevin,
}

impl Dialer {
    /// Dial and handshake. Every end path is an [`Attempt`].
    ///
    /// The shared lock is taken only to admit the received list, after the
    /// bans have been copied out and the response has been read. The dial
    /// and the read block this thread and do not hold the lists.
    pub(super) fn exchange<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        address: &NetworkAddress,
        aim: DialAim,
        nonce: &InFlightNonce,
        rng: &mut R,
    ) -> Attempt {
        let failed =
            |cause: CloseCause| Attempt::Done(DialOutcome::DialFailed(address.clone(), cause));
        let Some(endpoint) = endpoint_of(address) else {
            return failed(CloseCause::new(CloseKind::LocalClose));
        };
        let (Some(snapshot), Some(network_id)) = ((self.snapshot)(), self.network_id()) else {
            tracing::debug!(
                "{connector:?} dial {address:?} not made: no published tip or network id yet"
            );
            return failed(CloseCause::new(CloseKind::LocalClose));
        };
        let mut channel = match self.hub.dial_channel(&endpoint) {
            Ok(channel) => Unadopted::new(&self.hub, channel),
            Err(cause) => return failed(cause),
        };
        let connected_at = std::time::Instant::now();
        let request = HandshakeRequest {
            node_data: BasicNodeData { network_id },
            payload_data: sync_data(&snapshot),
            nonce: *nonce.bytes(),
        };
        let Ok(payload) = request.store() else {
            return failed(CloseCause::new(CloseKind::LocalClose));
        };
        if let Err(kind) = channel
            .held()
            .session
            .try_send(invoke(COMMAND_HANDSHAKE, &payload))
        {
            return failed(CloseCause::new(kind));
        }
        tracing::debug!(
            "{connector:?} dial {address:?}: handshake queued {} ns after the channel opened",
            u64::try_from(connected_at.elapsed().as_nanos()).unwrap_or(u64::MAX)
        );

        let response = match read_response(&mut channel.held().session) {
            Ok(response) => response,
            Err(Rejected::Closed) => return failed(channel.held().session.close_cause()),
            Err(Rejected::ByLevin) => {
                return failed(CloseCause::new(CloseKind::LevinHandshakeRejected));
            }
        };
        if response.node_data.network_id != network_id {
            return failed(CloseCause::new(CloseKind::LevinHandshakeRejected));
        }

        let id = channel.held().open.id();
        let now = self.hub.now();
        let mut bans = BanSnapshot::take(&self.hub);
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
            &mut bans,
            rng,
        );
        if admitted.is_err() {
            return Attempt::Done(DialOutcome::PeerlistRefused(address.clone()));
        }

        if aim == DialAim::Confirm {
            return Attempt::Done(DialOutcome::Confirmed(address.clone()));
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
            Err(cause) => {
                self.shared().adopting.remove(&id.get());
                // The hub made no row, so nothing else retires the id.
                self.hub.reap(id);
                return failed(cause);
            }
        };
        // `Established` runs its poster before `adopt` returns. A poster
        // that closed the session has already won: recording a kept row
        // would resurrect it.
        if let Some(cause) = self.hub.cause(id) {
            self.shared().adopting.remove(&id.get());
            drop(attached);
            return failed(cause);
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

/// A dialed channel the dialer holds until it adopts it. Every other end of
/// the exchange (a refusal, a failed read, a confirm) releases it on drop:
/// the session's drop closes the queue, the gap's drop ends the connector's
/// wait, and the admission closes with the dialer's own cause. There is no
/// row, so no `Closed` post. Then the dialer that built the channel retires
/// what it holds for the id ([`Hub::reap`]; the loopback joins its writer
/// thread). Only [`Self::into_adopted`] takes the channel out.
struct Unadopted<'h> {
    hub: &'h Hub,
    channel: Option<Channel>,
}

impl<'h> Unadopted<'h> {
    const fn new(hub: &'h Hub, channel: Channel) -> Self {
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

    /// The channel, for `adopt`. Nothing is released.
    fn into_adopted(mut self) -> Channel {
        self.channel
            .take()
            .expect("a channel is held until it is adopted")
    }
}

impl Drop for Unadopted<'_> {
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

fn sync_data(snapshot: &SyncPayload) -> CoreSyncData {
    CoreSyncData {
        current_height: snapshot.current_height,
        cumulative_difficulty: snapshot.cumulative_difficulty,
        cumulative_difficulty_top64: snapshot.cumulative_difficulty_top64,
        top_id: snapshot.top_id,
    }
}

/// Read frames until one whole `COMMAND_HANDSHAKE` response decodes.
fn read_response(session: &mut Session) -> Result<HandshakeResponse, Rejected> {
    let mut reader = BucketReader::new();
    loop {
        let Some(frame) = session.recv_blocking() else {
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
