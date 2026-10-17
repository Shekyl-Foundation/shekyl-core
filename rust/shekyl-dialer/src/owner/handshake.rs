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
//! A channel that ends before a well-formed response is dropped: the
//! session's drop closes the queue, and the outcome carries the cause the
//! connector stored. The handshake's only clock is the connector's
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
    PortableMap, Received, SupportFlags, COMMAND_HANDSHAKE,
};
use shekyl_peerlist::{
    CloseCause, CloseKind, ConnectorId, DialOutcome, NetworkAddress, SessionRow,
};
use shekyl_seam::{Channel, SocketId, SyncPayload};

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
    /// The peer's support flags, zero included.
    pub(super) support_flags: u32,
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
        let channel = match self.hub.dial_channel(&endpoint) {
            Ok(channel) => channel,
            Err(cause) => return failed(cause),
        };
        let connected_at = std::time::Instant::now();
        let request = HandshakeRequest {
            node_data: BasicNodeData {
                network_id,
                support_flags: SupportFlags::from_bits(self.support_flags),
            },
            payload_data: sync_data(&snapshot),
            nonce: *nonce.bytes(),
        };
        let Ok(payload) = request.store() else {
            drop(channel);
            return failed(CloseCause::new(CloseKind::LocalClose));
        };
        if let Err(kind) = channel
            .session
            .try_send(invoke(COMMAND_HANDSHAKE, &payload))
        {
            let cause = CloseCause::new(kind);
            drop(channel);
            return failed(cause);
        }
        tracing::debug!(
            "{connector:?} dial {address:?}: handshake queued {} ns after the channel opened",
            u64::try_from(connected_at.elapsed().as_nanos()).unwrap_or(u64::MAX)
        );

        let mut channel = channel;
        let response = match read_response(&mut channel.session) {
            Ok(response) => response,
            Err(Rejected::Closed) => return failed(channel.session.close_cause()),
            Err(Rejected::ByLevin) => {
                let cause = CloseCause::new(CloseKind::LevinHandshakeRejected);
                drop(channel);
                return failed(cause);
            }
        };
        if response.node_data.network_id != network_id {
            let cause = CloseCause::new(CloseKind::LevinHandshakeRejected);
            drop(channel);
            return failed(cause);
        }

        let id = channel.open.id();
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
            drop(channel);
            return Attempt::Done(DialOutcome::PeerlistRefused(address.clone()));
        }

        if aim == DialAim::Confirm {
            release_unadopted(channel);
            return Attempt::Done(DialOutcome::Confirmed(address.clone()));
        }

        let attached =
            match self
                .hub
                .adopt(channel.open, channel.session, channel.endpoint, channel.gap)
            {
                Ok(attached) => attached,
                Err(cause) => return failed(cause),
            };
        // `Established` runs its poster before `adopt` returns. A poster
        // that closed the session has already won: recording a kept row
        // would resurrect it.
        if let Some(cause) = self.hub.cause(id) {
            drop(attached);
            return failed(cause);
        }
        Attempt::Kept(KeptDial {
            id,
            support_flags: response.node_data.support_flags.bits(),
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

/// Close a channel that was never adopted. The session drop closes the
/// queue, the gap drop ends the connector's wait, and `open.close` releases
/// the admission with the dialer's own cause. No row, so no `Closed` post.
fn release_unadopted(channel: Channel) {
    let Channel {
        open,
        session,
        gap,
        endpoint: _,
    } = channel;
    drop(session);
    drop(gap);
    let _ = open.close(CloseCause::new(CloseKind::LocalClose));
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
