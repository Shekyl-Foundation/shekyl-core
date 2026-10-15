// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One outbound handshake.
//!
//! The owner loop decides the address and the aim. This module opens the
//! channel, writes the request, reads until the peer's handshake response,
//! admits the list the response carries, and adopts the channel. A channel
//! that ends before a well-formed response is dropped: the session's drop
//! closes the queue, and the outcome carries the cause the connector stored.
//! The handshake's only clock is the connector's transport gap, armed
//! before `dial_channel` returns.

use shekyl_draw_rng::RelayRng;
use shekyl_levin::{
    invoke, BasicNodeData, BucketReader, CoreSyncData, HandshakeRequest, HandshakeResponse,
    PortableMap, Received, SupportFlags, COMMAND_HANDSHAKE,
};
use shekyl_peerlist::{
    CloseCause, CloseKind, ConnectorId, DialOutcome, NetworkAddress, SessionRow,
};
use shekyl_seam::SyncPayload;

use super::address::endpoint_of;
use super::{session_of, Dialer};
use crate::fill::DialAim;
use crate::nonce::InFlightNonce;

/// How one attempt ended on the owner's thread.
pub(super) enum Attempt {
    /// A total outcome, before any adopt.
    Done(DialOutcome),
    /// Adopted and posted; the strand's verdict completes it.
    Posted(shekyl_seam::SocketId),
}

/// Why no well-formed handshake response was read.
enum Rejected {
    /// The connector closed the session; its cause is on the session.
    Closed,
    /// The peer sent something that is not the handshake response.
    ByLevin,
}

impl Dialer {
    /// Dial, handshake, adopt, post. Every end path is an [`Attempt`].
    ///
    /// The shared lock is taken only to admit the received list, after the
    /// response has been read. The dial and the read block this thread and
    /// do not hold the lists.
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
            &mut crate::bans::HubBans(&self.hub),
            rng,
        );
        if admitted.is_err() {
            drop(channel);
            return Attempt::Done(DialOutcome::PeerlistRefused(address.clone()));
        }

        let attached =
            match self
                .hub
                .adopt(channel.open, channel.session, channel.endpoint, channel.gap)
            {
                Ok(attached) => attached,
                Err(cause) => return failed(cause),
            };
        let keep = aim == DialAim::Keep;
        self.hub.post_handshake_result(
            id,
            connector,
            keep,
            response.node_data.support_flags.bits(),
            SyncPayload {
                current_height: response.payload_data.current_height,
                cumulative_difficulty: response.payload_data.cumulative_difficulty,
                cumulative_difficulty_top64: response.payload_data.cumulative_difficulty_top64,
                top_id: response.payload_data.top_id,
            },
        );
        let hub = self.hub.clone();
        let session = attached.session;
        let pump = std::thread::spawn(move || shekyl_seam::drive_inbound(&hub, id, session));
        self.hub.track_pump(id, pump);
        Attempt::Posted(id)
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
fn read_response(
    session: &mut shekyl_capped_stream::Session,
) -> Result<HandshakeResponse, Rejected> {
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
