// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The connectors the loopback harness hands the session layer: each
//! channel's far end is a scripted peer.
//!
//! What the node sends on a channel is read as Levin buckets on the far
//! side. The far side answers the node's handshake and timed sync itself,
//! with the claim the test gave it, and hands every other bucket to that
//! channel's [`SyncPeer`]. What the peer answers is pushed back into the
//! channel the way a connector's reader would, so it reaches the node
//! through the session layer and the owners exactly as a remote peer's
//! bytes do. A test pushes frames of its own with [`PeerDial::inject`].

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::thread::{self, JoinHandle};

use shekyl_capped_stream::{InboundEnd, QueueHold, StreamEnds};
use shekyl_levin::{
    response, BasicNodeData, BucketReader, CoreSyncData, HandshakeResponse, PortableMap, Received,
    TimedSyncResponse, DEFAULT_MAX_PACKET_SIZE,
};
use shekyl_p2p_session::harness::handshake_request;
use shekyl_p2p_session::{admit, Channel, Command, ConnectFuture, Dial, Endpoint};
use shekyl_peer_policy::InboundCeiling;
use shekyl_timing_engine::Tick;
use shekyl_transport_layer::{
    ConnectorId, DialEnd, DialFailure, Reached, Retry, SocketId, Sockets, StreamEnd,
};

/// The far end of one channel.
pub trait SyncPeer: Send {
    /// One whole bucket the node sent, after the handshake and the timed
    /// sync, which the far side answers itself. The frames returned are
    /// pushed back to the node, in order.
    fn on_message(&mut self, command: u32, payload: &[u8]) -> Vec<Vec<u8>>;
}

/// A peer that never answers.
pub struct Silent;

impl SyncPeer for Silent {
    fn on_message(&mut self, _command: u32, _payload: &[u8]) -> Vec<Vec<u8>> {
        Vec::new()
    }
}

/// The claim a peer with none makes: height zero, no work.
#[must_use]
pub fn empty_claim() -> CoreSyncData {
    CoreSyncData {
        current_height: 0,
        cumulative_difficulty: 0,
        cumulative_difficulty_top64: 0,
        top_id: [0; 32],
    }
}

struct Slot {
    inject: Option<InboundEnd>,
    hold: Option<QueueHold>,
    writer: Option<JoinHandle<()>>,
}

struct Expected {
    peer: Box<dyn SyncPeer>,
    claim: CoreSyncData,
}

/// The connectors (module docs).
pub struct PeerDial {
    sockets: Sockets,
    network_id: [u8; 16],
    ceiling: InboundCeiling,
    send_cap: usize,
    expected: Mutex<HashMap<IpAddr, Expected>>,
    slots: Mutex<HashMap<SocketId, Slot>>,
    nonces: AtomicU32,
}

impl PeerDial {
    /// Channels on `sockets` under `ceiling`, each with an outbound cap of
    /// `send_cap`; the far sides name `network_id` in their handshakes.
    #[must_use]
    pub fn new(
        sockets: Sockets,
        network_id: [u8; 16],
        ceiling: InboundCeiling,
        send_cap: usize,
    ) -> Self {
        Self {
            sockets,
            network_id,
            ceiling,
            send_cap,
            expected: Mutex::new(HashMap::new()),
            slots: Mutex::new(HashMap::new()),
            nonces: AtomicU32::new(1),
        }
    }

    /// The next channel dialed to `ip` has `peer` at its far end, claiming
    /// `claim` in its handshake response and every timed sync.
    pub fn expect(&self, ip: IpAddr, peer: Box<dyn SyncPeer>, claim: CoreSyncData) {
        self.expected
            .lock()
            .expect("expected peers")
            .insert(ip, Expected { peer, claim });
    }

    /// Admit an inbound connection from `endpoint` whose far side is
    /// `peer`, and open its channel for the layer to adopt. The far side
    /// writes its handshake request, claiming `claim`, as soon as the
    /// channel exists.
    ///
    /// # Errors
    /// This node's admission refused it.
    pub fn accept(
        &self,
        endpoint: Endpoint,
        peer: Box<dyn SyncPeer>,
        claim: CoreSyncData,
    ) -> Result<Channel, DialEnd> {
        let channel = self.open(&endpoint, peer, claim.clone())?;
        let nonce = self.nonces.fetch_add(1, Ordering::AcqRel);
        let mut nonce_bytes = [0u8; 32];
        nonce_bytes[..4].copy_from_slice(&nonce.to_le_bytes());
        nonce_bytes[4] = 0xa5;
        let request = handshake_request(self.network_id, nonce_bytes, claim);
        assert!(
            self.inject(channel.open.id(), request),
            "the inbound end is open before the layer adopts the channel"
        );
        Ok(channel)
    }

    /// Push `frame` into `id`'s channel as its peer. `false` when the
    /// channel is gone or the node stopped reading it.
    pub fn inject(&self, id: SocketId, frame: Vec<u8>) -> bool {
        let sender = self.slots().get(&id).and_then(|slot| slot.inject.clone());
        sender.is_some_and(|sender| sender.blocking_send(frame).is_ok())
    }

    /// Whether `id`'s channel is still open on this side.
    #[must_use]
    pub fn is_open(&self, id: SocketId) -> bool {
        self.slots().contains_key(&id)
    }

    /// Drop `id`'s far side: the ends close and the writer thread is
    /// joined. Called when the layer's row for `id` has closed.
    pub fn retire(&self, id: SocketId) {
        let Some(slot) = self.slots().remove(&id) else {
            return;
        };
        drop(slot.inject);
        drop(slot.hold);
        if let Some(writer) = slot.writer {
            let _joined = writer.join();
        }
    }

    fn slots(&self) -> MutexGuard<'_, HashMap<SocketId, Slot>> {
        self.slots.lock().expect("peer slots")
    }

    fn open(
        &self,
        endpoint: &Endpoint,
        peer: Box<dyn SyncPeer>,
        claim: CoreSyncData,
    ) -> Result<Channel, DialEnd> {
        // A refusal here is this node's own admission, before any I/O.
        let open = admit(&self.sockets, endpoint, Tick::new(0), self.ceiling).map_err(|cause| {
            DialEnd::new(DialFailure::local(Retry::Again, Reached::NoStream), cause)
        })?;
        let id = open.id();
        let ends = StreamEnds::open(self.send_cap);
        let writer_queue = ends.writer_queue.clone();
        let answer = ends.inbound.clone();
        let mut far = Far {
            peer,
            claim,
            network_id: self.network_id,
            reader: BucketReader::new(),
        };
        far.reader.complete_handshake(DEFAULT_MAX_PACKET_SIZE);
        let writer = thread::spawn(move || {
            while let Ok(bytes) = writer_queue.pop_blocking() {
                writer_queue.release(bytes.len());
                let Some(frames) = far.feed(&bytes) else {
                    return;
                };
                for frame in frames {
                    if answer.blocking_send(frame).is_err() {
                        return;
                    }
                }
            }
        });
        self.slots().insert(
            id,
            Slot {
                inject: Some(ends.inbound.clone()),
                hold: Some(ends.hold),
                writer: Some(writer),
            },
        );
        Ok(Channel {
            open,
            session: ends.session,
            endpoint: *endpoint,
            gap: None,
        })
    }
}

impl Dial for PeerDial {
    fn connect_async(&self, endpoint: &Endpoint) -> ConnectFuture {
        let expected = endpoint
            .clearnet_ip()
            .and_then(|ip| self.expected.lock().expect("expected peers").remove(&ip));
        let (peer, claim) = match expected {
            Some(Expected { peer, claim }) => (peer, claim),
            None => (Box::new(Silent) as Box<dyn SyncPeer>, empty_claim()),
        };
        let result = self.open(endpoint, peer, claim);
        Box::pin(async move { result })
    }

    /// Each connector's own table: a scripted peer stands in for that
    /// connector's far end, and its ends mean what the connector's do.
    fn stamp_stream_end(&self, connector: ConnectorId, end: StreamEnd) -> DialFailure {
        match connector {
            ConnectorId::Clearnet => shekyl_clearnet::stamp_stream_end(end),
            ConnectorId::Tor => shekyl_tor::stamp_stream_end(end),
        }
    }
}

impl Drop for PeerDial {
    fn drop(&mut self) {
        let ids: Vec<SocketId> = self.slots().keys().copied().collect();
        for id in ids {
            self.retire(id);
        }
    }
}

/// The far side of one channel: the node's bytes read as buckets, the
/// handshake and the timed sync answered here, the rest the peer's.
struct Far {
    peer: Box<dyn SyncPeer>,
    claim: CoreSyncData,
    network_id: [u8; 16],
    reader: BucketReader,
}

impl Far {
    /// The frames to push back for `bytes`. `None` once the node wrote
    /// something that does not frame: a real peer would close.
    fn feed(&mut self, bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
        if self.reader.feed(bytes).is_err() {
            return None;
        }
        let mut out = Vec::new();
        loop {
            match self.reader.next_message() {
                Ok(Some(received)) => out.extend(self.answer(received)),
                Ok(None) => return Some(out),
                Err(_) => return None,
            }
        }
    }

    fn answer(&mut self, received: Received) -> Vec<Vec<u8>> {
        match received {
            Received::Request { command, .. } if command == Command::Handshake.wire_id() => {
                let reply = HandshakeResponse {
                    node_data: BasicNodeData {
                        network_id: self.network_id,
                    },
                    payload_data: self.claim.clone(),
                    local_peerlist_new: Vec::new(),
                }
                .store()
                .expect("the response stores");
                vec![response(command, &reply)]
            }
            Received::Request { command, .. } if command == Command::TimedSync.wire_id() => {
                let reply = TimedSyncResponse {
                    payload_data: self.claim.clone(),
                    local_peerlist_new: Vec::new(),
                }
                .store()
                .expect("the response stores");
                vec![response(command, &reply)]
            }
            // The node's answer to this side's own handshake request.
            Received::Response { .. } => Vec::new(),
            Received::Request { command, payload }
            | Received::Notification { command, payload } => {
                self.peer.on_message(command, &payload)
            }
        }
    }
}
