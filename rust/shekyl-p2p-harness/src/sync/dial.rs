// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The seam dialer the loopback harness installs: each channel's far end
//! is a scripted peer.
//!
//! What the node sends on a channel is split into Levin buckets and handed
//! to that channel's [`SyncPeer`]. What the peer answers is pushed back
//! into the channel the way a socket reader would, so it reaches the node
//! through the hub's pump, the router and the owner exactly as a remote
//! peer's bytes do. A test pushes frames of its own with `Hub::inject`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard};
use std::thread::{self, JoinHandle};

use shekyl_capped_stream::{InboundEnd, QueueHold, Session, StreamEnds};
use shekyl_levin::{BucketHead, HEADER_SIZE};
use shekyl_peer_policy::InboundCeiling;
use shekyl_seam::{admit, drive_inbound, Channel, Dial, Endpoint, Hub};
use shekyl_timing_engine::Tick;
use shekyl_transport_layer::{CloseCause, SocketId, Sockets};

/// The far end of one channel.
pub trait SyncPeer: Send {
    /// One whole bucket the node sent. The frames returned are pushed back
    /// to the node, in order.
    fn on_message(&mut self, command: u32, payload: &[u8]) -> Vec<Vec<u8>>;
}

/// A peer that never answers.
pub struct Silent;

impl SyncPeer for Silent {
    fn on_message(&mut self, _command: u32, _payload: &[u8]) -> Vec<Vec<u8>> {
        Vec::new()
    }
}

struct Slot {
    inject: Option<InboundEnd>,
    hold: Option<QueueHold>,
    writer: Option<JoinHandle<()>>,
    pump: Option<JoinHandle<()>>,
}

/// The dialer (module docs).
pub struct PeerDial {
    sockets: Sockets,
    send_cap: usize,
    expected: Mutex<HashMap<IpAddr, Box<dyn SyncPeer>>>,
    slots: Mutex<HashMap<SocketId, Slot>>,
}

impl PeerDial {
    /// Channels on `sockets`, each with an outbound cap of `send_cap`.
    #[must_use]
    pub fn new(sockets: Sockets, send_cap: usize) -> Self {
        Self {
            sockets,
            send_cap,
            expected: Mutex::new(HashMap::new()),
            slots: Mutex::new(HashMap::new()),
        }
    }

    /// The next channel dialed to `ip` has `peer` at its far end.
    pub fn expect(&self, ip: IpAddr, peer: Box<dyn SyncPeer>) {
        self.expected
            .lock()
            .expect("expected peers")
            .insert(ip, peer);
    }

    fn slots(&self) -> MutexGuard<'_, HashMap<SocketId, Slot>> {
        self.slots.lock().expect("peer slots")
    }
}

impl Dial for PeerDial {
    fn connect(
        &self,
        endpoint: &Endpoint,
        ceiling: InboundCeiling,
        now: Tick,
    ) -> Result<Channel, CloseCause> {
        let open = admit(&self.sockets, endpoint, now, ceiling)?;
        let id = open.id();
        let ends = StreamEnds::open(self.send_cap);
        let writer_queue = ends.writer_queue.clone();
        let mut peer = endpoint
            .clearnet_ip()
            .and_then(|ip| self.expected.lock().expect("expected peers").remove(&ip))
            .unwrap_or_else(|| Box::new(Silent));
        let answer = ends.inbound.clone();
        let writer = thread::spawn(move || {
            let mut buckets = Buckets::default();
            while let Ok(bytes) = writer_queue.pop_blocking() {
                writer_queue.release(bytes.len());
                for (command, payload) in buckets.feed(&bytes) {
                    for frame in peer.on_message(command, &payload) {
                        if answer.blocking_send(frame).is_err() {
                            return;
                        }
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
                pump: None,
            },
        );
        Ok(Channel {
            open,
            session: ends.session,
            endpoint: *endpoint,
            gap: None,
        })
    }

    fn inject(&self, id: SocketId, frame: Vec<u8>) -> bool {
        let sender = self.slots().get(&id).and_then(|slot| slot.inject.clone());
        sender.is_some_and(|sender| sender.blocking_send(frame).is_ok())
    }

    fn reader_stopped(&self, id: SocketId) {
        let sender = self
            .slots()
            .get_mut(&id)
            .and_then(|slot| slot.inject.take());
        drop(sender);
    }

    fn retired(&self, id: SocketId) {
        let Some(slot) = self.slots().remove(&id) else {
            return;
        };
        drop(slot.inject);
        drop(slot.hold);
        if let Some(writer) = slot.writer {
            let _joined = writer.join();
        }
        if let Some(pump) = slot.pump {
            let _joined = pump.join();
        }
    }

    fn drive(&self, hub: &Hub, id: SocketId, session: Session) {
        let hub = hub.clone();
        let pump = thread::spawn(move || drive_inbound(&hub, id, session));
        let mut slots = self.slots();
        if let Some(slot) = slots.get_mut(&id) {
            slot.pump = Some(pump);
            return;
        }
        drop(slots);
        let _joined = pump.join();
    }
}

impl Drop for PeerDial {
    fn drop(&mut self) {
        let ids: Vec<SocketId> = self.slots().keys().copied().collect();
        for id in ids {
            self.retired(id);
        }
    }
}

/// A byte stream split into whole Levin buckets. A header that does not
/// read ends the stream: nothing after it is a bucket.
#[derive(Default)]
pub struct Buckets {
    buffer: Vec<u8>,
    broken: bool,
}

impl Buckets {
    /// The whole buckets `bytes` completes, as (command, payload).
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<(u32, Vec<u8>)> {
        let mut out = Vec::new();
        if self.broken {
            return out;
        }
        self.buffer.extend_from_slice(bytes);
        loop {
            if self.buffer.len() < HEADER_SIZE {
                return out;
            }
            let raw: [u8; HEADER_SIZE] = self.buffer[..HEADER_SIZE]
                .try_into()
                .expect("a whole header");
            let Ok(head) = BucketHead::read(&raw) else {
                self.broken = true;
                self.buffer.clear();
                return out;
            };
            let Ok(len) = usize::try_from(head.payload_len) else {
                self.broken = true;
                return out;
            };
            let Some(end) = HEADER_SIZE.checked_add(len) else {
                self.broken = true;
                return out;
            };
            if self.buffer.len() < end {
                return out;
            }
            let payload = self.buffer[HEADER_SIZE..end].to_vec();
            self.buffer.drain(..end);
            out.push((head.command, payload));
        }
    }

    /// Whether a header failed to read.
    #[must_use]
    pub const fn broken(&self) -> bool {
        self.broken
    }
}
