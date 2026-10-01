// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The in-memory channel the strand tests dial.
//!
//! It admits on the hub's socket table and builds a [`StreamEnds`]. A thread
//! discards outbound messages the way `write_capped` will once zone bind owns
//! the socket. Nothing here is a peer. Zone bind does not install this dialer.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::thread::{self, JoinHandle};

use shekyl_capped_stream::{FrameSender, QueueHold, StreamEnds};
use shekyl_peer_policy::InboundCeiling;
use shekyl_timing_engine::Tick;
use shekyl_transport_layer::{CloseCause, SocketId, Sockets};

use crate::dial::{Channel, Dial};
use crate::endpoint::{admit, Endpoint};

struct Slot {
    inject: Option<FrameSender>,
    hold: Option<QueueHold>,
    writer: Option<JoinHandle<()>>,
    pump: Option<JoinHandle<()>>,
}

/// Admits on `sockets` and hands back a session whose writer drains.
pub struct Loopback {
    sockets: Sockets,
    send_cap: usize,
    slots: Mutex<HashMap<SocketId, Slot>>,
}

impl Loopback {
    /// `send_cap` is the outbound byte cap of each harness channel.
    #[must_use]
    pub fn new(sockets: Sockets, send_cap: usize) -> Self {
        Self {
            sockets,
            send_cap,
            slots: Mutex::new(HashMap::new()),
        }
    }

    fn slots(&self) -> MutexGuard<'_, HashMap<SocketId, Slot>> {
        self.slots.lock().expect("loopback slots")
    }
}

impl Dial for Loopback {
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
        // The drain stops on either close reason and records neither: a
        // full send is recorded as `SendQueueFull` by the hub at the send
        // (`Hub::send`), and retirement drops the hold, a local close.
        let writer = thread::spawn(move || {
            while let Ok(bytes) = writer_queue.pop_blocking() {
                writer_queue.release(bytes.len());
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
            endpoint: endpoint.clone(),
            gap: None,
        })
    }

    fn inject(&self, id: SocketId, frame: Vec<u8>) -> bool {
        let sender = self.slots().get(&id).and_then(|slot| slot.inject.clone());
        let Some(sender) = sender else {
            return false;
        };
        sender.blocking_send(frame).is_ok()
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
            writer.join().expect("harness writer");
        }
        if let Some(pump) = slot.pump {
            pump.join().expect("harness pump");
        }
    }

    fn track_pump(&self, id: SocketId, pump: JoinHandle<()>) {
        let mut slots = self.slots();
        if let Some(slot) = slots.get_mut(&id) {
            slot.pump = Some(pump);
            return;
        }
        drop(slots);
        pump.join().expect("harness pump");
    }
}

impl Drop for Loopback {
    fn drop(&mut self) {
        let ids: Vec<SocketId> = self.slots().keys().copied().collect();
        for id in ids {
            self.retired(id);
        }
    }
}
