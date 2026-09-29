// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The dialer the seam asks for a channel.
//!
//! Zone bind installs the dialer that calls a connector. The loopback
//! dialer is the strand harness: an in-memory channel, not a socket.
//! The hub does not dial and does not build a [`shekyl_capped_stream::StreamEnds`].

use std::thread::JoinHandle;

use shekyl_capped_stream::Session;
use shekyl_peer_policy::InboundCeiling;
use shekyl_timing_engine::Tick;
use shekyl_transport_layer::{CloseCause, OpenSocket, SocketId};

use crate::endpoint::Endpoint;

/// A channel the connector already admitted and built.
pub struct Channel {
    /// The admission reservation.
    pub open: OpenSocket,
    /// The caller's end of the byte cap. The pump owns it.
    pub session: Session,
    /// What `established` posts.
    pub endpoint: Endpoint,
}

/// Opens a channel. The hub adopts the result and posts `established`.
pub trait Dial: Send + Sync {
    /// Admit and build the channel. `ceiling` and `now` are the hub's,
    /// copied before this call so the dial does not hold the table lock.
    fn connect(
        &self,
        endpoint: &Endpoint,
        ceiling: InboundCeiling,
        now: Tick,
    ) -> Result<Channel, CloseCause>;

    /// Push one frame into the channel the way the socket reader would.
    /// The harness does this. A connector dialer returns false: its read
    /// loop owns the sender.
    fn inject(&self, id: SocketId, frame: Vec<u8>) -> bool {
        let _ = (id, frame);
        false
    }

    /// The hub recorded a cause. Drop the harness sender so the pump's
    /// read returns. Does not join: the strand may be inside this call.
    fn reader_stopped(&self, id: SocketId) {
        let _ = id;
    }

    /// The executor dropped the link. Join the harness threads.
    fn retired(&self, id: SocketId) {
        let _ = id;
    }

    /// The synchronous connect path started the inbound pump on a thread.
    /// The harness joins it from [`Self::retired`].
    fn track_pump(&self, id: SocketId, pump: JoinHandle<()>) {
        drop((id, pump));
    }
}
