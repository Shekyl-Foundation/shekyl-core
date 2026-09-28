// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Inbound frames, one at a time, in the order the reader produced them.
//!
//! The connector's read side fills the session. This function takes each
//! frame, posts it, and does not take the next until the strand has
//! returned. That is the read window: the session channel holds one frame,
//! so the socket read stalls behind this wait.
//!
//! Zone bind runs this on the transport runtime. The synchronous connect
//! path runs it on a joined thread until that handoff.

use shekyl_transport_layer::{CloseCause, CloseKind};

use crate::hub::Hub;
use shekyl_capped_stream::Session;

/// Drive `session` until the reader stops or the handler refuses a frame.
///
/// A reader that stops with no cause recorded yet is [`CloseKind::PeerClosed`].
/// A cause that was already recorded stays the cause.
pub fn drive_inbound(hub: &Hub, id: shekyl_transport_layer::SocketId, mut session: Session) {
    while let Some(frame) = session.recv_blocking() {
        if !hub.deliver(id, frame) {
            return;
        }
    }
    hub.finish(id, CloseCause::new(CloseKind::PeerClosed));
}
