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
//! Zone bind runs [`drive_inbound_async`] as one task per connection on the
//! transport runtime. The harness's synchronous connect path runs
//! [`drive_inbound`] on a joined thread. The blocking form is not for the
//! zone: on a runtime with one blocking lane it drove one connection at a
//! time and left every later one deaf until the first closed.

use crate::hub::Hub;
use shekyl_capped_stream::Session;

/// Drive `session` until the reader stops or the handler refuses a frame.
///
/// The cause is the one the connector stored on the session.
/// [`CloseKind::PeerClosed`] is that cause only when the reader saw
/// end-of-file. A session closed with no stored cause is
/// [`CloseKind::LocalClose`].
pub fn drive_inbound(hub: &Hub, id: shekyl_transport_layer::SocketId, mut session: Session) {
    while let Some(frame) = session.recv_blocking() {
        if !hub.deliver(id, frame) {
            return;
        }
    }
    hub.finish(id, session.close_cause());
}

/// [`drive_inbound`] as a task. Holds no thread between frames or while the
/// strand parses one.
pub async fn drive_inbound_async(
    hub: &Hub,
    id: shekyl_transport_layer::SocketId,
    mut session: Session,
) {
    while let Some(frame) = session.recv().await {
        if !hub.deliver_async(id, frame).await {
            return;
        }
    }
    hub.finish(id, session.close_cause());
}
