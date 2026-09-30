// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One connection's two ends. The session is the caller's. The hold is
//! the connection task's. Dropping either one closes the queue.

use std::sync::Arc;

use shekyl_transport_layer::CloseKind;
use tokio::sync::mpsc;

use crate::queue::{ByteQueue, Overfull, PushError};

/// The sender the connector's reader uses to hand one frame to the session.
pub type FrameSender = mpsc::Sender<Vec<u8>>;

/// The send half of a session. Dropping it does not close the queue.
/// [`Session`] and [`QueueHold`] do.
#[derive(Clone)]
pub struct SendHalf {
    queue: ByteQueue,
}

impl SendHalf {
    /// Queue one whole message. A buffer that does not fit is not stored.
    ///
    /// [`CloseKind::SendQueueFull`] means the queue closed as overfull and
    /// tripped [`Overfull`], in one step (`ByteQueue`'s module docs).
    /// [`CloseKind::IoError`] means the queue is already closed.
    pub fn try_send(&self, bytes: Vec<u8>) -> Result<(), CloseKind> {
        match self.queue.try_push(bytes) {
            Ok(()) => Ok(()),
            Err(PushError::Full) => Err(CloseKind::SendQueueFull),
            Err(PushError::Closed) => Err(CloseKind::IoError),
        }
    }
}

/// Decoded frames waiting on [`Session::recv`].
///
/// One frame: a slow caller stops the reader, and TCP pushes back on
/// the peer. A second slot would hide that stall.
pub const UNREAD_FRAMES: usize = 1;

/// Closes the queue when the connection task ends.
///
/// The caller may still hold the [`Session`]. Further sends then fail,
/// and a writer waiting for bytes — [`crate::write_capped`] or
/// [`ByteQueue::pop_blocking`] — wakes with [`crate::CloseReason::Local`].
pub struct QueueHold {
    queue: ByteQueue,
}

impl Drop for QueueHold {
    fn drop(&mut self) {
        self.queue.close();
    }
}

/// The caller's end of one connection.
pub struct Session {
    inbound: mpsc::Receiver<Vec<u8>>,
    queue: ByteQueue,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.queue.close();
    }
}

impl Session {
    /// The next frame the connector decoded. `None` means the reader stopped.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.inbound.recv().await
    }

    /// [`Self::recv`] for a thread that is not a task.
    #[must_use]
    pub fn recv_blocking(&mut self) -> Option<Vec<u8>> {
        self.inbound.blocking_recv()
    }

    /// A send handle that does not close the queue when dropped.
    #[must_use]
    pub fn send_half(&self) -> SendHalf {
        SendHalf {
            queue: self.queue.clone(),
        }
    }

    /// Queue bytes up to the cap. A buffer that does not fit is not stored.
    ///
    /// [`CloseKind::SendQueueFull`] means the connection is closing.
    /// [`Overfull`] cancels a write that has already started. The cap is
    /// the caller's, unmeasured until PWD-T6 names it.
    /// [`CloseKind::IoError`] means the queue is already closed.
    pub fn try_send(&self, bytes: Vec<u8>) -> Result<(), CloseKind> {
        self.send_half().try_send(bytes)
    }
}

/// The pieces of one connection. [`Self::open`] is the only constructor,
/// so the session, the writer, and the hold share one queue.
pub struct StreamEnds {
    /// What the connector hands the caller.
    pub session: Session,
    /// A clone that does not close the queue on drop. The writer holds it.
    pub writer_queue: ByteQueue,
    /// Drop this when the connection task ends.
    pub hold: QueueHold,
    /// The full-queue signal the copy selects on: the queue's own.
    pub overfull: Arc<Overfull>,
    /// The reader sends decoded frames here.
    pub inbound: mpsc::Sender<Vec<u8>>,
}

impl StreamEnds {
    /// `send_queue_bytes` is the outbound cap.
    #[must_use]
    pub fn open(send_queue_bytes: usize) -> Self {
        let queue = ByteQueue::new(send_queue_bytes);
        let overfull = queue.overfull();
        let (inbound, inbound_rx) = mpsc::channel(UNREAD_FRAMES);
        let session = Session {
            inbound: inbound_rx,
            queue: queue.clone(),
        };
        Self {
            session,
            writer_queue: queue.clone(),
            hold: QueueHold { queue },
            overfull,
            inbound,
        }
    }
}
