// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One connection's two ends. The session is the caller's. The hold is
//! the connection task's. Dropping either one closes the queue.

use std::sync::{Arc, Mutex};

use shekyl_transport_layer::{CloseCause, CloseKind};
use tokio::sync::mpsc;

use crate::queue::{ByteQueue, Overfull, PushError};

/// The sender the connector's reader uses, and the cause that closes it.
///
/// [`Self::close`] records the first cause. Dropping every clone ends
/// [`Session::recv`]. The cause is whatever [`Self::close`] stored.
/// A drop that never called [`Self::close`] is [`CloseKind::LocalClose`],
/// not a peer close: [`CloseKind::PeerClosed`] is only the reader's
/// end-of-file.
#[derive(Clone)]
pub struct InboundEnd {
    tx: mpsc::Sender<Vec<u8>>,
    cause: Arc<Mutex<Option<CloseCause>>>,
}

impl InboundEnd {
    /// Record `cause` if none is recorded yet.
    pub fn close(&self, cause: CloseCause) {
        let mut slot = self.cause.lock().expect("inbound cause");
        if slot.is_none() {
            *slot = Some(cause);
        }
    }

    /// Record `cause` on this end and on the outbound queue.
    ///
    /// The first cause on each end stands. The connection task calls this
    /// once, then aborts the other half. A later drop does not replace it.
    pub fn seal(&self, hold: &QueueHold, cause: CloseCause) {
        self.close(cause);
        hold.close_with(cause);
    }

    /// Hand one decoded frame to the session.
    pub async fn send(&self, frame: Vec<u8>) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        self.tx.send(frame).await
    }

    /// [`Self::send`] for a thread that is not a task. The harness injects
    /// a frame this way.
    pub fn blocking_send(&self, frame: Vec<u8>) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        self.tx.blocking_send(frame)
    }
}

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

    /// Close the queue and drop the pending tail; the writer then finishes,
    /// and the connection task drops the socket.
    ///
    /// This is how a close that started on the caller's side reaches the
    /// wire. Without it the socket stays open until the peer next sends:
    /// the [`Session`] whose drop would close the queue is held by the
    /// inbound drive, parked in [`Session::recv`] waiting for that frame.
    ///
    /// The tail is discarded, not drained: a ban, a protocol refusal, or
    /// `del_in_connections` has nothing queued that it needs delivered.
    /// A write already taken by the writer is not part of that tail. That
    /// frame runs to completion, or the socket errors. A stalled in-flight
    /// write is not bounded here.
    pub fn discard(&self) {
        self.queue.discard();
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

impl QueueHold {
    /// Close the outbound end with the connector's cause. A later drop
    /// does not replace it.
    pub fn close_with(&self, cause: CloseCause) {
        self.queue.close_named(cause);
    }
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
    /// The cause [`InboundEnd::close`] stored. Read after [`Self::recv`]
    /// returns `None`.
    cause: Arc<Mutex<Option<CloseCause>>>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.queue.close();
    }
}

impl Session {
    /// The next frame the connector decoded. `None` means the inbound end
    /// closed. [`Self::close_cause`] is the cause the connector stored.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.inbound.recv().await
    }

    /// [`Self::recv`] for a thread that is not a task.
    #[must_use]
    pub fn recv_blocking(&mut self) -> Option<Vec<u8>> {
        self.inbound.blocking_recv()
    }

    /// The cause that closed this session.
    ///
    /// [`CloseKind::PeerClosed`] only when the connector's reader saw
    /// end-of-file and stored that cause. A close that stored nothing is
    /// [`CloseKind::LocalClose`].
    #[must_use]
    pub fn close_cause(&self) -> CloseCause {
        self.cause
            .lock()
            .expect("inbound cause")
            .unwrap_or_else(|| CloseCause::new(CloseKind::LocalClose))
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
    /// The reader sends decoded frames here. [`InboundEnd::close`] names
    /// why the session ended, before the last sender is dropped.
    pub inbound: InboundEnd,
}

impl StreamEnds {
    /// `send_queue_bytes` is the outbound cap.
    #[must_use]
    pub fn open(send_queue_bytes: usize) -> Self {
        let queue = ByteQueue::new(send_queue_bytes);
        let overfull = queue.overfull();
        let (tx, inbound_rx) = mpsc::channel(UNREAD_FRAMES);
        let cause = Arc::new(Mutex::new(None));
        let session = Session {
            inbound: inbound_rx,
            queue: queue.clone(),
            cause: Arc::clone(&cause),
        };
        Self {
            session,
            writer_queue: queue.clone(),
            hold: QueueHold { queue },
            overfull,
            inbound: InboundEnd { tx, cause },
        }
    }
}
