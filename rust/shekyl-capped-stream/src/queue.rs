// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The outbound cap. Bytes stay counted until the writer finishes them,
//! so a peer that stops reading cannot grow the queue past the cap.
//!
//! A queue closes once, and **why** it closed is recorded in the same
//! step, under its lock: a writer that finds it closed reads the reason
//! with the fact. Were the reason set after the close, a writer woken in
//! between would read "closed" without "full" and record the connection
//! as closed locally.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use shekyl_transport_layer::{CloseKind, MessageClass};
use tokio::sync::Notify;

struct Item {
    class: MessageClass,
    bytes: Vec<u8>,
}

/// Outbound bytes. The cap is the only storage limit. A send that does
/// not fit is not stored.
#[derive(Clone)]
pub struct ByteQueue {
    inner: Arc<Mutex<ByteQueueInner>>,
    data: Arc<Notify>,
    /// Wakes [`Self::pop_blocking`]. The async path uses [`Self::data`].
    parked: Arc<Condvar>,
    /// Tripped by the overflow that closes this queue, and by nothing
    /// else: the queue is the event's one owner.
    overfull: Arc<Overfull>,
}

struct ByteQueueInner {
    limit: usize,
    used: usize,
    /// `Some` once the queue is closed, with why. Set once; the first
    /// reason stands.
    closed: Option<CloseReason>,
    items: VecDeque<Item>,
}

/// Why a [`ByteQueue`] stopped taking bytes — what a writer that finds it
/// closed and empty reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// An end of the connection closed it: the caller's [`crate::Session`]
    /// or the connection task's [`crate::QueueHold`] was dropped.
    Local,
    /// A send did not fit under the cap.
    Overfull,
}

impl CloseReason {
    /// The D12 close kind this reason records.
    #[must_use]
    pub const fn kind(self) -> CloseKind {
        match self {
            Self::Local => CloseKind::LocalClose,
            Self::Overfull => CloseKind::SendQueueFull,
        }
    }
}

/// A push could not store the buffer. [`crate::SendHalf::try_send`] maps
/// each case to its close kind.
#[derive(Debug, PartialEq, Eq)]
pub enum PushError {
    /// `bytes` would pass the cap. Nothing was stored.
    Full,
    /// The queue was closed. Nothing was stored.
    Closed,
}

impl ByteQueue {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ByteQueueInner {
                limit,
                used: 0,
                closed: None,
                items: VecDeque::new(),
            })),
            data: Arc::new(Notify::new()),
            parked: Arc::new(Condvar::new()),
            overfull: Arc::new(Overfull::new()),
        }
    }

    /// The signal this queue trips when a send does not fit: what a copy
    /// in progress selects on to stop.
    #[must_use]
    pub fn overfull(&self) -> Arc<Overfull> {
        Arc::clone(&self.overfull)
    }

    fn wake(&self) {
        self.data.notify_waiters();
        self.parked.notify_all();
    }

    pub(crate) fn try_push(&self, bytes: Vec<u8>) -> Result<(), PushError> {
        let n = bytes.len();
        let mut inner = self.inner.lock().expect("outbound");
        if inner.closed.is_some() {
            return Err(PushError::Closed);
        }
        if n == 0 {
            return Ok(());
        }
        let Some(next) = inner.used.checked_add(n) else {
            return self.overflow(inner);
        };
        if next > inner.limit {
            return self.overflow(inner);
        }
        inner.used = next;
        inner.items.push_back(Item {
            class: MessageClass::Session,
            bytes,
        });
        drop(inner);
        self.data.notify_one();
        self.parked.notify_all();
        Ok(())
    }

    /// The buffer does not fit. The queue closes **as overfull** under the
    /// caller's lock, so a later send cannot land in the gap before the
    /// copy task exits and a writer cannot see the close without its
    /// reason. The signal is tripped before anyone is woken.
    fn overflow(
        &self,
        mut inner: std::sync::MutexGuard<'_, ByteQueueInner>,
    ) -> Result<(), PushError> {
        inner.closed = Some(CloseReason::Overfull);
        drop(inner);
        self.overfull.trip();
        self.wake();
        Err(PushError::Full)
    }

    /// Return `n` bytes of cap after the writer finishes that buffer.
    pub fn release(&self, n: usize) {
        let mut inner = self.inner.lock().expect("outbound");
        inner.used = inner.used.saturating_sub(n);
    }

    /// Close from an end of the connection. An overflow that already
    /// closed the queue keeps its reason.
    pub(crate) fn close(&self) {
        self.inner
            .lock()
            .expect("outbound")
            .closed
            .get_or_insert(CloseReason::Local);
        self.wake();
    }

    /// Close and drop the pending tail. The writer's next pop is the close
    /// reason at once, not after draining what is queued.
    ///
    /// This is the local-close path: a ban, a protocol refusal, or
    /// `del_in_connections` has nothing it needs delivered, so the tail is
    /// dropped, not flushed. An overflow that already closed the queue keeps
    /// its reason. It does not touch a write already in progress —
    /// `write_all` on the frame the writer already popped runs to completion
    /// or the socket errors; a stalled in-flight write is not bounded here.
    pub(crate) fn discard(&self) {
        let mut inner = self.inner.lock().expect("outbound");
        inner.closed.get_or_insert(CloseReason::Local);
        inner.items.clear();
        inner.used = 0;
        drop(inner);
        self.wake();
    }

    /// The next buffer and the class the sender named, or why the queue
    /// closed once it is closed and empty. The byte count stays until
    /// [`Self::release`].
    pub(crate) async fn pop(&self) -> Result<(MessageClass, Vec<u8>), CloseReason> {
        loop {
            let mut notified = std::pin::pin!(self.data.notified());
            notified.as_mut().enable();
            if let Some(next) = self.inner.lock().expect("outbound").next() {
                return next;
            }
            notified.await;
        }
    }

    /// The next buffer, if one is waiting. Does not wait, and does not
    /// return the bytes to the cap: the writer calls [`Self::release`]
    /// after it finishes them.
    #[must_use]
    pub fn try_pop(&self) -> Option<Vec<u8>> {
        self.inner
            .lock()
            .expect("outbound")
            .items
            .pop_front()
            .map(|item| item.bytes)
    }

    /// The next buffer, or why the queue closed once it is closed and
    /// empty. Blocks the calling thread. The byte count stays until
    /// [`Self::release`].
    ///
    /// [`crate::write_capped`] waits the same way on a task. This is the
    /// wait for a thread that is not a task: the seam harness writer, until
    /// zone bind runs the connector's `write_capped`.
    ///
    /// # Errors
    ///
    /// The [`CloseReason`] once the queue is closed and empty.
    pub fn pop_blocking(&self) -> Result<Vec<u8>, CloseReason> {
        let mut inner = self.inner.lock().expect("outbound");
        loop {
            if let Some(next) = inner.next() {
                return next.map(|(_class, bytes)| bytes);
            }
            inner = self
                .parked
                .wait(inner)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    #[cfg(test)]
    pub(crate) fn pop_now(&self) -> Option<Vec<u8>> {
        self.try_pop()
    }
}

impl ByteQueueInner {
    /// What a pop takes now: the next buffer, or the close reason once the
    /// queue is closed and empty; `None` to wait. One reading for both
    /// pops, under the lock that set the reason.
    fn next(&mut self) -> Option<Result<(MessageClass, Vec<u8>), CloseReason>> {
        match self.items.pop_front() {
            Some(item) => Some(Ok((item.class, item.bytes))),
            None => self.closed.map(Err),
        }
    }
}

/// The signal that a send did not fit, owned and tripped by its
/// [`ByteQueue`].
///
/// The flag is the fact. The notify wakes a write already in progress and
/// a reader. `notify_waiters` stores no permit, so the flag is what a late
/// waiter observes. A writer finding the queue closed does not read this:
/// the queue's [`CloseReason`] is set with the close.
pub struct Overfull {
    flag: AtomicBool,
    notify: Notify,
}

impl Overfull {
    pub(crate) fn new() -> Self {
        Self {
            flag: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    pub(crate) fn trip(&self) {
        self.flag.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    pub(crate) fn tripped(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }

    pub(crate) async fn wait(&self) {
        loop {
            let mut notified = std::pin::pin!(self.notify.notified());
            notified.as_mut().enable();
            if self.tripped() {
                return;
            }
            notified.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use shekyl_transport_layer::CloseKind;

    use super::{ByteQueue, CloseReason};

    #[test]
    fn the_cap_counts_bytes_and_holds_more_than_one_buffer() {
        let queue = ByteQueue::new(4);
        queue.try_push(b"ab".to_vec()).expect("first");
        let first = queue.pop_now().expect("queued");
        queue.release(first.len());
        queue
            .try_push(b"cdef".to_vec())
            .expect("the release freed the cap");
    }

    #[test]
    fn a_send_that_does_not_fit_closes_the_queue() {
        let queue = ByteQueue::new(4);
        queue.try_push(b"ab".to_vec()).expect("fits");
        assert_eq!(
            queue.try_push(b"cdef".to_vec()),
            Err(super::PushError::Full)
        );
        assert_eq!(queue.try_push(b"c".to_vec()), Err(super::PushError::Closed));
        assert_eq!(queue.pop_now().as_deref(), Some(b"ab".as_slice()));
        assert!(queue.pop_now().is_none());
    }

    /// The overflow's reason is read with its close: by the time
    /// `try_push` returns `Full`, a pop of the drained queue reports
    /// `Overfull` and the signal is tripped. With the reason set after
    /// the close, a writer woken in between read a local close.
    #[test]
    fn an_overflow_closes_with_its_reason() {
        let queue = ByteQueue::new(0);
        assert_eq!(queue.try_push(b"x".to_vec()), Err(super::PushError::Full));
        assert!(queue.overfull().tripped(), "tripped before the wake");
        assert_eq!(queue.pop_blocking(), Err(CloseReason::Overfull));
        queue.close();
        assert_eq!(
            queue.pop_blocking(),
            Err(CloseReason::Overfull),
            "a later local close keeps the first reason"
        );
    }

    #[test]
    fn a_local_close_is_local() {
        let queue = ByteQueue::new(4);
        queue.try_push(b"ab".to_vec()).expect("fits");
        queue.close();
        assert_eq!(queue.pop_blocking().as_deref(), Ok(b"ab".as_slice()));
        assert_eq!(queue.pop_blocking(), Err(CloseReason::Local));
        assert!(!queue.overfull().tripped());
        assert_eq!(CloseReason::Local.kind(), CloseKind::LocalClose);
        assert_eq!(CloseReason::Overfull.kind(), CloseKind::SendQueueFull);
    }

    /// A local close drops the tail. The next pop is the reason, not the
    /// bytes that were queued.
    #[test]
    fn a_discard_drops_the_tail_and_keeps_an_earlier_reason() {
        let queue = ByteQueue::new(8);
        queue.try_push(b"ab".to_vec()).expect("fits");
        queue.discard();
        assert_eq!(queue.pop_blocking(), Err(CloseReason::Local));

        let full = ByteQueue::new(0);
        assert_eq!(full.try_push(b"x".to_vec()), Err(super::PushError::Full));
        full.discard();
        assert_eq!(full.pop_blocking(), Err(CloseReason::Overfull));
    }
}
