// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The outbound cap. Bytes stay counted until the writer finishes them,
//! so a peer that stops reading cannot grow the queue past the cap.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use shekyl_transport_layer::MessageClass;
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
}

struct ByteQueueInner {
    limit: usize,
    used: usize,
    closed: bool,
    items: VecDeque<Item>,
}

/// [`ByteQueue::try_push`] could not store the buffer.
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
                closed: false,
                items: VecDeque::new(),
            })),
            data: Arc::new(Notify::new()),
            parked: Arc::new(Condvar::new()),
        }
    }

    fn wake(&self) {
        self.data.notify_waiters();
        self.parked.notify_all();
    }

    pub(crate) fn try_push(&self, bytes: Vec<u8>) -> Result<(), PushError> {
        let n = bytes.len();
        let mut inner = self.inner.lock().expect("outbound");
        if inner.closed {
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

    /// The buffer does not fit. The queue closes under the caller's lock,
    /// so a later send cannot land in the gap before the copy task exits.
    fn overflow(
        &self,
        mut inner: std::sync::MutexGuard<'_, ByteQueueInner>,
    ) -> Result<(), PushError> {
        inner.closed = true;
        drop(inner);
        self.wake();
        Err(PushError::Full)
    }

    /// Return `n` bytes of cap after the writer finishes that buffer.
    pub fn release(&self, n: usize) {
        let mut inner = self.inner.lock().expect("outbound");
        inner.used = inner.used.saturating_sub(n);
    }

    pub(crate) fn close(&self) {
        self.inner.lock().expect("outbound").closed = true;
        self.wake();
    }

    /// Close and drop the pending tail. The writer's next `pop`/`pop_blocking`
    /// returns `None` at once rather than after draining what is queued.
    ///
    /// This is the local-close path: a ban, a protocol refusal, or
    /// `del_in_connections` has nothing it needs delivered, so the tail is
    /// dropped, not flushed. It does not touch a write already in progress —
    /// `write_all` on the frame the writer already popped runs to completion
    /// or the socket errors; a stalled in-flight write is not bounded here.
    pub(crate) fn discard(&self) {
        let mut inner = self.inner.lock().expect("outbound");
        inner.closed = true;
        inner.items.clear();
        inner.used = 0;
        drop(inner);
        self.wake();
    }

    /// The next buffer and the class the sender named. `None` means the
    /// queue is closed and empty. The byte count stays until [`Self::release`].
    pub(crate) async fn pop(&self) -> Option<(MessageClass, Vec<u8>)> {
        loop {
            let mut notified = std::pin::pin!(self.data.notified());
            notified.as_mut().enable();
            {
                let mut inner = self.inner.lock().expect("outbound");
                if let Some(item) = inner.items.pop_front() {
                    return Some((item.class, item.bytes));
                }
                if inner.closed {
                    return None;
                }
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

    /// The next buffer. Blocks the calling thread. `None` means the queue
    /// is closed and empty. The byte count stays until [`Self::release`].
    ///
    /// [`Self::pop`] is the same wait on a task. This is the wait for a
    /// thread that is not a task: the seam harness writer, until zone bind
    /// runs the connector's `write_capped`.
    #[must_use]
    pub fn pop_blocking(&self) -> Option<Vec<u8>> {
        let mut inner = self.inner.lock().expect("outbound");
        loop {
            if let Some(item) = inner.items.pop_front() {
                return Some(item.bytes);
            }
            if inner.closed {
                return None;
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

/// The signal that a send did not fit.
///
/// The flag is the fact. The notify wakes a write already in progress.
/// `notify_waiters` stores no permit, so the flag is what a late waiter
/// observes.
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
    use super::ByteQueue;

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
}
