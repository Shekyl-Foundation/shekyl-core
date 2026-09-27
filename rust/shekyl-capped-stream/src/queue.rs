// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The outbound cap. Bytes stay counted until the writer finishes them,
//! so a peer that stops reading cannot grow the queue past the cap.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

/// Outbound bytes. The cap is the only storage limit. A send that does
/// not fit is not stored.
#[derive(Clone)]
pub struct ByteQueue {
    inner: Arc<Mutex<ByteQueueInner>>,
    data: Arc<Notify>,
}

struct ByteQueueInner {
    limit: usize,
    used: usize,
    closed: bool,
    items: VecDeque<Vec<u8>>,
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
        }
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
            return Err(PushError::Full);
        };
        if next > inner.limit {
            return Err(PushError::Full);
        }
        inner.used = next;
        inner.items.push_back(bytes);
        drop(inner);
        self.data.notify_one();
        Ok(())
    }

    /// Return `n` bytes of cap after the writer finishes that buffer.
    pub(crate) fn release(&self, n: usize) {
        let mut inner = self.inner.lock().expect("outbound");
        inner.used = inner.used.saturating_sub(n);
    }

    pub(crate) fn close(&self) {
        self.inner.lock().expect("outbound").closed = true;
        self.data.notify_waiters();
    }

    /// The next buffer. `None` means the queue is closed and empty.
    /// The byte count stays until [`Self::release`].
    pub(crate) async fn pop(&self) -> Option<Vec<u8>> {
        loop {
            let mut notified = std::pin::pin!(self.data.notified());
            notified.as_mut().enable();
            {
                let mut inner = self.inner.lock().expect("outbound");
                if let Some(bytes) = inner.items.pop_front() {
                    return Some(bytes);
                }
                if inner.closed {
                    return None;
                }
            }
            notified.await;
        }
    }

    #[cfg(test)]
    pub(crate) fn pop_now(&self) -> Option<Vec<u8>> {
        self.inner.lock().expect("outbound").items.pop_front()
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
        queue.try_push(b"cd".to_vec()).expect("second");
        assert!(queue.try_push(b"e".to_vec()).is_err());
        let first = queue.pop_now().expect("queued");
        queue.release(first.len());
        assert!(queue.try_push(b"ef".to_vec()).is_ok());
    }
}
