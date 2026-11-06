// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The wait in front of the operator's budget.
//!
//! [`LinkBudget`] decides. This waits, on the clock the caller installed,
//! until that decision is a grant. The wait is the connection pausing.
//! Nothing here closes a connection or drops a byte.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use shekyl_transport_layer::{
    monotonic_ms, unix_ms_of, LinkBudget, LinkDirection, MessageClass, Observed, Turn,
};
use tokio::sync::Notify;

struct GateInner {
    budget: Mutex<LinkBudget>,
    wake: Notify,
    clock: Mutex<Arc<dyn Fn() -> u64 + Send + Sync>>,
    /// Per session. The byte path stores into the atomic. Looking the
    /// atomic up is the only lock, and a copy does it once.
    send_stamps: Mutex<HashMap<u64, Arc<AtomicU64>>>,
    recv_stamps: Mutex<HashMap<u64, Arc<AtomicU64>>>,
}

/// The monotonic millisecond of the last byte on one direction.
///
/// [`ByteStamp::store`] does not take the link-budget lock. The grant
/// and the refund already take that lock; a stamp is not a grant.
#[derive(Clone)]
pub struct ByteStamp {
    ms: Arc<AtomicU64>,
}

impl ByteStamp {
    /// The bytes just moved. A grant does not call this.
    pub fn store(&self) {
        self.ms.store(monotonic_ms(), Ordering::Relaxed);
    }
}

/// One node's budget, shared by every connector's reader and writer.
#[derive(Clone)]
pub struct LinkGate {
    inner: Arc<GateInner>,
}

impl LinkGate {
    #[must_use]
    pub fn new() -> Self {
        let origin = Instant::now();
        Self {
            inner: Arc::new(GateInner {
                budget: Mutex::new(LinkBudget::new()),
                wake: Notify::new(),
                clock: Mutex::new(Arc::new(move || {
                    u64::try_from(origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
                })),
                send_stamps: Mutex::new(HashMap::new()),
                recv_stamps: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// The engine's clock. Marks from the interim clock are dropped so a
    /// new origin cannot refill a bucket by accident.
    pub fn install_clock(&self, clock: Arc<dyn Fn() -> u64 + Send + Sync>) {
        *self.inner.clock.lock().expect("link clock") = clock;
        self.inner
            .budget
            .lock()
            .expect("link budget")
            .forget_marks();
        self.inner.wake.notify_waiters();
    }

    fn now(&self) -> u64 {
        (self.inner.clock.lock().expect("link clock").clone())()
    }

    /// `None` is unlimited. `Some` is bytes per second, and the bucket
    /// starts full.
    pub fn set_up(&self, bytes_per_sec: Option<u64>) {
        self.set(LinkDirection::Up, bytes_per_sec);
    }

    pub fn set_down(&self, bytes_per_sec: Option<u64>) {
        self.set(LinkDirection::Down, bytes_per_sec);
    }

    #[must_use]
    pub fn rate_up(&self) -> Option<u64> {
        self.rate(LinkDirection::Up)
    }

    #[must_use]
    pub fn rate_down(&self) -> Option<u64> {
        self.rate(LinkDirection::Down)
    }

    /// `None` is unlimited. `Some` is bytes per second, and the bucket
    /// starts full at `now`.
    pub fn set(&self, direction: LinkDirection, bytes_per_sec: Option<u64>) {
        let now = self.now();
        self.inner
            .budget
            .lock()
            .expect("link budget")
            .set(direction, bytes_per_sec, now);
        self.inner.wake.notify_waiters();
    }

    #[must_use]
    pub fn rate(&self, direction: LinkDirection) -> Option<u64> {
        self.inner
            .budget
            .lock()
            .expect("link budget")
            .rate(direction)
    }

    /// Block this task until the budget grants at least one byte, or
    /// `want` when the bucket can pay for it. An empty bucket waits.
    /// It does not close.
    pub async fn acquire(
        &self,
        direction: LinkDirection,
        conn: u64,
        class: MessageClass,
        want: u64,
    ) -> u64 {
        if want == 0 {
            return 0;
        }
        loop {
            let notified = self.inner.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let decision = {
                let now = self.now();
                self.inner
                    .budget
                    .lock()
                    .expect("link budget")
                    .take(direction, conn, class, want, now)
            };
            match decision {
                Turn::Granted(n) => {
                    self.inner.wake.notify_waiters();
                    return n;
                }
                Turn::Paused { ready_ns } => {
                    if ready_ns == u64::MAX {
                        notified.await;
                        continue;
                    }
                    let now = self.now();
                    if ready_ns <= now {
                        continue;
                    }
                    tokio::select! {
                        () = notified => {}
                        () = tokio::time::sleep(Duration::from_nanos(ready_ns - now)) => {}
                    }
                }
                Turn::Wait => notified.await,
            }
        }
    }

    /// One message finished. Grants of a rate-limited message stay one count.
    pub fn record_message(&self, direction: LinkDirection, conn: u64) {
        self.inner
            .budget
            .lock()
            .expect("link budget")
            .record_message(direction, conn);
    }

    pub fn refund(&self, direction: LinkDirection, conn: u64, bytes: u64, whole_grant: bool) {
        self.inner
            .budget
            .lock()
            .expect("link budget")
            .refund(direction, conn, bytes, whole_grant);
    }

    pub fn leave(&self, direction: LinkDirection, conn: u64) {
        self.inner
            .budget
            .lock()
            .expect("link budget")
            .leave(direction, conn);
        self.stamp_map(direction)
            .lock()
            .expect("byte stamps")
            .remove(&conn);
        self.inner.wake.notify_waiters();
    }

    #[must_use]
    pub fn totals(&self) -> Observed {
        self.inner.budget.lock().expect("link budget").totals()
    }

    /// Bytes per second as of the installed clock, over the link
    /// budget's recent-speed window.
    #[must_use]
    pub fn speed(&self, conn: u64) -> (u64, u64) {
        let now = self.now();
        self.inner
            .budget
            .lock()
            .expect("link budget")
            .speed(conn, now)
    }

    #[must_use]
    pub fn connection(&self, conn: u64) -> Observed {
        self.inner
            .budget
            .lock()
            .expect("link budget")
            .connection(conn)
    }

    /// The atomic for `direction` on `conn`. A copy holds it and stores
    /// when a byte is read or written. The lookup is once per copy.
    #[must_use]
    fn stamp_map(&self, direction: LinkDirection) -> &Mutex<HashMap<u64, Arc<AtomicU64>>> {
        match direction {
            LinkDirection::Up => &self.inner.send_stamps,
            LinkDirection::Down => &self.inner.recv_stamps,
        }
    }

    pub fn byte_stamp(&self, direction: LinkDirection, conn: u64) -> ByteStamp {
        let mut stamps = self.stamp_map(direction).lock().expect("byte stamps");
        let ms = stamps
            .entry(conn)
            .or_insert_with(|| Arc::new(AtomicU64::new(0)))
            .clone();
        ByteStamp { ms }
    }

    /// Monotonic milliseconds of the last byte, `(send, recv)`.
    /// Zero until that direction has read or written a byte.
    #[must_use]
    pub fn activity(&self, conn: u64) -> (u64, u64) {
        let load = |direction: LinkDirection| {
            self.stamp_map(direction)
                .lock()
                .expect("byte stamps")
                .get(&conn)
                .map(|ms| ms.load(Ordering::Relaxed))
                .unwrap_or(0)
        };
        (load(LinkDirection::Up), load(LinkDirection::Down))
    }

    /// Unix milliseconds of those instants, for the operator view.
    #[must_use]
    pub fn activity_unix(&self, conn: u64) -> (u64, u64) {
        let (send, recv) = self.activity(conn);
        (unix_ms_of(send), unix_ms_of(recv))
    }

    /// Hold this across a copy. Drop releases the fairness slot and the stamp,
    /// including when the task is aborted before the copy returns.
    pub(crate) fn lease(&self, direction: LinkDirection, conn: u64) -> DirectionLease {
        DirectionLease {
            gate: self.clone(),
            direction,
            conn,
        }
    }

    /// Stamps currently stored, both directions.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn held_stamps(&self) -> usize {
        let count =
            |direction: LinkDirection| self.stamp_map(direction).lock().expect("byte stamps").len();
        count(LinkDirection::Up) + count(LinkDirection::Down)
    }
}

/// The copy's hold on one direction.
///
/// [`LinkGate::leave`] runs when this drops. The handshake queue does not
/// stamp, so it releases its slot with [`LinkGate::leave`] and does not
/// take a lease.
#[must_use = "the lease releases the byte stamp when dropped"]
pub(crate) struct DirectionLease {
    gate: LinkGate,
    direction: LinkDirection,
    conn: u64,
}

impl Drop for DirectionLease {
    fn drop(&mut self) {
        self.gate.leave(self.direction, self.conn);
    }
}

impl Default for LinkGate {
    fn default() -> Self {
        Self::new()
    }
}

/// The budget the daemon's flags and RPC calls reach.
#[must_use]
pub fn node_gate() -> LinkGate {
    static GATE: LazyLock<LinkGate> = LazyLock::new(LinkGate::new);
    GATE.clone()
}

#[cfg(test)]
mod tests {
    use shekyl_transport_layer::{LinkDirection, MessageClass};

    use super::LinkGate;

    #[tokio::test]
    async fn a_grant_does_not_stamp_and_a_byte_does() {
        let gate = LinkGate::new();
        let conn = 7u64;
        assert_eq!(gate.activity(conn), (0, 0));
        assert_eq!(gate.held_stamps(), 0);
        let granted = gate
            .acquire(LinkDirection::Down, conn, MessageClass::Session, 64)
            .await;
        assert_eq!(granted, 64);
        assert_eq!(gate.activity(conn), (0, 0));
        assert_eq!(gate.held_stamps(), 0);
        let stamp = gate.byte_stamp(LinkDirection::Down, conn);
        assert_eq!(gate.held_stamps(), 1);
        stamp.store();
        let (send, recv) = gate.activity(conn);
        assert_eq!(send, 0);
        assert!(recv > 0);
        drop(gate.lease(LinkDirection::Down, conn));
        assert_eq!(gate.activity(conn), (0, 0));
        assert_eq!(gate.held_stamps(), 0);
    }
}
