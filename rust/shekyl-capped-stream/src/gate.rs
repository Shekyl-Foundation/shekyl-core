// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The wait in front of the operator's budget.
//!
//! [`LinkBudget`] decides. This waits, on the clock the caller installed,
//! until that decision is a grant. The wait is the connection pausing.
//! Nothing here closes a connection or drops a byte.

use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use shekyl_transport_layer::{LinkBudget, LinkDirection, MessageClass, Observed, Turn};
use tokio::sync::Notify;

struct GateInner {
    budget: Mutex<LinkBudget>,
    wake: Notify,
    clock: Mutex<Arc<dyn Fn() -> u64 + Send + Sync>>,
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
        self.inner.wake.notify_waiters();
    }

    #[must_use]
    pub fn totals(&self) -> Observed {
        self.inner.budget.lock().expect("link budget").totals()
    }

    #[must_use]
    pub fn connection(&self, conn: u64) -> Observed {
        self.inner
            .budget
            .lock()
            .expect("link budget")
            .connection(conn)
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
