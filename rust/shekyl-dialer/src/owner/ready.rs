// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Whether a connector can dial now (`TOR_SUPERVISOR.md` `TSR-F1`, §4.6).
//!
//! A dial needs the connector's link to be usable, the core's tip and the
//! network id. A draw made without them ends as `DialFailed(LocalClose)`, and
//! the list rule drops a drawn gray address on that outcome, so the plan checks
//! all three before it draws anything. While one is missing, the owner loop
//! waits on the [`Bell`], which every change that could supply it rings: a
//! link published, the tip published, the network id set, and the stop.

use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

use shekyl_seam::{DownCause, Outbound};
use shekyl_timing_engine::{Clock, OwnerHandle};

/// What a connector lacks to dial. The plan draws nothing while any is
/// missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotReady {
    /// No route has been installed on the connector's link.
    NoRoute,
    /// The connector's link is down.
    LinkDown(DownCause),
    /// The core has not published a tip.
    NoTip,
    /// The zone host has not named the network.
    NoNetworkId,
}

impl NotReady {
    /// The link's outbound facet, when it is the one that is missing.
    #[must_use]
    pub const fn from_outbound(outbound: Outbound) -> Option<Self> {
        match outbound {
            Outbound::Usable { .. } => None,
            Outbound::Unknown => Some(Self::NoRoute),
            Outbound::Down { cause, .. } => Some(Self::LinkDown(cause)),
        }
    }

    /// For the log line a parked loop writes.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::NoRoute => "no route is installed on its link",
            Self::LinkDown(DownCause::ProcessExited) => {
                "its link is down: the Tor it dials through has exited"
            }
            Self::NoTip => "the core has published no tip",
            Self::NoNetworkId => "no network id is set",
        }
    }
}

/// Rung on every change a parked owner loop waits for. The count only grows,
/// so a loop that reads it before checking readiness cannot miss a ring that
/// lands between the check and the wait.
pub(super) struct Bell {
    state: Mutex<Rung>,
}

struct Rung {
    count: u64,
    /// Who is waiting for the next ring. Each is woken once, at that ring.
    waiting: Vec<Waker>,
}

impl Bell {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(Rung {
                count: 0,
                waiting: Vec::new(),
            }),
        }
    }

    /// How many times the bell has rung.
    pub(super) fn rung(&self) -> u64 {
        self.state.lock().expect("bell").count
    }

    pub(super) fn ring(&self) {
        let waiting = {
            let mut state = self.state.lock().expect("bell");
            state.count = state.count.wrapping_add(1);
            std::mem::take(&mut state.waiting)
        };
        for waker in waiting {
            waker.wake();
        }
    }

    /// Ready once the bell has rung since it read `seen`.
    fn poll_past(&self, seen: u64, cx: &Context<'_>) -> Poll<()> {
        let mut state = self.state.lock().expect("bell");
        if state.count != seen {
            return Poll::Ready(());
        }
        if !state
            .waiting
            .iter()
            .any(|waker| waker.will_wake(cx.waker()))
        {
            state.waiting.push(cx.waker().clone());
        }
        Poll::Pending
    }
}

/// Wait, with no timer armed, until `bell` rings after `seen` (`true`) or
/// `owner`'s wait ends because the engine closed or the owner was
/// deregistered (`false`: the loop ends). Both are polled on this thread, so
/// whichever comes first ends the wait, and neither can be missed.
pub(super) fn park<C: Clock>(bell: &Bell, owner: &OwnerHandle<C>, seen: u64) -> bool {
    let mut owner_wait = pin!(owner.wait_wake_async());
    block_on(|cx| {
        if let Poll::Ready(waited) = owner_wait.as_mut().poll(cx) {
            // Nothing is armed while the loop is parked, so only the end of
            // the owner's life ends its wait. A wake that does arrive is
            // treated as a ring: the loop looks again.
            return Poll::Ready(waited.is_ok());
        }
        bell.poll_past(seen, cx).map(|()| true)
    })
}

/// Poll `step` on this thread until it is ready, parking the thread between
/// polls. A wake unparks it.
fn block_on<T>(mut step: impl FnMut(&mut Context<'_>) -> Poll<T>) -> T {
    struct Unpark(std::thread::Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(value) = step(&mut cx) {
            return value;
        }
        std::thread::park();
    }
}
