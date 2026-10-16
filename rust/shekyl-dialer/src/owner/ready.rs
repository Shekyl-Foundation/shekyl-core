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

use std::sync::{Condvar, Mutex};

use shekyl_seam::{DownCause, Outbound};

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
    rung: Mutex<u64>,
    changed: Condvar,
}

impl Bell {
    pub(super) fn new() -> Self {
        Self {
            rung: Mutex::new(0),
            changed: Condvar::new(),
        }
    }

    /// How many times the bell has rung.
    pub(super) fn rung(&self) -> u64 {
        *self.rung.lock().expect("bell")
    }

    pub(super) fn ring(&self) {
        let mut rung = self.rung.lock().expect("bell");
        *rung = rung.wrapping_add(1);
        self.changed.notify_all();
    }

    /// Block until the bell has rung since it read `seen`.
    pub(super) fn wait_past(&self, seen: u64) {
        let mut rung = self.rung.lock().expect("bell");
        while *rung == seen {
            rung = self.changed.wait(rung).expect("bell");
        }
    }
}
