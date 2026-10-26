// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The transition into Running (`TOR_SUPERVISOR.md` §4.2).
//!
//! The quiet stretch starts here, so dials from before this Tor are not an
//! open on it. A sampled network view is read only from here on. The route
//! and the onion are owed.

use std::net::SocketAddr;

use super::super::posture::Cause;
use super::{Action, Core, Disk, Duty, Link, ManagedRunning, Phase};

impl Core {
    /// Enter Running.
    pub(super) fn enter_running(&mut self, now: u64, socks: SocketAddr) -> Vec<Action> {
        self.phase = Phase::Running {
            socks,
            route: Duty::Owed,
            onion: Duty::Owed,
            disk: Disk::Watching,
            link: Link::Open,
        };
        self.dials.restart(now);
        self.set_cause(Cause::None);
        self.arm_sample(now);
        self.arm_alive(now);
        vec![
            Action::Publish(ManagedRunning { socks }),
            Action::RepublishOnion,
        ]
    }
}
