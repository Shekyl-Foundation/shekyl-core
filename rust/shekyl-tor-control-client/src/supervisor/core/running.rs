// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The transition into Running (`TOR_SUPERVISOR.md` §4.2).
//!
//! The quiet stretch starts here, so dials from before this Tor are not an
//! open on it. A sampled network view is read only from here on. The route
//! and the onion are owed, and an onion that keeps its guards owes their
//! pin first.

use std::net::SocketAddr;

use super::super::posture::{Cause, Inbound};
use super::{Action, Core, Disk, Duty, Link, ManagedRunning, Phase, Probe};

impl Core {
    /// Enter Running.
    pub(super) fn enter_running(&mut self, now: u64, socks: SocketAddr) -> Vec<Action> {
        self.phase = Phase::Running {
            socks,
            route: Duty::Owed,
            onion: Duty::Owed,
            disk: Disk::Watching,
            link: Link::Open,
            guards: self.guards_for_new_tor(),
        };
        self.dials.restart(now);
        self.set_cause(Cause::None);
        // A new route drops the inbound evidence and keeps the offer: the
        // republished onion is publishing until this Tor's probe arrives. A
        // named clock still stands: this Tor's uploads are numbered from the
        // same clock. The old Tor's refused rounds are not this one's.
        self.refusals.clear();
        if !self.clock_is_behind() && self.inbound != Inbound::NotOffered {
            self.inbound = Inbound::Publishing { since: now };
        }
        self.probe = Probe::Idle;
        self.probe_confirms = false;
        self.directories = None;
        self.rounds.clear();
        self.service_republish = false;
        self.republish_new_tor();
        self.arm_sample(now);
        self.arm_alive(now);
        // An onion that keeps its guards waits for them: the publish below
        // is withheld until the pin is confirmed (`guards`).
        let mut actions = vec![Action::Publish(ManagedRunning { socks })];
        actions.extend(self.pin_on_entry());
        actions.push(Action::RepublishOnion);
        actions
    }
}
