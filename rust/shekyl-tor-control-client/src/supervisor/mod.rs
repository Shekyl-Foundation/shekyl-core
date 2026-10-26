// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The managed Tor's policy (`TOR_SUPERVISOR.md` §4).
//!
//! [`Core`] is the manager. An [`Input`] goes in. [`Action`]s and the next
//! deadline come out. The core has no process, no socket, and no clock of
//! its own: the driver performs each action and reports what happened,
//! including when a publish could not be performed.
//!
//! The Tor connector is not a caller. It reads the route the driver
//! publishes from [`ManagedRunning`] and dials. Liveness, the progress
//! line, and the bootstrap poll stay on this side of that seam: a control
//! question is not a network path (`TSR-Q9`).
//!
//! [`ManagedRunning`] is built only on the transition into `Running`.

mod core;
mod events;
mod posture;

pub use crate::control::{NetworkView, Reported};
pub use core::{Action, Core, DialTally, Input, ManagedRunning, Policy, Step};
pub use events::input_of;
pub use posture::{
    fixes, held_sentence, install_sentence, own_tx, render, BootstrapLine, Cause, Connectors,
    ManagedTorFix, OriginVerdict, OwnTx, Shown, Space, Status, Syncing, TorSetting,
};
