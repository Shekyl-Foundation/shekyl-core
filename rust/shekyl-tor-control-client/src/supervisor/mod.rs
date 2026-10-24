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
//! [`ManagedRunning`] is built only on the transition into `Running`.

mod core;
mod events;
mod posture;

pub use core::{Action, Core, Input, ManagedRunning, Policy, Step};
pub use events::input_of;
pub use posture::{
    fixes, own_tx, render, BootstrapLine, Cause, Connectors, ManagedTorFix, OwnTx, Shown, Space,
    Status, Syncing, TorSetting,
};
