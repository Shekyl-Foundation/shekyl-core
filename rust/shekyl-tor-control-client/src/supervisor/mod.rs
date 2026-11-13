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
mod view;

pub use crate::control::{NetworkView, Reported};
pub use core::{
    Action, Core, DialTally, DirectoryAnswer, DirectoryFetch, Input, ManagedRunning, Policy,
    RoundTally, Step, TorCensus, DESCRIPTOR_LIFETIME, REPLY_BOUND,
};
pub use events::{
    clock_evidence_of, directory_content_input_of, directory_input_of, input_of, round_inputs,
    CERTIFICATE_OUT_OF_DATE,
};
pub use posture::{
    fixes, own_tx, BootstrapLine, BootstrapPace, Carriage, Cause, Connectors, Inbound,
    InboundCause, ManagedTorFix, OriginVerdict, OwnTx, ReportedSkew, Sessions, Shown, Space,
    Status, Syncing, TorQuiet, TorSetting,
};
pub use view::{snapshot, wire_cause};
