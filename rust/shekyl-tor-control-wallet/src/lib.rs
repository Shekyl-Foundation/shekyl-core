// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Wallet Tor control: the archival-serving persona's Tor **instance** (SP-T0).
//!
//! [`WalletTorControl`](service::WalletTorControl) is this crate's capability.
//! It is **not** the control-protocol client — that is
//! `shekyl_tor_control_client::TorControlClient`, which any owner may use
//! against a Tor instance this supervisor must never share. The daemon's
//! sibling is `DaemonTorControl` (PWD-E7 piece 2, `shekyl-tor-control-daemon`).
//!
//! This crate owns what PWD-E9 marks **NO** to share with the daemon:
//!
//! - the supervisor that keeps one managed tor alive (`service`)
//! - vanguard rotation and the `VanguardsActive` witness (`vanguard_rotation`)
//! - persona publish orchestration (`onion_service`)
//!
//! It does **not** re-export the launch path (`TorControlClient`, `ManagedTor`,
//! `AddOnion`, `Command`). Types that already appear in this crate's public
//! signatures (`OnionIdentity`, `EventSink`, `ControlError`, `ServiceId`, …)
//! are re-exported from [`service`] so wallet consumers do not take the client
//! crate — and therefore cannot spawn a second Tor — just to name a field.

pub mod onion_service;
pub mod service;
pub mod vanguard_rotation;

#[cfg(test)]
mod test_support;
