// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `DaemonTorControl` — the daemon P2P overlay's Tor instance (PWD-E7 piece 2).
//!
//! # The posture this crate implements
//!
//! **Ephemeral, daemon-held, per boot** — the default overlay-endpoint posture
//! ruled in `docs/design/P2P_2_ENDPOINT_ROUND.md` (PWD-E7, signed 2026-09-06):
//! the daemon mints a v3 onion service key **in memory** at startup, publishes
//! it over a control connection it owns with `Flags=DiscardPK`, uses the
//! returned `ServiceID` as its overlay inbound address, and tears the service
//! down with the process. Restarting the daemon yields a **new key and a new
//! address**. Nothing is persisted; there is no durable name to seize, and no
//! vanguard state — vanguards defend a *durable* address's guard circuits, and
//! an address that dies with the boot has nothing durable to defend.
//!
//! The Tor process itself is **managed** (PWD-E9, MANAGED ruling): this crate
//! spawns its own pinned tor via the client crate's launch path rather than
//! requiring the operator to provision a control port — a default nobody
//! reaches is not a default. The operator-provisioned stable posture
//! (`--anonymous-inbound` with a torrc-configured hidden service) remains
//! available and is untouched by this crate.
//!
//! # What this crate deliberately does NOT contain
//!
//! - **No vanguard state, no `SETCONF`** — that is wallet-P posture
//!   (`shekyl-tor-control-wallet`), defending a durable address.
//! - **No dependency on the wallet crate, in either direction.** Both name
//!   `shekyl-tor-control-client`; neither names the other (PWD-E9: sharing
//!   code is library reuse; sharing a process, control session, data
//!   directory, or onion key is the forbidden crossover). Every
//!   instance-identifying input here is a parameter.
//! - **No respawn loop.** One incarnation per daemon boot: the C++ consumer's
//!   zone/proxy configuration is init-time static, so a respawned tor's
//!   auto-bound SOCKS port could not be consumed anyway. Death is exposed
//!   loudly ([`ephemeral::DaemonTorControl::is_alive`] /
//!   [`ephemeral::DaemonTorControl::wait_death`]) rather than papered over.
//!   Reopen when the consumer can take a dynamic SOCKS address (the PWD-E7
//!   piece 3 wiring is the named re-evaluation site).

pub mod blocking;
pub mod ephemeral;

pub use blocking::{probe_binary, BlockingDaemonTor, BlockingDaemonTorConfig, BlockingStartError};
pub use ephemeral::{DaemonTorConfig, DaemonTorControl, DaemonTorStartError};
// Re-exported so the FFI crate's probe/start seam names one crate (this one)
// rather than reaching around it to the client for the error type alone.
pub use shekyl_tor_control_client::binary::TorBinaryError;

#[cfg(test)]
mod test_support;
