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
//! it over a control connection it owns with `Flags=DiscardPK` and
//! proof-of-work enabled (D10.4), uses the
//! returned `ServiceID` as its overlay inbound address, and tears the service
//! down with the process. Restarting the daemon yields a **new key and a new
//! address**. Nothing is persisted; there is no durable name to seize, and no
//! vanguard state — vanguards defend a *durable* address's guard circuits, and
//! an address that dies with the boot has nothing durable to defend.
//!
//! The Tor process itself is **managed** (PWD-E9, MANAGED ruling): this crate
//! spawns its own pinned tor via the client crate's launch path rather than
//! requiring the operator to provision a control port — a default nobody
//! reaches is not a default. Its `DataDirectory` is a unique 0700 subdirectory
//! of a caller-named parent, wiped on teardown, so a restart cannot reuse
//! entry guards (the wallet supervisor keeps a durable directory; this crate
//! must not). The operator-provisioned stable posture (`--anonymous-inbound`
//! with a torrc-configured hidden service) remains available and is untouched
//! by this crate.
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
//! - **No respawn loop, until the supervisor lands.** One incarnation per
//!   daemon boot today. `docs/design/TOR_SUPERVISOR.md` (`TSR-`, ratified
//!   2026-10-15) replaces this crate's one-incarnation handle with a
//!   supervisor that respawns, keeping the onion within a boot; the Rust dial
//!   path already reads the SOCKS address at each dial. Until its increments
//!   land, death is exposed loudly
//!   ([`ephemeral::DaemonTorControl::is_alive`] /
//!   [`ephemeral::DaemonTorControl::wait_death`]) rather than papered over.

pub mod blocking;
mod data_dir;
pub mod ephemeral;

pub use blocking::{BlockingDaemonTor, BlockingDaemonTorConfig, BlockingStartError};
pub use ephemeral::{
    DaemonTorConfig, DaemonTorControl, DaemonTorPublishError, DaemonTorStartError, TorDeath,
};
pub use shekyl_tor_control_client::control::OnionPow;
// Re-exported so the FFI crate's probe/start seam names one crate (this one)
// rather than reaching around it to the client for the error type alone.
pub use shekyl_tor_control_client::binary::TorBinaryError;

#[cfg(test)]
mod test_support;
