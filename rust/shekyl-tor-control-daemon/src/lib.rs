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
//! address**. Nothing identity-bearing is persisted. Tor's public directory
//! files are the exception (`TSR-Q8`): `cached-microdesc-consensus`,
//! `cached-microdescs`, `cached-microdescs.new` and `cached-certs` live in
//! `tor-directory-cache`, and guards, keys and the onion do not. There is no
//! durable name to seize, and no vanguard state — vanguards defend a
//! *durable* address's guard circuits, and an address that dies with the boot
//! has nothing durable to defend.
//!
//! The Tor process itself is **managed** (PWD-E9, MANAGED ruling): this crate
//! spawns its own pinned tor via the client crate's launch path rather than
//! requiring the operator to provision a control port — a default nobody
//! reaches is not a default. Its `DataDirectory` is a unique 0700 subdirectory
//! of a caller-named parent. A respawn inside one boot keeps that directory,
//! so the guard sample in `state` survives (`TSR-Q1`). The directory is wiped
//! when the daemon stops, and the next boot mints a new onion. The directory
//! cache beside it is not that directory, and Tor is never pointed at it. The
//! operator-provisioned stable posture remains available and is untouched by
//! this crate.
//!
//! # What this crate deliberately does NOT contain
//!
//! - **No vanguard `SETCONF`.** The one `SETCONF` this daemon sends is
//!   `AvoidDiskWrites=1`, after the first `state` file, on the owning
//!   connection (`TSR-Q9`). Vanguards stay the wallet's.
//! - **No dependency on the wallet crate, in either direction.** Both name
//!   `shekyl-tor-control-client`; neither names the other (PWD-E9: sharing
//!   code is library reuse; sharing a process, control session, data
//!   directory, or onion key is the forbidden crossover). Every
//!   instance-identifying input here is a parameter.
//! - **The supervisor respawns.** `shekyl-daemon`'s `tor` module drives
//!   `shekyl-tor-control-client::supervisor`. The onion seed is held for the
//!   boot and passed into [`ephemeral::DaemonTorControl::publish`]. Death is
//!   still observable ([`ephemeral::DaemonTorControl::is_alive`] /
//!   [`ephemeral::DaemonTorControl::wait_death`]).

mod data_dir;
pub mod ephemeral;

pub use data_dir::{space_needed, sweep_stale_data_dirs, TOR_WRITE_HEADROOM};
pub use ephemeral::{
    CacheSave, DaemonTorConfig, DaemonTorControl, DaemonTorPublishError, DaemonTorStartError,
    KeptDataDir, LaunchFailure, OnionSeed, SpawnError, Teardown, TorDeath,
};
pub use shekyl_tor_control_client::control::OnionPow;
// Re-exported so the daemon's start seam (`shekyl-daemon`'s `tor.rs`) names
// one crate (this one) rather than reaching around it to the client for the
// error type alone.
pub use shekyl_tor_control_client::binary::TorBinaryError;

#[cfg(test)]
mod test_support;
