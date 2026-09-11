// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tor control-protocol **client**. Any caller. Not an owner of a Tor instance.
//!
//! # Capability families
//!
//! Two identities in this tree speak the control protocol, and they must not
//! share a Tor **instance** (PWD-E9): archival-serving **P** (wallet) and
//! **Principal**'s P2P onion (daemon). Sharing code is not crossover; sharing
//! a process, control session, data directory, or onion key is.
//!
//! | Family | Crate | Capability type | Instance |
//! |---|---|---|---|
//! | **client** (this crate) | `shekyl-tor-control-client` | [`TorControlClient`](control::TorControlClient) | none — data directory, control port and service key are parameters |
//! | **wallet** | `shekyl-tor-control-wallet` | `WalletTorControl` | durable archival-P onion, vanguards, SP-T0 supervisor |
//! | **daemon** | `shekyl-tor-control-daemon` (PWD-E7 piece 2) | `DaemonTorControl` | ephemeral per-boot onion, no vanguard state |
//!
//! `DaemonTorControl` is named so the sibling is grepable. It is **not**
//! stubbed here: an empty daemon crate would be speculative scaffolding
//! (rules 15/21). It lands with the daemon consumer, not ahead of it.
//!
//! This crate does not know which family is talking to it. A function that
//! defaulted, inferred, or discovered the instance cannot compile.
//!
//! The wallet crate does **not** re-export [`control::TorControlClient`],
//! `ManagedTor`, or `AddOnion`. A caller that wants to launch or speak the protocol names
//! this crate. A caller that only needs types already on `WalletTorControl`'s
//! public surface names the wallet crate.

pub mod binary;
pub mod control;
pub mod onion_identity;

#[cfg(test)]
mod test_support;
