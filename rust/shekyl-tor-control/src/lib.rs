// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Tor control-protocol layer, owned by neither the wallet nor the daemon.
//!
//! # Why this crate exists
//!
//! Two components in this tree need to speak Tor's control protocol, and they
//! must not share a Tor **instance**:
//!
//! - the **wallet** (`shekyl-tor`) runs its own Tor for the 2d-2 archival
//!   firewall and publishes the archival-serving persona's durable onion;
//! - the **daemon** publishes an ephemeral, per-boot onion for P2P inbound.
//!
//! Rick's ruling (2026-09-08, recorded as PWD-E9): *"the daemon needs it's own
//! path we DO NOT want crossover between the daemon and archival-serving P."*
//! That is an isolation requirement between two identities that must not be
//! linkable — not a layout preference.
//!
//! **Sharing code is not crossover; sharing state is.** The request types, the
//! reply parser and the framing are a library. What must never be shared is the
//! Tor process, the control connection, the supervisor, the guard set, the data
//! directory, or the onion identity — enumerated with a reason each in PWD-E9.
//!
//! # Why it is not in `shekyl-tor`
//!
//! `shekyl-tor` describes itself as *"Wallet-owned Tor integration for the 2d-2
//! archival firewall (SP-T0)"*. If the daemon became a second consumer of that
//! crate, that sentence would be false — and the test PWD-E9 sets is exactly
//! that **neither crate's docs should have to describe the other's posture**.
//! So the protocol layer lives here, `shekyl-tor` keeps the wallet supervisor
//! (vanguard rotation, serving posture, SP-T0 policy), and the daemon crate
//! owns the ephemeral posture with no vanguard state.
//!
//! # The rule this crate hands its callers
//!
//! **No entry point here may default, infer, or discover which Tor instance it
//! is talking to.** Data directory, control port and service key arrive from
//! the caller. Sharing this code must not be able to produce a shared instance,
//! and the guard against that is that an entry point without them cannot
//! compile.

pub mod binary;
pub mod control;
pub mod onion_identity;

#[cfg(test)]
mod test_support;
