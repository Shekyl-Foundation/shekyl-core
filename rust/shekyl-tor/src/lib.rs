// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Wallet-owned Tor integration for the 2d-2 archival firewall (SP-T0).
//!
//! SP-T0 owns the wallet's own Tor instance and exposes two **loopback-only**
//! channels (`docs/design/ARCHIVAL_BOND_2D2_SP_T0_TOR.md` §0):
//!
//! - the **SOCKS port**, which SP-T1's per-`P` `shekyl-p-transport` clients dial
//!   (each persona username keys a distinct `IsolateSOCKSAuth` circuit), and
//! - the **control port**, cookie-/SAFECOOKIE-authed, with two consumers — the
//!   bootstrap "Connecting…" gate and the measured circuit-ID disjointness test
//!   that closes the firewall's network axis.
//!
//! `ureq` (the SOCKS HTTP client SP-T1 already uses) cannot speak the control
//! protocol — it is a separate, line-based text protocol over a TCP socket — so
//! SP-T0 carries a **roll-our-own minimal control client** ([`control`], SP-T0a).
//! That decision is grounded in a rule-17 source-check: the maintained option
//! (`tor-interface`/Gosling) abstracts away the two raw capabilities this design
//! rests on (the raw SOCKS port and raw `STREAM`/CircID), so it is read as a
//! reference, not taken as a dependency (see the design doc's DQ-T0.2).
//!
//! The control port observes circuit metadata for the wallet's *own* clients; it
//! is a forensic surface (like the SOCKS username) whose data — circuit IDs, our
//! own targets — **must not be logged**.
//!
//! [`binary`] (SP-T0c) is the launch-trust half: it discovers the wallet's
//! `tor` binary and verifies it against a hash pin, minting the
//! [`binary::VerifiedTorBinary`] witness a managed launch requires — the
//! firewall rests on *our* tor, so trusting the binary is a mission-#1
//! precondition. (Shipping the binary itself is the installer/packaging job,
//! not this crate's.)
//!
//! [`service`] (DQ-T0.6, design §3c) is the liveness half: the `TorService`
//! supervisor keeps a managed tor alive across crashes — re-running the
//! [`binary`] gate on **every** spawn, publishing one long-lived
//! `watch<TorPosture>` (the SOCKS endpoint is data on that channel), and never
//! giving up: sustained failure alarms loudly (`Degraded`) while retries
//! continue, because for a bonded archival staker an unattended node that
//! *stopped* retrying is a guaranteed sliding-window slash.

pub mod binary;
pub mod control;
pub mod service;

#[cfg(test)]
mod test_support;
