// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SH-2b-2 — the persona serving host's **lifecycle**: what starts it, when,
//! what keeps its serve-set following the chain, and what takes it down.
//!
//! `shekyl-p-host` composes the loopback listener, the onion, and the pin
//! witness into one object with one lifetime (`ARCHIVAL_CHALLENGE_MECHANISM.md`
//! §9.7). It has no opinion about *when* that lifetime begins, and nothing
//! constructed one until this module. What is here is the three things the host
//! deliberately does not decide.
//!
//! # 1. The launch is scheduled independently of wallet open (gate-6 §10.9)
//!
//! §10.9's restore-flow bullet: *"On wallet restore, `StakeEngine` **must not
//! auto-launch `P`'s HS in lockstep with `LedgerEngine`'s principal sync**."*
//! Co-timing principal-sync with `.onion` reanimation is a correlation that
//! `p_slot` rotation does not foreclose — it changes the address, not the
//! timing. So the host does not start inside the open path beside the P-scan;
//! the task waits a drawn standoff first
//! ([`draw_serving_launch_delay`](super::super::stake_timing::draw_serving_launch_delay)).
//!
//! **What that buys is the interval, not the sequence** — a host cannot start
//! before there is a serve-set to pin, so `principal-sync → HS-up` is forced by
//! data dependency and is not concealed. See the window constant for the full
//! statement, including why the window is sized against *open frequency*.
//!
//! # 2. Refresh runs on its own cadence, and arms its own tripwire
//!
//! The plan of record said "P-scan-driven refresh", and this drives refresh on
//! an independent timer at the same cadence instead. The reason is the
//! **arming predicate**, not convenience. `StalenessBound` is armed only once
//! the wallet is caught up — during catch-up the wallet ingests far faster than
//! the steady-state rate the bound is sized for, so an armed check fires on
//! every healthy catch-up. Deciding that needs both the chain height and the
//! wallet's ingest height, and **both are already on the witness**:
//! `ServeSet::as_of_height` is the chain height the bond record was read at, and
//! `ServingReader::sync_tip_height` is what this wallet has ingested. Threading
//! a host handle into the sweep would buy a tip the witness already carries, at
//! the cost of shared mutable state for a host that does not exist during the
//! launch standoff. Recorded as a divergence rather than taken silently.
//!
//! (SH-2a's warning against subtracting those two heights is about the
//! *staleness clock*, which must be one clock read twice. This is a different
//! question — "is the wallet caught up" — and comparing the wallet's ingest to
//! the chain is exactly what that means.)
//!
//! # 3. Every condition reports through OA-1, and one of them is terminal
//!
//! [`Staleness`](shekyl_p_host::Staleness) and the pin report are projected
//! onto the operator alarm board. Four of the five conditions are recoverable
//! and land as `AlarmLifetime::Episode`. The fifth — leaf bytes already pruned
//! — is irreversible, and it is the reason the board needed a latch. It does
//! **not** need durable acknowledgment, because it re-derives at every start
//! more loudly than an alarm: `PinnedServeSet::acquire` refuses outright, so
//! the host does not start at all.
//!
//! Split the way `pscan/` already is: [`task`] is the running loop,
//! [`tor_config`] is the fingerprint-minimal `TorServiceConfig` surface,
//! [`start`] is the Engine construction site.

pub(crate) mod disk;
pub(crate) mod start;
pub(crate) mod task;
pub(crate) mod tor_config;

pub use start::ServingStartError;
pub use task::{ServingHandle, ServingPosture};
pub use tor_config::TorConfigError;
