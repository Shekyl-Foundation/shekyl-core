// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Engine capability mode.
//!
//! Re-exports [`shekyl_engine_file::Capability`]. The wallet-file layer
//! decodes the envelope's `capability_mode` byte into this typed enum;
//! the wallet-core orchestrator consumes it without ever pattern-matching
//! on the raw byte. [`Capability::Full`] is the only variant (rule 23;
//! decision log 2026-09-07: ViewOnly is REJECTED, hardware-offload is
//! DEFERRED with zero code) — every open wallet can spend, so there is
//! no capability-gating predicate.

pub use shekyl_engine_file::Capability;
