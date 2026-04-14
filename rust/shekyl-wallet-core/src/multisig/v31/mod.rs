// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! V3.1 equal-participants multisig protocol (PQC_MULTISIG.md).
//!
//! Coordinator-less governance with deterministic transaction construction,
//! per-output forward privacy, and rotating prover assignment.

pub mod intent;

pub use intent::{ChainStateFingerprint, SpendIntent, SpendIntentError};
