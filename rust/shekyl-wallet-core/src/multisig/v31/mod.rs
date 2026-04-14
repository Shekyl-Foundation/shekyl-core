// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! V3.1 equal-participants multisig protocol (PQC_MULTISIG.md).
//!
//! Coordinator-less governance with deterministic transaction construction,
//! per-output forward privacy, and rotating prover assignment.

pub mod intent;
pub mod invariants;
pub mod prover;

pub use intent::{ChainStateFingerprint, SpendIntent, SpendIntentError};
pub use invariants::{
    check_assembly_consensus, check_pre_signing_invariants, InvariantCheckInput,
    InvariantCheckResult, InvariantId,
};
pub use prover::{
    EquivocationProof, InvariantViolation, ProverInputProof, ProverOutput, ProverReceipt,
    SignatureShare, Veto, VetoReason,
};
