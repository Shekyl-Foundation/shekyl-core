// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! V3.1 equal-participants multisig protocol (PQC_MULTISIG.md).
//!
//! Coordinator-less governance with deterministic transaction construction,
//! per-output forward privacy, and rotating prover assignment.

pub mod counter_proof;
pub mod encryption;
pub mod heartbeat;
pub mod intent;
pub mod invariants;
pub mod messages;
pub mod prover;
pub mod state;

pub use counter_proof::{CounterProof, CounterProofChainView, CounterProofVerifyResult};
pub use encryption::{decrypt_payload, encrypt_payload, EncryptionError};
pub use heartbeat::{Heartbeat, HeartbeatAnomaly, HeartbeatTracker};
pub use intent::{ChainStateFingerprint, SpendIntent, SpendIntentError};
pub use invariants::{
    check_assembly_consensus, check_pre_signing_invariants, InvariantCheckInput,
    InvariantCheckResult, InvariantId,
};
pub use messages::{DecryptedPayload, EnvelopeError, MessageType, MultisigEnvelope};
pub use prover::{
    EquivocationProof, InvariantViolation, ProverInputProof, ProverOutput, ProverReceipt,
    SignatureShare, Veto, VetoReason,
};
pub use state::{IntentState, StateError, TrackedIntent, TxCounterTracker};
