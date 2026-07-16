// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! V3.1 equal-participants multisig protocol (PQC_MULTISIG.md).
//!
//! Coordinator-less governance with deterministic transaction construction
//! and per-output forward privacy.
//!
//! The Option-D prover lineage (`prover`, `heartbeat`, `counter_proof` —
//! rotating prover assignment, liveness heartbeats, and counter-proof
//! evidence) was excised under R1-F-6: Option D was superseded by Option E′
//! (§15.4a — coordinator-less per-participant spend-auth) on 2026-07-15.
//! The surviving modules are the E′-shared substrate. The Option-D-shaped
//! residue that E′ rewrites rather than deletes — the `ProverReady` edge in
//! `state`, the prover/heartbeat/counter-proof `MessageType` discriminants,
//! and the spec docs — is tracked in `docs/FOLLOWUPS.md` against MS-5.

pub mod encryption;
pub mod group_descriptor;
pub mod intent;
pub mod invariants;
pub mod messages;
pub mod state;

pub use encryption::{decrypt_payload, encrypt_payload, EncryptionError};
pub use group_descriptor::{GroupDescriptor, GroupDescriptorError};
pub use intent::{
    ChainStateFingerprint, SpendIntent, SpendIntentError, MAX_ADDRESS_LEN, MAX_INPUTS,
    MAX_RECIPIENTS,
};
pub use invariants::{
    check_pre_signing_invariants, InvariantCheckInput, InvariantCheckResult, InvariantId,
};
pub use messages::{
    DecryptedPayload, EnvelopeError, MessageType, MultisigEnvelope, MAX_PAYLOAD_LEN, MAX_SIG_LEN,
};
pub use state::{IntentState, StateError, TrackedIntent, TxCounterTracker};

#[cfg(test)]
mod tests;
