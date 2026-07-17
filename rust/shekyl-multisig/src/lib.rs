// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shekyl V3.1 multisig — Option E′ (`PQC_MULTISIG.md` §15.4a).
//!
//! Coordinator-less, equal-participants multisig with deterministic
//! transaction construction and per-output forward privacy. This crate is
//! **pure ceremony logic**: it takes a spend intent + outputs and returns
//! bytes. It owns no ledger, no I/O, and **no transport** — the dependency
//! list is the structural "no transport" ban (MS-1(a)); engine-core wires the
//! returned bytes to the wallet ledger.
//!
//! # Lineage (two deletions, one surviving design)
//!
//! - **Option A** — the FROST wrapper that fused threshold keys with a fixed
//!   group `pqc_public_key` — was rejected 2026-04-04: a fixed group PQC key in
//!   plaintext `pqc_auth` is a ~1996-byte on-chain fingerprint that collapses
//!   FCMP++ anonymity. Its FROST-SAL / DKG primitives live on in `shekyl-fcmp`.
//! - **Option D** — rotating prover assignment, liveness heartbeats,
//!   counter-proof evidence — was superseded by Option E′ (§15.4a,
//!   coordinator-less per-participant spend-auth) on 2026-07-15. Under MS-5 the
//!   Option-D FSM (`state.rs`) is **deleted, not inherited**, and its residue
//!   (the `ProverReady` edge, the prover/heartbeat/counter-proof `MessageType`
//!   discriminants, the `relays` descriptor field,
//!   `input_assigned_prover_indices`) is excised. The modules below are the
//!   E′-shared **format** substrate.
//!
//! The E′ spend ceremony itself — the FROST `SigningCeremony` FSM and its nonce
//! typestates — lands in this crate under MS-5; the format modules below are its
//! substrate.

pub mod encryption;
pub mod group_descriptor;
pub mod intent;
pub mod invariants;
pub mod messages;

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

#[cfg(test)]
mod tests;
