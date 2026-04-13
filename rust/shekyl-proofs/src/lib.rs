// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shekyl transaction proof and reserve proof protocol.
//!
//! Genesis-native design — no prior version, no migration, no fallback.
//!
//! Implements outbound tx proofs (Ed25519 Schnorr over tx_key), inbound tx
//! proofs (Ed25519 Schnorr over view_secret with domain separation), and
//! reserve proofs (Schnorr over spend_secret + per-output DLEQ for key
//! image binding). All proof types use a narrow `ProofSecrets` projection
//! `(ho, y, z, k_amount)` — raw `combined_ss` never leaves Rust.
//!
//! Wire format: hand-rolled canonical encoding (no bincode/serde).
//! Each proof type has a distinct Schnorr domain separator to prevent
//! cross-type replay. Verifier asserts `version == 1` before any crypto.
//!
//! See `docs/FCMP_PLUS_PLUS.md` section 21 for the full protocol spec.

#![deny(unsafe_code)]

pub mod dleq;
pub mod error;
pub mod reserve_proof;
pub mod tx_proof;
