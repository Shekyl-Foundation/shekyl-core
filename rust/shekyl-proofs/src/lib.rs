// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shekyl V3 transaction proof and reserve proof protocol.
//!
//! Implements outbound tx proofs (Ed25519 Schnorr over tx_key), inbound tx
//! proofs (Ed25519 Schnorr over view_secret with domain separation), and
//! reserve proofs. All proof types use a narrow `ProofSecrets` projection
//! `(ho, y, k_amount)` -- raw `combined_ss` never leaves Rust.
//!
//! Wire format: hand-rolled canonical encoding (no bincode/serde).
//!
//! See `docs/FCMP_PLUS_PLUS.md` for the full protocol specification.

#![deny(unsafe_code)]

pub mod tx_proof;
pub mod reserve_proof;
pub mod error;
