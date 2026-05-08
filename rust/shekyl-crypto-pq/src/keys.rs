// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Typed wrappers around the wallet's secret-bearing key material.
//!
//! Per `.cursor/rules/18-type-placement.mdc`, secret-bearing 32-byte
//! values get type-system protection against accidental misuse. Each
//! wrapper:
//!
//! - Encapsulates the raw bytes (private field; no `Copy`).
//! - Implements `Zeroize + ZeroizeOnDrop` so wipe-on-drop is structural,
//!   not per-call-site discipline (see `.cursor/rules/35-secure-memory.mdc`).
//! - Exposes a `to_canonical_bytes()` / `as_canonical_bytes()` accessor —
//!   the single auditable boundary at which the typed value is converted
//!   into raw bytes for cryptographic input. Cryptographic functions in
//!   this crate take `&[u8; N]` primitives, not the typed values, so the
//!   crate stays consumable by callers that have raw bytes (FFI, wallet
//!   envelope deserialization) without forcing them through the typed
//!   wrapper.
//!
//! Currently houses [`ViewSecret`]. The remaining `AllKeysBlob` secret /
//! key fields (`spend_sk` → `SpendSecret`, `view_pk` → `ViewPublicKey`,
//! `spend_pk` → `SpendPublicKey`) migrate to typed wrappers as a
//! near-term workstream before the M3b feat branch cuts; per the
//! `STAGE_1_PR_3` migration plan's Q1/Q2 deliberations this is a
//! near-term commitment, not a `FOLLOWUPS.md` deferral.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// The wallet's view-secret scalar, 32 canonical little-endian bytes.
///
/// This is the secret that gates view-only access to the wallet:
/// scanning the chain for owned outputs, decapsulating their hybrid
/// shared secrets, and deriving per-output spend material. Holding
/// `ViewSecret` is sufficient to detect outputs and read amounts;
/// spending also requires `SpendSecret` (forthcoming typed wrapper).
///
/// # Hygiene properties
///
/// - **No `Copy`.** Compiler-emitted copies would defeat
///   wipe-on-drop discipline; `Clone` is opt-in by callers.
/// - **`Zeroize + ZeroizeOnDrop`.** The inner bytes are wiped when
///   the wrapper drops. Holding a `ViewSecret` and dropping it
///   leaves no readable secret residue in the dropped allocation.
/// - **No `Debug`.** Default `Debug` would format the bytes; a
///   manual impl would still encode the secret. Callers needing
///   to inspect bytes for debugging must explicitly route through
///   `as_canonical_bytes()` and accept responsibility for what they
///   do with the result.
///
/// # Canonical-bytes contract
///
/// `as_canonical_bytes()` returns the 32-byte little-endian
/// scalar representation. Cryptographic functions
/// (e.g., [`crate::handle::derive_output_handle`]) take
/// `&[u8; 32]` and rely on this representation being stable across
/// every call site. Changing the encoding here invalidates every
/// previously-derived value keyed on `view_secret`. See
/// `.cursor/rules/18-type-placement.mdc` for the discipline.
///
/// # FFI layout invariant
///
/// `#[repr(transparent)]` guarantees `ViewSecret` has identical
/// memory layout to its inner `[u8; 32]`. This preserves the
/// bit-for-bit compatibility invariant between
/// [`crate::account::AllKeysBlob`] and `shekyl_ffi::ShekylAllKeysBlob`
/// asserted at the latter's `size_of::<...>()` test.
#[repr(transparent)]
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ViewSecret([u8; 32]);

impl ViewSecret {
    /// Construct from raw bytes.
    ///
    /// `pub(crate)` because the only legitimate construction sites are
    /// inside this crate (key derivation in `account.rs`, wallet-file
    /// open paths in `wallet_envelope.rs`). External callers receive
    /// `AllKeysBlob` references and read via `as_canonical_bytes`; they
    /// do not synthesize new `ViewSecret` values.
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the canonical 32-byte representation for cryptographic
    /// input. See type-level "Canonical-bytes contract" doc-comment.
    pub fn as_canonical_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_canonical_bytes() {
        let bytes = [0x42u8; 32];
        let secret = ViewSecret::from_bytes(bytes);
        assert_eq!(secret.as_canonical_bytes(), &bytes);
    }

    #[test]
    fn clone_produces_equal_canonical_bytes() {
        let secret = ViewSecret::from_bytes([0x37u8; 32]);
        let cloned = secret.clone();
        assert_eq!(secret.as_canonical_bytes(), cloned.as_canonical_bytes(),);
    }
}
