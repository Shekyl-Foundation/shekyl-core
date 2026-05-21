// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! AES round primitives for RandomX v2's `AesGenerator1R`,
//! `AesGenerator4R`, and `AesHash1R` per
//! [`specs.md`](../../external/randomx-v2/doc/specs.md) §§3.2-3.4.
//!
//! This module is the thin wrapper layer over the `aes` crate's
//! [`hazmat::cipher_round`] and [`hazmat::equiv_inv_cipher_round`]
//! single-round primitives. The wrappers exist to:
//!
//! - Decouple Phase 2b consumers from the `aes` crate's `Block` type
//!   (an `Array<u8, U16>` from RustCrypto's `hybrid-array`); internal
//!   callers use plain `[u8; 16]` and the conversion happens exactly
//!   once at the wrapper boundary.
//! - Document the FIPS-197 / Intel AES-NI semantic alignment in one
//!   rustdoc paragraph rather than once per call site.
//!
//! The wrappers are zero-cost: both `aes` crate functions take
//! `&mut Block` / `&Block` and `hybrid-array` provides
//! `impl From<&mut [T; N]> for &mut Array<T, U>` (and the analogous
//! shared-ref form), so the conversion is a `cast_from_core_mut`
//! re-borrow with no allocation or copy.
//!
//! # Spec / C reference
//!
//! - **Spec:** [`specs.md`](../../external/randomx-v2/doc/specs.md)
//!   §§3.2-3.4. The generators are defined in terms of AES single-round
//!   operations matching `_mm_aesenc_si128` (encrypt) and
//!   `_mm_aesdec_si128` (equivalent-inverse decrypt).
//! - **C reference:** `external/randomx-v2/src/soft_aes.cpp`'s
//!   `soft_aesenc` and `soft_aesdec` are the byte-for-byte target.
//!   `aes-0.9.0`'s [`hazmat::cipher_round`] matches `soft_aesenc` and
//!   [`hazmat::equiv_inv_cipher_round`] matches `soft_aesdec` per the
//!   §5.6 verification record in
//!   [`RANDOMX_V2_PHASE2B_PLAN.md`](../../docs/design/RANDOMX_V2_PHASE2B_PLAN.md).
//!
//! # Safety posture
//!
//! Both wrappers are safe at their public surface; the underlying `aes`
//! crate routes through an `if_intrinsics_available!` macro (CPUID-gated
//! AES-NI on x86, NEON on aarch64) with an `unsafe { ... }` interior
//! that is verified internal to the `aes` crate. `#![deny(unsafe_code)]`
//! at the crate level survives.
//!
//! # Scope at this commit (Phase 2b commit 1)
//!
//! Round primitives only. The §3.2-3.4 composites
//! (`AesGenerator1R`, `AesGenerator4R`, `AesHash1R`) land in Phase 2b
//! commit 2 within this same module.
//!
//! [`hazmat::cipher_round`]: aes::hazmat::cipher_round
//! [`hazmat::equiv_inv_cipher_round`]: aes::hazmat::equiv_inv_cipher_round

use aes::{hazmat, Block};

/// AES encrypt single round (FIPS 197 Appendix C / `_mm_aesenc_si128`).
///
/// Applies `SubBytes → ShiftRows → MixColumns → AddRoundKey` to
/// `state` in place, using `round_key` as the round key. Byte-for-byte
/// equivalent to `external/randomx-v2/src/soft_aes.cpp`'s `soft_aesenc`.
///
/// # REMOVE WHEN COMMIT 2 LANDS:
///
/// Phase 2b commit 2 lands `AesGenerator1R`, `AesGenerator4R`, and
/// `AesHash1R` composites which call this primitive from within this
/// module. Until then the only callers are tests; the `dead_code` lint
/// is silenced narrowly here per `21-reversion-clause-discipline.mdc`.
#[allow(dead_code)]
pub(crate) fn cipher_round(state: &mut [u8; 16], round_key: &[u8; 16]) {
    let block: &mut Block = state.into();
    let round_key: &Block = round_key.into();
    hazmat::cipher_round(block, round_key);
}

/// AES equivalent-inverse-cipher single round (FIPS 197 Appendix C
/// equivalent-inverse form / `_mm_aesdec_si128`).
///
/// Applies `InvSubBytes → InvShiftRows → InvMixColumns → AddRoundKey`
/// (equivalent-inverse order; NOT FIPS 197 standard inverse order) to
/// `state` in place, using `round_key` as the round key. Byte-for-byte
/// equivalent to `external/randomx-v2/src/soft_aes.cpp`'s `soft_aesdec`.
///
/// The equivalent-inverse form is the only single-round inverse
/// primitive exposed by `aes-0.9.0::hazmat`; the FIPS 197 standard
/// inverse form is not exposed. This structurally precludes the
/// wrong-form selection failure mode per
/// [`RANDOMX_V2_PHASE2B_PLAN.md`](../../docs/design/RANDOMX_V2_PHASE2B_PLAN.md)
/// §4.1.
///
/// # REMOVE WHEN COMMIT 2 LANDS:
///
/// Same dissolution timeline as [`cipher_round`].
#[allow(dead_code)]
pub(crate) fn equiv_inv_cipher_round(state: &mut [u8; 16], round_key: &[u8; 16]) {
    let block: &mut Block = state.into();
    let round_key: &Block = round_key.into();
    hazmat::equiv_inv_cipher_round(block, round_key);
}

#[cfg(test)]
mod tests {
    use super::*;

    // SubBytes(0x00) = 0x63 (AES S-box[0]); InvSubBytes(0x00) = 0x52
    // (AES inverse S-box[0]). For a uniform state and uniform round
    // key, ShiftRows / InvShiftRows are no-ops (each row is uniform)
    // and MixColumns / InvMixColumns of a uniform column [c, c, c, c]
    // produce [c, c, c, c] (the column-mix matrices have rows that
    // GF(2^8)-sum to 0x01). The single-round result is therefore the
    // post-SubBytes value XORed with the (uniform) round key.

    /// AES single round on all-zero state + all-zero round key:
    /// `SubBytes([0; 16])` = `[0x63; 16]`; `MixColumns` and
    /// `ShiftRows` are uniform-preserving; `AddRoundKey` with zero
    /// key leaves the state at `[0x63; 16]`.
    #[test]
    fn cipher_round_zero_state_zero_key_yields_sbox_zero() {
        let mut state = [0u8; 16];
        let key = [0u8; 16];
        cipher_round(&mut state, &key);
        assert_eq!(state, [0x63u8; 16]);
    }

    /// AES single round preserves the round-key argument (in-place
    /// only on the state).
    #[test]
    fn cipher_round_does_not_mutate_round_key() {
        let mut state = [0x42u8; 16];
        let key = [0x99u8; 16];
        let key_before = key;
        cipher_round(&mut state, &key);
        assert_eq!(key, key_before);
    }

    /// Equivalent-inverse-cipher single round on all-zero state +
    /// all-zero round key: `InvSubBytes([0; 16])` = `[0x52; 16]`;
    /// `InvShiftRows` and `InvMixColumns` are uniform-preserving;
    /// `AddRoundKey` with zero key leaves the state at `[0x52; 16]`.
    #[test]
    fn equiv_inv_cipher_round_zero_state_zero_key_yields_inv_sbox_zero() {
        let mut state = [0u8; 16];
        let key = [0u8; 16];
        equiv_inv_cipher_round(&mut state, &key);
        assert_eq!(state, [0x52u8; 16]);
    }

    /// Equivalent-inverse-cipher single round preserves the
    /// round-key argument.
    #[test]
    fn equiv_inv_cipher_round_does_not_mutate_round_key() {
        let mut state = [0x42u8; 16];
        let key = [0x99u8; 16];
        let key_before = key;
        equiv_inv_cipher_round(&mut state, &key);
        assert_eq!(key, key_before);
    }

    /// The two round primitives are distinct functions: on a chosen
    /// non-uniform state with a zero key, `cipher_round` and
    /// `equiv_inv_cipher_round` must produce different outputs. This
    /// catches a future implementation swap that would silently route
    /// both wrappers to the same underlying primitive.
    ///
    /// Note: on degenerate inputs (e.g., all-zero state + all-zero
    /// key) the single-round dec-of-enc *is* the identity by S-box
    /// inversion + uniform preservation under MixColumns; that's a
    /// property of the math, not a wiring bug. The non-uniform input
    /// here avoids the degeneracy.
    #[test]
    fn cipher_round_and_equiv_inv_cipher_round_are_distinct() {
        let non_uniform: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let key = [0u8; 16];
        let mut enc_state = non_uniform;
        cipher_round(&mut enc_state, &key);
        let mut dec_state = non_uniform;
        equiv_inv_cipher_round(&mut dec_state, &key);
        assert_ne!(enc_state, dec_state);
    }
}
