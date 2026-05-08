// Copyright (c) 2025-2026, The Shekyl Foundation
//
// Adapted from monero-oxide (shekyl-wallet), MIT license.
// All rights reserved.
// BSD-3-Clause

//! Subaddress derivation primitives.
//!
//! This module is the canonical home for **all** Shekyl subaddress
//! derivation. Today it contains the classical Edwards-curve component
//! ([`subaddress_derivation_scalar`], [`subaddress_keys`]); per
//! `STAGE_1_PR_3_KEY_ENGINE.md` §6.4 / §3.1.3, the per-subaddress hybrid KEM
//! keypair derivation (X25519 + ML-KEM-768) lands alongside as
//! `derive_subaddress_kem_keypair` once its underlying infrastructure
//! materializes (the missing infrastructure that Commit 4b stubs at
//! `KeyEngine::derive_subaddress(_, Recipient)`).
//!
//! The two components together form Shekyl's complete subaddress identity:
//! the classical Edwards points are the spend/view-side identity;
//! the hybrid KEM keypair is the receiver-side identity for FCMP++ output
//! detection. Co-locating them in one module makes the namespace's growth
//! trajectory visible to future readers — "everything subaddress-related"
//! lives here.
//!
//! ## "Classical Edwards-curve", not "classical-Monero"
//!
//! The functions below are **classical Edwards-curve** in the
//! pre-quantum-vs-PQC sense, not Monero-inherited. The pattern
//! (Keccak-keyed scalar derivation against the view secret) is structurally
//! similar to upstream Monero's, but every parameter is Shekyl-genesis-locked:
//! the `shekyl-subaddr-v1\0` domain tag is Shekyl's, the flat `u32` index
//! namespace is Shekyl's (`docs/V3_WALLET_DECISION_LOG.md`,
//! "Subaddress hierarchy"), and the byte encoding is owned by
//! `shekyl_engine_state::SubaddressIndex::to_canonical_bytes`. Per
//! `60-no-monero-legacy.mdc`, no Monero-era compatibility code lives
//! here; this is forward Shekyl crypto.
//!
//! ## Path-stateless discipline
//!
//! Per `.cursor/rules/18-type-placement.mdc`, subaddress derivation is
//! transform-shaped: it is a pure function from `(view_secret, spend_public,
//! subaddress_index)` to public material. The previous home was on
//! `shekyl_scanner::ViewPair` (a state-bearing wallet-credentials object),
//! which routed every caller through a wallet-state intermediate.
//!
//! Per `STAGE_1_PR_3_KEY_ENGINE.md` Commit 4a, the primitives are relocated
//! here so `KeyEngine` implementors (in particular
//! `shekyl_engine_core::engine::local_keys::LocalKeys`) call them directly
//! with byte/point inputs — the path from trait surface to cryptographic
//! primitive is stateless end-to-end. `ViewPair::subaddress_keys` is
//! preserved as a thin call-through to [`subaddress_keys`] for backward
//! compatibility with existing scanner code; the previously-internal
//! `subaddress_derivation` method was deleted (no live caller after the
//! relocation, per `15-deletion-and-debt.mdc`).
//!
//! ## Genesis lock
//!
//! The derivation is **genesis-locked**:
//!
//! ```text
//! m_i = keccak256_to_scalar( "shekyl-subaddr-v1\0" || view_scalar_le32 || idx_le32 )
//! ```
//!
//! where `view_scalar_le32` is the 32-byte little-endian canonical encoding
//! of the private view scalar, and `idx_le32` is the 4-byte little-endian
//! encoding of the flat subaddress index (per
//! `shekyl_engine_state::SubaddressIndex::to_canonical_bytes`). The math is
//! defined for every index — see `docs/V3_WALLET_DECISION_LOG.md`,
//! "Subaddress hierarchy".
//!
//! The `-v1` domain-separation suffix is reserved for a future post-genesis
//! derivation change gated on a hard fork; it is not a backward-compatibility
//! dial.
//!
//! ## Primary address is not the `idx == 0` derivation
//!
//! Despite the math being defined for `idx == 0`, the wallet's primary
//! address is the **bare account keys** `(D, a*G)`, not the `idx == 0`
//! derivation `(D + m_0*G, a*(D + m_0*G))`. Senders paying "the wallet"
//! target the base spend key `D` packed into
//! `AllKeysBlob::classical_address_bytes` by [`crate::account::rederive_account`].
//! `KeyEngine::derive_subaddress` enforces this contract by special-casing
//! `SubaddressIndex::PRIMARY` and returning the base account keys directly;
//! `subaddress_keys` is the per-index derivation primitive for `idx >= 1`.
//! See [`subaddress_keys`]'s "The primary address is *not* this derivation"
//! section and `shekyl_engine_state::SubaddressIndex`'s "Primary special
//! case" section for the cross-cutting rationale.

use core::ops::Deref;

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, EdwardsPoint, Scalar};
use zeroize::Zeroizing;

use shekyl_primitives::keccak256_to_scalar;

/// Domain-separation tag for `m_i` derivation. Genesis-locked; do not change.
const SUBADDR_DERIVATION_DOMAIN: &[u8] = b"shekyl-subaddr-v1\0";

/// Derive the per-subaddress scalar `m_i` from the view scalar and a 4-byte
/// little-endian subaddress index encoding.
///
/// Callers holding a typed [`SubaddressIndex`](shekyl_engine_state::SubaddressIndex)
/// pass `idx.to_canonical_bytes()` (the rule-18 canonical-bytes accessor);
/// callers holding a raw `u32` pass `idx.to_le_bytes()`. This function is the
/// single byte-layout boundary — it never sees the typed index.
///
/// The view scalar is consumed via its little-endian byte encoding. The
/// intermediate buffer holding the keccak input is wrapped in [`Zeroizing`]
/// so the embedded view-scalar bytes are wiped on drop; per
/// `35-secure-memory.mdc`, this preserves wipe-on-drop discipline across the
/// hash boundary.
pub fn subaddress_derivation_scalar(view_scalar: &Scalar, idx_le_bytes: &[u8; 4]) -> Scalar {
    keccak256_to_scalar(Zeroizing::new(
        [
            SUBADDR_DERIVATION_DOMAIN,
            Zeroizing::new(view_scalar.to_bytes()).as_slice(),
            idx_le_bytes.as_slice(),
        ]
        .concat(),
    ))
}

/// Derive the public `(spend, view)` point pair for a subaddress.
///
/// Returns
///
/// * `spend = D + m_i * G` where `D` is the wallet's base public spend
///   point and `m_i` is the per-subaddress scalar from
///   [`subaddress_derivation_scalar`], and
/// * `view = a * spend` where `a` is the wallet's private view scalar.
///
/// # The primary address is *not* this derivation
///
/// Calling this function with `idx_le_bytes = [0u8; 4]` is mathematically
/// well-defined and produces `(D + m_0 * G, a * (D + m_0 * G))` — but
/// **this is not the wallet's primary address.** The encoded primary
/// address (per [`crate::account::rederive_account`]) carries the bare
/// account keys `(D, a*G)`; senders paying "the wallet" target `D`.
///
/// `KeyEngine` implementors enforce this contract by special-casing
/// `SubaddressIndex::PRIMARY` and returning the base account keys
/// directly; this function is the per-index derivation primitive for
/// `idx >= 1`. Cryptographic call sites that operate on the
/// canonical-bytes form of the index (e.g., per-subaddress KEM-keypair
/// derivation, where every index is wallet-keyed and the value at
/// `idx == 0` is a distinct keypair from `idx == 1`) treat `idx == 0`
/// as a regular index — that is correct for *those* derivations
/// because they do not collapse into the bare account keys.
///
/// See `shekyl_engine_state::SubaddressIndex`'s "Primary special case"
/// section for the cross-cutting rationale.
pub fn subaddress_keys(
    view_scalar: &Zeroizing<Scalar>,
    spend_public: &EdwardsPoint,
    idx_le_bytes: &[u8; 4],
) -> (EdwardsPoint, EdwardsPoint) {
    let scalar = subaddress_derivation_scalar(view_scalar.deref(), idx_le_bytes);
    let spend = spend_public + (&scalar * ED25519_BASEPOINT_TABLE);
    let view = view_scalar.deref() * spend;
    (spend, view)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Determinism: same inputs produce the same scalar across calls.
    #[test]
    fn derivation_scalar_is_deterministic() {
        let view = Scalar::from(42u64);
        let idx = 7u32.to_le_bytes();
        let s1 = subaddress_derivation_scalar(&view, &idx);
        let s2 = subaddress_derivation_scalar(&view, &idx);
        assert_eq!(s1, s2);
    }

    /// Different indices produce different scalars (sanity check;
    /// the cryptographic property is keccak's collision resistance).
    #[test]
    fn derivation_scalar_differs_per_index() {
        let view = Scalar::from(42u64);
        let s0 = subaddress_derivation_scalar(&view, &0u32.to_le_bytes());
        let s1 = subaddress_derivation_scalar(&view, &1u32.to_le_bytes());
        assert_ne!(s0, s1);
    }

    /// Different view scalars produce different per-index scalars
    /// (sanity check; subaddresses are wallet-keyed, not just index-keyed).
    #[test]
    fn derivation_scalar_differs_per_view_scalar() {
        let idx = 0u32.to_le_bytes();
        let s_a = subaddress_derivation_scalar(&Scalar::from(1u64), &idx);
        let s_b = subaddress_derivation_scalar(&Scalar::from(2u64), &idx);
        assert_ne!(s_a, s_b);
    }

    /// `subaddress_keys` reproduces the relationship `spend = D + m_i * G`
    /// and `view = a * spend`.
    #[test]
    fn subaddress_keys_relationship() {
        let view = Zeroizing::new(Scalar::from(13u64));
        let spend_public = &Scalar::from(99u64) * ED25519_BASEPOINT_TABLE;
        let idx = 5u32.to_le_bytes();

        let m = subaddress_derivation_scalar(view.deref(), &idx);
        let (sub_spend, sub_view) = subaddress_keys(&view, &spend_public, &idx);

        assert_eq!(sub_spend, spend_public + (&m * ED25519_BASEPOINT_TABLE));
        assert_eq!(sub_view, view.deref() * sub_spend);
    }

    /// Hard-coded known-answer vector for `subaddress_derivation_scalar`.
    ///
    /// The expected scalar bytes are pinned to the actual cryptographic
    /// output captured at implementation time. This is a **true tripwire**:
    /// any change inside `keccak256_to_scalar` (algorithm swap, output
    /// encoding change), the `SUBADDR_DERIVATION_DOMAIN` constant, the
    /// scalar canonical encoding, or the index little-endian convention
    /// fails this test. Cryptographic correctness of the underlying
    /// keccak primitive rests on `shekyl-primitives`' own coverage; this
    /// test pins the composed function's output bytes.
    ///
    /// Inputs:
    /// * `view = Scalar::from(0x0102_0304_0506_0708u64)`
    /// * `idx  = 1u32.to_le_bytes()` (i.e. `[0x01, 0x00, 0x00, 0x00]`)
    ///
    /// Updating this vector requires explicit review per
    /// `30-cryptography.mdc` — vectors define consensus and cannot
    /// drift silently.
    #[test]
    fn derivation_scalar_pinned_vector() {
        let view = Scalar::from(0x0102_0304_0506_0708u64);
        let idx = 1u32.to_le_bytes();
        let got = subaddress_derivation_scalar(&view, &idx);

        const EXPECTED_BYTES: [u8; 32] = [
            0x88, 0x94, 0xa9, 0x64, 0xc3, 0xbb, 0xbc, 0xa0, 0x05, 0x74, 0xe3, 0x12, 0x50, 0xec,
            0x54, 0xd6, 0xa1, 0x7f, 0xb1, 0x45, 0x9d, 0x94, 0x89, 0x17, 0xbf, 0xd8, 0x53, 0xe1,
            0xf3, 0x81, 0x72, 0x00,
        ];
        assert_eq!(got.to_bytes(), EXPECTED_BYTES);
    }

    /// Formula-lock companion to [`derivation_scalar_pinned_vector`].
    ///
    /// Recomputes the expected scalar via the same composition this
    /// module documents (`SUBADDR_DERIVATION_DOMAIN || view_le32 || idx_le4`)
    /// using the underlying `keccak256_to_scalar` primitive directly.
    /// This catches refactors of `subaddress_derivation_scalar`'s
    /// internal composition (e.g., re-ordered concatenation, dropped
    /// domain tag, swapped scalar encoding) without depending on the
    /// hard-coded expected bytes — the two tests fail in different
    /// classes of regression and together pin both the spec and the
    /// implementation against drift.
    ///
    /// This test will pass even if `keccak256_to_scalar` itself
    /// changes, because both sides re-run the same primitive — that
    /// is what [`derivation_scalar_pinned_vector`] guards against.
    #[test]
    fn derivation_scalar_locks_composition_formula() {
        let view = Scalar::from(0x0102_0304_0506_0708u64);
        let idx = 1u32.to_le_bytes();
        let got = subaddress_derivation_scalar(&view, &idx);

        let expected = keccak256_to_scalar(Zeroizing::new(
            [
                SUBADDR_DERIVATION_DOMAIN,
                Zeroizing::new(view.to_bytes()).as_slice(),
                idx.as_slice(),
            ]
            .concat(),
        ));
        assert_eq!(got, expected);
    }
}
