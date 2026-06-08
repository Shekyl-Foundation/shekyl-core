// Copyright (c) 2025-2026, The Shekyl Foundation
//
// Adapted from monero-oxide (shekyl-wallet), MIT license.
// All rights reserved.
// BSD-3-Clause

//! Primary output claim — spend-offset scalar for signing.
//!
//! V3.0 uses one primary receive address per account (End-state 5;
//! `docs/design/SUBADDRESS_UNDER_PQC.md` §5.7). The load-bearing primitive
//! here is **not** “derive another address to give someone.” It computes
//! the spend-side offset `mᵢ` in `x = ho + b + mᵢ` when claiming outputs
//! paid to the wallet's primary hybrid address.
//!
//! ## Primary address vs signing offset (do not conflate)
//!
//! | Surface | Material | Notes |
//! |---------|----------|-------|
//! | Encoded primary address (what senders pay) | Base spend key `D` | `AllKeysBlob::classical_address_bytes` |
//! | Output claim / signing | `m₀` at index `0` | `x = ho + b + m₀`; `m₀ ≠ 0` in general |
//!
//! Senders target `D`; signing uses `m₀`. That mismatch is CryptoNote
//! inheritance, not multi-address. See
//! `docs/design/PRIMARY_CLAIM_DERIVATION_RENAME.md` §1.
//!
//! ## Genesis lock
//!
//! ```text
//! m_i = keccak256_to_scalar( "shekyl-subaddr-v1\0" || view_scalar_le32 || idx_le32 )
//! ```
//!
//! V3.0 production hardcodes `idx_le32 = PRIMARY_CLAIM_INDEX_LE` (`[0,0,0,0]`).
//! The formula is defined for every index; non-zero indices are exercised only
//! in this module's unit tests (index-sensitivity KATs), not in product paths.
//!
//! The `-v1` domain-separation suffix is reserved for a future post-genesis
//! derivation change gated on a hard fork.

use curve25519_dalek::Scalar;
use zeroize::Zeroizing;

use shekyl_primitives::keccak256_to_scalar;

/// Domain-separation tag for `m_i` derivation. Genesis-locked; do not change.
const CLAIM_DERIVATION_DOMAIN: &[u8] = b"shekyl-subaddr-v1\0";

/// Little-endian encoding of the primary claim index (`0`). V3.0 production
/// uses this exclusively in `LocalKeys::derive_primary_source_secrets_bundle`.
pub const PRIMARY_CLAIM_INDEX_LE: [u8; 4] = [0, 0, 0, 0];

/// Derive the output spend-offset scalar `m_i` from the view scalar and a
/// 4-byte little-endian index encoding.
///
/// Production callers pass [`PRIMARY_CLAIM_INDEX_LE`]. Index sensitivity for
/// non-zero values is tested in this module only; no public API accepts a
/// caller-chosen “which receive address” index for product flows.
///
/// The view scalar is consumed via its little-endian byte encoding. The
/// intermediate buffer holding the keccak input is wrapped in [`Zeroizing`]
/// so the embedded view-scalar bytes are wiped on drop.
pub fn output_spend_offset_scalar(view_scalar: &Scalar, idx_le_bytes: &[u8; 4]) -> Scalar {
    keccak256_to_scalar(Zeroizing::new(
        [
            CLAIM_DERIVATION_DOMAIN,
            Zeroizing::new(view_scalar.to_bytes()).as_slice(),
            idx_le_bytes.as_slice(),
        ]
        .concat(),
    ))
}

#[cfg(test)]
mod tests {
    use core::ops::Deref;

    use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, EdwardsPoint, Scalar};
    use zeroize::Zeroizing;

    use super::*;

    /// Derive `(spend, view)` for index-sensitivity tests: `D + m_i·G` and
    /// `a·spend`. Not a product API — V3.0 has no per-index receive surface.
    fn derived_spend_point_for_test(
        view_scalar: &Zeroizing<Scalar>,
        spend_public: &EdwardsPoint,
        idx_le_bytes: &[u8; 4],
    ) -> (EdwardsPoint, EdwardsPoint) {
        let scalar = output_spend_offset_scalar(view_scalar.deref(), idx_le_bytes);
        let spend = spend_public + (&scalar * ED25519_BASEPOINT_TABLE);
        let view = view_scalar.deref() * spend;
        (spend, view)
    }

    #[test]
    fn output_spend_offset_scalar_is_deterministic() {
        let view = Scalar::from(42u64);
        let idx = 7u32.to_le_bytes();
        let s1 = output_spend_offset_scalar(&view, &idx);
        let s2 = output_spend_offset_scalar(&view, &idx);
        assert_eq!(s1, s2);
    }

    /// Index sensitivity: V3.0 production uses `PRIMARY_CLAIM_INDEX_LE` only.
    #[test]
    fn output_spend_offset_scalar_differs_per_index() {
        let view = Scalar::from(42u64);
        let s0 = output_spend_offset_scalar(&view, &PRIMARY_CLAIM_INDEX_LE);
        let s1 = output_spend_offset_scalar(&view, &1u32.to_le_bytes());
        assert_ne!(s0, s1);
    }

    #[test]
    fn output_spend_offset_scalar_differs_per_view_scalar() {
        let idx = PRIMARY_CLAIM_INDEX_LE;
        let s_a = output_spend_offset_scalar(&Scalar::from(1u64), &idx);
        let s_b = output_spend_offset_scalar(&Scalar::from(2u64), &idx);
        assert_ne!(s_a, s_b);
    }

    #[test]
    fn derived_spend_point_relationship() {
        let view = Zeroizing::new(Scalar::from(13u64));
        let spend_public = &Scalar::from(99u64) * ED25519_BASEPOINT_TABLE;
        let idx = 5u32.to_le_bytes();

        let m = output_spend_offset_scalar(view.deref(), &idx);
        let (sub_spend, sub_view) = derived_spend_point_for_test(&view, &spend_public, &idx);

        assert_eq!(sub_spend, spend_public + (&m * ED25519_BASEPOINT_TABLE));
        assert_eq!(sub_view, view.deref() * sub_spend);
    }

    /// Hard-coded known-answer vector (byte-identical to pre-rename KAT).
    #[test]
    fn output_spend_offset_scalar_pinned_vector() {
        let view = Scalar::from(0x0102_0304_0506_0708u64);
        let idx = 1u32.to_le_bytes();
        let got = output_spend_offset_scalar(&view, &idx);

        const EXPECTED_BYTES: [u8; 32] = [
            0x88, 0x94, 0xa9, 0x64, 0xc3, 0xbb, 0xbc, 0xa0, 0x05, 0x74, 0xe3, 0x12, 0x50, 0xec,
            0x54, 0xd6, 0xa1, 0x7f, 0xb1, 0x45, 0x9d, 0x94, 0x89, 0x17, 0xbf, 0xd8, 0x53, 0xe1,
            0xf3, 0x81, 0x72, 0x00,
        ];
        assert_eq!(got.to_bytes(), EXPECTED_BYTES);
    }

    #[test]
    fn output_spend_offset_scalar_locks_composition_formula() {
        let view = Scalar::from(0x0102_0304_0506_0708u64);
        let idx = 1u32.to_le_bytes();
        let got = output_spend_offset_scalar(&view, &idx);

        let expected = keccak256_to_scalar(Zeroizing::new(
            [
                CLAIM_DERIVATION_DOMAIN,
                Zeroizing::new(view.to_bytes()).as_slice(),
                idx.as_slice(),
            ]
            .concat(),
        ));
        assert_eq!(got, expected);
    }
}
