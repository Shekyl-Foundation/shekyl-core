// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! 4-scalar curve tree leaf: `{O.x, I.x, C.x, CM.x}`.
//!
//! Extends the upstream 3-scalar FCMP++ leaf with the x-coordinate of the
//! output's PQC leaf commitment `CM = k·G_k + r·J`, `k = H_ℓ(hybrid_pk)`
//! (`PL-D3`, `docs/design/FCMP_SPEND_LINKABILITY.md` §6.2). The circuit proves
//! `K + r·J = CM` for the verifier-computed `K = k·G_k` of the key the spend
//! reveals, so the key is bound to the spent leaf without the leaf value being
//! a public function of the key — which is what closed `PL-D1`.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// The 32-byte 4th leaf scalar: the Wei25519 x-coordinate of the output's PQC
/// leaf commitment point `CM` (a Selene scalar), as stored in the leaf.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, Serialize, Deserialize)]
pub struct PqcLeafScalar(pub [u8; 32]);

impl PqcLeafScalar {
    /// The leaf scalar for a published commitment point (compressed Ed25519):
    /// `None` if the bytes are not a decompressible point. Admission checks
    /// canonical / prime-order / non-identity before the value reaches a leaf
    /// (`shekyl_crypto_pq::derivation::pqc_leaf_point_valid`); this is the
    /// conversion only.
    #[must_use]
    pub fn from_commitment_point(cm: &[u8; 32]) -> Option<Self> {
        crate::tree::ed25519_point_to_selene_scalar(cm).map(PqcLeafScalar)
    }
}

/// The per-output PQC key scalar `k = H_ℓ(hybrid_pk)` (an Ed25519 scalar), the
/// verifier's input to the opening check.
///
/// Forwards to [`shekyl_crypto_pq::derivation::pqc_key_scalar`] (the single
/// source; customization [`shekyl_crypto_pq::derivation::DOMAIN_PQC_LEAF_KEY`]).
/// A duplicate body here would be a second copy to drift; there is none.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, Serialize, Deserialize)]
pub struct PqcKeyScalar(pub [u8; 32]);

impl PqcKeyScalar {
    /// `k` for the canonical hybrid public key the spend reveals.
    #[must_use]
    pub fn from_pqc_public_key(pqc_pk_bytes: &[u8]) -> Self {
        PqcKeyScalar(shekyl_crypto_pq::derivation::pqc_key_scalar(pqc_pk_bytes))
    }

    /// The public point `K = k·G_k`, compressed — what the circuit's opening leg
    /// takes as its public value. Never on the wire.
    #[must_use]
    pub fn point(&self) -> [u8; 32] {
        use curve25519_dalek::scalar::Scalar;
        let k = Scalar::from_bytes_mod_order(self.0);
        (*shekyl_curve_generators::PQC_LEAF_COMMITMENT_G_K * k)
            .compress()
            .to_bytes()
    }
}

/// A Shekyl curve tree leaf with 4 scalars.
///
/// Layout: `{O.x, I.x, C.x, CM.x}` — each is a 32-byte Selene scalar.
/// Total: 128 bytes per output in the curve tree.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct ShekylLeaf {
    /// Output public key x-coordinate.
    pub o_x: [u8; 32],
    /// Key image generator x-coordinate.
    pub i_x: [u8; 32],
    /// Pedersen commitment x-coordinate.
    pub c_x: [u8; 32],
    /// The PQC leaf commitment's x-coordinate `CM.x` (`PL-D3`).
    pub h_pqc: PqcLeafScalar,
}

impl ShekylLeaf {
    /// Total byte size of a serialized leaf.
    pub const SIZE: usize = 128;

    /// Serialize the leaf to 128 bytes.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[..32].copy_from_slice(&self.o_x);
        out[32..64].copy_from_slice(&self.i_x);
        out[64..96].copy_from_slice(&self.c_x);
        out[96..128].copy_from_slice(&self.h_pqc.0);
        out
    }

    /// Deserialize a leaf from 128 bytes.
    pub fn from_bytes(bytes: &[u8; Self::SIZE]) -> Self {
        let mut o_x = [0u8; 32];
        let mut i_x = [0u8; 32];
        let mut c_x = [0u8; 32];
        let mut h_pqc = [0u8; 32];
        o_x.copy_from_slice(&bytes[..32]);
        i_x.copy_from_slice(&bytes[32..64]);
        c_x.copy_from_slice(&bytes[64..96]);
        h_pqc.copy_from_slice(&bytes[96..128]);
        ShekylLeaf {
            o_x,
            i_x,
            c_x,
            h_pqc: PqcLeafScalar(h_pqc),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphersuite::group::ff::PrimeField;
    use helioselene::HelioseleneField;

    // The byte pins for `PqcKeyScalar::from_pqc_public_key` live in
    // `docs/test_vectors/PQC_KEY_SCALAR_KAT.json`, consumed at the SSOT owner
    // (`shekyl-crypto-pq/src/derivation.rs`) and asserted through this wrapper.
    #[test]
    fn pqc_key_scalar_deterministic() {
        let pk = vec![0xab; 1952]; // ML-DSA-65 public key size
        let s1 = PqcKeyScalar::from_pqc_public_key(&pk);
        let s2 = PqcKeyScalar::from_pqc_public_key(&pk);
        assert_eq!(s1, s2);
    }
    #[test]
    fn pqc_key_scalar_different_keys() {
        let pk1 = vec![0xab; 1952];
        let pk2 = vec![0xcd; 1952];
        assert_ne!(
            PqcKeyScalar::from_pqc_public_key(&pk1),
            PqcKeyScalar::from_pqc_public_key(&pk2)
        );
    }
    #[test]
    fn pqc_key_scalar_is_canonical_ed25519_scalar() {
        use curve25519_dalek::scalar::Scalar;
        for pk in [vec![0xff; 1952], vec![], vec![0x01]] {
            let s = PqcKeyScalar::from_pqc_public_key(&pk);
            assert!(
                bool::from(Scalar::from_canonical_bytes(s.0).is_some()),
                "k must be a canonical Ed25519 scalar"
            );
            assert_ne!(s.0, [0u8; 32], "k must not be zero");
        }
    }
    #[test]
    fn pqc_key_point_is_k_times_g_k() {
        use curve25519_dalek::scalar::Scalar;
        let s = PqcKeyScalar::from_pqc_public_key(&[0xab; 1952]);
        let expected =
            *shekyl_curve_generators::PQC_LEAF_COMMITMENT_G_K * Scalar::from_bytes_mod_order(s.0);
        assert_eq!(s.point(), expected.compress().to_bytes());
    }
    #[test]
    fn leaf_scalar_from_commitment_point_is_wei25519_x() {
        use curve25519_dalek::scalar::Scalar;
        let cm = (*shekyl_curve_generators::PQC_LEAF_COMMITMENT_J
            * Scalar::from_bytes_mod_order([7u8; 32]))
        .compress()
        .to_bytes();
        let x = PqcLeafScalar::from_commitment_point(&cm).expect("valid point");
        assert!(
            bool::from(HelioseleneField::from_repr(x.0).is_some()),
            "leaf scalar must be a canonical Selene scalar"
        );
        assert_eq!(
            x.0,
            crate::tree::ed25519_point_to_selene_scalar(&cm).unwrap()
        );
        assert!(PqcLeafScalar::from_commitment_point(&[0xffu8; 32]).is_none());
    }
    #[test]
    fn leaf_roundtrip() {
        let leaf = ShekylLeaf {
            o_x: [1u8; 32],
            i_x: [2u8; 32],
            c_x: [3u8; 32],
            h_pqc: PqcLeafScalar([4u8; 32]),
        };
        let bytes = leaf.to_bytes();
        assert_eq!(bytes.len(), ShekylLeaf::SIZE);
        let restored = ShekylLeaf::from_bytes(&bytes);
        assert_eq!(leaf, restored);
    }

    #[test]
    fn leaf_size_constant_is_128() {
        assert_eq!(ShekylLeaf::SIZE, 128);
    }

    #[test]
    fn leaf_serialization_layout() {
        let leaf = ShekylLeaf {
            o_x: [0xAA; 32],
            i_x: [0xBB; 32],
            c_x: [0xCC; 32],
            h_pqc: PqcLeafScalar([0xDD; 32]),
        };
        let bytes = leaf.to_bytes();
        assert!(bytes[..32].iter().all(|&b| b == 0xAA));
        assert!(bytes[32..64].iter().all(|&b| b == 0xBB));
        assert!(bytes[64..96].iter().all(|&b| b == 0xCC));
        assert!(bytes[96..128].iter().all(|&b| b == 0xDD));
    }

    #[test]
    fn leaf_zero_roundtrip() {
        let leaf = ShekylLeaf {
            o_x: [0u8; 32],
            i_x: [0u8; 32],
            c_x: [0u8; 32],
            h_pqc: PqcLeafScalar([0u8; 32]),
        };
        let restored = ShekylLeaf::from_bytes(&leaf.to_bytes());
        assert_eq!(leaf, restored);
    }

    #[test]
    fn pqc_leaf_scalar_byte_roundtrip() {
        let original = PqcLeafScalar([0xab; 32]);
        let leaf = ShekylLeaf {
            o_x: [1u8; 32],
            i_x: [2u8; 32],
            c_x: [3u8; 32],
            h_pqc: original,
        };
        let bytes = leaf.to_bytes();
        let restored = ShekylLeaf::from_bytes(&bytes);
        assert_eq!(restored.h_pqc, original);
    }
}
