// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! 4-scalar curve tree leaf: `{O.x, I.x, C.x, H(pqc_pk)}`.
//!
//! Extends the upstream 3-scalar FCMP++ leaf with a PQC commitment hash
//! as the 4th Selene scalar. The verifier checks this value matches the
//! `pqc_auth` public key presented in the transaction, binding PQC
//! authorization to the UTXO set without revealing which output is spent.

use blake2::{Blake2b512, Digest};
use ciphersuite::group::ff::PrimeField;
use helioselene::HelioseleneField;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::DOMAIN_PQC_LEAF;

/// A 32-byte scalar representing `H(pqc_pk)` for the 4th leaf position.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, Serialize, Deserialize)]
pub struct PqcLeafScalar(pub [u8; 32]);

impl PqcLeafScalar {
    /// Compute `H(pqc_pk)` using domain-separated Blake2b-512, reduced to a
    /// Selene scalar. The hash is: `Blake2b-512(DOMAIN_PQC_LEAF || pqc_pk_bytes)`,
    /// then the 512-bit output is reduced modulo the Selene scalar field order.
    pub fn from_pqc_public_key(pqc_pk_bytes: &[u8]) -> Self {
        let mut hasher = Blake2b512::new();
        hasher.update(DOMAIN_PQC_LEAF);
        hasher.update(pqc_pk_bytes);
        let hash_512 = hasher.finalize();

        // Proper modular reduction: use the full 512-bit hash to produce
        // an unbiased, canonical Selene base field element (HelioseleneField).
        // The leaf layer of the curve tree is a Selene hash, so all 4 scalars
        // must be valid HelioseleneField elements.
        let mut uniform = [0u8; 64];
        uniform.copy_from_slice(hash_512.as_ref());
        let field_elem = HelioseleneField::wide_reduce(uniform);
        uniform.zeroize();

        PqcLeafScalar(field_elem.to_repr())
    }
}

/// A Shekyl curve tree leaf with 4 scalars.
///
/// Layout: `{O.x, I.x, C.x, H(pqc_pk)}` — each is a 32-byte Selene scalar.
/// Total: 128 bytes per output in the curve tree.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct ShekylLeaf {
    /// Output public key x-coordinate.
    pub o_x: [u8; 32],
    /// Key image generator x-coordinate.
    pub i_x: [u8; 32],
    /// Pedersen commitment x-coordinate.
    pub c_x: [u8; 32],
    /// PQC public key commitment: `H(pqc_pk)`.
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
        ShekylLeaf { o_x, i_x, c_x, h_pqc: PqcLeafScalar(h_pqc) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pqc_leaf_scalar_deterministic() {
        let pk = vec![0xab; 1952]; // ML-DSA-65 public key size
        let s1 = PqcLeafScalar::from_pqc_public_key(&pk);
        let s2 = PqcLeafScalar::from_pqc_public_key(&pk);
        assert_eq!(s1, s2);
    }

    #[test]
    fn pqc_leaf_scalar_different_keys() {
        let pk1 = vec![0xab; 1952];
        let pk2 = vec![0xcd; 1952];
        let s1 = PqcLeafScalar::from_pqc_public_key(&pk1);
        let s2 = PqcLeafScalar::from_pqc_public_key(&pk2);
        assert_ne!(s1, s2);
    }

    #[test]
    fn pqc_leaf_scalar_canonical() {
        let pk = vec![0xff; 1952];
        let s = PqcLeafScalar::from_pqc_public_key(&pk);
        // Verify the result is a canonical HelioseleneField element by round-tripping
        use ciphersuite::group::ff::PrimeField;
        assert!(bool::from(HelioseleneField::from_repr(s.0).is_some()),
            "leaf scalar must be a canonical Selene base field element");
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
    fn pqc_leaf_scalar_empty_key() {
        let s = PqcLeafScalar::from_pqc_public_key(&[]);
        assert!(bool::from(HelioseleneField::from_repr(s.0).is_some()));
    }

    #[test]
    fn pqc_leaf_scalar_single_byte_keys() {
        for b in 0..=255u8 {
            let s = PqcLeafScalar::from_pqc_public_key(&[b]);
            assert!(bool::from(HelioseleneField::from_repr(s.0).is_some()));
        }
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
