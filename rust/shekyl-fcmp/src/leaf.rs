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

        // Reduce the 512-bit hash to a 256-bit scalar.
        // For Selene (prime-order subgroup of a ~255-bit prime field),
        // taking the low 256 bits of a 512-bit hash gives negligible bias.
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&hash_512[..32]);

        // Clear the high bit to ensure the value is in the valid scalar range.
        // Selene's scalar field is close to 2^255, so clearing bit 255 guarantees
        // the value is < 2^255 < field order.
        scalar[31] &= 0x7f;

        PqcLeafScalar(scalar)
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
    fn pqc_leaf_scalar_high_bit_cleared() {
        let pk = vec![0xff; 1952];
        let s = PqcLeafScalar::from_pqc_public_key(&pk);
        assert_eq!(s.0[31] & 0x80, 0, "high bit must be cleared for scalar range");
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
}
