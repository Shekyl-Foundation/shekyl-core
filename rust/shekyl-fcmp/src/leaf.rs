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

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A 32-byte scalar representing `H(pqc_pk)` for the 4th leaf position.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, Serialize, Deserialize)]
pub struct PqcLeafScalar(pub [u8; 32]);

impl PqcLeafScalar {
    /// Compute `H(pqc_pk)` — the 4th leaf scalar.
    ///
    /// Forwards to [`shekyl_crypto_pq::derivation::hash_pqc_public_key`] (the
    /// single source for the consensus leaf hash; domain
    /// [`shekyl_crypto_pq::derivation::DOMAIN_PQC_LEAF`]). SA-3a retired the
    /// duplicate Blake2b/wide_reduce body that lived here — it was kept in sync
    /// with the owner only by a doc comment, so one edit to either side would
    /// have silently forked the leaf hash.
    pub fn from_pqc_public_key(pqc_pk_bytes: &[u8]) -> Self {
        PqcLeafScalar(shekyl_crypto_pq::derivation::hash_pqc_public_key(
            pqc_pk_bytes,
        ))
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

    /// Pinned KAT (SA-3a byte-proof). The consensus leaf hash for these fixed
    /// inputs must equal the exact bytes the **pre-dedup** implementation
    /// produced. SA-3a consolidated the duplicated `from_pqc_public_key` (which
    /// re-implemented Blake2b/wide_reduce) into a forward to
    /// `shekyl_crypto_pq::derivation::hash_pqc_public_key`; two "identical-value"
    /// implementations can still differ in an unexercised edge case (empty,
    /// short, full-length), so these vectors — captured from the original code
    /// before the merge — prove the consolidation changed no byte. On a
    /// consensus leaf hash, prove it; do not argue it.
    #[test]
    fn pqc_leaf_hash_pinned_kat() {
        let cases: [(Vec<u8>, &str); 4] = [
            (
                vec![],
                "dd457919e9f9129b3cc48b91a686bf758f9c5015ec9caf95fe0a9c87d844b675",
            ),
            (
                vec![0xab],
                "8b8de030e6ba684d7e00354ec2cd447a7da664ac14d79489b486b0cb0edbd413",
            ),
            (
                vec![0xab; 1952], // full ML-DSA-65 public-key length
                "85111edb0986bd48f35ee915ca9b8d566dc21897f6ce3c695f37a24e49070011",
            ),
            (
                vec![0xff; 1952],
                "3eb75d6bd70c42d729824cd57dc33e9de5e0c40c7b22c5f250d7a53b77d88207",
            ),
        ];
        for (pk, expected) in &cases {
            let s = PqcLeafScalar::from_pqc_public_key(pk);
            let got: String = s.0.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(
                &got,
                expected,
                "consensus leaf hash drifted for input length {}",
                pk.len()
            );
        }
    }

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
        assert!(
            bool::from(HelioseleneField::from_repr(s.0).is_some()),
            "leaf scalar must be a canonical Selene base field element"
        );
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
