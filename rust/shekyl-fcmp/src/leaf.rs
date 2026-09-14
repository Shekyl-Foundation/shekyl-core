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
    /// (`shekyl_crypto_pq::leaf_commitment::pqc_leaf_point_valid`); this is the
    /// conversion only.
    #[must_use]
    pub fn from_commitment_point(cm: &[u8; 32]) -> Option<Self> {
        crate::tree::ed25519_point_to_selene_scalar(cm).map(PqcLeafScalar)
    }
}

/// The per-output PQC key scalar `k = H_ℓ(hybrid_pk)` (an Ed25519 scalar), the
/// verifier's input to the opening check.
///
/// The wrapped bytes are **always the canonical encoding** of `k` — a consensus
/// input must have exactly one byte spelling, so every constructor either
/// produces a reduced scalar ([`Self::from_pqc_public_key`],
/// [`Self::from_scalar`]) or refuses non-canonical bytes
/// ([`Self::from_canonical_bytes`], the `Deserialize` impl). The field is
/// private so no path can bypass that invariant.
///
/// The derivation forwards to
/// [`shekyl_crypto_pq::leaf_commitment::pqc_key_scalar`] (the single source;
/// customization [`shekyl_crypto_pq::leaf_commitment::DOMAIN_PQC_LEAF_KEY`]).
/// A duplicate body here would be a second copy to drift; there is none.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, Serialize)]
pub struct PqcKeyScalar([u8; 32]);

impl PqcKeyScalar {
    /// `k` for the canonical hybrid public key the spend reveals.
    #[must_use]
    pub fn from_pqc_public_key(pqc_pk_bytes: &[u8]) -> Self {
        PqcKeyScalar(shekyl_crypto_pq::leaf_commitment::pqc_key_scalar(
            pqc_pk_bytes,
        ))
    }

    /// `k` from its canonical 32-byte encoding; `None` if the bytes are not the
    /// canonical encoding of an Ed25519 scalar. This is the boundary
    /// constructor (FFI, deserialization): a non-canonical spelling is refused,
    /// never silently reduced to a second encoding of the same `k`.
    #[must_use]
    pub fn from_canonical_bytes(bytes: [u8; 32]) -> Option<Self> {
        use curve25519_dalek::scalar::Scalar;
        if bool::from(Scalar::from_canonical_bytes(bytes).is_some()) {
            Some(PqcKeyScalar(bytes))
        } else {
            None
        }
    }

    /// `k` from an already-reduced scalar (derivation-side construction). A
    /// `curve25519_dalek::Scalar` is reduced by construction, so its canonical
    /// encoding is total — this cannot fail.
    #[must_use]
    pub fn from_scalar(s: curve25519_dalek::Scalar) -> Self {
        PqcKeyScalar(s.to_bytes())
    }

    /// The canonical 32-byte encoding of `k`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The canonical 32-byte encoding of `k`, by value.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// The public point `K = k·G_k`, compressed — what the circuit's opening leg
    /// takes as its public value. Never on the wire. Forwards to
    /// [`shekyl_crypto_pq::leaf_commitment::pqc_key_point_from_scalar`].
    #[must_use]
    pub fn point(&self) -> [u8; 32] {
        use curve25519_dalek::scalar::Scalar;
        // The constructors guarantee canonical bytes, so this reduction is the
        // identity — it only converts the encoding back to a `Scalar`.
        let k = Scalar::from_bytes_mod_order(self.0);
        shekyl_crypto_pq::leaf_commitment::pqc_key_point_from_scalar(&k)
    }

    /// The public point `K = k·G_k` as the proof ciphersuite's group element —
    /// the form the verifier feeds the circuit's opening leg directly, with no
    /// compress/decompress round-trip. Multiplies over the generator's
    /// precomputed basepoint table.
    #[must_use]
    pub fn key_point(&self) -> dalek_ff_group::EdwardsPoint {
        use curve25519_dalek::scalar::Scalar;
        // Canonical by the constructors' invariant; reduction is the identity.
        let k = Scalar::from_bytes_mod_order(self.0);
        dalek_ff_group::EdwardsPoint(&*shekyl_curve_generators::PQC_LEAF_COMMITMENT_G_K_TABLE * &k)
    }
}

/// Refuse-don't-reduce at the serde boundary: the derived impl would have
/// admitted a non-canonical spelling into a type whose invariant is
/// canonicality, so the impl is manual and routes through
/// [`PqcKeyScalar::from_canonical_bytes`].
impl<'de> Deserialize<'de> for PqcKeyScalar {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        PqcKeyScalar::from_canonical_bytes(bytes).ok_or_else(|| {
            serde::de::Error::custom("PqcKeyScalar: bytes are not a canonical Ed25519 scalar")
        })
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
    pub cm_x: PqcLeafScalar,
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
        out[96..128].copy_from_slice(&self.cm_x.0);
        out
    }

    /// Deserialize a leaf from 128 bytes.
    pub fn from_bytes(bytes: &[u8; Self::SIZE]) -> Self {
        let mut o_x = [0u8; 32];
        let mut i_x = [0u8; 32];
        let mut c_x = [0u8; 32];
        let mut cm_x = [0u8; 32];
        o_x.copy_from_slice(&bytes[..32]);
        i_x.copy_from_slice(&bytes[32..64]);
        c_x.copy_from_slice(&bytes[64..96]);
        cm_x.copy_from_slice(&bytes[96..128]);
        ShekylLeaf {
            o_x,
            i_x,
            c_x,
            cm_x: PqcLeafScalar(cm_x),
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
                bool::from(Scalar::from_canonical_bytes(*s.as_bytes()).is_some()),
                "k must be a canonical Ed25519 scalar"
            );
            assert_ne!(*s.as_bytes(), [0u8; 32], "k must not be zero");
        }
    }
    /// The canonicality invariant is structural: the boundary constructor and
    /// the serde boundary refuse a non-canonical spelling rather than reducing
    /// it into a second encoding of the same `k`.
    #[test]
    fn pqc_key_scalar_refuses_non_canonical_bytes() {
        use curve25519_dalek::scalar::Scalar;

        // ℓ itself: the smallest non-canonical encoding (reduces to zero).
        let ell: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        for bad in [ell, [0xff; 32]] {
            assert!(
                PqcKeyScalar::from_canonical_bytes(bad).is_none(),
                "non-canonical bytes must be refused, not reduced"
            );
            let json = serde_json::to_string(&bad.to_vec()).unwrap();
            assert!(
                serde_json::from_str::<PqcKeyScalar>(&json).is_err(),
                "Deserialize must refuse non-canonical bytes"
            );
        }

        // Canonical bytes are accepted, byte-identically, on both boundaries;
        // zero is canonical (identity refusal is the circuit's, downstream).
        for good in [
            [0u8; 32],
            Scalar::from_bytes_mod_order([0xab; 32]).to_bytes(),
        ] {
            let s = PqcKeyScalar::from_canonical_bytes(good).expect("canonical bytes accepted");
            assert_eq!(*s.as_bytes(), good);
            let json = serde_json::to_string(&s).unwrap();
            let de: PqcKeyScalar = serde_json::from_str(&json).expect("canonical roundtrip");
            assert_eq!(de, s);
        }
    }
    #[test]
    fn pqc_key_scalar_from_scalar_is_canonical() {
        use curve25519_dalek::scalar::Scalar;
        let k = Scalar::from_bytes_mod_order([0x77; 32]);
        let s = PqcKeyScalar::from_scalar(k);
        assert_eq!(s.to_bytes(), k.to_bytes());
        assert_eq!(
            PqcKeyScalar::from_canonical_bytes(s.to_bytes()),
            Some(s),
            "from_scalar output is canonical by construction"
        );
    }
    #[test]
    fn pqc_key_point_is_k_times_g_k() {
        use curve25519_dalek::scalar::Scalar;
        let s = PqcKeyScalar::from_pqc_public_key(&[0xab; 1952]);
        let expected = *shekyl_curve_generators::PQC_LEAF_COMMITMENT_G_K
            * Scalar::from_bytes_mod_order(*s.as_bytes());
        assert_eq!(s.point(), expected.compress().to_bytes());
    }
    /// `K` has two derivation homes — the compressed form through
    /// `shekyl_crypto_pq::pqc_key_point_from_scalar` and the group-element form
    /// over the curve-generators basepoint table. One `k`, one `K`: drift
    /// between them would split the prover's and verifier's public input.
    #[test]
    fn key_point_agrees_with_compressed_point() {
        use ciphersuite::group::GroupEncoding;
        let s = PqcKeyScalar::from_pqc_public_key(&[0xab; 1952]);
        assert_eq!(s.key_point().to_bytes(), s.point());
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
            cm_x: PqcLeafScalar([4u8; 32]),
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
            cm_x: PqcLeafScalar([0xDD; 32]),
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
            cm_x: PqcLeafScalar([0u8; 32]),
        };
        let restored = ShekylLeaf::from_bytes(&leaf.to_bytes());
        assert_eq!(leaf, restored);
    }

    /// Admission (`pqc_leaf_point_valid`, the CEN-I19 content rule: canonical,
    /// prime-order, non-identity, via `curve25519-dalek`) and DB-add
    /// (`construct_leaf` → [`PqcLeafScalar::from_commitment_point`], via
    /// `dalek-ff-group`) decompress the published `CM` through two different
    /// code paths. Every encoding admission accepts must convert — otherwise
    /// a consensus-valid block aborts the node at DB add (CEN-L11 "unreachable")
    /// — so the implication is asserted over the boundary set: a real `CM`,
    /// the identity, every small-order point, a real point plus torsion, and
    /// the non-canonical encodings (`y ≥ p`, and `x = 0` with the sign bit).
    /// The converse is not required (DB-add is looser on torsion) and is
    /// pinned as such so a later tightening is a conscious change.
    #[test]
    fn admission_accepted_points_always_convert_at_db_add() {
        use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
        use curve25519_dalek::traits::Identity;
        use curve25519_dalek::{EdwardsPoint, Scalar};
        use shekyl_curve_generators::pqc_leaf_point_valid;

        let real = Scalar::from(7u64) * ED25519_BASEPOINT_POINT;
        let mut cases: Vec<([u8; 32], &'static str, bool)> = vec![
            (real.compress().to_bytes(), "real CM", true),
            (
                EdwardsPoint::identity().compress().to_bytes(),
                "identity",
                false,
            ),
        ];
        for t in &EIGHT_TORSION {
            cases.push((t.compress().to_bytes(), "small-order point", false));
        }
        cases.push((
            (real + EIGHT_TORSION[1]).compress().to_bytes(),
            "real point plus torsion",
            false,
        ));
        // y = p (2^255 - 19), sign bit clear and set: non-canonical encodings
        // of y = 0.
        let mut y_p = [0xffu8; 32];
        y_p[0] = 0xed;
        y_p[31] = 0x7f;
        cases.push((y_p, "y = p", false));
        let mut y_p_sign = y_p;
        y_p_sign[31] |= 0x80;
        cases.push((y_p_sign, "y = p with sign bit", false));
        // y = p + 1 (encodes y = 1, the identity, non-canonically).
        let mut y_p1 = y_p;
        y_p1[0] = 0xee;
        cases.push((y_p1, "y = p + 1", false));
        // y = 1 with the sign bit set: x = 0 cannot be negative.
        let mut one_neg = [0u8; 32];
        one_neg[0] = 1;
        one_neg[31] = 0x80;
        cases.push((one_neg, "y = 1 with sign bit (x = 0)", false));

        for (bytes, name, expect_admitted) in cases {
            let admitted = pqc_leaf_point_valid(&bytes).is_some();
            let converts = PqcLeafScalar::from_commitment_point(&bytes).is_some();
            assert_eq!(admitted, expect_admitted, "{name}: admission verdict");
            assert!(
                !admitted || converts,
                "{name}: admission accepts an encoding DB-add cannot convert (node abort)"
            );
        }
    }

    #[test]
    fn pqc_leaf_scalar_byte_roundtrip() {
        let original = PqcLeafScalar([0xab; 32]);
        let leaf = ShekylLeaf {
            o_x: [1u8; 32],
            i_x: [2u8; 32],
            c_x: [3u8; 32],
            cm_x: original,
        };
        let bytes = leaf.to_bytes();
        let restored = ShekylLeaf::from_bytes(&bytes);
        assert_eq!(restored.cm_x, original);
    }
}
