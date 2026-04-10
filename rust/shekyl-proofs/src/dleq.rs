// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Two-base Schnorr DLEQ proof for reserve proof key image binding.
//!
//! Proves `DL_{base1}(pub1) == DL_{base2}(pub2)`, i.e. the prover knows
//! scalar `x` such that `pub1 = x * base1` and `pub2 = x * base2`.
//!
//! Used by reserve proofs to prove `key_image = x * Hp(O)` where
//! `x = ho + b` and `x * G = O - y * T`.

#![deny(unsafe_code)]

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G,
    edwards::EdwardsPoint,
    scalar::Scalar,
};
use rand_core::OsRng;
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

const DOMAIN_SEPARATOR: &[u8] = b"shekyl-reserve-proof-dleq-v1";

/// A DLEQ proof: challenge `c` and response `s`, each 32 bytes.
#[derive(Clone)]
pub struct DleqProof {
    pub c: [u8; 32],
    pub s: [u8; 32],
}

impl DleqProof {
    pub const SIZE: usize = 64;

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.c);
        out[32..].copy_from_slice(&self.s);
        out
    }

    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let mut c = [0u8; 32];
        let mut s = [0u8; 32];
        c.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);
        DleqProof { c, s }
    }
}

/// Compute the Fiat-Shamir challenge for the DLEQ.
///
/// `c = H(domain || G || base2 || R1 || R2 || pub1 || pub2 || msg)`
///
/// Both bases are included to prevent cross-protocol attacks. `G` is
/// constant but included for consistency; `base2` (`Hp(O)`) varies per
/// output and its inclusion is mandatory.
fn challenge_hash(
    base2: &EdwardsPoint,
    r1: &EdwardsPoint,
    r2: &EdwardsPoint,
    pub1: &EdwardsPoint,
    pub2: &EdwardsPoint,
    msg: &[u8],
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_SEPARATOR);
    hasher.update(G.compress().as_bytes());
    hasher.update(base2.compress().as_bytes());
    hasher.update(r1.compress().as_bytes());
    hasher.update(r2.compress().as_bytes());
    hasher.update(pub1.compress().as_bytes());
    hasher.update(pub2.compress().as_bytes());
    hasher.update(msg);
    Scalar::from_hash(hasher)
}

/// Generate a DLEQ proof.
///
/// Proves knowledge of `x` such that `pub1 = x * G` and `pub2 = x * base2`.
///
/// # Arguments
/// - `x`: the secret scalar
/// - `base2`: the second base point (typically `Hp(O)`)
/// - `pub1`: `x * G` (the x-component of the output key)
/// - `pub2`: `x * base2` (the key image)
/// - `msg`: context bytes bound into the challenge
pub fn prove_dleq(
    x: &Scalar,
    base2: &EdwardsPoint,
    pub1: &EdwardsPoint,
    pub2: &EdwardsPoint,
    msg: &[u8],
) -> DleqProof {
    let mut k = Scalar::random(&mut OsRng);
    let r1 = k * G;
    let r2 = k * base2;

    let c = challenge_hash(base2, &r1, &r2, pub1, pub2, msg);
    let s = k - c * x;

    k.zeroize();

    DleqProof {
        c: c.to_bytes(),
        s: s.to_bytes(),
    }
}

/// Verify a DLEQ proof.
///
/// Checks that `DL_G(pub1) == DL_{base2}(pub2)`.
///
/// # Arguments
/// - `base2`: the second base point (typically `Hp(O)`)
/// - `pub1`: claimed `x * G`
/// - `pub2`: claimed `x * base2` (key image)
/// - `msg`: context bytes that were bound into the challenge
/// - `proof`: the `(c, s)` proof to verify
pub fn verify_dleq(
    base2: &EdwardsPoint,
    pub1: &EdwardsPoint,
    pub2: &EdwardsPoint,
    msg: &[u8],
    proof: &DleqProof,
) -> bool {
    let c: Scalar = match Option::from(Scalar::from_canonical_bytes(proof.c)) {
        Some(c) => c,
        None => return false,
    };
    let s: Scalar = match Option::from(Scalar::from_canonical_bytes(proof.s)) {
        Some(s) => s,
        None => return false,
    };

    let r1_check = s * G + c * pub1;
    let r2_check = s * base2 + c * pub2;

    let c_check = challenge_hash(base2, &r1_check, &r2_check, pub1, pub2, msg);

    c == c_check
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dleq_round_trip() {
        let x = Scalar::random(&mut OsRng);
        let base2 = Scalar::random(&mut OsRng) * G;
        let pub1 = x * G;
        let pub2 = x * base2;
        let msg = b"test-message";

        let proof = prove_dleq(&x, &base2, &pub1, &pub2, msg);
        assert!(
            verify_dleq(&base2, &pub1, &pub2, msg, &proof),
            "valid DLEQ proof must verify"
        );

        eprintln!("[dleq] round-trip: proof.c = {}", hex::encode(proof.c));
        eprintln!("[dleq] round-trip: proof.s = {}", hex::encode(proof.s));
    }

    #[test]
    fn dleq_wrong_secret_fails() {
        let x = Scalar::random(&mut OsRng);
        let x_wrong = Scalar::random(&mut OsRng);
        let base2 = Scalar::random(&mut OsRng) * G;
        let pub1 = x * G;
        let pub2 = x * base2;
        let msg = b"test-message";

        let bad_proof = prove_dleq(&x_wrong, &base2, &pub1, &pub2, msg);
        assert!(
            !verify_dleq(&base2, &pub1, &pub2, msg, &bad_proof),
            "DLEQ with wrong secret must fail"
        );
    }

    #[test]
    fn dleq_wrong_message_fails() {
        let x = Scalar::random(&mut OsRng);
        let base2 = Scalar::random(&mut OsRng) * G;
        let pub1 = x * G;
        let pub2 = x * base2;

        let proof = prove_dleq(&x, &base2, &pub1, &pub2, b"msg-a");
        assert!(
            !verify_dleq(&base2, &pub1, &pub2, b"msg-b", &proof),
            "DLEQ with different message must fail"
        );
    }

    #[test]
    fn dleq_mismatched_discrete_logs_fails() {
        let x = Scalar::random(&mut OsRng);
        let y = Scalar::random(&mut OsRng);
        let base2 = Scalar::random(&mut OsRng) * G;
        let pub1 = x * G;
        let pub2 = y * base2; // different DL
        let msg = b"test";

        let proof = prove_dleq(&x, &base2, &pub1, &pub2, msg);
        assert!(
            !verify_dleq(&base2, &pub1, &pub2, msg, &proof),
            "DLEQ with mismatched DLs must fail"
        );
    }

    #[test]
    fn dleq_serialization_round_trip() {
        let x = Scalar::random(&mut OsRng);
        let base2 = Scalar::random(&mut OsRng) * G;
        let pub1 = x * G;
        let pub2 = x * base2;
        let msg = b"ser-test";

        let proof = prove_dleq(&x, &base2, &pub1, &pub2, msg);
        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), DleqProof::SIZE);
        let proof2 = DleqProof::from_bytes(&bytes);

        assert!(
            verify_dleq(&base2, &pub1, &pub2, msg, &proof2),
            "deserialized DLEQ proof must still verify"
        );
    }

    #[test]
    fn dleq_flipped_bit_in_c_fails() {
        let x = Scalar::random(&mut OsRng);
        let base2 = Scalar::random(&mut OsRng) * G;
        let pub1 = x * G;
        let pub2 = x * base2;
        let msg = b"tamper-test";

        let proof = prove_dleq(&x, &base2, &pub1, &pub2, msg);
        let mut bytes = proof.to_bytes();
        bytes[0] ^= 1;
        let tampered = DleqProof::from_bytes(&bytes);

        assert!(
            !verify_dleq(&base2, &pub1, &pub2, msg, &tampered),
            "DLEQ with flipped bit in c must fail"
        );
    }
}
