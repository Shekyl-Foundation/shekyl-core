// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Per-output PQC keypair derivation.
//!
//! From a combined KEM shared secret (X25519 + ML-KEM-768) and an output
//! index, deterministically derive an ML-DSA-65 keypair. The public key
//! hash `H(pqc_pk)` becomes the 4th scalar in the FCMP++ curve tree leaf.
//!
//! ```text
//! combined_ss ─── HKDF-Expand("shekyl-pqc-output" || output_index_le64)
//!                   └── 32-byte seed → ML-DSA-65 deterministic keygen
//! ```

use blake2::{Blake2b512, Digest};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroize;

use fips204::ml_dsa_65;
use fips204::traits::SerDes as _;

use crate::CryptoError;

/// Domain separator for per-output PQC leaf hash.
pub const DOMAIN_PQC_LEAF: &[u8] = b"shekyl-pqc-leaf";

/// Domain separator for per-output PQC keypair derivation.
pub const DOMAIN_PQC_OUTPUT: &[u8] = b"shekyl-pqc-output";

/// Fixed HKDF salt for PQC key derivation, providing explicit domain separation
/// to prevent cross-protocol seed reuse if the same combined shared secret
/// appears in other contexts.
const HKDF_SALT_PQC_DERIVE: &[u8] = b"shekyl-pqc-derive-v1";

/// Size of the derivation seed extracted from HKDF for ML-DSA keygen.
const DERIVATION_SEED_LEN: usize = 32;

/// ML-DSA-65 public key length.
pub const ML_DSA_65_PK_LEN: usize = ml_dsa_65::PK_LEN;

/// ML-DSA-65 secret key length.
pub const ML_DSA_65_SK_LEN: usize = ml_dsa_65::SK_LEN;

/// A derived per-output ML-DSA-65 keypair.
pub struct DerivedPqcKeypair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl Drop for DerivedPqcKeypair {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

/// Derive a per-output ML-DSA-65 keypair from the combined KEM shared secret.
///
/// The derivation is deterministic: given the same `combined_ss` and
/// `output_index`, the same keypair is always produced. This enables
/// wallet restore-from-seed (the seed derives the KEM keys, KEM produces
/// the shared secret, and this function produces the per-output PQC keys).
///
/// Steps:
/// 1. Build info = DOMAIN_PQC_OUTPUT || output_index as LE u64
/// 2. HKDF-Expand(combined_ss, info) → 32-byte seed
/// 3. Use seed as deterministic RNG input for ML-DSA-65 keygen
pub fn derive_pqc_keypair(
    combined_ss: &[u8; 64],
    output_index: u64,
) -> Result<DerivedPqcKeypair, CryptoError> {
    let mut info = Vec::with_capacity(DOMAIN_PQC_OUTPUT.len() + 8);
    info.extend_from_slice(DOMAIN_PQC_OUTPUT);
    info.extend_from_slice(&output_index.to_le_bytes());

    let hk = Hkdf::<Sha512>::new(Some(HKDF_SALT_PQC_DERIVE), combined_ss);
    let mut seed = [0u8; DERIVATION_SEED_LEN];
    hk.expand(&info, &mut seed)
        .map_err(|_| CryptoError::KeyGenerationFailed("HKDF expand for PQC seed".into()))?;

    let (pk, sk) = keygen_from_seed(&seed)?;

    seed.zeroize();

    Ok(DerivedPqcKeypair {
        public_key: pk.into_bytes().to_vec(),
        secret_key: sk.into_bytes().to_vec(),
    })
}

/// Domain separator for Ed25519 component of per-output hybrid key.
const DOMAIN_PQC_ED25519: &[u8] = b"shekyl-pqc-ed25519";

/// Derive a per-output HYBRID (Ed25519 + ML-DSA-65) keypair in canonical
/// encoding, suitable for use with `shekyl_pqc_sign` / `HybridSecretKey`.
///
/// Internally derives both components from the same shared secret using
/// distinct HKDF info domains: `DOMAIN_PQC_OUTPUT` for ML-DSA-65 and
/// `DOMAIN_PQC_ED25519` for Ed25519.
pub fn derive_hybrid_pqc_keypair(
    combined_ss: &[u8; 64],
    output_index: u64,
) -> Result<DerivedPqcKeypair, CryptoError> {
    use crate::signature::{HybridPublicKey, HybridSecretKey};
    use ed25519_dalek::SigningKey;

    let hk = Hkdf::<Sha512>::new(Some(HKDF_SALT_PQC_DERIVE), combined_ss);

    // ML-DSA-65 derivation (same path as derive_pqc_keypair for leaf-hash compatibility)
    let mut ml_info = Vec::with_capacity(DOMAIN_PQC_OUTPUT.len() + 8);
    ml_info.extend_from_slice(DOMAIN_PQC_OUTPUT);
    ml_info.extend_from_slice(&output_index.to_le_bytes());
    let mut ml_seed = [0u8; DERIVATION_SEED_LEN];
    hk.expand(&ml_info, &mut ml_seed)
        .map_err(|_| CryptoError::KeyGenerationFailed("HKDF expand for ML-DSA seed".into()))?;
    let (ml_pk, ml_sk) = keygen_from_seed(&ml_seed)?;
    ml_seed.zeroize();

    // Ed25519 derivation (separate domain)
    let mut ed_info = Vec::with_capacity(DOMAIN_PQC_ED25519.len() + 8);
    ed_info.extend_from_slice(DOMAIN_PQC_ED25519);
    ed_info.extend_from_slice(&output_index.to_le_bytes());
    let mut ed_seed = [0u8; 32];
    hk.expand(&ed_info, &mut ed_seed)
        .map_err(|_| CryptoError::KeyGenerationFailed("HKDF expand for Ed25519 seed".into()))?;
    let ed_signing = SigningKey::from_bytes(&ed_seed);
    ed_seed.zeroize();
    let ed_verifying = ed_signing.verifying_key();

    let hybrid_pk = HybridPublicKey {
        ed25519: ed_verifying.to_bytes(),
        ml_dsa: ml_pk.into_bytes().to_vec(),
    };
    let hybrid_sk = HybridSecretKey {
        ed25519: ed_signing.to_bytes().to_vec(),
        ml_dsa: ml_sk.into_bytes().to_vec(),
    };

    let pk_bytes = hybrid_pk.to_canonical_bytes()
        .map_err(|e| CryptoError::KeyGenerationFailed(format!("hybrid PK encoding: {e}")))?;
    let sk_bytes = hybrid_sk.to_canonical_bytes()
        .map_err(|e| CryptoError::KeyGenerationFailed(format!("hybrid SK encoding: {e}")))?;

    Ok(DerivedPqcKeypair {
        public_key: pk_bytes,
        secret_key: sk_bytes,
    })
}

/// ML-DSA-65 keygen from a deterministic seed.
///
/// Expands the seed into the `(xi, rho')` inputs that ML-DSA expects,
/// then performs standard keygen. This matches FIPS 204 Algorithm 1
/// with deterministic randomness.
pub fn keygen_from_seed(
    seed: &[u8; 32],
) -> Result<(ml_dsa_65::PublicKey, ml_dsa_65::PrivateKey), CryptoError> {
    // fips204's try_keygen_with_rng expects a CryptoRng + RngCore.
    // Use ChaCha20Rng (explicit algorithm) so deterministic derivation remains
    // stable across rand crate upgrades. StdRng's algorithm is not guaranteed.
    use rand::SeedableRng;

    let mut rng = rand_chacha::ChaCha20Rng::from_seed(*seed);
    ml_dsa_65::try_keygen_with_rng(&mut rng)
        .map_err(|e| CryptoError::KeyGenerationFailed(format!("ML-DSA-65 keygen: {e}")))
}

/// Compute `H(pqc_pk)` — the PQC leaf scalar for the curve tree.
///
/// Uses domain-separated Blake2b-512, reduced to a canonical Selene base
/// field element via `HelioseleneField::wide_reduce` on the full 512-bit
/// hash output. This matches `PqcLeafScalar::from_pqc_public_key` exactly.
pub fn hash_pqc_public_key(pqc_pk_bytes: &[u8]) -> [u8; 32] {
    use ciphersuite::group::ff::PrimeField;
    use helioselene::HelioseleneField;

    let mut hasher = Blake2b512::new();
    hasher.update(DOMAIN_PQC_LEAF);
    hasher.update(pqc_pk_bytes);
    let hash_512 = hasher.finalize();

    let mut uniform = [0u8; 64];
    uniform.copy_from_slice(hash_512.as_ref());
    let field_elem = HelioseleneField::wide_reduce(uniform);
    uniform.zeroize();
    field_elem.to_repr()
}

// ── OutputSecrets: Unified HKDF derivation for two-component output keys ─────
//
// Canonical derivation for Shekyl V3. HKDF labels defined here are the single
// source of truth; they must match:
//   - tools/reference/derive_output_secrets.py (Python reference impl)
//   - docs/test_vectors/PQC_OUTPUT_SECRETS.json (locked vectors)
//   - docs/POST_QUANTUM_CRYPTOGRAPHY.md (label registry)

use curve25519_dalek::scalar::Scalar;

/// HKDF salt for the combined shared secret derivation (Instance 1).
const HKDF_SALT_OUTPUT_DERIVE: &[u8] = b"shekyl-output-derive-v1";

/// HKDF salt for X25519-only view tag derivation (Instance 2).
const HKDF_SALT_VIEW_TAG_X25519: &[u8] = b"shekyl-view-tag-x25519-v1";

const LABEL_OUTPUT_X: &[u8] = b"shekyl-output-x";
const LABEL_OUTPUT_Y: &[u8] = b"shekyl-output-y";
const LABEL_OUTPUT_MASK: &[u8] = b"shekyl-output-mask";
const LABEL_OUTPUT_AMOUNT_KEY: &[u8] = b"shekyl-output-amount-key";
const LABEL_OUTPUT_VIEW_TAG_COMBINED: &[u8] = b"shekyl-output-view-tag-combined";
const LABEL_OUTPUT_AMOUNT_TAG: &[u8] = b"shekyl-output-amount-tag";
const LABEL_OUTPUT_PQC: &[u8] = b"shekyl-pqc-output";
const LABEL_OUTPUT_PQC_ED25519: &[u8] = b"shekyl-pqc-ed25519";
const LABEL_VIEW_TAG_X25519: &[u8] = b"shekyl-view-tag-x25519";

/// All per-output secrets derived from a combined KEM shared secret.
///
/// Derivation:
/// ```text
/// combined_ss = X25519(eph_sk, view_pk) || ML-KEM-768.Decap(kem_sk, ct)
/// prk = HKDF-Extract(salt="shekyl-output-derive-v1", ikm=combined_ss)
///
/// ho              = wide_reduce(HKDF-Expand(prk, "shekyl-output-x"              || idx_le64, 64))
/// y               = wide_reduce(HKDF-Expand(prk, "shekyl-output-y"              || idx_le64, 64))
/// z               = wide_reduce(HKDF-Expand(prk, "shekyl-output-mask"           || idx_le64, 64))
/// k_amount        =             HKDF-Expand(prk, "shekyl-output-amount-key"     || idx_le64, 32)
/// view_tag_combined = first_byte(HKDF-Expand(prk, "shekyl-output-view-tag-combined" || idx_le64, 32))
/// amount_tag      = first_byte(HKDF-Expand(prk, "shekyl-output-amount-tag"     || idx_le64, 32))
/// ml_dsa_seed     =             HKDF-Expand(prk, "shekyl-pqc-output"           || idx_le64, 32)
/// ed25519_pqc_seed=             HKDF-Expand(prk, "shekyl-pqc-ed25519"          || idx_le64, 32)
/// ```
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct OutputSecrets {
    /// DL of O w.r.t. G minus spend key b: `O = (ho+b)*G + y*T`
    pub ho: [u8; 32],
    /// DL of O w.r.t. T: SAL spend secret
    pub y: [u8; 32],
    /// Pedersen commitment mask: `C = z*G + amount*H`
    pub z: [u8; 32],
    /// Amount encryption key (XOR with 8-byte amount)
    pub k_amount: [u8; 32],
    /// View tag from combined SS -- post-decap cross-check (not the wire tag)
    pub view_tag_combined: u8,
    /// 1-byte AAD checked at decode to detect KEM corruption
    pub amount_tag: u8,
    /// ML-DSA-65 deterministic keygen seed
    pub ml_dsa_seed: [u8; 32],
    /// Ed25519 PQC component seed (for hybrid signing)
    pub ed25519_pqc_seed: [u8; 32],
}

/// Derive all per-output secrets from the combined KEM shared secret.
///
/// `combined_ss` is the concatenation of X25519 and ML-KEM-768 shared secrets.
/// Any length is accepted (HKDF-Extract handles variable-length IKM), but the
/// expected production length is 64 bytes (32 X25519 + 32 ML-KEM).
pub fn derive_output_secrets(combined_ss: &[u8], output_index: u64) -> OutputSecrets {
    let hk = Hkdf::<Sha512>::new(Some(HKDF_SALT_OUTPUT_DERIVE), combined_ss);

    let ho = expand_to_scalar(&hk, LABEL_OUTPUT_X, output_index);
    let y = expand_to_scalar(&hk, LABEL_OUTPUT_Y, output_index);
    let z = expand_to_scalar(&hk, LABEL_OUTPUT_MASK, output_index);
    let k_amount = expand_32(&hk, LABEL_OUTPUT_AMOUNT_KEY, output_index);
    let view_tag_combined = expand_first_byte(&hk, LABEL_OUTPUT_VIEW_TAG_COMBINED, output_index);
    let amount_tag = expand_first_byte(&hk, LABEL_OUTPUT_AMOUNT_TAG, output_index);
    let ml_dsa_seed = expand_32(&hk, LABEL_OUTPUT_PQC, output_index);
    let ed25519_pqc_seed = expand_32(&hk, LABEL_OUTPUT_PQC_ED25519, output_index);

    assert!(ho != [0u8; 32], "HKDF produced zero ho scalar -- implementation bug");
    assert!(y != [0u8; 32], "HKDF produced zero y scalar -- implementation bug");

    OutputSecrets {
        ho,
        y,
        z,
        k_amount,
        view_tag_combined,
        amount_tag,
        ml_dsa_seed,
        ed25519_pqc_seed,
    }
}

/// Derive the X25519-only view tag for scanner pre-filtering.
///
/// This tag goes on the wire and lets the scanner reject non-matching outputs
/// without performing ML-KEM decapsulation. Uses a separate HKDF instance
/// with its own salt.
pub fn derive_view_tag_x25519(x25519_ss: &[u8; 32], output_index: u64) -> u8 {
    let hk = Hkdf::<Sha512>::new(Some(HKDF_SALT_VIEW_TAG_X25519), x25519_ss);
    expand_first_byte(&hk, LABEL_VIEW_TAG_X25519, output_index)
}

fn make_info(label: &[u8], output_index: u64) -> Vec<u8> {
    let mut info = Vec::with_capacity(label.len() + 8);
    info.extend_from_slice(label);
    info.extend_from_slice(&output_index.to_le_bytes());
    info
}

fn expand_to_scalar(hk: &Hkdf<Sha512>, label: &[u8], output_index: u64) -> [u8; 32] {
    let info = make_info(label, output_index);
    let mut wide = [0u8; 64];
    hk.expand(&info, &mut wide)
        .expect("HKDF-Expand failed for 64-byte output");
    let scalar = Scalar::from_bytes_mod_order_wide(&wide);
    wide.zeroize();
    scalar.to_bytes()
}

fn expand_32(hk: &Hkdf<Sha512>, label: &[u8], output_index: u64) -> [u8; 32] {
    let info = make_info(label, output_index);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out)
        .expect("HKDF-Expand failed for 32-byte output");
    out
}

fn expand_first_byte(hk: &Hkdf<Sha512>, label: &[u8], output_index: u64) -> u8 {
    let buf = expand_32(hk, label, output_index);
    buf[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_deterministic() {
        let ss = [0xab; 64];
        let kp1 = derive_pqc_keypair(&ss, 0).unwrap();
        let kp2 = derive_pqc_keypair(&ss, 0).unwrap();
        assert_eq!(kp1.public_key, kp2.public_key);
        assert_eq!(kp1.secret_key, kp2.secret_key);
    }

    #[test]
    fn different_indices_different_keys() {
        let ss = [0xab; 64];
        let kp0 = derive_pqc_keypair(&ss, 0).unwrap();
        let kp1 = derive_pqc_keypair(&ss, 1).unwrap();
        assert_ne!(kp0.public_key, kp1.public_key);
    }

    #[test]
    fn different_secrets_different_keys() {
        let ss1 = [0xab; 64];
        let ss2 = [0xcd; 64];
        let kp1 = derive_pqc_keypair(&ss1, 0).unwrap();
        let kp2 = derive_pqc_keypair(&ss2, 0).unwrap();
        assert_ne!(kp1.public_key, kp2.public_key);
    }

    #[test]
    fn derived_key_sizes() {
        let ss = [0xab; 64];
        let kp = derive_pqc_keypair(&ss, 0).unwrap();
        assert_eq!(kp.public_key.len(), ML_DSA_65_PK_LEN);
        assert_eq!(kp.secret_key.len(), ML_DSA_65_SK_LEN);
    }

    #[test]
    fn derived_key_signs_and_verifies() {
        use fips204::traits::{Signer as _, Verifier as _};

        let ss = [0xab; 64];
        let kp = derive_pqc_keypair(&ss, 42).unwrap();

        let sk_bytes: [u8; ML_DSA_65_SK_LEN] = kp.secret_key.as_slice().try_into().unwrap();
        let pk_bytes: [u8; ML_DSA_65_PK_LEN] = kp.public_key.as_slice().try_into().unwrap();

        let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_bytes).unwrap();
        let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_bytes).unwrap();

        let msg = b"shekyl per-output pqc test";
        let sig = sk.try_sign(msg, &[]).unwrap();
        assert!(pk.verify(msg, &sig, &[]));
    }

    #[test]
    fn hash_pqc_pk_deterministic() {
        let pk = vec![0xab; ML_DSA_65_PK_LEN];
        let h1 = hash_pqc_public_key(&pk);
        let h2 = hash_pqc_public_key(&pk);
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_pqc_pk_canonical_field_element() {
        use ciphersuite::group::ff::PrimeField;
        use helioselene::HelioseleneField;

        let pk = vec![0xff; ML_DSA_65_PK_LEN];
        let h = hash_pqc_public_key(&pk);
        assert!(bool::from(HelioseleneField::from_repr(h).is_some()),
            "hash must produce a canonical Selene base field element");
    }

    #[test]
    fn derivation_sequential_indices_all_unique() {
        let ss = [0xab; 64];
        let mut seen_pks = std::collections::HashSet::new();
        for i in 0..10u64 {
            let kp = derive_pqc_keypair(&ss, i).unwrap();
            assert!(seen_pks.insert(kp.public_key.clone()), "index {i} produced duplicate key");
        }
    }

    #[test]
    fn derivation_large_index() {
        let ss = [0xab; 64];
        let kp = derive_pqc_keypair(&ss, u64::MAX).unwrap();
        assert_eq!(kp.public_key.len(), ML_DSA_65_PK_LEN);
    }

    #[test]
    fn hash_pqc_pk_different_lengths() {
        let short = hash_pqc_public_key(&[0xab; 32]);
        let long = hash_pqc_public_key(&[0xab; ML_DSA_65_PK_LEN]);
        assert_ne!(short, long);
    }

    #[test]
    fn hash_pqc_pk_empty_input() {
        use ciphersuite::group::ff::PrimeField;
        use helioselene::HelioseleneField;

        let h = hash_pqc_public_key(&[]);
        assert!(bool::from(HelioseleneField::from_repr(h).is_some()));
        assert_ne!(h, [0u8; 32]);
    }

    #[test]
    fn derived_keypair_sign_verify_consistency() {
        use fips204::traits::{Signer as _, Verifier as _};

        let ss = [0xcd; 64];
        for idx in [0u64, 1, 100, u64::MAX - 1] {
            let kp = derive_pqc_keypair(&ss, idx).unwrap();

            let sk_bytes: [u8; ML_DSA_65_SK_LEN] = kp.secret_key.as_slice().try_into().unwrap();
            let pk_bytes: [u8; ML_DSA_65_PK_LEN] = kp.public_key.as_slice().try_into().unwrap();
            let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_bytes).unwrap();
            let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_bytes).unwrap();

            let msg = format!("test message for output index {idx}");
            let sig = sk.try_sign(msg.as_bytes(), &[]).unwrap();
            assert!(pk.verify(msg.as_bytes(), &sig, &[]),
                "sign/verify failed for index {idx}");
        }
    }

    #[test]
    fn hash_matches_leaf_scalar() {
        use shekyl_fcmp::leaf::PqcLeafScalar;

        let ss = [0xab; 64];
        let kp = derive_pqc_keypair(&ss, 0).unwrap();
        let h = hash_pqc_public_key(&kp.public_key);
        let leaf_scalar = PqcLeafScalar::from_pqc_public_key(&kp.public_key);
        assert_eq!(h, leaf_scalar.0,
            "hash_pqc_public_key and PqcLeafScalar::from_pqc_public_key must agree");
    }

    #[test]
    fn hybrid_derivation_deterministic() {
        let ss = [0xab; 64];
        let kp1 = derive_hybrid_pqc_keypair(&ss, 0).unwrap();
        let kp2 = derive_hybrid_pqc_keypair(&ss, 0).unwrap();
        assert_eq!(kp1.public_key, kp2.public_key);
        assert_eq!(kp1.secret_key, kp2.secret_key);
    }

    #[test]
    fn hybrid_derivation_different_indices() {
        let ss = [0xab; 64];
        let kp0 = derive_hybrid_pqc_keypair(&ss, 0).unwrap();
        let kp1 = derive_hybrid_pqc_keypair(&ss, 1).unwrap();
        assert_ne!(kp0.public_key, kp1.public_key);
    }

    #[test]
    fn hybrid_keys_are_canonical() {
        use crate::signature::{HybridPublicKey, HybridSecretKey};

        let ss = [0xab; 64];
        let kp = derive_hybrid_pqc_keypair(&ss, 0).unwrap();
        HybridPublicKey::from_canonical_bytes(&kp.public_key)
            .expect("hybrid pk must be canonical");
        HybridSecretKey::from_canonical_bytes(&kp.secret_key)
            .expect("hybrid sk must be canonical");
    }

    #[test]
    fn hybrid_sign_and_verify() {
        use crate::signature::{HybridEd25519MlDsa, HybridSecretKey, HybridPublicKey, SignatureScheme};

        let ss = [0xab; 64];
        let kp = derive_hybrid_pqc_keypair(&ss, 42).unwrap();

        let sk = HybridSecretKey::from_canonical_bytes(&kp.secret_key).unwrap();
        let pk = HybridPublicKey::from_canonical_bytes(&kp.public_key).unwrap();
        let scheme = HybridEd25519MlDsa;

        let msg = b"hybrid pqc signing test";
        let sig = scheme.sign(&sk, msg).unwrap();
        assert!(scheme.verify(&pk, msg, &sig).unwrap());
    }

    #[test]
    fn hybrid_leaf_hash_consistent_with_ffi() {
        use shekyl_fcmp::leaf::PqcLeafScalar;

        let ss = [0xab; 64];
        let kp = derive_hybrid_pqc_keypair(&ss, 0).unwrap();
        let h = hash_pqc_public_key(&kp.public_key);
        let leaf_scalar = PqcLeafScalar::from_pqc_public_key(&kp.public_key);
        assert_eq!(h, leaf_scalar.0,
            "leaf hash must agree for canonical hybrid pk");
    }

    // ── OutputSecrets known-answer tests against locked vectors ──────────

    #[derive(serde::Deserialize)]
    struct TestVector {
        combined_ss: String,
        output_index: u64,
        ho: String,
        y: String,
        z: String,
        k_amount: String,
        view_tag_combined: u8,
        amount_tag: u8,
        ml_dsa_seed: String,
        x25519_ss: String,
        view_tag_x25519: u8,
    }

    #[derive(serde::Deserialize)]
    struct TestVectorFile {
        vectors: Vec<TestVector>,
    }

    fn load_test_vectors() -> Vec<TestVector> {
        let json = include_str!("../../../docs/test_vectors/PQC_OUTPUT_SECRETS.json");
        let file: TestVectorFile = serde_json::from_str(json)
            .expect("failed to parse PQC_OUTPUT_SECRETS.json");
        file.vectors
    }

    #[test]
    fn output_secrets_known_answer_vectors() {
        let vectors = load_test_vectors();
        assert!(vectors.len() >= 16, "expected at least 16 test vectors");

        for (i, v) in vectors.iter().enumerate() {
            let css = hex::decode(&v.combined_ss).unwrap();
            let secrets = derive_output_secrets(&css, v.output_index);

            let expected_ho = hex::decode(&v.ho).unwrap();
            let expected_y = hex::decode(&v.y).unwrap();
            let expected_z = hex::decode(&v.z).unwrap();
            let expected_k = hex::decode(&v.k_amount).unwrap();
            let expected_seed = hex::decode(&v.ml_dsa_seed).unwrap();

            assert_eq!(secrets.ho.as_slice(), expected_ho.as_slice(),
                "vector {i}: ho mismatch");
            assert_eq!(secrets.y.as_slice(), expected_y.as_slice(),
                "vector {i}: y mismatch");
            assert_eq!(secrets.z.as_slice(), expected_z.as_slice(),
                "vector {i}: z mismatch");
            assert_eq!(secrets.k_amount.as_slice(), expected_k.as_slice(),
                "vector {i}: k_amount mismatch");
            assert_eq!(secrets.view_tag_combined, v.view_tag_combined,
                "vector {i}: view_tag_combined mismatch");
            assert_eq!(secrets.amount_tag, v.amount_tag,
                "vector {i}: amount_tag mismatch");
            assert_eq!(secrets.ml_dsa_seed.as_slice(), expected_seed.as_slice(),
                "vector {i}: ml_dsa_seed mismatch");
        }
    }

    #[test]
    fn view_tag_x25519_known_answer_vectors() {
        let vectors = load_test_vectors();
        for (i, v) in vectors.iter().enumerate() {
            let x_ss_bytes = hex::decode(&v.x25519_ss).unwrap();
            let x_ss: [u8; 32] = x_ss_bytes.as_slice().try_into().unwrap();
            let tag = derive_view_tag_x25519(&x_ss, v.output_index);
            assert_eq!(tag, v.view_tag_x25519,
                "vector {i}: view_tag_x25519 mismatch");
        }
    }

    #[test]
    fn output_secrets_deterministic() {
        let css = [0xab; 64];
        let s1 = derive_output_secrets(&css, 0);
        let s2 = derive_output_secrets(&css, 0);
        assert_eq!(s1.ho, s2.ho);
        assert_eq!(s1.y, s2.y);
        assert_eq!(s1.z, s2.z);
        assert_eq!(s1.k_amount, s2.k_amount);
        assert_eq!(s1.view_tag_combined, s2.view_tag_combined);
        assert_eq!(s1.amount_tag, s2.amount_tag);
        assert_eq!(s1.ml_dsa_seed, s2.ml_dsa_seed);
        assert_eq!(s1.ed25519_pqc_seed, s2.ed25519_pqc_seed);
    }

    #[test]
    fn output_secrets_index_uniqueness() {
        let css = [0xab; 64];
        let s0 = derive_output_secrets(&css, 0);
        let s1 = derive_output_secrets(&css, 1);
        assert_ne!(s0.ho, s1.ho);
        assert_ne!(s0.y, s1.y);
        assert_ne!(s0.z, s1.z);
        assert_ne!(s0.k_amount, s1.k_amount);
        assert_ne!(s0.ml_dsa_seed, s1.ml_dsa_seed);
    }

    #[test]
    fn output_secrets_scalars_valid() {
        let css = [0xcd; 64];
        let l_bytes_le: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        ];
        for idx in [0u64, 1, 42, u64::MAX] {
            let s = derive_output_secrets(&css, idx);
            for (name, scalar_bytes) in [("ho", s.ho), ("y", s.y), ("z", s.z)] {
                assert!(le_bytes_lt(&scalar_bytes, &l_bytes_le),
                    "index {idx}: {name} is not < l");
            }
        }
    }

    #[test]
    fn output_secrets_label_independence() {
        let css = [0xef; 64];
        let s = derive_output_secrets(&css, 0);
        assert_ne!(s.ho, s.y, "ho and y should differ (different labels)");
        assert_ne!(s.y, s.z, "y and z should differ (different labels)");
        assert_ne!(s.ho, s.z, "ho and z should differ (different labels)");
        assert_ne!(s.k_amount, s.ml_dsa_seed, "k_amount and ml_dsa_seed differ");
    }

    fn le_bytes_lt(a: &[u8; 32], b: &[u8; 32]) -> bool {
        for i in (0..32).rev() {
            if a[i] < b[i] { return true; }
            if a[i] > b[i] { return false; }
        }
        false // equal
    }

    // ── Phase 0 domain-trap test ─────────────────────────────────────────
    //
    // This test intentionally asserts that the HKDF-derived y scalar
    // (from derive_output_secrets) and the Keccak-derived y scalar
    // (from the C++ derivation_to_y_scalar path) DISAGREE for the same
    // input material.
    //
    // If someone "fixes" this test by making the two derivations agree,
    // they have silently reintroduced the Keccak domain into the HKDF
    // world and the FCMP++ prover will start accepting the wrong y.
    // Do not "fix".

    /// Simulate the C++ `derivation_to_y_scalar(derivation, output_index)`
    /// path: Keccak-256("shekyl_y" || derivation_32 || varint(idx)) → sc_reduce32.
    fn simulate_keccak_derivation_to_y_scalar(
        derivation: &[u8; 32],
        output_index: u64,
    ) -> [u8; 32] {
        use sha3::{Keccak256, digest::Digest};

        let mut buf = Vec::with_capacity(8 + 32 + 10);
        buf.extend_from_slice(b"shekyl_y");
        buf.extend_from_slice(derivation);
        // Monero varint encoding
        let mut idx = output_index;
        loop {
            let byte = (idx & 0x7F) as u8;
            idx >>= 7;
            if idx == 0 {
                buf.push(byte);
                break;
            } else {
                buf.push(byte | 0x80);
            }
        }

        let hash: [u8; 32] = Keccak256::digest(&buf).into();
        // sc_reduce32: interpret as little-endian integer, reduce mod l
        Scalar::from_bytes_mod_order(hash).to_bytes()
    }

    #[test]
    fn hkdf_y_must_not_equal_keccak_derivation_to_y_scalar() {
        // Phase 0 domain-trap guard: HKDF y and Keccak y must disagree.
        //
        // The C++ wallet's legacy path computes y via:
        //   derivation_to_y_scalar(key_derivation, output_index)
        //     = sc_reduce32(Keccak256("shekyl_y" || derivation || varint(idx)))
        //
        // The canonical HKDF path computes y via:
        //   derive_output_secrets(combined_ss, output_index).y
        //     = wide_reduce(HKDF-Expand(HKDF-Extract(salt_B, combined_ss),
        //                               "shekyl-output-y" || idx_le64, 64))
        //
        // These MUST produce different values. If they ever agree, someone
        // has aliased the Keccak domain into the HKDF world (or vice versa)
        // and the FCMP++ prover will silently accept the wrong y scalar.
        // DO NOT "FIX" A FAILURE HERE — investigate the domain separation.

        let test_inputs: &[(&[u8; 64], u64)] = &[
            (&[0x00; 64], 0),
            (&[0x00; 64], 1),
            (&[0xFF; 64], 0),
            (&[0xAB; 64], 42),
        ];

        for (combined_ss, idx) in test_inputs {
            let hkdf_y = derive_output_secrets(*combined_ss, *idx).y;

            // Use the first 32 bytes as a simulated key_derivation
            let derivation: [u8; 32] = (*combined_ss)[..32].try_into().unwrap();
            let keccak_y = simulate_keccak_derivation_to_y_scalar(&derivation, *idx);

            assert_ne!(
                hkdf_y, keccak_y,
                "DOMAIN TRAP FAILURE: HKDF y == Keccak y for combined_ss[..8]={:02x}{:02x}..., idx={}. \
                 The two derivations use different hash functions (HKDF-SHA512 vs Keccak-256) \
                 and different domains. If this assertion fires, someone has silently \
                 reintroduced the Keccak domain into the HKDF world. Do not suppress.",
                combined_ss[0], combined_ss[1], idx
            );
        }
    }
}
