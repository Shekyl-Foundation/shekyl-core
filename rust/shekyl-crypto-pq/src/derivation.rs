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

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::traits::Identity;
use hkdf::Hkdf;
use sha2::Sha512;
use shekyl_crypto_hash::{cshake256_32, cshake256_64};
use shekyl_curve_generators::{PQC_LEAF_COMMITMENT_G_K, PQC_LEAF_COMMITMENT_J};
use zeroize::Zeroize;

use fips204::ml_dsa_65;

use crate::CryptoError;

/// cSHAKE256 customization for the per-output PQC **key scalar**
/// `k = H_ℓ(hybrid_pk)` (`PL-D3`, `docs/design/FCMP_SPEND_LINKABILITY.md` §6.2).
///
/// This crate is the **single source** for `k`: [`pqc_key_scalar`] is what the
/// sender, the scanner, the FCMP++ verifiers (through `shekyl_fcmp::PqcKeyScalar`)
/// and the emission backing gate all call. cSHAKE carries the domain in its
/// construction and the domain registry count-pins every call site, which is why
/// the leaf path moved off the prefixed Blake2b of `shekyl-pqc-leaf` (retired).
pub const DOMAIN_PQC_LEAF_KEY: &[u8] = b"shekyl/pqc-leaf-key-v1";

/// cSHAKE256 customization for the per-output post-quantum **record**
/// `cSHAKE256(pk ‖ r_h)` published beside the commitment point in `tx_extra`
/// `0x07` (`PL-D3a`). Commits to the canonical key bytes, not to `k`, so it
/// survives into a lattice-only world without Ed25519 arithmetic to define it.
pub const DOMAIN_PQC_LEAF_RECORD: &[u8] = b"shekyl/pqc-leaf-record-v1";

/// Width of one output's `0x07` entry: the compressed commitment point `CM`
/// followed by the 32-byte record (`PL-D3` + `PL-D3a`).
pub const PQC_LEAF_ENTRY_LEN: usize = 64;

/// ML-DSA-65 public key length.
pub const ML_DSA_65_PK_LEN: usize = ml_dsa_65::PK_LEN;

/// ML-DSA-65 secret key length.
pub const ML_DSA_65_SK_LEN: usize = ml_dsa_65::SK_LEN;

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

/// The per-output PQC key scalar `k = H_ℓ(hybrid_pk)`: a 64-byte cSHAKE256 read
/// of the canonical hybrid public key under [`DOMAIN_PQC_LEAF_KEY`], reduced into
/// the **Ed25519 scalar field** (`PL-D3`). The leaf's 4th scalar is the
/// x-coordinate of `CM = k·G_k + r·J`; the verifier recomputes `K = k·G_k` from
/// the key the spend reveals and the circuit proves `K + r·J = CM`.
///
/// This is the single source for `k`; `shekyl_fcmp::PqcKeyScalar` wraps it.
pub fn pqc_key_scalar(pqc_pk_bytes: &[u8]) -> [u8; 32] {
    let mut wide = cshake256_64(DOMAIN_PQC_LEAF_KEY, pqc_pk_bytes);
    let scalar = Scalar::from_bytes_mod_order_wide(&wide);
    wide.zeroize();
    scalar.to_bytes()
}

/// The verifier-side public point `K = k·G_k` for a revealed hybrid public key,
/// compressed. Never on the wire: derived from `pqc_auths[i].hybrid_public_key`
/// by every verifier, exactly as the old leaf hash was (`PL-D3`).
pub fn pqc_key_point(pqc_pk_bytes: &[u8]) -> [u8; 32] {
    let k = Scalar::from_bytes_mod_order(pqc_key_scalar(pqc_pk_bytes));
    (*PQC_LEAF_COMMITMENT_G_K * k).compress().to_bytes()
}

/// The post-quantum record `cSHAKE256(pk ‖ r_h)` published beside `CM` in
/// `tx_extra` `0x07` (`PL-D3a`). Checked by nothing live; Keccak-chained into the
/// block; what a transparent claim (`PL-D5`) opens with `(pk, r_h)`.
pub fn pqc_leaf_record(pqc_pk_bytes: &[u8], record_blind: &[u8; 32]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(pqc_pk_bytes.len() + 32);
    preimage.extend_from_slice(pqc_pk_bytes);
    preimage.extend_from_slice(record_blind);
    let out = cshake256_32(DOMAIN_PQC_LEAF_RECORD, &preimage);
    preimage.zeroize();
    out
}

/// The sender's / owner's opening of one output's PQC leaf commitment.
#[derive(Clone, Zeroize, zeroize::ZeroizeOnDrop)]
pub struct PqcLeafCommitment {
    /// `CM = k·G_k + r·J`, compressed Ed25519 (the first 32 bytes of the `0x07`
    /// entry; its Wei25519 x-coordinate is the leaf's 4th scalar).
    #[zeroize(skip)]
    pub point: [u8; 32],
    /// The record `cSHAKE256(pk ‖ r_h)` (the second 32 bytes of the `0x07` entry).
    #[zeroize(skip)]
    pub record: [u8; 32],
    /// The blind `r` (Ed25519 scalar) — the prover's in-circuit witness. Secret.
    pub blind: [u8; 32],
    /// The record blind `r_h`. Secret; opens the record at a transparent claim.
    pub record_blind: [u8; 32],
    /// The re-derivation counter the exceptional-value guard settled on
    /// (`0` in all but a ~2⁻²⁵² fraction of outputs).
    #[zeroize(skip)]
    pub counter: u8,
}

impl PqcLeafCommitment {
    /// The 64-byte `0x07` entry for this output: `point ‖ record`.
    #[must_use]
    pub fn entry(&self) -> [u8; PQC_LEAF_ENTRY_LEN] {
        let mut e = [0u8; PQC_LEAF_ENTRY_LEN];
        e[..32].copy_from_slice(&self.point);
        e[32..].copy_from_slice(&self.record);
        e
    }
}

/// Failure of [`pqc_leaf_commitment`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqcLeafCommitmentError {
    /// 256 counter values all produced an exceptional blind — impossible in
    /// practice (each rejection is a ~2⁻²⁵² event); returned rather than looped
    /// so the guard is a rule with a visible failure, not an assumption.
    GuardExhausted,
}

/// Derive the blind `r` for one output under the guard counter `ctr`
/// (`HKDF-Expand(prk, "shekyl-pqc-leaf-blind" ‖ idx_le64 ‖ ctr, 64) mod ℓ`).
fn derive_pqc_leaf_blind(combined_ss: &[u8], output_index: u64, ctr: u8) -> [u8; 32] {
    let hk = Hkdf::<Sha512>::new(Some(HKDF_SALT_OUTPUT_DERIVE), combined_ss);
    let mut info = make_info(LABEL_OUTPUT_PQC_LEAF_BLIND, output_index);
    info.push(ctr);
    let mut wide = [0u8; 64];
    hk.expand(&info, &mut wide)
        .expect("HKDF-Expand failed for 64-byte output");
    let scalar = Scalar::from_bytes_mod_order_wide(&wide);
    wide.zeroize();
    scalar.to_bytes()
}

/// Build the output's PQC leaf commitment and record from the owner's
/// `combined_ss` and the output's canonical hybrid public key (`PL-D3`, `PL-D3a`).
///
/// **Exceptional-value guard** (round doc §6.2): `r = 0` would make `CM = k·G_k`,
/// a deterministic function of the key — the very leak `PL-D1` names — and the
/// circuit's incomplete addition rejects an identity operand or equal/opposite
/// operands. Each is rejected here and the blind re-derived under the next
/// counter; the recipient reproduces the same walk at scan, so no counter is
/// carried on the wire.
pub fn pqc_leaf_commitment(
    combined_ss: &[u8],
    output_index: u64,
    pqc_pk_bytes: &[u8],
) -> Result<PqcLeafCommitment, PqcLeafCommitmentError> {
    let k = Scalar::from_bytes_mod_order(pqc_key_scalar(pqc_pk_bytes));
    let big_k = *PQC_LEAF_COMMITMENT_G_K * k;
    let hk = Hkdf::<Sha512>::new(Some(HKDF_SALT_OUTPUT_DERIVE), combined_ss);
    let record_blind = expand_32(&hk, LABEL_OUTPUT_PQC_LEAF_RECORD_BLIND, output_index);
    for ctr in 0u8..=u8::MAX {
        let blind_bytes = derive_pqc_leaf_blind(combined_ss, output_index, ctr);
        let r = Scalar::from_bytes_mod_order(blind_bytes);
        if r == Scalar::ZERO {
            continue;
        }
        let r_j = *PQC_LEAF_COMMITMENT_J * r;
        let cm = big_k + r_j;
        let exceptional = big_k == EdwardsPoint::identity()
            || r_j == EdwardsPoint::identity()
            || cm == EdwardsPoint::identity()
            || big_k == r_j
            || big_k == -r_j;
        if exceptional {
            continue;
        }
        return Ok(PqcLeafCommitment {
            point: cm.compress().to_bytes(),
            record: pqc_leaf_record(pqc_pk_bytes, &record_blind),
            blind: blind_bytes,
            record_blind,
            counter: ctr,
        });
    }
    Err(PqcLeafCommitmentError::GuardExhausted)
}

pub use shekyl_curve_generators::pqc_leaf_point_valid;

/// Derive the output's PQC leaf commitment (`CM ‖ record`, blinds, counter) from
/// the owner's combined shared secret and output index, without returning any
/// signing key material (`PL-D3`).
///
/// Internally derives the full hybrid keypair via `derive_output_secrets` +
/// `keygen_from_seed`, encodes the public key canonically, and zeroizes the
/// secret key on drop.
pub fn derive_pqc_leaf(
    combined_ss: &[u8; 64],
    output_index: u64,
) -> Result<PqcLeafCommitment, CryptoError> {
    let pk_bytes = derive_pqc_public_key(combined_ss, output_index)?;
    pqc_leaf_commitment(combined_ss, output_index, &pk_bytes)
        .map_err(|e| CryptoError::KeyGenerationFailed(format!("PQC leaf commitment guard: {e:?}")))
}

/// Derive the canonical hybrid public key bytes from combined shared secret and
/// output index, without returning any secret key material.
///
/// Used where the full public key (not just its hash) is needed before signing,
/// e.g. populating `tx.pqc_auths[i].hybrid_public_key` for payload construction.
pub fn derive_pqc_public_key(
    combined_ss: &[u8; 64],
    output_index: u64,
) -> Result<Vec<u8>, CryptoError> {
    use crate::signature::HybridPublicKey;
    use ed25519_dalek::SigningKey;

    let secrets = derive_output_secrets(combined_ss, output_index);
    let (ml_pk, _ml_sk) = keygen_from_seed(&secrets.ml_dsa_seed)?;

    let ed_signing = SigningKey::from_bytes(&secrets.ed25519_pqc_seed);
    let ed_verifying = ed_signing.verifying_key();

    let hybrid_pk = HybridPublicKey {
        ed25519: ed_verifying.to_bytes(),
        ml_dsa: {
            use fips204::traits::SerDes;
            ml_pk.into_bytes().to_vec()
        },
    };

    hybrid_pk
        .to_canonical_bytes()
        .map_err(|e| CryptoError::KeyGenerationFailed(format!("hybrid PK encoding: {e}")))
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

/// HKDF salt for ML-KEM-keyed view-tag pre-filter (Instance 2).
const HKDF_SALT_VIEW_TAG_PREFILTER: &[u8] = b"shekyl-view-tag-prefilter-v1";

/// HKDF salt for deterministic KEM seed derivation from tx_key (Instance 3).
///
/// Used by `construct_output` (sender-side deterministic encapsulation) and
/// `rederive_combined_ss` (proof verification re-derivation).
pub const SALT_KEM_DERIVE_V1: &[u8] = b"shekyl-output-kem-v1";

const _: () = assert!(SALT_KEM_DERIVE_V1.len() == 20);

const LABEL_OUTPUT_X: &[u8] = b"shekyl-output-x";
const LABEL_OUTPUT_Y: &[u8] = b"shekyl-output-y";
const LABEL_OUTPUT_MASK: &[u8] = b"shekyl-output-mask";
const LABEL_OUTPUT_AMOUNT_KEY: &[u8] = b"shekyl-output-amount-key";
const LABEL_OUTPUT_VIEW_TAG_COMBINED: &[u8] = b"shekyl-output-view-tag-combined";
const LABEL_OUTPUT_AMOUNT_TAG: &[u8] = b"shekyl-output-amount-tag";
const LABEL_OUTPUT_LABEL_KEY: &[u8] = b"shekyl-output-label-key";
const LABEL_OUTPUT_LABEL_TAG: &[u8] = b"shekyl-output-label-tag";
const LABEL_OUTPUT_PQC: &[u8] = b"shekyl-pqc-output";
const LABEL_OUTPUT_PQC_ED25519: &[u8] = b"shekyl-pqc-ed25519";
/// HKDF info label for the PQC leaf-commitment blind `r` (`PL-D3`); the info is
/// `label ‖ idx_le64 ‖ ctr` with the one-byte guard counter appended.
const LABEL_OUTPUT_PQC_LEAF_BLIND: &[u8] = b"shekyl-pqc-leaf-blind";
/// HKDF info label for the post-quantum record blind `r_h` (`PL-D3a`).
const LABEL_OUTPUT_PQC_LEAF_RECORD_BLIND: &[u8] = b"shekyl-pqc-leaf-record-blind";
const LABEL_VIEW_TAG_PREFILTER: &[u8] = b"shekyl-view-tag-prefilter";

/// All per-output secrets derived from a combined KEM shared secret.
///
/// Derivation:
/// ```text
/// combined_ss = HKDF-SHA-512(salt="shekyl-kem-v1", ikm=x25519_ss||ml_kem_ss, info="", L=64)
///   (see [`crate::kem::combine_shared_secrets`]; not raw concatenation)
/// prk = HKDF-Extract(salt="shekyl-output-derive-v1", ikm=combined_ss)
///
/// ho              = wide_reduce(HKDF-Expand(prk, "shekyl-output-x"              || idx_le64, 64))
/// y               = wide_reduce(HKDF-Expand(prk, "shekyl-output-y"              || idx_le64, 64))
/// z               = wide_reduce(HKDF-Expand(prk, "shekyl-output-mask"           || idx_le64, 64))
/// k_amount        =             HKDF-Expand(prk, "shekyl-output-amount-key"     || idx_le64, 32)
/// view_tag_combined = first_byte(HKDF-Expand(prk, "shekyl-output-view-tag-combined" || idx_le64, 32))
/// amount_tag      = first_byte(HKDF-Expand(prk, "shekyl-output-amount-tag"     || idx_le64, 32))
/// k_label         =             HKDF-Expand(prk, "shekyl-output-label-key"      || idx_le64, 32)
/// label_tag       = first_byte(HKDF-Expand(prk, "shekyl-output-label-tag"      || idx_le64, 32))
/// ml_dsa_seed     =             HKDF-Expand(prk, "shekyl-pqc-output"           || idx_le64, 32)
/// ed25519_pqc_seed=             HKDF-Expand(prk, "shekyl-pqc-ed25519"          || idx_le64, 32)
/// pqc_leaf_blind  = wide_reduce(HKDF-Expand(prk, "shekyl-pqc-leaf-blind"        || idx_le64 || ctr, 64))   (PL-D3; ctr = guard counter, 0 unless exceptional)
/// pqc_leaf_record_blind =       HKDF-Expand(prk, "shekyl-pqc-leaf-record-blind" || idx_le64, 32)          (PL-D3a)
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
    /// Label encryption key (XOR with 8-byte label plaintext)
    pub k_label: [u8; 32],
    /// 1-byte AAD for label integrity at scan
    pub label_tag: u8,
    /// ML-DSA-65 deterministic keygen seed
    pub ml_dsa_seed: [u8; 32],
    /// Ed25519 PQC component seed (for hybrid signing)
    pub ed25519_pqc_seed: [u8; 32],
}

/// Derive all per-output secrets from the combined KEM shared secret.
///
/// `combined_ss` is the 64-byte OKM from [`crate::kem::combine_shared_secrets`]
/// on the production scan path. Any length is accepted here (HKDF-Extract
/// handles variable-length IKM); test vectors may supply synthetic IKM directly.
pub fn derive_output_secrets(combined_ss: &[u8], output_index: u64) -> OutputSecrets {
    let hk = Hkdf::<Sha512>::new(Some(HKDF_SALT_OUTPUT_DERIVE), combined_ss);

    let ho = expand_to_scalar(&hk, LABEL_OUTPUT_X, output_index);
    let y = expand_to_scalar(&hk, LABEL_OUTPUT_Y, output_index);
    let z = expand_to_scalar(&hk, LABEL_OUTPUT_MASK, output_index);
    let k_amount = expand_32(&hk, LABEL_OUTPUT_AMOUNT_KEY, output_index);
    let view_tag_combined = expand_first_byte(&hk, LABEL_OUTPUT_VIEW_TAG_COMBINED, output_index);
    let amount_tag = expand_first_byte(&hk, LABEL_OUTPUT_AMOUNT_TAG, output_index);
    let k_label = expand_32(&hk, LABEL_OUTPUT_LABEL_KEY, output_index);
    let label_tag = expand_first_byte(&hk, LABEL_OUTPUT_LABEL_TAG, output_index);
    let ml_dsa_seed = expand_32(&hk, LABEL_OUTPUT_PQC, output_index);
    let ed25519_pqc_seed = expand_32(&hk, LABEL_OUTPUT_PQC_ED25519, output_index);

    assert!(
        ho != [0u8; 32],
        "HKDF produced zero ho scalar -- implementation bug"
    );
    assert!(
        y != [0u8; 32],
        "HKDF produced zero y scalar -- implementation bug"
    );

    OutputSecrets {
        ho,
        y,
        z,
        k_amount,
        view_tag_combined,
        amount_tag,
        k_label,
        label_tag,
        ml_dsa_seed,
        ed25519_pqc_seed,
    }
}

/// Derive the on-wire view-tag pre-filter byte from ML-KEM shared secret only.
///
/// FA-6 (T6): the wire tag must not be computable from quantum-recoverable
/// view material. Scanner compares this **after** universal ML-KEM decap.
pub fn derive_view_tag_prefilter(ml_kem_ss: &[u8; 32], output_index: u64) -> u8 {
    let hk = Hkdf::<Sha512>::new(Some(HKDF_SALT_VIEW_TAG_PREFILTER), ml_kem_ss);
    expand_first_byte(&hk, LABEL_VIEW_TAG_PREFILTER, output_index)
}

/// Pre-FA-6 classical view-tag pre-filter (X25519 ECDH IKM).
///
/// **Not** the V3 wire path after FA-6. Retained for §8.5.1 counterfactual
/// measurement (`fa6_decap_prefilter_gate --path classical`) and §10.1
/// disposition evidence only.
pub fn derive_view_tag_x25519_counterfactual(x25519_ss: &[u8; 32], output_index: u64) -> u8 {
    const SALT: &[u8] = b"shekyl-view-tag-x25519-v1";
    const LABEL: &[u8] = b"shekyl-view-tag-x25519";
    let hk = Hkdf::<Sha512>::new(Some(SALT), x25519_ss);
    expand_first_byte(&hk, LABEL, output_index)
}

/// Derive the per-output KEM seed from `tx_key` and recipient public keys.
///
/// Returns a 64-byte seed split as:
///   - `[0..32]`: X25519 ephemeral secret
///   - `[32..64]`: ML-KEM-768 encapsulation seed (for `encaps_from_seed`)
///
/// The HKDF `info` field uses a 40-byte domain separator:
/// `SHA3-256(x25519_pk || ml_kem_ek)` (32-byte fingerprint) `|| output_index_le64`.
/// The fingerprint is collision-resistant at 2^128, far exceeding what's needed
/// for domain separation, while avoiding a 1224-byte info field.
pub fn derive_kem_seed(
    tx_key_secret: &[u8; 32],
    x25519_pk: &[u8; 32],
    ml_kem_ek: &[u8],
    output_index: u64,
) -> zeroize::Zeroizing<[u8; 64]> {
    use sha3::{digest::Digest, Sha3_256};

    let mut hasher = Sha3_256::new();
    hasher.update(x25519_pk);
    hasher.update(ml_kem_ek);
    let fingerprint: [u8; 32] = hasher.finalize().into();

    let mut info = [0u8; 40];
    info[..32].copy_from_slice(&fingerprint);
    info[32..].copy_from_slice(&output_index.to_le_bytes());

    let hk = Hkdf::<Sha512>::new(Some(SALT_KEM_DERIVE_V1), tx_key_secret);
    let mut seed = zeroize::Zeroizing::new([0u8; 64]);
    hk.expand(&info, seed.as_mut())
        .expect("HKDF-Expand failed for 64-byte KEM seed output");

    seed
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
        let a = derive_pqc_leaf(&ss, 0).unwrap();
        let b = derive_pqc_leaf(&ss, 0).unwrap();
        assert_eq!(a.entry(), b.entry());
        assert_eq!(a.blind, b.blind);
        assert_eq!(a.record_blind, b.record_blind);
        assert_eq!(a.counter, b.counter);
    }

    #[test]
    fn different_indices_different_leaves() {
        let ss = [0xab; 64];
        let a = derive_pqc_leaf(&ss, 0).unwrap();
        let b = derive_pqc_leaf(&ss, 1).unwrap();
        assert_ne!(a.point, b.point);
        assert_ne!(a.record, b.record);
        assert_ne!(a.blind, b.blind);
    }

    #[test]
    fn different_secrets_different_leaves() {
        let a = derive_pqc_leaf(&[0xab; 64], 0).unwrap();
        let b = derive_pqc_leaf(&[0xcd; 64], 0).unwrap();
        assert_ne!(a.point, b.point);
        assert_ne!(a.record, b.record);
    }

    #[test]
    fn derived_key_sizes() {
        let ss = [0xab; 64];
        let secrets = derive_output_secrets(&ss, 0);
        let (pk, sk) = keygen_from_seed(&secrets.ml_dsa_seed).unwrap();
        use fips204::traits::SerDes;
        assert_eq!(pk.into_bytes().len(), ML_DSA_65_PK_LEN);
        assert_eq!(sk.into_bytes().len(), ML_DSA_65_SK_LEN);
    }

    #[test]
    fn derived_key_signs_and_verifies() {
        use fips204::traits::{Signer as _, Verifier as _};

        let ss = [0xab; 64];
        let secrets = derive_output_secrets(&ss, 42);
        let (pk, sk) = keygen_from_seed(&secrets.ml_dsa_seed).unwrap();

        let msg = b"shekyl per-output pqc test";
        let sig = sk.try_sign(msg, &[]).unwrap();
        assert!(pk.verify(msg, &sig, &[]));
    }

    // ── k = H_ℓ(hybrid_pk) ────────────────────────────────────────────────

    #[test]
    fn pqc_key_scalar_deterministic() {
        let pk = vec![0xab; ML_DSA_65_PK_LEN];
        assert_eq!(pqc_key_scalar(&pk), pqc_key_scalar(&pk));
    }

    #[test]
    fn pqc_key_scalar_is_canonical_nonzero_ed25519_scalar() {
        for pk in [
            vec![],
            vec![0x01],
            vec![0xab; 32],
            vec![0xff; ML_DSA_65_PK_LEN],
        ] {
            let k = pqc_key_scalar(&pk);
            assert!(
                bool::from(Scalar::from_canonical_bytes(k).is_some()),
                "k must be a canonical Ed25519 scalar (len {})",
                pk.len()
            );
            assert_ne!(k, [0u8; 32], "k must not be zero (len {})", pk.len());
        }
    }

    #[test]
    fn pqc_key_scalar_different_lengths_differ() {
        assert_ne!(
            pqc_key_scalar(&[0xab; 32]),
            pqc_key_scalar(&[0xab; ML_DSA_65_PK_LEN])
        );
    }

    #[test]
    fn pqc_key_scalar_is_domain_separated() {
        // The same bytes under the record customization must not collide with
        // the key customization: cSHAKE's domain is part of the construction.
        let pk = vec![0xab; 64];
        let under_key = cshake256_64(DOMAIN_PQC_LEAF_KEY, &pk);
        let under_record = cshake256_64(DOMAIN_PQC_LEAF_RECORD, &pk);
        assert_ne!(under_key, under_record);
    }

    #[test]
    fn pqc_key_point_is_k_times_g_k() {
        let pk = vec![0xab; ML_DSA_65_PK_LEN];
        let k = Scalar::from_bytes_mod_order(pqc_key_scalar(&pk));
        assert_eq!(
            pqc_key_point(&pk),
            (*PQC_LEAF_COMMITMENT_G_K * k).compress().to_bytes()
        );
        assert!(
            pqc_leaf_point_valid(&pqc_key_point(&pk)).is_some(),
            "K is a valid prime-order point"
        );
    }

    /// Cross-crate agreement pin: `shekyl_fcmp::PqcKeyScalar::from_pqc_public_key`
    /// forwards to [`pqc_key_scalar`] (the single source). Pins value agreement
    /// only; the byte pins live in `PQC_KEY_SCALAR_KAT.json`.
    #[test]
    fn key_scalar_matches_fcmp_wrapper() {
        use shekyl_fcmp::leaf::PqcKeyScalar;

        let ss = [0xab; 64];
        let pk_bytes = derive_pqc_public_key(&ss, 0).unwrap();
        let wrapper = PqcKeyScalar::from_pqc_public_key(&pk_bytes);
        assert_eq!(pqc_key_scalar(&pk_bytes), wrapper.0);
        assert_eq!(pqc_key_point(&pk_bytes), wrapper.point());
    }

    // ── CM = k·G_k + r·J, record = cSHAKE256(pk ‖ r_h) ────────────────────

    #[test]
    fn commitment_opens_to_key_point_under_blind() {
        let ss = [0xab; 64];
        let pk = derive_pqc_public_key(&ss, 7).unwrap();
        let leaf = pqc_leaf_commitment(&ss, 7, &pk).unwrap();
        let cm = pqc_leaf_point_valid(&leaf.point).expect("CM is a valid point");
        let r = Scalar::from_canonical_bytes(leaf.blind).expect("blind is canonical");
        assert_ne!(r, Scalar::ZERO);
        let k_point = cm - (*PQC_LEAF_COMMITMENT_J * r);
        assert_eq!(k_point.compress().to_bytes(), pqc_key_point(&pk));
        assert_eq!(leaf.counter, 0, "guard counter is 0 for a normal output");
    }

    #[test]
    fn record_is_cshake_of_pk_and_record_blind() {
        let ss = [0xab; 64];
        let pk = derive_pqc_public_key(&ss, 3).unwrap();
        let leaf = pqc_leaf_commitment(&ss, 3, &pk).unwrap();
        let mut preimage = pk.clone();
        preimage.extend_from_slice(&leaf.record_blind);
        assert_eq!(leaf.record, cshake256_32(DOMAIN_PQC_LEAF_RECORD, &preimage));
        assert_eq!(leaf.record, pqc_leaf_record(&pk, &leaf.record_blind));
        // The record commits to the canonical pk bytes, not to k: a different
        // key with the same r_h gives a different record.
        let other_pk = derive_pqc_public_key(&ss, 4).unwrap();
        assert_ne!(leaf.record, pqc_leaf_record(&other_pk, &leaf.record_blind));
    }

    #[test]
    fn commitment_hides_the_key_across_outputs() {
        // The same key committed under two different blinds gives two
        // different points: CM is not a function of pk alone (PL-D1's leak).
        let pk = derive_pqc_public_key(&[0xab; 64], 0).unwrap();
        let a = pqc_leaf_commitment(&[0x11; 64], 0, &pk).unwrap();
        let b = pqc_leaf_commitment(&[0x22; 64], 0, &pk).unwrap();
        assert_ne!(a.point, b.point);
        assert_ne!(a.point, pqc_key_point(&pk), "CM must not equal K");
    }

    #[test]
    fn entry_is_point_then_record() {
        let leaf = derive_pqc_leaf(&[0xab; 64], 0).unwrap();
        let e = leaf.entry();
        assert_eq!(e.len(), PQC_LEAF_ENTRY_LEN);
        assert_eq!(&e[..32], &leaf.point);
        assert_eq!(&e[32..], &leaf.record);
    }

    #[test]
    fn blind_counter_changes_the_blind() {
        let ss = [0xab; 64];
        let r0 = derive_pqc_leaf_blind(&ss, 0, 0);
        let r1 = derive_pqc_leaf_blind(&ss, 0, 1);
        assert_ne!(r0, r1, "the guard counter must re-derive the blind");
        assert!(bool::from(Scalar::from_canonical_bytes(r0).is_some()));
    }

    #[test]
    fn leaf_point_admission_rejects_identity_torsion_and_noncanonical() {
        use curve25519_dalek::constants::EIGHT_TORSION;

        assert!(pqc_leaf_point_valid(&EdwardsPoint::identity().compress().to_bytes()).is_none());
        for t in EIGHT_TORSION.iter().skip(1) {
            assert!(
                pqc_leaf_point_valid(&t.compress().to_bytes()).is_none(),
                "small-order point must be refused"
            );
        }
        // Not a point at all.
        assert!(pqc_leaf_point_valid(&[0xff; 32]).is_none());
        // Non-canonical encoding of a valid point: y = 2^255 - 19 + 1 ≡ 1 with the
        // sign bit — decompresses (to a torsion point) but does not re-encode to
        // the same bytes.
        let mut noncanonical = [0u8; 32];
        noncanonical[0] = 0xee; // p + 1 = 2^255 - 18
        for b in noncanonical.iter_mut().skip(1) {
            *b = 0xff;
        }
        noncanonical[31] = 0x7f;
        assert!(pqc_leaf_point_valid(&noncanonical).is_none());
        // A genuine commitment passes.
        let leaf = derive_pqc_leaf(&[0xab; 64], 0).unwrap();
        assert!(pqc_leaf_point_valid(&leaf.point).is_some());
    }

    // ── Pinned known-answer vectors ───────────────────────────────────────
    //
    // Both fixtures are self-pinned tripwires (rule 50): their regenerators
    // refuse to run unless `SHEKYL_PINNED_REGEN_DECISION="YYYY-MM-DD <rationale>"`
    // cites the `docs/V3_WALLET_DECISION_LOG.md` entry authorizing the move.

    const PINNED_REGEN_DECISION_ENV: &str = "SHEKYL_PINNED_REGEN_DECISION";

    fn regen_decision_or_refuse(fixture: &str) -> String {
        let decision = std::env::var(PINNED_REGEN_DECISION_ENV).unwrap_or_default();
        let cited = decision.len() > 11
            && decision.as_bytes()[..10]
                .iter()
                .enumerate()
                .all(|(i, b)| match i {
                    4 | 7 => *b == b'-',
                    _ => b.is_ascii_digit(),
                })
            && decision.as_bytes()[10] == b' ';
        assert!(
            cited,
            "refusing to regenerate {fixture}: set \
             {PINNED_REGEN_DECISION_ENV}=\"YYYY-MM-DD <rationale>\" citing the \
             docs/V3_WALLET_DECISION_LOG.md entry that authorizes moving it (got: \
             {decision:?}). Moving a pinned vector is a format decision, not a test \
             fix — see 50-testing.mdc."
        );
        decision
    }

    fn vectors_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/test_vectors")
    }

    /// The raw-pk inputs pinned in `PQC_KEY_SCALAR_KAT.json`: the degenerate
    /// lengths (empty, 1-byte, 32-byte) a derived key cannot express, plus one
    /// real derived hybrid key.
    fn key_scalar_kat_inputs() -> Vec<Vec<u8>> {
        vec![
            vec![],
            vec![0x01],
            vec![0xab; 32],
            derive_pqc_public_key(&[0xab; 64], 0).unwrap(),
        ]
    }

    #[derive(serde::Deserialize)]
    struct KeyScalarKat {
        pqc_pk: String,
        k: String,
        k_point: String,
    }

    #[derive(serde::Deserialize)]
    struct KeyScalarKatFile {
        vectors: Vec<KeyScalarKat>,
    }

    /// Byte pins for `k = H_ℓ(hybrid_pk)` and `K = k·G_k`, asserted through both
    /// consensus entry points (this owner and the `shekyl-fcmp` wrapper) so a
    /// fork of either copy fails here.
    #[test]
    fn pqc_key_scalar_known_answer_vectors() {
        use shekyl_fcmp::leaf::PqcKeyScalar;

        let json = include_str!("../../../docs/test_vectors/PQC_KEY_SCALAR_KAT.json");
        let file: KeyScalarKatFile =
            serde_json::from_str(json).expect("failed to parse PQC_KEY_SCALAR_KAT.json");
        assert_eq!(
            file.vectors.len(),
            4,
            "PQC_KEY_SCALAR_KAT.json is a frozen pin set — vectors are never added or removed"
        );
        for (i, v) in file.vectors.iter().enumerate() {
            let pk = hex::decode(&v.pqc_pk).unwrap_or_else(|_| panic!("vector {i}: pqc_pk hex"));
            let k = hex::decode(&v.k).unwrap_or_else(|_| panic!("vector {i}: k hex"));
            let k_point =
                hex::decode(&v.k_point).unwrap_or_else(|_| panic!("vector {i}: k_point hex"));
            assert_eq!(
                pqc_key_scalar(&pk).as_slice(),
                k.as_slice(),
                "vector {i}: pqc_key_scalar drifted for input length {}",
                pk.len()
            );
            assert_eq!(
                PqcKeyScalar::from_pqc_public_key(&pk).0.as_slice(),
                k.as_slice(),
                "vector {i}: PqcKeyScalar::from_pqc_public_key drifted for input length {}",
                pk.len()
            );
            assert_eq!(
                pqc_key_point(&pk).as_slice(),
                k_point.as_slice(),
                "vector {i}: pqc_key_point drifted for input length {}",
                pk.len()
            );
        }
    }

    /// ```text
    /// SHEKYL_PINNED_REGEN_DECISION="YYYY-MM-DD <rationale>" \
    ///   cargo test -p shekyl-crypto-pq --lib -- --ignored regenerate_pqc_key_scalar_kat
    /// ```
    #[test]
    #[ignore = "armed fixture regenerator; requires SHEKYL_PINNED_REGEN_DECISION"]
    fn regenerate_pqc_key_scalar_kat() {
        let decision = regen_decision_or_refuse("PQC_KEY_SCALAR_KAT.json");
        let vectors: Vec<serde_json::Value> = key_scalar_kat_inputs()
            .iter()
            .map(|pk| {
                serde_json::json!({
                    "pqc_pk": hex::encode(pk),
                    "k": hex::encode(pqc_key_scalar(pk)),
                    "k_point": hex::encode(pqc_key_point(pk)),
                })
            })
            .collect();
        let doc = serde_json::json!({
            "description": "PL-D3 pins for k = H_l(hybrid_pk) (cSHAKE256 under \
                shekyl/pqc-leaf-key-v1, 64-byte read reduced mod the Ed25519 group \
                order) and K = k*G_k. Inputs: the degenerate lengths (empty, 1 byte, \
                32 bytes) and one real derived hybrid public key. Consumed by \
                pqc_key_scalar_known_answer_vectors in \
                rust/shekyl-crypto-pq/src/derivation.rs, which asserts both \
                consensus entry points (pqc_key_scalar and the shekyl-fcmp \
                PqcKeyScalar wrapper). Frozen: never regenerated without a \
                decision-log entry (SHEKYL_PINNED_REGEN_DECISION).",
            "regeneration_decision": decision,
            "vectors": vectors,
        });
        let path = vectors_dir().join("PQC_KEY_SCALAR_KAT.json");
        std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
        eprintln!("wrote {}", path.display());
    }

    #[derive(serde::Deserialize)]
    struct LeafCommitmentKat {
        combined_ss: String,
        output_index: u64,
        point: String,
        record: String,
        blind: String,
        record_blind: String,
        counter: u8,
    }

    #[derive(serde::Deserialize)]
    struct LeafCommitmentKatFile {
        vectors: Vec<LeafCommitmentKat>,
    }

    fn leaf_commitment_kat_inputs() -> Vec<([u8; 64], u64)> {
        vec![
            ([0x00; 64], 0),
            ([0x00; 64], 1),
            ([0xab; 64], 0),
            ([0xab; 64], 7),
            ([0xff; 64], u64::MAX),
        ]
    }

    /// Byte pins for the owner-side `0x07` entry derivation
    /// (`derive_pqc_leaf`): the commitment point, the record, both blinds and
    /// the guard counter, per `(combined_ss, output_index)`.
    #[test]
    fn pqc_leaf_commitment_known_answer_vectors() {
        let json = include_str!("../../../docs/test_vectors/PQC_LEAF_COMMITMENT_KAT.json");
        let file: LeafCommitmentKatFile =
            serde_json::from_str(json).expect("failed to parse PQC_LEAF_COMMITMENT_KAT.json");
        assert_eq!(
            file.vectors.len(),
            leaf_commitment_kat_inputs().len(),
            "PQC_LEAF_COMMITMENT_KAT.json is a frozen pin set"
        );
        for (i, v) in file.vectors.iter().enumerate() {
            let css: [u8; 64] = hex::decode(&v.combined_ss)
                .unwrap_or_else(|_| panic!("vector {i}: combined_ss hex"))
                .try_into()
                .unwrap_or_else(|_| panic!("vector {i}: combined_ss not 64 bytes"));
            let leaf = derive_pqc_leaf(&css, v.output_index)
                .unwrap_or_else(|e| panic!("vector {i}: derive_pqc_leaf failed: {e}"));
            assert_eq!(hex::encode(leaf.point), v.point, "vector {i}: point");
            assert_eq!(hex::encode(leaf.record), v.record, "vector {i}: record");
            assert_eq!(hex::encode(leaf.blind), v.blind, "vector {i}: blind");
            assert_eq!(
                hex::encode(leaf.record_blind),
                v.record_blind,
                "vector {i}: record_blind"
            );
            assert_eq!(leaf.counter, v.counter, "vector {i}: counter");
        }
    }

    /// ```text
    /// SHEKYL_PINNED_REGEN_DECISION="YYYY-MM-DD <rationale>" \
    ///   cargo test -p shekyl-crypto-pq --lib -- --ignored regenerate_pqc_leaf_commitment_kat
    /// ```
    #[test]
    #[ignore = "armed fixture regenerator; requires SHEKYL_PINNED_REGEN_DECISION"]
    fn regenerate_pqc_leaf_commitment_kat() {
        let decision = regen_decision_or_refuse("PQC_LEAF_COMMITMENT_KAT.json");
        let vectors: Vec<serde_json::Value> = leaf_commitment_kat_inputs()
            .iter()
            .map(|(css, idx)| {
                let leaf = derive_pqc_leaf(css, *idx).unwrap();
                serde_json::json!({
                    "combined_ss": hex::encode(css),
                    "output_index": idx,
                    "point": hex::encode(leaf.point),
                    "record": hex::encode(leaf.record),
                    "blind": hex::encode(leaf.blind),
                    "record_blind": hex::encode(leaf.record_blind),
                    "counter": leaf.counter,
                })
            })
            .collect();
        let doc = serde_json::json!({
            "description": "PL-D3 / PL-D3a pins for the owner-side tx_extra 0x07 entry: \
                CM = k*G_k + r*J (k = H_l(hybrid_pk), r = HKDF-Expand(prk, \
                \"shekyl-pqc-leaf-blind\" || idx_le64 || ctr, 64) mod l), record = \
                cSHAKE256(shekyl/pqc-leaf-record-v1, pk || r_h), r_h = HKDF-Expand(prk, \
                \"shekyl-pqc-leaf-record-blind\" || idx_le64, 32), per (combined_ss, \
                output_index). Consumed by pqc_leaf_commitment_known_answer_vectors in \
                rust/shekyl-crypto-pq/src/derivation.rs. Frozen: never regenerated \
                without a decision-log entry (SHEKYL_PINNED_REGEN_DECISION).",
            "regeneration_decision": decision,
            "vectors": vectors,
        });
        let path = vectors_dir().join("PQC_LEAF_COMMITMENT_KAT.json");
        std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
        eprintln!("wrote {}", path.display());
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
        k_label: String,
        label_tag: u8,
        enc_label_sentinel: String,
        enc_label_sentinel_9: String,
        ml_dsa_seed: String,
        ml_kem_ss: String,
        view_tag_prefilter: u8,
    }

    #[derive(serde::Deserialize)]
    struct TestVectorFile {
        vectors: Vec<TestVector>,
    }

    fn load_test_vectors() -> Vec<TestVector> {
        let json = include_str!("../../../docs/test_vectors/PQC_OUTPUT_SECRETS.json");
        let file: TestVectorFile =
            serde_json::from_str(json).expect("failed to parse PQC_OUTPUT_SECRETS.json");
        file.vectors
    }

    use crate::label::{encrypt_label_plaintext, sentinel_plaintext};

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
            let expected_k_label = hex::decode(&v.k_label).unwrap();
            let expected_seed = hex::decode(&v.ml_dsa_seed).unwrap();

            assert_eq!(
                secrets.ho.as_slice(),
                expected_ho.as_slice(),
                "vector {i}: ho mismatch"
            );
            assert_eq!(
                secrets.y.as_slice(),
                expected_y.as_slice(),
                "vector {i}: y mismatch"
            );
            assert_eq!(
                secrets.z.as_slice(),
                expected_z.as_slice(),
                "vector {i}: z mismatch"
            );
            assert_eq!(
                secrets.k_amount.as_slice(),
                expected_k.as_slice(),
                "vector {i}: k_amount mismatch"
            );
            assert_eq!(
                secrets.view_tag_combined, v.view_tag_combined,
                "vector {i}: view_tag_combined mismatch"
            );
            assert_eq!(
                secrets.amount_tag, v.amount_tag,
                "vector {i}: amount_tag mismatch"
            );
            assert_eq!(
                secrets.k_label.as_slice(),
                expected_k_label.as_slice(),
                "vector {i}: k_label mismatch"
            );
            assert_eq!(
                secrets.label_tag, v.label_tag,
                "vector {i}: label_tag mismatch"
            );

            let enc = encrypt_label_plaintext(&sentinel_plaintext(), &secrets.k_label);
            let expected_enc: [u8; 8] = hex::decode(&v.enc_label_sentinel)
                .unwrap()
                .try_into()
                .unwrap();
            assert_eq!(enc, expected_enc, "vector {i}: enc_label_sentinel mismatch");
            let mut wire9_arr = [0u8; 9];
            wire9_arr[..8].copy_from_slice(&enc);
            wire9_arr[8] = secrets.label_tag;
            let expected_wire9: [u8; 9] = hex::decode(&v.enc_label_sentinel_9)
                .unwrap()
                .try_into()
                .unwrap();
            assert_eq!(
                wire9_arr, expected_wire9,
                "vector {i}: enc_label_sentinel_9 mismatch"
            );

            assert_eq!(
                secrets.ml_dsa_seed.as_slice(),
                expected_seed.as_slice(),
                "vector {i}: ml_dsa_seed mismatch"
            );
        }
    }

    #[test]
    fn view_tag_prefilter_known_answer_vectors() {
        let vectors = load_test_vectors();
        for (i, v) in vectors.iter().enumerate() {
            let ml_ss_bytes = hex::decode(&v.ml_kem_ss).unwrap();
            let ml_ss: [u8; 32] = ml_ss_bytes.as_slice().try_into().unwrap();
            let tag = derive_view_tag_prefilter(&ml_ss, v.output_index);
            assert_eq!(
                tag, v.view_tag_prefilter,
                "vector {i}: view_tag_prefilter mismatch"
            );
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
        assert_eq!(s1.k_label, s2.k_label);
        assert_eq!(s1.label_tag, s2.label_tag);
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
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        for idx in [0u64, 1, 42, u64::MAX] {
            let s = derive_output_secrets(&css, idx);
            for (name, scalar_bytes) in [("ho", s.ho), ("y", s.y), ("z", s.z)] {
                assert!(
                    le_bytes_lt(&scalar_bytes, &l_bytes_le),
                    "index {idx}: {name} is not < l"
                );
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
            if a[i] < b[i] {
                return true;
            }
            if a[i] > b[i] {
                return false;
            }
        }
        false // equal
    }

    // ── KEM_DERIVE_V1 KAT tests ─────────────────────────────────────────

    #[derive(serde::Deserialize)]
    struct KemDeriveKat {
        tx_key_secret: String,
        x25519_pk: String,
        ml_kem_ek: String,
        output_index: u64,
        recipient_fingerprint: String,
        per_output_seed: String,
        x25519_eph_pk: String,
        ml_kem_ct: String,
        ml_kem_ss: String,
        x25519_ss: String,
        combined_ss: String,
    }

    #[derive(serde::Deserialize)]
    struct KemDeriveKatFile {
        vectors: Vec<KemDeriveKat>,
    }

    #[test]
    fn kem_derive_v1_known_answer_vectors() {
        let json = include_str!("../../../docs/test_vectors/KEM_DERIVE_V1_KAT.json");
        let file: KemDeriveKatFile =
            serde_json::from_str(json).expect("failed to parse KEM_DERIVE_V1_KAT.json");
        assert!(
            !file.vectors.is_empty(),
            "no vectors in KEM_DERIVE_V1_KAT.json"
        );

        for (i, v) in file.vectors.iter().enumerate() {
            let tx_key: [u8; 32] = hex::decode(&v.tx_key_secret)
                .unwrap_or_else(|_| panic!("vector {i}: invalid tx_key_secret hex"))
                .as_slice()
                .try_into()
                .unwrap_or_else(|_| panic!("vector {i}: tx_key_secret not 32 bytes"));
            let x25519_pk: [u8; 32] = hex::decode(&v.x25519_pk)
                .unwrap_or_else(|_| panic!("vector {i}: invalid x25519_pk hex"))
                .as_slice()
                .try_into()
                .unwrap_or_else(|_| panic!("vector {i}: x25519_pk not 32 bytes"));
            let ml_kem_ek = hex::decode(&v.ml_kem_ek)
                .unwrap_or_else(|_| panic!("vector {i}: invalid ml_kem_ek hex"));

            let seed = derive_kem_seed(&tx_key, &x25519_pk, &ml_kem_ek, v.output_index);

            let expected_seed = hex::decode(&v.per_output_seed)
                .unwrap_or_else(|_| panic!("vector {i}: invalid per_output_seed hex"));
            assert_eq!(
                seed.as_slice(),
                expected_seed.as_slice(),
                "vector {i}: per_output_seed mismatch\n  got:      {}\n  expected: {}",
                hex::encode(seed.as_slice()),
                v.per_output_seed
            );

            let expected_fp = hex::decode(&v.recipient_fingerprint)
                .unwrap_or_else(|_| panic!("vector {i}: invalid recipient_fingerprint hex"));
            {
                use sha3::{digest::Digest as _, Sha3_256};
                let mut hasher = Sha3_256::new();
                hasher.update(x25519_pk);
                hasher.update(&ml_kem_ek);
                let fp: [u8; 32] = hasher.finalize().into();
                assert_eq!(
                    fp.as_slice(),
                    expected_fp.as_slice(),
                    "vector {i}: recipient_fingerprint mismatch"
                );
            }

            // Verify X25519 ephemeral public key derivation
            let x25519_eph_secret_bytes: [u8; 32] = seed[..32].try_into().unwrap();
            let x25519_eph_sk = x25519_dalek::StaticSecret::from(x25519_eph_secret_bytes);
            let x25519_eph_pk = x25519_dalek::PublicKey::from(&x25519_eph_sk);
            let expected_eph_pk = hex::decode(&v.x25519_eph_pk)
                .unwrap_or_else(|_| panic!("vector {i}: invalid x25519_eph_pk hex"));
            assert_eq!(
                x25519_eph_pk.as_bytes().as_slice(),
                expected_eph_pk.as_slice(),
                "vector {i}: x25519_eph_pk mismatch"
            );

            // Verify X25519 shared secret
            let x25519_recipient = x25519_dalek::PublicKey::from(x25519_pk);
            let x25519_ss = x25519_eph_sk.diffie_hellman(&x25519_recipient);
            let expected_x25519_ss = hex::decode(&v.x25519_ss)
                .unwrap_or_else(|_| panic!("vector {i}: invalid x25519_ss hex"));
            assert_eq!(
                x25519_ss.as_bytes().as_slice(),
                expected_x25519_ss.as_slice(),
                "vector {i}: x25519_ss mismatch"
            );

            // Verify ML-KEM deterministic encapsulation
            let ml_kem_encaps_seed: [u8; 32] = seed[32..64].try_into().unwrap();
            let ek_bytes: [u8; 1184] = ml_kem_ek
                .as_slice()
                .try_into()
                .unwrap_or_else(|_| panic!("vector {i}: ml_kem_ek not 1184 bytes"));
            let ek = fips203::ml_kem_768::EncapsKey::try_from_bytes(ek_bytes)
                .unwrap_or_else(|e| panic!("vector {i}: invalid EncapsKey: {e}"));
            use fips203::traits::{Encaps as _, SerDes as _};
            let (ml_ss, ml_ct) = ek.encaps_from_seed(&ml_kem_encaps_seed);
            let ml_ss_bytes = ml_ss.into_bytes();
            let ml_ct_bytes = ml_ct.into_bytes();

            let expected_ml_ss = hex::decode(&v.ml_kem_ss)
                .unwrap_or_else(|_| panic!("vector {i}: invalid ml_kem_ss hex"));
            assert_eq!(
                ml_ss_bytes.as_slice(),
                expected_ml_ss.as_slice(),
                "vector {i}: ml_kem_ss mismatch"
            );

            let expected_ml_ct = hex::decode(&v.ml_kem_ct)
                .unwrap_or_else(|_| panic!("vector {i}: invalid ml_kem_ct hex"));
            assert_eq!(
                ml_ct_bytes.as_slice(),
                expected_ml_ct.as_slice(),
                "vector {i}: ml_kem_ct mismatch"
            );

            // Verify combined shared secret
            let combined = crate::kem::combine_shared_secrets(x25519_ss.as_bytes(), &ml_ss_bytes)
                .unwrap_or_else(|e| panic!("vector {i}: combine_shared_secrets failed: {e}"));
            let expected_combined = hex::decode(&v.combined_ss)
                .unwrap_or_else(|_| panic!("vector {i}: invalid combined_ss hex"));
            assert_eq!(
                combined.0.as_slice(),
                expected_combined.as_slice(),
                "vector {i}: combined_ss mismatch"
            );
        }
    }

    #[test]
    #[ignore = "KAT regenerator for the kem_derive_v1 vectors; run manually with --ignored --nocapture after a derivation change"]
    fn generate_kem_derive_v1_kat() {
        use fips203::ml_kem_768;
        use fips203::traits::{Encaps as _, KeyGen as _, SerDes as _};
        use rand::SeedableRng;
        use sha3::{digest::Digest as _, Sha3_256};

        // Deterministic recipient keypair
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([0x01; 32]);
        let (ek, _dk) = ml_kem_768::KG::try_keygen_with_rng(&mut rng).unwrap();
        let ek_bytes = ek.into_bytes();
        let x25519_sk = x25519_dalek::StaticSecret::from([0x02u8; 32]);
        let x25519_pk = x25519_dalek::PublicKey::from(&x25519_sk);

        let test_cases: Vec<([u8; 32], u64)> = vec![
            ([0x00; 32], 0),
            ([0x00; 32], 1),
            ([0xAB; 32], 0),
            ([0xAB; 32], 42),
            ([0xFF; 32], 0),
            ([0xFF; 32], u64::MAX),
            (
                {
                    let mut k = [0u8; 32];
                    #[allow(clippy::cast_possible_truncation)]
                    for (i, b) in k.iter_mut().enumerate() {
                        *b = i as u8;
                    }
                    k
                },
                0,
            ),
            (
                {
                    let mut k = [0u8; 32];
                    #[allow(clippy::cast_possible_truncation)]
                    for (i, b) in k.iter_mut().enumerate() {
                        *b = i as u8;
                    }
                    k
                },
                1000,
            ),
        ];

        let mut vectors = Vec::new();
        for (tx_key, output_index) in &test_cases {
            let seed = derive_kem_seed(tx_key, x25519_pk.as_bytes(), &ek_bytes, *output_index);

            let mut hasher = Sha3_256::new();
            hasher.update(x25519_pk.as_bytes());
            hasher.update(ek_bytes);
            let fp: [u8; 32] = hasher.finalize().into();

            let eph_secret_bytes: [u8; 32] = seed[..32].try_into().unwrap();
            let eph_sk = x25519_dalek::StaticSecret::from(eph_secret_bytes);
            let eph_pk = x25519_dalek::PublicKey::from(&eph_sk);
            let x_ss = eph_sk.diffie_hellman(&x25519_pk);

            let ml_seed: [u8; 32] = seed[32..64].try_into().unwrap();
            let ek_parsed = ml_kem_768::EncapsKey::try_from_bytes(ek_bytes).unwrap();
            let (ml_ss, ml_ct) = ek_parsed.encaps_from_seed(&ml_seed);
            let ml_ss_bytes = ml_ss.into_bytes();
            let ml_ct_bytes = ml_ct.into_bytes();

            let combined =
                crate::kem::combine_shared_secrets(x_ss.as_bytes(), &ml_ss_bytes).unwrap();

            vectors.push(serde_json::json!({
                "tx_key_secret": hex::encode(tx_key),
                "x25519_pk": hex::encode(x25519_pk.as_bytes()),
                "ml_kem_ek": hex::encode(ek_bytes),
                "output_index": output_index,
                "recipient_fingerprint": hex::encode(fp),
                "per_output_seed": hex::encode(seed.as_slice()),
                "x25519_eph_pk": hex::encode(eph_pk.as_bytes()),
                "x25519_ss": hex::encode(x_ss.as_bytes()),
                "ml_kem_ct": hex::encode(ml_ct_bytes),
                "ml_kem_ss": hex::encode(ml_ss_bytes),
                "combined_ss": hex::encode(&combined.0),
            }));
        }

        let doc = serde_json::json!({ "vectors": vectors });
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
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
        use sha3::{digest::Digest, Keccak256};

        let mut buf = Vec::with_capacity(8 + 32 + 10);
        buf.extend_from_slice(b"shekyl_y");
        buf.extend_from_slice(derivation);
        // Shekyl wire varint (7-bit continuation, CryptoNote-style; same shape
        // as upstream Monero's varint, but Shekyl-genesis-locked — see
        // `60-no-monero-legacy.mdc`).
        let mut idx = output_index;
        loop {
            let byte = (idx & 0x7F) as u8;
            idx >>= 7;
            if idx == 0 {
                buf.push(byte);
                break;
            }
            buf.push(byte | 0x80);
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
