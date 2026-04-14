// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Two-component output construction and scanning.
//!
//! Implements the canonical Shekyl V3 output key derivation:
//!
//! ```text
//! Construction (sender):
//!   ephemeral_x25519_sk, combined_ss, kem_ct = HybridKEM.Encap(recipient_pk)
//!   secrets = derive_output_secrets(combined_ss, output_index)
//!   O = ho*G + B + y*T
//!   C = z*G + amount*H
//!   enc_amount = amount_le XOR k_amount[..8]
//!   pqc_kp = ML-DSA-65.KeyGen(ml_dsa_seed)
//!   h_pqc = PqcLeafHash(pqc_kp.pk)
//!
//! Scanning (recipient):
//!   x25519_ss = X25519(sk, kem_ct.x25519)
//!   view_tag check (fast pre-filter)
//!   combined_ss = HybridKEM.Decap(sk, kem_ct)
//!   secrets = derive_output_secrets(combined_ss, output_index)
//!   verify amount_tag
//!   recover amount = decrypt(enc_amount, k_amount)
//!   verify O == ho*G + B + y*T
//!   verify C == z*G + amount*H
//! ```

use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_POINT as G, X25519_BASEPOINT},
    edwards::{CompressedEdwardsY, EdwardsPoint},
    montgomery::MontgomeryPoint,
    scalar::Scalar,
};
use fips203::{
    ml_kem_768,
    traits::{Decaps, Encaps, SerDes},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use shekyl_generators::{H, T};

use crate::derivation::{
    derive_kem_seed, derive_output_secrets, derive_view_tag_x25519, hash_pqc_public_key,
    keygen_from_seed, OutputSecrets,
};
use crate::kem::{
    combine_shared_secrets, SharedSecret, ML_KEM_768_CT_LEN, ML_KEM_768_DK_LEN, ML_KEM_768_EK_LEN,
};
use crate::CryptoError;

/// All data produced by output construction that the sender needs to build the tx.
#[derive(ZeroizeOnDrop)]
pub struct OutputData {
    /// Compressed output public key O = ho*G + B + y*T.
    #[zeroize(skip)]
    pub output_key: [u8; 32],
    /// Compressed Pedersen commitment C = z*G + amount*H.
    #[zeroize(skip)]
    pub commitment: [u8; 32],
    /// XOR-encrypted amount (8 bytes).
    #[zeroize(skip)]
    pub enc_amount: [u8; 8],
    /// 1-byte AAD tag for amount integrity.
    #[zeroize(skip)]
    pub amount_tag: u8,
    /// X25519-only view tag for scanner pre-filtering.
    #[zeroize(skip)]
    pub view_tag_x25519: u8,
    /// Ephemeral X25519 public key (part of KEM ciphertext).
    #[zeroize(skip)]
    pub kem_ciphertext_x25519: [u8; 32],
    /// ML-KEM-768 ciphertext (part of KEM ciphertext).
    #[zeroize(skip)]
    pub kem_ciphertext_ml_kem: Vec<u8>,
    /// ML-DSA-65 public key for this output.
    #[zeroize(skip)]
    pub pqc_public_key: Vec<u8>,
    /// PQC leaf hash H(pqc_pk) for the curve tree.
    #[zeroize(skip)]
    pub h_pqc: [u8; 32],
    /// HKDF-derived y scalar (sender keeps for coinbase self-spend).
    pub y: [u8; 32],
    /// HKDF-derived commitment mask z.
    pub z: [u8; 32],
    /// HKDF-derived amount encryption key.
    pub k_amount: [u8; 32],
}

// CLIPPY: omitted fields are intentionally redacted (secrets or bulky ciphertexts).
#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for OutputData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutputData")
            .field("output_key", &self.output_key)
            .field("commitment", &self.commitment)
            .field("amount_tag", &self.amount_tag)
            .field("view_tag_x25519", &self.view_tag_x25519)
            .field("y", &"[REDACTED]")
            .field("z", &"[REDACTED]")
            .field("k_amount", &"[REDACTED]")
            .finish()
    }
}

/// Result of scanning an output (recipient-side).
#[derive(ZeroizeOnDrop)]
pub struct ScannedOutput {
    /// HKDF-derived y scalar for the prover.
    pub y: [u8; 32],
    /// HKDF-derived commitment mask z.
    pub z: [u8; 32],
    /// HKDF-derived amount encryption key.
    pub k_amount: [u8; 32],
    /// Decrypted amount.
    #[zeroize(skip)]
    pub amount: u64,
    /// Verified amount tag.
    #[zeroize(skip)]
    pub amount_tag: u8,
    /// ML-DSA-65 public key for this output.
    #[zeroize(skip)]
    pub pqc_public_key: Vec<u8>,
    /// ML-DSA-65 secret key for this output.
    pub pqc_secret_key: Vec<u8>,
    /// PQC leaf hash H(pqc_pk).
    #[zeroize(skip)]
    pub h_pqc: [u8; 32],
}

// CLIPPY: pqc_public_key intentionally omitted (bulky, derivable from pqc_secret_key).
#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for ScannedOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScannedOutput")
            .field("amount", &self.amount)
            .field("amount_tag", &self.amount_tag)
            .field("h_pqc", &self.h_pqc)
            .field("y", &"[REDACTED]")
            .field("z", &"[REDACTED]")
            .field("k_amount", &"[REDACTED]")
            .field("pqc_secret_key", &"[REDACTED]")
            .finish()
    }
}

/// Construct a two-component output with deterministic KEM from `tx_key_secret`.
///
/// `spend_key` is interpreted as a **compressed Edwards point** (opaque B),
/// not a scalar. This preserves the V4 FROST SAL migration path where B
/// may be a multisig aggregate key unknown to any single party as a scalar.
///
/// KEM encapsulation is deterministic: `tx_key_secret` + recipient public keys
/// + `output_index` uniquely determine the X25519 ephemeral key and ML-KEM
///   ciphertext. The sender can re-derive `combined_ss` at proof time from
///   `tx_key_secret` (stored in `m_tx_keys`) + public data.
pub fn construct_output(
    tx_key_secret: &[u8; 32],
    x25519_pk: &[u8; 32],
    ml_kem_ek: &[u8],
    spend_key: &[u8; 32],
    amount: u64,
    output_index: u64,
) -> Result<OutputData, CryptoError> {
    // --- Input validation ---

    let b_point = CompressedEdwardsY(*spend_key)
        .decompress()
        .ok_or(CryptoError::InvalidKeyMaterial)?;

    if b_point == EdwardsPoint::default() {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    if !b_point.is_torsion_free() {
        return Err(CryptoError::InvalidKeyMaterial);
    }

    if ml_kem_ek.len() != ML_KEM_768_EK_LEN {
        return Err(CryptoError::InvalidKeyMaterial);
    }

    // --- Deterministic KEM encapsulation from tx_key ---

    let per_output_seed = derive_kem_seed(tx_key_secret, x25519_pk, ml_kem_ek, output_index);

    let x25519_eph_secret_bytes: [u8; 32] = per_output_seed[..32]
        .try_into()
        .expect("per_output_seed is 64 bytes");
    let eph_scalar = Scalar::from_bytes_mod_order(x25519_eph_secret_bytes);
    let eph_mont_pub = &eph_scalar * &X25519_BASEPOINT;
    let recipient_mont = MontgomeryPoint(*x25519_pk);
    if crate::montgomery::is_low_order_montgomery(&recipient_mont) {
        return Err(CryptoError::LowOrderPoint);
    }
    let x25519_raw_ss = &eph_scalar * &recipient_mont;

    let ek_bytes: [u8; ML_KEM_768_EK_LEN] = ml_kem_ek
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let ek = ml_kem_768::EncapsKey::try_from_bytes(ek_bytes)
        .map_err(|e| CryptoError::EncapsulationFailed(format!("invalid encap key: {e}")))?;

    let ml_kem_encaps_seed: [u8; 32] = per_output_seed[32..64]
        .try_into()
        .expect("per_output_seed is 64 bytes");
    let (ml_ss, ml_ct) = ek.encaps_from_seed(&ml_kem_encaps_seed);

    let ml_ss_bytes = Zeroizing::new(ml_ss.into_bytes());
    let ml_ct_bytes = ml_ct.into_bytes();

    let combined_ss: SharedSecret =
        combine_shared_secrets(&x25519_raw_ss.0, &*ml_ss_bytes)?;

    // --- View tag (X25519-only, pre-filter) ---

    let view_tag_x25519 = derive_view_tag_x25519(&x25519_raw_ss.0, output_index);

    // --- Output secrets derivation ---

    let secrets: OutputSecrets = derive_output_secrets(&combined_ss.0, output_index);

    let ho: Scalar = Option::from(Scalar::from_canonical_bytes(secrets.ho))
        .expect("ho from wide_reduce is always canonical");
    let y_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(secrets.y))
        .expect("y from wide_reduce is always canonical");
    let z_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(secrets.z))
        .expect("z from wide_reduce is always canonical");

    // --- Output key: O = ho*G + B + y*T ---

    let output_point = (G * ho) + b_point + (*T * y_scalar);
    if !output_point.is_torsion_free() {
        return Err(CryptoError::KeyGenerationFailed(
            "constructed O is not in prime-order subgroup".into(),
        ));
    }
    let output_key = output_point.compress().to_bytes();

    // --- Pedersen commitment: C = z*G + amount*H ---

    let amount_scalar = Scalar::from(amount);
    let commitment_point = (G * z_scalar) + (*H * amount_scalar);
    let commitment = commitment_point.compress().to_bytes();

    // --- Amount encryption ---

    let amount_le = amount.to_le_bytes();
    let mut enc_amount = [0u8; 8];
    for i in 0..8 {
        enc_amount[i] = amount_le[i] ^ secrets.k_amount[i];
    }

    // --- PQC keypair ---

    let (pqc_pk, _pqc_sk) = keygen_from_seed_bytes(&secrets.ml_dsa_seed)?;
    let h_pqc = compute_hybrid_h_pqc(&secrets)?;

    Ok(OutputData {
        output_key,
        commitment,
        enc_amount,
        amount_tag: secrets.amount_tag,
        view_tag_x25519,
        kem_ciphertext_x25519: eph_mont_pub.0,
        kem_ciphertext_ml_kem: ml_ct_bytes.to_vec(),
        pqc_public_key: pqc_pk,
        h_pqc,
        y: secrets.y,
        z: secrets.z,
        k_amount: secrets.k_amount,
    })
}

/// Scan an output to determine ownership and recover secrets.
///
/// Returns `Err` for outputs that don't belong to this key, or for
/// cryptographic integrity failures. View-tag mismatch returns early
/// (cheap rejection). Amount-tag mismatch is a loud cryptographic failure.
// CLIPPY: parameters correspond 1:1 to on-chain output fields plus recipient
// keys; bundling into a struct would just move the field list elsewhere.
#[allow(clippy::too_many_arguments)]
pub fn scan_output(
    x25519_sk: &[u8; 32],
    ml_kem_dk: &[u8],
    kem_ct_x25519: &[u8; 32],
    kem_ct_ml_kem: &[u8],
    output_key: &[u8; 32],
    commitment: &[u8; 32],
    enc_amount: &[u8; 8],
    amount_tag_on_chain: u8,
    view_tag_on_chain: u8,
    spend_key: &[u8; 32],
    output_index: u64,
) -> Result<ScannedOutput, CryptoError> {
    // --- X25519 view tag pre-filter ---

    let view_scalar = Scalar::from_bytes_mod_order(*x25519_sk);
    let eph_mont = MontgomeryPoint(*kem_ct_x25519);

    // kem_ct_x25519 arrives from tx_extra on a network transaction — attacker-controlled.
    // Without clamping, view_scalar * low_order_point leaks view_scalar mod 8.
    if crate::montgomery::is_low_order_montgomery(&eph_mont) {
        return Err(CryptoError::LowOrderPoint);
    }

    // View secret is an Ed25519 scalar already reduced mod l; clamping would mutate it
    // and desynchronize from sender-side derivation. Low-order points are rejected above.
    // Constant-time: curve25519-dalek scalar * MontgomeryPoint is always constant-time.
    let x25519_raw_ss = &view_scalar * &eph_mont;

    let expected_view_tag = derive_view_tag_x25519(&x25519_raw_ss.0, output_index);
    if expected_view_tag != view_tag_on_chain {
        return Err(CryptoError::DecapsulationFailed(
            "X25519 view tag mismatch — output not for this key".into(),
        ));
    }

    // --- Full KEM decapsulation ---

    if ml_kem_dk.len() != ML_KEM_768_DK_LEN {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    if kem_ct_ml_kem.len() != ML_KEM_768_CT_LEN {
        return Err(CryptoError::DecapsulationFailed(
            "invalid ML-KEM ciphertext length".into(),
        ));
    }

    let dk_bytes: [u8; ML_KEM_768_DK_LEN] = ml_kem_dk
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let dk = ml_kem_768::DecapsKey::try_from_bytes(dk_bytes)
        .map_err(|e| CryptoError::DecapsulationFailed(format!("invalid decap key: {e}")))?;

    let ct_bytes: [u8; ML_KEM_768_CT_LEN] = kem_ct_ml_kem
        .try_into()
        .map_err(|_| CryptoError::DecapsulationFailed("invalid ciphertext".into()))?;
    let ct = ml_kem_768::CipherText::try_from_bytes(ct_bytes)
        .map_err(|e| CryptoError::DecapsulationFailed(format!("invalid ciphertext: {e}")))?;

    let ml_ss = dk
        .try_decaps(&ct)
        .map_err(|e| CryptoError::DecapsulationFailed(format!("ML-KEM-768 decaps: {e}")))?;
    let ml_ss_bytes = Zeroizing::new(ml_ss.into_bytes());

    let combined_ss: SharedSecret =
        combine_shared_secrets(&x25519_raw_ss.0, &*ml_ss_bytes)?;

    // --- Output secrets derivation ---

    let secrets: OutputSecrets = derive_output_secrets(&combined_ss.0, output_index);

    // --- Amount tag verification (loud failure) ---

    if secrets.amount_tag != amount_tag_on_chain {
        return Err(CryptoError::DecapsulationFailed(
            "amount_tag mismatch — possible KEM ciphertext corruption or tampering".into(),
        ));
    }

    // --- Amount decryption ---

    let mut amount_le = [0u8; 8];
    for i in 0..8 {
        amount_le[i] = enc_amount[i] ^ secrets.k_amount[i];
    }
    let amount = u64::from_le_bytes(amount_le);

    // --- Output key verification: O == ho*G + B + y*T ---

    let b_point = CompressedEdwardsY(*spend_key)
        .decompress()
        .ok_or(CryptoError::InvalidKeyMaterial)?;

    let ho: Scalar = Option::from(Scalar::from_canonical_bytes(secrets.ho))
        .expect("ho from wide_reduce is always canonical");
    let y_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(secrets.y))
        .expect("y from wide_reduce is always canonical");
    let z_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(secrets.z))
        .expect("z from wide_reduce is always canonical");

    let expected_o = (G * ho) + b_point + (*T * y_scalar);
    if expected_o.compress().to_bytes() != *output_key {
        return Err(CryptoError::DecapsulationFailed(
            "output key mismatch — not for this spend key".into(),
        ));
    }

    // --- Commitment verification: C == z*G + amount*H ---

    let amount_scalar = Scalar::from(amount);
    let expected_c = (G * z_scalar) + (*H * amount_scalar);
    if expected_c.compress().to_bytes() != *commitment {
        return Err(CryptoError::DecapsulationFailed(
            "commitment mismatch — amount or mask corrupted".into(),
        ));
    }

    // --- PQC keypair derivation ---

    let (pqc_pk, pqc_sk) = keygen_from_seed_bytes(&secrets.ml_dsa_seed)?;
    let h_pqc = compute_hybrid_h_pqc(&secrets)?;

    Ok(ScannedOutput {
        y: secrets.y,
        z: secrets.z,
        k_amount: secrets.k_amount,
        amount,
        amount_tag: secrets.amount_tag,
        pqc_public_key: pqc_pk,
        pqc_secret_key: pqc_sk,
        h_pqc,
    })
}

/// Output of `scan_output_recover`: KEM decap + HKDF + amount decryption +
/// recovered spend key B' = O - ho*G - y*T (for subaddress lookup).
/// Does NOT verify the spend key — caller must look up B' in a subaddress
/// table and decide ownership.
pub struct RecoveredOutput {
    pub ho: [u8; 32],
    pub y: [u8; 32],
    pub z: [u8; 32],
    pub k_amount: [u8; 32],
    pub amount: u64,
    pub amount_tag: u8,
    pub recovered_spend_key: [u8; 32],
    pub combined_ss: [u8; 64],
    pub pqc_public_key: Vec<u8>,
    pub pqc_secret_key: Vec<u8>,
    pub h_pqc: [u8; 32],
}

impl ZeroizeOnDrop for RecoveredOutput {}
impl Zeroize for RecoveredOutput {
    fn zeroize(&mut self) {
        self.ho.zeroize();
        self.y.zeroize();
        self.z.zeroize();
        self.k_amount.zeroize();
        self.combined_ss.zeroize();
        self.pqc_secret_key.zeroize();
    }
}

// CLIPPY: omitted fields are secrets intentionally redacted for safe debug output.
#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for RecoveredOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveredOutput")
            .field("amount", &self.amount)
            .field("amount_tag", &self.amount_tag)
            .field("recovered_spend_key", &"[REDACTED]")
            .field("y", &"[REDACTED]")
            .field("z", &"[REDACTED]")
            .finish()
    }
}

/// KEM decap + HKDF + amount verification, returning the recovered spend key
/// `B' = O - ho*G - y*T` for caller-side subaddress lookup.
///
/// This avoids iterating over subaddresses in Rust. The caller checks
/// `B'` against its subaddress table to determine ownership. Commitment
/// verification (`C == z*G + amount*H`) IS performed here.
// CLIPPY: parameters correspond 1:1 to on-chain output fields plus recipient keys.
#[allow(clippy::too_many_arguments)]
pub fn scan_output_recover(
    x25519_sk: &[u8; 32],
    ml_kem_dk: &[u8],
    kem_ct_x25519: &[u8; 32],
    kem_ct_ml_kem: &[u8],
    output_key: &[u8; 32],
    commitment: &[u8; 32],
    enc_amount: &[u8; 8],
    amount_tag_on_chain: u8,
    view_tag_on_chain: u8,
    output_index: u64,
) -> Result<RecoveredOutput, CryptoError> {
    // --- X25519 view tag pre-filter ---
    let view_scalar = Scalar::from_bytes_mod_order(*x25519_sk);
    let eph_mont = MontgomeryPoint(*kem_ct_x25519);

    // kem_ct_x25519 arrives from tx_extra on a network transaction — attacker-controlled.
    // Without clamping, view_scalar * low_order_point leaks view_scalar mod 8.
    if crate::montgomery::is_low_order_montgomery(&eph_mont) {
        return Err(CryptoError::LowOrderPoint);
    }

    // View secret is an Ed25519 scalar already reduced mod l; clamping would mutate it
    // and desynchronize from sender-side derivation. Low-order points are rejected above.
    // Constant-time: curve25519-dalek scalar * MontgomeryPoint is always constant-time.
    let x25519_raw_ss = &view_scalar * &eph_mont;

    let expected_view_tag = derive_view_tag_x25519(&x25519_raw_ss.0, output_index);
    if expected_view_tag != view_tag_on_chain {
        return Err(CryptoError::DecapsulationFailed(
            "X25519 view tag mismatch — output not for this key".into(),
        ));
    }

    // --- Full KEM decapsulation ---
    if ml_kem_dk.len() != ML_KEM_768_DK_LEN {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    if kem_ct_ml_kem.len() != ML_KEM_768_CT_LEN {
        return Err(CryptoError::DecapsulationFailed(
            "invalid ML-KEM ciphertext length".into(),
        ));
    }

    let dk_bytes: [u8; ML_KEM_768_DK_LEN] = ml_kem_dk
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let dk = ml_kem_768::DecapsKey::try_from_bytes(dk_bytes)
        .map_err(|e| CryptoError::DecapsulationFailed(format!("invalid decap key: {e}")))?;

    let ct_bytes: [u8; ML_KEM_768_CT_LEN] = kem_ct_ml_kem
        .try_into()
        .map_err(|_| CryptoError::DecapsulationFailed("invalid ciphertext".into()))?;
    let ct = ml_kem_768::CipherText::try_from_bytes(ct_bytes)
        .map_err(|e| CryptoError::DecapsulationFailed(format!("invalid ciphertext: {e}")))?;

    let ml_ss = dk
        .try_decaps(&ct)
        .map_err(|e| CryptoError::DecapsulationFailed(format!("ML-KEM-768 decaps: {e}")))?;
    let ml_ss_bytes = Zeroizing::new(ml_ss.into_bytes());

    let combined_ss: SharedSecret =
        combine_shared_secrets(&x25519_raw_ss.0, &*ml_ss_bytes)?;

    // --- Output secrets derivation ---
    let secrets: OutputSecrets = derive_output_secrets(&combined_ss.0, output_index);

    // --- Amount tag verification (loud failure) ---
    if secrets.amount_tag != amount_tag_on_chain {
        return Err(CryptoError::DecapsulationFailed(
            "amount_tag mismatch — possible KEM ciphertext corruption or tampering".into(),
        ));
    }

    // --- Amount decryption ---
    let mut amount_le = [0u8; 8];
    for i in 0..8 {
        amount_le[i] = enc_amount[i] ^ secrets.k_amount[i];
    }
    let amount = u64::from_le_bytes(amount_le);

    // --- Recover spend key: B' = O - ho*G - y*T ---
    let o_point = CompressedEdwardsY(*output_key)
        .decompress()
        .ok_or_else(|| CryptoError::DecapsulationFailed("invalid output key point".into()))?;

    let ho: Scalar = Option::from(Scalar::from_canonical_bytes(secrets.ho))
        .expect("ho from wide_reduce is always canonical");
    let y_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(secrets.y))
        .expect("y from wide_reduce is always canonical");
    let z_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(secrets.z))
        .expect("z from wide_reduce is always canonical");

    let recovered_b = o_point - (G * ho) - (*T * y_scalar);
    let recovered_spend_key = recovered_b.compress().to_bytes();

    // --- Commitment verification: C == z*G + amount*H ---
    let amount_scalar = Scalar::from(amount);
    let expected_c = (G * z_scalar) + (*H * amount_scalar);
    if expected_c.compress().to_bytes() != *commitment {
        return Err(CryptoError::DecapsulationFailed(
            "commitment mismatch — amount or mask corrupted".into(),
        ));
    }

    // --- PQC keypair derivation ---
    let (pqc_pk, pqc_sk) = keygen_from_seed_bytes(&secrets.ml_dsa_seed)?;
    let h_pqc = compute_hybrid_h_pqc(&secrets)?;

    Ok(RecoveredOutput {
        ho: secrets.ho,
        y: secrets.y,
        z: secrets.z,
        k_amount: secrets.k_amount,
        amount,
        amount_tag: secrets.amount_tag,
        recovered_spend_key,
        combined_ss: combined_ss.0,
        pqc_public_key: pqc_pk,
        pqc_secret_key: pqc_sk,
        h_pqc,
    })
}

/// Result of PQC signing for an output.
///
/// Contains the hybrid public key (for on-chain leaf hash) and the
/// hybrid signature. The ML-DSA secret key is derived, used, and
/// zeroized entirely within Rust — it never crosses the FFI boundary.
pub struct PqcAuthSignature {
    /// Canonical hybrid public key bytes.
    pub hybrid_public_key: Vec<u8>,
    /// Canonical hybrid signature bytes.
    pub signature: Vec<u8>,
}

impl std::fmt::Debug for PqcAuthSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqcAuthSignature")
            .field("hybrid_public_key_len", &self.hybrid_public_key.len())
            .field("signature_len", &self.signature.len())
            .finish()
    }
}

/// Sign a message for a specific output using the HKDF-derived PQC keypair.
///
/// This is the single point where ML-DSA secret keys exist. The key is
/// derived from `derive_output_secrets(combined_ss, output_index).ml_dsa_seed`
/// (salt B), used to sign `message`, and immediately zeroized. The secret
/// key never crosses the FFI boundary.
///
/// Returns the hybrid (Ed25519 + ML-DSA-65) public key and signature in
/// canonical encoding.
pub fn sign_pqc_auth_for_output(
    combined_ss: &[u8; 64],
    output_index: u64,
    message: &[u8],
) -> Result<PqcAuthSignature, CryptoError> {
    use crate::signature::{HybridEd25519MlDsa, HybridPublicKey, HybridSecretKey, SignatureScheme};
    use ed25519_dalek::SigningKey;

    let secrets: OutputSecrets = derive_output_secrets(combined_ss, output_index);

    // ML-DSA-65 keypair from HKDF seed
    let (ml_pk, ml_sk) = keygen_from_seed(&secrets.ml_dsa_seed)?;

    // Ed25519 keypair from HKDF seed
    let ed_signing = SigningKey::from_bytes(&secrets.ed25519_pqc_seed);
    let ed_verifying = ed_signing.verifying_key();

    let hybrid_pk = HybridPublicKey {
        ed25519: ed_verifying.to_bytes(),
        ml_dsa: {
            use fips204::traits::SerDes;
            ml_pk.into_bytes().to_vec()
        },
    };
    let hybrid_sk = HybridSecretKey {
        ed25519: ed_signing.to_bytes().to_vec(),
        ml_dsa: {
            use fips204::traits::SerDes;
            ml_sk.into_bytes().to_vec()
        },
    };

    let scheme = HybridEd25519MlDsa;
    let sig = scheme.sign(&hybrid_sk, message)?;

    let pk_bytes = hybrid_pk.to_canonical_bytes()?;
    let sig_bytes = sig.to_canonical_bytes()?;

    // hybrid_sk drops here — zeroized via HybridSecretKey's Zeroize impl
    // secrets drops here — zeroized via OutputSecrets's ZeroizeOnDrop

    Ok(PqcAuthSignature {
        hybrid_public_key: pk_bytes,
        signature: sig_bytes,
    })
}

// ── Proof helpers (Phase 1) ───────────────────────────────────────────

/// Narrow projection of output secrets for proof protocols.
///
/// Contains the values a proof verifier needs to verify output ownership
/// and decrypt amounts. `combined_ss` itself, `ml_dsa_seed`, and
/// `ed25519_pqc_seed` are never revealed.
///
/// TX proofs (outbound/inbound) use all four fields: ho and y for the
/// output key check `O = ho*G + B + y*T`, z for the commitment check
/// `C = z*G + amount*H`, and k_amount for amount decryption.
///
/// Reserve proofs use ho, y, k_amount plus a DLEQ proof for key image
/// correctness; z is omitted from the reserve wire format (the HKDF
/// binding argument and on-chain Bulletproofs+ make it redundant) but
/// is available here for optional defense-in-depth verification.
#[derive(ZeroizeOnDrop)]
pub struct ProofSecrets {
    pub ho: [u8; 32],
    pub y: [u8; 32],
    pub z: [u8; 32],
    pub k_amount: [u8; 32],
}

impl std::fmt::Debug for ProofSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofSecrets")
            .field("ho", &"[REDACTED]")
            .field("y", &"[REDACTED]")
            .field("z", &"[REDACTED]")
            .field("k_amount", &"[REDACTED]")
            .finish()
    }
}

/// Re-derive `combined_ss` from `tx_key_secret` and recipient public keys.
///
/// Used by the outbound proof verifier to reconstruct the shared secret
/// from the `tx_key` revealed in the proof. Returns the combined shared
/// secret plus the X25519 ephemeral public key and ML-KEM ciphertext
/// for on-chain integrity checking.
pub fn rederive_combined_ss(
    tx_key_secret: &[u8; 32],
    x25519_pk: &[u8; 32],
    ml_kem_ek: &[u8],
    output_index: u64,
) -> Result<(SharedSecret, [u8; 32], Vec<u8>), CryptoError> {
    if ml_kem_ek.len() != ML_KEM_768_EK_LEN {
        return Err(CryptoError::InvalidKeyMaterial);
    }

    let per_output_seed = derive_kem_seed(tx_key_secret, x25519_pk, ml_kem_ek, output_index);

    let x25519_eph_secret_bytes: [u8; 32] = per_output_seed[..32]
        .try_into()
        .expect("per_output_seed is 64 bytes");
    let eph_scalar = Scalar::from_bytes_mod_order(x25519_eph_secret_bytes);
    let eph_mont_pub = &eph_scalar * &X25519_BASEPOINT;
    let recipient_mont = MontgomeryPoint(*x25519_pk);
    if crate::montgomery::is_low_order_montgomery(&recipient_mont) {
        return Err(CryptoError::LowOrderPoint);
    }
    let x25519_raw_ss = &eph_scalar * &recipient_mont;

    let ek_bytes: [u8; ML_KEM_768_EK_LEN] = ml_kem_ek
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let ek = ml_kem_768::EncapsKey::try_from_bytes(ek_bytes)
        .map_err(|e| CryptoError::EncapsulationFailed(format!("invalid encap key: {e}")))?;

    let ml_kem_encaps_seed: [u8; 32] = per_output_seed[32..64]
        .try_into()
        .expect("per_output_seed is 64 bytes");
    let (ml_ss, ml_ct) = ek.encaps_from_seed(&ml_kem_encaps_seed);

    let ml_ss_bytes = Zeroizing::new(ml_ss.into_bytes());
    let ml_ct_bytes = ml_ct.into_bytes();

    let combined_ss: SharedSecret =
        combine_shared_secrets(&x25519_raw_ss.0, &*ml_ss_bytes)?;

    Ok((combined_ss, eph_mont_pub.0, ml_ct_bytes.to_vec()))
}

/// Derive the proof secrets projection from `combined_ss`.
///
/// Returns `(ho, y, z, k_amount)`. This is the ONLY function that
/// converts `combined_ss` into values that leave Rust in the proof path.
/// Does NOT return `ml_dsa_seed`, `ed25519_pqc_seed`, or `amount_tag`.
///
/// TX proofs use all four fields (z for commitment verification).
/// Reserve proofs use ho, y, k_amount (z omitted from wire format but
/// available for optional defense-in-depth).
pub fn derive_proof_secrets(combined_ss: &[u8; 64], output_index: u64) -> ProofSecrets {
    let secrets = derive_output_secrets(combined_ss, output_index);
    ProofSecrets {
        ho: secrets.ho,
        y: secrets.y,
        z: secrets.z,
        k_amount: secrets.k_amount,
    }
}

/// Derive the output public key `O = ho*G + B + y*T`.
///
/// Validates that `spend_key` decompresses to a prime-order point (not identity).
pub fn derive_output_key(
    combined_ss: &[u8; 64],
    spend_key: &[u8; 32],
    output_index: u64,
) -> Result<[u8; 32], CryptoError> {
    let b_point = CompressedEdwardsY(*spend_key)
        .decompress()
        .ok_or(CryptoError::InvalidKeyMaterial)?;
    if b_point == EdwardsPoint::default() {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    if !b_point.is_torsion_free() {
        return Err(CryptoError::InvalidKeyMaterial);
    }

    let secrets = derive_output_secrets(combined_ss, output_index);

    let ho: Scalar = Option::from(Scalar::from_canonical_bytes(secrets.ho))
        .expect("ho from wide_reduce is always canonical");
    let y_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(secrets.y))
        .expect("y from wide_reduce is always canonical");

    let output_point = (G * ho) + b_point + (*T * y_scalar);
    Ok(output_point.compress().to_bytes())
}

/// Recover the recipient's spend public key `B' = O - ho*G - y*T`.
///
/// Validates that the recovered `B'` is on the prime-order subgroup and
/// is not identity before returning.
pub fn recover_recipient_spend_pubkey(
    combined_ss: &[u8; 64],
    output_key: &[u8; 32],
    output_index: u64,
) -> Result<[u8; 32], CryptoError> {
    let o_point = CompressedEdwardsY(*output_key)
        .decompress()
        .ok_or_else(|| CryptoError::DecapsulationFailed("invalid output key point".into()))?;

    let secrets = derive_output_secrets(combined_ss, output_index);

    let ho: Scalar = Option::from(Scalar::from_canonical_bytes(secrets.ho))
        .expect("ho from wide_reduce is always canonical");
    let y_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(secrets.y))
        .expect("y from wide_reduce is always canonical");

    let recovered_b = o_point - (G * ho) - (*T * y_scalar);

    if recovered_b == EdwardsPoint::default() {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    if !recovered_b.is_torsion_free() {
        return Err(CryptoError::InvalidKeyMaterial);
    }

    Ok(recovered_b.compress().to_bytes())
}

/// Decrypt the amount from `enc_amount` using secrets derived from `combined_ss`.
///
/// Verifies the `amount_tag` before returning. Returns `Err` if the tag
/// doesn't match (possible KEM corruption or tampering).
pub fn decrypt_amount(
    combined_ss: &[u8; 64],
    enc_amount: &[u8; 8],
    amount_tag: u8,
    output_index: u64,
) -> Result<u64, CryptoError> {
    let secrets = derive_output_secrets(combined_ss, output_index);

    if secrets.amount_tag != amount_tag {
        return Err(CryptoError::DecapsulationFailed(
            "amount_tag mismatch — possible KEM ciphertext corruption or tampering".into(),
        ));
    }

    let mut amount_le = [0u8; 8];
    for i in 0..8 {
        amount_le[i] = enc_amount[i] ^ secrets.k_amount[i];
    }
    Ok(u64::from_le_bytes(amount_le))
}

/// Result of key image computation.
pub struct KeyImageResult {
    /// Key image `I = x * Hp(O)` where `x = ho + b`.
    pub key_image: [u8; 32],
    /// Output spend secret `x = ho + b` (needed by `inSk[i].dest` at signing).
    pub spend_secret_x: zeroize::Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for KeyImageResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        struct HexBytes<'a>(&'a [u8]);
        impl std::fmt::Debug for HexBytes<'_> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                for b in self.0 {
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
        }
        f.debug_struct("KeyImageResult")
            .field("key_image", &HexBytes(&self.key_image))
            .field("spend_secret_x", &"[REDACTED]")
            .finish()
    }
}

/// Compute the key image and output spend secret for a V3 output.
///
/// Derives `ho` internally from `combined_ss` -- `ho` never crosses FFI.
/// Returns both the key image `I = x * Hp(O)` and the output spend secret
/// `x = ho + b` (needed for signing).
///
/// `hp_of_output` is `Hp(O)` precomputed by C++ via `hash_to_ec` (Category 2
/// Keccak, stays in C++). Must decompress to a prime-order point.
pub fn compute_output_key_image(
    combined_ss: &[u8; 64],
    output_index: u64,
    spend_secret: &[u8; 32],
    hp_of_output: &[u8; 32],
) -> Result<KeyImageResult, CryptoError> {
    let hp_point = CompressedEdwardsY(*hp_of_output)
        .decompress()
        .ok_or(CryptoError::InvalidKeyMaterial)?;
    if hp_point == EdwardsPoint::default() {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    if !hp_point.is_torsion_free() {
        return Err(CryptoError::InvalidKeyMaterial);
    }

    let secrets = derive_output_secrets(combined_ss, output_index);
    let ho: Scalar = Option::from(Scalar::from_canonical_bytes(secrets.ho))
        .expect("ho from wide_reduce is always canonical");

    let b_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(*spend_secret))
        .ok_or(CryptoError::InvalidKeyMaterial)?;

    let x = ho + b_scalar;
    let key_image = (x * hp_point).compress().to_bytes();

    let mut x_bytes = zeroize::Zeroizing::new(x.to_bytes());

    let result = KeyImageResult {
        key_image,
        spend_secret_x: x_bytes.clone(),
    };

    x_bytes.zeroize();

    Ok(result)
}

/// Compute key image from pre-derived `ho` (for `tx_source_entry` boundary).
///
/// Same as `compute_output_key_image` but takes `ho` directly instead of
/// `combined_ss`. Used at the single site where `ho` has already crossed
/// the wallet -> tx_utils boundary via `tx_source_entry`.
pub fn compute_output_key_image_from_ho(
    ho: &[u8; 32],
    spend_secret: &[u8; 32],
    hp_of_output: &[u8; 32],
) -> Result<KeyImageResult, CryptoError> {
    let hp_point = CompressedEdwardsY(*hp_of_output)
        .decompress()
        .ok_or(CryptoError::InvalidKeyMaterial)?;
    if hp_point == EdwardsPoint::default() {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    if !hp_point.is_torsion_free() {
        return Err(CryptoError::InvalidKeyMaterial);
    }

    let ho_scalar: Scalar =
        Option::from(Scalar::from_canonical_bytes(*ho)).ok_or(CryptoError::InvalidKeyMaterial)?;
    let b_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(*spend_secret))
        .ok_or(CryptoError::InvalidKeyMaterial)?;

    let x = ho_scalar + b_scalar;
    let key_image = (x * hp_point).compress().to_bytes();

    let mut x_bytes = zeroize::Zeroizing::new(x.to_bytes());

    let result = KeyImageResult {
        key_image,
        spend_secret_x: x_bytes.clone(),
    };

    x_bytes.zeroize();

    Ok(result)
}

/// Internal helper: derive ML-DSA-65 keypair from seed bytes, returning
/// serialized public and secret key.
fn keygen_from_seed_bytes(ml_dsa_seed: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    use fips204::traits::SerDes;
    let (pk, sk) = keygen_from_seed(ml_dsa_seed)?;
    let pk_bytes: Vec<u8> = pk.into_bytes().to_vec();
    let sk_bytes: Vec<u8> = sk.into_bytes().to_vec();
    Ok((pk_bytes, sk_bytes))
}

/// Compute h_pqc from the full hybrid public key (Ed25519 + ML-DSA),
/// matching what the verifier computes from `tx.pqc_auths[i].hybrid_public_key`.
fn compute_hybrid_h_pqc(secrets: &OutputSecrets) -> Result<[u8; 32], CryptoError> {
    use crate::signature::HybridPublicKey;
    use ed25519_dalek::SigningKey;

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

    let pk_bytes = hybrid_pk
        .to_canonical_bytes()
        .map_err(|e| CryptoError::KeyGenerationFailed(format!("hybrid PK encoding: {e}")))?;

    Ok(hash_pqc_public_key(&pk_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::{HybridX25519MlKem, KeyEncapsulation};

    fn random_tx_key() -> [u8; 32] {
        Scalar::random(&mut rand::rngs::OsRng).to_bytes()
    }

    #[test]
    fn construct_scan_round_trip() {
        let kem = HybridX25519MlKem;
        let (recipient_pk, recipient_sk) = kem.keypair_generate().unwrap();

        let tx_key = random_tx_key();
        let spend_scalar = Scalar::random(&mut rand::rngs::OsRng);
        let spend_point = G * spend_scalar;
        let spend_key = spend_point.compress().to_bytes();

        let amount = 1_000_000_000u64;
        let output_index = 0u64;

        let out = construct_output(
            &tx_key,
            &recipient_pk.x25519,
            &recipient_pk.ml_kem,
            &spend_key,
            amount,
            output_index,
        )
        .expect("construct_output should succeed");

        assert_ne!(out.output_key, [0u8; 32], "O must not be zero");
        assert_ne!(out.commitment, [0u8; 32], "C must not be zero");
        assert!(!out.pqc_public_key.is_empty(), "PQC pk must be non-empty");
        assert_ne!(out.h_pqc, [0u8; 32], "h_pqc must not be zero");

        let scanned = scan_output(
            &recipient_sk.x25519,
            &recipient_sk.ml_kem,
            &out.kem_ciphertext_x25519,
            &out.kem_ciphertext_ml_kem,
            &out.output_key,
            &out.commitment,
            &out.enc_amount,
            out.amount_tag,
            out.view_tag_x25519,
            &spend_key,
            output_index,
        )
        .expect("scan_output should succeed");

        assert_eq!(scanned.amount, amount, "recovered amount must match");
        assert_eq!(scanned.y, out.y, "scanner y must match sender y");
        assert_eq!(scanned.z, out.z, "scanner z must match sender z");
        assert_eq!(
            scanned.k_amount, out.k_amount,
            "scanner k_amount must match"
        );
        assert_eq!(
            scanned.pqc_public_key, out.pqc_public_key,
            "PQC pk must match"
        );
        assert_eq!(scanned.h_pqc, out.h_pqc, "h_pqc must match");
        assert!(
            !scanned.pqc_secret_key.is_empty(),
            "PQC sk must be non-empty"
        );
    }

    #[test]
    fn construct_scan_multiple_outputs() {
        let kem = HybridX25519MlKem;
        let (recipient_pk, recipient_sk) = kem.keypair_generate().unwrap();

        let tx_key = random_tx_key();
        let spend_scalar = Scalar::random(&mut rand::rngs::OsRng);
        let spend_key = (G * spend_scalar).compress().to_bytes();

        for idx in 0..4u64 {
            let amount = 100_000 * (idx + 1);
            let out = construct_output(
                &tx_key,
                &recipient_pk.x25519,
                &recipient_pk.ml_kem,
                &spend_key,
                amount,
                idx,
            )
            .unwrap();

            let scanned = scan_output(
                &recipient_sk.x25519,
                &recipient_sk.ml_kem,
                &out.kem_ciphertext_x25519,
                &out.kem_ciphertext_ml_kem,
                &out.output_key,
                &out.commitment,
                &out.enc_amount,
                out.amount_tag,
                out.view_tag_x25519,
                &spend_key,
                idx,
            )
            .unwrap();

            assert_eq!(scanned.amount, amount, "amount mismatch at index {idx}");
        }
    }

    #[test]
    fn scan_wrong_spend_key_fails() {
        let kem = HybridX25519MlKem;
        let (recipient_pk, recipient_sk) = kem.keypair_generate().unwrap();

        let tx_key = random_tx_key();
        let spend_key = (G * Scalar::random(&mut rand::rngs::OsRng))
            .compress()
            .to_bytes();
        let wrong_spend_key = (G * Scalar::random(&mut rand::rngs::OsRng))
            .compress()
            .to_bytes();

        let out = construct_output(
            &tx_key,
            &recipient_pk.x25519,
            &recipient_pk.ml_kem,
            &spend_key,
            500,
            0,
        )
        .unwrap();

        let result = scan_output(
            &recipient_sk.x25519,
            &recipient_sk.ml_kem,
            &out.kem_ciphertext_x25519,
            &out.kem_ciphertext_ml_kem,
            &out.output_key,
            &out.commitment,
            &out.enc_amount,
            out.amount_tag,
            out.view_tag_x25519,
            &wrong_spend_key,
            0,
        );

        assert!(result.is_err(), "scan with wrong spend key must fail");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("output key mismatch"),
            "expected output key mismatch error, got: {err_msg}"
        );
    }

    #[test]
    fn scan_wrong_kem_key_view_tag_mismatch() {
        let kem = HybridX25519MlKem;
        let (recipient_pk, _) = kem.keypair_generate().unwrap();
        let (_, wrong_sk) = kem.keypair_generate().unwrap();

        let tx_key = random_tx_key();
        let spend_key = (G * Scalar::random(&mut rand::rngs::OsRng))
            .compress()
            .to_bytes();

        let out = construct_output(
            &tx_key,
            &recipient_pk.x25519,
            &recipient_pk.ml_kem,
            &spend_key,
            1000,
            0,
        )
        .unwrap();

        let result = scan_output(
            &wrong_sk.x25519,
            &wrong_sk.ml_kem,
            &out.kem_ciphertext_x25519,
            &out.kem_ciphertext_ml_kem,
            &out.output_key,
            &out.commitment,
            &out.enc_amount,
            out.amount_tag,
            out.view_tag_x25519,
            &spend_key,
            0,
        );

        assert!(result.is_err(), "scan with wrong KEM key must fail");
    }

    #[test]
    fn scan_tampered_amount_tag_fails() {
        let kem = HybridX25519MlKem;
        let (recipient_pk, recipient_sk) = kem.keypair_generate().unwrap();

        let tx_key = random_tx_key();
        let spend_key = (G * Scalar::random(&mut rand::rngs::OsRng))
            .compress()
            .to_bytes();

        let out = construct_output(
            &tx_key,
            &recipient_pk.x25519,
            &recipient_pk.ml_kem,
            &spend_key,
            7777,
            0,
        )
        .unwrap();

        let bad_tag = out.amount_tag.wrapping_add(1);
        let result = scan_output(
            &recipient_sk.x25519,
            &recipient_sk.ml_kem,
            &out.kem_ciphertext_x25519,
            &out.kem_ciphertext_ml_kem,
            &out.output_key,
            &out.commitment,
            &out.enc_amount,
            bad_tag,
            out.view_tag_x25519,
            &spend_key,
            0,
        );

        assert!(result.is_err(), "tampered amount tag must be detected");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("amount_tag mismatch"),
            "expected amount_tag error, got: {err_msg}"
        );
    }

    #[test]
    fn construct_rejects_identity_spend_key() {
        let kem = HybridX25519MlKem;
        let (pk, _) = kem.keypair_generate().unwrap();

        let tx_key = random_tx_key();
        let identity = EdwardsPoint::default().compress().to_bytes();
        let result = construct_output(&tx_key, &pk.x25519, &pk.ml_kem, &identity, 100, 0);
        assert!(result.is_err(), "identity spend key must be rejected");
    }

    #[test]
    fn construct_rejects_invalid_spend_key() {
        let kem = HybridX25519MlKem;
        let (pk, _) = kem.keypair_generate().unwrap();

        let tx_key = random_tx_key();
        let garbage = [0xFFu8; 32];
        let result = construct_output(&tx_key, &pk.x25519, &pk.ml_kem, &garbage, 100, 0);
        assert!(result.is_err(), "garbage spend key must be rejected");
    }

    #[test]
    fn zero_amount_round_trip() {
        let kem = HybridX25519MlKem;
        let (pk, sk) = kem.keypair_generate().unwrap();

        let spend_key = (G * Scalar::random(&mut rand::rngs::OsRng))
            .compress()
            .to_bytes();

        let tx_key = random_tx_key();
        let out = construct_output(&tx_key, &pk.x25519, &pk.ml_kem, &spend_key, 0, 0).unwrap();

        let scanned = scan_output(
            &sk.x25519,
            &sk.ml_kem,
            &out.kem_ciphertext_x25519,
            &out.kem_ciphertext_ml_kem,
            &out.output_key,
            &out.commitment,
            &out.enc_amount,
            out.amount_tag,
            out.view_tag_x25519,
            &spend_key,
            0,
        )
        .unwrap();

        assert_eq!(scanned.amount, 0);
    }

    #[test]
    fn max_amount_round_trip() {
        let kem = HybridX25519MlKem;
        let (pk, sk) = kem.keypair_generate().unwrap();

        let tx_key = random_tx_key();
        let spend_key = (G * Scalar::random(&mut rand::rngs::OsRng))
            .compress()
            .to_bytes();

        let out =
            construct_output(&tx_key, &pk.x25519, &pk.ml_kem, &spend_key, u64::MAX, 0).unwrap();

        let scanned = scan_output(
            &sk.x25519,
            &sk.ml_kem,
            &out.kem_ciphertext_x25519,
            &out.kem_ciphertext_ml_kem,
            &out.output_key,
            &out.commitment,
            &out.enc_amount,
            out.amount_tag,
            out.view_tag_x25519,
            &spend_key,
            0,
        )
        .unwrap();

        assert_eq!(scanned.amount, u64::MAX);
    }

    #[test]
    fn different_indices_produce_different_outputs() {
        let kem = HybridX25519MlKem;
        let (pk, _) = kem.keypair_generate().unwrap();

        let tx_key = random_tx_key();
        let spend_key = (G * Scalar::random(&mut rand::rngs::OsRng))
            .compress()
            .to_bytes();

        let out0 = construct_output(&tx_key, &pk.x25519, &pk.ml_kem, &spend_key, 100, 0).unwrap();
        let out1 = construct_output(&tx_key, &pk.x25519, &pk.ml_kem, &spend_key, 100, 1).unwrap();

        assert_ne!(
            out0.output_key, out1.output_key,
            "different indices must produce different O"
        );
        assert_ne!(
            out0.commitment, out1.commitment,
            "different indices must produce different C"
        );
        assert_ne!(
            out0.h_pqc, out1.h_pqc,
            "different indices must produce different h_pqc"
        );
    }

    #[test]
    fn sign_pqc_auth_round_trip() {
        use crate::signature::{
            HybridEd25519MlDsa, HybridPublicKey, HybridSignature, SignatureScheme,
        };

        let kem = HybridX25519MlKem;
        let (pk, sk) = kem.keypair_generate().unwrap();

        let tx_key = random_tx_key();
        let spend_key = (G * Scalar::random(&mut rand::rngs::OsRng))
            .compress()
            .to_bytes();

        let out = construct_output(&tx_key, &pk.x25519, &pk.ml_kem, &spend_key, 999, 0).unwrap();

        let scanned = scan_output(
            &sk.x25519,
            &sk.ml_kem,
            &out.kem_ciphertext_x25519,
            &out.kem_ciphertext_ml_kem,
            &out.output_key,
            &out.commitment,
            &out.enc_amount,
            out.amount_tag,
            out.view_tag_x25519,
            &spend_key,
            0,
        )
        .unwrap();

        // Recover the combined_ss by re-decapsulating (in real wallet this is cached)
        let view_scalar = Scalar::from_bytes_mod_order(sk.x25519);
        let eph_mont = MontgomeryPoint(out.kem_ciphertext_x25519);
        let x25519_raw_ss = &view_scalar * &eph_mont;

        let dk_bytes: [u8; ML_KEM_768_DK_LEN] = sk.ml_kem.as_slice().try_into().unwrap();
        let dk = ml_kem_768::DecapsKey::try_from_bytes(dk_bytes).unwrap();
        let ct_bytes: [u8; ML_KEM_768_CT_LEN] =
            out.kem_ciphertext_ml_kem.as_slice().try_into().unwrap();
        let ct = ml_kem_768::CipherText::try_from_bytes(ct_bytes).unwrap();
        let ml_ss = dk.try_decaps(&ct).unwrap();
        let combined_ss =
            combine_shared_secrets(&x25519_raw_ss.0, &ml_ss.into_bytes()).unwrap();

        let msg = b"test signing message";
        let auth = sign_pqc_auth_for_output(&combined_ss.0, 0, msg)
            .expect("sign_pqc_auth_for_output must succeed");

        // Verify the signature
        let hybrid_pk = HybridPublicKey::from_canonical_bytes(&auth.hybrid_public_key)
            .expect("hybrid pk must be parseable");
        let hybrid_sig = HybridSignature::from_canonical_bytes(&auth.signature)
            .expect("hybrid sig must be parseable");

        let scheme = HybridEd25519MlDsa;
        let ok = scheme
            .verify(&hybrid_pk, msg, &hybrid_sig)
            .expect("verify must not error");
        assert!(ok, "signature must verify");

        // h_pqc from construct/scan must match what the verifier computes
        // from the signing path's hybrid public key.
        let h_pqc_from_sign = crate::derivation::hash_pqc_public_key(&auth.hybrid_public_key);
        assert_eq!(
            scanned.h_pqc, out.h_pqc,
            "scanner h_pqc must match sender h_pqc"
        );
        assert_eq!(
            out.h_pqc, h_pqc_from_sign,
            "construct h_pqc must match hash of signing hybrid pk"
        );
    }

    #[test]
    fn h_pqc_matches_hybrid_pk_hash() {
        use crate::derivation::{derive_pqc_leaf_hash, hash_pqc_public_key};
        use crate::kem::combine_shared_secrets;

        let kem = HybridX25519MlKem;
        let (pk, sk) = kem.keypair_generate().unwrap();

        let tx_key = random_tx_key();
        let spend_key = (G * Scalar::random(&mut rand::rngs::OsRng))
            .compress()
            .to_bytes();

        let out = construct_output(&tx_key, &pk.x25519, &pk.ml_kem, &spend_key, 500, 0).unwrap();

        // h_pqc must NOT equal hash of just ML-DSA pk (that was the old bug)
        let h_pqc_ml_dsa_only = hash_pqc_public_key(&out.pqc_public_key);
        assert_ne!(
            out.h_pqc, h_pqc_ml_dsa_only,
            "h_pqc must hash the full hybrid pk, not just ML-DSA"
        );

        let scanned = scan_output(
            &sk.x25519,
            &sk.ml_kem,
            &out.kem_ciphertext_x25519,
            &out.kem_ciphertext_ml_kem,
            &out.output_key,
            &out.commitment,
            &out.enc_amount,
            out.amount_tag,
            out.view_tag_x25519,
            &spend_key,
            0,
        )
        .unwrap();

        assert_eq!(
            scanned.h_pqc, out.h_pqc,
            "scanner h_pqc must match sender h_pqc"
        );

        // Also verify via derive_pqc_leaf_hash (the standalone derivation path)
        let view_scalar = Scalar::from_bytes_mod_order(sk.x25519);
        let eph_mont = MontgomeryPoint(out.kem_ciphertext_x25519);
        let x25519_raw_ss = &view_scalar * &eph_mont;
        let dk_bytes: [u8; ML_KEM_768_DK_LEN] = sk.ml_kem.as_slice().try_into().unwrap();
        let dk = ml_kem_768::DecapsKey::try_from_bytes(dk_bytes).unwrap();
        let ct_bytes: [u8; ML_KEM_768_CT_LEN] =
            out.kem_ciphertext_ml_kem.as_slice().try_into().unwrap();
        let ct = ml_kem_768::CipherText::try_from_bytes(ct_bytes).unwrap();
        let ml_ss = dk.try_decaps(&ct).unwrap();
        let combined_ss =
            combine_shared_secrets(&x25519_raw_ss.0, &ml_ss.into_bytes()).unwrap();
        let h_pqc_derived = derive_pqc_leaf_hash(&combined_ss.0, 0).unwrap();
        assert_eq!(
            out.h_pqc, h_pqc_derived,
            "h_pqc must match derive_pqc_leaf_hash"
        );
    }

    // ── Phase 1 tests: determinism, rederive, proof_secrets, key image ──

    #[test]
    fn construct_output_is_deterministic() {
        let kem = HybridX25519MlKem;
        let (pk, _) = kem.keypair_generate().unwrap();

        let tx_key = random_tx_key();
        let spend_key = (G * Scalar::random(&mut rand::rngs::OsRng))
            .compress()
            .to_bytes();

        let out1 = construct_output(&tx_key, &pk.x25519, &pk.ml_kem, &spend_key, 42, 7).unwrap();
        let out2 = construct_output(&tx_key, &pk.x25519, &pk.ml_kem, &spend_key, 42, 7).unwrap();

        assert_eq!(out1.output_key, out2.output_key, "O must be deterministic");
        assert_eq!(out1.commitment, out2.commitment, "C must be deterministic");
        assert_eq!(
            out1.enc_amount, out2.enc_amount,
            "enc_amount must be deterministic"
        );
        assert_eq!(
            out1.amount_tag, out2.amount_tag,
            "amount_tag must be deterministic"
        );
        assert_eq!(
            out1.view_tag_x25519, out2.view_tag_x25519,
            "view_tag must be deterministic"
        );
        assert_eq!(
            out1.kem_ciphertext_x25519, out2.kem_ciphertext_x25519,
            "X25519 eph pk must be deterministic"
        );
        assert_eq!(
            out1.kem_ciphertext_ml_kem, out2.kem_ciphertext_ml_kem,
            "ML-KEM CT must be deterministic"
        );
        assert_eq!(
            out1.pqc_public_key, out2.pqc_public_key,
            "PQC pk must be deterministic"
        );
        assert_eq!(out1.h_pqc, out2.h_pqc, "h_pqc must be deterministic");
        assert_eq!(out1.y, out2.y, "y must be deterministic");
        assert_eq!(out1.z, out2.z, "z must be deterministic");
        assert_eq!(
            out1.k_amount, out2.k_amount,
            "k_amount must be deterministic"
        );
    }

    #[test]
    fn rederive_combined_ss_matches_construct() {
        let kem = HybridX25519MlKem;
        let (pk, _sk) = kem.keypair_generate().unwrap();

        let tx_key = random_tx_key();
        let spend_key = (G * Scalar::random(&mut rand::rngs::OsRng))
            .compress()
            .to_bytes();
        let amount = 500_000u64;
        let idx = 3u64;

        let out =
            construct_output(&tx_key, &pk.x25519, &pk.ml_kem, &spend_key, amount, idx).unwrap();

        let (ss_re, x25519_eph_re, ml_kem_ct_re) =
            rederive_combined_ss(&tx_key, &pk.x25519, &pk.ml_kem, idx).unwrap();

        assert_eq!(
            x25519_eph_re, out.kem_ciphertext_x25519,
            "rederived X25519 eph pk must match on-chain ciphertext"
        );
        assert_eq!(
            ml_kem_ct_re, out.kem_ciphertext_ml_kem,
            "rederived ML-KEM CT must match on-chain ciphertext"
        );

        let derived_o = derive_output_key(&ss_re.0, &spend_key, idx).unwrap();
        assert_eq!(
            derived_o, out.output_key,
            "rederived combined_ss must produce same output key as construct"
        );

        let ps = derive_proof_secrets(&ss_re.0, idx);
        assert_eq!(ps.y, out.y, "rederived y must match construct");
        assert_eq!(ps.z, out.z, "rederived z must match construct");
        assert_eq!(
            ps.k_amount, out.k_amount,
            "rederived k_amount must match construct"
        );
    }

    #[test]
    fn derive_proof_secrets_narrow_projection() {
        let kem = HybridX25519MlKem;
        let (pk, _) = kem.keypair_generate().unwrap();

        let tx_key = random_tx_key();
        let idx = 0u64;

        let (ss, _, _) = rederive_combined_ss(&tx_key, &pk.x25519, &pk.ml_kem, idx).unwrap();

        let ps = derive_proof_secrets(&ss.0, idx);

        assert_ne!(ps.ho, [0u8; 32], "ho must not be zero");
        assert_ne!(ps.y, [0u8; 32], "y must not be zero");
        assert_ne!(ps.z, [0u8; 32], "z must not be zero");
        assert_ne!(ps.k_amount, [0u8; 32], "k_amount must not be zero");

        let full_secrets = crate::derivation::derive_output_secrets(&ss.0, idx);
        assert_eq!(
            ps.ho, full_secrets.ho,
            "ProofSecrets.ho must equal OutputSecrets.ho"
        );
        assert_eq!(
            ps.y, full_secrets.y,
            "ProofSecrets.y must equal OutputSecrets.y"
        );
        assert_eq!(
            ps.z, full_secrets.z,
            "ProofSecrets.z must equal OutputSecrets.z"
        );
        assert_eq!(
            ps.k_amount, full_secrets.k_amount,
            "ProofSecrets.k_amount must equal OutputSecrets.k_amount"
        );
    }

    #[test]
    fn derive_output_key_matches_construct() {
        let kem = HybridX25519MlKem;
        let (pk, _) = kem.keypair_generate().unwrap();

        let tx_key = random_tx_key();
        let spend_key = (G * Scalar::random(&mut rand::rngs::OsRng))
            .compress()
            .to_bytes();

        for idx in 0..4u64 {
            let out =
                construct_output(&tx_key, &pk.x25519, &pk.ml_kem, &spend_key, 1000, idx).unwrap();

            let (ss, _, _) = rederive_combined_ss(&tx_key, &pk.x25519, &pk.ml_kem, idx).unwrap();

            let derived_o = derive_output_key(&ss.0, &spend_key, idx).unwrap();
            assert_eq!(
                derived_o, out.output_key,
                "derive_output_key must match construct_output's O at index {idx}"
            );
        }
    }

    #[test]
    fn derive_output_key_rejects_identity() {
        let fake_ss = [0x42u8; 64];
        let identity = EdwardsPoint::default().compress().to_bytes();

        let result = derive_output_key(&fake_ss, &identity, 0);
        assert!(result.is_err(), "identity spend key must be rejected");
        eprintln!(
            "derive_output_key identity rejection: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    fn derive_output_key_rejects_torsion_point() {
        let fake_ss = [0x42u8; 64];

        // Small-order torsion point (order 8): the bytes of the
        // non-trivial low-order point on Curve25519.
        let torsion_bytes: [u8; 32] = {
            let mut b = [0u8; 32];
            // c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa
            // is a well-known small-order point
            let hex = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa";
            for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
                b[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
            }
            b
        };

        if let Some(pt) = CompressedEdwardsY(torsion_bytes).decompress() {
            if !pt.is_torsion_free() {
                let result = derive_output_key(&fake_ss, &torsion_bytes, 0);
                assert!(result.is_err(), "torsion point spend key must be rejected");
                eprintln!(
                    "derive_output_key torsion rejection: {:?}",
                    result.unwrap_err()
                );
            }
        }
    }

    #[test]
    fn recover_spend_pubkey_round_trip() {
        let kem = HybridX25519MlKem;
        let (pk, _) = kem.keypair_generate().unwrap();

        let tx_key = random_tx_key();
        let spend_key = (G * Scalar::random(&mut rand::rngs::OsRng))
            .compress()
            .to_bytes();

        for idx in 0..3u64 {
            let (ss, _, _) = rederive_combined_ss(&tx_key, &pk.x25519, &pk.ml_kem, idx).unwrap();

            let output_key = derive_output_key(&ss.0, &spend_key, idx).unwrap();
            let recovered_b = recover_recipient_spend_pubkey(&ss.0, &output_key, idx).unwrap();

            assert_eq!(
                recovered_b, spend_key,
                "recovered spend pubkey must match original at index {idx}"
            );
        }
    }

    #[test]
    fn decrypt_amount_round_trip() {
        let kem = HybridX25519MlKem;
        let (pk, _) = kem.keypair_generate().unwrap();

        let tx_key = random_tx_key();
        let spend_key = (G * Scalar::random(&mut rand::rngs::OsRng))
            .compress()
            .to_bytes();

        let amounts = [0u64, 1, 999, 1_000_000_000, u64::MAX];
        for (idx, &amount) in amounts.iter().enumerate() {
            let out = construct_output(
                &tx_key, &pk.x25519, &pk.ml_kem, &spend_key, amount, idx as u64,
            )
            .unwrap();

            let (ss, _, _) =
                rederive_combined_ss(&tx_key, &pk.x25519, &pk.ml_kem, idx as u64).unwrap();

            let decrypted =
                decrypt_amount(&ss.0, &out.enc_amount, out.amount_tag, idx as u64).unwrap();
            assert_eq!(
                decrypted, amount,
                "decrypted amount must match original (amount={amount}, idx={idx})"
            );
        }
    }

    #[test]
    fn decrypt_amount_wrong_tag_fails() {
        let kem = HybridX25519MlKem;
        let (pk, _) = kem.keypair_generate().unwrap();

        let tx_key = random_tx_key();
        let spend_key = (G * Scalar::random(&mut rand::rngs::OsRng))
            .compress()
            .to_bytes();

        let out = construct_output(&tx_key, &pk.x25519, &pk.ml_kem, &spend_key, 12345, 0).unwrap();

        let (ss, _, _) = rederive_combined_ss(&tx_key, &pk.x25519, &pk.ml_kem, 0).unwrap();

        let bad_tag = out.amount_tag.wrapping_add(1);
        let result = decrypt_amount(&ss.0, &out.enc_amount, bad_tag, 0);
        assert!(result.is_err(), "wrong amount_tag must be rejected");
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("amount_tag mismatch"),
            "expected amount_tag mismatch error, got: {err}"
        );
    }

    /// Helper: get `combined_ss` and a valid `Hp(O)` point for key image tests.
    fn setup_key_image_test() -> (
        [u8; 64], // combined_ss
        [u8; 32], // spend_secret (scalar b)
        [u8; 32], // output_key O
        [u8; 32], // hp_of_output (a valid prime-order point, NOT real hash_to_ec)
        u64,      // output_index
    ) {
        let kem = HybridX25519MlKem;
        let (pk, _) = kem.keypair_generate().unwrap();

        let tx_key = random_tx_key();
        let spend_scalar = Scalar::random(&mut rand::rngs::OsRng);
        let spend_key = (G * spend_scalar).compress().to_bytes();
        let idx = 2u64;

        let out = construct_output(&tx_key, &pk.x25519, &pk.ml_kem, &spend_key, 1000, idx).unwrap();

        let (ss, _, _) = rederive_combined_ss(&tx_key, &pk.x25519, &pk.ml_kem, idx).unwrap();

        // Use a deterministic stand-in for Hp(O): hash output_key to a curve point
        // In production, C++ provides this via hash_to_ec. For testing, we use
        // the basepoint scaled by a hash (guaranteed prime-order and non-identity).
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"test-hp-of-output");
        hasher.update(&out.output_key);
        let hash: [u8; 32] = hasher.finalize().into();
        let hp_scalar = Scalar::from_bytes_mod_order(hash);
        let hp_point = (G * hp_scalar).compress().to_bytes();

        (ss.0, spend_scalar.to_bytes(), out.output_key, hp_point, idx)
    }

    #[test]
    fn key_image_both_variants_agree() {
        let (combined_ss, spend_secret, _output_key, hp_of_output, idx) = setup_key_image_test();

        let from_ss =
            compute_output_key_image(&combined_ss, idx, &spend_secret, &hp_of_output).unwrap();

        let ps = derive_proof_secrets(&combined_ss, idx);
        let from_ho =
            compute_output_key_image_from_ho(&ps.ho, &spend_secret, &hp_of_output).unwrap();

        assert_eq!(
            from_ss.key_image, from_ho.key_image,
            "compute_output_key_image and _from_ho must produce identical key images"
        );
        assert_eq!(
            from_ss.spend_secret_x.as_ref(),
            from_ho.spend_secret_x.as_ref(),
            "both variants must produce identical spend_secret_x"
        );
    }

    #[test]
    fn key_image_is_deterministic() {
        let (combined_ss, spend_secret, _output_key, hp_of_output, idx) = setup_key_image_test();

        let r1 = compute_output_key_image(&combined_ss, idx, &spend_secret, &hp_of_output).unwrap();
        let r2 = compute_output_key_image(&combined_ss, idx, &spend_secret, &hp_of_output).unwrap();

        assert_eq!(
            r1.key_image, r2.key_image,
            "key image must be deterministic"
        );
        assert_eq!(
            r1.spend_secret_x.as_ref(),
            r2.spend_secret_x.as_ref(),
            "spend_secret_x must be deterministic"
        );
    }

    #[test]
    fn key_image_rejects_identity_hp() {
        let (combined_ss, spend_secret, _, _, idx) = setup_key_image_test();

        let identity = EdwardsPoint::default().compress().to_bytes();
        let result = compute_output_key_image(&combined_ss, idx, &spend_secret, &identity);
        assert!(result.is_err(), "identity Hp(O) must be rejected");
        eprintln!(
            "key_image identity Hp(O) rejection: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    fn key_image_rejects_non_canonical_spend_secret() {
        let (combined_ss, _, _, hp_of_output, idx) = setup_key_image_test();

        // L (the group order) is NOT a valid canonical scalar
        let l_bytes: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];

        let result = compute_output_key_image(&combined_ss, idx, &l_bytes, &hp_of_output);
        assert!(
            result.is_err(),
            "non-canonical spend secret must be rejected"
        );
        eprintln!(
            "key_image non-canonical rejection: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    fn full_proof_pipeline_end_to_end() {
        let kem = HybridX25519MlKem;
        let (pk, sk) = kem.keypair_generate().unwrap();

        let tx_key = random_tx_key();
        let spend_scalar = Scalar::random(&mut rand::rngs::OsRng);
        let spend_key = (G * spend_scalar).compress().to_bytes();
        let amount = 7_500_000u64;
        let idx = 1u64;

        // Step 1: Sender constructs output
        let out =
            construct_output(&tx_key, &pk.x25519, &pk.ml_kem, &spend_key, amount, idx).unwrap();
        eprintln!(
            "[pipeline] constructed output O={}",
            hex::encode(out.output_key)
        );

        // Step 2: Sender rederives combined_ss from tx_key (outbound proof path)
        let (ss_re, x25519_eph_re, ml_kem_ct_re) =
            rederive_combined_ss(&tx_key, &pk.x25519, &pk.ml_kem, idx).unwrap();
        assert_eq!(
            x25519_eph_re, out.kem_ciphertext_x25519,
            "KEM CT X25519 integrity"
        );
        assert_eq!(
            ml_kem_ct_re, out.kem_ciphertext_ml_kem,
            "KEM CT ML-KEM integrity"
        );
        eprintln!("[pipeline] rederived combined_ss, KEM CT matches on-chain");

        // Step 3: Derive proof secrets (narrow projection)
        let ps = derive_proof_secrets(&ss_re.0, idx);
        assert_eq!(ps.y, out.y, "proof_secrets.y must match construct y");
        assert_eq!(ps.z, out.z, "proof_secrets.z must match construct z");
        assert_eq!(
            ps.k_amount, out.k_amount,
            "proof_secrets.k_amount must match construct k_amount"
        );
        eprintln!("[pipeline] derived ProofSecrets (ho, y, z, k_amount)");

        // Step 4: Derive output key and verify
        let derived_o = derive_output_key(&ss_re.0, &spend_key, idx).unwrap();
        assert_eq!(derived_o, out.output_key, "derived O must match");
        eprintln!("[pipeline] derive_output_key matches construct");

        // Step 5: Recover spend pubkey
        let recovered_b = recover_recipient_spend_pubkey(&ss_re.0, &out.output_key, idx).unwrap();
        assert_eq!(
            recovered_b, spend_key,
            "recovered B' must match original spend key"
        );
        eprintln!("[pipeline] recover_recipient_spend_pubkey round-trips");

        // Step 6: Decrypt amount
        let decrypted = decrypt_amount(&ss_re.0, &out.enc_amount, out.amount_tag, idx).unwrap();
        assert_eq!(decrypted, amount, "decrypted amount must match");
        eprintln!("[pipeline] decrypt_amount = {decrypted}");

        // Step 7: Recipient scans and verifies
        let scanned = scan_output(
            &sk.x25519,
            &sk.ml_kem,
            &out.kem_ciphertext_x25519,
            &out.kem_ciphertext_ml_kem,
            &out.output_key,
            &out.commitment,
            &out.enc_amount,
            out.amount_tag,
            out.view_tag_x25519,
            &spend_key,
            idx,
        )
        .unwrap();
        assert_eq!(scanned.amount, amount, "scan amount must match");
        eprintln!("[pipeline] scan_output succeeds, amount={}", scanned.amount);

        // Step 8: Compute key image (using test stand-in for Hp(O))
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"test-hp-of-output");
        hasher.update(&out.output_key);
        let hash: [u8; 32] = hasher.finalize().into();
        let hp_scalar = Scalar::from_bytes_mod_order(hash);
        let hp_point = (G * hp_scalar).compress().to_bytes();

        let ki_result =
            compute_output_key_image(&ss_re.0, idx, &spend_scalar.to_bytes(), &hp_point).unwrap();

        assert_ne!(ki_result.key_image, [0u8; 32], "key image must not be zero");
        eprintln!(
            "[pipeline] key_image computed: {}",
            hex::encode(ki_result.key_image)
        );

        // Verify x = ho + b
        let ho_scalar: Scalar =
            Option::from(Scalar::from_canonical_bytes(ps.ho)).expect("ho must be canonical");
        let expected_x = ho_scalar + spend_scalar;
        assert_eq!(
            ki_result.spend_secret_x.as_ref(),
            &expected_x.to_bytes(),
            "spend_secret_x must equal ho + b"
        );

        // Verify I = x * Hp(O)
        let hp_pt = CompressedEdwardsY(hp_point).decompress().unwrap();
        let expected_ki = (expected_x * hp_pt).compress().to_bytes();
        assert_eq!(
            ki_result.key_image, expected_ki,
            "key image must equal x * Hp(O)"
        );
        eprintln!("[pipeline] key image algebraically verified: I = x * Hp(O)");

        // Step 9: Verify _from_ho variant agrees
        let ki_from_ho =
            compute_output_key_image_from_ho(&ps.ho, &spend_scalar.to_bytes(), &hp_point).unwrap();
        assert_eq!(
            ki_result.key_image, ki_from_ho.key_image,
            "_from_ho variant must produce same key image"
        );
        eprintln!("[pipeline] _from_ho variant agrees -- full pipeline passed");
    }

    #[test]
    fn different_tx_keys_produce_different_outputs() {
        let kem = HybridX25519MlKem;
        let (pk, _) = kem.keypair_generate().unwrap();

        let spend_key = (G * Scalar::random(&mut rand::rngs::OsRng))
            .compress()
            .to_bytes();

        let tx_key1 = random_tx_key();
        let tx_key2 = random_tx_key();

        let out1 = construct_output(&tx_key1, &pk.x25519, &pk.ml_kem, &spend_key, 100, 0).unwrap();
        let out2 = construct_output(&tx_key2, &pk.x25519, &pk.ml_kem, &spend_key, 100, 0).unwrap();

        assert_ne!(
            out1.output_key, out2.output_key,
            "different tx_keys must produce different O"
        );
        assert_ne!(
            out1.kem_ciphertext_x25519, out2.kem_ciphertext_x25519,
            "different tx_keys must produce different X25519 eph keys"
        );
        assert_ne!(
            out1.kem_ciphertext_ml_kem, out2.kem_ciphertext_ml_kem,
            "different tx_keys must produce different ML-KEM CTs"
        );
    }

    #[test]
    fn rederive_combined_ss_rejects_wrong_kem_ek_length() {
        let tx_key = random_tx_key();
        let x25519_pk = [0x42u8; 32];
        let bad_ek = vec![0u8; 100]; // wrong length

        let result = rederive_combined_ss(&tx_key, &x25519_pk, &bad_ek, 0);
        assert!(result.is_err(), "wrong ML-KEM EK length must be rejected");
    }

    // ======================================================================
    // Phase 10: View-key-derived X25519 round-trip and low-order rejection
    // ======================================================================

    #[test]
    fn construct_scan_round_trip_with_view_key_derived_x25519() {
        use crate::montgomery::{ed25519_pk_to_x25519_pk, ed25519_sk_as_montgomery_scalar};

        let kem = HybridX25519MlKem;

        // Generate view keypair (Ed25519)
        let view_scalar = Scalar::random(&mut rand::rngs::OsRng);
        let view_pub = (&view_scalar * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE)
            .compress();

        // Derive X25519 from the view key
        let x25519_pub = ed25519_pk_to_x25519_pk(&view_pub.0).unwrap();
        let x25519_sec = ed25519_sk_as_montgomery_scalar(&view_scalar.to_bytes());

        // Generate ML-KEM keypair
        let (full_pk, full_sk) = kem.keypair_generate().unwrap();

        // Use the view-key-derived X25519 instead of the random one from keypair_generate
        let tx_key = random_tx_key();
        let spend_scalar = Scalar::random(&mut rand::rngs::OsRng);
        let spend_key = (G * spend_scalar).compress().to_bytes();
        let amount = 42_000_000u64;
        let idx = 0u64;

        // Sender constructs with view-key-derived X25519
        let out = construct_output(
            &tx_key, &x25519_pub, &full_pk.ml_kem, &spend_key, amount, idx,
        )
        .unwrap();

        // Recipient scans using the view-key-derived secret
        let recovered = scan_output_recover(
            &x25519_sec.to_bytes(),
            &full_sk.ml_kem,
            &out.kem_ciphertext_x25519,
            &out.kem_ciphertext_ml_kem,
            &out.output_key,
            &out.commitment,
            &out.enc_amount,
            out.amount_tag,
            out.view_tag_x25519,
            idx,
        )
        .unwrap();

        assert_eq!(recovered.amount, amount, "amount must match");
        assert_eq!(
            recovered.pqc_public_key, out.pqc_public_key,
            "PQC public key must match"
        );
    }

    #[test]
    fn construct_scan_round_trip_multiple_outputs_with_view_key_x25519() {
        use crate::montgomery::{ed25519_pk_to_x25519_pk, ed25519_sk_as_montgomery_scalar};

        let kem = HybridX25519MlKem;

        let view_scalar = Scalar::random(&mut rand::rngs::OsRng);
        let view_pub = (&view_scalar * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE)
            .compress();
        let x25519_pub = ed25519_pk_to_x25519_pk(&view_pub.0).unwrap();
        let x25519_sec = ed25519_sk_as_montgomery_scalar(&view_scalar.to_bytes());

        let (full_pk, full_sk) = kem.keypair_generate().unwrap();
        let tx_key = random_tx_key();
        let spend_key = (G * Scalar::random(&mut rand::rngs::OsRng))
            .compress()
            .to_bytes();

        for idx in 0u64..5 {
            let amount = (idx + 1) * 1_000_000;
            let out = construct_output(
                &tx_key, &x25519_pub, &full_pk.ml_kem, &spend_key, amount, idx,
            )
            .unwrap();

            let recovered = scan_output_recover(
                &x25519_sec.to_bytes(),
                &full_sk.ml_kem,
                &out.kem_ciphertext_x25519,
                &out.kem_ciphertext_ml_kem,
                &out.output_key,
                &out.commitment,
                &out.enc_amount,
                out.amount_tag,
                out.view_tag_x25519,
                idx,
            )
            .unwrap();

            assert_eq!(recovered.amount, amount, "amount mismatch at output {idx}");
        }
    }

    #[test]
    fn scan_output_recover_rejects_low_order_x25519_ephemeral() {
        use crate::montgomery::ed25519_sk_as_montgomery_scalar;

        let kem = HybridX25519MlKem;
        let (_, full_sk) = kem.keypair_generate().unwrap();

        let view_scalar = Scalar::random(&mut rand::rngs::OsRng);
        let x25519_sec = ed25519_sk_as_montgomery_scalar(&view_scalar.to_bytes());

        // All known low-order u-coordinates on Curve25519
        let low_order_u_coords: Vec<[u8; 32]> = {
            let mut pts = Vec::new();

            // u = 0 (identity, order 1)
            pts.push([0u8; 32]);

            // u = 1 (order 2)
            let mut u1 = [0u8; 32];
            u1[0] = 1;
            pts.push(u1);

            // u = p-1 = 2^255 - 20 (order 4)
            let mut pm1 = [0u8; 32];
            pm1[0] = 0xEC;
            for byte in pm1.iter_mut().skip(1).take(30) {
                *byte = 0xFF;
            }
            pm1[31] = 0x7F;
            pts.push(pm1);

            // Additional low-order points from the 8-torsion subgroup.
            // These are the u-coordinates of the remaining 9 small-subgroup points
            // (total 12 points on the twist and curve combined).
            // u = 325606250916557431795983626356110631294008115727848805560023387167927233504
            // (from https://cr.yp.to/ecdh.html)
            let u_order8_a: [u8; 32] = [
                0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3,
                0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32,
                0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
            ];
            pts.push(u_order8_a);

            // u = 39382357235489614581723060781553021112529911719440698176882885853963445705823
            let u_order8_b: [u8; 32] = [
                0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1,
                0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c,
                0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57,
            ];
            pts.push(u_order8_b);

            pts
        };

        let dummy_ml_kem_ct = vec![0u8; 1088]; // will never be reached

        for (i, low_order_u) in low_order_u_coords.iter().enumerate() {
            let result = scan_output_recover(
                &x25519_sec.to_bytes(),
                &full_sk.ml_kem,
                low_order_u,
                &dummy_ml_kem_ct,
                &[0u8; 32],   // dummy output key
                &[0u8; 32],   // dummy commitment
                &[0u8; 8],    // dummy enc_amount
                0,             // dummy amount_tag
                0,             // dummy view_tag
                0,             // output_index
            );
            assert!(
                result.is_err(),
                "low-order point {i} (u={:02x}{:02x}...) must be rejected",
                low_order_u[0],
                low_order_u[1],
            );
            match result.unwrap_err() {
                CryptoError::LowOrderPoint => {}
                other => panic!(
                    "low-order point {i} should give LowOrderPoint, got {:?}",
                    other
                ),
            }
        }
    }

    #[test]
    fn scan_output_rejects_low_order_x25519_ephemeral() {
        use crate::montgomery::ed25519_sk_as_montgomery_scalar;

        let kem = HybridX25519MlKem;
        let (_, full_sk) = kem.keypair_generate().unwrap();

        let view_scalar = Scalar::random(&mut rand::rngs::OsRng);
        let x25519_sec = ed25519_sk_as_montgomery_scalar(&view_scalar.to_bytes());
        let spend_key = (G * Scalar::random(&mut rand::rngs::OsRng))
            .compress()
            .to_bytes();

        // u = 0 (identity)
        let zero_eph = [0u8; 32];
        let result = scan_output(
            &x25519_sec.to_bytes(),
            &full_sk.ml_kem,
            &zero_eph,
            &vec![0u8; 1088],
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 8],
            0,
            0,
            &spend_key,
            0,
        );
        assert!(result.is_err(), "zero ephemeral must be rejected by scan_output");
    }
}
