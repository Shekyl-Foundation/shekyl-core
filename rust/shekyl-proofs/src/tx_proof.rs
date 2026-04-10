// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Outbound and inbound transaction proofs.
//!
//! Outbound: sender reveals tx_key_secret; verifier re-derives combined_ss
//! via deterministic KEM encapsulation, checks the derived ciphertexts
//! match on-chain, then projects to ProofSecrets and verifies O, C, and
//! amount. Ed25519 Schnorr signature seals the proof contents.
//!
//! Inbound: recipient derives ProofSecrets via KEM decapsulation, signs
//! with view_secret_key. Verifier checks O, C, amount, and signature
//! against the recipient's view public key.
//!
//! Wire format (hand-rolled canonical, no bincode):
//!
//! Outbound: `101 + 128*N` bytes
//!   header: version[1] + tx_key_secret[32] + schnorr[64] + output_count[4]
//!   per-output: ho[32] + y[32] + z[32] + k_amount[32]
//!
//! Inbound: `69 + 128*N` bytes
//!   header: version[1] + schnorr[64] + output_count[4]
//!   per-output: ho[32] + y[32] + z[32] + k_amount[32]

#![deny(unsafe_code)]

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

use shekyl_generators::{H as H_POINT_LAZY, T as T_LAZY};

use shekyl_crypto_pq::output::{
    derive_proof_secrets, rederive_combined_ss, ProofSecrets,
};
use crate::error::ProofError;

pub const CURRENT_PROOF_VERSION: u8 = 1;

const OUTBOUND_DOMAIN: &[u8] = b"shekyl-outbound-tx-proof-v1";
const INBOUND_DOMAIN: &[u8] = b"shekyl-inbound-tx-proof-v1";

const PER_OUTPUT_SIZE: usize = 128; // ho[32] + y[32] + z[32] + k_amount[32]
const OUTBOUND_HEADER_SIZE: usize = 101; // version[1] + tx_key_secret[32] + sig[64] + count[4]
const INBOUND_HEADER_SIZE: usize = 69; // version[1] + sig[64] + count[4]

// ── Per-output entry serialization ──────────────────────────────────

fn write_per_output(ps: &ProofSecrets, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&ps.ho);
    buf.extend_from_slice(&ps.y);
    buf.extend_from_slice(&ps.z);
    buf.extend_from_slice(&ps.k_amount);
}

fn read_per_output(data: &[u8]) -> Result<ProofSecrets, ProofError> {
    if data.len() < PER_OUTPUT_SIZE {
        return Err(ProofError::InvalidFormat(
            "per-output entry too short".into(),
        ));
    }
    let mut ho = [0u8; 32];
    let mut y = [0u8; 32];
    let mut z = [0u8; 32];
    let mut k_amount = [0u8; 32];
    ho.copy_from_slice(&data[0..32]);
    y.copy_from_slice(&data[32..64]);
    z.copy_from_slice(&data[64..96]);
    k_amount.copy_from_slice(&data[96..128]);
    Ok(ProofSecrets { ho, y, z, k_amount })
}

// ── Schnorr signature (Ed25519 key, SHA-512 challenge) ──────────────

fn schnorr_challenge(
    domain: &[u8],
    public_key: &EdwardsPoint,
    r_point: &EdwardsPoint,
    msg: &[u8],
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(domain);
    hasher.update(public_key.compress().as_bytes());
    hasher.update(r_point.compress().as_bytes());
    hasher.update(msg);
    Scalar::from_hash(hasher)
}

/// 64-byte Schnorr signature: R (32 compressed point) + s (32 scalar).
fn schnorr_sign(
    domain: &[u8],
    secret_key: &Scalar,
    public_key: &EdwardsPoint,
    msg: &[u8],
) -> [u8; 64] {
    let mut k = Scalar::random(&mut rand_core::OsRng);
    let r_point = k * G_POINT;
    let c = schnorr_challenge(domain, public_key, &r_point, msg);
    let s = k - c * secret_key;
    k.zeroize();

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(r_point.compress().as_bytes());
    sig[32..].copy_from_slice(&s.to_bytes());
    sig
}

fn schnorr_verify(
    domain: &[u8],
    public_key: &EdwardsPoint,
    msg: &[u8],
    sig: &[u8; 64],
) -> bool {
    let r_compressed = CompressedEdwardsY::from_slice(&sig[..32]);
    let r_point = match r_compressed.ok().and_then(|c| c.decompress()) {
        Some(p) => p,
        None => return false,
    };
    let mut s_arr = [0u8; 32];
    s_arr.copy_from_slice(&sig[32..]);
    let s: Scalar = match Option::from(Scalar::from_canonical_bytes(s_arr)) {
        Some(s) => s,
        None => return false,
    };

    let c = schnorr_challenge(domain, public_key, &r_point, msg);
    let check = s * G_POINT + c * public_key;
    check == r_point
}

// ── Message assembly (bound into Schnorr) ───────────────────────────

fn assemble_proof_message(
    txid: &[u8; 32],
    address_bytes: &[u8],
    user_message: &[u8],
    per_output_data: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(32 + address_bytes.len() + user_message.len() + per_output_data.len());
    msg.extend_from_slice(txid);
    msg.extend_from_slice(address_bytes);
    msg.extend_from_slice(user_message);
    msg.extend_from_slice(per_output_data);
    msg
}

// ═══════════════════════════════════════════════════════════════════════
// Outbound TX Proof
// ═══════════════════════════════════════════════════════════════════════

/// Data required to verify a single output in an outbound TX proof.
#[derive(Debug)]
pub struct VerifiedOutput {
    pub output_index: usize,
    pub amount: u64,
}

/// Generate an outbound transaction proof.
///
/// The sender reveals `tx_key_secret` and signs with it. The verifier
/// can re-derive combined_ss via KEM re-encapsulation and check that the
/// per-output ProofSecrets match.
///
/// # Arguments
/// - `tx_key_secret`: the per-tx ephemeral secret (32 bytes)
/// - `txid`: transaction hash (32 bytes)
/// - `address_bytes`: canonical encoding of the recipient address
/// - `user_message`: arbitrary user-supplied message string
/// - `recipient_x25519_pk`: recipient's X25519 view public key
/// - `recipient_ml_kem_ek`: recipient's ML-KEM-768 encapsulation key
/// - `output_indices`: which output indices in the tx to include
pub fn generate_outbound_proof(
    tx_key_secret: &[u8; 32],
    txid: &[u8; 32],
    address_bytes: &[u8],
    user_message: &[u8],
    recipient_x25519_pk: &[u8; 32],
    recipient_ml_kem_ek: &[u8],
    output_indices: &[u64],
) -> Result<Vec<u8>, ProofError> {
    if output_indices.is_empty() {
        return Err(ProofError::InvalidFormat("no outputs specified".into()));
    }

    let n = output_indices.len();
    let mut per_output_blob = Vec::with_capacity(n * PER_OUTPUT_SIZE);
    let mut secrets_for_signing: Vec<ProofSecrets> = Vec::with_capacity(n);

    for &idx in output_indices {
        let (combined_ss, _x25519_eph_pk, _ml_kem_ct) =
            rederive_combined_ss(tx_key_secret, recipient_x25519_pk, recipient_ml_kem_ek, idx)?;

        let ps = derive_proof_secrets(&combined_ss.0, idx);
        write_per_output(&ps, &mut per_output_blob);
        secrets_for_signing.push(ps);
    }

    let msg = assemble_proof_message(txid, address_bytes, user_message, &per_output_blob);

    let sk_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(*tx_key_secret))
        .ok_or(ProofError::InvalidFormat("tx_key_secret is not a canonical scalar".into()))?;
    let pk_point = sk_scalar * G_POINT;

    let sig = schnorr_sign(OUTBOUND_DOMAIN, &sk_scalar, &pk_point, &msg);

    let mut proof = Vec::with_capacity(OUTBOUND_HEADER_SIZE + n * PER_OUTPUT_SIZE);
    proof.push(CURRENT_PROOF_VERSION);
    proof.extend_from_slice(tx_key_secret);
    proof.extend_from_slice(&sig);
    proof.extend_from_slice(&(n as u32).to_le_bytes());
    proof.extend_from_slice(&per_output_blob);

    for mut s in secrets_for_signing {
        s.ho.zeroize();
        s.y.zeroize();
        s.z.zeroize();
        s.k_amount.zeroize();
    }

    Ok(proof)
}

/// Verification context for an outbound TX proof: what the verifier
/// reads from the blockchain for each output.
pub struct OnChainOutput {
    pub output_key: [u8; 32],
    pub commitment: [u8; 32],
    pub enc_amount: [u8; 8],
    pub x25519_eph_pk: [u8; 32],
    pub ml_kem_ct: Vec<u8>,
}

/// Verify an outbound transaction proof.
///
/// Returns the list of verified outputs with their decrypted amounts.
///
/// # Arguments
/// - `proof_bytes`: the serialized proof blob
/// - `txid`: transaction hash (32 bytes)
/// - `address_bytes`: canonical encoding of the recipient address
/// - `user_message`: arbitrary user-supplied message string
/// - `recipient_spend_pubkey`: B (32 bytes)
/// - `recipient_x25519_pk`: recipient's X25519 view public key
/// - `recipient_ml_kem_ek`: recipient's ML-KEM-768 encapsulation key
/// - `on_chain_outputs`: per-output data fetched from the blockchain
pub fn verify_outbound_proof(
    proof_bytes: &[u8],
    txid: &[u8; 32],
    address_bytes: &[u8],
    user_message: &[u8],
    recipient_spend_pubkey: &[u8; 32],
    recipient_x25519_pk: &[u8; 32],
    recipient_ml_kem_ek: &[u8],
    on_chain_outputs: &[OnChainOutput],
) -> Result<Vec<VerifiedOutput>, ProofError> {
    if proof_bytes.len() < OUTBOUND_HEADER_SIZE {
        return Err(ProofError::InvalidFormat("proof too short for header".into()));
    }

    let version = proof_bytes[0];
    if version != CURRENT_PROOF_VERSION {
        return Err(ProofError::InvalidFormat(format!(
            "unsupported proof version {version}, expected {CURRENT_PROOF_VERSION}"
        )));
    }

    let mut tx_key_secret = [0u8; 32];
    tx_key_secret.copy_from_slice(&proof_bytes[1..33]);

    let mut sig = [0u8; 64];
    sig.copy_from_slice(&proof_bytes[33..97]);

    let output_count = u32::from_le_bytes(
        proof_bytes[97..101].try_into().unwrap(),
    ) as usize;

    let expected_len = OUTBOUND_HEADER_SIZE + output_count * PER_OUTPUT_SIZE;
    if proof_bytes.len() != expected_len {
        return Err(ProofError::InvalidFormat(format!(
            "proof length {}, expected {expected_len} for {output_count} outputs",
            proof_bytes.len(),
        )));
    }

    if output_count != on_chain_outputs.len() {
        return Err(ProofError::InvalidFormat(format!(
            "proof has {output_count} outputs but {} on-chain outputs provided",
            on_chain_outputs.len(),
        )));
    }

    let per_output_blob = &proof_bytes[OUTBOUND_HEADER_SIZE..];

    let msg = assemble_proof_message(txid, address_bytes, user_message, per_output_blob);

    let sk_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(tx_key_secret))
        .ok_or(ProofError::InvalidFormat("tx_key_secret not canonical".into()))?;
    let pk_point = sk_scalar * G_POINT;

    if !schnorr_verify(OUTBOUND_DOMAIN, &pk_point, &msg, &sig) {
        return Err(ProofError::SignatureFailed);
    }

    let b_point = CompressedEdwardsY(recipient_spend_pubkey.to_owned())
        .decompress()
        .ok_or(ProofError::InvalidFormat("invalid spend pubkey".into()))?;

    let mut results = Vec::with_capacity(output_count);

    for (i, on_chain) in on_chain_outputs.iter().enumerate() {
        let offset = i * PER_OUTPUT_SIZE;
        let ps = read_per_output(&per_output_blob[offset..])?;

        let (rederived_ss, rederived_x25519_eph, rederived_ml_kem_ct) =
            rederive_combined_ss(&tx_key_secret, recipient_x25519_pk, recipient_ml_kem_ek, i as u64)?;

        if rederived_x25519_eph != on_chain.x25519_eph_pk {
            return Err(ProofError::KemCtMismatch);
        }
        if rederived_ml_kem_ct != on_chain.ml_kem_ct {
            return Err(ProofError::KemCtMismatch);
        }

        let expected_ps = derive_proof_secrets(&rederived_ss.0, i as u64);
        if ps.ho != expected_ps.ho || ps.y != expected_ps.y
            || ps.z != expected_ps.z || ps.k_amount != expected_ps.k_amount
        {
            return Err(ProofError::VerificationFailed(format!(
                "ProofSecrets mismatch at output {i}"
            )));
        }

        let ho_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(ps.ho))
            .ok_or(ProofError::InvalidFormat(format!("non-canonical ho at output {i}")))?;
        let y_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(ps.y))
            .ok_or(ProofError::InvalidFormat(format!("non-canonical y at output {i}")))?;

        let expected_o = ho_scalar * G_POINT + b_point + y_scalar * *T_LAZY;
        let on_chain_o = CompressedEdwardsY(on_chain.output_key)
            .decompress()
            .ok_or(ProofError::InvalidFormat(format!(
                "invalid on-chain output key at index {i}"
            )))?;

        if expected_o != on_chain_o {
            return Err(ProofError::OutputKeyMismatch { index: i });
        }

        let mut amount_bytes = [0u8; 8];
        for j in 0..8 {
            amount_bytes[j] = on_chain.enc_amount[j] ^ ps.k_amount[j];
        }
        let amount = u64::from_le_bytes(amount_bytes);

        let z_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(ps.z))
            .ok_or(ProofError::InvalidFormat(format!("non-canonical z at output {i}")))?;
        let amount_scalar = Scalar::from(amount);
        let expected_c = z_scalar * G_POINT + amount_scalar * *H_POINT_LAZY;
        let on_chain_c = CompressedEdwardsY(on_chain.commitment)
            .decompress()
            .ok_or(ProofError::InvalidFormat(format!(
                "invalid on-chain commitment at index {i}"
            )))?;

        if expected_c != on_chain_c {
            return Err(ProofError::VerificationFailed(format!(
                "commitment mismatch at output {i}: C != z*G + amount*H"
            )));
        }

        results.push(VerifiedOutput {
            output_index: i,
            amount,
        });
    }

    Ok(results)
}

// ═══════════════════════════════════════════════════════════════════════
// Inbound TX Proof
// ═══════════════════════════════════════════════════════════════════════

/// Generate an inbound transaction proof.
///
/// The recipient signs with `view_secret_key`. The verifier checks the
/// signature against the recipient's view public key and verifies the
/// per-output ProofSecrets algebraically.
///
/// # Arguments
/// - `view_secret_key`: recipient's Ed25519 view secret scalar (32 bytes)
/// - `txid`: transaction hash
/// - `address_bytes`: canonical encoding of the recipient address
/// - `user_message`: arbitrary user-supplied message string
/// - `per_output_secrets`: ProofSecrets for each output, derived from
///   KEM decapsulation by the recipient
pub fn generate_inbound_proof(
    view_secret_key: &[u8; 32],
    txid: &[u8; 32],
    address_bytes: &[u8],
    user_message: &[u8],
    per_output_secrets: &[ProofSecrets],
) -> Result<Vec<u8>, ProofError> {
    if per_output_secrets.is_empty() {
        return Err(ProofError::InvalidFormat("no outputs specified".into()));
    }

    let n = per_output_secrets.len();
    let mut per_output_blob = Vec::with_capacity(n * PER_OUTPUT_SIZE);
    for ps in per_output_secrets {
        write_per_output(ps, &mut per_output_blob);
    }

    let msg = assemble_proof_message(txid, address_bytes, user_message, &per_output_blob);

    let sk_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(*view_secret_key))
        .ok_or(ProofError::InvalidFormat("view_secret_key not canonical".into()))?;
    let pk_point = sk_scalar * G_POINT;

    let sig = schnorr_sign(INBOUND_DOMAIN, &sk_scalar, &pk_point, &msg);

    let mut proof = Vec::with_capacity(INBOUND_HEADER_SIZE + n * PER_OUTPUT_SIZE);
    proof.push(CURRENT_PROOF_VERSION);
    proof.extend_from_slice(&sig);
    proof.extend_from_slice(&(n as u32).to_le_bytes());
    proof.extend_from_slice(&per_output_blob);

    Ok(proof)
}

/// Verify an inbound transaction proof.
///
/// # Arguments
/// - `proof_bytes`: the serialized proof blob
/// - `txid`: transaction hash
/// - `address_bytes`: canonical encoding of the recipient address
/// - `user_message`: arbitrary user-supplied message string
/// - `view_public_key`: recipient's Ed25519 view public key (32 bytes)
/// - `recipient_spend_pubkey`: B (32 bytes)
/// - `on_chain_outputs`: per-output data fetched from the blockchain
pub fn verify_inbound_proof(
    proof_bytes: &[u8],
    txid: &[u8; 32],
    address_bytes: &[u8],
    user_message: &[u8],
    view_public_key: &[u8; 32],
    recipient_spend_pubkey: &[u8; 32],
    on_chain_outputs: &[OnChainOutput],
) -> Result<Vec<VerifiedOutput>, ProofError> {
    if proof_bytes.len() < INBOUND_HEADER_SIZE {
        return Err(ProofError::InvalidFormat("proof too short for header".into()));
    }

    let version = proof_bytes[0];
    if version != CURRENT_PROOF_VERSION {
        return Err(ProofError::InvalidFormat(format!(
            "unsupported proof version {version}, expected {CURRENT_PROOF_VERSION}"
        )));
    }

    let mut sig = [0u8; 64];
    sig.copy_from_slice(&proof_bytes[1..65]);

    let output_count = u32::from_le_bytes(
        proof_bytes[65..69].try_into().unwrap(),
    ) as usize;

    let expected_len = INBOUND_HEADER_SIZE + output_count * PER_OUTPUT_SIZE;
    if proof_bytes.len() != expected_len {
        return Err(ProofError::InvalidFormat(format!(
            "proof length {}, expected {expected_len} for {output_count} outputs",
            proof_bytes.len(),
        )));
    }

    if output_count != on_chain_outputs.len() {
        return Err(ProofError::InvalidFormat(format!(
            "proof has {output_count} outputs but {} on-chain outputs provided",
            on_chain_outputs.len(),
        )));
    }

    let per_output_blob = &proof_bytes[INBOUND_HEADER_SIZE..];

    let view_pk = CompressedEdwardsY(*view_public_key)
        .decompress()
        .ok_or(ProofError::InvalidFormat("invalid view public key".into()))?;

    let msg = assemble_proof_message(txid, address_bytes, user_message, per_output_blob);

    if !schnorr_verify(INBOUND_DOMAIN, &view_pk, &msg, &sig) {
        return Err(ProofError::SignatureFailed);
    }

    let b_point = CompressedEdwardsY(*recipient_spend_pubkey)
        .decompress()
        .ok_or(ProofError::InvalidFormat("invalid spend pubkey".into()))?;

    let mut results = Vec::with_capacity(output_count);

    for (i, on_chain) in on_chain_outputs.iter().enumerate() {
        let offset = i * PER_OUTPUT_SIZE;
        let ps = read_per_output(&per_output_blob[offset..])?;

        let ho_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(ps.ho))
            .ok_or(ProofError::InvalidFormat(format!("non-canonical ho at output {i}")))?;
        let y_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(ps.y))
            .ok_or(ProofError::InvalidFormat(format!("non-canonical y at output {i}")))?;

        let expected_o = ho_scalar * G_POINT + b_point + y_scalar * *T_LAZY;
        let on_chain_o = CompressedEdwardsY(on_chain.output_key)
            .decompress()
            .ok_or(ProofError::InvalidFormat(format!(
                "invalid on-chain output key at index {i}"
            )))?;

        if expected_o != on_chain_o {
            return Err(ProofError::OutputKeyMismatch { index: i });
        }

        let mut amount_bytes = [0u8; 8];
        for j in 0..8 {
            amount_bytes[j] = on_chain.enc_amount[j] ^ ps.k_amount[j];
        }
        let amount = u64::from_le_bytes(amount_bytes);

        let z_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(ps.z))
            .ok_or(ProofError::InvalidFormat(format!("non-canonical z at output {i}")))?;
        let amount_scalar = Scalar::from(amount);
        let expected_c = z_scalar * G_POINT + amount_scalar * *H_POINT_LAZY;
        let on_chain_c = CompressedEdwardsY(on_chain.commitment)
            .decompress()
            .ok_or(ProofError::InvalidFormat(format!(
                "invalid on-chain commitment at index {i}"
            )))?;

        if expected_c != on_chain_c {
            return Err(ProofError::VerificationFailed(format!(
                "commitment mismatch at output {i}: C != z*G + amount*H"
            )));
        }

        results.push(VerifiedOutput {
            output_index: i,
            amount,
        });
    }

    Ok(results)
}

/// Compute the expected proof size for an outbound TX proof.
pub const fn outbound_proof_size(output_count: usize) -> usize {
    OUTBOUND_HEADER_SIZE + output_count * PER_OUTPUT_SIZE
}

/// Compute the expected proof size for an inbound TX proof.
pub const fn inbound_proof_size(output_count: usize) -> usize {
    INBOUND_HEADER_SIZE + output_count * PER_OUTPUT_SIZE
}
