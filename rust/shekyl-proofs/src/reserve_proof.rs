// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Reserve proof: proves ownership of unspent outputs.
//!
//! Per output the proof carries: ho, y, k_amount, key_image, DLEQ(c, s).
//! The DLEQ proves `key_image = x * Hp(O)` where `x = ho + b`, which
//! the verifier checks against the spent key image pool to confirm the
//! output is unspent.
//!
//! Wire format: `69 + 192*N` bytes
//!   header: version[1] + schnorr[64] + output_count[4]
//!   per-output: ho[32] + y[32] + k_amount[32] + key_image[32] + dleq(c[32]+s[32])
//!
//! The verifier reads `enc_amount` from the blockchain, NOT from the proof.
//! This is load-bearing for soundness (see FCMP_PLUS_PLUS.md section 21).

#![deny(unsafe_code)]

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

use shekyl_generators::T as T_LAZY;

use shekyl_crypto_pq::output::ProofSecrets;
use crate::dleq::{self, DleqProof};
use crate::error::ProofError;

pub const CURRENT_PROOF_VERSION: u8 = 1;

const RESERVE_DOMAIN: &[u8] = b"shekyl-reserve-proof-v1";

const PER_OUTPUT_SIZE: usize = 192; // ho[32]+y[32]+k_amount[32]+key_image[32]+dleq[64]
const HEADER_SIZE: usize = 69; // version[1]+sig[64]+count[4]

// ── Per-output entry ────────────────────────────────────────────────

/// Input data for one output in a reserve proof (prover side).
pub struct ReserveOutputEntry {
    pub proof_secrets: ProofSecrets,
    pub key_image: [u8; 32],
    pub spend_secret: [u8; 32],
    pub output_key: [u8; 32],
}

/// Per-output data from a verified reserve proof entry.
#[derive(Debug)]
pub struct VerifiedReserveOutput {
    pub output_index: usize,
    pub key_image: [u8; 32],
    pub amount: u64,
}

fn write_per_output(
    ps: &ProofSecrets,
    key_image: &[u8; 32],
    dleq_proof: &DleqProof,
    buf: &mut Vec<u8>,
) {
    buf.extend_from_slice(&ps.ho);
    buf.extend_from_slice(&ps.y);
    buf.extend_from_slice(&ps.k_amount);
    buf.extend_from_slice(key_image);
    buf.extend_from_slice(&dleq_proof.to_bytes());
}

// ── Schnorr (same pattern as tx_proof, different domain) ────────────

fn schnorr_challenge(
    public_key: &EdwardsPoint,
    r_point: &EdwardsPoint,
    msg: &[u8],
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(RESERVE_DOMAIN);
    hasher.update(public_key.compress().as_bytes());
    hasher.update(r_point.compress().as_bytes());
    hasher.update(msg);
    Scalar::from_hash(hasher)
}

fn schnorr_sign(
    secret_key: &Scalar,
    public_key: &EdwardsPoint,
    msg: &[u8],
) -> [u8; 64] {
    let mut k = Scalar::random(&mut rand_core::OsRng);
    let r_point = k * G_POINT;
    let c = schnorr_challenge(public_key, &r_point, msg);
    let s = k - c * secret_key;
    k.zeroize();

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(r_point.compress().as_bytes());
    sig[32..].copy_from_slice(&s.to_bytes());
    sig
}

fn schnorr_verify(
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
    let c = schnorr_challenge(public_key, &r_point, msg);
    let check = s * G_POINT + c * public_key;
    check == r_point
}

fn assemble_proof_message(
    address_bytes: &[u8],
    user_message: &[u8],
    per_output_data: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(address_bytes.len() + user_message.len() + per_output_data.len());
    msg.extend_from_slice(address_bytes);
    msg.extend_from_slice(user_message);
    msg.extend_from_slice(per_output_data);
    msg
}

// ═══════════════════════════════════════════════════════════════════════
// Generate
// ═══════════════════════════════════════════════════════════════════════

/// Generate a reserve proof.
///
/// The prover signs with `spend_secret_key` (b). For each output, a DLEQ
/// proof is generated proving `key_image = (ho + b) * Hp(O)`.
///
/// # Arguments
/// - `spend_secret_key`: the wallet's spend secret key b (32 bytes)
/// - `address_bytes`: canonical encoding of the prover's address
/// - `user_message`: arbitrary user-supplied message string
/// - `entries`: per-output data including ProofSecrets, key_image, and output_key
pub fn generate_reserve_proof(
    spend_secret_key: &[u8; 32],
    address_bytes: &[u8],
    user_message: &[u8],
    entries: &[ReserveOutputEntry],
) -> Result<Vec<u8>, ProofError> {
    if entries.is_empty() {
        return Err(ProofError::InvalidFormat("no outputs specified".into()));
    }

    let b_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(*spend_secret_key))
        .ok_or(ProofError::InvalidFormat("spend_secret_key not canonical".into()))?;
    let b_point = b_scalar * G_POINT;

    let n = entries.len();
    let mut per_output_blob = Vec::with_capacity(n * PER_OUTPUT_SIZE);

    for entry in entries {
        let ho_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(entry.proof_secrets.ho))
            .ok_or(ProofError::InvalidFormat("non-canonical ho".into()))?;

        let x = ho_scalar + b_scalar;

        let hp_of_o = shekyl_generators::biased_hash_to_point(entry.output_key);

        let p = x * G_POINT; // P = x*G = O - y*T
        let ki_point = x * hp_of_o;

        let expected_ki = ki_point.compress().to_bytes();
        if expected_ki != entry.key_image {
            return Err(ProofError::VerificationFailed(
                "key_image does not match (ho+b)*Hp(O)".into(),
            ));
        }

        let dleq_msg = assemble_dleq_context(address_bytes, user_message, &entry.output_key);
        let dleq_proof = dleq::prove_dleq(&x, &hp_of_o, &p, &ki_point, &dleq_msg);

        write_per_output(&entry.proof_secrets, &entry.key_image, &dleq_proof, &mut per_output_blob);
    }

    let msg = assemble_proof_message(address_bytes, user_message, &per_output_blob);
    let sig = schnorr_sign(&b_scalar, &b_point, &msg);

    let mut proof = Vec::with_capacity(HEADER_SIZE + n * PER_OUTPUT_SIZE);
    proof.push(CURRENT_PROOF_VERSION);
    proof.extend_from_slice(&sig);
    proof.extend_from_slice(&(n as u32).to_le_bytes());
    proof.extend_from_slice(&per_output_blob);

    Ok(proof)
}

fn assemble_dleq_context(
    address_bytes: &[u8],
    user_message: &[u8],
    output_key: &[u8; 32],
) -> Vec<u8> {
    let mut ctx = Vec::with_capacity(address_bytes.len() + user_message.len() + 32);
    ctx.extend_from_slice(address_bytes);
    ctx.extend_from_slice(user_message);
    ctx.extend_from_slice(output_key);
    ctx
}

// ═══════════════════════════════════════════════════════════════════════
// Verify
// ═══════════════════════════════════════════════════════════════════════

/// On-chain data the verifier fetches for each output in a reserve proof.
///
/// `enc_amount` MUST come from the blockchain, NOT from the proof itself.
pub struct ReserveOnChainOutput {
    pub output_key: [u8; 32],
    pub commitment: [u8; 32],
    pub enc_amount: [u8; 8],
}

/// Verify a reserve proof.
///
/// Returns per-output verification results including key images and
/// decrypted amounts. The caller is responsible for checking each
/// key_image against the spent pool.
///
/// # Arguments
/// - `proof_bytes`: the serialized proof blob
/// - `address_bytes`: canonical encoding of the prover's address
/// - `user_message`: arbitrary user-supplied message string
/// - `spend_pubkey`: B (32 bytes, the prover's spend public key)
/// - `on_chain_outputs`: per-output data fetched from the blockchain
pub fn verify_reserve_proof(
    proof_bytes: &[u8],
    address_bytes: &[u8],
    user_message: &[u8],
    spend_pubkey: &[u8; 32],
    on_chain_outputs: &[ReserveOnChainOutput],
) -> Result<Vec<VerifiedReserveOutput>, ProofError> {
    if proof_bytes.len() < HEADER_SIZE {
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

    let expected_len = HEADER_SIZE + output_count * PER_OUTPUT_SIZE;
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

    let per_output_blob = &proof_bytes[HEADER_SIZE..];

    let b_point = CompressedEdwardsY(*spend_pubkey)
        .decompress()
        .ok_or(ProofError::InvalidFormat("invalid spend pubkey".into()))?;

    let msg = assemble_proof_message(address_bytes, user_message, per_output_blob);

    if !schnorr_verify(&b_point, &msg, &sig) {
        return Err(ProofError::SignatureFailed);
    }

    let mut results = Vec::with_capacity(output_count);

    for (i, on_chain) in on_chain_outputs.iter().enumerate() {
        let offset = i * PER_OUTPUT_SIZE;
        let chunk = &per_output_blob[offset..offset + PER_OUTPUT_SIZE];

        let mut ho = [0u8; 32];
        let mut y_bytes = [0u8; 32];
        let mut k_amount = [0u8; 32];
        let mut key_image = [0u8; 32];
        let mut dleq_bytes = [0u8; 64];

        ho.copy_from_slice(&chunk[0..32]);
        y_bytes.copy_from_slice(&chunk[32..64]);
        k_amount.copy_from_slice(&chunk[64..96]);
        key_image.copy_from_slice(&chunk[96..128]);
        dleq_bytes.copy_from_slice(&chunk[128..192]);

        let ho_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(ho))
            .ok_or(ProofError::InvalidFormat(format!("non-canonical ho at output {i}")))?;
        let y_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(y_bytes))
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

        let hp_of_o = shekyl_generators::biased_hash_to_point(on_chain.output_key);

        // P = O - y*T = (ho + b)*G = x*G
        let p = expected_o - y_scalar * *T_LAZY;

        let ki_point = CompressedEdwardsY(key_image)
            .decompress()
            .ok_or(ProofError::InvalidFormat(format!(
                "invalid key image at index {i}"
            )))?;

        let dleq_proof = DleqProof::from_bytes(&dleq_bytes);
        let dleq_msg = assemble_dleq_context(address_bytes, user_message, &on_chain.output_key);

        if !dleq::verify_dleq(&hp_of_o, &p, &ki_point, &dleq_msg, &dleq_proof) {
            return Err(ProofError::VerificationFailed(format!(
                "DLEQ verification failed at output {i}: key_image != x*Hp(O)"
            )));
        }

        let mut amount_bytes = [0u8; 8];
        for j in 0..8 {
            amount_bytes[j] = on_chain.enc_amount[j] ^ k_amount[j];
        }
        let amount = u64::from_le_bytes(amount_bytes);

        results.push(VerifiedReserveOutput {
            output_index: i,
            key_image,
            amount,
        });
    }

    Ok(results)
}

/// Compute the expected proof size for a reserve proof.
pub const fn reserve_proof_size(output_count: usize) -> usize {
    HEADER_SIZE + output_count * PER_OUTPUT_SIZE
}
