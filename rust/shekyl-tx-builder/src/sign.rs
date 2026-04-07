//! Core signing logic for FCMP++ transactions.
//!
//! The signing pipeline has two phases:
//!
//! 1. [`sign_transaction`] — Generates Bulletproof+ range proofs, FCMP++
//!    membership proofs, ECDH-encoded amounts, and pseudo-output commitments.
//!    Returns [`SignedProofs`] with an empty `pqc_auths` vector.
//!
//! 2. [`sign_pqc_auths`] — Given per-input PQC payload hashes (computed by the
//!    caller after inserting proofs into the transaction), produces hybrid
//!    Ed25519 + ML-DSA-65 signatures.
//!
//! This two-phase design avoids a circular dependency: the PQC payload hash
//! includes the serialized proofs, so the proofs must exist before signing.

use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;
use zeroize::Zeroizing;

use shekyl_fcmp::proof::{self, BranchLayer, ProveInput};
use shekyl_fcmp::PqcLeafScalar;
use shekyl_primitives::Commitment;

use crate::ecdh;
use crate::error::TxBuilderError;
use crate::types::{OutputInfo, PqcAuth, SignedProofs, SpendInput, TreeContext};
use crate::validate::validate_inputs;

/// Construct the proof portion of an FCMP++ transaction.
///
/// Generates Bulletproof+ range proofs over output commitments, FCMP++
/// full-chain membership proofs for all inputs, ECDH-encoded amounts,
/// and pseudo-output commitments. The returned [`SignedProofs`] has an
/// empty `pqc_auths` — call [`sign_pqc_auths`] after inserting the proofs
/// into the transaction and computing per-input PQC payload hashes.
///
/// # Errors
///
/// Returns [`TxBuilderError`] with a descriptive variant if any validation
/// check fails or a cryptographic operation errors.
///
/// # Panics
///
/// Never — all errors are returned via `Result`.
///
/// # Security
///
/// - All intermediate secret material (masks, blindings) is wrapped in
///   [`Zeroizing`] and wiped on drop.
/// - Randomness comes from [`OsRng`] (OS-provided CSPRNG).
/// - The `tree_root` in `TreeContext` must be the Selene curve tree root
///   from the block header, **not** the block hash. Passing the block hash
///   will produce an invalid proof that the verifier rejects.
#[allow(clippy::cast_possible_truncation)]
pub fn sign_transaction(
    tx_prefix_hash: [u8; 32],
    inputs: &[SpendInput],
    outputs: &[OutputInfo],
    fee: u64,
    tree: &TreeContext,
) -> Result<SignedProofs, TxBuilderError> {
    // ── 1. Validate ──────────────────────────────────────────────────
    validate_inputs(inputs, outputs, fee, tree)?;

    let n_in = inputs.len();
    let n_out = outputs.len();

    // ── 2. Bulletproofs+ range proof ─────────────────────────────────
    // Generate random masks for each output commitment.
    let mut masks = Zeroizing::new(Vec::with_capacity(n_out));
    let commitments_for_bp: Vec<Commitment> = outputs
        .iter()
        .map(|out| {
            let mask = Scalar::random(&mut OsRng);
            masks.push(mask);
            Commitment::new(mask, out.amount)
        })
        .collect();

    let bp = shekyl_bulletproofs::Bulletproof::prove_plus(&mut OsRng, commitments_for_bp)
        .map_err(|e| TxBuilderError::BulletproofError(e.to_string()))?;

    let mut bp_bytes = Vec::new();
    bp.write(&mut bp_bytes)
        .map_err(|e| TxBuilderError::BulletproofError(format!("serialization: {e}")))?;

    // ── 3. Output commitments (8*C) ──────────────────────────────────
    // Multiply each commitment point by the cofactor (8) for subgroup safety.
    let out_commitments: Vec<[u8; 32]> = outputs
        .iter()
        .zip(masks.iter())
        .map(|(out, mask)| {
            let c = Commitment::new(*mask, out.amount);
            let point = c.calculate();
            let cofactored = point.mul_by_cofactor();
            cofactored.compress().to_bytes()
        })
        .collect();

    // ── 4. ECDH encode amounts ───────────────────────────────────────
    let ecdh_amounts: Vec<[u8; 8]> = outputs
        .iter()
        .map(|out| ecdh::ecdh_encode_amount(out.amount, &out.amount_key))
        .collect();

    // ── 5. Pseudo-output balancing ───────────────────────────────────
    // Generate random blindings for all-but-last input; the last mask is
    // constrained so that: sum(pseudo_masks) == sum(output_masks) + 0 (fee
    // is committed with mask 0: fee*H).
    let mut pseudo_masks = Zeroizing::new(Vec::with_capacity(n_in));
    let sum_out_masks: Scalar = masks.iter().copied().sum();

    for i in 0..n_in {
        if i < n_in - 1 {
            pseudo_masks.push(Scalar::random(&mut OsRng));
        } else {
            let sum_pseudo: Scalar = pseudo_masks.iter().copied().sum();
            pseudo_masks.push(sum_out_masks - sum_pseudo);
        }
    }

    // ── 6. Build ProveInput for FCMP++ ───────────────────────────────
    let prove_inputs: Vec<ProveInput> = inputs
        .iter()
        .map(|inp| {
            let leaf_outputs: Vec<([u8; 32], [u8; 32], [u8; 32])> = inp
                .leaf_chunk
                .iter()
                .map(|e| (e.output_key, e.key_image_gen, e.commitment))
                .collect();
            let leaf_h_pqc: Vec<[u8; 32]> =
                inp.leaf_chunk.iter().map(|e| e.h_pqc).collect();

            let c1_branch_layers: Vec<BranchLayer> = inp
                .c1_layers
                .iter()
                .map(|siblings| BranchLayer {
                    siblings: siblings.clone(),
                })
                .collect();
            let c2_branch_layers: Vec<BranchLayer> = inp
                .c2_layers
                .iter()
                .map(|siblings| BranchLayer {
                    siblings: siblings.clone(),
                })
                .collect();

            ProveInput {
                output_key: inp.output_key,
                key_image_gen: compute_key_image_gen(&inp.output_key),
                commitment: inp.commitment,
                h_pqc: PqcLeafScalar(inp.h_pqc),
                spend_key_x: inp.spend_key_x,
                spend_key_y: inp.spend_key_y,
                leaf_chunk_outputs: leaf_outputs,
                leaf_chunk_h_pqc: leaf_h_pqc,
                c1_branch_layers,
                c2_branch_layers,
            }
        })
        .collect();

    // ── 7. FCMP++ prove ──────────────────────────────────────────────
    let prove_result = proof::prove(
        &prove_inputs,
        &tree.tree_root,
        tree.tree_depth,
        tx_prefix_hash,
    )
    .map_err(|e| TxBuilderError::FcmpProveError(e.to_string()))?;

    // ── 8. Assemble SignedProofs ──────────────────────────────────────
    Ok(SignedProofs {
        bulletproof_plus: bp_bytes,
        commitments: out_commitments,
        ecdh_amounts,
        pseudo_outs: prove_result.pseudo_outs,
        fcmp_proof: prove_result.proof.data,
        pqc_auths: Vec::new(),
        reference_block: tree.reference_block,
        tree_depth: tree.tree_depth,
    })
}

/// Produce PQC authentication signatures for each input.
///
/// This is Phase 2 of the signing pipeline. The caller must:
/// 1. Insert the proofs from [`sign_transaction`] into the transaction
/// 2. Compute `get_transaction_signed_payload` for each input
/// 3. Hash each payload with Keccak-256 to get `payload_hashes`
/// 4. Call this function with those hashes and the corresponding secret keys
///
/// # Errors
///
/// Returns [`TxBuilderError::PqcSignError`] if any individual signing
/// operation fails (e.g., malformed secret key).
pub fn sign_pqc_auths(
    payload_hashes: &[[u8; 32]],
    inputs: &[SpendInput],
) -> Result<Vec<PqcAuth>, TxBuilderError> {
    use shekyl_crypto_pq::signature::{HybridEd25519MlDsa, HybridSecretKey, SignatureScheme};

    if payload_hashes.len() != inputs.len() {
        return Err(TxBuilderError::PqcSignError {
            index: 0,
            reason: format!(
                "payload_hashes length {} != inputs length {}",
                payload_hashes.len(),
                inputs.len()
            ),
        });
    }

    let scheme = HybridEd25519MlDsa;
    let mut auths = Vec::with_capacity(inputs.len());

    for (i, (hash, inp)) in payload_hashes.iter().zip(inputs.iter()).enumerate() {
        let sk = HybridSecretKey::from_canonical_bytes(&inp.pqc_secret_key).map_err(|e| {
            TxBuilderError::PqcSignError {
                index: i,
                reason: format!("failed to decode PQC secret key: {e}"),
            }
        })?;

        let pk_bytes = derive_public_key_from_secret(&sk).map_err(|e| {
            TxBuilderError::PqcSignError {
                index: i,
                reason: format!("failed to derive PQC public key: {e}"),
            }
        })?;

        let sig = scheme.sign(&sk, hash).map_err(|e| TxBuilderError::PqcSignError {
            index: i,
            reason: e.to_string(),
        })?;

        let sig_bytes = sig.to_canonical_bytes().map_err(|e| TxBuilderError::PqcSignError {
            index: i,
            reason: format!("failed to serialize PQC signature: {e}"),
        })?;

        auths.push(PqcAuth {
            auth_version: 1,
            signature: sig_bytes,
            public_key: pk_bytes,
        });
    }

    Ok(auths)
}

/// Compute the key image generator Hp(O) for a given output key O.
///
/// Uses `biased_hash_to_point(O)` which matches the C++ `hash_to_p3(O)`.
/// This is the same deterministic hash-to-curve used in leaf construction.
fn compute_key_image_gen(output_key: &[u8; 32]) -> [u8; 32] {
    shekyl_generators::biased_hash_to_point(*output_key)
        .compress()
        .to_bytes()
}

/// Derive the canonical public key bytes from a hybrid secret key.
fn derive_public_key_from_secret(
    sk: &shekyl_crypto_pq::signature::HybridSecretKey,
) -> Result<Vec<u8>, shekyl_crypto_pq::CryptoError> {
    use ed25519_dalek::SigningKey;
    use fips204::ml_dsa_65;
    use fips204::traits::{SerDes as _, Signer as _};
    use shekyl_crypto_pq::signature::{HybridPublicKey, ML_DSA_65_SECRET_KEY_LENGTH};

    let ed_sk_bytes: [u8; 32] = sk
        .ed25519
        .clone()
        .try_into()
        .map_err(|_| shekyl_crypto_pq::CryptoError::InvalidKeyMaterial)?;
    let ed_signing = SigningKey::from_bytes(&ed_sk_bytes);
    let ed_pk = ed_signing.verifying_key().to_bytes();

    let ml_sk_bytes: [u8; ML_DSA_65_SECRET_KEY_LENGTH] = sk
        .ml_dsa
        .clone()
        .try_into()
        .map_err(|_| shekyl_crypto_pq::CryptoError::InvalidKeyMaterial)?;
    let ml_private = ml_dsa_65::PrivateKey::try_from_bytes(ml_sk_bytes)
        .map_err(|e| shekyl_crypto_pq::CryptoError::SerializationError(e.into()))?;
    let ml_pk = ml_private.get_public_key();

    let pk = HybridPublicKey {
        ed25519: ed_pk,
        ml_dsa: ml_pk.into_bytes().to_vec(),
    };
    pk.to_canonical_bytes()
}
