// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FCMP++ proof construction and verification with PQC commitment binding.
//!
//! The Shekyl proof extends upstream FCMP++ by including `H(pqc_pk)` as
//! a public input verified in-circuit against the 4th leaf scalar.

use crate::leaf::{PqcLeafScalar, ShekylLeaf};
use crate::MAX_INPUTS;
use thiserror::Error;
use zeroize::Zeroize;

/// Errors during FCMP++ proof construction.
#[derive(Debug, Error)]
pub enum ProveError {
    #[error("too many inputs: {0} exceeds maximum {MAX_INPUTS}")]
    TooManyInputs(usize),

    #[error("PQC hash mismatch at input {input_index}: leaf h_pqc differs from pqc_auth commitment")]
    PqcHashMismatch { input_index: usize },

    #[error("tree path unavailable for input {0}")]
    TreePathUnavailable(usize),

    #[error("upstream proof generation failed: {0}")]
    UpstreamError(String),
}

/// Errors during FCMP++ proof verification.
#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("proof deserialization failed")]
    DeserializationFailed,

    #[error("invalid tree root")]
    InvalidTreeRoot,

    #[error("PQC commitment mismatch at input {0}")]
    PqcCommitmentMismatch(usize),

    #[error("key image count mismatch")]
    KeyImageCountMismatch,

    #[error("upstream verification failed: {0}")]
    UpstreamError(String),
}

/// A serialized FCMP++ proof blob (opaque to C++ callers).
#[derive(Clone, Debug, Zeroize)]
pub struct ShekylFcmpProof {
    /// Raw proof bytes (upstream FCMP++ proof + Shekyl extensions).
    pub data: Vec<u8>,
    /// Number of inputs this proof covers.
    pub num_inputs: u32,
    /// Tree depth at the time of proving.
    pub tree_depth: u8,
}

/// Input data required for proof construction.
#[derive(Clone, Debug)]
pub struct ProveInput {
    /// The output being spent (leaf data).
    pub leaf: ShekylLeaf,
    /// Merkle path from leaf to root (serialized layer hashes).
    pub tree_path: Vec<u8>,
    /// Key image for this input.
    pub key_image: [u8; 32],
    /// Pseudo-out commitment.
    pub pseudo_out: [u8; 32],
    /// H(pqc_pk) for the PQC key committed in this leaf.
    pub pqc_hash: PqcLeafScalar,
}

/// Construct an FCMP++ proof for a set of inputs.
///
/// This function coordinates the upstream proof generation with Shekyl's
/// 4-scalar leaf extension. The proof proves:
/// 1. Each input's `{O.x, I.x, C.x, H(pqc_pk)}` exists in the tree
/// 2. The 4th scalar matches the PQC key hash provided as public input
/// 3. Standard FCMP++ linkability/spend-auth properties
///
/// The actual upstream proof call is gated behind the `shekyl-fcmp-plus-plus`
/// crate integration. This scaffolding validates inputs and prepares the
/// data structures.
pub fn prove(
    inputs: &[ProveInput],
    tree_root: &[u8; 32],
    tree_depth: u8,
) -> Result<ShekylFcmpProof, ProveError> {
    if inputs.len() > MAX_INPUTS {
        return Err(ProveError::TooManyInputs(inputs.len()));
    }
    if inputs.is_empty() {
        return Err(ProveError::TooManyInputs(0));
    }

    for (i, input) in inputs.iter().enumerate() {
        if input.tree_path.is_empty() {
            return Err(ProveError::TreePathUnavailable(i));
        }
    }

    // Validate PQC hash consistency: each input's leaf h_pqc must match
    // the separately-provided pqc_hash (which comes from pqc_auth).
    for (i, input) in inputs.iter().enumerate() {
        if input.leaf.h_pqc != input.pqc_hash {
            return Err(ProveError::PqcHashMismatch { input_index: i });
        }
    }

    // TODO(phase-1h): Invoke upstream shekyl-fcmp-plus-plus prove() with
    // 4-scalar leaf inputs once the circuit modification is complete.
    // For now, produce a placeholder proof structure that passes through
    // the FFI layer for integration testing.
    let estimated_size = crate::tree::proof_size(inputs.len(), tree_depth as usize);
    let mut proof_data = Vec::with_capacity(estimated_size);

    // Proof header: version byte + input count + tree depth
    proof_data.push(0x01); // proof version
    proof_data.push(inputs.len() as u8);
    proof_data.push(tree_depth);
    proof_data.extend_from_slice(tree_root);

    // Per-input: key image + pseudo-out + pqc_hash
    for input in inputs {
        proof_data.extend_from_slice(&input.key_image);
        proof_data.extend_from_slice(&input.pseudo_out);
        proof_data.extend_from_slice(&input.pqc_hash.0);
    }

    // Placeholder: mark as incomplete (upstream integration pending)
    proof_data.extend_from_slice(b"SHEKYL_FCMP_SCAFFOLD");

    Ok(ShekylFcmpProof {
        data: proof_data,
        num_inputs: inputs.len() as u32,
        tree_depth,
    })
}

/// Verify an FCMP++ proof.
///
/// Checks:
/// 1. Proof deserializes correctly
/// 2. Key image count matches
/// 3. PQC commitment hashes match the values in the proof's public inputs
/// 4. Tree root matches the referenced block's committed root
/// 5. Upstream FCMP++ verification passes
pub fn verify(
    proof: &ShekylFcmpProof,
    key_images: &[[u8; 32]],
    pseudo_outs: &[[u8; 32]],
    pqc_pk_hashes: &[PqcLeafScalar],
    tree_root: &[u8; 32],
    tree_depth: u8,
) -> Result<bool, VerifyError> {
    if key_images.len() != proof.num_inputs as usize {
        return Err(VerifyError::KeyImageCountMismatch);
    }
    if pseudo_outs.len() != proof.num_inputs as usize {
        return Err(VerifyError::KeyImageCountMismatch);
    }
    if pqc_pk_hashes.len() != proof.num_inputs as usize {
        return Err(VerifyError::PqcCommitmentMismatch(pqc_pk_hashes.len()));
    }
    if proof.tree_depth != tree_depth {
        return Err(VerifyError::InvalidTreeRoot);
    }

    // Verify proof header
    if proof.data.len() < 3 + 32 {
        return Err(VerifyError::DeserializationFailed);
    }
    let proof_tree_root = &proof.data[3..35];
    if proof_tree_root != tree_root.as_slice() {
        return Err(VerifyError::InvalidTreeRoot);
    }

    // TODO(phase-1h): Invoke upstream shekyl-fcmp-plus-plus verify() with
    // batch verifiers once the 4-scalar circuit is integrated.
    // For scaffolding, verify the proof structure is well-formed.
    let expected_per_input = 32 + 32 + 32; // key_image + pseudo_out + pqc_hash
    let expected_min_len = 3 + 32 + (proof.num_inputs as usize * expected_per_input) + 20;
    if proof.data.len() < expected_min_len {
        return Err(VerifyError::DeserializationFailed);
    }

    // Verify PQC hashes embedded in proof match those provided
    let mut offset = 35; // after header + tree_root
    for (i, pqc_hash) in pqc_pk_hashes.iter().enumerate() {
        let ki_end = offset + 32;
        let po_end = ki_end + 32;
        let ph_end = po_end + 32;

        if ph_end > proof.data.len() {
            return Err(VerifyError::DeserializationFailed);
        }

        if key_images[i] != proof.data[offset..ki_end] {
            return Err(VerifyError::PqcCommitmentMismatch(i));
        }
        if pseudo_outs[i] != proof.data[ki_end..po_end] {
            return Err(VerifyError::PqcCommitmentMismatch(i));
        }
        if pqc_hash.0 != proof.data[po_end..ph_end] {
            return Err(VerifyError::PqcCommitmentMismatch(i));
        }

        offset = ph_end;
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_input(idx: u8) -> ProveInput {
        let pqc_hash = PqcLeafScalar([idx; 32]);
        ProveInput {
            leaf: ShekylLeaf {
                o_x: [idx; 32],
                i_x: [idx + 1; 32],
                c_x: [idx + 2; 32],
                h_pqc: pqc_hash,
            },
            tree_path: vec![0u8; 64],
            key_image: [idx + 3; 32],
            pseudo_out: [idx + 4; 32],
            pqc_hash,
        }
    }

    #[test]
    fn prove_verify_roundtrip() {
        let inputs = vec![make_test_input(1), make_test_input(2)];
        let tree_root = [0xaa; 32];
        let tree_depth = 20;

        let proof = prove(&inputs, &tree_root, tree_depth).unwrap();
        assert_eq!(proof.num_inputs, 2);
        assert_eq!(proof.tree_depth, 20);

        let key_images: Vec<_> = inputs.iter().map(|i| i.key_image).collect();
        let pseudo_outs: Vec<_> = inputs.iter().map(|i| i.pseudo_out).collect();
        let pqc_hashes: Vec<_> = inputs.iter().map(|i| i.pqc_hash).collect();

        let result = verify(&proof, &key_images, &pseudo_outs, &pqc_hashes, &tree_root, tree_depth);
        assert!(result.unwrap());
    }

    #[test]
    fn prove_rejects_too_many_inputs() {
        let inputs: Vec<_> = (0..9).map(|i| make_test_input(i)).collect();
        let result = prove(&inputs, &[0; 32], 20);
        assert!(matches!(result, Err(ProveError::TooManyInputs(9))));
    }

    #[test]
    fn prove_rejects_empty_inputs() {
        let result = prove(&[], &[0; 32], 20);
        assert!(matches!(result, Err(ProveError::TooManyInputs(0))));
    }

    #[test]
    fn prove_rejects_empty_tree_path() {
        let mut input = make_test_input(1);
        input.tree_path = vec![];
        let result = prove(&[input], &[0; 32], 20);
        assert!(matches!(result, Err(ProveError::TreePathUnavailable(0))));
    }

    #[test]
    fn prove_rejects_pqc_hash_mismatch() {
        let mut input = make_test_input(1);
        input.pqc_hash = PqcLeafScalar([0xff; 32]);
        let result = prove(&[input], &[0; 32], 20);
        assert!(result.is_err());
    }

    #[test]
    fn prove_max_inputs_accepted() {
        let inputs: Vec<_> = (0..crate::MAX_INPUTS as u8).map(|i| make_test_input(i)).collect();
        let result = prove(&inputs, &[0xaa; 32], 20);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().num_inputs, crate::MAX_INPUTS as u32);
    }

    #[test]
    fn verify_rejects_wrong_tree_root() {
        let inputs = vec![make_test_input(1)];
        let proof = prove(&inputs, &[0xaa; 32], 20).unwrap();

        let key_images = vec![inputs[0].key_image];
        let pseudo_outs = vec![inputs[0].pseudo_out];
        let pqc_hashes = vec![inputs[0].pqc_hash];

        let result = verify(&proof, &key_images, &pseudo_outs, &pqc_hashes, &[0xbb; 32], 20);
        assert!(matches!(result, Err(VerifyError::InvalidTreeRoot)));
    }

    #[test]
    fn verify_rejects_wrong_tree_depth() {
        let inputs = vec![make_test_input(1)];
        let proof = prove(&inputs, &[0xaa; 32], 20).unwrap();

        let key_images = vec![inputs[0].key_image];
        let pseudo_outs = vec![inputs[0].pseudo_out];
        let pqc_hashes = vec![inputs[0].pqc_hash];

        let result = verify(&proof, &key_images, &pseudo_outs, &pqc_hashes, &[0xaa; 32], 15);
        assert!(matches!(result, Err(VerifyError::InvalidTreeRoot)));
    }

    #[test]
    fn verify_rejects_key_image_count_mismatch() {
        let inputs = vec![make_test_input(1), make_test_input(2)];
        let proof = prove(&inputs, &[0xaa; 32], 20).unwrap();

        let result = verify(&proof, &[inputs[0].key_image], &[inputs[0].pseudo_out],
            &[inputs[0].pqc_hash], &[0xaa; 32], 20);
        assert!(matches!(result, Err(VerifyError::KeyImageCountMismatch)));
    }

    #[test]
    fn verify_rejects_tampered_key_image() {
        let inputs = vec![make_test_input(1)];
        let proof = prove(&inputs, &[0xaa; 32], 20).unwrap();
        let mut bad_ki = inputs[0].key_image;
        bad_ki[0] ^= 0xff;

        let result = verify(&proof, &[bad_ki], &[inputs[0].pseudo_out],
            &[inputs[0].pqc_hash], &[0xaa; 32], 20);
        assert!(matches!(result, Err(VerifyError::PqcCommitmentMismatch(_))));
    }

    #[test]
    fn verify_rejects_truncated_proof() {
        let proof = ShekylFcmpProof {
            data: vec![0x01, 0x01, 20],
            num_inputs: 1,
            tree_depth: 20,
        };
        let result = verify(&proof, &[[0u8; 32]], &[[0u8; 32]],
            &[PqcLeafScalar([0u8; 32])], &[0u8; 32], 20);
        assert!(matches!(result, Err(VerifyError::DeserializationFailed)));
    }

    #[test]
    fn prove_verify_single_input() {
        let inputs = vec![make_test_input(42)];
        let tree_root = [0x55; 32];
        let proof = prove(&inputs, &tree_root, 10).unwrap();
        assert_eq!(proof.num_inputs, 1);
        assert_eq!(proof.tree_depth, 10);

        let result = verify(&proof,
            &[inputs[0].key_image],
            &[inputs[0].pseudo_out],
            &[inputs[0].pqc_hash],
            &tree_root, 10);
        assert!(result.unwrap());
    }
}
