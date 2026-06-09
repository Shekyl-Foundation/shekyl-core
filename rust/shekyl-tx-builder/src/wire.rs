//! Wire adapter: assemble `shekyl_oxide::transaction::Transaction::V2` and serialize.
//!
//! This module is the **sole** importer of `shekyl_oxide::transaction::Transaction`
//! in the `shekyl-tx-builder` crate (`sign.rs` stays format-agnostic).

use shekyl_io::{write_varint, write_vec, CompressedPoint};
use shekyl_oxide::fcmp::bulletproofs::Bulletproof;
use shekyl_oxide::fcmp::{
    EncryptedAmount, EncryptedLabel, ProofBase, ProofType, Proofs, PrunableProof,
};
use shekyl_oxide::primitives::keccak256;
use shekyl_oxide::transaction::{
    Input, NotPruned, Output, Timelock, Transaction, TransactionPrefix,
};

use crate::error::TxBuilderError;
use crate::types::PqcAuth;

/// Material for final on-wire transaction encoding (Phase 2a §4).
#[derive(Clone, Debug)]
pub struct WireEncodeInput {
    pub key_images: Vec<[u8; 32]>,
    pub output_keys: Vec<[u8; 32]>,
    pub view_tags: Vec<Option<u8>>,
    pub tx_extra: Vec<u8>,
    pub fee: u64,
    pub enc_amounts: Vec<[u8; 9]>,
    pub enc_labels: Vec<[u8; 9]>,
    pub out_commitments: Vec<[u8; 32]>,
    pub pseudo_outs: Vec<[u8; 32]>,
    pub bulletproof: Bulletproof,
    pub reference_block: [u8; 32],
    pub fcmp_proof: Vec<u8>,
    pub pqc_auths: Vec<PqcAuth>,
}

fn reference_block_u64(block: &[u8; 32]) -> u64 {
    let mut le = [0u8; 8];
    le.copy_from_slice(&block[..8]);
    u64::from_le_bytes(le)
}

fn serialize_prefix_blob(prefix: &TransactionPrefix) -> Result<Vec<u8>, TxBuilderError> {
    let mut buf = Vec::new();
    prefix
        .additional_timelock
        .write(&mut buf)
        .map_err(|e| TxBuilderError::WireError(format!("timelock write: {e}")))?;
    write_vec(Input::write, &prefix.inputs, &mut buf)
        .map_err(|e| TxBuilderError::WireError(format!("inputs write: {e}")))?;
    write_vec(Output::write, &prefix.outputs, &mut buf)
        .map_err(|e| TxBuilderError::WireError(format!("outputs write: {e}")))?;
    write_varint(&prefix.extra.len(), &mut buf)
        .map_err(|e| TxBuilderError::WireError(format!("extra len: {e}")))?;
    buf.extend_from_slice(&prefix.extra);
    Ok(buf)
}

fn tx_prefix_hash(prefix: &TransactionPrefix) -> [u8; 32] {
    let mut buf = Vec::new();
    write_varint(&2u8, &mut buf).expect("vec write");
    buf.extend_from_slice(&serialize_prefix_blob(prefix).expect("prefix blob serializes in tests"));
    keccak256(buf)
}

fn pqc_header_blob(auth: &PqcAuth) -> Vec<u8> {
    let pk_len = u32::try_from(auth.public_key.len())
        .map_err(|_| TxBuilderError::WireError("PQC public key length exceeds u32".into()))
        .expect("hybrid PQC public keys fit in u32");
    let mut out = Vec::with_capacity(4 + auth.public_key.len());
    out.push(auth.auth_version);
    out.push(1); // HYBRID_SCHEME_ID_ED25519_ML_DSA_65
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&pk_len.to_le_bytes());
    out.extend_from_slice(&auth.public_key);
    out
}

fn build_prefix(input: &WireEncodeInput) -> TransactionPrefix {
    let inputs: Vec<Input> = input
        .key_images
        .iter()
        .map(|ki| Input::ToKey {
            amount: None,
            key_offsets: Vec::new(),
            key_image: CompressedPoint::from(*ki),
        })
        .collect();

    let outputs: Vec<Output> = input
        .output_keys
        .iter()
        .zip(input.view_tags.iter())
        .map(|(key, view_tag)| Output {
            amount: None,
            key: CompressedPoint::from(*key),
            view_tag: *view_tag,
            staking: None,
        })
        .collect();

    TransactionPrefix {
        additional_timelock: Timelock::None,
        inputs,
        outputs,
        extra: input.tx_extra.clone(),
    }
}

fn build_proofs(input: &WireEncodeInput, n_in: usize, n_out: usize) -> Proofs {
    let base = ProofBase {
        fee: input.fee,
        encrypted_amounts: input
            .enc_amounts
            .iter()
            .map(|bytes| EncryptedAmount {
                amount: bytes[..8].try_into().expect("enc_amount len"),
                amount_tag: bytes[8],
            })
            .collect(),
        encrypted_labels: input
            .enc_labels
            .iter()
            .map(|bytes| EncryptedLabel {
                label: bytes[..8].try_into().expect("enc_label len"),
                label_tag: bytes[8],
            })
            .collect(),
        commitments: input
            .out_commitments
            .iter()
            .map(|c| CompressedPoint::from(*c))
            .collect(),
    };

    debug_assert_eq!(base.encrypted_amounts.len(), n_out);
    debug_assert_eq!(base.commitments.len(), n_out);
    debug_assert_eq!(input.pseudo_outs.len(), n_in);

    // PrunableProof stores per-input signature bytes only; the PQC header
    // is hashed separately in `phase1_payload_hashes`.
    let pqc_blobs: Vec<Vec<u8>> = input
        .pqc_auths
        .iter()
        .map(|auth| auth.signature.clone())
        .collect();

    let prunable = PrunableProof {
        pseudo_outs: input
            .pseudo_outs
            .iter()
            .map(|p| CompressedPoint::from(*p))
            .collect(),
        bulletproof: input.bulletproof.clone(),
        reference_block: reference_block_u64(&input.reference_block),
        fcmp_proof: input.fcmp_proof.clone(),
        pqc_auths: pqc_blobs,
    };

    Proofs { base, prunable }
}

/// Build per-input PQC payload hashes (Keccak-256) mirroring C++ `get_transaction_signed_payload`.
pub fn phase1_payload_hashes(input: &WireEncodeInput) -> Result<Vec<[u8; 32]>, TxBuilderError> {
    let prefix = build_prefix(input);
    let prefix_blob = serialize_prefix_blob(&prefix)?;

    let n_in = input.key_images.len();
    let n_out = input.output_keys.len();
    let proofs = build_proofs(input, n_in, n_out);

    let mut rct_base_blob = Vec::new();
    proofs
        .base
        .write(&mut rct_base_blob, ProofType::FcmpPlusPlusPqc)
        .map_err(|e| TxBuilderError::WireError(format!("rct base write: {e}")))?;

    let prunable_hash = keccak256(proofs.prunable.serialize());

    let mut all_key_hashes = Vec::with_capacity(n_in * 32);
    for auth in &input.pqc_auths {
        all_key_hashes.extend_from_slice(&keccak256(&auth.public_key));
    }

    let mut hashes = Vec::with_capacity(n_in);
    for (i, auth) in input.pqc_auths.iter().enumerate().take(n_in) {
        let header = pqc_header_blob(auth);
        let mut payload = Vec::new();
        payload.extend_from_slice(&prefix_blob);
        payload.extend_from_slice(&rct_base_blob);
        payload.extend_from_slice(&prunable_hash);
        payload.extend_from_slice(&header);
        payload.extend_from_slice(&all_key_hashes);
        let _ = i;
        hashes.push(keccak256(payload));
    }
    Ok(hashes)
}

/// Assemble and serialize the final signed transaction bytes.
pub fn encode_final_tx(input: &WireEncodeInput) -> Result<Vec<u8>, TxBuilderError> {
    let prefix = build_prefix(input);
    let n_in = input.key_images.len();
    let n_out = input.output_keys.len();
    let proofs = build_proofs(input, n_in, n_out);

    let tx: Transaction<NotPruned> = Transaction::V2 {
        prefix,
        proofs: Some(proofs),
    };

    Ok(tx.serialize())
}

/// Prefix hash used as FCMP++ `signable_tx_hash` input.
pub fn tx_prefix_hash_for_signing(input: &WireEncodeInput) -> [u8; 32] {
    tx_prefix_hash(&build_prefix(input))
}

/// Prefix hash from prefix fields only (no proofs required).
pub fn tx_prefix_hash_from_parts(
    key_images: &[[u8; 32]],
    output_keys: &[[u8; 32]],
    view_tags: &[Option<u8>],
    tx_extra: &[u8],
) -> [u8; 32] {
    let prefix = TransactionPrefix {
        additional_timelock: Timelock::None,
        inputs: key_images
            .iter()
            .map(|ki| Input::ToKey {
                amount: None,
                key_offsets: Vec::new(),
                key_image: CompressedPoint::from(*ki),
            })
            .collect(),
        outputs: output_keys
            .iter()
            .zip(view_tags.iter())
            .map(|(key, view_tag)| Output {
                amount: None,
                key: CompressedPoint::from(*key),
                view_tag: *view_tag,
                staking: None,
            })
            .collect(),
        extra: tx_extra.to_vec(),
    };
    tx_prefix_hash(&prefix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_oxide::fcmp::bulletproofs::Bulletproof;

    fn minimal_input() -> WireEncodeInput {
        WireEncodeInput {
            key_images: vec![[1u8; 32]],
            output_keys: vec![[2u8; 32]],
            view_tags: vec![Some(3)],
            tx_extra: vec![1, 2, 3],
            fee: 1_000,
            enc_amounts: vec![[0u8; 9]],
            enc_labels: vec![[0u8; 9]],
            out_commitments: vec![[4u8; 32]],
            pseudo_outs: vec![[5u8; 32]],
            bulletproof: Bulletproof::prove_plus(
                &mut rand_core::OsRng,
                vec![shekyl_primitives::Commitment::new(
                    curve25519_dalek::scalar::Scalar::from(1u64),
                    100,
                )],
            )
            .expect("bp prove"),
            reference_block: [0xAB; 32],
            fcmp_proof: vec![0xCC; 64],
            pqc_auths: vec![PqcAuth {
                auth_version: 1,
                signature: vec![0xDD; 128],
                public_key: vec![0xEE; 64],
            }],
        }
    }

    #[test]
    fn encode_final_tx_is_deterministic() {
        let input = minimal_input();
        let a = encode_final_tx(&input).expect("encode");
        let b = encode_final_tx(&input).expect("encode");
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn shekyl_oxide_transaction_import_is_wire_only() {
        let lib_rs = include_str!("lib.rs");
        let sign_rs = include_str!("sign.rs");
        let types_rs = include_str!("types.rs");
        assert!(
            !lib_rs.contains("shekyl_oxide::transaction"),
            "lib.rs must not import shekyl_oxide::transaction"
        );
        assert!(
            !sign_rs.contains("shekyl_oxide::transaction"),
            "sign.rs must stay format-agnostic"
        );
        assert!(
            !types_rs.contains("shekyl_oxide::transaction"),
            "types.rs must stay format-agnostic"
        );
    }

    #[test]
    fn phase1_payload_hashes_len_matches_inputs() {
        let input = minimal_input();
        let hashes = phase1_payload_hashes(&input).expect("hashes");
        assert_eq!(hashes.len(), input.key_images.len());
    }
}
