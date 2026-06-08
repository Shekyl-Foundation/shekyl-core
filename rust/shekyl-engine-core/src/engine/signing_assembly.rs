// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Orchestrator-side signing-context assembly (Phase 2a §3.4).
//!
//! Builds populated [`TxToSign`] from ledger [`TransferDetails`] and the
//! build request. Real curve-tree paths and tree-root verification land
//! with the curve-tree client (§3.0.4); until then the synthetic depth-1
//! path per §3.0.5 supplies structural placeholders for 2a-2 plumbing.

use curve25519_dalek::EdwardsPoint;
use shekyl_engine_state::TransferDetails;
use shekyl_generators::biased_hash_to_point;
use shekyl_oxide::primitives::Commitment;
use shekyl_tx_builder::{LeafEntry, TreeContext};

use super::error::SendError;
use super::pending::TxRequest;
use super::traits::key::{
    FcmpPlusPlusContext, FeeDirective, OutputDestination, TxInputSigningContext, TxOutputContext,
    TxToSign,
};

/// Synthetic single-leaf tree depth for pre-client 2a builds (§3.0.5).
const SYNTHETIC_2A_TREE_DEPTH: u8 = 1;

/// Placeholder tree root until the curve-tree client supplies the real root.
const SYNTHETIC_2A_TREE_ROOT: [u8; 32] = [0u8; 32];

/// Assemble a [`TxToSign`] for the selected transfer indices.
pub(crate) fn assemble_tx_to_sign(
    request: &TxRequest,
    selected_indices: &[usize],
    transfers: &[TransferDetails],
    reference_block: [u8; 32],
    fee_directive: FeeDirective,
) -> Result<TxToSign, SendError> {
    let mut inputs = Vec::with_capacity(selected_indices.len());

    for &index in selected_indices {
        let td = transfers.get(index).ok_or(SendError::CannotSign {
            reason: "selected transfer index out of range",
        })?;
        inputs.push(input_context_from_transfer(td)?);
    }

    let tree = TreeContext {
        reference_block,
        tree_root: SYNTHETIC_2A_TREE_ROOT,
        tree_depth: SYNTHETIC_2A_TREE_DEPTH,
    };

    let mut outputs = Vec::with_capacity(request.recipients.len() + 1);
    for recipient in &request.recipients {
        outputs.push(TxOutputContext::Payment {
            dest: OutputDestination {
                address: recipient.address.clone(),
            },
            amount: recipient.amount_atomic_units.to_raw(),
        });
    }
    outputs.push(TxOutputContext::Change);

    Ok(TxToSign {
        inputs,
        outputs,
        fcmp_plus_plus_context: FcmpPlusPlusContext { tree },
        fee: fee_directive,
    })
}

fn input_context_from_transfer(td: &TransferDetails) -> Result<TxInputSigningContext, SendError> {
    let handle = td.output_handle.ok_or(SendError::CannotSign {
        reason: "transfer missing output_handle (engine post-pass not run)",
    })?;
    let source_ciphertext = td.source_ciphertext.clone().ok_or(SendError::CannotSign {
        reason: "transfer missing source_ciphertext",
    })?;
    let output_key = output_key_bytes(&td.key);
    let commitment = commitment_bytes(&td.commitment);
    let h_pqc = synthetic_h_pqc_bytes(td.internal_output_index);
    let key_image_gen = key_image_gen_bytes(&output_key);

    let leaf_entry = LeafEntry {
        output_key,
        key_image_gen,
        commitment,
        h_pqc,
    };

    Ok(TxInputSigningContext {
        handle,
        source_ciphertext,
        output_key,
        commitment,
        h_pqc,
        leaf_chunk: vec![leaf_entry],
        c1_layers: Vec::new(),
        c2_layers: Vec::new(),
    })
}

fn output_key_bytes(point: &EdwardsPoint) -> [u8; 32] {
    point.compress().to_bytes()
}

fn commitment_bytes(commitment: &Commitment) -> [u8; 32] {
    commitment.calculate().compress().to_bytes()
}

fn key_image_gen_bytes(output_key: &[u8; 32]) -> [u8; 32] {
    biased_hash_to_point(*output_key).compress().to_bytes()
}

fn synthetic_h_pqc_bytes(seed: u64) -> [u8; 32] {
    use ciphersuite::group::ff::PrimeField;
    let mut buf = [0u8; 64];
    buf[..8].copy_from_slice(&seed.to_le_bytes());
    buf[32..40].copy_from_slice(&seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).to_le_bytes());
    let h_pqc_field = dalek_ff_group::FieldElement::wide_reduce(buf);
    h_pqc_field.to_repr()
}
