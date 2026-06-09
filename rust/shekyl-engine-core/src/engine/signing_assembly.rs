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
use shekyl_tx_builder::LeafEntry;

use super::error::SendError;
use super::network::Network;
use super::pending::TxRequest;
use super::synthetic_tree::{enrich_input_tree, synthetic_h_pqc_bytes, synthetic_tree_context};
use super::traits::key::{
    FcmpPlusPlusContext, FeeDirective, OutputDestination, TxInputSigningContext, TxOutputContext,
    TxToSign,
};

/// Assemble a [`TxToSign`] for the selected transfer indices.
pub(crate) fn assemble_tx_to_sign(
    network: Network,
    request: &TxRequest,
    selected_indices: &[usize],
    transfers: &[TransferDetails],
    reference_block: [u8; 32],
    tree_depth: u8,
    fee_directive: FeeDirective,
) -> Result<TxToSign, SendError> {
    let mut inputs = Vec::with_capacity(selected_indices.len());

    for &index in selected_indices {
        let td = transfers.get(index).ok_or(SendError::CannotSign {
            reason: "selected transfer index out of range",
        })?;
        inputs.push(input_context_from_transfer(td, tree_depth)?);
    }

    let leaf_for_root = inputs
        .first()
        .map(|i| i.leaf_chunk.as_slice())
        .unwrap_or(&[]);
    let tree = synthetic_tree_context(reference_block, tree_depth, leaf_for_root);

    let mut outputs = Vec::with_capacity(request.recipients.len() + 1);
    for recipient in &request.recipients {
        outputs.push(TxOutputContext::Payment {
            dest: OutputDestination {
                address: recipient.address.clone(),
            },
            amount: recipient.amount_atomic_units.to_raw(),
        });
    }
    outputs.push(TxOutputContext::Change {
        subaddress_index: 0,
    });

    Ok(TxToSign {
        network,
        inputs,
        outputs,
        fcmp_plus_plus_context: FcmpPlusPlusContext { tree },
        fee: fee_directive,
    })
}

fn input_context_from_transfer(
    td: &TransferDetails,
    tree_depth: u8,
) -> Result<TxInputSigningContext, SendError> {
    let key_image = td.key_image.ok_or(SendError::CannotSign {
        reason: "transfer missing key_image (scanner/indexes not populated)",
    })?;
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

    let (leaf_chunk, c1_layers, c2_layers, _) = enrich_input_tree(vec![leaf_entry], tree_depth);

    Ok(TxInputSigningContext {
        handle,
        tx_hash: td.tx_hash,
        internal_output_index: td.internal_output_index,
        amount: td.amount(),
        key_image,
        source_ciphertext,
        output_key,
        commitment,
        h_pqc,
        leaf_chunk,
        c1_layers,
        c2_layers,
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
