// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Orchestrator-side signing-context assembly (Phase 2a §3.4 / CT-5c).
//!
//! Builds a populated [`TxToSign`] from the selected ledger [`TransferDetails`]
//! and the real FCMP++ membership paths assembled by the curve-tree client
//! (`shekyl_curve_tree::CurveTreeClient::assemble_path`, delivered as the batch
//! `AssembleTx` reply — see [`super::curve_tree_actor`]). The per-input
//! secret-pathway fields (`handle`, `key_image`, `source_ciphertext`) come from
//! the transfer; the public membership material (leaf chunk, branch layers,
//! tree context) comes from the assembled path — a field copy across the
//! curve-tree → tx-builder type boundary, no transform. Secrets are added only
//! later, in [`super::sign_bridge`] → `SpendInput`, so this stays on the public
//! side of the secret-locality boundary ([`36-secret-locality`]).
//!
//! [`36-secret-locality`]: ../../../../../.cursor/rules/36-secret-locality.mdc

use shekyl_curve_tree::{AssembleInput, AssembledPath, ChunkLeaf, TreeContext as CurveTreeContext};
use shekyl_engine_state::TransferDetails;
use shekyl_tx_builder::{LeafEntry, TreeContext};

use super::error::SendError;
use super::network::Network;
use super::pending::TxRequest;
use super::traits::key::{
    FcmpPlusPlusContext, FeeDirective, OutputDestination, TxInputSigningContext, TxOutputContext,
    TxToSign,
};

/// Assemble a [`TxToSign`] from the selected transfers and their assembled
/// membership paths.
///
/// `selected_indices`, `assemble_inputs`, and `paths` are parallel arrays in
/// transaction input order: input `i` is the transfer at
/// `transfers[selected_indices[i]]`, whose membership request was
/// `assemble_inputs[i]` and whose assembled path is `paths[i]`.
/// [`TransferDetails`] is not `Clone` (it is secret-bearing), so the transfers
/// are read here by index rather than captured at selection time; each re-read
/// is guarded by a `gindex` check against `assemble_inputs[i]`, so an index
/// shift under a reorg between selection and this fold is refused, not
/// mis-signed. Every path shares one [`shekyl_curve_tree::TreeContext`] (the C1
/// single-snapshot guarantee — `assemble_tx` anchored every input to one
/// reference), so the tx's `FcmpPlusPlusContext` takes the first path's tree
/// context.
pub(crate) fn assemble_tx_to_sign(
    network: Network,
    request: &TxRequest,
    selected_indices: &[usize],
    transfers: &[TransferDetails],
    assemble_inputs: &[AssembleInput],
    paths: &[AssembledPath],
    fee_directive: FeeDirective,
) -> Result<TxToSign, SendError> {
    if selected_indices.len() != paths.len() || selected_indices.len() != assemble_inputs.len() {
        return Err(SendError::CannotSign {
            reason: "assembled path count does not match selected input count",
        });
    }
    let Some(first) = paths.first() else {
        return Err(SendError::CannotSign {
            reason: "transaction has no inputs to assemble",
        });
    };

    let mut inputs = Vec::with_capacity(selected_indices.len());
    for ((&index, ai), path) in selected_indices.iter().zip(assemble_inputs).zip(paths) {
        let td = transfers.get(index).ok_or(SendError::CannotSign {
            reason: "selected transfer index out of range",
        })?;
        // Index-stability guard: the transfer at this index must still be the
        // output its path was assembled for. A `gindex` mismatch means the
        // transfer vector shifted under the tx between selection and fold (a
        // reorg during the AssembleTx round-trip) — refuse rather than bind the
        // wrong secrets to this path.
        if td.global_output_index != ai.gindex.0 {
            return Err(SendError::CannotSign {
                reason: "selected transfer shifted under the transaction during assembly",
            });
        }
        inputs.push(input_context_from_transfer(td, path)?);
    }

    // C1: one tree context for the whole tx. `assemble_tx` anchored every path
    // to the same reference block, so all `path.tree` are equal; take the first.
    let tree = tree_context_from(&first.tree);

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
    path: &AssembledPath,
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
    let output_key = td.key.compress().to_bytes();
    let commitment = td.commitment.calculate().compress().to_bytes();

    let leaf_chunk: Vec<LeafEntry> = path.leaf_chunk.iter().map(leaf_entry_from_chunk).collect();
    // This input's own PQC leaf hash is the real `h_pqc` of its own entry in the
    // assembled leaf chunk (the chunk carries the path node's full child set,
    // including the spent output). Matched by output key — `assemble_path`'s
    // post-resolution identity check already guaranteed the resolved leaf is
    // this output, so the entry is present.
    let h_pqc = path
        .leaf_chunk
        .iter()
        .find(|cl| cl.output_key == output_key)
        .map(|cl| cl.h_pqc)
        .ok_or(SendError::CannotSign {
            reason: "assembled leaf chunk does not contain the spent output",
        })?;

    Ok(TxInputSigningContext {
        handle,
        // Signing context crosses into the crypto/FCMP layer, which takes raw
        // `[u8; 32]` (rule 18); convert at this edge.
        tx_hash: td.tx_hash.to_bytes(),
        internal_output_index: td.internal_output_index,
        amount: td.amount(),
        key_image,
        source_ciphertext,
        output_key,
        commitment,
        h_pqc,
        leaf_chunk,
        c1_layers: path.c1_layers.clone(),
        c2_layers: path.c2_layers.clone(),
    })
}

/// Field copy across the curve-tree → tx-builder boundary (mirror types, no
/// transform).
fn leaf_entry_from_chunk(cl: &ChunkLeaf) -> LeafEntry {
    LeafEntry {
        output_key: cl.output_key,
        key_image_gen: cl.key_image_gen,
        commitment: cl.commitment,
        h_pqc: cl.h_pqc,
    }
}

fn tree_context_from(tree: &CurveTreeContext) -> TreeContext {
    TreeContext {
        reference_block: tree.reference_block,
        tree_root: tree.tree_root,
        tree_depth: tree.tree_depth,
    }
}
