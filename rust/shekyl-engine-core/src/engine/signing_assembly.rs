// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Orchestrator-side signing-context assembly (Phase 2a §3.4 / CT-5c).
//!
//! Builds a populated [`TxToSign`] from the selected ledger [`TransferDetails`]
//! and the real FCMP++ membership paths the curve-tree client assembled, as
//! one sealed batch (`shekyl_curve_tree::CurveTreeClient::assemble_paths`,
//! delivered as the `AssembleTx` reply — see [`super::curve_tree_actor`]).
//! The per-input secret-pathway fields (`handle`, `key_image`,
//! `source_ciphertext`) come from the transfer; the public membership
//! material (leaf chunk, branch layers) comes from each assembled path and
//! the tree context from the batch — a field copy across the curve-tree →
//! tx-builder type boundary, no transform. Secrets are added only later, in
//! [`super::sign_bridge`] → `SpendInput`, so this stays on the public side
//! of the secret-locality boundary ([`36-secret-locality`]).
//!
//! [`36-secret-locality`]: ../../../../../.cursor/rules/36-secret-locality.mdc

use shekyl_curve_tree::{
    AssembledPath, AssembledPaths, ChunkLeaf, TreeContext as CurveTreeContext,
};
use shekyl_engine_state::TransferDetails;
use shekyl_tx_builder::{LeafEntry, TreeContext};

use super::error::SendError;
use super::network::Network;
use super::pending::TxRequest;
use super::traits::key::{
    FcmpPlusPlusContext, FeeDirective, OutputDestination, TxInputSigningContext, TxOutputContext,
    TxToSign,
};

/// Assemble a [`TxToSign`] from the selected transfers and the batch of
/// their membership paths.
///
/// Input `i` is the transfer at `transfers[selected_indices[i]]`, and the
/// batch's `i`-th path is the one assembled for it (the batch keeps the
/// order its inputs were asked for). [`TransferDetails`] is not `Clone` (it
/// is secret-bearing), so the transfers are read here by index rather than
/// captured at selection time; each re-read is guarded by a `gindex` check
/// against the input the batch's path was assembled for, so an index shift
/// under a reorg between selection and this fold is refused, not
/// mis-signed. The batch is to one tree by construction (R-26), so the
/// tx's `FcmpPlusPlusContext` takes the batch's tree context.
pub(crate) fn assemble_tx_to_sign(
    network: Network,
    request: &TxRequest,
    selected_indices: &[usize],
    transfers: &[TransferDetails],
    paths: &AssembledPaths,
    fee_directive: FeeDirective,
) -> Result<TxToSign, SendError> {
    // The selection and the batch are built in lockstep (selection → one
    // `AssembleInput` per index → one path per input), so a length mismatch
    // is an internal plumbing bug, not a runtime condition. The
    // `debug_assert` surfaces the actual counts in dev/CI (where it would be
    // diagnosed); the release guard refuses gracefully rather than letting
    // the `zip` below silently truncate to a shorter — and unsound —
    // transaction. (`BuildInvariant`'s reason is `&'static str`, so the
    // counts ride the assert rather than the error.)
    debug_assert_eq!(
        selected_indices.len(),
        paths.len(),
        "assembled path count must equal selected input count",
    );
    if selected_indices.len() != paths.len() {
        return Err(SendError::BuildInvariant {
            reason: "assembled path count does not match selected input count",
        });
    }

    let mut inputs = Vec::with_capacity(selected_indices.len());
    for (&index, (asked, path)) in selected_indices.iter().zip(paths.paths()) {
        let td = transfers.get(index).ok_or(SendError::BuildInvariant {
            reason: "selected transfer index out of range",
        })?;
        // Index-stability guard: the transfer at this index must still be the
        // output its path was assembled for. A `gindex` mismatch means the
        // transfer vector shifted under the tx between selection and fold (a
        // reorg during the AssembleTx round-trip) — refuse rather than bind the
        // wrong secrets to this path.
        if td.global_output_index != asked.gindex {
            return Err(SendError::BuildInvariant {
                reason: "selected transfer shifted under the transaction during assembly",
            });
        }
        inputs.push(input_context_from_transfer(td, path)?);
    }

    let tree = tree_context_from(&paths.tree());

    let mut outputs = Vec::with_capacity(request.recipients.len() + 1);
    for recipient in &request.recipients {
        outputs.push(TxOutputContext::Payment {
            dest: OutputDestination {
                destination: recipient.destination.clone(),
                rid: recipient.rid,
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
    let key_image = td.key_image.ok_or(SendError::BuildInvariant {
        reason: "transfer missing key_image (scanner/indexes not populated)",
    })?;
    let handle = td.output_handle.ok_or(SendError::BuildInvariant {
        reason: "transfer missing output_handle (engine post-pass not run)",
    })?;
    let source_ciphertext = td
        .source_ciphertext
        .clone()
        .ok_or(SendError::BuildInvariant {
            reason: "transfer missing source_ciphertext",
        })?;
    let output_key = td.key.compress().to_bytes();
    let commitment = td.commitment.calculate().compress().to_bytes();

    // The chunk carries the path node's full child set, including the spent
    // output; the signer (tx-builder) re-derives this input's own PQC leaf
    // commitment from its secrets and checks it against that entry before
    // proving (`PL-D3`; a mismatch is the typed received-but-unspendable
    // refusal), so nothing about the own leaf is read here.
    let leaf_chunk: Vec<LeafEntry> = path
        .leaf_chunk()
        .iter()
        .map(leaf_entry_from_chunk)
        .collect();

    Ok(TxInputSigningContext {
        handle,
        tx_hash: td.tx_hash,
        internal_output_index: td.internal_output_index.to_raw(),
        amount: td.amount(),
        key_image,
        source_ciphertext,
        output_key,
        commitment,
        leaf_chunk,
        c1_layers: path.c1_layers().to_vec(),
        c2_layers: path.c2_layers().to_vec(),
    })
}

/// Field copy across the curve-tree → tx-builder boundary (mirror types, no
/// transform). Shared with the emission-claim orchestrator
/// ([`super::claim_orchestrator`]), whose fee/backing paths cross the same
/// boundary.
pub(crate) fn leaf_entry_from_chunk(cl: &ChunkLeaf) -> LeafEntry {
    LeafEntry {
        output_key: cl.output_key.to_bytes(),
        key_image_gen: cl.key_image_gen,
        commitment: cl.commitment.to_bytes(),
        cm_x: cl.cm_x,
    }
}

/// Field copy for the tree context half of the same boundary (see
/// [`leaf_entry_from_chunk`]).
pub(crate) fn tree_context_from(tree: &CurveTreeContext) -> TreeContext {
    TreeContext {
        reference_block: tree.reference_block,
        tree_root: tree.tree_root,
        tree_depth: tree.tree_depth,
    }
}
