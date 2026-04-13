//! Input validation for [`crate::sign_transaction`].
//!
//! All preconditions are checked before any cryptographic work begins.
//! This ensures fast failure with clear error messages and avoids wasting
//! CPU on proof generation for malformed inputs.

use crate::error::TxBuilderError;
use crate::types::{OutputInfo, SpendInput, TreeContext};
use crate::{MAX_INPUTS, MAX_OUTPUTS};

/// Prover-side input validation for FCMP++ signing.
///
/// Validates the witness shape before proof construction. The verifier side
/// does not check c1/c2 counts explicitly -- the proof structure implicitly
/// enforces depth through the serialized transcript layout.
///
/// Returns `Ok(())` if all preconditions hold, or the first failing
/// [`TxBuilderError`] variant.
pub(crate) fn validate_inputs(
    inputs: &[SpendInput],
    outputs: &[OutputInfo],
    fee: u64,
    tree: &TreeContext,
) -> Result<(), TxBuilderError> {
    // --- Count bounds ---
    if inputs.is_empty() {
        return Err(TxBuilderError::NoInputs);
    }
    if inputs.len() > MAX_INPUTS {
        return Err(TxBuilderError::TooManyInputs(inputs.len()));
    }
    if outputs.is_empty() {
        return Err(TxBuilderError::NoOutputs);
    }
    if outputs.len() > MAX_OUTPUTS {
        return Err(TxBuilderError::TooManyOutputs(outputs.len()));
    }

    // --- Amount checks ---
    let mut input_total: u64 = 0;
    for (i, inp) in inputs.iter().enumerate() {
        if inp.amount == 0 {
            return Err(TxBuilderError::ZeroInputAmount { index: i });
        }
        input_total = input_total
            .checked_add(inp.amount)
            .ok_or(TxBuilderError::InputAmountOverflow)?;
    }

    let mut output_total: u64 = 0;
    for (i, out) in outputs.iter().enumerate() {
        if out.amount == 0 {
            return Err(TxBuilderError::ZeroOutputAmount { index: i });
        }
        output_total = output_total
            .checked_add(out.amount)
            .ok_or(TxBuilderError::OutputAmountOverflow)?;
    }
    let output_plus_fee = output_total
        .checked_add(fee)
        .ok_or(TxBuilderError::OutputAmountOverflow)?;
    if input_total < output_plus_fee {
        return Err(TxBuilderError::InsufficientFunds {
            input_total,
            output_plus_fee,
        });
    }

    // --- Tree depth ---
    if tree.tree_depth == 0 {
        return Err(TxBuilderError::ZeroTreeDepth);
    }
    if tree.tree_depth > shekyl_fcmp::MAX_TREE_DEPTH {
        return Err(TxBuilderError::TreeDepthTooLarge(tree.tree_depth));
    }

    let selene_chunk_width = shekyl_fcmp::SELENE_CHUNK_WIDTH;

    // --- Per-input structural checks ---
    for (i, inp) in inputs.iter().enumerate() {
        if inp.leaf_chunk.is_empty() {
            return Err(TxBuilderError::EmptyLeafChunk { index: i });
        }
        if inp.leaf_chunk.len() > selene_chunk_width {
            return Err(TxBuilderError::LeafChunkTooLarge {
                index: i,
                count: inp.leaf_chunk.len(),
                max: selene_chunk_width,
            });
        }

        // Branch layer consistency with tree depth.
        // The FCMP++ tree alternates Selene (C1) and Helios (C2) layers.
        // Layer 0 is always the leaf hash (Selene); branch layers sit above it.
        // For depth d: c1_count + c2_count + 1 == d.
        // Even-indexed branches are C1, odd-indexed are C2, so c1 == c2 or
        // c1 == c2 + 1.
        let c1 = inp.c1_layers.len();
        let c2 = inp.c2_layers.len();
        let depth = tree.tree_depth as usize;
        let branch_count = depth.saturating_sub(1);
        let expected_c1 = (branch_count + 1) / 2;
        let expected_c2 = branch_count / 2;
        if c1 != expected_c1 || c2 != expected_c2 {
            return Err(TxBuilderError::BranchLayerMismatch {
                index: i,
                c1,
                c2,
                depth: tree.tree_depth,
            });
        }

        if inp.combined_ss.len() != 64 {
            return Err(TxBuilderError::InvalidCombinedSsLength {
                index: i,
                len: inp.combined_ss.len(),
            });
        }
    }

    Ok(())
}
