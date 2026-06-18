//! Input validation for [`crate::sign_transaction`].
//!
//! All preconditions are checked before any cryptographic work begins.
//! This ensures fast failure with clear error messages and avoids wasting
//! CPU on proof generation for malformed inputs.

use crate::error::TxBuilderError;
use crate::types::{OutputInfo, SpendInput, TreeContext};
use crate::{MAX_INPUTS, MAX_OUTPUTS};
use shekyl_rct_balance::{InputTerm, OutputTerm};
use shekyl_units::AtomicUnits;

/// Prover-side input validation for FCMP++ signing.
///
/// Validates the witness shape before proof construction. The verifier side
/// does not check c1/c2 counts explicitly -- the proof structure implicitly
/// enforces depth through the serialized transcript layout.
///
/// `extra_inputs` / `extra_outputs` are the cleartext `amount * H` balance
/// terms (the same single-sourced [`InputTerm`] / [`OutputTerm`] the verify
/// side checks): they ride on the input or output side of the amount balance
/// exactly like `fee`, with implicit mask 0, so they enter only the
/// funds-sufficiency arithmetic here, not the pseudo-mask balancing or range
/// proofs. The common transfer path passes empty slices.
///
/// Returns `Ok(())` if all preconditions hold, or the first failing
/// [`TxBuilderError`] variant.
pub(crate) fn validate_inputs(
    inputs: &[SpendInput],
    outputs: &[OutputInfo],
    fee: AtomicUnits,
    extra_inputs: &[InputTerm],
    extra_outputs: &[OutputTerm],
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
    let mut input_total = AtomicUnits::ZERO;
    for (i, inp) in inputs.iter().enumerate() {
        if inp.amount.is_zero() {
            return Err(TxBuilderError::ZeroInputAmount { index: i });
        }
        input_total = input_total
            .checked_add(inp.amount)
            .ok_or(TxBuilderError::InputAmountOverflow)?;
    }

    let mut output_total = AtomicUnits::ZERO;
    for (i, out) in outputs.iter().enumerate() {
        if out.amount.is_zero() {
            return Err(TxBuilderError::ZeroOutputAmount { index: i });
        }
        output_total = output_total
            .checked_add(out.amount)
            .ok_or(TxBuilderError::OutputAmountOverflow)?;
    }
    // Fold the cleartext balance terms onto their fixed sides: `extra_inputs`
    // add to what the inputs make available, `extra_outputs` add to what must be
    // covered (alongside `fee`). All checked, so a term cannot silently wrap the
    // money path.
    let extra_in_total = AtomicUnits::checked_sum(extra_inputs.iter().map(|t| t.amount()))
        .ok_or(TxBuilderError::InputAmountOverflow)?;
    let available = input_total
        .checked_add(extra_in_total)
        .ok_or(TxBuilderError::InputAmountOverflow)?;

    let required = output_total
        .checked_add(fee)
        .ok_or(TxBuilderError::OutputAmountOverflow)?;
    let extra_out_total = AtomicUnits::checked_sum(extra_outputs.iter().map(|t| t.amount()))
        .ok_or(TxBuilderError::OutputAmountOverflow)?;
    let required = required
        .checked_add(extra_out_total)
        .ok_or(TxBuilderError::OutputAmountOverflow)?;

    if available < required {
        return Err(TxBuilderError::InsufficientFunds {
            input_total: available.to_raw(),
            output_plus_fee: required.to_raw(),
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

        // Branch layer consistency with tree depth (= upstream layers count).
        //
        // tree_depth here is the upstream library's `layers` value, which
        // includes the leaf layer: layers = LMDB_depth + 1.
        // Branch layers cover everything above the leaf layer:
        //   branch_count = layers - 1
        // Even-indexed branches are C1 (Selene), odd-indexed are C2 (Helios):
        //   c1 = ceil(B/2), c2 = floor(B/2).
        let c1 = inp.c1_layers.len();
        let c2 = inp.c2_layers.len();
        let branch_count = (tree.tree_depth as usize).saturating_sub(1);
        let expected_c1 = branch_count.div_ceil(2);
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
