//! Unit tests for `shekyl-tx-builder`.
//!
//! ## Validation edge cases
//! These tests verify that every [`TxBuilderError`] variant is correctly triggered
//! by the input validation layer, before any cryptographic work begins.
//!
//! ## Functional tests
//! Require valid test fixtures (key material, tree paths) and are gated behind
//! the `test_fixtures` cfg (run manually with real curve tree data).

use crate::error::TxBuilderError;
use crate::sign::{sign_pqc_auths, sign_transaction};
use crate::types::*;
use crate::validate::validate_inputs;
use crate::{MAX_INPUTS, MAX_OUTPUTS};
use shekyl_units::AtomicUnits;

fn dummy_leaf_entry() -> LeafEntry {
    LeafEntry {
        output_key: [1u8; 32],
        key_image_gen: [2u8; 32],
        commitment: [3u8; 32],
        h_pqc: [4u8; 32],
    }
}

fn dummy_spend_input(amount: u64) -> SpendInput {
    // depth=2 -> 1 branch at index 0 (tree layer 1) -> C2 (Helios), 0 C1 (Selene)
    SpendInput {
        output_key: [1u8; 32],
        commitment: [3u8; 32],
        amount: AtomicUnits::from_raw(amount),
        spend_key_x: [5u8; 32],
        spend_key_y: [6u8; 32],
        commitment_mask: [7u8; 32],
        h_pqc: [4u8; 32],
        combined_ss: vec![0u8; 64],
        output_index: 0,
        leaf_chunk: vec![dummy_leaf_entry()],
        c1_layers: vec![],
        c2_layers: vec![vec![[12u8; 32]]],
    }
}

fn dummy_output(amount: u64) -> OutputInfo {
    OutputInfo {
        dest_key: [20u8; 32],
        amount: AtomicUnits::from_raw(amount),
        commitment_mask: [21u8; 32],
        enc_amount: [0u8; 9],
        enc_label: [0u8; 9],
    }
}

fn dummy_tree() -> TreeContext {
    TreeContext {
        reference_block: [30u8; 32],
        tree_root: [31u8; 32],
        tree_depth: 2,
    }
}

// ── Validation edge cases ────────────────────────────────────────────

#[test]
fn test_no_inputs() {
    let result = sign_transaction(
        [0u8; 32],
        &[],
        &[dummy_output(100)],
        AtomicUnits::ZERO,
        &dummy_tree(),
    );
    assert!(matches!(result, Err(TxBuilderError::NoInputs)));
}

#[test]
fn test_too_many_inputs() {
    let inputs: Vec<SpendInput> = (0..=MAX_INPUTS).map(|_| dummy_spend_input(100)).collect();
    let result = sign_transaction(
        [0u8; 32],
        &inputs,
        &[dummy_output(100)],
        AtomicUnits::ZERO,
        &dummy_tree(),
    );
    assert!(matches!(result, Err(TxBuilderError::TooManyInputs(_))));
}

#[test]
fn test_no_outputs() {
    let result = sign_transaction(
        [0u8; 32],
        &[dummy_spend_input(100)],
        &[],
        AtomicUnits::ZERO,
        &dummy_tree(),
    );
    assert!(matches!(result, Err(TxBuilderError::NoOutputs)));
}

#[test]
fn test_too_many_outputs() {
    let outputs: Vec<OutputInfo> = (0..=MAX_OUTPUTS).map(|_| dummy_output(100)).collect();
    let result = sign_transaction(
        [0u8; 32],
        &[dummy_spend_input(100 * (MAX_OUTPUTS as u64 + 1))],
        &outputs,
        AtomicUnits::ZERO,
        &dummy_tree(),
    );
    assert!(matches!(result, Err(TxBuilderError::TooManyOutputs(_))));
}

#[test]
fn test_zero_input_amount() {
    let result = sign_transaction(
        [0u8; 32],
        &[dummy_spend_input(0)],
        &[dummy_output(100)],
        AtomicUnits::ZERO,
        &dummy_tree(),
    );
    assert!(matches!(
        result,
        Err(TxBuilderError::ZeroInputAmount { index: 0 })
    ));
}

#[test]
fn test_zero_output_amount() {
    let result = sign_transaction(
        [0u8; 32],
        &[dummy_spend_input(100)],
        &[dummy_output(0)],
        AtomicUnits::ZERO,
        &dummy_tree(),
    );
    assert!(matches!(
        result,
        Err(TxBuilderError::ZeroOutputAmount { index: 0 })
    ));
}

#[test]
fn test_input_amount_overflow() {
    let inputs = vec![dummy_spend_input(u64::MAX), dummy_spend_input(1)];
    let result = sign_transaction(
        [0u8; 32],
        &inputs,
        &[dummy_output(100)],
        AtomicUnits::ZERO,
        &dummy_tree(),
    );
    assert!(matches!(result, Err(TxBuilderError::InputAmountOverflow)));
}

#[test]
fn test_output_amount_overflow() {
    let outputs = vec![dummy_output(u64::MAX), dummy_output(1)];
    let result = sign_transaction(
        [0u8; 32],
        &[dummy_spend_input(u64::MAX)],
        &outputs,
        AtomicUnits::ZERO,
        &dummy_tree(),
    );
    assert!(matches!(result, Err(TxBuilderError::OutputAmountOverflow)));
}

#[test]
fn test_output_plus_fee_overflow() {
    let result = sign_transaction(
        [0u8; 32],
        &[dummy_spend_input(u64::MAX)],
        &[dummy_output(u64::MAX)],
        AtomicUnits::from_raw(1),
        &dummy_tree(),
    );
    assert!(matches!(result, Err(TxBuilderError::OutputAmountOverflow)));
}

#[test]
fn test_insufficient_funds() {
    let result = sign_transaction(
        [0u8; 32],
        &[dummy_spend_input(50)],
        &[dummy_output(100)],
        AtomicUnits::ZERO,
        &dummy_tree(),
    );
    assert!(matches!(
        result,
        Err(TxBuilderError::InsufficientFunds { .. })
    ));
}

#[test]
fn test_insufficient_funds_with_fee() {
    let result = sign_transaction(
        [0u8; 32],
        &[dummy_spend_input(100)],
        &[dummy_output(100)],
        AtomicUnits::from_raw(1),
        &dummy_tree(),
    );
    assert!(matches!(
        result,
        Err(TxBuilderError::InsufficientFunds { .. })
    ));
}

#[test]
fn test_empty_leaf_chunk() {
    let mut input = dummy_spend_input(100);
    input.leaf_chunk.clear();
    let result = sign_transaction(
        [0u8; 32],
        &[input],
        &[dummy_output(100)],
        AtomicUnits::ZERO,
        &dummy_tree(),
    );
    assert!(matches!(
        result,
        Err(TxBuilderError::EmptyLeafChunk { index: 0 })
    ));
}

#[test]
fn test_leaf_chunk_too_large() {
    let mut input = dummy_spend_input(100);
    let width = shekyl_fcmp::SELENE_CHUNK_WIDTH;
    input.leaf_chunk = vec![dummy_leaf_entry(); width + 1];
    let result = sign_transaction(
        [0u8; 32],
        &[input],
        &[dummy_output(100)],
        AtomicUnits::ZERO,
        &dummy_tree(),
    );
    assert!(matches!(
        result,
        Err(TxBuilderError::LeafChunkTooLarge { index: 0, .. })
    ));
}

#[test]
fn test_zero_tree_depth() {
    let mut tree = dummy_tree();
    tree.tree_depth = 0;
    let result = sign_transaction(
        [0u8; 32],
        &[dummy_spend_input(100)],
        &[dummy_output(100)],
        AtomicUnits::ZERO,
        &tree,
    );
    assert!(matches!(result, Err(TxBuilderError::ZeroTreeDepth)));
}

#[test]
fn test_branch_layer_mismatch() {
    let mut input = dummy_spend_input(100);
    // c1=2, c2=0 -> c1+c2+1=3, but tree_depth=2 -> mismatch
    input.c1_layers = vec![vec![[10u8; 32]], vec![[11u8; 32]]];
    input.c2_layers = vec![];
    let result = sign_transaction(
        [0u8; 32],
        &[input],
        &[dummy_output(100)],
        AtomicUnits::ZERO,
        &dummy_tree(),
    );
    assert!(matches!(
        result,
        Err(TxBuilderError::BranchLayerMismatch { index: 0, .. })
    ));
}

#[test]
fn test_invalid_combined_ss_length() {
    let mut input = dummy_spend_input(100);
    input.combined_ss = vec![0u8; 10]; // wrong length
    let result = sign_transaction(
        [0u8; 32],
        &[input],
        &[dummy_output(100)],
        AtomicUnits::ZERO,
        &dummy_tree(),
    );
    assert!(matches!(
        result,
        Err(TxBuilderError::InvalidCombinedSsLength { index: 0, .. })
    ));
}

#[test]
fn test_sign_pqc_length_mismatch() {
    let result = sign_pqc_auths(&[[0u8; 32]; 2], &[dummy_spend_input(100)]);
    assert!(matches!(
        result,
        Err(TxBuilderError::PqcSignError { index: 0, .. })
    ));
}

// ── Parametric depth tests ────────────────────────────────────────────
//
// The c1/c2 split is derived from the FCMP++ tower spec, not observed
// behavior. The leaf chunk is a C1 (Selene) node at layer 0; the branch
// directly above it (index 0, tree layer 1) is C2 (Helios), then alternating.
// So C2 (Helios) gets the even branch indices and C1 (Selene) the odd ones:
// c2 = ceil(B/2), c1 = floor(B/2). This matches the prover's
// "curve_2_layers is populated before curve_1_layers" and
// `shekyl_curve_tree::assemble_path`.

/// Build a `SpendInput` with the spec-correct c1/c2 split for a given depth.
fn dummy_spend_input_at_depth(depth: u8) -> SpendInput {
    let branch_count = depth.saturating_sub(1) as usize;
    // Branch index 0 (tree layer 1) is C2 (Helios); the even-indexed branches
    // are C2 and the odd-indexed are C1.
    let c1_count = branch_count / 2;
    let c2_count = branch_count.div_ceil(2);
    SpendInput {
        output_key: [1u8; 32],
        commitment: [3u8; 32],
        amount: AtomicUnits::from_raw(100),
        spend_key_x: [5u8; 32],
        spend_key_y: [6u8; 32],
        commitment_mask: [7u8; 32],
        h_pqc: [4u8; 32],
        combined_ss: vec![0u8; 64],
        output_index: 0,
        leaf_chunk: vec![dummy_leaf_entry()],
        c1_layers: vec![vec![[11u8; 32]]; c1_count],
        c2_layers: vec![vec![[12u8; 32]]; c2_count],
    }
}

fn dummy_tree_at_depth(depth: u8) -> TreeContext {
    TreeContext {
        reference_block: [30u8; 32],
        tree_root: [31u8; 32],
        tree_depth: depth,
    }
}

#[test]
fn validate_accepts_all_legal_depths() {
    for depth in 1..=shekyl_fcmp::MAX_TREE_DEPTH {
        let input = dummy_spend_input_at_depth(depth);
        let tree = dummy_tree_at_depth(depth);
        let result = validate_inputs(
            &[input],
            &[dummy_output(100)],
            AtomicUnits::ZERO,
            &[],
            &[],
            &tree,
        );
        assert!(
            result.is_ok(),
            "depth {} should pass validation (c1={}, c2={}), got: {:?}",
            depth,
            depth.saturating_sub(1) as usize / 2,
            (depth.saturating_sub(1) as usize).div_ceil(2),
            result,
        );
    }
}

#[test]
fn validate_rejects_above_max_depth() {
    let bad_depth = shekyl_fcmp::MAX_TREE_DEPTH + 1;
    let input = dummy_spend_input_at_depth(bad_depth);
    let tree = dummy_tree_at_depth(bad_depth);
    let result = validate_inputs(
        &[input],
        &[dummy_output(100)],
        AtomicUnits::ZERO,
        &[],
        &[],
        &tree,
    );
    assert!(
        matches!(result, Err(TxBuilderError::TreeDepthTooLarge(d)) if d == bad_depth),
        "depth {} should be rejected as exceeding MAX_TREE_DEPTH ({}), got: {:?}",
        bad_depth,
        shekyl_fcmp::MAX_TREE_DEPTH,
        result,
    );
}

#[test]
fn validate_depth_1_correct_branch_split() {
    let input = dummy_spend_input_at_depth(1);
    assert_eq!(input.c1_layers.len(), 0, "depth=1: c1 should be 0");
    assert_eq!(input.c2_layers.len(), 0, "depth=1: c2 should be 0");
}

#[test]
fn validate_depth_2_correct_branch_split() {
    let input = dummy_spend_input_at_depth(2);
    assert_eq!(
        input.c1_layers.len(),
        0,
        "depth=2: c1 should be 0 (the only branch, layer 1, is C2/Helios)"
    );
    assert_eq!(input.c2_layers.len(), 1, "depth=2: c2 should be 1");
}

#[test]
fn validate_depth_3_correct_branch_split() {
    let input = dummy_spend_input_at_depth(3);
    assert_eq!(input.c1_layers.len(), 1, "depth=3: c1 should be 1");
    assert_eq!(input.c2_layers.len(), 1, "depth=3: c2 should be 1");
}

#[test]
fn validate_rejects_wrong_branch_count_for_depth() {
    let mut input = dummy_spend_input_at_depth(3);
    input.c1_layers.push(vec![[13u8; 32]]);
    let tree = dummy_tree_at_depth(3);
    let result = validate_inputs(
        &[input],
        &[dummy_output(100)],
        AtomicUnits::ZERO,
        &[],
        &[],
        &tree,
    );
    assert!(
        matches!(result, Err(TxBuilderError::BranchLayerMismatch { .. })),
        "c1+c2+1 != depth should trigger BranchLayerMismatch, got: {result:?}",
    );
}

#[test]
fn validate_rejects_swapped_c1_c2_alternation() {
    // depth=3 expects c1=1, c2=1. Swap them: c1=1, c2=1 is actually valid
    // for depth=3 since both equal 1. Use depth=4 instead: expects c1=1, c2=2.
    // Provide c1=2, c2=1 (swapped) -- correct total but wrong alternation.
    let mut input = dummy_spend_input_at_depth(4);
    let saved_c1 = input.c1_layers.clone();
    let saved_c2 = input.c2_layers.clone();
    input.c1_layers = vec![vec![[11u8; 32]]; saved_c2.len()]; // was 1, now 2 (wrong)
    input.c2_layers = vec![vec![[12u8; 32]]; saved_c1.len()]; // was 2, now 1 (wrong)
    let tree = dummy_tree_at_depth(4);
    let result = validate_inputs(
        &[input],
        &[dummy_output(100)],
        AtomicUnits::ZERO,
        &[],
        &[],
        &tree,
    );
    assert!(
        matches!(result, Err(TxBuilderError::BranchLayerMismatch { .. })),
        "swapped c1/c2 alternation should trigger BranchLayerMismatch, got: {result:?}",
    );
}

// ── Typed-side cleartext balance terms (ARCHIVAL_BOND_CONSTRUCTION.md §7.2) ──

#[test]
fn extra_output_term_raises_required_total() {
    use shekyl_ct_balance::{InputTerm, OutputTerm};
    // input=100, output=100, fee=0 is exactly sufficient with no extra terms.
    let input = dummy_spend_input_at_depth(1);
    let tree = dummy_tree_at_depth(1);
    assert!(validate_inputs(
        std::slice::from_ref(&input),
        &[dummy_output(100)],
        AtomicUnits::ZERO,
        &[],
        &[],
        &tree,
    )
    .is_ok());

    // A 1-unit OutputTerm (e.g. a bond_credit) makes the inputs insufficient...
    let one = AtomicUnits::from_raw(1);
    let result = validate_inputs(
        std::slice::from_ref(&input),
        &[dummy_output(100)],
        AtomicUnits::ZERO,
        &[],
        &[OutputTerm::new(one)],
        &tree,
    );
    assert!(
        matches!(
            result,
            Err(TxBuilderError::InsufficientFunds {
                available_total: 100,
                required_total: 101
            })
        ),
        "an extra OutputTerm must raise the required total, got: {result:?}",
    );

    // ...and a matching InputTerm on the other side closes the gap again.
    assert!(validate_inputs(
        std::slice::from_ref(&input),
        &[dummy_output(100)],
        AtomicUnits::ZERO,
        &[InputTerm::new(one)],
        &[OutputTerm::new(one)],
        &tree,
    )
    .is_ok());
}
