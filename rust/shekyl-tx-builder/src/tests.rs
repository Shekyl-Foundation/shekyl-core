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
use crate::validate::validate_inputs;
use crate::types::*;
use crate::{MAX_INPUTS, MAX_OUTPUTS};

fn dummy_leaf_entry() -> LeafEntry {
    LeafEntry {
        output_key: [1u8; 32],
        key_image_gen: [2u8; 32],
        commitment: [3u8; 32],
        h_pqc: [4u8; 32],
    }
}

fn dummy_spend_input(amount: u64) -> SpendInput {
    // depth=2 -> 1 branch at even index 0 -> C1 (Selene), 0 C2 (Helios)
    SpendInput {
        output_key: [1u8; 32],
        commitment: [3u8; 32],
        amount,
        spend_key_x: [5u8; 32],
        spend_key_y: [6u8; 32],
        commitment_mask: [7u8; 32],
        h_pqc: [4u8; 32],
        combined_ss: vec![0u8; 64],
        output_index: 0,
        leaf_chunk: vec![dummy_leaf_entry()],
        c1_layers: vec![vec![[11u8; 32]]],
        c2_layers: vec![],
    }
}

fn dummy_output(amount: u64) -> OutputInfo {
    OutputInfo {
        dest_key: [20u8; 32],
        amount,
        commitment_mask: [21u8; 32],
        enc_amount: [0u8; 9],
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
    let result = sign_transaction([0u8; 32], &[], &[dummy_output(100)], 0, &dummy_tree());
    assert!(matches!(result, Err(TxBuilderError::NoInputs)));
}

#[test]
fn test_too_many_inputs() {
    let inputs: Vec<SpendInput> = (0..MAX_INPUTS + 1).map(|_| dummy_spend_input(100)).collect();
    let result = sign_transaction(
        [0u8; 32],
        &inputs,
        &[dummy_output(100)],
        0,
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
        0,
        &dummy_tree(),
    );
    assert!(matches!(result, Err(TxBuilderError::NoOutputs)));
}

#[test]
fn test_too_many_outputs() {
    let outputs: Vec<OutputInfo> = (0..MAX_OUTPUTS + 1).map(|_| dummy_output(100)).collect();
    let result = sign_transaction(
        [0u8; 32],
        &[dummy_spend_input(100 * (MAX_OUTPUTS as u64 + 1))],
        &outputs,
        0,
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
        0,
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
        0,
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
        0,
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
        0,
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
        1,
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
        0,
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
        1,
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
        0,
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
        0,
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
        0,
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
        0,
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
        0,
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
// behavior. The upstream Fcmp::verify iterates layers 0..depth-2 with
// even indices as C1 (Selene) and odd as C2 (Helios).

/// Build a `SpendInput` with the spec-correct c1/c2 split for a given depth.
fn dummy_spend_input_at_depth(depth: u8) -> SpendInput {
    let branch_count = depth.saturating_sub(1) as usize;
    // Even-indexed branches are C1, odd-indexed are C2
    let c1_count = (branch_count + 1) / 2;
    let c2_count = branch_count / 2;
    SpendInput {
        output_key: [1u8; 32],
        commitment: [3u8; 32],
        amount: 100,
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
        let result = validate_inputs(&[input], &[dummy_output(100)], 0, &tree);
        assert!(
            result.is_ok(),
            "depth {} should pass validation (c1={}, c2={}), got: {:?}",
            depth,
            (depth.saturating_sub(1) as usize + 1) / 2,
            depth.saturating_sub(1) as usize / 2,
            result,
        );
    }
}

#[test]
fn validate_rejects_above_max_depth() {
    let bad_depth = shekyl_fcmp::MAX_TREE_DEPTH + 1;
    let input = dummy_spend_input_at_depth(bad_depth);
    let tree = dummy_tree_at_depth(bad_depth);
    let result = validate_inputs(&[input], &[dummy_output(100)], 0, &tree);
    assert!(
        matches!(result, Err(TxBuilderError::TreeDepthTooLarge(d)) if d == bad_depth),
        "depth {} should be rejected as exceeding MAX_TREE_DEPTH ({}), got: {:?}",
        bad_depth, shekyl_fcmp::MAX_TREE_DEPTH, result,
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
    assert_eq!(input.c1_layers.len(), 1, "depth=2: c1 should be 1 (layer 0 is C1)");
    assert_eq!(input.c2_layers.len(), 0, "depth=2: c2 should be 0");
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
    let result = validate_inputs(&[input], &[dummy_output(100)], 0, &tree);
    assert!(
        matches!(result, Err(TxBuilderError::BranchLayerMismatch { .. })),
        "c1+c2+1 != depth should trigger BranchLayerMismatch, got: {:?}", result,
    );
}

#[test]
fn validate_rejects_swapped_c1_c2_alternation() {
    // depth=3 expects c1=1, c2=1. Swap them: c1=1, c2=1 is actually valid
    // for depth=3 since both equal 1. Use depth=4 instead: expects c1=2, c2=1.
    // Provide c1=1, c2=2 (swapped) -- correct total but wrong alternation.
    let mut input = dummy_spend_input_at_depth(4);
    let saved_c1 = input.c1_layers.clone();
    let saved_c2 = input.c2_layers.clone();
    input.c1_layers = vec![vec![[11u8; 32]]; saved_c2.len()]; // was 1, should be 2
    input.c2_layers = vec![vec![[12u8; 32]]; saved_c1.len()]; // was 2, should be 1
    let tree = dummy_tree_at_depth(4);
    let result = validate_inputs(&[input], &[dummy_output(100)], 0, &tree);
    assert!(
        matches!(result, Err(TxBuilderError::BranchLayerMismatch { .. })),
        "swapped c1/c2 alternation should trigger BranchLayerMismatch, got: {:?}", result,
    );
}
