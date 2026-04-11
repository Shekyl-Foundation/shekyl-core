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
        c1_layers: vec![vec![[10u8; 32]]],
        c2_layers: vec![vec![[11u8; 32]]],
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
    input.c1_layers = vec![vec![[10u8; 32]]];
    input.c2_layers = vec![]; // depth = 2 but only 1 layer total
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

// ECDH encoding tests removed — ecdh module deleted (Keccak Category 1 cleanup).
