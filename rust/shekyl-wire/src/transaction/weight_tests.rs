// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The weight model's proof-length term against measured proofs.

use shekyl_fcmp_proofs::FcmpPlusPlus;

use super::weight::{
    fcmp_proof_len, heaviest_legal_weight, is_legal_shape, max_inputs_at, pqc_auth_weight,
    spend_weight, FCMP_PROOF_LEN_MAX, TREE_DEPTH_FLOOR,
};
use super::{MAX_FCMP_INPUTS, MAX_OUTPUTS, MIN_NON_COINBASE_OUTPUTS, TX_WEIGHT_LIMIT};
use shekyl_curve_generators::{MAX_TREE_DEPTH, MIN_SPEND_LAYERS};

/// Measured FCMP++ proof sizes in bytes, indexed `[n_in][tree_depth]` over
/// `n_in ∈ 0..=8` and `tree_depth ∈ 0..=24` (row and column 0 are unused).
///
/// Emitted by `kat_emit_fcmp_proof_size_table` (in engine-core, where the
/// synthetic-tree measurement machinery lives) from the depth-consistent
/// single-path synthetic trees (PF7), and re-measured 2026-09-14 with `PL-D3`
/// (`FCMP_SPEND_LINKABILITY.md` §6.2). The series is **non-monotonic** in depth,
/// because the inner-product argument rounds. These are real proofs' lengths,
/// so they are the closed form's test vectors, and the closed form is the
/// model's source (`ICD-R1`).
const MEASURED_PROOF_LEN: [[usize; 25]; 9] = [
    [0; 25],
    [
        0, 3872, 4512, 4896, 5536, 5920, 6560, 5984, 6624, 6880, 6304, 6560, 6944, 7200, 7584,
        7840, 8224, 7648, 6944, 7200, 7456, 7584, 7840, 8096, 8352,
    ],
    [
        0, 5760, 7040, 6208, 7488, 8000, 7808, 7360, 8128, 8512, 8064, 8448, 8960, 9344, 9856,
        10240, 10752, 10304, 9728, 10112, 10496, 10752, 11136, 11520, 11904,
    ],
    [
        0, 5664, 7584, 8352, 8800, 8224, 8288, 8800, 9568, 10208, 10976, 10528, 10208, 10720,
        11360, 11872, 12384, 12896, 13536, 13920, 14432, 14944, 14624, 14432, 14816,
    ],
    [
        0, 6784, 9344, 8768, 9344, 10112, 10176, 9984, 11008, 11648, 11456, 12096, 12864, 13504,
        14272, 14912, 15680, 15488, 15168, 15808, 16448, 16960, 17600, 18240, 18880,
    ],
    [
        0, 6304, 8288, 9312, 10016, 9824, 11104, 11872, 11936, 12704, 13728, 14624, 15520, 15456,
        15392, 16032, 16800, 17568, 18464, 19232, 20000, 20640, 21408, 22176, 22944,
    ],
    [
        0, 7168, 9536, 10688, 11520, 11328, 11776, 12672, 13824, 14848, 16000, 15936, 16000, 16896,
        17920, 18816, 19712, 20608, 21632, 22400, 23296, 24192, 24256, 24448, 25216,
    ],
    [
        0, 8032, 10784, 10720, 11680, 12832, 13408, 14432, 15712, 15904, 16224, 17248, 18400,
        19424, 20576, 21472, 22496, 23520, 24672, 25696, 25760, 25952, 26976, 28000, 29024,
    ],
    [
        0, 8768, 11904, 11840, 12928, 14208, 14784, 15104, 16640, 17792, 18112, 19264, 20544,
        21696, 22976, 24128, 25408, 25728, 25920, 27072, 28224, 29248, 30400, 31552, 32704,
    ],
];

/// The closed form equals every measured proof, including at depths and input
/// counts the protocol does not admit: the formula is what is being tested, so
/// the vectors do not narrow with the protocol's limits.
#[test]
fn the_closed_form_is_every_measured_proof() {
    let mut cells = 0;
    for (n_in, row) in MEASURED_PROOF_LEN.iter().enumerate().skip(1) {
        for (depth, &measured) in row.iter().enumerate().skip(1) {
            assert_eq!(
                FcmpPlusPlus::proof_size(n_in, depth),
                measured,
                "{n_in} inputs at depth {depth}"
            );
            cells += 1;
        }
    }
    assert_eq!(cells, 192, "every measured cell was compared");
}

/// The model's term answers the closed form on the whole legal domain.
#[test]
fn the_model_reads_the_closed_form_on_the_legal_domain() {
    for n_in in 1..=MAX_FCMP_INPUTS {
        for depth in 1..=MAX_TREE_DEPTH {
            assert_eq!(
                fcmp_proof_len(n_in, depth),
                FcmpPlusPlus::proof_size(n_in, usize::from(depth))
            );
            assert!(fcmp_proof_len(n_in, depth) <= FCMP_PROOF_LEN_MAX);
        }
    }
}

/// A depth no transaction can carry answers the conservative maximum, never a
/// short length that would under-pay, and never a panic in the formula.
#[test]
fn an_illegal_depth_answers_the_longest_proof() {
    for depth in [0, MAX_TREE_DEPTH + 1, u8::MAX] {
        assert_eq!(fcmp_proof_len(1, depth), FCMP_PROOF_LEN_MAX);
    }
    assert_eq!(fcmp_proof_len(0, 2), FCMP_PROOF_LEN_MAX);
}

/// The lightest legal spend's weight: a solo signer and a one-byte fee.
fn lightest(n_in: usize, n_out: usize, depth: u8) -> usize {
    spend_weight(n_in, n_out, depth, 0, pqc_auth_weight(), 0)
}

/// The derived values at today's weight limit (`ICD-R1`, `ICD-R9`), written out
/// so a change to the limit is a reviewed change here too.
#[test]
fn the_derived_cap_and_depth_at_todays_weight_limit() {
    assert_eq!(TX_WEIGHT_LIMIT, 148_614);
    assert_eq!(MAX_FCMP_INPUTS, 22);
    assert_eq!(TREE_DEPTH_FLOOR, 12);
    assert_eq!(MAX_TREE_DEPTH, 14);
    let per_depth: Vec<usize> = (MIN_SPEND_LAYERS..=MAX_TREE_DEPTH)
        .map(|d| max_inputs_at(MIN_NON_COINBASE_OUTPUTS, d))
        .collect();
    assert_eq!(
        per_depth,
        [22, 22, 22, 21, 21, 20, 20, 20, 19, 19, 18, 18, 18]
    );
}

/// The count [`max_inputs_at`] answers is the whole boundary: it fits, and no
/// larger count fits, however the proof's padding steps. The stop-at-first-miss
/// search is only right if that holds.
#[test]
fn the_weight_limit_refuses_every_count_past_the_answer() {
    for depth in MIN_SPEND_LAYERS..=MAX_TREE_DEPTH {
        for n_out in MIN_NON_COINBASE_OUTPUTS..=MAX_OUTPUTS {
            let most = max_inputs_at(n_out, depth);
            assert!(most <= MAX_FCMP_INPUTS, "{n_out} outputs at depth {depth}");
            if most > 0 {
                assert!(lightest(most, n_out, depth) <= TX_WEIGHT_LIMIT);
            }
            for n_in in most + 1..=4 * MAX_FCMP_INPUTS {
                let weight = spend_weight(n_in, n_out, depth, 0, pqc_auth_weight(), 0);
                // Past the cap `fcmp_proof_len` answers its conservative
                // maximum, so read the closed form for the honest weight.
                let honest = weight - fcmp_proof_len(n_in, depth)
                    + FcmpPlusPlus::proof_size(n_in, usize::from(depth));
                assert!(
                    honest > TX_WEIGHT_LIMIT,
                    "{n_in} inputs, {n_out} outputs at depth {depth} fit"
                );
            }
        }
    }
}

/// The shape space is consensus's: one output, too many outputs, an empty tree
/// and a depth past the maximum are not shapes.
#[test]
fn the_legal_shapes_are_the_consensus_shapes() {
    assert!(is_legal_shape(MAX_FCMP_INPUTS, MIN_NON_COINBASE_OUTPUTS, 2));
    assert!(!is_legal_shape(
        MAX_FCMP_INPUTS + 1,
        MIN_NON_COINBASE_OUTPUTS,
        2
    ));
    assert!(!is_legal_shape(0, MIN_NON_COINBASE_OUTPUTS, 2));
    assert!(!is_legal_shape(1, MIN_NON_COINBASE_OUTPUTS - 1, 2));
    assert!(!is_legal_shape(1, MAX_OUTPUTS + 1, 2));
    assert!(!is_legal_shape(
        1,
        MIN_NON_COINBASE_OUTPUTS,
        MIN_SPEND_LAYERS - 1
    ));
    assert!(!is_legal_shape(
        1,
        MIN_NON_COINBASE_OUTPUTS,
        MAX_TREE_DEPTH + 1
    ));
    assert!(
        !is_legal_shape(MAX_FCMP_INPUTS, MIN_NON_COINBASE_OUTPUTS, MAX_TREE_DEPTH),
        "the weight limit binds below the cap at the deepest tree"
    );
}

/// The heaviest legal two-output spend: 22 inputs at depth 4, with room for the
/// widest fee varint.
#[test]
fn the_heaviest_legal_spend() {
    let heaviest = heaviest_legal_weight(MIN_NON_COINBASE_OUTPUTS);
    assert_eq!(heaviest, 148_521);
    assert_eq!(
        heaviest,
        spend_weight(22, 2, 4, u64::MAX, pqc_auth_weight(), 0)
    );
    assert!(heaviest <= TX_WEIGHT_LIMIT);
    assert_eq!(heaviest_legal_weight(1), 0, "no transaction has one output");
}
