// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The floor-device operands of every [`super::SPEC_VERIFY_COST`] cell.
//!
//! Each cell is the pool door's verification sequence at one shape (§72.2,
//! BA-Q9): the masks-and-proof term, `n_in` hybrid signatures, and the lone
//! range proof. [`DoorOperands::millis`] is that sum.
//!
//! Every operand here comes from one floor session on one binary
//! (`CEN_I4_INPUT_CAP_DERIVATION.md` `ICD-R5`): shekyl-core `4354a1cf1d`,
//! captured in
//! `docs/benchmarks/relay_admission_verify_pi4_rust_20261127T144430Z.txt`.
//! Each figure is criterion's point estimate there, in milliseconds.
//! `tests/spec_decision_matrix.rs` reads that capture and checks every
//! operand against it, so an operand that drifts from its measurement is a
//! red test, not a review item.

/// One hybrid Ed25519 + ML-DSA-65 verification on the floor device, at the
/// 1-input 2-output shape: `pqc_per_input` in the capture.
pub(super) const PI4_HYBRID_SIG_1IN_MS: f64 = 1.0121;

/// The same term at the 22-input 2-output shape, the consensus maximum.
pub(super) const PI4_HYBRID_SIG_22IN_MS: f64 = 1.0145;

/// The signature term every cell pays per input: the larger of the two
/// readings. The term verifies one signature, so it does not move with the
/// input count; the two readings differ by 0.24 %.
pub(super) const PI4_HYBRID_SIG_MS: f64 = larger(PI4_HYBRID_SIG_1IN_MS, PI4_HYBRID_SIG_22IN_MS);

/// The range proof as a batch of one (`verify_batch` at `TxSlot::Lone`, what
/// the pool door runs) over 2 outputs, at the 1-input shape: `bp_lone` in the
/// capture, on the constant-time commitment opening.
pub(super) const PI4_RANGE_PROOF_LONE_1IN_2OUT_MS: f64 = 18.911;

/// The same term at the 22-input 2-output shape.
pub(super) const PI4_RANGE_PROOF_LONE_22IN_2OUT_MS: f64 = 18.919;

/// The range-proof term every cell pays: the larger of the two readings. The
/// range proof reads only the output commitments, so it does not move with
/// the input count.
pub(super) const PI4_RANGE_PROOF_LONE_2OUT_MS: f64 = larger(
    PI4_RANGE_PROOF_LONE_1IN_2OUT_MS,
    PI4_RANGE_PROOF_LONE_22IN_2OUT_MS,
);

/// `f64::max` is not `const`.
const fn larger(a: f64, b: f64) -> f64 {
    if a > b {
        a
    } else {
        b
    }
}

/// The membership proof with the output masks (`relay_admission_verify`),
/// at depth 2 (the genesis tree), `n_in = 1..=22`, spread layout: the
/// production arrangement for unrelated spends. The shared-layout control
/// in the same capture reads within 0.3 % of each cell.
pub(super) const PI4_MASKS_AND_PROOF_D2_MS: [f64; 22] = [
    128.06, 155.05, 210.92, 235.1, 348.5, 370.87, 394.04, 415.51, 480.59, 644.14, 666.64, 688.27,
    709.04, 732.96, 754.28, 777.07, 890.37, 911.71, 1_221.2, 1_242.9, 1_263.4, 1_291.1,
];

/// The same term at depth 3, a synthesized tree (§81.2), `n_in = 1..=22`.
pub(super) const PI4_MASKS_AND_PROOF_D3_MS: [f64; 22] = [
    131.63, 192.62, 219.94, 314.5, 363.83, 389.03, 558.04, 581.66, 650.26, 674.38, 697.8, 725.74,
    1_036.4, 1_061.1, 1_087.7, 1_112.3, 1_228.2, 1_253.2, 1_280.2, 1_304.8, 1_330.3, 1_355.3,
];

/// The same term at depth 4, a synthesized tree, `n_in = 1..=22`.
pub(super) const PI4_MASKS_AND_PROOF_D4_MS: [f64; 22] = [
    136.52, 201.92, 254.8, 350.84, 422.17, 448.52, 621.75, 647.74, 768.19, 795.94, 821.46, 850.56,
    1_171.0, 1_202.7, 1_231.9, 1_257.7, 1_480.2, 1_508.5, 1_544.3, 1_567.2, 1_599.5, 1_631.7,
];

/// The same term at depth 5, a synthesized tree, `n_in = 1..=21`.
pub(super) const PI4_MASKS_AND_PROOF_D5_MS: [f64; 21] = [
    139.81, 207.18, 330.97, 361.32, 580.0, 611.75, 641.18, 670.64, 793.86, 1_117.9, 1_149.8,
    1_179.3, 1_211.9, 1_244.4, 1_277.1, 1_306.9, 1_535.7, 1_572.2, 1_603.8, 2_242.5, 2_277.6,
];

/// The same term at depth 6, a synthesized tree, `n_in = 1..=21`.
pub(super) const PI4_MASKS_AND_PROOF_D6_MS: [f64; 21] = [
    144.03, 237.14, 383.24, 414.61, 594.11, 718.35, 752.0, 783.93, 819.7, 1_149.6, 1_377.8,
    1_413.4, 1_451.5, 1_488.9, 1_527.5, 1_564.5, 1_603.5, 1_641.6, 1_682.4, 2_346.1, 2_385.8,
];

/// The same term at depth 7, a synthesized tree, `n_in = 1..=20`.
///
/// Depth 7 is where the Selene side of the proof crosses a padding step: one
/// input needs 267 rows and pads to 512 where depth 6 fits 256, and eight
/// inputs pad to 4 096 rows where depth 6 fits 2 048 (`Fcmp::ipa_rows`).
/// So the column is not a smooth continuation of depth 6: 180.02 ms against
/// 144.03 at one input, 1 106.4 against 783.93 at eight.
pub(super) const PI4_MASKS_AND_PROOF_D7_MS: [f64; 20] = [
    180.02, 312.12, 389.92, 572.0, 608.65, 735.69, 772.16, 1_106.4, 1_142.0, 1_180.3, 1_412.7,
    1_452.6, 1_492.9, 1_535.0, 1_581.3, 2_237.3, 2_283.7, 2_332.8, 2_378.1, 2_417.2,
];

/// The floor-device operands of one cell.
///
/// [`Self::millis`] is the sum. Every operand is measured on the floor
/// device in the one session; the sum is composed, not timed as one call.
/// The signature and the range proof read no tree, so every depth uses the
/// same two terms. What the sum leaves out is µs-class: `tx_form`'s parse
/// (4.9 µs at 1 input, 19.9 µs at 8, the 2026-09-05 capture) and the
/// cleartext balance (CEN-H18).
pub(super) struct DoorOperands {
    masks_and_proof_ms: f64,
    n_in: usize,
}

impl DoorOperands {
    /// The door's operands for an `n_in`-input spend whose masks-and-proof
    /// term is `masks_and_proof_ms`.
    pub(super) const fn at(masks_and_proof_ms: f64, n_in: usize) -> Self {
        Self {
            masks_and_proof_ms,
            n_in,
        }
    }

    /// `masks_and_proof + n_in × signature + range_proof`.
    ///
    /// The cast is exact for `n_in` within the table's input domain.
    /// `f64::from` is not `const`.
    #[allow(clippy::cast_precision_loss)]
    pub(super) const fn millis(self) -> f64 {
        self.masks_and_proof_ms
            + self.n_in as f64 * PI4_HYBRID_SIG_MS
            + PI4_RANGE_PROOF_LONE_2OUT_MS
    }
}
