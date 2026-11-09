// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The floor-device operands of one [`super::SPEC_VERIFY_COST`] cell.
//!
//! Each cell is the pool door's verification sequence at one shape (§72.2,
//! BA-Q9): the masks-and-proof term, `n_in` hybrid signatures, and the lone
//! range proof. [`DoorOperands::millis`] is that sum. The signature and the
//! range proof are one pair per input count ([`DoorInputCount`]); the masks
//! term is the cell's own.

/// One hybrid Ed25519 + ML-DSA-65 verification on the floor device, at the
/// 1-input 2-output shape: `pqc_per_input` in
/// `docs/benchmarks/gap7_block_verify_pi4_rust_20260905T181144Z.txt`
/// (criterion's point estimate, 971.86 µs; Rust verifier, rev `8af70a60a6`).
pub(super) const PI4_HYBRID_SIG_1IN_MS: f64 = 0.971_86;

/// The same term at the 8-input 2-output shape, from the same capture
/// (972.28 µs per verification).
pub(super) const PI4_HYBRID_SIG_8IN_MS: f64 = 0.972_28;

/// The range proof as a batch of one (`verify_batch`, the shipped verifier
/// the door runs at `TxSlot::Lone`) over 2 outputs, at the 1-input shape:
/// `bp_lone` in `docs/benchmarks/gap7_block_verify_pi4_rust_20261108T232442Z.txt`
/// (criterion's point estimate, 18.838 ms; the verifier that folds `Â` into
/// the batch, rev `78de6a14e2`). The eager verifier before the fold read
/// 34.80 ms in the same session and 35.017 ms in the 2026-09-05 capture.
pub(super) const PI4_RANGE_PROOF_LONE_1IN_2OUT_MS: f64 = 18.838;

/// The same term at the 8-input 2-output shape, from the same capture
/// (18.882 ms; the range proof reads only the output commitments).
pub(super) const PI4_RANGE_PROOF_LONE_8IN_2OUT_MS: f64 = 18.882;

// §85.3's membership proof with the output masks, on the Pi 4. Pre-`PL-D3`;
// BA-T10 re-measures the door's sequence, including these. Depth 2 is
// genesis; depth 7 is the synthesized projection.
pub(super) const PI4_MASKS_AND_PROOF_1IN_D2_MS: f64 = 124.5;
pub(super) const PI4_MASKS_AND_PROOF_1IN_D7_MS: f64 = 143.3;
pub(super) const PI4_MASKS_AND_PROOF_8IN_D2_MS: f64 = 399.2;
pub(super) const PI4_MASKS_AND_PROOF_8IN_D7_MS: f64 = 791.9;

/// The input count a signature term and a lone range-proof term were measured
/// at. Those two operands are one pair; the masks term is chosen per cell.
#[derive(Clone, Copy)]
pub(super) enum DoorInputCount {
    /// [`PI4_HYBRID_SIG_1IN_MS`] and [`PI4_RANGE_PROOF_LONE_1IN_2OUT_MS`].
    One,
    /// [`PI4_HYBRID_SIG_8IN_MS`] and [`PI4_RANGE_PROOF_LONE_8IN_2OUT_MS`].
    Eight,
}

/// The floor-device operands of one cell.
///
/// [`Self::millis`] is the sum. Every operand is measured on the floor
/// device; the sum is composed, not timed as one call. The signature and
/// the range proof read no tree, so a depth-7 cell uses the terms measured
/// at depth 2. What the sum leaves out is µs-class: `tx_form`'s parse
/// (4.9 µs at 1 input, 19.9 µs at 8, the 2026-09-05 capture) and the
/// cleartext balance (CEN-H18).
pub(super) struct DoorOperands {
    masks_and_proof_ms: f64,
    n_in: usize,
    signature_per_input_ms: f64,
    range_proof_lone_ms: f64,
}

impl DoorOperands {
    /// The door's operands at `masks_and_proof_ms`, with the signature and
    /// range-proof pair [`DoorInputCount`] names.
    pub(super) const fn at(masks_and_proof_ms: f64, inputs: DoorInputCount) -> Self {
        let (n_in, signature_per_input_ms, range_proof_lone_ms) = match inputs {
            DoorInputCount::One => (1, PI4_HYBRID_SIG_1IN_MS, PI4_RANGE_PROOF_LONE_1IN_2OUT_MS),
            DoorInputCount::Eight => (8, PI4_HYBRID_SIG_8IN_MS, PI4_RANGE_PROOF_LONE_8IN_2OUT_MS),
        };
        Self {
            masks_and_proof_ms,
            n_in,
            signature_per_input_ms,
            range_proof_lone_ms,
        }
    }

    /// `masks_and_proof + n_in × signature + range_proof`.
    ///
    /// The cast is exact for `n_in` within the table's input domain.
    /// `f64::from` is not `const`.
    #[allow(clippy::cast_precision_loss)]
    pub(super) const fn millis(self) -> f64 {
        self.masks_and_proof_ms
            + self.n_in as f64 * self.signature_per_input_ms
            + self.range_proof_lone_ms
    }
}
