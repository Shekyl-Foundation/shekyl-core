// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Structural tx-weight predictor and fee-directive helpers (Phase 2a §3.10).
//!
//! `predict_weight` mirrors `shekyl_wire::Transaction::write` byte-for-byte (and
//! adds the same Bp+ clawback), so it equals the post-build
//! `Transaction::weight()` without constructing a transaction — pinned by the
//! build-path cross-checks and `predict_weight_matches_wire_weight`. The
//! `fcmp_proof_size` term reads the measured 2a-3 KAT table.

use shekyl_crypto_pq::kem::ML_KEM_768_CT_LEN;
use shekyl_io::varint_len;
use shekyl_rpc::{tx_fee, FeeRate};
use shekyl_tx_builder::{MAX_INPUTS, MAX_TREE_DEPTH};
use shekyl_units::AtomicUnits;
use shekyl_wire::transaction::{
    bp_plus_weight_clawback, PQC_HYBRID_SINGLE_KEY_LEN, PQC_HYBRID_SINGLE_SIG_LEN, TX_VERSION,
};

use super::traits::key::FeeDirective;
use super::tx_counts::{InputCount, OutputCount};

// ── Wire-exact component sizes ──────────────────────────────────────────────
// Each constant is one field of `shekyl_wire::Transaction::write`; `predict_weight`
// sums them so it equals `Transaction::weight()` exactly (pinned by the build-path
// cross-checks + `predict_weight_matches_wire_weight`). Sizes that have a canonical
// home are imported, not re-typed: the hybrid PQC pk/sig lengths
// (`PQC_HYBRID_SINGLE_KEY_LEN` / `PQC_HYBRID_SINGLE_SIG_LEN`) come from `shekyl_wire`.

/// Hybrid KEM ciphertext per output in `tx_extra`: the 32-byte x25519 component ‖ the
/// ML-KEM-768 ciphertext (canonical length from `shekyl-crypto-pq`).
const KEM_CIPHERTEXT_LEN: usize = 32 + ML_KEM_768_CT_LEN;

/// `Input::ToKey`: tag + varint(amount=0) + varint(key_offsets=0) + key_image.
const INPUT_TO_KEY_WEIGHT: usize = 1 + 1 + 1 + 32;
/// `Output`: varint(amount=0) + tag + one-time key + view_tag.
const OUTPUT_WEIGHT: usize = 1 + 1 + 32 + 1;
/// `CtBase` per output: enc_amount + enc_label + commitment.
const CT_BASE_PER_OUTPUT_WEIGHT: usize = 9 + 9 + 32;
/// `reference_block` hash in the ct base.
const REFERENCE_BLOCK_LEN: usize = 32;
/// `pseudoOut` commitment per input in the prunable.
const PSEUDO_OUT_LEN: usize = 32;
/// `ExtraField::PublicKey`: tag + Edwards point.
const EXTRA_PUBKEY_FIELD_WEIGHT: usize = 1 + 32;

/// Measured FCMP++ proof sizes in bytes, indexed `[n_in][tree_depth]` over
/// `n_in ∈ 0..=8` and `tree_depth ∈ 0..=24` (row/col 0 are unused sentinels).
///
/// Emitted by `kat_emit_fcmp_proof_size_table` from the depth-consistent
/// single-path synthetic trees (PF7) — the CT-5c calibration the
/// pre-curve-tree-fixture comment deferred. The depth-1 column equals the
/// independently-known depth-1 row (the prior `FCMP_PROOF_DEPTH1` constant),
/// which cross-validates the measurement. The series is **non-monotonic** in
/// depth (the FCMP++ inner-product argument rounds), so this is a lookup table,
/// not a closed-form per-layer increment. `kat_fcmp_proof_size_grid` validates
/// every cell against re-measurement (`#[ignore]`; ~slow); `kat_fcmp_proof_size_depth1_row`
/// guards the depth-1 column in CI.
const FCMP_PROOF_SIZE_KAT: [[usize; 25]; 9] = [
    [0; 25],
    [
        0, 3744, 4384, 4768, 5408, 5792, 6432, 6816, 7456, 6880, 6304, 6560, 6944, 7200, 7584,
        7840, 8224, 7776, 7072, 7200, 7456, 7712, 7968, 8096, 8352,
    ],
    [
        0, 5504, 6784, 6208, 7488, 8000, 7808, 8320, 9088, 8640, 8192, 8576, 9088, 9472, 9984,
        10368, 10880, 10560, 9984, 10240, 10624, 11008, 11392, 11648, 12032,
    ],
    [
        0, 5664, 7584, 8352, 8800, 8352, 8416, 9056, 9824, 10336, 11104, 10912, 10592, 10976,
        11616, 12128, 12640, 13152, 13792, 14304, 14816, 15200, 14880, 15392, 15776,
    ],
    [
        0, 6784, 9344, 9024, 9600, 10368, 10432, 11200, 12224, 12032, 11840, 12480, 13248, 13888,
        14656, 15296, 16064, 16000, 15680, 16192, 16832, 17472, 18112, 18624, 19264,
    ],
    [
        0, 8032, 10016, 9568, 10272, 11296, 12576, 12384, 12448, 13216, 14240, 15008, 15904, 16800,
        16736, 16672, 17440, 18080, 18976, 19744, 20512, 21280, 22048, 22688, 23456,
    ],
    [
        0, 7552, 9920, 11072, 11904, 11840, 12288, 13312, 14464, 15360, 16512, 16704, 16768, 17536,
        18560, 19456, 20352, 21248, 22272, 23168, 24064, 24832, 24896, 25792, 26560,
    ],
    [
        0, 8416, 11168, 11360, 12320, 13472, 14048, 15200, 16480, 16672, 16992, 18016, 19168,
        20192, 21344, 22368, 23392, 24288, 25440, 26464, 26528, 26848, 27872, 28768, 29792,
    ],
    [
        0, 9280, 12416, 12608, 13696, 14976, 15552, 16832, 18368, 18688, 19008, 20160, 21440,
        22592, 23872, 25024, 26304, 26752, 26944, 27968, 29120, 30272, 31424, 32448, 33600,
    ],
];

/// Compile-time guard tying the table's dimensions to the canonical proof-system
/// limits: the rows cover `n_in ∈ 0..=MAX_INPUTS` and the columns
/// `tree_depth ∈ 0..=MAX_TREE_DEPTH` (index 0 unused). If either limit changes,
/// this fails to compile — forcing a table regeneration — rather than silently
/// falling back to `FCMP_PROOF_SIZE_MAX` for the newly-reachable cells (which
/// could under-estimate fees if real proofs there exceed the current max).
const _: () = {
    assert!(FCMP_PROOF_SIZE_KAT.len() == MAX_INPUTS + 1);
    assert!(FCMP_PROOF_SIZE_KAT[0].len() == MAX_TREE_DEPTH as usize + 1);
};

/// Largest cell of [`FCMP_PROOF_SIZE_KAT`]; the conservative fallback for an
/// out-of-range cell that should be unreachable (`validate_inputs` enforces
/// `n_in ∈ 1..=MAX_INPUTS`, `tree_depth ∈ 1..=MAX_TREE_DEPTH`).
///
/// Derived from the table at compile time, not hardcoded, so regenerating the
/// table can never leave the fallback stale — under-estimating fees (a
/// non-conservative drift) or over-estimating them.
const FCMP_PROOF_SIZE_MAX: usize = {
    let mut max = 0;
    let mut i = 0;
    while i < FCMP_PROOF_SIZE_KAT.len() {
        let row = &FCMP_PROOF_SIZE_KAT[i];
        let mut j = 0;
        while j < row.len() {
            if row[j] > max {
                max = row[j];
            }
            j += 1;
        }
        i += 1;
    }
    max
};

fn fcmp_proof_size(n_in: InputCount, tree_depth: u8) -> usize {
    // `n_in` is type-bounded to `1..=MAX_INPUTS`, so the row always hits a measured
    // cell; an out-of-range `tree_depth` falls back to the largest measured size so
    // the fee estimate stays conservative rather than panicking or under-paying.
    FCMP_PROOF_SIZE_KAT
        .get(n_in.get())
        .and_then(|row| row.get(usize::from(tree_depth)).copied())
        .filter(|&v| v != 0)
        .unwrap_or(FCMP_PROOF_SIZE_MAX)
}

/// `ExtraField::PqcKemCiphertext`: tag + varint(len) + ciphertext.
fn extra_kem_field_weight() -> usize {
    1 + varint_len(KEM_CIPHERTEXT_LEN as u64) + KEM_CIPHERTEXT_LEN
}

/// One per-input `PqcAuth`: auth_version + scheme_id + flags(u16) +
/// varint(pk_len) ‖ pk + varint(sig_len) ‖ sig.
fn pqc_auth_weight() -> usize {
    1 + 1
        + 2
        + varint_len(PQC_HYBRID_SINGLE_KEY_LEN as u64)
        + PQC_HYBRID_SINGLE_KEY_LEN
        + varint_len(PQC_HYBRID_SINGLE_SIG_LEN as u64)
        + PQC_HYBRID_SINGLE_SIG_LEN
}

/// Padded output count the Bp+ aggregates over — next power of two, ≥ 1.
fn padded_outputs(n_out: OutputCount) -> usize {
    // `n_out` is type-bounded to `1..=MAX_OUTPUTS`, so `next_power_of_two` is in
    // range with no clamp needed.
    n_out.get().next_power_of_two()
}

/// Serialized Bp+ size: 6 fixed points + varint(|L|)‖L + varint(|R|)‖R, where
/// `|L| == |R| == 6 + log2(n_padded)` (the proof's L/R vector length).
fn bp_plus_weight(n_out: OutputCount) -> usize {
    let nlr = 6 + padded_outputs(n_out).trailing_zeros() as usize;
    6 * 32 + 2 * (varint_len(nlr as u64) + nlr * 32)
}

/// Bp+ verification clawback for the predicted output count. Delegates to the canonical
/// [`shekyl_wire::transaction::bp_plus_weight_clawback`] so the predictor and `weight()`
/// share one formula; `padded_outputs` supplies the same `n_padded` (clamped to
/// `MAX_OUTPUTS`) that a built tx's proof would yield.
fn bp_plus_clawback_weight(n_out: OutputCount) -> usize {
    bp_plus_weight_clawback(padded_outputs(n_out))
}

/// Structural weight predictor (§3.10.1) — a byte-for-byte mirror of
/// `shekyl_wire::Transaction::write` plus the Bp+ clawback, so it equals
/// `Transaction::weight()` for the tx the builder will produce from these counts.
#[must_use]
pub(crate) fn predict_weight(
    n_in: InputCount,
    n_out: OutputCount,
    tree_depth: u8,
    fee: u64,
) -> usize {
    // `n_in`/`n_out` are type-bounded (`1..=MAX_INPUTS` / `1..=MAX_OUTPUTS`), so every
    // per-count product and the field sum stay far below `usize` overflow — plain
    // arithmetic, no saturation (the #179 saturating fold/products and `padded_outputs`
    // clamp collapse to the type invariant). Each entry below is one field of
    // `shekyl_wire::Transaction::write`, in wire order.
    let fcmp = fcmp_proof_size(n_in, tree_depth);
    let bp = bp_plus_weight(n_out);
    let bp_clawback = bp_plus_clawback_weight(n_out);
    let n_in = n_in.get();
    let n_out = n_out.get();
    let extra_len = EXTRA_PUBKEY_FIELD_WEIGHT + n_out * extra_kem_field_weight();
    [
        varint_len(TX_VERSION),            // version
        varint_len(0u64),                  // unlock_time
        varint_len(n_in as u64),           // vin count
        n_in * INPUT_TO_KEY_WEIGHT,        // vin elements
        varint_len(n_out as u64),          // vout count
        n_out * OUTPUT_WEIGHT,             // vout elements
        varint_len(extra_len as u64),      // tx_extra length prefix
        extra_len,                         // tx_extra body
        1,                   // ct type tag — one u8 (a byte width, not CT_TYPE_FCMP's value)
        varint_len(fee),     // fee
        REFERENCE_BLOCK_LEN, // reference_block
        n_out * CT_BASE_PER_OUTPUT_WEIGHT, // ct base (per output)
        n_in * pqc_auth_weight(), // per-input PQC auth
        varint_len(1u64),    // prunable nbp
        bp,                  // bulletproof+
        varint_len(u64::from(tree_depth)), // tree_depth
        varint_len(fcmp as u64), // fcmp_proof length prefix
        fcmp,                // fcmp_proof body
        n_in * PSEUDO_OUT_LEN, // pseudoOuts
        bp_clawback,         // Bp+ verification clawback
    ]
    .into_iter()
    .sum()
}

/// Marginal weight of one additional input at `D_ref = MAX_TREE_DEPTH`.
#[must_use]
#[allow(dead_code)] // 2a-3 dust-fold consumes; 2a-2 uses `tx_fee::MARGINAL_INPUT_WEIGHT` stub.
pub(crate) fn marginal_input_weight_at_d_ref(tree_depth: u8) -> usize {
    let fee = 0;
    let n_out = OutputCount::clamped(1);
    predict_weight(InputCount::clamped(2), n_out, tree_depth, fee).saturating_sub(predict_weight(
        InputCount::clamped(1),
        n_out,
        tree_depth,
        fee,
    ))
}

/// Canonical dust predicate inner expression (§3.10.2).
#[must_use]
pub(crate) fn dust_threshold_for_rate(rate: &FeeRate) -> u64 {
    tx_fee::dust_threshold(rate)
}

/// Map [`super::fee_estimator::FeePriority`] to a [`FeeRate`] from the snapshot.
pub(crate) fn fee_rate_for_priority(
    priority: super::fee_estimator::FeePriority,
    snapshot: &super::traits::FeeEstimates,
) -> Result<FeeRate, super::error::FeeEstimatorError> {
    use super::error::FeeEstimatorError;
    use super::fee_estimator::FeePriority;

    match priority {
        FeePriority::Economy => Ok(snapshot.economy),
        FeePriority::Standard => Ok(snapshot.standard),
        FeePriority::Priority => Ok(snapshot.priority),
        FeePriority::Custom(rate) => {
            let floor = snapshot.economy;
            let custom = FeeRate::new(rate.get(), snapshot.quantization_mask).map_err(|_| {
                FeeEstimatorError::DaemonResponseInvalid {
                    reason: "custom feerate or mask is zero",
                }
            })?;
            let floor_one = tx_fee::try_fee_from_weight(&floor, 1).ok_or(
                FeeEstimatorError::DaemonResponseInvalid {
                    reason: "economy feerate overflowed fee arithmetic",
                },
            )?;
            let custom_one = tx_fee::try_fee_from_weight(&custom, 1).ok_or(
                FeeEstimatorError::DaemonResponseInvalid {
                    reason: "custom feerate overflowed fee arithmetic",
                },
            )?;
            if custom_one < floor_one {
                return Err(FeeEstimatorError::DaemonResponseInvalid {
                    reason: "custom feerate below economy floor",
                });
            }
            let ceiling_fee = floor_one.saturating_mul(100);
            if custom_one > ceiling_fee {
                return Err(FeeEstimatorError::DaemonResponseInvalid {
                    reason: "custom feerate above sanity ceiling",
                });
            }
            Ok(custom)
        }
    }
}

/// Quantized fee from structural weight (non-panicking on daemon-derived rates).
#[must_use]
pub(crate) fn fee_from_weight(rate: &FeeRate, weight: usize) -> u64 {
    tx_fee::fee_from_weight(rate, weight)
}

/// Two-pass fee fixpoint for one output-count variant (§3.3 / §3.10.1).
#[must_use]
pub(crate) fn converge_fee(
    rate: &FeeRate,
    n_in: InputCount,
    n_out: OutputCount,
    tree_depth: u8,
    initial_fee: u64,
) -> u64 {
    let mut fee = initial_fee;
    for _ in 0..2 {
        let weight = predict_weight(n_in, n_out, tree_depth, fee);
        fee = fee_from_weight(rate, weight);
    }
    fee
}

/// Populate [`FeeDirective`] for the selected input count and payment outputs `N`.
pub(crate) fn build_fee_directive(
    rate: &FeeRate,
    n_in: InputCount,
    payment_output_count: OutputCount,
    tree_depth: u8,
) -> FeeDirective {
    let n_no_change = payment_output_count;
    // With-change adds one output; a perfect-fit MAX_OUTPUTS-payment spend has no
    // change slot, so the speculative `+1` caps at MAX_OUTPUTS (that variant is then
    // unbuildable and the orchestrator picks no-change).
    let n_with_change = OutputCount::clamped(payment_output_count.get() + 1);
    let seed = fee_from_weight(rate, predict_weight(n_in, n_no_change, tree_depth, 0));
    let fee_no_change = converge_fee(rate, n_in, n_no_change, tree_depth, seed);
    let fee_with_change = converge_fee(rate, n_in, n_with_change, tree_depth, fee_no_change);
    FeeDirective {
        fee_no_change,
        fee_with_change,
        dust_threshold: dust_threshold_for_rate(rate),
    }
}

/// Fee charged for the no-change variant (orchestrator picks variant in 2a-3).
#[must_use]
#[allow(dead_code)] // 2a-3 F4/F8 dust-fold calls this; 2a-2 stores raw fee on `PendingTx`.
pub(crate) fn fee_no_change_atomic(directive: &FeeDirective) -> AtomicUnits {
    AtomicUnits::from_raw(directive.fee_no_change)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_rpc::FeeRate;

    #[test]
    #[ignore]
    fn kat_print_depth1_fcmp_sizes() {
        for n_in in 1..=8usize {
            let measured = crate::engine::tx_weight_kat::support::measure_fcmp_proof_len(n_in, 1)
                .unwrap_or_else(|e| panic!("({n_in},1): {e}"));
            eprintln!("n_in={n_in} fcmp={measured}");
        }
    }

    #[test]
    fn kat_fcmp_proof_size_depth1_row() {
        for n_in in 1..=8usize {
            let measured = crate::engine::tx_weight_kat::support::measure_fcmp_proof_len(n_in, 1)
                .unwrap_or_else(|e| panic!("({n_in},1): {e}"));
            assert_eq!(
                fcmp_proof_size(InputCount::clamped(n_in), 1),
                measured,
                "depth=1 KAT mismatch at n_in={n_in}"
            );
        }
    }

    #[test]
    #[ignore = "slow: emit FCMP_PROOF_SIZE_KAT table; run with --ignored --nocapture"]
    fn kat_emit_fcmp_proof_size_table() {
        for n_in in 1..=8usize {
            print!("        [0");
            for tree_depth in 1..=24u8 {
                let measured =
                    crate::engine::tx_weight_kat::support::measure_fcmp_proof_len(n_in, tree_depth)
                        .unwrap_or_else(|e| panic!("({n_in},{tree_depth}): {e}"));
                print!(", {measured}");
            }
            println!("],");
        }
    }

    #[test]
    #[ignore = "slow: full [1,8]×[1,24] fcmp_proof_size KAT; run with --ignored"]
    fn kat_fcmp_proof_size_grid() {
        for tree_depth in 1..=24u8 {
            for n_in in 1..=8usize {
                let measured =
                    crate::engine::tx_weight_kat::support::measure_fcmp_proof_len(n_in, tree_depth)
                        .unwrap_or_else(|e| panic!("({n_in},{tree_depth}): {e}"));
                assert_eq!(
                    fcmp_proof_size(InputCount::clamped(n_in), tree_depth),
                    measured,
                    "KAT mismatch at n_in={n_in} depth={tree_depth}"
                );
            }
        }
    }

    #[test]
    fn predict_weight_increases_with_inputs_and_outputs() {
        let w1 = predict_weight(InputCount::clamped(1), OutputCount::clamped(1), 1, 1_000);
        let w2 = predict_weight(InputCount::clamped(2), OutputCount::clamped(1), 1, 1_000);
        let w3 = predict_weight(InputCount::clamped(1), OutputCount::clamped(2), 1, 1_000);
        assert!(w2 > w1);
        assert!(w3 > w1);
    }

    #[test]
    fn predict_weight_caps_oversize_counts() {
        // Counts are type-bounded, so an out-of-range value is unrepresentable:
        // `clamped` caps it at the bound and the predictor yields a finite MAX-count
        // weight (no overflow/panic, no wrap below a normal weight that would under-pay).
        let capped = predict_weight(
            InputCount::clamped(usize::MAX),
            OutputCount::clamped(usize::MAX),
            MAX_TREE_DEPTH,
            u64::MAX,
        );
        let normal = predict_weight(
            InputCount::clamped(2),
            OutputCount::clamped(2),
            MAX_TREE_DEPTH,
            1_000,
        );
        assert!(
            capped > normal,
            "capped MAX-count weight must exceed a normal weight"
        );
    }

    /// `predict_weight` must equal `shekyl_wire::Transaction::weight()` for the tx
    /// shape the builder produces from the same counts — the reopen criterion for the
    /// canonical-weight follow-up. Builds a wire tx whose field *sizes* mirror a real
    /// spend (real `Extra` serializer, so the tx_extra term is validated non-circularly;
    /// real Bp+ `|L|`, real PQC pk/sig lengths, KAT fcmp proof) across input/output
    /// scaling and the >2-output clawback. The live build-path cross-checks
    /// (`build_then_submit_*`) anchor the n_in=1/n_out=2 case against the real builder.
    #[test]
    fn predict_weight_matches_wire_weight() {
        use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        use shekyl_scanner::extra::Extra;
        use shekyl_wire::{
            BpPlus, Ct, CtBase, Input, Output, PqcAuth, Prunable, Transaction, TxPrefix,
        };

        for &(n_in, n_out, depth, fee) in &[
            (1usize, 1usize, 1u8, 0u64),
            (1, 2, 2, 103_760),
            (2, 2, 8, 1_000),
            (2, 3, 4, 50_000), // n_out=3 ⇒ 4 padded ⇒ non-zero clawback
            (3, 4, 12, 7),
        ] {
            let nlr = 6 + padded_outputs(OutputCount::clamped(n_out)).trailing_zeros() as usize;
            let bp = BpPlus {
                a: [0; 32],
                a1: [0; 32],
                b: [0; 32],
                r1: [0; 32],
                s1: [0; 32],
                d1: [0; 32],
                l: vec![[0; 32]; nlr],
                r: vec![[0; 32]; nlr],
            };
            let extra = Extra::for_hybrid_transfer(
                ED25519_BASEPOINT_POINT,
                (0..n_out).map(|_| vec![0u8; KEM_CIPHERTEXT_LEN]),
            )
            .serialize();
            let tx = Transaction {
                prefix: TxPrefix {
                    unlock_time: 0,
                    inputs: (0..n_in)
                        .map(|_| Input::ToKey {
                            amount: 0,
                            key_offsets: vec![],
                            key_image: [0; 32],
                        })
                        .collect(),
                    outputs: (0..n_out)
                        .map(|_| Output {
                            amount: 0,
                            key: [0; 32],
                            view_tag: 0,
                        })
                        .collect(),
                    extra,
                },
                ct: Ct::Fcmp {
                    fee,
                    reference_block: [0; 32],
                    base: CtBase {
                        enc_amounts: vec![[0; 9]; n_out],
                        enc_labels: vec![[0; 9]; n_out],
                        commitments: vec![[0; 32]; n_out],
                    },
                    pqc_auths: (0..n_in)
                        .map(|_| PqcAuth {
                            auth_version: 1,
                            scheme_id: 1,
                            flags: 0,
                            hybrid_public_key: vec![0u8; PQC_HYBRID_SINGLE_KEY_LEN],
                            hybrid_signature: vec![0u8; PQC_HYBRID_SINGLE_SIG_LEN],
                        })
                        .collect(),
                    prunable: Some(Prunable {
                        bulletproofs: vec![bp],
                        tree_depth: u64::from(depth),
                        fcmp_proof: vec![0u8; fcmp_proof_size(InputCount::clamped(n_in), depth)],
                        pseudo_outs: vec![[0; 32]; n_in],
                    }),
                },
            };
            assert_eq!(
                predict_weight(InputCount::clamped(n_in), OutputCount::clamped(n_out), depth, fee),
                tx.weight(),
                "predict_weight ≠ wire weight for n_in={n_in} n_out={n_out} depth={depth} fee={fee}"
            );
        }
    }

    #[test]
    fn converge_fee_is_stable_within_two_passes() {
        let rate = FeeRate::new(10, 1).unwrap();
        let fee = converge_fee(&rate, InputCount::clamped(1), OutputCount::clamped(2), 1, 0);
        assert!(fee > 0);
    }

    /// PHASE_2A_SEND_PATH.md §8.2 — documents the **implemented** Custom-only ceiling.
    /// Daemon-tier `DaemonFeeUnreasonable` remains a §10 security residual.
    #[test]
    fn custom_fee_above_sanity_ceiling_rejected() {
        use super::fee_rate_for_priority;
        use crate::engine::error::FeeEstimatorError;
        use crate::engine::fee_estimator::FeePriority;
        use crate::engine::traits::FeeEstimates;
        use std::num::NonZeroU64;

        let snapshot = FeeEstimates {
            economy: FeeRate::new(1, 1).expect("economy"),
            standard: FeeRate::new(10, 1).expect("standard"),
            priority: FeeRate::new(100, 1).expect("priority"),
            quantization_mask: 1,
        };
        let inflated = NonZeroU64::new(101).expect("above 100× economy at weight 1");
        let err = fee_rate_for_priority(FeePriority::Custom(inflated), &snapshot)
            .expect_err("custom feerate above ceiling");
        match err {
            FeeEstimatorError::DaemonResponseInvalid { reason } => {
                assert!(reason.contains("sanity ceiling"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
