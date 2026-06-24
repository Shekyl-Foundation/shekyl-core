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

use shekyl_io::varint_len;
use shekyl_rpc::{tx_fee, FeeRate};
use shekyl_tx_builder::{MAX_INPUTS, MAX_TREE_DEPTH};
use shekyl_units::AtomicUnits;
use shekyl_wire::transaction::TX_VERSION;

use super::traits::key::FeeDirective;

// ── Wire-exact component sizes ──────────────────────────────────────────────
// Each constant is one field of `shekyl_wire::Transaction::write`; `predict_weight`
// sums them so it equals `Transaction::weight()` exactly (pinned by the build-path
// cross-checks + `predict_weight_matches_wire_weight`).

/// Hybrid PQC public-key blob on the wire (ed25519 ‖ ML-DSA-65).
const PQC_PUBLIC_KEY_LEN: usize = 1996;
/// Hybrid PQC signature blob on the wire (ed25519 ‖ ML-DSA-65).
const PQC_SIGNATURE_LEN: usize = 3385;
/// Hybrid KEM ciphertext per output in `tx_extra` (x25519 ‖ ML-KEM-768 CT).
const KEM_CIPHERTEXT_LEN: usize = 32 + 1_088;

/// `Input::ToKey`: tag + varint(amount=0) + varint(key_offsets=0) + key_image.
const INPUT_TO_KEY_WEIGHT: usize = 1 + 1 + 1 + 32;
/// `Output`: tag + varint(amount=0) + one-time key + view_tag.
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
        0, 3392, 3808, 4160, 4704, 4928, 5344, 5696, 6240, 5760, 5280, 5472, 5824, 6016, 6240,
        6432, 6784, 6464, 5952, 6112, 6304, 6496, 6688, 6720, 6912,
    ],
    [
        0, 4832, 5792, 5440, 6272, 6784, 6528, 7040, 7488, 7296, 6848, 7200, 7584, 7936, 8192,
        8544, 8928, 8768, 8288, 8480, 8704, 9056, 9408, 9472, 9824,
    ],
    [
        0, 5152, 6528, 7104, 7520, 7200, 7264, 7680, 8256, 8640, 9216, 9088, 8800, 9152, 9696,
        10080, 10464, 10848, 11264, 11648, 12032, 12256, 12096, 12480, 12704,
    ],
    [
        0, 6048, 7968, 7808, 8128, 8832, 8768, 9472, 10112, 10112, 9856, 10400, 10976, 11520,
        11968, 12512, 13088, 13120, 12832, 13216, 13632, 14176, 14720, 14976, 15520,
    ],
    [
        0, 7104, 8544, 8224, 8832, 9600, 10560, 10432, 10496, 11072, 11840, 12416, 13024, 13760,
        13792, 13696, 14272, 14816, 15424, 16000, 16576, 17152, 17728, 18144, 18720,
    ],
    [
        0, 6880, 8672, 9600, 10112, 10144, 10560, 11200, 12128, 12864, 13664, 13760, 13952, 14400,
        15296, 15904, 16512, 17248, 18016, 18752, 19360, 19936, 20000, 20608, 21312,
    ],
    [
        0, 7712, 9728, 9824, 10624, 11552, 12000, 12800, 13760, 13984, 14240, 15008, 15808, 16576,
        17504, 18272, 19040, 19648, 20448, 21216, 21280, 21536, 22304, 23040, 23808,
    ],
    [
        0, 8416, 10784, 11008, 11712, 12800, 13120, 14208, 15232, 15616, 15744, 16672, 17632,
        18560, 19392, 20320, 21280, 21696, 21792, 22560, 23360, 24288, 25216, 25856, 26784,
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

fn fcmp_proof_size(n_in: usize, tree_depth: u8) -> usize {
    // Every reachable `(n_in, tree_depth)` has a measured cell. An out-of-range
    // lookup (rejected upstream) falls back to the largest measured size so the
    // fee estimate is conservative rather than panicking or under-paying.
    FCMP_PROOF_SIZE_KAT
        .get(n_in)
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
        + varint_len(PQC_PUBLIC_KEY_LEN as u64)
        + PQC_PUBLIC_KEY_LEN
        + varint_len(PQC_SIGNATURE_LEN as u64)
        + PQC_SIGNATURE_LEN
}

/// Padded output count the Bp+ aggregates over — next power of two, ≥ 1.
fn padded_outputs(n_out: usize) -> usize {
    n_out.max(1).next_power_of_two()
}

/// Serialized Bp+ size: 6 fixed points + varint(|L|)‖L + varint(|R|)‖R, where
/// `|L| == |R| == 6 + log2(n_padded)` (the proof's L/R vector length).
fn bp_plus_weight(n_out: usize) -> usize {
    let nlr = 6 + padded_outputs(n_out).trailing_zeros() as usize;
    6 * 32 + 2 * (varint_len(nlr as u64) + nlr * 32)
}

/// Bp+ verification clawback, the C++ `get_transaction_weight_clawback` — `0` for
/// ≤ 2 padded outputs. Mirrors `shekyl_wire`'s `bp_plus_clawback` (derived from
/// `n_padded` rather than the proof's `|L|`, equal for a well-formed tx).
fn bp_plus_clawback_weight(n_out: usize) -> usize {
    let n_padded = padded_outputs(n_out);
    if n_padded <= 2 {
        return 0;
    }
    const BP_BASE: usize = (32 * (6 + 7 * 2)) / 2;
    let nlr = n_padded.trailing_zeros() as usize + 6;
    let bp_size = 32 * (6 + 2 * nlr);
    let gross = BP_BASE * n_padded;
    if gross < bp_size {
        return 0;
    }
    (gross - bp_size) * 4 / 5
}

/// Structural weight predictor (§3.10.1) — a byte-for-byte mirror of
/// `shekyl_wire::Transaction::write` plus the Bp+ clawback, so it equals
/// `Transaction::weight()` for the tx the builder will produce from these counts.
#[must_use]
pub(crate) fn predict_weight(n_in: usize, n_out: usize, tree_depth: u8, fee: u64) -> usize {
    // version + unlock_time.
    let mut w = varint_len(TX_VERSION) + varint_len(0u64);
    // vin / vout: count prefix + elements.
    w += varint_len(n_in as u64) + n_in * INPUT_TO_KEY_WEIGHT;
    w += varint_len(n_out as u64) + n_out * OUTPUT_WEIGHT;
    // tx_extra: one PublicKey field + one PqcKemCiphertext per output.
    let extra_len = EXTRA_PUBKEY_FIELD_WEIGHT + n_out * extra_kem_field_weight();
    w += varint_len(extra_len as u64) + extra_len;
    // ct head: type byte + fee + reference_block.
    w += 1 + varint_len(fee) + REFERENCE_BLOCK_LEN;
    // ct base (per output) + per-input PQC auth.
    w += n_out * CT_BASE_PER_OUTPUT_WEIGHT;
    w += n_in * pqc_auth_weight();
    // prunable: nbp + bp+ + tree_depth + fcmp_proof + pseudoOuts.
    let fcmp = fcmp_proof_size(n_in, tree_depth);
    w += varint_len(1u64)
        + bp_plus_weight(n_out)
        + varint_len(u64::from(tree_depth))
        + varint_len(fcmp as u64)
        + fcmp
        + n_in * PSEUDO_OUT_LEN;
    // Bp+ verification clawback (0 for the genesis ≤2-output shapes).
    w + bp_plus_clawback_weight(n_out)
}

/// Marginal weight of one additional input at `D_ref = MAX_TREE_DEPTH`.
#[must_use]
#[allow(dead_code)] // 2a-3 dust-fold consumes; 2a-2 uses `tx_fee::MARGINAL_INPUT_WEIGHT` stub.
pub(crate) fn marginal_input_weight_at_d_ref(tree_depth: u8) -> usize {
    let fee = 0;
    let n_out = 1;
    predict_weight(2, n_out, tree_depth, fee)
        .saturating_sub(predict_weight(1, n_out, tree_depth, fee))
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
    n_in: usize,
    n_out: usize,
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
    n_in: usize,
    payment_output_count: usize,
    tree_depth: u8,
) -> FeeDirective {
    let n_no_change = payment_output_count;
    let n_with_change = payment_output_count + 1;
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
                fcmp_proof_size(n_in, 1),
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
                    fcmp_proof_size(n_in, tree_depth),
                    measured,
                    "KAT mismatch at n_in={n_in} depth={tree_depth}"
                );
            }
        }
    }

    #[test]
    fn predict_weight_increases_with_inputs_and_outputs() {
        let w1 = predict_weight(1, 1, 1, 1_000);
        let w2 = predict_weight(2, 1, 1, 1_000);
        let w3 = predict_weight(1, 2, 1, 1_000);
        assert!(w2 > w1);
        assert!(w3 > w1);
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
            let nlr = 6 + padded_outputs(n_out).trailing_zeros() as usize;
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
                            hybrid_public_key: vec![0u8; PQC_PUBLIC_KEY_LEN],
                            hybrid_signature: vec![0u8; PQC_SIGNATURE_LEN],
                        })
                        .collect(),
                    prunable: Some(Prunable {
                        bulletproofs: vec![bp],
                        tree_depth: u64::from(depth),
                        fcmp_proof: vec![0u8; fcmp_proof_size(n_in, depth)],
                        pseudo_outs: vec![[0; 32]; n_in],
                    }),
                },
            };
            assert_eq!(
                predict_weight(n_in, n_out, depth, fee),
                tx.weight(),
                "predict_weight ≠ wire weight for n_in={n_in} n_out={n_out} depth={depth} fee={fee}"
            );
        }
    }

    #[test]
    fn converge_fee_is_stable_within_two_passes() {
        let rate = FeeRate::new(10, 1).unwrap();
        let fee = converge_fee(&rate, 1, 2, 1, 0);
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
