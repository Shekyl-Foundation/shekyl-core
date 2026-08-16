// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Structural transaction-weight predictor + bounded input/output counts.
//!
//! [`predict_weight`] mirrors `shekyl_wire::Transaction::write` byte-for-byte
//! (and adds the same Bp+ clawback), so it equals the post-build
//! `Transaction::weight()` **without constructing a transaction** — pinned by
//! [`predict_weight_matches_wire_weight`](crate::tests) (the single-source
//! guarantee). The `fcmp_proof_size` term reads the measured 2a-3 KAT table.
//!
//! Hoisted from `shekyl-engine-core` (§12.3 D-1) so the wallet fee path **and**
//! `shekyl-economics-sim`'s W9 stuffer arm share one single-sourced weight model
//! rather than a replicated byte formula. The **fee-rate** layer
//! (`FeeRate`/`FeeDirective`/fee convergence) stays in engine-core — this crate
//! is weight only, so its dependency surface is just the wire layout + proof
//! sizes ({`shekyl-wire`, `shekyl-fcmp`, `shekyl-crypto-pq`, `shekyl-curve-io`}),
//! no RPC or wallet types. The FCMP proof-size KAT's *validation* against real
//! synthetic-tree measurements stays in engine-core (where the measurement
//! machinery lives) and calls the `pub` [`fcmp_proof_size`] here.

use shekyl_crypto_pq::kem::HYBRID_KEM_CT_LEN;
use shekyl_curve_io::varint_len;
// Consensus proof-system limits from their UPSTREAM home (constraint 1 — never
// via shekyl-tx-builder's re-export, which would invert the arrow). `MAX_TREE_DEPTH`
// and `MAX_OUTPUTS` are re-exported (`pub use`) so consumers that price real tx
// shapes (the economics sim's leaf-stuffer, DQ-2G) can single-source them through
// this crate — the sanctioned window into the weight model — instead of depping
// shekyl-fcmp / shekyl-wire directly; `MAX_INPUTS` stays crate-internal.
use shekyl_fcmp::MAX_INPUTS;
pub use shekyl_fcmp::MAX_TREE_DEPTH;
pub use shekyl_wire::transaction::MAX_OUTPUTS;
use shekyl_wire::transaction::{
    bp_plus_weight_clawback, PQC_HYBRID_SINGLE_KEY_LEN, PQC_HYBRID_SINGLE_SIG_LEN, TX_VERSION,
};

// ── Bounded input/output counts ─────────────────────────────────────────────

macro_rules! bounded_count {
    ($name:ident, $max:expr, $what:literal) => {
        #[doc = concat!("Transaction ", $what, " count, bounded to `1..=", stringify!($max), "`.")]
        ///
        /// Constructed via [`Self::clamped`] at the fee-path boundary; the bound
        /// is a type invariant, so consumers do plain (overflow-free) arithmetic.
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
        pub struct $name(usize);

        impl $name {
            /// Wrap a raw count, clamping into `1..=MAX`. An out-of-range value
            /// caps at the bound (the prior clamp/saturate behaviour): a valid tx
            /// is exact, and an oversize request still fails at build validation,
            /// so the predictor never sees a value that could overflow.
            #[must_use]
            pub fn clamped(n: usize) -> Self {
                Self(n.clamp(1, $max))
            }

            /// The count as a `usize`, guaranteed in `1..=MAX`.
            #[must_use]
            pub const fn get(self) -> usize {
                self.0
            }
        }
    };
}

bounded_count!(InputCount, MAX_INPUTS, "input");
bounded_count!(OutputCount, MAX_OUTPUTS, "output");

// ── Wire-exact component sizes ──────────────────────────────────────────────
// Each constant is one field of `shekyl_wire::Transaction::write`; `predict_weight`
// sums them so it equals `Transaction::weight()` exactly. Sizes with a canonical
// home are imported, not re-typed (the hybrid PQC pk/sig lengths come from
// `shekyl_wire`).

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
/// Emitted by `kat_emit_fcmp_proof_size_table` (in engine-core, where the
/// synthetic-tree measurement machinery lives) from the depth-consistent
/// single-path synthetic trees (PF7). The depth-1 column equals the
/// independently-known depth-1 row, which cross-validates the measurement. The
/// series is **non-monotonic** in depth (the FCMP++ inner-product argument
/// rounds), so this is a lookup table, not a closed-form per-layer increment.
/// engine-core's `kat_fcmp_proof_size_grid` validates every cell against
/// re-measurement (`#[ignore]`; ~slow); `kat_fcmp_proof_size_depth1_row` guards
/// the depth-1 column in CI. Both call the `pub` [`fcmp_proof_size`] below.
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
/// out-of-range cell that should be unreachable (`n_in ∈ 1..=MAX_INPUTS`,
/// `tree_depth ∈ 1..=MAX_TREE_DEPTH`).
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

/// Measured FCMP++ proof size in bytes for `n_in` inputs at `tree_depth`. `pub`
/// so engine-core's KAT-validation tests (which own the synthetic-tree
/// measurement machinery) can cross-check the table without re-hosting it.
#[must_use]
pub fn fcmp_proof_size(n_in: InputCount, tree_depth: u8) -> usize {
    // `n_in` is type-bounded to `1..=MAX_INPUTS`, so the row always hits a measured
    // cell; an out-of-range `tree_depth` falls back to the largest measured size so
    // the fee estimate stays conservative rather than panicking or under-paying.
    FCMP_PROOF_SIZE_KAT
        .get(n_in.get())
        .and_then(|row| row.get(usize::from(tree_depth)).copied())
        .filter(|&v| v != 0)
        .unwrap_or(FCMP_PROOF_SIZE_MAX)
}

/// The **single** `ExtraField::PqcKemCiphertext` (`0x06`) field: tag +
/// varint(len) + `n_out` concatenated per-output ciphertexts — the packing
/// `Extra::for_hybrid_transfer` emits, which every reader slices at
/// `o * HYBRID_KEM_CT_LEN`.
///
/// **Was one field PER OUTPUT** until the parallel `0x06` fix on `dev`
/// (`5cd252883`); this crate carried the pre-fix shape through the D-1 hoist and
/// is corrected here at the merge. The delta is only the 15 saved tag+varint
/// pairs (~45 B on a 1-in/16-out tx, ~0.13 %), but the predictor must byte-mirror
/// `Transaction::write` exactly — the traveling parity test is the arbiter.
fn extra_kem_field_weight(n_out: usize) -> usize {
    let blob = n_out * HYBRID_KEM_CT_LEN;
    1 + varint_len(blob as u64) + blob
}

/// `ExtraField::PqcLeafHashes` (`0x07`): tag + varint(len) + `n_out × 32`
/// `H(pqc_pk)` leaf hashes — the field whose omission ingests an output with a
/// zero `h_pqc` leaf (unspendable); the transfer path appends it (sign_bridge.rs,
/// PR-4b), so every predicted spend carries it.
fn extra_leaf_hashes_field_weight(n_out: usize) -> usize {
    let blob = n_out * 32;
    1 + varint_len(blob as u64) + blob
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

/// Bp+ verification clawback for the predicted output count. Delegates to the
/// canonical [`shekyl_wire::transaction::bp_plus_weight_clawback`] so the
/// predictor and `weight()` share one formula; `padded_outputs` supplies the same
/// `n_padded` a built tx's proof would yield (`n_out` is type-bounded to
/// `1..=MAX_OUTPUTS` by [`OutputCount`], so no separate clamp is needed).
fn bp_plus_clawback_weight(n_out: OutputCount) -> usize {
    bp_plus_weight_clawback(padded_outputs(n_out))
}

/// Structural weight predictor (§3.10.1) — a byte-for-byte mirror of
/// `shekyl_wire::Transaction::write` plus the Bp+ clawback, so it equals
/// `Transaction::weight()` for the tx the builder will produce from these counts.
#[must_use]
pub fn predict_weight(n_in: InputCount, n_out: OutputCount, tree_depth: u8, fee: u64) -> usize {
    // `n_in`/`n_out` are type-bounded (`1..=MAX_INPUTS` / `1..=MAX_OUTPUTS`), so every
    // per-count product and the field sum stay far below `usize` overflow — plain
    // arithmetic, no saturation. Each entry below is one field of
    // `shekyl_wire::Transaction::write`, in wire order.
    let fcmp = fcmp_proof_size(n_in, tree_depth);
    let bp = bp_plus_weight(n_out);
    let bp_clawback = bp_plus_clawback_weight(n_out);
    let n_in = n_in.get();
    let n_out = n_out.get();
    let extra_len = EXTRA_PUBKEY_FIELD_WEIGHT
        + extra_kem_field_weight(n_out)
        + extra_leaf_hashes_field_weight(n_out);
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

/// Serialized byte size **and** fee weight for the tx the builder would produce
/// from these counts, as one `(size, weight)` pair.
///
/// The two differ by exactly the Bp+ verification clawback
/// ([`bp_plus_clawback_weight`], zero for `n_padded <= 2`): `weight` is what the
/// fee model charges ([`predict_weight`], equal to `Transaction::weight()`),
/// `size` is the wire bytes (`Transaction::write`'s length). Derived by
/// subtraction from the one predictor rather than re-summing the field model, so
/// the byte model stays single-source.
#[must_use]
pub fn predict_size_and_weight(
    n_in: InputCount,
    n_out: OutputCount,
    tree_depth: u8,
    fee: u64,
) -> (usize, usize) {
    let weight = predict_weight(n_in, n_out, tree_depth, fee);
    let size = weight - bp_plus_clawback_weight(n_out);
    (size, weight)
}

/// Marginal weight of one additional input at `D_ref = MAX_TREE_DEPTH`.
#[must_use]
pub fn marginal_input_weight_at_d_ref(tree_depth: u8) -> usize {
    let fee = 0;
    let n_out = OutputCount::clamped(1);
    predict_weight(InputCount::clamped(2), n_out, tree_depth, fee).saturating_sub(predict_weight(
        InputCount::clamped(1),
        n_out,
        tree_depth,
        fee,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_into_range() {
        assert_eq!(InputCount::clamped(0).get(), 1, "zero clamps up to 1");
        assert_eq!(InputCount::clamped(3).get(), 3, "in-range is exact");
        assert_eq!(
            InputCount::clamped(MAX_INPUTS).get(),
            MAX_INPUTS,
            "MAX is exact"
        );
        assert_eq!(
            InputCount::clamped(MAX_INPUTS + 5).get(),
            MAX_INPUTS,
            "oversize caps at MAX_INPUTS"
        );
        assert_eq!(
            InputCount::clamped(usize::MAX).get(),
            MAX_INPUTS,
            "usize::MAX caps"
        );

        assert_eq!(OutputCount::clamped(0).get(), 1);
        assert_eq!(OutputCount::clamped(MAX_OUTPUTS).get(), MAX_OUTPUTS);
        assert_eq!(
            OutputCount::clamped(MAX_OUTPUTS + 1).get(),
            MAX_OUTPUTS,
            "with-change +1 over the limit caps at MAX_OUTPUTS"
        );
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
    /// shape the builder produces from the same counts — **the single-source
    /// guarantee** (D-1 constraint 3: this test travels with the predictor).
    /// Builds a wire tx whose field *sizes* mirror a real spend (real `Extra`
    /// serializer, so the tx_extra term is validated non-circularly; real Bp+
    /// `|L|`, real PQC pk/sig lengths, KAT fcmp proof) across input/output scaling
    /// and the >2-output clawback.
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
            let extra = {
                let mut e = Extra::for_hybrid_transfer(
                    ED25519_BASEPOINT_POINT,
                    (0..n_out).map(|_| vec![0u8; HYBRID_KEM_CT_LEN]),
                );
                // The 0x07 leaf-hash blob the transfer path appends (sign_bridge.rs)
                // — real serializer, same as the KEM term.
                e.push_pqc_leaf_hashes(vec![0u8; n_out * 32]);
                e.serialize()
            };
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
            let (size, weight) = predict_size_and_weight(
                InputCount::clamped(n_in),
                OutputCount::clamped(n_out),
                depth,
                fee,
            );
            assert_eq!(
                weight,
                tx.weight(),
                "predict_size_and_weight weight ≠ wire weight for n_in={n_in} n_out={n_out}"
            );
            assert_eq!(
                size,
                tx.serialized_len(),
                "predict_size_and_weight size ≠ wire serialized_len for n_in={n_in} n_out={n_out}"
            );
        }
    }
}

#[cfg(test)]
mod marginal_input_weight_pin {
    /// The dust boundary's marginal-input weight, pinned so any weight-model
    /// movement is a loud, reviewed change to the dust bar. The second
    /// assertion records the 2026-08-16 retirement fact: the provisional
    /// `MARGINAL_INPUT_WEIGHT = 3457` stub (zero FCMP proof increment)
    /// understated this by the whole per-input proof increment — a future
    /// "simplification" back to a proofless constant must fail here.
    #[test]
    fn marginal_input_weight_is_pinned() {
        let w = super::marginal_input_weight_at_d_ref(super::MAX_TREE_DEPTH);
        assert_eq!(w, 9136, "weight-model movement changes the dust boundary");
        assert!(
            w > 3457,
            "the marginal weight must exceed the retired proofless stub"
        );
    }
}
