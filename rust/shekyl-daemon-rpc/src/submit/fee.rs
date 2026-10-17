// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fee-floor arithmetic: the submit engine's interim admission predicate
//! (parity row P2 of `docs/design/DAEMON_SUBMIT_VERDICT.md` §8.6).
//!
//! `fee_per_byte` is a Phase-B snapshot fact computed C++-side (the tip
//! floor alone); the lattice is `shekyl_economics::FEE_QUANTIZATION_MASK`.
//!
//! ```text
//! needed  = quantized_fee(tx_weight, fee_per_byte)   (the lattice)
//! accept  ⇔ fee ≥ needed                             (zero slack, FL-R23)
//! ```
//!
//! Because the floor is per-block dynamic (F34), the same arithmetic runs
//! twice: Phase C against the snapshot params, and again over the **fresh**
//! params when a Phase-D race returns them.

use shekyl_economics::quantized_fee;

/// Whether `fee` clears the dynamic floor for `tx_weight` at
/// `fee_per_byte`: the tip floor alone, on the lattice, at zero slack.
///
/// **Never more permissive than the commit.** The commit's re-gate is
/// `shekyl_economics::relay_floor_admits` over the window
/// `(tip − G ..= tip)`, and it admits only when that window ends at the
/// tip it commits on. The window therefore contains the tip's floor, so
/// its minimum is at most the floor this predicate reads, and
/// `quantized_fee` is monotone in the floor: a fee that clears the tip
/// at zero slack clears the window. The same holds over Phase D's fresh
/// facts. So a short fee is `FeeTooLow` here, and never reaches the
/// commit to come back `RACED` with nothing to classify.
///
/// **Stricter than the commit, by the window's rise.** A fee that clears
/// the window minimum but not the tip floor is refused here although the
/// commit would admit it; the wallet re-quotes. That is the fail-safe
/// direction, and Rick accepted the interim for testnet (2026-10-16).
/// **Replaced at the DRS-X store flip** by `relay_floor_admits` over
/// `shekyl_chain_rules::relay_floor_window`: lookback-min over `G` = 5
/// floors read off the store.
///
/// A requirement that overflows `u64` is a floor no fee can meet, so it
/// refuses (rule 20 §4: checked where the C++ wrapped).
pub fn fee_meets_floor(tx_weight: u64, fee: u64, fee_per_byte: u64) -> bool {
    quantized_fee(tx_weight, fee_per_byte).is_some_and(|needed| fee >= needed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_multiple_of_the_lattice_needs_no_rounding() {
        // needed = 1500 × 8000 = 12_000_000, already a multiple of 1000.
        assert!(fee_meets_floor(1500, 12_000_000, 8000));
        assert!(!fee_meets_floor(1500, 11_999_999, 8000));
    }

    #[test]
    fn the_requirement_rounds_up_to_the_lattice() {
        // needed = 1501 × 8001 = 12_009_501 → 12_010_000.
        assert!(fee_meets_floor(1501, 12_010_000, 8001));
        assert!(!fee_meets_floor(1501, 12_009_999, 8001));
    }

    #[test]
    fn a_requirement_below_one_step_is_one_step() {
        // needed = 7 × 3 = 21 → 1000.
        assert!(fee_meets_floor(7, 1000, 3));
        assert!(!fee_meets_floor(7, 999, 3));
    }

    /// The boundary pair at zero slack: the requirement itself admits and
    /// one atomic unit below refuses, so nothing of the 2 % band FL-R23
    /// deleted is admitted.
    #[test]
    fn the_requirement_admits_and_one_unit_below_refuses() {
        for (weight, fee_per_byte) in [(1500, 8000), (1501, 8001), (7, 3), (2_400, 31_337)] {
            let needed = quantized_fee(weight, fee_per_byte).expect("in range");
            assert!(fee_meets_floor(weight, needed, fee_per_byte));
            assert!(!fee_meets_floor(weight, needed - 1, fee_per_byte));
        }
    }

    /// Phase C is never more permissive than the commit: whatever this
    /// predicate admits at the tip floor, `relay_floor_admits` admits over
    /// any window whose last floor is that tip.
    #[test]
    fn admission_at_the_tip_implies_admission_over_the_window() {
        use shekyl_economics::relay_floor_admits;
        let tip = 8_001;
        let windows: [&[u64]; 4] = [
            &[tip],
            &[8_200, 8_150, 8_100, 8_050, 8_020, tip],
            &[7_000, 9_000, 7_500, 8_500, 6_000, tip],
            &[tip, tip, tip, tip, tip, tip],
        ];
        for weight in [7, 1500, 1501, 2_400] {
            let needed = quantized_fee(weight, tip).expect("in range");
            for fee in [needed, needed + 1, needed + 999, needed * 2] {
                assert!(fee_meets_floor(weight, fee, tip));
                for window in windows {
                    assert!(
                        relay_floor_admits(fee, weight, window),
                        "fee {fee} at weight {weight} clears the tip but not {window:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn zero_fee_fails_any_positive_floor() {
        // The C++ floor is never zero (the relay floor is `max(1)`), so a
        // zero-fee tx — including the fee-only serve-credit shape, which
        // consensus pins to fee 0 — fails the pool fee gate. Parity with
        // add_tx today; the serve-credit submission contradiction is
        // recorded in FOLLOWUPS, not resolved here.
        assert!(!fee_meets_floor(300, 0, 1));
    }

    #[test]
    fn multiply_overflow_rejects_instead_of_wrapping() {
        assert!(!fee_meets_floor(u64::MAX, u64::MAX, u64::MAX));
    }
}
