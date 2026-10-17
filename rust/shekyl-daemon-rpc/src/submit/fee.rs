// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fee-floor arithmetic — the Rust port of `Blockchain::check_fee`'s
//! acceptance gate as it stood before FL-R23 (parity row P2 of
//! `docs/design/DAEMON_SUBMIT_VERDICT.md` §8.6).
//!
//! `fee_per_byte` is a Phase-B snapshot fact computed C++-side (the tip
//! floor alone); the lattice is `shekyl_economics::FEE_QUANTIZATION_MASK`.
//! This module ports only the gate arithmetic:
//!
//! ```text
//! needed  = quantized_fee(tx_weight, fee_per_byte)   (the lattice)
//! accept  ⇔ fee ≥ needed − needed / 50               (2% acceptance buffer)
//! ```
//!
//! Because the floor is per-block dynamic (F34), the same arithmetic runs
//! twice: Phase C against the snapshot params, and again over the **fresh**
//! params when a Phase-D race returns them.

use shekyl_economics::quantized_fee;

/// Whether `fee` clears the dynamic floor for `tx_weight` at
/// `fee_per_byte` — the pre-FL-R23 acceptance predicate: the tip floor
/// alone, on the lattice, with the 2 % buffer. Rick accepted this interim
/// for testnet (2026-10-16). **Replaced at the DRS-X store flip** by
/// `shekyl_economics::relay_floor_admits` over
/// `shekyl_chain_rules::relay_floor_window`: lookback-min over `G` = 5
/// floors read off the store, zero slack.
///
/// A requirement that overflows `u64` is a floor no fee can meet, so it
/// refuses (rule 20 §4: checked where the C++ wrapped).
pub fn fee_meets_floor(tx_weight: u64, fee: u64, fee_per_byte: u64) -> bool {
    match quantized_fee(tx_weight, fee_per_byte) {
        Some(needed) => fee >= needed - needed / 50,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_multiple_of_the_lattice_needs_no_rounding() {
        // needed = 1500 × 8000 = 12_000_000, already a multiple of 1000.
        // buffer: 12_000_000 − 240_000 = 11_760_000.
        assert!(fee_meets_floor(1500, 11_760_000, 8000));
        assert!(!fee_meets_floor(1500, 11_759_999, 8000));
    }

    #[test]
    fn the_requirement_rounds_up_to_the_lattice() {
        // needed = 1501 × 8001 = 12_009_501 → 12_010_000.
        // buffer: 12_010_000 − 240_200 = 11_769_800.
        assert!(fee_meets_floor(1501, 11_769_800, 8001));
        assert!(!fee_meets_floor(1501, 11_769_799, 8001));
    }

    #[test]
    fn a_requirement_below_one_step_is_one_step() {
        // needed = 7 × 3 = 21 → 1000; buffer: 1000 − 20 = 980.
        assert!(fee_meets_floor(7, 980, 3));
        assert!(!fee_meets_floor(7, 979, 3));
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
