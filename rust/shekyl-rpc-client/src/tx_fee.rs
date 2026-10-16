// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fee arithmetic over daemon-derived rates (Phase 2a §3.10).
//!
//! A fee is `weight × rate` rounded up to the fee lattice, and the lattice
//! and its rounding are `shekyl-economics`' ([`quantized_fee`],
//! `FEE_QUANTIZATION_MASK`): the same function relay admission runs, so a
//! wallet's fee and the daemon's requirement cannot sit on different
//! lattices.
//!
//! Ownership of the dust boundary, precisely (2026-08-16), because
//! "it moved to engine-core" would be wrong in both directions:
//!
//! - the **formula** stays here ([`dust_threshold`]) — it is rate
//!   arithmetic, which is what this module is;
//! - the **marginal-input weight** it takes belongs to
//!   `shekyl-tx-weight`, the single-source weight model, which this
//!   crate deliberately does not depend on;
//! - the **composition** happens at each call site (engine build,
//!   scanner coin selection), which is the only place both are in
//!   scope.
//!
//! So an edit to the arithmetic lands here, an edit to the weight
//! lands in `shekyl-tx-weight`, and neither crate has to know the
//! other exists. The pre-2026-08-16 `MARGINAL_INPUT_WEIGHT` constant
//! *here* was the thing that moved: a provisional stub with a zero
//! FCMP proof increment that outlived the KAT meant to replace it.

use shekyl_economics::quantized_fee;

use crate::FeeRate;

/// Dimensionless dust multiplier (`K_DUST = 1` per §3.10.2).
pub const K_DUST: u64 = 1;

/// Fee-relative dust boundary (§3.10.2 / §3.8.5): an amount is dust
/// when strictly below the cost to spend one additional input at
/// `rate`. `marginal_input_weight` comes from the weight model's owner
/// (`shekyl_tx_weight::marginal_input_weight_at_d_ref` — the 2a-3
/// replacement that retired the zero-proof-increment stub formerly
/// housed here), which this crate deliberately does not depend on: the
/// call sites (engine build, scanner coin selection) compose the
/// model's number with this formula, so the formula and the number
/// each have exactly one owner.
///
/// Canonical predicate: `amount < dust_threshold(rate, marginal)`.
#[must_use]
pub fn dust_threshold(rate: &FeeRate, marginal_input_weight: usize) -> u64 {
    K_DUST.saturating_mul(fee_from_weight(rate, marginal_input_weight))
}

/// Non-panicking fee from weight. Returns `None` on overflow or unusable weight.
#[must_use]
pub fn try_fee_from_weight(rate: &FeeRate, weight: usize) -> Option<u64> {
    quantized_fee(u64::try_from(weight).ok()?, rate.per_weight)
}

/// Fee from weight for wallet paths that must not panic on daemon-derived rates.
///
/// Returns `u64::MAX` when [`try_fee_from_weight`] would overflow so callers fail
/// closed (insufficient funds / invalid estimate) instead of aborting the process.
#[must_use]
pub fn fee_from_weight(rate: &FeeRate, weight: usize) -> u64 {
    try_fee_from_weight(rate, weight).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_economics::quantized_fee;

    use crate::FeeRate;

    #[test]
    fn the_fee_is_the_rate_times_the_weight_on_the_lattice() {
        let rate = FeeRate::new(333).unwrap();
        // 11 097 × 333 = 3 695 301, rounded up to the next 1 000.
        assert_eq!(fee_from_weight(&rate, 11_097), 3_696_000);
        assert_eq!(
            fee_from_weight(&rate, 11_097),
            rate.calculate_fee_from_weight(11_097)
        );
        assert_eq!(
            fee_from_weight(&rate, 11_097),
            shekyl_economics::quantized_fee(11_097, 333).unwrap(),
            "one arithmetic: the wallet rounds as admission requires"
        );
    }

    #[test]
    fn try_fee_from_weight_returns_none_on_overflow() {
        let rate = FeeRate::new(u64::MAX).unwrap();
        assert!(try_fee_from_weight(&rate, 2).is_none());
        assert_eq!(fee_from_weight(&rate, 2), u64::MAX);
    }
}
