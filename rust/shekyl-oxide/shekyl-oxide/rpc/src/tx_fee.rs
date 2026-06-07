// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Canonical dust threshold and non-panicking fee-from-weight helpers for
//! Phase 2a fee-relative output folding and structural fee prediction.
//!
//! Per `PHASE_2A_SEND_PATH.md` §3.10.2: one function, two sites
//! (coin selection + engine build). `MARGINAL_INPUT_WEIGHT` is
//! provisional until the `fcmp_proof_size` KAT lands in 2a-3.

use crate::FeeRate;

/// Dimensionless dust multiplier (`K_DUST = 1` per §3.10.2).
pub const K_DUST: u64 = 1;

/// Weight one additional input adds at `D_ref = MAX_TREE_DEPTH (24)`.
///
/// Provisional stub: `32 + 32 + 3385 + 8` (hybrid auth, input framing,
/// varint overhead), with zero FCMP proof increment until the 2a-3 KAT
/// replaces this. Reopen iff the KAT moves this by more than a token amount.
pub const MARGINAL_INPUT_WEIGHT: usize = 32 + 32 + 3385 + 8;

/// Non-panicking fee from weight. Returns `None` on overflow or unusable weight.
#[must_use]
pub fn try_fee_from_weight(rate: &FeeRate, weight: usize) -> Option<u64> {
    let weight_u64 = u64::try_from(weight).ok()?;
    rate.per_weight.checked_mul(weight_u64).and_then(|fee| {
        let aligned = fee.div_ceil(rate.mask);
        aligned.checked_mul(rate.mask)
    })
}

/// Fee from weight for wallet paths that must not panic on daemon-derived rates.
///
/// Returns `u64::MAX` when [`try_fee_from_weight`] would overflow so callers fail
/// closed (insufficient funds / invalid estimate) instead of aborting the process.
#[must_use]
pub fn fee_from_weight(rate: &FeeRate, weight: usize) -> u64 {
    try_fee_from_weight(rate, weight).unwrap_or(u64::MAX)
}

/// Fee-relative dust boundary (§3.10.2 / §3.8.5): an amount is dust when it is
/// strictly below the cost to spend one additional input at `rate`.
///
/// Canonical predicate: `amount < dust_threshold(rate)`.
#[must_use]
pub fn dust_threshold(rate: &FeeRate) -> u64 {
    K_DUST.saturating_mul(fee_from_weight(rate, MARGINAL_INPUT_WEIGHT))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FeeRate;

    #[test]
    fn fee_from_weight_matches_calculate_for_sane_rates() {
        let rate = FeeRate::new(10, 1).unwrap();
        assert_eq!(
            fee_from_weight(&rate, 100),
            rate.calculate_fee_from_weight(100)
        );
    }

    #[test]
    fn try_fee_from_weight_returns_none_on_overflow() {
        let rate = FeeRate::new(u64::MAX, 1).unwrap();
        assert!(try_fee_from_weight(&rate, 2).is_none());
        assert_eq!(fee_from_weight(&rate, 2), u64::MAX);
    }
}
