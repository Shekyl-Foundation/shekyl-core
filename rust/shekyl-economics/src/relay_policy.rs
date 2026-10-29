// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Relay policy: the admission lookback, its slack, the fee lattice's
//! decimal places, and the emission-claim hold.
//!
//! These select what a node relays. They are not chain identity
//! ([`crate::params::EconomicParams`] is), so they stay out of the
//! consensus digest (FL-R27). [`relay_policy`] is the shipped policy.
//! A fold that varies one builds its own [`RelayPolicy`] and calls
//! [`RelayPolicy::admits`], [`RelayPolicy::quantize`] or
//! [`RelayPolicy::admitted_floor`].

use shekyl_units::DISPLAY_DECIMAL_POINT;

use crate::fee::quantization::quantize_to_mask;
use crate::fee::{
    EMISSION_CLAIM_FEE_FLOOR, FEE_DECIMAL_PLACES, RELAY_ADMISSION_SLACK_BP, RELAY_FLOOR_LOOKBACK,
};

/// Basis points in one whole. [`RelayPolicy::admission_slack_bp`] is
/// written in these. A slack at or above this admits at zero.
const BASIS_POINTS: u128 = 10_000;

/// The relay numbers a node admits and quotes with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayPolicy {
    /// Lookback depth `G`, in blocks.
    pub lookback: u64,
    /// Admission slack, basis points. The shipped value is zero.
    pub admission_slack_bp: u32,
    /// Decimal places the fee lattice keeps.
    pub fee_decimal_places: u32,
    /// The emission-claim hold, in atomic units.
    pub emission_claim_fee_floor: u64,
}

impl RelayPolicy {
    /// The policy production admits, quotes and holds with. The four
    /// fields are the relay constants; this value is what readers use.
    ///
    /// `lookback` is [`RELAY_FLOOR_LOOKBACK`], a `usize` of 5.
    // CLIPPY: cast_possible_truncation — usize-to-u64 loses bits only on a
    // 128-bit target this tree does not build. The depth is 5.
    #[allow(clippy::cast_possible_truncation)]
    pub const SHIPPED: Self = Self {
        lookback: RELAY_FLOOR_LOOKBACK as u64,
        admission_slack_bp: RELAY_ADMISSION_SLACK_BP,
        fee_decimal_places: FEE_DECIMAL_PLACES,
        emission_claim_fee_floor: EMISSION_CLAIM_FEE_FLOOR,
    };

    /// Atomic units per lattice step, `10^(DISPLAY_DECIMAL_POINT − places)`.
    ///
    /// `None` when the places are finer than an atomic unit: that lattice
    /// cannot be stated.
    #[must_use]
    pub const fn quantization_mask(self) -> Option<u64> {
        if self.fee_decimal_places > DISPLAY_DECIMAL_POINT as u32 {
            None
        } else {
            Some(10u64.pow(DISPLAY_DECIMAL_POINT as u32 - self.fee_decimal_places))
        }
    }

    /// `weight × rate`, rounded up to this policy's lattice.
    ///
    /// `None` when the mask cannot be stated, or when the product or the
    /// rounding leaves `u64`. The shipped mask is
    /// [`crate::FEE_QUANTIZATION_MASK`].
    #[must_use]
    pub const fn quantize(self, weight: u64, rate: u64) -> Option<u64> {
        match self.quantization_mask() {
            Some(mask) => quantize_to_mask(weight, rate, mask),
            None => None,
        }
    }

    /// `floor` reduced by [`Self::admission_slack_bp`] basis points.
    ///
    /// Slack of zero is `floor`. A slack at or above [`BASIS_POINTS`]
    /// is zero: the reduction saturates rather than wrapping. The
    /// result is at most `floor`, so it fits `u64`.
    #[must_use]
    pub fn admitted_floor(self, floor: u64) -> u64 {
        let floor_wide = u128::from(floor);
        let reduction =
            floor_wide.saturating_mul(u128::from(self.admission_slack_bp)) / BASIS_POINTS;
        let admitted = floor_wide.saturating_sub(reduction);
        u64::try_from(admitted).expect("slack reduced a floor above the floor it started from")
    }

    /// Admit iff `fee` meets the quantized minimum floor, less this
    /// policy's slack.
    ///
    /// Empty `floors` refuses: no floor is not a floor of zero. A
    /// requirement the lattice cannot state refuses: no fee can meet it.
    /// Only the minimum floor is read, so order carries no meaning.
    #[must_use]
    pub fn admits(self, fee: u64, weight: u64, floors: &[u64]) -> bool {
        let Some(&min_floor) = floors.iter().min() else {
            return false;
        };
        let Some(needed) = self.quantize(weight, min_floor) else {
            return false;
        };
        u128::from(fee) >= u128::from(self.admitted_floor(needed))
    }
}

impl Default for RelayPolicy {
    fn default() -> Self {
        Self::SHIPPED
    }
}

/// The shipped [`RelayPolicy`].
#[must_use]
pub fn relay_policy() -> &'static RelayPolicy {
    &RelayPolicy::SHIPPED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_policy_is_the_relay_constants() {
        let policy = RelayPolicy::SHIPPED;
        assert_eq!(policy.lookback, 5);
        assert_eq!(policy.admission_slack_bp, 0);
        assert_eq!(policy.fee_decimal_places, 6);
        assert_eq!(policy.emission_claim_fee_floor, 3_600_000_000);
        assert_eq!(RelayPolicy::default(), policy);
        assert_eq!(*relay_policy(), policy);
        assert_eq!(policy.quantization_mask(), Some(1_000));
        assert_eq!(policy.quantize(1, 1), Some(1_000));
        assert_eq!(policy.admitted_floor(100_000), 100_000);
    }

    #[test]
    fn an_alternative_policy_changes_the_lattice_and_the_slack() {
        let shipped = RelayPolicy::SHIPPED;
        let finer = RelayPolicy {
            fee_decimal_places: 8,
            ..shipped
        };
        assert_eq!(finer.quantization_mask(), Some(10));
        assert_eq!(finer.quantize(1, 1), Some(10));
        assert_ne!(finer.quantize(1, 1), shipped.quantize(1, 1));

        let open = RelayPolicy {
            admission_slack_bp: 10_000,
            ..shipped
        };
        assert_eq!(open.admitted_floor(100_000), 0);
        assert!(open.admits(0, 1_000, &[100]));
        assert!(!shipped.admits(0, 1_000, &[100]));

        let too_fine = RelayPolicy {
            fee_decimal_places: u32::from(DISPLAY_DECIMAL_POINT) + 1,
            ..shipped
        };
        assert_eq!(too_fine.quantization_mask(), None);
        assert!(!too_fine.admits(u64::MAX, 1, &[1]));
        assert!(!shipped.admits(0, 1, &[]));
    }
}
