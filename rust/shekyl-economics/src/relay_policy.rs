// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Relay policy: the admission lookback, its slack, the fee lattice's
//! decimal places, and the emission-claim hold.
//!
//! These select what a node relays. They are not chain identity
//! ([`crate::params::EconomicParams`] is), so they stay out of the
//! consensus digest (FL-R27). Production reads [`relay_policy`]. A
//! simulation that varies one builds its own [`RelayPolicy`].

use std::sync::OnceLock;

use crate::fee::{
    EMISSION_CLAIM_FEE_FLOOR, FEE_DECIMAL_PLACES, RELAY_ADMISSION_SLACK_BP, RELAY_FLOOR_LOOKBACK,
};

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

impl Default for RelayPolicy {
    fn default() -> Self {
        Self {
            lookback: u64::try_from(RELAY_FLOOR_LOOKBACK).expect("G fits in u64"),
            admission_slack_bp: RELAY_ADMISSION_SLACK_BP,
            fee_decimal_places: FEE_DECIMAL_PLACES,
            emission_claim_fee_floor: EMISSION_CLAIM_FEE_FLOOR,
        }
    }
}

/// The shipped [`RelayPolicy`], resolved once.
pub fn relay_policy() -> &'static RelayPolicy {
    static POLICY: OnceLock<RelayPolicy> = OnceLock::new();
    POLICY.get_or_init(RelayPolicy::default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_policy_is_the_relay_constants() {
        let policy = RelayPolicy::default();
        assert_eq!(policy.lookback, 5);
        assert_eq!(policy.admission_slack_bp, 0);
        assert_eq!(policy.fee_decimal_places, 6);
        assert_eq!(policy.emission_claim_fee_floor, 3_600_000_000);
        assert_eq!(*relay_policy(), policy);
    }
}
