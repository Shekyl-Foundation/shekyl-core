// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Balance computation with staking-aware categorization.

use serde::Serialize;
use shekyl_units::AtomicUnits;

use crate::transfer::TransferDetails;

/// Complete balance summary with staking breakdown.
#[derive(Clone, Debug, Default, Serialize)]
pub struct BalanceSummary {
    /// Total balance of all unspent outputs (including locked, staked, and frozen).
    pub total: AtomicUnits,
    /// Balance available to spend right now (unlocked, not staked, not frozen).
    pub unlocked: AtomicUnits,
    /// Total balance currently locked (below eligible_height).
    pub locked_by_timelock: AtomicUnits,
    /// Total staked balance (all staking states combined).
    pub staked_total: AtomicUnits,
    /// Staked balance where the lock period has expired (may be unstaked/claimed).
    pub staked_matured: AtomicUnits,
    /// Staked balance still within lock period.
    pub staked_locked: AtomicUnits,
    /// Balance in frozen outputs.
    pub frozen: AtomicUnits,
}

/// Accumulate a balance bucket. A wallet's unspent total is bounded by the
/// money supply (`< u64::MAX` atomic units), so overflow here is not a
/// reachable condition for valid state — it is corrupted-state evidence and
/// must surface loudly (per ATOMIC_UNITS_NEWTYPE.md §7.2: `None` is a bug,
/// never `unwrap_or(ZERO)`).
fn accumulate(bucket: AtomicUnits, amount: AtomicUnits) -> AtomicUnits {
    bucket
        .checked_add(amount)
        .expect("balance overflow: unspent output total exceeds u64 atomic units (corrupted state)")
}

impl BalanceSummary {
    /// Compute balance from a set of transfer details at the given height.
    pub fn compute(transfers: &[TransferDetails], current_height: u64) -> Self {
        let mut summary = BalanceSummary::default();

        for td in transfers {
            if td.spent {
                continue;
            }

            let amount = td.amount();
            summary.total = accumulate(summary.total, amount);

            if td.frozen {
                summary.frozen = accumulate(summary.frozen, amount);
                continue;
            }

            let timelock_satisfied = current_height >= td.eligible_height;

            if td.staked {
                summary.staked_total = accumulate(summary.staked_total, amount);
                if td.is_matured_stake(current_height) {
                    summary.staked_matured = accumulate(summary.staked_matured, amount);
                } else {
                    summary.staked_locked = accumulate(summary.staked_locked, amount);
                }
                continue;
            }

            if !timelock_satisfied {
                summary.locked_by_timelock = accumulate(summary.locked_by_timelock, amount);
                continue;
            }

            summary.unlocked = accumulate(summary.unlocked, amount);
        }

        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar};
    use shekyl_oxide::primitives::Commitment;

    fn make_td(amount: u64, height: u64) -> TransferDetails {
        use crate::transfer::SPENDABLE_AGE;
        TransferDetails {
            tx_hash: [0u8; 32],
            internal_output_index: 0,
            global_output_index: 0,
            block_height: height,
            key: ED25519_BASEPOINT_POINT,
            key_offset: Scalar::ZERO,
            commitment: Commitment::new(Scalar::ZERO, amount),
            subaddress: None,
            payment_id: None,
            spent: false,
            spent_height: None,
            key_image: None,
            staked: false,
            stake_tier: 0,
            stake_lock_until: 0,
            last_claimed_height: 0,
            source_ciphertext: None,
            output_handle: None,
            eligible_height: height + SPENDABLE_AGE,
            frozen: false,
            fcmp_precomputed_path: None,
        }
    }

    #[test]
    fn empty_balance() {
        let summary = BalanceSummary::compute(&[], 100);
        assert_eq!(summary.total, AtomicUnits::ZERO);
        assert_eq!(summary.unlocked, AtomicUnits::ZERO);
    }

    #[test]
    fn basic_unlocked_balance() {
        let transfers = vec![make_td(1000, 50), make_td(2000, 60)];
        let summary = BalanceSummary::compute(&transfers, 100);
        assert_eq!(summary.total, AtomicUnits::from_raw(3000));
        assert_eq!(summary.unlocked, AtomicUnits::from_raw(3000));
    }

    #[test]
    fn timelocked_outputs() {
        let transfers = vec![make_td(1000, 95)];
        let summary = BalanceSummary::compute(&transfers, 100);
        assert_eq!(summary.total, AtomicUnits::from_raw(1000));
        assert_eq!(summary.unlocked, AtomicUnits::ZERO);
        assert_eq!(summary.locked_by_timelock, AtomicUnits::from_raw(1000));
    }

    #[test]
    fn staked_balance() {
        let mut td = make_td(5000, 50);
        td.staked = true;
        td.stake_tier = 1;
        td.stake_lock_until = 200;
        let transfers = vec![td];

        let summary = BalanceSummary::compute(&transfers, 100);
        assert_eq!(summary.total, AtomicUnits::from_raw(5000));
        assert_eq!(summary.unlocked, AtomicUnits::ZERO);
        assert_eq!(summary.staked_total, AtomicUnits::from_raw(5000));
        assert_eq!(summary.staked_locked, AtomicUnits::from_raw(5000));
        assert_eq!(summary.staked_matured, AtomicUnits::ZERO);

        let summary = BalanceSummary::compute(&transfers, 300);
        assert_eq!(summary.staked_matured, AtomicUnits::from_raw(5000));
        assert_eq!(summary.staked_locked, AtomicUnits::ZERO);
    }

    #[test]
    fn spent_excluded() {
        let mut td = make_td(1000, 50);
        td.spent = true;
        let transfers = vec![td];
        let summary = BalanceSummary::compute(&transfers, 100);
        assert_eq!(summary.total, AtomicUnits::ZERO);
    }

    #[test]
    fn frozen_excluded_from_unlocked() {
        let mut td = make_td(1000, 50);
        td.frozen = true;
        let transfers = vec![td];
        let summary = BalanceSummary::compute(&transfers, 100);
        assert_eq!(summary.total, AtomicUnits::from_raw(1000));
        assert_eq!(summary.unlocked, AtomicUnits::ZERO);
        assert_eq!(summary.frozen, AtomicUnits::from_raw(1000));
    }
}
