// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Balance computation with staking-aware categorization.

use serde::Serialize;

use crate::transfer::TransferDetails;

/// Default lock window (outputs cannot be spent for this many blocks after creation).
const DEFAULT_LOCK_WINDOW: u64 = 10;

/// Complete balance summary with staking breakdown.
#[derive(Clone, Debug, Default, Serialize)]
pub struct BalanceSummary {
    /// Total balance of all unspent outputs (including locked, staked, and frozen).
    pub total: u64,
    /// Balance available to spend right now (unlocked, not staked, not frozen).
    pub unlocked: u64,
    /// Total balance currently locked by the default lock window.
    pub locked_by_timelock: u64,
    /// Total staked balance (all staking states combined).
    pub staked_total: u64,
    /// Staked balance where the lock period has expired (may be unstaked/claimed).
    pub staked_matured: u64,
    /// Staked balance still within lock period.
    pub staked_locked: u64,
    /// Balance in frozen outputs.
    pub frozen: u64,
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
            summary.total += amount;

            if td.frozen {
                summary.frozen += amount;
                continue;
            }

            let matured_at = td.block_height + DEFAULT_LOCK_WINDOW;
            let timelock_satisfied = current_height >= matured_at;

            if td.staked {
                summary.staked_total += amount;
                if td.is_matured_stake(current_height) {
                    summary.staked_matured += amount;
                } else {
                    summary.staked_locked += amount;
                }
                continue;
            }

            if !timelock_satisfied {
                summary.locked_by_timelock += amount;
                continue;
            }

            summary.unlocked += amount;
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
            combined_shared_secret: None,
            frozen: false,
            fcmp_precomputed_path: None,
        }
    }

    #[test]
    fn empty_balance() {
        let summary = BalanceSummary::compute(&[], 100);
        assert_eq!(summary.total, 0);
        assert_eq!(summary.unlocked, 0);
    }

    #[test]
    fn basic_unlocked_balance() {
        let transfers = vec![make_td(1000, 50), make_td(2000, 60)];
        let summary = BalanceSummary::compute(&transfers, 100);
        assert_eq!(summary.total, 3000);
        assert_eq!(summary.unlocked, 3000);
    }

    #[test]
    fn timelocked_outputs() {
        let transfers = vec![make_td(1000, 95)];
        let summary = BalanceSummary::compute(&transfers, 100);
        assert_eq!(summary.total, 1000);
        assert_eq!(summary.unlocked, 0);
        assert_eq!(summary.locked_by_timelock, 1000);
    }

    #[test]
    fn staked_balance() {
        let mut td = make_td(5000, 50);
        td.staked = true;
        td.stake_tier = 1;
        td.stake_lock_until = 200;
        let transfers = vec![td];

        let summary = BalanceSummary::compute(&transfers, 100);
        assert_eq!(summary.total, 5000);
        assert_eq!(summary.unlocked, 0);
        assert_eq!(summary.staked_total, 5000);
        assert_eq!(summary.staked_locked, 5000);
        assert_eq!(summary.staked_matured, 0);

        let summary = BalanceSummary::compute(&transfers, 300);
        assert_eq!(summary.staked_matured, 5000);
        assert_eq!(summary.staked_locked, 0);
    }

    #[test]
    fn spent_excluded() {
        let mut td = make_td(1000, 50);
        td.spent = true;
        let transfers = vec![td];
        let summary = BalanceSummary::compute(&transfers, 100);
        assert_eq!(summary.total, 0);
    }

    #[test]
    fn frozen_excluded_from_unlocked() {
        let mut td = make_td(1000, 50);
        td.frozen = true;
        let transfers = vec![td];
        let summary = BalanceSummary::compute(&transfers, 100);
        assert_eq!(summary.total, 1000);
        assert_eq!(summary.unlocked, 0);
        assert_eq!(summary.frozen, 1000);
    }
}
