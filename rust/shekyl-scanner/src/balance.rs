// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Balance computation with lock/frozen categorization.

use serde::Serialize;
use shekyl_units::AtomicUnits;

use crate::transfer::TransferDetails;

/// Complete balance summary.
#[derive(Clone, Debug, Default, Serialize)]
pub struct BalanceSummary {
    /// Total balance of all unspent outputs (including locked and frozen).
    pub total: AtomicUnits,
    /// Balance available to spend right now (unlocked, not frozen).
    pub unlocked: AtomicUnits,
    /// Total balance currently locked (below eligible_height).
    pub locked_by_timelock: AtomicUnits,
    /// Balance in frozen outputs.
    pub frozen: AtomicUnits,
    /// Balance committed to a network-exposed spend awaiting chain
    /// confirmation (the F14 lock, `DAEMON_SUBMIT_VERDICT.md` §2.6).
    /// Counted in `total` (the spend has not settled) but never in
    /// `unlocked` — presenting it as spendable would invite a
    /// same-key-image rebuild.
    pub awaiting_confirmation: AtomicUnits,
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

            if td.awaiting_confirmation.is_some() {
                summary.awaiting_confirmation = accumulate(summary.awaiting_confirmation, amount);
                continue;
            }

            if td.frozen {
                summary.frozen = accumulate(summary.frozen, amount);
                continue;
            }

            let timelock_satisfied = current_height >= td.eligible_height;

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
    use shekyl_curve_primitives::Commitment;

    fn make_td(amount: u64, height: u64) -> TransferDetails {
        use crate::transfer::SPENDABLE_AGE;
        TransferDetails {
            tx_hash: shekyl_types::TxHash::from_bytes([0u8; 32]),
            internal_output_index: 0,
            global_output_index: 0,
            block_height: height,
            key: ED25519_BASEPOINT_POINT,
            key_offset: Scalar::ZERO,
            commitment: Commitment::new(Scalar::ZERO, amount),
            payment_id: None,
            spent: false,
            spent_height: None,
            key_image: None,
            awaiting_confirmation: None,
            source_ciphertext: None,
            output_handle: None,
            eligible_height: height + SPENDABLE_AGE,
            frozen: false,
            fcmp_precomputed_path: None,
            receive_attribution: shekyl_engine_state::ReceiveAttribution::default(),
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
    fn spent_excluded() {
        let mut td = make_td(1000, 50);
        td.spent = true;
        let transfers = vec![td];
        let summary = BalanceSummary::compute(&transfers, 100);
        assert_eq!(summary.total, AtomicUnits::ZERO);
    }

    #[test]
    fn awaiting_confirmation_excluded_from_unlocked() {
        let mut td = make_td(1000, 50);
        td.awaiting_confirmation = Some(shekyl_engine_state::AwaitingConfirmation {
            tx_hash: shekyl_types::TxHash::from_bytes([7u8; 32]),
            accepted_at_height: 90,
        });
        let transfers = vec![td];
        let summary = BalanceSummary::compute(&transfers, 100);
        assert_eq!(summary.total, AtomicUnits::from_raw(1000));
        assert_eq!(summary.unlocked, AtomicUnits::ZERO);
        assert_eq!(summary.awaiting_confirmation, AtomicUnits::from_raw(1000));
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
