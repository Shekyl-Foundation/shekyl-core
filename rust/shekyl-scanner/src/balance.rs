// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Balance computation with lock/frozen categorization.

use serde::Serialize;
use shekyl_types::BlockHeight;
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
    /// Balance in received-but-unspendable outputs
    /// (`TransferDetails::unspendable`, `PL-D3` §6.2): on chain and
    /// retained in the ledger, so counted in `total`, but never in
    /// `unlocked` — the chain leaf does not open to this wallet's
    /// derivation, so no spend can ever be proven.
    pub unspendable: AtomicUnits,
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
    ///
    /// `spend_locks` is the journal-derived awaiting-confirmation lock map
    /// (`SendJournalBlock::spend_locks`, PR-SJ-1b): a row whose
    /// `global_output_index` is locked is committed to a network-exposed
    /// spend, so it counts in `total` but never `unlocked`. Spent rows
    /// are excluded before the lock is consulted — confirmed evidence
    /// supersedes a lock, the same precedence the retired field's merge
    /// reconciler applied.
    pub fn compute(
        transfers: &[TransferDetails],
        current_height: BlockHeight,
        spend_locks: &shekyl_engine_state::InFlightSpendLocks,
    ) -> Self {
        let mut summary = BalanceSummary::default();

        for td in transfers {
            if td.spent {
                continue;
            }

            let amount = td.amount();
            summary.total = accumulate(summary.total, amount);

            if td.unspendable.is_some() {
                summary.unspendable = accumulate(summary.unspendable, amount);
                continue;
            }

            if spend_locks.contains(td.global_output_index) {
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
            internal_output_index: shekyl_types::OutputIndexInTx::from_raw(0),
            global_output_index: shekyl_types::GlobalOutputIndex::from_raw(0),
            block_height: shekyl_types::BlockHeight::from_raw(height),
            key: ED25519_BASEPOINT_POINT,
            key_offset: Scalar::ZERO,
            commitment: Commitment::new(Scalar::ZERO, amount),
            payment_id: None,
            spent: false,
            spent_height: None,
            key_image: None,
            spending_tx_hash: None,
            source_ciphertext: None,
            output_handle: None,
            eligible_height: shekyl_types::BlockHeight::from_raw(height) + SPENDABLE_AGE,
            frozen: false,
            unspendable: None,
            fcmp_precomputed_path: None,
            receive_attribution: shekyl_engine_state::ReceiveAttribution::default(),
        }
    }

    /// A journal with one in-flight send carrying `gindex`, derived into
    /// the lock set the consumer sees. Building the *journal* rather than
    /// the map is the point: `InFlightSpendLocks` has one constructor, so a test
    /// fixture and production read the same derivation rule.
    fn locks_over(gindex: u64, txid: [u8; 32]) -> shekyl_engine_state::InFlightSpendLocks {
        use shekyl_engine_state::{SendInputRef, SendJournalBlock};

        let mut journal = SendJournalBlock::empty();
        journal.record_dispatched(
            txid,
            BlockHeight::from_raw(90),
            0,
            Vec::new(),
            vec![SendInputRef { gindex, amount: 0 }],
        );
        assert!(journal.stamp_lock_baseline(&txid, 90));
        journal.spend_locks()
    }

    /// No live sends: an empty journal derives an empty lock set.
    /// Spelled through the derivation because `InFlightSpendLocks` has no other
    /// constructor — see its type docs for why.
    fn no_locks() -> shekyl_engine_state::InFlightSpendLocks {
        shekyl_engine_state::SendJournalBlock::empty().spend_locks()
    }

    #[test]
    fn empty_balance() {
        let summary = BalanceSummary::compute(&[], BlockHeight::from_raw(100), &no_locks());
        assert_eq!(summary.total, AtomicUnits::ZERO);
        assert_eq!(summary.unlocked, AtomicUnits::ZERO);
    }

    #[test]
    fn basic_unlocked_balance() {
        let transfers = vec![make_td(1000, 50), make_td(2000, 60)];
        let summary = BalanceSummary::compute(&transfers, BlockHeight::from_raw(100), &no_locks());
        assert_eq!(summary.total, AtomicUnits::from_raw(3000));
        assert_eq!(summary.unlocked, AtomicUnits::from_raw(3000));
    }

    #[test]
    fn timelocked_outputs() {
        let transfers = vec![make_td(1000, 95)];
        let summary = BalanceSummary::compute(&transfers, BlockHeight::from_raw(100), &no_locks());
        assert_eq!(summary.total, AtomicUnits::from_raw(1000));
        assert_eq!(summary.unlocked, AtomicUnits::ZERO);
        assert_eq!(summary.locked_by_timelock, AtomicUnits::from_raw(1000));
    }

    #[test]
    fn spent_excluded() {
        let mut td = make_td(1000, 50);
        td.spent = true;
        let transfers = vec![td];
        let summary = BalanceSummary::compute(&transfers, BlockHeight::from_raw(100), &no_locks());
        assert_eq!(summary.total, AtomicUnits::ZERO);
    }

    /// A journal-locked output (PR-SJ-1b: lock derived from the send
    /// journal, keyed by gindex) counts in `total` but never `unlocked`.
    #[test]
    fn awaiting_confirmation_excluded_from_unlocked() {
        let mut td = make_td(1000, 50);
        td.global_output_index = shekyl_types::GlobalOutputIndex::from_raw(77);
        let locks = locks_over(77, [7u8; 32]);
        let transfers = vec![td];
        let summary = BalanceSummary::compute(&transfers, BlockHeight::from_raw(100), &locks);
        assert_eq!(summary.total, AtomicUnits::from_raw(1000));
        assert_eq!(summary.unlocked, AtomicUnits::ZERO);
        assert_eq!(summary.awaiting_confirmation, AtomicUnits::from_raw(1000));
    }

    /// A spent row never lands in the awaiting bucket even when the
    /// journal still carries its gindex — confirmed evidence supersedes
    /// the lock (the reconciler precedence, now consumer-side).
    #[test]
    fn spent_row_supersedes_its_journal_lock() {
        let mut td = make_td(1000, 50);
        td.global_output_index = shekyl_types::GlobalOutputIndex::from_raw(78);
        td.spent = true;
        let locks = locks_over(78, [8u8; 32]);
        let summary = BalanceSummary::compute(&[td], BlockHeight::from_raw(100), &locks);
        assert_eq!(summary.total, AtomicUnits::ZERO);
        assert_eq!(summary.awaiting_confirmation, AtomicUnits::ZERO);
    }

    #[test]
    fn frozen_excluded_from_unlocked() {
        let mut td = make_td(1000, 50);
        td.frozen = true;
        let transfers = vec![td];
        let summary = BalanceSummary::compute(&transfers, BlockHeight::from_raw(100), &no_locks());
        assert_eq!(summary.total, AtomicUnits::from_raw(1000));
        assert_eq!(summary.unlocked, AtomicUnits::ZERO);
        assert_eq!(summary.frozen, AtomicUnits::from_raw(1000));
    }

    /// A received-but-unspendable output (`PL-D3` §6.2) is retained — it is
    /// on chain, so `total` counts it — but never spendable, in either
    /// reason.
    #[test]
    fn unspendable_counted_in_total_never_in_unlocked() {
        use shekyl_engine_state::UnspendableReason;
        for reason in [
            UnspendableReason::PqcLeafMismatch,
            UnspendableReason::PqcLeafEntryAbsent,
        ] {
            let mut td = make_td(1000, 50);
            td.unspendable = Some(reason);
            let transfers = vec![td];
            let summary =
                BalanceSummary::compute(&transfers, BlockHeight::from_raw(100), &no_locks());
            assert_eq!(summary.total, AtomicUnits::from_raw(1000), "{reason:?}");
            assert_eq!(summary.unlocked, AtomicUnits::ZERO, "{reason:?}");
            assert_eq!(
                summary.unspendable,
                AtomicUnits::from_raw(1000),
                "{reason:?}"
            );
            assert_eq!(summary.frozen, AtomicUnits::ZERO, "{reason:?}");
            assert_eq!(summary.locked_by_timelock, AtomicUnits::ZERO, "{reason:?}");
        }
    }
}
