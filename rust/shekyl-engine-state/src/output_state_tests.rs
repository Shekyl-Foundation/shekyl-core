// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The classifier, directly: a pure function of the row, the locks and the
//! horizon.

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar};
use shekyl_curve_primitives::Commitment;
use shekyl_types::{BlockCount, BlockHeight, GlobalOutputIndex, OutputIndexInTx, TxHash};

use super::{OutputState, SpendHorizon};
use crate::send_journal_block::{InFlightSpendLocks, SendInputRef, SendJournalBlock};
use crate::transfer::{TransferDetails, UnspendableReason};

fn row(gindex: u64, eligible: u64) -> TransferDetails {
    TransferDetails {
        tx_hash: TxHash::from_bytes([1; 32]),
        internal_output_index: OutputIndexInTx::from_raw(0),
        global_output_index: GlobalOutputIndex::from_raw(gindex),
        block_height: BlockHeight::from_raw(eligible.saturating_sub(10)),
        key: ED25519_BASEPOINT_POINT,
        key_offset: Scalar::ZERO,
        commitment: Commitment::new(Scalar::ZERO, 1_000),
        payment_id: None,
        spent: false,
        spent_height: None,
        key_image: None,
        spending_tx_hash: None,
        source_ciphertext: None,
        output_handle: None,
        eligible_height: BlockHeight::from_raw(eligible),
        unspendable: None,
        fcmp_precomputed_path: None,
        receive_attribution: crate::ReceiveAttribution::default(),
    }
}

/// The lock set of one accepted in-flight send carrying `gindex`.
fn locked(gindex: u64) -> InFlightSpendLocks {
    let mut journal = SendJournalBlock::empty();
    journal.record_dispatched(
        [7; 32],
        BlockHeight::from_raw(90),
        0,
        Vec::new(),
        vec![SendInputRef {
            gindex,
            amount: 1_000,
        }],
        vec![0xAA],
    );
    assert!(journal.stamp_lock_baseline(&[7; 32], 90));
    journal.spend_locks()
}

fn none() -> InFlightSpendLocks {
    SendJournalBlock::empty().spend_locks()
}

/// [`SpendHorizon::wait`] counts down one block per tip block and reaches
/// zero exactly at the first tip whose state is `Spendable`. That tip is
/// where a build first selects the output: the balance and the send path
/// decide by the same predicate. Bites if the balance's rule drifts from
/// the reference rule (the pre-A17 `tip >= eligible` read spendable 7
/// blocks early here).
#[test]
fn the_wait_counts_down_to_the_tip_that_spends() {
    let eligible = 120;
    let td = row(5, eligible);
    let mut spendable_at = None;
    let mut last_wait = None;
    for tip in 0..200u64 {
        let horizon = SpendHorizon::at_tip(BlockHeight::from_raw(tip));
        match td.state(horizon, &none()) {
            OutputState::Incoming => {
                let wait = horizon.wait(td.eligible_height);
                assert!(spendable_at.is_none(), "incoming again at {tip}");
                if let Some(prev) = last_wait {
                    assert_eq!(wait, prev - BlockCount::ONE, "tip {tip}");
                }
                last_wait = Some(wait);
            }
            OutputState::Spendable => {
                if spendable_at.is_none() {
                    assert_eq!(last_wait, Some(BlockCount::ONE), "one block before, wait 1");
                    assert_eq!(horizon.wait(td.eligible_height), BlockCount::ZERO);
                    spendable_at = Some(tip);
                }
            }
            other => panic!("tip {tip}: {other:?}"),
        }
    }
    let first = spendable_at.expect("spendable at some tip");
    assert!(first > eligible, "never at the eligible height itself");
    assert!(SpendHorizon::at_tip(BlockHeight::from_raw(first)).holds(td.eligible_height));
}

/// Below the anchoring floor no reference exists: every unspent, unlocked
/// output is incoming, with the wait counted through the first
/// reference.
#[test]
fn below_the_anchoring_floor_nothing_is_spendable() {
    let td = row(5, 1);
    let at = SpendHorizon::at_tip(BlockHeight::ZERO);
    assert_eq!(at.reference(), None);
    assert_eq!(td.state(at, &none()), OutputState::Incoming);
    assert!(at.wait(td.eligible_height) > BlockCount::ZERO);
}

/// The precedence: spent, unspendable, in flight, incoming, spendable.
/// Each flag outranks every flag below it, so a locked output that is
/// immature is in flight.
#[test]
fn each_state_outranks_the_ones_below_it() {
    let at = SpendHorizon::at_tip(BlockHeight::from_raw(500));
    let immature = 499;

    let mut td = row(5, immature);
    assert!(matches!(td.state(at, &none()), OutputState::Incoming));
    assert_eq!(td.state(at, &locked(5)), OutputState::InFlight);
    td.unspendable = Some(UnspendableReason::PqcLeafMismatch);
    assert_eq!(td.state(at, &locked(5)), OutputState::Unspendable);
    td.spent = true;
    assert_eq!(td.state(at, &locked(5)), OutputState::Spent);

    let mature = row(6, 100);
    assert_eq!(mature.state(at, &none()), OutputState::Spendable);
    assert!(mature.is_spendable(at, &none()));
    assert_eq!(mature.state(at, &locked(6)), OutputState::InFlight);
    assert!(!mature.is_spendable(at, &locked(6)));
    assert_eq!(mature.state(at, &locked(7)), OutputState::Spendable);
}
