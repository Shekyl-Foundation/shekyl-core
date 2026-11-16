// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The balance's legs, and the invariant that ties them to the classifier
//! and the journal.

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar};
use proptest::prelude::*;
use shekyl_curve_primitives::Commitment;
use shekyl_engine_state::{
    AbandonEdge, OutputState, SendDestination, SendInputRef, SendJournalBlock, SendRecipient,
    SpendHorizon, UnspendableReason,
};
use shekyl_types::{BlockCount, BlockHeight, GlobalOutputIndex, OutputIndexInTx, TxHash};
use shekyl_units::AtomicUnits;

use super::BalanceSummary;
use crate::transfer::{TransferDetails, SPENDABLE_AGE};

const TIP: u64 = 1_000;

fn td(gindex: u64, amount: u64, mined: u64) -> TransferDetails {
    TransferDetails {
        tx_hash: TxHash::from_bytes([0u8; 32]),
        internal_output_index: OutputIndexInTx::from_raw(0),
        global_output_index: GlobalOutputIndex::from_raw(gindex),
        block_height: BlockHeight::from_raw(mined),
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
        eligible_height: BlockHeight::from_raw(mined) + SPENDABLE_AGE,
        unspendable: None,
        fcmp_precomputed_path: None,
        receive_attribution: shekyl_engine_state::ReceiveAttribution::default(),
    }
}

fn at_tip() -> SpendHorizon {
    SpendHorizon::at_tip(BlockHeight::from_raw(TIP))
}

fn units(raw: u64) -> AtomicUnits {
    AtomicUnits::from_raw(raw)
}

/// Record one accepted send spending `inputs` (gindex, amount), paying
/// `paid` with `fee`; the journal derives its change.
fn send(journal: &mut SendJournalBlock, txid: u8, inputs: &[(u64, u64)], paid: u64, fee: u64) {
    journal.record_dispatched(
        [txid; 32],
        BlockHeight::from_raw(TIP - 1),
        fee,
        vec![SendRecipient {
            destination: SendDestination::Address("payee".into()),
            amount: paid,
            rid: None,
        }],
        inputs
            .iter()
            .map(|&(gindex, amount)| SendInputRef { gindex, amount })
            .collect(),
        vec![0xAA],
    );
    assert!(journal.stamp_lock_baseline(&[txid; 32], TIP - 1));
}

#[test]
fn an_empty_wallet_has_no_balance() {
    let summary = BalanceSummary::compute(&[], at_tip(), &SendJournalBlock::empty());
    assert_eq!(summary, BalanceSummary::default());
    assert_eq!(summary.balance(), AtomicUnits::ZERO);
}

/// Received money is incoming, with its wait, until the reference rule
/// admits it; then it is spendable and the wait is gone.
#[test]
fn received_money_is_incoming_until_the_rule_admits_it() {
    let old = td(1, 1_000, 10);
    let fresh = td(2, 500, TIP - 2);
    let summary = BalanceSummary::compute(&[old, fresh], at_tip(), &SendJournalBlock::empty());
    assert_eq!(summary.spendable, units(1_000));
    assert_eq!(summary.incoming, units(500));
    assert!(summary.incoming_wait.is_some_and(|w| w > BlockCount::ZERO));
    assert_eq!(summary.balance(), units(1_500));
}

/// A send in flight: its inputs leave spendable, its recipients and fee are
/// outgoing, its change is incoming with no wait (it is not on chain as
/// this wallet's output yet), and the balance drops by exactly what left.
#[test]
fn a_send_in_flight_moves_its_inputs_to_outgoing_and_change() {
    let input = td(1, 1_000, 10);
    let other = td(2, 300, 10);
    let mut journal = SendJournalBlock::empty();
    send(&mut journal, 9, &[(1, 1_000)], 600, 50);
    let summary = BalanceSummary::compute(&[input, other], at_tip(), &journal);
    assert_eq!(summary.spendable, units(300));
    assert_eq!(summary.outgoing, units(650));
    assert_eq!(summary.incoming, units(350));
    assert_eq!(
        summary.incoming_wait, None,
        "change in flight carries no wait"
    );
    assert_eq!(summary.balance(), units(1_300 - 650));
}

/// Once the scan spends the send's input it has received its change: the
/// change is a row like any other and the send adds nothing more, so it is
/// never counted twice.
#[test]
fn a_scanned_send_counts_its_change_once() {
    let mut input = td(1, 1_000, 10);
    input.spent = true;
    let change = td(3, 350, TIP - 1);
    let mut journal = SendJournalBlock::empty();
    send(&mut journal, 9, &[(1, 1_000)], 600, 50);
    let summary = BalanceSummary::compute(&[input, change], at_tip(), &journal);
    assert_eq!(summary.outgoing, AtomicUnits::ZERO);
    assert_eq!(summary.incoming, units(350));
    assert!(summary.incoming_wait.is_some());
}

/// Unspendable money is beside the balance, never in it, for every reason.
#[test]
fn unspendable_money_is_beside_the_balance() {
    for reason in [
        UnspendableReason::PqcLeafMismatch,
        UnspendableReason::PqcLeafEntryAbsent,
        UnspendableReason::MultisigEntryAbsent,
        UnspendableReason::MultisigGroupSize,
        UnspendableReason::MultisigHashesUndecryptable,
        UnspendableReason::MultisigMemberDecap,
        UnspendableReason::MultisigMemberKeyHash,
        UnspendableReason::MultisigDuplicateKeyHash,
        UnspendableReason::MultisigLeafMismatch,
    ] {
        // Total: a new reason does not compile until this test counts it.
        match reason {
            UnspendableReason::PqcLeafMismatch
            | UnspendableReason::PqcLeafEntryAbsent
            | UnspendableReason::MultisigEntryAbsent
            | UnspendableReason::MultisigGroupSize
            | UnspendableReason::MultisigHashesUndecryptable
            | UnspendableReason::MultisigMemberDecap
            | UnspendableReason::MultisigMemberKeyHash
            | UnspendableReason::MultisigDuplicateKeyHash
            | UnspendableReason::MultisigLeafMismatch => {}
        }
        let mut row = td(1, 1_000, 10);
        row.unspendable = Some(reason);
        let summary = BalanceSummary::compute(&[row], at_tip(), &SendJournalBlock::empty());
        assert_eq!(summary.unspendable, units(1_000), "{reason:?}");
        assert_eq!(summary.balance(), AtomicUnits::ZERO, "{reason:?}");
    }
}

/// One generated output: amount, mined height, and its flags.
#[derive(Clone, Debug)]
struct GenOutput {
    amount: u64,
    mined: u64,
    spent: bool,
    unspendable: bool,
}

/// One generated send: which free outputs it spends, how it pays, and
/// where its row stands.
#[derive(Clone, Debug)]
struct GenSend {
    take: Vec<prop::sample::Index>,
    paid_share: u8,
    fee: u64,
    state: u8,
    baseline: bool,
    scanned: bool,
}

fn gen_output() -> impl Strategy<Value = GenOutput> {
    (
        1u64..1_000_000,
        // Half near the tip, where outputs are incoming with different
        // waits, so the soonest wait is chosen among several.
        prop_oneof![0u64..TIP, TIP - 40..TIP],
        prop::bool::weighted(0.15),
        prop::bool::weighted(0.1),
    )
        .prop_map(|(amount, mined, spent, unspendable)| GenOutput {
            amount,
            mined,
            spent,
            unspendable,
        })
}

fn gen_send() -> impl Strategy<Value = GenSend> {
    (
        prop::collection::vec(any::<prop::sample::Index>(), 1..4),
        0u8..=100,
        0u64..500,
        0u8..5,
        any::<bool>(),
        prop::bool::weighted(0.25),
    )
        .prop_map(
            |(take, paid_share, fee, state, baseline, scanned)| GenSend {
                take,
                paid_share,
                fee,
                state,
                baseline,
                scanned,
            },
        )
}

/// Build the ledger and journal a generated wallet describes. A send
/// spends outputs no earlier send took; a scanned send has its inputs
/// spent and its change received as a fresh row.
fn build(outputs: &[GenOutput], sends: &[GenSend]) -> (Vec<TransferDetails>, SendJournalBlock) {
    let mut rows: Vec<TransferDetails> = outputs
        .iter()
        .enumerate()
        .map(|(i, g)| {
            let mut row = td(i as u64, g.amount, g.mined);
            row.spent = g.spent;
            row.unspendable = g.unspendable.then_some(UnspendableReason::PqcLeafMismatch);
            row
        })
        .collect();
    let mut journal = SendJournalBlock::empty();
    let mut free: Vec<usize> = (0..rows.len())
        .filter(|&i| !rows[i].spent && rows[i].unspendable.is_none())
        .collect();
    for (n, gen) in sends.iter().enumerate() {
        let mut inputs = Vec::new();
        for index in &gen.take {
            if free.is_empty() {
                break;
            }
            let at = index.index(free.len());
            inputs.push(free.swap_remove(at));
        }
        if inputs.is_empty() {
            continue;
        }
        let total: u64 = inputs.iter().map(|&i| rows[i].amount().to_raw()).sum();
        let fee = gen.fee.min(total);
        let paid = (total - fee) * u64::from(gen.paid_share) / 100;
        let txid = [u8::try_from(n + 1).expect("few sends"); 32];
        journal.record_dispatched(
            txid,
            BlockHeight::from_raw(TIP - 1),
            fee,
            vec![SendRecipient {
                destination: SendDestination::Address("payee".into()),
                amount: paid,
                rid: None,
            }],
            inputs
                .iter()
                .map(|&i| SendInputRef {
                    gindex: rows[i].global_output_index.to_raw(),
                    amount: rows[i].amount().to_raw(),
                })
                .collect(),
            vec![0xAA],
        );
        if gen.baseline {
            assert!(journal.stamp_lock_baseline(&txid, TIP - 1));
        }
        match gen.state {
            0 | 1 => {}
            2 => {
                let edge = journal.mark_abandoned(&txid);
                assert!(!matches!(edge, AbandonEdge::NotFound), "{edge:?}");
            }
            3 => {
                journal.mark_presumed_dead(&txid);
            }
            _ => {
                journal.mark_terminal_rejected(&txid);
            }
        }
        if gen.scanned {
            for &i in &inputs {
                rows[i].spent = true;
            }
            let change = total - paid - fee;
            if change > 0 {
                let gindex = 10_000 + n as u64;
                rows.push(td(gindex, change, TIP - 1));
            }
        }
    }
    (rows, journal)
}

proptest! {
    /// The A17 invariant over generated ledgers and journals:
    ///
    /// 1. every unspent output is in exactly one leg — the summary's legs
    ///    are the classifier's per-state sums, and the in-flight inputs'
    ///    value is exactly the unscanned in-flight sends' outgoing plus
    ///    change;
    /// 2. for every in-flight send, Σ inputs = Σ recipients + fee + change;
    /// 3. balance = spendable + incoming;
    /// 4. `incoming_wait` is the least wait among the incoming outputs on
    ///    chain, absent when there are none.
    ///
    /// The edits that make it fail: the classifier no longer consulting the
    /// locks (an in-flight input then reads spendable, and (1) breaks on
    /// the in-flight sum); the change of a scanned send still added to
    /// incoming (counted twice: (1) breaks on incoming); outgoing summed
    /// over every row rather than the in-flight ones (an abandoned or
    /// released send's money counted as leaving); the wait taken at any
    /// incoming output but the soonest ((4) breaks).
    #[test]
    fn every_unspent_output_is_in_exactly_one_leg(
        outputs in prop::collection::vec(gen_output(), 0..24),
        sends in prop::collection::vec(gen_send(), 0..5),
    ) {
        let (rows, journal) = build(&outputs, &sends);
        let horizon = at_tip();
        let locks = journal.spend_locks();
        let summary = BalanceSummary::compute(&rows, horizon, &journal);

        let mut by_state = [0u64; 4]; // spendable, incoming, in flight, unspendable
        let mut soonest: Option<BlockCount> = None;
        for row in &rows {
            let amount = row.amount().to_raw();
            match row.state(horizon, &locks) {
                OutputState::Spent => {}
                OutputState::Spendable => by_state[0] += amount,
                OutputState::Incoming => {
                    by_state[1] += amount;
                    let wait = horizon.wait(row.eligible_height);
                    soonest = Some(soonest.map_or(wait, |w| w.min(wait)));
                }
                OutputState::InFlight => by_state[2] += amount,
                OutputState::Unspendable => by_state[3] += amount,
            }
        }
        let unscanned: Vec<_> = journal
            .in_flight()
            .filter(|(_, row)| {
                row.inputs.iter().all(|input| {
                    rows.iter()
                        .any(|r| r.global_output_index.to_raw() == input.gindex && !r.spent)
                })
            })
            .collect();
        let outgoing: u64 = unscanned.iter().map(|(_, r)| r.outgoing_amount().unwrap()).sum();
        let change: u64 = unscanned.iter().map(|(_, r)| r.change_amount).sum();

        prop_assert_eq!(summary.spendable.to_raw(), by_state[0]);
        prop_assert_eq!(summary.incoming.to_raw(), by_state[1] + change);
        prop_assert_eq!(summary.unspendable.to_raw(), by_state[3]);
        prop_assert_eq!(summary.outgoing.to_raw(), outgoing);
        prop_assert_eq!(summary.incoming_wait, soonest);
        prop_assert_eq!(by_state[2], outgoing + change, "in-flight inputs = outgoing + change");

        for (_, row) in journal.in_flight() {
            let inputs: u64 = row.inputs.iter().map(|i| i.amount).sum();
            prop_assert_eq!(inputs, row.sent_amount().unwrap() + row.fee + row.change_amount);
        }

        prop_assert_eq!(
            summary.balance().to_raw(),
            summary.spendable.to_raw() + summary.incoming.to_raw()
        );
    }
}
