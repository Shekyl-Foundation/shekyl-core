// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fixtures for the emission's view-bound rows (CEN-J23, CEN-J25, CEN-J26)
//! through [`judge_emission_claim`] on the mock: the refusals, and the
//! vacuous recording off the class. The positive witness is the driver's claim
//! (`shekyl-chain-ingest`, `scenario_emission_tests`), which this chain
//! cannot host — nothing here closes an epoch by folding.

use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::harness::fixture::{
    anchored_on, balanced_emission, chain_of, emission_vin, listed_on, point, spendable_chain,
};
use crate::harness::{assert_refused, defined, MockChain};
use crate::rule_set::{FakechainSchedule, RuleSet, SettlementEpochBlocks};
use crate::rules::tx_against::{ReferenceContext, I15};
use crate::rules::tx_emission_against::judge_emission_claim;
use crate::rules::TxContext;
use crate::verdict::{Locus, TxSlot};
use shekyl_types::archival::SigmaWorkMilli;
use shekyl_types::{BlockCount, BlockHeight, CurveTreeRoot, SettlementEpoch};
use shekyl_units::AtomicUnits;
use shekyl_wire::{Ct, Input, Transaction};

const KI: [u8; 32] = point(9);
const CLAIMED: u64 = 0;

/// A fee-bearing emission claiming `CLAIMED`, with the harness's parseable
/// vin, unanchored.
fn emission() -> Transaction {
    let Input::ArchivalRewardEmission { canonical_bytes } = emission_vin(0x23, &[CLAIMED]) else {
        unreachable!("emission_vin builds an emission input");
    };
    balanced_emission(KI, canonical_bytes, 5)
}

/// A reference context as J21 would yield it on an empty tree — enough
/// for the sequence to be asked; nothing here verifies against it.
const REFERENCE: ReferenceContext = ReferenceContext {
    ref_height: BlockHeight::ZERO,
    anchor: CurveTreeRoot::EMPTY,
    tree_depth: 0,
};

/// A short epoch, so a mock chain of a few dozen blocks has closed one:
/// twenty blocks, a cap of five inside it.
fn short_epochs() -> RuleSet {
    RuleSet::fakechain(
        None,
        FakechainSchedule::new(
            SettlementEpochBlocks::new(20).expect("non-zero"),
            BlockCount::from_raw(5),
        )
        .expect("a valid pair"),
    )
}

/// Off the `Emission` class the sequence judges nothing and records all
/// three rows vacuous — the row-was-evaluated recording `run_tx` makes.
#[test]
fn off_the_emission_class_the_rows_are_recorded_vacuous() {
    let chain = spendable_chain();
    let spend = listed_on(&chain, KI);
    chain.with_view(|view| {
        let mut coverage = RuleCoverage::EMPTY;
        let cx =
            TxContext::derive(&spend, TxSlot::Lone, &mut coverage).expect("a spend classifies");
        defined(judge_emission_claim(
            &cx,
            &view,
            &RuleSet::GENESIS,
            None,
            &mut coverage,
        ))
        .expect("a spend is not judged here");
        assert!(coverage.contains(CenRow::J23));
        assert!(coverage.contains(CenRow::J25));
        assert!(coverage.contains(CenRow::J26));
    });
}

/// J26's body, I15's verify over the fee subset, asked directly — the
/// sequence cannot reach the row on the mock (J25 refuses every claim a
/// chain that closes nothing can carry). The harness's filler proof over
/// one fee spend is refused; a subset of no spends is admitted exactly
/// when the proof is absent; a slot that names no `ToKey` is refused.
#[test]
fn i15_over_the_fee_subset_refuses_filler_and_requires_absence_over_nothing() {
    let tx = emission();
    assert!(I15::verify(&tx, &[0], &REFERENCE).is_err(), "filler proof");
    assert!(
        I15::verify(&tx, &[], &REFERENCE).is_err(),
        "a proof over no spends"
    );
    assert!(
        I15::verify(&tx, &[1], &REFERENCE).is_err(),
        "the emission slot is not a spend"
    );
    let mut absent = tx;
    if let Ct::Fcmp {
        prunable: Some(p), ..
    } = &mut absent.ct
    {
        p.fcmp_proof.clear();
    }
    assert!(
        I15::verify(&absent, &[], &REFERENCE).is_ok(),
        "nothing to prove"
    );
    assert!(
        I15::verify(&absent, &[0], &REFERENCE).is_err(),
        "a spend with no proof"
    );
}

/// J23: a claimed epoch that is not closed and settled is refused at the
/// transaction before anything is verified, whether or not the reference
/// context was yielded; neither row is recorded. Two states refuse. The
/// epoch never closed: no budget, no `Σwork`. And the epoch closed and its
/// slash pass has not run: a budget and no `Σwork`, the ordinary state for
/// one epoch after every close (`SO-D11d`: `Σwork`'s row is the citing
/// gate).
#[test]
fn j23_refuses_a_claimed_epoch_that_is_not_closed_and_settled() {
    let never_closed = spendable_chain();
    let closed_not_settled = spendable_chain().with_close(
        SettlementEpoch::from_raw(CLAIMED),
        AtomicUnits::from_raw(1_000_000),
    );
    for chain in [never_closed, closed_not_settled] {
        refuses_at_j23(&chain);
    }
}

fn refuses_at_j23(chain: &MockChain) {
    let tx = anchored_on(chain, emission());
    chain.with_view(|view| {
        for reference in [Some(&REFERENCE), None] {
            let mut coverage = RuleCoverage::EMPTY;
            let cx = TxContext::derive(&tx, TxSlot::Lone, &mut coverage)
                .expect("an emission classifies");
            assert_refused(
                defined(judge_emission_claim(
                    &cx,
                    &view,
                    &RuleSet::GENESIS,
                    reference,
                    &mut coverage,
                )),
                CenRow::J23,
                Locus::Tx { slot: TxSlot::Lone },
            );
            assert!(!coverage.contains(CenRow::J23));
            assert!(!coverage.contains(CenRow::J25));
        }
    });
}

/// J23 is the first row that reads the vin: a vin the parse refuses — J19's
/// in `tx_form` — is refused here when the sequence is asked alone.
#[test]
fn j23_refuses_a_vin_it_cannot_read_when_asked_alone() {
    let chain = spendable_chain();
    let tx = anchored_on(&chain, balanced_emission(KI, vec![0xff; 8], 5));
    chain.with_view(|view| {
        let mut coverage = RuleCoverage::EMPTY;
        let cx = TxContext::derive(&tx, TxSlot::Lone, &mut coverage)
            .expect("an emission classifies by its input kind");
        assert_refused(
            defined(judge_emission_claim(
                &cx,
                &view,
                &RuleSet::GENESIS,
                Some(&REFERENCE),
                &mut coverage,
            )),
            CenRow::J23,
            Locus::Tx { slot: TxSlot::Lone },
        );
    });
}

/// J25: over a claimed epoch J23 admits — a planted close on a chain past
/// its close height — the harness's filler claim fails the verify (no
/// record for its persona, filler backing and auths) and is refused under
/// J25 with J23 recorded; and an emission the caller reached without a
/// reference context is refused under J25 rather than verified against
/// nothing.
#[test]
fn j25_refuses_a_claim_the_verify_rejects_and_one_with_no_reference() {
    let rules = short_epochs();
    let epoch = SettlementEpoch::from_raw(CLAIMED);
    let close_height = rules
        .settlement_schedule()
        .close_height(CLAIMED)
        .expect("epoch 0 closes");
    // Past the epoch's slash pass, so the universe the gather reads is
    // recorded.
    let settled_at = rules.settlement_schedule().slash_deadline_height(CLAIMED);
    assert!(
        close_height <= settled_at,
        "an epoch settles after it closes"
    );
    let chain = chain_of(settled_at + 6)
        .with_close(epoch, AtomicUnits::from_raw(1_000_000))
        .with_gather(epoch, SigmaWorkMilli::from_raw(1_000));
    let tx = anchored_on(&chain, emission());
    chain.with_view(|view| {
        for reference in [Some(&REFERENCE), None] {
            let mut coverage = RuleCoverage::EMPTY;
            let cx = TxContext::derive(&tx, TxSlot::Lone, &mut coverage)
                .expect("an emission classifies");
            assert_refused(
                defined(judge_emission_claim(
                    &cx,
                    &view,
                    &rules,
                    reference,
                    &mut coverage,
                )),
                CenRow::J25,
                Locus::Tx { slot: TxSlot::Lone },
            );
            assert!(coverage.contains(CenRow::J23), "the gathers were admitted");
            assert!(!coverage.contains(CenRow::J25));
        }
    });
}
