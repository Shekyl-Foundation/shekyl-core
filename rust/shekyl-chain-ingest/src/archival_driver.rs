// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared pins for the archival driver tests.
//!
//! The admission modules and `scenario_archival_tests` were each carrying
//! their own copy of the first spendable height and of the refusal shape.
//! One definition, typed as a [`BlockHeight`], is what both call.

use shekyl_chain_rules::{CenRow, Locus, RuleSet, TxSlot};
use shekyl_types::archival::BondRecord;
use shekyl_types::{BlockCount, BlockHeight};

use crate::scenario::{FreeHash, Mined, Scenario, StepOutcome};
use crate::scenario_archival::Persona;

/// A fixture fee large enough that a bond post's outputs balance.
pub(crate) const FEE: u64 = 1_000_000;

/// A non-zero serving endpoint. J14 refuses the all-zero one.
pub(crate) const ENDPOINT: [u8; 32] = [0xEE; 32];

/// The first height that can spend block 0's coinbase against a root that
/// holds it (`scenario_tests`: unlock window + spendable age + 1). The same
/// under every regtest rule set here: a levered schedule moves settlement,
/// not the unlock window.
pub(crate) fn first_spending_height() -> BlockHeight {
    let rules = &RuleSet::GENESIS;
    let wait = rules.mined_money_unlock_window() + rules.tx_spendable_age() + BlockCount::ONE;
    BlockHeight::ZERO
        .checked_add(wait)
        .expect("a regtest unlock window is a small span")
}

/// The bond post's vin. Every driven post spends at input 0 and posts at
/// input 1, in the listed transaction `slot`.
pub(crate) fn at_post(slot: usize) -> Locus {
    Locus::Input {
        slot: TxSlot::Listed(slot),
        input: 1,
    }
}

/// `outcome` is `row`'s refusal at `locus`. A connect, or another row, fails
/// the pin by name.
pub(crate) fn refused_at(outcome: Result<Mined, StepOutcome>, row: CenRow, locus: Locus) {
    match outcome {
        Err(StepOutcome::Refused(refused)) => {
            assert_eq!(refused.rule, row, "the row that refused: {refused}");
            assert_eq!(refused.locus, locus, "where it refused: {refused}");
        }
        Ok(block) => panic!("admitted at {}, expected {row}'s refusal", block.height),
        Err(other) => panic!("expected {row}'s refusal, got {other}"),
    }
}

/// The persona's record, which must exist.
pub(crate) async fn record_of(scenario: &Scenario<FreeHash>, persona: &Persona) -> BondRecord {
    scenario
        .bond_record(persona.id())
        .await
        .expect("the store answers")
        .expect("the persona has a record")
}
