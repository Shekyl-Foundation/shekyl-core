// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use shekyl_types::{BlockHash, TxHash};

use super::*;
use crate::harness::fixture::{candidate, coinbase};
use crate::harness::{infallible, MockChain};
use crate::rule_set::RuleSetId;

#[test]
fn with_zero_rules_every_candidate_passes_with_empty_coverage() {
    MockChain::default().with_view(|view| {
        let input = candidate(vec![coinbase(1), coinbase(2)]);
        let valid = infallible(validate(input, &view, &RuleSet::GENESIS))
            .expect("zero rules refuse nothing");
        assert_eq!(valid.rule_set_id(), RuleSetId::GENESIS);
        assert!(valid.coverage().is_empty());
        // The scaffold verdict is not parity evidence.
        assert!(!valid.coverage().is_complete_for(&RuleSet::GENESIS));
    });
}

#[test]
fn the_validated_block_is_the_candidate_with_identities_derived_once() {
    let input = candidate(vec![coinbase(1), coinbase(2)]);
    let expected_hash = BlockHash::from_bytes(input.block.hash());
    let expected_miner = TxHash::from_bytes(input.block.miner_transaction.hash());
    let expected_listed: Vec<(TxHash, Transaction)> = input
        .transactions
        .iter()
        .map(|tx| (TxHash::from_bytes(tx.hash()), tx.clone()))
        .collect();
    let expected_block = input.block.clone();

    MockChain::default().with_view(|view| {
        let valid = infallible(validate(input, &view, &RuleSet::GENESIS))
            .expect("zero rules refuse nothing");
        let block = valid.block();
        assert_eq!(block.hash(), expected_hash);
        assert_eq!(block.block(), &expected_block);
        assert_eq!(block.header(), &expected_block.header);
        assert_eq!(
            block.miner_tx(),
            (expected_miner, &expected_block.miner_transaction)
        );
        assert_eq!(block.transactions(), expected_listed.as_slice());
    });
}

#[test]
fn a_block_with_no_listed_transactions_passes() {
    MockChain::default().with_view(|view| {
        let valid = infallible(validate(candidate(Vec::new()), &view, &RuleSet::GENESIS))
            .expect("zero rules refuse nothing");
        assert!(valid.block().transactions().is_empty());
    });
}

#[test]
fn tx_entry_points_pass_with_empty_coverage() {
    let tx = coinbase(1);
    assert_eq!(tx_form(&tx, &RuleSet::GENESIS), Ok(RuleCoverage::EMPTY));
    MockChain::default().with_view(|view| {
        assert_eq!(
            tx_against(&tx, &view, &RuleSet::GENESIS),
            Ok(Ok(RuleCoverage::EMPTY))
        );
    });
}
