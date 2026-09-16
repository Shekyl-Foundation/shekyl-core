// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use shekyl_types::{BlockHash, PrunableHash, TxHash};

use super::*;
use crate::harness::fixture::{candidate, coinbase};
use crate::harness::{infallible, MockChain};
use crate::rule_set::RuleSetId;
use crate::TxIdentity;

#[test]
fn a_well_formed_candidate_passes_and_covers_only_the_landed_rows() {
    MockChain::default().with_view(|view| {
        let input = candidate(vec![coinbase(1), coinbase(2)]);
        let valid = infallible(validate(input, &view, &RuleSet::GENESIS))
            .expect("the fixture satisfies every landed rule");
        assert_eq!(valid.rule_set_id(), RuleSetId::GENESIS);
        // Slice 1's version rows and nothing else (the per-tx entry points
        // are still empty).
        assert_eq!(valid.coverage().len(), 3);
        assert!(valid.coverage().covers_landed(&RuleSet::GENESIS));
        // Not parity evidence until every row has landed.
        assert!(!valid.coverage().is_complete_for(&RuleSet::GENESIS));
    });
}

#[test]
fn the_validated_block_is_the_candidate_with_identities_derived_once() {
    let input = candidate(vec![coinbase(1), coinbase(2)]);
    let expected_hash = BlockHash::from_bytes(input.block.hash());
    let identity = |tx: &Transaction| TxIdentity {
        hash: TxHash::from_bytes(tx.hash()),
        prunable_hash: PrunableHash::from_bytes(tx.prunable_hash()),
    };
    let expected_miner = identity(&input.block.miner_transaction);
    let expected_listed: Vec<(TxIdentity, Transaction)> = input
        .transactions
        .iter()
        .map(|tx| (identity(tx), tx.clone()))
        .collect();
    let expected_block = input.block.clone();
    // A coinbase-shaped body has an empty prunable region: its digest is
    // keccak256("") (the value the store records), never the txid's null
    // substitute — the two identities are derived by different rules and
    // must not be conflated (SCW-10).
    const KECCAK256_OF_EMPTY: [u8; 32] = [
        0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03,
        0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85,
        0xa4, 0x70,
    ];
    assert_eq!(expected_miner.prunable_hash.as_bytes(), &KECCAK256_OF_EMPTY);
    assert_ne!(expected_miner.prunable_hash.as_bytes(), &[0u8; 32]);

    MockChain::default().with_view(|view| {
        let valid = infallible(validate(input, &view, &RuleSet::GENESIS))
            .expect("the fixture satisfies every landed rule");
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
            .expect("the fixture satisfies every landed rule");
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
