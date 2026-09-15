// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use core::convert::Infallible;

use shekyl_types::{BlockHash, BlockHeight, CurveTreeRoot, KeyImage, TxHash};
use shekyl_wire::{Block, BlockHeader, Ct, CtBase, Transaction, TxPrefix};

use super::*;
use crate::rule_set::RuleSetId;
use crate::view::{AtHeight, RecordedBlock};

/// A view of nothing: no key images, no blocks, every height above the tip.
/// Enough for a pipeline with zero rules; the harness replaces it.
struct Bare;

impl ChainView<'static> for Bare {
    type Fault = Infallible;

    fn has_key_image(&self, _: &KeyImage) -> Result<bool, Infallible> {
        Ok(false)
    }

    fn block_at(&self, _: BlockHeight) -> Result<AtHeight<RecordedBlock>, Infallible> {
        Ok(AtHeight::AboveTip)
    }

    fn root_at(&self, _: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, Infallible> {
        Ok(AtHeight::AboveTip)
    }
}

/// A coinbase-shaped transaction distinguished only by `unlock_time`.
fn coinbase(unlock_time: u64) -> Transaction {
    Transaction {
        prefix: TxPrefix {
            unlock_time,
            inputs: Vec::new(),
            outputs: Vec::new(),
            extra: Vec::new(),
        },
        ct: Ct::Null(CtBase {
            enc_amounts: Vec::new(),
            enc_labels: Vec::new(),
            commitments: Vec::new(),
        }),
    }
}

/// A candidate whose header lists exactly the bodies it carries.
fn candidate(listed: Vec<Transaction>) -> Candidate {
    let block = Block {
        header: BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: 1_700_000_000,
            previous: [0x11; 32],
            nonce: 7,
            curve_tree_root: [0x22; 32],
            attestation_root: [0x33; 32],
        },
        miner_transaction: coinbase(60),
        transaction_hashes: listed.iter().map(Transaction::hash).collect(),
    };
    Candidate {
        block,
        transactions: listed,
    }
}

#[test]
fn with_zero_rules_every_candidate_passes_with_empty_coverage() {
    let input = candidate(vec![coinbase(1), coinbase(2)]);
    let valid = validate(input, &Bare, &RuleSet::GENESIS)
        .expect("Infallible view")
        .expect("zero rules refuse nothing");
    assert_eq!(valid.rule_set_id(), RuleSetId::GENESIS);
    assert!(valid.coverage().is_empty());
    // The scaffold verdict is not parity evidence.
    assert!(!valid.coverage().is_complete_for(&RuleSet::GENESIS));
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

    let valid = validate(input, &Bare, &RuleSet::GENESIS)
        .expect("Infallible view")
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
}

#[test]
fn a_block_with_no_listed_transactions_passes() {
    let valid = validate(candidate(Vec::new()), &Bare, &RuleSet::GENESIS)
        .expect("Infallible view")
        .expect("zero rules refuse nothing");
    assert!(valid.block().transactions().is_empty());
}

#[test]
fn tx_entry_points_pass_with_empty_coverage() {
    let tx = coinbase(1);
    assert_eq!(tx_form(&tx, &RuleSet::GENESIS), Ok(RuleCoverage::EMPTY));
    assert_eq!(
        tx_against(&tx, &Bare, &RuleSet::GENESIS),
        Ok(Ok(RuleCoverage::EMPTY))
    );
}
