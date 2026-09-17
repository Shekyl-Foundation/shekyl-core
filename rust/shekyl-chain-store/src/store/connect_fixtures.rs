// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared `connect` / `pop` test fixtures. One place with `facts` so the
//! header root a candidate carries (`root_at_height`) cannot drift from the
//! root the connect of the parent wrote.

use shekyl_chain_rules::{validate, Candidate, ChainValid, RuleSet, RuleSetId};
use shekyl_types::CurveTreeRoot;
use shekyl_wire::{Block, BlockHeader, Ct, CtBase, Input, Output, Transaction, TxPrefix};

use super::store_tests::TestErr;
use super::view::BatchView;
use super::*;

pub(super) fn coinbase(height: u64, outputs: usize) -> Transaction {
    Transaction {
        prefix: TxPrefix {
            unlock_time: height + 60,
            inputs: vec![Input::Gen(height)],
            outputs: (0..outputs)
                .map(|i| Output {
                    amount: 0,
                    key: [0x40 + u8::try_from(i).expect("small"); 32],
                    view_tag: 1,
                })
                .collect(),
            extra: Vec::new(),
        },
        ct: Ct::Null(CtBase {
            enc_amounts: vec![[0x55; 9]; outputs],
            enc_labels: vec![[0x66; 9]; outputs],
            commitments: (0..outputs)
                .map(|i| [0x70 + u8::try_from(i).expect("small"); 32])
                .collect(),
        }),
    }
}

/// A spend-shaped listed transaction in the storage-pruned form (no
/// prunable, no pqc_auths): one key image in, `outputs` outputs. No landed
/// rule reads a transaction yet (4.H/4.I are later slices), so it is
/// admitted; what it exercises is the write set, not consensus.
pub(super) fn spend(key_image: u8, outputs: usize) -> Transaction {
    Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![Input::ToKey {
                amount: 0,
                key_offsets: Vec::new(),
                key_image: [key_image; 32],
            }],
            outputs: (0..outputs)
                .map(|i| Output {
                    amount: 0,
                    key: [0x80 + u8::try_from(i).expect("small"); 32],
                    view_tag: 2,
                })
                .collect(),
            extra: Vec::new(),
        },
        ct: Ct::Fcmp {
            fee: 7,
            reference_block: [0x99; 32],
            base: CtBase {
                enc_amounts: vec![[0x11; 9]; outputs],
                enc_labels: vec![[0x22; 9]; outputs],
                commitments: (0..outputs)
                    .map(|i| [0xa0 + u8::try_from(i).expect("small"); 32])
                    .collect(),
            },
            pqc_auths: Vec::new(),
            prunable: None,
        },
    }
}

/// The root the header at `height` must carry under CEN-B5: the tree state
/// *at* `height` — the `root_after` the connect of `height − 1` wrote
/// (`facts(height − 1)`), or the empty tree at genesis. Kept in one place
/// with `facts` so the two cannot drift.
pub(super) fn root_at_height(height: u64) -> CurveTreeRoot {
    match height.checked_sub(1) {
        None => CurveTreeRoot::EMPTY,
        Some(parent) => facts(parent, 0).root_after.value,
    }
}

pub(super) fn candidate(height: u64, previous: [u8; 32], listed: Vec<Transaction>) -> Candidate {
    let block = Block {
        header: BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: 1_000 + height * 60,
            previous,
            nonce: 7,
            curve_tree_root: root_at_height(height).to_bytes(),
            attestation_root: [0x33; 32],
        },
        miner_transaction: coinbase(height, 1),
        transaction_hashes: listed.iter().map(Transaction::hash).collect(),
    };
    Candidate::new(block, listed)
}

pub(super) fn facts(height: u64, burned: u64) -> ConnectFacts {
    ConnectFacts {
        weight: Fact::passed_through(1_000 + height),
        long_term_weight: Fact::passed_through(900 + height),
        cumulative_difficulty: Fact::passed_through(u128::from(height + 1) * 100),
        coins_generated: Fact::passed_through((height + 1) * 1_000_000),
        burned: Fact::passed_through(burned),
        root_after: Fact::passed_through(CurveTreeRoot::from_bytes(
            [0xc0 + u8::try_from(height).expect("small"); 32],
        )),
    }
}

pub(super) fn judge<'b, 'id>(
    view: &BatchView<'b, 'id>,
    candidate: Candidate,
) -> Result<ChainValid<'id, BatchView<'b, 'id>>, StoreError> {
    Ok(validate(candidate, view, &RuleSet::GENESIS)?
        .expect("the fixtures satisfy every landed rule"))
}

pub(super) const GENESIS_ID: RuleSetId = RuleSetId::GENESIS;

pub(super) fn connect_genesis(store: &ChainStore, burned: u64) -> (Connected, Block) {
    let cand = candidate(0, [0; 32], Vec::new());
    let block = cand.block.clone();
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let valid = judge(&view, cand)?;
        Ok(batch.connect(valid, facts(0, burned), GENESIS_ID)?)
    });
    (out.expect("genesis connects"), block)
}
