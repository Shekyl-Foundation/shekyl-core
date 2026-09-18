// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared `connect` / `pop` test fixtures. One place with `facts` so the
//! header root a candidate carries (`root_at_height`) cannot drift from the
//! root the connect of the parent wrote.

use shekyl_chain_rules::{validate, Candidate, ChainValid, RuleSet, RuleSetId};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockWeight, CurveTreeRoot, LongTermWeight};
use shekyl_units::AtomicUnits;
use shekyl_wire::{Block, BlockHeader, Ct, CtBase, Input, Output, PqcAuth, Transaction, TxPrefix};

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

/// [`spend`] with one `pqc_auths` entry, so its txid is **4-part** and its
/// identity carries `pqc_auth_hash: Some(_)` — the shape that writes a
/// `txs_pqc_auth_hash` row (amendment A3, `PDM-Q-F26` leg 1). The auth is
/// the minimal well-formed header (`auth_version 1`, `scheme_id 1`, empty
/// blobs): no landed rule verifies it, and what the store records is its
/// count-prefixed digest, not its validity.
pub(super) fn spend_with_pqc_auth(key_image: u8, outputs: usize) -> Transaction {
    let mut tx = spend(key_image, outputs);
    let Ct::Fcmp { pqc_auths, .. } = &mut tx.ct else {
        unreachable!("spend() builds Ct::Fcmp");
    };
    pqc_auths.push(PqcAuth {
        auth_version: 1,
        scheme_id: 1,
        flags: 0,
        hybrid_public_key: Vec::new(),
        hybrid_signature: Vec::new(),
    });
    tx
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
        weight: Fact::passed_through(BlockWeight::from_raw(1_000 + height)),
        long_term_weight: Fact::passed_through(LongTermWeight::from_raw(900 + height)),
        cumulative_difficulty: Fact::passed_through(CumulativeDifficulty::from_raw(
            u128::from(height + 1) * 100,
        )),
        coins_generated: Fact::passed_through(AtomicUnits::from_raw((height + 1) * 1_000_000)),
        burned: Fact::passed_through(AtomicUnits::from_raw(burned)),
        root_after: Fact::passed_through(CurveTreeRoot::from_bytes(
            [0xc0 + u8::try_from(height).expect("small"); 32],
        )),
        // Distinct per height, so a test that reads it back can tell `h`
        // from `h ± 1` (the SCR-19 indexing rule as a test, §3.6).
        long_term_effective_median: Fact::passed_through(LongTermWeight::from_raw(
            300_000 + 7 * height,
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

/// Connect `listed` as consecutive blocks from genesis in one batch,
/// handing each `facts(h, 0)`. Returns each block's hash.
pub(super) fn connect_chain(store: &ChainStore, listed: &[Vec<Transaction>]) -> Vec<[u8; 32]> {
    connect_chain_with_burn(store, listed, 0)
}

/// [`connect_chain`] with a uniform per-block `burned` fact (pop tests
/// fold a non-zero burn so they can assert the pre-image on pop).
pub(super) fn connect_chain_with_burn(
    store: &ChainStore,
    listed: &[Vec<Transaction>],
    burned: u64,
) -> Vec<[u8; 32]> {
    let mut hashes = Vec::new();
    let mut previous = [0u8; 32];
    let mut cands = Vec::new();
    for (h, txs) in listed.iter().enumerate() {
        let cand = candidate(h as u64, previous, txs.clone());
        previous = cand.block.hash();
        hashes.push(previous);
        cands.push(cand);
    }
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        for (h, cand) in cands.into_iter().enumerate() {
            batch.connect(judge(&view, cand)?, facts(h as u64, burned), GENESIS_ID)?;
        }
        Ok(())
    });
    out.expect("chain connects");
    hashes
}

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
