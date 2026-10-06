// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The persona's pending records, offered to the curve tree before the
//! block that carries them folds (`CT6_PROVING_STATE.md` §11.13).
//!
//! These passes sit beside the registration harness in [`super`] so
//! `ownership.rs` stays the production module plus that harness.

use super::expected_outputs_of;
use super::tests::{
    engine_at_genesis, nothing_new, probe, scan_result_with, CHAIN, OTHER_CHAIN, PER_BLOCK,
    SEED_MULT,
};
use crate::engine::test_support::{
    non_staker_engine, seeded_commitment, seeded_output_key, seeded_tx_leaves,
};
use crate::engine::{Engine, SoloSigner};
use crate::scan::ScanResult;

/// A transaction the persona built: `n` outputs with seeded keys and a
/// conforming extra, so it parses whole, hashes, and yields leaves.
fn persona_tx(seed: u64, n: usize) -> shekyl_wire::Transaction {
    use shekyl_wire::{Ct, CtBase, Input, Output, Transaction, TxPrefix};

    let outputs = (0..n)
        .map(|i| {
            let vout = u64::try_from(i).expect("a vout fits u64");
            Output {
                amount: 0,
                key: seeded_output_key(OTHER_CHAIN, seed, vout),
                view_tag: 0,
            }
        })
        .collect();
    Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![Input::Gen(seed)],
            outputs,
            extra: crate::engine::test_support::conforming_pqc_extra(n),
        },
        ct: Ct::Null(CtBase {
            enc_amounts: vec![[0u8; 9]; n],
            enc_labels: vec![[0u8; 9]; n],
            commitments: (0..n)
                .map(|i| {
                    let vout = u64::try_from(i).expect("a vout fits u64");
                    seeded_commitment(OTHER_CHAIN, seed, vout)
                })
                .collect(),
        }),
    }
}

const PERSONA: shekyl_types::PCanonicalId = shekyl_types::PCanonicalId::from_bytes([0xaa; 32]);

/// The engine behind the lock the pending seal's one write path takes.
type SharedEngine = std::sync::Arc<tokio::sync::RwLock<Engine<SoloSigner>>>;

/// Run `f` over the pending seal through its one write path (WI-3
/// gate 11), under the engine's own pending-post gate.
async fn mutate_pending<R>(
    engine: &SharedEngine,
    f: impl FnOnce(&mut shekyl_engine_state::pending_post_block::PendingPostBlock) -> (bool, R),
) -> R {
    let gate = engine.read().await.pending_gate.clone();
    crate::engine::pscan::start::pending_post_store_for_engine(std::sync::Arc::clone(engine), gate)
        .mutate(f)
        .await
        .expect("the pending seal writes")
}

/// Seal `tx` as the persona's one pending drain, through the seal's
/// one write path, as the dispatch seam does before the first send.
async fn seal_pending_drain(engine: &SharedEngine, tx: &shekyl_wire::Transaction) {
    use shekyl_engine_state::pending_post_block::{PendingDrain, PendingPostState, SealAdmission};

    let tx_bytes = crate::engine::test_support::whole_tx_wire_bytes(tx);
    mutate_pending(engine, |block| {
        let admission = block.seal_drain(
            PendingDrain {
                persona: PERSONA,
                tx_bytes,
                funding_gindexes: vec![shekyl_types::GlobalOutputIndex::from_raw(1)],
                state: PendingPostState::Pending,
            },
            shekyl_types::ChainCount::from_raw(1),
            block.generation(),
        );
        assert!(matches!(admission, SealAdmission::Admit), "{admission:?}");
        (true, ())
    })
    .await;
}

/// The block at height 1 carrying `tx`, as the scan would hand it to
/// the ingest: leaves decoded from the transaction itself, with its hash.
fn block_one_carrying(tx: &shekyl_wire::Transaction) -> Vec<crate::scan::OwnedTxLeaves> {
    let mut scannable = crate::engine::test_support::make_synthetic_block(
        1,
        shekyl_types::BlockHash::from_bytes([0x01; 32]),
    );
    scannable.block.transaction_hashes.push(tx.hash());
    scannable.transactions.push(tx.clone());
    crate::engine::curve_tree_decode::decode_block_leaves(&scannable).expect("the block decodes")
}

/// A scan result over `1..END` whose block 1 carries `tx` and whose other
/// blocks are empty. The shadow tree and its header roots are
/// [`super::scan_result_with`]'s: ingested through the tip, then read.
async fn result_carrying(tx: &shekyl_wire::Transaction) -> ScanResult {
    let block_one = std::sync::Arc::new(block_one_carrying(tx));
    scan_result_with(
        |height| {
            if height == 1 {
                std::sync::Arc::clone(&block_one)
            } else {
                seeded_tx_leaves(CHAIN, height, 0)
            }
        },
        Vec::new(),
    )
    .await
}

/// The outputs of a transaction the persona built are registered as
/// the block carrying it folds — named ahead by `(tx_hash, vout)` from
/// the sealed pending record, confirmed by key at ingest — so by the
/// time the leaf drains it is held and nothing is owed.
///
/// The probe right after the ingest is the discriminator: registered at
/// ingest, the pair is `AlreadyHeld`; registered by nobody, the probe
/// is its first registration and reads `after_drain == 1`.
#[tokio::test(flavor = "multi_thread")]
async fn a_pending_transactions_outputs_are_registered_as_its_block_folds() {
    let (_tmp, engine) = engine_at_genesis(SEED_MULT.wrapping_add(7)).await;
    let tx = persona_tx(900, 3);
    let shared: SharedEngine = std::sync::Arc::new(tokio::sync::RwLock::new(engine));
    seal_pending_drain(&shared, &tx).await;
    let engine = shared.read().await;

    let mut result = result_carrying(&tx).await;
    let set = engine.owned_outputs(&result);
    assert_eq!(
        set.expected,
        expected_outputs_of(&crate::engine::test_support::whole_tx_wire_bytes(&tx)),
        "every output of the sealed transaction, by hash and position"
    );
    assert_eq!(set.expected.len(), 3);
    assert!(!set.persona_seal_unreadable);

    engine
        .ingest_scan_result_into_curve_tree(&mut result)
        .await
        .expect("the scan result ingests");

    // The miner transaction of block 1 has no outputs, so the persona's
    // transaction takes the gindexes after the genesis chunk.
    for (vout, expected) in set.expected.iter().enumerate() {
        let index = u64::try_from(vout).expect("a vout fits u64");
        let pair = (
            shekyl_curve_tree::Gindex::from_raw(PER_BLOCK + index),
            expected.output_key,
        );
        let at_spend = probe(&engine, pair).await;
        assert_eq!(
            at_spend.already_held, 1,
            "vout {vout}: held since its block folded"
        );
        assert_eq!(at_spend.reconciliation, None, "vout {vout}: nothing owed");
    }
}

/// The expectation lives as long as its record: retired, it is gone
/// from the next offer, and the output is the scan seal's to name.
#[tokio::test(flavor = "multi_thread")]
async fn a_retired_pending_record_withdraws_its_expectations() {
    let (_tmp, engine) = non_staker_engine(SEED_MULT.wrapping_add(8));
    let tx = persona_tx(901, 2);
    let shared: SharedEngine = std::sync::Arc::new(tokio::sync::RwLock::new(engine));
    seal_pending_drain(&shared, &tx).await;
    assert_eq!(
        shared
            .read()
            .await
            .owned_outputs(&nothing_new())
            .expected
            .len(),
        2
    );

    mutate_pending(&shared, |block| {
        (block.remove_drain(&PERSONA).is_some(), ())
    })
    .await;

    let engine = shared.read().await;
    let set = engine.owned_outputs(&nothing_new());
    assert!(set.expected.is_empty());
    assert!(!set.persona_seal_unreadable);
}

/// A pending record whose bytes do not parse costs its expectations
/// and nothing else: the bytes were this wallet's own assembly, so that
/// is a defect to log, and the seal itself is readable.
#[test]
fn unparseable_pending_bytes_expect_nothing() {
    assert!(expected_outputs_of(&[0xff; 7]).is_empty());
    let mut trailing = crate::engine::test_support::whole_tx_wire_bytes(&persona_tx(902, 1));
    trailing.push(0);
    assert!(expected_outputs_of(&trailing).is_empty());
}
