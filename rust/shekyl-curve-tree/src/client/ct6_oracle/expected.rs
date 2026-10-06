// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Registration at ingest, from what the wallet expects (`CT-6` §11.13).
//!
//! A wallet that built a transaction knows each output's key before the
//! chain carries it; what it does not know is the gindex, which exists only
//! once the block is ingested. These passes grade the one place both are
//! known — [`CurveTreeClient::ingest_block`] — and the rule that the match
//! is by transaction and position with the key as confirmation, never by
//! key alone.

use super::super::ExpectedOutput;
use super::super::{BlockLeaves, TxLeafInputs};
use crate::types::{CommitmentBytes, Gindex, OneTimePubkey, TargetKind};
use crate::RawOutput;
use crate::{BlockHeight, ClientError, CurveTreeClient};
use shekyl_fcmp::tree::key_image_generator;
use shekyl_types::TxHash;

/// Outputs per transaction in these fixtures: one full leaf chunk, so a
/// chunk closes with each one.
const PER_TX: u64 = 38;

/// A valid, byte-distinct point per seed.
fn point(seed: u64) -> [u8; 32] {
    let mut preimage = [0u8; 32];
    preimage[..8].copy_from_slice(&seed.to_le_bytes());
    key_image_generator(&preimage)
}

/// One transaction of `PER_TX` outputs whose keys are `point(seed_base + i)`.
fn outputs(seed_base: u64) -> Vec<RawOutput> {
    (0..PER_TX)
        .map(|i| RawOutput {
            output_key: OneTimePubkey::from_bytes(point(seed_base + i)),
            commitment: Some(CommitmentBytes::from_bytes(point(
                1_000_000 + seed_base + i,
            ))),
            target: TargetKind::TaggedKey,
        })
        .collect()
}

/// The `0x07` blob for `n` outputs of the transaction seeded at `seed_base`.
fn blob(seed_base: u64, n: usize) -> Vec<u8> {
    (0..n)
        .flat_map(|i| {
            let mut entry = [0x07u8; 64];
            entry[..32].copy_from_slice(&point(2_000_000 + seed_base + i as u64));
            entry
        })
        .collect()
}

/// A transaction for a block: its hash as the feed would label it, and the
/// seed its outputs are drawn from.
struct Tx {
    hash: Option<TxHash>,
    seed_base: u64,
}

fn hash(n: u8) -> TxHash {
    TxHash::from_bytes([n; 32])
}

/// Ingest one block at `height` carrying `txs`: the first is the coinbase,
/// the rest are ordinary transactions (which drain after the short lock).
fn ingest(client: &mut CurveTreeClient, height: u64, txs: &[Tx]) -> Result<(), ClientError> {
    let outs: Vec<Vec<RawOutput>> = txs.iter().map(|t| outputs(t.seed_base)).collect();
    let blobs: Vec<Vec<u8>> = txs
        .iter()
        .map(|t| blob(t.seed_base, PER_TX as usize))
        .collect();
    let inputs: Vec<TxLeafInputs<'_>> = txs
        .iter()
        .enumerate()
        .map(|(i, t)| TxLeafInputs {
            is_miner: i == 0,
            tx_hash: t.hash,
            leaf_entry_blob: Some(&blobs[i]),
            outputs: &outs[i],
        })
        .collect();
    client.ingest_block(BlockLeaves {
        height: BlockHeight::from_raw(height),
        txs: &inputs,
    })
}

/// Ingest `from..=to` as empty blocks.
fn ingest_empty(client: &mut CurveTreeClient, from: u64, to: u64) {
    for height in from..=to {
        ingest(client, height, &[]).expect("an empty block ingests");
    }
}

/// The wallet's transaction in these passes: hash `0x11`, outputs seeded
/// at 500, expected at `vout` 3.
const OURS: u8 = 0x11;
const OURS_SEED: u64 = 500;
const OURS_VOUT: u64 = 3;

fn ours() -> Tx {
    Tx {
        hash: Some(hash(OURS)),
        seed_base: OURS_SEED,
    }
}

fn coinbase(seed_base: u64) -> Tx {
    Tx {
        hash: Some(hash(u8::try_from(seed_base % 200).expect("small"))),
        seed_base,
    }
}

fn expectation() -> ExpectedOutput {
    ExpectedOutput {
        tx_hash: hash(OURS),
        vout: OURS_VOUT,
        output_key: OneTimePubkey::from_bytes(point(OURS_SEED + OURS_VOUT)),
    }
}

/// A client with the genesis coinbase in and the expectation set.
fn expecting() -> CurveTreeClient {
    let mut client = CurveTreeClient::new();
    ingest(&mut client, 0, &[coinbase(1)]).expect("genesis ingests");
    client
        .set_expected_outputs(&[expectation()])
        .expect("expectations set");
    client
}

/// The gindex the *next* block's second transaction will give its `vout`:
/// the client's running count, past the coinbase. Read before the block is
/// ingested.
fn next_second_tx_gindex(client: &CurveTreeClient, vout: u64) -> Gindex {
    Gindex::from_raw(client.next_gindex + PER_TX + vout)
}

/// The expected output is registered the moment its transaction is
/// ingested — before its leaf drains — and nothing is owed afterwards: the
/// chunk that closes over it is captured by the fold, and the sync a spend
/// makes finds it held with no reconciliation.
#[test]
fn an_expected_output_is_registered_when_its_transaction_is_ingested() {
    let mut client = expecting();
    let pair = (
        next_second_tx_gindex(&client, OURS_VOUT),
        expectation().output_key,
    );
    assert!(
        !client.owned_outputs.contains_key(&pair.0),
        "nothing is registered before the transaction arrives"
    );

    ingest(&mut client, 1, &[coinbase(100), ours()]).expect("block 1 ingests");
    assert_eq!(
        client.owned_outputs.get(&pair.0),
        Some(&pair.1),
        "registered at ingest, with the gindex the ingest assigned"
    );
    assert_eq!(client.expected_output_mismatches(), 0);

    // The leaf drains and its chunk closes under the fold.
    ingest_empty(&mut client, 2, 80);
    let at_spend = client.sync_owned(&[pair]).expect("sync on a live client");
    assert_eq!(at_spend.already_held, 1, "held and served since block 1");
    assert_eq!(at_spend.reconciliation, None, "and nothing rebuilt");
}

/// A key is public the moment its transaction is relayed. Someone who
/// copies it into an output of their own, mined first, must not take the
/// registration: the match is by transaction and position, and the key only
/// confirms. The wallet's own output, mined after, is the one registered.
///
/// With the match made on the key alone the copy is registered at block 1
/// and this fails there.
#[test]
fn a_copied_key_in_another_transaction_is_not_registered() {
    let mut client = expecting();
    // The copy: a transaction with our key at the same vout, a different
    // hash, mined a block earlier.
    let copy_outputs = {
        let mut outs = outputs(700);
        outs[OURS_VOUT as usize].output_key = expectation().output_key;
        outs
    };
    let copy_blob = blob(700, PER_TX as usize);
    let coinbase_outs = outputs(100);
    let coinbase_blob = blob(100, PER_TX as usize);
    let txs = [
        TxLeafInputs {
            is_miner: true,
            tx_hash: Some(hash(100)),
            leaf_entry_blob: Some(&coinbase_blob),
            outputs: &coinbase_outs,
        },
        TxLeafInputs {
            is_miner: false,
            tx_hash: Some(hash(0x77)),
            leaf_entry_blob: Some(&copy_blob),
            outputs: &copy_outputs,
        },
    ];
    let copied_at = next_second_tx_gindex(&client, OURS_VOUT);
    client
        .ingest_block(BlockLeaves {
            height: BlockHeight::from_raw(1),
            txs: &txs,
        })
        .expect("block 1 ingests");
    assert!(
        !client.owned_outputs.contains_key(&copied_at),
        "the copy is not registered"
    );
    assert_eq!(
        client.expected_output_mismatches(),
        0,
        "and is not a mismatch either: its transaction was never expected"
    );

    let ours_at = next_second_tx_gindex(&client, OURS_VOUT);
    ingest(&mut client, 2, &[coinbase(101), ours()]).expect("block 2 ingests");
    assert_eq!(
        client.owned_outputs.get(&ours_at),
        Some(&expectation().output_key)
    );
    assert!(!client.owned_outputs.contains_key(&copied_at));
}

/// The transaction hash is the block feed's; the key is the wallet's own.
/// An expected transaction whose `vout` carries another key, or does not
/// have that `vout`, registers nothing and is counted — never an error,
/// because a feed that mislabels can cost the wallet an early registration
/// and nothing more.
#[test]
fn a_key_the_transaction_does_not_carry_is_counted_not_registered() {
    let mut client = CurveTreeClient::new();
    ingest(&mut client, 0, &[coinbase(1)]).expect("genesis ingests");
    let wrong_key = ExpectedOutput {
        output_key: OneTimePubkey::from_bytes(point(999_999)),
        ..expectation()
    };
    let no_such_vout = ExpectedOutput {
        vout: PER_TX + 5,
        ..expectation()
    };
    client
        .set_expected_outputs(&[wrong_key, no_such_vout])
        .expect("expectations set");

    ingest(&mut client, 1, &[coinbase(100), ours()]).expect("block 1 ingests");
    assert!(client.owned_outputs.is_empty());
    assert_eq!(client.expected_output_mismatches(), 2);
}

/// A rollback past the creation drops the registration with the leaf, and
/// the expectation stays: the transaction mined again on the other fork,
/// at another gindex, is matched again.
#[test]
fn a_re_mined_transaction_is_matched_again_after_a_rollback() {
    let mut client = expecting();
    let first = next_second_tx_gindex(&client, OURS_VOUT);
    ingest(&mut client, 1, &[coinbase(100), ours()]).expect("block 1 ingests");
    assert!(client.owned_outputs.contains_key(&first));

    client
        .rollback_to_fork(BlockHeight::ZERO)
        .expect("a rollback to genesis");
    assert!(
        !client.owned_outputs.contains_key(&first),
        "the registration went with the leaf"
    );

    // The other fork: block 1 is a coinbase alone, block 2 carries ours.
    ingest(&mut client, 1, &[coinbase(101)]).expect("block 1 ingests");
    let second = next_second_tx_gindex(&client, OURS_VOUT);
    ingest(&mut client, 2, &[coinbase(102), ours()]).expect("block 2 ingests");
    assert_ne!(first, second, "a different gindex on the other fork");
    assert_eq!(
        client.owned_outputs.get(&second),
        Some(&expectation().output_key)
    );
    assert!(!client.owned_outputs.contains_key(&first));
}

/// A producer that drops transaction hashes while expectations are live
/// would make every expected output a late registration without a trace.
/// Refused at the block instead, with nothing applied; with no expectation
/// live, a hash-less transaction is an ordinary one.
#[test]
fn a_transaction_without_its_hash_is_refused_while_expectations_are_live() {
    let mut client = expecting();
    let unlabelled = Tx {
        hash: None,
        seed_base: 300,
    };
    let err = ingest(&mut client, 1, &[coinbase(100), unlabelled])
        .expect_err("a hash-less transaction under live expectations");
    assert!(
        matches!(
            err,
            ClientError::TxHashMissing { height, tx_index } if height == BlockHeight::from_raw(1) && tx_index == 1
        ),
        "got {err:?}"
    );
    assert_eq!(
        client.ingested_tip_height(),
        Some(BlockHeight::ZERO),
        "the block was not applied"
    );

    client
        .set_expected_outputs(&[])
        .expect("expectations cleared");
    let unlabelled = Tx {
        hash: None,
        seed_base: 300,
    };
    ingest(&mut client, 1, &[coinbase(100), unlabelled]).expect("nothing to match against");
}

/// Each offer replaces the last: an expectation the wallet no longer holds
/// is not matched, and one it newly holds is.
#[test]
fn a_new_set_of_expectations_replaces_the_old() {
    let mut client = expecting();
    let other = ExpectedOutput {
        tx_hash: hash(0x22),
        vout: 0,
        output_key: OneTimePubkey::from_bytes(point(600)),
    };
    client
        .set_expected_outputs(&[other])
        .expect("expectations replaced");

    let other_tx = Tx {
        hash: Some(hash(0x22)),
        seed_base: 600,
    };
    let ours_at = next_second_tx_gindex(&client, OURS_VOUT);
    ingest(&mut client, 1, &[coinbase(100), ours()]).expect("block 1 ingests");
    let other_at = next_second_tx_gindex(&client, 0);
    ingest(&mut client, 2, &[coinbase(101), other_tx]).expect("block 2 ingests");
    assert!(
        !client.owned_outputs.contains_key(&ours_at),
        "the replaced expectation is gone"
    );
    assert_eq!(client.owned_outputs.get(&other_at), Some(&other.output_key));
}
