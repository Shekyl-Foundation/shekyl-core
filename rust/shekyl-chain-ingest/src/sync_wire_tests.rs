// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The captured chains, read as headers and as skeletons (CS-1 §4.1, §4.3).
//!
//! A header chain carries [`PowBlob`] bytes and no body. The identity of
//! those bytes is the block hash. A skeleton carries the unprunable bytes
//! and the three txid operands a pruned receiver cannot recompute, and
//! that txid is the transaction's.

use std::io::Cursor;

use shekyl_wire::transaction::Ct;
use shekyl_wire::{PowBlob, SkeletonTx};

use crate::corpus::CorpusReader;
use crate::source::{IngestEvent, Source};
use crate::vectors_tests::captured_chains;
use crate::vectors_tests::retired_keyless_join::UntilRetiredJoin;

fn each_captured_block(mut body: impl FnMut(&str, &shekyl_chain_rules::Candidate)) {
    let mut blocks = 0u64;
    for (dir, manifest) in captured_chains() {
        let bytes = std::fs::read(dir.join("corpus.e2")).expect("read corpus");
        let mut reader = UntilRetiredJoin::new(
            CorpusReader::open(Cursor::new(bytes.as_slice())).expect("open corpus"),
        );
        while let Some(sequenced) = reader.next().expect("corpus reads") {
            let IngestEvent::Extend(candidate) = sequenced.event else {
                continue;
            };
            body(&manifest.shape, &candidate);
            blocks += 1;
        }
        reader.finish(&manifest.shape);
    }
    assert!(blocks > 0, "the captured chains contain no blocks");
}

/// Every captured block's PoW preimage parses back to itself, and its
/// identity is the block hash. One changed field is a different block.
#[test]
fn every_captured_pow_blob_is_the_block_hash() {
    each_captured_block(|shape, candidate| {
        let block = &candidate.block;
        let encoded = block.pow_blob();
        let parsed = PowBlob::read(&encoded)
            .unwrap_or_else(|e| panic!("{shape}: PoW preimage does not parse: {e}"));
        let id = parsed.identity();
        assert_eq!(
            parsed.write(),
            encoded,
            "{shape}: PowBlob is the one encoder"
        );
        assert_eq!(
            id,
            block.hash(),
            "{shape}: the preimage's identity is the block hash"
        );
        let mut header = parsed.clone();
        let mut previous = header.header.previous.to_bytes();
        previous[0] ^= 0x01;
        header.header.previous = shekyl_types::BlockHash::from_bytes(previous);
        assert_ne!(header.identity(), id, "header");
        let mut tree = parsed.clone();
        let mut root = tree.tx_tree_hash.to_bytes();
        root[0] ^= 0x01;
        tree.tx_tree_hash = shekyl_types::TxTreeHash::from_bytes(root);
        assert_ne!(tree.identity(), id, "tx_tree_hash");
        let mut count = parsed;
        count.tx_count = count.tx_count.wrapping_add(1);
        assert_ne!(count.identity(), id, "tx_count");
    });
}

/// Every non-coinbase transaction's skeleton rebuilds its txid. This is
/// PDM-Q-F28's falsifier: the supplied components are the discarded bytes.
#[test]
fn every_captured_skeleton_txid_is_the_transaction_hash() {
    let mut spends = 0u64;
    each_captured_block(|shape, candidate| {
        // A null transaction is the coinbase, which rides in the block, and
        // `SkeletonTx` refuses one: it has no prunable region and no
        // authentication hash, so the supplied components are not its txid.
        // A listed null, if a chain ever carries one, is the same refusal.
        for tx in &candidate.transactions {
            if matches!(tx.ct, Ct::Null(_)) {
                let segments = tx.write_segments().expect("segment");
                let archival_len = segments.archival_len();
                let skeleton = SkeletonTx {
                    unprunable: segments.pruned,
                    prunable_hash: tx.prunable_hash(),
                    pqc_auth_hash: tx.pqc_auth_hash(),
                    archival_len,
                };
                assert!(
                    skeleton.txid().is_err(),
                    "{shape}: a null transaction is not a skeleton"
                );
                continue;
            }
            let segments = tx.write_segments().expect("segment");
            let archival_len = segments.archival_len();
            let skeleton = SkeletonTx {
                unprunable: segments.pruned,
                prunable_hash: tx.prunable_hash(),
                pqc_auth_hash: tx.pqc_auth_hash(),
                archival_len,
            };
            let got = skeleton
                .txid()
                .unwrap_or_else(|e| panic!("{shape}: skeleton does not read: {e}"));
            assert_eq!(got, tx.hash(), "{shape}: skeleton txid");
            spends += 1;
        }
        let coinbase = &candidate.block.miner_transaction;
        let segments = coinbase.write_segments().expect("coinbase segments");
        let archival_len = segments.archival_len();
        let skeleton = SkeletonTx {
            unprunable: segments.pruned,
            prunable_hash: coinbase.prunable_hash(),
            pqc_auth_hash: coinbase.pqc_auth_hash(),
            archival_len,
        };
        assert!(
            skeleton.txid().is_err(),
            "{shape}: the coinbase is not a skeleton"
        );
    });
    assert!(
        spends > 0,
        "the captured chains contain no non-coinbase transaction"
    );
}
