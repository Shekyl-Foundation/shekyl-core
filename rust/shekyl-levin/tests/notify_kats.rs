// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! LV-2b notify maps: 2001–2004 / 2006–2010.
//!
//! Pins fluff OPT, empty-container omit, CONTAINER_POD_AS_BLOB, pruned vs
//! unpruned `txs`, and the attestation-witness transport cap.

use shekyl_levin::{
    notify, BlockCompleteEntry, BucketReader, GetTxpoolComplement, NewBlock, NewTransactions,
    PayloadError, PortableMap, Received, RequestChain, RequestFluffyMissingTx, RequestGetObjects,
    ResponseChainEntry, ResponseGetObjects, TxBlobEntry, ATTESTATION_WITNESS_MAX_BYTES, HASH_SIZE,
    NOTIFY_NEW_TRANSACTIONS,
};
use shekyl_portable_storage::{store_to_binary, Array, Section, Value};

fn round_trip<T: PortableMap + PartialEq + std::fmt::Debug>(value: &T) {
    let bytes = value.store().expect("store");
    let decoded = T::load(&bytes).expect("load");
    assert_eq!(&decoded, value);
}

fn empty_block() -> BlockCompleteEntry {
    BlockCompleteEntry {
        pruned: false,
        block: b"blk".to_vec(),
        block_weight: 0,
        txs: Vec::new(),
        attestation_witness: Vec::new(),
    }
}

#[test]
fn witness_cap_is_cpp_formula() {
    assert_eq!(ATTESTATION_WITNESS_MAX_BYTES, 866_568);
    assert_eq!(HASH_SIZE, 32);
}

#[test]
fn new_transactions_fluff_omitted_when_true() {
    let msg = NewTransactions {
        txs: vec![b"tx1".to_vec()],
        padding: Vec::new(),
        dandelionpp_fluff: true,
    };
    let section = msg.to_section().expect("section");
    assert!(section.get("dandelionpp_fluff").is_none());
    assert!(section.get("_").is_some());
    round_trip(&msg);
}

#[test]
fn new_transactions_stem_stores_false() {
    let msg = NewTransactions {
        txs: vec![b"tx1".to_vec()],
        padding: b"pad".to_vec(),
        dandelionpp_fluff: false,
    };
    let section = msg.to_section().expect("section");
    assert_eq!(section.get("dandelionpp_fluff"), Some(&Value::Bool(false)));
    round_trip(&msg);
}

#[test]
fn new_transactions_empty_txs_omitted() {
    let msg = NewTransactions {
        txs: Vec::new(),
        padding: Vec::new(),
        dandelionpp_fluff: true,
    };
    let section = msg.to_section().expect("section");
    assert!(section.get("txs").is_none());
    round_trip(&msg);
}

#[test]
fn new_transactions_missing_fluff_loads_true() {
    let mut section = Section::new();
    section.insert("_", Value::Bytes(Vec::new()));
    let bytes = store_to_binary(&section).expect("encode");
    let loaded = NewTransactions::load(&bytes).expect("load");
    assert!(loaded.dandelionpp_fluff);
    assert!(loaded.txs.is_empty());
}

#[test]
fn new_transactions_notify_survives_bucket_reader() {
    let msg = NewTransactions {
        txs: vec![b"tx".to_vec()],
        padding: Vec::new(),
        dandelionpp_fluff: true,
    };
    let body = msg.store().expect("store");
    let bucket = notify(NOTIFY_NEW_TRANSACTIONS, &body);
    let mut reader = BucketReader::new();
    reader.feed(&bucket).expect("feed");
    match reader.next_message().expect("parse") {
        Some(Received::Notification { command, payload }) => {
            assert_eq!(command, NOTIFY_NEW_TRANSACTIONS);
            assert_eq!(NewTransactions::load(&payload).expect("load"), msg);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn unpruned_txs_are_blob_array_hashes_dropped() {
    let entry = BlockCompleteEntry {
        pruned: false,
        block: b"blk".to_vec(),
        block_weight: 0,
        txs: vec![TxBlobEntry {
            blob: b"tx".to_vec(),
            prunable_hash: [0x11; HASH_SIZE],
        }],
        attestation_witness: Vec::new(),
    };
    let section = entry.to_section().expect("section");
    match section.get("txs") {
        Some(Value::Array(Array::Bytes(blobs))) => assert_eq!(blobs, &vec![b"tx".to_vec()]),
        other => panic!("expected blob array, got {other:?}"),
    }
    let loaded = BlockCompleteEntry::load(&entry.store().expect("store")).expect("load");
    assert_eq!(loaded.txs[0].blob, b"tx");
    assert_eq!(loaded.txs[0].prunable_hash, [0u8; HASH_SIZE]);
}

#[test]
fn pruned_txs_are_objects() {
    let entry = BlockCompleteEntry {
        pruned: true,
        block: b"blk".to_vec(),
        block_weight: 12,
        txs: vec![TxBlobEntry {
            blob: b"tx".to_vec(),
            prunable_hash: [0x22; HASH_SIZE],
        }],
        attestation_witness: b"wit".to_vec(),
    };
    let section = entry.to_section().expect("section");
    assert!(matches!(
        section.get("txs"),
        Some(Value::Array(Array::Object(_)))
    ));
    round_trip(&entry);
}

#[test]
fn empty_unpruned_txs_omitted() {
    let entry = empty_block();
    let section = entry.to_section().expect("section");
    assert!(section.get("txs").is_none());
    assert!(section.get("pruned").is_none());
    assert!(section.get("block_weight").is_none());
    assert!(section.get("attestation_witness").is_none());
    round_trip(&entry);
}

#[test]
fn witness_over_cap_rejected() {
    let entry = BlockCompleteEntry {
        pruned: false,
        block: b"blk".to_vec(),
        block_weight: 0,
        txs: Vec::new(),
        attestation_witness: vec![0u8; ATTESTATION_WITNESS_MAX_BYTES + 1],
    };
    assert_eq!(
        entry.to_section(),
        Err(PayloadError::WitnessTooLarge {
            got: ATTESTATION_WITNESS_MAX_BYTES + 1,
            max: ATTESTATION_WITNESS_MAX_BYTES,
        })
    );
}

#[test]
fn new_block_round_trip() {
    round_trip(&NewBlock {
        b: empty_block(),
        current_blockchain_height: 9,
    });
}

#[test]
fn request_get_objects_pod_hashes() {
    let req = RequestGetObjects {
        blocks: vec![[0xaa; HASH_SIZE], [0xbb; HASH_SIZE]],
        prune: false,
    };
    let section = req.to_section().expect("section");
    match section.get("blocks") {
        Some(Value::Bytes(b)) => assert_eq!(b.len(), 64),
        other => panic!("expected concatenated hashes, got {other:?}"),
    }
    assert!(section.get("prune").is_none());
    round_trip(&req);
}

#[test]
fn request_get_objects_empty_omitted() {
    let req = RequestGetObjects {
        blocks: Vec::new(),
        prune: true,
    };
    let section = req.to_section().expect("section");
    assert!(section.get("blocks").is_none());
    assert_eq!(section.get("prune"), Some(&Value::Bool(true)));
    round_trip(&req);
}

#[test]
fn pod_blob_rejects_non_multiple() {
    let mut section = Section::new();
    section.insert("blocks", Value::Bytes(vec![0u8; 31]));
    let bytes = store_to_binary(&section).expect("encode");
    assert_eq!(
        RequestGetObjects::load(&bytes),
        Err(PayloadError::PodBlobLength {
            field: "blocks",
            element: HASH_SIZE,
            got: 31,
        })
    );
}

#[test]
fn response_get_objects_round_trip() {
    round_trip(&ResponseGetObjects {
        blocks: vec![empty_block()],
        missed_ids: vec![[0xcc; HASH_SIZE]],
        current_blockchain_height: 4,
    });
}

#[test]
fn request_chain_round_trip() {
    round_trip(&RequestChain {
        block_ids: vec![[1u8; HASH_SIZE]],
        prune: false,
    });
}

#[test]
fn response_chain_entry_top64_stored_when_zero() {
    let msg = ResponseChainEntry {
        start_height: 1,
        total_height: 2,
        cumulative_difficulty: 3,
        cumulative_difficulty_top64: 0,
        m_block_ids: vec![[0u8; HASH_SIZE]],
        m_block_weights: vec![100, 200],
        first_block: Vec::new(),
    };
    let section = msg.to_section().expect("section");
    assert!(section.get("cumulative_difficulty_top64").is_some());
    assert!(section.get("first_block").is_some());
    match section.get("m_block_weights") {
        Some(Value::Bytes(b)) => assert_eq!(b.len(), 16),
        other => panic!("expected u64 pod blob, got {other:?}"),
    }
    round_trip(&msg);
}

#[test]
fn fluffy_missing_tx_round_trip() {
    round_trip(&RequestFluffyMissingTx {
        block_hash: [0xdd; HASH_SIZE],
        current_blockchain_height: 7,
        missing_tx_indices: vec![0, 2, 5],
    });
}

#[test]
fn txpool_complement_empty_omitted() {
    let msg = GetTxpoolComplement { hashes: Vec::new() };
    let section = msg.to_section().expect("section");
    assert!(section.get("hashes").is_none());
    round_trip(&msg);
}

#[test]
fn txpool_complement_hashes_round_trip() {
    round_trip(&GetTxpoolComplement {
        hashes: vec![[0xee; HASH_SIZE]],
    });
}
