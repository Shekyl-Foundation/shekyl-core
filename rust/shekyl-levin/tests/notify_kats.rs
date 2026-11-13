// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! LV-2b notify maps: 2002–2004 / 2006–2010.
//!
//! Pins fluff OPT, empty-container omit, CONTAINER_POD_AS_BLOB, pruned vs
//! unpruned `txs`, and the bundle-references transport cap.

use shekyl_levin::{
    notify, BlockCompleteEntry, BucketReader, GetTxpoolComplement, NewCompactBlock,
    NewTransactions, PayloadError, PortableMap, Received, RequestCompactMissingTx, TxBlobEntry,
    HASH_SIZE, MAX_BUNDLE_REFERENCES, NOTIFY_NEW_TRANSACTIONS,
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
        bundle_references: Vec::new(),
    }
}

#[test]
fn hash_size_is_a_crypto_hash() {
    assert_eq!(HASH_SIZE, 32);
}

/// A block carries at most one section's references, and a section names
/// at most `W₂` of them: the ruled band's top. Red edit: move the section
/// bound in `shekyl-types` — this names the drift.
#[test]
fn a_blocks_references_are_at_most_one_sections() {
    assert_eq!(
        u64::try_from(MAX_BUNDLE_REFERENCES).expect("fits"),
        shekyl_archival_retention::constants::W2_MAX_DEFENSIBLE_BLOCKS
    );
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
        bundle_references: Vec::new(),
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
        bundle_references: vec![b"ref-a".to_vec(), b"ref-b".to_vec()],
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
    assert!(section.get("bundle_references").is_none());
    round_trip(&entry);
}

/// One section's references pass both ways; one more is refused on
/// either side of the codec. Red edit: drop either check — the side
/// without it accepts the oversized section.
#[test]
fn references_over_cap_rejected() {
    let at_cap = BlockCompleteEntry {
        bundle_references: vec![vec![0xAB]; MAX_BUNDLE_REFERENCES],
        ..empty_block()
    };
    round_trip(&at_cap);
    let over = BlockCompleteEntry {
        bundle_references: vec![vec![0xAB]; MAX_BUNDLE_REFERENCES + 1],
        ..empty_block()
    };
    let refused = PayloadError::TooManyReferences {
        got: MAX_BUNDLE_REFERENCES + 1,
        max: MAX_BUNDLE_REFERENCES,
    };
    assert_eq!(over.to_section(), Err(refused.clone()));
    let mut section = at_cap.to_section().expect("section");
    section.insert(
        "bundle_references",
        Value::Array(Array::Bytes(vec![vec![0xAB]; MAX_BUNDLE_REFERENCES + 1])),
    );
    assert_eq!(BlockCompleteEntry::from_section(&section), Err(refused));
}

#[test]
fn new_compact_block_round_trip() {
    round_trip(&NewCompactBlock {
        b: empty_block(),
        current_blockchain_height: 9,
    });
}

/// A POD-as-blob field whose length is not a whole number of elements is
/// refused, not truncated: the pool complement's hash list, which carries
/// the decoder now that the inherited block and chain requests are retired.
#[test]
fn pod_blob_rejects_non_multiple() {
    let mut section = Section::new();
    section.insert("hashes", Value::Bytes(vec![0u8; 31]));
    let bytes = store_to_binary(&section).expect("encode");
    assert_eq!(
        GetTxpoolComplement::load(&bytes),
        Err(PayloadError::PodBlobLength {
            field: "hashes",
            element: HASH_SIZE,
            got: 31,
        })
    );
}

#[test]
fn compact_missing_tx_round_trip() {
    round_trip(&RequestCompactMissingTx {
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
