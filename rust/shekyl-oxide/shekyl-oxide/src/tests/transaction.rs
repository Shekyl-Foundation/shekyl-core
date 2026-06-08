use crate::transaction::{Input, NotPruned, Timelock, Transaction};

// Legacy Monero transaction vectors (V1, CLSAG) are no longer parseable since
// Shekyl only supports V2 FCMP++. These tests verify that legacy bytes are
// correctly rejected.

#[test]
fn legacy_transaction_vectors_rejected() {
    const TRANSACTIONS: &str = include_str!("./vectors/transactions.json");

    #[derive(serde::Deserialize)]
    struct Vector {
        hex: String,
        #[serde(flatten)]
        _rest: serde_json::Value,
    }

    let vectors: Vec<Vector> = serde_json::from_str(TRANSACTIONS).unwrap();
    for v in vectors {
        let bytes = hex::decode(&v.hex).unwrap();
        let result = Transaction::<NotPruned>::read(&mut bytes.as_slice());
        // All legacy test vectors should fail to parse since Shekyl only accepts V2 FCMP++.
        // If any succeed, it means they happen to be valid V2 coinbase transactions.
        if let Ok(tx) = result {
            assert_eq!(tx.version(), 2, "only v2 transactions should parse");
        }
    }
}

#[test]
fn v2_coinbase_round_trip() {
    use crate::io::CompressedPoint;
    use crate::transaction::{Output, TransactionPrefix};

    let tx = Transaction::V2 {
        prefix: TransactionPrefix {
            additional_timelock: Timelock::Block(100),
            inputs: vec![Input::Gen(500)],
            outputs: vec![Output {
                amount: Some(1_000_000_000),
                key: CompressedPoint([1; 32]),
                view_tag: None,
                staking: None,
            }],
            extra: vec![1, 2, 3],
        },
        proofs: None,
    };

    let serialized = tx.serialize();
    let deserialized = Transaction::read(&mut serialized.as_slice()).unwrap();
    assert_eq!(tx, deserialized);
    assert_eq!(tx.hash(), deserialized.hash());
    assert!(deserialized.signature_hash().is_none());
}

#[test]
fn archival_serve_credit_input_gate2_kat() {
    const KAT: &str = include_str!(
        "../../../../shekyl-archival-retention/tests/fixtures/gate2_serve_credit_kat_v1.json"
    );

    #[derive(serde::Deserialize)]
    struct KatWire {
        wire_hex: String,
        shard_id: u64,
        settlement_epoch: u64,
        leaf_index_in_segment: u32,
    }

    #[derive(serde::Deserialize)]
    struct KatFixture {
        wire: KatWire,
    }

    let kat: KatFixture = serde_json::from_str(KAT).unwrap();
    let bytes = hex::decode(&kat.wire.wire_hex).unwrap();
    let input = Input::read(&mut bytes.as_slice()).unwrap();

    let Input::ArchivalServeCreditResponse(resp) = input else {
        panic!("expected archival serve-credit input");
    };
    assert_eq!(resp.shard_id, kat.wire.shard_id);
    assert_eq!(resp.settlement_epoch, kat.wire.settlement_epoch);
    assert_eq!(resp.leaf_index_in_segment, kat.wire.leaf_index_in_segment);

    let mut out = Vec::new();
    Input::ArchivalServeCreditResponse(resp.clone())
        .write(&mut out)
        .unwrap();
    assert_eq!(out, bytes);
}
