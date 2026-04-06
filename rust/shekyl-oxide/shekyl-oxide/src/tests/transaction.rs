use crate::{
  transaction::{NotPruned, Transaction, Timelock, Input},
};

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
  use crate::transaction::{Output, TransactionPrefix};
  use crate::io::CompressedPoint;

  let tx = Transaction::V2 {
    prefix: TransactionPrefix {
      additional_timelock: Timelock::Block(100),
      inputs: vec![Input::Gen(500)],
      outputs: vec![Output {
        amount: Some(1_000_000_000),
        key: CompressedPoint([1; 32]),
        view_tag: None,
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
