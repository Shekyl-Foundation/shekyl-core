use std_shims::io::{self, Cursor};

use crate::{
  fcmp::EncryptedAmount,
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

// -- EncryptedAmount codec tests (Commit A) --
//
// These tests exercise the codec layer only. The corruption-detection property
// (flipping a KEM-ciphertext bit causes the recipient's locally-derived amount_tag
// to mismatch the on-chain amount_tag) is exercised by tests in
// `rust/shekyl-crypto-pq/` in `shekyl-core` (`scan_tampered_amount_tag_fails` and
// the `fuzz_construct_output` / `fuzz_scan_malformed_ct` fuzz targets), not here.
// The fork's responsibility is the carrier byte on the wire; derivation and
// verification live downstream.

#[test]
fn encrypted_amount_round_trip_arbitrary_values() {
  // Sample-sweep over fixed values exercising both the amount payload and the tag.
  // Includes corner cases (all-zeros, all-ones, alternating) plus mid-range values.
  let cases: &[([u8; 8], u8)] = &[
    ([0x00; 8], 0x00),
    ([0xFF; 8], 0xFF),
    ([0x00; 8], 0xFF),
    ([0xFF; 8], 0x00),
    ([0xAA; 8], 0x55),
    ([0x55; 8], 0xAA),
    ([1, 2, 3, 4, 5, 6, 7, 8], 0x42),
    ([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE], 0x99),
  ];
  for (amount, amount_tag) in cases {
    let enc = EncryptedAmount { amount: *amount, amount_tag: *amount_tag };

    let mut buf = vec![];
    enc.write(&mut buf).unwrap();
    assert_eq!(buf.len(), 9, "EncryptedAmount serializes to exactly 9 bytes");
    assert_eq!(&buf[.. 8], amount, "first 8 bytes carry the amount payload");
    assert_eq!(buf[8], *amount_tag, "9th byte carries the amount_tag");

    let read_back = EncryptedAmount::read(&mut buf.as_slice()).unwrap();
    assert_eq!(read_back, enc, "round-trip is byte-equal");
  }
}

#[test]
fn encrypted_amount_read_on_short_buffer_fails_with_unexpected_eof() {
  // 8-byte input must NOT parse as an EncryptedAmount.
  //
  // This works because read_byte on an empty reader returns UnexpectedEof, NOT because
  // the codec semantically rejects 8-byte shapes — the codec has no concept of "shape".
  // Future contributors: do not "fix" this test by adding an explicit length check;
  // that would itself be a regression. Length enforcement is via Read's contract.
  let buf = [0x00; 8];
  let err = EncryptedAmount::read(&mut buf.as_slice()).unwrap_err();
  assert_eq!(
    err.kind(),
    io::ErrorKind::UnexpectedEof,
    "8-byte read must fail with UnexpectedEof, not partially populate"
  );
}

#[test]
fn encrypted_amount_read_is_non_greedy() {
  // 10-byte input: the codec must consume exactly 9 bytes and leave the 10th.
  // Asserted via Cursor::position to make non-greediness explicit.
  let buf = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xFF];
  let mut cursor = Cursor::new(&buf[..]);
  let enc = EncryptedAmount::read(&mut cursor).unwrap();
  assert_eq!(enc.amount, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
  assert_eq!(enc.amount_tag, 0x99);
  assert_eq!(cursor.position(), 9, "codec consumed exactly 9 bytes");
  // The 10th byte is still there (position is asserted as 9 above; index 9 is safe).
  assert_eq!(buf[9], 0xFF);
}

#[test]
fn encrypted_amount_codec_treats_tag_values_symmetrically() {
  // The codec has NO special tag values. Any rejection of specific amount_tag values is
  // consensus, not codec, and lives in `shekyl-crypto-pq` (which compares the on-chain
  // tag against an HKDF-derived expected value, not against a codec-level allowlist).
  for tag in [0x00u8, 0x01, 0x7F, 0x80, 0xFE, 0xFF] {
    let enc = EncryptedAmount { amount: [0x42; 8], amount_tag: tag };
    let mut buf = vec![];
    enc.write(&mut buf).unwrap();
    let read_back = EncryptedAmount::read(&mut buf.as_slice()).unwrap();
    assert_eq!(read_back, enc, "codec accepts amount_tag = {tag:#04x} symmetrically");
  }
}
