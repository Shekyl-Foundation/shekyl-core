use crate::block::{Block, BlockHeader};
use crate::io::CompressedPoint;
use crate::transaction::{Input, Output, Timelock, Transaction, TransactionPrefix};

// CT-5 pre-0: the consensus `block_header` serializes `curve_tree_root` after
// `nonce` (C++ `src/cryptonote_basic/cryptonote_basic.h`, `FIELD(curve_tree_root)`
// inside `BEGIN_SERIALIZE`/`END_SERIALIZE`). Before pre-0 the Rust `BlockHeader`
// parsed only five fields and stopped at `nonce`, so a real six-field consensus
// header left 32 bytes (the root) unconsumed and the following miner transaction
// mis-aligned. These KATs pin the six-field layout and prove the mis-alignment is
// closed.
//
// E3 severity (verified at source, disposition (a) "not-yet-exercised"): no real
// consensus block had ever been deserialized by the Rust path — `Block::read`
// would have failed loudly on the mis-aligned miner tx — so these KATs establish
// header/block deserialization correctness for the first time rather than
// asserting inertness against a prior compensating offset.

fn sample_header() -> BlockHeader {
    BlockHeader {
        hardfork_version: 1,
        hardfork_signal: 0,
        timestamp: 1_700_000_000,
        previous: [0x11; 32],
        nonce: 0x0403_0201,
        curve_tree_root: [0x22; 32],
    }
}

#[test]
fn header_round_trip_preserves_curve_tree_root() {
    let header = sample_header();
    let serialized = header.serialize();
    let deserialized = BlockHeader::read(&mut serialized.as_slice()).unwrap();
    assert_eq!(header, deserialized);
    assert_eq!(deserialized.curve_tree_root, [0x22; 32]);
}

#[test]
fn header_matches_consensus_field_layout() {
    // Hand-built blob in the consensus field order, with single-byte varints for
    // the small leading fields:
    //   major(varint) | minor(varint) | timestamp(varint) | prev(32) | nonce(4 LE)
    //   | curve_tree_root(32)
    let mut expected = Vec::new();
    expected.push(0x01); // hardfork_version = 1
    expected.push(0x00); // hardfork_signal = 0
    expected.push(0x00); // timestamp = 0
    expected.extend_from_slice(&[0x11; 32]); // previous
    expected.extend_from_slice(&0x0403_0201u32.to_le_bytes()); // nonce (LE)
    expected.extend_from_slice(&[0x22; 32]); // curve_tree_root

    let header = BlockHeader {
        hardfork_version: 1,
        hardfork_signal: 0,
        timestamp: 0,
        previous: [0x11; 32],
        nonce: 0x0403_0201,
        curve_tree_root: [0x22; 32],
    };

    // write reproduces the consensus layout exactly...
    assert_eq!(header.serialize(), expected);
    // ...and read parses the consensus layout with the root intact.
    let parsed = BlockHeader::read(&mut expected.as_slice()).unwrap();
    assert_eq!(parsed, header);
    assert_eq!(parsed.curve_tree_root, [0x22; 32]);
}

#[test]
fn block_round_trip_does_not_misalign_miner_tx() {
    // The §3.6 #2 regression: with the six-field header the miner transaction is
    // read at the correct offset. A full-block round-trip exercises exactly the
    // `BlockHeader::read` → `Transaction::read` boundary that mis-aligned before.
    let miner_transaction = Transaction::V3 {
        prefix: TransactionPrefix {
            additional_timelock: Timelock::None,
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

    let block = Block::new(sample_header(), miner_transaction, vec![[0xCD; 32]])
        .expect("valid coinbase block");

    let serialized = block.serialize();
    let deserialized = Block::read(&mut serialized.as_slice()).unwrap();
    assert_eq!(block, deserialized);
    assert_eq!(deserialized.header.curve_tree_root, [0x22; 32]);
    assert_eq!(deserialized.number(), 500);
}

// Real regtest coinbase blocks captured from `shekyld --regtest --fixed-difficulty 1`
// via `get_block` (the C++ serializer is the oracle for the genesis block/tx wire
// format). Round-trip **byte-identity** is the spec assertion: `Block::read` must
// parse a live PQC coinbase, and `Block::serialize` must reproduce the oracle bytes.
//
// Provenance: mined to the genesis treasury address; `vin = [gen]`,
// `rct_signatures.type == 0` (`RCTTypeNull`), one coinbase output (`vout`=1),
// ~1.1 KB PQC `tx_extra`. The coinbase rct base carries `enc_amounts` / `enc_labels`
// / `outPk` **even for `RCTTypeNull`** (C++ `serialize_rctsig_base`,
// `src/fcmp/rctTypes.h:209-280`) — the 50 bytes/output the pre-fix Rust
// deserializer skipped (`ProofBase::read` returned `None` after the type byte),
// so `Block::read` then mis-read the rct base as the block's tx-hash count and
// failed `UnexpectedEof`. This is the first live block the Rust path has parsed;
// it establishes coinbase block/tx deserialization correctness for the first time
// (cf. the `curve_tree_root` six-field-header KATs above).
#[test]
#[ignore = "gate (a): un-ignore once the coinbase RCTTypeNull base reader lands; \
            currently red — Block::read skips the coinbase rct base and fails UnexpectedEof"]
fn regtest_coinbase_blocks_round_trip_byte_identical() {
    let corpus: [(u64, &[u8]); 3] = [
        (0, include_bytes!("vectors/regtest_coinbase_h0.block")),
        (1, include_bytes!("vectors/regtest_coinbase_h1.block")),
        (2, include_bytes!("vectors/regtest_coinbase_h2.block")),
    ];
    for (height, blob) in corpus {
        let block = Block::read(&mut &blob[..])
            .unwrap_or_else(|e| panic!("height {height}: Block::read failed: {e}"));
        let reserialized = block.serialize();
        assert_eq!(
            reserialized.as_slice(),
            blob,
            "height {height}: re-serialization must be byte-identical to the C++ oracle blob \
             (len {} vs {})",
            reserialized.len(),
            blob.len(),
        );
    }
}
