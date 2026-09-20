// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use std::io::Cursor;

use shekyl_chain_rules::Candidate;
use shekyl_types::{AttestationRoot, BlockHash, BlockHeight, CurveTreeRoot};
use shekyl_wire::{Block, BlockHeader, Ct, CtBase, Input, Output, Transaction, TxPrefix};

use super::*;

// Wire-valid fixtures. The rules crate's `harness::fixture::coinbase` has no
// inputs and does not survive `Block::read` (its blocks never round-trip
// through bytes; RD-F16), so a corpus test builds its own: a miner tx with
// the sole `Input::Gen` the wire demands, and listed bodies that parse.

fn coinbase(height: u64) -> Transaction {
    Transaction {
        prefix: TxPrefix {
            unlock_time: height + 60,
            inputs: vec![Input::Gen(height)],
            outputs: vec![Output {
                amount: 0,
                key: [0x40; 32],
                view_tag: 1,
            }],
            extra: Vec::new(),
        },
        ct: Ct::Null(CtBase {
            enc_amounts: vec![[0x55; 9]],
            enc_labels: vec![[0x66; 9]],
            commitments: vec![[0x70; 32]],
        }),
    }
}

/// A listed body distinguishable from every other by `tag`.
fn listed(tag: u8) -> Transaction {
    Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![Input::Gen(u64::from(tag))],
            outputs: vec![Output {
                amount: 0,
                key: [tag; 32],
                view_tag: tag,
            }],
            extra: Vec::new(),
        },
        ct: Ct::Null(CtBase {
            enc_amounts: vec![[tag; 9]],
            enc_labels: vec![[tag; 9]],
            commitments: vec![[tag; 32]],
        }),
    }
}

/// A candidate at `height` with `n` listed bodies, serialized the way a
/// source hands blobs over: the block blob and the bodies in header order.
fn blobs(height: u64, n: usize) -> (Candidate, Vec<u8>, Vec<Vec<u8>>) {
    let bodies: Vec<Transaction> = (0..n)
        .map(|i| {
            listed(0x80 + u8::try_from(i).expect("small") + u8::try_from(height).expect("small"))
        })
        .collect();
    let block = Block {
        header: BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: 1_700_000_000 + height,
            previous: BlockHash::from_bytes([0x11; 32]),
            nonce: 7,
            curve_tree_root: CurveTreeRoot::from_bytes([0x22; 32]),
            attestation_root: AttestationRoot::from_bytes([0x33; 32]),
        },
        miner_transaction: coinbase(height),
        transaction_hashes: bodies.iter().map(Transaction::hash).collect(),
    };
    let block_blob = block.serialize();
    let tx_blobs = bodies.iter().map(Transaction::serialize).collect();
    (Candidate::new(block, bodies), block_blob, tx_blobs)
}

fn write(records: &[(Vec<u8>, Vec<Vec<u8>>)]) -> Vec<u8> {
    let mut w = CorpusWriter::create(
        Cursor::new(Vec::new()),
        CorpusNet::Fakechain,
        BlockHeight::ZERO,
    )
    .expect("header");
    for (block, txs) in records {
        w.append(block, txs).expect("verified record");
    }
    w.finish().expect("finish").into_inner()
}

#[test]
fn a_corpus_round_trips_as_an_extend_only_source_in_height_order() {
    let (c0, b0, t0) = blobs(0, 0);
    let (c1, b1, t1) = blobs(1, 2);
    let (c2, b2, t2) = blobs(2, 1);
    let bytes = write(&[(b0, t0), (b1, t1), (b2, t2)]);

    let mut reader = CorpusReader::open(Cursor::new(bytes)).expect("open");
    assert_eq!(reader.net(), CorpusNet::Fakechain);
    assert_eq!(reader.declared(), 3);
    let mut seen = Vec::new();
    while let Some(Sequenced { seq, event }) = reader.next().expect("record") {
        assert!(
            !event.is_barrier(),
            "a corpus yields Extend only; Extend is not a sequencer barrier"
        );
        match event {
            IngestEvent::Extend(cand) => seen.push((seq, *cand)),
            IngestEvent::Rewind { .. } => unreachable!("a corpus is Extend-only"),
        }
    }
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0].0, SequenceNo::FIRST);
    assert_eq!(seen[1].0, SequenceNo::FIRST.next());
    assert_eq!(seen[0].1, c0);
    assert_eq!(seen[1].1, c1);
    assert_eq!(seen[2].1, c2);
    assert!(reader.next().expect("clean end").is_none());
}

#[test]
fn the_writer_refuses_a_pruned_sources_shortfall_by_height() {
    // RD-F15: a pruned node returns fewer bodies than the header lists and
    // says nothing. The writer says it, naming the height, and writes no
    // record for it.
    let (_, b0, t0) = blobs(0, 0);
    let (_, b1, mut t1) = blobs(1, 2);
    t1.pop();
    let mut w = CorpusWriter::create(
        Cursor::new(Vec::new()),
        CorpusNet::Testnet,
        BlockHeight::ZERO,
    )
    .expect("header");
    w.append(&b0, &t0).expect("genesis");
    let refused = w.append(&b1, &t1).expect_err("one body short");
    assert!(
        matches!(
            refused,
            CorpusFault::IncompleteBodies {
                height,
                listed: 2,
                present: 1
            } if height == BlockHeight::from_raw(1)
        ),
        "{refused}"
    );
    // Nothing landed for height 1: the finished corpus has one record.
    let bytes = w.finish().expect("finish").into_inner();
    let reader = CorpusReader::open(Cursor::new(bytes)).expect("open");
    assert_eq!(reader.declared(), 1);
}

#[test]
fn trailing_bytes_inside_a_length_prefix_are_malformed_not_verified() {
    // The corpus holds complete blobs. `Block::read` / `Transaction::read`
    // are streaming parsers and would drop a trailing byte; from_bytes
    // refuses it, so a padded source cannot land and a padded artifact
    // cannot be read as the canonical body.
    let (_, mut block, txs) = blobs(0, 0);
    block.push(0x00);
    let mut w = CorpusWriter::create(
        Cursor::new(Vec::new()),
        CorpusNet::Fakechain,
        BlockHeight::ZERO,
    )
    .expect("header");
    let refused = w.append(&block, &txs).expect_err("padded block");
    assert!(
        matches!(refused, CorpusFault::Malformed { what: "block", .. }),
        "{refused}"
    );

    let (_, block, mut txs) = blobs(0, 1);
    txs[0].push(0x00);
    let mut w = CorpusWriter::create(
        Cursor::new(Vec::new()),
        CorpusNet::Mainnet,
        BlockHeight::ZERO,
    )
    .expect("header");
    let refused = w.append(&block, &txs).expect_err("padded body");
    assert!(
        matches!(
            refused,
            CorpusFault::Malformed {
                what: "transaction",
                ..
            }
        ),
        "{refused}"
    );
}

#[test]
fn the_writer_refuses_bodies_out_of_header_order() {
    let (_, b, mut t) = blobs(0, 2);
    t.swap(0, 1);
    let mut w = CorpusWriter::create(
        Cursor::new(Vec::new()),
        CorpusNet::Mainnet,
        BlockHeight::ZERO,
    )
    .expect("header");
    let refused = w.append(&b, &t).expect_err("reordered");
    assert!(
        matches!(refused, CorpusFault::BodyMismatch { index: 0, .. }),
        "{refused}"
    );
}

#[test]
fn the_reader_re_verifies_and_refuses_a_tampered_body() {
    // The writer verified it; someone edited the artifact afterwards. The
    // reader does not trust the write-time check — it re-derives it.
    let (_, b0, t0) = blobs(0, 0);
    let (_, b1, t1) = blobs(1, 1);
    let mut bytes = write(&[(b0, t0), (b1, t1)]);
    // Flip the last byte of the file: inside the second record's only body.
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let mut reader = CorpusReader::open(Cursor::new(bytes)).expect("open");
    reader.next().expect("genesis is intact");
    let refused = reader.next().expect_err("tampered");
    assert!(
        matches!(
            refused,
            CorpusFault::BodyMismatch { .. } | CorpusFault::Malformed { .. }
        ),
        "{refused}"
    );
}

#[test]
fn the_reader_refuses_a_foreign_magic_and_a_foreign_version() {
    let (_, b0, t0) = blobs(0, 0);
    let bytes = write(&[(b0, t0)]);
    let mut wrong_magic = bytes.clone();
    wrong_magic[0] ^= 0xff;
    assert!(matches!(
        CorpusReader::open(Cursor::new(wrong_magic)).err(),
        Some(CorpusFault::BadMagic)
    ));
    let mut wrong_version = bytes;
    wrong_version[8..12].copy_from_slice(&(CORPUS_FORMAT_VERSION + 1).to_le_bytes());
    assert!(matches!(
        CorpusReader::open(Cursor::new(wrong_version)).err(),
        Some(CorpusFault::UnsupportedVersion { found }) if found == CORPUS_FORMAT_VERSION + 1
    ));
}

#[test]
fn an_unfinished_corpus_is_refused_by_count() {
    // Write two records but never `finish`: the header still says zero.
    let (_, b0, t0) = blobs(0, 0);
    let (_, b1, t1) = blobs(1, 0);
    let mut w = CorpusWriter::create(
        Cursor::new(Vec::new()),
        CorpusNet::Stagenet,
        BlockHeight::ZERO,
    )
    .expect("header");
    w.append(&b0, &t0).expect("one");
    w.append(&b1, &t1).expect("two");
    // Reach in without finishing: the cursor holds the bytes.
    let bytes = {
        let CorpusWriter { out, .. } = w;
        out.into_inner()
    };
    let mut reader = CorpusReader::open(Cursor::new(bytes)).expect("open");
    let refused = reader.next().expect_err("declared 0, records present");
    assert!(
        matches!(
            refused,
            CorpusFault::CountMismatch {
                declared: 0,
                present: 1
            }
        ),
        "{refused}"
    );
}

#[test]
fn the_reader_refuses_a_crafted_tx_count_before_reading_bodies() {
    // The file's `tx_count` is untrusted. The header lists zero transactions;
    // a `u32::MAX` count must refuse as IncompleteBodies without allocating
    // 2^32 pointer slots (the wire parser's own "no pre-allocation against
    // n_tx" discipline, applied to the corpus record).
    let (_, b0, t0) = blobs(0, 0);
    let mut bytes = write(&[(b0.clone(), t0)]);
    // MAGIC ‖ version ‖ net ‖ first_height ‖ count ‖ height ‖ block_len ‖ block ‖ tx_count
    const HEADER_LEN: usize = 8 + 4 + 1 + 8 + 8;
    let tx_count_at = HEADER_LEN + 8 + 4 + b0.len();
    bytes[tx_count_at..tx_count_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut reader = CorpusReader::open(Cursor::new(bytes)).expect("open");
    let refused = reader.next().expect_err("crafted count");
    assert!(
        matches!(
            refused,
            CorpusFault::IncompleteBodies {
                listed: 0,
                present,
                ..
            } if present == u32::MAX as usize
        ),
        "{refused}"
    );
}

#[test]
fn a_truncated_corpus_is_refused_by_count_not_read_as_a_short_chain() {
    let (_, b0, t0) = blobs(0, 0);
    let (_, b1, t1) = blobs(1, 0);
    let mut bytes = write(&[(b0, t0), (b1, t1)]);
    bytes.truncate(bytes.len() - 5);
    let mut reader = CorpusReader::open(Cursor::new(bytes)).expect("open");
    reader.next().expect("first is whole");
    let refused = reader.next().expect_err("truncated second");
    assert!(
        matches!(
            refused,
            CorpusFault::CountMismatch { .. } | CorpusFault::Io(_)
        ),
        "{refused}"
    );
}
