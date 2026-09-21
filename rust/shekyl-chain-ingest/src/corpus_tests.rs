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
            unlock_time: height.saturating_add(60),
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
            // Distinct per (height, index); heights past u8 fold onto their
            // low bits, which is fine for distinctness within one block.
            listed(0x80 + u8::try_from(i).expect("small") + (height % 0x40) as u8)
        })
        .collect();
    let block = Block {
        header: BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: 1_700_000_000u64.saturating_add(height),
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
    // MAGIC ‖ version ‖ net ‖ first_height ‖ count ‖ tag ‖ height ‖ block_len ‖ block ‖ tx_count
    const HEADER_LEN: usize = 8 + 4 + 1 + 8 + 8;
    let tx_count_at = HEADER_LEN + 1 + 8 + 4 + b0.len();
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

#[test]
fn height_exhaustion_is_a_fault_on_both_sides_and_writes_nothing() {
    // A corpus may legitimately hold height u64::MAX. What it cannot do is
    // carry a record after it — and a crafted header claiming to must be
    // refused at `open`, not after the reader has yielded one valid record.
    let last = BlockHeight::from_raw(u64::MAX);
    let (_, b_last, t_last) = blobs(u64::MAX, 0);
    let mut w =
        CorpusWriter::create(Cursor::new(Vec::new()), CorpusNet::Fakechain, last).expect("header");
    w.append(&b_last, &t_last)
        .expect("the last height is representable");
    let (_, b_more, t_more) = blobs(0, 0);
    let refused = w.append(&b_more, &t_more).expect_err("no height follows");
    assert!(
        matches!(refused, CorpusFault::HeightExhausted { after } if after == last),
        "{refused}"
    );
    let bytes = w.finish().expect("finish").into_inner();
    // One record, readable.
    let mut reader = CorpusReader::open(Cursor::new(bytes.clone())).expect("open");
    assert_eq!(reader.declared(), 1);
    reader
        .next()
        .expect("the u64::MAX record")
        .expect("present");
    assert!(reader.next().expect("clean end").is_none());
    // The same bytes with the header claiming two records: refused at open,
    // before any record is consulted.
    let mut crafted = bytes;
    crafted[21..29].copy_from_slice(&2u64.to_le_bytes());
    assert!(
        matches!(
            CorpusReader::open(Cursor::new(crafted)).err(),
            Some(CorpusFault::HeightExhausted { .. })
        ),
        "a header that outruns the height space is refused at open"
    );
}

// ---------------------------------------------------------------------------
// The rewind record (RD-Q13, §7 commit 8c)
// ---------------------------------------------------------------------------

#[test]
fn a_corpus_with_a_rewind_round_trips_as_events() {
    use crate::test_support::{corpus_of_reorg, reorg};
    let r = reorg(4, 1, 3);
    let bytes = corpus_of_reorg(&r);
    let mut reader = CorpusReader::open(Cursor::new(bytes)).expect("open");
    assert_eq!(
        reader.declared(),
        4 + 1 + 3,
        "count is records of both kinds"
    );
    let mut kinds = Vec::new();
    while let Some(ev) = reader.next().expect("event") {
        kinds.push(match ev.event {
            IngestEvent::Extend(c) => format!("E{}", c.block.transaction_hashes.len()),
            IngestEvent::Rewind { to } => format!("R{}", to.to_raw()),
        });
    }
    // main 0..=3 (genesis lists nothing, then one spend each), rewind to 1,
    // fork 2'..=4' (one spend each).
    assert_eq!(kinds, ["E0", "E1", "E1", "E1", "R1", "E1", "E1", "E1"]);
}

#[test]
fn a_rewind_must_be_backward_inside_the_corpus_and_after_a_block() {
    let (_, b0, t0) = blobs(0, 0);
    let (_, b1, t1) = blobs(1, 1);
    let (_, b2, t2) = blobs(2, 1);
    let mut w = CorpusWriter::create(
        Cursor::new(Vec::new()),
        CorpusNet::Fakechain,
        BlockHeight::from_raw(0),
    )
    .expect("header");
    assert!(matches!(
        w.rewind(BlockHeight::from_raw(0)).expect_err("no tip"),
        CorpusFault::RewindOnEmpty
    ));
    w.append(&b0, &t0).expect("0");
    w.append(&b1, &t1).expect("1");
    w.append(&b2, &t2).expect("2");
    let refused = w.rewind(BlockHeight::from_raw(2)).expect_err("tip");
    assert!(
        matches!(refused, CorpusFault::RewindNotBackward { to, tip } if to.to_raw() == 2 && tip.to_raw() == 2),
        "{refused}"
    );
    // A corpus starting at 5 cannot rewind to 4.
    let (_, b5, t5) = blobs(5, 0);
    let (_, b6, t6) = blobs(6, 0);
    let mut w5 = CorpusWriter::create(
        Cursor::new(Vec::new()),
        CorpusNet::Fakechain,
        BlockHeight::from_raw(5),
    )
    .expect("header");
    w5.append(&b5, &t5).expect("5");
    w5.append(&b6, &t6).expect("6");
    let refused = w5
        .rewind(BlockHeight::from_raw(4))
        .expect_err("below first");
    assert!(
        matches!(refused, CorpusFault::RewindOutOfCorpus { to, first_height } if to.to_raw() == 4 && first_height.to_raw() == 5),
        "{refused}"
    );
    // The reader applies the same law to a hand-built rewind-to-tip record,
    // and after a rewind the next extend must carry `to + 1`.
    w.rewind(BlockHeight::from_raw(1)).expect("backward");
    let mut bytes = w.finish().expect("count").into_inner();
    // Patch the rewind's `to` (last 8 bytes) to 2 = the tip it followed.
    let n = bytes.len();
    bytes[n - 8..].copy_from_slice(&2u64.to_le_bytes());
    let mut reader = CorpusReader::open(Cursor::new(bytes)).expect("open");
    let mut last = Ok(None);
    for _ in 0..4 {
        last = reader.next();
        if !matches!(last, Ok(Some(_))) {
            break;
        }
    }
    assert!(
        matches!(last, Err(CorpusFault::RewindNotBackward { .. })),
        "{last:?}"
    );
    // An unknown tag is refused as such.
    let mut junk = write(&[(b0.clone(), t0)]);
    const HEADER_LEN: usize = 8 + 4 + 1 + 8 + 8;
    junk[HEADER_LEN] = 0x7f;
    let mut reader = CorpusReader::open(Cursor::new(junk)).expect("open");
    assert!(matches!(
        reader.next().expect_err("tag"),
        CorpusFault::UnknownTag(0x7f)
    ));
}
