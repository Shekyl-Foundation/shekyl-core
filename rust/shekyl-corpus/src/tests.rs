// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The codec's own laws: what the writer refuses, what the reader
//! re-derives, and where each refusal names itself. A replay's view of the
//! same records (sequence numbers, events, the bundle section on the
//! candidate) is `shekyl-chain-ingest`'s `corpus_tests`.

use std::io::Cursor;

use shekyl_network::Network;
use shekyl_types::{BlockHash, BlockHeight, CurveTreeRoot, SectionRoot};
use shekyl_wire::block::MAX_BLOCK_BLOB_SIZE;
use shekyl_wire::{Block, BlockHeader, Ct, CtBase, Input, Output, Transaction, TxPrefix};

use super::*;

/// A wire-valid transaction distinguishable by `tag`: one `Input::Gen`
/// (the shape the wire demands of a miner transaction) and one output.
/// The codec parses; it does not judge, so a body of the same shape
/// serves as a listed transaction.
fn tagged(tag: u64) -> Transaction {
    let byte = tag.to_le_bytes()[0];
    Transaction {
        prefix: TxPrefix {
            unlock_time: TxPrefix::NO_UNLOCK_TIME,
            inputs: vec![Input::Gen(tag)],
            outputs: vec![Output {
                amount: 0,
                key: [byte; 32],
                view_tag: byte,
            }],
            extra: Vec::new(),
        },
        ct: Ct::Null(CtBase {
            enc_amounts: vec![[byte; 9]],
            enc_labels: vec![[byte; 9]],
            commitments: vec![[byte; 32]],
        }),
    }
}

std::thread_local! {
    /// The block [`blobs`] built last at each height, on this test's
    /// thread: the parent of the next block it builds one height above.
    static BUILT: std::cell::RefCell<std::collections::HashMap<u64, BlockHash>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

/// The parent a block at `height` names when a test builds it in order:
/// the block [`blobs`] built last one height below, or a fixed hash for a
/// test's first block (a corpus's first `extend` follows whatever it
/// names).
fn parent_below(height: u64) -> BlockHash {
    height
        .checked_sub(1)
        .and_then(|below| BUILT.with(|built| built.borrow().get(&below).copied()))
        .unwrap_or_else(|| BlockHash::from_bytes([0x11; 32]))
}

/// A block at `height` listing `n` bodies, as a source hands it over: the
/// block blob and the bodies' blobs in header order, with the parsed
/// record they make. Its parent is the block this thread built last one
/// height below, so blocks built in height order form a chain the
/// lineage law accepts; a rebuilt height replaces the one before.
fn blobs(height: BlockHeight, n: u64) -> (Extend, Vec<u8>, Vec<Vec<u8>>) {
    let built = on(parent_below(height.to_raw()), height, n);
    BUILT.with(|map| {
        map.borrow_mut()
            .insert(height.to_raw(), built.0.block.hash())
    });
    built
}

/// [`blobs`]'s block, on `parent`, not recorded as built.
fn on(parent: BlockHash, height: BlockHeight, n: u64) -> (Extend, Vec<u8>, Vec<Vec<u8>>) {
    let raw = height.to_raw();
    // Distinct per (height, index) within a block.
    let bodies: Vec<Transaction> = (0..n)
        .map(|i| tagged(0x1_0000 + i + (raw % 0x40) * 0x100))
        .collect();
    let block = Block {
        header: BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: 1_700_000_000u64.saturating_add(raw),
            previous: parent,
            nonce: 7,
            curve_tree_root: CurveTreeRoot::from_bytes([0x22; 32]),
            section_root: SectionRoot::from_bytes([0x33; 32]),
        },
        miner_transaction: tagged(raw),
        transaction_hashes: bodies.iter().map(Transaction::hash).collect(),
    };
    let block_blob = block.serialize();
    let tx_blobs = bodies.iter().map(Transaction::serialize).collect();
    let record = Extend {
        height,
        block,
        transactions: bodies,
        bundle_references: None,
        bundle_bodies: Vec::new(),
    };
    (record, block_blob, tx_blobs)
}

fn write(records: &[(Vec<u8>, Vec<Vec<u8>>)]) -> Vec<u8> {
    let mut w = CorpusWriter::create(Cursor::new(Vec::new()), Network::Regtest, BlockHeight::ZERO)
        .expect("header");
    for (block, txs) in records {
        w.append(block, txs).expect("verified record");
    }
    w.finish().expect("finish").into_inner()
}

fn extend(record: Option<Record>) -> Extend {
    match record {
        Some(Record::Extend(extend)) => *extend,
        other => panic!("an extend record, not {other:?}"),
    }
}

#[test]
fn records_round_trip_in_height_order() {
    let (r0, b0, t0) = blobs(BlockHeight::from_raw(0), 0);
    let (r1, b1, t1) = blobs(BlockHeight::from_raw(1), 2);
    let (r2, b2, t2) = blobs(BlockHeight::from_raw(2), 1);
    let bytes = write(&[(b0, t0), (b1, t1), (b2, t2)]);

    let mut reader = CorpusReader::open(Cursor::new(bytes)).expect("open");
    assert_eq!(reader.net(), Network::Regtest);
    assert_eq!(reader.first_height(), BlockHeight::ZERO);
    assert_eq!(reader.declared(), 3);
    assert_eq!(extend(reader.next_record().expect("0")), r0);
    assert_eq!(extend(reader.next_record().expect("1")), r1);
    assert_eq!(extend(reader.next_record().expect("2")), r2);
    assert!(reader.next_record().expect("clean end").is_none());
}

#[test]
fn the_writer_refuses_a_pruned_sources_shortfall_by_height() {
    // RD-F15: a pruned node returns fewer bodies than the header lists and
    // says nothing. The writer says it, naming the height, and writes no
    // record for it.
    let (_, b0, t0) = blobs(BlockHeight::from_raw(0), 0);
    let (_, b1, mut t1) = blobs(BlockHeight::from_raw(1), 2);
    t1.pop();
    let mut w = CorpusWriter::create(Cursor::new(Vec::new()), Network::Testnet, BlockHeight::ZERO)
        .expect("header");
    w.append(&b0, &t0).expect("genesis");
    let refused = w.append(&b1, &t1).expect_err("one body short");
    assert!(
        matches!(
            refused,
            CorpusFault::IncompleteBodies {
                at,
                listed: 2,
                present: 1
            } if at == RecordAt::Height(BlockHeight::from_raw(1))
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
    let (_, mut block, txs) = blobs(BlockHeight::from_raw(0), 0);
    block.push(0x00);
    let mut w = CorpusWriter::create(Cursor::new(Vec::new()), Network::Regtest, BlockHeight::ZERO)
        .expect("header");
    let refused = w.append(&block, &txs).expect_err("padded block");
    assert!(
        matches!(refused, CorpusFault::Malformed { what: "block", .. }),
        "{refused}"
    );

    let (_, block, mut txs) = blobs(BlockHeight::from_raw(0), 1);
    txs[0].push(0x00);
    let mut w = CorpusWriter::create(Cursor::new(Vec::new()), Network::Mainnet, BlockHeight::ZERO)
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
    let (_, b, mut t) = blobs(BlockHeight::from_raw(0), 2);
    t.swap(0, 1);
    let mut w = CorpusWriter::create(Cursor::new(Vec::new()), Network::Mainnet, BlockHeight::ZERO)
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
    let (_, b0, t0) = blobs(BlockHeight::from_raw(0), 0);
    let (_, b1, t1) = blobs(BlockHeight::from_raw(1), 1);
    let body = t1.last().expect("block 1 lists a transaction").clone();
    let mut bytes = write(&[(b0, t0), (b1, t1)]);
    // Flip the last byte of the second record's only body. The body is not
    // the file's last bytes since format 4: the record's bundle section
    // follows it.
    let at_byte = bytes
        .windows(body.len())
        .rposition(|window| window == body.as_slice())
        .expect("the body is in the second record")
        + body.len()
        - 1;
    bytes[at_byte] ^= 0x01;
    let mut reader = CorpusReader::open(Cursor::new(bytes)).expect("open");
    reader.next_record().expect("genesis is intact");
    let refused = reader.next_record().expect_err("tampered");
    assert!(
        matches!(
            refused,
            CorpusFault::BodyMismatch { .. } | CorpusFault::Malformed { .. }
        ),
        "{refused}"
    );
}

#[test]
fn the_reader_refuses_a_foreign_magic_a_foreign_version_and_an_unknown_net() {
    let (_, b0, t0) = blobs(BlockHeight::from_raw(0), 0);
    let bytes = write(&[(b0, t0)]);
    let mut wrong_magic = bytes.clone();
    wrong_magic[0] ^= 0xff;
    assert!(matches!(
        CorpusReader::open(Cursor::new(wrong_magic)).err(),
        Some(CorpusFault::BadMagic)
    ));
    let mut wrong_version = bytes.clone();
    wrong_version[VERSION_AT..NET_AT].copy_from_slice(&(CORPUS_FORMAT_VERSION + 1).to_le_bytes());
    assert!(matches!(
        CorpusReader::open(Cursor::new(wrong_version)).err(),
        Some(CorpusFault::UnsupportedVersion { found }) if found == CORPUS_FORMAT_VERSION + 1
    ));
    // Layout 4 is the one older layout read (`CF-R7`); the one before it is
    // refused.
    let older = as_layout(bytes.clone(), LAYOUT_4 - 1);
    assert!(matches!(
        CorpusReader::open(Cursor::new(older)).err(),
        Some(CorpusFault::UnsupportedVersion { found }) if found == LAYOUT_4 - 1
    ));
    let mut wrong_net = bytes;
    wrong_net[12] = 0xff;
    assert!(Network::from_code(0xff).is_none(), "0xff names no network");
    assert!(matches!(
        CorpusReader::open(Cursor::new(wrong_net)).err(),
        Some(CorpusFault::UnknownNet(0xff))
    ));
}

#[test]
fn an_unfinished_corpus_is_refused_by_count() {
    // Write two records but never `finish`: the header still says zero.
    let (_, b0, t0) = blobs(BlockHeight::from_raw(0), 0);
    let (_, b1, t1) = blobs(BlockHeight::from_raw(1), 0);
    let mut w = CorpusWriter::create(
        Cursor::new(Vec::new()),
        Network::Stagenet,
        BlockHeight::ZERO,
    )
    .expect("header");
    w.append(&b0, &t0).expect("one");
    w.append(&b1, &t1).expect("two");
    // Take the bytes without `finish`: the header still says zero.
    let bytes = w.into_unfinished().into_inner();
    let mut reader = CorpusReader::open(Cursor::new(bytes)).expect("open");
    let refused = reader
        .next_record()
        .expect_err("declared 0, records present");
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
    let (_, b0, t0) = blobs(BlockHeight::from_raw(0), 0);
    let mut bytes = write(&[(b0.clone(), t0)]);
    // header ‖ tag ‖ height ‖ block_len ‖ block ‖ tx_count
    let tx_count_at = HEADER_LEN + TAG_LEN + HEIGHT_LEN + LEN_PREFIX + b0.len();
    bytes[tx_count_at..tx_count_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut reader = CorpusReader::open(Cursor::new(bytes)).expect("open");
    let refused = reader.next_record().expect_err("crafted count");
    assert!(
        matches!(
            refused,
            CorpusFault::IncompleteBodies {
                listed: 0,
                present,
                ..
            } if present == usize::try_from(u32::MAX).expect("u32 fits usize")
        ),
        "{refused}"
    );
}

#[test]
fn a_truncated_corpus_is_refused_by_count_not_read_as_a_short_chain() {
    // Wherever the cut falls inside the second record — its tag, its
    // height, its body — the reader names one whole record present, never
    // a bare I/O error that reads as a broken disk.
    let (_, b0, t0) = blobs(BlockHeight::from_raw(0), 0);
    let (_, b1, t1) = blobs(BlockHeight::from_raw(1), 0);
    let whole = write(&[(b0.clone(), t0.clone()), (b1, t1)]);
    let first_record_end = write(&[(b0, t0)]).len();
    for keep in [
        first_record_end,     // cut before the second record's tag
        first_record_end + 1, // inside its height
        first_record_end + 4, // still inside its height
        whole.len() - 5,      // inside its body
    ] {
        let mut reader = CorpusReader::open(Cursor::new(whole[..keep].to_vec())).expect("open");
        reader.next_record().expect("first is whole");
        let refused = reader.next_record().expect_err("truncated second");
        assert!(
            matches!(
                refused,
                CorpusFault::CountMismatch {
                    declared: 2,
                    present: 1
                }
            ),
            "cut at {keep}: {refused}"
        );
    }
    // And bytes past the declared end are a count mismatch too.
    let mut longer = write(&[(blobs(BlockHeight::from_raw(0), 0).1, Vec::new())]);
    longer.push(tag::EXTEND);
    let mut reader = CorpusReader::open(Cursor::new(longer)).expect("open");
    reader.next_record().expect("the declared record");
    assert!(matches!(
        reader.next_record(),
        Err(CorpusFault::CountMismatch {
            declared: 1,
            present: 2
        })
    ));
}

#[test]
fn a_record_must_carry_the_next_height() {
    let (_, b0, t0) = blobs(BlockHeight::from_raw(0), 0);
    let (_, b1, t1) = blobs(BlockHeight::from_raw(1), 0);
    let mut bytes = write(&[(b0.clone(), t0), (b1, t1)]);
    // The second record's height, patched from 1 to 5.
    // First record (no bodies): tag, height, block length, block, tx count,
    // reference count. Then the next record's tag, then its height.
    let first_record_len = TAG_LEN + HEIGHT_LEN + LEN_PREFIX + b0.len() + LEN_PREFIX + LEN_PREFIX;
    let second_height_at = HEADER_LEN + first_record_len + TAG_LEN;
    bytes[second_height_at..second_height_at + 8].copy_from_slice(&5u64.to_le_bytes());
    let mut reader = CorpusReader::open(Cursor::new(bytes)).expect("open");
    reader.next_record().expect("first");
    let refused = reader.next_record().expect_err("a gap");
    assert!(
        matches!(refused, CorpusFault::HeightGap { expected, found } if expected == BlockHeight::from_raw(1) && found == BlockHeight::from_raw(5)),
        "{refused}"
    );
}

#[test]
fn height_exhaustion_is_a_fault_on_both_sides_and_writes_nothing() {
    // A corpus may legitimately hold height u64::MAX. What it cannot do is
    // carry an `extend` after it: the writer refuses the append, and the
    // reader refuses that extend once its tag is read, before its height.
    // (The header's count cannot say this at `open` — a `rewind`
    // occupies no height, so the count is not a span.)
    let last = BlockHeight::from_raw(u64::MAX);
    let (_, b_last, t_last) = blobs(last, 0);
    let mut w =
        CorpusWriter::create(Cursor::new(Vec::new()), Network::Regtest, last).expect("header");
    w.append(&b_last, &t_last)
        .expect("the last height is representable");
    let (_, b_more, t_more) = blobs(BlockHeight::from_raw(0), 0);
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
        .next_record()
        .expect("the u64::MAX record")
        .expect("present");
    assert!(reader.next_record().expect("clean end").is_none());
    // The same bytes with a second `extend` record spliced in and the
    // header claiming two: the first reads, the second is refused before
    // its height is read — as HeightExhausted, not as a gap at some
    // wrapped height.
    let mut crafted = bytes.clone();
    crafted.extend_from_slice(&bytes[HEADER_LEN..]);
    let count_at = COUNT_OFFSET;
    crafted[count_at..count_at + COUNT_LEN].copy_from_slice(&2u64.to_le_bytes());
    let mut reader = CorpusReader::open(Cursor::new(crafted)).expect("open");
    reader.next_record().expect("first").expect("present");
    let refused = reader.next_record().expect_err("no height follows");
    assert!(
        matches!(refused, CorpusFault::HeightExhausted { after } if after == last),
        "{refused}"
    );
    // The tag alone is enough. No height follows it, and the fault is still
    // exhaustion: the reader does not need those bytes to refuse.
    let mut tag_only = bytes;
    tag_only.push(tag::EXTEND);
    tag_only[count_at..count_at + COUNT_LEN].copy_from_slice(&2u64.to_le_bytes());
    let mut reader = CorpusReader::open(Cursor::new(tag_only)).expect("open");
    reader.next_record().expect("first").expect("present");
    assert!(matches!(
        reader.next_record(),
        Err(CorpusFault::HeightExhausted { after }) if after == last
    ));
    // A writer near the top with a rewind: three records over two heights,
    // and the reader takes them — the count is records, not a span.
    let (_, b_prev, t_prev) = blobs(BlockHeight::from_raw(u64::MAX - 1), 0);
    // Built again on `b_prev`, so the two form a chain.
    let (_, b_last, t_last) = blobs(last, 0);
    let mut w = CorpusWriter::create(
        Cursor::new(Vec::new()),
        Network::Regtest,
        BlockHeight::from_raw(u64::MAX - 1),
    )
    .expect("header");
    w.append(&b_prev, &t_prev).expect("MAX - 1");
    w.append(&b_last, &t_last).expect("MAX");
    w.rewind(BlockHeight::from_raw(u64::MAX - 1))
        .expect("backward, inside the corpus");
    let bytes = w.finish().expect("finish").into_inner();
    let mut reader = CorpusReader::open(Cursor::new(bytes)).expect("three records, two heights");
    assert_eq!(reader.declared(), 3);
    let mut n = 0;
    while reader.next_record().expect("record").is_some() {
        n += 1;
    }
    assert_eq!(n, 3);
}

#[test]
fn a_rewind_must_be_backward_inside_the_corpus_and_after_a_block() {
    let (_, b0, t0) = blobs(BlockHeight::from_raw(0), 0);
    let (_, b1, t1) = blobs(BlockHeight::from_raw(1), 1);
    let (_, b2, t2) = blobs(BlockHeight::from_raw(2), 1);
    let mut w = CorpusWriter::create(
        Cursor::new(Vec::new()),
        Network::Regtest,
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
        matches!(refused, CorpusFault::RewindNotBackward { to, tip } if to == BlockHeight::from_raw(2) && tip == BlockHeight::from_raw(2)),
        "{refused}"
    );
    // A corpus starting at 5 cannot rewind to 4.
    let (_, b5, t5) = blobs(BlockHeight::from_raw(5), 0);
    let (_, b6, t6) = blobs(BlockHeight::from_raw(6), 0);
    let mut w5 = CorpusWriter::create(
        Cursor::new(Vec::new()),
        Network::Regtest,
        BlockHeight::from_raw(5),
    )
    .expect("header");
    w5.append(&b5, &t5).expect("5");
    w5.append(&b6, &t6).expect("6");
    let refused = w5
        .rewind(BlockHeight::from_raw(4))
        .expect_err("below first");
    assert!(
        matches!(refused, CorpusFault::RewindOutOfCorpus { to, first_height } if to == BlockHeight::from_raw(4) && first_height == BlockHeight::from_raw(5)),
        "{refused}"
    );
    // The reader yields a rewind as a record, and after it the next extend
    // must carry `to + 1`.
    w.rewind(BlockHeight::from_raw(1)).expect("backward");
    let (_, b2_again, t2_again) = blobs(BlockHeight::from_raw(2), 0);
    w.append(&b2_again, &t2_again)
        .expect("2 again, after the rewind");
    let bytes = w.finish().expect("count").into_inner();
    let mut reader = CorpusReader::open(Cursor::new(bytes.clone())).expect("open");
    for _ in 0..3 {
        extend(reader.next_record().expect("a block"));
    }
    assert_eq!(
        reader.next_record().expect("the rewind"),
        Some(Record::Rewind {
            to: BlockHeight::from_raw(1)
        })
    );
    assert_eq!(
        extend(reader.next_record().expect("2 again")).height,
        BlockHeight::from_raw(2)
    );
    assert!(reader.next_record().expect("clean end").is_none());
    // The reader applies the writer's law to a hand-built rewind-to-tip
    // record: patch the rewind's `to` (the 8 bytes after its tag) to 2,
    // the tip it followed.
    // tag ‖ height ‖ block_len ‖ block ‖ tx_count ‖ ref_count
    let last_extend_len =
        TAG_LEN + HEIGHT_LEN + LEN_PREFIX + b2_again.len() + LEN_PREFIX + LEN_PREFIX;
    let rewind_at = bytes
        .len()
        .checked_sub(last_extend_len + REWIND_RECORD_LEN)
        .expect("the rewind precedes the last extend");
    assert_eq!(bytes[rewind_at], tag::REWIND);
    let mut patched = bytes;
    patched[rewind_at + TAG_LEN..rewind_at + TAG_LEN + HEIGHT_LEN]
        .copy_from_slice(&2u64.to_le_bytes());
    let mut reader = CorpusReader::open(Cursor::new(patched)).expect("open");
    for _ in 0..3 {
        reader.next_record().expect("a block");
    }
    assert!(
        matches!(
            reader.next_record(),
            Err(CorpusFault::RewindNotBackward { .. })
        ),
        "a rewind to the tip"
    );
    // An unknown tag is refused as such, in layout 5 and in layout 4:
    // `0x03` (version 3's out-of-band serve-credit record) is unknown to
    // both.
    for layout in [CORPUS_FORMAT_VERSION, LAYOUT_4] {
        for unknown in [0x03, 0x7f] {
            let mut junk = as_layout(write(&[(b0.clone(), t0.clone())]), layout);
            junk[HEADER_LEN] = unknown;
            let mut reader = CorpusReader::open(Cursor::new(junk)).expect("open");
            let refused = reader.next_record().expect_err("tag");
            assert!(
                matches!(refused, CorpusFault::UnknownTag(t) if t == unknown),
                "layout {layout}, {unknown:#04x}: {refused:?}"
            );
        }
    }
}

/// `bytes` with its header's layout version set to `layout`.
fn as_layout(mut bytes: Vec<u8>, layout: u32) -> Vec<u8> {
    bytes[VERSION_AT..NET_AT].copy_from_slice(&layout.to_le_bytes());
    bytes
}

/// An alternative to the block [`blobs`] builds at `height`: the same
/// bodies under another nonce, so another block at that height.
fn alternative(height: BlockHeight, n: u64) -> (Offer, Vec<u8>, Vec<Vec<u8>>) {
    let (extend, _, tx_blobs) = on(parent_below(height.to_raw()), height, n);
    let mut block = extend.block;
    block.header.nonce = block.header.nonce.wrapping_add(1);
    let block_blob = block.serialize();
    let offer = Offer {
        block,
        transactions: extend.transactions,
        bundle_references: None,
        bundle_bodies: Vec::new(),
    };
    (offer, block_blob, tx_blobs)
}

#[test]
fn an_offer_round_trips_between_extends_and_does_not_move_the_height_law() {
    let (r0, b0, t0) = blobs(BlockHeight::from_raw(0), 0);
    let (r1, b1, t1) = blobs(BlockHeight::from_raw(1), 2);
    let (o1, ob1, ot1) = alternative(BlockHeight::from_raw(1), 2);
    let (r2, b2, t2) = blobs(BlockHeight::from_raw(2), 1);
    let mut w = CorpusWriter::create(Cursor::new(Vec::new()), Network::Regtest, BlockHeight::ZERO)
        .expect("header");
    w.append(&b0, &t0).expect("0");
    w.append(&b1, &t1).expect("1");
    w.offer(&ob1, &ot1, &[], &[]).expect("the offer");
    // The offer did not move the tip: the next extend is still height 2.
    w.append(&b2, &t2).expect("2");
    let bytes = w.finish().expect("finish").into_inner();

    let mut reader = CorpusReader::open(Cursor::new(bytes)).expect("open");
    assert_eq!(reader.layout(), CORPUS_FORMAT_VERSION);
    assert_eq!(reader.declared(), 4, "an offer is a record");
    assert_eq!(extend(reader.next_record().expect("0")), r0);
    assert_eq!(extend(reader.next_record().expect("1")), r1);
    match reader.next_record().expect("the offer") {
        Some(Record::Offer(offer)) => assert_eq!(*offer, o1),
        other => panic!("an offer record, not {other:?}"),
    }
    assert_eq!(extend(reader.next_record().expect("2")), r2);
    assert!(reader.next_record().expect("clean end").is_none());
}

#[test]
fn an_offers_bodies_are_verified_on_both_sides_naming_its_record() {
    // RD-F15 holds for an offer as for an extend: the writer refuses a
    // shortfall and writes nothing, and the reader refuses a tampered body;
    // each names the offer by its place among the records.
    let (_, b0, t0) = blobs(BlockHeight::from_raw(0), 0);
    let (_, b1, t1) = blobs(BlockHeight::from_raw(1), 2);
    let (_, ob1, ot1) = alternative(BlockHeight::from_raw(1), 2);
    let mut w = CorpusWriter::create(Cursor::new(Vec::new()), Network::Regtest, BlockHeight::ZERO)
        .expect("header");
    w.append(&b0, &t0).expect("0");
    w.append(&b1, &t1).expect("1");
    let short = &ot1[..1];
    let refused = w.offer(&ob1, short, &[], &[]).expect_err("one body short");
    assert!(
        matches!(
            refused,
            CorpusFault::IncompleteBodies {
                at: RecordAt::Offer { record: 2 },
                listed: 2,
                present: 1
            }
        ),
        "{refused}"
    );
    w.offer(&ob1, &ot1, &[], &[]).expect("the whole offer");
    let mut bytes = w.finish().expect("finish").into_inner();

    // The offer's last body's last byte, flipped: it no longer hashes to
    // what the header lists.
    let last = bytes.len() - LEN_PREFIX - 1;
    bytes[last] ^= 0x01;
    let mut reader = CorpusReader::open(Cursor::new(bytes)).expect("open");
    reader.next_record().expect("0");
    reader.next_record().expect("1");
    let refused = reader.next_record().expect_err("a tampered body");
    assert!(
        matches!(
            refused,
            CorpusFault::BodyMismatch {
                at: RecordAt::Offer { record: 2 },
                index: 1,
                ..
            } | CorpusFault::Malformed {
                at: RecordAt::Offer { record: 2 },
                ..
            }
        ),
        "{refused:?}"
    );
}

#[test]
fn a_layout_4_corpus_is_read_and_an_offer_in_it_is_an_unknown_tag() {
    // CF-R7: the reader reads layout 4 until the last layout-4 corpus is
    // gone. Layout 4 has no `offer`, so a layout-4 corpus carrying tag
    // 0x04 is refused as an unknown tag.
    let (r0, b0, t0) = blobs(BlockHeight::from_raw(0), 0);
    let (r1, b1, t1) = blobs(BlockHeight::from_raw(1), 2);
    let old = as_layout(
        write(&[(b0.clone(), t0.clone()), (b1.clone(), t1.clone())]),
        LAYOUT_4,
    );
    let mut reader = CorpusReader::open(Cursor::new(old)).expect("a layout-4 corpus opens");
    assert_eq!(reader.layout(), LAYOUT_4);
    assert_eq!(extend(reader.next_record().expect("0")), r0);
    assert_eq!(extend(reader.next_record().expect("1")), r1);
    assert!(reader.next_record().expect("clean end").is_none());

    let (_, ob1, ot1) = alternative(BlockHeight::from_raw(1), 2);
    let mut w = CorpusWriter::create(Cursor::new(Vec::new()), Network::Regtest, BlockHeight::ZERO)
        .expect("header");
    w.append(&b0, &t0).expect("0");
    w.offer(&ob1, &ot1, &[], &[]).expect("the offer");
    let carrying = as_layout(w.finish().expect("finish").into_inner(), LAYOUT_4);
    let mut reader = CorpusReader::open(Cursor::new(carrying)).expect("open");
    reader.next_record().expect("0");
    let refused = reader.next_record().expect_err("no offer in layout 4");
    assert!(
        matches!(refused, CorpusFault::UnknownTag(t) if t == tag::OFFER),
        "{refused:?}"
    );
}

#[test]
fn an_oversized_length_is_refused_before_it_is_read() {
    let (_, b0, t0) = blobs(BlockHeight::from_raw(0), 0);
    let mut bytes = write(&[(b0, t0)]);
    // The first record's `block_len`.
    let block_len_at = HEADER_LEN + TAG_LEN + HEIGHT_LEN;
    let claimed = u32::try_from(MAX_BLOCK_BLOB_SIZE + 1).expect("the cap fits u32");
    bytes[block_len_at..block_len_at + 4].copy_from_slice(&claimed.to_le_bytes());
    let mut reader = CorpusReader::open(Cursor::new(bytes)).expect("open");
    assert!(matches!(
        reader.next_record(),
        Err(CorpusFault::Oversized { what: "block", len }) if len == u64::from(claimed)
    ));
}

/// A competing block at `height` on `parent`, no bodies: [`on`]'s block
/// under another nonce, so another id than the chain's block there.
fn rival(parent: BlockHash, height: BlockHeight) -> (Block, Vec<u8>) {
    let (extend, _, _) = on(parent, height, 0);
    let mut block = extend.block;
    block.header.nonce = block.header.nonce.wrapping_add(1);
    let blob = block.serialize();
    (block, blob)
}

/// One `extend` record as the layout writes it, for a corpus the writer
/// would refuse: the reader must refuse it on its own.
fn raw_extend(height: u64, block: &[u8]) -> Vec<u8> {
    let mut record = vec![tag::EXTEND];
    record.extend_from_slice(&height.to_le_bytes());
    record.extend_from_slice(&u32::try_from(block.len()).expect("small").to_le_bytes());
    record.extend_from_slice(block);
    record.extend_from_slice(&0u32.to_le_bytes()); // no listed bodies
    record.extend_from_slice(&0u32.to_le_bytes()); // no bundle section
    record
}

/// A corpus of hand-encoded `records` from height 0.
fn raw_corpus(records: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = header::encode(
        Network::Regtest,
        BlockHeight::ZERO,
        u64::try_from(records.len()).expect("small"),
    )
    .to_vec();
    for record in records {
        bytes.extend_from_slice(record);
    }
    bytes
}

#[test]
fn an_extend_may_follow_an_offered_block_and_that_branch_is_the_chain_after() {
    // Main 0..=2; a branch of three offered on block 0 (1', 2', 3'); then
    // the first block after the switch, 4', on 3', and 5' on 4'. The writer
    // takes them and the reader yields them, 4' at the height one past its
    // offered parent.
    let (e0, b0, t0) = blobs(BlockHeight::from_raw(0), 0);
    let (_, b1, t1) = blobs(BlockHeight::from_raw(1), 0);
    let (_, b2, t2) = blobs(BlockHeight::from_raw(2), 0);
    let (o1, ob1) = rival(e0.block.hash(), BlockHeight::from_raw(1));
    let (o2, ob2) = rival(o1.hash(), BlockHeight::from_raw(2));
    let (o3, ob3) = rival(o2.hash(), BlockHeight::from_raw(3));
    let (after, _, _) = on(o3.hash(), BlockHeight::from_raw(4), 0);
    let (next, _, _) = on(after.block.hash(), BlockHeight::from_raw(5), 0);
    let mut w = CorpusWriter::create(Cursor::new(Vec::new()), Network::Regtest, BlockHeight::ZERO)
        .expect("header");
    w.append(&b0, &t0).expect("0");
    w.append(&b1, &t1).expect("1");
    w.append(&b2, &t2).expect("2");
    for blob in [&ob1, &ob2, &ob3] {
        w.offer(blob, &[], &[], &[]).expect("an offer");
    }
    w.append(&after.block.serialize(), &[])
        .expect("an extend on the offered branch's tip");
    w.append(&next.block.serialize(), &[])
        .expect("an extend on the tip after it");
    let bytes = w.finish().expect("finish").into_inner();

    let mut reader = CorpusReader::open(Cursor::new(bytes)).expect("open");
    for _ in 0..6 {
        reader.next_record().expect("a record").expect("present");
    }
    let followed = extend(reader.next_record().expect("4'"));
    assert_eq!(followed.height, BlockHeight::from_raw(4));
    assert_eq!(followed.block, after.block);
    assert_eq!(
        extend(reader.next_record().expect("5'")).height,
        BlockHeight::from_raw(5)
    );
    assert!(reader.next_record().expect("clean end").is_none());
}

#[test]
fn an_extend_that_follows_neither_the_tip_nor_an_offer_is_refused_on_both_sides() {
    let (e0, b0, t0) = blobs(BlockHeight::from_raw(0), 0);
    let (_, b1, t1) = blobs(BlockHeight::from_raw(1), 0);
    // A block at 2 on block 0, which is neither the tip (1) nor offered.
    let (stray, _, _) = on(e0.block.hash(), BlockHeight::from_raw(2), 0);
    let stray_blob = stray.block.serialize();

    let mut w = CorpusWriter::create(Cursor::new(Vec::new()), Network::Regtest, BlockHeight::ZERO)
        .expect("header");
    w.append(&b0, &t0).expect("0");
    w.append(&b1, &t1).expect("1");
    let refused = w.append(&stray_blob, &[]).expect_err("follows neither");
    assert!(
        matches!(
            refused,
            CorpusFault::ExtendUnfollowed { height, parent }
                if height == BlockHeight::from_raw(2) && parent == e0.block.hash()
        ),
        "{refused}"
    );

    // The reader refuses the same record on its own.
    let bytes = raw_corpus(&[
        raw_extend(0, &b0),
        raw_extend(1, &b1),
        raw_extend(2, &stray_blob),
    ]);
    let mut reader = CorpusReader::open(Cursor::new(bytes)).expect("open");
    reader.next_record().expect("0");
    reader.next_record().expect("1");
    let refused = reader.next_record().expect_err("follows neither");
    assert!(
        matches!(refused, CorpusFault::ExtendUnfollowed { .. }),
        "{refused:?}"
    );
}

#[test]
fn an_extend_on_an_offered_block_carries_the_height_one_past_it() {
    // An extend on the offered 1' must be at 2; one that says 3 is a gap.
    let (e0, b0, _) = blobs(BlockHeight::from_raw(0), 0);
    let (_, b1, _) = blobs(BlockHeight::from_raw(1), 0);
    let (o1, ob1) = rival(e0.block.hash(), BlockHeight::from_raw(1));
    let (after, _, _) = on(o1.hash(), BlockHeight::from_raw(2), 0);
    let mut offer = vec![tag::OFFER];
    offer.extend_from_slice(&u32::try_from(ob1.len()).expect("small").to_le_bytes());
    offer.extend_from_slice(&ob1);
    offer.extend_from_slice(&0u32.to_le_bytes());
    offer.extend_from_slice(&0u32.to_le_bytes());
    let bytes = raw_corpus(&[
        raw_extend(0, &b0),
        raw_extend(1, &b1),
        offer,
        raw_extend(3, &after.block.serialize()),
    ]);
    let mut reader = CorpusReader::open(Cursor::new(bytes)).expect("open");
    for _ in 0..3 {
        reader.next_record().expect("a record");
    }
    assert!(matches!(
        reader.next_record(),
        Err(CorpusFault::HeightGap { expected, found })
            if expected == BlockHeight::from_raw(2) && found == BlockHeight::from_raw(3)
    ));
}
