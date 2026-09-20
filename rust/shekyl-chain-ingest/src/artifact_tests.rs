// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The two artifacts (§3.9): round trips, pinned layout facts, and every
//! refusal observed — in particular RD-F15's, a pruned source's shortfall.

use std::io::Cursor;

use shekyl_chain_store::digest_v0::LogicalStateDigestV0;
use shekyl_chain_store::store::{ConnectFacts, Origin};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{
    AttestationRoot, BlockHash, BlockHeight, BlockWeight, CurveTreeRoot, LongTermWeight,
};
use shekyl_units::AtomicUnits;
use shekyl_wire::{Block, BlockHeader, Ct, CtBase, Input, Output, Transaction, TxPrefix};

use crate::corpus::{CorpusFault, CorpusReader, CorpusWriter, CORPUS_MAGIC, CORPUS_VERSION};
use crate::source::{IngestEvent, Seq, Source};
use crate::trace::{Facts, Trace, TraceFault, TraceWriter, CHECKPOINT_LEN, FACTS_LEN, TRACE_MAGIC};

// ---------------------------------------------------------------- fixtures

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

fn spend(key_image: u8) -> Transaction {
    Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![Input::ToKey {
                amount: 0,
                key_offsets: Vec::new(),
                key_image: [key_image; 32],
            }],
            outputs: vec![Output {
                amount: 0,
                key: [0x80; 32],
                view_tag: 2,
            }],
            extra: Vec::new(),
        },
        ct: Ct::Fcmp {
            fee: 7,
            reference_block: BlockHash::from_bytes([0x99; 32]),
            base: CtBase {
                enc_amounts: vec![[0x11; 9]],
                enc_labels: vec![[0x22; 9]],
                commitments: vec![[0xa0; 32]],
            },
            pqc_auths: Vec::new(),
            prunable: None,
        },
    }
}

fn block(height: u64, previous: BlockHash, listed: &[Transaction]) -> Block {
    let tag = u8::try_from(height).expect("small fixture height");
    Block {
        header: BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: 1_000 + height * 60,
            previous,
            nonce: 7,
            curve_tree_root: CurveTreeRoot::from_bytes([0xc0 + tag; 32]),
            attestation_root: AttestationRoot::from_bytes([0x33; 32]),
        },
        miner_transaction: coinbase(height),
        transaction_hashes: listed.iter().map(Transaction::hash).collect(),
    }
}

/// Three blocks: genesis (no listed txs), one spend, two spends — as the
/// network carries them: (block bytes, body bytes).
fn three_blocks() -> Vec<(Vec<u8>, Vec<Vec<u8>>)> {
    let listed: [Vec<Transaction>; 3] = [vec![], vec![spend(1)], vec![spend(2), spend(3)]];
    let mut previous = BlockHash::NULL;
    listed
        .iter()
        .enumerate()
        .map(|(h, txs)| {
            let b = block(h as u64, previous, txs);
            previous = b.hash();
            let mut body = Vec::new();
            let bodies = txs
                .iter()
                .map(|t| {
                    body.clear();
                    t.write(&mut body).expect("write");
                    body.clone()
                })
                .collect();
            (b.serialize(), bodies)
        })
        .collect()
}

fn write_corpus(blocks: &[(Vec<u8>, Vec<Vec<u8>>)]) -> Vec<u8> {
    let mut w = CorpusWriter::new(Vec::new(), BlockHeight::from_raw(0)).expect("header");
    for (b, bodies) in blocks {
        w.push(b, bodies).expect("verified");
    }
    w.finish().expect("trailer")
}

fn h(n: u64) -> BlockHeight {
    BlockHeight::from_raw(n)
}

// ------------------------------------------------------------------ corpus

#[test]
fn the_corpus_round_trips_and_is_the_first_source() {
    let blocks = three_blocks();
    let bytes = write_corpus(&blocks);
    assert_eq!(&bytes[..8], &CORPUS_MAGIC);
    assert_eq!(bytes[8], CORPUS_VERSION);

    let mut reader = CorpusReader::open(Cursor::new(&bytes)).expect("open");
    let mut seen = Vec::new();
    while let Some(ev) = reader.next().expect("record") {
        let IngestEvent::Extend(cb) = ev.item else {
            panic!("a corpus is Extend-only");
        };
        seen.push((ev.seq, cb.height, cb.candidate.transactions.len()));
    }
    assert_eq!(
        seen,
        vec![
            (Seq::FIRST, h(0), 0),
            (Seq::FIRST.next(), h(1), 1),
            (Seq::FIRST.next().next(), h(2), 2),
        ]
    );
    // Exhausted stays exhausted.
    assert!(reader.next().expect("after trailer").is_none());
}

#[test]
fn a_pruned_sources_shortfall_is_refused_naming_the_height_by_writer_and_reader() {
    // RD-F15: the header lists two, the record carries one, nothing else
    // says so. The writer refuses; a hand-forged file with the same
    // shortfall is refused by the reader at the same height.
    let blocks = three_blocks();
    let (b2, bodies2) = &blocks[2];
    let mut w = CorpusWriter::new(Vec::new(), h(0)).expect("header");
    w.push(&blocks[0].0, &blocks[0].1).expect("genesis");
    w.push(&blocks[1].0, &blocks[1].1).expect("block 1");
    let err = w.push(b2, &bodies2[..1]).expect_err("shortfall");
    assert!(
        matches!(
            err,
            CorpusFault::Incomplete {
                height: 2,
                listed: 2,
                carried: 1
            }
        ),
        "{err}"
    );

    // Forge the same shortfall into a file: blocks 0 and 1 as written,
    // then block 2's record by hand with one body and a trailer that
    // claims three records.
    let mut w = CorpusWriter::new(Vec::new(), h(0)).expect("header");
    for (b, bodies) in &blocks[..2] {
        w.push(b, bodies).expect("ok");
    }
    let two = w.finish().expect("trailer");
    let mut forged = two[..two.len() - (1 + 8 + 32)].to_vec();
    forged.push(0x01);
    forged.extend_from_slice(&2u64.to_le_bytes());
    forged.extend_from_slice(&u32::try_from(b2.len()).expect("small").to_le_bytes());
    forged.extend_from_slice(b2);
    forged.extend_from_slice(&1u32.to_le_bytes());
    forged.extend_from_slice(
        &u32::try_from(bodies2[0].len())
            .expect("small")
            .to_le_bytes(),
    );
    forged.extend_from_slice(&bodies2[0]);
    forged.push(0xFF);
    forged.extend_from_slice(&3u64.to_le_bytes());
    forged.extend_from_slice(Block::from_bytes(b2).expect("block").hash().as_bytes());

    let mut r = CorpusReader::open(Cursor::new(&forged)).expect("open");
    r.next_record().expect("0");
    r.next_record().expect("1");
    let err = r.next_record().expect_err("the reader re-verifies");
    assert!(
        matches!(err, CorpusFault::Incomplete { height: 2, .. }),
        "{err}"
    );
    assert!(r.next_record().expect("exhausted").is_none());
}

#[test]
fn a_reordered_or_substituted_body_and_a_broken_chain_are_refused_at_their_height() {
    let blocks = three_blocks();
    let mut w = CorpusWriter::new(Vec::new(), h(0)).expect("header");
    w.push(&blocks[0].0, &blocks[0].1).expect("genesis");
    w.push(&blocks[1].0, &blocks[1].1).expect("block 1");
    let (b2, bodies2) = &blocks[2];
    let swapped = vec![bodies2[1].clone(), bodies2[0].clone()];
    let err = w.push(b2, &swapped).expect_err("reordered");
    assert!(
        matches!(
            err,
            CorpusFault::WrongBody {
                height: 2,
                index: 0
            }
        ),
        "{err}"
    );
    // A block whose previous is not block 1's hash.
    let stray = block(2, BlockHash::from_bytes([0xee; 32]), &[]).serialize();
    let err = w.push(&stray, &[]).expect_err("unchained");
    assert!(matches!(err, CorpusFault::Unchained { height: 2 }), "{err}");
    // Genesis must point at NULL.
    let mut w0 = CorpusWriter::new(Vec::new(), h(0)).expect("header");
    let bad_genesis = block(0, BlockHash::from_bytes([0x01; 32]), &[]).serialize();
    assert!(matches!(
        w0.push(&bad_genesis, &[]).expect_err("genesis"),
        CorpusFault::Unchained { height: 0 }
    ));
}

#[test]
fn header_and_trailer_refusals() {
    let blocks = three_blocks();
    let good = write_corpus(&blocks);

    let mut bad_magic = good.clone();
    bad_magic[0] ^= 0xff;
    assert!(matches!(
        CorpusReader::open(Cursor::new(&bad_magic)).expect_err("refused"),
        CorpusFault::BadMagic
    ));

    let mut bad_version = good.clone();
    bad_version[8] = 9;
    assert!(matches!(
        CorpusReader::open(Cursor::new(&bad_version)).expect_err("refused"),
        CorpusFault::UnsupportedVersion { found: 9 }
    ));

    let mut reserved = good.clone();
    reserved[12] = 1;
    assert!(matches!(
        CorpusReader::open(Cursor::new(&reserved)).expect_err("refused"),
        CorpusFault::ReservedNonZero
    ));

    let truncated = &good[..good.len() - 40];
    let mut r = CorpusReader::open(Cursor::new(truncated)).expect("open");
    let mut last = Ok(None);
    for _ in 0..4 {
        last = r.next_record();
        if last.is_err() {
            break;
        }
    }
    assert!(
        matches!(
            last,
            Err(CorpusFault::Truncated { records: 3 } | CorpusFault::Io(_))
        ),
        "{last:?}"
    );

    let mut bad_count = good.clone();
    let n = bad_count.len();
    bad_count[n - 40] ^= 0x01; // the count's low byte
    let mut r = CorpusReader::open(Cursor::new(&bad_count)).expect("open");
    let mut last = Ok(None);
    for _ in 0..4 {
        last = r.next_record();
        if !matches!(last, Ok(Some(_))) {
            break;
        }
    }
    assert!(
        matches!(last, Err(CorpusFault::TrailerMismatch { what: "count" })),
        "{last:?}"
    );

    // The reserved Rewind tag is refused as reserved, not unknown.
    let mut rewind = good.clone();
    let first_record = 8 + 1 + 7 + 8;
    rewind[first_record] = 0x02;
    let mut r = CorpusReader::open(Cursor::new(&rewind)).expect("open");
    assert!(matches!(
        r.next_record().expect_err("reserved"),
        CorpusFault::ReservedTag(0x02)
    ));
}

// ------------------------------------------------------------------- trace

fn facts_at(hh: u64) -> Facts {
    Facts {
        weight: BlockWeight::from_raw(1_000 + hh),
        long_term_weight: LongTermWeight::from_raw(900 + hh),
        coins_generated: AtomicUnits::from_raw(50 * (hh + 1)),
        burned: AtomicUnits::from_raw(hh),
        root_after: CurveTreeRoot::from_bytes([0xc0 + u8::try_from(hh).expect("small"); 32]),
        long_term_effective_median: LongTermWeight::from_raw(800 + hh),
        cumulative_difficulty: CumulativeDifficulty::from_raw(u128::from(hh) * 1_000_003 + 1),
    }
}

#[test]
fn the_trace_round_trips_through_both_doors_and_the_borrow_is_passed_through() {
    let mut w = TraceWriter::new(Vec::new()).expect("header");
    for hh in 0..3 {
        w.push_facts(h(hh), &facts_at(hh)).expect("facts");
    }
    let hashes = [[0x11; 32], [0x12; 32], [0x13; 32]];
    let spent = [[0x21; 32], [0x22; 32]];
    let root = CurveTreeRoot::from_bytes([0xc2; 32]);
    let state = w
        .push_checkpoint_families(h(2), &hashes, &spent, root)
        .expect("checkpoint");
    assert_eq!(
        state,
        LogicalStateDigestV0::from_families(&hashes, &spent, root)
    );
    let bytes = w.finish().expect("trailer");
    assert_eq!(&bytes[..8], &TRACE_MAGIC);
    assert_eq!(
        bytes.len(),
        16 + 3 * (1 + 8 + FACTS_LEN) + (1 + 8 + CHECKPOINT_LEN) + 17
    );

    let trace = Trace::read(Cursor::new(&bytes)).expect("read");
    assert_eq!(trace.covered(), Some((h(0), h(2))));
    assert_eq!(trace.checkpoint_heights().collect::<Vec<_>>(), vec![h(2)]);
    assert_eq!(trace.borrow(h(1)).expect("covered").value(), &facts_at(1));
    assert!(
        trace.borrow(h(3)).is_none(),
        "past the trace is absence, not a fault"
    );
    assert_eq!(trace.expect(h(2)).expect("checkpointed").value(), &state);
    assert!(trace.expect(h(1)).is_none());

    // The borrow door mints only passed-through facts.
    let cf: ConnectFacts = trace.borrow(h(2)).expect("covered").into();
    assert_eq!(cf.weight.value, BlockWeight::from_raw(1_002));
    assert_eq!(cf.root_after.value, CurveTreeRoot::from_bytes([0xc2; 32]));
    for origin in [
        cf.weight.origin,
        cf.long_term_weight.origin,
        cf.coins_generated.origin,
        cf.burned.origin,
        cf.root_after.origin,
        cf.long_term_effective_median.origin,
    ] {
        assert_eq!(origin, Origin::PassedThrough);
    }
}

#[test]
fn trace_refusals_gap_unanchored_duplicate_reserved_and_trailer() {
    let mut w = TraceWriter::new(Vec::new()).expect("header");
    w.push_facts(h(0), &facts_at(0)).expect("0");
    assert!(matches!(
        w.push_facts(h(2), &facts_at(2)).expect_err("gap"),
        TraceFault::HeightGap {
            expected: 1,
            found: 2
        }
    ));
    let state = LogicalStateDigestV0::from_families(&[], &[], CurveTreeRoot::EMPTY);
    assert!(matches!(
        w.push_checkpoint(h(5), &state).expect_err("unanchored"),
        TraceFault::UnanchoredCheckpoint { height: 5 }
    ));
    w.push_checkpoint(h(0), &state).expect("anchored");
    assert!(matches!(
        w.push_checkpoint(h(0), &state).expect_err("twice"),
        TraceFault::DuplicateCheckpoint { height: 0 }
    ));
    let good = w.finish().expect("trailer");
    assert!(Trace::read(Cursor::new(&good)).is_ok());

    let mut reserved = good.clone();
    reserved[16] = 0x03;
    assert!(matches!(
        Trace::read(Cursor::new(&reserved)).expect_err("reserved"),
        TraceFault::ReservedTag(0x03)
    ));

    let mut bad_count = good.clone();
    let n = bad_count.len();
    bad_count[n - 16] ^= 0x01;
    assert!(matches!(
        Trace::read(Cursor::new(&bad_count)).expect_err("count"),
        TraceFault::TrailerMismatch { what: "facts" }
    ));

    let truncated = &good[..good.len() - 17];
    assert!(matches!(
        Trace::read(Cursor::new(truncated)).expect_err("truncated"),
        TraceFault::Truncated
    ));

    let mut bad_version = good;
    bad_version[8] = 1;
    assert!(matches!(
        Trace::read(Cursor::new(&bad_version)).expect_err("version"),
        TraceFault::UnsupportedVersion { found: 1 }
    ));
}

#[test]
fn the_facts_layout_is_pinned() {
    // §3.9's table as bytes: change the layout, change the version, change
    // this.
    let mut w = TraceWriter::new(Vec::new()).expect("header");
    w.push_facts(h(7), &facts_at(7)).expect("facts");
    let bytes = w.finish().expect("trailer");
    let rec = &bytes[16..16 + 1 + 8 + FACTS_LEN];
    assert_eq!(rec[0], 0x01);
    assert_eq!(&rec[1..9], &7u64.to_le_bytes());
    assert_eq!(&rec[9..17], &1_007u64.to_le_bytes(), "weight");
    assert_eq!(&rec[17..25], &907u64.to_le_bytes(), "long_term_weight");
    assert_eq!(&rec[25..33], &400u64.to_le_bytes(), "coins_generated");
    assert_eq!(&rec[33..41], &7u64.to_le_bytes(), "burned");
    assert_eq!(&rec[41..73], &[0xc7; 32], "root_after");
    assert_eq!(
        &rec[73..81],
        &807u64.to_le_bytes(),
        "long_term_effective_median"
    );
    assert_eq!(
        &rec[81..97],
        &(7u128 * 1_000_003 + 1).to_le_bytes(),
        "cumulative_difficulty"
    );
    assert_eq!(FACTS_LEN, 88);
    assert_eq!(CHECKPOINT_LEN, 144);
}
