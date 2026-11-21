// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use std::io::Cursor;

use shekyl_chain_rules::Candidate;
use shekyl_types::{BlockHash, BlockHeight, CurveTreeRoot, SectionRoot};
use shekyl_wire::{Block, BlockHeader, Ct, CtBase, Input, Output, Transaction, TxPrefix};

use shekyl_corpus::{CorpusWriter, MAX_SECTION_BLOB};

use super::*;
use crate::test_support::coinbase;

// Wire-valid fixtures: the shared `test_support::coinbase` (a miner tx with
// the sole `Input::Gen` the wire demands; RD-F16), and listed bodies that
// parse.

/// A listed body distinguishable from every other by `tag`.
fn listed(tag: u8) -> Transaction {
    Transaction {
        prefix: TxPrefix {
            unlock_time: TxPrefix::NO_UNLOCK_TIME,
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

std::thread_local! {
    /// The block [`blobs`] built last at each height, on this test's
    /// thread: the parent of the next block it builds one height above.
    static BUILT: std::cell::RefCell<std::collections::HashMap<u64, BlockHash>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

/// A candidate at `height` with `n` listed bodies, serialized the way a
/// source hands blobs over: the block blob and the bodies in header order.
/// Its parent is the block this thread built last one height below, so
/// blocks built in height order form a chain the corpus's lineage law
/// accepts; a rebuilt height replaces the one before.
fn blobs(height: u64, n: usize) -> (Candidate, Vec<u8>, Vec<Vec<u8>>) {
    let parent = height
        .checked_sub(1)
        .and_then(|below| BUILT.with(|built| built.borrow().get(&below).copied()))
        .unwrap_or_else(|| BlockHash::from_bytes([0x11; 32]));
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
            previous: parent,
            nonce: 7,
            curve_tree_root: CurveTreeRoot::from_bytes([0x22; 32]),
            section_root: SectionRoot::from_bytes([0x33; 32]),
        },
        miner_transaction: coinbase(height),
        transaction_hashes: bodies.iter().map(Transaction::hash).collect(),
    };
    let block_blob = block.serialize();
    let tx_blobs = bodies.iter().map(Transaction::serialize).collect();
    BUILT.with(|built| built.borrow_mut().insert(height, block.hash()));
    (Candidate::new(block, bodies), block_blob, tx_blobs)
}

/// The edit that makes this red: move `MAX_SECTION_BLOB` or
/// `DEFAULT_MAX_PACKET_SIZE` and not the other. A section blob is allocated
/// at the same ceiling command 2017 reads a bundle body at.
#[test]
fn the_section_blob_ceiling_is_the_bundle_body_packet_ceiling() {
    assert_eq!(
        u64::try_from(MAX_SECTION_BLOB).expect("the ceiling fits u64"),
        shekyl_levin::DEFAULT_MAX_PACKET_SIZE
    );
}

fn write(records: &[(Vec<u8>, Vec<Vec<u8>>)]) -> Vec<u8> {
    let mut w = CorpusWriter::create(Cursor::new(Vec::new()), Network::Regtest, BlockHeight::ZERO)
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

    let mut reader = CorpusSource::open(Cursor::new(bytes)).expect("open");
    assert_eq!(reader.net(), Network::Regtest);
    assert_eq!(reader.declared(), 3);
    let mut seen = Vec::new();
    while let Some(Sequenced { seq, event }) = reader.next().expect("record") {
        assert!(
            !event.is_barrier(),
            "a corpus yields Extend only; Extend is not a sequencer barrier"
        );
        match event {
            IngestEvent::Extend(cand) => seen.push((seq, *cand)),
            IngestEvent::Rewind { .. } | IngestEvent::Offer(_) => {
                unreachable!("this corpus is Extend-only")
            }
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

// ---------------------------------------------------------------------------
// The rewind record (RD-Q13, §7 commit 8c)
// ---------------------------------------------------------------------------

/// The codec's refusals reach a replay unchanged: the adapter adds no
/// fault of its own and swallows none.
#[test]
fn the_codecs_refusal_is_the_sources() {
    let (_, b0, t0) = blobs(0, 0);
    let mut bytes = write(&[(b0, t0)]);
    bytes[0] ^= 0xff;
    assert!(matches!(
        CorpusSource::open(Cursor::new(bytes)).err(),
        Some(CorpusFault::BadMagic)
    ));
    let (_, b0, t0) = blobs(0, 0);
    let (_, b1, t1) = blobs(1, 0);
    let whole = write(&[(b0.clone(), t0.clone()), (b1, t1)]);
    let cut = write(&[(b0, t0)]).len() + 1;
    let mut source = CorpusSource::open(Cursor::new(whole[..cut].to_vec())).expect("open");
    source.next().expect("the first record is whole");
    assert!(matches!(
        source.next(),
        Err(CorpusFault::CountMismatch {
            declared: 2,
            present: 1
        })
    ));
}

#[test]
fn a_corpus_with_a_rewind_round_trips_as_events() {
    use crate::test_support::{corpus_of_reorg, reorg};
    // Main reaches two spend blocks past CEN-I11's floor; the fork rewinds
    // to the block before the first and lists three spends of its own.
    let floor = crate::test_support::FIRST_SPEND_HEIGHT;
    let r = reorg(floor + 2, floor - 1, 3);
    let bytes = corpus_of_reorg(&r);
    let mut reader = CorpusSource::open(Cursor::new(bytes)).expect("open");
    assert_eq!(
        reader.declared(),
        (floor + 2) + 1 + 3,
        "count is records of both kinds"
    );
    let mut kinds = Vec::new();
    while let Some(ev) = reader.next().expect("event") {
        kinds.push(match ev.event {
            IngestEvent::Extend(c) => format!("E{}", c.block.transaction_hashes.len()),
            IngestEvent::Rewind { to } => format!("R{}", to.to_raw()),
            IngestEvent::Offer(c) => format!("O{}", c.block.transaction_hashes.len()),
        });
    }
    // main: nothing listed below the floor, one spend at the floor and the
    // block after; rewind to the block before the floor; fork: one spend
    // each at the floor and the two blocks after.
    let mut expected: Vec<String> = vec!["E0".to_owned(); usize::try_from(floor).expect("small")];
    expected.extend(["E1", "E1"].map(str::to_owned));
    expected.push(format!("R{}", floor - 1));
    expected.extend(["E1", "E1", "E1"].map(str::to_owned));
    assert_eq!(kinds, expected);
}

/// A block's bundle section rides its record (version 4, the switch's C4):
/// the references and, in section order, each one's body come back on the
/// candidate a replay judges. A body that is not its reference's is refused
/// before the record is written. Red edit: drop the body check in
/// `shekyl-corpus`'s `verified_section` — the swapped body is written.
#[test]
fn a_record_carries_its_bundle_section_and_refuses_a_body_that_is_not_its_own() {
    use shekyl_chain_rules::harness::bundle::BundleWorld;
    use shekyl_chain_rules::RuleSet;

    let (_, block, txs) = blobs(0, 1);
    let one = BundleWorld::with(
        BlockHeight::from_raw(7),
        BundleWorld::SEED,
        0,
        &RuleSet::GENESIS,
    );
    let (reference, body) = one.bundle(&[]);
    let other = BundleWorld::with(
        BlockHeight::from_raw(8),
        BundleWorld::SEED,
        0,
        &RuleSet::GENESIS,
    );
    let (_, foreign) = other.bundle(&[]);

    let mut w = CorpusWriter::create(
        Cursor::new(Vec::new()),
        Network::Stagenet,
        BlockHeight::ZERO,
    )
    .expect("header");
    let refused = w
        .append_carrying(
            &block,
            &txs,
            &[reference.encode()],
            &[foreign.as_bytes().to_vec()],
        )
        .expect_err("a body that is not the reference's");
    assert!(
        matches!(refused, CorpusFault::BadSection { .. }),
        "{refused}"
    );
    w.append_carrying(
        &block,
        &txs,
        &[reference.encode()],
        &[body.as_bytes().to_vec()],
    )
    .expect("the section holds");
    let bytes = w.finish().expect("finish").into_inner();

    let mut reader = CorpusSource::open(Cursor::new(bytes)).expect("open");
    let IngestEvent::Extend(candidate) =
        reader.next().expect("one record").expect("a record").event
    else {
        panic!("an extend record");
    };
    assert_eq!(
        candidate
            .bundle_references
            .as_ref()
            .map(|section| section.as_slice().to_vec()),
        Some(vec![reference.encode()])
    );
    assert_eq!(candidate.bundle_bodies, vec![body]);
}
