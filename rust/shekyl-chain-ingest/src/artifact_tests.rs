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
use shekyl_types::{BlockHash, BlockHeight, BlockWeight, CurveTreeRoot, LongTermWeight};
use shekyl_units::AtomicUnits;
use shekyl_wire::Block;

use crate::corpus::{
    CorpusFault, CorpusReader, CorpusRecord, CorpusWriter, CORPUS_MAGIC, CORPUS_VERSION,
};
use crate::source::{IngestEvent, Seq, Source};
use crate::test_support::{
    block, block_with_nonce, chain_listing, corpus_of_reorg, reorg, spend, wire,
};
use crate::trace::{Facts, Trace, TraceFault, TraceWriter, CHECKPOINT_LEN, FACTS_LEN, TRACE_MAGIC};

// ---------------------------------------------------------------- fixtures

/// Three blocks — genesis, one spend, two spends — as the network carries
/// them: (block bytes, body bytes).
fn three_blocks() -> Vec<(Vec<u8>, Vec<Vec<u8>>)> {
    chain_listing(vec![vec![], vec![spend(1)], vec![spend(2), spend(3)]])
        .iter()
        .map(|(b, txs)| wire(b, txs))
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

    // A Rewind as the first record has no tip to rewind from.
    let mut rewind = good.clone();
    let first_record = 8 + 1 + 7 + 8;
    rewind[first_record] = 0x02;
    let mut r = CorpusReader::open(Cursor::new(&rewind)).expect("open");
    assert!(matches!(
        r.next_record().expect_err("no tip"),
        CorpusFault::RewindOnEmpty
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

// ------------------------------------------------------------------- fetch

mod fetch {
    use std::collections::VecDeque;
    use std::future::Future;
    use std::sync::{Arc, Mutex};

    use shekyl_rpc_client::{Rpc, RpcError};
    use shekyl_rpc_types::{
        BlockEntry, GetBlocksByHeightRequest, GetBlocksByHeightResponse, RpcStatus,
    };
    use shekyl_types::BlockHeight;

    use super::three_blocks;
    use crate::corpus::{CorpusFault, CorpusReader, CorpusWriter};
    use crate::fetch::{fetch_corpus, FetchFault, ROUTE};

    /// One recorded request: the route and the heights asked.
    type Asked = (String, Vec<u64>);

    /// A transport that answers from a script and records what it was asked.
    #[derive(Clone)]
    struct Scripted {
        replies: Arc<Mutex<VecDeque<Vec<u8>>>>,
        asked: Arc<Mutex<Vec<Asked>>>,
    }

    impl Scripted {
        fn new(replies: &[GetBlocksByHeightResponse]) -> Self {
            Self {
                replies: Arc::new(Mutex::new(
                    replies
                        .iter()
                        .map(|r| r.to_bin().expect("encode"))
                        .collect(),
                )),
                asked: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl Rpc for Scripted {
        fn post(
            &self,
            route: &str,
            body: Vec<u8>,
        ) -> impl Send + Future<Output = Result<Vec<u8>, RpcError>> {
            let req = GetBlocksByHeightRequest::from_bin(&body).expect("a by-height request");
            self.asked
                .lock()
                .expect("lock")
                .push((route.to_owned(), req.heights));
            let next = self.replies.lock().expect("lock").pop_front();
            async move { next.ok_or_else(|| RpcError::ConnectionError("script exhausted".into())) }
        }
    }

    fn reply(entries: &[(Vec<u8>, Vec<Vec<u8>>)]) -> GetBlocksByHeightResponse {
        GetBlocksByHeightResponse {
            status: RpcStatus::ok(),
            blocks: entries
                .iter()
                .map(|(block, txs)| BlockEntry {
                    block: block.clone(),
                    txs: txs.clone(),
                })
                .collect(),
        }
    }

    #[tokio::test]
    async fn fetches_in_batches_through_the_route_and_the_corpus_reads_back() {
        let blocks = three_blocks();
        let rpc = Scripted::new(&[reply(&blocks[..2]), reply(&blocks[2..])]);
        let mut w = CorpusWriter::new(Vec::new(), BlockHeight::from_raw(0)).expect("header");
        let written = fetch_corpus(&rpc, 0..3, 2, &mut w).await.expect("fetched");
        assert_eq!(written, 3);
        assert_eq!(
            *rpc.asked.lock().expect("lock"),
            vec![(ROUTE.to_owned(), vec![0, 1]), (ROUTE.to_owned(), vec![2])]
        );
        let bytes = w.finish().expect("trailer");
        let mut r = CorpusReader::open(std::io::Cursor::new(&bytes)).expect("open");
        let mut n = 0;
        while r.next_record().expect("record").is_some() {
            n += 1;
        }
        assert_eq!(n, 3);
    }

    #[tokio::test]
    async fn a_pruned_answer_is_caught_by_the_writer_at_its_height() {
        // RD-F15 end to end: the daemon returns block 2 with one of its two
        // bodies and says nothing; the fetcher hands it to the writer and
        // the writer names height 2.
        let blocks = three_blocks();
        let mut pruned = blocks.clone();
        pruned[2].1.truncate(1);
        let rpc = Scripted::new(&[reply(&pruned)]);
        let mut w = CorpusWriter::new(Vec::new(), BlockHeight::from_raw(0)).expect("header");
        let err = fetch_corpus(&rpc, 0..3, 10, &mut w)
            .await
            .expect_err("pruned");
        assert!(
            matches!(
                err,
                FetchFault::Corpus(CorpusFault::Incomplete {
                    height: 2,
                    listed: 2,
                    carried: 1
                })
            ),
            "{err}"
        );
        assert_eq!(w.count(), 2, "the writer stopped at the height that failed");
    }

    #[tokio::test]
    async fn a_refusal_and_a_short_reply_are_the_conversations_faults() {
        let blocks = three_blocks();
        let refused = GetBlocksByHeightResponse {
            status: RpcStatus("Failed".into()),
            blocks: Vec::new(),
        };
        let rpc = Scripted::new(&[refused]);
        let mut w = CorpusWriter::new(Vec::new(), BlockHeight::from_raw(0)).expect("header");
        let err = fetch_corpus(&rpc, 0..3, 10, &mut w)
            .await
            .expect_err("refused");
        assert!(
            matches!(
                err,
                FetchFault::Refused {
                    first: 0,
                    end: 3,
                    ..
                }
            ),
            "{err}"
        );

        let rpc = Scripted::new(&[reply(&blocks[..1])]);
        let mut w = CorpusWriter::new(Vec::new(), BlockHeight::from_raw(0)).expect("header");
        let err = fetch_corpus(&rpc, 0..3, 10, &mut w)
            .await
            .expect_err("short");
        assert!(
            matches!(
                err,
                FetchFault::CountMismatch {
                    first: 0,
                    asked: 3,
                    got: 1
                }
            ),
            "{err}"
        );

        let rpc = Scripted::new(&[]);
        let mut w = CorpusWriter::new(Vec::new(), BlockHeight::from_raw(0)).expect("header");
        assert!(matches!(
            fetch_corpus(&rpc, 0..1, 1, &mut w)
                .await
                .expect_err("transport"),
            FetchFault::Rpc(RpcError::ConnectionError(_))
        ));
    }
}

// ---------------------------------------------------------------------------
// Corpus: the Rewind record (RD-Q13, commit 8c)
// ---------------------------------------------------------------------------

#[test]
fn a_corpus_with_a_rewind_round_trips_and_chains_the_fork_onto_the_rewound_tip() {
    let r = reorg(4, 1, 3);
    let bytes = corpus_of_reorg(&r);
    let mut reader = CorpusReader::open(Cursor::new(&bytes)).expect("open");
    let mut heights = Vec::new();
    loop {
        match reader.next_record().expect("record") {
            Some(CorpusRecord::Extend(rec)) => heights.push(format!("E{}", rec.height.to_raw())),
            Some(CorpusRecord::Rewind(to)) => heights.push(format!("R{}", to.to_raw())),
            None => break,
        }
    }
    assert_eq!(heights, ["E0", "E1", "E2", "E3", "R1", "E2", "E3", "E4"]);
    // As a Source, the same shape in events.
    let mut src = CorpusReader::open(Cursor::new(&bytes)).expect("open");
    let mut kinds = Vec::new();
    while let Some(ev) = src.next().expect("event") {
        kinds.push(match ev.item {
            IngestEvent::Extend(b) => format!("E{}", b.height.to_raw()),
            IngestEvent::Rewind { to } => format!("R{}", to.to_raw()),
        });
    }
    assert_eq!(kinds, heights);
}

#[test]
fn a_rewind_must_be_backward_inside_the_corpus_and_after_a_block() {
    let three = chain_listing(vec![Vec::new(), vec![spend(1)], vec![spend(2)]]);
    // Before any block: no tip.
    let mut w = CorpusWriter::new(Vec::new(), BlockHeight::from_raw(0)).expect("header");
    assert!(matches!(
        w.rewind(BlockHeight::from_raw(0)).expect_err("empty"),
        CorpusFault::RewindOnEmpty
    ));
    for (b, txs) in &three {
        let (bytes, bodies) = wire(b, txs);
        w.push(&bytes, &bodies).expect("push");
    }
    // To the tip: nothing to pop.
    assert!(matches!(
        w.rewind(BlockHeight::from_raw(2)).expect_err("tip"),
        CorpusFault::RewindNotBackward { to: 2, tip: 2 }
    ));
    // A corpus starting at 5 cannot rewind to 4: the block at 4 is not in it.
    let mut w5 = CorpusWriter::new(Vec::new(), BlockHeight::from_raw(5)).expect("header");
    let b5 = block(5, BlockHash::from_bytes([9u8; 32]), &[]);
    let (bytes, bodies) = wire(&b5, &[]);
    w5.push(&bytes, &bodies).expect("push 5");
    let b6 = block(6, b5.hash(), &[]);
    let (bytes, bodies) = wire(&b6, &[]);
    w5.push(&bytes, &bodies).expect("push 6");
    assert!(matches!(
        w5.rewind(BlockHeight::from_raw(4))
            .expect_err("below first"),
        CorpusFault::RewindOutOfCorpus {
            to: 4,
            first_height: 5
        }
    ));
    // The reader applies the same law to a hand-built rewind-to-tip record.
    let mut good = CorpusWriter::new(Vec::new(), BlockHeight::from_raw(0)).expect("header");
    for (b, txs) in &three {
        let (bytes, bodies) = wire(b, txs);
        good.push(&bytes, &bodies).expect("push");
    }
    let mut bytes = good.finish().expect("finish");
    let trailer_at = bytes.len() - (1 + 8 + 32);
    let mut with_bad_rewind = bytes[..trailer_at].to_vec();
    with_bad_rewind.push(0x02);
    with_bad_rewind.extend_from_slice(&2u64.to_le_bytes());
    with_bad_rewind.extend_from_slice(&bytes[trailer_at..]);
    bytes = with_bad_rewind;
    let mut r = CorpusReader::open(Cursor::new(&bytes)).expect("open");
    let mut last = Ok(None);
    for _ in 0..4 {
        last = r.next_record();
        if !matches!(last, Ok(Some(_))) {
            break;
        }
    }
    assert!(
        matches!(last, Err(CorpusFault::RewindNotBackward { to: 2, tip: 2 })),
        "{last:?}"
    );
}

#[test]
fn after_a_rewind_the_next_block_must_chain_onto_the_rewound_tip() {
    let r = reorg(4, 1, 3);
    let mut w = CorpusWriter::new(Vec::new(), BlockHeight::from_raw(0)).expect("header");
    for (b, txs) in &r.main {
        let (bytes, bodies) = wire(b, txs);
        w.push(&bytes, &bodies).expect("push");
    }
    w.rewind(BlockHeight::from_raw(1)).expect("rewind");
    // A block at 2 chained onto main[2] (the popped block) is unchained now.
    let wrong = block_with_nonce(2, r.main[2].0.hash(), &[spend(0xB0)], 5);
    let (bytes, bodies) = wire(&wrong, &[spend(0xB0)]);
    assert!(matches!(
        w.push(&bytes, &bodies).expect_err("unchained"),
        CorpusFault::Unchained { height: 2 }
    ));
    // Chained onto main[1], it is accepted.
    let (bytes, bodies) = wire(&r.after[2].0, &r.after[2].1);
    w.push(&bytes, &bodies)
        .expect("the fork chains onto the rewound tip");
}
