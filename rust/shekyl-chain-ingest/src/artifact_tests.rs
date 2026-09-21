// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The trace artifact (§3.9): round trips, pinned layout facts, every
//! refusal observed; and `fetch_corpus` against a scripted transport — in
//! particular RD-F15's pruned answer. The corpus's own tests live in
//! `corpus_tests.rs`.

use std::io::Cursor;

use shekyl_chain_store::digest_v0::digest_v0;
use shekyl_chain_store::store::{ConnectFacts, Origin};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockWeight, CurveTreeRoot, LongTermWeight};
use shekyl_units::AtomicUnits;

use crate::test_support::{chain_listing, h, spend, wire};
use crate::trace::{Facts, Trace, TraceFault, TraceWriter, CHECKPOINT_LEN, FACTS_LEN, TRACE_MAGIC};

// ---------------------------------------------------------------- fixtures

/// Three blocks — genesis, one spend, two spends — as the network carries
/// them: (block bytes, body bytes).
fn three_blocks() -> Vec<(Vec<u8>, Vec<Vec<u8>>)> {
    chain_listing(vec![Vec::new(), vec![spend(1)], vec![spend(2), spend(3)]])
        .iter()
        .map(|(b, txs)| wire(b, txs))
        .collect()
}

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
    assert_eq!(state, digest_v0(&hashes, &spent, root.as_bytes()));
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
    let state = digest_v0(&[], &[], CurveTreeRoot::EMPTY.as_bytes());
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
    assert_eq!(CHECKPOINT_LEN, 32, "one outer digest per checkpoint");
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
    use crate::corpus::{CorpusFault, CorpusNet, CorpusReader, CorpusWriter};
    use crate::fetch::{fetch_corpus, FetchFault, ROUTE};
    use crate::source::Source;

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
        let mut w = CorpusWriter::create(
            std::io::Cursor::new(Vec::new()),
            CorpusNet::Fakechain,
            BlockHeight::from_raw(0),
        )
        .expect("header");
        let written = fetch_corpus(&rpc, 0..3, 2, &mut w).await.expect("fetched");
        assert_eq!(written, 3);
        assert_eq!(
            *rpc.asked.lock().expect("lock"),
            vec![(ROUTE.to_owned(), vec![0, 1]), (ROUTE.to_owned(), vec![2])]
        );
        let bytes = w.finish().expect("count").into_inner();
        let mut r = CorpusReader::open(std::io::Cursor::new(&bytes)).expect("open");
        let mut n = 0;
        while r.next().expect("record").is_some() {
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
        let mut w = CorpusWriter::create(
            std::io::Cursor::new(Vec::new()),
            CorpusNet::Fakechain,
            BlockHeight::from_raw(0),
        )
        .expect("header");
        let err = fetch_corpus(&rpc, 0..3, 10, &mut w)
            .await
            .expect_err("pruned");
        match err {
            FetchFault::Corpus(CorpusFault::IncompleteBodies {
                height,
                listed: 2,
                present: 1,
            }) => assert_eq!(height, BlockHeight::from_raw(2)),
            other => panic!("{other}"),
        }
    }

    #[tokio::test]
    async fn a_refusal_and_a_short_reply_are_the_conversations_faults() {
        let blocks = three_blocks();
        let refused = GetBlocksByHeightResponse {
            status: RpcStatus("Failed".into()),
            blocks: Vec::new(),
        };
        let rpc = Scripted::new(&[refused]);
        let mut w = CorpusWriter::create(
            std::io::Cursor::new(Vec::new()),
            CorpusNet::Fakechain,
            BlockHeight::from_raw(0),
        )
        .expect("header");
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
        let mut w = CorpusWriter::create(
            std::io::Cursor::new(Vec::new()),
            CorpusNet::Fakechain,
            BlockHeight::from_raw(0),
        )
        .expect("header");
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
        let mut w = CorpusWriter::create(
            std::io::Cursor::new(Vec::new()),
            CorpusNet::Fakechain,
            BlockHeight::from_raw(0),
        )
        .expect("header");
        assert!(matches!(
            fetch_corpus(&rpc, 0..1, 1, &mut w)
                .await
                .expect_err("transport"),
            FetchFault::Rpc(RpcError::ConnectionError(_))
        ));
    }
}
