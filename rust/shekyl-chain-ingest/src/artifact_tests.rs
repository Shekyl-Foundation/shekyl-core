// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The trace artifact (§3.9): round trips, pinned layout facts, every
//! refusal observed; and `fetch_corpus` against a scripted transport — in
//! particular RD-F15's pruned answer. The corpus's own tests live in
//! `corpus_tests.rs`.

use std::io::Cursor;

use shekyl_chain_store::archival_snapshot::{ArchivalSnapshot, SnapshotFault, EMPTY_BODY_LEN};
use shekyl_chain_store::digest_v0::digest_v0;
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockWeight, CurveTreeRoot, LongTermWeight, SettlementEpoch};
use shekyl_units::AtomicUnits;

use crate::test_support::h;
#[cfg(feature = "fetch")]
use crate::test_support::{block, filler_spend, key_image, wire, Family};
use crate::trace::{
    Facts, Trace, TraceFault, TraceWriter, CHECKPOINT_LEN, FACTS_LEN, TRACE_MAGIC, TRACE_VERSION,
};
#[cfg(feature = "fetch")]
use shekyl_types::BlockHash;

// ---------------------------------------------------------------- fixtures

/// Three blocks — genesis, one body, two bodies — as the network carries
/// them: (block bytes, body bytes). Built block by block rather than through
/// `Growing`: nothing here is judged, the subject is the fetch and the
/// corpus's body count, so the bodies are fixture filler (`filler_spend`)
/// sitting where the byte shapes want them, below any height a real spend
/// could be proven for.
#[cfg(feature = "fetch")]
fn three_blocks() -> Vec<(Vec<u8>, Vec<Vec<u8>>)> {
    let ki = |n| filler_spend(key_image(Family::Main, n));
    let listed = [Vec::new(), vec![ki(1)], vec![ki(2), ki(3)]];
    let mut previous = BlockHash::NULL;
    listed
        .iter()
        .enumerate()
        .map(|(hh, txs)| {
            // Bytes for the artifact round-trip, never judged: unpriced.
            let b = block(CurveTreeRoot::EMPTY, hh as u64, previous, txs, 0);
            previous = b.hash();
            wire(&b, txs)
        })
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
fn the_trace_round_trips_through_both_doors() {
    let mut w = TraceWriter::new(Vec::new()).expect("header");
    for hh in 0..3 {
        w.push_facts(h(hh), &facts_at(hh)).expect("facts");
    }
    let hashes = [[0x11; 32], [0x12; 32], [0x13; 32]];
    let spent = [[0x21; 32], [0x22; 32]];
    let root = CurveTreeRoot::from_bytes([0xc2; 32]);
    let state = digest_v0(&hashes, &spent, root.as_bytes());
    w.push_checkpoint(&state).expect("checkpoint");
    // The checkpoint's other encoding (§3.8.1): one accrual row, one
    // budget row — 8 + 8 bytes each behind a `u32` length.
    let mut snapshot = ArchivalSnapshot::empty();
    snapshot
        .set_budget_accruing(SettlementEpoch::from_raw(0), AtomicUnits::from_raw(150))
        .expect("accruing");
    snapshot
        .push_budget(SettlementEpoch::from_raw(3), AtomicUnits::from_raw(9))
        .expect("budget");
    w.push_archival_snapshot(&snapshot)
        .expect("archival snapshot");
    let bytes = w.finish().expect("trailer");
    assert_eq!(&bytes[..8], &TRACE_MAGIC);
    assert_eq!(bytes[8], TRACE_VERSION);
    assert_eq!(
        bytes.len(),
        16 + 3 * (1 + 8 + FACTS_LEN)
            + (1 + 8 + CHECKPOINT_LEN)
            + (1 + 8 + EMPTY_BODY_LEN + 2 * (4 + 16))
            + 17
    );

    let trace = Trace::read(Cursor::new(&bytes)).expect("read");
    assert_eq!(trace.covered(), Some((h(0), h(2))));
    assert_eq!(
        trace.checkpoint().map(|(hh, _)| hh),
        Some(h(2)),
        "one checkpoint, at the covered tip"
    );
    let (at, rows) = trace.archival_snapshot().expect("the snapshot");
    assert_eq!(at, h(2), "at the checkpoint's height");
    assert!(rows.value().diff(&snapshot).is_identical());
    assert_eq!(rows.value().row_count(), 2);
    assert_eq!(trace.borrow(h(1)).expect("covered").value(), &facts_at(1));
    assert!(
        trace.borrow(h(3)).is_none(),
        "past the trace is absence, not a fault"
    );
    assert_eq!(trace.expect(h(2)).expect("checkpointed").value(), &state);
    assert!(trace.expect(h(1)).is_none());

    // The borrow door yields the recorded values as the oracles' comparison
    // inputs and nothing `connect` is handed (the passed-through conversion
    // left with E6 slice 7 wave B; the burn was its last field).
    let recorded = *trace.borrow(h(2)).expect("covered").value();
    assert_eq!(recorded.weight, BlockWeight::from_raw(1_002));
    assert_eq!(recorded.root_after, CurveTreeRoot::from_bytes([0xc2; 32]));
    assert_eq!(recorded.coins_generated, facts_at(2).coins_generated);
    assert_eq!(recorded.burned, facts_at(2).burned);
    assert_eq!(
        recorded.long_term_effective_median,
        facts_at(2).long_term_effective_median
    );
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
    let mut empty = TraceWriter::new(Vec::new()).expect("header");
    assert!(matches!(
        empty.push_checkpoint(&state).expect_err("no facts"),
        TraceFault::UnanchoredCheckpoint
    ));
    // The checkpoint is the covered tip: a trace starting at 3 checkpoints
    // at 3, and a second call is a duplicate. Height is not a parameter, so
    // a writer cannot name a height the reader would refuse.
    let mut from_three = TraceWriter::new(Vec::new()).expect("header");
    from_three.push_facts(h(3), &facts_at(3)).expect("facts");
    from_three
        .push_checkpoint(&state)
        .expect("anchored at its only row");
    assert!(matches!(
        from_three.push_checkpoint(&state).expect_err("second"),
        TraceFault::DuplicateCheckpoint { height: 3 }
    ));
    w.push_checkpoint(&state).expect("anchored at 0");
    assert!(matches!(
        w.push_checkpoint(&state).expect_err("twice"),
        TraceFault::DuplicateCheckpoint { height: 0 }
    ));
    assert!(matches!(
        w.push_facts(h(1), &facts_at(1))
            .expect_err("facts after checkpoint"),
        TraceFault::FactsAfterCheckpoint { height: 1 }
    ));
    w.push_archival_snapshot(&ArchivalSnapshot::empty())
        .expect("the checkpoint's other encoding");
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

    let mut bad_version = good.clone();
    bad_version[8] = 2;
    assert!(matches!(
        Trace::read(Cursor::new(&bad_version)).expect_err("version"),
        TraceFault::UnsupportedVersion { found: 2 }
    ));

    // The trailer ends a trace: two concatenated, or one byte past it, is
    // refused rather than read as the first.
    let mut doubled = good.clone();
    doubled.extend_from_slice(&good);
    assert!(matches!(
        Trace::read(Cursor::new(&doubled)).expect_err("two traces"),
        TraceFault::TrailingBytes
    ));
    let mut padded = good;
    padded.push(0);
    assert!(matches!(
        Trace::read(Cursor::new(&padded)).expect_err("a byte past the trailer"),
        TraceFault::TrailingBytes
    ));
}

#[test]
fn the_archival_snapshot_is_the_checkpoints_other_encoding_on_both_sides() {
    // DRS-E4 §3.8.1 (pairing, 2026-10-01): under `TRACE_VERSION` the `0x02`
    // and `0x04` records are one checkpoint's two encodings. The writer
    // refuses a snapshot with nothing to pair with, a second one, and a
    // `finish` with the checkpoint and not its snapshot; the reader refuses
    // the same shapes in the bytes, plus a snapshot whose height is not the
    // checkpoint's. A trace with no checkpoint carries neither and reads;
    // the `0x00` layout, which carried neither record, is not read at all.
    let empty = ArchivalSnapshot::empty();
    let state = digest_v0(&[], &[], CurveTreeRoot::EMPTY.as_bytes());

    // Writer: unanchored, duplicate, missing.
    let mut w = TraceWriter::new(Vec::new()).expect("header");
    w.push_facts(h(0), &facts_at(0)).expect("facts");
    assert!(matches!(
        w.push_archival_snapshot(&empty).expect_err("no checkpoint"),
        TraceFault::UnanchoredSnapshot
    ));
    w.push_checkpoint(&state).expect("checkpoint");
    w.push_archival_snapshot(&empty).expect("paired");
    assert!(matches!(
        w.push_archival_snapshot(&empty).expect_err("second"),
        TraceFault::DuplicateSnapshot { height: 0 }
    ));
    let good = w.finish().expect("trailer");
    let trace = Trace::read(Cursor::new(&good)).expect("read");
    let (at, rows) = trace.archival_snapshot().expect("snapshot");
    assert_eq!(at, h(0));
    assert_eq!(rows.value().row_count(), 0);

    let mut unpaired = TraceWriter::new(Vec::new()).expect("header");
    unpaired.push_facts(h(0), &facts_at(0)).expect("facts");
    unpaired.push_checkpoint(&state).expect("checkpoint");
    assert!(matches!(
        unpaired.finish().expect_err("checkpoint without snapshot"),
        TraceFault::MissingSnapshot { height: 0 }
    ));

    // No checkpoint: neither record, and the trace reads.
    let mut none = TraceWriter::new(Vec::new()).expect("header");
    none.push_facts(h(0), &facts_at(0)).expect("facts");
    let bytes = none.finish().expect("trailer");
    let trace = Trace::read(Cursor::new(&bytes)).expect("read");
    assert!(trace.checkpoint().is_none());
    assert!(trace.archival_snapshot().is_none());

    // The empty record's layout: tag, height, ten zero counts.
    let snapshot_at = 16 + (1 + 8 + FACTS_LEN) + (1 + 8 + CHECKPOINT_LEN);
    let record = &good[snapshot_at..snapshot_at + 1 + 8 + EMPTY_BODY_LEN];
    assert_eq!(record[0], 0x04);
    assert_eq!(&record[1..9], &0u64.to_le_bytes());
    assert!(record[9..].iter().all(|&b| b == 0));
    assert_eq!(good.len(), snapshot_at + 1 + 8 + EMPTY_BODY_LEN + 17);

    // Reader: the snapshot stripped out of a `0x01` trace is a missing one.
    let mut stripped = good[..snapshot_at].to_vec();
    stripped.extend_from_slice(&good[snapshot_at + 1 + 8 + EMPTY_BODY_LEN..]);
    assert!(matches!(
        Trace::read(Cursor::new(&stripped)).expect_err("missing"),
        TraceFault::MissingSnapshot { height: 0 }
    ));
    // Reader: the `0x00` layout is no longer read (DRS-E4 commit 7), with
    // or without the record — the version byte alone refuses the file.
    for mut old in [good.clone(), stripped.clone()] {
        old[8] = 0x00;
        assert!(matches!(
            Trace::read(Cursor::new(&old)).expect_err("a v0 trace"),
            TraceFault::UnsupportedVersion { found: 0x00 }
        ));
    }
    // Reader: the snapshot's height is not the checkpoint's.
    let mut not_tip = good.clone();
    not_tip[snapshot_at + 1..snapshot_at + 9].copy_from_slice(&7u64.to_le_bytes());
    assert!(matches!(
        Trace::read(Cursor::new(&not_tip)).expect_err("not the tip"),
        TraceFault::SnapshotNotTip { height: 7, tip: 0 }
    ));
    // Reader: the snapshot before its checkpoint.
    let checkpoint_at = 16 + (1 + 8 + FACTS_LEN);
    let mut swapped = good[..checkpoint_at].to_vec();
    swapped.extend_from_slice(&good[snapshot_at..snapshot_at + 1 + 8 + EMPTY_BODY_LEN]);
    swapped.extend_from_slice(&good[checkpoint_at..snapshot_at]);
    swapped.extend_from_slice(&good[snapshot_at + 1 + 8 + EMPTY_BODY_LEN..]);
    assert!(matches!(
        Trace::read(Cursor::new(&swapped)).expect_err("before the checkpoint"),
        TraceFault::UnanchoredSnapshot
    ));
    // Reader: two snapshots.
    let mut doubled = good[..snapshot_at + 1 + 8 + EMPTY_BODY_LEN].to_vec();
    doubled.extend_from_slice(&good[snapshot_at..]);
    assert!(matches!(
        Trace::read(Cursor::new(&doubled)).expect_err("two snapshots"),
        TraceFault::DuplicateSnapshot { height: 0 }
    ));
    // Reader: a row the snapshot refuses — a second row of a singleton
    // family — is the snapshot's fault, carried.
    let mut two_watermarks = good[..snapshot_at + 1 + 8 + 9 * 8].to_vec();
    two_watermarks.extend_from_slice(&2u64.to_le_bytes());
    for epoch in [1u64, 2] {
        two_watermarks.extend_from_slice(&8u32.to_le_bytes());
        two_watermarks.extend_from_slice(&epoch.to_le_bytes());
    }
    two_watermarks.extend_from_slice(&good[snapshot_at + 1 + 8 + EMPTY_BODY_LEN..]);
    assert!(matches!(
        Trace::read(Cursor::new(&two_watermarks)).expect_err("two watermarks"),
        TraceFault::Snapshot(SnapshotFault::SecondSingletonRow { .. })
    ));
}

#[test]
fn a_facts_record_after_the_last_height_is_a_fault_on_both_sides() {
    // The writer may record u64::MAX; nothing follows it. The reader meets
    // the same edge as a fault — a crafted file does not take the replay
    // binary down through an `expect`.
    let mut w = TraceWriter::new(Vec::new()).expect("header");
    w.push_facts(h(u64::MAX), &facts_at(0))
        .expect("the last height");
    assert!(matches!(
        w.push_facts(h(0), &facts_at(0)).expect_err("no successor"),
        TraceFault::HeightExhausted { after: u64::MAX }
    ));
    let mut two = w.finish().expect("trailer");
    let record = 1 + 8 + FACTS_LEN;
    // Duplicate the one facts record and fix the trailer's count: the
    // second record now follows u64::MAX.
    let first = two[16..16 + record].to_vec();
    two.splice(16 + record..16 + record, first);
    let n = two.len();
    two[n - 16..n - 8].copy_from_slice(&2u64.to_le_bytes());
    assert!(matches!(
        Trace::read(Cursor::new(&two)).expect_err("no successor"),
        TraceFault::HeightExhausted { after: u64::MAX }
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

#[cfg(feature = "fetch")]
mod fetch {
    use std::collections::VecDeque;
    use std::future::Future;
    use std::sync::{Arc, Mutex};

    use shekyl_rpc_client::{Rpc, RpcError};
    use shekyl_rpc_types::{
        BlockEntry, GetBlocksByHeightRequest, GetBlocksByHeightResponse, RpcStatus,
    };
    use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch, ShardId};

    use super::three_blocks;
    use crate::corpus::{CorpusFault, CorpusNet, CorpusReader, CorpusWriter};
    use crate::fetch::{fetch_corpus, FetchFault, ROUTE};
    use crate::source::{IngestEvent, Injection, Sequenced, ServeCredit, Source};

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

    fn batch(n: usize) -> std::num::NonZeroUsize {
        std::num::NonZeroUsize::new(n).expect("non-zero")
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
        let written = fetch_corpus(&rpc, 0..3, batch(2), &[], &mut w)
            .await
            .expect("fetched");
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
        let err = fetch_corpus(&rpc, 0..3, batch(10), &[], &mut w)
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
        let err = fetch_corpus(&rpc, 0..3, batch(10), &[], &mut w)
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
        let err = fetch_corpus(&rpc, 0..3, batch(10), &[], &mut w)
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
            fetch_corpus(&rpc, 0..1, batch(1), &[], &mut w)
                .await
                .expect_err("transport"),
            FetchFault::Rpc(RpcError::ConnectionError(_))
        ));
    }

    fn receipt(at: u64, tag: u8) -> Injection {
        Injection {
            at: BlockHeight::from_raw(at),
            credit: ServeCredit {
                persona: PCanonicalId::from_bytes([tag; 32]),
                shard: ShardId::from_raw(u64::from(tag) + 100),
                epoch: SettlementEpoch::from_raw(u64::from(tag)),
            },
        }
    }

    /// The injector's receipts are placed right after the block at their
    /// height — across a batch boundary, two at one height in the order
    /// given — and the corpus reads the `Inject` back where the daemon
    /// wrote it. A receipt the range does not reach is refused before the
    /// first request.
    #[tokio::test]
    async fn injections_land_beside_their_block_and_a_stray_one_is_refused_first() {
        let blocks = three_blocks();
        let rpc = Scripted::new(&[reply(&blocks[..2]), reply(&blocks[2..])]);
        let mut w = CorpusWriter::create(
            std::io::Cursor::new(Vec::new()),
            CorpusNet::Fakechain,
            BlockHeight::from_raw(0),
        )
        .expect("header");
        // Out of height order on purpose: placement is by `at`, not by
        // position in the flag list.
        let receipts = [receipt(2, 0x22), receipt(1, 0x11), receipt(2, 0x33)];
        let written = fetch_corpus(&rpc, 0..3, batch(2), &receipts, &mut w)
            .await
            .expect("fetched");
        assert_eq!(written, 3, "blocks, not records");
        let bytes = w.finish().expect("count").into_inner();
        let mut r = CorpusReader::open(std::io::Cursor::new(&bytes)).expect("open");
        assert_eq!(r.declared(), 6);
        let mut shape = Vec::new();
        while let Some(Sequenced { event, .. }) = r.next().expect("record") {
            shape.push(match event {
                IngestEvent::Extend(_) => None,
                IngestEvent::Inject(credit) => Some(credit),
                other => panic!("{other:?}"),
            });
        }
        assert_eq!(
            shape,
            vec![
                None,
                None,
                Some(receipts[1].credit),
                None,
                Some(receipts[0].credit),
                Some(receipts[2].credit),
            ]
        );

        let rpc = Scripted::new(&[reply(&blocks)]);
        let mut w = CorpusWriter::create(
            std::io::Cursor::new(Vec::new()),
            CorpusNet::Fakechain,
            BlockHeight::from_raw(0),
        )
        .expect("header");
        let err = fetch_corpus(&rpc, 0..3, batch(10), &[receipt(3, 0x44)], &mut w)
            .await
            .expect_err("stray");
        assert!(
            matches!(err, FetchFault::InjectionOutOfRange { injection } if injection == receipt(3, 0x44)),
            "{err}"
        );
        assert!(
            rpc.asked.lock().expect("lock").is_empty(),
            "refused before any block was requested"
        );
    }
}
