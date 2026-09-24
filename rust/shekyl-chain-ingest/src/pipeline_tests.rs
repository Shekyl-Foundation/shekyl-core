// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The connector and the driver (§7 commit 5). The **first** test is the
//! no-restart test, written while the actor was small, as ruled.

use std::num::NonZeroUsize;
use std::sync::Arc;

use kameo::actor::Spawn;
use kameo::error::SendError;
use redb::ReadableTable;
use shekyl_chain_rules::harness::MockSubstrate;
use shekyl_chain_rules::{
    form, Candidate, CenRow, FormAttempt, InvalidBlock, Locus, Retry, RuleSet, StructurallyValid,
    Verdict,
};
use shekyl_chain_store::codec::{BlockInfo, Canonical, Present};
use shekyl_chain_store::lmdb_order::LmdbHashKey;
use shekyl_chain_store::schema::{BLOCK_INFO, CURVE_TREE_ROOTS, SPENT_KEYS};
use shekyl_chain_store::store::{ConnectState, StoreError, StoreInvariant};
use shekyl_difficulty::{CumulativeDifficulty, SEEDHASH_EPOCH_BLOCKS, SEEDHASH_EPOCH_LAG};
use shekyl_types::{BlockHash, CurveTreeRoot};

use crate::connector::{Apply, Connector, ConnectorArgs, Digest, HashAt, RunEnd, RunFault};
use crate::corpus::CorpusReader;
use crate::metrics::Metrics;
use crate::pipeline::{run, Checkpoint, PipelineConfig, PipelineFault};
use crate::schedule::ChainRules;
use crate::sequencer::SequenceError;
use crate::source::{IngestEvent, SequenceNo, Sequenced};
use crate::test_support::{
    block_with_nonce, chain, cleanup, corpus_from, corpus_of, corpus_of_reorg, expected_state, h,
    key_image, open_store, reorg, spend, tmp, trace_of, Family, Scripted,
};
use crate::trace::Trace;

/// Regtest without a fixed target: the genesis rules at every height.
const GENESIS_RULES: ChainRules = ChainRules::Regtest {
    fixed_difficulty: None,
};

fn nz(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n).expect("non-zero")
}

/// A config small enough that a few blocks exercise the window and the
/// hasher bound both.
fn cfg(window: usize) -> PipelineConfig {
    PipelineConfig {
        window: nz(window),
        hashers: nz(2),
    }
}

fn substrate() -> Arc<MockSubstrate> {
    Arc::new(MockSubstrate::default())
}

/// Form one candidate at `height` under GENESIS with the mock substrate,
/// claiming `seed`.
fn formed(
    height: u64,
    candidate: Candidate,
    seed: BlockHash,
) -> (shekyl_types::BlockHeight, Verdict<StructurallyValid>) {
    let verdict = form(
        candidate,
        &RuleSet::GENESIS,
        &MockSubstrate::default(),
        seed,
        FormAttempt::FIRST,
    )
    .expect("mock substrate forms");
    (h(height), verdict)
}

fn candidate(b: &shekyl_wire::Block, txs: &[shekyl_wire::Transaction]) -> Candidate {
    Candidate::new(b.clone(), txs.to_vec())
}

fn tip_of(path: &std::path::Path) -> Option<(shekyl_types::BlockHeight, BlockHash)> {
    let reopened = open_store(path);
    let tip = reopened
        .begin_read()
        .expect("read")
        .tip()
        .expect("tip")
        .recorded
        .map(|t| (t.height, t.hash));
    drop(reopened);
    tip
}

// ------------------------------------------------------- the first test

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_connector_stays_stopped_after_a_halt_and_does_not_come_back() {
    // RD-Q11: a halt is terminal. Connect genesis, then break the file
    // under the actor (the root row block 1's validation reads), so the
    // validator's view read comes back SI-7 through Fault::View — the
    // supervision table's "halt" row. Every later message is refused as
    // Over; once stopped the actor is not alive and nothing revives it.
    let path = tmp("connector-halt");
    let chain = chain(2);
    let trace = Arc::new(trace_of(&chain, false));

    // Genesis lands through a first connector, which is then stopped and
    // joined so the store is released; the record is broken; a second
    // connector is spawned on the reopened store and meets the hole.
    {
        let prepared =
            kameo::actor::PreparedActor::<Connector<Trace>>::new(kameo::mailbox::unbounded());
        let first = prepared.actor_ref().clone();
        let task = prepared.spawn(ConnectorArgs {
            store: open_store(&path),
            rules: GENESIS_RULES,
            facts: Arc::clone(&trace),
        });
        let (h0, f0) = formed(0, candidate(&chain[0].0, &chain[0].1), BlockHash::NULL);
        let applied = first
            .ask(Apply(vec![(h0, f0)]))
            .await
            .expect("genesis connects");
        assert_eq!(applied.connected.len(), 1);
        assert!(applied.refused.is_none());
        first.stop_gracefully().await.expect("stop");
        first.wait_for_shutdown().await;
        let _joined = task.await;
    }
    // Break the record: curve_tree_roots[1] is what block 1's B5 reads.
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        {
            let mut roots = txn.open_table(CURVE_TREE_ROOTS).expect("t");
            roots.remove(1u64).expect("remove");
        }
        txn.commit().expect("commit");
    }
    let connector = Connector::spawn(ConnectorArgs {
        store: open_store(&path),
        rules: GENESIS_RULES,
        facts: trace,
    });

    let (h1, f1) = formed(1, candidate(&chain[1].0, &chain[1].1), chain[0].0.hash());
    let err = connector
        .ask(Apply(vec![(h1, f1)]))
        .await
        .expect_err("the view read is SI-7 → halt");
    let SendError::HandlerError(RunFault::Store(StoreError::InvariantViolated(row))) = err else {
        panic!("expected the store's violation, got {err:?}");
    };
    assert_eq!(row.row(), 7, "SI-7: the root row is absent below the tip");

    // Over: the same message again is refused with the recorded end, and
    // so is a rewind — the latch is the writer's, not each handler's.
    let (h1b, f1b) = formed(1, candidate(&chain[1].0, &chain[1].1), chain[0].0.hash());
    let again = connector
        .ask(Apply(vec![(h1b, f1b)]))
        .await
        .expect_err("over");
    assert!(
        matches!(
            again,
            SendError::HandlerError(RunFault::Over(RunEnd::Halted(
                StoreInvariant::CellCorrupt { .. }
            )))
        ),
        "{again:?}"
    );
    let rewind = connector
        .ask(crate::connector::Rewind { to: h(0) })
        .await
        .expect_err("over");
    assert!(
        matches!(rewind, SendError::HandlerError(RunFault::Over(_))),
        "{rewind:?}"
    );
    // Reads stay open on a halted store — and this one meets the same hole
    // the validator did, as SI-7, never as a verdict.
    let digest = connector.ask(Digest).await;
    assert!(
        matches!(
            digest,
            Err(SendError::HandlerError(RunFault::Store(
                StoreError::InvariantViolated(StoreInvariant::CellCorrupt {
                    key: "curve_tree_roots",
                    ..
                })
            )))
        ),
        "{digest:?}"
    );
    assert_eq!(
        connector
            .ask(HashAt { height: h(0) })
            .await
            .expect("a read"),
        Some(chain[0].0.hash()),
        "the hash read stays open too"
    );

    // Stopped stays stopped: no supervisor, no restart.
    connector.stop_gracefully().await.expect("stop");
    connector.wait_for_shutdown().await;
    assert!(!connector.is_alive());
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(!connector.is_alive(), "nothing revived the actor");
    let (h1c, f1c) = formed(1, candidate(&chain[1].0, &chain[1].1), chain[0].0.hash());
    assert!(matches!(
        connector
            .ask(Apply(vec![(h1c, f1c)]))
            .await
            .expect_err("dead"),
        SendError::ActorNotRunning(_)
    ));

    // The halt is not persisted (a restart re-derives it), but block 1
    // never landed.
    let reopened = open_store(&path);
    assert_eq!(reopened.connect_state(), ConnectState::Live);
    drop(reopened);
    assert_eq!(tip_of(&path).map(|t| t.0), Some(h(0)));
    cleanup(&path);
}

// ------------------------------------------------------------ the run

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_corpus_replays_end_to_end_and_the_redb_digest_matches_the_trace_checkpoint() {
    let path = tmp("pipeline-replay");
    let chain = chain(5);
    let trace = Arc::new(trace_of(&chain, true));
    let bytes = corpus_of(&chain);
    let mut source = CorpusReader::open(std::io::Cursor::new(&bytes)).expect("open");
    let metrics = Arc::new(Metrics::new());
    let report = run(
        &mut source,
        substrate(),
        Arc::clone(&metrics),
        GENESIS_RULES,
        open_store(&path),
        Arc::clone(&trace),
        cfg(2),
    )
    .await
    .expect("the corpus replays");
    assert_eq!(report.connected.len(), 5);
    assert_eq!(
        report
            .connected
            .iter()
            .map(|(hh, _)| hh.to_raw())
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4]
    );
    assert!(report.refused.is_none());
    assert_eq!(report.popped(), 0);
    assert_eq!(report.disagreements().count(), 0);
    // The checkpoint after block 4: the redb digest equals the trace's
    // expectation, and both equal the state computed from the chain.
    let Checkpoint { at, ours, theirs } = report.checkpoint.expect("covered-tip checkpoint");
    assert_eq!(at, h(4));
    assert_eq!(ours, theirs, "redb and the LMDB-shaped checkpoint agree");
    assert_eq!(ours, expected_state(&chain));
    // The measurement carries the concurrency it was taken under.
    assert_eq!(
        report.metrics.concurrency.map(|c| (c.hashers, c.window)),
        Some((2, 2))
    );
    assert_eq!(report.metrics.blocks_formed, 5);
    assert_eq!(tip_of(&path).map(|t| t.0), Some(h(4)));
    cleanup(&path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_seed_is_a_driver_defect_surfaced_on_first_occurrence() {
    // RD-Q5: the retry path exists (the fault carries Retry::Again(2)) and
    // is exercised here by injection, never by waiting for a bug; the
    // connector surfaces it and stays up.
    let path = tmp("connector-stale-seed");
    let chain = chain(2);
    let trace = Arc::new(trace_of(&chain, false));
    let connector = Connector::spawn(ConnectorArgs {
        store: open_store(&path),
        rules: GENESIS_RULES,
        facts: trace,
    });
    let (h0, f0) = formed(0, candidate(&chain[0].0, &chain[0].1), BlockHash::NULL);
    connector.ask(Apply(vec![(h0, f0)])).await.expect("genesis");
    let wrong = BlockHash::from_bytes([0xee; 32]);
    let (h1, f1) = formed(1, candidate(&chain[1].0, &chain[1].1), wrong);
    let err = connector
        .ask(Apply(vec![(h1, f1)]))
        .await
        .expect_err("stale seed");
    match err {
        SendError::HandlerError(RunFault::StaleSeed {
            height,
            claimed,
            expected,
            retry,
        }) => {
            assert_eq!(height, h(1));
            assert_eq!(claimed, wrong);
            assert_eq!(expected, chain[0].0.hash());
            assert!(matches!(retry, Retry::Again(a) if a.number() == 2));
        }
        other => panic!("{other:?}"),
    }
    let again = connector.ask(Digest).await;
    assert!(again.is_ok(), "reads are unaffected");
    // The writer stays up: a later Apply with the store's seed connects.
    // Replay treats StaleSeed as run-ending; E3 re-forms on this actor.
    let (h1b, f1b) = formed(1, candidate(&chain[1].0, &chain[1].1), chain[0].0.hash());
    let applied = connector
        .ask(Apply(vec![(h1b, f1b)]))
        .await
        .expect("writer stayed up");
    assert_eq!(applied.connected.len(), 1);
    assert!(applied.refused.is_none());
    connector.stop_gracefully().await.expect("stop");
    connector.wait_for_shutdown().await;
    cleanup(&path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_is_a_verdict_and_the_writer_stays_up() {
    // A verdict is data on Applied. The writer does not go Over, so a
    // later Apply at the same height can still run (E3 / mutation family).
    let path = tmp("connector-refusal");
    let chain = chain(2);
    let trace = Arc::new(trace_of(&chain, false));
    let connector = Connector::spawn(ConnectorArgs {
        store: open_store(&path),
        rules: GENESIS_RULES,
        facts: trace,
    });
    let (h0, f0) = formed(0, candidate(&chain[0].0, &chain[0].1), BlockHash::NULL);
    connector.ask(Apply(vec![(h0, f0)])).await.expect("genesis");
    let refused = InvalidBlock::new(CenRow::A1, Locus::Block);
    let applied = connector
        .ask(Apply(vec![(h(1), Err(refused))]))
        .await
        .expect("a verdict is data");
    assert_eq!(applied.refused, Some((h(1), refused)));
    assert!(applied.connected.is_empty());
    connector.ask(Digest).await.expect("writer is up");
    let (h1, f1) = formed(1, candidate(&chain[1].0, &chain[1].1), chain[0].0.hash());
    let applied = connector
        .ask(Apply(vec![(h1, f1)]))
        .await
        .expect("writer stayed up");
    assert_eq!(applied.connected.len(), 1);
    connector.stop_gracefully().await.expect("stop");
    connector.wait_for_shutdown().await;
    cleanup(&path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_ends_the_run_and_is_a_disagreement_the_report_names() {
    // The refusal reaches the report as a verdict and as a disagreement,
    // so a caller with no register cannot read the run as a pass.
    let path = tmp("pipeline-refusal");
    let main = chain(3);
    // Block 2 chained on a wrong parent: A2 refuses it.
    let orphan = block_with_nonce(2, BlockHash::from_bytes([0x77; 32]), &[], 5);
    let trace = Arc::new(trace_of(&main, false));
    let events = vec![
        IngestEvent::Extend(Box::new(candidate(&main[0].0, &main[0].1))),
        IngestEvent::Extend(Box::new(candidate(&main[1].0, &main[1].1))),
        IngestEvent::Extend(Box::new(candidate(&orphan, &[]))),
    ];
    let mut source = Scripted::new(events);
    let report = run(
        &mut source,
        substrate(),
        Arc::new(Metrics::new()),
        GENESIS_RULES,
        open_store(&path),
        trace,
        cfg(4),
    )
    .await
    .expect("a refusal is a verdict, not a fault");
    assert_eq!(report.connected.len(), 2);
    let (height, verdict) = report.refused.expect("refused");
    assert_eq!((height, verdict.rule), (h(2), CenRow::A2));
    assert_eq!(
        report.disagreements().collect::<Vec<_>>(),
        vec![crate::pipeline::Disagreement::Refused { height, verdict }]
    );
    assert_eq!(
        report.observations().refused,
        Some(("CEN-A2", h(2))),
        "derived from the report, not written beside it"
    );
    cleanup(&path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_corrupt_record_observed_by_the_validator_halts_through_refuse_corrupt() {
    // SI-10 end to end: replay N + 1 blocks, then lower one recorded
    // cumulative difficulty inside D4's window; the next block's
    // validation observes it, the connector hands it to refuse_corrupt,
    // and the run ends with the halt — never a verdict.
    let path = tmp("pipeline-corrupt");
    let n = shekyl_difficulty::N;
    let n_us = usize::try_from(n).expect("N is small");
    let chain = chain(n + 2);
    let trace = Arc::new(trace_of(&chain, false));
    let first = corpus_of(&chain[..=n_us]);
    let mut source = CorpusReader::open(std::io::Cursor::new(&first)).expect("open");
    let report = run(
        &mut source,
        substrate(),
        Arc::new(Metrics::new()),
        GENESIS_RULES,
        open_store(&path),
        Arc::clone(&trace),
        PipelineConfig::default(),
    )
    .await
    .expect("the first N + 1 blocks replay");
    assert_eq!(report.connected.len(), n_us + 1);

    // Plant: block_info[50].cumulative_difficulty below block 49's.
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        {
            let mut infos = txn.open_table(BLOCK_INFO).expect("t");
            let mut row: BlockInfo = infos
                .get(50u64)
                .expect("g")
                .expect("row")
                .value()
                .decode()
                .expect("decodes");
            row.cumulative_difficulty = CumulativeDifficulty::from_raw(1);
            infos
                .insert(50u64, row.encoded().as_encoded())
                .expect("plant");
        }
        txn.commit().expect("commit");
    }

    // The next block, through the pipeline, from a store that already holds
    // the chain (the seed claim asks the store for block 0).
    let rest = corpus_from(h(n + 1), &chain[n_us + 1..=n_us + 1]);
    let mut source = CorpusReader::open(std::io::Cursor::new(&rest)).expect("open");
    let err = run(
        &mut source,
        substrate(),
        Arc::new(Metrics::new()),
        GENESIS_RULES,
        open_store(&path),
        trace,
        PipelineConfig::default(),
    )
    .await
    .expect_err("the validator observes the planted decrease");
    // The store's `write` makes the violation win over anything else the
    // closure returned, so the fault is the SI-10 row itself, at the height
    // the validator's `Corrupt` named.
    match err {
        PipelineFault::Connector(RunFault::Store(StoreError::InvariantViolated(
            StoreInvariant::WorkNotIncreasing { height },
        ))) => {
            assert_eq!(height, 50);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        tip_of(&path).map(|t| t.0),
        Some(h(n)),
        "block N + 1 did not land"
    );
    cleanup(&path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_misaligned_source_is_refused_before_anything_is_formed() {
    // A corpus starting at 5 against an empty store: formed as is, block 5
    // would be judged at height 0 and its refusal read as a verdict.
    let path = tmp("pipeline-misaligned");
    let chain = chain(7);
    let trace = Arc::new(trace_of(&chain, false));
    let bytes = corpus_from(h(5), &chain[5..]);
    let mut source = CorpusReader::open(std::io::Cursor::new(&bytes)).expect("open");
    let err = run(
        &mut source,
        substrate(),
        Arc::new(Metrics::new()),
        GENESIS_RULES,
        open_store(&path),
        trace,
        cfg(2),
    )
    .await
    .expect_err("misaligned");
    assert!(
        matches!(
            err,
            PipelineFault::Misaligned {
                source_first,
                store_next
            } if source_first == h(5) && store_next == h(0)
        ),
        "{err:?}"
    );
    assert_eq!(tip_of(&path), None, "nothing was formed or connected");
    cleanup(&path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hole_in_the_sources_numbering_is_a_loud_fault_not_a_hang() {
    // A source that skips a number breaks the consecutive contract; the
    // driver says so at the event instead of parking the later item in the
    // sequencer behind a position nothing will fill.
    let path = tmp("pipeline-sequence-hole");
    let chain = chain(3);
    let trace = Arc::new(trace_of(&chain, false));
    let two = SequenceNo::FIRST.next().next();
    let events = vec![
        Sequenced {
            seq: SequenceNo::FIRST,
            event: IngestEvent::Extend(Box::new(candidate(&chain[0].0, &chain[0].1))),
        },
        Sequenced {
            seq: two,
            event: IngestEvent::Extend(Box::new(candidate(&chain[1].0, &chain[1].1))),
        },
    ];
    let mut source = Scripted::numbered(h(0), events);
    let err = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        run(
            &mut source,
            substrate(),
            Arc::new(Metrics::new()),
            GENESIS_RULES,
            open_store(&path),
            trace,
            cfg(4),
        ),
    )
    .await
    .expect("the run ends; it does not spin")
    .expect_err("a hole is a fault");
    assert!(
        matches!(
            err,
            PipelineFault::Sequence(SequenceError::NotNext { expected, found })
                if expected == SequenceNo::FIRST.next() && found == two
        ),
        "{err:?}"
    );
    cleanup(&path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rewind_pops_behind_the_barrier_and_the_fork_connects() {
    // RD-Q13: Extend 0, 1, 2; Rewind { to: 1 }; Extend 2' (another nonce);
    // Extend 3 on 2'. The rewind is a barrier — 2' is formed only after the
    // pop committed — and the fork's blocks chain onto the rewound tip.
    let path = tmp("pipeline-rewind");
    let main = chain(3);
    let fork_spend = |height| spend(key_image(Family::Fork, height));
    let fork2 = block_with_nonce(2, main[1].0.hash(), &[fork_spend(2)], 99);
    assert_ne!(fork2.hash(), main[2].0.hash());
    let fork3 = block_with_nonce(3, fork2.hash(), &[fork_spend(3)], 7);
    // Facts for heights 0..=3 (the fork reuses height 2's facts: same
    // root_after by construction). The fork spends its own family's key
    // images — reusing the main chain's would be the double spend SI-1
    // refuses.
    let trace_chain: Vec<_> = vec![
        main[0].clone(),
        main[1].clone(),
        (fork2.clone(), vec![fork_spend(2)]),
        (fork3.clone(), vec![fork_spend(3)]),
    ];
    let trace = Arc::new(trace_of(&trace_chain, true));
    let events = vec![
        IngestEvent::Extend(Box::new(candidate(&main[0].0, &main[0].1))),
        IngestEvent::Extend(Box::new(candidate(&main[1].0, &main[1].1))),
        IngestEvent::Extend(Box::new(candidate(&main[2].0, &main[2].1))),
        IngestEvent::Rewind { to: h(1) },
        IngestEvent::Extend(Box::new(candidate(&fork2, &[fork_spend(2)]))),
        IngestEvent::Extend(Box::new(candidate(&fork3, &[fork_spend(3)]))),
    ];
    let mut source = Scripted::new(events);
    let report = run(
        &mut source,
        substrate(),
        Arc::new(Metrics::new()),
        GENESIS_RULES,
        open_store(&path),
        Arc::clone(&trace),
        cfg(4),
    )
    .await
    .expect("the scripted reorg replays");
    assert_eq!(report.popped(), 1);
    let connected: Vec<(u64, BlockHash)> = report
        .connected
        .iter()
        .map(|(hh, x)| (hh.to_raw(), *x))
        .collect();
    assert_eq!(
        connected,
        vec![
            (0, main[0].0.hash()),
            (1, main[1].0.hash()),
            (2, main[2].0.hash()),
            (2, fork2.hash()),
            (3, fork3.hash()),
        ]
    );
    // The digest after the switch is the fork's, at the checkpoint (3).
    let Checkpoint { ours, theirs, .. } = report.checkpoint.expect("covered-tip checkpoint");
    assert_eq!(ours, theirs);
    assert_eq!(ours, expected_state(&trace_chain));
    assert_eq!(tip_of(&path), Some((h(3), fork3.hash())));
    cleanup(&path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rewind_across_a_seed_epoch_step_claims_the_seed_from_the_store() {
    // The seed ledger is a window: once block 2113 is formed under seed
    // height 2048, everything below 2048 is forgotten. A rewind to 2111
    // then forms 2112' whose seed height is 0 — a height the ledger no
    // longer holds and the store does. A depth-two reorg at every epoch
    // rollover is routine on a live chain; this run must not end with
    // SeedUnknown. Main 0..=2113, rewind to 2111, fork 2112'..=2114'.
    let path = tmp("pipeline-rewind-epoch");
    let boundary = SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG + 1; // 2113
    let r = reorg(boundary + 1, boundary - 2, 3);
    let trace = Arc::new(trace_of(&r.after, true));
    let bytes = corpus_of_reorg(&r);
    let mut source = CorpusReader::open(std::io::Cursor::new(&bytes)).expect("open");
    let report = run(
        &mut source,
        substrate(),
        Arc::new(Metrics::new()),
        GENESIS_RULES,
        open_store(&path),
        trace,
        PipelineConfig {
            window: PipelineConfig::DEFAULT_WINDOW,
            hashers: nz(4),
        },
    )
    .await
    .expect("the rewind across the epoch step replays");
    assert_eq!(report.switches.len(), 1);
    assert_eq!(
        (report.switches[0].to, report.switches[0].popped),
        (h(boundary - 2), 2)
    );
    assert_eq!(
        report.connected.len(),
        usize::try_from(boundary + 1 + 3).expect("small")
    );
    let Checkpoint { at, ours, theirs } = report.checkpoint.expect("covered-tip checkpoint");
    assert_eq!(at, h(boundary + 1));
    assert_eq!(ours, theirs, "the fork's tip matches its own trace");
    assert_eq!(ours, expected_state(&r.after));
    cleanup(&path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_regtest_corpus_replays_under_a_fixed_difficulty_and_connects() {
    // RD-Q7 through the pipeline: `--fixed-difficulty 7` → RuleSet::fakechain(7)
    // in force at every height, formed and validated under the same set,
    // and connect accepts it (RD-F13's repair) while the CEN-B3 belt lands
    // GENESIS's id. Cumulative work climbs by the fixed target per block.
    let path = tmp("pipeline-fakechain");
    let chain = chain(4);
    let trace = Arc::new(trace_of(&chain, false));
    let bytes = corpus_of(&chain);
    let mut source = CorpusReader::open(std::io::Cursor::new(&bytes)).expect("open");
    let rules = ChainRules::Regtest {
        fixed_difficulty: std::num::NonZeroU128::new(7),
    };
    let report = run(
        &mut source,
        substrate(),
        Arc::new(Metrics::new()),
        rules,
        open_store(&path),
        trace,
        PipelineConfig::default(),
    )
    .await
    .expect("a fakechain corpus replays under its own set");
    assert_eq!(report.connected.len(), 4);
    let reopened = open_store(&path);
    let snap = reopened.begin_read().expect("read");
    let shekyl_chain_rules::AtHeight::Recorded(info) = snap.block_info(h(3)).expect("read") else {
        panic!("block 3 recorded");
    };
    // Genesis carries 1 (blockchain.cpp:975), then +7 per block.
    assert_eq!(
        info.cumulative_difficulty,
        CumulativeDifficulty::from_raw(1 + 3 * 7)
    );
    drop(snap);
    drop(reopened);
    cleanup(&path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replayed_run_grades_its_exercised_rows_correct_and_its_producers_borrowed() {
    // RD-Q6 through the pipeline: the observations the run emits, graded
    // against a register in the extractor's shape. Every row the landed
    // rules exercised grades AcceptedAsCorrect on the verdict clause; the
    // producers of passed-through facts are Borrowed on the component clause
    // whatever their verdict; the digest matched, so the rest are real.
    use crate::grader::{
        grade_run, ComponentEvidence, GradedAcceptance, Register, VerdictEvidence,
    };
    let path = tmp("pipeline-grade");
    let chain = chain(4);
    let trace = Arc::new(trace_of(&chain, true));
    let bytes = corpus_of(&chain);
    let mut source = CorpusReader::open(std::io::Cursor::new(&bytes)).expect("open");
    let report = run(
        &mut source,
        substrate(),
        Arc::new(Metrics::new()),
        GENESIS_RULES,
        open_store(&path),
        trace,
        PipelineConfig::default(),
    )
    .await
    .expect("replays");
    let obs = report.observations();
    assert!(!obs.exercised.is_empty(), "the landed rules ran");
    assert_eq!(obs.digest_identical, Some(true));

    // A register naming every exercised row CHECKED-CONFORMANT, plus the
    // root producers as the register has them.
    let mut rows: Vec<String> = obs
        .exercised
        .iter()
        .map(|id| format!("{{\"id\": \"{id}\", \"state\": \"CHECKED-CONFORMANT\"}}"))
        .collect();
    for extra in ["CEN-G6", "CEN-I12"] {
        if !obs.exercised.contains(extra) {
            rows.push(format!(
                "{{\"id\": \"{extra}\", \"state\": \"CHECKED-CONFORMANT\"}}"
            ));
        }
    }
    let json = format!(
        "{{\"schema_version\": \"shekyl_e2_register_v1\", \"rows\": [{}], \"unrecorded_ratified\": []}}",
        rows.join(",")
    );
    let register = Register::from_json(&json).expect("register");
    let graded = grade_run(&register, &obs);
    assert!(graded.passes(), "{:?}", graded.unadjudicated);
    assert!(graded.refusal.is_none());
    for row in &graded.rows {
        if obs.exercised.contains(row.id.as_str()) {
            assert_eq!(
                row.verdict,
                VerdictEvidence::Exercised { agreed: true },
                "{}",
                row.id
            );
            assert_eq!(
                row.verdict_acceptance,
                Some(GradedAcceptance::AcceptedAsCorrect),
                "{}",
                row.id
            );
        }
        let is_producer = shekyl_chain_store::store::ConnectFacts::DELETED_BY
            .iter()
            .any(|d| d.rows.contains(&row.id.as_str()));
        if is_producer {
            assert!(
                matches!(row.component, ComponentEvidence::Borrowed { .. }),
                "{}",
                row.id
            );
        } else {
            assert_eq!(
                row.component,
                ComponentEvidence::Real { identical: true },
                "{}",
                row.id
            );
        }
    }
    assert_eq!(graded.derived_and_conformant, obs.exercised.len());
    cleanup(&path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_reorg_family_replays_through_the_corpus_reader_with_a_digest_after_the_switch() {
    // §3.8 / RD-Q13 through the real Source: main 0..=4, rewind to 1,
    // fork 2'..=5'. The digest after the switch is the state at 1 exactly as
    // it was when 1 was first the tip (pop symmetry through the actor); the
    // trace checkpoint at the fork's tip (5, beyond every pre-switch tip)
    // MATCHes the fork's state.
    let path = tmp("pipeline-reorg-family");
    let r = reorg(5, 1, 4);
    let trace = Arc::new(trace_of(&r.after, true));
    let bytes = corpus_of_reorg(&r);
    let mut source = CorpusReader::open(std::io::Cursor::new(&bytes)).expect("open");
    let report = run(
        &mut source,
        substrate(),
        Arc::new(Metrics::new()),
        GENESIS_RULES,
        open_store(&path),
        trace,
        cfg(2),
    )
    .await
    .expect("the reorg replays");
    assert_eq!(report.popped(), 3, "blocks 2, 3, 4 popped");
    assert_eq!(report.switches.len(), 1);
    let sw = &report.switches[0];
    assert_eq!((sw.to, sw.popped), (h(1), 3));
    assert_eq!(
        sw.digest,
        expected_state(&r.main[..=1]),
        "pop restored the state at 1"
    );
    let connected: Vec<u64> = report.connected.iter().map(|(hh, _)| hh.to_raw()).collect();
    assert_eq!(connected, [0, 1, 2, 3, 4, 2, 3, 4, 5]);
    let Checkpoint { at, ours, theirs } = report.checkpoint.expect("covered-tip checkpoint");
    assert_eq!(at, h(5));
    assert_eq!(ours, theirs, "the fork's tip matches its own trace");
    assert_eq!(ours, expected_state(&r.after));
    assert_eq!(report.observations().digest_identical, Some(true));
    cleanup(&path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_checkpoint_goes_red_and_the_graded_run_does_not_pass() {
    // The comparator's negative control on the expectation side (rule 47):
    // a trace whose checkpoint is anything but the chain's state DIVERGEs,
    // the report names the disagreement, and the grade fails every
    // CHECKED-CONFORMANT row on the component clause. The store side's
    // controls — one mutation per digested family — follow.
    use crate::grader::{grade_run, Clause, GradedAcceptance, Register};
    use crate::trace::{Trace, TraceWriter};
    let path = tmp("pipeline-negative-control");
    let chain = chain(3);
    let trace = {
        let mut w = TraceWriter::new(Vec::new()).expect("header");
        for hh in 0..3u64 {
            w.push_facts(h(hh), &crate::test_support::facts_at(hh))
                .expect("facts");
        }
        w.push_checkpoint(&[0xEE; 32]).expect("a wrong checkpoint");
        Arc::new(Trace::read(std::io::Cursor::new(w.finish().expect("trailer"))).expect("read"))
    };
    let bytes = corpus_of(&chain);
    let mut source = CorpusReader::open(std::io::Cursor::new(&bytes)).expect("open");
    let report = run(
        &mut source,
        substrate(),
        Arc::new(Metrics::new()),
        GENESIS_RULES,
        open_store(&path),
        trace,
        PipelineConfig::default(),
    )
    .await
    .expect("the run itself completes; the verdict is the grader's");
    let checkpoint = report.checkpoint.expect("covered-tip checkpoint");
    assert!(!checkpoint.identical(), "DIVERGE");
    assert_eq!(
        report.disagreements().collect::<Vec<_>>(),
        vec![crate::pipeline::Disagreement::Diverged { at: h(2) }]
    );
    let obs = report.observations();
    assert_eq!(obs.digest_identical, Some(false));
    let register = Register::from_json(
        r#"{"schema_version":"shekyl_e2_register_v1","rows":[{"id":"CEN-A1","state":"CHECKED-CONFORMANT"}],"unrecorded_ratified":[]}"#,
    )
    .expect("register");
    let graded = grade_run(&register, &obs);
    assert!(!graded.passes());
    assert_eq!(
        (
            graded.unadjudicated[0].clause,
            graded.unadjudicated[0].acceptance
        ),
        (
            Clause::Component,
            GradedAcceptance::FailedConformantDiffered
        )
    );
    cleanup(&path);
}

/// The store side of the negative control: replay a chain whose trace
/// checkpoint matches, then mutate **one row of one digested family** in
/// raw redb and read the digest again. Each family must move the digest on
/// its own — the checkpoint's families are `block_info.hash`,
/// `spent_keys` and `curve_tree_roots[tip + 1]` — or a corruption in that
/// family would be invisible to the comparator.
async fn digest_after_replay_and_mutation(
    name: &str,
    mutate: impl FnOnce(&redb::WriteTransaction),
) -> (crate::trace::Digest, crate::trace::Digest) {
    let path = tmp(name);
    let chain = chain(4);
    let trace = Arc::new(trace_of(&chain, true));
    let bytes = corpus_of(&chain);
    let mut source = CorpusReader::open(std::io::Cursor::new(&bytes)).expect("open");
    let report = run(
        &mut source,
        substrate(),
        Arc::new(Metrics::new()),
        GENESIS_RULES,
        open_store(&path),
        trace,
        PipelineConfig::default(),
    )
    .await
    .expect("replays");
    let checkpoint = report.checkpoint.expect("covered-tip checkpoint");
    assert!(checkpoint.identical(), "the control's baseline is a MATCH");
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        mutate(&txn);
        txn.commit().expect("commit");
    }
    let reopened = open_store(&path);
    let after = reopened
        .begin_read()
        .expect("read")
        .logical_state_digest_v0()
        .expect("digest");
    drop(reopened);
    cleanup(&path);
    (checkpoint.theirs, after)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_flipped_block_hash_row_moves_the_digest_off_the_checkpoint() {
    let (expected, after) = digest_after_replay_and_mutation("control-block-info", |txn| {
        let mut infos = txn.open_table(BLOCK_INFO).expect("t");
        let mut row: BlockInfo = infos
            .get(2u64)
            .expect("g")
            .expect("row")
            .value()
            .decode()
            .expect("decodes");
        let mut bytes = row.hash.to_bytes();
        bytes[0] ^= 0x01;
        row.hash = BlockHash::from_bytes(bytes);
        infos
            .insert(2u64, row.encoded().as_encoded())
            .expect("flip");
    })
    .await;
    assert_ne!(after, expected, "block_info.hash is in the digest");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dropped_spent_key_row_moves_the_digest_off_the_checkpoint() {
    let (expected, after) = digest_after_replay_and_mutation("control-spent-keys", |txn| {
        let mut spent = txn.open_table(SPENT_KEYS).expect("t");
        let removed = spent
            .remove(LmdbHashKey::from_bytes(key_image(Family::Main, 2)))
            .expect("remove")
            .is_some();
        assert!(removed, "the row was there to drop");
        // And a foreign member the chain never spent, so the set differs
        // even for a comparator that counted rows.
        spent
            .insert(LmdbHashKey::from_bytes(key_image(Family::Fork, 2)), Present)
            .expect("plant");
    })
    .await;
    assert_ne!(after, expected, "spent_keys is in the digest");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rewritten_live_root_row_moves_the_digest_off_the_checkpoint() {
    let (expected, after) = digest_after_replay_and_mutation("control-live-root", |txn| {
        let mut roots = txn.open_table(CURVE_TREE_ROOTS).expect("t");
        // The live root is the row at tip + 1 = 4.
        roots
            .insert(
                4u64,
                CurveTreeRoot::from_bytes([0xd1; 32]).encoded().as_encoded(),
            )
            .expect("rewrite");
    })
    .await;
    assert_ne!(
        after, expected,
        "curve_tree_roots[tip + 1] is in the digest"
    );
}
