// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The connector and the driver (§7 commit 5). The **first** test is the
//! no-restart test, written while the actor was small, as ruled.

use std::sync::Arc;

use kameo::actor::Spawn;
use kameo::error::SendError;
use redb::ReadableTable;
use shekyl_chain_rules::harness::MockSubstrate;
use shekyl_chain_rules::{FormAttempt, Retry, RuleSet};
use shekyl_chain_store::codec::{BlockInfo, Canonical};
use shekyl_chain_store::schema::{BLOCK_INFO, CURVE_TREE_ROOTS};
use shekyl_chain_store::store::{ConnectState, StoreError, StoreInvariant};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::BlockHash;

use crate::connector::{Apply, Connector, ConnectorArgs, Digest, RunEnd, RunFault};
use crate::corpus::CorpusReader;
use crate::metrics::Metrics;
use crate::pipeline::{run, PipelineConfig, PipelineFault};
use crate::schedule::ChainRules;
use crate::source::IngestEvent;
use crate::stage::{form_extend, Staged};
use crate::test_support::{
    block_with_nonce, chain, cleanup, corpus_from, corpus_of, corpus_of_reorg, expected_state, h,
    open_store, reorg, spend, tmp, trace_of, Scripted,
};
use shekyl_chain_rules::Candidate;

/// Regtest without a fixed target: the genesis rules at every height.
const GENESIS_RULES: ChainRules = ChainRules::Regtest {
    fixed_difficulty: None,
};

fn substrate() -> Arc<MockSubstrate> {
    Arc::new(MockSubstrate::default())
}

/// Form one candidate at `height` under GENESIS with the mock substrate,
/// claiming `seed`.
fn formed(
    height: u64,
    candidate: Candidate,
    seed: BlockHash,
) -> (
    shekyl_types::BlockHeight,
    Box<shekyl_chain_rules::Verdict<shekyl_chain_rules::StructurallyValid>>,
) {
    match form_extend(
        h(height),
        candidate,
        &RuleSet::GENESIS,
        &MockSubstrate::default(),
        seed,
        FormAttempt::FIRST,
    ) {
        Ok(Staged::Extend { height, formed }) => (height, formed),
        other => panic!("form: {other:?}"),
    }
}

fn candidate(b: &shekyl_wire::Block, txs: &[shekyl_wire::Transaction]) -> Candidate {
    Candidate::new(b.clone(), txs.to_vec())
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
        let prepared = kameo::actor::PreparedActor::<Connector>::new(kameo::mailbox::unbounded());
        let first = prepared.actor_ref().clone();
        let task = prepared.spawn(ConnectorArgs {
            store: open_store(&path),
            rules: GENESIS_RULES,
            trace: Arc::clone(&trace),
        });
        let (h0, f0) = formed(0, candidate(&chain[0].0, &chain[0].1), BlockHash::NULL);
        let applied = first
            .ask(Apply(vec![(h0, *f0)]))
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
        trace,
    });

    let (h1, f1) = formed(1, candidate(&chain[1].0, &chain[1].1), chain[0].0.hash());
    let err = connector
        .ask(Apply(vec![(h1, *f1)]))
        .await
        .expect_err("the view read is SI-7 → halt");
    let SendError::HandlerError(RunFault::Store(StoreError::InvariantViolated(row))) = err else {
        panic!("expected the store's violation, got {err:?}");
    };
    assert_eq!(row.row(), 7, "SI-7: the root row is absent below the tip");

    // Over: the same message again is refused with the recorded end.
    let (h1b, f1b) = formed(1, candidate(&chain[1].0, &chain[1].1), chain[0].0.hash());
    let again = connector
        .ask(Apply(vec![(h1b, *f1b)]))
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

    // Stopped stays stopped: no supervisor, no restart.
    connector.stop_gracefully().await.expect("stop");
    connector.wait_for_shutdown().await;
    assert!(!connector.is_alive());
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(!connector.is_alive(), "nothing revived the actor");
    let (h1c, f1c) = formed(1, candidate(&chain[1].0, &chain[1].1), chain[0].0.hash());
    assert!(matches!(
        connector
            .ask(Apply(vec![(h1c, *f1c)]))
            .await
            .expect_err("dead"),
        SendError::ActorNotRunning(_)
    ));

    // The halt is not persisted (a restart re-derives it), but block 1
    // never landed.
    let reopened = open_store(&path);
    assert_eq!(reopened.connect_state(), ConnectState::Live);
    let tip = reopened
        .begin_read()
        .expect("read")
        .tip()
        .expect("tip")
        .recorded
        .map(|t| t.height);
    assert_eq!(tip, Some(h(0)));
    drop(reopened);
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
    let report = run(
        &mut source,
        substrate(),
        Arc::new(Metrics::new()),
        GENESIS_RULES,
        open_store(&path),
        Arc::clone(&trace),
        PipelineConfig { window: 2 },
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
    assert_eq!(report.popped, 0);
    // The checkpoint after block 4: the redb digest equals the trace's
    // expectation, and both equal the state computed from the chain.
    assert_eq!(report.checkpoints.len(), 1);
    let (at, ours, theirs) = &report.checkpoints[0];
    assert_eq!(*at, h(4));
    assert_eq!(ours, theirs, "redb and the LMDB-shaped checkpoint agree");
    assert_eq!(*ours, expected_state(&chain));

    let reopened = open_store(&path);
    let tip = reopened
        .begin_read()
        .expect("read")
        .tip()
        .expect("tip")
        .recorded
        .map(|t| t.height);
    assert_eq!(tip, Some(h(4)));
    drop(reopened);
    cleanup(&path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_seed_is_a_driver_defect_surfaced_on_first_occurrence() {
    // RD-Q5: the retry path exists (the fault carries Retry::Again(2)) and
    // is exercised here by injection, never by waiting for a bug; the
    // connector surfaces it and the run is over.
    let path = tmp("connector-stale-seed");
    let chain = chain(2);
    let trace = Arc::new(trace_of(&chain, false));
    let connector = Connector::spawn(ConnectorArgs {
        store: open_store(&path),
        rules: GENESIS_RULES,
        trace,
    });
    let (h0, f0) = formed(0, candidate(&chain[0].0, &chain[0].1), BlockHash::NULL);
    connector
        .ask(Apply(vec![(h0, *f0)]))
        .await
        .expect("genesis");
    let wrong = BlockHash::from_bytes([0xee; 32]);
    let (h1, f1) = formed(1, candidate(&chain[1].0, &chain[1].1), wrong);
    let err = connector
        .ask(Apply(vec![(h1, *f1)]))
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
    let (h1b, f1b) = formed(1, candidate(&chain[1].0, &chain[1].1), chain[0].0.hash());
    assert!(matches!(
        connector
            .ask(Apply(vec![(h1b, *f1b)]))
            .await
            .expect_err("over"),
        SendError::HandlerError(RunFault::Over(RunEnd::StaleSeed { .. }))
    ));
    connector.stop_gracefully().await.expect("stop");
    connector.wait_for_shutdown().await;
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
    // the chain (the ledger warms from the store).
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
    let reopened = open_store(&path);
    let tip = reopened
        .begin_read()
        .expect("read")
        .tip()
        .expect("tip")
        .recorded
        .map(|t| t.height);
    assert_eq!(tip, Some(h(n)), "block N + 1 did not land");
    drop(reopened);
    cleanup(&path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rewind_pops_behind_the_barrier_and_the_fork_connects() {
    // RD-Q13: Extend 0, 1, 2; Rewind { to: 1 }; Extend 2' (another nonce);
    // Extend 3 on 2'. The rewind is a barrier — 2' is formed only after the
    // pop committed — and the fork's blocks chain onto the rewound tip.
    let path = tmp("pipeline-rewind");
    let main = chain(3);
    let fork2 = block_with_nonce(2, main[1].0.hash(), &[spend(0x22)], 99);
    assert_ne!(fork2.hash(), main[2].0.hash());
    let fork3 = block_with_nonce(3, fork2.hash(), &[spend(0x23)], 7);
    // Facts for heights 0..=3 (the fork reuses height 2's facts: same
    // root_after by construction). The fork spends fresh key images —
    // reusing the main chain's would be the double spend SI-1 refuses.
    let trace_chain: Vec<_> = vec![
        main[0].clone(),
        main[1].clone(),
        (fork2.clone(), vec![spend(0x22)]),
        (fork3.clone(), vec![spend(0x23)]),
    ];
    let trace = Arc::new(trace_of(&trace_chain, true));
    let events = vec![
        IngestEvent::Extend(Box::new(candidate(&main[0].0, &main[0].1))),
        IngestEvent::Extend(Box::new(candidate(&main[1].0, &main[1].1))),
        IngestEvent::Extend(Box::new(candidate(&main[2].0, &main[2].1))),
        IngestEvent::Rewind { to: h(1) },
        IngestEvent::Extend(Box::new(candidate(&fork2, &[spend(0x22)]))),
        IngestEvent::Extend(Box::new(candidate(&fork3, &[spend(0x23)]))),
    ];
    let mut source = Scripted::new(events);
    let report = run(
        &mut source,
        substrate(),
        Arc::new(Metrics::new()),
        GENESIS_RULES,
        open_store(&path),
        Arc::clone(&trace),
        PipelineConfig { window: 4 },
    )
    .await
    .expect("the scripted reorg replays");
    assert_eq!(report.popped, 1);
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
    assert_eq!(report.checkpoints.len(), 1);
    let (_, ours, theirs) = &report.checkpoints[0];
    assert_eq!(ours, theirs);
    assert_eq!(*ours, expected_state(&trace_chain));

    let reopened = open_store(&path);
    let tip = reopened
        .begin_read()
        .expect("read")
        .tip()
        .expect("tip")
        .recorded;
    assert_eq!(tip.map(|t| (t.height, t.hash)), Some((h(3), fork3.hash())));
    drop(reopened);
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
    assert!(
        !report.observations.exercised.is_empty(),
        "the landed rules ran"
    );
    assert_eq!(report.observations.digest_identical, Some(true));

    // A register naming every exercised row CHECKED-CONFORMANT, plus the
    // root producers as the register has them.
    let mut rows: Vec<String> = report
        .observations
        .exercised
        .iter()
        .map(|id| format!("{{\"id\": \"{id}\", \"state\": \"CHECKED-CONFORMANT\"}}"))
        .collect();
    for extra in ["CEN-G6", "CEN-I12"] {
        if !report.observations.exercised.contains(extra) {
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
    let graded = grade_run(&register, &report.observations);
    assert!(graded.passes(), "{:?}", graded.unadjudicated);
    for row in &graded.rows {
        if report.observations.exercised.contains(row.id.as_str()) {
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
    assert_eq!(
        graded.derived_and_conformant,
        report.observations.exercised.len()
    );
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
        PipelineConfig { window: 2 },
    )
    .await
    .expect("the reorg replays");
    assert_eq!(report.popped, 3, "blocks 2, 3, 4 popped");
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
    assert_eq!(report.checkpoints.len(), 1);
    let (at, ours, theirs) = &report.checkpoints[0];
    assert_eq!(*at, h(5));
    assert_eq!(ours, theirs, "the fork's tip matches its own trace");
    assert_eq!(*ours, expected_state(&r.after));
    assert_eq!(report.observations.digest_identical, Some(true));
    cleanup(&path);
}
