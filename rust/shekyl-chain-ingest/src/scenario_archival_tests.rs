// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-L7 through the production stack (DRS-E4 commits 4 and 5,
//! `DRS_E4_ARCHIVAL_WRITER.md` §6 rows 4–5): bond posts a persona's keys
//! built and signed, riding the driver's real spend, judged by `validate`
//! over the redb store's view, connected by `ChainStore::connect` — which
//! since commit 5 writes the verdict's delta (`archival_write.rs`) — and
//! read back two ways: the transition off the connector's reply, and the
//! rows the next block's rules read off the store.
//!
//! # Which arms are witnessed here
//!
//! The archival transition has two kinds of arm. **Single-block arms**
//! judge the block in hand over a view that holds no bond — a join (the
//! record it inserts), the refusals of a post for a persona with no
//! record. **Multi-block arms** read a record a previous block wrote — a
//! release, a reinstate, a second join, a credit for a persona who joined
//! earlier. Commit 4 witnessed the first kind and pinned the second as
//! unreachable (nothing wrote a record); commit 5's writer turned that
//! pin, and `scenario_join_tests`'s
//! `a_join_is_written_and_the_blocks_after_it_read_the_record`
//! is the same test with the two assertions inverted: the record is `Some`
//! after the join, and the next block's credit for it connects. (*Was*,
//! until E6 slice 8 row 3: "a serve credit for a persona whose join is in
//! the same block" stood among the single-block arms. It is no arm at all
//! — CEN-J4 reads the record off the view before the block, so that
//! credit is refused on the record's absence; the credit's one witness is
//! multi-block.) The multi-block
//! arms follow on the same chain: a release of the persisted record (its
//! post-image read back), a release whose debit is not that record's total
//! refused at CEN-J16 before the valid one connects, a second join for a
//! bonded persona refused at CEN-J14, and a reinstate against a record
//! whose only interval is a clean close refused at CEN-J18 (*was* L7's,
//! all three, until E6 slice 8 row 5 landed the post rows ahead of the
//! fold) — the reinstate arm's *positive* witness needs an open interval,
//! which only a slash writes, and no fixture chain here reaches the slash
//! scan (a slash needs `M` epochs of settled misses and one epoch of
//! grace; `shekyl-chain-store`'s `slash_writes_land_at_the_m_epoch_deadline`
//! is that path's witness).
//!
//! One arm the plan listed as single-block is not. A join and a release
//! for one persona in one block do not reach L7, and the release arm's
//! positive witness is a release of a *persisted* record. *Records-was:*
//! until E6 slice 8 row 5 this file read the pair as **CEN-G10**'s refusal
//! (`bond_post_block_unique`, ratified 2026-07-12: one bond post per `P`
//! per block, whatever its kind) on the ground that "G10 runs before the
//! transition". It does — but the slot loop runs before G10, and with
//! CEN-J16 in it the release reads the view before the block, finds no
//! record for `P`, and is refused there (`RecordMissing`) a pass ahead of
//! G10. The C++ has the same order (`check_tx_inputs` per body, the
//! block's duplicate-post pass after), so the pair never reached G10 there
//! either; the sentence was true of the design and false of both
//! implementations. G10's witness is two posts that each pass the slot
//! loop alone: two **joins** for one `P`, pinned below.
//!
//! # The shards
//!
//! The compact persona joins shards 0 and 1, and the chain fills them
//! first (`scenario_shard`, E6 slice 8 §5 row 6): CEN-J15 admits a compact
//! join only onto shards closed, final and priced at its parent, so the
//! join scenario (`scenario_join_tests`) mines under the levered schedule,
//! closes the two shards with real spends, and joins at the first height
//! both operands lift. That is minutes of proofs, and it runs in the live
//! lane (`cargo test -p shekyl-chain-ingest --features pipeline -- --ignored
//! a_join_is_written`). The tests in this file post no compact holding and
//! stay on the production schedule in the default lane. (*Was:* shards 7
//! and 42 on a chain that had closed none — green because the C++ admitted
//! any shard id, and never a holding of anything.)
//!
//! # What the store says
//!
//! The accrual assertion is derived, not recomputed by the scenario: the verdict's
//! `Accrual` is the epoch's row as the store held it before the block plus
//! the block's own archival leg (`PaidEmission::accrual`), and the row the
//! store holds after the block is that sum. Both reads go through the
//! connector (`BudgetAccruingOf`, `BondRecordOf`), the same store the
//! validator's view reads.
//!
//! # What is fixture here
//!
//! The serve credit's Ed25519 countersignature (no Rust countersigner
//! exists; CEN-J1/J10 pending). That is not what L7 judges. Everything L7
//! reads — the post's fields, the persona's standing, the block's own
//! posts — is the production object over the production view. (*Was*,
//! until slice 6 row 6 on 2026-10-08: the funding spend's FCMP proof was
//! fixture too, the consensus-side verify pending on this class. It is
//! CEN-J27's now — the bond post's funding half, the reference context and
//! the proof over the funding spends as one row — and the honest join in
//! `posts_for_a_persona_with_no_record_are_refused_on_the_store` is its
//! pass, the same join with one proof byte flipped its refusal.)

use std::sync::Arc;

use kameo::error::SendError;
use shekyl_archival_retention::ARCHIVAL_BOND_FLOOR_ATOMIC;
use shekyl_chain_rules::{Candidate, CenRow, Locus, RuleSet, TxSlot};
use shekyl_chain_store::archival_snapshot::{ArchivalSnapshot, SnapshotFamily};
use shekyl_chain_store::store::{StoreCannot, StoreError};
use shekyl_types::{BlockCount, BlockHeight, ChainCount, SettlementEpoch, ShardId};
use shekyl_wire::transaction::{BondPostKind, Holdings as WireHoldings};
use shekyl_wire::{Ct, Transaction};

use crate::archival_driver::{first_spending_height, refused_at, ENDPOINT, FEE};
use crate::connector::{ArchivalState, CheckpointState, Inject, Injected, RunFault};
use crate::metrics::Metrics;
use crate::pipeline::{run, PipelineConfig, PipelineFault};
use crate::scenario::{Clocked, FreeHash, Mined, Scenario, RULES};
use crate::scenario_archival::{complete_tree, shard_set, Persona};
use crate::source::{IngestEvent, Injection, ServeCredit};
use crate::test_support::{cleanup, open_store, tmp, trace_of, trace_read, Scripted};
use shekyl_harness_spender::Spender;

/// The settlement epoch open at `height` under the genesis rule set — the
/// epoch a join at `height` records and a credit at `height` is keyed by.
fn epoch_at(height: BlockHeight) -> SettlementEpoch {
    RuleSet::GENESIS.settlement_schedule().epoch_at(height)
}

/// The refusals a view with no bonds produces, each through the production
/// stack: a post is assembled and signed as a wallet would (so CEN-H21 and
/// I18 pass and L7 is the row that fires), listed at the same height — a
/// refused block leaves the chain where it was — and refused at the post's
/// own input: the release at **CEN-J16**, the reinstate at **CEN-J18**,
/// the empty compact join at **CEN-J14** (all three *were* L7's until E6
/// slice 8 row 5), the unnamed kind at L7 in the sequence itself — the
/// same row and locus the fold refuses, whose arm stays the belt. The
/// join-and-release pair is
/// J16's too, not G10's (module docs). The serve credit is **CEN-J4**'s
/// (E6 slice 8 row 3): the one bond-state read the transaction pass makes,
/// ahead of the fold — *was* L7's until row 3 landed, the pin slice 8's
/// row 2 held. The funding half is **CEN-J27**'s (slice 6 row 6): the
/// honest join records it, and the same join with one byte of its funding
/// proof flipped is refused on it at the transaction — after the post rows,
/// which read nothing the flip changed, and before the signatures, whose
/// preimage covers the prunable region too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn posts_for_a_persona_with_no_record_are_refused_on_the_store() {
    let connecting = first_spending_height();
    let mut scenario = Scenario::open("scenario-archival-refusals");
    let mined = scenario
        .mine(ChainCount::from_next_height(connecting).to_raw())
        .await;
    let spender = Spender::over(&mined);
    let persona = Persona::at(3);
    let epoch = epoch_at(connecting);
    let at_post = Locus::Input {
        slot: TxSlot::Listed(0),
        input: 1,
    };
    // Every post spends block 0's coinbase at the same height — a refused
    // block leaves the chain where it was, so one funding serves them all.
    let riding = |bond| {
        spender.spend_coinbase_posting(
            scenario.wallet(),
            BlockHeight::ZERO,
            connecting,
            FEE,
            Some(&bond),
        )
    };

    // A release (through `build_release_vin`, `bond_spend_sk` signing the
    // slot, the debit a source the outputs grow by) with no record to
    // empty: J16's `RecordMissing`. J13's Release arm is gated on the
    // record, so with none it has nothing to pin the slot against.
    let release = riding(persona.release(ARCHIVAL_BOND_FLOOR_ATOMIC));
    // A reinstate with no record. No wallet producer exists for one, so the
    // post is a join's fields under the Reinstate tag.
    let mut reinstate = persona.join_post(shard_set(vec![7]), ENDPOINT);
    reinstate.kind = BondPostKind::Other(shekyl_archival_retention::BondPostKind::Reinstate as u8);
    let reinstate = riding(persona.post_by_hand(reinstate));
    // A kind no rule set names.
    let mut unknown = persona.join_post(shard_set(vec![7]), ENDPOINT);
    unknown.kind = BondPostKind::Other(9);
    let unknown = riding(persona.post_by_hand(unknown));
    // A compact join holding nothing: the wire carries an empty list,
    // J14's `ShardSetCompactEmpty` refuses it; the transition's refusal of
    // a record with no holdings is the belt beneath. (A repeated shard is
    // not listed here: the wire decoder refuses it before any rule reads
    // the block, so L7's duplicate arm is a belt behind the decoder — the
    // fixture's case, `archival_tests`, is its witness.)
    let mut empty = persona.join_post(shard_set(vec![7]), ENDPOINT);
    empty.holdings = WireHoldings::ShardSetCompact(Vec::new());
    let empty = riding(persona.post_by_hand(empty));
    // The positive control: a complete tree. A compact join names a shard
    // that must be closed, final and priced (CEN-J15); this scenario closes
    // none, and the shard shape is not its subject.
    let honest = riding(persona.join(complete_tree(), ENDPOINT));

    // A serve credit for a persona with no record: J4 at the credit's own
    // input, before the fold's L7 is reached.
    refused_at(
        scenario
            .mine_listing(vec![persona.serve_credit(7, epoch.to_raw() + 1)])
            .await,
        CenRow::J4,
        Locus::Input {
            slot: TxSlot::Listed(0),
            input: 0,
        },
    );
    refused_at(
        scenario.mine_listing(vec![release]).await,
        CenRow::J16,
        at_post,
    );
    refused_at(
        scenario.mine_listing(vec![reinstate]).await,
        CenRow::J18,
        at_post,
    );
    refused_at(
        scenario.mine_listing(vec![unknown]).await,
        CenRow::L7,
        at_post,
    );
    refused_at(
        scenario.mine_listing(vec![empty]).await,
        CenRow::J14,
        at_post,
    );

    // CEN-J27 on the pipeline: the honest join with one byte of its
    // funding-spend FCMP++ proof flipped. The prunable region is outside
    // the prefix, so the post rows (J13–J15, which read the post and the
    // view) admit the body as before; the funding half is the first row
    // that reads what changed, and it refuses at the transaction before
    // the signatures (I18, whose preimage also covers the prunable) are
    // asked. The block does not connect.
    let mut corrupt_funding_proof = honest.clone();
    if let Ct::Fcmp {
        prunable: Some(p), ..
    } = &mut corrupt_funding_proof.ct
    {
        p.fcmp_proof[0] ^= 0x01;
    }
    refused_at(
        scenario.mine_listing(vec![corrupt_funding_proof]).await,
        CenRow::J27,
        Locus::Tx {
            slot: TxSlot::Listed(0),
        },
    );

    // Positive control on the same chain: the honest join connects, so the
    // refusals above were the posts', not the height's or the funding's —
    // and its funding half is judged, not skipped: J27 is in the verdict.
    let block = scenario
        .mine_listing(vec![honest])
        .await
        .unwrap_or_else(|outcome| panic!("the honest join connects: {outcome}"));
    assert!(
        block.judged_by.contains(&CenRow::J27),
        "the funding half (CEN-J27) judged the honest join"
    );
    assert_eq!(block.archival.records().len(), 1);
    assert_eq!(block.archival.records()[0].persona(), &persona.id());

    scenario.close().await;
}

/// A join and a release for one persona in one block is **CEN-J16**'s
/// refusal at the release — the view the slot loop reads is the one before
/// the block, so the record the join would open is not there (module
/// docs: *was* pinned as CEN-G10's until E6 slice 8 row 5, on a sentence
/// true of neither implementation). It never reaches the transition, so
/// the release arm's positive witness needs a persisted record: commit
/// 5's. CEN-G10's own witness is the second block: two joins for one
/// persona, each passing the slot loop alone, the second refused after it
/// at its post.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_posts_for_one_persona_in_one_block_are_j16s_then_g10s() {
    // Two spends in one block, of coinbases 0 and 1: the block connects
    // where the later of the two is mature, one past coinbase 0's first
    // spending height.
    let connecting = first_spending_height() + BlockCount::ONE;
    let mut scenario = Scenario::open("scenario-archival-g10");
    let mined = scenario
        .mine(ChainCount::from_next_height(connecting).to_raw())
        .await;
    let spender = Spender::over(&mined);
    let persona = Persona::at(4);
    let second = Locus::Input {
        slot: TxSlot::Listed(1),
        input: 1,
    };
    // Complete trees throughout: the subject is the order of the rows over
    // two posts, not the holding — a compact join would need a closed,
    // final, priced shard (CEN-J15), and this scenario closes none.
    let join = persona.join(complete_tree(), ENDPOINT);
    let release = persona.release(ARCHIVAL_BOND_FLOOR_ATOMIC);
    let listed: Vec<Transaction> = vec![
        spender.spend_coinbase_posting(
            scenario.wallet(),
            BlockHeight::ZERO,
            connecting,
            FEE,
            Some(&join),
        ),
        spender.spend_coinbase_posting(
            scenario.wallet(),
            BlockHeight::from_raw(1),
            connecting,
            FEE,
            Some(&release),
        ),
    ];
    refused_at(scenario.mine_listing(listed).await, CenRow::J16, second);
    // The refused block wrote nothing, so both joins read no record and
    // J14 passes each; G10 counts the second.
    let again = persona.join(complete_tree(), ENDPOINT);
    let joins: Vec<Transaction> = vec![
        spender.spend_coinbase_posting(
            scenario.wallet(),
            BlockHeight::ZERO,
            connecting,
            FEE,
            Some(&join),
        ),
        spender.spend_coinbase_posting(
            scenario.wallet(),
            BlockHeight::from_raw(1),
            connecting,
            FEE,
            Some(&again),
        ),
    ];
    refused_at(scenario.mine_listing(joins).await, CenRow::G10, second);
    scenario.close().await;
}

/// A chain with one bonded persona and a few blocks past the join, as the
/// injector finds it: the blocks (for a replay) and the persona. The
/// persona holds a complete tree — shard 7 with every other; a compact
/// join would need a closed, final, priced shard (CEN-J15), this chain
/// closes none, and the injected credit is the subject, not the holding.
async fn bonded_chain(name: &str) -> (Scenario<FreeHash>, Vec<Mined>, Persona) {
    let connecting = first_spending_height();
    let mut scenario = Scenario::open(name);
    let mut mined = scenario
        .mine(ChainCount::from_next_height(connecting).to_raw())
        .await;
    let spender = Spender::over(&mined);
    let persona = Persona::at(1);
    let join = persona.join(complete_tree(), ENDPOINT);
    let joined = scenario
        .mine_listing(vec![spender.spend_coinbase_posting(
            scenario.wallet(),
            BlockHeight::ZERO,
            connecting,
            FEE,
            Some(&join),
        )])
        .await
        .unwrap_or_else(|outcome| panic!("the join connects: {outcome}"));
    mined.push(joined);
    mined.extend(scenario.mine(2).await);
    (scenario, mined, persona)
}

/// The regtest injector through the connector (DRS-E4 §3.8 item 3): the
/// bit lands in its own transaction at the **tip** — the receipt's height
/// is the connected tip, one below the producer's `connecting` count
/// (ARW-26's two quantities, told apart here by the type each read
/// returns) — and the archival snapshot afterwards differs from before by
/// exactly that one `archival_serve_credit` row. A persona with no bond
/// record is the store's refusal, and the writer stays up: the refusal is
/// a `Cannot`, not a halt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_injected_serve_credit_lands_at_the_tip_and_is_one_snapshot_row() {
    let (scenario, mined, persona) = bonded_chain("scenario-archival-inject").await;
    let tip = mined.last().expect("mined").height;
    let connector = scenario.connector();
    let before = connector
        .ask(ArchivalState)
        .await
        .expect("the snapshot reads");

    let credit = ServeCredit {
        persona: persona.id(),
        shard: ShardId::from_raw(7),
        epoch: epoch_at(tip),
    };
    let Injected { at } = connector
        .ask(Inject(credit))
        .await
        .expect("a bonded persona's credit is injected");
    assert_eq!(at, tip, "attributed to the connected tip");
    let facts = scenario.facts().await.expect("facts");
    assert_eq!(
        at.checked_add(BlockCount::ONE),
        Some(facts.connecting),
        "the receipt is the tip; the producer's `connecting` is the count, one above (ARW-26)"
    );

    let after = connector
        .ask(ArchivalState)
        .await
        .expect("the snapshot reads");
    let mut expected_row = ArchivalSnapshot::empty();
    expected_row
        .push_serve_credit(&credit.persona, credit.shard, credit.epoch, at)
        .expect("one row");
    let diff = after.diff(&before);
    let only_new: Vec<_> = diff.diverged().collect();
    assert_eq!(only_new.len(), 1, "one family moved: {diff:?}");
    assert_eq!(only_new[0].family, SnapshotFamily::ServeCredit);
    assert_eq!(
        only_new[0].only_ours,
        expected_row
            .rows(SnapshotFamily::ServeCredit)
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        "the one new row is the credit keyed at the attributed height"
    );
    assert!(only_new[0].unequal.is_empty() && only_new[0].only_theirs.is_empty());

    // A stranger: refused by the store before the write, as a `Cannot`.
    let stranger = ServeCredit {
        persona: Persona::at(9).id(),
        ..credit
    };
    let refused = connector
        .ask(Inject(stranger))
        .await
        .expect_err("no record, no bit");
    assert!(
        matches!(
            refused,
            SendError::HandlerError(RunFault::Store(StoreError::Cannot(
                StoreCannot::InjectionForUnbondedPersona { persona }
            ))) if persona == stranger.persona
        ),
        "{refused:?}"
    );
    // Not a halt: the connector still answers, and the chain still extends.
    let again = connector
        .ask(ArchivalState)
        .await
        .expect("the writer is up");
    assert_eq!(again, after);
    scenario.close().await;
}

/// The same chain through the pipeline, as a replay meets it in a
/// captured corpus: the `Inject` is a barrier applied at the committed tip
/// and reported as the receipt the injector would have written; a later
/// `Rewind` to the injection's height is allowed and one below it is
/// [`PipelineFault::RewindBelowInjection`] — the bit is not block-owned,
/// so the pop would strand it (§3.8 item 3's "a `Rewind` below an
/// `Inject`'s height is a defect").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replayed_inject_is_reported_as_its_receipt_and_a_rewind_below_it_is_refused() {
    let (scenario, mined, persona) = bonded_chain("scenario-archival-inject-replay").await;
    scenario.close().await;
    let chain: Vec<(shekyl_wire::Block, Vec<Transaction>)> = mined
        .iter()
        .map(|m| (m.template.block.clone(), m.template.transactions.clone()))
        .collect();
    let extend = |m: &Mined| {
        IngestEvent::Extend(Box::new(Candidate::new(
            m.template.block.clone(),
            m.template.transactions.clone(),
        )))
    };
    let inject_after = mined.len() - 2;
    let injected_at = mined[inject_after].height;
    let credit = ServeCredit {
        persona: persona.id(),
        shard: ShardId::from_raw(7),
        epoch: epoch_at(injected_at),
    };
    // The driver's clock, advanced past every block the scenario mined.
    let clock = || {
        let clock = Clocked::new(FreeHash);
        for _ in &mined {
            clock.tick();
        }
        Arc::new(clock)
    };
    let trace = Arc::new(trace_of(&chain, false));

    // Inject, then two more blocks: the receipt is the tip at the barrier.
    let path = tmp("pipeline-inject-report");
    let mut events: Vec<IngestEvent> = mined[..=inject_after].iter().map(extend).collect();
    events.push(IngestEvent::Inject(credit));
    events.extend(mined[inject_after + 1..].iter().map(extend));
    let mut source = Scripted::new(events);
    let report = run(
        &mut source,
        clock(),
        Arc::new(Metrics::new()),
        RULES,
        open_store(&path),
        Arc::clone(&trace),
        PipelineConfig::default(),
    )
    .await
    .expect("the injected chain replays");
    assert_eq!(report.connected.len(), mined.len());
    assert_eq!(
        report.injected,
        vec![Injection {
            at: injected_at,
            credit
        }],
        "one injection, reported as its receipt"
    );
    let reopened = open_store(&path);
    let snapshot = reopened
        .begin_read()
        .expect("read")
        .archival_snapshot()
        .expect("snapshot");
    let mut expected_row = ArchivalSnapshot::empty();
    expected_row
        .push_serve_credit(&credit.persona, credit.shard, credit.epoch, injected_at)
        .expect("one row");
    assert_eq!(
        snapshot.rows(SnapshotFamily::ServeCredit),
        expected_row.rows(SnapshotFamily::ServeCredit)
    );
    drop(reopened);
    cleanup(&path);

    // A rewind to the injection's height keeps the bit; one below strands
    // it and is refused before the connector is asked.
    let path = tmp("pipeline-inject-rewind");
    let mut events: Vec<IngestEvent> = mined[..=inject_after].iter().map(extend).collect();
    events.push(IngestEvent::Inject(credit));
    events.extend(mined[inject_after + 1..].iter().map(extend));
    events.push(IngestEvent::Rewind { to: injected_at });
    let below = BlockHeight::from_raw(injected_at.to_raw() - 1);
    events.push(IngestEvent::Rewind { to: below });
    let mut source = Scripted::new(events);
    let fault = run(
        &mut source,
        clock(),
        Arc::new(Metrics::new()),
        RULES,
        open_store(&path),
        trace,
        PipelineConfig::default(),
    )
    .await
    .expect_err("a rewind below the injection is a pipeline fault");
    assert!(
        matches!(
            fault,
            PipelineFault::RewindBelowInjection {
                to,
                injected_at: reported,
                credit: stranded,
            } if to == below && reported == injected_at && stranded == credit
        ),
        "{fault:?}"
    );
    cleanup(&path);
}

/// An `Inject` filed at the **covered tip** — where a capture files it: the
/// injector writes at the daemon's tip and the walker reads after, so the
/// corpus's last event is the credit and the trace's `0x04` record carries
/// it. The checkpoint is compared after that barrier commits
/// (`Drive::compare_checkpoint`), not when the tip connected; compared at
/// the connect, the redb side had not yet written the row and a faithful
/// replay read as divergent (PR #937 review, finding 1). The reference is
/// the scenario's own store after the injection, read once through
/// [`CheckpointState`] as the walker reads LMDB. The control — the same
/// chain without the injection, against the same trace — diverges in
/// exactly `ServeCredit`, so the comparison that passes is one that sees
/// the row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_inject_at_the_covered_tip_commits_before_the_checkpoint_is_compared() {
    let (scenario, mined, persona) = bonded_chain("scenario-archival-inject-at-tip").await;
    let tip = mined.last().expect("mined").height;
    let credit = ServeCredit {
        persona: persona.id(),
        shard: ShardId::from_raw(7),
        epoch: epoch_at(tip),
    };
    let connector = scenario.connector();
    let Injected { at } = connector
        .ask(Inject(credit))
        .await
        .expect("a bonded persona's credit is injected");
    assert_eq!(at, tip, "attributed to the covered tip");
    let reference = connector
        .ask(CheckpointState)
        .await
        .expect("one read of both encodings");
    assert_eq!(reference.tip, Some(tip));
    scenario.close().await;

    let chain: Vec<(shekyl_wire::Block, Vec<Transaction>)> = mined
        .iter()
        .map(|m| (m.template.block.clone(), m.template.transactions.clone()))
        .collect();
    let trace = Arc::new(trace_read(&chain, reference.digest, &reference.archival));
    let extend = |m: &Mined| {
        IngestEvent::Extend(Box::new(Candidate::new(
            m.template.block.clone(),
            m.template.transactions.clone(),
        )))
    };
    let clock = || {
        let clock = Clocked::new(FreeHash);
        for _ in &mined {
            clock.tick();
        }
        Arc::new(clock)
    };

    // As captured: every block, then the credit at the tip, last.
    let path = tmp("pipeline-inject-at-tip");
    let mut events: Vec<IngestEvent> = mined.iter().map(extend).collect();
    events.push(IngestEvent::Inject(credit));
    let mut source = Scripted::new(events);
    let report = run(
        &mut source,
        clock(),
        Arc::new(Metrics::new()),
        RULES,
        open_store(&path),
        Arc::clone(&trace),
        PipelineConfig::default(),
    )
    .await
    .expect("the injected chain replays");
    assert_eq!(report.injected, vec![Injection { at: tip, credit }]);
    let checkpoint = report
        .checkpoint
        .expect("the committed tip is the covered tip: compared");
    assert_eq!(checkpoint.at, tip);
    assert!(checkpoint.identical(), "the digests agree");
    let archival = report.archival.expect("compared with the digest");
    assert_eq!(archival.at, tip);
    assert!(
        archival.identical(),
        "the credit committed before the rows were read: {:?}",
        archival.diff.diverged().collect::<Vec<_>>()
    );
    cleanup(&path);

    // The control: no injection, the same trace. The digest still agrees
    // (it carries no archival state, ARW-25); the rows differ by the one
    // credit the trace holds and this replay never wrote.
    let path = tmp("pipeline-inject-at-tip-control");
    let mut source = Scripted::new(mined.iter().map(extend).collect());
    let report = run(
        &mut source,
        clock(),
        Arc::new(Metrics::new()),
        RULES,
        open_store(&path),
        trace,
        PipelineConfig::default(),
    )
    .await
    .expect("the uninjected chain replays");
    assert!(report.injected.is_empty());
    assert!(report.checkpoint.expect("compared").identical());
    let archival = report.archival.expect("compared");
    let diverged: Vec<_> = archival.diff.diverged().collect();
    assert_eq!(diverged.len(), 1, "one family moved: {diverged:?}");
    assert_eq!(diverged[0].family, SnapshotFamily::ServeCredit);
    assert!(diverged[0].only_ours.is_empty() && diverged[0].unequal.is_empty());
    assert_eq!(
        diverged[0].only_theirs.len(),
        1,
        "the trace's one credit row, which this replay did not write"
    );
    cleanup(&path);
}
