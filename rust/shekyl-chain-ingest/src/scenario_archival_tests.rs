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
//! record it inserts), a serve credit for a persona whose join is in the
//! same block, the refusals of a post for a persona with no record.
//! **Multi-block arms** read a record a previous block wrote — a release,
//! a reinstate, a second join, a credit for a persona who joined earlier.
//! Commit 4 witnessed the first kind and pinned the second as unreachable
//! (nothing wrote a record); commit 5's writer turned that pin, and
//! [`a_join_is_written_and_the_blocks_after_it_read_the_record`] is the
//! same test with the two assertions inverted: the record is `Some` after
//! the join, and the next block's credit for it connects. The multi-block
//! arms follow on the same chain: a release of the persisted record (its
//! post-image read back), a second join for a bonded persona refused, and
//! a reinstate against a record whose only interval is a clean close
//! refused — the reinstate arm's *positive* witness needs an open interval,
//! which only a slash writes, and no fixture chain here reaches the slash
//! scan (a slash needs `M` epochs of settled misses and one epoch of
//! grace; `shekyl-chain-store`'s `slash_writes_land_at_the_m_epoch_deadline`
//! is that path's witness).
//!
//! One arm the plan listed as single-block is not. A join and a release
//! for one persona in one block do not reach L7: **CEN-G10**
//! (`bond_post_block_unique`, ratified 2026-07-12) refuses a second bond
//! post for a `P` in a block, whatever its kind, and G10 runs before the
//! transition. So "join + release in one block" is G10's refusal, pinned
//! below as such, and the release arm's positive witness is a release of a
//! *persisted* record.
//!
//! # What the store says
//!
//! The accrual assertion is derived, not computed here: the verdict's
//! `Accrual` is the epoch's row as the store held it before the block plus
//! the block's own archival leg (`PaidEmission::accrual`), and the row the
//! store holds after the block is that sum. Both reads go through the
//! connector (`BudgetAccruingOf`, `BondRecordOf`), the same store the
//! validator's view reads.
//!
//! # What is fixture here
//!
//! The serve credit's Ed25519 countersignature (no Rust countersigner
//! exists; CEN-J1/J4/J10 pending), and the FCMP proof's consensus-side
//! verification (CEN-I15 pending; the driver self-verifies it against the
//! wallet-side root). Neither is what L7 judges. Everything L7 reads — the
//! post's fields, the persona's standing, the block's own posts — is the
//! production object over the production view.

use shekyl_archival_retention::ARCHIVAL_BOND_FLOOR_ATOMIC;
use shekyl_chain_rules::{Accrual, CenRow, Locus, RecordWriteKind, RuleSet, TxSlot};
use shekyl_types::archival::{BadInterval, Holdings};
use shekyl_types::{BlockHeight, SettlementEpoch, ShardId};
use shekyl_units::AtomicUnits;
use shekyl_wire::transaction::{BondPostKind, Holdings as WireHoldings};
use shekyl_wire::{Input, Transaction};

use crate::scenario::{Scenario, StepOutcome};
use crate::scenario_archival::{complete_tree, shard_set, Persona};
use crate::scenario_spend::Spender;

/// The first height that can spend block 0's coinbase against a root that
/// holds it (`scenario_tests`: unlock window + spendable age + 1).
fn first_spending_height() -> u64 {
    RuleSet::GENESIS.mined_money_unlock_window().to_raw()
        + RuleSet::GENESIS.tx_spendable_age().to_raw()
        + 1
}

/// The settlement epoch open at `height` under the genesis rule set — the
/// epoch a join at `height` records and a credit at `height` is keyed by.
fn epoch_at(height: u64) -> SettlementEpoch {
    SettlementEpoch::from_raw(
        RuleSet::GENESIS
            .settlement_schedule()
            .epoch_at_height(height),
    )
}

const FEE: u64 = 1_000_000;
const ENDPOINT: [u8; 32] = [0xEE; 32];

fn refused_at(outcome: Result<crate::scenario::Mined, StepOutcome>, row: CenRow, locus: Locus) {
    match outcome {
        Err(StepOutcome::Refused(refused)) => {
            assert_eq!(refused.rule, row, "the row that refused: {refused}");
            assert_eq!(refused.locus, locus, "where it refused: {refused}");
        }
        Ok(block) => panic!("admitted at {}, expected {row}'s refusal", block.height),
        Err(other) => panic!("expected {row}'s refusal, got {other}"),
    }
}

/// A JoinMarket through `build_join_market_vin`, signed by the persona,
/// riding a real spend: the verdict's transition is that persona's
/// `Insert`, field for field from the post and the open epoch; a serve
/// credit in the same block is keyed to the post; the accrual is the open
/// epoch's row plus the block's leg. Then the store: the record is there,
/// the accrual row is the post-image, and the blocks after read them — a
/// credit for the persona connects, a release empties the other record
/// and its post-image is what the store holds, a second join and a
/// reinstate over a clean close are L7's refusals at their input.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_join_is_written_and_the_blocks_after_it_read_the_record() {
    let connecting = first_spending_height();
    let mut scenario = Scenario::open("scenario-archival-join");
    let mined = scenario.mine(connecting).await;
    let mut spender = Spender::over(&mined);

    let compact = Persona::at(1);
    let whole = Persona::at(2);
    let join_compact = compact.join(shard_set(vec![7, 42]), ENDPOINT);
    let join_whole = whole.join(complete_tree(), ENDPOINT);
    let listed = vec![
        spender.spend_coinbase_posting(scenario.wallet(), 0, connecting, FEE, Some(&join_compact)),
        spender.spend_coinbase_posting(scenario.wallet(), 1, connecting, FEE, Some(&join_whole)),
        compact.serve_credit(7, epoch_at(connecting).to_raw()),
    ];
    let epoch = epoch_at(connecting);
    // The epoch's row before this block: what the blocks before it accrued.
    let accrued_before = scenario
        .budget_accruing(epoch)
        .await
        .expect("read")
        .unwrap_or(AtomicUnits::ZERO);
    let block = scenario
        .mine_listing(listed)
        .await
        .unwrap_or_else(|outcome| panic!("two joins and a credit connect: {outcome}"));
    assert_eq!(block.height, BlockHeight::from_raw(connecting));
    for row in [
        CenRow::H21,
        CenRow::H20,
        CenRow::I18,
        CenRow::G10,
        CenRow::L7,
    ] {
        assert!(block.judged_by.contains(&row), "{row} judged the block");
    }

    // The transition: two inserts, in post order.
    let records = block.archival.records();
    assert_eq!(records.len(), 2, "one write per join");
    let Input::BondPost(posted) = &join_compact.input else {
        unreachable!()
    };
    assert_eq!(records[0].persona(), &compact.id());
    assert_eq!(records[0].kind(), RecordWriteKind::Insert);
    let record = records[0].record();
    assert_eq!(record.hybrid_pubkey, compact.identity());
    assert_eq!(record.bond_spend_pk, compact.bond_spend());
    assert_eq!(record.endpoint, ENDPOINT);
    assert_eq!(record.join_settlement_epoch, epoch);
    assert_eq!(
        record.bonded_total.to_raw(),
        2 * ARCHIVAL_BOND_FLOOR_ATOMIC,
        "the constructor priced two shards at the floor"
    );
    assert_eq!(record.bonded_total.to_raw(), posted.bonded_total_atomic);
    let Holdings::ShardSet(held) = &record.holdings else {
        panic!("a compact join holds a shard set");
    };
    let held: Vec<(u64, SettlementEpoch)> = held
        .as_slice()
        .iter()
        .map(|h| (h.shard.to_raw(), h.add_epoch))
        .collect();
    assert_eq!(held, vec![(7, epoch), (42, epoch)]);
    assert!(record.bad_intervals.is_empty());
    assert!(record.claimed_settlement_epochs.is_empty());
    assert_eq!(record.first_paying_emission_height, None);

    assert_eq!(records[1].persona(), &whole.id());
    assert_eq!(records[1].kind(), RecordWriteKind::Insert);
    assert_eq!(records[1].record().holdings, Holdings::CompleteTree);
    assert_eq!(
        records[1].record().bonded_total.to_raw(),
        ARCHIVAL_BOND_FLOOR_ATOMIC,
        "a complete tree is one holding at the floor"
    );

    // The credit, keyed to the same-block post.
    let credits = block.archival.serve_credits();
    assert_eq!(credits.len(), 1);
    assert_eq!(credits[0].persona, compact.id());
    assert_eq!(credits[0].shard, ShardId::from_raw(7));
    assert_eq!(credits[0].epoch, epoch);

    // The accrual is the open epoch's post-image: the row the store held
    // before this block plus the block's archival emission leg (the
    // verdict's own `PaidEmission::accrual`, not a number this test
    // computed). This block, well inside the first epoch, slashes and
    // closes nothing.
    let accrued = accrued_before
        .checked_add(block.emission.accrual)
        .expect("a fixture chain's accrual fits");
    assert_eq!(
        block.archival.accrual(),
        Accrual {
            epoch,
            total: accrued,
        }
    );
    assert!(block.archival.slashes().is_empty());
    assert!(block.archival.close().is_none());
    assert_eq!(block.archival.slash_watermark(), None);

    // The store holds what the verdict derived: both records, field for
    // field, and the accrual post-image (SI-19, SI-23).
    assert_eq!(
        scenario.bond_record(compact.id()).await.expect("read"),
        Some(record.clone()),
        "the join's insert is the store's row"
    );
    assert_eq!(
        scenario.bond_record(whole.id()).await.expect("read"),
        Some(records[1].record().clone()),
    );
    assert_eq!(
        scenario.budget_accruing(epoch).await.expect("read"),
        Some(accrued),
        "the epoch's accruing row is the verdict's post-image"
    );
    let whole_record = records[1].record().clone();
    spender.push(&block);

    // The next block reads the records: the credit for a persona who
    // joined earlier connects (SI-15's row keyed to it), and a release of
    // the other persisted record is its `Update` — bonded to zero, holding
    // nothing, one clean interval close at the open epoch.
    let next = connecting + 1;
    let release_whole = whole.release(whole_record.bonded_total.to_raw());
    let block = scenario
        .mine_listing(vec![
            compact.serve_credit(42, epoch.to_raw()),
            spender.spend_coinbase_posting(scenario.wallet(), 2, next, FEE, Some(&release_whole)),
        ])
        .await
        .unwrap_or_else(|outcome| panic!("a credit and a release connect: {outcome}"));
    assert_eq!(block.height, BlockHeight::from_raw(next));
    let credits = block.archival.serve_credits();
    assert_eq!(credits.len(), 1);
    assert_eq!(credits[0].persona, compact.id());
    assert_eq!(credits[0].shard, ShardId::from_raw(42));
    assert_eq!(credits[0].epoch, epoch);
    let records = block.archival.records();
    assert_eq!(records.len(), 1, "the release is the block's one write");
    assert_eq!(records[0].persona(), &whole.id());
    assert_eq!(records[0].kind(), RecordWriteKind::Update);
    let released = records[0].record();
    assert_eq!(released.bonded_total, AtomicUnits::ZERO);
    assert_eq!(
        released.holdings,
        Holdings::shard_set(Vec::new()).expect("empty"),
        "a release empties the holdings"
    );
    assert_eq!(
        released.bad_intervals,
        vec![BadInterval {
            start_epoch: epoch.to_raw(),
            end_exclusive: epoch.to_raw(),
        }],
        "one clean interval close at the release epoch"
    );
    assert_eq!(released.hybrid_pubkey, whole_record.hybrid_pubkey);
    assert_eq!(
        released.join_settlement_epoch,
        whole_record.join_settlement_epoch
    );
    assert_eq!(
        block.archival.accrual().total,
        accrued.checked_add(block.emission.accrual).expect("fits"),
        "the accrual keeps folding over the written row"
    );
    assert_eq!(
        scenario.bond_record(whole.id()).await.expect("read"),
        Some(released.clone()),
        "the release's post-image is the store's row (SI-20 journals the pre-image)"
    );
    assert_eq!(
        scenario.bond_record(compact.id()).await.expect("read"),
        Some(record.clone()),
        "a credit does not touch the record"
    );
    spender.push(&block);

    // Refusals that read a persisted record: a second join for a bonded
    // persona (SI-19's insert-once, judged at L7 first), and a reinstate
    // of the released record — it holds nothing and its only interval is
    // a clean close, so the fold has nothing to reinstate. Each is refused
    // at the post's own input; the chain stays where it was.
    let after = next + 1;
    let at_post = Locus::Input {
        slot: TxSlot::Listed(0),
        input: 1,
    };
    let rejoin = compact.join(shard_set(vec![9]), ENDPOINT);
    refused_at(
        scenario
            .mine_listing(vec![spender.spend_coinbase_posting(
                scenario.wallet(),
                3,
                after,
                FEE,
                Some(&rejoin),
            )])
            .await,
        CenRow::L7,
        at_post,
    );
    let mut reinstate = whole.join_post(complete_tree(), ENDPOINT);
    reinstate.kind = BondPostKind::Other(shekyl_archival_retention::BondPostKind::Reinstate as u8);
    let reinstate = whole.post_by_hand(reinstate);
    refused_at(
        scenario
            .mine_listing(vec![spender.spend_coinbase_posting(
                scenario.wallet(),
                3,
                after,
                FEE,
                Some(&reinstate),
            )])
            .await,
        CenRow::L7,
        at_post,
    );
    assert_eq!(
        scenario.bond_record(whole.id()).await.expect("read"),
        Some(released.clone()),
        "a refused block writes nothing"
    );

    scenario.close().await;
}

/// The refusals a view with no bonds produces, each through the production
/// stack: a post is assembled and signed as a wallet would (so CEN-H21 and
/// I18 pass and L7 is the row that fires), listed at the same height — a
/// refused block leaves the chain where it was — and refused at the post's
/// own input. The last case is G10's, not L7's (module docs).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn posts_for_a_persona_with_no_record_are_refused_at_l7_on_the_store() {
    let connecting = first_spending_height();
    let mut scenario = Scenario::open("scenario-archival-refusals");
    let mined = scenario.mine(connecting).await;
    let spender = Spender::over(&mined);
    let persona = Persona::at(3);
    let epoch = epoch_at(connecting);
    let at_post = Locus::Input {
        slot: TxSlot::Listed(0),
        input: 1,
    };
    // Every post spends block 0's coinbase at the same height — a refused
    // block leaves the chain where it was, so one funding serves them all.
    let riding =
        |bond| spender.spend_coinbase_posting(scenario.wallet(), 0, connecting, FEE, Some(&bond));

    // A release (through `build_release_vin`, `bond_spend_sk` signing the
    // slot, the debit a source the outputs grow by) with no record to empty.
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
    // A compact join holding nothing: the wire carries an empty list, the
    // transition refuses a record with no holdings. (A repeated shard is
    // not listed here: the wire decoder refuses it before any rule reads
    // the block, so L7's duplicate arm is a belt behind the decoder — the
    // fixture's case, `archival_tests`, is its witness.)
    let mut empty = persona.join_post(shard_set(vec![7]), ENDPOINT);
    empty.holdings = WireHoldings::ShardSetCompact(Vec::new());
    let empty = riding(persona.post_by_hand(empty));
    // The positive control.
    let honest = riding(persona.join(shard_set(vec![7]), ENDPOINT));

    // A serve credit for a persona with no record: the credit's own input.
    refused_at(
        scenario
            .mine_listing(vec![persona.serve_credit(7, epoch.to_raw())])
            .await,
        CenRow::L7,
        Locus::Input {
            slot: TxSlot::Listed(0),
            input: 0,
        },
    );
    refused_at(
        scenario.mine_listing(vec![release]).await,
        CenRow::L7,
        at_post,
    );
    refused_at(
        scenario.mine_listing(vec![reinstate]).await,
        CenRow::L7,
        at_post,
    );
    refused_at(
        scenario.mine_listing(vec![unknown]).await,
        CenRow::L7,
        at_post,
    );
    refused_at(
        scenario.mine_listing(vec![empty]).await,
        CenRow::L7,
        at_post,
    );

    // Positive control on the same chain: the honest join connects, so the
    // refusals above were the posts', not the height's or the funding's.
    let block = scenario
        .mine_listing(vec![honest])
        .await
        .unwrap_or_else(|outcome| panic!("the honest join connects: {outcome}"));
    assert_eq!(block.archival.records().len(), 1);
    assert_eq!(block.archival.records()[0].persona(), &persona.id());

    scenario.close().await;
}

/// A join and a release for one persona in one block is CEN-G10's refusal
/// (one bond post per `P` per block), at the second post — it never reaches
/// the transition. The release arm's positive witness therefore needs a
/// persisted record: commit 5's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_join_and_a_release_in_one_block_is_g10s_refusal_not_l7s() {
    let connecting = first_spending_height();
    let mut scenario = Scenario::open("scenario-archival-g10");
    let mined = scenario.mine(connecting).await;
    let spender = Spender::over(&mined);
    let persona = Persona::at(4);
    let join = persona.join(shard_set(vec![7]), ENDPOINT);
    let release = persona.release(ARCHIVAL_BOND_FLOOR_ATOMIC);
    let listed: Vec<Transaction> = vec![
        spender.spend_coinbase_posting(scenario.wallet(), 0, connecting, FEE, Some(&join)),
        spender.spend_coinbase_posting(scenario.wallet(), 1, connecting, FEE, Some(&release)),
    ];
    refused_at(
        scenario.mine_listing(listed).await,
        CenRow::G10,
        Locus::Input {
            slot: TxSlot::Listed(1),
            input: 1,
        },
    );
    scenario.close().await;
}
