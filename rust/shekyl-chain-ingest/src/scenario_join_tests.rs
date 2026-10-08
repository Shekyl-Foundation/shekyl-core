// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The compact join through the production stack, and the blocks that
//! read the record it wrote (E6 slice 8 PR-b). Split out of
//! `scenario_archival_tests` so that file stays the single-block arms:
//! this scenario fills two shards, joins, and then walks the credit,
//! release, rejoin and reinstate that a persisted record makes reachable.
//! Minutes of proofs; the live lane (`cargo test -p shekyl-chain-ingest
//! --features pipeline -- --ignored a_join_is_written`). The suite's
//! account of which arms live here is the module docs of
//! `scenario_archival_tests`.

use shekyl_archival_retention::ARCHIVAL_BOND_FLOOR_ATOMIC;
use shekyl_chain_rules::{Accrual, CenRow, Locus, RecordWriteKind, TxSlot};
use shekyl_types::archival::{BadInterval, Holdings};
use shekyl_types::{BlockCount, BlockHeight, SettlementEpoch, ShardId};
use shekyl_units::AtomicUnits;
use shekyl_wire::transaction::BondPostKind;
use shekyl_wire::Input;

use crate::archival_driver::{first_spending_height, refused_at, ENDPOINT, FEE};
use crate::scenario::{FreeHash, Scenario};
use crate::scenario_archival::{complete_tree, shard_set, Persona};
use crate::scenario_shard::{
    close_shards, first_admissible_compact_join, inside_one_epoch, levered_rules, levered_schedule,
    mine_to,
};
use shekyl_harness_spender::Spender;

/// The settlement epoch open at `height` under the levered schedule the
/// join mines.
fn levered_epoch_at(height: BlockHeight) -> SettlementEpoch {
    levered_schedule().epoch_at(height)
}

/// The first coinbase the join test's fill spends; the posts ride 0–3.
const FILL_FROM_COINBASE: u64 = 10;

/// A JoinMarket through `build_join_market_vin`, signed by the persona,
/// riding a real spend: the verdict's transition is that persona's
/// `Insert`, field for field from the post and the open epoch; the accrual
/// is the open epoch's row plus the block's leg. Then the store: the
/// record is there, the accrual row is the post-image, and the blocks
/// after read them — a credit for the persona, for the first epoch it may
/// serve (`E_join + 1`, CEN-J5), connects, a release whose debit is not
/// the persisted total is CEN-J16's before any connect, a release of that
/// total empties the record and its post-image is what the store holds, a
/// second join is CEN-J14's refusal and a reinstate over a clean close is
/// CEN-J18's, at their input (all three *were* L7's until slice 8 row 5).
/// The compact persona's two-shard join is the corpus's one two-floor
/// positive for J14, and the same post with one floor behind it is the
/// negative the fixtures cannot shape. The two shards are 0 and 1, filled
/// and closed before the join, which lands at the first height CEN-J15
/// admits it (module docs).
///
/// *Records-was:* until E6 slice 8 row 3 this block also listed a credit
/// **beside** the join, for the join's own epoch, and it connected: the
/// fold sequenced the post before the credit within the block. CEN-J4
/// reads the record off the view before the block and CEN-J5 refuses the
/// join epoch, as the C++'s `check_tx_inputs` does; the credit now lists
/// in the block after, for the epoch after.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "fills two shards with real proofs; minutes. Run in the live lane: cargo test -p shekyl-chain-ingest --features pipeline -- --ignored a_join_is_written"]
async fn a_join_is_written_and_the_blocks_after_it_read_the_record() {
    let rules = levered_rules();
    let mut scenario = Scenario::open_under("scenario-archival-join", FreeHash, rules);
    let mut mined = scenario.mine(first_spending_height().to_raw()).await;
    let filled = close_shards(&mut scenario, &mut mined, FILL_FROM_COINBASE, 2).await;
    let shards: Vec<u64> = filled.closed.iter().map(|c| c.shard.to_raw()).collect();
    assert_eq!(shards, vec![0, 1]);
    // The join connects at the first height J15 admits both shards; the
    // block after it (the credit and the release) stays in the join's
    // epoch, and neither block is an epoch close — the rows read here are
    // the posts', not a close's.
    let connecting = inside_one_epoch(
        filled
            .closed
            .iter()
            .map(|&close| first_admissible_compact_join(&rules, close))
            .max()
            .expect("two shards closed"),
        2,
    );
    mine_to(&mut scenario, &mut mined, connecting).await;
    let mut spender = Spender::over(&mined);

    let compact = Persona::at(1);
    let whole = Persona::at(2);
    let join_compact = compact.join(shard_set(shards.clone()), ENDPOINT);
    let join_whole = whole.join(complete_tree(), ENDPOINT);
    let listed = vec![
        spender.spend_coinbase_posting(
            scenario.wallet(),
            BlockHeight::ZERO,
            connecting,
            FEE,
            Some(&join_compact),
        ),
        spender.spend_coinbase_posting(
            scenario.wallet(),
            BlockHeight::from_raw(1),
            connecting,
            FEE,
            Some(&join_whole),
        ),
    ];
    let epoch = levered_epoch_at(connecting);
    // The first epoch a persona joining in `epoch` may serve (CEN-J5).
    let serving = SettlementEpoch::from_raw(epoch.to_raw() + 1);
    // The epoch's row before this block: what the blocks before it accrued.
    let accrued_before = scenario
        .budget_accruing(epoch)
        .await
        .expect("read")
        .unwrap_or(AtomicUnits::ZERO);
    let block = scenario
        .mine_listing(listed)
        .await
        .unwrap_or_else(|outcome| panic!("two joins connect: {outcome}"));
    assert_eq!(block.height, connecting);
    for row in [
        CenRow::H21,
        CenRow::I18,
        CenRow::G10,
        CenRow::J4,
        CenRow::J13,
        CenRow::J14,
        CenRow::J15,
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
    assert_eq!(held, vec![(0, epoch), (1, epoch)]);
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

    assert!(
        block.archival.serve_credits().is_empty(),
        "no credit can list beside the join it needs (J4 reads the view before the block)"
    );

    // The accrual is the open epoch's post-image: the row the store held
    // before this block plus the block's archival emission leg (the
    // verdict's own `PaidEmission::accrual`, not a number this test
    // computed). This block is not an epoch close, and no record
    // preceded it for a slash to read.
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
    // joined earlier — for the first epoch it may serve — connects through
    // J4, J5 and J6 over the persisted record (SI-15's row keyed to it),
    // and a release of the other persisted record is its `Update` — bonded
    // to zero, holding nothing, one clean interval close at the open epoch.
    let next = connecting + BlockCount::ONE;
    // A debit that is not the persisted total is CEN-J16's
    // (`DebitNotFullBalance`) at the post input — J13 passes it first,
    // the slot being `bond_spend_pk`'s; the fold's `DebitNotRecordTotal`
    // is the belt beneath. The block does not connect, so the valid
    // release below still lands at `next` on the same coinbase.
    let wrong_debit = whole.release(whole_record.bonded_total.to_raw() + 1);
    refused_at(
        scenario
            .mine_listing(vec![spender.spend_coinbase_posting(
                scenario.wallet(),
                BlockHeight::from_raw(2),
                next,
                FEE,
                Some(&wrong_debit),
            )])
            .await,
        CenRow::J16,
        Locus::Input {
            slot: TxSlot::Listed(0),
            input: 1,
        },
    );
    let release_whole = whole.release(whole_record.bonded_total.to_raw());
    let block = scenario
        .mine_listing(vec![
            compact.serve_credit(0, serving.to_raw()),
            spender.spend_coinbase_posting(
                scenario.wallet(),
                BlockHeight::from_raw(2),
                next,
                FEE,
                Some(&release_whole),
            ),
        ])
        .await
        .unwrap_or_else(|outcome| panic!("a credit and a release connect: {outcome}"));
    assert_eq!(block.height, next);
    for row in [CenRow::H20, CenRow::J4, CenRow::J5, CenRow::J6] {
        assert!(block.judged_by.contains(&row), "{row} judged the credit");
    }
    // The release passed J13 (the bond-spend slot) and J16 over the
    // persisted record: `whole` never served, so the cooldown and the
    // slash watermark have nothing to wait on.
    for row in [CenRow::J13, CenRow::J16] {
        assert!(block.judged_by.contains(&row), "{row} judged the release");
    }
    let credits = block.archival.serve_credits();
    assert_eq!(credits.len(), 1);
    assert_eq!(credits[0].persona, compact.id());
    assert_eq!(credits[0].shard, ShardId::from_raw(0));
    assert_eq!(credits[0].epoch, serving);
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
        "the release's post-image is the store's row (the replace journals the pre-image)"
    );
    assert_eq!(
        scenario.bond_record(compact.id()).await.expect("read"),
        Some(record.clone()),
        "a credit does not touch the record"
    );
    spender.push(&block);

    // Refusals that read a persisted record: a second join for a bonded
    // persona (CEN-J14's `RecordExists`; SI-19's insert-once is the fold's
    // belt beneath it), and a reinstate of the released record — it holds
    // nothing and its only interval is a clean close, so CEN-J18 has
    // nothing to reinstate. Each is refused at the post's own input; the
    // chain stays where it was.
    let after = next + BlockCount::ONE;
    let at_post = Locus::Input {
        slot: TxSlot::Listed(0),
        input: 1,
    };
    let rejoin = compact.join(shard_set(vec![0]), ENDPOINT);
    refused_at(
        scenario
            .mine_listing(vec![spender.spend_coinbase_posting(
                scenario.wallet(),
                BlockHeight::from_raw(3),
                after,
                FEE,
                Some(&rejoin),
            )])
            .await,
        CenRow::J14,
        at_post,
    );
    let mut reinstate = whole.join_post(complete_tree(), ENDPOINT);
    reinstate.kind = BondPostKind::Other(shekyl_archival_retention::BondPostKind::Reinstate as u8);
    let reinstate = whole.post_by_hand(reinstate);
    refused_at(
        scenario
            .mine_listing(vec![spender.spend_coinbase_posting(
                scenario.wallet(),
                BlockHeight::from_raw(3),
                after,
                FEE,
                Some(&reinstate),
            )])
            .await,
        CenRow::J18,
        at_post,
    );
    // CEN-J14's floor arm, which the fixtures cannot shape (every
    // fixture's holdings cost one floor): the compact persona's two-shard
    // join with one floor behind it. The post names a persona already
    // bonded, so the arm under test is reached only because the verify
    // reads the money before the record — `FloorMismatch` ahead of
    // `RecordExists`, the retention crate's order.
    let mut under_bonded = compact.join_post(shard_set(shards), ENDPOINT);
    under_bonded.bonded_total_atomic = ARCHIVAL_BOND_FLOOR_ATOMIC;
    under_bonded.bond_credit = ARCHIVAL_BOND_FLOOR_ATOMIC;
    let under_bonded = compact.post_by_hand(under_bonded);
    refused_at(
        scenario
            .mine_listing(vec![spender.spend_coinbase_posting(
                scenario.wallet(),
                BlockHeight::from_raw(3),
                after,
                FEE,
                Some(&under_bonded),
            )])
            .await,
        CenRow::J14,
        at_post,
    );
    assert_eq!(
        scenario.bond_record(whole.id()).await.expect("read"),
        Some(released.clone()),
        "a refused block writes nothing"
    );

    scenario.close().await;
}
