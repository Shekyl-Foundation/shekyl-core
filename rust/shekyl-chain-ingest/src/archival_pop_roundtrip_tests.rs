// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Pop round trips over archival state (DRS-X PR 3e, e2; CEN-L7 and the
//! archival substrate cases the C++ pinned in `archival_substrate_lmdb`).
//!
//! The chains are the ones the other drivers already mine.
//! [`a_claim_chain_pops_and_reconnects_at_every_block_from_the_joins_on`]
//! is the frozen-membership chain, and
//! [`a_slash_and_reinstate_chain_pops_and_reconnects_at_every_block_from_the_join_on`]
//! is the levered slash chain. Each connect after the proof fill is popped
//! and connected again by [`Driven`](crate::chain_drive::Driven). The pop
//! equals its parent, except on a pruning boundary, where a retired table
//! keeps the keys the parent and the connect share, at the connect's value.
//! The reconnect is exact, digest included.
//!
//! [`a_popped_claim_restores_the_epoch_its_prune_dropped_and_a_second_claim_is_refused`]
//! is the one pop that is not that per-block trip: two blocks, so the claim
//! window's floor drops and the epoch the second claim pruned is claimable
//! again, and still refused.
//!
//! The fills are real proofs, so all three run in nightly.yml's
//! `chain-ingest-ignored` job.

use shekyl_archival_retention::{
    claim_window_floor, claimant_reward_share, epoch_close_compute, shard_contribution_micro,
    CreditPair, EmissionEpochSource, EpochCloseBond, EpochCloseInputs, EpochCloseShard, ShardClose,
    ShardWorkEntry, WorkEpochClaim, MAX_CLAIM_AGE_W,
};
use shekyl_chain_rules::{CenRow, Locus, TxSlot};
use shekyl_types::archival::FirstPayingHeight;
use shekyl_types::{BlockCount, BlockHeight, SettlementEpoch, ShardId};
use shekyl_wire::Transaction;

use crate::archival_driver::{first_spending_height, record_of, ENDPOINT, FEE};
use crate::archival_slash_tests::{run_levered_slash_chain, ConnectMode};
use crate::chain_drive::{
    catch_up, issue_draws, priced_emission_claim, spender_owning_before, Driven,
    EmissionClaimParts, IssuedPair,
};
use crate::emission_assembly::ClaimTerms;
use crate::frozen_membership::{drive_frozen_membership, price_frozen_claim};
use crate::scenario::{FreeHash, Mined, Scenario, StepOutcome};
use crate::scenario_archival::{shard_set, Persona};
use crate::scenario_shard::{
    close_shards, first_admissible_compact_join, inside_one_epoch, levered_rules, levered_schedule,
    mine_to, EPOCH_BLOCKS, FILL_FROM_COINBASE,
};
use shekyl_harness_spender::{Owner, Recipient, Spender};

/// The claim chain's transaction key. The straddle's three claims each
/// have their own, in the order they are priced.
const CLAIM_TX_KEY: [u8; 32] = [0x6c; 32];
const STRADDLE_FIRST_TX_KEY: [u8; 32] = [0x71; 32];
const STRADDLE_SECOND_TX_KEY: [u8; 32] = [0x72; 32];
const STRADDLE_AGAIN_TX_KEY: [u8; 32] = [0x73; 32];

/// The claim chain (module docs), every block from the joins on popped and
/// reconnected.
///
/// Events round-tripped, in chain order: three joins in one block at a
/// non-zero epoch; the drain of their funding outputs into the tree ten
/// blocks later (CEN-L11); each epoch's close; `served`'s pass (settlements,
/// `R_market`, `Σwork`, the frozen complete-tree set); a Release; a slash,
/// whose pop is its revert; the claim at the first block of `served + W`,
/// which sets the first paying height once and is the block whose batch
/// retires the claimable rows below `served − 1`. Popping the claim and
/// connecting it again mints once: the record names the epoch once and the
/// coins generated at the tip are the first connect's.
///
/// Supersedes, from `archival_substrate_lmdb` at `eb5be7767`:
/// `bond_post_connect_pop_roundtrip_through_real_block_path` (a join at a
/// non-zero epoch), `release_connect_pop_roundtrip_through_real_block_path`,
/// `budget_close_row_revert_and_reclose_symmetry` (close rows; its
/// zero-budget row has no driven witness, since every close here carries the
/// staker emission), `emission_snapshot_identity_and_descriptor_immunity`
/// (`Σwork` read from the store at each tip),
/// `emission_claim_first_paying_set_once_and_pop_symmetric`,
/// `emission_claim_apply_journal_and_revert_roundtrip`,
/// `emission_connect_pop_roundtrip_through_real_block_path` and
/// `emission_claim_prune_straddle_no_double_mint`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "fills a shard with real proofs; minutes; run by nightly.yml's chain-ingest-ignored job"]
async fn a_claim_chain_pops_and_reconnects_at_every_block_from_the_joins_on() {
    let rules = levered_rules();
    let mut scenario = Scenario::open_under("archival-pop-claim", FreeHash, rules);
    let mut mined = scenario.mine(first_spending_height().to_raw()).await;
    let filled = close_shards(&mut scenario, &mut mined, FILL_FROM_COINBASE, 1).await;
    let [closed] = filled.closed.as_slice() else {
        panic!("one shard closed");
    };
    let join_height = inside_one_epoch(first_admissible_compact_join(&rules, *closed), 1);
    mine_to(&mut scenario, &mut mined, join_height).await;
    let mut drive = Driven::begin(scenario, mined);
    drive.round_trip_from_here().await;
    let facts = drive_frozen_membership(&mut drive, *closed).await;

    let generated_before = drive
        .scenario
        .facts()
        .await
        .expect("facts")
        .parent_coins_generated;
    let spender = spender_owning_before(
        &drive.chain,
        facts.join_height,
        &[facts.backing_key, facts.fee_key],
    );
    let claim_tx = price_frozen_claim(
        &mut drive.scenario,
        &facts,
        &spender,
        facts.served,
        CLAIM_TX_KEY,
    )
    .await;
    let claimed = drive
        .connect(vec![claim_tx])
        .await
        .unwrap_or_else(|outcome| panic!("the claim on the frozen membership connects: {outcome}"));
    assert_eq!(claimed.height, facts.connecting);
    let record = record_of(&drive.scenario, &facts.persona).await;
    assert_eq!(
        record.claimed_settlement_epochs,
        vec![facts.served],
        "after the pop and the reconnect the record names the epoch once"
    );
    assert_eq!(
        record.first_paying_emission_height,
        FirstPayingHeight::new(facts.connecting),
        "the first paying height is the claim's, set once"
    );
    let generated_after = drive
        .scenario
        .facts()
        .await
        .expect("facts")
        .parent_coins_generated;
    assert_eq!(
        generated_after, claimed.emission.coins_generated,
        "the coins generated at the tip are the claim block's, across its pop and reconnect"
    );
    assert_eq!(
        generated_after.to_raw() - generated_before.to_raw(),
        claimed.emission.paid.to_raw(),
        "the claim block minted once"
    );

    // Every close here has a budget: the staker emission accrues on every
    // block, so a driven chain closes no epoch at zero.
    let closes = drive.closes();
    assert_eq!(closes[0], 0, "no close at a zero budget");
    assert!(closes[1] > 0, "closes were round-tripped");
    // The boundary exception is exercised, not only written: a schedule
    // change that moved every prune past the chain would leave it unread.
    assert!(drive.trips() > 0, "blocks were round-tripped");
    assert!(
        drive.boundaries() > 0,
        "a pruning boundary was round-tripped"
    );
    drive.close().await;
}

/// The slash-and-reinstate chain (module docs), every block from the join
/// on popped and reconnected: a compact join on two shards at a non-zero
/// epoch; its first serve credit; eleven epochs of settlements, passed on one
/// shard and missed on the other, with injected credits; the slash, whose
/// pop is its revert; the Reinstate that closes the interval; the release
/// at the cooldown's boundary.
///
/// Supersedes, from `archival_substrate_lmdb` at `eb5be7767`:
/// `bond_post_connect_pop_roundtrip_through_real_block_path` (the compact
/// join), `same_epoch_slashes_coalesce_one_open_interval` (the slash and its
/// revert), `reinstate_standing_only_zero_credit_roundtrip` and
/// `release_connect_pop_roundtrip_through_real_block_path`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "fills two shards with real proofs; minutes; run by nightly.yml's chain-ingest-ignored job"]
async fn a_slash_and_reinstate_chain_pops_and_reconnects_at_every_block_from_the_join_on() {
    let run = run_levered_slash_chain(ConnectMode::RoundTrip).await;
    assert!(run.trips > 0, "blocks were round-tripped");
    assert!(run.boundaries > 0, "a pruning boundary was round-tripped");
}

/// What one straddle claim is priced from. The share is recomputed for the
/// epoch: this chain serves two epochs, and each close has its own budget.
struct StraddleClaim<'a> {
    persona: &'a Persona,
    backing_key: [u8; 32],
    fee_key: [u8; 32],
    join_epoch: SettlementEpoch,
    close_height: BlockHeight,
    epoch: SettlementEpoch,
    connecting: BlockHeight,
    tx_key: [u8; 32],
}

/// A claim of `claim.epoch` at the relay floor, over the one bond, the one
/// shard and the one Served pair this chain fed the close.
async fn claim_of(
    scenario: &mut Scenario<FreeHash>,
    spender: &Spender,
    mined: &[Mined],
    claim: &StraddleClaim<'_>,
) -> Transaction {
    let count_at_close = (claim.epoch.to_raw() + 1) * EPOCH_BLOCKS;
    let budget = mined[usize::try_from(count_at_close - 1).expect("small")]
        .archival
        .close()
        .expect("the block that completes the epoch closes it")
        .budget();
    let bonds = [EpochCloseBond {
        join_settlement_epoch: claim.join_epoch.to_raw(),
        is_support_complete_tree: false,
        bad_intervals: &[],
    }];
    let shards = [EpochCloseShard {
        shard_id: 0,
        close: ShardClose::ClosedAt(claim.close_height),
    }];
    let pairs = [CreditPair {
        bond_idx: 0,
        shard_idx: 0,
    }];
    let inputs = EpochCloseInputs::under_schedule(
        levered_schedule(),
        claim.epoch.to_raw(),
        count_at_close,
        &bonds,
        &shards,
        &pairs,
    );
    let result = epoch_close_compute(&inputs).expect("the pair indexes its bond and shard");
    let share = claimant_reward_share(&EmissionEpochSource {
        inputs: inputs.clone(),
        persisted_sigma_work_milli: result.sigma_work_milli,
        claimant_bond_idx: Some(0),
        budget: budget.to_raw(),
    })
    .expect("the claimant indexes its bond");
    assert!(
        share.is_member && share.reward > 0,
        "a share is owed for {:?}",
        claim.epoch
    );
    let scarcity = shard_contribution_micro(&inputs, &result.r_market_by_shard, 0);
    let owner = Owner::persona(claim.persona.keys());
    priced_emission_claim(
        scenario,
        EmissionClaimParts {
            spender,
            owner: &owner,
            keys: claim.persona.keys(),
            backing_key: claim.backing_key,
            fee_key: claim.fee_key,
            terms: ClaimTerms {
                holdings: shard_set(vec![0]),
                settlement_epochs: vec![claim.epoch.to_raw()],
                work_claim: vec![WorkEpochClaim {
                    epoch: claim.epoch.to_raw(),
                    shard_entries: vec![ShardWorkEntry {
                        shard_id: 0,
                        serve_credit_bit: true,
                        scarcity_micro: u32::try_from(scarcity).expect("a per-entry term fits"),
                    }],
                }],
                reward_amount_plain: vec![share.reward],
            },
            connecting: claim.connecting,
            tx_key: claim.tx_key,
        },
    )
    .await
}

/// The prune-straddle (`REWARD_EMISSION_E3_GATING_ROUND.md` §6.4 #3) on a
/// driven chain. The claimed set is pruned on insert
/// (`claimed_epochs_check_and_set` keeps the epochs at or above the claim
/// window's floor), so a later claim drops an epoch the persona was already
/// paid for. Popping that claim must bring the epoch back, or a branch that
/// lowers the floor again would pay it twice.
///
/// One compact persona on shard 0, Served in `E_old` and in
/// `E_new = E_old + W − 1`:
///
/// 1. `E_old` is claimed the block after its pass and paid.
/// 2. `E_new` is claimed at the first block of epoch `t = E_old + W + 1`,
///    the first block where `Σwork(E_new)` is a row. The window's floor
///    there is `t − W = E_old + 1`, so the insert prunes `E_old`.
/// 3. The chain pops two blocks, the claim and the pass before it. The
///    epoch is a function of height, so only a pop past the epoch's first
///    block lowers the floor: the next block is in epoch `t − 1`, whose
///    floor is `E_old`, and `E_old` is claimable again by the window.
/// 4. A fresh claim of `E_old` there is refused at CEN-J25, the verify's
///    `EpochAlreadyClaimed`: the pop restored the record's pre-image (the
///    undo journal's `archival_bond` row), `E_old` and the first paying
///    height with it.
///
/// Supersedes `archival_substrate_lmdb`'s
/// `emission_claim_prune_straddle_no_double_mint` (at `eb5be7767`).
///
/// Red edit: skip the undo journal's `archival_bond` entries in
/// `shekyl-chain-store`'s `undo::replay` — the pop leaves the post-image,
/// `E_old` is not in the set, and the fresh claim connects: a second mint.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "fills a shard with real proofs; minutes; run by nightly.yml's chain-ingest-ignored job"]
async fn a_popped_claim_restores_the_epoch_its_prune_dropped_and_a_second_claim_is_refused() {
    let rules = levered_rules();
    let schedule = levered_schedule();
    let window = MAX_CLAIM_AGE_W;
    let mut scenario = Scenario::open_under("archival-pop-straddle", FreeHash, rules);
    let mut mined = scenario.mine(first_spending_height().to_raw()).await;
    let filled = close_shards(&mut scenario, &mut mined, FILL_FROM_COINBASE, 1).await;
    let [closed] = filled.closed.as_slice() else {
        panic!("one shard closed");
    };
    let join_height = inside_one_epoch(first_admissible_compact_join(&rules, *closed), 2);
    mine_to(&mut scenario, &mut mined, join_height).await;
    let mut spender = Spender::over(&mined);
    let mut seen = mined.len();

    // The join rides coinbase 0, paying the persona the claims' backing and
    // the first claim's fee; coinbases 1 and 2 pay the other two fees, each
    // in its own block (the spender draws output keys from the height).
    let persona = Persona::at(1);
    let recipient = Recipient::persona(persona.keys());
    let mut fee_keys = Vec::new();
    let funding = spender.spend_coinbase_to(
        scenario.wallet(),
        BlockHeight::ZERO,
        join_height,
        FEE,
        Some(&persona.join(shard_set(vec![0]), ENDPOINT)),
        &recipient,
    );
    let backing_key = funding.prefix.outputs[0].key;
    spender.own(backing_key);
    fee_keys.push(funding.prefix.outputs[1].key);
    spender.own(fee_keys[0]);
    let block = scenario
        .mine_listing(vec![funding])
        .await
        .unwrap_or_else(|outcome| panic!("the join connects: {outcome}"));
    mined.push(block);
    for coinbase in 1..=2u64 {
        catch_up(&mut spender, &mined, &mut seen);
        let height = BlockHeight::from_raw(u64::try_from(mined.len()).expect("a height"));
        let paying = spender.spend_coinbase_to(
            scenario.wallet(),
            BlockHeight::from_raw(coinbase),
            height,
            FEE,
            None,
            &recipient,
        );
        let fee_key = paying.prefix.outputs[1].key;
        spender.own(fee_key);
        fee_keys.push(fee_key);
        let block = scenario
            .mine_listing(vec![paying])
            .await
            .unwrap_or_else(|outcome| panic!("fee funding {coinbase} connects: {outcome}"));
        mined.push(block);
    }
    let join_epoch = schedule.epoch_at(join_height);
    let e_old = SettlementEpoch::from_raw(join_epoch.to_raw() + 1);
    let e_new = SettlementEpoch::from_raw(e_old.to_raw() + window - 1);
    let at_epoch = e_old.to_raw() + window + 1;
    let shard = ShardId::from_raw(0);
    for epoch in [e_old, e_new] {
        issue_draws(
            &scenario,
            epoch,
            &[IssuedPair {
                persona: persona.id(),
                shard,
                passed: true,
            }],
        )
        .await;
    }

    let claim = |fee_index: usize,
                 epoch: SettlementEpoch,
                 connecting: BlockHeight,
                 tx_key: [u8; 32]| StraddleClaim {
        persona: &persona,
        backing_key,
        fee_key: fee_keys[fee_index],
        join_epoch,
        close_height: closed.close_height,
        epoch,
        connecting,
        tx_key,
    };

    // 1. `E_old`, the block after its pass.
    let first_connecting =
        BlockHeight::from_raw(schedule.slash_deadline_height(e_old.to_raw()) + 1);
    mine_to(&mut scenario, &mut mined, first_connecting).await;
    catch_up(&mut spender, &mined, &mut seen);
    let first = claim_of(
        &mut scenario,
        &spender,
        &mined,
        &claim(0, e_old, first_connecting, STRADDLE_FIRST_TX_KEY),
    )
    .await;
    let block = scenario
        .mine_listing(vec![first])
        .await
        .unwrap_or_else(|outcome| panic!("the claim of E_old connects: {outcome}"));
    mined.push(block);
    let paid = record_of(&scenario, &persona).await;
    assert_eq!(paid.claimed_settlement_epochs, vec![e_old]);
    assert_eq!(
        paid.first_paying_emission_height,
        FirstPayingHeight::new(first_connecting)
    );

    // 2. `E_new` at the first block of `at_epoch`: the insert prunes `E_old`.
    let second_connecting = BlockHeight::from_raw(schedule.open_height(at_epoch));
    assert_eq!(
        schedule.slash_deadline_height(e_new.to_raw()) + 1,
        second_connecting.to_raw(),
        "the first block where Σwork(E_new) is a row"
    );
    assert_eq!(claim_window_floor(at_epoch), e_old.to_raw() + 1);
    mine_to(&mut scenario, &mut mined, second_connecting).await;
    catch_up(&mut spender, &mined, &mut seen);
    let second = claim_of(
        &mut scenario,
        &spender,
        &mined,
        &claim(1, e_new, second_connecting, STRADDLE_SECOND_TX_KEY),
    )
    .await;
    let block = scenario
        .mine_listing(vec![second])
        .await
        .unwrap_or_else(|outcome| panic!("the claim of E_new connects: {outcome}"));
    assert_eq!(block.height, second_connecting);
    mined.push(block);
    assert_eq!(
        record_of(&scenario, &persona)
            .await
            .claimed_settlement_epochs,
        vec![e_new],
        "the insert pruned E_old below the floor"
    );

    // 3. Pop the claim and the pass before it: the next block is in
    // `at_epoch − 1`, whose floor is `E_old`.
    let below = BlockHeight::from_raw(second_connecting.to_raw() - 2);
    let rewound = scenario.rewind_to(below).await.expect("the rewind answers");
    assert_eq!(rewound.popped(), 2, "{rewound:?}");
    mined.truncate(usize::try_from(below.to_raw() + 1).expect("small"));
    let rebuilt = below + BlockCount::ONE;
    assert_eq!(schedule.epoch_at(rebuilt).to_raw(), at_epoch - 1);
    assert_eq!(
        claim_window_floor(at_epoch - 1),
        e_old.to_raw(),
        "E_old is inside the window again"
    );

    // 4. A fresh claim of `E_old` is refused, at the transaction. The
    // spender is rebuilt over the surviving chain, watching the persona's
    // outputs from before the blocks that paid them.
    let again_claim = claim(2, e_old, rebuilt, STRADDLE_AGAIN_TX_KEY);
    let mut owned = vec![backing_key];
    owned.extend(fee_keys);
    let spender = spender_owning_before(&mined, join_height, &owned);
    let again = claim_of(&mut scenario, &spender, &mined, &again_claim).await;
    match scenario.mine_listing(vec![again]).await {
        Err(StepOutcome::Refused(refused)) => {
            assert_eq!(refused.rule, CenRow::J25, "refused by: {refused}");
            assert_eq!(
                refused.locus,
                Locus::Tx {
                    slot: TxSlot::Listed(0)
                }
            );
        }
        Ok(block) => panic!(
            "double mint: E_old, paid at {first_connecting}, was claimed again at {}",
            block.height
        ),
        Err(other) => panic!("expected J25's refusal, got {other}"),
    }
    let restored = record_of(&scenario, &persona).await;
    assert_eq!(
        restored, paid,
        "the pop restored the record the first claim wrote, E_old and its first paying height"
    );
    scenario.close().await;
}
