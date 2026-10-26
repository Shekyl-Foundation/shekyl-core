// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The frozen-membership chain (`SO-D12h`), through the claim window.
//!
//! A compact persona joins shard 0 beside two complete trees. All three
//! are Served for one epoch. One tree releases, the other is slashed, and
//! the chain mines to the first block where that epoch is the oldest the
//! claim window admits. The claim itself is the caller's: the emission
//! test still has an expired claim and a pool submission to judge before
//! it connects, and the pop test connects the same claim through
//! [`Driven::connect`] so the mint is round-tripped.

use shekyl_archival_retention::{
    claim_window_floor, claimant_reward_share, epoch_close_compute, good_through,
    shard_contribution_micro, CreditPair, EmissionEpochSource, EpochCloseBond, EpochCloseInputs,
    EpochCloseShard, ShardClose, ShardWorkEntry, WorkEpochClaim, MAX_CLAIM_AGE_W,
};
use shekyl_chain_rules::EpochFloor;
use shekyl_harness_spender::{Owner, Recipient, Spender};
use shekyl_types::archival::SettlementOutcome;
use shekyl_types::{BlockCount, BlockHeight, SettlementEpoch, ShardId};
use shekyl_wire::Transaction;

use crate::archival_driver::{record_of, ENDPOINT, FEE};
use crate::chain_drive::{
    catch_up, failure_window_epochs, priced_emission_claim, Driven, EmissionClaimParts, IssuedPair,
};
use crate::emission_assembly::ClaimTerms;
use crate::scenario::{FreeHash, Scenario};
use crate::scenario_archival::{complete_tree, shard_set, Persona};
use crate::scenario_shard::{levered_schedule, ClosedShard, EPOCH_BLOCKS};

/// The release's funding coinbase. The joins ride coinbases 0 to 2.
const RELEASE_COINBASE: u64 = 3;

/// The claim the caller connects, and the facts it is priced from.
pub(crate) struct FrozenClaim {
    pub persona: Persona,
    /// The block the three joins connected in. A spender that will spend
    /// the persona's outputs owns them before scanning this block.
    pub join_height: BlockHeight,
    pub served: SettlementEpoch,
    /// The next block: the first of `served + W`.
    pub connecting: BlockHeight,
    pub backing_key: [u8; 32],
    pub fee_key: [u8; 32],
    pub scarcity: u64,
    pub reward: u64,
}

impl FrozenClaim {
    /// A claim of `epoch` at the one share this chain computed for `served`.
    /// The expired and the retired epochs are priced from that share too:
    /// they are refused before the reward is read.
    pub(crate) fn terms_for(&self, epoch: SettlementEpoch) -> ClaimTerms {
        ClaimTerms {
            holdings: shard_set(vec![0]),
            settlement_epochs: vec![epoch.to_raw()],
            work_claim: vec![WorkEpochClaim {
                epoch: epoch.to_raw(),
                shard_entries: vec![ShardWorkEntry {
                    shard_id: 0,
                    serve_credit_bit: true,
                    scarcity_micro: u32::try_from(self.scarcity).expect("a per-entry term fits"),
                }],
            }],
            reward_amount_plain: vec![self.reward],
        }
    }
}

/// Price a claim of `epoch` from `facts`, at the chain's relay floor.
pub(crate) async fn price_frozen_claim(
    scenario: &mut Scenario<FreeHash>,
    facts: &FrozenClaim,
    spender: &Spender,
    epoch: SettlementEpoch,
    tx_key: [u8; 32],
) -> Transaction {
    let owner = Owner::persona(facts.persona.keys());
    priced_emission_claim(
        scenario,
        EmissionClaimParts {
            spender,
            owner: &owner,
            keys: facts.persona.keys(),
            backing_key: facts.backing_key,
            fee_key: facts.fee_key,
            terms: facts.terms_for(epoch),
            connecting: facts.connecting,
            tx_key,
        },
    )
    .await
}

/// Joins through the slash, then mine to the claim's block (module docs).
/// `drive`'s next block is the join. `closed` is the shard the joins name.
pub(crate) async fn drive_frozen_membership(
    drive: &mut Driven,
    closed: ClosedShard,
) -> FrozenClaim {
    assert_eq!(closed.shard.to_raw(), 0);
    let schedule = levered_schedule();
    let join_height = drive.height();
    let persona = Persona::at(1);
    let released = Persona::at(2);
    let slashed = Persona::at(3);
    let mut spender = Spender::over(&drive.chain);
    let mut seen = drive.chain.len();
    let (joins, backing_key, fee_key) = {
        let recipient = Recipient::persona(persona.keys());
        let funding = spender.spend_coinbase_to(
            drive.scenario.wallet(),
            BlockHeight::ZERO,
            join_height,
            FEE,
            Some(&persona.join(shard_set(vec![0]), ENDPOINT)),
            &recipient,
        );
        let backing_key = funding.prefix.outputs[0].key;
        let fee_key = funding.prefix.outputs[1].key;
        spender.own(backing_key);
        spender.own(fee_key);
        let trees: Vec<Transaction> = [&released, &slashed]
            .into_iter()
            .zip(1u64..)
            .map(|(tree, coinbase)| {
                spender.spend_coinbase_posting(
                    drive.scenario.wallet(),
                    BlockHeight::from_raw(coinbase),
                    join_height,
                    FEE,
                    Some(&tree.join(complete_tree(), ENDPOINT)),
                )
            })
            .collect();
        ([vec![funding], trees].concat(), backing_key, fee_key)
    };
    let joined = drive
        .connect(joins)
        .await
        .unwrap_or_else(|outcome| panic!("the three joins connect: {outcome}"));
    assert_eq!(joined.height, join_height);
    assert_eq!(joined.archival.records().len(), 3, "three joins");
    for tree in [&released, &slashed] {
        assert!(
            record_of(&drive.scenario, tree).await.is_complete_tree(),
            "a complete tree joined"
        );
    }
    let join_epoch = schedule.epoch_at(join_height);
    assert!(join_epoch.to_raw() > 0, "the joins are at a non-zero epoch");
    let served = SettlementEpoch::from_raw(join_epoch.to_raw() + 1);
    let shard = ShardId::from_raw(0);
    let all = [persona.id(), released.id(), slashed.id()];

    // `served`: every pair passes. Then the failure window, in which the
    // second tree alone is drawn and fails, so the pass of the last slashes it.
    let passing: Vec<_> = all
        .iter()
        .map(|id| IssuedPair {
            persona: *id,
            shard,
            passed: true,
        })
        .collect();
    drive.issue_draws(served, &passing).await;
    let slash_epoch = SettlementEpoch::from_raw(served.to_raw() + failure_window_epochs());
    for raw in (served.to_raw() + 1)..=slash_epoch.to_raw() {
        drive
            .issue_draws(
                SettlementEpoch::from_raw(raw),
                &[IssuedPair {
                    persona: slashed.id(),
                    shard,
                    passed: false,
                }],
            )
            .await;
    }

    let at_pass = BlockHeight::from_raw(schedule.slash_deadline_height(served.to_raw()));
    drive.advance_to(at_pass + BlockCount::ONE).await;
    let count_at_close = (served.to_raw() + 1) * EPOCH_BLOCKS;
    let close = *drive.chain[usize::try_from(count_at_close - 1).expect("small")]
        .archival
        .close()
        .expect("the block that completes the epoch carries its close");
    let pass = drive.chain[usize::try_from(at_pass.to_raw()).expect("small")]
        .archival
        .clone();
    let mut settled: Vec<_> = pass
        .settlements()
        .iter()
        .map(|row| (row.persona, row.epoch, row.row.outcome()))
        .collect();
    settled.sort_unstable_by_key(|(id, _, _)| *id);
    let mut expected: Vec<_> = all
        .iter()
        .map(|id| (*id, served, SettlementOutcome::Served))
        .collect();
    expected.sort_unstable_by_key(|(id, _, _)| *id);
    assert_eq!(settled, expected, "all three pairs settled Served");
    let gather = pass
        .gathers()
        .iter()
        .find(|gather| gather.epoch() == served)
        .expect("the pass gathers the epoch it settles");
    let mut trees = vec![released.id(), slashed.id()];
    trees.sort_unstable();
    assert_eq!(
        gather.complete_trees().as_slice(),
        trees.as_slice(),
        "the pass froze the two complete trees it kept out of the market"
    );

    // `Σwork(served)` from the store, not the fold.
    let stored_sigma = drive
        .scenario
        .with_store(|store, _| {
            store
                .begin_read()
                .expect("a snapshot")
                .sigma_work(served, EpochFloor::NONE)
                .expect("the read")
        })
        .await
        .expect("Σwork(served) is a row after the pass");
    assert_eq!(stored_sigma, gather.sigma_work());

    let bond = |complete| EpochCloseBond {
        join_settlement_epoch: join_epoch.to_raw(),
        is_support_complete_tree: complete,
        bad_intervals: &[],
    };
    let bonds = [bond(false), bond(true), bond(true)];
    let shards = [EpochCloseShard {
        shard_id: 0,
        close: ShardClose::ClosedAt(closed.close_height),
    }];
    let pairs: Vec<CreditPair> = (0..bonds.len())
        .map(|bond_idx| CreditPair {
            bond_idx,
            shard_idx: 0,
        })
        .collect();
    let inputs = EpochCloseInputs::under_schedule(
        schedule,
        served.to_raw(),
        count_at_close,
        &bonds,
        &shards,
        &pairs,
    );
    let result = epoch_close_compute(&inputs).expect("the pairs index their bonds and shard");
    assert_eq!(result.r_market_by_shard, vec![1], "one market member");
    assert_eq!(gather.sigma_work().to_raw(), result.sigma_work_milli);
    let share = claimant_reward_share(&EmissionEpochSource {
        inputs: inputs.clone(),
        persisted_sigma_work_milli: result.sigma_work_milli,
        claimant_bond_idx: Some(0),
        budget: close.budget().to_raw(),
    })
    .expect("the claimant indexes its bond");
    assert!(
        share.is_member && share.reward > 0,
        "the server is owed a share"
    );
    let scarcity = shard_contribution_micro(&inputs, &result.r_market_by_shard, 0);

    catch_up(&mut spender, &drive.chain, &mut seen);
    let release_height = at_pass + BlockCount::ONE;
    let bonded = record_of(&drive.scenario, &released)
        .await
        .bonded_total
        .to_raw();
    let release = released.release(bonded);
    let releasing = spender.spend_coinbase_posting(
        drive.scenario.wallet(),
        BlockHeight::from_raw(RELEASE_COINBASE),
        release_height,
        FEE,
        Some(&release),
    );
    let block = drive
        .connect(vec![releasing])
        .await
        .unwrap_or_else(|outcome| panic!("the release connects: {outcome}"));
    assert_eq!(block.height, release_height);
    assert_eq!(block.archival.records().len(), 1, "the release's write");
    let after_release = record_of(&drive.scenario, &released).await;
    assert!(
        !after_release.is_complete_tree(),
        "a released tree reads compact"
    );
    assert!(good_through(
        join_epoch.to_raw(),
        served.to_raw(),
        &after_release.bad_intervals
    ));

    let slash_height = BlockHeight::from_raw(schedule.slash_deadline_height(slash_epoch.to_raw()));
    drive.advance_to(slash_height + BlockCount::ONE).await;
    let slashes = drive.chain[usize::try_from(slash_height.to_raw()).expect("small")]
        .archival
        .slashes();
    assert_eq!(slashes.len(), 1, "one slash, at the eleventh miss's pass");
    assert_eq!(slashes[0].entry.persona, slashed.id());
    let after_slash = record_of(&drive.scenario, &slashed).await;
    assert!(
        !after_slash.is_complete_tree(),
        "a slashed tree reads compact"
    );
    assert!(
        good_through(
            join_epoch.to_raw(),
            served.to_raw(),
            &after_slash.bad_intervals
        ),
        "its interval opens after `served`"
    );

    let connecting = BlockHeight::from_raw(schedule.open_height(served.to_raw() + MAX_CLAIM_AGE_W));
    assert_eq!(
        claim_window_floor(schedule.epoch_at(connecting).to_raw()),
        served.to_raw(),
        "`served` is the oldest claimable epoch at the claim"
    );
    drive.advance_to(connecting).await;
    FrozenClaim {
        persona,
        join_height,
        served,
        connecting,
        backing_key,
        fee_key,
        scarcity,
        reward: share.reward,
    }
}
