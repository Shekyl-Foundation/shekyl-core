// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! An emission claim's terms: the epoch close's arithmetic, re-run over the
//! rows the plan fed it, as the driver's emission scenario computes them
//! (`scenario_emission_tests`, `the_drivers_emission_claim_connects_and_pays_the_persona`).
//!
//! The claim step needs one bond, one shard and one served pair on the
//! chain: the persona's. The validator then holds the claim to the rows the
//! slash pass wrote (CEN-J21, J23, J25), so terms this arithmetic got wrong
//! are refused, never forged.

use shekyl_archival_retention::{
    archival_params, claimant_reward_share, epoch_close_compute, shard_contribution_micro,
    CreditPair, EmissionEpochSource, EpochCloseBond, EpochCloseInputs, EpochCloseShard, ShardClose,
    ShardWorkEntry, WorkEpochClaim,
};
use shekyl_chain_ingest::emission_assembly::ClaimTerms;
use shekyl_chain_ingest::scenario_archival::shard_set;
use shekyl_chain_rules::SettlementSchedule;
use shekyl_types::{BlockHeight, SettlementEpoch};

/// What the claim's arithmetic reads.
pub struct Served {
    /// The schedule the chain runs.
    pub schedule: SettlementSchedule,
    /// The epoch the persona served and claims.
    pub epoch: SettlementEpoch,
    /// The epoch the persona joined in.
    pub join_epoch: SettlementEpoch,
    /// The one shard: its id and the height its fill closed it.
    pub shard: u64,
    /// The height whose fold first counted the shard closed.
    pub close_height: BlockHeight,
    /// The epoch's budget, as its close froze it.
    pub budget: u64,
}

/// The claim's terms over `served`.
///
/// # Panics
///
/// If the arithmetic finds the persona outside the market or owed nothing:
/// a claim for nothing is not a claim the validator admits (CEN-H22).
#[must_use]
pub fn terms(served: &Served) -> ClaimTerms {
    let bonds = [EpochCloseBond {
        join_settlement_epoch: served.join_epoch.to_raw(),
        bad_intervals: &[],
    }];
    let shards = [EpochCloseShard {
        shard_id: served.shard,
        close: ShardClose::ClosedAt(served.close_height),
    }];
    let pairs = [CreditPair {
        bond_idx: 0,
        shard_idx: 0,
    }];
    let count_at_close = (served.epoch.to_raw() + 1) * served.schedule.blocks().get();
    let inputs = EpochCloseInputs::under_schedule(
        served.schedule,
        served.epoch.to_raw(),
        count_at_close,
        &bonds,
        &shards,
        &pairs,
        archival_params(),
    );
    let result = epoch_close_compute(&inputs).expect("the pair indexes its bond and shard");
    let share = claimant_reward_share(&EmissionEpochSource {
        inputs: inputs.clone(),
        persisted_sigma_work_milli: result.sigma_work_milli,
        claimant_bond_idx: Some(0),
        budget: served.budget,
    })
    .expect("the claimant indexes its bond");
    assert!(share.is_member, "the one server is in the market");
    assert!(
        share.reward > 0,
        "the one server is owed a share (budget {}, Σwork {})",
        served.budget,
        result.sigma_work_milli
    );
    let scarcity = shard_contribution_micro(&inputs, &result.r_market_by_shard, 0);
    ClaimTerms {
        holdings: shard_set(vec![served.shard]),
        settlement_epochs: vec![served.epoch.to_raw()],
        work_claim: vec![WorkEpochClaim {
            epoch: served.epoch.to_raw(),
            shard_entries: vec![ShardWorkEntry {
                shard_id: served.shard,
                serve_credit_bit: true,
                scarcity_micro: u32::try_from(scarcity).expect("a per-entry term fits (F-C)"),
            }],
        }],
        reward_amount_plain: vec![share.reward],
    }
}
