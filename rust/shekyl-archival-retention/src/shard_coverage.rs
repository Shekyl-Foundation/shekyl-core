// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Operator coverage ranking (`ARCHIVAL_SHARD_SELECTION_LIST.md` SL-D4).
//!
//! C++ fills per-shard operands from LMDB; this module computes
//! join-adjusted scarcity and expected-profit and orders the list.
//! Presentation only — every frozen shard remains legal (SL-D8 reading 1).

use crate::bond_floor::ARCHIVAL_REWARD_AGE_WEIGHT_MILLI;
use crate::consensus_state::shard_age_milli;
use crate::constants::effective_settlement_epoch_blocks;
use crate::reward_arithmetic::{reward_share_floor, scarcity_micro, work_milli_from_micro};

/// One frozen shard's coverage operands as marshaled by the daemon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShardCoverageIn {
    pub shard_id: u64,
    pub bonded_count: u64,
    pub served_count: u64,
    pub freeze_height: u64,
}

/// Ranked coverage row: operands plus join-adjusted scarcity and SKL hint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShardCoverageOut {
    pub shard_id: u64,
    pub bonded_count: u64,
    pub served_count: u64,
    pub freeze_height: u64,
    pub join_scarcity_micro: u64,
    pub expected_profit_atomic: u64,
}

/// Join-adjusted scarcity: `scarcity_micro(bonded_count + 1, age, weight)`.
///
/// `r_market == 0` scores 0, so the picker must count the operator's own
/// future seat (`SL-D4`).
#[must_use]
pub fn join_scarcity_micro(bonded_count: u64, age_milli: u64) -> u64 {
    scarcity_micro(
        bonded_count.saturating_add(1),
        age_milli,
        ARCHIVAL_REWARD_AGE_WEIGHT_MILLI,
    )
}

/// Rank `in_rows` by join-scarcity descending, then `shard_id` ascending.
///
/// Equal scarcity bands stay adjacent so a client can shuffle within a band.
/// `expected_profit_atomic` is 0 when `sigma_work_milli == 0` (no epoch has
/// paid yet); ranking still uses scarcity.
#[must_use]
pub fn order_shard_coverage(
    tip_height: u64,
    budget_atomic: u64,
    sigma_work_milli: u64,
    in_rows: &[ShardCoverageIn],
) -> Vec<ShardCoverageOut> {
    let seb = effective_settlement_epoch_blocks();
    let mut out: Vec<ShardCoverageOut> = in_rows
        .iter()
        .map(|row| {
            let age = shard_age_milli(tip_height, row.freeze_height, seb);
            let join = join_scarcity_micro(row.bonded_count, age);
            let expected = if sigma_work_milli == 0 {
                0
            } else {
                reward_share_floor(budget_atomic, work_milli_from_micro(join), sigma_work_milli)
            };
            ShardCoverageOut {
                shard_id: row.shard_id,
                bonded_count: row.bonded_count,
                served_count: row.served_count,
                freeze_height: row.freeze_height,
                join_scarcity_micro: join,
                expected_profit_atomic: expected,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        b.join_scarcity_micro
            .cmp(&a.join_scarcity_micro)
            .then_with(|| a.shard_id.cmp(&b.shard_id))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(shard_id: u64, bonded_count: u64, freeze_height: u64) -> ShardCoverageIn {
        ShardCoverageIn {
            shard_id,
            bonded_count,
            served_count: 0,
            freeze_height,
        }
    }

    #[test]
    fn join_scarcity_matches_bonded_plus_one() {
        let age = shard_age_milli(50_000, 1_000, effective_settlement_epoch_blocks());
        assert_eq!(
            join_scarcity_micro(3, age),
            scarcity_micro(4, age, ARCHIVAL_REWARD_AGE_WEIGHT_MILLI)
        );
    }

    #[test]
    fn extra_bond_lowers_rank() {
        // Same freeze (same age); denser shard ranks below the sparser one.
        let ranked = order_shard_coverage(
            50_000,
            1_000_000,
            1_000,
            &[row(0, 4, 1_000), row(1, 1, 1_000), row(2, 0, 1_000)],
        );
        assert_eq!(
            ranked.iter().map(|r| r.shard_id).collect::<Vec<_>>(),
            vec![2, 1, 0]
        );
        assert!(ranked[0].join_scarcity_micro > ranked[1].join_scarcity_micro);
        assert!(ranked[1].join_scarcity_micro > ranked[2].join_scarcity_micro);
    }

    #[test]
    fn equal_scarcity_adjacent_and_id_stable() {
        let ranked = order_shard_coverage(
            50_000,
            1_000_000,
            1_000,
            &[row(7, 1, 1_000), row(3, 1, 1_000), row(5, 1, 1_000)],
        );
        assert_eq!(
            ranked.iter().map(|r| r.shard_id).collect::<Vec<_>>(),
            vec![3, 5, 7]
        );
        assert_eq!(ranked[0].join_scarcity_micro, ranked[1].join_scarcity_micro);
        assert_eq!(ranked[1].join_scarcity_micro, ranked[2].join_scarcity_micro);
    }

    #[test]
    fn sigma_zero_keeps_scarcity_rank_and_zero_profit() {
        let ranked =
            order_shard_coverage(50_000, 1_000_000, 0, &[row(1, 0, 1_000), row(0, 8, 1_000)]);
        assert_eq!(ranked[0].shard_id, 1);
        assert_eq!(ranked[0].expected_profit_atomic, 0);
        assert_eq!(ranked[1].expected_profit_atomic, 0);
        assert!(ranked[0].join_scarcity_micro > ranked[1].join_scarcity_micro);
    }
}
