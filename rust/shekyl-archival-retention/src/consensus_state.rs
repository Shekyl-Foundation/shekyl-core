//! Pure consensus-state helpers for emission reads (ARCHIVAL_CONSENSUS_STATE.md §3–§5).
//!
//! No LMDB — fixture/KAT replay only. C++ materialization must match these semantics.

use crate::reward_arithmetic::{curve_milli, scarcity_milli, BandedCurveParams, WORK_MILLI_SCALE};

/// Half-open bad-standing interval `[start_epoch, end_exclusive)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadInterval {
    pub start_epoch: u64,
    pub end_exclusive: u64,
}

/// Spec-correct `good_through` (interval semantics at E-close).
#[must_use]
pub fn good_through(
    join_settlement_epoch: u64,
    settlement_epoch: u64,
    bad_intervals: &[BadInterval],
) -> bool {
    if settlement_epoch < join_settlement_epoch.saturating_add(1) {
        return false;
    }
    for iv in bad_intervals {
        if settlement_epoch < iv.start_epoch {
            continue;
        }
        if iv.end_exclusive == u64::MAX || settlement_epoch < iv.end_exclusive {
            return false;
        }
    }
    true
}

/// Market membership at epoch close (ARCHIVAL_BOND_GATE4.md §2.2).
#[must_use]
pub fn market_member_at_epoch(
    join_settlement_epoch: u64,
    settlement_epoch: u64,
    bad_intervals: &[BadInterval],
    is_foundation_complete_tree: bool,
) -> bool {
    if is_foundation_complete_tree {
        return false;
    }
    good_through(join_settlement_epoch, settlement_epoch, bad_intervals)
}

/// One archiver's serve-credit row for `R_market` materialization KATs.
#[derive(Debug, Clone)]
pub struct ServeCreditRow {
    pub p_id: [u8; 32],
    pub shard_id: u64,
    pub serve_credit: bool,
    pub join_settlement_epoch: u64,
    pub bad_intervals: Vec<BadInterval>,
    pub is_foundation: bool,
}

/// `R_market(shard, E)` — serve-credit-weighted count (Gap 2 pin).
#[must_use]
pub fn r_market_count(rows: &[ServeCreditRow], shard_id: u64, settlement_epoch: u64) -> u64 {
    let mut n = 0u64;
    for row in rows {
        if row.shard_id != shard_id || !row.serve_credit {
            continue;
        }
        if !market_member_at_epoch(
            row.join_settlement_epoch,
            settlement_epoch,
            &row.bad_intervals,
            row.is_foundation,
        ) {
            continue;
        }
        if !good_through(
            row.join_settlement_epoch,
            settlement_epoch,
            &row.bad_intervals,
        ) {
            continue;
        }
        n = n.saturating_add(1);
    }
    n
}

/// Work milli for one held shard with serve credit.
#[must_use]
pub fn shard_work_milli(
    r_market: u64,
    age_milli: u64,
    age_weight_milli: u64,
    serve_credit: bool,
) -> u64 {
    if !serve_credit || r_market == 0 {
        return 0;
    }
    scarcity_milli(r_market, age_milli, age_weight_milli)
}

/// `Σwork(E)` milli — sum of `Curve(work_P)` over market archivers.
#[must_use]
pub fn sigma_work_milli(
    per_p_work_milli: &[u64],
    curve: &BandedCurveParams,
    market_mask: &[bool],
) -> u64 {
    assert_eq!(per_p_work_milli.len(), market_mask.len());
    let mut sum = 0u64;
    for (&work, &in_market) in per_p_work_milli.iter().zip(market_mask.iter()) {
        if !in_market || work == 0 {
            continue;
        }
        sum = sum.saturating_add(curve_milli(work, curve));
    }
    sum
}

/// Foundation excluded from market_R / Σwork (E-2 footnote — immediate, not lagged).
pub const FOUNDATION_EXCLUDED_FROM_MARKET: bool = true;

#[cfg(test)]
mod tests {
    use super::*;

    fn row(shard: u64, serve: bool, bad: Vec<BadInterval>) -> ServeCreditRow {
        ServeCreditRow {
            p_id: [0u8; 32],
            shard_id: shard,
            serve_credit: serve,
            join_settlement_epoch: 0,
            bad_intervals: bad,
            is_foundation: false,
        }
    }

    #[test]
    fn bonded_without_serve_credit_not_in_r_market() {
        let shard = 7u64;
        let e = 5u64;
        assert_eq!(r_market_count(&[row(shard, false, vec![])], shard, e), 0);
        assert_eq!(r_market_count(&[row(shard, true, vec![])], shard, e), 1);
    }

    #[test]
    fn partial_slash_bad_interval_excludes_from_r_market() {
        let shard = 3u64;
        let e = 10u64;
        let bad = vec![BadInterval {
            start_epoch: 8,
            end_exclusive: u64::MAX,
        }];
        assert!(!good_through(0, e, &bad));
        assert_eq!(r_market_count(&[row(shard, true, bad)], shard, e), 0);
    }

    #[test]
    fn good_through_before_slash_interval() {
        let bad = vec![BadInterval {
            start_epoch: 11,
            end_exclusive: u64::MAX,
        }];
        assert!(good_through(0, 10, &bad));
        assert!(!good_through(0, 11, &bad));
    }
}
