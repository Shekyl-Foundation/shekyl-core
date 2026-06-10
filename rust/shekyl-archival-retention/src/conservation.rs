// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bonded-aggregation audit helper (gate-4 §4.5).
//!
//! **Audit/KAT only** — not a per-connect or per-block consensus check. A full
//! `Σ_P` scan is O(N_P); live enforcement would need incremental maintenance plus
//! periodic audit (out of scope for gate-4 §8 phase 1).

use thiserror::Error;

/// Snapshot inputs for §4.5 bonded-aggregation cross-check (no LMDB).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConservationSnapshot<'a> {
    pub total_bonded_atomic: u64,
    pub per_p_bonded: &'a [u64],
    /// When all three are `Some`, checks the full supply law (emission KATs).
    pub already_generated: Option<u64>,
    pub circulating: Option<u64>,
    pub burned: Option<u64>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConservationError {
    #[error("sum(per_p_bonded) overflowed u64")]
    BondedSumOverflow,
    #[error("total_bonded_atomic {total} != sum(per_p_bonded) {sum}")]
    BondedAggregationMismatch { total: u64, sum: u64 },
    #[error(
        "already_generated {generated} != circulating {circulating} + bonded {bonded} + burned {burned}"
    )]
    SupplyLawMismatch {
        generated: u64,
        circulating: u64,
        bonded: u64,
        burned: u64,
    },
}

/// Bonded-aggregation identity: `total_bonded_atomic == Σ_P bonded_total_atomic`.
pub fn verify_conservation_snapshot(s: &ConservationSnapshot<'_>) -> Result<(), ConservationError> {
    let mut sum = 0u64;
    for &bonded in s.per_p_bonded {
        sum = sum
            .checked_add(bonded)
            .ok_or(ConservationError::BondedSumOverflow)?;
    }
    if s.total_bonded_atomic != sum {
        return Err(ConservationError::BondedAggregationMismatch {
            total: s.total_bonded_atomic,
            sum,
        });
    }
    if let (Some(generated), Some(circulating), Some(burned)) =
        (s.already_generated, s.circulating, s.burned)
    {
        let rhs = circulating
            .checked_add(s.total_bonded_atomic)
            .and_then(|x| x.checked_add(burned));
        if rhs != Some(generated) {
            return Err(ConservationError::SupplyLawMismatch {
                generated,
                circulating,
                bonded: s.total_bonded_atomic,
                burned,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregation_holds_for_single_join() {
        let per_p = [750_000_000];
        let s = ConservationSnapshot {
            total_bonded_atomic: 750_000_000,
            per_p_bonded: &per_p,
            already_generated: None,
            circulating: None,
            burned: None,
        };
        assert!(verify_conservation_snapshot(&s).is_ok());
    }

    #[test]
    fn aggregation_rejects_per_p_sum_overflow() {
        let per_p = [u64::MAX, 1];
        let s = ConservationSnapshot {
            total_bonded_atomic: 0,
            per_p_bonded: &per_p,
            already_generated: None,
            circulating: None,
            burned: None,
        };
        assert_eq!(
            verify_conservation_snapshot(&s),
            Err(ConservationError::BondedSumOverflow)
        );
    }

    #[test]
    fn aggregation_rejects_desync() {
        let per_p = [750_000_000];
        let s = ConservationSnapshot {
            total_bonded_atomic: 1,
            per_p_bonded: &per_p,
            already_generated: None,
            circulating: None,
            burned: None,
        };
        assert_eq!(
            verify_conservation_snapshot(&s),
            Err(ConservationError::BondedAggregationMismatch {
                total: 1,
                sum: 750_000_000
            })
        );
    }

    #[test]
    fn aggregation_holds_for_multiple_p() {
        let per_p = [750_000_000, 1_500_000_000, 750_000_000];
        let s = ConservationSnapshot {
            total_bonded_atomic: 3_000_000_000,
            per_p_bonded: &per_p,
            already_generated: None,
            circulating: None,
            burned: None,
        };
        assert!(verify_conservation_snapshot(&s).is_ok());
    }

    #[test]
    fn aggregation_accepts_empty_per_p_when_total_zero() {
        let per_p: [u64; 0] = [];
        let s = ConservationSnapshot {
            total_bonded_atomic: 0,
            per_p_bonded: &per_p,
            already_generated: None,
            circulating: None,
            burned: None,
        };
        assert!(verify_conservation_snapshot(&s).is_ok());
    }

    #[test]
    fn supply_law_holds_when_all_fields_present() {
        let per_p = [750_000_000];
        let s = ConservationSnapshot {
            total_bonded_atomic: 750_000_000,
            per_p_bonded: &per_p,
            already_generated: Some(1_000_000_000),
            circulating: Some(200_000_000),
            burned: Some(50_000_000),
        };
        assert!(verify_conservation_snapshot(&s).is_ok());
    }

    #[test]
    fn supply_law_rejects_mismatch() {
        let per_p = [750_000_000];
        let s = ConservationSnapshot {
            total_bonded_atomic: 750_000_000,
            per_p_bonded: &per_p,
            already_generated: Some(1_000_000_000),
            circulating: Some(200_000_000),
            burned: Some(51_000_000),
        };
        assert_eq!(
            verify_conservation_snapshot(&s),
            Err(ConservationError::SupplyLawMismatch {
                generated: 1_000_000_000,
                circulating: 200_000_000,
                bonded: 750_000_000,
                burned: 51_000_000,
            })
        );
    }

    #[test]
    fn supply_law_skipped_when_any_field_missing() {
        let per_p = [100];
        let partial = ConservationSnapshot {
            total_bonded_atomic: 100,
            per_p_bonded: &per_p,
            already_generated: Some(1_000),
            circulating: Some(200),
            burned: None,
        };
        assert!(verify_conservation_snapshot(&partial).is_ok());
    }

    #[test]
    fn supply_law_rejects_rhs_overflow() {
        let per_p = [u64::MAX];
        let s = ConservationSnapshot {
            total_bonded_atomic: u64::MAX,
            per_p_bonded: &per_p,
            already_generated: Some(u64::MAX),
            circulating: Some(u64::MAX),
            burned: Some(1),
        };
        assert_eq!(
            verify_conservation_snapshot(&s),
            Err(ConservationError::SupplyLawMismatch {
                generated: u64::MAX,
                circulating: u64::MAX,
                bonded: u64::MAX,
                burned: 1,
            })
        );
    }
}
