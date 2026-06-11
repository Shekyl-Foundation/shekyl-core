// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! JoinMarket bond-post semantic verify (gate-4 §3.2–3.5).
//!
//! Structural bounds (hybrid pubkey length) and `P_canonical_id` hint checks stay
//! in C++ consensus glue; this module covers post-kind, holdings, term rigidity,
//! floor equality, and record-existence (via `record_exists` from LMDB).

use thiserror::Error;

use crate::bond_floor::bond_floor;
use crate::bond_wire::{ArchivalBondPostVin, BondPostKind, HoldingsKind};

#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum BondPostError {
    #[error("post_kind is not JoinMarket at genesis")]
    PostKindNotJoinMarket,
    #[error("ShardSetCompact requires at least one shard")]
    ShardSetCompactEmpty,
    #[error("CompleteTree must not carry shard ids")]
    CompleteTreeWithShardIds,
    #[error("JoinMarket bond-post must not carry bond_debit")]
    BondDebitNonzero,
    #[error("bond_credit and bond_debit are both non-zero")]
    BothTermsNonzero,
    #[error("bond_floor(holdings) is zero")]
    BondFloorZero,
    #[error("bonded_total_atomic and bond_credit must equal bond_floor")]
    FloorMismatch,
    #[error("bond record already exists for P_canonical_id")]
    RecordExists,
}

/// Verify JoinMarket bond-post semantics after wire decode and LMDB substrate read.
///
/// `record_exists` is `true` when `get_archival_bond_hybrid_pubkey` would succeed.
pub fn verify_join_market_bond_post(
    vin: &ArchivalBondPostVin,
    record_exists: bool,
) -> Result<(), BondPostError> {
    if vin.post_kind != BondPostKind::JoinMarket {
        return Err(BondPostError::PostKindNotJoinMarket);
    }

    match vin.holdings.kind {
        HoldingsKind::ShardSetCompact if vin.holdings.shard_ids.is_empty() => {
            return Err(BondPostError::ShardSetCompactEmpty);
        }
        HoldingsKind::CompleteTree if !vin.holdings.shard_ids.is_empty() => {
            return Err(BondPostError::CompleteTreeWithShardIds);
        }
        _ => {}
    }

    if vin.bond_credit > 0 && vin.bond_debit > 0 {
        return Err(BondPostError::BothTermsNonzero);
    }
    if vin.bond_debit != 0 {
        return Err(BondPostError::BondDebitNonzero);
    }

    let floor = bond_floor(&vin.holdings);
    if floor == 0 {
        return Err(BondPostError::BondFloorZero);
    }
    if vin.bonded_total_atomic != floor || vin.bond_credit != floor {
        return Err(BondPostError::FloorMismatch);
    }

    if record_exists {
        return Err(BondPostError::RecordExists);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bond_floor::ARCHIVAL_BOND_FLOOR_ATOMIC;
    use crate::bond_wire::{HoldingsDescriptor, HoldingsKind};

    fn valid_join_vin() -> ArchivalBondPostVin {
        ArchivalBondPostVin {
            hybrid_public_key: vec![0xAB; 64],
            p_canonical_id: [0x11; 32],
            post_kind: BondPostKind::JoinMarket,
            holdings: HoldingsDescriptor {
                kind: HoldingsKind::ShardSetCompact,
                shard_ids: vec![7, 42],
            },
            bonded_total_atomic: 2 * ARCHIVAL_BOND_FLOOR_ATOMIC,
            bond_credit: 2 * ARCHIVAL_BOND_FLOOR_ATOMIC,
            bond_debit: 0,
        }
    }

    #[test]
    fn accepts_valid_join_market() {
        assert!(verify_join_market_bond_post(&valid_join_vin(), false).is_ok());
    }

    #[test]
    fn rejects_non_join_post_kind() {
        let mut vin = valid_join_vin();
        vin.post_kind = BondPostKind::Rebond;
        assert_eq!(
            verify_join_market_bond_post(&vin, false),
            Err(BondPostError::PostKindNotJoinMarket)
        );
    }

    #[test]
    fn rejects_empty_shard_set() {
        let mut vin = valid_join_vin();
        vin.holdings.shard_ids.clear();
        assert_eq!(
            verify_join_market_bond_post(&vin, false),
            Err(BondPostError::ShardSetCompactEmpty)
        );
    }

    #[test]
    fn rejects_complete_tree_with_shards() {
        let mut vin = valid_join_vin();
        vin.holdings.kind = HoldingsKind::CompleteTree;
        vin.holdings.shard_ids = vec![1];
        vin.bonded_total_atomic = ARCHIVAL_BOND_FLOOR_ATOMIC;
        vin.bond_credit = ARCHIVAL_BOND_FLOOR_ATOMIC;
        assert_eq!(
            verify_join_market_bond_post(&vin, false),
            Err(BondPostError::CompleteTreeWithShardIds)
        );
    }

    #[test]
    fn rejects_bond_debit_nonzero() {
        let mut vin = valid_join_vin();
        vin.bond_credit = 0;
        vin.bonded_total_atomic = 0;
        vin.bond_debit = 1;
        assert_eq!(
            verify_join_market_bond_post(&vin, false),
            Err(BondPostError::BondDebitNonzero)
        );
    }

    #[test]
    fn rejects_both_terms_nonzero() {
        let mut vin = valid_join_vin();
        vin.bond_debit = ARCHIVAL_BOND_FLOOR_ATOMIC;
        assert_eq!(
            verify_join_market_bond_post(&vin, false),
            Err(BondPostError::BothTermsNonzero)
        );
    }

    #[test]
    fn rejects_floor_zero_via_empty_shards() {
        let mut vin = valid_join_vin();
        vin.holdings.shard_ids.clear();
        assert_eq!(
            verify_join_market_bond_post(&vin, false),
            Err(BondPostError::ShardSetCompactEmpty)
        );
    }

    #[test]
    fn rejects_credit_above_floor() {
        let mut vin = valid_join_vin();
        vin.bond_credit = 2 * ARCHIVAL_BOND_FLOOR_ATOMIC + 1;
        assert_eq!(
            verify_join_market_bond_post(&vin, false),
            Err(BondPostError::FloorMismatch)
        );
    }

    #[test]
    fn rejects_total_below_floor() {
        let mut vin = valid_join_vin();
        vin.bonded_total_atomic = 2 * ARCHIVAL_BOND_FLOOR_ATOMIC - 1;
        assert_eq!(
            verify_join_market_bond_post(&vin, false),
            Err(BondPostError::FloorMismatch)
        );
    }

    #[test]
    fn rejects_existing_record() {
        assert_eq!(
            verify_join_market_bond_post(&valid_join_vin(), true),
            Err(BondPostError::RecordExists)
        );
    }
}
