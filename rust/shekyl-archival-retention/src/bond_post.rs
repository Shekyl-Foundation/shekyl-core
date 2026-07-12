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
use crate::release_cooldown::release_cooldown_elapsed;

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
    #[error("post_kind is not Unbond")]
    PostKindNotUnbond,
    #[error("Unbond requires an existing bond record")]
    RecordMissing,
    #[error("Unbond on a record with zero bonded total (nothing to unbond)")]
    NothingToUnbond,
    #[error("Unbond bond-post must not carry bond_credit")]
    UnbondCreditNonzero,
    #[error("Unbond full-exit holdings must be empty, not a floor-zero shard set")]
    UnbondHoldingsNotEmpty,
    #[error("post-connect bonded_total_atomic must equal bond_floor(holdings)")]
    UnbondFloorMismatch,
    #[error("Unbond is a full exit: post-connect bonded_total_atomic must be zero")]
    NotFullUnbond,
    #[error("Unbond bond_debit must equal the record's current bonded_total")]
    DebitNotFullBalance,
    #[error("Unbond release cooldown has not elapsed")]
    CooldownNotElapsed,
    #[error("record interval log is full; the connect's clean interval-close cannot append")]
    IntervalLogFull,
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

/// Verify `Unbond` bond-post semantics — a full record release (gate-4 §3.2/§3.4/
/// §3.5/§4.3; `PHASE_2B_FSM_RETOOL.md` P2B-8).
///
/// Marshaled facts from LMDB (C++ reads, Rust decides — same split as
/// [`verify_join_market_bond_post`]): `record_bonded_total` is `None` when no bond
/// record exists for `P_canonical_id`; `last_served_epoch` is the derived
/// whole-record release-cooldown anchor
/// ([`crate::release_cooldown::whole_record_last_served`] over the per-shard
/// reverse-cursor maxima), read at `current_settlement_epoch`.
///
/// The vin's `holdings` / `bonded_total_atomic` are the **post-connect** state
/// (gate-4 §3.5 debit-path note, ratified P2B-8): a full `Unbond` ends at empty
/// holdings, so `bonded_total_atomic == 0 == bond_floor(∅)`, and the debit removes
/// the whole current balance. The `bonded_total_atomic != 0` case is a partial
/// unbond and belongs on the `HoldingsUpdate`-drop path, not here.
///
/// `record_bad_interval_count` is the record's interval-log length; verify
/// rejects a log at [`MAX_BOND_BAD_INTERVALS`](crate::bond_connect::MAX_BOND_BAD_INTERVALS)
/// because the connect's clean interval-close could not append — a tx that
/// verifies but cannot connect would be a deterministic halt, so verify and
/// connect enforce the same bound.
pub fn verify_unbond_bond_post(
    vin: &ArchivalBondPostVin,
    record_bonded_total: Option<u64>,
    record_bad_interval_count: usize,
    last_served_epoch: Option<u64>,
    current_settlement_epoch: u64,
) -> Result<(), BondPostError> {
    if vin.post_kind != BondPostKind::Unbond {
        return Err(BondPostError::PostKindNotUnbond);
    }

    let Some(current_bonded) = record_bonded_total else {
        return Err(BondPostError::RecordMissing);
    };
    if current_bonded == 0 {
        return Err(BondPostError::NothingToUnbond);
    }

    if vin.bond_credit != 0 {
        return Err(BondPostError::UnbondCreditNonzero);
    }

    // Step-4 floor equality on the vin's post-connect state (§3.5 debit-path note).
    let floor = bond_floor(&vin.holdings);
    // A full Unbond ends at the canonical empty holdings, whose floor is 0. But
    // `bond_floor` also returns 0 for a structurally-invalid (oversize) shard set,
    // so a floor-0 descriptor that still carries shards is not an exit — reject it
    // rather than let it masquerade as empty. (Join rejects floor-0 outright as
    // `BondFloorZero`; Unbond cannot, because the empty end-state is legitimately
    // floor 0, so it guards the non-empty case explicitly.)
    if floor == 0 && !vin.holdings.shard_ids.is_empty() {
        return Err(BondPostError::UnbondHoldingsNotEmpty);
    }
    if vin.bonded_total_atomic != floor {
        return Err(BondPostError::UnbondFloorMismatch);
    }
    // Full exit: post-connect total is zero (⇒ empty holdings, by floor equality).
    if vin.bonded_total_atomic != 0 {
        return Err(BondPostError::NotFullUnbond);
    }

    // The debit removes the whole current balance (§3.2 table; §4.3 refund).
    if vin.bond_debit != current_bonded {
        return Err(BondPostError::DebitNotFullBalance);
    }

    // The connect must append the clean interval-close (§4.3 F3); a full log
    // (`bond_connect::MAX_BOND_BAD_INTERVALS`, the codec's `kMaxBadIntervals`
    // pin) makes the tx unconnectable, so it is unverifiable too.
    if record_bad_interval_count >= crate::bond_connect::MAX_BOND_BAD_INTERVALS {
        return Err(BondPostError::IntervalLogFull);
    }

    // Release cooldown: the grace window past the last served epoch must have
    // elapsed, so no pending challenge can still slash (gate-4 §4.3; the Gate-6
    // F-D3/F-D4 gate).
    if !release_cooldown_elapsed(last_served_epoch, current_settlement_epoch) {
        return Err(BondPostError::CooldownNotElapsed);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bond_floor::ARCHIVAL_BOND_FLOOR_ATOMIC;
    use crate::bond_wire::{HoldingsDescriptor, HoldingsKind, MAX_HOLDINGS_SHARDS};

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

    // ── Unbond ──────────────────────────────────────────────────────────────

    // `RELEASE_COOLDOWN_EPOCHS` is config-generated (genesis 2); the fixture reads
    // it so a re-pin re-derives the cooldown boundary.
    const UNBOND_LAST_SERVED: u64 = 100;
    const UNBOND_CURRENT: u64 = UNBOND_LAST_SERVED + crate::bond_floor::RELEASE_COOLDOWN_EPOCHS;
    const RECORD_BONDED: u64 = 2 * ARCHIVAL_BOND_FLOOR_ATOMIC;

    /// The post-connect state of a full exit: empty holdings, zero total.
    fn valid_unbond_vin() -> ArchivalBondPostVin {
        ArchivalBondPostVin {
            hybrid_public_key: vec![0xAB; 64],
            p_canonical_id: [0x11; 32],
            post_kind: BondPostKind::Unbond,
            holdings: HoldingsDescriptor {
                kind: HoldingsKind::ShardSetCompact,
                shard_ids: vec![],
            },
            bonded_total_atomic: 0,
            bond_credit: 0,
            bond_debit: RECORD_BONDED,
        }
    }

    fn ok_unbond(vin: &ArchivalBondPostVin) -> Result<(), BondPostError> {
        verify_unbond_bond_post(
            vin,
            Some(RECORD_BONDED),
            0,
            Some(UNBOND_LAST_SERVED),
            UNBOND_CURRENT,
        )
    }

    #[test]
    fn accepts_valid_full_unbond() {
        assert!(ok_unbond(&valid_unbond_vin()).is_ok());
    }

    #[test]
    fn accepts_unbond_when_never_served() {
        // No serve bit anywhere ⇒ no pending challenge ⇒ cooldown vacuously elapsed.
        assert!(
            verify_unbond_bond_post(&valid_unbond_vin(), Some(RECORD_BONDED), 0, None, 0).is_ok()
        );
    }

    #[test]
    fn rejects_full_interval_log() {
        // The connect's clean interval-close could not append (codec cap), so
        // verify refuses — a verified-but-unconnectable tx would be a halt.
        use crate::bond_connect::MAX_BOND_BAD_INTERVALS;
        assert_eq!(
            verify_unbond_bond_post(
                &valid_unbond_vin(),
                Some(RECORD_BONDED),
                MAX_BOND_BAD_INTERVALS,
                Some(UNBOND_LAST_SERVED),
                UNBOND_CURRENT,
            ),
            Err(BondPostError::IntervalLogFull)
        );
        assert!(verify_unbond_bond_post(
            &valid_unbond_vin(),
            Some(RECORD_BONDED),
            MAX_BOND_BAD_INTERVALS - 1,
            Some(UNBOND_LAST_SERVED),
            UNBOND_CURRENT,
        )
        .is_ok());
    }

    #[test]
    fn rejects_wrong_post_kind() {
        let mut vin = valid_unbond_vin();
        vin.post_kind = BondPostKind::JoinMarket;
        assert_eq!(ok_unbond(&vin), Err(BondPostError::PostKindNotUnbond));
    }

    #[test]
    fn rejects_missing_record() {
        assert_eq!(
            verify_unbond_bond_post(
                &valid_unbond_vin(),
                None,
                0,
                Some(UNBOND_LAST_SERVED),
                UNBOND_CURRENT
            ),
            Err(BondPostError::RecordMissing)
        );
    }

    #[test]
    fn rejects_nothing_to_unbond() {
        let mut vin = valid_unbond_vin();
        vin.bond_debit = 0;
        assert_eq!(
            verify_unbond_bond_post(&vin, Some(0), 0, Some(UNBOND_LAST_SERVED), UNBOND_CURRENT),
            Err(BondPostError::NothingToUnbond)
        );
    }

    #[test]
    fn rejects_credit_on_unbond() {
        let mut vin = valid_unbond_vin();
        vin.bond_credit = 1;
        assert_eq!(ok_unbond(&vin), Err(BondPostError::UnbondCreditNonzero));
    }

    #[test]
    fn rejects_floor_mismatch_nonempty_holdings() {
        // Non-empty holdings ⇒ bond_floor > 0, but bonded_total_atomic is 0.
        let mut vin = valid_unbond_vin();
        vin.holdings.shard_ids = vec![7];
        assert_eq!(ok_unbond(&vin), Err(BondPostError::UnbondFloorMismatch));
    }

    #[test]
    fn rejects_oversize_shard_set_masquerading_as_empty() {
        // `bond_floor` returns 0 for an oversize shard set just as it does for the
        // empty full-exit holdings, so a floor-0 descriptor that still carries shards
        // must not pass the full-exit checks. Reachable via the FFI, which marshals
        // shard ids without re-running the wire decoder's MAX_HOLDINGS_SHARDS bound.
        let mut vin = valid_unbond_vin();
        vin.holdings.shard_ids = vec![0u64; MAX_HOLDINGS_SHARDS + 1];
        assert_eq!(bond_floor(&vin.holdings), 0);
        assert_eq!(ok_unbond(&vin), Err(BondPostError::UnbondHoldingsNotEmpty));
    }

    #[test]
    fn rejects_partial_unbond_nonzero_post_total() {
        // Consistent post-state but total != 0 ⇒ partial exit; belongs on the
        // HoldingsUpdate-drop path, not Unbond.
        let mut vin = valid_unbond_vin();
        vin.holdings.shard_ids = vec![7];
        vin.bonded_total_atomic = ARCHIVAL_BOND_FLOOR_ATOMIC;
        assert_eq!(ok_unbond(&vin), Err(BondPostError::NotFullUnbond));
    }

    #[test]
    fn rejects_debit_not_full_balance() {
        // The debit must remove the record's whole current bonded_total.
        let mut vin = valid_unbond_vin();
        vin.bond_debit = ARCHIVAL_BOND_FLOOR_ATOMIC; // record holds RECORD_BONDED = 2*FLOOR
        assert_eq!(ok_unbond(&vin), Err(BondPostError::DebitNotFullBalance));
    }

    #[test]
    fn rejects_cooldown_not_elapsed() {
        // One epoch before the boundary: pending challenge could still slash.
        assert_eq!(
            verify_unbond_bond_post(
                &valid_unbond_vin(),
                Some(RECORD_BONDED),
                0,
                Some(UNBOND_LAST_SERVED),
                UNBOND_CURRENT - 1,
            ),
            Err(BondPostError::CooldownNotElapsed)
        );
    }
}
