// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for bond-post verify (`bond_post.rs`).

use super::*;
use crate::bond_floor::ARCHIVAL_BOND_FLOOR_ATOMIC;
use crate::bond_wire::{HoldingsDescriptor, HoldingsKind, ShardSet, ENDPOINT_BYTES};

fn valid_join_vin() -> ArchivalBondPostVin {
    ArchivalBondPostVin::join_market(
        vec![0xAB; 64],
        [0x11; 32],
        vec![0xE5; 64],
        [0xEE; ENDPOINT_BYTES],
        HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::new(vec![7, 42]).unwrap(),
        },
        2 * ARCHIVAL_BOND_FLOOR_ATOMIC,
        2 * ARCHIVAL_BOND_FLOOR_ATOMIC,
    )
}

#[test]
fn accepts_valid_join_market() {
    assert!(verify_join_market_bond_post(&valid_join_vin(), false).is_ok());
}

#[test]
fn rejects_all_zero_endpoint() {
    let mut vin = valid_join_vin();
    vin.set_endpoint([0u8; ENDPOINT_BYTES]);
    assert_eq!(
        verify_join_market_bond_post(&vin, false),
        Err(BondPostError::EndpointZero)
    );
    let mut ep = [0u8; ENDPOINT_BYTES];
    ep[ENDPOINT_BYTES - 1] = 1;
    vin.set_endpoint(ep);
    assert!(verify_join_market_bond_post(&vin, false).is_ok());
}

#[test]
fn rejects_non_join_post_kind() {
    let vin = ArchivalBondPostVin::rebond(
        vec![0xAB; 64],
        [0x11; 32],
        HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::new(vec![7, 42]).unwrap(),
        },
        2 * ARCHIVAL_BOND_FLOOR_ATOMIC,
        2 * ARCHIVAL_BOND_FLOOR_ATOMIC,
        0,
    );
    assert_eq!(
        verify_join_market_bond_post(&vin, false),
        Err(BondPostError::PostKindNotJoinMarket)
    );
}

#[test]
fn rejects_empty_shard_set() {
    let mut vin = valid_join_vin();
    vin.holdings.shard_ids = ShardSet::empty();
    assert_eq!(
        verify_join_market_bond_post(&vin, false),
        Err(BondPostError::ShardSetCompactEmpty)
    );
}

#[test]
fn rejects_complete_tree_with_shards() {
    let mut vin = valid_join_vin();
    vin.holdings.kind = HoldingsKind::CompleteTree;
    vin.holdings.shard_ids = ShardSet::new(vec![1]).unwrap();
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
    vin.holdings.shard_ids = ShardSet::empty();
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

// ── Release ──────────────────────────────────────────────────────────────

// `RELEASE_COOLDOWN_EPOCHS` is config-generated (genesis 2); the fixture reads
// it so a re-pin re-derives the cooldown boundary.
const RELEASE_LAST_SERVED: u64 = 100;
const RELEASE_CURRENT: u64 = RELEASE_LAST_SERVED + crate::bond_floor::RELEASE_COOLDOWN_EPOCHS;
// The scheduler watermark has reached the anchor: epochs ≤ last-served settled.
const RELEASE_SETTLED: Option<u64> = Some(RELEASE_LAST_SERVED);
const RECORD_BONDED: u64 = 2 * ARCHIVAL_BOND_FLOOR_ATOMIC;

/// The post-connect state of a full exit: empty holdings, zero total.
fn valid_release_vin() -> ArchivalBondPostVin {
    ArchivalBondPostVin::release(
        vec![0xAB; 64],
        [0x11; 32],
        HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::empty(),
        },
        0,
        0,
        RECORD_BONDED,
    )
}

fn ok_release(vin: &ArchivalBondPostVin) -> Result<(), BondPostError> {
    verify_release_bond_post(
        vin,
        Some(RECORD_BONDED),
        0,
        Some(RELEASE_LAST_SERVED),
        RELEASE_SETTLED,
        RELEASE_CURRENT,
    )
}

#[test]
fn accepts_valid_full_release() {
    assert!(ok_release(&valid_release_vin()).is_ok());
}

#[test]
fn accepts_release_when_never_served() {
    // No serve bit anywhere ⇒ no anchor: every held-but-unserved epoch either
    // already settled (slashed while bonded) or falls in the exit-forgiven
    // tail, with or without a scheduler watermark.
    assert!(
        verify_release_bond_post(&valid_release_vin(), Some(RECORD_BONDED), 0, None, None, 0)
            .is_ok()
    );
}

#[test]
fn rejects_slash_settlement_pending() {
    // The one-block race (release_cooldown module docs): cooldown elapsed by
    // epoch distance, but the scheduler watermark has not reached the anchor —
    // the anchor epoch's deadline block has not folded yet.
    for watermark in [Some(RELEASE_LAST_SERVED - 1), None] {
        assert_eq!(
            verify_release_bond_post(
                &valid_release_vin(),
                Some(RECORD_BONDED),
                0,
                Some(RELEASE_LAST_SERVED),
                watermark,
                RELEASE_CURRENT,
            ),
            Err(BondPostError::SlashSettlementPending)
        );
    }
    // Watermark past the anchor also accepts.
    assert!(verify_release_bond_post(
        &valid_release_vin(),
        Some(RECORD_BONDED),
        0,
        Some(RELEASE_LAST_SERVED),
        Some(RELEASE_LAST_SERVED + 5),
        RELEASE_CURRENT,
    )
    .is_ok());
}

#[test]
fn rejects_full_interval_log() {
    // The connect's clean interval-close could not append (codec cap), so
    // verify refuses — a verified-but-unconnectable tx would be a halt.
    use crate::bond_connect::MAX_BOND_BAD_INTERVALS;
    assert_eq!(
        verify_release_bond_post(
            &valid_release_vin(),
            Some(RECORD_BONDED),
            MAX_BOND_BAD_INTERVALS,
            Some(RELEASE_LAST_SERVED),
            RELEASE_SETTLED,
            RELEASE_CURRENT,
        ),
        Err(BondPostError::IntervalLogFull)
    );
    assert!(verify_release_bond_post(
        &valid_release_vin(),
        Some(RECORD_BONDED),
        MAX_BOND_BAD_INTERVALS - 1,
        Some(RELEASE_LAST_SERVED),
        RELEASE_SETTLED,
        RELEASE_CURRENT,
    )
    .is_ok());
}

#[test]
fn rejects_wrong_post_kind() {
    let vin = valid_join_vin();
    assert_eq!(ok_release(&vin), Err(BondPostError::PostKindNotRelease));
}

#[test]
fn rejects_missing_record() {
    assert_eq!(
        verify_release_bond_post(
            &valid_release_vin(),
            None,
            0,
            Some(RELEASE_LAST_SERVED),
            RELEASE_SETTLED,
            RELEASE_CURRENT
        ),
        Err(BondPostError::RecordMissing)
    );
}

#[test]
fn rejects_nothing_to_release() {
    let mut vin = valid_release_vin();
    vin.bond_debit = 0;
    assert_eq!(
        verify_release_bond_post(
            &vin,
            Some(0),
            0,
            Some(RELEASE_LAST_SERVED),
            RELEASE_SETTLED,
            RELEASE_CURRENT
        ),
        Err(BondPostError::NothingToRelease)
    );
}

#[test]
fn rejects_credit_on_release() {
    let mut vin = valid_release_vin();
    vin.bond_credit = 1;
    assert_eq!(ok_release(&vin), Err(BondPostError::ReleaseCreditNonzero));
}

#[test]
fn rejects_floor_mismatch_nonempty_holdings() {
    // Non-empty holdings ⇒ bond_floor > 0, but bonded_total_atomic is 0.
    let mut vin = valid_release_vin();
    vin.holdings.shard_ids = ShardSet::new(vec![7]).unwrap();
    assert_eq!(ok_release(&vin), Err(BondPostError::ReleaseFloorMismatch));
}

// (The former `rejects_oversize_shard_set_masquerading_as_empty` test is
// retired: an oversize holdings is now unrepresentable — `ShardSet::new`
// rejects it at the decode/marshal boundary before any verify runs. The
// type-level rejection and byte-identity are covered by the `ShardSet` tests
// in `bond_wire`; the FFI marshal boundary keeps its own oversize test.)

#[test]
fn rejects_partial_release_nonzero_post_total() {
    // Consistent post-state but total != 0 ⇒ partial exit; belongs on the
    // HoldingsUpdate-drop path, not Release.
    let mut vin = valid_release_vin();
    vin.holdings.shard_ids = ShardSet::new(vec![7]).unwrap();
    vin.bonded_total_atomic = ARCHIVAL_BOND_FLOOR_ATOMIC;
    assert_eq!(ok_release(&vin), Err(BondPostError::NotFullRelease));
}

#[test]
fn rejects_debit_not_full_balance() {
    // The debit must remove the record's whole current bonded_total.
    let mut vin = valid_release_vin();
    vin.bond_debit = ARCHIVAL_BOND_FLOOR_ATOMIC; // record holds RECORD_BONDED = 2*FLOOR
    assert_eq!(ok_release(&vin), Err(BondPostError::DebitNotFullBalance));
}

#[test]
fn block_unique_rejects_every_same_p_pair() {
    let a = [0x11u8; 32];
    let b = [0x22u8; 32];
    assert!(bond_post_block_unique(&[]));
    assert!(bond_post_block_unique(&[a]));
    assert!(bond_post_block_unique(&[a, b]));
    // Any same-P pair rejects, regardless of post kinds (the pass is
    // keyed on P alone) or position in the block.
    assert!(!bond_post_block_unique(&[a, a]));
    assert!(!bond_post_block_unique(&[a, b, a]));
}

#[test]
fn rejects_cooldown_not_elapsed() {
    // One epoch before the boundary: pending challenge could still slash.
    assert_eq!(
        verify_release_bond_post(
            &valid_release_vin(),
            Some(RECORD_BONDED),
            0,
            Some(RELEASE_LAST_SERVED),
            RELEASE_SETTLED,
            RELEASE_CURRENT - 1,
        ),
        Err(BondPostError::CooldownNotElapsed)
    );
}

// ── HoldingsUpdate: the single-shard diff ────────────────────────────────

#[test]
fn single_shard_diff_classifies_add_drop_and_rejects_others() {
    assert!(matches!(
        single_shard_diff(&[7, 9], &[7, 9, 11]),
        SingleDiff::Added(11)
    ));
    assert!(matches!(
        single_shard_diff(&[7, 9, 11], &[7, 9]),
        SingleDiff::Removed(11)
    ));
    // Order-agnostic (holdings is a set): same set, no change.
    assert!(matches!(
        single_shard_diff(&[9, 7], &[7, 9]),
        SingleDiff::NotSingle
    ));
    // Two-shard change, a swap, and a duplicate in post all reject.
    assert!(matches!(
        single_shard_diff(&[7], &[7, 9, 11]),
        SingleDiff::NotSingle
    ));
    assert!(matches!(
        single_shard_diff(&[7, 9], &[7, 11]),
        SingleDiff::NotSingle
    ));
    assert!(matches!(
        single_shard_diff(&[7], &[7, 7]),
        SingleDiff::NotSingle
    ));
}

// ── HoldingsUpdate-add verify ────────────────────────────────────────────

const HU_JOIN: u64 = 3;
const HU_CURRENT: u64 = 20;
fn hu_current_shards() -> Vec<u64> {
    vec![7, 9]
}

fn valid_add_vin() -> ArchivalBondPostVin {
    ArchivalBondPostVin::holdings_update(
        vec![0xAB; 64],
        [0x11; 32],
        HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::new(vec![7, 9, 11]).unwrap(), // current + one new shard
        },
        3 * ARCHIVAL_BOND_FLOOR_ATOMIC,
        ARCHIVAL_BOND_FLOOR_ATOMIC,
        0,
    )
}

fn ok_add(vin: &ArchivalBondPostVin) -> Result<(), BondPostError> {
    verify_holdings_update_add(
        vin,
        Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
        HoldingsKind::ShardSetCompact,
        &hu_current_shards(),
        HU_JOIN,
        &[],
        HU_CURRENT,
    )
}

#[test]
fn accepts_valid_add() {
    assert!(ok_add(&valid_add_vin()).is_ok());
}

#[test]
fn add_rejects_wrong_post_kind() {
    let vin = valid_join_vin();
    assert_eq!(ok_add(&vin), Err(BondPostError::PostKindNotHoldingsUpdate));
}

#[test]
fn add_rejects_missing_record() {
    assert_eq!(
        verify_holdings_update_add(
            &valid_add_vin(),
            None,
            HoldingsKind::ShardSetCompact,
            &hu_current_shards(),
            HU_JOIN,
            &[],
            HU_CURRENT,
        ),
        Err(BondPostError::RecordMissing)
    );
}

#[test]
fn add_rejects_complete_tree_record() {
    assert_eq!(
        verify_holdings_update_add(
            &valid_add_vin(),
            Some(ARCHIVAL_BOND_FLOOR_ATOMIC),
            HoldingsKind::CompleteTree,
            &[],
            HU_JOIN,
            &[],
            HU_CURRENT,
        ),
        Err(BondPostError::HoldingsUpdateOnCompleteTree)
    );
}

#[test]
fn add_rejects_exited_record_resurrection() {
    // The Exited shape (post-Release): zero total, empty holdings, and a
    // zero-length clean interval-close that good_through excludes nothing
    // for. Without the Bonded gate this passed EVERY add gate — a
    // JoinMarket-bypassing re-entry path whose connect then threw on the
    // empty-pre-image journal encode (verify-valid but unconnectable on
    // every node: a chain-stall vector). P2B-7 Pin 1: Bonded → Bonded.
    let mut vin = valid_add_vin();
    vin.holdings.shard_ids = ShardSet::new(vec![11]).unwrap();
    vin.bonded_total_atomic = ARCHIVAL_BOND_FLOOR_ATOMIC;
    vin.bond_credit = ARCHIVAL_BOND_FLOOR_ATOMIC;
    assert_eq!(
        verify_holdings_update_add(
            &vin,
            Some(0), // Exited: nothing bonded
            HoldingsKind::ShardSetCompact,
            &[], // Exited: no held shards
            HU_JOIN,
            &[],
            HU_CURRENT,
        ),
        Err(BondPostError::HoldingsUpdateRecordNotBonded)
    );
}

#[test]
fn add_rejects_open_bad_interval() {
    // An open bad interval (post-slash, pre-Rebond) is not good standing.
    let open = crate::consensus_state::BadInterval {
        start_epoch: 10,
        end_exclusive: u64::MAX,
    };
    assert_eq!(
        verify_holdings_update_add(
            &valid_add_vin(),
            Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
            HoldingsKind::ShardSetCompact,
            &hu_current_shards(),
            HU_JOIN,
            &[open],
            HU_CURRENT,
        ),
        Err(BondPostError::HoldingsUpdateNotGoodStanding)
    );
}

#[test]
fn add_rejects_wrong_terms() {
    let mut vin = valid_add_vin();
    vin.bond_credit = 2 * ARCHIVAL_BOND_FLOOR_ATOMIC; // must be exactly one FLOOR
    assert_eq!(ok_add(&vin), Err(BondPostError::HoldingsUpdateAddTerms));
    let mut vin = valid_add_vin();
    vin.bond_debit = 1; // credit path must carry no debit
    assert_eq!(ok_add(&vin), Err(BondPostError::HoldingsUpdateAddTerms));
}

#[test]
fn add_rejects_not_single_add() {
    // Post adds two shards.
    let mut vin = valid_add_vin();
    vin.holdings.shard_ids = ShardSet::new(vec![7, 9, 11, 13]).unwrap();
    vin.bonded_total_atomic = 4 * ARCHIVAL_BOND_FLOOR_ATOMIC;
    assert_eq!(ok_add(&vin), Err(BondPostError::HoldingsUpdateNotSingleAdd));
}

#[test]
fn add_rejects_floor_mismatch() {
    let mut vin = valid_add_vin();
    vin.bonded_total_atomic = 4 * ARCHIVAL_BOND_FLOOR_ATOMIC; // != |post|·FLOOR
    assert_eq!(
        ok_add(&vin),
        Err(BondPostError::HoldingsUpdateAddFloorMismatch)
    );
}

// ── HoldingsUpdate-drop verify ───────────────────────────────────────────

// A shard old enough to drop: added at epoch 0 (genesis band, freeze 0 ⇒ age
// max ⇒ bond_duration 20), tenure = current − 0 must reach 20.
const DROP_ADD_EPOCH: u64 = 0;
const DROP_FREEZE: u64 = 0;
const DROP_LAST_SERVED: u64 = 5;
const DROP_CURRENT: u64 = 40; // tenure 40 ≥ horizon 20; cooldown/settle satisfied

fn valid_drop_vin() -> ArchivalBondPostVin {
    ArchivalBondPostVin::holdings_update(
        vec![0xAB; 64],
        [0x11; 32],
        HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::new(vec![7]).unwrap(), // current {7, 11} minus 11
        },
        ARCHIVAL_BOND_FLOOR_ATOMIC,
        0,
        ARCHIVAL_BOND_FLOOR_ATOMIC,
    )
}

#[allow(clippy::too_many_arguments)]
fn ok_drop(vin: &ArchivalBondPostVin) -> Result<(), BondPostError> {
    verify_holdings_update_drop(
        vin,
        Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
        HoldingsKind::ShardSetCompact,
        &[7, 11],
        11,
        DROP_ADD_EPOCH,
        DROP_FREEZE,
        Some(DROP_LAST_SERVED),
        Some(DROP_CURRENT),
        DROP_CURRENT,
    )
}

#[test]
fn accepts_valid_drop() {
    assert!(ok_drop(&valid_drop_vin()).is_ok());
}

#[test]
fn drop_rejects_released_record() {
    // The add arm's Bonded-gate twin (shared prologue): a zero-total /
    // no-shards record refuses before any diff or term arithmetic runs.
    assert_eq!(
        verify_holdings_update_drop(
            &valid_drop_vin(),
            Some(0),
            HoldingsKind::ShardSetCompact,
            &[],
            11,
            DROP_ADD_EPOCH,
            DROP_FREEZE,
            Some(DROP_LAST_SERVED),
            Some(DROP_CURRENT),
            DROP_CURRENT,
        ),
        Err(BondPostError::HoldingsUpdateRecordNotBonded)
    );
}

#[test]
fn drop_rejects_wrong_terms() {
    let mut vin = valid_drop_vin();
    vin.bond_debit = 2 * ARCHIVAL_BOND_FLOOR_ATOMIC;
    assert_eq!(ok_drop(&vin), Err(BondPostError::HoldingsUpdateDropTerms));
}

#[test]
fn drop_rejects_not_single_or_wrong_shard() {
    // The vin drops a shard, but C++ passed a different dropped_shard_id.
    let vin = valid_drop_vin();
    assert_eq!(
        verify_holdings_update_drop(
            &vin,
            Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
            HoldingsKind::ShardSetCompact,
            &[7, 11],
            7, // wrong: the diff removed 11, not 7
            DROP_ADD_EPOCH,
            DROP_FREEZE,
            Some(DROP_LAST_SERVED),
            Some(DROP_CURRENT),
            DROP_CURRENT,
        ),
        Err(BondPostError::HoldingsUpdateNotSingleDrop)
    );
}

#[test]
fn drop_rejects_last_shard() {
    // Dropping the only shard: post empty → use Release.
    let mut vin = valid_drop_vin();
    vin.holdings.shard_ids = ShardSet::empty();
    vin.bonded_total_atomic = 0;
    assert_eq!(
        verify_holdings_update_drop(
            &vin,
            Some(ARCHIVAL_BOND_FLOOR_ATOMIC),
            HoldingsKind::ShardSetCompact,
            &[11],
            11,
            DROP_ADD_EPOCH,
            DROP_FREEZE,
            Some(DROP_LAST_SERVED),
            Some(DROP_CURRENT),
            DROP_CURRENT,
        ),
        Err(BondPostError::HoldingsUpdateDropLastShard)
    );
}

#[test]
fn drop_rejects_within_horizon() {
    // Same shard, but current epoch is only 10 past add — horizon for a
    // genesis-band shard is 20, so tenure 10 < 20.
    assert_eq!(
        verify_holdings_update_drop(
            &valid_drop_vin(),
            Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
            HoldingsKind::ShardSetCompact,
            &[7, 11],
            11,
            DROP_ADD_EPOCH,
            DROP_FREEZE,
            Some(DROP_LAST_SERVED),
            Some(10),
            10,
        ),
        Err(BondPostError::HoldingsUpdateDropWithinHorizon)
    );
}

#[test]
fn drop_rejects_cooldown_not_elapsed() {
    // Last-served at current − 1: the release cooldown (2 epochs) has not passed.
    let near = DROP_CURRENT;
    assert_eq!(
        verify_holdings_update_drop(
            &valid_drop_vin(),
            Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
            HoldingsKind::ShardSetCompact,
            &[7, 11],
            11,
            DROP_ADD_EPOCH,
            DROP_FREEZE,
            Some(near),
            Some(near),
            near,
        ),
        Err(BondPostError::CooldownNotElapsed)
    );
}

#[test]
fn drop_rejects_slash_settlement_pending() {
    // Cooldown elapsed, but the slash scheduler has not settled through the
    // dropped shard's last-served anchor.
    assert_eq!(
        verify_holdings_update_drop(
            &valid_drop_vin(),
            Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
            HoldingsKind::ShardSetCompact,
            &[7, 11],
            11,
            DROP_ADD_EPOCH,
            DROP_FREEZE,
            Some(DROP_LAST_SERVED),
            Some(DROP_LAST_SERVED - 1), // watermark below the anchor
            DROP_CURRENT,
        ),
        Err(BondPostError::SlashSettlementPending)
    );
}

// ── Rebond (P2B-9) ────────────────────────────────────────────────────────

use crate::consensus_state::BadInterval;

fn open_interval(start: u64) -> BadInterval {
    BadInterval {
        start_epoch: start,
        end_exclusive: u64::MAX,
    }
}

fn closed_interval(start: u64, end: u64) -> BadInterval {
    BadInterval {
        start_epoch: start,
        end_exclusive: end,
    }
}

/// Partial-slash record: held {7, 9} (shard 11 was slashed away), one open
/// interval, floor-consistent balance.
fn rebond_record_shards() -> Vec<u64> {
    vec![7, 9]
}

fn rebond_vin(post: Vec<u64>, credit: u64) -> ArchivalBondPostVin {
    let shard_ids = ShardSet::new(post).expect("rebond fixture holdings are valid");
    let post_floor = shard_ids.len() as u64 * ARCHIVAL_BOND_FLOOR_ATOMIC;
    ArchivalBondPostVin::rebond(
        vec![0xAB; 64],
        [0x11; 32],
        HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids,
        },
        post_floor,
        credit,
        0,
    )
}

fn ok_rebond(vin: &ArchivalBondPostVin) -> Result<(), BondPostError> {
    verify_rebond_bond_post(
        vin,
        Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
        HoldingsKind::ShardSetCompact,
        &rebond_record_shards(),
        &[open_interval(5)],
    )
}

#[test]
fn rebond_accepts_standing_only_zero_credit() {
    // The common case: same set, credit 0 — pure reinstatement (Pin 2).
    assert!(ok_rebond(&rebond_vin(vec![7, 9], 0)).is_ok());
}

#[test]
fn rebond_accepts_growth_with_matching_credit() {
    // Re-acquire the slashed shard + one new: credit = 2·FLOOR.
    assert!(ok_rebond(&rebond_vin(
        vec![7, 9, 11, 13],
        2 * ARCHIVAL_BOND_FLOOR_ATOMIC
    ))
    .is_ok());
}

#[test]
fn rebond_accepts_terminal_slash_full_refund() {
    // Terminal: bonded 0, empty holdings, open interval — full floor credit.
    assert!(verify_rebond_bond_post(
        &rebond_vin(vec![7, 9], 2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
        Some(0),
        HoldingsKind::ShardSetCompact,
        &[],
        &[open_interval(5)],
    )
    .is_ok());
}

#[test]
fn rebond_rejects_wrong_post_kind() {
    let vin = valid_add_vin();
    assert_eq!(ok_rebond(&vin), Err(BondPostError::PostKindNotRebond));
}

#[test]
fn rebond_rejects_missing_record() {
    assert_eq!(
        verify_rebond_bond_post(
            &rebond_vin(vec![7, 9], 0),
            None,
            HoldingsKind::ShardSetCompact,
            &rebond_record_shards(),
            &[open_interval(5)],
        ),
        Err(BondPostError::RecordMissing)
    );
}

#[test]
fn rebond_rejects_complete_tree_record_and_post() {
    assert_eq!(
        verify_rebond_bond_post(
            &rebond_vin(vec![7, 9], 0),
            Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
            HoldingsKind::CompleteTree,
            &[],
            &[open_interval(5)],
        ),
        Err(BondPostError::RebondOnCompleteTree)
    );
    let mut vin = rebond_vin(vec![], 0);
    vin.holdings.kind = HoldingsKind::CompleteTree;
    assert_eq!(ok_rebond(&vin), Err(BondPostError::RebondPostNotCompact));
}

#[test]
fn rebond_rejects_empty_post() {
    // A terminal-slash "standing-only" rebond to ∅ would mint a zombie.
    assert_eq!(
        verify_rebond_bond_post(
            &rebond_vin(vec![], 0),
            Some(0),
            HoldingsKind::ShardSetCompact,
            &[],
            &[open_interval(5)],
        ),
        Err(BondPostError::ShardSetCompactEmpty)
    );
}

#[test]
fn rebond_rejects_unslashed_record() {
    // No open interval: nothing to reinstate (Exited's zero-length clean
    // close is not open — good_through skips it).
    assert_eq!(
        verify_rebond_bond_post(
            &rebond_vin(vec![7, 9], 0),
            Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
            HoldingsKind::ShardSetCompact,
            &rebond_record_shards(),
            &[closed_interval(5, 6), closed_interval(9, 9)],
        ),
        Err(BondPostError::RebondNotSlashed)
    );
}

#[test]
fn rebond_rejects_multiple_open_intervals() {
    // Corruption of the Pin-5 coalescing invariant — reject at verify so a
    // verify-valid tx can never meet the connect fold's loud belt.
    assert_eq!(
        verify_rebond_bond_post(
            &rebond_vin(vec![7, 9], 0),
            Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
            HoldingsKind::ShardSetCompact,
            &rebond_record_shards(),
            &[open_interval(5), open_interval(5)],
        ),
        Err(BondPostError::RebondMultipleOpenIntervals)
    );
}

#[test]
fn rebond_rejects_interval_log_without_headroom() {
    // Pin 6: 254 is the last acceptable size (one slot for the next slash +
    // one for the Release clean close); 255 rejects.
    let mut log: Vec<BadInterval> = (0..254u64).map(|i| closed_interval(i, i + 1)).collect();
    log.push(open_interval(300));
    assert_eq!(log.len(), 255);
    assert_eq!(
        verify_rebond_bond_post(
            &rebond_vin(vec![7, 9], 0),
            Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
            HoldingsKind::ShardSetCompact,
            &rebond_record_shards(),
            &log,
        ),
        Err(BondPostError::RebondIntervalLogHeadroom)
    );
    // At exactly 254 (253 closed + the open one) the same vin verifies.
    log.pop();
    log.pop();
    log.push(open_interval(300));
    assert_eq!(log.len(), 254);
    assert!(verify_rebond_bond_post(
        &rebond_vin(vec![7, 9], 0),
        Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
        HoldingsKind::ShardSetCompact,
        &rebond_record_shards(),
        &log,
    )
    .is_ok());
}

#[test]
fn rebond_rejects_swap_and_shed_respec() {
    // The swap-shed dodge (Pin 1): drop a carried shard, add a different one
    // — same floor, credit 0 — must NOT pass as reinstatement.
    assert_eq!(
        ok_rebond(&rebond_vin(vec![7, 13], 0)),
        Err(BondPostError::RebondNotSuperset)
    );
    // A plain shed (subset) is arithmetically a shrink and also not a superset.
    assert_eq!(
        ok_rebond(&rebond_vin(vec![7], 0)),
        Err(BondPostError::RebondNotSuperset)
    );
    // (A duplicate post — `vec![7, 9, 9]` — is no longer reachable here: it
    // cannot be constructed into a `ShardSet`, so the "not a set" case is a
    // `ShardSet::new` rejection, tested in `bond_wire`.)
}

#[test]
fn rebond_rejects_term_mismatches() {
    // Debit is never carried on a credit path.
    let mut vin = rebond_vin(vec![7, 9], 0);
    vin.bond_debit = 1;
    assert_eq!(ok_rebond(&vin), Err(BondPostError::RebondTerms));
    // Credit must equal floor(post) − bonded: growth without credit…
    assert_eq!(
        ok_rebond(&rebond_vin(vec![7, 9, 11], 0)),
        Err(BondPostError::RebondTerms)
    );
    // …and credit on a standing-only re-spec.
    assert_eq!(
        ok_rebond(&rebond_vin(vec![7, 9], ARCHIVAL_BOND_FLOOR_ATOMIC)),
        Err(BondPostError::RebondTerms)
    );
    // Post bonded_total must equal bond_floor(post).
    let mut vin = rebond_vin(vec![7, 9], 0);
    vin.bonded_total_atomic += 1;
    assert_eq!(ok_rebond(&vin), Err(BondPostError::RebondTerms));
    // A record whose bonded exceeds floor(record holdings) is corruption —
    // the explicit floor-invariant check names it (an honest shrink is
    // unrepresentable under the superset anyway).
    assert_eq!(
        verify_rebond_bond_post(
            &rebond_vin(vec![7, 9], 0),
            Some(3 * ARCHIVAL_BOND_FLOOR_ATOMIC),
            HoldingsKind::ShardSetCompact,
            &rebond_record_shards(),
            &[open_interval(5)],
        ),
        Err(BondPostError::RebondRecordFloorBroken)
    );
}

#[test]
fn rebond_rejects_record_floor_drift() {
    // Drifted record (1.5·FLOOR over two shards): terms would verify and
    // connect would FATAL; verify rejects so the chain does not halt.
    let drifted = ARCHIVAL_BOND_FLOOR_ATOMIC + ARCHIVAL_BOND_FLOOR_ATOMIC / 2;
    let vin = rebond_vin(vec![7, 9], 2 * ARCHIVAL_BOND_FLOOR_ATOMIC - drifted);
    assert_eq!(
        verify_rebond_bond_post(
            &vin,
            Some(drifted),
            HoldingsKind::ShardSetCompact,
            &rebond_record_shards(),
            &[open_interval(5)],
        ),
        Err(BondPostError::RebondRecordFloorBroken)
    );
}
