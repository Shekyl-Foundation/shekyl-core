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
    let vin = ArchivalBondPostVin::reinstate(
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
    // Consistent post-state but total != 0 ⇒ partial exit; there is no
    // in-place shrink kind. A smaller set is rotation (`Release` + `JoinMarket`).
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

// ── Reinstate (P2B-9) ────────────────────────────────────────────────────────

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
fn reinstate_record_shards() -> Vec<u64> {
    vec![7, 9]
}

fn reinstate_vin(post: Vec<u64>, credit: u64) -> ArchivalBondPostVin {
    let shard_ids = ShardSet::new(post).expect("reinstate fixture holdings are valid");
    let post_floor = shard_ids.len() as u64 * ARCHIVAL_BOND_FLOOR_ATOMIC;
    ArchivalBondPostVin::reinstate(
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

fn ok_reinstate(vin: &ArchivalBondPostVin) -> Result<(), BondPostError> {
    verify_reinstate_bond_post(
        vin,
        Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
        HoldingsKind::ShardSetCompact,
        &reinstate_record_shards(),
        &[open_interval(5)],
    )
}

#[test]
fn reinstate_accepts_standing_only_zero_credit() {
    // The common case: same set, credit 0 — pure reinstatement (Pin 2).
    assert!(ok_reinstate(&reinstate_vin(vec![7, 9], 0)).is_ok());
}

#[test]
fn reinstate_rejects_growth_and_terminal_reentry() {
    // Immutable-bond: putting shards back on this P is unrepresentable.
    assert_eq!(
        ok_reinstate(&reinstate_vin(
            vec![7, 9, 11, 13],
            2 * ARCHIVAL_BOND_FLOOR_ATOMIC
        )),
        Err(BondPostError::ReinstateHoldingsChanged)
    );
    // Terminal slash emptied the record: re-entry is JoinMarket, not Reinstate.
    assert_eq!(
        verify_reinstate_bond_post(
            &reinstate_vin(vec![7, 9], 2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
            Some(0),
            HoldingsKind::ShardSetCompact,
            &[],
            &[open_interval(5)],
        ),
        Err(BondPostError::ReinstateHoldingsChanged)
    );
}

#[test]
fn reinstate_rejects_wrong_post_kind() {
    let vin = valid_join_vin();
    assert_eq!(ok_reinstate(&vin), Err(BondPostError::PostKindNotReinstate));
}

#[test]
fn reinstate_rejects_missing_record() {
    assert_eq!(
        verify_reinstate_bond_post(
            &reinstate_vin(vec![7, 9], 0),
            None,
            HoldingsKind::ShardSetCompact,
            &reinstate_record_shards(),
            &[open_interval(5)],
        ),
        Err(BondPostError::RecordMissing)
    );
}

#[test]
fn reinstate_rejects_complete_tree_record_and_post() {
    assert_eq!(
        verify_reinstate_bond_post(
            &reinstate_vin(vec![7, 9], 0),
            Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
            HoldingsKind::CompleteTree,
            &[],
            &[open_interval(5)],
        ),
        Err(BondPostError::ReinstateOnCompleteTree)
    );
    let mut vin = reinstate_vin(vec![], 0);
    vin.holdings.kind = HoldingsKind::CompleteTree;
    assert_eq!(
        ok_reinstate(&vin),
        Err(BondPostError::ReinstatePostNotCompact)
    );
}

#[test]
fn reinstate_rejects_empty_post() {
    // A terminal-slash "standing-only" reinstate to ∅ would mint a zombie.
    assert_eq!(
        verify_reinstate_bond_post(
            &reinstate_vin(vec![], 0),
            Some(0),
            HoldingsKind::ShardSetCompact,
            &[],
            &[open_interval(5)],
        ),
        Err(BondPostError::ShardSetCompactEmpty)
    );
}

#[test]
fn reinstate_rejects_unslashed_record() {
    // No open interval: nothing to reinstate (Exited's zero-length clean
    // close is not open — good_through skips it).
    assert_eq!(
        verify_reinstate_bond_post(
            &reinstate_vin(vec![7, 9], 0),
            Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
            HoldingsKind::ShardSetCompact,
            &reinstate_record_shards(),
            &[closed_interval(5, 6), closed_interval(9, 9)],
        ),
        Err(BondPostError::ReinstateNotSlashed)
    );
}

#[test]
fn reinstate_rejects_multiple_open_intervals() {
    // Corruption of the Pin-5 coalescing invariant — reject at verify so a
    // verify-valid tx can never meet the connect fold's loud belt.
    assert_eq!(
        verify_reinstate_bond_post(
            &reinstate_vin(vec![7, 9], 0),
            Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
            HoldingsKind::ShardSetCompact,
            &reinstate_record_shards(),
            &[open_interval(5), open_interval(5)],
        ),
        Err(BondPostError::ReinstateMultipleOpenIntervals)
    );
}

#[test]
fn reinstate_rejects_interval_log_without_headroom() {
    // Pin 6: 254 is the last acceptable size (one slot for the next slash +
    // one for the Release clean close); 255 rejects.
    let mut log: Vec<BadInterval> = (0..254u64).map(|i| closed_interval(i, i + 1)).collect();
    log.push(open_interval(300));
    assert_eq!(log.len(), 255);
    assert_eq!(
        verify_reinstate_bond_post(
            &reinstate_vin(vec![7, 9], 0),
            Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
            HoldingsKind::ShardSetCompact,
            &reinstate_record_shards(),
            &log,
        ),
        Err(BondPostError::ReinstateIntervalLogHeadroom)
    );
    // At exactly 254 (253 closed + the open one) the same vin verifies.
    log.pop();
    log.pop();
    log.push(open_interval(300));
    assert_eq!(log.len(), 254);
    assert!(verify_reinstate_bond_post(
        &reinstate_vin(vec![7, 9], 0),
        Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
        HoldingsKind::ShardSetCompact,
        &reinstate_record_shards(),
        &log,
    )
    .is_ok());
}

#[test]
fn reinstate_rejects_swap_and_shed_respec() {
    // Swap, shed, and growth are the same refusal: holdings cannot change.
    assert_eq!(
        ok_reinstate(&reinstate_vin(vec![7, 13], 0)),
        Err(BondPostError::ReinstateHoldingsChanged)
    );
    assert_eq!(
        ok_reinstate(&reinstate_vin(vec![7], 0)),
        Err(BondPostError::ReinstateHoldingsChanged)
    );
    assert_eq!(
        ok_reinstate(&reinstate_vin(vec![7, 9, 11], 0)),
        Err(BondPostError::ReinstateHoldingsChanged)
    );
}

#[test]
fn reinstate_rejects_term_mismatches() {
    // Zero-money: debit, credit, and a drifted bonded_total all refuse.
    let mut vin = reinstate_vin(vec![7, 9], 0);
    vin.bond_debit = 1;
    assert_eq!(ok_reinstate(&vin), Err(BondPostError::ReinstateTerms));
    assert_eq!(
        ok_reinstate(&reinstate_vin(vec![7, 9], ARCHIVAL_BOND_FLOOR_ATOMIC)),
        Err(BondPostError::ReinstateTerms)
    );
    let mut vin = reinstate_vin(vec![7, 9], 0);
    vin.bonded_total_atomic += 1;
    assert_eq!(ok_reinstate(&vin), Err(BondPostError::ReinstateTerms));
    assert_eq!(
        verify_reinstate_bond_post(
            &reinstate_vin(vec![7, 9], 0),
            Some(3 * ARCHIVAL_BOND_FLOOR_ATOMIC),
            HoldingsKind::ShardSetCompact,
            &reinstate_record_shards(),
            &[open_interval(5)],
        ),
        Err(BondPostError::ReinstateRecordFloorBroken)
    );
}

#[test]
fn reinstate_rejects_record_floor_drift() {
    // Drifted record (1.5·FLOOR over two shards): terms would verify and
    // connect would FATAL; verify rejects so the chain does not halt.
    let drifted = ARCHIVAL_BOND_FLOOR_ATOMIC + ARCHIVAL_BOND_FLOOR_ATOMIC / 2;
    let vin = reinstate_vin(vec![7, 9], 2 * ARCHIVAL_BOND_FLOOR_ATOMIC - drifted);
    assert_eq!(
        verify_reinstate_bond_post(
            &vin,
            Some(drifted),
            HoldingsKind::ShardSetCompact,
            &reinstate_record_shards(),
            &[open_interval(5)],
        ),
        Err(BondPostError::ReinstateRecordFloorBroken)
    );
}
