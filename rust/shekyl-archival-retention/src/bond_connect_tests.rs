// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for bond-post connect/pop (`bond_connect.rs`).

use super::*;
use crate::bond_floor::{bond_floor, ARCHIVAL_BOND_FLOOR_ATOMIC};
use crate::consensus_state::good_through;

const E_UNBOND: u64 = 42;
const RECORD_BONDED: u64 = 2 * ARCHIVAL_BOND_FLOOR_ATOMIC;
const TOTAL_BONDED: u64 = 5 * ARCHIVAL_BOND_FLOOR_ATOMIC;

fn record_holdings() -> HoldingsDescriptor {
    HoldingsDescriptor {
        kind: HoldingsKind::ShardSetCompact,
        shard_ids: ShardSet::new(vec![7, 42]).unwrap(),
    }
}

fn ok_connect() -> UnbondConnect {
    let holdings = record_holdings();
    unbond_connect(
        RECORD_BONDED,
        holdings.kind,
        holdings.shard_ids.len(),
        0,
        RECORD_BONDED,
        TOTAL_BONDED,
        E_UNBOND,
    )
    .expect("valid connect")
}

#[test]
fn connect_full_release_effect() {
    let effect = ok_connect();
    assert_eq!(effect.post_bonded_total, 0);
    assert_eq!(effect.post_holdings.kind, HoldingsKind::ShardSetCompact);
    assert!(effect.post_holdings.shard_ids.is_empty());
    assert_eq!(effect.interval_close, clean_interval_close(E_UNBOND));
    assert_eq!(effect.new_total_bonded_atomic, TOTAL_BONDED - RECORD_BONDED);
    // §4.3 identity: refund == debit == bond_floor(record's current holdings).
    assert_eq!(effect.refund_atomic, RECORD_BONDED);
    assert_eq!(effect.refund_atomic, bond_floor(&record_holdings()));
}

#[test]
fn connect_releases_complete_tree_record() {
    // Foundation-shaped record: floor is one FLOOR regardless of shards.
    let effect = unbond_connect(
        ARCHIVAL_BOND_FLOOR_ATOMIC,
        HoldingsKind::CompleteTree,
        0,
        0,
        ARCHIVAL_BOND_FLOOR_ATOMIC,
        TOTAL_BONDED,
        E_UNBOND,
    )
    .expect("complete-tree release");
    // The exit shape is uniform: compact-and-empty, same as slash-to-zero.
    assert_eq!(effect.post_holdings.kind, HoldingsKind::ShardSetCompact);
    assert!(effect.post_holdings.shard_ids.is_empty());
}

#[test]
fn clean_close_leaves_good_through_true() {
    // The load-bearing §4.3 property: appending the clean interval-close
    // changes no `good_through(E)` verdict — backlog emission for served
    // epochs still verifies within `W`.
    let close = clean_interval_close(E_UNBOND);
    let join = 3u64;
    for epoch in [join + 1, E_UNBOND - 1, E_UNBOND, E_UNBOND + 1, u64::MAX] {
        assert_eq!(
            good_through(join, epoch, &[close]),
            good_through(join, epoch, &[]),
            "clean close changed good_through at E = {epoch}"
        );
    }
}

#[test]
fn clean_close_is_inert_next_to_an_open_interval() {
    // Capital flight after a slash: the open interval keeps post-slash
    // epochs bad; the appended close changes nothing.
    let open = BadInterval {
        start_epoch: 10,
        end_exclusive: u64::MAX,
    };
    let with_close = [open, clean_interval_close(E_UNBOND)];
    for epoch in [1, 9, 10, E_UNBOND, E_UNBOND + 7] {
        assert_eq!(
            good_through(0, epoch, &with_close),
            good_through(0, epoch, &[open]),
            "clean close changed good_through at E = {epoch}"
        );
    }
}

// The tests marshal the fixture holdings the way the FFI caller does:
// (kind, shard count), never the id values.
const HOLDINGS_KIND: HoldingsKind = HoldingsKind::ShardSetCompact;
const HOLDINGS_COUNT: usize = 2;

#[test]
fn connect_rejects_zero_debit() {
    assert_eq!(
        unbond_connect(
            0,
            HOLDINGS_KIND,
            HOLDINGS_COUNT,
            0,
            0,
            TOTAL_BONDED,
            E_UNBOND
        ),
        Err(UnbondConnectError::DebitZero)
    );
}

#[test]
fn connect_rejects_debit_mismatch() {
    assert_eq!(
        unbond_connect(
            RECORD_BONDED,
            HOLDINGS_KIND,
            HOLDINGS_COUNT,
            0,
            RECORD_BONDED - 1,
            TOTAL_BONDED,
            E_UNBOND,
        ),
        Err(UnbondConnectError::DebitNotRecordTotal)
    );
}

#[test]
fn connect_rejects_broken_floor_invariant() {
    // Record claims 3×FLOOR bonded over 2 shards — §3.2 equality broken.
    let corrupt = 3 * ARCHIVAL_BOND_FLOOR_ATOMIC;
    assert_eq!(
        unbond_connect(
            corrupt,
            HOLDINGS_KIND,
            HOLDINGS_COUNT,
            0,
            corrupt,
            TOTAL_BONDED,
            E_UNBOND
        ),
        Err(UnbondConnectError::RecordFloorInvariantBroken)
    );
}

#[test]
fn connect_rejects_total_bonded_underflow() {
    assert_eq!(
        unbond_connect(
            RECORD_BONDED,
            HOLDINGS_KIND,
            HOLDINGS_COUNT,
            0,
            RECORD_BONDED,
            RECORD_BONDED - 1,
            E_UNBOND,
        ),
        Err(UnbondConnectError::TotalBondedUnderflow)
    );
}

#[test]
fn connect_rejects_full_interval_log() {
    assert_eq!(
        unbond_connect(
            RECORD_BONDED,
            HOLDINGS_KIND,
            HOLDINGS_COUNT,
            MAX_BOND_BAD_INTERVALS,
            RECORD_BONDED,
            TOTAL_BONDED,
            E_UNBOND,
        ),
        Err(UnbondConnectError::IntervalLogFull)
    );
}

#[test]
fn connect_appends_below_the_cap() {
    assert!(unbond_connect(
        RECORD_BONDED,
        HOLDINGS_KIND,
        HOLDINGS_COUNT,
        MAX_BOND_BAD_INTERVALS - 1,
        RECORD_BONDED,
        TOTAL_BONDED,
        E_UNBOND,
    )
    .is_ok());
}

#[test]
fn pop_restores_total_bonded_exactly() {
    // Connect ∘ pop is the identity on the global counter (§5 pop twin).
    let effect = ok_connect();
    let restored = unbond_pop(
        effect.post_bonded_total,
        effect.post_holdings.shard_ids.len(),
        Some(effect.interval_close),
        E_UNBOND,
        RECORD_BONDED,
        effect.new_total_bonded_atomic,
    )
    .expect("valid pop");
    assert_eq!(restored, TOTAL_BONDED);
}

#[test]
fn pop_rejects_record_not_exited() {
    assert_eq!(
        unbond_pop(
            1,
            0,
            Some(clean_interval_close(E_UNBOND)),
            E_UNBOND,
            RECORD_BONDED,
            0,
        ),
        Err(UnbondPopError::RecordNotExited)
    );
    assert_eq!(
        unbond_pop(
            0,
            1,
            Some(clean_interval_close(E_UNBOND)),
            E_UNBOND,
            RECORD_BONDED,
            0,
        ),
        Err(UnbondPopError::RecordNotExited)
    );
}

#[test]
fn pop_rejects_missing_or_mismatched_clean_close() {
    assert_eq!(
        unbond_pop(0, 0, None, E_UNBOND, RECORD_BONDED, 0),
        Err(UnbondPopError::MissingCleanClose)
    );
    // Wrong epoch.
    assert_eq!(
        unbond_pop(
            0,
            0,
            Some(clean_interval_close(E_UNBOND + 1)),
            E_UNBOND,
            RECORD_BONDED,
            0,
        ),
        Err(UnbondPopError::MissingCleanClose)
    );
    // An open interval is not a clean close.
    assert_eq!(
        unbond_pop(
            0,
            0,
            Some(BadInterval {
                start_epoch: E_UNBOND,
                end_exclusive: u64::MAX,
            }),
            E_UNBOND,
            RECORD_BONDED,
            0,
        ),
        Err(UnbondPopError::MissingCleanClose)
    );
}

#[test]
fn pop_rejects_empty_pre_image() {
    assert_eq!(
        unbond_pop(0, 0, Some(clean_interval_close(E_UNBOND)), E_UNBOND, 0, 0),
        Err(UnbondPopError::PreImageEmpty)
    );
}

#[test]
fn pop_rejects_total_bonded_overflow() {
    assert_eq!(
        unbond_pop(
            0,
            0,
            Some(clean_interval_close(E_UNBOND)),
            E_UNBOND,
            RECORD_BONDED,
            u64::MAX,
        ),
        Err(UnbondPopError::TotalBondedOverflow)
    );
}

// ── HoldingsUpdate add / drop connect + pop ──────────────────────────────

const HU_TOTAL: u64 = 5 * ARCHIVAL_BOND_FLOOR_ATOMIC;

#[test]
fn add_connect_grows_by_one_floor() {
    let effect = holdings_update_add_connect(
        2 * ARCHIVAL_BOND_FLOOR_ATOMIC, // record: 2 shards
        &[7, 9],
        &[7, 9, 11], // post
        HU_TOTAL,
        42, // E_add
    )
    .expect("valid add");
    assert_eq!(effect.added_shard_id, 11);
    assert_eq!(effect.add_settlement_epoch, 42);
    assert_eq!(effect.new_bonded_total, 3 * ARCHIVAL_BOND_FLOOR_ATOMIC);
    assert_eq!(
        effect.new_total_bonded_atomic,
        HU_TOTAL + ARCHIVAL_BOND_FLOOR_ATOMIC
    );
}

#[test]
fn drop_connect_shrinks_by_one_floor() {
    let effect = holdings_update_drop_connect(
        2 * ARCHIVAL_BOND_FLOOR_ATOMIC,
        &[7, 11],
        &[7], // post
        HU_TOTAL,
    )
    .expect("valid drop");
    assert_eq!(effect.dropped_shard_id, 11);
    assert_eq!(effect.new_bonded_total, ARCHIVAL_BOND_FLOOR_ATOMIC);
    assert_eq!(
        effect.new_total_bonded_atomic,
        HU_TOTAL - ARCHIVAL_BOND_FLOOR_ATOMIC
    );
    // §3.2: the refund the bond_debit source term returns == one FLOOR.
    assert_eq!(effect.refund_atomic, ARCHIVAL_BOND_FLOOR_ATOMIC);
}

#[test]
fn add_connect_rejects_non_single_and_broken_invariant() {
    // Two shards added.
    assert_eq!(
        holdings_update_add_connect(
            2 * ARCHIVAL_BOND_FLOOR_ATOMIC,
            &[7, 9],
            &[7, 9, 11, 13],
            HU_TOTAL,
            42
        ),
        Err(HoldingsUpdateConnectError::NotSingleAdd)
    );
    // Record bonded_total disagrees with bond_floor(current 2 shards).
    assert_eq!(
        holdings_update_add_connect(
            3 * ARCHIVAL_BOND_FLOOR_ATOMIC,
            &[7, 9],
            &[7, 9, 11],
            HU_TOTAL,
            42
        ),
        Err(HoldingsUpdateConnectError::RecordFloorInvariantBroken)
    );
}

#[test]
fn drop_connect_rejects_last_shard() {
    assert_eq!(
        holdings_update_drop_connect(ARCHIVAL_BOND_FLOOR_ATOMIC, &[7], &[], HU_TOTAL),
        Err(HoldingsUpdateConnectError::DropLastShard)
    );
}

#[test]
fn holdings_update_pop_reverts_both_directions() {
    // ADD: connect took total → total+FLOOR, record pre 2·FLOOR → post 3·FLOOR.
    // Pop: total+FLOOR back to total, given post/pre.
    let restored = holdings_update_pop(
        3 * ARCHIVAL_BOND_FLOOR_ATOMIC, // current (post)
        2 * ARCHIVAL_BOND_FLOOR_ATOMIC, // journal pre
        HU_TOTAL + ARCHIVAL_BOND_FLOOR_ATOMIC,
    )
    .expect("add pop");
    assert_eq!(restored, HU_TOTAL);

    // DROP: post 1·FLOOR, pre 2·FLOOR; pop re-credits the FLOOR.
    let restored = holdings_update_pop(
        ARCHIVAL_BOND_FLOOR_ATOMIC,
        2 * ARCHIVAL_BOND_FLOOR_ATOMIC,
        HU_TOTAL - ARCHIVAL_BOND_FLOOR_ATOMIC,
    )
    .expect("drop pop");
    assert_eq!(restored, HU_TOTAL);
}

#[test]
fn holdings_update_add_connect_rejects_unbonded_record() {
    // The connect-fold belt of the verify-side Bonded gate: an Exited
    // record's floor invariant is vacuously true (bond_floor(∅) == 0 ==
    // bonded_total), so without the explicit gate the fold proceeded and
    // the C++ writer only failed later, throwing on the empty-pre-image
    // journal row.
    assert_eq!(
        holdings_update_add_connect(0, &[], &[11], 0, 5),
        Err(HoldingsUpdateConnectError::RecordNotBonded)
    );
}

#[test]
fn holdings_update_pop_rejects_non_floor_delta() {
    assert_eq!(
        holdings_update_pop(
            3 * ARCHIVAL_BOND_FLOOR_ATOMIC,
            ARCHIVAL_BOND_FLOOR_ATOMIC, // delta 2·FLOOR, not a single shard
            HU_TOTAL,
        ),
        Err(HoldingsUpdatePopError::NotSingleShardDelta)
    );
}

// ── Rebond connect/pop (P2B-9) ────────────────────────────────────────────

const RB_EPOCH: u64 = 20;
const RB_TOTAL: u64 = 9 * ARCHIVAL_BOND_FLOOR_ATOMIC;

fn rb_open(start: u64) -> BadInterval {
    BadInterval {
        start_epoch: start,
        end_exclusive: u64::MAX,
    }
}

fn rb_closed(start: u64, end: u64) -> BadInterval {
    BadInterval {
        start_epoch: start,
        end_exclusive: end,
    }
}

#[test]
fn rebond_connect_standing_only_moves_no_collateral() {
    let intervals = [rb_closed(2, 3), rb_open(5)];
    let e = rebond_connect(
        2 * ARCHIVAL_BOND_FLOOR_ATOMIC,
        &[7, 9],
        &intervals,
        &[7, 9],
        RB_TOTAL,
        RB_EPOCH,
    )
    .unwrap();
    assert!(e.added_shard_ids.is_empty());
    assert_eq!(e.add_settlement_epoch, RB_EPOCH);
    assert_eq!(e.closed_interval_index, 1);
    assert_eq!(e.interval_end_exclusive, RB_EPOCH + 1); // Pin 3
    assert_eq!(e.new_bonded_total, 2 * ARCHIVAL_BOND_FLOOR_ATOMIC);
    assert_eq!(e.new_total_bonded_atomic, RB_TOTAL);
}

#[test]
fn rebond_connect_growth_credits_added_floors() {
    // Terminal-slash reinstatement: empty current, two shards re-specified.
    let e = rebond_connect(0, &[], &[rb_open(5)], &[7, 11], RB_TOTAL, RB_EPOCH).unwrap();
    assert_eq!(e.added_shard_ids, vec![7, 11]);
    assert_eq!(e.new_bonded_total, 2 * ARCHIVAL_BOND_FLOOR_ATOMIC);
    assert_eq!(
        e.new_total_bonded_atomic,
        RB_TOTAL + 2 * ARCHIVAL_BOND_FLOOR_ATOMIC
    );
}

#[test]
fn rebond_connect_rejects_shape_and_invariant_breaches() {
    let intervals = [rb_open(5)];
    assert_eq!(
        rebond_connect(0, &[], &intervals, &[], RB_TOTAL, RB_EPOCH),
        Err(RebondConnectError::EmptyPost)
    );
    assert_eq!(
        rebond_connect(
            2 * ARCHIVAL_BOND_FLOOR_ATOMIC,
            &[7, 9],
            &intervals,
            &[7, 13], // swap
            RB_TOTAL,
            RB_EPOCH,
        ),
        Err(RebondConnectError::NotSuperset)
    );
    assert_eq!(
        rebond_connect(
            ARCHIVAL_BOND_FLOOR_ATOMIC, // != 2·FLOOR for two shards
            &[7, 9],
            &intervals,
            &[7, 9],
            RB_TOTAL,
            RB_EPOCH,
        ),
        Err(RebondConnectError::RecordFloorInvariantBroken)
    );
    assert_eq!(
        rebond_connect(
            2 * ARCHIVAL_BOND_FLOOR_ATOMIC,
            &[7, 9],
            &[rb_closed(2, 3)], // nothing open
            &[7, 9],
            RB_TOTAL,
            RB_EPOCH,
        ),
        Err(RebondConnectError::NoOpenInterval)
    );
    assert_eq!(
        rebond_connect(
            2 * ARCHIVAL_BOND_FLOOR_ATOMIC,
            &[7, 9],
            &[rb_open(5), rb_open(5)], // coalescing invariant broken
            &[7, 9],
            RB_TOTAL,
            RB_EPOCH,
        ),
        Err(RebondConnectError::MultipleOpenIntervals)
    );
    assert_eq!(
        rebond_connect(
            2 * ARCHIVAL_BOND_FLOOR_ATOMIC,
            &[7, 9],
            &[rb_open(RB_EPOCH + 5)], // slash start after the close point
            &[7, 9],
            RB_TOTAL,
            RB_EPOCH,
        ),
        Err(RebondConnectError::IntervalOrdering)
    );
}

#[test]
fn slash_appends_open_interval_only_when_none_open() {
    // First slash of the epoch appends [E, MAX) — on an empty log and next
    // to closed history alike.
    assert_eq!(
        slash_open_interval_to_append(&[], RB_EPOCH),
        Some(rb_open(RB_EPOCH))
    );
    assert_eq!(
        slash_open_interval_to_append(&[rb_closed(2, 3)], RB_EPOCH),
        Some(rb_open(RB_EPOCH))
    );
    // An existing open interval coalesces the sibling — including one from
    // an earlier epoch (unreachable live, since good_through blocks later
    // epochs while any interval is open, but the decision is
    // interval-shaped, not epoch-shaped).
    assert_eq!(
        slash_open_interval_to_append(&[rb_open(RB_EPOCH)], RB_EPOCH),
        None
    );
    assert_eq!(
        slash_open_interval_to_append(&[rb_closed(1, 2), rb_open(3)], RB_EPOCH),
        None
    );
}

#[test]
fn slash_coalescing_caps_same_epoch_sweep_at_one_interval() {
    // The consensus-halt scenario the coalescing fixes (P2B-9 Pin 5): an
    // offline record with more failing shards than the interval log's
    // codec headroom takes one slash call per shard in ONE block. Folding
    // each decision over the growing log must append exactly one interval
    // — never 300 past MAX_BOND_BAD_INTERVALS.
    let mut log = vec![rb_closed(2, 3)];
    for _ in 0..300 {
        if let Some(iv) = slash_open_interval_to_append(&log, RB_EPOCH) {
            log.push(iv);
        }
    }
    assert_eq!(log.len(), 2);
    assert_eq!(log[1], rb_open(RB_EPOCH));
    assert!(log.len() < MAX_BOND_BAD_INTERVALS);
}

#[test]
fn rebond_connect_rejects_oversize_post() {
    // The verify-side RebondPostOversize twin: the fold refuses to produce
    // a record the codec cannot encode.
    let post: Vec<u64> = (0..=(MAX_HOLDINGS_SHARDS as u64)).collect();
    assert_eq!(
        rebond_connect(0, &[], &[rb_open(5)], &post, RB_TOTAL, RB_EPOCH),
        Err(RebondConnectError::PostOversize)
    );
}

#[test]
fn rebond_pop_reverts_growth_and_tolerates_zero_delta() {
    // Growth of 2·FLOOR reverts exactly.
    assert_eq!(
        rebond_pop(
            3 * ARCHIVAL_BOND_FLOOR_ATOMIC,
            ARCHIVAL_BOND_FLOOR_ATOMIC,
            RB_TOTAL,
        ),
        Ok(RB_TOTAL - 2 * ARCHIVAL_BOND_FLOOR_ATOMIC)
    );
    // Standing-only: zero delta, counter unchanged.
    assert_eq!(
        rebond_pop(
            2 * ARCHIVAL_BOND_FLOOR_ATOMIC,
            2 * ARCHIVAL_BOND_FLOOR_ATOMIC,
            RB_TOTAL,
        ),
        Ok(RB_TOTAL)
    );
}

#[test]
fn rebond_pop_rejects_shrink_partial_floor_and_underflow() {
    // A Rebond never shrinks the balance.
    assert_eq!(
        rebond_pop(
            ARCHIVAL_BOND_FLOOR_ATOMIC,
            2 * ARCHIVAL_BOND_FLOOR_ATOMIC,
            RB_TOTAL,
        ),
        Err(RebondPopError::NotRebondDelta)
    );
    // Delta must be a whole number of FLOORs.
    assert_eq!(
        rebond_pop(
            2 * ARCHIVAL_BOND_FLOOR_ATOMIC + 1,
            ARCHIVAL_BOND_FLOOR_ATOMIC,
            RB_TOTAL,
        ),
        Err(RebondPopError::NotRebondDelta)
    );
    // Reverting more than the global counter holds is corruption.
    assert_eq!(
        rebond_pop(
            2 * ARCHIVAL_BOND_FLOOR_ATOMIC,
            0,
            ARCHIVAL_BOND_FLOOR_ATOMIC
        ),
        Err(RebondPopError::CounterRange)
    );
}
