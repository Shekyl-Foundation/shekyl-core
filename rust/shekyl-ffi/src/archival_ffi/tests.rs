// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for the archival FFI edge (extracted from the former monofile).

use super::*;
use shekyl_archival_retention::{
    as_of_e_served_work, epoch_close_compute, epoch_close_height,
    p_canonical_id_from_hybrid_pubkey, ArchivalRewardEmissionVin, BadInterval, CreditPair,
    EmissionVerifyError, EpochCloseBond, EpochCloseInputs, EpochCloseShard, HoldingsDescriptor,
    HoldingsKind, RewardCommit, ShardSet, ARCHIVAL_REWARD_AGE_WEIGHT_MILLI,
    HYBRID_PUBKEY_CANONICAL_BYTES, MAX_CLAIMED_EPOCH_ENTRIES, MAX_CLAIM_AGE_W,
    SETTLEMENT_EPOCH_BLOCKS,
};
use shekyl_crypto_pq::signature::{HybridEd25519MlDsa, SignatureScheme};
use std::ptr;

#[test]
fn ffi_constants_match_timing_cluster() {
    assert_eq!(SETTLEMENT_EPOCH_BLOCKS, 10_000);
    assert_eq!(shekyl_archival_epoch_open_height(100), 1_000_000);
    assert_eq!(shekyl_archival_epoch_close_height(100), 1_009_999);
}

#[test]
fn ffi_rejects_null_context() {
    let code = unsafe {
        shekyl_archival_verify_serve_credit_vin(ptr::null(), 0, ptr::null(), 0, ptr::null())
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_VERIFY_ERR_NULL_PTR);
}

#[test]
fn extract_empty_slice_is_wire_not_null() {
    // A Rust empty slice has a non-null `as_ptr()`; length 0 is a parse
    // failure, not a call-site pointer bug.
    let empty: [u8; 0] = [];
    let mut p_id = [0u8; 32];
    let mut shard = 0u64;
    let mut epoch = 0u64;
    let code = unsafe {
        shekyl_archival_serve_credit_extract(
            empty.as_ptr(),
            0,
            p_id.as_mut_ptr(),
            &raw mut shard,
            &raw mut epoch,
        )
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_VERIFY_ERR_WIRE);
}

#[test]
fn extract_null_ptr_is_null() {
    let mut p_id = [0u8; 32];
    let mut shard = 0u64;
    let mut epoch = 0u64;
    let code = unsafe {
        shekyl_archival_serve_credit_extract(
            ptr::null(),
            0,
            p_id.as_mut_ptr(),
            &raw mut shard,
            &raw mut epoch,
        )
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_VERIFY_ERR_NULL_PTR);
}

#[test]
fn checked_sum_amounts_sums_overflows_and_guards() {
    // Empty set (null allowed iff len == 0) sums to 0.
    let mut out: u64 = 7;
    assert_eq!(
        unsafe { shekyl_checked_sum_amounts(ptr::null(), 0, &raw mut out) },
        0
    );
    assert_eq!(out, 0);

    // Normal sum.
    let amounts = [1u64, 2, 3, 4];
    let mut sum: u64 = 0;
    assert_eq!(
        unsafe { shekyl_checked_sum_amounts(amounts.as_ptr(), amounts.len(), &raw mut sum) },
        0
    );
    assert_eq!(sum, 10);

    // Overflow rejects (non-zero return, caller must reject the tx).
    let overflow = [u64::MAX, 1];
    let mut bad: u64 = 0;
    assert_eq!(
        unsafe { shekyl_checked_sum_amounts(overflow.as_ptr(), overflow.len(), &raw mut bad) },
        1
    );

    // Null out pointer and null data with non-zero len both reject.
    assert_eq!(
        unsafe { shekyl_checked_sum_amounts(amounts.as_ptr(), amounts.len(), ptr::null_mut()) },
        1
    );
    let mut o: u64 = 0;
    assert_eq!(
        unsafe { shekyl_checked_sum_amounts(ptr::null(), 3, &raw mut o) },
        1
    );
}

#[test]
fn bond_post_ffi_maps_each_reject_reason() {
    use shekyl_archival_retention::ARCHIVAL_BOND_FLOOR_ATOMIC;

    let floor = ARCHIVAL_BOND_FLOOR_ATOMIC;
    let shard = 42u64;
    let spend_pk = vec![0xE5u8; HYBRID_PUBKEY_CANONICAL_BYTES];
    let verify = |post_kind: u8,
                  holdings_kind: u8,
                  shards: Option<&u64>,
                  shard_len: usize,
                  total: u64,
                  credit: u64,
                  debit: u64,
                  record_exists: u8| unsafe {
        shekyl_archival_verify_join_market_bond_post(
            post_kind,
            holdings_kind,
            shards.map_or(std::ptr::null(), std::ptr::from_ref),
            shard_len,
            spend_pk.as_ptr(),
            spend_pk.len(),
            total,
            credit,
            debit,
            record_exists,
        )
    };

    assert_eq!(
        verify(0, 0, Some(&shard), 1, floor, floor, 0, 0),
        SHEKYL_ARCHIVAL_BOND_POST_OK
    );
    // A conforming Rebond vin carries NO key (§9.11), so the post-kind
    // verdict is asserted with an empty one; Rebond WITH a key is the
    // coupling case at the bottom.
    assert_eq!(
        unsafe {
            shekyl_archival_verify_join_market_bond_post(
                1,
                0,
                std::ptr::from_ref(&shard),
                1,
                std::ptr::null(),
                0,
                floor,
                floor,
                0,
                0,
            )
        },
        SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND
    );
    assert_eq!(
        verify(0, 0, None, 1, floor, floor, 0, 0),
        SHEKYL_ARCHIVAL_BOND_POST_ERR_NULL_PTR
    );
    assert_eq!(
        verify(0, 99, Some(&shard), 1, floor, floor, 0, 0),
        SHEKYL_ARCHIVAL_BOND_POST_ERR_HOLDINGS_KIND
    );
    assert_eq!(
        verify(0, 0, None, 0, floor, floor, 0, 0),
        SHEKYL_ARCHIVAL_BOND_POST_ERR_SHARD_SET_EMPTY
    );
    assert_eq!(
        verify(0, 1, Some(&shard), 1, floor, floor, 0, 0),
        SHEKYL_ARCHIVAL_BOND_POST_ERR_COMPLETE_TREE_WITH_SHARDS
    );
    assert_eq!(
        verify(0, 0, Some(&shard), 1, floor, floor, floor, 0),
        SHEKYL_ARCHIVAL_BOND_POST_ERR_BOTH_TERMS
    );
    assert_eq!(
        verify(0, 0, Some(&shard), 1, 0, 0, 1, 0),
        SHEKYL_ARCHIVAL_BOND_POST_ERR_BOND_DEBIT_NONZERO
    );
    assert_eq!(
        verify(0, 0, Some(&shard), 1, floor + 1, floor + 1, 0, 0),
        SHEKYL_ARCHIVAL_BOND_POST_ERR_FLOOR_MISMATCH
    );
    assert_eq!(
        verify(0, 0, Some(&shard), 1, floor, floor, 0, 1),
        SHEKYL_ARCHIVAL_BOND_POST_ERR_RECORD_EXISTS
    );

    // §9.11 coupling at the marshaler: JoinMarket requires the
    // exact-canonical-length key — empty and truncated both refuse.
    let coupling = |pk: &[u8]| unsafe {
        shekyl_archival_verify_join_market_bond_post(
            0,
            0,
            std::ptr::from_ref(&shard),
            1,
            if pk.is_empty() {
                std::ptr::null()
            } else {
                pk.as_ptr()
            },
            pk.len(),
            floor,
            floor,
            0,
            0,
        )
    };
    assert_eq!(
        coupling(&[]),
        SHEKYL_ARCHIVAL_BOND_POST_ERR_BOND_SPEND_PK_COUPLING
    );
    assert_eq!(
        coupling(&spend_pk[..HYBRID_PUBKEY_CANONICAL_BYTES - 1]),
        SHEKYL_ARCHIVAL_BOND_POST_ERR_BOND_SPEND_PK_COUPLING
    );
    // ...and the inverse direction: a non-JoinMarket kind (Rebond) carrying
    // a key refuses at the marshaler, before the post-kind verdict.
    assert_eq!(
        verify(1, 0, Some(&shard), 1, floor, floor, 0, 0),
        SHEKYL_ARCHIVAL_BOND_POST_ERR_BOND_SPEND_PK_COUPLING
    );
    // A null key pointer with a positive length is the caller bug, not coupling.
    assert_eq!(
        unsafe {
            shekyl_archival_verify_join_market_bond_post(
                0,
                0,
                std::ptr::from_ref(&shard),
                1,
                std::ptr::null(),
                HYBRID_PUBKEY_CANONICAL_BYTES,
                floor,
                floor,
                0,
                0,
            )
        },
        SHEKYL_ARCHIVAL_BOND_POST_ERR_NULL_PTR
    );
}

#[test]
fn unbond_ffi_folds_cooldown_and_maps_verdicts() {
    use shekyl_archival_retention::{
        BondPostKind, HoldingsKind, ARCHIVAL_BOND_FLOOR_ATOMIC, RELEASE_COOLDOWN_EPOCHS,
    };

    let floor = ARCHIVAL_BOND_FLOOR_ATOMIC;
    let record_bonded = 2 * floor;
    // Two served shards → the whole-record anchor is the max (100). The FFI
    // folds this array to the cooldown anchor, so the boundary sits at 102.
    let served = [80u64, 100u64];
    let ok_current = 100 + RELEASE_COOLDOWN_EPOCHS;
    // The slash scheduler's watermark has reached the anchor.
    let settled_ok = 100u64;

    // (current, settled, debit, total, holdings_len, record_exists); the post
    // is a ShardSetCompact `Unbond` with credit 0 and holdings shard 7 when
    // present.
    let verify = |current: u64,
                  settled: u64,
                  debit: u64,
                  total: u64,
                  holdings_len: usize,
                  record_exists: u8| unsafe {
        let shard = 7u64;
        shekyl_archival_verify_unbond_bond_post(
            BondPostKind::Unbond as u8,
            HoldingsKind::ShardSetCompact as u8,
            if holdings_len == 0 {
                std::ptr::null()
            } else {
                std::ptr::from_ref(&shard)
            },
            holdings_len,
            std::ptr::null(), // bond_spend_pk (§9.11: never on Unbond)
            0,
            total,
            0, // credit
            debit,
            record_exists,
            record_bonded,
            0, // record_bad_interval_count
            served.as_ptr(),
            served.len(),
            settled,
            current,
        )
    };

    // Accept: empty holdings, zero post-total, full debit, cooldown elapsed,
    // anchor slash-settled.
    assert_eq!(
        verify(ok_current, settled_ok, record_bonded, 0, 0, 1),
        SHEKYL_ARCHIVAL_BOND_POST_OK
    );
    // One epoch short — proves the anchor fold (max = 100, boundary 102).
    assert_eq!(
        verify(ok_current - 1, settled_ok, record_bonded, 0, 0, 1),
        SHEKYL_ARCHIVAL_BOND_POST_ERR_COOLDOWN_NOT_ELAPSED
    );
    // Cooldown elapsed but the anchor epoch not yet slash-settled — the
    // one-block connect-ordering race guard.
    assert_eq!(
        verify(ok_current, settled_ok - 1, record_bonded, 0, 0, 1),
        SHEKYL_ARCHIVAL_BOND_POST_ERR_SLASH_SETTLEMENT_PENDING
    );
    // u64::MAX is the "no epoch settled yet" storage sentinel, not a watermark.
    assert_eq!(
        verify(ok_current, u64::MAX, record_bonded, 0, 0, 1),
        SHEKYL_ARCHIVAL_BOND_POST_ERR_SLASH_SETTLEMENT_PENDING
    );
    // Record missing.
    assert_eq!(
        verify(ok_current, settled_ok, record_bonded, 0, 0, 0),
        SHEKYL_ARCHIVAL_BOND_POST_ERR_RECORD_MISSING
    );
    // Non-empty holdings with zero post-total → floor mismatch.
    assert_eq!(
        verify(ok_current, settled_ok, record_bonded, 0, 1, 1),
        SHEKYL_ARCHIVAL_BOND_POST_ERR_UNBOND_FLOOR_MISMATCH
    );
    // Consistent post-state but non-zero total → partial, not full exit.
    assert_eq!(
        verify(ok_current, settled_ok, floor, floor, 1, 1),
        SHEKYL_ARCHIVAL_BOND_POST_ERR_NOT_FULL_UNBOND
    );
    // Debit != the record's current bonded_total.
    assert_eq!(
        verify(ok_current, settled_ok, floor, 0, 0, 1),
        SHEKYL_ARCHIVAL_BOND_POST_ERR_DEBIT_NOT_FULL
    );

    // A missing record is rejected before the cooldown gate, so the verdict
    // must not hinge on cooldown marshaling: a null serve-credit pointer with
    // a nonzero length under `record_exists == 0` surfaces RECORD_MISSING, not
    // NULL_PTR. (The closure always passes a valid `served` slice, so this
    // precedence case is exercised directly.)
    let record_missing_null_cooldown = unsafe {
        shekyl_archival_verify_unbond_bond_post(
            BondPostKind::Unbond as u8,
            HoldingsKind::ShardSetCompact as u8,
            std::ptr::null(), // shard_ids_ptr (empty holdings)
            0,                // shard_ids_len
            std::ptr::null(), // bond_spend_pk_ptr (§9.11: never on Unbond)
            0,                // bond_spend_pk_len
            0,                // bonded_total_atomic
            0,                // bond_credit
            record_bonded,    // bond_debit
            0,                // record_exists → missing
            record_bonded,    // record_bonded_total (ignored when missing)
            0,                // record_bad_interval_count
            std::ptr::null(), // per_shard_last_served_ptr (null)
            1,                // per_shard_last_served_len > 0
            u64::MAX,         // last_settled_slash_epoch (none-settled sentinel)
            ok_current,
        )
    };
    assert_eq!(
        record_missing_null_cooldown,
        SHEKYL_ARCHIVAL_BOND_POST_ERR_RECORD_MISSING
    );

    // §9.11 coupling at the marshaler: an Unbond vin carrying ANY
    // bond_spend_pk bytes refuses — even the canonical length that would
    // satisfy JoinMarket (the field is JoinMarket-coupled, not
    // length-gated).
    let stray_key = vec![0xC7u8; HYBRID_PUBKEY_CANONICAL_BYTES];
    let unbond_with_stray_key = unsafe {
        shekyl_archival_verify_unbond_bond_post(
            BondPostKind::Unbond as u8,
            HoldingsKind::ShardSetCompact as u8,
            std::ptr::null(),
            0,
            stray_key.as_ptr(),
            stray_key.len(),
            0,
            0,
            record_bonded,
            1,
            record_bonded,
            0,
            served.as_ptr(),
            served.len(),
            settled_ok,
            ok_current,
        )
    };
    assert_eq!(
        unbond_with_stray_key,
        SHEKYL_ARCHIVAL_BOND_POST_ERR_BOND_SPEND_PK_COUPLING
    );
}

#[test]
fn unbond_ffi_rejects_len_overflow() {
    use shekyl_archival_retention::{BondPostKind, HoldingsKind};
    let dummy = 7u64;
    // A shard_ids length whose byte span overflows isize::MAX must reject
    // (LEN_OVERFLOW) rather than reach from_raw_parts with an unsound length.
    let shard_overflow = unsafe {
        shekyl_archival_verify_unbond_bond_post(
            BondPostKind::Unbond as u8,
            HoldingsKind::ShardSetCompact as u8,
            std::ptr::from_ref(&dummy),
            usize::MAX,
            std::ptr::null(),
            0,
            0,
            0,
            0,
            1,
            1,
            0,
            std::ptr::null(),
            0,
            u64::MAX,
            0,
        )
    };
    assert_eq!(shard_overflow, SHEKYL_ARCHIVAL_BOND_POST_ERR_LEN_OVERFLOW);
    // Same guard on the bond_spend_pk byte slice.
    let spend_pk_overflow = unsafe {
        shekyl_archival_verify_unbond_bond_post(
            BondPostKind::Unbond as u8,
            HoldingsKind::ShardSetCompact as u8,
            std::ptr::null(),
            0,
            std::ptr::from_ref(&dummy).cast::<u8>(),
            usize::MAX,
            0,
            0,
            0,
            1,
            1,
            0,
            std::ptr::null(),
            0,
            u64::MAX,
            0,
        )
    };
    assert_eq!(
        spend_pk_overflow,
        SHEKYL_ARCHIVAL_BOND_POST_ERR_LEN_OVERFLOW
    );
    // Same guard on the serve-credit anchor array (reached once the record exists).
    let served_overflow = unsafe {
        shekyl_archival_verify_unbond_bond_post(
            BondPostKind::Unbond as u8,
            HoldingsKind::ShardSetCompact as u8,
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
            0,
            0,
            0,
            1,
            1,
            0,
            std::ptr::from_ref(&dummy),
            usize::MAX,
            u64::MAX,
            0,
        )
    };
    assert_eq!(served_overflow, SHEKYL_ARCHIVAL_BOND_POST_ERR_LEN_OVERFLOW);
}

#[test]
fn unbond_ffi_rejects_oversize_holdings_masquerading_as_empty() {
    use shekyl_archival_retention::{BondPostKind, HoldingsKind};
    // The FFI marshal is a second decoder for the wire object, so it
    // enforces the wire decoder's MAX_HOLDINGS_SHARDS (4096) bound at the
    // boundary: an oversize ShardSetCompact never reaches verify (where
    // bond_floor's in-band 0 would make it masquerade as the empty
    // full-exit state — the verify-level guard for direct Rust callers is
    // pinned by bond_post.rs's rejects_oversize_shard_set_masquerading_as_empty).
    let shards = vec![0u64; 4097];
    let code = unsafe {
        shekyl_archival_verify_unbond_bond_post(
            BondPostKind::Unbond as u8,
            HoldingsKind::ShardSetCompact as u8,
            shards.as_ptr(),
            shards.len(),
            std::ptr::null(), // bond_spend_pk (§9.11: never on Unbond)
            0,
            0, // bonded_total_atomic (post-connect full exit)
            0, // bond_credit
            1, // bond_debit == record_bonded_total
            1, // record_exists
            1, // record_bonded_total
            0, // record_bad_interval_count
            std::ptr::null(),
            0,
            u64::MAX,
            0,
        )
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_BOND_POST_ERR_HOLDINGS_COUNT_EXCEEDED);
}

#[test]
fn rebond_ffi_rejects_oversize_post_at_the_marshal_boundary() {
    use shekyl_archival_retention::{BondPostKind, HoldingsKind};
    // The finding this closes: a >4096-shard Rebond post on a
    // terminal-slashed record (bonded 0) collapsed bond_floor to 0, so the
    // zero-credit terms verified and the connect then aborted block apply
    // at the record encode. The marshal cap makes the oversize set
    // unrepresentable past the FFI for every post kind.
    let shards: Vec<u64> = (0..4097u64).collect();
    let intervals = [5u64, u64::MAX]; // one open interval (slashed record)
    let code = unsafe {
        shekyl_archival_verify_rebond_bond_post(
            BondPostKind::Rebond as u8,
            HoldingsKind::ShardSetCompact as u8,
            shards.as_ptr(),
            shards.len(),
            std::ptr::null(), // bond_spend_pk (§9.11: never on Rebond)
            0,
            0, // bonded_total_atomic — the floor-collapse masquerade
            0, // bond_credit — zero collateral demanded
            0, // bond_debit
            1, // record_exists
            0, // record_bonded_total — terminal slash
            HoldingsKind::ShardSetCompact as u8,
            std::ptr::null(), // record holds nothing
            0,
            intervals.as_ptr(),
            1,
        )
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_BOND_POST_ERR_HOLDINGS_COUNT_EXCEEDED);
}

#[test]
fn bond_post_ffi_rejects_duplicate_holdings_at_the_marshal_boundary() {
    use shekyl_archival_retention::{BondPostKind, HoldingsKind, ARCHIVAL_BOND_FLOOR_ATOMIC};
    // "A set on the wire": the marshal is a second decoder, so it rejects a
    // duplicate shard id (the JoinMarket path that silently double-counted
    // the floor before the newtype). One arbitrary verify entry proves the
    // shared marshal — the rejection is at the marshal, kind-agnostic, and
    // fires before any post-kind semantics.
    let dup = [7u64, 42, 7];
    let code = unsafe {
        shekyl_archival_verify_join_market_bond_post(
            BondPostKind::JoinMarket as u8,
            HoldingsKind::ShardSetCompact as u8,
            dup.as_ptr(),
            dup.len(),
            std::ptr::null(),
            0,
            3 * ARCHIVAL_BOND_FLOOR_ATOMIC,
            3 * ARCHIVAL_BOND_FLOOR_ATOMIC,
            0,
            0, // record_exists
        )
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_BOND_POST_ERR_HOLDINGS_DUPLICATE_SHARD);
}

#[test]
fn unbond_connect_ffi_folds_effect_and_pop_restores() {
    use shekyl_archival_retention::{HoldingsKind, ARCHIVAL_BOND_FLOOR_ATOMIC};

    let record_bonded = 2 * ARCHIVAL_BOND_FLOOR_ATOMIC;
    let total_bonded = 5 * ARCHIVAL_BOND_FLOOR_ATOMIC;
    let epoch = 42u64;
    let shards = [7u64, 42u64];

    let mut post_bonded = u64::MAX;
    let mut post_kind = u8::MAX;
    let mut post_count = u64::MAX;
    let mut close_start = u64::MAX;
    let mut close_end = u64::MAX;
    let mut new_total = u64::MAX;
    let rc = unsafe {
        shekyl_archival_unbond_connect(
            record_bonded,
            HoldingsKind::ShardSetCompact as u8,
            shards.len() as u64,
            0,
            record_bonded,
            total_bonded,
            epoch,
            &raw mut post_bonded,
            &raw mut post_kind,
            &raw mut post_count,
            &raw mut close_start,
            &raw mut close_end,
            &raw mut new_total,
        )
    };
    assert_eq!(rc, SHEKYL_ARCHIVAL_UNBOND_APPLY_OK);
    assert_eq!(post_bonded, 0);
    assert_eq!(post_kind, HoldingsKind::ShardSetCompact as u8);
    assert_eq!(post_count, 0);
    // The clean interval-close is zero-length at the unbond epoch.
    assert_eq!((close_start, close_end), (epoch, epoch));
    assert_eq!(new_total, total_bonded - record_bonded);

    // Pop twin restores the counter exactly (§5).
    let mut restored = u64::MAX;
    let rc = unsafe {
        shekyl_archival_unbond_pop(
            post_bonded,
            post_count,
            1,
            close_start,
            close_end,
            epoch,
            record_bonded,
            new_total,
            &raw mut restored,
        )
    };
    assert_eq!(rc, SHEKYL_ARCHIVAL_UNBOND_APPLY_OK);
    assert_eq!(restored, total_bonded);
}

#[test]
fn unbond_connect_ffi_maps_fatal_arms() {
    use shekyl_archival_retention::{
        HoldingsKind, ARCHIVAL_BOND_FLOOR_ATOMIC, MAX_BOND_BAD_INTERVALS,
    };

    let record_bonded = 2 * ARCHIVAL_BOND_FLOOR_ATOMIC;
    let shards = [7u64, 42u64];
    let connect = |record_total: u64, bad_count: usize, debit: u64, total: u64| -> (u8, u64) {
        let mut post_bonded = 0u64;
        let mut post_kind = 0u8;
        let mut post_count = 0u64;
        let mut close_start = 0u64;
        let mut close_end = 0u64;
        let mut new_total = 0u64;
        let rc = unsafe {
            shekyl_archival_unbond_connect(
                record_total,
                HoldingsKind::ShardSetCompact as u8,
                shards.len() as u64,
                bad_count,
                debit,
                total,
                42,
                &raw mut post_bonded,
                &raw mut post_kind,
                &raw mut post_count,
                &raw mut close_start,
                &raw mut close_end,
                &raw mut new_total,
            )
        };
        (rc, new_total)
    };

    assert_eq!(
        connect(record_bonded, 0, 0, record_bonded).0,
        SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_DEBIT_ZERO
    );
    assert_eq!(
        connect(record_bonded, 0, record_bonded - 1, record_bonded).0,
        SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_DEBIT_NOT_RECORD_TOTAL
    );
    // 3×FLOOR bonded over 2 shards breaks the §3.2 equality.
    let corrupt = 3 * ARCHIVAL_BOND_FLOOR_ATOMIC;
    assert_eq!(
        connect(corrupt, 0, corrupt, corrupt).0,
        SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_RECORD_FLOOR_INVARIANT
    );
    assert_eq!(
        connect(record_bonded, 0, record_bonded, record_bonded - 1).0,
        SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_TOTAL_BONDED_UNDERFLOW
    );
    assert_eq!(
        connect(
            record_bonded,
            MAX_BOND_BAD_INTERVALS,
            record_bonded,
            record_bonded
        )
        .0,
        SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_INTERVAL_LOG_FULL
    );

    // Null out-pointer rejects before any write.
    let rc = unsafe {
        shekyl_archival_unbond_connect(
            record_bonded,
            HoldingsKind::ShardSetCompact as u8,
            shards.len() as u64,
            0,
            record_bonded,
            record_bonded,
            42,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_NULL_PTR);
    // A hostile over-cap shard count cannot satisfy the floor invariant
    // (bond_floor_of returns 0 past MAX_HOLDINGS_SHARDS), so it maps to the
    // record-corruption arm rather than needing a pointer-length guard.
    let mut sink = 0u64;
    let mut kind_sink = 0u8;
    let rc = unsafe {
        shekyl_archival_unbond_connect(
            record_bonded,
            HoldingsKind::ShardSetCompact as u8,
            u64::MAX,
            0,
            record_bonded,
            record_bonded,
            42,
            &raw mut sink,
            &raw mut kind_sink,
            &raw mut sink,
            &raw mut sink,
            &raw mut sink,
            &raw mut sink,
        )
    };
    assert_eq!(rc, SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_RECORD_FLOOR_INVARIANT);
}

#[test]
fn unbond_pop_ffi_maps_desync_arms() {
    let mut out = 0u64;
    // Record not in the exited state.
    let rc = unsafe { shekyl_archival_unbond_pop(1, 0, 1, 42, 42, 42, 10, 0, &raw mut out) };
    assert_eq!(rc, SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_RECORD_NOT_EXITED);
    // No trailing interval at all.
    let rc = unsafe { shekyl_archival_unbond_pop(0, 0, 0, 0, 0, 42, 10, 0, &raw mut out) };
    assert_eq!(rc, SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_MISSING_CLEAN_CLOSE);
    // Trailing interval is open, not the zero-length clean close.
    let rc = unsafe { shekyl_archival_unbond_pop(0, 0, 1, 42, u64::MAX, 42, 10, 0, &raw mut out) };
    assert_eq!(rc, SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_MISSING_CLEAN_CLOSE);
    // Journaled pre-image is empty.
    let rc = unsafe { shekyl_archival_unbond_pop(0, 0, 1, 42, 42, 42, 0, 0, &raw mut out) };
    assert_eq!(rc, SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_PRE_IMAGE_EMPTY);
    // Re-credit overflow.
    let rc = unsafe { shekyl_archival_unbond_pop(0, 0, 1, 42, 42, 42, 10, u64::MAX, &raw mut out) };
    assert_eq!(rc, SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_TOTAL_BONDED_OVERFLOW);
    // Null out-pointer.
    let rc =
        unsafe { shekyl_archival_unbond_pop(0, 0, 1, 42, 42, 42, 10, 0, std::ptr::null_mut()) };
    assert_eq!(rc, SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_NULL_PTR);
}

#[test]
fn bond_post_block_unique_ffi_rejects_same_p_pairs() {
    // Two distinct P ids pass; any same-P pair rejects (keyed on P alone,
    // whatever the post kinds); null with nonzero count fails closed.
    let mut flat = vec![0x11u8; 32];
    flat.extend(vec![0x22u8; 32]);
    let unique = unsafe { shekyl_archival_bond_post_block_unique(flat.as_ptr(), 2) };
    assert_eq!(unique, 1);
    flat.extend(vec![0x11u8; 32]);
    let dup = unsafe { shekyl_archival_bond_post_block_unique(flat.as_ptr(), 3) };
    assert_eq!(dup, 0);
    assert_eq!(
        unsafe { shekyl_archival_bond_post_block_unique(std::ptr::null(), 0) },
        1
    );
    assert_eq!(
        unsafe { shekyl_archival_bond_post_block_unique(std::ptr::null(), 1) },
        0
    );
}

#[test]
fn serve_credit_epoch_ok_ffi_matches_rust() {
    assert_eq!(shekyl_archival_serve_credit_epoch_ok(0, 0), 0);
    assert_eq!(shekyl_archival_serve_credit_epoch_ok(1, 0), 1);
    assert_eq!(
        shekyl_archival_serve_credit_epoch_ok(u64::MAX, u64::MAX - 1),
        1
    );
    assert_eq!(shekyl_archival_serve_credit_epoch_ok(u64::MAX, u64::MAX), 0);
}

#[test]
fn bond_ct_balance_ffi_rejects_null_with_nonzero_count() {
    let code = unsafe {
        shekyl_archival_verify_bond_post_ct_balance(ptr::null(), 1, ptr::null(), 0, 0, 0, 0)
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_NULL_PTR);
}

#[test]
fn bond_ct_balance_ffi_rejects_count_overflow() {
    let buf = [0u8; 32];
    let code = unsafe {
        shekyl_archival_verify_bond_post_ct_balance(
            buf.as_ptr(),
            usize::MAX,
            ptr::null(),
            0,
            0,
            0,
            0,
        )
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_INVALID_POINT);
}

// The both / neither bond-term rigidity is unrepresentable inside the core
// `BondTerm`, so it is enforced (and tested) here at the `(credit, debit) ->
// BondTerm` FFI conversion — the boundary where the untrusted u64s enter.
#[test]
fn bond_ct_balance_ffi_rejects_neither_bond_term() {
    // credit = debit = 0 (empty balance) → NO_BOND_TERM, not OK.
    let code = unsafe {
        shekyl_archival_verify_bond_post_ct_balance(ptr::null(), 0, ptr::null(), 0, 0, 0, 0)
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_NO_BOND_TERM);
}

#[test]
fn bond_ct_balance_ffi_rejects_both_bond_terms() {
    // credit and debit both non-zero → BOTH_TERMS.
    let code = unsafe {
        shekyl_archival_verify_bond_post_ct_balance(ptr::null(), 0, ptr::null(), 0, 0, 1, 1)
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_BOTH_TERMS);
}

#[test]
fn ffi_rejects_leaf_layer_scalar_count_not_multiple_of_four() {
    let pubkey = [0u8; 32];
    let scalars = [0u8; 32];
    let ctx = ShekylArchivalVerifyCtx {
        current_height: 1,
        settlement_epoch: 0,
        block_hash_at_seal: [0u8; 32],
        registry_segment_subroot_rk: [0u8; 32],
        segment_leaf_count: 1,
        // Non-zero on purpose: an all-zero hash is the PC-D3 unpopulated
        // sentinel, refused ahead of the scalar-shape check. Leaving it zero
        // would make this test pass on the WRONG code and stop testing the
        // scalar shape at all.
        prev_block_hash: [0x6D; 32],
        pqc_pubkey_ptr: pubkey.as_ptr(),
        pqc_pubkey_len: pubkey.len(),
        leaf_layer_scalars_ptr: scalars.as_ptr(),
        leaf_layer_scalars_len: scalars.len(),
    };
    let payload = [0u8];
    // Shape checks on the ctx precede both parses, so a dummy pruned slice
    // is never read here -- the assertion is on the ORDER of the checks.
    let code = unsafe {
        shekyl_archival_verify_serve_credit_vin(
            payload.as_ptr(),
            payload.len(),
            payload.as_ptr(),
            payload.len(),
            std::ptr::from_ref(&ctx),
        )
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_VERIFY_ERR_SCALAR_SHAPE);
}

/// `PC-D3`'s red side: an unpopulated `prev_block_hash` is refused, and refused
/// **before** anything the prover controls is parsed.
///
/// The vin and pruned slices here are deliberate garbage. If the refusal ever
/// moves below the parses, this returns a wire error instead and goes red --
/// which is the point: a caller-wiring defect that only surfaces when the
/// prover happens to send a well-formed vin is a defect that a hostile prover
/// decides whether the operator ever sees.
///
/// The edit that makes this red is deleting the zero-hash guard, or moving it
/// after `ArchivalServeCreditResponse::read_exact`.
#[test]
fn ffi_refuses_an_unpopulated_prev_block_hash_before_parsing_the_vin() {
    let pubkey = [0u8; 32];
    let scalars = [0u8; 128];
    let ctx = ShekylArchivalVerifyCtx {
        current_height: 1,
        settlement_epoch: 0,
        block_hash_at_seal: [0xAB; 32],
        registry_segment_subroot_rk: [0u8; 32],
        segment_leaf_count: 25_992,
        prev_block_hash: [0u8; 32],
        pqc_pubkey_ptr: pubkey.as_ptr(),
        pqc_pubkey_len: pubkey.len(),
        leaf_layer_scalars_ptr: scalars.as_ptr(),
        leaf_layer_scalars_len: scalars.len(),
    };
    let garbage = [0xFFu8; 4];
    let code = unsafe {
        shekyl_archival_verify_serve_credit_vin(
            garbage.as_ptr(),
            garbage.len(),
            garbage.as_ptr(),
            garbage.len(),
            std::ptr::from_ref(&ctx),
        )
    };
    assert_eq!(
        code, SHEKYL_ARCHIVAL_VERIFY_ERR_PREVHASH_UNPOPULATED,
        "an unpopulated ctx block was not refused ahead of the vin parse; a \
         prover can now mask the node's own misconfiguration with garbage"
    );
}

#[test]
fn good_through_ffi_matches_interval_semantics() {
    // Open-ended slash at epoch 11: good before, bad from 11 on.
    let flat = [11u64, u64::MAX];
    let good = |e: u64| unsafe { shekyl_archival_good_through(0, e, flat.as_ptr(), 1) };
    assert_eq!(good(10), 1);
    assert_eq!(good(11), 0);
    // Pre-E_first epochs are not good.
    assert_eq!(
        unsafe { shekyl_archival_good_through(5, 5, std::ptr::null(), 0) },
        0
    );
    assert_eq!(
        unsafe { shekyl_archival_good_through(5, 6, std::ptr::null(), 0) },
        1
    );
    // Null with nonzero length fails closed.
    assert_eq!(
        unsafe { shekyl_archival_good_through(0, 10, std::ptr::null(), 1) },
        0
    );
}

#[test]
fn epoch_timing_ffi_boundaries() {
    let seb = SETTLEMENT_EPOCH_BLOCKS;
    let mut epoch = u64::MAX;
    assert_eq!(
        unsafe { shekyl_archival_epoch_close_due(0, ptr::from_mut(&mut epoch)) },
        0
    );
    assert_eq!(
        unsafe { shekyl_archival_epoch_close_due(seb, ptr::from_mut(&mut epoch)) },
        1
    );
    assert_eq!(epoch, 0);
    assert_eq!(
        unsafe { shekyl_archival_epoch_close_due(seb + 1, ptr::from_mut(&mut epoch)) },
        0
    );

    assert_eq!(shekyl_archival_settlement_epoch_at_height(seb - 1), 0);
    assert_eq!(shekyl_archival_settlement_epoch_at_height(seb), 1);

    let w = MAX_CLAIM_AGE_W;
    let mut below = u64::MAX;
    assert_eq!(
        unsafe { shekyl_archival_prune_below_epoch(w * seb, ptr::from_mut(&mut below)) },
        0
    );
    assert_eq!(
        unsafe { shekyl_archival_prune_below_epoch((w + 1) * seb, ptr::from_mut(&mut below)) },
        1
    );
    assert_eq!(below, 1);
}

#[test]
fn epoch_close_compute_ffi_full_pipeline() {
    // Two members share shard 7; one slashed bond and one foundation
    // complete-tree contribute neither market count nor work.
    let slashed = [0u64, u64::MAX];
    let bonds = [
        ShekylArchivalEpochCloseBond {
            join_settlement_epoch: 0,
            bad_intervals_ptr: ptr::null(),
            bad_intervals_len: 0,
            is_foundation_complete_tree: 0,
        },
        ShekylArchivalEpochCloseBond {
            join_settlement_epoch: 0,
            bad_intervals_ptr: ptr::null(),
            bad_intervals_len: 0,
            is_foundation_complete_tree: 0,
        },
        ShekylArchivalEpochCloseBond {
            join_settlement_epoch: 0,
            bad_intervals_ptr: slashed.as_ptr(),
            bad_intervals_len: 1,
            is_foundation_complete_tree: 0,
        },
        ShekylArchivalEpochCloseBond {
            join_settlement_epoch: 0,
            bad_intervals_ptr: ptr::null(),
            bad_intervals_len: 0,
            is_foundation_complete_tree: 1,
        },
    ];
    let shards = [ShekylArchivalEpochCloseShard {
        shard_id: 7,
        freeze_height: 0,
        has_segment: 1,
    }];
    let pairs = [
        ShekylArchivalCreditPair {
            bond_idx: 0,
            shard_idx: 0,
        },
        ShekylArchivalCreditPair {
            bond_idx: 1,
            shard_idx: 0,
        },
        ShekylArchivalCreditPair {
            bond_idx: 2,
            shard_idx: 0,
        },
        ShekylArchivalCreditPair {
            bond_idx: 3,
            shard_idx: 0,
        },
    ];
    let mut r_market = [u64::MAX; 1];
    let mut sigma = u64::MAX;
    let code = unsafe {
        shekyl_archival_epoch_close_compute(
            5,
            5 * SETTLEMENT_EPOCH_BLOCKS,
            bonds.as_ptr(),
            bonds.len(),
            shards.as_ptr(),
            shards.len(),
            pairs.as_ptr(),
            pairs.len(),
            r_market.as_mut_ptr(),
            ptr::from_mut(&mut sigma),
        )
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_EPOCH_CLOSE_OK);
    assert_eq!(r_market, [2]);

    // Cross-check against the pure crate computation with the same pins.
    let bad: Vec<BadInterval> = vec![BadInterval {
        start_epoch: 0,
        end_exclusive: u64::MAX,
    }];
    let rust_bonds = [
        EpochCloseBond {
            join_settlement_epoch: 0,
            is_foundation_complete_tree: false,
            bad_intervals: &[],
        },
        EpochCloseBond {
            join_settlement_epoch: 0,
            is_foundation_complete_tree: false,
            bad_intervals: &[],
        },
        EpochCloseBond {
            join_settlement_epoch: 0,
            is_foundation_complete_tree: false,
            bad_intervals: &bad,
        },
        EpochCloseBond {
            join_settlement_epoch: 0,
            is_foundation_complete_tree: true,
            bad_intervals: &[],
        },
    ];
    let rust_shards = [EpochCloseShard {
        shard_id: 7,
        has_segment: true,
        freeze_height: 0,
    }];
    let rust_pairs: Vec<CreditPair> = (0..4)
        .map(|bond_idx| CreditPair {
            bond_idx,
            shard_idx: 0,
        })
        .collect();
    let expected = epoch_close_compute(&EpochCloseInputs {
        settlement_epoch: 5,
        close_block_height: 5 * SETTLEMENT_EPOCH_BLOCKS,
        settlement_epoch_blocks: SETTLEMENT_EPOCH_BLOCKS,
        age_weight_milli: ARCHIVAL_REWARD_AGE_WEIGHT_MILLI,
        bonds: &rust_bonds,
        shards: &rust_shards,
        credit_pairs: &rust_pairs,
    })
    .unwrap();
    assert_eq!(sigma, expected.sigma_work_milli);
    assert!(
        sigma > 0,
        "two members with work must produce nonzero Σwork"
    );
}

/// M-2 supply-conservation identity at the FFI boundary
/// (`REWARD_EMISSION_E3_GATING_ROUND.md` §3 item 2): summing
/// `shekyl_archival_emission_epoch_work`'s capped term over every gathered
/// bond reproduces the close's persisted `Σwork(E)` exactly. Verify's
/// per-P numerator and close's denominator come from the same sourcing
/// function over the same rows, so `Σ_P Curve(work_P) == Σwork` is an
/// identity, not an approximation; non-members (slashed, foundation
/// complete-tree) contribute zero to both sides.
#[test]
fn emission_epoch_work_sums_to_persisted_sigma() {
    let slashed = [0u64, u64::MAX];
    let bonds = [
        ShekylArchivalEpochCloseBond {
            join_settlement_epoch: 0,
            bad_intervals_ptr: ptr::null(),
            bad_intervals_len: 0,
            is_foundation_complete_tree: 0,
        },
        ShekylArchivalEpochCloseBond {
            join_settlement_epoch: 0,
            bad_intervals_ptr: ptr::null(),
            bad_intervals_len: 0,
            is_foundation_complete_tree: 0,
        },
        ShekylArchivalEpochCloseBond {
            join_settlement_epoch: 0,
            bad_intervals_ptr: slashed.as_ptr(),
            bad_intervals_len: 1,
            is_foundation_complete_tree: 0,
        },
        ShekylArchivalEpochCloseBond {
            join_settlement_epoch: 0,
            bad_intervals_ptr: ptr::null(),
            bad_intervals_len: 0,
            is_foundation_complete_tree: 1,
        },
    ];
    let shards = [
        ShekylArchivalEpochCloseShard {
            shard_id: 7,
            freeze_height: 0,
            has_segment: 1,
        },
        ShekylArchivalEpochCloseShard {
            shard_id: 9,
            freeze_height: 2 * SETTLEMENT_EPOCH_BLOCKS,
            has_segment: 1,
        },
    ];
    // Asymmetric work: bond 0 serves both shards, bond 1 one shard, so
    // the identity is exercised with distinct per-P terms.
    let pairs = [
        ShekylArchivalCreditPair {
            bond_idx: 0,
            shard_idx: 0,
        },
        ShekylArchivalCreditPair {
            bond_idx: 0,
            shard_idx: 1,
        },
        ShekylArchivalCreditPair {
            bond_idx: 1,
            shard_idx: 0,
        },
        ShekylArchivalCreditPair {
            bond_idx: 2,
            shard_idx: 0,
        },
        ShekylArchivalCreditPair {
            bond_idx: 3,
            shard_idx: 1,
        },
    ];

    let mut r_market = [u64::MAX; 2];
    let mut sigma = u64::MAX;
    let code = unsafe {
        shekyl_archival_epoch_close_compute(
            5,
            6 * SETTLEMENT_EPOCH_BLOCKS,
            bonds.as_ptr(),
            bonds.len(),
            shards.as_ptr(),
            shards.len(),
            pairs.as_ptr(),
            pairs.len(),
            r_market.as_mut_ptr(),
            ptr::from_mut(&mut sigma),
        )
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_EPOCH_CLOSE_OK);
    assert!(sigma > 0, "fixture must close with nonzero Σwork");

    let snapshot_for = |claimant_bond_idx: usize| ShekylArchivalEmissionEpochSnapshot {
        settlement_epoch: 5,
        close_block_height: 6 * SETTLEMENT_EPOCH_BLOCKS,
        sigma_work_milli: sigma,
        // Numerator-path test: the budget close row is not consulted by
        // the epoch-work FFI (only the vin-verify body divides by it).
        budget_atomic: 0,
        bonds_ptr: bonds.as_ptr(),
        bonds_len: bonds.len(),
        shards_ptr: shards.as_ptr(),
        shards_len: shards.len(),
        credit_pairs_ptr: pairs.as_ptr(),
        credit_pairs_len: pairs.len(),
        claimant_bond_idx,
    };

    let mut credited_terms: Vec<u64> = Vec::with_capacity(bonds.len());
    for idx in 0..bonds.len() {
        let snap = snapshot_for(idx);
        let mut work = u64::MAX;
        let mut credited = u64::MAX;
        let code = unsafe {
            shekyl_archival_emission_epoch_work(
                ptr::from_ref(&snap),
                ptr::from_mut(&mut work),
                ptr::from_mut(&mut credited),
            )
        };
        assert_eq!(code, SHEKYL_ARCHIVAL_EPOCH_CLOSE_OK);
        if idx >= 2 {
            assert_eq!(work, 0, "non-member bond {idx} must have zero work");
            assert_eq!(
                credited, 0,
                "non-member bond {idx} must have zero credited term"
            );
        } else {
            assert!(work > 0, "member bond {idx} must have nonzero work");
        }
        credited_terms.push(credited);
    }
    let credited_sum: u64 = credited_terms.iter().sum();
    assert_eq!(
        credited_sum, sigma,
        "sum of per-P credited terms must equal the persisted Σwork(E)"
    );
    // Reuse the per-bond terms already computed above rather than
    // re-invoking the FFI: the two members must differ for the identity to
    // be non-trivial.
    assert_ne!(
        credited_terms[0], credited_terms[1],
        "fixture must produce distinct per-P terms for the identity to be non-trivial"
    );

    // No credit row for P (claimant_bond_idx == SIZE_MAX): zero work by
    // construction, OK status.
    let snap = snapshot_for(usize::MAX);
    let mut work = u64::MAX;
    let mut credited = u64::MAX;
    let code = unsafe {
        shekyl_archival_emission_epoch_work(
            ptr::from_ref(&snap),
            ptr::from_mut(&mut work),
            ptr::from_mut(&mut credited),
        )
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_EPOCH_CLOSE_OK);
    assert_eq!(work, 0);
    assert_eq!(credited, 0);

    // Out-of-range claimant index (not the SIZE_MAX sentinel) rejects and
    // zeroes outputs.
    let snap = snapshot_for(bonds.len());
    let mut work = u64::MAX;
    let mut credited = u64::MAX;
    let code = unsafe {
        shekyl_archival_emission_epoch_work(
            ptr::from_ref(&snap),
            ptr::from_mut(&mut work),
            ptr::from_mut(&mut credited),
        )
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_INDEX_RANGE);
    assert_eq!(work, 0, "failure path must not leave stale outputs");
    assert_eq!(credited, 0);
}

/// The close-processing boundary wrapper single-sources
/// `consensus_state::epoch_close_height`: `(E+1)·SEB`, one above the
/// settlement close height, 0 for the overflowing epoch.
#[test]
fn epoch_close_processing_height_wrapper() {
    assert_eq!(
        shekyl_archival_epoch_close_processing_height(0),
        SETTLEMENT_EPOCH_BLOCKS
    );
    assert_eq!(
        shekyl_archival_epoch_close_processing_height(5),
        6 * SETTLEMENT_EPOCH_BLOCKS
    );
    assert_eq!(
        shekyl_archival_epoch_close_processing_height(5),
        shekyl_archival_epoch_close_height(5) + 1
    );
    assert_eq!(shekyl_archival_epoch_close_processing_height(u64::MAX), 0);
}

#[test]
fn epoch_close_compute_ffi_rejects_bad_indices_and_zeroes_outputs() {
    let shards = [ShekylArchivalEpochCloseShard {
        shard_id: 7,
        freeze_height: 0,
        has_segment: 1,
    }];
    let pairs = [ShekylArchivalCreditPair {
        bond_idx: 3,
        shard_idx: 0,
    }];
    let mut r_market = [u64::MAX; 1];
    let mut sigma = u64::MAX;
    let code = unsafe {
        shekyl_archival_epoch_close_compute(
            5,
            5 * SETTLEMENT_EPOCH_BLOCKS,
            ptr::null(),
            0,
            shards.as_ptr(),
            shards.len(),
            pairs.as_ptr(),
            pairs.len(),
            r_market.as_mut_ptr(),
            ptr::from_mut(&mut sigma),
        )
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_INDEX_RANGE);
    assert_eq!(r_market, [0], "failure path must not leave stale outputs");
    assert_eq!(sigma, 0);

    let code = unsafe {
        shekyl_archival_epoch_close_compute(
            5,
            5 * SETTLEMENT_EPOCH_BLOCKS,
            ptr::null(),
            0,
            shards.as_ptr(),
            shards.len(),
            pairs.as_ptr(),
            pairs.len(),
            ptr::null_mut(),
            ptr::from_mut(&mut sigma),
        )
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_NULL_PTR);
}

#[test]
fn claimed_epochs_check_and_set_ffi_write_back_and_polarity() {
    // Value-preserving: MAX_CLAIMED_EPOCH_ENTRIES is const-asserted == 32.
    #[allow(clippy::cast_possible_truncation)]
    const CAP: usize = MAX_CLAIMED_EPOCH_ENTRIES as usize;
    let mut buf = [0u64; CAP];
    let mut len: usize = 0;

    // Insert into an empty set.
    let code = unsafe {
        shekyl_archival_claimed_epochs_check_and_set(
            buf.as_mut_ptr(),
            ptr::from_mut(&mut len),
            CAP,
            10,
            12,
        )
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_INSERTED);
    assert_eq!(&buf[..len], &[10]);

    // Dedup hit leaves the buffer untouched.
    let code = unsafe {
        shekyl_archival_claimed_epochs_check_and_set(
            buf.as_mut_ptr(),
            ptr::from_mut(&mut len),
            CAP,
            10,
            12,
        )
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ALREADY_CLAIMED);
    assert_eq!(&buf[..len], &[10]);

    // Not-settled and expired map to their own codes without mutation.
    let code = unsafe {
        shekyl_archival_claimed_epochs_check_and_set(
            buf.as_mut_ptr(),
            ptr::from_mut(&mut len),
            CAP,
            12,
            12,
        )
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_NOT_SETTLED);
    let far_future = MAX_CLAIM_AGE_W + 100;
    let code = unsafe {
        shekyl_archival_claimed_epochs_check_and_set(
            buf.as_mut_ptr(),
            ptr::from_mut(&mut len),
            CAP,
            1,
            far_future,
        )
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_EXPIRED);
    assert_eq!(&buf[..len], &[10]);

    // A window-advancing insert prunes stale entries in the write-back:
    // epoch 10 falls below `far_future − W` and is evicted.
    let code = unsafe {
        shekyl_archival_claimed_epochs_check_and_set(
            buf.as_mut_ptr(),
            ptr::from_mut(&mut len),
            CAP,
            far_future - 1,
            far_future,
        )
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_INSERTED);
    assert_eq!(&buf[..len], &[far_future - 1]);

    // Null pointers and a non-increasing buffer reject as invalid.
    let code = unsafe {
        shekyl_archival_claimed_epochs_check_and_set(
            ptr::null_mut(),
            ptr::from_mut(&mut len),
            CAP,
            5,
            12,
        )
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_INVALID);
    let mut bad = [7u64, 7u64];
    let mut bad_len: usize = 2;
    let code = unsafe {
        shekyl_archival_claimed_epochs_check_and_set(
            bad.as_mut_ptr(),
            ptr::from_mut(&mut bad_len),
            2,
            5,
            12,
        )
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_INVALID);
}

// -----------------------------------------------------------------------
// C-1 emission-vin FFI (`shekyl_archival_emission_vin_extract`,
// `shekyl_emission_vin_verify`). The honest fixture mirrors the crate KAT
// (`emission_verify_kat.rs`) but is recomputed with the FFI's own pinned
// consensus constants (plateau curve), so the test
// exercises the exact operand plumbing the C++ dispatch will use.
// -----------------------------------------------------------------------

use shekyl_archival_retention::{
    reward_share_floor, sigma_work_milli, EmissionAuthRole, MembershipOnlyBacking, ShardWorkEntry,
    WorkEpochClaim,
};
use shekyl_crypto_pq::derivation::hash_pqc_public_key;
use shekyl_crypto_pq::multisig::{SINGLE_KEY_CANONICAL_LEN, SINGLE_SIG_CANONICAL_LEN};

const EM_EPOCH: u64 = 5;
const EM_BUDGET: u64 = 1_000_000;
const EM_SHARD_A: u64 = 7;
const EM_SHARD_B: u64 = 9;

/// Owned honest-emission scenario: two bonds (idx 0 = claimant on shard A
/// only; idx 1 on A and B, so `R_market(A) = 2`), real hybrid keypairs and
/// signatures over the vin's own Q1 role messages, work/reward derived
/// through the same sourcing functions the FFI verify recomputes with.
/// The backing proof is garbage bytes — step 6 is pinned positive in
/// `shekyl-fcmp`'s KATs; here it is the terminal rejection that proves
/// steps 1–5 and 8 already passed through the marshaling.
struct EmissionFfiFixture {
    vin_bytes: Vec<u8>,
    p_pubkey: Vec<u8>,
    commits_flat: Vec<u8>,
    tx_hash: [u8; 32],
    reward: u64,
    sigma: u64,
    close: u64,
    ffi_bonds: Vec<ShekylArchivalEpochCloseBond>,
    ffi_shards: Vec<ShekylArchivalEpochCloseShard>,
    ffi_pairs: Vec<ShekylArchivalCreditPair>,
}

impl EmissionFfiFixture {
    fn build() -> Self {
        let close = epoch_close_height(EM_EPOCH).expect("fixture epoch closes");
        let bonds = [
            EpochCloseBond {
                join_settlement_epoch: 1,
                is_foundation_complete_tree: false,
                bad_intervals: &[],
            },
            EpochCloseBond {
                join_settlement_epoch: 1,
                is_foundation_complete_tree: false,
                bad_intervals: &[],
            },
        ];
        let shards = [
            EpochCloseShard {
                shard_id: EM_SHARD_A,
                has_segment: true,
                freeze_height: close - 5_000,
            },
            EpochCloseShard {
                shard_id: EM_SHARD_B,
                has_segment: true,
                freeze_height: close - 8_000,
            },
        ];
        let pairs = [
            CreditPair {
                bond_idx: 0,
                shard_idx: 0,
            },
            CreditPair {
                bond_idx: 1,
                shard_idx: 0,
            },
            CreditPair {
                bond_idx: 1,
                shard_idx: 1,
            },
        ];
        let inputs = EpochCloseInputs {
            settlement_epoch: EM_EPOCH,
            close_block_height: close,
            settlement_epoch_blocks: SETTLEMENT_EPOCH_BLOCKS,
            age_weight_milli: ARCHIVAL_REWARD_AGE_WEIGHT_MILLI,
            bonds: &bonds,
            shards: &shards,
            credit_pairs: &pairs,
        };
        let served = as_of_e_served_work(&inputs).expect("well-formed fixture");
        let work = served.work_by_bond[0];
        // Single-shard fixture ⇒ the sole entry's micro scarcity is the whole
        // per-bond micro sum; the wire carries micro, so verify's micro-space
        // aggregate compare demands this exact value (D1 fix).
        let work_micro = served.work_micro_by_bond[0];
        assert!(served.member[0] && work > 0, "fixture claimant must earn");
        let sigma = sigma_work_milli(&served.work_by_bond, &served.member);
        // D3/R2: no plateau in the reward path — the credited term is the work.
        let reward = reward_share_floor(EM_BUDGET, work, sigma);
        assert!(reward > 0, "fixture reward must be wire-encodable (>0)");

        let scheme = HybridEd25519MlDsa;
        let (p_pk, p_sk) = scheme
            .generate_ephemeral_keypair_for_tests()
            .expect("P keypair");
        let (b_pk, b_sk) = scheme
            .generate_ephemeral_keypair_for_tests()
            .expect("backing keypair");
        let mut vin = ArchivalRewardEmissionVin {
            p_pubkey: p_pk.to_canonical_bytes().expect("canonical P pubkey"),
            holdings: HoldingsDescriptor {
                kind: HoldingsKind::ShardSetCompact,
                shard_ids: ShardSet::new(vec![EM_SHARD_A]).unwrap(),
            },
            settlement_epochs: vec![EM_EPOCH],
            work_claim: vec![WorkEpochClaim {
                epoch: EM_EPOCH,
                shard_entries: vec![ShardWorkEntry {
                    shard_id: EM_SHARD_A,
                    serve_credit_bit: true,
                    scarcity_micro: u32::try_from(work_micro).expect("fixture scarcity fits u32"),
                }],
            }],
            backing: MembershipOnlyBacking {
                proof: vec![0xAB; 64],
                pseudo_out: [0x22; 32],
                pqc_pk_hash: [0; 32],
                backing_pubkey: b_pk.to_canonical_bytes().expect("canonical backing pubkey"),
                tree_depth: 3,
            },
            reward_amount_plain: vec![reward],
            auth_backing: vec![0x55; SINGLE_SIG_CANONICAL_LEN],
            auth_claim: vec![0x66; SINGLE_SIG_CANONICAL_LEN],
        };
        vin.backing.pqc_pk_hash = hash_pqc_public_key(&vin.backing.backing_pubkey);
        assert_eq!(vin.p_pubkey.len(), SINGLE_KEY_CANONICAL_LEN);

        let commits = [RewardCommit {
            commitment: [0x71; 32],
            amount_plain: reward,
            one_time_key: [0x72; 32],
        }];
        let tx_hash = [0x5F; 32];
        let msgs = vin.auth_msgs(&commits, &tx_hash).expect("role messages");
        vin.auth_backing = scheme
            .sign(
                &b_sk,
                shekyl_crypto_pq::signature::SCHEME_DOMAIN_EMISSION_BACKING,
                &msgs.backing,
            )
            .expect("backing sign")
            .to_canonical_bytes()
            .expect("canonical backing sig");
        vin.auth_claim = scheme
            .sign(
                &p_sk,
                shekyl_crypto_pq::signature::SCHEME_DOMAIN_EMISSION_CLAIM,
                &msgs.claim,
            )
            .expect("claim sign")
            .to_canonical_bytes()
            .expect("canonical claim sig");

        let mut commits_flat = Vec::with_capacity(72);
        commits_flat.extend_from_slice(&commits[0].commitment);
        commits_flat.extend_from_slice(&commits[0].amount_plain.to_le_bytes());
        commits_flat.extend_from_slice(&commits[0].one_time_key);

        Self {
            p_pubkey: vin.p_pubkey.clone(),
            vin_bytes: vin.serialize().expect("canonical wire"),
            commits_flat,
            tx_hash,
            reward,
            sigma,
            close,
            ffi_bonds: bonds
                .iter()
                .map(|b| ShekylArchivalEpochCloseBond {
                    join_settlement_epoch: b.join_settlement_epoch,
                    bad_intervals_ptr: ptr::null(),
                    bad_intervals_len: 0,
                    is_foundation_complete_tree: 0,
                })
                .collect(),
            ffi_shards: shards
                .iter()
                .map(|s| ShekylArchivalEpochCloseShard {
                    shard_id: s.shard_id,
                    freeze_height: s.freeze_height,
                    has_segment: 1,
                })
                .collect(),
            ffi_pairs: pairs
                .iter()
                .map(|p| ShekylArchivalCreditPair {
                    bond_idx: p.bond_idx,
                    shard_idx: p.shard_idx,
                })
                .collect(),
        }
    }

    fn snapshot(&self) -> ShekylArchivalEmissionEpochSnapshot {
        ShekylArchivalEmissionEpochSnapshot {
            settlement_epoch: EM_EPOCH,
            close_block_height: self.close,
            sigma_work_milli: self.sigma,
            budget_atomic: EM_BUDGET,
            bonds_ptr: self.ffi_bonds.as_ptr(),
            bonds_len: self.ffi_bonds.len(),
            shards_ptr: self.ffi_shards.as_ptr(),
            shards_len: self.ffi_shards.len(),
            credit_pairs_ptr: self.ffi_pairs.as_ptr(),
            credit_pairs_len: self.ffi_pairs.len(),
            claimant_bond_idx: 0,
        }
    }

    /// One coarse verify crossing with the honest operands, with the two
    /// knobs the negatives vary. Returns `(code, total_reward, epochs)`.
    fn verify(&self, bond_present: u8, tx_hash: &[u8; 32]) -> (u8, u64, Vec<u64>) {
        let snapshots = [self.snapshot()];
        let bond_shard_ids = [EM_SHARD_A];
        let tree_root = [0u8; 32];
        let mut out_total = u64::MAX;
        let mut out_epochs = [u64::MAX; 4];
        let mut out_len = usize::MAX;
        let code = unsafe {
            shekyl_emission_vin_verify(
                self.vin_bytes.as_ptr(),
                self.vin_bytes.len(),
                self.close + 1,
                self.reward,
                bond_present,
                1,
                HoldingsKind::ShardSetCompact as u8,
                bond_shard_ids.as_ptr(),
                bond_shard_ids.len(),
                ptr::null(),
                0,
                snapshots.as_ptr(),
                snapshots.len(),
                tree_root.as_ptr(),
                3,
                tx_hash.as_ptr(),
                self.commits_flat.as_ptr(),
                1,
                ptr::from_mut(&mut out_total),
                out_epochs.as_mut_ptr(),
                out_epochs.len(),
                ptr::from_mut(&mut out_len),
            )
        };
        assert!(
            out_len <= out_epochs.len(),
            "out_epochs_len must be written"
        );
        (code, out_total, out_epochs[..out_len].to_vec())
    }
}

/// Extract roundtrip: the pre-parse call surfaces `P_canonical_id`
/// (recomputed from `P_pubkey`) and the claimed epochs from the opaque
/// blob; truncated bytes and an undersized epoch buffer reject with
/// zeroed outputs.
#[test]
fn emission_vin_extract_roundtrip_and_rejects() {
    let fx = EmissionFfiFixture::build();

    let mut pid = [0u8; 32];
    let mut epochs = [u64::MAX; 4];
    let mut epochs_len = usize::MAX;
    let code = unsafe {
        shekyl_archival_emission_vin_extract(
            fx.vin_bytes.as_ptr(),
            fx.vin_bytes.len(),
            pid.as_mut_ptr(),
            epochs.as_mut_ptr(),
            epochs.len(),
            ptr::from_mut(&mut epochs_len),
        )
    };
    assert_eq!(code, SHEKYL_EMISSION_VIN_OK);
    assert_eq!(epochs_len, 1);
    assert_eq!(epochs[0], EM_EPOCH);
    assert_eq!(
        &pid,
        p_canonical_id_from_hybrid_pubkey(&fx.p_pubkey).as_bytes(),
        "extract must key the bond record by the §6.1 canonical id"
    );

    // Truncated wire rejects (and a trailing byte would too: the parse is
    // length-exact).
    let mut epochs_len = usize::MAX;
    let code = unsafe {
        shekyl_archival_emission_vin_extract(
            fx.vin_bytes.as_ptr(),
            fx.vin_bytes.len() - 1,
            pid.as_mut_ptr(),
            epochs.as_mut_ptr(),
            epochs.len(),
            ptr::from_mut(&mut epochs_len),
        )
    };
    assert_eq!(code, SHEKYL_EMISSION_VIN_ERR_WIRE);
    assert_eq!(epochs_len, 0, "failure path must not leave stale lengths");

    // Undersized epoch buffer and null pointers reject.
    let code = unsafe {
        shekyl_archival_emission_vin_extract(
            fx.vin_bytes.as_ptr(),
            fx.vin_bytes.len(),
            pid.as_mut_ptr(),
            epochs.as_mut_ptr(),
            0,
            ptr::from_mut(&mut epochs_len),
        )
    };
    assert_eq!(code, SHEKYL_EMISSION_VIN_ERR_NULL_PTR);
    let code = unsafe {
        shekyl_archival_emission_vin_extract(
            ptr::null(),
            0,
            pid.as_mut_ptr(),
            epochs.as_mut_ptr(),
            epochs.len(),
            ptr::from_mut(&mut epochs_len),
        )
    };
    assert_eq!(code, SHEKYL_EMISSION_VIN_ERR_NULL_PTR);
}

/// Block-level (P,E) uniqueness FFI over flattened 40-byte pairs — the
/// §6.4 KAT-1 shape (same-block double-claim) through the marshaling
/// boundary, plus the fail-closed null case.
#[test]
fn emission_block_claims_unique_ffi() {
    let flat = |pairs: &[([u8; 32], u64)]| -> Vec<u8> {
        let mut out = Vec::with_capacity(pairs.len() * 40);
        for (pid, epoch) in pairs {
            out.extend_from_slice(pid);
            out.extend_from_slice(&epoch.to_le_bytes());
        }
        out
    };
    let p = [0xaa; 32];
    let q = [0xbb; 32];

    // Distinct pairs (same P different E; different P same E) pass.
    let ok = flat(&[(p, 7), (p, 8), (q, 7)]);
    assert_eq!(
        unsafe { shekyl_emission_block_claims_unique(ok.as_ptr(), 3) },
        1
    );

    // Same-block duplicate (P, E) — non-adjacent — rejects.
    let dup = flat(&[(p, 7), (q, 3), (p, 7)]);
    assert_eq!(
        unsafe { shekyl_emission_block_claims_unique(dup.as_ptr(), 3) },
        0
    );

    // Empty block trivially unique; null with non-zero count fails closed.
    assert_eq!(
        unsafe { shekyl_emission_block_claims_unique(ptr::null(), 0) },
        1
    );
    assert_eq!(
        unsafe { shekyl_emission_block_claims_unique(ptr::null(), 1) },
        0
    );
}

/// End-to-end coarse verify over the honest fixture: claims (steps 1–5)
/// and the hybrid auth gate (step 8) pass through the full FFI
/// marshaling — snapshots, bond record, flattened reward commits — and
/// the call terminates at step 6 rejecting the garbage backing proof.
/// Reaching `BACKING_REJECTED` (not any earlier code) is the assertion:
/// it proves the DoS ordering (auth before backing) and that every
/// marshaled operand reproduced the crate-level honest fixture.
#[test]
fn emission_vin_verify_ffi_marshals_honest_operands_to_step_6() {
    let fx = EmissionFfiFixture::build();

    let (code, total, epochs) = fx.verify(1, &fx.tx_hash);
    assert_eq!(
        code, SHEKYL_EMISSION_VIN_ERR_BACKING_REJECTED,
        "honest claims + auths must reach (and stop at) the garbage proof"
    );
    assert_eq!(total, 0, "rejection must zero the mint output");
    assert!(epochs.is_empty(), "rejection must zero the commit set");

    // Auth-before-backing ordering: a tampered tx context breaks the Q1
    // binding messages, so the same vin now rejects at step 8 — earlier
    // than the backing proof it rejected at above.
    let mut wrong_hash = fx.tx_hash;
    wrong_hash[0] ^= 0x01;
    let (code, total, epochs) = fx.verify(1, &wrong_hash);
    assert_eq!(code, SHEKYL_EMISSION_VIN_ERR_AUTH_REJECTED);
    assert_eq!(total, 0);
    assert!(epochs.is_empty());

    // Step 2: no bond record marshaled (`bond_present == 0`).
    let (code, total, epochs) = fx.verify(0, &fx.tx_hash);
    assert_eq!(code, SHEKYL_EMISSION_VIN_ERR_BOND_MISSING);
    assert_eq!(total, 0);
    assert!(epochs.is_empty());
}

/// Marshaling negatives for the coarse verify: truncated wire, null
/// pointers, and the diagnostic error-code map for the auth variants the
/// C ABI collapses.
#[test]
fn emission_vin_verify_ffi_rejects_bad_marshaling() {
    let fx = EmissionFfiFixture::build();
    let snapshots = [fx.snapshot()];
    let tree_root = [0u8; 32];
    let mut out_total = u64::MAX;
    let mut out_epochs = [u64::MAX; 4];
    let mut out_len = usize::MAX;

    // Truncated vin bytes fail the length-exact parse.
    let code = unsafe {
        shekyl_emission_vin_verify(
            fx.vin_bytes.as_ptr(),
            fx.vin_bytes.len() - 1,
            fx.close + 1,
            fx.reward,
            0,
            0,
            0,
            ptr::null(),
            0,
            ptr::null(),
            0,
            snapshots.as_ptr(),
            snapshots.len(),
            tree_root.as_ptr(),
            3,
            fx.tx_hash.as_ptr(),
            fx.commits_flat.as_ptr(),
            1,
            ptr::from_mut(&mut out_total),
            out_epochs.as_mut_ptr(),
            out_epochs.len(),
            ptr::from_mut(&mut out_len),
        )
    };
    assert_eq!(code, SHEKYL_EMISSION_VIN_ERR_WIRE);
    assert_eq!(out_total, 0, "failure path must not leave stale outputs");
    assert_eq!(out_len, 0);

    // Null vin pointer rejects before any parse.
    let code = unsafe {
        shekyl_emission_vin_verify(
            ptr::null(),
            0,
            fx.close + 1,
            fx.reward,
            0,
            0,
            0,
            ptr::null(),
            0,
            ptr::null(),
            0,
            snapshots.as_ptr(),
            snapshots.len(),
            tree_root.as_ptr(),
            3,
            fx.tx_hash.as_ptr(),
            fx.commits_flat.as_ptr(),
            1,
            ptr::from_mut(&mut out_total),
            out_epochs.as_mut_ptr(),
            out_epochs.len(),
            ptr::from_mut(&mut out_len),
        )
    };
    assert_eq!(code, SHEKYL_EMISSION_VIN_ERR_NULL_PTR);

    // The C ABI's collapsed diagnostic map, pinned per auth variant.
    assert_eq!(
        map_emission_vin_error(&EmissionVerifyError::AuthMalformed {
            role: EmissionAuthRole::Claim
        }),
        SHEKYL_EMISSION_VIN_ERR_AUTH_MALFORMED
    );
    assert_eq!(
        map_emission_vin_error(&EmissionVerifyError::AuthRejected {
            role: EmissionAuthRole::Backing
        }),
        SHEKYL_EMISSION_VIN_ERR_AUTH_REJECTED
    );
}
