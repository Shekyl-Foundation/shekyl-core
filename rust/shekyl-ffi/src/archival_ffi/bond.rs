// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bond-post verify / connect / pop FFI (JoinMarket, Unbond, HoldingsUpdate, Rebond).

use shekyl_archival_retention::{
    debit_auth_pin, holdings_update_add_connect, holdings_update_drop_connect, holdings_update_pop,
    rebond_connect, rebond_pop, unbond_connect, unbond_pop, verify_holdings_update_add,
    verify_holdings_update_drop, verify_join_market_bond_post, verify_rebond_bond_post,
    verify_unbond_bond_post, whole_record_last_served, ArchivalBondPostVin, BadInterval,
    BondPostKind, DebitAuthError, HoldingsDescriptor, HoldingsKind, LastServedScan, ShardSet,
    ShardSetError, HYBRID_PUBKEY_CANONICAL_BYTES,
};

use super::codes::*;
use super::epoch_close::gather_bad_intervals;

fn holdings_kind_from_u8(kind: u8) -> Result<HoldingsKind, u8> {
    HoldingsKind::from_u8(kind).map_err(|_| SHEKYL_ARCHIVAL_BOND_POST_ERR_HOLDINGS_KIND)
}

/// Run `f` over a bound-checked `&[u64]` marshaled from a raw C pointer at the
/// bond-post FFI boundary (shared by the JoinMarket and Unbond entry points).
///
/// `len == 0` passes an empty slice (a null pointer is allowed only then). A null
/// pointer with a positive `len` is a caller marshaling bug (`ERR_NULL_PTR`), and a
/// `len` whose byte span (`len * size_of::<u64>()`) would exceed `isize::MAX` — the
/// soundness precondition of [`std::slice::from_raw_parts`] — is rejected
/// (`ERR_LEN_OVERFLOW`) rather than invoking undefined behavior on a corrupted or
/// hostile length. The slice is confined to `f`, so no caller can name its lifetime
/// or let it escape the pointer's validity window.
///
/// # Safety
/// When `len > 0`, `ptr` must be valid for `len` `u64`s for the duration of the call.
unsafe fn with_bond_post_u64_slice<R>(
    ptr: *const u64,
    len: usize,
    f: impl FnOnce(&[u64]) -> R,
) -> Result<R, u8> {
    if len == 0 {
        return Ok(f(&[]));
    }
    if ptr.is_null() {
        return Err(SHEKYL_ARCHIVAL_BOND_POST_ERR_NULL_PTR);
    }
    let Some(byte_len) = len.checked_mul(std::mem::size_of::<u64>()) else {
        return Err(SHEKYL_ARCHIVAL_BOND_POST_ERR_LEN_OVERFLOW);
    };
    if byte_len > isize::MAX as usize {
        return Err(SHEKYL_ARCHIVAL_BOND_POST_ERR_LEN_OVERFLOW);
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    Ok(f(slice))
}

/// [`with_bond_post_u64_slice`]'s byte twin, for the `bond_spend_pk` marshal.
/// Same contract: `len == 0` passes an empty slice, a null pointer with a
/// positive `len` is `ERR_NULL_PTR`, and a `len` past the `from_raw_parts`
/// `isize::MAX` soundness bound is `ERR_LEN_OVERFLOW`.
///
/// # Safety
/// When `len > 0`, `ptr` must be valid for `len` bytes for the duration of the call.
unsafe fn with_bond_post_u8_slice<R>(
    ptr: *const u8,
    len: usize,
    f: impl FnOnce(&[u8]) -> R,
) -> Result<R, u8> {
    if len == 0 {
        return Ok(f(&[]));
    }
    if ptr.is_null() {
        return Err(SHEKYL_ARCHIVAL_BOND_POST_ERR_NULL_PTR);
    }
    if len > isize::MAX as usize {
        return Err(SHEKYL_ARCHIVAL_BOND_POST_ERR_LEN_OVERFLOW);
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    Ok(f(slice))
}

/// Marshal the shared bond-post args into an [`ArchivalBondPostVin`] for the JoinMarket
/// and Unbond FFI entry points. The `post_kind` byte is decoded at each call site (the
/// two name an out-of-range byte differently — `ERR_POST_KIND` vs
/// `ERR_POST_KIND_NOT_UNBOND`), so it arrives here already typed. The C++ hybrid pubkey
/// and `P_id` hint stay consensus-side, so the vin carries placeholders for them.
///
/// `bond_spend_pk` is marshaled for real, NOT placeholdered: the §9.11 coupling
/// (JoinMarket iff exact-canonical-length key) is structural in
/// [`ArchivalBondPostVin`] — `serialize()` refuses a violating vin — and unlike
/// the consensus-side placeholders above, an empty key is a *valid* wire shape
/// for the debit kinds, so a placeholder would silently satisfy the wrong
/// invariant. The marshaler enforces the coupling (`ERR_BOND_SPEND_PK_COUPLING`)
/// instead of constructing a violating vin. (The key is authorized on-chain by
/// P's surface-A `pqc_auths` signature over the whole-tx payload, not by an
/// on-vin blob — SA-2b, SIGNATURE_ALIGNMENT.md §2.2.)
///
/// # Safety
/// `shard_ids_ptr` must be valid for `shard_ids_len` `u64`s, or null when the len is 0;
/// `bond_spend_pk_ptr` must be valid for `bond_spend_pk_len` bytes, or null when the
/// len is 0.
#[allow(clippy::too_many_arguments)] // coarse-call FFI: mirrors the entry points' flat operand list
unsafe fn bond_post_vin_from_raw(
    post_kind: BondPostKind,
    holdings_kind: u8,
    shard_ids_ptr: *const u64,
    shard_ids_len: usize,
    bond_spend_pk_ptr: *const u8,
    bond_spend_pk_len: usize,
    bonded_total_atomic: u64,
    bond_credit: u64,
    bond_debit: u64,
) -> Result<ArchivalBondPostVin, u8> {
    let shard_ids_raw =
        unsafe { with_bond_post_u64_slice(shard_ids_ptr, shard_ids_len, <[u64]>::to_vec) }?;
    // The wire decoder validates the vin's shard list through `ShardSet::new`;
    // this marshal is a second decoder for the same wire object, so it routes
    // through the identical constructor — the bound AND duplicate-freeness are
    // unrepresentable-if-violated past the FFI boundary for EVERY post kind, not
    // a case each downstream verify must re-guard (`bond_floor` collapses to an
    // in-band 0 on oversize, which let an unguarded verify read it as the empty
    // exit shape; and a duplicate silently double-counted the floor).
    let shard_ids = ShardSet::new(shard_ids_raw).map_err(|e| match e {
        ShardSetError::CountExceeded { .. } => {
            SHEKYL_ARCHIVAL_BOND_POST_ERR_HOLDINGS_COUNT_EXCEEDED
        }
        ShardSetError::Duplicate { .. } => SHEKYL_ARCHIVAL_BOND_POST_ERR_HOLDINGS_DUPLICATE_SHARD,
    })?;
    let bond_spend_pk =
        unsafe { with_bond_post_u8_slice(bond_spend_pk_ptr, bond_spend_pk_len, <[u8]>::to_vec) }?;
    let coupling_ok = if post_kind == BondPostKind::JoinMarket {
        bond_spend_pk.len() == HYBRID_PUBKEY_CANONICAL_BYTES
    } else {
        bond_spend_pk.is_empty()
    };
    if !coupling_ok {
        return Err(SHEKYL_ARCHIVAL_BOND_POST_ERR_BOND_SPEND_PK_COUPLING);
    }
    let holdings_kind = holdings_kind_from_u8(holdings_kind)?;
    Ok(ArchivalBondPostVin {
        hybrid_public_key: Vec::new(),
        p_canonical_id: [0u8; 32],
        post_kind,
        bond_spend_pk,
        holdings: HoldingsDescriptor {
            kind: holdings_kind,
            shard_ids,
        },
        bonded_total_atomic,
        bond_credit,
        bond_debit,
    })
}

/// Verify JoinMarket bond-post semantics after C++ hybrid-pubkey and `P_id` checks.
///
/// Hybrid pubkey bounds and `p_canonical_id` hint recompute stay in C++ consensus glue.
/// `record_exists` is `1` when LMDB already has a bond record for this `P_id`.
/// `bond_spend_pk_*` is the vin's GF-1 debit authorizer; the shared marshaler
/// enforces the §9.11 coupling (exact-canonical-length key iff JoinMarket,
/// `ERR_BOND_SPEND_PK_COUPLING` otherwise).
///
/// # Safety
/// `bond_spend_pk_ptr` must be valid for `bond_spend_pk_len` bytes, or null when
/// the len is 0.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_verify_join_market_bond_post(
    post_kind: u8,
    holdings_kind: u8,
    shard_ids_ptr: *const u64,
    shard_ids_len: usize,
    bond_spend_pk_ptr: *const u8,
    bond_spend_pk_len: usize,
    bonded_total_atomic: u64,
    bond_credit: u64,
    bond_debit: u64,
    record_exists: u8,
) -> u8 {
    let post_kind = match BondPostKind::from_u8(post_kind) {
        Ok(k) => k,
        Err(_) => return SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND,
    };
    let vin = match bond_post_vin_from_raw(
        post_kind,
        holdings_kind,
        shard_ids_ptr,
        shard_ids_len,
        bond_spend_pk_ptr,
        bond_spend_pk_len,
        bonded_total_atomic,
        bond_credit,
        bond_debit,
    ) {
        Ok(v) => v,
        Err(code) => return code,
    };
    match verify_join_market_bond_post(&vin, record_exists != 0) {
        Ok(()) => SHEKYL_ARCHIVAL_BOND_POST_OK,
        Err(e) => map_bond_post_error(e),
    }
}

/// Verify `Unbond` bond-post semantics after C++ hybrid-pubkey and `P_id` checks
/// (gate-4 §3.5 debit path; `PHASE_2B_FSM_RETOOL.md` P2B-8).
///
/// Marshaled facts (C++ owns the LMDB I/O): `record_exists` / `record_bonded_total` /
/// `record_bad_interval_count` from the bond record; `per_shard_last_served_*` is the
/// array of the **served** shards' last-served settlement epochs (never-served shards
/// omitted) from the reverse-cursor seeks over the serve-credit table — for a
/// `CompleteTree` record, from the all-shards `P`-prefix scan. The FFI folds them to
/// the whole-record release-cooldown anchor via [`whole_record_last_served`], keeping
/// the derivation and the verdict in Rust.
///
/// `last_settled_slash_epoch` is the slash scheduler's monotone watermark
/// (`archival_last_slash_epoch`), with `u64::MAX` meaning **no epoch settled yet** —
/// the scheduler's own storage sentinel, translated to `None` here. It gates the
/// release on every epoch through the anchor being slash-settled
/// (`release_cooldown::slashes_settled_through`; closes the one-block
/// connect-ordering race the module docs name).
/// # Safety
/// `bond_spend_pk_ptr` must be valid for `bond_spend_pk_len` bytes, or null when
/// the len is 0 (an `Unbond` vin never carries the §9.11 field, so a conforming
/// caller passes null/0; the shared marshaler rejects anything else as
/// `ERR_BOND_SPEND_PK_COUPLING`).
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_verify_unbond_bond_post(
    post_kind: u8,
    holdings_kind: u8,
    shard_ids_ptr: *const u64,
    shard_ids_len: usize,
    bond_spend_pk_ptr: *const u8,
    bond_spend_pk_len: usize,
    bonded_total_atomic: u64,
    bond_credit: u64,
    bond_debit: u64,
    record_exists: u8,
    record_bonded_total: u64,
    record_bad_interval_count: usize,
    per_shard_last_served_ptr: *const u64,
    per_shard_last_served_len: usize,
    last_settled_slash_epoch: u64,
    current_settlement_epoch: u64,
) -> u8 {
    let post_kind = match BondPostKind::from_u8(post_kind) {
        Ok(k) => k,
        Err(_) => return SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND_NOT_UNBOND,
    };
    let vin = match bond_post_vin_from_raw(
        post_kind,
        holdings_kind,
        shard_ids_ptr,
        shard_ids_len,
        bond_spend_pk_ptr,
        bond_spend_pk_len,
        bonded_total_atomic,
        bond_credit,
        bond_debit,
    ) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let record_bonded_total = if record_exists != 0 {
        Some(record_bonded_total)
    } else {
        None
    };
    // The cooldown anchor only gates a record that exists: a missing record is
    // rejected (`RECORD_MISSING`) before the cooldown check, so we neither require
    // the serve-credit pointer nor fold it when there is no record. This keeps the
    // record-missing verdict independent of cooldown marshaling and skips the
    // reverse-cursor fold on an already-invalid tx; `verify_unbond_bond_post`
    // remains the sole decider of record validity and the cooldown gate.
    let last_served_epoch = if record_bonded_total.is_some() {
        // The served shards' last-served epochs → the whole-record anchor (Rust);
        // never-served shards are omitted by C++, so an empty slice folds to `None`.
        match unsafe {
            with_bond_post_u64_slice(
                per_shard_last_served_ptr,
                per_shard_last_served_len,
                whole_record_last_served,
            )
        } {
            Ok(anchor) => anchor,
            Err(code) => return code,
        }
    } else {
        None
    };
    // u64::MAX is the scheduler's "no epoch settled yet" storage sentinel
    // (`get_archival_last_slash_epoch`'s initial value) — never a settled epoch.
    let last_settled_slash_epoch = if last_settled_slash_epoch == u64::MAX {
        None
    } else {
        Some(last_settled_slash_epoch)
    };
    match verify_unbond_bond_post(
        &vin,
        record_bonded_total,
        record_bad_interval_count,
        last_served_epoch,
        last_settled_slash_epoch,
        current_settlement_epoch,
    ) {
        Ok(()) => SHEKYL_ARCHIVAL_BOND_POST_OK,
        Err(e) => map_bond_post_error(e),
    }
}

/// Fold the served shards' last-served epochs into the whole-record
/// release-cooldown anchor — **the same fold** consensus applies inside
/// [`shekyl_archival_verify_unbond_bond_post`], exported so a marshaling caller
/// reports the anchor instead of deriving a second one.
///
/// The claim-source RPC is that caller: the wallet needs the anchor to answer
/// `unbond_readiness(P)` and to know whether an `Unbond` can verify at all, and
/// a C++-side or wallet-side re-fold would be a second derivation of a
/// consensus operand — the failure mode `close_block_height` already forbids
/// ("as the daemon sourced it; the wallet never re-derives").
///
/// Never-served shards are omitted by the caller's gather, so an empty slice is
/// the legitimate "record exists, nothing has served yet" case and folds to
/// *absent* rather than to an epoch. That distinction is load-bearing
/// downstream: `release_cooldown_elapsed` and `slashes_settled_through` both
/// treat an absent anchor as *permissive* (nothing served ⇒ nothing to cool
/// down from), so a consumer must never be able to confuse it with "the value
/// did not arrive". `out_present` is what keeps those two facts distinct on the
/// wire — the value is reported, not inferred from a missing field.
///
/// Writes `*out_present = 1` and `*out_epoch = anchor` when at least one shard
/// has served; `*out_present = 0` and `*out_epoch = 0` otherwise. Both outputs
/// are written on every `OK` return, so a caller cannot read a stale slot.
///
/// # Safety
/// When `per_shard_last_served_len > 0`, `per_shard_last_served_ptr` must be
/// valid for that many `u64`s for the duration of the call. `out_present` and
/// `out_epoch` must each be valid for one write.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_whole_record_last_served(
    per_shard_last_served_ptr: *const u64,
    per_shard_last_served_len: usize,
    out_present: *mut u8,
    out_epoch: *mut u64,
) -> u8 {
    if out_present.is_null() || out_epoch.is_null() {
        return SHEKYL_ARCHIVAL_BOND_POST_ERR_NULL_PTR;
    }
    let anchor = match unsafe {
        with_bond_post_u64_slice(
            per_shard_last_served_ptr,
            per_shard_last_served_len,
            whole_record_last_served,
        )
    } {
        Ok(a) => a,
        Err(code) => return code,
    };
    unsafe {
        match anchor {
            Some(epoch) => {
                *out_present = 1;
                *out_epoch = epoch;
            }
            None => {
                *out_present = 0;
                *out_epoch = 0;
            }
        }
    }
    SHEKYL_ARCHIVAL_BOND_POST_OK
}

/// Decide which last-served LMDB scan a holdings kind uses.
///
/// This is the **kind→scan decision**, exhaustive on [`HoldingsKind`]: a third
/// variant fails to compile in [`HoldingsKind::last_served_scan`] until its
/// arm is written. The two C++ gather sites (Unbond verify in
/// `blockchain.cpp`, claim-source marshal in `archival_claim_source.cpp`)
/// ask this instead of branching on `is_complete_tree()` independently.
///
/// Writes `*out_scan` to [`LastServedScan::HeldShards`] (0) or
/// [`LastServedScan::AllShards`] (1) on `OK`. An unknown `holdings_kind` is
/// `ERR_HOLDINGS_KIND` and does not write.
///
/// # Safety
/// `out_scan` must be valid for one write.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_last_served_scan(
    holdings_kind: u8,
    out_scan: *mut u8,
) -> u8 {
    if out_scan.is_null() {
        return SHEKYL_ARCHIVAL_BOND_POST_ERR_NULL_PTR;
    }
    let kind = match HoldingsKind::from_u8(holdings_kind) {
        Ok(k) => k,
        Err(_) => return SHEKYL_ARCHIVAL_BOND_POST_ERR_HOLDINGS_KIND,
    };
    let scan = match kind.last_served_scan() {
        LastServedScan::HeldShards => LastServedScan::HeldShards as u8,
        LastServedScan::AllShards => LastServedScan::AllShards as u8,
    };
    unsafe {
        *out_scan = scan;
    }
    SHEKYL_ARCHIVAL_BOND_POST_OK
}

/// Pin a debit's presented authorizer against the bond record's committed
/// `bond_spend_pk` (`shekyl-archival-retention::debit_auth_pin`).
///
/// The single authorization gate for every value-out bond-post arm
/// (`Unbond`, `HoldingsUpdate`, `Rebond`). The C++ block path calls this;
/// the Rust submit battery calls the same function natively
/// (`DAEMON_SUBMIT_VERDICT.md` §8.7.1.1 row UB3), so the two paths cannot
/// drift on the one predicate that has no recovery — a compromised serving
/// host holds the identity key and could otherwise authorize a collateral
/// drain.
///
/// Both refusals are distinct codes so the operator log separates *a record
/// that authorizes nothing* from *a wrong key against a record that does*.
/// A record committing no canonical-length key authorizes **nothing**;
/// there is no identity-key fallback.
///
/// # Safety
/// When a length is positive, its pointer must be valid for that many bytes
/// for the duration of the call. A zero length accepts a null pointer.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_debit_auth_pin(
    record_bond_spend_pk_ptr: *const u8,
    record_bond_spend_pk_len: usize,
    auth_pubkey_ptr: *const u8,
    auth_pubkey_len: usize,
) -> u8 {
    // Nested so neither key is copied: both are canonical-length hybrid
    // public keys (~2 KiB each) on a consensus path, and the pin only ever
    // reads them.
    let pinned = unsafe {
        with_bond_post_u8_slice(
            record_bond_spend_pk_ptr,
            record_bond_spend_pk_len,
            |record| {
                with_bond_post_u8_slice(auth_pubkey_ptr, auth_pubkey_len, |auth| {
                    debit_auth_pin(record, auth)
                })
            },
        )
    };
    let pinned = match pinned {
        Ok(Ok(inner)) => inner,
        Ok(Err(code)) | Err(code) => return code,
    };
    match pinned {
        Ok(()) => SHEKYL_ARCHIVAL_BOND_POST_OK,
        Err(DebitAuthError::RecordCommitsNoKey) => {
            SHEKYL_ARCHIVAL_BOND_POST_ERR_DEBIT_AUTH_NO_RECORD_KEY
        }
        Err(DebitAuthError::AuthKeyMismatch) => {
            SHEKYL_ARCHIVAL_BOND_POST_ERR_DEBIT_AUTH_KEY_MISMATCH
        }
    }
}

/// Fold the `Unbond` block-connect state transition (gate-4 §4.3 "On confirm";
/// `shekyl-archival-retention::bond_connect::unbond_connect`).
///
/// The C++ connect arm owns the LMDB write transaction and writes **exactly**
/// what the outs dictate: the record becomes `post_bonded_total_out` /
/// `post_holdings_kind_out` with `post_held_shard_count_out` (always `0`)
/// shard ids, the clean interval-close `[start, end)` is appended to the
/// record's interval log, and the global counter becomes
/// `new_total_bonded_out`. No consensus arithmetic happens caller-side. The
/// caller journals the record's full pre-image **before** applying (the
/// emission-claim WS-2 §6.3 shape) so the pop twin restores byte-identically.
///
/// Errors are connect-time invariant breaches (verify already rejected these);
/// the caller maps any non-OK code to a FATAL abort, never a soft skip.
///
/// The record's holdings arrive as `(kind, held shard count)` — the fold's
/// floor invariant never reads shard-id values (`bond_floor_of`), so the
/// caller marshals the count only (the `shekyl_archival_unbond_pop` shape),
/// not a pointer to the record's shard-id array.
///
/// # Safety
/// All out-pointers must be valid for writes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_unbond_connect(
    record_bonded_total: u64,
    record_holdings_kind: u8,
    record_held_shard_count: u64,
    record_bad_interval_count: usize,
    vin_bond_debit: u64,
    total_bonded_atomic: u64,
    unbond_settlement_epoch: u64,
    post_bonded_total_out: *mut u64,
    post_holdings_kind_out: *mut u8,
    post_held_shard_count_out: *mut u64,
    interval_close_start_out: *mut u64,
    interval_close_end_out: *mut u64,
    new_total_bonded_out: *mut u64,
) -> u8 {
    if post_bonded_total_out.is_null()
        || post_holdings_kind_out.is_null()
        || post_held_shard_count_out.is_null()
        || interval_close_start_out.is_null()
        || interval_close_end_out.is_null()
        || new_total_bonded_out.is_null()
    {
        return SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_NULL_PTR;
    }
    let Ok(kind) = HoldingsKind::from_u8(record_holdings_kind) else {
        return SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_HOLDINGS_KIND;
    };
    // A u64 count cannot exceed usize on 64-bit targets; saturate on narrower
    // ones — an over-cap count fails the floor invariant identically.
    let held_shard_count = usize::try_from(record_held_shard_count).unwrap_or(usize::MAX);
    let effect = match unbond_connect(
        record_bonded_total,
        kind,
        held_shard_count,
        record_bad_interval_count,
        vin_bond_debit,
        total_bonded_atomic,
        unbond_settlement_epoch,
    ) {
        Err(e) => return map_unbond_connect_error(e),
        Ok(effect) => effect,
    };
    unsafe {
        *post_bonded_total_out = effect.post_bonded_total;
        *post_holdings_kind_out = effect.post_holdings.kind as u8;
        *post_held_shard_count_out = effect.post_holdings.shard_ids.len() as u64;
        *interval_close_start_out = effect.interval_close.start_epoch;
        *interval_close_end_out = effect.interval_close.end_exclusive;
        *new_total_bonded_out = effect.new_total_bonded_atomic;
    }
    SHEKYL_ARCHIVAL_UNBOND_APPLY_OK
}

/// Fold the `Unbond` pop twin (gate-4 §5;
/// `shekyl-archival-retention::bond_connect::unbond_pop`): validate the tip
/// record is the connect's product — `Exited` state plus the trailing clean
/// interval-close for `unbond_settlement_epoch` — then re-credit
/// `total_bonded_atomic` with the journaled pre-image balance.
///
/// The record fields themselves are restored caller-side as a byte-copy of the
/// pre-image journal row; this fold owns the counter movement and the
/// consistency checks. `has_trailing_interval` is `0` when the record's
/// interval log is empty (the trailing `start`/`end` operands are then
/// ignored). Non-OK codes are journal/state desyncs — FATAL, never a skip.
///
/// # Safety
/// `new_total_bonded_out` must be valid for a write.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_unbond_pop(
    current_record_bonded_total: u64,
    current_record_held_shard_count: u64,
    has_trailing_interval: u8,
    trailing_interval_start: u64,
    trailing_interval_end: u64,
    unbond_settlement_epoch: u64,
    journal_pre_bonded_total: u64,
    total_bonded_atomic: u64,
    new_total_bonded_out: *mut u64,
) -> u8 {
    if new_total_bonded_out.is_null() {
        return SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_NULL_PTR;
    }
    let trailing_interval = (has_trailing_interval != 0).then_some(BadInterval {
        start_epoch: trailing_interval_start,
        end_exclusive: trailing_interval_end,
    });
    // A u64 count cannot exceed usize on 64-bit targets; saturate on narrower
    // ones — any nonzero count fails the exited-state check identically.
    let held_shard_count = usize::try_from(current_record_held_shard_count).unwrap_or(usize::MAX);
    match unbond_pop(
        current_record_bonded_total,
        held_shard_count,
        trailing_interval,
        unbond_settlement_epoch,
        journal_pre_bonded_total,
        total_bonded_atomic,
    ) {
        Ok(new_total) => {
            unsafe { *new_total_bonded_out = new_total };
            SHEKYL_ARCHIVAL_UNBOND_APPLY_OK
        }
        Err(e) => map_unbond_pop_error(e),
    }
}

/// Shared record-fact entry-point prologue for the bond-post kinds that verify
/// against an existing record's holdings (`HoldingsUpdate` add + drop,
/// `Rebond`): decode the post kind (an out-of-range byte maps to the caller's
/// `wrong_post_kind_err` — the kinds name it differently), marshal the vin
/// (§9.11 coupling enforced by the shared marshaler), decode the record's
/// holdings kind, and gather the common record facts. Keeping this
/// single-sourced means an admission-marshal change cannot land on one entry
/// point and silently miss another — the kinds must return one verdict for the
/// same malformed record facts.
///
/// # Safety
/// Same contracts as the entry points: each `*_ptr` valid for its `*_len`
/// elements, or null when the len is 0.
#[allow(clippy::too_many_arguments)] // coarse-call FFI: mirrors the entry points' flat operand list
unsafe fn bond_post_record_marshal_prologue(
    wrong_post_kind_err: u8,
    post_kind: u8,
    holdings_kind: u8,
    shard_ids_ptr: *const u64,
    shard_ids_len: usize,
    bond_spend_pk_ptr: *const u8,
    bond_spend_pk_len: usize,
    bonded_total_atomic: u64,
    bond_credit: u64,
    bond_debit: u64,
    record_exists: u8,
    record_bonded_total: u64,
    record_holdings_kind: u8,
    record_shard_ids_ptr: *const u64,
    record_shard_ids_len: usize,
) -> Result<(ArchivalBondPostVin, Option<u64>, HoldingsKind, Vec<u64>), u8> {
    let post_kind = match BondPostKind::from_u8(post_kind) {
        Ok(k) => k,
        Err(_) => return Err(wrong_post_kind_err),
    };
    let vin = unsafe {
        bond_post_vin_from_raw(
            post_kind,
            holdings_kind,
            shard_ids_ptr,
            shard_ids_len,
            bond_spend_pk_ptr,
            bond_spend_pk_len,
            bonded_total_atomic,
            bond_credit,
            bond_debit,
        )
    }?;
    // Parse the record's kind only when a record exists: a missing record must
    // surface as RECORD_MISSING (the verify's own verdict), never as a
    // misleading HOLDINGS_KIND from whatever placeholder the caller passed.
    // The dummy is unread — every verify checks RecordMissing before kinds.
    let record_holdings_kind = if record_exists != 0 {
        match HoldingsKind::from_u8(record_holdings_kind) {
            Ok(k) => k,
            Err(_) => return Err(SHEKYL_ARCHIVAL_BOND_POST_ERR_HOLDINGS_KIND),
        }
    } else {
        HoldingsKind::ShardSetCompact
    };
    let record_bonded_total = (record_exists != 0).then_some(record_bonded_total);
    let record_shards = unsafe {
        with_bond_post_u64_slice(record_shard_ids_ptr, record_shard_ids_len, <[u64]>::to_vec)
    }?;
    Ok((
        vin,
        record_bonded_total,
        record_holdings_kind,
        record_shards,
    ))
}

/// Verify `HoldingsUpdate`-add bond-post semantics (gate-4 §4.4 credit path).
///
/// The vin's post-holdings arrive via `shard_ids_*`; `record_shard_ids_*` is the
/// record's **current** holdings (for the single-shard diff), and
/// `record_bad_intervals_*` is the flattened `(start, end)` pairs
/// (`2 × record_bad_intervals_len` `u64`s) feeding the good-standing gate. A
/// non-JoinMarket vin never carries `bond_spend_pk`, so a conforming caller passes
/// null/0 (the shared marshaler enforces the §9.11 coupling).
///
/// # Safety
/// Each `*_ptr` must be valid for its `*_len` elements, or null when the len is 0.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn shekyl_archival_verify_holdings_update_add(
    post_kind: u8,
    holdings_kind: u8,
    shard_ids_ptr: *const u64,
    shard_ids_len: usize,
    bond_spend_pk_ptr: *const u8,
    bond_spend_pk_len: usize,
    bonded_total_atomic: u64,
    bond_credit: u64,
    bond_debit: u64,
    record_exists: u8,
    record_bonded_total: u64,
    record_holdings_kind: u8,
    record_shard_ids_ptr: *const u64,
    record_shard_ids_len: usize,
    record_join_settlement_epoch: u64,
    record_bad_intervals_ptr: *const u64,
    record_bad_intervals_len: usize,
    current_settlement_epoch: u64,
) -> u8 {
    let (vin, record_bonded_total, record_holdings_kind, record_shards) = match unsafe {
        bond_post_record_marshal_prologue(
            SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND_NOT_HOLDINGS_UPDATE,
            post_kind,
            holdings_kind,
            shard_ids_ptr,
            shard_ids_len,
            bond_spend_pk_ptr,
            bond_spend_pk_len,
            bonded_total_atomic,
            bond_credit,
            bond_debit,
            record_exists,
            record_bonded_total,
            record_holdings_kind,
            record_shard_ids_ptr,
            record_shard_ids_len,
        )
    } {
        Ok(v) => v,
        Err(code) => return code,
    };
    let Some(bad) =
        (unsafe { gather_bad_intervals(record_bad_intervals_ptr, record_bad_intervals_len) })
    else {
        return SHEKYL_ARCHIVAL_BOND_POST_ERR_LEN_OVERFLOW;
    };
    match verify_holdings_update_add(
        &vin,
        record_bonded_total,
        record_holdings_kind,
        &record_shards,
        record_join_settlement_epoch,
        &bad,
        current_settlement_epoch,
    ) {
        Ok(()) => SHEKYL_ARCHIVAL_BOND_POST_OK,
        Err(e) => map_bond_post_error(e),
    }
}

/// Verify `HoldingsUpdate`-drop bond-post semantics (gate-4 §4.4 grace-tail debit
/// path). C++ identifies the dropped shard by set-difference and reads its
/// per-shard facts (`dropped_shard_add_epoch`, `dropped_shard_freeze_height`,
/// `dropped_shard_last_served`); the Rust verify recomputes the diff and
/// cross-checks `dropped_shard_id`. `dropped_shard_last_served == u64::MAX` and
/// `last_settled_slash_epoch == u64::MAX` are the "never served" / "no epoch
/// settled" storage sentinels, translated to `None`.
///
/// # Safety
/// Each `*_ptr` must be valid for its `*_len` elements, or null when the len is 0.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn shekyl_archival_verify_holdings_update_drop(
    post_kind: u8,
    holdings_kind: u8,
    shard_ids_ptr: *const u64,
    shard_ids_len: usize,
    bond_spend_pk_ptr: *const u8,
    bond_spend_pk_len: usize,
    bonded_total_atomic: u64,
    bond_credit: u64,
    bond_debit: u64,
    record_exists: u8,
    record_bonded_total: u64,
    record_holdings_kind: u8,
    record_shard_ids_ptr: *const u64,
    record_shard_ids_len: usize,
    dropped_shard_id: u64,
    dropped_shard_add_epoch: u64,
    dropped_shard_freeze_height: u64,
    dropped_shard_last_served: u64,
    last_settled_slash_epoch: u64,
    current_settlement_epoch: u64,
) -> u8 {
    let (vin, record_bonded_total, record_holdings_kind, record_shards) = match unsafe {
        bond_post_record_marshal_prologue(
            SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND_NOT_HOLDINGS_UPDATE,
            post_kind,
            holdings_kind,
            shard_ids_ptr,
            shard_ids_len,
            bond_spend_pk_ptr,
            bond_spend_pk_len,
            bonded_total_atomic,
            bond_credit,
            bond_debit,
            record_exists,
            record_bonded_total,
            record_holdings_kind,
            record_shard_ids_ptr,
            record_shard_ids_len,
        )
    } {
        Ok(v) => v,
        Err(code) => return code,
    };
    let last_served = (dropped_shard_last_served != u64::MAX).then_some(dropped_shard_last_served);
    let last_settled = (last_settled_slash_epoch != u64::MAX).then_some(last_settled_slash_epoch);
    match verify_holdings_update_drop(
        &vin,
        record_bonded_total,
        record_holdings_kind,
        &record_shards,
        dropped_shard_id,
        dropped_shard_add_epoch,
        dropped_shard_freeze_height,
        last_served,
        last_settled,
        current_settlement_epoch,
    ) {
        Ok(()) => SHEKYL_ARCHIVAL_BOND_POST_OK,
        Err(e) => map_bond_post_error(e),
    }
}

/// Fold the `HoldingsUpdate`-add connect (gate-4 §4.4). The C++ arm journals the
/// pre-image, sets `held_shard_ids = post` + appends `add_settlement_epoch_out`
/// as the added shard's add-epoch (rebuilding the coupled arrays), and sets the
/// counters from `new_bonded_total_out` / `new_total_bonded_out`. `total_bonded`
/// is the **absolute** post-value — thread it per post (the Unbond note).
///
/// # Safety
/// `record_shard_ids_ptr` / `post_shard_ids_ptr` valid for their lens (or null at
/// len 0); all out-pointers valid for writes.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn shekyl_archival_holdings_update_add_connect(
    record_bonded_total: u64,
    record_shard_ids_ptr: *const u64,
    record_shard_ids_len: usize,
    post_shard_ids_ptr: *const u64,
    post_shard_ids_len: usize,
    total_bonded_atomic: u64,
    add_settlement_epoch: u64,
    added_shard_id_out: *mut u64,
    add_settlement_epoch_out: *mut u64,
    new_bonded_total_out: *mut u64,
    new_total_bonded_out: *mut u64,
) -> u8 {
    if added_shard_id_out.is_null()
        || add_settlement_epoch_out.is_null()
        || new_bonded_total_out.is_null()
        || new_total_bonded_out.is_null()
    {
        return SHEKYL_ARCHIVAL_HU_APPLY_ERR_NULL_PTR;
    }
    let current = match unsafe {
        with_bond_post_u64_slice(record_shard_ids_ptr, record_shard_ids_len, <[u64]>::to_vec)
    } {
        Ok(v) => v,
        Err(_) => return SHEKYL_ARCHIVAL_HU_APPLY_ERR_LEN_OVERFLOW,
    };
    let post = match unsafe {
        with_bond_post_u64_slice(post_shard_ids_ptr, post_shard_ids_len, <[u64]>::to_vec)
    } {
        Ok(v) => v,
        Err(_) => return SHEKYL_ARCHIVAL_HU_APPLY_ERR_LEN_OVERFLOW,
    };
    match holdings_update_add_connect(
        record_bonded_total,
        &current,
        &post,
        total_bonded_atomic,
        add_settlement_epoch,
    ) {
        Ok(e) => {
            unsafe {
                *added_shard_id_out = e.added_shard_id;
                *add_settlement_epoch_out = e.add_settlement_epoch;
                *new_bonded_total_out = e.new_bonded_total;
                *new_total_bonded_out = e.new_total_bonded_atomic;
            }
            SHEKYL_ARCHIVAL_HU_APPLY_OK
        }
        Err(e) => map_holdings_update_connect_error(e),
    }
}

/// Fold the `HoldingsUpdate`-drop connect (gate-4 §4.4 grace-tail). The C++ arm
/// journals the pre-image, sets `held_shard_ids = post` (dropping the coupled
/// add-epoch of `dropped_shard_id_out`), and sets the counters. `refund_out`
/// (`== FLOOR`) is the `bond_debit` source term, CT-balanced on the wire.
///
/// # Safety
/// `record_shard_ids_ptr` / `post_shard_ids_ptr` valid for their lens (or null at
/// len 0); all out-pointers valid for writes.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn shekyl_archival_holdings_update_drop_connect(
    record_bonded_total: u64,
    record_shard_ids_ptr: *const u64,
    record_shard_ids_len: usize,
    post_shard_ids_ptr: *const u64,
    post_shard_ids_len: usize,
    total_bonded_atomic: u64,
    dropped_shard_id_out: *mut u64,
    new_bonded_total_out: *mut u64,
    new_total_bonded_out: *mut u64,
    refund_out: *mut u64,
) -> u8 {
    if dropped_shard_id_out.is_null()
        || new_bonded_total_out.is_null()
        || new_total_bonded_out.is_null()
        || refund_out.is_null()
    {
        return SHEKYL_ARCHIVAL_HU_APPLY_ERR_NULL_PTR;
    }
    let current = match unsafe {
        with_bond_post_u64_slice(record_shard_ids_ptr, record_shard_ids_len, <[u64]>::to_vec)
    } {
        Ok(v) => v,
        Err(_) => return SHEKYL_ARCHIVAL_HU_APPLY_ERR_LEN_OVERFLOW,
    };
    let post = match unsafe {
        with_bond_post_u64_slice(post_shard_ids_ptr, post_shard_ids_len, <[u64]>::to_vec)
    } {
        Ok(v) => v,
        Err(_) => return SHEKYL_ARCHIVAL_HU_APPLY_ERR_LEN_OVERFLOW,
    };
    match holdings_update_drop_connect(record_bonded_total, &current, &post, total_bonded_atomic) {
        Ok(e) => {
            unsafe {
                *dropped_shard_id_out = e.dropped_shard_id;
                *new_bonded_total_out = e.new_bonded_total;
                *new_total_bonded_out = e.new_total_bonded_atomic;
                *refund_out = e.refund_atomic;
            }
            SHEKYL_ARCHIVAL_HU_APPLY_OK
        }
        Err(e) => map_holdings_update_connect_error(e),
    }
}

/// Fold the `HoldingsUpdate` add/drop pop twin (gate-4 §5): the C++ arm restores
/// the record fields from the pre-image journal byte-identically; this reverts
/// the global `total_bonded_atomic` by the connect's `±FLOOR` delta, guarding
/// that the tip record's `bonded_total` and the journaled pre-image differ by
/// exactly one FLOOR.
///
/// # Safety
/// `new_total_bonded_out` must be valid for a write.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_holdings_update_pop(
    current_record_bonded_total: u64,
    journal_pre_bonded_total: u64,
    total_bonded_atomic: u64,
    new_total_bonded_out: *mut u64,
) -> u8 {
    if new_total_bonded_out.is_null() {
        return SHEKYL_ARCHIVAL_HU_APPLY_ERR_NULL_PTR;
    }
    match holdings_update_pop(
        current_record_bonded_total,
        journal_pre_bonded_total,
        total_bonded_atomic,
    ) {
        Ok(new_total) => {
            unsafe { *new_total_bonded_out = new_total };
            SHEKYL_ARCHIVAL_HU_APPLY_OK
        }
        Err(e) => map_holdings_update_pop_error(e),
    }
}

/// Verify `Rebond` bond-post semantics (gate-4 §3.4; P2B-9 reinstatement). The
/// vin's post-holdings arrive via `shard_ids_*`; `record_shard_ids_*` is the
/// record's **current** holdings (the superset base), and
/// `record_bad_intervals_*` is the flattened `(start, end_exclusive)` pairs —
/// `record_bad_intervals_len` counts **pairs** (buffer holds `2 × len` u64s) —
/// carrying the open-interval precondition and the Pin-6 headroom bound. A
/// `Rebond` vin never carries `bond_spend_pk` (credit path; the record keeps its
/// join-time key), so a conforming caller passes null/0.
///
/// # Safety
/// Each `*_ptr` must be valid for its `*_len` elements, or null when the len is 0.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn shekyl_archival_verify_rebond_bond_post(
    post_kind: u8,
    holdings_kind: u8,
    shard_ids_ptr: *const u64,
    shard_ids_len: usize,
    bond_spend_pk_ptr: *const u8,
    bond_spend_pk_len: usize,
    bonded_total_atomic: u64,
    bond_credit: u64,
    bond_debit: u64,
    record_exists: u8,
    record_bonded_total: u64,
    record_holdings_kind: u8,
    record_shard_ids_ptr: *const u64,
    record_shard_ids_len: usize,
    record_bad_intervals_ptr: *const u64,
    record_bad_intervals_len: usize,
) -> u8 {
    let (vin, record_bonded_total, record_holdings_kind, record_shards) = match unsafe {
        bond_post_record_marshal_prologue(
            SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND_NOT_REBOND,
            post_kind,
            holdings_kind,
            shard_ids_ptr,
            shard_ids_len,
            bond_spend_pk_ptr,
            bond_spend_pk_len,
            bonded_total_atomic,
            bond_credit,
            bond_debit,
            record_exists,
            record_bonded_total,
            record_holdings_kind,
            record_shard_ids_ptr,
            record_shard_ids_len,
        )
    } {
        Ok(v) => v,
        Err(code) => return code,
    };
    let Some(bad) =
        (unsafe { gather_bad_intervals(record_bad_intervals_ptr, record_bad_intervals_len) })
    else {
        return SHEKYL_ARCHIVAL_BOND_POST_ERR_LEN_OVERFLOW;
    };
    match verify_rebond_bond_post(
        &vin,
        record_bonded_total,
        record_holdings_kind,
        &record_shards,
        &bad,
    ) {
        Ok(()) => SHEKYL_ARCHIVAL_BOND_POST_OK,
        Err(e) => map_bond_post_error(e),
    }
}

/// Fold the `Rebond` connect (gate-4 §3.4; P2B-9). The C++ arm journals the
/// record pre-image (including the closed interval's index + start), sets
/// `held_shard_ids = post` and rebuilds the coupled add-epochs (carried shards
/// keep theirs; every id written to `added_shard_ids_out` takes
/// `add_settlement_epoch_out = E_rebond`), closes the open interval **in place**
/// (`bad_intervals[closed_interval_index_out].end_exclusive =
/// interval_end_exclusive_out`, `== E_rebond + 1`), and sets the counters.
/// `total_bonded_atomic` is the LIVE global counter (thread per post).
/// `added_shard_ids_cap` must be ≥ the post length (added ⊆ post).
///
/// # Safety
/// Array pointers valid for their lens (or null at len 0);
/// `added_shard_ids_out` valid for `added_shard_ids_cap` writes; all scalar
/// out-pointers valid for writes.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn shekyl_archival_rebond_connect(
    record_bonded_total: u64,
    record_shard_ids_ptr: *const u64,
    record_shard_ids_len: usize,
    record_bad_intervals_ptr: *const u64,
    record_bad_intervals_len: usize,
    post_shard_ids_ptr: *const u64,
    post_shard_ids_len: usize,
    total_bonded_atomic: u64,
    rebond_settlement_epoch: u64,
    added_shard_ids_out: *mut u64,
    added_shard_ids_cap: usize,
    added_shard_ids_len_out: *mut usize,
    add_settlement_epoch_out: *mut u64,
    closed_interval_index_out: *mut u64,
    interval_end_exclusive_out: *mut u64,
    new_bonded_total_out: *mut u64,
    new_total_bonded_out: *mut u64,
) -> u8 {
    if (added_shard_ids_out.is_null() && added_shard_ids_cap > 0)
        || added_shard_ids_len_out.is_null()
        || add_settlement_epoch_out.is_null()
        || closed_interval_index_out.is_null()
        || interval_end_exclusive_out.is_null()
        || new_bonded_total_out.is_null()
        || new_total_bonded_out.is_null()
    {
        return SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_NULL_PTR;
    }
    let current = match unsafe {
        with_bond_post_u64_slice(record_shard_ids_ptr, record_shard_ids_len, <[u64]>::to_vec)
    } {
        Ok(v) => v,
        Err(_) => return SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_LEN_OVERFLOW,
    };
    let post = match unsafe {
        with_bond_post_u64_slice(post_shard_ids_ptr, post_shard_ids_len, <[u64]>::to_vec)
    } {
        Ok(v) => v,
        Err(_) => return SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_LEN_OVERFLOW,
    };
    let Some(bad) =
        (unsafe { gather_bad_intervals(record_bad_intervals_ptr, record_bad_intervals_len) })
    else {
        return SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_LEN_OVERFLOW;
    };
    match rebond_connect(
        record_bonded_total,
        &current,
        &bad,
        &post,
        total_bonded_atomic,
        rebond_settlement_epoch,
    ) {
        Ok(e) => {
            if e.added_shard_ids.len() > added_shard_ids_cap {
                return SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_ADDED_BUFFER_TOO_SMALL;
            }
            unsafe {
                if !e.added_shard_ids.is_empty() {
                    std::ptr::copy_nonoverlapping(
                        e.added_shard_ids.as_ptr(),
                        added_shard_ids_out,
                        e.added_shard_ids.len(),
                    );
                }
                *added_shard_ids_len_out = e.added_shard_ids.len();
                *add_settlement_epoch_out = e.add_settlement_epoch;
                *closed_interval_index_out = e.closed_interval_index as u64;
                *interval_end_exclusive_out = e.interval_end_exclusive;
                *new_bonded_total_out = e.new_bonded_total;
                *new_total_bonded_out = e.new_total_bonded_atomic;
            }
            SHEKYL_ARCHIVAL_REBOND_APPLY_OK
        }
        Err(e) => map_rebond_connect_error(e),
    }
}

/// Fold the `Rebond` pop twin (gate-4 §5): the C++ arm restores the record
/// fields from the pre-image journal byte-identically (including re-opening the
/// closed interval to `end_exclusive = MAX`); this reverts the global
/// `total_bonded_atomic` by the connect's `|added|·FLOOR` credit — zero delta
/// included (the standing-only reinstatement moved no collateral).
///
/// # Safety
/// `new_total_bonded_out` must be valid for a write.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_rebond_pop(
    current_record_bonded_total: u64,
    journal_pre_bonded_total: u64,
    total_bonded_atomic: u64,
    new_total_bonded_out: *mut u64,
) -> u8 {
    if new_total_bonded_out.is_null() {
        return SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_NULL_PTR;
    }
    match rebond_pop(
        current_record_bonded_total,
        journal_pre_bonded_total,
        total_bonded_atomic,
    ) {
        Ok(new_total) => {
            unsafe { *new_total_bonded_out = new_total };
            SHEKYL_ARCHIVAL_REBOND_APPLY_OK
        }
        Err(e) => map_rebond_pop_error(e),
    }
}
