// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! D3/R3 admission viability FFI (`shekyl-archival-retention::admission`).
//!
//! C++ owns LMDB I/O; Rust owns epoch-key selection, age derivation, and the
//! viability predicate. Keeping this surface out of `archival_ffi.rs` stops
//! that file from absorbing every archival concern.

use std::ffi::CStr;
use std::os::raw::c_char;

use shekyl_archival_retention::{
    admission_codes, check_admission_of, last_settled_epoch_as_of_parent,
    parent_state_shards_from_gather, HoldingsKind, ParentStateHoldings,
};

/// The holding credits at least `ADMISSION_MIN_WORK_MILLI`.
pub const SHEKYL_ARCHIVAL_ADMISSION_OK: u8 = admission_codes::OK;
/// A gather array pointer was null with a non-zero length.
pub const SHEKYL_ARCHIVAL_ADMISSION_ERR_NULL_PTR: u8 = admission_codes::ERR_NULL_PTR;
/// `holdings_kind` is not a valid discriminant.
pub const SHEKYL_ARCHIVAL_ADMISSION_ERR_HOLDINGS_KIND: u8 = admission_codes::ERR_HOLDINGS_KIND;
/// The marshaled gather does not line up with the vin's shard list.
pub const SHEKYL_ARCHIVAL_ADMISSION_ERR_GATHER_MISMATCH: u8 = admission_codes::ERR_GATHER_MISMATCH;
/// The holding would score zero at every epoch close — a bond the frozen work
/// scale cannot pay.
pub const SHEKYL_ARCHIVAL_ADMISSION_ERR_BELOW_FLOOR: u8 = admission_codes::ERR_BELOW_FLOOR;

/// Settlement epoch whose `archival_r_market` rows are readable as of the parent
/// block. Single-sources the admission gather's LMDB epoch key so C++ never
/// re-derives `settlement_epoch(parent) − 1`.
#[no_mangle]
pub extern "C" fn shekyl_archival_last_settled_epoch_as_of_parent(parent_height: u64) -> u64 {
    last_settled_epoch_as_of_parent(parent_height)
}

/// Static reason string for an admission C-ABI code (including marshal-only
/// failures). Never null; unknown codes return a fixed sentinel. NUL-terminated
/// for C++ `MERROR_VER` — do not free.
#[no_mangle]
pub extern "C" fn shekyl_archival_admission_err_string(code: u8) -> *const c_char {
    let s: &'static CStr = match code {
        SHEKYL_ARCHIVAL_ADMISSION_OK => c"ok",
        SHEKYL_ARCHIVAL_ADMISSION_ERR_NULL_PTR => c"null gather pointer with non-zero length",
        SHEKYL_ARCHIVAL_ADMISSION_ERR_HOLDINGS_KIND => c"invalid holdings_kind",
        SHEKYL_ARCHIVAL_ADMISSION_ERR_GATHER_MISMATCH => {
            c"admission gather length does not match the vin's shard list"
        }
        SHEKYL_ARCHIVAL_ADMISSION_ERR_BELOW_FLOOR => {
            c"holdings credit no work at the parent-block read-point - this bond would score zero at every epoch close"
        }
        _ => c"unknown admission error",
    };
    s.as_ptr()
}

/// D3/R3 admission gate: refuse a bond whose holdings credit no work.
///
/// Marshaled facts (C++ owns the LMDB I/O, Rust decides — the same split as
/// `shekyl_archival_verify_join_market_bond_post`): `r_market_*` is the
/// per-shard `archival_r_market` row for
/// [`shekyl_archival_last_settled_epoch_as_of_parent`], `freeze_height_*` the
/// per-shard segment freeze height, and `has_segment_*` whether that segment
/// row exists at all — **all three parallel to the vin's shard list**. A shard
/// with no `r_market` row marshals as `0` (load-bearing: Rust scores
/// `r_market + 1`, so a never-served shard is maximal scarcity, not a zero).
///
/// **`has_segment_*` is required and must be the real presence bit** — i.e. the
/// return value of `archival_shard_freeze_height`, not a guess derived from the
/// height. A shard with no frozen segment scores `age_milli = 0`, matching
/// `shard_contribution_micro`; and `freeze_height = 0` is a *legitimate*
/// genesis-band value, so presence cannot be recovered from the height. Passing
/// `true` with a defaulted `0` height would score the **maximum** age where the
/// reward path scores zero, over-scoring the holding.
///
/// **`parent_height` must be the parent block's height (`chain_height − 1`).**
/// `chain_height` at the dispatch is `m_db->height()`, the block being
/// validated; passing it here would date the age term one block into the
/// future. No Rust test can catch a tip-height mistake at the C++ call site.
///
/// Age weight and the SEB schedule are **not** parameters — Rust sources both
/// so the gate cannot be handed a schedule that differs from the reward path.
///
/// `CompleteTree` holdings are decided without a gather (dominance); pass
/// `vin_shard_count = 0` and null arrays.
///
/// # Safety
/// `r_market_ptr` must be valid for `r_market_len` `u64`s, `freeze_height_ptr`
/// for `freeze_height_len` `u64`s, and `has_segment_ptr` for `has_segment_len`
/// `u8`s, or null when the corresponding len is 0.
///
/// `has_segment` crosses as `u8` rather than `bool` deliberately: every byte is
/// a valid `u8` and is read as `!= 0`, so a malformed marshal is harmless —
/// whereas a `bool` holding anything but `0`/`1` is instant UB on the Rust side.
/// It also keeps the caller clear of `std::vector<bool>`, which is a bitset
/// specialization with no contiguous `bool*` to hand across the ABI.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_check_bond_admission(
    holdings_kind: u8,
    vin_shard_count: usize,
    r_market_ptr: *const u64,
    r_market_len: usize,
    freeze_height_ptr: *const u64,
    freeze_height_len: usize,
    has_segment_ptr: *const u8,
    has_segment_len: usize,
    parent_height: u64,
) -> u8 {
    let kind = match HoldingsKind::from_u8(holdings_kind) {
        Ok(k) => k,
        Err(_) => return SHEKYL_ARCHIVAL_ADMISSION_ERR_HOLDINGS_KIND,
    };

    if (r_market_ptr.is_null() && r_market_len != 0)
        || (freeze_height_ptr.is_null() && freeze_height_len != 0)
        || (has_segment_ptr.is_null() && has_segment_len != 0)
    {
        return SHEKYL_ARCHIVAL_ADMISSION_ERR_NULL_PTR;
    }

    let r_market = if r_market_len == 0 {
        &[][..]
    } else {
        // SAFETY: caller guarantees valid for r_market_len; null+len0 handled.
        unsafe { std::slice::from_raw_parts(r_market_ptr, r_market_len) }
    };
    let freeze_heights = if freeze_height_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(freeze_height_ptr, freeze_height_len) }
    };
    let has_segment: Vec<bool> = if has_segment_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(has_segment_ptr, has_segment_len) }
            .iter()
            .map(|&b| b != 0)
            .collect()
    };

    let shards = match parent_state_shards_from_gather(
        r_market,
        freeze_heights,
        &has_segment,
        parent_height,
    ) {
        Ok(s) => s,
        Err(e) => return e.code(),
    };
    let parent_state = ParentStateHoldings::with_consensus_age_weight(&shards);
    match check_admission_of(kind, vin_shard_count, &parent_state) {
        Ok(()) => SHEKYL_ARCHIVAL_ADMISSION_OK,
        Err(e) => e.code(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_archival_retention::HoldingsKind;
    use std::ffi::CStr;

    /// The D3/R3 gate across the C ABI: the `k = 1` boundary survives the
    /// marshal, and the two shapes the dispatch relies on (`CompleteTree` with
    /// no gather, a never-served shard reading `r_market = 0`) decide correctly.
    ///
    /// `parent_height = 0` with `freeze_height = 0` pins age to zero, so a shard
    /// scores `floor(1e6 / (r_market + 1))` micro.
    #[test]
    fn check_bond_admission_ffi_pins_the_viability_boundary() {
        let kind = HoldingsKind::ShardSetCompact as u8;
        let call = |r: &[u64]| {
            let freeze = vec![0u64; r.len()];
            let seg = vec![1u8; r.len()];
            unsafe {
                shekyl_archival_check_bond_admission(
                    kind,
                    r.len(),
                    r.as_ptr(),
                    r.len(),
                    freeze.as_ptr(),
                    freeze.len(),
                    seg.as_ptr(),
                    seg.len(),
                    0,
                )
            }
        };

        assert_eq!(call(&[999]), SHEKYL_ARCHIVAL_ADMISSION_OK);
        assert_eq!(call(&[1_000]), SHEKYL_ARCHIVAL_ADMISSION_ERR_BELOW_FLOOR);
        assert_eq!(call(&[0]), SHEKYL_ARCHIVAL_ADMISSION_OK);

        assert_eq!(
            unsafe {
                shekyl_archival_check_bond_admission(
                    HoldingsKind::CompleteTree as u8,
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                    0,
                )
            },
            SHEKYL_ARCHIVAL_ADMISSION_OK
        );

        let r = [999u64, 999];
        let freeze = [0u64];
        let seg = [1u8, 1u8];
        assert_eq!(
            unsafe {
                shekyl_archival_check_bond_admission(
                    kind,
                    2,
                    r.as_ptr(),
                    r.len(),
                    freeze.as_ptr(),
                    freeze.len(),
                    seg.as_ptr(),
                    seg.len(),
                    0,
                )
            },
            SHEKYL_ARCHIVAL_ADMISSION_ERR_GATHER_MISMATCH,
            "parallel gather arrays of different lengths"
        );
        assert_eq!(
            unsafe {
                shekyl_archival_check_bond_admission(
                    kind,
                    1,
                    r.as_ptr(),
                    2,
                    freeze.as_ptr(),
                    2,
                    seg.as_ptr(),
                    2,
                    0,
                )
            },
            SHEKYL_ARCHIVAL_ADMISSION_ERR_GATHER_MISMATCH,
            "gather that does not match the vin's shard count"
        );
        assert_eq!(
            unsafe {
                shekyl_archival_check_bond_admission(
                    kind,
                    1,
                    std::ptr::null(),
                    1,
                    freeze.as_ptr(),
                    1,
                    seg.as_ptr(),
                    1,
                    0,
                )
            },
            SHEKYL_ARCHIVAL_ADMISSION_ERR_NULL_PTR
        );
        assert_eq!(
            unsafe {
                shekyl_archival_check_bond_admission(
                    9,
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                    0,
                )
            },
            SHEKYL_ARCHIVAL_ADMISSION_ERR_HOLDINGS_KIND
        );
    }

    #[test]
    fn last_settled_epoch_ffi_matches_rust() {
        assert_eq!(shekyl_archival_last_settled_epoch_as_of_parent(0), 0);
        assert_eq!(
            shekyl_archival_last_settled_epoch_as_of_parent(10_000),
            last_settled_epoch_as_of_parent(10_000)
        );
    }

    #[test]
    fn admission_err_string_distinguishes_floor_from_marshal() {
        let floor = unsafe { CStr::from_ptr(shekyl_archival_admission_err_string(4)) };
        let mismatch = unsafe { CStr::from_ptr(shekyl_archival_admission_err_string(3)) };
        let floor_s = floor.to_str().unwrap();
        let mismatch_s = mismatch.to_str().unwrap();
        assert!(
            floor_s.contains("score zero"),
            "floor code must claim zero-work: {floor_s}"
        );
        assert!(
            !mismatch_s.contains("score zero"),
            "gather mismatch must not claim zero-work: {mismatch_s}"
        );
        assert!(mismatch_s.contains("gather"), "{mismatch_s}");
    }
}
