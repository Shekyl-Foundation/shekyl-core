// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Coverage-list FFI (`ARCHIVAL_SHARD_SELECTION_LIST.md` SL-D4).
//!
//! C++ marshals per-shard operands; Rust computes join-adjusted scarcity,
//! expected-profit, and order. Codes are local to this entry (0 = OK).

use shekyl_archival_retention::{order_shard_coverage, ShardCoverageIn};

/// Packed operand row. Field order is the ABI; keep in lockstep with
/// `ShekylArchivalShardCoverageIn` in `shekyl_ffi.h`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShekylArchivalShardCoverageIn {
    pub shard_id: u64,
    pub bonded_count: u64,
    pub served_count: u64,
    pub freeze_height: u64,
}

/// Packed ranked row. Field order is the ABI; keep in lockstep with
/// `ShekylArchivalShardCoverageOut` in `shekyl_ffi.h`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShekylArchivalShardCoverageOut {
    pub shard_id: u64,
    pub bonded_count: u64,
    pub served_count: u64,
    pub freeze_height: u64,
    pub join_scarcity_micro: u64,
    pub expected_profit_atomic: u64,
}

pub const SHEKYL_ARCHIVAL_SHARD_COVERAGE_OK: u8 = 0;
pub const SHEKYL_ARCHIVAL_SHARD_COVERAGE_ERR_MARSHAL: u8 = 1;
pub const SHEKYL_ARCHIVAL_SHARD_COVERAGE_ERR_CAP: u8 = 2;

/// Order coverage rows. Writes `in_len` ranked rows to `out_ptr` when
/// `out_cap >= in_len`. `out_len` is always written on OK.
///
/// # Safety
///
/// `in_ptr`/`out_ptr`/`out_len` must be valid for the stated lengths, or
/// null only when the matching length is 0 (`in_ptr`/`out_ptr`).
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_order_shard_coverage(
    tip_height: u64,
    budget_atomic: u64,
    sigma_work_milli: u64,
    in_ptr: *const ShekylArchivalShardCoverageIn,
    in_len: usize,
    out_ptr: *mut ShekylArchivalShardCoverageOut,
    out_cap: usize,
    out_len: *mut usize,
) -> u8 {
    if out_len.is_null() {
        return SHEKYL_ARCHIVAL_SHARD_COVERAGE_ERR_MARSHAL;
    }
    if in_len > 0 && in_ptr.is_null() {
        return SHEKYL_ARCHIVAL_SHARD_COVERAGE_ERR_MARSHAL;
    }
    if out_cap < in_len {
        return SHEKYL_ARCHIVAL_SHARD_COVERAGE_ERR_CAP;
    }
    if in_len > 0 && out_ptr.is_null() {
        return SHEKYL_ARCHIVAL_SHARD_COVERAGE_ERR_MARSHAL;
    }

    let inputs = if in_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(in_ptr, in_len) }
    };
    let rows: Vec<ShardCoverageIn> = inputs
        .iter()
        .map(|r| ShardCoverageIn {
            shard_id: r.shard_id,
            bonded_count: r.bonded_count,
            served_count: r.served_count,
            freeze_height: r.freeze_height,
        })
        .collect();
    let ranked = order_shard_coverage(tip_height, budget_atomic, sigma_work_milli, &rows);
    debug_assert_eq!(ranked.len(), in_len);

    if in_len > 0 {
        let out = unsafe { std::slice::from_raw_parts_mut(out_ptr, in_len) };
        for (dst, src) in out.iter_mut().zip(ranked.iter()) {
            *dst = ShekylArchivalShardCoverageOut {
                shard_id: src.shard_id,
                bonded_count: src.bonded_count,
                served_count: src.served_count,
                freeze_height: src.freeze_height,
                join_scarcity_micro: src.join_scarcity_micro,
                expected_profit_atomic: src.expected_profit_atomic,
            };
        }
    }
    unsafe {
        *out_len = in_len;
    }
    SHEKYL_ARCHIVAL_SHARD_COVERAGE_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extra_bond_lowers_rank_across_ffi() {
        let inputs = [
            ShekylArchivalShardCoverageIn {
                shard_id: 0,
                bonded_count: 4,
                served_count: 1,
                freeze_height: 1_000,
            },
            ShekylArchivalShardCoverageIn {
                shard_id: 1,
                bonded_count: 0,
                served_count: 0,
                freeze_height: 1_000,
            },
        ];
        let mut out = [ShekylArchivalShardCoverageOut {
            shard_id: 0,
            bonded_count: 0,
            served_count: 0,
            freeze_height: 0,
            join_scarcity_micro: 0,
            expected_profit_atomic: 0,
        }; 2];
        let mut n = 0usize;
        let rc = unsafe {
            shekyl_archival_order_shard_coverage(
                50_000,
                1_000_000,
                1_000,
                inputs.as_ptr(),
                inputs.len(),
                out.as_mut_ptr(),
                out.len(),
                std::ptr::from_mut(&mut n),
            )
        };
        assert_eq!(rc, SHEKYL_ARCHIVAL_SHARD_COVERAGE_OK);
        assert_eq!(n, 2);
        assert_eq!(out[0].shard_id, 1);
        assert_eq!(out[1].shard_id, 0);
        assert!(out[0].join_scarcity_micro > out[1].join_scarcity_micro);
    }

    #[test]
    fn null_out_len_is_marshal() {
        let rc = unsafe {
            shekyl_archival_order_shard_coverage(
                0,
                0,
                0,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, SHEKYL_ARCHIVAL_SHARD_COVERAGE_ERR_MARSHAL);
    }
}
