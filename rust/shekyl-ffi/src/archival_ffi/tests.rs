// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for the archival FFI edge (extracted from the former monofile).

use super::*;
use std::ptr;

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

// Both-terms is unrepresentable inside `BondTerm`; zero/zero is Unmoved.
// The FFI conversion is `BondTerm::from_credit_debit` — tested here at the
// untrusted u64 edge.
#[test]
fn bond_ct_balance_ffi_unmoved_closes_empty() {
    // credit = debit = 0, empty commitments, fee 0 → Unmoved, OK.
    let code = unsafe {
        shekyl_archival_verify_bond_post_ct_balance(ptr::null(), 0, ptr::null(), 0, 0, 0, 0)
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_BOND_CT_BALANCE_OK);
    // Retired-assigned: zero-money used to return this. Number 5 stays.
    assert_eq!(SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_NO_BOND_TERM, 5);
}

#[test]
fn bond_ct_balance_ffi_rejects_both_bond_terms() {
    // credit and debit both non-zero → BOTH_TERMS.
    let code = unsafe {
        shekyl_archival_verify_bond_post_ct_balance(ptr::null(), 0, ptr::null(), 0, 0, 1, 1)
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_BOTH_TERMS);
}
