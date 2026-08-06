// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bond-post CT balance verification FFI.

use shekyl_archival_retention::{verify_bond_post_ct_balance, BondCtBalanceError, BondTerm};
use shekyl_units::{AtomicUnits, NonZeroAtomicUnits};

use super::codes::*;

fn map_bond_ct_balance_error(err: BondCtBalanceError) -> u8 {
    match err {
        BondCtBalanceError::InvalidPoint => SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_INVALID_POINT,
        BondCtBalanceError::SumMismatch => SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_SUM_MISMATCH,
    }
}

/// Flattened `count × 32` commitment keys from a C pointer; rejects overflow and oversize slices.
///
/// # Safety
///
/// When `count > 0`, `ptr` must address `count * 32` valid bytes for the lifetime `'a`.
unsafe fn flat_commitment_keys<'a>(ptr: *const u8, count: usize) -> Result<&'a [u8], u8> {
    if count == 0 {
        return Ok(&[]);
    }
    let Some(byte_len) = count.checked_mul(32) else {
        return Err(SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_INVALID_POINT);
    };
    if byte_len > isize::MAX as usize {
        return Err(SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_INVALID_POINT);
    }
    // SAFETY: caller contract per function docs.
    Ok(std::slice::from_raw_parts(ptr, byte_len))
}

/// Verify bond-post CT balance: `sum(pseudoOuts) + bond_debit = sum(out masks) + fee + bond_credit`.
///
/// `pseudo_outs_ptr` and `out_masks_ptr` are flattened `N × 32` byte arrays; either pointer may
/// be null when the corresponding count is zero.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_verify_bond_post_ct_balance(
    pseudo_outs_ptr: *const u8,
    num_pseudo_outs: usize,
    out_masks_ptr: *const u8,
    num_out_masks: usize,
    txn_fee: u64,
    bond_credit: u64,
    bond_debit: u64,
) -> u8 {
    if num_pseudo_outs > 0 && pseudo_outs_ptr.is_null() {
        return SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_NULL_PTR;
    }
    if num_out_masks > 0 && out_masks_ptr.is_null() {
        return SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_NULL_PTR;
    }

    let pseudo_flat = match unsafe { flat_commitment_keys(pseudo_outs_ptr, num_pseudo_outs) } {
        Ok(slice) => slice,
        Err(code) => return code,
    };
    let mask_flat = match unsafe { flat_commitment_keys(out_masks_ptr, num_out_masks) } {
        Ok(slice) => slice,
        Err(code) => return code,
    };

    // The C ABI carries the two directions as separate u64s; convert to the
    // `BondTerm` the (total) core function takes, rejecting the both / neither /
    // zero states here — at the untrusted-input boundary — with the same status
    // codes. Matching on the `NonZeroAtomicUnits` options folds the zero-amount
    // case into "neither term" for free (a zero credit or debit is `None`).
    let term = match (
        NonZeroAtomicUnits::new(AtomicUnits::from_raw(bond_credit)),
        NonZeroAtomicUnits::new(AtomicUnits::from_raw(bond_debit)),
    ) {
        (None, None) => return SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_NO_BOND_TERM,
        (Some(credit), None) => BondTerm::Credit(credit),
        (None, Some(debit)) => BondTerm::Debit(debit),
        (Some(_), Some(_)) => return SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_BOTH_TERMS,
    };

    match verify_bond_post_ct_balance(pseudo_flat, mask_flat, txn_fee, term) {
        Ok(()) => SHEKYL_ARCHIVAL_BOND_CT_BALANCE_OK,
        Err(e) => map_bond_ct_balance_error(e),
    }
}
