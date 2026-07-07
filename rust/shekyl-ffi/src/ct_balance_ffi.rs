// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! General CT cleartext-balance verification FFI.
//!
//! Exposes `shekyl-ct-balance`'s commitment-sum balance equation to the C++
//! consensus hook for the *general* spend / fee-only shapes (no bond terms) —
//! the sibling of the bond-post export in [`crate::archival_ffi`]. The genesis
//! rule it enforces — canonical prime-order commitment points, and the
//! transaction-malleability surface that rule closes — is ratified in
//! `GENESIS_TX_WIRE_FORMAT.md` §2.3.
//!
//! This is the Rust side of the `verRctSemanticsSimple` / `verRctSemanticsFeeOnly`
//! cutover (FOLLOWUPS V3.0). The export lands *ahead* of the C++ re-point so the
//! pre-cutover differential corpus can exercise it against the C++ oracle; it is
//! dormant (called by no consensus path) until the atomic cutover swaps
//! `rctSigs.cpp`'s native `addKeys`/`equalKeys` block for this call.

use shekyl_ct_balance::{verify_ct_balance, CtBalanceError};
use shekyl_units::AtomicUnits;

/// Balance holds (`ΣpseudoOuts = Σout_masks + fee*H`) over canonical prime-order points.
pub const SHEKYL_CT_BALANCE_OK: u8 = 0;
/// A required pointer was null while its count was nonzero.
pub const SHEKYL_CT_BALANCE_ERR_NULL_PTR: u8 = 1;
/// A commitment was non-canonical / not torsion-free, or `count * 32` overflowed
/// in the flatten path. (The flat buffer is always `count * 32` bytes here, so a
/// non-multiple-of-32 length is not reachable through this `ptr + count` FFI.)
pub const SHEKYL_CT_BALANCE_ERR_INVALID_POINT: u8 = 2;
/// The input-side and output-side commitment sums differ.
pub const SHEKYL_CT_BALANCE_ERR_SUM_MISMATCH: u8 = 3;

fn map_err(e: CtBalanceError) -> u8 {
    match e {
        CtBalanceError::InvalidPoint => SHEKYL_CT_BALANCE_ERR_INVALID_POINT,
        CtBalanceError::SumMismatch => SHEKYL_CT_BALANCE_ERR_SUM_MISMATCH,
    }
}

/// Validate `(ptr, count)` and return the flattened byte length (`count * 32`).
///
/// Deliberately returns the *length*, not the slice: the caller builds the slice
/// locally so it cannot outlive the FFI call. (An earlier `-> &'a [u8]` form left
/// `'a` unconstrained, letting a caller pick any lifetime — a footgun even though
/// the call site consumes the slice immediately.) A safe fn — it never
/// dereferences `ptr`, only null-checks it and computes the length.
fn flat_len(ptr: *const u8, count: usize) -> Result<usize, u8> {
    if count == 0 {
        return Ok(0);
    }
    if ptr.is_null() {
        return Err(SHEKYL_CT_BALANCE_ERR_NULL_PTR);
    }
    let Some(byte_len) = count.checked_mul(32) else {
        return Err(SHEKYL_CT_BALANCE_ERR_INVALID_POINT);
    };
    if byte_len > isize::MAX as usize {
        return Err(SHEKYL_CT_BALANCE_ERR_INVALID_POINT);
    }
    Ok(byte_len)
}

/// Verify the general CT cleartext balance `ΣpseudoOuts = Σout_masks + fee*H`.
///
/// `pseudo_outs_ptr` / `out_masks_ptr` are flattened `N × 32` byte arrays; either
/// pointer may be null when its count is zero (the fee-only shape has no
/// pseudoOuts). Every commitment must be a canonical prime-order point (§2.3),
/// else the call returns [`SHEKYL_CT_BALANCE_ERR_INVALID_POINT`] — and that check
/// runs **before** the sum comparison, so a torsion-laden input is rejected as
/// `INVALID_POINT`, never `SUM_MISMATCH`.
///
/// # Safety
///
/// `pseudo_outs_ptr` / `out_masks_ptr` must each address `count * 32` valid bytes
/// for the duration of the call when their count is nonzero.
#[no_mangle]
pub unsafe extern "C" fn shekyl_verify_ct_balance(
    pseudo_outs_ptr: *const u8,
    num_pseudo_outs: usize,
    out_masks_ptr: *const u8,
    num_out_masks: usize,
    txn_fee: u64,
) -> u8 {
    let pseudo_len = match flat_len(pseudo_outs_ptr, num_pseudo_outs) {
        Ok(len) => len,
        Err(code) => return code,
    };
    let mask_len = match flat_len(out_masks_ptr, num_out_masks) {
        Ok(len) => len,
        Err(code) => return code,
    };
    // Build both slices locally — they are bounded to this scope and never
    // returned, so no unbounded-lifetime slice escapes.
    // SAFETY: `flat_len` proved each length is `count * 32 <= isize::MAX` and that
    // the pointer is non-null whenever its length is nonzero; the caller's safety
    // contract guarantees those bytes are valid for this call.
    let pseudo_flat: &[u8] = if pseudo_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(pseudo_outs_ptr, pseudo_len) }
    };
    let mask_flat: &[u8] = if mask_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(out_masks_ptr, mask_len) }
    };
    match verify_ct_balance(
        pseudo_flat,
        mask_flat,
        AtomicUnits::from_raw(txn_fee),
        &[],
        &[],
    ) {
        Ok(()) => SHEKYL_CT_BALANCE_OK,
        Err(e) => map_err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    // A known curve25519 small-order (8-torsion) point, shared with the
    // `shekyl-ct-balance` crate's own `rejects_small_order_commitment` vector.
    const TORSION: [u8; 32] = [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0xfa,
    ];

    #[test]
    fn null_pointer_with_nonzero_count_is_rejected() {
        let code = unsafe { shekyl_verify_ct_balance(ptr::null(), 1, ptr::null(), 0, 0) };
        assert_eq!(code, SHEKYL_CT_BALANCE_ERR_NULL_PTR);
    }

    #[test]
    fn count_overflow_is_invalid_point() {
        let buf = [0u8; 32];
        let code = unsafe { shekyl_verify_ct_balance(buf.as_ptr(), usize::MAX, ptr::null(), 0, 0) };
        assert_eq!(code, SHEKYL_CT_BALANCE_ERR_INVALID_POINT);
    }

    #[test]
    fn empty_balance_with_zero_fee_is_ok() {
        // Σ(∅) = Σ(∅) + 0 — the degenerate identity-vs-identity case.
        let code = unsafe { shekyl_verify_ct_balance(ptr::null(), 0, ptr::null(), 0, 0) };
        assert_eq!(code, SHEKYL_CT_BALANCE_OK);
    }

    #[test]
    fn torsion_is_invalid_point_before_sum_mismatch() {
        // A torsion-only pseudoOut with no matching mask: the sum cannot balance,
        // yet the point check fires first — the FFI error-precedence the corpus
        // pins (INVALID_POINT ahead of SUM_MISMATCH).
        let code = unsafe { shekyl_verify_ct_balance(TORSION.as_ptr(), 1, ptr::null(), 0, 0) };
        assert_eq!(code, SHEKYL_CT_BALANCE_ERR_INVALID_POINT);
    }
}
