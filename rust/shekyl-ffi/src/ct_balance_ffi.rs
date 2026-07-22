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
//!
//! The module also exports the §2.3 **output-point validity** rule
//! ([`shekyl_check_output_keys`] / [`shekyl_check_commitment_masks`], ratified
//! 2026-07-22, prompted by advisory GHSA-r675-h3pj-wj2f): the admission gates
//! for output public keys and coinbase `outPk` masks, replacing the inherited
//! `crypto::check_key` (curve-point-only) and the native
//! `check_commitment_mask_valid` fingerprint block in `blockchain.cpp`.

use shekyl_ct_balance::{
    check_commitment_masks, check_output_keys, verify_ct_balance, CtBalanceError, OutputPointsError,
};
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

/// Output-point validity codes (`GENESIS_TX_WIRE_FORMAT.md` §2.3 output-point
/// rule). All points are canonical, prime-order, and structurally valid.
pub const SHEKYL_OUTPUT_POINTS_OK: u8 = 0;
/// A required pointer was null while its count was nonzero.
pub const SHEKYL_OUTPUT_POINTS_ERR_NULL_PTR: u8 = 1;
/// An output public key was non-canonical, torsioned, the identity, or
/// `count * 32` overflowed in the flatten path.
pub const SHEKYL_OUTPUT_POINTS_ERR_INVALID_KEY: u8 = 2;
/// A commitment mask was non-canonical or torsioned, or `count * 32` overflowed.
pub const SHEKYL_OUTPUT_POINTS_ERR_INVALID_MASK: u8 = 3;
/// A commitment mask took a trivial amount-leaking form (identity, `G`, or
/// coinbase `zeroCommit(amount)`).
pub const SHEKYL_OUTPUT_POINTS_ERR_TRIVIAL_MASK: u8 = 4;

fn map_err(e: CtBalanceError) -> u8 {
    match e {
        CtBalanceError::InvalidPoint => SHEKYL_CT_BALANCE_ERR_INVALID_POINT,
        CtBalanceError::SumMismatch => SHEKYL_CT_BALANCE_ERR_SUM_MISMATCH,
    }
}

fn map_output_points_err(e: OutputPointsError) -> u8 {
    match e {
        OutputPointsError::InvalidOutputKey => SHEKYL_OUTPUT_POINTS_ERR_INVALID_KEY,
        OutputPointsError::InvalidMask => SHEKYL_OUTPUT_POINTS_ERR_INVALID_MASK,
        OutputPointsError::TrivialMask => SHEKYL_OUTPUT_POINTS_ERR_TRIVIAL_MASK,
    }
}

/// Validate `(ptr, count)` and return the flattened byte length
/// (`count * elem_size`). `overflow_code` is the caller's shape-error code, so
/// the balance and output-point entry points each report overflow in their own
/// code space (`NULL_PTR` is `1` in both).
///
/// Deliberately returns the *length*, not the slice: the caller builds the slice
/// locally so it cannot outlive the FFI call. (An earlier `-> &'a [u8]` form left
/// `'a` unconstrained, letting a caller pick any lifetime — a footgun even though
/// the call site consumes the slice immediately.) A safe fn — it never
/// dereferences `ptr`, only null-checks it and computes the length.
fn flat_len_sized<T>(
    ptr: *const T,
    count: usize,
    elem_size: usize,
    overflow_code: u8,
) -> Result<usize, u8> {
    if count == 0 {
        return Ok(0);
    }
    if ptr.is_null() {
        return Err(SHEKYL_CT_BALANCE_ERR_NULL_PTR);
    }
    let Some(byte_len) = count.checked_mul(elem_size) else {
        return Err(overflow_code);
    };
    if byte_len > isize::MAX as usize {
        return Err(overflow_code);
    }
    Ok(byte_len)
}

fn flat_len(ptr: *const u8, count: usize) -> Result<usize, u8> {
    flat_len_sized(ptr, count, 32, SHEKYL_CT_BALANCE_ERR_INVALID_POINT)
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

/// Check output public keys against the §2.3 output-point rule: each 32-byte
/// key in the flattened `num_keys × 32` buffer must be a canonical,
/// prime-order (torsion-free), non-identity curve25519 point.
///
/// Replaces the inherited `crypto::check_key` (curve-point-only) on the
/// admission path — the FCMP++ leaf builder decodes prime-order-only, so
/// anything laxer here admits outputs the curve tree silently skips.
/// `keys_ptr` may be null when `num_keys` is zero.
///
/// # Safety
///
/// `keys_ptr` must address `num_keys * 32` valid bytes for the duration of the
/// call when `num_keys` is nonzero.
#[no_mangle]
pub unsafe extern "C" fn shekyl_check_output_keys(keys_ptr: *const u8, num_keys: usize) -> u8 {
    let keys_len =
        match flat_len_sized(keys_ptr, num_keys, 32, SHEKYL_OUTPUT_POINTS_ERR_INVALID_KEY) {
            Ok(len) => len,
            Err(code) => return code,
        };
    // SAFETY: `flat_len_sized` proved `keys_len = num_keys * 32 <= isize::MAX`
    // and that the pointer is non-null whenever the length is nonzero; the
    // caller's safety contract guarantees those bytes are valid for this call.
    let keys_flat: &[u8] = if keys_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(keys_ptr, keys_len) }
    };
    match check_output_keys(keys_flat) {
        Ok(()) => SHEKYL_OUTPUT_POINTS_OK,
        Err(e) => map_output_points_err(e),
    }
}

/// Check `outPk` commitment masks against the §2.3 output-point rule plus the
/// trivial-mask fingerprint guards (identity, `G`, coinbase
/// `zeroCommit(amount)`).
///
/// `masks_ptr` is a flattened `num_masks × 32` buffer. For a **coinbase** tx,
/// pass the cleartext vout amounts via `coinbase_amounts_ptr` /
/// `num_coinbase_amounts` (mask `i` is checked against
/// `zeroCommit(amounts[i])` for `i < num_coinbase_amounts`); for non-coinbase
/// txs pass `(null, 0)`, which skips only the coinbase fingerprint. Either
/// pointer may be null when its count is zero.
///
/// # Safety
///
/// `masks_ptr` must address `num_masks * 32` valid bytes and
/// `coinbase_amounts_ptr` must address `num_coinbase_amounts` valid `u64`s for
/// the duration of the call when their counts are nonzero.
#[no_mangle]
pub unsafe extern "C" fn shekyl_check_commitment_masks(
    masks_ptr: *const u8,
    num_masks: usize,
    coinbase_amounts_ptr: *const u64,
    num_coinbase_amounts: usize,
) -> u8 {
    let masks_len = match flat_len_sized(
        masks_ptr,
        num_masks,
        32,
        SHEKYL_OUTPUT_POINTS_ERR_INVALID_MASK,
    ) {
        Ok(len) => len,
        Err(code) => return code,
    };
    if num_coinbase_amounts > 0 && coinbase_amounts_ptr.is_null() {
        return SHEKYL_OUTPUT_POINTS_ERR_NULL_PTR;
    }
    // SAFETY: `flat_len_sized` proved `masks_len = num_masks * 32 <= isize::MAX`
    // and that the pointer is non-null whenever the length is nonzero; the
    // caller's safety contract guarantees those bytes are valid for this call.
    let masks_flat: &[u8] = if masks_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(masks_ptr, masks_len) }
    };
    // SAFETY: null-checked above when the count is nonzero; the caller's safety
    // contract guarantees `num_coinbase_amounts` valid, aligned `u64`s.
    let coinbase_amounts: Option<&[u64]> = if num_coinbase_amounts == 0 {
        None
    } else {
        Some(unsafe { std::slice::from_raw_parts(coinbase_amounts_ptr, num_coinbase_amounts) })
    };
    match check_commitment_masks(masks_flat, coinbase_amounts) {
        Ok(()) => SHEKYL_OUTPUT_POINTS_OK,
        Err(e) => map_output_points_err(e),
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

    // curve25519 identity in canonical compressed form (y = 1).
    const IDENTITY: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    };

    fn g_bytes() -> [u8; 32] {
        curve25519_dalek::constants::ED25519_BASEPOINT_POINT
            .compress()
            .to_bytes()
    }

    #[test]
    fn output_keys_accept_and_reject() {
        let g = g_bytes();
        assert_eq!(
            unsafe { shekyl_check_output_keys(g.as_ptr(), 1) },
            SHEKYL_OUTPUT_POINTS_OK
        );
        assert_eq!(
            unsafe { shekyl_check_output_keys(ptr::null(), 0) },
            SHEKYL_OUTPUT_POINTS_OK
        );
        assert_eq!(
            unsafe { shekyl_check_output_keys(TORSION.as_ptr(), 1) },
            SHEKYL_OUTPUT_POINTS_ERR_INVALID_KEY
        );
        assert_eq!(
            unsafe { shekyl_check_output_keys(IDENTITY.as_ptr(), 1) },
            SHEKYL_OUTPUT_POINTS_ERR_INVALID_KEY
        );
        assert_eq!(
            unsafe { shekyl_check_output_keys(ptr::null(), 1) },
            SHEKYL_OUTPUT_POINTS_ERR_NULL_PTR
        );
    }

    #[test]
    fn commitment_masks_accept_and_reject() {
        // A generic mask zG (z != 0, 1) is structurally fine.
        let mask = (curve25519_dalek::scalar::Scalar::from_bytes_mod_order([5u8; 32])
            * curve25519_dalek::constants::ED25519_BASEPOINT_POINT)
            .compress()
            .to_bytes();
        assert_eq!(
            unsafe { shekyl_check_commitment_masks(mask.as_ptr(), 1, ptr::null(), 0) },
            SHEKYL_OUTPUT_POINTS_OK
        );
        assert_eq!(
            unsafe { shekyl_check_commitment_masks(TORSION.as_ptr(), 1, ptr::null(), 0) },
            SHEKYL_OUTPUT_POINTS_ERR_INVALID_MASK
        );
        let g = g_bytes();
        assert_eq!(
            unsafe { shekyl_check_commitment_masks(g.as_ptr(), 1, ptr::null(), 0) },
            SHEKYL_OUTPUT_POINTS_ERR_TRIVIAL_MASK
        );
        assert_eq!(
            unsafe { shekyl_check_commitment_masks(mask.as_ptr(), 1, ptr::null(), 1) },
            SHEKYL_OUTPUT_POINTS_ERR_NULL_PTR
        );
    }

    #[test]
    fn coinbase_zero_commit_fingerprint_fires_through_ffi() {
        const AMOUNT: u64 = 600_000_000_000;
        let zero_commit = (curve25519_dalek::constants::ED25519_BASEPOINT_POINT
            + shekyl_ct_balance::amount_commitment(AtomicUnits::from_raw(AMOUNT)))
        .compress()
        .to_bytes();
        let amounts = [AMOUNT];
        assert_eq!(
            unsafe { shekyl_check_commitment_masks(zero_commit.as_ptr(), 1, amounts.as_ptr(), 1) },
            SHEKYL_OUTPUT_POINTS_ERR_TRIVIAL_MASK
        );
        // Without the coinbase amounts the same point is a well-formed mask.
        assert_eq!(
            unsafe { shekyl_check_commitment_masks(zero_commit.as_ptr(), 1, ptr::null(), 0) },
            SHEKYL_OUTPUT_POINTS_OK
        );
    }
}
