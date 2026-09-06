// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FFI surface for the `tx_extra` PQC field shape rule
//! ([`shekyl_wire::tx_extra::check_pqc_field_shape`]; `GENESIS_TX_WIRE_FORMAT.md`
//! §9.6a as ruled 2026-09-05, census CEN-I19).
//!
//! The daemon parses `tx_extra` with its own parser and hands over only the
//! facts the rule needs — the output count and the byte length of every
//! `0x06` and `0x07` field found — so the rule has one home (the wire crate,
//! where the port applies it to its own parse) and the C++ admission path is
//! an adapter. Called from `core::check_tx_semantic` (relay and block) and
//! `Blockchain::prevalidate_miner_transaction` (coinbase).
//!
//! Return codes are the error enum flattened; `0` is conformant. The daemon
//! turns the code back into the same sentence the Rust error displays.

use shekyl_wire::tx_extra::{check_pqc_field_shape, PqcFieldShapeError};

/// Conformant.
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_OK: i32 = 0;
/// A null pointer with a non-zero count.
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_NULL_PTR: i32 = 1;
/// `0x06` present on a transaction with no outputs.
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_PRESENT_WITHOUT_OUTPUTS: i32 = 2;
/// `0x06` missing on a transaction with outputs.
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_MISSING: i32 = 3;
/// More than one `0x06` field.
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_DUPLICATE: i32 = 4;
/// The `0x06` field is not `1120 · n_outputs` bytes.
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_LENGTH: i32 = 5;
/// `0x07` present on a transaction with no outputs.
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_PRESENT_WITHOUT_OUTPUTS: i32 = 6;
/// `0x07` missing on a transaction with outputs.
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_MISSING: i32 = 7;
/// More than one `0x07` field.
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_DUPLICATE: i32 = 8;
/// The `0x07` field is not `32 · n_outputs` bytes.
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_LENGTH: i32 = 9;

fn code(err: PqcFieldShapeError) -> i32 {
    use PqcFieldShapeError as E;
    const KEM: u8 = shekyl_wire::tx_extra::TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT;
    match err {
        E::PresentWithoutOutputs { tag } if tag == KEM => {
            SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_PRESENT_WITHOUT_OUTPUTS
        }
        E::PresentWithoutOutputs { .. } => SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_PRESENT_WITHOUT_OUTPUTS,
        E::Missing { tag } if tag == KEM => SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_MISSING,
        E::Missing { .. } => SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_MISSING,
        E::Duplicate { tag, .. } if tag == KEM => SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_DUPLICATE,
        E::Duplicate { .. } => SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_DUPLICATE,
        E::Length { tag, .. } if tag == KEM => SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_LENGTH,
        E::Length { .. } => SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_LENGTH,
    }
}

/// Apply the shape rule. `kem_lens` / `leaf_lens` point to `kem_count` /
/// `leaf_count` byte lengths, one per `0x06` / `0x07` field the caller's
/// parser found, in order (a null pointer is accepted only with count 0).
///
/// # Safety
/// The arrays are valid for their counts for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn shekyl_tx_extra_pqc_field_shape(
    n_outputs: usize,
    kem_lens: *const usize,
    kem_count: usize,
    leaf_lens: *const usize,
    leaf_count: usize,
) -> i32 {
    // SAFETY: caller contract on both arrays.
    let (kem, leaf) = unsafe {
        let Some(kem) = usize_slice(kem_lens, kem_count) else {
            return SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_NULL_PTR;
        };
        let Some(leaf) = usize_slice(leaf_lens, leaf_count) else {
            return SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_NULL_PTR;
        };
        (kem, leaf)
    };
    match check_pqc_field_shape(n_outputs, kem, leaf) {
        Ok(()) => SHEKYL_TX_EXTRA_PQC_SHAPE_OK,
        Err(err) => code(err),
    }
}

/// Borrow `count` `usize`s; a null pointer is accepted only with count 0.
/// The file's one typed-slice raw site (pinned in the boundary ratchet); it
/// re-owns the `isize::MAX` byte bound the language requires.
unsafe fn usize_slice<'a>(ptr: *const usize, count: usize) -> Option<&'a [usize]> {
    if count == 0 {
        return Some(&[]);
    }
    if ptr.is_null() || count > isize::MAX as usize / std::mem::size_of::<usize>() {
        return None;
    }
    // SAFETY: non-null, `count` initialized elements per the caller's
    // contract, byte length bounded above; the borrow does not outlive the
    // FFI call.
    Some(unsafe { std::slice::from_raw_parts(ptr, count) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_follow_the_rule() {
        let k = [1120usize];
        let l = [32usize];
        let l2 = [32usize, 32];
        unsafe {
            assert_eq!(
                shekyl_tx_extra_pqc_field_shape(1, k.as_ptr(), 1, l.as_ptr(), 1),
                0
            );
            assert_eq!(
                shekyl_tx_extra_pqc_field_shape(0, std::ptr::null(), 0, std::ptr::null(), 0),
                0
            );
            assert_eq!(
                shekyl_tx_extra_pqc_field_shape(1, k.as_ptr(), 1, l2.as_ptr(), 2),
                SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_DUPLICATE
            );
            assert_eq!(
                shekyl_tx_extra_pqc_field_shape(1, std::ptr::null(), 0, l.as_ptr(), 1),
                SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_MISSING
            );
            assert_eq!(
                shekyl_tx_extra_pqc_field_shape(2, k.as_ptr(), 1, l.as_ptr(), 1),
                SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_LENGTH
            );
            assert_eq!(
                shekyl_tx_extra_pqc_field_shape(0, k.as_ptr(), 1, std::ptr::null(), 0),
                SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_PRESENT_WITHOUT_OUTPUTS
            );
            assert_eq!(
                shekyl_tx_extra_pqc_field_shape(1, std::ptr::null(), 1, l.as_ptr(), 1),
                SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_NULL_PTR
            );
        }
    }
}
