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
//! The call returns the error enum flattened to a code (`0` is conformant) and
//! writes the error's own sentence into a caller-owned buffer. The daemon logs
//! that sentence verbatim rather than formatting a second one from the code:
//! two formatters producing "the same message" is a synchronisation promise
//! nobody can keep, and the rule's words belong to the crate that owns the
//! rule. The code is what the daemon branches on; the string is what it prints.

use std::os::raw::c_char;

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

/// Buffer size the caller must provide for the message, NUL included. The
/// longest sentence this type produces is well under half of it; a message
/// that would not fit is truncated on a character boundary, never unterminated.
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_MSG_CAP: usize = 256;

fn code(err: PqcFieldShapeError) -> i32 {
    use PqcFieldShapeError as E;
    const KEM: u8 = shekyl_wire::tx_extra::TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT;
    match err {
        E::PresentWithoutOutputs { tag } if tag == KEM => {
            SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_PRESENT_WITHOUT_OUTPUTS
        }
        E::PresentWithoutOutputs { .. } => SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_PRESENT_WITHOUT_OUTPUTS,
        E::Missing { tag, .. } if tag == KEM => SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_MISSING,
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
/// On a non-conformant shape the error's sentence is written to `out_msg` as a
/// NUL-terminated string (at most `out_msg_cap` bytes including the NUL,
/// truncated on a character boundary if it would not fit); on
/// [`SHEKYL_TX_EXTRA_PQC_SHAPE_OK`] the buffer is set to the empty string.
/// `out_msg` may be null with `out_msg_cap` 0 for a caller that wants only the
/// code.
///
/// # Safety
/// The arrays are valid for their counts, and `out_msg` is writable for
/// `out_msg_cap` bytes, for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn shekyl_tx_extra_pqc_field_shape(
    n_outputs: usize,
    kem_lens: *const usize,
    kem_count: usize,
    leaf_lens: *const usize,
    leaf_count: usize,
    out_msg: *mut c_char,
    out_msg_cap: usize,
) -> i32 {
    // SAFETY: caller contract on `out_msg` / `out_msg_cap`.
    unsafe { write_msg(out_msg, out_msg_cap, "") };
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
        Err(err) => {
            // SAFETY: caller contract on `out_msg` / `out_msg_cap`.
            unsafe { write_msg(out_msg, out_msg_cap, &err.to_string()) };
            code(err)
        }
    }
}

/// Write `msg` NUL-terminated into a caller-owned buffer, truncating on a
/// character boundary. A null buffer or a zero capacity writes nothing.
unsafe fn write_msg(out: *mut c_char, cap: usize, msg: &str) {
    if out.is_null() || cap == 0 {
        return;
    }
    let mut n = msg.len().min(cap - 1);
    while n > 0 && !msg.is_char_boundary(n) {
        n -= 1;
    }
    // SAFETY: `out` is writable for `cap` bytes per the caller's contract and
    // `n < cap`, so the bytes and the terminator both land inside it. The
    // regions cannot overlap: `msg` is Rust-owned.
    unsafe {
        std::ptr::copy_nonoverlapping(msg.as_ptr().cast::<c_char>(), out, n);
        *out.add(n) = 0;
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

    fn call(n: usize, kem: &[usize], leaf: &[usize], msg: &mut [c_char]) -> i32 {
        unsafe {
            shekyl_tx_extra_pqc_field_shape(
                n,
                if kem.is_empty() { std::ptr::null() } else { kem.as_ptr() },
                kem.len(),
                if leaf.is_empty() { std::ptr::null() } else { leaf.as_ptr() },
                leaf.len(),
                msg.as_mut_ptr(),
                msg.len(),
            )
        }
    }

    fn text(msg: &[c_char]) -> String {
        let bytes: Vec<u8> = msg
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        String::from_utf8(bytes).expect("the message is UTF-8")
    }

    #[test]
    fn codes_follow_the_rule() {
        const K: usize = 1120;
        const L: usize = 32;
        let mut msg = [0 as c_char; SHEKYL_TX_EXTRA_PQC_SHAPE_MSG_CAP];

        assert_eq!(call(1, &[K], &[L], &mut msg), SHEKYL_TX_EXTRA_PQC_SHAPE_OK);
        assert_eq!(text(&msg), "", "a conformant shape leaves no message");
        assert_eq!(call(0, &[], &[], &mut msg), SHEKYL_TX_EXTRA_PQC_SHAPE_OK);

        assert_eq!(
            call(1, &[K], &[L, L], &mut msg),
            SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_DUPLICATE
        );
        assert_eq!(
            text(&msg),
            "tx_extra 0x07 appears 2 times; exactly one is admitted"
        );

        assert_eq!(
            call(1, &[], &[L], &mut msg),
            SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_MISSING
        );
        assert_eq!(
            text(&msg),
            "tx_extra 0x06 missing on a transaction with outputs; 1120 bytes required"
        );

        assert_eq!(
            call(2, &[K], &[L], &mut msg),
            SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_LENGTH
        );
        assert_eq!(
            text(&msg),
            "tx_extra 0x06 is 1120 bytes; 2240 required for this output count"
        );

        assert_eq!(
            call(0, &[K], &[], &mut msg),
            SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_PRESENT_WITHOUT_OUTPUTS
        );

        // A null array with a non-zero count is refused, not dereferenced.
        assert_eq!(
            unsafe {
                shekyl_tx_extra_pqc_field_shape(
                    1,
                    std::ptr::null(),
                    1,
                    [L].as_ptr(),
                    1,
                    msg.as_mut_ptr(),
                    msg.len(),
                )
            },
            SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_NULL_PTR
        );

        // A buffer too small truncates and still terminates; a null buffer is
        // tolerated for a caller that wants only the code.
        let mut small = [0 as c_char; 8];
        assert_eq!(
            call(1, &[K], &[L, L], &mut small),
            SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_DUPLICATE
        );
        assert_eq!(text(&small), "tx_extr");
        assert_eq!(
            unsafe {
                shekyl_tx_extra_pqc_field_shape(1, [K].as_ptr(), 1, std::ptr::null(), 0, std::ptr::null_mut(), 0)
            },
            SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_MISSING
        );
    }
}
