// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FFI surface for the `tx_extra` PQC field shape rule
//! ([`shekyl_wire::tx_extra::check_pqc_field_shape`]; `GENESIS_TX_WIRE_FORMAT.md`
//! §9.6a as ruled 2026-09-05, census CEN-I19).
//!
//! The daemon parses `tx_extra` with its own parser and hands over only the
//! facts the rule needs — the output count, the byte length of every
//! `0x06` and `0x07` field found, and the `0x07` payload bytes for the leaf
//! commitment content rule (`PL-D3`) — so the rule has one home (the wire crate,
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

use shekyl_wire::tx_extra::{check_pqc_field_shape, check_pqc_leaf_entries, ExtraShapeError};

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
/// The `0x07` field is not `64 · n_outputs` bytes.
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_LENGTH: i32 = 9;
/// A `0x07` entry's leaf commitment is not a canonical prime-order point
/// (`PL-D3` content rule).
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_POINT: i32 = 10;
/// The caller's `leaf_blob` disagrees with its declared `leaf_lens` (null
/// with a nonzero length, or a byte count other than the single declared
/// field's length). This is an FFI marshalling bug in the caller — a fact
/// about the call, not a verdict about the transaction's content — and it is
/// reported as such so the daemon never logs a content diagnosis (e.g. "leaf
/// commitment is not a canonical prime-order point") for a C++-side bug.
/// Fail-closed: the transaction is refused either way.
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_MARSHALLING: i32 = 11;
/// Coinbase grammar (`TXE-Q6′`): no `0x02` nonce in a coinbase extra.
pub const SHEKYL_TX_EXTRA_SHAPE_COINBASE_NONCE_MISSING: i32 = 12;
/// Coinbase grammar: the `0x02` nonce is not exactly `COINBASE_NONCE_BYTES`.
pub const SHEKYL_TX_EXTRA_SHAPE_COINBASE_NONCE_LENGTH: i32 = 13;
/// Coinbase grammar: more than one `0x02` nonce.
pub const SHEKYL_TX_EXTRA_SHAPE_COINBASE_NONCE_DUPLICATE: i32 = 14;
/// Coinbase grammar: a tag outside `[0x01, 0x02, 0x06, 0x07]`.
pub const SHEKYL_TX_EXTRA_SHAPE_COINBASE_FOREIGN_TAG: i32 = 15;
/// Coinbase grammar: the fields are out of canonical order, or the `0x01`
/// pubkey is missing or duplicated.
pub const SHEKYL_TX_EXTRA_SHAPE_COINBASE_LAYOUT: i32 = 16;
/// A `0x02` nonce on a non-coinbase transaction.
pub const SHEKYL_TX_EXTRA_SHAPE_NONCE_OUTSIDE_COINBASE: i32 = 17;

/// The sentence written for [`SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_MARSHALLING`].
/// Owned here (not in `shekyl-wire`): the wire crate rules on transaction
/// bytes; a blob/length disagreement never reaches it.
const MARSHALLING_MSG: &str = "FFI marshalling: leaf blob length disagrees with declared lengths";

/// Buffer size the caller must provide for the message, NUL included. The
/// longest sentence this type produces is well under half of it; a message
/// that would not fit is truncated on a character boundary, never unterminated.
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_MSG_CAP: usize = 256;

/// The flattened code for a shape verdict; shared with the codec surface
/// (`tx_extra_codec_ffi`), which returns these unchanged.
pub(crate) fn shape_code(err: ExtraShapeError) -> i32 {
    use ExtraShapeError as E;
    const KEM: u8 = shekyl_wire::tx_extra::TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT;
    const PUBKEY: u8 = shekyl_wire::tx_extra::TX_EXTRA_TAG_PUBKEY;
    const NONCE: u8 = shekyl_wire::tx_extra::TX_EXTRA_TAG_NONCE;
    match err {
        // Coinbase grammar arms first: `Missing` / `Duplicate` on the pubkey
        // and nonce tags are grammar verdicts, not PQC ones.
        E::Missing { tag, .. } if tag == PUBKEY => SHEKYL_TX_EXTRA_SHAPE_COINBASE_LAYOUT,
        E::Duplicate { tag, .. } if tag == PUBKEY => SHEKYL_TX_EXTRA_SHAPE_COINBASE_LAYOUT,
        E::Duplicate { tag, .. } if tag == NONCE => SHEKYL_TX_EXTRA_SHAPE_COINBASE_NONCE_DUPLICATE,
        E::CoinbaseNonceMissing => SHEKYL_TX_EXTRA_SHAPE_COINBASE_NONCE_MISSING,
        E::CoinbaseNonceLength { .. } => SHEKYL_TX_EXTRA_SHAPE_COINBASE_NONCE_LENGTH,
        E::CoinbaseForeignTag { .. } => SHEKYL_TX_EXTRA_SHAPE_COINBASE_FOREIGN_TAG,
        E::CoinbaseFieldOrder { .. } => SHEKYL_TX_EXTRA_SHAPE_COINBASE_LAYOUT,
        E::NonceOutsideCoinbase => SHEKYL_TX_EXTRA_SHAPE_NONCE_OUTSIDE_COINBASE,
        E::PresentWithoutOutputs { tag } if tag == KEM => {
            SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_PRESENT_WITHOUT_OUTPUTS
        }
        E::PresentWithoutOutputs { .. } => SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_PRESENT_WITHOUT_OUTPUTS,
        E::Missing { tag, .. } if tag == KEM => SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_MISSING,
        E::Missing { .. } => SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_MISSING,
        E::Duplicate { tag, .. } if tag == KEM => SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_DUPLICATE,
        E::Duplicate { .. } => SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_DUPLICATE,
        E::Length { tag, .. } if tag == KEM => SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_LENGTH,
        // `LeafBlobLength` is the content rule's own precondition
        // (`check_pqc_leaf_entries` on a blob that is not a whole, non-zero
        // number of 64-byte entries). Unreachable through this FFI — the
        // shape rule has already pinned the single field to `64 · n_outputs`
        // bytes and the marshalling check has pinned the handed-over blob to
        // that declared length — but mapped to the length-family code
        // (fail-closed) rather than dropped, so a future reordering can
        // never turn it into an "OK".
        E::Length { .. } | E::LeafBlobLength { .. } => SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_LENGTH,
        E::LeafPointInvalid { .. } => SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_POINT,
    }
}

/// Apply the shape rule, then the `0x07` content rule. `kem_lens` /
/// `leaf_lens` point to `kem_count` / `leaf_count` byte lengths, one per
/// `0x06` / `0x07` field the caller's parser found, in order (a null pointer
/// is accepted only with count 0). `leaf_blob` / `leaf_blob_len` are the bytes
/// of the `0x07` field when the parser found exactly one (null with length 0
/// otherwise); once the shape rule has admitted a single correctly-sized
/// field, every entry's commitment point is checked
/// ([`check_pqc_leaf_entries`], `PL-D3`). A `leaf_blob` that disagrees with
/// the declared `leaf_lens` (null with a nonzero length, or a different byte
/// count) is refused with [`SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_MARSHALLING`] —
/// a caller bug, reported distinctly from any content verdict.
///
/// On a non-conformant shape the error's sentence is written to `out_msg` as a
/// NUL-terminated string (at most `out_msg_cap` bytes including the NUL,
/// truncated on a character boundary if it would not fit); on
/// [`SHEKYL_TX_EXTRA_PQC_SHAPE_OK`] the buffer is set to the empty string.
/// `out_msg` may be null with `out_msg_cap` 0 for a caller that wants only the
/// code.
///
/// # Safety
/// The arrays are valid for their counts, `leaf_blob` is readable for
/// `leaf_blob_len` bytes, and `out_msg` is writable for `out_msg_cap` bytes,
/// for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn shekyl_tx_extra_pqc_field_shape(
    n_outputs: usize,
    kem_lens: *const usize,
    kem_count: usize,
    leaf_lens: *const usize,
    leaf_count: usize,
    leaf_blob: *const u8,
    leaf_blob_len: usize,
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
    if let Err(err) = check_pqc_field_shape(n_outputs, kem, leaf) {
        // SAFETY: caller contract on `out_msg` / `out_msg_cap`.
        unsafe { write_msg(out_msg, out_msg_cap, &err.to_string()) };
        return shape_code(err);
    }
    if leaf.len() != 1 {
        // Only the `n_outputs == 0` arm admits no field; nothing to check.
        return SHEKYL_TX_EXTRA_PQC_SHAPE_OK;
    }
    // SAFETY: caller contract on `leaf_blob` / `leaf_blob_len`.
    let blob = unsafe { byte_slice(leaf_blob, leaf_blob_len) };
    // The caller said one field of `leaf[0]` bytes but handed over something
    // else (a null blob with a nonzero length, or a different byte count).
    // That is a marshalling bug in the caller, not a fact about the
    // transaction: refuse with the marshalling code — never "conformant",
    // and never a content verdict the daemon would log as a bad entry.
    let (Some(blob), true) = (blob, leaf_blob_len == leaf[0]) else {
        // SAFETY: caller contract on `out_msg` / `out_msg_cap`.
        unsafe { write_msg(out_msg, out_msg_cap, MARSHALLING_MSG) };
        return SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_MARSHALLING;
    };
    match check_pqc_leaf_entries(blob) {
        Ok(()) => SHEKYL_TX_EXTRA_PQC_SHAPE_OK,
        Err(err) => {
            // SAFETY: caller contract on `out_msg` / `out_msg_cap`.
            unsafe { write_msg(out_msg, out_msg_cap, &err.to_string()) };
            shape_code(err)
        }
    }
}

/// Borrow `len` bytes; a null pointer is accepted only with length 0.
/// Routed through the crate's one byte-slice seam (`slice_from_ptr`) so this
/// file adds no raw site of its own (SA-R-7 boundary ratchet).
unsafe fn byte_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    // SAFETY: the caller's contract — `len` readable bytes behind a non-null
    // `ptr` — is exactly the seam helper's precondition; the borrow does not
    // outlive the FFI call.
    unsafe { crate::legacy_util::slice_from_ptr(ptr, len) }
}

/// Write `msg` NUL-terminated into a caller-owned buffer, truncating on a
/// character boundary. A null buffer or a zero capacity writes nothing.
pub(crate) unsafe fn write_msg(out: *mut c_char, cap: usize, msg: &str) {
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

/// Write the conforming 64-byte `0x07` leaf entry
/// ([`shekyl_wire::tx_extra::conforming_pqc_leaf_entry`]) to `out`: the
/// compressed `PQC_LEAF_COMMITMENT_J` generator followed by the fixed opaque
/// record. Exists for the C++ unit-test fixtures
/// (`tests/unit_tests/pqc_spend_fixture.h`), which previously hand-copied the
/// point's bytes — one code path on both sides makes drift impossible.
/// Test-support surface, not consensus: production callers derive real
/// entries via `shekyl_derive_pqc_leaf_entry`.
///
/// # Safety
/// `out` must point to 64 writable bytes; null is tolerated (no write).
#[no_mangle]
pub unsafe extern "C" fn shekyl_test_conforming_pqc_leaf_entry(out: *mut u8) {
    if out.is_null() {
        return;
    }
    let entry = shekyl_wire::tx_extra::conforming_pqc_leaf_entry();
    // SAFETY: caller contract — 64 writable bytes behind a non-null `out`.
    unsafe { std::ptr::copy_nonoverlapping(entry.as_ptr(), out, entry.len()) };
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

    /// Shape-only call: with exactly one `0x07` length the content rule
    /// needs bytes, so a conforming blob of that length is supplied.
    fn call(n: usize, kem: &[usize], leaf: &[usize], msg: &mut [c_char]) -> i32 {
        let blob = match leaf {
            [len] => shekyl_wire::tx_extra::conforming_pqc_leaf_blob(len / 64),
            _ => Vec::new(),
        };
        call_with_blob(n, kem, leaf, &blob, msg)
    }

    fn call_with_blob(
        n: usize,
        kem: &[usize],
        leaf: &[usize],
        blob: &[u8],
        msg: &mut [c_char],
    ) -> i32 {
        unsafe {
            shekyl_tx_extra_pqc_field_shape(
                n,
                if kem.is_empty() {
                    std::ptr::null()
                } else {
                    kem.as_ptr()
                },
                kem.len(),
                if leaf.is_empty() {
                    std::ptr::null()
                } else {
                    leaf.as_ptr()
                },
                leaf.len(),
                if blob.is_empty() {
                    std::ptr::null()
                } else {
                    blob.as_ptr()
                },
                blob.len(),
                msg.as_mut_ptr(),
                msg.len(),
            )
        }
    }

    /// The message the call wrote, as the daemon would read it. `CStr` keeps
    /// this portable across platforms where `c_char` is unsigned.
    fn text(msg: &[c_char]) -> String {
        // SAFETY: every path through the call under test NUL-terminates
        // inside the buffer, which is what this asserts about.
        unsafe { std::ffi::CStr::from_ptr(msg.as_ptr()) }
            .to_str()
            .expect("the message is UTF-8")
            .to_owned()
    }

    #[test]
    fn codes_follow_the_rule() {
        const K: usize = 1120;
        const L: usize = 64;
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
                    std::ptr::null(),
                    0,
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
                shekyl_tx_extra_pqc_field_shape(
                    1,
                    [K].as_ptr(),
                    1,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null_mut(),
                    0,
                )
            },
            SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_MISSING
        );
    }

    /// The `0x07` content rule (PL-D3) runs after the shape rule admits a
    /// single correctly-sized field: a zero-filled entry, a small-order
    /// point, and a blob shorter than the declared length are all refused
    /// with the point code; a valid blob passes.
    #[test]
    fn leaf_point_content_rule() {
        const K: usize = 1120;
        const L: usize = 64;
        let mut msg = [0 as c_char; SHEKYL_TX_EXTRA_PQC_SHAPE_MSG_CAP];
        let good = shekyl_wire::tx_extra::conforming_pqc_leaf_blob(2);
        assert_eq!(
            call_with_blob(2, &[2 * K], &[2 * L], &good, &mut msg),
            SHEKYL_TX_EXTRA_PQC_SHAPE_OK
        );
        let zeros = vec![0u8; 2 * L];
        assert_eq!(
            call_with_blob(2, &[2 * K], &[2 * L], &zeros, &mut msg),
            SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_POINT
        );
        assert_eq!(
            text(&msg),
            "tx_extra 0x07 entry 0: leaf commitment is not a canonical prime-order point"
        );
        let mut torsion = good.clone();
        torsion[L..L + 32].copy_from_slice(&[0u8; 32]);
        assert_eq!(
            call_with_blob(2, &[2 * K], &[2 * L], &torsion, &mut msg),
            SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_POINT
        );
        assert_eq!(
            text(&msg),
            "tx_extra 0x07 entry 1: leaf commitment is not a canonical prime-order point"
        );
        // Declared length and handed-over bytes disagree: refused as an FFI
        // marshalling bug — distinct from a content verdict, so the daemon
        // never logs "bad entry" for a C++-side blob/length mismatch.
        assert_eq!(
            call_with_blob(2, &[2 * K], &[2 * L], &good[..L], &mut msg),
            SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_MARSHALLING
        );
        assert_eq!(
            text(&msg),
            "FFI marshalling: leaf blob length disagrees with declared lengths"
        );
        // A null blob with a nonzero declared length is the same caller bug.
        assert_eq!(
            unsafe {
                shekyl_tx_extra_pqc_field_shape(
                    2,
                    [2 * K].as_ptr(),
                    1,
                    [2 * L].as_ptr(),
                    1,
                    std::ptr::null(),
                    2 * L,
                    msg.as_mut_ptr(),
                    msg.len(),
                )
            },
            SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_MARSHALLING
        );
        // The shape rule still fires first on a wrong length.
        assert_eq!(
            call_with_blob(1, &[K], &[2 * L], &good, &mut msg),
            SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_LENGTH
        );
    }
}
