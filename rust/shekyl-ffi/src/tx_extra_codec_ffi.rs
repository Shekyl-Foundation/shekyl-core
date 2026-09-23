// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `tx_extra` codec's FFI: `shekyl-wire` parses and builds, the C++
//! daemon transports (`TX_EXTRA_RUST_CUTOVER.md` §3; rule 40).
//!
//! Before this module the daemon parsed `extra` with its own parser and
//! handed Rust *field lengths* to judge (`tx_extra_ffi::shekyl_tx_extra_pqc_field_shape`,
//! TXE-F3). Two parsers over one consensus grammar is the divergence class
//! CEN-I19 was routed through Rust to close; these entry points close it: the
//! C++ receives a fixed-size value or an opaque payload and never reads
//! inside an `extra` again.
//!
//! # Four calls, one writer
//!
//! - [`shekyl_tx_extra_field`] — the `index`th field of `tag`, as its
//!   payload bytes. **`ABSENT` and `MALFORMED` are distinct codes**: a
//!   parsed extra without the tag is the committed empty set (the `0x0B`
//!   reader's `headers_readable = true`, empty), an unparseable extra is
//!   not (`headers_readable = false`). The prose contract
//!   `parse_archival_attestation_from_extra` carried is the return type here.
//! - [`shekyl_tx_extra_tx_pubkey`] — the `0x01` key, written directly into
//!   the caller's 32 bytes (fixed size → raw pointer, rule 40).
//! - [`shekyl_tx_extra_leaf_entries`] — parse, apply the shape rule over
//!   that parse, return the `0x07` blob. One call where `blockchain_db.cpp`
//!   had three passes (shape check, re-parse, find).
//! - [`shekyl_coinbase_extra`] — the coinbase writer: `[PubKey, Nonce(8),
//!   KEM, Leaf]` built in the grammar's one layout, judged by the grammar,
//!   serialized. The nonce is **fixed at `COINBASE_NONCE_BYTES`** (`TXE-Q6′`,
//!   ruled 2026-09-23): a 32-bit header nonce exhausts a template at
//!   ≈ 36 MH/s, each nonce byte multiplies that by 256, and a fixed width
//!   carries no length signal. A template that could not pass admission is
//!   refused here, not at the miner.
//!
//! [`shekyl_tx_extra_shape_of`] is the shape rule over bytes —
//! `check_tx_extra_shape` in the daemon is a one-line adapter over it; the
//! lengths-taking I19 form goes with the C++ parser that fed it. The rule is
//! `shekyl_wire::tx_extra::check_tx_extra_shape`: CEN-I19 on every
//! transaction, the closed coinbase grammar on a coinbase, no `0x02` off it.
//!
//! # Codes
//!
//! Shape verdicts keep their `SHEKYL_TX_EXTRA_PQC_SHAPE_*` /
//! `SHEKYL_TX_EXTRA_SHAPE_*` values (`0` OK, `1..=17`), since
//! [`shekyl_tx_extra_leaf_entries`] and [`shekyl_coinbase_extra`] return
//! them unchanged when the rule refuses.
//! This module's own outcomes start at `100` so the two families cannot
//! collide: a caller branching on `rc < 100` is looking at a shape verdict.
//! A null pointer is the shape family's `ERR_NULL_PTR` everywhere.
//!
//! # No panics, no unwinding
//!
//! The workspace is `panic = "abort"` (see `difficulty_ffi`); every body
//! here is `Result`-shaped end to end — `parse` and `serialize` return
//! `io::Result`, the shape rule returns its error enum — and no body
//! indexes, unwraps or expects.

use std::os::raw::c_char;

use shekyl_wire::tx_extra::{
    check_tx_extra_shape, parse, serialize, TxExtraField, COINBASE_NONCE_BYTES,
};

use crate::legacy_types::ShekylBuffer;
use crate::tx_extra_ffi::{
    shape_code, write_msg, SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_NULL_PTR, SHEKYL_TX_EXTRA_PQC_SHAPE_OK,
};

/// The call succeeded and `out` holds the result.
pub const SHEKYL_TX_EXTRA_OK: i32 = SHEKYL_TX_EXTRA_PQC_SHAPE_OK;
/// The extra parsed and holds no `index`th field of `tag` — the committed
/// empty set for a reader whose absent tag means "nothing to verify".
pub const SHEKYL_TX_EXTRA_ABSENT: i32 = 100;
/// The extra does not parse. Never the same as [`SHEKYL_TX_EXTRA_ABSENT`]:
/// attestation-shaped bytes could ride an unparseable extra outside the
/// commitment, so an unreadable extra is a loud refusal, not an empty one.
pub const SHEKYL_TX_EXTRA_MALFORMED: i32 = 101;
/// The caller asked for a tag the grammar has no payload for (`0x00`
/// padding, a retired or reserved byte). A caller bug, reported distinctly
/// from every verdict about the bytes.
pub const SHEKYL_TX_EXTRA_UNKNOWN_TAG: i32 = 102;
/// The writer was handed an input the codec refuses to lay out: the KEM or
/// leaf blob exceeds the wire cap, or a `0x06`/`0x07` blob is not
/// `n_outputs` entries wide (the I19 code says which).
pub const SHEKYL_TX_EXTRA_UNSERIALIZABLE: i32 = 103;

/// The sentence for [`SHEKYL_TX_EXTRA_MALFORMED`] where a caller logs one.
/// Owned here: the wire crate's `io::Error` text is a parse diagnostic, not
/// the admission sentence.
const MALFORMED_MSG: &str = "tx_extra does not parse; the PQC field shape cannot be established";

/// Bytes of a tx public key.
const PUBKEY_LEN: usize = 32;

/// The payload bytes a field carries under [`shekyl_tx_extra_field`]'s
/// contract, or `None` for a field that has none to hand over as bytes
/// (padding is a length, not a payload).
fn payload(field: &TxExtraField) -> Option<Vec<u8>> {
    match field {
        TxExtraField::Padding(_) => None,
        TxExtraField::PubKey(key) => Some(key.to_vec()),
        TxExtraField::AdditionalPubKeys(keys) => Some(keys.concat()),
        TxExtraField::Nonce(b)
        | TxExtraField::PqcKemCiphertext(b)
        | TxExtraField::PqcLeafEntries(b)
        | TxExtraField::PqcViewTagHints(b)
        | TxExtraField::PqcSpendAuthPubkeys(b)
        | TxExtraField::ArchivalAttestation(b) => Some(b.clone()),
    }
}

/// The tag byte a parsed field carries.
fn tag_of(field: &TxExtraField) -> u8 {
    use shekyl_wire::tx_extra as t;
    match field {
        TxExtraField::Padding(_) => t::TX_EXTRA_TAG_PADDING,
        TxExtraField::PubKey(_) => t::TX_EXTRA_TAG_PUBKEY,
        TxExtraField::Nonce(_) => t::TX_EXTRA_TAG_NONCE,
        TxExtraField::AdditionalPubKeys(_) => t::TX_EXTRA_TAG_ADDITIONAL_PUBKEYS,
        TxExtraField::PqcKemCiphertext(_) => t::TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT,
        TxExtraField::PqcLeafEntries(_) => t::TX_EXTRA_TAG_PQC_LEAF_ENTRIES,
        TxExtraField::PqcViewTagHints(_) => t::TX_EXTRA_TAG_PQC_VIEW_TAG_HINTS,
        TxExtraField::PqcSpendAuthPubkeys(_) => t::TX_EXTRA_TAG_PQC_SPEND_AUTH_PUBKEYS,
        TxExtraField::ArchivalAttestation(_) => t::TX_EXTRA_TAG_ARCHIVAL_ATTESTATION,
    }
}

/// Whether `tag` names a field with a payload this surface hands over.
fn tag_has_payload(tag: u8) -> bool {
    use shekyl_wire::tx_extra as t;
    matches!(
        tag,
        t::TX_EXTRA_TAG_PUBKEY
            | t::TX_EXTRA_TAG_NONCE
            | t::TX_EXTRA_TAG_ADDITIONAL_PUBKEYS
            | t::TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT
            | t::TX_EXTRA_TAG_PQC_LEAF_ENTRIES
            | t::TX_EXTRA_TAG_PQC_VIEW_TAG_HINTS
            | t::TX_EXTRA_TAG_PQC_SPEND_AUTH_PUBKEYS
            | t::TX_EXTRA_TAG_ARCHIVAL_ATTESTATION
    )
}

/// Borrow `len` bytes; a null pointer is accepted only with length 0.
unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    // SAFETY: the caller's contract — `len` readable bytes behind a non-null
    // `ptr` — is the seam helper's precondition; the borrow ends with the call.
    unsafe { crate::legacy_util::slice_from_ptr(ptr, len) }
}

/// Hand `data` to the caller through `out`. `out` was checked non-null by
/// the caller of this helper.
unsafe fn give(out: *mut ShekylBuffer, data: Vec<u8>) {
    // SAFETY: `out` is a valid, writable `ShekylBuffer` per the FFI contract.
    unsafe { out.write(ShekylBuffer::from_vec(data)) };
}

/// The `index`th field of `tag` in `extra`, as its payload bytes.
///
/// Returns [`SHEKYL_TX_EXTRA_OK`] and writes `out` (free with
/// `shekyl_buffer_free`); [`SHEKYL_TX_EXTRA_ABSENT`] when the extra parses
/// but holds no such field; [`SHEKYL_TX_EXTRA_MALFORMED`] when it does not
/// parse; [`SHEKYL_TX_EXTRA_UNKNOWN_TAG`] for a tag with no payload. `out`
/// holds the payload on `OK` and the null buffer otherwise. An empty
/// payload (a present `0x0B` with zero bytes) is `OK` with a zero-length
/// buffer — present-empty and absent are different facts.
///
/// # Safety
/// `extra` is readable for `extra_len` bytes (null only with 0) and `out`
/// is a writable `ShekylBuffer`, for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn shekyl_tx_extra_field(
    extra: *const u8,
    extra_len: usize,
    tag: u8,
    index: usize,
    out: *mut ShekylBuffer,
) -> i32 {
    if out.is_null() {
        return SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_NULL_PTR;
    }
    // SAFETY: caller contract on `out`.
    unsafe { out.write(ShekylBuffer::null()) };
    if !tag_has_payload(tag) {
        return SHEKYL_TX_EXTRA_UNKNOWN_TAG;
    }
    // SAFETY: caller contract on `extra` / `extra_len`.
    let Some(extra) = (unsafe { bytes(extra, extra_len) }) else {
        return SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_NULL_PTR;
    };
    let Ok(fields) = parse(extra) else {
        return SHEKYL_TX_EXTRA_MALFORMED;
    };
    let Some(found) = fields.iter().filter(|f| tag_of(f) == tag).nth(index) else {
        return SHEKYL_TX_EXTRA_ABSENT;
    };
    let Some(data) = payload(found) else {
        // Unreachable — `tag_has_payload` admitted the tag — but the arm is
        // the honest code, never a silent empty buffer.
        return SHEKYL_TX_EXTRA_UNKNOWN_TAG;
    };
    // SAFETY: `out` checked above.
    unsafe { give(out, data) };
    SHEKYL_TX_EXTRA_OK
}

/// The transaction public key (`0x01`, first occurrence), written into
/// `out32`. Same codes as [`shekyl_tx_extra_field`] minus `UNKNOWN_TAG`;
/// `out32` is written only on `OK`.
///
/// # Safety
/// `extra` is readable for `extra_len` bytes (null only with 0); `out32` is
/// writable for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_tx_extra_tx_pubkey(
    extra: *const u8,
    extra_len: usize,
    out32: *mut u8,
) -> i32 {
    if out32.is_null() {
        return SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_NULL_PTR;
    }
    // SAFETY: caller contract on `extra` / `extra_len`.
    let Some(extra) = (unsafe { bytes(extra, extra_len) }) else {
        return SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_NULL_PTR;
    };
    let Ok(fields) = parse(extra) else {
        return SHEKYL_TX_EXTRA_MALFORMED;
    };
    let Some(key) = fields.iter().find_map(|f| match f {
        TxExtraField::PubKey(k) => Some(k),
        _ => None,
    }) else {
        return SHEKYL_TX_EXTRA_ABSENT;
    };
    // SAFETY: `out32` is writable for 32 bytes per the caller's contract;
    // `key` is Rust-owned, so the regions cannot overlap.
    unsafe { std::ptr::copy_nonoverlapping(key.as_ptr(), out32, PUBKEY_LEN) };
    SHEKYL_TX_EXTRA_OK
}

/// The shape rule over `extra`'s own parse (`is_coinbase` selects the
/// coinbase grammar), then the `0x07` blob.
///
/// Returns [`SHEKYL_TX_EXTRA_OK`] with the blob in `out` (a zero-length
/// buffer when `n_outputs == 0`, the rule's leafless case); a
/// `SHEKYL_TX_EXTRA_*SHAPE_*` code with the rule's own sentence in
/// `out_msg` when the shape or the leaf content is refused;
/// [`SHEKYL_TX_EXTRA_MALFORMED`] when the extra does not parse. Replaces
/// `blockchain_db.cpp`'s shape-check / re-parse / find with one read.
///
/// # Safety
/// `extra` is readable for `extra_len` bytes (null only with 0); `out` is a
/// writable `ShekylBuffer`; `out_msg` is writable for `out_msg_cap` bytes
/// (null with 0 for a caller that wants only the code).
#[no_mangle]
pub unsafe extern "C" fn shekyl_tx_extra_leaf_entries(
    extra: *const u8,
    extra_len: usize,
    n_outputs: usize,
    is_coinbase: bool,
    out: *mut ShekylBuffer,
    out_msg: *mut c_char,
    out_msg_cap: usize,
) -> i32 {
    // SAFETY: caller contract on `out_msg` / `out_msg_cap`.
    unsafe { write_msg(out_msg, out_msg_cap, "") };
    if out.is_null() {
        return SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_NULL_PTR;
    }
    // SAFETY: caller contract on `out`.
    unsafe { out.write(ShekylBuffer::null()) };
    // SAFETY: caller contract on `extra` / `extra_len`.
    let Some(extra) = (unsafe { bytes(extra, extra_len) }) else {
        return SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_NULL_PTR;
    };
    let Ok(fields) = parse(extra) else {
        return SHEKYL_TX_EXTRA_MALFORMED;
    };
    if let Err(err) = check_tx_extra_shape(&fields, n_outputs, is_coinbase) {
        // SAFETY: caller contract on `out_msg` / `out_msg_cap`.
        unsafe { write_msg(out_msg, out_msg_cap, &err.to_string()) };
        return shape_code(err);
    }
    // The rule admitted exactly one 0x07 field when n_outputs > 0 and none
    // otherwise; the leafless case hands over an empty buffer.
    let blob = fields
        .iter()
        .find_map(|f| match f {
            TxExtraField::PqcLeafEntries(b) => Some(b.clone()),
            _ => None,
        })
        .unwrap_or_default();
    // SAFETY: `out` checked above.
    unsafe { give(out, blob) };
    SHEKYL_TX_EXTRA_OK
}

/// The shape rule over `extra`'s own parse — the verdict and the rule's
/// sentence, nothing handed back. `is_coinbase` selects the closed coinbase
/// grammar; off the coinbase the rule is CEN-I19 plus "no `0x02`". The
/// bytes-taking successor of `tx_extra_ffi::shekyl_tx_extra_pqc_field_shape`,
/// for `check_tx_extra_shape`'s three C++ callers. An extra that does not
/// parse is [`SHEKYL_TX_EXTRA_MALFORMED`] — the rule's own precondition,
/// stated as a code rather than a C++ sentence.
///
/// # Safety
/// `extra` is readable for `extra_len` bytes (null only with 0); `out_msg`
/// is writable for `out_msg_cap` bytes (null with 0).
#[no_mangle]
pub unsafe extern "C" fn shekyl_tx_extra_shape_of(
    extra: *const u8,
    extra_len: usize,
    n_outputs: usize,
    is_coinbase: bool,
    out_msg: *mut c_char,
    out_msg_cap: usize,
) -> i32 {
    // SAFETY: caller contract on `out_msg` / `out_msg_cap`.
    unsafe { write_msg(out_msg, out_msg_cap, "") };
    // SAFETY: caller contract on `extra` / `extra_len`.
    let Some(extra) = (unsafe { bytes(extra, extra_len) }) else {
        return SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_NULL_PTR;
    };
    let Ok(fields) = parse(extra) else {
        // SAFETY: caller contract on `out_msg` / `out_msg_cap`.
        unsafe { write_msg(out_msg, out_msg_cap, MALFORMED_MSG) };
        return SHEKYL_TX_EXTRA_MALFORMED;
    };
    match check_tx_extra_shape(&fields, n_outputs, is_coinbase) {
        Ok(()) => SHEKYL_TX_EXTRA_OK,
        Err(err) => {
            // SAFETY: caller contract on `out_msg` / `out_msg_cap`.
            unsafe { write_msg(out_msg, out_msg_cap, &err.to_string()) };
            shape_code(err)
        }
    }
}

/// Build the coinbase's `extra` in the grammar's one layout:
/// `[PubKey(tx_pubkey), Nonce(nonce, 8 bytes), PqcKemCiphertext(kem),
/// PqcLeafEntries(leaf)]` — `[PubKey, Nonce]` when `n_outputs == 0` — judged
/// by `check_coinbase_extra_shape` before it is handed back.
///
/// `nonce` is exactly [`COINBASE_NONCE_BYTES`] bytes, the miner's template
/// search space beyond the 32-bit header nonce (`TXE-Q6′`); the daemon
/// zero-fills it when no miner asked. The KEM blob is `1120 · n_outputs`
/// bytes and the leaf blob `64 · n_outputs`, exactly as
/// `shekyl_construct_output` produced them; anything else is refused with
/// the shape code that names the field (a template that cannot pass
/// admission is refused at construction, not at the miner), and a blob past
/// the wire cap is [`SHEKYL_TX_EXTRA_UNSERIALIZABLE`]. `out` holds the extra
/// on `OK` and the null buffer otherwise.
///
/// # Safety
/// `tx_pubkey` is readable for 32 bytes and `nonce` for
/// `COINBASE_NONCE_BYTES`; `kem` / `leaf` are readable for their lengths
/// (null only with 0); `out` is a writable `ShekylBuffer`; `out_msg` is
/// writable for `out_msg_cap` bytes (null with 0).
#[no_mangle]
pub unsafe extern "C" fn shekyl_coinbase_extra(
    tx_pubkey: *const u8,
    nonce: *const u8,
    kem: *const u8,
    kem_len: usize,
    leaf: *const u8,
    leaf_len: usize,
    n_outputs: usize,
    out: *mut ShekylBuffer,
    out_msg: *mut c_char,
    out_msg_cap: usize,
) -> i32 {
    // SAFETY: caller contract on `out_msg` / `out_msg_cap`.
    unsafe { write_msg(out_msg, out_msg_cap, "") };
    if out.is_null() || tx_pubkey.is_null() || nonce.is_null() {
        return SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_NULL_PTR;
    }
    // SAFETY: caller contract on `out`.
    unsafe { out.write(ShekylBuffer::null()) };
    // SAFETY: caller contracts on the four inputs.
    let (key, nonce, kem, leaf) = unsafe {
        let (Some(key), Some(nonce)) = (
            bytes(tx_pubkey, PUBKEY_LEN),
            bytes(nonce, COINBASE_NONCE_BYTES),
        ) else {
            return SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_NULL_PTR;
        };
        let (Some(kem), Some(leaf)) = (bytes(kem, kem_len), bytes(leaf, leaf_len)) else {
            return SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_NULL_PTR;
        };
        (key, nonce, kem, leaf)
    };
    let mut pubkey = [0u8; PUBKEY_LEN];
    pubkey.copy_from_slice(key);
    let mut fields = vec![
        TxExtraField::PubKey(pubkey),
        TxExtraField::Nonce(nonce.to_vec()),
    ];
    if n_outputs > 0 || !kem.is_empty() || !leaf.is_empty() {
        // Present fields are judged by the rule below; a leafless coinbase
        // that was handed bytes anyway is refused there, not dropped here.
        fields.push(TxExtraField::PqcKemCiphertext(kem.to_vec()));
        fields.push(TxExtraField::PqcLeafEntries(leaf.to_vec()));
    }
    if let Err(err) = check_tx_extra_shape(&fields, n_outputs, true) {
        // SAFETY: caller contract on `out_msg` / `out_msg_cap`.
        unsafe { write_msg(out_msg, out_msg_cap, &err.to_string()) };
        return shape_code(err);
    }
    let Ok(blob) = serialize(&fields) else {
        return SHEKYL_TX_EXTRA_UNSERIALIZABLE;
    };
    // SAFETY: `out` checked above.
    unsafe { give(out, blob) };
    SHEKYL_TX_EXTRA_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy_util::shekyl_buffer_free;
    use shekyl_wire::tx_extra::{
        conforming_pqc_leaf_blob, TX_EXTRA_TAG_ARCHIVAL_ATTESTATION, TX_EXTRA_TAG_NONCE,
        TX_EXTRA_TAG_PADDING, TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT, TX_EXTRA_TAG_PQC_LEAF_ENTRIES,
        TX_EXTRA_TAG_PUBKEY,
    };

    fn take(buf: &ShekylBuffer) -> Vec<u8> {
        if buf.ptr.is_null() {
            return Vec::new();
        }
        // SAFETY: the pair came from `ShekylBuffer::from_vec` in this process.
        let v = unsafe { crate::legacy_util::slice_from_ptr(buf.ptr, buf.len) }
            .expect("a non-null buffer")
            .to_vec();
        unsafe { shekyl_buffer_free(buf.ptr, buf.len) };
        v
    }

    fn field(extra: &[u8], tag: u8, index: usize) -> (i32, Vec<u8>) {
        let mut out = ShekylBuffer::null();
        let rc =
            unsafe { shekyl_tx_extra_field(extra.as_ptr(), extra.len(), tag, index, &raw mut out) };
        (rc, take(&out))
    }

    const NONCE: [u8; COINBASE_NONCE_BYTES] = [0xC0, 0x1D, 0xBE, 0xEF, 0, 0, 0, 1];

    fn coinbase(key: [u8; 32], n: usize, kem: &[u8], leaf: &[u8]) -> (i32, Vec<u8>, String) {
        let mut out = ShekylBuffer::null();
        let mut msg = [0 as c_char; 256];
        let rc = unsafe {
            shekyl_coinbase_extra(
                key.as_ptr(),
                NONCE.as_ptr(),
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
                n,
                &raw mut out,
                msg.as_mut_ptr(),
                msg.len(),
            )
        };
        let text = unsafe { std::ffi::CStr::from_ptr(msg.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        (rc, take(&out), text)
    }

    fn valid_extra(n: usize) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let kem = vec![0x44u8; shekyl_wire::tx_extra::HYBRID_KEM_CT_BYTES * n];
        let leaf = conforming_pqc_leaf_blob(n);
        let (rc, extra, _) = coinbase([0x11; 32], n, &kem, &leaf);
        assert_eq!(rc, SHEKYL_TX_EXTRA_OK);
        (extra, kem, leaf)
    }

    #[test]
    fn the_coinbase_writer_lays_out_pubkey_nonce_kem_leaf_and_the_reads_find_each() {
        let (extra, kem, leaf) = valid_extra(2);
        // The grammar's one layout: 0x01, 0x02(8), 0x06, 0x07 — byte-identical
        // to serializing the same four fields by hand, and admitted by the
        // rule a validator applies to a coinbase.
        let by_hand = serialize(&[
            TxExtraField::PubKey([0x11; 32]),
            TxExtraField::Nonce(NONCE.to_vec()),
            TxExtraField::PqcKemCiphertext(kem.clone()),
            TxExtraField::PqcLeafEntries(leaf.clone()),
        ])
        .expect("serializes");
        assert_eq!(extra, by_hand);
        assert_eq!(
            shekyl_wire::tx_extra::check_coinbase_extra_shape(&parse(&extra).unwrap(), 2),
            Ok(())
        );
        assert_eq!(
            field(&extra, TX_EXTRA_TAG_PUBKEY, 0),
            (SHEKYL_TX_EXTRA_OK, vec![0x11; 32])
        );
        assert_eq!(
            field(&extra, TX_EXTRA_TAG_NONCE, 0),
            (SHEKYL_TX_EXTRA_OK, NONCE.to_vec())
        );
        assert_eq!(
            field(&extra, TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT, 0),
            (SHEKYL_TX_EXTRA_OK, kem)
        );
        assert_eq!(
            field(&extra, TX_EXTRA_TAG_PQC_LEAF_ENTRIES, 0),
            (SHEKYL_TX_EXTRA_OK, leaf.clone())
        );
        let mut key = [0u8; 32];
        assert_eq!(
            unsafe { shekyl_tx_extra_tx_pubkey(extra.as_ptr(), extra.len(), key.as_mut_ptr()) },
            SHEKYL_TX_EXTRA_OK
        );
        assert_eq!(key, [0x11; 32]);
        let mut out = ShekylBuffer::null();
        let rc = unsafe {
            shekyl_tx_extra_leaf_entries(
                extra.as_ptr(),
                extra.len(),
                2,
                true,
                &raw mut out,
                std::ptr::null_mut(),
                0,
            )
        };
        assert_eq!((rc, take(&out)), (SHEKYL_TX_EXTRA_OK, leaf));
    }

    #[test]
    fn absent_and_malformed_are_different_codes_and_present_empty_is_neither() {
        let (extra, _, _) = valid_extra(1);
        assert_eq!(
            field(&extra, TX_EXTRA_TAG_ARCHIVAL_ATTESTATION, 0).0,
            SHEKYL_TX_EXTRA_ABSENT
        );
        assert_eq!(
            field(&extra, TX_EXTRA_TAG_PUBKEY, 1).0,
            SHEKYL_TX_EXTRA_ABSENT
        );
        // Present-empty 0x0B: two bytes, OK with a zero-length buffer.
        let mut with_empty = extra.clone();
        with_empty.extend_from_slice(&[TX_EXTRA_TAG_ARCHIVAL_ATTESTATION, 0x00]);
        assert_eq!(
            field(&with_empty, TX_EXTRA_TAG_ARCHIVAL_ATTESTATION, 0),
            (SHEKYL_TX_EXTRA_OK, Vec::new())
        );
        // An unknown tag byte makes the whole extra unparseable.
        let malformed = [0xFEu8, 0x01, 0x02];
        assert_eq!(
            field(&malformed, TX_EXTRA_TAG_PUBKEY, 0).0,
            SHEKYL_TX_EXTRA_MALFORMED
        );
        let mut key = [0u8; 32];
        assert_eq!(
            unsafe {
                shekyl_tx_extra_tx_pubkey(malformed.as_ptr(), malformed.len(), key.as_mut_ptr())
            },
            SHEKYL_TX_EXTRA_MALFORMED
        );
        let mut msg = [0 as c_char; 256];
        assert_eq!(
            unsafe {
                shekyl_tx_extra_shape_of(
                    malformed.as_ptr(),
                    malformed.len(),
                    1,
                    false,
                    msg.as_mut_ptr(),
                    msg.len(),
                )
            },
            SHEKYL_TX_EXTRA_MALFORMED
        );
        let text = unsafe { std::ffi::CStr::from_ptr(msg.as_ptr()) }.to_string_lossy();
        assert_eq!(text, MALFORMED_MSG);
    }

    #[test]
    fn a_tag_with_no_payload_is_a_caller_bug_not_a_verdict() {
        let (extra, _, _) = valid_extra(1);
        assert_eq!(
            field(&extra, TX_EXTRA_TAG_PADDING, 0).0,
            SHEKYL_TX_EXTRA_UNKNOWN_TAG
        );
        assert_eq!(
            field(&extra, 0x05, 0).0,
            SHEKYL_TX_EXTRA_UNKNOWN_TAG,
            "retired byte"
        );
        assert_eq!(
            field(&extra, 0x08, 0).0,
            SHEKYL_TX_EXTRA_UNKNOWN_TAG,
            "reserved byte"
        );
    }

    #[test]
    fn null_out_pointers_are_refused_before_anything_is_read() {
        let (extra, _, _) = valid_extra(1);
        assert_eq!(
            unsafe {
                shekyl_tx_extra_field(
                    extra.as_ptr(),
                    extra.len(),
                    TX_EXTRA_TAG_PUBKEY,
                    0,
                    std::ptr::null_mut(),
                )
            },
            SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_NULL_PTR
        );
        assert_eq!(
            unsafe { shekyl_tx_extra_tx_pubkey(extra.as_ptr(), extra.len(), std::ptr::null_mut()) },
            SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_NULL_PTR
        );
        // A null extra with a nonzero length is a null-pointer fault, not MALFORMED.
        let mut out = ShekylBuffer::null();
        assert_eq!(
            unsafe {
                shekyl_tx_extra_field(std::ptr::null(), 4, TX_EXTRA_TAG_PUBKEY, 0, &raw mut out)
            },
            SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_NULL_PTR
        );
        // An empty extra (null, 0) parses to nothing: ABSENT.
        assert_eq!(
            unsafe {
                shekyl_tx_extra_field(std::ptr::null(), 0, TX_EXTRA_TAG_PUBKEY, 0, &raw mut out)
            },
            SHEKYL_TX_EXTRA_ABSENT
        );
    }

    #[test]
    fn the_writer_refuses_what_admission_would_refuse_with_the_rules_own_sentence() {
        let leaf = conforming_pqc_leaf_blob(2);
        let kem_short = vec![0x44u8; shekyl_wire::tx_extra::HYBRID_KEM_CT_BYTES];
        let (rc, blob, msg) = coinbase([0x11; 32], 2, &kem_short, &leaf);
        assert_eq!(
            rc,
            crate::tx_extra_ffi::SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_LENGTH
        );
        assert!(blob.is_empty(), "nothing handed back on a refusal");
        assert!(msg.contains("1120"), "the rule's sentence: {msg}");
        // A leaf entry that is not a point.
        let mut bad_leaf = conforming_pqc_leaf_blob(1);
        bad_leaf[..32].copy_from_slice(&[0xFF; 32]);
        let kem = vec![0x44u8; shekyl_wire::tx_extra::HYBRID_KEM_CT_BYTES];
        let (rc, _, _) = coinbase([0x11; 32], 1, &kem, &bad_leaf);
        assert_eq!(
            rc,
            crate::tx_extra_ffi::SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_POINT
        );
        // Leafless coinbase: pubkey and nonce only, and bytes handed in
        // anyway are refused.
        let (rc, blob, _) = coinbase([0x22; 32], 0, &[], &[]);
        assert_eq!(rc, SHEKYL_TX_EXTRA_OK);
        assert_eq!(
            parse(&blob).expect("parses"),
            vec![
                TxExtraField::PubKey([0x22; 32]),
                TxExtraField::Nonce(NONCE.to_vec())
            ]
        );
        let (rc, _, _) = coinbase([0x22; 32], 0, &kem, &conforming_pqc_leaf_blob(1));
        assert_eq!(
            rc,
            crate::tx_extra_ffi::SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_PRESENT_WITHOUT_OUTPUTS
        );
    }

    #[test]
    fn the_leaf_read_is_the_shape_rule_then_the_blob_and_a_bad_extra_names_the_field() {
        let (extra, _, _) = valid_extra(1);
        let mut out = ShekylBuffer::null();
        let mut msg = [0 as c_char; 256];
        // Wrong output count for this extra: the rule refuses, nothing handed back.
        let rc = unsafe {
            shekyl_tx_extra_leaf_entries(
                extra.as_ptr(),
                extra.len(),
                3,
                true,
                &raw mut out,
                msg.as_mut_ptr(),
                msg.len(),
            )
        };
        assert_eq!(
            rc,
            crate::tx_extra_ffi::SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_LENGTH
        );
        assert!(out.ptr.is_null());
        // Leafless, non-coinbase (a serve-credit shape): OK, empty.
        let pubkey_only = serialize(&[TxExtraField::PubKey([0x11; 32])]).expect("serializes");
        let rc = unsafe {
            shekyl_tx_extra_leaf_entries(
                pubkey_only.as_ptr(),
                pubkey_only.len(),
                0,
                false,
                &raw mut out,
                msg.as_mut_ptr(),
                msg.len(),
            )
        };
        assert_eq!((rc, take(&out)), (SHEKYL_TX_EXTRA_OK, Vec::new()));
    }

    #[test]
    fn the_coinbase_grammar_is_judged_on_both_reads_and_off_the_coinbase_the_nonce_is_refused() {
        use crate::tx_extra_ffi::{
            SHEKYL_TX_EXTRA_SHAPE_COINBASE_FOREIGN_TAG, SHEKYL_TX_EXTRA_SHAPE_COINBASE_LAYOUT,
            SHEKYL_TX_EXTRA_SHAPE_COINBASE_NONCE_LENGTH,
            SHEKYL_TX_EXTRA_SHAPE_COINBASE_NONCE_MISSING,
            SHEKYL_TX_EXTRA_SHAPE_NONCE_OUTSIDE_COINBASE,
        };
        let shape = |extra: &[u8], n: usize, coinbase: bool| -> (i32, String) {
            let mut msg = [0 as c_char; 256];
            let rc = unsafe {
                shekyl_tx_extra_shape_of(
                    extra.as_ptr(),
                    extra.len(),
                    n,
                    coinbase,
                    msg.as_mut_ptr(),
                    msg.len(),
                )
            };
            let text = unsafe { std::ffi::CStr::from_ptr(msg.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            (rc, text)
        };
        let (extra, kem, leaf) = valid_extra(1);
        assert_eq!(shape(&extra, 1, true).0, SHEKYL_TX_EXTRA_OK);
        // The same bytes are not a valid non-coinbase extra: the nonce.
        let (rc, msg) = shape(&extra, 1, false);
        assert_eq!(rc, SHEKYL_TX_EXTRA_SHAPE_NONCE_OUTSIDE_COINBASE);
        assert!(msg.contains("coinbase-only"), "{msg}");
        // No nonce: a valid non-coinbase extra, an invalid coinbase one.
        let no_nonce = serialize(&[
            TxExtraField::PubKey([0x11; 32]),
            TxExtraField::PqcKemCiphertext(kem.clone()),
            TxExtraField::PqcLeafEntries(leaf.clone()),
        ])
        .unwrap();
        assert_eq!(shape(&no_nonce, 1, false).0, SHEKYL_TX_EXTRA_OK);
        assert_eq!(
            shape(&no_nonce, 1, true).0,
            SHEKYL_TX_EXTRA_SHAPE_COINBASE_NONCE_MISSING
        );
        // Seven bytes: the width is fixed.
        let short = serialize(&[
            TxExtraField::PubKey([0x11; 32]),
            TxExtraField::Nonce(vec![0; 7]),
            TxExtraField::PqcKemCiphertext(kem.clone()),
            TxExtraField::PqcLeafEntries(leaf.clone()),
        ])
        .unwrap();
        let (rc, msg) = shape(&short, 1, true);
        assert_eq!(rc, SHEKYL_TX_EXTRA_SHAPE_COINBASE_NONCE_LENGTH);
        assert!(msg.contains("exactly 8"), "{msg}");
        // Padding — or any tag off the whitelist — in a coinbase.
        let mut padded = extra.clone();
        padded.push(0x00);
        assert_eq!(
            shape(&padded, 1, true).0,
            SHEKYL_TX_EXTRA_SHAPE_COINBASE_FOREIGN_TAG
        );
        // Out of order.
        let swapped = serialize(&[
            TxExtraField::Nonce(NONCE.to_vec()),
            TxExtraField::PubKey([0x11; 32]),
            TxExtraField::PqcKemCiphertext(kem),
            TxExtraField::PqcLeafEntries(leaf),
        ])
        .unwrap();
        assert_eq!(
            shape(&swapped, 1, true).0,
            SHEKYL_TX_EXTRA_SHAPE_COINBASE_LAYOUT
        );
        // The leaf read applies the same grammar.
        let mut out = ShekylBuffer::null();
        let rc = unsafe {
            shekyl_tx_extra_leaf_entries(
                short.as_ptr(),
                short.len(),
                1,
                true,
                &raw mut out,
                std::ptr::null_mut(),
                0,
            )
        };
        assert_eq!(rc, SHEKYL_TX_EXTRA_SHAPE_COINBASE_NONCE_LENGTH);
        assert!(out.ptr.is_null());
        // The writer refuses a short nonce before anything is built: the
        // pointer contract is 8 bytes, so the only way to hand it fewer is
        // through the rule — exercised via `shape` above; here the null
        // nonce is a pointer fault.
        let mut msg = [0 as c_char; 256];
        let rc = unsafe {
            shekyl_coinbase_extra(
                [0x11u8; 32].as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                0,
                &raw mut out,
                msg.as_mut_ptr(),
                msg.len(),
            )
        };
        assert_eq!(rc, SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_NULL_PTR);
    }
}
