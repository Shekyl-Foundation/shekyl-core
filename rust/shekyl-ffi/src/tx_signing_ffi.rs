// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The PQC signing preimage's FFI: `shekyl-wire` derives, the C++ daemon
//! verifies against it (`CHAIN_RULES_SLICE_6.md` §5 commit 7, Q7 (c);
//! rule 40).
//!
//! Until this module the daemon assembled the per-input signing payload
//! itself (`tx_pqc_verify.cpp`, `get_transaction_signed_payload`) — rule
//! content in a shim (slice 6 §3.1): what a signature *binds* decided in C++
//! while the wallet signed over the wire crate's derivation, the two
//! reconciled by nothing but signatures currently verifying. One derivation
//! now, [`shekyl_wire::PqcSigningPreimage`]; the daemon hands the
//! transaction's bytes over and receives the 32-byte hash each input's hybrid
//! signature is verified against. The KAT that holds the derivation to the
//! specification's output over eight daemon-accepted shapes is
//! `shekyl-wire/tests/pqc_signing_preimage_kat.rs`.
//!
//! Coarse (rule 40): the whole transaction in, every input's hash out, in one
//! call — not a per-input call over C++-assembled components, which would
//! leave the composition in C++.

use core::ffi::c_char;

use shekyl_wire::Transaction;

use crate::legacy_util::slice_from_ptr;
use crate::tx_extra_ffi::write_msg;

/// Every input's hash written; `out_count` holds how many (`0` for a body
/// with no `pqc_auths` to sign over: a coinbase, a storage-pruned spend, and
/// the serve-credit form — which consensus forbids them (CEN-H20) because
/// its hybrid countersignature is over the pass record instead, CEN-J10).
pub const SHEKYL_TX_SIGNING_OK: i32 = 0;
/// A required pointer was null (a non-null `tx` of `tx_len` bytes, `out` of
/// `32 · out_cap` bytes, `out_count`).
pub const SHEKYL_TX_SIGNING_ERR_NULL_PTR: i32 = 1;
/// The bytes are not a transaction — they do not parse, or do not parse
/// exactly. The preimage is defined over a parsed transaction and nothing
/// is derived from bytes that are not one.
pub const SHEKYL_TX_SIGNING_MALFORMED: i32 = 2;
/// The transaction carries more per-input authentications than `out_cap`
/// hashes fit; nothing was written. The caller sized `out` from a count it
/// believed, and the bytes disagree.
pub const SHEKYL_TX_SIGNING_CAPACITY: i32 = 3;

/// Every input's `signed_hash(i)` of the transaction `tx` occupies
/// (`FCMP_SPEND_SIGNING_PREIMAGE.md` §1.1), in input order, 32 bytes each,
/// written into `out`; `*out_count` is how many. `out_cap` is the number of
/// hashes `out` has room for — the caller's input count, since a body the
/// daemon admits carries one authentication per input.
///
/// # Safety
/// `tx` is readable for `tx_len` bytes; `out` is writable for `32 · out_cap`
/// bytes; `out_count` is writable; `out_msg` is writable for `out_msg_cap`
/// bytes (null with 0).
#[no_mangle]
pub unsafe extern "C" fn shekyl_tx_pqc_signing_payload_hashes(
    tx: *const u8,
    tx_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_count: *mut usize,
    out_msg: *mut c_char,
    out_msg_cap: usize,
) -> i32 {
    // SAFETY: caller contract on `out_msg` / `out_msg_cap`.
    unsafe { write_msg(out_msg, out_msg_cap, "") };
    if out_count.is_null() || (out.is_null() && out_cap > 0) {
        return SHEKYL_TX_SIGNING_ERR_NULL_PTR;
    }
    // SAFETY: caller contract on `tx` / `tx_len`.
    let Some(bytes) = (unsafe { slice_from_ptr(tx, tx_len) }) else {
        return SHEKYL_TX_SIGNING_ERR_NULL_PTR;
    };
    let tx = match Transaction::from_bytes(bytes) {
        Ok(tx) => tx,
        Err(err) => {
            // SAFETY: caller contract on `out_msg` / `out_msg_cap`.
            unsafe { write_msg(out_msg, out_msg_cap, &err.to_string()) };
            return SHEKYL_TX_SIGNING_MALFORMED;
        }
    };
    let hashes = tx.pqc_signing_payload_hashes();
    if hashes.len() > out_cap {
        // SAFETY: caller contract on `out_msg` / `out_msg_cap`.
        unsafe {
            write_msg(
                out_msg,
                out_msg_cap,
                &format!(
                    "{} per-input authentications, room for {out_cap}",
                    hashes.len()
                ),
            );
        }
        return SHEKYL_TX_SIGNING_CAPACITY;
    }
    for (i, hash) in hashes.iter().enumerate() {
        // SAFETY: `out` is writable for `32 · out_cap` bytes and `i < out_cap`.
        unsafe { core::ptr::copy_nonoverlapping(hash.as_bytes().as_ptr(), out.add(32 * i), 32) };
    }
    // SAFETY: `out_count` checked non-null above.
    unsafe { *out_count = hashes.len() };
    SHEKYL_TX_SIGNING_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn fixture() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../shekyl-wire/tests/fixtures/pqc_signing_preimage_v1.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).expect("fixture")).expect("json")
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// The seam hands back exactly the KAT's hashes for every pinned shape,
    /// including zero for the serve-credit form.
    #[test]
    fn hands_back_the_kats_hashes_for_every_shape() {
        for entry in fixture()["transactions"].as_array().expect("array") {
            let name = entry["name"].as_str().expect("name");
            let tx = hex_bytes(entry["tx_hex"].as_str().expect("tx_hex"));
            let expected: Vec<Vec<u8>> = entry["signed_hashes_hex"]
                .as_array()
                .expect("hashes")
                .iter()
                .map(|h| hex_bytes(h.as_str().expect("hex")))
                .collect();
            let cap = 8;
            let mut out = vec![0u8; 32 * cap];
            let mut count = usize::MAX;
            let mut msg = [0 as c_char; 128];
            let rc = unsafe {
                shekyl_tx_pqc_signing_payload_hashes(
                    tx.as_ptr(),
                    tx.len(),
                    out.as_mut_ptr(),
                    cap,
                    &raw mut count,
                    msg.as_mut_ptr(),
                    msg.len(),
                )
            };
            assert_eq!(rc, SHEKYL_TX_SIGNING_OK, "{name}");
            assert_eq!(count, expected.len(), "{name}: count");
            for (i, want) in expected.iter().enumerate() {
                assert_eq!(
                    &out[32 * i..32 * (i + 1)],
                    want.as_slice(),
                    "{name} input {i}"
                );
            }
        }
    }

    /// Bytes that are not a transaction derive nothing; a caller whose
    /// buffer is too small for the body's authentications gets a refusal,
    /// not a truncated answer.
    #[test]
    fn refuses_malformed_bytes_and_a_short_buffer() {
        let mut out = [0u8; 32];
        let mut count = 0usize;
        let mut msg = [0 as c_char; 128];
        let rc = unsafe {
            shekyl_tx_pqc_signing_payload_hashes(
                [0xffu8; 4].as_ptr(),
                4,
                out.as_mut_ptr(),
                1,
                &raw mut count,
                msg.as_mut_ptr(),
                msg.len(),
            )
        };
        assert_eq!(rc, SHEKYL_TX_SIGNING_MALFORMED);

        let six_inputs = fixture()["transactions"]
            .as_array()
            .expect("array")
            .iter()
            .find(|e| e["name"] == "spend-6in-2out")
            .map(|e| hex_bytes(e["tx_hex"].as_str().expect("tx_hex")))
            .expect("the six-input shape is pinned");
        let rc = unsafe {
            shekyl_tx_pqc_signing_payload_hashes(
                six_inputs.as_ptr(),
                six_inputs.len(),
                out.as_mut_ptr(),
                1,
                &raw mut count,
                msg.as_mut_ptr(),
                msg.len(),
            )
        };
        assert_eq!(rc, SHEKYL_TX_SIGNING_CAPACITY);
        assert_eq!(out, [0u8; 32], "nothing written on a capacity refusal");

        let rc = unsafe {
            shekyl_tx_pqc_signing_payload_hashes(
                six_inputs.as_ptr(),
                six_inputs.len(),
                out.as_mut_ptr(),
                1,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0,
            )
        };
        assert_eq!(rc, SHEKYL_TX_SIGNING_ERR_NULL_PTR);
    }
}
