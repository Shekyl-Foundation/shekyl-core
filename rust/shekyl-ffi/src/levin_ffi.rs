// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FFI surface for Levin p2p payload compression, backed by `shekyl-levin`.
//!
//! # Why this boundary exists (single-owner libzstd)
//!
//! Before this seam the daemon carried **two independent zstd stories**: the
//! C++ `epee::levin` compression path linked whatever libzstd the build host
//! had (pkg-config / `find_library`, version drift included, with a
//! silently-degraded `HAVE_ZSTD`-off fallback), while `shekyl-levin` pinned
//! the vendored `zstd-sys` copy. Routing the C++ path through these exports
//! makes the Rust-pinned libzstd the **only** implementation in the binary:
//! no system dependency, no version drift across builds, no future
//! `ZSTD_*` symbol collision when `shekyl-levin` joins a linked staticlib
//! (the `links = "zstd"` key is claimed once, by `zstd-sys`).
//!
//! The seam is **payload-level**, matching the pre-existing
//! `epee::levin::compress_payload` / `decompress_payload` API: framing (the
//! bucket-header rewrite that sets the `COMPRESSED` flag) stays on whichever
//! side framed the message; only opaque payload bytes cross. Payloads are
//! public wire data — `ShekylBuffer` returns are the correct shape (rule 40's
//! secret-material restriction does not apply).
//!
//! Error codes follow rule 40 (distinct codes, not booleans):
//! `0` success; `1` compression declined (send uncompressed — the C++
//! `compress_payload == false` path); `-3` invalid/oversized frame;
//! `-4` null pointer; `-6` compression not compiled in.

use crate::{slice_from_ptr, ShekylBuffer};

/// Success: `out` holds the (de)compressed payload.
pub const SHEKYL_LEVIN_OK: i32 = 0;
/// Compression declined (payload too small, incompressible, or codec
/// unavailable): send the payload uncompressed. Not an error.
pub const SHEKYL_LEVIN_DECLINED: i32 = 1;
/// Malformed input: bad frame, missing declared content size, or a declared
/// size above the caller's limit / `DECOMPRESSED_MAX_SIZE`.
pub const SHEKYL_LEVIN_ERR_FORMAT: i32 = -3;
/// A required pointer was null.
pub const SHEKYL_LEVIN_ERR_NULL: i32 = -4;
/// The Rust image was built without the `zstd` feature (production always
/// has it on; this code is for pure-Rust feature-off builds only).
pub const SHEKYL_LEVIN_ERR_UNAVAILABLE: i32 = -6;

/// Whether the linked Rust image can compress/decompress Levin payloads.
#[no_mangle]
pub extern "C" fn shekyl_levin_compression_available() -> bool {
    shekyl_levin::is_compression_available()
}

/// Compress one Levin payload (zstd level 1, 256-byte minimum,
/// only-if-smaller — the `epee::levin::compress_payload` contract).
///
/// Returns [`SHEKYL_LEVIN_OK`] with `out` set, or [`SHEKYL_LEVIN_DECLINED`]
/// meaning "send it uncompressed" (`out` is nulled). Free `out` with
/// `shekyl_buffer_free`.
///
/// # Safety
///
/// `input` must point to `input_len` readable bytes (`input_len` is bounded
/// at [`shekyl_levin::DEFAULT_MAX_PACKET_SIZE`]; larger returns
/// [`SHEKYL_LEVIN_ERR_FORMAT`]); `out` must be a valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn shekyl_levin_compress_payload(
    input: *const u8,
    input_len: usize,
    out: *mut ShekylBuffer,
) -> i32 {
    if out.is_null() {
        return SHEKYL_LEVIN_ERR_NULL;
    }
    // SAFETY: caller guarantees `out` is writable (checked non-null above).
    unsafe { *out = ShekylBuffer::null() };
    let Some(payload) = (unsafe { slice_from_ptr(input, input_len) }) else {
        return SHEKYL_LEVIN_ERR_NULL;
    };
    // Bounded deserialization (rule 40): nothing framed under the Levin
    // packet limit can legitimately be larger than this.
    if u64::try_from(input_len).is_ok_and(|len| len > shekyl_levin::DEFAULT_MAX_PACKET_SIZE) {
        return SHEKYL_LEVIN_ERR_FORMAT;
    }
    match shekyl_levin::compress_payload(payload) {
        Some(compressed) => {
            // SAFETY: `out` checked non-null above.
            unsafe { *out = ShekylBuffer::from_vec(compressed) };
            SHEKYL_LEVIN_OK
        }
        None => SHEKYL_LEVIN_DECLINED,
    }
}

/// Decompress one Levin `COMPRESSED` payload. The frame must declare its
/// content size; the declared size is checked against
/// `min(max_output, DECOMPRESSED_MAX_SIZE)` **before any allocation**.
/// Callers pass the packet-size limit the bucket header was checked
/// against, so an inflated payload can never exceed it.
///
/// Returns [`SHEKYL_LEVIN_OK`] with `out` set (free with
/// `shekyl_buffer_free`), [`SHEKYL_LEVIN_ERR_FORMAT`] on a malformed,
/// size-less, or oversized frame, or [`SHEKYL_LEVIN_ERR_UNAVAILABLE`]
/// without zstd support.
///
/// # Safety
///
/// `input` must point to `input_len` readable bytes (`input_len` is bounded
/// at [`shekyl_levin::DEFAULT_MAX_PACKET_SIZE`]); `out` must be a valid
/// writable pointer.
#[no_mangle]
pub unsafe extern "C" fn shekyl_levin_decompress_payload(
    input: *const u8,
    input_len: usize,
    max_output: u64,
    out: *mut ShekylBuffer,
) -> i32 {
    if out.is_null() {
        return SHEKYL_LEVIN_ERR_NULL;
    }
    // SAFETY: caller guarantees `out` is writable (checked non-null above).
    unsafe { *out = ShekylBuffer::null() };
    let Some(payload) = (unsafe { slice_from_ptr(input, input_len) }) else {
        return SHEKYL_LEVIN_ERR_NULL;
    };
    if u64::try_from(input_len).is_ok_and(|len| len > shekyl_levin::DEFAULT_MAX_PACKET_SIZE) {
        return SHEKYL_LEVIN_ERR_FORMAT;
    }
    match shekyl_levin::decompress_payload(payload, max_output) {
        Ok(decompressed) => {
            // SAFETY: `out` checked non-null above.
            unsafe { *out = ShekylBuffer::from_vec(decompressed) };
            SHEKYL_LEVIN_OK
        }
        Err(shekyl_levin::Error::CompressionUnavailable) => SHEKYL_LEVIN_ERR_UNAVAILABLE,
        Err(_) => SHEKYL_LEVIN_ERR_FORMAT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round trip across the exact boundary the C++ shim uses; bites against
    /// a marshaling defect (length, ownership, code mapping) — it does NOT
    /// re-prove the codec, which `shekyl-levin`'s own tests own.
    #[test]
    fn ffi_roundtrip_and_code_mapping() {
        let payload = vec![7u8; 4096];
        let mut compressed = ShekylBuffer::null();
        // SAFETY: valid slice + out pointer.
        let rc = unsafe {
            shekyl_levin_compress_payload(payload.as_ptr(), payload.len(), &raw mut compressed)
        };
        assert_eq!(rc, SHEKYL_LEVIN_OK);
        assert!(!compressed.ptr.is_null() && compressed.len < payload.len());

        let mut inflated = ShekylBuffer::null();
        // SAFETY: buffer from the call above; valid out pointer.
        let rc = unsafe {
            shekyl_levin_decompress_payload(
                compressed.ptr,
                compressed.len,
                shekyl_levin::DEFAULT_MAX_PACKET_SIZE,
                &raw mut inflated,
            )
        };
        assert_eq!(rc, SHEKYL_LEVIN_OK);
        // SAFETY: buffer returned by the decompress call.
        let bytes = unsafe { std::slice::from_raw_parts(inflated.ptr, inflated.len) };
        assert_eq!(bytes, &payload[..]);

        // SAFETY: freeing exactly the buffers the exports returned.
        unsafe {
            crate::shekyl_buffer_free(compressed.ptr, compressed.len);
            crate::shekyl_buffer_free(inflated.ptr, inflated.len);
        }
    }

    #[test]
    fn small_payload_declines_and_garbage_frame_rejects() {
        let mut out = ShekylBuffer::null();
        let tiny = [0u8; 8];
        // SAFETY: valid slice + out pointer.
        let rc = unsafe { shekyl_levin_compress_payload(tiny.as_ptr(), tiny.len(), &raw mut out) };
        assert_eq!(rc, SHEKYL_LEVIN_DECLINED);
        assert!(out.ptr.is_null());

        let garbage = b"not a zstd frame";
        // SAFETY: valid slice + out pointer.
        let rc = unsafe {
            shekyl_levin_decompress_payload(
                garbage.as_ptr(),
                garbage.len(),
                shekyl_levin::DEFAULT_MAX_PACKET_SIZE,
                &raw mut out,
            )
        };
        assert_eq!(rc, SHEKYL_LEVIN_ERR_FORMAT);
        assert!(out.ptr.is_null());

        // SAFETY: null out pointer is the case under test.
        let rc = unsafe {
            shekyl_levin_compress_payload(tiny.as_ptr(), tiny.len(), std::ptr::null_mut())
        };
        assert_eq!(rc, SHEKYL_LEVIN_ERR_NULL);
    }
}
