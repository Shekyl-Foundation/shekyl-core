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
//! side framed the message; only opaque payload bytes cross.
//!
//! Error codes follow rule 40 (distinct codes, not booleans):
//! `0` success; `1` compression declined (send uncompressed — the C++
//! `compress_payload == false` path); `-3` malformed frame; `-4` null
//! pointer; `-6` compression not compiled in; `-7` size limit exceeded.
//!
//! `-3` and `-7` are deliberately **not** one code. On the receive path
//! both close the connection, but they describe opposite situations — a
//! corrupt or hostile peer versus an honest peer whose batch outgrew the
//! per-command cap — and an operator watching disconnect logs has to be
//! able to tell which one they are looking at, because the responses (ban
//! the peer / raise the cap) are opposite too.
//!
//! # Buffer ownership
//!
//! Decompression writes **into caller storage**
//! ([`shekyl_levin_inflated_size`] then [`shekyl_levin_decompress_into`]):
//! the C++ shim sizes its `std::string` and inflates straight into it, so
//! no allocation is made on the Rust side, nothing is copied across the
//! boundary, and no heap ownership crosses in either direction. This is the
//! rule-40 direct-write shape, and it matters on the receive path
//! specifically — during IBD these are multi-megabyte block batches, once
//! per packet per connection.
//!
//! Compression still returns an owned [`ShekylBuffer`], because its output
//! size is not knowable before the fact and the emit path is not the one
//! that carries bulk. Payloads are public wire data, so returning them by
//! buffer is permitted (rule 40's secret-material restriction does not
//! apply).

use crate::{slice_from_ptr, ShekylBuffer};

/// Success: the operation completed and its output parameter is set.
pub const SHEKYL_LEVIN_OK: i32 = 0;
/// Compression declined (payload too small, incompressible, or codec
/// unavailable): send the payload uncompressed. Not an error.
pub const SHEKYL_LEVIN_DECLINED: i32 = 1;
/// Malformed input: bad zstd frame, or one that does not declare its
/// content size.
pub const SHEKYL_LEVIN_ERR_FORMAT: i32 = -3;
/// A required pointer was null, or an output buffer was too small.
pub const SHEKYL_LEVIN_ERR_NULL: i32 = -4;
/// The Rust image was built without the `zstd` feature (production always
/// has it on; this code is for pure-Rust feature-off builds only).
pub const SHEKYL_LEVIN_ERR_UNAVAILABLE: i32 = -6;
/// A size limit was exceeded: a frame declaring more than
/// `min(max_output, DECOMPRESSED_MAX_SIZE)` on the receive side, or a
/// payload above `DECOMPRESSED_MAX_SIZE` offered to the compressor.
pub const SHEKYL_LEVIN_ERR_TOO_LARGE: i32 = -7;

/// Map a `shekyl-levin` error onto its wire code. Written as a total match
/// on purpose: a new variant must be given a code here rather than falling
/// into a catch-all that reports it as a malformed frame.
fn code_for(err: &shekyl_levin::Error) -> i32 {
    use shekyl_levin::Error;
    match err {
        Error::CompressionUnavailable => SHEKYL_LEVIN_ERR_UNAVAILABLE,
        Error::OversizeInflate { .. } | Error::OversizeDeflate { .. } => SHEKYL_LEVIN_ERR_TOO_LARGE,
        Error::Decompress { .. }
        | Error::BadSignature
        | Error::OversizePacket { .. }
        | Error::BufferLimit { .. }
        | Error::FragmentTooSmall
        | Error::InnerLengthTruncated { .. }
        | Error::Poisoned
        | Error::NoiseTooSmall { .. } => SHEKYL_LEVIN_ERR_FORMAT,
    }
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
/// `input` must point to `input_len` readable bytes; `out` must be a valid
/// writable pointer. The input bound is
/// [`shekyl_levin::DECOMPRESSED_MAX_SIZE`] — the *plaintext* maximum, not
/// the wire packet limit, because a payload between the two is exactly what
/// compression exists to bring under the wire limit. Larger returns
/// [`SHEKYL_LEVIN_ERR_TOO_LARGE`].
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
    match shekyl_levin::compress_payload(payload) {
        Ok(Some(compressed)) => {
            // SAFETY: `out` checked non-null above.
            unsafe { *out = ShekylBuffer::from_vec(compressed) };
            SHEKYL_LEVIN_OK
        }
        Ok(None) => SHEKYL_LEVIN_DECLINED,
        Err(err) => code_for(&err),
    }
}

/// Read a `COMPRESSED` payload's frame header and report how many bytes it
/// will inflate to, writing it to `out_size`.
///
/// This is the allocation gate: the declared size is validated against
/// `min(max_output, DECOMPRESSED_MAX_SIZE)` before the caller sizes
/// anything from it, so a frame that lies about its content size cannot
/// cost an allocation. Callers pass the packet-size limit the bucket header
/// was checked against, which makes the bound on an inflated payload
/// identical to the bound the same connection enforces on an uncompressed
/// one.
///
/// Returns [`SHEKYL_LEVIN_OK`] with `out_size` set,
/// [`SHEKYL_LEVIN_ERR_FORMAT`] on a malformed or size-less frame,
/// [`SHEKYL_LEVIN_ERR_TOO_LARGE`] when the declared size exceeds the limit,
/// or [`SHEKYL_LEVIN_ERR_UNAVAILABLE`] without zstd support.
///
/// # Safety
///
/// `input` must point to `input_len` readable bytes; `out_size` must be a
/// valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn shekyl_levin_inflated_size(
    input: *const u8,
    input_len: usize,
    max_output: u64,
    out_size: *mut usize,
) -> i32 {
    if out_size.is_null() {
        return SHEKYL_LEVIN_ERR_NULL;
    }
    // SAFETY: caller guarantees `out_size` is writable (checked non-null).
    unsafe { *out_size = 0 };
    let Some(payload) = (unsafe { slice_from_ptr(input, input_len) }) else {
        return SHEKYL_LEVIN_ERR_NULL;
    };
    match shekyl_levin::inflated_size(payload, max_output) {
        Ok(size) => {
            // SAFETY: `out_size` checked non-null above.
            unsafe { *out_size = size };
            SHEKYL_LEVIN_OK
        }
        Err(err) => code_for(&err),
    }
}

/// Inflate a `COMPRESSED` payload directly into caller-owned storage.
///
/// `out` must be `out_cap` writable bytes, sized from
/// [`shekyl_levin_inflated_size`] on the same `input`. On success
/// `out_written` receives the byte count, which always equals the size that
/// call reported. No allocation is performed and no ownership crosses the
/// boundary — the buffer is and remains the caller's.
///
/// Returns [`SHEKYL_LEVIN_OK`], [`SHEKYL_LEVIN_ERR_FORMAT`] if the codec
/// rejects the frame or it does not deliver exactly `out_cap` bytes,
/// [`SHEKYL_LEVIN_ERR_NULL`] on a null pointer, or
/// [`SHEKYL_LEVIN_ERR_UNAVAILABLE`] without zstd support.
///
/// # Safety
///
/// `input` must point to `input_len` readable bytes; `out` must point to
/// `out_cap` writable, initialized bytes; `out_written` must be a valid
/// writable pointer. The regions must not overlap.
#[no_mangle]
pub unsafe extern "C" fn shekyl_levin_decompress_into(
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_written: *mut usize,
) -> i32 {
    if out_written.is_null() {
        return SHEKYL_LEVIN_ERR_NULL;
    }
    // SAFETY: caller guarantees `out_written` is writable (checked non-null).
    unsafe { *out_written = 0 };
    let Some(payload) = (unsafe { slice_from_ptr(input, input_len) }) else {
        return SHEKYL_LEVIN_ERR_NULL;
    };
    if out.is_null() && out_cap > 0 {
        return SHEKYL_LEVIN_ERR_NULL;
    }
    // SAFETY: caller guarantees `out` points at `out_cap` writable,
    // initialized bytes; the null-with-capacity case is rejected above and
    // `from_raw_parts_mut` accepts a dangling pointer only at length 0,
    // which is what the empty case supplies.
    let destination = if out_cap == 0 {
        &mut [][..]
    } else {
        unsafe { std::slice::from_raw_parts_mut(out, out_cap) }
    };
    match shekyl_levin::decompress_into(payload, destination) {
        Ok(written) => {
            // SAFETY: `out_written` checked non-null above.
            unsafe { *out_written = written };
            SHEKYL_LEVIN_OK
        }
        Err(err) => code_for(&err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round trip across the exact boundary the C++ shim uses — compress to
    /// an owned buffer, then size-and-inflate into caller storage. Bites
    /// against a marshaling defect (length, ownership, code mapping); it
    /// does NOT re-prove the codec, which `shekyl-levin`'s tests own.
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

        let mut size = 0usize;
        // SAFETY: buffer from the call above; valid out pointer.
        let rc = unsafe {
            shekyl_levin_inflated_size(
                compressed.ptr,
                compressed.len,
                shekyl_levin::DEFAULT_MAX_PACKET_SIZE,
                &raw mut size,
            )
        };
        assert_eq!(rc, SHEKYL_LEVIN_OK);
        assert_eq!(size, payload.len());

        let mut inflated = vec![0u8; size];
        let mut written = 0usize;
        // SAFETY: valid input slice, caller-owned destination, out pointer.
        let rc = unsafe {
            shekyl_levin_decompress_into(
                compressed.ptr,
                compressed.len,
                inflated.as_mut_ptr(),
                inflated.len(),
                &raw mut written,
            )
        };
        assert_eq!(rc, SHEKYL_LEVIN_OK);
        assert_eq!(written, payload.len());
        assert_eq!(inflated, payload);

        // SAFETY: freeing exactly the buffer the compress export returned.
        unsafe { crate::shekyl_buffer_free(compressed.ptr, compressed.len) };
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
        let mut size = 0usize;
        // SAFETY: valid slice + out pointer.
        let rc = unsafe {
            shekyl_levin_inflated_size(
                garbage.as_ptr(),
                garbage.len(),
                shekyl_levin::DEFAULT_MAX_PACKET_SIZE,
                &raw mut size,
            )
        };
        assert_eq!(rc, SHEKYL_LEVIN_ERR_FORMAT);
        assert_eq!(size, 0);

        // SAFETY: null out pointer is the case under test.
        let rc = unsafe {
            shekyl_levin_compress_payload(tiny.as_ptr(), tiny.len(), std::ptr::null_mut())
        };
        assert_eq!(rc, SHEKYL_LEVIN_ERR_NULL);
    }

    /// The two failure codes the C++ shim logs differently must actually be
    /// different at the boundary: a frame that is too large is `-7`, a frame
    /// that is malformed is `-3`. Asserting only the "is it non-zero" shape
    /// would pass with the codes collapsed, which is the defect.
    #[test]
    fn oversize_and_malformed_map_to_distinct_codes() {
        let payload = vec![7u8; 4096];
        let mut compressed = ShekylBuffer::null();
        // SAFETY: valid slice + out pointer.
        let rc = unsafe {
            shekyl_levin_compress_payload(payload.as_ptr(), payload.len(), &raw mut compressed)
        };
        assert_eq!(rc, SHEKYL_LEVIN_OK);

        // A well-formed frame whose declared size is over the caller's cap.
        let mut size = 0usize;
        // SAFETY: buffer from the call above; valid out pointer.
        let rc = unsafe {
            shekyl_levin_inflated_size(compressed.ptr, compressed.len, 64, &raw mut size)
        };
        assert_eq!(rc, SHEKYL_LEVIN_ERR_TOO_LARGE);
        assert_eq!(size, 0);

        // The same frame under a sufficient cap is accepted, so the code
        // above is about the limit and not about the frame.
        // SAFETY: as above.
        let rc = unsafe {
            shekyl_levin_inflated_size(compressed.ptr, compressed.len, 4096, &raw mut size)
        };
        assert_eq!(rc, SHEKYL_LEVIN_OK);
        assert_eq!(size, 4096);

        // SAFETY: freeing exactly the buffer the compress export returned.
        unsafe { crate::shekyl_buffer_free(compressed.ptr, compressed.len) };
    }

    /// A destination smaller than the frame declares must fail loudly and
    /// leave the caller's buffer untouched, not deliver a truncated payload
    /// the receive path would then parse as a message.
    #[test]
    fn undersized_destination_rejects_without_partial_write() {
        let payload = vec![7u8; 4096];
        let mut compressed = ShekylBuffer::null();
        // SAFETY: valid slice + out pointer.
        let rc = unsafe {
            shekyl_levin_compress_payload(payload.as_ptr(), payload.len(), &raw mut compressed)
        };
        assert_eq!(rc, SHEKYL_LEVIN_OK);

        let mut small = vec![0u8; 32];
        let mut written = 1usize;
        // SAFETY: valid input, caller-owned destination, out pointer.
        let rc = unsafe {
            shekyl_levin_decompress_into(
                compressed.ptr,
                compressed.len,
                small.as_mut_ptr(),
                small.len(),
                &raw mut written,
            )
        };
        assert_eq!(rc, SHEKYL_LEVIN_ERR_FORMAT);
        assert_eq!(written, 0);
        assert_eq!(small, vec![0u8; 32]);

        // SAFETY: freeing exactly the buffer the compress export returned.
        unsafe { crate::shekyl_buffer_free(compressed.ptr, compressed.len) };
    }
}
