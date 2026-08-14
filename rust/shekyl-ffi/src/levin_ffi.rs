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
//! The two directions sit at **different levels, on purpose**.
//!
//! Emit is **message-level** ([`shekyl_levin_compress_message`],
//! [`shekyl_levin_noise_notify`], [`shekyl_levin_fragmented_notify`]):
//! whether a buffer may be compressed at all is a property of its bucket
//! header, not its payload bytes — is it already compressed, is it exactly
//! one message, is it the noise/fragment class whose constant on-wire size
//! is the entire point of it. A payload-level seam would have to leave
//! those questions on the C++ side, which is exactly how the C++ came to
//! carry a second, weaker copy of the policy. `shekyl-levin` owns all of
//! it; `epee::levin::{try_compress_message, make_noise_notify,
//! make_fragmented_notify}` forward. The noise/fragment cut also collapses
//! the last dual implementation of the fragment padding algorithm — the
//! privacy-load-bearing piece the constant-parity gate could never cover
//! (it pins constants, not algorithms).
//!
//! Receive is **frame-level** ([`shekyl_levin_inflated_size`] +
//! [`shekyl_levin_decompress_into`]): by then the C++ handler has already
//! parsed and range-checked the header, and what it holds is one opaque
//! zstd frame plus the limit it must not exceed.
//!
//! Error codes follow rule 40 (distinct codes, not booleans):
//! `0` success; `1` compression declined (send the input unchanged); `-3`
//! malformed frame; `-4` null pointer; `-6` compression not compiled in;
//! `-7` size limit exceeded.
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
//! Variable-length emit (compress, noise, fragment) returns an owned
//! [`ShekylBuffer`]. Compression's size is not knowable before the fact;
//! fragment's size is a pad-or-split decision the library owns; noise
//! could be direct-write but shares the emit ownership shape so the three
//! C++ shims stay one helper. Levin payloads are public wire data, so
//! returning them by buffer is permitted (rule 40's secret-material
//! restriction does not apply). Receive stays direct-write.

use crate::{slice_from_ptr, ShekylBuffer};

/// Success: the operation completed and its output parameter is set.
pub const SHEKYL_LEVIN_OK: i32 = 0;
/// Compression declined: send the input unchanged. Not an error — it
/// covers the message being too small, incompressible, already compressed,
/// cover traffic whose size must not move, or the codec being absent.
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

/// Compress one finalized Levin message — header and payload together.
///
/// The seam is at the **message** level, not the payload level, because the
/// decision of whether a given buffer may be compressed is not a property
/// of its payload bytes: it depends on the bucket header (already
/// compressed? exactly one message? the noise/fragment class, whose
/// constant on-wire size is the whole point of it?). Splitting the decision
/// from the data it is about is what left the C++ carrying a second,
/// weaker copy of this policy; `shekyl-levin` owns all of it now, and
/// `epee::levin::try_compress_message` is a forwarding shim.
///
/// Returns [`SHEKYL_LEVIN_OK`] with `out` holding the re-framed
/// `COMPRESSED` message (free with `shekyl_buffer_free`), or
/// [`SHEKYL_LEVIN_DECLINED`] meaning "send the input unchanged" (`out` is
/// nulled) — which covers every refusal, from "too small to be worth it"
/// to "this is cover traffic". The caller still owns its input in both
/// cases, so a decline costs it nothing.
///
/// # Safety
///
/// `input` must point to `input_len` readable bytes; `out` must be a valid
/// writable pointer.
#[no_mangle]
pub unsafe extern "C" fn shekyl_levin_compress_message(
    input: *const u8,
    input_len: usize,
    out: *mut ShekylBuffer,
) -> i32 {
    if out.is_null() {
        return SHEKYL_LEVIN_ERR_NULL;
    }
    // SAFETY: caller guarantees `out` is writable (checked non-null above).
    unsafe { *out = ShekylBuffer::null() };
    let Some(message) = (unsafe { slice_from_ptr(input, input_len) }) else {
        return SHEKYL_LEVIN_ERR_NULL;
    };
    match shekyl_levin::compress_message(message) {
        Some(compressed) => {
            // SAFETY: `out` checked non-null above.
            unsafe { *out = ShekylBuffer::from_vec(compressed) };
            SHEKYL_LEVIN_OK
        }
        None => SHEKYL_LEVIN_DECLINED,
    }
}

/// Build a dummy ("noise") message of exactly `noise_bytes` total length:
/// command 0, `B|E` set, zeroed payload — the white-noise cover-traffic
/// unit. Byte-identical to the C++ `make_noise_notify` it replaces, pinned
/// by the `make_noise.*` gtests now running through this export.
///
/// Returns [`SHEKYL_LEVIN_OK`] with `out` set (free with
/// `shekyl_buffer_free`), or [`SHEKYL_LEVIN_ERR_FORMAT`] when `noise_bytes`
/// cannot hold a bucket header or would produce an `m_cb` above the Levin
/// packet limit (the C++ shim returns a null slice for both, matching the
/// historical contract). Size policy lives in [`shekyl_levin::noise_notify`];
/// this export is marshaling.
///
/// # Safety
///
/// `out` must be a valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn shekyl_levin_noise_notify(
    noise_bytes: usize,
    out: *mut ShekylBuffer,
) -> i32 {
    if out.is_null() {
        return SHEKYL_LEVIN_ERR_NULL;
    }
    // SAFETY: caller guarantees `out` is writable (checked non-null above).
    unsafe { *out = ShekylBuffer::null() };
    match shekyl_levin::noise_notify(noise_bytes) {
        Ok(noise) => {
            // SAFETY: `out` checked non-null above.
            unsafe { *out = ShekylBuffer::from_vec(noise) };
            SHEKYL_LEVIN_OK
        }
        Err(err) => code_for(&err),
    }
}

/// Emit a notification for `command` as one or more messages, each exactly
/// `noise_size` bytes on the wire — a single zero-padded notification when
/// it fits, `B`/middle/`E` fragments when it does not. This is the
/// white-noise fragmentation path; constant on-wire size is the property
/// the feature exists to provide, and the algorithm (padding discipline
/// included) now has exactly one implementation. Byte-identical to the C++
/// `make_fragmented_notify` it replaces, pinned by the `make_fragment.*`
/// gtests now running through this export.
///
/// Returns [`SHEKYL_LEVIN_OK`] with `out` set (free with
/// `shekyl_buffer_free`), or [`SHEKYL_LEVIN_ERR_FORMAT`] when `noise_size`
/// cannot hold two headers or would produce an `m_cb` above the Levin
/// packet limit. The inner payload may itself be larger — that is why this
/// path fragments. Size policy lives in
/// [`shekyl_levin::fragmented_notify`]; this export is marshaling.
///
/// # Safety
///
/// `payload` must point to `payload_len` readable bytes; `out` must be a
/// valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn shekyl_levin_fragmented_notify(
    noise_size: usize,
    command: u32,
    payload: *const u8,
    payload_len: usize,
    out: *mut ShekylBuffer,
) -> i32 {
    if out.is_null() {
        return SHEKYL_LEVIN_ERR_NULL;
    }
    // SAFETY: caller guarantees `out` is writable (checked non-null above).
    unsafe { *out = ShekylBuffer::null() };
    let Some(payload) = (unsafe { slice_from_ptr(payload, payload_len) }) else {
        return SHEKYL_LEVIN_ERR_NULL;
    };
    match shekyl_levin::fragmented_notify(noise_size, command, payload) {
        Ok(stream) => {
            // SAFETY: `out` checked non-null above.
            unsafe { *out = ShekylBuffer::from_vec(stream) };
            SHEKYL_LEVIN_OK
        }
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
    use shekyl_levin::HEADER_SIZE;

    /// Compress a notify message across the FFI, returning the buffer the
    /// export handed back. Panics unless the export actually compressed it,
    /// so a test built on this cannot silently exercise the decline path.
    fn compress_notify(payload: &[u8]) -> ShekylBuffer {
        let message = shekyl_levin::notify(2002, payload);
        let mut out = ShekylBuffer::null();
        // SAFETY: valid slice + out pointer.
        let rc =
            unsafe { shekyl_levin_compress_message(message.as_ptr(), message.len(), &raw mut out) };
        assert_eq!(rc, SHEKYL_LEVIN_OK);
        assert!(!out.ptr.is_null() && out.len < message.len());
        out
    }

    /// The zstd frame inside a re-framed `COMPRESSED` message.
    ///
    /// # Safety
    /// `buf` must be a buffer returned by `shekyl_levin_compress_message`.
    unsafe fn frame_of(buf: &ShekylBuffer) -> &[u8] {
        unsafe { std::slice::from_raw_parts(buf.ptr.add(HEADER_SIZE), buf.len - HEADER_SIZE) }
    }

    /// Round trip across the exact boundary the C++ shim uses — compress a
    /// whole message, then size-and-inflate its frame into caller storage.
    /// Bites against a marshaling defect (length, ownership, code mapping);
    /// it does NOT re-prove the codec, which `shekyl-levin`'s tests own.
    #[test]
    fn ffi_roundtrip_and_code_mapping() {
        let payload = vec![7u8; 4096];
        let compressed = compress_notify(&payload);
        // SAFETY: buffer returned by the export above.
        let frame = unsafe { frame_of(&compressed) };

        let mut size = 0usize;
        // SAFETY: valid slice + out pointer.
        let rc = unsafe {
            shekyl_levin_inflated_size(
                frame.as_ptr(),
                frame.len(),
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
                frame.as_ptr(),
                frame.len(),
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
    fn small_message_declines_and_garbage_frame_rejects() {
        let mut out = ShekylBuffer::null();
        let tiny = shekyl_levin::notify(2002, &[0u8; 8]);
        // SAFETY: valid slice + out pointer.
        let rc = unsafe { shekyl_levin_compress_message(tiny.as_ptr(), tiny.len(), &raw mut out) };
        assert_eq!(rc, SHEKYL_LEVIN_DECLINED);
        assert!(
            out.ptr.is_null(),
            "a decline must hand back nothing to free"
        );

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
            shekyl_levin_compress_message(tiny.as_ptr(), tiny.len(), std::ptr::null_mut())
        };
        assert_eq!(rc, SHEKYL_LEVIN_ERR_NULL);
    }

    /// The noise/fragment emitters must hand back exactly the bytes the
    /// library functions produce — these exports exist so the C++ shims are
    /// pure marshaling, and a marshaling defect (length, offset, code
    /// mapping) is what this bites. The byte *content* oracle is the C++
    /// gtest suite (`make_noise.*` / `make_fragment.*`), which runs through
    /// these exports after the cut.
    #[test]
    fn noise_and_fragment_exports_match_the_library() {
        let mut out = ShekylBuffer::null();
        // SAFETY: valid out pointer.
        let rc = unsafe { shekyl_levin_noise_notify(1024, &raw mut out) };
        assert_eq!(rc, SHEKYL_LEVIN_OK);
        // SAFETY: buffer returned by the export above.
        let got = unsafe { std::slice::from_raw_parts(out.ptr, out.len) };
        assert_eq!(got, shekyl_levin::noise_notify(1024).unwrap());
        // SAFETY: freeing exactly the buffer the export returned.
        unsafe { crate::shekyl_buffer_free(out.ptr, out.len) };

        let payload: Vec<u8> = (0u32..2922)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let mut out = ShekylBuffer::null();
        // SAFETY: valid slice + out pointer.
        let rc = unsafe {
            shekyl_levin_fragmented_notify(1024, 114, payload.as_ptr(), payload.len(), &raw mut out)
        };
        assert_eq!(rc, SHEKYL_LEVIN_OK);
        // SAFETY: buffer returned by the export above.
        let got = unsafe { std::slice::from_raw_parts(out.ptr, out.len) };
        assert_eq!(
            got,
            shekyl_levin::fragmented_notify(1024, 114, &payload).unwrap()
        );
        assert_eq!(got.len() % 1024, 0, "wire is noise-granular");
        // SAFETY: freeing exactly the buffer the export returned.
        unsafe { crate::shekyl_buffer_free(out.ptr, out.len) };
    }

    /// Invalid sizes map to the codes the C++ shim turns into the
    /// historical null-slice contract; a null out pointer is its own code.
    /// Bites against a marshaling defect that would collapse `-3` into
    /// `-7` (or drop the oversize arm); it does NOT re-prove the library
    /// bound, which `shekyl-levin`'s emit tests own.
    #[test]
    fn noise_and_fragment_reject_invalid_sizes() {
        let mut out = ShekylBuffer::null();
        // SAFETY: valid out pointer.
        let rc = unsafe { shekyl_levin_noise_notify(HEADER_SIZE - 1, &raw mut out) };
        assert_eq!(rc, SHEKYL_LEVIN_ERR_FORMAT);
        assert!(out.ptr.is_null());

        // SAFETY: valid slice + out pointer.
        let rc =
            unsafe { shekyl_levin_fragmented_notify(0, 0, [0u8; 1].as_ptr(), 1, &raw mut out) };
        assert_eq!(rc, SHEKYL_LEVIN_ERR_FORMAT);
        assert!(out.ptr.is_null());

        let too_big = HEADER_SIZE
            + usize::try_from(shekyl_levin::DEFAULT_MAX_PACKET_SIZE)
                .expect("packet limit fits usize")
            + 1;
        // SAFETY: valid out pointer; the library rejects before allocating.
        let rc = unsafe { shekyl_levin_noise_notify(too_big, &raw mut out) };
        assert_eq!(rc, SHEKYL_LEVIN_ERR_FORMAT);
        assert!(out.ptr.is_null());

        // SAFETY: valid slice + out pointer; same reject-before-allocate.
        let rc = unsafe {
            shekyl_levin_fragmented_notify(too_big, 0, [0u8; 1].as_ptr(), 1, &raw mut out)
        };
        assert_eq!(rc, SHEKYL_LEVIN_ERR_FORMAT);
        assert!(out.ptr.is_null());

        // SAFETY: null out pointer is the case under test.
        let rc = unsafe { shekyl_levin_noise_notify(1024, std::ptr::null_mut()) };
        assert_eq!(rc, SHEKYL_LEVIN_ERR_NULL);
    }

    /// Cover traffic must cross the boundary unchanged. This is the guard
    /// the C++ emit path never had while it carried its own copy of the
    /// policy: a noise bucket's constant on-wire size is the entire property
    /// the white-noise feature buys, and compressing one would shorten it.
    #[test]
    fn noise_message_declines_across_the_ffi() {
        let dummy = shekyl_levin::noise_notify(4096).unwrap();
        let mut out = ShekylBuffer::null();
        // SAFETY: valid slice + out pointer.
        let rc =
            unsafe { shekyl_levin_compress_message(dummy.as_ptr(), dummy.len(), &raw mut out) };
        assert_eq!(rc, SHEKYL_LEVIN_DECLINED);
        assert!(out.ptr.is_null());
    }

    /// The two failure codes the C++ shim logs differently must actually be
    /// different at the boundary: a frame that is too large is `-7`, a frame
    /// that is malformed is `-3`. Asserting only the "is it non-zero" shape
    /// would pass with the codes collapsed, which is the defect.
    #[test]
    fn oversize_and_malformed_map_to_distinct_codes() {
        let compressed = compress_notify(&vec![7u8; 4096]);
        // SAFETY: buffer returned by the export.
        let frame = unsafe { frame_of(&compressed) };

        // A well-formed frame whose declared size is over the caller's cap.
        let mut size = 0usize;
        // SAFETY: valid slice + out pointer.
        let rc =
            unsafe { shekyl_levin_inflated_size(frame.as_ptr(), frame.len(), 64, &raw mut size) };
        assert_eq!(rc, SHEKYL_LEVIN_ERR_TOO_LARGE);
        assert_eq!(size, 0);

        // The same frame under a sufficient cap is accepted, so the code
        // above is about the limit and not about the frame.
        // SAFETY: as above.
        let rc =
            unsafe { shekyl_levin_inflated_size(frame.as_ptr(), frame.len(), 4096, &raw mut size) };
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
        let compressed = compress_notify(&vec![7u8; 4096]);
        // SAFETY: buffer returned by the export.
        let frame = unsafe { frame_of(&compressed) };

        let mut small = vec![0u8; 32];
        let mut written = 1usize;
        // SAFETY: valid input, caller-owned destination, out pointer.
        let rc = unsafe {
            shekyl_levin_decompress_into(
                frame.as_ptr(),
                frame.len(),
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
