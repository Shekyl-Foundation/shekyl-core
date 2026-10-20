// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FFI surface for Levin framing policy, backed by `shekyl-levin`.
//!
//! Two jobs, both so the policy has one implementation:
//!
//! - **Ingress** ([`shekyl_levin_ingress_admit`]): the C++ `handle_recv`
//!   asks this crate whether a parsed bucket header is admitted and at what
//!   payload cap (PWD-B3 / PWD-B3a / PWD-B4). Undefined flag bits are
//!   connection-fatal; that includes `0x10`, the compressed-payload bit,
//!   since compression left the protocol (Rick, 2026-10-19).
//! - **White-noise emit** ([`shekyl_levin_noise_notify`],
//!   [`shekyl_levin_fragmented_notify`]): `epee::levin::{make_noise_notify,
//!   make_fragmented_notify}` forward here, which collapses the last dual
//!   implementation of the fragment padding algorithm — the
//!   privacy-load-bearing piece the constant-parity gate could never cover
//!   (it pins constants, not algorithms).
//!
//! Error codes follow rule 40 (distinct codes, not booleans): `0` success;
//! `-3` a noise or fragment size that cannot be emitted; `-4` null pointer;
//! `-8` unknown flag bits at ingress; `-9` unknown dispatch command.
//!
//! # Buffer ownership
//!
//! Variable-length emit returns an owned [`ShekylBuffer`]: fragment's size
//! is a pad-or-split decision the library owns, and noise shares the same
//! shape so the C++ shims stay one helper. Levin payloads are public wire
//! data, so returning them by buffer is permitted (rule 40's
//! secret-material restriction does not apply).

use crate::{slice_from_ptr, ShekylBuffer};

/// Success: the operation completed and its output parameter is set.
pub const SHEKYL_LEVIN_OK: i32 = 0;
/// A noise or fragment size that cannot hold its header(s), or that would
/// produce a bucket above the Levin packet limit.
pub const SHEKYL_LEVIN_ERR_FORMAT: i32 = -3;
/// A required pointer was null.
pub const SHEKYL_LEVIN_ERR_NULL: i32 = -4;
/// A bucket header set a flag bit this protocol does not define
/// (PWD-B3a). Connection-fatal at ingress.
pub const SHEKYL_LEVIN_ERR_UNKNOWN_FLAGS: i32 = -8;
/// A dispatch bucket (`REQUEST` or `RESPONSE`) named a command this
/// protocol does not define (PWD-B3a). Connection-fatal at ingress.
pub const SHEKYL_LEVIN_ERR_UNKNOWN_COMMAND: i32 = -9;

/// Map a `shekyl-levin` error onto its wire code. Written as a total match
/// on purpose: a new variant must be given a code here rather than falling
/// into a catch-all that reports it as a malformed frame.
fn code_for(err: &shekyl_levin::Error) -> i32 {
    use shekyl_levin::Error;
    match err {
        Error::BadSignature
        | Error::OversizePacket { .. }
        | Error::BufferLimit { .. }
        | Error::FragmentTooSmall
        | Error::InnerLengthTruncated { .. }
        | Error::Poisoned
        | Error::NoiseTooSmall { .. } => SHEKYL_LEVIN_ERR_FORMAT,
        Error::UnknownFlags { .. } => SHEKYL_LEVIN_ERR_UNKNOWN_FLAGS,
        Error::UnknownCommand { .. } => SHEKYL_LEVIN_ERR_UNKNOWN_COMMAND,
    }
}

/// Admit one parsed bucket header (PWD-B3 / PWD-B3a / PWD-B4).
///
/// Writes the payload cap into `out_cap` on success. A noise/fragment
/// bucket (neither `REQUEST` nor `RESPONSE`) writes `u64::MAX` so the
/// caller's packet limit binds — cover traffic with command 0 is not
/// an unknown command. A Q/S-flagged bucket whose command is not in the
/// defined set, or any unknown flag bit, is connection-fatal.
///
/// Return: `0` admitted (`*out_cap` set); `-4` `out_cap` was null;
/// `-8` unknown flags; `-9` unknown dispatch command.
#[no_mangle]
pub unsafe extern "C" fn shekyl_levin_ingress_admit(
    command: u32,
    flags: u32,
    out_cap: *mut u64,
) -> i32 {
    if out_cap.is_null() {
        return SHEKYL_LEVIN_ERR_NULL;
    }
    match shekyl_levin::ingress_payload_cap(command, shekyl_levin::Flags::from_bits(flags)) {
        Ok(cap) => {
            // SAFETY: `out_cap` checked non-null above.
            unsafe { *out_cap = cap };
            SHEKYL_LEVIN_OK
        }
        Err(err) => code_for(&err),
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

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_levin::HEADER_SIZE;

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
    /// Bites against a marshaling defect that would drop the oversize arm;
    /// it does NOT re-prove the library bound, which `shekyl-levin`'s emit
    /// tests own.
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

    #[test]
    fn ingress_admit_maps_the_three_codes() {
        let mut cap = 0u64;
        // Handshake (1001) + REQUEST: admitted at the envelope derived from
        // the disclosure count (PR-3: `DISCLOSE_COUNT` largest entries beside
        // the largest fixed part; `shekyl-levin` pins the parts).
        let rc = unsafe { shekyl_levin_ingress_admit(1001, 0x1, &raw mut cap) };
        assert_eq!(rc, SHEKYL_LEVIN_OK);
        assert_eq!(
            cap,
            shekyl_peerlist::DISCLOSE_COUNT as u64 * shekyl_levin::PEERLIST_ENTRY_MAX_ENCODED_BYTES
                + shekyl_levin::HANDSHAKE_FIXED_MAX_BYTES
        );

        // Compact announce (2008) keeps the inherited 4 MiB envelope.
        let rc = unsafe { shekyl_levin_ingress_admit(2008, 0x1, &raw mut cap) };
        assert_eq!(rc, SHEKYL_LEVIN_OK);
        assert_eq!(cap, 4 * 1024 * 1024);

        // Noise class (BEGIN|END, command 0): admitted, packet limit binds.
        let rc = unsafe { shekyl_levin_ingress_admit(0, 0x4 | 0x8, &raw mut cap) };
        assert_eq!(rc, SHEKYL_LEVIN_OK);
        assert_eq!(cap, u64::MAX);

        // Q-flagged command 0 is a dispatch of an unknown command.
        let rc = unsafe { shekyl_levin_ingress_admit(0, 0x1, &raw mut cap) };
        assert_eq!(rc, SHEKYL_LEVIN_ERR_UNKNOWN_COMMAND);

        // Unknown flag bit, even on a defined command.
        let rc = unsafe { shekyl_levin_ingress_admit(1001, 0x1 | 0x20, &raw mut cap) };
        assert_eq!(rc, SHEKYL_LEVIN_ERR_UNKNOWN_FLAGS);

        // The retired compression bit is refused like any undefined bit:
        // the C++ receiver closes the connection on it.
        let rc = unsafe { shekyl_levin_ingress_admit(2002, 0x1 | 0x10, &raw mut cap) };
        assert_eq!(rc, SHEKYL_LEVIN_ERR_UNKNOWN_FLAGS);

        // Retired ping (1003) and deleted NOTIFY_NEW_BLOCK (2001) on a dispatch.
        let rc = unsafe { shekyl_levin_ingress_admit(1003, 0x1, &raw mut cap) };
        assert_eq!(rc, SHEKYL_LEVIN_ERR_UNKNOWN_COMMAND);
        let rc = unsafe { shekyl_levin_ingress_admit(2001, 0x1, &raw mut cap) };
        assert_eq!(rc, SHEKYL_LEVIN_ERR_UNKNOWN_COMMAND);

        let rc = unsafe { shekyl_levin_ingress_admit(1001, 0x1, std::ptr::null_mut()) };
        assert_eq!(rc, SHEKYL_LEVIN_ERR_NULL);
    }
}
