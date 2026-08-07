// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared pointer/slice helpers for the legacy monofile FFI surface.

use super::legacy_types::ShekylBuffer;

pub(crate) fn arr32_from_ptr(ptr: *const u8) -> Option<[u8; 32]> {
    if ptr.is_null() {
        return None;
    }
    let mut arr = [0u8; 32];
    unsafe { std::ptr::copy_nonoverlapping(ptr, arr.as_mut_ptr(), 32) };
    Some(arr)
}

/// Read 32 **secret** bytes from a C pointer directly into a `Zeroizing`
/// buffer, so no intermediate plaintext stack copy ever exists (rule 30
/// direct-write) and the bytes wipe on drop (rule 35). Use this instead of
/// [`arr32_from_ptr`] for key material (e.g. a wallet spend secret); the
/// non-secret variant is fine for public 32-byte values.
pub(crate) fn zeroizing_arr32_from_ptr(ptr: *const u8) -> Option<zeroize::Zeroizing<[u8; 32]>> {
    if ptr.is_null() {
        return None;
    }
    let mut buf = zeroize::Zeroizing::new([0u8; 32]);
    unsafe { std::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), 32) };
    Some(buf)
}

/// # Safety
///
/// The caller must ensure that `ptr` points to a valid allocation of at
/// least `len` bytes, and that the returned reference does not outlive the
/// allocation. This is the standard FFI raw-pointer-to-slice contract —
/// the function is `unsafe` because safe Rust cannot verify these
/// preconditions.
pub(crate) unsafe fn slice_from_ptr<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        return None;
    }
    Some(std::slice::from_raw_parts(ptr, len))
}

// ─── Generic Buffer Helpers ──────────────────────────────────────────────────

impl ShekylBuffer {
    pub(crate) fn from_vec(mut data: Vec<u8>) -> Self {
        let buffer = ShekylBuffer {
            ptr: data.as_mut_ptr(),
            len: data.len(),
        };
        std::mem::forget(data);
        buffer
    }

    pub(crate) fn null() -> Self {
        ShekylBuffer {
            ptr: std::ptr::null_mut(),
            len: 0,
        }
    }
}

/// Free a buffer originally allocated by a Rust FFI export.
///
/// # Safety
/// `len` **must** equal the buffer length from the paired Rust export (i.e.,
/// the `len` field of the `ShekylBuffer` that was returned). Passing a
/// different `len` is undefined behavior — it reconstructs a `Vec` with
/// mismatched capacity.
#[no_mangle]
pub unsafe extern "C" fn shekyl_buffer_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        use zeroize::Zeroize;
        std::slice::from_raw_parts_mut(ptr, len).zeroize();
        drop(Vec::from_raw_parts(ptr, len, len));
    }
}
