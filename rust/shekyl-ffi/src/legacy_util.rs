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
    // `from_raw_parts` has a LANGUAGE-LEVEL precondition that the byte
    // length not exceed `isize::MAX` — violating it is UB even if the
    // caller really provided that much memory. This helper is the
    // crate's FFI-read seam for that bound; sites that still call
    // `from_raw_parts` directly re-own it (SA-R-7 conventions-tail
    // residual).
    if len > isize::MAX as usize {
        return None;
    }
    Some(std::slice::from_raw_parts(ptr, len))
}

/// Read a fixed-size **public** array through [`slice_from_ptr`].
/// One typed construction on top of the seam: null / zero-length /
/// `isize::MAX` are the helper's, the `N`-byte conversion is this
/// layer's.
///
/// # Safety
/// Same as [`slice_from_ptr`]: a non-null pointer must address at
/// least `N` bytes. That allocation-size precondition is the
/// caller's `# Safety` contract — no read idiom can check it.
pub(crate) unsafe fn array_from_ptr<const N: usize>(ptr: *const u8) -> Option<[u8; N]> {
    let slice = unsafe { slice_from_ptr(ptr, N) }?;
    Some(slice.try_into().expect("slice length is N by construction"))
}

/// Reserve `count` slots only if `remaining` bytes can back that many
/// `stride`-byte elements. Wire-embedded counts must go through this;
/// a raw `with_capacity(wire_count)` is the host-abort class SA-R-7
/// clause 2 names. `stride == 0` is a caller bug and refuses.
// Ratchet-mandated allocation path (`tests/ffi_boundary_ratchet.rs`), so it stays
// ungated and available to any future wire parser. Its only non-test callers today
// are the multisig witness parsers, so allow dead code exactly in the build where
// that is true — the allow disappears under `--features multisig`, where a genuine
// disuse would still fail the build.
#[cfg_attr(not(feature = "multisig"), allow(dead_code))]
pub(crate) fn bounded_capacity<T>(count: usize, stride: usize, remaining: usize) -> Option<Vec<T>> {
    if stride == 0 || count > remaining / stride {
        return None;
    }
    Some(Vec::with_capacity(count))
}

// ─── Generic Buffer Helpers ──────────────────────────────────────────────────

impl ShekylBuffer {
    /// Leak `data` as a raw `(ptr, len)` pair for C++ to take ownership of.
    ///
    /// The boxed-slice conversion is **load-bearing, not stylistic**. A
    /// `ShekylBuffer` carries no capacity field, so its only possible free
    /// path — [`shekyl_buffer_free`] — must reconstruct the allocation as
    /// `Vec::from_raw_parts(ptr, len, len)`. That is sound *only* when the
    /// leaked allocation was exactly `len` bytes wide, and a `Vec` is under
    /// no obligation to be: `zstd::bulk::compress`, for one, returns a
    /// `Vec` sized at `compress_bound(input)` with `len` set to the (always
    /// strictly smaller) compressed size. Freeing that through a
    /// `len`-capacity `Vec` hands the allocator a `Layout` that never
    /// matched the allocation — benign under glibc `free()`, which ignores
    /// the size, and heap corruption under any size-aware allocator.
    ///
    /// `into_boxed_slice()` shrinks the allocation to exactly `len` first,
    /// which makes `capacity == len` an invariant of every buffer that
    /// crosses this boundary rather than a property each caller has to
    /// remember to establish.
    pub(crate) fn from_vec(data: Vec<u8>) -> Self {
        let data = Box::leak(data.into_boxed_slice());
        ShekylBuffer {
            ptr: data.as_mut_ptr(),
            len: data.len(),
        }
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
/// `ptr`/`len` **must** be exactly the pair from the paired Rust export
/// (i.e. the fields of the [`ShekylBuffer`] that was returned), which
/// [`ShekylBuffer::from_vec`] guarantees was allocated exactly `len` bytes
/// wide. Passing a different `len` is undefined behavior — it reconstructs
/// a `Vec` whose capacity does not match the allocation.
#[no_mangle]
pub unsafe extern "C" fn shekyl_buffer_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        use zeroize::Zeroize;
        std::slice::from_raw_parts_mut(ptr, len).zeroize();
        drop(Vec::from_raw_parts(ptr, len, len));
    }
}

#[cfg(test)]
mod slice_from_ptr_tests {
    use super::*;

    /// The `isize::MAX` byte bound is refused BEFORE `from_raw_parts` is
    /// reached (the guard returns `None` without constructing the slice,
    /// so the dangling pointer is never dereferenced or blessed).
    #[test]
    fn oversized_len_is_refused_before_slice_construction() {
        let dangling = std::ptr::NonNull::<u8>::dangling().as_ptr();
        let too_big = (isize::MAX as usize) + 1;
        assert!(unsafe { slice_from_ptr(dangling, too_big) }.is_none());
        // Control: a small length over real bytes still works.
        let bytes = [7u8; 4];
        assert_eq!(
            unsafe { slice_from_ptr(bytes.as_ptr(), 4) },
            Some(&bytes[..])
        );
    }

    #[test]
    fn bounded_capacity_refuses_unbacked_and_zero_stride() {
        let v: Option<Vec<u8>> = bounded_capacity(3, 32, 96);
        assert_eq!(v.map(|x| x.capacity()), Some(3));
        assert!(bounded_capacity::<u8>(4, 32, 96).is_none());
        assert!(bounded_capacity::<u8>(1, 0, 96).is_none());
        // Exact fit is allowed; one byte short is not.
        assert!(bounded_capacity::<u8>(1, 128, 128).is_some());
        assert!(bounded_capacity::<u8>(1, 128, 127).is_none());
    }
}
