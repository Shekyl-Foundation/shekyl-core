// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FFI for the DRS-P0d logical-state digest v0.
//!
//! One coarse export: C++ walks production LMDB (height-ordered
//! `block_info` hashes, `spent_keys`, live curve-tree root) and hands
//! the three families over in one call. The hasher lives in
//! `shekyl-chain-store` (`#![deny(unsafe_code)]`); this module is the
//! `unsafe` pointer boundary only.

use crate::{array_from_ptr, slice_from_ptr};
use shekyl_chain_store::digest_v0::digest_v0;

/// Success; `*out_digest` holds the 32-byte digest.
pub const SHEKYL_CHAIN_DIGEST_V0_OK: i32 = 0;
/// A required pointer was null. `curve_root` and `out_digest` are
/// always required; `block_hashes` / `spent_keys` may be null only
/// when the corresponding count is 0.
pub const SHEKYL_CHAIN_DIGEST_V0_ERR_NULL_PTR: i32 = -1;
/// `n_blocks` or `n_spent` overflowed `usize` when widened to bytes.
pub const SHEKYL_CHAIN_DIGEST_V0_ERR_OVERFLOW: i32 = -2;

/// Layout-independent logical state digest v0.
///
/// `block_hashes` is `n_blocks` concatenated 32-byte hashes in height
/// order (index 0 = genesis). `spent_keys` is `n_spent` concatenated
/// 32-byte key images in any order. `curve_root` / `out_digest` are
/// 32-byte buffers.
///
/// # Safety
///
/// Pointers that the null-pointer convention requires must be valid
/// for `count * 32` bytes of reads (or 32 bytes of writes for
/// `out_digest`) for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn shekyl_logical_state_digest_v0(
    block_hashes: *const u8,
    n_blocks: u64,
    spent_keys: *const u8,
    n_spent: u64,
    curve_root: *const u8,
    out_digest: *mut u8,
) -> i32 {
    if out_digest.is_null() || curve_root.is_null() {
        return SHEKYL_CHAIN_DIGEST_V0_ERR_NULL_PTR;
    }
    if n_blocks > 0 && block_hashes.is_null() {
        return SHEKYL_CHAIN_DIGEST_V0_ERR_NULL_PTR;
    }
    if n_spent > 0 && spent_keys.is_null() {
        return SHEKYL_CHAIN_DIGEST_V0_ERR_NULL_PTR;
    }

    let blocks = match hashes_from_raw(block_hashes, n_blocks) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let spent = match hashes_from_raw(spent_keys, n_spent) {
        Ok(s) => s,
        Err(code) => return code,
    };

    let Some(root) = (unsafe { array_from_ptr::<32>(curve_root) }) else {
        return SHEKYL_CHAIN_DIGEST_V0_ERR_NULL_PTR;
    };
    let digest = digest_v0(blocks, spent, &root);
    unsafe {
        out_digest.copy_from_nonoverlapping(digest.as_ptr(), 32);
    }
    SHEKYL_CHAIN_DIGEST_V0_OK
}

/// Borrow `n` concatenated 32-byte hashes through the crate's FFI-read
/// seam (`slice_from_ptr`), then view them as `&[[u8; 32]]` via
/// `as_chunks` so this file never re-owns `from_raw_parts` (SA-R-7).
fn hashes_from_raw<'a>(ptr: *const u8, n: u64) -> Result<&'a [[u8; 32]], i32> {
    if n == 0 {
        return Ok(&[]);
    }
    let count = match usize::try_from(n) {
        Ok(c) => c,
        Err(_) => return Err(SHEKYL_CHAIN_DIGEST_V0_ERR_OVERFLOW),
    };
    let byte_len = match count.checked_mul(32) {
        Some(len) => len,
        None => return Err(SHEKYL_CHAIN_DIGEST_V0_ERR_OVERFLOW),
    };
    let Some(bytes) = (unsafe { slice_from_ptr(ptr, byte_len) }) else {
        return Err(if ptr.is_null() {
            SHEKYL_CHAIN_DIGEST_V0_ERR_NULL_PTR
        } else {
            SHEKYL_CHAIN_DIGEST_V0_ERR_OVERFLOW
        });
    };
    let (chunks, rem) = bytes.as_chunks::<32>();
    debug_assert!(rem.is_empty(), "byte_len is a multiple of 32");
    Ok(chunks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_chain_store::digest_v0::digest_v0;

    #[test]
    fn null_out_digest_is_refused() {
        let root = [0x44u8; 32];
        let code = unsafe {
            shekyl_logical_state_digest_v0(
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                root.as_ptr(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(code, SHEKYL_CHAIN_DIGEST_V0_ERR_NULL_PTR);
    }

    #[test]
    fn null_hashes_with_nonzero_count_is_refused() {
        let root = [0x44u8; 32];
        let mut out = [0u8; 32];
        let code = unsafe {
            shekyl_logical_state_digest_v0(
                std::ptr::null(),
                1,
                std::ptr::null(),
                0,
                root.as_ptr(),
                out.as_mut_ptr(),
            )
        };
        assert_eq!(code, SHEKYL_CHAIN_DIGEST_V0_ERR_NULL_PTR);
    }

    #[test]
    fn empty_families_match_the_safe_hasher() {
        let root = [0x44u8; 32];
        let mut out = [0u8; 32];
        let code = unsafe {
            shekyl_logical_state_digest_v0(
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                root.as_ptr(),
                out.as_mut_ptr(),
            )
        };
        assert_eq!(code, SHEKYL_CHAIN_DIGEST_V0_OK);
        assert_eq!(out, digest_v0(&[], &[], &root));
    }

    #[test]
    fn spent_order_does_not_cross_the_ffi() {
        let blocks = [0x11u8; 32];
        let mut spent = [0u8; 64];
        spent[..32].fill(0x22);
        spent[32..].fill(0x33);
        let mut spent_rev = [0u8; 64];
        spent_rev[..32].fill(0x33);
        spent_rev[32..].fill(0x22);
        let root = [0x44u8; 32];
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        let ca = unsafe {
            shekyl_logical_state_digest_v0(
                blocks.as_ptr(),
                1,
                spent.as_ptr(),
                2,
                root.as_ptr(),
                a.as_mut_ptr(),
            )
        };
        let cb = unsafe {
            shekyl_logical_state_digest_v0(
                blocks.as_ptr(),
                1,
                spent_rev.as_ptr(),
                2,
                root.as_ptr(),
                b.as_mut_ptr(),
            )
        };
        assert_eq!(ca, SHEKYL_CHAIN_DIGEST_V0_OK);
        assert_eq!(cb, SHEKYL_CHAIN_DIGEST_V0_OK);
        assert_eq!(a, b);
    }
}
