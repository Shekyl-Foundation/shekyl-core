// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Serve-credit vin verification FFI (`ARCHIVAL_RETENTION_GATE2.md` §5.3).

use std::io::Cursor;

use shekyl_archival_retention::ArchivalServeCreditResponse;

use super::codes::*;
use crate::legacy_util::slice_from_ptr;

/// Extract the three fields C++ indexes a serve-credit by — `(P, shard, E)` —
/// from the opaque kept-side vin (`canonical_bytes`, **tag byte included**).
///
/// The Rust codec is the blob's only parser (rule 40): the tag, the interior,
/// and trailing-byte rejection all live here. C++ never slices the tag off.
/// An empty slice is a wire failure, not a null-pointer failure — a Rust
/// caller of `slice.as_ptr()` on an empty buffer is non-null.
///
/// # Safety
/// `vin_ptr[..vin_len]` must be readable when `vin_len > 0`; `out_p_canonical_id`
/// must point at 32 writable bytes; `out_shard_id` / `out_settlement_epoch`
/// must be valid.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_serve_credit_extract(
    vin_ptr: *const u8,
    vin_len: usize,
    out_p_canonical_id: *mut u8,
    out_shard_id: *mut u64,
    out_settlement_epoch: *mut u64,
) -> u8 {
    if vin_ptr.is_null()
        || out_p_canonical_id.is_null()
        || out_shard_id.is_null()
        || out_settlement_epoch.is_null()
    {
        return SHEKYL_ARCHIVAL_VERIFY_ERR_NULL_PTR;
    }
    let Some(bytes) = (unsafe { slice_from_ptr(vin_ptr, vin_len) }) else {
        return SHEKYL_ARCHIVAL_VERIFY_ERR_NULL_PTR;
    };
    let kept = match ArchivalServeCreditResponse::read_exact(&mut Cursor::new(bytes)) {
        Ok(k) => k,
        Err(e) => return map_wire_error(&e),
    };
    unsafe {
        std::ptr::copy_nonoverlapping(kept.p_canonical_id.as_ptr(), out_p_canonical_id, 32);
        *out_shard_id = kept.shard_id;
        *out_settlement_epoch = kept.settlement_epoch;
    }
    SHEKYL_ARCHIVAL_VERIFY_OK
}
