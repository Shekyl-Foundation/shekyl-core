// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

//! Settlement-outcome row encoding across the FFI boundary (`SO-D2`).
//!
//! C++ owns the LMDB table and the key; **Rust owns the value**, because the
//! value carries the invariant that its `outcome` byte equals the fold over
//! its counts. Rule 36: C++ holds opaque bytes and never composes them.
//!
//! There is deliberately no `outcome` parameter here. The caller supplies
//! counts and receives three bytes — the same reason
//! [`shekyl_archival_retention::SettlementRow`] has no outcome-taking
//! constructor. An FFI entry that accepted an outcome would reopen, at the
//! boundary, exactly the disagreement the type closes.

use shekyl_archival_retention::{SettlementRow, SETTLEMENT_ROW_LEN};

/// Row encoded successfully; `out_row` holds [`SETTLEMENT_ROW_LEN`] bytes.
pub const SHEKYL_ARCHIVAL_SETTLEMENT_OK: u8 = 0;
/// A null pointer was passed.
pub const SHEKYL_ARCHIVAL_SETTLEMENT_ERR_NULL: u8 = 1;
/// `passes > issued` — a desynced accounting input, not a settlement state.
pub const SHEKYL_ARCHIVAL_SETTLEMENT_ERR_MORE_PASSES_THAN_ISSUED: u8 = 2;
/// `issued` does not fit the one byte the row allots it.
pub const SHEKYL_ARCHIVAL_SETTLEMENT_ERR_ISSUED_RANGE: u8 = 3;

/// Encode one settlement-outcome row from its counts.
///
/// Writes exactly [`SETTLEMENT_ROW_LEN`] bytes to `out_row` on
/// [`SHEKYL_ARCHIVAL_SETTLEMENT_OK`], and writes nothing otherwise — a refused
/// fold must not leave a half-written buffer that a caller ignoring the return
/// code would store.
///
/// # Safety
///
/// `out_row` must be non-null and point to at least [`SETTLEMENT_ROW_LEN`]
/// writable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_settlement_row(
    passes: u32,
    issued: u32,
    out_row: *mut u8,
) -> u8 {
    if out_row.is_null() {
        return SHEKYL_ARCHIVAL_SETTLEMENT_ERR_NULL;
    }
    match SettlementRow::settle(passes, issued) {
        Ok(row) => {
            // SAFETY: caller guarantees SETTLEMENT_ROW_LEN writable bytes.
            unsafe {
                std::ptr::copy_nonoverlapping(row.as_bytes().as_ptr(), out_row, SETTLEMENT_ROW_LEN);
            }
            SHEKYL_ARCHIVAL_SETTLEMENT_OK
        }
        Err(shekyl_archival_retention::RowError::IssuedOutOfRange { .. }) => {
            SHEKYL_ARCHIVAL_SETTLEMENT_ERR_ISSUED_RANGE
        }
        Err(_) => SHEKYL_ARCHIVAL_SETTLEMENT_ERR_MORE_PASSES_THAN_ISSUED,
    }
}

/// Length of an encoded settlement row, so C++ sizes its buffer from the
/// definition rather than a literal `3`.
#[no_mangle]
pub extern "C" fn shekyl_archival_settlement_row_len() -> usize {
    SETTLEMENT_ROW_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_the_forcing_case() {
        let mut row = [0u8; SETTLEMENT_ROW_LEN];
        // SAFETY: `row` is a live 3-byte buffer.
        let rc = unsafe { shekyl_archival_settlement_row(0, 3, row.as_mut_ptr()) };
        assert_eq!(rc, SHEKYL_ARCHIVAL_SETTLEMENT_OK);
        assert_eq!(
            row,
            *SettlementRow::settle(0, 3).expect("settleable").as_bytes()
        );
    }

    #[test]
    fn a_refused_fold_writes_nothing() {
        let mut row = [0xAAu8; SETTLEMENT_ROW_LEN];
        // SAFETY: `row` is a live 3-byte buffer.
        let rc = unsafe { shekyl_archival_settlement_row(3, 2, row.as_mut_ptr()) };
        assert_eq!(rc, SHEKYL_ARCHIVAL_SETTLEMENT_ERR_MORE_PASSES_THAN_ISSUED);
        assert_eq!(
            row, [0xAA; SETTLEMENT_ROW_LEN],
            "a refused fold must leave the caller's buffer untouched, or a caller \
             that ignores the return code stores a fabricated settlement"
        );
    }

    #[test]
    fn issued_beyond_one_byte_has_its_own_code() {
        let mut row = [0u8; SETTLEMENT_ROW_LEN];
        // SAFETY: `row` is a live 3-byte buffer.
        let rc = unsafe { shekyl_archival_settlement_row(0, 256, row.as_mut_ptr()) };
        assert_eq!(rc, SHEKYL_ARCHIVAL_SETTLEMENT_ERR_ISSUED_RANGE);
    }

    #[test]
    fn null_out_is_refused_not_dereferenced() {
        // SAFETY: passing null is exactly what this entry must survive.
        let rc = unsafe { shekyl_archival_settlement_row(0, 3, std::ptr::null_mut()) };
        assert_eq!(rc, SHEKYL_ARCHIVAL_SETTLEMENT_ERR_NULL);
    }

    #[test]
    fn cpp_sizes_its_buffer_from_the_definition() {
        assert_eq!(shekyl_archival_settlement_row_len(), SETTLEMENT_ROW_LEN);
    }
}
