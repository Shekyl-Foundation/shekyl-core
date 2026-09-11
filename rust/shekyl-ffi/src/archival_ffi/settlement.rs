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
/// `SO-D1`: `issued == 0` is not a row. A pair the urn never reached is
/// recorded by its ABSENCE, so writing one would make absence ambiguous.
pub const SHEKYL_ARCHIVAL_SETTLEMENT_ERR_ISSUED_ZERO: u8 = 4;
/// READ-ONLY: the stored outcome byte is not one of the three live tags — a
/// zero-filled or garbage cell. Cannot arise from the writer.
pub const SHEKYL_ARCHIVAL_SETTLEMENT_ERR_UNKNOWN_OUTCOME: u8 = 5;
/// READ-ONLY: the stored outcome is a live tag, but not the one its own counts
/// fold to. Distinct from `UNKNOWN_OUTCOME` because the causes differ — a
/// garbage cell versus counts or a tag that were altered after the fold — and
/// this is a FATAL diagnostic, where "which corruption" is the whole value of
/// the code. Cannot arise from the writer.
pub const SHEKYL_ARCHIVAL_SETTLEMENT_ERR_OUTCOME_DISAGREES: u8 = 6;

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
        Err(shekyl_archival_retention::RowError::IssuedZero) => {
            SHEKYL_ARCHIVAL_SETTLEMENT_ERR_ISSUED_ZERO
        }
        Err(_) => SHEKYL_ARCHIVAL_SETTLEMENT_ERR_MORE_PASSES_THAN_ISSUED,
    }
}

// The row length is a FIXED-SIZE FFI contract, so it is agreed at COMPILE
// time on both sides (rule 40: "Both sides agree on the length at compile
// time"), not queried at run time.
//
// This was `shekyl_archival_settlement_row_len()`, justified as letting C++
// size its buffer from the definition. It did not: the C++ destination is
// `std::array<uint8_t, 3>`, already a compile-time 3, and the export only
// bought a runtime comparison against it — permanent FFI surface for a check
// that fires after the mismatch would already have been compiled in. The
// paired assertions below and `SHEKYL_ARCHIVAL_SETTLEMENT_ROW_BYTES` in
// shekyl_ffi.h fail the BUILD instead, which is what the rule asks for.
const _: () = assert!(SETTLEMENT_ROW_LEN == 3);

/// Validate a stored settlement row: re-fold its counts and confirm the stored
/// outcome is the one they derive (`SettlementRow::decode`).
///
/// The READ half of the invariant. `SO-D1`/`SO-D2` say a settlement whose
/// outcome contradicts its counts — or a zero-issued row — is not a
/// settlement, and the write path already cannot emit one. Without this the
/// read path had no way to ask: `decode` lives in Rust and C++ cannot reach
/// it, so a corrupt cell was handed back as a valid row and the invariant held
/// in one direction only.
///
/// C++ does not parse these bytes to check them (rule 40) — it asks.
///
/// **Three scalars, not a pointer**, and the row's fixed 3-byte width is why
/// that is the smaller boundary rather than a stylistic choice: there is no
/// null case, no length to agree on, and no raw slice reconstruction — the
/// three things a `*const u8` entry would have added. The SA-R-7 boundary
/// ratchet is what surfaced it; the first version took a pointer and grew the
/// raw surface for a value that never needed one. If `SETTLEMENT_ROW_LEN` ever
/// moves, this signature stops compiling, which is the correct failure.
///
/// Returns 0 when the row is canonical, otherwise the same code the writer
/// would have refused it with.
#[no_mangle]
pub extern "C" fn shekyl_archival_settlement_row_validate(
    outcome: u8,
    passes: u8,
    issued: u8,
) -> u8 {
    // Every arm named, no wildcard. The wildcard here was inherited from the
    // WRITER's mapping, and the writer cannot produce two of these failures at
    // all -- so `UnknownOutcome` and `OutcomeDisagrees` were both reported as
    // code 2, whose published contract is `passes > issued`. A `(Missed, 3, 3)`
    // row is outcome corruption and was announced as a count desync: the code
    // named a cause that was not the cause, on the one path whose entire job is
    // to say what went wrong.
    use shekyl_archival_retention::RowError;
    match shekyl_archival_retention::SettlementRow::decode(&[outcome, passes, issued]) {
        Ok(_) => 0,
        Err(RowError::IssuedZero) => SHEKYL_ARCHIVAL_SETTLEMENT_ERR_ISSUED_ZERO,
        Err(RowError::IssuedOutOfRange { .. }) => SHEKYL_ARCHIVAL_SETTLEMENT_ERR_ISSUED_RANGE,
        Err(RowError::UnknownOutcome { .. }) => SHEKYL_ARCHIVAL_SETTLEMENT_ERR_UNKNOWN_OUTCOME,
        Err(RowError::OutcomeDisagrees { .. }) => SHEKYL_ARCHIVAL_SETTLEMENT_ERR_OUTCOME_DISAGREES,
        Err(RowError::Settle(_)) => SHEKYL_ARCHIVAL_SETTLEMENT_ERR_MORE_PASSES_THAN_ISSUED,
        // Unreachable from three scalars, and named rather than swept into a
        // wildcard so that adding a RowError variant fails to compile here
        // instead of silently landing on someone else's code.
        Err(RowError::BadLength { .. }) => SHEKYL_ARCHIVAL_SETTLEMENT_ERR_NULL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_archival_retention::{OUTCOME_MISSED, OUTCOME_NON_OBSERVATION, OUTCOME_SERVED};

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
    fn a_corrupt_row_is_refused_on_read() {
        // The write path cannot emit these; the read path must still refuse
        // them, or the invariant holds in one direction only.
        assert_eq!(
            shekyl_archival_settlement_row_validate(OUTCOME_NON_OBSERVATION, 0, 0),
            SHEKYL_ARCHIVAL_SETTLEMENT_ERR_ISSUED_ZERO
        );

        // Outcome disagreeing with its counts: 3 of 3 passes is Served, not
        // Missed. Asserted on the SPECIFIC code, not just non-zero: this used
        // to report ERR_MORE_PASSES_THAN_ISSUED, which names a cause that is
        // not the cause, and a non-zero assertion would have passed over it.
        assert_eq!(
            shekyl_archival_settlement_row_validate(OUTCOME_MISSED, 3, 3),
            SHEKYL_ARCHIVAL_SETTLEMENT_ERR_OUTCOME_DISAGREES,
            "a row whose outcome contradicts its counts must say so, not report a count desync"
        );

        // An unknown tag — the zero-filled cell — is its own cause.
        assert_eq!(
            shekyl_archival_settlement_row_validate(0x00, 0, 0),
            SHEKYL_ARCHIVAL_SETTLEMENT_ERR_UNKNOWN_OUTCOME
        );

        // And the count desync the code-2 contract actually names.
        assert_eq!(
            shekyl_archival_settlement_row_validate(OUTCOME_SERVED, 3, 2),
            SHEKYL_ARCHIVAL_SETTLEMENT_ERR_MORE_PASSES_THAN_ISSUED
        );

        assert_eq!(
            shekyl_archival_settlement_row_validate(OUTCOME_SERVED, 2, 3),
            0
        );
    }
}
