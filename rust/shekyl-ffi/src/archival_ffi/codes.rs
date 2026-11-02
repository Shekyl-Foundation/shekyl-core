// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared archival FFI verdict codes and the wire-error mapper for the
//! exports that remain after `DEL-008` (`DRS_X_STORE_FLIP.md` §3.5).
//!
//! Domain modules may also define local codes next to their entry points.
//! C++ / `shekyl_ffi.h` mirror the literals (rule 25).

use shekyl_archival_retention::WireError;

/// Success.
pub const SHEKYL_ARCHIVAL_VERIFY_OK: u8 = 0;
/// Required pointer was null.
pub const SHEKYL_ARCHIVAL_VERIFY_ERR_NULL_PTR: u8 = 1;
/// Vin payload failed structural decode.
pub const SHEKYL_ARCHIVAL_VERIFY_ERR_WIRE: u8 = 2;
// Code 6 (`ERR_LEAF_INDEX`) is RETIRED with code 7: the index it compared is
// derived, not transported (RF-D6). Unassigned, not reused.
// Code 7 (`ERR_REGISTRY_RK`) is RETIRED, not reusable: it reported a wire `R_k`
// disagreeing with the registry's, and RF-D6 took `R_k` off the wire. The
// number stays unassigned so an old log line cannot be misread as a new
// condition.

/// Bond-post CT balance sum matches (ARCHIVAL_BOND_GATE4.md §3.2).
pub const SHEKYL_ARCHIVAL_BOND_CT_BALANCE_OK: u8 = 0;
/// Required pointer was null while count > 0.
pub const SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_NULL_PTR: u8 = 1;
/// Both `bond_credit` and `bond_debit` are non-zero.
pub const SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_BOTH_TERMS: u8 = 2;
/// Invalid commitment point, malformed flat buffer (length not a multiple of 32), or
/// `count * 32` overflow / oversize slice in the FFI flatten path.
pub const SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_INVALID_POINT: u8 = 3;
/// Left and right commitment sums differ.
pub const SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_SUM_MISMATCH: u8 = 4;
/// Retired-assigned: zero-money is `BondTerm::Unmoved` (Reinstate), not an
/// error. Number 5 stays so it cannot be reminted.
pub const SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_NO_BOND_TERM: u8 = 5;

pub(super) fn map_wire_error(_err: &WireError) -> u8 {
    SHEKYL_ARCHIVAL_VERIFY_ERR_WIRE
}
