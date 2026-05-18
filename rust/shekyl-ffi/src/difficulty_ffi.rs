// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FFI surface for the Shekyl LWMA-1 difficulty-adjustment algorithm.
//!
//! Single export: [`shekyl_difficulty_lwma1_next`] wraps
//! [`shekyl_difficulty::lwma1_next`] in a C-compatible ABI. The
//! algorithm itself stays in [`shekyl_difficulty`] (the `#![no_std]`
//! `#![deny(unsafe_code)]` crate that holds the LWMA-1 logic); this
//! module is the `unsafe` boundary that translates raw pointers and
//! decomposed `u128` halves into the safe-Rust slice/`u128` API per
//! `docs/design/DAA_LWMA1.md` §6.1.
//!
//! # `ShekylU128` ABI
//!
//! Rust `u128`'s C ABI was target-dependent until rustc 1.77 and
//! remains a footgun on uncommon targets. Per `DAA_LWMA1.md` §6.1
//! (Round 5 disposition) we decompose into two `u64` halves with
//! universally stable C ABI:
//!
//! ```text
//! #[repr(C)]
//! struct ShekylU128 { lo: u64, hi: u64 }
//! ```
//!
//! Field semantics: little-endian — `lo` is bits 0..64, `hi` is
//! bits 64..128. C++ callers with a native `uint128_t`-typed buffer
//! must explicitly construct `shekyl_u128` instances at the call
//! site (`{ .lo = (uint64_t)v, .hi = (uint64_t)(v >> 64) }`) and
//! decompose returned values symmetrically. The field-meaning is
//! the contract; reinterpret-casting a `uint128_t` to `shekyl_u128`
//! relies on target-defined struct-layout ABI which Round 5
//! explicitly rejects.
//!
//! # Panic safety
//!
//! The workspace runs `panic = "abort"` in both `dev` and `release`
//! profiles (rust/Cargo.toml). Under `panic = "abort"`, panics
//! terminate the process immediately rather than unwinding;
//! `std::panic::catch_unwind` is therefore a no-op in this workspace
//! and is not wrapped around the algorithm call. The safety
//! property under abort is: an uncaught panic cannot corrupt
//! cross-FFI state because the process is already gone. The Rust
//! algorithm body is panic-free by construction — it returns a
//! `Result<u128, Error>` for every error path that the spec
//! recognises (per `shekyl_difficulty::Error`) and uses `u128`
//! arithmetic with explicit `checked_*` / `try_from` overflow
//! guards; the §8.1 vector corpus and the §8.2 cross-check exercise
//! both branches. If a panic ever did fire (workspace-level
//! arithmetic-overflow tripwire or a defensive `unreachable!()`
//! the algorithm doesn't currently use), the abort is the correct
//! response.
//!
//! This deviates from the `catch_unwind` prescription drafted in an
//! earlier round of `DAA_LWMA1_PLAN.md` Phase 3; the deviation is
//! noted in the plan's Phase 2/3-absorption update.
//!
//! # Error taxonomy
//!
//! The FFI returns an `i32` status code, wire-stable:
//!
//! | Code | Constant                                  | Meaning                                                       |
//! |-----:|:------------------------------------------|:--------------------------------------------------------------|
//! |  `0` | [`SHEKYL_DIFFICULTY_OK`]                  | Success; `*out_next_difficulty` is written.                   |
//! | `-1` | [`SHEKYL_DIFFICULTY_ERR_NULL_PTR`]        | A required pointer was null (see per-arg rules below).        |
//! | `-2` | [`SHEKYL_DIFFICULTY_ERR_INVALID_COUNT`]   | `count` disagrees with `chain_height` per §5.3 step 1.        |
//! | `-3` | [`SHEKYL_DIFFICULTY_ERR_OVERFLOW`]        | Consensus invariant violation or `u128` arithmetic overflow.  |
//! | `-4` | [`SHEKYL_DIFFICULTY_ERR_INTERNAL`]        | Reserved; not currently returned (panic=abort short-circuits).|
//!
//! # Null-pointer convention
//!
//! `out_next_difficulty` must always be non-null. `timestamps` and
//! `cum_difficulties` may be null when `count == 0` (the genesis
//! short-circuit case where `chain_height < N`); the FFI synthesises
//! empty slices for that path. When `count > 0` both input pointers
//! must be non-null.

use core::slice;

use shekyl_difficulty::{lwma1_next, Error as DifficultyError};

/// Difficulty target at the C-ABI boundary.
///
/// Decomposes Rust `u128` into two `u64` halves with universally
/// stable C ABI. Little-endian: `lo` is bits 0..64, `hi` is bits
/// 64..128. See module docs for the round-5 ABI rationale.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShekylU128 {
    /// Lower 64 bits.
    pub lo: u64,
    /// Upper 64 bits.
    pub hi: u64,
}

impl From<u128> for ShekylU128 {
    fn from(v: u128) -> Self {
        Self {
            lo: v as u64,
            hi: (v >> 64) as u64,
        }
    }
}

impl From<ShekylU128> for u128 {
    fn from(v: ShekylU128) -> u128 {
        (u128::from(v.hi) << 64) | u128::from(v.lo)
    }
}

/// Success status code returned by [`shekyl_difficulty_lwma1_next`].
pub const SHEKYL_DIFFICULTY_OK: i32 = 0;
/// A required FFI pointer was null. See module docs for the null-pointer
/// convention (`out_next_difficulty` mandatory; input pointers mandatory
/// when `count > 0`).
pub const SHEKYL_DIFFICULTY_ERR_NULL_PTR: i32 = -1;
/// `count` disagrees with `chain_height` per `DAA_LWMA1.md` §5.3 step 1
/// (must equal `N + 1` when `chain_height >= N`).
pub const SHEKYL_DIFFICULTY_ERR_INVALID_COUNT: i32 = -2;
/// Consensus invariant violation (non-monotonic cumulative difficulty)
/// or `u128` arithmetic overflow inside `lwma1_next`.
pub const SHEKYL_DIFFICULTY_ERR_OVERFLOW: i32 = -3;
/// Reserved for unexpected internal failure. Not currently returned;
/// the workspace `panic = "abort"` strategy short-circuits any path
/// that would otherwise need it. See module docs.
pub const SHEKYL_DIFFICULTY_ERR_INTERNAL: i32 = -4;

/// Compute the next LWMA-1 difficulty target.
///
/// # Arguments
///
/// - `timestamps` — pointer to a `[u64; count]` buffer of block
///   timestamps, ordered oldest-first. Must be non-null when
///   `count > 0`; may be null when `count == 0`.
/// - `cum_difficulties` — pointer to a `[ShekylU128; count]` buffer
///   of cumulative difficulties at the same heights as `timestamps`,
///   monotonically non-decreasing. Must be non-null when `count > 0`;
///   may be null when `count == 0`.
/// - `count` — number of entries in `timestamps` and
///   `cum_difficulties`. Must equal `N + 1` (currently 91) when
///   `chain_height >= N`; must equal 0 when `chain_height < N`.
/// - `chain_height` — height of the block whose difficulty target
///   is being computed.
/// - `out_next_difficulty` — pointer to a single `ShekylU128`
///   that receives the next difficulty target on success.
///
/// # Return
///
/// `0` on success (and `*out_next_difficulty` is written), or a
/// negative error code per the constants above.
///
/// # Safety
///
/// The caller must uphold:
/// - When `count > 0`, `timestamps` and `cum_difficulties` point to
///   `count` valid, aligned, initialized values of their respective
///   element types.
/// - `out_next_difficulty` points to a valid, aligned `ShekylU128`
///   slot writable by this function.
/// - The buffers and the out-pointer do not alias each other.
/// - No other thread mutates the buffers for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn shekyl_difficulty_lwma1_next(
    timestamps: *const u64,
    cum_difficulties: *const ShekylU128,
    count: usize,
    chain_height: u64,
    out_next_difficulty: *mut ShekylU128,
) -> i32 {
    if out_next_difficulty.is_null() {
        return SHEKYL_DIFFICULTY_ERR_NULL_PTR;
    }
    if count > 0 && (timestamps.is_null() || cum_difficulties.is_null()) {
        return SHEKYL_DIFFICULTY_ERR_NULL_PTR;
    }

    let (ts, cd_ffi): (&[u64], &[ShekylU128]) = if count == 0 {
        (&[], &[])
    } else {
        // SAFETY: pointers are non-null and the caller's contract
        // guarantees `count` valid, aligned, initialized elements.
        (
            slice::from_raw_parts(timestamps, count),
            slice::from_raw_parts(cum_difficulties, count),
        )
    };

    // Decompose the ShekylU128 inputs into native u128 for the
    // algorithm. Allocation is acceptable here (orchestrator-side
    // FFI shim with `std`); shekyl-difficulty itself remains
    // no_std.
    let cd: Vec<u128> = cd_ffi.iter().copied().map(u128::from).collect();

    match lwma1_next(chain_height, ts, &cd) {
        Ok(next) => {
            // SAFETY: out_next_difficulty is non-null per the check
            // above; the caller's contract guarantees alignment and
            // writability.
            core::ptr::write(out_next_difficulty, ShekylU128::from(next));
            SHEKYL_DIFFICULTY_OK
        }
        Err(DifficultyError::InvalidCount) => SHEKYL_DIFFICULTY_ERR_INVALID_COUNT,
        Err(DifficultyError::Overflow) => SHEKYL_DIFFICULTY_ERR_OVERFLOW,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shekyl_u128_round_trip() {
        for v in [
            0u128,
            1,
            u128::MAX,
            (1u128 << 64) - 1,
            1u128 << 64,
            (1u128 << 64) + 1,
            0x0123_4567_89ab_cdef_fedc_ba98_7654_3210,
        ] {
            let abi = ShekylU128::from(v);
            assert_eq!(abi.lo, v as u64, "low half of {v:#x}");
            assert_eq!(abi.hi, (v >> 64) as u64, "high half of {v:#x}");
            let back: u128 = abi.into();
            assert_eq!(back, v, "round-trip of {v:#x}");
        }
    }

    #[test]
    fn genesis_short_circuit_via_ffi() {
        // chain_height < N must succeed with empty buffers.
        let mut out = ShekylU128 { lo: 0, hi: 0 };
        // SAFETY: count == 0 so the null buffers are legal per the
        // module's null-pointer convention; out is a valid stack
        // slot.
        let rc = unsafe {
            shekyl_difficulty_lwma1_next(core::ptr::null(), core::ptr::null(), 0, 0, &raw mut out)
        };
        assert_eq!(rc, SHEKYL_DIFFICULTY_OK);
        let value: u128 = out.into();
        assert_eq!(value, shekyl_difficulty::GENESIS_DIFFICULTY);
    }

    #[test]
    fn null_out_pointer_rejected() {
        // SAFETY: out_next_difficulty is null, which the FFI explicitly
        // rejects with ERR_NULL_PTR before dereferencing.
        let rc = unsafe {
            shekyl_difficulty_lwma1_next(
                core::ptr::null(),
                core::ptr::null(),
                0,
                0,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(rc, SHEKYL_DIFFICULTY_ERR_NULL_PTR);
    }

    #[test]
    fn null_input_with_nonzero_count_rejected() {
        let mut out = ShekylU128 { lo: 0, hi: 0 };
        // SAFETY: out is a valid stack slot; the null input pointers
        // with count > 0 are rejected before any dereference.
        let rc = unsafe {
            shekyl_difficulty_lwma1_next(core::ptr::null(), core::ptr::null(), 91, 90, &raw mut out)
        };
        assert_eq!(rc, SHEKYL_DIFFICULTY_ERR_NULL_PTR);
    }

    #[test]
    fn invalid_count_returns_minus_two() {
        let mut out = ShekylU128 { lo: 0, hi: 0 };
        let ts: [u64; 1] = [0];
        let cd: [ShekylU128; 1] = [ShekylU128 { lo: 1, hi: 0 }];
        // chain_height = 90 (>= N) but count = 1 (!= N + 1) is the
        // ERR_INVALID_COUNT path per §5.3 step 1.
        // SAFETY: pointers are valid and the buffers are correctly
        // sized for count = 1.
        let rc =
            unsafe { shekyl_difficulty_lwma1_next(ts.as_ptr(), cd.as_ptr(), 1, 90, &raw mut out) };
        assert_eq!(rc, SHEKYL_DIFFICULTY_ERR_INVALID_COUNT);
    }
}
