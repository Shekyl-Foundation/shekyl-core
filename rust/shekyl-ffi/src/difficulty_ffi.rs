// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FFI surface for the Shekyl difficulty crate.
//!
//! Two exports, both thin `unsafe` boundaries over the `#![no_std]`
//! `#![deny(unsafe_code)]` [`shekyl_difficulty`] crate:
//!
//! - [`shekyl_difficulty_lwma1_next`] wraps
//!   [`shekyl_difficulty::lwma1_next`] (the LWMA-1 difficulty-adjustment
//!   algorithm) per `docs/completed/DAA_LWMA1.md` §6.1.
//! - [`shekyl_difficulty_check_hash`] wraps
//!   [`shekyl_difficulty::check_hash`] (the PoW-target predicate ported
//!   from the inherited C++ `cryptonote::check_hash` family).
//!
//! Both translate raw pointers and the decomposed `ShekylU128` `u128`
//! ABI into the safe-Rust slice/`u128` API.
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
//!
//! # Performance / allocation
//!
//! Each call allocates one `Vec<u128>` of length `count`
//! (`count == N + 1 == 91` in the production path) to widen the
//! `[ShekylU128]` input into a `[u128]` for [`shekyl_difficulty::lwma1_next`].
//! Transmuting `&[ShekylU128]` directly to `&[u128]` is not safe:
//! `ShekylU128` is `#[repr(C)]` with two-`u64` layout (alignment 8
//! on x86_64), while Rust `u128` has alignment 16; the
//! reinterpret-cast is exactly the layout-coupling Round 5 rejected
//! when it chose the `ShekylU128` ABI in the first place.
//!
//! At 91 elements × 16 bytes the allocation is ~1.5 KiB per call,
//! satisfied from the system allocator's small-object freelist in
//! the nanosecond range. The cost is dominated by the algorithm's
//! own 90-iteration weighted-sum loop, not the allocation. Phase 4
//! (C++ daemon cutover, per `DAA_LWMA1_PLAN.md`) calls this once
//! per block validation; at the production block target
//! (`T = 120s`) the allocation is amortized to negligible. A
//! stack-buffer alternative (`heapless::Vec<u128, N_PLUS_ONE>` or a
//! signature change accepting `&[u128]` directly) is tracked as a
//! V3.1+ FOLLOWUPS item rather than landed here, per the
//! Phase 2 scope discipline.

use core::slice;

use shekyl_difficulty::{check_hash, check_timestamp_rule, lwma1_next, Error as DifficultyError};

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
        // Deliberate lo/hi split of the u128: both halves are kept, so the
        // truncating cast is value-preserving by construction.
        #[allow(clippy::cast_possible_truncation)]
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

    // Widen ShekylU128 (two-u64, align 8) to u128 (align 16) for
    // the algorithm. The materialized Vec is unavoidable here:
    // reinterpret-casting the input slice violates the alignment
    // contract Round 5's ABI was designed to insulate from
    // (see module docs § "ShekylU128 ABI", § "Performance /
    // allocation"). shekyl-difficulty remains `#![no_std]`;
    // the `Vec` is on the `std`-having FFI side.
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

/// PoW-target predicate: does `hash` satisfy `difficulty`?
///
/// Wraps [`shekyl_difficulty::check_hash`] — passes iff the 32-byte
/// `hash`, read as a 256-bit little-endian integer, satisfies
/// `hash * difficulty < 2^256`. This is the unified port of the
/// inherited C++ `cryptonote::check_hash`/`_64`/`_128` family; the
/// `_64`/`_128` split was a speed optimization and the boolean is
/// identical on both paths (proven over the differential corpus in
/// `shekyl-difficulty`).
///
/// # Arguments
///
/// - `hash_ptr` — pointer to exactly 32 bytes (little-endian PoW hash).
///   Typed `*const [u8; 32]` (C `const uint8_t (*)[32]`) so the fixed
///   length is part of the ABI, not a caller convention. Must be non-null.
/// - `difficulty` — the 128-bit difficulty as a [`ShekylU128`]
///   (constructed at the C++ call site as `{lo, hi}`; never
///   reinterpret-cast from a native `uint128_t` — see module docs).
///   `difficulty == 0` always passes (matching the inherited C++
///   behaviour; not an error).
/// - `out_pass` — pointer to a single `bool` that receives the
///   predicate result on success. Must be non-null.
///
/// # Return
///
/// [`SHEKYL_DIFFICULTY_OK`] (`0`) on success (and `*out_pass` is
/// written), or [`SHEKYL_DIFFICULTY_ERR_NULL_PTR`] (`-1`) if
/// `hash_ptr` or `out_pass` is null (in which case `*out_pass` is
/// untouched).
///
/// # Safety
///
/// The caller must uphold:
/// - `hash_ptr` points to a valid, aligned, initialized `[u8; 32]`.
/// - `out_pass` points to a valid, aligned `bool` slot writable by
///   this function.
/// - The hash buffer and the out-pointer do not alias.
/// - No other thread mutates the hash buffer for the duration of the
///   call.
#[no_mangle]
pub unsafe extern "C" fn shekyl_difficulty_check_hash(
    hash_ptr: *const [u8; 32],
    difficulty: ShekylU128,
    out_pass: *mut bool,
) -> i32 {
    if hash_ptr.is_null() || out_pass.is_null() {
        return SHEKYL_DIFFICULTY_ERR_NULL_PTR;
    }

    // SAFETY: hash_ptr is non-null and the caller's contract guarantees
    // an aligned, initialized [u8; 32].
    let hash = &*hash_ptr;

    let pass = check_hash(hash, u128::from(difficulty));

    // SAFETY: out_pass is non-null per the check above; the caller's
    // contract guarantees alignment and writability.
    core::ptr::write(out_pass, pass);
    SHEKYL_DIFFICULTY_OK
}

/// Verdict codes for [`shekyl_difficulty_check_timestamp_rule`],
/// wire-stable mirrors of [`shekyl_difficulty::TimestampRuleVerdict`]'s
/// discriminants (renumbering is an FFI break):
/// the candidate satisfies both bounds.
pub const SHEKYL_TIMESTAMP_RULE_OK: i32 = 0;
/// The caller handed more than `MTP_WINDOW` (11) timestamps — a caller
/// bug (the newest-11 selection is order-dependent and the caller's job,
/// C2-R3-Q1 sub-a); refused, never silently medianed. `*out_median` is 0.
pub const SHEKYL_TIMESTAMP_RULE_WINDOW_TOO_WIDE: i32 = 1;
/// The candidate exceeds `local_clock + FTL` (saturating arithmetic).
pub const SHEKYL_TIMESTAMP_RULE_ABOVE_FTL: i32 = 2;
/// The candidate is not strictly greater than the window median.
pub const SHEKYL_TIMESTAMP_RULE_NOT_ABOVE_MEDIAN: i32 = 3;
/// A required pointer was null (`out_median`, or `window` with
/// `window_len > 0`).
pub const SHEKYL_TIMESTAMP_RULE_ERR_NULL_PTR: i32 = -1;

/// The C2-R3 block-timestamp consensus rule
/// (`docs/completed/CONSENSUS_C2_R3_TIMESTAMPS.md` §4.3, ratified
/// 2026-09-01; Rust crossing re-ratified same day).
///
/// Wraps [`shekyl_difficulty::check_timestamp_rule`] — the ONE
/// implementation of the ruled sentence: valid iff
/// `candidate_ts <= local_clock + 540` (saturating) AND strictly greater
/// than sorted-index-5 of the 11 timestamps immediately preceding the
/// candidate, the window right-padded with `genesis_ts` when fewer than
/// 11 predecessors exist. The C++ validator's `check_block_timestamp` is
/// a marshaling shim over this entry point (rule 20), exactly as
/// [`shekyl_difficulty_lwma1_next`] above serves the difficulty half.
///
/// # Arguments
///
/// - `candidate_ts` — the candidate block's timestamp.
/// - `window` — pointer to `[u64; window_len]`, the ≤ 11 newest
///   predecessor timestamps in any order (callers with deeper history
///   truncate to the newest 11 first). May be null when
///   `window_len == 0` (the block-1 case: full genesis padding); must be
///   non-null when `window_len > 0`.
/// - `window_len` — entries in `window`. Values above 11 return
///   [`SHEKYL_TIMESTAMP_RULE_WINDOW_TOO_WIDE`].
/// - `genesis_ts` — the timestamp of block 0 (the padding value).
/// - `local_clock` — the validator's wall clock (FTL reference).
/// - `out_median` — receives the padded window's median on every verdict
///   except `WINDOW_TOO_WIDE` (where it receives 0); the miner-template
///   caller reads it unconditionally. Must be non-null.
///
/// # Return
///
/// A verdict code ≥ 0 per the constants above (the rule's answer), or
/// [`SHEKYL_TIMESTAMP_RULE_ERR_NULL_PTR`] on pointer misuse.
///
/// # Safety
///
/// The caller must uphold: when `window_len > 0`, `window` points to
/// `window_len` valid, aligned, initialized `u64`s; `out_median` points
/// to a valid, aligned, writable `u64`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_difficulty_check_timestamp_rule(
    candidate_ts: u64,
    window: *const u64,
    window_len: usize,
    genesis_ts: u64,
    local_clock: u64,
    out_median: *mut u64,
) -> i32 {
    if out_median.is_null() || (window_len > 0 && window.is_null()) {
        return SHEKYL_TIMESTAMP_RULE_ERR_NULL_PTR;
    }

    // Refuse oversized windows BEFORE constructing the slice: the API
    // promises WINDOW_TOO_WIDE for every length above the MTP window, and
    // `from_raw_parts` has a language-level precondition (byte span <=
    // isize::MAX) that a corrupted C length would violate as UB rather
    // than the documented refusal. Same pre-check pattern as
    // archival_ffi/bond.rs. The rule's own width check stays as the
    // semantic owner for native callers; this is the boundary's copy of
    // the guard, not a second rule site.
    if window_len > shekyl_difficulty::MTP_WINDOW_USIZE {
        // SAFETY: out_median is non-null per the check above; the
        // caller's contract guarantees alignment and writability.
        core::ptr::write(out_median, 0);
        return SHEKYL_TIMESTAMP_RULE_WINDOW_TOO_WIDE;
    }

    let win: &[u64] = if window_len == 0 {
        &[]
    } else {
        // SAFETY: non-null per the check above; `window_len <= 11` per
        // the width refusal above, so the caller's contract of
        // `window_len` valid, aligned, initialized elements is within
        // slice-invariant bounds.
        slice::from_raw_parts(window, window_len)
    };

    let (verdict, median) = check_timestamp_rule(candidate_ts, win, genesis_ts, local_clock);
    // SAFETY: out_median is non-null per the check above; the caller's
    // contract guarantees alignment and writability.
    core::ptr::write(out_median, median);
    verdict as i32
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
            // Deliberate: asserting the low half of the split, so the
            // truncating cast is the expected value here.
            #[allow(clippy::cast_possible_truncation)]
            let lo = v as u64;
            assert_eq!(abi.lo, lo, "low half of {v:#x}");
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

    #[test]
    fn check_hash_null_hash_rejected() {
        let mut pass = true;
        // SAFETY: out_pass is a valid stack slot; the null hash pointer
        // is rejected before any dereference.
        let rc = unsafe {
            shekyl_difficulty_check_hash(
                core::ptr::null(),
                ShekylU128 { lo: 1, hi: 0 },
                &raw mut pass,
            )
        };
        assert_eq!(rc, SHEKYL_DIFFICULTY_ERR_NULL_PTR);
    }

    #[test]
    fn check_hash_null_out_rejected() {
        let hash = [0u8; 32];
        // SAFETY: hash points to 32 valid bytes; the null out-pointer is
        // rejected before any write.
        let rc = unsafe {
            shekyl_difficulty_check_hash(
                &raw const hash,
                ShekylU128 { lo: 1, hi: 0 },
                core::ptr::null_mut(),
            )
        };
        assert_eq!(rc, SHEKYL_DIFFICULTY_ERR_NULL_PTR);
    }

    #[test]
    fn check_hash_known_pass() {
        // hash = 1 (LE), difficulty = 1: 1 * 1 = 1 < 2^256 -> pass.
        let mut hash = [0u8; 32];
        hash[0] = 1;
        let mut pass = false;
        // SAFETY: hash points to 32 valid bytes; out_pass is a valid
        // stack slot.
        let rc = unsafe {
            shekyl_difficulty_check_hash(
                &raw const hash,
                ShekylU128 { lo: 1, hi: 0 },
                &raw mut pass,
            )
        };
        assert_eq!(rc, SHEKYL_DIFFICULTY_OK);
        assert!(pass);
    }

    #[test]
    fn check_hash_known_fail() {
        // hash = all-ones (2^256 - 1), difficulty = 2:
        // (2^256 - 1) * 2 >= 2^256 -> fail.
        let hash = [0xffu8; 32];
        let mut pass = true;
        // SAFETY: hash points to 32 valid bytes; out_pass is a valid
        // stack slot.
        let rc = unsafe {
            shekyl_difficulty_check_hash(
                &raw const hash,
                ShekylU128 { lo: 2, hi: 0 },
                &raw mut pass,
            )
        };
        assert_eq!(rc, SHEKYL_DIFFICULTY_OK);
        assert!(!pass);
    }

    #[test]
    fn check_hash_difficulty_zero_passes() {
        // difficulty == 0 always passes (matches inherited C++).
        let hash = [0xffu8; 32];
        let mut pass = false;
        // SAFETY: hash points to 32 valid bytes; out_pass is a valid
        // stack slot.
        let rc = unsafe {
            shekyl_difficulty_check_hash(
                &raw const hash,
                ShekylU128 { lo: 0, hi: 0 },
                &raw mut pass,
            )
        };
        assert_eq!(rc, SHEKYL_DIFFICULTY_OK);
        assert!(pass);
    }

    /// The boundary's width pre-check must fire BEFORE slice
    /// construction: a hostile/corrupted `window_len` (here usize::MAX
    /// against a 2-element buffer) must come back as the documented
    /// WINDOW_TOO_WIDE with `*out_median == 0`. This call is only sound
    /// BECAUSE of the pre-check — the named red edit (removing the
    /// pre-check) turns this test into the very slice-invariant UB the
    /// guard exists to refuse, so a regression is a crash/UB detector
    /// here, not a clean assertion failure.
    #[test]
    fn oversized_window_len_is_refused_before_slice_construction() {
        let tiny = [1u64, 2u64];
        let mut median = 123u64;
        let rc = unsafe {
            shekyl_difficulty_check_timestamp_rule(
                999,
                tiny.as_ptr(),
                usize::MAX,
                0,
                999,
                &raw mut median,
            )
        };
        assert_eq!(rc, SHEKYL_TIMESTAMP_RULE_WINDOW_TOO_WIDE);
        assert_eq!(median, 0);
    }
}
