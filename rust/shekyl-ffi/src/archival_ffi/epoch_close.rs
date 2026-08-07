// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Epoch-close, failure-window, prune, and emission-epoch snapshot types.

use super::codes::*;
use shekyl_archival_retention::{
    claim_window_floor, effective_settlement_epoch_blocks, epoch_close_compute,
    epoch_close_due_at_height, failure_window_slashable, good_through, prune_below_epoch_at_height,
    serve_credit_epoch_ok, settlement_epoch_at_height, settlement_epoch_blocks_overridden,
    slash_open_interval_to_append, BadInterval, BaselineObservation, CreditPair, EpochCloseBond,
    EpochCloseInputs, EpochCloseShard, FAILURE_WINDOW_M, FAILURE_WINDOW_N,
    FAILURE_WINDOW_SERVE_BUDGET, MAX_CLAIM_AGE_W,
};
/// Returns `1` when `settlement_epoch >= join_settlement_epoch + 1` (gate-4 §2.2 `E_first` lower bound).
#[no_mangle]
pub extern "C" fn shekyl_archival_serve_credit_epoch_ok(
    settlement_epoch: u64,
    join_settlement_epoch: u64,
) -> u8 {
    u8::from(serve_credit_epoch_ok(
        settlement_epoch,
        join_settlement_epoch,
    ))
}

/// [`shekyl_archival_slash_open_interval_to_append`]: no append — an open
/// interval already exists (the same-epoch sibling coalesces).
pub const SHEKYL_ARCHIVAL_SLASH_INTERVAL_COALESCE: u8 = 0;
/// [`shekyl_archival_slash_open_interval_to_append`]: append the out-params'
/// open interval.
pub const SHEKYL_ARCHIVAL_SLASH_INTERVAL_APPEND: u8 = 1;
/// [`shekyl_archival_slash_open_interval_to_append`]: marshal error (null
/// pointer with nonzero length, pair-count overflow, or null out-pointer) —
/// the C++ slash writer maps this to a FATAL abort, never a skip.
pub const SHEKYL_ARCHIVAL_SLASH_INTERVAL_ERR_MARSHAL: u8 = 2;

/// Same-epoch slash-coalescing decision (P2B-9 Pin 5;
/// `shekyl-archival-retention::bond_connect::slash_open_interval_to_append`):
/// returns [`SHEKYL_ARCHIVAL_SLASH_INTERVAL_APPEND`] and writes the open
/// interval `[settlement_epoch, u64::MAX)` when the record carries no open bad
/// interval, or [`SHEKYL_ARCHIVAL_SLASH_INTERVAL_COALESCE`] (no write) when one
/// exists. The decision AND the interval shape are consensus semantics — the
/// C++ slash writer appends exactly what this returns, deciding nothing.
///
/// `bad_intervals_ptr` is `2 × bad_intervals_len` `u64`s — flattened
/// `(start_epoch, end_exclusive)` pairs (the `shekyl_archival_good_through`
/// layout).
///
/// # Safety
/// When `bad_intervals_len > 0`, `bad_intervals_ptr` must address
/// `2 × bad_intervals_len` valid `u64`s; the out-pointers must be valid for
/// writes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_slash_open_interval_to_append(
    bad_intervals_ptr: *const u64,
    bad_intervals_len: usize,
    settlement_epoch: u64,
    interval_start_out: *mut u64,
    interval_end_out: *mut u64,
) -> u8 {
    if interval_start_out.is_null() || interval_end_out.is_null() {
        return SHEKYL_ARCHIVAL_SLASH_INTERVAL_ERR_MARSHAL;
    }
    let Some(bad) = (unsafe { gather_bad_intervals(bad_intervals_ptr, bad_intervals_len) }) else {
        return SHEKYL_ARCHIVAL_SLASH_INTERVAL_ERR_MARSHAL;
    };
    match slash_open_interval_to_append(&bad, settlement_epoch) {
        Some(iv) => {
            unsafe {
                *interval_start_out = iv.start_epoch;
                *interval_end_out = iv.end_exclusive;
            }
            SHEKYL_ARCHIVAL_SLASH_INTERVAL_APPEND
        }
        None => SHEKYL_ARCHIVAL_SLASH_INTERVAL_COALESCE,
    }
}

/// [`shekyl_archival_failure_window_slashable`]: the window absorbs this miss —
/// fewer than `m` of the last `n` baseline observations were missed, so the
/// slash does NOT fire (pin §1 "an isolated transient miss does not slash").
pub const SHEKYL_ARCHIVAL_FAILURE_WINDOW_ABSORB: u8 = 0;
/// [`shekyl_archival_failure_window_slashable`]: `m` of the last `n`
/// observations were missed — a confirmed durable absence; proceed to the
/// gate-4 §4.2 slash.
pub const SHEKYL_ARCHIVAL_FAILURE_WINDOW_SLASH: u8 = 1;
/// [`shekyl_archival_failure_window_slashable`] /
/// [`shekyl_archival_failure_window_params`]: marshal error (null pointer, an
/// empty window (`observations_len == 0`), a window longer than `n`,
/// non-descending epochs, or a passed head). The C++ slash scan maps this to a
/// FATAL abort, never a skip in either direction — deciding a slash over a
/// malformed window would be a consensus divergence.
pub const SHEKYL_ARCHIVAL_FAILURE_WINDOW_ERR_MARSHAL: u8 = 2;

/// Sliding-window failure-confirmation parameters
/// (`ARCHIVAL_FAILURE_CONFIRMATION_PIN.md` §1), read from the one authority
/// (`config/consensus_constants.json` → `shekyl-archival-retention`).
///
/// The C++ slash scan reads them here rather than from a generated header
/// constant so there is no cross-language drift pair to keep aligned: `m` and
/// `n` exist in exactly one place, and C++ holds no second copy. The Round-2
/// re-pin itself still touches two sites by design — the JSON value plus the
/// Round-1 sentinel const-assert in
/// [`shekyl_archival_retention::failure_window`] that pins the shipped pair
/// (the `bond_floor` idiom, so a genesis-sensitive numerics change cannot
/// happen incidentally).
///
/// - `m_out` — misses required inside the window to slash.
/// - `n_out` — baseline observations the miss count is taken over; the caller's
///   look-back stops after gathering this many.
/// - `serve_budget_out` — passed observations the window tolerates before `m`
///   becomes unreachable (`n − m`). Once the caller has seen more than this many
///   passes it can stop reading LMDB: the verdict is already
///   [`SHEKYL_ARCHIVAL_FAILURE_WINDOW_ABSORB`]. Computed here so the arithmetic
///   stays Rust-side (`20-rust-vs-cpp-policy`).
///
/// # Safety
/// All three out-pointers must be valid for writes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_failure_window_params(
    m_out: *mut u32,
    n_out: *mut u32,
    serve_budget_out: *mut u32,
) -> u8 {
    if m_out.is_null() || n_out.is_null() || serve_budget_out.is_null() {
        return SHEKYL_ARCHIVAL_FAILURE_WINDOW_ERR_MARSHAL;
    }
    unsafe {
        *m_out = FAILURE_WINDOW_M;
        *n_out = FAILURE_WINDOW_N;
        *serve_budget_out = FAILURE_WINDOW_SERVE_BUDGET;
    }
    SHEKYL_ARCHIVAL_FAILURE_WINDOW_ABSORB
}

/// Sliding-window **m-of-n** failure confirmation
/// (`shekyl-archival-retention::failure_window::failure_window_slashable`;
/// `ARCHIVAL_FAILURE_CONFIRMATION_PIN.md` §1) — is this observation sequence a
/// *slashable* failure, or a transient the window absorbs?
///
/// This is the decision gate-2 §6's `challenge_failed(P, s, E)` now feeds: a
/// single missed baseline is no longer a slash. The interval the slash appends
/// is unchanged ([`shekyl_archival_slash_open_interval_to_append`]); only
/// whether it fires is decided here.
///
/// The caller supplies the trailing window for one `(P_id, shard)` pair as two
/// parallel arrays of `observations_len` entries, **most recent first**:
///
/// - `observation_epochs_ptr` — the settlement epoch of each baseline
///   observation, strictly descending. Head is the decision epoch.
/// - `observation_served_ptr` — `0` iff that epoch's `serve_credit_bit` is
///   unset (the miss the window counts); any nonzero value is a pass.
///
/// Only epochs at which a challenge was actually posed belong in the arrays —
/// bonded-but-untested epochs are not observations and must not appear (the
/// pin §3.1 Round-2 concern, on the enforcement side). Gathering stops at the
/// boundary of the pair's current continuous challengeable run, so a shorter
/// window is normal (a young or freshly-reinstated pair) and is evaluated
/// as-is. An empty window (`observations_len == 0`) is rejected as
/// [`SHEKYL_ARCHIVAL_FAILURE_WINDOW_ERR_MARSHAL`]: the decision epoch is always
/// the head, so a well-formed gather never produces one.
///
/// Returns [`SHEKYL_ARCHIVAL_FAILURE_WINDOW_SLASH`],
/// [`SHEKYL_ARCHIVAL_FAILURE_WINDOW_ABSORB`], or
/// [`SHEKYL_ARCHIVAL_FAILURE_WINDOW_ERR_MARSHAL`].
///
/// # Safety
/// When `observations_len > 0`, both pointers must address `observations_len`
/// valid elements of their respective types for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_failure_window_slashable(
    observation_epochs_ptr: *const u64,
    observation_served_ptr: *const u8,
    observations_len: usize,
) -> u8 {
    if observations_len == 0 {
        return SHEKYL_ARCHIVAL_FAILURE_WINDOW_ERR_MARSHAL;
    }
    if observation_epochs_ptr.is_null() || observation_served_ptr.is_null() {
        return SHEKYL_ARCHIVAL_FAILURE_WINDOW_ERR_MARSHAL;
    }
    let epochs = unsafe { std::slice::from_raw_parts(observation_epochs_ptr, observations_len) };
    let served = unsafe { std::slice::from_raw_parts(observation_served_ptr, observations_len) };
    let observations: Vec<BaselineObservation> = epochs
        .iter()
        .zip(served.iter())
        .map(|(&settlement_epoch, &served)| BaselineObservation {
            settlement_epoch,
            served: served != 0,
        })
        .collect();
    match failure_window_slashable(&observations) {
        Ok(true) => SHEKYL_ARCHIVAL_FAILURE_WINDOW_SLASH,
        Ok(false) => SHEKYL_ARCHIVAL_FAILURE_WINDOW_ABSORB,
        Err(_) => SHEKYL_ARCHIVAL_FAILURE_WINDOW_ERR_MARSHAL,
    }
}

/// `good_through(P, E)` from bond fields (ARCHIVAL_CONSENSUS_STATE.md §3.4 interval semantics).
///
/// `bad_intervals_ptr` is `2 × bad_intervals_len` `u64` values — flattened
/// `(start_epoch, end_exclusive)` pairs. The buffer is typed (`*const u64`),
/// so no byte-order applies; callers pass in-memory `u64`s, not serialized
/// bytes. Returns `0` (fail-closed) on a null pointer with nonzero length or
/// on pair-count overflow.
///
/// # Safety
///
/// When `bad_intervals_len > 0`, `bad_intervals_ptr` must address
/// `2 × bad_intervals_len` valid `u64`s for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_good_through(
    join_settlement_epoch: u64,
    settlement_epoch: u64,
    bad_intervals_ptr: *const u64,
    bad_intervals_len: usize,
) -> u8 {
    let Some(bad) = (unsafe { gather_bad_intervals(bad_intervals_ptr, bad_intervals_len) }) else {
        return 0;
    };
    u8::from(good_through(join_settlement_epoch, settlement_epoch, &bad))
}

/// Settlement epoch containing `block_height` (bond-connect join epoch derivation).
#[no_mangle]
pub extern "C" fn shekyl_archival_settlement_epoch_at_height(block_height: u64) -> u64 {
    settlement_epoch_at_height(block_height)
}

/// The effective settlement-epoch length in blocks (the genesis-pinned
/// 10 000, or the clamped `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` override —
/// the fakechain-only regtest lever). Single source for C++ consumers
/// needing the length itself; the schedule functions above already
/// consume it internally.
#[no_mangle]
pub extern "C" fn shekyl_archival_settlement_epoch_blocks() -> u64 {
    effective_settlement_epoch_blocks()
}

/// True iff a `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` override is active (the
/// effective schedule differs from the genesis default — which requires
/// this process to have **armed** via
/// [`shekyl_archival_settlement_epoch_arm_regtest`]). Drives the daemon's
/// loud fakechain warning.
#[no_mangle]
pub extern "C" fn shekyl_archival_settlement_epoch_overridden() -> bool {
    settlement_epoch_blocks_overridden()
}

/// True iff `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` is present in the process
/// environment at all (no validation, no schedule latch). Drives the
/// daemon's fail-closed public-network refusal: the settlement-epoch
/// schedule is consensus, and on a non-FAKECHAIN net the *presence* of the
/// lever is the operator error to refuse on (`Blockchain::init`, next to
/// the `SEEDHASH_EPOCH_*` gate) — before any question of the value's
/// validity.
#[no_mangle]
pub extern "C" fn shekyl_archival_settlement_epoch_override_present() -> bool {
    shekyl_archival_retention::settlement_epoch_override_present()
}

/// Arm the `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` override for the daemon's
/// FAKECHAIN startup path, latching the validated override (or the genesis
/// pin when the variable is unset). An unarmed process ignores the lever
/// entirely, so arming is the single gate a regtest schedule passes
/// through.
///
/// Returns a **cause code**, not a bool: the two refusals need different
/// remedies and sending an operator after the wrong one costs real
/// debugging time (a levered daemon dying on
/// [`SHEKYL_ARCHIVAL_SEB_ARM_ERR_TOO_LATE`] is a daemon-side
/// initialization-order defect, never a bad value).
#[no_mangle]
pub extern "C" fn shekyl_archival_settlement_epoch_arm_regtest() -> u8 {
    use shekyl_archival_retention::SettlementEpochOverrideError as E;
    match shekyl_archival_retention::arm_settlement_epoch_override_for_regtest() {
        Ok(_) => SHEKYL_ARCHIVAL_SEB_ARM_OK,
        Err(E::Invalid { .. }) => SHEKYL_ARCHIVAL_SEB_ARM_ERR_INVALID,
        Err(E::ArmedTooLate { .. }) => SHEKYL_ARCHIVAL_SEB_ARM_ERR_TOO_LATE,
    }
}

/// Returns `1` and writes the settlement epoch whose close is processed at
/// `block_height`; `0` (no write) at height 0, non-boundary heights, or null out.
///
/// # Safety
///
/// `out_settlement_epoch` must be a valid writable `u64` pointer or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_epoch_close_due(
    block_height: u64,
    out_settlement_epoch: *mut u64,
) -> u8 {
    if out_settlement_epoch.is_null() {
        return 0;
    }
    match epoch_close_due_at_height(block_height) {
        Some(epoch) => {
            unsafe { *out_settlement_epoch = epoch };
            1
        }
        None => 0,
    }
}

/// The oldest still-claimable settlement epoch for `current_settled_epoch` —
/// a thin delegate to [`claim_window_floor`], the **single source of the
/// claim-window boundary** (`claimed_epochs.rs`). Exposed for the emission
/// claim-source RPC handler so the daemon-side window derivation resolves
/// through the one landed definition rather than an inline `settled − W`
/// copy (`EMISSION_CLAIM_BUILDER.md` §2 step 1's consumption-not-re-derivation
/// pin, applied daemon-side).
#[no_mangle]
pub extern "C" fn shekyl_archival_claim_window_floor(current_settled_epoch: u64) -> u64 {
    claim_window_floor(current_settled_epoch)
}

/// Returns `1` and writes the prune horizon (`tip_epoch − MAX_CLAIM_AGE_W`) when the
/// chain is older than the claim window at `block_height`; `0` (no write) otherwise.
///
/// # Safety
///
/// `out_prune_below_epoch` must be a valid writable `u64` pointer or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_prune_below_epoch(
    block_height: u64,
    out_prune_below_epoch: *mut u64,
) -> u8 {
    if out_prune_below_epoch.is_null() {
        return 0;
    }
    match prune_below_epoch_at_height(block_height, MAX_CLAIM_AGE_W) {
        Some(below) => {
            unsafe { *out_prune_below_epoch = below };
            1
        }
        None => 0,
    }
}

/// Epoch-close computation succeeded.
pub const SHEKYL_ARCHIVAL_EPOCH_CLOSE_OK: u8 = 0;
/// A required pointer was null (or null with nonzero length).
pub const SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_NULL_PTR: u8 = 1;
/// A per-bond interval pair count overflowed `usize`.
pub const SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_LEN_OVERFLOW: u8 = 2;
/// A credit pair referenced a bond/shard index outside the gather arrays.
pub const SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_INDEX_RANGE: u8 = 3;

/// One gathered bond for `shekyl_archival_epoch_close_compute`.
///
/// Layout must match `struct shekyl_archival_epoch_close_bond` in `shekyl_ffi.h`.
///
/// Carries no holdings descriptor (WS-1): the held-and-served set is sourced
/// solely from the serve-credit ledger rows the gather passes as credit
/// pairs, so tip holdings never cross into the work channel.
#[repr(C)]
pub struct ShekylArchivalEpochCloseBond {
    pub join_settlement_epoch: u64,
    /// Flattened `(start_epoch, end_exclusive)` pairs; `2 × bad_intervals_len` u64s.
    pub bad_intervals_ptr: *const u64,
    /// Pair count (not u64 count).
    pub bad_intervals_len: usize,
    pub is_foundation_complete_tree: u8,
}

/// One gathered shard-registry row for `shekyl_archival_epoch_close_compute`.
///
/// Layout must match `struct shekyl_archival_epoch_close_shard` in `shekyl_ffi.h`.
#[repr(C)]
pub struct ShekylArchivalEpochCloseShard {
    pub shard_id: u64,
    pub freeze_height: u64,
    /// `0` when no frozen segment row exists (shard age is then zero).
    pub has_segment: u8,
}

/// One serve-credit row as indices into the bond/shard gather arrays.
///
/// Layout must match `struct shekyl_archival_credit_pair` in `shekyl_ffi.h`.
#[repr(C)]
pub struct ShekylArchivalCreditPair {
    pub bond_idx: usize,
    pub shard_idx: usize,
}

/// Owned decode of the as-of-`E` gather arrays, shared by
/// `shekyl_archival_epoch_close_compute` and
/// `shekyl_archival_emission_epoch_work`. One decoder for both consumers of
/// the frozen gather (WS-1 single sourcing, `REWARD_EMISSION_E3_GATING_ROUND.md`
/// §5.5): close and verify cannot diverge on marshaling semantics because
/// there is only one marshaling path to diverge from.
pub(super) struct DecodedEpochRows {
    pub(super) joins: Vec<u64>,
    pub(super) completes: Vec<bool>,
    pub(super) bad: Vec<Vec<BadInterval>>,
    pub(super) shards: Vec<EpochCloseShard>,
    pub(super) pairs: Vec<CreditPair>,
}

impl DecodedEpochRows {
    pub(super) fn bonds(&self) -> Vec<EpochCloseBond<'_>> {
        self.joins
            .iter()
            .zip(&self.completes)
            .zip(&self.bad)
            .map(|((&join, &complete), bad)| EpochCloseBond {
                join_settlement_epoch: join,
                is_foundation_complete_tree: complete,
                bad_intervals: bad,
            })
            .collect()
    }
}

/// # Safety
///
/// Pointers must satisfy their stated lengths for the duration of the call,
/// including each bond's interval buffer per its embedded lengths.
pub(super) unsafe fn decode_epoch_rows(
    bonds_ptr: *const ShekylArchivalEpochCloseBond,
    bonds_len: usize,
    shards_ptr: *const ShekylArchivalEpochCloseShard,
    shards_len: usize,
    credit_pairs_ptr: *const ShekylArchivalCreditPair,
    credit_pairs_len: usize,
) -> Result<DecodedEpochRows, u8> {
    if (bonds_ptr.is_null() && bonds_len > 0)
        || (shards_ptr.is_null() && shards_len > 0)
        || (credit_pairs_ptr.is_null() && credit_pairs_len > 0)
    {
        return Err(SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_NULL_PTR);
    }

    let raw_bonds: &[ShekylArchivalEpochCloseBond] = if bonds_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(bonds_ptr, bonds_len) }
    };
    let raw_shards: &[ShekylArchivalEpochCloseShard] = if shards_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(shards_ptr, shards_len) }
    };
    let raw_pairs: &[ShekylArchivalCreditPair] = if credit_pairs_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(credit_pairs_ptr, credit_pairs_len) }
    };

    let mut joins = Vec::with_capacity(raw_bonds.len());
    let mut completes = Vec::with_capacity(raw_bonds.len());
    let mut bad = Vec::with_capacity(raw_bonds.len());
    for bond in raw_bonds {
        let Some(intervals) =
            (unsafe { gather_bad_intervals(bond.bad_intervals_ptr, bond.bad_intervals_len) })
        else {
            return Err(if bond.bad_intervals_ptr.is_null() {
                SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_NULL_PTR
            } else {
                SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_LEN_OVERFLOW
            });
        };
        joins.push(bond.join_settlement_epoch);
        completes.push(bond.is_foundation_complete_tree != 0);
        bad.push(intervals);
    }

    let shards: Vec<EpochCloseShard> = raw_shards
        .iter()
        .map(|s| EpochCloseShard {
            shard_id: s.shard_id,
            has_segment: s.has_segment != 0,
            freeze_height: s.freeze_height,
        })
        .collect();
    let pairs: Vec<CreditPair> = raw_pairs
        .iter()
        .map(|p| CreditPair {
            bond_idx: p.bond_idx,
            shard_idx: p.shard_idx,
        })
        .collect();

    Ok(DecodedEpochRows {
        joins,
        completes,
        bad,
        shards,
        pairs,
    })
}

/// Decode a flattened `(start, end_exclusive)` interval buffer; `None` on
/// null-with-length or pair-count overflow.
pub(super) unsafe fn gather_bad_intervals(
    ptr: *const u64,
    pair_len: usize,
) -> Option<Vec<BadInterval>> {
    if pair_len == 0 {
        return Some(Vec::new());
    }
    if ptr.is_null() {
        return None;
    }
    let flat_len = pair_len.checked_mul(2)?;
    let flat = unsafe { std::slice::from_raw_parts(ptr, flat_len) };
    Some(
        flat.chunks_exact(2)
            .map(|pair| BadInterval {
                start_epoch: pair[0],
                end_exclusive: pair[1],
            })
            .collect(),
    )
}

/// Full epoch-close consensus computation (ARCHIVAL_CONSENSUS_STATE.md §3.3, §3.5).
///
/// The daemon gathers raw LMDB rows — distinct credit-bearing bonds, the shards
/// they credited, and the credit pairs — and receives `R_market` per shard plus
/// the finalized `Σwork(E)` milli value. All consensus arithmetic (membership,
/// counting, age weighting, scarcity, curve, saturation) runs in
/// `shekyl-archival-retention` against pinned `consensus_constants.json` values;
/// C++ performs storage orchestration only (`40-ffi-discipline.mdc` coarse-call rule).
///
/// `out_r_market_ptr` must address `shards_len` writable `u64`s; outputs are
/// zeroed before computation so a failure never leaves stale values.
///
/// # Safety
///
/// All pointers must satisfy their stated lengths for the duration of the call:
/// `bonds_ptr[0..bonds_len]`, `shards_ptr[0..shards_len]`,
/// `credit_pairs_ptr[0..credit_pairs_len]`, `out_r_market_ptr[0..shards_len]`,
/// and each bond's interval buffer per its embedded lengths.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_epoch_close_compute(
    settlement_epoch: u64,
    close_block_height: u64,
    bonds_ptr: *const ShekylArchivalEpochCloseBond,
    bonds_len: usize,
    shards_ptr: *const ShekylArchivalEpochCloseShard,
    shards_len: usize,
    credit_pairs_ptr: *const ShekylArchivalCreditPair,
    credit_pairs_len: usize,
    out_r_market_ptr: *mut u64,
    out_sigma_work_milli_ptr: *mut u64,
) -> u8 {
    if (bonds_ptr.is_null() && bonds_len > 0)
        || (shards_ptr.is_null() && shards_len > 0)
        || (credit_pairs_ptr.is_null() && credit_pairs_len > 0)
        || out_sigma_work_milli_ptr.is_null()
    {
        return SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_NULL_PTR;
    }

    unsafe { *out_sigma_work_milli_ptr = 0 };
    if shards_len > 0 {
        if out_r_market_ptr.is_null() {
            return SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_NULL_PTR;
        }
        unsafe { std::ptr::write_bytes(out_r_market_ptr, 0, shards_len) };
    }

    let rows = match unsafe {
        decode_epoch_rows(
            bonds_ptr,
            bonds_len,
            shards_ptr,
            shards_len,
            credit_pairs_ptr,
            credit_pairs_len,
        )
    } {
        Ok(rows) => rows,
        Err(code) => return code,
    };

    let bonds = rows.bonds();
    // Pinned params via the single-sourced close-view constructor (a struct
    // literal here would be a second param source that edits in lockstep).
    let inputs = EpochCloseInputs::close_view(
        settlement_epoch,
        close_block_height,
        &bonds,
        &rows.shards,
        &rows.pairs,
    );
    let result = match epoch_close_compute(&inputs) {
        Ok(r) => r,
        Err(_) => return SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_INDEX_RANGE,
    };

    unsafe {
        if shards_len > 0 {
            std::ptr::copy_nonoverlapping(
                result.r_market_by_shard.as_ptr(),
                out_r_market_ptr,
                shards_len,
            );
        }
        *out_sigma_work_milli_ptr = result.sigma_work_milli;
    }
    SHEKYL_ARCHIVAL_EPOCH_CLOSE_OK
}

/// The M-2/Q7 as-of-`E` consensus snapshot for one claimed settlement epoch
/// (`REWARD_EMISSION_E3_GATING_ROUND.md` §3 item 2;
/// `REWARD_EMISSION_VIN_PLAN.md` §8.0.2(B)).
///
/// Layout must match `struct shekyl_archival_emission_epoch_snapshot` in
/// `shekyl_ffi.h`. Marshaled by value from the frozen `E`-close
/// materialization: the serve-credit rows for `E` (the WS-1 §5 held source),
/// the credited bonds' standing fields, shard freeze heights, and the
/// **persisted** `Σwork(E)` — never the live bond holdings descriptor. Every
/// row is immutable for a claimable `E` (credit acceptance rejects past
/// `H_close(E)`; pruning deletes only below the claim window's floor; reorg
/// pops revert close and credits symmetrically), so a re-gather at any height
/// in the claim window reproduces the close's gather exactly.
///
/// `sigma_work_milli` must be the persisted close output, not a recompute —
/// the close's outcome reaches verify only through the stored denominator.
#[repr(C)]
pub struct ShekylArchivalEmissionEpochSnapshot {
    pub settlement_epoch: u64,
    /// The close-processing height `(E+1) × SEB` the gather froze at (shard-age
    /// operand; must equal the height the close ran at). NOT `H_close(E)` =
    /// `shekyl_archival_epoch_close_height(E)` = the epoch's last block =
    /// `(E+1) × SEB − 1`, one block lower.
    pub close_block_height: u64,
    /// Persisted finalized `Σwork(E)` milli — the stored denominator.
    pub sigma_work_milli: u64,
    /// Persisted frozen `budget(E)` atomic — the gate-1 numerator operand,
    /// stored at close beside `Σwork(E)` (the `archival_budget` close row,
    /// `ARCHIVAL_BUDGET_SCHEDULE.md` §5). Like the denominator, always the
    /// stored value, never a recompute: the accrual accumulator is live
    /// state; only the close row is frozen.
    pub budget_atomic: u64,
    pub bonds_ptr: *const ShekylArchivalEpochCloseBond,
    pub bonds_len: usize,
    pub shards_ptr: *const ShekylArchivalEpochCloseShard,
    pub shards_len: usize,
    pub credit_pairs_ptr: *const ShekylArchivalCreditPair,
    pub credit_pairs_len: usize,
    /// Claimant `P`'s index into `bonds`, or `SIZE_MAX` when `P` has no
    /// serve-credit row in `E` (its work is then zero by construction).
    pub claimant_bond_idx: usize,
}
