// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Economics FFI: release, burn, emission split, block reward, fee ladder.
//!
//! The C ABI for `shekyl-economics`. Logic stays in that crate; these
//! functions marshal pointers and status codes.

use super::legacy_types::*;
use super::legacy_util::*;

// ─── Economics: Release Rate ────────────────────────────────────────────────

/// Calculate the release multiplier from transaction volume.
///
/// The volume operand crosses as the exact window `(tx_count_sum,
/// window_blocks)` — FL-R24: the daemon no longer truncates the mean to
/// whole transactions per block before the ratio is formed. C++ marshals
/// `Blockchain::get_tx_volume_window` here and computes nothing itself.
///
/// Returns fixed-point value (SCALE=1_000_000). 1_000_000 = 1.0x.
#[no_mangle]
pub extern "C" fn shekyl_calc_release_multiplier(
    tx_count_sum: u64,
    window_blocks: u64,
    tx_volume_baseline: u64,
    release_min: u64,
    release_max: u64,
) -> u64 {
    shekyl_economics::release::calc_release_multiplier(
        shekyl_economics::TxVolume::window(tx_count_sum, window_blocks),
        tx_volume_baseline,
        release_min,
        release_max,
    )
}

// ─── Economics: Fee Burn ────────────────────────────────────────────────────

/// Free-parameter burn percentage. Not the consensus burn.
///
/// [`shekyl_compute_fee_burn`] and [`shekyl_calc_burn_pct_at`] derive the
/// supply and read `EconomicParams`. The relay-floor ring
/// (`fee_correction_from`) still calls this with gross
/// `already_generated_coins`: it recomputes historical rungs, and no
/// per-height burn fold is stored (FL-R16c).
///
/// Volume operand as for [`shekyl_calc_release_multiplier`]: the exact
/// window `(tx_count_sum, window_blocks)` (FL-R24).
///
/// Returns fixed-point burn percentage (SCALE=1_000_000). 400_000 = 40%.
#[no_mangle]
pub extern "C" fn shekyl_calc_burn_pct(
    tx_count_sum: u64,
    window_blocks: u64,
    tx_baseline: u64,
    circulating_supply: u64,
    total_supply: u64,
    burn_base_rate: u64,
    burn_cap: u64,
) -> u64 {
    shekyl_economics::burn::calc_burn_pct(
        shekyl_economics::TxVolume::window(tx_count_sum, window_blocks),
        tx_baseline,
        circulating_supply,
        total_supply,
        burn_base_rate,
        burn_cap,
    )
}

/// Pack a Rust [`BurnSplit`] for the C ABI — single packing site for both
/// burn-split exports so field order cannot drift between them.
fn burn_split_to_c(split: shekyl_economics::BurnSplit) -> ShekylBurnSplit {
    ShekylBurnSplit {
        miner_fee_income: split.miner_fee_income,
        staker_pool_amount: split.staker_pool_amount,
        actually_destroyed: split.actually_destroyed,
    }
}

/// Compute the three-way fee split for a block, with a caller-supplied flat
/// share.
///
/// Consensus C++ no longer calls this (Stage 3b routes every burn split
/// through [`shekyl_compute_burn_split_escalated`]); it is retained as the
/// differential oracle for the genesis-neutrality pin. It holds no share
/// constant of its own (the share is an argument), so keeping it duplicates no
/// fact.
#[no_mangle]
pub extern "C" fn shekyl_compute_burn_split(
    total_fees: u64,
    burn_pct: u64,
    staker_pool_share: u64,
) -> ShekylBurnSplit {
    use shekyl_economics::{compute_burn_split, ScaledShare};
    burn_split_to_c(compute_burn_split(
        total_fees,
        burn_pct,
        ScaledShare::from_raw(staker_pool_share),
    ))
}

/// Compute the three-way fee split with the **D2-escalated** staker share.
///
/// Thin FFI over the canonical Rust entry
/// [`shekyl_economics::compute_burn_split_at`]. `frozen_segment_count` is the
/// burden operand `n`, read **at parent-block state** (M3-1 cached-counter
/// drift class). Numerics stay in shipped `EconomicParams`.
///
/// **The share cannot reach `miner_fee_income`** (§12.11.1 Leg 1). At the
/// genesis-neutral parameterization this is bit-identical to
/// [`shekyl_compute_burn_split`] with the flat constant, for every `n`.
#[no_mangle]
pub extern "C" fn shekyl_compute_burn_split_escalated(
    total_fees: u64,
    burn_pct: u64,
    frozen_segment_count: u64,
) -> ShekylBurnSplit {
    use shekyl_economics::{compute_burn_split_at, EconomicParams, FrozenSegmentCount};
    burn_split_to_c(compute_burn_split_at(
        total_fees,
        burn_pct,
        FrozenSegmentCount::new(frozen_segment_count),
        &EconomicParams::default(),
    ))
}

/// Status codes for the fee-burn family's fallible entries.
pub const SHEKYL_ECONOMICS_OK: i32 = 0;
/// A required out-pointer was null.
pub const SHEKYL_ECONOMICS_NULL_OUT: i32 = -1;
/// `total_burned > coins_generated` — a store-invariant violation
/// ([`shekyl_economics::SupplyInvariantViolation`]), never a saturated zero.
pub const SHEKYL_ECONOMICS_SUPPLY_INVARIANT: i32 = -2;

/// **The one owner of the fee burn, at the boundary** (CEN-F17; E6 slice 4
/// precursor, `CHAIN_RULES_SLICE_4.md` §3.1 S1/S3/S15, FL-R16c).
///
/// C++ passes the two **store facts** the supply derives from —
/// `coins_generated` (the parent's `already_generated_coins`) and
/// `total_burned` (the destroyed-fee fold), both read at parent state — and
/// Rust derives `circulating_supply = coins_generated − total_burned`
/// (`shekyl_economics::CirculatingSupply::derive`), the percentage, the
/// escalated split and the zero-fee arm. Until this landed the C++ shim
/// `economics.h` owned the zero arm and the composition, and two C++ sites
/// defined the supply operand as gross emission — the definitional defect
/// FL-R16c bound the implementing PR to correct.
///
/// # Safety
///
/// `out` must be null or valid for writing one `ShekylBurnSplit`. Null is
/// checked ([`SHEKYL_ECONOMICS_NULL_OUT`]); a supply underflow returns
/// [`SHEKYL_ECONOMICS_SUPPLY_INVARIANT`] and writes nothing — the caller
/// halts, it does not proceed on a zero.
#[no_mangle]
pub unsafe extern "C" fn shekyl_compute_fee_burn(
    total_fees: u64,
    tx_count_sum: u64,
    window_blocks: u64,
    coins_generated: u64,
    total_burned: u64,
    frozen_segment_count: u64,
    out: *mut ShekylBurnSplit,
) -> i32 {
    use shekyl_economics::{compute_fee_burn, EconomicParams, FrozenSegmentCount, TxVolume};
    if out.is_null() {
        return SHEKYL_ECONOMICS_NULL_OUT;
    }
    let Ok(supply) = circulating_supply(coins_generated, total_burned) else {
        return SHEKYL_ECONOMICS_SUPPLY_INVARIANT;
    };
    let split = compute_fee_burn(
        total_fees,
        TxVolume::window(tx_count_sum, window_blocks),
        supply,
        FrozenSegmentCount::new(frozen_segment_count),
        &EconomicParams::default(),
    );
    // SAFETY: non-null per the check above; the caller guarantees writability.
    unsafe { out.write(burn_split_to_c(split)) };
    SHEKYL_ECONOMICS_OK
}

/// Burn percentage for the info RPC, from the two store facts.
///
/// Same derivation and invariant status as [`shekyl_compute_fee_burn`].
/// The relay floor does not call this; it still uses
/// [`shekyl_calc_burn_pct`] (FL-R16c).
///
/// # Safety
///
/// `out_pct` must be null or valid for writing one `u64`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_calc_burn_pct_at(
    tx_count_sum: u64,
    window_blocks: u64,
    coins_generated: u64,
    total_burned: u64,
    out_pct: *mut u64,
) -> i32 {
    use shekyl_economics::{calc_burn_pct_at, EconomicParams, TxVolume};
    if out_pct.is_null() {
        return SHEKYL_ECONOMICS_NULL_OUT;
    }
    let Ok(supply) = circulating_supply(coins_generated, total_burned) else {
        return SHEKYL_ECONOMICS_SUPPLY_INVARIANT;
    };
    let pct = calc_burn_pct_at(
        TxVolume::window(tx_count_sum, window_blocks),
        supply,
        &EconomicParams::default(),
    );
    // SAFETY: non-null per the check above.
    unsafe { out_pct.write(pct) };
    SHEKYL_ECONOMICS_OK
}

fn circulating_supply(
    coins_generated: u64,
    total_burned: u64,
) -> Result<shekyl_economics::CirculatingSupply, shekyl_economics::SupplyInvariantViolation> {
    use shekyl_units::AtomicUnits;
    shekyl_economics::CirculatingSupply::derive(
        AtomicUnits::from_raw(coins_generated),
        AtomicUnits::from_raw(total_burned),
    )
}

/// **The one owner of the emission split, at the boundary** (CEN-F16; E6
/// slice 4 precursor §3.1 S4/S6). The zero-emission arm and the
/// share→split composition that the C++ shim `economics.h` used to own are
/// `shekyl_economics::compute_emission_split`'s; the three constants it
/// marshaled are that crate's. `genesis_ng_height` is CEN-F21's epoch (1 on
/// every shipped network). Infallible.
#[no_mangle]
pub extern "C" fn shekyl_compute_emission_split(
    block_emission: u64,
    current_height: u64,
    genesis_ng_height: u64,
) -> ShekylEmissionSplit {
    let split =
        shekyl_economics::compute_emission_split(block_emission, current_height, genesis_ng_height);
    ShekylEmissionSplit {
        miner_emission: split.miner_emission,
        staker_emission: split.staker_emission,
    }
}

/// The D2-escalated staker share at `frozen_segment_count`, fixed-point `SCALE`.
///
/// Observability / callers that need the share without a split. Same
/// parent-state read-point obligation as [`shekyl_compute_burn_split_escalated`].
#[no_mangle]
pub extern "C" fn shekyl_staker_pool_share_at(frozen_segment_count: u64) -> u64 {
    use shekyl_economics::{staker_pool_share_at, EconomicParams, FrozenSegmentCount};
    staker_pool_share_at(
        FrozenSegmentCount::new(frozen_segment_count),
        &EconomicParams::default().escalation(),
    )
    .to_raw()
}

/// Base block subsidy before weight penalty and release multiplier (0h KAT export).
///
/// Total since FL-R12′: `base_block_reward` floors `remaining` at zero, so a
/// past-asymptote accumulator yields the perpetual tail rather than needing an
/// input clamp — this `extern "C"` export cannot panic (or unwind) across the
/// FFI boundary. Note this is the M_r-NEUTRAL view; the paid pipeline's floor
/// applies after the release multiplier (see `shekyl_block_reward`).
#[no_mangle]
pub extern "C" fn shekyl_base_block_reward(already_generated_coins: u64) -> u64 {
    let params = shekyl_economics::params::EconomicParams::default();
    // The only residual error is a tail-subsidy overflow that canonical
    // params never trigger; fall back to 0 deterministically.
    shekyl_economics::base_block_reward(already_generated_coins, &params).unwrap_or(0)
}

/// Effective block-weight median: `short_term` bounded to
/// `[long_term, S · long_term]`. Cannot fail. C++ gathers the window
/// medians; this is the clamp `update_next_cumulative_weight_limit`
/// consumes.
#[no_mangle]
pub extern "C" fn shekyl_effective_block_weight_median(
    long_term_effective: u64,
    short_term_median: u64,
) -> u64 {
    shekyl_economics::effective_median(long_term_effective, short_term_median)
}

/// Bound a block's long-term-median contribution to `[LTEM/1.7, LTEM·1.7]`.
/// Cannot fail. C++ gathers `LTEM`; this is the bound
/// `get_next_long_term_block_weight` consumes.
#[no_mangle]
pub extern "C" fn shekyl_long_term_block_weight(
    long_term_effective: u64,
    block_weight: u64,
) -> u64 {
    shekyl_economics::long_term_weight(long_term_effective, block_weight)
}

/// Status: reward computed. `out_reward` and `out_weight_limit` are written.
pub const SHEKYL_BLOCK_REWARD_OK: i32 = 0;
/// Status: the block exceeds twice the effective median — a CONSENSUS
/// REJECTION the caller is expected to act on, not an internal fault.
/// `out_weight_limit` is written so the caller can report the limit it was
/// rejected against; `out_reward` is left untouched.
pub const SHEKYL_BLOCK_REWARD_BLOCK_TOO_BIG: i32 = 1;
/// Status: a required out-pointer was null, or the inputs were out of domain.
/// A CALLER BUG. Negative to keep misuse distinguishable from rejection.
pub const SHEKYL_BLOCK_REWARD_INVALID: i32 = -1;

/// Block reward after the median-weight penalty.
///
/// The C2c cutover's last step: the `mul128`/`div128_64` penalty arithmetic
/// that lived in `get_block_reward` (`cryptonote_basic_impl.cpp`) now lives in
/// `shekyl-economics`, and C++ marshals to it here.
///
/// THIS IS THE FIRST FALLIBLE ENTRY IN THE ECONOMICS FFI FAMILY, and the break
/// is deliberate. The other economics exports document themselves as unable to
/// fail across the boundary (they clamp their inputs instead). This one has a
/// genuine consensus outcome to report — "too big" is how a block gets
/// rejected — and collapsing it into a sentinel reward would make an invalid
/// block indistinguishable from a valid one paying zero at exactly
/// `2 * median`. Hence a status return, with rejection POSITIVE and caller
/// misuse NEGATIVE.
///
/// The penalty-free zone is **not** a parameter: it is `EconomicParams::
/// full_reward_zone`, generated from `config/consensus_constants.json` for
/// both languages (E6 slice 4 §3.1 S8). Until then the C++ supplied its
/// hand-written macro on every call — a consensus constant with no Rust
/// home, and a caller that could pass a different one.
///
/// Since FL-R12′ this marshals the ONE owner `paid_block_reward` — the full
/// signed composition `max(M_r·curve(remaining), TAIL)·penalty(x)` — so it
/// takes the volume operand, as the exact window `(tx_count_sum,
/// window_blocks)` since FL-R24, and there is no C++-side multiplier, cap,
/// or flag path. A past-asymptote accumulator is a legitimate perpetual-tail state,
/// not an error (FL-R16a).
///
/// # Safety
///
/// `out_reward` and `out_weight_limit` must each be either null or a valid,
/// writable `u64`. Null is checked, not assumed: the function returns
/// [`SHEKYL_BLOCK_REWARD_INVALID`] without writing through either pointer.
#[no_mangle]
pub unsafe extern "C" fn shekyl_block_reward(
    median_weight: u64,
    current_block_weight: u64,
    already_generated_coins: u64,
    tx_count_sum: u64,
    window_blocks: u64,
    out_reward: *mut u64,
    out_weight_limit: *mut u64,
) -> i32 {
    if out_reward.is_null() || out_weight_limit.is_null() {
        return SHEKYL_BLOCK_REWARD_INVALID;
    }
    let params = shekyl_economics::params::EconomicParams::default();

    // Written on every path, including rejection: the caller logs the limit it
    // was rejected against, and it must come from the same clamp that made the
    // decision rather than a recomputation on the C++ side.
    let limit = shekyl_economics::block_weight_limit(median_weight, &params);
    // SAFETY: non-null per the check above; the caller guarantees writability.
    unsafe { out_weight_limit.write(limit) };

    match shekyl_economics::paid_block_reward(
        median_weight,
        current_block_weight,
        already_generated_coins,
        shekyl_economics::TxVolume::window(tx_count_sum, window_blocks),
        &params,
    ) {
        Ok(reward) => {
            // SAFETY: non-null per the check above.
            unsafe { out_reward.write(reward) };
            SHEKYL_BLOCK_REWARD_OK
        }
        Err(shekyl_economics::EmissionError::BlockTooBig) => SHEKYL_BLOCK_REWARD_BLOCK_TOO_BIG,
        // Total in `ag` (FL-R16a); the only other arms are overflow shapes
        // canonical params never trigger. Report misuse rather than
        // panicking across the boundary.
        Err(_) => SHEKYL_BLOCK_REWARD_INVALID,
    }
}

/// Raw fee-correction `C = (1−σ)·M_r/(1−b)` in SCALE units — the served
/// multiplier. `(tx_count_sum, window_blocks)` is the undivided volume
/// window; `sigma` / `burn` are the validation-path values at this state.
/// Cannot fail.
#[no_mangle]
pub extern "C" fn shekyl_fee_correction(
    tx_count_sum: u64,
    window_blocks: u64,
    sigma_scaled: u64,
    burn_pct_scaled: u64,
) -> u64 {
    let params = shekyl_economics::params::EconomicParams::default();
    shekyl_economics::fee_correction(
        shekyl_economics::TxVolume::window(tx_count_sum, window_blocks),
        sigma_scaled,
        burn_pct_scaled,
        &params,
    )
    .as_scaled()
}

/// Lookback depth `G`. Rust is the owner; C++ sizes the ring from this.
#[no_mangle]
pub extern "C" fn shekyl_relay_floor_lookback() -> u64 {
    shekyl_economics::RELAY_FLOOR_LOOKBACK as u64
}

/// Admission slack in basis points. Rust is the owner; pinned at zero.
#[no_mangle]
pub extern "C" fn shekyl_relay_admission_slack_bp() -> u32 {
    shekyl_economics::RELAY_ADMISSION_SLACK_BP
}

/// Three-slot ladder `[economy, standard, priority]`. Economy **is** the
/// relay floor at the same operands. The penalty-free zone is
/// [`shekyl_economics::EconomicParams::full_reward_zone`], not an argument.
/// Writes three `u64`s.
///
/// Returns `0` written, `-1` null `out_fees`, `-2` scalars outside the
/// `u128` domain (rule 40: refuse rather than abort).
///
/// # Safety
///
/// `out_fees` must be null or valid for writing three `u64`s.
#[no_mangle]
pub unsafe extern "C" fn shekyl_corrected_fee_ladder(
    base_reward: u64,
    median: u64,
    ref_tx_weight: u64,
    c_scaled: u64,
    out_fees: *mut u64,
) -> i32 {
    if out_fees.is_null() {
        return -1;
    }
    let params = shekyl_economics::EconomicParams::default();
    let Some(ladder) = shekyl_economics::checked_corrected_fee_ladder(
        base_reward,
        median,
        ref_tx_weight,
        shekyl_economics::FeeCorrection::from_scaled(c_scaled),
        &params,
    ) else {
        return -2;
    };
    let fees = ladder.as_slots();
    for (i, f) in fees.iter().enumerate() {
        // SAFETY: non-null per the check; caller guarantees 3 writable u64s.
        unsafe { out_fees.add(i).write(*f) };
    }
    0
}

/// Relay floor `F = R·C·w_ref/M²`, floored at 1. Same function as the
/// ladder's economy rung. The penalty-free zone is
/// [`shekyl_economics::EconomicParams::full_reward_zone`], not an argument.
/// Returns `0` written, `-1` null, `-2` out of domain.
///
/// # Safety
///
/// `out_floor` must be null or point at one writable `u64`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_fee_floor(
    base_reward: u64,
    median: u64,
    ref_tx_weight: u64,
    c_scaled: u64,
    out_floor: *mut u64,
) -> i32 {
    if out_floor.is_null() {
        return -1;
    }
    let params = shekyl_economics::EconomicParams::default();
    let Some(floor) = shekyl_economics::checked_relay_fee_floor(
        base_reward,
        median,
        ref_tx_weight,
        shekyl_economics::FeeCorrection::from_scaled(c_scaled),
        &params,
    ) else {
        return -2;
    };
    // SAFETY: non-null per the check; caller guarantees one writable u64.
    unsafe { out_floor.write(floor) };
    0
}

/// Admit iff `fee >= mask_round_up(weight · min(floors)) − slack`.
///
/// `floors` is at most [`shekyl_economics::RELAY_FLOOR_WINDOW`] values;
/// a longer window is refused (`-1`). Empty refuses. Returns `1` / `0` /
/// `-1`.
///
/// # Safety
///
/// `floors` must point at `floors_len` readable `u64`s, or be null with
/// `floors_len == 0`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_floor_admits(
    fee: u64,
    weight: u64,
    mask: u64,
    floors: *const u64,
    floors_len: usize,
    slack_bp: u32,
) -> i32 {
    if floors_len > shekyl_economics::RELAY_FLOOR_WINDOW {
        return -1;
    }
    // SAFETY: caller contract matches the seam — `floors` addresses
    // `floors_len` u64s, or is null with a zero length.
    let Some(window) = (unsafe { slice_from_typed_ptr(floors, floors_len) }) else {
        return -1;
    };
    i32::from(shekyl_economics::relay_floor_admits(
        fee, weight, mask, window, slack_bp,
    ))
}

/// Advance `already_generated_coins` by a block reward.
///
/// One entry point for both C++ connect paths (main-chain and alt-chain),
/// which each carried their own copy of the rule. Cannot fail. Since
/// FL-R12′ it advances THROUGH the emission-curve asymptote (perpetual
/// tail); the only saturation is the u64 rail (FL-R14).
#[no_mangle]
pub extern "C" fn shekyl_advance_already_generated(
    already_generated_coins: u64,
    block_reward: u64,
) -> u64 {
    shekyl_economics::advance_already_generated(already_generated_coins, block_reward)
}

// ─── Emission Share (Component 4) ───────────────────────────────────────────

/// Calculate the effective staker emission share at a given block height.
///
/// Returns fixed-point SCALE value (e.g., 150_000 = 15%).
#[no_mangle]
pub extern "C" fn shekyl_calc_emission_share(
    current_height: u64,
    genesis_height: u64,
    initial_share: u64,
    annual_decay: u64,
    blocks_per_year: u64,
) -> u64 {
    shekyl_economics::emission_share::calc_effective_emission_share(
        current_height,
        genesis_height,
        initial_share,
        annual_decay,
        blocks_per_year,
    )
}

#[no_mangle]
pub extern "C" fn shekyl_split_block_emission(
    block_emission: u64,
    effective_share: u64,
) -> ShekylEmissionSplit {
    let (miner, staker) =
        shekyl_economics::emission_share::split_block_emission(block_emission, effective_share);
    ShekylEmissionSplit {
        miner_emission: miner,
        staker_emission: staker,
    }
}
