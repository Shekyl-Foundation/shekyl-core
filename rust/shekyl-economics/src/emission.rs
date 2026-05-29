//! Base block subsidy curve (0h) and neutral-trajectory projection (0h′).
//!
//! Matches `get_block_reward` base path in `cryptonote_basic_impl.cpp` before
//! weight penalty and release multiplier.

use crate::params::EconomicParams;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EmissionError {
    #[error("already_generated_coins exceeds money_supply")]
    AlreadyGeneratedExceedsSupply,
    #[error("arithmetic overflow projecting emission")]
    Overflow,
}

/// Effective emission speed factor for the configured DAA target block time.
///
/// Returned as `u64` because its sole consumer is the right-shift in
/// `base_block_reward` (`remaining >> esf`), and Rust shifts accept a `u64`
/// shift amount directly. Keeping the value in `u64` avoids a gratuitous
/// narrowing cast.
#[inline]
fn emission_speed_factor(params: &EconomicParams) -> u64 {
    debug_assert_eq!(
        params.daa_target_seconds % 60,
        0,
        "DAA target must be a multiple of 60 seconds"
    );
    let target_minutes = params.daa_target_seconds / 60;
    params.emission_speed_factor_per_minute - (target_minutes - 1)
}

/// Tail (minimum) subsidy per block in atomic units.
#[inline]
fn tail_subsidy_per_block(params: &EconomicParams) -> Result<u64, EmissionError> {
    params
        .final_subsidy_per_minute
        .checked_mul(params.daa_target_seconds / 60)
        .ok_or(EmissionError::Overflow)
}

/// Base block reward before weight penalty and release multiplier (0h).
pub fn base_block_reward(
    already_generated_coins: u64,
    params: &EconomicParams,
) -> Result<u64, EmissionError> {
    if already_generated_coins > params.money_supply {
        return Err(EmissionError::AlreadyGeneratedExceedsSupply);
    }
    let remaining = params.money_supply - already_generated_coins;
    let esf = emission_speed_factor(params);
    let mut base_reward = remaining >> esf;
    let tail = tail_subsidy_per_block(params)?;
    if base_reward < tail {
        base_reward = tail;
    }
    Ok(base_reward)
}

/// Neutral-trajectory `already_generated` at `height` under interpretation (A) (0h′).
///
/// Sum of `base_block_reward` for blocks `0..height` with no release multiplier.
pub fn projected_already_generated(
    height: u64,
    params: &EconomicParams,
) -> Result<u64, EmissionError> {
    let mut ag = 0u64;
    for _ in 0..height {
        let base = base_block_reward(ag, params)?;
        ag = ag.checked_add(base).ok_or(EmissionError::Overflow)?;
        if ag >= params.money_supply {
            return Ok(params.money_supply);
        }
    }
    Ok(ag)
}

/// Neutral base subsidy at `height`: `base_block_reward(projected_already_generated(h))`.
pub fn base_emission_at(height: u64, params: &EconomicParams) -> Result<u64, EmissionError> {
    let ag = projected_already_generated(height, params)?;
    base_block_reward(ag, params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::EconomicParams;

    #[test]
    fn base_block_reward_matches_cpp_first_values() {
        let p = EconomicParams::default();
        assert_eq!(base_block_reward(0, &p).unwrap(), 2_048_000_000_000_u64);
        assert_eq!(
            base_block_reward(2_048_000_000_000, &p).unwrap(),
            2_047_999_023_437_u64
        );
        assert_eq!(
            base_block_reward(2_756_434_948_434_199_641, &p).unwrap(),
            733_629_392_416_u64
        );
    }

    #[test]
    fn base_block_reward_tail_floor() {
        let p = EconomicParams::default();
        let tail = p.final_subsidy_per_minute * (p.daa_target_seconds / 60);
        let near_max = p.money_supply - ((2 << 20) + 1);
        assert_eq!(base_block_reward(near_max, &p).unwrap(), tail);
    }

    #[test]
    fn projected_already_generated_at_genesis_is_zero() {
        let p = EconomicParams::default();
        assert_eq!(projected_already_generated(0, &p).unwrap(), 0);
    }

    #[test]
    fn projected_already_generated_height_one() {
        let p = EconomicParams::default();
        assert_eq!(
            projected_already_generated(1, &p).unwrap(),
            base_block_reward(0, &p).unwrap()
        );
    }

    #[test]
    fn base_emission_at_height_zero() {
        let p = EconomicParams::default();
        assert_eq!(
            base_emission_at(0, &p).unwrap(),
            base_block_reward(0, &p).unwrap()
        );
    }

    #[test]
    fn c2a_prime_layer1_base_reward_grid_matches_spec() {
        // Layer-1 leg B (STAGE_1_PR_7 §5.8) — Q_subsidy spec confirmation. The
        // oracle is an INDEPENDENT closed-form re-derivation of the 0h curve
        // `max((money_supply - ag) >> esf, tail)`, NOT a call to
        // `base_block_reward`. A shift/floor regression in the production curve
        // diverges from this oracle, so the assertion is non-tautological.
        let p = EconomicParams::default();
        let esf = p.emission_speed_factor_per_minute - (p.daa_target_seconds / 60 - 1);
        let tail = p.final_subsidy_per_minute * (p.daa_target_seconds / 60);
        let grid = [
            0_u64,
            2_048_000_000_000,
            2_756_434_948_434_199_641,
            p.money_supply - ((2 << 20) + 1), // tail-floor regime
        ];
        for ag in grid {
            let reward = base_block_reward(ag, &p).unwrap();
            let spec = core::cmp::max((p.money_supply - ag) >> esf, tail);
            assert_eq!(
                reward, spec,
                "Q_subsidy diverges from closed-form spec at ag={ag}"
            );
        }
    }

    #[test]
    fn c2a_prime_layer1_per_quantity_split_matches_spec() {
        // Layer-1 leg B (STAGE_1_PR_7 §5.8) — per-quantity spec for the derived
        // emission quantities the dual-leg grid must cover beyond Q_subsidy:
        //   Q_full_emission → {Q_miner_base, Q_staker_emission} → Q_miner_coinbase.
        // Confirms the emission split conserves the full block emission (the
        // property fix α depends on: Component 4 redistributes within Q_full, it
        // does not open a second issuance axis) and that the miner coinbase
        // composes from the split plus the fee-burn miner leg — all independent
        // of the C++ connect path.
        use crate::burn::compute_burn_split;
        use crate::emission_share::{calc_effective_emission_share, split_block_emission};
        use crate::params::SCALE;
        use crate::release::{apply_release_multiplier, calc_release_multiplier};

        // Canonical staker-emission constants (mirror config/economics_params.json;
        // not in EconomicParams, stated here as spec-oracle literals per the
        // existing emission_share test style).
        const STAKER_EMISSION_SHARE: u64 = 150_000; // 15%
        const STAKER_EMISSION_DECAY: u64 = 900_000; // 0.90 / year
        const BLOCKS_PER_YEAR: u64 = 262_800;

        let p = EconomicParams::default();
        let ag_grid = [0_u64, 2_048_000_000_000, 2_756_434_948_434_199_641];
        let height_grid = [
            1_u64,
            BLOCKS_PER_YEAR / 2,
            BLOCKS_PER_YEAR,
            5 * BLOCKS_PER_YEAR,
        ];

        for ag in ag_grid {
            // Q_subsidy → Q_full_emission. Empty-block volume 0 clamps the release
            // multiplier to RELEASE_MIN, matching the live chain's accumulation.
            let q_subsidy = base_block_reward(ag, &p).unwrap();
            let mult =
                calc_release_multiplier(0, p.tx_volume_baseline, p.release_min, p.release_max);
            let q_full = apply_release_multiplier(q_subsidy, mult);

            for h in height_grid {
                let share = calc_effective_emission_share(
                    h,
                    0,
                    STAKER_EMISSION_SHARE,
                    STAKER_EMISSION_DECAY,
                    BLOCKS_PER_YEAR,
                );
                let (q_miner_base, q_staker_emission) = split_block_emission(q_full, share);

                // Conservation — the distinguishing property of Q4_spec vs Q4_cpp.
                assert_eq!(
                    q_miner_base + q_staker_emission,
                    q_full,
                    "emission split not conservative at ag={ag} h={h}"
                );
                // Spec staker leg: floor(Q_full * share / SCALE). share ≤ SCALE,
                // so the quotient ≤ q_full ≤ u64::MAX — the conversion is infallible.
                let spec_staker =
                    u64::try_from(u128::from(q_full) * u128::from(share) / u128::from(SCALE))
                        .expect("staker leg ≤ q_full ≤ u64::MAX");
                assert_eq!(
                    q_staker_emission, spec_staker,
                    "Q_staker_emission off-spec at ag={ag} h={h}"
                );
                // Pre-decay heights carve out a positive staker share, so the full
                // emission strictly exceeds the miner share. This is exactly what
                // the live Layer-3 cap invariant relies on to catch the overwrite.
                if share > 0 && q_full > 0 {
                    assert!(
                        q_full > q_miner_base,
                        "no staker carve-out at ag={ag} h={h}"
                    );
                }

                // Q_miner_coinbase = Q_miner_base + miner fee income. Fee-free block
                // (the Layer-3 scenario) collapses to Q_miner_base; a fee-bearing
                // block adds the burn miner leg.
                assert_eq!(
                    q_miner_base,
                    q_miner_base + compute_burn_split(0, 0, p.staker_pool_share).miner_fee_income,
                    "fee-free Q_miner_coinbase must equal Q_miner_base at ag={ag} h={h}"
                );
                let fees = 1_000_000_000_u64;
                let burn = compute_burn_split(fees, p.burn_cap, p.staker_pool_share);
                let q_miner_coinbase = q_miner_base + burn.miner_fee_income;
                assert!(
                    q_miner_coinbase >= q_miner_base && burn.miner_fee_income <= fees,
                    "Q_miner_coinbase composition invalid at ag={ag} h={h}"
                );
            }
        }
    }

    #[test]
    fn c2a_prime_layer2_b_accum_matches_projected_already_generated() {
        let p = EconomicParams::default();
        let mut ag = 0_u64;
        for height in 0..1000 {
            assert_eq!(ag, projected_already_generated(height, &p).unwrap());
            let q_full = base_block_reward(ag, &p).unwrap();
            ag = ag.saturating_add(q_full).min(p.money_supply);
        }
    }
}
