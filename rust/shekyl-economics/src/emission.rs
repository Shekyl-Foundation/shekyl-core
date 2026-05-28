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
#[inline]
fn emission_speed_factor(params: &EconomicParams) -> u32 {
    debug_assert_eq!(
        params.daa_target_seconds % 60,
        0,
        "DAA target must be a multiple of 60 seconds"
    );
    let target_minutes = params.daa_target_seconds / 60;
    (params.emission_speed_factor_per_minute - (target_minutes - 1)) as u32
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
        assert_eq!(
            base_block_reward(0, &p).unwrap(),
            2_048_000_000_000_u64
        );
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
        let p = EconomicParams::default();
        let grid = [
            0_u64,
            2_048_000_000_000,
            2_756_434_948_434_199_641,
        ];
        for ag in grid {
            let reward = base_block_reward(ag, &p).unwrap();
            assert!(reward > 0);
            assert_eq!(reward, base_block_reward(ag, &p).unwrap());
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
