// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_staking::tiers::{tier_by_id, TIERS};

/// Simulates the per-block reward computation using 128-bit integer arithmetic,
/// matching the consensus path in blockchain.cpp::check_stake_claim_input.
fn compute_reward_integer(total_reward: u64, weight: u64, total_weighted_stake: u128) -> u64 {
    if total_reward == 0 || total_weighted_stake == 0 {
        return 0;
    }
    let product = total_reward as u128 * weight as u128;
    (product / total_weighted_stake) as u64
}

/// Compute stake weight matching the C FFI: amount * yield_multiplier / SCALE.
fn stake_weight(amount: u64, tier_id: u8) -> u64 {
    let tier = match tier_by_id(tier_id) {
        Some(t) => t,
        None => return 0,
    };
    ((amount as u128 * tier.yield_multiplier as u128) / 1_000_000u128) as u64
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 26 {
        return;
    }

    let tier_id = data[0] % 3;
    let stake_amount = u64::from_le_bytes(data[1..9].try_into().unwrap());
    let staker_emission = u64::from_le_bytes(data[9..17].try_into().unwrap());
    let staker_fee_pool = u64::from_le_bytes(data[17..25].try_into().unwrap());
    let total_weighted_raw = data[25] as u64;

    if stake_amount == 0 {
        return;
    }

    let weight = stake_weight(stake_amount, tier_id);

    // Ensure total_weighted_stake >= weight (staker is part of total)
    let total_weighted_stake: u128 = if total_weighted_raw == 0 {
        weight as u128
    } else {
        (weight as u128).saturating_add((total_weighted_raw as u128).saturating_mul(1_000_000))
    };

    if total_weighted_stake == 0 {
        return;
    }

    let total_reward = staker_emission.saturating_add(staker_fee_pool);

    let reward = compute_reward_integer(total_reward, weight, total_weighted_stake);

    // Invariant 1: reward must not exceed total pool
    assert!(
        reward <= total_reward,
        "reward {reward} > total_reward {total_reward}"
    );

    // Invariant 2: no overflow in intermediate computation
    // (already guaranteed by u128 arithmetic)

    // Invariant 3: higher weight means >= reward (monotonicity)
    for other_tier in &TIERS {
        let other_weight = stake_weight(stake_amount, other_tier.id);
        let other_reward =
            compute_reward_integer(total_reward, other_weight, total_weighted_stake);
        if other_weight >= weight {
            assert!(
                other_reward >= reward,
                "tier {} (weight {other_weight}) gives reward {other_reward} < tier {tier_id} (weight {weight}) reward {reward}",
                other_tier.id
            );
        }
    }

    // Invariant 4: zero total_reward produces zero reward
    assert_eq!(compute_reward_integer(0, weight, total_weighted_stake), 0);

    // Invariant 5: cumulative rewards over N blocks don't exceed N * max_per_block
    let n_blocks = 5u64;
    let mut cumulative = 0u64;
    for _ in 0..n_blocks {
        cumulative = cumulative.saturating_add(reward);
    }
    assert!(cumulative <= n_blocks.saturating_mul(total_reward));
});
