// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Per-staked-output lifecycle view for the wallet's staking UI.
//!
//! [`StakeView`] is a *transform-shaped* wire type: one record per live staked
//! output, carrying everything the staking screen needs — maturity countdown,
//! in-flight unstake state, accrued reward, and a projected to-maturity yield.
//! It supersedes the three overlapping ad-hoc shapes the GUI previously built
//! by hand (staked / claimable / unstakeable), so the read surface is defined
//! once here instead of duplicated at each consumer.
//!
//! Built by [`LedgerBlockExt::stake_views`](crate::LedgerBlockExt::stake_views),
//! which composes the scanner's ledger state with the accrual aggregate on
//! [`LedgerIndexes::staker_pool`](shekyl_engine_state::LedgerIndexes::staker_pool).

use serde::{Deserialize, Serialize};
use shekyl_units::AtomicUnits;

/// One live staked output's full lifecycle state.
///
/// Atomic-unit fields serialize as plain integers (`AtomicUnits` is
/// `#[serde(transparent)]` over `u64`); `tx_hash` is lowercase hex.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StakeView {
    /// Transaction that created the stake (lowercase hex).
    pub tx_hash: String,
    /// Global output index on the blockchain.
    pub global_output_index: u64,
    /// Staked amount.
    pub amount: AtomicUnits,
    /// Staking tier (0 = short, 1 = medium, 2 = long).
    pub tier: u8,
    /// Block height the stake was created at.
    pub stake_height: u64,
    /// Absolute height the lock expires at.
    pub stake_lock_until: u64,
    /// Blocks remaining until maturity (0 once matured).
    pub blocks_until_mature: u64,
    /// Whether the lock has expired — the output can be unstaked.
    pub matured: bool,
    /// Whether an unstake transaction has been broadcast for this output but
    /// not yet observed as spent on-chain. Advisory; reset on wallet restart.
    pub pending_unstake: bool,
    /// Reward claimable right now.
    pub accrued_claimable: AtomicUnits,
    /// Projected total reward by maturity, extrapolated linearly from the
    /// trailing average accrual rate over the output's accrued range. An
    /// estimate for display, never a guarantee; equals `accrued_claimable`
    /// once matured (`blocks_until_mature == 0`).
    pub estimated_yield_to_maturity: AtomicUnits,
}
