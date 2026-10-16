// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The relay floor's operands, read off the chain: `F(h)` at one height
//! and the `G + 1` floors admission reads at a connecting height.
//!
//! `FEE_LADDER_DERIVATION.md` §11.6 and PR C §6 (Rick, 2026-10-16: built
//! and tested here, wired in at the DRS-X store flip). The composition is
//! `shekyl_economics::relay_floor_from`; this module is the six reads that
//! feed it, each the consensus definition the validator already uses:
//!
//! - the volume window, [`tx_volume_window`] (CEN-F20);
//! - the parent's `coins_generated`, [`recorded`] at `height − 1`
//!   (CEN-F13's operand);
//! - the circulating supply, [`CirculatingSupply::derive`] over that and
//!   the burned total through the parent (FL-R16c; a fold above the
//!   emission is [`Corrupt::BurnExceedsEmission`], never a zero);
//! - the long-term effective median in force for the block: at the
//!   connecting height [`effective_median_at`] (CEN-G6), at a recorded
//!   height the stored row ([`ChainView::long_term_effective_median_at`],
//!   written by its connect, FL-R3-STORE).
//!
//! No ring and no cache: the window is reads off the view, so it is
//! correct after a reorg by construction. The C++ `RelayFloorRing`, its
//! 725-block blob walk and its rolling median over 100 000 weights are what
//! the flip deletes.

use shekyl_economics::{relay_floor_from, CirculatingSupply, FeeOperands, RELAY_FLOOR_LOOKBACK};
use shekyl_types::BlockHeight;
use shekyl_units::AtomicUnits;

use crate::fault::{Corrupt, PerHeightRecord, ViewRead};
use crate::rules::block_weight::effective_median_at;
use crate::rules::miner::{economics, tx_volume_window};
use crate::rules::recorded;
use crate::view::{AtHeight, ChainView, Tip};

/// The fee operands of the block at `height`, read off `view`: a recorded
/// height reads its stored median; the connecting height (`tip + 1`)
/// derives it. Above the connecting height is [`AtHeight::AboveTip`].
///
/// # Errors
///
/// [`ViewRead::View`] on a view fault; [`ViewRead::Corrupt`] when a height
/// the operands span is not recorded, the prefix sum decreased, or the
/// burned total exceeds the parent's emission.
pub fn fee_operands_at<'id, V: ChainView<'id>>(
    view: &V,
    height: BlockHeight,
) -> Result<AtHeight<FeeOperands>, ViewRead<V::Fault>> {
    let connecting = Tip::connecting_height(view.tip().map_err(ViewRead::View)?.as_ref());
    if height > connecting {
        return Ok(AtHeight::AboveTip);
    }
    let median = if height == connecting {
        effective_median_at(view, height)?
            .long_term_effective_median
            .to_raw()
    } else {
        match view
            .long_term_effective_median_at(height)
            .map_err(ViewRead::View)?
        {
            AtHeight::Recorded(median) => median.to_raw(),
            AtHeight::AboveTip => {
                return Err(ViewRead::Corrupt(Corrupt::HoleBelowTip {
                    at: height,
                    record: PerHeightRecord::Block,
                }))
            }
        }
    };
    let tx_volume = tx_volume_window(view, height)?;
    let (parent_coins, burned) = match height.to_raw().checked_sub(1) {
        None => (AtomicUnits::ZERO, AtomicUnits::ZERO),
        Some(parent) => {
            let parent = BlockHeight::from_raw(parent);
            let coins = recorded(view, parent)?.coins_generated;
            let burned = if height == connecting {
                view.total_burned().map_err(ViewRead::View)?
            } else {
                match view.burned_through(parent).map_err(ViewRead::View)? {
                    AtHeight::Recorded(burned) => burned,
                    AtHeight::AboveTip => {
                        return Err(ViewRead::Corrupt(Corrupt::HoleBelowTip {
                            at: parent,
                            record: PerHeightRecord::Block,
                        }))
                    }
                }
            };
            (coins, burned)
        }
    };
    let supply = CirculatingSupply::derive(parent_coins, burned).map_err(|_| {
        ViewRead::Corrupt(Corrupt::BurnExceedsEmission {
            coins_generated: parent_coins,
            total_burned: burned,
        })
    })?;
    Ok(AtHeight::Recorded(FeeOperands {
        height: height.to_raw(),
        parent_coins_generated: parent_coins.to_raw(),
        supply,
        tx_volume,
        long_term_effective_median: median,
    }))
}

/// `F(height)`: [`relay_floor_from`] at [`fee_operands_at`].
///
/// # Errors
///
/// As [`fee_operands_at`].
///
/// # Panics
///
/// If the owner cannot price the operands: the parameters' tail subsidy is
/// asserted priceable when [`economics`] resolves, and the scalars are
/// chain `u64`s with `C` bounded by the parameters, so the `u128` domain
/// holds for any median a block can carry.
pub fn relay_floor_at<'id, V: ChainView<'id>>(
    view: &V,
    height: BlockHeight,
) -> Result<AtHeight<u64>, ViewRead<V::Fault>> {
    Ok(match fee_operands_at(view, height)? {
        AtHeight::Recorded(operands) => AtHeight::Recorded(
            relay_floor_from(operands, economics())
                .expect("economics() priced the tail; the floor's scalars are chain u64s"),
        ),
        AtHeight::AboveTip => AtHeight::AboveTip,
    })
}

/// The `RELAY_FLOOR_WINDOW` floors admission at `connecting` reads:
/// `F(h)` for `h` in `max(0, connecting − G) ..= connecting`, oldest
/// first. Fewer than `G + 1` only while the chain is shorter than `G`.
///
/// **Not wired yet.** The DRS-X store flip replaces
/// `shekyl_daemon_rpc`'s `fee_meets_floor` (the tip floor alone, with the
/// pre-FL-R23 `needed/50` rule) with
/// `shekyl_economics::relay_floor_admits` over this window, and deletes
/// the C++ ring.
///
/// # Errors
///
/// As [`fee_operands_at`] at any height in the window.
pub fn relay_floor_window<'id, V: ChainView<'id>>(
    view: &V,
    connecting: BlockHeight,
) -> Result<AtHeight<Vec<u64>>, ViewRead<V::Fault>> {
    let newest = connecting.to_raw();
    let oldest = newest.saturating_sub(RELAY_FLOOR_LOOKBACK as u64);
    let mut floors = Vec::with_capacity(RELAY_FLOOR_LOOKBACK + 1);
    for h in oldest..=newest {
        match relay_floor_at(view, BlockHeight::from_raw(h))? {
            AtHeight::Recorded(floor) => floors.push(floor),
            AtHeight::AboveTip => return Ok(AtHeight::AboveTip),
        }
    }
    Ok(AtHeight::Recorded(floors))
}

#[cfg(test)]
#[path = "relay_floor_tests.rs"]
mod relay_floor_tests;
