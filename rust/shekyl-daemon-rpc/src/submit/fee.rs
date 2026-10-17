// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The submit path's fee gate, until the DRS-X store flip.
//!
//! `fee_per_byte` is the tip floor from the Phase-B snapshot. Admission
//! is `shekyl_economics::relay_floor_admits` over that one floor: the
//! predicate the commit runs, on a one-element window. A short window is
//! never looser, so a fee that clears the tip clears the commit's window,
//! and a fee that clears only the window's minimum is refused here. The
//! wallet re-quotes. The flip passes `shekyl_chain_rules::relay_floor_window`
//! in place of the one floor.

use shekyl_economics::relay_floor_admits;

/// Whether `fee` clears the tip floor for `tx_weight`.
///
/// A requirement that leaves `u64` refuses: no fee can state it.
pub fn fee_meets_floor(tx_weight: u64, fee: u64, fee_per_byte: u64) -> bool {
    relay_floor_admits(fee, tx_weight, &[fee_per_byte])
}
