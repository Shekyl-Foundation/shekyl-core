// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The submit path's fee gate, until the DRS-X store flip.
//!
//! The predicate is [`shekyl_economics::relay_floor_admits`] (CEN-M3): a fee
//! clears the minimum of the floors it is shown, on the lattice, at zero
//! slack. An empty window refuses.
//!
//! The Rust pool shim shows the door's window, so the engine and the pool
//! give one transaction one fee verdict. The C++ shim shows none, and the
//! gate then admits on the snapshot tip floor alone — the same predicate
//! over one element. A short window is never looser, so a fee that clears
//! the tip clears the commit's window, and a fee that clears only the
//! window's minimum is refused on the one-floor path. The wallet re-quotes.
//! The flip deletes the C++ shim; the window is all that remains.

use shekyl_economics::relay_floor_admits;

use crate::submit::facts::SubmitFacts;

/// The engine's fee gate over `facts`.
///
/// The window, when the shim supplied one; the tip floor alone when it did
/// not.
#[must_use]
pub fn fee_clears(tx_weight: u64, fee: u64, facts: &SubmitFacts) -> bool {
    match facts.fee_floor_window.as_deref() {
        Some(floors) => relay_floor_admits(fee, tx_weight, floors),
        None => fee_meets_floor(tx_weight, fee, facts.fee_per_byte),
    }
}

/// Whether `fee` clears the tip floor for `tx_weight`.
///
/// One floor, the predicate the commit runs. A requirement that leaves
/// `u64` refuses: no fee can state it.
#[must_use]
pub fn fee_meets_floor(tx_weight: u64, fee: u64, fee_per_byte: u64) -> bool {
    relay_floor_admits(fee, tx_weight, &[fee_per_byte])
}
