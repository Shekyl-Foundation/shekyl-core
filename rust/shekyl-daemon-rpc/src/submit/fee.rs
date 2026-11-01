// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The submit path's fee gate (DX-Q10).
//!
//! The predicate is [`shekyl_economics::relay_floor_admits`] (CEN-M3): a fee
//! clears the minimum of the floors it is shown, on the lattice, at zero
//! slack. An empty window refuses. The pool shim supplies the relay-floor
//! window, and a snapshot with none is refused.

use shekyl_economics::relay_floor_admits;

use crate::submit::facts::SubmitFacts;

/// The engine's fee gate over `facts`.
///
/// The relay-floor window the shim supplied. No window refuses.
#[must_use]
pub fn fee_clears(tx_weight: u64, fee: u64, facts: &SubmitFacts) -> bool {
    match facts.fee_floor_window.as_deref() {
        Some(floors) => relay_floor_admits(fee, tx_weight, floors),
        None => false,
    }
}
