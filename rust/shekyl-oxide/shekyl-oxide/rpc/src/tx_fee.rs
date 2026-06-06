// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Canonical dust threshold for Phase 2a fee-relative output folding.
//!
//! Per `PHASE_2A_SEND_PATH.md` §3.10.2: one function, two sites
//! (coin selection + engine build). `MARGINAL_INPUT_WEIGHT` is
//! provisional until the `fcmp_proof_size` KAT lands in 2a-3.

use crate::FeeRate;

/// Dimensionless dust multiplier (`K_DUST = 1` per §3.10.2).
pub const K_DUST: u64 = 1;

/// Weight one additional input adds at `D_ref = MAX_TREE_DEPTH (24)`.
///
/// Provisional stub: `32 + 32 + 3385 + 8` (hybrid auth, input framing,
/// varint overhead), with zero FCMP proof increment until the 2a-3 KAT
/// replaces this. Reopen iff the KAT moves this by more than a token amount.
pub const MARGINAL_INPUT_WEIGHT: usize = 32 + 32 + 3385 + 8;

/// Fee-relative dust boundary (§3.10.2 / §3.8.5): an amount is dust when it is
/// strictly below the cost to spend one additional input at `rate`.
///
/// Canonical predicate: `amount < dust_threshold(rate)`.
#[must_use]
pub fn dust_threshold(rate: &FeeRate) -> u64 {
    K_DUST * rate.calculate_fee_from_weight(MARGINAL_INPUT_WEIGHT)
}
