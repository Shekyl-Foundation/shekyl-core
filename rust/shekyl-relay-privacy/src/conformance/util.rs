// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

/// Narrow a draw already bounded by a `usize`-derived range.
pub(crate) fn usize_from(v: u64) -> usize {
    usize::try_from(v).expect("draw was bounded by a usize-derived range")
}

/// Hard cap on simulated stem length, so a pathological fluff probability
/// cannot make a trial run forever. Far above any reachable stem: at the
/// inherited q = 20% the expected length is 5.
pub(crate) const MAX_SIMULATED_HOPS: usize = 4_096;
