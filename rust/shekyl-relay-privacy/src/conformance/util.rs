// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use crate::rng::RelayRng;

/// Narrow a draw already bounded by a `usize`-derived range.
pub(crate) fn usize_from(v: u64) -> usize {
    usize::try_from(v).expect("draw was bounded by a usize-derived range")
}

/// Bernoulli trial at probability `p`, matching the diffusion first-spy draw.
///
/// `p <= 0` never hits and `p >= 1` always hits. In between, the threshold
/// is `p` across `u32::MAX` and the comparison is `<=`, so `p == 1` would
/// also be certain if the short-circuit were absent.
pub(crate) fn bernoulli_unit<R: RelayRng + ?Sized>(rng: &mut R, p: f64) -> bool {
    if p <= 0.0 {
        return false;
    }
    if p >= 1.0 {
        return true;
    }
    let threshold = (p * f64::from(u32::MAX)) as u32;
    (rng.next_u64() as u32) <= threshold
}

/// Hard cap on simulated stem length, so a pathological fluff probability
/// cannot make a trial run forever. Far above any reachable stem: at the
/// inherited q = 20% the expected length is 5.
pub(crate) const MAX_SIMULATED_HOPS: usize = 4_096;
