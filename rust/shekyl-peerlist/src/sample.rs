// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The disclosure draw.
//!
//! [`sample_prefix`] is the partial Fisher-Yates that `Partition::disclose`
//! and the §5a instrument both call. One function, so the measurement and
//! the list cannot drift: the same inclusive `bounded_uniform` at each
//! index, the same swap.

use shekyl_relay_privacy::rng::{bounded_uniform, RelayRng};

/// Place a uniform sample of `count` members in the prefix, in random
/// order. Returns how many were placed (`count` capped by the population).
///
/// Each step draws `bounded_uniform(rng, remaining - 1)` — an inclusive
/// bound — and swaps that member into the prefix. A later step never
/// touches an earlier choice, so the prefix is `count` distinct members
/// when the population is at least that long.
pub(crate) fn sample_prefix<T, R: RelayRng + ?Sized>(
    population: &mut [T],
    count: usize,
    rng: &mut R,
) -> usize {
    let take = count.min(population.len());
    for i in 0..take {
        let remaining = population.len() - i;
        let pick = i + usize::try_from(bounded_uniform(rng, (remaining - 1) as u64))
            .expect("the draw is bounded by the population");
        population.swap(i, pick);
    }
    take
}

#[cfg(test)]
mod tests {
    use shekyl_relay_privacy::rng::SplitMix64;

    use super::*;

    #[test]
    fn the_prefix_is_distinct_members_of_the_population() {
        let mut rng = SplitMix64::new(1);
        let mut population: Vec<usize> = (0..30).collect();
        let taken = sample_prefix(&mut population, 12, &mut rng);
        assert_eq!(taken, 12);
        let mut prefix = population[..taken].to_vec();
        prefix.sort_unstable();
        prefix.dedup();
        assert_eq!(prefix.len(), 12);
        assert!(prefix.iter().all(|n| *n < 30));
    }
}
