// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `U1b`'s reading B (`ARCHIVAL_SHARD_T_DERIVATION.md` §9.3a): how many
//! drawable pairs one floor device can answer challenge reads for, per
//! settlement epoch.
//!
//! **It is not a bound on `W`.** Reading A ([`crate::ceiling::floor_device_read`])
//! is the one `U1b` reading that bears on the shard length. This one is an
//! input to the participation floor (gates 4 and 5): what an operator on the
//! floor device can hold. It is reported as the **maximum sustainable
//! holding**, across a table of holdings.
//!
//! No holding is the anchor. `MAX_HOLDINGS_SHARDS` bounds one record's list,
//! not an operator, who can post another record (the `L2` ruling, §3), so the
//! list bound is one row of [`HOLDING_TABLE`] and nothing more.
//!
//! # The computation
//!
//! With one read in flight — how the soak arm fetches — the device completes
//! `c = completions / Σ elapsed` reads per second. A completion is a success
//! inside [`DEADLINE`], the same miss definition [`crate::ceiling`] uses; a
//! miss costs the time it took and delivers nothing. Over an epoch that is
//! `R = c × epoch` reads, and a holding of `H` pairs draws
//! [`CHALLENGE_READS_PER_PAIR`]` × H` of them. `H` is sustainable when that
//! load is at most `R`.
//!
//! Every comparison is exact integer arithmetic on milliseconds, so a row's
//! verdict cannot turn on rounding.
//!
//! # What it does not count
//!
//! - **Organic and band-2 reads.** Nothing in the tree gives them a rate, so
//!   they are not load here; the headroom a row leaves is what is left for
//!   them.
//! - **Concurrency.** One read in flight is a floor on capacity: the server
//!   admits concurrent reads, and `SPIKE-F-11` found reader concurrency does
//!   not materially degrade a persona.

use std::time::Duration;

use shekyl_archival_retention::constants::{
    CHALLENGES_PER_PAIR_PER_EPOCH, SETTLEMENT_EPOCH_BLOCKS,
};
use shekyl_difficulty::T_SECONDS;
use shekyl_types::archival::MAX_HOLDINGS_SHARDS;

use crate::ceiling::DEADLINE;
use crate::measure::Observation;

/// One settlement epoch of wall-clock time: its blocks at the target block
/// time.
pub const EPOCH: Duration = Duration::from_secs(SETTLEMENT_EPOCH_BLOCKS * T_SECONDS);

/// Challenge reads one drawable pair draws per epoch.
pub const CHALLENGE_READS_PER_PAIR: u32 = CHALLENGES_PER_PAIR_PER_EPOCH;

/// The list bound on one record's holdings (`MAX_HOLDINGS_SHARDS`). A row of
/// the table, never its anchor.
pub const LIST_BOUND: usize = MAX_HOLDINGS_SHARDS;

/// The holdings reading B reports, in pairs. Fixed before any observation:
/// a small operator's few shards up through several times the list bound,
/// because a holding is not limited to one record.
pub const HOLDING_TABLE: [usize; 9] = [1, 16, 128, 512, 1_024, 2_048, LIST_BOUND, 8_192, 16_384];

/// What one day's attempts at one object say about serving capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capacity {
    completions: usize,
    busy: Duration,
}

fn wide(n: usize) -> u128 {
    u128::try_from(n).unwrap_or(u128::MAX)
}

/// A count as a float, for display. Saturates past `u32::MAX`, which no
/// count here reaches; no verdict reads it.
fn shown(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

impl Capacity {
    /// The capacity the attempts show, with one read in flight.
    ///
    /// `None` when there is nothing to divide by: no attempts, or attempts
    /// that took no time.
    #[must_use]
    pub fn of(observations: &[Observation]) -> Option<Self> {
        let completions = observations
            .iter()
            .filter(|o| o.is_success() && o.elapsed <= DEADLINE)
            .count();
        let busy = observations
            .iter()
            .fold(Duration::ZERO, |sum, o| sum.saturating_add(o.elapsed));
        (busy.as_millis() > 0).then_some(Self { completions, busy })
    }

    /// Completed reads per second. For display; no verdict reads it.
    #[must_use]
    pub fn reads_per_second(&self) -> f64 {
        shown(self.completions) / self.busy.as_secs_f64()
    }

    /// Completed reads per epoch, rounded down.
    #[must_use]
    pub fn reads_per_epoch(&self) -> u128 {
        wide(self.completions) * EPOCH.as_millis() / self.busy.as_millis()
    }

    /// Whether a holding of `pairs` is sustainable: its challenge reads per
    /// epoch are at most the reads the device completes in one.
    #[must_use]
    pub fn sustains(&self, pairs: usize) -> bool {
        u128::from(CHALLENGE_READS_PER_PAIR) * wide(pairs) * self.busy.as_millis()
            <= wide(self.completions) * EPOCH.as_millis()
    }

    /// The largest sustainable holding, in pairs.
    #[must_use]
    pub fn max_sustainable_holding(&self) -> u128 {
        wide(self.completions) * EPOCH.as_millis()
            / (u128::from(CHALLENGE_READS_PER_PAIR) * self.busy.as_millis())
    }

    /// The share of one epoch's reads a holding of `pairs` draws. Over 1.0
    /// is not sustainable; under it, the rest is the room left for organic
    /// and band-2 reads. For display; [`Self::sustains`] is the verdict.
    #[must_use]
    pub fn utilization(&self, pairs: usize) -> f64 {
        let load = f64::from(CHALLENGE_READS_PER_PAIR) * shown(pairs);
        let reads = self.reads_per_second() * EPOCH.as_secs_f64();
        load / reads
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::measure::FailureKind;

    fn ok(secs: u64) -> Observation {
        Observation::success(Duration::from_secs(secs))
    }

    /// The epoch is the consensus one: 10,000 blocks of 120 s.
    #[test]
    fn the_epoch_is_ten_thousand_blocks_of_two_minutes() {
        assert_eq!(EPOCH, Duration::from_secs(1_200_000));
        assert_eq!(CHALLENGE_READS_PER_PAIR, 3);
    }

    /// Ten reads of 100 s each: 0.01 reads per second, 12,000 per epoch,
    /// 4,000 pairs. The threshold sits exactly there: 4,000 is sustainable,
    /// 4,001 and the list bound are not.
    #[test]
    fn the_threshold_is_three_reads_per_pair_against_the_epochs_reads() {
        let observations: Vec<Observation> = (0..10).map(|_| ok(100)).collect();
        let capacity = Capacity::of(&observations).expect("attempts");
        assert_eq!(capacity.reads_per_epoch(), 12_000);
        assert_eq!(capacity.max_sustainable_holding(), 4_000);
        assert!(capacity.sustains(4_000));
        assert!(!capacity.sustains(4_001));
        assert!(!capacity.sustains(LIST_BOUND));
        assert!((capacity.utilization(4_000) - 1.0).abs() < 1e-12);
        assert!((capacity.reads_per_second() - 0.01).abs() < 1e-12);
    }

    /// A miss costs the device its time and serves nothing, and a success
    /// past the deadline is a miss.
    #[test]
    fn a_miss_costs_time_and_delivers_nothing() {
        let observations = [
            ok(100),
            ok(100),
            ok(150), // past the deadline: a miss
            Observation::failure(Duration::from_secs(50), FailureKind::Circuit),
        ];
        let capacity = Capacity::of(&observations).expect("attempts");
        // Two completions in 400 s: 6,000 reads an epoch, 2,000 pairs.
        assert_eq!(capacity.reads_per_epoch(), 6_000);
        assert_eq!(capacity.max_sustainable_holding(), 2_000);

        let all_missed = [Observation::failure(
            Duration::from_secs(30),
            FailureKind::Timeout,
        )];
        let none = Capacity::of(&all_missed).expect("attempts");
        assert_eq!(none.max_sustainable_holding(), 0);
        assert!(!none.sustains(1));
        assert!(none.sustains(0));
    }

    #[test]
    fn nothing_to_divide_by_is_no_capacity() {
        assert_eq!(Capacity::of(&[]), None);
        assert_eq!(Capacity::of(&[ok(0)]), None);
    }

    /// A worked example through the whole path, on a committed file that is
    /// not `U1b`'s: the W₂ PoW-on window's largest object, 306 completions
    /// in its attempts' summed time, reads 64,040 an epoch and 21,346 pairs.
    #[test]
    fn a_recorded_window_reads_through_the_same_path() {
        let file =
            include_str!("../../../docs/benchmarks/w2_ladder_interleaved_pow_on_20261001.tsv");
        let sizes = crate::ceiling::soak_ladder(file).expect("the committed file parses");
        let (bytes, largest) = sizes.iter().next_back().expect("three sizes");
        assert_eq!(*bytes, 3_326_976);
        let capacity = Capacity::of(largest).expect("attempts");
        assert_eq!(capacity.completions, 306);
        assert_eq!(capacity.reads_per_epoch(), 64_040);
        assert_eq!(capacity.max_sustainable_holding(), 21_346);
        assert!(capacity.sustains(16_384) && !capacity.sustains(21_347));
    }

    /// The table is fixed, ordered, and carries the list bound as one row
    /// among holdings above and below it.
    #[test]
    fn the_list_bound_is_a_row_not_the_anchor() {
        assert!(HOLDING_TABLE.windows(2).all(|w| w[0] < w[1]));
        assert!(HOLDING_TABLE.contains(&LIST_BOUND));
        assert!(HOLDING_TABLE.iter().any(|&h| h < LIST_BOUND));
        assert!(HOLDING_TABLE.iter().any(|&h| h > LIST_BOUND));
    }
}
