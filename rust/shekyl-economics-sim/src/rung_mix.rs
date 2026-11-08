// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The fee ladder's three rungs, and how a block's demand splits across
//! them (ESR-10, `docs/design/ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.29).
//!
//! What share of users pays each rung is not knowable before launch, so a
//! [`RungMix`] is a declared input of the run, like the Standard
//! multiplier (§4). The split is integer arithmetic: each block's demand
//! goes to the rungs by largest remainder on the **cumulative** target,
//! each rung's share of all demand so far less what it has been given. A
//! per-block largest remainder would not do: 15/80/5 of 50 is 7.5/40/2.5,
//! two equal remainders, so a fixed tie-break would hand the same rung the
//! extra transaction every block, 500 in 1 000 blocks. Carried, the
//! remainder alternates, and no rung's cumulative count is a whole
//! transaction from its share.

use core::fmt;
use core::ops::{Index, IndexMut};

use serde::Serialize;

/// Thousandths in one: a mix's shares sum to this.
const MILLI: u64 = 1_000;

/// A rung of the production fee ladder (`shekyl_economics::FeeLadder`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Rung {
    /// The relay floor `F`.
    Economy,
    /// `standard_over_economy × F`, times the run's multiplier.
    Standard,
    /// `max(priority_factor·R·C/M, standard)`.
    Priority,
}

impl Rung {
    /// Every rung, cheapest first: the order a [`PerRung`] holds them in.
    pub const ALL: [Self; 3] = [Self::Economy, Self::Standard, Self::Priority];

    /// The order one block's arrivals are admitted in: richest first. The
    /// order changes only the label of a drop, never the pool (§5.29).
    pub const ADMISSION: [Self; 3] = [Self::Priority, Self::Standard, Self::Economy];

    const fn index(self) -> usize {
        match self {
            Self::Economy => 0,
            Self::Standard => 1,
            Self::Priority => 2,
        }
    }
}

/// One value per rung, indexed by [`Rung`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct PerRung<T>([T; 3]);

impl<T> PerRung<T> {
    /// `f` of every rung, in [`Rung::ALL`]'s order.
    pub fn from_fn(mut f: impl FnMut(Rung) -> T) -> Self {
        Self(Rung::ALL.map(&mut f))
    }

    /// The values, in [`Rung::ALL`]'s order.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.0.iter()
    }
}

impl<T> Index<Rung> for PerRung<T> {
    type Output = T;
    fn index(&self, rung: Rung) -> &T {
        &self.0[rung.index()]
    }
}

impl<T> IndexMut<Rung> for PerRung<T> {
    fn index_mut(&mut self, rung: Rung) -> &mut T {
        &mut self.0[rung.index()]
    }
}

/// The share of demand each rung takes, in thousandths summing to 1 000.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RungMix {
    milli: PerRung<u64>,
}

impl RungMix {
    /// Every ordinary transaction pays Standard: what every run did before
    /// ESR-10, and what the default report runs.
    pub const ALL_STANDARD: Self = Self::of(0, MILLI, 0);

    /// The defaulted mix (`FEE_LADDER_DERIVATION.md` §5.5): 15 % Economy,
    /// 80 % Standard, 5 % Priority.
    pub const DEFAULTED: Self = Self::of(150, 800, 50);

    /// The defaulted mix with its Priority share moved to Standard.
    pub const ZERO_PRIORITY: Self = Self::of(150, 850, 0);

    /// A mix of `economy`, `standard` and `priority` thousandths. Refuses
    /// shares that do not sum to 1 000: in a constant, at compile time.
    const fn of(economy: u64, standard: u64, priority: u64) -> Self {
        assert!(
            economy <= MILLI && standard <= MILLI && priority <= MILLI,
            "a share is at most 1 000 thousandths"
        );
        assert!(
            economy + standard + priority == MILLI,
            "a rung mix's shares sum to 1 000 thousandths"
        );
        Self {
            milli: PerRung([economy, standard, priority]),
        }
    }

    /// The rung's share, in thousandths.
    #[must_use]
    pub fn milli(self, rung: Rung) -> u64 {
        self.milli[rung]
    }

    /// Whether any demand pays `rung`.
    #[must_use]
    pub fn uses(self, rung: Rung) -> bool {
        self.milli[rung] > 0
    }
}

impl fmt::Display for RungMix {
    /// `E/S/P` in percent: `15/80/5`. A share that is not a whole percent
    /// prints its tenths.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let percent = |milli: u64| {
            if milli.is_multiple_of(10) {
                (milli / 10).to_string()
            } else {
                format!("{}.{}", milli / 10, milli % 10)
            }
        };
        write!(
            f,
            "{}/{}/{}",
            percent(self.milli[Rung::Economy]),
            percent(self.milli[Rung::Standard]),
            percent(self.milli[Rung::Priority]),
        )
    }
}

/// The cumulative state of a run's split: all demand so far, and what each
/// rung has been given of it.
#[derive(Debug, Clone, Default)]
pub(crate) struct RungSplit {
    demand: u128,
    given: PerRung<u128>,
}

impl RungSplit {
    /// Split one block's `demand` by `mix`. The shares sum to `demand`, and
    /// after the block each rung has been given its share of all demand so
    /// far to within one transaction.
    pub(crate) fn split(&mut self, mix: RungMix, demand: u64) -> PerRung<u64> {
        self.demand += u128::from(demand);
        // What each rung is owed, in thousandths of a transaction: its share
        // of all demand so far, less what it has been given. The owed sum to
        // `demand` thousand exactly, because the shares sum to 1 000 and the
        // given sum to all demand before this block.
        let owed = PerRung::from_fn(|rung| {
            let target = self.demand * u128::from(mix.milli(rung));
            let given = self.given[rung] * u128::from(MILLI);
            i128::try_from(target).expect("a run's demand fits")
                - i128::try_from(given).expect("a run's demand fits")
        });
        let milli = i128::from(MILLI);
        let mut shares = PerRung::from_fn(|rung| {
            u64::try_from(owed[rung].max(0) / milli).expect("at most the block's demand")
        });
        let given: u64 = shares.iter().sum();
        // The remainders, largest first; an equal remainder goes to the
        // cheaper rung.
        let mut order = Rung::ALL;
        order.sort_by(|&a, &b| {
            let rem = |rung: Rung| owed[rung] - i128::from(shares[rung]) * milli;
            rem(b).cmp(&rem(a)).then(a.cmp(&b))
        });
        // The floors never pass the demand. A rung is owed less than nothing
        // only when it was given ahead of its share, and every rung is under
        // one transaction from its share, so the rungs ahead are under one in
        // all (were they more, the rest would be more than one behind).
        assert!(
            given <= demand,
            "the floors {given} passed the block's demand {demand}"
        );
        for &rung in order
            .iter()
            .take(usize::try_from(demand - given).expect("small"))
        {
            shares[rung] += 1;
        }
        for rung in Rung::ALL {
            self.given[rung] += u128::from(shares[rung]);
        }
        shares
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mix_prints_its_percentages() {
        assert_eq!(RungMix::DEFAULTED.to_string(), "15/80/5");
        assert_eq!(RungMix::ZERO_PRIORITY.to_string(), "15/85/0");
        assert_eq!(RungMix::ALL_STANDARD.to_string(), "0/100/0");
        assert_eq!(RungMix::of(125, 870, 5).to_string(), "12.5/87/0.5");
    }

    #[test]
    #[should_panic(expected = "sum to 1 000")]
    fn a_mix_that_does_not_sum_to_one_thousand_is_refused() {
        let _ = RungMix::of(150, 800, 49);
    }

    /// All-Standard gives every transaction to Standard, every block: the
    /// default report's demand, unchanged (P1).
    #[test]
    fn all_standard_gives_standard_everything() {
        let mut split = RungSplit::default();
        for demand in [0, 1, 50, 7, 2_347_813] {
            let shares = split.split(RungMix::ALL_STANDARD, demand);
            assert_eq!(shares, PerRung([0, demand, 0]));
        }
    }

    /// The registered mix on the baseline's 50: 7.5/40/2.5 alternates
    /// 8/40/2 and 7/40/3, where a per-block split would give 8/40/2 every
    /// block.
    #[test]
    fn the_remainder_is_carried_not_tie_broken_every_block() {
        let mut split = RungSplit::default();
        assert_eq!(split.split(RungMix::DEFAULTED, 50), PerRung([8, 40, 2]));
        assert_eq!(split.split(RungMix::DEFAULTED, 50), PerRung([7, 40, 3]));
        assert_eq!(split.split(RungMix::DEFAULTED, 50), PerRung([8, 40, 2]));
    }

    /// Demand series of the shapes the scenarios' schedules take, each with
    /// the drift it is held to over a 1 000-block span, in thousandths of a
    /// transaction. Constant, stepped and cyclic demand hold the brief's one
    /// transaction on the registered mixes. A demand that grows or wanders
    /// between blocks, or a mix that is not registered, is held to
    /// the bound the split proves, under two: each rung is under one
    /// transaction from its share at both ends of the span. Measured on the
    /// registered scenarios over 60 years, only sustained growth's 15/80/5
    /// passes one, at 1.15 (Priority).
    fn demand_series() -> Vec<(&'static str, Vec<u64>, i128)> {
        let blocks = 20_000u64;
        let one = i128::from(MILLI);
        let under_two = 2 * i128::from(MILLI) - 1;
        vec![
            ("constant 50", vec![50; 20_000], one),
            (
                "step 50 to 150",
                (0..blocks)
                    .map(|b| if b < 7_000 { 50 } else { 150 })
                    .collect(),
                one,
            ),
            (
                "cycle 15/150",
                (0..blocks)
                    .map(|b| if (b / 997) % 2 == 0 { 15 } else { 150 })
                    .collect(),
                one,
            ),
            (
                "growing",
                (0..blocks).map(|b| 50 + b / 37).collect(),
                under_two,
            ),
            (
                "sparse",
                (0..blocks).map(|b| u64::from(b % 3 == 0)).collect(),
                under_two,
            ),
            (
                "wandering",
                (0..blocks).map(|b| (b * 7_919 + 13) % 101).collect(),
                under_two,
            ),
        ]
    }

    /// The shares sum to the block's demand every block; each rung stays
    /// under one transaction from its share of all demand so far; and over
    /// any 1 000-block span no rung drifts past its series' bound.
    #[test]
    fn the_split_sums_to_demand_and_no_rung_drifts() {
        // The registered mixes, then two that are not: an unregistered mix
        // is held to the proven bound on every series.
        let mixes = [
            (RungMix::ALL_STANDARD, true),
            (RungMix::DEFAULTED, true),
            (RungMix::ZERO_PRIORITY, true),
            (RungMix::of(333, 333, 334), false),
            (RungMix::of(1, 998, 1), false),
        ];
        const SPAN: usize = 1_000;
        for (mix, registered) in mixes {
            for (name, series, bound) in demand_series() {
                let bound = if registered {
                    bound
                } else {
                    2 * i128::from(MILLI) - 1
                };
                let mut split = RungSplit::default();
                // Thousandths given less thousandths owed, per rung, after
                // each block: the drift over a span is the change in this.
                let mut lead: Vec<PerRung<i128>> = vec![PerRung::default()];
                let mut demand_so_far = 0u128;
                for (block, &demand) in series.iter().enumerate() {
                    let shares = split.split(mix, demand);
                    assert_eq!(
                        shares.iter().sum::<u64>(),
                        demand,
                        "{mix} {name}: block {block} shares {shares:?} do not sum to {demand}"
                    );
                    demand_so_far += u128::from(demand);
                    lead.push(PerRung::from_fn(|rung| {
                        i128::try_from(split.given[rung] * u128::from(MILLI)).expect("fits")
                            - i128::try_from(demand_so_far * u128::from(mix.milli(rung)))
                                .expect("fits")
                    }));
                }
                for rung in Rung::ALL {
                    for (at, now) in lead.iter().enumerate() {
                        assert!(
                            now[rung].abs() < i128::from(MILLI),
                            "{mix} {name}: {rung:?} is a transaction from its share at block {at}"
                        );
                    }
                    for window in lead.windows(SPAN + 1) {
                        let drift = (window[SPAN][rung] - window[0][rung]).abs();
                        assert!(
                            drift <= bound,
                            "{mix} {name}: {rung:?} drifted {drift}/1000 over {SPAN} blocks"
                        );
                    }
                }
            }
        }
    }
}
