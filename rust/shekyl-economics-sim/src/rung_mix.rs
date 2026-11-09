// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The fee ladder's three rungs, how a block's demand splits across them,
//! and what each rung's traffic comes to (ESR-10,
//! `docs/design/ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.29).
//!
//! What share of users pays each rung is not knowable before launch, so a
//! [`RungMix`] is a declared input of the run, like the Standard
//! multiplier (§4). The split is integer arithmetic: each block's demand
//! goes to the rungs by largest remainder on the **cumulative** target. A
//! per-block largest remainder would not do: 15/80/5 of 50 is 7.5/40/2.5,
//! two equal remainders, so a fixed tie-break would hand the same rung the
//! extra transaction every block, 500 in 1 000 blocks. Carried, the
//! remainder alternates, and no rung's cumulative count is a whole
//! transaction from its share.

use core::fmt;
use core::ops::{Add, AddAssign, Index, IndexMut};

use serde::Serialize;

use crate::fee_model::MILLI;

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

    /// The order one block's arrivals reach the pool: richest first. **A
    /// declared assumption** (§4 of the design document): the order users'
    /// transactions of different rungs reach a node within one block's
    /// interval is not knowable. Each arrival is admitted by CEN-M10's
    /// `make_room` in turn, so the order can change the pool when the rungs
    /// weigh differently, as they do by their fees' varints
    /// (`block_space_tests.rs` shows both cases). Its bias: a richer arrival
    /// is never refused for a cheaper one that reached the pool first in the
    /// same block.
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

    /// The sum over the rungs of `f` of each value.
    pub fn sum<N: core::iter::Sum<N>>(&self, f: impl Fn(&T) -> N) -> N {
        self.0.iter().map(f).sum()
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

/// Rung by rung: a year's traffic gathers its blocks'.
impl<T: AddAssign<U>, U> AddAssign<PerRung<U>> for PerRung<T> {
    fn add_assign(&mut self, other: PerRung<U>) {
        for (total, part) in self.0.iter_mut().zip(other.0) {
            *total += part;
        }
    }
}

/// The share of demand each rung takes, in thousandths summing to
/// [`MILLI`].
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
    /// shares that do not sum to [`MILLI`]: in a constant, at compile time.
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
        const MILLI_PER_PERCENT: u64 = MILLI / 100;
        let percent = |milli: u64| {
            let (whole, tenths) = (milli / MILLI_PER_PERCENT, milli % MILLI_PER_PERCENT);
            if tenths == 0 {
                whole.to_string()
            } else {
                format!("{whole}.{tenths}")
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

/// The state a run's split carries from block to block: what each rung is
/// owed, in thousandths of a transaction. Its share of all demand so far,
/// less what it has been given.
///
/// The owed sum to zero after every block, because the shares sum to
/// [`MILLI`] and the given sum to the demand. Each is under one transaction
/// either way ([`Self::split`]), so the state stays within `±MILLI` however
/// long the run.
#[derive(Debug, Clone, Default)]
pub(crate) struct RungSplit {
    owed: PerRung<i64>,
}

impl RungSplit {
    /// Split one block's `demand` by `mix`. The shares sum to `demand`, and
    /// after the block each rung has been given its share of all demand so
    /// far to within one transaction.
    ///
    /// Each rung is first given the whole transactions it is owed, then the
    /// rest go one each to the largest remainders, an equal remainder to the
    /// cheaper rung. The floors never pass the demand: a rung is owed less
    /// than nothing only when it was given ahead of its share, and every rung
    /// is under one transaction from its share, so the rungs ahead are under
    /// one in all (were they more, the rest would be more than one behind).
    pub(crate) fn split(&mut self, mix: RungMix, demand: u64) -> PerRung<u64> {
        let one = i64::try_from(MILLI).expect("a thousand fits");
        let owed = PerRung::from_fn(|rung| {
            let due = i64::try_from(demand * mix.milli(rung)).expect("one block's demand fits");
            self.owed[rung] + due
        });
        let mut shares = PerRung::from_fn(|rung| {
            u64::try_from(owed[rung].max(0) / one).expect("a floor is not negative")
        });
        let floors = shares.sum(|&share| share);
        assert!(
            floors <= demand,
            "the floors {floors} passed the block's demand {demand}"
        );
        let remainder = |rung: Rung| owed[rung] - i64::try_from(shares[rung]).expect("small") * one;
        let mut order = Rung::ALL;
        order.sort_by(|&a, &b| remainder(b).cmp(&remainder(a)).then(a.cmp(&b)));
        let leftover = usize::try_from(demand - floors).expect("fewer than the rungs");
        for &rung in order.iter().take(leftover) {
            shares[rung] += 1;
        }
        self.owed = PerRung::from_fn(|rung| {
            owed[rung] - i64::try_from(shares[rung]).expect("one block's demand fits") * one
        });
        debug_assert_eq!(self.owed.sum(|&owed| owed), 0, "the owed sum to zero");
        shares
    }
}

/// One rung's traffic: what it demanded, what the blocks carried, what left
/// the pool unserved and how, and what the carried paid. `u64` for one
/// block ([`crate::block_space::Filled`]), `u128` summed over a year
/// ([`crate::stage2::A1YearAgg`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct RungTraffic<N> {
    /// Transactions the scenario's schedule offered on this rung.
    pub demand_txs: N,
    /// Transactions the blocks listed: what the fill rule admitted (ESR-6),
    /// the count the fees were paid on.
    pub carried_txs: N,
    /// Transactions whose reference left CEN-I11's window unserved (ESR-17).
    pub expired_txs: N,
    /// Transactions CEN-M10 evicted: for an arrival paying more per weight,
    /// or to bring the pool within its limit.
    pub evicted_txs: N,
    /// Arrivals the pool refused: no strictly cheaper entries freed room.
    pub refused_txs: N,
    /// The carried transactions' fees, atomic units.
    pub fees_atomic: N,
}

impl<N: Copy + Add<Output = N>> RungTraffic<N> {
    /// Transactions that left the pool unserved: expired, evicted or refused.
    #[must_use]
    pub fn dropped_txs(&self) -> N {
        self.expired_txs + self.evicted_txs + self.refused_txs
    }
}

/// A year gathers a block's traffic.
impl AddAssign<RungTraffic<u64>> for RungTraffic<u128> {
    fn add_assign(&mut self, block: RungTraffic<u64>) {
        self.demand_txs += u128::from(block.demand_txs);
        self.carried_txs += u128::from(block.carried_txs);
        self.expired_txs += u128::from(block.expired_txs);
        self.evicted_txs += u128::from(block.evicted_txs);
        self.refused_txs += u128::from(block.refused_txs);
        self.fees_atomic += u128::from(block.fees_atomic);
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

    /// Blocks in a demand series.
    const SERIES_BLOCKS: u64 = 20_000;

    /// The span a rung's drift is measured over, in blocks.
    const DRIFT_SPAN: usize = 1_000;

    /// The brief's bound on a rung's drift over a span: one transaction, in
    /// thousandths.
    const ONE_TX: i64 = 1_000;

    /// The bound the split proves for any demand: each rung is under one
    /// transaction from its share at both ends of a span, so it drifts under
    /// two across it.
    const UNDER_TWO_TXS: i64 = 2 * ONE_TX - 1;

    /// Demand series of the shapes the scenarios' schedules take, each with
    /// the drift it is held to over [`DRIFT_SPAN`] blocks. Constant, stepped
    /// and cyclic demand hold the brief's [`ONE_TX`] on the registered
    /// mixes. A demand that grows or wanders between blocks, or a mix that
    /// is not registered, is held to [`UNDER_TWO_TXS`]. Measured on the
    /// registered scenarios over 60 years, only sustained growth's 15/80/5
    /// passes one, at 1.15 (Priority).
    fn demand_series() -> Vec<(&'static str, Vec<u64>, i64)> {
        let blocks = 0..SERIES_BLOCKS;
        vec![
            ("constant 50", blocks.clone().map(|_| 50).collect(), ONE_TX),
            (
                "step 50 to 150",
                blocks
                    .clone()
                    .map(|b| if b < 7_000 { 50 } else { 150 })
                    .collect(),
                ONE_TX,
            ),
            (
                "cycle 15/150",
                blocks
                    .clone()
                    .map(|b| if (b / 997) % 2 == 0 { 15 } else { 150 })
                    .collect(),
                ONE_TX,
            ),
            (
                "growing",
                blocks.clone().map(|b| 50 + b / 37).collect(),
                UNDER_TWO_TXS,
            ),
            (
                "sparse",
                blocks.clone().map(|b| u64::from(b % 3 == 0)).collect(),
                UNDER_TWO_TXS,
            ),
            (
                "wandering",
                blocks.map(|b| (b * 7_919 + 13) % 101).collect(),
                UNDER_TWO_TXS,
            ),
        ]
    }

    /// The shares sum to the block's demand every block; each rung stays
    /// under one transaction from its share of all demand so far; and over
    /// any [`DRIFT_SPAN`] blocks no rung drifts past its series' bound. The
    /// lead is measured from the shares the split returns, independently of
    /// the state it carries.
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
        for (mix, registered) in mixes {
            for (name, series, bound) in demand_series() {
                let bound = if registered { bound } else { UNDER_TWO_TXS };
                let mut split = RungSplit::default();
                // Thousandths given less thousandths owed, per rung, after
                // each block: the drift over a span is the change in this.
                let mut lead: Vec<PerRung<i128>> = vec![PerRung::default()];
                let (mut demand_so_far, mut given) = (0u128, PerRung::<u128>::default());
                for (block, &demand) in series.iter().enumerate() {
                    let shares = split.split(mix, demand);
                    assert_eq!(
                        shares.sum(|&share| share),
                        demand,
                        "{mix} {name}: block {block} shares {shares:?} do not sum to {demand}"
                    );
                    demand_so_far += u128::from(demand);
                    for rung in Rung::ALL {
                        given[rung] += u128::from(shares[rung]);
                    }
                    lead.push(PerRung::from_fn(|rung| {
                        i128::try_from(given[rung] * u128::from(MILLI)).expect("fits")
                            - i128::try_from(demand_so_far * u128::from(mix.milli(rung)))
                                .expect("fits")
                    }));
                }
                for rung in Rung::ALL {
                    for (at, now) in lead.iter().enumerate() {
                        assert!(
                            now[rung].abs() < i128::from(ONE_TX),
                            "{mix} {name}: {rung:?} is a transaction from its share at block {at}"
                        );
                    }
                    for window in lead.windows(DRIFT_SPAN + 1) {
                        let drift = (window[DRIFT_SPAN][rung] - window[0][rung]).abs();
                        assert!(
                            drift <= i128::from(bound),
                            "{mix} {name}: {rung:?} drifted {drift}/1000 over {DRIFT_SPAN} blocks"
                        );
                    }
                }
            }
        }
    }

    /// A year's traffic is its blocks', rung by rung, and what was dropped
    /// is the three ways out.
    #[test]
    fn a_year_gathers_its_blocks_traffic() {
        let block = RungTraffic::<u64> {
            demand_txs: 9,
            carried_txs: 5,
            expired_txs: 1,
            evicted_txs: 2,
            refused_txs: 1,
            fees_atomic: 700,
        };
        let mut year = PerRung::<RungTraffic<u128>>::default();
        year += PerRung::from_fn(|rung| {
            if rung == Rung::Standard {
                block
            } else {
                RungTraffic::default()
            }
        });
        year += PerRung::from_fn(|_| block);
        assert_eq!(year[Rung::Standard].carried_txs, 10);
        assert_eq!(year[Rung::Economy].fees_atomic, 700);
        assert_eq!(year[Rung::Standard].dropped_txs(), 8);
        assert_eq!(year.sum(|rung| rung.demand_txs), 36);
    }
}
