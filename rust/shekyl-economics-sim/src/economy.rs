// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The economies' arms (`docs/design/ECONOMICS_SIM_PRODUCTION_REBASE.md`
//! §5.37, EUP-4 prep 3): what a fold changes to run an economy other than
//! production. Each arm defaults to production, so a run that names none
//! folds exactly what it folded before.
//!
//! - [`PenaltyDestination`]: C1, where the block-size penalty goes.
//! - [`BurnSignal`]: C2, what the fee burn reads.
//! - [`TemplateRule`]: which coinbase the template's fill compares.
//!
//! B (the `Fixed` volume signal), C3 (the escalation's two overrides) and
//! A-stuffed (a producer's own bodies at every block) are arms the sim
//! already had; [`crate::whole_economy`] names them beside these.

use shekyl_economics::params::SCALE;
use shekyl_economics::{
    calc_burn_pct, compute_burn_split_at, CirculatingSupply, ClosedShardCount, EconomicParams,
    PaidEmission, TxVolume,
};
use shekyl_units::AtomicUnits;

/// Where the penalty a block's weight withheld goes (C1). The penalty is the
/// reward the weight withheld: production's pre-penalty emission less the
/// paid reward. The stakers' part is paid at the block; the rest stays
/// unminted, as production leaves all of it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PenaltyDestination {
    /// Production: none of it is paid; it stays in the curve.
    #[default]
    Deferred,
    /// All of it to the staker pool.
    All,
    /// The share `x` of it, `x` the block's excess over its median as a
    /// fraction of the median: nothing at the median, all of it at twice.
    GraduatedUp,
    /// The share `1 − x`: all of it just past the median, nothing at twice.
    GraduatedDown,
    /// Half of it.
    Flat50,
}

impl PenaltyDestination {
    /// Every destination, production first.
    #[cfg(test)]
    pub(crate) const ALL: [Self; 5] = [
        Self::Deferred,
        Self::All,
        Self::GraduatedUp,
        Self::GraduatedDown,
        Self::Flat50,
    ];

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Deferred => "deferred",
            Self::All => "all",
            Self::GraduatedUp => "graduated up",
            Self::GraduatedDown => "graduated down",
            Self::Flat50 => "flat 50 %",
        }
    }

    /// The stakers' part of `penalty`, for a block of `block_weight` judged
    /// at the effective median `median`. Floored, so the part is never more
    /// than the penalty and the rest is never negative.
    #[must_use]
    pub(crate) fn stakers_part(self, penalty: u64, block_weight: u64, median: u64) -> u64 {
        if penalty == 0 {
            return 0;
        }
        let median = median.max(1);
        let excess = block_weight.saturating_sub(median).min(median);
        let of = |numerator: u64| -> u64 {
            u64::try_from(u128::from(penalty) * u128::from(numerator) / u128::from(median))
                .expect("a part of the penalty fits the penalty")
        };
        match self {
            Self::Deferred => 0,
            Self::All => penalty,
            Self::GraduatedUp => of(excess),
            Self::GraduatedDown => of(median - excess),
            Self::Flat50 => penalty / 2,
        }
    }
}

/// What the fee burn reads (C2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BurnSignal {
    /// Production: the volume signal's operand, the window's count (or
    /// the arm [`crate::volume_window::VolumeSignal`] names).
    #[default]
    Count,
    /// The window's fees paid per block, in units of each block's own
    /// Standard fee, against a baseline of the count's baseline in those
    /// units (§5.37, C2).
    FeesPaid,
}

/// One block's fees in units of its own Standard fee, `SCALE` to a unit:
/// the figure C2's window sums. A block whose Standard fee is zero reads
/// its fees as none.
#[must_use]
pub(crate) fn fee_units_scaled(fees_atomic: u64, standard_fee_atomic: u64) -> u64 {
    if standard_fee_atomic == 0 {
        return 0;
    }
    u64::try_from(u128::from(fees_atomic) * u128::from(SCALE) / u128::from(standard_fee_atomic))
        .expect("a block's fees in Standard-fee units fit the window's u64 sum")
}

/// C2's burn: production's formula, read on the window of fees paid in
/// Standard-fee units against the count's baseline in the same units.
#[must_use]
pub(crate) fn fees_paid_burn_pct(
    fee_units: TxVolume,
    supply: CirculatingSupply,
    params: &EconomicParams,
) -> u64 {
    let baseline = params
        .tx_volume_baseline
        .checked_mul(SCALE)
        .expect("the baseline in scaled units fits u64");
    calc_burn_pct(
        fee_units,
        baseline,
        supply.to_raw(),
        params.emission_curve_asymptote,
        params.burn_base_rate,
        params.burn_cap,
    )
}

/// `paid` with its fee burn split at `burn_pct` instead of the count's:
/// production's split ([`compute_burn_split_at`]) at the block's closed-shard
/// count, and the owed and accrual sums it composes.
#[must_use]
pub(crate) fn with_burn_pct(
    paid: PaidEmission,
    total_fees: u64,
    burn_pct: u64,
    closed_shards: ClosedShardCount,
    params: &EconomicParams,
) -> PaidEmission {
    let fee_burn = compute_burn_split_at(total_fees, burn_pct, closed_shards, params);
    let owed = paid
        .split
        .miner_emission
        .checked_add(fee_burn.miner_fee_income)
        .expect("the miner's emission and fee income fit one coinbase");
    let accrual = paid
        .split
        .staker_emission
        .checked_add(fee_burn.staker_pool_amount)
        .expect("the stakers' emission and pool fit u64");
    PaidEmission {
        fee_burn,
        owed: AtomicUnits::from_raw(owed),
        accrual: AtomicUnits::from_raw(accrual),
        ..paid
    }
}

/// Which coinbase the template's fill compares.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TemplateRule {
    /// Production's `Fill::admit`: the gross coinbase, the penalised reward
    /// plus every fee.
    #[default]
    Gross,
    /// A body is listed only while the miner's share of its fee covers the
    /// miner's share of the reward it costs: `(S − b)·fee ≥ (S − σ)·δ`, with
    /// σ the staker emission share and `b` the burn at that height.
    MinerNet,
}

impl TemplateRule {
    pub(crate) const ALL: [Self; 2] = [Self::Gross, Self::MinerNet];

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Gross => "gross",
            Self::MinerNet => "miner's net",
        }
    }

    /// The fee production's fill is offered for a body that pays `fee`.
    ///
    /// Gross: the fee. Miner's net: `⌊fee·(S − b)/(S − σ)⌋`. The penalty `δ`
    /// a body adds is an integer, so `(S − σ)·δ ≤ (S − b)·fee` exactly when
    /// `δ ≤ ⌊fee·(S − b)/(S − σ)⌋`: the gross test on this fee is the
    /// miner's-net test on the body's own fee, body by body. The factor is
    /// one for every body of a block, so the order by fee per weight, and
    /// with it the fill's stop rule, is unchanged. σ and `b` are clamped
    /// below `SCALE` as `C` clamps them (`fee/correction.rs`).
    #[must_use]
    pub(crate) fn offered_fee(self, fee: u64, sigma_scaled: u64, burn_pct_scaled: u64) -> u64 {
        match self {
            Self::Gross => fee,
            Self::MinerNet => {
                let sigma = sigma_scaled.min(SCALE - 1);
                let b = burn_pct_scaled.min(SCALE - 1);
                u64::try_from(u128::from(fee) * u128::from(SCALE - b) / u128::from(SCALE - sigma))
                    .unwrap_or(u64::MAX)
            }
        }
    }
}

/// A run's economy arms, each production by default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EconomyArms {
    pub penalty: PenaltyDestination,
    pub burn: BurnSignal,
    pub template: TemplateRule,
}

impl EconomyArms {
    /// Production on every arm.
    pub(crate) const PRODUCTION: Self = Self {
        penalty: PenaltyDestination::Deferred,
        burn: BurnSignal::Count,
        template: TemplateRule::Gross,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C2's window can pass `u64` late in a growth fold, and reads as
    /// `u64::MAX` there. The burn reads it through a ratio that has already
    /// saturated at that sum, so every larger true sum burns the same.
    #[test]
    fn a_fee_window_past_u64_burns_as_its_true_sum() {
        let params = EconomicParams::default();
        let baseline = params.tx_volume_baseline * SCALE;
        let clamped = TxVolume::window(u64::MAX, shekyl_economics::params::TX_VOLUME_WINDOW);
        assert_eq!(clamped.ratio_scaled_squared(baseline), u64::MAX);
    }

    #[test]
    fn production_is_the_default_on_every_arm() {
        assert_eq!(EconomyArms::default(), EconomyArms::PRODUCTION);
        assert_eq!(PenaltyDestination::ALL[0], PenaltyDestination::default());
        assert_eq!(TemplateRule::ALL[0], TemplateRule::default());
    }

    #[test]
    fn each_destination_pays_its_share_of_the_penalty() {
        let median = 1_000_000;
        let penalty = 800;
        let at = |w| PenaltyDestination::ALL.map(|d| d.stakers_part(penalty, w, median));
        // Just past the median, at a quarter over, and at twice.
        assert_eq!(at(median), [0, 800, 0, 800, 400]);
        assert_eq!(at(median * 5 / 4), [0, 800, 200, 600, 400]);
        assert_eq!(at(median * 2), [0, 800, 800, 0, 400]);
        // No penalty, nothing paid, whatever the weight.
        for d in PenaltyDestination::ALL {
            assert_eq!(d.stakers_part(0, median * 3 / 2, median), 0);
        }
    }

    #[test]
    fn the_net_offered_fee_is_the_net_test_body_by_body() {
        // For every penalty, the gross test on the offered fee agrees with
        // the miner's-net test on the body's fee, in exact integers.
        let fee = 1_234_567;
        for (sigma, b) in [
            (150_000, 15_000),
            (55_000, 225_000),
            (6_700, 421_000),
            (0, 0),
        ] {
            let offered = TemplateRule::MinerNet.offered_fee(fee, sigma, b);
            for delta in offered.saturating_sub(3)..=offered + 3 {
                let gross_on_offered = delta <= offered;
                let net = u128::from(SCALE - sigma) * u128::from(delta)
                    <= u128::from(SCALE - b) * u128::from(fee);
                assert_eq!(gross_on_offered, net, "sigma {sigma}, b {b}, delta {delta}");
            }
        }
        assert_eq!(TemplateRule::Gross.offered_fee(fee, 150_000, 15_000), fee);
    }

    #[test]
    fn the_net_factor_cancels_c_and_leaves_one_when_the_shares_match() {
        // When the burn's share equals the staker share, the net test is
        // the gross one.
        assert_eq!(
            TemplateRule::MinerNet.offered_fee(1_000_000, 150_000, 150_000),
            1_000_000
        );
        // Burn below the staker share: more lenient; above it: stricter.
        assert!(TemplateRule::MinerNet.offered_fee(1_000_000, 150_000, 15_000) > 1_000_000);
        assert!(TemplateRule::MinerNet.offered_fee(1_000_000, 6_700, 421_000) < 1_000_000);
    }

    /// The miner's-net rule as the sim runs it, production's fill offered
    /// each body at [`TemplateRule::offered_fee`], lists exactly what a walk
    /// of the rule lists: one body at a time, each while the block stays
    /// under twice the median and `(S − σ)·δ ≤ (S − b)·fee`, `δ` the reward
    /// the body costs. Drawn over medians, body weights, fees, shares, burns,
    /// emission states and counts.
    #[test]
    fn the_net_rule_on_production_s_fill_is_the_single_offer_walk() {
        use shekyl_block_template::Fill;
        use shekyl_wire::transaction::COINBASE_RESERVE;

        let params = crate::engine::SimParams::default();
        let economic = params.economic();
        let coinbase = u64::try_from(COINBASE_RESERVE).expect("the reserve fits");
        let medians = [300_000, 1_260_000, 1_830_000, 10_000_000];
        let weights = [3_000, 14_640, 15_280, 40_000];
        let shares = [
            (150_000, 15_000),
            (55_000, 225_000),
            (6_700, 421_000),
            (0, 900_000),
        ];
        let asymptote = economic.emission_curve_asymptote;
        let mut state: u64 = 0x005e_ed1e_550f_f1ce;
        let mut draw = |bound: u64| {
            // A 64-bit LCG (Knuth's MMIX constants): the test's own stream.
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 11) % bound.max(1)
        };
        let mut cases = 0;
        let mut past_free = 0;
        for _ in 0..240 {
            let median = medians[draw(4) as usize];
            let weight = weights[draw(4) as usize];
            let (sigma, b) = shares[draw(4) as usize];
            let generated = draw(asymptote);
            let volume = TxVolume::per_block(economic.tx_volume_baseline);
            let fee_bits = 10 + draw(28);
            let fee = 1 + draw(1 << fee_bits);
            let count_bits = 1 + draw(12);
            let count = 1 + draw(1 << count_bits);
            let offered = TemplateRule::MinerNet.offered_fee(fee, sigma, b);
            let mut fill = Fill::empty(median, coinbase, generated, volume, economic)
                .expect("an empty block is priced");
            let walk_from = fill;
            let taken = fill.admit_up_to(weight, offered, count).taken;

            let mut bodies = 0u64;
            let mut walked = 0u64;
            while walked < count {
                let next = bodies + weight;
                if next + coinbase > median * 2 {
                    break;
                }
                let (Ok(now), Ok(then)) = (walk_from.reward_at(bodies), walk_from.reward_at(next))
                else {
                    break;
                };
                let delta = now - then;
                if u128::from(SCALE - sigma) * u128::from(delta)
                    > u128::from(SCALE - b) * u128::from(fee)
                {
                    break;
                }
                bodies = next;
                walked += 1;
            }
            assert_eq!(
                taken, walked,
                "median {median}, weight {weight}, fee {fee}, sigma {sigma}, b {b}, \
                 generated {generated}, count {count}"
            );
            cases += 1;
            if walked * weight > walk_from.penalty_free_bodies() {
                past_free += 1;
            }
        }
        assert_eq!(cases, 240, "every drawn case ran");
        assert!(past_free > 0, "some case lists a body past the free weight");
    }

    #[test]
    fn a_block_s_fees_read_in_standard_fee_units() {
        assert_eq!(fee_units_scaled(50 * 3_000, 3_000), 50 * SCALE);
        assert_eq!(fee_units_scaled(1_500, 3_000), SCALE / 2);
        assert_eq!(fee_units_scaled(1_500, 0), 0);
    }
}
