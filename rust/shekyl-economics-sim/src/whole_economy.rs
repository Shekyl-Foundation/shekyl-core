// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! EUP-4 prep 3: the three economies graded whole
//! (`docs/design/ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.37, WE-1…WE-12).
//!
//! One table for EUP-4: a row per economy, template rule, scenario, zone
//! and `w_ref`, each figure the median and range across the declared seeds.
//! Its columns answer the five questions (security, inclusion, archival
//! funding, bloat, distribution), with the release multiplier's and the
//! burn's yearly means, the tail beside the fees, the emitted fraction and
//! the Standard fee. It prints measures, never a verdict.
//!
//! Every run is ESR-10's fold ([`a1_year_aggs_probed`]) with an
//! [`EconomyProbe`] asked at every block. The probe changes the fold only
//! where an economy names it: it lists a stuffer's own bodies (A-stuffed)
//! and stops a fold at its supply break. The arms that change pricing are
//! the run's [`crate::economy::EconomyArms`], its volume signal and its
//! escalation overrides.

use std::collections::VecDeque;
use std::fmt::{self, Write};

use serde::{Deserialize, Serialize};
use shekyl_economics::params::{BLOCK_WEIGHT_LONG_TERM_WINDOW, SCALE, TX_VOLUME_WINDOW};
use shekyl_economics::{
    effective_emission, split_block_emission, staker_pool_share_at, tail_subsidy_per_block,
    ClosedShardCount, PrePenaltyEmission, TxVolume,
};
use shekyl_types::SHARD_LENGTH;

use crate::baseline::Override;
use crate::chain_cursor::{OwnFee, Traffic};
use crate::economy::{BurnSignal, EconomyArms, PenaltyDestination, TemplateRule};
use crate::engine::{ScenarioConfig, SimParams, VolumeSchedule};
use crate::escalation::{EscalationCurve, ASYMPTOTE_BAND, KNEE_BAND};
use crate::esr10::{rederived_pair, scenario_named};
use crate::eup4::{release_multiplier_at, skl};
use crate::fee_model::OrdinaryTx;
use crate::jg_grid::{
    reference_spend_weight, spend_zone_bytes, zones, DESIGN_LOAD_SPENDS, INHERITED_ZONE,
};
use crate::rng::HONEST_SEEDS;
use crate::rung_mix::FeePriority;
use crate::scenarios::{BASELINE_STEADY_STATE, BOOM_BUST_CYCLE, SUSTAINED_GROWTH};
use crate::stage2::{a1_year_aggs_probed, A1YearAgg, BlockSeen, FoldEdge, FoldProbe};
use crate::volume_window::VolumeSignal;

/// The ratified structural horizon (`ECONOMY_UMBRELLA_PLAN.md` §4.1, Rick
/// 2026-11-13): the tail-era questions are read to about year 135.
pub(crate) const HORIZON_YEARS: u64 = 135;

/// The new scenario's name: demand at a tenth of the baseline for five
/// years, then the baseline's path (§5.37).
pub(crate) const SLOW_ADOPTION: &str = "slow_adoption";
/// Its slow years.
const SLOW_ADOPTION_YEARS: u64 = 5;
/// Its slow demand, as a divisor of the baseline.
const SLOW_ADOPTION_DIVISOR: u64 = 10;

/// The scenarios the table folds, in its order.
const SCENARIOS: [&str; 4] = [
    BASELINE_STEADY_STATE,
    BOOM_BUST_CYCLE,
    SUSTAINED_GROWTH,
    SLOW_ADOPTION,
];

/// The grid's zone points the brief names, in 2-in/2-out spends.
const SPENDS: [u64; 2] = [90, 150];

/// C3's asymptote: the band's middle member. The steepest member (the
/// band's top at the smallest knee) is excluded until BA-T10 sets S (Rick,
/// 2026-11-13), so the escalation runs at the middle asymptote across the
/// three knees.
const C3_ASYMPTOTE: u64 = ASYMPTOTE_BAND[1];
/// The knee C together runs at.
const C_TOGETHER_KNEE: u64 = KNEE_BAND[1];

/// The years a row prints. Every year is in the JSON summary.
const SAMPLE_YEARS: [u64; 8] = [1, 5, 10, 20, 30, 60, 100, 135];
/// The share of a year's blocks paying the tail above which the year is in
/// the tail era: the narration marks it, and the derived table reads the
/// tail test from it.
const TAIL_ERA_SHARE: f64 = 0.5;
/// The years the miner's-net fee revenue's deciles print.
const DECILE_YEARS: [u64; 3] = [60, 100, 135];
/// The years the adversaries are priced at, at the first block of each.
const ADVERSARY_YEARS: [u64; 3] = [5, 20, 40];
/// The miner-staker's stake shares, percent.
const MINER_STAKE_PCT: [u64; 4] = [0, 5, 20, 33];
/// The staker-inducer's stake shares, per mille: 0.5 %, 5 % and 20 %.
const STAKER_STAKE_PERMILLE: [u64; 3] = [5, 50, 200];
/// Per mille.
const PER_MILLE: u64 = 1_000;
/// Percent.
const PERCENT: u64 = 100;
/// The ratchet's excess over the median: a quarter (blocks at 1.25 times
/// the median).
const RATCHET_EXCESS_QUARTERS: u64 = 1;
/// Quarters of the median.
const QUARTERS: u64 = 4;
/// The archival age bands' edges, years before the year read: the last
/// ten years, ten to forty, and older.
const AGE_BAND_EDGES: [u64; 2] = [10, 40];
/// The declared sweep of the extra propagation delay per byte, ms/KB: a
/// transaction its peers already hold up to a cold relay over a 1 Mbit/s
/// Tor circuit (§5.37, the inclusion column).
const TAU_SWEEP_MS_PER_KB: [f64; 2] = [0.01, 10.0];
/// Seconds in a day.
const SECONDS_PER_DAY: u64 = 86_400;
/// Bytes in a (decimal) gigabyte: the floor device's 1 GB a day.
const BYTES_PER_GB: u64 = 1_000_000_000;
/// Bytes in a terabyte, for the reward domain's median.
const BYTES_PER_TB: f64 = 1e12;
/// Milliseconds in a second.
const MS_PER_SECOND: f64 = 1_000.0;
/// Bytes in a (decimal) kilobyte.
const BYTES_PER_KB: f64 = 1_000.0;

/// One economy (§5.37).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Economy {
    /// Production; no miner lists its own bodies.
    AHonest,
    /// Production; every miner fills its free room with its own bodies at
    /// every block.
    AStuffed,
    /// #1416's `Fixed` signal.
    Decoupled,
    /// B's release, the penalty to stakers at a destination.
    C1(PenaltyDestination),
    /// B's release, the burn keyed to fees paid.
    C2,
    /// B's release, the D2 escalation at [`C3_ASYMPTOTE`] and this knee.
    C3(u64),
    /// C1 at a destination, with C2 and C3 at [`C_TOGETHER_KNEE`].
    CTogether(PenaltyDestination),
}

/// C1's destinations: every one but production's.
const C1_DESTINATIONS: [PenaltyDestination; 4] = [
    PenaltyDestination::All,
    PenaltyDestination::GraduatedUp,
    PenaltyDestination::GraduatedDown,
    PenaltyDestination::Flat50,
];

impl Economy {
    /// Every economy, in the table's order: fifteen.
    pub(crate) fn all() -> Vec<Self> {
        let mut out = vec![Self::AHonest, Self::AStuffed, Self::Decoupled];
        out.extend(C1_DESTINATIONS.map(Self::C1));
        out.push(Self::C2);
        out.extend(KNEE_BAND.map(Self::C3));
        out.extend(C1_DESTINATIONS.map(Self::CTogether));
        out
    }

    pub(crate) fn name(self) -> String {
        match self {
            Self::AHonest => "A-honest".into(),
            Self::AStuffed => "A-stuffed".into(),
            Self::Decoupled => "B".into(),
            Self::C1(d) => format!("C1 {}", d.name()),
            Self::C2 => "C2".into(),
            Self::C3(knee) => format!("C3 knee {knee}"),
            Self::CTogether(d) => format!("C1+2+3 {}", d.name()),
        }
    }

    /// Whether every miner lists its own bodies at every block.
    const fn stuffs(self) -> bool {
        match self {
            Self::AStuffed => true,
            Self::AHonest
            | Self::Decoupled
            | Self::C1(_)
            | Self::C2
            | Self::C3(_)
            | Self::CTogether(_) => false,
        }
    }

    /// `cell` run as this economy under `rule`.
    ///
    /// Each arm is named. A new economy does not compile until it says which
    /// volume signal, penalty, burn and escalation it runs.
    pub(crate) fn params(self, cell: &SimParams, rule: TemplateRule) -> SimParams {
        let escalated = |knee: u64| {
            cell.with_more(EscalationCurve::overrides(C3_ASYMPTOTE, knee))
                .expect("a band member passes the validators")
        };
        let mut params = match self {
            Self::C3(knee) => escalated(knee),
            Self::CTogether(_) => escalated(C_TOGETHER_KNEE),
            Self::AHonest | Self::AStuffed | Self::Decoupled | Self::C1(_) | Self::C2 => {
                cell.clone()
            }
        };
        params.volume_signal = match self {
            Self::AHonest | Self::AStuffed => VolumeSignal::Sum,
            Self::Decoupled | Self::C1(_) | Self::C2 | Self::C3(_) | Self::CTogether(_) => {
                VolumeSignal::Fixed
            }
        };
        params.economy = EconomyArms {
            penalty: match self {
                Self::C1(destination) | Self::CTogether(destination) => destination,
                Self::AHonest | Self::AStuffed | Self::Decoupled | Self::C2 | Self::C3(_) => {
                    PenaltyDestination::Deferred
                }
            },
            burn: match self {
                Self::C2 | Self::CTogether(_) => BurnSignal::FeesPaid,
                Self::AHonest | Self::AStuffed | Self::Decoupled | Self::C1(_) | Self::C3(_) => {
                    BurnSignal::Count
                }
            },
            template: rule,
        };
        params
    }
}

/// The slow-adoption scenario under `params`.
pub(crate) fn slow_adoption(params: &SimParams) -> ScenarioConfig {
    let baseline = params.economic().tx_volume_baseline;
    let mut config = scenario_named(params, BASELINE_STEADY_STATE);
    config.name = SLOW_ADOPTION.into();
    config.description = format!(
        "{} of the baseline for {SLOW_ADOPTION_YEARS} years, then the baseline",
        format_args!("1/{SLOW_ADOPTION_DIVISOR}")
    );
    config.volume = VolumeSchedule {
        get_volume: Box::new(move |block, blocks_per_year| {
            if block < SLOW_ADOPTION_YEARS * blocks_per_year {
                baseline / SLOW_ADOPTION_DIVISOR
            } else {
                baseline
            }
        }),
    };
    config
}

/// The scenario called `name`, to the horizon.
fn scenario(params: &SimParams, name: &str) -> ScenarioConfig {
    let mut config = if name == SLOW_ADOPTION {
        slow_adoption(params)
    } else {
        scenario_named(params, name)
    };
    config.sim_years = HORIZON_YEARS;
    config
}

/// A zone point at a `w_ref`: what a row's cell is built on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Place {
    pub(crate) zone: String,
    pub(crate) zone_bytes: u64,
    pub(crate) w_ref: u64,
}

/// Every place: the zones of [`SPENDS`], the inherited and the re-derived,
/// each at the base `w_ref` and the re-derived one.
fn places(base: &SimParams) -> Vec<Place> {
    let w_refs = [base.relay().ref_tx_weight, rederived_pair(base).w_ref];
    let mut out = Vec::new();
    for zone in zones(base, &SPENDS) {
        for w_ref in w_refs {
            out.push(Place {
                zone: zone.label.clone(),
                zone_bytes: zone.bytes,
                w_ref,
            });
        }
    }
    out
}

/// `base` at `place` and `seed`.
fn at_place(base: &SimParams, place: &Place, seed: u64) -> SimParams {
    let overrides: Vec<Override> = [
        format!("economic.full_reward_zone={}", place.zone_bytes),
        format!("relay.ref_tx_weight={}", place.w_ref),
    ]
    .iter()
    .map(|t| Override::parse(t).expect("well-formed"))
    .collect();
    let mut params = base
        .with_more(overrides)
        .expect("a zone point passes the validators");
    params.traffic = Traffic::Variable(seed);
    params
}

/// Which cells a scope folds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    /// Every economy, rule, scenario, place and seed.
    Full,
    /// The nightly slice: the baseline at N = 90 and the base `w_ref`, seed
    /// 1, every economy under both rules; and the inherited zone at the
    /// base `w_ref`, A-honest and B under both rules.
    Nightly,
}

impl Scope {
    /// Whether this scope folds the cell.
    ///
    /// The nightly zones are the N = 90 spend's byte size and the inherited
    /// zone's byte size. The labels those sizes print are not the identity.
    fn keeps(
        self,
        scenario: &str,
        place: &Place,
        economy: Economy,
        seed: u64,
        base_w_ref: u64,
        nightly_spend_bytes: u64,
    ) -> bool {
        match self {
            Self::Full => true,
            Self::Nightly => {
                scenario == BASELINE_STEADY_STATE
                    && seed == HONEST_SEEDS[0]
                    && place.w_ref == base_w_ref
                    && (place.zone_bytes == nightly_spend_bytes
                        || (place.zone_bytes == INHERITED_ZONE
                            && matches!(economy, Economy::AHonest | Economy::Decoupled)))
            }
        }
    }
}

/// One cell before its fold.
#[derive(Debug, Clone)]
struct Cell {
    economy: Economy,
    rule: TemplateRule,
    scenario: &'static str,
    place: Place,
    seed: u64,
}

fn cells(base: &SimParams, scope: Scope) -> Vec<Cell> {
    let places = places(base);
    let base_w_ref = base.relay().ref_tx_weight;
    let nightly_spend_bytes = spend_zone_bytes(reference_spend_weight(base), SPENDS[0]);
    let mut out = Vec::new();
    for scenario in SCENARIOS {
        for place in &places {
            for economy in Economy::all() {
                for rule in TemplateRule::ALL {
                    for seed in HONEST_SEEDS {
                        if scope.keeps(
                            scenario,
                            place,
                            economy,
                            seed,
                            base_w_ref,
                            nightly_spend_bytes,
                        ) {
                            out.push(Cell {
                                economy,
                                rule,
                                scenario,
                                place: place.clone(),
                                seed,
                            });
                        }
                    }
                }
            }
        }
    }
    out
}

/// A distribution's summary: what a column reads of a year's blocks.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub(crate) struct Spread {
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) p50: f64,
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) p95: f64,
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) p99: f64,
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) mean: f64,
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) variance: f64,
}

/// The nearest-rank quantile `q` of `sorted`.
fn quantile(sorted: &[u64], q: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (q * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// `values` (atomic), sorted in place, as a [`Spread`] in SKL.
#[allow(clippy::cast_precision_loss)]
fn spread(values: &mut [u64]) -> Spread {
    values.sort_unstable();
    let n = values.len().max(1) as f64;
    let mean = values.iter().map(|&v| skl(u128::from(v))).sum::<f64>() / n;
    let variance = values
        .iter()
        .map(|&v| (skl(u128::from(v)) - mean).powi(2))
        .sum::<f64>()
        / n;
    Spread {
        p50: skl(u128::from(quantile(values, 0.5))),
        p95: skl(u128::from(quantile(values, 0.95))),
        p99: skl(u128::from(quantile(values, 0.99))),
        mean,
        variance,
    }
}

/// One year of a fold, as the table reads it.
///
/// Each f64 decodes from the decimal text it was written as
/// ([`crate::exact_f64`]).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct YearFig {
    pub(crate) year: u64,
    /// The release multiplier's mean over the year's blocks.
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) release_mean: f64,
    /// The burn's mean over the year's blocks, a fraction.
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) burn_mean: f64,
    /// Miner income per block (`PaidEmission::owed`), SKL, and its fee part.
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) miner_income: f64,
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) miner_fee: f64,
    /// Per-block fee revenue, gross and the miner's net.
    pub(crate) fee_gross: Spread,
    pub(crate) fee_net: Spread,
    /// The net fee revenue's deciles (10 % … 90 %), on [`DECILE_YEARS`].
    #[serde(deserialize_with = "crate::exact_f64::de_opt_f64_9")]
    pub(crate) fee_net_deciles: Option<[f64; 9]>,
    /// The tail per block, gross and the miner's share after the stakers'
    /// cut at the year's last block.
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) tail_gross: f64,
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) tail_net: f64,
    /// The share of the year's blocks whose effective emission is the tail.
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) tail_share: f64,
    /// The Standard transaction's fee (SKL) and weight (bytes), means.
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) standard_fee: f64,
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) standard_weight: f64,
    /// The inclusion threshold `τ*`, ms/KB: gross, and the miner's net.
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) tau_gross: f64,
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) tau_net: f64,
    /// The penalty withheld over the year (SKL), and the part paid to
    /// stakers.
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) penalty: f64,
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) penalty_to_stakers: f64,
    /// Stakers' income per block by source, SKL.
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) staker_emission: f64,
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) staker_pool: f64,
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) staker_penalty: f64,
    /// Bodies a block carries, and the producer's own among them.
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) carried: f64,
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) own: f64,
    /// The long-term effective median at the year's last block, bytes.
    pub(crate) ltem: u64,
    /// Coins generated through the year, as a fraction of the asymptote.
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) emitted_fraction: f64,
    /// Bytes and outputs a day; cumulative archival bytes.
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) bytes_a_day: f64,
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) outputs_a_day: f64,
    pub(crate) archival_bytes: u64,
    /// The archival bytes held by age band: the last ten years, ten to
    /// forty, and older.
    pub(crate) bytes_by_age: [u64; 3],
    /// Stakers' income from every source over the year, per gigabyte held
    /// at its end, SKL.
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) staker_income_per_gb_year: f64,
}

impl YearFig {
    /// Whether more than [`TAIL_ERA_SHARE`] of the year's blocks paid the
    /// tail.
    fn in_tail_era(&self) -> bool {
        self.tail_share > TAIL_ERA_SHARE
    }
}

/// One adversary pricing, at a year's first block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Adversaries {
    pub(crate) year: u64,
    /// The ratchet's cost as a ratio to production's, per stake share of
    /// [`MINER_STAKE_PCT`].
    #[serde(deserialize_with = "crate::exact_f64::de_f64_4")]
    pub(crate) ratchet_ratio: [f64; 4],
    /// The ratchet's cost on production, SKL.
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) ratchet_cost: f64,
    /// The staker-inducer's net, as a fraction of the penalty it pays, per
    /// share of [`STAKER_STAKE_PERMILLE`].
    #[serde(deserialize_with = "crate::exact_f64::de_f64_3")]
    pub(crate) inducer_net: [f64; 3],
    /// The shard-advance stuffer's cost and gain, SKL.
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) shard_advance_cost: f64,
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) shard_advance_gain: f64,
}

/// A fold's reading.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Folded {
    pub(crate) years: Vec<YearFig>,
    /// Where the fold stopped before the horizon, if it did.
    pub(crate) stop: Option<FoldStop>,
    /// The first year half the asymptote is out, fractional.
    #[serde(deserialize_with = "crate::exact_f64::de_opt_f64")]
    pub(crate) half_year: Option<f64>,
    /// The emitted fraction when the honest carried count's trailing mean
    /// first reached the baseline, and that block's year.
    #[serde(deserialize_with = "crate::exact_f64::de_opt_pair")]
    pub(crate) adoption: Option<(f64, f64)>,
    pub(crate) adversaries: Vec<Adversaries>,
    /// The design load's bytes a day at genesis.
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) design_load_bytes_a_day: f64,
    /// The bond production posts per held gigabyte, SKL.
    #[serde(deserialize_with = "crate::exact_f64::de_f64")]
    pub(crate) bond_per_gb: f64,
}

/// Where a fold stopped before the horizon: the edge, the year whose block
/// reached it (the table reads only the whole years before), and the
/// effective median there, bytes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct FoldStop {
    pub(crate) edge: FoldEdge,
    pub(crate) year: u64,
    pub(crate) median_bytes: u64,
}

impl FoldStop {
    #[allow(clippy::cast_precision_loss)]
    fn label(&self) -> String {
        match self.edge {
            FoldEdge::SupplyBreak => format!("break y{}", self.year),
            FoldEdge::RewardDomain => format!(
                "domain y{} at {:.1} TB",
                self.year,
                self.median_bytes as f64 / BYTES_PER_TB
            ),
        }
    }
}

/// The state an adversary is priced at: a year's first block.
#[derive(Debug, Clone, Copy)]
struct Snapshot {
    year: u64,
    median: u64,
    generated: u64,
    volume: TxVolume,
    burn_pct: u64,
    economy_tx: OrdinaryTx,
}

/// One year's sums as the probe takes them.
#[derive(Debug, Default)]
struct YearSums {
    blocks: u64,
    release: u128,
    burn: u128,
    owed: u128,
    miner_fee: u128,
    fee_gross: Vec<u64>,
    fee_net: Vec<u64>,
    tail_blocks: u64,
    standard_fee: u128,
    standard_weight: u128,
    coinbase_gross: u128,
    coinbase_net: u128,
    penalty: u128,
    penalty_to_stakers: u128,
    staker_emission: u128,
    staker_pool: u128,
    carried: u128,
    own: u128,
    sigma_last: u64,
}

/// One sealed year: the probe's sums, and the coins generated through its
/// last block. The [`YearFig`] is built from this and the fold's year
/// aggregate together.
struct ClosedYear {
    year: u64,
    sums: YearSums,
    generated: u128,
}

/// The table's probe.
struct EconomyProbe<'p> {
    params: &'p SimParams,
    stuffs: bool,
    blocks_per_year: u64,
    tail: u64,
    sums: YearSums,
    /// Whole years the probe has sealed. A year still in progress stays in
    /// [`Self::sums`].
    closed: Vec<ClosedYear>,
    /// The honest carried counts of the last [`TX_VOLUME_WINDOW`] blocks.
    honest: VecDeque<u64>,
    honest_sum: u64,
    adoption: Option<(f64, f64)>,
    half_year: Option<f64>,
    snapshots: Vec<Snapshot>,
    stop: Option<FoldStop>,
    heartbeat: Option<Heartbeat>,
}

/// A fold's progress line every [`HEARTBEAT_YEARS`], to stderr, for a
/// timed run that must name a slow cell before it ends. The table's own
/// folds carry none.
struct Heartbeat {
    label: String,
    started: std::time::Instant,
}

/// Years between two heartbeat lines.
const HEARTBEAT_YEARS: u64 = 5;

/// The wall clock, UTC, as `YYYY-MM-DDTHH:MM:SSZ`, on each heartbeat and
/// end line: a host shared with another run is then read by when, not only
/// by how long (§5.37.1), and a run that crosses midnight stays unambiguous.
fn utc_clock() -> String {
    utc_stamp(time::OffsetDateTime::now_utc())
}

/// `at` as `YYYY-MM-DDTHH:MM:SSZ`.
fn utc_stamp(at: time::OffsetDateTime) -> String {
    const STAMP: &[time::format_description::FormatItem<'static>] =
        time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    at.to_offset(time::UtcOffset::UTC)
        .format(STAMP)
        .expect("a compile-time format description formats every date")
}

impl<'p> EconomyProbe<'p> {
    fn new(params: &'p SimParams, stuffs: bool) -> Self {
        Self {
            params,
            stuffs,
            blocks_per_year: params.blocks_per_year(),
            tail: tail_subsidy_per_block(params.economic()).expect("the tail is in its domain"),
            sums: YearSums::default(),
            closed: Vec::new(),
            honest: VecDeque::new(),
            honest_sum: 0,
            adoption: None,
            half_year: None,
            snapshots: Vec::new(),
            stop: None,
            heartbeat: None,
        }
    }

    /// Seal the year in progress. The figure is built later, once the fold's
    /// year aggregate exists, so a year is not half-filled.
    fn seal_year(&mut self, year: u64, generated: u128) {
        self.closed.push(ClosedYear {
            year,
            sums: std::mem::take(&mut self.sums),
            generated,
        });
    }
}

impl FoldProbe for EconomyProbe<'_> {
    fn own_bodies(&mut self, _block: u64) -> Option<OwnFee> {
        self.stuffs.then_some(OwnFee::RelayFloor)
    }

    fn stops_at_edges(&self) -> bool {
        true
    }

    fn stopped(&mut self, edge: FoldEdge, block: u64, effective_median: u64) {
        self.stop = Some(FoldStop {
            edge,
            year: block / self.blocks_per_year + 1,
            median_bytes: effective_median,
        });
    }

    #[allow(clippy::cast_precision_loss)]
    fn seen(&mut self, seen: &BlockSeen<'_, '_>) {
        let priced = seen.priced;
        let params = self.params;
        let economic = params.economic();
        let year = seen.block / self.blocks_per_year + 1;
        if seen.block.is_multiple_of(self.blocks_per_year) && ADVERSARY_YEARS.contains(&year) {
            self.snapshots.push(Snapshot {
                year,
                median: priced.medians.effective_median.to_raw(),
                generated: priced.fee_point.already_generated,
                volume: priced.volume,
                burn_pct: priced.burn_pct,
                economy_tx: params
                    .fee
                    .rung_tx(FeePriority::Economy, &priced.fee_point)
                    .expect("every arm prices the Economy rung"),
            });
        }
        let filled = &priced.filled;
        let paid = &priced.paid;
        let fees = filled.fees_atomic();
        let sums = &mut self.sums;
        sums.blocks += 1;
        sums.release += u128::from(release_multiplier_at(seen, params));
        sums.burn += u128::from(priced.burn_pct);
        sums.owed += u128::from(paid.owed.to_raw());
        sums.miner_fee += u128::from(paid.fee_burn.miner_fee_income);
        sums.fee_gross.push(fees);
        sums.fee_net.push(paid.fee_burn.miner_fee_income);
        let effective =
            effective_emission(priced.fee_point.already_generated, priced.volume, economic)
                .expect("the fold priced this block's emission");
        if effective == self.tail {
            sums.tail_blocks += 1;
        }
        sums.standard_fee += u128::from(priced.tx.fee_atomic);
        sums.standard_weight += u128::from(priced.tx.weight);
        sums.coinbase_gross += u128::from(priced.paid_reward()) + u128::from(fees);
        sums.coinbase_net += u128::from(paid.owed.to_raw());
        sums.penalty += u128::from(filled.past_free.penalty_atomic);
        sums.penalty_to_stakers += u128::from(priced.penalty_minted);
        sums.staker_emission += u128::from(paid.split.staker_emission);
        sums.staker_pool += u128::from(paid.fee_burn.staker_pool_amount);
        let honest = filled.carried_txs() - filled.own.txs;
        sums.carried += u128::from(filled.carried_txs());
        sums.own += u128::from(filled.own.txs);
        sums.sigma_last = priced.emission_share;

        let asymptote = economic.emission_curve_asymptote;
        let years_in = (seen.block + 1) as f64 / self.blocks_per_year as f64;
        if self.half_year.is_none() && seen.already_generated * 2 >= u128::from(asymptote) {
            self.half_year = Some(years_in);
        }
        self.honest.push_back(honest);
        self.honest_sum += honest;
        if self.honest.len() as u64 > TX_VOLUME_WINDOW {
            self.honest_sum -= self.honest.pop_front().expect("over the window");
        }
        if self.adoption.is_none()
            && self.honest.len() as u64 == TX_VOLUME_WINDOW
            && self.honest_sum >= economic.tx_volume_baseline * TX_VOLUME_WINDOW
        {
            self.adoption = Some((seen.already_generated as f64 / asymptote as f64, years_in));
        }
        if (seen.block + 1).is_multiple_of(self.blocks_per_year) {
            self.seal_year(year, seen.already_generated);
            if let Some(beat) = &self.heartbeat {
                if year.is_multiple_of(HEARTBEAT_YEARS) {
                    // Straight to the process's stderr: the test harness
                    // captures `eprintln!`, and a slow cell must be named
                    // while it runs, not after its test ends.
                    use std::io::Write as _;
                    let _ = writeln!(
                        std::io::stderr(),
                        "beat | {} | {} | y{year} | median {} B | waiting {} | cohorts {} | {:.0} s",
                        utc_clock(),
                        beat.label,
                        priced.medians.effective_median.to_raw(),
                        filled.waiting,
                        filled.cohorts_waiting,
                        beat.started.elapsed().as_secs_f64()
                    );
                }
            }
        }
    }
}

/// Each sealed year as one [`YearFig`]. The probe's sums and the fold's
/// aggregate are both in hand, so every field is set here.
#[allow(clippy::cast_precision_loss)]
fn years_from(
    closed: Vec<ClosedYear>,
    aggs: &[A1YearAgg],
    params: &SimParams,
    tail: u64,
) -> Vec<YearFig> {
    assert_eq!(
        closed.len(),
        aggs.len(),
        "a sealed year is a year the fold recorded"
    );
    let economic = params.economic();
    let blocks_a_day = SECONDS_PER_DAY / economic.daa_target_seconds;
    let days = params.blocks_per_year() as f64 / blocks_a_day as f64;
    let target = economic.daa_target_seconds as f64;
    let asymptote = economic.emission_curve_asymptote as f64;
    let bytes_at = |year: u64| -> u64 {
        year.checked_sub(1)
            .and_then(|i| aggs.get(i as usize))
            .map_or(0, |a| a.cumulative_archival_bytes)
    };
    closed
        .into_iter()
        .zip(aggs)
        .enumerate()
        .map(|(i, (closed, agg))| {
            assert_eq!(
                closed.year, agg.year,
                "the probe and the fold name one year"
            );
            let sums = closed.sums;
            let n = sums.blocks.max(1);
            let per_block = |total: u128| skl(total) / n as f64;
            let mean = |total: u128| total as f64 / n as f64;
            let scaled = |total: u128| mean(total) / SCALE as f64;
            let mut fee_gross = sums.fee_gross;
            let mut fee_net = sums.fee_net;
            let fee_gross_spread = spread(&mut fee_gross);
            let fee_net_spread = spread(&mut fee_net);
            let fee_net_deciles = DECILE_YEARS.contains(&closed.year).then(|| {
                core::array::from_fn(|i| skl(u128::from(quantile(&fee_net, (i + 1) as f64 / 10.0))))
            });
            let (tail_miner, _) = split_block_emission(tail, sums.sigma_last);
            let standard_fee = mean(sums.standard_fee);
            let standard_weight = mean(sums.standard_weight);
            let tau = |fee: f64, coinbase: f64| {
                if coinbase <= 0.0 || standard_weight <= 0.0 {
                    0.0
                } else {
                    fee / coinbase * target * MS_PER_SECOND / (standard_weight / BYTES_PER_KB)
                }
            };
            let burn_mean = scaled(sums.burn);
            let staker_emission = per_block(sums.staker_emission);
            let staker_pool = per_block(sums.staker_pool);
            let staker_penalty = per_block(sums.penalty_to_stakers);
            let (bytes_before, outputs_before) = i.checked_sub(1).map_or((0, 0), |p| {
                (
                    aggs[p].cumulative_archival_bytes,
                    aggs[p].cumulative_outputs,
                )
            });
            let now = agg.cumulative_archival_bytes;
            let ten = bytes_at(agg.year.saturating_sub(AGE_BAND_EDGES[0]));
            let forty = bytes_at(agg.year.saturating_sub(AGE_BAND_EDGES[1]));
            let held = now as f64 / BYTES_PER_GB as f64;
            let income =
                (staker_emission + staker_pool + staker_penalty) * params.blocks_per_year() as f64;
            YearFig {
                year: closed.year,
                release_mean: scaled(sums.release),
                burn_mean,
                miner_income: per_block(sums.owed),
                miner_fee: per_block(sums.miner_fee),
                fee_gross: fee_gross_spread,
                fee_net: fee_net_spread,
                fee_net_deciles,
                tail_gross: skl(u128::from(tail)),
                tail_net: skl(u128::from(tail_miner)),
                tail_share: sums.tail_blocks as f64 / n as f64,
                standard_fee: per_block(sums.standard_fee),
                standard_weight,
                tau_gross: tau(standard_fee, mean(sums.coinbase_gross)),
                tau_net: tau(standard_fee * (1.0 - burn_mean), mean(sums.coinbase_net)),
                penalty: skl(sums.penalty),
                penalty_to_stakers: skl(sums.penalty_to_stakers),
                staker_emission,
                staker_pool,
                staker_penalty,
                carried: mean(sums.carried),
                own: mean(sums.own),
                ltem: agg.long_term_median,
                emitted_fraction: closed.generated as f64 / asymptote,
                bytes_a_day: (now - bytes_before) as f64 / days,
                outputs_a_day: (agg.cumulative_outputs - outputs_before) as f64 / days,
                archival_bytes: now,
                bytes_by_age: [now - ten, ten - forty, forty],
                staker_income_per_gb_year: if held > 0.0 { income / held } else { f64::NAN },
            }
        })
        .collect()
}

/// The adversaries priced at each snapshot, on `params`' destination and
/// burn, against production's deferred penalty.
#[allow(clippy::cast_precision_loss)]
fn adversaries(snapshots: &[Snapshot], aggs: &[A1YearAgg], params: &SimParams) -> Vec<Adversaries> {
    let economic = params.economic();
    let destination = params.economy.penalty;
    let blocks = BLOCK_WEIGHT_LONG_TERM_WINDOW / 2 + 1;
    snapshots
        .iter()
        .map(|s| {
            let ratchet_weight = s.median + s.median * RATCHET_EXCESS_QUARTERS / QUARTERS;
            let emission = PrePenaltyEmission::of(s.generated, s.volume, economic)
                .expect("the fold priced this state");
            let free = emission
                .penalised(s.median, s.median, economic)
                .expect("a block at the median is priced");
            let ratcheted = emission
                .penalised(s.median, ratchet_weight, economic)
                .expect("a block under twice the median is priced");
            let penalty = free - ratcheted;
            // The ratchet's own bodies fill the excess at the relay floor;
            // the miner keeps their fees but the burn.
            let bodies = (ratchet_weight - s.median).div_ceil(s.economy_tx.weight.max(1));
            let own_fees = u128::from(bodies) * u128::from(s.economy_tx.fee_atomic);
            let burn_on_own = own_fees * u128::from(s.burn_pct) / u128::from(SCALE);
            let returned = destination.stakers_part(penalty, ratchet_weight, s.median);
            let per_block_production = u128::from(penalty) + burn_on_own;
            let ratchet_ratio = MINER_STAKE_PCT.map(|f| {
                let back = u128::from(returned) * u128::from(f) / u128::from(PERCENT);
                (per_block_production - back) as f64 / per_block_production.max(1) as f64
            });
            // The inducer pays the penalty as a fee; it recovers its stake's
            // share of the stakers' part and of the pool's share of the
            // fee's burn.
            let n_at = s
                .year
                .checked_sub(1)
                .and_then(|y| y.checked_sub(1))
                .and_then(|i| aggs.get(i as usize));
            let n = n_at.map_or(0, |a| a.n);
            let pool_share = staker_pool_share_at(ClosedShardCount::new(n), &economic.escalation());
            let pool_of_fee = u128::from(penalty) * u128::from(s.burn_pct) / u128::from(SCALE)
                * u128::from(pool_share.to_raw())
                / u128::from(SCALE);
            let inducer_net = STAKER_STAKE_PERMILLE.map(|share| {
                let back = (u128::from(returned) + pool_of_fee) * u128::from(share)
                    / u128::from(PER_MILLE);
                (back as f64 - penalty as f64) / penalty.max(1) as f64
            });
            // The shard advance: a year's archival bytes written early at the
            // relay floor, against the escalation's extra pool share for a
            // year at the count a year on.
            let year_index = s.year as usize - 1;
            let (year_bytes, year_burn, n_now) = aggs.get(year_index).map_or((0, 0, n), |a| {
                let before = year_index
                    .checked_sub(1)
                    .map_or(0, |p| aggs[p].cumulative_archival_bytes);
                (
                    a.cumulative_archival_bytes - before,
                    a.whole_burn_atomic,
                    a.n,
                )
            });
            let advance_bodies = year_bytes.div_ceil(s.economy_tx.weight.max(1));
            let cost = u128::from(advance_bodies) * u128::from(s.economy_tx.fee_atomic);
            let shards_a_year = year_bytes / SHARD_LENGTH.to_raw();
            let share = |n: u64| {
                u128::from(
                    staker_pool_share_at(ClosedShardCount::new(n), &economic.escalation()).to_raw(),
                )
            };
            let lift = share(n_now + shards_a_year).saturating_sub(share(n_now));
            let gain = year_burn * lift / u128::from(SCALE);
            Adversaries {
                year: s.year,
                ratchet_ratio,
                ratchet_cost: skl(per_block_production * u128::from(blocks)),
                inducer_net,
                shard_advance_cost: skl(cost),
                shard_advance_gain: skl(gain),
            }
        })
        .collect()
}

/// One cell's fold.
#[allow(clippy::cast_precision_loss)]
fn fold(base: &SimParams, cell: &Cell) -> Folded {
    fold_beating(base, cell, None)
}

/// [`fold`], printing a [`Heartbeat`] labelled `label` when given one.
fn fold_beating(base: &SimParams, cell: &Cell, label: Option<String>) -> Folded {
    let placed = at_place(base, &cell.place, cell.seed);
    let params = cell.economy.params(&placed, cell.rule);
    let config = scenario(&params, cell.scenario);
    let mut probe = EconomyProbe::new(&params, cell.economy.stuffs());
    probe.heartbeat = label.map(|label| Heartbeat {
        label,
        started: std::time::Instant::now(),
    });
    let aggs = a1_year_aggs_probed(&params, &config, &mut probe);
    let years = years_from(
        std::mem::take(&mut probe.closed),
        &aggs,
        &params,
        probe.tail,
    );
    let stop = probe.stop;
    let adversaries = adversaries(&probe.snapshots, &aggs, &params);
    let blocks_a_day = SECONDS_PER_DAY / params.economic().daa_target_seconds;
    let design_load_bytes_a_day =
        (DESIGN_LOAD_SPENDS * reference_spend_weight(&params) * blocks_a_day) as f64;
    let bond_per_gb = skl(u128::from(params.archival().bond_floor_atomic)) * BYTES_PER_GB as f64
        / SHARD_LENGTH.to_raw() as f64;
    Folded {
        years,
        stop,
        half_year: probe.half_year,
        adoption: probe.adoption,
        adversaries,
        design_load_bytes_a_day,
        bond_per_gb,
    }
}

/// A row of the table: one economy, rule, scenario and place, its seeds'
/// folds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Row {
    pub(crate) economy: String,
    pub(crate) rule: String,
    pub(crate) scenario: String,
    pub(crate) place: Place,
    pub(crate) seeds: Vec<u64>,
    pub(crate) folds: Vec<Folded>,
}

/// The `--economies` summary: every row, every year.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Summary {
    pub(crate) horizon_years: u64,
    #[serde(deserialize_with = "crate::exact_f64::de_f64_2")]
    pub(crate) tau_sweep_ms_per_kb: [f64; 2],
    pub(crate) rows: Vec<Row>,
}

/// The `--economies` report and its summary.
///
/// # Errors
///
/// Only `out`'s.
pub(crate) fn run(
    out: &mut impl Write,
    base: &SimParams,
    scope: Scope,
) -> Result<Summary, fmt::Error> {
    let cells = cells(base, scope);
    let folded = crate::parallel::map(&cells, |cell| fold(base, cell));
    let mut rows: Vec<Row> = Vec::new();
    for (cell, f) in cells.iter().zip(folded) {
        let same = |r: &Row| {
            r.economy == cell.economy.name()
                && r.rule == cell.rule.name()
                && r.scenario == cell.scenario
                && r.place.zone == cell.place.zone
                && r.place.w_ref == cell.place.w_ref
        };
        if let Some(row) = rows.iter_mut().find(|r| same(r)) {
            row.seeds.push(cell.seed);
            row.folds.push(f);
        } else {
            rows.push(Row {
                economy: cell.economy.name(),
                rule: cell.rule.name().to_owned(),
                scenario: cell.scenario.to_owned(),
                place: cell.place.clone(),
                seeds: vec![cell.seed],
                folds: vec![f],
            });
        }
    }
    report::write_report(out, &rows, scope)?;
    Ok(Summary {
        horizon_years: HORIZON_YEARS,
        tau_sweep_ms_per_kb: TAU_SWEEP_MS_PER_KB,
        rows,
    })
}

/// The summary's canonical bytes: what `--economies` writes to stdout and
/// what the recorded SHA-256 covers, so a redirected run reads back through
/// the digest check.
pub(crate) fn summary_json(summary: &Summary) -> String {
    serde_json::to_string(summary).expect("JSON serialization failed")
}

#[path = "whole_economy_report.rs"]
mod report;

#[cfg(test)]
#[path = "whole_economy_tests.rs"]
mod tests;
