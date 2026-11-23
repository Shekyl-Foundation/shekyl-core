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
use crate::economy::{BurnSignal, PenaltyDestination, TemplateRule};
use crate::engine::{ScenarioConfig, SimParams, VolumeSchedule};
use crate::escalation::{EscalationCurve, ASYMPTOTE_BAND, KNEE_BAND};
use crate::esr10::{rederived_pair, scenario_named};
use crate::eup4::{release_multiplier_at, skl};
use crate::fee_model::OrdinaryTx;
use crate::jg_grid::{reference_spend_weight, zones, DESIGN_LOAD_SPENDS};
use crate::rng::HONEST_SEEDS;
use crate::rung_mix::FeePriority;
use crate::scenarios::{BASELINE_STEADY_STATE, BOOM_BUST_CYCLE, SUSTAINED_GROWTH};
use crate::stage2::{
    a1_year_aggs_probed, penalty_to_stakers, A1YearAgg, BlockSeen, FoldEdge, FoldProbe,
};
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
        matches!(self, Self::AStuffed)
    }

    /// `cell` run as this economy under `rule`.
    pub(crate) fn params(self, cell: &SimParams, rule: TemplateRule) -> SimParams {
        let escalated = |knee: u64| {
            cell.with_more(EscalationCurve::overrides(C3_ASYMPTOTE, knee))
                .expect("a band member passes the validators")
        };
        let mut params = match self {
            Self::C3(knee) => escalated(knee),
            Self::CTogether(_) => escalated(C_TOGETHER_KNEE),
            _ => cell.clone(),
        };
        if !matches!(self, Self::AHonest | Self::AStuffed) {
            params.volume_signal = VolumeSignal::Fixed;
        }
        params.economy.template = rule;
        match self {
            Self::C1(d) | Self::CTogether(d) => params.economy.penalty = d,
            _ => {}
        }
        if matches!(self, Self::C2 | Self::CTogether(_)) {
            params.economy.burn = BurnSignal::FeesPaid;
        }
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
    let mut out = Vec::new();
    for scenario in SCENARIOS {
        for place in &places {
            for economy in Economy::all() {
                for rule in TemplateRule::ALL {
                    for seed in HONEST_SEEDS {
                        let keep = match scope {
                            Scope::Full => true,
                            Scope::Nightly => {
                                scenario == BASELINE_STEADY_STATE
                                    && seed == HONEST_SEEDS[0]
                                    && place.w_ref == base_w_ref
                                    && (place.zone == format!("N = {}", SPENDS[0])
                                        || (place.zone == "inherited"
                                            && matches!(
                                                economy,
                                                Economy::AHonest | Economy::Decoupled
                                            )))
                            }
                        };
                        if keep {
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
    pub(crate) p50: f64,
    pub(crate) p95: f64,
    pub(crate) p99: f64,
    pub(crate) mean: f64,
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct YearFig {
    pub(crate) year: u64,
    /// The release multiplier's mean over the year's blocks.
    pub(crate) release_mean: f64,
    /// The burn's mean over the year's blocks, a fraction.
    pub(crate) burn_mean: f64,
    /// Miner income per block (`PaidEmission::owed`), SKL, and its fee part.
    pub(crate) miner_income: f64,
    pub(crate) miner_fee: f64,
    /// Per-block fee revenue, gross and the miner's net.
    pub(crate) fee_gross: Spread,
    pub(crate) fee_net: Spread,
    /// The net fee revenue's deciles (10 % … 90 %), on [`DECILE_YEARS`].
    pub(crate) fee_net_deciles: Option<[f64; 9]>,
    /// The tail per block, gross and the miner's share after the stakers'
    /// cut at the year's last block.
    pub(crate) tail_gross: f64,
    pub(crate) tail_net: f64,
    /// The share of the year's blocks whose effective emission is the tail.
    pub(crate) tail_share: f64,
    /// The Standard transaction's fee (SKL) and weight (bytes), means.
    pub(crate) standard_fee: f64,
    pub(crate) standard_weight: f64,
    /// The inclusion threshold `τ*`, ms/KB: gross, and the miner's net.
    pub(crate) tau_gross: f64,
    pub(crate) tau_net: f64,
    /// The penalty withheld over the year (SKL), and the part paid to
    /// stakers.
    pub(crate) penalty: f64,
    pub(crate) penalty_to_stakers: f64,
    /// Stakers' income per block by source, SKL.
    pub(crate) staker_emission: f64,
    pub(crate) staker_pool: f64,
    pub(crate) staker_penalty: f64,
    /// Bodies a block carries, and the producer's own among them.
    pub(crate) carried: f64,
    pub(crate) own: f64,
    /// The long-term effective median at the year's last block, bytes.
    pub(crate) ltem: u64,
    /// Coins generated through the year, as a fraction of the asymptote.
    pub(crate) emitted_fraction: f64,
    /// Bytes and outputs a day; cumulative archival bytes.
    pub(crate) bytes_a_day: f64,
    pub(crate) outputs_a_day: f64,
    pub(crate) archival_bytes: u64,
    /// The archival bytes held by age band: the last ten years, ten to
    /// forty, and older.
    pub(crate) bytes_by_age: [u64; 3],
    /// Stakers' income from every source over the year, per gigabyte held
    /// at its end, SKL.
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
    pub(crate) ratchet_ratio: [f64; 4],
    /// The ratchet's cost on production, SKL.
    pub(crate) ratchet_cost: f64,
    /// The staker-inducer's net, as a fraction of the penalty it pays, per
    /// share of [`STAKER_STAKE_PERMILLE`].
    pub(crate) inducer_net: [f64; 3],
    /// The shard-advance stuffer's cost and gain, SKL.
    pub(crate) shard_advance_cost: f64,
    pub(crate) shard_advance_gain: f64,
}

/// A fold's reading.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Folded {
    pub(crate) years: Vec<YearFig>,
    /// Where the fold stopped before the horizon, if it did.
    pub(crate) stop: Option<FoldStop>,
    /// The first year half the asymptote is out, fractional.
    pub(crate) half_year: Option<f64>,
    /// The emitted fraction when the honest carried count's trailing mean
    /// first reached the baseline, and that block's year.
    pub(crate) adoption: Option<(f64, f64)>,
    pub(crate) adversaries: Vec<Adversaries>,
    /// The design load's bytes a day at genesis.
    pub(crate) design_load_bytes_a_day: f64,
    /// The bond production posts per held gigabyte, SKL.
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

/// The table's probe.
struct EconomyProbe<'p> {
    params: &'p SimParams,
    stuffs: bool,
    blocks_per_year: u64,
    tail: u64,
    sums: YearSums,
    years: Vec<YearFig>,
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
            years: Vec::new(),
            honest: VecDeque::new(),
            honest_sum: 0,
            adoption: None,
            half_year: None,
            snapshots: Vec::new(),
            stop: None,
            heartbeat: None,
        }
    }

    #[allow(clippy::cast_precision_loss)]
    fn close_year(&mut self, year: u64, already_generated: u128) {
        let sums = std::mem::take(&mut self.sums);
        let n = sums.blocks.max(1);
        let per_block = |total: u128| skl(total) / n as f64;
        let mean = |total: u128| total as f64 / n as f64;
        let scaled = |total: u128| mean(total) / SCALE as f64;
        let mut fee_gross = sums.fee_gross;
        let mut fee_net = sums.fee_net;
        let fee_gross_spread = spread(&mut fee_gross);
        let fee_net_spread = spread(&mut fee_net);
        let fee_net_deciles = DECILE_YEARS.contains(&year).then(|| {
            core::array::from_fn(|i| skl(u128::from(quantile(&fee_net, (i + 1) as f64 / 10.0))))
        });
        let (tail_miner, _) = split_block_emission(self.tail, sums.sigma_last);
        let target = self.params.economic().daa_target_seconds as f64;
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
        let asymptote = self.params.economic().emission_curve_asymptote as f64;
        self.years.push(YearFig {
            year,
            release_mean: scaled(sums.release),
            burn_mean,
            miner_income: per_block(sums.owed),
            miner_fee: per_block(sums.miner_fee),
            fee_gross: fee_gross_spread,
            fee_net: fee_net_spread,
            fee_net_deciles,
            tail_gross: skl(u128::from(self.tail)),
            tail_net: skl(u128::from(tail_miner)),
            tail_share: sums.tail_blocks as f64 / n as f64,
            standard_fee: per_block(sums.standard_fee),
            standard_weight,
            tau_gross: tau(standard_fee, mean(sums.coinbase_gross)),
            tau_net: tau(standard_fee * (1.0 - burn_mean), mean(sums.coinbase_net)),
            penalty: skl(sums.penalty),
            penalty_to_stakers: skl(sums.penalty_to_stakers),
            staker_emission: per_block(sums.staker_emission),
            staker_pool: per_block(sums.staker_pool),
            staker_penalty: per_block(sums.penalty_to_stakers),
            carried: mean(sums.carried),
            own: mean(sums.own),
            emitted_fraction: already_generated as f64 / asymptote,
            ..YearFig::default()
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
        let to_stakers = penalty_to_stakers(priced, params);
        sums.penalty += u128::from(filled.past_free.penalty_atomic);
        sums.penalty_to_stakers += u128::from(to_stakers);
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
            self.close_year(year, seen.already_generated);
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

/// The fold's yearly aggregates added to its years: bytes and outputs a
/// day, the archive and its age bands, the median.
#[allow(clippy::cast_precision_loss)]
fn add_aggregates(years: &mut [YearFig], aggs: &[A1YearAgg], params: &SimParams) {
    let blocks_a_day = SECONDS_PER_DAY / params.economic().daa_target_seconds;
    let days = params.blocks_per_year() as f64 / blocks_a_day as f64;
    let bytes_at = |year: u64| -> u64 {
        year.checked_sub(1)
            .and_then(|i| aggs.get(i as usize))
            .map_or(0, |a| a.cumulative_archival_bytes)
    };
    for (i, (fig, agg)) in years.iter_mut().zip(aggs).enumerate() {
        let (bytes_before, outputs_before) = i.checked_sub(1).map_or((0, 0), |p| {
            (
                aggs[p].cumulative_archival_bytes,
                aggs[p].cumulative_outputs,
            )
        });
        fig.bytes_a_day = (agg.cumulative_archival_bytes - bytes_before) as f64 / days;
        fig.outputs_a_day = (agg.cumulative_outputs - outputs_before) as f64 / days;
        fig.archival_bytes = agg.cumulative_archival_bytes;
        fig.ltem = agg.long_term_median;
        let year = agg.year;
        let now = agg.cumulative_archival_bytes;
        let ten = bytes_at(year.saturating_sub(AGE_BAND_EDGES[0]));
        let forty = bytes_at(year.saturating_sub(AGE_BAND_EDGES[1]));
        fig.bytes_by_age = [now - ten, ten - forty, forty];
        let held = now as f64 / BYTES_PER_GB as f64;
        let income = (fig.staker_emission + fig.staker_pool + fig.staker_penalty)
            * params.blocks_per_year() as f64;
        fig.staker_income_per_gb_year = if held > 0.0 { income / held } else { f64::NAN };
    }
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
    let mut years = probe.years;
    years.truncate(aggs.len());
    add_aggregates(&mut years, &aggs, &params);
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
    pub(crate) tau_sweep_ms_per_kb: [f64; 2],
    pub(crate) rows: Vec<Row>,
}

/// The median and range of `values`, formatted with `digits` decimals.
fn mr(values: &[f64], digits: usize) -> String {
    let Some((median, low, high)) = median_and_range(values) else {
        return "-".into();
    };
    if (low - high).abs() < f64::EPSILON {
        return format!("{median:.digits$}");
    }
    format!("{median:.digits$} [{low:.digits$}, {high:.digits$}]")
}

/// The lower median of `values`' finite members, and their least and
/// greatest; nothing when none is finite. The narration and the derived
/// table both read their medians here.
fn median_and_range(values: &[f64]) -> Option<(f64, f64, f64)> {
    let mut v: Vec<f64> = values.iter().copied().filter(|x| x.is_finite()).collect();
    if v.is_empty() {
        return None;
    }
    v.sort_by(f64::total_cmp);
    Some((v[(v.len() - 1) / 2], v[0], v[v.len() - 1]))
}

/// Each fold's figure at `year`, or nothing past its stop.
fn at_year<'r>(row: &'r Row, year: u64) -> impl Iterator<Item = &'r YearFig> + 'r {
    row.folds
        .iter()
        .filter_map(move |f| f.years.get(year as usize - 1))
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
    write_report(out, &rows, scope)?;
    Ok(Summary {
        horizon_years: HORIZON_YEARS,
        tau_sweep_ms_per_kb: TAU_SWEEP_MS_PER_KB,
        rows,
    })
}

fn write_report(out: &mut impl Write, rows: &[Row], scope: Scope) -> fmt::Result {
    writeln!(
        out,
        "THREE ECONOMIES GRADED WHOLE (ECONOMICS_SIM_PRODUCTION_REBASE.md §5.37, WE-1..WE-12).\n\
         Measures only, never a verdict. Scope: {}. Standard traffic; each figure is the median\n\
         [range] across the row's seeds ({:?}). Horizon y{HORIZON_YEARS}; a fold that reaches its\n\
         supply break or the edge of the reward's arithmetic stops there and prints which, the\n\
         year and the median. {SUSTAINED_GROWTH} is a stress of the mechanism, not a forecast:\n\
         its folds run until the arithmetic or the supply runs out. Read the tail columns from\n\
         the other scenarios. SKL per block unless named.",
        match scope {
            Scope::Full => "full",
            Scope::Nightly => "nightly slice",
        },
        HONEST_SEEDS
    )?;
    let mut last: Option<(&str, &str, u64)> = None;
    for row in rows {
        let key = (
            row.scenario.as_str(),
            row.place.zone.as_str(),
            row.place.w_ref,
        );
        if last != Some(key) {
            writeln!(
                out,
                "\n== {}{} | zone {} ({} B) | w_ref {} ==",
                row.scenario,
                stress_tag(&row.scenario),
                row.place.zone,
                row.place.zone_bytes,
                row.place.w_ref
            )?;
            last = Some(key);
        }
        write_row(out, row, scope)?;
    }
    Ok(())
}

/// The stress scenario's mark on its sections and tail lines: the
/// sustained growth's demand compounds without a ceiling, so its folds
/// show where the mechanism's arithmetic or supply runs out, and the tail
/// is read from the other scenarios (§5.37.1).
fn stress_tag(scenario: &str) -> &'static str {
    if is_stress(scenario) {
        " (stress: runs to its edge; not read for the tail)"
    } else {
        ""
    }
}

/// Whether `scenario` is a stress: run to its edge, labelled so, and not
/// read for the tail (Rick, 2026-11-21).
fn is_stress(scenario: &str) -> bool {
    scenario == SUSTAINED_GROWTH
}

#[allow(clippy::cast_precision_loss)]
fn write_row(out: &mut impl Write, row: &Row, scope: Scope) -> fmt::Result {
    let fig = |year: u64, f: &dyn Fn(&YearFig) -> f64, digits: usize| -> String {
        let v: Vec<f64> = at_year(row, year).map(f).collect();
        mr(&v, digits)
    };
    let stops: Vec<String> = row
        .folds
        .iter()
        .map(|f| f.stop.map_or("-".into(), |stop| stop.label()))
        .collect();
    writeln!(
        out,
        "-- {} | {} | stops {}",
        row.economy,
        row.rule,
        stops.join(",")
    )?;
    let half: Vec<f64> = row.folds.iter().filter_map(|f| f.half_year).collect();
    let mut security = format!("   security: 50% year {}", mr(&half, 2));
    for year in SAMPLE_YEARS {
        write!(
            security,
            " | y{year} income {} fee {}",
            fig(year, &|y| y.miner_income, 2),
            fig(year, &|y| y.miner_fee, 4)
        )?;
    }
    writeln!(out, "{security}")?;
    // Every year in the nightly slice and in the JSON summary: STD-5 could
    // not be graded because no report carried these means (§5.35.1). The
    // full table prints the sample years, which keeps its narration at
    // 8.4 MB instead of about 15 MB; every year of every cell is in its
    // JSON (§5.37.1).
    let years: Vec<u64> = match scope {
        Scope::Nightly => (1..=HORIZON_YEARS).collect(),
        Scope::Full => SAMPLE_YEARS.to_vec(),
    };
    let mut release = format!(
        "   release and burn (yearly means, {}):",
        match scope {
            Scope::Nightly => "every year",
            Scope::Full => "sample years; every year in the JSON",
        }
    );
    for year in years {
        write!(
            release,
            " | y{year} M_r {} burn {}",
            fig(year, &|y| y.release_mean, 3),
            fig(year, &|y| y.burn_mean, 3)
        )?;
    }
    writeln!(out, "{release}")?;
    let mut template = String::from("   median and fee:");
    for year in SAMPLE_YEARS {
        write!(
            template,
            " | y{year} LTEM {} KB carried {} own {} Standard {} SKL {} B penalty {}",
            fig(year, &|y| y.ltem as f64 / BYTES_PER_KB, 0),
            fig(year, &|y| y.carried, 1),
            fig(year, &|y| y.own, 1),
            fig(year, &|y| y.standard_fee, 5),
            fig(year, &|y| y.standard_weight, 0),
            fig(year, &|y| y.penalty, 1)
        )?;
    }
    writeln!(out, "{template}")?;
    let mut tail = format!(
        "   tail{} (miner's-net tail over miner's-net fees p50/p95/p99):",
        stress_tag(&row.scenario)
    );
    for year in SAMPLE_YEARS {
        let ratio = |p: fn(&Spread) -> f64| {
            move |y: &YearFig| {
                let fees = p(&y.fee_net);
                if fees > 0.0 {
                    y.tail_net / fees
                } else {
                    f64::INFINITY
                }
            }
        };
        write!(
            tail,
            " | y{year}{} {} / {} / {} (fees gross p95 {} net p95 {} var {})",
            if at_year(row, year).any(YearFig::in_tail_era) {
                " tail-era"
            } else {
                ""
            },
            fig(year, &ratio(|s| s.p50), 1),
            fig(year, &ratio(|s| s.p95), 1),
            fig(year, &ratio(|s| s.p99), 1),
            fig(year, &|y| y.fee_gross.p95, 4),
            fig(year, &|y| y.fee_net.p95, 4),
            fig(year, &|y| y.fee_net.variance, 6)
        )?;
    }
    writeln!(out, "{tail}")?;
    for year in DECILE_YEARS {
        let deciles: Vec<String> = (0..9)
            .map(|i| {
                fig(
                    year,
                    &move |y: &YearFig| y.fee_net_deciles.map_or(f64::NAN, |d| d[i]),
                    5,
                )
            })
            .collect();
        writeln!(
            out,
            "   y{year} net fee deciles: {} | p95 {} p99 {}",
            deciles.join(" "),
            fig(year, &|y| y.fee_net.p95, 5),
            fig(year, &|y| y.fee_net.p99, 5)
        )?;
    }
    let mut inclusion = format!(
        "   inclusion tau* ms/KB (sweep {}-{}):",
        TAU_SWEEP_MS_PER_KB[0], TAU_SWEEP_MS_PER_KB[1]
    );
    for year in SAMPLE_YEARS {
        write!(
            inclusion,
            " | y{year} gross {} net {}",
            fig(year, &|y| y.tau_gross, 3),
            fig(year, &|y| y.tau_net, 3)
        )?;
    }
    writeln!(out, "{inclusion}")?;
    let gb = BYTES_PER_GB as f64;
    let crossing = |design: bool| -> Vec<f64> {
        row.folds
            .iter()
            .map(|f| {
                if design {
                    if f.design_load_bytes_a_day >= gb {
                        1.0
                    } else {
                        f64::INFINITY
                    }
                } else {
                    f.years
                        .iter()
                        .find(|y| y.bytes_a_day >= gb)
                        .map_or(f64::INFINITY, |y| y.year as f64)
                }
            })
            .collect()
    };
    let design: Vec<f64> = row
        .folds
        .iter()
        .map(|f| f.design_load_bytes_a_day / gb)
        .collect();
    let mut bloat = format!(
        "   bloat: 1 GB/day first in year {} (cell's load), design load {} GB/day (first {})",
        mr(&crossing(false), 0),
        mr(&design, 3),
        mr(&crossing(true), 0)
    );
    for year in SAMPLE_YEARS {
        write!(
            bloat,
            " | y{year} {} GB/day {} outputs/day archive {} GB",
            fig(year, &|y| y.bytes_a_day / gb, 3),
            fig(year, &|y| y.outputs_a_day, 0),
            fig(year, &|y| y.archival_bytes as f64 / gb, 1)
        )?;
    }
    writeln!(out, "{bloat}")?;
    let adoption: Vec<f64> = row
        .folds
        .iter()
        .filter_map(|f| f.adoption.map(|a| a.0))
        .collect();
    let adoption_year: Vec<f64> = row
        .folds
        .iter()
        .filter_map(|f| f.adoption.map(|a| a.1))
        .collect();
    writeln!(
        out,
        "   distribution: emitted before blocks first carry the baseline {} (at year {})",
        mr(&adoption, 4),
        mr(&adoption_year, 3)
    )?;
    let bond: Vec<f64> = row.folds.iter().map(|f| f.bond_per_gb).collect();
    let mut archival = format!("   archival (bond {} SKL per GB held):", mr(&bond, 2));
    for year in SAMPLE_YEARS {
        write!(
            archival,
            " | y{year} stakers: emission {} pool {} penalty {}; per GB-year {}; bytes <10y/10-40y/>40y {}/{}/{} GB",
            fig(year, &|y| y.staker_emission, 3),
            fig(year, &|y| y.staker_pool, 4),
            fig(year, &|y| y.staker_penalty, 4),
            fig(year, &|y| y.staker_income_per_gb_year, 6),
            fig(year, &|y| y.bytes_by_age[0] as f64 / gb, 0),
            fig(year, &|y| y.bytes_by_age[1] as f64 / gb, 0),
            fig(year, &|y| y.bytes_by_age[2] as f64 / gb, 0)
        )?;
    }
    writeln!(out, "{archival}")?;
    let mut predictability = String::from("   emitted fraction:");
    for year in SAMPLE_YEARS {
        write!(
            predictability,
            " | y{year} {}",
            fig(year, &|y| y.emitted_fraction, 4)
        )?;
    }
    writeln!(out, "{predictability}")?;
    for (i, year) in ADVERSARY_YEARS.iter().enumerate() {
        let pick = |f: &dyn Fn(&Adversaries) -> f64| -> String {
            let v: Vec<f64> = row
                .folds
                .iter()
                .filter_map(|fo| fo.adversaries.get(i))
                .map(f)
                .collect();
            mr(&v, 3)
        };
        writeln!(
            out,
            "   adversaries y{year}: ratchet cost/production at f 0/5/20/33% {} / {} / {} / {} (production {} SKL) | inducer net/penalty at 0.5/5/20% {} / {} / {} | shard advance cost {} gain {} SKL",
            pick(&|a| a.ratchet_ratio[0]),
            pick(&|a| a.ratchet_ratio[1]),
            pick(&|a| a.ratchet_ratio[2]),
            pick(&|a| a.ratchet_ratio[3]),
            pick(&|a| a.ratchet_cost),
            pick(&|a| a.inducer_net[0]),
            pick(&|a| a.inducer_net[1]),
            pick(&|a| a.inducer_net[2]),
            pick(&|a| a.shard_advance_cost),
            pick(&|a| a.shard_advance_gain)
        )?;
    }
    Ok(())
}

/// The summary's canonical bytes: what `--economies` writes to stdout and
/// what the recorded SHA-256 covers, so a redirected run reads back through
/// the digest check.
pub(crate) fn summary_json(summary: &Summary) -> String {
    serde_json::to_string(summary).expect("JSON serialization failed")
}

/// The derived table (§5.37.1, Rick 2026-11-21 and 2026-11-22): one CSV
/// line per row, the figures the rulings read, each the median across the
/// row's seeds as the narration prints it. The full run's narration and JSON
/// summary are the record behind it; neither is committed, and the repo keeps
/// the SHA-256 of each. Test code: the nightly slice's table and the full
/// table are each rebuilt from their run by a pin.
#[cfg(test)]
fn table(summary: &Summary) -> String {
    let mut out = String::new();
    write_table(&mut out, &summary.rows).expect("String sink is infallible");
    out
}

/// What the committed full table says above its header about the run it is
/// derived from (Rick, 2026-11-23, §5.37.2). That run's fee-unit window
/// saturated on the growth folds, so the C2 and C-together rows there are
/// stale from year 69 until the table's next full run. It is the
/// recorded summary's note, not the table's: the nightly slice's table,
/// derived from its own fold, carries none.
#[cfg(test)]
const RECORDED_RUN_NOTE: &str = "\
# SUPERSEDED IN PART (Rick, 2026-11-23; ECONOMICS_SIM_PRODUCTION_REBASE.md §5.37.2). Derived from the
# full run of 2026-11-21 (shekyl-core f8e6f1ec4b).
#   - STALE from year 69: the C2 and C1+2+3 rows on sustained_growth (60 rows, role 'stress'). The
#     run's lifetime fee-unit sum saturated a u64 there, so their burn fell to zero and their income,
#     fees, supply and stops after it are artifacts. Their figures before year 69 stand.
#   - CURRENT: every other row, A-stuffed included. The correction of the stuffers' searched shapes
#     to two outputs (CEN-I1) does not reach this table: A-stuffed lists ordinary Economy-rung
#     transactions, which already have two outputs, and the narration's adversaries price the same.
# The next full run replaces this table and this note.
";

/// The derived table's columns, in order: the row's names, then security,
/// release and burn, inclusion, bloat, distribution, archival, and the
/// reward against the fees with the year the tail era begins.
#[cfg(test)]
const TABLE_COLUMNS: [&str; 41] = [
    "scenario",
    "zone",
    "w_ref",
    "economy",
    "rule",
    "role",
    "stops",
    "half_year",
    "income_y1",
    "income_y10",
    "income_y30",
    "income_y60",
    "income_y135",
    "fee_share_y10",
    "m_r_y1",
    "m_r_y10",
    "m_r_y30",
    "burn_y1",
    "burn_y10",
    "burn_y30",
    "ltem_kb_y30",
    "standard_fee_y1",
    "tau_gross_y1",
    "tau_gross_y30",
    "tau_net_y1",
    "tau_net_y30",
    "gb_day_y1",
    "gb_day_y10",
    "gb_day_y30",
    "first_1gb_day_year",
    "archive_gb_y135",
    "adoption_fraction",
    "adoption_year",
    "stakers_per_gb_year_y10",
    "stakers_per_gb_year_y30",
    "staker_pool_y10",
    "staker_penalty_y10",
    "reward_net_over_fees_p95_y60",
    "reward_net_over_fees_p95_y100",
    "reward_net_over_fees_p95_y135",
    "tail_era_year",
];

/// The narration's median of `values` ([`median_and_range`]), as `digits`
/// decimals, or `-`.
#[cfg(test)]
fn med(values: &[f64], digits: usize) -> String {
    median_and_range(values)
        .map_or_else(|| "-".into(), |(median, _, _)| format!("{median:.digits$}"))
}

#[cfg(test)]
#[allow(clippy::cast_precision_loss)]
fn write_table(out: &mut impl Write, rows: &[Row]) -> fmt::Result {
    writeln!(
        out,
        "# THREE ECONOMIES GRADED WHOLE, the derived table (ECONOMICS_SIM_PRODUCTION_REBASE.md §5.37.1).\n\
         # One line per economy, template rule, scenario, zone and w_ref; each figure is the median\n\
         # across the row's seeds, '-' where no seed has it (past a stop, or never reached). SKL per\n\
         # block unless named; tau in ms/KB; m_r and burn are yearly means. reward_net_over_fees_p95 is\n\
         # a ratio with no unit: the miner's-net emission (the paid reward's miner leg, a yearly mean,\n\
         # SKL a block) over the 95th-percentile block's miner's-net fees (SKL a block). tail_era_year is\n\
         # the first year more than half a fold's blocks pay the tail; from it on, the emission is the\n\
         # tail and the ratio is the tail test, read against k = 1; before it, the ratio is the emission\n\
         # a miner is paid then. adoption_year is the year the honest carried count's trailing mean over\n\
         # {TX_VOLUME_WINDOW} blocks first reaches the baseline: the year blocks first carry it, not the\n\
         # year demand reaches it ({SLOW_ADOPTION}'s demand reaches it at year {SLOW_ADOPTION_YEARS});\n\
         # adoption_fraction is the supply emitted by then. role 'stress' marks {SUSTAINED_GROWTH}: it\n\
         # runs to its edge and is not read for the tail, which is read from the 'read' rows. stops\n\
         # names, per seed, where the fold ended: the horizon (year {HORIZON_YEARS}), the supply's break,\n\
         # or the reward's domain edge. The narration and the JSON summary are the full record."
    )?;
    writeln!(out, "{}", TABLE_COLUMNS.join(","))?;
    let gb = BYTES_PER_GB as f64;
    for row in rows {
        let fig = |year: u64, f: &dyn Fn(&YearFig) -> f64, digits: usize| -> String {
            let v: Vec<f64> = at_year(row, year).map(f).collect();
            med(&v, digits)
        };
        let stops: Vec<String> = row
            .folds
            .iter()
            .map(|f| f.stop.map_or("horizon".into(), |stop| stop.label()))
            .collect();
        let half: Vec<f64> = row.folds.iter().filter_map(|f| f.half_year).collect();
        let first_gb: Vec<f64> = row
            .folds
            .iter()
            .map(|f| {
                f.years
                    .iter()
                    .find(|y| y.bytes_a_day >= gb)
                    .map_or(f64::INFINITY, |y| y.year as f64)
            })
            .collect();
        let adoption: Vec<f64> = row
            .folds
            .iter()
            .filter_map(|f| f.adoption.map(|a| a.0))
            .collect();
        let adoption_year: Vec<f64> = row
            .folds
            .iter()
            .filter_map(|f| f.adoption.map(|a| a.1))
            .collect();
        let reward = |y: &YearFig| {
            if y.fee_net.p95 > 0.0 {
                (y.miner_income - y.miner_fee) / y.fee_net.p95
            } else {
                f64::INFINITY
            }
        };
        let tail_era: Vec<f64> = row
            .folds
            .iter()
            .map(|f| {
                f.years
                    .iter()
                    .find(|y| y.in_tail_era())
                    .map_or(f64::INFINITY, |y| y.year as f64)
            })
            .collect();
        let cells = [
            row.scenario.clone(),
            row.place.zone.clone(),
            row.place.w_ref.to_string(),
            row.economy.clone(),
            row.rule.clone(),
            if is_stress(&row.scenario) {
                "stress"
            } else {
                "read"
            }
            .to_owned(),
            stops.join(";"),
            med(&half, 2),
            fig(1, &|y| y.miner_income, 2),
            fig(10, &|y| y.miner_income, 2),
            fig(30, &|y| y.miner_income, 2),
            fig(60, &|y| y.miner_income, 2),
            fig(135, &|y| y.miner_income, 2),
            fig(10, &|y| y.miner_fee / y.miner_income, 4),
            fig(1, &|y| y.release_mean, 3),
            fig(10, &|y| y.release_mean, 3),
            fig(30, &|y| y.release_mean, 3),
            fig(1, &|y| y.burn_mean, 3),
            fig(10, &|y| y.burn_mean, 3),
            fig(30, &|y| y.burn_mean, 3),
            fig(30, &|y| y.ltem as f64 / BYTES_PER_KB, 0),
            fig(1, &|y| y.standard_fee, 5),
            fig(1, &|y| y.tau_gross, 3),
            fig(30, &|y| y.tau_gross, 3),
            fig(1, &|y| y.tau_net, 3),
            fig(30, &|y| y.tau_net, 3),
            fig(1, &|y| y.bytes_a_day / gb, 3),
            fig(10, &|y| y.bytes_a_day / gb, 3),
            fig(30, &|y| y.bytes_a_day / gb, 3),
            med(&first_gb, 0),
            fig(135, &|y| y.archival_bytes as f64 / gb, 1),
            med(&adoption, 4),
            med(&adoption_year, 3),
            fig(10, &|y| y.staker_income_per_gb_year, 3),
            fig(30, &|y| y.staker_income_per_gb_year, 3),
            fig(10, &|y| y.staker_pool, 4),
            fig(10, &|y| y.staker_penalty, 4),
            fig(60, &reward, 1),
            fig(100, &reward, 1),
            fig(135, &reward, 1),
            med(&tail_era, 0),
        ];
        writeln!(out, "{}", cells.join(","))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committed_fixture::{self, regenerate, Output};

    /// The nightly slice's committed narration.
    const NIGHTLY_FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/economies_nightly_narration.txt"
    );
    /// The nightly slice's committed derived table.
    const NIGHTLY_TABLE_FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/economies_nightly_table.csv"
    );
    /// The SHA-256 of the full run's narration and JSON summary, in
    /// `sha256sum`'s format. The two files are not committed (Rick,
    /// 2026-11-22): the on-demand full run is their proof.
    const FULL_DIGESTS: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/economies_full_digests.txt"
    );
    /// The full run's narration's name, in [`FULL_DIGESTS`] and in
    /// [`FULL_OUTPUT_DIR_ENV`]'s directory.
    const FULL_NARRATION_NAME: &str = "economies_narration.txt";
    /// The full run's JSON summary's name, likewise.
    const FULL_SUMMARY_NAME: &str = "economies_summary.json";
    /// A directory a full run writes its narration and JSON summary into,
    /// under the names above, before it is checked: a run that fails leaves
    /// what it made to read.
    const FULL_OUTPUT_DIR_ENV: &str = "SHEKYL_ECONOMIES_FULL_DIR";

    /// One run's narration, its JSON summary and its derived table.
    struct Outputs {
        narration: String,
        json: String,
        table: String,
    }

    fn outputs(scope: Scope) -> Outputs {
        let mut narration = String::new();
        let summary =
            run(&mut narration, &SimParams::default(), scope).expect("String sink is infallible");
        Outputs {
            json: summary_json(&summary),
            table: table(&summary),
            narration,
        }
    }

    /// The nightly slice's outputs, folded once for its pin and its
    /// regeneration alike.
    fn nightly() -> &'static Outputs {
        static NIGHTLY: std::sync::OnceLock<Outputs> = std::sync::OnceLock::new();
        NIGHTLY.get_or_init(|| outputs(Scope::Nightly))
    }

    /// The full run's outputs, folded once, written to
    /// [`FULL_OUTPUT_DIR_ENV`]'s directory when it names one.
    fn full() -> &'static Outputs {
        static FULL: std::sync::OnceLock<Outputs> = std::sync::OnceLock::new();
        FULL.get_or_init(|| {
            let full = outputs(Scope::Full);
            if let Ok(dir) = std::env::var(FULL_OUTPUT_DIR_ENV) {
                for (name, bytes) in [
                    (FULL_NARRATION_NAME, &full.narration),
                    (FULL_SUMMARY_NAME, &full.json),
                ] {
                    let path = std::path::Path::new(&dir).join(name);
                    std::fs::write(&path, bytes).expect("write the full run's output");
                    eprintln!("wrote {}", path.display());
                }
            }
            full
        })
    }

    fn sha256_hex(bytes: &str) -> String {
        use sha2::{Digest, Sha256};
        Sha256::digest(bytes.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// [`FULL_DIGESTS`]'s content for `narration` and `json`.
    fn digests(narration: &str, json: &str) -> String {
        digest_lines(&sha256_hex(narration), &sha256_hex(json))
    }

    /// [`FULL_DIGESTS`]'s content for the two files' SHA-256, in
    /// `sha256sum`'s format.
    fn digest_lines(narration_sha: &str, summary_sha: &str) -> String {
        format!("{narration_sha}  {FULL_NARRATION_NAME}\n{summary_sha}  {FULL_SUMMARY_NAME}\n")
    }

    /// The recorded SHA-256 of the full run's file `name`
    /// ([`FULL_NARRATION_NAME`] or [`FULL_SUMMARY_NAME`]), read from
    /// [`FULL_DIGESTS`].
    fn recorded_digest(name: &str) -> String {
        let digests = std::fs::read_to_string(FULL_DIGESTS).expect("read the recorded digests");
        digests
            .lines()
            .find_map(|line| line.strip_suffix(&format!("  {name}")))
            .unwrap_or_else(|| panic!("{FULL_DIGESTS} records no {name}"))
            .to_owned()
    }

    #[test]
    fn the_economies_are_fifteen_with_production_first() {
        let all = Economy::all();
        assert_eq!(all.len(), 15);
        assert_eq!(all[0], Economy::AHonest);
        let names: Vec<String> = all.iter().map(|e| e.name()).collect();
        let mut unique = names.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            names.len(),
            "each economy prints its own name: {names:?}"
        );
    }

    /// Each economy sets what it names and nothing else.
    #[test]
    fn each_economy_sets_what_it_names() {
        let cell = SimParams::default();
        for rule in TemplateRule::ALL {
            let honest = Economy::AHonest.params(&cell, rule);
            assert_eq!(honest.volume_signal, VolumeSignal::Sum);
            assert_eq!(honest.economy.penalty, PenaltyDestination::Deferred);
            assert_eq!(honest.economy.burn, BurnSignal::Count);
            assert_eq!(honest.economy.template, rule);
            assert!(honest.overrides().is_empty());
            assert!(Economy::AStuffed.stuffs() && !Economy::AHonest.stuffs());

            let decoupled = Economy::Decoupled.params(&cell, rule);
            assert_eq!(decoupled.volume_signal, VolumeSignal::Fixed);
            assert_eq!(decoupled.economy.penalty, PenaltyDestination::Deferred);
            assert!(decoupled.overrides().is_empty());

            for d in C1_DESTINATIONS {
                let c1 = Economy::C1(d).params(&cell, rule);
                assert_eq!(
                    (c1.volume_signal, c1.economy.penalty),
                    (VolumeSignal::Fixed, d)
                );
                assert_eq!(c1.economy.burn, BurnSignal::Count);
                let together = Economy::CTogether(d).params(&cell, rule);
                assert_eq!(together.economy.penalty, d);
                assert_eq!(together.economy.burn, BurnSignal::FeesPaid);
                assert_eq!(
                    together.overrides().len(),
                    EscalationCurve::overrides(C3_ASYMPTOTE, C_TOGETHER_KNEE).len()
                );
            }
            let c2 = Economy::C2.params(&cell, rule);
            assert_eq!(
                (c2.volume_signal, c2.economy.burn),
                (VolumeSignal::Fixed, BurnSignal::FeesPaid)
            );
            for knee in KNEE_BAND {
                let c3 = Economy::C3(knee).params(&cell, rule);
                assert_eq!(c3.volume_signal, VolumeSignal::Fixed);
                assert_eq!(c3.economy.penalty, PenaltyDestination::Deferred);
                assert_eq!(c3.economic().escalation_knee_n, knee);
                assert_eq!(c3.economic().escalation_asymptote_share, C3_ASYMPTOTE);
            }
        }
    }

    #[test]
    fn slow_adoption_is_a_tenth_then_the_baseline() {
        let params = SimParams::default();
        let config = slow_adoption(&params);
        let year = params.blocks_per_year();
        let baseline = params.economic().tx_volume_baseline;
        assert_eq!(config.name, SLOW_ADOPTION);
        assert_eq!(
            (config.volume.get_volume)(0, year),
            baseline / SLOW_ADOPTION_DIVISOR
        );
        assert_eq!(
            (config.volume.get_volume)(SLOW_ADOPTION_YEARS * year - 1, year),
            baseline / SLOW_ADOPTION_DIVISOR
        );
        assert_eq!(
            (config.volume.get_volume)(SLOW_ADOPTION_YEARS * year, year),
            baseline
        );
        assert_eq!(scenario(&params, SLOW_ADOPTION).sim_years, HORIZON_YEARS);
        assert_eq!(
            scenario(&params, BASELINE_STEADY_STATE).sim_years,
            HORIZON_YEARS
        );
    }

    #[test]
    fn the_quantiles_are_nearest_rank() {
        let v: Vec<u64> = (1..=100).collect();
        assert_eq!(quantile(&v, 0.5), 50);
        assert_eq!(quantile(&v, 0.95), 95);
        assert_eq!(quantile(&v, 0.99), 99);
        assert_eq!(quantile(&v, 0.1), 10);
        assert_eq!(quantile(&[], 0.5), 0);
        assert_eq!(quantile(&[7], 0.99), 7);
    }

    /// The scopes' cells: the full table's count, and the nightly slice's
    /// cells named in §5.37.
    #[test]
    fn the_scopes_fold_the_cells_they_name() {
        let base = SimParams::default();
        let full = cells(&base, Scope::Full);
        assert_eq!(full.len(), 15 * 2 * 4 * 8 * 3);
        let nightly = cells(&base, Scope::Nightly);
        assert_eq!(nightly.len(), 15 * 2 + 2 * 2);
        assert!(nightly
            .iter()
            .all(|c| c.scenario == BASELINE_STEADY_STATE && c.seed == HONEST_SEEDS[0]));
    }

    /// The pre-flight: every scenario but the baseline (which the nightly
    /// slice folds) at seed 1, every economy, rule and place (720 folds),
    /// each to where it stops. No cell refuses a body outside the reward's
    /// domain: each ends at the horizon or at a named edge, and reads only
    /// the whole years before it (§5.37.1). Each fold prints a heartbeat
    /// every five years and a line when it ends, with its wall time, so a
    /// slow cell is named while the run goes on. It runs before the full
    /// table, whose cells these are at one seed of three.
    #[test]
    #[ignore = "--economies pre-flight: 720 folds at seed 1 — on demand, before the full table; run with --release --ignored --nocapture"]
    fn every_preflight_cell_ends_at_the_horizon_or_a_named_edge() {
        let base = SimParams::default();
        let preflight: Vec<Cell> = cells(&base, Scope::Full)
            .into_iter()
            .filter(|cell| cell.scenario != BASELINE_STEADY_STATE && cell.seed == HONEST_SEEDS[0])
            .collect();
        assert_eq!(preflight.len(), 15 * 2 * 8 * (SCENARIOS.len() - 1));
        let label = |cell: &Cell| {
            format!(
                "{} | {} | {} | {} at w_ref {}",
                cell.scenario,
                cell.economy.name(),
                cell.rule.name(),
                cell.place.zone,
                cell.place.w_ref
            )
        };
        let folded = crate::parallel::map(&preflight, |cell| {
            let started = std::time::Instant::now();
            let folded = fold_beating(&base, cell, Some(label(cell)));
            let stop = folded
                .stop
                .map_or_else(|| format!("y{HORIZON_YEARS}"), |stop| stop.label());
            eprintln!(
                "done | {} | {} | {stop} | {:.0} s",
                utc_clock(),
                label(cell),
                started.elapsed().as_secs_f64()
            );
            folded
        });
        for folded in &folded {
            match folded.stop {
                None => assert_eq!(folded.years.len() as u64, HORIZON_YEARS),
                Some(stop) => {
                    assert_eq!(folded.years.len() as u64 + 1, stop.year);
                    if stop.edge == FoldEdge::RewardDomain {
                        assert!(stop.median_bytes as f64 >= BYTES_PER_TB);
                    }
                }
            }
        }
    }

    /// The nightly slice, folded once: its narration and the table derived
    /// from its own summary, each against its committed copy. The derive
    /// function runs on real output every night, with nothing fetched.
    #[test]
    #[ignore = "--economies nightly slice: 34 folds to y135 — nightly; run with --release --ignored; fixtures generated and checked on Linux x86-64"]
    fn economies_nightly_slice_matches_its_narration_and_table() {
        let nightly = nightly();
        committed_fixture::assert_matches(
            "--economies nightly narration",
            NIGHTLY_FIXTURE,
            &nightly.narration,
        );
        committed_fixture::assert_matches(
            "--economies nightly derived table",
            NIGHTLY_TABLE_FIXTURE,
            &nightly.table,
        );
    }

    /// The full table, folded once: its narration and JSON summary against
    /// their recorded SHA-256, and the table derived from that summary
    /// against the committed copy. Set [`FULL_OUTPUT_DIR_ENV`] to keep the
    /// two files.
    ///
    /// **It does not pass until the table's next full run**
    /// (Rick, 2026-11-23, §5.37.2). The recorded run's fee-unit window
    /// saturated on the growth folds and this code's does not, so a fresh
    /// fold's C2 and C-together rows on `sustained_growth` differ from the
    /// record from year 69, and with them both digests. The committed table
    /// also carries [`RECORDED_RUN_NOTE`], which a fresh fold's table does
    /// not. That run regenerates the digests and the table; until then
    /// this test is not run. No test compares the full table with the
    /// nightly slice's, which is one seed where the full table is the median
    /// of three.
    #[test]
    #[ignore = "--economies, the full table: 2 880 folds to y135 — on demand, not nightly; run with --release --ignored; digests and table generated and checked on Linux x86-64"]
    fn economies_full_run_matches_its_digests_and_table() {
        let full = full();
        committed_fixture::assert_matches(
            "--economies full-run digests",
            FULL_DIGESTS,
            &digests(&full.narration, &full.json),
        );
        committed_fixture::assert_matches("--economies derived table", TABLE_FIXTURE, &full.table);
    }

    /// The derived table's committed copy (§5.37.1).
    const TABLE_FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/economies_table.csv"
    );

    /// A fold whose every year to `years` carries `scale`, stopped at the
    /// reward's edge when `stop` says so.
    fn synthetic_fold(years: u64, scale: f64, stop: Option<FoldStop>) -> Folded {
        Folded {
            years: (1..=years)
                .map(|year| YearFig {
                    year,
                    release_mean: scale,
                    burn_mean: scale / 10.0,
                    miner_income: 100.0 * scale,
                    miner_fee: scale,
                    fee_net: Spread {
                        p95: scale,
                        ..Spread::default()
                    },
                    tail_net: 2.0 * scale,
                    tail_share: if year > 100 { 1.0 } else { 0.0 },
                    bytes_a_day: if year >= 3 { 2.0e9 } else { 1.0e8 },
                    ..YearFig::default()
                })
                .collect(),
            stop,
            half_year: Some(11.0 * scale),
            adoption: None,
            adversaries: Vec::new(),
            design_load_bytes_a_day: 4.3e8,
            bond_per_gb: 250.0,
        }
    }

    fn synthetic_summary() -> Summary {
        let place = Place {
            zone: "N = 90".into(),
            zone_bytes: 1_795_896,
            w_ref: 3_000,
        };
        let edge = FoldStop {
            edge: FoldEdge::RewardDomain,
            year: 8,
            median_bytes: 4_000_000_000_000,
        };
        Summary {
            horizon_years: HORIZON_YEARS,
            tau_sweep_ms_per_kb: TAU_SWEEP_MS_PER_KB,
            rows: vec![
                Row {
                    economy: "A-honest".into(),
                    rule: "gross".into(),
                    scenario: BASELINE_STEADY_STATE.into(),
                    place: place.clone(),
                    seeds: HONEST_SEEDS.to_vec(),
                    folds: vec![
                        synthetic_fold(HORIZON_YEARS, 1.0, None),
                        synthetic_fold(HORIZON_YEARS, 2.0, None),
                        synthetic_fold(HORIZON_YEARS, 3.0, None),
                    ],
                },
                Row {
                    economy: "B".into(),
                    rule: "miner's net".into(),
                    scenario: SUSTAINED_GROWTH.into(),
                    place,
                    seeds: HONEST_SEEDS.to_vec(),
                    folds: vec![
                        synthetic_fold(7, 1.0, Some(edge)),
                        synthetic_fold(7, 2.0, Some(edge)),
                        synthetic_fold(7, 3.0, Some(edge)),
                    ],
                },
            ],
        }
    }

    /// The derived table: its header, one line per row with every column,
    /// the seeds' median, and `-` past a fold's stop.
    #[test]
    fn the_derived_table_has_a_line_per_row_and_every_column() {
        let table = table(&synthetic_summary());
        let lines: Vec<&str> = table.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(lines.len(), 3, "the header and two rows");
        assert_eq!(lines[0], TABLE_COLUMNS.join(","));
        let column = |line: &str, name: &str| -> String {
            let at = TABLE_COLUMNS
                .iter()
                .position(|c| *c == name)
                .expect("a column");
            line.split(',')
                .nth(at)
                .expect("the column's cell")
                .to_owned()
        };
        for line in &lines[1..] {
            assert_eq!(line.split(',').count(), TABLE_COLUMNS.len(), "{line}");
        }
        // The seeds carry 1, 2 and 3: the median is 2.
        assert_eq!(column(lines[1], "income_y10"), "200.00");
        assert_eq!(column(lines[1], "half_year"), "22.00");
        assert_eq!(column(lines[1], "first_1gb_day_year"), "3");
        // Each seed's emission is 99 times its p95 fees, and its tail era
        // begins at year 101.
        assert_eq!(column(lines[1], "reward_net_over_fees_p95_y60"), "99.0");
        assert_eq!(column(lines[1], "reward_net_over_fees_p95_y135"), "99.0");
        assert_eq!(column(lines[1], "tail_era_year"), "101");
        assert_eq!(column(lines[1], "role"), "read");
        assert_eq!(column(lines[1], "stops"), "horizon;horizon;horizon");
        // The growth row is a stress, and reads nothing past year 7.
        assert_eq!(column(lines[2], "role"), "stress");
        assert_eq!(column(lines[2], "income_y1"), "200.00");
        assert_eq!(column(lines[2], "income_y10"), "-");
        assert_eq!(column(lines[2], "tail_era_year"), "-");
        assert_eq!(
            column(lines[2], "stops"),
            "domain y8 at 4.0 TB;domain y8 at 4.0 TB;domain y8 at 4.0 TB"
        );
    }

    /// The heartbeat's stamp is the UTC date and time, through a leap day
    /// and a century's end.
    #[test]
    fn the_utc_stamp_reads_the_calendar() {
        let at = |seconds: i64| {
            utc_stamp(time::OffsetDateTime::from_unix_timestamp(seconds).expect("in range"))
        };
        assert_eq!(at(0), "1970-01-01T00:00:00Z");
        assert_eq!(at(951_786_061), "2000-02-29T01:01:01Z");
        assert_eq!(at(1_795_391_999), "2026-11-22T23:59:59Z");
        assert_eq!(at(4_102_444_799), "2099-12-31T23:59:59Z");
    }

    /// The JSON summary `--economies` writes reads back to the same table.
    #[test]
    fn the_summary_reads_back_to_the_same_table() {
        let summary = synthetic_summary();
        let json = serde_json::to_string(&summary).expect("serialize");
        let back: Summary = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(table(&back), table(&summary));
    }

    /// A summary's f64 reads back bit for bit. The literal is a fee variance
    /// from the recorded full run that serde_json's default parse reads one
    /// ULP off. The narration prints it to six decimals, past an f64's
    /// precision, so without `float_roundtrip` the summary renders a
    /// different narration from the run's.
    #[test]
    fn a_summary_float_reads_back_bit_for_bit() {
        let recorded = "21231060353.333294";
        let x: f64 = recorded.parse().expect("std parses a decimal exactly");
        let json = serde_json::to_string(&x).expect("serialize");
        assert_eq!(json, recorded);
        let back: f64 = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            back.to_bits(),
            x.to_bits(),
            "{recorded} read back as {back}"
        );
    }

    /// Names a full run's JSON summary on disk, for deriving the table
    /// without folding it again (a 13.9-hour run, §5.37.1).
    const SUMMARY_PATH_ENV: &str = "SHEKYL_ECONOMIES_SUMMARY";

    /// The JSON summary [`SUMMARY_PATH_ENV`] names, read whole. Refuses,
    /// naming the variable, when it names none, and when the file is not the
    /// summary whose SHA-256 the repo records: the pin and the helper below
    /// have no subject without it (rule 47).
    fn recorded_summary() -> Summary {
        let path = std::env::var(SUMMARY_PATH_ENV).unwrap_or_else(|_| {
            panic!(
                "{SUMMARY_PATH_ENV} names no JSON summary: name a full run's {FULL_SUMMARY_NAME}"
            )
        });
        let json = std::fs::read_to_string(&path).expect("read the JSON summary");
        assert_eq!(
            sha256_hex(&json),
            recorded_digest(FULL_SUMMARY_NAME),
            "{path} is not the JSON summary whose SHA-256 {FULL_DIGESTS} records"
        );
        serde_json::from_str(&json).expect("the JSON summary parses")
    }

    /// The committed full table: [`RECORDED_RUN_NOTE`] above the table
    /// derived from the recorded JSON summary.
    fn recorded_table() -> String {
        format!("{RECORDED_RUN_NOTE}{}", table(&recorded_summary()))
    }

    /// The derived table against the recorded full run, read from its JSON
    /// summary on disk: seconds, where the full pin above takes hours.
    #[test]
    #[ignore = "--economies, the derived table: reads the recorded JSON summary (379 MB) SHEKYL_ECONOMIES_SUMMARY names — on demand"]
    fn economies_table_matches_the_recorded_summary() {
        committed_fixture::assert_matches(
            "--economies derived table",
            TABLE_FIXTURE,
            &recorded_table(),
        );
    }

    /// The full narration, rendered from the recorded JSON summary
    /// [`SUMMARY_PATH_ENV`] names.
    fn narration_from_recorded_summary() -> String {
        let mut narration = String::new();
        write_report(&mut narration, &recorded_summary().rows, Scope::Full)
            .expect("String sink is infallible");
        narration
    }

    /// The full narration rendered from the recorded JSON summary, against
    /// the narration's recorded SHA-256: the summary is the run's record, so
    /// it renders the run's narration byte for byte without folding again.
    #[test]
    #[ignore = "--economies, the full narration: renders the recorded JSON summary (379 MB) SHEKYL_ECONOMIES_SUMMARY names — on demand"]
    fn economies_narration_renders_from_the_recorded_summary() {
        assert_eq!(
            sha256_hex(&narration_from_recorded_summary()),
            recorded_digest(FULL_NARRATION_NAME),
            "the narration rendered from the recorded JSON summary is not the one {FULL_DIGESTS} records"
        );
    }

    /// Armed: rewrites the derived table from the recorded JSON summary on
    /// disk under a cited decision, for a change to the table's form.
    #[test]
    #[ignore = "armed regeneration helper; writes the derived table from the recorded JSON summary SHEKYL_ECONOMIES_SUMMARY names; requires SHEKYL_PINNED_REGEN_DECISION"]
    fn regen_economies_table_fixture() {
        regenerate(
            "the --economies derived table",
            &[Output {
                path: TABLE_FIXTURE,
                build: recorded_table,
            }],
        );
    }

    /// Armed: rewrites the nightly slice's narration and table, from one
    /// fold of the slice, under a cited decision.
    #[test]
    #[ignore = "armed regeneration helper; writes the nightly slice's committed narration and table; requires SHEKYL_PINNED_REGEN_DECISION"]
    fn regen_economies_nightly_fixtures() {
        regenerate(
            "the --economies nightly narration and table",
            &[
                Output {
                    path: NIGHTLY_FIXTURE,
                    build: || nightly().narration.clone(),
                },
                Output {
                    path: NIGHTLY_TABLE_FIXTURE,
                    build: || nightly().table.clone(),
                },
            ],
        );
    }

    /// Armed: re-renders the full narration from the recorded JSON summary
    /// under a cited decision, for a change to the narration's wording, and
    /// rewrites its SHA-256 in [`FULL_DIGESTS`]. The summary and its SHA-256
    /// stay: nothing is folded again. The narration is written to
    /// [`FULL_OUTPUT_DIR_ENV`]'s directory, to be kept beside the summary.
    #[test]
    #[ignore = "armed regeneration helper; re-renders the full narration from the recorded JSON summary SHEKYL_ECONOMIES_SUMMARY names and rewrites its digest; requires SHEKYL_PINNED_REGEN_DECISION and SHEKYL_ECONOMIES_FULL_DIR"]
    fn regen_economies_full_narration_digest() {
        assert!(
            std::env::var(FULL_OUTPUT_DIR_ENV).is_ok(),
            "{FULL_OUTPUT_DIR_ENV} names no directory for the re-rendered narration"
        );
        regenerate(
            "the --economies full narration's digest, re-rendered from the recorded JSON summary",
            &[Output {
                path: FULL_DIGESTS,
                build: || {
                    let narration = narration_from_recorded_summary();
                    let dir = std::env::var(FULL_OUTPUT_DIR_ENV).expect("checked above");
                    let path = std::path::Path::new(&dir).join(FULL_NARRATION_NAME);
                    std::fs::write(&path, &narration).expect("write the re-rendered narration");
                    eprintln!("wrote {}", path.display());
                    digest_lines(&sha256_hex(&narration), &recorded_digest(FULL_SUMMARY_NAME))
                },
            }],
        );
    }

    /// Armed: rewrites the full run's recorded digests and the derived
    /// table, from one full fold, under a cited decision. Refuses unless
    /// [`FULL_OUTPUT_DIR_ENV`] names where the two files go: a digest of
    /// bytes nobody kept proves nothing.
    #[test]
    #[ignore = "armed regeneration helper; writes the full run's digests and the derived table, and the run's narration and JSON summary into SHEKYL_ECONOMIES_FULL_DIR; requires SHEKYL_PINNED_REGEN_DECISION"]
    fn regen_economies_full_fixtures() {
        assert!(
            std::env::var(FULL_OUTPUT_DIR_ENV).is_ok(),
            "{FULL_OUTPUT_DIR_ENV} names no directory for the full run's narration and JSON summary"
        );
        regenerate(
            "the --economies full run's digests and derived table",
            &[
                Output {
                    path: FULL_DIGESTS,
                    build: || digests(&full().narration, &full().json),
                },
                Output {
                    path: TABLE_FIXTURE,
                    build: || full().table.clone(),
                },
            ],
        );
    }
}
