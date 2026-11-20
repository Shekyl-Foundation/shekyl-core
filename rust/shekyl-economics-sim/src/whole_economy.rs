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

use serde::Serialize;
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
use crate::stage2::{a1_year_aggs_probed, penalty_to_stakers, A1YearAgg, BlockSeen, FoldProbe};
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
#[derive(Debug, Clone, Serialize)]
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
#[derive(Debug, Clone, Copy, Default, Serialize)]
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
#[derive(Debug, Clone, Default, Serialize)]
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

/// One adversary pricing, at a year's first block.
#[derive(Debug, Clone, Serialize)]
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
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Folded {
    pub(crate) years: Vec<YearFig>,
    /// The year the fold stopped at its supply break, if it did.
    pub(crate) stopped_at: Option<u64>,
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

    fn stops_at_supply_break(&self) -> bool {
        true
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
    let placed = at_place(base, &cell.place, cell.seed);
    let params = cell.economy.params(&placed, cell.rule);
    let config = scenario(&params, cell.scenario);
    let mut probe = EconomyProbe::new(&params, cell.economy.stuffs());
    let aggs = a1_year_aggs_probed(&params, &config, &mut probe);
    let mut years = probe.years;
    years.truncate(aggs.len());
    add_aggregates(&mut years, &aggs, &params);
    let stopped_at = (aggs.len() < HORIZON_YEARS as usize).then_some(aggs.len() as u64 + 1);
    let adversaries = adversaries(&probe.snapshots, &aggs, &params);
    let blocks_a_day = SECONDS_PER_DAY / params.economic().daa_target_seconds;
    let design_load_bytes_a_day =
        (DESIGN_LOAD_SPENDS * reference_spend_weight(&params) * blocks_a_day) as f64;
    let bond_per_gb = skl(u128::from(params.archival().bond_floor_atomic)) * BYTES_PER_GB as f64
        / SHARD_LENGTH.to_raw() as f64;
    Folded {
        years,
        stopped_at,
        half_year: probe.half_year,
        adoption: probe.adoption,
        adversaries,
        design_load_bytes_a_day,
        bond_per_gb,
    }
}

/// A row of the table: one economy, rule, scenario and place, its seeds'
/// folds.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Row {
    pub(crate) economy: String,
    pub(crate) rule: &'static str,
    pub(crate) scenario: &'static str,
    pub(crate) place: Place,
    pub(crate) seeds: Vec<u64>,
    pub(crate) folds: Vec<Folded>,
}

/// The `--economies` summary: every row, every year.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Summary {
    pub(crate) horizon_years: u64,
    pub(crate) tau_sweep_ms_per_kb: [f64; 2],
    pub(crate) rows: Vec<Row>,
}

/// The median and range of `values`, formatted with `digits` decimals.
fn mr(values: &[f64], digits: usize) -> String {
    let mut v: Vec<f64> = values.iter().copied().filter(|x| x.is_finite()).collect();
    if v.is_empty() {
        return "-".into();
    }
    v.sort_by(f64::total_cmp);
    let median = v[(v.len() - 1) / 2];
    if v.len() == 1 || (v[0] - v[v.len() - 1]).abs() < f64::EPSILON {
        return format!("{median:.digits$}");
    }
    format!(
        "{median:.digits$} [{:.digits$}, {:.digits$}]",
        v[0],
        v[v.len() - 1]
    )
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
                rule: cell.rule.name(),
                scenario: cell.scenario,
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
         supply break stops there and prints the year. SKL per block unless named.",
        match scope {
            Scope::Full => "full",
            Scope::Nightly => "nightly slice",
        },
        HONEST_SEEDS
    )?;
    let mut last: Option<(&str, &str, u64)> = None;
    for row in rows {
        let key = (row.scenario, row.place.zone.as_str(), row.place.w_ref);
        if last != Some(key) {
            writeln!(
                out,
                "\n== {} | zone {} ({} B) | w_ref {} ==",
                row.scenario, row.place.zone, row.place.zone_bytes, row.place.w_ref
            )?;
            last = Some(key);
        }
        write_row(out, row, scope)?;
    }
    Ok(())
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
        .map(|f| f.stopped_at.map_or("-".into(), |y| format!("y{y}")))
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
    // full table prints the sample years, which keeps its narration near
    // 1.6 MB instead of 8 MB; every year of every cell is in its JSON.
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
    let mut tail = String::from("   tail (miner's-net tail over miner's-net fees p50/p95/p99):");
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
            if at_year(row, year).any(|y| y.tail_share > 0.5) {
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
        "   distribution: emitted before demand reaches the baseline {} (at year {})",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committed_fixture::{self, regenerate, Output};

    /// The nightly slice's committed narration.
    const NIGHTLY_FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/economies_nightly_narration.txt"
    );
    /// The full table's committed narration.
    const FULL_FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/economies_narration.txt"
    );

    fn narration(scope: Scope) -> String {
        let mut out = String::new();
        run(&mut out, &SimParams::default(), scope).expect("String sink is infallible");
        out
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

    /// The nightly slice against its committed copy.
    #[test]
    #[ignore = "--economies nightly slice: 34 folds to y135 — nightly; run with --release --ignored; fixture generated and checked on Linux x86-64"]
    fn economies_nightly_narration_matches_the_committed_fixture() {
        committed_fixture::assert_matches(
            "--economies nightly narration",
            NIGHTLY_FIXTURE,
            &narration(Scope::Nightly),
        );
    }

    /// The full table against its committed copy.
    #[test]
    #[ignore = "--economies, the full table: 2 880 folds to y135 — on demand, not nightly; run with --release --ignored; fixture generated and checked on Linux x86-64"]
    fn economies_narration_matches_the_committed_fixture() {
        committed_fixture::assert_matches(
            "--economies narration",
            FULL_FIXTURE,
            &narration(Scope::Full),
        );
    }

    /// Armed: rewrites the committed narrations under a cited decision.
    #[test]
    #[ignore = "armed regeneration helper; writes the committed fixtures; requires SHEKYL_PINNED_REGEN_DECISION"]
    fn regen_economies_narration_fixtures() {
        regenerate(
            "the --economies narrations",
            &[
                Output {
                    path: NIGHTLY_FIXTURE,
                    build: || narration(Scope::Nightly),
                },
                Output {
                    path: FULL_FIXTURE,
                    build: || narration(Scope::Full),
                },
            ],
        );
    }
}
