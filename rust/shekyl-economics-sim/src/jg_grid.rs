// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! J × G: the volume signal crossed with the zone
//! (`docs/design/ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.33 and §5.34; the
//! umbrella's §4.3).
//!
//! The grid crosses five signal arms (production's window sum, its median,
//! the median with the floor enforced on a stuffer's own bodies, the
//! baseline in place of volume, and `M_r` alone held at 1.0 by the release
//! rails) with honest traffic that is steady or varies block to block, and
//! with the zone, stated as N 2-in/2-out spends plus the coinbase reserve,
//! on two `w_ref` levels held fixed across N. On each it reads the honest
//! chain (where it rests, the year-1 Standard fee, a day's fill, the year
//! blocks carry the design load, the step) and a stuffer at each share
//! from two start years. Every cell is the production fold with overrides
//! on the zone, `w_ref` and, for the rails-only arm, the release rails; the
//! median and the baseline are the fold's `VolumeSignal`, the traffic its
//! `Traffic`. It prints measures, never verdicts.

use std::collections::HashMap;
use std::fmt;

#[path = "jg_report.rs"]
mod report;

use serde::Serialize;
use shekyl_tx_weight::{predict_weight, InputCount, OutputCount};
use shekyl_wire::transaction::COINBASE_RESERVE;

use crate::baseline::Override;
use crate::calibration::tree_depth_for_leaves;
use crate::chain_cursor::{OwnFee, Traffic};
use crate::engine::SimParams;
use crate::esr10::{
    genesis_standard_tx, rederived_pair, scenario_named, year_one_fee_ceiling,
    year_one_standard_fee,
};
use crate::eup4::skl;
use crate::honest_step::honest_step;
use crate::onset::at_horizon;
use crate::rng::HONEST_SEEDS;
use crate::scenarios::BASELINE_STEADY_STATE;
use crate::stage2::{a1_year_aggs_probed, NoProbe};
use crate::volume_window::VolumeSignal;
use crate::window_stuffer::{
    at_rest, fold_campaign, scaled, Campaign, Folded, CAMPAIGN_START_YEARS, MEASURED_BLOCKS,
    STUFFER_SHARES_PCT,
};

/// The zone points the brief names, in 2-in/2-out spends beside the
/// inherited and re-derived zones: from 14 to 150, Rick's target at 90.
const SPENDS: [u64; 12] = [14, 20, 25, 30, 35, 45, 60, 75, 90, 105, 120, 150];

/// The inherited zone (`config/consensus_constants.json`).
const INHERITED_ZONE: u64 = 300_000;

/// Every miner, as a share of the blocks.
const EVERY_MINER: u64 = 100;

/// The release rails at 1.0, which hold `M_r` at 1.0 and leave the burn and
/// `C` on the sum (§5.33's arm 5, `rails-only` since §5.34).
const RAILS_AT_ONE: u64 = 1_000_000;

/// The design load, in 2-in/2-out spends a block
/// (`DAEMON_REDB_STORE.md` §1.3a.6, ruling 1).
const DESIGN_LOAD_SPENDS: u64 = 30;

/// The design load as ordinary transactions a block: its spends' weight
/// over the ordinary 1-in/2-out's, rounded up, both at genesis depth and
/// the genesis Standard fee (§5.33: a count, as the fold carries).
fn design_load_txs(base: &SimParams) -> u64 {
    let ordinary = genesis_standard_tx(base).weight;
    (DESIGN_LOAD_SPENDS * reference_spend_weight(base)).div_ceil(ordinary)
}

/// One of J's arms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Signal {
    /// Production's window sum.
    Sma,
    /// The window's median (arm 1), against the shipped baseline.
    Median,
    /// The median against the baseline restated in median terms (§5.34):
    /// on variable traffic only, where it is defined.
    MedianRestated,
    /// The median, with the stuffer paying the floor on its own bodies
    /// (arm 2): the median's honest chain, enforced terms.
    MedianEnforced,
    /// The baseline in place of volume (arm 5, §5.34): release, the burn and
    /// `C` read no volume.
    Decoupled,
    /// `M_r` alone held at 1.0 by the release rails; the burn and `C` still
    /// read the sum (§5.33's arm 5).
    RailsOnly,
}

impl Signal {
    const CAMPAIGNS: [Self; 6] = [
        Self::Sma,
        Self::Median,
        Self::MedianRestated,
        Self::MedianEnforced,
        Self::Decoupled,
        Self::RailsOnly,
    ];
    /// The arms with an honest chain of their own: arm 2 is the median's.
    const HONEST: [Self; 5] = [
        Self::Sma,
        Self::Median,
        Self::MedianRestated,
        Self::Decoupled,
        Self::RailsOnly,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Sma => "SMA",
            Self::Median => "median",
            Self::MedianRestated => "median-r",
            Self::MedianEnforced => "median+floor",
            Self::Decoupled => "decoupled",
            Self::RailsOnly => "rails-only",
        }
    }

    /// The honest chain the arm runs on.
    const fn honest(self) -> Self {
        match self {
            Self::MedianEnforced => Self::Median,
            other => other,
        }
    }

    /// What the stuffer's own bodies pay.
    const fn own_fee(self) -> OwnFee {
        match self {
            Self::MedianEnforced => OwnFee::RelayFloor,
            Self::Sma | Self::Median | Self::MedianRestated | Self::Decoupled | Self::RailsOnly => {
                OwnFee::None
            }
        }
    }

    const fn volume_signal(self) -> VolumeSignal {
        match self {
            Self::Sma | Self::RailsOnly => VolumeSignal::Sum,
            Self::Median | Self::MedianEnforced => VolumeSignal::Median,
            Self::MedianRestated => VolumeSignal::MedianRestated,
            Self::Decoupled => VolumeSignal::Fixed,
        }
    }

    /// Whether the arm runs on `traffic`: the restated baseline is the
    /// median of variable traffic, so it has no steady cell.
    const fn runs_on(self, traffic: Traffic) -> bool {
        !matches!((self, traffic), (Self::MedianRestated, Traffic::Steady))
    }

    /// Whether the arm's unclamped ratio is one honest count.
    const fn reads_a_count(self) -> bool {
        matches!(
            self,
            Self::Median | Self::MedianEnforced | Self::MedianRestated
        )
    }

    /// The honest per-block count a median arm's unclamped ratio reads, or
    /// `None` for an arm that reads no single count.
    fn median_count(self, ratio: u64, baseline: u64) -> Option<u64> {
        let scale = shekyl_economics::params::SCALE;
        match self {
            Self::Median | Self::MedianEnforced => Some(ratio * baseline / scale),
            Self::MedianRestated => {
                Some((ratio * crate::rng::geometric_median(baseline) + scale / 2) / scale)
            }
            Self::Sma | Self::Decoupled | Self::RailsOnly => None,
        }
    }
}

/// One zone point.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Zone {
    pub(crate) label: String,
    pub(crate) bytes: u64,
}

/// The 2-in/2-out spend's weight at genesis depth and the genesis Standard
/// fee: the zone's reference transaction.
pub(crate) fn reference_spend_weight(base: &SimParams) -> u64 {
    let fee = genesis_standard_tx(base).fee_atomic;
    predict_weight(
        InputCount::clamped(2),
        OutputCount::clamped(2),
        tree_depth_for_leaves(0),
        fee,
    ) as u64
}

/// The zone axis, smallest first: the brief's spends at the reference
/// weight plus the coinbase reserve, and the inherited and re-derived zones.
pub(crate) fn zones(base: &SimParams, spends: &[u64]) -> Vec<Zone> {
    let reference = reference_spend_weight(base);
    let reserve = u64::try_from(COINBASE_RESERVE).expect("the reserve fits");
    let mut zones: Vec<Zone> = spends
        .iter()
        .map(|&n| Zone {
            label: format!("N = {n}"),
            bytes: n * reference + reserve,
        })
        .collect();
    zones.push(Zone {
        label: "inherited".into(),
        bytes: INHERITED_ZONE,
    });
    zones.push(Zone {
        label: "re-derived".into(),
        bytes: rederived_pair(base).zone,
    });
    zones.sort_by_key(|z| z.bytes);
    zones
}

/// Steady traffic, or variable traffic at one seed.
fn traffic_name(traffic: Traffic) -> String {
    match traffic {
        Traffic::Steady => "steady".into(),
        Traffic::Variable(seed) => format!("variable s{seed}"),
    }
}

/// Steady traffic, then variable traffic, each family in seed order.
/// An empty family is omitted.
fn families(traffic: &[Traffic]) -> Vec<Vec<Traffic>> {
    let steady: Vec<Traffic> = traffic
        .iter()
        .copied()
        .filter(|t| matches!(t, Traffic::Steady))
        .collect();
    let variable: Vec<Traffic> = traffic
        .iter()
        .copied()
        .filter(|t| matches!(t, Traffic::Variable(_)))
        .collect();
    [steady, variable]
        .into_iter()
        .filter(|family| !family.is_empty())
        .collect()
}

/// `steady` or `variable`. A line is one family.
fn family_name(traffic: &[Traffic]) -> &'static str {
    assert!(!traffic.is_empty(), "a printed line names its traffic");
    match traffic[0] {
        Traffic::Steady => {
            assert!(
                traffic.iter().all(|t| matches!(t, Traffic::Steady)),
                "a printed line is one family"
            );
            "steady"
        }
        Traffic::Variable(_) => {
            assert!(
                traffic.iter().all(|t| matches!(t, Traffic::Variable(_))),
                "a printed line is one family"
            );
            "variable"
        }
    }
}

/// A cell's parameters: the zone, `w_ref`, the arm's rails and signal, and
/// the traffic.
fn cell(base: &SimParams, signal: Signal, traffic: Traffic, zone: u64, w_ref: u64) -> SimParams {
    let mut texts = vec![
        format!("economic.full_reward_zone={zone}"),
        format!("relay.ref_tx_weight={w_ref}"),
    ];
    if signal == Signal::RailsOnly {
        texts.push(format!("economic.release_min={RAILS_AT_ONE}"));
        texts.push(format!("economic.release_max={RAILS_AT_ONE}"));
    }
    let overrides: Vec<Override> = texts
        .iter()
        .map(|t| Override::parse(t).expect("well-formed"))
        .collect();
    let mut params = base
        .with_more(overrides)
        .expect("a grid cell passes the validators");
    params.volume_signal = signal.volume_signal();
    params.traffic = traffic;
    params
}

/// The honest chain's reading in one cell, at one seed.
#[derive(Debug, Clone, Serialize)]
pub struct HonestRow {
    signal: &'static str,
    traffic: String,
    zone: String,
    zone_bytes: u64,
    w_ref: u64,
    year_one_standard_fee_skl: Option<f64>,
    over_ceiling: Option<f64>,
    /// A day's blocks filled to the zone at the year-1 relay floor, SKL.
    fill_a_day_skl: f64,
    /// The first year whose blocks carry the design load.
    design_load_year: Option<u64>,
    /// Where the chain rests before the step: the operand over the
    /// baseline, unclamped, a window's mean.
    resting_ratio: f64,
    /// The step's up-edge: `M_r` before and after, each a window's mean,
    /// and the blocks to 95 % of that move.
    step_m_r: (f64, f64),
    step_settles_blocks: Option<u64>,
    /// A median arm's honest count over year 1 after the window's first
    /// fill: its mean, and the share of blocks at the derived median less
    /// one and at the derived median.
    median_count: Option<MedianCount>,
}

/// A median arm's measured honest count (§5.34), beside the derived one.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct MedianCount {
    derived: u64,
    mean: f64,
    below_pct: f64,
    at_pct: f64,
}

/// One campaign's reading in one cell, at one seed.
#[derive(Debug, Clone, Serialize)]
pub struct CampaignRow {
    signal: &'static str,
    traffic: String,
    zone: String,
    w_ref: u64,
    start_year: u64,
    share_pct: u64,
    bodies: u64,
    /// `M_r` at the span's last block.
    m_r_last: f64,
    /// `M_r` and the operand over the baseline, unclamped, over the span's
    /// last window.
    m_r_at_rest: f64,
    ratio_at_rest: f64,
    mean_m_r: f64,
    longest_run_blocks: u64,
    net_gain_skl: f64,
    /// The burn rate on the stuffer's own floor fees at which its net gain
    /// is zero, percent; `None` with no bodies.
    break_even_burn_pct: Option<f64>,
    /// The burn rate and `C` at the span's last block.
    burn_last_pct: f64,
    c_last: f64,
}

/// What `--jg-grid` prints as JSON.
#[derive(Debug, Default, Serialize)]
pub struct Summary {
    reference_spend_weight: u64,
    honest: Vec<HonestRow>,
    campaigns: Vec<CampaignRow>,
}

/// How much of the grid a run folds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Every point: `--jg-grid`, and the on-demand pin.
    Full,
    /// The nightly pin's slice: the inherited zone and N = 90, the SMA, the
    /// median and the restated median, steady and the canonical seed, 20 %
    /// and 51 %, from year 5.
    #[cfg(test)]
    Nightly,
}

fn honest_row(
    base: &SimParams,
    signal: Signal,
    traffic: Traffic,
    zone: &Zone,
    w_ref: u64,
) -> HonestRow {
    let params = cell(base, signal, traffic, zone.bytes, w_ref);
    let config = at_horizon(scenario_named(&params, BASELINE_STEADY_STATE));
    let aggs = a1_year_aggs_probed(&params, &config, &mut NoProbe);
    let bpy = params.blocks_per_year();
    let ceiling = year_one_fee_ceiling();
    let fee = year_one_standard_fee(&aggs);
    let blocks_a_day = 86_400 / params.economic().daa_target_seconds;
    let floor = aggs.first().map_or(0, |a| a.admission_rate.atomic());
    let load = design_load_txs(base);
    let design_load_year = aggs
        .iter()
        .find(|a| a.carried_txs() >= u128::from(load) * u128::from(bpy))
        .map(|a| a.year);
    let step = honest_step(&params);
    let up = &step.up;
    let baseline = params.economic().tx_volume_baseline;
    let derived = crate::rng::geometric_median(baseline);
    // A variable-traffic reading only: on steady traffic every block
    // carries the schedule's count, so there is no distribution to read.
    let median_count =
        (signal.reads_a_count() && matches!(traffic, Traffic::Variable(_))).then(|| {
            let (mut blocks, mut sum, mut below, mut at) = (0u64, 0u128, 0u64, 0u64);
            for (&ratio, &n) in &step.year_one_ratios {
                let count = signal
                    .median_count(ratio, baseline)
                    .expect("a median arm reads its count");
                blocks += n;
                sum += u128::from(count) * u128::from(n);
                if count + 1 == derived {
                    below += n;
                } else if count == derived {
                    at += n;
                }
            }
            let share = |n: u64| 100.0 * n as f64 / blocks.max(1) as f64;
            MedianCount {
                derived,
                mean: sum as f64 / blocks.max(1) as f64,
                below_pct: share(below),
                at_pct: share(at),
            }
        });
    HonestRow {
        signal: signal.name(),
        traffic: traffic_name(traffic),
        zone: zone.label.clone(),
        zone_bytes: zone.bytes,
        w_ref,
        year_one_standard_fee_skl: fee.map(|f| skl(u128::from(f))),
        over_ceiling: fee.map(|f| f as f64 / ceiling as f64),
        fill_a_day_skl: skl(u128::from(zone.bytes) * u128::from(floor) * u128::from(blocks_a_day)),
        design_load_year,
        resting_ratio: up.resting_ratio,
        step_m_r: (up.before, up.after),
        step_settles_blocks: up.settles,
        median_count,
    }
}

/// The axes a scope crosses.
struct Axes {
    spends: Vec<u64>,
    /// Whether the re-derived zone joins the N points.
    with_rederived: bool,
    signals: Vec<Signal>,
    honest_signals: Vec<Signal>,
    traffic: Vec<Traffic>,
    shares: Vec<u64>,
    starts: Vec<u64>,
}

impl Scope {
    fn axes(self) -> Axes {
        match self {
            Self::Full => Axes {
                spends: SPENDS.to_vec(),
                with_rederived: true,
                signals: Signal::CAMPAIGNS.to_vec(),
                honest_signals: Signal::HONEST.to_vec(),
                traffic: std::iter::once(Traffic::Steady)
                    .chain(HONEST_SEEDS.map(Traffic::Variable))
                    .collect(),
                shares: STUFFER_SHARES_PCT
                    .into_iter()
                    .chain([EVERY_MINER])
                    .collect(),
                starts: CAMPAIGN_START_YEARS.to_vec(),
            },
            // The nightly slice: the inherited zone and N = 90, the SMA, the
            // median and the restated median, steady and the canonical seed,
            // 20 % and 51 %, from year 5.
            #[cfg(test)]
            Self::Nightly => {
                let signals = vec![Signal::Sma, Signal::Median, Signal::MedianRestated];
                Axes {
                    spends: vec![90],
                    with_rederived: false,
                    honest_signals: signals.clone(),
                    signals,
                    traffic: vec![Traffic::Steady, Traffic::Variable(HONEST_SEEDS[0])],
                    shares: vec![20, 51],
                    starts: vec![CAMPAIGN_START_YEARS[0]],
                }
            }
        }
    }
}

/// One honest line: one signal, one traffic family, one zone, one `w_ref`.
struct HonestGroup {
    signal: Signal,
    traffic: Vec<Traffic>,
    zone: usize,
    w_ref: u64,
}

struct HonestJob {
    group: usize,
    signal: Signal,
    traffic: Traffic,
    zone: usize,
    w_ref: u64,
}

/// One campaign line: the same, plus the year and the share.
struct CampaignGroup {
    signal: Signal,
    traffic: Vec<Traffic>,
    zone: usize,
    w_ref: u64,
    year: u64,
    share: u64,
}

struct CampaignJob {
    group: usize,
    signal: Signal,
    traffic: Traffic,
    zone: usize,
    w_ref: u64,
    year: u64,
    share: u64,
}

/// The seeds of `family` the arm runs on, in the family's order.
fn seeds_of(signal: Signal, family: &[Traffic]) -> Vec<Traffic> {
    family
        .iter()
        .copied()
        .filter(|&traffic| signal.runs_on(traffic))
        .collect()
}

/// The grid at `scope`.
///
/// # Errors
///
/// The sink's.
pub fn run(
    out: &mut impl fmt::Write,
    base: &SimParams,
    scope: Scope,
) -> Result<Summary, fmt::Error> {
    let Axes {
        spends,
        with_rederived,
        signals,
        honest_signals,
        traffic,
        shares,
        starts,
    } = scope.axes();
    let zone_axis: Vec<Zone> = zones(base, &spends)
        .into_iter()
        .filter(|zone| with_rederived || zone.label != "re-derived")
        .collect();
    let w_refs = [base.relay().ref_tx_weight, rederived_pair(base).w_ref];
    let reference = reference_spend_weight(base);
    let seeds: Vec<String> = traffic
        .iter()
        .filter_map(|t| match t {
            Traffic::Variable(seed) => Some(seed.to_string()),
            Traffic::Steady => None,
        })
        .collect();
    let derived = crate::rng::geometric_median(base.economic().tx_volume_baseline);
    let families = families(&traffic);
    report::write_opening(out, derived, reference, w_refs, &seeds)?;
    let mut honest_groups: Vec<HonestGroup> = Vec::new();
    let mut honest_jobs: Vec<HonestJob> = Vec::new();
    for &signal in &honest_signals {
        for family in &families {
            let seeds = seeds_of(signal, family);
            if seeds.is_empty() {
                continue;
            }
            for zone in 0..zone_axis.len() {
                for &w_ref in &w_refs {
                    let group = honest_groups.len();
                    for &traffic in &seeds {
                        honest_jobs.push(HonestJob {
                            group,
                            signal,
                            traffic,
                            zone,
                            w_ref,
                        });
                    }
                    honest_groups.push(HonestGroup {
                        signal,
                        traffic: seeds.clone(),
                        zone,
                        w_ref,
                    });
                }
            }
        }
    }
    let honest_rows = crate::parallel::map(&honest_jobs, |job| {
        honest_row(
            base,
            job.signal,
            job.traffic,
            &zone_axis[job.zone],
            job.w_ref,
        )
    });
    let mut honest_by_group: Vec<Vec<HonestRow>> = honest_groups
        .iter()
        .map(|group| Vec::with_capacity(group.traffic.len()))
        .collect();
    for (job, row) in honest_jobs.iter().zip(honest_rows) {
        honest_by_group[job.group].push(row);
    }
    report::write_honest(
        out,
        base,
        derived,
        &zone_axis,
        &honest_groups,
        &honest_by_group,
    )?;
    // One unstuffed span per honest signal, seed, zone, w_ref and start.
    // Each printed line is the seeds of one family.
    type Key = (Signal, Traffic, usize, u64, u64);
    let mut bases: Vec<Key> = Vec::new();
    let mut base_index: HashMap<Key, usize> = HashMap::new();
    let mut campaign_groups: Vec<CampaignGroup> = Vec::new();
    let mut campaign_jobs: Vec<CampaignJob> = Vec::new();
    for zone in 0..zone_axis.len() {
        for &w_ref in &w_refs {
            for family in &families {
                for &signal in &signals {
                    let seeds = seeds_of(signal, family);
                    if seeds.is_empty() {
                        continue;
                    }
                    for &year in &starts {
                        for &traffic in &seeds {
                            let key = (signal.honest(), traffic, zone, w_ref, year);
                            base_index.entry(key).or_insert_with(|| {
                                bases.push(key);
                                bases.len() - 1
                            });
                        }
                        for &share in &shares {
                            let group = campaign_groups.len();
                            for &traffic in &seeds {
                                campaign_jobs.push(CampaignJob {
                                    group,
                                    signal,
                                    traffic,
                                    zone,
                                    w_ref,
                                    year,
                                    share,
                                });
                            }
                            campaign_groups.push(CampaignGroup {
                                signal,
                                traffic: seeds.clone(),
                                zone,
                                w_ref,
                                year,
                                share,
                            });
                        }
                    }
                }
            }
        }
    }
    let start = |params: &SimParams, year: u64| (year - 1) * params.blocks_per_year();
    let base_runs = crate::parallel::map(&bases, |&(signal, traffic, zone, w_ref, year)| {
        let params = cell(base, signal, traffic, zone_axis[zone].bytes, w_ref);
        let span = start(&params, year);
        fold_campaign(
            &params,
            year,
            Campaign::uniform(EVERY_MINER, span, None, MEASURED_BLOCKS),
        )
    });
    let campaign_runs = crate::parallel::map(&campaign_jobs, |job| {
        let params = cell(
            base,
            job.signal,
            job.traffic,
            zone_axis[job.zone].bytes,
            job.w_ref,
        );
        // Every share holds for the whole measured span: M_r at rest is then
        // where a stuffer holding that share keeps it, and a majority holds
        // over half the window throughout (§5.33.1).
        let campaign = Campaign::uniform(
            job.share,
            start(&params, job.year),
            Some(job.signal.own_fee()),
            MEASURED_BLOCKS,
        );
        (campaign, fold_campaign(&params, job.year, campaign))
    });
    let mut rows_by_group: Vec<Vec<CampaignRow>> = campaign_groups
        .iter()
        .map(|group| Vec::with_capacity(group.traffic.len()))
        .collect();
    for (job, (campaign, run)) in campaign_jobs.iter().zip(&campaign_runs) {
        let base_run: &Folded = &base_runs[*base_index
            .get(&(
                job.signal.honest(),
                job.traffic,
                job.zone,
                job.w_ref,
                job.year,
            ))
            .expect("every cell has its unstuffed span")];
        let (longest, _) = crate::window_stuffer::longest_run_above_one(&run.m_r);
        let mean = run.m_r.iter().map(|&m| u128::from(m)).sum::<u128>() as f64
            / run.m_r.len().max(1) as f64
            / shekyl_economics::params::SCALE as f64;
        let row = CampaignRow {
            signal: job.signal.name(),
            traffic: traffic_name(job.traffic),
            zone: zone_axis[job.zone].label.clone(),
            w_ref: job.w_ref,
            start_year: job.year,
            share_pct: job.share,
            bodies: run.listed,
            m_r_last: run.m_r.last().map_or(0.0, |&m| scaled(m)),
            m_r_at_rest: scaled(at_rest(&run.m_r)),
            ratio_at_rest: scaled(run.ratio_at_rest),
            mean_m_r: mean,
            longest_run_blocks: longest,
            net_gain_skl: run.net_gain(base_run, *campaign) as f64 / crate::burden::COIN as f64,
            break_even_burn_pct: run
                .break_even_burn(base_run, *campaign)
                .map(|burn| 100.0 * burn as f64 / shekyl_economics::params::SCALE as f64),
            burn_last_pct: 100.0 * scaled(run.burn_and_c.0),
            c_last: scaled(run.burn_and_c.1),
        };
        rows_by_group[job.group].push(row);
    }
    report::write_campaigns(out, &zone_axis, &campaign_groups, &rows_by_group)?;
    let campaigns = rows_by_group.into_iter().flatten().collect();
    let honest = honest_by_group.into_iter().flatten().collect();
    Ok(Summary {
        reference_spend_weight: reference,
        honest,
        campaigns,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committed_fixture::{self, regenerate, Output};
    use shekyl_economics::{calc_release_multiplier, TxVolume};

    /// The zone's reference transaction is the 2-in/2-out spend at genesis
    /// depth and the genesis Standard fee: 19 939 B, beside the ordinary
    /// 1-in/2-out's 12 595 B (`w_ref′`). The design load, 30 of them, is 48
    /// ordinary transactions.
    #[test]
    fn the_reference_spend_is_the_2_in_2_out_at_genesis_depth() {
        let base = SimParams::default();
        assert_eq!(reference_spend_weight(&base), 19_939);
        assert_eq!(
            genesis_standard_tx(&base).weight,
            rederived_pair(&base).w_ref
        );
        assert_eq!(design_load_txs(&base), 48);
    }

    /// The axis holds the brief's points, smallest first: N spends plus the
    /// reserve, the inherited zone and the re-derived one.
    #[test]
    fn the_zone_axis_is_the_briefs() {
        let base = SimParams::default();
        let axis = zones(&base, &SPENDS);
        assert_eq!(axis.len(), SPENDS.len() + 2);
        assert!(axis.windows(2).all(|w| w[0].bytes <= w[1].bytes));
        assert!(axis.iter().any(|z| z.bytes == INHERITED_ZONE));
        assert!(axis.iter().any(|z| z.bytes == rederived_pair(&base).zone));
        let reserve = u64::try_from(COINBASE_RESERVE).expect("fits");
        let target = axis
            .iter()
            .find(|z| z.label == "N = 90")
            .expect("Rick's target");
        assert_eq!(target.bytes, 90 * reference_spend_weight(&base) + reserve);
    }

    /// The rails-only arm's rails hold `M_r` at 1.0 whatever the window
    /// holds, and leave the burn and `C` on the sum; the decoupled arm reads
    /// the baseline and keeps the shipped rails. Their cells, and a variable
    /// one, pass the validators.
    #[test]
    fn the_arm_5_cells_cut_off_what_they_name() {
        let base = SimParams::default();
        let rails = cell(
            &base,
            Signal::RailsOnly,
            Traffic::Steady,
            INHERITED_ZONE,
            3_000,
        );
        let economic = rails.economic();
        for mean in [0, 25, 50, 500] {
            assert_eq!(
                calc_release_multiplier(
                    TxVolume::per_block(mean),
                    economic.tx_volume_baseline,
                    economic.release_min,
                    economic.release_max,
                ),
                RAILS_AT_ONE,
                "mean {mean}"
            );
        }
        assert_eq!(
            rails.volume_signal,
            VolumeSignal::Sum,
            "the burn and C read the sum"
        );
        let decoupled = cell(
            &base,
            Signal::Decoupled,
            Traffic::Variable(HONEST_SEEDS[0]),
            INHERITED_ZONE,
            3_000,
        );
        assert_eq!(decoupled.volume_signal, VolumeSignal::Fixed);
        assert_eq!(decoupled.traffic, Traffic::Variable(HONEST_SEEDS[0]));
        assert_eq!(
            (
                decoupled.economic().release_min,
                decoupled.economic().release_max
            ),
            (base.economic().release_min, base.economic().release_max),
            "the decoupled arm needs no rails: the baseline reads 1.0"
        );
        assert_eq!(
            cell(
                &base,
                Signal::MedianEnforced,
                Traffic::Steady,
                INHERITED_ZONE,
                3_000
            )
            .volume_signal,
            VolumeSignal::Median
        );
    }

    /// The restated median runs on variable traffic only, and each median
    /// arm reads its honest count back from its unclamped ratio: 35 at the
    /// shipped baseline is 0.7 on the median and 1.0 on the restated one.
    #[test]
    fn the_median_arms_read_their_count_back() {
        assert!(!Signal::MedianRestated.runs_on(Traffic::Steady));
        assert!(Signal::MedianRestated.runs_on(Traffic::Variable(2)));
        assert!(Signal::Median.runs_on(Traffic::Steady));
        let scale = shekyl_economics::params::SCALE;
        for count in [0u64, 34, 35, 36, 122] {
            let shipped = TxVolume::window(count * 720, 720).ratio_scaled(50);
            assert_eq!(Signal::Median.median_count(shipped, 50), Some(count));
            let restated = TxVolume::window(count * 720 * 50, 720 * 35).ratio_scaled(50);
            assert_eq!(
                Signal::MedianRestated.median_count(restated, 50),
                Some(count)
            );
        }
        assert_eq!(
            TxVolume::window(35 * 720 * 50, 720 * 35).ratio_scaled(50),
            scale
        );
        assert_eq!(Signal::Sma.median_count(scale, 50), None);
    }

    /// A figure across the seeds is its lower-middle median and its range.
    /// A figure some seed lacks is written seed by seed; none at all is the
    /// absence word.
    #[test]
    fn a_spread_is_the_median_and_the_range() {
        assert_eq!(report::show(&[1.5], 2), "1.50");
        assert_eq!(report::show(&[3.0, 1.0, 2.0], 1), "2.0 [1.0, 3.0]");
        assert_eq!(report::show(&[], 1), "-");
        assert_eq!(report::figure(&[Some(1.5)], 2, "no move"), "1.50");
        assert_eq!(
            report::figure(&[Some(3.0), Some(1.0), Some(2.0)], 1, "no move"),
            "2.0 [1.0, 3.0]"
        );
        assert_eq!(report::figure(&[None, None], 1, "no move"), "no move");
        assert_eq!(
            report::figure(&[Some(1.0), None, Some(3.0)], 0, "no move"),
            "1/-/3"
        );
        assert_eq!(report::same_label(&["y1".into(), "y1".into()]), "y1");
        assert_eq!(
            report::same_label(&["y1".into(), "never".into()]),
            "y1/never"
        );
    }

    fn path(scope: Scope) -> &'static str {
        match scope {
            Scope::Full => concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/jg_grid_narration.txt"
            ),
            Scope::Nightly => concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/jg_grid_narration_nightly.txt"
            ),
        }
    }

    fn narration(scope: Scope) -> String {
        let mut narration = String::new();
        run(&mut narration, &SimParams::default(), scope).expect("String sink is infallible");
        narration
    }

    /// The whole grid against its committed copy. Ignored by default and run
    /// on demand, on a fleet host: about 160 000 fold-years.
    #[test]
    #[ignore = "full --jg-grid, about 160 000 fold-years — on demand, not nightly; run with --release --ignored on a fleet host; fixture generated and checked on Linux x86-64"]
    fn jg_grid_narration_matches_the_committed_fixture() {
        committed_fixture::assert_matches(
            "--jg-grid narration",
            path(Scope::Full),
            &narration(Scope::Full),
        );
    }

    /// The nightly slice against its committed copy ([`Scope::Nightly`]).
    #[test]
    #[ignore = "--jg-grid's nightly slice — run with --release --ignored; nightly economics-sim-ignored; fixture generated and checked on Linux x86-64"]
    fn jg_grid_nightly_narration_matches_the_committed_fixture() {
        committed_fixture::assert_matches(
            "--jg-grid nightly narration",
            path(Scope::Nightly),
            &narration(Scope::Nightly),
        );
    }

    /// Regenerate both committed narrations, armed (rule 50).
    #[test]
    #[ignore = "armed regeneration helper; writes the committed fixtures; requires SHEKYL_PINNED_REGEN_DECISION"]
    fn regen_jg_grid_narration_fixtures() {
        regenerate(
            "the --jg-grid narrations",
            &[
                // The slice first: it is written minutes in, the full grid
                // hours later.
                Output {
                    path: path(Scope::Nightly),
                    build: || narration(Scope::Nightly),
                },
                Output {
                    path: path(Scope::Full),
                    build: || narration(Scope::Full),
                },
            ],
        );
    }
}
