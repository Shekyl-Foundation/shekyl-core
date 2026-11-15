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

use std::fmt;

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
use crate::onset::at_horizon;
use crate::scenarios::BASELINE_STEADY_STATE;
use crate::stage2::{a1_year_aggs_probed, NoProbe};
use crate::volume_window::VolumeSignal;
use crate::window_stuffer::{
    at_rest, fold_campaign, honest_step, scaled, Campaign, Folded, CAMPAIGN_START_YEARS,
    MEASURED_BLOCKS, STUFFER_SHARES_PCT,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Signal {
    /// Production's window sum.
    Sma,
    /// The window's median (arm 1).
    Median,
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
    const CAMPAIGNS: [Self; 5] = [
        Self::Sma,
        Self::Median,
        Self::MedianEnforced,
        Self::Decoupled,
        Self::RailsOnly,
    ];
    /// The arms with an honest chain of their own: arm 2 is the median's.
    const HONEST: [Self; 4] = [Self::Sma, Self::Median, Self::Decoupled, Self::RailsOnly];

    const fn name(self) -> &'static str {
        match self {
            Self::Sma => "SMA",
            Self::Median => "median",
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
            Self::Sma | Self::Median | Self::Decoupled | Self::RailsOnly => OwnFee::None,
        }
    }

    const fn volume_signal(self) -> VolumeSignal {
        match self {
            Self::Sma | Self::RailsOnly => VolumeSignal::Sum,
            Self::Median | Self::MedianEnforced => VolumeSignal::Median,
            Self::Decoupled => VolumeSignal::Baseline,
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

const fn traffic_name(traffic: Traffic) -> &'static str {
    match traffic {
        Traffic::Steady => "steady",
        Traffic::Varied => "varied",
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

/// The honest chain's reading in one cell.
#[derive(Debug, Clone, Serialize)]
pub struct HonestRow {
    signal: &'static str,
    traffic: &'static str,
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
    /// baseline, unclamped, and `M_r`, each a window's mean.
    resting_ratio: f64,
    /// The step's up-edge: `M_r` before and after, each a window's mean,
    /// and the blocks to 95 % of that move.
    step_m_r: (f64, f64),
    step_settles_blocks: Option<u64>,
}

/// One campaign's reading in one cell.
#[derive(Debug, Clone, Serialize)]
pub struct CampaignRow {
    signal: &'static str,
    traffic: &'static str,
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
    /// The nightly pin's slice: the inherited zone and N = 90, the SMA and
    /// the median, steady and varied, 20 % and 51 %, from year 5.
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
    let step = &honest_step(&params)[0];
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
        resting_ratio: step.resting_ratio,
        step_m_r: (step.before, step.after),
        step_settles_blocks: step.settles,
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
                traffic: vec![Traffic::Steady, Traffic::Varied],
                shares: STUFFER_SHARES_PCT
                    .into_iter()
                    .chain([EVERY_MINER])
                    .collect(),
                starts: CAMPAIGN_START_YEARS.to_vec(),
            },
            // The nightly slice: the inherited zone and N = 90, the SMA and
            // the median, steady and varied, 20 % and 51 %, from year 5.
            #[cfg(test)]
            Self::Nightly => Axes {
                spends: vec![90],
                with_rederived: false,
                signals: vec![Signal::Sma, Signal::Median],
                honest_signals: vec![Signal::Sma, Signal::Median],
                traffic: vec![Traffic::Steady, Traffic::Varied],
                shares: vec![20, 51],
                starts: vec![CAMPAIGN_START_YEARS[0]],
            },
        }
    }
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
    writeln!(
        out,
        "J x G — THE VOLUME SIGNAL CROSSED WITH THE ZONE (ECONOMICS_SIM_PRODUCTION_REBASE.md §5.33, §5.34).\n\
         Measures only. Signals: SMA (production's window sum), median (the window's lower-middle\n\
         per-block count), median+floor (the median, the stuffer paying the relay floor on its own\n\
         bodies), decoupled (the baseline in place of volume: release, the burn and C read none),\n\
         rails-only (release rails at 1.0; the burn and C still read the sum). Traffic: steady (the\n\
         schedule's demand every block) or varied (a geometric count around it, drawn at the block's\n\
         height: Poisson arrivals over exponential block intervals; the pool carries what a block does\n\
         not list). Zone: N 2-in/2-out spends of {reference} B (genesis depth and Standard fee) plus the\n\
         coinbase reserve ({} B), beside the inherited and re-derived zones; w_ref at {} and {} B, each\n\
         fixed across N. Not re-derived: TX_WEIGHT_LIMIT (the sim does not read it; it caps one\n\
         transaction, not a count) and COINBASE_RESERVE (it does not depend on the zone). A ratio is\n\
         the operand over the baseline before the release rails clamp it to [0.8, 1.3].",
        COINBASE_RESERVE, w_refs[0], w_refs[1]
    )?;
    // The honest chain, per signal, traffic, zone and w_ref.
    let honest_jobs: Vec<(Signal, Traffic, usize, u64)> = honest_signals
        .iter()
        .flat_map(|&s| traffic.iter().map(move |&t| (s, t)))
        .flat_map(|(s, t)| {
            (0..zone_axis.len()).flat_map(move |z| w_refs.into_iter().map(move |w| (s, t, z, w)))
        })
        .collect();
    let honest = crate::parallel::map(&honest_jobs, |&(s, t, z, w)| {
        honest_row(base, s, t, &zone_axis[z], w)
    });
    writeln!(
        out,
        "\nTHE HONEST CHAIN. Per signal, traffic, zone and w_ref: the ratio the chain rests at (the window\n\
         before the step), the year-1 Standard fee (SKL, and over the ceiling), a day's blocks filled to\n\
         the zone at the year-1 relay floor (SKL), the first year blocks carry the design load\n\
         ({DESIGN_LOAD_SPENDS} spends, {} ordinary transactions a block), and the declared step's up-edge: M_r over\n\
         the window before it and the trace's last window, and the blocks to 95 % of that move.",
        design_load_txs(base)
    )?;
    for row in &honest {
        writeln!(
            out,
            "  {:<12} {:<6} {:<12} {:>9} B w_ref {:>5}: rests {:.3} ; fee {} ; fill a day {:>10.1} ; design load {} ; step M_r {:.3}->{:.3} in {}",
            row.signal,
            row.traffic,
            row.zone,
            row.zone_bytes,
            row.w_ref,
            row.resting_ratio,
            match (row.year_one_standard_fee_skl, row.over_ceiling) {
                (Some(f), Some(c)) => format!("{f:.4} ({c:.2}x)"),
                _ => "none carried".to_string(),
            },
            row.fill_a_day_skl,
            row.design_load_year.map_or("never".to_string(), |y| format!("y{y}")),
            row.step_m_r.0,
            row.step_m_r.1,
            row.step_settles_blocks.map_or("no move".to_string(), |b| format!("{b} blocks")),
        )?;
    }
    // The campaigns: one unstuffed span per honest signal, traffic, zone,
    // w_ref and start, then each campaign.
    type Key = (Signal, Traffic, usize, u64, u64);
    let mut bases: Vec<Key> = Vec::new();
    let mut cells: Vec<(Key, u64)> = Vec::new();
    for z in 0..zone_axis.len() {
        for &w in &w_refs {
            for &t in &traffic {
                for &signal in &signals {
                    for &year in &starts {
                        let key = (signal.honest(), t, z, w, year);
                        if !bases.contains(&key) {
                            bases.push(key);
                        }
                        for &share in &shares {
                            cells.push(((signal, t, z, w, year), share));
                        }
                    }
                }
            }
        }
    }
    let start = |params: &SimParams, year: u64| (year - 1) * params.blocks_per_year();
    let base_runs = crate::parallel::map(&bases, |&(signal, t, z, w, year)| {
        let params = cell(base, signal, t, zone_axis[z].bytes, w);
        let span = start(&params, year);
        fold_campaign(
            &params,
            year,
            Campaign::uniform(EVERY_MINER, span, None, MEASURED_BLOCKS),
        )
    });
    let campaign_runs = crate::parallel::map(&cells, |&((signal, t, z, w, year), share)| {
        let params = cell(base, signal, t, zone_axis[z].bytes, w);
        // Every share holds for the whole measured span: M_r at rest is then
        // where a stuffer holding that share keeps it, and a majority holds
        // over half the window throughout (§5.33.1).
        let campaign = Campaign::uniform(
            share,
            start(&params, year),
            Some(signal.own_fee()),
            MEASURED_BLOCKS,
        );
        (campaign, fold_campaign(&params, year, campaign))
    });
    writeln!(
        out,
        "\nTHE STUFFER. Per signal, traffic, zone, w_ref and start: a stuffer holding its share (100 = every\n\
         miner) for the whole measured span ({MEASURED_BLOCKS} blocks from the start of the year); the bodies\n\
         listed, M_r at the span's last block, M_r and the ratio over its last window (at rest), M_r's mean\n\
         over the span, the longest run of M_r > 1.0, the stuffer's payout less its fees against no\n\
         stuffing (SKL), and the burn and C at the span's last block. A share is an even proportion of\n\
         the blocks; the bodies are the ordinary 1-in/2-out, the lightest valid shape (CEN-I1)."
    )?;
    let mut campaigns = Vec::new();
    let mut heading = None;
    for (&((signal, t, z, w, year), share), (campaign, run)) in cells.iter().zip(&campaign_runs) {
        let key = (z, w, t);
        if heading != Some(key) {
            writeln!(
                out,
                "== {} ({} B) | w_ref {w} | {}\n  {:<12} {:>3} {:>5} {:>7} {:>8} {:>8} {:>7} {:>7} {:>6} {:>14} {:>7} {:>7}",
                zone_axis[z].label,
                zone_axis[z].bytes,
                traffic_name(t),
                "signal",
                "y",
                "share",
                "bodies",
                "last",
                "at rest",
                "ratio",
                "mean",
                "run",
                "net gain SKL",
                "burn %",
                "C"
            )?;
            heading = Some(key);
        }
        let base_run: &Folded = &base_runs[bases
            .iter()
            .position(|&k| k == (signal.honest(), t, z, w, year))
            .expect("every cell has its unstuffed span")];
        let (longest, _) = crate::window_stuffer::longest_run_above_one(&run.m_r);
        let mean = run.m_r.iter().map(|&m| u128::from(m)).sum::<u128>() as f64
            / run.m_r.len().max(1) as f64
            / shekyl_economics::params::SCALE as f64;
        let row = CampaignRow {
            signal: signal.name(),
            traffic: traffic_name(t),
            zone: zone_axis[z].label.clone(),
            w_ref: w,
            start_year: year,
            share_pct: share,
            bodies: run.listed,
            m_r_last: run.m_r.last().map_or(0.0, |&m| scaled(m)),
            m_r_at_rest: scaled(at_rest(&run.m_r)),
            ratio_at_rest: scaled(at_rest(&run.ratio)),
            mean_m_r: mean,
            longest_run_blocks: longest,
            net_gain_skl: run.net_gain(base_run, *campaign) as f64 / crate::burden::COIN as f64,
            burn_last_pct: 100.0 * scaled(run.burn_and_c.0),
            c_last: scaled(run.burn_and_c.1),
        };
        writeln!(
            out,
            "  {:<12} {:>3} {:>4}% {:>7} {:>8.4} {:>8.4} {:>7.3} {:>7.4} {:>6} {:>14.2} {:>7.3} {:>7.4}",
            row.signal,
            row.start_year,
            row.share_pct,
            row.bodies,
            row.m_r_last,
            row.m_r_at_rest,
            row.ratio_at_rest,
            row.mean_m_r,
            row.longest_run_blocks,
            row.net_gain_skl,
            row.burn_last_pct,
            row.c_last,
        )?;
        campaigns.push(row);
    }
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
    /// the baseline and keeps the shipped rails. Their cells, and a varied
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
            Traffic::Varied,
            INHERITED_ZONE,
            3_000,
        );
        assert_eq!(decoupled.volume_signal, VolumeSignal::Baseline);
        assert_eq!(decoupled.traffic, Traffic::Varied);
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
    /// on demand, on a fleet host: about 70 000 fold-years.
    #[test]
    #[ignore = "full --jg-grid, about 70 000 fold-years — on demand, not nightly; run with --release --ignored on a fleet host; fixture generated and checked on Linux x86-64"]
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
                Output {
                    path: path(Scope::Full),
                    build: || narration(Scope::Full),
                },
                Output {
                    path: path(Scope::Nightly),
                    build: || narration(Scope::Nightly),
                },
            ],
        );
    }
}
