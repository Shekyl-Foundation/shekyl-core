// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! A1-T and A1-L — the **onset year** of A1 failure and the **lever table**
//! (`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §12.14).
//!
//! §12.13 found that in the byte unit no Stage-2 scenario has the escalation
//! clearing where the flat share does not, and that the one failing scenario
//! fails on the bond term. Its A1 verdict is a **minimum** over sustained
//! years, and a minimum hides *when* the failure arrives. The review of #929
//! modelled the same equations by hand and read three eras off them: emission
//! carries everything to ~year 15; the staker emission leg (half-life ≈ 2.9 y
//! under the 0.9/yr decay on a curve that halves every ~5.5 y) crosses the
//! linearly-growing bond burden somewhere in years 15–25; and from then on
//! the staker lives on `fees × burn_pct × share`, whose clearance against a
//! corpus `∝ V·t` is **independent of traffic `V`** — a fee *flow* funding a
//! bond *stock* can carry only the most recent `H` traffic-years of corpus.
//! This module measures all of that rather than taking it from the hand model.
//!
//! **A1-T** runs every Stage-2 scenario to [`ONSET_HORIZON_YEARS`] (the
//! schedules' own closures evaluated past their horizons — mechanical, and
//! flagged where unphysical) and reports, per scenario: the year the staker
//! emission leg first falls below the bond opportunity cost, the first year
//! the shipped budget fails to clear, and the flat-25 ratio per decade.
//!
//! **A1-L** prices the levers for the two scenarios that bracket the question
//! (the settled-chain tail and the busy steady chain, both at 60 y): share of
//! the burn at the band's top and at 100 %; share of **all** fees (the miner's
//! income included — the PoW security budget, named as such); a **non-decaying
//! staker floor** on emission at several percentages up to the whole perpetual
//! tail; and the staker-emission decay re-pinned. Each is a budget formed by
//! the production integer ops and folded through the one clearance function
//! (`stage2::a1_year_clearance_ratio`). The levers are **priced here, not
//! proposed**: every one of them is a genesis-frozen or ceremony-gated number,
//! and the table exists so the owner sees where each tops out instead of one
//! FAIL cell.

use std::fmt;

use serde::Serialize;
use shekyl_archival_retention::ARCHIVAL_BOND_FLOOR_ATOMIC;
use shekyl_economics::{
    burn::calc_burn_pct,
    calc_effective_emission_share,
    params::{mul_scale, SCALE},
    TxVolume,
};

use crate::burden::{
    normal_tx_archival_bytes, KryderRate, OPP_COST_RATE_BAND, REPLICAS_PER_SHARD,
    SKL_FIAT_PRICE_BAND,
};
use crate::engine::{ScenarioConfig, SimParams};
use crate::escalation::{family, flat_25, EscalationCurve, KNEE_BAND};
use crate::scenarios::all_scenarios;
use crate::stage2::{
    a1_min_clearance_ratio, a1_shipped_budget_atomic, a1_sustained_years, a1_year_aggs,
    a1_year_clearance_ratio, A1YearAgg,
};

/// Atomic units per SKL (mirrors `engine.rs`).
const COIN: f64 = 1_000_000_000.0;

/// The horizon every scenario is run to for the onset table. Long enough that
/// the emission curve (12.5 %/yr of the remainder at ESF 22 on 2-minute
/// blocks) has reached the tail floor, so the fee era is observed, not
/// extrapolated.
pub const ONSET_HORIZON_YEARS: u64 = 60;

/// The decades reported in the per-scenario series.
const DECADES: [u64; 6] = [10, 20, 30, 40, 50, 60];

/// Index of the binding opportunity-cost rate (10 %/yr) in the band.
const BINDING: usize = OPP_COST_RATE_BAND.len() - 1;

/// Non-decaying staker floor percentages priced in A1-L, fixed-point `SCALE`.
/// The last is the **whole** perpetual tail — the absolute ceiling of any
/// stock-shaped lever on emission.
pub const TAIL_FLOOR_BAND: [u64; 3] = [150_000, 500_000, 1_000_000];

/// Alternative staker-emission decay constants priced in A1-L, fixed-point
/// `SCALE` (`1_000_000` = no decay). The shipped `900_000` is a 2.9-year
/// half-life on the leg that carries clearance before the crossover, and it
/// was never derived against a bond burden.
pub const DECAY_BAND: [u64; 2] = [950_000, 1_000_000];

/// What the staker's fee leg is a share **of**.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum FeeBase {
    /// The fee burn — the shipped composition (`burn.rs`: `pool = burned ×
    /// share`). The `√V` damper in `calc_burn_pct` sits between fees and
    /// this.
    Burn,
    /// All fees, the miner's income included. Reaching into it is a PoW
    /// security-budget decision, not a parameter.
    AllFees,
}

/// An escalation candidate as the JSON reports it (A1's shape:
/// `asymptote_pct`, `knee_shards`).
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct CurveId {
    pub asymptote_pct: f64,
    pub knee_shards: u64,
}

impl From<EscalationCurve> for CurveId {
    fn from(c: EscalationCurve) -> Self {
        CurveId {
            asymptote_pct: c.asymptote as f64 / (SCALE as f64 / 100.0),
            knee_shards: c.knee_shards,
        }
    }
}

/// How the staker's fee share is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeShare {
    /// An escalation candidate's `share(n)` (the flat baseline included).
    Curve(EscalationCurve),
    /// A fixed share, fixed-point `SCALE`.
    Fixed(u64),
}

impl Serialize for FeeShare {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match *self {
            FeeShare::Curve(c) => CurveId::from(c).serialize(s),
            FeeShare::Fixed(v) => v.serialize(s),
        }
    }
}

/// How the staker's emission leg is formed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EmissionLeg {
    /// The shipped decaying split (`split_block_emission` per block, summed).
    Shipped,
    /// The shipped share with a re-pinned annual decay, applied to the year's
    /// total emission through the production share function at the year's
    /// midpoint height (within a year the factor moves < 1 %).
    Decay { annual_decay: u64 },
    /// The shipped leg floored at `floor × total emission` — a staker floor
    /// on the perpetual tail that does not decay.
    Floor { floor: u64 },
}

/// One priced lever: a way of forming the year's staker budget.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Lever {
    pub label: &'static str,
    pub fee_base: FeeBase,
    pub fee_share: FeeShare,
    pub emission: EmissionLeg,
}

impl Lever {
    /// The year's budget under this lever, **atomic** (DQ-2G: integer until
    /// the reported ratio).
    #[must_use]
    pub fn budget_atomic(&self, a: &A1YearAgg, params: &SimParams) -> u128 {
        let fee_pool = match self.fee_base {
            FeeBase::Burn => a.whole_burn_atomic,
            FeeBase::AllFees => a.whole_fees_atomic,
        };
        let share_milli = match self.fee_share {
            FeeShare::Curve(c) => c.share(a.n),
            FeeShare::Fixed(s) => s,
        };
        let fee_leg = u128::from(mul_scale(fee_pool, share_milli));
        let emission_leg = match self.emission {
            EmissionLeg::Shipped => u128::from(a.emission_leg_atomic),
            EmissionLeg::Decay { annual_decay } => {
                u128::from(emission_leg_at_decay(a, params, annual_decay))
            }
            EmissionLeg::Floor { floor } => u128::from(a.emission_leg_atomic)
                .max(u128::from(mul_scale(a.total_emission_atomic, floor))),
        };
        emission_leg + fee_leg
    }
}

/// The year's staker emission leg at an alternative decay: the production
/// share function evaluated at the year's midpoint height, applied to the
/// year's total emission with production's `mul_scale`. At the shipped decay
/// this reproduces `emission_leg_atomic` to well under 1 % (pinned below).
#[must_use]
pub fn emission_leg_at_decay(a: &A1YearAgg, params: &SimParams, annual_decay: u64) -> u64 {
    let mid_height = (a.year - 1) * params.blocks_per_year + params.blocks_per_year / 2;
    let share = calc_effective_emission_share(
        mid_height,
        0,
        params.staker_emission_share,
        annual_decay,
        params.blocks_per_year,
    );
    mul_scale(a.total_emission_atomic, share)
}

/// The lever set A1-L prices, in the order printed. `best` is the scenario's
/// strongest band candidate (A1's selection: max of the min ratio at 10 %).
fn lever_set(best: EscalationCurve) -> Vec<Lever> {
    let flat = flat_25();
    vec![
        Lever {
            label: "shipped: burn x flat 25%",
            fee_base: FeeBase::Burn,
            fee_share: FeeShare::Curve(flat),
            emission: EmissionLeg::Shipped,
        },
        Lever {
            label: "burn x best band cand.",
            fee_base: FeeBase::Burn,
            fee_share: FeeShare::Curve(best),
            emission: EmissionLeg::Shipped,
        },
        Lever {
            label: "burn x 100%",
            fee_base: FeeBase::Burn,
            fee_share: FeeShare::Fixed(SCALE),
            emission: EmissionLeg::Shipped,
        },
        Lever {
            label: "ALL fees x 25%",
            fee_base: FeeBase::AllFees,
            fee_share: FeeShare::Curve(flat),
            emission: EmissionLeg::Shipped,
        },
        Lever {
            label: "ALL fees x 100% (PoW)",
            fee_base: FeeBase::AllFees,
            fee_share: FeeShare::Fixed(SCALE),
            emission: EmissionLeg::Shipped,
        },
        Lever {
            label: "flat + tail floor 15%",
            fee_base: FeeBase::Burn,
            fee_share: FeeShare::Curve(flat),
            emission: EmissionLeg::Floor {
                floor: TAIL_FLOOR_BAND[0],
            },
        },
        Lever {
            label: "flat + tail floor 50%",
            fee_base: FeeBase::Burn,
            fee_share: FeeShare::Curve(flat),
            emission: EmissionLeg::Floor {
                floor: TAIL_FLOOR_BAND[1],
            },
        },
        Lever {
            label: "flat + WHOLE tail (100%)",
            fee_base: FeeBase::Burn,
            fee_share: FeeShare::Curve(flat),
            emission: EmissionLeg::Floor {
                floor: TAIL_FLOOR_BAND[2],
            },
        },
        Lever {
            label: "flat + decay 0.95/yr",
            fee_base: FeeBase::Burn,
            fee_share: FeeShare::Curve(flat),
            emission: EmissionLeg::Decay {
                annual_decay: DECAY_BAND[0],
            },
        },
        Lever {
            label: "flat + NO decay",
            fee_base: FeeBase::Burn,
            fee_share: FeeShare::Curve(flat),
            emission: EmissionLeg::Decay {
                annual_decay: DECAY_BAND[1],
            },
        },
    ]
}

/// A scenario's config re-horizoned to [`ONSET_HORIZON_YEARS`]. The schedule
/// is the scenario's own closure evaluated past its horizon.
fn at_horizon(mut config: ScenarioConfig) -> ScenarioConfig {
    config.sim_years = ONSET_HORIZON_YEARS;
    config
}

/// A1's selection rule, applied to one aggregate series: the band candidate
/// with the greatest min clearance at the binding rate.
fn best_candidate(aggs: &[A1YearAgg]) -> EscalationCurve {
    let mid_price = SKL_FIAT_PRICE_BAND[1];
    family()
        .into_iter()
        .max_by(|a, b| {
            let ra = a1_min_clearance_ratio(
                aggs,
                a,
                OPP_COST_RATE_BAND[BINDING],
                mid_price,
                KryderRate::Stall,
            );
            let rb = a1_min_clearance_ratio(
                aggs,
                b,
                OPP_COST_RATE_BAND[BINDING],
                mid_price,
                KryderRate::Stall,
            );
            ra.total_cmp(&rb)
        })
        .expect("the escalation family is non-empty")
}

/// Per-year clearance under a budget function, over the sustained years.
fn year_ratios<'a>(
    aggs: &'a [A1YearAgg],
    rate: f64,
    budget: impl Fn(&A1YearAgg) -> u128 + 'a,
) -> impl Iterator<Item = (u64, f64)> + 'a {
    let mid_price = SKL_FIAT_PRICE_BAND[1];
    a1_sustained_years(aggs).map(move |a| {
        (
            a.year,
            a1_year_clearance_ratio(a, budget(a), rate, mid_price, KryderRate::Stall),
        )
    })
}

/// The first sustained year whose ratio is `< 1`, and whether any later year
/// clears again (a cyclic schedule can dip and recover).
#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub struct Onset {
    pub year: Option<u64>,
    pub recovers: bool,
}

fn onset_of(ratios: impl Iterator<Item = (u64, f64)>) -> Onset {
    let mut year = None;
    let mut recovers = false;
    for (y, r) in ratios {
        match (year, r < 1.0) {
            (None, true) => year = Some(y),
            (Some(_), false) => recovers = true,
            _ => {}
        }
    }
    Onset { year, recovers }
}

fn fmt_onset(o: Onset) -> String {
    match o.year {
        None => "never".to_string(),
        Some(y) if o.recovers => format!("y{y}*"),
        Some(y) => format!("y{y}"),
    }
}

/// A1-T row: one scenario at the 60-year horizon.
#[derive(Debug, Clone, Serialize)]
pub struct OnsetScenarioResult {
    pub scenario: String,
    pub horizon_years: u64,
    /// Closed shards at the horizon.
    pub final_n: u64,
    /// First year the staker **emission leg alone** falls below the bond
    /// opportunity cost at 10 % — the end of the era emission carries.
    pub emission_crossover_year: Option<u64>,
    pub onset_flat_binding: Onset,
    pub onset_best_binding: Onset,
    pub onset_flat_low: Onset,
    pub onset_best_low: Onset,
    pub best: CurveId,
    /// `(year, flat-25 ratio at 10 %)` at each decade.
    pub flat_binding_by_decade: Vec<(u64, f64)>,
}

/// A1-L row: one lever on one scenario.
#[derive(Debug, Clone, Serialize)]
pub struct LeverResult {
    pub scenario: String,
    pub lever: Lever,
    /// Min clearance ratio per band rate, parallel to `OPP_COST_RATE_BAND`.
    pub min_ratio_by_rate: Vec<f64>,
    /// `REPLICAS_PER_SHARD × min ratio` at the binding rate.
    pub replicas_sustained_binding: f64,
    pub onset_binding: Onset,
}

/// The fee-era clearance horizon in traffic-years, closed form: for constant
/// traffic `V`, fee pool `∝ V` and corpus `∝ V·t`, so `V` cancels and
///
/// `ratio(t) ≈ fee · base · share · W / (bond · R · rate · bytes_per_tx · t)`
///
/// clears for `t ≤ H`. Returns `H` in years. `base` is the fraction of fees
/// the share is taken of (the burn fraction at baseline volume with the
/// supply emitted, from the production `calc_burn_pct`, or 1 for all fees).
#[must_use]
pub fn fee_horizon_years(
    fee_per_tx_atomic: u64,
    base_fraction: f64,
    share_fraction: f64,
    rate: f64,
    bytes_per_tx: u64,
    shard_bytes: u64,
) -> f64 {
    let fee_skl = fee_per_tx_atomic as f64 / COIN;
    let bond_skl = ARCHIVAL_BOND_FLOOR_ATOMIC as f64 / COIN;
    fee_skl * base_fraction * share_fraction * shard_bytes as f64
        / (bond_skl * REPLICAS_PER_SHARD as f64 * rate * bytes_per_tx as f64)
}

/// The burn fraction at baseline volume once the supply is emitted — the
/// fee-era `base` for the horizon line, from production, not restated.
fn fee_era_burn_fraction(params: &SimParams) -> f64 {
    calc_burn_pct(
        TxVolume::per_block(params.tx_volume_baseline),
        params.tx_volume_baseline,
        params.emission_curve_asymptote,
        params.emission_curve_asymptote,
        params.burn_base_rate,
        params.burn_cap,
    ) as f64
        / SCALE as f64
}

/// Shards the whole perpetual tail funds at a rate, if every tail SKL went to
/// archival bonds' opportunity cost.
fn shards_funded_by_tail(tail_skl_per_year: f64, rate: f64) -> f64 {
    let bond_skl = ARCHIVAL_BOND_FLOOR_ATOMIC as f64 / COIN;
    tail_skl_per_year / (bond_skl * REPLICAS_PER_SHARD as f64 * rate)
}

/// A1-T — the onset table. Prints to `out`, returns the data.
pub fn onset_report(
    out: &mut impl fmt::Write,
    params: &SimParams,
) -> Result<Vec<OnsetScenarioResult>, fmt::Error> {
    writeln!(
        out,
        "\nA1-T — ONSET of A1 failure (§12.14): every scenario run to {H} y; the min hides WHEN.\n\
         'xover' = first year the staker EMISSION leg alone < bond opp cost @10% (end of the\n\
         era emission carries). 'onset' = first sustained year budget/burden < 1 (shipped burn\n\
         x share; '*' = a later year clears again; 'never' = clears to {H} y). Schedules are\n\
         the scenarios' own closures past their horizons: constant, cyclic, or growing —\n\
         sustained_growth's 20%/yr to 60 y is unphysical (block weight caps it) and is read\n\
         for shape only.",
        H = ONSET_HORIZON_YEARS,
    )?;
    writeln!(
        out,
        "{:<20} {:>10} {:>6}   {:>7} {:>7}   {:>7} {:>7}   flat-25 ratio @10% at y10/20/30/40/50/60",
        "scenario",
        "final_n",
        "xover",
        "flat@10",
        "best@10",
        "flat@2",
        "best@2",
    )?;
    let mid_price = SKL_FIAT_PRICE_BAND[1];
    let low = OPP_COST_RATE_BAND[0];
    let binding = OPP_COST_RATE_BAND[BINDING];
    let mut results = Vec::new();
    for config in all_scenarios(params).into_iter().map(at_horizon) {
        let aggs = a1_year_aggs(params, &config);
        let flat = flat_25();
        let best = best_candidate(&aggs);
        let shipped = |c: EscalationCurve| move |a: &A1YearAgg| a1_shipped_budget_atomic(a, &c);

        let emission_crossover_year = a1_sustained_years(&aggs)
            .find(|a| {
                a1_year_clearance_ratio(
                    a,
                    u128::from(a.emission_leg_atomic),
                    binding,
                    mid_price,
                    KryderRate::Stall,
                ) < 1.0
            })
            .map(|a| a.year);
        let onset_flat_binding = onset_of(year_ratios(&aggs, binding, shipped(flat)));
        let onset_best_binding = onset_of(year_ratios(&aggs, binding, shipped(best)));
        let onset_flat_low = onset_of(year_ratios(&aggs, low, shipped(flat)));
        let onset_best_low = onset_of(year_ratios(&aggs, low, shipped(best)));
        let flat_binding_by_decade: Vec<(u64, f64)> = year_ratios(&aggs, binding, shipped(flat))
            .filter(|(y, _)| DECADES.contains(y))
            .collect();
        let series = flat_binding_by_decade
            .iter()
            .map(|(_, r)| {
                if r.is_infinite() {
                    "inf".to_string()
                } else {
                    format!("{r:.2}")
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        writeln!(
            out,
            "{:<20} {:>10} {:>6}   {:>7} {:>7}   {:>7} {:>7}   {}",
            trunc(&config.name, 20),
            aggs.last().map_or(0, |a| a.n),
            emission_crossover_year.map_or("never".to_string(), |y| format!("y{y}")),
            fmt_onset(onset_flat_binding),
            fmt_onset(onset_best_binding),
            fmt_onset(onset_flat_low),
            fmt_onset(onset_best_low),
            series,
        )?;
        results.push(OnsetScenarioResult {
            scenario: config.name.clone(),
            horizon_years: ONSET_HORIZON_YEARS,
            final_n: aggs.last().map_or(0, |a| a.n),
            emission_crossover_year,
            onset_flat_binding,
            onset_best_binding,
            onset_flat_low,
            onset_best_low,
            best: best.into(),
            flat_binding_by_decade,
        });
    }

    // The fee-era horizon, closed form from production constants.
    let fee = all_scenarios(params)[0].fee_per_tx;
    let burn_base = fee_era_burn_fraction(params);
    let bytes_per_tx =
        normal_tx_archival_bytes(crate::burden::honest_leaves_at_closed_shards(KNEE_BAND[2]));
    let w = shekyl_types::SHARD_LENGTH.to_raw();
    writeln!(
        out,
        "  -> FEE HORIZON (closed form, constant traffic V cancels): the fee leg clears a corpus\n\
         no deeper than H = fee x base x share x W / (bond x R x rate x bytes/tx) traffic-years.\n\
         fee {fee:.3} SKL/tx, burn base {burn_base:.2} at baseline V with supply emitted, W {w} B,\n\
         bond {bond:.2} SKL x R{R}, {bpt} archival B/tx (1in/2out, deep):",
        fee = fee as f64 / COIN,
        bond = ARCHIVAL_BOND_FLOOR_ATOMIC as f64 / COIN,
        R = REPLICAS_PER_SHARD,
        bpt = bytes_per_tx,
    )?;
    for (label, base, share) in [
        ("burn x flat 25%", burn_base, 0.25),
        ("burn x 100%", burn_base, 1.0),
        ("ALL fees x 100%", 1.0, 1.0),
    ] {
        let hs: Vec<String> = OPP_COST_RATE_BAND
            .iter()
            .map(|&r| {
                format!(
                    "{:.0}y @{:.0}%",
                    fee_horizon_years(fee, base, share, r, bytes_per_tx, w),
                    r * 100.0
                )
            })
            .collect();
        writeln!(out, "       {label:<18} H = {}", hs.join(", "))?;
    }
    writeln!(
        out,
        "     Older corpus than H is unfunded by fees REGARDLESS of how busy the chain is; a\n\
         busy chain crosses the same line later only because its corpus is younger. The\n\
         shapes that match a bond STOCK scale with time or corpus, not traffic: the tail,\n\
         the emission-decay constant, and the bond itself."
    )?;
    Ok(results)
}

/// A1-L — the lever table on the two bracketing scenarios. Prints to `out`,
/// returns the data.
pub fn lever_report(
    out: &mut impl fmt::Write,
    params: &SimParams,
) -> Result<Vec<LeverResult>, fmt::Error> {
    writeln!(
        out,
        "\nA1-L — LEVERS priced (§12.14), min budget/burden over sustained years to {H} y, plus\n\
         R sustained @10% and the onset year @10%. PRICED, NOT PROPOSED: every row is a\n\
         genesis-frozen or ceremony-gated number. 'ALL fees' reaches into the miner's income —\n\
         the fee-era PoW security budget; that trade needs its own wargame, not a parameter.\n\
         'tail floor p%' = staker leg floored at p% of ALL block emission, non-decaying (at the\n\
         tail: p% of {tail_skl:.0} SKL/yr). 'decay' re-pins shekyl_staker_emission_decay.",
        H = ONSET_HORIZON_YEARS,
        tail_skl = tail_skl_per_year(params),
    )?;
    let binding = OPP_COST_RATE_BAND[BINDING];
    let mut results = Vec::new();
    let scenarios = all_scenarios(params);
    let picks = [
        scenarios.len() - 1, // scenario 9: the settled-chain tail
        0,                   // baseline steady state: the busy comparator
    ];
    for idx in picks {
        let config = at_horizon(
            all_scenarios(params)
                .into_iter()
                .nth(idx)
                .expect("scenario index in range"),
        );
        let aggs = a1_year_aggs(params, &config);
        let best = best_candidate(&aggs);
        writeln!(
            out,
            "\n  {} (n = {} at {} y; best band cand. {}%/{})",
            config.name,
            aggs.last().map_or(0, |a| a.n),
            ONSET_HORIZON_YEARS,
            best.asymptote / (SCALE / 100),
            best.knee_shards,
        )?;
        writeln!(
            out,
            "  {:<26} {:>7} {:>7} {:>7}   {:>9} {:>7}",
            "lever", "@2%", "@5%", "@10%", "R@10%", "onset"
        )?;
        for lever in lever_set(best) {
            let min_ratio_by_rate: Vec<f64> = OPP_COST_RATE_BAND
                .iter()
                .map(|&rate| {
                    year_ratios(&aggs, rate, |a| lever.budget_atomic(a, params))
                        .map(|(_, r)| r)
                        .fold(f64::INFINITY, f64::min)
                })
                .collect();
            let onset_binding = onset_of(year_ratios(&aggs, binding, |a| {
                lever.budget_atomic(a, params)
            }));
            let replicas_sustained_binding = min_ratio_by_rate[BINDING] * REPLICAS_PER_SHARD as f64;
            writeln!(
                out,
                "  {:<26} {:>7.2} {:>7.2} {:>7.2}   {:>9.2} {:>7}",
                lever.label,
                min_ratio_by_rate[0],
                min_ratio_by_rate[1],
                min_ratio_by_rate[2],
                replicas_sustained_binding,
                fmt_onset(onset_binding),
            )?;
            results.push(LeverResult {
                scenario: config.name.clone(),
                lever,
                min_ratio_by_rate,
                replicas_sustained_binding,
                onset_binding,
            });
        }
    }
    let tail = tail_skl_per_year(params);
    let funded: Vec<String> = OPP_COST_RATE_BAND
        .iter()
        .map(|&r| {
            format!(
                "{:.2} M @{:.0}%",
                shards_funded_by_tail(tail, r) / 1e6,
                r * 100.0
            )
        })
        .collect();
    writeln!(
        out,
        "  -> The WHOLE perpetual tail ({tail:.0} SKL/yr) funds the bond opp cost of {} shards\n\
         — the only income shaped like the burden, and its ceiling. Beyond it the lever is\n\
         the bond itself (0.75 SKL locked per {W} B forever, R = {R}), not any share.",
        funded.join(", "),
        W = shekyl_types::SHARD_LENGTH.to_raw(),
        R = REPLICAS_PER_SHARD,
    )?;
    Ok(results)
}

/// The perpetual tail per year in SKL: `final_subsidy_per_minute × 2 min ×
/// blocks_per_year`, from the params (mirrors `tail_subsidy_per_block`).
fn tail_skl_per_year(params: &SimParams) -> f64 {
    let per_block = params.final_subsidy_per_minute * 2;
    (per_block as f64 / COIN) * params.blocks_per_year as f64
}

fn trunc(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        s.chars().take(n).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_lever_reproduces_a1() {
        // The lever machinery at its shipped setting is A1's budget exactly —
        // one home for the ratio, no second derivation.
        let params = SimParams::default();
        for config in all_scenarios(&params) {
            let aggs = a1_year_aggs(&params, &config);
            let flat = flat_25();
            let lever = lever_set(flat)[0];
            for a in a1_sustained_years(&aggs) {
                assert_eq!(
                    lever.budget_atomic(a, &params),
                    a1_shipped_budget_atomic(a, &flat),
                    "{} y{}",
                    config.name,
                    a.year
                );
            }
        }
    }

    #[test]
    fn decay_leg_at_shipped_decay_matches_the_per_block_split() {
        // The year-level re-pin (production share fn at the midpoint height ×
        // the year's total emission) stands in for the per-block split; at the
        // shipped decay the two must agree to well under 1 %.
        let params = SimParams::default();
        let config = at_horizon(all_scenarios(&params).remove(0));
        let aggs = a1_year_aggs(&params, &config);
        for a in aggs.iter().filter(|a| a.emission_leg_atomic > 0) {
            let alt = emission_leg_at_decay(a, &params, params.staker_emission_decay) as f64;
            let shipped = a.emission_leg_atomic as f64;
            let rel = (alt - shipped).abs() / shipped;
            assert!(rel < 0.01, "y{}: {rel:.4} relative", a.year);
        }
    }

    #[test]
    fn no_decay_is_never_below_shipped_and_floor_is_a_floor() {
        let params = SimParams::default();
        let config = at_horizon(all_scenarios(&params).remove(0));
        let aggs = a1_year_aggs(&params, &config);
        let flat = flat_25();
        let levers = lever_set(flat);
        let shipped = levers[0];
        let no_decay = levers[9];
        let whole_tail = levers[7];
        for a in a1_sustained_years(&aggs) {
            assert!(no_decay.budget_atomic(a, &params) >= shipped.budget_atomic(a, &params));
            assert!(whole_tail.budget_atomic(a, &params) >= shipped.budget_atomic(a, &params));
            // The whole-tail floor is the whole emission plus the fee leg.
            assert!(whole_tail.budget_atomic(a, &params) >= u128::from(a.total_emission_atomic));
        }
    }

    #[test]
    fn onset_marks_recovery() {
        let o = onset_of([(3, 2.0), (4, 0.5), (5, 0.7), (6, 1.5)].into_iter());
        assert_eq!(
            o,
            Onset {
                year: Some(4),
                recovers: true
            }
        );
        let o = onset_of([(3, 2.0), (4, 0.5)].into_iter());
        assert_eq!(
            o,
            Onset {
                year: Some(4),
                recovers: false
            }
        );
        assert_eq!(fmt_onset(onset_of(std::iter::empty())), "never");
    }

    #[test]
    fn fee_horizon_is_traffic_independent_in_the_fee_era() {
        // In the fee era, for constant V, the per-year ratio ≈ H / t: check
        // the closed form against the fold on the baseline scenario late in
        // its 60-y run (emission at the tail), to within the tail's
        // contribution and the storage add-on.
        let params = SimParams::default();
        let config = at_horizon(all_scenarios(&params).remove(0));
        let aggs = a1_year_aggs(&params, &config);
        let fee = config.fee_per_tx;
        let bytes =
            normal_tx_archival_bytes(crate::burden::honest_leaves_at_closed_shards(KNEE_BAND[2]));
        let w = shekyl_types::SHARD_LENGTH.to_raw();
        let h = fee_horizon_years(fee, fee_era_burn_fraction(&params), 0.25, 0.10, bytes, w);
        let a = aggs.last().expect("60 years");
        // Fee leg alone, so the comparison isolates the closed form.
        let flat = flat_25();
        let fee_only = u128::from(mul_scale(a.whole_burn_atomic, flat.share(a.n)));
        let measured =
            a1_year_clearance_ratio(a, fee_only, 0.10, SKL_FIAT_PRICE_BAND[1], KryderRate::Stall);
        let predicted = h / a.year as f64;
        let rel = (measured - predicted).abs() / predicted;
        assert!(
            rel < 0.25,
            "y{}: measured {measured:.3} vs closed form {predicted:.3} ({rel:.2} rel)",
            a.year
        );
    }
}
