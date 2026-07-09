// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
//! Volume regimes for the F-B1c-c2 disposition-(b) reopen sim (`budget.rs`).
//!
//! Each regime is chosen to stress the demand-throttling question from a
//! different angle: how low does `budget(E)` fall under (a), how much would (b)
//! restore, and does the emission-share decay close the gap before the fee era.

use crate::budget::BudgetScenario;
use crate::engine::SimParams;

/// Baseline reference: steady 1× volume — the release multiplier sits at 1.0, so
/// (a) and (b) coincide except for rounding. Anchors the swing measurements.
fn baseline(params: &SimParams) -> BudgetScenario {
    let b = params.tx_volume_baseline;
    BudgetScenario {
        name: "baseline_1x".into(),
        description: "Steady 1x baseline volume over 30 years (release mult = 1.0; a == b)".into(),
        sim_years: 30,
        get_volume: Box::new(move |_blk, _bpy| b),
        fee_per_tx: 100_000_000,
        initial_emitted_fraction: 0.0,
        genesis_height_offset: 0,
    }
}

/// The deepest sustained-low stress: 10% of baseline for the whole mining era.
/// The release multiplier pins to its `release_min` floor (0.8×) every block,
/// so this is the maximum-throttle corner — the worst case (b) could point to.
fn sustained_low(params: &SimParams) -> BudgetScenario {
    let b = params.tx_volume_baseline;
    BudgetScenario {
        name: "sustained_low_0.1x".into(),
        description: "Sustained 0.1x baseline for 30 years (release mult pinned to 0.8x floor)"
            .into(),
        sim_years: 30,
        get_volume: Box::new(move |_blk, _bpy| (b as f64 * 0.1) as u64),
        fee_per_tx: 100_000_000,
        initial_emitted_fraction: 0.0,
        genesis_height_offset: 0,
    }
}

/// The compounding concern: low volume *when the emission share is highest*.
/// A genesis cold-start ramps 0.1x -> 0.2x -> 0.5x -> 1x -> 1.5x, exactly the
/// years the 15% staker-emission share has not yet decayed — so any (a)-vs-(b)
/// gap is at its structural maximum here. (Volume shape mirrors the legacy
/// `scenario_7_bootstrap`.)
fn bootstrap(params: &SimParams) -> BudgetScenario {
    let b = params.tx_volume_baseline;
    BudgetScenario {
        name: "bootstrap_coldstart".into(),
        description: "Genesis cold-start: 0.1/0.2/0.5/1/1.5x over years 0-4 then 1.5x (low volume \
                      while emission share is highest)"
            .into(),
        sim_years: 10,
        get_volume: Box::new(move |blk, bpy| {
            let year = blk / bpy;
            match year {
                0 => b / 10,
                1 => b / 5,
                2 => b / 2,
                3 => b,
                _ => b * 3 / 2,
            }
        }),
        fee_per_tx: 100_000_000,
        initial_emitted_fraction: 0.0,
        genesis_height_offset: 0,
    }
}

/// Boom/bust: 3× for a year, 0.3× the next, repeating. Probes whether the
/// *volatility* of the throttle (not just its floor) matters — the bust years
/// hit the 0.8× floor while the boom years cap at 1.3×.
fn boom_bust(params: &SimParams) -> BudgetScenario {
    let b = params.tx_volume_baseline;
    BudgetScenario {
        name: "boom_bust".into(),
        description: "3x volume one year, 0.3x the next, repeating over 20 years".into(),
        sim_years: 20,
        get_volume: Box::new(move |blk, bpy| {
            let year = blk / bpy;
            if year % 2 == 0 {
                b * 3
            } else {
                (b as f64 * 0.3) as u64
            }
        }),
        fee_per_tx: 100_000_000,
        initial_emitted_fraction: 0.0,
        genesis_height_offset: 0,
    }
}

/// Prolonged bust after establishment: 1× for 5 years, then 0.2× sustained.
/// This is the "demand collapses on an established chain" shape — the worst
/// realistic starvation window, deep enough into the decay that the emission
/// leg is already shrinking.
fn prolonged_bust(params: &SimParams) -> BudgetScenario {
    let b = params.tx_volume_baseline;
    BudgetScenario {
        name: "prolonged_bust".into(),
        description: "1x for 5 years then a sustained 0.2x demand collapse for 15 years".into(),
        sim_years: 20,
        get_volume: Box::new(move |blk, bpy| {
            let year = blk / bpy;
            if year < 5 {
                b
            } else {
                (b as f64 * 0.2) as u64
            }
        }),
        fee_per_tx: 100_000_000,
        initial_emitted_fraction: 0.0,
        genesis_height_offset: 0,
    }
}

/// Fee-era / late-tail: 95% already emitted, low absolute volume, starting ~year
/// 30 — where `staker_emission` has decayed toward zero, so the (a)-vs-(b) gap
/// (an *emission-leg* phenomenon) should vanish and `budget(E)` becomes
/// fee-driven under both. Confirms the reopen question is bounded in time.
fn fee_era(_params: &SimParams) -> BudgetScenario {
    BudgetScenario {
        name: "fee_era_late_tail".into(),
        description: "95% emitted, low volume, ~year 30 onward (emission share ~decayed; a ~ b)"
            .into(),
        sim_years: 10,
        get_volume: Box::new(|blk, bpy| {
            let year = blk / bpy;
            // low, choppy fee-market volume
            match year {
                0 => 200,
                1 => 250,
                2 => 180,
                3 => 300,
                _ => 220,
            }
        }),
        fee_per_tx: 100_000_000,
        initial_emitted_fraction: 0.95,
        genesis_height_offset: 30 * 262_800, // ~year 30
    }
}

pub fn all_budget_scenarios(params: &SimParams) -> Vec<BudgetScenario> {
    vec![
        baseline(params),
        sustained_low(params),
        bootstrap(params),
        boom_bust(params),
        prolonged_bust(params),
        fee_era(params),
    ]
}
