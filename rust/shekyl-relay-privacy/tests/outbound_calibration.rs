// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The §95 calibration. Ignored: a level from this file is a result, and an
//! unconverged cell is a refusal.

use shekyl_relay_privacy::conformance::composition::{
    converged_composition_fluff, hidden_inbound_load, shipped_fluff_reference, shipped_graph_p90,
    simulate_class_aware_first_spy, CompositionFluff, LinkTransit, Mix, Routing, SpyArm,
};
use shekyl_relay_privacy::conformance::epoch_traffic::{
    simulate_epoch_traffic, simulate_origin_rate_contrast,
};
use shekyl_relay_privacy::conformance::{converge_p90, transit_for, ConvergenceBudget, FloodReach};
use shekyl_relay_privacy::params::inherited::FLUFF_AVERAGE_IN_QUARTER_SECS;
use shekyl_relay_privacy::params::DandelionParams;
use shekyl_relay_privacy::schedule::DelayFamily;
use shekyl_relay_privacy::MeasuredConnector;
use shekyl_relay_privacy::SplitMix64;

#[test]
#[ignore = "the §95 512-node calibration; run locally, do not put a level into CI"]
fn outbound_calibration_grid() {
    let tor = transit_for(MeasuredConnector::Tor);
    let clear = transit_for(MeasuredConnector::Clearnet);
    let provisional = u64::from(DandelionParams::adopted().fluff_return_ms);
    println!("REACH OutboundOnly in every cell. nodes 512. provisional input {provisional}");
    println!("per-connector transit hidden {tor} clearnet {clear}");

    let mut rng = SplitMix64::new(0xF7_000C);
    let provenance_free = shipped_fluff_reference(24, &mut rng);
    let mut rng = SplitMix64::new(0xF7_000C);
    let provenance_tor = shipped_graph_p90(tor, FloodReach::OutboundOnly, 24, &mut rng);
    println!(
        "SHIPPED provenance seed 0xF7_000C trials 24 transit-free {provenance_free} with-tor {provenance_tor} exceeds {}",
        provenance_tor > provisional
    );

    let budget = ConvergenceBudget {
        start_trials: 8,
        max_trials: 16,
        tolerance_ms: 250,
    };
    let seeds = [0xC4_u64, 0xC5, 0xC6, 0xC7];
    for (label, transit) in [("transit-free", 0_u64), ("tor-transit", tor)] {
        let reading = converge_p90(&seeds, budget, |seed, trials| {
            let mut rng = SplitMix64::new(seed);
            shipped_graph_p90(transit, FloodReach::OutboundOnly, trials, &mut rng)
        });
        match reading {
            Ok(v) => println!(
                "CELL shipped {label} p90={} spread={} trials={} exceeds {}",
                v.p90_ms,
                v.spread_ms,
                v.trials_per_seed,
                v.p90_ms > provisional
            ),
            Err(e) => println!("CELL shipped {label} REFUSED {e}"),
        }
    }

    for h in [12_usize, 14, 16] {
        for c in (0..=16).step_by(2) {
            let mix = Mix::new(512, h, c, 1.0);
            let mut free_p90 = None;
            let mut link_p90 = None;
            for (label, hidden_ms, clear_ms, slot) in [
                ("transit-free", 0_u64, 0_u64, &mut free_p90),
                ("per-connector", tor, clear, &mut link_p90),
            ] {
                let reading = converged_composition_fluff(
                    CompositionFluff {
                        mix,
                        transit: LinkTransit {
                            hidden_ms,
                            clearnet_ms: clear_ms,
                        },
                        reach: FloodReach::OutboundOnly,
                    },
                    FLUFF_AVERAGE_IN_QUARTER_SECS,
                    DelayFamily::Geometric,
                    &seeds,
                    budget,
                    |seed| SplitMix64::new(seed ^ (h as u64) << 16 ^ (c as u64) << 8),
                );
                match reading {
                    Ok(v) => {
                        *slot = Some(v.p90_ms);
                        println!(
                            "CELL h={h} c={c} {label} p90={} spread={} trials={}",
                            v.p90_ms, v.spread_ms, v.trials_per_seed
                        );
                    }
                    Err(e) => println!("CELL h={h} c={c} {label} REFUSED {e}"),
                }
            }
            let ratio = link_p90.map(|p90| p90.saturating_mul(1000) / provisional);
            let approvable = link_p90.is_some_and(|p90| p90 <= provisional);
            let mut rng = SplitMix64::new(0xE0C4 + (h as u64) * 20 + c as u64);
            let post = simulate_epoch_traffic(
                Mix::new(40, h, c, 1.0),
                Routing::HiddenStemSlot,
                6,
                &mut rng,
            );
            println!(
                "POINT h={h} c={c} ratio_milli={ratio:?} approvable={approvable} own={:.3} hid={:.3} \
                 tor_circuits={h} sockets_out={} hid_in_f1={} hid_in_f05={} hid_in_f025={} hid_in_f01={} \
                 free_p90={free_p90:?} link_p90={link_p90:?}",
                post.posterior_own_edge,
                post.posterior_hidden,
                h + c,
                h,
                h * 2,
                h * 4,
                h * 10,
            );
        }
    }

    for h in [12_usize, 16] {
        let mut rng = SplitMix64::new(0x1B_F0 + h as u64);
        let load = hidden_inbound_load(&build_for_inbound(h, 0.1, &mut rng));
        println!(
            "TAIL f=0.1 h={h} mean={:.1} p90={} max={}",
            load.mean, load.p90, load.max
        );
    }

    let spy_mix = Mix::new(32, 12, 8, 1.0);
    for routing in [Routing::HiddenStemSlot, Routing::UniformHop0] {
        for (label, arm) in [
            ("p20", SpyArm::Uniform { p: 0.2 }),
            ("ph30", SpyArm::OnionBiased { p: 0.3 }),
        ] {
            let mut rng = SplitMix64::new(0x5A10);
            let spy = simulate_class_aware_first_spy(spy_mix, routing, arm, 0, 200, &mut rng);
            println!(
                "SPY {routing:?} {label} blind prec={:.3} rec={:.3} aware prec={:.3} rec={:.3}",
                spy.blind.precision, spy.blind.recall, spy.aware.precision, spy.aware.recall
            );
        }
    }
    let mut rng = SplitMix64::new(0x5A11);
    let marked = simulate_class_aware_first_spy(
        Mix::new(32, 8, 8, 1.0).with_clearnet_only(8),
        Routing::HiddenStemSlot,
        SpyArm::Uniform { p: 0.2 },
        0,
        200,
        &mut rng,
    );
    println!(
        "MARK clearnet_only=8 origin=0 blind prec={:.3} aware prec={:.3}",
        marked.blind.precision, marked.aware.precision
    );

    let mut rng = SplitMix64::new(0x4E_11);
    let heavy = simulate_origin_rate_contrast(
        Mix::new(32, 12, 12, 1.0),
        Routing::HiddenStemSlot,
        8,
        8,
        &mut rng,
    );
    println!(
        "HEAVY posterior {:.3} rest {:.3}",
        heavy.heavy_posterior, heavy.rest_posterior
    );
}

fn build_for_inbound(
    hidden: usize,
    fraction: f64,
    rng: &mut SplitMix64,
) -> shekyl_relay_privacy::conformance::composition::TwoClassGraph {
    use shekyl_relay_privacy::conformance::composition::build_two_class;
    build_two_class(Mix::new(400, hidden, 0, fraction), rng)
}
