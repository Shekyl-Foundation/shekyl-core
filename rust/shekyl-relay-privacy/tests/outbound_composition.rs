// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Two-class composition. These tests pin the instrument's distinctions.
//! They do not pin a fluff-return level: that reading is a result, and an
//! unconverged one is a refusal.

use shekyl_relay_privacy::conformance::composition::{
    build_two_class, composition_fluff_p90, hidden_inbound_load, simulate_class_posterior,
    simulate_own_edge_capture, LinkClass, Mix, Routing,
};
use shekyl_relay_privacy::conformance::{converge_p90, ConvergenceBudget, ConvergenceRefusal};
use shekyl_relay_privacy::SplitMix64;

#[test]
fn every_node_initiates_its_hidden_and_clearnet_degree() {
    let mut rng = SplitMix64::new(0xC0_11);
    let graph = build_two_class(32, 4, 3, 1.0, &mut rng);
    for (node, row) in graph.initiated.iter().enumerate() {
        let hidden = row.iter().filter(|e| e.class == LinkClass::Hidden).count();
        let clear = row
            .iter()
            .filter(|e| e.class == LinkClass::Clearnet)
            .count();
        assert_eq!(hidden, 4, "node {node}");
        assert_eq!(clear, 3, "node {node}");
        assert!(row.iter().all(|e| e.to != node));
        let mut tos: Vec<usize> = row.iter().map(|e| e.to).collect();
        tos.sort_unstable();
        tos.dedup();
        assert_eq!(tos.len(), row.len(), "node {node} repeated a peer");
    }
    let hops = graph.fluff_hops(1, 2);
    for (from, row) in graph.initiated.iter().enumerate() {
        for edge in row {
            assert!(
                hops[edge.to].iter().any(|h| h.to == from
                    && h.transit_ms
                        == match edge.class {
                            LinkClass::Hidden => 1,
                            LinkClass::Clearnet => 2,
                        }),
                "missing reciprocal"
            );
        }
    }
}

#[test]
fn a_split_graph_is_certain_and_a_clearnet_arrival_is_relayed() {
    let mut rng = SplitMix64::new(0x5B_11);
    let split = simulate_class_posterior(
        Mix {
            nodes: 24,
            hidden_out: 4,
            clearnet_out: 4,
            onion_fraction: 1.0,
        },
        Routing::Split,
        400,
        &mut rng,
    );
    assert_eq!(split.clearnet_originated, 0);
    assert_eq!(split.hidden_relayed, 0);
    assert!((split.posterior_hidden - 1.0).abs() < 1e-12);
    assert!(split.posterior_clearnet.abs() < 1e-12);
    assert!(
        split.relayed_per_originated > 2.0 && split.relayed_per_originated < 8.0,
        "walk_stem at q=20% should relay about 4 times, got {}",
        split.relayed_per_originated
    );

    let mut rng = SplitMix64::new(0x5B_12);
    let mixed = simulate_class_posterior(
        Mix {
            nodes: 24,
            hidden_out: 4,
            clearnet_out: 4,
            onion_fraction: 1.0,
        },
        Routing::HiddenOwnEdge,
        400,
        &mut rng,
    );
    assert_eq!(
        mixed.clearnet_originated, 0,
        "the own-edge is hidden, so a clearnet arrival is relayed"
    );
    assert!(mixed.posterior_clearnet.abs() < 1e-12);
    assert!(
        mixed.posterior_own_edge > mixed.hidden_share + 0.05,
        "the pinned peer's posterior ({}) is above the share ({})",
        mixed.posterior_own_edge,
        mixed.hidden_share
    );
}

#[test]
fn an_all_clearnet_graph_puts_originated_traffic_on_clearnet() {
    let mut rng = SplitMix64::new(0xC1_EA);
    let paper = simulate_class_posterior(
        Mix {
            nodes: 24,
            hidden_out: 0,
            clearnet_out: 8,
            onion_fraction: 1.0,
        },
        Routing::AllClearnet,
        200,
        &mut rng,
    );
    assert_eq!(paper.hidden_originated, 0);
    assert_eq!(paper.hidden_relayed, 0);
    assert!(paper.posterior_clearnet > 0.0);
    assert!(paper.posterior_clearnet < 1.0);
}

#[test]
fn pool_capture_tracks_the_closed_form_and_epochs_raise_it() {
    let mut rng = SplitMix64::new(0xCA_90);
    let cap = simulate_own_edge_capture(2, 0.5, 6, 2, 800, &mut rng);
    assert!((cap.closed_form - 0.25).abs() < 1e-9);
    assert!(
        (cap.drawn_all_sessions - cap.closed_form).abs() < 0.04,
        "drawn {} vs {}",
        cap.drawn_all_sessions,
        cap.closed_form
    );
    assert!(
        cap.ever_across_epochs > cap.pin_is_spy,
        "a window of epochs is a higher capture chance than one pin: ever {} pin {}",
        cap.ever_across_epochs,
        cap.pin_is_spy
    );
}

#[test]
fn publisher_inbound_mean_tracks_h_over_f() {
    let mut rng = SplitMix64::new(0x1B_0A);
    let graph = build_two_class(400, 12, 0, 0.25, &mut rng);
    let load = hidden_inbound_load(&graph);
    let expect = 12.0 / 0.25;
    assert!(
        (load.mean - expect).abs() < 3.0,
        "mean {} expected about {expect}",
        load.mean
    );
    assert!(load.max > load.p50, "the tail is not the mean");
    assert!(
        load.above_24 > 0.0,
        "h/f = 48, so some publishers sit above 24"
    );
}

#[test]
fn a_seed_spread_is_refused_rather_than_reported() {
    let budget = ConvergenceBudget {
        start_trials: 1,
        max_trials: 1,
        tolerance_ms: 250,
    };
    let refused = converge_p90(
        &[1, 2],
        budget,
        |seed, _| if seed == 1 { 1_000 } else { 5_000 },
    );
    assert!(matches!(refused, Err(ConvergenceRefusal::Spread { .. })));
    let agreed = converge_p90(&[1, 2], budget, |_, _| 3_250);
    assert!(matches!(agreed, Ok(c) if c.p90_ms == 3_250));
}

#[test]
#[ignore = "the §95 grid; run locally, do not put a level into CI"]
fn outbound_composition_grid() {
    use shekyl_relay_privacy::conformance::composition::{
        converged_composition_fluff, simulate_stem_first_spy, LinkTransit, SpyArm,
    };
    use shekyl_relay_privacy::conformance::transit_for;
    use shekyl_relay_privacy::schedule::DelayFamily;
    use shekyl_relay_privacy::MeasuredConnector;

    let points = [
        (12, 0),
        (12, 4),
        (16, 0),
        (12, 8),
        (16, 4),
        (12, 12),
        (16, 8),
        (24, 0),
    ];
    let hidden_ms = transit_for(MeasuredConnector::Tor);
    let clear_ms = transit_for(MeasuredConnector::Clearnet);
    println!("transit hidden {hidden_ms} clearnet {clear_ms}");
    for (h, c) in points {
        let mix = Mix {
            nodes: 48,
            hidden_out: h,
            clearnet_out: c,
            onion_fraction: 1.0,
        };
        let mut rng = SplitMix64::new(0x5950_0000 + (h as u64) * 16 + c as u64);
        let post = simulate_class_posterior(mix, Routing::HiddenOwnEdge, 600, &mut rng);
        println!(
            "POST h={h} c={c} share={:.3} own={:.3} hid={:.3} clr={:.3} relayed={:.2}",
            post.hidden_share,
            post.posterior_own_edge,
            post.posterior_hidden,
            post.posterior_clearnet,
            post.relayed_per_originated
        );
        let mut rng = SplitMix64::new(0x5910);
        let spy = simulate_stem_first_spy(
            mix,
            Routing::HiddenOwnEdge,
            SpyArm::Uniform { p: 0.2 },
            400,
            &mut rng,
        );
        let mut rng = SplitMix64::new(0x5930);
        let spy30 = simulate_stem_first_spy(
            mix,
            Routing::HiddenOwnEdge,
            SpyArm::OnionBiased { p: 0.3 },
            400,
            &mut rng,
        );
        println!(
            "SPY h={h} c={c} p20 prec={:.3} rec={:.3} | p_h(0.3) prec={:.3} rec={:.3}",
            spy.precision, spy.recall, spy30.precision, spy30.recall
        );
    }
    let budget = ConvergenceBudget {
        start_trials: 8,
        max_trials: 32,
        tolerance_ms: 250,
    };
    let seeds = [0xF1_u64, 0xF2, 0xF3, 0xF4];
    for (h, c) in [(12, 0), (12, 4), (16, 0), (16, 4), (12, 12)] {
        let mix = Mix {
            nodes: 128,
            hidden_out: h,
            clearnet_out: c,
            onion_fraction: 1.0,
        };
        let reading = converged_composition_fluff(
            mix,
            LinkTransit {
                hidden_ms,
                clearnet_ms: clear_ms,
            },
            20,
            DelayFamily::Geometric,
            &seeds,
            budget,
            SplitMix64::new,
        );
        match reading {
            Ok(v) => println!(
                "FLUFF h={h} c={c} p90={} spread={} trials={}",
                v.p90_ms, v.spread_ms, v.trials_per_seed
            ),
            Err(e) => println!("FLUFF h={h} c={c} REFUSED {e}"),
        }
    }
    for (i, f) in [1.0_f64, 0.5, 0.25, 0.1].into_iter().enumerate() {
        for h in [12, 16, 24] {
            let mut rng = SplitMix64::new(0x1B00 + (h as u64) * 10 + i as u64);
            let graph = build_two_class(400, h, 0, f, &mut rng);
            let load = hidden_inbound_load(&graph);
            println!(
                "IN f={f} h={h} mean={:.1} p50={} p90={} max={} >12={:.2} >24={:.2} >64={:.2}",
                load.mean,
                load.p50,
                load.p90,
                load.max,
                load.above_12,
                load.above_24,
                load.above_64
            );
        }
    }
    for (i, (h, p_h)) in [
        (12, 0.1),
        (12, 0.2),
        (16, 0.1),
        (16, 0.2),
        (12, 0.3),
        (16, 0.3),
    ]
    .into_iter()
    .enumerate()
    {
        let mut rng = SplitMix64::new(0xCA00 + i as u64);
        let cap = simulate_own_edge_capture(h, p_h, 8, 3, 400, &mut rng);
        println!(
            "CAP h={h} p_h={p_h} form={:.3e} drawn={:.3e} pin={:.3} frozen={:.3} ever={:.3}",
            cap.closed_form,
            cap.drawn_all_sessions,
            cap.pin_is_spy,
            cap.frozen_after_churn,
            cap.ever_across_epochs
        );
    }
    let mut rng = SplitMix64::new(0x5B_11);
    let split = simulate_class_posterior(
        Mix {
            nodes: 32,
            hidden_out: 12,
            clearnet_out: 4,
            onion_fraction: 1.0,
        },
        Routing::Split,
        300,
        &mut rng,
    );
    println!(
        "BASE split own={} hid={} clr={}",
        split.posterior_own_edge, split.posterior_hidden, split.posterior_clearnet
    );
    let mut rng = SplitMix64::new(0xC1);
    let paper = simulate_class_posterior(
        Mix {
            nodes: 32,
            hidden_out: 0,
            clearnet_out: 16,
            onion_fraction: 1.0,
        },
        Routing::AllClearnet,
        300,
        &mut rng,
    );
    println!(
        "BASE clearnet own={} clr={}",
        paper.posterior_own_edge, paper.posterior_clearnet
    );
}

#[test]
fn link_transit_moves_the_first_passage() {
    let mut fast = SplitMix64::new(0x77_A0);
    let mut slow = SplitMix64::new(0x77_A0);
    let hidden = build_two_class(20, 4, 0, 1.0, &mut fast);
    let clear = build_two_class(20, 0, 4, 1.0, &mut slow);
    let fast_p90 = composition_fluff_p90(&hidden, 0, 0, 8, &mut SplitMix64::new(1));
    let slow_p90 = composition_fluff_p90(&clear, 0, 20_000, 8, &mut SplitMix64::new(1));
    assert!(
        slow_p90 > fast_p90,
        "clearnet transit 20000 ms must slow the passage ({slow_p90} vs {fast_p90})"
    );
}
