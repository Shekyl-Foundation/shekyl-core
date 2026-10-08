// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Two-class composition. These tests pin the instrument's distinctions.
//! They do not pin a fluff-return level: that reading is a result, and an
//! unconverged one is a refusal.

use shekyl_relay_privacy::conformance::composition::{
    build_node_maps, build_two_class, clearnet_arrival_is_relayed, graph_fluff_p90,
    hidden_inbound_load, simulate_own_edge_capture, walk_originated, LinkClass, LinkTransit, Mix,
    Routing, StemRelayBudget,
};
use shekyl_relay_privacy::conformance::epoch_traffic::{epoch_traffic_on, simulate_epoch_traffic};
use shekyl_relay_privacy::conformance::{
    converge_p90, ConvergenceBudget, ConvergenceRefusal, FloodReach,
};
use shekyl_relay_privacy::params::DandelionParams;
use shekyl_relay_privacy::schedule::{EmbargoTimer, DEFAULT_EMBARGO_TICK_MILLIS};
use shekyl_relay_privacy::stem_map::ConnectionId;
use shekyl_relay_privacy::SplitMix64;

#[test]
fn every_node_initiates_its_hidden_and_clearnet_degree() {
    let mut rng = SplitMix64::new(0xC0_11);
    let graph = build_two_class(Mix::new(32, 4, 3, 1.0), &mut rng);
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
    let hops = graph.fluff_hops(1, 2, FloodReach::EveryPeer);
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
    let outbound = graph.fluff_hops(1, 2, FloodReach::OutboundOnly);
    let initiated: usize = graph.initiated.iter().map(Vec::len).sum();
    let directed: usize = outbound.iter().map(Vec::len).sum();
    assert_eq!(
        directed, initiated,
        "outbound-only fluff is the initiated edges"
    );
}

#[test]
fn a_split_graph_is_certain_and_a_clearnet_arrival_is_relayed() {
    let mix = Mix::new(24, 4, 4, 1.0);
    let mut rng = SplitMix64::new(0x5B_11);
    let split = simulate_epoch_traffic(mix, Routing::Split, 8, &mut rng);
    assert!(
        (split.posterior_hidden - 1.0).abs() < 1e-12,
        "split hidden posterior {}",
        split.posterior_hidden
    );
    assert!(
        split.posterior_clearnet.abs() < 1e-12,
        "split clearnet posterior {}",
        split.posterior_clearnet
    );
    assert!(
        (split.posterior_own_edge - 1.0).abs() < 1e-12,
        "the split own-edge carries no relay, posterior {}",
        split.posterior_own_edge
    );
    assert!(
        split.relayed_per_originated > 2.0 && split.relayed_per_originated < 8.0,
        "walk_stem at q=20% should relay about 4 times, got {}",
        split.relayed_per_originated
    );

    let mut rng = SplitMix64::new(0x5B_12);
    let mixed = simulate_epoch_traffic(mix, Routing::HiddenOwnEdge, 8, &mut rng);
    assert!(
        mixed.posterior_clearnet.abs() < 1e-12,
        "originated stems stay off clearnet, posterior {}",
        mixed.posterior_clearnet
    );
}

#[test]
fn an_all_clearnet_graph_shares_the_stem_slot_with_relays() {
    let mut rng = SplitMix64::new(0xC1_EA);
    let paper = simulate_epoch_traffic(Mix::new(32, 0, 8, 1.0), Routing::AllClearnet, 12, &mut rng);
    assert!(
        paper.posterior_hidden.abs() < 1e-12,
        "no hidden deliveries, posterior {}",
        paper.posterior_hidden
    );
    assert!(
        paper.posterior_own_edge < 0.75,
        "the paper's own-edge is a stem slot, so the posterior is not the \
         single-path 0.91, got {}",
        paper.posterior_own_edge
    );
    assert!(
        paper.posterior_own_edge > 0.05,
        "originated traffic is still on the slot, got {}",
        paper.posterior_own_edge
    );
    assert!(
        paper.own_edge_relayed_per_originated > 0.4,
        "relays share the slot ({:.3} per originated, carrying {:.3}); a single-path \
         revisit count stays near 0.1",
        paper.own_edge_relayed_per_originated,
        paper.own_edges_carrying_relayed
    );
}

#[test]
fn hidden_stem_slot_carries_relayed_traffic_the_separate_draw_does_not() {
    let mix = Mix::new(32, 6, 6, 1.0);
    let mut rng = SplitMix64::new(0x57_E1);
    let slot = simulate_epoch_traffic(mix, Routing::HiddenStemSlot, 16, &mut rng);
    let mut rng = SplitMix64::new(0x57_E2);
    let own = simulate_epoch_traffic(mix, Routing::HiddenOwnEdge, 16, &mut rng);
    assert!(
        slot.own_edge_relayed_per_originated > own.own_edge_relayed_per_originated,
        "stem slot own={:.3} rel/orig={:.3} carrying={:.3}; separate own={:.3} rel/orig={:.3} carrying={:.3}",
        slot.posterior_own_edge,
        slot.own_edge_relayed_per_originated,
        slot.own_edges_carrying_relayed,
        own.posterior_own_edge,
        own.own_edge_relayed_per_originated,
        own.own_edges_carrying_relayed
    );
    assert!(
        own.own_edges_carrying_relayed < 0.45,
        "a separate own-edge coincides with a stem slot about 2/(h+c) of the time, fraction {}",
        own.own_edges_carrying_relayed
    );
    assert!(
        slot.own_edge_relayed_per_originated > own.own_edge_relayed_per_originated * 2.0,
        "stem slot relays {} per originated, separate draw {}",
        slot.own_edge_relayed_per_originated,
        own.own_edge_relayed_per_originated
    );
}

#[test]
fn the_local_source_of_a_hidden_stem_slot_occupies_that_slot() {
    let mut rng = SplitMix64::new(0x51_07);
    let graph = build_two_class(Mix::new(30, 6, 6, 1.0), &mut rng);
    let maps = build_node_maps(&graph, Routing::HiddenStemSlot, &mut rng);
    for (node, map) in maps.iter().enumerate() {
        let local = map.local.expect("mixed graph has a hidden first hop");
        assert_eq!(local.class, LinkClass::Hidden, "node {node}");
        let id = peer_bytes(local.to);
        assert!(
            map.map.slots().contains(&Some(id)),
            "node {node} local peer is not a stem slot"
        );
    }
    let mut rng = SplitMix64::new(0x51_08);
    let graph = build_two_class(Mix::new(30, 6, 6, 1.0), &mut rng);
    let maps = build_node_maps(&graph, Routing::HiddenOwnEdge, &mut rng);
    let mut on_slot = 0_usize;
    for map in &maps {
        let local = map.local.expect("hidden pool is non-empty");
        if map.map.slots().contains(&Some(peer_bytes(local.to))) {
            on_slot += 1;
        }
    }
    assert!(
        on_slot * 2 < maps.len(),
        "the separate draw landed on a stem slot {on_slot}/{}, which is HiddenStemSlot",
        maps.len()
    );
}

#[test]
fn a_dial_only_sender_relays_nothing_on_either_routing() {
    let mut rng = SplitMix64::new(0xD1_A1);
    let mut graph = build_two_class(Mix::new(20, 4, 2, 1.0), &mut rng);
    for row in &mut graph.initiated {
        row.retain(|edge| edge.to != 0);
    }
    for routing in [Routing::HiddenStemSlot, Routing::HiddenOwnEdge] {
        let mut rng = SplitMix64::new(0xD1_A2);
        let traffic = epoch_traffic_on(&graph, routing, 4, &mut rng);
        assert!(
            traffic.dial_only_senders >= 4,
            "{routing:?} dial-only senders {}",
            traffic.dial_only_senders
        );
        assert_eq!(
            traffic.dial_only_relayed, 0,
            "{routing:?} a node with no inbound relays nothing"
        );
        assert!(traffic.dial_only_originated >= 4);
        assert!((traffic.posterior_dial_only - 1.0).abs() < 1e-12);
    }
}

fn peer_bytes(node: usize) -> ConnectionId {
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&(node as u64).to_le_bytes());
    ConnectionId::from_bytes(bytes)
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
fn zero_churn_leaves_the_pin_and_the_window_counts_that_pin() {
    let mut rng = SplitMix64::new(0xCA_91);
    let still = simulate_own_edge_capture(4, 0.5, 4, 0, 300, &mut rng);
    assert!(
        (still.frozen_after_churn - still.pin_is_spy).abs() < 1e-12,
        "zero churn moved the pin: frozen {} pin {}",
        still.frozen_after_churn,
        still.pin_is_spy
    );
    let mut rng = SplitMix64::new(0xCA_92);
    let one = simulate_own_edge_capture(3, 0.5, 1, 2, 2_000, &mut rng);
    assert!(
        (one.ever_across_epochs - one.pin_is_spy).abs() < 1e-12,
        "a one-epoch window counted the fallback: ever {} pin {}",
        one.ever_across_epochs,
        one.pin_is_spy
    );
}

#[test]
fn an_originated_stem_stops_when_it_revisits_a_node() {
    let mut rng = SplitMix64::new(0xC1_C1);
    let params = DandelionParams::adopted();
    let embargo = EmbargoTimer::geometric_from_ticks(1, DEFAULT_EMBARGO_TICK_MILLIS);
    let mut covered = false;
    for _ in 0..80 {
        let graph = build_two_class(Mix::new(3, 1, 1, 1.0), &mut rng);
        let mut maps = build_node_maps(&graph, Routing::HiddenStemSlot, &mut rng);
        let budget = StemRelayBudget::from_walk(&params, &embargo, &mut rng);
        let landing = walk_originated(&graph, &mut maps, 0, budget, &mut rng);
        let mut seen = vec![false; graph.nodes()];
        for node in &landing.path {
            assert!(!seen[*node], "stem continued through node {node}");
            seen[*node] = true;
        }
        assert!(landing.path.len() <= graph.nodes());
        if landing.path.len() == graph.nodes() {
            covered = true;
        }
    }
    assert!(
        covered,
        "no trial walked far enough to meet the cycle bound"
    );
}

#[test]
fn publisher_inbound_mean_tracks_h_over_f() {
    let mut rng = SplitMix64::new(0x1B_0A);
    let graph = build_two_class(Mix::new(400, 12, 0, 0.25), &mut rng);
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
#[ignore = "local composition dump; the ruled sweep is outbound_calibration_grid"]
fn outbound_composition_grid() {
    use shekyl_relay_privacy::conformance::composition::{simulate_stem_first_spy, SpyArm};

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
    println!(
        "local dump only. The ruled fluff sweep is outbound_calibration_grid \
         (OutboundOnly, 512 nodes). f = 1 is the normal case."
    );
    for (h, c) in points {
        let mix = Mix::new(48, h, c, 1.0);
        for routing in [Routing::HiddenStemSlot, Routing::HiddenOwnEdge] {
            let mut rng = SplitMix64::new(0x5950_0000 + (h as u64) * 16 + c as u64);
            let post = simulate_epoch_traffic(mix, routing, 20, &mut rng);
            let headline = if (h, c) == (12, 0) { " HEADLINE" } else { "" };
            println!(
                "EPOCH {routing:?}{headline} h={h} c={c} own={:.3} inbound={:.3} hid={:.3} clr={:.3} \
                 relayed_on_own={:.2} carrying={:.2} dial0={} dial_post={:.3}",
                post.posterior_own_edge,
                post.posterior_own_edge_with_inbound,
                post.posterior_hidden,
                post.posterior_clearnet,
                post.own_edge_relayed_per_originated,
                post.own_edges_carrying_relayed,
                post.dial_only_senders,
                post.posterior_dial_only
            );
            let busy = post
                .by_inbound
                .iter()
                .max_by_key(|bin| bin.senders)
                .expect("a degree bin");
            println!(
                "  degree {} senders {} posterior {:.3} (orig {} rel {})",
                busy.inbound, busy.senders, busy.posterior, busy.originated, busy.relayed
            );
        }
        for routing in [Routing::HiddenStemSlot, Routing::HiddenOwnEdge] {
            let mut rng = SplitMix64::new(0x5910);
            let spy =
                simulate_stem_first_spy(mix, routing, SpyArm::Uniform { p: 0.2 }, 0, 200, &mut rng);
            let mut rng = SplitMix64::new(0x5930);
            let spy30 = simulate_stem_first_spy(
                mix,
                routing,
                SpyArm::OnionBiased { p: 0.3 },
                0,
                200,
                &mut rng,
            );
            println!(
                "SPY {routing:?} h={h} c={c} p20 prec={:.3} rec={:.3} | p_h(0.3) prec={:.3} rec={:.3}",
                spy.precision, spy.recall, spy30.precision, spy30.recall
            );
        }
    }
    println!(
        "IN rows at f < 1 are opt-out and failure stress, not the normal published-onion fraction"
    );
    for (i, f) in [1.0_f64, 0.5, 0.25, 0.1].into_iter().enumerate() {
        for h in [12, 16, 24] {
            let mut rng = SplitMix64::new(0x1B00 + (h as u64) * 10 + i as u64);
            let graph = build_two_class(Mix::new(400, h, 0, f), &mut rng);
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
    let split = simulate_epoch_traffic(Mix::new(36, 12, 4, 1.0), Routing::Split, 8, &mut rng);
    println!(
        "BASE split own={:.3} hid={:.3} clr={:.3}",
        split.posterior_own_edge, split.posterior_hidden, split.posterior_clearnet
    );
    let mut rng = SplitMix64::new(0xC1);
    let paper =
        simulate_epoch_traffic(Mix::new(36, 0, 16, 1.0), Routing::AllClearnet, 12, &mut rng);
    println!(
        "BASE clearnet own={:.3} clr={:.3} carrying={:.3}",
        paper.posterior_own_edge, paper.posterior_clearnet, paper.own_edges_carrying_relayed
    );
}

#[test]
fn link_transit_moves_the_first_passage() {
    let mut fast = SplitMix64::new(0x77_A0);
    let mut slow = SplitMix64::new(0x77_A0);
    let hidden = build_two_class(Mix::new(20, 4, 0, 1.0), &mut fast);
    let clear = build_two_class(Mix::new(20, 0, 4, 1.0), &mut slow);
    let fast_p90 = graph_fluff_p90(
        &hidden,
        LinkTransit {
            hidden_ms: 0,
            clearnet_ms: 0,
        },
        FloodReach::EveryPeer,
        8,
        &mut SplitMix64::new(1),
    );
    let slow_p90 = graph_fluff_p90(
        &clear,
        LinkTransit {
            hidden_ms: 0,
            clearnet_ms: 20_000,
        },
        FloodReach::EveryPeer,
        8,
        &mut SplitMix64::new(1),
    );
    assert!(
        slow_p90 > fast_p90,
        "clearnet transit 20000 ms must slow the passage ({slow_p90} vs {fast_p90})"
    );
}

#[test]
fn a_clearnet_arrival_from_a_hidden_sender_is_relayed() {
    assert!(clearnet_arrival_is_relayed(LinkClass::Clearnet, true));
    assert!(!clearnet_arrival_is_relayed(LinkClass::Clearnet, false));
    assert!(!clearnet_arrival_is_relayed(LinkClass::Hidden, true));
}

#[test]
fn the_class_aware_estimator_does_not_name_an_exonerated_sender() {
    use shekyl_relay_privacy::conformance::composition::{simulate_class_aware_first_spy, SpyArm};
    let mut rng = SplitMix64::new(0xC1_A5);
    let reading = simulate_class_aware_first_spy(
        Mix::new(24, 4, 4, 1.0),
        Routing::HiddenStemSlot,
        SpyArm::Uniform { p: 0.3 },
        0,
        60,
        &mut rng,
    );
    assert!(reading.aware.named <= reading.blind.named);
    assert!(reading.aware.precision.is_finite());
    assert!(reading.aware.named_origin <= reading.blind.named_origin);
}

#[test]
fn a_heavy_originator_sits_closer_to_posterior_one() {
    use shekyl_relay_privacy::conformance::epoch_traffic::simulate_origin_rate_contrast;
    let mix = Mix::new(24, 4, 4, 1.0);
    let mut rng = SplitMix64::new(0x4E_47);
    let contrast = simulate_origin_rate_contrast(mix, Routing::HiddenStemSlot, 8, 10, &mut rng);
    assert!(
        contrast.heavy_posterior > contrast.rest_posterior,
        "heavy {} rest {}",
        contrast.heavy_posterior,
        contrast.rest_posterior
    );
}

#[test]
fn class_aware_precision_rises_only_when_the_first_hop_is_hidden() {
    use shekyl_relay_privacy::conformance::composition::{simulate_class_aware_first_spy, SpyArm};
    let mix = Mix::new(32, 12, 8, 1.0);
    let mut rng = SplitMix64::new(0x5A10);
    let hidden = simulate_class_aware_first_spy(
        mix,
        Routing::HiddenStemSlot,
        SpyArm::Uniform { p: 0.2 },
        0,
        200,
        &mut rng,
    );
    assert_eq!(hidden.aware.named_origin, hidden.blind.named_origin);
    assert!(hidden.aware.named <= hidden.blind.named);
    let mut rng = SplitMix64::new(0x5A10);
    let paper = simulate_class_aware_first_spy(
        mix,
        Routing::UniformHop0,
        SpyArm::Uniform { p: 0.2 },
        0,
        200,
        &mut rng,
    );
    assert!(
        paper.aware.named_origin * paper.blind.named < paper.blind.named_origin * paper.aware.named,
        "uniform hop 0 can be clearnet, so exonerating it drops the origin"
    );
}

#[test]
fn uniform_hop0_is_not_confined_to_the_hidden_pool() {
    let mut rng = SplitMix64::new(0x0F_00);
    let graph = build_two_class(Mix::new(40, 6, 6, 1.0), &mut rng);
    let maps = build_node_maps(&graph, Routing::UniformHop0, &mut rng);
    let clearnet = maps
        .iter()
        .filter(|map| {
            map.local
                .is_some_and(|edge| edge.class == LinkClass::Clearnet)
        })
        .count();
    assert!(clearnet > 0, "uniform hop 0 never used clearnet");
    assert!(clearnet < maps.len(), "uniform hop 0 never used hidden");
}

#[test]
fn clearnet_only_nodes_initiate_no_hidden_session() {
    let mut rng = SplitMix64::new(0xC0_12);
    let clearnet_only = 8;
    let graph = build_two_class(
        Mix::new(32, 4, 3, 1.0).with_clearnet_only(clearnet_only),
        &mut rng,
    );
    for (node, row) in graph.initiated.iter().enumerate() {
        let hidden = row.iter().filter(|e| e.class == LinkClass::Hidden).count();
        let clear = row
            .iter()
            .filter(|e| e.class == LinkClass::Clearnet)
            .count();
        assert_eq!(clear, 3, "node {node}");
        if node < clearnet_only {
            assert_eq!(hidden, 0, "node {node}");
            assert!(!graph.has_hidden_outbound(node));
        } else {
            assert_eq!(hidden, 4, "node {node}");
            assert!(graph.has_hidden_outbound(node));
        }
    }
}

#[test]
fn a_clearnet_relay_from_a_hidden_sender_is_not_an_origin_mark() {
    let mix = Mix::new(32, 8, 8, 1.0).with_clearnet_only(8);
    let mut rng = SplitMix64::new(0x5A11);
    let params = DandelionParams::adopted();
    let embargo = EmbargoTimer::geometric_from_ticks(1, DEFAULT_EMBARGO_TICK_MILLIS);
    let mut saw_hidden_sender = false;
    for _ in 0..80 {
        let graph = build_two_class(mix, &mut rng);
        let budget = StemRelayBudget::from_walk(&params, &embargo, &mut rng);
        let mut maps = build_node_maps(&graph, Routing::HiddenStemSlot, &mut rng);
        let stem = walk_originated(&graph, &mut maps, 0, budget, &mut rng);
        for (hop_index, hop) in stem.relayed.iter().enumerate() {
            let sender = stem.path[hop_index + 1];
            let hidden = graph.has_hidden_outbound(sender);
            if hop.class == LinkClass::Clearnet && hidden {
                assert!(clearnet_arrival_is_relayed(hop.class, hidden));
                saw_hidden_sender = true;
            }
            if !hidden {
                assert!(!clearnet_arrival_is_relayed(hop.class, hidden));
            }
        }
    }
    assert!(
        saw_hidden_sender,
        "no clearnet relay from a sender that still has a hidden session"
    );
}

#[test]
#[should_panic(expected = "no legal own-edge")]
fn origin_rate_contrast_refuses_a_node_with_no_own_edge() {
    use shekyl_relay_privacy::conformance::epoch_traffic::simulate_origin_rate_contrast;
    let mut rng = SplitMix64::new(1);
    let _contrast = simulate_origin_rate_contrast(
        Mix::new(8, 0, 4, 1.0),
        Routing::HiddenOwnEdge,
        4,
        1,
        &mut rng,
    );
}
