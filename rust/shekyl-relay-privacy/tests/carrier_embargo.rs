// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The embargo with every stem hop paced by the cover carrier (`CVR-R5`;
//! Rick, 2026-11-18): each hop's window wait, a message ahead of it at a
//! channel's expected occupancy, and the epoch tail.

use shekyl_relay_privacy::params::carrier::{
    channel_occupancy, EMBARGO_LIMIT_SECS, SMALLEST_NETWORK_NODES,
};
use shekyl_relay_privacy::schedule::{EmbargoTimer, DEFAULT_EMBARGO_TICK_MILLIS};
use shekyl_relay_privacy::verify_cost::{ADOPTED_TRANSIT, ANON_ZONE_TRANSIT};
use shekyl_relay_privacy::{
    full_travel_probability, full_travel_probability_paced, CarrierPacing, DandelionParams,
};

/// The pacing never helps a stem: with no wait at all the paced survival is
/// the unpaced one, and every wait it adds lowers it.
///
/// Red edits: drop a wait from the paced product (the ordering check fails
/// for that wait), or apply a wait as a gain.
#[test]
fn a_carrier_wait_only_lowers_full_travel() {
    let params = DandelionParams::adopted_for_transit_ms(ANON_ZONE_TRANSIT);
    let none = CarrierPacing {
        cadence_mean_ms: 5_000,
        hop_windows: 0,
        ahead_windows: 0,
        ahead_share: 0.0,
        tail_windows: 0,
        tail_share: 0.0,
    };
    for mean in [400_u32, 2_000, 8_000] {
        let plain = full_travel_probability(&params, mean, DEFAULT_EMBARGO_TICK_MILLIS);
        let zero = full_travel_probability_paced(&params, mean, DEFAULT_EMBARGO_TICK_MILLIS, &none);
        assert!(
            (plain - zero).abs() < 1e-12,
            "no wait: {plain} against {zero}"
        );
        let hop = CarrierPacing {
            hop_windows: 1,
            ..none
        };
        let ahead = CarrierPacing {
            ahead_windows: 1,
            ahead_share: 0.1,
            ..hop
        };
        let tail = CarrierPacing {
            tail_windows: 4,
            tail_share: 0.03,
            ..ahead
        };
        let mut last = zero;
        for pacing in [hop, ahead, tail] {
            let paced =
                full_travel_probability_paced(&params, mean, DEFAULT_EMBARGO_TICK_MILLIS, &pacing);
            assert!(paced < last, "{pacing:?} at mean {mean}: {paced} ≥ {last}");
            last = paced;
        }
    }
}

fn shipped_secs(params: &DandelionParams, nodes: u32) -> u32 {
    EmbargoTimer::adopted_paced(params, &CarrierPacing::shipped(nodes, params)).mean_secs()
}

/// The shipped embargo stays inside the 30-minute limit on both connectors
/// at the smallest network it is sized for, and the size below which the
/// Tor connector's would pass the limit is recorded (`CVR-R5`).
///
/// The figures are pinned: a cadence, tail, load or network-size change
/// moves them, and this test names which.
///
/// Red edits: size the embargo with the backlog cap at every hop (it passes
/// the limit), or drop the occupancy term (the breaking size falls to 1).
#[test]
fn the_shipped_embargo_is_inside_its_limit_at_the_smallest_network() {
    let anon = DandelionParams::adopted_for_transit_ms(ANON_ZONE_TRANSIT);
    let clearnet = DandelionParams::adopted_for_transit_ms(ADOPTED_TRANSIT);
    let anon_secs = shipped_secs(&anon, SMALLEST_NETWORK_NODES);
    let clearnet_secs = shipped_secs(&clearnet, SMALLEST_NETWORK_NODES);
    assert_eq!(
        EmbargoTimer::shipped(&anon).mean_secs(),
        anon_secs,
        "the shipped timer is the paced solve at the smallest network"
    );
    // The smallest network whose Tor embargo is still inside the limit.
    let smallest_inside = (1..=SMALLEST_NETWORK_NODES)
        .find(|nodes| shipped_secs(&anon, *nodes) <= EMBARGO_LIMIT_SECS)
        .expect("the smallest network is inside the limit");
    let occupancy = channel_occupancy(
        SMALLEST_NETWORK_NODES,
        anon.fluff_probability_pct,
        anon.min_epoch_secs,
    );
    println!(
        "Tor {anon_secs} s, clearnet {clearnet_secs} s at {SMALLEST_NETWORK_NODES} nodes \
         (occupancy {occupancy:.4}); the Tor embargo passes {EMBARGO_LIMIT_SECS} s below \
         {smallest_inside} nodes"
    );
    assert!(anon_secs <= EMBARGO_LIMIT_SECS, "Tor: {anon_secs} s");
    assert!(
        clearnet_secs <= EMBARGO_LIMIT_SECS,
        "clearnet: {clearnet_secs} s"
    );
    assert_eq!(
        (anon_secs, clearnet_secs, smallest_inside),
        PINNED,
        "the shipped embargoes or the breaking network size moved"
    );
}

/// Tor's and clearnet's shipped embargo means in seconds, and the smallest
/// network whose Tor embargo is inside the limit.
const PINNED: (u32, u32, u32) = (1_638, 1_320, 14);
