// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The embargo with every stem hop paced by the cover carrier (`CVR-R5`;
//! Rick, 2026-11-18): the hop's window wait and the epoch tail.

use shekyl_relay_privacy::schedule::DEFAULT_EMBARGO_TICK_MILLIS;
use shekyl_relay_privacy::verify_cost::ANON_ZONE_TRANSIT;
use shekyl_relay_privacy::{
    full_travel_probability, full_travel_probability_paced, CarrierPacing, DandelionParams,
};

/// The pacing never helps a stem: with no wait at all the paced survival is
/// the unpaced one, and every wait it adds lowers it.
///
/// Red edits: drop a wait from the paced product (the zero-pacing case still
/// matches, and the ordering check fails for that wait), or apply a wait as
/// a gain.
#[test]
fn a_carrier_wait_only_lowers_full_travel() {
    let params = DandelionParams::adopted_for_transit_ms(ANON_ZONE_TRANSIT);
    let none = CarrierPacing {
        cadence_mean_ms: 5_000,
        hop_windows: 0,
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
        let mut last = zero;
        for pacing in [
            CarrierPacing {
                hop_windows: 1,
                ..none
            },
            CarrierPacing::shipped(0, params.min_epoch_secs),
            CarrierPacing::shipped(4, params.min_epoch_secs),
        ] {
            let paced =
                full_travel_probability_paced(&params, mean, DEFAULT_EMBARGO_TICK_MILLIS, &pacing);
            assert!(paced < last, "{pacing:?} at mean {mean}: {paced} ≥ {last}");
            last = paced;
        }
    }
}
