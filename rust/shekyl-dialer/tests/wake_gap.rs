// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The wake spacing: each gap is the connector's base plus a uniform
//! jitter, drawn per dial.

use shekyl_dialer::next_wake_nanos;
use shekyl_draw_rng::SplitMix64;
use shekyl_peerlist::dial_profile;
use shekyl_peerlist::ConnectorId;

/// The wake spacing this file's connector dials at: its dial profile's.
const WAKE_BASE_NANOS: u64 = shekyl_peerlist::dial_profile(ConnectorId::Clearnet)
    .wake
    .base_nanos;
const WAKE_JITTER_NANOS: u64 = shekyl_peerlist::dial_profile(ConnectorId::Clearnet)
    .wake
    .jitter_nanos;

#[test]
fn the_wake_gap_is_half_a_second_plus_up_to_one_second() {
    let mut rng = SplitMix64::new(6);
    let mut low = u64::MAX;
    let mut high = 0;
    let mut sum = 0u128;
    let draws = 20_000u64;
    for _ in 0..draws {
        let gap = next_wake_nanos(dial_profile(ConnectorId::Clearnet).wake, &mut rng);
        assert!((WAKE_BASE_NANOS..=WAKE_BASE_NANOS + WAKE_JITTER_NANOS).contains(&gap));
        low = low.min(gap);
        high = high.max(gap);
        sum += u128::from(gap);
    }
    let mean = u64::try_from(sum / u128::from(draws)).expect("fits");
    // Mean 1 s; both ends of the range are reached to within 1 %.
    assert!((990_000_000..=1_010_000_000).contains(&mean), "mean {mean}");
    assert!(low < WAKE_BASE_NANOS + WAKE_JITTER_NANOS / 100);
    assert!(high > WAKE_BASE_NANOS + WAKE_JITTER_NANOS * 99 / 100);
}
