// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;

fn sample(round_trips: u32, decoded: u64, seconds: f64) -> BlockSample {
    BlockSample {
        height: 1,
        round_trips,
        wire_hex_bytes: decoded * 2,
        decoded_bytes: decoded,
        seconds,
    }
}

#[test]
fn a_fixed_cost_per_round_trip_is_attributed_to_round_trips() {
    // Three round trips at 20 ms each, and essentially nothing else: the whole
    // cost is the term a throughput model cannot see.
    let samples: Vec<_> = (0..20).map(|_| sample(3, 1_000, 0.060)).collect();
    let floor = RoundTripFloor {
        median_s: 0.020,
        samples: 50,
    };
    let p = project(&samples, floor);
    assert_eq!(p.attribution, Attribution::RoundTripBound);
    assert_eq!(p.blocks_projected, crate::corpus::HELD_BUFFER_BLOCKS);
    assert_eq!(
        p.projected_round_trips,
        3 * crate::corpus::HELD_BUFFER_BLOCKS
    );
}

#[test]
fn a_cost_that_scales_with_content_is_attributed_to_volume() {
    // Same three round trips, but each block costs far more than the round-trip
    // floor accounts for -- this is where §6.3.4 row 3's companion file is the
    // right remedy.
    let samples: Vec<_> = (0..20).map(|_| sample(3, 3_000_000, 1.000)).collect();
    let floor = RoundTripFloor {
        median_s: 0.001,
        samples: 50,
    };
    let p = project(&samples, floor);
    assert_eq!(p.attribution, Attribution::VolumeBound);
}

#[test]
fn a_balanced_cost_refuses_to_pick_a_term() {
    // Neither term clears dominance: the harness says so rather than guessing,
    // because the attribution decides which remedy fires.
    let samples: Vec<_> = (0..20).map(|_| sample(2, 500_000, 0.100)).collect();
    let floor = RoundTripFloor {
        median_s: 0.025,
        samples: 50,
    };
    let p = project(&samples, floor);
    assert_eq!(p.attribution, Attribution::Mixed);
}

#[test]
fn wire_and_decoded_bytes_are_reported_separately() {
    // The block blob arrives hex-encoded. Conflating the two would understate
    // the wire by half -- and "bytes" was exactly the ambiguous term in the
    // model this module replaced.
    let samples: Vec<_> = (0..5).map(|_| sample(3, 1_000, 0.010)).collect();
    let p = project(
        &samples,
        RoundTripFloor {
            median_s: 0.001,
            samples: 10,
        },
    );
    assert_eq!(p.projected_wire_hex_bytes, 2 * p.projected_decoded_bytes);
}

#[test]
fn an_empty_sample_does_not_claim_an_attribution() {
    let p = project(
        &[],
        RoundTripFloor {
            median_s: 0.0,
            samples: 0,
        },
    );
    assert_eq!(p.attribution, Attribution::Mixed);
    assert_eq!(p.blocks_measured, 0);
}

#[test]
fn a_noisy_floor_never_produces_a_negative_volume_term() {
    // A round-trip floor measured higher than the per-block cost (contended
    // box, cold cache) must clamp rather than report a negative remainder.
    let samples: Vec<_> = (0..10).map(|_| sample(3, 100, 0.001)).collect();
    let p = project(
        &samples,
        RoundTripFloor {
            median_s: 10.0,
            samples: 5,
        },
    );
    assert!(p.volume_term_s >= 0.0);
    assert!(p.round_trip_term_s <= p.projected_s);
}

// ── The corpus-density gate ─────────────────────────────────────────────────

#[test]
fn a_coinbase_only_corpus_is_refused_as_too_thin_to_grade() {
    // The first live run's actual figure: 1432 B per block against a nominal
    // 300 000. A sample this far below the density the budget is stated at
    // cannot fail, so a pass over it would be a pass for the wrong reason.
    let samples: Vec<_> = (0..30).map(|_| sample(2, 1_432, 0.0002)).collect();
    let d = judge_density(&samples, crate::corpus::nominal_block_weight());
    assert_eq!(d.measured_bytes_per_block, 1_432);
    assert!(!d.sufficient, "{:.4} of graded", d.fraction_of_graded);
}

#[test]
fn a_corpus_at_the_graded_density_may_grade() {
    let weight = crate::corpus::nominal_block_weight();
    let samples: Vec<_> = (0..30).map(|_| sample(3, weight, 0.05)).collect();
    let d = judge_density(&samples, weight);
    assert!(d.sufficient);
    assert!((d.fraction_of_graded - 1.0).abs() < 1e-9);
}

#[test]
fn the_density_gate_has_a_boundary_it_can_be_pushed_across() {
    // Both sides of MIN_CORPUS_DENSITY_FRACTION, so the threshold is shown to
    // separate two states rather than being a constant nothing reaches.
    let weight = crate::corpus::nominal_block_weight();
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let just_under = (weight as f64 * (MIN_CORPUS_DENSITY_FRACTION - 0.01)) as u64;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let just_over = (weight as f64 * (MIN_CORPUS_DENSITY_FRACTION + 0.01)) as u64;
    assert!(!judge_density(&[sample(3, just_under, 0.01)], weight).sufficient);
    assert!(judge_density(&[sample(3, just_over, 0.01)], weight).sufficient);
}

#[test]
fn an_empty_sample_is_not_dense_enough_to_grade() {
    // Absence of signal is first evidence the subject is absent (rule 47):
    // zero blocks must not read as "density fine".
    assert!(!judge_density(&[], crate::corpus::nominal_block_weight()).sufficient);
}
