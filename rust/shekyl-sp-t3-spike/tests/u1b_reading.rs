// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `U1b` record, held to its data (`ARCHIVAL_SHARD_T_DERIVATION.md`
//! §10.8).
//!
//! The two observation files closed `SHT-5` and with it the last measurement
//! `W` waited on. Every number the record states is computed here from the
//! committed files by the same library the binaries print from, so a change
//! to a file, the row parser, the miss rule, the interval, the capacity rule,
//! the fit or the comparison moves a number here before it can move the
//! verdict silently. The W₂ files are held the same way (`ceiling.rs`,
//! `capacity.rs`).

use std::collections::BTreeMap;

use shekyl_sp_t3_spike::capacity::{Capacity, HOLDING_TABLE, LIST_BOUND};
use shekyl_sp_t3_spike::ceiling::{
    fit, floor_device_read, soak_ladder, Fit, FloorDeviceRead, SizeReading,
};
use shekyl_sp_t3_spike::compare::{judge, Statistic, Verdict};
use shekyl_sp_t3_spike::measure::Observation;

const DEVICE: &str = include_str!("../../../docs/benchmarks/u1b_floor_device_20261002.tsv");
const CONTROL: &str = include_str!("../../../docs/benchmarks/u1b_control_20261002.tsv");

const QUARTER: u32 = 831_744;
const HALF: u32 = 1_663_488;
const WHOLE: u32 = 3_326_976;

fn ladder(text: &str) -> BTreeMap<u32, Vec<Observation>> {
    let sizes = soak_ladder(text).expect("the committed file parses");
    assert_eq!(
        sizes.keys().copied().collect::<Vec<_>>(),
        [QUARTER, HALF, WHOLE],
        "the three objects §4.1a fixes"
    );
    sizes
}

fn readings(sizes: &BTreeMap<u32, Vec<Observation>>) -> Vec<SizeReading> {
    sizes
        .iter()
        .map(|(bytes, observations)| {
            SizeReading::of(*bytes, observations).expect("no void arm in the record")
        })
        .collect()
}

fn close(value: f64, expected: f64, tolerance: f64) -> bool {
    (value - expected).abs() < tolerance
}

/// Reading A on the floor device: 12 of 616 missed at 1×, three circuit and
/// nine transfer, interval 1.12 – 3.37 %, and the verdict that the device
/// does not lower `W`'s ceiling. The control's 1× arm, for the record: 15 of
/// 635.
#[test]
fn reading_a_is_as_recorded() {
    let device = readings(&ladder(DEVICE));
    let whole = device.last().expect("three sizes");
    assert_eq!(
        (whole.bytes(), whole.attempts(), whole.misses()),
        (WHOLE, 616, 12)
    );
    assert_eq!((whole.circuit_misses(), whole.transfer_misses()), (3, 9));
    let (low, high) = whole.miss_interval();
    assert!(
        close(low, 0.0112, 5e-5) && close(high, 0.0337, 5e-5),
        "{low} {high}"
    );
    assert_eq!(
        floor_device_read(&device),
        Some(Ok(FloorDeviceRead::DoesNotLowerTheCeiling))
    );

    let control = readings(&ladder(CONTROL));
    let whole = control.last().expect("three sizes");
    assert_eq!((whole.attempts(), whole.misses()), (635, 15));
}

/// Reading B on the floor device: 54,689 reads an epoch and a maximum
/// sustainable holding of 18,229 pairs, with every row of the table
/// sustained, the list bound among them.
#[test]
fn reading_b_is_as_recorded() {
    let sizes = ladder(DEVICE);
    let capacity = Capacity::of(&sizes[&WHOLE]).expect("a reading");
    assert_eq!(capacity.reads_per_epoch(), 54_689);
    assert_eq!(capacity.max_sustainable_holding(), 18_229);
    assert!(capacity.sustains(18_229) && !capacity.sustains(18_230));
    assert!(HOLDING_TABLE.iter().all(|&pairs| capacity.sustains(pairs)));
    assert!(close(capacity.utilization(LIST_BOUND), 0.2247, 5e-4));
}

/// The device's fit, reported and not judged: kept, 7.377 s + bytes /
/// 254,684 B/s, a 28.5 MB ceiling that is an extrapolation.
#[test]
fn the_device_fit_is_as_recorded() {
    let Fit::Kept {
        line,
        w_max_bytes,
        extrapolated,
    } = fit(&readings(&ladder(DEVICE)))
    else {
        panic!("the model is kept");
    };
    assert!(close(line.t_fixed_s, 7.377, 5e-4), "{line:?}");
    assert!(close(line.bytes_per_s, 254_684.0, 0.5), "{line:?}");
    assert!(close(w_max_bytes, 28_533_771.0, 1.0), "{w_max_bytes}");
    assert!(extrapolated);
}

/// The device against its same-window control, reported and not judged:
/// completion immaterial at all three objects; the p90 at ¼× material, 7.3 s
/// slower; the p50 at ½× immaterial; the other four latency statistics
/// inconclusive.
#[test]
fn the_control_comparison_is_as_recorded() {
    let control = ladder(CONTROL);
    let device = ladder(DEVICE);
    let verdict = |bytes: u32, statistic: Statistic| {
        judge(&control[&bytes], &device[&bytes], statistic)
            .expect("defined on both runs")
            .verdict
    };
    for bytes in [QUARTER, HALF, WHOLE] {
        assert_eq!(verdict(bytes, Statistic::Completion), Verdict::Immaterial);
    }
    let p90 = judge(&control[&QUARTER], &device[&QUARTER], Statistic::P90).expect("defined");
    assert_eq!(p90.verdict, Verdict::Material);
    assert!(close(p90.delta(), 7.295, 5e-4), "{p90:?}");
    assert_eq!(verdict(HALF, Statistic::P50), Verdict::Immaterial);
    for (bytes, statistic) in [
        (QUARTER, Statistic::P50),
        (HALF, Statistic::P90),
        (WHOLE, Statistic::P50),
        (WHOLE, Statistic::P90),
    ] {
        assert_eq!(
            verdict(bytes, statistic),
            Verdict::Inconclusive,
            "{bytes} {statistic:?}"
        );
    }
}
