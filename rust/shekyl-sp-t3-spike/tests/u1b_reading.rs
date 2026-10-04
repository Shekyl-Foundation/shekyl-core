// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `U1b` record, held to its data (`ARCHIVAL_SHARD_T_DERIVATION.md`
//! §10.8).
//!
//! The two observation files closed `SHT-5` and with it the last measurement
//! `W` waited on. Every number §10.8 states is computed here from the
//! committed files — the two `U1b` files, and W₂'s PoW-on window for the one
//! comparison that reads it — by the same library the binaries print from, so
//! a change to a file, the row parser, the miss rule, the interval, the
//! capacity rule, the fit or the comparison moves a number here before it can
//! move the record silently. The W₂ files are held the same way
//! (`ceiling.rs`, `capacity.rs`).

use std::collections::BTreeMap;

use shekyl_sp_t3_spike::capacity::{Capacity, HOLDING_TABLE, LIST_BOUND};
use shekyl_sp_t3_spike::ceiling::{
    completion_line, fit, floor_device_read, soak_ladder, Fit, FloorDeviceRead, SizeReading,
    HEAVIEST_SHARD_BYTES,
};
use shekyl_sp_t3_spike::compare::{judge, Statistic, Verdict};
use shekyl_sp_t3_spike::measure::Observation;

const DEVICE: &str = include_str!("../../../docs/benchmarks/u1b_floor_device_20261002.tsv");
const CONTROL: &str = include_str!("../../../docs/benchmarks/u1b_control_20261002.tsv");
const W2_POW_ON: &str =
    include_str!("../../../docs/benchmarks/w2_ladder_interleaved_pow_on_20261001.tsv");

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
    // The run's size: 1,846 fetches on the device and 1,904 on the control,
    // a third at each object.
    let attempts = |text: &str| {
        readings(&ladder(text))
            .iter()
            .map(SizeReading::attempts)
            .collect::<Vec<_>>()
    };
    assert_eq!(attempts(DEVICE), [615, 615, 616]);
    assert_eq!(attempts(CONTROL), [634, 635, 635]);

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
    assert!(
        close(whole.miss_rate(), 0.0236, 5e-5),
        "the control's 1× miss share"
    );
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
    assert!(close(capacity.reads_per_second(), 0.0456, 5e-5));
    assert!(close(capacity.utilization(LIST_BOUND), 0.2247, 5e-4));
    assert!(close(capacity.utilization(16_384), 0.899, 5e-4));
    // §10.8's table, the share of capacity per holding, to its printed
    // tenth of a per cent.
    let printed: Vec<String> = HOLDING_TABLE
        .iter()
        .map(|&pairs| format!("{:.1}", 100.0 * capacity.utilization(pairs)))
        .collect();
    assert_eq!(
        printed,
        ["0.0", "0.1", "0.7", "2.8", "5.6", "11.2", "22.5", "44.9", "89.9"]
    );
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
    assert!(
        close(line.off_per_cent, 0.1, 0.05),
        "the middle point's residual"
    );
    assert!(
        close(line.at(HEAVIEST_SHARD_BYTES), 19.7, 0.05),
        "t70 at the heaviest shard"
    );

    let sizes = ladder(DEVICE);
    let ladder_view: Vec<(u32, &[Observation])> = sizes
        .iter()
        .map(|(bytes, observations)| (*bytes, observations.as_slice()))
        .collect();
    let p99 = completion_line(&ladder_view, 99).expect("the p99 line is kept");
    assert!(close(p99.at(HEAVIEST_SHARD_BYTES), 96.8, 0.05), "{p99:?}");
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
    assert!(
        close(p90.interval.0, 2.377, 5e-4) && close(p90.interval.1, 12.963, 5e-4),
        "{p90:?}"
    );
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

/// The control against W₂'s PoW-on window (2026-10-01), reported and not
/// judged: the control's p50 is materially slower at ½× (+2.4 s) and 1×
/// (+4.5 s); completion is inconclusive at ½× and 1× and immaterial at ¼×.
#[test]
fn the_control_against_the_w2_window_is_as_recorded() {
    let w2 = ladder(W2_POW_ON);
    let control = ladder(CONTROL);
    let judged = |bytes: u32, statistic: Statistic| {
        judge(&w2[&bytes], &control[&bytes], statistic).expect("defined on both runs")
    };
    let half = judged(HALF, Statistic::P50);
    let whole = judged(WHOLE, Statistic::P50);
    assert_eq!(
        (half.verdict, whole.verdict),
        (Verdict::Material, Verdict::Material)
    );
    assert!(close(half.delta(), 2.430, 5e-4), "{half:?}");
    assert!(close(whole.delta(), 4.484, 5e-4), "{whole:?}");
    assert_eq!(
        judged(HALF, Statistic::Completion).verdict,
        Verdict::Inconclusive
    );
    assert_eq!(
        judged(WHOLE, Statistic::Completion).verdict,
        Verdict::Inconclusive
    );
    assert_eq!(
        judged(QUARTER, Statistic::Completion).verdict,
        Verdict::Immaterial
    );
}
