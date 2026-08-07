// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared helpers for the propagation measurement suite.

#![allow(clippy::cast_precision_loss)]

use shekyl_relay_privacy::conformance::PropagationSummary;
use shekyl_relay_privacy::schedule::DEFAULT_EMBARGO_TICK_MILLIS;

pub const TRIALS: usize = 200_000;

pub fn row(label: &str, embargo_secs: u32, s: &PropagationSummary) {
    row_ticked(label, embargo_secs, DEFAULT_EMBARGO_TICK_MILLIS, s);
}

pub fn row_ticked(label: &str, embargo_secs: u32, tick_ms: u64, s: &PropagationSummary) {
    println!(
        "{label:<28} {embargo_secs:>7}s {tick_ms:>6}ms {:>9.2} {:>12.0}ms {:>12}ms {:>13.4} {:>12.4}",
        s.mean_stem_hops,
        s.mean_natural_fluff_ms,
        s.p99_natural_fluff_ms,
        s.full_travel_rate,
        s.preemption_rate,
    );
}

pub fn header(title: &str) {
    println!("\n{title}");
    println!(
        "{:<28} {:>8} {:>8} {:>9} {:>14} {:>14} {:>13} {:>12}",
        "parameter set",
        "embargo",
        "tick",
        "hops",
        "mean fluff",
        "p99 fluff",
        "full-travel",
        "preempted"
    );
    println!("{}", "-".repeat(112));
}
