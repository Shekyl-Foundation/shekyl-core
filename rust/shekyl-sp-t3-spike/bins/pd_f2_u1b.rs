// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `U1b`'s two readings, as `ARCHIVAL_SHARD_T_DERIVATION.md` §9.3a fixes them,
//! on the floor device's observations file.
//!
//! ```text
//! pd-f2-u1b OBSERVATIONS.tsv
//! ```
//!
//! - **Reading A** bears on `W`: the miss interval at the largest object,
//!   which must bound the heaviest shard, against the target. One-sided.
//! - **Reading B** does not: the maximum sustainable holding per floor
//!   device, from the largest object's attempts, and a table of holdings
//!   with the list bound as one row.
//!
//! All of it is [`shekyl_sp_t3_spike::ceiling`] and
//! [`shekyl_sp_t3_spike::capacity`]; this file only reads and prints.

use std::path::Path;

use shekyl_sp_t3_spike::capacity::{
    Capacity, NoCapacity, CHALLENGE_READS_PER_PAIR, EPOCH, HOLDING_TABLE, LIST_BOUND,
};
use shekyl_sp_t3_spike::ceiling::{
    floor_device_read, soak_ladder, BelowTheHeaviestShard, Decision, FloorDeviceRead, SizeReading,
    DEADLINE, HEAVIEST_SHARD_BYTES, SOAK_ARM_PREFIX, TARGET_MISS_PER_CENT,
};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [path] = args.as_slice() else {
        return Err("usage: pd-f2-u1b OBSERVATIONS.tsv".into());
    };
    let text = std::fs::read_to_string(Path::new(path)).map_err(|e| format!("{path}: {e}"))?;
    let sizes = soak_ladder(&text).map_err(|e| format!("{path}: {e}"))?;
    // Rule 47: no soak arm is no subject, not a clean result.
    let Some((largest_bytes, largest)) = sizes.iter().next_back() else {
        return Err(format!("{path}: no `{SOAK_ARM_PREFIX}<bytes>` arm to read").into());
    };
    let readings: Vec<SizeReading> = sizes
        .iter()
        .map(|(bytes, observations)| {
            SizeReading::of(*bytes, observations).map_err(|void| {
                format!("{path}: {SOAK_ARM_PREFIX}{bytes} is not a reading — {void}")
            })
        })
        .collect::<Result<_, _>>()?;

    println!("observations: {path}");
    println!(
        "reading A — one read of the heaviest shard ({HEAVIEST_SHARD_BYTES} B) inside {} s, against a {TARGET_MISS_PER_CENT} % miss target (bears on W):",
        DEADLINE.as_secs()
    );
    let a = floor_device_read(&readings).ok_or("no readings")?;
    let largest_reading = readings.last().ok_or("no readings")?;
    let (low, high) = largest_reading.miss_interval();
    println!(
        "  at {} B: {} of {} missed, 95 % [{:.2}, {:.2}] %",
        largest_reading.bytes(),
        largest_reading.misses(),
        largest_reading.attempts(),
        100.0 * low,
        100.0 * high
    );
    match a {
        Ok(FloorDeviceRead::DoesNotLowerTheCeiling) => {
            println!("  the object bounds the heaviest shard from above; verdict: the floor device does NOT lower W's ceiling");
        }
        Ok(FloorDeviceRead::NoVerdict(decision)) => {
            let shape = match decision {
                Decision::Binds => "wholly over the target",
                Decision::Inconclusive => "straddles the target",
                Decision::Stands => "under the target",
            };
            println!("  the object bounds the heaviest shard from above; NO VERDICT: the interval {shape}, and this rig cannot separate the device as a server, so the split rig runs");
        }
        Err(BelowTheHeaviestShard { largest_bytes }) => {
            println!("  NOT READING A: the largest object, {largest_bytes} B, is smaller than the heaviest shard");
        }
    }

    println!(
        "reading B — sustainable holding per floor device, one read in flight, {CHALLENGE_READS_PER_PAIR} challenge reads per pair per {} s epoch (does NOT bear on W; a gate 4/5 participation-floor input):",
        EPOCH.as_secs()
    );
    let capacity = match Capacity::of(largest) {
        Ok(capacity) => capacity,
        Err(NoCapacity::Void(void)) => {
            return Err(format!(
                "{path}: {SOAK_ARM_PREFIX}{largest_bytes} is not a reading — {void}"
            )
            .into());
        }
        Err(NoCapacity::NoTime) => {
            println!("  no capacity: the {largest_bytes} B arm took no time");
            return Ok(());
        }
    };
    println!(
        "  at {largest_bytes} B: {:.4} reads/s, {} reads per epoch; maximum sustainable holding {} pairs",
        capacity.reads_per_second(),
        capacity.reads_per_epoch(),
        capacity.max_sustainable_holding()
    );
    println!(
        "  {:>8}  {:>10}  {:>11}  sustainable",
        "pairs", "reads", "utilization"
    );
    for pairs in HOLDING_TABLE {
        let reads = u64::from(CHALLENGE_READS_PER_PAIR) * u64::try_from(pairs)?;
        println!(
            "  {pairs:>8}  {reads:>10}  {:>10.1} %  {}{}",
            100.0 * capacity.utilization(pairs),
            if capacity.sustains(pairs) {
                "yes"
            } else {
                "no"
            },
            if pairs == LIST_BOUND {
                "   (the list bound: one row, not the anchor)"
            } else {
                ""
            }
        );
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("pd-f2-u1b: {e}");
        std::process::exit(1);
    }
}
