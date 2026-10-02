// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Read one `pd-f2-measure` observation file's soak ladder as a witness-miss
//! ceiling — the analysis `ARCHIVAL_SHARD_T_DERIVATION.md` §10.1 fixes.
//!
//! ```text
//! pd-f2-ceiling OBSERVATIONS.tsv
//! ```
//!
//! For every `soak@<bytes>` arm it prints the miss rate with its 95 % Wilson
//! interval, the circuit and transfer shares, and the governing percentile.
//! Then the decision at the largest object, and the fit over the ladder with
//! the ceiling it gives or the reason it gives none. All of it is
//! [`shekyl_sp_t3_spike::ceiling`]; this file only reads and prints.

use std::collections::BTreeMap;
use std::path::Path;

use shekyl_sp_t3_spike::ceiling::{
    decide, fit, Decision, Fit, Rejection, SizeReading, DEADLINE, GOVERNING_PERCENTILE,
    LINEARITY_TOLERANCE_PER_CENT, OVERSHOOT_BYTES, TARGET_MISS_PER_CENT,
};
use shekyl_sp_t3_spike::measure::{parse_row, Observation, ROW_HEADER};

/// The arm prefix the size ladder's soak writes: `soak@<object bytes>`.
const SOAK_ARM_PREFIX: &str = "soak@";

/// The soak arms of one observations file, by object size.
fn load(path: &Path) -> Result<BTreeMap<u32, Vec<Observation>>, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut sizes: BTreeMap<u32, Vec<Observation>> = BTreeMap::new();
    for line in text.lines().filter(|l| *l != ROW_HEADER && !l.is_empty()) {
        let (arm, observation) = parse_row(line).map_err(|e| format!("{}: {e}", path.display()))?;
        let Some(bytes) = arm.strip_prefix(SOAK_ARM_PREFIX) else {
            continue;
        };
        let bytes: u32 = bytes
            .parse()
            .map_err(|_| format!("{}: arm {arm} names no object size", path.display()))?;
        sizes.entry(bytes).or_default().push(observation);
    }
    Ok(sizes)
}

fn per_cent(share: f64) -> f64 {
    100.0 * share
}

fn size_line(reading: &SizeReading) {
    let (low, high) = reading.miss_interval();
    let governing = reading.t_governing().map_or_else(
        || "never".to_owned(),
        |t| format!("{:.2} s", t.as_secs_f64()),
    );
    println!(
        "  {:>9} B  n {:>4}  miss {:>3} ({:5.2} %)  95% [{:5.2}, {:5.2}] %  circuit {:>3}  transfer {:>3}  t{GOVERNING_PERCENTILE} {governing}",
        reading.bytes(),
        reading.attempts(),
        reading.misses(),
        per_cent(reading.miss_rate()),
        per_cent(low),
        per_cent(high),
        reading.circuit_misses(),
        reading.transfer_misses(),
    );
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [path] = args.as_slice() else {
        return Err("usage: pd-f2-ceiling OBSERVATIONS.tsv".into());
    };
    let sizes = load(Path::new(path))?;
    // Rule 47: no soak arm is no subject, not a clean result.
    if sizes.is_empty() {
        return Err(format!("{path}: no `{SOAK_ARM_PREFIX}<bytes>` arm to read").into());
    }
    // A void arm — no attempts, or a refused exchange — is the apparatus, and
    // it voids the file: the other sizes were measured on the same rig.
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
        "a miss: any outcome but ok, or an ok slower than {} s; target miss {TARGET_MISS_PER_CENT} %",
        DEADLINE.as_secs()
    );
    for reading in &readings {
        size_line(reading);
    }

    let largest = readings.last().expect("non-empty, checked above");
    let verdict = match decide(largest) {
        Decision::Stands => "interval wholly at or under the target: the length STANDS",
        Decision::Binds => "interval wholly over the target: the ceiling BINDS",
        Decision::Inconclusive => "interval straddles the target: INCONCLUSIVE",
    };
    println!("decision at {} B: {verdict}", largest.bytes());

    match fit(&readings) {
        Fit::TooFewSizes => println!("fit: fewer than three sizes, nothing fitted"),
        Fit::Unbounded { bytes } => println!(
            "fit: not fitted — more than {TARGET_MISS_PER_CENT} % missed at {bytes} B, so its t{GOVERNING_PERCENTILE} is infinite"
        ),
        Fit::Rejected {
            t_fixed_s,
            bytes_per_s,
            why,
        } => {
            let reason = match why {
                Rejection::NegativeFixedTime => "the fixed time is negative".to_owned(),
                Rejection::NoPositiveRate => "time does not grow with size".to_owned(),
                Rejection::NotLinear { off_per_cent } => format!(
                    "an interior point is {off_per_cent:.1} % of its own value off the line (limit {LINEARITY_TOLERANCE_PER_CENT} %)"
                ),
            };
            println!(
                "fit: REJECTED — {reason} (t_fixed {t_fixed_s:.3} s, v {bytes_per_s:.0} B/s); no ceiling"
            );
        }
        Fit::Kept {
            t_fixed_s,
            bytes_per_s,
            off_per_cent,
            w_max_bytes,
            extrapolated,
        } => {
            println!(
                "fit: t{GOVERNING_PERCENTILE} = {t_fixed_s:.3} s + bytes / {bytes_per_s:.0} B/s; interior point {off_per_cent:.1} % off the line (limit {LINEARITY_TOLERANCE_PER_CENT} %)"
            );
            println!(
                "ceiling: W_max = v * ({} s - t_fixed) - {OVERSHOOT_BYTES} B = {w_max_bytes:.0} B{}",
                DEADLINE.as_secs(),
                if extrapolated {
                    " — an EXTRAPOLATION past the largest object measured"
                } else {
                    ""
                }
            );
        }
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("pd-f2-ceiling: {e}");
        std::process::exit(1);
    }
}
