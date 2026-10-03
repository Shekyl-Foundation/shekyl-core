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
//! Then the decision at the largest object, the fit over the ladder with the
//! ceiling it gives or the reason it gives none, and the read of one attempt
//! and its retries with the retry budget that follows. All of it is
//! [`shekyl_sp_t3_spike::ceiling`]; this file only reads and prints.

use std::collections::BTreeMap;
use std::path::Path;

use shekyl_sp_t3_spike::ceiling::{
    completion_line, decide, fit, longest_read, read_with_retries, retry_budget, soak_ladder,
    Decision, Fit, Line, NoLine, Rejection, SizeReading, DEADLINE, FETCH_SPAN,
    GOVERNING_PERCENTILE, HEAVIEST_SHARD_BYTES, LINEARITY_TOLERANCE_PER_CENT, OVERSHOOT_BYTES,
    RETRY_CEILING, SOAK_ARM_PREFIX, TARGET_MISS_PER_CENT,
};
use shekyl_sp_t3_spike::measure::Observation;

/// The soak arms of one observations file, by object size.
fn load(path: &Path) -> Result<BTreeMap<u32, Vec<Observation>>, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(soak_ladder(&text).map_err(|e| format!("{}: {e}", path.display()))?)
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

/// The completion percentiles §4.1a fits.
const COMPLETION_PERCENTILES: [u8; 3] = [50, 90, 99];

/// The retry counts the read is printed for: none, then one past the count
/// the ceiling admits, so the line that does not fit is on the page.
const RETRY_LADDER: [u32; 4] = [0, 1, 2, 3];

fn line_words(line: &Line) -> String {
    format!(
        "{:.3} s + bytes / {:.0} B/s; interior point {:.1} % off the line (limit {LINEARITY_TOLERANCE_PER_CENT} %)",
        line.t_fixed_s, line.bytes_per_s, line.off_per_cent
    )
}

fn no_line_words(no_line: NoLine) -> String {
    match no_line {
        NoLine::TooFewSizes => "fewer than three sizes, nothing fitted".to_owned(),
        NoLine::Rejected {
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
            format!("REJECTED — {reason} (t_fixed {t_fixed_s:.3} s, v {bytes_per_s:.0} B/s)")
        }
    }
}

/// One line's time at the heaviest shard, with the line it came from.
fn span_line(label: &str, line: &Line) {
    println!(
        "  span at the heaviest shard ({HEAVIEST_SHARD_BYTES} B), {label}: {:.1} s  [{}]",
        line.at(HEAVIEST_SHARD_BYTES),
        line_words(line)
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
        Fit::Unbounded { bytes } => println!(
            "fit: not fitted — more than {TARGET_MISS_PER_CENT} % missed at {bytes} B, so its t{GOVERNING_PERCENTILE} is infinite"
        ),
        Fit::NoLine(no_line) => println!("fit: {}; no ceiling", no_line_words(no_line)),
        Fit::Kept {
            line,
            w_max_bytes,
            extrapolated,
        } => {
            println!("fit: t{GOVERNING_PERCENTILE} = {}", line_words(&line));
            println!(
                "ceiling: W_max = v * ({} s - t_fixed) - {OVERSHOOT_BYTES} B = {w_max_bytes:.0} B{}",
                DEADLINE.as_secs(),
                if extrapolated {
                    " — an EXTRAPOLATION past the largest object measured"
                } else {
                    ""
                }
            );
            span_line(&format!("t{GOVERNING_PERCENTILE}, all attempts"), &line);
        }
    }

    // §4.1a's per-percentile fits, over completions, read at the same object.
    let ladder: Vec<(u32, &[Observation])> = sizes
        .iter()
        .map(|(bytes, observations)| (*bytes, observations.as_slice()))
        .collect();
    for p in COMPLETION_PERCENTILES {
        match completion_line(&ladder, p) {
            Ok(line) => span_line(&format!("p{p} of completions"), &line),
            Err(no_line) => println!("  p{p} of completions: {}", no_line_words(no_line)),
        }
    }

    let (largest_bytes, largest_observations) = ladder.last().expect("non-empty, checked above");
    println!(
        "a read of one attempt and its retries at {largest_bytes} B, over every ordered tuple of its {} attempts (a miss costs what it took, at most {} s; the failure share assumes independent attempts and is a floor):",
        largest_observations.len(),
        DEADLINE.as_secs()
    );
    for retries in RETRY_LADDER {
        let completed_by = |p: u8| {
            read_with_retries(largest_observations, retries, p)
                .and_then(|read| read.completed_by)
                .map_or_else(
                    || "never".to_owned(),
                    |t| format!("{:.1} s", t.as_secs_f64()),
                )
        };
        let failure =
            read_with_retries(largest_observations, retries, 50).map_or(0.0, |r| r.failure_rate);
        println!(
            "  {retries} {}: every attempt misses {:5.2} %; completed reads p50 {}  p90 {}  p99 {}; longest possible {} s",
            if retries == 1 { "retry  " } else { "retries" },
            per_cent(failure),
            completed_by(50),
            completed_by(90),
            completed_by(99),
            longest_read(retries).as_secs()
        );
    }
    match retry_budget(largest_observations) {
        Some(budget) => println!(
            "retry budget: {budget} — the largest count whose p99 is inside the {} s span and whose longest read is not past {} s",
            FETCH_SPAN.as_secs(),
            RETRY_CEILING.as_secs()
        ),
        None => println!("retry budget: none — no read completes"),
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("pd-f2-ceiling: {e}");
        std::process::exit(1);
    }
}
