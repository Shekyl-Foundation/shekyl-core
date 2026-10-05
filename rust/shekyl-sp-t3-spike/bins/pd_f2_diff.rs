// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Compare two `pd-f2-measure` observation files, arm by arm — the PoW diff
//! `ARCHIVAL_SHARD_T_DERIVATION.md` §4.1a pre-registers.
//!
//! ```text
//! pd-f2-diff BASELINE.tsv TREATMENT.tsv [CONTROL_A.tsv CONTROL_B.tsv]
//! ```
//!
//! For every arm both files carry (`soak@3326976`, …) it prints each run's
//! `n`, completion rate and success percentiles, then judges completion,
//! p50 and p90 by [`shekyl_sp_t3_spike::compare`]: a bootstrap interval of
//! `treatment − baseline` read against a pre-registered margin. `p99` is
//! printed and not judged. With a control pair — two runs that differ only
//! in the day — a statistic the control finds material is **VOID** in the
//! treatment comparison. Reads the files through the same row format the
//! measurement writes; a row it cannot parse stops the diff.

use std::collections::BTreeMap;
use std::path::Path;

use shekyl_sp_t3_spike::compare::{judge, Judged, Statistic, Verdict, RESAMPLES};
use shekyl_sp_t3_spike::measure::{
    parse_row, summarize, Observation, Summary, REPORTED_PERCENTILES, ROW_HEADER,
};

/// One observations file, grouped by arm.
type Arms = BTreeMap<String, Vec<Observation>>;

fn load(path: &Path) -> Result<Arms, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut arms = Arms::new();
    for line in text.lines().filter(|l| *l != ROW_HEADER && !l.is_empty()) {
        let (arm, observation) = parse_row(line).map_err(|e| format!("{}: {e}", path.display()))?;
        arms.entry(arm.to_owned()).or_default().push(observation);
    }
    Ok(arms)
}

fn percentiles(summary: &Summary) -> String {
    REPORTED_PERCENTILES
        .iter()
        .map(|p| {
            summary
                .percentiles
                .iter()
                .find(|(q, _)| q == p)
                .map_or_else(
                    || format!("p{p} -"),
                    |(_, d)| format!("p{p} {:.2}", d.as_secs_f64()),
                )
        })
        .collect::<Vec<_>>()
        .join("  ")
}

fn line(label: &str, observations: &[Observation]) {
    let s = summarize(observations);
    println!(
        "  {label:<9} n {:>4}  completion {:.3}  {}",
        s.n,
        s.completion_rate(),
        percentiles(&s)
    );
}

fn verdict_word(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Material => "MATERIAL",
        Verdict::Immaterial => "immaterial",
        Verdict::Inconclusive => "inconclusive",
        Verdict::Void => "VOID (the control moves it)",
    }
}

fn judged_line(judged: &Judged, verdict: Verdict) {
    println!(
        "  {:<11} {:>9.3} -> {:>9.3}  Δ {:>+8.3}  95% [{:>+8.3}, {:>+8.3}]  {}",
        judged.statistic.name(),
        judged.baseline,
        judged.treatment,
        judged.delta(),
        judged.interval.0,
        judged.interval.1,
        verdict_word(verdict)
    );
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (base_path, treat_path, control) = match args.as_slice() {
        [b, t] => (b, t, None),
        [b, t, ca, cb] => (b, t, Some((ca, cb))),
        _ => {
            return Err(
                "usage: pd-f2-diff BASELINE.tsv TREATMENT.tsv [CONTROL_A.tsv CONTROL_B.tsv]".into(),
            )
        }
    };
    let baseline = load(Path::new(base_path))?;
    let treatment = load(Path::new(treat_path))?;
    let control = match control {
        Some((a, b)) => Some((load(Path::new(a))?, load(Path::new(b))?)),
        None => None,
    };
    println!("baseline:  {base_path}\ntreatment: {treat_path}");
    if let [_, _, a, b] = args.as_slice() {
        println!("control:   {a} vs {b}");
    }
    println!("{RESAMPLES} bootstrap resamples per statistic; p99 is shown, never judged");

    let mut compared = 0usize;
    for (arm, base) in &baseline {
        let Some(treat) = treatment.get(arm) else {
            continue;
        };
        compared += 1;
        println!("\n=== {arm} ===");
        line("baseline", base);
        line("treatment", treat);
        for statistic in Statistic::JUDGED {
            let Some(judged) = judge(base, treat, statistic) else {
                println!(
                    "  {:<11} undefined on a run or a resample",
                    statistic.name()
                );
                continue;
            };
            let control_verdict = control
                .as_ref()
                .and_then(|(a, b)| Some(judge(a.get(arm)?, b.get(arm)?, statistic)?.verdict));
            judged_line(&judged, judged.verdict.under_control(control_verdict));
        }
    }
    if compared == 0 {
        return Err("the two files share no arm: nothing was compared".into());
    }
    Ok(())
}
