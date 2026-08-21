// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! §94 transit analysis: pooled quantiles, the size slope, and the convergence
//! check — over the JSONL sessions the rig emits.
//!
//! Reports, per arm, exactly what §94.2(d) pre-registered: **p90 adopted, p50
//! and p99 alongside**. The quantile is not chosen here; it was chosen before
//! any data existed, and this tool only computes it.
//!
//! Two things it deliberately does NOT do:
//!
//! - **It does not decide.** It prints the pooled p90 and the per-session
//!   deltas; whether the convergence criterion (§94.2(e)) is met is read off
//!   those numbers against the rule, not asserted by the tool. A tool that
//!   announces convergence is a tool that can be argued with about its
//!   threshold.
//! - **It does not drop failures silently.** Excluded rows are counted and
//!   reported. §94.2(a) excludes send-failures from the distribution because
//!   they are the backstop's event, but an exclusion nobody can see is
//!   indistinguishable from a sample that never happened.

use std::collections::BTreeMap;

/// One field out of a flat JSONL object. The rig writes this format, so a full
/// parser would be machinery for a problem that does not exist here.
fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let at = line.find(&format!("\"{key}\":"))? + key.len() + 3;
    let rest = &line[at..];
    let rest = rest.strip_prefix('"').unwrap_or(rest);
    let end = rest.find(['"', ',', '}'])?;
    Some(&rest[..end])
}

fn quantile(sorted: &[u64], q: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    // Nearest-rank. Stated because "which quantile definition" is exactly the
    // kind of unfrozen knob §94 exists to close: with n>=200 per arm the
    // choice moves the answer by well under the 5% convergence band, but it
    // moves it, so it is pinned rather than left to a default.
    let rank = (q * sorted.len() as f64).ceil().max(1.0) as usize;
    sorted[rank.min(sorted.len()) - 1]
}

fn main() {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: analyze <session.jsonl> [session.jsonl ...]");
        std::process::exit(2);
    }

    // arm -> session -> samples
    let mut by_arm: BTreeMap<String, Vec<Vec<u64>>> = BTreeMap::new();
    let mut excluded: BTreeMap<String, usize> = BTreeMap::new();
    let mut utc_lo = u128::MAX;
    let mut utc_hi = 0u128;

    for (idx, path) in paths.iter().enumerate() {
        let Ok(text) = std::fs::read_to_string(path) else {
            eprintln!("cannot read {path}");
            std::process::exit(2);
        };
        for line in text.lines().filter(|l| l.starts_with('{')) {
            let Some(arm) = field(line, "arm") else {
                continue;
            };
            let outcome = field(line, "outcome").unwrap_or("ok");
            if let Some(u) = field(line, "utc_ms").and_then(|v| v.parse::<u128>().ok()) {
                utc_lo = utc_lo.min(u);
                utc_hi = utc_hi.max(u);
            }
            if outcome != "ok" {
                *excluded.entry(outcome.to_string()).or_default() += 1;
                continue;
            }
            let Some(us) = field(line, "one_way_us").and_then(|v| v.parse::<u64>().ok()) else {
                continue;
            };
            let sessions = by_arm.entry(arm.to_string()).or_default();
            while sessions.len() <= idx {
                sessions.push(Vec::new());
            }
            sessions[idx].push(us);
        }
    }

    println!("sessions: {}", paths.len());
    let span_h = (utc_hi.saturating_sub(utc_lo)) as f64 / 3_600_000.0;
    println!(
        "time-of-day span across all samples: {span_h:.1} h  (§94.5(e) requires >= 8 h across >= 3 days)"
    );
    if excluded.is_empty() {
        println!("excluded: none — the in-band-rebuild arm is empty, as §94.5 expected");
    } else {
        for (k, v) in &excluded {
            println!("excluded ({k}): {v}  — EXPECTED EMPTY; a non-zero count falsifies §94.5's Tor-stream reasoning");
        }
    }

    let mut p90_by_arm: BTreeMap<String, f64> = BTreeMap::new();
    for (arm, sessions) in &by_arm {
        let mut pooled: Vec<u64> = sessions.iter().flatten().copied().collect();
        pooled.sort_unstable();
        let n = pooled.len();
        println!("\n=== {arm}  (n={n}) ===");
        println!(
            "  p50 {:>8.1} ms   p90 {:>8.1} ms   p99 {:>8.1} ms",
            quantile(&pooled, 0.50) as f64 / 1000.0,
            quantile(&pooled, 0.90) as f64 / 1000.0,
            quantile(&pooled, 0.99) as f64 / 1000.0
        );
        p90_by_arm.insert(arm.clone(), quantile(&pooled, 0.90) as f64 / 1000.0);

        // Convergence: the pooled p90 as each session is folded in. §94.2(e)
        // stops when a further session moves it by <5%.
        let mut running: Vec<u64> = Vec::new();
        let mut prev: Option<f64> = None;
        for (i, s) in sessions.iter().enumerate() {
            running.extend_from_slice(s);
            let mut sorted = running.clone();
            sorted.sort_unstable();
            let p90 = quantile(&sorted, 0.90) as f64 / 1000.0;
            match prev {
                Some(p) if p > 0.0 => println!(
                    "  after session {:>2}: pooled p90 {:>8.1} ms   ({:+.1}% vs previous)",
                    i + 1,
                    p90,
                    (p90 - p) / p * 100.0
                ),
                _ => println!("  after session {:>2}: pooled p90 {p90:>8.1} ms", i + 1),
            }
            prev = Some(p90);
        }
    }

    // The size slope — the point of the second arm. If this is small against
    // the six-hop rendezvous RTT, a scalar transit constant is defensible and
    // §86.1's narrowed premise needs nothing further.
    if let (Some(m), Some(x)) = (p90_by_arm.get("modal"), p90_by_arm.get("max_admissible")) {
        let d_kib = (16_651.0 - 8_395.0) / 1024.0;
        println!("\n=== size slope (§94.5(b)) ===");
        // A zero modal p90 means the modal arm produced no `ok` samples at all.
        // Printing `inf`/`NaN` there reads as a strange measurement rather than
        // a missing one, which is the opposite of what a diagnostic should do —
        // so the empty case is named instead of divided by.
        if *m <= 0.0 {
            println!("  modal arm has no successful samples; no slope to report.");
            println!("  (that is a SESSION failure, not a reading — check the .err file)");
        } else {
            println!("  p90 modal {m:.1} ms -> max_admissible {x:.1} ms   delta {:+.1} ms over {d_kib:.1} KiB", x - m);
            println!(
                "  per-KiB slope {:+.1} ms/KiB ({:+.1}% of the modal p90)",
                (x - m) / d_kib,
                (x - m) / m * 100.0
            );
            println!(
                "  ANON_ZONE_TRANSIT_ASSUMPTION_MS = 1625.0 (the labelled assumption being replaced)"
            );
        }
    }
}
