// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The PD-F-2 measurement run. **A binary that produces a data file, not a test.**
//!
//! Per §7 the measurement is deliberately not a `cargo test`: its result depends
//! on live Tor conditions, so as a test it would be a flake generator, and a
//! green/red verdict is the wrong shape for a distribution anyway.
//!
//! ```text
//! SHEKYL_SPIKE_TOR=/path/to/tor \
//! SHEKYL_SPIKE_SHARD=/path/to/shard.bin \
//! SHEKYL_SPIKE_OUT=/path/to/observations.tsv \
//! SHEKYL_SPIKE_PERSONAS=P \
//! SHEKYL_SPIKE_COLD=N SHEKYL_SPIKE_WARM=N SHEKYL_SPIKE_CONC=N \
//! SHEKYL_SPIKE_HOURS=H \
//!   cargo run -p shekyl-sp-t3-spike --release --bin pd-f2-measure
//! ```
//!
//! `SHEKYL_SPIKE_PERSONAS` (default 4) is the width of the concurrency
//! sweep: that many personas come up, **each behind its own tor**, plus the
//! client tor every fetch dials through. The sweep runs widths
//! `1, 2, 4, …` up to `P` (and `P` itself if not a power of two), `CONC`
//! rounds each; every round is `NEWNYM` then `width` fetches at once, with
//! the starting persona rotating by round so every width samples every
//! persona. Its table is the client-side circuit-churn input `SF-D7` names
//! as the upper bound on `N`. The box's uplink is shared across every tor
//! here, which biases the sweep *pessimistic* — named in the report, not
//! hidden.
//!
//! # What it prints for the two pins
//!
//! - **`N` (`SF-D7`):** the churn table — per width: `n`, p50, p99, p99 as
//!   a ratio to width 1, circuit-failure rate, `D*`, and the memory term
//!   `width × max_body_bytes()`. The binary does **not** pick the knee; a
//!   threshold it invented would be exactly the kind of number the `L`
//!   note's falsifier was rewritten to avoid. The reader takes the largest
//!   width that is not churning *and* whose memory term fits the Pi 4
//!   floor, and pins that.
//! - **`L` (`SF-D8`):** the cold arm's p99 against the PROVISIONAL note's
//!   two thresholds (under two minutes → drop to 3; over six → tighten the
//!   `SF-D6` retry budget, do not raise `L`), and how many attempts of that
//!   p99 fit under six minutes. Single-attempt, stated as such: retry is
//!   the scheduler's, so "fetch-plus-retry" is this p99 times whatever
//!   `TJ-D` budgets.
//!
//! # What it writes, and what it refuses to write
//!
//! The output is **aggregates plus per-observation durations without any
//! identifying context** (§6.4): a row is `arm`, `elapsed_ms`, `outcome`. There
//! is no wall-clock timestamp, no ordinal within the run, no persona, and no
//! circuit id — so the file cannot be used to correlate a fetch to a circuit
//! even by someone who obtains it. Durations alone are what the CDF needs.
//!
//! The run **refuses to start without a real shard fixture**: there is no
//! synthetic fallback anywhere in this crate, because a measurement that quietly
//! substituted its payload would be worse than no measurement.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use shekyl_p_fetch::max_body_bytes;
use shekyl_sp_t3_spike::fixture::ShardFixture;
use shekyl_sp_t3_spike::harness::Apparatus;
use shekyl_sp_t3_spike::measure::{
    attempts_within_budget, churn_table, l_verdict, p99, summarize, sweep_round_indices,
    warmup_drift, DStar, FailureKind, LVerdict, Observation, Summary, SweepPoint,
    L_BUDGET_TOO_GENEROUS_ABOVE, L_DROP_BELOW, Q_RISK_STAR,
};

fn env_path(key: &str) -> Option<PathBuf> {
    std::env::var_os(key).map(PathBuf::from)
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// One arm's rows, appended as they are produced so a run killed mid-flight
/// still leaves the observations it earned.
fn append_rows(out: &mut Option<std::fs::File>, arm: &str, obs: &[Observation]) {
    use std::io::Write as _;
    let Some(f) = out.as_mut() else { return };
    for o in obs {
        let outcome = match o.failure {
            None => "ok",
            Some(FailureKind::Timeout) => "timeout",
            Some(FailureKind::Circuit) => "circuit",
            Some(FailureKind::Truncated) => "truncated",
            Some(FailureKind::Refused) => "refused",
        };
        // arm, elapsed_ms, outcome. Nothing else — see the module doc.
        writeln!(f, "{arm}\t{}\t{outcome}", o.elapsed.as_millis()).ok();
    }
    f.flush().ok();
}

/// The widths the sweep visits: powers of two up to `personas`, plus
/// `personas` itself when it is not one.
fn sweep_widths(personas: usize) -> Vec<usize> {
    let mut widths: Vec<usize> = std::iter::successors(Some(1usize), |w| w.checked_mul(2))
        .take_while(|&w| w <= personas)
        .collect();
    if widths.last() != Some(&personas) && personas >= 1 {
        widths.push(personas);
    }
    widths
}

fn fmt_opt_secs(d: Option<Duration>) -> String {
    d.map_or_else(
        || "   —    ".to_owned(),
        |d| format!("{:>8.2}", d.as_secs_f64()),
    )
}

/// The `SF-D7` churn table, with the memory term beside each row.
fn report_churn(points: &[SweepPoint]) {
    println!("\n=== SF-D7 upper-bound inputs: client-side churn by in-flight width ===");
    println!("(one client tor; `width` cold fetches to `width` personas at once, start rotating by round; shared uplink → pessimistic)");
    println!(
        "(one PFetchClient per persona on purpose: the SPIKE-PIN admission semaphore this \
         sweep exists to replace is NOT in the path; a production daemon has one client)"
    );
    println!(
        "{:>5} {:>5} {:>8} {:>8} {:>9} {:>8} {:>10}  {:>10}  valid",
        "width", "n", "p50 s", "p99 s", "p99/w1", "circ %", "D* s", "mem MB"
    );
    let per_body = max_body_bytes();
    let rows = churn_table(points);
    let void_rows = rows.iter().filter(|r| r.is_void()).count();
    for row in &rows {
        let d_star = match row.d_star {
            DStar::At(d) => format!("{:>10.2}", d.as_secs_f64()),
            DStar::Unbounded => " UNBOUNDED".to_owned(),
            DStar::Undefined => "     undef".to_owned(),
        };
        // `width × max_body_bytes()` is the resident term SF-D7 caps
        // against the Pi 4 floor; integer bytes, shown to a tenth of a MB.
        let mem_bytes = u64::try_from(row.width)
            .expect("width fits u64")
            .saturating_mul(per_body);
        let mem_mb = format!(
            "{}.{}",
            mem_bytes / 1_000_000,
            (mem_bytes % 1_000_000) / 100_000
        );
        let valid = match (row.cap_refusals, row.refused) {
            (0, 0) => "ok".to_owned(),
            (shed, 0) => format!("VOID ({shed} shed at the serve-side cap)"),
            (0, refused) => format!("VOID ({refused} refused by the client)"),
            (shed, refused) => format!("VOID ({shed} shed, {refused} refused)"),
        };
        println!(
            "{:>5} {:>5} {} {} {:>9} {:>7.1}% {d_star}  {mem_mb:>10}  {valid}",
            row.width,
            row.n,
            fmt_opt_secs(row.p50),
            fmt_opt_secs(row.p99),
            row.p99_over_width_1
                .map_or_else(|| "—".to_owned(), |r| format!("{r:.2}×")),
            row.circuit_rate * 100.0,
        );
    }
    if void_rows != 0 {
        println!(
            "{void_rows} row(s) VOID: the serve-side placeholder cap shed connections while they \
             ran, or the client refused a completed exchange (404 / malformed / bad \
             countersignature — the apparatus disagreeing with itself), so their churn is not \
             Tor's. Read N from the remaining rows only, or fix the cause and re-run the sweep."
        );
    }
    println!(
        "The pin is min(largest non-churning width, memory fit on the Pi 4 floor). \
         This table does not pick it."
    );
}

/// The `L` falsifier, read off the cold arm.
fn report_l(cold: &Summary) {
    println!("\n=== SF-D8 `L` falsifier (PROVISIONAL L = 4), from the cold arm ===");
    match p99(cold) {
        None => println!("no cold successes — the falsifier is undefined on this run"),
        Some(p) => {
            println!(
                "single-attempt cold p99 = {:.1} s  (note thresholds: < {} s → drop to 3; > {} s → tighten SF-D6 budget, not L)",
                p.as_secs_f64(),
                L_DROP_BELOW.as_secs(),
                L_BUDGET_TOO_GENEROUS_ABOVE.as_secs()
            );
            match l_verdict(cold) {
                LVerdict::DropToThreeCandidate => println!(
                    "verdict: DROP-TO-3 CANDIDATE — necessary, not sufficient: fetch-plus-retry must \
                     also land under two minutes once TJ-D's retry budget is applied"
                ),
                LVerdict::DropRefutedBudgetOpen => println!(
                    "verdict: DROP-TO-3 REFUTED (a fetch-plus-retry span starts at this attempt, \
                     so it cannot land under two minutes); the six-minute branch is OPEN until \
                     SF-D6's retry budget is applied to this tail — see the attempts line below"
                ),
                LVerdict::TightenRetryBudgetNotL => println!(
                    "verdict: OVER SIX MINUTES ON ONE ATTEMPT — the note says tighten SF-D6's \
                     retry budget, do not raise L; a single attempt this long also questions \
                     the fetch itself"
                ),
                LVerdict::Undefined => unreachable!("p99 present"),
            }
            match attempts_within_budget(cold) {
                Some(k) => println!(
                    "attempts of this p99 that fit under six minutes: {k} — the most SF-D6 can \
                     budget per witness attempt before L absorbs the budget"
                ),
                None => println!("attempts of this p99 that fit under six minutes: 0"),
            }
        }
    }
}

fn report(arm: &str, obs: &[Observation]) {
    let s = summarize(obs);
    // The warm-up check, computed here from the in-memory sequence and reported
    // as two aggregates only (no ordering is persisted -- §6.4). A cold arm whose
    // last quarter is materially faster than its first is not cold, and its tail
    // is optimistic in the direction that inflates D*.
    if let Some((first, last)) = warmup_drift(obs) {
        let ratio = last.as_secs_f64() / first.as_secs_f64().max(f64::MIN_POSITIVE);
        println!(
            "  warm-up check: first-quarter p50 = {:.2} s, last-quarter p50 = {:.2} s (ratio {ratio:.2})",
            first.as_secs_f64(),
            last.as_secs_f64()
        );
        if ratio < 0.75 {
            println!(
                "  *** WARNING: this arm got materially faster as it ran. If this is the \n                 *** cold arm, its tail is OPTIMISTIC and D* below is an OVERSTATEMENT \n                 *** of how generous TJ-C's deadline may be. Do not use it as a safety margin."
            );
        }
    }
    println!("\n=== arm: {arm} ===");
    println!("n = {}, successes = {}", s.n, s.successes);
    println!("completion rate = {:.4}", s.completion_rate());
    if !s.failures.is_empty() {
        println!("failures: {:?}", s.failures);
    }
    for (p, d) in &s.percentiles {
        println!("  p{p:<3} = {:>8.2} s", d.as_secs_f64());
    }
    match s.d_star {
        DStar::At(d) => println!(
            "D* = {:.2} s   (q(D) >= {Q_RISK_STAR} for all D <= D*)",
            d.as_secs_f64()
        ),
        DStar::Unbounded => println!(
            "D* = UNBOUNDED — the outright-failure rate alone reaches {Q_RISK_STAR}; \
             no deadline makes this arm safe"
        ),
        DStar::Undefined => println!("D* = undefined (empty sample)"),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tor = env_path("SHEKYL_SPIKE_TOR")
        .ok_or("SHEKYL_SPIKE_TOR must point at the pinned Tor Expert Bundle binary")?;
    let shard_path = env_path("SHEKYL_SPIKE_SHARD")
        .ok_or("SHEKYL_SPIKE_SHARD must point at a real extracted shard fixture")?;
    let personas = env_usize("SHEKYL_SPIKE_PERSONAS", 4).max(1);
    let cold_n = env_usize("SHEKYL_SPIKE_COLD", 100);
    let warm_n = env_usize("SHEKYL_SPIKE_WARM", 100);
    let conc_n = env_usize("SHEKYL_SPIKE_CONC", 50);
    let hours = env_usize("SHEKYL_SPIKE_HOURS", 0);

    // Loud, first: no synthetic fallback exists, so a missing fixture stops the
    // run here rather than producing a number about the wrong payload.
    let fixture = ShardFixture::load(&shard_path)?;
    println!("shard fixture: {} bytes", fixture.len());

    let dir = tempfile::tempdir()?;
    println!(
        "bringing up a client tor and {personas} personas, each behind its own tor ({} bootstraps, in parallel)...",
        personas + 1
    );
    let app = Arc::new(
        Apparatus::bring_up(
            tor,
            dir.path().join("tor-data"),
            u32::try_from(personas)?,
            fixture.bytes(),
        )
        .await?,
    );

    // The expected body length is the apparatus's to know, not this binary's
    // to pass: it is derived from the payload through the production serving
    // contract (RF-D4's frame included), so no caller here can hand in a
    // number that the wire has since moved away from.
    println!(
        "served body: {} bytes (frame + shard)",
        app.expected_body_len()
    );
    let publish = app.await_reachable().await?;
    println!(
        "personas cold-reachable after {:.1} s (publication + HSDir propagation — EXCLUDED from every arm)",
        publish.as_secs_f64()
    );

    let mut out = env_path("SHEKYL_SPIKE_OUT").and_then(|p| std::fs::File::create(p).ok());
    if let Some(f) = out.as_mut() {
        use std::io::Write as _;
        writeln!(f, "arm\telapsed_ms\toutcome").ok();
    }

    // --- Arm 1: cold, single stream. `NEWNYM` to the client tor before each
    // fetch, so descriptor fetch + intro + rendezvous are inside the timed path
    // (§6.2). This is the faithful model of a drawn miner dialling a `P` it has
    // never dialled, and is expected to dominate the tail. The ten-second
    // NEWNYM spacing is paid *outside* the clock.
    let mut cold = Vec::new();
    for i in 0..cold_n {
        app.rotate_client_circuits().await?;
        cold.push(app.timed_fetch(0).await);
        if (i + 1) % 10 == 0 {
            println!("  cold {}/{cold_n}", i + 1);
        }
    }
    append_rows(&mut out, "cold", &cold);
    report("cold (NEWNYM before each), single stream", &cold);
    let cold_summary = summarize(&cold);

    // --- Arm 2: warm. Back-to-back fetches to one persona with no signal in
    // between, so the client tor reuses its rendezvous circuit and only the
    // stream cost is paid — the organic fill scheduler's steady state against
    // one `P`, and the optimistic case.
    let mut warm = Vec::new();
    for i in 0..warm_n {
        warm.push(app.timed_fetch(0).await);
        if (i + 1) % 10 == 0 {
            println!("  warm {}/{warm_n}", i + 1);
        }
    }
    append_rows(&mut out, "warm", &warm);
    report("warm (reused circuit), single stream", &warm);

    // --- Arm 3: the concurrency sweep. At each width, `NEWNYM` once, then
    // `width` cold fetches to `width` distinct personas at once through the
    // one client tor — `width` rendezvous circuits building together on the
    // daemon's tor. The starting persona rotates by round so a width-1 row
    // is not "always persona 0" and a width-8 row is not "the first eight
    // plus whatever was added." (The recorded W₂ pin used the prefix; the
    // N=8 pin already included every persona, so it is not re-run.) This is
    // `SF-D7`'s client-side churn question, and the table it produces is
    // the upper-bound input for `N`. (The serve-side contention datum the
    // old two-persona arm doubled as is gone on purpose: the personas are
    // on separate tors now, and serve-side load is SPIKE-F-11's, measured
    // from other hosts.)
    let mut sweep = Vec::new();
    for width in sweep_widths(personas) {
        let mut at_width = Vec::with_capacity(conc_n * width);
        // The serve-side cap counter *before* this width, so the delta across
        // it is this width's alone. A non-zero delta voids the row.
        let refused_before = app.refused_total();
        for i in 0..conc_n {
            app.rotate_client_circuits().await?;
            // One task per fetch, as a daemon's scheduler would issue them;
            // joined in order so the round's observations land together.
            // Starting persona rotates by round (`sweep_round_indices`).
            let tasks: Vec<_> = sweep_round_indices(i, width, personas)
                .into_iter()
                .map(|p| {
                    let app = Arc::clone(&app);
                    tokio::spawn(async move { app.timed_fetch(p).await })
                })
                .collect();
            for t in tasks {
                at_width.push(t.await?);
            }
            if (i + 1) % 10 == 0 {
                println!("  width {width}: round {}/{conc_n}", i + 1);
            }
        }
        append_rows(&mut out, &format!("conc{width}"), &at_width);
        report(&format!("{width} in flight, cold client"), &at_width);
        let cap_refusals = app.refused_total() - refused_before;
        if cap_refusals != 0 {
            println!(
                "  width {width}: the serve-side cap shed {cap_refusals} connection(s) — \
                 this row is VOID as an N input (the placeholder cap shaped it, not Tor)"
            );
        }
        sweep.push(SweepPoint {
            width,
            observations: at_width,
            cap_refusals,
        });
    }

    // --- Arm 4: the dispersion soak. Circuit-latency dispersion is the
    // load-bearing parameter (§8.3) and it is *time-varying*, so a one-hour
    // sample understates the tail. Runs for SHEKYL_SPIKE_HOURS wall-clock,
    // cold-circuit, spaced out.
    if hours > 0 {
        println!("\nsoak arm: {hours} h of spaced cold fetches...");
        let until = Instant::now() + Duration::from_secs(hours as u64 * 3600);
        let mut soak = Vec::new();
        while Instant::now() < until {
            app.rotate_client_circuits().await?;
            soak.push(app.timed_fetch(0).await);
            // Flush EVERY observation, not every 25th. A 24 h run on a dev box is
            // a run that gets killed, and the doc comment on `append_rows`
            // promises a killed run still leaves what it earned -- a 25-row
            // buffer would make that promise false by up to 24 observations plus
            // the whole summary.
            append_rows(&mut out, "soak", &soak[soak.len() - 1..]);
            if soak.len() % 25 == 0 {
                println!("  soak n={}", soak.len());
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
        report("soak (>=24h target)", &soak);
    }

    // Apparatus cross-check: the endpoints must have served what the client leg
    // believes it fetched. A mismatch means some "success" came from somewhere
    // else, which would invalidate every number above.
    println!("\nendpoints served {} requests total", app.served_total());
    // The run-wide serve-side cap total. Per-width deltas already voided the
    // sweep rows they fell in; this is the whole-run figure for the record,
    // and any count outside the sweep (cold/warm/soak are single-stream, so
    // it should be zero there) is the apparatus disagreeing with itself.
    println!(
        "endpoints shed {} connections at the serve-side cap over the whole run",
        app.refused_total()
    );

    // The two pin inputs this run exists to produce, last so they are what
    // the operator sees at the bottom of the log.
    report_churn(&sweep);
    report_l(&cold_summary);

    let app = Arc::try_unwrap(app).map_err(|_| "a fetch task still holds the apparatus")?;
    app.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::sweep_widths;

    #[test]
    fn sweep_visits_powers_of_two_and_the_top() {
        assert_eq!(sweep_widths(1), vec![1]);
        assert_eq!(sweep_widths(4), vec![1, 2, 4]);
        // A non-power-of-two persona count is still visited at full width,
        // or the sweep would never measure the apparatus it brought up.
        assert_eq!(sweep_widths(6), vec![1, 2, 4, 6]);
        assert_eq!(sweep_widths(8), vec![1, 2, 4, 8]);
    }
}
