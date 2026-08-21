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
//! SHEKYL_SPIKE_COLD=N SHEKYL_SPIKE_WARM=N SHEKYL_SPIKE_CONC=N \
//! SHEKYL_SPIKE_HOURS=H \
//!   cargo run -p shekyl-sp-t3-spike --release --bin pd-f2-measure
//! ```
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
use std::time::{Duration, Instant};

use shekyl_sp_t3_spike::fixture::ShardFixture;
use shekyl_sp_t3_spike::harness::{cold_client_id, warm_client_id, Apparatus};
use shekyl_sp_t3_spike::measure::{
    summarize, warmup_drift, DStar, FailureKind, Observation, Q_RISK_STAR,
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
            Some(FailureKind::Transport) => "transport",
        };
        // arm, elapsed_ms, outcome. Nothing else — see the module doc.
        writeln!(f, "{arm}\t{}\t{outcome}", o.elapsed.as_millis()).ok();
    }
    f.flush().ok();
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
    let cold_n = env_usize("SHEKYL_SPIKE_COLD", 100);
    let warm_n = env_usize("SHEKYL_SPIKE_WARM", 100);
    let conc_n = env_usize("SHEKYL_SPIKE_CONC", 50);
    let hours = env_usize("SHEKYL_SPIKE_HOURS", 0);

    // Loud, first: no synthetic fallback exists, so a missing fixture stops the
    // run here rather than producing a number about the wrong payload.
    let fixture = ShardFixture::load(&shard_path)?;
    println!("shard fixture: {} bytes", fixture.len());

    let dir = tempfile::tempdir()?;
    println!("bringing up 2 personas behind one tor (this includes a bootstrap)...");
    let app = Apparatus::bring_up(tor, dir.path().join("tor-data"), 2, fixture.bytes()).await?;

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
        "personas reachable after {:.1} s (descriptor publication — EXCLUDED from every arm)",
        publish.as_secs_f64()
    );

    let mut out = env_path("SHEKYL_SPIKE_OUT").and_then(|p| std::fs::File::create(p).ok());
    if let Some(f) = out.as_mut() {
        use std::io::Write as _;
        writeln!(f, "arm\telapsed_ms\toutcome").ok();
    }

    // --- Arm 1: cold circuit, single stream. A fresh client id per fetch, so
    // circuit build + rendezvous are inside the timed path (§6.2). This is the
    // faithful model of a drawn miner and is expected to dominate the tail.
    let mut cold = Vec::new();
    for i in 0..cold_n {
        cold.push(app.timed_fetch(&cold_client_id(i as u64), 0).await);
        if (i + 1) % 10 == 0 {
            println!("  cold {}/{cold_n}", i + 1);
        }
    }
    append_rows(&mut out, "cold", &cold);
    report("cold circuit, single stream", &cold);

    // --- Arm 2: warm circuit. One reused client id, so tor reuses the circuit
    // and only the rendezvous/stream cost is paid — the optimistic case.
    let warm_id = warm_client_id();
    let mut warm = Vec::new();
    for i in 0..warm_n {
        warm.push(app.timed_fetch(&warm_id, 0).await);
        if (i + 1) % 10 == 0 {
            println!("  warm {}/{warm_n}", i + 1);
        }
    }
    append_rows(&mut out, "warm", &warm);
    report("warm circuit, single stream", &warm);

    // --- Arm 3: two personas served concurrently. Doubles as the §5.2 contention
    // datum: if serving A degrades B, it shows up as a widened tail here relative
    // to the cold arm.
    let mut conc = Vec::new();
    for i in 0..conc_n {
        let id_a = cold_client_id(1_000_000 + i as u64);
        let id_b = cold_client_id(2_000_000 + i as u64);
        let (ra, rb) = tokio::join!(app.timed_fetch(&id_a, 0), app.timed_fetch(&id_b, 1));
        conc.push(ra);
        conc.push(rb);
        if (i + 1) % 10 == 0 {
            println!("  concurrent {}/{conc_n}", i + 1);
        }
    }
    append_rows(&mut out, "concurrent", &conc);
    report("2 personas concurrent", &conc);

    // --- Arm 4: the dispersion soak. Circuit-latency dispersion is the
    // load-bearing parameter (§8.3) and it is *time-varying*, so a one-hour
    // sample understates the tail. Runs for SHEKYL_SPIKE_HOURS wall-clock,
    // cold-circuit, spaced out.
    if hours > 0 {
        println!("\nsoak arm: {hours} h of spaced cold fetches...");
        let until = Instant::now() + Duration::from_secs(hours as u64 * 3600);
        let mut soak = Vec::new();
        let mut seq = 5_000_000u64;
        while Instant::now() < until {
            soak.push(app.timed_fetch(&cold_client_id(seq), 0).await);
            seq += 1;
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

    app.shutdown().await;
    Ok(())
}
