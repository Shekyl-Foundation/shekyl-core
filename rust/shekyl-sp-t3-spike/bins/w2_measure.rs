// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The W₂ floor check. **A binary that answers one yes/no, not a derivation.**
//!
//! W₂ is pinned by ruling — `CHALLENGE_RESPONSE_BLOCKS = SETTLEMENT_EPOCH_BLOCKS
//! / W2_EPOCH_DIVISOR`, 500 blocks — and this rig does not re-derive it. It asks
//! the one question a pinned value still owes an answer to: **does the honest
//! concurrent batch fit inside the window with the stated margin?** A pass ends
//! it. A fail raises W₂, which by that ruling costs nothing. So the measurement
//! can only move the constant in the safe direction, which is why it is a check
//! and not a search.
//!
//! ```text
//! SHEKYL_W2_TOR=/path/to/tor \
//! SHEKYL_W2_SHARD=/path/to/shard.bin \
//! SHEKYL_W2_SHAPE=serving|producing \
//! SHEKYL_W2_BATCHES=N SHEKYL_W2_OUT=/path/to/batches.tsv \
//!   cargo run -p shekyl-sp-t3-spike --release --bin w2-measure
//! ```
//!
//! # The shape is required, because the two shapes have different floors
//!
//! `SHEKYL_W2_SHAPE` has no default, deliberately. The rig can express both
//! sides of the fetch and they are measurements of **different machines'
//! problems** (see [`crate::w2`]):
//!
//! - `serving` — one persona, many concurrent readers. This is what a staker's
//!   `P` faces, and rule 76 makes the Pi-4 its floor. **This is the shape to run
//!   on the floor device.**
//! - `producing` — many personas, one client fetching from all of them at once.
//!   This is what a block producer faces when `λ·D/E` pairs land on its block.
//!   Rule 76 names no floor for mining, so this shape yields a capability check
//!   on whatever box ran it — never a floor datum, *including* on a Pi.
//!
//! Defaulting the knob would pick one of those silently, and the wrong pick
//! reads as a completed check rather than as a mislabelled one.
//!
//! The declaration here only selects the apparatus configuration. What lands in
//! the datum is [`MeasuredSide::from_shape`], read off the apparatus that
//! actually ran — a declaration cannot reach the provenance.
//!
//! # What it writes, and what it refuses to write
//!
//! Batch aggregates only, with no ordinal and no wall-clock stamp, following the
//! §6.4 discipline the sibling `pd-f2-measure` binary already keeps: a row is
//! `launched`, `completed`, `batch_ms`, `slowest_ms`.
//!
//! It refuses to print a verdict when [`Apparatus::provenance`] returns `None` —
//! no vanguards, or a consensus too small to be the real network. §9.7 wants an
//! incomplete run to yield **no datum rather than an unlabelled one**, so the
//! run exits non-zero with the reason instead of reporting the timings it
//! collected. The numbers are real; the *claim* is what it cannot make.

use std::path::PathBuf;
use std::time::Duration;

use shekyl_archival_retention::constants::CHALLENGE_RESPONSE_BLOCKS;
use shekyl_economics::EconomicParams;
use shekyl_sp_t3_spike::fixture::ShardFixture;
use shekyl_sp_t3_spike::harness::Apparatus;
use shekyl_sp_t3_spike::w2::{MeasuredSide, W2Datum};
use shekyl_tor::control::onion::OnionPow;
use shekyl_tor::vanguard_rotation::VanguardsMode;

/// Margin the floor check demands over the window.
///
/// Two orders, which is the margin `W2_MIN_DEFENSIBLE_BLOCKS`'s own derivation
/// cites for the pinned 500 blocks ("500 blocks is ≈16.7 h — two orders of
/// margin"). Asking the rig for the same margin the constant was chosen to carry
/// is what makes a pass mean "the ruling holds" rather than "it fit, barely".
const FLOOR_CHECK_MARGIN: u32 = 100;

/// Concurrent readers in the `serving` shape.
///
/// 32 is the top of the range `SP_T3_SKELETON_MEASUREMENT.md` §18 already
/// walked (4→32, p50 10.9 s → 14.8 s), so a run here is directly comparable to
/// that record instead of starting a second, unrelated series.
const DEFAULT_SERVING_READERS: usize = 32;

/// Concurrent pairs in the `producing` shape.
///
/// ~97 is §9.5's maturity figure: the schedule assigns `λ·D/E` pairs to each
/// block's producer, and at maturity that is ~97 landing on one block at once.
const DEFAULT_PRODUCING_PAIRS: usize = 97;

fn env_path(key: &str) -> Option<PathBuf> {
    std::env::var_os(key).map(PathBuf::from)
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// The apparatus configuration a shape selects: how many personas to publish,
/// and how wide each batch is.
struct Shape {
    personas: u32,
    batch: usize,
}

fn shape_from_env() -> Result<Shape, String> {
    match std::env::var("SHEKYL_W2_SHAPE").as_deref() {
        Ok("serving") => Ok(Shape {
            // Exactly one, which is what puts every concurrent reader on the
            // same persona's inbound path.
            personas: 1,
            batch: env_usize("SHEKYL_W2_READERS", DEFAULT_SERVING_READERS),
        }),
        Ok("producing") => {
            let pairs = env_usize("SHEKYL_W2_PAIRS", DEFAULT_PRODUCING_PAIRS);
            // One persona per pair by default: a producer fetches from ~97
            // *distinct* personas, and publishing fewer would stack several
            // fetches on each, which is serving-side load contaminating a
            // producer-side number. Overridable, because publishing 97 onions is
            // itself expensive and a smaller run is still worth having — just
            // say so on purpose.
            let personas = env_usize("SHEKYL_W2_PERSONAS", pairs);
            Ok(Shape {
                personas: u32::try_from(personas).map_err(|_| "SHEKYL_W2_PERSONAS too large")?,
                batch: pairs,
            })
        }
        _ => Err(
            "SHEKYL_W2_SHAPE must be `serving` (one persona, many readers — \
                  the rule-76 floor shape) or `producing` (many personas, one \
                  client — a capability check, never a floor datum). There is no \
                  default: the two measure different machines' problems."
                .to_owned(),
        ),
    }
}

/// The W₂ window in wall time: the pinned block count at the consensus block
/// target.
///
/// Both halves come from their owners rather than being re-typed here — the
/// block count from `shekyl-archival-retention`, the target from
/// `shekyl-economics`, which is the same single-sourcing `ServingConfig`'s
/// production constructor does. A local copy of either would let this check keep
/// passing against a window the chain no longer has.
fn w2_window() -> Duration {
    let target = EconomicParams::default().daa_target_seconds;
    Duration::from_secs(CHALLENGE_RESPONSE_BLOCKS.saturating_mul(target))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tor = env_path("SHEKYL_W2_TOR")
        .ok_or("SHEKYL_W2_TOR must point at the pinned Tor Expert Bundle binary")?;
    let shard_path = env_path("SHEKYL_W2_SHARD")
        .ok_or("SHEKYL_W2_SHARD must point at a real extracted shard fixture")?;
    let shape = shape_from_env()?;
    let batches_n = env_usize("SHEKYL_W2_BATCHES", 5);

    let fixture = ShardFixture::load(&shard_path)?;
    let payload_len = fixture.len();
    let window = w2_window();
    println!(
        "W2 window: {CHALLENGE_RESPONSE_BLOCKS} blocks x {} s = {:.1} h",
        EconomicParams::default().daa_target_seconds,
        window.as_secs_f64() / 3600.0,
    );
    println!(
        "shard fixture: {payload_len} bytes; {} personas, batches of {} x {batches_n}",
        shape.personas, shape.batch,
    );

    println!("bringing up tor with full vanguards (bootstrap + guard pin + publication)...");
    let dir = tempfile::tempdir()?;
    let app = Apparatus::bring_up_with(
        tor,
        dir.path().join("tor-data"),
        shape.personas,
        fixture.bytes(),
        // The same default the sibling binary runs, so a W2 batch and a PD-F-2
        // arm are not separated by an inbound-defence difference nobody asked
        // for.
        OnionPow::Disabled,
        VanguardsMode::Managed,
    )
    .await?;

    let publish = app.await_reachable(payload_len).await?;
    println!(
        "personas reachable after {:.1} s (descriptor publication — EXCLUDED from every batch)",
        publish.as_secs_f64(),
    );

    let mut out = env_path("SHEKYL_W2_OUT").and_then(|p| std::fs::File::create(p).ok());
    if let Some(f) = out.as_mut() {
        use std::io::Write as _;
        writeln!(f, "launched\tcompleted\tbatch_ms\tslowest_ms").ok();
    }

    let mut observed = Vec::with_capacity(batches_n);
    for i in 0..batches_n {
        let batch = app.timed_batch(shape.batch, payload_len).await.observe();
        println!(
            "  batch {}/{batches_n}: {}/{} in {:.1} s (slowest fetch {:.1} s)",
            i + 1,
            batch.completed,
            batch.launched,
            batch.batch_completion.as_secs_f64(),
            batch.slowest_fetch.as_secs_f64(),
        );
        if let Some(f) = out.as_mut() {
            use std::io::Write as _;
            // Flushed per batch: a run killed mid-flight still leaves the
            // batches it earned.
            writeln!(
                f,
                "{}\t{}\t{}\t{}",
                batch.launched,
                batch.completed,
                batch.batch_completion.as_millis(),
                batch.slowest_fetch.as_millis(),
            )
            .ok();
            f.flush().ok();
        }
        observed.push(batch);
    }

    println!("\nendpoints served {} requests total", app.served_total());

    // The provenance gate, after the timings are safely on disk and before any
    // verdict is printed: an unattestable run keeps its numbers and loses its
    // claim.
    let provenance = app.provenance(shape.batch);
    app.shutdown().await;
    let Some(provenance) = provenance else {
        return Err(
            "this run cannot attest its provenance (no vanguards witness, or a \
                    consensus too small to be the real Tor network), so it yields no W2 \
                    datum — the batch timings above stand, the floor verdict does not"
                .into(),
        );
    };

    let datum = W2Datum::new(provenance, observed);
    let p = datum.provenance();
    println!("\n=== W2 floor check ===");
    println!("device: {} ({})", p.device().cpu, p.device().arch);
    println!("consensus: {} relays", p.network().relays_seen);
    match p.side() {
        MeasuredSide::Serving { readers } => {
            println!("side: serving — {readers} concurrent readers on one persona");
        }
        MeasuredSide::Producing { pairs } => {
            println!("side: producing — {pairs} concurrent pairs from one client");
        }
    }
    println!(
        "floor datum: {}",
        if p.is_floor_datum() {
            "YES — a rule-76 provisioning input"
        } else {
            "no — a capability check on this machine, not a provisioning input"
        },
    );
    if let Some(worst) = datum.worst_batch_completion() {
        println!("worst batch completion: {:.1} s", worst.as_secs_f64());
    }
    match datum.fits_within(window, FLOOR_CHECK_MARGIN) {
        Some(true) => println!(
            "VERDICT: fits within W2 with {FLOOR_CHECK_MARGIN}x margin — the pinned \
             window holds on this machine for this side"
        ),
        Some(false) => println!(
            "VERDICT: does NOT fit with {FLOOR_CHECK_MARGIN}x margin. By the W2 ruling \
             this costs nothing to fix: raise the window."
        ),
        None => println!(
            "VERDICT: unanswered — a batch did not complete in full, and a run that \
             could not fetch everything is not a fast run"
        ),
    }
    Ok(())
}
