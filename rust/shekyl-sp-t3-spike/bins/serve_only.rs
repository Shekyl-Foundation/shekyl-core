// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SPIKE-F-11 service side — publish **one** persona and hold, so readers on
//! other hosts can measure it.
//!
//! ```text
//! SHEKYL_SPIKE_TOR=/path/to/pinned/tor \
//! SHEKYL_SPIKE_SHARD=/path/to/shard.bin \
//! SHEKYL_SPIKE_POW=off|on|tuned:<rate>:<burst> \
//!   cargo run -p shekyl-sp-t3-spike --release --bin serve-only
//! ```
//!
//! # Why a separate binary from `pd-f2-measure`
//!
//! `pd-f2-measure` is client **and** server in one process on one host: it
//! measures its own service, so at high concurrency it measures the box rather
//! than the persona. That confound is the reason SPIKE-F-11 could not simply be
//! another arm there (§12.0d).
//!
//! This binary is the server half only. The readers live on separate hosts, so
//! the client load is not competing with the service for the same cores, and the
//! measured latency is transport plus service rather than transport plus
//! self-contention.
//!
//! # `persona_count = 1`, always
//!
//! One persona on the wire is the conformant shape
//! (`ARCHIVAL_BOND_CONSTRUCTION.md:667` — many held, one serving). SPIKE-F-11 is
//! about **one persona's readers**, not about co-serving, which is exactly the
//! variable the withdrawn concurrency arm confused.

use std::path::PathBuf;
use std::time::Duration;

use shekyl_sp_t3_spike::fixture::ShardFixture;
use shekyl_sp_t3_spike::harness::Apparatus;
use shekyl_tor::control::onion::OnionPow;

fn env_path(key: &str) -> Option<PathBuf> {
    std::env::var_os(key).map(PathBuf::from)
}

/// Parse `SHEKYL_SPIKE_POW`: `off`, `on`, or `tuned:<rate>:<burst>`.
///
/// An unrecognised value is a hard error rather than a silent fall-back to
/// `off` — the PoW arm and the no-PoW arm are the whole point of this run, and a
/// typo that quietly disabled the defense would produce a labelled-wrong dataset.
fn parse_pow(raw: &str) -> Result<OnionPow, String> {
    match raw {
        "off" => Ok(OnionPow::Disabled),
        "on" => Ok(OnionPow::Enabled),
        other => {
            let mut parts = other.split(':');
            match (parts.next(), parts.next(), parts.next(), parts.next()) {
                (Some("tuned"), Some(r), Some(b), None) => {
                    let queue_rate = r.parse().map_err(|_| format!("bad rate {r:?}"))?;
                    let queue_burst = b.parse().map_err(|_| format!("bad burst {b:?}"))?;
                    Ok(OnionPow::EnabledTuned {
                        queue_rate,
                        queue_burst,
                    })
                }
                _ => Err(format!(
                    "SHEKYL_SPIKE_POW={other:?} is not off | on | tuned:<rate>:<burst>"
                )),
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tor = env_path("SHEKYL_SPIKE_TOR").ok_or("SHEKYL_SPIKE_TOR must be set")?;
    let shard = env_path("SHEKYL_SPIKE_SHARD").ok_or("SHEKYL_SPIKE_SHARD must be set")?;
    let pow = parse_pow(&std::env::var("SHEKYL_SPIKE_POW").unwrap_or_else(|_| "off".to_owned()))?;

    // No synthetic fallback, same as the measurement binary.
    let fixture = ShardFixture::load(&shard)?;
    let len = fixture.len();
    eprintln!("shard fixture: {len} bytes");
    eprintln!("pow: {pow:?}");

    let dir = tempfile::tempdir()?;
    eprintln!("bringing up 1 persona (conformant shape) behind one tor...");
    let app =
        Apparatus::bring_up_with_pow(tor, dir.path().join("tor-data"), 1, fixture.bytes(), pow)
            .await?;

    let publish = app.await_reachable().await?;
    let persona = &app.personas[0];

    // The address readers dial. This is the one place a service id is printed on
    // purpose: the operator needs it to drive remote readers, and this is a
    // disposable spike rig, not the wallet.
    println!("ONION={}", persona.service_id().hostname());
    println!("URL={}", persona.shard_url(0));
    println!("PAYLOAD_BYTES={len}");
    // The number a remote reader should compare a fetched body against. Not
    // PAYLOAD_BYTES: since RF-D4 the body leads with a frame header, and the
    // apparatus derives the framed length through the production contract.
    println!("BODY_BYTES={}", app.expected_body_len());
    eprintln!(
        "reachable after {:.1} s; holding. Ctrl-C to stop.",
        publish.as_secs_f64()
    );

    // Aggregate-only heartbeat: served / refused. No per-request structure, no
    // peer, no timing — the client side is where this run is timed anyway.
    let mut last = (0u64, 0u64);
    loop {
        tokio::time::sleep(Duration::from_secs(15)).await;
        let now = (app.served_total(), app.refused_total());
        if now != last {
            eprintln!("served={} refused={}", now.0, now.1);
            last = now;
        }
    }
}
