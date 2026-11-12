// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The open-edge measurement: refetching the held buffer, `<= 5 s` absolute.
//!
//! Measured against the **production** fetch path —
//! `DaemonClient::fetch_scannable_block`, which resolves to
//! `engine::block_fetch::fetch_scannable_block_with_form`. A replica would
//! measure a second implementation's round-trip shape, and round-trip shape is
//! the whole subject here (`crate::openedge`).
//!
//! **Scope, per §6.3.4 row 3: this grades the local posture only.** A remote
//! daemon over Tor refetches more slowly and is not graded by the 5 s
//! threshold — a stated scope, not an omission.

use std::process::ExitCode;

use clap::Parser;
use serde::Serialize;
use shekyl_engine_core::engine::daemon::DaemonClient;
use shekyl_rpc_client::{wire, Rpc};
use shekyl_rpc_types::kinds::{Height, NoParams};
use shekyl_rpc_types::wire::block::{BlockSelect, BlockShowSelect};
use shekyl_rpc_types::wire::shared::{OrArchived, Selector};
use shekyl_wss_q1b_bench::corpus::nominal_block_weight;
use shekyl_wss_q1b_bench::openedge::{
    judge_density, project, Attribution, BlockSample, CorpusDensity, Projection, RoundTripFloor,
};
use shekyl_wss_q1b_bench::report::{emit, ProverPin, Verdict, OPEN_EDGE_BUDGET_S, SCHEMA_VERSION};
use shekyl_wss_q1b_bench::rig::{self, Environment, RigVerdict, StorageAttestation};
use shekyl_wss_q1b_bench::timing::duration_s;

/// Round trips `fetch_scannable_block` makes for one block: one
/// `block_show`, whatever the block holds.
const ROUND_TRIPS_PER_BLOCK: u32 = 1;

#[derive(Parser, Debug)]
#[command(
    name = "open_edge",
    about = "WSS-Q1(b) open-edge measurement (WALLET_SIDE_STORE.md §6.3.4 row 3)"
)]
struct Args {
    /// Local daemon base URL.
    #[arg(long, default_value = "http://127.0.0.1:18081")]
    daemon: String,

    /// Blocks to sample. The projection to the full buffer is built from this
    /// sample's per-block distribution.
    #[arg(long, default_value_t = 50)]
    blocks: u64,

    /// Height to start sampling from.
    #[arg(long, default_value_t = 1)]
    from_height: u64,

    /// Minimal round trips to time for the floor. At least one.
    ///
    /// Range-checked by clap rather than at the use site: zero produced an
    /// empty vector that the median then indexed, so a malformed invocation
    /// panicked instead of refusing.
    #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u16).range(1..))]
    floor_samples: u16,

    /// Apply the ruled arithmetic and emit a verdict.
    #[arg(long, default_value_t = false)]
    grade: bool,

    /// Operator attestation for a property the process cannot observe.
    #[arg(long, value_parser = parse_storage)]
    attest_storage: Option<StorageAttestation>,

    /// Operator attestation that the board reached thermal steady state.
    #[arg(long, default_value_t = false)]
    attest_thermal_steady: bool,

    /// Write the JSON record here instead of stdout.
    #[arg(long)]
    json: Option<String>,
}

fn parse_storage(s: &str) -> Result<StorageAttestation, String> {
    match s {
        "usb-ssd" => Ok(StorageAttestation::UsbSsd),
        "microsd" => Ok(StorageAttestation::MicroSd),
        "other" => Ok(StorageAttestation::Other),
        other => Err(format!(
            "unknown storage {other}; expected usb-ssd, microsd or other"
        )),
    }
}

/// A complete open-edge run.
#[derive(Serialize)]
struct OpenEdgeRecord {
    schema_version: u32,
    measurement: &'static str,
    /// §6.3.4 row 3's stated scope.
    posture: &'static str,
    environment: Environment,
    rig: RigVerdict,
    build_pin: ProverPin,
    projection: Projection,
    round_trip_floor: RoundTripFloor,
    /// The density the budget is graded at, and whether the sample reached it.
    density: CorpusDensity,
    /// Why grading was withheld, when it was.
    ungraded_because: Option<&'static str>,
    threshold_s: f64,
    verdict: Verdict,
    /// Which remedy a miss fires — the §6.3.4 row 3 amendment.
    miss_response: &'static str,
    /// How round trips were counted.
    round_trip_accounting: &'static str,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    let environment = Environment::capture();
    let rig_verdict = match rig::decide(
        &environment,
        args.grade,
        args.attest_storage,
        args.attest_thermal_steady,
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };

    // §6.3.4 row 3's budget is defined for the LOCAL posture, and the record
    // hard-codes that string. Grading a remote daemon against a local budget
    // is a category error, not a slow run: the verdict would be incomparable
    // with every other graded run while claiming to be one of them.
    if rig_verdict.grading && !rig::is_loopback_endpoint(&args.daemon) {
        eprintln!(
            "refusing to grade: {} is not a loopback daemon, and the 5 s budget grades the \
             local posture only (§6.3.4 row 3). Measure without --grade instead.",
            args.daemon
        );
        return ExitCode::from(2);
    }

    let inner = match shekyl_rpc_transport::HttpRpc::new(args.daemon.clone()).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("could not reach {}: {e}", args.daemon);
            return ExitCode::from(4);
        }
    };
    let client = DaemonClient::new(inner);

    // ── The round-trip floor ────────────────────────────────────────────
    //
    // Measured directly rather than regressed out of the block samples: round
    // trips per block are nearly constant, so a fit over them is
    // under-determined.
    // `chain_height`: a minimal JSON-RPC body, TYPED, so a refusal is an
    // error and never a timed sample. Timing a refused call is not timing a
    // round trip, and this figure decides an attribution.
    eprintln!("── timing {} minimal round trips ──", args.floor_samples);
    let floor_sample_count = usize::from(args.floor_samples);
    let mut floor_samples = Vec::with_capacity(floor_sample_count);
    for _ in 0..floor_sample_count {
        let start = std::time::Instant::now();
        let res = client.call::<wire::ChainHeight>(NoParams).await;
        let elapsed = duration_s(start.elapsed());
        if let Err(e) = res {
            eprintln!("floor probe failed: {e}");
            return ExitCode::from(4);
        }
        floor_samples.push(elapsed);
    }
    floor_samples.sort_by(|a, b| a.partial_cmp(b).expect("timings are never NaN"));
    let floor = RoundTripFloor {
        median_s: floor_samples[floor_samples.len() / 2],
        samples: floor_samples.len(),
    };
    eprintln!("   floor {:.4} s per round trip", floor.median_s);

    // ── The per-block distribution ──────────────────────────────────────
    eprintln!(
        "── fetching {} blocks from {} ──",
        args.blocks, args.from_height
    );
    let mut samples = Vec::with_capacity(args.blocks as usize);
    for offset in 0..args.blocks {
        let height = args.from_height + offset;
        let start = std::time::Instant::now();
        let block = match client.fetch_scannable_block(height as usize).await {
            Ok(b) => b,
            Err(e) => {
                eprintln!("fetch at height {height} failed: {e}");
                return ExitCode::from(4);
            }
        };
        let seconds = duration_s(start.elapsed());

        // Round trips are counted analytically, because the production fetch
        // exposes no counter. The accounting is recorded in the output so a
        // reader can check it against `block_fetch.rs` rather than trust it.
        drop(block);
        let round_trips = ROUND_TRIPS_PER_BLOCK;

        // Byte accounting rides a SEPARATE, untimed `block_show`: the production
        // fetch returns parsed types, not the bytes it received, and
        // instrumenting the timed path would change what is being timed.
        //
        // A failure here is REFUSED rather than recorded as zero bytes. Zero is
        // a legitimate-looking sample that drags the measured density down,
        // which both understates the volume term and pushes the attribution
        // toward round-trip bound -- an error conflated with a measurement.
        let (wire_bytes, decoded_bytes) = match measure_bytes(&client, height).await {
            Ok(b) => b,
            Err(e) => {
                eprintln!("byte accounting failed at height {height}: {e}");
                return ExitCode::from(4);
            }
        };

        samples.push(BlockSample {
            height,
            round_trips,
            wire_bytes,
            decoded_bytes,
            seconds,
        });
    }

    let projection = project(&samples, floor);
    let density = judge_density(&samples, nominal_block_weight());
    // Two independent reasons to withhold a verdict, reported separately: the
    // wrong machine, and a corpus too thin for the budget to bite. A pass over
    // coinbase-only blocks would be a pass for the wrong reason.
    let (verdict, ungraded_because) = if !rig_verdict.grading {
        (
            Verdict::Ungraded,
            Some("not the pinned rig, or --grade not given"),
        )
    } else if !density.sufficient {
        (
            Verdict::Ungraded,
            Some("the sampled blocks are below the graded density -- this corpus cannot fail"),
        )
    } else if projection.projected_s <= OPEN_EDGE_BUDGET_S {
        (Verdict::Pass, None)
    } else {
        (Verdict::Miss, None)
    };

    let miss_response = match projection.attribution {
        Attribution::RoundTripBound => {
            "round-trip bound: a miss fires bulk/pipelined fetch, NOT the companion file"
        }
        Attribution::VolumeBound => {
            "volume bound: a miss fires §6.3.4 row 3's companion file as pre-registered"
        }
        Attribution::Mixed => {
            "neither term dominates: a miss is attributed by the maintainer, not here"
        }
        Attribution::Inconsistent => {
            "the per-round-trip floor does not fit inside the measured cost: the two \
             instruments disagree, so NO remedy follows from this run -- fix the floor \
             measurement and re-run before attributing a miss"
        }
    };

    let record = OpenEdgeRecord {
        schema_version: SCHEMA_VERSION,
        measurement: "wss-q1b-open-edge",
        posture: "local daemon (§6.3.4 row 3 grades this posture only; remote/Tor is out of scope)",
        environment,
        rig: rig_verdict,
        build_pin: ProverPin::capture(),
        projection,
        round_trip_floor: floor,
        density,
        ungraded_because,
        threshold_s: OPEN_EDGE_BUDGET_S,
        verdict,
        miss_response,
        round_trip_accounting: "per block: block_show under prune (1), awaited \
                                in block_fetch.rs",
    };

    // The write failure is an error, not a warning: an explicitly requested
    // artifact that silently fails to appear leaves a pass or miss with no
    // evidence behind it. `emit` is the one home for that rule (report.rs).
    let write_failed = emit(&record, args.json.as_deref())
        .map_err(|e| eprintln!("{e}"))
        .is_err();
    summarize(&record);
    if write_failed {
        return ExitCode::from(5);
    }

    match record.verdict {
        Verdict::Miss => ExitCode::from(1),
        Verdict::Pass | Verdict::Ungraded => ExitCode::SUCCESS,
    }
}

/// Wire bytes for one block: **the block's bytes plus its transactions'
/// bodies**, in the pruned form the production fetch requests, read through
/// the shared `block_show` type, so a renamed member fails this compile the
/// same way it fails the wallet instead of reporting zero bytes.
///
/// Every body arrives base64-encoded, so the wire figure is the encoded
/// length of each and the decoded figure the bytes themselves.
async fn measure_bytes(client: &DaemonClient, height: u64) -> Result<(u64, u64), String> {
    let block = client
        .call::<wire::BlockShow>(BlockShowSelect(BlockSelect {
            select: Selector::Height(Height(height)),
            pow: false,
            prune: Some(true),
        }))
        .await
        .map_err(|e| format!("block_show: {e}"))?;
    let base64_len = |n: usize| (n.div_ceil(3) * 4) as u64;
    let mut wire = base64_len(block.body.0.len());
    let mut decoded = block.body.0.len() as u64;
    for slot in &block.tx {
        let OrArchived::Item(tx) = slot else {
            return Err("a pruned block_show answered an archived slot".to_string());
        };
        wire += base64_len(tx.body.0.len());
        decoded += tx.body.0.len() as u64;
    }
    Ok((wire, decoded))
}

fn summarize(record: &OpenEdgeRecord) {
    let p = &record.projection;
    eprintln!();
    eprintln!("── WSS-Q1(b) open edge ──");
    eprintln!("  posture        local daemon");
    eprintln!("  sampled        {} blocks", p.blocks_measured);
    eprintln!(
        "  per block      median {:.4} s, p95 {:.4} s",
        p.per_block_median_s, p.per_block_p95_s
    );
    eprintln!(
        "  projected      {} blocks, {} round trips",
        p.blocks_projected, p.projected_round_trips
    );
    eprintln!(
        "  bytes          {} wire (base64), {} decoded",
        p.projected_wire_bytes, p.projected_decoded_bytes
    );
    eprintln!(
        "  REFETCH        {:.3} s  (threshold {:.1} s)",
        p.projected_s, record.threshold_s
    );
    eprintln!(
        "  attribution    {:?}  — round trips {:.3} s, volume {:.3} s",
        p.attribution, p.round_trip_term_s, p.volume_term_s
    );
    if record.projection.floor_exceeds_total {
        eprintln!(
            "  WARNING        the round-trip floor ({:.6} s x {}) exceeds the whole projection: \
             the floor probe and the per-block timings disagree",
            record.round_trip_floor.median_s, record.projection.projected_round_trips
        );
    }
    eprintln!("  miss response  {}", record.miss_response);
    eprintln!(
        "  density        {} B/block measured vs {} graded ({:.1} % -- {})",
        record.density.measured_bytes_per_block,
        record.density.graded_at_weight,
        record.density.fraction_of_graded * 100.0,
        if record.density.sufficient {
            "sufficient"
        } else {
            "TOO THIN TO GRADE"
        }
    );
    eprintln!("  VERDICT        {:?}", record.verdict);
    if let Some(why) = record.ungraded_because {
        eprintln!("                 {why}");
    }
}
