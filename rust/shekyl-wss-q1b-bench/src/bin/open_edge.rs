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
use shekyl_rpc_client::Rpc;
use shekyl_wss_q1b_bench::openedge::{
    project, Attribution, BlockSample, Projection, RoundTripFloor,
};
use shekyl_wss_q1b_bench::report::{ProverPin, Verdict, OPEN_EDGE_BUDGET_S, SCHEMA_VERSION};
use shekyl_wss_q1b_bench::rig::{self, Environment, RigVerdict, StorageAttestation};
use shekyl_wss_q1b_bench::timing::duration_s;

/// Round trips `fetch_scannable_block` makes for a block with no non-miner
/// transactions: `get_block` + `get_o_indexes`.
const ROUND_TRIPS_EMPTY_BLOCK: u32 = 2;
/// Transactions per `get_transactions` call — `block_fetch::TXS_PER_REQUEST`.
const TXS_PER_REQUEST: usize = 100;

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

    /// Minimal round trips to time for the floor.
    #[arg(long, default_value_t = 50)]
    floor_samples: usize,

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
    eprintln!("── timing {} minimal round trips ──", args.floor_samples);
    let mut floor_samples = Vec::with_capacity(args.floor_samples);
    for _ in 0..args.floor_samples {
        let start = std::time::Instant::now();
        let res: Result<serde_json::Value, _> = client.json_rpc_call("get_info", None).await;
        if let Err(e) = res {
            eprintln!("floor probe failed: {e}");
            return ExitCode::from(4);
        }
        floor_samples.push(duration_s(start.elapsed()));
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

        // Round trips are counted analytically from the block's shape, because
        // the production fetch exposes no counter. The accounting is recorded
        // in the output so a reader can check it against `block_fetch.rs`
        // rather than trust it.
        let tx_count = block.block.transaction_hashes.len();
        let tx_calls = tx_count.div_ceil(TXS_PER_REQUEST) as u32;
        let round_trips = ROUND_TRIPS_EMPTY_BLOCK + tx_calls;

        // Byte accounting rides a SEPARATE, untimed `get_block`: the production
        // fetch returns parsed types, not the bytes it received, and
        // instrumenting the timed path would change what is being timed.
        let (wire_hex_bytes, decoded_bytes) = measure_bytes(&client, height).await;

        samples.push(BlockSample {
            height,
            round_trips,
            wire_hex_bytes,
            decoded_bytes,
            seconds,
        });
    }

    let projection = project(&samples, floor);
    let verdict = if !rig_verdict.grading {
        Verdict::Ungraded
    } else if projection.projected_s <= OPEN_EDGE_BUDGET_S {
        Verdict::Pass
    } else {
        Verdict::Miss
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
        threshold_s: OPEN_EDGE_BUDGET_S,
        verdict,
        miss_response,
        round_trip_accounting: "per block: get_block (1) + get_transactions \
                                (ceil(tx_count / 100)) + get_o_indexes (1), all \
                                sequentially awaited in block_fetch.rs",
    };

    let json = serde_json::to_string_pretty(&record).expect("record serializes");
    match args.json.as_deref() {
        Some(p) => {
            if let Err(e) = std::fs::write(p, &json) {
                eprintln!("could not write {p}: {e}");
            }
        }
        None => println!("{json}"),
    }
    summarize(&record);

    match record.verdict {
        Verdict::Miss => ExitCode::from(1),
        Verdict::Pass | Verdict::Ungraded => ExitCode::SUCCESS,
    }
}

async fn measure_bytes(client: &DaemonClient, height: u64) -> (u64, u64) {
    let params = serde_json::json!({ "hash": "", "height": height, "fill_pow_hash": false });
    let res: Result<serde_json::Value, _> = client.json_rpc_call("get_block", Some(params)).await;
    let Ok(value) = res else { return (0, 0) };
    let hex_len = value
        .get("blob")
        .and_then(serde_json::Value::as_str)
        .map_or(0, str::len) as u64;
    // The blob arrives hex-encoded, so the decoded size is half the wire size.
    // Reporting one figure for both would understate the wire by half.
    (hex_len, hex_len / 2)
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
        "  bytes          {} wire (hex), {} decoded",
        p.projected_wire_hex_bytes, p.projected_decoded_bytes
    );
    eprintln!(
        "  REFETCH        {:.3} s  (threshold {:.1} s)",
        p.projected_s, record.threshold_s
    );
    eprintln!(
        "  attribution    {:?}  — round trips {:.3} s, volume {:.3} s",
        p.attribution, p.round_trip_term_s, p.volume_term_s
    );
    eprintln!("  miss response  {}", record.miss_response);
    eprintln!("  VERDICT        {:?}", record.verdict);
}
