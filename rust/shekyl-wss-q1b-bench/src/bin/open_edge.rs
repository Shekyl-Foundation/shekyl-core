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
use shekyl_rpc_types::{
    GetBlockRequest, GetBlockResponse, GetTransactionsRequest, GetTransactionsResponse,
};
use shekyl_wss_q1b_bench::corpus::nominal_block_weight;
use shekyl_wss_q1b_bench::openedge::{
    judge_density, project, Attribution, BlockSample, CorpusDensity, Projection, RoundTripFloor,
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
    eprintln!("── timing {} minimal round trips ──", args.floor_samples);
    let floor_sample_count = usize::from(args.floor_samples);
    let mut floor_samples = Vec::with_capacity(floor_sample_count);
    for _ in 0..floor_sample_count {
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
        //
        // A failure here is REFUSED rather than recorded as zero bytes. Zero is
        // a legitimate-looking sample that drags the measured density down,
        // which both understates the volume term and pushes the attribution
        // toward round-trip bound -- an error conflated with a measurement.
        let (wire_hex_bytes, decoded_bytes) = match measure_bytes(&client, height).await {
            Ok(b) => b,
            Err(e) => {
                eprintln!("byte accounting failed at height {height}: {e}");
                return ExitCode::from(4);
            }
        };

        samples.push(BlockSample {
            height,
            round_trips,
            wire_hex_bytes,
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
        round_trip_accounting: "per block: get_block (1) + get_transactions \
                                (ceil(tx_count / 100)) + get_o_indexes (1), all \
                                sequentially awaited in block_fetch.rs",
    };

    // An explicitly requested artifact that silently fails to appear leaves a
    // pass or miss with no evidence behind it, which is worse than no run.
    let write_failed = match serde_json::to_string_pretty(&record) {
        Ok(json) => match args.json.as_deref() {
            Some(p) => std::fs::write(p, &json)
                .map_err(|e| eprintln!("could not write {p}: {e}"))
                .is_err(),
            None => {
                println!("{json}");
                false
            }
        },
        Err(e) => {
            eprintln!("could not serialize the record: {e}");
            true
        }
    };
    summarize(&record);
    if write_failed {
        return ExitCode::from(5);
    }

    match record.verdict {
        Verdict::Miss => ExitCode::from(1),
        Verdict::Pass | Verdict::Ungraded => ExitCode::SUCCESS,
    }
}

/// Wire bytes for one block, through the **shared** request/response types.
///
/// `GetBlockRequest` / `GetBlockResponse` are the same types `block_fetch.rs`
/// deserializes, for the reason its own comment gives: a hand-rolled params
/// object and a walk over an untyped reply are *"two definitions of one shape,
/// and the one the daemon cannot see is the one that drifts."* A renamed field
/// then fails this compile the same way it fails the wallet, instead of
/// silently reporting zero bytes.
/// Wire bytes for one block: **the block blob plus the non-miner transaction
/// bodies**, in the pruned form the production fetch requests.
///
/// The first version counted only the `get_block` blob. That blob carries the
/// miner transaction and the *hashes* of the non-miner ones — the bodies come
/// separately, through `get_transactions` (`block_fetch.rs`). So a
/// transaction-filled block still measured thin, which is not a cosmetic
/// undercount: **the density gate reads this figure**, so it could never have
/// recognised the 300 kB corpus it exists to require, and the volume term it
/// feeds was understated at the same time.
///
/// `prune: true` matches `TxBodyForm::Pruned`, which is what
/// `default_fetch_scannable_block` asks for — measuring the unpruned form
/// would count bytes the timed path never moves.
async fn measure_bytes(client: &DaemonClient, height: u64) -> Result<(u64, u64), String> {
    let request = GetBlockRequest {
        hash: String::new(),
        height,
        fill_pow_hash: false,
    };
    let params = serde_json::to_value(request).map_err(|e| format!("encode request: {e}"))?;
    let response: GetBlockResponse = client
        .json_rpc_call("get_block", Some(params))
        .await
        .map_err(|e| format!("get_block: {e}"))?;
    let mut hex_len = response.blob.len() as u64;

    let block = shekyl_wire::Block::from_bytes(
        &hex::decode(&response.blob).map_err(|e| format!("block blob is not hex: {e}"))?,
    )
    .map_err(|_| "block blob did not parse".to_string())?;
    let hashes: Vec<String> = block.transaction_hashes.iter().map(hex::encode).collect();
    if !hashes.is_empty() {
        let req = GetTransactionsRequest {
            txs_hashes: hashes,
            decode_as_json: false,
            prune: true,
            split: false,
        };
        let params = serde_json::to_value(req).map_err(|e| format!("encode tx request: {e}"))?;
        let txs: GetTransactionsResponse = client
            .rpc_call("get_transactions", Some(params))
            .await
            .map_err(|e| format!("get_transactions: {e}"))?;
        for entry in &txs.txs {
            // The pruned body is what the timed fetch moves; `as_hex` carries
            // the whole transaction and would overcount by the prunable region.
            hex_len += entry.pruned_as_hex.len() as u64;
        }
    }

    // Everything above arrives hex-encoded, so the decoded size is half the
    // wire size. Reporting one figure for both would understate the wire by
    // half.
    Ok((hex_len, hex_len / 2))
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
