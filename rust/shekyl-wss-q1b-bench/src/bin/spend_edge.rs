// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The spend-edge measurement: `delta <= max(2 s, 15 % of proving time)`.
//!
//! Measures, in one run on one machine (§6.3.4: *"same rig, same run, same
//! canonical tx shape"*):
//!
//! - **delta** — the state copy at `F`, the buffer replay, the path read-off
//!   and `Path` construction;
//! - **the denominator** — the prover invocation alone.
//!
//! Proof serialization is charged to neither, which is why the prover is called
//! directly rather than through `sign_transaction`.

use std::process::ExitCode;

use clap::Parser;
use shekyl_wss_q1b_bench::corpus::{
    worst_case_leaves_per_block, CANONICAL_INPUTS, CANONICAL_OUTPUTS, HELD_BUFFER_BLOCKS,
    REPLAY_WINDOW_BLOCKS,
};
use shekyl_wss_q1b_bench::fixture::{
    build_corpus, prove_inputs, prove_only, read_off_path, replay, synth_sparse_path,
    ControlExperiment, Path,
};
use shekyl_wss_q1b_bench::report::{
    ProverPin, SpendBudget, SpendCorpus, SpendEdgeRecord, Verdict, SCHEMA_VERSION,
};
use shekyl_wss_q1b_bench::rig::{self, Environment, StorageAttestation};
use shekyl_wss_q1b_bench::timing::{sustained, DEFAULT_TOLERANCE_PCT};

/// Divergence at which the sparse path stops being a stand-in for a dense one.
const CONTROL_TOLERANCE_PCT: f64 = 10.0;

#[derive(Parser, Debug)]
#[command(
    name = "spend_edge",
    about = "WSS-Q1(b) spend-edge measurement (WALLET_SIDE_STORE.md §6.3.4 row 2)"
)]
struct Args {
    /// Tree depth the denominator is proved at. §6.3.2 row 4 puts the
    /// production target at ~6 layers.
    #[arg(long, default_value_t = 6)]
    depth: u8,

    /// Depth the sparse-versus-dense control runs at. Must be a depth whose
    /// dense corpus is cheap to build.
    #[arg(long, default_value_t = 4)]
    control_depth: u8,

    /// Leaves to replay. Defaults to the worst-case window at `--depth`.
    #[arg(long)]
    window_leaves: Option<u64>,

    /// Warm-up iterations discarded before timing.
    #[arg(long, default_value_t = 2)]
    warmup: usize,

    /// Apply the ruled arithmetic and emit a verdict. Refused off the pinned
    /// rig.
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

fn main() -> ExitCode {
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
            // The grading-mode refusal. Measurement remains available; only the
            // verdict is gated.
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };

    let leaf_rate = worst_case_leaves_per_block(args.depth);
    let window_leaves = args
        .window_leaves
        .unwrap_or(leaf_rate.leaves_per_block * REPLAY_WINDOW_BLOCKS);

    eprintln!(
        "── control: sparse vs dense at depth {} ──",
        args.control_depth
    );
    let control = run_control(args.control_depth);
    if !control.both_verified {
        eprintln!("control arms did not both verify; refusing to report a denominator");
        return ExitCode::from(3);
    }
    let sparse_licensed = control.sparse_equals_dense;
    eprintln!(
        "   dense {:.3} s vs sparse {:.3} s ({:+.1} %) -> sparse {}",
        control.dense_s,
        control.sparse_s,
        control.divergence_pct,
        if sparse_licensed {
            "licensed"
        } else {
            "REFUSED"
        }
    );

    eprintln!("── corpus: {window_leaves} leaves over {REPLAY_WINDOW_BLOCKS} blocks ──");
    let corpus = build_corpus(window_leaves, 0x5A);

    // ── delta, part 1: the buffer replay ────────────────────────────────
    let replay_series = sustained(args.warmup, DEFAULT_TOLERANCE_PCT, || {
        std::hint::black_box(replay(&corpus));
    });

    // ── delta, part 2: path read-off and `Path` construction ────────────
    let layers = replay(&corpus);
    let path_series = sustained(args.warmup, DEFAULT_TOLERANCE_PCT, || {
        let p = read_off_path(&layers, corpus.spent_index);
        std::hint::black_box(prove_inputs(&corpus, &p, CANONICAL_INPUTS));
    });

    // ── the denominator: the prover invocation, nothing else ────────────
    let graded_path: Path = if sparse_licensed {
        synth_sparse_path(&corpus, args.depth)
    } else {
        read_off_path(&layers, corpus.spent_index)
    };
    let inputs = prove_inputs(&corpus, &graded_path, CANONICAL_INPUTS);
    let mut proof_ok = true;
    let prove_series = sustained(
        args.warmup.min(1),
        DEFAULT_TOLERANCE_PCT,
        || match prove_only(&inputs, &graded_path, [0xA5; 32]) {
            Ok(r) => {
                // Keep the proof bytes alive past the timer so the optimizer
                // cannot elide the work the denominator is defined as.
                std::hint::black_box(&r);
            }
            Err(e) => {
                eprintln!("prove failed: {e}");
                proof_ok = false;
            }
        },
    );

    let delta_s = replay_series.graded_s() + path_series.graded_s();
    let budget = SpendBudget::grade(delta_s, prove_series.graded_s(), rig_verdict.grading);

    let record = SpendEdgeRecord {
        schema_version: SCHEMA_VERSION,
        measurement: "wss-q1b-spend-edge",
        environment,
        rig: rig_verdict,
        prover_pin: ProverPin::capture(),
        corpus: SpendCorpus {
            replay_window_blocks: REPLAY_WINDOW_BLOCKS,
            held_buffer_blocks: HELD_BUFFER_BLOCKS,
            leaf_rate,
            window_leaves,
            tree_depth: graded_path.tree_depth,
            canonical_shape: if CANONICAL_INPUTS == 2 && CANONICAL_OUTPUTS == 2 {
                "2-in/2-out (FCMP_PLUS_PLUS.md §13)"
            } else {
                "non-canonical"
            },
            path_provenance: if sparse_licensed {
                "synthesized sparse, licensed by the same-depth control"
            } else {
                "dense, read off a real tree (control refused the sparse arm)"
            },
        },
        replay: replay_series,
        path_construction: path_series,
        proving: prove_series,
        budget,
        paths_verified: proof_ok && control.both_verified,
        proxy_note: "replay proxy: leaf-layer hashing exact (dominant ~38x); \
                     upper-layer work under-modelled (2-3 layers vs ~6); net an \
                     upper bound, since build_layers rehashes every upper node \
                     where a frontier advance touches one per layer",
    };

    emit(&record, args.json.as_deref());
    summarize(&record, &control);

    match record.budget.verdict {
        Verdict::Miss => ExitCode::from(1),
        Verdict::Pass | Verdict::Ungraded => ExitCode::SUCCESS,
    }
}

/// Same depth, sparse versus dense — sparsity held as the only variable.
fn run_control(depth: u8) -> ControlExperiment {
    let dense_leaves = shekyl_wss_q1b_bench::corpus::min_leaves_for_depth(depth)
        .expect("a control depth of at least 2");
    let dense_corpus = build_corpus(dense_leaves, 0xC0);
    let dense_layers = replay(&dense_corpus);
    let dense_path = read_off_path(&dense_layers, dense_corpus.spent_index);
    let sparse_path = synth_sparse_path(&dense_corpus, depth);

    let dense_inputs = prove_inputs(&dense_corpus, &dense_path, CANONICAL_INPUTS);
    let sparse_inputs = prove_inputs(&dense_corpus, &sparse_path, CANONICAL_INPUTS);

    let mut both_verified = true;
    let dense = sustained(1, DEFAULT_TOLERANCE_PCT, || {
        if prove_only(&dense_inputs, &dense_path, [0x01; 32]).is_err() {
            both_verified = false;
        }
    });
    let sparse = sustained(1, DEFAULT_TOLERANCE_PCT, || {
        if prove_only(&sparse_inputs, &sparse_path, [0x02; 32]).is_err() {
            both_verified = false;
        }
    });

    let dense_s = dense.graded_s();
    let sparse_s = sparse.graded_s();
    let divergence_pct = if dense_s > 0.0 {
        (sparse_s - dense_s) / dense_s * 100.0
    } else {
        f64::INFINITY
    };
    ControlExperiment {
        tree_depth: depth,
        dense_leaves,
        dense_s,
        sparse_s,
        divergence_pct,
        sparse_equals_dense: divergence_pct.abs() <= CONTROL_TOLERANCE_PCT,
        both_verified,
    }
}

fn emit(record: &SpendEdgeRecord, path: Option<&str>) {
    let json = serde_json::to_string_pretty(record).expect("record serializes");
    match path {
        Some(p) => {
            if let Err(e) = std::fs::write(p, &json) {
                eprintln!("could not write {p}: {e}");
            }
        }
        None => println!("{json}"),
    }
}

fn summarize(record: &SpendEdgeRecord, control: &ControlExperiment) {
    let b = &record.budget;
    eprintln!();
    eprintln!("── WSS-Q1(b) spend edge ──");
    eprintln!(
        "  machine        {} / {}-bit",
        record.environment.arch, record.environment.pointer_width_bits
    );
    eprintln!("  depth          {}", record.corpus.tree_depth);
    eprintln!(
        "  window         {} leaves over {} blocks",
        record.corpus.window_leaves, record.corpus.replay_window_blocks
    );
    eprintln!(
        "  leaf rate      {} leaves/block (ceiling {} weight)",
        record.corpus.leaf_rate.leaves_per_block, record.corpus.leaf_rate.block_weight_ceiling
    );
    eprintln!(
        "  control        dense {:.3} s vs sparse {:.3} s ({:+.1} %)",
        control.dense_s, control.sparse_s, control.divergence_pct
    );
    eprintln!(
        "  replay         {:.3} s (converged: {})",
        record.replay.median_s, record.replay.converged
    );
    eprintln!(
        "  path build     {:.3} s",
        record.path_construction.median_s
    );
    eprintln!("  DELTA          {:.3} s", b.delta_s);
    eprintln!(
        "  proving        {:.3} s (converged: {})",
        b.proving_s, record.proving.converged
    );
    eprintln!(
        "  ratio          {:.1} %  (threshold {:.3} s, binding arm: {})",
        b.ratio * 100.0,
        b.threshold_s,
        b.binding_arm
    );
    eprintln!("  VERDICT        {:?}", b.verdict);
    if matches!(b.verdict, Verdict::Ungraded) {
        eprintln!("                 (measurement only — not the pinned rig, or --grade not given)");
    }
}
