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
use shekyl_wss_q1b_bench::corpus;
use shekyl_wss_q1b_bench::corpus::{
    worst_case_leaves_per_block, CANONICAL_INPUTS, CANONICAL_OUTPUTS, HELD_BUFFER_BLOCKS,
    REPLAY_WINDOW_BLOCKS,
};
use shekyl_wss_q1b_bench::fixture::{
    build_corpus, prove_and_verify, prove_inputs, prove_only, read_off_path, replay,
    synth_sparse_path, ControlExperiment, Path,
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

    /// Depths the sparse-versus-dense control runs at. Repeatable.
    ///
    /// Two rungs by default, not one: a single rung proves sparse == dense at
    /// *that* depth and leaves every deeper rung an extrapolation off the end
    /// of one point. Two adjacent rungs show whether the ratio is flat, which
    /// is what licenses the next one. Depth 5 (467 857 leaves, 60 MB) is the
    /// deepest rung whose dense corpus is cheap to build; depth 6 is 2.28 GB,
    /// which is the reason the sparse path exists at all.
    #[arg(long = "control-depth", default_values_t = [4u8, 5u8])]
    control_depths: Vec<u8>,

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
    // Argument validity is machine-independent, so it is checked before the rig
    // gate: an unusable control set is unusable on a dev box too, and finding
    // that out only on the rig wastes the run the rig exists for.
    if let Err(why) = corpus::validate_control_depths(&args.control_depths) {
        eprintln!("{why}");
        return ExitCode::from(2);
    }
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

    // In grading mode the corpus is the ruled one, not the operator's. `--grade`
    // gating only the MACHINE would let `--grade --window-leaves 1` emit a
    // genuine `rig.grading: true` record for a corpus that is not §6.3.4's
    // 725-block worst case -- the same "cannot fail" defect the open edge's
    // density gate closes, on the other edge.
    if args.grade && args.window_leaves.is_some() {
        eprintln!(
            "refusing to grade: --window-leaves overrides the ruled worst-case corpus. \
             Drop it to grade, or drop --grade to measure a custom window."
        );
        return ExitCode::from(2);
    }

    let leaf_rate = worst_case_leaves_per_block(args.depth);
    let window_leaves = args
        .window_leaves
        .unwrap_or(leaf_rate.leaves_per_block * REPLAY_WINDOW_BLOCKS);

    let mut controls: Vec<ControlExperiment> = Vec::new();
    for depth in &args.control_depths {
        eprintln!("── control: sparse vs dense at depth {depth} ──");
        let control = run_control(*depth);
        if !control.both_verified {
            eprintln!("control arms did not both verify; refusing to report a denominator");
            return ExitCode::from(3);
        }
        eprintln!(
            "   {} leaves: dense {:.3} s vs sparse {:.3} s ({:+.1} %)",
            control.dense_leaves, control.dense_s, control.sparse_s, control.divergence_pct
        );
        controls.push(control);
    }
    // Every arm must hold. One arm passing while another fails is not a flat
    // ratio -- it is a depth dependence, which is exactly what would make the
    // extrapolation to the grading depth unsafe.
    let sparse_licensed = !controls.is_empty() && controls.iter().all(|c| c.sparse_equals_dense);
    let deepest_control = controls.iter().map(|c| c.tree_depth).max().unwrap_or(0);
    // Flatness across adjacent rungs licenses THE NEXT ONE, and no further.
    // Labelling a two-rung extrapolation `MORE THAN ONE RUNG` documented an
    // invalid claim instead of refusing it; `--depth 8` under the default
    // controls would still have produced a graded budget.
    let within_licence = args.depth <= deepest_control + 1;
    let sparse_licensed = sparse_licensed && within_licence;
    eprintln!(
        "   -> sparse {} ({} rung(s), deepest {}; grading at {})",
        if sparse_licensed {
            "licensed"
        } else {
            "REFUSED"
        },
        controls.len(),
        deepest_control,
        args.depth
    );
    if !within_licence {
        eprintln!(
            "   grading depth {} is more than one rung above the deepest control ({}); \
             the sparse path is not licensed there",
            args.depth, deepest_control
        );
    }

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
        // The dense fallback is the WINDOW's tree, whose depth is set by the
        // window's leaf count -- not by `--depth`. At the worst-case corpus
        // that is depth 5 while `--depth` is 6, so a refused control would
        // otherwise have silently moved the denominator to a different depth
        // and still emitted a budget.
        let dense = read_off_path(&layers, corpus.spent_index);
        if dense.tree_depth != args.depth {
            eprintln!(
                "refusing to grade: the sparse path is unlicensed and the dense fallback \
                 reaches depth {}, not the requested {}. Run a control at the grading \
                 depth, or grade at the depth this corpus actually builds.",
                dense.tree_depth, args.depth
            );
            return ExitCode::from(3);
        }
        dense
    };

    // The verify round trip, ONCE and OUTSIDE the timer. `verify` is real work
    // and the denominator is the prover invocation alone, so folding it into
    // the series would inflate the figure the 15 % arm is taken against.
    let paths_verified = match prove_and_verify(&corpus, &graded_path, CANONICAL_INPUTS, [0xA5; 32])
    {
        Ok(true) => true,
        Ok(false) => {
            eprintln!("the graded path did not verify against its own root; refusing the record");
            return ExitCode::from(3);
        }
        Err(e) => {
            eprintln!("prove failed during the verify round trip: {e}");
            return ExitCode::from(3);
        }
    };

    let inputs = prove_inputs(&corpus, &graded_path, CANONICAL_INPUTS);
    let mut prove_failed = false;
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
                prove_failed = true;
            }
        },
    );
    // A prover that fails fast would otherwise contribute a small median and
    // grade as a pass. There is no denominator without a proof.
    if prove_failed {
        eprintln!("the denominator could not be produced; refusing the record");
        return ExitCode::from(3);
    }

    let replay_median = replay_series.graded_s();
    let delta_s = replay_median + path_series.graded_s();
    // §5.2's contract: an unconverged series is REPORTED, never substituted for
    // a converged one. Grading an unconverged median would do exactly the
    // substitution the `stopped_because` field exists to make visible.
    let all_converged = replay_series.converged && path_series.converged && prove_series.converged;
    if rig_verdict.grading && !all_converged {
        eprintln!(
            "not grading: a timing series did not converge (replay: {}, path: {}, proving: {})",
            replay_series.stopped_because,
            path_series.stopped_because,
            prove_series.stopped_because
        );
    }
    let budget = SpendBudget::grade(
        delta_s,
        prove_series.graded_s(),
        rig_verdict.grading && all_converged,
    );

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
            // The provenance names the DISTANCE from the deepest control arm.
            // "Licensed by the control" would be true only at a depth the
            // control actually ran at; anywhere above it the claim is an
            // extrapolation, and the record says how far.
            path_provenance: if !sparse_licensed {
                "dense, read off a real tree (the control refused the sparse arm)"
            } else if args.depth <= deepest_control {
                "synthesized sparse, licensed by a control AT the grading depth"
            } else if args.depth == deepest_control + 1 {
                "synthesized sparse, one rung above the deepest control arm"
            } else {
                "synthesized sparse, MORE THAN ONE RUNG above the deepest control arm"
            },
        },
        replay: replay_series,
        path_construction: path_series,
        proving: prove_series,
        budget,
        // The replay term alone over the window it covers -- path construction
        // is not per-block work and would inflate it.
        per_block_advance_worst_case_s: replay_median / REPLAY_WINDOW_BLOCKS as f64,
        controls: controls.clone(),
        paths_verified: paths_verified && controls.iter().all(|c| c.both_verified),
        proxy_note: "replay proxy: leaf-layer hashing exact (dominant ~38x); \
                     upper-layer work under-modelled (2-3 layers vs ~6); net an \
                     upper bound, since build_layers rehashes every upper node \
                     where a frontier advance touches one per layer",
    };

    if let Err(e) = emit(&record, args.json.as_deref()) {
        eprintln!("{e}");
        summarize(&record, &controls);
        return ExitCode::from(5);
    }
    summarize(&record, &controls);

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

    // Both arms verify ONCE, outside their timers. `both_verified` previously
    // recorded only that `prove` returned -- so a prover result carrying an
    // invalid proof could license the sparse path at the grading depth, which
    // is the single claim this experiment exists to make.
    let both_verified = matches!(
        prove_and_verify(&dense_corpus, &dense_path, CANONICAL_INPUTS, [0x01; 32]),
        Ok(true)
    ) && matches!(
        prove_and_verify(&dense_corpus, &sparse_path, CANONICAL_INPUTS, [0x02; 32]),
        Ok(true)
    );

    let dense_inputs = prove_inputs(&dense_corpus, &dense_path, CANONICAL_INPUTS);
    let sparse_inputs = prove_inputs(&dense_corpus, &sparse_path, CANONICAL_INPUTS);
    let dense = sustained(1, DEFAULT_TOLERANCE_PCT, || {
        std::hint::black_box(prove_only(&dense_inputs, &dense_path, [0x01; 32]).ok());
    });
    let sparse = sustained(1, DEFAULT_TOLERANCE_PCT, || {
        std::hint::black_box(prove_only(&sparse_inputs, &sparse_path, [0x02; 32]).ok());
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

/// Write the record, or say the run failed.
///
/// An explicitly requested artifact that silently fails to appear leaves a
/// pass or miss with no evidence behind it, which is worse than no run.
fn emit(record: &SpendEdgeRecord, path: Option<&str>) -> Result<(), String> {
    let json = serde_json::to_string_pretty(record).map_err(|e| format!("serialize: {e}"))?;
    match path {
        Some(p) => std::fs::write(p, &json).map_err(|e| format!("could not write {p}: {e}")),
        None => {
            println!("{json}");
            Ok(())
        }
    }
}

fn summarize(record: &SpendEdgeRecord, controls: &[ControlExperiment]) {
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
    for c in controls {
        eprintln!(
            "  control d{}     dense {:.3} s vs sparse {:.3} s ({:+.1} %)",
            c.tree_depth, c.dense_s, c.sparse_s, c.divergence_pct
        );
    }
    eprintln!("  path source    {}", record.corpus.path_provenance);
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
        "  per block      {:.0} ms  (amortized frontier advance, worst case)",
        record.per_block_advance_worst_case_s * 1000.0
    );
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
