// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The verify-edge baseline: `root_at_count` on an unfrozen population.
//!
//! Rows 2 and 3 of `WALLET_SIDE_STORE.md` §6.3.4 grade the two edges a human
//! waits at. This measures the one nobody waits at and nothing grades — the
//! per-block verify cost `CT-6` F3(a) priced — so that increment 6's
//! **re-grade** has something to compare against.
//!
//! It emits **no verdict**. See [`shekyl_wss_q1b_bench::verifyedge`].

use std::process::ExitCode;

use clap::Parser;
use shekyl_curve_tree::{BlockHeight, LeafStore};
use shekyl_wss_q1b_bench::corpus::{
    self, leaves_per_block_at, nominal_block_weight, worst_case_leaves_per_block,
    GRADED_TREE_DEPTH, W,
};
use shekyl_wss_q1b_bench::fixture::build_corpus;
use shekyl_wss_q1b_bench::report::{VerifyEdgeRecord, BLOCK_TARGET_S, SCHEMA_VERSION};
use shekyl_wss_q1b_bench::rig::{self, Environment};
use shekyl_wss_q1b_bench::timing::{DEFAULT_TOLERANCE_PCT, MAX_WALL_SECONDS};
use shekyl_wss_q1b_bench::verifyedge::{build_population, frozen_count, time_root_at};

/// A frozen phase at least this much faster than the unfrozen one confirms the
/// mixed-composition path ran rather than the `full_build_root` fallback.
///
/// The fallback ignores frozen sub-roots entirely, so under it the ratio is
/// ~1. A margin rather than `> 1.0` because timing noise straddles 1.0; 1.5×
/// is far below the ~29-segment recompute this population is built to contain
/// and far above jitter.
const MIXED_PATH_RATIO_FLOOR: f64 = 1.5;

#[derive(Parser, Debug)]
#[command(
    name = "verify_edge",
    about = "WSS-Q1(b) verify-edge baseline — per-block root_at_count (CT-6 F3a). Ungraded."
)]
struct Args {
    /// Tree depth the leaf rate is derived at.
    #[arg(long, default_value_t = GRADED_TREE_DEPTH)]
    depth: u8,

    /// Density: `worst-case` (row 2's sustained ceiling) or `nominal`
    /// (row 3's full-reward zone). Both are run by default.
    #[arg(long, value_parser = ["worst-case", "nominal", "both"], default_value = "both")]
    density: String,

    /// Blocks of leaves to build. Defaults to `W`, the burial window — the
    /// population that is complete-but-unfrozen in production.
    #[arg(long, default_value_t = W)]
    blocks: u64,

    /// Store path. Defaults to a temp file: a file-backed store is the
    /// production posture rule 76's rig pins, and the I/O term is real.
    #[arg(long)]
    store: Option<String>,

    /// Emit the JSON record on stdout.
    #[arg(long, default_value_t = false)]
    json: bool,
}

fn run(args: &Args, density: &'static str) -> Result<VerifyEdgeRecord, String> {
    let rate = match density {
        "worst-case" => worst_case_leaves_per_block(args.depth),
        _ => leaves_per_block_at(args.depth, nominal_block_weight()),
    };

    let dir = tempfile::tempdir().map_err(|e| format!("temp dir: {e}"))?;
    let path = args
        .store
        .clone()
        .unwrap_or_else(|| dir.path().join("verify_edge.redb").display().to_string());
    let store = LeafStore::open(&path).map_err(|e| format!("open store: {e:?}"))?;

    // Leaf bytes come from the corpus builder, so this mints no second leaf
    // shape. One block's worth is generated and indexed cyclically: the
    // recompute cost is independent of content, and building 771 000 distinct
    // leaves would dominate the run for no measured difference.
    let sample = build_corpus(rate.leaves_per_block.min(4_096), 7);
    let bytes: Vec<[u8; 128]> = sample
        .chunk
        .iter()
        .filter_map(|c| c.scalars())
        .map(|sc| {
            let mut b = [0u8; 128];
            for (i, s) in sc.iter().enumerate() {
                b[i * 32..(i + 1) * 32].copy_from_slice(s);
            }
            b
        })
        .collect();
    if bytes.is_empty() {
        return Err("corpus produced no valid leaf scalars".to_owned());
    }
    let n_sample = bytes.len() as u64;
    let leaf_bytes = move |p: u64| bytes[(p % n_sample) as usize];

    let pop = build_population(&store, args.blocks, &rate, &leaf_bytes)
        .map_err(|e| format!("build population: {e:?}"))?;

    // Rule 47, before anything is timed: the subject must be in the state this
    // measurement claims. A population that froze by accident makes every
    // number cheap, and a leaf count that drifted off the derived rate makes
    // the scale a fiction.
    let frozen_before =
        frozen_count(&store, pop.complete_segments).map_err(|e| format!("frozen scan: {e:?}"))?;
    if frozen_before != 0 {
        return Err(format!(
            "{frozen_before} segment(s) already frozen — the unfrozen phase would \
             measure a cost this population is supposed to contain"
        ));
    }
    if pop.leaves != args.blocks * rate.leaves_per_block {
        return Err(format!(
            "population holds {} leaves, derived rate says {}",
            pop.leaves,
            args.blocks * rate.leaves_per_block
        ));
    }
    if pop.complete_segments == 0 {
        return Err(format!(
            "population has no complete segment ({} leaves, E = {}) — there is no \
             recompute to measure",
            pop.leaves, pop.leaves_per_segment
        ));
    }

    let (unfrozen, root_a) = time_root_at(
        &store,
        pop.leaves,
        1,
        DEFAULT_TOLERANCE_PCT,
        MAX_WALL_SECONDS,
    );

    // The control: freeze everything, then time the same call. A tip far above
    // every drain height makes every complete segment burial-eligible.
    store
        .maybe_freeze_segments(BlockHeight::from_raw(args.blocks + corpus::W + 1))
        .map_err(|e| format!("freeze: {e:?}"))?;
    let frozen_after =
        frozen_count(&store, pop.complete_segments).map_err(|e| format!("frozen scan: {e:?}"))?;
    if frozen_after != pop.complete_segments {
        return Err(format!(
            "control froze {frozen_after} of {} complete segments — the contrast would \
             understate the recompute it is meant to remove",
            pop.complete_segments
        ));
    }

    let (frozen, root_b) = time_root_at(
        &store,
        pop.leaves,
        1,
        DEFAULT_TOLERANCE_PCT,
        MAX_WALL_SECONDS,
    );

    let ratio = if frozen.median_s > 0.0 {
        unfrozen.median_s / frozen.median_s
    } else {
        f64::INFINITY
    };
    // `grade_requested` is **false**, and not because grading was skipped:
    // there is no ruled threshold to request grading against (`CT-6 Q4` is
    // pending as a derivation). The machine is still captured, because the
    // rig pins are what make two runs comparable under rule 76 even when
    // neither is graded.
    let env = Environment::capture();
    let rig_verdict = rig::decide(&env, false, None, false).map_err(|e| format!("rig: {e}"))?;

    Ok(VerifyEdgeRecord {
        schema_version: SCHEMA_VERSION,
        measurement: "verify edge — root_at_count, unfrozen population",
        grading: "baseline — no ruled threshold. CT-6 Q4 is pending as a derivation and \
                  grades the amortized advance; this is the naive cost that form replaces. \
                  CT-6 increment 6 re-grades against this record.",
        rig: rig_verdict,
        environment: env,
        density: if density == "worst-case" {
            "worst case — sustained block-weight ceiling (row 2's density)"
        } else {
            "nominal — full-reward zone, MIN_BLOCK_WEIGHT (row 3's density)"
        },
        leaf_count: pop.leaves,
        cadence_fraction: unfrozen.median_s / BLOCK_TARGET_S,
        recompute_ratio: ratio,
        mixed_path_confirmed: ratio >= MIXED_PATH_RATIO_FLOOR,
        root_stable_across_freeze: root_a == root_b,
        call_site: "shekyl-engine-core/src/engine/merge.rs:661 (verify_root, per block) \
                    via CurveTreeClient::root_at — 'the §3.3 verify hot path'",
        population: pop,
        unfrozen,
        frozen,
    })
}

fn report(r: &VerifyEdgeRecord) {
    eprintln!("verify edge — {}", r.density);
    eprintln!(
        "  population     {} leaves over {} blocks ({} leaves/block)",
        r.population.leaves, r.population.blocks, r.population.leaf_rate.leaves_per_block
    );
    eprintln!(
        "  segments       {} complete, {} leaves in tail (E = {})",
        r.population.complete_segments, r.population.tail_leaves, r.population.leaves_per_segment
    );
    eprintln!(
        "  UNFROZEN       {:.3} s per call (converged: {})",
        r.unfrozen.median_s, r.unfrozen.converged
    );
    eprintln!(
        "  frozen ctrl    {:.3} s per call  ({:.1}x faster)",
        r.frozen.median_s, r.recompute_ratio
    );
    eprintln!(
        "  mixed path     {}  root stable: {}",
        r.mixed_path_confirmed, r.root_stable_across_freeze
    );
    eprintln!(
        "  cadence        {:.2} % of a {:.0} s block (informational)",
        r.cadence_fraction * 100.0,
        BLOCK_TARGET_S
    );
    eprintln!("  GRADING        {}", r.grading);
}

fn main() -> ExitCode {
    let args = Args::parse();
    let densities: Vec<&'static str> = match args.density.as_str() {
        "worst-case" => vec!["worst-case"],
        "nominal" => vec!["nominal"],
        _ => vec!["worst-case", "nominal"],
    };
    let mut records = Vec::new();
    for d in densities {
        match run(&args, d) {
            Ok(r) => {
                report(&r);
                records.push(r);
            }
            Err(e) => {
                eprintln!("verify_edge ({d}): {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    if args.json {
        match serde_json::to_string_pretty(&records) {
            Ok(j) => println!("{j}"),
            Err(e) => {
                eprintln!("serialize: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}
