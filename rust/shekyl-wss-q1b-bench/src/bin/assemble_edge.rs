// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The path-assembly cost instrument: what a spend pays to build its paths.
//!
//! `CT-6` increment 5. Capture's claim is that path assembly becomes **flat in
//! chain size at a fixed owned-output count**. This binary measures the claim's
//! subject — [`shekyl_curve_tree::CurveTreeClient::assemble_paths`] — which
//! nothing measured before: the spend edge proves against synthesized paths, so
//! assembly was bypassed entirely.
//!
//! It emits a **baseline**, not a pass. The criterion is pre-registered
//! (`shekyl_wss_q1b_bench::assembleedge::FlatnessCriterion`) and reported
//! against this run, so a slope today is the expected reading and the evidence
//! for why capture must exist. Increment 6 re-grades the same arms against the
//! same criterion once capture has landed.
//!
//! Run `--plan` to print the derived populations without measuring anything.

use std::process::ExitCode;

use clap::Parser;
use shekyl_wss_q1b_bench::assembleedge::{
    expected_cross_rung_ratio, outcome, plan_at_depth, plan_at_replay_window, signed_change_pct,
    spread_pct, Arm, ArmRole, AssembleRig, FlatnessCriterion, PlanKind, LEAF_RATE_MODEL_DEPTH,
};
use shekyl_wss_q1b_bench::corpus::worst_case_leaves_per_block;
use shekyl_wss_q1b_bench::report::{
    emit, AssembleArmRecord, AssembleEdgeRecord, LoadControl, SCHEMA_VERSION,
};
use shekyl_wss_q1b_bench::rig::{self, Environment};
use shekyl_wss_q1b_bench::timing::{Series, DEFAULT_TOLERANCE_PCT, MAX_WALL_SECONDS};

/// Samples discarded before a series is summarised.
///
/// One: the first call on a freshly ingested client reads cold store pages,
/// and the quantity is the cost a wallet pays on a warm store it has just
/// been refreshing.
const WARMUP_CALLS: usize = 1;

#[derive(Parser, Debug)]
#[command(
    name = "assemble_edge",
    about = "CT-6 path-assembly cost — assemble_paths across leaf populations. Baseline, ungraded."
)]
struct Args {
    /// Print the derived plan and exit, measuring nothing.
    #[arg(long)]
    plan: bool,

    /// Measure the shape on this depth's rung instead of the graded one.
    ///
    /// The graded plan's top population is the real worst-case window, which
    /// costs hours to ingest and whose absolute seconds belong on the floor
    /// device (rule 76). A shallower rung establishes the same SHAPE -- flat
    /// across a rung, one layer's step at its boundary -- in minutes. It does
    /// not establish the figure, and the record says which plan it ran.
    #[arg(long)]
    rung: Option<u8>,

    /// Leaves per ingested block. Defaults to the worst-case rate the graded
    /// window is derived from, so the corpus is built the way it accrues.
    #[arg(long)]
    leaves_per_block: Option<u64>,

    /// Directory the scratch client store is created in. On the pinned rig
    /// this must be the attested storage (rule 76).
    #[arg(long)]
    store_dir: Option<String>,

    /// Write the JSON record here instead of stdout.
    #[arg(long)]
    json: Option<String>,
}

/// Time one arm and **release its rig** before returning.
///
/// The control re-times `rung_top` at the end of the run and must see the same
/// machine `top_first` saw. A live rig holds its whole drained entry set in
/// memory and its scratch database on disk, so keeping the other arms' rigs
/// alive would put the control under harness-created memory and disk pressure
/// that the first timing never had — and the control exists precisely to
/// attribute a divergence to the *board*. Holding them would also multiply
/// peak resources across every population at once.
///
/// This was the original shape: the arms were bound to `_below_rig` and
/// friends, and an `_`-prefixed binding keeps a value alive to the end of
/// scope rather than dropping it. Releasing explicitly here, rather than
/// relying on that distinction at four call sites.
fn measure_and_release(arm: Arm, leaves_per_block: u64, store_dir: Option<&str>) -> Series {
    let (rig, series) = measure(arm, leaves_per_block, store_dir);
    drop(rig);
    series
}

/// Time one arm, building its client first (untimed), and keep the rig.
fn measure(arm: Arm, leaves_per_block: u64, store_dir: Option<&str>) -> (AssembleRig, Series) {
    eprintln!(
        "  building {:>11}  n={:<10} depth={} k={} ...",
        arm.role.as_str(),
        arm.population.leaf_count,
        arm.population.depth,
        arm.owned_inputs
    );
    let rig = AssembleRig::new(arm, leaves_per_block, store_dir.map(std::path::Path::new));
    let series = time(&rig);
    (rig, series)
}

fn time(rig: &AssembleRig) -> Series {
    shekyl_wss_q1b_bench::timing::sustained_within(
        WARMUP_CALLS,
        DEFAULT_TOLERANCE_PCT,
        MAX_WALL_SECONDS,
        || {
            rig.assemble_once();
        },
    )
}

fn arm_record(arm: Arm, series: Series) -> AssembleArmRecord {
    AssembleArmRecord {
        role: arm.role.as_str(),
        leaf_count: arm.population.leaf_count,
        depth: arm.population.depth,
        owned_inputs: arm.owned_inputs,
        series,
    }
}

fn run(args: &Args) -> Result<AssembleEdgeRecord, String> {
    let arms = args.rung.map_or_else(plan_at_replay_window, plan_at_depth);
    let leaves_per_block = args
        .leaves_per_block
        .unwrap_or_else(|| worst_case_leaves_per_block(LEAF_RATE_MODEL_DEPTH).leaves_per_block);

    let find = |role: ArmRole| {
        *arms
            .iter()
            .find(|a| a.role == role)
            .expect("the plan carries every role")
    };
    let below = find(ArmRole::RungBelow);
    let floor = find(ArmRole::RungFloor);
    let top = find(ArmRole::RungTop);
    let cap = find(ArmRole::InputCap);

    // The graded top is measured first and held, so the control at the end of
    // the run re-times *identical work* on the same client. Two terms with one
    // sensitivity profile: whatever separates them is the board, not the
    // workload. A control across two different arms would not cancel, which is
    // the mistake `CT6_PROVING_STATE.md` §10.4 retired a claim over.
    let (top_rig, top_first) = measure(top, leaves_per_block, args.store_dir.as_deref());
    let below_series = measure_and_release(below, leaves_per_block, args.store_dir.as_deref());
    let floor_series = measure_and_release(floor, leaves_per_block, args.store_dir.as_deref());
    let cap_series = measure_and_release(cap, leaves_per_block, args.store_dir.as_deref());

    eprintln!("  re-timing rung_top as the board control ...");
    let top_again = time(&top_rig);

    let control_divergence_pct = spread_pct(
        std::time::Duration::from_secs_f64(top_first.median_s),
        std::time::Duration::from_secs_f64(top_again.median_s),
    );
    let load_control = LoadControl::over(
        [(
            control_divergence_pct,
            top_first.converged && top_again.converged,
        )],
        DEFAULT_TOLERANCE_PCT,
    );

    let d = |s: &Series| std::time::Duration::from_secs_f64(s.median_s);
    let criterion = FlatnessCriterion::default();
    let same_rung = (d(&floor_series), d(&top_first));
    let cross_rung = (d(&below_series), d(&floor_series));
    let cross_depths = (below.population.depth, floor.population.depth);

    // Every series that feeds the reading, including the control's own. A
    // median from a series that never settled is not yet a cost, so a grade
    // taken over one would be a reading of an unfinished measurement.
    let every_series_converged = [
        &below_series,
        &floor_series,
        &top_first,
        &cap_series,
        &top_again,
    ]
    .iter()
    .all(|s| s.converged);

    let plan_kind = args
        .rung
        .map_or(PlanKind::ReplayWindow, |depth| PlanKind::Shape { depth });

    Ok(AssembleEdgeRecord {
        schema_version: SCHEMA_VERSION,
        measurement: "path assembly — CurveTreeClient::assemble_paths across leaf populations",
        grading: "baseline — capture is unbuilt, so a same-rung slope is the EXPECTED reading \
                  and is the evidence for why capture must exist. The criterion carried here \
                  was fixed before capture existed; CT-6 increment 6 re-grades these same arms \
                  against it. The integrity gate's verdict is green by construction (the \
                  reference root is taken from the client); root agreement is graded in-crate \
                  by shekyl-curve-tree's client::ct6_oracle, not here.",
        environment: Environment::capture(),
        rig: rig::decide(&Environment::capture(), false, None, false)
            .map_err(|e| format!("rig: {e}"))?,
        call_site: "shekyl-curve-tree/src/assemble.rs — CurveTreeClient::assemble_paths, \
                    reached from the CT-5c send path once per spend",
        plan: plan_kind,
        plan_note: plan_kind.note(),
        criterion,
        same_rung_spread_pct: spread_pct(same_rung.0, same_rung.1),
        cross_rung_ratio: cross_rung.1.as_secs_f64() / cross_rung.0.as_secs_f64(),
        cross_rung_expected: expected_cross_rung_ratio(cross_depths.0, cross_depths.1),
        input_cap_change_pct: signed_change_pct(d(&top_first), d(&cap_series)),
        grade: outcome(
            criterion,
            load_control.quiet,
            every_series_converged,
            same_rung,
            cross_rung,
            cross_depths,
        ),
        control_series: top_again,
        arms: vec![
            arm_record(below, below_series),
            arm_record(floor, floor_series),
            arm_record(top, top_first),
            arm_record(cap, cap_series),
        ],
        load_control,
    })
}

fn report(r: &AssembleEdgeRecord) {
    eprintln!("\n{} [{}]", r.measurement, r.plan.label());
    for arm in &r.arms {
        eprintln!(
            "  {:>11}  n={:<10} depth={}  k={}  {:.4} s/call (converged: {})",
            arm.role,
            arm.leaf_count,
            arm.depth,
            arm.owned_inputs,
            arm.series.median_s,
            arm.series.converged
        );
    }
    eprintln!(
        "  same rung      {:.1} % spread across n (bound {:.1} %) — must reach 0 for flatness",
        r.same_rung_spread_pct, r.criterion.same_rung_tolerance_pct
    );
    eprintln!(
        "  cross rung     {:.3}x measured, {:.3}x predicted by one layer's work",
        r.cross_rung_ratio, r.cross_rung_expected
    );
    eprintln!(
        "  input cap      {:+.1} % to raise k to MAX_INPUTS at one population (#842's n + k; \
         negative means cheaper, so k is lost in n)",
        r.input_cap_change_pct
    );
    eprintln!(
        "  board          {:.1} % control divergence (bound {:.1} %), quiet: {}",
        r.load_control.max_divergence_pct, r.load_control.tolerance_pct, r.load_control.quiet
    );
    eprintln!("  READING        {:?}", r.grade);
    eprintln!("  PLAN           {}", r.plan_note);
    eprintln!("  GRADING        {}", r.grading);
}

fn main() -> ExitCode {
    let args = Args::parse();

    if args.plan {
        eprintln!(
            "leaf rate modelled at depth {LEAF_RATE_MODEL_DEPTH} (proof weight); each arm's \
             tree depth is read from its own leaf count"
        );
        for arm in args.rung.map_or_else(plan_at_replay_window, plan_at_depth) {
            eprintln!(
                "  {:>11}  n={:<10} depth={}  k={}",
                arm.role.as_str(),
                arm.population.leaf_count,
                arm.population.depth,
                arm.owned_inputs
            );
        }
        return ExitCode::SUCCESS;
    }

    match run(&args) {
        Ok(r) => {
            report(&r);
            if let Err(e) = emit(&r, args.json.as_deref()) {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("assemble_edge: {e}");
            ExitCode::FAILURE
        }
    }
}
