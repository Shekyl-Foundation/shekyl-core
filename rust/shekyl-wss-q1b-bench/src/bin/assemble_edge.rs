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
    plan_at_depth, plan_at_replay_window, read_flatness, rung_floor_is_representable,
    signed_change_pct, spread_pct, window_leaf_ratio, ArmRole, AssembleRig, AssemblyPlan,
    AssemblyWork, FlatnessCriterion, GradeConvergence, PlanKind, WindowReading,
    LEAF_RATE_MODEL_DEPTH,
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

    /// Measure the shape on this depth's rung instead of the replay-window plan.
    ///
    /// The replay-window plan is the rung one day of chain reaches, with the
    /// window as a reading beside that rung (`plan_at_replay_window`). It
    /// costs hours to ingest. `--rung` at the window's own depth runs the same
    /// four pair arms without the window.
    /// A shallower rung establishes the same shape — flat across a rung, and
    /// a cross-rung step no dearer than one layer — in minutes. Neither plan
    /// is the graded assembly population. That population is a ruled chain
    /// age, and the record says which plan ran.
    ///
    /// Depth 2 is the shallowest tree (`min_leaves_for_depth`): the leaf
    /// layer is never itself the root.
    #[arg(long, value_parser = clap::value_parser!(u8).range(2..))]
    rung: Option<u8>,

    /// Leaves per ingested block. Defaults to the worst-case rate at
    /// `LEAF_RATE_MODEL_DEPTH`, the depth a path's proof weight is priced at.
    /// That depth is not the tree depth of either plan. Must be at least 1
    /// and no larger than the smallest arm's population, so every arm holds
    /// at least one block.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
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
fn measure_and_release(
    label: &'static str,
    work: AssemblyWork,
    leaves_per_block: u64,
    store_dir: Option<&str>,
) -> Series {
    let (rig, series) = measure(label, work, leaves_per_block, store_dir);
    drop(rig);
    series
}

/// Time one population, building its client first (untimed), and keep the rig.
fn measure(
    label: &'static str,
    work: AssemblyWork,
    leaves_per_block: u64,
    store_dir: Option<&str>,
) -> (AssembleRig, Series) {
    eprintln!(
        "  building {label:>11}  n={:<10} depth={} k={} ...",
        work.population.leaf_count, work.population.depth, work.owned_inputs
    );
    let rig = AssembleRig::new(work, leaves_per_block, store_dir.map(std::path::Path::new));
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

fn work_record(role: &'static str, work: AssemblyWork, series: Series) -> AssembleArmRecord {
    AssembleArmRecord {
        role,
        leaf_count: work.population.leaf_count,
        depth: work.population.depth,
        owned_inputs: work.owned_inputs,
        series,
    }
}

/// The plan this invocation names, and its kind.
///
/// **One resolution path for every mode.** `--plan` and the measurement both
/// come through here, so neither can accept a depth the other refuses — which
/// is exactly what happened when the check lived in `run` alone: `--plan
/// --rung 15` walked past it and panicked inside `plan_at_depth`.
///
/// The depth bound is read rather than restated. Above some depth
/// `outputs_per_node`'s product wraps in a release build, so
/// [`rung_floor_is_representable`] — a reading of `min_leaves_for_depth`'s
/// `Option` — is the only place that knows where the ladder ends.
fn resolve_plan(args: &Args) -> Result<(AssemblyPlan, PlanKind), String> {
    match args.rung {
        None => Ok((plan_at_replay_window(), PlanKind::ReplayWindow)),
        Some(depth) => {
            if !rung_floor_is_representable(depth) {
                return Err(format!(
                    "--rung {depth}: the rung floor is not representable. \
                     `outputs_per_node`'s product overflows at this depth and wraps \
                     silently in a release build, so the plan would name a population \
                     that does not exist. Pick a shallower rung."
                ));
            }
            Ok((
                AssemblyPlan::rung_only(plan_at_depth(depth)),
                PlanKind::Shape { depth },
            ))
        }
    }
}

/// One plan, measured. The window series is `None` on a shape plan.
///
/// One rig is resident at a time. `rung_top` is the control subject, so it
/// is built last and timed twice, back to back, on the same client. The two
/// timings have one sensitivity profile: whatever separates them is the
/// board. A control across two different arms would not cancel
/// (`CT6_PROVING_STATE.md` §10.4).
///
/// The other arms, and the window reading, finish and their rigs drop before
/// that client exists. Holding it across them would time `rung_floor` beside
/// `rung_top`'s working set and shrink the same-rung spread toward `Flat`.
/// The window is among those earlier readings. It is not among the series
/// that withhold the grade.
struct MeasuredPlan {
    below: Series,
    floor: Series,
    top: Series,
    input_cap: Series,
    window: Option<Series>,
    /// `rung_top` timed a second time, on the client `top` just used.
    control: Series,
}

fn measure_plan(plan: AssemblyPlan, leaves_per_block: u64, store: Option<&str>) -> MeasuredPlan {
    let rung = plan.rung;
    let below = measure_and_release(
        rung.below.role.as_str(),
        rung.below.work,
        leaves_per_block,
        store,
    );
    let floor = measure_and_release(
        rung.floor.role.as_str(),
        rung.floor.work,
        leaves_per_block,
        store,
    );
    let input_cap = measure_and_release(
        rung.input_cap.role.as_str(),
        rung.input_cap.work,
        leaves_per_block,
        store,
    );
    let window = plan.window.map(|reading| {
        measure_and_release(
            WindowReading::RECORD_ROLE,
            reading.work,
            leaves_per_block,
            store,
        )
    });
    let (top_rig, top) = measure(
        rung.top.role.as_str(),
        rung.top.work,
        leaves_per_block,
        store,
    );
    eprintln!("  re-timing rung_top as the board control ...");
    let control = time(&top_rig);
    drop(top_rig);
    MeasuredPlan {
        below,
        floor,
        top,
        input_cap,
        window,
        control,
    }
}

fn run(args: &Args) -> Result<AssembleEdgeRecord, String> {
    let (plan, plan_kind) = resolve_plan(args)?;
    let leaves_per_block = args
        .leaves_per_block
        .unwrap_or_else(|| worst_case_leaves_per_block(LEAF_RATE_MODEL_DEPTH).leaves_per_block);
    let measured = measure_plan(plan, leaves_per_block, args.store_dir.as_deref());

    let median = |series: &Series| std::time::Duration::from_secs_f64(series.median_s);
    let control_divergence_pct = spread_pct(median(&measured.top), median(&measured.control));
    let load_control = LoadControl::over(
        [(
            control_divergence_pct,
            measured.top.converged && measured.control.converged,
        )],
        DEFAULT_TOLERANCE_PCT,
    );

    // The grade's series are the four pair arms and the control. The window
    // reading is timed above and recorded below; it is not a field of
    // `GradeConvergence`, so an unconverged window cannot withhold the pair
    // grade. The input cap stays: `input_cap_change_pct` is published from it.
    let convergence = GradeConvergence {
        below: measured.below.converged,
        floor: measured.floor.converged,
        top: measured.top.converged,
        input_cap: measured.input_cap.converged,
        control: measured.control.converged,
    };
    let criterion = FlatnessCriterion::default();
    let rung = plan.rung;
    let reading = read_flatness(
        criterion,
        load_control.quiet,
        convergence.all_converged(),
        (median(&measured.floor), median(&measured.top)),
        (median(&measured.below), median(&measured.floor)),
        (
            rung.below.work.population.depth,
            rung.floor.work.population.depth,
        ),
    );
    let input_cap_change_pct =
        signed_change_pct(median(&measured.top), median(&measured.input_cap));

    let arms = vec![
        work_record(rung.below.role.as_str(), rung.below.work, measured.below),
        work_record(rung.floor.role.as_str(), rung.floor.work, measured.floor),
        work_record(rung.top.role.as_str(), rung.top.work, measured.top),
        work_record(
            rung.input_cap.role.as_str(),
            rung.input_cap.work,
            measured.input_cap,
        ),
    ];
    let window = plan
        .window
        .zip(measured.window)
        .map(|(reading, series)| work_record(WindowReading::RECORD_ROLE, reading.work, series));

    Ok(AssembleEdgeRecord {
        schema_version: SCHEMA_VERSION,
        measurement: "path assembly — CurveTreeClient::assemble_paths across leaf populations",
        grading: "baseline — this harness registers nothing, so assembly takes the rebuild \
                  it keeps for an unregistered input and a same-rung slope is the EXPECTED \
                  reading: the before-figure capture exists to remove. The criterion carried \
                  here was fixed before capture existed; CT-6 increment 6 re-grades these \
                  same arms, registered, against it. A cross-rung pass is a ceiling (no dearer than one layer), not \
                  evidence the step matched the uniform-layer model. The integrity gate's \
                  verdict is green by construction (the reference root is taken from the \
                  client); root agreement is graded in-crate by shekyl-curve-tree's \
                  client::ct6_oracle, not here.",
        environment: Environment::capture(),
        rig: rig::decide(&Environment::capture(), false, None, false)
            .map_err(|e| format!("rig: {e}"))?,
        call_site: "shekyl-curve-tree/src/assemble.rs — CurveTreeClient::assemble_paths, \
                    reached from the CT-5c send path once per spend",
        plan: plan_kind,
        plan_note: plan_kind.note(),
        criterion,
        input_cap_change_pct,
        window,
        reading,
        control_series: measured.control,
        arms,
        load_control,
    })
}

/// The window's leaf ratio, from the leaves the record stored.
///
/// `None` when the plan had no window. This is the print boundary: the ratio
/// is not a field, and the floor is found by its role because `arms` stays
/// the pair-arm array a v3 reader already knows.
fn recorded_window_separation(record: &AssembleEdgeRecord) -> Option<f64> {
    let window = record.window.as_ref()?;
    let floor_leaves = record
        .arms
        .iter()
        .find(|arm| arm.role == ArmRole::RungFloor.as_str())
        .expect("a record with a window reading carries its rung floor")
        .leaf_count;
    Some(window_leaf_ratio(window.leaf_count, floor_leaves))
}

fn write_series(role: &str, leaf_count: u64, depth: u8, owned_inputs: usize, series: &Series) {
    eprintln!(
        "  {role:>11}  n={leaf_count:<10} depth={depth}  k={owned_inputs}  {:.4} s/call (converged: {})",
        series.median_s, series.converged
    );
}

fn write_window_separation(separation: Option<f64>) {
    if let Some(separation) = separation {
        eprintln!(
            "  window         {separation:.3}x its rung floor — a reading, not a pair member \
             (reported, never required)"
        );
    }
}

fn report(r: &AssembleEdgeRecord) {
    eprintln!("\n{} [{}]", r.measurement, r.plan.label());
    for arm in &r.arms {
        write_series(
            arm.role,
            arm.leaf_count,
            arm.depth,
            arm.owned_inputs,
            &arm.series,
        );
    }
    if let Some(window) = &r.window {
        write_series(
            window.role,
            window.leaf_count,
            window.depth,
            window.owned_inputs,
            &window.series,
        );
    }
    eprintln!(
        "  same rung      {:.1} % spread across n (bound {:.1} %) — must reach 0 for flatness",
        r.reading.same_rung_spread_pct, r.criterion.same_rung_tolerance_pct
    );
    eprintln!(
        "  cross rung     {:.3}x measured, {:.3}x the one-layer ceiling (a pass is not a match)",
        r.reading.cross_rung_ratio, r.reading.cross_rung_expected
    );
    write_window_separation(recorded_window_separation(r));
    eprintln!(
        "  input cap      {:+.1} % to raise k to MAX_INPUTS at one population (#842's n + k; \
         negative means cheaper, so k is lost in n)",
        r.input_cap_change_pct
    );
    eprintln!(
        "  board          {:.1} % control divergence (bound {:.1} %), quiet: {}",
        r.load_control.max_divergence_pct, r.load_control.tolerance_pct, r.load_control.quiet
    );
    eprintln!("  READING        {:?}", r.reading.outcome);
    eprintln!("  PLAN           {}", r.plan_note);
    eprintln!("  GRADING        {}", r.grading);
}

fn main() -> ExitCode {
    let args = Args::parse();

    if args.plan {
        let (plan, plan_kind) = match resolve_plan(&args) {
            Ok(resolved) => resolved,
            Err(e) => {
                eprintln!("assemble_edge: {e}");
                return ExitCode::FAILURE;
            }
        };
        eprintln!(
            "leaf rate modelled at depth {LEAF_RATE_MODEL_DEPTH} (proof weight); each arm's \
             tree depth is read from its own leaf count"
        );
        eprintln!("plan: {}", plan_kind.label());
        for arm in plan.rung.arms() {
            eprintln!(
                "  {:>11}  n={:<10} depth={}  k={}",
                arm.role.as_str(),
                arm.work.population.leaf_count,
                arm.work.population.depth,
                arm.work.owned_inputs
            );
        }
        if let Some(window) = plan.window {
            eprintln!(
                "  {:>11}  n={:<10} depth={}  k={}",
                WindowReading::RECORD_ROLE,
                window.work.population.leaf_count,
                window.work.population.depth,
                window.work.owned_inputs
            );
        }
        write_window_separation(plan.window_separation());
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
