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
    signed_change_pct, spread_pct, Arm, ArmRole, AssembleRig, FlatnessCriterion, PlanKind,
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
    /// The replay-window plan is one day of chain (`plan_at_replay_window`).
    /// It costs hours to ingest, and its seconds are a one-day-old chain's.
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
fn resolve_plan(args: &Args) -> Result<(Vec<Arm>, PlanKind), String> {
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
            Ok((plan_at_depth(depth), PlanKind::Shape { depth }))
        }
    }
}

fn run(args: &Args) -> Result<AssembleEdgeRecord, String> {
    let (arms, plan_kind) = resolve_plan(args)?;
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
    // Asserted up front, before any ingest. The loop below measures it.
    let _cap = find(ArmRole::InputCap);

    // One rig resident at a time. `rung_top` is the control subject, so it is
    // built last and timed twice, back to back, on the same client. The two
    // timings have one sensitivity profile: whatever separates them is the
    // board. A control across two different arms would not cancel
    // (`CT6_PROVING_STATE.md` §10.4).
    //
    // The other arms finish, and their rigs drop, before that client exists.
    // Holding it across them would time `rung_floor` beside `rung_top`'s
    // working set and shrink the same-rung spread toward `Flat` — the reading
    // capture is trying to earn. The control therefore does not span the
    // earlier arms. Spanning them is the bias it exists to exclude.
    let store = args.store_dir.as_deref();
    let mut timed: Vec<(Arm, Series)> = Vec::with_capacity(arms.len());
    // Every arm except the control subject. The set is the plan, so a new
    // role is released before `rung_top` exists rather than timed beside it.
    for arm in arms
        .iter()
        .copied()
        .filter(|arm| arm.role != ArmRole::RungTop)
    {
        timed.push((arm, measure_and_release(arm, leaves_per_block, store)));
    }
    let (top_rig, top_first) = measure(top, leaves_per_block, store);
    eprintln!("  re-timing rung_top as the board control ...");
    let top_again = time(&top_rig);
    drop(top_rig);
    timed.push((top, top_first));

    let series_of = |role: ArmRole| {
        timed
            .iter()
            .find(|(arm, _)| arm.role == role)
            .map(|(_, series)| series)
            .expect("the plan's roles were all timed")
    };
    let median = |role: ArmRole| std::time::Duration::from_secs_f64(series_of(role).median_s);

    let control_divergence_pct = spread_pct(
        median(ArmRole::RungTop),
        std::time::Duration::from_secs_f64(top_again.median_s),
    );
    let load_control = LoadControl::over(
        [(
            control_divergence_pct,
            series_of(ArmRole::RungTop).converged && top_again.converged,
        )],
        DEFAULT_TOLERANCE_PCT,
    );

    // Every series that feeds the reading, including the control's own. A
    // median from a series that never settled is not yet a cost, so a grade
    // taken over one would be a reading of an unfinished measurement.
    let every_series_converged =
        timed.iter().all(|(_, series)| series.converged) && top_again.converged;
    let criterion = FlatnessCriterion::default();
    let reading = read_flatness(
        criterion,
        load_control.quiet,
        every_series_converged,
        (median(ArmRole::RungFloor), median(ArmRole::RungTop)),
        (median(ArmRole::RungBelow), median(ArmRole::RungFloor)),
        (below.population.depth, floor.population.depth),
    );
    let input_cap_change_pct =
        signed_change_pct(median(ArmRole::RungTop), median(ArmRole::InputCap));

    let arm_records = arms
        .iter()
        .map(|arm| {
            let index = timed
                .iter()
                .position(|(timed_arm, _)| timed_arm.role == arm.role)
                .expect("every plan arm was timed");
            let (arm, series) = timed.swap_remove(index);
            arm_record(arm, series)
        })
        .collect();

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
        reading,
        control_series: top_again,
        arms: arm_records,
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
        r.reading.same_rung_spread_pct, r.criterion.same_rung_tolerance_pct
    );
    eprintln!(
        "  cross rung     {:.3}x measured, {:.3}x the one-layer ceiling (a pass is not a match)",
        r.reading.cross_rung_ratio, r.reading.cross_rung_expected
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
    eprintln!("  READING        {:?}", r.reading.outcome);
    eprintln!("  PLAN           {}", r.plan_note);
    eprintln!("  GRADING        {}", r.grading);
}

fn main() -> ExitCode {
    let args = Args::parse();

    if args.plan {
        let (arms, plan_kind) = match resolve_plan(&args) {
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
        for arm in arms {
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
