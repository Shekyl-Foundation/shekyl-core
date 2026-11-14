#![deny(unsafe_code)]
mod admission;
mod baseline;
mod block_space;
mod budget;
mod budget_scenarios;
mod burden;
mod calibration;
mod cartel;
mod chain_cursor;
mod committed_fixture;
mod distribution;
mod engine;
mod escalation;
mod esr10;
mod eup4;
mod fee_bar;
mod fee_floor;
mod fee_horizon;
mod fee_ladder;
mod fee_model;
mod fee_signal;
mod growth_gate;
mod median_window;
mod miner_stuffer;
mod mn_feasibility;
mod onset;
mod parallel;
mod population;
mod proxy;
mod redistribution;
mod rng;
mod rung_mix;
mod secret_draw;
mod secret_draw_production;
mod stranding;
mod swing;
mod volume_window;
mod window_stuffer;
// The `RecordedChainFixture` recorder is test-substrate only: it
// generates / verifies `docs/test_vectors/economics/*.json` for the
// `EconomicsEngine` C4 differential (`docs/design/STAGE_1_PR_7_ECONOMICS_ENGINE.md`
// §5.4). Gated `#[cfg(test)]` so its `pub` surface does not become
// dead code in the production `sim` binary.
#[cfg(test)]
mod record;
mod scenarios;
mod stage2;

use budget::run_budget_scenario;
use budget_scenarios::all_budget_scenarios;
use engine::{run_scenario, ScenarioResult, SimParams};
use scenarios::{all_scenarios, gate7_scenarios};
use std::io::Write;

/// Runs all economics simulation scenarios and writes results as JSON to stdout.
///
/// **Output convention**: Machine-readable JSON goes to **stdout** (pipe-friendly).
/// Human-readable progress and summaries go to **stderr** via `eprintln!`.
/// This lets callers do `cargo run -p shekyl-economics-sim > results.json`
/// while still seeing progress on the terminal.
///
/// `--gate7` runs the gate-7 locked-supply re-pricing set
/// (`STAKER_ARCHIVAL_SIM.md` §Iteration-5 scope) instead of the legacy
/// eight; the default invocation stays byte-identical.
///
/// `--fb1c-c2` runs the archival-funding demand-insulation set
/// (`REWARD_EMISSION_E3_GATING_ROUND.md` §9.9 disposition-(b) rule-21 reopen;
/// `budget.rs`): measures how much `budget(E)` swings with tx volume under the
/// shipped disposition (a) versus the demand-insulated (b) counterfactual.
///
/// `--control-flat-fee` runs any fee-consuming mode on the control arm: one
/// flat fee per transaction, the fee the `ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md`
/// §12.13–§12.14 tables were measured on. Without it the run charges the
/// production ladder (`fee_model.rs`). Every such report names its arm.
/// The run's overrides: every `--set set.field=value`, in order
/// (`baseline.rs`). Parsed and applied before any mode runs.
fn overrides_from_args() -> Result<Vec<baseline::Override>, baseline::OverrideError> {
    let args: Vec<String> = std::env::args().collect();
    let mut overrides = Vec::new();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--set" {
            let text = args.get(i + 1).map_or("", String::as_str);
            overrides.push(baseline::Override::parse(text)?);
            i += 2;
        } else {
            i += 1;
        }
    }
    Ok(overrides)
}

/// Refuse a run and exit before any fold.
fn refuse(reason: &str) -> ! {
    eprintln!("shekyl-economics-sim: {reason}");
    std::process::exit(2);
}

fn main() {
    let control = std::env::args().any(|a| a == "--control-flat-fee");
    let arm = |mut params: SimParams| {
        if control {
            params.fee = SimParams::section_12_14_control().fee;
        }
        params
    };
    let overrides = overrides_from_args().unwrap_or_else(|e| refuse(&e.to_string()));
    let params =
        arm(SimParams::with_overrides(overrides).unwrap_or_else(|e| refuse(&e.to_string())));

    // Every report starts with the baseline's three digests and the run's
    // overrides (ESR-16 completion, ruling 6).
    let mut header = String::new();
    baseline::write_header(&mut header, params.overrides()).expect("String sink is infallible");
    eprint!("{header}");

    // A sweep cell is a `--stage2` or `--esr10` run: each prints a cell
    // beside its baseline. Every other mode reads the shipped baseline, so
    // an override there would change nothing it prints, or change it with
    // no baseline beside it.
    let stage2 = std::env::args().any(|a| a == "--stage2");
    let esr10 = std::env::args().any(|a| a == "--esr10");
    // EUP-4 prep 2 (§5.32): `--eup4` runs every instrument; each
    // instrument's own mode runs it alone, and only that mode takes a cell.
    let eup4 = std::env::args().any(|a| a == "--eup4");
    let instrument = eup4::Instrument::ALL
        .into_iter()
        .find(|i| std::env::args().any(|a| a == i.flag()));
    if !params.overrides().is_empty() && !stage2 && !esr10 && instrument.is_none() {
        refuse(
            "overrides are read by --stage2, --esr10 and each instrument's own mode only: each \
             prints a cell beside its baseline",
        );
    }
    if esr10 && control {
        refuse("--esr10 runs the production ladder: the flat control fee has no rungs to mix");
    }
    if (eup4 || instrument.is_some()) && control {
        refuse("the instruments name their fee arms: --control-flat-fee selects none of them");
    }
    // An override on a field the mode's report does not read would print
    // the baseline, which reads as "no effect": refused before the fold.
    let (mode, reads) = if let Some(instrument) = instrument {
        baseline::instrument_reach(instrument)
    } else if esr10 {
        baseline::esr10_reach()
    } else {
        baseline::stage2_reach(control)
    };
    if let Err(e) = baseline::check_reach(params.overrides(), params.baseline(), mode, reads) {
        refuse(&e.to_string());
    }

    if eup4 || instrument.is_some() {
        let started = std::time::Instant::now();
        let mut narration = String::new();
        let summary =
            eup4::run(&mut narration, &params, instrument).expect("String sink is infallible");
        if params.overrides().is_empty() {
            eprint!("{narration}");
        } else {
            let mut baseline_narration = String::new();
            eup4::run(&mut baseline_narration, &SimParams::default(), instrument)
                .expect("String sink is infallible");
            // The reach the mode declares is the fold's; whether the cell
            // reaches this instrument's figures is read here, from the two
            // reports, so a cell never prints its baseline as a result.
            if let Some(reason) = baseline::unmoved_cell_refusal(
                &narration,
                &baseline_narration,
                instrument.map_or("--eup4", eup4::Instrument::flag),
            ) {
                refuse(&reason);
            }
            eprint!(
                "{}",
                baseline::beside_baseline(&narration, &baseline_narration)
            );
        }
        let json = serde_json::to_string_pretty(&summary).expect("JSON serialization failed");
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(json.as_bytes()).expect("write failed");
        stdout.write_all(b"\n").expect("write failed");
        eprintln!(
            "{} wall time: {:.0} s",
            instrument.map_or("--eup4", eup4::Instrument::flag),
            started.elapsed().as_secs_f64()
        );
        return;
    }

    if std::env::args().any(|a| a == "--fb1c-c2") {
        eprintln!("{}", params.fee.label());
        run_fb1c_c2(&params);
        return;
    }

    // FL instrument (`docs/design/FEE_LADDER_DERIVATION.md` §1.9): the fee
    // ladder derivation round's registered measurement set. The module
    // renders; this binary target performs the writes (stage2 precedent —
    // JSON to stdout, summary to stderr).
    if std::env::args().any(|a| a == "--fee-ladder") {
        let report = fee_ladder::report();
        let mut summary = String::new();
        fee_ladder::render_summary(&report, &mut summary);
        eprint!("{summary}");
        println!("{}", fee_ladder::render_json(&report));
        return;
    }

    // §11 confirmation set (`FEE_LADDER_DERIVATION.md` §11.5, FL-E1…FL-E3):
    // the relay floor's per-block slew on raw `C` under both SMA
    // resolutions, and FL-C7's loop through the FL-R20 served map.
    if std::env::args().any(|a| a == "--fee-floor") {
        let report = fee_floor::report();
        let mut summary = String::new();
        fee_floor::render_summary(&report, &mut summary);
        eprint!("{summary}");
        println!("{}", fee_floor::render_json(&report));
        return;
    }

    if std::env::args().any(|a| a == "--secret-draw") {
        // ESR-11's experiment (ECONOMICS_SIM_PRODUCTION_REBASE.md §5.13)
        // on ESR-13's loop at ESR-11's timing (§5.22): the secret per-block
        // draw at 0 / 10 / 30 % producer dropout, pairs short of three
        // issued draws, draws per block, and the failure window
        // re-checked. JSON to stdout, table to stderr.
        let report = secret_draw_production::Report {
            cells: secret_draw_production::esr11_timing_specs()
                .into_iter()
                .map(secret_draw_production::cell)
                .collect(),
        };
        let mut summary = String::new();
        secret_draw_production::render_summary(&mut summary, &report)
            .expect("String sink is infallible");
        eprint!("{summary}");
        println!("{}", secret_draw_production::evidence_json(&report));
        return;
    }

    if std::env::args().any(|a| a == "--secret-draw-production") {
        // ESR-13 (ECONOMICS_SIM_PRODUCTION_REBASE.md §5.17): ESR-11's epoch
        // on production's `draw_count` and `select_draw`, with a block's
        // draws issued only when its bundle is admitted. Each cell is
        // reported to stderr as it finishes, with its wall time; then the
        // table to stderr and JSON to stdout.
        let started = std::time::Instant::now();
        let mut report = secret_draw_production::Report { cells: Vec::new() };
        for pairs in secret_draw::EVIDENCE_PAIRS {
            for spec in secret_draw_production::evidence_specs(pairs) {
                let cell_started = std::time::Instant::now();
                let cell = secret_draw_production::cell(spec);
                let mut row = String::new();
                secret_draw_production::render_cell(&mut row, &cell)
                    .expect("String sink is infallible");
                eprintln!(
                    "[{:>7.1} s] {}",
                    cell_started.elapsed().as_secs_f64(),
                    row.trim_end()
                );
                report.cells.push(cell);
            }
        }
        let mut summary = String::new();
        secret_draw_production::render_summary(&mut summary, &report)
            .expect("String sink is infallible");
        eprint!("\n{summary}");
        eprintln!(
            "wall time: {:.1} s, {} seeds per cell on one thread each",
            started.elapsed().as_secs_f64(),
            secret_draw::SEEDS
        );
        println!("{}", secret_draw_production::evidence_json(&report));
        return;
    }

    // ESR-10 (`ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.29): the fee multiplier
    // and the rung mix on both `w_ref` arms. The narration to stderr, as
    // `--stage2`'s; the summary EUP-5 reads as JSON to stdout.
    if esr10 {
        let started = std::time::Instant::now();
        let mut narration = String::new();
        let rows = esr10::run_esr10(&mut narration, &params, &esr10::every_scenario(&params))
            .expect("String sink is infallible");
        if params.overrides().is_empty() {
            eprint!("{narration}");
        } else {
            let shipped = SimParams::default();
            let mut baseline_narration = String::new();
            esr10::run_esr10(
                &mut baseline_narration,
                &shipped,
                &esr10::every_scenario(&shipped),
            )
            .expect("String sink is infallible");
            eprint!(
                "{}",
                baseline::beside_baseline(&narration, &baseline_narration)
            );
        }
        let json = serde_json::to_string_pretty(&rows).expect("JSON serialization failed");
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(json.as_bytes()).expect("write failed");
        stdout.write_all(b"\n").expect("write failed");
        eprintln!(
            "--esr10 wall time: {:.0} s",
            started.elapsed().as_secs_f64()
        );
        return;
    }

    if stage2 {
        // The I/O boundary lives here, in the binary target: the arm modules
        // *render* into a sink (`fmt::Write`) and `main` performs the write.
        // That keeps each report next to the model it renders — the
        // `mode_adversarial_ratio` precedent — while the debug-macro lint's
        // intent (no ad-hoc printing in non-binary source) is satisfied by
        // construction rather than by exemption.
        let mut narration = String::new();
        stage2::run_stage2(&mut narration, &params).expect("String sink is infallible");
        if params.overrides().is_empty() {
            eprint!("{narration}");
        } else {
            let mut baseline_narration = String::new();
            stage2::run_stage2(&mut baseline_narration, &arm(SimParams::default()))
                .expect("String sink is infallible");
            eprint!(
                "{}",
                baseline::beside_baseline(&narration, &baseline_narration)
            );
        }
        return;
    }

    let gate7 = std::env::args().any(|a| a == "--gate7");
    let configs = if gate7 {
        gate7_scenarios(&params)
    } else {
        all_scenarios(&params)
    };

    let mut results: Vec<ScenarioResult> = Vec::new();

    eprintln!("{}", params.fee.label());
    for config in configs {
        eprintln!("Running scenario: {} ...", config.name);
        let result = run_scenario(&params, &config);

        eprintln!(
            "  -> {} years, final emitted: {:.2}%, total burned: {:.2} SHEKYL",
            result.years.len(),
            result.final_supply_emitted_pct,
            result.final_total_burned,
        );

        if let Some(last) = result.years.last() {
            eprintln!(
                "  -> Last year: burn={:.2}%, staker_yield={:.4}%, release={:.3}x",
                last.effective_burn_rate_pct, last.staker_annual_yield_pct, last.release_multiplier,
            );
        }

        results.push(result);
    }

    let json = serde_json::to_string_pretty(&results).expect("JSON serialization failed");
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(json.as_bytes()).expect("write failed");
    stdout.write_all(b"\n").expect("write failed");
    if gate7 {
        eprintln!("\nGate-7 scenario set complete. JSON written to stdout.");
    } else {
        eprintln!(
            "\nAll {} scenarios complete. JSON written to stdout.",
            results.len()
        );
    }
}

/// F-B1c-c2 disposition-(b) reopen evidence. Runs the demand-insulation
/// scenario set and writes per-epoch budget accounting (JSON) to stdout, with a
/// human-readable reopen verdict table to stderr.
fn run_fb1c_c2(params: &SimParams) {
    let scenarios = all_budget_scenarios(params);
    let mut results = Vec::new();

    eprintln!(
        "F-B1c-c2 disposition-(b) reopen sim — budget(E) demand-insulation\n\
         (a) = shipped, emission leg on MODULATED base_reward; \
         (b) = counterfactual, UNMODULATED subsidy\n\
         throttle = budget_a/budget_b (1.0 = no throttle); \
         uplift% = extra funding (b) would buy\n"
    );
    eprintln!(
        "{:<22} {:>10} {:>12} {:>12} {:>13}",
        "scenario", "worst_thr", "max_uplift%", "mean_uplift%", "emis_frac@wt"
    );

    for scenario in &scenarios {
        let result = run_budget_scenario(params, scenario);
        eprintln!(
            "{:<22} {:>10.4} {:>12.2} {:>12.2} {:>13.4}",
            result.name,
            result.worst_ratio_a_over_b,
            result.max_insulation_uplift_pct,
            result.mean_insulation_uplift_pct,
            result.emission_frac_at_worst_throttle,
        );
        results.push(result);
    }

    eprintln!(
        "\nReopen reading (rule 21): (b) reopens only if the throttle materially\n\
         starves the serving incentive in a plausible low-volume window.\n\
         - worst_thr: deepest budget_a/budget_b; floors at release_min (0.8x).\n\
         - max_uplift%: the most extra funding (b) could buy in any epoch.\n\
         - emis_frac@wt: emission leg's share of budget at the worst-throttle\n\
           epoch — the fee leg (1-this) is disposition-neutral, so this bounds\n\
           how much of TOTAL budget the 0.8x floor can even touch."
    );

    let json = serde_json::to_string_pretty(&results).expect("JSON serialization failed");
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(json.as_bytes()).expect("write failed");
    stdout.write_all(b"\n").expect("write failed");
    eprintln!("\nF-B1c-c2 scenario set complete. Per-epoch JSON written to stdout.");
}
