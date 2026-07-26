mod admission;
mod budget;
mod budget_scenarios;
mod burden;
mod calibration;
mod distribution;
mod engine;
mod escalation;
mod population;
mod proxy;
mod redistribution;
mod stranding;
mod swing;
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
fn main() {
    let params = SimParams::default();

    if std::env::args().any(|a| a == "--fb1c-c2") {
        run_fb1c_c2(&params);
        return;
    }

    if std::env::args().any(|a| a == "--stage2") {
        // The I/O boundary lives here, in the binary target: the arm modules
        // *render* into a sink (`fmt::Write`) and `main` performs the write.
        // That keeps each report next to the model it renders — the
        // `mode_adversarial_ratio` precedent — while the debug-macro lint's
        // intent (no ad-hoc printing in non-binary source) is satisfied by
        // construction rather than by exemption.
        let mut narration = String::new();
        stage2::run_stage2(&mut narration, &params).expect("String sink is infallible");
        eprint!("{narration}");
        return;
    }

    let gate7 = std::env::args().any(|a| a == "--gate7");
    let configs = if gate7 {
        gate7_scenarios(&params)
    } else {
        all_scenarios(&params)
    };

    let mut results: Vec<ScenarioResult> = Vec::new();

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
        eprintln!("\nAll 8 scenarios complete. JSON written to stdout.");
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
