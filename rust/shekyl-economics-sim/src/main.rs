mod engine;
mod scenarios;

use engine::{run_scenario, ScenarioResult, SimParams};
use scenarios::all_scenarios;
use std::io::Write;

/// Runs all economics simulation scenarios and writes results as JSON to stdout.
///
/// **Output convention**: Machine-readable JSON goes to **stdout** (pipe-friendly).
/// Human-readable progress and summaries go to **stderr** via `eprintln!`.
/// This lets callers do `cargo run -p shekyl-economics-sim > results.json`
/// while still seeing progress on the terminal.
fn main() {
    let params = SimParams::default();
    let configs = all_scenarios(&params);

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
                last.effective_burn_rate_pct,
                last.staker_annual_yield_pct,
                last.release_multiplier,
            );
        }

        results.push(result);
    }

    let json = serde_json::to_string_pretty(&results).expect("JSON serialization failed");
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(json.as_bytes()).expect("write failed");
    stdout.write_all(b"\n").expect("write failed");
    eprintln!("\nAll 8 scenarios complete. JSON written to stdout.");
}
