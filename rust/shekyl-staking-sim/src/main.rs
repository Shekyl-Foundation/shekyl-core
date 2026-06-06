//! `shekyl-staking-sim` — agent-based staker-archival coverage simulation.
//!
//! Iteration 1 (coverage dynamics) of the gate-7 instrument for the
//! pay-for-service / firewalled-pseudonym rebasing. The model under test is
//! canonical in `docs/design/V3_STAKER_ARCHIVAL.md`; the test plan (sub-claims,
//! sweeps, success/failure/finding) is `docs/design/STAKER_ARCHIVAL_SIM.md`.
//!
//! This binary runs the curated iteration-1 sweep set and emits:
//! - machine-readable JSON (the full per-scenario results) to **stdout**, and
//! - a human-readable summary table + an interpretation header to **stderr**,
//!
//! matching the `shekyl-economics-sim` stdout/stderr convention.

mod agent;
mod metrics;
mod model;
mod reward;
mod scenarios;

use scenarios::{build_scenarios, run_sim, ScenarioResult};

fn yn(b: bool) -> &'static str {
    if b {
        "PASS"
    } else {
        "fail"
    }
}

fn print_summary(results: &[ScenarioResult]) {
    eprintln!("shekyl-staking-sim — iteration 1 (coverage dynamics)");
    eprintln!("Model: docs/design/V3_STAKER_ARCHIVAL.md; plan: docs/design/STAKER_ARCHIVAL_SIM.md");
    eprintln!();
    eprintln!("Sub-claims (stated thresholds): covered = frac_under_target<0.05 & min_R>=1;");
    eprintln!("  spread = gini_actor<0.6 & max_actor_share<0.20 (ACTOR-level, the whale test);");
    eprintln!("  deep_history = deep_frac_under_target<0.10; churn_stable = churn<0.05.");
    eprintln!("Note: gini_psd is the pseudonym-level (on-chain-observer) read — reported, not");
    eprintln!("  the pass criterion. A splitting whale looks egalitarian there by design.");
    eprintln!();
    eprintln!("Durability columns: dS/dN = CO-LOCATED coverage (L8 min-form) =");
    eprintln!(
        "  Sum_actor min(floor(capital/bond), floor(storage/shard_size)) / Sum_deep R_target."
    );
    eprintln!(
        "  Each actor contributes only its SMALLER leg — a deep shard needs storage AND bond-"
    );
    eprintln!(
        "  capital on the same actor — so this catches starvation the aggregate ratio misses"
    );
    eprintln!("  (bscale_s0: aggregate 3.24 but co-located ~0.71, matching deep_und 0.75). seat =");
    eprintln!("  affording_actors >= R_target(deepest) (capital-leg distinct count); oldU/wB4 =");
    eprintln!("  oldest-band residual/whale share.");
    eprintln!();
    eprintln!("  oChrn = oldest-band churn rate (flips/held-epoch in the deepest band; L9 duration target).");
    eprintln!();
    eprintln!(
        "{:<22} {:<18} {:>5} {:>4} {:>5} {:>3} | {:>8} {:>8} {:>8} {:>7} | {:>4} {:>4} {:>4} {:>4} {:>4} | {:>4} {:>4} {:>6} {:>5} {:>6}",
        "scenario",
        "axis",
        "bond",
        "g",
        "act",
        "whl",
        "frac_und",
        "deep_und",
        "gini_act",
        "churn",
        "cov",
        "sprd",
        "deep",
        "chrn",
        "ALL",
        "dS/dN",
        "seat",
        "oldU",
        "wB4",
        "oChrn",
    );

    for r in results {
        let m = &r.final_metrics;
        let old = m.bands.last();
        let old_under = old.map(|b| b.frac_under).unwrap_or(0.0);
        let whale_b4 = old.and_then(|b| b.whale_share);
        let slot_ratio = m.colocated_coverage;
        eprintln!(
            "{:<22} {:<18} {:>5.2} {:>4.1} {:>5} {:>3} | {:>8.3} {:>8.3} {:>8.3} {:>7.4} | {:>4} {:>4} {:>4} {:>4} {:>4} | {:>6.2} {:>4} {:>6.3} {:>5} {:>6.3}",
            r.name,
            r.axis,
            r.bond_rate,
            r.age_weight,
            r.n_actors,
            if r.whale { "Y" } else { "n" },
            m.frac_under_target,
            m.deep_frac_under_target,
            m.gini_actor,
            r.churn,
            yn(r.claims.covered),
            yn(r.claims.spread),
            yn(r.claims.deep_history),
            yn(r.claims.churn_stable),
            yn(r.claims.all_pass),
            slot_ratio,
            if m.seating_feasible { "Y" } else { "n" },
            old_under,
            match whale_b4 {
                Some(v) => format!("{v:.2}"),
                None => "-".into(),
            },
            r.oldest_churn,
        );
    }

    let n_all = results.iter().filter(|r| r.claims.all_pass).count();
    eprintln!();
    eprintln!(
        "{n_all}/{} scenarios pass all four sub-claims.",
        results.len()
    );
}

fn main() {
    let cfgs = build_scenarios();
    let results: Vec<ScenarioResult> = cfgs.iter().map(run_sim).collect();

    match serde_json::to_string_pretty(&results) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("error serializing results: {e}"),
    }

    print_summary(&results);
}

#[cfg(test)]
mod tests {
    use crate::metrics::gini;
    use crate::model::{bond_age, bond_duration, g_age, r_target, World};
    use crate::model::{Actor, Shard};

    #[test]
    fn gini_equal_is_zero() {
        assert!(gini(&[5.0, 5.0, 5.0, 5.0]).abs() < 1e-9);
    }

    #[test]
    fn gini_concentrated_is_high() {
        // One holder has everything → Gini → (n-1)/n.
        let g = gini(&[0.0, 0.0, 0.0, 10.0]);
        assert!(g > 0.7, "expected high concentration, got {g}");
    }

    #[test]
    fn gini_empty_and_zero_safe() {
        assert_eq!(gini(&[]), 0.0);
        assert_eq!(gini(&[0.0, 0.0]), 0.0);
    }

    #[test]
    fn g_age_baseline_is_one() {
        assert!((g_age(0.0, 0.0) - 1.0).abs() < 1e-12);
        assert!((g_age(1.0, 0.0) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn g_age_premium_rises_with_age() {
        assert!(g_age(1.0, 2.0) > g_age(0.0, 2.0));
    }

    #[test]
    fn bond_age_flat_when_scale_zero() {
        // scale 0 ⇒ every deep shard bonds at exactly bond_rate.
        assert!((bond_age(0.5, 2.0, 0.0, 0.5) - 2.0).abs() < 1e-12);
        assert!((bond_age(1.0, 2.0, 0.0, 0.5) - 2.0).abs() < 1e-12);
    }

    #[test]
    fn bond_age_tilt_is_mean_preserving() {
        // The tilt pivots about deep_mid = (deep_threshold+1)/2, so at deep_mid the
        // bond equals bond_rate regardless of scale, and it rises with age above it.
        let dt = 0.5;
        let mid = (dt + 1.0) / 2.0; // 0.75
        assert!((bond_age(mid, 2.0, 3.0, dt) - 2.0).abs() < 1e-12);
        assert!(bond_age(1.0, 2.0, 3.0, dt) > bond_age(0.6, 2.0, 3.0, dt));
        // Floor keeps the youngest deep shard from bonding free at high scale.
        assert!(bond_age(0.5, 2.0, 100.0, dt) > 0.0);
    }

    #[test]
    fn bond_duration_flat_when_scale_zero() {
        // scale 0 ⇒ every deep shard commits for exactly `base` epochs (rounded).
        assert_eq!(bond_duration(0.5, 4.0, 0.0), 4);
        assert_eq!(bond_duration(1.0, 4.0, 0.0), 4);
    }

    #[test]
    fn bond_duration_age_scaled_is_longer_for_older() {
        // Older shards carry a strictly longer commitment horizon when scaled.
        let young = bond_duration(0.5, 4.0, 2.0);
        let old = bond_duration(1.0, 4.0, 2.0);
        assert!(old > young, "old {old} should exceed young {young}");
        // Floored at 1 so a near-zero-age deep shard still commits.
        assert!(bond_duration(0.0, 0.1, 0.0) >= 1);
    }

    #[test]
    fn advance_epoch_retires_oldest_and_decrements_locks() {
        let shards = vec![Shard { age: 0.98 }, Shard { age: 0.2 }];
        let actors = vec![Actor {
            storage_capacity: 4,
            capital: 10.0,
            is_whale: false,
        }];
        let mut w = World::new(shards, actors);
        w.holdings[0][0] = true;
        w.locks[0][0] = 3;
        w.holdings[0][1] = true;
        w.locks[0][1] = 0;
        w.advance_epoch(0.05);
        // Shard 0 crossed age 1.0 → retired/recycled: age reset, holding+lock cleared.
        assert!((w.shards[0].age - 0.0).abs() < 1e-12);
        assert!(!w.holdings[0][0]);
        assert_eq!(w.locks[0][0], 0);
        // Shard 1 just ages; its (zero) lock stays floored at 0.
        assert!((w.shards[1].age - 0.25).abs() < 1e-12);
        assert!(w.holdings[0][1]);
    }

    #[test]
    fn r_target_deeper_is_higher() {
        let hot = r_target(0.0, 3.0, 6.0);
        let deep = r_target(1.0, 3.0, 6.0);
        assert_eq!(hot, 3);
        assert_eq!(deep, 6);
        assert!(deep > hot);
    }
}
