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
//!
//! Optional filter: `--axis=<prefix>` runs only scenarios whose `axis` field starts with
//! the prefix (e.g. `--axis=gate4_fine` for the iteration-2 bond window sweep).

mod agent;
mod audit;
mod metrics;
mod model;
mod participation;
mod retrieval;
mod reward;
mod scenarios;
mod transport;

use scenarios::{build_scenarios, run_sim, ScenarioResult};

fn yn(b: bool) -> &'static str {
    if b {
        "PASS"
    } else {
        "fail"
    }
}

fn print_summary(results: &[ScenarioResult]) {
    eprintln!("shekyl-staking-sim — staker-archival coverage (see STAKER_ARCHIVAL_SIM.md)");
    eprintln!("Model: docs/design/V3_STAKER_ARCHIVAL.md; plan: docs/design/STAKER_ARCHIVAL_SIM.md");
    eprintln!();
    eprintln!("Sub-claims (stated thresholds): covered = frac_under_target<0.05 & min_R>=1;");
    eprintln!("  spread = gini_actor<0.6 & max_actor_share<0.20 (ACTOR-level, final-epoch SNAPSHOT);");
    eprintln!("  sprdW = same thresholds on WINDOWED read (mean gini, peak max_share over churn_window);");
    eprintln!("  ALL uses sprdW not sprd (L9 lesson: steady-state read is the discipline gate).");
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
    eprintln!(
        "  oChrn = oldest-band churn rate (flips/held-epoch in the deepest band; L9 abandonment)."
    );
    eprintln!(
        "  oUmx  = max oldest-band frac_under over the window (L9 NECESSITY: coverage oscillation;"
    );
    eprintln!("          abandonment is benign rotation unless this is > 0 — discriminates only at lean).");
    eprintln!();
    eprintln!(
        "  deep_und is the FINAL-epoch committed deep under (snapshot); cDeepU is its WINDOWED"
    );
    eprintln!("  MEAN (steady-state read — use this, not the snapshot: the bind_* 'cost' was a");
    eprintln!(
        "  final-epoch artifact). sDeepU/sOUmx = SERVING (seated-replica) deep-under mean / oldest-"
    );
    eprintln!(
        "  under max (L10 retrieval view; = committed when fetch_latency=0). sOUmx is the timing benefit."
    );
    eprintln!(
        "  actv = EMERGENT active fraction of the pool; bondA = EMERGENT bonded-archiver count"
    );
    eprintln!("  (L11 free entry/exit; flat at full population when endogenous=false).");
    eprintln!(
        "  bDU = BOOTSTRAP worst deep gap, unfloored (peak serving deep-under over the run);"
    );
    eprintln!("  bDUf = same WITH the population-decaying foundation floor; baPk = peak bonded-");
    eprintln!(
        "  archiver count (baPk - bondA is the OVERSHOOT). L12; all 0/=bondA outside bootstrap."
    );
    eprintln!("  boOld = OLDEST-band floored gap peak (P3); > bDUf ⇒ residual concentrates in the");
    eprintln!(
        "  irreplaceable tail; age-stratified floor (floor_age_tilt>0) pulls it toward bDUf."
    );
    eprintln!(
        "  feB = FEE-ERA realized purse at end (< budget = subsidy decayed; = ceiling = servo"
    );
    eprintln!("  saturated); fDUpk = worst serving deep gap over the run's 2nd half (death-spiral");
    eprintln!("  read — sustained high = priority-1 failure). L13; =budget/0 outside fee-era.");
    eprintln!("  rUDp = RETRIEVAL deep frac under the SLA (1-(1-u)^d < A*); rAvl = deep-set mean");
    eprintln!(
        "  availability; rTgtA = DERIVED R_target from (u,A*). L15; nonzero rUDp on a covered"
    );
    eprintln!(
        "  set (deep_und~0) = coverage!=retrieval (correlated failure binds). 0/1 outside L15."
    );
    eprintln!(
        "  trU = TRANSPORT-depressed uptime (L16); rTgtA rises as trU falls — the onion path"
    );
    eprintln!(
        "  depresses u and stipulating r_target_deep=6 silently assumed clearnet u. 0 outside L16."
    );
    eprintln!("  dUDp = DURABILITY deep frac under D* (1-(1-s)^d < D*); dAvl = deep-set mean");
    eprintln!("  retention survival; dTgtR = DERIVED R_target from (s,D*). s is per-domain bond-");
    eprintln!(
        "  backed survival (not transport-depressed). L15d/L16d rescore; 0/1 outside durability model."
    );
    eprintln!("  auN = NAIVE audit cadence (challenge every shard at a*); auC = CREDITED cadence");
    eprintln!("  (real reads self-prove → auC<<auN); auDp = deep share of oversight (~1 = traffic");
    eprintln!(
        "  on cold tail only); auOld = oldest-band cadence (P3). L14; 0 outside audit model."
    );
    eprintln!();
    eprintln!(
        "{:<22} {:<18} {:>5} {:>4} {:>5} {:>3} | {:>8} {:>8} {:>8} {:>7} | {:>6} {:>5} | {:>4} {:>4} {:>5} {:>4} {:>4} {:>4} | {:>4} {:>4} {:>6} {:>5} {:>6} {:>6} | {:>6} {:>6} {:>6} | {:>5} {:>6} | {:>5} {:>5} {:>5} {:>5} | {:>6} {:>6} | {:>5} {:>6} {:>5} {:>5} | {:>5} {:>5} {:>5} | {:>5} {:>5} {:>5} {:>5}",
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
        "giniW",
        "mxSW",
        "cov",
        "sprd",
        "sprdW",
        "deep",
        "chrn",
        "ALL",
        "dS/dN",
        "seat",
        "oldU",
        "wB4",
        "oChrn",
        "oUmx",
        "cDeepU",
        "sDeepU",
        "sOUmx",
        "actv",
        "bondA",
        "bDU",
        "bDUf",
        "baPk",
        "boOld",
        "feB",
        "fDUpk",
        "rUDp",
        "rAvl",
        "rTgtA",
        "trU",
        "dUDp",
        "dAvl",
        "dTgtR",
        "auN",
        "auC",
        "auDp",
        "auOld",
    );

    for r in results {
        let m = &r.final_metrics;
        let old = m.bands.last();
        let old_under = old.map(|b| b.frac_under).unwrap_or(0.0);
        let whale_b4 = old.and_then(|b| b.whale_share);
        let slot_ratio = m.colocated_coverage;
        eprintln!(
            "{:<22} {:<18} {:>5.2} {:>4.1} {:>5} {:>3} | {:>8.3} {:>8.3} {:>8.3} {:>7.4} | {:>6.3} {:>5.3} | {:>4} {:>4} {:>5} {:>4} {:>4} {:>4} | {:>6.2} {:>4} {:>6.3} {:>5} {:>6.3} {:>6.3} | {:>6.3} {:>6.3} {:>6.3} | {:>5.2} {:>6.1} | {:>5.3} {:>5.3} {:>5.1} {:>5.3} | {:>6.1} {:>6.3} | {:>5.3} {:>6.4} {:>5} {:>5.3} | {:>5.3} {:>5.4} {:>5} | {:>5.3} {:>5.3} {:>5.2} {:>5.3}",
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
            r.gini_actor_window,
            r.max_actor_share_window,
            yn(r.claims.covered),
            yn(r.claims.spread),
            yn(r.claims.spread_windowed),
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
            r.oldest_under_max,
            r.committed_deep_under,
            r.serving_deep_under,
            r.serving_oldest_under_max,
            r.active_frac,
            r.bonded_active,
            r.boot_deep_under_peak,
            r.boot_deep_under_floored_peak,
            r.bonded_active_peak,
            r.boot_oldest_floored_peak,
            r.fee_budget_end,
            r.fee_deep_under_peak,
            r.retr_under_deep,
            r.retr_avail_deep,
            r.r_target_avail as usize,
            r.transport_u_eff,
            r.dur_under_deep,
            r.dur_avail_deep,
            r.r_target_dur as usize,
            r.audit_oversight_naive,
            r.audit_oversight_credited,
            r.audit_deep_share,
            r.audit_oldest_cadence,
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
    let axis_filter = std::env::args().find_map(|a| a.strip_prefix("--axis=").map(str::to_string));

    let cfgs: Vec<_> = build_scenarios()
        .into_iter()
        .filter(|c| {
            axis_filter
                .as_ref()
                .is_none_or(|prefix| c.axis.starts_with(prefix))
        })
        .collect();

    if cfgs.is_empty() {
        eprintln!(
            "shekyl-staking-sim: no scenarios matched{}",
            axis_filter
                .as_ref()
                .map(|p| format!(" --axis={p}"))
                .unwrap_or_default()
        );
        std::process::exit(1);
    }

    if let Some(ref prefix) = axis_filter {
        eprintln!(
            "shekyl-staking-sim: running {} scenario(s) with axis prefix `{prefix}`",
            cfgs.len()
        );
    }

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
    use crate::participation::{foundation_floor, foundation_floor_aged};

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
            reservation: 0.0,
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

    #[test]
    fn foundation_floor_aged_reduces_to_uniform_at_zero_tilt() {
        // P3: tilt 0 ⇒ the aged floor is byte-identical to the uniform floor at every age.
        // This is the invariant that keeps every pre-P3 scenario (floor_age_tilt default 0)
        // unchanged.
        let dt = 0.5;
        for &pop in &[0usize, 40, 80] {
            for age in [0.5, 0.7, 0.9, 1.0] {
                assert_eq!(
                    foundation_floor_aged(pop, 6, 80.0, 0.0, age, dt),
                    foundation_floor(pop, 6, 80.0),
                    "tilt-0 must equal uniform at pop={pop}, age={age}"
                );
            }
        }
    }

    #[test]
    fn foundation_floor_aged_tilts_toward_oldest() {
        // P3: a positive tilt steers replicas to the oldest band at the expense of the
        // freshly-deepened band, pivoting about the deep midpoint (mean-preserving in the
        // continuous form). At pop=0 the base floor is the full `floor0`.
        let dt = 0.5;
        let base = foundation_floor(0, 6, 80.0); // 6
        let oldest = foundation_floor_aged(0, 6, 80.0, 0.6, 1.0, dt);
        let youngest_deep = foundation_floor_aged(0, 6, 80.0, 0.6, dt, dt);
        assert!(
            oldest > base,
            "oldest must be over-floored: {oldest} > {base}"
        );
        assert!(
            youngest_deep < base,
            "freshly-deepened must be under-floored: {youngest_deep} < {base}"
        );
        // A zero base floor (population at/above decay_pop) stays zero regardless of tilt —
        // the tilt redistributes a floor, it does not create one.
        assert_eq!(foundation_floor_aged(80, 6, 80.0, 0.9, 1.0, dt), 0);
    }
}
