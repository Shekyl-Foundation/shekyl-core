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
//!
//! Modes: `--timing-cluster` (ARCHIVAL_TIMING_CONSTANTS pin);
//! `--failure-confirmation` (L14b Round-1 policy comparator per
//! ARCHIVAL_FAILURE_CONFIRMATION_PIN.md); `--gf7-timeline` (the GF-7 joint
//! timeline recorded through production's broadcast seam, its axis coverage,
//! and the §19 leg-(b) wall-clock arm; ARCHIVAL_BOND_WI4_MEASUREMENT.md, WI-4);
//! `--gf7-seal <artifact>` (also `--gf7-seal=<artifact>`; the §19.8 leg-(b)
//! sealing-form grader of the receipts artifact the `shekyl-engine-core`
//! `gf7_sealing_run` harness writes from a live-driver run; per WI-4 §19.10.3
//! a dispersal-regression tripwire).

mod agent;
mod audit;
mod budget_throttle;
mod clustering;
mod curve;
mod failure_confirmation;
mod fingerprint;
mod gf7_seal;
mod gf7_timeline;
mod metrics;
mod model;
mod participation;
mod retrieval;
mod reward;
mod rng;
use reward::{CurveImpl, RewardArm};
#[cfg(test)]
mod l11_l13_pin;
mod scenarios;
mod standoff;
mod timing_cluster;
mod transport;
mod wallclock_leg;

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
    eprintln!(
        "  spread = max_actor_share<0.20 & wB4<0.20 (DIRECT whale gauges, final-epoch SNAPSHOT;"
    );
    eprintln!(
        "    re-anchored 2026-06-11 Layer-2 band close — gini is a reported trend gauge only);"
    );
    eprintln!(
        "  sprdW = peak max_actor_share over churn_window < 0.20 & wB4<0.20 (WINDOWED read);"
    );
    eprintln!("  ALL uses sprdW not sprd (L9 lesson: steady-state read is the discipline gate).");
    eprintln!("  deep_history = deep_frac_under_target<0.10;");
    eprintln!("  churn_stable = max(oUmx, serving_oUmx)<0.05 (coverage oscillation, NOT abandonment churn).");
    eprintln!("Note: gini/giniW (actor-level) and gini_psd (pseudonym-level, on-chain-observer");
    eprintln!("  read) are reported, not pass criteria. The Layer-2 band run decomposed giniW:");
    eprintln!("  it tracks population leanness (bondA), not whale capture. A splitting whale");
    eprintln!("  looks egalitarian in gini_psd by design.");
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
        "  bDU = BOOTSTRAP worst deep gap (peak serving deep-under over the run); baPk = peak"
    );
    eprintln!(
        "  bonded-archiver count (baPk - bondA is the OVERSHOOT). L12; all 0/=bondA outside bootstrap."
    );
    eprintln!("  boOld = OLDEST-band gap peak (P3); > bDU ⇒ residual concentrates in the");
    eprintln!("  irreplaceable tail.");
    eprintln!(
        "  feB = FEE-ERA realized purse at end (< budget = subsidy decayed; = ceiling = servo"
    );
    eprintln!("  saturated); fDUpk = worst serving deep gap over the run's 2nd half (death-spiral");
    eprintln!("  read — sustained high = priority-1 failure). L13; =budget/0 outside fee-era.");
    eprintln!("  shkP = post-shock worst serving deep gap; shkRec = epochs the deep tail stayed");
    eprintln!("  over the 0.10 bar after the shock (0 = never breached, -1 = NOT recovered by");
    eprintln!("  run end); shkBA = post-shock bonded-archiver trough. L17; 0 outside shock axis.");
    eprintln!("  extT = deep-shard market-holder-set WIPE-OUT events run-wide (serving holder set");
    eprintln!("  emptied after being seated at depth; sticky per slot until recycle). Under the");
    eprintln!("  foundation retention guarantee (V3_STAKER_ARCHIVAL.md, complete trees held");
    eprintln!("  permanently) these are FOUNDATION-AS-SOLE-SOURCE transitions, not data loss;");
    eprintln!("  shkExt = the post-shock subset. swan-2/W1, re-read swan-4.");
    eprintln!(
        "  extB = shkExt binned by age band at wipe-out (b1/../b5, oldest last). swan-3/W12-13."
    );
    eprintln!(
        "  ssSE = sole-source SHARD-EPOCHS run-wide (deep shards x epochs with the foundation"
    );
    eprintln!(
        "  as only source); ssMxW = longest single-shard sole-source window; ssOpn = windows"
    );
    eprintln!(
        "  still open at run end (market never re-seated). With reseed_rate>0 the re-seed is"
    );
    eprintln!("  foundation-bandwidth-bound (serialized recovery ~ backlog/rate). swan-4.");
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
        "{:<22} {:<18} {:>5} {:>4} {:>5} {:>3} | {:>8} {:>8} {:>8} {:>7} | {:>6} {:>5} | {:>4} {:>4} {:>5} {:>4} {:>4} {:>4} | {:>4} {:>4} {:>6} {:>5} {:>6} {:>6} | {:>6} {:>6} {:>6} | {:>5} {:>6} | {:>5} {:>5} {:>5} | {:>6} {:>6} | {:>5} {:>6} {:>5} {:>4} {:>6} {:>14} {:>5} {:>5} {:>5} | {:>5} {:>6} {:>5} {:>5} | {:>5} {:>5} {:>5} | {:>5} {:>5} {:>5} {:>5}",
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
        "baPk",
        "boOld",
        "feB",
        "fDUpk",
        "shkP",
        "shkRec",
        "shkBA",
        "extT",
        "shkExt",
        "extB",
        "ssSE",
        "ssMxW",
        "ssOpn",
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
            "{:<22} {:<18} {:>5.2} {:>4.1} {:>5} {:>3} | {:>8.3} {:>8.3} {:>8.3} {:>7.4} | {:>6.3} {:>5.3} | {:>4} {:>4} {:>5} {:>4} {:>4} {:>4} | {:>6.2} {:>4} {:>6.3} {:>5} {:>6.3} {:>6.3} | {:>6.3} {:>6.3} {:>6.3} | {:>5.2} {:>6.1} | {:>5.3} {:>5.1} {:>5.3} | {:>6.1} {:>6.3} | {:>5.3} {:>6.0} {:>5.0} {:>4.0} {:>6.0} {:>14} {:>5.0} {:>5.0} {:>5.0} | {:>5.3} {:>6.4} {:>5} {:>5.3} | {:>5.3} {:>5.4} {:>5} | {:>5.3} {:>5.3} {:>5.2} {:>5.3}",
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
            r.bonded_active_peak,
            r.boot_oldest_under_peak,
            r.fee_budget_end,
            r.fee_deep_under_peak,
            r.shock_deep_under_peak,
            r.shock_recovery_epochs,
            r.shock_bonded_trough,
            r.deep_extinct_total,
            r.shock_deep_extinct,
            r.shock_extinct_bands
                .iter()
                .map(|&x| format!("{}", x as usize))
                .collect::<Vec<_>>()
                .join("/"),
            r.sole_source_shard_epochs,
            r.sole_source_max_window,
            r.sole_source_open_end,
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

    let ta1_rows: Vec<_> = results.iter().filter(|r| r.ta1.is_some()).collect();
    if !ta1_rows.is_empty() {
        eprintln!();
        eprintln!("T-A1/T-A2 F1 re-linkage (PHASE_2B §7.7; SEB=10_000 default):");
        eprintln!(
            "  Timeline (diagnostic): baseline sim≥0.90; rotation relink≤baseline (no advantage)."
        );
        eprintln!("  Cohort (gate): mean cohort≥2.0; singleton≤10%. Distinctive: singleton≥50%.");
        eprintln!(
            "{:<22} {:>4} {:>5} {:>5} {:>5} {:>5} {:>5} {:>5} | {:>4} {:>4} {:>4} {:>4} {:>4} {:>4}",
            "scenario",
            "nE",
            "base",
            "relnk",
            "adv",
            "cohrt",
            "sing",
            "cosm",
            "samp",
            "hom",
            "rot",
            "coh",
            "dst",
            "F1",
        );
        for r in &ta1_rows {
            let t = r.ta1.as_ref().unwrap();
            let c = &t.claims;
            eprintln!(
                "{:<22} {:>4} {:>5.3} {:>5.3} {:>5.3} {:>5.1} {:>5.3} {:>5.3} | {:>4} {:>4} {:>4} {:>4} {:>4} {:>4}",
                r.name,
                t.settlement_epochs,
                t.mean_independent_similarity,
                t.lapse_relink_similarity.unwrap_or(-1.0),
                t.lapse_vs_baseline_advantage.unwrap_or(-1.0),
                t.mean_portfolio_cohort_size,
                t.singleton_portfolio_fraction,
                t.cosmetic_overlap.unwrap_or(-1.0),
                yn(c.sample_adequate),
                yn(c.timeline_homogeneous),
                yn(c.rotation_no_timeline_advantage),
                yn(c.cohort_adequate),
                yn(c.distinctive_identifiable),
                yn(c.f1_pass),
            );
        }
        let lean = ta1_rows
            .iter()
            .find(|r| r.name == "ta1_f1_hygiene" || r.name == "ta1_cohort_lean")
            .and_then(|r| r.ta1.as_ref());
        let distinctive = ta1_rows
            .iter()
            .find(|r| r.name == "ta1_cohort_distinctive")
            .and_then(|r| r.ta1.as_ref());
        if let Some(h) = lean {
            eprintln!(
                "  Lean: baseline {:.3}, lapse {:.3}, advantage {:+.3}, cohort {:.1}, singleton {:.3}",
                h.mean_independent_similarity,
                h.lapse_relink_similarity.unwrap_or(-1.0),
                h.lapse_vs_baseline_advantage.unwrap_or(-1.0),
                h.mean_portfolio_cohort_size,
                h.singleton_portfolio_fraction,
            );
        }
        if let Some(d) = distinctive {
            eprintln!(
                "  Distinctive: cohort {:.1}, singleton {:.3} (portfolio threat demo)",
                d.mean_portfolio_cohort_size, d.singleton_portfolio_fraction,
            );
        }
        let shared = ta1_rows
            .iter()
            .find(|r| r.name == "ta1_cohort_shared")
            .and_then(|r| r.ta1.as_ref());
        if let Some(s) = shared {
            eprintln!(
                "  Shared (+ctrl): cohort {:.1}, singleton {:.3} (F1 cohort {})",
                s.mean_portfolio_cohort_size,
                s.singleton_portfolio_fraction,
                if s.claims.f1_pass { "PASS" } else { "FAIL" },
            );
        }
        let f1_pass = lean.map(|t| t.claims.f1_pass).unwrap_or(false);
        eprintln!();
        eprintln!(
            "F1 gate (lean cohort): {}",
            if f1_pass { "PASS" } else { "FAIL" }
        );
    }
}

fn print_failure_confirmation_report(axis_filter: Option<&str>) {
    let report = failure_confirmation::run_full_report(axis_filter);
    if report.scenarios.is_empty() {
        eprintln!(
            "shekyl-staking-sim: no failure-confirmation scenarios matched{}",
            axis_filter
                .map(|p| format!(" --axis={p}"))
                .unwrap_or_default()
        );
        std::process::exit(1);
    }

    eprintln!("shekyl-staking-sim — L14b failure-confirmation Round-1 (ARCHIVAL_FAILURE_CONFIRMATION_PIN.md)");
    eprintln!("Pin: sliding-window m-of-n. Gate: dodge slash (both policies) → binding → volR.");
    eprintln!(
        "Binding: vol_frac={:.5} vol_bind={} lat_bind={} — {}",
        report.binding.volume_fraction_of_block_budget,
        yn(report.binding.volume_binding),
        yn(report.binding.latency_binding),
        report.binding.rationale,
    );
    let pin = &report.policy_pin;
    eprintln!(
        "Policy pin: {} m={} n={} (span>{}) | dodge esc={:.3} slide={:.3} | tuned fs esc={:.3} slide={:.3}",
        pin.chosen_policy,
        pin.chosen_miss_threshold,
        pin.chosen_window_epochs,
        pin.max_single_outage_baselines,
        pin.escalate_dodge_slash_rate,
        pin.sliding_dodge_slash_rate,
        pin.escalate_transient_false_slash,
        pin.tuned_sliding_transient_false_slash,
    );
    for line in &pin.rationale {
        eprintln!("  • {line}");
    }
    eprintln!(
        "Baseline timing: {} | prod: {}",
        report.baseline_timing.sim_baseline_model, report.baseline_timing.production_baseline_model
    );
    eprintln!("Sliding m-sweep (transient fs, m>span):");
    for pt in &report.sliding_m_sweep {
        if pt.above_outage_span {
            eprintln!(
                "  m={} n={} fs={:.3}",
                pt.miss_threshold, pt.window_epochs, pt.transient_false_slash_rate
            );
        }
    }
    eprintln!("Honest P(slash) vs u:");
    for pt in &report.u_sweep {
        eprintln!(
            "  u={:.2}  P_slash_esc={:.3}  P_slash_slide={:.3}",
            pt.uptime_target, pt.escalate_slash_probability, pt.sliding_slash_probability,
        );
    }
    eprintln!();
    eprintln!(
        "{:<32} {:>5} {:>5} {:>5} {:>5} {:>4} {:>4} {:>5} | gate",
        "scenario", "volR", "fsE", "fsS", "fsT", "dEsc", "dSl", "FSM?",
    );
    for r in &report.scenarios {
        eprintln!(
            "{:<32} {:>5.2} {:>5.3} {:>5.3} {:>5.3} {:>4.2} {:>4.2} {:>5} | {}",
            r.name,
            r.decision.volume_ratio,
            r.transient.escalate_false_slash_rate,
            r.transient.sliding_false_slash_rate,
            r.transient.sliding_tuned_false_slash_rate,
            r.dodge.escalate_slash_rate,
            r.dodge.sliding_slash_rate,
            if r.decision.fsm_justified {
                "yes"
            } else {
                "no"
            },
            if r.decision.sliding_window_preferred {
                "slide"
            } else {
                "reopen"
            },
        );
    }

    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("error serializing failure-confirmation report: {e}"),
    }
}

fn print_timing_cluster_report() {
    let report = timing_cluster::verify();
    eprintln!("shekyl-staking-sim — archival timing cluster pin (ARCHIVAL_TIMING_CONSTANTS.md)");
    eprintln!(
        "  W={} epochs (~{:.1} d)  deepest retention={} blocks (~{:.0} d)  reorg_depth={} blocks (~{:.1} h)",
        report.constants.max_claim_age_w,
        report.constants.w_wall_clock_days,
        report.constants.deepest_retention_blocks,
        report.constants.deepest_retention_days,
        report.constants.archival_reorg_depth_blocks,
        report.constants.archival_reorg_depth_days * 24.0,
    );
    eprintln!(
        "  release_cooldown={} epochs  slash_grace={} epochs  prune_epochs={}  couplings+F4: {}",
        report.constants.release_cooldown_epochs,
        report.constants.slash_grace_epochs,
        report.constants.prune_horizon_epochs,
        yn(report.all_pass)
    );
    for c in &report.couplings {
        eprintln!("    {} — {} ({})", yn(c.pass), c.name, c.detail);
    }
    eprintln!(
        "    F4 offline burst — worst offline {} / {} tested: {}",
        report.f4_offline_burst.worst_offline_without_forfeit,
        report.f4_offline_burst.max_offline_epochs_tested,
        yn(report.f4_offline_burst.pass)
    );
    eprintln!(
        "    F4 slow emitter — {}: {}",
        report.f4_slow_emitter.detail,
        yn(report.f4_slow_emitter.pass)
    );
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("error serializing timing cluster report: {e}"),
    }
    if !report.all_pass {
        std::process::exit(1);
    }
}

fn print_standoff_report() {
    let report = standoff::run_full_report();
    eprintln!("shekyl-staking-sim — funding-seam entry-standoff anonymity (ARCHIVAL_FIREWALL_GATE6.md §10.12)");
    eprintln!(
        "Charter: hide P ↔ principal (GF-7), not P ↔ rewards. Background funding-spend rate is a"
    );
    eprintln!("  SWEPT pre-testnet assumption (like fetch_latency_per_unit), not a measurement.");
    eprintln!(
        "Homeostasis: standoff entry latency = window/epoch (epoch={} blk); free ≤ {:.2} epoch.",
        report.settlement_epoch_blocks, report.homeostasis_free_frac_epoch
    );
    eprintln!("  Economic dynamics are epoch-quantized (~13.9 d); obfuscation-useful windows are");
    eprintln!("  minutes-to-hours — two orders smaller, so the standoff is off the economic axis.");
    eprintln!();
    eprintln!(
        "  set = candidate funders (1 target + Poisson background decoys); link = 1/set (uniform);"
    );
    eprintln!("  thin = P(set ≤ 2) (the tail an averaged window hides);");
    eprintln!("  latΕ = entry latency / epoch.");
    eprintln!();
    eprintln!(
        "{:<20} {:<20} {:>6} {:>7} {:>6} {:>4} | {:>6} {:>6} {:>6} {:>6} | {:>7} {:>5}",
        "scenario",
        "axis",
        "win",
        "win_min",
        "rate",
        "shr",
        "setMean",
        "setP05",
        "thin",
        "link",
        "latΕ",
        "free",
    );
    for r in &report.results {
        eprintln!(
            "{:<20} {:<20} {:>6} {:>7.0} {:>6.3} {:>4} | {:>6.2} {:>6.1} {:>6.3} {:>6.3} | {:>7.4} {:>5}",
            r.name,
            r.axis,
            r.window_blocks,
            r.window_minutes,
            r.net_funding_rate_per_block,
            if r.shared_trigger { "Y" } else { "n" },
            r.anon_set_mean,
            r.anon_set_p05,
            r.thin_cover_frac,
            r.link_prob_mean,
            r.entry_latency_frac_epoch,
            if r.homeostasis_free { "Y" } else { "n" },
        );
    }
    eprintln!();
    eprintln!(
        "Recommended window for set≥{:.0} (independent trigger):",
        report.target_anon_set
    );
    eprintln!(
        "{:>8} {:>14} {:>10} {:>10} {:>8} {:>5}",
        "rate", "spend_int_min", "rec_win", "rec_min", "latΕ", "free",
    );
    for rec in &report.recommendations {
        eprintln!(
            "{:>8.3} {:>14.1} {:>10} {:>10.0} {:>8.4} {:>5}",
            rec.net_funding_rate_per_block,
            rec.funding_spend_interval_minutes,
            rec.recommended_window_blocks,
            rec.recommended_window_minutes,
            rec.entry_latency_frac_epoch,
            if rec.homeostasis_free { "Y" } else { "n" },
        );
    }
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("error serializing standoff report: {e}"),
    }
}

/// Render the §19.8 sealing-form grade: interpretation + table to stderr,
/// JSON to stdout (the binary's convention; grading itself is `gf7_seal::run`).
fn print_gf7_seal_report(report: &gf7_seal::GF7SealReport) {
    use gf7_seal::{PooledEstimate, POSTS_PER_PERSONA, WALLETS};

    eprintln!(
        "shekyl-staking-sim — GF-7 leg-(b) SEALING form (ARCHIVAL_BOND_WI4_MEASUREMENT.md §19.8)"
    );
    eprintln!(
        "Receipt-timestamped live-driver re-run: production task+dispatch code path against a"
    );
    eprintln!(
        "  live shekyld --regtest (harness: shekyl-engine-core gf7_sealing_run.rs, gf7-hooks)."
    );
    eprintln!(
        "  Same statistic and bound as §19.4 (circular mean/distance; r = P(link)·(N−1) < {:.1});",
        report.ratio_bound
    );
    eprintln!(
        "  T = {} ms; N = {WALLETS}; chance 1/(N−1) = {:.3}. Clustered SE is run-level (the 10",
        report.tick_ms,
        1.0 / (WALLETS - 1) as f64
    );
    eprintln!("  tasks within a run share arrivals); the two-SE escalation band defers, never");
    eprintln!("  moves the bar (§19.8.4).");
    eprintln!();
    eprintln!("Controls (§19.8.3; either failing grades the session INVALID):");
    for c in &report.controls {
        eprintln!(
            "  [{}] {:<42} P(link)={:.3} baseline={:.3}  ({})",
            if c.passed { "ok" } else { "FAIL" },
            c.name,
            c.p_link,
            c.baseline,
            c.expectation,
        );
    }
    eprintln!(
        "  Receipt-noise floor (sibling phase spread at dispersal 0): {:.1} ms of T = {} ms",
        report.noise_floor_ms, report.tick_ms
    );
    eprintln!();
    eprintln!(
        "  {:<24} {:>4} {:>5} {:>4} | {:>7} {:>6} {:>6} {:>6}",
        "row", "runs", "tasks", "m", "P(link)", "seP", "r", "se_r",
    );
    let row = |label: &str, m: usize, e: &PooledEstimate| {
        eprintln!(
            "  {:<24} {:>4} {:>5} {:>4} | {:>7.3} {:>6.3} {:>6.3} {:>6.3}",
            label, e.runs, e.tasks, m, e.p_link, e.clustered_se_p, e.ratio, e.clustered_se_ratio,
        );
    };
    row("production (GATE)", POSTS_PER_PERSONA, &report.production);
    row("production m=1 context", 1, &report.production_m1_context);
    eprintln!();
    eprintln!("Sealing verdict: {}", report.verdict);

    match serde_json::to_string_pretty(report) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("error serializing gf7-seal report: {e}"),
    }
}

fn print_gf7_timeline_report() {
    let report = gf7_timeline::run_full_report();
    eprintln!("shekyl-staking-sim — GF-7 joint timeline (ARCHIVAL_BOND_WI4_MEASUREMENT.md; WI-4)");
    eprintln!("  The sim's recorder of the production broadcast seam: one principal↔P timeline");
    eprintln!("  through draw_entry_gap and bounded_uniform, all three GF-7 axes recorded. No");
    eprintln!("  correlator and no verdict: the graded round was withdrawn with the order coin.");
    eprintln!(
        "  Axis coverage (one sample timeline): bond-post={} perP={} lifecycle={}.",
        report.coverage.axis_i_bond_post_events,
        report.coverage.axis_ii_per_p_submits,
        report.coverage.axis_iii_lifecycle_events
    );
    eprintln!();

    // Leg-(b) wall-clock sweep-phase arm (measurement doc §19).
    let leg = &report.wallclock_leg;
    eprintln!(
        "Leg-(b) wall-clock sweep-phase arm (§19; WI-3 §3.2 part 3). Tick T={}ms; a-priori",
        leg.tick_ms
    );
    eprintln!(
        "  bound (§19.2, committed before this arm existed): r = P(link)·(N-1) < {:.1} on",
        leg.ratio_bound
    );
    eprintln!(
        "  sibling identification; trials/row={}. Harness-timestamp synthesis (§19.1) —",
        leg.trials
    );
    eprintln!("  the hooks payload ban stays intact; sealing form is the receipt-timestamped");
    eprintln!("  live-driver re-run (named carrier, open).");
    eprintln!("  Controls (§19.3; must both pass or the leg is INVALID):");
    for c in &leg.controls {
        eprintln!(
            "  [{}] {:<28} P(link)={:.3} baseline={:.3}  ({})",
            if c.passed { "ok" } else { "FAIL" },
            c.name,
            c.p_link,
            c.baseline,
            c.expectation,
        );
    }
    eprintln!(
        "  [{}] §19.5 observer-strength tripwire: T/2 at m=52 must FAIL the bound",
        if leg.observer_strength_ok {
            "ok"
        } else {
            "FAIL"
        },
    );
    eprintln!(
        "  {:<16} {:>8} {:>4} {:>4} {:>3} | {:>7} {:>6} {:>5}",
        "group", "disp_ms", "m", "N", "K", "P(link)", "r", "pass",
    );
    for r in &leg.rows {
        eprintln!(
            "  {:<16} {:>8} {:>4} {:>4} {:>3} | {:>7.3} {:>6.2} {:>5}{}",
            r.group,
            r.dispersal_ms,
            r.posts_per_persona,
            r.n,
            r.wallet_size,
            r.p_link,
            r.ratio,
            if r.clears_bound { "Y" } else { "N" },
            if r.gate_relevant { " *" } else { "" },
        );
    }
    eprintln!("  Leg-(b) status: {}", leg.status);
    eprintln!("  A model-consistency check (WI-4 §19.10.2a), not a channel grade.");
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("error serializing gf7-timeline report: {e}"),
    }
}

fn print_clustering_report() {
    use clustering::Regime;
    let regime = |r: Regime| match r {
        Regime::Lean => "lean",
        Regime::Trough => "trough",
    };
    let report = clustering::run_clustering_report();
    eprintln!(
        "shekyl-staking-sim — TM-1 / A0 shard-portfolio linkage across SEQUENTIAL persona rotation"
    );
    eprintln!("The dispersive-default haircut IS the local steepness of the scarcity value-curve: the value a");
    eprintln!("  fresh persona gives up to pick a set DISJOINT from the retired one rather than re-take the top");
    eprintln!("  block. win=disperse window: 0 = CROSS-TIER (spread over the whole value list — charges the");
    eprintln!("  intrinsic g(age) age-premium AND abandons the scarce deep top; the anti-virtuous baseline);");
    eprintln!("  3 = IN-TIER (stay where an independent deep-concentrated operator sits, spread only WHICH deep");
    eprintln!("  shards — isolates the flattenable 1/R). haircut=value fraction given up; steep=top-decile/mean.");
    eprintln!("  MECHANISM: if cross-tier dispersion abandons the deep top, dR FALLS / dVal RISES with α. ROOM");
    eprintln!("  (in-tier feasibility): redun=mean deep R = slack; →1 ⇒ no room regardless of α (honest-degrade).");
    eprintln!();
    eprintln!(
        "{:>7} {:>4} {:>5} {:>5} | {:>7} {:>6} | {:>5} {:>5} {:>6} {:>5} | {:>6}",
        "regime", "win", "alpha", "phi", "haircut", "steep", "dSrv", "dR", "dVal", "dHF", "redun",
    );
    for p in &report.points {
        eprintln!(
            "{:>7} {:>4} {:>5.2} {:>5.2} | {:>7.3} {:>6.2} | {:>5.2} {:>5.2} {:>6.3} {:>5.2} | {:>6.2}",
            regime(p.regime),
            p.spread_window_mult,
            p.alpha,
            p.phi,
            p.haircut,
            p.curve_steepness,
            p.deep_served_frac,
            p.deep_mean_r,
            p.deep_mean_value,
            p.deep_hold_frac,
            p.room_redundancy,
        );
    }
    eprintln!();
    eprintln!("COMPARISON (α=1, φ=0) — cross-tier (anti-virtuous baseline) vs in-tier (faithful):");
    eprintln!(
        "  lean:   cross-tier haircut {:.3}  →  in-tier {:.3}   (deep redundancy {:.2} — room to disperse)",
        report.lean_haircut_a1_crosstier, report.lean_haircut_a1_intier, report.lean_room_redundancy,
    );
    eprintln!(
        "  trough: cross-tier haircut {:.3}  →  in-tier {:.3}   (deep redundancy {:.2} — room {})",
        report.trough_haircut_a1_crosstier,
        report.trough_haircut_a1_intier,
        report.trough_room_redundancy,
        if report.trough_room_redundancy < 1.5 {
            "RUNS OUT: within-tier dispersion has no slack"
        } else {
            "available"
        },
    );
    eprintln!(
        "  Residual after dispersion is the TEMPORAL intersection (clustering the succession over a lifetime)"
    );
    eprintln!("  = T-A1 / TM-2, already instrumented in fingerprint.rs — not a new problem.");
    match report.lean_flip_phi {
        Some(phi) => eprintln!(
            "Per-shard-cost SENSITIVITY (in-tier lean): haircut crosses the floor threshold at φ = {phi:.2}."
        ),
        None => eprintln!(
            "Per-shard-cost SENSITIVITY (in-tier lean): no floor-crossing up to φ = {:.2}.",
            report.phi_max_swept
        ),
    }
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("error serializing clustering report: {e}"),
    }
}

/// F-B1c-c2 disposition-(b) coverage cross-check (`--budget-throttle`) —
/// renders `budget_throttle`'s computed evidence: table to stderr, verdict to
/// stderr, full per-point JSON to stdout. See `budget_throttle.rs` for the
/// model, the emis_frac weighting, and the reopen framing.
fn print_budget_throttle_report() {
    use budget_throttle::{
        evaluate_point, read_budget, transfer_template, BudgetThrottleReport, COVERED_BAR,
        POINTS_SPEC, SEEDS, TRANSFER_BUDGETS,
    };

    let release_min = budget_throttle::release_min_floor();
    let template = transfer_template();

    eprintln!(
        "shekyl-staking-sim --budget-throttle — F-B1c-c2 disposition-(b) coverage cross-check"
    );
    eprintln!("(Part 2; Part 1 = shekyl-economics-sim --fb1c-c2. See budget_throttle.rs header.)");
    eprintln!(
        "Each cell is the mean over {} seeds (knee is a chaotic knife-edge single-seed).",
        SEEDS.len()
    );
    eprintln!();
    eprintln!(
        "m_eff = 1 - emis_frac*(1-{release_min}); (a) budget = base*m_eff, (b) budget = base."
    );
    eprintln!(
        "cDeepU = windowed committed deep under-target (lower better); covered < {COVERED_BAR}."
    );
    eprintln!();
    eprintln!(
        "{:<19} {:>4} {:>8} {:>7} {:>7} {:>8} {:>8} {:>8} {:>8}",
        "regime", "real", "emisFrac", "bud_a", "bud_b", "cDeepU_a", "cDeepU_b", "delta", "verdict"
    );

    let mut points = Vec::new();
    let mut any_material = false;
    for (regime, base, emis_frac, real) in POINTS_SPEC {
        let point = evaluate_point(&template, regime, base, emis_frac, real);
        any_material |= point.material_starvation;
        let verdict = if !real {
            "counterfact"
        } else if point.material_starvation {
            "MATERIAL"
        } else {
            "tolerable"
        };
        eprintln!(
            "{:<19} {:>4} {:>8.3} {:>7.2} {:>7.1} {:>8.4} {:>8.4} {:>+8.4} {:>8}",
            point.regime,
            if real { "yes" } else { "no" },
            point.emis_frac,
            point.read_a.budget,
            point.read_b.budget,
            point.read_a.cdeepu_mean,
            point.read_b.cdeepu_mean,
            point.coverage_delta,
            verdict,
        );
        points.push(point);
    }

    eprintln!();
    eprintln!("Transfer curve (seed-averaged; locates the knee):");
    eprintln!(
        "{:>7} {:>9} {:>10} {:>9} {:>9}",
        "budget", "bondA", "cDeepU", "cDeepUmax", "oUmx"
    );
    let mut transfer_curve = Vec::new();
    for budget in TRANSFER_BUDGETS {
        let r = read_budget(&template, &format!("bt_curve_{budget}"), budget);
        eprintln!(
            "{:>7.1} {:>9.1} {:>10.4} {:>9.4} {:>9.4}",
            r.budget, r.bonda_mean, r.cdeepu_mean, r.cdeepu_max, r.oumx_mean
        );
        transfer_curve.push(r);
    }

    eprintln!();
    if any_material {
        eprintln!(
            "VERDICT: a real operating point shows material starvation under (a) —\n\
             the swing is MATERIAL; disposition (b) reopens (§9.9 rule-21 criterion)."
        );
    } else {
        eprintln!(
            "VERDICT: no real operating point materially degrades under (a).\n\
             - mining_saturated: 0.8x of a co-location-saturated purse stays covered.\n\
             - fee_era_lean: the decayed emission leg makes the throttle ~0.24% — below\n\
               the knee's ~20% and below the seed-noise floor.\n\
             - mining_lean_stress (counterfactual): a full 0.8x on a LEAN purse WOULD\n\
               cross the knee, but that regime does not occur (mining is saturated).\n\
             Swing TOLERABLE => disposition (a) stands."
        );
    }

    let report = BudgetThrottleReport {
        points,
        transfer_curve,
        any_material_starvation: any_material,
    };
    let json = serde_json::to_string_pretty(&report).expect("JSON serialization failed");
    println!("{json}");
}

fn main() {
    if std::env::args().any(|a| a == "--timing-cluster") {
        print_timing_cluster_report();
        return;
    }

    if std::env::args().any(|a| a == "--standoff") {
        print_standoff_report();
        return;
    }

    if std::env::args().any(|a| a == "--gf7-timeline") {
        print_gf7_timeline_report();
        return;
    }

    // Both documented forms: `--gf7-seal=<path>` and `--gf7-seal <path>`.
    // A bare `--gf7-seal` with no path fails loudly — main() otherwise falls
    // through to the default simulation, and a silently-wrong report from the
    // dispersal tripwire is exactly what this mode must never produce.
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args
        .iter()
        .position(|a| a == "--gf7-seal" || a.starts_with("--gf7-seal="))
    {
        let artifact = args[i]
            .strip_prefix("--gf7-seal=")
            .map(str::to_string)
            .or_else(|| args.get(i + 1).cloned())
            .filter(|p| !p.is_empty() && !p.starts_with("--"))
            .unwrap_or_else(|| {
                eprintln!(
                    "--gf7-seal requires an artifact path (--gf7-seal <path> or --gf7-seal=<path>)"
                );
                std::process::exit(2);
            });
        let report = gf7_seal::run(&artifact);
        print_gf7_seal_report(&report);
        return;
    }

    if std::env::args().any(|a| a == "--clustering") {
        print_clustering_report();
        return;
    }

    if std::env::args().any(|a| a == "--budget-throttle") {
        print_budget_throttle_report();
        return;
    }

    let axis_filter = std::env::args().find_map(|a| a.strip_prefix("--axis=").map(str::to_string));

    if std::env::args().any(|a| a == "--failure-confirmation") {
        print_failure_confirmation_report(axis_filter.as_deref());
        return;
    }

    // The reward arm. Production pays linear credited work on its integer
    // operands, bonds every held shard and carries capital on the bond; it is
    // the default. The registered arm runs the configuration L11/L13 were
    // published on (plateau, deep-only bonds, flat carry; `arm_defaults`),
    // reproduces their pins, and is on the retirement list (Appendix B, D1).
    // An unrecognized value fails loudly.
    let reward_arm =
        match std::env::args().find_map(|a| a.strip_prefix("--reward-arm=").map(str::to_string)) {
            None => RewardArm::Production,
            Some(v) => match v.as_str() {
                "production" => RewardArm::Production,
                "registered-plateau" => RewardArm::RegisteredPlateau,
                other => {
                    eprintln!(
                        "shekyl-staking-sim: unknown --reward-arm={other:?} \
                     (expected `production` (default) or `registered-plateau`)"
                    );
                    std::process::exit(2);
                }
            },
        };
    // The registered arm's plateau backend. Integer evaluates the banded curve
    // with `curve_milli`; PR 1.5 (ARCHIVAL_SIM_ECONOMICS_VERDICT.md) showed the
    // float mirror over-reads worst-shard redundancy by up to one replica, so
    // float is opt-in. Production applies no plateau.
    let curve_flag =
        std::env::args().find_map(|a| a.strip_prefix("--curve-impl=").map(str::to_string));
    // The backend selects nothing on the production arm, so a run that names
    // one there would print production output under a backend's label. Refuse it.
    if curve_flag.is_some() && reward_arm != RewardArm::RegisteredPlateau {
        eprintln!(
            "shekyl-staking-sim: --curve-impl selects the registered plateau arm's backend; \
             add --reward-arm=registered-plateau (production credits linear work, no plateau)"
        );
        std::process::exit(2);
    }
    let curve_impl = match curve_flag {
        None => CurveImpl::Integer,
        Some(v) => match v.as_str() {
            "integer" => CurveImpl::Integer,
            "float" => CurveImpl::Float,
            other => {
                eprintln!(
                    "shekyl-staking-sim: unknown --curve-impl={other:?} \
                     (expected `integer` (authoritative, default) or `float` (exploration only))"
                );
                std::process::exit(2);
            }
        },
    };
    match reward_arm {
        RewardArm::Production => eprintln!(
            "shekyl-staking-sim: reward arm = Production (linear credited work, production integer arithmetic; every held shard bonds; capital carry on the bond; the exit waits the release cooldown)"
        ),
        RewardArm::RegisteredPlateau => eprintln!(
            "shekyl-staking-sim: reward arm = RegisteredPlateau (retired plateau, deep-only bonds, flat carry, exit refunded at once; L11/L13 pins' control), curve backend = {curve_impl:?}{}",
            match curve_impl {
                CurveImpl::Integer => " (curve_milli)",
                CurveImpl::Float =>
                    " (float mirror, exploration only; see ARCHIVAL_SIM_ECONOMICS_VERDICT.md)",
            }
        ),
    }

    let mut cfgs: Vec<_> = build_scenarios()
        .into_iter()
        .filter(|c| {
            axis_filter
                .as_ref()
                .is_none_or(|prefix| c.axis.starts_with(prefix))
        })
        .collect();

    for c in &mut cfgs {
        c.curve_impl = curve_impl;
        c.reward_arm = reward_arm;
    }

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
    use crate::model::{bond_age, bond_duration, g_age, r_target, World, AGE_WEIGHT};
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
    fn reconciliation_curve_float_vs_integer() {
        use crate::reward::{curve, CurveImpl, RewardArm, RewardParams};
        use shekyl_archival_retention::WORK_MILLI_SCALE;

        // Two milli quanta: one for the integer backend's milli rounding, one
        // for the float→milli conversion of the comparison input.
        const EPS_CURVE: f64 = 2.0 / WORK_MILLI_SCALE as f64;
        let params = RewardParams {
            budget: 100.0,
            cap: 8.0,
            pseudonym_cost: 0.05,
            age_weight: AGE_WEIGHT,
            curve_impl: CurveImpl::Integer,
            arm: RewardArm::RegisteredPlateau,
        };
        let float_params = RewardParams {
            curve_impl: CurveImpl::Float,
            ..params.clone()
        };

        for tenth in 0..=200 {
            let work = tenth as f64 * 0.1;
            let int_c = curve(work, &params);
            let flt_c = curve(work, &float_params);
            let diff = (int_c - flt_c).abs();
            assert!(
                diff <= EPS_CURVE,
                "work={work}: integer={int_c} float={flt_c} diff={diff}"
            );
        }
    }

    #[test]
    fn reconciliation_plateau_cross_check() {
        use crate::curve::curve_banded;
        use shekyl_archival_retention::{curve_milli, BandedCurveParams, WORK_MILLI_SCALE};

        let banded = BandedCurveParams::from_plateau_value(8_000);
        let int_cap = curve_milli(16_000, &banded);
        let flt_milli = (curve_banded(16.0, 8.0) * WORK_MILLI_SCALE as f64).round() as u64;
        assert_eq!(int_cap, flt_milli);
    }
}
