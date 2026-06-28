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
//! ARCHIVAL_FAILURE_CONFIRMATION_PIN.md).

mod agent;
mod audit;
mod clustering;
mod cover;
mod curve;
mod failure_confirmation;
mod fingerprint;
mod metrics;
mod model;
mod participation;
mod retrieval;
mod reward;
use reward::CurveImpl;
mod scenarios;
mod standoff;
mod timing_cluster;
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
    eprintln!("  shkP = post-shock worst serving deep gap; shkRec = epochs the deep tail stayed");
    eprintln!("  over the 0.10 bar after the shock (0 = never breached, -1 = NOT recovered by");
    eprintln!("  run end); shkBA = post-shock bonded-archiver trough. L17; 0 outside shock axis.");
    eprintln!("  extT = deep-shard market-holder-set WIPE-OUT events run-wide (serving holder set");
    eprintln!("  emptied after being seated at depth; sticky per slot until recycle). Under the");
    eprintln!("  foundation retention guarantee (V3_STAKER_ARCHIVAL.md, complete trees held");
    eprintln!("  permanently) these are FOUNDATION-AS-SOLE-SOURCE transitions, not data loss;");
    eprintln!("  shkExt = the post-shock subset. swan-2/W1, re-read swan-4.");
    eprintln!(
        "  shkExF = post-shock wipe-outs NET OF THE MODELED SERVING FLOOR (counted only when"
    );
    eprintln!(
        "  market holders AND floor are simultaneously zero; = shkExt when floor_replicas=0)."
    );
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
        "{:<22} {:<18} {:>5} {:>4} {:>5} {:>3} | {:>8} {:>8} {:>8} {:>7} | {:>6} {:>5} | {:>4} {:>4} {:>5} {:>4} {:>4} {:>4} | {:>4} {:>4} {:>6} {:>5} {:>6} {:>6} | {:>6} {:>6} {:>6} | {:>5} {:>6} | {:>5} {:>5} {:>5} {:>5} | {:>6} {:>6} | {:>5} {:>6} {:>5} {:>4} {:>6} {:>6} {:>14} {:>5} {:>5} {:>5} | {:>5} {:>6} {:>5} {:>5} | {:>5} {:>5} {:>5} | {:>5} {:>5} {:>5} {:>5}",
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
        "shkP",
        "shkRec",
        "shkBA",
        "extT",
        "shkExt",
        "shkExF",
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
            "{:<22} {:<18} {:>5.2} {:>4.1} {:>5} {:>3} | {:>8.3} {:>8.3} {:>8.3} {:>7.4} | {:>6.3} {:>5.3} | {:>4} {:>4} {:>5} {:>4} {:>4} {:>4} | {:>6.2} {:>4} {:>6.3} {:>5} {:>6.3} {:>6.3} | {:>6.3} {:>6.3} {:>6.3} | {:>5.2} {:>6.1} | {:>5.3} {:>5.3} {:>5.1} {:>5.3} | {:>6.1} {:>6.3} | {:>5.3} {:>6.0} {:>5.0} {:>4.0} {:>6.0} {:>6.0} {:>14} {:>5.0} {:>5.0} {:>5.0} | {:>5.3} {:>6.4} {:>5} {:>5.3} | {:>5.3} {:>5.4} {:>5} | {:>5.3} {:>5.3} {:>5.2} {:>5.3}",
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
            r.shock_deep_under_peak,
            r.shock_recovery_epochs,
            r.shock_bonded_trough,
            r.deep_extinct_total,
            r.shock_deep_extinct,
            r.shock_deep_extinct_floored,
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
        "  W={} epochs (~{:.1} d)  retention={} blocks (~{:.0} d)  reorg_depth={} blocks (~{:.1} h)",
        report.constants.max_claim_age_w,
        report.constants.w_wall_clock_days,
        report.constants.retention_horizon_blocks,
        report.constants.retention_horizon_days,
        report.constants.archival_reorg_depth_blocks,
        report.constants.archival_reorg_depth_days * 24.0,
    );
    eprintln!(
        "  release_cooldown={} epochs  challenge={} blocks  prune_epochs={}  couplings+F4: {}",
        report.constants.release_cooldown_epochs,
        report.constants.challenge_resolution_blocks,
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
    eprintln!("  thin = P(set ≤ 2) (the tail an averaged window hides); invBrk = share where bond");
    eprintln!("  precedes entry (causal 0; inversion ~0.5); latΕ = entry latency / epoch.");
    eprintln!();
    eprintln!(
        "{:<20} {:<20} {:>6} {:>7} {:>6} {:>4} {:>4} | {:>6} {:>6} {:>6} {:>6} | {:>6} {:>7} {:>5}",
        "scenario",
        "axis",
        "win",
        "win_min",
        "rate",
        "inv",
        "shr",
        "setMean",
        "setP05",
        "thin",
        "link",
        "invBrk",
        "latΕ",
        "free",
    );
    for r in &report.results {
        eprintln!(
            "{:<20} {:<20} {:>6} {:>7.0} {:>6.3} {:>4} {:>4} | {:>6.2} {:>6.1} {:>6.3} {:>6.3} | {:>6.2} {:>7.4} {:>5}",
            r.name,
            r.axis,
            r.window_blocks,
            r.window_minutes,
            r.net_funding_rate_per_block,
            if r.inversion { "Y" } else { "n" },
            if r.shared_trigger { "Y" } else { "n" },
            r.anon_set_mean,
            r.anon_set_p05,
            r.thin_cover_frac,
            r.link_prob_mean,
            r.inversion_prior_break,
            r.entry_latency_frac_epoch,
            if r.homeostasis_free { "Y" } else { "n" },
        );
    }
    eprintln!();
    eprintln!(
        "Recommended window for set≥{:.0} (independent trigger, no inversion — conservative):",
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

fn print_cover_report() {
    use cover::Dispersion;
    let disp = |d: Dispersion| match d {
        Dispersion::Clustered => "clust",
        Dispersion::Dispersed => "disp",
    };
    let report = cover::run_full_report();
    eprintln!(
        "shekyl-staking-sim — funding-seam cover-amount anonymity (ARCHIVAL_COVER_DRAW.md §7)"
    );
    eprintln!(
        "Charter: hide principal ↔ P via A = bond_floor + cover. The attacker tests A − bond_floor"
    );
    eprintln!(
        "  ∈ [C_min,C_max]; the candidate set is the k rungs straddling s_P (floor = {:.2} SKL/rung).",
        report.floor_skl
    );
    eprintln!(
        "  Per-rung DENSITY (clustered vs dispersed) is the SWEPT pre-testnet assumption, not a"
    );
    eprintln!("  measurement (the cover analogue of the standoff's background rate).");
    eprintln!();
    eprintln!(
        "  set = candidate funders (1 target + in-window, timing-retained decoys); link = 1/set;"
    );
    eprintln!(
        "  thin = P(set ≤ 2); tax = cover span / bond (k/s_P), worst = the rung-1 staker (§7.3);"
    );
    eprintln!("  rt = timing-retain (§1.1: 1.0 = amount-marginal upper bound).");
    eprintln!();
    eprintln!(
        "{:<24} {:<16} {:>4} {:>5} {:>5} {:>4} {:>4} | {:>7} {:>6} {:>6} {:>6} | {:>6} {:>6}",
        "scenario",
        "axis",
        "n_P",
        "mean",
        "dens",
        "k",
        "rt",
        "covSKL",
        "setMean",
        "setP05",
        "thin",
        "taxMn",
        "taxWst",
    );
    for r in &report.results {
        eprintln!(
            "{:<24} {:<16} {:>4} {:>5.0} {:>5} {:>4} {:>4.1} | {:>7.2} {:>6.2} {:>6.1} {:>6.3} | {:>6.2} {:>6.1}",
            r.name,
            r.axis,
            r.n_p,
            r.mean_shards,
            disp(r.dispersion),
            r.rungs_blurred,
            r.timing_retain,
            r.cover_span_skl,
            r.anon_set_mean,
            r.anon_set_p05,
            r.thin_cover_frac,
            r.tax_mean,
            r.tax_worst,
        );
    }
    eprintln!();
    eprintln!(
        "Saturation-knee pin (thin/dispersed corner): smallest k past which a rung of cover buys"
    );
    eprintln!(
        "  < {:.2} set/rung. The pool saturates (satSet = reachable ceiling), so this is the PIN —",
        report.marginal_cutoff
    );
    eprintln!(
        "  past it capital is wasted and §7.5 opt-out makes it harmful. rt<1.0 is the JOINT corner"
    );
    eprintln!("  (the genesis-pin input); rt=1.0 amount-marginal is only a FLOOR. rch = target reachable.");
    eprintln!(
        "{:>4} {:>8} {:>8} {:>4} {:>8} {:>8} {:>8} {:>7}",
        "rt", "knee_k", "satSet", "rch", "covSKL", "wstTax", "setMean", "thin",
    );
    for rec in &report.recommendations {
        eprintln!(
            "{:>4.1} {:>8} {:>8.2} {:>4} {:>8.2} {:>7.0}x {:>8.2} {:>7.3}",
            rec.timing_retain,
            rec.knee_rungs,
            rec.saturation_set,
            if rec.mean_target_reached { "Y" } else { "n" },
            rec.cover_span_skl,
            rec.worst_tax_multiple,
            rec.anon_set_mean,
            rec.thin_cover_frac,
        );
    }
    eprintln!();
    eprintln!(
        "Economic participation (§7.5): cover-stays-with-P ⇒ a staker funds cover only if C_max ≤"
    );
    eprintln!(
        "  beta x bond (rung ≥ k/beta); below it they take the cover==0 opt-out. Rung is PUBLIC, so"
    );
    eprintln!(
        "  the attacker discounts opt-outs ⇒ realized payer set < honest. optOut = priced-out frac;"
    );
    eprintln!(
        "  pyrSet/pyrThin = realized set/tail for PAYERS; honSet = honest-uniform set (contrast)."
    );
    eprintln!(
        "{:>4} {:>4} {:>7} {:>8} {:>8} {:>8} {:>8} {:>8}",
        "beta", "k", "covSKL", "minRung", "optOut", "pyrSet", "pyrThin", "honSet",
    );
    for p in &report.participation {
        eprintln!(
            "{:>4.1} {:>4} {:>7.2} {:>8} {:>8.3} {:>8.2} {:>8.3} {:>8.2}",
            p.beta,
            p.rungs_blurred,
            p.cover_span_skl,
            p.min_paying_rung,
            p.opt_out_frac,
            p.payer_set_mean,
            p.payer_thin_frac,
            p.honest_set_mean,
        );
    }
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("error serializing cover report: {e}"),
    }
}

fn print_cover_fn_report() {
    use cover::Dispersion;
    let disp = |d: Dispersion| match d {
        Dispersion::Clustered => "clust",
        Dispersion::Dispersed => "disp",
    };
    let report = cover::run_cover_fn_report();
    eprintln!("shekyl-staking-sim — cover §7.6/§7.7: scalar-robustness vs pin-a-function");
    eprintln!("Realized PAYER set under the FULL model (timing × participation), thin N_P corner.");
    eprintln!();

    // (A) Hump robustness across the pessimistic corners.
    eprintln!(
        "(A) Hump across corners (density × timing_retain × beta): k* = realized-set-max dial."
    );
    eprintln!(
        "{:>6} {:>5} {:>5} | {:>6} {:>7}",
        "dens", "rt", "beta", "k*", "peakSet",
    );
    for c in &report.hump.corners {
        eprintln!(
            "{:>6} {:>5.1} {:>5.1} | {:>6} {:>7.2}",
            disp(c.density),
            c.timing_retain,
            c.beta,
            c.k_star,
            c.peak_set,
        );
    }
    eprintln!(
        "  k* spread across corners = {} rungs; robust k = {} holds {:.0}% of peak at the WORST",
        report.hump.k_star_spread,
        report.hump.robust_k,
        report.hump.worst_corner_ratio * 100.0,
    );
    eprintln!(
        "  corner ⇒ a single frozen scalar is {} the 90%-of-peak bar across all corners.",
        if report.hump.robust_band_90 {
            "WITHIN"
        } else {
            "OUTSIDE"
        }
    );
    eprintln!();

    // (B) Adaptive (population-conditioned) dial vs the frozen scalar.
    eprintln!(
        "(B) Adaptive D (per-density k*) vs frozen scalar k={} across sparse→dense (rt=0.5,b=2):",
        report.hump.robust_k
    );
    eprintln!(
        "{:>12} {:>4} {:>5} | {:>4} {:>7} {:>8} | {:>7} {:>8}",
        "level", "n_P", "mean", "ak", "aSet", "aCovSKL", "fSet", "fCovSKL",
    );
    for d in &report.adaptive {
        eprintln!(
            "{:>12} {:>4} {:>5.0} | {:>4} {:>7.2} {:>8.2} | {:>7.2} {:>8.2}",
            d.label,
            d.n_p,
            d.mean_shards,
            d.adaptive_k,
            d.adaptive_set,
            d.adaptive_cover_skl,
            d.frozen_set,
            d.frozen_cover_skl,
        );
    }
    eprintln!("  one frozen scalar can't serve both ends; adaptive sizes to local k* — the gap is");
    eprintln!(
        "  the set the frozen scalar leaves on the table (largest where it under-serves dense)."
    );
    eprintln!();

    // (C) Net-leak bounding proxy.
    eprintln!("(C) Net-leak proxy: a height-aware attacker exploiting per-height D drift across a");
    eprintln!(
        "  timing window. leak = set stripped. Realistic drift ≈ {:.2} (600-blk window / 10k epoch).",
        report.realistic_drift
    );
    eprintln!(
        "{:>6} {:>8} {:>9} {:>8}",
        "drift", "frozSet", "adaptSet", "leak",
    );
    for p in &report.leak {
        eprintln!(
            "{:>6.2} {:>8.2} {:>9.2} {:>7.1}%",
            p.drift,
            p.frozen_set,
            p.adaptive_set,
            p.leak_frac * 100.0,
        );
    }
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("error serializing cover-fn report: {e}"),
    }
}

fn print_cover_targeting_report() {
    let report = cover::run_targeting_report();
    eprintln!("shekyl-staking-sim — statistic DQ: count-uniform vs histogram-per-rung (§7.8/§7.9)");
    eprintln!(
        "Rung-local suppression adversary: withdraw m own bonds (at the victim's rung for the"
    );
    eprintln!("  per-rung response, globally for the uniform one) across a closed epoch, so f's");
    eprintln!(
        "  epoch-close statistic sees the suppressed value. Thin N_P corner; lower set = more"
    );
    eprintln!(
        "  narrowed cover = worse for the victim. MOD = a moderate (targetable) rung; thin rungs the"
    );
    eprintln!(
        "  histogram already concedes and dense rungs swamp the attacker — the middle is where a"
    );
    eprintln!(
        "  rung-local depopulation moves the dial. honest avg local occ (±{} rungs) = {:.2}.",
        report.w_ref, report.honest_avg_local
    );
    eprintln!();
    eprintln!(
        "{:>4} | {:>9} {:>9} | {:>10} {:>10}",
        "m", "cntSet", "histSet", "cntModSet", "histModSet",
    );
    for p in &report.points {
        eprintln!(
            "{:>4} | {:>9.2} {:>9.2} | {:>10.2} {:>10.2}",
            p.attacker_bonds,
            p.count_uniform_set,
            p.histogram_set,
            p.count_uniform_mod_set,
            p.histogram_mod_set,
        );
    }
    eprintln!();
    let fmt_m = |o: Option<u64>| o.map(|m| format!("{m}")).unwrap_or_else(|| ">8".into());
    eprintln!(
        "Attacker bonds to HALVE a moderate victim's set: histogram = {}, count = {}.",
        fmt_m(report.histogram_m_to_halve_mod),
        fmt_m(report.count_m_to_halve_mod),
    );
    eprintln!(
        "Decision: if histogram narrows the moderate victim materially more than count, the per-rung"
    );
    eprintln!("  targeting gain is MATERIAL ⇒ count-uniform confirmed. If neither moves (honest");
    eprintln!("  occupancy swamps the attacker), the histogram is safe to take with eyes open.");
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("error serializing cover-targeting report: {e}"),
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
        "shekyl-staking-sim — TM-1 / A0 cross-persona clustering: dispersive-default viability (C-5)"
    );
    eprintln!("The dispersive-default haircut IS the local steepness of the scarcity value-curve. win=disperse");
    eprintln!(
        "  window: 0 = CROSS-TIER (spread over the whole value list — charges the intrinsic g(age)"
    );
    eprintln!("  age-premium AND abandons the scarce deep top; the kept anti-virtuous baseline); 3 = IN-TIER");
    eprintln!("  (stay where an independent deep-concentrated operator sits, spread only WHICH deep shards —");
    eprintln!("  isolates the flattenable 1/R component). haircut=value fraction given up; steep=top-decile/mean;");
    eprintln!("  coloc=1−intra/baseline persona-centroid spread (0=unclusterable on co-location);");
    eprintln!("  overlap=mean exact sibling overlap (≈0 ⇒ overlap is NOT the signal). MECHANISM: if dispersion");
    eprintln!("  abandons the deep top, dR FALLS / dVal RISES with α. ROOM (in-tier feasibility): redun=mean");
    eprintln!("  deep R = slack to rearrange; →1 ⇒ no room regardless of α (the honest-degradation threshold).");
    eprintln!();
    eprintln!(
        "{:>7} {:>4} {:>5} {:>5} | {:>3} {:>5} | {:>7} {:>6} | {:>6} {:>7} | {:>5} {:>5} {:>6} {:>5} | {:>6}",
        "regime", "win", "alpha", "phi", "k", "equal", "haircut", "steep", "coloc", "overlap", "dSrv",
        "dR", "dVal", "dHF", "redun",
    );
    for p in &report.points {
        eprintln!(
            "{:>7} {:>4} {:>5.2} {:>5.2} | {:>3} {:>5} | {:>7.3} {:>6.2} | {:>6.3} {:>7.3} | {:>5.2} {:>5.2} {:>6.3} {:>5.2} | {:>6.2}",
            regime(p.regime),
            p.spread_window_mult,
            p.alpha,
            p.phi,
            p.split_k,
            p.split_equal,
            p.haircut,
            p.curve_steepness,
            p.colocation_signal,
            p.exact_overlap,
            p.deep_served_frac,
            p.deep_mean_r,
            p.deep_mean_value,
            p.deep_hold_frac,
            p.room_redundancy,
        );
    }
    eprintln!();
    eprintln!(
        "COMPARISON (α=1, φ=0, k=2) — cross-tier (anti-virtuous baseline) vs in-tier (faithful):"
    );
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
        "  AIMING READ: point the matcher at the regime where in-tier drives the haircut toward 0 (portfolios"
    );
    eprintln!(
        "  decorrelated) — that is where 'does the PARTITION still leak despite decorrelation?' is the real test."
    );
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

fn print_matcher_report() {
    let report = clustering::run_matcher_report();
    eprintln!(
        "shekyl-staking-sim — TM-1 / A0 sibling-clustering MATCHER (C0 chain observer, lean attractor,"
    );
    eprintln!(
        "  α=1, in-tier/decorrelated portfolios). Pairwise 'same operator?' discrimination AUC:"
    );
    eprintln!("  0.5 = indistinguishable from independent operators; →1 = siblings trivially regroupable.");
    eprintln!("  null = AUC under SHUFFLED operator labels (must be ≈0.5 — the measured baseline, not assumed).");
    eprintln!("  Read AUCs AGAINST null, not 0.5. ABLATION: portf = which-shards features only; part = split");
    eprintln!(
        "  (size+onset) features only; full = both; Δ = full−portf (how much the PARTITION adds)."
    );
    eprintln!("  HETEROGENEITY: if part AUC stays high across varied/stagger/hetK ⇒ STRUCTURAL leak (disclose);");
    eprintln!("  if heterogeneity collapses it toward null ⇒ BLUR-ABLE (mitigation: heterogeneous staggered splits).");
    eprintln!();
    eprintln!("  DECOMPOSITION: size = equal-split size-similarity (killed by VARIED splits); onset = co-timing");
    eprintln!("  (killed by STAGGER — but partly a modelling choice). size near null + onset high ⇒ onset-driven");
    eprintln!("  (behavioural, blur-able); size high ⇒ intrinsic to equal splitting (structural).");
    eprintln!();
    eprintln!(
        "{:>30} | {:>6} | {:>6} {:>6} {:>6} | {:>6} {:>6} | {:>6}",
        "scenario", "portf", "part", "size", "onset", "full", "null", "Δpart",
    );
    for r in &report.rows {
        eprintln!(
            "{:>30} | {:>6.3} | {:>6.3} {:>6.3} {:>6.3} | {:>6.3} {:>6.3} | {:>6.3}",
            r.label,
            r.auc_portfolio,
            r.auc_partition,
            r.auc_size,
            r.auc_onset,
            r.auc_full,
            r.auc_null,
            r.ablation_delta,
        );
    }
    eprintln!();
    let regular = report.rows.first();
    let blurred = report
        .rows
        .iter()
        .find(|r| r.label.contains("varied+stagger+hetK"));
    if let (Some(reg), Some(blur)) = (regular, blurred) {
        eprintln!(
            "READ: regular split — portfolio AUC {:.3} (vs null {:.3}), partition AUC {:.3}, full {:.3}.",
            reg.auc_portfolio, reg.auc_null, reg.auc_partition, reg.auc_full,
        );
        eprintln!(
            "  ablation Δ(partition adds) = {:.3}: {}",
            reg.ablation_delta,
            if reg.ablation_delta > 0.10 && reg.auc_portfolio < reg.auc_null + 0.10 {
                "the PARTITION is the signal, shards near null — dispersing shards is the easy half."
            } else if reg.auc_portfolio > reg.auc_null + 0.15 {
                "the SHARDS still leak (in-tier did not fully decorrelate) — it is BOTH."
            } else {
                "mixed — see the numbers."
            },
        );
        eprintln!(
            "  heterogeneity: full AUC regular {:.3} → varied+stagger+hetK {:.3} ({}).",
            reg.auc_full,
            blur.auc_full,
            if blur.auc_full < reg.auc_null + 0.10 {
                "collapses toward null ⇒ BLUR-ABLE: heterogeneous staggered splits are a real mitigation"
            } else {
                "stays above null ⇒ STRUCTURAL: the partition leak is not fixed by heterogeneity — DISCLOSE"
            },
        );
    }
    // Check B — full-range onset stagger: is the onset sub-channel a user-lever?
    if let Some(full_stag) = report.rows.iter().find(|r| r.label.contains("FULL-range")) {
        eprintln!(
            "CHECK B (full-range onset stagger): onset AUC {:.3} (vs null {:.3}) — {}",
            full_stag.auc_onset,
            full_stag.auc_null,
            if full_stag.auc_onset < full_stag.auc_null + 0.10 {
                "collapses to null ⇒ onset is a USER-CONTROLLABLE lever (stagger by default); only cardinality remains."
            } else {
                "stays up ⇒ onset is a SECOND irreducible channel, not just a co-timing artifact."
            },
        );
    }
    // Check A — does the size-AUC re-inflation track the K-mix (mechanism not seed)?
    eprintln!(
        "CHECK A (heterogeneous-K mechanism): size-AUC vs high-K fraction, across {} seeds —",
        report
            .hetk_mechanism
            .first()
            .map(|p| p.n_seeds)
            .unwrap_or(0)
    );
    eprintln!("  mechanism predicts size-AUC FALLS as high-K fraction rises (less K=1 background to stand out against):");
    eprintln!("  {:>10} | {:>10} {:>8}", "highK_frac", "size_AUC", "±std");
    for p in &report.hetk_mechanism {
        eprintln!(
            "  {:>10.2} | {:>10.3} {:>8.3}",
            p.high_k_fraction, p.mean_size_auc, p.std_size_auc
        );
    }
    if let (Some(lo), Some(hi)) = (report.hetk_mechanism.first(), report.hetk_mechanism.last()) {
        eprintln!(
            "  trend: size-AUC {:.3} @ frac {:.2} → {:.3} @ frac {:.2} ({}).",
            lo.mean_size_auc,
            lo.high_k_fraction,
            hi.mean_size_auc,
            hi.high_k_fraction,
            if lo.mean_size_auc > hi.mean_size_auc + 0.05 {
                "TRACKS — mechanism confirmed, the structural cardinality claim is bulletproof"
            } else {
                "does NOT track — re-inflation may be seed-soft; 'structural' weakens to 'under uniform K'"
            },
        );
    }
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("error serializing matcher report: {e}"),
    }
}

fn print_cover_dispersion_report() {
    use cover::Dispersion;
    let shape = |d: Dispersion| match d {
        Dispersion::Clustered => "clustered",
        Dispersion::Dispersed => "dispersed",
    };
    let report = cover::run_dispersion_report();
    eprintln!("shekyl-staking-sim — statistic DQ: does count need the dispersion scalar? (§7.9)");
    eprintln!("Count alone can't tell clustered from dispersed (same N_P, different spread → same");
    eprintln!(
        "  uniform D). A global dispersion scalar (occupied-rungs) converts count → density. We"
    );
    eprintln!(
        "  size for target set {:.0} at the thin N_P corner; count-only assumes a fixed reference",
        report.target_set
    );
    eprintln!(
        "  span ({:.1}), count+disp reads the realised occupied-rungs. set = victim realised set.",
        report.span_ref
    );
    eprintln!();
    eprintln!(
        "{:>10} {:>8} | {:>8} {:>8} | {:>8} {:>8}",
        "shape", "occRung", "cntWid", "cntSet", "dispWid", "dispSet",
    );
    for r in &report.rows {
        eprintln!(
            "{:>10} {:>8.1} | {:>8.1} {:>8.2} | {:>8.1} {:>8.2}",
            shape(r.shape),
            r.occ_rungs,
            r.width_count_only,
            r.set_count_only,
            r.width_count_disp,
            r.set_count_disp,
        );
    }
    eprintln!();
    eprintln!(
        "Clustered↔dispersed realised-set gap: count-only = {:.2}, count+dispersion = {:.2}.",
        report.gap_count_only, report.gap_count_disp
    );
    eprintln!(
        "Decision: if count-only leaves a material gap that count+dispersion closes, the scalar"
    );
    eprintln!("  earns its place (still global ⇒ targeting-resistant, §7.9). If the gap is small,");
    eprintln!("  count alone suffices — take the simpler statistic.");
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("error serializing cover-dispersion report: {e}"),
    }
}

fn print_cover_magnitudes_report() {
    let report = cover::run_magnitude_report();
    eprintln!("shekyl-staking-sim — §8 magnitude pass: K_sat(C) + derived C_boot (JOINT corner)");
    eprintln!(
        "Joint pessimistic corner: dispersed, timing_retain={:.1}, beta={:.0}, mean={:.0} (count is",
        report.timing_retain, report.beta, report.mean_shards
    );
    eprintln!(
        "  the x-axis). kSat = saturation knee at this count; covSKL = K_sat·floor; setKnee = joint"
    );
    eprintln!(
        "  set there; base = k=0 (C_min-only) baseline; gain = setKnee−base; plat = robust plateau"
    );
    eprintln!(
        "  width (dial rungs within 90% of peak — narrow ⇒ sharp optimum ⇒ widen conservatism)."
    );
    eprintln!();
    eprintln!(
        "{:>5} | {:>5} {:>7} {:>8} {:>6} {:>6} {:>6}",
        "C", "kSat", "covSKL", "setKnee", "base", "gain", "plat",
    );
    for r in &report.rows {
        eprintln!(
            "{:>5} | {:>5} {:>7.2} {:>8.2} {:>6.2} {:>6.2} {:>6}",
            r.count,
            r.k_sat,
            r.cover_span_skl,
            r.set_at_knee,
            r.baseline_set,
            r.set_gain,
            r.plateau_width_rungs,
        );
    }
    eprintln!();
    match report.c_boot_continuity {
        Some(c) => eprintln!(
            "C_boot (recommended) = {c}: first count with K_sat>0; below it K_sat=0, so k(C)=K_sat(C) \
             is CONTINUOUS through the boundary (cover span at it = {:.2} SKL ramps up from 0 — no",
            report.c_boot_continuity_cover_span_skl
        ),
        None => eprintln!("K_sat is 0 at every swept count — the joint corner buys no usable cover."),
    }
    eprintln!(
        "  step). The bootstrap clause is the k=0 TAIL of K_sat, not a glued floor (§8.4/§8.5)."
    );
    if let Some(cs) = report.c_substantial {
        eprintln!(
            "  Context: cover becomes 'substantial' (gain ≥ baseline) only at C={cs} — but conceding"
        );
        eprintln!("  up to there would re-introduce the step (K_sat already large), so it is NOT the cutoff.");
    }
    eprintln!("  C_min is economic (runway, 2d-1 ramp) — out of this arm.");
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("error serializing cover-magnitudes report: {e}"),
    }
}

fn print_cover_dial_report() {
    // The §8.8 float-free k(C) form: cover span (C_max−C_min) vs count C. The
    // dial k = span/floor (floor = 0.75 SKL). Cubic-smoothstep: decays to 0 in the
    // tail (no clamp kink) and joins the cap with zero slope — integer-exact.
    eprintln!("shekyl-staking-sim — §8.8 k(C) form: cover span vs count (float-free smoothstep)");
    eprintln!(
        "span = C_max−C_min (atomic); kEff = span/floor rungs (floor=0.75 SKL). Decays to 0 below"
    );
    eprintln!("  C=13, caps at 7.5 SKL above C=79, with zero slope at both ends (no kink, §8.4).");
    eprintln!();
    eprintln!(
        "{:>5} | {:>13} {:>9} {:>7}",
        "C", "span(atomic)", "spanSKL", "kEff"
    );
    let floor_atomic = 750_000_000u64;
    for c in [0u64, 13, 14, 16, 20, 25, 33, 46, 60, 79, 100, 154] {
        let span = cover::cover_dial_span_atomic(c);
        eprintln!(
            "{:>5} | {:>13} {:>9.3} {:>7.2}",
            c,
            span,
            span as f64 / 1e9,
            span as f64 / floor_atomic as f64,
        );
    }
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

    if std::env::args().any(|a| a == "--cover") {
        print_cover_report();
        return;
    }

    if std::env::args().any(|a| a == "--cover-fn") {
        print_cover_fn_report();
        return;
    }

    if std::env::args().any(|a| a == "--cover-targeting") {
        print_cover_targeting_report();
        return;
    }

    if std::env::args().any(|a| a == "--cover-dispersion") {
        print_cover_dispersion_report();
        return;
    }

    if std::env::args().any(|a| a == "--cover-magnitudes") {
        print_cover_magnitudes_report();
        return;
    }

    if std::env::args().any(|a| a == "--cover-dial") {
        print_cover_dial_report();
        return;
    }

    if std::env::args().any(|a| a == "--clustering") {
        print_clustering_report();
        return;
    }

    if std::env::args().any(|a| a == "--matcher") {
        print_matcher_report();
        return;
    }

    let axis_filter = std::env::args().find_map(|a| a.strip_prefix("--axis=").map(str::to_string));

    if std::env::args().any(|a| a == "--failure-confirmation") {
        print_failure_confirmation_report(axis_filter.as_deref());
        return;
    }

    // Integer is the authoritative backend: it is what the emission vin mints
    // money with at zero tolerance (REWARD_EMISSION_VIN_PLAN.md §5.4), and PR 1.5
    // (ARCHIVAL_SIM_ECONOMICS_VERDICT.md) showed float over-reads worst-shard
    // redundancy by up to one replica. So sweeps default to integer; float is
    // opt-in exploration only. An unrecognized value fails loudly rather than
    // silently falling back to the non-authoritative backend.
    let curve_impl =
        match std::env::args().find_map(|a| a.strip_prefix("--curve-impl=").map(str::to_string)) {
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
    eprintln!(
        "shekyl-staking-sim: curve backend = {curve_impl:?}{}",
        match curve_impl {
            CurveImpl::Integer => " (authoritative — canonical reward_arithmetic)",
            CurveImpl::Float =>
                " (exploration only — NOT authoritative; see ARCHIVAL_SIM_ECONOMICS_VERDICT.md)",
        }
    );

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

    #[test]
    fn reconciliation_curve_float_vs_integer() {
        use crate::reward::{curve, CurveImpl, RewardParams};
        use shekyl_archival_retention::WORK_MILLI_SCALE;

        // Two milli quanta: one for the integer backend's milli rounding, one
        // for the float→milli conversion of the comparison input.
        const EPS_CURVE: f64 = 2.0 / WORK_MILLI_SCALE as f64;
        let params = RewardParams {
            budget: 100.0,
            cap: 8.0,
            pseudonym_cost: 0.05,
            age_weight: 2.0,
            curve_impl: CurveImpl::Integer,
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

        let banded = BandedCurveParams::from_sim_cap_milli(8_000);
        let int_cap = curve_milli(16_000, &banded);
        let flt_milli = (curve_banded(16.0, 8.0) * WORK_MILLI_SCALE as f64).round() as u64;
        assert_eq!(int_cap, flt_milli);
    }
}
