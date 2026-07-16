//! Exit-seam standoff sweep — the F-D4 §8 pre-registered arms
//! (`docs/design/ARCHIVAL_EXIT_STANDOFF_FD4_WINDOW.md`; Gate-6 §12.5/§12.8).
//!
//! The window's *value* is sealed by the Phase 7.7 stressnet read through the
//! §5.4 frozen rule; this harness is the **pre-registered instrument** that
//! read runs through. Today's run grades the shipped mechanism
//! (`draw_exit_gap` — the same code path the wallet runs, parameterized via
//! `kat_inject` because the window is still the provisional sentinel) against
//! the §5.1 planning box, and supplies the §5.3 lever-vs-queue costing its
//! numbers. Nothing here seals anything: `ρ_x`, `σ_L`, `N_x` are **swept
//! pre-testnet assumptions, not measurements** (the entry harness's
//! conditionality caveat, verbatim).
//!
//! **The arms (F-D4 §8, pre-registered so the harness is built to the bar):**
//!
//! 1. **X-1** — lone exit against swept `ρ_x`, graded `r = P(link) · N <
//!    RATIO_BOUND` at the exit-derived anchor and across the WI-4 N-sweep
//!    (`r < 2` at every swept `N`, not only 10 — §13.4). `W` per row comes
//!    from the §5.4 **frozen rule** ([`frozen_rule_window`]), so the sweep
//!    exercises the exact rule the seal will apply.
//! 2. **X-2** — synchronized crisis cohort (`N_x ∈ {3, 5, 8}`), one-anchor
//!    and two-anchor splits per the §3 quantization lemma, swept `σ_L`;
//!    grades intra-cohort assignment. Two-anchor rows additionally grade the
//!    **X-3 coverage boundary**: measured cross-anchor mixing at the straddle
//!    against the predicted mixed fraction `(W − SEB)/W` (§5.2a) — the arm
//!    certifies *mixes-at-all* and reports the fraction; it never certifies
//!    "merged".
//! 3. **Shared-trigger negative control** (§8.3): a cohort with the draw
//!    disabled must be *caught* as clustered (clustering-detection, not the
//!    entry's inversion-detection). Note the assignment observer alone cannot
//!    catch it — identical release heights are mutually blind — which is
//!    exactly why the control keys on clustering; a harness that cannot fail
//!    this control certifies nothing.
//! 4. **Thin-regime bias arm** (§8.4): realized gap-position statistics at
//!    the trough row (the exit-seam analogue of the entry's `1.86` finding —
//!    the one-sided draw has no order coin, so the graded question is whether
//!    the realized positions stay unbiased at small effective populations).
//! 5. **Threshold ordering** (§8.5): every graded row uses the committed
//!    `r < RATIO_BOUND` (imported from the WI-4 correlator — one bar, one
//!    home); worst row reported; no post-hoc thresholds (GF7 §5.1).
//!
//! **The observer (pre-registered here, before any row ran).** Modeled S-3,
//! specialized per F-D4 §2: the adversary sees every release height (public,
//! `P_id`-keyed) and the principal-side re-appearance timing; FCMP++ hides
//! the value path, so the channel is timing only. The principal re-appears at
//! `T = R + L` with wallet-drawn latency `L ~ U[0, σ_L]` (the §5.2 discipline;
//! max-entropy bounded, distribution public, draw private). Given `T`, every
//! release `R'` with `0 ≤ T − R' ≤ σ_L` is **exactly equally likely** under
//! the model (uniform `L`, uniform draw, stationary background), so the
//! support-gated uniform guess *is* the exact Bayes observer — not a
//! simplification. `P(link) = E[1/|support|]`.
//!
//! **The headline structural consequence — stated, not buried.** Under this
//! observer the *delivered* X-1 cover is `ρ_x × σ_L` (releases inside the
//! latency support), **not** the §5.1 nominal `ρ_x × W` (releases inside the
//! window): the window de-quantizes the release process (without the draw the
//! background piles onto epoch anchors — the negative control's failure mode,
//! network-wide) and buys the X-3 anchor merge, but the latency-gated
//! confusability that X-1 grades is bought by `σ_L`. The report carries both
//! covers per row plus the `σ_L` each row would *require* to clear the bar
//! ([`required_sigma_l`]), so the §5.3 lever-vs-queue costing prices the
//! actual constraint. Rows that fail are reported failing — a failed row is a
//! decorrelation-redesign signal, never a move-the-bar signal (GF7 §5.1).
//!
//! Constant discipline: [`EXIT_TARGET_ANON_SET`] is minted **here**, at its
//! consumer, numerically equal to the entry `TARGET_ANON_SET` by the §13
//! derivation (convergence, not inheritance) and independently movable
//! (F-D4 §13.4's concrete carrier is this module).

use serde::Serialize;

use shekyl_standoff::{bounded_uniform, draw_exit_gap, ExitGapWindow};

use crate::gf7_timeline::RATIO_BOUND;
use crate::standoff::SplitMix64;
use crate::timing_cluster::SETTLEMENT_EPOCH_BLOCKS;

/// The exit-seam anonymity-set anchor — F-D4 §13: `N_t(exit) = 10`, derived
/// a-priori for the exit adversary (equal to the entry seam's
/// `standoff::TARGET_ANON_SET` by convergence, not inheritance; §13.4 mints
/// it as its own constant precisely so the two seams can move independently).
pub const EXIT_TARGET_ANON_SET: u64 = 10;

/// The §5.1 planning-box `ρ_x` corners plus the round-1 interior planning
/// instance (kept for the §10 audit trail): `ρ_x = N_P × c / SEB` at
/// `(N_P, c)` = (79, 0.02), (80, 0.05), (154, 0.20). SWEPT pre-testnet
/// assumptions — the stressnet read replaces them (§5.4 seal event).
pub const RHO_X_BOX: [f64; 3] = [1.58e-4, 4.0e-4, 3.08e-3];

/// The §5.4 frozen decision rule, encoded once so the seal applies code, not
/// prose: `W := the smallest multiple of SETTLEMENT_EPOCH_BLOCKS ≥
/// max((N_t − 1)/ρ_x, 2 × SEB)`. The first term is the X-1 rate-driven bound
/// (§5.1); the second is the X-3 anchor-merge bound (§5.2a, rate-independent).
pub fn frozen_rule_window(rho_x: f64, n_t: u64) -> u64 {
    assert!(rho_x > 0.0, "frozen rule requires a positive exit rate");
    assert!(n_t >= 1, "anonymity target must be at least the exiter");
    let x1 = ((n_t - 1) as f64 / rho_x).ceil() as u64;
    let x3 = 2 * SETTLEMENT_EPOCH_BLOCKS;
    x1.max(x3).div_ceil(SETTLEMENT_EPOCH_BLOCKS) * SETTLEMENT_EPOCH_BLOCKS
}

/// The smallest `σ_L` (blocks) at which the support-gated observer's X-1 row
/// clears `r < RATIO_BOUND` at cover target `n`: solves
/// `E[1/(1 + Pois(λ))] = (1 − e^{−λ})/λ ≤ RATIO_BOUND/n` for `λ = ρ_x·σ_L`
/// by bisection (the expectation is exact for Poisson support counts). This
/// is the number the §5.3 lever-vs-queue costing needs: what the wallet
/// discipline must actually hold, under the pre-registered observer.
pub fn required_sigma_l(rho_x: f64, n: u64) -> u64 {
    assert!(rho_x > 0.0);
    let bar = RATIO_BOUND / n as f64;
    if bar >= 1.0 {
        return 0; // blind guessing already clears the bound at this N
    }
    // E[1/(1+Pois(λ))] = (1 − e^{−λ})/λ, monotone decreasing in λ.
    let f = |lambda: f64| (1.0 - (-lambda).exp()) / lambda;
    let (mut lo, mut hi) = (1e-9, 1e6);
    for _ in 0..200 {
        let mid = 0.5 * (lo + hi);
        if f(mid) > bar {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    (hi / rho_x).ceil() as u64
}

// ---------------------------------------------------------------------------
// X-1 — steady-state lone exit
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ExitX1Config {
    pub name: String,
    /// Background exit-class event rate (events/block, network-wide). SWEPT.
    pub rho_x: f64,
    /// The N-sweep point: the cover target this row grades `r` against, and
    /// the `N_t` fed to the frozen rule to size this row's window.
    pub n: u64,
    /// Principal-side re-appearance spread (blocks). SWEPT design lever.
    pub sigma_l: u64,
    /// Window from the frozen rule at (`rho_x`, `n`).
    pub window: u64,
    pub trials: u64,
    pub seed: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExitX1Result {
    pub name: String,
    pub rho_x: f64,
    pub n: u64,
    pub sigma_l: u64,
    pub window: u64,
    /// §5.1 nominal cover — exit-class events inside the window (`ρ_x × W`).
    pub nominal_window_cover: f64,
    /// Delivered cover under the latency-gated observer — mean support size
    /// (`1 + ρ_x × σ_L` analytically; the MC confirms).
    pub delivered_support_mean: f64,
    /// Exact-Bayes single-guess link probability, `E[1/|support|]`.
    pub p_link: f64,
    /// Advantage ratio `r = P(link) · n`; `< RATIO_BOUND` is the bar.
    pub ratio: f64,
    pub clears_bound: bool,
    /// The `σ_L` this (`ρ_x`, `n`) would require to clear the bar — the §5.3
    /// lever's real price under the pre-registered observer.
    pub required_sigma_l: u64,
}

fn run_x1(cfg: &ExitX1Config) -> ExitX1Result {
    assert!(cfg.trials > 0);
    let window = ExitGapWindow::kat_inject(cfg.window);
    let mut rng = SplitMix64(cfg.seed);
    let mut support_sum = 0.0;
    let mut link_sum = 0.0;
    for _ in 0..cfg.trials {
        // Exercise the real shipped draw (single-sourcing: the harness fails
        // if the draw itself breaks). Under the stationary background the
        // target's drawn *position* does not move the support count — that
        // W-independence is the arm's headline finding (module docs); the
        // draw's realized positions feed the thin-regime arm's statistics.
        let _gap = draw_exit_gap(window, &mut rng);
        // Support = the target + background releases inside [T − σ_L, T].
        // Background releases are stationary at ρ_x *because* every wallet
        // runs the draw (the window smears the anchor quantization; the
        // negative control shows the piled alternative).
        let bg = rng.poisson(cfg.rho_x * cfg.sigma_l as f64);
        let support = 1.0 + bg as f64;
        support_sum += support;
        link_sum += 1.0 / support;
    }
    let p_link = link_sum / cfg.trials as f64;
    let ratio = p_link * cfg.n as f64;
    ExitX1Result {
        name: cfg.name.clone(),
        rho_x: cfg.rho_x,
        n: cfg.n,
        sigma_l: cfg.sigma_l,
        window: cfg.window,
        nominal_window_cover: cfg.rho_x * cfg.window as f64,
        delivered_support_mean: support_sum / cfg.trials as f64,
        p_link,
        ratio,
        clears_bound: ratio < RATIO_BOUND,
        required_sigma_l: required_sigma_l(cfg.rho_x, cfg.n),
    }
}

// ---------------------------------------------------------------------------
// X-2 — crisis cohort (the L17/W8 wargame arm) + X-3 coverage boundary
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ExitX2Config {
    pub name: String,
    /// Trough cohort size (L17 swan table: 9–25 bonded × ~30 % exit ⇒ 3–8).
    pub n_x: u64,
    /// Two-anchor split per the §3 lemma (`E`/`E − 1` seam, anchors SEB
    /// apart) vs the fully-shared single anchor.
    pub two_anchor: bool,
    /// Principal-side re-appearance spread (blocks). SWEPT design lever.
    pub sigma_l: u64,
    /// Candidate window (a frozen-rule output at a box corner).
    pub window: u64,
    /// Draw disabled = the §8.3 shared-trigger negative-control world.
    pub draw_disabled: bool,
    pub worlds: u64,
    pub seed: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExitX2Result {
    pub name: String,
    pub n_x: u64,
    pub two_anchor: bool,
    pub sigma_l: u64,
    pub window: u64,
    pub draw_disabled: bool,
    /// Mean per-query correct-assignment probability under the support-gated
    /// exact-Bayes observer (uniform over support).
    pub p_assign: f64,
    /// `r = P(assign) · N_x`; `< RATIO_BOUND` is the bar (blind = 1).
    pub ratio: f64,
    pub clears_bound: bool,
    /// Two-anchor rows: measured fraction of early-anchor draws landing past
    /// the adjacent anchor (`s ≥ SEB` — the overlap zone). X-3's empirical
    /// mixed fraction; certifies *mixes-at-all*, never "merged".
    pub measured_overlap_frac: f64,
    /// The §5.2a prediction `(W − SEB)/W` (0 when `W ≤ SEB`).
    pub predicted_overlap_frac: f64,
    /// Two-anchor rows: fraction of queries whose support contains at least
    /// one cross-anchor release (cross-anchor confusability realized).
    pub cross_anchor_confusion: f64,
    /// Clustering statistic: mean (over worlds) share of cohort releases
    /// sharing one exact height. Drawn cohorts disperse (→ ~1/N_x floor from
    /// the max of singletons); a draw-skipping cohort piles to 1.0 — the
    /// §8.3 control's detector.
    pub max_same_height_share: f64,
    /// Thin-regime bias statistics (§8.4) over this row's realized draws:
    /// mean gap as a fraction of the window (unbiased ⇒ ≈ 0.5)…
    pub gap_mean_frac: f64,
    /// …and the share of draws in the window's upper half (unbiased ⇒ ≈ 0.5).
    pub gap_upper_half_share: f64,
}

fn run_x2(cfg: &ExitX2Config) -> ExitX2Result {
    assert!(cfg.worlds > 0 && cfg.n_x > 0);
    let window = ExitGapWindow::kat_inject(cfg.window);
    let seb = SETTLEMENT_EPOCH_BLOCKS;
    let mut rng = SplitMix64(cfg.seed);

    let n = cfg.n_x as usize;
    let mut assign_sum = 0.0;
    let mut queries = 0u64;
    let mut early_draws = 0u64;
    let mut early_overlap = 0u64;
    let mut cross_confused = 0u64;
    let mut same_height_share_sum = 0.0;
    let mut gap_frac_sum = 0.0;
    let mut gap_upper = 0u64;
    let mut gaps_total = 0u64;

    let mut anchors: Vec<u64> = Vec::with_capacity(n);
    let mut releases: Vec<u64> = Vec::with_capacity(n);
    for _ in 0..cfg.worlds {
        anchors.clear();
        releases.clear();
        for i in 0..n {
            // Two-anchor split: alternate members across the E/E−1 seam
            // (anchors exactly SEB apart per the §3 quantization lemma).
            let anchor = if cfg.two_anchor && i % 2 == 1 { seb } else { 0 };
            let s = if cfg.draw_disabled {
                0 // the shared-trigger failure: everyone posts at H_0
            } else {
                draw_exit_gap(window, &mut rng).blocks()
            };
            if !cfg.draw_disabled {
                gap_frac_sum += s as f64 / cfg.window as f64;
                if s > cfg.window / 2 {
                    gap_upper += 1;
                }
                gaps_total += 1;
                if anchor == 0 {
                    early_draws += 1;
                    if s >= seb {
                        early_overlap += 1;
                    }
                }
            }
            anchors.push(anchor);
            releases.push(anchor + s);
        }

        // Clustering detector (§8.3): the largest share of cohort releases
        // sharing one exact height.
        let mut max_count = 0usize;
        for (i, &r) in releases.iter().enumerate() {
            let count = releases[i..].iter().filter(|&&x| x == r).count();
            max_count = max_count.max(count);
        }
        same_height_share_sum += max_count as f64 / n as f64;

        // Support-gated exact-Bayes assignment, one query per member.
        for i in 0..n {
            let l = bounded_uniform(&mut rng, cfg.sigma_l);
            let t = releases[i] + l;
            let mut support = 0u64;
            let mut cross = false;
            for j in 0..n {
                if releases[j] <= t && t - releases[j] <= cfg.sigma_l {
                    support += 1;
                    if anchors[j] != anchors[i] {
                        cross = true;
                    }
                }
            }
            debug_assert!(support >= 1, "the true release is always in support");
            assign_sum += 1.0 / support as f64;
            if cross {
                cross_confused += 1;
            }
            queries += 1;
        }
    }

    let p_assign = assign_sum / queries as f64;
    let ratio = p_assign * cfg.n_x as f64;
    ExitX2Result {
        name: cfg.name.clone(),
        n_x: cfg.n_x,
        two_anchor: cfg.two_anchor,
        sigma_l: cfg.sigma_l,
        window: cfg.window,
        draw_disabled: cfg.draw_disabled,
        p_assign,
        ratio,
        clears_bound: ratio < RATIO_BOUND,
        measured_overlap_frac: if early_draws > 0 {
            early_overlap as f64 / early_draws as f64
        } else {
            0.0
        },
        predicted_overlap_frac: if cfg.window > seb {
            (cfg.window - seb) as f64 / cfg.window as f64
        } else {
            0.0
        },
        cross_anchor_confusion: cross_confused as f64 / queries as f64,
        max_same_height_share: same_height_share_sum / cfg.worlds as f64,
        gap_mean_frac: if gaps_total > 0 {
            gap_frac_sum / gaps_total as f64
        } else {
            0.0
        },
        gap_upper_half_share: if gaps_total > 0 {
            gap_upper as f64 / gaps_total as f64
        } else {
            0.0
        },
    }
}

// ---------------------------------------------------------------------------
// §8.3 negative control and §5.3 lever-vs-queue costing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct NegativeControlResult {
    /// Clustering statistic with the draw running (disperses).
    pub drawn_max_same_height_share: f64,
    /// …and with the draw disabled (piles onto the anchor).
    pub skipped_max_same_height_share: f64,
    /// The control passes iff the detector separates the two worlds cleanly.
    pub caught: bool,
    /// The assignment observer's ratio in the *skipped* world — recorded to
    /// document why the control keys on clustering: identical heights are
    /// mutually blind (`r ≈ 1`), so assignment alone cannot catch the skip.
    pub skipped_assignment_ratio: f64,
}

/// One row of the §5.3 lever-vs-queue costing: what satisfying the joint
/// constraint costs down each path, on the shared capital-idle axis.
#[derive(Debug, Clone, Serialize)]
pub struct LeverQueueRow {
    pub rho_x: f64,
    pub n_x: u64,
    /// Frozen-rule window at this `ρ_x` and the §13 anchor.
    pub window: u64,
    /// §5.3 spacing-form lever floor: `σ_L ≥ W / N_x` (mutual confusability
    /// of cohort neighbours).
    pub lever_sigma_l_spacing: u64,
    /// What the pre-registered X-1 observer actually requires of `σ_L` to
    /// clear `r < RATIO_BOUND` at the §13 anchor — the sweep's headline
    /// number for the costing (module docs).
    pub required_sigma_l_x1: u64,
    /// Queue alternative: `k = W / SEB` epochs of crisis spread.
    pub queue_k: u64,
    /// Lever cost: mean idle blocks `required_σ_L / 2`, paid by exiters only.
    pub lever_cost_mean_blocks: u64,
    /// Queue cost: mean extra lockup `W / 2`, paid by **every** exit.
    pub queue_cost_mean_blocks: u64,
}

// ---------------------------------------------------------------------------
// Full report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ExitStandoffReport {
    pub settlement_epoch_blocks: u64,
    pub ratio_bound: f64,
    pub exit_target_anon_set: u64,
    pub x1: Vec<ExitX1Result>,
    pub x2: Vec<ExitX2Result>,
    pub negative_control: NegativeControlResult,
    pub lever_queue_costing: Vec<LeverQueueRow>,
    /// §8.5: the worst graded row (name, ratio) across X-1 and X-2 — the
    /// reported number under the WI-4 regime-splitting discipline.
    pub worst_row_name: String,
    pub worst_row_ratio: f64,
}

fn build_x1_configs() -> Vec<ExitX1Config> {
    let mut cfgs = Vec::new();
    let mut seed = 0xE817_0001u64;
    // σ_L sweep spans the §5.3 spacing-form floors through the scale the
    // support-gated observer demands (module docs: ≈ 5/ρ_x at N = 10).
    let sigma_ls = [1_000u64, 4_000, 12_500, 32_000];
    // WI-4 N-sweep form: the anchor plus points below and above it.
    let ns = [3u64, 5, EXIT_TARGET_ANON_SET, 20];
    for &rho_x in &RHO_X_BOX {
        for &n in &ns {
            let window = frozen_rule_window(rho_x, n);
            for &sigma_l in &sigma_ls {
                cfgs.push(ExitX1Config {
                    name: format!("x1_rho{rho_x:.2e}_n{n}_sl{sigma_l}"),
                    rho_x,
                    n,
                    sigma_l,
                    window,
                    trials: 20_000,
                    seed,
                });
                seed += 1;
            }
        }
    }
    cfgs
}

fn build_x2_configs() -> Vec<ExitX2Config> {
    let mut cfgs = Vec::new();
    let mut seed = 0xE817_1001u64;
    // Frozen-rule outputs at the §5.1 box corners (2/3/6 × SEB).
    let windows: Vec<u64> = RHO_X_BOX
        .iter()
        .map(|&r| frozen_rule_window(r, EXIT_TARGET_ANON_SET))
        .collect();
    let sigma_ls = [100u64, 1_000, 4_000, 12_500];
    for &window in &windows {
        for &n_x in &[3u64, 5, 8] {
            for &two_anchor in &[false, true] {
                for &sigma_l in &sigma_ls {
                    cfgs.push(ExitX2Config {
                        name: format!(
                            "x2_w{window}_nx{n_x}_{}_sl{sigma_l}",
                            if two_anchor { "2a" } else { "1a" }
                        ),
                        n_x,
                        two_anchor,
                        sigma_l,
                        window,
                        draw_disabled: false,
                        worlds: 4_000,
                        seed,
                    });
                    seed += 1;
                }
            }
        }
    }
    cfgs
}

fn run_negative_control() -> NegativeControlResult {
    let base = ExitX2Config {
        name: "control_drawn".into(),
        n_x: 5,
        two_anchor: false,
        sigma_l: 4_000,
        window: 2 * SETTLEMENT_EPOCH_BLOCKS,
        draw_disabled: false,
        worlds: 2_000,
        seed: 0xE817_2001,
    };
    let drawn = run_x2(&base);
    let skipped = run_x2(&ExitX2Config {
        name: "control_skipped".into(),
        draw_disabled: true,
        ..base
    });
    NegativeControlResult {
        drawn_max_same_height_share: drawn.max_same_height_share,
        skipped_max_same_height_share: skipped.max_same_height_share,
        // A skip piles the whole cohort onto one height; a drawn cohort over
        // an SEB-scale window collides essentially never.
        caught: skipped.max_same_height_share > 0.99 && drawn.max_same_height_share < 0.5,
        skipped_assignment_ratio: skipped.ratio,
    }
}

fn build_costing() -> Vec<LeverQueueRow> {
    let mut rows = Vec::new();
    for &rho_x in &RHO_X_BOX {
        let window = frozen_rule_window(rho_x, EXIT_TARGET_ANON_SET);
        let required = required_sigma_l(rho_x, EXIT_TARGET_ANON_SET);
        for &n_x in &[3u64, 5, 8] {
            rows.push(LeverQueueRow {
                rho_x,
                n_x,
                window,
                lever_sigma_l_spacing: window.div_ceil(n_x),
                required_sigma_l_x1: required,
                queue_k: window / SETTLEMENT_EPOCH_BLOCKS,
                lever_cost_mean_blocks: required / 2,
                queue_cost_mean_blocks: window / 2,
            });
        }
    }
    rows
}

pub fn run_full_report() -> ExitStandoffReport {
    let x1: Vec<ExitX1Result> = build_x1_configs().iter().map(run_x1).collect();
    let x2: Vec<ExitX2Result> = build_x2_configs().iter().map(run_x2).collect();
    let negative_control = run_negative_control();
    let lever_queue_costing = build_costing();

    let (mut worst_name, mut worst_ratio) = (String::new(), f64::MIN);
    for r in &x1 {
        if r.ratio > worst_ratio {
            worst_ratio = r.ratio;
            worst_name = r.name.clone();
        }
    }
    for r in &x2 {
        if r.ratio > worst_ratio {
            worst_ratio = r.ratio;
            worst_name = r.name.clone();
        }
    }

    ExitStandoffReport {
        settlement_epoch_blocks: SETTLEMENT_EPOCH_BLOCKS,
        ratio_bound: RATIO_BOUND,
        exit_target_anon_set: EXIT_TARGET_ANON_SET,
        x1,
        x2,
        negative_control,
        lever_queue_costing,
        worst_row_name: worst_name,
        worst_row_ratio: worst_ratio,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The frozen rule reproduces the §5.1 planning-box corners exactly
    /// (F-D4 §5.4 — the seal applies this function, so these pins are the
    /// rule's KAT): dense corner floors at 2×SEB, the interior instance at
    /// 3×SEB, the sparse corner at 6×SEB.
    #[test]
    fn frozen_rule_pins_the_planning_box() {
        assert_eq!(frozen_rule_window(3.08e-3, 10), 2 * SETTLEMENT_EPOCH_BLOCKS);
        assert_eq!(frozen_rule_window(4.0e-4, 10), 3 * SETTLEMENT_EPOCH_BLOCKS);
        assert_eq!(frozen_rule_window(1.58e-4, 10), 6 * SETTLEMENT_EPOCH_BLOCKS);
    }

    /// X-3 floor: no rate, however dense, produces a window below 2×SEB, and
    /// every output is an SEB multiple (the §5.1 two-anchor-merging shape).
    #[test]
    fn frozen_rule_holds_the_x3_floor_and_seb_quantization() {
        for &rho in &[1e-6, 1e-4, 1e-2, 1.0, 100.0] {
            let w = frozen_rule_window(rho, 10);
            assert!(w >= 2 * SETTLEMENT_EPOCH_BLOCKS);
            assert_eq!(w % SETTLEMENT_EPOCH_BLOCKS, 0);
        }
    }

    /// The bisection inverts the exact Poisson-support expectation: at the
    /// returned σ_L the analytic ratio sits at the bar (within bisection
    /// tolerance), and one block less falls short.
    #[test]
    fn required_sigma_l_inverts_the_bar() {
        let rho = 4.0e-4;
        let n = EXIT_TARGET_ANON_SET;
        let sigma = required_sigma_l(rho, n);
        let ratio_at = |s: f64| {
            let lambda = rho * s;
            (1.0 - (-lambda).exp()) / lambda * n as f64
        };
        assert!(ratio_at(sigma as f64) <= RATIO_BOUND + 1e-6);
        assert!(ratio_at((sigma - sigma / 100) as f64) > RATIO_BOUND);
        // Blind guessing already clears the bound at N ≤ 2.
        assert_eq!(required_sigma_l(rho, 2), 0);
    }

    /// X-1's delivered cover tracks `1 + ρ_x·σ_L` (the latency-gated support),
    /// not the nominal `ρ_x·W` — the module-docs headline finding, asserted.
    #[test]
    fn x1_delivered_cover_is_latency_gated() {
        let cfg = ExitX1Config {
            name: "t".into(),
            rho_x: 4.0e-4,
            n: 10,
            sigma_l: 12_500,
            window: frozen_rule_window(4.0e-4, 10),
            trials: 50_000,
            seed: 42,
        };
        let r = run_x1(&cfg);
        let expected = 1.0 + cfg.rho_x * cfg.sigma_l as f64; // = 6.0
        assert!((r.delivered_support_mean - expected).abs() / expected < 0.05);
        // The nominal window cover is materially larger here (ρ_x·W = 12).
        assert!(r.nominal_window_cover > r.delivered_support_mean);
    }

    /// X-1 clears the bar once σ_L passes the required level and fails well
    /// below it (graded with margin either side of the boundary, so MC noise
    /// at the exact bar cannot flake the test).
    #[test]
    fn x1_clears_at_the_required_sigma_and_fails_below() {
        let rho = 4.0e-4;
        let required = required_sigma_l(rho, 10);
        let base = ExitX1Config {
            name: "t".into(),
            rho_x: rho,
            n: 10,
            sigma_l: required + required / 5,
            window: frozen_rule_window(rho, 10),
            trials: 100_000,
            seed: 7,
        };
        assert!(run_x1(&base).clears_bound);
        let starved = ExitX1Config {
            sigma_l: required / 4,
            ..base.clone()
        };
        assert!(!run_x1(&starved).clears_bound);
    }

    /// X-2 assignment confusability is bought by σ_L: widening the spread
    /// lowers the ratio monotonically at fixed cohort and window.
    #[test]
    fn x2_wider_sigma_lowers_the_assignment_ratio() {
        let base = ExitX2Config {
            name: "t".into(),
            n_x: 5,
            two_anchor: false,
            sigma_l: 100,
            window: 2 * SETTLEMENT_EPOCH_BLOCKS,
            draw_disabled: false,
            worlds: 3_000,
            seed: 9,
        };
        let narrow = run_x2(&base);
        let wide = run_x2(&ExitX2Config {
            sigma_l: 12_500,
            ..base.clone()
        });
        assert!(wide.ratio < narrow.ratio);
    }

    /// X-3 coverage boundary: at `W = 2×SEB` the measured overlap fraction
    /// matches the predicted `(W − SEB)/W = 0.5` — mixes-at-all, not merged.
    #[test]
    fn x2_two_anchor_overlap_matches_the_x3_prediction() {
        let cfg = ExitX2Config {
            name: "t".into(),
            n_x: 8,
            two_anchor: true,
            sigma_l: 4_000,
            window: 2 * SETTLEMENT_EPOCH_BLOCKS,
            draw_disabled: false,
            worlds: 5_000,
            seed: 13,
        };
        let r = run_x2(&cfg);
        assert!((r.predicted_overlap_frac - 0.5).abs() < 1e-9);
        assert!((r.measured_overlap_frac - 0.5).abs() < 0.03);
        // Some queries realize cross-anchor confusion once the ranges overlap.
        assert!(r.cross_anchor_confusion > 0.0);
    }

    /// §8.3: the harness can fail its own control — a draw-skipping cohort is
    /// caught by clustering while the assignment observer stays blind to it.
    #[test]
    fn negative_control_catches_the_skipped_draw() {
        let c = run_negative_control();
        assert!(c.caught, "control not caught: {c:?}");
        assert!(c.skipped_max_same_height_share > 0.99);
        assert!(c.drawn_max_same_height_share < 0.5);
        // Identical heights are mutually blind: r ≈ 1 (blind), which is why
        // the control keys on clustering, not assignment.
        assert!((c.skipped_assignment_ratio - 1.0).abs() < 0.05);
    }

    /// §8.4 thin-regime bias: at the trough cohort the one-sided draw's
    /// realized positions stay unbiased (mean ≈ W/2, upper-half share ≈ 0.5).
    #[test]
    fn thin_regime_gap_positions_are_unbiased() {
        let cfg = ExitX2Config {
            name: "t".into(),
            n_x: 3,
            two_anchor: false,
            sigma_l: 4_000,
            window: 2 * SETTLEMENT_EPOCH_BLOCKS,
            draw_disabled: false,
            worlds: 10_000,
            seed: 17,
        };
        let r = run_x2(&cfg);
        assert!((r.gap_mean_frac - 0.5).abs() < 0.01);
        assert!((r.gap_upper_half_share - 0.5).abs() < 0.01);
    }

    /// The report is well-formed: every graded row's ratio is `p·N`, the
    /// clears flag matches the bar, and the worst row is the max.
    #[test]
    fn report_is_well_formed() {
        let report = run_full_report();
        assert_eq!(report.ratio_bound, RATIO_BOUND);
        let mut max_seen = f64::MIN;
        for r in &report.x1 {
            assert!((r.ratio - r.p_link * r.n as f64).abs() < 1e-9);
            assert_eq!(r.clears_bound, r.ratio < RATIO_BOUND);
            max_seen = max_seen.max(r.ratio);
        }
        for r in &report.x2 {
            assert!((r.ratio - r.p_assign * r.n_x as f64).abs() < 1e-9);
            assert_eq!(r.clears_bound, r.ratio < RATIO_BOUND);
            max_seen = max_seen.max(r.ratio);
        }
        assert_eq!(report.worst_row_ratio, max_seen);
        assert!(report.negative_control.caught);
        assert!(!report.lever_queue_costing.is_empty());
    }
}
