//! GF-7 joint three-axis timeline scenario — the §6.3 pipeline proof
//! (`docs/design/ARCHIVAL_BOND_2C_GF7_HOOKS.md`).
//!
//! This module is the **only recording implementation** of the
//! `BroadcastTimelineObserver` seam (hooks-spec §4 layer 2 — this crate is a
//! standalone binary no production crate depends on; CI asserts the
//! dependency graph). It drives all three GF-7 correlation axes through one
//! recorded timeline per principal↔`P` pair and runs the **funding-seam-blind
//! adversary** (§2's named failure mode) against the recorded stream — plus a
//! funding-seam arm for contrast, so the report shows what the entry-gap
//! jitter does and does not decorrelate.
//!
//! # What this is, and is not
//!
//! This is the **pipeline proof**, not the measurement round. The grading here
//! is deliberately trivial (nearest-cadence-event argmin over principals); the
//! measurement round (hooks-spec §5) replaces the correlator with the real
//! S-3 adversary model and sets the genesis-gate threshold with the swept
//! surface as evidence. What this scenario proves end-to-end before anything
//! depends on it:
//!
//! 1. the recorded stream carries **all three event classes** — principal
//!    lifecycle (axis iii), the bond-post and its draw (axis i), `P`'s other
//!    broadcasts (axis ii) — as **one joint stream**, never per-axis series;
//! 2. the correlator consumes **only the recorded events** (never sim
//!    internals), so the evidence pipeline is the same shape the measurement
//!    round will use;
//! 3. the bond-post placement in the stream is the real single-sourced
//!    `draw_entry_gap` → `plan_entry_seam` pipeline — the sim grades the draw
//!    that ships, not a re-derivation.
//!
//! # The two adversary arms
//!
//! - **funding-seam arm**: correlates each bond-post against principals'
//!   funding-send times only — the axis the entry-gap jitter already handles.
//!   Expected: linkage falls as the window widens (the jitter works).
//! - **funding-seam-blind arm**: ignores funding sends entirely and correlates
//!   against the principal's *lifecycle cadence* (session/refresh/drain
//!   rhythm) — the residual GF-7 names, which the jitter does **not** address.
//!   Expected: linkage stays above baseline across the window sweep. That gap
//!   is the reason the hooks exist.

use serde::Serialize;
use shekyl_standoff::gf7::{BroadcastTimelineObserver, TimelineEvent};
use shekyl_standoff::{draw_entry_gap, plan_entry_seam, DEFAULT_ENTRY_GAP_WINDOW};

use crate::standoff::SplitMix64;

/// The sim-side recording observer — collects the joint timeline into a
/// `Vec`. One observer session per principal↔`P` pair; the pair index is
/// ground truth held sim-side (hooks-spec §3: the emission carries opaque
/// ordinals only; the sim *is* the ground truth and joins on its own side).
pub struct RecordingObserver {
    pub events: Vec<TimelineEvent>,
}

impl RecordingObserver {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }
}

impl BroadcastTimelineObserver for RecordingObserver {
    fn record(&mut self, event: TimelineEvent) {
        self.events.push(event);
    }
}

/// Scenario parameters. Everything is logical time (blocks); the cadence
/// heterogeneity (per-principal period/phase) is what gives the blind
/// adversary a rhythm to correlate on.
pub struct ScenarioConfig {
    /// Principal↔`P` pairs per trial (baseline link probability = 1/n).
    pub n_principals: usize,
    /// Timeline horizon in blocks.
    pub horizon_blocks: u64,
    /// Per-principal session period drawn uniform from this range (min, max).
    pub period_range_blocks: (u64, u64),
    /// Standoff windows to sweep (`DEFAULT_ENTRY_GAP_WINDOW` is the
    /// inherited grading anchor per hooks-spec §5).
    pub windows: Vec<u64>,
    /// Trials per window (each trial re-draws cadences and seams).
    pub trials: u32,
    pub seed: u64,
}

impl Default for ScenarioConfig {
    fn default() -> Self {
        Self {
            n_principals: 8,
            horizon_blocks: 4_000,
            period_range_blocks: (40, 400),
            windows: vec![0, 60, 300, DEFAULT_ENTRY_GAP_WINDOW],
            trials: 200,
            seed: 0x6F7_7A11_2C2B_0001,
        }
    }
}

/// One row of the swept grading surface.
#[derive(Serialize)]
pub struct WindowResult {
    pub window_blocks: u64,
    /// Funding-seam-blind arm: P(link) via lifecycle-cadence proximity.
    pub p_link_blind: f64,
    /// Funding-seam arm: P(link) via funding-send proximity (the axis the
    /// jitter handles).
    pub p_link_funding: f64,
    /// Uniform-guess baseline, 1/n.
    pub baseline: f64,
}

/// Event-class coverage counts over one representative recorded timeline —
/// the §6.3 "all three event classes through one recorded timeline" evidence,
/// reported rather than asserted-only.
#[derive(Serialize)]
pub struct AxisCoverage {
    pub axis_i_bond_post_events: usize,
    pub axis_ii_per_p_submits: usize,
    pub axis_iii_lifecycle_events: usize,
}

#[derive(Serialize)]
pub struct Gf7TimelineReport {
    pub n_principals: usize,
    pub trials: u32,
    pub horizon_blocks: u64,
    pub coverage: AxisCoverage,
    pub results: Vec<WindowResult>,
}

/// The per-pair ground truth the sim keeps on its own side: which recorded
/// stream belongs to which principal. The correlator never sees this struct —
/// it consumes only the event streams and guesses the mapping.
struct RecordedPair {
    events: Vec<TimelineEvent>,
}

/// Synthesize one principal↔`P` pair's joint timeline into `observer`.
///
/// Cadence model: the principal runs wallet sessions (with a refresh cycle
/// each) at `phase + k·period`; the funding intent **co-triggers** with a
/// session (the intent forms while the wallet is open — the co-trigger shape
/// GATE6 §6 names), a drain rides a later session, and the persona makes two
/// later `PerP` submits. The entry-seam placement is the real pipeline:
/// `draw_entry_gap(window)` → `plan_entry_seam`, both events placed relative
/// to the private anchor `t0` (the co-triggering session's block).
///
/// # Preconditions (asserted — misconfiguration fails loudly, never silently)
///
/// - `1 <= period_range.0 <= period_range.1`: a zero period breaks the
///   cadence arithmetic (mod-by-zero, non-advancing loop); an inverted range
///   underflows the width.
/// - `period_range.1 <= horizon / 2`: guarantees the first session (`phase <
///   period`) lands in the first half, so the private anchor exists and the
///   seam events fit the horizon even at the widest swept window.
fn simulate_pair(
    rng: &mut SplitMix64,
    window: u64,
    horizon: u64,
    period_range: (u64, u64),
    observer: &mut RecordingObserver,
) {
    let (pmin, pmax) = period_range;
    assert!(
        pmin >= 1 && pmin <= pmax,
        "period_range must satisfy 1 <= min <= max (got {pmin}..={pmax}): \
         a zero period breaks the cadence arithmetic and an inverted range \
         underflows"
    );
    assert!(
        pmax <= horizon / 2,
        "max session period ({pmax}) must fit in half the horizon ({horizon}): \
         the private anchor must land in the first half so the seam events \
         fit the horizon"
    );
    let period = pmin + rng.next_u64() % (pmax - pmin + 1);
    let phase = rng.next_u64() % period;

    // Axis (iii): the session/refresh cadence over the horizon.
    let mut sessions = Vec::new();
    let mut t = phase;
    while t <= horizon {
        sessions.push(t);
        observer.record(TimelineEvent::WalletSessionMarker { at: t });
        observer.record(TimelineEvent::RefreshCycleMarker { at: t });
        t += period;
    }

    // The private intent anchor co-triggers with a session in the first half
    // (so the seam events fit the horizon comfortably even at window 600).
    // Non-empty by the asserted precondition: `phase < period <= horizon / 2`,
    // so the first session always lands in the first half.
    let first_half = sessions.iter().filter(|&&s| s <= horizon / 2).count();
    let anchor_idx = (rng.next_u64() as usize) % first_half;
    let t0 = sessions[anchor_idx];

    // Axis (i): the real draw → planner pipeline, events carrying the values
    // that actually ran.
    let draw = draw_entry_gap(window, rng);
    let (spread_blocks, bond_first) = draw;
    observer.record(TimelineEvent::EntryGapDrawConsumed {
        persona: 0,
        window_blocks: window,
        spread_blocks,
        bond_first,
    });
    let plan = plan_entry_seam(draw);
    observer.record(TimelineEvent::BondPostScheduled {
        persona: 0,
        entry_offset_blocks: plan.entry_offset_blocks,
        bond_post_offset_blocks: plan.bond_post_offset_blocks,
    });
    observer.record(TimelineEvent::FundingSendDispatched {
        at: t0 + plan.entry_offset_blocks,
    });
    observer.record(TimelineEvent::BondPostDispatched {
        persona: 0,
        at: t0 + plan.bond_post_offset_blocks,
    });

    // Axis (iii) continued: a drain rides a later session, when one exists.
    if let Some(&drain_at) = sessions.iter().find(|&&s| s > t0 + window) {
        observer.record(TimelineEvent::DrainDispatched { at: drain_at });
    }

    // Axis (ii): the persona's other broadcasts (serve-credit-claim-shaped),
    // at the persona's own later rhythm.
    let bond_at = t0 + plan.bond_post_offset_blocks;
    for _ in 0..2 {
        let at = bond_at + 200 + rng.next_u64() % 1_000;
        observer.record(TimelineEvent::PerPSubmitDispatched { persona: 0, at });
    }
}

/// The bond-post dispatch time, read back **from the recorded stream** (the
/// correlator's view — never sim internals).
fn recorded_bond_time(events: &[TimelineEvent]) -> u64 {
    events
        .iter()
        .find_map(|e| match e {
            TimelineEvent::BondPostDispatched { at, .. } => Some(*at),
            _ => None,
        })
        .expect("every pair timeline records a bond-post dispatch")
}

/// Lifecycle feature times for the funding-seam-blind arm: session, refresh,
/// and drain events — **excluding** funding sends (that exclusion is what
/// "blind" means; §2's named failure mode is an adversary who never looks at
/// the funding seam).
fn lifecycle_times(events: &[TimelineEvent]) -> Vec<u64> {
    events
        .iter()
        .filter_map(|e| match e {
            TimelineEvent::WalletSessionMarker { at }
            | TimelineEvent::RefreshCycleMarker { at }
            | TimelineEvent::DrainDispatched { at } => Some(*at),
            _ => None,
        })
        .collect()
}

/// Funding-send feature times for the funding-seam arm.
fn funding_times(events: &[TimelineEvent]) -> Vec<u64> {
    events
        .iter()
        .filter_map(|e| match e {
            TimelineEvent::FundingSendDispatched { at } => Some(*at),
            _ => None,
        })
        .collect()
}

/// Trivial proximity correlator: guess the principal whose feature set has
/// the smallest distance to the bond-post time (ties → lowest index,
/// deterministic). Returns the guessed principal index.
fn nearest_principal(bond_at: u64, features_per_principal: &[Vec<u64>]) -> usize {
    let mut best = (u64::MAX, 0usize);
    for (idx, feats) in features_per_principal.iter().enumerate() {
        let d = feats
            .iter()
            .map(|&t| t.abs_diff(bond_at))
            .min()
            .unwrap_or(u64::MAX);
        if d < best.0 {
            best = (d, idx);
        }
    }
    best.1
}

/// Run one window configuration: `trials` independent worlds of
/// `n_principals` pairs each; both adversary arms consume only the recorded
/// streams. Returns `(p_link_blind, p_link_funding)`.
fn run_window(cfg: &ScenarioConfig, window: u64, rng: &mut SplitMix64) -> (f64, f64) {
    let mut blind_correct = 0u64;
    let mut funding_correct = 0u64;
    let total = cfg.trials as u64 * cfg.n_principals as u64;

    for _ in 0..cfg.trials {
        let pairs: Vec<RecordedPair> = (0..cfg.n_principals)
            .map(|_| {
                let mut obs = RecordingObserver::new();
                simulate_pair(
                    rng,
                    window,
                    cfg.horizon_blocks,
                    cfg.period_range_blocks,
                    &mut obs,
                );
                RecordedPair { events: obs.events }
            })
            .collect();

        let blind_features: Vec<Vec<u64>> =
            pairs.iter().map(|p| lifecycle_times(&p.events)).collect();
        let funding_features: Vec<Vec<u64>> =
            pairs.iter().map(|p| funding_times(&p.events)).collect();

        for (truth, pair) in pairs.iter().enumerate() {
            let bond_at = recorded_bond_time(&pair.events);
            if nearest_principal(bond_at, &blind_features) == truth {
                blind_correct += 1;
            }
            if nearest_principal(bond_at, &funding_features) == truth {
                funding_correct += 1;
            }
        }
    }

    (
        blind_correct as f64 / total as f64,
        funding_correct as f64 / total as f64,
    )
}

/// Coverage counts over one representative recorded timeline (fresh RNG arm,
/// does not perturb the sweep's stream).
fn coverage_sample(cfg: &ScenarioConfig) -> AxisCoverage {
    let mut rng = SplitMix64(cfg.seed ^ 0xC0DE);
    let mut obs = RecordingObserver::new();
    simulate_pair(
        &mut rng,
        DEFAULT_ENTRY_GAP_WINDOW,
        cfg.horizon_blocks,
        cfg.period_range_blocks,
        &mut obs,
    );
    let mut cov = AxisCoverage {
        axis_i_bond_post_events: 0,
        axis_ii_per_p_submits: 0,
        axis_iii_lifecycle_events: 0,
    };
    for e in &obs.events {
        match e {
            TimelineEvent::EntryGapDrawConsumed { .. }
            | TimelineEvent::BondPostScheduled { .. }
            | TimelineEvent::BondPostDispatched { .. } => cov.axis_i_bond_post_events += 1,
            TimelineEvent::PerPSubmitDispatched { .. } => cov.axis_ii_per_p_submits += 1,
            TimelineEvent::FundingSendDispatched { .. }
            | TimelineEvent::DrainDispatched { .. }
            | TimelineEvent::RefreshCycleMarker { .. }
            | TimelineEvent::WalletSessionMarker { .. } => cov.axis_iii_lifecycle_events += 1,
        }
    }
    cov
}

pub fn run_full_report() -> Gf7TimelineReport {
    let cfg = ScenarioConfig::default();
    let mut rng = SplitMix64(cfg.seed);
    let baseline = 1.0 / cfg.n_principals as f64;

    let results = cfg
        .windows
        .iter()
        .map(|&window| {
            let (p_link_blind, p_link_funding) = run_window(&cfg, window, &mut rng);
            WindowResult {
                window_blocks: window,
                p_link_blind,
                p_link_funding,
                baseline,
            }
        })
        .collect();

    Gf7TimelineReport {
        n_principals: cfg.n_principals,
        trials: cfg.trials,
        horizon_blocks: cfg.horizon_blocks,
        coverage: coverage_sample(&cfg),
        results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_standoff::EntrySeamPlan;

    fn recorded_sample(window: u64, seed: u64) -> Vec<TimelineEvent> {
        let cfg = ScenarioConfig::default();
        let mut rng = SplitMix64(seed);
        let mut obs = RecordingObserver::new();
        simulate_pair(
            &mut rng,
            window,
            cfg.horizon_blocks,
            cfg.period_range_blocks,
            &mut obs,
        );
        obs.events
    }

    /// §6.3: one recorded timeline carries all three event classes.
    #[test]
    fn recorded_timeline_carries_all_three_axes() {
        let events = recorded_sample(DEFAULT_ENTRY_GAP_WINDOW, 42);
        let has = |f: &dyn Fn(&TimelineEvent) -> bool| events.iter().any(f);
        // Axis (i)
        assert!(has(&|e| matches!(
            e,
            TimelineEvent::EntryGapDrawConsumed { .. }
        )));
        assert!(has(&|e| matches!(
            e,
            TimelineEvent::BondPostScheduled { .. }
        )));
        assert!(has(&|e| matches!(
            e,
            TimelineEvent::BondPostDispatched { .. }
        )));
        // Axis (ii)
        assert!(has(&|e| matches!(
            e,
            TimelineEvent::PerPSubmitDispatched { .. }
        )));
        // Axis (iii)
        assert!(has(&|e| matches!(
            e,
            TimelineEvent::WalletSessionMarker { .. }
        )));
        assert!(has(&|e| matches!(
            e,
            TimelineEvent::RefreshCycleMarker { .. }
        )));
        assert!(has(&|e| matches!(
            e,
            TimelineEvent::FundingSendDispatched { .. }
        )));
    }

    /// Pipeline integrity, correlator-side: re-derive the plan from the
    /// *recorded* draw parameters and check the recorded schedule and the
    /// entry/bond event times are exactly that plan. This is "the sim grades
    /// the draw that ran, not a re-derivation" made testable — over the
    /// events alone, no sim internals.
    #[test]
    fn recorded_schedule_is_the_planner_over_the_recorded_draw() {
        for seed in [1u64, 7, 99, 12345] {
            let events = recorded_sample(DEFAULT_ENTRY_GAP_WINDOW, seed);

            let (spread, coin) = events
                .iter()
                .find_map(|e| match e {
                    TimelineEvent::EntryGapDrawConsumed {
                        spread_blocks,
                        bond_first,
                        ..
                    } => Some((*spread_blocks, *bond_first)),
                    _ => None,
                })
                .unwrap();
            let expected = plan_entry_seam((spread, coin));

            let recorded_plan = events
                .iter()
                .find_map(|e| match e {
                    TimelineEvent::BondPostScheduled {
                        entry_offset_blocks,
                        bond_post_offset_blocks,
                        ..
                    } => Some(EntrySeamPlan {
                        entry_offset_blocks: *entry_offset_blocks,
                        bond_post_offset_blocks: *bond_post_offset_blocks,
                    }),
                    _ => None,
                })
                .unwrap();
            assert_eq!(recorded_plan, expected);

            // The dispatched separation equals the drawn spread, and the
            // recorded order matches the coin.
            let entry_at = events
                .iter()
                .find_map(|e| match e {
                    TimelineEvent::FundingSendDispatched { at } => Some(*at),
                    _ => None,
                })
                .unwrap();
            let bond_at = recorded_bond_time(&events);
            assert_eq!(entry_at.abs_diff(bond_at), spread);
            if spread > 0 {
                assert_eq!(bond_at < entry_at, coin);
            }
        }
    }

    /// The two-arm grading behaves as the module docs predict on the fixed
    /// seed: the funding-seam arm degrades as the window widens (the jitter
    /// works on the axis it targets), while the funding-seam-blind arm stays
    /// above the uniform baseline (the residual GF-7 names — the reason the
    /// measurement round exists). Deterministic via the seeded PRNG.
    #[test]
    fn jitter_degrades_funding_arm_but_not_cadence_arm() {
        let report = run_full_report();
        let by_window = |w: u64| {
            report
                .results
                .iter()
                .find(|r| r.window_blocks == w)
                .unwrap()
        };
        let w0 = by_window(0);
        let w600 = by_window(DEFAULT_ENTRY_GAP_WINDOW);

        for r in &report.results {
            for p in [r.p_link_blind, r.p_link_funding, r.baseline] {
                assert!((0.0..=1.0).contains(&p));
            }
        }
        // Zero window = bond-post at the funding block exactly: the funding
        // arm links (near-)perfectly, and much better than at window 600.
        assert!(w0.p_link_funding > 0.9);
        assert!(w0.p_link_funding > w600.p_link_funding);
        // The blind arm keeps a residual advantage over uniform guessing even
        // at the widest window — the linkage channel the jitter does not
        // touch.
        assert!(w600.p_link_blind > w600.baseline);
    }

    /// Coverage sample reports non-zero counts on every axis.
    #[test]
    fn coverage_sample_counts_every_axis() {
        let cov = coverage_sample(&ScenarioConfig::default());
        assert!(cov.axis_i_bond_post_events >= 3);
        assert!(cov.axis_ii_per_p_submits >= 1);
        assert!(cov.axis_iii_lifecycle_events >= 3);
    }

    // The two precondition guards bite (not just exist): a degenerate or
    // inverted period range, and a period too large for the anchor to land
    // in the first half, both fail loudly instead of panicking obscurely
    // (mod-by-zero / out-of-bounds) or looping forever.

    #[test]
    #[should_panic(expected = "period_range must satisfy 1 <= min <= max")]
    fn zero_period_range_is_refused() {
        let mut rng = SplitMix64(1);
        let mut obs = RecordingObserver::new();
        simulate_pair(&mut rng, 600, 4_000, (0, 0), &mut obs);
    }

    #[test]
    #[should_panic(expected = "period_range must satisfy 1 <= min <= max")]
    fn inverted_period_range_is_refused() {
        let mut rng = SplitMix64(1);
        let mut obs = RecordingObserver::new();
        simulate_pair(&mut rng, 600, 4_000, (400, 40), &mut obs);
    }

    #[test]
    #[should_panic(expected = "must fit in half the horizon")]
    fn period_exceeding_half_horizon_is_refused() {
        let mut rng = SplitMix64(1);
        let mut obs = RecordingObserver::new();
        simulate_pair(&mut rng, 600, 4_000, (40, 2_001), &mut obs);
    }
}
