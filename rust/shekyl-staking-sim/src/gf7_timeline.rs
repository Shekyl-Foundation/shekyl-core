//! GF-7 joint timeline: the sim's recorder of the production broadcast seam.
//!
//! This module is the **only recording implementation** of the
//! `BroadcastTimelineObserver` seam (hooks-spec §4 layer 2; this crate is a
//! standalone binary no production crate depends on, and CI asserts the
//! dependency graph). It synthesizes one principal↔`P` pair's joint timeline
//! through production's own entry-seam draw (`draw_entry_gap`) and dispersal
//! draw (`bounded_uniform`), records all three GF-7 axes, and reports their
//! coverage. `--gf7-timeline` also runs the §19 leg-(b) wall-clock arm
//! (`wallclock_leg`), a model-consistency check (WI-4 §19.10.2a).
//!
//! There is no correlator here and no verdict. The graded measurement round
//! that scored this timeline against `r < 2` was withdrawn when the order coin
//! and the `FundingSendDispatched` event it graded were retired (WI-4 §13.1);
//! its correlator, arms, controls and fail-closed verdict were deleted
//! 2026-11-08 (Appendix B D9 of `ECONOMICS_SIM_PRODUCTION_REBASE.md`) and were
//! last at `76677fcfa`.

use serde::Serialize;
use shekyl_standoff::gf7::{BroadcastTimelineObserver, TimelineEvent};
use shekyl_standoff::{bounded_uniform, draw_entry_gap, DEFAULT_ENTRY_GAP_WINDOW};

use crate::rng::SplitMix64;
use crate::wallclock_leg::{run_wallclock_leg, WallclockLegReport};

/// The synthesized timeline's horizon (blocks): a steady-state principal.
const HORIZON_BLOCKS: u64 = 4_000;
/// The principal's session period range (blocks), near-periodic (WI-4 §6).
const SESSION_PERIOD_RANGE: (u64, u64) = (40, 400);
/// Seed of the coverage sample's timeline.
const COVERAGE_SEED: u64 = 0x6F7_7A11_2C2B_0002 ^ 0xC0DE;

/// The sim-side recording observer — collects the joint timeline into a `Vec`.
/// One observer session per principal↔`P` pair; the pair index is ground truth
/// held sim-side (hooks-spec §3: the emission carries opaque ordinals only; the
/// sim *is* the ground truth and joins on its own side).
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

/// One pair's synthesis parameters, in logical block time.
#[derive(Clone, Copy)]
pub struct SynthParams {
    pub window: u64,
    /// WI-3 intra-tick dispersal bound (blocks): the bond dispatch gets
    /// `U[0, dispersal_bound)` added via `bounded_uniform`, matching the live
    /// driver's draw shape for distributional parity (WI-4 §7). `0` = no
    /// dispersal.
    pub dispersal_bound: u64,
    /// Model the D-B3 resume channel: an unconfirmed post re-dispatched at the
    /// wallet's next session open (WI-3 resubmits at the next due tick; a
    /// close/reopen with a pending post puts that tick at session-open, so the
    /// resubmit's `BondPostDispatched` lands **on the session lattice**).
    pub resume_redispatch: bool,
}

impl SynthParams {
    /// The recommended posture: 600-block uniform-independent window and
    /// `dispersal_bound = 0`, because WI-3's dispersal is
    /// `U[0, DEFAULT_PSCAN_CADENCE)` = `U[0, 60s)`, well under one block.
    pub(crate) fn posture() -> Self {
        Self {
            window: DEFAULT_ENTRY_GAP_WINDOW,
            dispersal_bound: 0,
            resume_redispatch: false,
        }
    }
}

/// Synthesize one principal↔`P` pair's joint timeline into `observer`.
///
/// Cadence model (pessimistic per WI-4 §6): the principal runs near-periodic
/// wallet sessions (with a refresh each) at `phase + k·period`; the funding
/// intent **co-triggers** with a session (GATE6 §6/S-1), a drain rides a later
/// session, and the persona makes two later `PerP` submits. The entry seam is
/// the real `draw_entry_gap`, placed causally; the bond dispatch then gets
/// WI-3's modeled intra-tick dispersal added.
///
/// # Preconditions (asserted — misconfiguration fails loudly)
///
/// - `1 <= period_range.0 <= period_range.1 <= horizon / 2` (the private
///   anchor lands in the first half).
/// - `window + max(dispersal_bound − 1, 0) <= horizon / 2` (the combined seam
///   span: the anchor lands by `horizon / 2`, the bond dispatch lands at most
///   `window + (dispersal_bound − 1)` after it, so every seam event lands on
///   the recorded timeline).
fn simulate_pair(rng: &mut SplitMix64, p: &SynthParams, observer: &mut RecordingObserver) {
    let (horizon, (pmin, pmax)) = (HORIZON_BLOCKS, SESSION_PERIOD_RANGE);
    assert!(
        pmin >= 1 && pmin <= pmax,
        "period_range must satisfy 1 <= min <= max (got {pmin}..={pmax}): \
         a zero period breaks the cadence arithmetic and an inverted range \
         underflows"
    );
    assert!(
        pmax <= horizon / 2,
        "max session period ({pmax}) must fit in half the horizon ({horizon}): \
         the private anchor must land in the first half"
    );
    // The combined seam span, not two independent half-horizon checks: the
    // anchor `t0` lands by `horizon / 2` (previous assert), and the farthest
    // seam event is the bond dispatch at `t0 + spread + dispersal` with
    // `spread <= window` and `dispersal <= dispersal_bound − 1` (the draw is
    // `U[0, dispersal_bound)`). Bounding the sum by the remaining half is the
    // exact condition for every seam event to land on the recorded timeline;
    // `window` and `dispersal_bound` each passing `<= horizon / 2` separately
    // would not compose to that guarantee.
    let seam_span = p.window + p.dispersal_bound.saturating_sub(1);
    assert!(
        seam_span <= horizon / 2,
        "seam span (window {} + max dispersal {}) must fit in half the horizon \
         ({horizon}): the bond dispatch must land on the recorded timeline",
        p.window,
        p.dispersal_bound.saturating_sub(1)
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

    // The private intent anchor co-triggers with a first-half session.
    // Non-empty by precondition: `phase < period <= horizon / 2`.
    let first_half = sessions.iter().filter(|&&s| s <= horizon / 2).count();
    let anchor_idx = (rng.next_u64() as usize) % first_half;
    let t0 = sessions[anchor_idx];

    // Axis (i): the entry seam, the real shipped draw. Causal: the draw yields
    // a single spread, and the funding always precedes the bond post it funds
    // (funding at the anchor `t0`, bond post `spread` blocks later). The
    // funding send is not recorded: it is the unnamed, CT-hidden FCMP++
    // input, not a chain-attributable event.
    let spread_blocks = draw_entry_gap(p.window, rng);
    observer.record(TimelineEvent::EntryGapDrawConsumed {
        persona: 0,
        window_blocks: p.window,
        spread_blocks,
    });
    // Causal placement: the bond post sits `spread_blocks` after the private
    // intent anchor (bond-post offset = spread; there is no entry offset).
    observer.record(TimelineEvent::BondPostScheduled {
        persona: 0,
        bond_post_offset_blocks: spread_blocks,
    });

    // WI-3 intra-tick dispersal: add `U[0, dispersal_bound)` to the scheduled
    // dispatch, drawn via the *same* `bounded_uniform` the live driver uses
    // (measurement doc §7 — distributional parity between sim and driver).
    let dispersal = if p.dispersal_bound > 0 {
        bounded_uniform(rng, p.dispersal_bound - 1)
    } else {
        0
    };
    let bond_at = t0 + spread_blocks + dispersal;
    observer.record(TimelineEvent::BondPostDispatched {
        persona: 0,
        at: bond_at,
    });

    // The D-B3 resume channel (swept): an unconfirmed post's resubmit fires at
    // the next due tick after the wallet reopens — i.e. at the next *session*
    // — so the byte-identical resubmit's `BondPostDispatched` lands on the
    // session lattice, a chain-visible event carrying the session clock.
    if p.resume_redispatch {
        if let Some(&resume_at) = sessions.iter().find(|&&s| s > bond_at) {
            observer.record(TimelineEvent::BondPostDispatched {
                persona: 0,
                at: resume_at,
            });
        }
    }

    // Axis (iii) continued: a drain rides a later session, when one exists.
    if let Some(&drain_at) = sessions.iter().find(|&&s| s > t0 + p.window) {
        observer.record(TimelineEvent::DrainDispatched { at: drain_at });
    }

    // Axis (ii): the persona's other broadcasts, at the persona's own rhythm.
    for _ in 0..2 {
        let at = bond_at + 200 + rng.next_u64() % 1_000;
        observer.record(TimelineEvent::PerPSubmitDispatched { persona: 0, at });
    }
}

/// Event-class coverage over one representative recorded timeline (§6.3
/// evidence, reported rather than asserted-only).
#[derive(Serialize)]
pub struct AxisCoverage {
    pub axis_i_bond_post_events: usize,
    pub axis_ii_per_p_submits: usize,
    pub axis_iii_lifecycle_events: usize,
}

/// The `--gf7-timeline` report: the recorded axes' coverage and the §19
/// leg-(b) wall-clock arm.
#[derive(Serialize)]
pub struct TimelineReport {
    pub coverage: AxisCoverage,
    /// The §19 leg-(b) wall-clock sweep-phase arm, a model-consistency check
    /// (WI-4 §19.10.2a), not a channel grade.
    pub wallclock_leg: WallclockLegReport,
}

/// Coverage counts over one representative recorded timeline .
fn coverage_sample() -> AxisCoverage {
    let mut rng = SplitMix64::new(COVERAGE_SEED);
    let mut obs = RecordingObserver::new();
    simulate_pair(&mut rng, &SynthParams::posture(), &mut obs);
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
            TimelineEvent::DrainDispatched { .. }
            | TimelineEvent::RefreshCycleMarker { .. }
            | TimelineEvent::WalletSessionMarker { .. } => cov.axis_iii_lifecycle_events += 1,
        }
    }
    cov
}

/// Binary entry.
pub fn run_full_report() -> TimelineReport {
    TimelineReport {
        coverage: coverage_sample(),
        wallclock_leg: run_wallclock_leg(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recorded_sample(p: &SynthParams, seed: u64) -> Vec<TimelineEvent> {
        let mut rng = SplitMix64::new(seed);
        let mut obs = RecordingObserver::new();
        simulate_pair(&mut rng, p, &mut obs);
        obs.events
    }

    /// §6.3: one recorded timeline carries all three event classes.
    #[test]
    fn recorded_timeline_carries_all_three_axes() {
        let events = recorded_sample(&SynthParams::posture(), 42);
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
        // Axis (iii). The funding send is deliberately NOT recorded (GF-7 coin
        // retirement): it is the CT-hidden FCMP++ input, not a chain-attributable
        // event, so the observable lifecycle axis is the session/refresh cadence.
        assert!(has(&|e| matches!(
            e,
            TimelineEvent::WalletSessionMarker { .. }
        )));
        assert!(has(&|e| matches!(
            e,
            TimelineEvent::RefreshCycleMarker { .. }
        )));
    }

    /// Pipeline integrity, correlator-side: the recorded bond-post schedule is
    /// the **causal** placement of the recorded draw — over the events alone.
    /// With the order coin retired the placement is deterministic: the bond post
    /// sits `spread` after the private funding anchor (bond-post offset = spread,
    /// no entry offset, funding-first), and no funding event is recorded (it is
    /// the CT-hidden input). The bond dispatch may carry the dispersal offset, so
    /// this checks the undispersed schedule against the recorded spread.
    #[test]
    fn recorded_schedule_is_the_causal_placement_of_the_recorded_draw() {
        // Dispersal off here so the schedule offset equals the drawn spread.
        let p = SynthParams {
            dispersal_bound: 0,
            ..SynthParams::posture()
        };
        for seed in [1u64, 7, 99, 12345] {
            let events = recorded_sample(&p, seed);

            let spread = events
                .iter()
                .find_map(|e| match e {
                    TimelineEvent::EntryGapDrawConsumed { spread_blocks, .. } => {
                        Some(*spread_blocks)
                    }
                    _ => None,
                })
                .unwrap();

            let bond_offset = events
                .iter()
                .find_map(|e| match e {
                    TimelineEvent::BondPostScheduled {
                        bond_post_offset_blocks,
                        ..
                    } => Some(*bond_post_offset_blocks),
                    _ => None,
                })
                .unwrap();
            // Causal placement: the bond-post offset is exactly the drawn spread.
            assert_eq!(bond_offset, spread);
        }
    }

    /// The D-B3 resume channel is recorded: the resubmit is a second
    /// `BondPostDispatched` whenever a session follows the first dispatch.
    #[test]
    fn resume_channel_is_recorded() {
        let events = recorded_sample(
            &SynthParams {
                resume_redispatch: true,
                ..SynthParams::posture()
            },
            7,
        );
        let recorded = events
            .iter()
            .filter(|e| matches!(e, TimelineEvent::BondPostDispatched { .. }))
            .count();
        assert!((1..=2).contains(&recorded));
    }

    /// Coverage sample reports non-zero counts on every axis.
    #[test]
    fn coverage_sample_counts_every_axis() {
        let cov = coverage_sample();
        assert!(cov.axis_i_bond_post_events >= 3);
        assert!(cov.axis_ii_per_p_submits >= 1);
        assert!(cov.axis_iii_lifecycle_events >= 3);
    }

    // The precondition guards bite (not just exist). The period guards are
    // unreachable through `SynthParams` (the cadence constants are valid), so
    // the reachable guard is the combined seam span.

    #[test]
    #[should_panic(expected = "seam span")]
    fn window_exceeding_half_horizon_is_refused() {
        let mut rng = SplitMix64::new(1);
        let mut obs = RecordingObserver::new();
        simulate_pair(
            &mut rng,
            &SynthParams {
                window: 2_001,
                ..SynthParams::posture()
            },
            &mut obs,
        );
    }

    #[test]
    #[should_panic(expected = "seam span")]
    fn dispersal_exceeding_half_horizon_is_refused() {
        let mut rng = SplitMix64::new(1);
        let mut obs = RecordingObserver::new();
        simulate_pair(
            &mut rng,
            &SynthParams {
                dispersal_bound: 2_001,
                ..SynthParams::posture()
            },
            &mut obs,
        );
    }

    /// The guard is on the *combined* span: window and dispersal each within
    /// the half-horizon individually, but their sum past it, must still be
    /// refused — the case the two pre-fix independent checks let through.
    #[test]
    #[should_panic(expected = "seam span")]
    fn combined_seam_span_exceeding_half_horizon_is_refused() {
        let mut rng = SplitMix64::new(1);
        let mut obs = RecordingObserver::new();
        simulate_pair(
            &mut rng,
            &SynthParams {
                window: 1_500,
                dispersal_bound: 1_500,
                ..SynthParams::posture()
            },
            &mut obs,
        );
    }
}
