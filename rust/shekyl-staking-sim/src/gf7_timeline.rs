//! GF-7 measurement round (WI-4) — the graded genesis gate for principal↔`P`
//! funding-seam unlinkability
//! ([`docs/design/ARCHIVAL_BOND_WI4_MEASUREMENT.md`], built to the pre-committed
//! spec; adversary vocabulary from `ARCHIVAL_BOND_2C_GF7_HOOKS.md` §2/§5).
//!
//! This module is the **only recording implementation** of the
//! `BroadcastTimelineObserver` seam (hooks-spec §4 layer 2 — this crate is a
//! standalone binary no production crate depends on; CI asserts the dependency
//! graph). It drives all three GF-7 correlation axes through one recorded
//! timeline per principal↔`P` pair and grades that timeline against the
//! **a-priori threshold** committed in the WI-4 measurement doc §3:
//!
//! > `r(T_obs) = P(link | T_obs) · N < 2` — the modeled observer may at most
//! > double the blind-guessing success rate (additive advantage `A < 1/N`).
//!
//! # What replaced the pipeline proof
//!
//! Earlier this module held a *pipeline proof*: it proved the recorded stream
//! carried all three axes and the correlator consumed only recorded events,
//! but graded with a deliberately trivial nearest-cadence placeholder
//! (`nearest_principal`). WI-4 replaces that placeholder with the real
//! correlator and turns the module into the graded measurement round. What the
//! pipeline proof established still holds and is still exercised (the coverage
//! sample and the recorded-schedule pipeline-integrity test), but the grading
//! is now the S-3 measurement, not a stand-in.
//!
//! # The three grading arms (measurement doc §4.3)
//!
//! All three run against the **same** recorded timeline; §3's bound is applied
//! to each (§3.4 — a pass on the modeled arm that the stress arm fails is
//! model-limited, a finding, not a pass).
//!
//! - **Modeled S-3** — joint fusion of every axis the S-3 observer sees
//!   (funding seam + principal lifecycle + `P`'s other broadcasts). The
//!   certified-against observer.
//! - **Funding-seam-blind null** (§2's named failure mode) — correlates on
//!   principal-lifecycle cadence **only**, ignoring the funding/entry seam.
//!   Proves the gate is not certified purely on the axis the entry jitter
//!   already handles.
//! - **Stronger-than-S-3 stress** — a likelihood-ratio scorer over the same
//!   joint timeline, density-corrected so a busy principal cannot win by anchor
//!   count alone. The robustness check; the strongest in-model observer.
//!
//! Every arm **fuses** the axes into one score per (bond-post, candidate)
//! pair — a single distance/likelihood over the full feature vector, never an
//! `axis_a * axis_b` product (measurement doc §4.2; the co-trigger structure
//! violates the independence a product would assume).
//!
//! # Instrumentation controls (measurement doc §5)
//!
//! Two controls run **before any graded scenario counts** and gate the run's
//! own validity: a **known-linked** positive control (un-jittered coupling —
//! the correlator must come back linked) and a **known-independent** negative
//! control (bond-post drawn independently of every principal — the correlator
//! must come back at chance). A controls-failed run is emitted **INVALID** and
//! satisfies no acceptance criterion.
//!
//! # Provisional, pre-live (measurement doc §7/§8)
//!
//! This grades the sim's **synthesized** `BondPostDispatched` timeline,
//! including a model of WI-3's intra-tick dispersal draw (`U[0, bound)` via the
//! same `bounded_uniform` the live driver uses, for distributional parity). It
//! is the **continue/redesign checkpoint, not the seal**: the report is marked
//! PROVISIONAL. The sealing re-run against WI-3's *live* `BondPostDispatched`
//! emission is the WI-3↔WI-4 reconvergence leg (b) (rule 21), tracked in
//! `docs/FOLLOWUPS.md`.

use serde::Serialize;
use shekyl_standoff::gf7::{BroadcastTimelineObserver, TimelineEvent};
use shekyl_standoff::{bounded_uniform, draw_entry_gap, plan_entry_seam, DEFAULT_ENTRY_GAP_WINDOW};

use crate::standoff::SplitMix64;

/// The committed a-priori advantage-ratio bound (measurement doc §3.2):
/// `r = P(link) · N < RATIO_BOUND`. Committed in the reviewed design doc
/// **before** this correlator existed; a bar chosen after grading certifies a
/// false floor (§3.5 ordering rule), so this constant is not tunable to fit a
/// sweep — it reopens only if the S-1 model itself is amended (§12 reversion).
pub const RATIO_BOUND: f64 = 2.0;

/// Positive-control pass floor: the known-linked control must link well above
/// baseline for the run to be valid (measurement doc §5 control 1).
const POSITIVE_CONTROL_MIN: f64 = 0.80;

/// Negative-control tolerance: the known-independent control must land within
/// this of the `1/N` baseline for the run to be valid (§5 control 2).
const NEGATIVE_CONTROL_TOL: f64 = 0.05;

/// Correlator timing tolerance floor (blocks). The kernel width is
/// `sigma = max(window, dispersal_bound, SIGMA_FLOOR)`: a well-specified
/// observer sets its tolerance to the jitter budget it is trying to defeat, so
/// widening the defense widens `sigma` and correctly flattens the kernel. The
/// floor keeps the zero-jitter controls well-conditioned.
const SIGMA_FLOOR: u64 = 30;

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

/// Principal activity regime (measurement doc §3.3 / §6). Graded and reported
/// distinctly; a low-activity result is never permitted to move the
/// steady-state bar.
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Regime {
    /// `N` at or above the target cover — the ratio bound is the pass/fail gate.
    SteadyState,
    /// `N` small (thin cover) — the named pre-seal residual (L12); reported,
    /// not gating.
    LowActivity,
}

impl Regime {
    fn label(self) -> &'static str {
        match self {
            Regime::SteadyState => "steady",
            Regime::LowActivity => "low-activity",
        }
    }

    /// Horizon and session-period range for the regime. Low-activity is a
    /// long-period, few-session cadence over a longer horizon — the standoff's
    /// proven worst case (funds one bond, rarely spends): sparse cadence gives
    /// the blind arm little to hide the seam among.
    fn cadence(self) -> (u64, (u64, u64)) {
        match self {
            Regime::SteadyState => (4_000, (40, 400)),
            Regime::LowActivity => (8_000, (1_500, 3_000)),
        }
    }
}

/// Entry-gap draw shape (measurement doc §10 row 3).
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DrawShape {
    /// The real shipped `draw_entry_gap` (uniform-independent spread).
    Direct,
    /// The conformance-trap draw: two offsets jittered off a common anchor,
    /// spread = their difference (triangular, peaked at zero — clusters the
    /// funding and bond events). The standoff's "shared trigger is
    /// catastrophic" negative anchor; demonstrates the correlator bites when
    /// the draw is wrong.
    Trap,
}

impl DrawShape {
    fn label(self) -> &'static str {
        match self {
            DrawShape::Direct => "direct",
            DrawShape::Trap => "trap",
        }
    }
}

/// One pair's synthesis parameters — the swept surface (measurement doc §10)
/// plus the control couplings (§5), all in logical block time.
#[derive(Clone, Copy)]
pub struct SynthParams {
    pub window: u64,
    /// Order-coin on/off. Off ⇒ funding always precedes the bond (no inversion
    /// prior break) — the standoff's low-activity lever.
    pub inversion: bool,
    /// WI-3 intra-tick dispersal bound (blocks): the bond dispatch gets
    /// `U[0, dispersal_bound)` added via `bounded_uniform`, matching the live
    /// driver's draw shape for distributional parity (§7). `0` = no dispersal.
    pub dispersal_bound: u64,
    pub draw_shape: DrawShape,
    /// Known-independent negative control (§5 control 2): the bond dispatch
    /// time is drawn independently of the principal's lifecycle. The correlator
    /// must come back at chance.
    pub independent_bond: bool,
    pub regime: Regime,
    /// Model the D-B3 resume channel: an unconfirmed post re-dispatched at the
    /// wallet's next session open (WI-3 resubmits at the next due tick; a
    /// close/reopen with a pending post puts that tick at session-open, so the
    /// resubmit's `BondPostDispatched` lands **on the session lattice** — a
    /// chain-visible event carrying the session clock directly). Swept as its
    /// own group; the normal path (confirmed first dispatch, no resubmit) is
    /// the posture.
    pub resume_redispatch: bool,
}

impl SynthParams {
    /// The recommended posture (measurement doc §3.2 / standoff): 600-block
    /// uniform-independent window, inversion on, steady-state — and
    /// `dispersal_bound = 0` because the *realistic* dispersal is sub-block.
    ///
    /// WI-3's dispersal is `U[0, DEFAULT_PSCAN_CADENCE)` = `U[0, 60s)`, well
    /// under one block, so in block-granular logical time it is ≈0 blocks: it
    /// decorrelates the wall-clock *sweep phase* (a network-arrival channel),
    /// not the block-time funding seam this correlator grades (measurement doc
    /// §7 / WI-3 §3.2). The block-time gate is therefore carried by the
    /// entry-gap window jitter and evaluated at `dispersal=0`; the block-unit
    /// dispersal *sweep* (the `dispersal` group) is a coarse-tick counterfactual
    /// bracket, and the wall-clock sweep-phase channel is graded by the live
    /// re-run (leg b, §8).
    fn posture() -> Self {
        Self {
            window: DEFAULT_ENTRY_GAP_WINDOW,
            inversion: true,
            dispersal_bound: 0,
            draw_shape: DrawShape::Direct,
            independent_bond: false,
            regime: Regime::SteadyState,
            resume_redispatch: false,
        }
    }

    /// A row is gate-relevant iff it sits at the realistic recommended posture
    /// (steady-state, real draw, inversion on, full window, realistic sub-block
    /// dispersal ⇒ `dispersal_bound == 0`): the swept surface around it (weaker
    /// windows, inversion off, the trap, low-activity, and the block-unit
    /// dispersal counterfactual) is reported as context/anchors, not as the
    /// pass/fail gate (measurement doc §3.2/§3.3/§3.5).
    fn gate_relevant(&self) -> bool {
        self.regime == Regime::SteadyState
            && self.draw_shape == DrawShape::Direct
            && self.inversion
            && self.window == DEFAULT_ENTRY_GAP_WINDOW
            && self.dispersal_bound == 0
            && !self.independent_bond
            && !self.resume_redispatch
    }

    /// Correlator kernel width for this posture (blocks).
    fn sigma(&self) -> u64 {
        self.window.max(self.dispersal_bound).max(SIGMA_FLOOR)
    }
}

/// Synthesize one principal↔`P` pair's joint timeline into `observer`.
///
/// Cadence model (pessimistic per measurement doc §6): the principal runs
/// near-periodic wallet sessions (with a refresh each) at `phase + k·period`;
/// the funding intent **co-triggers** with a session (GATE6 §6/S-1), a drain
/// rides a later session, and the persona makes two later `PerP` submits. The
/// entry-seam placement is the real pipeline (`draw_entry_gap` →
/// `plan_entry_seam`) for the [`DrawShape::Direct`] shape; the bond dispatch
/// then gets WI-3's modeled intra-tick dispersal added.
///
/// # Preconditions (asserted — misconfiguration fails loudly)
///
/// - `1 <= period_range.0 <= period_range.1` (a zero period breaks the cadence
///   arithmetic; an inverted range underflows the width).
/// - `period_range.1 <= horizon / 2` (the private anchor lands in the first
///   half).
/// - `window + max(dispersal_bound − 1, 0) <= horizon / 2` (the combined seam
///   span: the anchor lands by `horizon / 2`, the bond dispatch lands at most
///   `window + (dispersal_bound − 1)` after it, so this is exactly the bound
///   that keeps every seam event on the recorded timeline, not past its end —
///   two separate half-horizon checks would not compose to that guarantee).
fn simulate_pair(rng: &mut SplitMix64, p: &SynthParams, observer: &mut RecordingObserver) {
    let (horizon, (pmin, pmax)) = p.regime.cadence();
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

    // Axis (i): the entry seam. Direct = the real shipped draw; Trap = the
    // conformance-trap draw (two offsets off a common anchor, spread = diff).
    let (spread_blocks, bond_first) = match p.draw_shape {
        DrawShape::Direct => {
            let (spread, coin) = draw_entry_gap(p.window, rng);
            (spread, if p.inversion { coin } else { false })
        }
        DrawShape::Trap => {
            let a = if p.window > 0 {
                bounded_uniform(rng, p.window)
            } else {
                0
            };
            let b = if p.window > 0 {
                bounded_uniform(rng, p.window)
            } else {
                0
            };
            let coin = b < a;
            (a.abs_diff(b), if p.inversion { coin } else { false })
        }
    };
    observer.record(TimelineEvent::EntryGapDrawConsumed {
        persona: 0,
        window_blocks: p.window,
        spread_blocks,
        bond_first,
    });
    let plan = plan_entry_seam((spread_blocks, bond_first));
    observer.record(TimelineEvent::BondPostScheduled {
        persona: 0,
        entry_offset_blocks: plan.entry_offset_blocks,
        bond_post_offset_blocks: plan.bond_post_offset_blocks,
    });
    observer.record(TimelineEvent::FundingSendDispatched {
        at: t0 + plan.entry_offset_blocks,
    });

    // WI-3 intra-tick dispersal: add `U[0, dispersal_bound)` to the scheduled
    // dispatch, drawn via the *same* `bounded_uniform` the live driver uses
    // (measurement doc §7 — distributional parity between sim and driver).
    let dispersal = if p.dispersal_bound > 0 {
        bounded_uniform(rng, p.dispersal_bound - 1)
    } else {
        0
    };
    let bond_at = if p.independent_bond {
        // §5 control 2: dispatch time independent of the principal lifecycle.
        bounded_uniform(rng, horizon.saturating_sub(1).max(1))
    } else {
        t0 + plan.bond_post_offset_blocks + dispersal
    };
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

/// The first bond-post dispatch time, read back **from the recorded stream**
/// (the correlator's view — never sim internals). Production scoring goes
/// through [`query_times`] (all dispatches); this single-event accessor
/// remains for the pipeline-integrity test, which checks the *first* dispatch
/// against the recorded seam plan.
#[cfg(test)]
fn recorded_bond_time(events: &[TimelineEvent]) -> u64 {
    events
        .iter()
        .find_map(|e| match e {
            TimelineEvent::BondPostDispatched { at, .. } => Some(*at),
            _ => None,
        })
        .expect("every pair timeline records a bond-post dispatch")
}

/// The persona-side query the correlator scores against every candidate
/// principal's activity: **every** `BondPostDispatched` time (axis i — the
/// GF-7 events being de-anonymized). WI-3's emission-completeness contract is
/// per-submit — the first send *and* each byte-identical resubmit are network
/// exposures — so the query scores them all; under the D-B3 resume scenario
/// the resubmit lands on the session lattice and is exactly the exposure the
/// `resume` sweep group grades.
///
/// Axis (ii) — the persona's other broadcasts (`PerPSubmitDispatched`) — is
/// carried in the recorded stream (coverage proves it present) but is **not**
/// scored: in the current synthesis those submits are *persona-timed* (a fixed
/// offset after the bond), not *principal-timed*, so they carry no
/// principal-linkage signal — feeding them to the scorer injects a candidate-
/// density artifact, not a real channel (a busy principal would win by anchor
/// count alone). A rational S-3 observer weights a signal-free axis zero. When
/// a later slice makes per-`P` cadence principal-coupled (serve-credit claim
/// cadence, SP-T4b), the query extends to include axis (ii); the joint-fusion
/// scorer already sums over the query vector, so that is a one-line change.
fn query_times(events: &[TimelineEvent]) -> Vec<u64> {
    events
        .iter()
        .filter_map(|e| match e {
            TimelineEvent::BondPostDispatched { at, .. } => Some(*at),
            _ => None,
        })
        .collect()
}

/// Principal-lifecycle feature times (axis iii) — the funding-seam-blind arm's
/// anchor set: the lifecycle events observable under the recommended posture —
/// the **drain** (§4.2: "every drain is a co-trigger") — **excluding** the
/// funding seam (that is axis i).
///
/// # The marker exclusion is a posture theorem, not a modeling convention
///
/// `WalletSessionMarker` / `RefreshCycleMarker` are excluded as **direct**
/// anchors, and the exclusion is sound **only under the local-daemon posture**
/// (measurement doc §4.1 as amended; the D-B1/D-B6 trust-fact family): a
/// refresh is the wallet pulling blocks from, and a session is the wallet
/// opening against, the *local* daemon — loopback traffic no chain reader,
/// and no network-position observer on the host's uplink, can see (the
/// daemon's own p2p sync rhythm is decoupled from wallet activity). Under a
/// **remote / non-isolated-daemon posture** the wallet's polling cadence is
/// network-observable (connection timing / traffic volume to a daemon the
/// user does not control) and the markers become live anchors — that posture
/// **reopens this exclusion** and the gate must be re-graded with them in
/// (the pre-fix measurement is the shape of that world: `r ≈ 5`, a fail).
/// Same reopen family as WI-3's D-B1 tip-clock invariant (2d-2).
///
/// # The indirect channel is *not* excluded — it is graded
///
/// Excluding the markers as direct anchors does not remove session cadence
/// from the observable world, because `simulate_pair` **couples** the
/// chain-visible events to the session lattice: `t0` (funding co-trigger) *is*
/// a session, the drain *is* a session, and the D-B3 resume resubmit lands on
/// a session (the `resume` sweep group). The blind arm scoring drains against
/// the bond is therefore grading the session clock *through* its chain-visible
/// shadow — `blind = 0.237` at window 0 (well above the 0.1 baseline) is that
/// indirect channel measured live, and the entry jitter driving it to ≈0.13 is
/// the decorrelation doing real work against it, not against a refresh-free
/// world.
fn lifecycle_times(events: &[TimelineEvent]) -> Vec<u64> {
    events
        .iter()
        .filter_map(|e| match e {
            TimelineEvent::DrainDispatched { at } => Some(*at),
            _ => None,
        })
        .collect()
}

/// Funding-send feature times (axis i seam).
fn funding_times(events: &[TimelineEvent]) -> Vec<u64> {
    events
        .iter()
        .filter_map(|e| match e {
            TimelineEvent::FundingSendDispatched { at } => Some(*at),
            _ => None,
        })
        .collect()
}

/// Joint linkage score of a persona's query under a candidate principal's
/// anchor set: for each query event, the nearest anchor's **bounded** Gaussian
/// kernel `exp(-d²/2σ²) ∈ (0,1]`, summed. This is the **joint fusion**
/// (measurement doc §4.2): one score over the full feature vector, never a
/// per-axis product.
///
/// The kernel is bounded on purpose (sum-rule fusion, not a log-likelihood
/// sum): an event with no near anchor contributes ≈0 to *every* candidate, so
/// noise axes (e.g. the per-`P` submits, which carry no principal signal in
/// this synthesis) wash out equally rather than swamping the discriminating
/// bond-post term. Higher = more consistent with the candidate; empty
/// anchors ⇒ `0`.
fn kernel_sum(query: &[u64], anchors: &[u64], sigma2: f64) -> f64 {
    if anchors.is_empty() {
        return 0.0;
    }
    let mut s = 0.0;
    for &q in query {
        let dmin = anchors
            .iter()
            .map(|&a| a.abs_diff(q))
            .min()
            .expect("anchors non-empty");
        let d = dmin as f64;
        s += (-(d * d) / (2.0 * sigma2)).exp();
    }
    s
}

/// The three grading arms (measurement doc §4.3).
#[derive(Clone, Copy)]
enum Arm {
    /// Lifecycle cadence only — the §2 named failure mode.
    Blind,
    /// Funding seam ∪ lifecycle, joint MAP — the modeled S-3 observer.
    ModeledS3,
}

/// Per-arm anchor sets for one candidate principal.
struct Candidate {
    lifecycle: Vec<u64>,
    funding: Vec<u64>,
    s3: Vec<u64>,
}

/// Score one candidate under one single-correlator arm.
fn arm_score(arm: Arm, query: &[u64], c: &Candidate, sigma2: f64) -> f64 {
    match arm {
        Arm::Blind => kernel_sum(query, &c.lifecycle, sigma2),
        Arm::ModeledS3 => kernel_sum(query, &c.s3, sigma2),
    }
}

/// Argmax candidate under one arm (ties → lowest index, deterministic).
fn guess(arm: Arm, query: &[u64], candidates: &[Candidate], sigma2: f64) -> usize {
    let mut best = (f64::NEG_INFINITY, 0usize);
    for (idx, c) in candidates.iter().enumerate() {
        let s = arm_score(arm, query, c, sigma2);
        if s > best.0 {
            best = (s, idx);
        }
    }
    best.1
}

/// Density-corrected MAP: `kernel_sum / anchor_count` discounts "near by
/// chance," so a sparse candidate with one close anchor can beat a dense
/// candidate the plain MAP would reward on anchor count alone. One member of
/// the stress panel (`grade`).
fn guess_density_corrected(query: &[u64], candidates: &[Candidate], sigma2: f64) -> usize {
    let mut best = (f64::NEG_INFINITY, 0usize);
    for (idx, c) in candidates.iter().enumerate() {
        let s = kernel_sum(query, &c.s3, sigma2) / (c.s3.len().max(1) as f64);
        if s > best.0 {
            best = (s, idx);
        }
    }
    best.1
}

/// Seam-consistency-gated MAP — the **exact in-model likelihood filter**, the
/// panel's Neyman-Pearson-honest member. The generative model puts the
/// **first** bond dispatch within `spread + dispersal` of the candidate's
/// funding send (`plan_entry_seam`: one offset is `0`, the other
/// `spread ~ U[0, window]`, dispersal `U[0, dispersal_bound)` added on top),
/// so the true candidate **always** has its earliest dispatch inside `bound`
/// of a funding send — that box is the true support of the seam likelihood,
/// and candidates outside it have exact likelihood zero. The correlator
/// hard-rejects them and runs the kernel MAP among the survivors: strictly
/// better use of the known model than the smooth kernel alone whenever the
/// plain MAP would have picked an inconsistent candidate.
///
/// The gate reads only the **earliest** dispatch (`min`, an observer-realizable
/// statistic over the recorded timestamps): the D-B3 resume resubmit lands on
/// the session lattice, not the seam, so admitting a candidate on resubmit
/// proximity would widen the gate past the true support — exactly the
/// exact-zero-likelihood leak the filter exists to reject. The first dispatch
/// alone carries the seam, and it always admits the truth.
fn guess_consistency_gated(
    query: &[u64],
    candidates: &[Candidate],
    sigma2: f64,
    bound: u64,
) -> usize {
    let consistent = |c: &Candidate| {
        query
            .iter()
            .min()
            .is_some_and(|&first| c.funding.iter().any(|&f| first.abs_diff(f) <= bound))
    };
    let mut best = (f64::NEG_INFINITY, 0usize);
    for (idx, c) in candidates.iter().enumerate() {
        // Inconsistent candidates score below every consistent one
        // (kernel_sum ≥ 0), preserving deterministic lowest-index ties.
        let s = if consistent(c) {
            kernel_sum(query, &c.s3, sigma2)
        } else {
            -1.0
        };
        if s > best.0 {
            best = (s, idx);
        }
    }
    best.1
}

/// Grade one parameter point: `trials` independent worlds of `n` pairs each;
/// all three arms consume only the recorded streams. Returns `(blind, s3, lr)`
/// P(link) over `trials · n` linking decisions.
fn grade(p: &SynthParams, n: usize, trials: u32, rng: &mut SplitMix64) -> (f64, f64, f64) {
    let sigma = p.sigma() as f64;
    let sigma2 = sigma * sigma;
    let total = trials as u64 * n as u64;
    let (mut blind, mut s3, mut lr) = (0u64, 0u64, 0u64);

    for _ in 0..trials {
        let streams: Vec<Vec<TimelineEvent>> = (0..n)
            .map(|_| {
                let mut obs = RecordingObserver::new();
                simulate_pair(rng, p, &mut obs);
                obs.events
            })
            .collect();

        let candidates: Vec<Candidate> = streams
            .iter()
            .map(|ev| {
                let lifecycle = lifecycle_times(ev);
                let funding = funding_times(ev);
                let mut s3 = funding.clone();
                s3.extend_from_slice(&lifecycle);
                Candidate {
                    lifecycle,
                    funding,
                    s3,
                }
            })
            .collect();

        // The exact in-model seam support: `spread ≤ window` plus the maximum
        // dispersal added to the dispatch — the draw is `U[0, dispersal_bound)`
        // (`bounded_uniform(max = dispersal_bound - 1)`, matching the live
        // driver), so its supremum is `dispersal_bound - 1`, not
        // `dispersal_bound`. A bound wider by even one block admits candidates
        // with exact likelihood zero and understates the gated member — the
        // stress panel must be graded on the tight support
        // (guess_consistency_gated docs).
        let seam_bound = p.window + p.dispersal_bound.saturating_sub(1);

        for (truth, ev) in streams.iter().enumerate() {
            let query = query_times(ev);
            if guess(Arm::Blind, &query, &candidates, sigma2) == truth {
                blind += 1;
            }
            let s3_hit = guess(Arm::ModeledS3, &query, &candidates, sigma2) == truth;
            if s3_hit {
                s3 += 1;
            }
            // Stronger-than-S-3 stress panel (§4.3 as amended): an
            // oracle-panel upper bound — link if *any* fielded correlator
            // identifies truth (MAP, density-corrected MAP, or the exact
            // seam-consistency-gated MAP). The oracle framing is deliberate:
            // it upper-bounds every realizable per-instance strategy over
            // these correlators, so `lr ≥ s3` cannot certify a floor the
            // panel's stronger members break — the gated member is where the
            // exact generative knowledge bites.
            let dens_hit = guess_density_corrected(&query, &candidates, sigma2) == truth;
            let gated_hit =
                guess_consistency_gated(&query, &candidates, sigma2, seam_bound) == truth;
            if s3_hit || dens_hit || gated_hit {
                lr += 1;
            }
        }
    }

    (
        blind as f64 / total as f64,
        s3 as f64 / total as f64,
        lr as f64 / total as f64,
    )
}

/// One arm's graded result at one parameter point.
#[derive(Serialize)]
pub struct ArmResult {
    pub p_link: f64,
    /// Advantage ratio `r = P(link) · N`; `< RATIO_BOUND` is the per-arm bar.
    pub ratio: f64,
    pub clears_bound: bool,
}

impl ArmResult {
    fn new(p_link: f64, n: usize) -> Self {
        let ratio = p_link * n as f64;
        Self {
            p_link,
            ratio,
            clears_bound: ratio < RATIO_BOUND,
        }
    }
}

/// One row of the swept grading surface.
#[derive(Serialize)]
pub struct ScenarioRow {
    pub group: &'static str,
    pub window_blocks: u64,
    pub inversion: bool,
    pub dispersal_bound: u64,
    pub draw_shape: &'static str,
    pub regime: &'static str,
    pub n: usize,
    pub baseline: f64,
    pub blind: ArmResult,
    pub modeled_s3: ArmResult,
    pub lr_stress: ArmResult,
    /// All graded arms clear the bound.
    pub pass: bool,
    /// This row sits at the recommended posture family — it participates in the
    /// steady-state gate verdict (measurement doc §3.2/§3.5).
    pub gate_relevant: bool,
}

/// A control result and its validity verdict (measurement doc §5).
#[derive(Serialize)]
pub struct ControlResult {
    pub name: &'static str,
    pub p_link: f64,
    pub baseline: f64,
    pub expectation: &'static str,
    pub passed: bool,
}

/// Event-class coverage over one representative recorded timeline (§6.3
/// evidence, reported rather than asserted-only).
#[derive(Serialize)]
pub struct AxisCoverage {
    pub axis_i_bond_post_events: usize,
    pub axis_ii_per_p_submits: usize,
    pub axis_iii_lifecycle_events: usize,
}

/// The full graded measurement report.
#[derive(Serialize)]
pub struct MeasurementReport {
    /// Always true for this module: it grades the synthesized timeline; the
    /// live-driver sealing re-run is the reconvergence leg (b) (measurement doc
    /// §8), tracked in FOLLOWUPS, not performed here.
    pub provisional: bool,
    pub ratio_bound: f64,
    pub n_principals: usize,
    pub trials: u32,
    pub controls_valid: bool,
    /// PROVISIONAL-PASS / PROVISIONAL-FAIL / INVALID — the steady-state gate
    /// verdict over the gate-relevant rows (measurement doc §3.5).
    pub gate_status: String,
    pub controls: Vec<ControlResult>,
    pub coverage: AxisCoverage,
    pub rows: Vec<ScenarioRow>,
}

/// Full-run config (binary evidence generation).
struct RunConfig {
    n: usize,
    trials: u32,
    seed: u64,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            // N = TARGET_ANON_SET (standoff steady-state cover) ⇒ baseline 0.1,
            // absolute bar 0.20 (measurement doc §3.2 posture-anchored instance).
            n: 10,
            trials: 1_000,
            seed: 0x6F7_7A11_2C2B_0002,
        }
    }
}

/// Run the two validity controls (measurement doc §5); both must pass for the
/// graded rows to count.
fn run_controls(cfg: &RunConfig, rng: &mut SplitMix64) -> (Vec<ControlResult>, bool) {
    let baseline = 1.0 / cfg.n as f64;

    // Positive: un-jittered coupling (window 0, no dispersal) — must link.
    let pos = SynthParams {
        window: 0,
        inversion: true,
        dispersal_bound: 0,
        draw_shape: DrawShape::Direct,
        independent_bond: false,
        regime: Regime::SteadyState,
        resume_redispatch: false,
    };
    let (_, pos_s3, _) = grade(&pos, cfg.n, cfg.trials, rng);
    let pos_ok = pos_s3 >= POSITIVE_CONTROL_MIN;

    // Negative: bond dispatch independent of the principal — must be at chance.
    let neg = SynthParams {
        independent_bond: true,
        ..SynthParams::posture()
    };
    let (_, neg_s3, _) = grade(&neg, cfg.n, cfg.trials, rng);
    let neg_ok = (neg_s3 - baseline).abs() < NEGATIVE_CONTROL_TOL;

    let controls = vec![
        ControlResult {
            name: "known-linked (positive)",
            p_link: pos_s3,
            baseline,
            expectation: "P(link) >= 0.80 (the tripwire must bite)",
            passed: pos_ok,
        },
        ControlResult {
            name: "known-independent (negative)",
            p_link: neg_s3,
            baseline,
            expectation: "|P(link) - 1/N| < 0.05 (no manufactured linkage)",
            passed: neg_ok,
        },
    ];
    (controls, pos_ok && neg_ok)
}

/// The pre-committed sweep surface (measurement doc §10), as named groups that
/// each vary one axis around the recommended posture.
fn sweep_specs() -> Vec<(&'static str, SynthParams)> {
    let mut specs = Vec::new();
    let base = SynthParams::posture();

    // Group "window": entry-jitter sweep (else posture).
    for w in [0, 60, 300, DEFAULT_ENTRY_GAP_WINDOW] {
        specs.push(("window", SynthParams { window: w, ..base }));
    }
    // Group "dispersal": WI-3 dispersal-bound sweep (within the gate family).
    for d in [0, 150, 300, DEFAULT_ENTRY_GAP_WINDOW, 1_200] {
        specs.push((
            "dispersal",
            SynthParams {
                dispersal_bound: d,
                ..base
            },
        ));
    }
    // Group "inversion": order-coin off/on (the low-activity lever).
    for inv in [false, true] {
        specs.push((
            "inversion",
            SynthParams {
                inversion: inv,
                window: 300,
                ..base
            },
        ));
    }
    // Group "draw": real vs conformance-trap draw (negative anchor).
    for shape in [DrawShape::Direct, DrawShape::Trap] {
        specs.push((
            "draw",
            SynthParams {
                draw_shape: shape,
                ..base
            },
        ));
    }
    // Group "regime": steady-state vs low-activity/cold-start.
    for regime in [Regime::SteadyState, Regime::LowActivity] {
        specs.push(("regime", SynthParams { regime, ..base }));
    }
    // Group "resume": the D-B3 resume channel — an unconfirmed post's
    // resubmit at wallet reopen lands a chain-visible `BondPostDispatched`
    // on the session lattice. Context row (conditional path), graded so the
    // channel is measured, not assumed away.
    for resume in [false, true] {
        specs.push((
            "resume",
            SynthParams {
                resume_redispatch: resume,
                ..base
            },
        ));
    }
    specs
}

/// Coverage counts over one representative recorded timeline (fresh RNG arm,
/// does not perturb the graded stream).
fn coverage_sample(cfg: &RunConfig) -> AxisCoverage {
    let mut rng = SplitMix64(cfg.seed ^ 0xC0DE);
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
            TimelineEvent::FundingSendDispatched { .. }
            | TimelineEvent::DrainDispatched { .. }
            | TimelineEvent::RefreshCycleMarker { .. }
            | TimelineEvent::WalletSessionMarker { .. } => cov.axis_iii_lifecycle_events += 1,
        }
    }
    cov
}

/// Run the full graded measurement (config-driven so tests can run a small
/// surface; `run_full_report` is the binary evidence config).
fn run_measurement(cfg: &RunConfig) -> MeasurementReport {
    let mut rng = SplitMix64(cfg.seed);
    let baseline = 1.0 / cfg.n as f64;

    // Controls first (measurement doc §5): they gate the run's validity.
    let (controls, controls_valid) = run_controls(cfg, &mut rng);

    let rows: Vec<ScenarioRow> = sweep_specs()
        .into_iter()
        .map(|(group, p)| {
            let (blind, s3, lr) = grade(&p, cfg.n, cfg.trials, &mut rng);
            let (blind, s3, lr) = (
                ArmResult::new(blind, cfg.n),
                ArmResult::new(s3, cfg.n),
                ArmResult::new(lr, cfg.n),
            );
            let pass = blind.clears_bound && s3.clears_bound && lr.clears_bound;
            ScenarioRow {
                group,
                window_blocks: p.window,
                inversion: p.inversion,
                dispersal_bound: p.dispersal_bound,
                draw_shape: p.draw_shape.label(),
                regime: p.regime.label(),
                n: cfg.n,
                baseline,
                blind,
                modeled_s3: s3,
                lr_stress: lr,
                pass,
                gate_relevant: p.gate_relevant(),
            }
        })
        .collect();

    let gate_status = if !controls_valid {
        "INVALID (controls failed — the run counts for nothing)".to_string()
    } else if rows.iter().filter(|r| r.gate_relevant).all(|r| r.pass) {
        "PROVISIONAL-PASS (local-daemon posture only; remote-daemon posture unmet, \
         named residual; wall-clock leg b open)"
            .to_string()
    } else {
        "PROVISIONAL-FAIL (decorrelation-redesign signal; pre-WI-3-live)".to_string()
    };

    MeasurementReport {
        provisional: true,
        ratio_bound: RATIO_BOUND,
        n_principals: cfg.n,
        trials: cfg.trials,
        controls_valid,
        gate_status,
        controls,
        coverage: coverage_sample(cfg),
        rows,
    }
}

/// Binary entry: the full graded measurement (evidence config).
pub fn run_full_report() -> MeasurementReport {
    run_measurement(&RunConfig::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_standoff::EntrySeamPlan;

    /// Small config for fast, deterministic tests (the binary uses the full
    /// surface via `run_full_report`).
    fn small() -> RunConfig {
        RunConfig {
            n: 6,
            trials: 80,
            seed: 0x51DE_0001,
        }
    }

    fn recorded_sample(p: &SynthParams, seed: u64) -> Vec<TimelineEvent> {
        let mut rng = SplitMix64(seed);
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
    /// funding event time are exactly that plan — over the events alone. The
    /// bond dispatch may carry the dispersal offset, so we check the funding
    /// event (undispersed) against the plan and the schedule/order separately.
    #[test]
    fn recorded_schedule_is_the_planner_over_the_recorded_draw() {
        // Dispersal off here so the bond↔funding separation equals the spread.
        let p = SynthParams {
            dispersal_bound: 0,
            ..SynthParams::posture()
        };
        for seed in [1u64, 7, 99, 12345] {
            let events = recorded_sample(&p, seed);

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

    /// The controls gate the run (measurement doc §5): the known-linked
    /// positive control links, the known-independent negative control is at
    /// chance. If this ever breaks, every graded number is measuring
    /// `P(link | axes independent)` and must not be trusted.
    #[test]
    fn controls_pass_on_the_measurement() {
        let report = run_measurement(&small());
        assert!(
            report.controls_valid,
            "controls must gate the run valid: {:?}",
            report
                .controls
                .iter()
                .map(|c| (c.name, c.p_link, c.passed))
                .collect::<Vec<_>>()
        );
        let pos = &report.controls[0];
        let neg = &report.controls[1];
        assert!(pos.passed && pos.p_link >= POSITIVE_CONTROL_MIN);
        assert!(neg.passed && (neg.p_link - neg.baseline).abs() < NEGATIVE_CONTROL_TOL);
    }

    /// The funding-seam-blind null is no stronger than the seam-using S-3 arm
    /// (the funding seam is real signal the null throws away), the stress
    /// panel dominates the modeled S-3 on every row (`lr ≥ s3` is the panel's
    /// oracle-union construction — the property that makes it an upper bound
    /// rather than a second opinion), and all arms are well-defined
    /// probabilities. Deterministic via the seeded PRNG.
    #[test]
    fn blind_null_is_no_stronger_than_the_seam_arm() {
        let report = run_measurement(&small());
        let posture = report
            .rows
            .iter()
            .find(|r| r.group == "window" && r.window_blocks == DEFAULT_ENTRY_GAP_WINDOW)
            .unwrap();
        for a in [&posture.blind, &posture.modeled_s3, &posture.lr_stress] {
            assert!((0.0..=1.0).contains(&a.p_link));
        }
        assert!(posture.blind.p_link <= posture.modeled_s3.p_link + 1e-9);
        for r in &report.rows {
            assert!(
                r.lr_stress.p_link >= r.modeled_s3.p_link - 1e-9,
                "stress panel must dominate the modeled S-3 (group {}, win {})",
                r.group,
                r.window_blocks
            );
        }
    }

    /// The D-B3 resume channel is graded, not assumed away: the `resume` group
    /// carries both the off and on rows, and the on row records a second
    /// bond-post exposure on the session lattice (query length 2).
    #[test]
    fn resume_channel_is_swept_and_recorded() {
        let report = run_measurement(&small());
        let on = report.rows.iter().filter(|r| r.group == "resume").count();
        assert_eq!(on, 2, "resume group grades off and on");

        let events = recorded_sample(
            &SynthParams {
                resume_redispatch: true,
                ..SynthParams::posture()
            },
            7,
        );
        // Two exposures whenever a session exists after the first dispatch —
        // seed-dependent, so accept 1 or 2 but require the query plumbing to
        // carry every dispatch it recorded.
        let dispatches = query_times(&events);
        let recorded = events
            .iter()
            .filter(|e| matches!(e, TimelineEvent::BondPostDispatched { .. }))
            .count();
        assert_eq!(dispatches.len(), recorded);
        assert!((1..=2).contains(&recorded));
    }

    /// Widening the entry jitter degrades the seam-using arm (the jitter works
    /// on the axis it targets): the zero-window row (dispersal only) links
    /// better than the full-window row (dispersal + full entry spread).
    #[test]
    fn jitter_degrades_the_seam_arm() {
        let report = run_measurement(&small());
        let by_window = |w: u64| {
            report
                .rows
                .iter()
                .find(|r| r.group == "window" && r.window_blocks == w)
                .unwrap()
        };
        let w0 = by_window(0);
        let w600 = by_window(DEFAULT_ENTRY_GAP_WINDOW);
        assert!(w0.modeled_s3.p_link > w600.modeled_s3.p_link);
    }

    /// The conformance-trap draw is catastrophically more linkable than the
    /// real draw at the same posture (the standoff's "shared trigger is
    /// catastrophic" negative anchor, reproduced): the trap clusters the seam,
    /// so the S-3 arm links much harder than under the shipped uniform draw.
    #[test]
    fn conformance_trap_is_more_linkable_than_the_real_draw() {
        let report = run_measurement(&small());
        let direct = report
            .rows
            .iter()
            .find(|r| r.group == "draw" && r.draw_shape == "direct")
            .unwrap();
        let trap = report
            .rows
            .iter()
            .find(|r| r.group == "draw" && r.draw_shape == "trap")
            .unwrap();
        assert!(trap.modeled_s3.p_link > direct.modeled_s3.p_link);
    }

    /// The report is well-formed: every row carries all three arms with ratios
    /// = P(link)·N, the gate family is non-empty, and the status is provisional.
    #[test]
    fn report_is_well_formed() {
        let report = run_measurement(&small());
        assert!(report.provisional);
        assert_eq!(report.ratio_bound, RATIO_BOUND);
        assert!(report.rows.iter().any(|r| r.gate_relevant));
        for r in &report.rows {
            for a in [&r.blind, &r.modeled_s3, &r.lr_stress] {
                assert!((a.ratio - a.p_link * r.n as f64).abs() < 1e-9);
                assert_eq!(a.clears_bound, a.ratio < RATIO_BOUND);
            }
        }
        assert!(
            report.gate_status.starts_with("PROVISIONAL")
                || report.gate_status.starts_with("INVALID")
        );
    }

    /// Coverage sample reports non-zero counts on every axis.
    #[test]
    fn coverage_sample_counts_every_axis() {
        let cov = coverage_sample(&small());
        assert!(cov.axis_i_bond_post_events >= 3);
        assert!(cov.axis_ii_per_p_submits >= 1);
        assert!(cov.axis_iii_lifecycle_events >= 3);
    }

    // The precondition guards bite (not just exist). The period guard is
    // unreachable through `SynthParams` (the regime enum's cadence is always
    // internally valid), so the reachable guard is the combined seam span.

    #[test]
    #[should_panic(expected = "seam span")]
    fn window_exceeding_half_horizon_is_refused() {
        let mut rng = SplitMix64(1);
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
        let mut rng = SplitMix64(1);
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
        let mut rng = SplitMix64(1);
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
