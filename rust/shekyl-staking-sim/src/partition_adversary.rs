//! §14.4 partition-adversary arm (WI-4 / GF-7) — the correlator probe that
//! gates the founder-cover launch-posture claim
//! ([`docs/design/ARCHIVAL_BOND_WI4_MEASUREMENT.md`] §14.4, frozen spec; §17
//! rounds R4–R7 ratified 2026-07-11, PR #290).
//!
//! # What this arm tests
//!
//! Not "2-means fails" but the stronger null (§14.4): *no decision rule the
//! adversary can field over the observable set recovers the founder/user
//! labels better than chance.* The arm synthesizes `M = 5` founder pairs and
//! `N − M` user pairs from the **same generator at the same posture** (P1's
//! indistinguishability-by-construction), fields a **named rule family `F`**
//! over a **named feature dictionary**, and reports the maximum label-agreement
//! `T` over `F`, calibrated against the permutation distribution of that same
//! maximized statistic.
//!
//! # Co-first deliverables (this slice)
//!
//! R4/R5 bind two deliverables to land **before any sweep grades** (§14.4):
//!
//! 1. **The gating lemma** ([`gating_lemma_bound`]) — an a-priori absolute
//!    upper bound on the probability that `M` i.i.d. production entry-gap draws
//!    cluster into a detectable partition under the launch-window geometry,
//!    derived with **no reliance on a contemporaneous user cohort**. Two
//!    dispositions consume it (§17.6 finding 1): P2-as-amended's "no
//!    enforcement mechanism" branch and §16.2 obligation 3's strip-row floor.
//!    One lemma, two citation sites — never discharged twice informally.
//! 2. **Compile-time witness-typing for controls** ([`ControlWitness`],
//!    [`MarkedControl`]) — the five marked controls M-a…M-e are precisely the
//!    worst founder configurations that exist, so per the PF-2 precedent a
//!    control fixture that could leak onto a production founder path would *be*
//!    the vulnerability it tests. The control fixture is **un-constructible
//!    from the production founder-config constructor at compile time** (§17.7
//!    finding 4): a distinct witness type, not a flag on the production config.
//!
//! The family members (1–7), the feature dictionary, the `T` statistic, the
//! permutation null, and the pass bounds land in the following slice; this
//! module's first slice exposes the two co-first deliverables and makes both
//! **live** through the `--partition-adversary` report.

use serde::Serialize;

use shekyl_standoff::{draw_entry_gap, plan_entry_seam, DEFAULT_ENTRY_GAP_WINDOW};

use crate::standoff::SplitMix64;

/// `M` — the founder-persona count the launch posture provides as cover
/// (§14.2 P1). The arm synthesizes `M` founder pairs and `N − M` user pairs per
/// trial.
pub const FOUNDER_COUNT: usize = 5;

/// The clustering resolution `c` (blocks) below which `M` dispatch anchors read
/// as **one cluster** to the correlator — i.e. a detectable partition. Pinned
/// to the GF-7 correlator kernel floor (`gf7_timeline`'s `SIGMA_FLOOR = 30`):
/// two events closer than the kernel width are coincident to the observer, so a
/// span `≤ c` is exactly the trap the cohesion (member 3 / control M-c) and
/// lockstep (control M-a) members bite. Using the observer's own resolution
/// keeps the lemma's "detectable" definition the correlator's, not a looser one
/// chosen to make the bound small.
pub const CLUSTER_SPAN_BLOCKS: u64 = 30;

/// The production entry-gap window `W` (blocks) — `shekyl_standoff`'s shipped
/// [`DEFAULT_ENTRY_GAP_WINDOW`]. **K-invariant by construction** (§17 P2
/// premise): the founder draw law is the production entry-gap draw, never a
/// function of the launch-window length (`= f(K_COVER)`). The lemma is stated
/// over this window and only this window.
pub const ENTRY_GAP_WINDOW: u64 = DEFAULT_ENTRY_GAP_WINDOW;

/// A documented "derivably small" ceiling the committed gating bound must sit
/// under (three orders below the tightest control headroom in bound 2's
/// `0.30`, and four below any per-trial label-agreement the family reports at
/// chance). Not a tunable bar — a sanity assertion that the geometry actually
/// delivers the rarity the disposition claims (`gating_lemma_is_derivably_small`).
pub const GATING_LEMMA_CEILING: f64 = 1.0e-4;

/// The §14.4 **gating lemma**: an a-priori absolute upper bound on the
/// probability that `m` i.i.d. uniform entry-gap draws over a `w`-block window
/// all fall within a span of `c` blocks — the clustering trap the family bites,
/// derived with no reliance on a contemporaneous user cohort.
///
/// # Derivation
///
/// Model the `m` founder dispatch anchors as i.i.d. uniform over the integer
/// block offsets `{0, 1, …, w}` — `w + 1` values, exactly the production
/// entry-gap law (`bounded_uniform(rng, w)` is inclusive). §17 P2's
/// K-invariance is what makes this the *deployed* distribution rather than a
/// launch-window-scaled one, so the bound is a property of the shipped draw,
/// not of a tuned launch geometry. The trap the cohesion/lockstep members
/// detect is "all `m` anchors within a span `c`", i.e. `max − min ≤ c`.
///
/// Union-bound over which draw realizes the minimum: if draw `i` is minimal at
/// value `a`, the event requires every other draw to land in
/// `[a, a + c]` — at most `c + 1` of the `w + 1` values. Hence
///
/// ```text
/// P(range ≤ c) ≤ m · ((c + 1) / (w + 1))^(m − 1) ,
/// ```
///
/// which is conservative (an over-estimate: the per-minimum events overlap and
/// boundary intervals truncate) and is the quantity both consumers cite. At
/// the launch geometry (`m = 5`, `c = 30`, `w = 600`) this is
/// `5 · (31/601)^4 ≈ 3.538e-5` — derivably small.
///
/// # Why this is the right event
///
/// The lemma bounds the *clustering* trap (small mutual spacing), which is the
/// shape members 1 (k-means), 3 (cohesion enumeration) and control M-a
/// (lockstep) all detect. The dual trap — enforced *repulsion* (member 7 /
/// control M-e) — is not an i.i.d. draw at all but a mechanism, so under i.i.d.
/// draws member 7 is at chance by exchangeability; the lemma's clustering arm
/// plus P2's "staggering must be statistical, never mechanized" jointly close
/// both directions (the §17.6 "dismissed soft middle path": tail-only rejection
/// sampling has clip-rate ≈ trap-rate, so either the trap is derivably rare —
/// this lemma — or the clip is frequent enough for member 7 to bite the induced
/// repulsion).
///
/// # Panics
///
/// If `m < 2` (clustering needs at least two anchors).
pub fn gating_lemma_bound(m: usize, c: u64, w: u64) -> f64 {
    assert!(m >= 2, "clustering requires at least 2 anchors (got {m})");
    let ratio = ((c + 1) as f64) / ((w + 1) as f64);
    (m as f64) * ratio.powi(m as i32 - 1)
}

/// The exact discrete range probability `P(max − min ≤ c)` for `m` i.i.d.
/// uniform draws over `{0, …, w}`, by direct enumeration over the minimum's
/// position: a tuple with minimum exactly `a` and range `≤ c` has all values in
/// `[a, min(a + c, w)]` (`L` values) with at least one equal to `a`, giving
/// `L^m − (L−1)^m` tuples. Reported alongside the committed upper bound so a
/// reader sees the slack the bound throws away; never the committed quantity —
/// the disposition cites the upper bound so the number is conservative under
/// any refinement.
pub fn gating_lemma_exact(m: usize, c: u64, w: u64) -> f64 {
    assert!(m >= 2, "clustering requires at least 2 anchors (got {m})");
    let total = ((w + 1) as f64).powi(m as i32);
    let mut favorable = 0.0f64;
    for a in 0..=w {
        let l = (c.min(w - a) + 1) as f64;
        favorable += l.powi(m as i32) - (l - 1.0).powi(m as i32);
    }
    favorable / total
}

/// The committed gating-lemma bound at the launch geometry ([`FOUNDER_COUNT`],
/// [`CLUSTER_SPAN_BLOCKS`], [`ENTRY_GAP_WINDOW`]). This is the single a-priori
/// constant both the P2 no-mechanism disposition and the §16.2 strip-row floor
/// cite.
pub fn committed_gating_bound() -> f64 {
    gating_lemma_bound(FOUNDER_COUNT, CLUSTER_SPAN_BLOCKS, ENTRY_GAP_WINDOW)
}

/// The five marked positive controls (§14.4), one per founder-cover failure
/// mode. Each is a **worst founder configuration** — precisely the shapes that
/// destroy founder cover — so per the R4 finding-6 witness-typing requirement
/// it must be un-constructible as a production founder config.
///
/// This enum is reachable **only** through [`ControlWitness`]: no production
/// constructor accepts it, and there is no `From`/`Into` bridge from it to
/// [`FounderConfig`]. That structural absence is the compile-time witness
/// typing (see [`ControlWitness`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
pub enum MarkedControl {
    /// **M-a (lockstep):** all five founder dispatch anchors clustered — the P2
    /// violation. Bitten by family member 1 (k-swept clustering).
    Lockstep,
    /// **M-b (outlier):** four founders at posture, one with a distinct
    /// cadence. Bitten by family member 2 (per-feature outlier set).
    Outlier,
    /// **M-c (cohesion):** five founders individually within the user range but
    /// drawn from a narrow common band. Bitten by member 3 (cohesive-subset
    /// enumeration), and — under seeding — member 5.
    Cohesion,
    /// **M-d (correlation-breaking):** every marginal in-range, feature
    /// *combinations* off the joint support. Bitten by member 6 (joint-density
    /// isolation); members 1–5 are blind to it.
    CorrelationBreak,
    /// **M-e (repulsed/scheduled):** five founder anchors placed by an
    /// enforced-staggering mechanism (hard-core minimum-gap process). Bitten by
    /// member 7 (most-regular-subset enumeration) — the P2 violation from the
    /// opposite direction to M-a.
    Repulsion,
}

impl MarkedControl {
    /// Every marked control, in M-a…M-e order. The family-completeness driver:
    /// bound 2 grades each of these separately.
    pub const ALL: [MarkedControl; 5] = [
        MarkedControl::Lockstep,
        MarkedControl::Outlier,
        MarkedControl::Cohesion,
        MarkedControl::CorrelationBreak,
        MarkedControl::Repulsion,
    ];

    /// The `M-x` label.
    pub fn tag(self) -> &'static str {
        match self {
            MarkedControl::Lockstep => "M-a",
            MarkedControl::Outlier => "M-b",
            MarkedControl::Cohesion => "M-c",
            MarkedControl::CorrelationBreak => "M-d",
            MarkedControl::Repulsion => "M-e",
        }
    }

    /// A short human label (`M-x (name)`).
    pub fn label(self) -> &'static str {
        match self {
            MarkedControl::Lockstep => "M-a (lockstep)",
            MarkedControl::Outlier => "M-b (outlier)",
            MarkedControl::Cohesion => "M-c (cohesion)",
            MarkedControl::CorrelationBreak => "M-d (correlation-breaking)",
            MarkedControl::Repulsion => "M-e (repulsed/scheduled)",
        }
    }

    /// The family member the control is aimed at (1-indexed, per §14.4). Bound 2
    /// checks the aimed member bites; "a family proven to bite on M-a alone
    /// proves nothing about its other members."
    pub fn aimed_member(self) -> usize {
        match self {
            MarkedControl::Lockstep => 1,
            MarkedControl::Outlier => 2,
            MarkedControl::Cohesion => 3,
            MarkedControl::CorrelationBreak => 6,
            MarkedControl::Repulsion => 7,
        }
    }

    /// Whether the control's failure mode is **whole-set** (all five founders
    /// carry the signature: M-a lockstep, M-c cohesion, M-e repulsion) as
    /// opposed to **single-member-targeted** (the signature lives on one
    /// member's axis only: M-b's one-of-M outlier, M-d's mutually-dissimilar
    /// joint-isolation cohort — the Q2-A/Q2-B adversary shapes). Whole-set
    /// failure modes genuinely move the family-max `T`, so bound 2's `+0.30`
    /// applies to them; single-member ones are graded on the any-member arm
    /// (see [`FAMILY_ALPHA`] — the classification is a property of the
    /// adversary the control encodes, fixed a-priori, never of measured
    /// scores).
    pub fn whole_set(self) -> bool {
        matches!(
            self,
            MarkedControl::Lockstep | MarkedControl::Cohesion | MarkedControl::Repulsion
        )
    }
}

/// The **production** founder configuration — the deployed launch posture
/// (§14.2 P1–P4). This is the type the production founder-config constructor
/// yields.
///
/// # The witness-typing guarantee (§17.7 finding 4)
///
/// The only constructor is [`FounderConfig::deployed`]. There is deliberately:
///
/// - no constructor that accepts a [`MarkedControl`] or a [`ControlWitness`],
/// - no `From<ControlWitness>` / `From<MarkedControl>` for `FounderConfig`,
/// - no field of a control-bearing type on this struct.
///
/// A control fixture therefore **cannot be built through this type**: the
/// generator's control path takes `&ControlWitness` and the deployed path takes
/// `&FounderConfig`, and no code path turns the former into the latter. This is
/// the make-bad-states-unrepresentable discipline applied to the test
/// apparatus — a runtime assertion would not satisfy it (a leaked control would
/// still *compile*), so the property is enforced at the type level and is a
/// co-first deliverable of the implementation round.
#[derive(Clone, Copy, Debug)]
pub struct FounderConfig {
    /// Deployed entry-gap window (blocks) — the K-invariant production draw
    /// (§17 P2). Kept private: the only way to obtain a `FounderConfig` is
    /// `deployed()`, which sets this to [`ENTRY_GAP_WINDOW`].
    window: u64,
}

impl FounderConfig {
    /// The one production constructor: the deployed posture. No parameter can
    /// steer it toward a control shape (that is the point — see the type docs).
    pub fn deployed() -> Self {
        Self {
            window: ENTRY_GAP_WINDOW,
        }
    }

    /// The deployed entry-gap window (blocks).
    pub fn window(&self) -> u64 {
        self.window
    }
}

/// A **control fixture witness** — the distinct type that carries a
/// [`MarkedControl`]. This is the *only* way a control configuration exists in
/// the type system; it is not a variant or flag on [`FounderConfig`], so it
/// cannot be produced by the production founder-config constructor.
///
/// The generator's marked-control path consumes `&ControlWitness`; the deployed
/// path consumes `&FounderConfig`. Because there is no conversion from
/// `ControlWitness` (or `MarkedControl`) to `FounderConfig`, a control fixture
/// is un-constructible on the production path at compile time (§17.7 finding
/// 4 / PF-2 precedent).
#[derive(Clone, Copy, Debug)]
pub struct ControlWitness {
    marked: MarkedControl,
    /// The deployed posture the four in-posture founders + the user cohort are
    /// drawn from; the marked founders perturb *off* it. Kept private and only
    /// ever the deployed window — a control witness cannot smuggle a
    /// non-production base posture either.
    window: u64,
}

impl ControlWitness {
    /// Build the witness for one marked control at the deployed base posture.
    /// This is the only `ControlWitness` constructor, and it exists only in the
    /// test-apparatus surface — never reachable from [`FounderConfig`].
    pub fn marked(marked: MarkedControl) -> Self {
        Self {
            marked,
            window: ENTRY_GAP_WINDOW,
        }
    }

    /// Which marked control this witness carries.
    pub fn control(&self) -> MarkedControl {
        self.marked
    }

    /// The deployed base window (blocks) the non-marked founders and users draw
    /// from.
    pub fn window(&self) -> u64 {
        self.window
    }
}

/// The co-first-deliverable report: the committed gating lemma (value +
/// derivation inputs) and the witness-typed control inventory. Emitted by
/// `--partition-adversary` so both deliverables are **live** (constructed and
/// exercised) from the first slice, not merely documented intentions.
#[derive(Serialize)]
pub struct GatingWitnessReport {
    /// `M` (founder count).
    pub founder_count: usize,
    /// `c` (clustering resolution, blocks).
    pub cluster_span_blocks: u64,
    /// `w` (production entry-gap window, blocks).
    pub entry_gap_window: u64,
    /// The committed a-priori bound `m·((c+1)/(w+1))^(m−1)` (the discrete
    /// inclusive-endpoint form — see [`gating_lemma_bound`]'s derivation).
    pub gating_lemma_bound: f64,
    /// The tight range CDF (reported for slack visibility, not committed).
    pub gating_lemma_exact: f64,
    /// The documented "derivably small" ceiling the bound sits under.
    pub gating_lemma_ceiling: f64,
    /// True iff `bound < ceiling` — the disposition's rarity claim holds.
    pub derivably_small: bool,
    /// The deployed founder window read back through the production
    /// constructor (proves [`FounderConfig`] is live).
    pub deployed_window: u64,
    /// The witness-typed control inventory (proves [`ControlWitness`] is live).
    pub controls: Vec<ControlInventoryRow>,
}

/// One witnessed control in the co-first-deliverable inventory.
#[derive(Serialize)]
pub struct ControlInventoryRow {
    pub tag: &'static str,
    pub label: &'static str,
    pub aimed_member: usize,
    /// Built through [`ControlWitness::marked`] — never through
    /// [`FounderConfig`].
    pub witness_typed: bool,
}

/// Build the co-first-deliverable report: compute the committed gating lemma
/// and enumerate the witness-typed controls, exercising both deliverables.
pub fn run_gating_witness_report() -> GatingWitnessReport {
    let bound = committed_gating_bound();
    let exact = gating_lemma_exact(FOUNDER_COUNT, CLUSTER_SPAN_BLOCKS, ENTRY_GAP_WINDOW);

    // Exercise the production constructor (the deployed path).
    let deployed = FounderConfig::deployed();

    // Exercise the witness type for every marked control (the control path).
    let controls = MarkedControl::ALL
        .iter()
        .map(|&m| {
            let witness = ControlWitness::marked(m);
            ControlInventoryRow {
                tag: witness.control().tag(),
                label: witness.control().label(),
                aimed_member: witness.control().aimed_member(),
                // The window is the deployed base by construction; reading it
                // confirms the witness carries a production-base posture the
                // marked founders perturb off, not an arbitrary one.
                witness_typed: witness.window() == ENTRY_GAP_WINDOW,
            }
        })
        .collect();

    GatingWitnessReport {
        founder_count: FOUNDER_COUNT,
        cluster_span_blocks: CLUSTER_SPAN_BLOCKS,
        entry_gap_window: ENTRY_GAP_WINDOW,
        gating_lemma_bound: bound,
        gating_lemma_exact: exact,
        gating_lemma_ceiling: GATING_LEMMA_CEILING,
        derivably_small: bound < GATING_LEMMA_CEILING,
        deployed_window: deployed.window(),
        controls,
    }
}

// ===========================================================================
// §14.4 the family, the feature dictionary, the statistic, the null, the bounds
// ===========================================================================

/// The steady-state cadence horizon (blocks) the arm synthesizes each pair over
/// — the `gf7_timeline` `Regime::SteadyState` horizon, kept identical so the
/// arm grades the same generator shape the main gate does (P1
/// same-generator-same-posture).
const HORIZON: u64 = 4_000;
/// Steady-state session-period range (blocks), matching `gf7_timeline`'s
/// `Regime::SteadyState` cadence `(40, 400)`.
const PERIOD_MIN: u64 = 40;
const PERIOD_MAX: u64 = 400;

/// The anonymity-set size the enumeration family is graded at. Fixed at the
/// standoff cover target (`TARGET_ANON_SET = 10`) because members 3/6/7
/// enumerate `C(N, M)` subsets — exact at `N = 10` (`C(10,5) = 252`); the
/// N-sweep rider grades larger `N` on the main gate and the deployed
/// bound-1 arm with a greedy fallback (§16.7 item 4 / §17.1).
pub const ARM_N: usize = 10;

/// Largest `n` the graded arm accepts (PR #291 review: geometry guard).
/// The design is exact `C(n, M)` enumeration; at `n = 20` that is
/// `C(20,5) = 15 504` subsets scanned per label evaluation — the tractable
/// ceiling for the evidence configuration's `trials × (perms + 1)` label
/// evaluations. Beyond it the arm does not degrade, it refuses: grading a
/// larger anonymity set is a design change (sampled-subset members 3/7),
/// and sweep coverage of larger `N` already lives in the N-sweep rider.
pub const MAX_EXACT_N: usize = 20;

/// Deployed-posture tolerance (bound 1): `|T − null_mean| ≤ 0.05` — no rule in
/// the family sorts founder from user better than chance (§14.4 bound 1).
pub const BOUND1_TOL: f64 = 0.05;

/// Per-control lift (bound 2): each marked control's `T` must sit at least
/// `0.30` above its permutation-null mean (§14.4 bound 2). After the T-site
/// verification below, this family-max form is retained for the **whole-set**
/// controls only; single-member-targeted controls grade on the any-member arm.
pub const BOUND2_LIFT: f64 = 0.30;

/// Family-wise one-sided operating significance for the **any-member arm** —
/// the aggregator fix selected by the T-site verification (§14.4 pin
/// resolution).
///
/// **The verified T-site fact.** `family_max` is a raw max over per-member
/// Jaccard agreements (no cross-member consensus), but the operating verdict
/// read only `T − null(T)`, and `null(T)` re-maximizes the family per
/// relabeling: at `N = 10` it sits ≈ 0.66, set by the *selection freedom of
/// other members* (member 3 enumerates all `C(10,5) = 252` subsets; members
/// 1/4 take best-of-`k` clusters; member 2 best-of-feature). A lone
/// member-6/7 signature — exactly the Q2-A/Q2-B adversary shapes those
/// members exist for — must exceed the max-null waterline in *absolute*
/// Jaccard before it registers in `T` at all, and `null + 0.30` to clear
/// bound 2. Member 6's own chance level is ≈ 1/3; a strong single-member
/// signal is therefore structurally invisible to the family-max arm, and the
/// same insensitivity makes a bound-1 pass on `T` alone potentially
/// false-clean. Detector-architecture finding, not a grading-wording gap.
///
/// **The arm.** Per member `k`, the observed trial-mean agreement is tested
/// against its own null-of-the-mean draws (permutation `p`'s agreement
/// averaged across trials — `perms` i.i.d. draws from the null of the mean)
/// via the exact rank p-value `(1 + #{draws ≥ obs}) / (perms + 1)`; member
/// `k` **flags** iff that p-value ≤ `FAMILY_ALPHA / 7` (Bonferroni over the
/// family). Deployed bound 1 requires `|T − null| ≤ BOUND1_TOL` **and** no
/// member flags (privacy requires that *no* member resolves the founders —
/// the max must not hide the one that does). Each marked control requires its
/// aimed member to flag; whole-set controls (M-a/M-c/M-e) additionally retain
/// the family-max `+0.30` bound, which their failure modes genuinely move.
///
/// The bar derives a-priori from per-member null geometry plus the
/// multiple-comparison correction — never from observed control scores
/// (the after-seeing-scores move the gating lemma exists to forbid). At
/// `perms = 200`: `α/7 ≈ 0.00714`, and the smallest achievable rank p-value
/// is `1/201 ≈ 0.00498`, so a member flags iff its observed mean exceeds
/// every one of its 200 null draws.
pub const FAMILY_ALPHA: f64 = 0.05;

/// Family size the Bonferroni correction divides over (members 1–7).
pub const FAMILY_SIZE: usize = 7;

/// Maximum chain-visible events per pair (funding, bond, drain, two per-`P`
/// submits, resume) ⇒ at most this many inter-event gaps.
const MAX_GAPS: usize = 5;

/// Feature-dictionary dimension (§14.4 named features; see [`Features`]).
const N_FEATURES: usize = 5 + MAX_GAPS;

/// The named feature dictionary (§14.4), per pair, over posture-conditioned
/// **chain-visible** observables only (funding send, bond dispatch, drain,
/// resume, per-`P` submits — never the local-daemon session/refresh markers,
/// excluded as direct anchors per §4.1). Named so the implementation cannot
/// cherry-pick weak features: every family member sees this exact vector.
///
/// Indices: `0` seam gap `|bond − funding|`; `1` dispatch phase (bond position
/// in the horizon); `2..2 + MAX_GAPS` the **full sorted inter-event gap
/// vector** (ascending, zero-padded — §14.4 names the vector, not a summary;
/// the vector carries the session-grid structure a (min, median, max)
/// reduction would blur); then estimated cadence period (drain/resume
/// spacing); observable event count; resume-to-bond spacing (`0` where
/// absent).
#[derive(Clone, Copy)]
struct Features([f64; N_FEATURES]);

/// One synthesized pair's raw chain-visible dispatch times — the observer's view
/// (never generator internals). [`Features`] is derived from this; member 7's
/// repulsion detector reads `bond` directly (spacing regularity is an
/// absolute-time property the standardized feature space discards).
#[derive(Clone)]
struct PairRaw {
    funding: u64,
    /// The dispatch anchor (bond-post time) — member 7's raw input.
    bond: u64,
    drain: Option<u64>,
    per_p: [u64; 2],
    resume: Option<u64>,
}

impl PairRaw {
    /// The chain-visible event times, ascending — the observable set the gap
    /// vector and event count are computed over.
    fn observable(&self) -> Vec<u64> {
        let mut ev = vec![self.funding, self.bond, self.per_p[0], self.per_p[1]];
        if let Some(d) = self.drain {
            ev.push(d);
        }
        if let Some(r) = self.resume {
            ev.push(r);
        }
        ev.sort_unstable();
        ev
    }

    /// Extract the §14.4 feature dictionary.
    fn features(&self) -> Features {
        let ev = self.observable();
        let mut gaps: Vec<u64> = ev.windows(2).map(|w| w[1] - w[0]).collect();
        gaps.sort_unstable();
        let cadence = self.drain.map(|d| d.saturating_sub(self.bond)).unwrap_or(0) as f64;
        let resume_spacing = self
            .resume
            .map(|r| r.saturating_sub(self.bond))
            .unwrap_or(0) as f64;
        let mut f = [0.0f64; N_FEATURES];
        f[0] = self.bond.abs_diff(self.funding) as f64;
        f[1] = self.bond as f64;
        for (i, g) in gaps.iter().take(MAX_GAPS).enumerate() {
            f[2 + i] = *g as f64;
        }
        f[2 + MAX_GAPS] = cadence;
        f[3 + MAX_GAPS] = ev.len() as f64;
        f[4 + MAX_GAPS] = resume_spacing;
        Features(f)
    }
}

/// A synthesized trial: `ARM`/config `n` pairs, the first [`FOUNDER_COUNT`] of
/// which carry the true founder label. `feat` is the **standardized** feature
/// matrix (per-column z-score) so the Euclidean distances the family uses weight
/// every named feature equally; `anchors` are the raw bond times for member 7.
struct Trial {
    n: usize,
    /// Standardized feature vectors, one per pair (`feat[i][f]`).
    feat: Vec<[f64; N_FEATURES]>,
    /// Raw dispatch anchors (bond times), index-aligned with `feat`.
    anchors: Vec<u64>,
    /// The true founder mask, index-aligned with `feat`. Pair positions are
    /// **shuffled** at trial build so no family member can read cohort from
    /// index order (stable sorts on tied features would otherwise return the
    /// generation order and hand member 2 the founder set for free).
    truth_mask: Vec<bool>,
}

impl Trial {
    /// The true founder mask (position-shuffled; see `truth_mask`).
    fn truth(&self) -> Vec<bool> {
        self.truth_mask.clone()
    }

    /// Squared Euclidean distance between two pairs in standardized feature
    /// space.
    fn dist2(&self, i: usize, j: usize) -> f64 {
        self.feat[i]
            .iter()
            .zip(self.feat[j].iter())
            .map(|(a, b)| (a - b) * (a - b))
            .sum()
    }
}

/// Draw one deployed pair at the given entry-gap `window` (the K-invariant
/// production law, §17 P2). Mirrors `gf7_timeline::simulate_pair`'s steady-state
/// cadence: near-periodic sessions, a first-half dispatch anchor, the real
/// `draw_entry_gap` → `plan_entry_seam` seam, a drain on a later session, two
/// persona-timed submits.
fn gen_deployed(rng: &mut SplitMix64, window: u64) -> PairRaw {
    let period = PERIOD_MIN + rng.next_u64() % (PERIOD_MAX - PERIOD_MIN + 1);
    let phase = rng.next_u64() % period;
    gen_at(rng, window, period, phase, None)
}

/// Core pair synthesis at an explicit `(period, phase)` and optional forced
/// cadence override (M-d's off-manifold drain). Shared by the deployed path and
/// every control so founders and users come off the *same* generator, perturbed
/// only where the control names.
fn gen_at(
    rng: &mut SplitMix64,
    window: u64,
    period: u64,
    phase: u64,
    forced_cadence: Option<u64>,
) -> PairRaw {
    // Sessions over the horizon; the anchor is a first-half session.
    let first_half = (HORIZON / 2).saturating_sub(phase) / period + 1;
    let t0 = phase + period * (rng.next_u64() % first_half);
    gen_at_anchor(rng, window, period, t0, forced_cadence)
}

/// [`gen_at`] with an explicit dispatch anchor `t0` (M-a's shared co-trigger;
/// M-c's common anchor band). The pair's whole observable stream rides the
/// session grid at `period` from `t0` — drain at the first grid point past the
/// entry window, the two per-`P` submits at the next two grid points. Session-
/// locked dispatch is the posture (every action fires on a wallet session, per
/// the timing law); it also gives the deployed cohort a well-defined joint
/// manifold — features are functions of `(t0, period, seam)` — which is what
/// makes member 6's joint-density isolation a meaningful detector and M-d's
/// off-manifold combinations a meaningful control.
fn gen_at_anchor(
    rng: &mut SplitMix64,
    window: u64,
    period: u64,
    t0: u64,
    forced_cadence: Option<u64>,
) -> PairRaw {
    let (spread, bond_first) = draw_entry_gap(window, rng);
    let plan = plan_entry_seam((spread, bond_first));
    let funding = t0 + plan.entry_offset_blocks;
    let bond = t0 + plan.bond_post_offset_blocks;

    // First session-grid point past the entry window (deployed law).
    let k = window / period + 1;
    let drain = match forced_cadence {
        None => Some(t0 + period * k),
        Some(c) => Some(bond + c),
    };
    // Submits on the two grid points after the drain slot.
    let per_p = [t0 + period * (k + 1), t0 + period * (k + 2)];
    PairRaw {
        funding,
        bond,
        drain,
        per_p,
        resume: None,
    }
}

/// Build a deployed trial: every pair drawn from the production law at the
/// production window. Nothing in the generation distinguishes founders — P1
/// indistinguishability-by-construction.
fn build_deployed_trial(rng: &mut SplitMix64, n: usize, window: u64) -> Trial {
    let raw: Vec<PairRaw> = (0..n).map(|_| gen_deployed(rng, window)).collect();
    finalize_trial(n, raw, rng)
}

/// Build a control trial: the `M` founders are perturbed per the witnessed
/// marked control; the `N − M` users are deployed. The control enters **only**
/// through `&ControlWitness` (never [`FounderConfig`]) — the compile-time
/// witness-typing guarantee (§17.7 finding 4).
fn build_control_trial(rng: &mut SplitMix64, n: usize, witness: &ControlWitness) -> Trial {
    let window = witness.window();
    let founders = gen_founders(rng, witness.control(), window);
    let mut raw = founders;
    raw.extend((FOUNDER_COUNT..n).map(|_| gen_deployed(rng, window)));
    finalize_trial(n, raw, rng)
}

/// Synthesize the `M` marked founders for one control. Each shape is the worst
/// founder configuration for its aimed family member (§14.4 marked controls).
fn gen_founders(rng: &mut SplitMix64, control: MarkedControl, window: u64) -> Vec<PairRaw> {
    match control {
        // M-a (lockstep): all founders fire off **one shared trigger** — the
        // same first-half anchor, the same period, and one entry draw applied
        // to all five (one decision dispatched five wallets). Anchors
        // clustered, seams identical, cadences identical: the P2 co-trigger
        // violation, a maximal cluster in feature space. Member 1.
        MarkedControl::Lockstep => {
            let period = PERIOD_MIN + rng.next_u64() % (PERIOD_MAX - PERIOD_MIN + 1);
            let base_t0 = rng.next_u64() % (HORIZON / 2);
            // One entry draw dispatched to all five wallets — the co-trigger
            // bypasses the per-wallet production draw, which is exactly the P2
            // violation ("anchors clustered": the anchors only cluster if the
            // per-wallet draws never happened).
            let shared = draw_entry_gap(window, rng);
            let plan = plan_entry_seam(shared);
            let k = window / period + 1;
            (0..FOUNDER_COUNT)
                .map(|_| {
                    // Per-wallet dispatch latency only (the trigger is shared).
                    let t0 = base_t0 + rng.next_u64() % 30;
                    PairRaw {
                        funding: t0 + plan.entry_offset_blocks,
                        bond: t0 + plan.bond_post_offset_blocks,
                        drain: Some(t0 + period * k),
                        per_p: [t0 + period * (k + 1), t0 + period * (k + 2)],
                        resume: None,
                    }
                })
                .collect()
        }
        // M-b (outlier): four at posture, one with a **distinct cadence** — a
        // drain spacing far above the deployed support (deployed cadence lives
        // in (window − seam, window + period]). The single-marginal outlier:
        // member 2 (per-feature top-M on the cadence feature).
        MarkedControl::Outlier => {
            let mut v: Vec<PairRaw> = (0..FOUNDER_COUNT - 1)
                .map(|_| gen_deployed(rng, window))
                .collect();
            let period = PERIOD_MIN + rng.next_u64() % (PERIOD_MAX - PERIOD_MIN + 1);
            let phase = rng.next_u64() % period;
            // Cadence ≈ 2.5× the deployed maximum (window + PERIOD_MAX).
            let forced = (window + PERIOD_MAX) * 5 / 2 + rng.next_u64() % 100;
            v.push(gen_at(rng, window, period, phase, Some(forced)));
            v
        }
        // M-c (cohesion): each founder individually within the user range but
        // all drawn from a **narrow common band** across the dictionary —
        // period band, anchor band, and (via rejection against the production
        // law) seam band. Every coordinate is a value users take; the five
        // are mutually near in all of them — the shared-playbook shape.
        // Distinct absolute times, no co-trigger (never M-a). Member 3 (and
        // member 5 under seeding: the seed's neighbours are the band).
        MarkedControl::Cohesion => {
            let band_lo = PERIOD_MIN + (PERIOD_MAX - PERIOD_MIN) / 2;
            let period_band = 4u64;
            // One first-half base anchor; each founder lands within 60 blocks.
            let base_t0 = rng.next_u64() % (HORIZON / 2 - 300);
            // One in-range seam band centre; each founder's production draw is
            // rejection-conditioned into `centre ± 20` (a mid-window centre so
            // the band is never marginally extreme), with one shared
            // order-coin outcome (a common playbook posts in a common order).
            let seam_centre = 150 + rng.next_u64() % (window / 2);
            let shared_coin = rng.next_u64() & 1 == 0;
            (0..FOUNDER_COUNT)
                .map(|_| {
                    let period = band_lo + rng.next_u64() % period_band;
                    let t0 = base_t0 + rng.next_u64() % 60;
                    let (spread, bond_first) = loop {
                        let d = draw_entry_gap(window, rng);
                        if d.0.abs_diff(seam_centre) <= 20 && d.1 == shared_coin {
                            break d;
                        }
                    };
                    let plan = plan_entry_seam((spread, bond_first));
                    let k = window / period + 1;
                    PairRaw {
                        funding: t0 + plan.entry_offset_blocks,
                        bond: t0 + plan.bond_post_offset_blocks,
                        drain: Some(t0 + period * k),
                        per_p: [t0 + period * (k + 1), t0 + period * (k + 2)],
                        resume: None,
                    }
                })
                .collect()
        }
        // M-d (correlation-breaking): every marginal in-range, the **joint**
        // off the support — the shared-ops-tool shape (§14.4 member 6:
        // "plausible values in implausible pairings"). Deployed pairs live on
        // a 3-parameter manifold — every feature is a function of `(t0,
        // period, seam)`; in particular the drain and the two submits ride
        // one session grid (equal trailing gaps) and the cadence is locked to
        // `(period, seam)`. Each M-d founder starts from production draws
        // with the deployed couplings intact, then breaks exactly **one**
        // coupling with an in-band override (the `match` below) — off the
        // manifold in one direction, on it everywhere else. Marginals exactly
        // production — no band, no extreme, nothing for a per-feature ranking
        // to hold — and the five break *different* couplings, so they carry
        // no cluster (defeats 1/3/4/5), no marginal outlier (defeats 2), and
        // no anchor regularity (defeats 7). Member 6 (joint-density
        // isolation) alone prices the joint. (The alternative — fully
        // factorizing every coordinate from its own fresh ghost — was graded
        // and rejected, PR #291 review: it breaks the equal-gaps coupling
        // (ii) for *all five* founders — a shared off-manifold trait where
        // the design wants five founders sharing none — and it measurably
        // dilutes the aimed bite (member-6 lift `+0.116` factorized vs
        // `+0.136` targeted at the evidence config) by spending the
        // off-support budget on couplings member 6 was not aimed at. See
        // the defaults note in the constructor below.)
        MarkedControl::CorrelationBreak => {
            // Every marginal in-range, the **joint** off the support (§14.4
            // member 6: "plausible values in implausible pairings"). The five
            // founders are **mutually dissimilar** — each breaks a *different*
            // deployed coupling — so they form no cluster (defeats 1/3/4), a
            // seed finds no similar others (defeats 5), and anchors stay
            // untouched production draws (defeats 7); every coordinate is a
            // value the deployed marginal reaches, so no descending top-`M`
            // ranking flags them (defeats 2). Only member 6's whitened
            // joint-density isolation, which amplifies the deployed
            // couplings' zero-variance directions, prices the pairings. The
            // deployed couplings (all derivable from `gen_at_anchor`'s
            // session-grid law, `drain = t0 + period·(⌊window/period⌋+1)`,
            // `per_p` on the next two grid points): (i) `seam + cadence >
            // window` (drain past the entry window); (ii) the two trailing
            // inter-submit gaps are exactly equal (both the pair's own
            // period); (iii) a large cadence forces a large trailing period.
            fn in_band(rng: &mut SplitMix64, lo: u64, hi: u64) -> u64 {
                lo + rng.next_u64() % (hi - lo + 1)
            }
            (0..FOUNDER_COUNT)
                .map(|i| {
                    // Defaults: production draws with the deployed couplings
                    // INTACT — seam and cadence off one ghost, both trailing
                    // gaps off one `per_p` (exactly equal, coupling (ii)
                    // verbatim). Deliberate, not draw-thrift: every coordinate
                    // this founder does *not* target below must stay ON the
                    // deployed manifold, so each founder is off-support in
                    // precisely one coupling and the five share no broken
                    // coupling. Fully factorizing the defaults (a fresh ghost
                    // per coordinate) was graded and rejected (PR #291
                    // review): it breaks (ii) for *every* founder — one
                    // shared off-manifold trait — and dilutes the aimed
                    // member-6 bite (lift `+0.116` factorized vs `+0.136`
                    // targeted at the evidence config) by spending the
                    // off-support budget on untargeted couplings.
                    let bond = gen_deployed(rng, window).bond;
                    let g = gen_deployed(rng, window);
                    let mut seam = g.bond.abs_diff(g.funding);
                    let mut cadence = g.drain.unwrap() - g.bond;
                    let p = gen_deployed(rng, window).per_p;
                    let (mut gap_a, mut gap_b) = (p[1] - p[0], p[1] - p[0]);
                    match i {
                        // Trailing gaps at opposite in-range extremes — breaks
                        // (ii): both a short and a long inter-submit gap in one
                        // pair, each individually a common period.
                        0 => {
                            gap_a = in_band(rng, PERIOD_MIN, PERIOD_MIN + 40);
                            gap_b = in_band(rng, PERIOD_MAX - 40, PERIOD_MAX);
                        }
                        // Mid-band seam with a bottom-band cadence — breaks (i)
                        // from the wedge; both individually common values.
                        1 => {
                            seam = in_band(rng, 250, 450);
                            cadence = in_band(rng, 40, 150);
                        }
                        // High cadence over a short-period session — breaks
                        // (iii): the cadence claims a long period, the trailing
                        // gaps say short.
                        2 => {
                            cadence = in_band(rng, window + 300, window + PERIOD_MAX);
                            let gp = in_band(rng, PERIOD_MIN, 100);
                            gap_a = gp;
                            gap_b = gp;
                        }
                        // Tiny seam with a mid-bulk cadence below the window —
                        // breaks (i) from the bulk side.
                        3 => {
                            seam = in_band(rng, 0, 20);
                            cadence = in_band(rng, 420, 580);
                        }
                        // Mid-bulk cadence with unequal mid/short trailing gaps
                        // — breaks (ii) and (iii) together.
                        _ => {
                            cadence = in_band(rng, 650, 750);
                            gap_a = in_band(rng, PERIOD_MIN, 80);
                            gap_b = in_band(rng, 200, 280);
                        }
                    }
                    let drain = bond + cadence;
                    PairRaw {
                        funding: bond.saturating_sub(seam),
                        bond,
                        drain: Some(drain),
                        per_p: [drain + gap_a, drain + gap_a + gap_b],
                        resume: None,
                    }
                })
                .collect()
        }
        // M-e (repulsed/scheduled): anchors placed by a hard-core minimum-gap
        // process — evenly spaced across the horizon with tiny jitter, so the
        // inter-anchor gaps are near-equal (low variance). Spread, not clustered;
        // mutually dissimilar. Member 7 (regularity), never 1/3.
        MarkedControl::Repulsion => {
            // Even slots guarantee a minimum gap. Slots start past the entry
            // window so the backed-out anchor `t0 = bond − offset` never
            // saturates (an offset can reach the full window; a schedule
            // point below it would silently move the realized bond off
            // schedule and break the very regularity the control marks).
            let slot = (HORIZON / 2 - window) / (FOUNDER_COUNT as u64 + 1);
            (0..FOUNDER_COUNT)
                .map(|i| {
                    let center = window + slot * (i as u64 + 1);
                    // Tiny jitter, far below the slot so the enforced spacing
                    // survives (a hard-core process schedules; it does not
                    // re-randomize what it scheduled).
                    let jitter = rng.next_u64() % (slot / 32).max(1);
                    let bond = center + jitter;
                    // Everything but the anchor placement rides the production
                    // law: real seam draw, session-grid drain and submits — the
                    // mechanism schedules only *when* the dispatch fires.
                    let period = PERIOD_MIN + rng.next_u64() % (PERIOD_MAX - PERIOD_MIN + 1);
                    let (spread, bond_first) = draw_entry_gap(window, rng);
                    let plan = plan_entry_seam((spread, bond_first));
                    // Back out the anchor that lands the bond on schedule
                    // (saturating: an early slot can sit below the offset).
                    let t0 = bond.saturating_sub(plan.bond_post_offset_blocks);
                    let k = window / period + 1;
                    PairRaw {
                        funding: t0 + plan.entry_offset_blocks,
                        bond: t0 + plan.bond_post_offset_blocks,
                        drain: Some(t0 + period * k),
                        per_p: [t0 + period * (k + 1), t0 + period * (k + 2)],
                        resume: None,
                    }
                })
                .collect()
        }
    }
}

/// Standardize the raw feature matrix (per-column z-score), shuffle pair
/// positions (index order must not encode cohort — a stable sort on tied
/// features would otherwise leak generation order), and package the trial.
/// Zero-variance columns collapse to `0` (the mean-subtracted value), which is
/// correct: a feature identical across all pairs carries no linkage.
fn finalize_trial(n: usize, mut raw: Vec<PairRaw>, rng: &mut SplitMix64) -> Trial {
    // Fisher–Yates on (pair, is_founder) — founders are the first M on entry.
    let mut tagged: Vec<(PairRaw, bool)> = raw
        .drain(..)
        .enumerate()
        .map(|(i, p)| (p, i < FOUNDER_COUNT))
        .collect();
    for i in (1..n).rev() {
        let j = (rng.next_u64() as usize) % (i + 1);
        tagged.swap(i, j);
    }
    let truth_mask: Vec<bool> = tagged.iter().map(|(_, f)| *f).collect();
    let raw: Vec<PairRaw> = tagged.into_iter().map(|(p, _)| p).collect();

    let anchors: Vec<u64> = raw.iter().map(|p| p.bond).collect();
    let rows: Vec<Features> = raw.iter().map(|p| p.features()).collect();
    let mut feat = vec![[0.0f64; N_FEATURES]; n];
    for f in 0..N_FEATURES {
        let col: Vec<f64> = rows.iter().map(|r| r.0[f]).collect();
        let mean = col.iter().sum::<f64>() / n as f64;
        let var = col.iter().map(|v| (v - mean) * (v - mean)).sum::<f64>() / n as f64;
        let std = var.sqrt();
        for (row, r) in feat.iter_mut().zip(rows.iter()) {
            row[f] = if std > 1e-9 {
                (r.0[f] - mean) / std
            } else {
                0.0
            };
        }
    }
    Trial {
        n,
        feat,
        anchors,
        truth_mask,
    }
}

// --------------------------------------------------------------------------
// Label-agreement metric
// --------------------------------------------------------------------------

/// Label agreement between a predicted founder mask and the truth mask:
/// **Jaccard overlap**, `|pred ∩ founders| / |pred ∪ founders|`.
///
/// §14.4's own scoring language for the set-valued members (2, 3, 6, and by
/// symmetry 7) is "score its overlap with the founder set"; the Jaccard index
/// is that overlap, size-guarded on both sides (an over-sized prediction pays
/// through the union; predicting everything scores `M/N`, never `1`). Two
/// alternative readings fail a-priori-bound arithmetic on a `[0, 1]`
/// statistic at `N = 2M = 10` and are rejected as spec-defeating: symmetric
/// accuracy puts the max-statistic permutation null past `0.80`
/// (cluster-assignment freedom absorbs it), and the overlap *coefficient*
/// `|∩| / max(|pred|, M)` — chance `0.5` per mask — puts the max-over-family
/// null past `0.72`; under either, bound 2's `+0.30` exceeds the achievable
/// lift even for a control the family recovers *exactly* (`T = 1`), which
/// cannot be the ratified reading. Jaccard's chance level per random
/// `M`-mask is `≈ 1/3` at `N = 10`, leaving the committed headroom reachable
/// while every ranking the members produce is unchanged (Jaccard is monotone
/// in `|∩|` at fixed sizes).
fn agreement(pred: &[bool], truth: &[bool]) -> f64 {
    let inter = pred
        .iter()
        .zip(truth.iter())
        .filter(|(p, t)| **p && **t)
        .count();
    let union = pred
        .iter()
        .zip(truth.iter())
        .filter(|(p, t)| **p || **t)
        .count();
    inter as f64 / union.max(1) as f64
}

/// Best cluster-subset-to-cohort agreement (members 1 and 4, spec wording
/// "score the best cluster-subset-to-cohort assignment"): each cluster is a
/// candidate pair-subset; assign the best-scoring one to the founder cohort
/// and report its overlap. (The wider "any union of clusters" reading is
/// rejected: it hands the *null* free `2^k` selection freedom, inflating the
/// permutation null of the maximized statistic to the point where bound 2's
/// `+0.30` headroom is arithmetically absent from a `[0, 1]` statistic — an
/// a-priori-bound-defeating reading of a scoring clause cannot be the
/// ratified one. At `k = 2` both readings coincide with the original 2-means
/// rule.) This selection freedom is still priced by the permutation null,
/// which re-runs the same best-cluster assignment per relabeling (§14.4
/// "Best-assignment overlap … chance-inflated; permuting the maximized
/// statistic calibrates"). `labels[i]` is pair `i`'s cluster id.
fn cluster_agreement(labels: &[usize], truth: &[bool], k: usize) -> f64 {
    let n = truth.len();
    let mut best = 0.0f64;
    for c in 0..k {
        let pred: Vec<bool> = (0..n).map(|i| labels[i] == c).collect();
        best = best.max(agreement(&pred, truth));
    }
    best
}

// --------------------------------------------------------------------------
// Label-independent trial structures (computed once; re-scored per permutation)
// --------------------------------------------------------------------------

/// The per-trial structures each family member produces **independent of the
/// labels**, so the permutation null re-scores them cheaply (no re-enumeration).
/// Members 1/4 fix clusterings (only the cohort assignment reads labels);
/// members 2/3/6/7 fix a predicted set; member 5's per-seed neighbour lists are
/// label-independent (only the seed's membership in the founder set reads
/// labels).
struct Structures {
    /// Member 1: k-means clusterings for `k ∈ {2,3,4,5}` (labels per pair).
    kmeans: Vec<(usize, Vec<usize>)>,
    /// Member 2: per-feature top-`M` outlier masks.
    outlier_sets: Vec<Vec<bool>>,
    /// Member 3: the single most-cohesive `M`-subset mask.
    cohesion_set: Vec<bool>,
    /// Member 4: spectral clusterings for `k ∈ {2,3,4,5}`.
    spectral: Vec<(usize, Vec<usize>)>,
    /// Member 5: per-pair neighbour order (nearest first), for seeded expansion.
    neighbours: Vec<Vec<usize>>,
    /// Member 6: the top-`M` joint-density-isolation mask.
    isolation_set: Vec<bool>,
    /// Member 7: the most-regular `M`-subset mask.
    regular_set: Vec<bool>,
}

/// All `M`-subsets of `0..n` as index vectors (label-independent; computed once
/// per `n`). Exact enumeration — used at `ARM_N` where `C(10,5) = 252`.
fn m_subsets(n: usize, m: usize) -> Vec<Vec<usize>> {
    let mut out = Vec::new();
    let mut idx: Vec<usize> = (0..m).collect();
    loop {
        out.push(idx.clone());
        // Advance the combination (lexicographic).
        let mut i = m;
        while i > 0 {
            i -= 1;
            if idx[i] != i + n - m {
                idx[i] += 1;
                for j in i + 1..m {
                    idx[j] = idx[j - 1] + 1;
                }
                break;
            }
            if i == 0 {
                return out;
            }
        }
    }
}

fn mask_from(indices: &[usize], n: usize) -> Vec<bool> {
    let mut mask = vec![false; n];
    for &i in indices {
        mask[i] = true;
    }
    mask
}

/// k-means (Lloyd) over the standardized feature space; deterministic seeded
/// init. Small `k`, tiny `n`, fixed iteration budget.
fn kmeans(trial: &Trial, k: usize, rng: &mut SplitMix64) -> Vec<usize> {
    let n = trial.n;
    // Seed: k distinct points chosen by the seeded stream.
    let mut centroids: Vec<[f64; N_FEATURES]> = Vec::with_capacity(k);
    let mut chosen = vec![false; n];
    while centroids.len() < k {
        let c = (rng.next_u64() as usize) % n;
        if !chosen[c] {
            chosen[c] = true;
            centroids.push(trial.feat[c]);
        }
    }
    let mut labels = vec![0usize; n];
    for _ in 0..25 {
        // Assign.
        for (label, row) in labels.iter_mut().zip(trial.feat.iter()) {
            let mut best = (f64::INFINITY, 0usize);
            for (c, cen) in centroids.iter().enumerate() {
                let d: f64 = row
                    .iter()
                    .zip(cen.iter())
                    .map(|(a, b)| (a - b) * (a - b))
                    .sum();
                if d < best.0 {
                    best = (d, c);
                }
            }
            *label = best.1;
        }
        // Update.
        let mut sums = vec![[0.0f64; N_FEATURES]; k];
        let mut counts = vec![0usize; k];
        for (label, row) in labels.iter().zip(trial.feat.iter()) {
            counts[*label] += 1;
            for (s, v) in sums[*label].iter_mut().zip(row.iter()) {
                *s += v;
            }
        }
        for ((cen, sum), &count) in centroids.iter_mut().zip(sums.iter()).zip(counts.iter()) {
            if count > 0 {
                for (c, s) in cen.iter_mut().zip(sum.iter()) {
                    *c = s / count as f64;
                }
            }
        }
    }
    labels
}

/// Spectral bipartition via the Fiedler vector (power iteration on the
/// normalized affinity, with deflation of the trivial top component); recursive
/// bisection of the largest part yields `k` clusters. No linalg dependency —
/// `n ≤ 10`, so the dense iteration is trivial.
fn spectral(trial: &Trial, k: usize) -> Vec<usize> {
    let n = trial.n;
    let mut labels = vec![0usize; n];
    let mut next_label = 1usize;
    // Repeatedly bisect the largest cluster until we have k parts.
    while next_label < k {
        // Find the largest current cluster.
        let mut sizes = vec![0usize; next_label];
        for &l in &labels {
            sizes[l] += 1;
        }
        let target = (0..next_label).max_by_key(|&c| sizes[c]).unwrap();
        let members: Vec<usize> = (0..n).filter(|&i| labels[i] == target).collect();
        if members.len() < 2 {
            break;
        }
        let side = fiedler_bipartition(trial, &members);
        for (idx, &i) in members.iter().enumerate() {
            if side[idx] {
                labels[i] = next_label;
            }
        }
        next_label += 1;
    }
    labels
}

/// Fiedler-vector sign bipartition of the sub-point-set `members`. Returns a
/// per-member bool (one side of the cut).
fn fiedler_bipartition(trial: &Trial, members: &[usize]) -> Vec<bool> {
    let m = members.len();
    // Affinity with a median-distance bandwidth.
    let mut dists = Vec::new();
    for a in 0..m {
        for b in a + 1..m {
            dists.push(trial.dist2(members[a], members[b]).sqrt());
        }
    }
    let sigma = if dists.is_empty() {
        1.0
    } else {
        let mut d = dists.clone();
        d.sort_by(|x, y| x.partial_cmp(y).unwrap());
        (d[d.len() / 2]).max(1e-6)
    };
    let mut w = vec![vec![0.0f64; m]; m];
    for a in 0..m {
        for b in 0..m {
            if a != b {
                let d = trial.dist2(members[a], members[b]).sqrt();
                w[a][b] = (-(d * d) / (2.0 * sigma * sigma)).exp();
            }
        }
    }
    let deg: Vec<f64> = w
        .iter()
        .map(|row| row.iter().sum::<f64>().max(1e-9))
        .collect();
    // Normalized affinity A = D^{-1/2} W D^{-1/2}.
    let mut a_mat = vec![vec![0.0f64; m]; m];
    for i in 0..m {
        for j in 0..m {
            a_mat[i][j] = w[i][j] / (deg[i].sqrt() * deg[j].sqrt());
        }
    }
    // Top eigenvector v1 ≈ D^{1/2}·1 (trivial); power-iterate then deflate.
    let v1 = power_iter(&a_mat, None);
    let v2 = power_iter(&a_mat, Some(&v1));
    // Fiedler = D^{-1/2} v2; sign gives the cut.
    (0..m).map(|i| v2[i] / deg[i].sqrt() >= 0.0).collect()
}

/// Power iteration for the dominant eigenvector; if `deflate = Some(v1)`,
/// project the iterate off `v1` after every multiply (`v ← (I − v1 v1ᵀ)·A·v`),
/// recovering the second eigenvector of a symmetric `A`.
///
/// Projection deflation is chosen over the Hotelling form
/// `(A − λ1·v1 v1ᵀ)·v`: it annihilates the `v1` component exactly at every
/// step with no dependence on an *estimated* `λ1`, so a Rayleigh-quotient
/// error in `λ1` (or a matrix whose top eigenvalue is not 1) can never leak
/// `v1` back into the iterate. (PR #291 review: the previous Hotelling-form
/// code deflated with the wrong dot product — masked here only because the
/// normalized affinity's `λ1` is exactly 1.)
fn power_iter(a: &[Vec<f64>], deflate: Option<&[f64]>) -> Vec<f64> {
    let m = a.len();
    let mut v = vec![1.0 / (m as f64).sqrt(); m];
    // Perturb so a symmetric start does not sit on a node of the target mode.
    for (i, vi) in v.iter_mut().enumerate() {
        *vi += if i % 2 == 0 { 1e-3 } else { -1e-3 };
    }
    for _ in 0..200 {
        let mut nv = vec![0.0f64; m];
        for i in 0..m {
            let mut s = 0.0;
            for j in 0..m {
                s += a[i][j] * v[j];
            }
            nv[i] = s;
        }
        if let Some(v1) = deflate {
            let dot: f64 = nv.iter().zip(v1.iter()).map(|(x, y)| x * y).sum();
            for (x, &y) in nv.iter_mut().zip(v1.iter()) {
                *x -= dot * y;
            }
        }
        let norm = nv.iter().map(|x| x * x).sum::<f64>().sqrt();
        if norm < 1e-12 {
            break;
        }
        for x in nv.iter_mut() {
            *x /= norm;
        }
        v = nv;
    }
    v
}

/// Compute all label-independent structures for a trial (see [`Structures`]).
fn structures(trial: &Trial, subsets: &[Vec<usize>], rng: &mut SplitMix64) -> Structures {
    let n = trial.n;
    let m = FOUNDER_COUNT;

    // Member 1: k-means for k ∈ {2,3,4,5}.
    let kmeans_sets: Vec<(usize, Vec<usize>)> = [2, 3, 4, 5]
        .iter()
        .map(|&k| (k, kmeans(trial, k, rng)))
        .collect();

    // Member 2: per-feature top-M — "rank pairs and take the top-M set"
    // (§14.4 member 2, literally: one ranking per feature, its top-`M`). Not
    // |z| and not both directions: widening to per-direction or
    // absolute-value masks doubles member 2's selection freedom, inflating
    // its (and the family-max's) permutation null, and folds mid-band joint
    // shapes into a per-feature detector — member 6's territory, breaking
    // M-d's members-1–5-at-chance requirement.
    let outlier_sets: Vec<Vec<bool>> = (0..N_FEATURES)
        .map(|f| {
            let mut order: Vec<usize> = (0..n).collect();
            order.sort_by(|&a, &b| trial.feat[b][f].partial_cmp(&trial.feat[a][f]).unwrap());
            mask_from(&order[..m], n)
        })
        .collect();

    // Member 3: the M-subset minimizing mean pairwise distance.
    let cohesion_idx = subsets
        .iter()
        .min_by(|a, b| {
            subset_mean_dist(trial, a)
                .partial_cmp(&subset_mean_dist(trial, b))
                .unwrap()
        })
        .unwrap();
    let cohesion_set = mask_from(cohesion_idx, n);

    // Member 4: spectral for k ∈ {2,3,4,5}.
    let spectral_sets: Vec<(usize, Vec<usize>)> = [2, 3, 4, 5]
        .iter()
        .map(|&k| (k, spectral(trial, k)))
        .collect();

    // Member 5: neighbour order per pair (nearest first).
    let neighbours: Vec<Vec<usize>> = (0..n)
        .map(|i| {
            let mut order: Vec<usize> = (0..n).filter(|&j| j != i).collect();
            order.sort_by(|&a, &b| trial.dist2(i, a).partial_cmp(&trial.dist2(i, b)).unwrap());
            order
        })
        .collect();

    // Member 6: top-M by **joint**-density isolation — k-NN distance over the
    // full dictionary in the trial-**whitened** (shrinkage-Mahalanobis)
    // metric. Whitening is what makes the density *joint*: the deployed law
    // couples the dictionary tightly (every feature is a function of one
    // `(t0, period, seam)` triple), so low-variance directions in the trial
    // covariance are exactly the couplings, and a pair whose *combination*
    // is off-support (M-d: every marginal in-range) is far from everything
    // in the whitened metric while staying unremarkable in the plain
    // z-scored metric members 1–5 use — which is the member-6-catches /
    // members-1–5-blind separation §14.4 names. `k` is small (2), not `M`:
    // §14.4 pins M-d's founders as capable of being mutually *dissimilar*,
    // so the off-support cohort cannot supply its own neighbours (the
    // mutually-similar off-support cohort is member 3's catch); `k = 2`
    // (not 1) guards a single accidental founder–user coincidence.
    let white = whitened_dist2(trial);
    let iso_k = 2;
    let mut iso_rank: Vec<usize> = (0..n).collect();
    let iso_score = |i: usize| -> f64 {
        let mut d: Vec<f64> = (0..n).filter(|&j| j != i).map(|j| white[i][j]).collect();
        d.sort_by(|a, b| a.partial_cmp(b).unwrap());
        d[(iso_k - 1).min(d.len() - 1)]
    };
    iso_rank.sort_by(|&a, &b| iso_score(b).partial_cmp(&iso_score(a)).unwrap());
    let isolation_set = mask_from(&iso_rank[..m], n);

    // Member 7: the M-subset with the most regular anchor spacing (lowest
    // coefficient of variation of sorted inter-anchor gaps).
    let regular_idx = subsets
        .iter()
        .min_by(|a, b| {
            spacing_cv(&trial.anchors, a)
                .partial_cmp(&spacing_cv(&trial.anchors, b))
                .unwrap()
        })
        .unwrap();
    let regular_set = mask_from(regular_idx, n);

    Structures {
        kmeans: kmeans_sets,
        outlier_sets,
        cohesion_set,
        spectral: spectral_sets,
        neighbours,
        isolation_set,
        regular_set,
    }
}

/// Pairwise squared distances in the trial-whitened (shrinkage-Mahalanobis)
/// metric — member 6's joint-density metric. Whitening is what makes the
/// density *joint*: the deployed law couples the dictionary tightly, so the
/// couplings are the low-variance directions of the feature covariance, and
/// inverting the covariance amplifies exactly those directions — a pair whose
/// *combination* is off-support is far from the bulk in the whitened metric
/// while unremarkable in the plain z-scored metric members 1–5 use.
///
/// The covariance is estimated **robustly**: at `N = 2M` the founders are half
/// the trial, so a full-trial covariance would be contaminated by the very
/// off-support combinations member 6 is trying to price (the founders inflate
/// the coupling directions' variance and erase their own amplification). One
/// decontamination pass fixes this: rank by the plain metric, drop the top-`M`
/// most-isolated (the presumed founders), estimate the covariance over the
/// remaining presumed-users, then whiten. This is the robust-density estimate
/// an adversary would actually use; it is label-free (the drop is by the
/// statistic, not by truth).
fn whitened_dist2(trial: &Trial) -> Vec<Vec<f64>> {
    let n = trial.n;
    let d = N_FEATURES;
    let m = FOUNDER_COUNT.min(n / 2);
    let lambda = 0.25;

    // Provisional plain-metric isolation to find the presumed-user subset.
    let plain = |i: usize, j: usize| -> f64 {
        (0..d)
            .map(|f| (trial.feat[i][f] - trial.feat[j][f]).powi(2))
            .sum()
    };
    let mut prov: Vec<usize> = (0..n).collect();
    let prov_score = |i: usize| -> f64 {
        let mut dd: Vec<f64> = (0..n).filter(|&j| j != i).map(|j| plain(i, j)).collect();
        dd.sort_by(|a, b| a.partial_cmp(b).unwrap());
        dd[1.min(dd.len() - 1)]
    };
    prov.sort_by(|&a, &b| prov_score(b).partial_cmp(&prov_score(a)).unwrap());
    let users: Vec<usize> = prov[m..].to_vec();

    // Covariance over the presumed-users only.
    let mut mean = [0.0f64; N_FEATURES];
    for &i in &users {
        for (mm, v) in mean.iter_mut().zip(trial.feat[i].iter()) {
            *mm += v;
        }
    }
    for mm in &mut mean {
        *mm /= users.len() as f64;
    }
    let mut cov = vec![vec![0.0f64; d]; d];
    for &i in &users {
        for a in 0..d {
            for b in 0..d {
                cov[a][b] += (trial.feat[i][a] - mean[a]) * (trial.feat[i][b] - mean[b]);
            }
        }
    }
    for (a, cov_row) in cov.iter_mut().enumerate() {
        for (b, c) in cov_row.iter_mut().enumerate() {
            *c = (1.0 - lambda) * (*c / users.len() as f64) + if a == b { lambda } else { 0.0 };
        }
    }
    // Gauss–Jordan inverse (d = 11; pivots are safe under the shrinkage).
    let mut aug: Vec<Vec<f64>> = (0..d)
        .map(|i| {
            let mut r = cov[i].clone();
            r.extend((0..d).map(|j| if i == j { 1.0 } else { 0.0 }));
            r
        })
        .collect();
    for col in 0..d {
        let piv = (col..d)
            .max_by(|&a, &b| aug[a][col].abs().partial_cmp(&aug[b][col].abs()).unwrap())
            .unwrap();
        aug.swap(col, piv);
        let p = aug[col][col];
        for x in &mut aug[col] {
            *x /= p;
        }
        let pivot_row = aug[col].clone();
        for (r, row) in aug.iter_mut().enumerate() {
            if r != col {
                let f = row[col];
                for (x, p) in row.iter_mut().zip(pivot_row.iter()) {
                    *x -= f * p;
                }
            }
        }
    }
    let inv: Vec<Vec<f64>> = aug.into_iter().map(|r| r[d..].to_vec()).collect();

    let maha = |i: usize, j: usize| -> f64 {
        let diff: Vec<f64> = trial.feat[i]
            .iter()
            .zip(trial.feat[j].iter())
            .map(|(a, b)| a - b)
            .collect();
        inv.iter()
            .zip(diff.iter())
            .map(|(row, &da)| {
                da * row
                    .iter()
                    .zip(diff.iter())
                    .map(|(&iab, &db)| iab * db)
                    .sum::<f64>()
            })
            .sum()
    };
    (0..n)
        .map(|i| (0..n).map(|j| maha(i, j)).collect())
        .collect()
}

/// Mean pairwise standardized distance over an `M`-subset (member 3's score).
fn subset_mean_dist(trial: &Trial, idx: &[usize]) -> f64 {
    let mut s = 0.0;
    let mut c = 0.0;
    for a in 0..idx.len() {
        for b in a + 1..idx.len() {
            s += trial.dist2(idx[a], idx[b]).sqrt();
            c += 1.0;
        }
    }
    if c > 0.0 {
        s / c
    } else {
        0.0
    }
}

/// Coefficient of variation of the sorted inter-anchor gaps of a subset
/// (member 7's regularity score; lower = more regular). A degenerate zero-mean
/// subset scores maximally irregular so it never spuriously wins.
fn spacing_cv(anchors: &[u64], idx: &[usize]) -> f64 {
    let mut a: Vec<u64> = idx.iter().map(|&i| anchors[i]).collect();
    a.sort_unstable();
    let gaps: Vec<f64> = a.windows(2).map(|w| (w[1] - w[0]) as f64).collect();
    if gaps.len() < 2 {
        return f64::INFINITY;
    }
    let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
    if mean < 1e-9 {
        return f64::INFINITY;
    }
    let var = gaps.iter().map(|g| (g - mean) * (g - mean)).sum::<f64>() / gaps.len() as f64;
    var.sqrt() / mean
}

/// Per-member agreement for a given label vector (all seven members). Member 5
/// (seeded) is scored only when its seed is a true founder, averaged over the
/// founders in `truth`; if `truth` has no founders it returns chance (`0`
/// lift), which the caller never hits (truth always has `M`).
fn member_agreements(s: &Structures, trial: &Trial, truth: &[bool]) -> [f64; 7] {
    let n = trial.n;
    let m = FOUNDER_COUNT;

    // 1: k-means, best k.
    let m1 = s
        .kmeans
        .iter()
        .map(|(k, labels)| cluster_agreement(labels, truth, *k))
        .fold(0.0f64, f64::max);

    // 2: per-feature outlier set, best feature.
    let m2 = s
        .outlier_sets
        .iter()
        .map(|set| agreement(set, truth))
        .fold(0.0f64, f64::max);

    // 3: most-cohesive subset.
    let m3 = agreement(&s.cohesion_set, truth);

    // 4: spectral, best k.
    let m4 = s
        .spectral
        .iter()
        .map(|(k, labels)| cluster_agreement(labels, truth, *k))
        .fold(0.0f64, f64::max);

    // 5: seeded NN expansion, averaged over true-founder seeds; scored over the
    // non-seed labels only (§14.4 member 5 calibration).
    let founders: Vec<usize> = (0..n).filter(|&i| truth[i]).collect();
    let m5 = if founders.is_empty() {
        0.0
    } else {
        let mut acc = 0.0;
        for &seed in &founders {
            let mut pred = vec![false; n];
            pred[seed] = true;
            for &nb in s.neighbours[seed].iter().take(m - 1) {
                pred[nb] = true;
            }
            // Overlap with the *remaining* founders over the non-seed pairs
            // only (§14.4 member 5: "score the overlap with the remaining
            // founders"; calibration permutes the non-seed labels).
            let (pred_ns, truth_ns): (Vec<bool>, Vec<bool>) = (0..n)
                .filter(|&i| i != seed)
                .map(|i| (pred[i], truth[i]))
                .unzip();
            acc += agreement(&pred_ns, &truth_ns);
        }
        acc / founders.len() as f64
    };

    // 6: joint-density isolation top-M.
    let m6 = agreement(&s.isolation_set, truth);

    // 7: most-regular subset.
    let m7 = agreement(&s.regular_set, truth);

    [m1, m2, m3, m4, m5, m6, m7]
}

/// `T` = max over the family of label agreement, for one label vector.
fn family_max(s: &Structures, trial: &Trial, truth: &[bool]) -> f64 {
    member_agreements(s, trial, truth)
        .iter()
        .copied()
        .fold(0.0f64, f64::max)
}

/// A random `M`-founder label mask (Fisher-Yates over `0..n`, first `M` chosen)
/// — the permutation null's relabeling.
fn random_labels(n: usize, m: usize, rng: &mut SplitMix64) -> Vec<bool> {
    let mut idx: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let j = (rng.next_u64() as usize) % (i + 1);
        idx.swap(i, j);
    }
    mask_from(&idx[..m], n)
}

/// The permutation null for a fixed trial: relabel `perms` times, re-maximize
/// the full family per relabeling (§14.4 null), and return the mean of `T`
/// plus per-member null means (the per-member bite calibration the marked
/// controls are diagnosed against).
///
/// `per_perm_member[p][k]` additionally accumulates permutation `p`'s member-`k`
/// agreement across trials: after dividing by the trial count, row `p` is one
/// i.i.d. draw from the null of the **trial-mean** per-member agreement — the
/// null geometry the any-member arm's rank test reads (see [`FAMILY_ALPHA`]).
fn permutation_null(
    s: &Structures,
    trial: &Trial,
    perms: u32,
    rng: &mut SplitMix64,
    per_perm_member: &mut [[f64; FAMILY_SIZE]],
) -> (f64, [f64; 7]) {
    let mut t_acc = 0.0;
    let mut member_acc = [0.0f64; 7];
    for row in per_perm_member.iter_mut().take(perms as usize) {
        let labels = random_labels(trial.n, FOUNDER_COUNT, rng);
        let agr = member_agreements(s, trial, &labels);
        t_acc += agr.iter().copied().fold(0.0f64, f64::max);
        for ((acc, slot), v) in member_acc.iter_mut().zip(row.iter_mut()).zip(agr.iter()) {
            *acc += v;
            *slot += v;
        }
    }
    for v in member_acc.iter_mut() {
        *v /= perms as f64;
    }
    (t_acc / perms as f64, member_acc)
}

/// One graded scenario (deployed posture, or one marked control): the observed
/// `T`, the permutation-null mean, their difference, per-member observed
/// agreements, and the bound verdict.
#[derive(Serialize)]
pub struct PartitionScenario {
    /// `"deployed"` or the control tag (`"M-a"` …).
    pub scenario: &'static str,
    /// Human label.
    pub label: &'static str,
    /// The family member this scenario validates (`0` = deployed / none).
    pub aimed_member: usize,
    /// Observed `T` (max over family), averaged over trials.
    pub t_obs: f64,
    /// Permutation-null mean of `T`, averaged over trials.
    pub null_mean: f64,
    /// `t_obs − null_mean` — the lift.
    pub lift: f64,
    /// The aimed member's own observed agreement (diagnostic; `0` for deployed).
    pub aimed_member_agreement: f64,
    /// The aimed member's lift over its own permutation-null mean — the
    /// per-member **bite** record (§14.4: "each control validates the member
    /// aimed at its failure mode").
    pub aimed_member_lift: f64,
    /// All seven members' observed agreements (diagnostic — records members 1–5
    /// at chance against M-d, etc., per the §14.4 recorded-per-run requirement).
    pub member_agreements: [f64; 7],
    /// All seven members' permutation-null means (the per-member chance level
    /// each observed agreement is read against).
    pub member_null_means: [f64; 7],
    /// Any-member arm: exact rank p-value per member against its own
    /// null-of-the-mean draws (`(1 + #{null ≥ obs}) / (perms + 1)`).
    pub member_p: [f64; 7],
    /// Any-member arm: member flags iff its p-value ≤ `FAMILY_ALPHA / 7`
    /// (Bonferroni). Deployed must have **no** flag; each control's aimed
    /// member **must** flag.
    pub member_flags: [bool; 7],
    /// The largest null-of-the-mean draw per member — the effective bar the
    /// rank test applies at the operating `perms`.
    pub member_null_max: [f64; 7],
    /// Bound verdict. Deployed: bound 1 (`|lift| ≤ 0.05`) **and** no member
    /// flags on the any-member arm. Whole-set controls: bound 2
    /// (`lift ≥ 0.30`) **and** the aimed member flags. Single-member-targeted
    /// controls: the aimed member flags (the §14.4 bound-2 pin resolution —
    /// graded against the same any-member rule deployment uses).
    pub passed: bool,
    /// The bound the verdict applied.
    pub bound: &'static str,
}

/// The graded partition-adversary measurement.
#[derive(Serialize)]
pub struct PartitionReport {
    pub n: usize,
    pub founder_count: usize,
    pub trials: u32,
    pub permutations: u32,
    pub bound1_tol: f64,
    pub bound2_lift: f64,
    /// The deployed-posture scenario (bound 1).
    pub deployed: PartitionScenario,
    /// The five marked controls (bound 2, each).
    pub controls: Vec<PartitionScenario>,
    /// Overall verdict (§14.4 bound 3: all-or-nothing).
    pub status: String,
    /// Material under-specifications pinned to the doc rather than improvised
    /// (task directive). Empty when none surfaced.
    pub pinned_underspecifications: Vec<String>,
}

/// Config for the graded partition arm (small in tests, full for the binary).
pub struct PartitionConfig {
    pub n: usize,
    pub trials: u32,
    pub perms: u32,
    pub seed: u64,
}

impl Default for PartitionConfig {
    /// Evidence configuration. `trials` is **power-sized a-priori to the
    /// single-member effect ceiling**, not tuned to any observed score:
    /// M-b's one-of-`M` perturbation guarantees at most one extra
    /// intersection element in the aimed member's top-`M` prediction, so its
    /// Jaccard shift is bounded by arithmetic — at `N = 2M = 10`,
    /// `E[J | 1 guaranteed + M−1 random] − E[J | chance] ≈ 0.40 − 0.35 =
    /// +0.05` (hypergeometric expectation over `C(10,5)` masks). The rank
    /// test must resolve a mean shift of that order against the null-of-the-
    /// mean spread `σ/√trials` (measured member-2 relabeling σ ≈ 0.18) at
    /// `α/7`: detecting `δ ≈ +0.03` (the ceiling attenuated by the member's
    /// own selection boost, which lifts null and observed together) with
    /// power ≈ 0.9 needs `trials ≈ ((z_{α/7} + z_{0.9})·σ/δ)² ≈ 500`.
    /// `perms` must satisfy the α/7 resolution guard (`≥ 139`; see
    /// `run_partition_measurement`).
    fn default() -> Self {
        Self {
            n: ARM_N,
            trials: 500,
            perms: 200,
            seed: 0x9A7C_144A_2C2B_0003,
        }
    }
}

/// Grade one scenario across `cfg.trials` independent worlds: mean observed `T`,
/// mean null, and mean per-member agreements. `control = None` is the deployed
/// posture; `Some(witness)` a marked control.
fn grade_scenario(
    cfg: &PartitionConfig,
    subsets: &[Vec<usize>],
    control: Option<&ControlWitness>,
    rng: &mut SplitMix64,
) -> ScenarioAggregates {
    let (mut t_sum, mut null_sum) = (0.0, 0.0);
    let mut agr_sum = [0.0f64; 7];
    let mut member_null_sum = [0.0f64; 7];
    // Null-of-the-mean draws for the any-member arm: row `p` accumulates
    // permutation `p`'s per-member agreement across trials.
    let mut null_draws = vec![[0.0f64; FAMILY_SIZE]; cfg.perms as usize];
    for _ in 0..cfg.trials {
        let trial = match control {
            None => build_deployed_trial(rng, cfg.n, ENTRY_GAP_WINDOW),
            Some(w) => build_control_trial(rng, cfg.n, w),
        };
        let s = structures(&trial, subsets, rng);
        let truth = trial.truth();
        t_sum += family_max(&s, &trial, &truth);
        let agr = member_agreements(&s, &trial, &truth);
        for (acc, v) in agr_sum.iter_mut().zip(agr.iter()) {
            *acc += v;
        }
        let (null_t, null_members) = permutation_null(&s, &trial, cfg.perms, rng, &mut null_draws);
        null_sum += null_t;
        for (acc, v) in member_null_sum.iter_mut().zip(null_members.iter()) {
            *acc += v;
        }
    }
    let t = cfg.trials as f64;
    for v in agr_sum.iter_mut() {
        *v /= t;
    }
    for v in member_null_sum.iter_mut() {
        *v /= t;
    }
    for row in null_draws.iter_mut() {
        for v in row.iter_mut() {
            *v /= t;
        }
    }

    // Any-member arm: exact rank p-value per member against its own
    // null-of-the-mean draws, Bonferroni-corrected over the family
    // (a-priori derivation; see FAMILY_ALPHA).
    let per_member_alpha = FAMILY_ALPHA / FAMILY_SIZE as f64;
    let mut member_p = [0.0f64; 7];
    let mut member_flags = [false; 7];
    let mut member_null_max = [0.0f64; 7];
    for k in 0..FAMILY_SIZE {
        let obs = agr_sum[k];
        let ge = null_draws.iter().filter(|row| row[k] >= obs).count();
        member_p[k] = (1 + ge) as f64 / (cfg.perms as f64 + 1.0);
        member_flags[k] = member_p[k] <= per_member_alpha;
        member_null_max[k] = null_draws
            .iter()
            .map(|row| row[k])
            .fold(f64::NEG_INFINITY, f64::max);
    }

    ScenarioAggregates {
        t_obs: t_sum / t,
        null_mean: null_sum / t,
        member_agreements: agr_sum,
        member_null_means: member_null_sum,
        member_p,
        member_flags,
        member_null_max,
    }
}

/// Aggregates for one graded scenario across trials.
struct ScenarioAggregates {
    t_obs: f64,
    null_mean: f64,
    member_agreements: [f64; 7],
    member_null_means: [f64; 7],
    /// Any-member arm: exact rank p-value per member vs its own
    /// null-of-the-mean draws.
    member_p: [f64; 7],
    /// Any-member arm: `member_p ≤ FAMILY_ALPHA / 7`.
    member_flags: [bool; 7],
    /// The largest null-of-the-mean draw per member (the effective bar at
    /// the operating `perms`).
    member_null_max: [f64; 7],
}

/// Run the graded §14.4 partition-adversary measurement: the deployed posture
/// (bound 1) and the five witness-typed marked controls (bound 2), calibrated
/// against the permutation null of the max-over-family statistic.
pub fn run_partition_measurement(cfg: &PartitionConfig) -> PartitionReport {
    // Resolution guard for the any-member arm: the exact rank p-value's floor
    // is `1/(perms+1)`; if that floor exceeds `α/7`, no member can ever flag
    // and the arm is silently toothless — deployed would pass on
    // mis-configuration (the exact false-clean failure mode the arm exists to
    // close) and every single-member control would fail spuriously. Fail
    // loudly instead: `perms ≥ 7/α − 1` (= 139 at α = 0.05).
    let per_member_alpha = FAMILY_ALPHA / FAMILY_SIZE as f64;
    assert!(
        1.0 / (cfg.perms as f64 + 1.0) <= per_member_alpha,
        "perms={} cannot resolve the any-member arm's α/7 = {per_member_alpha:.5} bar \
         (rank p-value floor 1/(perms+1) = {:.5}); need perms ≥ {}",
        cfg.perms,
        1.0 / (cfg.perms as f64 + 1.0),
        (FAMILY_SIZE as f64 / FAMILY_ALPHA).ceil() as u32 - 1,
    );

    // Geometry guards (PR #291 review). The arm's grading is built on exact
    // `C(n, M)` subset enumeration (members 3/7) and a non-degenerate
    // founders-among-users population, so an out-of-range `n` is a
    // mis-configuration, never a smaller-effort run — fail loudly rather
    // than underflow (`n < M` wraps `m_subsets`' combination advance),
    // degenerate (`n = M` makes every label vector the truth), or explode
    // (`C(n, M)` growth swamps the per-label scans). `MAX_EXACT_N` bounds
    // the exact-enumeration design; anonymity sets beyond it are the
    // N-sweep rider's territory (`riders.rs`), and lifting the cap here
    // means designing a sampled-subset member-3/7 variant, not raising a
    // number. `trials = 0` would make every aggregate `0/0 = NaN` and the
    // verdict vacuous.
    assert!(
        cfg.n > FOUNDER_COUNT && cfg.n <= MAX_EXACT_N,
        "n={} out of the exact-enumeration design range ({} < n ≤ {}); the arm \
         is specified at N = {ARM_N} (§14.4)",
        cfg.n,
        FOUNDER_COUNT,
        MAX_EXACT_N,
    );
    assert!(cfg.trials > 0, "trials must be ≥ 1");

    let mut rng = SplitMix64(cfg.seed);
    let subsets = m_subsets(cfg.n, FOUNDER_COUNT);

    // Deployed posture — bound 1, both arms: the family-max lift must sit at
    // chance AND no member may flag against its own FW-corrected null.
    // Privacy requires that no member resolves the founders; the max must not
    // hide the one that does (the false-clean hazard the T-site verification
    // surfaced).
    let agg = grade_scenario(cfg, &subsets, None, &mut rng);
    let lift = agg.t_obs - agg.null_mean;
    let any_flag = agg.member_flags.iter().any(|&f| f);
    let deployed = PartitionScenario {
        scenario: "deployed",
        label: "deployed posture",
        aimed_member: 0,
        t_obs: agg.t_obs,
        null_mean: agg.null_mean,
        lift,
        aimed_member_agreement: 0.0,
        aimed_member_lift: 0.0,
        member_agreements: agg.member_agreements,
        member_null_means: agg.member_null_means,
        member_p: agg.member_p,
        member_flags: agg.member_flags,
        member_null_max: agg.member_null_max,
        passed: lift.abs() <= BOUND1_TOL && !any_flag,
        bound: "bound 1: |T − null| ≤ 0.05 AND no member flags at α/7",
    };

    // Marked controls — bound 2, each, under the resolved grading rule
    // (§14.4 pin resolution; see FAMILY_ALPHA for the T-site verification
    // that selected it). Every control's aimed member must flag on the
    // any-member arm — the same rule deployment uses, so a control PASS
    // certifies that deployment would catch the adversary the control
    // encodes. Whole-set controls (M-a/M-c/M-e) additionally retain the
    // family-max `T ≥ null + 0.30` bound, which their failure modes
    // genuinely move; single-member-targeted controls (M-b/M-d) cannot move
    // the family max by construction (their Q2-A/Q2-B adversaries live on
    // one member's axis), so the family-max form does not apply to them —
    // their bar is the aimed member's FW-corrected rank test, derived from
    // null geometry, never from observed scores.
    let mut controls = Vec::new();
    let pins: Vec<String> = Vec::new();
    for &mc in &MarkedControl::ALL {
        let witness = ControlWitness::marked(mc);
        let agg = grade_scenario(cfg, &subsets, Some(&witness), &mut rng);
        let lift = agg.t_obs - agg.null_mean;
        let aimed = mc.aimed_member();
        let aimed_lift = agg.member_agreements[aimed - 1] - agg.member_null_means[aimed - 1];
        let aimed_flag = agg.member_flags[aimed - 1];
        let (passed, bound) = if mc.whole_set() {
            (
                lift >= BOUND2_LIFT && aimed_flag,
                "bound 2 (whole-set): T ≥ null + 0.30 AND aimed member flags at α/7",
            )
        } else {
            (
                aimed_flag,
                "bound 2 (single-member): aimed member flags at α/7",
            )
        };
        controls.push(PartitionScenario {
            scenario: mc.tag(),
            label: mc.label(),
            aimed_member: aimed,
            t_obs: agg.t_obs,
            null_mean: agg.null_mean,
            lift,
            aimed_member_agreement: agg.member_agreements[aimed - 1],
            aimed_member_lift: aimed_lift,
            member_agreements: agg.member_agreements,
            member_null_means: agg.member_null_means,
            member_p: agg.member_p,
            member_flags: agg.member_flags,
            member_null_max: agg.member_null_max,
            passed,
            bound,
        });
    }

    let all_pass = deployed.passed && controls.iter().all(|c| c.passed);
    let status = if all_pass {
        "PARTITION-PASS (deployed at chance on both arms; every marked control \
         bites its aimed member)"
            .to_string()
    } else if !deployed.passed {
        "PARTITION-FAIL (deployed posture sortable — launch-posture blocker, \
         never a bar move; §14.4 consumer 1)"
            .to_string()
    } else {
        "INVALID (a marked control did not bite its aimed member — bound 3 \
         all-or-nothing; the detector cannot certify coverage of that \
         control's adversary)"
            .to_string()
    };

    PartitionReport {
        n: cfg.n,
        founder_count: FOUNDER_COUNT,
        trials: cfg.trials,
        permutations: cfg.perms,
        bound1_tol: BOUND1_TOL,
        bound2_lift: BOUND2_LIFT,
        deployed,
        controls,
        status,
        pinned_underspecifications: pins,
    }
}

/// Binary entry: the full graded partition measurement (evidence config).
pub fn run_partition_report() -> PartitionReport {
    run_partition_measurement(&PartitionConfig::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The committed bound sits under the documented ceiling — the disposition's
    /// "derivably small" claim is a computed property, not an assertion. At the
    /// launch geometry the value is `5·(31/601)^4 ≈ 3.538e-5`.
    #[test]
    fn gating_lemma_is_derivably_small() {
        let bound = committed_gating_bound();
        assert!(
            bound < GATING_LEMMA_CEILING,
            "committed gating bound {bound} must be below the derivably-small \
             ceiling {GATING_LEMMA_CEILING}"
        );
        let expected = 5.0 * (31.0f64 / 601.0).powi(4);
        assert!(
            (bound - expected).abs() < 1e-12,
            "expected {expected}, got {bound}"
        );
    }

    /// The mis-configuration guards refuse loudly rather than degrade
    /// (PR #291 review): a `perms` too small to resolve the any-member arm's
    /// α/7 bar, an `n` outside the exact-enumeration design range, and a
    /// zero-trial run are each configuration errors, never smaller-effort
    /// runs.
    #[test]
    #[should_panic(expected = "cannot resolve the any-member arm")]
    fn guard_refuses_unresolvable_perms() {
        let cfg = PartitionConfig {
            perms: 100,
            ..PartitionConfig::default()
        };
        run_partition_measurement(&cfg);
    }

    #[test]
    #[should_panic(expected = "exact-enumeration design range")]
    fn guard_refuses_out_of_range_n() {
        let cfg = PartitionConfig {
            n: MAX_EXACT_N + 1,
            ..PartitionConfig::default()
        };
        run_partition_measurement(&cfg);
    }

    #[test]
    #[should_panic(expected = "trials must be ≥ 1")]
    fn guard_refuses_zero_trials() {
        let cfg = PartitionConfig {
            trials: 0,
            ..PartitionConfig::default()
        };
        run_partition_measurement(&cfg);
    }

    /// The committed upper bound is conservative: it is ≥ the tight range CDF
    /// (it drops a subtracted non-negative term).
    #[test]
    fn upper_bound_dominates_exact() {
        for &(m, c, w) in &[
            (5usize, 30u64, 600u64),
            (2, 1, 10),
            (5, 60, 600),
            (3, 5, 100),
        ] {
            let bound = gating_lemma_bound(m, c, w);
            let exact = gating_lemma_exact(m, c, w);
            assert!(
                bound + 1e-15 >= exact,
                "upper bound {bound} must dominate exact {exact} (m={m}, c={c}, w={w})"
            );
            assert!(
                (0.0..=1.0).contains(&exact),
                "exact must be a probability: {exact}"
            );
        }
    }

    /// The bound rises with the clustering resolution and falls as the window
    /// widens — the "widen the entry-gap distribution" redesign lever (§14.4:
    /// "if the bound is not derivably small … posture redesign … never bar
    /// relaxation").
    #[test]
    fn bound_monotone_in_geometry() {
        let base = gating_lemma_bound(5, 30, 600);
        assert!(
            gating_lemma_bound(5, 60, 600) > base,
            "wider span ⇒ larger bound"
        );
        assert!(
            gating_lemma_bound(5, 30, 1_200) < base,
            "wider window ⇒ smaller bound"
        );
    }

    /// Witness typing, positive direction: both the production config and every
    /// marked-control witness construct and round-trip.
    ///
    /// The **negative** direction (a control config constructible on the
    /// production path) is a compile-time *absence*, not a runtime check: there
    /// is no `FounderConfig` constructor taking a `MarkedControl`/`ControlWitness`
    /// and no `From` bridge, so such a construction does not typecheck. A test
    /// cannot exhibit code that fails to compile within the same crate, so the
    /// guarantee is carried by the type surface (documented on `FounderConfig`)
    /// and reviewed structurally.
    #[test]
    fn witness_types_construct_and_round_trip() {
        let deployed = FounderConfig::deployed();
        assert_eq!(deployed.window(), ENTRY_GAP_WINDOW);

        for &m in &MarkedControl::ALL {
            let w = ControlWitness::marked(m);
            assert_eq!(w.control(), m);
            assert_eq!(w.window(), ENTRY_GAP_WINDOW);
        }
    }

    /// Each marked control aims at a distinct family member (bound 2's
    /// per-control bite requirement), and the aimed members are exactly the
    /// §14.4 mapping {M-a→1, M-b→2, M-c→3, M-d→6, M-e→7}.
    #[test]
    fn controls_aim_at_their_members() {
        let aimed: Vec<usize> = MarkedControl::ALL
            .iter()
            .map(|c| c.aimed_member())
            .collect();
        assert_eq!(aimed, vec![1, 2, 3, 6, 7]);
    }

    /// The graded arm's structurally stable outcome (seed-robust at 120
    /// trials) under the resolved grading rule (§14.4 pin resolution — the
    /// any-member arm selected by the T-site verification):
    ///
    /// - the deployed posture holds **both** bound-1 arms: the family-max
    ///   lift at chance AND no member flags against its own FW-corrected
    ///   null (the per-member re-check that closes the false-clean hazard —
    ///   a max/consensus `T` can pass on insensitivity; the per-member arm
    ///   cannot);
    /// - every whole-set control (M-a lockstep, M-c cohesion, M-e repulsion)
    ///   clears family-max bound 2 with its aimed member flagging;
    /// - the single-member-targeted controls (M-b, M-d) bite through the
    ///   any-member arm — their aimed members (2, 6) flag at α/7 even though
    ///   the family max cannot move (the Q2-A adversary lives on member 6's
    ///   axis alone), certifying that deployment's rule catches the
    ///   adversaries members 6/7 were added for;
    /// - M-d still keeps members 1–5 at chance (the §14.4 recorded-per-run
    ///   requirement) — the flags are member-6-specific, not a family-wide
    ///   artifact;
    /// - no pins remain, and bound 3's all-or-nothing verdict is
    ///   PARTITION-PASS.
    #[test]
    fn graded_arm_structural_outcome() {
        // `perms` must resolve the any-member arm's α/7 bar (rank p-value
        // floor 1/(perms+1); ≥ 139 at α = 0.05 — loud guard in
        // `run_partition_measurement`), and `trials` must be power-sized to
        // the single-member effect ceiling (δ ≈ +0.03–0.04 vs null-of-mean
        // spread σ/√trials, σ ≈ 0.18 — the derivation on
        // `PartitionConfig::default`); 400 trials puts the M-b ceiling at
        // > 4σ. Both are a-priori sizings, not tuned to observed scores.
        let cfg = PartitionConfig {
            n: ARM_N,
            trials: 400,
            perms: 160,
            seed: 0xDEAD_BEEF_0001,
        };
        let r = run_partition_measurement(&cfg);

        // Bound 1, both arms: deployed founders are indistinguishable from
        // users on the family max AND on every member's own axis.
        assert!(
            r.deployed.passed,
            "deployed posture must hold bound 1 (lift {:+.3}, flags {:?}, p {:?})",
            r.deployed.lift, r.deployed.member_flags, r.deployed.member_p
        );
        assert!(
            r.deployed.member_flags.iter().all(|&f| !f),
            "no member may resolve deployed founders on its own axis (p {:?})",
            r.deployed.member_p
        );

        // Bound 2 (whole-set): each control bites the family max, its aimed
        // member's own lift dominates the +0.30 bound, and the aimed member
        // flags on the any-member arm.
        for tag in ["M-a", "M-c", "M-e"] {
            let c = r.controls.iter().find(|c| c.scenario == tag).unwrap();
            assert!(
                c.passed,
                "{tag} must bite bound 2 (family-max lift {:+.3}, aimed flag {})",
                c.lift,
                c.member_flags[c.aimed_member - 1]
            );
            assert!(
                c.aimed_member_lift >= BOUND2_LIFT,
                "{tag}'s aimed member {} must itself lift ≥ {BOUND2_LIFT} (got {:+.3})",
                c.aimed_member,
                c.aimed_member_lift
            );
        }

        // Bound 2 (single-member): M-b and M-d bite through the any-member
        // arm — the resolved rule the deployed detector itself uses.
        for tag in ["M-b", "M-d"] {
            let c = r.controls.iter().find(|c| c.scenario == tag).unwrap();
            assert!(
                c.passed,
                "{tag}'s aimed member {} must flag at α/7 (p {:.4}, obs {:.3}, \
                 null max {:.3})",
                c.aimed_member,
                c.member_p[c.aimed_member - 1],
                c.member_agreements[c.aimed_member - 1],
                c.member_null_max[c.aimed_member - 1]
            );
        }

        // M-d keeps members 1–5 at chance (the §14.4 recorded-per-run
        // requirement) while member 6 is the only positive detector.
        let md = r.controls.iter().find(|c| c.scenario == "M-d").unwrap();
        for k in 0..5 {
            let lift = md.member_agreements[k] - md.member_null_means[k];
            assert!(
                lift < 0.10,
                "M-d must leave member {} at chance (lift {lift:+.3})",
                k + 1
            );
        }
        assert!(
            md.aimed_member_lift > 0.0,
            "M-d's member 6 must be the biting detector (lift {:+.3})",
            md.aimed_member_lift
        );

        // The bound-2 under-specification is resolved (T-site fact verified,
        // any-member arm landed); no pins remain and the all-or-nothing
        // verdict is a genuine pass — reached by adding a detection arm,
        // never by lowering a bar.
        assert!(
            r.pinned_underspecifications.is_empty(),
            "no under-specification pins expected after the §14.4 resolution: {:?}",
            r.pinned_underspecifications
        );
        assert!(
            r.status.starts_with("PARTITION-PASS"),
            "expected PARTITION-PASS, got: {}",
            r.status
        );
    }

    /// The co-first-deliverable report is well-formed: it commits the gating
    /// lemma below the ceiling and enumerates all five witness-typed controls.
    #[test]
    fn report_is_well_formed() {
        let r = run_gating_witness_report();
        assert_eq!(r.founder_count, FOUNDER_COUNT);
        assert!(r.derivably_small);
        assert!(r.gating_lemma_bound < r.gating_lemma_ceiling);
        assert!(r.gating_lemma_exact <= r.gating_lemma_bound + 1e-15);
        assert_eq!(r.deployed_window, ENTRY_GAP_WINDOW);
        assert_eq!(r.controls.len(), 5);
        assert!(r.controls.iter().all(|c| c.witness_typed));
        assert_eq!(
            r.controls.iter().map(|c| c.tag).collect::<Vec<_>>(),
            vec!["M-a", "M-b", "M-c", "M-d", "M-e"]
        );
    }
}
