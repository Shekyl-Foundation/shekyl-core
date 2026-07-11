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

use shekyl_standoff::DEFAULT_ENTRY_GAP_WINDOW;

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
    /// The committed a-priori bound `m·(c/w)^(m−1)`.
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
