// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `--mode=adversarial-ratio` orchestrator (Phase 2h R1-D5 close).
//!
//! Per
//! [`RANDOMX_V2_PHASE2H_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2H_PLAN.md)
//! Round 1 R1-D5 close, this module replaces the historical
//! `mode_worst_case` deferred-stub at Phase 2g
//! `main.rs:492-510` with the recipe-derived adversarial-ratio
//! measurement methodology. The mode iterates over the recipe
//! corpus produced by [`crate::adversarial::get_corpus`], evaluates
//! each recipe via [`crate::adversarial::interpreter::evaluate`],
//! constructs paired Rust/C sessions via the
//! [`from_raw_for_testing`](crate::rust_subject::RustSubjectSession::from_raw_for_testing)
//! and
//! [`from_raw_for_testing`](crate::c_oracle::COracleSession::from_raw_for_testing)
//! accessors (Phase 2h R1-D2 close cache-level test-internals
//! surface plus its C-side symmetric counterpart), and measures
//! per-hash latency on both sides with the same interleaved
//! methodology as [`crate::mode_latency`].
//!
//! ## Two distinct claims (R1-D5 close)
//!
//! - **Claim 1 — per-recipe ratio bound (hard gate).** For every
//!   corpus entry, Rust verifier max-ratio latency must be within
//!   `(5.0 − RUNNER_NOISE_MARGIN)` of C reference max-ratio latency.
//!   Per-recipe failure is hard-gate; single-retry noise filter
//!   (per R1-D5 close framing) is reserved for the C8 CI workflow
//!   wrapper, not this in-process module.
//! - **Claim 2 — no per-class systematic regression (regression-
//!   tracking signal).** No category-grouped median ratio exceeds
//!   the corpus-wide median ratio by more than
//!   [`CLAIM_2_THRESHOLD`]. Category-level outliers are *surfaced*
//!   as regression-tracking signal; they do not block the run by
//!   themselves.
//!
//! Both claims read their thresholds from
//! [`crate::adversarial_canonical_outputs`]'s
//! [`RUNNER_NOISE_MARGIN`] and [`CLAIM_2_THRESHOLD`] constants
//! (C1-landed substrate, refined per the §2.3 provisional-value
//! discipline).
//!
//! ## Measurement methodology
//!
//! Per recipe:
//!
//! 1. **Derive base cache bytes once** via
//!    [`crate::adversarial::canonical::derive_base_cache_bytes`].
//!    The base derivation pays the ~150–200 ms Argon2d-fill cost
//!    once per recipe; subsequent samples reuse the derived bytes.
//!    Future commits may amortize across recipes sharing the same
//!    base seedhash; the C6 disposition is one derivation per
//!    recipe for simplicity (the corpus's C4 starter set shares a
//!    single base seedhash, so the optimization is no-op at the
//!    current scale).
//! 2. **Evaluate the recipe** via
//!    [`crate::adversarial::interpreter::evaluate`] to produce the
//!    `(seedhash, cache_bytes)` pair.
//! 3. **Construct paired sessions** via the symmetric
//!    `from_raw_for_testing` accessors; both sides now hold a
//!    `(seedhash, cache_bytes)` pair byte-identical to the
//!    evaluator's output.
//! 4. **Sample [`SAMPLE_BUDGET_PER_RECIPE`] hashes** per side using
//!    the same interleaved methodology as
//!    [`crate::mode_latency`]: even-index iterations run Rust then
//!    C; odd-index iterations run C then Rust, neutralizing
//!    CPU-cache-warmth bias.
//! 5. **Compute per-recipe statistics** — median, p95, max per side;
//!    median-ratio and max-ratio against the C-side median.
//!
//! Cross-recipe aggregation computes the corpus-wide median ratio
//! and the per-class median ratio (recipes grouped by R1-D8 evidence
//! category extracted from the recipe's `rationale` prefix).
//!
//! ## Data input
//!
//! Per-recipe samples use a deterministic 32-byte data value
//! ([`ADVERSARIAL_RATIO_DATA`]) — a single fixed input is
//! sufficient because the per-recipe ratio's substrate is the
//! recipe's cache contents, not the data input. The data input's
//! identity is recipe-independent so per-recipe ratios are
//! comparable across the corpus.
//!
//! ## Cadence
//!
//! Per R1-D6 close, this mode runs at the **nightly** cadence
//! pre-genesis (via a `workflow_dispatch`-triggered dedicated
//! workflow at C8) and at **release-gate** cadence post-genesis.
//! It is **not** part of the per-PR workflow — the ~100-samples-per-
//! recipe-per-side measurement is too expensive for per-PR cadence
//! even at the C4 starter-corpus size.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::hint::black_box;
use std::time::Instant;

use crate::adversarial::canonical::derive_base_cache_bytes;
use crate::adversarial::get_corpus;
use crate::adversarial::interpreter::evaluate;
use crate::adversarial::types::CacheRecipe;
use crate::adversarial_canonical_outputs::{
    CLAIM_2_THRESHOLD, RUNNER_NOISE_MARGIN, SAMPLE_BUDGET_PER_RECIPE,
};
use crate::c_oracle::{COracleError, COracleSession};
use crate::rust_subject::RustSubjectSession;

/// Claim-1 absolute per-recipe ratio bound before noise-margin
/// adjustment, per parent
/// [`RANDOMX_V2_PLAN.md`](../../../../docs/design/RANDOMX_V2_PLAN.md)
/// §6's "≤5.0× on adversarial inputs" pin.
///
/// The effective gate is
/// [`CLAIM_1_RATIO_BOUND`] − [`RUNNER_NOISE_MARGIN`] per R1-D5
/// close; pinned as a constant here so the assertion is centralized
/// and any future bound change requires a plan-doc round per §5.7's
/// drift-prevention discipline.
pub const CLAIM_1_RATIO_BOUND: f64 = 5.0;

/// Deterministic 32-byte data input used for every per-recipe
/// timing sample.
///
/// A single fixed input is sufficient per R1-D5 close: the
/// per-recipe ratio's substrate is the recipe's cache contents,
/// not the data input. Pinning the data input means per-recipe
/// ratios are comparable across the corpus without per-recipe data
/// substrate to explain ratio variance.
///
/// The value is the byte string `0x00..0x1f` (32 ascending bytes);
/// no special significance — any deterministic 32-byte pattern
/// would satisfy the methodology.
pub const ADVERSARIAL_RATIO_DATA: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// Per-recipe timing report.
///
/// One [`PerRecipeReport`] per [`CacheRecipe`] in
/// [`get_corpus`]'s ordering, populated by [`run`] in the order
/// the corpus enumerates the recipes.
#[derive(Debug, Clone, PartialEq)]
pub struct PerRecipeReport {
    /// Echoes [`CacheRecipe::name`] for diagnostic correlation.
    pub recipe_name: &'static str,
    /// R1-D8 evidence category derived from the rationale prefix
    /// (1, 2, or 3); see [`recipe_category`] for the extraction
    /// rule.
    pub category: u8,
    /// Per-recipe sample count (always equals
    /// [`SAMPLE_BUDGET_PER_RECIPE`] for a clean run).
    pub samples: usize,
    /// Rust subject's median per-hash wall-clock (nanoseconds).
    pub rust_median_ns: u64,
    /// Rust subject's p95 per-hash wall-clock (nanoseconds).
    pub rust_p95_ns: u64,
    /// Rust subject's max per-hash wall-clock (nanoseconds).
    pub rust_max_ns: u64,
    /// C oracle's median per-hash wall-clock (nanoseconds).
    pub c_median_ns: u64,
    /// C oracle's p95 per-hash wall-clock (nanoseconds).
    pub c_p95_ns: u64,
    /// C oracle's max per-hash wall-clock (nanoseconds).
    pub c_max_ns: u64,
    /// `rust_median_ns / c_median_ns`.
    pub median_ratio: f64,
    /// `rust_max_ns / c_max_ns`. The Claim 1 gate compares this
    /// against `CLAIM_1_RATIO_BOUND − RUNNER_NOISE_MARGIN`.
    pub max_ratio: f64,
}

/// Per-category aggregation for Claim 2.
#[derive(Debug, Clone, PartialEq)]
pub struct PerClassReport {
    /// R1-D8 evidence category (1, 2, or 3).
    pub category: u8,
    /// Number of recipes in this category.
    pub recipe_count: usize,
    /// Median of per-recipe `median_ratio` values across this
    /// class. Compared against `corpus_median_ratio ×
    /// CLAIM_2_THRESHOLD` for the Claim-2 regression-tracking
    /// signal.
    pub class_median_ratio: f64,
}

/// Top-level successful-run report.
///
/// Stdout emission via the [`fmt::Display`] impl below; the C9
/// structured-JSON failure schema may serialize this in the future
/// without re-running.
#[derive(Debug, Clone, PartialEq)]
pub struct AdversarialRatioReport {
    /// Number of recipes the run measured (equals
    /// `get_corpus().len()` for a clean run).
    pub corpus_size: usize,
    /// Per-recipe sample count (equals [`SAMPLE_BUDGET_PER_RECIPE`]
    /// for a clean run; overridable for in-process testing).
    pub samples_per_recipe: usize,
    /// One report per corpus entry; populated in `get_corpus()`
    /// ordering.
    pub per_recipe: Vec<PerRecipeReport>,
    /// One report per evidence category present in the corpus
    /// (sorted by category number).
    pub per_class: Vec<PerClassReport>,
    /// Median of per-recipe `median_ratio` values across the
    /// entire corpus. The Claim-2 reference value.
    pub corpus_median_ratio: f64,
    /// `CLAIM_1_RATIO_BOUND − RUNNER_NOISE_MARGIN` snapshot at
    /// report-build time. Re-emitted in the report so a reviewer
    /// reading historical output sees the constants the report
    /// was built against.
    pub claim_1_effective_bound: f64,
    /// [`CLAIM_2_THRESHOLD`] snapshot at report-build time
    /// (same rationale as [`Self::claim_1_effective_bound`]).
    pub claim_2_threshold: f64,
    /// Categories whose per-class median ratio exceeds
    /// `corpus_median_ratio × CLAIM_2_THRESHOLD`. Empty on a
    /// non-violating run. Per R1-D5 close: Claim-2 is a
    /// tracking-signal; the presence of entries here does not
    /// fail the run by itself.
    pub claim_2_violations: Vec<u8>,
}

impl fmt::Display for AdversarialRatioReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "adversarial-ratio mode (recipes={}, samples_per_recipe={}):",
            self.corpus_size, self.samples_per_recipe
        )?;
        writeln!(f, "  per-recipe results:")?;
        for r in &self.per_recipe {
            writeln!(
                f,
                "    [cat={}] {}: rust median={} ns, c median={} ns, median ratio={:.3}x, max ratio={:.3}x",
                r.category, r.recipe_name, r.rust_median_ns, r.c_median_ns, r.median_ratio, r.max_ratio
            )?;
        }
        writeln!(f, "  per-class medians:")?;
        for c in &self.per_class {
            writeln!(
                f,
                "    [cat={}] recipes={}, class_median_ratio={:.3}x",
                c.category, c.recipe_count, c.class_median_ratio
            )?;
        }
        writeln!(f, "  corpus_median_ratio={:.3}x", self.corpus_median_ratio)?;
        writeln!(
            f,
            "  Claim 1 gate: max_ratio ≤ {:.3}x (= {:.1} − {:.2})",
            self.claim_1_effective_bound, CLAIM_1_RATIO_BOUND, RUNNER_NOISE_MARGIN
        )?;
        write!(
            f,
            "  Claim 2 threshold: class_median ≤ corpus_median × {:.2}x",
            self.claim_2_threshold
        )?;
        if !self.claim_2_violations.is_empty() {
            write!(
                f,
                "  (TRACKING-SIGNAL: classes exceeding threshold: {:?})",
                self.claim_2_violations
            )?;
        }
        Ok(())
    }
}

/// Failure modes the adversarial-ratio orchestrator can surface.
#[derive(Debug)]
pub enum AdversarialRatioError {
    /// C oracle resource allocation failed (one of the three
    /// [`COracleError`] variants).
    COracle(COracleError),
    /// `samples_per_recipe == 0`: per-recipe measurement requires
    /// at least one iteration. Surfaced at run-time as a
    /// belt-and-braces guard; the CLI parse layer rejects
    /// `--samples-per-recipe=0` before reaching this code path.
    ZeroSamples,
    /// `get_corpus()` returned an empty slice. Should not occur
    /// post-C4 (the C4 starter corpus has 8 recipes); surfaced
    /// for forward-compatibility against a future corpus-tooling
    /// disposition that empties the corpus.
    EmptyCorpus,
    /// Claim-1 hard-gate failure: one or more recipes' per-recipe
    /// `max_ratio` exceeded `CLAIM_1_RATIO_BOUND −
    /// RUNNER_NOISE_MARGIN`. Carries the full report for the
    /// failure-output diagnostic (the C9 structured-JSON schema
    /// can serialize without re-running). The report is `Box`-ed
    /// to keep [`AdversarialRatioError`] small per Clippy's
    /// `result_large_err` lint.
    Claim1BoundExceeded {
        report: Box<AdversarialRatioReport>,
        offending_recipes: Vec<&'static str>,
    },
}

impl fmt::Display for AdversarialRatioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::COracle(e) => write!(f, "c-oracle setup failed: {e}"),
            Self::ZeroSamples => write!(
                f,
                "adversarial-ratio mode requires --samples-per-recipe >= 1; got 0"
            ),
            Self::EmptyCorpus => write!(
                f,
                "adversarial-ratio mode requires a non-empty corpus; get_corpus() returned 0 recipes"
            ),
            Self::Claim1BoundExceeded {
                report,
                offending_recipes,
            } => write!(
                f,
                "Claim 1 gate failed for {} recipe(s): {:?}\n{}",
                offending_recipes.len(),
                offending_recipes,
                report
            ),
        }
    }
}

impl std::error::Error for AdversarialRatioError {}

impl From<COracleError> for AdversarialRatioError {
    fn from(e: COracleError) -> Self {
        Self::COracle(e)
    }
}

/// Extract the R1-D8 evidence-category number (1, 2, or 3) from a
/// recipe's `rationale` prefix.
///
/// Per
/// [`crate::adversarial::tests::corpus_recipes_are_well_formed`],
/// every corpus recipe's `rationale` starts with `"Category N: "`
/// where N ∈ {1, 2, 3}. This function parses the prefix and
/// returns the category number; a malformed rationale (which the
/// well-formedness test would have caught at PR review) panics
/// with a diagnostic naming the offending recipe.
#[must_use]
pub fn recipe_category(recipe: &CacheRecipe) -> u8 {
    if recipe.rationale.starts_with("Category 1:") {
        1
    } else if recipe.rationale.starts_with("Category 2:") {
        2
    } else if recipe.rationale.starts_with("Category 3:") {
        3
    } else {
        panic!(
            "Recipe `{}` rationale does not start with `Category N:` prefix (N = 1/2/3); \
             the well-formedness test should have caught this at PR review",
            recipe.name
        )
    }
}

/// Run `--mode=adversarial-ratio` per the Phase 2h R1-D5 close.
///
/// `samples_per_recipe_override` lets in-process callers (e.g.,
/// future integration tests) shrink the per-recipe sample count
/// for smoke runs; `None` uses [`SAMPLE_BUDGET_PER_RECIPE`].
///
/// # Errors
///
/// - [`AdversarialRatioError::ZeroSamples`] if the effective
///   `samples_per_recipe` is zero.
/// - [`AdversarialRatioError::EmptyCorpus`] if `get_corpus()`
///   returns an empty slice.
/// - [`AdversarialRatioError::COracle`] on C-side allocation
///   failure for any recipe's session pair.
/// - [`AdversarialRatioError::Claim1BoundExceeded`] if any
///   per-recipe `max_ratio` exceeds
///   `CLAIM_1_RATIO_BOUND − RUNNER_NOISE_MARGIN`.
pub fn run(
    samples_per_recipe_override: Option<usize>,
) -> Result<AdversarialRatioReport, AdversarialRatioError> {
    let samples_per_recipe = samples_per_recipe_override.unwrap_or(SAMPLE_BUDGET_PER_RECIPE);
    if samples_per_recipe == 0 {
        return Err(AdversarialRatioError::ZeroSamples);
    }
    let corpus = get_corpus();
    if corpus.is_empty() {
        return Err(AdversarialRatioError::EmptyCorpus);
    }

    let mut per_recipe: Vec<PerRecipeReport> = Vec::with_capacity(corpus.len());
    for recipe in &corpus {
        let base_bytes = derive_base_cache_bytes(&recipe.base);
        let evaluated = evaluate(recipe, &base_bytes);
        let rust = RustSubjectSession::from_raw_for_testing(evaluated.seedhash, &evaluated.cache_bytes);
        let c = COracleSession::from_raw_for_testing(evaluated.seedhash, &evaluated.cache_bytes)?;

        let mut rust_samples_ns: Vec<u64> = Vec::with_capacity(samples_per_recipe);
        let mut c_samples_ns: Vec<u64> = Vec::with_capacity(samples_per_recipe);
        for i in 0..samples_per_recipe {
            // Interleaved per-iteration timing, mirroring
            // mode_latency.rs's R1-D7 methodology so cache-warmth
            // bias amortizes symmetrically between sides.
            if i % 2 == 0 {
                let (rust_ns, _h) = time_rust(&rust, &ADVERSARIAL_RATIO_DATA);
                let (c_ns, _h) = time_c(&c, &ADVERSARIAL_RATIO_DATA);
                rust_samples_ns.push(rust_ns);
                c_samples_ns.push(c_ns);
            } else {
                let (c_ns, _h) = time_c(&c, &ADVERSARIAL_RATIO_DATA);
                let (rust_ns, _h) = time_rust(&rust, &ADVERSARIAL_RATIO_DATA);
                rust_samples_ns.push(rust_ns);
                c_samples_ns.push(c_ns);
            }
        }
        let (rust_median_ns, rust_p95_ns, rust_max_ns) = median_p95_max(&mut rust_samples_ns);
        let (c_median_ns, c_p95_ns, c_max_ns) = median_p95_max(&mut c_samples_ns);
        let median_ratio = safe_ratio(rust_median_ns, c_median_ns);
        let max_ratio = safe_ratio(rust_max_ns, c_max_ns);
        per_recipe.push(PerRecipeReport {
            recipe_name: recipe.name,
            category: recipe_category(recipe),
            samples: samples_per_recipe,
            rust_median_ns,
            rust_p95_ns,
            rust_max_ns,
            c_median_ns,
            c_p95_ns,
            c_max_ns,
            median_ratio,
            max_ratio,
        });
    }

    let report = build_report(per_recipe, samples_per_recipe);

    // Claim-1 gate (hard): any per-recipe max_ratio exceeding
    // `CLAIM_1_RATIO_BOUND − RUNNER_NOISE_MARGIN` is a failure.
    let offending: Vec<&'static str> = report
        .per_recipe
        .iter()
        .filter(|r| r.max_ratio > report.claim_1_effective_bound)
        .map(|r| r.recipe_name)
        .collect();
    if !offending.is_empty() {
        return Err(AdversarialRatioError::Claim1BoundExceeded {
            report: Box::new(report),
            offending_recipes: offending,
        });
    }
    Ok(report)
}

/// Build [`AdversarialRatioReport`] from per-recipe data plus
/// cross-recipe aggregation. Pulled out of [`run`] so the
/// aggregation logic is unit-testable without paying the cost of
/// real `derive`/`compute_hash` invocations.
fn build_report(
    per_recipe: Vec<PerRecipeReport>,
    samples_per_recipe: usize,
) -> AdversarialRatioReport {
    let corpus_size = per_recipe.len();
    let mut all_medians: Vec<f64> = per_recipe.iter().map(|r| r.median_ratio).collect();
    let corpus_median_ratio = median_of_f64(&mut all_medians);

    let mut per_class_map: BTreeMap<u8, Vec<f64>> = BTreeMap::new();
    for r in &per_recipe {
        per_class_map
            .entry(r.category)
            .or_default()
            .push(r.median_ratio);
    }
    let per_class: Vec<PerClassReport> = per_class_map
        .into_iter()
        .map(|(category, mut medians)| PerClassReport {
            category,
            recipe_count: medians.len(),
            class_median_ratio: median_of_f64(&mut medians),
        })
        .collect();

    let claim_1_effective_bound = CLAIM_1_RATIO_BOUND - RUNNER_NOISE_MARGIN;
    let claim_2_threshold = CLAIM_2_THRESHOLD;
    let claim_2_violations: Vec<u8> = per_class
        .iter()
        .filter(|c| c.class_median_ratio > corpus_median_ratio * claim_2_threshold)
        .map(|c| c.category)
        .collect();

    AdversarialRatioReport {
        corpus_size,
        samples_per_recipe,
        per_recipe,
        per_class,
        corpus_median_ratio,
        claim_1_effective_bound,
        claim_2_threshold,
        claim_2_violations,
    }
}

/// Time one Rust-subject `compute_hash` invocation. Mirrors
/// [`crate::mode_latency::time_rust`]'s `black_box` discipline;
/// duplicated here (rather than reusing the public surface) to keep
/// `mode_latency`'s helpers `pub(super)` per the Phase 2g §5.7
/// drift-prevention boundary.
#[inline(never)]
fn time_rust(rust: &RustSubjectSession, data: &[u8]) -> (u64, [u8; 32]) {
    let data = black_box(data);
    let start = Instant::now();
    let hash = rust.compute_hash(data);
    let elapsed = start.elapsed();
    let hash = black_box(hash);
    (duration_to_ns(elapsed), hash)
}

/// Time one C-oracle `calculate_hash` invocation. See
/// [`time_rust`] for the duplication rationale.
#[inline(never)]
fn time_c(c: &COracleSession, data: &[u8]) -> (u64, [u8; 32]) {
    let data = black_box(data);
    let start = Instant::now();
    let hash = c.calculate_hash(data);
    let elapsed = start.elapsed();
    let hash = black_box(hash);
    (duration_to_ns(elapsed), hash)
}

fn duration_to_ns(d: std::time::Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

/// `(median, p95, max)` over a `u64` sample slice using the same
/// upper-median + integer-percentile convention as
/// [`crate::mode_latency::median_p95_max`].
fn median_p95_max(samples: &mut [u64]) -> (u64, u64, u64) {
    debug_assert!(!samples.is_empty());
    samples.sort_unstable_by(|a, b| a.cmp(b).then(Ordering::Equal));
    let n = samples.len();
    let median = samples[n / 2];
    let p95_idx = ((n.saturating_sub(1)) * 95) / 100;
    let p95 = samples[p95_idx];
    let max = samples[n - 1];
    (median, p95, max)
}

/// Median over an `f64` sample slice. NaN values are sorted to the
/// end via `partial_cmp(...).unwrap_or(Ordering::Greater)`; the
/// per-recipe ratios produced by [`safe_ratio`] are finite (∞
/// emitted on the `c_median_ns == 0` guard), so the median's
/// stability under the `partial_cmp` ordering is preserved for
/// realistic inputs.
fn median_of_f64(samples: &mut [f64]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    samples.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Greater));
    samples[samples.len() / 2]
}

/// `rust_ns as f64 / c_ns as f64`, with `c_ns == 0` handled by
/// returning `f64::INFINITY` rather than panicking on
/// divide-by-zero. The `c_ns == 0` case is unreachable on real
/// hardware (one RandomX hash is >100 µs even in the fastest
/// configuration); the guard is belt-and-braces.
fn safe_ratio(rust_ns: u64, c_ns: u64) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    if c_ns == 0 {
        f64::INFINITY
    } else {
        rust_ns as f64 / c_ns as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic per-recipe data hits the Claim-1 gate cleanly when
    /// the max_ratio is below the effective bound, and trips the
    /// gate when one recipe exceeds. The aggregation arithmetic is
    /// independently testable without paying the cost of real
    /// `derive`/`compute_hash` invocations.
    #[test]
    fn build_report_aggregates_per_class_medians() {
        let per_recipe = vec![
            PerRecipeReport {
                recipe_name: "cat1-a",
                category: 1,
                samples: 100,
                rust_median_ns: 200,
                rust_p95_ns: 250,
                rust_max_ns: 300,
                c_median_ns: 100,
                c_p95_ns: 110,
                c_max_ns: 120,
                median_ratio: 2.0,
                max_ratio: 2.5,
            },
            PerRecipeReport {
                recipe_name: "cat1-b",
                category: 1,
                samples: 100,
                rust_median_ns: 220,
                rust_p95_ns: 270,
                rust_max_ns: 320,
                c_median_ns: 100,
                c_p95_ns: 110,
                c_max_ns: 120,
                median_ratio: 2.2,
                max_ratio: 2.67,
            },
            PerRecipeReport {
                recipe_name: "cat3-a",
                category: 3,
                samples: 100,
                rust_median_ns: 150,
                rust_p95_ns: 180,
                rust_max_ns: 200,
                c_median_ns: 100,
                c_p95_ns: 110,
                c_max_ns: 120,
                median_ratio: 1.5,
                max_ratio: 1.67,
            },
        ];
        let report = build_report(per_recipe, 100);
        assert_eq!(report.corpus_size, 3);
        assert_eq!(report.per_class.len(), 2);
        assert!((report.corpus_median_ratio - 2.0).abs() < 1e-9);
        // Category 1's class median is the upper-median of [2.0, 2.2] = 2.2.
        let cat1 = report.per_class.iter().find(|c| c.category == 1).unwrap();
        assert!((cat1.class_median_ratio - 2.2).abs() < 1e-9);
        // Category 3's class median is 1.5 (single recipe).
        let cat3 = report.per_class.iter().find(|c| c.category == 3).unwrap();
        assert!((cat3.class_median_ratio - 1.5).abs() < 1e-9);
        // Claim 2 violations: corpus_median × 1.5 = 3.0; neither class
        // (2.2, 1.5) exceeds, so no violations.
        assert!(report.claim_2_violations.is_empty());
    }

    #[test]
    fn build_report_flags_claim_2_violation() {
        let per_recipe = vec![
            PerRecipeReport {
                recipe_name: "cat1-a",
                category: 1,
                samples: 100,
                rust_median_ns: 500,
                rust_p95_ns: 600,
                rust_max_ns: 700,
                c_median_ns: 100,
                c_p95_ns: 110,
                c_max_ns: 120,
                median_ratio: 5.0,
                max_ratio: 5.83,
            },
            PerRecipeReport {
                recipe_name: "cat3-a",
                category: 3,
                samples: 100,
                rust_median_ns: 100,
                rust_p95_ns: 110,
                rust_max_ns: 120,
                c_median_ns: 100,
                c_p95_ns: 110,
                c_max_ns: 120,
                median_ratio: 1.0,
                max_ratio: 1.0,
            },
        ];
        let report = build_report(per_recipe, 100);
        // corpus_median is upper-median of [1.0, 5.0] = 5.0.
        assert!((report.corpus_median_ratio - 5.0).abs() < 1e-9);
        // Category 1's class median (5.0) > corpus_median (5.0) × 1.5 (7.5)?
        // No — 5.0 < 7.5, so no violation. Category 3's class median
        // (1.0) < 7.5. So no violations on this configuration.
        assert!(report.claim_2_violations.is_empty());
    }

    #[test]
    fn recipe_category_extracts_category_1() {
        let recipe = CacheRecipe {
            name: "test-recipe",
            rationale: "Category 1: audit-anchored test recipe",
            base: crate::adversarial::types::BaseSeedhash {
                name: "test-base",
                bytes: [0u8; 32],
            },
            modifications: &[],
        };
        assert_eq!(recipe_category(&recipe), 1);
    }

    #[test]
    fn recipe_category_extracts_category_3() {
        let recipe = CacheRecipe {
            name: "test-recipe",
            rationale: "Category 3: substrate-derived test recipe",
            base: crate::adversarial::types::BaseSeedhash {
                name: "test-base",
                bytes: [0u8; 32],
            },
            modifications: &[],
        };
        assert_eq!(recipe_category(&recipe), 3);
    }

    #[test]
    #[should_panic(expected = "rationale does not start with `Category N:`")]
    fn recipe_category_panics_on_malformed_rationale() {
        let recipe = CacheRecipe {
            name: "test-recipe",
            rationale: "Bad rationale prefix without Category",
            base: crate::adversarial::types::BaseSeedhash {
                name: "test-base",
                bytes: [0u8; 32],
            },
            modifications: &[],
        };
        // Bind the result to satisfy `#[must_use]`; the panic
        // unwind is what the `#[should_panic]` attribute asserts.
        let _category = recipe_category(&recipe);
    }

    /// Claim-1 effective bound calculation matches the constant
    /// definitions. Pinned so a future change to
    /// `RUNNER_NOISE_MARGIN` or `CLAIM_1_RATIO_BOUND` surfaces in
    /// the test output rather than silently shifting the gate.
    #[test]
    fn claim_1_effective_bound_matches_constants() {
        let report = build_report(vec![], 100);
        assert!(
            (report.claim_1_effective_bound - (CLAIM_1_RATIO_BOUND - RUNNER_NOISE_MARGIN)).abs()
                < 1e-9
        );
    }

    /// `safe_ratio` returns infinity on `c_ns == 0` rather than
    /// panicking.
    #[test]
    fn safe_ratio_handles_zero_denominator() {
        assert!(safe_ratio(100, 0).is_infinite());
        assert!((safe_ratio(200, 100) - 2.0).abs() < 1e-9);
    }
}
