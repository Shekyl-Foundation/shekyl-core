// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `--mode=latency` orchestrator (§5.1.12, T5, R1-D7).
//!
//! Per `docs/design/RANDOMX_V2_PHASE2G_PLAN.md` §5.1.12 + R1-D7's
//! Round 1 disposition, this module measures the per-hash latency
//! of the Rust verifier against the C reference using
//! **interleaved Rust/C per-iteration timing**: each iteration
//! computes one hash on each side back-to-back so that any
//! CPU-cache-warmth bias amortizes symmetrically across the two
//! implementations (rather than favoring whichever side runs after
//! the other has warmed the cache).
//!
//! ## Methodology (R1-D7 Round 1 disposition)
//!
//! - **Single fixed seedhash.** The seedhash is the first nightly
//!   seedhash from [`crate::corpus_random::generate_latency_data`],
//!   byte-identical to `generate_random_corpus(1, 1)[0].seedhash`.
//!   Pinning the seedhash to a single value isolates the per-hash
//!   compute path from per-seedhash cache-derivation cost (which
//!   pays once and is excluded from the per-iteration measurement).
//! - **N=1024 deterministic data values per side (default).** The
//!   data values come from a single ChaCha20 stream seeded with
//!   [`crate::corpus_random::RANDOM_CORPUS_SEED_V1`] (per R1-D7's
//!   "sub-sample of the per-PR corpus per R1-D4's ChaCha20Rng-seeded
//!   shape"); operator can override via `--samples=<u32>`.
//! - **Interleaved per-iteration timing.** For each iteration, the
//!   harness alternates which side runs first (even iterations:
//!   Rust then C; odd iterations: C then Rust). The alternation
//!   neutralizes any "second-to-run wins" bias from CPU /
//!   instruction-cache warmth.
//! - **`black_box` discipline.** Both the data input and the hash
//!   output are passed through [`std::hint::black_box`] so the
//!   compiler cannot elide the per-iteration work or hoist it out
//!   of the measurement loop.
//! - **`Instant::now` measurement.** Per-iteration wall-clock cost
//!   is captured via [`std::time::Instant::now`] before and after
//!   each hash; the difference is recorded as nanoseconds via
//!   [`std::time::Duration::as_nanos`] downcast to `u64` (per-hash
//!   wall-clock fits `u64` ns for any realistic measurement —
//!   `u64::MAX / 1e9 ≈ 584 years`).
//!
//! ## T5 assertion (≤ 3.0× ratio)
//!
//! Per R1-D7's "median(Rust per-hash wall-clock) / median(C
//! per-hash wall-clock) ≤ 3.0×" close + parent §6 line 237's "≤
//! 3.0× on the cache mode daemons actually run in" budget, this
//! module computes the **median** Rust per-hash latency and the
//! **median** C per-hash latency and asserts the ratio. The
//! median (rather than mean) is used per R1-D7's explicit pin
//! ("parent plan §6 line 243 names median"), which is robust to
//! outliers from OS-level pre-emption or one-off CPU-cache miss
//! spikes that would skew a mean.
//!
//! Per §6.2 T5, the report also surfaces **p95** and **max** for
//! each side; these are informational at 2g (no assertion) and
//! land in [`LatencyReport`] for the C9 BENCH_RESULTS.md emission
//! and the structured-JSON failure schema.
//!
//! ## Failure surfacing
//!
//! At C7 the failure path emits a human-readable diagnostic via
//! [`std::fmt::Display`] (matched against `cargo test` failure
//! output) and exits non-zero through `main.rs`'s `ExitCode`. The
//! §5.1.14 structured-JSON failure schema lands at C9; this
//! module's [`LatencyError`] carries the measured statistics so
//! the C9 schema can populate without re-running.
//!
//! ## Cadence
//!
//! Per R1-D12 (c) + R1-D7's "no per-PR CI gate at 2g; activates at
//! Phase 3a", this mode runs in the **nightly** workflow (and
//! optionally the release-gate workflow) but not in the per-PR
//! workflow. The §6.2 T5 entry pins the cadence as "nightly +
//! release-gate".

use std::cmp::Ordering;
use std::fmt;
use std::hint::black_box;
use std::time::Instant;

use crate::c_oracle::{COracleError, COracleSession};
use crate::cache_precondition::{assert_equivalent, PreconditionMismatch};
use crate::corpus_random::generate_latency_data;
use crate::rust_subject::RustSubjectSession;

/// Latency-ratio budget per R1-D7 + parent §6 line 237.
///
/// Pinned as a constant here so the assertion is centralized;
/// changing the budget requires a plan-doc round per §5.7's
/// drift-prevention discipline. Encoded as `f64` because the
/// ratio is `median_rust_ns / median_c_ns`, an `f64` quotient.
pub const LATENCY_RATIO_BUDGET: f64 = 3.0;

/// Successful run summary surfaced on the stdout report path
/// (plus consumed at C9 to populate the BENCH_RESULTS.md row per
/// §6.2 T5).
#[derive(Debug, Clone, PartialEq)]
pub struct LatencyReport {
    /// Number of `(rust, c)` hash pairs measured. Equals the
    /// CLI `--samples=<N>` flag value (default 1024 per R1-D7 §F2).
    pub samples: usize,
    /// Rust verifier's median per-hash wall-clock (nanoseconds).
    pub rust_median_ns: u64,
    /// Rust verifier's p95 per-hash wall-clock (nanoseconds).
    pub rust_p95_ns: u64,
    /// Rust verifier's max per-hash wall-clock (nanoseconds).
    pub rust_max_ns: u64,
    /// C reference's median per-hash wall-clock (nanoseconds).
    pub c_median_ns: u64,
    /// C reference's p95 per-hash wall-clock (nanoseconds).
    pub c_p95_ns: u64,
    /// C reference's max per-hash wall-clock (nanoseconds).
    pub c_max_ns: u64,
    /// `rust_median_ns / c_median_ns`; passes when
    /// `≤ LATENCY_RATIO_BUDGET` (3.0).
    pub ratio: f64,
}

impl fmt::Display for LatencyReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "latency mode (N={}):", self.samples)?;
        writeln!(
            f,
            "  Rust median={} ns, p95={} ns, max={} ns",
            self.rust_median_ns, self.rust_p95_ns, self.rust_max_ns
        )?;
        writeln!(
            f,
            "  C    median={} ns, p95={} ns, max={} ns",
            self.c_median_ns, self.c_p95_ns, self.c_max_ns
        )?;
        write!(
            f,
            "  ratio (rust/c) = {:.3}x (budget: ≤{:.1}x)",
            self.ratio, LATENCY_RATIO_BUDGET
        )
    }
}

/// All failure modes the latency orchestrator can surface.
#[derive(Debug)]
pub enum LatencyError {
    /// C oracle resource allocation failed.
    COracle(COracleError),
    /// R1-D14 cache-equivalence precondition failed. Latency
    /// measurements against a divergent cache are meaningless —
    /// the per-hash cost on a divergent cache would not reflect
    /// the spec-faithful path.
    Precondition(PreconditionMismatch),
    /// `samples == 0`: latency mode requires at least one
    /// iteration. Surfaced at parse-time normally; here as a
    /// belt-and-braces check.
    ZeroSamples,
    /// T5: ratio exceeded [`LATENCY_RATIO_BUDGET`]. Carries the
    /// full [`LatencyReport`] for diagnostics; the C9 JSON schema
    /// serializes it without re-running.
    RatioBudgetExceeded { report: LatencyReport },
}

impl fmt::Display for LatencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::COracle(e) => write!(f, "c-oracle setup failed: {e}"),
            Self::Precondition(e) => write!(f, "{e}"),
            Self::ZeroSamples => write!(f, "latency mode requires --samples >= 1; got 0"),
            Self::RatioBudgetExceeded { report } => write!(
                f,
                "latency budget exceeded: ratio {:.3}x > {:.1}x\n{}",
                report.ratio, LATENCY_RATIO_BUDGET, report
            ),
        }
    }
}

impl std::error::Error for LatencyError {}

impl From<COracleError> for LatencyError {
    fn from(e: COracleError) -> Self {
        Self::COracle(e)
    }
}

/// Run `--mode=latency` per §5.1.12 + R1-D7.
///
/// Measures per-hash Rust/C latency over `samples` iterations with
/// the R1-D7 interleaved methodology and asserts
/// `median_rust / median_c ≤ LATENCY_RATIO_BUDGET`. Returns the
/// full [`LatencyReport`] on success; the [`LatencyError`] surfaces
/// the first failure mode encountered.
///
/// # Errors
///
/// - [`LatencyError::ZeroSamples`] if `samples == 0`.
/// - [`LatencyError::COracle`] on C-side allocation failure.
/// - [`LatencyError::Precondition`] if R1-D14 cache equivalence
///   fails.
/// - [`LatencyError::RatioBudgetExceeded`] if the T5 ratio gate
///   fails.
pub fn run(samples: usize) -> Result<LatencyReport, LatencyError> {
    if samples == 0 {
        return Err(LatencyError::ZeroSamples);
    }

    let (seedhash, data_values) = generate_latency_data(samples);
    debug_assert_eq!(data_values.len(), samples);

    let rust = RustSubjectSession::derive(seedhash);
    let c = COracleSession::new(seedhash)?;

    // R1-D14 precondition. Latency measurements against a
    // divergent cache would not reflect the spec-faithful path
    // and could under-/over-state the ratio in either direction.
    if let Err(mismatch) = assert_equivalent(&rust, &c) {
        return Err(LatencyError::Precondition(mismatch));
    }

    let mut rust_samples_ns: Vec<u64> = Vec::with_capacity(samples);
    let mut c_samples_ns: Vec<u64> = Vec::with_capacity(samples);

    for (i, data) in data_values.iter().enumerate() {
        // Per R1-D7's "interleaved Rust/C per-iteration" + the
        // "alternate which side runs first" symmetry: even
        // iterations run Rust then C, odd iterations run C then
        // Rust. Each side's i-th sample is captured into its
        // own Vec; subsequent statistics treat the two streams
        // as independent populations of N each.
        if i % 2 == 0 {
            let (rust_ns, _rust_hash) = time_rust(&rust, data);
            let (c_ns, _c_hash) = time_c(&c, data);
            rust_samples_ns.push(rust_ns);
            c_samples_ns.push(c_ns);
        } else {
            let (c_ns, _c_hash) = time_c(&c, data);
            let (rust_ns, _rust_hash) = time_rust(&rust, data);
            rust_samples_ns.push(rust_ns);
            c_samples_ns.push(c_ns);
        }
    }

    let (rust_median_ns, rust_p95_ns, rust_max_ns) = median_p95_max(&mut rust_samples_ns);
    let (c_median_ns, c_p95_ns, c_max_ns) = median_p95_max(&mut c_samples_ns);

    // `c_median_ns == 0` is unreachable on real hardware (one
    // RandomX hash is >100 µs even in the fastest configuration)
    // but is defended against here as a belt-and-braces invariant.
    // A zero C median would make the ratio undefined; surface a
    // budget-exceeded error rather than a divide-by-zero panic.
    //
    // The `u64 → f64` precision-loss lint is acknowledged and
    // allowed for the ratio computation: f64's 52-bit mantissa
    // covers nanosecond counts up to ~2^52 ns ≈ 52 days, which is
    // ~10 orders of magnitude beyond any realistic per-hash
    // measurement (a 100 µs hash is 10^5 ns; f64 holds up to
    // 4.5×10^15 ns exactly). Per-hash precision loss is
    // unreachable in this measurement domain.
    #[allow(clippy::cast_precision_loss)]
    let ratio = if c_median_ns == 0 {
        f64::INFINITY
    } else {
        rust_median_ns as f64 / c_median_ns as f64
    };

    let report = LatencyReport {
        samples,
        rust_median_ns,
        rust_p95_ns,
        rust_max_ns,
        c_median_ns,
        c_p95_ns,
        c_max_ns,
        ratio,
    };

    if ratio > LATENCY_RATIO_BUDGET {
        return Err(LatencyError::RatioBudgetExceeded { report });
    }
    Ok(report)
}

/// Time one Rust-side `compute_hash` invocation. Both the input
/// and the output are passed through `black_box` so the compiler
/// cannot hoist or elide the per-iteration work.
#[inline(never)]
fn time_rust(rust: &RustSubjectSession, data: &[u8]) -> (u64, [u8; 32]) {
    let data = black_box(data);
    let start = Instant::now();
    let hash = rust.compute_hash(data);
    let elapsed = start.elapsed();
    let hash = black_box(hash);
    (duration_to_ns(elapsed), hash)
}

/// Time one C-side `randomx_calculate_hash` invocation. Both the
/// input and the output are passed through `black_box`.
#[inline(never)]
fn time_c(c: &COracleSession, data: &[u8]) -> (u64, [u8; 32]) {
    let data = black_box(data);
    let start = Instant::now();
    let hash = c.calculate_hash(data);
    let elapsed = start.elapsed();
    let hash = black_box(hash);
    (duration_to_ns(elapsed), hash)
}

/// Convert a [`std::time::Duration`] to nanoseconds as `u64`.
///
/// `Duration::as_nanos` returns `u128`; saturating to `u64::MAX`
/// is safe because no realistic per-hash measurement approaches
/// 584 years.
fn duration_to_ns(d: std::time::Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

/// Compute `(median, p95, max)` of a sample slice. Sorts the
/// slice in place; callers that need the original ordering
/// preserved must clone first.
///
/// `median` is the upper-median for even-length samples
/// (`samples[n / 2]`, no interpolation): for `n = 10` the result
/// is `samples[5]`, not `samples[4]`. The upper-median is the
/// integer-percentile convention used by hyperfine/criterion and
/// matches the verifier's existing latency-bench scripts; the
/// `median_p95_max_known_values` test below pins the convention.
/// `p95` is the index `(samples * 95) / 100`, the standard
/// integer-percentile shape. `max` is the last element after
/// sorting.
fn median_p95_max(samples: &mut [u64]) -> (u64, u64, u64) {
    debug_assert!(!samples.is_empty());
    samples.sort_unstable_by(|a, b| a.cmp(b).then(Ordering::Equal));
    let n = samples.len();
    let median = samples[n / 2];
    // Saturating subtraction guards `n = 1` (then p95 = max).
    let p95_idx = ((n.saturating_sub(1)) * 95) / 100;
    let p95 = samples[p95_idx];
    let max = samples[n - 1];
    (median, p95, max)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `median_p95_max` matches hand-computed values for small
    /// samples. Pins the percentile-formula convention.
    #[test]
    fn median_p95_max_known_values() {
        let mut s = vec![10_u64, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        let (median, p95, max) = median_p95_max(&mut s);
        // n=10, median=s[5]=60; p95_idx=(9*95)/100=8; p95=s[8]=90; max=100.
        assert_eq!(median, 60);
        assert_eq!(p95, 90);
        assert_eq!(max, 100);
    }

    /// `median_p95_max` with single-sample input emits the same
    /// value as median, p95, and max (all three collapse).
    #[test]
    fn median_p95_max_single_sample() {
        let mut s = vec![42_u64];
        let (median, p95, max) = median_p95_max(&mut s);
        assert_eq!(median, 42);
        assert_eq!(p95, 42);
        assert_eq!(max, 42);
    }

    /// `median_p95_max` sorts the input in place; callers cannot
    /// rely on the original ordering after the call.
    #[test]
    fn median_p95_max_sorts_in_place() {
        let mut s = vec![50_u64, 10, 30, 20, 40];
        let _ = median_p95_max(&mut s);
        assert_eq!(s, vec![10, 20, 30, 40, 50]);
    }

    /// `LatencyReport`'s `Display` impl emits the sample count,
    /// per-side median/p95/max, and the ratio with the budget.
    #[test]
    fn latency_report_display() {
        let report = LatencyReport {
            samples: 1024,
            rust_median_ns: 600_000,
            rust_p95_ns: 700_000,
            rust_max_ns: 800_000,
            c_median_ns: 300_000,
            c_p95_ns: 350_000,
            c_max_ns: 400_000,
            ratio: 2.0,
        };
        let s = format!("{report}");
        assert!(s.contains("N=1024"), "got: {s}");
        assert!(s.contains("Rust median=600000 ns"), "got: {s}");
        assert!(s.contains("C    median=300000 ns"), "got: {s}");
        assert!(s.contains("2.000x"), "got: {s}");
        assert!(s.contains("≤3.0x"), "got: {s}");
    }

    /// `LatencyError::Display` includes the report on
    /// budget-exceeded.
    #[test]
    fn latency_error_budget_exceeded_display() {
        let report = LatencyReport {
            samples: 4,
            rust_median_ns: 1000,
            rust_p95_ns: 1000,
            rust_max_ns: 1000,
            c_median_ns: 100,
            c_p95_ns: 100,
            c_max_ns: 100,
            ratio: 10.0,
        };
        let err = LatencyError::RatioBudgetExceeded { report };
        let s = format!("{err}");
        assert!(s.contains("latency budget exceeded"), "got: {s}");
        assert!(s.contains("10.000x"), "got: {s}");
        assert!(s.contains("3.0x"), "got: {s}");
    }

    /// `LATENCY_RATIO_BUDGET` is pinned at 3.0× per R1-D7 + parent
    /// §6 line 237.
    #[test]
    fn latency_ratio_budget_pinned() {
        assert!((LATENCY_RATIO_BUDGET - 3.0).abs() < f64::EPSILON);
    }

    /// `duration_to_ns` converts a sub-microsecond duration
    /// faithfully.
    #[test]
    fn duration_to_ns_sub_microsecond() {
        let d = std::time::Duration::from_nanos(123);
        assert_eq!(duration_to_ns(d), 123);
    }

    /// `duration_to_ns` saturates rather than wrapping on
    /// astronomical durations (which can't occur on real hardware
    /// but is a structural invariant).
    #[test]
    fn duration_to_ns_saturates_on_overflow() {
        // u64::MAX nanoseconds ≈ 584 years; pick a duration that
        // is 1000× larger so the conversion has to saturate.
        let huge = std::time::Duration::from_secs(u64::MAX);
        assert_eq!(duration_to_ns(huge), u64::MAX);
    }
}
