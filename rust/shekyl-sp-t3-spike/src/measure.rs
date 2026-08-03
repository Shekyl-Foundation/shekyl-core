// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! D6 — the PD-F-2 statistics: **deadline-agnostic, and inverted.**
//!
//! # Why this does not report a pass rate
//!
//! `CHALLENGE_RESOLUTION_BLOCKS = 10_000` is the **pre-TJ** value
//! (`shekyl_archival_retention::constants`), and §8.3 says explicitly that
//! *"TJ-C's deadline is a dependency, not this round's answer."* Measuring
//! pass/fail against 10 000 blocks would return a trivial "not forceable" and
//! answer nothing — at ~2 min/block that deadline is over a week, and every fetch
//! passes.
//!
//! So the harness reports the **distribution**, and inverts it:
//!
//! > for deadline `D`, the failure probability is `q(D)`;
//! > `q(D) ≥ q*` holds for all `D ≤ D*`.
//!
//! [`Summary::d_star`] is that `D*` — the deliverable TJ-C can use directly:
//! *the deadline must be at or below `D*` for the sampling branch to stay live.*
//!
//! # The inversion, stated precisely
//!
//! `q(D)` is the empirical probability a fetch fails to complete within `D`:
//! outright failures always count as failures, and successes count as failures
//! when slower than `D`. `q` is therefore non-increasing in `D`, so
//! `{D : q(D) ≥ q*}` is a down-set and `D* = sup` of it.
//!
//! Concretely, with `n` observations of which `f` failed outright: the largest
//! `D` with `q(D) ≥ q*` is the `k`-th smallest **success** latency, where `k` is
//! chosen so that (successes slower than `D`) + `f` still reaches `⌈q*·n⌉`. If
//! `f/n ≥ q*` already, every deadline qualifies and `D*` is unbounded — reported
//! as [`DStar::Unbounded`] rather than as a large number, because "the failure
//! floor alone exceeds the threshold" is a categorically different finding from
//! "slow fetches push it over."
//!
//! # Aggregates only
//!
//! §6.4 forbids per-request logs and any timestamp that could correlate to a
//! circuit. [`Summary`] holds counts, percentiles and a coarse CDF; the harness
//! never persists an observation's wall-clock time, its ordinal, or its persona.
//! [`Observation`] itself carries no timestamp — only a duration and an outcome —
//! so there is nothing to leak even in memory.

use std::time::Duration;

/// The §6.2 threshold the inversion is taken against: `q_risk* = 0.1011`
/// (`ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md` §6.2, the reward-forfeit figure the
/// `q ≥ 0.10` gate rounds).
///
/// Carried as the precise value rather than 0.10 because the gate's own wording
/// is *"the threshold comes from `q_risk* = 0.1011`"* — rounding it here would
/// quietly move the answer.
pub const Q_RISK_STAR: f64 = 0.1011;

/// Why a fetch did not deliver a shard. The taxonomy §6.4 asks for.
///
/// Kept coarse on purpose: a finer split would need per-request detail that §6.4
/// forbids retaining, and these four are what distinguish "Tor was slow" from
/// "the apparatus broke", which is the distinction the verdict turns on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// The request exceeded the harness's own ceiling without completing.
    Timeout,
    /// The circuit or rendezvous could not be established.
    Circuit,
    /// A response arrived but was short or malformed — the apparatus-failure
    /// signal (a truncated shard is not a slow shard).
    Truncated,
    /// Anything else below HTTP: connect, proxy, IO.
    Transport,
}

/// One timed fetch. **No timestamp, no persona, no circuit id** — see the module
/// doc; there is deliberately nothing here to correlate.
#[derive(Debug, Clone, Copy)]
pub struct Observation {
    /// Request initiation → last byte received.
    pub elapsed: Duration,
    /// `None` on success; the failure class otherwise.
    pub failure: Option<FailureKind>,
}

impl Observation {
    /// A completed fetch.
    #[must_use]
    pub fn success(elapsed: Duration) -> Self {
        Self {
            elapsed,
            failure: None,
        }
    }

    /// A fetch that did not deliver, with the time spent before giving up.
    #[must_use]
    pub fn failure(elapsed: Duration, kind: FailureKind) -> Self {
        Self {
            elapsed,
            failure: Some(kind),
        }
    }

    /// Whether this fetch delivered a shard.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.failure.is_none()
    }
}

/// The largest deadline at which the failure probability still reaches the
/// threshold.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DStar {
    /// `q(D) ≥ q*` for every finite `D`: the outright-failure rate alone already
    /// meets the threshold, so no deadline makes the branch safe. A far stronger
    /// (and more alarming) result than a large finite `D*`.
    Unbounded,
    /// `q(D) ≥ q*` exactly for `D ≤` this value.
    At(Duration),
    /// `q(D) < q*` even at `D = 0`, which can only happen when the sample is
    /// empty. Reported rather than silently treated as zero.
    Undefined,
}

/// Aggregate statistics for one measurement arm.
#[derive(Debug, Clone)]
pub struct Summary {
    /// Observations in the arm.
    pub n: usize,
    /// Fetches that delivered a shard.
    pub successes: usize,
    /// Outright failures, by class.
    pub failures: Vec<(FailureKind, usize)>,
    /// Success-latency percentiles: (percentile, value). Empty if no successes.
    pub percentiles: Vec<(u8, Duration)>,
    /// The inverted gate answer.
    pub d_star: DStar,
}

impl Summary {
    /// Completion rate — successes over all attempts.
    #[must_use]
    pub fn completion_rate(&self) -> f64 {
        ratio(self.successes, self.n)
    }
}

/// The empirical failure probability at deadline `d`.
///
/// An outright failure counts as a failure at every deadline; a success counts as
/// a failure when it took longer than `d`. Returns 0.0 for an empty sample (there
/// is no evidence of failure, which the caller must not read as evidence of
/// success — [`summarize`] reports `n` alongside).
#[must_use]
pub fn q_at(observations: &[Observation], d: Duration) -> f64 {
    if observations.is_empty() {
        return 0.0;
    }
    let failed = observations
        .iter()
        .filter(|o| o.failure.is_some() || o.elapsed > d)
        .count();
    ratio(failed, observations.len())
}

/// `numer / denom` as a ratio, without a lossy `usize as f64` cast.
///
/// Observation counts are in the thousands — an arm large enough to overflow
/// `u32` would be a different kind of problem entirely — so narrowing to `u32`
/// and using the lossless `f64::from` is exact here. Written as a helper rather
/// than silenced with an `allow(clippy::cast_precision_loss)`, because the lint
/// is asking a real question (is this conversion exact?) and the answer belongs
/// in one place with its reasoning.
fn ratio(numer: usize, denom: usize) -> f64 {
    if denom == 0 {
        return 0.0;
    }
    let n = u32::try_from(numer).unwrap_or(u32::MAX);
    let d = u32::try_from(denom).unwrap_or(u32::MAX);
    f64::from(n) / f64::from(d)
}

/// Invert `q` to find `D*`: the largest deadline with `q(D) ≥ q_star`.
///
/// Because `q` is a step function that only changes at observed success
/// latencies, the supremum is attained at one of them — so the search is over the
/// sorted success times rather than over a continuum, and the answer is exact for
/// the sample rather than a bisection's approximation.
#[must_use]
pub fn invert(observations: &[Observation], q_star: f64) -> DStar {
    let n = observations.len();
    if n == 0 {
        return DStar::Undefined;
    }
    let outright = observations.iter().filter(|o| o.failure.is_some()).count();
    // The failure floor alone meets the threshold: no deadline, however generous,
    // brings q below q*.
    if ratio(outright, n) >= q_star {
        return DStar::Unbounded;
    }
    let mut successes: Vec<Duration> = observations
        .iter()
        .filter(|o| o.is_success())
        .map(|o| o.elapsed)
        .collect();
    successes.sort_unstable();

    // Walk deadlines from the largest observed latency downward; the first
    // candidate whose q reaches q* is the supremum of the down-set.
    for &candidate in successes.iter().rev() {
        if q_at(observations, candidate) >= q_star {
            return DStar::At(candidate);
        }
    }
    // Even a zero deadline does not reach q* — only reachable when the sample has
    // no failures at all and q* > 0, i.e. q(0) = (successes slower than 0)/n = 1.
    // That means q(0) = 1 ≥ q*, so this branch is unreachable for q* ≤ 1; it is
    // kept as an explicit `Undefined` rather than an `unreachable!` because a
    // caller passing q* > 1 should get an answer, not a panic.
    DStar::Undefined
}

/// The percentile of a sorted slice by nearest-rank (the conservative choice for
/// a tail statistic: it returns an *observed* value, never an interpolation
/// between two, so a reported p90 is a latency that actually happened).
fn nearest_rank(sorted: &[Duration], p: u8) -> Option<Duration> {
    if sorted.is_empty() {
        return None;
    }
    // ceil(p * len / 100) in integer arithmetic — exact, and it removes the
    // float round-trip a percentile index has no business needing.
    let rank = (usize::from(p) * sorted.len()).div_ceil(100);
    let idx = rank.saturating_sub(1).min(sorted.len() - 1);
    Some(sorted[idx])
}

/// A within-arm warm-up check: median success latency of the arm's **first**
/// quarter against its **last** quarter.
///
/// # Why this exists — the cold arm might not be cold
///
/// The cold/warm split rests on distinct SOCKS usernames getting distinct
/// circuits (`IsolateSOCKSAuth`), which controls the **client** side. It does
/// *not* control the **service** side: a client that has already fetched a
/// persona's descriptor may have it cached, and tor may reuse service-side
/// rendezvous machinery across successive fetches to the *same* persona. The
/// cold arm varies the client id but hits one persona throughout, so fetch #150
/// can be paying a materially smaller setup cost than fetch #1 while both are
/// labelled "cold".
///
/// **The bias is directional and unsafe.** If later cold fetches are faster, the
/// arm's tail is optimistic, which pushes `D*` *up* — handing TJ-C a more
/// generous deadline than reality supports. A consensus safety margin must not
/// be derived from a distribution that quietly improved as it was measured.
///
/// # Why it returns two numbers and not an ordering
///
/// §6.4 forbids retaining per-request ordering, so this is computed **in memory
/// during the run** and only the two medians are reported. That is enough to
/// answer "did it drift?" without persisting anything that could place a fetch
/// in a sequence.
///
/// Returns `None` when either quarter has no successes to compare.
#[must_use]
pub fn warmup_drift(observations: &[Observation]) -> Option<(Duration, Duration)> {
    // A quarter of the arm at each end; below 8 observations the quarters are too
    // small for the comparison to mean anything, so it is declined rather than
    // reported as noise.
    if observations.len() < 8 {
        return None;
    }
    let q = observations.len() / 4;
    let median_of = |slice: &[Observation]| -> Option<Duration> {
        let mut v: Vec<Duration> = slice
            .iter()
            .filter(|o| o.is_success())
            .map(|o| o.elapsed)
            .collect();
        v.sort_unstable();
        nearest_rank(&v, 50)
    };
    let first = median_of(&observations[..q])?;
    let last = median_of(&observations[observations.len() - q..])?;
    Some((first, last))
}

/// Summarize one arm.
#[must_use]
pub fn summarize(observations: &[Observation]) -> Summary {
    let mut successes: Vec<Duration> = observations
        .iter()
        .filter(|o| o.is_success())
        .map(|o| o.elapsed)
        .collect();
    successes.sort_unstable();

    let mut failures: Vec<(FailureKind, usize)> = Vec::new();
    for kind in [
        FailureKind::Timeout,
        FailureKind::Circuit,
        FailureKind::Truncated,
        FailureKind::Transport,
    ] {
        let c = observations
            .iter()
            .filter(|o| o.failure == Some(kind))
            .count();
        if c > 0 {
            failures.push((kind, c));
        }
    }

    let percentiles = [50u8, 75, 90, 95, 99]
        .iter()
        .filter_map(|&p| nearest_rank(&successes, p).map(|v| (p, v)))
        .collect();

    Summary {
        n: observations.len(),
        successes: successes.len(),
        failures,
        percentiles,
        d_star: invert(observations, Q_RISK_STAR),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    /// `n` successes with the given second-latencies.
    fn oks(v: &[u64]) -> Vec<Observation> {
        v.iter().map(|&s| Observation::success(secs(s))).collect()
    }

    #[test]
    fn q_is_non_increasing_in_the_deadline() {
        // The property the inversion rests on. Asserted rather than assumed
        // because if q were not monotone, "the largest D with q(D) >= q*" would
        // not be well-defined and D* would be meaningless.
        let obs = oks(&[1, 2, 3, 5, 8, 13]);
        let mut prev = 1.0;
        for d in 0..20u64 {
            let q = q_at(&obs, secs(d));
            assert!(q <= prev + f64::EPSILON, "q rose at D={d}");
            prev = q;
        }
        assert!(
            (q_at(&obs, secs(0)) - 1.0).abs() < f64::EPSILON,
            "no fetch beats a zero deadline"
        );
        assert!(
            q_at(&obs, secs(100)).abs() < f64::EPSILON,
            "all beat a generous deadline"
        );
    }

    #[test]
    fn outright_failures_count_at_every_deadline() {
        // A failed fetch is a failure no matter how generous the deadline — the
        // distinction between "slow" and "never" that a pure latency percentile
        // would erase.
        let mut obs = oks(&[1, 1, 1]);
        obs.push(Observation::failure(secs(999), FailureKind::Circuit));
        assert!((q_at(&obs, secs(10_000)) - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn d_star_is_the_largest_deadline_whose_tail_still_reaches_the_threshold() {
        // 20 observations: 17 at 5 s, then 25, 30, 40. Walking deadlines down:
        //
        //   q(40) = 0/20  = 0.00
        //   q(30) = 1/20  = 0.05   < 0.1011
        //   q(25) = 2/20  = 0.10   < 0.1011   <- the near miss that matters
        //   q(5)  = 3/20  = 0.15  >= 0.1011   <- first to reach it
        //
        // So D* = 5 s. The 25 s step is the point of this fixture: 0.10 is *not*
        // >= 0.1011, and a threshold sloppily rounded to 0.10 would stop there and
        // report D* = 25 s -- a five-fold overstatement of how generous TJ-C's
        // deadline could be. Pinning both the verdict and the exact q(25) keeps
        // that rounding from creeping back in.
        let mut v: Vec<u64> = vec![5; 17];
        v.extend_from_slice(&[25, 30, 40]);
        let obs = oks(&v);
        assert_eq!(obs.len(), 20);
        assert!((q_at(&obs, secs(25)) - 0.10).abs() < 1e-12);
        assert!(q_at(&obs, secs(25)) < Q_RISK_STAR, "0.10 is not >= 0.1011");
        assert!(q_at(&obs, secs(5)) >= Q_RISK_STAR);
        assert_eq!(invert(&obs, Q_RISK_STAR), DStar::At(secs(5)));
    }

    #[test]
    fn a_failure_floor_above_the_threshold_is_unbounded_not_a_big_number() {
        // 2 outright failures in 10 => 0.20 >= 0.1011 before any deadline is
        // considered. Reporting a large finite D* here would suggest a generous
        // deadline fixes it; it does not, and the type says so.
        let mut obs = oks(&[1; 8]);
        obs.push(Observation::failure(secs(60), FailureKind::Timeout));
        obs.push(Observation::failure(secs(60), FailureKind::Transport));
        assert_eq!(invert(&obs, Q_RISK_STAR), DStar::Unbounded);
    }

    #[test]
    fn an_empty_sample_is_undefined_not_zero() {
        // Guards the vacuous read: "no failures observed" out of zero attempts is
        // not evidence of a low q.
        assert_eq!(invert(&[], Q_RISK_STAR), DStar::Undefined);
        assert!(q_at(&[], secs(1)).abs() < f64::EPSILON);
        let s = summarize(&[]);
        assert_eq!(s.n, 0);
        assert!(s.completion_rate().abs() < f64::EPSILON);
        assert!(s.percentiles.is_empty());
    }

    #[test]
    fn percentiles_are_observed_values_by_nearest_rank() {
        // Nearest-rank, not interpolation: a reported p90 must be a latency that
        // actually occurred, so the tail figure cannot be an artefact of averaging
        // across a gap.
        let sorted: Vec<Duration> = (1..=10).map(secs).collect();
        assert_eq!(nearest_rank(&sorted, 50), Some(secs(5)));
        assert_eq!(nearest_rank(&sorted, 90), Some(secs(9)));
        assert_eq!(nearest_rank(&sorted, 99), Some(secs(10)));
        assert_eq!(nearest_rank(&[], 50), None);
    }

    #[test]
    fn warmup_drift_detects_an_arm_that_got_faster_as_it_ran() {
        // The unsafe case: a "cold" arm whose later fetches are systematically
        // faster because descriptor/rendezvous state warmed. Left undetected this
        // makes the tail optimistic and pushes D* up.
        let mut v: Vec<u64> = vec![40; 10]; // first quarter slow
        v.extend(vec![20; 20]); // middle
        v.extend(vec![5; 10]); // last quarter fast
        let (first, last) = warmup_drift(&oks(&v)).expect("both quarters have successes");
        assert!(
            first > last,
            "a warming arm must show first-quarter median above last-quarter"
        );
        assert_eq!(first, secs(40));
        assert_eq!(last, secs(5));
    }

    #[test]
    fn warmup_drift_is_flat_for_a_genuinely_cold_arm() {
        // The control: a stationary arm must not read as drifting, or the check
        // would cry wolf on every run and get ignored.
        let obs = oks(&[10, 12, 9, 11, 10, 13, 9, 10, 11, 12, 10, 9, 11, 10, 12, 10]);
        let (first, last) = warmup_drift(&obs).expect("both quarters have successes");
        let delta = first.abs_diff(last);
        assert!(delta < secs(4), "stationary arm drifted by {delta:?}");
    }

    #[test]
    fn warmup_drift_declines_when_there_is_nothing_to_compare() {
        // Too few observations, and an arm whose quarters hold no successes: both
        // decline rather than reporting a meaningless number.
        assert_eq!(warmup_drift(&oks(&[1, 2, 3])), None);
        let all_failed: Vec<Observation> = (0..16)
            .map(|_| Observation::failure(secs(1), FailureKind::Circuit))
            .collect();
        assert_eq!(warmup_drift(&all_failed), None);
    }

    #[test]
    fn summary_reports_the_failure_taxonomy_and_completion_rate() {
        let mut obs = oks(&[2, 4, 6]);
        obs.push(Observation::failure(secs(9), FailureKind::Truncated));
        let s = summarize(&obs);
        assert_eq!(s.n, 4);
        assert_eq!(s.successes, 3);
        assert_eq!(s.failures, vec![(FailureKind::Truncated, 1)]);
        assert!((s.completion_rate() - 0.75).abs() < 1e-12);
        // A truncated response is an apparatus failure, and it must not be able to
        // masquerade as a fast success in the percentiles.
        assert_eq!(s.percentiles[0], (50, secs(4)));
    }
}
