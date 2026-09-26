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
/// forbids retaining. Timeout/Circuit/Truncated are the path; Refused is the
/// apparatus — the distinction the void-row rule and the `q` inversion share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// The request exceeded the harness's own ceiling without completing.
    Timeout,
    /// The circuit or rendezvous could not be established, or the connection
    /// closed before any response head — no exchange happened.
    Circuit,
    /// A response head arrived, then the stream broke or closed short of
    /// `content-length`. That is a **transport** failure (not a slow
    /// success): it counts in `q`/`D*`, and it is **not** an `N`-void.
    /// Voiding the row would throw away the width as a circuit-churn
    /// sample because a mid-body RST is Tor. A complete exchange of the
    /// wrong body length is [`Self::Refused`] instead (the apparatus).
    Truncated,
    /// A **completed** exchange the production client refused: the identical
    /// 404, a malformed head or envelope, a countersignature that does not
    /// verify under `P`'s key. `SF-D6` classes every one of these as a miss,
    /// not a stall, and none of them is Tor's doing — a non-zero count here
    /// means the apparatus is wrong (anchor gate, key, fixture), never that
    /// the path was slow.
    Refused,
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
/// The cold arm rests on `SIGNAL NEWNYM` to the **client** tor before each
/// fetch (`harness.rs`, the re-based rig): tor drops its client circuits and
/// its client-side onion-service state, so the next fetch pays descriptor,
/// intro, and rendezvous from nothing. That controls the client side. It does
/// *not* control the **service** side — the persona's tor keeps its intro
/// points and may reuse service-side rendezvous machinery across successive
/// fetches from the *same* client — and it does not control the guards, which
/// `NEWNYM` deliberately keeps. The cold arm hits one persona throughout, so
/// fetch #150 can be paying a materially smaller setup cost than fetch #1
/// while both are labelled "cold". (The first rig's isolation-key mechanism
/// had the same exposure through a shared descriptor cache; the mechanism
/// changed, the check did not.)
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
        FailureKind::Refused,
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

/// `p99` of an arm's successes, if the arm had any.
#[must_use]
pub fn p99(summary: &Summary) -> Option<Duration> {
    summary
        .percentiles
        .iter()
        .find(|(p, _)| *p == 99)
        .map(|(_, d)| *d)
}

/// Below this p99 the `L` note says **drop `L` to 3**.
///
/// Verbatim from the PROVISIONAL note on
/// `archival_attestation_anchor_lag_blocks` in `consensus_constants.json`:
/// *"If p99 fetch-plus-retry lands under two minutes, drop to 3."* Held
/// here as the number the note states, not re-derived from a block
/// interval — the note is in minutes, so the check is in minutes.
pub const L_DROP_BELOW: Duration = Duration::from_secs(120);

/// Above this p99 the `L` note says the answer is **not** to raise `L`.
///
/// *"If it lands over six minutes the answer is NOT to raise L — L would
/// then be absorbing what SF-D6's retry budget should bound; tighten the
/// budget instead."* Same source as [`L_DROP_BELOW`].
pub const L_BUDGET_TOO_GENEROUS_ABOVE: Duration = Duration::from_secs(360);

/// What the cold arm's tail says about the provisional `L = 4`.
///
/// The note's falsifier is *fetch-plus-retry*; this rig makes one attempt
/// per observation (retry is the scheduler's, `SF-D6` / `TJ-D`), so the
/// verdict is over the **single-attempt** p99 and says only what that
/// number can decide. A fetch-plus-retry span is never shorter than its
/// first attempt, so a single-attempt p99 is a **lower bound** on the
/// note's quantity: it can *refute* the "under two minutes" branch and it
/// can *establish* the "over six" branch, but it can never establish that
/// the span stays under six — that needs the retry policy, which is not
/// in this crate. There is deliberately no `Holds` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LVerdict {
    /// p99 under [`L_DROP_BELOW`]: the note's "drop to 3" branch is live,
    /// subject to the retry budget — *necessary*, not sufficient.
    DropToThreeCandidate,
    /// p99 in `[L_DROP_BELOW, L_BUDGET_TOO_GENEROUS_ABOVE]`: the drop branch
    /// is **refuted** (a span that starts at ≥ 2 min cannot end under it);
    /// the six-minute branch is **open** until `SF-D6`'s retry budget is
    /// applied to this tail — [`attempts_within_budget`] is that input.
    DropRefutedBudgetOpen,
    /// p99 over [`L_BUDGET_TOO_GENEROUS_ABOVE`] on a **single** attempt: the
    /// note's "tighten the budget, do not raise `L`" branch — and since no
    /// retry budget can make a single over-budget attempt fit, this is the
    /// one verdict that also questions the fetch itself.
    TightenRetryBudgetNotL,
    /// No successes to take a p99 over.
    Undefined,
}

/// Read the `L` falsifier off an arm.
#[must_use]
pub fn l_verdict(summary: &Summary) -> LVerdict {
    match p99(summary) {
        None => LVerdict::Undefined,
        Some(p) if p < L_DROP_BELOW => LVerdict::DropToThreeCandidate,
        Some(p) if p > L_BUDGET_TOO_GENEROUS_ABOVE => LVerdict::TightenRetryBudgetNotL,
        Some(_) => LVerdict::DropRefutedBudgetOpen,
    }
}

/// How many attempts of this p99 fit under [`L_BUDGET_TOO_GENEROUS_ABOVE`]
/// — the most `SF-D6`'s bounded retry can afford per witness attempt
/// before `L` is absorbing what the budget should bound. `None` when even
/// one does not fit, or there is no p99.
#[must_use]
pub fn attempts_within_budget(summary: &Summary) -> Option<u32> {
    let p = p99(summary)?;
    let fits = L_BUDGET_TOO_GENEROUS_ABOVE.as_secs_f64() / p.as_secs_f64().max(f64::MIN_POSITIVE);
    // A truncating cast is the intent: the number of *whole* attempts.
    let whole = fits.floor();
    (whole >= 1.0).then(|| {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let n = whole.min(f64::from(u32::MAX)) as u32;
        n
    })
}

/// One width of the concurrency sweep: `width` cold fetches in flight at
/// once through the one client tor, to `width` distinct personas.
pub struct SweepPoint {
    /// Fetches in flight.
    pub width: usize,
    /// The observations at that width — every fetch of every round.
    pub observations: Vec<Observation>,
    /// Connections the **serve side** shed at its own in-flight cap while
    /// this width ran (the delta of the endpoints' refusal counters across
    /// the point). Non-zero means the placeholder cap, not the transport,
    /// shaped these observations: the row is **void** as an `N` input and
    /// is reported as such, never quietly folded into the table.
    pub cap_refusals: u64,
}

/// One row of the churn table `SF-D7` reads its upper bound from.
///
/// The table **reports, it does not rule.** Any knee threshold written
/// here — "p99 within 1.5× of width 1" — would be a number this crate
/// invented, which is the shape the `L` note's own falsifier was rewritten
/// to avoid. The ratio and the circuit-failure rate are what a reader
/// compares across widths; the pin is theirs, taken together with the
/// memory term the binary prints beside each row.
#[derive(Debug, Clone, PartialEq)]
pub struct ChurnRow {
    /// Fetches in flight.
    pub width: usize,
    /// Observations at this width.
    pub n: usize,
    /// Success p50, if any.
    pub p50: Option<Duration>,
    /// Success p99, if any.
    pub p99: Option<Duration>,
    /// This width's p99 over width 1's, when both exist.
    pub p99_over_width_1: Option<f64>,
    /// Fraction of observations that failed as `Circuit` — the churn signal
    /// itself: rendezvous circuits that did not come up under load.
    pub circuit_rate: f64,
    /// The inverted gate answer at this width.
    pub d_star: DStar,
    /// Serve-side cap refusals during this width (see
    /// [`SweepPoint::cap_refusals`]). A row with a non-zero count is
    /// **void**: its churn is the placeholder cap's, not Tor's. It stays in
    /// the table so the reader sees *that* it was void rather than a gap,
    /// and it is never the ratio baseline.
    pub cap_refusals: u64,
    /// Observations at this width the **client** refused after a completed
    /// exchange ([`FailureKind::Refused`]: `404`, malformed protocol, bad
    /// countersignature). Any non-zero count is the apparatus being wrong
    /// (this module's own reading of the class), so the row is **void** on
    /// the same footing as a cap-bound one: what it measured was not Tor.
    pub refused: usize,
}

impl ChurnRow {
    /// Whether this row can be read as an `N` input at all: neither the
    /// serve-side cap nor a client refusal touched it. Mid-body
    /// [`FailureKind::Truncated`] observations stay in the row — they are
    /// Tor, and they do not void the width.
    #[must_use]
    pub const fn is_void(&self) -> bool {
        self.cap_refusals != 0 || self.refused != 0
    }
}

/// Summarise a sweep into the churn table, ordered by width.
///
/// The `p99 / p99(width 1)` ratio takes its baseline from the width-1 row
/// only when that row is not void; a cap-bound or refusal-tainted baseline
/// would scale every other row by an apparatus artefact, so the column is
/// left empty instead.
#[must_use]
pub fn churn_table(points: &[SweepPoint]) -> Vec<ChurnRow> {
    let mut rows: Vec<ChurnRow> = points
        .iter()
        .map(|pt| {
            let s = summarize(&pt.observations);
            let count = |kind: FailureKind| {
                s.failures
                    .iter()
                    .find(|(k, _)| *k == kind)
                    .map_or(0, |(_, c)| *c)
            };
            let circuits = count(FailureKind::Circuit);
            let refused = count(FailureKind::Refused);
            ChurnRow {
                width: pt.width,
                n: s.n,
                p50: s
                    .percentiles
                    .iter()
                    .find(|(p, _)| *p == 50)
                    .map(|(_, d)| *d),
                p99: p99(&s),
                p99_over_width_1: None,
                circuit_rate: ratio(circuits, s.n),
                d_star: s.d_star,
                cap_refusals: pt.cap_refusals,
                refused,
            }
        })
        .collect();
    rows.sort_by_key(|r| r.width);
    let baseline = rows
        .iter()
        .find(|r| r.width == 1 && !r.is_void())
        .and_then(|r| r.p99)
        .map(|d| d.as_secs_f64());
    for row in &mut rows {
        row.p99_over_width_1 = match (baseline, row.p99) {
            (Some(b), Some(p)) if b > 0.0 && !row.is_void() => Some(p.as_secs_f64() / b),
            _ => None,
        };
    }
    rows
}

/// Persona indices for one concurrency-sweep round: `width` consecutive
/// slots wrapping from `round`, so every width samples every persona
/// across rounds rather than always taking the prefix `0..width`.
///
/// The recorded W₂ pin used the prefix (`round == 0` start every time).
/// That cannot have hidden churn at the pinned width: width 8 already
/// included every persona. Rotation is so a later `SF-D7` re-derive is
/// not confounded with which serving tors were in the batch.
#[must_use]
pub fn sweep_round_indices(round: usize, width: usize, personas: usize) -> Vec<usize> {
    if personas == 0 || width == 0 {
        return Vec::new();
    }
    let width = width.min(personas);
    (0..width).map(|k| (round + k) % personas).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    #[test]
    fn l_verdict_reads_the_note_s_two_thresholds_off_p99() {
        // 100 successes so nearest-rank p99 is the 99th value.
        let fast: Vec<Observation> = (1..=100).map(|_| Observation::success(secs(30))).collect();
        assert_eq!(l_verdict(&summarize(&fast)), LVerdict::DropToThreeCandidate);
        assert_eq!(attempts_within_budget(&summarize(&fast)), Some(12));

        let mid: Vec<Observation> = (1..=100).map(|_| Observation::success(secs(200))).collect();
        assert_eq!(l_verdict(&summarize(&mid)), LVerdict::DropRefutedBudgetOpen);
        assert_eq!(attempts_within_budget(&summarize(&mid)), Some(1));

        let slow: Vec<Observation> = (1..=100).map(|_| Observation::success(secs(400))).collect();
        assert_eq!(
            l_verdict(&summarize(&slow)),
            LVerdict::TightenRetryBudgetNotL
        );
        assert_eq!(attempts_within_budget(&summarize(&slow)), None);

        let none = [Observation::failure(secs(1), FailureKind::Circuit)];
        assert_eq!(l_verdict(&summarize(&none)), LVerdict::Undefined);
    }

    #[test]
    fn l_verdict_is_exactly_the_note_s_boundaries() {
        // At two minutes the note says nothing about dropping; at six it
        // says nothing about the budget. Both boundaries are inclusive to
        // the open middle, so the verdict never fires on the number the
        // note names.
        let at = |s: u64| {
            summarize(
                &(1..=100)
                    .map(|_| Observation::success(secs(s)))
                    .collect::<Vec<_>>(),
            )
        };
        assert_eq!(l_verdict(&at(120)), LVerdict::DropRefutedBudgetOpen);
        assert_eq!(l_verdict(&at(360)), LVerdict::DropRefutedBudgetOpen);
        assert_eq!(l_verdict(&at(119)), LVerdict::DropToThreeCandidate);
        assert_eq!(l_verdict(&at(361)), LVerdict::TightenRetryBudgetNotL);
    }

    #[test]
    fn churn_table_reports_ratio_and_circuit_rate_without_ruling() {
        let one = SweepPoint {
            width: 1,
            observations: (1..=100).map(|_| Observation::success(secs(10))).collect(),
            cap_refusals: 0,
        };
        let mut four_obs: Vec<Observation> =
            (1..=90).map(|_| Observation::success(secs(25))).collect();
        four_obs.extend((1..=10).map(|_| Observation::failure(secs(60), FailureKind::Circuit)));
        let four = SweepPoint {
            width: 4,
            observations: four_obs,
            cap_refusals: 0,
        };
        // Out of order on purpose: the table sorts by width.
        let rows = churn_table(&[four, one]);
        assert_eq!(rows[0].width, 1);
        assert_eq!(rows[0].p99_over_width_1, Some(1.0));
        assert!((rows[0].circuit_rate - 0.0).abs() < f64::EPSILON);
        assert!(!rows[0].is_void());
        assert_eq!(rows[1].width, 4);
        assert_eq!(rows[1].p99_over_width_1, Some(2.5));
        assert!((rows[1].circuit_rate - 0.10).abs() < 1e-9);
        // No `bound` field, no knee: the row carries the inputs and stops.
    }

    #[test]
    fn a_cap_bound_row_is_void_and_never_the_baseline() {
        // The serve-side cap shed connections at width 1: those circuit
        // failures are the placeholder's, so the row is void, and it must
        // not become the denominator every other row is read against.
        let one = SweepPoint {
            width: 1,
            observations: (1..=100).map(|_| Observation::success(secs(10))).collect(),
            cap_refusals: 3,
        };
        let two = SweepPoint {
            width: 2,
            observations: (1..=100).map(|_| Observation::success(secs(12))).collect(),
            cap_refusals: 0,
        };
        let rows = churn_table(&[one, two]);
        assert!(rows[0].is_void());
        assert_eq!(rows[0].cap_refusals, 3);
        assert_eq!(rows[0].p99_over_width_1, None);
        // Width 2 is clean but has no clean baseline to be read against.
        assert!(!rows[1].is_void());
        assert_eq!(rows[1].p99_over_width_1, None);
        // The void row is still *in* the table — a gap would hide that the
        // cap bound; a flagged row shows it.
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn a_client_refusal_voids_the_row_like_the_cap_does() {
        // One `Refused` observation among 100 at width 2: the apparatus was
        // wrong for at least one exchange, so nothing at that width is a
        // Tor measurement. Width 1 is clean and stays the baseline.
        let one = SweepPoint {
            width: 1,
            observations: (1..=100).map(|_| Observation::success(secs(10))).collect(),
            cap_refusals: 0,
        };
        let mut tainted: Vec<Observation> =
            (1..=99).map(|_| Observation::success(secs(12))).collect();
        tainted.push(Observation::failure(secs(1), FailureKind::Refused));
        let two = SweepPoint {
            width: 2,
            observations: tainted,
            cap_refusals: 0,
        };
        let rows = churn_table(&[one, two]);
        assert!(!rows[0].is_void());
        assert_eq!(rows[0].p99_over_width_1, Some(1.0));
        assert!(rows[1].is_void());
        assert_eq!(rows[1].refused, 1);
        assert_eq!(rows[1].cap_refusals, 0);
        assert_eq!(rows[1].p99_over_width_1, None);
    }

    #[test]
    fn a_truncated_row_is_not_void() {
        // Mid-body RST is Tor. Voiding the width would discard the circuit-
        // churn sample because a body that started is evidence the
        // rendezvous came up. A complete wrong-length body is `Refused`
        // (the apparatus) and voids; this class does not.
        let one = SweepPoint {
            width: 1,
            observations: (1..=100).map(|_| Observation::success(secs(10))).collect(),
            cap_refusals: 0,
        };
        let mut mixed: Vec<Observation> =
            (1..=99).map(|_| Observation::success(secs(12))).collect();
        mixed.push(Observation::failure(secs(1), FailureKind::Truncated));
        let two = SweepPoint {
            width: 2,
            observations: mixed,
            cap_refusals: 0,
        };
        let rows = churn_table(&[one, two]);
        assert!(!rows[1].is_void());
        assert_eq!(rows[1].refused, 0);
        assert_eq!(rows[1].p99_over_width_1, Some(1.2));
    }

    #[test]
    fn sweep_round_indices_rotate_the_start_and_stay_distinct() {
        assert_eq!(sweep_round_indices(0, 1, 8), vec![0]);
        assert_eq!(sweep_round_indices(1, 1, 8), vec![1]);
        assert_eq!(sweep_round_indices(0, 4, 8), vec![0, 1, 2, 3]);
        assert_eq!(sweep_round_indices(1, 4, 8), vec![1, 2, 3, 4]);
        assert_eq!(sweep_round_indices(7, 2, 8), vec![7, 0]);
        assert_eq!(sweep_round_indices(0, 8, 8), (0..8).collect::<Vec<_>>());
        let wrapped = sweep_round_indices(5, 8, 8);
        let mut sorted = wrapped.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..8).collect::<Vec<_>>());
        assert_eq!(
            wrapped.len(),
            wrapped
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
        );
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
        obs.push(Observation::failure(secs(60), FailureKind::Refused));
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
        // A truncated response is a failure, and it must not be able to
        // masquerade as a fast success in the percentiles.
        assert_eq!(s.percentiles[0], (50, secs(4)));
    }
}
