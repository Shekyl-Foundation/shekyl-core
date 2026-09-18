//! Edge-case integration tests for `shekyl-difficulty`:
//! - genesis short-circuit (§5.3 step 1)
//! - invalid count (§5.3 step 1 boundary; FFI consensus invariant)
//! - cumulative-difficulty monotonicity violation (Overflow)
//! - §5.3 step-8 overflow guard boundary (both branches exercised)
//! - §5.3 step 2 `solvetime[1] = -T` regression (running-max +
//!   symmetric-clamp formulation correctness on the smallest
//!   possible negative-solvetime input)
//! - timestamp predicates (`is_timestamp_below_ftl`, `is_above_mtp`)

use shekyl_difficulty::{
    is_above_mtp, is_timestamp_below_ftl, lwma1_next, CumulativeDifficulty, Difficulty, Error,
    FTL_SECONDS, GENESIS_DIFFICULTY, MTP_WINDOW_USIZE, N, N_USIZE, T_SECONDS,
};
use shekyl_types::{BlockHeight, Timestamp};

const B: u64 = 1_700_000_000;
const AVG_D: u128 = 1_000_000;

fn h(v: u64) -> BlockHeight {
    BlockHeight::from_raw(v)
}

fn ts(v: u64) -> Timestamp {
    Timestamp::from_raw(v)
}

fn cd(v: u128) -> CumulativeDifficulty {
    CumulativeDifficulty::from_raw(v)
}

fn cd_window() -> Vec<CumulativeDifficulty> {
    (0..=N).map(|i| cd(u128::from(i) * AVG_D)).collect()
}

fn stable_ts() -> Vec<Timestamp> {
    (0..=N).map(|i| ts(B + i * T_SECONDS)).collect()
}

#[test]
fn genesis_short_circuit_returns_genesis_difficulty() {
    // chain_height < N must return GENESIS_DIFFICULTY without
    // inspecting the input vectors. Test the full range
    // `0..=N-1` so an off-by-one in §5.3 step 1's boundary is
    // surfaced.
    for height in 0..N {
        let result = lwma1_next(h(height), &[], &[]);
        assert_eq!(
            result,
            Ok(Difficulty::from_raw(GENESIS_DIFFICULTY)),
            "chain_height = {height} must short-circuit to \
             GENESIS_DIFFICULTY (got {result:?})"
        );
    }
}

#[test]
fn genesis_short_circuit_ignores_inputs() {
    // §5.3 step 1: when chain_height < N, the vectors are not
    // inspected. A non-empty (but consensus-invalid) input must
    // still produce GENESIS_DIFFICULTY.
    let result = lwma1_next(h(0), &[ts(42), ts(43), ts(44)], &[cd(100)]);
    assert_eq!(result, Ok(Difficulty::from_raw(GENESIS_DIFFICULTY)));
}

#[test]
fn invalid_count_when_chain_height_at_boundary() {
    // §5.3 step 1 boundary: chain_height == N is the first non-
    // short-circuit invocation; the window MUST be exactly N+1.
    let timestamps = stable_ts();
    let cumulative = cd_window();
    // Too short: drop one entry from each vector.
    let result = lwma1_next(h(N), &timestamps[..N_USIZE], &cumulative[..N_USIZE]);
    assert_eq!(result, Err(Error::InvalidCount));
    // Too long: extra entry.
    let mut ts_long = timestamps.clone();
    let mut cd_long = cumulative.clone();
    ts_long.push(ts(B + (N + 1) * T_SECONDS));
    cd_long.push(cd(u128::from(N + 1) * AVG_D));
    let result = lwma1_next(h(N), &ts_long, &cd_long);
    assert_eq!(result, Err(Error::InvalidCount));
    // Length mismatch between the two vectors (one correct, one
    // off by one).
    let result = lwma1_next(h(N), &timestamps, &cumulative[..N_USIZE]);
    assert_eq!(result, Err(Error::InvalidCount));
}

#[test]
fn overflow_when_cumulative_difficulty_decreases() {
    // Consensus invariant violation: cum_diff[N] < cum_diff[0]
    // surfaces as Error::Overflow rather than wrapping.
    let timestamps = stable_ts();
    let mut cumulative = cd_window();
    cumulative[0] = cd(u128::MAX / 2);
    cumulative[N_USIZE] = cd(0);
    let result = lwma1_next(h(N), &timestamps, &cumulative);
    assert_eq!(result, Err(Error::Overflow));
}

/// Compute `2_000_000 * N * N * T` (the §5.3 step-8 threshold) with
/// `checked_mul` so a spec amendment that pushes N or T into u128-
/// overflow territory fails this helper with a targeted message
/// rather than silently wrapping and shifting which boundary the
/// step-8 tests actually exercise. Mirrors the impl's discipline in
/// `src/lwma1.rs` step-8 path.
fn step_8_threshold() -> u128 {
    let n = u128::from(N);
    let t = u128::from(T_SECONDS);
    2_000_000u128
        .checked_mul(n)
        .and_then(|x| x.checked_mul(n))
        .and_then(|x| x.checked_mul(t))
        .expect(
            "§5.3 step-8 threshold (2_000_000 * N * N * T) must fit \
             in u128 for the pinned consensus parameters",
        )
}

#[test]
fn step_8_overflow_guard_at_boundary_unguarded_branch() {
    // §5.3 step 8 boundary: the guard fires on `avg_D > threshold`
    // (strict). avg_D == threshold is therefore the largest avg_D
    // that still takes the unguarded branch -- the load-bearing
    // boundary to test, since an off-by-one in the guard predicate
    // would route this here-correct case into the wrong branch.
    let timestamps = stable_ts();
    let threshold = step_8_threshold();
    // avg_D = threshold (exactly at the boundary, unguarded side);
    // cum_diff[N] - cum_diff[0] = N * avg_D. Use `checked_mul` to
    // surface a future spec drift that would overflow rather than
    // silently wrap the cumulative-difficulty series.
    let cumulative: Vec<CumulativeDifficulty> = (0..=N)
        .map(|i| {
            cd(u128::from(i).checked_mul(threshold).expect(
                "cum_diff[i] = i * threshold must fit in u128 \
                 for the pinned consensus parameters",
            ))
        })
        .collect();
    let result = lwma1_next(h(N), &timestamps, &cumulative)
        .expect("step-8 at-boundary (unguarded) must compute");
    // Sanity: result is positive and bounded by a large multiple
    // of the input avg_D (no wraparound).
    assert!(result > Difficulty::ZERO);
    let upper = threshold.checked_mul(10).expect(
        "sanity-check upper bound (10 * threshold) must fit in u128 \
         for the pinned consensus parameters",
    );
    assert!(result < Difficulty::from_raw(upper));
}

#[test]
fn step_8_overflow_guard_just_above_threshold_guarded_branch() {
    // §5.3 step 8 boundary: avg_D = threshold + 1 is the smallest
    // value that crosses into `avg_D > threshold`, taking the
    // guarded (divide-first) branch.
    let timestamps = stable_ts();
    let threshold = step_8_threshold();
    let above = threshold.checked_add(1).expect(
        "threshold + 1 must fit in u128 (threshold << u128::MAX for \
         pinned consensus parameters)",
    );
    // avg_D = threshold + 1; cum_diff[N] - cum_diff[0] = N * (threshold + 1).
    let cumulative: Vec<CumulativeDifficulty> = (0..=N)
        .map(|i| {
            cd(u128::from(i).checked_mul(above).expect(
                "cum_diff[i] = i * (threshold + 1) must fit in u128 \
                 for the pinned consensus parameters",
            ))
        })
        .collect();
    let result = lwma1_next(h(N), &timestamps, &cumulative)
        .expect("step-8 just-above-threshold (guarded) must compute");
    assert!(result > Difficulty::ZERO);
}

#[test]
fn solvetime_one_negative_t_regression() {
    // §5.3 step 2: the smallest negative-solvetime input the
    // running-max formulation can encounter on iter 1 is
    // `timestamps[1] = timestamps[0]` (zero gap). Combined with
    // the `-T` synthetic anchor, this produces `solvetime[1] =
    // 0 - (B - T) = +T` (the running-max IS the -T anchor, no
    // negative solvetime fires on iter 1 except via an attacker-
    // controlled `timestamps[1] < timestamps[0]`).
    //
    // The genuine `solvetime[1] = -T` regression: set
    // `timestamps[1] = timestamps[0] - T`. Then under §5.3 step 2,
    // `prev_max = B - T`, so `solvetime[1] = (B - T) - (B - T) =
    // 0`. To force `solvetime[1] = -T` exactly, set
    // `timestamps[1] = B - 2*T`. Then `solvetime[1] = (B - 2*T) -
    // (B - T) = -T`.
    //
    // Stable for the rest of the window. The test asserts the
    // algorithm computes without overflow and produces a positive
    // result. The exact value is not pinned here (this is a
    // regression test against pre-Round-12 behavior where
    // `solvetime[1]` was incorrectly shifted by +T).
    let mut timestamps = stable_ts();
    timestamps[1] = ts(B - 2 * T_SECONDS);
    // Fill timestamps[2..=N] on the `B + (i-1)*T` shifted-stable
    // schedule. Under this construction the running max behaves as:
    // prev_max[0] = B - T (synthetic anchor), prev_max[1] = B - T
    // (back-step at iter 1 does not advance the max), then climbs
    // monotonically as B + T, B + 2T, ... at iters 2..=N. The
    // resulting solvetime sequence is: -T at iter 1 (the regression
    // target), +2T at iter 2 (recovery jump after the back-step
    // catches up to the synthetic anchor), then +T at iters 3..=N
    // (steady state). All solvetimes are within ±6T so the clamp
    // never engages, isolating the iter-1 negative-solvetime path
    // from any clamp-engagement side effect.
    for (i, slot) in timestamps.iter_mut().enumerate().skip(2) {
        *slot = ts(B + (u64::try_from(i).expect("i fits") - 1) * T_SECONDS);
    }
    let cumulative = cd_window();
    let result =
        lwma1_next(h(N), &timestamps, &cumulative).expect("solvetime[1] = -T must compute");
    assert!(
        result > Difficulty::ZERO,
        "regression must not overflow or zero out"
    );
}

#[test]
fn ftl_predicate_inside_bound() {
    // Just-under and exactly-at the FTL bound both accept.
    assert!(is_timestamp_below_ftl(ts(1_700_000_000), ts(1_700_000_000)));
    assert!(is_timestamp_below_ftl(
        ts(1_700_000_000 + FTL_SECONDS),
        ts(1_700_000_000)
    ));
    // Strict-greater rejects.
    assert!(!is_timestamp_below_ftl(
        ts(1_700_000_000 + FTL_SECONDS + 1),
        ts(1_700_000_000)
    ));
    // Incoming earlier than local clock: unconditionally accepts.
    assert!(is_timestamp_below_ftl(ts(0), ts(1_700_000_000)));
}

#[test]
fn mtp_predicate_strict_above_median() {
    // Median of {1, 2, ..., 11} is 6; incoming must be > 6.
    let window: [Timestamp; MTP_WINDOW_USIZE] =
        core::array::from_fn(|i| ts(u64::try_from(i + 1).expect("11 fits in u64")));
    assert!(is_above_mtp(ts(7), &window));
    assert!(!is_above_mtp(ts(6), &window));
    assert!(!is_above_mtp(ts(0), &window));
    // Median is invariant under permutation; reverse the window.
    let mut reversed = window;
    reversed.reverse();
    assert!(is_above_mtp(ts(7), &reversed));
    assert!(!is_above_mtp(ts(6), &reversed));
}

#[test]
fn mtp_predicate_with_duplicates() {
    // Median is the middle element after sorting (stability does
    // not matter for median selection -- duplicates compare equal,
    // so any ordering among them places the same value at the
    // median index). With duplicates around the median, the
    // predicate still answers correctly.
    let window: [Timestamp; MTP_WINDOW_USIZE] = [ts(5); MTP_WINDOW_USIZE];
    assert!(is_above_mtp(ts(6), &window));
    assert!(!is_above_mtp(ts(5), &window));
    assert!(!is_above_mtp(ts(4), &window));
}
