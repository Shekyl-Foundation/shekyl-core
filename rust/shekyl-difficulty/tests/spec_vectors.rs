//! Integration tests against the §8.1 test corpus of
//! `docs/design/DAA_LWMA1.md`.
//!
//! Each vector here is transcribed from the empirical-confirmation
//! step in the Phase 0 pre-flight harness
//! (`tests/phase0/preflight_outofseq.cpp`). The §8.1 pinned outputs
//! were obtained by running the canonical zawy12 `LWMA1_()` (verbatim
//! from `docs/design/refs/zawy12_issue_3_lwma1.md`) and the Shekyl-
//! corrected variant (per
//! `docs/design/refs/shekyl_lwma1_running_max_symmetric_clamp.md`)
//! against each input vector. The Rust implementation must match the
//! Shekyl-corrected output (which equals the canonical output on
//! monotonic inputs and diverges on out-of-sequence inputs — the
//! load-bearing security property the running-max + symmetric-clamp
//! refinement delivers).
//!
//! The seven vectors below are the §8.1 baseline. Additional tests
//! for genesis short-circuit, invalid count, overflow, and the
//! §5.3 step-8 boundary live in `tests/edge_cases.rs`.

use shekyl_difficulty::{lwma1_next, GENESIS_DIFFICULTY, N, N_USIZE, T_SECONDS};

/// Unix-epoch base anchor matching `tests/phase0/preflight_outofseq.cpp`
/// line 114 (`B = 1_700_000_000`). Load-bearing per §8.1: it prevents
/// `u64` underflow at `prev_max_initial = timestamps[0] - T` on the
/// first iteration of §5.3 step 2 (`prev_max_initial = B - T` is well-
/// defined for any `B > T`).
const B: u64 = 1_700_000_000;

/// `avg_D = 1_000_000` per all §8.1 vectors; `cumulative_difficulties[i]
/// = i * AVG_D` (cumulative difficulty grows linearly with chain
/// height).
const AVG_D: u128 = 1_000_000;

/// Build `cumulative_difficulties[0..=N] = i * AVG_D`.
fn cd_window() -> Vec<u128> {
    (0..=N).map(|i| u128::from(i) * AVG_D).collect()
}

/// `chain_height` for §8.1 vectors: window spans heights `0..=N`, so
/// the chain tip is at height `N` and the algorithm computes the
/// difficulty for the next block at height `N+1`.
const CHAIN_HEIGHT: u64 = N;

// (1) Perfectly stable hashrate (§8.1).
// `timestamps[i] = B + i*T` → `next_D = 990_000` (the 1% bias-factor
// residual on deterministic input, rounded by §5.3 step 9; see §8.1
// for the stochastic-vs-deterministic explanation).
#[test]
fn vector_1_perfectly_stable_hashrate() {
    let ts: Vec<u64> = (0..=N).map(|i| B + i * T_SECONDS).collect();
    let cd = cd_window();
    let next_d = lwma1_next(CHAIN_HEIGHT, &ts, &cd).expect("vector 1 must compute");
    assert_eq!(
        next_d, 990_000,
        "DAA_LWMA1.md §8.1 stable-hashrate vector: expected 990_000, \
         got {next_d}"
    );
}

// (2) Sudden 2× hashrate increase (§8.1).
// `timestamps[i] = B + i*(T/2)` → `next_D = 1_980_000`.
#[test]
fn vector_2_sudden_2x_hashrate_increase() {
    let ts: Vec<u64> = (0..=N).map(|i| B + i * (T_SECONDS / 2)).collect();
    let cd = cd_window();
    let next_d = lwma1_next(CHAIN_HEIGHT, &ts, &cd).expect("vector 2 must compute");
    assert_eq!(
        next_d, 1_980_000,
        "DAA_LWMA1.md §8.1 2x-up vector: expected 1_980_000, got {next_d}"
    );
}

// (3) Sudden 2× hashrate decrease (§8.1).
// `timestamps[i] = B + i*(2*T)` → `next_D = 495_000`.
#[test]
fn vector_3_sudden_2x_hashrate_decrease() {
    let ts: Vec<u64> = (0..=N).map(|i| B + i * (2 * T_SECONDS)).collect();
    let cd = cd_window();
    let next_d = lwma1_next(CHAIN_HEIGHT, &ts, &cd).expect("vector 3 must compute");
    assert_eq!(
        next_d, 495_000,
        "DAA_LWMA1.md §8.1 2x-down vector: expected 495_000, got {next_d}"
    );
}

// (4) Solvetime clamp engagement (§8.1).
// Stable for `i ∈ 0..=N-1`, then `ts[N] = ts[N-1] + 100*T`. The
// outlier `solvetime[N] = +100*T` clamps to `+6*T` per §5.3 step 3.
// `next_D = 892_000`.
#[test]
fn vector_4_solvetime_clamp_engagement() {
    let mut ts: Vec<u64> = (0..=N).map(|i| B + i * T_SECONDS).collect();
    ts[N_USIZE] = ts[N_USIZE - 1] + 100 * T_SECONDS;
    let cd = cd_window();
    let next_d = lwma1_next(CHAIN_HEIGHT, &ts, &cd).expect("vector 4 must compute");
    assert_eq!(
        next_d, 892_000,
        "DAA_LWMA1.md §8.1 clamp vector: expected 892_000, got {next_d}"
    );
    // §8.1 secondary assertion: the clamp absorbs the rest of the
    // outlier, so next_D ends below the stable-hashrate reference.
    assert!(
        next_d < 990_000,
        "clamp vector should produce lower difficulty than stable \
         (clamp absorbed part of the outlier)"
    );
}

// (5) Minimum-L floor engagement (§8.1).
// `ts[i] = B + i` (1-second gaps; extreme fast hashrate). Raw L is
// well below the §5.3 step-5 floor `N*N*T/20 = 48_600`, so the floor
// fires. `next_D = 10_000_000` (≈10× stable reference).
#[test]
fn vector_5_minimum_l_floor_engagement() {
    let ts: Vec<u64> = (0..=N).map(|i| B + i).collect();
    let cd = cd_window();
    let next_d = lwma1_next(CHAIN_HEIGHT, &ts, &cd).expect("vector 5 must compute");
    assert_eq!(
        next_d, 10_000_000,
        "DAA_LWMA1.md §8.1 min-L floor vector: expected 10_000_000, \
         got {next_d}"
    );
}

// (6) Out-of-sequence: `ts[N] = B + (N-2)*T` (one period back from
// `ts[N-1]`; coincides with `ts[N-2]` in absolute value). Under
// Shekyl's running-max + symmetric-clamp formulation,
// `solvetime[N] = -T` (within ±6T clamp). `next_D = 1_040_000`.
//
// Canonical LWMA-1 produces `1_010_000` on the same input (its
// `previous_timestamp+1` floor neutralizes the back-step to a +1
// solvetime). The Shekyl/canonical divergence is the load-bearing
// security property per §5.3 step 2.
#[test]
fn vector_6_out_of_sequence_single_back_step() {
    let mut ts: Vec<u64> = (0..=N).map(|i| B + i * T_SECONDS).collect();
    ts[N_USIZE] = B + (N - 2) * T_SECONDS;
    let cd = cd_window();
    let next_d = lwma1_next(CHAIN_HEIGHT, &ts, &cd).expect("vector 6 must compute");
    assert_eq!(
        next_d, 1_040_000,
        "DAA_LWMA1.md §8.1 out-of-sequence vector (Shekyl): expected \
         1_040_000, got {next_d}"
    );
    // §8.1 secondary assertion: Shekyl penalizes the back-step with
    // higher difficulty than the all-monotonic-T reference (denies
    // the attack).
    assert!(
        next_d > 990_000,
        "out-of-sequence must penalize (next_D > stable 990_000); \
         this is the §5.3 step-2 selfish-mine defense."
    );
}

// (7) Selfish-mine attack regression (§8.1; zawy12 issue #24 item
// 14, September 2018 attack class).
// `ts[i] = B + i*T` for `i ∈ 0..=N-2`,
// `ts[N-1] = B + (N-2)*T + 1000*T`  (artificial forward jump),
// `ts[N]   = B + (N-2)*T + T`       (genuine post-attack timestamp).
// Under Shekyl's running-max + symmetric-clamp, the recovery
// iteration's `solvetime[N] = -999*T` clamps to `-6*T`, symmetrically
// cancelling the attacker's +1000*T jump. `next_D = 1_040_000`.
//
// Canonical LWMA-1 produces `911_000` (the attacker's pattern
// drives difficulty DOWN — the attack rewards under canonical).
// Shekyl > canonical for this input is the §5.3 step-2 defense
// in action.
#[test]
fn vector_7_selfish_mine_attack_regression() {
    let mut ts: Vec<u64> = (0..=N).map(|i| B + i * T_SECONDS).collect();
    ts[N_USIZE - 1] = B + (N - 2) * T_SECONDS + 1000 * T_SECONDS;
    ts[N_USIZE] = B + (N - 2) * T_SECONDS + T_SECONDS;
    let cd = cd_window();
    let next_d = lwma1_next(CHAIN_HEIGHT, &ts, &cd).expect("vector 7 must compute");
    assert_eq!(
        next_d, 1_040_000,
        "DAA_LWMA1.md §8.1 selfish-mine vector (Shekyl): expected \
         1_040_000, got {next_d}"
    );
    // §8.1 (b): Shekyl output strictly above stable reference
    // (penalizes the attack rather than rewarding it).
    assert!(
        next_d > 990_000,
        "selfish-mine vector must produce next_D > stable 990_000; \
         this is the September 2018 attack-class defense."
    );
}

// `GENESIS_DIFFICULTY` is consumed below; alias kept for cheap
// import-survives-refactor confidence at grep time.
#[test]
fn genesis_difficulty_is_one_hundred() {
    assert_eq!(GENESIS_DIFFICULTY, 100, "DAA_LWMA1.md §2.6");
}
