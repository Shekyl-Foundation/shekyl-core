//! LWMA-1 next-difficulty computation.
//!
//! Direct, verbatim transcription of `docs/design/DAA_LWMA1.md` §5.3
//! into safe Rust. Every step is annotated with the spec step number;
//! audit reviews should be able to read `§5.3 step 1..=9` against the
//! body of [`lwma1_next`] line-for-line.
//!
//! Type discipline (per §5.4):
//! - The accumulator `L` is computed as `i128` because §5.3 step 2's
//!   running-max formulation produces signed solvetimes. After §5.3
//!   step 5's minimum-L floor, `L` is mathematically positive and is
//!   re-typed to `u128` for the step-7 division.
//! - All FFI-boundary types (`chain_height`, `timestamps[i]`, entries
//!   of `cumulative_difficulties`, `next_difficulty`) are `u64` /
//!   `u128`.
//! - The §5.3 step-8 overflow guard prevents `u128` overflow on the
//!   `avg_D * N * (N+1) * T * 99` multiplication chain when `avg_D >
//!   2_000_000 * N * N * T`.
//!
//! Round 3 disposition (§4): the bias factor `99/200`, the solvetime
//! clamp `6`, and the minimum-L floor `1/20` appear here as bare
//! integer literals rather than named constants. Changing them is a
//! deviation from canonical zawy12 LWMA-1, not a tunable parameter.
//! Named consts live in [`crate::consts`] for the window-shape
//! constants only.

use crate::consts::{GENESIS_DIFFICULTY, N, N_USIZE, T_SECONDS};
use crate::error::Error;

/// LWMA-1 next-difficulty computation per
/// `docs/design/DAA_LWMA1.md` §5.3.
///
/// # Inputs
///
/// - `chain_height`: height of the chain tip (the most recent block
///   already on chain). Genesis is height `0`. The function computes
///   the difficulty for the *next* block at height `chain_height + 1`.
/// - `timestamps`: raw `u64` block timestamps (seconds since Unix
///   epoch), in chain order with `timestamps[0]` the oldest and the
///   last entry the chain tip. When `chain_height >= N`, must contain
///   exactly `N + 1` entries (the consensus invariant — see §5.3 step
///   1's boundary; an off-by-one here is a hard fork). When
///   `chain_height < N`, this slice is *not inspected* and may be of
///   any length, including empty.
/// - `cumulative_difficulties`: matching window of `u128` cumulative
///   difficulties; the length contract mirrors `timestamps`.
///
/// # Output
///
/// On success, the `u128` difficulty value that the next block must
/// satisfy per §5.3 step 9's rounded output.
///
/// # Errors
///
/// - [`Error::InvalidCount`] if `chain_height >= N` and either input
///   slice does not have exactly `N + 1` entries, or the two slices
///   disagree in length.
/// - [`Error::Overflow`] if `cumulative_difficulties[N] <
///   cumulative_difficulties[0]`, which indicates a consensus invariant
///   violation (cumulative difficulty is monotonically
///   non-decreasing). The caller must treat this as a protocol error.
pub fn lwma1_next(
    chain_height: u64,
    timestamps: &[u64],
    cumulative_difficulties: &[u128],
) -> Result<u128, Error> {
    // §5.3 step 1: genesis short-circuit. The first N+1 blocks
    // share GENESIS_DIFFICULTY; the algorithm computes against the
    // window only once chain_height has reached N.
    if chain_height < N {
        return Ok(GENESIS_DIFFICULTY);
    }

    // §5.3 step 1 boundary: when chain_height >= N, the window MUST
    // contain exactly N+1 entries. This is the consensus invariant.
    let expected_len = N_USIZE + 1;
    if timestamps.len() != expected_len || cumulative_difficulties.len() != expected_len {
        return Err(Error::InvalidCount);
    }

    // §5.3 step 2: running-max + signed solvetime (the Shekyl-specific
    // refinement of the LWMA-3 timestamp-protection trick per
    // DAA_LWMA1.md §5.3 step 2 — the running max tracks all
    // previously-seen timestamps, and each new solvetime is the signed
    // difference between the current timestamp and that running max).
    //
    // §5.3 step 3: symmetric ±6*T solvetime clamp, applied
    // step-by-step so the clamped value is what gets weighted in step
    // 4. Clamp magnitude is `6` per the Round 9 disposition; not
    // named-const per §4's bare-integer-literal rule.
    //
    // §5.3 step 4: linear-weighted-sum accumulation as i128.
    //
    // All four are folded into one pass for cache friendliness; the
    // step boundaries are marked inline.
    let t_i128: i128 = i128::from(T_SECONDS);
    let lo = -6 * t_i128;
    let hi = 6 * t_i128;

    // The synthetic anchor `timestamps[0] - T`. Per §5.3 step 2 this
    // value is the initial running max so that `solvetime[1]` matches
    // canonical zawy12 LWMA-1 line 112 exactly. Using i128 for
    // `prev_max` matches the corrected harness in
    // `tests/phase0/preflight_outofseq.cpp` (Round 13 follow-up
    // findings 2): the spec's §5.4 signed-128-bit type discipline
    // applies here, and using a signed type both removes the need for
    // an implementation-defined `u64 -> i64` cast at the max() site
    // and is the natural width for the subtraction `timestamps[0] -
    // T` which would underflow `u64` when `timestamps[0] < T`.
    let mut prev_max: i128 = i128::from(timestamps[0]) - t_i128;

    // §5.3 step 2 (Round 12 ordering correction): solvetime is
    // computed BEFORE the running-max update so iter 1's synthetic
    // -T anchor contributes to solvetime[1] exactly as in canonical
    // zawy12 LWMA-1. Reversing these two operations would overwrite
    // the anchor and shift solvetime[1] by +T.
    //
    // §5.3 step 4: weighted accumulation as i128. Worst-case |acc|
    // bound is sum(i=1..=N) * 6*T = N*(N+1)/2 * 6*T = 2_948_400 for
    // N=90, T=120, well within i128 (`assert!` in consts.rs pins
    // this).
    let mut acc: i128 = 0;
    for (i, &raw_ti) in timestamps.iter().enumerate().skip(1) {
        let ti = i128::from(raw_ti);
        let solvetime = (ti - prev_max).clamp(lo, hi);
        // `i` is in 1..=N (skip(1) above iter()ed over the N+1-length
        // slice). Weight equals the slice index, matching canonical
        // zawy12 line 117 (`L += i*...`). The i128::try_from
        // conversion is infallible for any reachable `i` here (i <=
        // N == 90), but we prefer the lint-clean form over
        // `as i128`.
        let weight = i128::try_from(i).map_err(|_| Error::Overflow)?;
        acc += weight * solvetime;
        if ti > prev_max {
            prev_max = ti;
        }
    }

    // §5.3 step 5: minimum-L floor at N*N*T/20. After this, L is
    // mathematically positive and re-types to u128.
    let n_i128 = i128::from(N);
    let l_min: i128 = n_i128 * n_i128 * t_i128 / 20;
    let l_signed: i128 = if acc < l_min { l_min } else { acc };
    // Post-floor, `l_signed >= l_min >= 48_600 > 0`, so the u128
    // conversion is value-preserving. `try_from` is the lint-clean
    // form (the `as` cast would fire `cast_sign_loss`); the error
    // case below is unreachable in correct code but we surface it as
    // `Error::Overflow` rather than `expect`/`unwrap` to keep the
    // panic-free property of the algorithm.
    let l: u128 = u128::try_from(l_signed).map_err(|_| Error::Overflow)?;

    // §5.3 step 6: avg_D over the window. Per the doc's signature
    // contract, `cumulative_difficulties[N] >=
    // cumulative_difficulties[0]` is a consensus invariant; if it
    // doesn't hold, the chain state is broken and we surface
    // ERR_OVERFLOW rather than producing a wrap-around value.
    let cd_n = cumulative_difficulties[N_USIZE];
    let cd_0 = cumulative_difficulties[0];
    let avg_d: u128 = cd_n
        .checked_sub(cd_0)
        .ok_or(Error::Overflow)?
        .checked_div(u128::from(N))
        .ok_or(Error::Overflow)?;

    // §5.3 step 7/8: apply the bias-corrected formula. The §5.3
    // step-8 overflow guard splits the formula at the boundary
    // `avg_D > 2_000_000 * N * N * T` to keep the u128 multiplication
    // chain in range. Both branches use checked arithmetic so a
    // pathological avg_D (e.g., near u128::MAX from an attacker-
    // controlled cumulative_difficulty injection at the consumer
    // boundary) surfaces as ERR_OVERFLOW rather than wrapping
    // silently. Per §5.4 the canonical inputs do not overflow either
    // branch; the checked_* calls are belt-and-suspenders for the
    // consensus-invariant-violation case.
    let n_u128: u128 = u128::from(N);
    let t_u128: u128 = u128::from(T_SECONDS);
    let nf_t_99: u128 = n_u128
        .checked_mul(n_u128 + 1)
        .and_then(|x| x.checked_mul(t_u128))
        .and_then(|x| x.checked_mul(99))
        .ok_or(Error::Overflow)?;
    let two_hundred_l: u128 = l.checked_mul(200).ok_or(Error::Overflow)?;
    let threshold: u128 = 2_000_000u128
        .checked_mul(n_u128)
        .and_then(|x| x.checked_mul(n_u128))
        .and_then(|x| x.checked_mul(t_u128))
        .ok_or(Error::Overflow)?;

    let next_d_raw: u128 = if avg_d > threshold {
        // Guarded branch: divide first, then multiply. Matches
        // canonical zawy12 issue #3 LWMA-1 lines 124-125 verbatim.
        avg_d
            .checked_div(two_hundred_l)
            .ok_or(Error::Overflow)?
            .checked_mul(nf_t_99)
            .ok_or(Error::Overflow)?
    } else {
        // Unguarded branch: multiply first, then divide. Matches
        // canonical zawy12 issue #3 LWMA-1 lines 126-127 verbatim.
        avg_d
            .checked_mul(nf_t_99)
            .ok_or(Error::Overflow)?
            .checked_div(two_hundred_l)
            .ok_or(Error::Overflow)?
    };

    // §5.3 step 9: canonical rounding to 3 significant decimal
    // digits at the largest meaningful magnitude. Verbatim from
    // canonical LWMA1_() lines 116-119 of the pinned issue body.
    //
    // The loop runs at most 10 iterations (r ∈ {10^9, 10^8, ..., 10^1,
    // 10^0}) and exits at the first r where `next_D > 100*r`, or with
    // r == 1 (no rounding) when next_D <= 100. The §5.3 step 9
    // reversion clause names this step as canonical zawy12 LWMA-1
    // verbatim; removing it breaks the §8.2 cross-check assertion.
    let mut next_d = next_d_raw;
    let mut r: u128 = 1_000_000_000;
    while r > 1 {
        if next_d > r.saturating_mul(100) {
            // ((next_d + r/2) / r) * r
            // Per §5.4 the i128 worst-case fits comfortably and the
            // u128 form is identical-by-cast since next_d is
            // non-negative. checked_add covers the (next_d + r/2)
            // overflow that would only fire on attacker-controlled
            // u128::MAX-adjacent inputs; treat as Overflow.
            next_d = next_d
                .checked_add(r / 2)
                .ok_or(Error::Overflow)?
                .checked_div(r)
                .ok_or(Error::Overflow)?
                .checked_mul(r)
                .ok_or(Error::Overflow)?;
            break;
        }
        r /= 10;
    }

    Ok(next_d)
}
