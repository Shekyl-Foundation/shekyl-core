// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The corrected fee ladder (FL round §5.2, three tiers per FL-R17) and its
//! quantized correction factor (FL-R12′ round-8 amendment, whole-scalar
//! form).
//!
//! **What the daemon serves** (`FEE_LADDER_DERIVATION.md` §5.2, signed
//! rungs FL-R17 / operand per the adopted round-8 amendment):
//!
//! ```text
//! served = C_q · ladder(max(curve(remaining), TAIL))
//! C_q    = 2^ceil(log2( (1−σ)·M_r / (1−b) ))     — the WHOLE volume-
//!                                                   dependent scalar
//! ```
//!
//! The amendment quantizes the whole scalar rather than leaving `M_r` raw
//! in the operand: `Q(C′)·M_r ≠ Q(C′·M_r)` — identical in algebra, not in
//! quantization — and the raw-`M_r` split re-created the measured FL-C4a
//! dwell failure (4-block anonymity cohorts at baseline volume). The
//! operand is therefore the **M_r-neutral** total reward view
//! ([`crate::base_block_reward`]); `M_r` lives inside the quantized scalar.
//!
//! Tier contracts (§5.5): `fees[0]` economy — the admission rung, clamped
//! by the CALLER at the unbuffered relay floor; `fees[1]` standard — the
//! sustained-growth rung and the default; `fees[2]` priority — exact
//! marginal-cost pricing of expansion to the 2×median cap, the `Fh` main
//! arm made **unconditional** (the surge discount was FL-C2(b)'s one
//! derived defect in the inherited shape).

use crate::params::{EconomicParams, SCALE};
use crate::release::calc_release_multiplier;
use crate::volume::TxVolume;

/// `CRYPTONOTE_SCALING_2021_FEE_ROUNDING_PLACES = 2`:
/// `round_money_up(v, 2)` — round UP to 2 significant decimal digits.
///
/// Production owner of this rule. Wallet cap and the FL instrument
/// import this function rather than carrying a third copy. The C++
/// original throws on overflow; saturation here is unreachable for any
/// fee the ladder can emit and documented as the fail-safe.
#[must_use]
pub fn round_money_up_2(v: u64) -> u64 {
    if v < 100 {
        return v;
    }
    let mut unit = 1u64;
    let mut head = v;
    while head >= 100 {
        head /= 10;
        unit *= 10;
    }
    v.div_ceil(unit).saturating_mul(unit)
}

/// Exact-integer `2^k ≤ c/s` (no float log2 — this feeds a
/// wallet-must-match-daemon derivation, so cross-platform float behavior
/// must not be load-bearing).
fn pow2_le(c: u128, s: u128, k: i32) -> bool {
    if k >= 0 {
        (s << k) <= c
    } else {
        s <= (c << (-k))
    }
}

/// Ceiling pow2 snap in `SCALE` fixed point: smallest exact power of two
/// `≥ c/SCALE`. Panics only if the snapped exponent leaves the range
/// `SCALE = 10^6` can represent exactly (`2^-6 … 2^43`), unreachable for
/// the derivation's `C` range — loud, not truncated, if a parameter change
/// ever widens it.
#[must_use]
pub fn quantize_pow2_ceil(c_scaled: u64) -> u64 {
    assert!(c_scaled > 0, "correction factor is structurally positive");
    let c = u128::from(c_scaled);
    let s = u128::from(SCALE);
    let mut kf: i32 = -40;
    while pow2_le(c, s, kf + 1) {
        kf += 1;
    }
    let exact = if kf >= 0 {
        (s << kf) == c
    } else {
        (c << (-kf)) == s
    };
    let k = if exact { kf } else { kf + 1 };
    assert!(
        (-6..=43).contains(&k),
        "2^{k} not exactly representable in SCALE units"
    );
    if k >= 0 {
        SCALE << k
    } else {
        SCALE >> (-k)
    }
}

/// The **raw** fee-correction scalar `C = (1−σ)·M_r/(1−b)`, in [`SCALE`]
/// units (FL-R20).
///
/// This is the scalar the relay floor follows: `F(h) = R·C(h)·w_ref/M²`,
/// with **no snap, no band, no rounding**, and **one formula for every
/// regime** — `C < 1` on a quiet chain (`M_r` at its low rail) lowers the
/// floor below the inherited value exactly as `C > 1` raises it. There is
/// no `max(F, F_inherited)` arm, because a floor that only ever rises is
/// not a correction.
///
/// `sigma_scaled` and `burn_pct_scaled` are the caller's already-computed
/// fixed-point components — the same `shekyl_calc_emission_share` /
/// `shekyl_calc_burn_pct` values the validation path uses at this state,
/// so there is one derivation and no second model on the estimate side.
///
/// Total by construction, which is what lets it cross `extern "C"`
/// without a fallible arm (rule 40): `σ` and `b` are each clamped below
/// `SCALE`, so the divisor `SCALE − b` is at least 1 and the quotient of
/// two `u128`s built from `u64`s cannot exceed `u64::MAX` — the numerator
/// is bounded by `SCALE · release_max`. The reachable range is far
/// narrower than the type: `C ≈ 0.68` at the young-quiet corner
/// (`M_r` = 0.8, `σ` = 0.15, `b` = 0) up to `≈ 13` congested-mature, which
/// is why FL-R21 could delete `MIN_REPRESENTABLE_C` — the pow2 floor it
/// provided guarded a boundary raw `C` never approaches.
#[must_use]
pub fn fee_correction(
    tx_volume: TxVolume,
    sigma_scaled: u64,
    burn_pct_scaled: u64,
    params: &EconomicParams,
) -> u64 {
    let m_r = calc_release_multiplier(
        tx_volume,
        params.tx_volume_baseline,
        params.release_min,
        params.release_max,
    );
    let sigma = sigma_scaled.min(SCALE - 1);
    let b = burn_pct_scaled.min(params.burn_cap).min(SCALE - 1);
    u64::try_from(u128::from(SCALE - sigma) * u128::from(m_r) / u128::from(SCALE - b))
        .expect("C fits u64: numerator <= SCALE * release_max, divisor >= 1")
}

/// The quantized fee-correction scalar `C_q` (round-8 amendment,
/// whole-scalar form), with boundary hysteresis.
///
/// `sigma` and `burn_pct` are the caller's already-computed fixed-point
/// components (the same `shekyl_calc_emission_share` / `shekyl_calc_burn_pct`
/// values the validation path uses at this state — one source, no second
/// derivation). `prev_cq_scaled = 0` means no previous value (no
/// hysteresis).
///
/// Hysteresis (FL round §7 construction requirement): a state sitting
/// exactly on a pow2 boundary must not flicker between steps. The raw
/// `C_q` replaces the previous one only when `C` has moved beyond the
/// previous step's implied band by more than `HYSTERESIS_MARGIN_MILLI`
/// (3%); within the band the previous quantized value is kept.
///
/// **The daemon does not reach this branch yet, and that is a gap being
/// closed, not the design.** `blockchain.cpp` passes `prev_cq = 0`, so
/// what is served today is the plain ceiling snap. FL-R3 is RULED: the
/// band stays and is restored to the served path.
///
/// What blocks the restoration is the SHAPE of the previous value, not
/// the decision. The band needs one, and neither obvious source works:
/// a remembered value makes the served rate depend on the process's
/// query history, and the previous block's unseeded snap is a one-step
/// approximation that inverts the result rather than evaluating the
/// recurrence `C_q(h) = f(C(h), C_q(h−1))`. The answer is a
/// grid-anchored previous value — bounded to evaluate and still a pure
/// function of chain state — which is a design change and comes back as
/// its own round.
///
/// **So do not wire a caller to a nonzero `prev_cq` until that round
/// lands, and when it does, honour FL-R3's two binding constraints: the
/// band stays a PURE FUNCTION OF CHAIN STATE (a per-node remembered
/// value repeals FL-R18 rather than restoring FL-R3), and it keeps a
/// SINGLE OWNER — see [`hysteresis_step`], which exists because a
/// transliterated copy had already drifted.**
#[must_use]
pub fn fee_correction_quantized(
    tx_volume: TxVolume,
    sigma_scaled: u64,
    burn_pct_scaled: u64,
    prev_cq_scaled: u64,
    params: &EconomicParams,
) -> u64 {
    // The raw scalar has ONE owner ([`fee_correction`]) and this is the
    // quantizer wrapped around it. Before FL-R20 the expression lived here
    // and nowhere else, so the relay floor could not read `C` without
    // reading the snap with it — which is the whole of FL-R20's finding.
    // TOTALITY AT THE BOUNDARY is `hysteresis_step`'s floor: `σ` and `b`
    // are clamped inside `fee_correction`, so what remains is a `C` of 0,
    // which the floor absorbs. The reasoning lives there, with the code
    // that does it.
    hysteresis_step(
        fee_correction(tx_volume, sigma_scaled, burn_pct_scaled, params),
        prev_cq_scaled,
    )
}

/// The smallest exactly-representable raw `C`: the floor [`hysteresis_step`]
/// applies before snapping, and therefore the smallest band state there is.
const MIN_REPRESENTABLE_C: u64 = SCALE >> 6;

/// The pow2 ceiling snap of a raw correction `C`, behind the §7
/// hysteresis band.
///
/// Split out of [`fee_correction_quantized`] so the band has ONE
/// implementation. The derivation instrument sweeps raw `C` directly and
/// so cannot enter through the whole-scalar function; it used to carry a
/// transliterated copy of this logic, which had already drifted — the
/// copy never picked up the `MIN_REPRESENTABLE_C` floor — and a
/// measurement taken on a drifted copy is a measurement of a different
/// mechanism than the one shipped.
///
/// `prev_cq_scaled = 0` means no history: the plain ceiling snap. With a
/// history the raw `C` must clear the new step's boundary by
/// `HYSTERESIS_MARGIN_MILLI` before the value moves, i.e. `C` must leave
/// `[prev/2·(1−m), prev·(1+m)]`.
///
/// `C` is floored at the smallest exactly-representable value first.
/// [`quantize_pow2_ceil`] is deliberately LOUD about a `C` outside that
/// window — the guard earns its keep on the derivation path, where a
/// parameter change that widened the range should stop the build rather
/// than truncate — but this is reached through `extern "C"`, where rule
/// 40 forbids a malformed input from panicking across the ABI. A `σ` at
/// its clamp with a dormant multiplier drives integer division to
/// `C = 0`, which no chain state produces (the reachable floor is ≈ 0.68)
/// but a caller can hand us. Flooring keeps the boundary total, and the
/// direction is the safe one: a smaller `C_q` can only under-price, which
/// the caller's relay-floor clamp then lifts (§5.2's acceptance identity).
#[must_use]
pub fn hysteresis_step(c_scaled: u64, prev_cq_scaled: u64) -> u64 {
    const HYSTERESIS_MARGIN_MILLI: u128 = 30; // 3%
    let c = c_scaled.max(MIN_REPRESENTABLE_C);
    let cq = quantize_pow2_ceil(c);
    if prev_cq_scaled == 0 || cq == prev_cq_scaled {
        return cq;
    }
    let prev = u128::from(prev_cq_scaled);
    let c = u128::from(c);
    let upper = prev * (1000 + HYSTERESIS_MARGIN_MILLI) / 1000;
    let lower = (prev / 2) * (1000 - HYSTERESIS_MARGIN_MILLI) / 1000;
    if c > upper || c < lower {
        cq
    } else {
        prev_cq_scaled
    }
}

/// The §7 band applied to a **span** of raw corrections, unseeded at the
/// first (`FEE_LADDER_DERIVATION.md` §10.12.4).
///
/// This is the FL-R3 time-grid fold's single owner: `cells[0]` is the
/// anchor `h₀ = h − (h mod P)` and `cells[i]` the raw `C` at `h₀ + i`.
/// The first cell snaps with no history (the anchor is where the grid
/// forgets), and every later cell enters [`hysteresis_step`] against the
/// value the previous cell produced. The result is the banded `C_q` at
/// the last height — a pure function of the span, which is what lets the
/// daemon recompute it from chain state alone instead of carrying a
/// `prev_cq` it has no owner for (§10.1's two constraints).
///
/// `None` for an empty span: there is no anchor to snap. The FFI wrapper
/// (§10.12.4) turns that into its `−2` status; nothing here panics on
/// input, per rule 40. `P` and the anchor rule are the caller's — this
/// function knows only the span it is handed, so the constant that
/// R18-M1 has not yet signed lands nowhere in it.
///
/// The derivation instrument's grid arms fold through this function
/// rather than through a private loop, for the same reason
/// [`hysteresis_step`] exists: a measurement of a copy is a measurement of
/// a different mechanism.
#[must_use]
pub fn hysteresis_fold(cells_scaled: &[u64]) -> Option<u64> {
    let (first, rest) = cells_scaled.split_first()?;
    let mut cq = hysteresis_step(*first, 0);
    for &c in rest {
        cq = hysteresis_step(c, cq);
    }
    Some(cq)
}

/// Is a raw correction **settled** — clear of every pow2 boundary by more
/// than the §7 margin, so the band's state at it is `⌈c⌉₂` **whatever the
/// history** (`FEE_LADDER_DERIVATION.md` §10.14.2)?
///
/// [`hysteresis_step`] holds a `prev ≠ ⌈c⌉₂` only when `c` lies inside
/// `[(prev/2)(1−m), prev(1+m)]`. With `cq = ⌈c⌉₂` and `c ∈ (cq/2, cq]`,
/// the only powers of two that window can reach are `2cq` (needs `c` within
/// the margin *below* the boundary `cq`) and `cq/2` (needs `c` within the
/// margin *above* the boundary `cq/2`). So a sample is settled iff the step
/// from **both** neighbours lands on `cq` — and that is how this is
/// computed: through the step itself, never through a second copy of the
/// margin arithmetic, so the predicate and the band cannot drift apart.
///
/// This is what lets a fold anchor at *the last settled sample* and be the
/// exact recurrence rather than an approximation of it:
/// `hysteresis_fold(seq) == hysteresis_fold(&seq[j..])` for every settled
/// `j` (the property test below is that theorem).
#[must_use]
pub fn hysteresis_settled(c_scaled: u64) -> bool {
    let cq = hysteresis_step(c_scaled, 0);
    // `cq / 2` below the representable floor is not a state the band can
    // be in (every state is the snap of a floored `c`), so only the upper
    // neighbour can hold there.
    let lower_holds = cq / 2 >= MIN_REPRESENTABLE_C && hysteresis_step(c_scaled, cq / 2) != cq;
    let upper_holds = hysteresis_step(c_scaled, cq.saturating_mul(2)) != cq;
    !(lower_holds || upper_holds)
}

/// Wallet-side emission-claim **value floor**, in atomic units
/// (`ENGINE_CADENCE_DRIVER.md` §4): the engine cadence driver's claim leg
/// holds settled epochs until Σreward across the held set clears this
/// floor — claiming rewards worth less than the sweep fee they cost
/// converts a zero into a negative.
///
/// **Derivation (rule 75).** The floor summarizes the economy rung's price
/// for one claim-tx envelope at the genesis anchor: economy
/// (`C_q·R·w_ref/Mfw²`) = 70 000 atomic per weight byte at the uncongested
/// genesis state (`R` = 2 100 SKL, `Mfw` = 300 000, `C_q` = 1 — the same
/// anchor the genesis-condition ladder test below pins via
/// `Fh = 14 000 000`), times the claim envelope
/// (`EMISSION_NON_CLAIMS_RESERVE_BYTES` 48 KiB + a ~2 KiB single-row vin
/// allowance ≈ 51 200 B) ≈ 3.584 SKL — rounded up to 3.6 SKL so the floor
/// errs toward holding one more epoch, never toward claiming at a loss.
///
/// **Bounds.** [1 SKL, 15 SKL] is safe today: below invites negative-value
/// claims under congestion (`C_q > 1` scales the real fee above the
/// anchor); above defers claims the fee arithmetic already justifies
/// (deferral is bounded by the claim window — the leg
/// evaluates-and-forfeits at the window floor rather than forcing). The
/// anchor decays with the base reward, so the safe band shifts down over
/// the emission curve; revisit when `R` has decayed materially. That
/// retune is a wallet release, deliberately **not** consensus: freezing a
/// wallet fee-policy threshold into `config/consensus_constants.json`
/// would cost a consensus retune to adjust while buying nothing.
///
/// **A compiled-in constant, deliberately** (anti-fingerprint): a
/// per-wallet knob or config value would partition the anonymity set by
/// fee policy — rule 00 §2, privacy is never a setting. Uniform across
/// wallets, the inclusion decision it drives carries no per-wallet signal
/// beyond the (accepted, recorded) fee-policy bucketing itself.
pub const EMISSION_CLAIM_FEE_FLOOR: u64 = 3_600_000_000;

/// The three priced rungs. [`Self::as_slots`] is the wire projection:
/// `[economy, standard, priority]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeLadder {
    pub economy: u64,
    pub standard: u64,
    pub priority: u64,
}

impl FeeLadder {
    /// Every rung at the `u64` rail. The saturation
    /// [`corrected_fee_ladder`] takes outside its `u128` domain, which no
    /// chain state reaches.
    pub const SATURATED: Self = Self {
        economy: u64::MAX,
        standard: u64::MAX,
        priority: u64::MAX,
    };

    /// Wire shape `[economy, standard, priority]` — one slot per priced tier.
    #[must_use]
    pub const fn as_slots(self) -> [u64; 3] {
        [self.economy, self.standard, self.priority]
    }
}

/// The corrected three-tier ladder (FL-R17).
///
/// `base_reward` is the **M_r-neutral** total reward
/// ([`crate::base_block_reward`] — `max(curve(remaining), TAIL)`, total
/// past the asymptote); `c_q` is [`fee_correction_quantized`]'s output.
/// The rung formulas are the derived ones (`FEE_LADDER_DERIVATION.md`
/// §3.2/§5.2):
///
/// * `economy  = C_q · R·w_ref/Mfw²` — single-reference-tx self-funding
///   (the caller clamps this at the unbuffered relay floor, which is what
///   makes the estimate err only toward acceptance);
/// * `standard = C_q · 4·R·w_ref/Mfw²`;
/// * `priority = C_q · 2·R/Mfw` — the `Fh` main arm, UNCONDITIONAL: no
///   surge discount, full expansion is funded in every state.
///
/// `C_q` lives in the numerator before the median division (`(C_q·R·w)/M²`,
/// not `(R·w/M²)·C_q`). Truncating the rung first throws away a remainder
/// that `C_q > 1` would have scaled over a rounding step (10 SKL / 1.5 MB
/// / `C_q = 16` is 220 vs 210). Amount arithmetic, so the formula is the
/// integer reading of the signed expression, not a post-hoc rescale.
///
/// Each rung is then daemon-rounded to 2 significant digits.
///
/// Total: outside the arithmetic's `u128` domain — which no chain state
/// reaches, see [`checked_corrected_fee_ladder`] — every rung saturates,
/// the same fallback the division already takes. Callers that must
/// distinguish that input from a priced ladder use the checked form; the
/// FFI boundary does, and refuses it.
#[must_use]
pub fn corrected_fee_ladder(
    base_reward: u64,
    mnw: u64,
    mlw: u64,
    full_reward_zone: u64,
    ref_tx_weight: u64,
    c_q: u64,
) -> FeeLadder {
    checked_corrected_fee_ladder(base_reward, mnw, mlw, full_reward_zone, ref_tx_weight, c_q)
        .unwrap_or(FeeLadder::SATURATED)
}

/// [`corrected_fee_ladder`], or `None` when the scalars cannot form the
/// rungs' products in `u128`.
///
/// Every honest input is far inside the domain — `R` is bounded by the
/// subsidy curve at ≈2⁴¹, `w_ref` is 3 000, `C_q` ≤ 16 in `SCALE` units,
/// and `Mfw` is a block weight — so the fallible arm exists for the
/// `extern "C"` boundary alone (rule 40): the ABI takes bare `u64`s, and
/// operands near `u64::MAX` overflow `u128` BEFORE `round_scaled`'s
/// conversion fallback can see it, which is an abort in an
/// overflow-checked build and wrapped fees otherwise.
///
/// The domain is decided HERE, from the same operands the rungs
/// multiply, rather than being re-derived at the boundary. **The three
/// rungs do not share an operand list** — `priority` is `2·R·C_q` and is
/// the only rung that does not carry `w_ref` — so a boundary check
/// written against one representative product is not a check of the
/// others: `w_ref = 0` zeroes every `w_ref`-bearing product and passes,
/// then `2·R·C_q` overflows. That is not a hypothetical; it is what the
/// hand-mirrored boundary copy this replaces actually did.
#[must_use]
pub fn checked_corrected_fee_ladder(
    base_reward: u64,
    mnw: u64,
    mlw: u64,
    full_reward_zone: u64,
    ref_tx_weight: u64,
    c_q: u64,
) -> Option<FeeLadder> {
    let mfw = u128::from(effective_fee_median(mnw, mlw, full_reward_zone));
    let base = u128::from(base_reward);
    let cq = u128::from(c_q);
    let ms = mfw.checked_mul(u128::from(SCALE))?;

    // `economy` IS the relay floor, by call and not by coincidence. FL-R6
    // became an identity under FL-R20, and an identity asserted by two
    // expressions that happen to agree is one edit away from being false
    // — so the wire's slot 0 and `check_fee`'s floor are the same
    // function of the same operands.
    let economy =
        checked_relay_fee_floor(base_reward, mnw, mlw, full_reward_zone, ref_tx_weight, c_q)?;
    Some(FeeLadder {
        economy,
        // `4F`, not `round(4·R·w·C/M²)`. FL-R20 prices the sustained-growth
        // rung as a multiple OF THE FLOOR, so the two cannot drift apart
        // by a rounding step at the bottom of the range where `max(1)`
        // binds and `4 × (the unfloored quotient)` would be zero.
        // `4F` in u128, saturating at the u64 rail exactly as `economy`
        // does. NOT `economy.checked_mul(4)?`: that multiplies in u64 and
        // so narrows the ladder's DOMAIN — the pre-FL-R20 shape formed
        // `4·R·w·C` in the u128 numerator before dividing, and a reward
        // large enough to make `4F` exceed u64 (the BLOCK_REWARD_OVERESTIMATE
        // fallback reaches it) would refuse a ladder that used to price.
        // `rpc_facts_shims.a_fee_estimate_writes_three_priced_tiers` caught
        // that as an FFI-level refusal, not as a wrong number.
        standard: u64::try_from(u128::from(economy) * 4).unwrap_or(u64::MAX),
        // `2RC/M` — the `Fh` main arm — floored at 1 for the reason FL-R20
        // keeps `max(1)` on the relay floor: a zero rung is not a cheap
        // price, it is a tier that admits everything.
        //
        // The floor is NOT redundant, which is worth stating because the
        // obvious algebra says it is: `2RC/M` beats `RCw/M^2` whenever
        // `2M > w_ref`, and `M >= full_reward_zone` = 300 000 against a
        // 3 000-byte reference tx, so priority looks like it dominates a
        // floored economy automatically. It does not — `economy` carries
        // its own `max(1)`, so at a reward small enough to truncate both
        // quotients to zero, economy is 1 and an unfloored priority is 0.
        // `priority_dominates_the_floor` found that corner; the algebra
        // above was written before it and was wrong.
        // Raised to `standard` when the arithmetic falls below it, so the
        // ladder is MONOTONE BY CONSTRUCTION. The obvious algebra says this
        // never binds — `2RC/M` beats `4RCw/M^2` whenever `M > 2·w_ref`, and
        // `M >= full_reward_zone` = 300 000 against a 3 000-byte reference tx
        // — and it is wrong, because the rungs it compares carry floors of
        // their own. At a reward small enough to truncate every quotient to
        // zero, `economy` is `max(1)` = 1, `standard` is `4F` = 4, and an
        // unfloored `priority` is 0: `[1, 4, 1]`, which is not a ladder. A
        // bare `max(1)` does not fix that; the rung has to clear the one
        // below it.
        //
        // Found by `rpc_facts_shims.a_fee_estimate_writes_three_priced_tiers`,
        // which asserts the wire contract `fees[0] <= fees[1] <= fees[2]`
        // every tier-selecting consumer relies on. The Rust test that should
        // have caught it asserted `priority >= economy` — true, wrong axis.
        priority: u64::try_from(base.checked_mul(cq)?.checked_mul(2)? / ms)
            .unwrap_or(u64::MAX)
            .max(u64::try_from(u128::from(economy) * 4).unwrap_or(u64::MAX)),
    })
}

/// The fee median `M` every rung and the relay floor divide by — **one
/// definition**, so FL-R6's identity cannot be broken by editing one of
/// two copies.
///
/// The `min` is inherited and provably dead at both call sites: the
/// estimate passes `Mnw = min(Msw, 50·Mlw)` with `Msw >= Mlw`, and the
/// daemon's relay path passes `(effective_median, LTM)` where the
/// effective median is built as `max(LTM, short_term)` clamped to
/// `50·LTM`. Both give `mnw >= mlw`, so the `min` has never selected its
/// first argument. It is NOT removed here: the operand crosses the FFI,
/// so dropping it is a signature change, and it may only go together
/// with tests pinning the two invariants that make it dead (FL-R21 sweep,
/// PR C).
fn effective_fee_median(mnw: u64, mlw: u64, full_reward_zone: u64) -> u64 {
    mnw.min(mlw).max(full_reward_zone).max(1)
}

/// The FL-R20 relay floor `F(h) = R·C·w_ref/M²`, floored at 1 — what
/// `check_fee` prices admission from and what the estimate serves as its
/// economy rung.
///
/// **Raw `C`, and no rounding.** Monero's 0.95 and the 2 % admission
/// buffer were the same fudge for the same gap, and FL-R23 closes that
/// gap structurally; `round_money_up_2` on the served path went with
/// them (FL-R21), because a floor rounded up to two significant digits
/// is a floor a conforming wallet's exact quote can miss.
///
/// `max(1)` is kept: a zero floor admits everything, and `get_dynamic_base_fee`'s
/// contract — that `0` is unambiguously the block-reward-failure arm, not
/// a price — is load-bearing at the C++ call site.
///
/// `None` only outside the `u128` domain, which no chain state reaches;
/// see [`checked_corrected_fee_ladder`] for why that arm exists at all.
#[must_use]
pub fn checked_relay_fee_floor(
    base_reward: u64,
    mnw: u64,
    mlw: u64,
    full_reward_zone: u64,
    ref_tx_weight: u64,
    c_scaled: u64,
) -> Option<u64> {
    let mfw = u128::from(effective_fee_median(mnw, mlw, full_reward_zone));
    let ms = mfw.checked_mul(u128::from(SCALE))?;
    let m2s = mfw.checked_mul(ms)?;
    let num = u128::from(base_reward)
        .checked_mul(u128::from(ref_tx_weight))?
        .checked_mul(u128::from(c_scaled))?;
    Some(u64::try_from(num / m2s).unwrap_or(u64::MAX).max(1))
}

/// [`checked_relay_fee_floor`], saturating outside the domain — the same
/// fallback [`corrected_fee_ladder`] takes, so the floor and the rung it
/// equals cannot disagree about an impossible input either.
#[must_use]
pub fn relay_fee_floor(
    base_reward: u64,
    mnw: u64,
    mlw: u64,
    full_reward_zone: u64,
    ref_tx_weight: u64,
    c_scaled: u64,
) -> u64 {
    checked_relay_fee_floor(
        base_reward,
        mnw,
        mlw,
        full_reward_zone,
        ref_tx_weight,
        c_scaled,
    )
    .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base_block_reward;

    /// Neutral correction (`C_q = 1`) against the `scaling_2021.cpp`
    /// heritage vectors: three tiers, `Fh` main arm unconditional (the
    /// 22 000 surge value in the second heritage case becomes the
    /// main-arm 67 000 — the FL-C2(b) fix, deliberate).
    #[test]
    fn neutral_ladder_matches_heritage_vectors_with_signed_shape() {
        let coin = 1_000_000_000u64;
        assert_eq!(
            corrected_fee_ladder(10 * coin, 300_000, 300_000, 300_000, 3_000, SCALE).as_slots(),
            [333, 1332, 66_666]
        );
        // Heritage case 2: Mnw = 15 MB surge over a 300 kB long-term
        // median. Was 22 000 under the surge discount; the unconditional
        // main arm prices full expansion here too.
        assert_eq!(
            corrected_fee_ladder(10 * coin, 15_000_000, 300_000, 300_000, 3_000, SCALE).as_slots(),
            [333, 1332, 66_666]
        );
        assert_eq!(
            corrected_fee_ladder(10 * coin, 1_500_000, 1_500_000, 300_000, 3_000, SCALE).as_slots(),
            [13, 52, 13_333]
        );
    }

    /// The domain must be decided per RUNG, not against a representative
    /// product. Each case below overflows exactly one rung's operand
    /// list while leaving the others formable, so a check written against
    /// any single product lets one of them through — which is how
    /// `priority` (`2·R·C_q`, the rung with no `w_ref`) survived a
    /// boundary check written against `4·R·w_ref·C_q`.
    #[test]
    fn the_domain_covers_each_rung_separately() {
        let z = 300_000;
        // `w_ref = 0` collapses every `w_ref`-bearing product to zero;
        // only `priority`'s `2·R·C_q` can still overflow.
        assert!(checked_corrected_fee_ladder(u64::MAX, z, z, z, 0, u64::MAX).is_none());
        // …and with `C_q` small it is back in the domain, so the refusal
        // above is the arithmetic and not a blanket on `w_ref = 0`.
        assert!(checked_corrected_fee_ladder(u64::MAX, z, z, z, 0, SCALE).is_some());
        // `C = 2` keeps `priority` formable while `R·w_ref·C` — the
        // floor's numerator, which `economy` and `standard` share —
        // overflows u128.
        //
        // RE-DERIVED under FL-R20, not re-pinned. This case used to read
        // `C_q = 1` and overflow on `4·R·w_ref·C_q`, because `standard`
        // was `round(4·R·w·C / M²)` and formed the `4·` inside the u128
        // numerator. Item 4 makes it `4F` — four times the FLOOR, after
        // the division — so that input is now genuinely inside the domain
        // and refusing it would be the wrong answer. The rung's operand
        // list changed; the case that probes it has to change with it,
        // which is the whole point of deciding the domain per rung.
        assert!(checked_corrected_fee_ladder(u64::MAX, z, z, z, u64::MAX, 2).is_none());
        // The same operands at `C = 1` ARE in the domain — so the refusal
        // above is the arithmetic, not a blanket on a huge `w_ref`.
        assert!(checked_corrected_fee_ladder(u64::MAX, z, z, z, u64::MAX, 1).is_some());
        // A denominator past the rail, with a numerator that fits.
        assert!(checked_corrected_fee_ladder(1, u64::MAX, u64::MAX, u64::MAX, 1, 1).is_none());
        // The honest domain is not swept up by any of it.
        assert!(checked_corrected_fee_ladder(10_000_000_000, z, z, z, 3_000, SCALE).is_some());
    }

    /// The infallible entry saturates rather than aborting, and does so
    /// at the same input the checked form refuses.
    #[test]
    fn the_infallible_entry_saturates_outside_the_domain() {
        let z = 300_000;
        assert_eq!(
            corrected_fee_ladder(u64::MAX, z, z, z, 0, u64::MAX),
            FeeLadder::SATURATED
        );
        assert_eq!(FeeLadder::SATURATED.as_slots(), [u64::MAX; 3]);
    }

    /// `C_q` in the numerator before the median division, not a rescale of
    /// an already-truncated rung. The 10 SKL / 1.5 MB / `C_q = 16` case is
    /// the measured divergence (220 vs the post-truncation 210).
    #[test]
    fn correction_lives_in_the_numerator() {
        let coin = 1_000_000_000u64;
        let ladder =
            corrected_fee_ladder(10 * coin, 1_500_000, 1_500_000, 300_000, 3_000, 16 * SCALE);
        // 213, not the 208 a post-hoc rescale of the C = 1 rung (13) would
        // give. The remainder C scales over is still thrown away by
        // truncating first; only the rounding step that used to hide it is
        // gone (FL-R21), so the gap narrowed from 220-vs-210 to 213-vs-208
        // and the property is unchanged.
        assert_eq!(ladder.economy, 213);
        assert_eq!(13 * 16, 208, "the rescale-after value this rung must beat");
        assert_eq!(
            ladder.as_slots(),
            [ladder.economy, ladder.standard, ladder.priority]
        );
    }

    /// Genesis-condition top rung with `C = 1` is the uncongested genesis
    /// `Fh` (13,653,333); at the genesis-congested `C = 2` it is
    /// 27,306,666.
    ///
    /// **These are the unrounded values.** They were 14,000,000 and
    /// 28,000,000 while `round_money_up_2` sat on the served path; FL-R21
    /// deletes it, so the anchor is now the arithmetic's own answer rather
    /// than that answer rounded up to two significant digits. (13,653,333
    /// is the very value `round_money_up_two_places_matches_cpp` pins as
    /// rounding to 14,000,000 — same number, one step earlier.)
    ///
    /// 27,306,666 is the GENESIS ANCHOR, not a cap. It was FL-R9's wallet
    /// cap until #640 re-derived that as the 220,000,000 structural bound
    /// — the old value sat below honest daemon quotes from ≈ year 3, so
    /// naming it a cap here would preserve the superseded contract in the
    /// new owner's own documentation. What this pins is the genesis point
    /// of the ladder; the cap's adequacy is pinned in `fee_policy.rs`.
    #[test]
    fn genesis_top_rung_anchors() {
        let p = EconomicParams::default();
        let base = base_block_reward(0, &p).unwrap();
        assert_eq!(
            corrected_fee_ladder(base, 300_000, 300_000, 300_000, 3_000, SCALE).priority,
            13_653_333
        );
        assert_eq!(
            corrected_fee_ladder(base, 300_000, 300_000, 300_000, 3_000, 2 * SCALE).priority,
            27_306_666
        );
    }

    #[test]
    fn quantize_snap_is_exact_integer_ceiling() {
        for c in [500_000u64, 1_000_000, 2_000_000, 4_000_000] {
            assert_eq!(quantize_pow2_ceil(c), c);
        }
        assert_eq!(quantize_pow2_ceil(680_000), 1_000_000);
        assert_eq!(quantize_pow2_ceil(1_130_000), 2_000_000);
        assert_eq!(quantize_pow2_ceil(12_917_390), 16_000_000);
    }

    /// Raw `C` at the corners §1 derives, and the two properties FL-R20
    /// rests on: it is CONTINUOUS (no snap) and it goes BELOW `SCALE`.
    ///
    /// A quantized `C_q` cannot express either — `quantize_pow2_ceil`
    /// maps the whole young-quiet corner onto `SCALE` — so a relay floor
    /// reading `C_q` can only ever be raised, never lowered, which is the
    /// asymmetry FL-R20 removes.
    #[test]
    fn raw_correction_is_continuous_and_falls_below_one() {
        let p = EconomicParams::default();

        // Baseline volume, no subsidy split, no burn: C is exactly 1.
        assert_eq!(fee_correction(TxVolume::per_block(50), 0, 0, &p), SCALE);

        // Young-quiet corner: M_r at its 0.8 low rail, sigma = 0.15, b = 0.
        // C = 0.8 * 0.85 = 0.68 — BELOW SCALE, which is the half of the
        // range the quantizer erased.
        let quiet = fee_correction(TxVolume::per_block(1), SCALE * 15 / 100, 0, &p);
        assert_eq!(quiet, SCALE * 68 / 100);
        assert!(quiet < SCALE, "raw C must be able to LOWER the floor");

        // Continuity: one transaction more in the window moves C by a
        // hair, not by a factor of two. The quantized scalar's step at a
        // pow2 boundary is what FL-R3 spent two rounds trying to damp.
        let a = fee_correction(TxVolume::window(50 * 720 + 1, 720), 0, 0, &p);
        let b = fee_correction(TxVolume::window(50 * 720 + 2, 720), 0, 0, &p);
        assert!(b >= a, "C is monotone in volume");
        assert!(
            b - a < SCALE / 1000,
            "one tx must move raw C by well under 0.1%, got {} in SCALE units",
            b - a
        );
    }

    /// The quantizer is now a wrapper, and this is the falsifier for that
    /// claim: for every state, `C_q` is exactly the snap of raw `C`. If
    /// the extraction had changed the arithmetic — a clamp applied in a
    /// different order, say — these would part company.
    #[test]
    fn quantized_correction_is_exactly_the_snap_of_the_raw_one() {
        let p = EconomicParams::default();
        let mut stepped = 0usize;
        for v in [1u64, 10, 40, 49, 50, 51, 65, 80, 200] {
            for sigma_pct in [0u64, 5, 15] {
                for burn_pct in [0u64, 10, 50] {
                    let sigma = SCALE * sigma_pct / 100;
                    let burn = SCALE * burn_pct / 100;
                    let raw = fee_correction(TxVolume::per_block(v), sigma, burn, &p);
                    assert_eq!(
                        fee_correction_quantized(TxVolume::per_block(v), sigma, burn, 0, &p),
                        hysteresis_step(raw, 0),
                        "C_q must be the snap of raw C at v={v} sigma={sigma} b={burn}"
                    );
                    if hysteresis_step(raw, 0) != raw {
                        stepped += 1;
                    }
                }
            }
        }
        // Rule 47: if the snap never moved anything, the assertion above
        // would hold for a `hysteresis_step` that is the identity, and
        // this test would be asserting nothing about the quantizer.
        assert!(
            stepped > 0,
            "the sweep must include states the snap actually moves"
        );
    }

    /// The 18-row grid migrated from the deleted C++ KATs
    /// (`tests/unit_tests/fee.cpp` in full, and
    /// `scaling_2021.cpp`'s `fee_2021_scaling.relay_fee`), which tested
    /// `Blockchain::get_dynamic_base_fee` — the inherited
    /// `0.95 · R·w_ref/M²`. FL-R20 deletes the 0.95 and moves the
    /// arithmetic here, so the function they called no longer exists.
    ///
    /// **Every expected value is re-derived from FL-R20, not read off this
    /// code.** A migrated KAT whose values come from the implementation it
    /// is meant to pin asserts only that the code equals itself, which is
    /// exactly how a formula change ships a regression with green tests.
    /// The `old` column is what the C++ assertion held, and it is kept in
    /// the table so the delta is reviewable rather than asserted.
    ///
    /// Only eight of eighteen rows move: below ≈ 80 atomic units the integer
    /// truncation had already absorbed the 5%, so deleting it changes nothing
    /// there. That is also why the 0.95 was easy to overlook — it is invisible
    /// across most of the served range, and every row where it *is* visible is
    /// a row where the old floor under-priced by exactly one twentieth.
    ///
    /// The per-row `old == new - new/20` assertion is the independent check on
    /// the new column: it holds for all eighteen rows, so each new value is the
    /// old one with precisely the 0.95 removed and nothing else.
    #[test]
    fn relay_floor_matches_the_migrated_heritage_grid() {
        const COIN: u64 = 1_000_000_000;
        const ZONE: u64 = 300_000;
        const W_REF: u64 = 3_000;

        // (reward, median, old 0.95 value, new FL-R20 value)
        let grid: [(u64, u64, u64, u64); 18] = [
            (10 * COIN, ZONE, 317, 333),
            (10 * COIN, ZONE / 2, 317, 333),
            (10 * COIN, 1, 317, 333),
            (10 * COIN, 100_000, 317, 333),
            (10 * COIN, 600_000, 79, 83),
            (10 * COIN, 3_000_000, 3, 3),
            (10 * COIN, 6_000_000, 1, 1),
            (COIN, ZONE, 32, 33),
            (COIN, ZONE / 2, 32, 33),
            (COIN, 1, 32, 33),
            (COIN, 600_000, 8, 8),
            (COIN, 3_000_000, 1, 1),
            (3 * COIN / 10, ZONE, 10, 10),
            (3 * COIN / 10, ZONE / 2, 10, 10),
            (3 * COIN / 10, 1, 10, 10),
            (3 * COIN / 10, 600_000, 2, 2),
            (3 * COIN / 10, 3_000_000, 1, 1),
            (1, ZONE, 1, 1),
        ];

        let mut moved = 0usize;
        for &(reward, median, old, new) in &grid {
            // The daemon passes `(effective_median, LTM)`; at the KAT's single
            // median both operands are that median, and the `.max(ZONE)` inside
            // reproduces `get_dynamic_base_fee`'s `min_block_weight` clamp.
            assert_eq!(
                relay_fee_floor(reward, median, median, ZONE, W_REF, SCALE),
                new,
                "FL-R20 floor at reward={reward} median={median} (C = 1)"
            );
            // The old value is the new one less 1/20, floored — the shape of
            // the deletion, asserted rather than asserted-about.
            assert_eq!(new - new / 20, old, "0.95 relation at median={median}");
            if new != old {
                moved += 1;
            }
        }
        // Rule 47: if no row moved, this grid would pass unchanged against the
        // pre-FL-R20 formula and would not be testing the deletion at all.
        assert_eq!(moved, 8, "exactly eight rows move when the 0.95 goes");

        // The very large median the C++ `minimum_fee_floor` case used, kept as
        // its own row because it is the one that proves `max(1)` still binds.
        assert_eq!(
            relay_fee_floor(COIN, 100_000 * ZONE, 100_000 * ZONE, ZONE, W_REF, SCALE),
            1,
            "max(1) is kept: a zero floor admits everything"
        );
    }

    /// **FL-R6's identity, asserted.** The served economy rung and the
    /// relay floor `check_fee` prices from must be the same number for
    /// every state — that is what makes FL-R21's deletion of the
    /// `fees[0] = max(fees[0], floor)` clamp a deletion of a no-op rather
    /// than a behaviour change.
    ///
    /// A clamp deleted because two expressions happen to agree is one edit
    /// away from being wrong. This is the test that notices.
    #[test]
    fn economy_rung_is_the_relay_floor() {
        let coin = 1_000_000_000u64;
        let mut floored = 0usize;
        for &reward in &[1u64, 1_000, 10 * coin, 2_048_000_000_000] {
            for &(mnw, mlw) in &[
                (300_000u64, 300_000u64),
                (15_000_000, 300_000),
                (1_500_000, 1_500_000),
                (300_000, 15_000_000),
                (50_000_000, 50_000_000),
            ] {
                for &c in &[SCALE * 68 / 100, SCALE, 2 * SCALE, 16 * SCALE] {
                    let ladder = corrected_fee_ladder(reward, mnw, mlw, 300_000, 3_000, c);
                    let floor = relay_fee_floor(reward, mnw, mlw, 300_000, 3_000, c);
                    assert_eq!(
                        ladder.economy, floor,
                        "economy != relay floor at reward={reward} mnw={mnw} mlw={mlw} c={c}"
                    );
                    assert_eq!(ladder.standard, floor * 4, "standard must be 4F");
                    if floor == 1 {
                        floored += 1;
                    }
                }
            }
        }
        // Rule 47: `max(1)` is part of the identity, so the sweep has to
        // reach it. Without a state where the floor binds, the identity
        // would be untested exactly where the two expressions could most
        // easily part company.
        assert!(floored > 0, "the sweep must reach the max(1) floor");
    }

    /// **The wire contract: `economy <= standard <= priority`.**
    ///
    /// Every tier-selecting consumer relies on the served slots being
    /// ordered, and `rpc_facts_shims.a_fee_estimate_writes_three_priced_tiers`
    /// asserts it on the C++ side. This is the same contract at the
    /// arithmetic's own level, and it exists because the first version of
    /// this test asserted only `priority >= economy` — which is true, and
    /// is the wrong axis. `standard` is `4F`, so it sits ABOVE economy by
    /// construction, and the rung that can fall below it is `priority`.
    /// The degenerate corner (a reward small enough to truncate every
    /// quotient to zero) produced `[1, 4, 1]` and the weaker assertion
    /// passed on it.
    #[test]
    fn the_served_ladder_is_monotone() {
        let coin = 1_000_000_000u64;
        for &reward in &[1u64, 1_000, 10 * coin, 2_048_000_000_000] {
            for &m in &[300_000u64, 1_500_000, 15_000_000, 50_000_000] {
                for &c in &[SCALE * 68 / 100, SCALE, 16 * SCALE] {
                    let ladder = corrected_fee_ladder(reward, m, m, 300_000, 3_000, c);
                    assert!(
                        ladder.economy <= ladder.standard,
                        "economy {} above standard {} at reward={reward} m={m} c={c}",
                        ladder.economy,
                        ladder.standard
                    );
                    assert!(
                        ladder.standard <= ladder.priority,
                        "standard {} above priority {} at reward={reward} m={m} c={c}",
                        ladder.standard,
                        ladder.priority
                    );
                }
            }
        }

        // The corner that produced `[1, 4, 1]`, pinned so the regression has
        // a name rather than only a property to violate.
        let degenerate = corrected_fee_ladder(1, 300_000, 300_000, 300_000, 3_000, SCALE);
        assert_eq!(
            degenerate.as_slots(),
            [1, 4, 4],
            "every rung truncates to zero here; the floors must still leave a ladder"
        );
    }

    /// The hysteresis band: sitting on a boundary does not flicker; a
    /// decisive move does switch.
    #[test]
    fn correction_hysteresis_holds_the_boundary() {
        let p = EconomicParams::default();
        // v = 51 at zero sigma/burn puts raw C = 1.02 — just past the
        // 2^0 boundary, inside the 3% band of a held C_q = 1.
        assert_eq!(
            fee_correction_quantized(TxVolume::per_block(51), 0, 0, SCALE, &p),
            SCALE
        );
        // Without a previous value it snaps up.
        assert_eq!(
            fee_correction_quantized(TxVolume::per_block(51), 0, 0, 0, &p),
            2 * SCALE
        );
        // A decisive move (v = 65 → M_r = 1.3) leaves the band and steps.
        assert_eq!(
            fee_correction_quantized(TxVolume::per_block(65), 0, 0, SCALE, &p),
            2 * SCALE
        );
        // And a held higher step survives small dips below its boundary.
        assert_eq!(
            fee_correction_quantized(TxVolume::per_block(51), 0, 0, 2 * SCALE, &p),
            2 * SCALE
        );
    }

    /// §10.12.4's KAT: a one-cell fold IS the unseeded snap, and a fold
    /// IS the iterated step — the grid owner adds no mechanism of its own.
    #[test]
    fn hysteresis_fold_is_the_iterated_step() {
        assert_eq!(hysteresis_fold(&[]), None);
        for c in [0, SCALE >> 6, 680_000, SCALE, 1_020_000, 12_917_390] {
            assert_eq!(hysteresis_fold(&[c]), Some(hysteresis_step(c, 0)));
        }
        // Anchor snaps 1.02 → 2 unseeded; the in-band wobble that follows
        // (1.02, 0.99, 1.01) is held at 2 by the band; the decisive dip to
        // 0.9 leaves it. Every intermediate is the step's own answer.
        let span = [1_020_000, 1_020_000, 990_000, 1_010_000, 900_000];
        let mut cq = hysteresis_step(span[0], 0);
        assert_eq!(cq, 2 * SCALE);
        for (i, &c) in span.iter().enumerate().skip(1) {
            cq = hysteresis_step(c, cq);
            assert_eq!(hysteresis_fold(&span[..=i]), Some(cq));
        }
        assert_eq!(hysteresis_fold(&span[..4]), Some(2 * SCALE));
        assert_eq!(hysteresis_fold(&span), Some(SCALE));
    }

    /// A deterministic ensemble of raw-`C` sequences **biased toward the
    /// pow2 boundaries** (where the settled predicate is false and the band
    /// actually does something), so the two theorems below are exercised
    /// on the hard region rather than on samples the snap decides alone.
    fn boundary_biased_sequences() -> Vec<Vec<u64>> {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        (0..200)
            .map(|_| {
                let len = 8 + (next() % 40) as usize;
                (0..len)
                    .map(|_| {
                        let boundary = SCALE << (next() % 6);
                        // ±6 % of a boundary, half the draws inside the 3 % margin.
                        let milli = next() % 121; // 0 ..= 120
                        boundary / 1000 * (940 + milli)
                    })
                    .collect()
            })
            .collect()
    }

    /// §10.14.2's settled-state theorem, as a test rather than a claim: at
    /// a settled sample the band's state is `⌈c⌉₂` from EVERY `prev`, hence
    /// the fold from any settled index equals the full fold.
    #[test]
    fn hysteresis_fold_from_any_settled_index_is_the_full_fold() {
        let mut settled_seen = 0u32;
        let mut unsettled_seen = 0u32;
        for seq in boundary_biased_sequences() {
            let full = hysteresis_fold(&seq);
            for (j, &c) in seq.iter().enumerate() {
                let cq = hysteresis_step(c, 0);
                if hysteresis_settled(c) {
                    settled_seen += 1;
                    for prev in [0, cq / 4, cq / 2, cq, 2 * cq, 4 * cq, SCALE >> 6] {
                        assert_eq!(hysteresis_step(c, prev), cq, "c={c} prev={prev}");
                    }
                    assert_eq!(hysteresis_fold(&seq[j..]), full, "j={j} c={c}");
                } else {
                    unsettled_seen += 1;
                    // The predicate is exact, not conservative: an unsettled
                    // sample really IS held by some neighbour.
                    let held = hysteresis_step(c, 2 * cq) != cq
                        || (cq / 2 >= (SCALE >> 6) && hysteresis_step(c, cq / 2) != cq);
                    assert!(held, "c={c} declared unsettled but no neighbour holds it");
                }
            }
        }
        // The ensemble has to reach both branches or the test proved nothing.
        assert!(
            settled_seen > 500 && unsettled_seen > 500,
            "{settled_seen}/{unsettled_seen}"
        );
    }

    /// §10.14.2's monotonicity invariant for the exact recurrence: the band
    /// over a sequence changes value no more often than the snap of that
    /// sequence does. (The bounded-scan arm can break this only through
    /// its fallback anchor; that is measured in the sim, not asserted here.)
    #[test]
    fn banded_sequence_transitions_never_exceed_snap_transitions() {
        for seq in boundary_biased_sequences() {
            let mut snap_transitions = 0u32;
            let mut band_transitions = 0u32;
            let mut prev_snap = hysteresis_step(seq[0], 0);
            let mut prev_band = prev_snap;
            for &c in &seq[1..] {
                let snap = hysteresis_step(c, 0);
                let band = hysteresis_step(c, prev_band);
                snap_transitions += u32::from(snap != prev_snap);
                band_transitions += u32::from(band != prev_band);
                prev_snap = snap;
                prev_band = band;
            }
            assert!(
                band_transitions <= snap_transitions,
                "{band_transitions} > {snap_transitions}"
            );
        }
    }

    #[test]
    fn round_money_up_two_places_matches_cpp() {
        assert_eq!(round_money_up_2(0), 0);
        assert_eq!(round_money_up_2(99), 99);
        assert_eq!(round_money_up_2(101), 110);
        assert_eq!(round_money_up_2(27_810), 28_000);
        assert_eq!(round_money_up_2(13_653_333), 14_000_000);
    }
}
