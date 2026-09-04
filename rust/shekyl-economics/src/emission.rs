//! Base block subsidy curve (0h) and neutral-trajectory projection (0h′).
//!
//! Matches `get_block_reward` base path in `cryptonote_basic_impl.cpp` before
//! weight penalty and release multiplier.

use crate::params::EconomicParams;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EmissionError {
    #[error("already_generated_coins exceeds money_supply")]
    AlreadyGeneratedExceedsSupply,
    #[error("arithmetic overflow projecting emission")]
    Overflow,
    /// The block exceeds twice the effective median and earns no reward.
    ///
    /// A CONSENSUS REJECTION, not an internal fault: the caller is expected to
    /// reject the block. It is an `Err` rather than `Ok(0)` because a zero
    /// reward is a legitimate result at exactly `2 * median`, and collapsing
    /// the two would make an invalid block indistinguishable from a valid one
    /// that happens to pay nothing.
    #[error("block weight exceeds twice the effective median")]
    BlockTooBig,
}

/// Effective emission speed factor for the configured DAA target block time.
///
/// Returned as `u64` because its sole consumer is the right-shift in
/// `base_block_reward` (`remaining >> esf`), and Rust shifts accept a `u64`
/// shift amount directly. Keeping the value in `u64` avoids a gratuitous
/// narrowing cast.
#[inline]
pub fn emission_speed_factor(params: &EconomicParams) -> u64 {
    debug_assert_eq!(
        params.daa_target_seconds % 60,
        0,
        "DAA target must be a multiple of 60 seconds"
    );
    let target_minutes = params.daa_target_seconds / 60;
    params.emission_speed_factor_per_minute - (target_minutes - 1)
}

/// Tail (minimum) subsidy per block in atomic units.
///
/// `pub` (with [`emission_speed_factor`]) since the FL round: the fee-ladder
/// instrument's degenerate pins consume both, and a local re-derivation
/// there was a third undeclared drift pair (FL round review round 3).
#[inline]
pub fn tail_subsidy_per_block(params: &EconomicParams) -> Result<u64, EmissionError> {
    params
        .final_subsidy_per_minute
        .checked_mul(params.daa_target_seconds / 60)
        .ok_or(EmissionError::Overflow)
}

/// Base block reward before weight penalty and release multiplier (0h).
pub fn base_block_reward(
    already_generated_coins: u64,
    params: &EconomicParams,
) -> Result<u64, EmissionError> {
    if already_generated_coins > params.money_supply {
        return Err(EmissionError::AlreadyGeneratedExceedsSupply);
    }
    let remaining = params.money_supply - already_generated_coins;
    let esf = emission_speed_factor(params);
    let mut base_reward = remaining >> esf;
    let tail = tail_subsidy_per_block(params)?;
    if base_reward < tail {
        base_reward = tail;
    }
    Ok(base_reward)
}

/// Neutral-trajectory `already_generated` at `height` under interpretation (A) (0h′).
///
/// Sum of `base_block_reward` for blocks `0..height` with no release multiplier.
pub fn projected_already_generated(
    height: u64,
    params: &EconomicParams,
) -> Result<u64, EmissionError> {
    let mut ag = 0u64;
    for _ in 0..height {
        let base = base_block_reward(ag, params)?;
        ag = ag.checked_add(base).ok_or(EmissionError::Overflow)?;
        if ag >= params.money_supply {
            return Ok(params.money_supply);
        }
    }
    Ok(ag)
}

/// Neutral base subsidy at `height`: `base_block_reward(projected_already_generated(h))`.
pub fn base_emission_at(height: u64, params: &EconomicParams) -> Result<u64, EmissionError> {
    let ag = projected_already_generated(height, params)?;
    base_block_reward(ag, params)
}

/// Block reward after the median-weight penalty (0h + penalty).
///
/// Ports the arithmetic that lived in `get_block_reward`
/// (`cryptonote_basic_impl.cpp`) — the last economics calculation C++ still
/// performed itself. C++ now marshals to this function through
/// `shekyl_block_reward`.
///
/// The shape, preserved exactly:
///
/// 1. `base = base_block_reward(already_generated_coins)`;
/// 2. the effective median is `max(median_weight, full_reward_zone)` — the
///    "make it soft" clamp;
/// 3. at or below the effective median there is no penalty;
/// 4. above twice it the block is rejected ([`EmissionError::BlockTooBig`]);
/// 5. otherwise `base * (2m - current) * current / m / m`.
///
/// `full_reward_zone` is a PARAMETER rather than a constant read here.
/// `CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5` is a block-policy constant
/// with ~40 consumers across the C++ tree and none in Rust; copying it into a
/// Rust-side constant would create exactly the C++/Rust drift pair that
/// `config/consensus_constants.json` exists to prevent. Passing it keeps one
/// authority. If a second Rust consumer ever appears, it earns an entry in
/// that JSON and this parameter goes away.
///
/// DOMAIN. Step 5 evaluates in `u128` and is EXACT wherever
/// `base * (2m - c) * c` fits there. `base` is bounded by the subsidy curve at
/// ~2^41, and `(2m - c) * c < m^2`, so every median below ~2^43 — block
/// weights around 8 TB, against a 300 KB free zone — is exact. Beyond that the
/// product needs up to ~192 bits and the function returns
/// [`EmissionError::Overflow`] rather than wrapping or panicking. It never
/// panics for any `u64` input; "total" in that sense only.
///
/// WHY NOT REPRODUCE THE C++ WRAP. The original formed `(2m - c) * c` in
/// `uint64_t`, so it wrapped once the median passed ~2^32 and produced a
/// reward derived from truncated garbage. This function does not reproduce
/// that. Pre-genesis there is no chain whose history the wrap defines, so
/// there is nothing to stay bit-compatible WITH — and reproducing it is
/// exactly the failure §5.8's H1 exists to prevent, where a C++-only oracle
/// certifies a latent bug and makes it canonical once the original is
/// deleted. Rule 16: inherited code is not inherited architecture. Rule 20's
/// fourth Rust criterion names silent overflow on amounts as the bug class.
/// `c2a_prime_layer1_penalty_diverges_from_the_legacy_u64_wrap` pins the
/// divergence point so the choice stays visible rather than implicit.
///
/// Beyond the exact domain the result is fail-closed: `Overflow` surfaces as
/// `SHEKYL_BLOCK_REWARD_INVALID` and the block is rejected. A block whose
/// median is measured in terabytes is unreachable under every other weight
/// limit in the system; rejecting is the safe reading of an impossible input,
/// where wrapping would silently mint from truncation.
pub fn block_reward_with_penalty(
    median_weight: u64,
    current_block_weight: u64,
    already_generated_coins: u64,
    full_reward_zone: u64,
    params: &EconomicParams,
) -> Result<u64, EmissionError> {
    let base = base_block_reward(already_generated_coins, params)?;

    // "make it soft" — a median below the free zone is raised to it.
    let median = median_weight.max(full_reward_zone);

    if current_block_weight <= median {
        return Ok(base);
    }
    // `2 * median` in u128: the comparison must not wrap for medians above
    // u64::MAX / 2, which consensus never produces but the FFI edge cannot
    // assume away.
    let double_median = u128::from(median) * 2;
    if u128::from(current_block_weight) > double_median {
        return Err(EmissionError::BlockTooBig);
    }

    let current = u128::from(current_block_weight);
    // Cannot overflow and so is deliberately unguarded: `double_median -
    // current` is below `median <= u64::MAX` (we are past the `current <=
    // median` return), and `current <= 2 * median`, so the product stays under
    // `2 * u64::MAX^2 < u128::MAX`. A `checked_mul` here would add an arm no
    // input can reach, which is untestable by construction.
    let multiplicand = (double_median - current) * current;
    let median = u128::from(median);

    // This one CAN overflow — `base * multiplicand` needs up to ~192 bits once
    // the median passes ~2^43 — so it is checked. Fail closed; do not wrap.
    let numerator = u128::from(base)
        .checked_mul(multiplicand)
        .ok_or(EmissionError::Overflow)?;
    let reward = numerator / median / median;

    // `reward < base` always: `multiplicand = (2m - c) * c` is strictly below
    // `m^2` for every `c` in `(m, 2m]` (it would peak at `c == m`, which the
    // branch above already returned), so dividing by `m^2` cannot reach
    // `base`. `min` makes that bound structural instead of a comment, and
    // `try_from` means a future change to the bound fails loudly rather than
    // wrapping silently — the fallback arm is unreachable today.
    let capped = reward.min(u128::from(base));
    Ok(u64::try_from(capped).unwrap_or(base))
}

/// The block weight limit implied by an effective median: `2 * max(median, zone)`.
///
/// Exposed so a caller that must REPORT the limit it rejected against reads it
/// from the same place the rejection came from, instead of recomputing the
/// clamp and risking a message that disagrees with the decision.
/// Saturating: the true limit above `u64::MAX / 2` is unrepresentable, and a
/// saturated value is only ever used for diagnostics.
pub fn block_weight_limit(median_weight: u64, full_reward_zone: u64) -> u64 {
    median_weight.max(full_reward_zone).saturating_mul(2)
}

/// Cap a block reward at the supply headroom still unminted.
///
/// The emission-side twin of [`advance_already_generated`]: that one stops the
/// running total at `money_supply`, this one stops a single block from
/// exceeding what remains. Both express the same invariant — total emission
/// never passes the cap — so they live together rather than one being C++-side
/// arithmetic and the other Rust.
///
/// `saturating_sub`, not `-`. The C++ this replaces computed
/// `MONEY_SUPPLY - already_generated_coins` in `uint64_t`, which UNDERFLOWS to
/// a near-`u64::MAX` headroom when `already_generated_coins` exceeds the cap,
/// silently disabling the clamp it was written to be. The connect path caps
/// the stored total, so no production caller reaches that today — but
/// `shekyl_base_block_reward` and `shekyl_block_reward` both defend against an
/// out-of-range total explicitly, and leaving one member of the family
/// undefended is how the next caller finds the edge. Rule 20's fourth
/// criterion: this is integer arithmetic on an amount.
pub fn cap_reward_to_remaining_supply(
    reward: u64,
    already_generated_coins: u64,
    params: &EconomicParams,
) -> u64 {
    reward.min(params.money_supply.saturating_sub(already_generated_coins))
}

/// Advance `already_generated_coins` by a block's base reward, capped at supply.
///
/// The supply-advance clamp, previously written out at two C++ call sites
/// (`blockchain.cpp` main-chain connect and alt-chain). Past the cap the total
/// would overflow `u64`; `already_generated_coins` only feeds the subsidy
/// curve, and the curve yields the tail floor at full emission, so saturating
/// is the correct behaviour rather than a defensive guard.
///
/// One entry point for both call sites on purpose — the same
/// division-one-site discipline `config/consensus_constants.json` records for
/// `segment_leaf_count`. Two copies of a consensus clamp are a drift pair
/// waiting to happen.
pub fn advance_already_generated(
    already_generated_coins: u64,
    block_reward: u64,
    params: &EconomicParams,
) -> u64 {
    already_generated_coins
        .saturating_add(block_reward)
        .min(params.money_supply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::EconomicParams;

    #[test]
    fn base_block_reward_matches_cpp_first_values() {
        let p = EconomicParams::default();
        assert_eq!(base_block_reward(0, &p).unwrap(), 2_048_000_000_000_u64);
        assert_eq!(
            base_block_reward(2_048_000_000_000, &p).unwrap(),
            2_047_999_023_437_u64
        );
        assert_eq!(
            base_block_reward(2_756_434_948_434_199_641, &p).unwrap(),
            733_629_392_416_u64
        );
    }

    #[test]
    fn base_block_reward_tail_floor() {
        let p = EconomicParams::default();
        let tail = p.final_subsidy_per_minute * (p.daa_target_seconds / 60);
        let near_max = p.money_supply - ((2 << 20) + 1);
        assert_eq!(base_block_reward(near_max, &p).unwrap(), tail);
    }

    /// FL-V10's red companion, and conjunct (b) of the census-R2 reopen
    /// criterion (`docs/design/FEE_LADDER_DERIVATION.md` §0.1): the
    /// estimate leg (uncapped [`base_block_reward`], the C++ 5-arg path),
    /// the projection leg ([`projected_already_generated`] →
    /// [`base_block_reward`], which saturates clean past exhaustion), and
    /// the validation leg (the same reward through
    /// [`cap_reward_to_remaining_supply`], the 6-arg path) must agree at
    /// the terminal state — they are descriptions of one chain.
    ///
    /// The FL-R12′ oracle in its SIGNED form (review round 8):
    /// `paid = max(M_r·curve(remaining), TAIL) · penalty(x)` — floor on
    /// the paid emission (the multiplier has no object at a perpetual
    /// tail), penalty AFTER the floor (floors belong to emission;
    /// penalties apply to the paid quantity — the governance lever must
    /// always bite), `remaining` floored at zero, the supply cap retired.
    ///
    /// RED TODAY three ways against the shipped composition
    /// (curve → tail floor → penalty → multiplier → cap):
    /// 1. dormancy at `x = 0`, boundary: shipped pays `M_r·TAIL` =
    ///    480 000 000 (then remaining-capped) vs the signed 600 000 000;
    /// 2. tail with `x > 0`: shipped applies the penalty before the
    ///    multiplier and cap (360 000 000 at `x = ½` under dormancy) vs
    ///    the signed `TAIL·(1−x²)` = 450 000 000;
    /// 3. ladder-operand equality: the 5-arg estimate base must equal
    ///    the payer's pre-penalty quantity `R_eff` at every point —
    ///    red mid-curve, where the estimate is unmodulated while the
    ///    payer's quantity carries `M_r`.
    ///
    /// Un-ignore with the FL-R12′ implementation (build authorized at
    /// round 8 upon the record).
    #[test]
    #[ignore = "FL-R12' signed (round 8) but not yet implemented: shipped composition floors the base, penalizes before the multiplier, and caps at remaining"]
    fn terminal_reward_legs_agree() {
        use crate::release::{apply_release_multiplier, calc_release_multiplier};

        let p = EconomicParams::default();
        let tail = tail_subsidy_per_block(&p).unwrap();
        let esf = emission_speed_factor(&p);
        let s = p.money_supply;
        // Dormancy pins the release multiplier at its 0.8 rail — the
        // regime the floor exists for.
        let m_r = calc_release_multiplier(0, p.tx_volume_baseline, p.release_min, p.release_max);
        // The signed contract's pre-penalty quantity.
        let r_eff = |ag: u64| -> u64 {
            let curve = s.saturating_sub(ag) >> esf;
            apply_release_multiplier(curve, m_r).max(tail)
        };

        // Leg 1 — floor on the paid emission at x = 0, both sides of the
        // boundary and past the asymptote.
        let zone = 300_000; // full-reward zone; weight == median ⇒ no penalty
        for ag in [s - tail + 1, s, s + tail] {
            let shipped = {
                let base = block_reward_with_penalty(zone, zone, ag, zone, &p)
                    .unwrap_or_else(|e| panic!("shipped leg errored at ag={ag}: {e:?}"));
                cap_reward_to_remaining_supply(apply_release_multiplier(base, m_r), ag, &p)
            };
            assert_eq!(
                shipped,
                r_eff(ag),
                "paid reward != max(M_r*curve, TAIL) under dormancy at already_generated={ag}"
            );
        }

        // Leg 2 — penalty applies AFTER the floor: at the tail with
        // x = 1/2 (weight = 1.5 * median), the signed contract pays
        // TAIL * (1 - x^2) = TAIL * 3/4.
        let ag = s;
        let (median, weight) = (zone, zone + zone / 2);
        let shipped = {
            let base = block_reward_with_penalty(median, weight, ag, zone, &p)
                .unwrap_or_else(|e| panic!("shipped penalized leg errored: {e:?}"));
            cap_reward_to_remaining_supply(apply_release_multiplier(base, m_r), ag, &p)
        };
        let expected = {
            // penalty(x) in the canonical integer form: (2m - c)*c / m^2.
            let (m, c) = (u128::from(median), u128::from(weight));
            u64::try_from(u128::from(r_eff(ag)) * (2 * m - c) * c / (m * m)).unwrap()
        };
        assert_eq!(
            shipped, expected,
            "penalized tail reward != TAIL*(1-x^2): penalty must compose AFTER the floor"
        );

        // Leg 3 — the ladder's operand equals the payer's pre-penalty
        // quantity everywhere, mid-curve included (kills the V1 class).
        let mid = s / 2;
        assert_eq!(
            base_block_reward(mid, &p).unwrap(),
            r_eff(mid),
            "estimate operand != payer pre-penalty quantity (R_eff) mid-curve under dormancy"
        );
    }

    #[test]
    fn projected_already_generated_at_genesis_is_zero() {
        let p = EconomicParams::default();
        assert_eq!(projected_already_generated(0, &p).unwrap(), 0);
    }

    #[test]
    fn projected_already_generated_height_one() {
        let p = EconomicParams::default();
        assert_eq!(
            projected_already_generated(1, &p).unwrap(),
            base_block_reward(0, &p).unwrap()
        );
    }

    #[test]
    fn base_emission_at_height_zero() {
        let p = EconomicParams::default();
        assert_eq!(
            base_emission_at(0, &p).unwrap(),
            base_block_reward(0, &p).unwrap()
        );
    }

    #[test]
    fn c2a_prime_layer1_base_reward_grid_matches_spec() {
        // Layer-1 leg B (STAGE_1_PR_7 §5.8) — Q_subsidy spec confirmation. The
        // oracle is an INDEPENDENT closed-form re-derivation of the 0h curve
        // `max((money_supply - ag) >> esf, tail)`, NOT a call to
        // `base_block_reward`. A shift/floor regression in the production curve
        // diverges from this oracle, so the assertion is non-tautological.
        let p = EconomicParams::default();
        let esf = p.emission_speed_factor_per_minute - (p.daa_target_seconds / 60 - 1);
        let tail = p.final_subsidy_per_minute * (p.daa_target_seconds / 60);
        let grid = [
            0_u64,
            2_048_000_000_000,
            2_756_434_948_434_199_641,
            p.money_supply - ((2 << 20) + 1), // tail-floor regime
        ];
        for ag in grid {
            let reward = base_block_reward(ag, &p).unwrap();
            let spec = core::cmp::max((p.money_supply - ag) >> esf, tail);
            assert_eq!(
                reward, spec,
                "Q_subsidy diverges from closed-form spec at ag={ag}"
            );
        }
    }

    #[test]
    fn c2a_prime_layer1_per_quantity_split_matches_spec() {
        // Layer-1 leg B (STAGE_1_PR_7 §5.8) — per-quantity spec for the derived
        // emission quantities the dual-leg grid must cover beyond Q_subsidy:
        //   Q_full_emission → {Q_miner_base, Q_staker_emission} → Q_miner_coinbase.
        // Confirms the emission split conserves the full block emission (the
        // property fix α depends on: Component 4 redistributes within Q_full, it
        // does not open a second issuance axis) and that the miner coinbase
        // composes from the split plus the fee-burn miner leg — all independent
        // of the C++ connect path.
        use crate::burn::compute_burn_split;
        use crate::emission_share::{calc_effective_emission_share, split_block_emission};
        use crate::escalation::ScaledShare;
        use crate::params::SCALE;
        use crate::release::{apply_release_multiplier, calc_release_multiplier};

        // Canonical staker-emission constants (mirror config/economics_params.json;
        // not in EconomicParams, stated here as spec-oracle literals per the
        // existing emission_share test style).
        const STAKER_EMISSION_SHARE: u64 = 150_000; // 15%
        const STAKER_EMISSION_DECAY: u64 = 900_000; // 0.90 / year
        const BLOCKS_PER_YEAR: u64 = 262_800;

        let p = EconomicParams::default();
        let ag_grid = [0_u64, 2_048_000_000_000, 2_756_434_948_434_199_641];
        let height_grid = [
            1_u64,
            BLOCKS_PER_YEAR / 2,
            BLOCKS_PER_YEAR,
            5 * BLOCKS_PER_YEAR,
        ];

        for ag in ag_grid {
            // Q_subsidy → Q_full_emission. Empty-block volume 0 clamps the release
            // multiplier to RELEASE_MIN, matching the live chain's accumulation.
            let q_subsidy = base_block_reward(ag, &p).unwrap();
            let mult =
                calc_release_multiplier(0, p.tx_volume_baseline, p.release_min, p.release_max);
            let q_full = apply_release_multiplier(q_subsidy, mult);

            for h in height_grid {
                let share = calc_effective_emission_share(
                    h,
                    0,
                    STAKER_EMISSION_SHARE,
                    STAKER_EMISSION_DECAY,
                    BLOCKS_PER_YEAR,
                );
                let (q_miner_base, q_staker_emission) = split_block_emission(q_full, share);

                // Conservation — the distinguishing property of Q4_spec vs Q4_cpp.
                assert_eq!(
                    q_miner_base + q_staker_emission,
                    q_full,
                    "emission split not conservative at ag={ag} h={h}"
                );
                // Spec staker leg: floor(Q_full * share / SCALE). share ≤ SCALE,
                // so the quotient ≤ q_full ≤ u64::MAX — the conversion is infallible.
                let spec_staker =
                    u64::try_from(u128::from(q_full) * u128::from(share) / u128::from(SCALE))
                        .expect("staker leg ≤ q_full ≤ u64::MAX");
                assert_eq!(
                    q_staker_emission, spec_staker,
                    "Q_staker_emission off-spec at ag={ag} h={h}"
                );
                // Pre-decay heights carve out a positive staker share, so the full
                // emission strictly exceeds the miner share. This is exactly what
                // the live Layer-3 cap invariant relies on to catch the overwrite.
                if share > 0 && q_full > 0 {
                    assert!(
                        q_full > q_miner_base,
                        "no staker carve-out at ag={ag} h={h}"
                    );
                }

                // Q_miner_coinbase = Q_miner_base + miner fee income. Fee-free block
                // (the Layer-3 scenario) collapses to Q_miner_base; a fee-bearing
                // block adds the burn miner leg.
                let floor_share = ScaledShare::from_raw(p.staker_pool_share);
                assert_eq!(
                    q_miner_base,
                    q_miner_base + compute_burn_split(0, 0, floor_share).miner_fee_income,
                    "fee-free Q_miner_coinbase must equal Q_miner_base at ag={ag} h={h}"
                );
                let fees = 1_000_000_000_u64;
                let burn = compute_burn_split(fees, p.burn_cap, floor_share);
                let q_miner_coinbase = q_miner_base + burn.miner_fee_income;
                assert!(
                    q_miner_coinbase >= q_miner_base && burn.miner_fee_income <= fees,
                    "Q_miner_coinbase composition invalid at ag={ag} h={h}"
                );
            }
        }
    }

    #[test]
    fn c2a_prime_layer2_b_accum_matches_projected_already_generated() {
        let p = EconomicParams::default();
        let mut ag = 0_u64;
        for height in 0..1000 {
            assert_eq!(ag, projected_already_generated(height, &p).unwrap());
            let q_full = base_block_reward(ag, &p).unwrap();
            ag = ag.saturating_add(q_full).min(p.money_supply);
        }
    }

    /// The C2a′ weight-penalty transition KAT — the SAME vectors asserted by
    /// `EconomicsC2aPrime.Layer1WeightPenaltyPinnedVectors` in
    /// `tests/unit_tests/economics_c2a_prime.cpp`.
    ///
    /// Duplicated across the language boundary deliberately. These vectors
    /// pinned the C++ implementation before the penalty moved here; asserting
    /// them only from C++ would let the pin die with the C++ tests, and
    /// asserting them only here would not prove the move preserved behaviour.
    /// Both copies must be edited together, and a divergence between them is
    /// the signal the KAT exists to raise.
    ///
    /// Layout: (median_weight, current_block_weight, already_generated_coins,
    /// expect_ok, expect_reward). `expect_reward` is meaningless when
    /// `expect_ok` is false.
    #[test]
    fn c2a_prime_layer1_weight_penalty_pinned_vectors() {
        const ZONE: u64 = 300_000; // CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5
        const VECTORS: &[(u64, u64, u64, bool, u64)] = &[
            (0, 150000, 0, true, 2048000000000),
            (0, 150000, 2048000000000, true, 2047999023437),
            (0, 150000, 2756434948434199641, true, 733629392416),
            (0, 300000, 0, true, 2048000000000),
            (0, 300000, 2048000000000, true, 2047999023437),
            (0, 300000, 2756434948434199641, true, 733629392416),
            (0, 300001, 0, true, 2047999999977),
            (0, 300001, 2048000000000, true, 2047999023414),
            (0, 300001, 2756434948434199641, true, 733629392407),
            (0, 337500, 0, true, 2016000000000),
            (0, 337500, 2048000000000, true, 2015999038695),
            (0, 337500, 2756434948434199641, true, 722166433159),
            (0, 450000, 0, true, 1536000000000),
            (0, 450000, 2048000000000, true, 1535999267577),
            (0, 450000, 2756434948434199641, true, 550222044312),
            (0, 562500, 0, true, 480000000000),
            (0, 562500, 2048000000000, true, 479999771118),
            (0, 562500, 2756434948434199641, true, 171944388847),
            (0, 599999, 0, true, 13653310),
            (0, 599999, 2048000000000, true, 13653304),
            (0, 599999, 2756434948434199641, true, 4890854),
            (0, 600000, 0, true, 0),
            (0, 600000, 2048000000000, true, 0),
            (0, 600000, 2756434948434199641, true, 0),
            (0, 600001, 0, false, 0),
            (0, 600001, 2048000000000, false, 0),
            (0, 600001, 2756434948434199641, false, 0),
            (300000, 150000, 0, true, 2048000000000),
            (300000, 150000, 2048000000000, true, 2047999023437),
            (300000, 150000, 2756434948434199641, true, 733629392416),
            (300000, 300000, 0, true, 2048000000000),
            (300000, 300000, 2048000000000, true, 2047999023437),
            (300000, 300000, 2756434948434199641, true, 733629392416),
            (300000, 300001, 0, true, 2047999999977),
            (300000, 300001, 2048000000000, true, 2047999023414),
            (300000, 300001, 2756434948434199641, true, 733629392407),
            (300000, 337500, 0, true, 2016000000000),
            (300000, 337500, 2048000000000, true, 2015999038695),
            (300000, 337500, 2756434948434199641, true, 722166433159),
            (300000, 450000, 0, true, 1536000000000),
            (300000, 450000, 2048000000000, true, 1535999267577),
            (300000, 450000, 2756434948434199641, true, 550222044312),
            (300000, 562500, 0, true, 480000000000),
            (300000, 562500, 2048000000000, true, 479999771118),
            (300000, 562500, 2756434948434199641, true, 171944388847),
            (300000, 599999, 0, true, 13653310),
            (300000, 599999, 2048000000000, true, 13653304),
            (300000, 599999, 2756434948434199641, true, 4890854),
            (300000, 600000, 0, true, 0),
            (300000, 600000, 2048000000000, true, 0),
            (300000, 600000, 2756434948434199641, true, 0),
            (300000, 600001, 0, false, 0),
            (300000, 600001, 2048000000000, false, 0),
            (300000, 600001, 2756434948434199641, false, 0),
            (2100000, 1050000, 0, true, 2048000000000),
            (2100000, 1050000, 2048000000000, true, 2047999023437),
            (2100000, 1050000, 2756434948434199641, true, 733629392416),
            (2100000, 2100000, 0, true, 2048000000000),
            (2100000, 2100000, 2048000000000, true, 2047999023437),
            (2100000, 2100000, 2756434948434199641, true, 733629392416),
            (2100000, 2100001, 0, true, 2047999999999),
            (2100000, 2100001, 2048000000000, true, 2047999023436),
            (2100000, 2100001, 2756434948434199641, true, 733629392415),
            (2100000, 2362500, 0, true, 2016000000000),
            (2100000, 2362500, 2048000000000, true, 2015999038695),
            (2100000, 2362500, 2756434948434199641, true, 722166433159),
            (2100000, 3150000, 0, true, 1536000000000),
            (2100000, 3150000, 2048000000000, true, 1535999267577),
            (2100000, 3150000, 2756434948434199641, true, 550222044312),
            (2100000, 3937500, 0, true, 480000000000),
            (2100000, 3937500, 2048000000000, true, 479999771118),
            (2100000, 3937500, 2756434948434199641, true, 171944388847),
            (2100000, 4199999, 0, true, 1950475),
            (2100000, 4199999, 2048000000000, true, 1950474),
            (2100000, 4199999, 2756434948434199641, true, 698694),
            (2100000, 4200000, 0, true, 0),
            (2100000, 4200000, 2048000000000, true, 0),
            (2100000, 4200000, 2756434948434199641, true, 0),
            (2100000, 4200001, 0, false, 0),
            (2100000, 4200001, 2048000000000, false, 0),
            (2100000, 4200001, 2756434948434199641, false, 0),
        ];

        let p = EconomicParams::default();
        let mut penalty_bearing = 0usize;
        let mut rejected = 0usize;

        for &(median, current, ag, expect_ok, expect_reward) in VECTORS {
            match block_reward_with_penalty(median, current, ag, ZONE, &p) {
                Ok(reward) => {
                    assert!(
                        expect_ok,
                        "median={median} current={current} ag={ag}: expected rejection"
                    );
                    assert_eq!(
                        reward, expect_reward,
                        "median={median} current={current} ag={ag}"
                    );
                    if reward != base_block_reward(ag, &p).unwrap() {
                        penalty_bearing += 1;
                    }
                }
                Err(EmissionError::BlockTooBig) => {
                    assert!(
                        !expect_ok,
                        "median={median} current={current} ag={ag}: unexpected rejection"
                    );
                    rejected += 1;
                }
                Err(e) => panic!("median={median} current={current} ag={ag}: {e}"),
            }
        }

        // The table must reach the arithmetic it claims to pin (rule 47).
        assert!(
            penalty_bearing > 0,
            "no vector exercises the weight penalty"
        );
        assert!(rejected > 0, "no vector exercises the reject arm");
    }

    /// The C++ table pins the CONSENSUS-REACHABLE region. These pin the
    /// function's behaviour at the u64 extremes, which C++ never reaches and
    /// which therefore must NOT be added to the shared vector table.
    ///
    /// "Never panics" — not "always exact". Past the exact domain the
    /// function reports `Overflow`; the last case pins that, and pins that it
    /// is an error rather than a panic or a wrap.
    #[test]
    fn block_reward_with_penalty_never_panics_at_u64_extremes() {
        let p = EconomicParams::default();
        const ZONE: u64 = 300_000;

        // A median above u64::MAX/2: `2 * median` is not representable in u64.
        // current = u64::MAX then sits JUST BELOW the doubled median, i.e. deep
        // in the penalty band where the reward rounds to zero — it is accepted,
        // not rejected. A u64 doubling would wrap to 0 here and reject every
        // block instead, so this pins the u128 comparison specifically.
        let huge = u64::MAX / 2 + 1;
        assert_eq!(
            block_reward_with_penalty(huge, u64::MAX, 0, ZONE, &p).unwrap(),
            0
        );

        // One weight above the doubled median IS rejected, and computing that
        // boundary must not wrap either. `huge * 2 == u64::MAX + 1`, so no u64
        // current can exceed it: the whole domain is accepted at this median.
        assert!(block_reward_with_penalty(huge - 1, u64::MAX, 0, ZONE, &p).is_err());

        // Maximum median with maximum weight: current <= median, so the base
        // reward is returned untouched. No panic, no overflow.
        assert_eq!(
            block_reward_with_penalty(u64::MAX, u64::MAX, 0, ZONE, &p).unwrap(),
            base_block_reward(0, &p).unwrap()
        );

        // already_generated_coins beyond the supply cap is the FFI's clamp
        // responsibility, not this function's: it reports the domain error
        // rather than silently saturating.
        assert!(block_reward_with_penalty(0, ZONE, u64::MAX, ZONE, &p).is_err());

        // Past the exact domain: `base * (2m - c) * c` needs more than 128
        // bits. Before this was checked it PANICKED here in debug builds and
        // wrapped in release, while the doc comment claimed totality —
        // observed, not reasoned about. Now it fails closed.
        let m: u64 = 1 << 48;
        assert_eq!(
            block_reward_with_penalty(m, m + m / 2, 0, ZONE, &p),
            Err(EmissionError::Overflow)
        );
    }

    /// The deliberate divergence from the legacy C++ arithmetic, pinned so the
    /// decision stays visible.
    ///
    /// The C++ original formed `(2m - c) * c` in `uint64_t`. Past a median of
    /// ~2^32 that product wraps, and the reward derived from it is garbage.
    /// This crate computes the same expression exactly, so the two disagree in
    /// that region — deliberately, per rule 16 and rule 20's overflow
    /// criterion, and safely because pre-genesis no chain history depends on
    /// the wrapped values.
    ///
    /// The wrapped value is recomputed here with `wrapping_mul` rather than
    /// asserted from memory, so the test shows the divergence instead of
    /// claiming it. This is Rust-only: the shared 81-vector table pins the
    /// TRANSITION and every one of its rows sits where the two agree.
    #[test]
    fn c2a_prime_layer1_penalty_diverges_from_the_legacy_u64_wrap() {
        let p = EconomicParams::default();
        const ZONE: u64 = 300_000;

        // 2^33 median, block at 1.5x: the legacy multiplicand is
        // 0.75 * 2^66, which is exactly 0 modulo 2^64 — the most legible
        // possible divergence, since the legacy path pays nothing at all.
        let m: u64 = 1 << 33;
        let c: u64 = m + m / 2;

        let legacy_multiplicand = (2u64.wrapping_mul(m).wrapping_sub(c)).wrapping_mul(c);
        assert_eq!(legacy_multiplicand, 0, "fixture must sit on the wrap point");

        let base = base_block_reward(0, &p).unwrap();
        let legacy_reward = u64::try_from(
            u128::from(base) * u128::from(legacy_multiplicand) / u128::from(m) / u128::from(m),
        )
        .expect("legacy reward is bounded by base");
        assert_eq!(legacy_reward, 0, "the legacy path pays nothing here");

        // Exact: (2m - c) * c = 0.5m * 1.5m = 0.75 m^2, so reward = 0.75 base.
        let exact = block_reward_with_penalty(m, c, 0, ZONE, &p).unwrap();
        assert_eq!(exact, base / 4 * 3);
        assert_ne!(exact, legacy_reward, "this test exists to pin a divergence");
    }

    /// The exact/overflow boundary, from both sides.
    ///
    /// Copilot's review asked for vectors "around the 64-bit multiplicand
    /// boundary". The multiplicand crossing 2^64 is not itself the boundary —
    /// `u128` absorbs that — so these pin the boundary that IS real: where
    /// `base * multiplicand` leaves `u128`.
    #[test]
    fn block_reward_with_penalty_exact_domain_boundary() {
        let p = EconomicParams::default();
        const ZONE: u64 = 300_000;
        let base_u64 = base_block_reward(0, &p).unwrap();
        let base = u128::from(base_u64);

        // Walk medians upward at a fixed 1.5x block and find the first median
        // whose product leaves u128; assert exact below it, Overflow at it.
        let mut first_overflow: Option<u64> = None;
        for shift in 30..56u32 {
            let m: u64 = 1 << shift;
            let c: u64 = m + m / 2;
            let multiplicand = (u128::from(m) * 2 - u128::from(c)) * u128::from(c);
            let fits = base.checked_mul(multiplicand).is_some();
            let got = block_reward_with_penalty(m, c, 0, ZONE, &p);
            if fits {
                assert!(got.is_ok(), "median 2^{shift} should be exact");
                assert_eq!(got.unwrap(), base_u64 / 4 * 3, "2^{shift}");
            } else {
                assert_eq!(got, Err(EmissionError::Overflow), "median 2^{shift}");
                first_overflow.get_or_insert(m);
            }
        }
        assert!(
            first_overflow.is_some(),
            "the sweep must cross the boundary, or it pins nothing"
        );
    }

    #[test]
    fn block_weight_limit_reports_the_effective_double_median() {
        assert_eq!(block_weight_limit(0, 300_000), 600_000);
        assert_eq!(block_weight_limit(2_100_000, 300_000), 4_200_000);
        // Saturating rather than wrapping — diagnostics only.
        assert_eq!(block_weight_limit(u64::MAX, 300_000), u64::MAX);
    }

    #[test]
    fn cap_reward_to_remaining_supply_does_not_underflow_past_the_cap() {
        let p = EconomicParams::default();
        // Normal: plenty of headroom, the reward passes through.
        assert_eq!(cap_reward_to_remaining_supply(100, 0, &p), 100);
        // At the headroom exactly.
        assert_eq!(
            cap_reward_to_remaining_supply(100, p.money_supply - 100, &p),
            100
        );
        // Above it: capped to what remains.
        assert_eq!(
            cap_reward_to_remaining_supply(100, p.money_supply - 10, &p),
            10
        );
        // AT the cap: nothing remains, so nothing is paid.
        assert_eq!(cap_reward_to_remaining_supply(100, p.money_supply, &p), 0);
        // PAST the cap — the case the C++ `MONEY_SUPPLY - ag` got wrong. There
        // it underflowed to a near-u64::MAX headroom and the clamp silently
        // did nothing; here it saturates to zero headroom and pays nothing.
        assert_eq!(
            cap_reward_to_remaining_supply(100, p.money_supply + 1, &p),
            0
        );
        assert_eq!(cap_reward_to_remaining_supply(u64::MAX, u64::MAX, &p), 0);
    }

    /// The supply-advance clamp, pinned at the boundary the two former C++
    /// copies had to agree on.
    #[test]
    fn advance_already_generated_saturates_at_money_supply() {
        let p = EconomicParams::default();
        assert_eq!(advance_already_generated(0, 100, &p), 100);
        // Exactly at the cap with a nonzero reward stays at the cap.
        assert_eq!(
            advance_already_generated(p.money_supply, 1, &p),
            p.money_supply
        );
        // Crossing the cap lands on it, not past it.
        assert_eq!(
            advance_already_generated(p.money_supply - 1, 50, &p),
            p.money_supply
        );
        // u64 overflow saturates before the supply cap is applied.
        assert_eq!(
            advance_already_generated(u64::MAX, u64::MAX, &p),
            p.money_supply
        );
    }
}
