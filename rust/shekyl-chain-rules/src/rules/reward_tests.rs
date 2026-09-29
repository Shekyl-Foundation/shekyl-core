// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-F14 / F14b / F16 / G12 — the reward chain at F14's inclusive bound,
//! the penalty on the paid quantity, the split's genesis arm, the
//! accumulator, and the verdict carrying all of it.
//!
//! The bound under test is a **relationship**, `2 × M`
//! (`blockchain.cpp:6099`, `m_current_block_cumul_weight_limit =
//! m_current_block_cumul_weight_median * 2`), and the value it takes here
//! follows `M`, which follows the zone (`consensus_constants.json`,
//! `CONSENSUS_C2_R2_WEIGHT_FEES.md` Q1). No test below names `600 000`.

use super::*;
use crate::block::Candidate;
use crate::census::CenRow;
use crate::fault::FormAttempt;
use crate::harness::fixture::{
    candidate, candidate_on, chain_of, listed_on, point_at, spendable_chain,
};
use crate::harness::{assert_refused, expected_seed, judged, Faulted, MockChain, MockSubstrate};
use crate::rule_set::RuleSet;
use crate::rules::block_weight::{EffectiveMedian, Weights};
use crate::rules::miner::Emission;
use crate::trust::Trust;
use crate::validate::{form, validate};
use crate::verdict::InvalidBlock;
use shekyl_economics::{effective_emission, FULL_REWARD_ZONE};
use shekyl_types::{BlockWeight, LongTermWeight};

const ZONE: u64 = FULL_REWARD_ZONE;

/// Weights whose medians are both `M`, at block weight `w`.
fn weights(m: u64, w: u64) -> Weights {
    Weights {
        medians: EffectiveMedian {
            long_term_effective_median: LongTermWeight::from_raw(m),
            effective_median: BlockWeight::from_raw(m),
        },
        weight: BlockWeight::from_raw(w),
        long_term_weight: LongTermWeight::from_raw(w),
    }
}

/// The emission the 4.F definitions price at `connecting` on `chain`.
fn emission_on(chain: &MockChain, connecting: u64) -> Emission {
    chain.with_view(|view| {
        let mut unrecorded = RuleCoverage::EMPTY;
        judged(Emission::derive(
            &view,
            BlockHeight::from_raw(connecting),
            &mut unrecorded,
        ))
    })
}

fn judge(chain: &MockChain, connecting: u64, w: Weights) -> Verdict<PaidEmission> {
    judge_paying(chain, connecting, w, None)
}

/// [`judge`] with the coinbase's first output paying `amount` when given
/// — the genesis arm reads the configured total off the coinbase.
fn judge_paying(
    chain: &MockChain,
    connecting: u64,
    w: Weights,
    amount: Option<u64>,
) -> Verdict<PaidEmission> {
    let emission = emission_on(chain, connecting);
    let mut miner = candidate_on(chain, Vec::new()).block.miner_transaction;
    if let Some(amount) = amount {
        miner.prefix.outputs[0].amount = amount;
    }
    let mut coverage = RuleCoverage::EMPTY;
    let verdict = judge_emission(
        BlockHeight::from_raw(connecting),
        &emission,
        &w,
        &miner,
        &mut coverage,
    );
    if verdict.is_ok() {
        for row in [CenRow::F14, CenRow::F14b, CenRow::F16, CenRow::G12] {
            assert!(coverage.contains(row), "{row} recorded on the passing path");
        }
    }
    verdict
}

// ---------------------------------------------------------------------------
// F14: the inclusive bound at 2 × M
// ---------------------------------------------------------------------------

/// Exactly twice the median is **accepted** and pays **zero** (the recorded
/// divergence from the inherited exclusive bound, census F14); one byte
/// over is refused on F14 at `Locus::Block`. The pair is asserted together
/// so an off-by-one in the bound fails here.
#[test]
fn f14_a_block_at_exactly_twice_the_median_pays_zero_and_one_over_is_refused() {
    let chain = chain_of(3);
    let m = ZONE;
    let at_bound = judge(&chain, 3, weights(m, 2 * m)).expect("at the bound: accepted");
    assert_eq!(at_bound.paid, AtomicUnits::ZERO, "zero subsidy at 2 × M");
    assert_eq!(at_bound.split.miner_emission, 0);
    assert_eq!(at_bound.split.staker_emission, 0);
    assert_refused(
        judge(&chain, 3, weights(m, 2 * m + 1)),
        CenRow::F14,
        Locus::Block,
    );
}

/// The bound moves with `M`, not with the zone: a higher median admits a
/// heavier block, and the same weight that was refused under the zone's
/// median is accepted under a doubled one.
#[test]
fn f14_the_bound_is_twice_the_effective_median_in_force() {
    let chain = chain_of(3);
    let heavy = 2 * ZONE + 1;
    assert_refused(
        judge(&chain, 3, weights(ZONE, heavy)),
        CenRow::F14,
        Locus::Block,
    );
    judge(&chain, 3, weights(2 * ZONE, heavy))
        .expect("under a doubled median the same weight passes");
}

// ---------------------------------------------------------------------------
// F14b: the penalty on the paid quantity
// ---------------------------------------------------------------------------

/// At or below the median the full effective emission is paid; above it
/// the quadratic penalty `paid · (2m − w) · w / m²` applies, strictly
/// decreasing to zero at `2m`. The reference is `shekyl_economics`'
/// own effective emission, so the test pins the *composition* (penalty
/// after the floor, FL-R12′) and not a re-derivation of the curve.
#[test]
fn f14b_the_penalty_is_zero_through_the_median_and_quadratic_above_it() {
    let chain = chain_of(3);
    let m = ZONE;
    let emission = emission_on(&chain, 3);
    let full = match emission.subsidy() {
        Subsidy::Derived { effective, .. } => effective.to_raw(),
        Subsidy::Configured => unreachable!("height 3 is derived"),
    };
    assert_eq!(
        full,
        effective_emission(
            emission.parent_coins_generated().to_raw(),
            emission.tx_volume(),
            economics()
        )
        .expect("priced"),
        "F15's value is the operand"
    );
    let paid_at = |w: u64| {
        judge(&chain, 3, weights(m, w))
            .expect("accepted")
            .paid
            .to_raw()
    };
    assert_eq!(paid_at(1), full);
    assert_eq!(paid_at(m), full, "exactly the median pays in full");
    let just_over = paid_at(m + 1);
    assert!(just_over < full, "one byte over the median is penalised");
    let expected = u128::from(full) * u128::from(2 * m - (m + 1)) * u128::from(m + 1)
        / u128::from(m)
        / u128::from(m);
    assert_eq!(u128::from(just_over), expected, "the quadratic, in u128");
    let half_way = paid_at(m + m / 2);
    assert!(half_way < just_over && half_way > 0);
    assert_eq!(paid_at(2 * m), 0);
}

// ---------------------------------------------------------------------------
// F16 and G12
// ---------------------------------------------------------------------------

/// The split is `compute_emission_split` over the **paid** reward at the
/// connecting height and CEN-F21's epoch: the legs sum to the paid amount,
/// and a penalised block splits the penalised figure, not the full one.
#[test]
fn f16_splits_the_paid_reward_at_the_epoch() {
    let chain = chain_of(3);
    let m = ZONE;
    let full = judge(&chain, 3, weights(m, m)).expect("accepted");
    let penalised = judge(&chain, 3, weights(m, m + m / 2)).expect("accepted");
    for paid in [&full, &penalised] {
        assert_eq!(
            paid.split.miner_emission + paid.split.staker_emission,
            paid.paid.to_raw(),
            "the legs sum to the paid reward"
        );
        assert_eq!(
            paid.split,
            shekyl_economics::compute_emission_split(
                paid.paid.to_raw(),
                3,
                EMISSION_SPLIT_EPOCH.to_raw()
            )
        );
    }
    assert!(penalised.split.miner_emission < full.split.miner_emission);
}

/// G12: the parent's accumulator plus the **paid** reward — the penalised
/// figure, as the C++ advances by `base_reward` after `get_block_reward`.
#[test]
fn g12_advances_the_parent_accumulator_by_the_paid_reward() {
    let chain = chain_of(3);
    let parent = emission_on(&chain, 3).parent_coins_generated();
    let m = ZONE;
    let penalised = judge(&chain, 3, weights(m, m + m / 2)).expect("accepted");
    assert_eq!(
        penalised.coins_generated.to_raw(),
        parent.to_raw() + penalised.paid.to_raw()
    );
    assert!(penalised.coins_generated > parent);
}

// ---------------------------------------------------------------------------
// Genesis
// ---------------------------------------------------------------------------

/// At height 0 the configured emission stands: F14 is recorded vacuous
/// (no bound is evaluated, whatever the weight), the paid amount is the
/// coinbase's total, the split is the whole of it to the miner (G13's
/// arm), and the accumulator starts at it.
#[test]
fn at_genesis_the_configured_emission_stands_unbounded_and_unsplit() {
    let chain = MockChain::default();
    // The fixture coinbase pays zero; name a configured amount so the
    // three equalities below are not `0 == 0`.
    let configured = 7_000_000_000u64;
    let fixture_pays: u64 = candidate(Vec::new())
        .block
        .miner_transaction
        .prefix
        .outputs
        .iter()
        .map(|o| o.amount)
        .sum();
    assert_eq!(fixture_pays, 0, "the fixture's own amount is zero");
    // A weight far over any bound: F14 does not apply at genesis.
    let paid = judge_paying(&chain, 0, weights(ZONE, 10 * ZONE), Some(configured))
        .expect("genesis is not bounded");
    assert_eq!(paid.paid.to_raw(), configured);
    assert_eq!(paid.split.miner_emission, configured);
    assert_eq!(paid.split.staker_emission, 0);
    assert_eq!(paid.coins_generated.to_raw(), configured);
}

// ---------------------------------------------------------------------------
// Through `validate`: the verdict carries the chain's output
// ---------------------------------------------------------------------------

fn validated_on(chain: &MockChain, candidate: Candidate) -> Verdict<(Weights, PaidEmission)> {
    let formed = match form(
        candidate,
        &RuleSet::GENESIS,
        &MockSubstrate::default(),
        expected_seed(chain),
        FormAttempt::FIRST,
    ) {
        Ok(Ok(formed)) => formed,
        Ok(Err(refused)) => return Err(refused),
        Err(Faulted) => unreachable!("the default MockSubstrate never faults"),
    };
    chain.with_view(|view| {
        judged(validate(
            formed,
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .map(|valid| {
            for row in [CenRow::F14, CenRow::F14b, CenRow::F16, CenRow::G12] {
                assert!(valid.coverage().contains(row), "{row} recorded");
            }
            (*valid.block().weights(), *valid.block().emission())
        })
    })
}

/// A light block through `validate` pays the full emission and advances
/// the accumulator by it; the verdict carries both.
#[test]
fn the_verdict_carries_the_paid_emission() {
    let chain = spendable_chain();
    let body = listed_on(&chain, point_at(9));
    let (w, paid) = validated_on(&chain, candidate_on(&chain, vec![body])).expect("valid");
    assert!(w.weight.to_raw() < ZONE);
    let emission = emission_on(&chain, chain.tip().expect("tip").height.to_raw() + 1);
    let full = match emission.subsidy() {
        Subsidy::Derived { effective, .. } => effective,
        Subsidy::Configured => unreachable!(),
    };
    assert_eq!(paid.paid, full);
    assert_eq!(
        paid.coins_generated.to_raw(),
        emission.parent_coins_generated().to_raw() + full.to_raw()
    );
}

/// F14 through `validate`: enough listed bodies to put the block over
/// twice the zone is refused on F14 at `Locus::Block` — after every body
/// passed its own rows (the refusal is the block's, not a slot's) — and
/// the same chain one body lighter connects with a penalised, non-zero
/// reward.
#[test]
fn f14_an_overweight_block_is_refused_at_the_block_after_every_body_passed() {
    let chain = spendable_chain();
    let one = listed_on(&chain, point_at(1000));
    let body_weight = u64::try_from(one.weight()).expect("fits");
    let limit = 2 * ZONE;
    // Bodies enough to cross the limit, each with its own key image.
    let needed = limit / body_weight + 1;
    let bodies: Vec<Transaction> = (0..needed)
        .map(|k| listed_on(&chain, point_at(1000 + k)))
        .collect();
    let total: u64 = bodies
        .iter()
        .map(|b| u64::try_from(b.weight()).expect("fits"))
        .sum();
    assert!(
        total > limit,
        "the fixture crosses the bound: {total} > {limit}"
    );
    match validated_on(&chain, candidate_on(&chain, bodies.clone())) {
        Err(InvalidBlock { rule, locus }) => {
            assert_eq!(rule, CenRow::F14);
            assert_eq!(locus, Locus::Block);
        }
        Ok(_) => panic!("a block over twice the median must be refused"),
    }
    // Drop bodies until the block is inside the bound but over the median.
    let mut lighter = bodies;
    while lighter
        .iter()
        .map(|b| u64::try_from(b.weight()).expect("fits"))
        .sum::<u64>()
        > limit - 2_000
    {
        lighter.pop();
    }
    let (w, paid) = validated_on(&chain, candidate_on(&chain, lighter)).expect("inside the bound");
    assert!(w.weight.to_raw() <= limit && w.weight.to_raw() > ZONE);
    assert!(paid.paid > AtomicUnits::ZERO, "penalised, not zeroed");
}
