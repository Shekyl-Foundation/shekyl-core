// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Negative fixtures for the PoW half of 4.D (`CHAIN_RULES_SLICE_2.md` §5):
//! D1 refuses a hash above the target; D1b is the ported comparison, driven
//! by an oracle vector through the rule; D2 is computed in `form` and a
//! verifier fault is a fault; D3 verifies the claimed seed at the epoch
//! boundaries and a stale seed is `Stale::Seed` with a bounded retry.

use super::*;
use crate::fault::{FormAttempt, Retry};
use crate::harness::fixture::{candidate_on, chain_of};
use crate::harness::{assert_refused, expected_seed, judged, Faulted, MockChain, MockSubstrate};
use crate::rule_set::RuleSet;
use crate::trust::Trust;
use crate::validate::{form, validate};
use crate::verdict::ChainValid;
use crate::view::AtHeight;
use shekyl_difficulty::{check_hash, Difficulty, GENESIS_DIFFICULTY};

/// Both stages over `chain` with `substrate`, claiming `seed`, at `attempt`.
fn judge_with(
    chain: &MockChain,
    substrate: &MockSubstrate,
    seed: BlockHash,
    attempt: FormAttempt,
) -> Result<Verdict<()>, Fault<core::convert::Infallible>> {
    let candidate = candidate_on(chain, Vec::new());
    let formed = match form(candidate, &RuleSet::GENESIS, substrate, seed, attempt) {
        Ok(Ok(formed)) => formed,
        Ok(Err(refused)) => return Ok(Err(refused)),
        Err(Faulted) => unreachable!("the mock substrate never faults here"),
    };
    chain.with_view(|view| {
        validate(formed, &view, &RuleSet::GENESIS, &Trust::UNANCHORED)
            .map(|v| v.map(|_valid: ChainValid<_>| ()))
    })
}

/// The `Result` is the fn pointer's shape.
#[allow(clippy::unnecessary_wraps)]
fn top_byte_set(_: &[u8], _: &BlockHash) -> Result<PowHash, Faulted> {
    let mut bytes = [0u8; 32];
    bytes[31] = 0xff;
    Ok(PowHash::from_bytes(bytes))
}

// --- CEN-D1 / D1b ---------------------------------------------------------

#[test]
fn cen_d1_a_longhash_above_the_target_is_refused() {
    let chain = chain_of(1);
    let seed = expected_seed(&chain);
    // The all-zero hash satisfies every target; a hash with its most
    // significant byte set satisfies none above 1 (target here: 400).
    let passes = MockSubstrate::default();
    let fails = MockSubstrate {
        longhash: top_byte_set,
        ..MockSubstrate::default()
    };
    judged(judge_with(&chain, &passes, seed, FormAttempt::FIRST)).expect("zero hash passes");
    assert_refused(
        judged(judge_with(&chain, &fails, seed, FormAttempt::FIRST)),
        CenRow::D1,
        Locus::Block,
    );
}

#[test]
fn cen_d1b_the_comparison_is_the_ported_check_hash() {
    // One oracle vector's shape, driven through the rule's definition: the
    // boundary `hash · d == 2^256` fails and one below it passes. With
    // hash = 2^255 (top bit set), d = 2 is the boundary.
    let mut bytes = [0u8; 32];
    bytes[31] = 0x80;
    let pow = PowHash::from_bytes(bytes);
    let mut coverage = RuleCoverage::EMPTY;
    let at_boundary = crate::rules::difficulty::D6::mint(Difficulty::from_raw(2), &mut coverage)
        .expect("non-zero");
    let below = crate::rules::difficulty::D6::mint(Difficulty::from_raw(1), &mut coverage)
        .expect("non-zero");
    assert!(!D1b::satisfies(pow, at_boundary, &mut coverage));
    assert!(D1b::satisfies(pow, below, &mut coverage));
    assert!(coverage.contains(CenRow::D1b), "the definition records");
    // And the same answer as the one implementation, by name.
    assert_eq!(
        D1b::satisfies(pow, at_boundary, &mut coverage),
        check_hash(pow.as_bytes(), Difficulty::from_raw(2))
    );
}

// --- CEN-D2 ---------------------------------------------------------------

#[test]
fn cen_d2_the_longhash_is_computed_in_form_over_the_pow_blob_under_the_seed() {
    let chain = chain_of(3);
    let candidate = candidate_on(&chain, Vec::new());
    let seed = BlockHash::from_bytes([0x5e; 32]);
    // A substrate that encodes its inputs into the hash, so the fixture can
    // see what it was asked.
    #[allow(clippy::unnecessary_wraps)] // the fn pointer's shape
    fn echo(pow_blob: &[u8], seed: &BlockHash) -> Result<PowHash, Faulted> {
        let mut out = [0u8; 32];
        out[..8].copy_from_slice(&(pow_blob.len() as u64).to_le_bytes());
        out[8..16].copy_from_slice(&seed.to_bytes()[..8]);
        Ok(PowHash::from_bytes(out))
    }
    let substrate = MockSubstrate {
        longhash: echo,
        ..MockSubstrate::default()
    };
    let expected_len = candidate.block.pow_blob().len() as u64;
    let formed = form(
        candidate,
        &RuleSet::GENESIS,
        &substrate,
        seed,
        FormAttempt::FIRST,
    )
    .expect("no fault")
    .expect("passes the stateless stage");
    let pow = formed.pow().to_bytes();
    assert_eq!(
        u64::from_le_bytes(pow[..8].try_into().expect("8")),
        expected_len
    );
    assert_eq!(&pow[8..16], &[0x5e; 8]);
    assert!(
        formed.coverage().contains(CenRow::D2),
        "recorded where derived"
    );
}

#[test]
fn cen_d2_a_verifier_that_cannot_compute_is_a_fault_not_a_verdict() {
    fn faults(_: &[u8], _: &BlockHash) -> Result<PowHash, Faulted> {
        Err(Faulted)
    }
    let substrate = MockSubstrate {
        longhash: faults,
        ..MockSubstrate::default()
    };
    let result = form(
        candidate_on(&MockChain::default(), Vec::new()),
        &RuleSet::GENESIS,
        &substrate,
        BlockHash::NULL,
        FormAttempt::FIRST,
    );
    assert!(matches!(result, Err(Faulted)), "unproven, not disproven");
}

// --- CEN-D3 ---------------------------------------------------------------

#[test]
fn cen_d3_genesis_admission_expects_the_null_seed() {
    let chain = MockChain::default();
    assert_eq!(expected_seed(&chain), BlockHash::NULL);
    judged(judge_with(
        &chain,
        &MockSubstrate::default(),
        BlockHash::NULL,
        FormAttempt::FIRST,
    ))
    .expect("the null seed is the genesis seed");
}

#[test]
fn cen_d3_the_seed_is_block_zero_through_the_first_epoch_and_lag() {
    // Connecting heights 2112 (still block 0) and 2113 (first rollover to
    // block 2048): the boundary the schedule's pinned values name.
    for (blocks, seed_height) in [(2112u64, 0u64), (2113, 2048)] {
        let chain = chain_of(blocks);
        let connecting = blocks;
        assert_eq!(
            crate::seed_height(BlockHeight::from_raw(connecting)),
            Some(BlockHeight::from_raw(seed_height))
        );
        let seed = expected_seed(&chain);
        let at_seed_height = chain.with_view(|view| {
            match crate::harness::infallible(view.block_at(BlockHeight::from_raw(seed_height))) {
                AtHeight::Recorded(block) => block.hash,
                AtHeight::AboveTip => panic!("recorded"),
            }
        });
        assert_eq!(seed, at_seed_height);
        judged(judge_with(
            &chain,
            &MockSubstrate::default(),
            seed,
            FormAttempt::FIRST,
        ))
        .expect("the right seed passes D3");
    }
}

#[test]
fn cen_d3_a_stale_seed_is_a_fault_with_a_bounded_retry_not_a_refusal() {
    let chain = chain_of(2113);
    let expected = expected_seed(&chain);
    let wrong = BlockHash::from_bytes([0xbb; 32]);
    match judge_with(&chain, &MockSubstrate::default(), wrong, FormAttempt::FIRST) {
        Err(Fault::Stale(Stale::Seed {
            claimed,
            expected: e,
            retry,
        })) => {
            assert_eq!(claimed, wrong);
            assert_eq!(e, expected);
            assert!(
                matches!(retry, Retry::Again(_)),
                "the first attempt may be redone"
            );
        }
        other => panic!("expected Stale::Seed, got {other:?}"),
    }
    // Nothing past D3 was judged: the view stage stopped before the
    // predicates ran, so no refusal masquerades as the outcome.
}

#[test]
fn cen_d3_the_last_attempt_with_a_stale_seed_is_exhausted() {
    let chain = chain_of(1);
    let wrong = BlockHash::from_bytes([0xbb; 32]);
    match judge_with(
        &chain,
        &MockSubstrate::default(),
        wrong,
        FormAttempt::last_for_tests(),
    ) {
        Err(Fault::Stale(Stale::Seed { retry, .. })) => assert_eq!(retry, Retry::Exhausted),
        other => panic!("expected an exhausted stale seed, got {other:?}"),
    }
}

#[test]
fn cen_d3_records_and_the_pow_rows_cover_on_a_passing_block() {
    let chain = chain_of(2);
    let seed = expected_seed(&chain);
    let candidate = candidate_on(&chain, Vec::new());
    let formed = form(
        candidate,
        &RuleSet::GENESIS,
        &MockSubstrate::default(),
        seed,
        FormAttempt::FIRST,
    )
    .expect("no fault")
    .expect("passes");
    chain.with_view(|view| {
        let valid = judged(validate(
            formed,
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .expect("passes");
        for row in [CenRow::D1, CenRow::D1b, CenRow::D2, CenRow::D3] {
            assert!(valid.coverage().contains(row), "{row}");
        }
        assert_eq!(
            valid.block().target().difficulty(),
            Difficulty::from_raw(GENESIS_DIFFICULTY)
        );
    });
}
