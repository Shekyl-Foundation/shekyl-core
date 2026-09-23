// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;
use crate::census::CenRow;
use crate::fault::{Fault, FormAttempt, Retry, Stale};
use crate::harness::fixture::{candidate, coinbase, listed};
use crate::harness::{formed, formed_under, judged, Faulted, MockChain, MockSubstrate};
use crate::rule_set::RuleSetId;
use crate::substrate::Substrate;
use crate::trust::Trust;
use crate::TxIdentity;

#[test]
fn a_well_formed_candidate_passes_and_covers_only_the_landed_rows() {
    MockChain::default().with_view(|view| {
        let input = candidate(vec![listed([0xC1; 32]), listed([0xC2; 32])]);
        let valid = judged(validate(
            formed(input),
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .expect("the fixture satisfies every landed rule");
        assert_eq!(valid.rule_set_id(), RuleSetId::GENESIS);
        // Slice 1's block rows — B1, B2, B7 from the stateless stage, A2,
        // B5 from the view-bound one, B6 from the derivation — slice 2's
        // 4.C rows (C1, C2 predicates; C3 definition) and 4.D rows (D2 in
        // form; D3's verification, D4 the target, D6 at its mint, D1b the
        // comparison, D1 the predicate), slice 3's E1, and slice 4's 4.F
        // rows (F1, F3, F7, F9, F10 in form; F4, F5, F6 view-bound; F11,
        // F13, F15, F20 the emission definitions), and nothing else (the
        // per-tx entry points are still empty; F2/F8/F19/F21 hold by
        // construction and are never in a coverage).
        assert_eq!(
            valid.coverage().iter().collect::<Vec<_>>(),
            [
                CenRow::A2,
                CenRow::B1,
                CenRow::B2,
                CenRow::B5,
                CenRow::B6,
                CenRow::B7,
                CenRow::C1,
                CenRow::C2,
                CenRow::C3,
                CenRow::D1,
                CenRow::D1b,
                CenRow::D2,
                CenRow::D3,
                CenRow::D4,
                CenRow::D6,
                CenRow::D7,
                CenRow::E1,
                CenRow::F1,
                CenRow::F3,
                CenRow::F4,
                CenRow::F5,
                CenRow::F6,
                CenRow::F7,
                CenRow::F9,
                CenRow::F10,
                CenRow::F11,
                CenRow::F13,
                CenRow::F15,
                CenRow::F20,
                CenRow::H1,
                CenRow::H3,
                CenRow::H4,
                CenRow::H5,
                CenRow::H6,
                CenRow::H9,
                CenRow::H14,
                CenRow::H16,
            ]
        );
        assert!(valid.coverage().covers_landed(&RuleSet::GENESIS));
        // Not parity evidence until every row has landed.
        assert!(!valid.coverage().is_complete_for(&RuleSet::GENESIS));
    });
}

#[test]
fn the_validated_block_is_the_candidate_with_identities_derived_once() {
    let input = candidate(vec![listed([0xC1; 32]), listed([0xC2; 32])]);
    let expected_hash = input.block.hash();
    let identity = |tx: &Transaction| {
        let parts = tx.txid_parts();
        TxIdentity {
            hash: parts.hash,
            pqc_auth_hash: parts.pqc_auth_hash,
            prunable_hash: parts.prunable_hash,
        }
    };
    let expected_miner = identity(&input.block.miner_transaction);
    let expected_listed: Vec<(TxIdentity, Transaction)> = input
        .transactions
        .iter()
        .map(|tx| (identity(tx), tx.clone()))
        .collect();
    let expected_block = input.block.clone();
    // A coinbase-shaped body has an empty prunable region: its digest is
    // keccak256("") (the value the store records), never the txid's null
    // substitute — the two identities are derived by different rules and
    // must not be conflated (SCW-10).
    const KECCAK256_OF_EMPTY: [u8; 32] = [
        0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03,
        0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85,
        0xa4, 0x70,
    ];
    assert_eq!(expected_miner.prunable_hash.as_bytes(), &KECCAK256_OF_EMPTY);
    assert_ne!(expected_miner.prunable_hash.as_bytes(), &[0u8; 32]);
    // A coinbase txid is 3-part: there is no third component to record
    // (PDM-Q-F26) — `None` is the identity's arity, not a discarded value.
    // The listed spends carry no `pqc_auths` either, so theirs is `None` too.
    assert_eq!(expected_miner.pqc_auth_hash, None);
    for (id, _) in &expected_listed {
        assert_eq!(id.pqc_auth_hash, None);
    }

    MockChain::default().with_view(|view| {
        let valid = judged(validate(
            formed(input),
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .expect("the fixture satisfies every landed rule");
        let block = valid.block();
        assert_eq!(block.hash(), expected_hash);
        assert_eq!(block.block(), &expected_block);
        assert_eq!(block.header(), &expected_block.header);
        assert_eq!(
            block.miner_tx(),
            (expected_miner, &expected_block.miner_transaction)
        );
        assert_eq!(block.transactions(), expected_listed.as_slice());
    });
}

#[test]
fn a_block_with_no_listed_transactions_passes() {
    MockChain::default().with_view(|view| {
        let valid = judged(validate(
            formed(candidate(Vec::new())),
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .expect("the fixture satisfies every landed rule");
        assert!(valid.block().transactions().is_empty());
    });
}

/// `tx_form` judges the landed 4.H rows at the slot it is given (slice 5);
/// `tx_against` still records nothing (4.I is slice 6). At the miner slot a
/// well-formed coinbase records H1/H3/H4 vacuous and H16 passed — every
/// landed row was evaluated.
#[test]
fn tx_entry_points_record_the_landed_rows() {
    let tx = coinbase(1);
    let form = tx_form(&tx, TxSlot::Miner, &RuleSet::GENESIS).expect("a coinbase passes");
    assert_eq!(
        form.iter().collect::<Vec<_>>(),
        [
            CenRow::H1,
            CenRow::H3,
            CenRow::H4,
            CenRow::H5,
            CenRow::H6,
            CenRow::H9,
            CenRow::H14,
            CenRow::H16
        ]
    );
    MockChain::default().with_view(|view| {
        assert_eq!(
            tx_against(&tx, &view, &RuleSet::GENESIS),
            Ok(Ok(RuleCoverage::EMPTY))
        );
    });
}

// --- the two stages ---------------------------------------------------------

#[test]
fn form_carries_the_clock_the_seed_and_the_attempt_it_was_given() {
    let seed = shekyl_types::BlockHash::from_bytes([0x5e; 32]);
    let substrate = MockSubstrate {
        clock: shekyl_types::Timestamp::from_raw(1_700_000_777),
        ..MockSubstrate::default()
    };
    let formed = form(
        candidate(Vec::new()),
        &RuleSet::GENESIS,
        &substrate,
        seed,
        FormAttempt::FIRST,
    )
    .expect("the mock substrate answers")
    .expect("a well-formed candidate passes the stateless stage");
    assert_eq!(formed.judged_at(), substrate.clock);
    assert_eq!(formed.seed(), seed);
    assert_eq!(formed.attempt(), FormAttempt::FIRST);
    assert_eq!(formed.rule_set_id(), RuleSetId::GENESIS);
    // The identity is derived here, once, and is the block's (slice 3 F8).
    assert_eq!(formed.hash(), formed.candidate().block.hash());
    // The stateless rows, and only those, are recorded before the view
    // stage runs — the three version rows, the two definitions B6 (the
    // identity) and D2 (the longhash), and the coinbase's stateless shape
    // (F1, F3, F7, F9, F10).
    assert_eq!(
        formed.coverage().iter().collect::<Vec<_>>(),
        [
            CenRow::B1,
            CenRow::B2,
            CenRow::B6,
            CenRow::B7,
            CenRow::D2,
            CenRow::F1,
            CenRow::F3,
            CenRow::F7,
            CenRow::F9,
            CenRow::F10,
        ]
    );
}

#[test]
fn a_substrate_that_cannot_read_the_clock_is_a_fault_not_a_verdict() {
    struct NoClock;
    impl Substrate for NoClock {
        type Fault = Faulted;
        fn local_clock(&self) -> Result<shekyl_types::Timestamp, Faulted> {
            Err(Faulted)
        }
        fn longhash(
            &self,
            _: &[u8],
            _: &shekyl_types::BlockHash,
        ) -> Result<shekyl_types::PowHash, Faulted> {
            unreachable!("the clock faults first")
        }
    }
    let result = form(
        candidate(Vec::new()),
        &RuleSet::GENESIS,
        &NoClock,
        shekyl_types::BlockHash::NULL,
        FormAttempt::FIRST,
    );
    assert!(matches!(result, Err(Faulted)));
}

#[test]
fn a_rule_set_claim_the_view_stage_refutes_is_stale_with_a_bounded_retry() {
    let admits_two = RuleSet::admitting_for_tests(2);
    let mut input = candidate(Vec::new());
    input.block.header.major_version = 2;
    input.block.header.minor_version = 2;
    // Formed under the rule set that admits 2; validated under GENESIS.
    let formed = form(
        input,
        &admits_two,
        &MockSubstrate::default(),
        shekyl_types::BlockHash::NULL,
        FormAttempt::FIRST,
    )
    .expect("no fault")
    .expect("major 2 passes B1 under a set that admits 2");
    MockChain::default().with_view(|view| {
        let fault = validate(formed, &view, &RuleSet::GENESIS, &Trust::UNANCHORED)
            .expect_err("a stale rule-set claim is a fault, not a verdict");
        let Fault::Stale(Stale::RuleSet {
            formed_under,
            in_force,
            retry,
        }) = fault
        else {
            panic!("expected Stale::RuleSet, got {fault:?}");
        };
        assert_eq!(formed_under, admits_two);
        assert_eq!(in_force, RuleSet::GENESIS);
        // The first attempt may be retried; the payload says with what.
        assert_eq!(retry, Retry::Again(FormAttempt::FIRST.next_for_tests()));
    });
}

#[test]
fn the_last_attempt_is_terminal() {
    let admits_two = RuleSet::admitting_for_tests(2);
    let mut input = candidate(Vec::new());
    input.block.header.major_version = 2;
    input.block.header.minor_version = 2;
    let last = FormAttempt::last_for_tests();
    let formed = form(
        input,
        &admits_two,
        &MockSubstrate::default(),
        shekyl_types::BlockHash::NULL,
        last,
    )
    .expect("no fault")
    .expect("passes the stateless stage");
    MockChain::default().with_view(|view| {
        match validate(formed, &view, &RuleSet::GENESIS, &Trust::UNANCHORED) {
            Err(Fault::Stale(Stale::RuleSet { retry, .. })) => {
                assert_eq!(retry, Retry::Exhausted);
            }
            other => panic!("expected an exhausted stale fault, got {other:?}"),
        }
    });
}

#[test]
fn a_fakechain_rule_set_mints_at_genesis_with_d6_in_coverage() {
    // The Fixed arm used to return a Target without recording D6;
    // `covers_landed` then panicked at mint. Genesis and the set's id
    // coinciding with GENESIS is the shape that hid it.
    let seven = RuleSet::fakechain(core::num::NonZeroU128::new(7).expect("non-zero"));
    MockChain::default().with_view(|view| {
        let formed = formed_under(candidate(Vec::new()), &seven, shekyl_types::BlockHash::NULL);
        let valid = judged(validate(formed, &view, &seven, &Trust::UNANCHORED))
            .expect("fakechain genesis mints");
        assert!(valid.coverage().covers_landed(&seven));
        assert!(valid.coverage().contains(CenRow::D6));
        assert_eq!(
            valid.block().target().difficulty(),
            shekyl_difficulty::Difficulty::from_raw(1),
            "height 0 is 1 under a fixed target"
        );
    });
}

#[test]
fn a_fakechain_set_is_stale_against_genesis_even_at_the_same_id() {
    let seven = RuleSet::fakechain(core::num::NonZeroU128::new(7).expect("non-zero"));
    assert_eq!(seven.id(), RuleSet::GENESIS.id());
    let formed = formed_under(candidate(Vec::new()), &seven, shekyl_types::BlockHash::NULL);
    MockChain::default().with_view(|view| {
        let fault = validate(formed, &view, &RuleSet::GENESIS, &Trust::UNANCHORED)
            .expect_err("the set moved, even though the id did not");
        match fault {
            Fault::Stale(Stale::RuleSet {
                formed_under,
                in_force,
                ..
            }) => {
                assert_eq!(formed_under, seven);
                assert_eq!(in_force, RuleSet::GENESIS);
            }
            other => panic!("expected Stale::RuleSet, got {other:?}"),
        }
    });
}

#[test]
fn two_fakechain_targets_are_distinct_sets() {
    let three = RuleSet::fakechain(core::num::NonZeroU128::new(3).expect("non-zero"));
    let seven = RuleSet::fakechain(core::num::NonZeroU128::new(7).expect("non-zero"));
    let formed = formed_under(candidate(Vec::new()), &three, shekyl_types::BlockHash::NULL);
    MockChain::default().with_view(|view| {
        let fault = validate(formed, &view, &seven, &Trust::UNANCHORED)
            .expect_err("different Fixed targets");
        assert!(matches!(fault, Fault::Stale(Stale::RuleSet { .. })));
    });
}
