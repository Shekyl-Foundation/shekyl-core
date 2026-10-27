// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The mutation wrapper's own contract (`DRS_E2_REPLAY_DRIVER.md` §3.10):
//! numbering, exactly one mutated block, and the faults raised before a
//! row is judged. The runs that land on census rows stay in the parent.

use shekyl_chain_rules::harness::MockSubstrate;
use shekyl_chain_rules::{CenRow, RowStatus};
use shekyl_difficulty::FTL_SECONDS;
use shekyl_types::{BlockHeight, CurveTreeRoot, Timestamp};

use crate::mutation::{
    Before, Environment, ExpectedPlace, Mutated, Mutation, MutationFault, Unmutable,
    UNHELD_ATTESTATION_ROOT, UNHELD_ROOT,
};
use crate::source::{IngestEvent, Source};
use crate::test_support::{h, GrownTree, Scripted, FIRST_SPEND_HEIGHT};

use super::{candidate, scripted, AT, CHAIN_LEN};

fn env() -> Environment<'static> {
    Environment {
        clock: MockSubstrate::CLOCK,
        pow: None,
        overweight: None,
        twins: &[],
        resigned: None,
    }
}

fn drain<S: Source>(source: &mut S) -> Result<usize, S::Fault> {
    let mut n = 0;
    while source.next()?.is_some() {
        n += 1;
    }
    Ok(n)
}

#[test]
fn the_wrapper_keeps_numbering_and_heights_and_mutates_exactly_one_block() {
    let chain = crate::test_support::chain(3);
    let mut source = Mutated::new(scripted(&chain), h(1), Mutation::Orphan, env());
    assert_eq!(source.first_height(), h(0));
    let mut seen = Vec::new();
    while let Some(ev) = source.next().expect("no fault") {
        seen.push(ev);
    }
    assert_eq!(seen.len(), 3);
    for (i, ev) in seen.iter().enumerate() {
        assert_eq!(ev.seq.to_raw(), i as u64, "numbering is the inner source's");
    }
    let block_at = |i: usize| match &seen[i].event {
        IngestEvent::Extend(c) => c.block.clone(),
        IngestEvent::Rewind { .. } | IngestEvent::Inject(_) => panic!("Extend-only"),
    };
    assert_eq!(block_at(0), chain[0].0, "below: untouched");
    assert_eq!(block_at(2), chain[2].0, "above: untouched");
    assert_ne!(block_at(1).header.previous, chain[1].0.header.previous);
    assert_eq!(
        block_at(1).header.timestamp,
        chain[1].0.header.timestamp,
        "one violation"
    );
}

#[test]
fn a_rewind_from_the_inner_source_is_a_wrapper_fault() {
    let chain = crate::test_support::chain(2);
    let events = vec![
        IngestEvent::Extend(Box::new(candidate(&chain[0].0, &chain[0].1))),
        IngestEvent::Rewind { to: h(0) },
    ];
    let mut source = Mutated::new(Scripted::new(events), h(0), Mutation::WrongRoot, env());
    source.next().expect("block 0 mutated");
    match source.next() {
        Err(MutationFault::Rewind { to }) => assert_eq!(to, h(0)),
        other => panic!("{other:?}"),
    }
    match source.next() {
        Err(MutationFault::Stopped) => {}
        other => panic!("a fault is not retryable: {other:?}"),
    }
}

#[test]
fn a_mutation_height_the_chain_never_reaches_is_a_fault_not_a_clean_replay() {
    let chain = crate::test_support::chain(2);
    let mut source = Mutated::new(scripted(&chain), h(5), Mutation::Orphan, env());
    match drain(&mut source) {
        Err(MutationFault::NeverReached { at, next }) => {
            assert_eq!((at, next), (h(5), Some(h(2))));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_candidate_that_cannot_carry_the_mutation_names_why() {
    // The first spend block of `chain(FIRST_SPEND_HEIGHT + 1)` lists one
    // body: nothing to reorder.
    let first_spend = FIRST_SPEND_HEIGHT;
    let chain = crate::test_support::chain(first_spend + 1);
    let mut source = Mutated::new(
        scripted(&chain),
        h(first_spend),
        Mutation::ReorderedBodies,
        env(),
    );
    for below in 0..first_spend {
        source
            .next()
            .unwrap_or_else(|e| panic!("block {below} passes through: {e:?}"));
    }
    match source.next() {
        Err(MutationFault::Unmutable {
            mutation: Mutation::ReorderedBodies,
            at,
            cause: Unmutable::TooFewBodies { listed: 1 },
        }) => assert_eq!(at, h(first_spend)),
        other => panic!("{other:?}"),
    }
    // Genesis has nothing spent before it: no double spend to stage.
    let mut source = Mutated::new(scripted(&chain), h(0), Mutation::DoubleSpend, env());
    match source.next() {
        Err(MutationFault::Unmutable {
            cause: Unmutable::NothingSpentBefore,
            ..
        }) => {}
        other => panic!("{other:?}"),
    }
    // PoW without the leg.
    let mut source = Mutated::new(scripted(&chain), h(0), Mutation::PowUnderWrongSeed, env());
    match source.next() {
        Err(MutationFault::Unmutable {
            cause: Unmutable::NoPowEnvironment,
            ..
        }) => {}
        other => panic!("{other:?}"),
    }
}

#[test]
fn every_mutation_names_a_row_and_the_pending_ones_are_those_the_plan_lists() {
    let pending: Vec<CenRow> = Mutation::ALL
        .iter()
        .map(|m| m.expected())
        .filter(|row| row.status() == RowStatus::Pending)
        .collect();
    // §3.10's table at the pin: **empty** since E6 slice 7 wave B ported
    // F18. When a mutation is written for an unported row, this line and
    // the family's `Pending` arm both go red together — the plan's table
    // is then updated with the row and the arm pins today's shape, not the
    // test loosened. (Slice 4 re-keyed WrongReward F13 → F18, Q8: F13
    // landed as a definition, and the predicate a wrong amount trips is
    // F18. Slice 6 commit 4 ported I7: `DoubleSpend` refuses at its input.
    // Slice 7 commit 6 ported G2: the three G2 mutations refuse at their
    // loci. Slice 7 wave B ported F18: `WrongReward` refuses at the miner
    // slot, the last pending row.)
    assert_eq!(pending, Vec::<CenRow>::new());
    for m in Mutation::ALL {
        assert!(
            m.to_string().contains(m.expected().as_str()),
            "{m}: Display names the row"
        );
    }
    let places: Vec<(Mutation, ExpectedPlace)> = Mutation::ALL
        .into_iter()
        .map(|m| (m, m.expected_place()))
        .collect();
    assert_eq!(
        places,
        vec![
            (Mutation::HeaderVersion, ExpectedPlace::Block),
            (Mutation::Orphan, ExpectedPlace::Block),
            (Mutation::WrongRoot, ExpectedPlace::Block),
            // Slice 8 row 10: B4 names the block, as the header rows do.
            (Mutation::WrongAttestationRoot, ExpectedPlace::Block),
            (Mutation::FutureTimestamp, ExpectedPlace::Block),
            (Mutation::StaleTimestamp, ExpectedPlace::Block),
            (Mutation::PowUnderWrongSeed, ExpectedPlace::Block),
            (Mutation::WrongReward, ExpectedPlace::Miner),
            // Slice 7 commit 6 (Q8): G2's index arm names the first
            // mismatching listed slot; its length arm names the block.
            (Mutation::ReorderedBodies, ExpectedPlace::Listed),
            (Mutation::MissingBody, ExpectedPlace::Block),
            (Mutation::SubstitutedBody, ExpectedPlace::Listed),
            // Slice 7 commit 7 (Q8): G1 names the slot whose hash it looked
            // up; the archival passes name the second vin; F14 the block's
            // summed weight. (G9's `DuplicateClaim` retired to the driver,
            // slice 8 row 9 — `Mutation` docs.)
            (Mutation::RelistedTransaction, ExpectedPlace::Listed),
            (Mutation::DoubledListing, ExpectedPlace::Listed),
            (Mutation::DuplicateServeCredit, ExpectedPlace::Input),
            (Mutation::DuplicateBondPost, ExpectedPlace::Input),
            (Mutation::OverweightBlock, ExpectedPlace::Block),
            (Mutation::DoubleSpend, ExpectedPlace::Input),
            // Slice 6 commit 5: the reference rows name the transaction.
            (Mutation::UnknownReference, ExpectedPlace::Listed),
            (Mutation::ReferenceTooRecent, ExpectedPlace::Listed),
            // Slice 6 commit 8: the signature names its input, as I7 does.
            (Mutation::ForgedSignature, ExpectedPlace::Input),
        ]
    );
}

#[test]
fn a_timestamp_mutation_at_genesis_cannot_provoke_its_row() {
    let chain = crate::test_support::chain(1);
    for mutation in [Mutation::FutureTimestamp, Mutation::StaleTimestamp] {
        let mut source = Mutated::new(scripted(&chain), h(0), mutation, env());
        match source.next() {
            Err(MutationFault::Unmutable {
                cause: Unmutable::GenesisExempt(which),
                at,
                ..
            }) => {
                assert_eq!(which, mutation);
                assert_eq!(at, h(0));
            }
            other => panic!("{mutation}: {other:?}"),
        }
        match source.next() {
            Err(MutationFault::Stopped) => {}
            other => panic!("{mutation}: a fault is not retryable: {other:?}"),
        }
    }
}

#[test]
fn a_clock_with_no_representable_future_does_not_pretend_to_be_past_the_ftl() {
    let chain = crate::test_support::chain(2);
    // `clock + FTL + 1` is `u64::MAX + 1`. The saturating predicate would
    // still accept `u64::MAX`, so emitting it would not be CEN-C1.
    let env = Environment {
        clock: Timestamp::from_raw(u64::MAX - FTL_SECONDS),
        pow: None,
        overweight: None,
        twins: &[],
        resigned: None,
    };
    let mut source = Mutated::new(scripted(&chain), h(1), Mutation::FutureTimestamp, env);
    source.next().expect("block 0 is not the mutation");
    match source.next() {
        Err(MutationFault::Unmutable {
            cause: Unmutable::NoRepresentableFuture,
            at,
            ..
        }) => assert_eq!(at, h(1)),
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_amount_at_the_top_of_the_range_cannot_move_by_one() {
    let chain = crate::test_support::chain(1);
    let mut candidate = candidate(&chain[0].0, &chain[0].1);
    candidate.block.miner_transaction.prefix.outputs[0].amount = u64::MAX;
    let err = Mutation::WrongReward
        .apply(candidate, &env(), &Before::default(), h(0))
        .expect_err("u64::MAX + 1 does not fit");
    assert_eq!(err, Unmutable::RewardSaturated);
}

#[test]
fn the_unheld_root_is_not_a_fixture_root() {
    let chain = crate::test_support::chain(CHAIN_LEN);
    let mut source = Mutated::new(scripted(&chain), h(AT), Mutation::WrongRoot, env());
    for _ in 0..AT {
        source.next().expect("blocks below the mutation");
    }
    let ev = source.next().expect("the mutated block").expect("yielded");
    let IngestEvent::Extend(candidate) = ev.event else {
        panic!("Extend-only");
    };
    let root = candidate.block.header.curve_tree_root;
    assert_eq!(root.as_bytes(), &UNHELD_ROOT);
    assert_ne!(root, CurveTreeRoot::EMPTY);
    assert_ne!(root, GrownTree::over(&chain).root_going_into(h(AT)));
}

#[test]
fn the_unheld_attestation_root_is_not_the_empty_sets() {
    // The mutation's whole claim: a block supplying nothing commits the
    // empty set, so a root that is not the empty set's is CEN-B4's
    // refusal. Pinned against the retention crate's recompute, which the
    // production module cannot name (`UNHELD_ATTESTATION_ROOT` docs).
    let chain = crate::test_support::chain(CHAIN_LEN);
    let mut source = Mutated::new(
        scripted(&chain),
        h(AT),
        Mutation::WrongAttestationRoot,
        env(),
    );
    for _ in 0..AT {
        source.next().expect("blocks below the mutation");
    }
    let ev = source.next().expect("the mutated block").expect("yielded");
    let IngestEvent::Extend(candidate) = ev.event else {
        panic!("Extend-only");
    };
    assert!(candidate.attestation_witness.is_none(), "nothing supplied");
    let root = candidate.block.header.attestation_root;
    assert_eq!(root.as_bytes(), &UNHELD_ATTESTATION_ROOT);
    assert_ne!(
        *root.as_bytes(),
        shekyl_archival_retention::empty_attestation_root()
    );
}

#[test]
fn the_last_representable_height_is_yielded_and_another_event_is_a_fault() {
    let chain = crate::test_support::chain(1);
    let block = IngestEvent::Extend(Box::new(candidate(&chain[0].0, &chain[0].1)));
    let ceiling = BlockHeight::from_raw(u64::MAX);
    let mut source = Mutated::new(
        Scripted::from(ceiling, vec![block.clone(), block]),
        ceiling,
        Mutation::Orphan,
        env(),
    );
    let yielded = source
        .next()
        .expect("the block at u64::MAX is a real event")
        .expect("yielded");
    let IngestEvent::Extend(carried) = yielded.event else {
        panic!("Extend-only");
    };
    assert_ne!(
        carried.block.header.previous, chain[0].0.header.previous,
        "the mutation landed on the last height"
    );
    match source.next() {
        Err(MutationFault::HeightExhausted { after }) => assert_eq!(after, ceiling),
        other => panic!("{other:?}"),
    }
    match source.next() {
        Err(MutationFault::Stopped) => {}
        other => panic!("a fault is not retryable: {other:?}"),
    }

    // The same height, with the source ending there, is a clean close.
    let block = IngestEvent::Extend(Box::new(candidate(&chain[0].0, &chain[0].1)));
    let mut source = Mutated::new(
        Scripted::from(ceiling, vec![block]),
        ceiling,
        Mutation::Orphan,
        env(),
    );
    assert!(source.next().expect("yielded").is_some());
    assert!(source.next().expect("clean end").is_none());
}
