// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `alt.rs` — the alt tier: the two alt arms (CEN-K1b, CEN-D5),
//! their place in the ladder (CEN-K4), and what the tier does not do
//! (`DRS_E5_POOL_ALT_PRUNE.md` §2.1, `E5-Q4` β).

use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockCount, BlockHash, BlockHeight};
use shekyl_wire::Input;

use super::*;
use crate::census::CenRow;
use crate::fault::{Fault, FormAttempt, Retry, Stale};
use crate::harness::fixture::{candidate, candidate_on, chain_of, recorded_with_work};
use crate::harness::{
    assert_refused, expected_seed, expected_target, formed_on, formed_under, judged, MockChain,
    MockSubstrate,
};
use crate::rule_set::{FakechainSchedule, RuleSet, SettlementEpochBlocks};
use crate::trust::Trust;
use crate::validate::{form, validate};
use crate::verdict::Locus;
use crate::view::{AtHeight, HeaderRecord, Tip};

const fn height(raw: u64) -> BlockHeight {
    BlockHeight::from_raw(raw)
}

/// A mock view paired with the fork the test says it describes — the
/// [`AltChainView`] the tier takes. The store's `AltView` derives both
/// from one snapshot; the tests pick the pair, including pairs the store
/// cannot build, to reach each arm.
struct Forked<'v, V> {
    view: &'v V,
    fork: Fork,
}

const fn forked<V>(view: &V, fork: Fork) -> Forked<'_, V> {
    Forked { view, fork }
}

impl<'id, V: HeaderView<'id>> HeaderView<'id> for Forked<'_, V> {
    type Fault = V::Fault;

    fn tip(&self) -> Result<Option<Tip>, V::Fault> {
        self.view.tip()
    }

    fn header_at(&self, height: BlockHeight) -> Result<AtHeight<HeaderRecord>, V::Fault> {
        self.view.header_at(height)
    }
}

impl<'id, V: HeaderView<'id>> AltChainView<'id> for Forked<'_, V> {
    fn fork(&self) -> Fork {
        self.fork
    }
}

/// The fork an alternative extending the recorded tip would cause: it
/// pops nothing. The tier's steady-state input.
fn fork_at_tip(chain: &MockChain) -> Fork {
    let tip = chain.tip().expect("a non-empty chain");
    Fork::new(tip, tip).expect("a tip is not above itself")
}

/// A fork rooted at `root` on `chain`, popping every recorded block above
/// it.
fn fork_rooted_at(chain: &MockChain, root: u64) -> Fork {
    let tip = chain.tip().expect("a non-empty chain");
    let root = chain.with_view(|view| {
        let AtHeight::Recorded(header) = view.header_at(height(root)).expect("infallible") else {
            panic!("root {root} is above the fixture's tip")
        };
        Tip {
            height: height(root),
            hash: header.hash,
        }
    });
    Fork::new(root, tip).expect("the fixture roots at or below the tip")
}

#[test]
fn an_inverted_fork_is_not_a_fork() {
    // A root above the recorded tip is not a span of blocks. `Fork::new`
    // refuses it; E2 never sees the saturated zero that used to admit it.
    let above = Tip {
        height: height(5),
        hash: BlockHash::from_bytes([1; 32]),
    };
    let below = Tip {
        height: height(4),
        hash: BlockHash::from_bytes([2; 32]),
    };
    assert!(Fork::new(above, below).is_err());
    let fork = Fork::new(below, above).expect("the lower tip is the root");
    assert_eq!(fork.root(), below);
    assert_eq!(fork.recorded_tip(), above);
    assert_eq!(fork.pops(), BlockCount::from_raw(1));
    let level = Fork::new(below, below).expect("a fork at the tip pops nothing");
    assert_eq!(level.pops(), BlockCount::ZERO);
}

/// The rows the tier evaluates beyond `form`'s: the two alt arms and the
/// header ladder — CEN-K4's set, in census order. A2 is the ladder's
/// parent link, the one header fact the tier checks against its own
/// candidate; D7 is the fixed-target consultation D4 records on every
/// derivation (`None` under GENESIS). CEN-D1 is `form`'s, judged against
/// the claimed target before any body work; the tier verifies the claim
/// where it derives D4 (`Stale::Target` on a mismatch).
const ALT_TIER_ROWS: [CenRow; 16] = [
    CenRow::A2,
    CenRow::C1,
    CenRow::C2,
    CenRow::C3,
    CenRow::D1b,
    CenRow::D3,
    CenRow::D4,
    CenRow::D5,
    CenRow::D6,
    CenRow::D7,
    CenRow::E1,
    CenRow::F4,
    CenRow::F5,
    CenRow::F6,
    CenRow::K1b,
    CenRow::K4,
];

#[test]
fn the_cheap_tier_evaluates_the_header_ladder_and_the_alt_arms_and_nothing_else() {
    // CEN-K4: the tier's row set is `form`'s rows plus exactly
    // `ALT_TIER_ROWS`. Every row `validate` adds that reads chain state —
    // the tree root B5, the attestation set B4, the weight medians, the
    // emission, every per-transaction row — is absent: not skipped,
    // unreachable, since the view is a `HeaderView`.
    let chain = chain_of(12);
    chain.with_view(|view| {
        let input = candidate_on(&chain, Vec::new());
        let stateless = *formed_on(&chain, input.clone()).coverage();
        let valid = judged(alt_against(
            formed_on(&chain, input),
            &forked(&view, fork_at_tip(&chain)),
            &RuleSet::GENESIS,
            &Trust::UNPINNED,
        ))
        .expect("the fixture satisfies every row of the tier");

        let mut expected = stateless;
        for row in ALT_TIER_ROWS {
            assert!(!stateless.contains(row), "{row} is not a stateless row");
            expected.insert(row);
        }
        assert_eq!(
            valid.coverage().iter().collect::<Vec<_>>(),
            expected.iter().collect::<Vec<_>>()
        );
        for absent in [CenRow::B4, CenRow::B5, CenRow::G6, CenRow::F14b] {
            assert!(
                !valid.coverage().contains(absent),
                "{absent} is a chain-state row"
            );
        }
        assert!(
            !valid.coverage().covers_landed(&RuleSet::GENESIS),
            "an alt verdict is never parity evidence for the block"
        );
    });
}

#[test]
fn a_view_whose_tip_is_not_the_candidates_parent_is_refused_on_the_parent_link() {
    // CEN-A2, the ladder's first header predicate: a view built for another
    // block — here the chain the candidate was formed on, one block short —
    // has a tip the candidate does not extend. The tier refuses at A2 and
    // mints no `AltValid` for a chain the block is not on; the fork and the
    // alt arms before the ladder pass, so the row is the ladder's.
    let formed_on_chain = chain_of(12);
    let shorter = chain_of(11);
    let input = candidate_on(&formed_on_chain, Vec::new());
    assert_ne!(
        input.block.header.previous,
        shorter.tip().expect("non-empty").hash,
        "the fixture's parent is the longer chain's tip"
    );
    shorter.with_view(|view| {
        assert_refused(
            judged(alt_against(
                formed_on(&formed_on_chain, input.clone()),
                &forked(&view, fork_at_tip(&shorter)),
                &RuleSet::GENESIS,
                &Trust::UNPINNED,
            )),
            CenRow::A2,
            Locus::Block,
        );
    });
}

#[test]
fn the_alt_tier_derives_the_facts_validate_derives_over_the_same_chain() {
    // Over one chain the two tiers agree on position and work: the height
    // is the parent's plus one, the cumulative difficulty is the parent's
    // plus the target CEN-D5 derived — the same target CEN-D4 derives,
    // since the algorithm is one function over whichever window it is
    // fed. The weight is the candidate's bytes.
    let chain = chain_of(12);
    chain.with_view(|view| {
        let input = candidate_on(&chain, Vec::new());
        let main = judged(validate(
            formed_on(&chain, input.clone()),
            &view,
            &RuleSet::GENESIS,
            &Trust::UNPINNED,
        ))
        .expect("well-formed on the main chain");
        let alt = judged(alt_against(
            formed_on(&chain, input.clone()),
            &forked(&view, fork_at_tip(&chain)),
            &RuleSet::GENESIS,
            &Trust::UNPINNED,
        ))
        .expect("well-formed on the alt tier");

        assert_eq!(alt.hash(), main.block().hash());
        assert_eq!(alt.height(), height(12));
        assert_eq!(
            alt.cumulative_difficulty(),
            main.block().cumulative_difficulty()
        );
        assert_eq!(alt.rule_set(), RuleSet::GENESIS);
        assert_eq!(alt.block_weight(), main.block().weights().weight);
        assert_eq!(alt.candidate(), &input);
        assert_eq!(alt.into_candidate(), input);
    });
}

#[test]
fn the_alt_target_follows_the_window_it_is_fed() {
    // CEN-D5: a stitched chain whose suffix carries different work and
    // timestamps yields a different target, and so a different cumulative
    // difficulty, than the recorded chain at the same height. Two chains
    // of twelve that agree through height 9 and differ above it.
    let shared = chain_of(10);
    let recorded = (10..12u64).fold(shared.clone(), |chain, h| {
        chain.push(
            recorded_with_work(
                1_000 + h * 120,
                CumulativeDifficulty::from_raw(u128::from(h + 1) * 1_000),
            ),
            crate::harness::fixture::root(1),
        )
    });
    let stitched = (10..12u64).fold(shared, |chain, h| {
        chain.push(
            recorded_with_work(
                1_000 + h * 30,
                CumulativeDifficulty::from_raw(u128::from(h + 1) * 4_000),
            ),
            crate::harness::fixture::root(1),
        )
    });
    let on_recorded = recorded.with_view(|view| {
        judged(alt_against(
            formed_on(&recorded, candidate_on(&recorded, Vec::new())),
            &forked(&view, fork_at_tip(&recorded)),
            &RuleSet::GENESIS,
            &Trust::UNPINNED,
        ))
        .expect("well-formed")
        .cumulative_difficulty()
    });
    let on_stitched = stitched.with_view(|view| {
        judged(alt_against(
            formed_on(&stitched, candidate_on(&stitched, Vec::new())),
            &forked(&view, fork_at_tip(&stitched)),
            &RuleSet::GENESIS,
            &Trust::UNPINNED,
        ))
        .expect("well-formed")
        .cumulative_difficulty()
    });
    assert_ne!(on_recorded, on_stitched);
}

#[test]
fn a_height_zero_claim_is_refused_before_anything_is_read() {
    // CEN-K1b at the block locus, and first: the view is empty, so a tier
    // that read a header before the claim would report something else.
    let empty = MockChain::default();
    let twelve = chain_of(12);
    let deep = fork_rooted_at(&twelve, 2);
    empty.with_view(|view| {
        let input = candidate(Vec::new());
        assert_eq!(
            input.block.miner_transaction.prefix.inputs,
            vec![Input::Gen(0)],
            "the genesis fixture claims height 0"
        );
        assert_refused(
            judged(alt_against(
                formed_on(&empty, input),
                &forked(&view, deep),
                &RuleSet::GENESIS,
                &Trust::UNPINNED,
            )),
            CenRow::K1b,
            Locus::Block,
        );
    });
}

#[test]
fn a_fork_past_the_reorg_cap_is_not_a_consensus_refusal() {
    // The reorg cap (`D_max`) is the switch's local limit, from the pruning
    // horizon (`PopBeyondReorgCap`): a node cannot switch that deep, and
    // the block is not invalid for it (S1, design review 2026-11-03). A
    // Fakechain set capping at 3; a fork rooted at 7 on a chain whose tip
    // is 11 pops 4, and the tier admits it.
    let schedule = FakechainSchedule::new(
        SettlementEpochBlocks::new(512).expect("non-zero"),
        BlockCount::from_raw(3),
    )
    .expect("3 is inside 512");
    let capped = RuleSet::fakechain(None, schedule);
    assert_eq!(capped.reorg_cap(), BlockCount::from_raw(3));
    let chain = chain_of(12);
    let formed = formed_under(
        candidate_on(&chain, Vec::new()),
        &capped,
        expected_seed(&chain),
        expected_target(&chain, &capped),
        &crate::block::ReferenceClaims::EMPTY,
    );
    chain.with_view(|view| {
        let fork = fork_rooted_at(&chain, 7);
        assert!(fork.pops() > capped.reorg_cap());
        judged(alt_against(
            formed,
            &forked(&view, fork),
            &capped,
            &Trust::UNPINNED,
        ))
        .expect("past the cap is not a verdict");
    });
}

/// As `validate`: a target claim the stitched chain does not derive is
/// `Stale::Target`, never a verdict — the tier verifies the claim where it
/// derives D4, through the one ladder preparation both share.
#[test]
fn a_target_claim_the_alt_chain_does_not_derive_is_stale_not_a_verdict() {
    let chain = chain_of(12);
    let seven = RuleSet::fakechain(
        core::num::NonZeroU128::new(7),
        FakechainSchedule::PRODUCTION,
    );
    let wrong = expected_target(&chain, &seven);
    let right = expected_target(&chain, &RuleSet::GENESIS);
    assert_ne!(wrong, right, "the fixture's claim must be wrong");
    let formed = match form(
        candidate_on(&chain, Vec::new()),
        &RuleSet::GENESIS,
        &MockSubstrate::default(),
        expected_seed(&chain),
        wrong,
        &crate::block::ReferenceClaims::EMPTY,
        FormAttempt::FIRST,
    ) {
        Ok(Ok(formed)) => formed,
        other => panic!("the fixture forms: {other:?}"),
    };
    chain.with_view(|view| {
        match alt_against(
            formed,
            &forked(&view, fork_at_tip(&chain)),
            &RuleSet::GENESIS,
            &Trust::UNPINNED,
        ) {
            Err(Fault::Stale(Stale::Target {
                claimed, expected, ..
            })) => {
                assert_eq!(claimed, wrong);
                assert_eq!(expected, right);
            }
            other => panic!("expected Stale::Target, got {other:?}"),
        }
    });
}

#[test]
fn a_rule_set_the_token_was_not_formed_under_is_stale_not_a_verdict() {
    // As `validate`: the claim check is the same, and a mismatch names
    // both sets and the retry.
    let chain = chain_of(12);
    let other = RuleSet::fakechain(None, FakechainSchedule::PRODUCTION);
    let formed_under_other = chain.with_view(|_| {
        match form(
            candidate_on(&chain, Vec::new()),
            &other,
            &MockSubstrate::default(),
            expected_seed(&chain),
            expected_target(&chain, &other),
            &crate::block::ReferenceClaims::EMPTY,
            FormAttempt::FIRST,
        ) {
            Ok(Ok(formed)) => formed,
            other => panic!("the fixture forms: {other:?}"),
        }
    });
    let distinct = RuleSet::fakechain(
        None,
        FakechainSchedule::new(
            SettlementEpochBlocks::new(512).expect("non-zero"),
            BlockCount::from_raw(3),
        )
        .expect("inside"),
    );
    assert_ne!(other, distinct);
    chain.with_view(|view| {
        match alt_against(
            formed_under_other,
            &forked(&view, fork_at_tip(&chain)),
            &distinct,
            &Trust::UNPINNED,
        ) {
            Err(Fault::Stale(Stale::RuleSet {
                formed_under,
                in_force,
                retry,
            })) => {
                assert_eq!(*formed_under, other);
                assert_eq!(*in_force, distinct);
                assert_eq!(retry, Retry::Again(FormAttempt::FIRST.next_for_tests()));
            }
            other => panic!("expected a stale rule set, got {other:?}"),
        }
    });
}
