// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `alt.rs` — the alt tier: the three alt arms (CEN-K1b, CEN-E2, CEN-D5),
//! their place in the ladder (CEN-K4), and what the tier does not do
//! (`DRS_E5_POOL_ALT_PRUNE.md` §2.1, `E5-Q4` β).

use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockCount, BlockHash, BlockHeight};
use shekyl_wire::Input;

use super::*;
use crate::anchors::{Anchor, ReleaseAnchors};
use crate::census::CenRow;
use crate::fault::{Fault, FormAttempt, Retry, Stale};
use crate::harness::fixture::{candidate, candidate_on, chain_of, recorded_with_work};
use crate::harness::{
    assert_refused, expected_seed, formed_on, formed_under, judged, MockChain, MockSubstrate,
};
use crate::rule_set::{FakechainSchedule, RuleSet, SettlementEpochBlocks};
use crate::trust::Trust;
use crate::validate::{form, validate};
use crate::verdict::Locus;
use crate::view::{AtHeight, HeaderRecord, Tip};

const fn height(raw: u64) -> BlockHeight {
    BlockHeight::from_raw(raw)
}

const fn anchor(raw: u64, fill: u8) -> Anchor {
    Anchor {
        height: height(raw),
        hash: BlockHash::from_bytes([fill; 32]),
    }
}

/// A release anchoring height 5. No fixture in this file connects *at*
/// 5, so CEN-E1 never fires on the hash; the table exists for its
/// `current()`.
const ANCHORED_AT_5: ReleaseAnchors = ReleaseAnchors::for_tests(None, &[anchor(5, 0xA5)]);

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

/// The rows the tier evaluates beyond `form`'s: the three alt arms and the
/// header ladder — CEN-K4's set, in census order. A2 is the ladder's
/// parent link, the one header fact the tier checks against its own
/// candidate; D7 is the fixed-target consultation D4 records on every
/// derivation (`None` under GENESIS).
const ALT_TIER_ROWS: [CenRow; 18] = [
    CenRow::A2,
    CenRow::C1,
    CenRow::C2,
    CenRow::C3,
    CenRow::D1,
    CenRow::D1b,
    CenRow::D3,
    CenRow::D4,
    CenRow::D5,
    CenRow::D6,
    CenRow::D7,
    CenRow::E1,
    CenRow::E2,
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
            &Trust::UNANCHORED,
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
                &Trust::UNANCHORED,
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
            &Trust::UNANCHORED,
        ))
        .expect("well-formed on the main chain");
        let alt = judged(alt_against(
            formed_on(&chain, input.clone()),
            &forked(&view, fork_at_tip(&chain)),
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
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
            &Trust::UNANCHORED,
        ))
        .expect("well-formed")
        .cumulative_difficulty()
    });
    let on_stitched = stitched.with_view(|view| {
        judged(alt_against(
            formed_on(&stitched, candidate_on(&stitched, Vec::new())),
            &forked(&view, fork_at_tip(&stitched)),
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .expect("well-formed")
        .cumulative_difficulty()
    });
    assert_ne!(on_recorded, on_stitched);
}

#[test]
fn a_height_zero_claim_is_refused_before_anything_is_read() {
    // CEN-K1b at the block locus, and first: the fork below would refuse
    // on CEN-E2 (rooted below the anchor) and the view is empty, so a tier
    // that read either before the claim would report something else.
    let empty = MockChain::default();
    let anchored = Trust::full(ANCHORED_AT_5);
    let twelve = chain_of(12);
    let below_anchor = fork_rooted_at(&twelve, 2);
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
                &forked(&view, below_anchor),
                &RuleSet::GENESIS,
                &anchored,
            )),
            CenRow::K1b,
            Locus::Block,
        );
    });
}

#[test]
fn an_anchor_above_the_recorded_tip_is_no_floor_yet() {
    // CEN-E2's floor is the last anchor at or below the recorded tip. An
    // anchor at 13 on a chain whose tip is 11 has not been reached: a fork
    // rooted at 4 is not below any floor, and the cap does not bind.
    const ANCHORED_AT_13: ReleaseAnchors = ReleaseAnchors::for_tests(None, &[anchor(13, 0xAD)]);
    let chain = chain_of(12);
    let ahead = Trust::full(ANCHORED_AT_13);
    chain.with_view(|view| {
        judged(alt_against(
            formed_on(&chain, candidate_on(&chain, Vec::new())),
            &forked(&view, fork_rooted_at(&chain, 4)),
            &RuleSet::GENESIS,
            &ahead,
        ))
        .unwrap_or_else(|refused| panic!("an unreached anchor floored the fork: {refused}"));
    });
    // Reached, the same anchor table floors it: the tip at 11 sits at or
    // above an anchor at 5 in the two-anchor table, and 4 is below it.
    const BOTH: ReleaseAnchors =
        ReleaseAnchors::for_tests(None, &[anchor(5, 0xA5), anchor(13, 0xAD)]);
    chain.with_view(|view| {
        assert_refused(
            judged(alt_against(
                formed_on(&chain, candidate_on(&chain, Vec::new())),
                &forked(&view, fork_rooted_at(&chain, 4)),
                &RuleSet::GENESIS,
                &Trust::full(BOTH),
            )),
            CenRow::E2,
            Locus::Block,
        );
    });
}

#[test]
fn an_alternative_rooted_below_the_anchor_is_refused_and_one_at_or_above_it_is_not() {
    // CEN-E2 band 1. The anchor is at 5; a fork rooted at 4 would replace
    // the anchored block, one rooted at 5 or 7 would not. The refusal is
    // before any header read: the chain is the same in all three.
    let chain = chain_of(12);
    let anchored = Trust::full(ANCHORED_AT_5);
    chain.with_view(|view| {
        assert_refused(
            judged(alt_against(
                formed_on(&chain, candidate_on(&chain, Vec::new())),
                &forked(&view, fork_rooted_at(&chain, 4)),
                &RuleSet::GENESIS,
                &anchored,
            )),
            CenRow::E2,
            Locus::Block,
        );
        for root in [5, 7] {
            // Popping 11 − root blocks: 6 and 4, both inside GENESIS's cap.
            judged(alt_against(
                formed_on(&chain, candidate_on(&chain, Vec::new())),
                &forked(&view, fork_rooted_at(&chain, root)),
                &RuleSet::GENESIS,
                &anchored,
            ))
            .unwrap_or_else(|refused| panic!("root {root} is at or above the anchor: {refused}"));
        }
    });
}

#[test]
fn an_alternative_popping_more_than_the_cap_is_refused_only_when_anchored() {
    // CEN-E2 band 2, read from the rule set: a Fakechain set capping at 3.
    // A fork rooted at 7 on a chain whose tip is 11 pops 4. Anchored, that
    // is over the cap and refused; unanchored, the cap does not bind
    // (`PDM-Q11`: the anchor is the cap's precondition) and the same fork
    // is admitted. Rooted at 8 it pops 3 — at the cap, admitted anchored.
    let schedule = FakechainSchedule::new(
        SettlementEpochBlocks::new(512).expect("non-zero"),
        BlockCount::from_raw(3),
    )
    .expect("3 is inside 512");
    let capped = RuleSet::fakechain(None, schedule);
    assert_eq!(capped.reorg_cap(), BlockCount::from_raw(3));
    let chain = chain_of(12);
    let anchored = Trust::full(ANCHORED_AT_5);
    let formed = |chain: &MockChain| {
        formed_under(
            candidate_on(chain, Vec::new()),
            &capped,
            expected_seed(chain),
        )
    };
    chain.with_view(|view| {
        assert_refused(
            judged(alt_against(
                formed(&chain),
                &forked(&view, fork_rooted_at(&chain, 7)),
                &capped,
                &anchored,
            )),
            CenRow::E2,
            Locus::Block,
        );
        judged(alt_against(
            formed(&chain),
            &forked(&view, fork_rooted_at(&chain, 7)),
            &capped,
            &Trust::UNANCHORED,
        ))
        .expect("no anchor, no cap");
        judged(alt_against(
            formed(&chain),
            &forked(&view, fork_rooted_at(&chain, 8)),
            &capped,
            &anchored,
        ))
        .expect("popping exactly the cap is inside it");
    });
}

#[test]
fn the_fork_is_judged_before_the_header_ladder() {
    // CEN-K4's order between the arms and the ladder: a candidate CEN-C2
    // would refuse (a timestamp at or below the window's median), on a
    // fork CEN-E2 refuses, is refused on E2 — the fork costs no header
    // read and goes first.
    let chain = chain_of(12);
    let anchored = Trust::full(ANCHORED_AT_5);
    let mut stale = candidate_on(&chain, Vec::new());
    stale.block.header.timestamp = 0;
    chain.with_view(|view| {
        assert_refused(
            judged(alt_against(
                formed_on(&chain, stale.clone()),
                &forked(&view, fork_at_tip(&chain)),
                &RuleSet::GENESIS,
                &anchored,
            )),
            CenRow::C2,
            Locus::Block,
        );
        assert_refused(
            judged(alt_against(
                formed_on(&chain, stale),
                &forked(&view, fork_rooted_at(&chain, 2)),
                &RuleSet::GENESIS,
                &anchored,
            )),
            CenRow::E2,
            Locus::Block,
        );
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
            &Trust::UNANCHORED,
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
