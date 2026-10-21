// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The environment a fixture is judged in, and the assertions every rule
//! test is written with.

use core::convert::Infallible;
use core::fmt::Debug;

use shekyl_types::{BlockHash, BlockHeight, PowHash, Timestamp};

use super::views::Faulted;
use super::MockChain;
use crate::block::{Candidate, ReferenceClaim, ReferenceClaims, StructurallyValid};
use crate::census::CenRow;
use crate::fault::{Fault, FormAttempt, ViewRead};
use crate::rule_set::RuleSet;
use crate::rules::difficulty::{target_claim, Target};
use crate::substrate::Substrate;
use crate::validate::form;
use crate::verdict::{InvalidBlock, Locus, Verdict};
use crate::view::{AtHeight, ChainView};

/// The environment a fixture is judged in: a fixed clock and a longhash
/// function the test chooses.
///
/// The default longhash is the **all-zero** hash — `0 · d < 2^256` for
/// every target, so PoW passes at any difficulty and a fixture that is not
/// about PoW never trips on it. A PoW fixture swaps in a closure that
/// returns what it needs; a fault fixture swaps in one that returns
/// [`Faulted`].
#[derive(Clone, Copy)]
pub struct MockSubstrate {
    /// What `local_clock` returns.
    pub clock: Timestamp,
    /// What `longhash` returns, given the preimage and the seed.
    pub longhash: fn(&[u8], &BlockHash) -> Result<PowHash, Faulted>,
}

impl MockSubstrate {
    /// A clock comfortably after every fixture header's timestamp
    /// ([`fixture::header`] is `1_700_000_000`), so CEN-C1 passes unless a
    /// test moves one or the other.
    pub const CLOCK: Timestamp = Timestamp::from_raw(1_700_000_100);

    /// The longhash that satisfies every target. The `Result` is the fn
    /// pointer's shape, not this function's choice.
    #[allow(clippy::unnecessary_wraps)]
    pub fn always_satisfies(_: &[u8], _: &BlockHash) -> Result<PowHash, Faulted> {
        Ok(PowHash::from_bytes([0; 32]))
    }
}

impl Default for MockSubstrate {
    fn default() -> Self {
        Self {
            clock: Self::CLOCK,
            longhash: Self::always_satisfies,
        }
    }
}

impl Substrate for MockSubstrate {
    type Fault = Faulted;
    type Held = ();

    fn local_clock(&self) -> Result<Timestamp, Faulted> {
        Ok(self.clock)
    }

    fn longhash(&self, pow_blob: &[u8], seed: &BlockHash) -> Result<PowHash, Faulted> {
        (self.longhash)(pow_blob, seed)
    }
}

/// The seed CEN-D3 expects for a candidate on `chain`'s tip: the null hash
/// at genesis admission, else the identity of the block at
/// [`seed_height`](crate::seed_height). What an honest driver claims to
/// `form`.
#[must_use]
pub fn expected_seed(chain: &MockChain) -> BlockHash {
    let connecting = BlockHeight::from_raw(chain.tip().map_or(0, |tip| tip.height.to_raw() + 1));
    let Some(seed_height) = crate::seed_height(connecting) else {
        return BlockHash::NULL;
    };
    match chain.block(seed_height) {
        AtHeight::Recorded(block) => block.header.hash,
        AtHeight::AboveTip => unreachable!("the seed height is below the tip"),
    }
}

/// The target CEN-D4 derives for a candidate on `chain`'s tip under
/// `rule_set`: what an honest driver claims to `form`, through the one
/// derivation (`target_claim`). Panics on a D6 refusal — a fixture chain
/// whose difficulty derives zero is a fixture error.
#[must_use]
#[track_caller]
pub fn expected_target(chain: &MockChain, rule_set: &RuleSet) -> Target {
    let connecting = BlockHeight::from_raw(chain.tip().map_or(0, |tip| tip.height.to_raw() + 1));
    chain.with_view(|view| match target_claim(&view, connecting, rule_set) {
        Ok(Ok(target)) => target,
        Ok(Err(refused)) => panic!("the fixture chain derives no target: {refused}"),
        Err(Fault::View(never)) => match never {},
        Err(fault) => panic!("the fixture chain's headers are not a chain: {fault}"),
    })
}

/// The reference claims an honest driver makes for `candidate` on `chain`
/// (`CHAIN_RULES_CRATE.md` §4.6, the third claim): for each reference a
/// listed body names that the chain records, its height (CEN-I10's read)
/// and the chain's root **at** that height (CEN-I12's anchor, `root_at`,
/// not the fixture header's field — the mock records roots beside its
/// blocks, and a `recorded` header carries a placeholder root). A
/// reference the chain does not hold is not claimed, which is what the
/// driver would do; I10 refuses it in `validate`.
#[must_use]
pub fn expected_references(chain: &MockChain, candidate: &Candidate) -> ReferenceClaims {
    chain.with_view(|view| {
        ReferenceClaims::gather(candidate, |reference| {
            let height = infallible(view.height_of(reference))?;
            match infallible(view.root_at(height)) {
                AtHeight::Recorded(root) => Some(ReferenceClaim { height, root }),
                AtHeight::AboveTip => None,
            }
        })
    })
}

/// Run the stateless stage under `rule_set` with the default substrate,
/// claiming `seed`, `target` and `references`. Panics if the substrate
/// faults or a stateless rule refuses — a fixture that wants to exercise
/// either calls [`form`] itself, or [`judge_on`] for the first refusal of
/// either stage.
#[track_caller]
pub fn formed_under(
    candidate: Candidate,
    rule_set: &RuleSet,
    seed: BlockHash,
    target: Target,
    references: &ReferenceClaims,
) -> StructurallyValid {
    match form(
        candidate,
        rule_set,
        &MockSubstrate::default(),
        seed,
        target,
        references,
        FormAttempt::FIRST,
    ) {
        Ok(Ok(formed)) => formed,
        Ok(Err(refused)) => panic!("the fixture was refused by a stateless rule: {refused}"),
        Err(Faulted) => unreachable!("the default MockSubstrate never faults"),
    }
}

/// [`formed_under`] the genesis rule set, claiming the seed, target and
/// references `chain` expects — the honest driver's call, so D3, D4 and
/// I12's comparison hold and the view stage judges the candidate.
#[track_caller]
pub fn formed_on(chain: &MockChain, candidate: Candidate) -> StructurallyValid {
    let references = expected_references(chain, &candidate);
    formed_under(
        candidate,
        &RuleSet::GENESIS,
        expected_seed(chain),
        expected_target(chain, &RuleSet::GENESIS),
        &references,
    )
}

/// Both stages on `chain` under the genesis rule set, honest claims, the
/// default substrate: `form`'s refusal if it refuses, else `validate`'s
/// verdict. The shape a negative fixture takes when the row it names may
/// be judged in either stage — since the stateless transaction rows and
/// CEN-H19's batch moved into `form`, a refusal a test once read off
/// `validate` may arrive from `form` instead, and the test's subject is
/// the row, not the stage.
#[track_caller]
pub fn judge_on(chain: &MockChain, candidate: Candidate) -> Verdict<()> {
    let references = expected_references(chain, &candidate);
    let formed = match form(
        candidate,
        &RuleSet::GENESIS,
        &MockSubstrate::default(),
        expected_seed(chain),
        expected_target(chain, &RuleSet::GENESIS),
        &references,
        FormAttempt::FIRST,
    ) {
        Ok(Ok(formed)) => formed,
        Ok(Err(refused)) => return Err(refused),
        Err(Faulted) => unreachable!("the default MockSubstrate never faults"),
    };
    chain.with_view(|view| {
        judged(crate::validate::validate(
            formed,
            &view,
            &RuleSet::GENESIS,
            &crate::trust::Trust::UNANCHORED,
        ))
        .map(|_valid| ())
    })
}

/// The token a test of **one view-bound rule alone** reads: the claims an
/// honest driver makes on `chain` (seed, target), the block's identity and
/// the default substrate's clock and longhash — and no stateless judgement.
/// `form` now judges the transactions and CEN-H19's batch; a test whose
/// subject is one `BlockRule` over a candidate built to trip only that rule
/// must not depend on every other row admitting it. Never a verdict: the
/// coverage is empty, so nothing minted from it could pass the mint gate.
pub fn token_for_one_rule(chain: &MockChain, candidate: Candidate) -> StructurallyValid {
    let hash = candidate.block.hash();
    let substrate = MockSubstrate::default();
    let seed = expected_seed(chain);
    let pow = match substrate.longhash(&candidate.block.pow_blob(), &seed) {
        Ok(pow) => pow,
        Err(Faulted) => unreachable!("the default MockSubstrate never faults"),
    };
    let target = expected_target(chain, &RuleSet::GENESIS);
    let header = candidate.block.header.clone();
    StructurallyValid::new(
        candidate,
        RuleSet::GENESIS,
        crate::coverage::RuleCoverage::EMPTY,
        crate::header_facts::HeaderFacts {
            header,
            identity: hash,
            judged_at: substrate.clock,
            seed,
            target,
            attempt: FormAttempt::FIRST,
            proof: crate::header_facts::Proven { longhash: pow },
        },
        Vec::new(),
    )
}

/// [`formed_on`] an empty chain — a genesis candidate.
#[track_caller]
pub fn formed(candidate: Candidate) -> StructurallyValid {
    formed_on(&MockChain::default(), candidate)
}

/// Unwrap a result whose error cannot exist.
pub fn infallible<T>(result: Result<T, Infallible>) -> T {
    match result {
        Ok(value) => value,
        Err(never) => match never {},
    }
}

/// Unwrap a parent-side definition ([`crate::tx_volume_window`],
/// [`crate::mtp_median_at`]) over a view that cannot fault and is dense.
/// A hole is a fixture failure.
#[track_caller]
pub fn defined<T>(read: Result<T, ViewRead<Infallible>>) -> T {
    match read {
        Ok(value) => value,
        Err(ViewRead::View(never)) => match never {},
        Err(ViewRead::Corrupt(corrupt)) => panic!("corrupt view: {corrupt}"),
    }
}

/// Unwrap `validate`'s outer position over a view that cannot fault: the
/// view arm is uninhabited, and the crate's own arms are a fixture failure
/// unless the test asked for them.
#[track_caller]
pub fn judged<T>(result: Result<T, Fault<Infallible>>) -> T {
    match result {
        Ok(value) => value,
        Err(Fault::View(never)) => match never {},
        Err(Fault::Stale(stale)) => panic!("unexpected stale premise: {stale}"),
        Err(Fault::Corrupt(corrupt)) => panic!("unexpected corrupt view: {corrupt}"),
    }
}

/// Assert `result` is exactly a refusal on `rule` at `locus`.
///
/// Panics on a pass ("the rule did not fire"), on a refusal by any other
/// row ("the wrong rule fired"), and on the right row at the wrong place
/// (miner vs listed vs input index) — the three ways a negative fixture
/// goes vacuous.
#[track_caller]
pub fn assert_refused<T: Debug>(result: Verdict<T>, rule: CenRow, locus: Locus) {
    match result {
        Err(InvalidBlock {
            rule: fired,
            locus: at,
        }) if fired == rule && at == locus => {}
        Err(other) => panic!("expected {rule} at {locus}, but {other}"),
        Ok(passed) => {
            panic!("expected {rule} at {locus}, but the candidate passed: {passed:?}")
        }
    }
}

/// A `by_construction` falsifier that serves several rows names every one of
/// them, and this is what each served row must pass: it is registered
/// `by_construction`. Slice 5 Q6's condition — one test credited to N rows
/// is not N rows covered unless the test walks the list — so a falsifier
/// calls this first with the rows it serves, and the coverage gate refuses
/// a shared falsifier whose body does not name each of them. A row re-keyed
/// to another status or another falsifier fails here until it is taken off
/// the list.
#[track_caller]
pub fn credited_to_this_falsifier(rows: &[CenRow], falsifier: &str) {
    for row in rows {
        assert_eq!(
            row.status(),
            crate::census::RowStatus::ByConstruction,
            "{row} is credited to `{falsifier}` but is not registered by_construction"
        );
    }
}

/// Assert `f` passes `last_ok` and refuses `first_bad` on `rule` at `locus`
/// — the two sides of a boundary, so an off-by-one in the rule fails here.
#[track_caller]
pub fn boundary_pair<T: Debug, V>(
    last_ok: V,
    first_bad: V,
    rule: CenRow,
    locus: Locus,
    f: impl Fn(V) -> Verdict<T>,
) {
    if let Err(refused) = f(last_ok) {
        panic!("the last acceptable value was refused: {refused}");
    }
    assert_refused(f(first_bad), rule, locus);
}
