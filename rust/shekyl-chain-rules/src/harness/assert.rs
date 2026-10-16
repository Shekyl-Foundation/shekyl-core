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
use crate::block::{Candidate, StructurallyValid};
use crate::census::CenRow;
use crate::fault::{Fault, FormAttempt, ViewRead};
use crate::rule_set::RuleSet;
use crate::substrate::Substrate;
use crate::validate::form;
use crate::verdict::{InvalidBlock, Locus, Verdict};
use crate::view::AtHeight;

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

/// Run the stateless stage under `rule_set` with the default substrate,
/// claiming `seed`. Panics if the substrate faults or a stateless rule
/// refuses — a fixture that wants to exercise either calls [`form`] itself.
#[track_caller]
pub fn formed_under(
    candidate: Candidate,
    rule_set: &RuleSet,
    seed: BlockHash,
) -> StructurallyValid {
    match form(
        candidate,
        rule_set,
        &MockSubstrate::default(),
        seed,
        FormAttempt::FIRST,
    ) {
        Ok(Ok(formed)) => formed,
        Ok(Err(refused)) => panic!("the fixture was refused by a stateless rule: {refused}"),
        Err(Faulted) => unreachable!("the default MockSubstrate never faults"),
    }
}

/// [`formed_under`] the genesis rule set, claiming the seed `chain` expects
/// — the honest driver's call, so D3 holds and the view stage judges the
/// candidate.
#[track_caller]
pub fn formed_on(chain: &MockChain, candidate: Candidate) -> StructurallyValid {
    formed_under(candidate, &RuleSet::GENESIS, expected_seed(chain))
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
