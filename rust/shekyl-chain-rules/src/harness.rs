// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The negative-fixture harness: a mock chain, a branded mock view, a view
//! whose every read faults, and the two assertions every rule test is
//! written with (`CHAIN_RULES_CRATE.md` §8.7).
//!
//! Test-only (`#[cfg(test)]` at the declaration). Rules are generic over
//! `ChainView<'id>`, so a rule is exercised here against a [`MockChain`](crate::harness::MockChain) of
//! a few recorded blocks with no database — the capability the C++ never
//! had (C2-R8 §9.1). A harness with no subject is a vacuous pass; the probe
//! in `harness_probe_tests.rs` is the subject that keeps this one honest.

use core::convert::Infallible;
use core::fmt::Debug;
use core::marker::PhantomData;
use std::collections::BTreeSet;

use shekyl_difficulty::{CumulativeDifficulty, GENESIS_DIFFICULTY};
use shekyl_types::{
    AttestationRoot, BlockHash, BlockHeight, CurveTreeRoot, KeyImage, PowHash, Timestamp,
};
use shekyl_units::AtomicUnits;
use shekyl_wire::transaction::PQC_HYBRID_SINGLE_KEY_LEN;
use shekyl_wire::tx_extra::{
    self, conforming_pqc_leaf_blob, TxExtraField, COINBASE_NONCE_BYTES, HYBRID_KEM_CT_BYTES,
};
use shekyl_wire::{
    Block, BlockHeader, BpPlus, Ct, CtBase, Input, Output, PqcAuth, Prunable, Transaction, TxPrefix,
};

use crate::block::{Candidate, StructurallyValid};
use crate::census::CenRow;
use crate::fault::{Fault, FormAttempt, ViewRead};
use crate::rule_set::RuleSet;
use crate::substrate::Substrate;
use crate::validate::form;
use crate::verdict::{InvalidBlock, Locus, Verdict};
use crate::view::{AtHeight, ChainView, RecordedBlock, Tip};

/// Invariant brand, as in `verdict.rs`.
type Brand<'id> = PhantomData<fn(&'id ()) -> &'id ()>;

/// A recorded chain in memory — **a struct literal with a `ChainView`
/// impl, and nothing else**. It computes nothing; every value it serves is
/// a value a test pushed into it.
///
/// # Charter (slice 6 §5.2, `50-testing.mdc`) — three jobs
///
/// A mock that is *told* a root, a depth or a spent set and *serves* it to
/// a rule proves that the rule reads what it was handed — none of the
/// evidence about production behaviour a green check implies. So this type
/// is the right instrument for exactly three things, and no fourth:
///
/// 1. **Predicate logic on plain values, where there is no state to
///    fake** — a window's boundary arithmetic, an ordering, a count, a
///    derivation being *recorded*. The chain is incidental; the test is
///    about the arithmetic.
/// 2. **Faults the real substrate cannot be made to exhibit on demand** —
///    "a store fault propagates as a `Fault`, never a verdict" needs a view
///    that fails at height 7 ([`FaultingView`]); a real store will not.
/// 3. **States a conforming store refuses to hold** — a tip that says one
///    height and a row missing below it. The instrument is
///    [`WithholdingView`]: one read ([`WithheldRead`]) answers `AboveTip`,
///    and the assertion is the fault class, never a verdict.
///
/// The line between the three and everything else is whether the chain is
/// the subject. "This block exists", "this root is what the tree grew",
/// "this depth is consistent with the leaves" are assertions about a chain,
/// and a constructed view answering them tests the construction. The witness
/// for a rule that reads derived state is the real chain: captured regtest
/// blocks replayed through `form → validate → connect` against a real
/// store, in `shekyl-chain-ingest` (`vectors_tests.rs`), which is where the
/// dependency-direction belt (`check_chain_rules_no_store.sh`) allows a
/// store to live.
///
/// Blocks and roots are **dense by construction**: [`push`](Self::push)
/// appends at `tip + 1`, so — like the store — the only absence the view can
/// report is above the tip. Key images are a set.
///
/// Roots are keyed the way the store keys them (S-CHAIN-W SCW-19):
/// `root_at(h)` is the tree state **at** `h` — after block `h − 1` connected,
/// before block `h` drained — so `roots[0]` is the empty tree, the root
/// pushed *with* block `h` is `roots[h + 1]`, and `root_at(tip + 1)` is
/// recorded (the state the next candidate is checked against, CEN-B5) while
/// `root_at(tip + 2)` is `AboveTip`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MockChain {
    recorded: Vec<RecordedBlock>,
    /// `roots[h]` = the tree state at height `h`; `roots.len() == recorded.len() + 1`.
    roots: Vec<CurveTreeRoot>,
    key_images: BTreeSet<KeyImage>,
}

impl Default for MockChain {
    fn default() -> Self {
        Self {
            recorded: Vec::new(),
            roots: vec![CurveTreeRoot::EMPTY],
            key_images: BTreeSet::new(),
        }
    }
}

impl MockChain {
    /// Append a block at `tip + 1` and the tree state **after** it — what
    /// `root_at(tip + 2)` will return, and what the header of the block
    /// after it must carry (CEN-B5).
    pub fn push(mut self, block: RecordedBlock, root_after: CurveTreeRoot) -> Self {
        self.recorded.push(block);
        self.roots.push(root_after);
        self
    }

    /// Record a spent key image.
    pub fn with_key_image(mut self, key_image: KeyImage) -> Self {
        self.key_images.insert(key_image);
        self
    }

    /// The last recorded block — height and identity — if any.
    #[must_use]
    pub fn tip(&self) -> Option<Tip> {
        let len = u64::try_from(self.recorded.len()).expect("a Vec fits in u64");
        let height = BlockHeight::from_raw(len.checked_sub(1)?);
        let block = self.recorded.last()?;
        Some(Tip {
            height,
            hash: block.hash,
        })
    }

    /// Project a branded view and run `f` against it.
    ///
    /// `'id` is fresh per call — `f` must accept *any* brand, so no caller
    /// can name it, and two calls yield two brands. The mock's analogue of
    /// the store's `write`: a `ChainValid<'id, MockView<'_, 'id>>` minted
    /// inside one call is not a `ChainValid` of any other.
    pub fn with_view<R>(&self, f: impl for<'id> FnOnce(MockView<'_, 'id>) -> R) -> R {
        f(MockView {
            chain: self,
            _brand: PhantomData,
        })
    }

    fn block(&self, height: BlockHeight) -> AtHeight<&RecordedBlock> {
        usize::try_from(height.to_raw())
            .ok()
            .and_then(|index| self.recorded.get(index))
            .map_or(AtHeight::AboveTip, AtHeight::Recorded)
    }

    fn root(&self, height: BlockHeight) -> AtHeight<CurveTreeRoot> {
        usize::try_from(height.to_raw())
            .ok()
            .and_then(|index| self.roots.get(index))
            .map_or(AtHeight::AboveTip, |root| AtHeight::Recorded(*root))
    }
}

/// A `ChainView<'id>` over a [`MockChain`]. Never faults.
pub struct MockView<'a, 'id> {
    chain: &'a MockChain,
    _brand: Brand<'id>,
}

impl<'id> ChainView<'id> for MockView<'_, 'id> {
    type Fault = Infallible;

    fn has_key_image(&self, key_image: &KeyImage) -> Result<bool, Infallible> {
        Ok(self.chain.key_images.contains(key_image))
    }

    fn block_at(&self, height: BlockHeight) -> Result<AtHeight<RecordedBlock>, Infallible> {
        Ok(match self.chain.block(height) {
            AtHeight::Recorded(block) => AtHeight::Recorded(block.clone()),
            AtHeight::AboveTip => AtHeight::AboveTip,
        })
    }

    fn height_of(&self, hash: &BlockHash) -> Result<Option<BlockHeight>, Infallible> {
        Ok(self
            .chain
            .recorded
            .iter()
            .position(|block| block.hash == *hash)
            .map(|index| BlockHeight::from_raw(u64::try_from(index).expect("a Vec fits in u64"))))
    }

    fn root_at(&self, height: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, Infallible> {
        Ok(self.chain.root(height))
    }

    fn tip(&self) -> Result<Option<Tip>, Infallible> {
        Ok(self.chain.tip())
    }
}

/// The fault a [`FaultingView`] raises.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Faulted;

/// A view whose every read faults — the substrate failing under the rule.
#[derive(Default)]
pub struct FaultingView<'id>(Brand<'id>);

impl<'id> ChainView<'id> for FaultingView<'id> {
    type Fault = Faulted;

    fn has_key_image(&self, _: &KeyImage) -> Result<bool, Faulted> {
        Err(Faulted)
    }

    fn block_at(&self, _: BlockHeight) -> Result<AtHeight<RecordedBlock>, Faulted> {
        Err(Faulted)
    }

    fn height_of(&self, _: &BlockHash) -> Result<Option<BlockHeight>, Faulted> {
        Err(Faulted)
    }

    fn root_at(&self, _: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, Faulted> {
        Err(Faulted)
    }

    fn tip(&self) -> Result<Option<Tip>, Faulted> {
        Err(Faulted)
    }
}

/// The one per-height read a [`WithholdingView`] answers `AboveTip` for.
///
/// One read, one height. A view that withholds several, or that lies about
/// its tip, is a different instrument and is not this one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WithheldRead {
    /// [`ChainView::block_at`] at this height — the block row.
    BlockAt(BlockHeight),
    /// [`ChainView::root_at`] at this height — the curve-tree root.
    RootAt(BlockHeight),
}

/// A [`MockView`] with one per-height read withheld.
///
/// Charter job 3. A conforming store refuses to hold this (SI-7): the tip
/// still says the chain is dense, and one row answers [`AtHeight::AboveTip`].
/// The assertion a test makes with it is the fault class — [`crate::Corrupt`]
/// — never a verdict. Every read other than the withheld one is the inner
/// mock's, so the contradiction is exactly one fact.
pub struct WithholdingView<'a, 'id> {
    inner: MockView<'a, 'id>,
    withheld: WithheldRead,
}

impl<'a, 'id> MockView<'a, 'id> {
    /// Withhold `read`. The mock moves into the wrapper; the chain it
    /// borrows is unchanged.
    #[must_use]
    pub fn withholding(self, read: WithheldRead) -> WithholdingView<'a, 'id> {
        WithholdingView {
            inner: self,
            withheld: read,
        }
    }
}

impl<'id> ChainView<'id> for WithholdingView<'_, 'id> {
    type Fault = Infallible;

    fn has_key_image(&self, key_image: &KeyImage) -> Result<bool, Infallible> {
        self.inner.has_key_image(key_image)
    }

    fn block_at(&self, height: BlockHeight) -> Result<AtHeight<RecordedBlock>, Infallible> {
        if let WithheldRead::BlockAt(at) = self.withheld {
            if height == at {
                return Ok(AtHeight::AboveTip);
            }
        }
        self.inner.block_at(height)
    }

    fn height_of(&self, hash: &BlockHash) -> Result<Option<BlockHeight>, Infallible> {
        self.inner.height_of(hash)
    }

    fn root_at(&self, height: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, Infallible> {
        if let WithheldRead::RootAt(at) = self.withheld {
            if height == at {
                return Ok(AtHeight::AboveTip);
            }
        }
        self.inner.root_at(height)
    }

    fn tip(&self) -> Result<Option<Tip>, Infallible> {
        self.inner.tip()
    }
}

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
        AtHeight::Recorded(block) => block.hash,
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

pub mod fixture;

#[cfg(test)]
#[path = "harness_probe_tests.rs"]
mod harness_probe_tests;

#[cfg(test)]
#[path = "fixture_sanity_tests.rs"]
mod fixture_sanity_tests;
