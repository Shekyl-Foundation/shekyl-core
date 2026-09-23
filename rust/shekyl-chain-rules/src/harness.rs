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

use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{
    AttestationRoot, BlockHash, BlockHeight, CurveTreeRoot, KeyImage, PowHash, Timestamp,
};
use shekyl_units::AtomicUnits;
use shekyl_wire::{Block, BlockHeader, Ct, CtBase, Input, Output, Transaction, TxPrefix};

use crate::block::{Candidate, StructurallyValid};
use crate::census::CenRow;
use crate::fault::{Fault, FormAttempt};
use crate::rule_set::RuleSet;
use crate::substrate::Substrate;
use crate::validate::form;
use crate::verdict::{InvalidBlock, Locus, Verdict};
use crate::view::{AtHeight, ChainView, RecordedBlock, Tip};

/// Invariant brand, as in `verdict.rs`.
type Brand<'id> = PhantomData<fn(&'id ()) -> &'id ()>;

/// A recorded chain in memory.
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

    fn root_at(&self, _: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, Faulted> {
        Err(Faulted)
    }

    fn tip(&self) -> Result<Option<Tip>, Faulted> {
        Err(Faulted)
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

/// Fixtures: well-formed values to mutate one field of.
///
/// **"Well-formed" is a gated claim, not a label.** A fixture is built by
/// test code and never passes through a production builder, so it can be
/// illegal in ways nobody checks — and each latent illegality surfaces one
/// rule at a time, as a mid-commit surprise, when the rule that refuses it
/// lands (slice 5 commit 2: three fixtures listed coinbase-shaped bodies,
/// and CEN-H5 refused them). `fixture_sanity_tests` holds every fixture
/// here to `validate` / `tx_form` under **current** coverage, at every slot
/// it is meant for, so a bad fixture fails the moment it is written. A new
/// valid fixture is added there too; the negative fixtures live with their
/// rows and are labelled by the row they refuse on.
pub mod fixture {
    use super::*;

    /// The compressed Ed25519 basepoint `G`: canonical, prime-order,
    /// non-identity — an output key CEN-F9 accepts. As a **mask** it is the
    /// trivial form CEN-F10 refuses (`mask = 1, amount = 0`), which is
    /// what the F10 fixture uses it for.
    pub const G: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ];

    /// `2·G` compressed: a canonical prime-order point that is neither the
    /// identity, nor `G`, nor `zeroCommit(0) = G` — a commitment mask CEN-F10
    /// accepts for a zero-amount coinbase output. `fixture_points_are_what_
    /// they_claim` (miner_tests) pins both constants through
    /// `shekyl-ct-balance`.
    pub const TWO_G: [u8; 32] = [
        0xc9, 0xa3, 0xf8, 0x6a, 0xae, 0x46, 0x5f, 0x0e, 0x56, 0x51, 0x38, 0x64, 0x51, 0x0f, 0x39,
        0x97, 0x56, 0x1f, 0xa2, 0xc9, 0xe8, 0x5e, 0xa2, 0x1d, 0xc2, 0x29, 0x23, 0x09, 0xf3, 0xcd,
        0x60, 0x22,
    ];

    /// A coinbase that satisfies every structural 4.F row for a block at
    /// `height`: one `Input::Gen(height)` (F1, F5), `Ct::Null` (F3), one
    /// output (F4) paying `0` with key `G` (F9) and mask `2·G` (F10),
    /// `unlock_time = height + mined_money_unlock_window` (F6). Amounts are
    /// not this fixture's concern — the exact-payout row (F18) is not
    /// landed — so a chain of these pays nothing and reads the tail subsidy
    /// at every height.
    ///
    /// The F6 claim holds at every height a chain can reach. Within the
    /// window of `u64::MAX` no coinbase satisfies F6 — the rule's own sum
    /// overflows and it refuses (`rules::miner::F6`) — so the fixture
    /// saturates rather than panics there: the corpus tests build records
    /// at `u64::MAX` to exercise height exhaustion in the *store*, and need
    /// the bytes, not a verdict.
    pub fn coinbase(height: u64) -> Transaction {
        let unlock_time =
            height.saturating_add(RuleSet::GENESIS.mined_money_unlock_window().to_raw());
        Transaction {
            prefix: TxPrefix {
                unlock_time,
                inputs: vec![Input::Gen(height)],
                outputs: vec![Output {
                    amount: 0,
                    key: G,
                    view_tag: 1,
                }],
                extra: Vec::new(),
            },
            ct: Ct::Null(CtBase {
                enc_amounts: vec![[0x55; 9]],
                enc_labels: vec![[0x66; 9]],
                commitments: vec![TWO_G],
            }),
        }
    }

    /// A **listed** (non-coinbase) transaction spending `key_image`, shaped
    /// to pass every structural 4.H row that has landed: one `ToKey` input
    /// with empty offsets (CEN-I6), one zero-amount output keyed `G` with a
    /// `2·G` mask (H7, H17), `Ct::Fcmp` with the committed base sized to the
    /// outputs (H8), `unlock_time` below the sentinel (H16). No prunable
    /// region: the proof rows (H19's verification, 4.I) are not landed, and
    /// a fixture that carried an unverifiable proof would be a lie about
    /// what the rules accept. Mutate one field to build a negative fixture.
    pub fn listed(key_image: [u8; 32]) -> Transaction {
        Transaction {
            prefix: TxPrefix {
                unlock_time: 0,
                inputs: vec![Input::ToKey {
                    amount: 0,
                    key_offsets: Vec::new(),
                    key_image,
                }],
                outputs: vec![Output {
                    amount: 0,
                    key: G,
                    view_tag: 2,
                }],
                extra: Vec::new(),
            },
            ct: Ct::Fcmp {
                fee: 7,
                reference_block: BlockHash::from_bytes([0x99; 32]),
                base: CtBase {
                    enc_amounts: vec![[0x11; 9]],
                    enc_labels: vec![[0x22; 9]],
                    commitments: vec![TWO_G],
                },
                pqc_auths: Vec::new(),
                prunable: None,
            },
        }
    }

    /// A **serve-credit-only** transaction (CEN-H20's shape: serve-credit
    /// inputs and nothing else, no outputs, zero fee, no spend material),
    /// carrying `record` as its one pass record. The one legal non-coinbase
    /// shape with **no key image** — what a test needs when it must list the
    /// same body twice (SI-3) without tripping the spent-key-image set. The
    /// record's bytes are the wire's minimum (tag byte, then payload); the
    /// serving-credit rules that read them are 4.J's, not this crate's yet.
    pub fn serve_credit_only(record: [u8; 32]) -> Transaction {
        let mut canonical_bytes = vec![shekyl_wire::transaction::TAG_INPUT_SERVE_CREDIT];
        canonical_bytes.extend_from_slice(&record);
        Transaction {
            prefix: TxPrefix {
                unlock_time: 0,
                inputs: vec![Input::ServeCredit { canonical_bytes }],
                outputs: Vec::new(),
                extra: Vec::new(),
            },
            ct: Ct::Fcmp {
                fee: 0,
                reference_block: BlockHash::from_bytes([0x99; 32]),
                base: CtBase {
                    enc_amounts: Vec::new(),
                    enc_labels: Vec::new(),
                    commitments: Vec::new(),
                },
                pqc_auths: Vec::new(),
                prunable: None,
            },
        }
    }

    /// A header with every field set to a recognisable non-zero value —
    /// the shape of a *recorded* block. A candidate takes its `previous` and
    /// `curve_tree_root` from the chain it is built on ([`candidate_on`]).
    pub fn header() -> BlockHeader {
        BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: 1_700_000_000,
            previous: BlockHash::from_bytes([0x11; 32]),
            nonce: 7,
            curve_tree_root: CurveTreeRoot::from_bytes([0x22; 32]),
            attestation_root: AttestationRoot::from_bytes([0x33; 32]),
        }
    }

    /// A well-formed candidate **on `chain`'s tip**: `previous` is the tip's
    /// hash (the null hash on an empty chain — CEN-A2) and `curve_tree_root`
    /// is the tree state at the connecting height (`root_at(tip + 1)`; the
    /// empty tree at genesis — CEN-B5); the header lists exactly the bodies
    /// it carries. Mutate one field to build a negative fixture.
    pub fn candidate_on(chain: &MockChain, listed: Vec<Transaction>) -> Candidate {
        let tip = chain.tip();
        let connecting = Tip::connecting_height(tip.as_ref());
        let root = match chain.root(connecting) {
            AtHeight::Recorded(root) => root,
            AtHeight::AboveTip => unreachable!("the mock records the root at tip + 1"),
        };
        let block = Block {
            header: BlockHeader {
                previous: tip.map_or(BlockHash::NULL, |t| t.hash),
                curve_tree_root: root,
                ..header()
            },
            miner_transaction: coinbase(connecting.to_raw()),
            transaction_hashes: listed.iter().map(Transaction::hash).collect(),
        };
        Candidate::new(block, listed)
    }

    /// A well-formed **genesis** candidate: [`candidate_on`] an empty chain.
    pub fn candidate(listed: Vec<Transaction>) -> Candidate {
        candidate_on(&MockChain::default(), listed)
    }

    /// A recorded block whose header carries `timestamp`, identity derived,
    /// with **no work recorded** (`cumulative_difficulty` zero). Enough for
    /// every fixture that is not about difficulty — a chain shorter than
    /// the LWMA-1 window never reads the field — and a chain that *is*
    /// about it builds its series with [`recorded_with_work`].
    pub fn recorded(timestamp: u64) -> RecordedBlock {
        recorded_with_work(timestamp, CumulativeDifficulty::ZERO)
    }

    /// A recorded block with `timestamp` and `cumulative_difficulty` both
    /// chosen — the LWMA-1 fixtures' shape.
    pub fn recorded_with_work(
        timestamp: u64,
        cumulative_difficulty: CumulativeDifficulty,
    ) -> RecordedBlock {
        let block = Block {
            header: BlockHeader {
                timestamp,
                ..header()
            },
            // Recorded blocks are never judged, so the coinbase's height
            // claim does not matter; `0` keeps the identity a pure
            // function of `timestamp`.
            miner_transaction: coinbase(0),
            transaction_hashes: Vec::new(),
        };
        RecordedBlock {
            hash: block.hash(),
            header: block.header,
            cumulative_difficulty,
            // No emission recorded and no listed transactions: a chain
            // whose fixtures are not about the coinbase reads the tail
            // subsidy at every height and a zero volume window. A fixture
            // that is about them sets both (`recorded_with_emission`).
            coins_generated: AtomicUnits::ZERO,
            cumulative_tx_count: 0,
        }
    }

    /// A curve-tree root filled with `byte`.
    #[must_use]
    pub const fn root(byte: u8) -> CurveTreeRoot {
        CurveTreeRoot::from_bytes([byte; 32])
    }
}

#[cfg(test)]
#[path = "harness_probe_tests.rs"]
mod harness_probe_tests;

#[cfg(test)]
#[path = "fixture_sanity_tests.rs"]
mod fixture_sanity_tests;
