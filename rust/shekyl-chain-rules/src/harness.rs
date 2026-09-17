// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The negative-fixture harness: a mock chain, a branded mock view, a view
//! whose every read faults, and the two assertions every rule test is
//! written with (`CHAIN_RULES_CRATE.md` §8.7).
//!
//! Test-only (`#[cfg(test)]` at the declaration). Rules are generic over
//! `ChainView<'id>`, so a rule is exercised here against a [`MockChain`] of
//! a few recorded blocks with no database — the capability the C++ never
//! had (C2-R8 §9.1). A harness with no subject is a vacuous pass; the probe
//! in `harness_probe_tests.rs` is the subject that keeps this one honest.

use core::convert::Infallible;
use core::fmt::Debug;
use core::marker::PhantomData;
use std::collections::BTreeSet;

use shekyl_types::{BlockHash, BlockHeight, CurveTreeRoot, KeyImage};
use shekyl_wire::{Block, BlockHeader, Ct, CtBase, Transaction, TxPrefix};

use crate::block::Candidate;
use crate::census::CenRow;
use crate::verdict::{InvalidBlock, Locus, Verdict};
use crate::view::{AtHeight, ChainView, RecordedBlock, Tip};

/// Invariant brand, as in `verdict.rs`.
type Brand<'id> = PhantomData<fn(&'id ()) -> &'id ()>;

/// A recorded chain in memory.
///
/// Blocks and roots are **dense by construction**: [`push`](Self::push)
/// appends at `tip + 1`, so — like the store — the only absence the view can
/// report is above the tip. Key images are a set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MockChain {
    recorded: Vec<(RecordedBlock, CurveTreeRoot)>,
    key_images: BTreeSet<KeyImage>,
}

impl MockChain {
    /// Append a block and the curve-tree root after it at the next height.
    pub fn push(mut self, block: RecordedBlock, root: CurveTreeRoot) -> Self {
        self.recorded.push((block, root));
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
        let (block, _) = self.recorded.last()?;
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

    fn at(&self, height: BlockHeight) -> AtHeight<&(RecordedBlock, CurveTreeRoot)> {
        usize::try_from(height.to_raw())
            .ok()
            .and_then(|index| self.recorded.get(index))
            .map_or(AtHeight::AboveTip, AtHeight::Recorded)
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
        Ok(match self.chain.at(height) {
            AtHeight::Recorded((block, _)) => AtHeight::Recorded(block.clone()),
            AtHeight::AboveTip => AtHeight::AboveTip,
        })
    }

    fn root_at(&self, height: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, Infallible> {
        Ok(match self.chain.at(height) {
            AtHeight::Recorded((_, root)) => AtHeight::Recorded(*root),
            AtHeight::AboveTip => AtHeight::AboveTip,
        })
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

/// Unwrap a result whose error cannot exist.
pub fn infallible<T>(result: Result<T, Infallible>) -> T {
    match result {
        Ok(value) => value,
        Err(never) => match never {},
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
pub mod fixture {
    use super::*;

    /// A coinbase-shaped transaction, distinguished by `unlock_time`.
    pub fn coinbase(unlock_time: u64) -> Transaction {
        Transaction {
            prefix: TxPrefix {
                unlock_time,
                inputs: Vec::new(),
                outputs: Vec::new(),
                extra: Vec::new(),
            },
            ct: Ct::Null(CtBase {
                enc_amounts: Vec::new(),
                enc_labels: Vec::new(),
                commitments: Vec::new(),
            }),
        }
    }

    /// A header with every field set to a recognisable non-zero value.
    pub fn header() -> BlockHeader {
        BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: 1_700_000_000,
            previous: [0x11; 32],
            nonce: 7,
            curve_tree_root: [0x22; 32],
            attestation_root: [0x33; 32],
        }
    }

    /// A candidate whose header lists exactly the bodies it carries.
    pub fn candidate(listed: Vec<Transaction>) -> Candidate {
        let block = Block {
            header: header(),
            miner_transaction: coinbase(60),
            transaction_hashes: listed.iter().map(Transaction::hash).collect(),
        };
        Candidate::new(block, listed)
    }

    /// A recorded block whose header carries `timestamp`, identity derived.
    pub fn recorded(timestamp: u64) -> RecordedBlock {
        let block = Block {
            header: BlockHeader {
                timestamp,
                ..header()
            },
            miner_transaction: coinbase(60),
            transaction_hashes: Vec::new(),
        };
        RecordedBlock {
            hash: BlockHash::from_bytes(block.hash()),
            header: block.header,
        }
    }

    /// A curve-tree root filled with `byte`.
    #[must_use]
    pub const fn root(byte: u8) -> CurveTreeRoot {
        CurveTreeRoot::from_bytes([byte; 32])
    }
}

#[path = "harness_probe_tests.rs"]
mod harness_probe_tests;
