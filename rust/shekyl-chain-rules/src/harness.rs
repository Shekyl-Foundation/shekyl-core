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
use std::collections::{BTreeMap, BTreeSet};

use shekyl_difficulty::{CumulativeDifficulty, GENESIS_DIFFICULTY};
use shekyl_economics::FULL_REWARD_ZONE;
use shekyl_types::archival::{RMarket, SigmaWorkMilli};
use shekyl_types::{
    AttestationRoot, BlockCount, BlockHash, BlockHeight, BlockWeight, CurveTreeRoot, KeyImage,
    LongTermWeight, SettlementEpoch, ShardId, TxHash,
};
use shekyl_units::AtomicUnits;
use shekyl_wire::transaction::PQC_HYBRID_SINGLE_KEY_LEN;
use shekyl_wire::tx_extra::{
    self, conforming_pqc_leaf_blob, TxExtraField, COINBASE_NONCE_BYTES, HYBRID_KEM_CT_BYTES,
};
use shekyl_wire::{
    Block, BlockHeader, BondPost, BpPlus, Ct, CtBase, Input, Output, PqcAuth, Prunable,
    Transaction, TxPrefix,
};

use crate::block::Candidate;
use crate::rule_set::RuleSet;
use crate::tree_growth::TreeFrontier;
use crate::view::{AtHeight, BlockOutputs, ChainView, RecordedBlock, RecordedWeights, Tip};

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
/// 3. **States a conforming store refuses to hold.** The assertion is the
///    fault class, never a verdict. Two instruments: [`WithholdingView`]
///    answers `AboveTip` for one per-height read ([`WithheldRead`]) while
///    the tip still says the chain is dense; [`NonCanonicalBondView`]
///    serves one persona a bond record whose hybrid key is not canonical
///    bytes. A valid bond, a derived root, or a spent set is neither
///    instrument — those are the real chain's to witness.
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
/// Trees are keyed the way the store keys them (S-CHAIN-W SCW-19):
/// `root_at(h)` is the tree state **at** `h` — after block `h − 1` connected,
/// before block `h` drained — so `trees[0]` is the empty tree, the tree
/// pushed *with* block `h` is `trees[h + 1]`, and `root_at(tip + 1)` is
/// recorded (the state the next candidate is checked against, CEN-B5) while
/// `root_at(tip + 2)` is `AboveTip`. The leaf count is keyed identically and
/// travels with the root it is a function of ([`PlantedTree`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MockChain {
    recorded: Vec<RecordedBlock>,
    /// `trees[h]` = the tree state at height `h`; `trees.len() == recorded.len() + 1`.
    ///
    /// The mock is **told** its tree, never derives it: it records no
    /// outputs, so nothing here grows, and a root or a count is what a
    /// fixture pushed. A count other than `0` is a planted tree, the way a
    /// planted key image is a planted spend — a fixture that names one
    /// ([`push_tree`](Self::push_tree)) declares the tree is not its
    /// subject; a fixture whose subject *is* the tree's depth uses
    /// `I13::admits`, and the tree's own witness is a driven chain
    /// (`scenario_*`). Until 2026-10-07 `leaf_count_at` answered `0` for
    /// every recorded height whatever root sat there, a tree question the
    /// mock was never asked to hold; this is the symmetry that replaced it.
    trees: Vec<PlantedTree>,
    /// `weights[h]` = block `h`'s two recorded weights; `weights.len() ==
    /// recorded.len()`. What the store projects from `block_info` for
    /// CEN-G6's medians (slice 7); [`push`](Self::push) records the
    /// penalty-free zone for both, the value the C++ floors a short chain's
    /// median to, so a fixture that is not about weights names none.
    weights: Vec<RecordedWeights>,
    key_images: BTreeSet<KeyImage>,
    /// Every transaction identity recorded on the chain — CEN-G1's read.
    /// The mock cannot derive these from [`RecordedBlock`] (no bodies cross
    /// the view, G13), so a fixture that lists a recorded transaction
    /// records its hash here, as the store's `tx_indices` would hold it.
    transactions: BTreeSet<TxHash>,
    /// The chain's destroyed fold — CEN-F17's `total_burned` read. Zero
    /// unless a fixture names one ([`with_total_burned`](Self::with_total_burned));
    /// the mock's recorded blocks burn nothing, so a value here is a
    /// planted fold, the way a planted key image is a planted spend.
    total_burned: AtomicUnits,
    /// Planted market prices — CEN-J15's `r_market` read, keyed as the
    /// view keys it ([`with_r_market`](Self::with_r_market)). Empty unless
    /// a fixture prices a shard.
    r_market: BTreeMap<(ShardId, SettlementEpoch), RMarket>,
    /// Planted frozen closes — CEN-J23's `budget` and CEN-J25's
    /// `sigma_work` reads, per epoch ([`with_close`](Self::with_close)).
    /// With the prices, the archival reads this chain plants; every other
    /// archival read answers *no bonds*. Empty unless a fixture closes an
    /// epoch.
    closes: BTreeMap<SettlementEpoch, (SigmaWorkMilli, AtomicUnits)>,
}

impl Default for MockChain {
    fn default() -> Self {
        Self {
            recorded: Vec::new(),
            trees: vec![PlantedTree::EMPTY],
            weights: Vec::new(),
            key_images: BTreeSet::new(),
            transactions: BTreeSet::new(),
            total_burned: AtomicUnits::ZERO,
            r_market: BTreeMap::new(),
            closes: BTreeMap::new(),
        }
    }
}

impl MockChain {
    /// Plant the chain's `total_burned` fold — what CEN-F17's supply
    /// operand reads beside the parent's accumulator. A fold above the
    /// accumulator is the corrupt view F17 halts on.
    #[must_use]
    pub const fn with_total_burned(mut self, total_burned: AtomicUnits) -> Self {
        self.total_burned = total_burned;
        self
    }

    /// Append a block at `tip + 1` and the root **after** it — what
    /// `root_at(tip + 2)` will return, and what the header of the block
    /// after it must carry (CEN-B5). The leaf count carries over from the
    /// tree before: the mock records no outputs, so a pushed block grows
    /// nothing, and a chain built by `push` alone has the empty tree's
    /// count (`0`) at every height. The block's weights are the
    /// penalty-free zone, both columns; a weights fixture uses
    /// [`push_weighing`](Self::push_weighing).
    pub fn push(self, block: RecordedBlock, root_after: CurveTreeRoot) -> Self {
        self.push_weighing(block, root_after, Self::ZONE_WEIGHTS)
    }

    /// [`push`](Self::push) with the block's recorded weights named — what
    /// `weights_window` will return for its height.
    pub fn push_weighing(
        self,
        block: RecordedBlock,
        root_after: CurveTreeRoot,
        weights: RecordedWeights,
    ) -> Self {
        let leaf_count = self.trees.last().expect("never empty").leaf_count;
        let tree_after = PlantedTree {
            root: root_after,
            leaf_count,
        };
        self.push_recording(block, tree_after, weights)
    }

    /// [`push`](Self::push) with the tree after the block **planted** —
    /// its root and its leaf count together, what `root_at(tip + 2)` and
    /// `leaf_count_at(tip + 2)` (so `depth_at`) will return. A planted
    /// tree, the register's sense: the mock did not grow it and cannot
    /// serve its chunks ([`MockView::tree_frontier`]); a fixture plants one
    /// to put a tree of some depth under a rule whose subject is not the
    /// tree (CEN-I13's admission is the pure `I13::admits`; the grown
    /// tree's witness is a driven chain).
    pub fn push_tree(
        self,
        block: RecordedBlock,
        root_after: CurveTreeRoot,
        leaf_count_after: u64,
    ) -> Self {
        self.push_tree_weighing(block, root_after, leaf_count_after, Self::ZONE_WEIGHTS)
    }

    /// [`push_tree`](Self::push_tree) with the block's recorded weights
    /// named as well — a mirror of a real store's block carries both the
    /// tree the store recorded after it and the weights it recorded for
    /// it, and a conformance twin that omits either answers a rule's read
    /// differently from the store it mirrors (CEN-I13 reads `depth_at`,
    /// CEN-G6 the weights window).
    pub fn push_tree_weighing(
        self,
        block: RecordedBlock,
        root_after: CurveTreeRoot,
        leaf_count_after: u64,
        weights: RecordedWeights,
    ) -> Self {
        let tree_after = PlantedTree {
            root: root_after,
            leaf_count: leaf_count_after,
        };
        self.push_recording(block, tree_after, weights)
    }

    /// The penalty-free zone in both weight columns — what a block whose
    /// fixture is not about weights records.
    const ZONE_WEIGHTS: RecordedWeights = RecordedWeights {
        weight: BlockWeight::from_raw(FULL_REWARD_ZONE),
        long_term_weight: LongTermWeight::from_raw(FULL_REWARD_ZONE),
    };

    fn push_recording(
        mut self,
        block: RecordedBlock,
        tree_after: PlantedTree,
        weights: RecordedWeights,
    ) -> Self {
        self.recorded.push(block);
        self.trees.push(tree_after);
        self.weights.push(weights);
        self
    }

    /// Record a spent key image.
    pub fn with_key_image(mut self, key_image: KeyImage) -> Self {
        self.key_images.insert(key_image);
        self
    }

    /// Record a transaction identity as on the chain (CEN-G1's read).
    pub fn with_transaction(mut self, hash: TxHash) -> Self {
        self.transactions.insert(hash);
        self
    }

    /// Plant `shard`'s market price at `epoch`'s close — what CEN-J15
    /// reads at the last settled epoch as of the parent. Planted archival
    /// state, and why: J15's accept needs a shard that is closed, final
    /// **and priced**, the close is the fold's (which the chain already
    /// synthesizes), and no driven chain in the tree reaches a close — a
    /// shard is `SHARD_LENGTH` of real proof bytes. A price is a value the
    /// epoch close wrote, not a record; planting it tests no construction
    /// (DRS-E4 §5.2's concern). A shard with no planted price reads
    /// `None`, which is J15's Q4 refusal.
    #[must_use]
    pub fn with_r_market(mut self, shard: ShardId, epoch: SettlementEpoch, price: RMarket) -> Self {
        self.r_market.insert((shard, epoch), price);
        self
    }

    /// Plant `epoch`'s frozen close — the `Σwork(E)` and `budget(E)` the
    /// fold writes in one event, what CEN-J23 reads to admit a claimed
    /// epoch and CEN-J25 verifies against. The same justification as
    /// [`with_r_market`](Self::with_r_market): a frozen close is a settled
    /// value, not a record, and J25's refusal arm needs a claimed epoch
    /// J23 admits (`rules/tx_emission_against.rs`). An epoch with no
    /// planted close reads `None` for both, which is J23's refusal.
    #[must_use]
    pub fn with_close(
        mut self,
        epoch: SettlementEpoch,
        sigma_work: SigmaWorkMilli,
        budget: AtomicUnits,
    ) -> Self {
        self.closes.insert(epoch, (sigma_work, budget));
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

    pub(crate) fn tree(&self, height: BlockHeight) -> AtHeight<PlantedTree> {
        usize::try_from(height.to_raw())
            .ok()
            .and_then(|index| self.trees.get(index))
            .map_or(AtHeight::AboveTip, |tree| AtHeight::Recorded(*tree))
    }
}

/// The tree state at one height as the mock holds it: the root and the
/// leaf count the root is a function of, pushed together
/// ([`MockChain::push_tree`]) so one cannot be asked what the other was
/// never told. The store records the same pair per height
/// (`curve_tree_roots[h]`, `curve_tree_leaf_counts[h]`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PlantedTree {
    pub(crate) root: CurveTreeRoot,
    pub(crate) leaf_count: u64,
}

impl PlantedTree {
    /// The empty tree: `CurveTreeRoot::EMPTY` over no leaves.
    const EMPTY: Self = Self {
        root: CurveTreeRoot::EMPTY,
        leaf_count: 0,
    };
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

    fn total_burned(&self) -> Result<AtomicUnits, Infallible> {
        Ok(self.chain.total_burned)
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
        Ok(match self.chain.tree(height) {
            AtHeight::Recorded(tree) => AtHeight::Recorded(tree.root),
            AtHeight::AboveTip => AtHeight::AboveTip,
        })
    }

    fn tip(&self) -> Result<Option<Tip>, Infallible> {
        Ok(self.chain.tip())
    }

    /// The store's contract, on the mock's vector: `end` past `tip + 1` is
    /// `AboveTip`; otherwise the `min(at_most, end)` entries below `end`,
    /// in height order. A hole cannot occur here — the vector is dense by
    /// construction — which is why the SI-7 arm is the store's alone to
    /// test (`read_tests`).
    fn weights_window(
        &self,
        end: BlockHeight,
        at_most: BlockCount,
    ) -> Result<AtHeight<Vec<RecordedWeights>>, Infallible> {
        // Classified before any conversion: a height no `usize` can index
        // is past every recorded block, and a count past `usize` takes the
        // whole prefix — neither is a panic, both are the contract's arms.
        let Ok(end) = usize::try_from(end.to_raw()) else {
            return Ok(AtHeight::AboveTip);
        };
        if end > self.chain.weights.len() {
            return Ok(AtHeight::AboveTip);
        }
        let span = usize::try_from(at_most.to_raw()).map_or(end, |n| n.min(end));
        Ok(AtHeight::Recorded(
            self.chain.weights[end - span..end].to_vec(),
        ))
    }

    fn has_transaction(&self, hash: &TxHash) -> Result<bool, Infallible> {
        Ok(self.chain.transactions.contains(hash))
    }

    /// The tree at `tip + 1` as the next grow would need it: the leaf
    /// count the chain was told, over **no chunks** — the mock holds none,
    /// having grown nothing. For a chain built by `push` alone that is
    /// `TreeFrontier::EMPTY`, the honest frontier of a chain that records
    /// no outputs. For a planted tree ([`MockChain::push_tree`]) it is a
    /// frontier `grow` refuses as `FrontierFault::Shape`, which the drain
    /// raises as `Corrupt::TreeUnservable`: the view cannot describe the
    /// tree, which is the truth of a plant, said in the type rather than by
    /// an empty frontier under a non-zero count. The drain reads this only
    /// with outputs to append, and the mock's outputs are none.
    fn tree_frontier(&self) -> Result<TreeFrontier, Infallible> {
        let tree = self.chain.trees.last().expect("never empty");
        Ok(TreeFrontier {
            leaf_count: tree.leaf_count,
            last_chunks: Vec::new(),
        })
    }

    /// The leaf count pushed with the root at `height` — `0` for every
    /// height of a chain built by `push`, the planted count where
    /// [`MockChain::push_tree`] named one. `depth_at` derives from it.
    fn leaf_count_at(&self, height: BlockHeight) -> Result<AtHeight<u64>, Infallible> {
        Ok(match self.chain.tree(height) {
            AtHeight::Recorded(tree) => AtHeight::Recorded(tree.leaf_count),
            AtHeight::AboveTip => AtHeight::AboveTip,
        })
    }

    /// None at every recorded height: the mock records no outputs, which
    /// is why nothing in it grows and the drain appends nothing.
    fn outputs_at(&self, height: BlockHeight) -> Result<AtHeight<BlockOutputs>, Infallible> {
        Ok(match self.chain.block(height) {
            AtHeight::Recorded(_) => AtHeight::Recorded(BlockOutputs::default()),
            AtHeight::AboveTip => AtHeight::AboveTip,
        })
    }

    // No bonds. Archival state is derived from connected posts and settled
    // epochs; a constructed record would test the construction (DRS-E4
    // §5.2, *No `Mock*` archival state*). The witness for a 4.J rule over a
    // held shard is a real chain that posted the bond, through `connect`.
    // The planted reads are the market price (`MockChain::with_r_market`,
    // which says why: CEN-J15's accept over a closed shard has no driven
    // witness, a shard being `SHARD_LENGTH` of real proof bytes) and the
    // frozen close (`MockChain::with_close`: CEN-J25's refusal needs an
    // epoch CEN-J23 admits).
    crate::archival_reads!(empty, r_market from chain.r_market, close from chain.closes);
}

mod assert;
mod views;

pub use assert::{
    assert_refused, boundary_pair, credited_to_this_falsifier, defined, expected_seed, formed,
    formed_on, formed_under, infallible, judged, MockSubstrate,
};
pub use views::{
    Faulted, FaultingView, NonCanonicalBondView, NonCanonicalHybridKey, WithheldRead,
    WithholdingView,
};

pub mod fixture;
mod price;

#[cfg(test)]
#[path = "harness_probe_tests.rs"]
mod harness_probe_tests;

#[cfg(test)]
#[path = "fixture_sanity_tests.rs"]
mod fixture_sanity_tests;
