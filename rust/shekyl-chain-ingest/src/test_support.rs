// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fixtures shared by the artifact, corpus and pipeline tests: a chain the
//! landed rules accept under the mock substrate, its corpus bytes, and a
//! trace whose facts the chain's headers agree with (CEN-B5: the header
//! root at `h` is the root after `h − 1`'s drain).
//!
//! Since DRS-E3 the root is the validator's derivation — the curve tree
//! grown over the outputs that matured — and no function of the height can
//! supply it. [`GrownTree`] is the fixture's tree: a `ChainView` over the
//! blocks built so far, advanced by the production `tree_after` as each
//! block is added, so a chain's headers and its trace carry the roots the
//! store will derive when it connects them. One derivation (the rules
//! crate's), driven over a fixture view; not a second definition of the
//! drain.
//!
//! [`trace_with`] is how a fixture trace is built. It grows that tree over
//! the chain it is given and writes each row's `root_after` from it; the
//! caller supplies the economics and cannot name a root. [`trace_of`] is
//! [`trace_with`] with the synthetic economics. [`facts_at`] is the other
//! door, for a caller that must name the root.
//!
//! Every spend a chain lists is a **real** one since slice 6 row 6: the
//! harness miner's coinbase, matured, sourced and proven by
//! [`shekyl_harness_spender::Spender`] over the wallet-side tree fed the
//! same blocks ([`Growing`]), so CEN-I13/I15 judge it rather than skip a
//! filler. Block `c` spends the coinbase that matured for it — block
//! `c − FIRST_SPEND_HEIGHT`'s — and a fork's block at `c` spends the same
//! coinbase at another fee ([`Family::fee`]), so the two chains' trees
//! differ once those outputs mature, as a real fork's do. The one fixture
//! key image left ([`key_image`]) names bodies no spend rule judges: the
//! archival join a mutation duplicates, the unjudged artifact filler.
//!
//! Most of these fixtures serve the pipeline tests, which exist only with the
//! `pipeline` feature. The artifact and corpus tests use a small core. So a
//! build without the feature leaves the rest unused by design; that build
//! expects the dead code rather than scattering a feature gate over each
//! pipeline-only helper, and the expectation fails the moment it no longer
//! holds.
#![cfg_attr(
    not(feature = "pipeline"),
    expect(
        dead_code,
        reason = "pipeline-only fixtures are unused when the pipeline tests are not built"
    )
)]

use core::convert::Infallible;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

use shekyl_chain_rules::harness::fixture;
use shekyl_chain_rules::{
    effective_median_at, quote_emission, tree_after, AtHeight, BlockOutputs, Candidate, ChainView,
    LeafSource, RecordedBlock, RecordedWeights, RuleSet, SettlementSchedule, Tip, TreeFrontier,
    ViewRead,
};
use shekyl_chain_store::archival_snapshot::ArchivalSnapshot;
use shekyl_chain_store::codec::SettlementEpochBlocks;
use shekyl_chain_store::digest_v0::digest_v0;
use shekyl_chain_store::store::ChainStore;
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_economics::{base_block_reward, EconomicParams};
use shekyl_harness_spender::{first_spending_height, MinedBlock, MinerWallet, PostedBond, Spender};
use shekyl_harness_wallet::coinbase::repay;
use shekyl_types::{
    ArchivalLength, AttestationRoot, BlockCount, BlockHash, BlockHeight, BlockWeight,
    CurveTreeRoot, GlobalOutputIndex, KeyImage, LongTermWeight, SettlementEpoch, TxHash,
};
use shekyl_units::AtomicUnits;
use shekyl_wire::tx_extra::{admitted_leaf_blob, parse, pqc_leaf_entries_per_output};
use shekyl_wire::{Block, BlockHeader, Ct, Input, Transaction};

#[cfg(feature = "pipeline")]
use crate::connector::{Connector, ConnectorArgs};
use crate::corpus::{CorpusNet, CorpusWriter};
use crate::source::{IngestEvent, SequenceNo, Sequenced, Source};
use crate::trace::{Digest, Facts, Trace, TraceWriter};

/// A settlement epoch for test stores.
pub const EPOCH: SettlementEpochBlocks = match SettlementEpochBlocks::new(10_000) {
    Some(e) => e,
    None => unreachable!(),
};

/// A fresh temp path for a store.
///
/// A redb store is **one file**, so a stale one is removed with
/// `remove_file`; `remove_dir_all` on a file fails with `NotADirectory`,
/// which is how an earlier version of this helper left every store behind
/// and would have handed a same-named test a *reopened* stale store rather
/// than a fresh one (`ChainStore::create` reopens an existing path).
pub fn tmp(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("shekyl-ingest-{}-{name}", std::process::id()));
    cleanup(&p);
    assert!(
        !p.exists(),
        "stale store at {} could not be removed",
        p.display()
    );
    p
}

/// Remove the store at `p` (a file — or a directory, should a helper ever
/// make one). Absence is not an error.
pub fn cleanup(p: &std::path::Path) {
    let _gone = std::fs::remove_file(p).or_else(|_| std::fs::remove_dir_all(p));
}

pub fn h(n: u64) -> BlockHeight {
    BlockHeight::from_raw(n)
}

/// The curve tree a synthetic chain grows (module docs): the outputs of
/// every block built so far, the root and leaf count going into each
/// height, and the layer chunks — advanced by the production derivation
/// (`shekyl_chain_rules::tree_after`) as blocks are pushed, exactly as
/// `connect` will advance the store's when it connects them.
#[derive(Default)]
pub struct GrownTree {
    /// `outputs[h]` — block `h`'s outputs as leaf sources, global indices
    /// assigned dense in connect order (miner first, then listed).
    outputs: Vec<BlockOutputs>,
    /// `roots[h]` — the root going into `h`; `roots[0]` is the empty tree.
    roots: Vec<CurveTreeRoot>,
    /// `leaf_counts[h]` — the leaf count going into `h`.
    leaf_counts: Vec<u64>,
    /// `(layer, chunk)` → hash, every chunk any grow wrote.
    layers: BTreeMap<(u8, u64), [u8; 32]>,
    next_output: u64,
    /// `weights[h]` — block `h`'s weight and long-term weight, derived as
    /// the validator derives them (CEN-G6/G6b, slice 7): the wire weight
    /// of the block, clamped under the long-term effective median in
    /// force at `h`. What `weights_window` answers.
    weights: Vec<RecordedWeights>,
    /// `medians[h]` — the long-term effective median in force **for**
    /// block `h` (over the weights below it), what the trace's row at `h`
    /// records and the validator's verdict must equal.
    medians: Vec<LongTermWeight>,
    /// `blocks[h]` — block `h` as the store would record it: identity,
    /// header, the work through it (a synthetic chain is regtest at
    /// difficulty one, so `h + 1`), the accumulator [`quote_emission`]
    /// returned and the listed-transaction prefix sum. What `block_at`
    /// answers, so `tx_volume_window` (CEN-F20) reads this tree the way
    /// the validator reads the store.
    blocks: Vec<RecordedBlock>,
    /// Burned fees through the blocks already pushed. The next block's
    /// price reads this fold as the parent's `total_burned` (CEN-F17);
    /// the push then adds that block's own burn. Genesis burns nothing,
    /// so the fold starts at zero.
    total_burned: AtomicUnits,
    /// `burned[h]` — block `h`'s own burn (`PaidEmission::burned`, the
    /// fee share CEN-F17 destroys), what the store's `block_burn` row
    /// holds and the trace's row at `h` must carry. Zero for a block
    /// listing nothing; a real spend's fee burns, so a trace cannot name
    /// it — it reads it here ([`Self::burned_at`]).
    burned: Vec<AtomicUnits>,
    /// `accrual[h]` — block `h`'s staker inflow (CEN-G11, the
    /// `PaidEmission::accrual` the reward chain priced), what the store's
    /// E4 hook folds into the open epoch's `archival_budget_accruing` row.
    /// [`archival_snapshot_after`](Self::archival_snapshot_after) sums it.
    accrual: Vec<AtomicUnits>,
}

impl GrownTree {
    /// An empty tree with no blocks.
    #[must_use]
    pub fn new() -> Self {
        Self {
            roots: vec![CurveTreeRoot::EMPTY],
            leaf_counts: vec![0],
            ..Self::default()
        }
    }

    /// The tree after every block of `chain`, in order.
    #[must_use]
    pub fn over(chain: &[(Block, Vec<Transaction>)]) -> Self {
        let mut tree = Self::new();
        for (block, txs) in chain {
            tree.push(block, txs);
        }
        tree
    }

    /// How many blocks have been pushed — the next connecting height.
    #[must_use]
    pub fn built(&self) -> u64 {
        self.outputs.len() as u64
    }

    /// The root the header connecting at `height` must carry (CEN-B5):
    /// the root going into `height`.
    #[must_use]
    pub fn root_going_into(&self, height: u64) -> CurveTreeRoot {
        self.roots[at(height)]
    }

    /// The root after block `height`'s drain — what its connect writes at
    /// `height + 1`.
    #[must_use]
    pub fn root_after(&self, height: u64) -> CurveTreeRoot {
        self.roots[at(height + 1)]
    }

    /// Block `height`'s weight and long-term weight as this chain derives
    /// them — what the store's `block_info` would hold.
    #[must_use]
    pub fn weights_of(&self, height: u64) -> RecordedWeights {
        self.weights[at(height)]
    }

    /// The long-term effective median in force for block `height` — the
    /// value the validator's verdict carries for it and the trace's row
    /// records.
    #[must_use]
    pub fn median_for(&self, height: u64) -> LongTermWeight {
        self.medians[at(height)]
    }

    /// The gross emission through block `height` as this chain derives it
    /// — the parent's plus the paid reward (CEN-F14b, G12): what the
    /// validator's verdict carries and the trace's row records.
    #[must_use]
    pub fn coins_generated_at(&self, height: u64) -> AtomicUnits {
        self.blocks[at(height)].coins_generated
    }

    /// What block `height` burned as this chain derives it (CEN-F17 over
    /// the fees its bodies paid) — what the store's `block_burn` row holds
    /// and the trace's row records.
    #[must_use]
    pub fn burned_at(&self, height: BlockHeight) -> AtomicUnits {
        self.burned[at(height.to_raw())]
    }

    /// The archival state after block `height` as the store writes it for
    /// a synthetic chain — one that posts no bonds, so the only archival
    /// row is the open epoch's accruing total: the sum of every block's
    /// staker inflow from the epoch's open height through `height`
    /// (`archival_write.rs` phase 9a, under the genesis schedule). The
    /// §3.8.1 rows the trace's `0x04` record carries for such a chain.
    ///
    /// A chain that reaches a settlement close has a different shape (the
    /// accruing row is removed and the budget row written); the fixtures
    /// stay short of one, and this asserts it.
    #[must_use]
    pub fn archival_snapshot_after(&self, height: u64) -> ArchivalSnapshot {
        let schedule = SettlementSchedule::GENESIS;
        assert!(
            schedule.close_due_at_height(height + 1).is_none(),
            "the synthetic fixtures stay short of a settlement close"
        );
        let epoch = schedule.epoch_at_height(height);
        let open = schedule.open_height(epoch);
        let total = self.accrual[at(open)..=at(height)]
            .iter()
            .try_fold(AtomicUnits::ZERO, |sum, a| sum.checked_add(*a))
            .expect("a fixture chain's accrual fold fits u64");
        let mut snapshot = ArchivalSnapshot::empty();
        snapshot
            .set_budget_accruing(SettlementEpoch::from_raw(epoch), total)
            .expect("the first accruing row");
        snapshot
    }

    /// Connect `block` at the next height: derive its drain over the tree
    /// as it stands, apply the growth, then register its outputs — and
    /// derive its weights under the medians the chain so far yields, the
    /// same production definition the validator runs
    /// (`effective_median_at`), so a trace built over this chain cannot
    /// record a median the chain did not have.
    pub fn push(&mut self, block: &Block, txs: &[Transaction]) {
        let height = h(self.built());
        let medians = effective_median_at(self, height)
            .expect("a fixture chain's weights are complete below its tip");
        let weight = core::iter::once(&block.miner_transaction)
            .chain(txs)
            .map(|tx| u64::try_from(tx.weight()).expect("a fixture body's weight fits u64"))
            .fold(0u64, u64::saturating_add);
        let long_term =
            shekyl_economics::long_term_weight(medians.long_term_effective_median.to_raw(), weight);
        // The block as it is, not a settled clone: `reward_for` already
        // wrote the coinbase, and the recorded emission is what the
        // validator will compute for these bytes. A refusal means the
        // builder was asked to extend with a block the reward chain refuses.
        let emission = match quote_emission(
            self,
            height,
            &Candidate::new(block.clone(), txs.to_vec()),
        ) {
            Ok(Ok(emission)) => emission,
            Ok(Err(refused)) => panic!(
                "a chain builder was asked to extend with a block the reward chain refuses: {refused}"
            ),
            Err(ViewRead::View(never)) => match never {},
            Err(ViewRead::Corrupt(corrupt)) => {
                panic!("the fixture chain's parent reads are corrupt: {corrupt:?}")
            }
        };
        self.total_burned = self
            .total_burned
            .checked_add(emission.burned())
            .expect("a fixture chain's burned fold fits u64");
        self.burned.push(emission.burned());
        let coins_generated = emission.coins_generated;
        self.accrual.push(emission.accrual);
        let (listed_before, archival_before) =
            height
                .to_raw()
                .checked_sub(1)
                .map_or((0, ArchivalLength::ZERO), |parent| {
                    let p = &self.blocks[at(parent)];
                    (p.cumulative_tx_count, p.cumulative_archival_len)
                });
        // The archival fold the store keeps (`SHT-Q2`): the coinbase's and
        // every listed transaction's `archival_len`, on the parent's.
        let cumulative_archival_len = core::iter::once(&block.miner_transaction)
            .chain(txs)
            .map(Transaction::archival_len)
            .try_fold(archival_before, ArchivalLength::checked_add)
            .expect("a fixture chain's archival fold fits u64");
        self.blocks.push(RecordedBlock {
            hash: block.hash(),
            header: block.header.clone(),
            // Regtest at difficulty one: the work through `h` is `h + 1`.
            cumulative_difficulty: CumulativeDifficulty::from_raw(u128::from(height.to_raw()) + 1),
            coins_generated,
            cumulative_tx_count: listed_before
                + u64::try_from(txs.len()).expect("a fixture body count fits"),
            cumulative_archival_len,
        });
        self.weights.push(RecordedWeights {
            weight: BlockWeight::from_raw(weight),
            long_term_weight: LongTermWeight::from_raw(long_term),
        });
        self.medians.push(medians.long_term_effective_median);
        let (root, drain) = tree_after(self, height, &RuleSet::GENESIS)
            .expect("a fixture chain's view is complete and its points decompress");
        let mut leaf_count = self.leaf_counts[at(height.to_raw())];
        if let Some(drain) = drain {
            for write in &drain.growth().layer_writes {
                self.layers.insert((write.layer, write.chunk), write.hash);
            }
            leaf_count = drain.growth().leaf_count_after();
        }
        self.roots.push(root);
        self.leaf_counts.push(leaf_count);
        let coinbase = self.register(&block.miner_transaction);
        let listed = txs.iter().flat_map(|tx| self.register(tx)).collect();
        self.outputs.push(BlockOutputs { coinbase, listed });
    }

    /// One transaction's outputs as leaf sources, assigned the next global
    /// indices — the store's own keying (SOK-2, dense in connect order).
    fn register(&mut self, tx: &Transaction) -> Vec<LeafSource> {
        let commitments = match &tx.ct {
            Ct::Null(base) | Ct::Fcmp { base, .. } => &base.commitments,
        };
        let fields = parse(&tx.prefix.extra).expect("fixture extra parses");
        let blob =
            admitted_leaf_blob(&fields, tx.prefix.outputs.len()).expect("fixture leaf field");
        let entries = pqc_leaf_entries_per_output(&blob).expect("whole entries");
        tx.prefix
            .outputs
            .iter()
            .zip(commitments)
            .zip(entries)
            .map(|((output, commitment), entry)| {
                let index = GlobalOutputIndex::from_raw(self.next_output);
                self.next_output += 1;
                let mut pqc_leaf_commitment = [0u8; 32];
                pqc_leaf_commitment.copy_from_slice(&entry[..32]);
                LeafSource {
                    output: index,
                    key: output.key,
                    commitment: *commitment,
                    pqc_leaf_commitment,
                }
            })
            .collect()
    }

    fn recorded<T: Clone>(rows: &[T], height: BlockHeight) -> AtHeight<T> {
        usize::try_from(height.to_raw())
            .ok()
            .and_then(|i| rows.get(i))
            .map_or(AtHeight::AboveTip, |row| AtHeight::Recorded(row.clone()))
    }
}

/// The tree `tree_after` grows, and the block records, weight window and
/// burned fold the reward chain reads when a block is pushed.
impl<'id> ChainView<'id> for GrownTree {
    type Fault = Infallible;

    fn has_key_image(&self, _: &KeyImage) -> Result<bool, Infallible> {
        Ok(false)
    }

    /// The block as the store would record it (CEN-F20's prefix sums,
    /// F13's accumulator), so the rules' definitions read this tree as they
    /// read the store.
    fn block_at(&self, height: BlockHeight) -> Result<AtHeight<RecordedBlock>, Infallible> {
        Ok(Self::recorded(&self.blocks, height))
    }

    fn height_of(&self, _: &BlockHash) -> Result<Option<BlockHeight>, Infallible> {
        Ok(None)
    }

    /// The weights of the blocks below `end`, at most `at_most` of them —
    /// the store's contract, so `effective_median_at` over this tree is
    /// the validator's own read (CEN-G6).
    fn weights_window(
        &self,
        end: BlockHeight,
        at_most: BlockCount,
    ) -> Result<AtHeight<Vec<RecordedWeights>>, Infallible> {
        let Ok(end) = usize::try_from(end.to_raw()) else {
            return Ok(AtHeight::AboveTip);
        };
        if end > self.weights.len() {
            return Ok(AtHeight::AboveTip);
        }
        let span = usize::try_from(at_most.to_raw())
            .unwrap_or(usize::MAX)
            .min(end);
        Ok(AtHeight::Recorded(self.weights[end - span..end].to_vec()))
    }

    fn has_transaction(&self, _: &TxHash) -> Result<bool, Infallible> {
        Ok(false)
    }

    fn root_at(&self, height: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, Infallible> {
        Ok(Self::recorded(&self.roots, height))
    }

    fn tip(&self) -> Result<Option<Tip>, Infallible> {
        let Some(block) = self.blocks.last() else {
            return Ok(None);
        };
        let height = BlockHeight::from_raw(
            u64::try_from(self.blocks.len() - 1).expect("a fixture chain fits u64"),
        );
        Ok(Some(Tip {
            height,
            hash: block.hash,
        }))
    }

    fn tree_frontier(&self) -> Result<TreeFrontier, Infallible> {
        let leaf_count = *self.leaf_counts.last().expect("never empty");
        let last_chunks = TreeFrontier::last_chunk_indices(leaf_count)
            .into_iter()
            .map(|key| self.layers[&key])
            .collect();
        Ok(TreeFrontier {
            leaf_count,
            last_chunks,
        })
    }

    fn leaf_count_at(&self, height: BlockHeight) -> Result<AtHeight<u64>, Infallible> {
        Ok(Self::recorded(&self.leaf_counts, height))
    }

    fn outputs_at(&self, height: BlockHeight) -> Result<AtHeight<BlockOutputs>, Infallible> {
        Ok(Self::recorded(&self.outputs, height))
    }

    fn total_burned(&self) -> Result<AtomicUnits, Infallible> {
        Ok(self.total_burned)
    }

    // A grown tree posts no bond (`DRS_E4_ARCHIVAL_WRITER.md` §5.2).
    shekyl_chain_rules::archival_reads!(empty);
}

/// The miner transaction for `height`: the rules harness's, which since
/// slice 4 is the one definition of a coinbase every landed 4.F row
/// accepts (sole `Input::Gen(height)`, `Null` ct, one output with a
/// canonical key and a non-trivial mask, `unlock_time = height + 60`) and
/// which round-trips through `Block::read`. This crate's private copy
/// (RD-F16, minted when the harness fixture had no inputs) carried a key
/// that was not a point and stopped connecting the day F9 landed — the
/// coupling Q7 of that slice named: a test's fixture is cross-lane through
/// the rules it must satisfy. Saturating at `u64::MAX` as before.
pub fn coinbase(height: u64) -> Transaction {
    fixture::coinbase(height)
}

/// Which chain a spend belongs to. A fork block at `c` spends the coinbase
/// the main block at `c` spent — the store un-spent it when the main
/// block popped — at this family's fee, so the fork's body is a different
/// transaction with different outputs, and the two trees differ once
/// those outputs mature (the reorg family's premise, [`reorg_of`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Family {
    /// The chain [`chain`] builds.
    Main = 0xA0,
    /// The fork [`reorg`] builds onto it.
    Fork = 0xB0,
}

impl Family {
    /// The fee a spend of this family pays. Any figure the coinbase funds
    /// serves; the two differ so that a fork's spend of a coinbase is not
    /// the main chain's body.
    #[must_use]
    pub const fn fee(self) -> u64 {
        match self {
            Family::Main => 1_000_000,
            Family::Fork => 2_000_000,
        }
    }
}

/// A fixture key image for a body **no spend rule judges**: `k·G` for a
/// `k` distinct per `(family, height)` — a canonical prime-order point
/// (CEN-H11). Since slice 6 row 6 every spend a chain lists is a real
/// one, with its own image ([`Growing::spend_matured`]); this names the
/// archival join the mutation family duplicates (a bond post, judged by
/// 4.J, not I13/I15), the artifact tests' unjudged filler, and the foreign
/// member a digest control plants. A spend of a fixture image is not a
/// shape a connected chain carries any more.
pub fn key_image(family: Family, height: u64) -> [u8; 32] {
    let offset = match family {
        Family::Main => 1_000,
        Family::Fork => 2_000_000,
    };
    fixture::point_at(offset + height)
}

/// The rules harness's two-output filler spend of `key_image`
/// ([`fixture::listed`]) — a conforming body, not a proven one. For the
/// artifact tests, which judge nothing: a connected chain lists real
/// spends ([`Growing::spend_matured`]), and a filler that reached
/// `connect` would be CEN-I13's refusal.
pub fn filler_spend(key_image: [u8; 32]) -> Transaction {
    fixture::listed(key_image)
}

/// The first height at which a block may list a spend: the height at which
/// block 0's coinbase can be spent against a root that holds it —
/// [`first_spending_height`] under the genesis rule set (the unlock
/// window, one, and the reference age; the derivation is that function's
/// doc). Derived, not pinned: a reader who wants the figure evaluates it.
/// Block `c ≥ FIRST_SPEND_HEIGHT` spends the coinbase of block
/// `c − FIRST_SPEND_HEIGHT`, the one that matured for it; [`chain`] lists
/// nothing below.
pub const FIRST_SPEND_HEIGHT: u64 = first_spending_height(&RuleSet::GENESIS).to_raw();

/// A fixture height as an index into a hash or block list.
pub fn at(height: u64) -> usize {
    usize::try_from(height).expect("a fixture height fits usize")
}

/// A **fixture** body `tx` anchored for a block at `height` on the chain
/// whose block hashes so far are `hashes`: the harness's
/// [`fixture::anchored_at`] — the newest reference CEN-I11 admits. For the
/// archival bodies (a join, a serve credit, which is left as it is); a
/// real spend carries its reference inside its proof and is never passed
/// here — rewriting it would be the forged-reference shape, not an anchor.
pub fn anchor(hashes: &[BlockHash], height: u64, tx: Transaction) -> Transaction {
    fixture::anchored_at(hashes, height, tx)
}

/// A block at `height` on `previous`, listing `listed`, with `nonce`, whose
/// header carries `root` — the tree state going into `height`
/// ([`GrownTree::root_going_into`]; CEN-B5) — and whose coinbase pays
/// `reward`: what CEN-F18 owes it, priced by [`reward_for`] over the tree
/// the block extends (a block nothing will judge may pass `0`). The
/// coinbase is re-paid through the harness wallet ([`repay`]), so its
/// commitment and encrypted amount are the amount's: a bare amount write
/// over the fixture's commitment would be an output no scanner recovers
/// and no spend can prove.
pub fn block_with_nonce(
    root: CurveTreeRoot,
    height: u64,
    previous: BlockHash,
    listed: &[Transaction],
    reward: u64,
    nonce: u32,
) -> Block {
    let mut miner_transaction = coinbase(height);
    assert!(
        repay(
            &mut miner_transaction,
            MinerWallet::harness().recipient(),
            reward
        ),
        "the harness coinbase is the shape `repay` prices"
    );
    Block {
        header: BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: 1_000 + height * 60,
            previous,
            nonce,
            curve_tree_root: root,
            // The empty set's root: a block carrying no witness is judged
            // against it (CEN-B4, slice 8 row 10).
            attestation_root: AttestationRoot::from_bytes(
                shekyl_archival_retention::empty_attestation_root(),
            ),
        },
        miner_transaction,
        transaction_hashes: listed.iter().map(Transaction::hash).collect(),
    }
}

pub fn block(
    root: CurveTreeRoot,
    height: u64,
    previous: BlockHash,
    listed: &[Transaction],
    reward: u64,
) -> Block {
    block_with_nonce(root, height, previous, listed, reward, 7)
}

/// What a fixture chain's genesis coinbase pays. At genesis the validator
/// derives no reward — the configured emission stands whole, whatever it
/// is (CEN-F11) — so the figure is the fixture's to choose, and it
/// chooses the emission curve's own first figure, the base reward over
/// nothing yet generated. The bare harness coinbase pays zero, which no
/// spend can fund a fee from; endowed, block 0's coinbase is the first a
/// chain spends, at [`FIRST_SPEND_HEIGHT`] exactly as the maturity law
/// states it — not block 1's a height later, which would have put a `+ 1`
/// with no law behind it into every count built on the first spend.
pub fn genesis_endowment() -> u64 {
    base_block_reward(0, &EconomicParams::default())
        .expect("the curve's first figure is priced at every parameter set")
}

/// What CEN-F18 owes the coinbase of the next block on `tree`, listing
/// `listed` — [`fixture::priced`], which settles through the validator's
/// reward chain. `height` is that next height: a caller that prices a
/// different one is naming a block this tree is not building.
///
/// [`genesis_endowment`] at genesis, where nothing is derived and the
/// configured figure stands; `0` for a block the chain refuses before F18.
pub fn reward_for(
    tree: &GrownTree,
    root: CurveTreeRoot,
    height: u64,
    previous: BlockHash,
    listed: &[Transaction],
) -> u64 {
    assert_eq!(
        height,
        tree.built(),
        "reward_for prices the block this tree connects next"
    );
    if height == 0 {
        return genesis_endowment();
    }
    let provisional = block(root, height, previous, listed, 0);
    let priced = match fixture::priced(tree, Candidate::new(provisional, listed.to_vec())) {
        Ok(candidate) => candidate,
        Err(ViewRead::View(never)) => match never {},
        Err(ViewRead::Corrupt(corrupt)) => {
            panic!("the fixture chain's parent reads are corrupt: {corrupt:?}")
        }
    };
    priced.block.miner_transaction.prefix.outputs[0].amount
}

/// A block and its listed bodies as the wallet-side tree reads them
/// ([`MinedBlock`]), so a fixture chain's blocks feed a [`Spender`].
pub struct Linked<'a>(pub &'a Block, pub &'a [Transaction]);

impl MinedBlock for Linked<'_> {
    fn height(&self) -> BlockHeight {
        match self.0.miner_transaction.prefix.inputs.first() {
            Some(Input::Gen(height)) => BlockHeight::from_raw(*height),
            _ => panic!("a fixture block's coinbase opens with Input::Gen"),
        }
    }

    fn hash(&self) -> BlockHash {
        self.0.hash()
    }

    fn miner_transaction(&self) -> &Transaction {
        &self.0.miner_transaction
    }

    fn listed(&self) -> &[Transaction] {
        self.1
    }
}

/// A chain under construction, with the two trees a real spend needs kept
/// in step: the validator's ([`GrownTree`], what the headers and the
/// trace carry) and the wallet's ([`Spender`], what a spend's path and
/// proof are made in). Every block pushed asserts the two agree on the
/// root going into it — the second-oracle property the spender crate
/// states (its docs); a spend built here is then valid against the root
/// the header it references carries, and a disagreement is found at the
/// block that opened it, not at CEN-I15 some heights later.
pub struct Growing {
    hashes: Vec<BlockHash>,
    tree: GrownTree,
    spender: Spender,
    built: Vec<(Block, Vec<Transaction>)>,
}

impl Default for Growing {
    fn default() -> Self {
        Self::new()
    }
}

impl Growing {
    /// An empty chain.
    #[must_use]
    pub fn new() -> Self {
        Self {
            hashes: Vec::new(),
            tree: GrownTree::new(),
            spender: Spender::over::<Linked<'_>>(&[]),
            built: Vec::new(),
        }
    }

    /// The chain `blocks`, re-grown — both trees advanced over blocks
    /// already built, as a fork's builder starts from the main chain's
    /// prefix.
    #[must_use]
    pub fn over(blocks: &[(Block, Vec<Transaction>)]) -> Self {
        let mut growing = Self::new();
        for (block, txs) in blocks {
            growing.record(block.clone(), txs.clone());
        }
        growing
    }

    /// The next connecting height.
    #[must_use]
    pub fn height(&self) -> BlockHeight {
        h(self.tree.built())
    }

    /// The block hashes so far — what a fixture archival body anchors on.
    #[must_use]
    pub fn hashes(&self) -> &[BlockHash] {
        &self.hashes
    }

    /// A real spend, for the block connecting next, of the coinbase that
    /// matured for it: block `height − FIRST_SPEND_HEIGHT`'s, at
    /// `family`'s fee. `None` while no coinbase has matured. Along a
    /// chain each coinbase is spent once, by the block exactly
    /// `FIRST_SPEND_HEIGHT` above it.
    #[must_use]
    pub fn spend_matured(&self, family: Family) -> Option<Transaction> {
        self.height()
            .to_raw()
            .checked_sub(FIRST_SPEND_HEIGHT)
            .map(|coinbase| self.spend_of(coinbase, family))
    }

    /// A real spend, for the block connecting next, of block `coinbase`'s
    /// coinbase at `family`'s fee. The caller names a coinbase that has
    /// matured (the spender's path assembly asserts it) and that no block
    /// on this chain spent (CEN-I7 would refuse the block otherwise). The
    /// spending wallet is the miner's — the one every fixture coinbase pays.
    #[must_use]
    pub fn spend_of(&self, coinbase: u64, family: Family) -> Transaction {
        self.spend_of_posting(coinbase, family, None)
    }

    /// [`Self::spend_of`] with an archival bond post riding it
    /// ([`Spender::spend_coinbase_posting`]): a **real** join or release,
    /// its funding spend proven over the wallet-side tree, so the body
    /// passes CEN-J27 (the funding half) as it passes I13/I15 — what a
    /// fixture archival body cannot do since slice 6 row 6. With `None`
    /// the bytes are [`Self::spend_of`]'s exactly.
    #[must_use]
    pub fn spend_of_posting(
        &self,
        coinbase: u64,
        family: Family,
        bond: Option<&PostedBond<'_>>,
    ) -> Transaction {
        self.spender.spend_coinbase_posting(
            MinerWallet::harness(),
            h(coinbase),
            self.height(),
            family.fee(),
            bond,
        )
    }

    /// A **fixture** archival body anchored for the block connecting next
    /// ([`anchor`]); never a real spend.
    #[must_use]
    pub fn anchored(&self, tx: Transaction) -> Transaction {
        anchor(&self.hashes, self.height().to_raw(), tx)
    }

    /// Extend with a block listing `listed`, built by [`block_with_nonce`]
    /// with `nonce`, on the tip, carrying the root going into its height
    /// and the reward CEN-F18 owes it. Returns the block and its bodies.
    pub fn extend(&mut self, listed: Vec<Transaction>, nonce: u32) -> &(Block, Vec<Transaction>) {
        self.extend_with(listed, |root, height, previous, txs, reward| {
            block_with_nonce(root, height, previous, txs, reward, nonce)
        })
    }

    /// [`Self::extend`] with the block builder supplied — a mined chain
    /// hands one that searches nonces (the mutation family's D1 case).
    /// `make` receives the root the tree has going into the height and
    /// the reward the coinbase must pay ([`reward_for`] over that tree).
    pub fn extend_with(
        &mut self,
        listed: Vec<Transaction>,
        make: impl FnOnce(CurveTreeRoot, u64, BlockHash, &[Transaction], u64) -> Block,
    ) -> &(Block, Vec<Transaction>) {
        let height = self.height().to_raw();
        let previous = self.hashes.last().copied().unwrap_or(BlockHash::NULL);
        let root = self.tree.root_going_into(height);
        let reward = reward_for(&self.tree, root, height, previous, &listed);
        let block = make(root, height, previous, &listed, reward);
        self.record(block, listed)
    }

    /// Push `block` to both trees, holding them to one root first.
    fn record(&mut self, block: Block, listed: Vec<Transaction>) -> &(Block, Vec<Transaction>) {
        let height = self.height();
        self.tree.push(&block, &listed);
        self.spender.push(&Linked(&block, &listed));
        // The wallet-side client answers a root at a height it has
        // ingested — the root going into that height, as the store keys
        // it — so the check is made once the block is in on both sides.
        assert_eq!(
            self.spender.root_at(height),
            self.tree.root_going_into(height.to_raw()),
            "height {height:?}: the wallet-side tree and the validator's agree on the root going in"
        );
        self.hashes.push(block.hash());
        self.built.push((block, listed));
        self.built.last().expect("just pushed")
    }

    /// The blocks built, in order.
    #[must_use]
    pub fn finish(self) -> Vec<(Block, Vec<Transaction>)> {
        self.built
    }
}

/// The main chain the tests share, grown once per process and extended
/// on demand: `chain(n)` is a prefix of `chain(m)` for `n ≤ m`, so every
/// test reads one chain and no spend is proven twice. A real spend costs
/// about two seconds to prove; the family alone asks for twenty chains of
/// the same shape.
static MAIN: Mutex<Vec<(Block, Vec<Transaction>)>> = Mutex::new(Vec::new());

/// A chain of `n` blocks: block `c ≥ FIRST_SPEND_HEIGHT` lists one real
/// spend of the coinbase that matured for it (block
/// `c − FIRST_SPEND_HEIGHT`'s, [`Growing::spend_matured`]); the blocks
/// below list nothing — no coinbase has matured for them. A chain shorter
/// than `FIRST_SPEND_HEIGHT + 1` blocks carries no spend at all.
pub fn chain(n: u64) -> Vec<(Block, Vec<Transaction>)> {
    let mut main = MAIN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let have = u64::try_from(main.len()).expect("a fixture chain fits");
    if have < n {
        let mut growing = Growing::over(&main);
        for _ in have..n {
            let listed = growing.spend_matured(Family::Main).into_iter().collect();
            growing.extend(listed, 7);
        }
        *main = growing.finish();
    }
    main[..at(n)].to_vec()
}

/// A chain of `n` blocks listing nothing. For a test whose subject is
/// not the bodies — a planted work decrease, an epoch step — and for a
/// block that must find many coinbases unspent ([`Growing::spend_of`]).
pub fn bare_chain(n: u64) -> Vec<(Block, Vec<Transaction>)> {
    let mut growing = Growing::new();
    for _ in 0..n {
        growing.extend(Vec::new(), 7);
    }
    growing.finish()
}

/// The reorg family (§3.8, RD-Q13): a main chain, a `Rewind { to }`, then
/// `fork_len` fork blocks chained onto `main[to]` with nonces the main
/// chain never used. A fork block at `c ≥ FIRST_SPEND_HEIGHT` spends the
/// coinbase that matured for it — the one the main block at `c` spent,
/// which the rewind un-spent — **at the fork family's fee**, so the body
/// is another transaction with other outputs, and the fork's tree differs
/// from the main chain's once those outputs mature (`tx_spendable_age`
/// blocks on), as a real fork's would; a root comparison that failed to
/// retract the abandoned branch would show it (`pipeline_tests`).
/// `fork_len` must exceed `main_len - 1 - to` so the fork's tip is beyond
/// every pre-switch tip (corpus module docs: a checkpoint height is
/// compared the first time it is the tip).
pub struct Reorg {
    /// The chain before the switch.
    pub main: Vec<(Block, Vec<Transaction>)>,
    /// Where the switch rewinds to.
    pub to: u64,
    /// The chain after the switch: `main[..=to]` then the fork blocks.
    pub after: Vec<(Block, Vec<Transaction>)>,
}

/// [`reorg_of`] over the shared [`chain`] of `main_len` blocks.
pub fn reorg(main_len: u64, to: u64, fork_len: u64) -> Reorg {
    reorg_of(chain(main_len), to, fork_len)
}

/// A [`Reorg`] from `main` to `to` with a fork of `fork_len` blocks.
pub fn reorg_of(main: Vec<(Block, Vec<Transaction>)>, to: u64, fork_len: u64) -> Reorg {
    let main_len = u64::try_from(main.len()).expect("a fixture chain fits");
    assert!(to + 1 < main_len, "the rewind must pop at least one block");
    assert!(
        to + fork_len >= main_len,
        "the fork's tip must reach beyond every pre-switch tip"
    );
    // The fork's trees are the main chain's through `to`, then their own.
    let mut growing = Growing::over(&main[..=at(to)]);
    for i in 0..fork_len {
        let listed = growing.spend_matured(Family::Fork).into_iter().collect();
        growing.extend(listed, 99 + u32::try_from(i).expect("small"));
    }
    Reorg {
        main,
        to,
        after: growing.finish(),
    }
}

/// The reorg as a corpus: main's blocks, a rewind record, the fork's.
pub fn corpus_of_reorg(r: &Reorg) -> Vec<u8> {
    let mut w = CorpusWriter::create(std::io::Cursor::new(Vec::new()), CorpusNet::Fakechain, h(0))
        .expect("header");
    for (b, txs) in &r.main {
        let (bytes, bodies) = wire(b, txs);
        w.append(&bytes, &bodies).expect("append");
    }
    w.rewind(h(r.to)).expect("rewind");
    for (b, txs) in &r.after[usize::try_from(r.to).expect("small") + 1..] {
        let (bytes, bodies) = wire(b, txs);
        w.append(&bytes, &bodies).expect("append fork");
    }
    w.finish().expect("count").into_inner()
}

pub fn wire(b: &Block, txs: &[Transaction]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let bodies = txs
        .iter()
        .map(|t| {
            let mut body = Vec::new();
            t.write(&mut body).expect("write");
            body
        })
        .collect();
    (b.serialize(), bodies)
}

/// The corpus of `chain`.
pub fn corpus_of(chain: &[(Block, Vec<Transaction>)]) -> Vec<u8> {
    corpus_from(h(0), chain)
}

/// The corpus of `chain`, whose first block is at `first`.
pub fn corpus_from(first: BlockHeight, chain: &[(Block, Vec<Transaction>)]) -> Vec<u8> {
    let mut w = CorpusWriter::create(
        std::io::Cursor::new(Vec::new()),
        CorpusNet::Fakechain,
        first,
    )
    .expect("header");
    for (b, txs) in chain {
        let (bb, bodies) = wire(b, txs);
        w.append(&bb, &bodies).expect("verified");
    }
    w.finish().expect("count").into_inner()
}

/// The trace row's economics — the values a chain does **not** determine.
///
/// `root_after` is not a field: [`trace_with`] writes it from the chain's
/// [`GrownTree`], so a trace built this way cannot record a root the chain
/// it names did not grow. Since slice 7 commit 4 the same holds for the
/// three weight values (`weight`, `long_term_weight`,
/// `long_term_effective_median`), since commit 5 for `coins_generated`,
/// and since slice 6 row 6 for `burned`: the tree derives them by the
/// validator's own definitions as it grows — a real spend's fee burns a
/// share, so the burn is the bodies' to determine — and a caller cannot
/// name them. A trace whose medians, burn or accumulator disagreed with
/// its chain would be the fixture problem the oracles exist to rule out,
/// and the type makes it unrepresentable rather than the test-writer's to
/// avoid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceEconomics {
    /// `block_info.bi_diff` — the accumulator the trace holds the
    /// validator's derivation to.
    pub cumulative_difficulty: CumulativeDifficulty,
}

impl TraceEconomics {
    /// The row: what the chain determined (`tree`, at `height`) beside
    /// what it did not (`self`).
    fn over(self, tree: &GrownTree, height: u64) -> Facts {
        let weights = tree.weights_of(height);
        Facts {
            weight: weights.weight,
            long_term_weight: weights.long_term_weight,
            coins_generated: tree.coins_generated_at(height),
            burned: tree.burned_at(h(height)),
            root_after: tree.root_after(height),
            long_term_effective_median: tree.median_for(height),
            cumulative_difficulty: self.cumulative_difficulty,
        }
    }
}

/// Synthetic economics for `height`: the accumulator `height + 1`.
fn synthetic_economics(height: u64) -> TraceEconomics {
    TraceEconomics {
        cumulative_difficulty: CumulativeDifficulty::from_raw(u128::from(height) + 1),
    }
}

/// Facts for `height` naming every value a chain determines: the root
/// after the drain, the weights under the median, the accumulator.
///
/// The door for a caller that must name them. The CTW-5 negative control
/// plants a wrong root here, the G6 control a wrong median, the F14b/G12
/// control a wrong accumulator; a trace for a chain uses [`trace_with`],
/// which fills every derived value from that chain and takes none. The
/// burn is zero: every caller's chain lists nothing (three blocks, below
/// the first spend), and a block listing nothing burns nothing.
pub fn facts_at(
    height: u64,
    root_after: CurveTreeRoot,
    weights: RecordedWeights,
    long_term_effective_median: LongTermWeight,
    coins_generated: AtomicUnits,
) -> Facts {
    let economics = synthetic_economics(height);
    Facts {
        weight: weights.weight,
        long_term_weight: weights.long_term_weight,
        coins_generated,
        burned: AtomicUnits::from_raw(0),
        root_after,
        long_term_effective_median,
        cumulative_difficulty: economics.cumulative_difficulty,
    }
}

/// The spent-key set of `chain` after its last block: one key image per
/// listed spend.
pub fn spent_keys_of(chain: &[(Block, Vec<Transaction>)]) -> Vec<[u8; 32]> {
    chain
        .iter()
        .flat_map(|(_, txs)| txs.iter())
        .flat_map(|t| t.prefix.inputs.iter())
        .filter_map(|i| match i {
            Input::ToKey { key_image, .. } => Some(KeyImage::from_bytes(*key_image).to_bytes()),
            _ => None,
        })
        .collect()
}

/// What a test trace's covered-tip checkpoint records. The checkpoint's two
/// encodings travel together (`trace.rs`), so this names both at once.
#[derive(Clone, Copy, Debug)]
pub enum Pinned<'a> {
    /// The grown tree's own state after the tip: its digest, and the
    /// archival rows the store writes for a chain that posts no bonds
    /// ([`GrownTree::archival_snapshot_after`]).
    OfTree,
    /// A state read from a reference store — the pair as the LMDB walker
    /// would have taken it, for chains the tree cannot derive (bond posts,
    /// an injected credit).
    Read {
        /// The reference digest.
        digest: Digest,
        /// The reference rows.
        archival: &'a ArchivalSnapshot,
    },
}

/// A trace for `chain`. Each row's `root_after` is [`GrownTree::root_after`]
/// of this chain and its three weight values are the tree's derivation at
/// that height ([`GrownTree::weights_of`], [`GrownTree::median_for`]);
/// `economics` supplies the rest and is called once per height, from
/// genesis, in order. `pinned` appends the checkpoint — both encodings —
/// after the tip, when given.
///
/// Heights are the chain's indices. A chain whose first block is not
/// genesis is not this constructor's input.
pub fn trace_pinned(
    chain: &[(Block, Vec<Transaction>)],
    mut economics: impl FnMut(u64) -> TraceEconomics,
    pinned: Option<Pinned<'_>>,
) -> Trace {
    let mut w = TraceWriter::new(Vec::new()).expect("header");
    let tree = GrownTree::over(chain);
    for index in 0..chain.len() {
        let height = u64::try_from(index).expect("a fixture height fits");
        let facts = economics(height).over(&tree, height);
        w.push_facts(h(height), &facts).expect("facts");
    }
    if let Some(pinned) = pinned {
        let (digest, archival) = match pinned {
            Pinned::OfTree => {
                let tip = chain
                    .len()
                    .checked_sub(1)
                    .and_then(|t| u64::try_from(t).ok())
                    .expect("a checkpoint of the tree needs a tip: the chain is empty");
                (
                    digest_of(chain, tree.root_after(tip).as_bytes()),
                    tree.archival_snapshot_after(tip),
                )
            }
            Pinned::Read { digest, archival } => (digest, archival.clone()),
        };
        w.push_checkpoint(&digest).expect("checkpoint");
        w.push_archival_snapshot(&archival)
            .expect("archival snapshot");
    }
    Trace::read(std::io::Cursor::new(w.finish().expect("trailer"))).expect("read")
}

/// [`trace_pinned`] with the tree's own checkpoint, or none.
pub fn trace_with(
    chain: &[(Block, Vec<Transaction>)],
    economics: impl FnMut(u64) -> TraceEconomics,
    checkpoint: bool,
) -> Trace {
    trace_pinned(chain, economics, checkpoint.then_some(Pinned::OfTree))
}

/// [`trace_with`] with the synthetic economics: distinct per height, zero burn.
pub fn trace_of(chain: &[(Block, Vec<Transaction>)], checkpoint: bool) -> Trace {
    trace_with(chain, synthetic_economics, checkpoint)
}

/// [`trace_pinned`] with the synthetic economics and a checkpoint read
/// from a reference store ([`Pinned::Read`]).
pub fn trace_read(
    chain: &[(Block, Vec<Transaction>)],
    digest: Digest,
    archival: &ArchivalSnapshot,
) -> Trace {
    trace_pinned(
        chain,
        synthetic_economics,
        Some(Pinned::Read { digest, archival }),
    )
}

/// The redb-shaped digest of `chain` given the root after its tip.
fn digest_of(chain: &[(Block, Vec<Transaction>)], root_after_tip: &[u8; 32]) -> Digest {
    let hashes: Vec<[u8; 32]> = chain
        .iter()
        .map(|(block, _)| block.hash().to_bytes())
        .collect();
    digest_v0(&hashes, &spent_keys_of(chain), root_after_tip)
}

/// The redb-shaped digest one would expect after `chain`.
pub fn expected_state(chain: &[(Block, Vec<Transaction>)]) -> Digest {
    let last = u64::try_from(chain.len() - 1).expect("a chain has a tip");
    digest_of(chain, GrownTree::over(chain).root_after(last).as_bytes())
}

pub fn open_store(path: &std::path::Path) -> ChainStore {
    ChainStore::create(path, EPOCH).expect("create")
}

/// A store under the `(SEB, cap)` pair of the rule set that will judge its
/// blocks — a chain mined on a levered regtest schedule opens its store
/// the way the daemon did (`Horizons::under`), or `connect` refuses the
/// first block for naming another epoch (`ARW-15`).
///
/// The archival [`ApplyPolicy`] is the caller's: the replays pass
/// [`ApplyPolicy::Full`]; the sufficiency stamp (DRS-E4 §3.8 item 2) opens
/// a store with one family's writer stubbed and asks whether the comparator
/// notices.
///
/// [`ApplyPolicy`]: shekyl_chain_store::apply_policy::ApplyPolicy
/// [`ApplyPolicy::Full`]: shekyl_chain_store::apply_policy::ApplyPolicy::Full
pub fn open_store_under(
    path: &std::path::Path,
    in_force: &RuleSet,
    policy: shekyl_chain_store::apply_policy::ApplyPolicy,
) -> ChainStore {
    let horizons = shekyl_chain_store::store::Horizons::under(in_force)
        .expect("a well-formed rule set's pair is a store schedule");
    ChainStore::with_horizons(path, policy, horizons).expect("create")
}

/// A connector whose task the test holds, so that stopping it can wait until
/// the actor — and the [`ChainStore`] it owns — has been dropped.
///
/// [`kameo::actor::ActorRef::wait_for_shutdown`] is not that wait. kameo 0.20
/// resolves it when the mailbox closes, which is before `on_stop` runs and
/// before the task drops the actor value; a store reopened after it races
/// that drop and meets redb's single-writer lock as `DatabaseAlreadyOpen`.
/// The drop flushes the file, so the window is widest on a disk-backed temp
/// directory under load. Joining the task closes it — the same join the
/// production run does after stopping its connector (`pipeline.rs`).
#[cfg(feature = "pipeline")]
pub struct JoinedConnector {
    pub actor: kameo::actor::ActorRef<Connector>,
    task: tokio::task::JoinHandle<
        Result<(Connector, kameo::error::ActorStopReason), kameo::error::PanicError>,
    >,
}

#[cfg(feature = "pipeline")]
impl JoinedConnector {
    pub fn spawn(args: ConnectorArgs) -> Self {
        let prepared = kameo::actor::PreparedActor::<Connector>::new(kameo::mailbox::unbounded());
        let actor = prepared.actor_ref().clone();
        let task = prepared.spawn(args);
        Self { actor, task }
    }

    /// Wait for the actor's task to end, dropping the actor and releasing its
    /// store. The caller has already stopped it.
    pub async fn join(self) {
        drop(self.task.await.expect("the connector task joins"));
    }

    /// Stop the actor, then [`Self::join`].
    pub async fn stop_and_join(self) {
        let _already_stopped = self.actor.stop_gracefully().await.is_err();
        self.join().await;
    }
}

/// A source that plays a script of events, sequenced from `FIRST`, whose
/// first `Extend` is at `first`.
pub struct Scripted {
    first: BlockHeight,
    events: VecDeque<Sequenced<IngestEvent>>,
}

impl Scripted {
    /// Events numbered consecutively from `FIRST`, starting at height 0.
    pub fn new(events: Vec<IngestEvent>) -> Self {
        Self::from(h(0), events)
    }

    /// Events numbered consecutively from `FIRST`, starting at `first`.
    pub fn from(first: BlockHeight, events: Vec<IngestEvent>) -> Self {
        let mut seq = SequenceNo::FIRST;
        let events = events
            .into_iter()
            .map(|event| {
                let at = seq;
                seq = seq.next();
                Sequenced { seq: at, event }
            })
            .collect();
        Self { first, events }
    }

    /// Events with the numbers given — for a source that breaks the
    /// numbering contract on purpose.
    pub fn numbered(first: BlockHeight, events: Vec<Sequenced<IngestEvent>>) -> Self {
        Self {
            first,
            events: events.into(),
        }
    }
}

impl Source for Scripted {
    type Fault = std::convert::Infallible;

    fn first_height(&self) -> BlockHeight {
        self.first
    }

    fn next(&mut self) -> Result<Option<Sequenced<IngestEvent>>, Self::Fault> {
        Ok(self.events.pop_front())
    }
}
