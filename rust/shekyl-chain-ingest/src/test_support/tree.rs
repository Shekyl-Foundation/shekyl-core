// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The validator-side curve tree a synthetic chain grows.
//!
//! Advanced by the production derivation (`tree_after`) as blocks are
//! pushed, the same way `connect` advances the store. [`Growing`](super::Growing)
//! keeps the wallet-side tree on this one's root.

#![cfg_attr(
    not(feature = "pipeline"),
    expect(
        dead_code,
        reason = "pipeline-only fixtures are unused when the pipeline tests are not built"
    )
)]

use core::convert::Infallible;

use std::collections::BTreeMap;

use shekyl_chain_rules::{
    effective_median_at, quote_emission, tree_after, AtHeight, BlockOutputs, Candidate, ChainView,
    HeaderRecord, HeaderView, LeafSource, RecordedBlock, RecordedWeights, RuleSet,
    SettlementSchedule, Tip, TreeFrontier, ViewRead,
};
use shekyl_chain_store::archival_snapshot::ArchivalSnapshot;
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{
    ArchivalLength, BlockCount, BlockHash, BlockHeight, BlockWeight, CurveTreeRoot,
    GlobalOutputIndex, KeyImage, LongTermWeight, SettlementEpoch, TxHash,
};
use shekyl_units::AtomicUnits;
use shekyl_wire::tx_extra::{admitted_leaf_blob, parse, pqc_leaf_entries_per_output};
use shekyl_wire::{Block, Ct, Transaction};

use super::{at, h};

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
    pub fn root_going_into(&self, height: BlockHeight) -> CurveTreeRoot {
        self.roots[at(height.to_raw())]
    }

    /// The root after block `height`'s drain — what its connect writes at
    /// the next height.
    #[must_use]
    pub fn root_after(&self, height: BlockHeight) -> CurveTreeRoot {
        let next = height
            .checked_add(BlockCount::ONE)
            .expect("a fixture height has a successor");
        self.roots[at(next.to_raw())]
    }

    /// Block `height`'s weight and long-term weight as this chain derives
    /// them — what the store's `block_info` would hold.
    #[must_use]
    pub fn weights_of(&self, height: BlockHeight) -> RecordedWeights {
        self.weights[at(height.to_raw())]
    }

    /// The long-term effective median in force for block `height` — the
    /// value the validator's verdict carries for it and the trace's row
    /// records.
    #[must_use]
    pub fn median_for(&self, height: BlockHeight) -> LongTermWeight {
        self.medians[at(height.to_raw())]
    }

    /// The gross emission through block `height` as this chain derives it
    /// — the parent's plus the paid reward (CEN-F14b, G12): what the
    /// validator's verdict carries and the trace's row records.
    #[must_use]
    pub fn coins_generated_at(&self, height: BlockHeight) -> AtomicUnits {
        self.blocks[at(height.to_raw())].coins_generated
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
    pub fn archival_snapshot_after(&self, height: BlockHeight) -> ArchivalSnapshot {
        let raw = height.to_raw();
        let next = height
            .checked_add(BlockCount::ONE)
            .expect("a fixture height has a successor")
            .to_raw();
        let schedule = SettlementSchedule::GENESIS;
        assert!(
            schedule.close_due_at_height(next).is_none(),
            "the synthetic fixtures stay short of a settlement close"
        );
        let epoch = schedule.epoch_at_height(raw);
        let open = schedule.open_height(epoch);
        let total = self.accrual[at(open)..=at(raw)]
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
            header: HeaderRecord {
                hash: block.hash(),
                header: block.header.clone(),
                // Regtest at difficulty one: the work through `h` is `h + 1`.
                cumulative_difficulty: CumulativeDifficulty::from_raw(
                    u128::from(height.to_raw()) + 1,
                ),
            },
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

impl<'id> HeaderView<'id> for GrownTree {
    type Fault = Infallible;

    fn tip(&self) -> Result<Option<Tip>, Infallible> {
        let Some(block) = self.blocks.last() else {
            return Ok(None);
        };
        let height = BlockHeight::from_raw(
            u64::try_from(self.blocks.len() - 1).expect("a fixture chain fits u64"),
        );
        Ok(Some(Tip {
            height,
            hash: block.header.hash,
        }))
    }

    /// The header half of the record `block_at` answers, the same vector.
    fn header_at(&self, height: BlockHeight) -> Result<AtHeight<HeaderRecord>, Infallible> {
        Ok(match Self::recorded(&self.blocks, height) {
            AtHeight::Recorded(block) => AtHeight::Recorded(block.header),
            AtHeight::AboveTip => AtHeight::AboveTip,
        })
    }
}

/// The tree `tree_after` grows, and the block records, weight window and
/// burned fold the reward chain reads when a block is pushed.
impl<'id> ChainView<'id> for GrownTree {
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
