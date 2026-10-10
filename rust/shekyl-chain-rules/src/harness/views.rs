// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Views that exhibit a fault, or a state a conforming store refuses to hold.
//!
//! [`FaultingView`] fails every read. [`WithholdingView`] answers `AboveTip`
//! for one per-height read while the tip still says the chain is dense.
//! [`NonCanonicalBondView`] serves one persona a bond record whose hybrid
//! key is not canonical. When a mock is the right instrument at all is
//! [`MockChain`](super::MockChain)'s charter.

use std::collections::BTreeMap;

use core::convert::Infallible;

use shekyl_crypto_pq::signature::HybridPublicKey;
use shekyl_types::archival::{
    BondRecord, Holdings, IndexedDraw, IssuedDigest, PassCount, RMarket, ServedShard,
    SettlementRow, SigmaWorkMilli, SlashLogEntry,
};
use shekyl_types::{
    BlockCount, BlockHash, BlockHeight, CurveTreeRoot, KeyImage, PCanonicalId, SettlementEpoch,
    ShardId, TxHash,
};
use shekyl_units::AtomicUnits;

use super::{Brand, MockView};
use crate::tree_growth::TreeFrontier;
use crate::view::{AtHeight, BlockOutputs, ChainView, RecordedBlock, RecordedWeights, Tip};

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

    fn total_burned(&self) -> Result<AtomicUnits, Faulted> {
        Err(Faulted)
    }

    fn tree_frontier(&self) -> Result<TreeFrontier, Faulted> {
        Err(Faulted)
    }

    fn leaf_count_at(&self, _: BlockHeight) -> Result<AtHeight<u64>, Faulted> {
        Err(Faulted)
    }

    fn outputs_at(&self, _: BlockHeight) -> Result<AtHeight<BlockOutputs>, Faulted> {
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

    fn weights_window(
        &self,
        _: BlockHeight,
        _: BlockCount,
    ) -> Result<AtHeight<Vec<RecordedWeights>>, Faulted> {
        Err(Faulted)
    }

    fn has_transaction(&self, _: &TxHash) -> Result<bool, Faulted> {
        Err(Faulted)
    }

    fn tip(&self) -> Result<Option<Tip>, Faulted> {
        Err(Faulted)
    }

    crate::archival_reads!(fault Faulted);
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
    /// [`ChainView::weights_window`] ending at this height — the weights
    /// projection answers `AboveTip` for a height the tip says is
    /// recorded (slice 7, CEN-G6's read).
    WeightsBelow(BlockHeight),
    /// [`ChainView::leaf_count_at`] at this height — the tree's size,
    /// and so [`ChainView::depth_at`] (slice 8, CEN-J21's I13 read).
    LeafCountAt(BlockHeight),
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

    fn total_burned(&self) -> Result<AtomicUnits, Infallible> {
        self.inner.total_burned()
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

    fn weights_window(
        &self,
        end: BlockHeight,
        at_most: BlockCount,
    ) -> Result<AtHeight<Vec<RecordedWeights>>, Infallible> {
        if let WithheldRead::WeightsBelow(at) = self.withheld {
            if end == at {
                return Ok(AtHeight::AboveTip);
            }
        }
        self.inner.weights_window(end, at_most)
    }

    fn has_transaction(&self, hash: &TxHash) -> Result<bool, Infallible> {
        self.inner.has_transaction(hash)
    }

    fn tree_frontier(&self) -> Result<TreeFrontier, Infallible> {
        self.inner.tree_frontier()
    }

    fn leaf_count_at(&self, height: BlockHeight) -> Result<AtHeight<u64>, Infallible> {
        if let WithheldRead::LeafCountAt(at) = self.withheld {
            if height == at {
                return Ok(AtHeight::AboveTip);
            }
        }
        self.inner.leaf_count_at(height)
    }

    fn outputs_at(&self, height: BlockHeight) -> Result<AtHeight<BlockOutputs>, Infallible> {
        self.inner.outputs_at(height)
    }

    crate::archival_reads!(delegate inner);
}

/// Hybrid-key bytes [`HybridPublicKey::from_canonical_bytes`] rejects.
///
/// The constructor is that rejection, so a [`NonCanonicalBondView`] cannot
/// serve a key the admission grammar accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonCanonicalHybridKey(Vec<u8>);

impl NonCanonicalHybridKey {
    /// `Some` when `bytes` are not a canonical hybrid public key.
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Option<Self> {
        let bytes = bytes.into();
        if HybridPublicKey::from_canonical_bytes(&bytes).is_ok() {
            None
        } else {
            Some(Self(bytes))
        }
    }
}

/// A [`MockView`] that serves one persona a bond record whose hybrid key
/// is not canonical.
///
/// Job 3 of the mock's charter, beside [`WithholdingView`]. `bond_records`
/// is the inner list with this persona's record planted, so the two bond
/// reads agree and every other persona stays the inner mock's. A chain
/// that posts a real bond is the writer's to witness, not this view's:
/// the constructor will not accept a canonical key.
pub struct NonCanonicalBondView<'a, 'id> {
    inner: MockView<'a, 'id>,
    persona: PCanonicalId,
    record: BondRecord,
}

impl<'a, 'id> MockView<'a, 'id> {
    /// Serve `persona` the record whose hybrid key is `key`. The record's
    /// other fields are empty: this instrument exists so a rule can observe
    /// the key, and it folds nothing.
    #[must_use]
    pub fn with_non_canonical_bond(
        self,
        persona: PCanonicalId,
        key: NonCanonicalHybridKey,
    ) -> NonCanonicalBondView<'a, 'id> {
        NonCanonicalBondView {
            inner: self,
            persona,
            record: BondRecord {
                hybrid_pubkey: key.0,
                bond_spend_pk: Vec::new(),
                endpoint: [0; 32],
                join_settlement_epoch: SettlementEpoch::ZERO,
                bonded_total: AtomicUnits::ZERO,
                holdings: Holdings::shard_set(Vec::new())
                    .expect("an empty shard set is a holdings value"),
                bad_intervals: Vec::new(),
                claimed_settlement_epochs: Vec::new(),
                first_paying_emission_height: None,
            },
        }
    }
}

impl<'id> ChainView<'id> for NonCanonicalBondView<'_, 'id> {
    type Fault = Infallible;

    fn has_key_image(&self, key_image: &KeyImage) -> Result<bool, Infallible> {
        self.inner.has_key_image(key_image)
    }

    fn total_burned(&self) -> Result<AtomicUnits, Infallible> {
        self.inner.total_burned()
    }

    fn block_at(&self, height: BlockHeight) -> Result<AtHeight<RecordedBlock>, Infallible> {
        self.inner.block_at(height)
    }

    fn height_of(&self, hash: &BlockHash) -> Result<Option<BlockHeight>, Infallible> {
        self.inner.height_of(hash)
    }

    fn root_at(&self, height: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, Infallible> {
        self.inner.root_at(height)
    }

    fn tip(&self) -> Result<Option<Tip>, Infallible> {
        self.inner.tip()
    }

    fn weights_window(
        &self,
        end: BlockHeight,
        at_most: BlockCount,
    ) -> Result<AtHeight<Vec<RecordedWeights>>, Infallible> {
        self.inner.weights_window(end, at_most)
    }

    fn has_transaction(&self, hash: &TxHash) -> Result<bool, Infallible> {
        self.inner.has_transaction(hash)
    }

    fn tree_frontier(&self) -> Result<TreeFrontier, Infallible> {
        self.inner.tree_frontier()
    }

    fn leaf_count_at(&self, height: BlockHeight) -> Result<AtHeight<u64>, Infallible> {
        self.inner.leaf_count_at(height)
    }

    fn outputs_at(&self, height: BlockHeight) -> Result<AtHeight<BlockOutputs>, Infallible> {
        self.inner.outputs_at(height)
    }

    fn bond_record(&self, persona: &PCanonicalId) -> Result<Option<BondRecord>, Infallible> {
        if persona == &self.persona {
            Ok(Some(self.record.clone()))
        } else {
            self.inner.bond_record(persona)
        }
    }

    fn slash_log_after(
        &self,
        persona: &PCanonicalId,
        height: BlockHeight,
    ) -> Result<Vec<SlashLogEntry>, Infallible> {
        self.inner.slash_log_after(persona, height)
    }

    fn last_served_epoch(
        &self,
        persona: &PCanonicalId,
        shard: ShardId,
    ) -> Result<Option<SettlementEpoch>, Infallible> {
        self.inner.last_served_epoch(persona, shard)
    }

    fn served_shards(&self, persona: &PCanonicalId) -> Result<Vec<ServedShard>, Infallible> {
        self.inner.served_shards(persona)
    }

    fn pass_count(
        &self,
        persona: &PCanonicalId,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<PassCount, Infallible> {
        self.inner.pass_count(persona, shard, epoch)
    }

    fn r_market(
        &self,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<Option<RMarket>, Infallible> {
        self.inner.r_market(shard, epoch)
    }

    fn sigma_work(&self, epoch: SettlementEpoch) -> Result<Option<SigmaWorkMilli>, Infallible> {
        self.inner.sigma_work(epoch)
    }

    fn budget(&self, epoch: SettlementEpoch) -> Result<Option<AtomicUnits>, Infallible> {
        self.inner.budget(epoch)
    }

    fn last_settled_slash_epoch(&self) -> Result<Option<SettlementEpoch>, Infallible> {
        self.inner.last_settled_slash_epoch()
    }

    fn bond_records(&self) -> Result<Vec<(PCanonicalId, BondRecord)>, Infallible> {
        let mut records = self.inner.bond_records()?;
        if let Some((_, record)) = records
            .iter_mut()
            .find(|(persona, _)| *persona == self.persona)
        {
            *record = self.record.clone();
        } else {
            records.push((self.persona, self.record.clone()));
        }
        Ok(records)
    }

    fn slash_applied(
        &self,
        persona: &PCanonicalId,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<bool, Infallible> {
        self.inner.slash_applied(persona, shard, epoch)
    }

    fn budget_accruing(&self, epoch: SettlementEpoch) -> Result<Option<AtomicUnits>, Infallible> {
        self.inner.budget_accruing(epoch)
    }

    fn settlement_row(
        &self,
        persona: &PCanonicalId,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<Option<SettlementRow>, Infallible> {
        self.inner.settlement_row(persona, shard, epoch)
    }

    fn issued_draws(&self, epoch: SettlementEpoch) -> Result<Vec<IndexedDraw>, Infallible> {
        self.inner.issued_draws(epoch)
    }

    fn issued_digest(&self, epoch: SettlementEpoch) -> Result<IssuedDigest, Infallible> {
        self.inner.issued_digest(epoch)
    }

    fn served_at(
        &self,
        persona: &PCanonicalId,
        epochs: &[SettlementEpoch],
    ) -> Result<BTreeMap<SettlementEpoch, Vec<ShardId>>, Infallible> {
        self.inner.served_at(persona, epochs)
    }
}
