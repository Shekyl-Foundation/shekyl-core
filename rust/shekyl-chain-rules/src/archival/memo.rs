// Copyright (c) 2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The drawable-set memo the count reads (`SO-D12b`).
//!
//! Keyed by the epoch and the hash of the block that opened it. A lookup
//! that misses rebuilds the set from the asking view and keeps the result
//! only when that rebuild digests to the view's recorded digest. The memo
//! is rules-side state held by the connect loop. It is not a store table,
//! not consensus state, not persisted, and not undone: an aborted batch's
//! insert is keyed by a hash no later committed view asks for.

use std::collections::BTreeMap;

use shekyl_archival_retention::{DrawableEpoch, SettlementSchedule};
use shekyl_types::{BlockHash, BlockHeight, SettlementEpoch};

/// How many opening-block forks of one epoch the memo holds.
///
/// A switch needs the chain in force and the chain being adopted. A third
/// fork misses and is rebuilt, which is the same set. The entry is the
/// epoch: at maturity a block contributes on the order of a hundred pairs,
/// and over an epoch the receipt keys (`RECEIPT_SIGN_PK_LEN` bytes each,
/// one per persona) dominate. Two entries are what a switch holds.
const FORKS_PER_EPOCH: usize = 2;

struct Slot {
    open: BlockHash,
    drawable: DrawableEpoch,
}

/// The drawable sets the count has already built, by epoch and by the
/// opening block's hash.
#[derive(Default)]
pub struct DrawableMemo {
    by_epoch: BTreeMap<SettlementEpoch, Vec<Slot>>,
}

impl DrawableMemo {
    /// An empty memo. A harness that passes [`None`] instead rebuilds on
    /// every call through the same function.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The set recorded for `epoch` under `open`, when this memo holds it.
    #[must_use]
    pub fn get(&self, epoch: SettlementEpoch, open: &BlockHash) -> Option<&DrawableEpoch> {
        self.by_epoch
            .get(&epoch)?
            .iter()
            .find(|slot| slot.open == *open)
            .map(|slot| &slot.drawable)
    }

    /// Remember `drawable` as the set `open` produced for `epoch`.
    ///
    /// Visible to the archival module, and called from the count phase only:
    /// at an open,
    /// with the post-state set the transition just built, or after a
    /// rebuild whose digest matched the recorded one. A hit is trusted, so
    /// a set inserted from outside that path would make
    /// `validate_with_memo` disagree with `validate` on the same block.
    /// The connector constructs the memo and retains it. It does not seed it.
    ///
    /// A second insert of the same hash replaces that slot. Past
    /// [`FORKS_PER_EPOCH`] the oldest slot of the epoch is dropped: the
    /// fork it named misses and rebuilds.
    pub(super) fn insert(
        &mut self,
        epoch: SettlementEpoch,
        open: BlockHash,
        drawable: DrawableEpoch,
    ) {
        let slots = self.by_epoch.entry(epoch).or_default();
        if let Some(slot) = slots.iter_mut().find(|slot| slot.open == open) {
            slot.drawable = drawable;
            return;
        }
        if slots.len() == FORKS_PER_EPOCH {
            slots.remove(0);
        }
        slots.push(Slot { open, drawable });
    }

    /// Drop epochs whose lifetime has ended at `connecting`.
    ///
    /// A set is read from `h_open(E)` through `h_close(E) + W₂`, and `W₂`
    /// is zero when the schedule has no window. `W₂ < SEB`, so epoch
    /// `E − 2` is already past that end at `h_open(E)`.
    pub fn evict(&mut self, connecting: BlockHeight, schedule: SettlementSchedule) {
        let height = connecting.to_raw();
        let window = schedule
            .challenge_response_blocks()
            .map_or(0, core::num::NonZeroU64::get);
        self.by_epoch.retain(|&epoch, _| {
            let end = schedule.last_block(epoch.to_raw()).saturating_add(window);
            height <= end
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_archival_retention::{DrawablePair, SettlementEpochBlocks};
    use shekyl_crypto_pq::fn_dsa_hybrid::HybridEd25519FnDsa;
    use shekyl_types::{PCanonicalId, ShardId};

    fn empty(epoch: SettlementEpoch) -> DrawableEpoch {
        DrawableEpoch::new(
            epoch,
            Vec::<(PCanonicalId, shekyl_types::archival::ReceiptSignPk)>::new(),
            [],
        )
        .expect("an empty set")
    }

    fn one_pair(epoch: SettlementEpoch) -> DrawableEpoch {
        let persona = PCanonicalId::from_bytes([0x10; 32]);
        let key = HybridEd25519FnDsa::keypair_from_seeds(&[1; 32], &[101; 32])
            .expect("keygen")
            .0
            .to_receipt_sign_pk();
        DrawableEpoch::new(
            epoch,
            [(persona, key)],
            [DrawablePair {
                persona,
                shard: ShardId::from_raw(1),
            }],
        )
        .expect("one pair, one key")
    }

    fn hash(byte: u8) -> BlockHash {
        BlockHash::from_bytes([byte; 32])
    }

    /// Two forks of one epoch stay distinct, and each hash reads its own
    /// length. Red edit: key by the epoch alone — both hashes read the
    /// second set, or the first hash misses.
    #[test]
    fn two_opening_hashes_keep_two_sets() {
        let epoch = SettlementEpoch::from_raw(4);
        let mut memo = DrawableMemo::new();
        memo.insert(epoch, hash(1), one_pair(epoch));
        memo.insert(epoch, hash(2), empty(epoch));
        assert_eq!(memo.get(epoch, &hash(1)).expect("the first fork").len(), 1);
        assert_eq!(memo.get(epoch, &hash(2)).expect("the second fork").len(), 0);
        assert!(memo.get(epoch, &hash(3)).is_none());
    }

    /// A third fork drops the oldest slot. Red edit: keep every fork.
    #[test]
    fn a_third_fork_drops_the_oldest() {
        let epoch = SettlementEpoch::from_raw(4);
        let mut memo = DrawableMemo::new();
        memo.insert(epoch, hash(1), empty(epoch));
        memo.insert(epoch, hash(2), empty(epoch));
        memo.insert(epoch, hash(3), empty(epoch));
        assert!(memo.get(epoch, &hash(1)).is_none());
        assert!(memo.get(epoch, &hash(2)).is_some());
        assert!(memo.get(epoch, &hash(3)).is_some());
    }

    /// Epoch `E − 2` is past its window at the open of `E`. Red edit: keep
    /// every epoch.
    #[test]
    fn an_epoch_past_its_window_is_evicted() {
        let blocks = SettlementEpochBlocks::new(20).expect("non-zero");
        let schedule = SettlementSchedule::new(blocks);
        let mut memo = DrawableMemo::new();
        let epoch0 = SettlementEpoch::from_raw(0);
        let epoch1 = SettlementEpoch::from_raw(1);
        memo.insert(epoch0, hash(1), empty(epoch0));
        memo.insert(epoch1, hash(1), empty(epoch1));
        // `h_close(0) + W₂ = 19 + 1`. Height 21 is past it; epoch 1 is not.
        memo.evict(BlockHeight::from_raw(21), schedule);
        assert!(memo.get(epoch0, &hash(1)).is_none());
        assert!(memo.get(epoch1, &hash(1)).is_some());
    }
}
