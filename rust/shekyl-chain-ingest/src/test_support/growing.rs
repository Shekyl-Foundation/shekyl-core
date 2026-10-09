// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A chain under construction, with the validator tree and the wallet-side
//! tree held to one root.

#![cfg_attr(
    not(feature = "pipeline"),
    expect(
        dead_code,
        reason = "pipeline-only fixtures are unused when the pipeline tests are not built"
    )
)]

use shekyl_harness_spender::{Linked, MinerWallet, PostedBond, Spender};
use shekyl_types::{BlockHash, BlockHeight, CurveTreeRoot};
use shekyl_wire::{Block, Transaction};

use super::{anchor, block_with_nonce, h, reward_for, Family, GrownTree, FIRST_SPEND_HEIGHT};

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
        let height = self.height();
        let raw = height.to_raw();
        let previous = self.hashes.last().copied().unwrap_or(BlockHash::NULL);
        let root = self.tree.root_going_into(height);
        let reward = reward_for(&self.tree, root, raw, previous, &listed);
        let block = make(root, raw, previous, &listed, reward);
        self.record(block, listed)
    }

    /// Push `block` to both trees, holding them to one root first.
    fn record(&mut self, block: Block, listed: Vec<Transaction>) -> &(Block, Vec<Transaction>) {
        let height = self.height();
        self.tree.push(&block, &listed);
        self.spender.push_agreeing(
            &Linked::new(&block, &listed),
            self.tree.root_going_into(height),
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
