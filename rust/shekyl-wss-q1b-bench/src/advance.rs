// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `CT-6 Q4`'s subject: **the per-block advance of the amortized form**.
//!
//! ## What this replaces, and why the replacement is not optional
//!
//! `per_block_advance_worst_case_s` was `replay_median / REPLAY_WINDOW_BLOCKS`
//! — the spend replay divided by the blocks it covered. That is a legitimate
//! *pre-build model estimate* (uniform hashing over the window) and an
//! illegitimate *grade* once the form exists, because the built advance does
//! work the replay never did: it folds a frontier instead of rebuilding a
//! tree, and it writes a snapshot the replay has no counterpart for. A field
//! whose name says "advance" and whose derivation says "a share of the
//! replay" is the defect `CT-6 Q4` was left open to catch
//! (`CT6_PROVING_STATE.md` §5, Q4).
//!
//! ## What one iteration is
//!
//! Exactly what `CurveTreeClient::ingest_block` does for the ring, in the
//! order it does it and through the same functions:
//!
//! 1. fold the block's worst-case leaf population into the live
//!    [`Frontier`] — `leaves_per_block` calls to the production
//!    `push_leaf`;
//! 2. `encode` the advanced frontier — the capture;
//! 3. commit it to the ring through the production
//!    [`LeafStore::append_block_deltas`], which is where the horizon
//!    eviction and the store transaction are paid.
//!
//! **What it deliberately leaves out**: the leaf and pending table writes,
//! block decode, and leaf collection. Those are not new — they are what
//! ingest already cost before the ring existed — and the quantity `Q4`
//! pre-registers is the *advance*, which is the cost the amortization adds
//! and removes. Including unchanged work would flatter nothing and would make
//! the figure incomparable with the `537.59 ms` model it replaces, which also
//! counted no table writes.
//!
//! ## Leaves are real
//!
//! The population is the corpus's own derived leaves (`derive_pqc_leaf`,
//! through `build_corpus`), repacked into the store's 128-byte leaf layout.
//! A synthetic leaf would measure a different curve point's hash cost.

use shekyl_curve_tree::frontier::Frontier;
use shekyl_curve_tree::BlockHeight;
use shekyl_curve_tree::LeafStore;
use shekyl_curve_tree::SEGMENT_FREEZE_REORG_MARGIN_BLOCKS;
use shekyl_fcmp::tree::SCALARS_PER_LEAF;

use crate::fixture::Corpus;

/// One stored leaf: `SCALARS_PER_LEAF` Selene scalars, packed as the store
/// holds them.
const LEAF_BYTES: usize = SCALARS_PER_LEAF * 32;

/// A live frontier, a real ring, and the block population to advance over.
pub struct AdvanceRig {
    /// Kept so the database file outlives the rig. The rig measures a real
    /// store on the storage the caller names — the axis `§6.3.4` pins the
    /// rig's disk for.
    _dir: tempfile::TempDir,
    store: LeafStore,
    frontier: Frontier,
    height: u64,
    /// Blocks advanced before timing began, so [`Self::blocks_advanced`]
    /// reports the timed series rather than the prefill.
    prefilled: u64,
    /// Leaves folded before timing began, so [`Self::timed_leaves_folded`]
    /// covers the same window [`Self::blocks_advanced`] does.
    prefilled_leaves: u64,
    /// One block's worth of leaves, reused every iteration so the
    /// measurement is the advance and not a leaf generator.
    block_leaves: Vec<[u8; LEAF_BYTES]>,
}

impl AdvanceRig {
    /// Build a rig that advances `leaves_per_block` leaves per iteration.
    ///
    /// `store_dir` is where the ring's database is created. The ring commit
    /// is an fsync'd disk write, so on the pinned rig this must be the
    /// attested storage; `None` falls back to the system temporary
    /// directory, which off-rig is the same device and on-rig is not.
    ///
    /// # Panics
    ///
    /// If the scratch store cannot be created, or if the corpus holds fewer
    /// leaves than one block needs — a rig that silently advanced a short
    /// block would report a cost for a population it did not have.
    #[must_use]
    pub fn new(
        corpus: &Corpus,
        leaves_per_block: u64,
        store_dir: Option<&std::path::Path>,
    ) -> Self {
        let wanted = usize::try_from(leaves_per_block).expect("leaves per block fits usize");
        let available = corpus.leaf_scalars.len() / SCALARS_PER_LEAF;
        assert!(
            available >= wanted,
            "corpus holds {available} leaves; one worst-case block needs {wanted}"
        );
        let block_leaves: Vec<[u8; LEAF_BYTES]> = corpus
            .leaf_scalars
            .chunks_exact(SCALARS_PER_LEAF)
            .take(wanted)
            .map(|leaf| {
                let mut out = [0u8; LEAF_BYTES];
                for (slot, scalar) in out.chunks_exact_mut(32).zip(leaf) {
                    slot.copy_from_slice(scalar);
                }
                out
            })
            .collect();

        let dir = match store_dir {
            Some(parent) => tempfile::tempdir_in(parent).expect("scratch dir for the ring"),
            None => tempfile::tempdir().expect("scratch dir for the ring"),
        };
        let store = LeafStore::open(dir.path().join("advance.curvetree")).expect("ring store");
        Self {
            _dir: dir,
            store,
            frontier: Frontier::new(),
            height: 0,
            prefilled: 0,
            prefilled_leaves: 0,
            block_leaves,
        }
    }

    /// Advance one block: fold, capture, commit.
    ///
    /// # Panics
    ///
    /// On a frontier fold or store failure. There is no degraded advance to
    /// fall back to, and a rig that swallowed one would report the cost of
    /// not doing the work.
    pub fn advance_one_block(&mut self) {
        for leaf in &self.block_leaves {
            self.frontier.push_leaf(leaf).expect("frontier advance");
        }
        let snapshot = self.frontier.encode();
        self.store
            .append_block_deltas(
                &[],
                &[],
                &[],
                BlockHeight::from_raw(self.height),
                Some(&snapshot),
            )
            .expect("ring commit");
        self.height += 1;
    }

    /// Fill the ring past its retention horizon, untimed.
    ///
    /// **Every timed advance must pay a real eviction, and eviction cannot
    /// fire until the ring is full.** The retained run is `[h - horizon, h]`,
    /// so the write at `h` first drops a row at `h = horizon + 1`. A series
    /// started from an empty rig therefore pays *no* eviction for its first
    /// `horizon + 1` blocks and folds a shallower tree throughout — the
    /// first graded run converged after 479 blocks and so never evicted once,
    /// while the module doc above claims the commit is "where the horizon
    /// eviction ... is paid". This closes that gap rather than restating it.
    ///
    /// The prefill is excluded from [`Self::blocks_advanced`] so the rule-47
    /// subject assertion still speaks for the timed series alone.
    pub fn prefill_to_steady_state(&mut self) {
        while self.height < SEGMENT_FREEZE_REORG_MARGIN_BLOCKS + 1 {
            self.advance_one_block();
        }
        self.prefilled = self.height;
        self.prefilled_leaves = self.frontier.leaf_count();
    }

    /// Blocks advanced **while timed** — the rig's own subject assertion: a
    /// series that measured nothing leaves this at zero, and the prefill
    /// cannot stand in for it.
    #[must_use]
    pub fn blocks_advanced(&self) -> u64 {
        self.height - self.prefilled
    }

    /// Leaves folded **while timed**.
    ///
    /// The companion to [`Self::blocks_advanced`], so a caller's rule-47
    /// subject assertion compares two quantities covering the same window.
    /// The frontier's *whole* count is deliberately not exposed: read against
    /// `blocks_advanced` it would compare two different windows and refuse
    /// every prefilled run, which is the defect this pair replaced.
    #[must_use]
    pub fn timed_leaves_folded(&self) -> u64 {
        self.frontier.leaf_count() - self.prefilled_leaves
    }
}
