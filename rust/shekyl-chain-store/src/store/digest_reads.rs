// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The redb half of the logical-state digest v0 — DRS-E2's oracle read
//! (`DRS_E2_REPLAY_DRIVER.md` RD-F5; format: [`crate::digest_v0`]).
//!
//! [`digest_v0`](crate::digest_v0::digest_v0) had one caller, fed from the
//! C++ side through `shekyl-ffi`. Nothing assembled its three families from
//! **this** store, so the replay driver had an LMDB digest and no redb
//! digest to grade it against. This module is that assembly, over the reads
//! S-CHAIN-R and S-OUT-KI already landed:
//!
//! | Family | This store | Read |
//! | --- | --- | --- |
//! | height-ordered block hashes | `block_info[h].hash`, `h ∈ 0..=tip` | `ReadSnapshot::block_infos` (SI-2 dense; a hole is SI-7) |
//! | the spent-key **set** | `spent_keys` | `ReadSnapshot::key_images` (K2; `MDB_NODUPDATA`'s redb twin is the key being the set) |
//! | the live curve-tree root | `curve_tree_roots[tip + 1]` — what the tip block's connect wrote (`ConnectFacts::root_after`); the empty tree when nothing is recorded | one cell read, here (SI-4: `1..=tip + 1` present; a hole is SI-7) |
//!
//! **The root is a copy, and the value says so.** `connect` writes
//! `root_after` as it was passed through from LMDB, so the digest's root
//! component compares LMDB's root with itself (RD-F7). The result therefore
//! carries the components **separately** — [`LogicalStateDigestV0::chain`],
//! [`spent`](LogicalStateDigestV0::spent), [`curve_root`](LogicalStateDigestV0::curve_root)
//! — so the grader applies RD-Q9's two clauses per component rather than
//! reading one 32-byte outer digest as evidence for all three. The outer
//! digest is still computed, once, from those components
//! ([`digest_v0::outer_preimage`](crate::digest_v0::outer_preimage)), and is
//! byte-identical to what [`digest_v0`](crate::digest_v0::digest_v0) yields
//! over the same inputs — the test holds both.
//!
//! **Not a public root read.** The live-root cell read is this module's
//! own, `pub(super)`-free and private: S-CURVE (DRS-E3) decides the public
//! shape of curve-tree reads on `ReadSnapshot`, and a digest that needs one
//! value is not the consumer that shapes that surface.

use shekyl_chain_rules::AtHeight;
use shekyl_types::{BlockHeight, CurveTreeRoot, KeyImage};

use super::chain_reads::{self, absent, ReadFault};
use super::error::StoreError;
use super::read::ReadSnapshot;
use crate::digest_v0::{chain_component, outer_digest, outer_preimage, spent_accumulator};
use crate::schema::CURVE_TREE_ROOTS;

/// The v0 logical state of one snapshot, by component, with its outer
/// digest. Produced by [`ReadSnapshot::logical_state_digest_v0`].
///
/// Components are carried alongside the digest because they grade
/// differently (module docs): `chain` and `spent` are what replay actually
/// produced; `curve_root` is the passed-through fact written back. A
/// consumer that only wants the oracle reads [`digest`](Self::digest).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogicalStateDigestV0 {
    /// Recorded blocks, `tip + 1` — the preimage's `n_blocks`.
    pub n_blocks: u64,
    /// Cardinality of the spent-key set — the preimage's `n_spent`.
    pub n_spent: u64,
    /// [`chain_component`] over the height-ordered block hashes.
    pub chain: [u8; 32],
    /// [`spent_accumulator`] over the spent-key set.
    pub spent: [u8; 32],
    /// The live root, `curve_tree_roots[tip + 1]`; [`CurveTreeRoot::EMPTY`]
    /// when nothing is recorded.
    pub curve_root: CurveTreeRoot,
    /// `cSHAKE256(OUTER_CUSTOMIZATION, outer_preimage(...))` over the five
    /// fields above — equal to `digest_v0(hashes, spent, root)`.
    pub digest: [u8; 32],
}

impl ReadSnapshot<'_> {
    /// **RD-F5.** The v0 logical-state digest of this snapshot, assembled
    /// from the redb tables (module docs). One full scan of `block_info`
    /// and `spent_keys` — the comparator's read, not a hot path.
    ///
    /// # Errors
    ///
    /// SI-7 for a hole in `block_info` at or below the tip or a missing
    /// `curve_tree_roots[tip + 1]`; engine and codec faults pass through.
    pub fn logical_state_digest_v0(&self) -> Result<LogicalStateDigestV0, StoreError> {
        let tip = self.tip()?.recorded.map(|t| t.height.to_raw());

        let mut hashes: Vec<[u8; 32]> = Vec::new();
        if let Some(tip) = tip {
            let end = BlockHeight::from_raw(tip.checked_add(1).expect("tip + 1 fits u64"));
            let AtHeight::Recorded(rows) = self.block_infos(BlockHeight::from_raw(0)..end)? else {
                // `0..=tip` is never above the tip it was read against.
                return Err(absent("block_info").into_plain());
            };
            hashes.reserve(usize::try_from(tip).map_or(0, |t| t.saturating_add(1)));
            for row in rows {
                let (_, info) = row?;
                hashes.push(info.hash.to_bytes());
            }
        }

        let spent: Vec<[u8; 32]> = self
            .key_images()?
            .map(|ki| ki.map(KeyImage::to_bytes))
            .collect::<Result<_, _>>()?;

        let curve_root = match tip {
            None => CurveTreeRoot::EMPTY,
            Some(tip) => self.live_root(tip)?,
        };

        let n_blocks = u64::try_from(hashes.len()).expect("block count fits u64");
        let n_spent = u64::try_from(spent.len()).expect("spent-key count fits u64");
        let chain = chain_component(&hashes);
        let spent = spent_accumulator(&spent);
        let digest = outer_digest(&outer_preimage(
            n_blocks,
            n_spent,
            &chain,
            &spent,
            curve_root.as_bytes(),
        ));
        Ok(LogicalStateDigestV0 {
            n_blocks,
            n_spent,
            chain,
            spent,
            curve_root,
            digest,
        })
    }

    /// `curve_tree_roots[tip + 1]` — the state after the tip block's connect
    /// (SI-4 writes keys `1..=tip + 1`), which is what LMDB's
    /// `get_curve_tree_root()` returns. A missing row is SI-7. Private: the
    /// public curve-tree read surface is S-CURVE's to shape.
    fn live_root(&self, tip: u64) -> Result<CurveTreeRoot, StoreError> {
        let key = tip.checked_add(1).expect("tip + 1 fits u64");
        chain_reads::cell(&self.txn, CURVE_TREE_ROOTS, key, "curve_tree_roots")
            .and_then(|root| root.ok_or_else(|| absent("curve_tree_roots")))
            .map_err(ReadFault::into_plain)
    }
}
