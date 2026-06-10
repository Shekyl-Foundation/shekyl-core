// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Top-level curve-tree client orchestration (CT-3).
//!
//! Drives block-derived reconstruction over synced blocks: decodes each
//! block, builds [`crate::types::OutputIdentity`] values, threads the
//! global output index across blocks ([`crate::recon::collect_block_leaves`]),
//! owns the reference-height → drain-threshold mapping, and exposes the
//! wallet-facing API.
//!
//! The `tx_extra 0x07` parse reuses `shekyl_scanner::extra::Extra` at this
//! boundary (where blocks are already decoded); the parsed blob is then
//! validated by [`crate::recon::extract_leaf_hashes`]. No second
//! `tx_extra` parser is written.
//!
//! ## Boundary
//!
//! This crate does not depend on `shekyl-scanner` (lib.rs "Layering").
//! The caller (the engine's block-decode path) runs scanner `Extra` to
//! turn raw `tx_extra` into the `0x07` leaf-hash blob and extracts each
//! output's `O`/`C`/target, then hands this client the reduced
//! [`BlockLeaves`]. The client owns everything from there: `h_pqc`
//! resolution ([`recon::extract_leaf_hashes`] + [`recon::per_output_h_pqc`]),
//! leaf collection + global-index threading ([`recon::collect_block_leaves`]),
//! the reference-height → drain-cutoff mapping, store-backed root
//! reconstruction ([`LeafStore::root_at_count`], CT-1), and the integrity
//! gate (§3.3): a reconstructed root that does not match the consensus header
//! root is a loud failure, never a silent bad proof. Store failures surface as
//! [`ClientError::Store`] with no replay-oracle fallback.
//!
//! ## Reorg (§3.4 / §6, S3-folds-into-S1/S2)
//!
//! Global output indices and leaf entries are *derived* from the replayed
//! block sequence, never from a persisted counter (derive-don't-accumulate,
//! `CT2_DRAIN_ORDER.md` §7.1). A reorg is therefore handled by rebuilding
//! from the post-reorg block list ([`CurveTreeClient::from_blocks`]) — there
//! is no separate reorg machinery in this client.
//!
//! ## Not here
//!
//! Membership-path assembly is CT-4 ([`crate::assemble`]); the cached
//! frozen-`R_k` hot path and persistence are CT-1 ([`crate::store`]). The
//! CT-2 replay oracle ([`recon::root_from_scalars`]) remains the KAT baseline;
//! production root queries use the store hot path only.
//!
//! See `docs/design/CURVE_TREE_CLIENT.md` §3 and
//! `docs/design/CT2_DRAIN_ORDER.md` §7 (data flow).

use std::collections::BTreeMap;

use crate::recon::{
    collect_block_leaves, drained_sorted, extract_leaf_hashes, per_output_h_pqc, TxOutputs,
};
use crate::store::{LeafStore, StoreError};
use crate::types::{LeafEntry, OutputIdentity, ReferenceBlock, TargetKind};

/// One output's leaf-relevant facts as decoded at the caller's boundary,
/// **before** `h_pqc` resolution. The client resolves `h_pqc` from the
/// transaction's `0x07` blob (recon-owned) and builds the full
/// [`OutputIdentity`] internally.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RawOutput {
    /// Compressed Ed25519 output public key (`O`).
    pub output_key: [u8; 32],
    /// Amount commitment (`C`); `None` when the output has no commitment
    /// slot (`i >= outPk.size()`), which makes it leaf-ineligible.
    pub commitment: Option<[u8; 32]>,
    /// Output target kind (decides maturity and leaf candidacy).
    pub target: TargetKind,
}

/// One transaction's leaf inputs, in `vout` order. The `0x07` leaf-hash
/// blob is the raw payload from `shekyl_scanner::extra::Extra::pqc_leaf_hashes()`
/// (`None` when the tag is absent); the client validates and slices it.
#[derive(Clone, Copy, Debug)]
pub struct TxLeafInputs<'a> {
    /// Whether this is the block's coinbase (`is_miner`).
    pub is_miner: bool,
    /// Parsed `tx_extra 0x07` blob, or `None` if the tag is absent.
    pub leaf_hash_blob: Option<&'a [u8]>,
    /// Per-output identities in `vout` order, `h_pqc` not yet resolved.
    pub outputs: &'a [RawOutput],
}

/// One decoded block's leaf inputs. Transactions must be in C++ order:
/// the coinbase first, then block txs in block-list order.
#[derive(Clone, Copy, Debug)]
pub struct BlockLeaves<'a> {
    /// Block height.
    pub height: u64,
    /// Transactions in block order (coinbase first).
    pub txs: &'a [TxLeafInputs<'a>],
}

/// Errors the client raises rather than emitting a silent bad proof.
#[derive(Debug)]
pub enum ClientError {
    /// The root reconstructed for `height` did not match the consensus
    /// header root — the integrity gate (§3.3). Refuse to proceed.
    RootMismatch {
        /// Reference height whose root failed to match.
        height: u64,
        /// Consensus header root the wallet must reproduce.
        expected: [u8; 32],
        /// Root the client reconstructed from its leaves.
        got: [u8; 32],
    },
    /// The requested output is not a drained leaf at the reference height,
    /// so no membership path exists for it there (the §4.3 lookup miss).
    OutputNotDrained {
        /// Compressed output key that was not found among drained leaves.
        output_key: [u8; 32],
    },
    /// Persistent leaf store failure (I/O or corruption).
    Store(StoreError),
}

/// Block-derived curve-tree client with persistent [`LeafStore`] (CT-1).
///
/// Holds leaf candidates and mirrors drained leaves into the store on each
/// [`Self::ingest_block`]. Construct with [`Self::from_blocks`] (or
/// [`Self::try_new`] + ingest) and reconstruct/verify a root at a reference
/// height via the persisted [`LeafStore`] hot path ([`Self::root_at`]);
/// store errors propagate and there is no silent replay-oracle fallback.
#[derive(Debug)]
pub struct CurveTreeClient {
    store: LeafStore,
    // `pub(crate)` so the sibling `assemble` module and unit tests read leaf
    // candidates. Drained leaves are mirrored into `store` on each ingest.
    pub(crate) entries: Vec<LeafEntry>,
    pub(crate) next_gindex: u64,
    /// `(drained_through, drained_leaf_count)` cache keyed by exact cutoff
    /// heights previously synced or queried. Lookups miss to the maturity
    /// index rather than interpolating between cached cutoffs.
    drained_through_counts: Vec<(u64, u64)>,
    /// Maturity bucket → indices into [`Self::entries`] for O(bucket) drain
    /// batching on each ingested block.
    entries_by_maturity: BTreeMap<u64, Vec<usize>>,
}

impl Default for CurveTreeClient {
    fn default() -> Self {
        Self::new()
    }
}

impl CurveTreeClient {
    /// Open an empty client backed by an ephemeral store.
    pub fn try_new() -> Result<Self, ClientError> {
        Ok(Self {
            store: LeafStore::open_ephemeral().map_err(ClientError::from)?,
            entries: Vec::new(),
            next_gindex: 0,
            drained_through_counts: Vec::new(),
            entries_by_maturity: BTreeMap::new(),
        })
    }

    /// An empty client (no blocks ingested). Its root at any reference
    /// height is the empty-tree root until the first leaf drains.
    ///
    /// Panics if the ephemeral store cannot be opened; production callers
    /// should use [`Self::try_new`] or [`Self::from_blocks`].
    #[must_use]
    pub fn new() -> Self {
        Self::try_new().expect("ephemeral leaf store")
    }

    /// Build a client by replaying `blocks` in order from genesis. This is
    /// also the reorg path: re-call with the post-reorg chain to rebuild
    /// (derive-don't-accumulate makes the rollback free).
    pub fn from_blocks(blocks: &[BlockLeaves<'_>]) -> Result<Self, ClientError> {
        let mut client = Self::try_new()?;
        client.store.clear()?;
        for block in blocks {
            client.ingest_block(*block)?;
        }
        Ok(client)
    }

    /// Ingest one block, resolving `h_pqc` per output, threading the global
    /// output index, and accumulating drained-leaf entries. Blocks must be
    /// ingested in ascending height order from genesis (the gindex is the
    /// cumulative chain position).
    pub fn ingest_block(&mut self, block: BlockLeaves<'_>) -> Result<(), ClientError> {
        // Resolve h_pqc per tx, then collect leaves. `identities` is kept
        // alive across the `collect_block_leaves` call that borrows it.
        let identities: Vec<Vec<OutputIdentity>> = block
            .txs
            .iter()
            .map(|tx| {
                let leaf_hashes = extract_leaf_hashes(tx.leaf_hash_blob);
                tx.outputs
                    .iter()
                    .enumerate()
                    .map(|(i, raw)| OutputIdentity {
                        output_key: raw.output_key,
                        commitment: raw.commitment,
                        h_pqc: per_output_h_pqc(&leaf_hashes, i),
                        target: raw.target,
                    })
                    .collect()
            })
            .collect();

        let txs: Vec<TxOutputs<'_>> = block
            .txs
            .iter()
            .zip(&identities)
            .map(|(tx, outs)| TxOutputs {
                is_miner: tx.is_miner,
                outputs: outs,
            })
            .collect();

        let entry_base = self.entries.len();
        self.next_gindex =
            collect_block_leaves(block.height, &txs, self.next_gindex, &mut self.entries);
        for (offset, entry) in self.entries[entry_base..].iter().enumerate() {
            self.entries_by_maturity
                .entry(entry.maturity)
                .or_default()
                .push(entry_base + offset);
        }
        self.sync_store(block.height)
    }

    fn sync_store(&mut self, tip_height: u64) -> Result<(), ClientError> {
        let through = Self::drained_through(tip_height);
        let store_tip = self.store.sync_tip_height()?;
        // When `root_at` advanced the store ahead of the ingested tip, new leaves
        // may already drain under `drained_through(store_tip)` and must still be
        // appended (`append_drained` keeps `META_SYNC_TIP` monotonic).
        let target_through = if tip_height <= store_tip {
            Self::drained_through(store_tip)
        } else {
            through
        };
        let stored = self.store.leaf_count()?;
        let canonical: Vec<LeafEntry> = drained_sorted(&self.entries, target_through)
            .into_iter()
            .copied()
            .collect();
        let stored_usize = usize::try_from(stored).expect("stored leaf count fits usize");
        if canonical.len() < stored_usize {
            return Err(StoreError::CorruptMeta("store leaf count exceeds canonical drain").into());
        }
        let new_entries = canonical[stored_usize..].to_vec();
        if !new_entries.is_empty() || tip_height > store_tip {
            self.store.append_drained(&new_entries, tip_height)?;
        }
        self.record_drained_count(
            through,
            Self::canonical_drained_count(&self.entries, through),
        );
        if target_through != through {
            let count = u64::try_from(canonical.len()).expect("canonical drain count fits u64");
            self.record_drained_count(target_through, count);
        }
        Ok(())
    }

    /// Catch the persisted store up to `tip_height` when a root query runs
    /// ahead of the ingested chain tip. Appends the canonical drained prefix
    /// missing from the store in one transaction (freeze eligibility at
    /// `tip_height`), rather than one txn per intermediate height.
    fn sync_store_to(&mut self, tip_height: u64) -> Result<(), ClientError> {
        let sync_tip = self.store.sync_tip_height()?;
        if sync_tip >= tip_height {
            return Ok(());
        }
        let target_through = Self::drained_through(tip_height);
        let stored = self.store.leaf_count()?;
        let canonical: Vec<LeafEntry> = drained_sorted(&self.entries, target_through)
            .into_iter()
            .copied()
            .collect();
        let stored_usize = usize::try_from(stored).expect("stored leaf count fits usize");
        if canonical.len() < stored_usize {
            return Err(StoreError::CorruptMeta("store leaf count exceeds canonical drain").into());
        }
        let new_entries = canonical[stored_usize..].to_vec();
        self.store.append_drained(&new_entries, tip_height)?;
        let new_count = u64::try_from(canonical.len()).expect("canonical drain count fits u64");
        self.record_drained_count(target_through, new_count);
        Ok(())
    }

    fn canonical_drained_count(entries: &[LeafEntry], through: u64) -> u64 {
        u64::try_from(drained_sorted(entries, through).len()).expect("drained leaf count fits u64")
    }

    /// Upsert `(drained_through, drained_leaf_count)` while keeping the cache
    /// sorted by `drained_through` (required after out-of-order `root_at` then
    /// `ingest_block`).
    fn record_drained_count(&mut self, through: u64, count: u64) {
        if let Some(i) = self
            .drained_through_counts
            .iter()
            .position(|(t, _)| *t == through)
        {
            self.drained_through_counts[i].1 = count;
            return;
        }
        let i = self
            .drained_through_counts
            .partition_point(|(t, _)| *t < through);
        self.drained_through_counts.insert(i, (through, count));
    }

    fn drained_leaf_count_at(&self, through: u64) -> u64 {
        if let Ok(i) = self
            .drained_through_counts
            .binary_search_by_key(&through, |(t, _)| *t)
        {
            return self.drained_through_counts[i].1;
        }
        self.drained_count_from_index(through)
    }

    /// Count leaves with `maturity <= through` via [`Self::entries_by_maturity`].
    fn drained_count_from_index(&self, through: u64) -> u64 {
        self.entries_by_maturity
            .range(..=through)
            .map(|(_, indices)| u64::try_from(indices.len()).expect("bucket fits u64"))
            .sum()
    }

    /// The drain cutoff for a reference height: a leaf maturing at `m`
    /// enters the tree on connection of the *next* block, so the root
    /// committed in the header at `reference_height` reflects every leaf
    /// matured through `reference_height - 1`
    /// (`drained_through = H - 1`, pinned by the CT-2 KAT). Height 0 has no
    /// predecessor and drains nothing.
    ///
    /// `pub(crate)` so the sibling `assemble` module shares the one
    /// reference-height → drain-cutoff mapping.
    #[must_use]
    pub(crate) fn drained_through(reference_height: u64) -> u64 {
        reference_height.saturating_sub(1)
    }

    /// Reconstruct the curve-tree root via the persisted [`LeafStore`] hot path.
    ///
    /// The empty tree (no drained leaves) is the `selene_hash_init` sentinel,
    /// not `build_layers(&[])` (`CT2_DRAIN_ORDER.md` §5). Errors from the
    /// store propagate — there is no silent fallback to the replay oracle, so
    /// KATs and callers gate the CT-1 hot path rather than masking corruption.
    pub fn root_at(&mut self, reference_height: u64) -> Result<[u8; 32], ClientError> {
        self.sync_store_to(reference_height)?;
        let through = Self::drained_through(reference_height);
        let n = self.drained_leaf_count_at(through);
        self.store.root_at_count(n).map_err(ClientError::from)
    }

    /// Integrity gate (§3.3): the reconstructed root at `reference.height`
    /// must byte-equal the consensus header `curve_tree_root`. Returns
    /// [`ClientError::RootMismatch`] otherwise — the wallet refuses to
    /// build a proof against a tree it cannot reproduce.
    pub fn verify_root(&mut self, reference: &ReferenceBlock) -> Result<(), ClientError> {
        let got = self.root_at(reference.height)?;
        if got == reference.curve_tree_root {
            Ok(())
        } else {
            Err(ClientError::RootMismatch {
                height: reference.height,
                expected: reference.curve_tree_root,
                got,
            })
        }
    }

    /// Number of leaves drained into the tree at `reference_height`.
    #[must_use]
    pub fn drained_leaf_count(&self, reference_height: u64) -> usize {
        usize::try_from(self.drained_leaf_count_at(Self::drained_through(reference_height)))
            .expect("drained leaf count fits usize")
    }
}

impl From<StoreError> for ClientError {
    fn from(err: StoreError) -> Self {
        Self::Store(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_fcmp::tree::selene_hash_init;
    use shekyl_oxide::COINBASE_LOCK_WINDOW;

    /// Standard Ed25519 basepoint, compressed — a valid, torsion-free
    /// point `construct_leaf` accepts for both `O` and `C`.
    const ED25519_BASEPOINT: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ];

    fn coinbase_raw() -> RawOutput {
        RawOutput {
            output_key: ED25519_BASEPOINT,
            commitment: Some(ED25519_BASEPOINT),
            target: TargetKind::TaggedKey,
        }
    }

    /// One coinbase tx carrying a per-output `0x07` hash blob of `n` × 32
    /// bytes (one well-formed hash per output, as a V3 chain always emits).
    fn coinbase_block<'a>(outputs: &'a [RawOutput], blob: &'a [u8]) -> Vec<TxLeafInputs<'a>> {
        vec![TxLeafInputs {
            is_miner: true,
            leaf_hash_blob: Some(blob),
            outputs,
        }]
    }

    #[test]
    fn empty_client_root_is_empty_tree() {
        let mut client = CurveTreeClient::new();
        assert_eq!(client.root_at(0).unwrap(), selene_hash_init());
        assert_eq!(client.root_at(1000).unwrap(), selene_hash_init());
        assert_eq!(client.drained_leaf_count(1000), 0);
    }

    #[test]
    fn duplicate_drained_through_updates_cache_in_place() {
        let outs = [coinbase_raw()];
        let blob = [0x07u8; 32];
        let txs = coinbase_block(&outs, &blob);
        let mut client = CurveTreeClient::new();
        client
            .ingest_block(BlockLeaves {
                height: 0,
                txs: &txs,
            })
            .unwrap();
        client
            .ingest_block(BlockLeaves {
                height: 1,
                txs: &txs,
            })
            .unwrap();
        assert_eq!(client.drained_through_counts.len(), 1);
        assert_eq!(client.drained_through_counts[0].0, 0);
        assert_eq!(client.drained_leaf_count(1), client.drained_leaf_count(2));
    }

    #[test]
    fn drained_through_is_reference_minus_one() {
        assert_eq!(CurveTreeClient::drained_through(0), 0);
        assert_eq!(CurveTreeClient::drained_through(1), 0);
        assert_eq!(CurveTreeClient::drained_through(61), 60);
    }

    #[test]
    fn drained_leaf_count_sparse_cache_does_not_interpolate() {
        // `root_at` far ahead leaves a high cutoff in the cache; a later query
        // at an intermediate reference height must not reuse that entry's count.
        let outs = [coinbase_raw()];
        let blob = [0x07u8; 32];
        let txs0 = coinbase_block(&outs, &blob);
        let txs1 = coinbase_block(&outs, &blob);
        let mut client = CurveTreeClient::new();
        client
            .ingest_block(BlockLeaves {
                height: 0,
                txs: &txs0,
            })
            .unwrap();
        client
            .ingest_block(BlockLeaves {
                height: 1,
                txs: &txs1,
            })
            .unwrap();
        let _ = client.root_at(200).unwrap();
        assert_eq!(
            client.drained_leaf_count(61),
            1,
            "only the genesis coinbase has drained by height 61"
        );
        assert_eq!(client.drained_leaf_count(62), 2);
    }

    #[test]
    fn ingest_after_store_ahead_appends_retroactive_drains() {
        let outs = [coinbase_raw()];
        let blob = [0x07u8; 32];
        let txs0 = coinbase_block(&outs, &blob);
        let txs1 = coinbase_block(&outs, &blob);
        let mut client = CurveTreeClient::new();
        client
            .ingest_block(BlockLeaves {
                height: 0,
                txs: &txs0,
            })
            .unwrap();
        let _ = client.root_at(200).unwrap();
        assert_eq!(client.store.sync_tip_height().unwrap(), 200);
        assert_eq!(client.store.leaf_count().unwrap(), 1);
        client
            .ingest_block(BlockLeaves {
                height: 1,
                txs: &txs1,
            })
            .unwrap();
        assert_eq!(
            client.store.leaf_count().unwrap(),
            2,
            "second coinbase must append even though sync tip stayed at 200"
        );
        let mut oracle = CurveTreeClient::from_blocks(&[
            BlockLeaves {
                height: 0,
                txs: &txs0,
            },
            BlockLeaves {
                height: 1,
                txs: &txs1,
            },
        ])
        .unwrap();
        assert_eq!(client.root_at(200).unwrap(), oracle.root_at(200).unwrap());
        assert_eq!(client.drained_leaf_count(200), 2);
    }

    #[test]
    fn root_at_ahead_of_ingest_then_ingest_preserves_root() {
        let outs = [coinbase_raw()];
        let blob = [0x07u8; 32];
        let txs = coinbase_block(&outs, &blob);
        let mut client = CurveTreeClient::new();
        client
            .ingest_block(BlockLeaves {
                height: 0,
                txs: &txs,
            })
            .unwrap();
        let root61 = client.root_at(61).unwrap();
        client
            .ingest_block(BlockLeaves {
                height: 1,
                txs: &txs,
            })
            .unwrap();
        assert_eq!(client.root_at(61).unwrap(), root61);
        assert_eq!(client.drained_leaf_count(61), 1);
        for w in client.drained_through_counts.windows(2) {
            assert!(w[0].0 <= w[1].0, "drained_through cache must stay sorted");
        }
    }

    #[test]
    fn founder_coinbase_first_visible_at_height_61() {
        // Genesis coinbase at height 0 matures at +60 and drains at +61.
        let outs = [coinbase_raw()];
        let blob = [0x07u8; 32];
        let txs = coinbase_block(&outs, &blob);
        let blocks = [BlockLeaves {
            height: 0,
            txs: &txs,
        }];
        let mut client = CurveTreeClient::from_blocks(&blocks).unwrap();

        // Empty through the maturity height itself...
        assert_eq!(client.root_at(60).unwrap(), selene_hash_init());
        assert_eq!(client.drained_leaf_count(60), 0);
        // ...non-empty from the next block.
        assert_ne!(client.root_at(61).unwrap(), selene_hash_init());
        assert_eq!(client.drained_leaf_count(61), 1);
        assert_eq!(COINBASE_LOCK_WINDOW as u64, 60);
    }

    #[test]
    fn gindex_threads_across_blocks() {
        // Two single-coinbase blocks: gindex must advance 0 then 1.
        let outs = [coinbase_raw()];
        let blob = [0xAAu8; 32];
        let txs0 = coinbase_block(&outs, &blob);
        let txs1 = coinbase_block(&outs, &blob);
        let blocks = [
            BlockLeaves {
                height: 0,
                txs: &txs0,
            },
            BlockLeaves {
                height: 1,
                txs: &txs1,
            },
        ];
        let client = CurveTreeClient::from_blocks(&blocks).unwrap();
        assert_eq!(client.next_gindex, 2, "two coinbases consume indices 0,1");
        assert_eq!(client.entries.len(), 2);
        assert_eq!(client.entries[0].gindex, 0);
        assert_eq!(client.entries[1].gindex, 1);
    }

    #[test]
    fn ingest_resolves_h_pqc_from_blob() {
        // The blob's per-output hash must land in the leaf's 4th scalar.
        let outs = [coinbase_raw()];
        let blob = [0x42u8; 32];
        let txs = coinbase_block(&outs, &blob);
        let mut client = CurveTreeClient::new();
        client
            .ingest_block(BlockLeaves {
                height: 0,
                txs: &txs,
            })
            .unwrap();
        assert_eq!(client.entries.len(), 1);
        assert_eq!(&client.entries[0].leaf[96..128], &[0x42u8; 32]);
    }

    #[test]
    fn other_target_consumes_index_but_is_not_a_leaf() {
        // [Other, valid]: the Other output advances gindex but is no leaf.
        let mut other = coinbase_raw();
        other.target = TargetKind::Other;
        let outs = [other, coinbase_raw()];
        let blob = [0x01u8; 64]; // one hash per vout
        let txs = coinbase_block(&outs, &blob);
        let client = CurveTreeClient::from_blocks(&[BlockLeaves {
            height: 0,
            txs: &txs,
        }])
        .unwrap();
        assert_eq!(client.next_gindex, 2, "both vouts consume an index");
        assert_eq!(client.entries.len(), 1, "only the valid output is a leaf");
        assert_eq!(client.entries[0].gindex, 1);
    }

    #[test]
    fn reorg_is_rebuild_from_post_reorg_chain() {
        // Derive-don't-accumulate: a client built from chain [0,1] then
        // rebuilt from a shorter chain [0] equals a fresh client from [0].
        let outs = [coinbase_raw()];
        let blob = [0x09u8; 32];
        let txs0 = coinbase_block(&outs, &blob);
        let txs1 = coinbase_block(&outs, &blob);

        let long = CurveTreeClient::from_blocks(&[
            BlockLeaves {
                height: 0,
                txs: &txs0,
            },
            BlockLeaves {
                height: 1,
                txs: &txs1,
            },
        ])
        .unwrap();
        let _ = long; // the long chain is what a reorg pops back from.

        let mut rebuilt = CurveTreeClient::from_blocks(&[BlockLeaves {
            height: 0,
            txs: &txs0,
        }])
        .unwrap();
        let mut fresh = {
            let mut c = CurveTreeClient::new();
            c.ingest_block(BlockLeaves {
                height: 0,
                txs: &txs0,
            })
            .unwrap();
            c
        };
        assert_eq!(rebuilt.next_gindex, fresh.next_gindex);
        assert_eq!(rebuilt.entries, fresh.entries);
        // Roots agree at every height the shorter chain covers.
        for h in 0..=200u64 {
            assert_eq!(
                rebuilt.root_at(h).unwrap(),
                fresh.root_at(h).unwrap(),
                "height {h}"
            );
        }
    }

    #[test]
    fn verify_root_accepts_match_and_rejects_mismatch() {
        let outs = [coinbase_raw()];
        let blob = [0x07u8; 32];
        let txs = coinbase_block(&outs, &blob);
        let mut client = CurveTreeClient::from_blocks(&[BlockLeaves {
            height: 0,
            txs: &txs,
        }])
        .unwrap();

        // The reconstructed root at height 61 is the consensus value.
        let good = ReferenceBlock {
            height: 61,
            curve_tree_root: client.root_at(61).unwrap(),
        };
        assert!(client.verify_root(&good).is_ok());

        let bad = ReferenceBlock {
            height: 61,
            curve_tree_root: [0xFFu8; 32],
        };
        match client.verify_root(&bad) {
            Err(ClientError::RootMismatch {
                height,
                expected,
                got,
            }) => {
                assert_eq!(height, 61);
                assert_eq!(expected, [0xFFu8; 32]);
                assert_eq!(got, client.root_at(61).unwrap());
            }
            other => panic!("expected RootMismatch, got {other:?}"),
        }
    }
}
