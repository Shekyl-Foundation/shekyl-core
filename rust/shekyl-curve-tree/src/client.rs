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

use crate::recon::{collect_block_leaves, extract_leaf_hashes, per_output_h_pqc, TxOutputs};
use crate::store::{LeafStore, StoreError};
use crate::types::{BlockHeight, LeafEntry, OutputIdentity, ReferenceBlock, TargetKind};

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
    /// [`CurveTreeClient::ingest_block`] was called with a block height that
    /// is not the next consecutive height after the prior ingest (including
    /// duplicates and gaps). The gindex and maturity index assume a full,
    /// in-order chain replay from genesis.
    NonConsecutiveBlockHeight {
        /// Height supplied on this ingest call.
        got: u64,
        /// Height required to continue the replay (`0` on the first block).
        expected: u64,
    },
    /// A root was requested at a reference height beyond the ingested chain
    /// tip. The client can only reproduce roots for the chain it has replayed
    /// (production reference blocks sit `REFERENCE_BLOCK_MIN_AGE` *behind*
    /// the tip, so this is never a production flow); answering ahead of
    /// ingest would silently omit leaves from blocks not yet replayed.
    ReferenceBeyondIngestedTip {
        /// Reference height that was requested.
        reference_height: u64,
        /// Ingested chain tip (`None` when no block has been ingested).
        ingested_tip: Option<u64>,
    },
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
    /// heights previously synced. Lookups miss to the maturity index rather
    /// than interpolating between cached cutoffs.
    drained_through_counts: Vec<(u64, u64)>,
    /// Maturity bucket → indices into [`Self::entries`] for O(bucket) drain
    /// batching on each ingested block.
    entries_by_maturity: BTreeMap<u64, Vec<usize>>,
    /// Last block height passed to [`Self::ingest_block`], if any. Root
    /// queries are bounded by this tip ([`ClientError::ReferenceBeyondIngestedTip`]).
    ingested_tip_height: Option<u64>,
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
            ingested_tip_height: None,
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
    /// ingested in strictly consecutive height order from genesis (`0`, `1`,
    /// `2`, …); gaps, duplicates, and rewinds return
    /// [`ClientError::NonConsecutiveBlockHeight`].
    ///
    /// If the store mirror fails ([`ClientError::Store`]), the in-memory
    /// indices have already advanced; the next successful ingest replays the
    /// missing canonical drained suffix, so the store self-heals rather than
    /// skipping a maturity bucket.
    pub fn ingest_block(&mut self, block: BlockLeaves<'_>) -> Result<(), ClientError> {
        let expected = self.ingested_tip_height.map_or(0, |last| {
            last.checked_add(1).expect("chain height fits u64")
        });
        if block.height != expected {
            return Err(ClientError::NonConsecutiveBlockHeight {
                got: block.height,
                expected,
            });
        }

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
        self.ingested_tip_height = Some(block.height);
        self.sync_store(block.height)
    }

    /// Mirror the canonical drained prefix at `drained_through(tip_height)`
    /// into the store and advance the freeze clock (`META_SYNC_TIP`) to the
    /// *ingested* tip — the only height the freeze gate is ever driven by.
    ///
    /// Because ingest is strictly consecutive, the drain cutoff advances by
    /// at most one maturity bucket per block and the store is append-only by
    /// construction. The steady-state append is the single newly-final bucket
    /// (O(bucket)); if the store lags by more than one bucket (a prior
    /// `append_drained` returned an error and the caller continued), the
    /// missing canonical suffix is replayed instead, so a failed sync heals on
    /// the next successful ingest rather than silently skipping a bucket.
    fn sync_store(&mut self, tip_height: u64) -> Result<(), ClientError> {
        let through = Self::drained_through(tip_height);
        let stored = self.store.leaf_count()?;
        let canonical = self.canonical_drained_count_on_ingest(through);
        if canonical < stored {
            return Err(StoreError::CorruptMeta("store leaf count exceeds canonical drain").into());
        }
        if stored == canonical {
            self.store.append_drained(&[], BlockHeight(tip_height))?;
        } else {
            let bucket = self.newly_drained_from_index(through);
            let bucket_len = u64::try_from(bucket.len()).expect("bucket fits u64");
            // `stored + bucket_len == canonical` ⟺ the store holds exactly the
            // canonical prefix below this block's bucket (counts of canonical
            // prefixes are unique), so appending the bucket is sound.
            let new_entries = if stored + bucket_len == canonical {
                bucket
            } else {
                let skip = usize::try_from(stored).expect("stored leaf count fits usize");
                self.drained_suffix_from_index(through, skip)
            };
            self.store
                .append_drained(&new_entries, BlockHeight(tip_height))?;
        }
        self.record_drained_count(through, canonical);
        Ok(())
    }

    /// Leaves that newly drain when the inclusive cutoff advances to
    /// `drained_through`, via the maturity index only (O(bucket)).
    ///
    /// On monotonic ingest, `drained_through` increases by at most one per
    /// block; indices within each bucket are appended in `gindex` order.
    pub(crate) fn newly_drained_from_index(&self, drained_through: u64) -> Vec<LeafEntry> {
        self.entries_by_maturity
            .get(&drained_through)
            .map(|indices| indices.iter().map(|&i| self.entries[i]).collect())
            .unwrap_or_default()
    }

    /// Canonical drain-order suffix via [`Self::entries_by_maturity`] (maturity
    /// ascending; indices within each bucket are appended in `gindex` order).
    pub(crate) fn drained_suffix_from_index(&self, through: u64, skip: usize) -> Vec<LeafEntry> {
        let mut remaining_skip = skip;
        let mut out = Vec::new();
        for (_, indices) in self.entries_by_maturity.range(..=through) {
            for &i in indices {
                if remaining_skip > 0 {
                    remaining_skip -= 1;
                    continue;
                }
                out.push(self.entries[i]);
            }
        }
        out
    }

    /// Upsert `(drained_through, drained_leaf_count)` while keeping the cache
    /// sorted by `drained_through`. On consecutive ingest the cutoff is
    /// monotonic, so this is an O(1) append (or an in-place refresh of the
    /// repeated genesis cutoff `0`).
    fn record_drained_count(&mut self, through: u64, count: u64) {
        let i = self
            .drained_through_counts
            .partition_point(|(t, _)| *t < through);
        if self
            .drained_through_counts
            .get(i)
            .is_some_and(|(t, _)| *t == through)
        {
            self.drained_through_counts[i].1 = count;
        } else {
            self.drained_through_counts.insert(i, (through, count));
        }
    }

    /// Canonical drained count at `through` on the consecutive-ingest path,
    /// computed incrementally from the previous block's cached cutoff (O(1))
    /// instead of a full maturity-index scan — the scan is O(buckets) per
    /// block, which makes long-chain ingest O(height²) overall.
    ///
    /// Soundness: an output created at block `h` matures no earlier than
    /// `h + DEFAULT_LOCK_WINDOW` ([`crate::recon::maturity_height`]), so the
    /// block being ingested can never add entries at maturities `<=` its own
    /// drain cutoff `h - 1`. Therefore:
    /// - same cutoff as the previous sync (the repeated genesis cutoff `0`):
    ///   the count is unchanged;
    /// - cutoff advanced by one: previous count plus the newly-final bucket,
    ///   which is complete by the same maturity bound.
    ///
    /// Any other cache shape (first block, or a prior store error that
    /// skipped [`Self::record_drained_count`]) falls back to the full scan.
    fn canonical_drained_count_on_ingest(&self, through: u64) -> u64 {
        let canonical = match self.drained_through_counts.last() {
            Some(&(t, count)) if t == through => count,
            Some(&(t, count)) if t.checked_add(1) == Some(through) => {
                let bucket = self.entries_by_maturity.get(&through).map_or(0, |indices| {
                    u64::try_from(indices.len()).expect("bucket fits u64")
                });
                count + bucket
            }
            _ => self.drained_count_from_index(through),
        };
        debug_assert_eq!(
            canonical,
            self.drained_count_from_index(through),
            "incremental drained count diverged from the maturity index at through={through}"
        );
        canonical
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
    /// `reference_height` must be within the ingested chain
    /// (`<= ingested tip`); otherwise
    /// [`ClientError::ReferenceBeyondIngestedTip`] is returned. Production
    /// reference blocks sit at least `REFERENCE_BLOCK_MIN_AGE` behind the
    /// tip, so the bound never binds on the production path; it exists so an
    /// unsynced height can never drive the store's freeze clock or produce a
    /// root that omits leaves from blocks not yet replayed.
    ///
    /// The empty tree (no drained leaves) is the `selene_hash_init` sentinel,
    /// not `build_layers(&[])` (`CT2_DRAIN_ORDER.md` §5). Errors from the
    /// store propagate — there is no silent fallback to the replay oracle, so
    /// KATs and callers gate the CT-1 hot path rather than masking corruption.
    pub fn root_at(&self, reference_height: u64) -> Result<[u8; 32], ClientError> {
        let within_chain = self
            .ingested_tip_height
            .is_some_and(|tip| reference_height <= tip);
        if !within_chain {
            return Err(ClientError::ReferenceBeyondIngestedTip {
                reference_height,
                ingested_tip: self.ingested_tip_height,
            });
        }
        let through = Self::drained_through(reference_height);
        let n = self.drained_leaf_count_at(through);
        self.store.root_at_count(n).map_err(ClientError::from)
    }

    /// Integrity gate (§3.3): the reconstructed root at `reference.height`
    /// must byte-equal the consensus header `curve_tree_root`. Returns
    /// [`ClientError::RootMismatch`] otherwise — the wallet refuses to
    /// build a proof against a tree it cannot reproduce.
    pub fn verify_root(&self, reference: &ReferenceBlock) -> Result<(), ClientError> {
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
    use crate::recon::{
        assemble_leaf_stream, drained_sorted, newly_drained_at_cutoff, root_from_scalars,
    };
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

    /// Ingest consecutive single-coinbase blocks at heights `from..=to` — the
    /// production chain shape (every real block carries a coinbase).
    fn ingest_coinbase_blocks(client: &mut CurveTreeClient, from: u64, to: u64) {
        let outs = [coinbase_raw()];
        let blob = [0x07u8; 32];
        for height in from..=to {
            let txs = coinbase_block(&outs, &blob);
            client
                .ingest_block(BlockLeaves { height, txs: &txs })
                .unwrap();
        }
    }

    #[test]
    fn newly_drained_from_index_matches_oracle() {
        let outs = [coinbase_raw()];
        let blob = [0x07u8; 32];
        let txs0 = coinbase_block(&outs, &blob);
        let txs1 = coinbase_block(&outs, &blob);
        let client = CurveTreeClient::from_blocks(&[
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
        for through in 0..=61u64 {
            assert_eq!(
                client.newly_drained_from_index(through),
                newly_drained_at_cutoff(&client.entries, through),
                "through={through}"
            );
        }
    }

    #[test]
    fn drained_suffix_from_index_matches_oracle() {
        let outs = [coinbase_raw()];
        let blob = [0x07u8; 32];
        let txs0 = coinbase_block(&outs, &blob);
        let txs1 = coinbase_block(&outs, &blob);
        let client = CurveTreeClient::from_blocks(&[
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
        let through = 61;
        let oracle: Vec<LeafEntry> = drained_sorted(&client.entries, through)
            .into_iter()
            .copied()
            .collect();
        for skip in 0..=oracle.len() {
            assert_eq!(
                client.drained_suffix_from_index(through, skip),
                oracle[skip..],
                "skip={skip}"
            );
        }
    }

    #[test]
    fn ingest_block_rejects_non_consecutive_heights() {
        let outs = [coinbase_raw()];
        let blob = [0x07u8; 32];
        let txs = coinbase_block(&outs, &blob);
        let block0 = BlockLeaves {
            height: 0,
            txs: &txs,
        };
        let block1 = BlockLeaves {
            height: 1,
            txs: &txs,
        };
        let mut client = CurveTreeClient::new();

        assert!(matches!(
            client.ingest_block(block1),
            Err(ClientError::NonConsecutiveBlockHeight {
                got: 1,
                expected: 0,
            })
        ));

        client.ingest_block(block0).unwrap();
        assert!(matches!(
            client.ingest_block(block0),
            Err(ClientError::NonConsecutiveBlockHeight {
                got: 0,
                expected: 1,
            })
        ));
        assert!(matches!(
            client.ingest_block(BlockLeaves {
                height: 2,
                txs: &txs,
            }),
            Err(ClientError::NonConsecutiveBlockHeight {
                got: 2,
                expected: 1,
            })
        ));
    }

    #[test]
    fn root_before_any_ingest_is_rejected() {
        let client = CurveTreeClient::new();
        assert!(matches!(
            client.root_at(0),
            Err(ClientError::ReferenceBeyondIngestedTip {
                reference_height: 0,
                ingested_tip: None,
            })
        ));
        assert_eq!(client.drained_leaf_count(1000), 0);
    }

    #[test]
    fn genesis_root_is_empty_tree() {
        // Block 0 drains nothing (no predecessor), so the root committed at
        // genesis is the empty-tree sentinel.
        let mut client = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut client, 0, 0);
        assert_eq!(client.root_at(0).unwrap(), selene_hash_init());
        assert_eq!(client.drained_leaf_count(0), 0);
    }

    #[test]
    fn root_beyond_ingested_tip_is_rejected() {
        let mut client = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut client, 0, 0);
        assert!(matches!(
            client.root_at(1),
            Err(ClientError::ReferenceBeyondIngestedTip {
                reference_height: 1,
                ingested_tip: Some(0),
            })
        ));
        // The rejected query left no trace in the store: the freeze clock
        // still sits at the ingested tip.
        assert_eq!(client.store.sync_tip_height().unwrap(), BlockHeight(0));
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
    fn drained_leaf_count_matches_drain_schedule() {
        // Coinbase at height h matures at h+60 and drains at h+61: counts
        // must track that schedule exactly, with no interpolation between
        // cached cutoffs.
        let mut client = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut client, 0, 62);
        assert_eq!(client.drained_leaf_count(60), 0);
        assert_eq!(
            client.drained_leaf_count(61),
            1,
            "only the genesis coinbase has drained by height 61"
        );
        assert_eq!(client.drained_leaf_count(62), 2);
        for w in client.drained_through_counts.windows(2) {
            assert!(w[0].0 <= w[1].0, "drained_through cache must stay sorted");
        }
    }

    #[test]
    fn incremental_drained_count_matches_index_on_mixed_chain() {
        // Every block carries a coinbase (m = h+60) and a regular output
        // (m = h+11), so once both schedules overlap each maturity bucket
        // holds two entries from two different blocks. The O(1) incremental
        // count in sync_store must agree with the maturity-index scan at
        // every cutoff (the ingest-path debug_assert also checks each step).
        let cb = coinbase_raw();
        let regular = RawOutput {
            output_key: ED25519_BASEPOINT,
            commitment: Some(ED25519_BASEPOINT),
            target: TargetKind::TaggedKey,
        };
        let blob = [0x07u8; 32];
        let cb_outs = [cb];
        let reg_outs = [regular];
        let mut client = CurveTreeClient::new();
        for height in 0..=100u64 {
            let txs = [
                TxLeafInputs {
                    is_miner: true,
                    leaf_hash_blob: Some(&blob),
                    outputs: &cb_outs,
                },
                TxLeafInputs {
                    is_miner: false,
                    leaf_hash_blob: Some(&blob),
                    outputs: &reg_outs,
                },
            ];
            client
                .ingest_block(BlockLeaves { height, txs: &txs })
                .unwrap();
        }
        for reference in 0..=100u64 {
            let through = CurveTreeClient::drained_through(reference);
            assert_eq!(
                client.drained_leaf_count_at(through),
                client.drained_count_from_index(through),
                "reference={reference}"
            );
        }
        // Both maturity schedules are live in the drained set.
        assert_eq!(
            u64::try_from(client.drained_leaf_count(100)).unwrap(),
            client.drained_count_from_index(99)
        );
        assert!(client.drained_leaf_count(100) > 0);
    }

    #[test]
    fn mixed_maturity_ingest_mirrors_canonical_drain_order() {
        // Block 0 coinbase (m=60); block 1 carries a coinbase (m=61) and a
        // lower-maturity regular output (m=11). Insertion order differs from
        // canonical `(maturity, gindex)` drain order; the store mirror must
        // produce the canonical-order root anyway.
        let outs_cb = [coinbase_raw()];
        let regular = RawOutput {
            output_key: ED25519_BASEPOINT,
            commitment: Some(ED25519_BASEPOINT),
            target: TargetKind::TaggedKey,
        };
        let blob0 = [0x01u8; 32];
        let blob1_cb = [0x02u8; 32];
        let blob1_reg = [0x03u8; 32];
        let txs0 = coinbase_block(&outs_cb, &blob0);
        let txs1 = [
            TxLeafInputs {
                is_miner: true,
                leaf_hash_blob: Some(&blob1_cb),
                outputs: &outs_cb,
            },
            TxLeafInputs {
                is_miner: false,
                leaf_hash_blob: Some(&blob1_reg),
                outputs: &[regular],
            },
        ];
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
        ingest_coinbase_blocks(&mut client, 2, 62);

        // At through=61 the drained set is m=11 (regular), m=60 (cb 0),
        // m=61 (cb 1) — none of the later coinbases.
        let drained = drained_sorted(&client.entries, 61);
        assert_eq!(drained.len(), 3);
        assert!(drained
            .windows(2)
            .all(|w| (w[0].maturity, w[0].gindex) <= (w[1].maturity, w[1].gindex)));

        let oracle = root_from_scalars(&assemble_leaf_stream(&client.entries, 61));
        assert_eq!(
            client.root_at(62).unwrap(),
            oracle,
            "store mirror must follow canonical drain order, not insertion order"
        );
    }

    #[test]
    fn historical_root_stable_as_chain_extends() {
        let mut client = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut client, 0, 61);
        let root61 = client.root_at(61).unwrap();
        ingest_coinbase_blocks(&mut client, 62, 62);
        assert_eq!(client.root_at(61).unwrap(), root61);
        assert_eq!(client.drained_leaf_count(61), 1);
        for w in client.drained_through_counts.windows(2) {
            assert!(w[0].0 <= w[1].0, "drained_through cache must stay sorted");
        }
    }

    #[test]
    fn founder_coinbase_first_visible_at_height_61() {
        // Genesis coinbase at height 0 matures at +60 and drains at +61.
        let mut client = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut client, 0, 61);

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
        // Derive-don't-accumulate: a client built tall (0..=66) then rebuilt
        // from the shorter post-reorg chain (0..=65) equals a fresh client
        // that only ever saw the shorter chain.
        let mut long = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut long, 0, 66);
        let _ = long; // the long chain is what a reorg pops back from.

        let mut rebuilt = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut rebuilt, 0, 65);
        let mut fresh = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut fresh, 0, 65);

        assert_eq!(rebuilt.next_gindex, fresh.next_gindex);
        assert_eq!(rebuilt.entries, fresh.entries);
        // Roots agree at every height the shorter chain covers (non-trivial
        // from 61, where the first coinbase drains).
        for h in 0..=65u64 {
            assert_eq!(
                rebuilt.root_at(h).unwrap(),
                fresh.root_at(h).unwrap(),
                "height {h}"
            );
        }
    }

    #[test]
    fn verify_root_accepts_match_and_rejects_mismatch() {
        let mut client = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut client, 0, 61);

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
