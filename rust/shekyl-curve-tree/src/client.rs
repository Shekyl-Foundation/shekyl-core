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
//! `CT2_DRAIN_ORDER.md` §7.1). The production persistent reorg path uses
//! [`CurveTreeClient::rollback_to_fork`] to roll the store and in-memory
//! state back to the shared fork point, then resumes forward ingest from
//! `fork_height + 1`; [`CurveTreeClient::from_blocks`] remains the
//! ephemeral/KAT replay path.
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
use std::path::Path;

use crate::recon::{collect_block_leaves, extract_leaf_hashes, per_output_h_pqc, TxOutputs};
use crate::store::{LeafStore, StoreError};
use crate::types::{BlockHeight, Gindex, LeafEntry, OutputIdentity, ReferenceBlock, TargetKind};

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
    pub height: BlockHeight,
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
        height: BlockHeight,
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
        got: BlockHeight,
        /// Height required to continue the replay (`0` on the first block).
        expected: BlockHeight,
    },
    /// A root was requested at a reference height beyond the ingested chain
    /// tip. The client can only reproduce roots for the chain it has replayed
    /// (production reference blocks sit `REFERENCE_BLOCK_MIN_AGE` *behind*
    /// the tip, so this is never a production flow); answering ahead of
    /// ingest would silently omit leaves from blocks not yet replayed.
    ReferenceBeyondIngestedTip {
        /// Reference height that was requested.
        reference_height: BlockHeight,
        /// Ingested chain tip (`None` when no block has been ingested).
        ingested_tip: Option<BlockHeight>,
    },
    /// [`CurveTreeClient::open`] found a store whose drained tables have
    /// been pruned (`prune_frozen` dropped non-owned leaf bytes), so the
    /// in-memory entry vec cannot be rebuilt element-wise and every root
    /// query would silently undercount. Pruned-store resume is the F5
    /// store-backed-assembly work (rides the prune-policy item in
    /// `CT3_SYNC.md` §5); until that lands the V3.0 client never prunes,
    /// so this is unreachable through production writes — it fires only
    /// on a store produced by something other than this client. Reopen
    /// (replace this error with a store-backed resume path) when F5
    /// lands; until then loud refusal beats a wrong root.
    ResumeFromPrunedStore {
        /// Drained positions the store has assigned (`leaf_count`).
        stored: u64,
        /// Drained rows actually readable (post-prune survivors).
        readable: u64,
    },
    /// [`CurveTreeClient::open`] found a store whose readable drained rows
    /// *exceed* its own `leaf_count` metadata. Pruning can only remove
    /// readable rows (`readable < leaf_count`), so `readable > leaf_count`
    /// is a table/metadata disagreement no client write produces — store
    /// corruption, reported distinctly from the pruned shape so the
    /// diagnosis is not "pruned" when the store is actually corrupt.
    ResumeFromCorruptStore {
        /// Drained positions the `leaf_count` metadata claims.
        stored: u64,
        /// Drained rows actually readable (exceeds `stored` — the breach).
        readable: u64,
    },
    /// The client was poisoned by a [`CurveTreeClient::rollback_to_fork`]
    /// that committed the authoritative store rollback but then failed
    /// before the in-memory state was rebuilt (frozen-tail recheck or
    /// rebuild errored). Its in-memory leaves no longer match the store, so
    /// every load-bearing public method fails fast with this error rather
    /// than ingesting against stale memory or returning a stale root. The
    /// store on disk is authoritative at the fork height; recover by
    /// dropping this object and re-opening with [`CurveTreeClient::open`].
    Poisoned,
}

/// Block-derived curve-tree client with persistent [`LeafStore`] (CT-1).
///
/// Holds leaf candidates and writes block deltas (drained + pending) into
/// the store on each [`Self::ingest_block`]. The production wallet
/// constructs with [`Self::open`] (persistent store, resume from contents
/// — CT-3b); [`Self::from_blocks`] and [`Self::try_new`] + ingest cover
/// the ephemeral/replay shapes. Reconstruct/verify a root at a reference
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
    drained_through_counts: Vec<(BlockHeight, u64)>,
    /// Maturity bucket → indices into [`Self::entries`] for O(bucket) drain
    /// batching on each ingested block.
    entries_by_maturity: BTreeMap<BlockHeight, Vec<usize>>,
    /// Last block height passed to [`Self::ingest_block`], if any. Root
    /// queries are bounded by this tip ([`ClientError::ReferenceBeyondIngestedTip`]).
    ingested_tip_height: Option<BlockHeight>,
    /// Set when [`Self::rollback_to_fork`] commits the store rollback but
    /// fails before rebuilding in-memory state, leaving memory inconsistent
    /// with the authoritative store. While set, load-bearing public methods
    /// fail fast with [`ClientError::Poisoned`]; the only recovery is
    /// drop-and-reopen ([`Self::open`]). See the `rollback_to_fork` poison
    /// contract.
    poisoned: bool,
}

/// In-memory state reconstructed from a [`LeafStore`] snapshot.
struct RebuiltState {
    entries: Vec<LeafEntry>,
    next_gindex: u64,
    entries_by_maturity: BTreeMap<BlockHeight, Vec<usize>>,
    ingested_tip_height: Option<BlockHeight>,
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
            poisoned: false,
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

    /// Open (or create) a client backed by the persistent store at `path`
    /// and resume from its contents — **no genesis replay** (`CT3_SYNC.md`
    /// §3.1 / R1-Q2). The store's schema-version guard fires here
    /// ([`StoreError::SchemaVersionMismatch`] for CT-1/CT-2 and
    /// CT-3a-window stores; pre-genesis disposition is delete and
    /// re-sync). An empty store on disk is the restore-from-seed trivial
    /// case (F8): resume yields an empty client ready for genesis ingest.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ClientError> {
        let store = LeafStore::open(path).map_err(ClientError::from)?;
        Self::resume(store)
    }

    /// Rebuild the in-memory client state from a store's persisted tables.
    ///
    /// **Resume order invariant (B4):** the rebuilt [`Self::entries`] vec
    /// is element-wise identical to a continuous run's `entries` at the
    /// same tip. A continuous run appends in creation order, which is
    /// gindex-ascending (`collect_block_leaves` assigns gindex in block
    /// order; blocks are ingested in height order; gindex is monotone
    /// across blocks), so the union of the drained rows (tree-position
    /// order) and pending rows (gindex order) is merged into one
    /// gindex-sorted vec. `entries_by_maturity` is then built by scanning
    /// that vec in order, so each bucket's index list is gindex-ascending —
    /// matching fresh-build drain order within a maturity bucket.
    ///
    /// `next_gindex = max(persisted gindex) + 1` (0 when empty) is
    /// absolute-exact on any chain whose root the wallet can verify:
    /// consensus admits only tagged-key and staked-key outputs (both
    /// leaf-eligible) and every output carries a commitment slot, so
    /// gindex is dense over leaves. For the defensively-mirrored
    /// leaf-ineligible class (unreachable on a consensus-valid block) the
    /// guarantee degrades to order-isomorphism with the consensus leaf
    /// index, which is the only property the `(maturity, gindex)` drain
    /// tiebreak consumes: a rewound counter still assigns above every
    /// persisted gindex, relative leaf order is preserved, and leaf bytes
    /// do not embed gindex, so drain order and roots are unchanged.
    /// Persisting the output-sequence cursor in store meta was considered
    /// and rejected — schema surface for consensus-unreachable state.
    /// **Reopening criterion:** a consensus change admitting an output
    /// type that is not leaf-eligible (i.e., the daemon's
    /// `check_output_types` accepted set grows beyond tagged/staked keys)
    /// makes gindex sparse over leaves; that change must land the cursor
    /// as a store-meta field written by `append_block_deltas`, as schema
    /// work with its own KAT, before any such block can be ingested.
    ///
    /// `drained_through_counts` is left empty: a resumed client rides the
    /// maturity-index-scan fallback ([`Self::drained_count_from_index`])
    /// for cutoffs at or below the resume tip — a small standing perf
    /// divergence from a continuous client, fine under the R1-Q6 V3.0
    /// memory model and exercised directly by the restart round-trip KAT.
    ///
    /// The resume tip is [`LeafStore::sync_tip_height`]; a store with no
    /// rows and tip 0 is indistinguishable from never-synced (the meta
    /// cell defaults to 0) and resumes as fresh (`ingested_tip_height =
    /// None`). On a real chain block 0's coinbase always contributes
    /// pending rows, so the ambiguity binds only on a synthetic empty
    /// block 0, where re-ingesting it is idempotent.
    ///
    /// Fails with [`ClientError::ResumeFromPrunedStore`] when drained rows
    /// have been pruned (`leaf_count` exceeds the readable rows): the
    /// in-memory vec would undercount and every root query would be
    /// silently wrong. Unreachable through this client's own writes (the
    /// V3.0 client never prunes); store-backed resume over pruned stores
    /// is the F5 work. The opposite imbalance — readable rows exceeding
    /// `leaf_count` — cannot arise from pruning and is reported distinctly
    /// as [`ClientError::ResumeFromCorruptStore`] so a corrupt store is
    /// not misdiagnosed as a pruned one.
    fn resume(store: LeafStore) -> Result<Self, ClientError> {
        let rebuilt = Self::rebuild_from_store(&store)?;

        Ok(Self {
            store,
            entries: rebuilt.entries,
            next_gindex: rebuilt.next_gindex,
            drained_through_counts: Vec::new(),
            entries_by_maturity: rebuilt.entries_by_maturity,
            ingested_tip_height: rebuilt.ingested_tip_height,
            poisoned: false,
        })
    }

    /// Rebuild the in-memory state from the store's drained and pending
    /// tables. Callers assign the returned state only after every check
    /// succeeds so stale memory is never partially overwritten on `Err`.
    fn rebuild_from_store(store: &LeafStore) -> Result<RebuiltState, ClientError> {
        let stored = store.leaf_count().map_err(ClientError::from)?;
        let drained = store.read_drained_entries().map_err(ClientError::from)?;
        let readable = u64::try_from(drained.len()).expect("drained row count fits u64");
        if readable < stored {
            // Pruning dropped frozen leaf bytes: the in-memory vec would
            // undercount and every root would be silently wrong (F5 work).
            return Err(ClientError::ResumeFromPrunedStore { stored, readable });
        }
        if readable > stored {
            // More readable rows than `leaf_count` claims — a direction
            // pruning cannot produce; the store is corrupt, not pruned.
            return Err(ClientError::ResumeFromCorruptStore { stored, readable });
        }
        let pending = store.read_pending_candidates().map_err(ClientError::from)?;
        let tip = store.sync_tip_height().map_err(ClientError::from)?;

        let mut entries: Vec<LeafEntry> = drained;
        entries.extend(pending);
        entries.sort_by_key(|entry| entry.gindex);
        for pair in entries.windows(2) {
            // A gindex lives in exactly one of {drained, pending}; a
            // duplicate across the union is store corruption, not a
            // mergeable state.
            if pair[1].gindex <= pair[0].gindex {
                return Err(StoreError::DuplicateGindex {
                    gindex: pair[1].gindex.0,
                }
                .into());
            }
        }

        let mut entries_by_maturity: BTreeMap<BlockHeight, Vec<usize>> = BTreeMap::new();
        for (i, entry) in entries.iter().enumerate() {
            entries_by_maturity
                .entry(entry.maturity)
                .or_default()
                .push(i);
        }
        let next_gindex = entries.last().map_or(0, |entry| {
            entry.gindex.0.checked_add(1).expect("gindex fits u64")
        });
        let ingested_tip_height = if entries.is_empty() && tip == BlockHeight(0) {
            None
        } else {
            Some(tip)
        };

        Ok(RebuiltState {
            entries,
            next_gindex,
            entries_by_maturity,
            ingested_tip_height,
        })
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

    /// Roll the persistent client back to `fork_height` (inclusive).
    ///
    /// The store-level operation is authoritative and single-transactional:
    /// it migrates drained-but-now-pending rows back into the pending table,
    /// drops orphaned rows, and resets the persisted tip to `fork_height`.
    /// In-memory state is rebuilt from that store snapshot and assigned only
    /// after rebuild succeeds, so no partial memory overwrite occurs on
    /// error.
    ///
    /// **Poison contract (CT-5), machine-enforced.** Failures *before* the
    /// store rollback commits (e.g. an above-tip request) leave both store
    /// and memory untouched and return `Err` with the client fully usable.
    /// Failures *after* the commit but before the in-memory rebuild
    /// completes (frozen-tail recheck or rebuild errors) leave the store
    /// authoritative at `fork_height` while memory is stale; the client
    /// marks itself [poisoned](ClientError::Poisoned) and every subsequent
    /// load-bearing public call ([`Self::ingest_block`], [`Self::root_at`],
    /// [`Self::verify_root`], and this method) fails fast with
    /// [`ClientError::Poisoned`]. The caller does not have to inspect which
    /// phase failed: a poisoned client is recovered only by dropping it and
    /// re-opening from the store ([`Self::open`]).
    pub fn rollback_to_fork(&mut self, fork_height: BlockHeight) -> Result<(), ClientError> {
        self.ensure_live()?;
        self.store
            .rollback_to_fork(fork_height)
            .map_err(ClientError::from)?;
        // Store rollback committed: it is now authoritative at `fork_height`
        // and in-memory state is stale. Any failure from here leaves the two
        // inconsistent, so poison first and clear only once the rebuild has
        // fully landed. The `?` early-returns below therefore leave the
        // client poisoned, which is the contract.
        self.poisoned = true;
        self.store.verify_frozen_tail().map_err(ClientError::from)?;
        let rebuilt = Self::rebuild_from_store(&self.store)?;
        self.entries = rebuilt.entries;
        self.next_gindex = rebuilt.next_gindex;
        self.drained_through_counts = Vec::new();
        self.entries_by_maturity = rebuilt.entries_by_maturity;
        self.ingested_tip_height = rebuilt.ingested_tip_height;
        self.poisoned = false;
        Ok(())
    }

    /// Fail fast if the client was poisoned by a partially-applied
    /// [`Self::rollback_to_fork`]. See that method's poison contract.
    fn ensure_live(&self) -> Result<(), ClientError> {
        if self.poisoned {
            return Err(ClientError::Poisoned);
        }
        Ok(())
    }

    /// Ingest one block, resolving `h_pqc` per output, threading the global
    /// output index, and accumulating drained-leaf entries. Blocks must be
    /// ingested in strictly consecutive height order from genesis (`0`, `1`,
    /// `2`, …); gaps, duplicates, and rewinds return
    /// [`ClientError::NonConsecutiveBlockHeight`].
    ///
    /// **Store-write-before-commit (B5).** The block's full delta — newly
    /// drained bucket, newly created pending leaves, drained pending
    /// removals, tip advance — lands in one ACID
    /// [`LeafStore::append_block_deltas`] transaction *before* any
    /// in-memory state changes. On `Err` the client is unchanged on both
    /// sides and the same block can be re-ingested; on `Ok` the in-memory
    /// commit is infallible. The store can therefore never lag memory; the
    /// only residual asymmetry is store-*ahead*-of-memory for the instant
    /// between the commit and the in-memory update, which matters only if
    /// the process dies in that gap — where memory evaporates and resume
    /// re-derives from the store.
    pub fn ingest_block(&mut self, block: BlockLeaves<'_>) -> Result<(), ClientError> {
        self.ensure_live()?;
        let expected = self.ingested_tip_height.map_or(BlockHeight(0), |last| {
            BlockHeight(last.0.checked_add(1).expect("chain height fits u64"))
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

        // Collect this block's leaves into a local vec — `self.entries` is
        // untouched until the store transaction commits.
        let mut new_leaves: Vec<LeafEntry> = Vec::new();
        let next_gindex =
            collect_block_leaves(block.height.0, &txs, self.next_gindex, &mut new_leaves);

        // The bucket newly final at this block's cutoff, read from the
        // *existing* maturity index (a leaf created in this block can never
        // mature at `height - 1`: the minimum lock window is ≥ 10 blocks,
        // which also guarantees every drained leaf entered the pending
        // table when its creation block was ingested — so the removals
        // below are present by construction). Blocks 0 and 1 share cutoff
        // 0, whose bucket is empty for the same reason.
        let through = Self::drained_through(block.height);
        let drained = self.newly_drained_from_index(through);
        let removed: Vec<Gindex> = drained.iter().map(|entry| entry.gindex).collect();

        // One ACID transaction for the whole block delta; the freeze clock
        // (`META_SYNC_TIP`) advances to the ingested tip — the only height
        // the freeze gate is ever driven by. An all-empty delta still
        // advances the tip.
        self.store
            .append_block_deltas(&drained, &new_leaves, &removed, block.height)?;

        // Store committed — the in-memory commit below is infallible.
        let canonical = self.canonical_drained_count_on_ingest(through);
        let entry_base = self.entries.len();
        for (offset, entry) in new_leaves.iter().enumerate() {
            self.entries_by_maturity
                .entry(entry.maturity)
                .or_default()
                .push(entry_base + offset);
        }
        self.entries.extend(new_leaves);
        self.next_gindex = next_gindex;
        self.ingested_tip_height = Some(block.height);
        self.record_drained_count(through, canonical);
        Ok(())
    }

    /// Leaves that newly drain when the inclusive cutoff advances to
    /// `drained_through`, via the maturity index only (O(bucket)).
    ///
    /// On monotonic ingest, `drained_through` increases by at most one per
    /// block; indices within each bucket are appended in `gindex` order.
    pub(crate) fn newly_drained_from_index(&self, drained_through: BlockHeight) -> Vec<LeafEntry> {
        self.entries_by_maturity
            .get(&drained_through)
            .map(|indices| indices.iter().map(|&i| self.entries[i]).collect())
            .unwrap_or_default()
    }

    /// Upsert `(drained_through, drained_leaf_count)` while keeping the cache
    /// sorted by `drained_through`. On consecutive ingest the cutoff is
    /// monotonic, so this is an O(1) append (or an in-place refresh of the
    /// repeated genesis cutoff `0`).
    fn record_drained_count(&mut self, through: BlockHeight, count: u64) {
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
    /// Any other cache shape (first block, first post-resume block, or a
    /// prior store error that skipped [`Self::record_drained_count`])
    /// falls back to the full scan.
    fn canonical_drained_count_on_ingest(&self, through: BlockHeight) -> u64 {
        let canonical = match self.drained_through_counts.last() {
            Some(&(t, count)) if t == through => count,
            Some(&(t, count)) if t.0.checked_add(1) == Some(through.0) => {
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
            "incremental drained count diverged from the maturity index at through={}",
            through.0
        );
        canonical
    }

    fn drained_leaf_count_at(&self, through: BlockHeight) -> u64 {
        if let Ok(i) = self
            .drained_through_counts
            .binary_search_by_key(&through, |(t, _)| *t)
        {
            return self.drained_through_counts[i].1;
        }
        self.drained_count_from_index(through)
    }

    /// Count leaves with `maturity <= through` via [`Self::entries_by_maturity`].
    fn drained_count_from_index(&self, through: BlockHeight) -> u64 {
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
    pub(crate) fn drained_through(reference_height: BlockHeight) -> BlockHeight {
        BlockHeight(reference_height.0.saturating_sub(1))
    }

    /// The last block height passed to [`Self::ingest_block`] — or rebuilt by
    /// [`Self::rollback_to_fork`] / [`Self::resume`] — or `None` when the client
    /// is fresh (no blocks ingested).
    ///
    /// This is the **authoritative resume cursor** for a forward / backfill
    /// ingest driver: the next block to ingest is `tip + 1` (`BlockHeight(0)`
    /// when `None`), matching [`Self::ingest_block`]'s own consecutive-height
    /// expectation. The driver reads this cursor every iteration and holds **no**
    /// driver-local fetch-frontier of its own, so a reorg that rewinds the cursor
    /// (`rollback_to_fork` rebuilds it from the authoritative store) is observed
    /// on the next read and the driver resumes from the rebuilt tip. That is the
    /// cursor-driven resume the CT-5 design pins as forbidden-by-construction for
    /// counter-drift (`CT5_ENGINE_WIRING.md` §3.2.1 R3-Q6 / §3.2.1.1 D2); a
    /// driver that cached its own frontier would silently desync from the tree on
    /// a reorg into the backfilled range.
    ///
    /// Pure read of the in-memory cursor; it does **not** gate on the poison flag
    /// (contrast [`Self::root_at`]). A poisoned client's recovery is
    /// drop-and-reopen, which reloads this from the store, so the cursor a caller
    /// reads is always either the live tip or — post-recovery — the store's
    /// last-committed tip.
    #[must_use]
    pub fn ingested_tip_height(&self) -> Option<BlockHeight> {
        self.ingested_tip_height
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
    pub fn root_at(&self, reference_height: BlockHeight) -> Result<[u8; 32], ClientError> {
        self.ensure_live()?;
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
    pub fn drained_leaf_count(&self, reference_height: BlockHeight) -> usize {
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

    fn staked_raw(lock_blocks: u64) -> RawOutput {
        RawOutput {
            output_key: ED25519_BASEPOINT,
            commitment: Some(ED25519_BASEPOINT),
            target: TargetKind::StakedKey { lock_blocks },
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
                .ingest_block(BlockLeaves {
                    height: BlockHeight(height),
                    txs: &txs,
                })
                .unwrap();
        }
    }

    fn ingest_outputs_at(client: &mut CurveTreeClient, height: u64, outputs: &[RawOutput]) {
        let blob = vec![0x07u8; outputs.len() * 32];
        let txs = coinbase_block(outputs, &blob);
        client
            .ingest_block(BlockLeaves {
                height: BlockHeight(height),
                txs: &txs,
            })
            .unwrap();
    }

    fn ingest_class_b_fixture_prefix(client: &mut CurveTreeClient, tip: u64) {
        for height in 0..=tip {
            if height == 1 {
                let outputs = [coinbase_raw(), staked_raw(150_000)];
                ingest_outputs_at(client, height, &outputs);
            } else {
                let outputs = [coinbase_raw()];
                ingest_outputs_at(client, height, &outputs);
            }
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
                height: BlockHeight(0),
                txs: &txs0,
            },
            BlockLeaves {
                height: BlockHeight(1),
                txs: &txs1,
            },
        ])
        .unwrap();
        for through in 0..=61u64 {
            assert_eq!(
                client.newly_drained_from_index(BlockHeight(through)),
                newly_drained_at_cutoff(&client.entries, through),
                "through={through}"
            );
        }
    }

    #[test]
    fn ingest_block_rejects_non_consecutive_heights() {
        let outs = [coinbase_raw()];
        let blob = [0x07u8; 32];
        let txs = coinbase_block(&outs, &blob);
        let block0 = BlockLeaves {
            height: BlockHeight(0),
            txs: &txs,
        };
        let block1 = BlockLeaves {
            height: BlockHeight(1),
            txs: &txs,
        };
        let mut client = CurveTreeClient::new();

        assert!(matches!(
            client.ingest_block(block1),
            Err(ClientError::NonConsecutiveBlockHeight {
                got: BlockHeight(1),
                expected: BlockHeight(0),
            })
        ));

        client.ingest_block(block0).unwrap();
        assert!(matches!(
            client.ingest_block(block0),
            Err(ClientError::NonConsecutiveBlockHeight {
                got: BlockHeight(0),
                expected: BlockHeight(1),
            })
        ));
        assert!(matches!(
            client.ingest_block(BlockLeaves {
                height: BlockHeight(2),
                txs: &txs,
            }),
            Err(ClientError::NonConsecutiveBlockHeight {
                got: BlockHeight(2),
                expected: BlockHeight(1),
            })
        ));
    }

    #[test]
    fn root_before_any_ingest_is_rejected() {
        let client = CurveTreeClient::new();
        assert!(matches!(
            client.root_at(BlockHeight(0)),
            Err(ClientError::ReferenceBeyondIngestedTip {
                reference_height: BlockHeight(0),
                ingested_tip: None,
            })
        ));
        assert_eq!(client.drained_leaf_count(BlockHeight(1000)), 0);
    }

    #[test]
    fn genesis_root_is_empty_tree() {
        // Block 0 drains nothing (no predecessor), so the root committed at
        // genesis is the empty-tree sentinel.
        let mut client = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut client, 0, 0);
        assert_eq!(client.root_at(BlockHeight(0)).unwrap(), selene_hash_init());
        assert_eq!(client.drained_leaf_count(BlockHeight(0)), 0);
    }

    #[test]
    fn root_beyond_ingested_tip_is_rejected() {
        let mut client = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut client, 0, 0);
        assert!(matches!(
            client.root_at(BlockHeight(1)),
            Err(ClientError::ReferenceBeyondIngestedTip {
                reference_height: BlockHeight(1),
                ingested_tip: Some(BlockHeight(0)),
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
                height: BlockHeight(0),
                txs: &txs,
            })
            .unwrap();
        client
            .ingest_block(BlockLeaves {
                height: BlockHeight(1),
                txs: &txs,
            })
            .unwrap();
        assert_eq!(client.drained_through_counts.len(), 1);
        assert_eq!(client.drained_through_counts[0].0, BlockHeight(0));
        assert_eq!(
            client.drained_leaf_count(BlockHeight(1)),
            client.drained_leaf_count(BlockHeight(2))
        );
    }

    #[test]
    fn drained_through_is_reference_minus_one() {
        assert_eq!(
            CurveTreeClient::drained_through(BlockHeight(0)),
            BlockHeight(0)
        );
        assert_eq!(
            CurveTreeClient::drained_through(BlockHeight(1)),
            BlockHeight(0)
        );
        assert_eq!(
            CurveTreeClient::drained_through(BlockHeight(61)),
            BlockHeight(60)
        );
    }

    #[test]
    fn drained_leaf_count_matches_drain_schedule() {
        // Coinbase at height h matures at h+60 and drains at h+61: counts
        // must track that schedule exactly, with no interpolation between
        // cached cutoffs.
        let mut client = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut client, 0, 62);
        assert_eq!(client.drained_leaf_count(BlockHeight(60)), 0);
        assert_eq!(
            client.drained_leaf_count(BlockHeight(61)),
            1,
            "only the genesis coinbase has drained by height 61"
        );
        assert_eq!(client.drained_leaf_count(BlockHeight(62)), 2);
        for w in client.drained_through_counts.windows(2) {
            assert!(w[0].0 <= w[1].0, "drained_through cache must stay sorted");
        }
    }

    #[test]
    fn incremental_drained_count_matches_index_on_mixed_chain() {
        // Every block carries a coinbase (m = h+60) and a regular output
        // (m = h+11), so once both schedules overlap each maturity bucket
        // holds two entries from two different blocks. The O(1) incremental
        // count in ingest_block must agree with the maturity-index scan at
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
                .ingest_block(BlockLeaves {
                    height: BlockHeight(height),
                    txs: &txs,
                })
                .unwrap();
        }
        for reference in 0..=100u64 {
            let through = CurveTreeClient::drained_through(BlockHeight(reference));
            assert_eq!(
                client.drained_leaf_count_at(through),
                client.drained_count_from_index(through),
                "reference={reference}"
            );
        }
        // Both maturity schedules are live in the drained set.
        assert_eq!(
            u64::try_from(client.drained_leaf_count(BlockHeight(100))).unwrap(),
            client.drained_count_from_index(BlockHeight(99))
        );
        assert!(client.drained_leaf_count(BlockHeight(100)) > 0);
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
                height: BlockHeight(0),
                txs: &txs0,
            })
            .unwrap();
        client
            .ingest_block(BlockLeaves {
                height: BlockHeight(1),
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
            client.root_at(BlockHeight(62)).unwrap(),
            oracle,
            "store mirror must follow canonical drain order, not insertion order"
        );
    }

    #[test]
    fn historical_root_stable_as_chain_extends() {
        let mut client = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut client, 0, 61);
        let root61 = client.root_at(BlockHeight(61)).unwrap();
        ingest_coinbase_blocks(&mut client, 62, 62);
        assert_eq!(client.root_at(BlockHeight(61)).unwrap(), root61);
        assert_eq!(client.drained_leaf_count(BlockHeight(61)), 1);
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
        assert_eq!(client.root_at(BlockHeight(60)).unwrap(), selene_hash_init());
        assert_eq!(client.drained_leaf_count(BlockHeight(60)), 0);
        // ...non-empty from the next block.
        assert_ne!(client.root_at(BlockHeight(61)).unwrap(), selene_hash_init());
        assert_eq!(client.drained_leaf_count(BlockHeight(61)), 1);
        assert_eq!(COINBASE_LOCK_WINDOW as u64, 60);
    }

    #[test]
    fn gindex_threads_across_blocks() {
        // Two single-coinbase blocks: gindex must advance 0 then 1.
        // The blob lands verbatim as the leaf's 4th scalar and the store
        // validates pending rows at write time, so it must be canonical
        // (top bit clear keeps it below the Selene modulus).
        let outs = [coinbase_raw()];
        let blob = [0x2Au8; 32];
        let txs0 = coinbase_block(&outs, &blob);
        let txs1 = coinbase_block(&outs, &blob);
        let blocks = [
            BlockLeaves {
                height: BlockHeight(0),
                txs: &txs0,
            },
            BlockLeaves {
                height: BlockHeight(1),
                txs: &txs1,
            },
        ];
        let client = CurveTreeClient::from_blocks(&blocks).unwrap();
        assert_eq!(client.next_gindex, 2, "two coinbases consume indices 0,1");
        assert_eq!(client.entries.len(), 2);
        assert_eq!(client.entries[0].gindex, Gindex(0));
        assert_eq!(client.entries[1].gindex, Gindex(1));
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
                height: BlockHeight(0),
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
            height: BlockHeight(0),
            txs: &txs,
        }])
        .unwrap();
        assert_eq!(client.next_gindex, 2, "both vouts consume an index");
        assert_eq!(client.entries.len(), 1, "only the valid output is a leaf");
        assert_eq!(client.entries[0].gindex, Gindex(1));
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
                rebuilt.root_at(BlockHeight(h)).unwrap(),
                fresh.root_at(BlockHeight(h)).unwrap(),
                "height {h}"
            );
        }
    }

    #[test]
    fn rollback_to_fork_rebuilds_memory_and_resyncs() {
        let mut rolled = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut rolled, 0, 70);
        // Populate the cache before rollback; rollback must clear it rather
        // than preserving stale cutoff answers from the orphaned suffix.
        assert_eq!(rolled.drained_leaf_count(BlockHeight(70)), 10);
        assert!(!rolled.drained_through_counts.is_empty());

        rolled.rollback_to_fork(BlockHeight(65)).unwrap();
        assert_eq!(rolled.ingested_tip_height, Some(BlockHeight(65)));
        assert!(rolled.drained_through_counts.is_empty());
        assert_eq!(rolled.next_gindex, 66);
        assert_eq!(
            rolled.store.sync_tip_height().unwrap(),
            BlockHeight(65),
            "store tip is the rollback source of truth"
        );

        ingest_coinbase_blocks(&mut rolled, 66, 70);

        let mut fresh = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut fresh, 0, 70);
        assert_eq!(rolled.entries, fresh.entries);
        assert_eq!(rolled.next_gindex, fresh.next_gindex);
        assert_eq!(
            rolled.store.read_pending_candidates().unwrap(),
            fresh.store.read_pending_candidates().unwrap()
        );
        assert_eq!(
            rolled.store.leaf_count().unwrap(),
            fresh.store.leaf_count().unwrap()
        );
        for h in 0..=70u64 {
            assert_eq!(
                rolled.root_at(BlockHeight(h)).unwrap(),
                fresh.root_at(BlockHeight(h)).unwrap(),
                "height {h}"
            );
        }
    }

    #[test]
    fn rollback_to_fork_at_tip_is_client_noop() {
        let mut client = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut client, 0, 10);
        let entries = client.entries.clone();
        let next_gindex = client.next_gindex;
        let pending = client.store.read_pending_candidates().unwrap();

        client.rollback_to_fork(BlockHeight(10)).unwrap();
        assert_eq!(client.entries, entries);
        assert_eq!(client.next_gindex, next_gindex);
        assert_eq!(client.ingested_tip_height, Some(BlockHeight(10)));
        assert_eq!(client.store.read_pending_candidates().unwrap(), pending);
        assert!(client.drained_through_counts.is_empty());
    }

    #[test]
    fn rollback_to_fork_above_tip_is_invalid_and_leaves_memory() {
        let mut client = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut client, 0, 5);
        let entries = client.entries.clone();
        let next_gindex = client.next_gindex;

        let err = client.rollback_to_fork(BlockHeight(6)).unwrap_err();
        assert!(matches!(
            err,
            ClientError::Store(StoreError::InvalidRollback {
                fork_height: 6,
                sync_tip: 5,
            })
        ));
        assert_eq!(client.entries, entries);
        assert_eq!(client.next_gindex, next_gindex);
        assert_eq!(client.ingested_tip_height, Some(BlockHeight(5)));
        assert_eq!(client.store.sync_tip_height().unwrap(), BlockHeight(5));
        // The failure was before the store committed, so the client is not
        // poisoned: it stays fully usable.
        assert!(!client.poisoned);
        client.root_at(BlockHeight(5)).unwrap();
        client.rollback_to_fork(BlockHeight(3)).unwrap();
    }

    #[test]
    fn poisoned_client_fails_fast_on_load_bearing_methods() {
        // A post-commit rollback failure (frozen-tail recheck or rebuild)
        // sets the poison flag; simulate that terminal state directly and
        // assert every load-bearing public entry point refuses to proceed
        // rather than ingesting against stale memory or returning a stale
        // root. Recovery is drop-and-reopen, which this client cannot do.
        let mut client = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut client, 0, 5);
        client.poisoned = true;

        assert!(matches!(
            client.root_at(BlockHeight(5)),
            Err(ClientError::Poisoned)
        ));
        assert!(matches!(
            client.verify_root(&ReferenceBlock {
                height: BlockHeight(5),
                curve_tree_root: [0u8; 32],
                block_hash: [0u8; 32],
            }),
            Err(ClientError::Poisoned)
        ));
        assert!(matches!(
            client.rollback_to_fork(BlockHeight(3)),
            Err(ClientError::Poisoned)
        ));
        let block = BlockLeaves {
            height: BlockHeight(6),
            txs: &[],
        };
        assert!(matches!(
            client.ingest_block(block),
            Err(ClientError::Poisoned)
        ));
    }

    #[test]
    fn ingested_tip_height_getter_tracks_cursor() {
        // The public getter is the forward/backfill driver's resume substrate
        // (CT-5 §3.2.1.1 D2): None when fresh, the last ingested height after
        // ingest, and the *rebuilt* tip after a rollback — so a driver reading
        // it each iteration resumes from the tree, never from a stale local
        // counter.
        let mut client = CurveTreeClient::new();
        assert_eq!(client.ingested_tip_height(), None);

        // `ingest_coinbase_blocks(from, to)` is inclusive: heights 0..=5.
        ingest_coinbase_blocks(&mut client, 0, 5);
        assert_eq!(client.ingested_tip_height(), Some(BlockHeight(5)));

        client.rollback_to_fork(BlockHeight(2)).unwrap();
        assert_eq!(client.ingested_tip_height(), Some(BlockHeight(2)));
    }

    #[test]
    fn rollback_to_genesis_keeps_genesis_and_accepts_height_one() {
        let mut client = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut client, 0, 10);

        client.rollback_to_fork(BlockHeight(0)).unwrap();
        assert_eq!(client.entries.len(), 1);
        assert_eq!(client.entries[0].gindex, Gindex(0));
        assert_eq!(client.next_gindex, 1);
        assert_eq!(client.ingested_tip_height, Some(BlockHeight(0)));
        assert_eq!(
            client.store.read_pending_candidates().unwrap(),
            vec![client.entries[0]]
        );

        ingest_coinbase_blocks(&mut client, 1, 1);
        assert_eq!(client.ingested_tip_height, Some(BlockHeight(1)));
        assert_eq!(client.entries.len(), 2);
        assert_eq!(client.next_gindex, 2);
    }

    #[test]
    fn from_blocks_pending_matches_explicit_replay() {
        // CT-3c's fresh-build oracle is meaningful only because
        // from_blocks replays the same per-block delta path.
        let out0 = [coinbase_raw()];
        let blob0 = [0x07u8; 32];
        let txs0 = coinbase_block(&out0, &blob0);
        let out1 = [coinbase_raw(), staked_raw(1_000)];
        let blob1 = [0x07u8; 64];
        let txs1 = coinbase_block(&out1, &blob1);
        let blocks = [
            BlockLeaves {
                height: BlockHeight(0),
                txs: &txs0,
            },
            BlockLeaves {
                height: BlockHeight(1),
                txs: &txs1,
            },
        ];
        let from_blocks = CurveTreeClient::from_blocks(&blocks).unwrap();
        let mut explicit = CurveTreeClient::new();
        explicit.ingest_block(blocks[0]).unwrap();
        explicit.ingest_block(blocks[1]).unwrap();

        assert_eq!(
            from_blocks.store.read_pending_candidates().unwrap(),
            explicit.store.read_pending_candidates().unwrap()
        );
    }

    #[test]
    fn rollback_restores_pending_rows_for_redraining_and_long_maturity() {
        // Primary R1-Q3 gate: a class-(b) leaf created on the shared prefix
        // (height 5 coinbase, maturity 65) drains only on the orphaned
        // suffix block 66. Rollback to fork 65 must migrate it back to
        // pending so the new branch's block 66 drains the same row. The
        // height-1 staked output pins the never-draining long-maturity half
        // of the invariant: pending equality catches it even though no
        // practical root window can.
        let mut orphaned = CurveTreeClient::new();
        ingest_class_b_fixture_prefix(&mut orphaned, 66);
        assert!(
            orphaned
                .store
                .read_drained_entries()
                .unwrap()
                .iter()
                .any(|entry| entry.maturity == BlockHeight(65)),
            "orphaned suffix must drain the class-(b) witness"
        );

        orphaned.rollback_to_fork(BlockHeight(65)).unwrap();

        let mut fresh_prefix = CurveTreeClient::new();
        ingest_class_b_fixture_prefix(&mut fresh_prefix, 65);
        assert_eq!(
            orphaned.store.read_pending_candidates().unwrap(),
            fresh_prefix.store.read_pending_candidates().unwrap(),
            "post-rollback pending set must equal fresh shared-prefix replay"
        );
        assert!(
            orphaned
                .store
                .read_pending_candidates()
                .unwrap()
                .iter()
                .any(|entry| entry.maturity == BlockHeight(150_001)),
            "long-maturity staked row stays pending and directly compared"
        );

        let output = [coinbase_raw()];
        ingest_outputs_at(&mut orphaned, 66, &output);
        let mut fresh_redrain = CurveTreeClient::new();
        ingest_class_b_fixture_prefix(&mut fresh_redrain, 66);
        assert_eq!(
            orphaned.store.read_pending_candidates().unwrap(),
            fresh_redrain.store.read_pending_candidates().unwrap(),
            "pending set still matches after the class-(b) row re-drains"
        );
        assert_eq!(
            orphaned.store.read_drained_entries().unwrap(),
            fresh_redrain.store.read_drained_entries().unwrap(),
            "drain order corroborates the pending-set proof"
        );
        assert_eq!(
            orphaned.root_at(BlockHeight(66)).unwrap(),
            fresh_redrain.root_at(BlockHeight(66)).unwrap(),
            "root equality corroborates after re-drain"
        );
    }

    #[test]
    fn verify_root_accepts_match_and_rejects_mismatch() {
        let mut client = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut client, 0, 61);

        // The reconstructed root at height 61 is the consensus value.
        let good = ReferenceBlock {
            height: BlockHeight(61),
            curve_tree_root: client.root_at(BlockHeight(61)).unwrap(),
            block_hash: [0u8; 32],
        };
        assert!(client.verify_root(&good).is_ok());

        let bad = ReferenceBlock {
            height: BlockHeight(61),
            curve_tree_root: [0xFFu8; 32],
            block_hash: [0u8; 32],
        };
        match client.verify_root(&bad) {
            Err(ClientError::RootMismatch {
                height,
                expected,
                got,
            }) => {
                assert_eq!(height, BlockHeight(61));
                assert_eq!(expected, [0xFFu8; 32]);
                assert_eq!(got, client.root_at(BlockHeight(61)).unwrap());
            }
            other => panic!("expected RootMismatch, got {other:?}"),
        }
    }

    /// Unique on-disk path for file-backed open tests (stdlib only,
    /// mirroring the store test helper). The caller removes the file.
    fn temp_client_path(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "shekyl-curve-tree-client-{tag}-{}-{n}.redb",
            std::process::id()
        ))
    }

    /// Hand-built leaf entry with canonical leaf bytes (each 32-byte limb
    /// a small Selene scalar) distinguishable per gindex.
    fn store_entry(gindex: u64, maturity: u64, creation: u64) -> LeafEntry {
        let mut leaf = [0u8; 128];
        // Low-order little-endian bytes of the first limb: a small,
        // canonical Selene scalar unique per gindex.
        leaf[0..8].copy_from_slice(&(gindex + 1).to_le_bytes());
        LeafEntry {
            gindex: Gindex(gindex),
            maturity: BlockHeight(maturity),
            creation_height: BlockHeight(creation),
            leaf,
            identity: OutputIdentity {
                output_key: [1u8; 32],
                commitment: Some([2u8; 32]),
                h_pqc: [3u8; 32],
                target: TargetKind::TaggedKey,
            },
        }
    }

    #[test]
    fn delta_ingest_maintains_pending_table() {
        // The pending table tracks the undrained set exactly: every leaf
        // candidate enters it on its creation block's ingest and leaves it
        // on the ingest that drains its maturity bucket — keeping the
        // store's drained ∪ pending equal to the in-memory entries at
        // every step (the resume read path's source of truth).
        let mut client = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut client, 0, 61);

        let pending = client.store.read_pending_candidates().unwrap();
        let drained_count = usize::try_from(client.store.leaf_count().unwrap()).unwrap();
        assert_eq!(
            drained_count, 1,
            "only the genesis coinbase (m=60) drains by block 61"
        );
        assert_eq!(pending.len() + drained_count, client.entries.len());

        // Pending rows are exactly the undrained in-memory entries, in
        // gindex order (entries[0] drained; the rest are still locked).
        assert_eq!(pending, client.entries[1..]);
        assert_eq!(
            client.store.read_drained_entries().unwrap(),
            client.entries[..1]
        );
    }

    #[test]
    fn open_on_empty_store_resumes_as_fresh_client() {
        // F8 restore-from-seed trivial case: no store on disk -> empty
        // client ready for genesis ingest, indistinguishable from `new()`.
        let path = temp_client_path("open-empty");
        let mut client = CurveTreeClient::open(&path).unwrap();
        assert_eq!(client.ingested_tip_height, None);
        assert!(client.entries.is_empty());
        assert_eq!(client.next_gindex, 0);
        assert!(matches!(
            client.root_at(BlockHeight(0)),
            Err(ClientError::ReferenceBeyondIngestedTip {
                reference_height: BlockHeight(0),
                ingested_tip: None,
            })
        ));
        ingest_coinbase_blocks(&mut client, 0, 0);
        assert_eq!(client.root_at(BlockHeight(0)).unwrap(), selene_hash_init());
        drop(client);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn open_resumes_gindex_sorted_union_of_drained_and_pending() {
        // Resume order invariant (B4): the rebuilt `entries` vec is the
        // drained ∪ pending union sorted by gindex — the interleave is the
        // real shape (a long-lock output at a low gindex stays pending
        // while a later coinbase drains past it).
        let path = temp_client_path("open-roundtrip");
        let drained = [store_entry(0, 60, 0), store_entry(2, 61, 1)];
        let pending = [store_entry(1, 200, 0), store_entry(3, 150_000, 1)];
        {
            let store = LeafStore::open(&path).unwrap();
            store
                .append_block_deltas(&drained, &pending, &[], BlockHeight(70))
                .unwrap();
        }

        let client = CurveTreeClient::open(&path).unwrap();
        assert_eq!(
            client.entries,
            vec![drained[0], pending[0], drained[1], pending[1]],
            "entries must merge gindex-ascending, not table-grouped"
        );
        assert_eq!(client.next_gindex, 4);
        assert_eq!(client.ingested_tip_height, Some(BlockHeight(70)));
        assert!(client.drained_through_counts.is_empty());

        // Maturity index rebuilt from the sorted vec: cutoff 61 covers the
        // two drained rows; the pending maturities sit above it.
        assert_eq!(client.drained_leaf_count(BlockHeight(62)), 2);
        assert_eq!(client.drained_leaf_count(BlockHeight(0)), 0);

        // Root queries post-resume ride the maturity-index fallback and
        // must agree with the store's drained prefix.
        assert_eq!(
            client.root_at(BlockHeight(62)).unwrap(),
            client.store.root_at_count(2).unwrap()
        );
        drop(client);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn resume_rejects_duplicate_gindex_across_tables() {
        // A gindex lives in exactly one of {drained, pending}; the store's
        // collision check only guards the pending table against itself, so
        // a cross-table duplicate is constructible through the real write
        // path and must fail resume loudly.
        let store = LeafStore::open_ephemeral().unwrap();
        store
            .append_block_deltas(
                &[store_entry(0, 60, 0)],
                &[store_entry(0, 200, 0)],
                &[],
                BlockHeight(70),
            )
            .unwrap();
        let err = CurveTreeClient::resume(store).unwrap_err();
        assert!(
            matches!(
                err,
                ClientError::Store(StoreError::DuplicateGindex { gindex: 0 })
            ),
            "expected DuplicateGindex {{ gindex: 0 }} for cross-table gindex \
             duplicate, got {err:?}"
        );
    }

    #[test]
    fn resume_rejects_pruned_store() {
        // Pruned-store resume is F5 work; until it lands the client must
        // refuse rather than silently undercount. The pruned shape is
        // produced through the real path: freeze segment 0, prune it.
        let store = LeafStore::open_ephemeral().unwrap();
        let e = u64::try_from(crate::segment::leaves_per_segment()).expect("fits u64");
        let mut entries: Vec<LeafEntry> = (0..e).map(|i| store_entry(i, 50, 10)).collect();
        entries.push(store_entry(e, 5_000, 4_000));
        store.append_drained(&entries, BlockHeight(10_000)).unwrap();
        store.prune_frozen(&[]).unwrap();

        let err = CurveTreeClient::resume(store).unwrap_err();
        match err {
            ClientError::ResumeFromPrunedStore { stored, readable } => {
                assert_eq!(stored, e + 1);
                assert_eq!(readable, 1, "only the unfrozen tail row survives");
            }
            other => panic!("expected ResumeFromPrunedStore, got {other:?}"),
        }
    }

    #[test]
    fn restart_roundtrip_matches_continuous_run() {
        // The resume order invariant (B4) cashed end-to-end through the
        // production path: ingest, drop, reopen, keep ingesting. The
        // resumed client must be element-wise identical to one that never
        // restarted, and no block is replayed from genesis.
        let path = temp_client_path("restart-roundtrip");
        {
            let mut before = CurveTreeClient::open(&path).unwrap();
            ingest_coinbase_blocks(&mut before, 0, 70);
        }

        let mut resumed = CurveTreeClient::open(&path).unwrap();
        // Resume picks the persisted tip up directly: a genesis replay is
        // structurally rejected as a non-consecutive ingest.
        assert_eq!(resumed.ingested_tip_height, Some(BlockHeight(70)));
        let outs = [coinbase_raw()];
        let blob = [0x07u8; 32];
        let genesis_txs = coinbase_block(&outs, &blob);
        assert!(matches!(
            resumed.ingest_block(BlockLeaves {
                height: BlockHeight(0),
                txs: &genesis_txs,
            }),
            Err(ClientError::NonConsecutiveBlockHeight {
                got: BlockHeight(0),
                expected: BlockHeight(71),
            })
        ));
        ingest_coinbase_blocks(&mut resumed, 71, 140);

        let mut continuous = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut continuous, 0, 140);

        assert_eq!(
            resumed.entries, continuous.entries,
            "resumed entries must be element-wise identical to a continuous run"
        );
        assert_eq!(resumed.next_gindex, continuous.next_gindex);
        // Drain-order identity: the persisted drained prefix matches the
        // never-restarted run's byte-for-byte, in order.
        assert_eq!(
            resumed.store.read_drained_entries().unwrap(),
            continuous.store.read_drained_entries().unwrap()
        );
        for h in 0..=140u64 {
            assert_eq!(
                resumed.root_at(BlockHeight(h)).unwrap(),
                continuous.root_at(BlockHeight(h)).unwrap(),
                "height {h}"
            );
        }
        drop(resumed);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn staked_locks_drain_and_persist_across_restart() {
        // B3 split from the plan, both halves over one restart.
        //
        // (a) A synthetic 300-block stake lock — tractable in a test, same
        //     `StakedKey` code path as any consensus tier — must drain at
        //     the right height on the *resumed* client, identically to a
        //     run that never restarted.
        // (b) The adversarial 150_000-block stake must survive the same
        //     restart byte-correct in the pending table and never drain
        //     inside the window — asserted directly against the table, so
        //     a long-maturity resume bug cannot hide behind root checks
        //     that never reach its maturity.
        let path = temp_client_path("staked-restart");
        const SHORT_LOCK: u64 = 300;
        const LONG_LOCK: u64 = 150_000;
        let staked = |lock_blocks: u64| RawOutput {
            output_key: ED25519_BASEPOINT,
            commitment: Some(ED25519_BASEPOINT),
            target: TargetKind::StakedKey { lock_blocks },
        };
        let cb = [coinbase_raw()];
        let outs_short = [staked(SHORT_LOCK)];
        let outs_long = [staked(LONG_LOCK)];
        let blob_cb = [0x07u8; 32];
        let blob_short = [0x11u8; 32];
        let blob_long = [0x13u8; 32];
        let block0_txs = vec![
            TxLeafInputs {
                is_miner: true,
                leaf_hash_blob: Some(&blob_cb),
                outputs: &cb,
            },
            TxLeafInputs {
                is_miner: false,
                leaf_hash_blob: Some(&blob_short),
                outputs: &outs_short,
            },
            TxLeafInputs {
                is_miner: false,
                leaf_hash_blob: Some(&blob_long),
                outputs: &outs_long,
            },
        ];

        {
            let mut client = CurveTreeClient::open(&path).unwrap();
            client
                .ingest_block(BlockLeaves {
                    height: BlockHeight(0),
                    txs: &block0_txs,
                })
                .unwrap();
            // Stop inside the short stake's lock window (matures at 300,
            // drains at 301): the restart lands while both stakes pend.
            ingest_coinbase_blocks(&mut client, 1, 250);
        }

        let mut resumed = CurveTreeClient::open(&path).unwrap();

        // (b) pre-drive: the 150k stake came back byte-correct.
        let pending = resumed.store.read_pending_candidates().unwrap();
        let long_row = pending
            .iter()
            .find(|e| e.gindex == Gindex(2))
            .expect("150k stake pending after resume");
        assert_eq!(long_row.maturity, BlockHeight(LONG_LOCK));
        assert_eq!(long_row.creation_height, BlockHeight(0));
        assert_eq!(
            long_row.identity.target,
            TargetKind::StakedKey {
                lock_blocks: LONG_LOCK
            }
        );

        // (a) drive the resumed client past the short stake's drain
        // boundary and compare against a continuous run.
        ingest_coinbase_blocks(&mut resumed, 251, SHORT_LOCK + 1);
        let mut continuous = CurveTreeClient::new();
        continuous
            .ingest_block(BlockLeaves {
                height: BlockHeight(0),
                txs: &block0_txs,
            })
            .unwrap();
        ingest_coinbase_blocks(&mut continuous, 1, SHORT_LOCK + 1);

        assert_eq!(resumed.entries, continuous.entries);
        let drained = resumed.store.read_drained_entries().unwrap();
        assert_eq!(drained, continuous.store.read_drained_entries().unwrap());
        assert!(
            drained
                .iter()
                .any(|e| e.maturity == BlockHeight(SHORT_LOCK)),
            "short stake must drain at lock expiry on the resumed client"
        );
        assert_eq!(
            resumed.root_at(BlockHeight(SHORT_LOCK + 1)).unwrap(),
            continuous.root_at(BlockHeight(SHORT_LOCK + 1)).unwrap()
        );

        // (b) post-drive: the 150k stake never drained and still pends.
        assert!(drained.iter().all(|e| e.gindex != Gindex(2)));
        assert!(resumed
            .store
            .read_pending_candidates()
            .unwrap()
            .iter()
            .any(|e| e.gindex == Gindex(2)));
        drop(resumed);
        std::fs::remove_file(&path).unwrap();
    }
}
