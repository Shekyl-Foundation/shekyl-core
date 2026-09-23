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
use std::sync::Arc;

use crate::recon::{
    assemble_leaf_stream, collect_block_leaves, extract_leaf_commitments, root_from_scalars,
    TxOutputs,
};
use crate::store::{LeafStore, PostureDeclaration, SegmentPin, ServingReader, StoreError};
use crate::types::{
    BlockHeight, CommitmentBytes, CurveTreeRoot, Gindex, LeafEntry, OneTimePubkey, OutputIdentity,
    ReferenceBlock, TargetKind,
};

/// One output's leaf-relevant facts as decoded at the caller's boundary,
/// **before** `h_pqc` resolution. The client resolves `h_pqc` from the
/// transaction's `0x07` blob (recon-owned) and builds the full
/// [`OutputIdentity`] internally.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RawOutput {
    /// Compressed Ed25519 output public key (`O`).
    pub output_key: OneTimePubkey,
    /// Amount commitment (`C`); `None` when the output has no commitment
    /// slot (`i >= outPk.size()`), which makes it leaf-ineligible.
    pub commitment: Option<CommitmentBytes>,
    /// Output target kind (decides maturity and leaf candidacy).
    pub target: TargetKind,
}

/// One transaction's leaf inputs, in `vout` order. The `0x07` blob (one
/// 64-byte `CM ‖ record` entry per output, `PL-D3`) is the raw payload from
/// `shekyl_scanner::extra::Extra::pqc_leaf_entries()` (`None` when the tag is
/// absent); the client slices it, and refuses the block if it cannot.
#[derive(Clone, Copy, Debug)]
pub struct TxLeafInputs<'a> {
    /// Whether this is the block's coinbase (`is_miner`).
    pub is_miner: bool,
    /// Parsed `tx_extra 0x07` blob, or `None` if the tag is absent.
    pub leaf_entry_blob: Option<&'a [u8]>,
    /// Per-output identities in `vout` order, leaf commitment not yet resolved.
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
        expected: CurveTreeRoot,
        /// Root the client reconstructed from its leaves.
        got: CurveTreeRoot,
    },
    /// The requested output is not a drained leaf at the reference height,
    /// so no membership path exists for it there (the §4.3 lookup miss).
    OutputNotDrained {
        /// Global output index (the resolution key, X3) that matched no drained
        /// leaf at the reference height — the primary diagnostic for a numbering
        /// desync or a caller passing a not-yet-drained output.
        gindex: Gindex,
        /// Compressed output key the caller supplied alongside `gindex`.
        output_key: OneTimePubkey,
    },
    /// `gindex` resolved to a drained leaf whose `(output_key, commitment)`
    /// does not match the caller-supplied [`crate::AssembleInput`] (X3,
    /// CT-5c). The curve tree's `next_output_seq` numbering and the wallet's
    /// `TransferDetails.global_output_index` must be identical for `gindex`
    /// resolution to be sound; a mismatch means those numberings diverged
    /// (the classic cause: a new output class entering the tree shifted the
    /// count) or the store/scanner desynced. Refuse rather than assemble a
    /// wrong-leaf proof — DoS-never-theft, the only runtime guard of an
    /// inter-component invariant no single component owns.
    IdentityMismatch {
        /// Global output index whose resolved leaf failed the identity check.
        gindex: Gindex,
        /// Output key the caller expected at `gindex`.
        expected_output_key: OneTimePubkey,
        /// Output key actually found at `gindex` among the drained leaves.
        got_output_key: OneTimePubkey,
        /// Whether the resolved leaf's amount commitment matched the expected
        /// one. The check is on the full `(output_key, commitment)` pair, so
        /// this disambiguates a commitment-only divergence (keys match,
        /// commitment does not) from a wrong-leaf divergence — without widening
        /// the error enum past the `result_large_err` threshold with a fourth
        /// 32-byte field. The values themselves are recoverable from `gindex`.
        commitment_matched: bool,
    },
    /// A batch membership-assembly request carried more inputs than the FCMP++
    /// proof system permits per transaction (`shekyl_fcmp::MAX_INPUTS`). Raised
    /// at the engine's `AssembleTx` actor boundary before any path is assembled,
    /// so an over-length request cannot spin the single-writer actor in an
    /// unbounded loop (a self-inflicted DoS). The engine's output selection is
    /// independently bounded by the same limit, so this is a defense-in-depth
    /// backstop at the actor boundary, never a production path.
    TooManyInputs {
        /// Number of inputs supplied in the batch.
        got: usize,
        /// Maximum membership inputs per transaction.
        max: usize,
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
    /// A transaction's `tx_extra 0x07` payload could not be sliced into one
    /// leaf commitment per output. On an admitted chain this cannot happen
    /// (the shape and content rules refuse such a transaction at relay and
    /// connect), so it means the block feed handed the replica something the
    /// daemon never stored — refused, never zero-filled (`PL-D3`, census
    /// `d-3`).
    LeafEntries {
        /// Block height being ingested.
        height: BlockHeight,
        /// Transaction index within the block (coinbase is `0`).
        tx_index: usize,
        /// What was wrong with the payload.
        source: crate::recon::LeafEntryError,
    },
    /// An output's published point (`O`, `C`, or the `0x07` leaf commitment
    /// `CM`) failed Ed25519 decompression while building this block's
    /// leaves. The point-content twin of [`ClientError::LeafEntries`]: on an
    /// admitted chain the content rule refuses such a transaction, and the
    /// daemon **aborts** on the same input at store time (`DB_ERROR`,
    /// `src/blockchain_db/blockchain_db.cpp:617`) — both surfaces agree
    /// fail-closed, so the replica refuses the block rather than omitting
    /// the leaf and building a silently divergent tree.
    LeafPoint {
        /// Block height being ingested.
        height: BlockHeight,
        /// The offending output (by gindex) and the failing point.
        source: crate::recon::LeafPointError,
    },
}

impl ClientError {
    /// `true` iff this is a [`StoreError::is_already_open`] store failure: the
    /// redb single-writer lock is *transiently* held by a not-yet-dropped handle
    /// (the `close → reopen` / respawn race, where kameo drops the old client —
    /// and its lock — only after `wait_for_shutdown` resolves).
    ///
    /// The actor layer uses this to poll-retry **only** the transient case and
    /// surface every other open error immediately, rather than spinning a
    /// permanently-failing open out to the grace-window timeout.
    #[must_use]
    pub fn is_already_open(&self) -> bool {
        matches!(self, ClientError::Store(e) if e.is_already_open())
    }
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
    /// Behind an `Arc` so the read-only [`ServingReader`] can share the
    /// open database rather than opening a second one (redb takes an
    /// exclusive file lock, so a second open would simply be refused).
    /// The `Arc` leaves this client only as that read-only wrapper, or
    /// inside a [`WriterRecovery`] — so a fail-stop recovery does not open
    /// a second database beside a serving host that is still holding the
    /// first, and the read-only wrapper stays unable to mint a writer.
    store: Arc<LeafStore>,
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
    /// fail fast with [`ClientError::Poisoned`]; the only recovery is to
    /// drop this client and [`WriterRecovery::resume`] over the same store
    /// (or [`Self::open`] a path when nothing else holds it). See the
    /// `rollback_to_fork` poison contract.
    poisoned: bool,
}

/// The authority to rebuild the single writer over an already-open store —
/// the fail-stop recovery capability, separate from the serving read.
///
/// # Why this is not a [`ServingReader`]
///
/// Both wrap the same open database, and it is tempting to recover from the
/// reader the actor handle is already holding. That would make
/// [`ServingReader`] *write-minting*: it is `Clone`, and copies of it are
/// handed to the persona serving crates, which would then each be one call
/// away from a second, unsynchronized writer on a store whose single writer
/// is the whole point of the actor layer. The read-only guarantee
/// [`CurveTreeClient::serving_reader`] documents would become a convention.
///
/// So recovery is its own capability, and the boundary is **obtainability**:
/// the only way to get one is [`CurveTreeClient::writer_recovery`], which
/// needs a `&CurveTreeClient` — a thing no serving crate has or can build,
/// because nothing hands one out. `Clone` is deliberately left on: copying a
/// recovery mints no writer (only [`Self::resume`] does), so restricting it
/// would be ceremony rather than a guarantee, and the actor handle needs to
/// be `Clone` anyway.
///
/// # Why recovery does not reopen the path
///
/// [`CurveTreeClient::open`] opens a *new* database. Once a serving host
/// holds a [`ServingReader`] on the live one, a second open is redb's
/// `DatabaseAlreadyOpen` for the host's whole life — and if it ever did
/// succeed it would be a *different* store, so pins applied through the
/// recovered writer would not cover the bytes the host is serving. Recovery
/// therefore keeps the `Arc` and rebuilds only the in-memory writer state.
#[derive(Clone)]
pub struct WriterRecovery {
    store: Arc<LeafStore>,
}

impl WriterRecovery {
    /// Rebuild a write client over the held store.
    ///
    /// # Errors
    ///
    /// The same resume refusals `CurveTreeClient::open` surfaces
    /// ([`ClientError::ResumeFromPrunedStore`],
    /// [`ClientError::ResumeFromCorruptStore`], store I/O) — the store's
    /// contents are re-read, so a store that has become unreadable is
    /// reported here rather than at the next write.
    ///
    /// # One writer at a time — the caller's obligation, not this type's
    ///
    /// `resume` mints a writer; it does **not** retire the previous one. redb
    /// serializes the transactions themselves, so two live clients cannot
    /// corrupt the file — but they carry independent in-memory tree state, and
    /// the loser's view of the accumulator is wrong from the first write the
    /// winner makes. Retirement is the caller's to pay.
    ///
    /// Today's only production reach pays it: `CurveTreeHandle::respawn` kills
    /// the actor and awaits its shutdown — which drops the sole
    /// [`CurveTreeClient`], since the actor owns it — before resuming, and the
    /// single path that reaches `respawn` runs under the engine's per-refresh
    /// single-flight slot, so two respawns cannot interleave.
    ///
    /// That is a fact about callers, not a property of this function, and it is
    /// stated here because this is where the next caller will look. A second
    /// recovery path outside that slot must bring its own mutual exclusion.
    /// Enforcement was deliberately not put here: "the previous writer is gone"
    /// is a fact about a task's lifetime that this type cannot observe, so a
    /// flag maintained on this side would be asserting something it cannot
    /// check — and would fail open exactly when a task aborted, which is the
    /// case recovery exists for.
    pub fn resume(&self) -> Result<CurveTreeClient, ClientError> {
        CurveTreeClient::resume(Arc::clone(&self.store))
    }
}

impl std::fmt::Debug for WriterRecovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriterRecovery").finish_non_exhaustive()
    }
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
            store: Arc::new(LeafStore::open_ephemeral().map_err(ClientError::from)?),
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
        Self::resume(Arc::new(store))
    }

    /// A read-only handle on this client's store, for the persona serving
    /// loop (`ARCHIVAL_CHALLENGE_MECHANISM.md` §9.5 item 3).
    ///
    /// Serving reads run concurrently with block ingest — a shard body is
    /// held open for the seconds a 3.33 MB rendezvous transfer takes, and
    /// stalling ingest behind it is not an option. redb readers are MVCC
    /// snapshots, so that concurrency is free; what is *not* free is
    /// letting the serving side write, because this client is the single
    /// writer the actor layer serializes. [`ServingReader`] is how both
    /// hold true at once: same open database, no write reachable.
    #[must_use]
    pub fn serving_reader(&self) -> ServingReader {
        ServingReader::new(Arc::clone(&self.store))
    }

    /// Pin every member of a persona's serve-set so [`LeafStore::prune_frozen`]
    /// cannot discard bytes it is bonded to serve — the silent-slash hazard
    /// (`ARCHIVAL_CHALLENGE_MECHANISM.md` §9.6 item 4).
    ///
    /// **Reachable here rather than on the serving side**, even though it is
    /// the serving side that cares, because pinning is a store *write*: it
    /// must run on the object the actor owns, or it is a second writer
    /// beside the one whose message loop is the serialization. The serving
    /// host holds only [`Self::serving_reader`] and reaches this through the
    /// actor. Pure forward to [`LeafStore::pin_serve_set`] — the per-member
    /// contract lives there.
    ///
    /// # Errors
    ///
    /// [`ClientError::Store`] wrapping [`LeafStore::pin_serve_set`]'s.
    pub fn pin_serve_set(&self, shard_ids: &[u64]) -> Result<Vec<(u64, SegmentPin)>, ClientError> {
        self.store
            .pin_serve_set(shard_ids)
            .map_err(ClientError::from)
    }

    /// Every shard id currently pinned — the reconcile input for release.
    ///
    /// Pure forward to [`LeafStore::pinned_shard_ids`]; the reason it exists
    /// lives there.
    ///
    /// # Errors
    ///
    /// [`ClientError::Store`] wrapping the store's.
    pub fn pinned_shard_ids(&self) -> Result<Vec<u64>, ClientError> {
        self.store.pinned_shard_ids().map_err(ClientError::from)
    }

    /// Declare the prune-disabled posture, reporting what the store found.
    ///
    /// A store **write**, same as [`Self::pin_serve_set`]: the method is a
    /// pure forward, so a holder of this client *can* call it directly.
    /// The engine does not — production declaration rides
    /// `PinCompleteTreePrefix` so it serializes with ingest / pin /
    /// rollback on the actor that owns the client. A caller outside that
    /// actor is a second writer and owns the interleaving. Pure forward to
    /// [`LeafStore::set_prune_disabled`], including the parts that matter
    /// most: the declaration is one-way with no clear path, and the
    /// returned [`PostureDeclaration`] is the loss detector a re-declaring
    /// refresh reads (`COMPLETETREE_ACTIVATION.md` RR-2).
    ///
    /// # Errors
    ///
    /// [`ClientError::Store`] wrapping the store's.
    pub fn set_prune_disabled(&self) -> Result<PostureDeclaration, ClientError> {
        self.store.set_prune_disabled().map_err(ClientError::from)
    }

    /// The store's burial-gated freeze cursor — the CompleteTree prefix
    /// obligation `[0, k)`.
    ///
    /// Pure forward to [`LeafStore::next_freeze_seg`]; the prefix invariant
    /// and the deliberate non-collision with
    /// `shekyl_archival_retention::frozen_segment_count` live there.
    ///
    /// # Errors
    ///
    /// [`ClientError::Store`] wrapping the store's.
    pub fn next_freeze_seg(&self) -> Result<u64, ClientError> {
        self.store.next_freeze_seg().map_err(ClientError::from)
    }

    /// Release pins so the prune can reclaim those segments.
    ///
    /// A store **write**, so it runs on the actor's object for the same reason
    /// pinning does. Pure forward to [`LeafStore::release_pins`] — including
    /// the part that matters most: the store does not enforce the finality
    /// gate, and the caller owns it.
    ///
    /// # Errors
    ///
    /// [`ClientError::Store`] wrapping the store's.
    pub fn release_pins(&self, shard_ids: &[u64]) -> Result<usize, ClientError> {
        self.store
            .release_pins(shard_ids)
            .map_err(ClientError::from)
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
    /// consensus admits only tagged-key outputs (the claim-era staked-key
    /// output type is retired) and every output carries a commitment slot, so
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
    /// `check_output_types` accepted set grows beyond the tagged key)
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
    fn resume(store: Arc<LeafStore>) -> Result<Self, ClientError> {
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

    /// The authority to rebuild this client's writer after a fail-stop, as
    /// a value that can be held somewhere the client itself cannot be.
    ///
    /// The actor's handle needs to survive its own actor: when the actor
    /// fail-stops, the [`CurveTreeClient`] dies with the task, and recovery
    /// must rebuild a writer over the **same** open database. Handing the
    /// handle a [`ServingReader`] for that would have been the wrong
    /// capability — see [`WriterRecovery`] for why.
    #[must_use]
    pub fn writer_recovery(&self) -> WriterRecovery {
        WriterRecovery {
            store: Arc::clone(&self.store),
        }
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
                    gindex: pair[1].gindex.to_raw(),
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
            entry
                .gindex
                .to_raw()
                .checked_add(1)
                .expect("gindex fits u64")
        });
        let ingested_tip_height = if entries.is_empty() && tip == BlockHeight::from_raw(0) {
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

    /// Ingest one block, resolving each output's leaf commitment, threading the global
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
        let expected = self.ingested_tip_height.map_or(BlockHeight::ZERO, |last| {
            last.checked_add(shekyl_types::BlockCount::ONE)
                .expect("chain height fits u64")
        });
        if block.height != expected {
            return Err(ClientError::NonConsecutiveBlockHeight {
                got: block.height,
                expected,
            });
        }

        // Resolve each output's published leaf commitment from the tx's
        // `0x07` payload, then collect leaves. `identities` is kept alive
        // across the `collect_block_leaves` call that borrows it. A payload
        // an admitted chain cannot carry is an error, never a placeholder.
        let mut identities: Vec<Vec<OutputIdentity>> = Vec::with_capacity(block.txs.len());
        for (tx_index, tx) in block.txs.iter().enumerate() {
            let commitments = extract_leaf_commitments(tx.leaf_entry_blob, tx.outputs.len())
                .map_err(|source| ClientError::LeafEntries {
                    height: block.height,
                    tx_index,
                    source,
                })?;
            identities.push(
                tx.outputs
                    .iter()
                    .zip(commitments)
                    .map(|(raw, cm)| OutputIdentity {
                        output_key: raw.output_key,
                        commitment: raw.commitment,
                        cm,
                        target: raw.target,
                    })
                    .collect(),
            );
        }

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
        // untouched until the store transaction commits. A bad published
        // point refuses the whole block (the local vec is discarded), so no
        // partial leaf set can reach the store or memory.
        let mut new_leaves: Vec<LeafEntry> = Vec::new();
        let next_gindex =
            collect_block_leaves(block.height, &txs, self.next_gindex, &mut new_leaves).map_err(
                |source| ClientError::LeafPoint {
                    height: block.height,
                    source,
                },
            )?;

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
            Some(&(t, count)) if t.checked_add(shekyl_types::BlockCount::ONE) == Some(through) => {
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
            through.to_raw()
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
        reference_height.saturating_sub_count(shekyl_types::BlockCount::ONE)
    }

    /// The last block height passed to [`Self::ingest_block`] — or rebuilt by
    /// [`Self::rollback_to_fork`] / [`Self::resume`] — or `None` when the client
    /// is fresh (no blocks ingested).
    ///
    /// This is the **authoritative resume cursor** for a forward / backfill
    /// ingest driver: the next block to ingest is `tip + 1` (`BlockHeight::from_raw(0)`
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
    pub fn root_at(&self, reference_height: BlockHeight) -> Result<CurveTreeRoot, ClientError> {
        // Single-source the reconstruction: defer to `root_and_depth_at` and
        // drop the depth (CT-5c Q1). Both the root-only read (this method, the
        // §3.3 verify hot path) and the root+depth read go through the one
        // `root_at_count(n)` call, so they cannot describe different tree
        // states. The discarded depth is `layer_count_for_leaves`, a handful of
        // integer divisions — negligible on the verify path.
        self.root_and_depth_at(reference_height)
            .map(|(root, _)| root)
    }

    /// Reconstruct the curve-tree root **and** its depth at `reference_height`,
    /// both pinned to the same drained leaf count `n` (CT-5c Q1).
    ///
    /// The root is the [`LeafStore::root_at_count`] hot path; the depth is
    /// [`shekyl_fcmp::tree::layer_count_for_leaves`] over the same `n` (depth is
    /// a pure function of the leaf count, so it needs no tree build). The two
    /// reads share `n`, so the returned `(root, depth)` always describe the same
    /// tree state — there is no cross-await window in which they could diverge.
    ///
    /// The CT-5c send path needs both before assembling: the depth sizes the
    /// FCMP++ proof weight for fee estimation (which runs *before* path
    /// assembly), and the root binds the [`ReferenceBlock`]. The depth equals
    /// the assembler's `AssembledPath.tree.tree_depth` (which `assemble_path`
    /// takes from `build_layers(..).len()`) by the `layer_count_for_leaves`
    /// drift KAT, so the engine can assert their equality as a consistency
    /// check that never fires benignly.
    pub fn root_and_depth_at(
        &self,
        reference_height: BlockHeight,
    ) -> Result<(CurveTreeRoot, u8), ClientError> {
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
        let root =
            CurveTreeRoot::from_bytes(self.store.root_at_count(n).map_err(ClientError::from)?);
        let depth = shekyl_fcmp::tree::layer_count_for_leaves(n);
        Ok((root, depth))
    }

    /// The root a block built on the current tip commits to
    /// (`FCMP_PLUS_PLUS.md` §5): the tree state at chain height `tip + 1`,
    /// after the tip's own drain — what the daemon's `get_curve_tree_root()`
    /// reports once the tip has connected, and what [`Self::root_at`]`(tip + 1)`
    /// returns once that next block is ingested. For a fresh client (no
    /// blocks) it is the empty-tree sentinel, i.e. the genesis header.
    ///
    /// [`Self::root_at`] refuses heights beyond the ingested tip because a
    /// *verifier* must never anchor on a state it has not replayed. A
    /// *producer* of the next header needs exactly that state, so this is
    /// the one read that looks one block past the tip; `n` is the count
    /// drained through the tip.
    ///
    /// The store is verifier-shaped: ingesting block `h` drains the bucket
    /// that matures at `h − 1`, so it holds the state through `tip − 1` and
    /// serves `root_at(tip)` from cache. The one-block-ahead read this method
    /// makes needs the bucket maturing at `tip` as well, which enters the
    /// store only when block `tip + 1` is ingested. Only when that bucket is
    /// empty does the store path answer; on any chain with coinbases a bucket
    /// matures at every height past the first window, so past height 60 the
    /// common case rebuilds the root from the in-memory entries in canonical
    /// drain order with the same layer builder (`recon::root_from_scalars`,
    /// the oracle the store KATs are pinned to) — linear in the drained
    /// leaves per call. A producer-side read (test generator, template
    /// construction on a store-less node), not the verify hot path.
    pub fn next_block_root(&self) -> Result<CurveTreeRoot, ClientError> {
        self.ensure_live()?;
        let Some(tip) = self.ingested_tip_height else {
            return Ok(CurveTreeRoot::EMPTY);
        };
        let n = self.drained_leaf_count_at(tip);
        let stored = self.store.leaf_count().map_err(ClientError::from)?;
        if n <= stored {
            return Ok(CurveTreeRoot::from_bytes(
                self.store.root_at_count(n).map_err(ClientError::from)?,
            ));
        }
        Ok(CurveTreeRoot::from_bytes(root_from_scalars(
            &assemble_leaf_stream(&self.entries, tip),
        )))
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
    use crate::types::{BlockHash, CurveTreeRoot};
    use shekyl_consensus::COINBASE_LOCK_WINDOW;

    /// Standard Ed25519 basepoint, compressed — a valid, torsion-free
    /// point `construct_leaf` accepts for both `O` and `C`.
    const ED25519_BASEPOINT: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ];

    fn coinbase_raw() -> RawOutput {
        RawOutput {
            output_key: OneTimePubkey::from_bytes(ED25519_BASEPOINT),
            commitment: Some(CommitmentBytes::from_bytes(ED25519_BASEPOINT)),
            target: TargetKind::TaggedKey,
        }
    }

    /// One conforming `0x07` entry: `CM` is a valid, torsion-free point
    /// derived deterministically from `seed` (`Hp` over a seed-filled key,
    /// via the crate's existing point primitive), followed by an opaque
    /// record. Distinct seeds give byte-distinct commitment points and so
    /// byte-distinct leaves — which is what lets an ordering test tell two
    /// leaves apart.
    fn leaf_entry(seed: u8) -> [u8; 64] {
        let mut entry = [0x07u8; 64];
        entry[..32].copy_from_slice(&shekyl_fcmp::tree::key_image_generator(&[seed; 32]));
        entry
    }

    /// One conforming `0x07` entry per output, as a V3 chain always emits
    /// (`PL-D3`); entry `i` is seeded `i + 1`, so entries within one blob
    /// are byte-distinct.
    fn leaf_blob(n: usize) -> Vec<u8> {
        (0..n)
            .flat_map(|i| leaf_entry(u8::try_from(i + 1).expect("test blob fits u8")))
            .collect()
    }

    /// One coinbase tx carrying a per-output `0x07` blob of `n` × 64 bytes.
    fn coinbase_block<'a>(outputs: &'a [RawOutput], blob: &'a [u8]) -> Vec<TxLeafInputs<'a>> {
        vec![TxLeafInputs {
            is_miner: true,
            leaf_entry_blob: Some(blob),
            outputs,
        }]
    }

    /// Ingest consecutive single-coinbase blocks at heights `from..=to` — the
    /// production chain shape (every real block carries a coinbase).
    ///
    /// `CT-6` increment 2 — the C1 oracle, height-keyed.
    ///
    /// `CT6_PROVING_STATE.md` C1: *"Snapshot-derived root at height `h` equals
    /// `build_layers`' root at `h`, for every `h`. The existing full-tree
    /// implementation is the oracle."* C3 pins what "at `h`" means: a read at
    /// `h` reproduces `drained_leaf_count_at(drained_through(h))`, and root and
    /// depth stay pinned to that one `n`.
    ///
    /// # What this module is actually testing, and what it is not
    ///
    /// **Comparing `root_at_count` against `build_layers` alone would be very
    /// nearly a tautology**, and saying so is the point of this comment.
    /// `full_build_root` (`store/ops.rs:86`) *is* `try_build_layers` followed
    /// by `root_from_layers` — the same function under another name — and the
    /// count-keyed direction already has its KAT
    /// (`tail_layer_j_promotion_matches_oracle_at_j2`). Re-running that through
    /// a height would add a green test and no coverage.
    ///
    /// **The height axis adds exactly one thing: the mapping
    /// `h → drained_through(h) → drained_leaf_count_at → n`.** That is C3, and
    /// it is the only place a height-keyed read can be wrong while every
    /// count-keyed test stays green. So the assertions below are built to fail
    /// on *that* mapping, and the red-bites mutate it rather than corrupting a
    /// leaf.
    ///
    /// # Why the expectation is independent of the subject
    ///
    /// The cutoff is written as `h - 1` **here**, from the contract
    /// (`drained_through_is_reference_minus_one`), never taken from
    /// `drained_through` — a test that asks the subject where to look cannot
    /// discover that the subject looks in the wrong place.
    ///
    /// The count then comes from [`crate::recon::drained_sorted`], which is a
    /// genuinely **second instrument**: the production read counts through
    /// `drained_leaf_count_at`'s cache and maturity index, a different path
    /// from the sort. Two ways of counting the same cutoff, cross-checked.
    mod ct6_height_keyed_oracle {
        use super::*;
        use crate::recon::drained_sorted;
        use shekyl_fcmp::tree::{HELIOS_CHUNK_WIDTH, SELENE_CHUNK_WIDTH};

        /// Outputs per block, chosen so the drained count is **not** an affine
        /// function of the height.
        ///
        /// A uniform one-per-block fixture makes `n = h - 60` exactly, and then
        /// every off-by-one in the cutoff shifts `n` by exactly one leaf —
        /// always visible, which sounds good and hides the case that matters.
        /// With a varying schedule, a one-block error shifts `n` by however
        /// many outputs that block carried, **including zero**. The zero-output
        /// blocks are the reason this is a schedule and not a constant: they
        /// are where an off-by-one is invisible in the count, so the fixture
        /// must place assertions on both sides of them.
        const SCHEDULE: [usize; 12] = [1, 3, 0, 2, 5, 0, 1, 4, 2, 0, 3, 1];

        /// Height at which the fixture's outputs start draining.
        ///
        /// Coinbase maturity is creation + `COINBASE_LOCK_WINDOW`, the only
        /// drain gate for this fixture (`recon.rs:116-126`).
        fn drains_at(created_at: u64) -> u64 {
            created_at + COINBASE_LOCK_WINDOW as u64
        }

        /// Ingest `tip + 1` blocks whose output counts cycle through
        /// [`SCHEDULE`], and return outputs-created-per-height.
        fn ingest_varying(client: &mut CurveTreeClient, tip: u64) -> Vec<usize> {
            let mut created: Vec<usize> = Vec::new();
            for height in 0..=tip {
                // The remainder is < SCHEDULE.len(), so it indexes in range on any
                // pointer width; `usize::try_from` on the remainder cannot fail.
                let slot = usize::try_from(height % SCHEDULE.len() as u64)
                    .expect("remainder below SCHEDULE.len() fits usize");
                let n = SCHEDULE[slot];
                if n == 0 {
                    // A block with no leaf-eligible outputs still advances the
                    // chain: the gap is the fixture's point.
                    let txs: Vec<TxLeafInputs> = Vec::new();
                    client
                        .ingest_block(BlockLeaves {
                            height: BlockHeight::from_raw(height),
                            txs: &txs,
                        })
                        .unwrap();
                } else {
                    let outs = vec![coinbase_raw(); n];
                    ingest_outputs_at(client, height, &outs);
                }
                created.push(n);
            }
            created
        }

        /// The oracle: `build_layers`' root over the leaves drained through
        /// `cutoff`, with `cutoff` supplied by the caller rather than read from
        /// the subject.
        fn oracle_root_and_count(client: &CurveTreeClient, cutoff: u64) -> ([u8; 32], u64) {
            let drained = drained_sorted(&client.entries, BlockHeight::from_raw(cutoff));
            let scalars: Vec<[u8; 32]> = drained
                .iter()
                .flat_map(|e| {
                    let mut out = Vec::new();
                    for chunk in e.leaf.chunks_exact(32) {
                        let mut s = [0u8; 32];
                        s.copy_from_slice(chunk);
                        out.push(s);
                    }
                    out
                })
                .collect();
            let n = drained.len() as u64;
            if n == 0 {
                return (shekyl_fcmp::tree::selene_hash_init(), 0);
            }
            let layers = shekyl_fcmp::tree::build_layers(&scalars);
            (layers.last().unwrap()[0], n)
        }

        /// C1 + C3 at every height the fixture spans, including both sides of
        /// each zero-output block.
        #[test]
        fn a_height_keyed_read_matches_build_layers_at_every_height() {
            let tip = 96;
            let mut client = CurveTreeClient::new();
            let created = ingest_varying(&mut client, tip);

            // Only heights whose reads have something drained are meaningful,
            // and the fixture must actually reach that state or this test
            // would pass by never exercising the mapping (rule 47).
            let first_drained = drains_at(0) + 1;
            assert!(
                first_drained <= tip,
                "fixture never reaches a drained state: nothing would be compared"
            );

            // **Start below `first_drained`, not at it.** `layer_count_for_leaves`
            // changes value at only two counts in reach — `0 -> 1` and
            // `684 -> 685` — so a sweep that begins once leaves exist straddles
            // neither, and the depth assertion below becomes one that cannot
            // fail. Heights with nothing drained are where the first boundary
            // lives, so they are asserted rather than skipped.
            let mut heights_with_leaves = 0;
            let mut heights_empty = 0;
            for h in 1..=tip {
                // The cutoff is the contract's, not the subject's.
                let (want_root, want_n) = oracle_root_and_count(&client, h - 1);
                let (got_root, got_depth) = client
                    .root_and_depth_at(BlockHeight::from_raw(h))
                    .unwrap_or_else(|e| panic!("height {h}: {e:?}"));

                assert_eq!(
                    got_root.to_bytes(),
                    want_root,
                    "height {h}: root disagrees with build_layers over the {want_n} \
                     leaves drained through {}",
                    h - 1
                );
                // C3: depth is pinned to the same `n` the root was taken at.
                assert_eq!(
                    got_depth,
                    shekyl_fcmp::tree::layer_count_for_leaves(want_n),
                    "height {h}: depth is not pinned to n={want_n}"
                );
                if want_n > 0 {
                    heights_with_leaves += 1;
                } else {
                    heights_empty += 1;
                }
            }
            assert!(
                heights_empty > 0,
                "no height with an empty tree was asserted, so the 0 -> 1 depth \
                 boundary went untested and the depth claim could not fail"
            );
            assert!(
                heights_with_leaves > 0,
                "every height compared an empty tree — the mapping was never exercised"
            );
            // The schedule must have contributed a zero-output block inside the
            // drained span, or the invisible-off-by-one case went untested.
            let drained_span =
                usize::try_from(tip - COINBASE_LOCK_WINDOW as u64).expect("fixture tip fits usize");
            let zero_blocks = created[..=drained_span].iter().filter(|&&n| n == 0).count();
            assert!(
                zero_blocks > 0,
                "no zero-output block inside the drained span: the case where an \
                 off-by-one shifts the count by nothing was not covered"
            );
        }

        /// The depth boundary, asserted where it actually moves.
        ///
        /// `layer_count_for_leaves` is flat almost everywhere: between `1` and
        /// `684` it is 2, and it only steps at `0 -> 1` and `684 -> 685`
        /// (`SELENE_CHUNK_WIDTH` = 38, `HELIOS_CHUNK_WIDTH` = 18, so 38 x 18 =
        /// 684 leaves is the last count that roots at two layers). A depth
        /// assertion taken anywhere else is green against a wrong `n` as well
        /// as a right one.
        ///
        /// This is the second of the two boundaries, and it is the one a small
        /// fixture would never reach by accident, so the blocks here are wide
        /// rather than many.
        #[test]
        fn depth_steps_where_the_layer_count_steps_and_the_root_follows_n() {
            const WIDE: usize = 100;
            let boundary = (SELENE_CHUNK_WIDTH * HELIOS_CHUNK_WIDTH) as u64; // 684
            assert_eq!(
                shekyl_fcmp::tree::layer_count_for_leaves(boundary),
                shekyl_fcmp::tree::layer_count_for_leaves(boundary - 1),
                "fixture premise: the count below the boundary is flat"
            );
            assert_ne!(
                shekyl_fcmp::tree::layer_count_for_leaves(boundary),
                shekyl_fcmp::tree::layer_count_for_leaves(boundary + 1),
                "fixture premise: the boundary is where the depth actually steps"
            );

            // Enough wide blocks to carry the drained count past `boundary + 1`.
            let blocks_needed = (boundary + 1).div_ceil(WIDE as u64) + 1;
            let tip = blocks_needed + COINBASE_LOCK_WINDOW as u64 + 1;
            let mut client = CurveTreeClient::new();
            for height in 0..=tip {
                if height < blocks_needed {
                    let outs = vec![coinbase_raw(); WIDE];
                    ingest_outputs_at(&mut client, height, &outs);
                } else {
                    let txs: Vec<TxLeafInputs> = Vec::new();
                    client
                        .ingest_block(BlockLeaves {
                            height: BlockHeight::from_raw(height),
                            txs: &txs,
                        })
                        .unwrap();
                }
            }

            // Walk heights and assert at each; record whether both sides of the
            // boundary were actually visited, because a fixture that stops short
            // would make this test green without testing anything.
            let mut saw_below = false;
            let mut saw_above = false;
            for h in 1..=tip {
                let (want_root, want_n) = oracle_root_and_count(&client, h - 1);
                let (got_root, got_depth) = client
                    .root_and_depth_at(BlockHeight::from_raw(h))
                    .unwrap_or_else(|e| panic!("height {h}: {e:?}"));
                assert_eq!(got_root.to_bytes(), want_root, "height {h}: root");
                assert_eq!(
                    got_depth,
                    shekyl_fcmp::tree::layer_count_for_leaves(want_n),
                    "height {h}: depth not pinned to n={want_n}"
                );
                if want_n > 0 && want_n <= boundary {
                    saw_below = true;
                }
                if want_n > boundary {
                    saw_above = true;
                }
            }
            assert!(
                saw_below && saw_above,
                "the fixture did not land on both sides of n={boundary} \
                 (below={saw_below}, above={saw_above}); the depth step was never crossed"
            );
        }

        /// The red-bite, stated as an executable claim rather than a comment.
        ///
        /// If the cutoff the production read uses were `h` instead of `h - 1`,
        /// the root must differ at some height — otherwise nothing in this
        /// module could detect a wrong cutoff, and the whole file would be
        /// decoration. This asserts the *detectability*, which is the property
        /// a mutation test would otherwise have to be run by hand to learn.
        #[test]
        fn a_cutoff_off_by_one_is_detectable_at_some_height() {
            let tip = 96;
            let mut client = CurveTreeClient::new();
            ingest_varying(&mut client, tip);

            let mut differing = 0;
            let mut identical = 0;
            for h in (drains_at(0) + 1)..=tip {
                let (correct, n_correct) = oracle_root_and_count(&client, h - 1);
                let (shifted, n_shifted) = oracle_root_and_count(&client, h);
                if correct == shifted {
                    // Expected wherever block `h` carried no outputs — the
                    // count is unchanged, so the root is too.
                    assert_eq!(n_correct, n_shifted);
                    identical += 1;
                } else {
                    differing += 1;
                }
            }
            assert!(
                differing > 0,
                "a one-block cutoff shift changed nothing anywhere: this module \
                 cannot detect a wrong cutoff and its green means nothing"
            );
            assert!(
                identical > 0,
                "a one-block shift changed the root at every height, so the \
                 fixture never placed an assertion across a zero-output block — \
                 the invisible case is the one worth covering"
            );
        }
    }

    fn ingest_coinbase_blocks(client: &mut CurveTreeClient, from: u64, to: u64) {
        let outs = [coinbase_raw()];
        let blob = leaf_blob(1);
        for height in from..=to {
            let txs = coinbase_block(&outs, &blob);
            client
                .ingest_block(BlockLeaves {
                    height: BlockHeight::from_raw(height),
                    txs: &txs,
                })
                .unwrap();
        }
    }

    fn ingest_outputs_at(client: &mut CurveTreeClient, height: u64, outputs: &[RawOutput]) {
        let blob = leaf_blob(outputs.len());
        let txs = coinbase_block(outputs, &blob);
        client
            .ingest_block(BlockLeaves {
                height: BlockHeight::from_raw(height),
                txs: &txs,
            })
            .unwrap();
    }

    fn ingest_class_b_fixture_prefix(client: &mut CurveTreeClient, tip: u64) {
        for height in 0..=tip {
            if height == 64 {
                // Two coinbase outputs: the second is the never-draining
                // long-maturity witness (matures at 64 + COINBASE_LOCK_WINDOW
                // = 124, far past the test's 66-block window). Post claim-era
                // cutover the coinbase lock is the longest wire-real maturity,
                // so a near-tip coinbase replaces the old staked fixture.
                let outputs = [coinbase_raw(), coinbase_raw()];
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
        let blob = leaf_blob(1);
        let txs0 = coinbase_block(&outs, &blob);
        let txs1 = coinbase_block(&outs, &blob);
        let client = CurveTreeClient::from_blocks(&[
            BlockLeaves {
                height: BlockHeight::from_raw(0),
                txs: &txs0,
            },
            BlockLeaves {
                height: BlockHeight::from_raw(1),
                txs: &txs1,
            },
        ])
        .unwrap();
        for through in 0..=61u64 {
            assert_eq!(
                client.newly_drained_from_index(BlockHeight::from_raw(through)),
                newly_drained_at_cutoff(&client.entries, BlockHeight::from_raw(through)),
                "through={through}"
            );
        }
    }

    #[test]
    fn ingest_block_rejects_non_consecutive_heights() {
        let outs = [coinbase_raw()];
        let blob = leaf_blob(1);
        let txs = coinbase_block(&outs, &blob);
        let block0 = BlockLeaves {
            height: BlockHeight::from_raw(0),
            txs: &txs,
        };
        let block1 = BlockLeaves {
            height: BlockHeight::from_raw(1),
            txs: &txs,
        };
        let mut client = CurveTreeClient::new();

        assert!(matches!(
            client.ingest_block(block1),
            Err(ClientError::NonConsecutiveBlockHeight { got, expected })
                if got == BlockHeight::from_raw(1)
                    && expected == BlockHeight::from_raw(0)
        ));

        client.ingest_block(block0).unwrap();
        assert!(matches!(
            client.ingest_block(block0),
            Err(ClientError::NonConsecutiveBlockHeight { got, expected })
                if got == BlockHeight::from_raw(0)
                    && expected == BlockHeight::from_raw(1)
        ));
        assert!(matches!(
            client.ingest_block(BlockLeaves {
                height: BlockHeight::from_raw(2),
                txs: &txs,
            }),
            Err(ClientError::NonConsecutiveBlockHeight { got, expected })
                if got == BlockHeight::from_raw(2)
                    && expected == BlockHeight::from_raw(1)
        ));
    }

    #[test]
    fn root_before_any_ingest_is_rejected() {
        let client = CurveTreeClient::new();
        assert!(matches!(
            client.root_at(BlockHeight::from_raw(0)),
            Err(ClientError::ReferenceBeyondIngestedTip { reference_height, ingested_tip })
                if reference_height == BlockHeight::from_raw(0) && ingested_tip.is_none()
        ));
        assert_eq!(client.drained_leaf_count(BlockHeight::from_raw(1000)), 0);
    }

    #[test]
    fn genesis_root_is_empty_tree() {
        // Block 0 drains nothing (no predecessor), so the root committed at
        // genesis is the empty-tree sentinel.
        let mut client = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut client, 0, 0);
        assert_eq!(
            client.root_at(BlockHeight::from_raw(0)).unwrap(),
            CurveTreeRoot::EMPTY
        );
        assert_eq!(client.drained_leaf_count(BlockHeight::from_raw(0)), 0);
    }

    #[test]
    fn root_beyond_ingested_tip_is_rejected() {
        let mut client = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut client, 0, 0);
        assert!(matches!(
            client.root_at(BlockHeight::from_raw(1)),
            Err(ClientError::ReferenceBeyondIngestedTip { reference_height, .. })
                if reference_height == BlockHeight::from_raw(1)
        ));
        // The rejected query left no trace in the store: the freeze clock
        // still sits at the ingested tip.
        assert_eq!(
            client.store.sync_tip_height().unwrap(),
            BlockHeight::from_raw(0)
        );
    }

    #[test]
    fn duplicate_drained_through_updates_cache_in_place() {
        let outs = [coinbase_raw()];
        let blob = leaf_blob(1);
        let txs = coinbase_block(&outs, &blob);
        let mut client = CurveTreeClient::new();
        client
            .ingest_block(BlockLeaves {
                height: BlockHeight::from_raw(0),
                txs: &txs,
            })
            .unwrap();
        client
            .ingest_block(BlockLeaves {
                height: BlockHeight::from_raw(1),
                txs: &txs,
            })
            .unwrap();
        assert_eq!(client.drained_through_counts.len(), 1);
        assert_eq!(client.drained_through_counts[0].0, BlockHeight::from_raw(0));
        assert_eq!(
            client.drained_leaf_count(BlockHeight::from_raw(1)),
            client.drained_leaf_count(BlockHeight::from_raw(2))
        );
    }

    #[test]
    fn drained_through_is_reference_minus_one() {
        assert_eq!(
            CurveTreeClient::drained_through(BlockHeight::from_raw(0)),
            BlockHeight::from_raw(0)
        );
        assert_eq!(
            CurveTreeClient::drained_through(BlockHeight::from_raw(1)),
            BlockHeight::from_raw(0)
        );
        assert_eq!(
            CurveTreeClient::drained_through(BlockHeight::from_raw(61)),
            BlockHeight::from_raw(60)
        );
    }

    #[test]
    fn drained_leaf_count_matches_drain_schedule() {
        // Coinbase at height h matures at h+60 and drains at h+61: counts
        // must track that schedule exactly, with no interpolation between
        // cached cutoffs.
        let mut client = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut client, 0, 62);
        assert_eq!(client.drained_leaf_count(BlockHeight::from_raw(60)), 0);
        assert_eq!(
            client.drained_leaf_count(BlockHeight::from_raw(61)),
            1,
            "only the genesis coinbase has drained by height 61"
        );
        assert_eq!(client.drained_leaf_count(BlockHeight::from_raw(62)), 2);
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
            output_key: OneTimePubkey::from_bytes(ED25519_BASEPOINT),
            commitment: Some(CommitmentBytes::from_bytes(ED25519_BASEPOINT)),
            target: TargetKind::TaggedKey,
        };
        let blob = leaf_blob(1);
        let cb_outs = [cb];
        let reg_outs = [regular];
        let mut client = CurveTreeClient::new();
        for height in 0..=100u64 {
            let txs = [
                TxLeafInputs {
                    is_miner: true,
                    leaf_entry_blob: Some(&blob),
                    outputs: &cb_outs,
                },
                TxLeafInputs {
                    is_miner: false,
                    leaf_entry_blob: Some(&blob),
                    outputs: &reg_outs,
                },
            ];
            client
                .ingest_block(BlockLeaves {
                    height: BlockHeight::from_raw(height),
                    txs: &txs,
                })
                .unwrap();
        }
        for reference in 0..=100u64 {
            let through = CurveTreeClient::drained_through(BlockHeight::from_raw(reference));
            assert_eq!(
                client.drained_leaf_count_at(through),
                client.drained_count_from_index(through),
                "reference={reference}"
            );
        }
        // Both maturity schedules are live in the drained set.
        assert_eq!(
            u64::try_from(client.drained_leaf_count(BlockHeight::from_raw(100))).unwrap(),
            client.drained_count_from_index(BlockHeight::from_raw(99))
        );
        assert!(client.drained_leaf_count(BlockHeight::from_raw(100)) > 0);
    }

    #[test]
    fn mixed_maturity_ingest_mirrors_canonical_drain_order() {
        // Block 0 coinbase (m=60); block 1 carries a coinbase (m=61) and a
        // lower-maturity regular output (m=11). Insertion order differs from
        // canonical `(maturity, gindex)` drain order; the store mirror must
        // produce the canonical-order root anyway.
        let outs_cb = [coinbase_raw()];
        let regular = RawOutput {
            output_key: OneTimePubkey::from_bytes(ED25519_BASEPOINT),
            commitment: Some(CommitmentBytes::from_bytes(ED25519_BASEPOINT)),
            target: TargetKind::TaggedKey,
        };
        // Three byte-distinct entries (distinct commitment points), so the
        // three leaves are byte-distinct and the root comparison below can
        // actually fail if the store mirror routes two of them in the wrong
        // order — identical leaves would make every ordering produce the
        // same root.
        let blob0 = leaf_entry(1).to_vec();
        let blob1_cb = leaf_entry(2).to_vec();
        let blob1_reg = leaf_entry(3).to_vec();
        {
            // The test observes its own setup: the discrimination claim
            // rests on pairwise-distinct commitment points.
            let points = [&blob0[..32], &blob1_cb[..32], &blob1_reg[..32]];
            assert!(
                points[0] != points[1] && points[0] != points[2] && points[1] != points[2],
                "setup: the three 0x07 commitment points must be pairwise distinct"
            );
        }
        let txs0 = coinbase_block(&outs_cb, &blob0);
        let txs1 = [
            TxLeafInputs {
                is_miner: true,
                leaf_entry_blob: Some(&blob1_cb),
                outputs: &outs_cb,
            },
            TxLeafInputs {
                is_miner: false,
                leaf_entry_blob: Some(&blob1_reg),
                outputs: &[regular],
            },
        ];
        let mut client = CurveTreeClient::new();
        client
            .ingest_block(BlockLeaves {
                height: BlockHeight::from_raw(0),
                txs: &txs0,
            })
            .unwrap();
        client
            .ingest_block(BlockLeaves {
                height: BlockHeight::from_raw(1),
                txs: &txs1,
            })
            .unwrap();
        ingest_coinbase_blocks(&mut client, 2, 62);

        // At through=61 the drained set is m=11 (regular), m=60 (cb 0),
        // m=61 (cb 1) — none of the later coinbases.
        let drained = drained_sorted(&client.entries, BlockHeight::from_raw(61));
        assert_eq!(drained.len(), 3);
        assert!(drained
            .windows(2)
            .all(|w| (w[0].maturity, w[0].gindex) <= (w[1].maturity, w[1].gindex)));

        let oracle = CurveTreeRoot::from_bytes(root_from_scalars(&assemble_leaf_stream(
            &client.entries,
            BlockHeight::from_raw(61),
        )));
        assert_eq!(
            client.root_at(BlockHeight::from_raw(62)).unwrap(),
            oracle,
            "store mirror must follow canonical drain order, not insertion order"
        );
    }

    #[test]
    fn historical_root_stable_as_chain_extends() {
        let mut client = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut client, 0, 61);
        let root61 = client.root_at(BlockHeight::from_raw(61)).unwrap();
        ingest_coinbase_blocks(&mut client, 62, 62);
        assert_eq!(client.root_at(BlockHeight::from_raw(61)).unwrap(), root61);
        assert_eq!(client.drained_leaf_count(BlockHeight::from_raw(61)), 1);
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
        assert_eq!(
            client.root_at(BlockHeight::from_raw(60)).unwrap(),
            CurveTreeRoot::EMPTY
        );
        assert_eq!(client.drained_leaf_count(BlockHeight::from_raw(60)), 0);
        // ...non-empty from the next block.
        assert_ne!(
            client.root_at(BlockHeight::from_raw(61)).unwrap(),
            CurveTreeRoot::EMPTY
        );
        assert_eq!(client.drained_leaf_count(BlockHeight::from_raw(61)), 1);
        assert_eq!(COINBASE_LOCK_WINDOW as u64, 60);
    }

    #[test]
    fn gindex_threads_across_blocks() {
        // Two single-coinbase blocks: gindex must advance 0 then 1.
        // The entry's commitment point yields the leaf's 4th scalar (its
        // x-coordinate, always a canonical Selene scalar) and the store
        // validates pending rows at write time.
        let outs = [coinbase_raw()];
        let blob = leaf_blob(1);
        let txs0 = coinbase_block(&outs, &blob);
        let txs1 = coinbase_block(&outs, &blob);
        let blocks = [
            BlockLeaves {
                height: BlockHeight::from_raw(0),
                txs: &txs0,
            },
            BlockLeaves {
                height: BlockHeight::from_raw(1),
                txs: &txs1,
            },
        ];
        let client = CurveTreeClient::from_blocks(&blocks).unwrap();
        assert_eq!(client.next_gindex, 2, "two coinbases consume indices 0,1");
        assert_eq!(client.entries.len(), 2);
        assert_eq!(client.entries[0].gindex, Gindex::from_raw(0));
        assert_eq!(client.entries[1].gindex, Gindex::from_raw(1));
    }

    #[test]
    fn ingest_resolves_h_pqc_from_blob() {
        // The entry's commitment point must land in the leaf's 4th scalar as
        // its Wei25519 x-coordinate (`construct_leaf` extracts it).
        let outs = [coinbase_raw()];
        let blob = leaf_blob(1);
        let mut cm = [0u8; 32];
        cm.copy_from_slice(&blob[..32]);
        let txs = coinbase_block(&outs, &blob);
        let mut client = CurveTreeClient::new();
        client
            .ingest_block(BlockLeaves {
                height: BlockHeight::from_raw(0),
                txs: &txs,
            })
            .unwrap();
        assert_eq!(client.entries.len(), 1);
        let cm_x = shekyl_fcmp::tree::ed25519_point_to_selene_scalar(&cm)
            .expect("leaf_blob commitment point decompresses");
        assert_eq!(&client.entries[0].leaf[96..128], &cm_x);
        assert_eq!(client.entries[0].identity.cm, cm);
    }

    #[test]
    fn other_target_consumes_index_but_is_not_a_leaf() {
        // [Other, valid]: the Other output advances gindex but is no leaf.
        let mut other = coinbase_raw();
        other.target = TargetKind::Other;
        let outs = [other, coinbase_raw()];
        let blob = leaf_blob(2); // one entry per vout
        let txs = coinbase_block(&outs, &blob);
        let client = CurveTreeClient::from_blocks(&[BlockLeaves {
            height: BlockHeight::from_raw(0),
            txs: &txs,
        }])
        .unwrap();
        assert_eq!(client.next_gindex, 2, "both vouts consume an index");
        assert_eq!(client.entries.len(), 1, "only the valid output is a leaf");
        assert_eq!(client.entries[0].gindex, Gindex::from_raw(1));
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
                rebuilt.root_at(BlockHeight::from_raw(h)).unwrap(),
                fresh.root_at(BlockHeight::from_raw(h)).unwrap(),
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
        assert_eq!(rolled.drained_leaf_count(BlockHeight::from_raw(70)), 10);
        assert!(!rolled.drained_through_counts.is_empty());

        rolled.rollback_to_fork(BlockHeight::from_raw(65)).unwrap();
        assert_eq!(rolled.ingested_tip_height, Some(BlockHeight::from_raw(65)));
        assert!(rolled.drained_through_counts.is_empty());
        assert_eq!(rolled.next_gindex, 66);
        assert_eq!(
            rolled.store.sync_tip_height().unwrap(),
            BlockHeight::from_raw(65),
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
                rolled.root_at(BlockHeight::from_raw(h)).unwrap(),
                fresh.root_at(BlockHeight::from_raw(h)).unwrap(),
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

        client.rollback_to_fork(BlockHeight::from_raw(10)).unwrap();
        assert_eq!(client.entries, entries);
        assert_eq!(client.next_gindex, next_gindex);
        assert_eq!(client.ingested_tip_height, Some(BlockHeight::from_raw(10)));
        assert_eq!(client.store.read_pending_candidates().unwrap(), pending);
        assert!(client.drained_through_counts.is_empty());
    }

    #[test]
    fn rollback_to_fork_above_tip_is_invalid_and_leaves_memory() {
        let mut client = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut client, 0, 5);
        let entries = client.entries.clone();
        let next_gindex = client.next_gindex;

        let err = client
            .rollback_to_fork(BlockHeight::from_raw(6))
            .unwrap_err();
        assert!(matches!(
            err,
            ClientError::Store(StoreError::InvalidRollback {
                fork_height: 6,
                sync_tip: 5,
            })
        ));
        assert_eq!(client.entries, entries);
        assert_eq!(client.next_gindex, next_gindex);
        assert_eq!(client.ingested_tip_height, Some(BlockHeight::from_raw(5)));
        assert_eq!(
            client.store.sync_tip_height().unwrap(),
            BlockHeight::from_raw(5)
        );
        // The failure was before the store committed, so the client is not
        // poisoned: it stays fully usable.
        assert!(!client.poisoned);
        client.root_at(BlockHeight::from_raw(5)).unwrap();
        client.rollback_to_fork(BlockHeight::from_raw(3)).unwrap();
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
            client.root_at(BlockHeight::from_raw(5)),
            Err(ClientError::Poisoned)
        ));
        assert!(matches!(
            client.verify_root(&ReferenceBlock {
                height: BlockHeight::from_raw(5),
                curve_tree_root: CurveTreeRoot::from_bytes([0u8; 32]),
                block_hash: BlockHash::NULL,
            }),
            Err(ClientError::Poisoned)
        ));
        assert!(matches!(
            client.rollback_to_fork(BlockHeight::from_raw(3)),
            Err(ClientError::Poisoned)
        ));
        let block = BlockLeaves {
            height: BlockHeight::from_raw(6),
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
        assert_eq!(client.ingested_tip_height(), Some(BlockHeight::from_raw(5)));

        client.rollback_to_fork(BlockHeight::from_raw(2)).unwrap();
        assert_eq!(client.ingested_tip_height(), Some(BlockHeight::from_raw(2)));
    }

    #[test]
    fn rollback_to_genesis_keeps_genesis_and_accepts_height_one() {
        let mut client = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut client, 0, 10);

        client.rollback_to_fork(BlockHeight::from_raw(0)).unwrap();
        assert_eq!(client.entries.len(), 1);
        assert_eq!(client.entries[0].gindex, Gindex::from_raw(0));
        assert_eq!(client.next_gindex, 1);
        assert_eq!(client.ingested_tip_height, Some(BlockHeight::from_raw(0)));
        assert_eq!(
            client.store.read_pending_candidates().unwrap(),
            vec![client.entries[0]]
        );

        ingest_coinbase_blocks(&mut client, 1, 1);
        assert_eq!(client.ingested_tip_height, Some(BlockHeight::from_raw(1)));
        assert_eq!(client.entries.len(), 2);
        assert_eq!(client.next_gindex, 2);
    }

    #[test]
    fn from_blocks_pending_matches_explicit_replay() {
        // CT-3c's fresh-build oracle is meaningful only because
        // from_blocks replays the same per-block delta path.
        let out0 = [coinbase_raw()];
        let blob0 = leaf_blob(1);
        let txs0 = coinbase_block(&out0, &blob0);
        let out1 = [coinbase_raw(), coinbase_raw()];
        let blob1 = leaf_blob(2);
        let txs1 = coinbase_block(&out1, &blob1);
        let blocks = [
            BlockLeaves {
                height: BlockHeight::from_raw(0),
                txs: &txs0,
            },
            BlockLeaves {
                height: BlockHeight::from_raw(1),
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
        // height-64 second coinbase (maturity 64 + COINBASE_LOCK_WINDOW,
        // far past the 66-block window) pins the never-draining
        // long-maturity half of the invariant: pending equality catches it
        // even though no practical root window can.
        let mut orphaned = CurveTreeClient::new();
        ingest_class_b_fixture_prefix(&mut orphaned, 66);
        assert!(
            orphaned
                .store
                .read_drained_entries()
                .unwrap()
                .iter()
                .any(|entry| entry.maturity == BlockHeight::from_raw(65)),
            "orphaned suffix must drain the class-(b) witness"
        );

        orphaned
            .rollback_to_fork(BlockHeight::from_raw(65))
            .unwrap();

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
                .any(|entry| entry.maturity
                    == BlockHeight::from_raw(64 + COINBASE_LOCK_WINDOW as u64)),
            "long-maturity coinbase row stays pending and directly compared"
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
            orphaned.root_at(BlockHeight::from_raw(66)).unwrap(),
            fresh_redrain.root_at(BlockHeight::from_raw(66)).unwrap(),
            "root equality corroborates after re-drain"
        );
    }

    #[test]
    fn verify_root_accepts_match_and_rejects_mismatch() {
        let mut client = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut client, 0, 61);

        // The reconstructed root at height 61 is the consensus value.
        let good = ReferenceBlock {
            height: BlockHeight::from_raw(61),
            curve_tree_root: client.root_at(BlockHeight::from_raw(61)).unwrap(),
            block_hash: BlockHash::NULL,
        };
        assert!(client.verify_root(&good).is_ok());

        let bad = ReferenceBlock {
            height: BlockHeight::from_raw(61),
            curve_tree_root: CurveTreeRoot::from_bytes([0xFFu8; 32]),
            block_hash: BlockHash::NULL,
        };
        match client.verify_root(&bad) {
            Err(ClientError::RootMismatch {
                height,
                expected,
                got,
            }) => {
                assert_eq!(height, BlockHeight::from_raw(61));
                assert_eq!(expected, CurveTreeRoot::from_bytes([0xFFu8; 32]));
                assert_eq!(got, client.root_at(BlockHeight::from_raw(61)).unwrap());
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
            gindex: Gindex::from_raw(gindex),
            maturity: BlockHeight::from_raw(maturity),
            creation_height: BlockHeight::from_raw(creation),
            leaf,
            identity: OutputIdentity {
                output_key: OneTimePubkey::from_bytes([1u8; 32]),
                commitment: Some(CommitmentBytes::from_bytes([2u8; 32])),
                cm: [3u8; 32],
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
            client.root_at(BlockHeight::from_raw(0)),
            Err(ClientError::ReferenceBeyondIngestedTip { reference_height, ingested_tip })
                if reference_height == BlockHeight::from_raw(0) && ingested_tip.is_none()
        ));
        ingest_coinbase_blocks(&mut client, 0, 0);
        assert_eq!(
            client.root_at(BlockHeight::from_raw(0)).unwrap(),
            CurveTreeRoot::EMPTY
        );
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
                .append_block_deltas(&drained, &pending, &[], BlockHeight::from_raw(70))
                .unwrap();
        }

        let client = CurveTreeClient::open(&path).unwrap();
        assert_eq!(
            client.entries,
            vec![drained[0], pending[0], drained[1], pending[1]],
            "entries must merge gindex-ascending, not table-grouped"
        );
        assert_eq!(client.next_gindex, 4);
        assert_eq!(client.ingested_tip_height, Some(BlockHeight::from_raw(70)));
        assert!(client.drained_through_counts.is_empty());

        // Maturity index rebuilt from the sorted vec: cutoff 61 covers the
        // two drained rows; the pending maturities sit above it.
        assert_eq!(client.drained_leaf_count(BlockHeight::from_raw(62)), 2);
        assert_eq!(client.drained_leaf_count(BlockHeight::from_raw(0)), 0);

        // Root queries post-resume ride the maturity-index fallback and
        // must agree with the store's drained prefix.
        assert_eq!(
            client.root_at(BlockHeight::from_raw(62)).unwrap(),
            CurveTreeRoot::from_bytes(client.store.root_at_count(2).unwrap())
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
                BlockHeight::from_raw(70),
            )
            .unwrap();
        let err = CurveTreeClient::resume(Arc::new(store)).unwrap_err();
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
        store
            .append_drained(&entries, BlockHeight::from_raw(10_000))
            .unwrap();
        store.prune_frozen(&[]).unwrap();

        let err = CurveTreeClient::resume(Arc::new(store)).unwrap_err();
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
        assert_eq!(resumed.ingested_tip_height, Some(BlockHeight::from_raw(70)));
        let outs = [coinbase_raw()];
        let blob = leaf_blob(1);
        let genesis_txs = coinbase_block(&outs, &blob);
        assert!(matches!(
            resumed.ingest_block(BlockLeaves {
                height: BlockHeight::from_raw(0),
                txs: &genesis_txs,
            }),
            Err(ClientError::NonConsecutiveBlockHeight { got, expected })
                if got == BlockHeight::from_raw(0)
                    && expected == BlockHeight::from_raw(71)
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
                resumed.root_at(BlockHeight::from_raw(h)).unwrap(),
                continuous.root_at(BlockHeight::from_raw(h)).unwrap(),
                "height {h}"
            );
        }
        drop(resumed);
        std::fs::remove_file(&path).unwrap();
    }
}
