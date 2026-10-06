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
//! validated by [`crate::recon::extract_leaf_commitments`]. No second
//! `tx_extra` parser is written.
//!
//! ## Boundary
//!
//! This crate does not depend on `shekyl-scanner` (lib.rs "Layering").
//! The caller (the engine's block-decode path) runs scanner `Extra` to
//! turn raw `tx_extra` into the `0x07` leaf-hash blob and extracts each
//! output's `O`/`C`/target, then hands this client the reduced
//! [`BlockLeaves`]. The client owns everything from there: `h_pqc`
//! resolution ([`crate::recon::extract_leaf_commitments`]), leaf
//! collection + global-index threading ([`crate::recon::collect_block_leaves`]),
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
//! CT-2 replay oracle ([`crate::recon::root_from_scalars`]) remains the KAT baseline.
//! Production root queries go through [`CurveTreeClient::root_and_depth_at`]:
//! an in-horizon height answers from its frontier snapshot, and a miss falls
//! through to the store's count-keyed hot path.
//!
//! See `docs/design/CURVE_TREE_CLIENT.md` §3 and
//! `docs/design/CT2_DRAIN_ORDER.md` §7 (data flow).

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use crate::frontier::Frontier;
use crate::recon::{
    assemble_leaf_stream, collect_block_leaves, extract_leaf_commitments, root_from_scalars,
    TxOutputs,
};
use crate::store::{
    LeafStore, PostureDeclaration, SegmentPin, ServingReader, StoreError, StoreOpenFault,
};
use crate::types::{
    BlockHeight, CommitmentBytes, CurveTreeRoot, Gindex, LeafEntry, OneTimePubkey, OutputIdentity,
    ReferenceBlock, TargetKind,
};

mod capture;

pub(crate) use capture::{
    ChunkSpan, CAPTURED_IDENTITY_BYTES, CAPTURED_IDENTITY_CM_X_AT, CAPTURED_IDENTITY_COMMITMENT_AT,
    CAPTURED_IDENTITY_OUTPUT_KEY_AT, CURVE_ELEMENT_BYTES, NODE_CHILD_BYTES,
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
    /// An assembled path does not commit to the root it claims (`CT-6` §11.6).
    ///
    /// Raised after assembly, from `verify_path_against_its_branches`.
    /// The store gate above it compares two store reads and cannot see this:
    /// [`crate::types::TreeContext::tree_root`] is copied from the gated
    /// reference, and the branches come from the route that assembled the
    /// path — the capture table and the frontier snapshot, or the rebuild of
    /// `entries`. [`crate::assemble::PathRootFault`] names which step refused.
    /// [`crate::assemble::PathRootFault::ChildAbsent`] is the membership link.
    /// [`crate::assemble::PathRootFault::RootDisagrees`] is the final
    /// comparison. [`crate::assemble::PathRootFault::ShortPath`] and
    /// [`crate::assemble::PathRootFault::LongPath`] are also how a rebuilt
    /// layer count that disagrees with the gate's depth is reported.
    ///
    /// This is a defect, not a user condition: the wallet's two views of one
    /// tree disagree. Refusing is the point — an inconsistent path yields a
    /// proof that fails after the prover has run, or a transaction the daemon
    /// rejects, and neither says what went wrong.
    PathRootMismatch {
        /// The root the path claimed, copied from the gated reference.
        claimed: CurveTreeRoot,
        /// Which step of the fold refused.
        fault: crate::assemble::PathRootFault,
    },
    /// A registration names an output this client does not hold at that
    /// `gindex`.
    ///
    /// The wallet says it owns `O` at `gindex`; the client's chain view has
    /// a different output there. One of the two is reading a different
    /// chain, which is the same inter-component invariant
    /// [`ClientError::IdentityMismatch`] guards at assembly — raised here so
    /// it surfaces at registration rather than at the spend that needed the
    /// capture.
    ///
    /// Refused rather than stored: a registration this client cannot match
    /// would capture nothing and report nothing, and the remedy is the
    /// wallet's own rescan, which re-registers with the key its scan of the
    /// current chain found (rule 82).
    RegistrationIdentityMismatch {
        /// The global output index the registration named.
        gindex: Gindex,
        /// The output key the registration carried.
        expected: OneTimePubkey,
        /// The output key this client holds at that `gindex`.
        got: OneTimePubkey,
    },
    /// The reference height has no frontier snapshot, so the open chunks of
    /// a captured path cannot be read at it.
    ///
    /// The ring holds `[tip - horizon, tip]` with the horizon at
    /// `SEGMENT_FREEZE_REORG_MARGIN_BLOCKS` (720), and the daemon rejects a
    /// reference older than `REFERENCE_BLOCK_MAX_AGE` (100) blocks. A
    /// reference past that horizon is one the daemon would refuse, and
    /// rebuilding the tree from every drained leaf to serve it is not worth
    /// the read. A miss *inside* the horizon is a hole: the height was
    /// ingested, and reading it again does not write the row. Re-anchor
    /// treats both as terminal. The unregistered route never reaches this
    /// error; it rebuilds before the snapshot is consulted.
    ReferenceOutsideSnapshotRing {
        /// The reference height asked for.
        height: BlockHeight,
    },
    /// A chunk a captured path needs has closed, and the capture table does
    /// not hold it.
    ///
    /// The owned position was resolved, so every chunk over it should have
    /// been written — by the fold as it closed, or by reconciliation for the
    /// ones that closed before registration. One missing means that did not
    /// happen, and the remedy is [`CurveTreeClient::reconcile_captures`],
    /// which writes exactly what is due and absent. Not a fallback to the
    /// rebuild: that would serve the spend while hiding that the mechanism
    /// it relies on has a hole.
    CaptureMissing {
        /// Leaf position the chunk closed at — the capture row's key.
        end_leaf: u64,
        /// The layer the row lacks.
        layer: u8,
    },
    /// A held owned position is not one the canonical drain order produces.
    ///
    /// `owned_positions` is written by the fold, leaf by leaf, as the
    /// frontier counts. [`CurveTreeClient::reconcile_captures`] recomputes
    /// the same set from `drained_sorted` — the order assembly resolves
    /// against — and the two must agree, with the recomputed set a superset
    /// (it also covers registrations the fold never saw). A held position
    /// the recomputation does not produce means the two orders have
    /// diverged, and every capture keyed on the fold's coordinate is then
    /// keyed on the wrong leaf.
    ///
    /// Reported rather than repaired: reconciliation would otherwise
    /// silently overwrite one order's coordinates with the other's, and
    /// nothing says which is right.
    ///
    /// Classified [`StoreOpenFault::Internal`], not `Corrupt`. The store may
    /// be sound — the disagreement is in memory — and `Corrupt`'s remedy is
    /// to delete the store.
    OwnedPositionDrift {
        /// The held position the canonical order does not produce.
        position: u64,
    },
    /// Capture needed the leaf identities under a closing layer-0 chunk and
    /// the store did not hold all of them.
    ///
    /// The chunk's siblings come from the leaf rows at `end_leaf + 1 -
    /// SELENE_CHUNK_WIDTH ..= end_leaf`: the rows below this block's first
    /// drain from [`LeafStore::read_drained_range`], the rest from the block
    /// being ingested. A short count means a leaf row is gone from a position
    /// the store still counts — which only [`LeafStore::prune_frozen`]
    /// produces, by dropping non-owned frozen leaf bytes. Resume already
    /// refuses such a store ([`ClientError::ResumeFromPrunedStore`], F5);
    /// this is the same refusal for a store pruned while open, and it refuses
    /// the block rather than writing a short chunk the merge would accept.
    CaptureIdentitiesIncomplete {
        /// Leaf position at which the chunk closed — the capture row's key.
        end_leaf: u64,
        /// Siblings the chunk has, which is [`shekyl_fcmp::tree::SELENE_CHUNK_WIDTH`].
        want: usize,
        /// Siblings the leaf rows yielded.
        got: usize,
    },
    /// The requested output has no resolved owned position, so there is no
    /// captured path to read.
    ///
    /// Assembly reads captures and never rebuilds; an input reaches it
    /// registered or not at all. The curve-tree actor registers a batch's
    /// inputs ([`CurveTreeClient::sync_owned`]) before assembling, so this
    /// fires for a direct caller that skipped that, or for an input the sync
    /// reported stale — the client holds a different output at that gindex,
    /// and the caller's view of the chain is behind.
    OutputNotRegistered {
        /// The input's global output index.
        gindex: Gindex,
        /// The output key the caller supplied.
        output_key: OneTimePubkey,
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
    /// The incremental frontier could not advance, close, or be decoded
    /// from the snapshot ring (CT-6 increment 4).
    ///
    /// Every one of those is a refusal rather than a fallback. A frontier
    /// that will not advance refuses its block, exactly as a bad published
    /// point does; a snapshot that will not decode refuses its read rather
    /// than quietly answering from the store, because a ring that silently
    /// stopped being read is indistinguishable from a ring that works.
    Frontier {
        /// Height whose advance or read failed.
        height: BlockHeight,
        /// What the frontier refused on.
        source: crate::frontier::FrontierError,
    },
    /// A ring snapshot's own leaf count is not the count the client holds
    /// for that height — C3's pin, enforced on the production read.
    ///
    /// Root and depth are both taken from the snapshot's count, so a
    /// snapshot built over a different `n` would answer with a root and a
    /// depth that are self-consistent and wrong. Refused, never served.
    SnapshotLeafCountMismatch {
        /// Reference height that was read.
        height: BlockHeight,
        /// Leaf count the snapshot carries.
        snapshot: u64,
        /// Leaf count the client's drain index gives for that height.
        expected: u64,
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

    /// What this failure means when [`CurveTreeClient::open`] raised it
    /// ([`StoreOpenFault`]). An open reads nothing but the store, so what it
    /// can raise is a store failure, a resume refusal, or the store's own
    /// rows failing to rebuild — a ring snapshot that will not decode, or
    /// whose leaf count disagrees with the drain index. Resume calls that
    /// last case corruption (`rebuild_from_store`), and so does this. Every
    /// other arm is raised by ingest or assembly, and seeing one at open is
    /// a programming error. Exhaustive, so a new variant has to be placed
    /// before it compiles.
    #[must_use]
    pub fn open_fault(&self) -> StoreOpenFault {
        match self {
            ClientError::Store(e) => e.open_fault(),
            // Pruned-store resume is unbuilt (F5): a shape this build cannot
            // resume, not a broken store.
            ClientError::ResumeFromPrunedStore { .. }
            // Same cause, same verdict: leaf bytes capture needs are gone
            // from a position the store counts. Pruned-store *support* is
            // F5 work, so this build cannot proceed over one.
            | ClientError::CaptureIdentitiesIncomplete { .. } => StoreOpenFault::Unsupported,
            ClientError::ResumeFromCorruptStore { .. }
            | ClientError::Frontier { .. }
            | ClientError::SnapshotLeafCountMismatch { .. } => StoreOpenFault::Corrupt,
            // Not `Corrupt`: that fault's stated remedy is *delete the
            // store and let the wallet rebuild it*, and drift is the
            // client's in-memory positions disagreeing with the canonical
            // drain order — the store may be entirely sound. Destroying a
            // good store over a memory defect is naming a remedy that costs
            // more than the fault (rule 82). It is also not an open-time
            // outcome at all, which is what `Internal` says here, exactly
            // as `PathRootMismatch` does.
            // A registration disagreeing with the chain view is the same
            // family as `IdentityMismatch` below it: a caller-vs-client
            // disagreement, not an open-time outcome.
            ClientError::RegistrationIdentityMismatch { .. }
            | ClientError::OwnedPositionDrift { .. }
            | ClientError::ReferenceOutsideSnapshotRing { .. }
            | ClientError::CaptureMissing { .. }
            | ClientError::RootMismatch { .. }
            | ClientError::PathRootMismatch { .. }
            | ClientError::OutputNotRegistered { .. }
            | ClientError::OutputNotDrained { .. }
            | ClientError::IdentityMismatch { .. }
            | ClientError::TooManyInputs { .. }
            | ClientError::NonConsecutiveBlockHeight { .. }
            | ClientError::ReferenceBeyondIngestedTip { .. }
            | ClientError::Poisoned
            | ClientError::LeafEntries { .. }
            | ClientError::LeafPoint { .. } => StoreOpenFault::Internal,
        }
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
    // `pub(crate)` for the sibling `assemble` module's capture reads.
    pub(crate) store: Arc<LeafStore>,
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
    /// The live curve-tree frontier: the accumulator over exactly the
    /// leaves the store has drained, which is the snapshot the ring holds
    /// at [`Self::ingested_tip_height`].
    ///
    /// Kept in memory because the advance is the per-block hot path and a
    /// decode per block would pay for the ring twice. It is not a second
    /// source of truth: [`Self::ingest_block`] writes this exact value into
    /// the ring in the block's own transaction, and every path that rebuilds
    /// in-memory state ([`Self::resume`], [`Self::rollback_to_fork`])
    /// re-derives it from the store rather than adjusting it.
    frontier: Frontier,
    /// Outputs whose membership-path material this client captures, as
    /// `gindex -> O`.
    ///
    /// **Both halves, because a `gindex` is a name and not an identity.** It
    /// is a position in the chain's output sequence, and a reorg re-derives
    /// it: the same number can name a different output on the new chain. A
    /// registry keyed on the number alone would then mark a stranger's leaf
    /// as owned and capture its chunks, and no rule evaluated on the rebuilt
    /// state can tell the two apart — see [`Self::rollback_to_fork`] for the
    /// two inequalities that tried. `O` is a one-time key, so the pair names
    /// one specific output and the question stops being answerable only in
    /// hindsight.
    ///
    /// Registered by the wallet ([`Self::register_owned`]), never derived:
    /// the curve-tree client sees every output on the chain and cannot tell
    /// which are the wallet's — that is the scanner's knowledge, and keeping
    /// it on this side would mean either a second view-key consumer or a
    /// guess.
    ///
    /// **Session-scoped on purpose.** [`Self::resume`] starts empty, because
    /// a registry persisted here would be a second copy of the wallet's own
    /// output list — the thing that would silently rot when the two diverge.
    /// The wallet re-registers what it holds; what that leaves owed is the
    /// captures for chunks that closed before the registration, which
    /// reconciliation discharges.
    pub(crate) owned_outputs: BTreeMap<Gindex, OneTimePubkey>,
    /// Drain positions of owned leaves, as the fold assigned them.
    ///
    /// Not derived from [`Self::owned_outputs`] on demand: a position is
    /// the leaf's index in drain order, which is what the frontier counts as
    /// it pushes. Recording it there is the one instrument; resolving it
    /// again from the maturity index would be a second.
    ///
    /// Keyed by **position**, because the fold's intersection test is a
    /// range over positions; the value is the gindex it resolved, which is
    /// what assembly reverses to find an input's position. That reverse
    /// lookup is a scan — the registry is the wallet's own output count and
    /// a batch holds at most `MAX_INPUTS`.
    ///
    /// A rollback **retains** the positions below the surviving leaf count
    /// and drops the rest — see [`Self::rollback_to_fork`].
    pub(crate) owned_positions: BTreeMap<u64, Gindex>,
}

/// What registering an owned output means for the captures it needs
/// ([`CurveTreeClient::register_owned`]).
///
/// The distinction is not cosmetic: capture rides the **fold**, and a fold
/// happens once. Registering before the leaf drains puts every chunk over it
/// on the capture path; registering after means the chunks that already
/// closed were folded without a reason to keep them, and no future fold
/// reports them again.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OwnedRegistration {
    /// The leaf has not drained at the ingested tip. Every chunk over it is
    /// captured as the fold closes it; nothing is owed.
    BeforeDrain,
    /// The leaf had already drained. Chunks over it that closed before this
    /// call are **not** captured, and are owed to reconciliation; chunks
    /// that have yet to close are captured as normal.
    ///
    /// This is the state a resumed client leaves every held output in, since
    /// the registry does not persist
    /// ([`CurveTreeClient::register_owned`]).
    AfterDrain,
    /// The same pair was already held, and nothing is owed: either the leaf
    /// has not drained, or its position is already resolved so every chunk
    /// over it is captured by the fold as it closes.
    ///
    /// This is what makes a re-offer cheap. The wallet re-registers
    /// everything it holds on every refresh ([`CurveTreeClient::sync_owned`]),
    /// and a verdict of `AfterDrain` for a pair that is already fully served
    /// would trigger a reconciliation per refresh that reads the table and
    /// writes nothing. A held pair whose leaf *has* drained but whose position
    /// is **not** resolved is still `AfterDrain` — that is the one case where
    /// "held" and "served" diverge, and it is owed.
    AlreadyHeld,
}

/// What one [`CurveTreeClient::sync_owned`] call did with its batch.
///
/// Per-output verdicts are counted rather than returned one by one, because
/// the caller's decisions are batch-level: whether anything was owed (and so
/// reconciled), and which outputs the client could not accept. The stale
/// list is the one per-output fact that matters, because each entry names a
/// caller whose view of the chain is behind the client's.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct OwnershipSync {
    /// Registered ahead of their drain; the fold will capture them.
    pub before_drain: usize,
    /// Registered after their drain; their closed chunks were owed and
    /// `reconciliation` wrote them.
    pub after_drain: usize,
    /// Already held and fully served; nothing done.
    pub already_held: usize,
    /// Refused: the client holds a *different* output at that gindex. Not an
    /// error for the batch — the rest were registered — because this is the
    /// normal outcome of a scan that lags the tree across a reorg: the caller
    /// re-offers the right key once its rescan reaches the new chain.
    pub stale: Vec<Gindex>,
    /// The reconciliation run iff anything was `after_drain`.
    pub reconciliation: Option<CaptureReconciliation>,
}

/// What one [`CurveTreeClient::reconcile_captures`] call did.
///
/// Reported rather than returned as a bare count because the three numbers
/// answer different questions: whether the call found work it did not know
/// about, how many rows it touched, and how much it wrote. A reconcile that
/// resolves positions but writes nothing is the normal steady state; one
/// that writes on every call would mean the delta check is not working.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CaptureReconciliation {
    /// Owned positions this call resolved that were not already held — the
    /// late registrations it picked up.
    pub positions_resolved: usize,
    /// Capture rows (`end_leaf` keys) written.
    pub rows_written: usize,
    /// Chunks written across those rows. Higher than `rows_written` wherever
    /// a cascade put two layers under one key.
    pub chunks_written: usize,
    /// Leaves read and hashed to rebuild the missing chunks.
    ///
    /// The cost figure, and the one a caller should watch. **Zero** when
    /// every due capture is already present, which is the normal resume —
    /// reconciliation then costs a table read per due coordinate and no
    /// hashing at all. A non-zero value is bounded by the spans of the
    /// chunks actually missing (`outputs_per_node(layer)` each), never by
    /// the chain's length.
    pub leaves_rebuilt: u64,
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
    frontier: Frontier,
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
            frontier: Frontier::new(),
            owned_outputs: BTreeMap::new(),
            owned_positions: BTreeMap::new(),
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
            frontier: rebuilt.frontier,
            // A resumed client holds no registrations: the wallet's output
            // list is the wallet's, and re-registering is what tells this
            // client what to capture. See `owned_outputs`.
            owned_outputs: BTreeMap::new(),
            owned_positions: BTreeMap::new(),
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

        // The live frontier comes from the ring's row at `tip` when there is
        // one — an O(depth) decode instead of an O(leaves) fold, which is
        // what makes an in-horizon rewind cost the fork height's snapshot
        // plus the replay forward rather than a rebuild of the whole tree.
        //
        // A row whose leaf count is not the store's is **refused**, not
        // quietly re-derived: the ring and the leaf tables are written in one
        // transaction from a frontier already checked against the drain
        // index, so a disagreement here is corruption, and C8's answer to
        // corruption is refuse-and-resync rather than a repair that hides it.
        //
        // The fold below is the path for a store the ring does not cover: one
        // written before the table existed, or one rolled back past the
        // ring's span. It is correct and slow, which is the right way round.
        let frontier = match Self::snapshot_at_in(store, tip)? {
            Some(snapshot) => {
                if snapshot.leaf_count() != stored {
                    return Err(ClientError::SnapshotLeafCountMismatch {
                        height: tip,
                        snapshot: snapshot.leaf_count(),
                        expected: stored,
                    });
                }
                snapshot
            }
            None => {
                let mut frontier = Frontier::new();
                for entry in &drained {
                    frontier
                        .push_leaf(&entry.leaf)
                        .map_err(|source| ClientError::Frontier {
                            height: tip,
                            source,
                        })?;
                }
                frontier
            }
        };

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
            frontier,
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
        // Which registrations name an output this client holds *now* — read
        // before the rebuild, because staleness is a set difference **across**
        // the rollback and neither side alone answers it. See the retain
        // below for why no inequality on `gindex` can.
        let named_a_held_output: Vec<(Gindex, OneTimePubkey)> = self
            .owned_outputs
            .iter()
            .filter(|(gindex, key)| Self::held_output(&self.entries, **gindex) == Some(**key))
            .map(|(gindex, key)| (*gindex, *key))
            .collect();
        let rebuilt = Self::rebuild_from_store(&self.store)?;
        self.entries = rebuilt.entries;
        self.next_gindex = rebuilt.next_gindex;
        self.drained_through_counts = Vec::new();
        self.entries_by_maturity = rebuilt.entries_by_maturity;
        self.ingested_tip_height = rebuilt.ingested_tip_height;
        // The two holders a rollback has to trim, one event in two units.
        //
        // **Positions**, in drained-leaf coordinates: truncation deletes
        // `range(start..)` and shifts nothing, so a surviving leaf keeps its
        // position and a removed one re-resolves through the fold when it
        // drains again. `start` is the surviving leaf count, which is the
        // rebuilt frontier's — the same coordinate `FoldedChunk::end_leaf`
        // is compared against.
        let surviving = rebuilt.frontier.leaf_count();
        self.owned_positions
            .retain(|position, _| *position < surviving);

        // **Registrations**, in `(gindex, O)`. This is now *cleanup*, not
        // the correctness rule: ownership is tested by identity at the fold
        // and in reconciliation, so a rebound gindex simply does not match
        // and a stranger's chunks are never captured, whatever this does.
        // What it buys is a registry that does not accumulate dead rows
        // across reorgs.
        //
        // A registration is dropped iff the output it names *was* here and
        // is now absent **or different** — the set difference taken above
        // and below the rebuild, over the pair rather than the number. The
        // identity half is load-bearing even here: a rollback that rebinds a
        // gindex leaves it present, so a gindex-only difference keeps the
        // dead row. Three rules were tried before this one, and the first
        // two were not merely untidy but wrong:
        //
        // `gindex >= surviving_leaf_count` mixes units (a gindex is not a
        // position; `TargetKind::Other` consumes one without draining a
        // leaf) — `a_gindex_is_not_a_position`.
        //
        // `gindex < next_gindex && !entries.contains(gindex)` typechecks and
        // still fails, in the case it was written for. A rollback removes
        // the chain's tail, so every output it removes holds a gindex at or
        // above the **rebuilt** `next_gindex`, which is `entries.last() + 1`
        // over what survived. The clause meant to protect a registration for
        // a not-yet-ingested output therefore protects every removed one too,
        // and the rule drops nothing — `a_removed_gindex_sits_above_the_
        // rebuilt_next_gindex`.
        //
        // *Candidate 3 — the same difference on `gindex` alone.* Shipped,
        // then found to miss the rebinding case: a rollback that gives the
        // gindex to a different output leaves it present, so the difference
        // sees nothing gone.
        //
        // None of the three could answer the question from the rebuilt state,
        // because a `gindex` is a name. Binding the registration to `O` at
        // registration time is what makes it answerable at all — see
        // `owned_outputs`. Nothing persists the registry (`resume` starts
        // empty), so there is no stale trace to re-derive on a later open.
        for (gindex, key) in named_a_held_output {
            if Self::held_output(&self.entries, gindex) != Some(key) {
                self.owned_outputs.remove(&gindex);
            }
        }
        self.frontier = rebuilt.frontier;
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
    /// removals, tip advance, the frontier snapshot, and the path material
    /// captured for registered outputs ([`Self::register_owned`]) — lands in
    /// one ACID
    /// [`LeafStore::append_block_with_snapshot`] transaction *before* any
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

        // The frontier advances on a clone, and capture is collected with
        // it, before the transaction opens. A hash failure or a short
        // layer-0 read refuses the block with both sides untouched.
        let mut advanced = self.frontier.clone();
        let captured = self.fold_block_captures(block.height, &drained, &mut advanced)?;
        // C3 in production, not only in a test: the snapshot this block
        // captures must carry exactly the drain index's count for the
        // cutoff, because root and depth are both read back off it.
        let canonical = self.canonical_drained_count_on_ingest(through);
        if advanced.leaf_count() != canonical {
            return Err(ClientError::SnapshotLeafCountMismatch {
                height: block.height,
                snapshot: advanced.leaf_count(),
                expected: canonical,
            });
        }
        let snapshot = advanced.encode();

        // One ACID transaction for the whole block delta — leaves, pending
        // rows, the snapshot, and the freeze clock (`META_SYNC_TIP`, which
        // advances to the ingested tip and is the only height the freeze gate
        // is ever driven by). An all-empty delta still advances the tip, and
        // still captures: a block that drains nothing has a frontier, and a
        // ring that skipped it would have a hole at that height.
        self.store.append_block_with_snapshot(
            &drained,
            &new_leaves,
            &removed,
            block.height,
            &snapshot,
            &captured.rows,
        )?;

        // Store committed — the in-memory commit below is infallible.
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
        self.frontier = advanced;
        self.owned_positions.extend(captured.pending_owned);
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

    pub(crate) fn drained_leaf_count_at(&self, through: BlockHeight) -> u64 {
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
        // §3.3 verify hot path) and the root+depth read go through that one
        // dispatcher — the snapshot ring when it covers the height, otherwise
        // the count-keyed store path — so they cannot describe different tree
        // states. The discarded depth is a handful of integer divisions.
        self.root_and_depth_at(reference_height)
            .map(|(root, _)| root)
    }

    /// Reconstruct the curve-tree root **and** its depth at `reference_height`,
    /// both pinned to the same drained leaf count `n` (CT-5c Q1, CT-6 C3).
    ///
    /// When the snapshot ring covers the height, the root is [`Frontier::root`]
    /// and the depth is [`Frontier::depth`], after checking the snapshot's own
    /// leaf count against this height's `n`. A mismatch is
    /// [`ClientError::SnapshotLeafCountMismatch`]: the row names a different
    /// tree than the drain index, and serving around it would hide the capture.
    /// A miss falls through to [`LeafStore::root_at_count`] for the root and
    /// [`shekyl_fcmp::tree::layer_count_for_leaves`] for the depth, over that
    /// same `n`. The two halves of a reading share one count, so they describe
    /// the same tree.
    ///
    /// The CT-5c send path needs both before assembling: the depth sizes the
    /// FCMP++ proof weight for fee estimation (which runs *before* path
    /// assembly), and the root binds the [`ReferenceBlock`]. Both assembly
    /// routes stamp this depth onto `AssembledPath.tree.tree_depth`. The
    /// rebuild compares it with `build_layers(..).len()` and refuses when
    /// they disagree; the `layer_count_for_leaves` drift KAT is why that
    /// comparison holds on a sound tree.
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
        if let Some(snapshot) = self.snapshot_at(reference_height)? {
            // C3: the snapshot answers with its own `n`, so the one thing
            // that must be checked is that its `n` is this height's. A
            // disagreement is refused rather than resolved in the store's
            // favour: a ring row for the wrong height is a defect in the
            // capture, and serving around it would hide it.
            if snapshot.leaf_count() != n {
                return Err(ClientError::SnapshotLeafCountMismatch {
                    height: reference_height,
                    snapshot: snapshot.leaf_count(),
                    expected: n,
                });
            }
            return Self::snapshot_reading(reference_height, &snapshot);
        }
        self.segment_tier_reading_at_count(n)
    }

    /// Root and depth off one snapshot, both taken from **its own** leaf
    /// count (C3). The single place a `Frontier` becomes a reading, so the
    /// production read above and the Q2 examiner below cannot be looking at
    /// two different closures.
    fn snapshot_reading(
        height: BlockHeight,
        snapshot: &Frontier,
    ) -> Result<(CurveTreeRoot, u8), ClientError> {
        let root = snapshot
            .root()
            .map_err(|source| ClientError::Frontier { height, source })?;
        Ok((CurveTreeRoot::from_bytes(root), snapshot.depth()))
    }

    /// The **snapshot tier's** reading at `height`, or `None` where the ring
    /// does not cover it — CT-6 Q2's second tier, as the increment-2
    /// examiner consumes it.
    ///
    /// Root and depth both come from the snapshot's own leaf count. Taking
    /// the depth from the client's drain index instead would weld this tier
    /// to the segment tier on the depth axis, and the two could then never
    /// disagree there — which is precisely the axis C3 pins.
    ///
    /// `None` means "outside the ring". A decode failure or a store error is
    /// an `Err`: a tier that fails has no way to present itself as a gap.
    ///
    /// **Test-visible because only the examiner reads a tier in isolation.**
    /// Production reads the *dispatcher*, [`Self::root_and_depth_at`]. This
    /// is a delegation to the same two internals the dispatcher calls, not a
    /// second read path — grading a path production does not run would grade
    /// a shim.
    #[cfg(test)]
    pub(crate) fn snapshot_tier_reading(
        &self,
        height: BlockHeight,
    ) -> Result<Option<(CurveTreeRoot, u8)>, ClientError> {
        let Some(snapshot) = self.snapshot_at(height)? else {
            return Ok(None);
        };
        Self::snapshot_reading(height, &snapshot).map(Some)
    }

    /// The **segment tier's** reading at `height`: the landed CT-1
    /// composition (frozen `R_k` where the store holds them, recomputed
    /// where it does not) over the drain index's count for that height.
    /// Test-visible for the same reason as [`Self::snapshot_tier_reading`].
    #[cfg(test)]
    pub(crate) fn segment_tier_reading(
        &self,
        height: BlockHeight,
    ) -> Result<(CurveTreeRoot, u8), ClientError> {
        let n = self.drained_leaf_count_at(Self::drained_through(height));
        self.segment_tier_reading_at_count(n)
    }

    fn segment_tier_reading_at_count(&self, n: u64) -> Result<(CurveTreeRoot, u8), ClientError> {
        let root =
            CurveTreeRoot::from_bytes(self.store.root_at_count(n).map_err(ClientError::from)?);
        Ok((root, shekyl_fcmp::tree::layer_count_for_leaves(n)))
    }

    /// Decode the ring's row at `height`, if it has one.
    pub(crate) fn snapshot_at(&self, height: BlockHeight) -> Result<Option<Frontier>, ClientError> {
        Self::snapshot_at_in(&self.store, height)
    }

    /// [`Self::snapshot_at`] against a store this client does not own yet —
    /// the resume path, which runs before there is a `self`.
    fn snapshot_at_in(
        store: &LeafStore,
        height: BlockHeight,
    ) -> Result<Option<Frontier>, ClientError> {
        let Some(bytes) = store
            .frontier_snapshot_at(height)
            .map_err(ClientError::from)?
        else {
            return Ok(None);
        };
        Frontier::decode(&bytes)
            .map(Some)
            .map_err(|source| ClientError::Frontier { height, source })
    }

    /// Heights the snapshot ring currently covers, or `None` when it is
    /// empty — the snapshot tier's `HeightSpan`, read off the rows it has.
    #[cfg(test)]
    pub(crate) fn snapshot_span(&self) -> Result<Option<(BlockHeight, BlockHeight)>, ClientError> {
        self.store
            .frontier_snapshot_span()
            .map_err(ClientError::from)
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

    /// Overwrite (or, with `None`, delete) the ring's row at `height`.
    ///
    /// Test-only. A correct capture and a correct restore write the same
    /// bytes, so a test that wants to know **which** of them a reader
    /// consulted has to change one of those bytes and look.
    #[cfg(test)]
    pub(crate) fn test_set_snapshot(
        &self,
        height: BlockHeight,
        frontier: Option<&Frontier>,
    ) -> Result<(), ClientError> {
        let encoded = frontier.map(Frontier::encode);
        self.store
            .test_set_frontier_snapshot(height, encoded.as_deref())
            .map_err(ClientError::from)
    }

    /// The live frontier's leaf count — what the next block's snapshot will
    /// be captured over. Test-only; production reads the ring.
    #[cfg(test)]
    pub(crate) fn live_frontier_leaf_count(&self) -> u64 {
        self.frontier.leaf_count()
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

// CT-6 increment 2. The oracle fixture and the Q2 examiner live in
// `ct6_oracle` so this file does not absorb them. Increment 4's real-tier
// passes live in `ct6_oracle::ring` and grade both tiers through
// `examine_tier_readings`.
#[cfg(test)]
mod ct6_oracle;

// The leaf fixtures every test under this module builds its chains from.
#[cfg(test)]
pub(crate) mod test_fixtures;

#[cfg(test)]
mod tests {
    use super::test_fixtures::{
        coinbase_block, ingest_coinbase_blocks, ingest_outputs_at, leaf_blob_at, leaf_entry_at,
        leaves_pairwise_distinct, raw_output_at, raw_outputs_at,
    };
    use super::*;
    use crate::recon::{
        assemble_leaf_stream, drained_sorted, newly_drained_at_cutoff, root_from_scalars,
    };
    use crate::types::{BlockHash, CurveTreeRoot};
    use shekyl_consensus::COINBASE_LOCK_WINDOW;

    fn ingest_class_b_fixture_prefix(client: &mut CurveTreeClient, tip: u64) {
        for height in 0..=tip {
            if height == 64 {
                // Two coinbase outputs: the second is the never-draining
                // long-maturity witness (matures at 64 + COINBASE_LOCK_WINDOW
                // = 124, far past the test's 66-block window). Post claim-era
                // cutover the coinbase lock is the longest wire-real maturity,
                // so a near-tip coinbase replaces the old staked fixture.
                ingest_outputs_at(client, height, &raw_outputs_at(height, 2));
            } else {
                ingest_outputs_at(client, height, &raw_outputs_at(height, 1));
            }
        }
    }

    #[test]
    fn newly_drained_from_index_matches_oracle() {
        // Two coinbase outputs (m = h+60) and two regular outputs (m = h+10)
        // per block, so a maturity bucket holds leaves from two blocks and
        // two leaves from each. A one-leaf bucket has one order, and neither
        // side's ordering could be wrong on it.
        let mut client = CurveTreeClient::new();
        for height in 0..=80u64 {
            let cb_outs = [raw_output_at(height, 0), raw_output_at(height, 1)];
            let reg_outs = [raw_output_at(height, 2), raw_output_at(height, 3)];
            let cb_blob = leaf_blob_at(height, 2);
            let reg_blob: Vec<u8> = [leaf_entry_at(height, 2), leaf_entry_at(height, 3)].concat();
            let txs = [
                TxLeafInputs {
                    is_miner: true,
                    leaf_entry_blob: Some(&cb_blob),
                    outputs: &cb_outs,
                },
                TxLeafInputs {
                    is_miner: false,
                    leaf_entry_blob: Some(&reg_blob),
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
        let mut widest = 0;
        for through in 0..=80u64 {
            let from_index = client.newly_drained_from_index(BlockHeight::from_raw(through));
            widest = widest.max(from_index.len());
            assert_eq!(
                from_index,
                newly_drained_at_cutoff(&client.entries, BlockHeight::from_raw(through)),
                "through={through}"
            );
        }
        assert_eq!(
            widest, 4,
            "a bucket must hold both blocks' pairs, or no ordering was compared"
        );
    }

    #[test]
    fn ingest_block_rejects_non_consecutive_heights() {
        let outs = raw_outputs_at(0, 1);
        let blob = leaf_blob_at(0, 1);
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
        let mut client = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut client, 0, 1);
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
        let mut client = CurveTreeClient::new();
        for height in 0..=100u64 {
            let cb_outs = [raw_output_at(height, 0)];
            let reg_outs = [raw_output_at(height, 1)];
            let cb_blob = leaf_entry_at(height, 0);
            let reg_blob = leaf_entry_at(height, 1);
            let txs = [
                TxLeafInputs {
                    is_miner: true,
                    leaf_entry_blob: Some(&cb_blob),
                    outputs: &cb_outs,
                },
                TxLeafInputs {
                    is_miner: false,
                    leaf_entry_blob: Some(&reg_blob),
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
        let outs0 = [raw_output_at(0, 0)];
        let outs1_cb = [raw_output_at(1, 0)];
        let outs1_reg = [raw_output_at(1, 1)];
        let blob0 = leaf_entry_at(0, 0);
        let blob1_cb = leaf_entry_at(1, 0);
        let blob1_reg = leaf_entry_at(1, 1);
        let txs0 = coinbase_block(&outs0, &blob0);
        let txs1 = [
            TxLeafInputs {
                is_miner: true,
                leaf_entry_blob: Some(&blob1_cb),
                outputs: &outs1_cb,
            },
            TxLeafInputs {
                is_miner: false,
                leaf_entry_blob: Some(&blob1_reg),
                outputs: &outs1_reg,
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
        // The test observes its own setup. With identical leaves every
        // ordering produces the same root, and the comparison below could
        // not fail.
        let drained_leaves: Vec<LeafEntry> = drained.iter().map(|entry| **entry).collect();
        assert_eq!(leaves_pairwise_distinct(&drained_leaves), Ok(()));
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
        let (outs0, blob0) = (raw_outputs_at(0, 1), leaf_blob_at(0, 1));
        let (outs1, blob1) = (raw_outputs_at(1, 1), leaf_blob_at(1, 1));
        let txs0 = coinbase_block(&outs0, &blob0);
        let txs1 = coinbase_block(&outs1, &blob1);
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
        let outs = raw_outputs_at(0, 1);
        let blob = leaf_blob_at(0, 1);
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
            .expect("fixture commitment point decompresses");
        assert_eq!(&client.entries[0].leaf[96..128], &cm_x);
        assert_eq!(client.entries[0].identity.cm, cm);
    }

    #[test]
    fn other_target_consumes_index_but_is_not_a_leaf() {
        // [Other, valid]: the Other output advances gindex but is no leaf.
        let mut other = raw_output_at(0, 0);
        other.target = TargetKind::Other;
        let outs = [other, raw_output_at(0, 1)];
        let blob = leaf_blob_at(0, 2); // one entry per vout
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
        let out0 = raw_outputs_at(0, 1);
        let blob0 = leaf_blob_at(0, 1);
        let txs0 = coinbase_block(&out0, &blob0);
        let out1 = raw_outputs_at(1, 2);
        let blob1 = leaf_blob_at(1, 2);
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

        ingest_outputs_at(&mut orphaned, 66, &raw_outputs_at(66, 1));
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

    /// A ring snapshot that will not decode at open is the store's own row
    /// failing its check: corruption, as the resume path names it.
    #[test]
    fn an_undecodable_snapshot_at_open_is_corruption() {
        let err = ClientError::Frontier {
            height: BlockHeight::from_raw(10),
            source: crate::frontier::FrontierError::InvalidNodeScalars,
        };
        assert_eq!(err.open_fault(), StoreOpenFault::Corrupt);
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
        let outs = raw_outputs_at(0, 1);
        let blob = leaf_blob_at(0, 1);
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
