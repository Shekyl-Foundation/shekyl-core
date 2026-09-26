// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SP-3/SP-5 — the dual-extractor scan-step: the bounded, public message/result
//! types and the pure [`run_dual_extractor`] the actor offloads.
//!
//! ## SP-3 — one block-iteration, two extractors
//!
//! [`run_dual_extractor`] sweeps each block of a [`BlockRange`] with **two**
//! extractors over the same decoded block
//! (`docs/design/ARCHIVAL_BOND_2D1_PSCAN_PLAN.md` §6 SP-3):
//!
//! 1. **Funding** (view-key, *secret*): each bonded persona's
//!    [`GuaranteedScanner`] recovers its owned outputs; their amounts sum per
//!    [`SettlementEpoch`]. The burning-bug-immune `Guaranteed` variant is forced
//!    by the input type (SP-1), so a corrupted-inflow `C_min` mis-size (DQ7) is
//!    unrepresentable here.
//! 2. **Bond-post** (cleartext, *no secret*): the block's `Input::BondPost`s whose
//!    `p_canonical_id` is one of ours are collected for SP-6 reconcile.
//!
//! ## SP-5 — runs inside the actor, offloaded; only public data crosses
//!
//! The [`StakeEngine`](crate::engine::stake_engine) handler clones the bonded
//! union's transient scanners (DQ5) and offloads [`run_dual_extractor`] to
//! `spawn_blocking`. The secret scanners live **only** inside that closure and
//! drop at its end; `view_sk` never crosses the actor boundary. The
//! [`ScanStepResult`] that comes back is public — per-epoch funding *deltas* and
//! public bond-post matches.
//!
//! ## Why the message carries blocks, not heights-only
//!
//! The design sketch had the actor fetch from a `BlockSource` inside the handler;
//! we refine that: the **task** owns the `BlockSource` and fetches
//! (`…PSCAN_PLAN.md` §6 SP-5, "the task owns … the `BlockSource`"), and
//! [`ScanStep`] carries the already-fetched blocks. Blocks are public chain data,
//! so this keeps network I/O out of the single-threaded actor mailbox (the
//! design's own anti-blocking concern, DQ6) without weakening the SP-4
//! anti-injection rule: the message carries blocks, **never** a `PFundingInflow`.
//!
//! ## A scan-step is a *partial* epoch — deltas, not a finalized inflow
//!
//! A settlement epoch is `SETTLEMENT_EPOCH_BLOCKS` (`10_000`) blocks; a bounded
//! scan-step covers far fewer. So a step **cannot** finalize SP-4's
//! `PFundingInflow` (which is a recompute over an epoch's *complete* confirmed
//! set). [`run_dual_extractor`] therefore returns per-epoch *deltas*; the driving
//! task (PR-B) accumulates them and finalizes the per-epoch inflow at epoch-close.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use zeroize::{Zeroize, ZeroizeOnDrop};

use shekyl_archival_retention::consensus_state::settlement_epoch_at_height;
use shekyl_archival_retention::{p_canonical_id_from_hybrid_pubkey, ArchivalRewardEmissionVin};
use shekyl_engine_state::pscan_state::{MintLineageOutput, PFundingOutputRecord};
use shekyl_engine_state::transfer::eligible_height;
use shekyl_scanner::{GuaranteedScanner, ScannableBlock};
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch, TxHash};
use shekyl_units::AtomicUnits;
use shekyl_wire::transaction::{Input, Transaction};

use crate::engine::bond_watch::match_watch;

/// Hard ceiling on the blocks one [`ScanStep`] may carry — the **enforced** form
/// of DQ6's "bounded per message" (the actor holds `&mut self` across the offload,
/// so an unbounded batch stalls its mailbox and balloons memory). This is a
/// fail-closed **backstop** against a task bug or test misuse, *not* the tuning
/// knob: PR-B's driving task sizes real batches far smaller (sized against the
/// worst-case block, to interleave rotation/sign). [`run_dual_extractor`] rejects
/// anything over it.
pub(crate) const MAX_SCAN_STEP_BLOCKS: u64 = 1024;

pub(crate) use block_range::BlockRange;

// `BlockRange` lives in its own module purely for **field privacy**: with `start`/`end`
// private to `block_range`, even `scan_step` itself (and its `tests`) can only obtain one via
// `BlockRange::new`. That turns non-emptiness into a *structural* invariant rather than a
// same-module convention a future edit or a `BlockRange { .. }` literal could silently break.
mod block_range {
    use shekyl_types::BlockHeight;

    /// A bounded, half-open block-height range `[start, end)` — the unit of one scan-step.
    /// **Bounded per message** (DQ6): the driving task loops over small ranges so the actor
    /// interleaves rotation/sign between batches.
    ///
    /// **Non-empty by construction.** The `start`/`end` fields are private to this module, so
    /// the *only* way to obtain a `BlockRange` anywhere — including inside `scan_step` and its
    /// tests — is [`BlockRange::new`], which rejects `start >= end`. Every `BlockRange` that
    /// exists therefore covers at least one block, which is why the cover-discovery gate can
    /// drop its empty-window check without relying on a convention.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct BlockRange {
        start: BlockHeight,
        /// Exclusive upper bound.
        end: BlockHeight,
    }

    impl BlockRange {
        /// Number of blocks in the range — always `>= 1` (non-empty by construction).
        pub(crate) fn block_count(&self) -> u64 {
            self.end.to_raw() - self.start.to_raw()
        }

        /// Height of the `i`-th block in the range (`start + i`). The caller must keep `i` a
        /// valid offset — `(i as u64) < block_count()`, which at the aligned call site is
        /// exactly `i < blocks.len()`. `pub(super)` because only `scan_step`'s
        /// `run_dual_extractor` iterates a range against its aligned blocks.
        pub(super) fn height_at(&self, i: usize) -> BlockHeight {
            BlockHeight::from_raw(self.start.to_raw() + i as u64)
        }
    }

    // Constructor + bounds accessors. `BlockRange::new` is called by the pscan task, so
    // this carries no suppression — kept as a separate `impl` from the one above so the
    // dead-code lint still reports `block_count`/`height_at` individually.
    impl BlockRange {
        /// A **non-empty** half-open `[start, end)` range, or `None` if it would be empty or
        /// inverted (`start >= end`). The **sole** constructor: with the fields private to
        /// this module, non-emptiness holds for *every* `BlockRange` value — not merely those
        /// built by external consumers — so the cover-discovery gate relies on it structurally
        /// and the check lives here once rather than being re-asserted at each use.
        pub(crate) fn new(start: BlockHeight, end: BlockHeight) -> Option<Self> {
            (start.to_raw() < end.to_raw()).then_some(Self { start, end })
        }

        /// Inclusive lower bound.
        pub(crate) fn start(&self) -> BlockHeight {
            self.start
        }

        /// Exclusive upper bound.
        pub(crate) fn end(&self) -> BlockHeight {
            self.end
        }
    }
}

/// The actor scan-step message (SP-5): a bounded range and its already-fetched
/// blocks, `blocks[i]` aligned to height `range.start + i`.
///
/// **Public input only.** Blocks are public chain data; there are no secrets and
/// — per SP-4's anti-injection rule — **no `PFundingInflow` inbound**. The only
/// in-crate sender is the P-scan task, which fetches from its `BlockSource`.
pub(crate) struct ScanStep {
    /// The bounded height range this step covers.
    pub(crate) range: BlockRange,
    /// Blocks aligned to `range`: `blocks[i]` is the block at `range.start + i`.
    /// `blocks.len()` must equal `range.block_count()`.
    pub(crate) blocks: Vec<ScannableBlock>,
    /// `P`'s currently-held funding records (public identity, from the task's
    /// accrual as of the frontier) — the authoritative list the actor refreshes
    /// its key-image watch cache from before running the step (SP-R0 arm #1,
    /// DQ-A: derive-on-add / drop-on-prune; the derived key images never leave
    /// the actor except inside the transient [`KeyImageWatchSet`] handed to the
    /// offload closure). A shared snapshot, not a per-step deep copy: the task
    /// re-snapshots only when an ingest changed the list, so the steady-state
    /// step sends an `Arc` bump instead of re-cloning every record's ~1 KB
    /// ML-KEM ciphertext.
    pub(crate) held_funding: Arc<[FundingOutputMatch]>,
}

/// One settlement epoch's confirmed funding **delta** from a single step
/// (public). A step is a partial epoch, so this is a contribution the task
/// accumulates; the per-epoch `PFundingInflow` is finalized at epoch-close.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EpochInflowDelta {
    /// The settlement epoch the contributing blocks fall in.
    pub(crate) epoch: SettlementEpoch,
    /// Checked sum of the confirmed owned-output amounts in this step at `epoch`.
    pub(crate) amount: AtomicUnits,
}

/// A matched archival bond-post (public) — the cleartext half of the dual
/// extractor, for SP-6 reconcile. Carries the height and post-kind byte so a
/// later reconcile pass can act on lifecycle posts (e.g. `Release`) without a
/// re-scan.
///
/// `Debug` is **redacted**: the `(p_canonical_id, height, post_kind)` tuple is a row of
/// `P`'s persona-activity history (the firewall's whole purpose is to keep that
/// off-disk/off-log in the clear), so it carries the same no-clear-`Debug` discipline as
/// its persisted twin [`BondPostRecord`](shekyl_engine_state::pscan_state::BondPostRecord),
/// not the looser treatment a public amount-delta gets.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct BondPostMatch {
    /// Height of the block carrying the post (from the step's range).
    pub(crate) height: BlockHeight,
    /// The matched persona's cleartext canonical id (the domain newtype; the wire
    /// `[u8; 32]` is lifted at the match site below).
    pub(crate) p_canonical_id: PCanonicalId,
    /// Wire post-kind byte (`0` = JoinMarket; otherwise the `Other` tag).
    pub(crate) post_kind: u8,
}

impl std::fmt::Debug for BondPostMatch {
    /// Redacted — see the type docs. Never render the persona-history contents through
    /// a log / error / `{:?}` path.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BondPostMatch(<redacted persona-history>)")
    }
}

/// A recovered `P`-owned funding output's **public identity** (WI-2 D-A1,
/// `ARCHIVAL_BOND_WI2_ASSEMBLY.md` §3.1) — the transform-shaped twin of the
/// persisted [`PFundingOutputRecord`] (rule 18), carrying everything bond
/// assembly needs to select, path-prove, and re-derive spend secrets for the
/// output without a targeted network fetch. **No derived secrets** — `y` / `z`
/// / `k_amount` / `combined_shared_secret` stay inside the offload closure and
/// drop with the scanners (DQ5); the spend bundle is re-derived at assemble
/// time inside the actor from `(ciphertext, index_in_transaction)`.
///
/// `Debug` is **redacted**: a row of `P`'s funding history (slot, amount,
/// placement) — the same no-clear-`Debug` discipline as [`BondPostMatch`].
///
/// **Why a separate type when it is byte-identical to [`PFundingOutputRecord`]
/// today** (do not collapse the two without revisiting this): the split is the
/// engine-core↔engine-state *serialization boundary*, not incidental
/// duplication. `PFundingOutputRecord` carries `Serialize`/`Deserialize`/`Schema`
/// and *is* the on-disk format gated by `PSCAN_STATE_VERSION` — changing it is a
/// persisted-schema event (rule 42: version bump + snapshot check). This
/// transform twin is the in-memory scan-extraction result crossing the actor
/// boundary, version-free, so the live scan path can evolve without touching the
/// frozen persisted format. That decoupling is also the seam along which the two
/// are expected to **diverge** once the P posture settles post-GF-7 (a transient
/// scan-time field the disk form should not carry, or vice-versa). The sibling
/// [`BondPostMatch`]/`BondPostRecord` pair is twinned at the same boundary for
/// the same reason. The duplication hazard is compiler-guarded: both `From`
/// impls are exhaustive struct literals, so a field added to either type fails to
/// compile until both types and both impls carry it.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct FundingOutputMatch {
    /// The owning persona's slot ordinal (selects the re-derivation keys).
    pub(crate) p_slot: shekyl_types::PSlot,
    /// The output's index within its transaction — the KEM derivation index.
    pub(crate) index_in_transaction: u64,
    /// The global (chain-wide) output index — the curve-tree leaf position.
    pub(crate) gindex: shekyl_types::GlobalOutputIndex,
    /// The on-chain output key `O` (compressed Edwards bytes).
    pub(crate) output_key: [u8; 32],
    /// The on-chain amount commitment point `C` (compressed Edwards bytes) —
    /// the point, never the opened `(mask, amount)` pair (the mask is a
    /// derived secret).
    pub(crate) commitment: [u8; 32],
    /// X25519 half of the output's hybrid KEM ciphertext (public, on-chain).
    pub(crate) ciphertext_x25519: [u8; 32],
    /// ML-KEM-768 half of the output's hybrid KEM ciphertext (public, on-chain).
    pub(crate) ciphertext_ml_kem: Vec<u8>,
    /// The recovered cleartext amount.
    pub(crate) amount: AtomicUnits,
    /// Height of the block carrying the output.
    pub(crate) height: BlockHeight,
    /// The settlement epoch `height` falls in.
    pub(crate) epoch: SettlementEpoch,
    /// GF-4b mint-lineage rung, classified structurally from the carrying
    /// tx while the block is in hand (`ARCHIVAL_GF4B_BACKING_LINEAGE.md`
    /// §3.3, rung 1 per §5 item 2): a tx carrying the owning persona's own
    /// emission vin → `EmissionReward`; the owner's own `BondPost` input →
    /// `BondPostChange`; anything else fails toward the forbidden rung,
    /// `ExternalTransfer` (which structurally covers the anomalous
    /// coinbase-to-`P` case — `P` never mines, and a coinbase tx cannot
    /// carry a `BondPost` or emission input).
    pub(crate) lineage: MintLineageOutput,
    /// The height this output becomes spendable (its curve-tree insertion
    /// height) — the shared `transfer::eligible_height` result, computed
    /// here at the seam from the block height and the output's
    /// `additional_timelock` (GF4b-6, `ARCHIVAL_GF4B_BACKING_LINEAGE.md`
    /// §3.6). The GF-4b sweep filters on it.
    pub(crate) spendable_height: BlockHeight,
}

impl std::fmt::Debug for FundingOutputMatch {
    /// Redacted — see the type docs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FundingOutputMatch(<redacted funding-history>)")
    }
}

impl From<&FundingOutputMatch> for PFundingOutputRecord {
    /// The rule-18 transform→state seam: field-for-field into the persisted twin.
    fn from(m: &FundingOutputMatch) -> Self {
        PFundingOutputRecord {
            p_slot: m.p_slot,
            index_in_transaction: m.index_in_transaction,
            gindex: m.gindex,
            output_key: m.output_key,
            commitment: m.commitment,
            ciphertext_x25519: m.ciphertext_x25519,
            ciphertext_ml_kem: m.ciphertext_ml_kem.clone(),
            amount: m.amount,
            height: m.height,
            epoch: m.epoch,
            lineage: m.lineage,
            spendable_height: m.spendable_height,
        }
    }
}

impl From<&PFundingOutputRecord> for FundingOutputMatch {
    /// The rule-18 state→transform seam (resume from a sealed state).
    fn from(r: &PFundingOutputRecord) -> Self {
        FundingOutputMatch {
            p_slot: r.p_slot,
            index_in_transaction: r.index_in_transaction,
            gindex: r.gindex,
            output_key: r.output_key,
            commitment: r.commitment,
            ciphertext_x25519: r.ciphertext_x25519,
            ciphertext_ml_kem: r.ciphertext_ml_kem.clone(),
            amount: r.amount,
            height: r.height,
            epoch: r.epoch,
            lineage: r.lineage,
            spendable_height: r.spendable_height,
        }
    }
}

/// A confirmed on-chain spend of one of `P`'s held funding outputs — arm (c)
/// of the extractor (SP-R0 arm #1). Carries exactly the prune key: every
/// consumer (the prune-at-ingest in `PScanAccrual::ingest`, the actor's
/// drop-on-prune) keys on `gindex` alone, so the match carries nothing else —
/// derivable detail (the spend's height) stays out rather than accreting
/// bookkeeping no reader consumes.
///
/// `Debug` is redacted: the match marks that an on-chain spend consumed `P`'s
/// output — a row of `P`'s funding history, the same discipline as
/// [`FundingOutputMatch`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SpentFundingMatch {
    /// The spent output's global index — the prune key into `funding_outputs`.
    pub(crate) gindex: shekyl_types::GlobalOutputIndex,
}

impl std::fmt::Debug for SpentFundingMatch {
    /// Redacted — see the type docs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SpentFundingMatch(<redacted funding-history>)")
    }
}

/// The key-image watch-set (SP-R0 arm #1, DQ-A): key images of `P`'s **held,
/// unspent** funding outputs, derived **in-actor** from the vault and handed to
/// the scan closure so arm (c) can match on-chain spends. Spend material never
/// enters the closure — only the derived tags, mapped to their prune keys.
///
/// ## Containment is structural (DQ-A, ratified 2026-07-18)
///
/// A key image is public only once its output is *spent*; this set is key
/// images of **unspent** outputs — pre-publication values, and as a set a
/// correlated fingerprint of `P`'s live UTXO. It is safe only because it is
/// `≤ view_sk`, transient, and same-process. That contingency is frozen here,
/// not left as a review note:
///
/// - **redacting `Debug`** — no clear log/`{:?}` path, not even a length;
/// - **no `Serialize`/`Deserialize`, ever** — the type cannot be persisted or
///   cross a wire; a refactor that tries to send it over a boundary is a
///   compile error, not a leak. The `watch_set_has_no_serialize_impl`
///   tripwire test enforces this stays true at the source level;
/// - **wipe on drop** (rule 35) — the entries zeroize structurally, so the
///   pre-publication key images do not linger in freed heap, swap, or a core
///   dump after the set (or a transient snapshot of it) drops.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct KeyImageWatchSet {
    /// Entries sorted by key image (binary-search lookup). A sorted `Vec`,
    /// not a `BTreeMap`: the wipe-on-drop leg above needs elements that can
    /// be zeroized in place, which map nodes cannot. Residual bound shared
    /// with every growable zeroizing container: growth/removal may leave
    /// moved copies in spare capacity; every live entry wipes.
    entries: Vec<WatchEntry>,
}

/// One watch entry: the (pre-publication) key image and its public prune key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct WatchEntry {
    key_image: [u8; 32],
    /// Public identity (the curve-tree leaf position) — nothing to wipe.
    #[zeroize(skip)]
    gindex: shekyl_types::GlobalOutputIndex,
}

impl KeyImageWatchSet {
    /// An empty watch-set.
    pub(crate) fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Watch `gindex` under `key_image` (derive-on-add).
    pub(crate) fn insert(&mut self, key_image: [u8; 32], gindex: shekyl_types::GlobalOutputIndex) {
        match self
            .entries
            .binary_search_by(|e| e.key_image.cmp(&key_image))
        {
            Ok(i) => self.entries[i].gindex = gindex,
            Err(i) => self.entries.insert(i, WatchEntry { key_image, gindex }),
        }
    }

    /// The watched gindex `key_image` spends, if any — arm (c)'s match.
    pub(crate) fn lookup(&self, key_image: &[u8; 32]) -> Option<shekyl_types::GlobalOutputIndex> {
        self.entries
            .binary_search_by(|e| e.key_image.cmp(key_image))
            .ok()
            .map(|i| self.entries[i].gindex)
    }

    /// The set of currently-watched gindexes — built once per refresh so the
    /// per-record cache check is a set lookup, not a scan of the whole watch
    /// per held record (which made the refresh quadratic in the held count).
    pub(crate) fn watched_gindexes(&self) -> BTreeSet<shekyl_types::GlobalOutputIndex> {
        self.entries.iter().map(|e| e.gindex).collect()
    }

    /// Drop-on-prune: stop watching `gindex`. Linear over the set — the held
    /// funding set is small (a persona's live outputs), and a second
    /// gindex-keyed index would be a premature optimization (SP-R0 §5 DQ-A
    /// carried pin: note it, don't pre-build it).
    pub(crate) fn remove_gindex(&mut self, gindex: shekyl_types::GlobalOutputIndex) {
        self.entries.retain(|e| e.gindex != gindex);
    }

    /// Drop every entry whose gindex is not in `held` — the task's held list
    /// is authoritative (records-driven, the SP-R0 framing pin).
    pub(crate) fn retain_gindexes(&mut self, held: &BTreeSet<shekyl_types::GlobalOutputIndex>) {
        self.entries.retain(|e| held.contains(&e.gindex));
    }
}

impl Clone for KeyImageWatchSet {
    /// Documented rule-35 `Clone` exception: the only cloner is the `ScanStep`
    /// handler, which hands a transient snapshot into the extractor's
    /// `spawn_blocking` closure (the live cache cannot be borrowed across the
    /// `'static` offload boundary). Both copies wipe on drop; the snapshot
    /// dies with the closure.
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
        }
    }
}

impl std::fmt::Debug for KeyImageWatchSet {
    /// Redacted — see the type docs (not even the length renders).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyImageWatchSet(<redacted live-utxo-fingerprint>)")
    }
}

/// The extractor's full output: the public [`ScanStepResult`] the task
/// consumes, plus the **trailing key images** — every `ToKey` key image
/// observed at a height after the step's first in-step funding discovery.
///
/// The trailing set exists to close arm (c)'s in-step blind spot: an output
/// discovered at height `h` can be spent at `h' > h` **within the same step**,
/// and its key image is derivable only in-actor *after* the closure returns
/// (spend material never enters the closure, DQ-A). The handler derives the
/// step's discoveries, matches them against this set, and merges any hits into
/// `result.spent_funding` — so the watch has no same-step gap and D-2's
/// absence-as-evidence argument holds without a batch-size caveat. Empty
/// whenever the step discovered nothing (the common case — zero cost). Never
/// crosses the actor→task boundary.
#[derive(Debug)]
pub(crate) struct DualExtractOutput {
    /// The public scan-step result (after the handler's merge).
    pub(crate) result: ScanStepResult,
    /// Key image of every spend input observed after the first in-step
    /// discovery. Public on-chain data (each is already published by its
    /// spend); a plain set — the handler's merge is a membership check, and
    /// the prune key is the gindex, so no per-spend detail rides along.
    pub(crate) trailing_key_images: BTreeSet<[u8; 32]>,
}

/// Public result of one scan-step — only public extraction outputs cross the
/// actor boundary (the secret scanners stay in the offload closure).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ScanStepResult {
    /// The range this step covered (for the task's cursor bookkeeping).
    pub(crate) range: BlockRange,
    /// Per-epoch confirmed funding deltas (sorted by epoch).
    pub(crate) funding: Vec<EpochInflowDelta>,
    /// Bond-posts in this range whose `p_canonical_id` is one of ours.
    pub(crate) bond_post_matches: Vec<BondPostMatch>,
    /// Per-output funding-discovery records (WI-2 D-A1) — public identity only;
    /// per-epoch sums of these equal `funding`'s deltas by construction.
    pub(crate) funding_outputs: Vec<FundingOutputMatch>,
    /// Arm (c): observed spends of held funding outputs — the prune set
    /// (SP-R0 arm #1; includes the handler's in-step trailing merges). The
    /// task removes the matching records on ingest, before the seal.
    pub(crate) spent_funding: Vec<SpentFundingMatch>,
    /// The persona canonical ids this step scanned FOR (the bonded scan
    /// union's public ids). The provenance half of the reconcile evidence:
    /// `bond_post_matches` is complete only over these personas, so the
    /// accrual records each persona's **watch floor** (the first scanned
    /// height it was watched at) from this set — an absence claim is sound
    /// only over `[floor, frontier)`. Public ids; the slot association stays
    /// behind the redacted-Debug persisted map.
    pub(crate) watched_personas: Vec<PCanonicalId>,
}

/// Why a dual-extraction failed. All arms fail **closed** — a corrupted scan
/// mis-sizes a privacy parameter (`C_min`), so we never paper over one.
#[derive(Debug)]
pub(crate) enum DualExtractError {
    /// `blocks.len()` did not equal `range.block_count()` — the task's range↔block
    /// alignment invariant was violated; refuse rather than mis-attribute.
    RangeBlockMismatch {
        range_block_count: u64,
        blocks: usize,
    },
    /// The step exceeded [`MAX_SCAN_STEP_BLOCKS`] — the "bounded per message"
    /// invariant (DQ6) enforced, not merely contracted: an unbounded batch would
    /// stall the single-threaded actor mailbox and balloon memory. Fail closed so
    /// a task bug or test misuse cannot starve rotation/sign.
    StepTooLarge { block_count: u64, max: u64 },
    /// A persona scan returned an error (malformed block / unsupported protocol).
    Scan(shekyl_scanner::ScanError),
    /// An epoch's confirmed inflow summed past `u64::MAX` (an attacker-stuffed or
    /// impossible amount set). Fail closed rather than wrap a money total.
    InflowOverflow { epoch: SettlementEpoch },
}

impl std::fmt::Display for DualExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RangeBlockMismatch {
                range_block_count,
                blocks,
            } => write!(
                f,
                "scan-step range covers {range_block_count} blocks but {blocks} were supplied"
            ),
            Self::StepTooLarge { block_count, max } => write!(
                f,
                "scan-step covers {block_count} blocks, over the {max}-block bound (DQ6)"
            ),
            Self::Scan(e) => write!(f, "persona scan failed: {e}"),
            Self::InflowOverflow { epoch } => {
                write!(f, "funding inflow overflowed u64 at epoch {epoch:?}")
            }
        }
    }
}

impl std::error::Error for DualExtractError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Scan(e) => Some(e),
            Self::RangeBlockMismatch { .. }
            | Self::StepTooLarge { .. }
            | Self::InflowOverflow { .. } => None,
        }
    }
}

/// GF-4b rung-1 classifier (C-1, `ARCHIVAL_GF4B_BACKING_LINEAGE.md` §5
/// item 2): per tx, the set of *our* persona slots whose **own** emission
/// vin the tx carries — the structural proof that lifts the tx's recovered
/// outputs to [`MintLineageOutput::EmissionReward`]. Public data only: an
/// emission vin is on-chain cleartext, and its `p_pubkey → p_canonical_id`
/// derivation ([`p_canonical_id_from_hybrid_pubkey`], the §6.1 rule) is the
/// same one the bond post published, so no secret is touched.
///
/// **Lazy, memoized per tx — hot-path economics.** Parsing an emission vin
/// allocates its proof blob, work-claim rows, and two canonical-length auth
/// vectors, then hashes a ~4 KiB hybrid pubkey — and the verdict is only
/// ever consulted for a tx that recovered one of OUR outputs (rare). An
/// eager per-block pre-pass would pay that parse for every emission vin on
/// chain, scaling every wallet's full P-scan with chain-wide claim volume.
/// [`Self::contains`] therefore parses on first query per tx and memoizes;
/// unqueried txs cost one 32-byte hash→index map entry.
///
/// **Fail-toward-forbidden (GF4b-4), enforced by what does *not* classify.**
/// A tx yields a slot only when *all* of the following hold; each failure
/// yields the empty set, so the caller's classification defaults the output
/// to rung 3 (`ExternalTransfer`):
///
/// - **The blob parses under the archival-retention reader** —
///   [`ArchivalRewardEmissionVin::read`], the crate that *is* the Rust
///   validator for this wire (`shekyl-wire` deliberately carries the vin as
///   an opaque blob; the C++ posture). The reader enforces the §8.0.2
///   structural invariants inline as it parses (canonical key/sig lengths,
///   epoch bounds/ordering, amount positivity, proof-size bounds), so
///   "parses" here means *structurally valid*, not merely "bytes read".
/// - **The parse consumed the blob exactly.** `read` alone stops at the last
///   field; a blob with trailing bytes is not the canonical encoding of the
///   vin it fronts, so it is not a structural proof. Same exact-parse
///   discipline as `read_payload_exact`, applied at this consumption site.
/// - **The derived `p_canonical_id` is one of ours** — a foreign emission vin
///   proves someone *else's* claim, never ours.
/// - **The tx's hash is present** in the positionally-paired
///   `transaction_hashes` — a hash-less tx cannot be keyed, so its outputs
///   cannot be lifted (the same under-classify posture as the bond-post
///   pre-pass; upstream, the scanner refuses a mispaired block outright and
///   the caller's debug tripwire catches it in test builds, so this arm is
///   the innermost of three defenses).
///
/// A misclassification in this direction can only *exclude* a safe output
/// from backing eligibility, never admit an unsafe one (GF4b-4's acceptance
/// criterion for this arm).
struct OwnEmissionSlots<'a> {
    transactions: &'a [Transaction],
    known_personas: &'a BTreeMap<PCanonicalId, u32>,
    /// Positionally-paired hash → tx index (32-byte copies only; built
    /// without touching any vin blob).
    idx_by_hash: BTreeMap<TxHash, usize>,
    /// Computed verdicts: an entry present means "parsed" (possibly empty).
    memo: BTreeMap<TxHash, BTreeSet<u32>>,
}

impl<'a> OwnEmissionSlots<'a> {
    fn new(
        transactions: &'a [Transaction],
        transaction_hashes: &'a [TxHash],
        known_personas: &'a BTreeMap<PCanonicalId, u32>,
    ) -> Self {
        Self {
            transactions,
            known_personas,
            idx_by_hash: transaction_hashes
                .iter()
                .enumerate()
                .map(|(j, h)| (*h, j))
                .collect(),
            memo: BTreeMap::new(),
        }
    }

    /// Whether `tx_hash`'s tx carries `slot`'s own emission vin — parsing
    /// (and memoizing) that one tx's emission vins on first query.
    fn contains(&mut self, tx_hash: TxHash, slot: u32) -> bool {
        if let Some(slots) = self.memo.get(&tx_hash) {
            return slots.contains(&slot);
        }
        let mut slots = BTreeSet::new();
        if let Some(&j) = self.idx_by_hash.get(&tx_hash) {
            for input in &self.transactions[j].prefix.inputs {
                let Input::ArchivalRewardEmission { canonical_bytes } = input else {
                    continue;
                };
                let mut r = canonical_bytes.as_slice();
                let Ok(vin) = ArchivalRewardEmissionVin::read(&mut r) else {
                    continue; // unparseable → no lift → rung 3
                };
                if !r.is_empty() {
                    continue; // trailing bytes → not canonical → rung 3
                }
                let id = p_canonical_id_from_hybrid_pubkey(&vin.p_pubkey);
                if let Some(s) = self.known_personas.get(&id) {
                    slots.insert(*s);
                }
            }
        }
        let contained = slots.contains(&slot);
        self.memo.insert(tx_hash, slots);
        contained
    }
}

/// SP-3 — the dual extractor. Runs **off** the actor thread (the handler offloads
/// it to `spawn_blocking`); the secret `scanners` live only here and drop at
/// return (DQ5). Returns **only** public data.
///
/// `scanners` is the bonded union's slot-tagged scanner set (the tag attributes
/// each recovered output to its owning persona slot for the WI-2 D-A1 funding
/// records); `known_personas` maps the union's cleartext `p_canonical_id`s to
/// their slot ordinals — the id set drives the bond-post match exactly as the
/// former set-shaped input did, and the slot half attributes a matched
/// `BondPost` to the recovered output's **own** persona for the GF-4b lineage
/// classification (`ARCHIVAL_GF4B_BACKING_LINEAGE.md` §3.3); `range` and
/// `blocks` are aligned (`blocks[i]` at `range.start + i`).
pub(crate) fn run_dual_extractor(
    mut scanners: Vec<(u32, GuaranteedScanner)>,
    known_personas: &BTreeMap<PCanonicalId, u32>,
    range: BlockRange,
    blocks: &[ScannableBlock],
    watch: &KeyImageWatchSet,
) -> Result<DualExtractOutput, DualExtractError> {
    // Enforce DQ6's bound first, rather than trust the caller (the actor mailbox
    // is blocked for the step's duration); then check the range↔block alignment.
    if range.block_count() > MAX_SCAN_STEP_BLOCKS {
        return Err(DualExtractError::StepTooLarge {
            block_count: range.block_count(),
            max: MAX_SCAN_STEP_BLOCKS,
        });
    }
    if blocks.len() as u64 != range.block_count() {
        return Err(DualExtractError::RangeBlockMismatch {
            range_block_count: range.block_count(),
            blocks: blocks.len(),
        });
    }

    // Per-epoch confirmed amounts, accumulated with a running checked add so an
    // overflow fails closed immediately. An epoch entry is created lazily (only
    // on a recovered output), so an epoch with nothing of ours yields no delta
    // rather than a spurious zero. The per-output funding records (WI-2 D-A1)
    // accumulate alongside — public identity only; the recovered secrets drop
    // with each `RecoveredWalletOutput` inside this function.
    let mut by_epoch: BTreeMap<SettlementEpoch, AtomicUnits> = BTreeMap::new();
    let mut bond_post_matches = Vec::new();
    let mut funding_outputs = Vec::new();
    // Arm (c) — SP-R0 arm #1. `spent_funding` collects watch hits; the
    // trailing set collects every spend key image seen after the step's first
    // in-step discovery (whose own key image only the actor can derive, after
    // this closure returns — see `DualExtractOutput`). A block's inputs are
    // processed before its outputs are scanned, and a same-block
    // create-and-spend is impossible (membership requires a prior tree root),
    // so "after the first discovery" is exactly the possible blind-spot window.
    let mut spent_funding = Vec::new();
    let mut trailing_key_images: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut discovered_in_step = false;

    for (i, block) in blocks.iter().enumerate() {
        let height = range.height_at(i);
        let epoch = SettlementEpoch::from_raw(settlement_epoch_at_height(height.to_raw()));

        // GF-4b lineage pre-passes (`ARCHIVAL_GF4B_BACKING_LINEAGE.md` §3.3;
        // rung 1: §5 item 2), public data only: per tx, the set of *our*
        // persona slots whose own emission vin it carries (rung 1, the
        // lazy `OwnEmissionSlots` classifier above) and the set posting a `BondPost`
        // in it (rung 2, inline below). `transaction_hashes` is positionally
        // paired with `transactions` (the scanner enforces the length match);
        // a tx whose hash is missing simply gains no map entry, so its outputs
        // fail toward the forbidden rung below. There is no miner/coinbase arm:
        // `P` never mines (owner ruling, §3.3), and a coinbase tx carries only
        // `Input::Gen` — an anomalous coinbase-to-`P` output lands on
        // `ExternalTransfer` structurally.
        //
        // The positional pairing is a scanner invariant; assert it loudly in
        // debug/test so an upstream violation surfaces as a failure rather
        // than a silent lineage downgrade, while release keeps the
        // fail-toward-forbidden `get(j)` (a wallet must not crash on a state
        // it can safely under-classify — same posture as the GF4b-3 survivor
        // tripwire, §3.4).
        debug_assert_eq!(
            block.block.transaction_hashes.len(),
            block.transactions.len(),
            "transaction_hashes must be positionally paired with transactions \
             (scanner invariant); a mismatch would silently degrade GF-4b lineage \
             attribution to ExternalTransfer"
        );
        let mut bond_post_slots: BTreeMap<TxHash, BTreeSet<u32>> = BTreeMap::new();
        let mut emission_slots = OwnEmissionSlots::new(
            &block.transactions,
            &block.block.transaction_hashes,
            known_personas,
        );

        // (b) public bond-post match — reads inputs, no secret, no clone.
        // The lift + id→slot match live in [`match_watch`]; this extractor
        // and the principal scan's bond watch cannot disagree on what a
        // bond-post observation is. The *map* (bonded-persona set here,
        // probe-id cache there) stays with each consumer.
        // (c) spent-key-image match against the actor-derived watch-set
        // (SP-R0 arm #1) — a hit is a confirmed spend of a held funding
        // output, pruned by the task on ingest. Inputs are few; the two
        // walks (key images, then bond posts) stay separate so each
        // consumer of the shared lift stays a one-liner.
        for (j, tx) in block.transactions.iter().enumerate() {
            for input in &tx.prefix.inputs {
                if let Input::ToKey { key_image, .. } = input {
                    if let Some(gindex) = watch.lookup(key_image) {
                        spent_funding.push(SpentFundingMatch { gindex });
                    }
                    if discovered_in_step {
                        trailing_key_images.insert(*key_image);
                    }
                }
            }
            for (obs, slot) in match_watch(tx, known_personas) {
                bond_post_matches.push(BondPostMatch {
                    height,
                    p_canonical_id: obs.p_canonical_id,
                    post_kind: obs.post_kind,
                });
                if let Some(tx_hash) = block.block.transaction_hashes.get(j) {
                    bond_post_slots.entry(*tx_hash).or_default().insert(slot);
                }
            }
        }

        // (a) funding — scan with each bonded persona's scanner. `scan` consumes
        // the block, so clone per scanner; an output belongs to at most one
        // persona, so no cross-scanner double-count. Each recovered output
        // contributes its epoch delta *and* a per-output funding record (WI-2
        // D-A1) — public identity only; the `RecoveredWalletOutput`'s derived
        // secrets drop with it at the end of each iteration.
        for (slot, scanner) in &mut scanners {
            let recovered = scanner
                .scan(block.clone())
                .map_err(DualExtractError::Scan)?;
            for out in recovered.into_inner() {
                // PL-D3 §6.2 (`FCMP_SPEND_LINKABILITY.md`): the scanner has
                // compared the output's published `0x07` entry with the
                // persona's own derivation; an unspendable output is neither
                // bond funding nor a funding record — counting it would fail
                // at post assembly with the money already promised. Loud but
                // anonymous (the D-A1 / rule-82 reconciliation): D-A1 redacts
                // the persona↔funding-tx association (`FundingOutputMatch`'s
                // redacted `Debug`), and any sender can trip this branch
                // against a suspected persona — a slot or tx hash here would
                // hand the log channel exactly what D-A1 withholds. Rule 82
                // is satisfied at the wallet surface (ledger row + CLI name
                // the sending transaction), so the log names neither.
                if out.unspendable().is_some() {
                    tracing::warn!(
                        target: "shekyl_engine_core::pscan",
                        "a persona-scan output failed the PL-D3 leaf-commitment check \
                         and was quarantined (received but unspendable, not counted as \
                         funding); the wallet ledger names the sending transaction"
                    );
                    continue;
                }
                let acc = by_epoch.entry(epoch).or_insert(AtomicUnits::ZERO);
                *acc = acc
                    .checked_add(out.amount())
                    .ok_or(DualExtractError::InflowOverflow { epoch })?;

                let wo = out.wallet_output();
                let ct = out.source_ciphertext();

                // GF-4b classification (§3.3 + §5 item 2), fail-toward-the-
                // forbidden-rung: only a structural proof — the *owning*
                // persona's own emission vin (rung 1) or own bond post
                // (rung 2) in the carrying tx — lifts an output off rung 3.
                // The rung-1 arm is checked first per ladder order; the two
                // proofs cannot coexist on a consensus-valid chain (the wire
                // mixing matrix rejects emission + bond-post in one tx,
                // `shekyl_wire::transaction::validate_context_free_pruned`),
                // and both rungs are equally backing-eligible in
                // `BackingSet`, so the precedence carries no eligibility
                // consequence even off one.
                let tx_hash = wo.transaction();
                let lineage = if emission_slots.contains(tx_hash, *slot) {
                    MintLineageOutput::EmissionReward
                } else if bond_post_slots
                    .get(&tx_hash)
                    .is_some_and(|slots| slots.contains(slot))
                {
                    MintLineageOutput::BondPostChange
                } else {
                    MintLineageOutput::ExternalTransfer
                };

                // GF4b-6 (§3.6): the *shared* eligible-height computation —
                // the one definition of "in the tree yet," also used by the
                // transfer path (X5) — never a local formula. The coinbase
                // +60 arrives through `additional_timelock` (its consensus-
                // enforced `unlock_time` shape); no miner-tx arm exists.
                let spendable_height = eligible_height(height, wo.additional_timelock());

                funding_outputs.push(FundingOutputMatch {
                    p_slot: shekyl_types::PSlot::from_raw(*slot),
                    index_in_transaction: wo.index_in_transaction(),
                    gindex: shekyl_types::GlobalOutputIndex::from_raw(wo.index_on_blockchain()),
                    output_key: wo.key().compress().to_bytes(),
                    commitment: wo.commitment().calculate().compress().to_bytes(),
                    ciphertext_x25519: ct.x25519,
                    ciphertext_ml_kem: ct.ml_kem.clone(),
                    amount: out.amount(),
                    height,
                    epoch,
                    lineage,
                    spendable_height,
                });
                // Arm (c): later blocks in this step may spend this discovery;
                // its key image is derivable only in-actor, so from here on the
                // trailing set collects candidates for the handler's pass.
                discovered_in_step = true;
            }
        }
    }

    let funding = by_epoch
        .into_iter()
        .map(|(epoch, amount)| EpochInflowDelta { epoch, amount })
        .collect();

    Ok(DualExtractOutput {
        result: ScanStepResult {
            range,
            funding,
            bond_post_matches,
            funding_outputs,
            spent_funding,
            watched_personas: known_personas.keys().copied().collect(),
        },
        trailing_key_images,
    })
}

#[cfg(test)]
#[path = "scan_step_tests.rs"]
mod tests;
