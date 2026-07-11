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

use shekyl_archival_retention::consensus_state::settlement_epoch_at_height;
use shekyl_archival_retention::{p_canonical_id_from_hybrid_pubkey, ArchivalRewardEmissionVin};
use shekyl_engine_state::pscan_state::{MintLineageOutput, PFundingOutputRecord};
use shekyl_engine_state::transfer::eligible_height;
use shekyl_scanner::{GuaranteedScanner, ScannableBlock};
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch};
use shekyl_units::AtomicUnits;
use shekyl_wire::transaction::{BondPostKind, Input, Transaction};

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

    // Constructor + bounds accessors. Held under a transient allow until the PR-B driving
    // task fully wires them — kept separate from the live `impl` above so the dead-code lint
    // still covers `block_count`/`height_at`.
    #[allow(dead_code)]
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
/// later reconcile pass can act on lifecycle posts (e.g. `Unbond`) without a
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
    pub(crate) p_slot: u32,
    /// Hash of the transaction carrying the output.
    pub(crate) tx_hash: [u8; 32],
    /// The output's index within its transaction — the KEM derivation index.
    pub(crate) index_in_transaction: u64,
    /// The global (chain-wide) output index — the curve-tree leaf position.
    pub(crate) gindex: u64,
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
            tx_hash: m.tx_hash,
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
            tx_hash: r.tx_hash,
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

/// The wire post-kind byte (JoinMarket's dense tag is `0x00`,
/// `shekyl_wire::transaction` §9.11). Single-sourced from the wire crate's own
/// [`BOND_POST_KIND_JOINMARKET`](shekyl_wire::transaction::BOND_POST_KIND_JOINMARKET)
/// so the recorded byte and the confirmation filter in [`PScanAccrual`] cannot
/// drift from the wire definition.
fn post_kind_byte(kind: &BondPostKind) -> u8 {
    match kind {
        BondPostKind::JoinMarket { .. } => shekyl_wire::transaction::BOND_POST_KIND_JOINMARKET,
        BondPostKind::Other(b) => *b,
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
    idx_by_hash: BTreeMap<[u8; 32], usize>,
    /// Computed verdicts: an entry present means "parsed" (possibly empty).
    memo: BTreeMap<[u8; 32], BTreeSet<u32>>,
}

impl<'a> OwnEmissionSlots<'a> {
    fn new(
        transactions: &'a [Transaction],
        transaction_hashes: &'a [[u8; 32]],
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
    fn contains(&mut self, tx_hash: [u8; 32], slot: u32) -> bool {
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
) -> Result<ScanStepResult, DualExtractError> {
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
        let mut bond_post_slots: BTreeMap<[u8; 32], BTreeSet<u32>> = BTreeMap::new();
        let mut emission_slots = OwnEmissionSlots::new(
            &block.transactions,
            &block.block.transaction_hashes,
            known_personas,
        );

        // (b) public bond-post match — reads inputs, no secret, no clone.
        for (j, tx) in block.transactions.iter().enumerate() {
            for input in &tx.prefix.inputs {
                if let Input::BondPost(bp) = input {
                    // Lift the wire `[u8; 32]` into the domain id once, at the
                    // wire→domain boundary, then match + carry the typed value.
                    let id = PCanonicalId::from_bytes(bp.p_canonical_id);
                    if let Some(slot) = known_personas.get(&id) {
                        bond_post_matches.push(BondPostMatch {
                            height,
                            p_canonical_id: id,
                            post_kind: post_kind_byte(&bp.kind),
                        });
                        if let Some(tx_hash) = block.block.transaction_hashes.get(j) {
                            bond_post_slots.entry(*tx_hash).or_default().insert(*slot);
                        }
                    }
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
                    p_slot: *slot,
                    tx_hash,
                    index_in_transaction: wo.index_in_transaction(),
                    gindex: wo.index_on_blockchain(),
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
            }
        }
    }

    let funding = by_epoch
        .into_iter()
        .map(|(epoch, amount)| EpochInflowDelta { epoch, amount })
        .collect();

    Ok(ScanStepResult {
        range,
        funding,
        bond_post_matches,
        funding_outputs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use shekyl_archival_retention::{
        HoldingsDescriptor, HoldingsKind, MembershipOnlyBacking, ShardWorkEntry, WorkEpochClaim,
    };
    use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat, MASTER_SEED_BYTES};
    use shekyl_crypto_pq::archival_p::{derive_archival_p_keys, ArchivalPKeys};
    use shekyl_crypto_pq::kem::HybridKemPublicKey;
    use shekyl_crypto_pq::multisig::{SINGLE_KEY_CANONICAL_LEN, SINGLE_SIG_CANONICAL_LEN};
    use shekyl_scanner::bench_fixtures::{
        build_typical_case_scannable_block, scannable_block_for_recipient,
    };
    use shekyl_wire::transaction::BondPost;
    use shekyl_wire::Holdings;

    use crate::engine::pscan::persona_scanner::guaranteed_scanner_for_persona;

    const SEED: [u8; MASTER_SEED_BYTES] = [0x07u8; MASTER_SEED_BYTES];

    fn persona(slot: u32) -> ArchivalPKeys {
        derive_archival_p_keys(&SEED, DerivationNetwork::Fakechain, SeedFormat::Raw32, slot)
            .expect("derive a test persona")
    }

    /// The cleartext canonical id the way an on-chain bond-post carries it.
    fn canonical_id(p: &ArchivalPKeys) -> PCanonicalId {
        let bytes = p
            .hybrid_bond_id()
            .to_canonical_bytes()
            .expect("hybrid id encodes");
        p_canonical_id_from_hybrid_pubkey(&bytes)
    }

    /// A block carrying one output addressed to `recipient`.
    fn funding_block(recipient: &ArchivalPKeys) -> ScannableBlock {
        let kem = HybridKemPublicKey {
            x25519: recipient.x25519_pk,
            ml_kem: recipient.ml_kem_ek.to_vec(),
        };
        scannable_block_for_recipient(1, &kem, recipient.spend_pk.as_canonical_bytes())
    }

    /// A JoinMarket bond-post for persona `p`.
    fn bond_post_for(p: &ArchivalPKeys) -> BondPost {
        BondPost {
            hybrid_public_key: p.hybrid_bond_id().to_canonical_bytes().expect("encode"),
            p_canonical_id: canonical_id(p).to_bytes(),
            kind: BondPostKind::JoinMarket {
                bond_spend_pk: Vec::new(),
            },
            holdings: Holdings::CompleteTree,
            bonded_total_atomic: 1_000,
            bond_credit: 1_000,
            bond_debit: 0,
        }
    }

    /// A structurally-valid emission vin naming persona `p` as claimant — the
    /// §8.0.2 field set with dummy proof/auth bytes (the rung-1 pre-pass
    /// parses structure; it does not verify proofs or auths, which is the
    /// daemon's C-1 gate). `p_pubkey` is `p`'s real canonical hybrid key so
    /// the §6.1 `p_canonical_id` derivation matches the id the bond post
    /// published.
    fn emission_vin_for(p: &ArchivalPKeys) -> ArchivalRewardEmissionVin {
        ArchivalRewardEmissionVin {
            p_pubkey: p.hybrid_bond_id().to_canonical_bytes().expect("encode"),
            holdings: HoldingsDescriptor {
                kind: HoldingsKind::CompleteTree,
                shard_ids: Vec::new(),
            },
            settlement_epochs: vec![11],
            work_claim: vec![WorkEpochClaim {
                epoch: 11,
                shard_entries: vec![ShardWorkEntry {
                    shard_id: 7,
                    serve_credit_bit: true,
                    scarcity_milli: 850,
                }],
            }],
            backing: MembershipOnlyBacking {
                proof: vec![0xEE; 128],
                pseudo_out: [0x22; 32],
                pqc_pk_hash: [0x33; 32],
                backing_pubkey: vec![0xB2; SINGLE_KEY_CANONICAL_LEN],
                tree_depth: 3,
            },
            reward_amount_plain: vec![1_000_000],
            auth_backing: vec![0xC3; SINGLE_SIG_CANONICAL_LEN],
            auth_claim: vec![0xD4; SINGLE_SIG_CANONICAL_LEN],
        }
    }

    /// The wire input carrying `p`'s emission vin (canonical blob, leading
    /// `0x04` tag included — the shape `shekyl-wire` transports opaquely).
    fn emission_input_for(p: &ArchivalPKeys) -> Input {
        Input::ArchivalRewardEmission {
            canonical_bytes: emission_vin_for(p).serialize().expect("serialize"),
        }
    }

    fn range(start: u64, end: u64) -> BlockRange {
        BlockRange::new(BlockHeight::from_raw(start), BlockHeight::from_raw(end)).expect("range")
    }

    #[test]
    fn block_range_is_non_empty_by_construction() {
        // The invariant the cover-discovery gate (and the scan loop) rely on: a `BlockRange`
        // always covers at least one block. Empty (`start == end`) and inverted
        // (`start > end`) both fail closed to `None`, so no empty range can ever reach a
        // consumer — there is no empty-window edge to re-guard downstream.
        assert!(
            BlockRange::new(BlockHeight::from_raw(5), BlockHeight::from_raw(5)).is_none(),
            "empty range rejected"
        );
        assert!(
            BlockRange::new(BlockHeight::from_raw(6), BlockHeight::from_raw(5)).is_none(),
            "inverted range rejected"
        );
        let r = BlockRange::new(BlockHeight::from_raw(5), BlockHeight::from_raw(6))
            .expect("single-block range is valid");
        assert_eq!(r.block_count(), 1);
    }

    #[test]
    fn funding_sums_owned_outputs_at_the_range_epoch() {
        let p = persona(0);
        let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
        // Height 20_001 → settlement epoch 2 (SETTLEMENT_EPOCH_BLOCKS = 10_000).
        let res = run_dual_extractor(
            vec![(0, scanner)],
            &BTreeMap::new(),
            range(20_001, 20_002),
            &[funding_block(&p)],
        )
        .expect("extract");

        assert_eq!(res.funding.len(), 1, "one epoch touched");
        assert_eq!(res.funding[0].epoch, SettlementEpoch::from_raw(2));
        assert!(
            res.funding[0].amount > AtomicUnits::ZERO,
            "the persona's own output was summed into the epoch delta"
        );
        assert!(res.bond_post_matches.is_empty());
    }

    /// D-A1 consistency gate (WI-2): the per-output funding records and the
    /// per-epoch deltas are two views of the same recovered set — the records'
    /// per-epoch amount sums must equal the deltas exactly, and each record
    /// carries the tagging slot plus a complete public identity.
    #[test]
    fn funding_records_sum_to_the_epoch_deltas_and_carry_the_slot_tag() {
        let p = persona(0);
        let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
        let res = run_dual_extractor(
            vec![(7, scanner)],
            &BTreeMap::new(),
            range(20_001, 20_002),
            &[funding_block(&p)],
        )
        .expect("extract");

        assert!(
            !res.funding_outputs.is_empty(),
            "the recovered output produced a per-output record"
        );
        // sum(records) per epoch == the epoch delta, exactly.
        let mut by_epoch: BTreeMap<SettlementEpoch, AtomicUnits> = BTreeMap::new();
        for rec in &res.funding_outputs {
            let acc = by_epoch.entry(rec.epoch).or_insert(AtomicUnits::ZERO);
            *acc = acc.checked_add(rec.amount).expect("no overflow in test");
        }
        assert_eq!(by_epoch.len(), res.funding.len());
        for delta in &res.funding {
            assert_eq!(by_epoch.get(&delta.epoch), Some(&delta.amount));
        }
        for rec in &res.funding_outputs {
            assert_eq!(rec.p_slot, 7, "record carries the scanner's slot tag");
            assert_eq!(rec.height, BlockHeight::from_raw(20_001));
            assert_ne!(rec.output_key, [0u8; 32], "output key populated");
            assert_ne!(rec.commitment, [0u8; 32], "commitment populated");
            assert!(
                !rec.ciphertext_ml_kem.is_empty(),
                "hybrid ciphertext ML-KEM half preserved for re-derivation"
            );
        }
    }

    /// D-A1 redaction gate: a funding record is a row of `P`'s funding history —
    /// its `Debug` must render the constant placeholder, never fields.
    #[test]
    fn funding_output_match_debug_is_redacted() {
        let p = persona(0);
        let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
        let res = run_dual_extractor(
            vec![(0, scanner)],
            &BTreeMap::new(),
            range(20_001, 20_002),
            &[funding_block(&p)],
        )
        .expect("extract");
        let rec = res.funding_outputs.first().expect("one record");
        assert_eq!(
            format!("{rec:?}"),
            "FundingOutputMatch(<redacted funding-history>)"
        );
    }

    #[test]
    fn bond_post_matches_only_known_canonical_ids() {
        let mine = persona(0);
        let other = persona(1);

        // A foreign block (no outputs we own) carrying two bond-posts: ours + a
        // stranger's. Adding inputs to an existing tx keeps its Ct valid.
        let mut block = build_typical_case_scannable_block(1);
        let tx = block.transactions.get_mut(0).expect("a non-miner tx");
        tx.prefix
            .inputs
            .push(Input::BondPost(Box::new(bond_post_for(&mine))));
        tx.prefix
            .inputs
            .push(Input::BondPost(Box::new(bond_post_for(&other))));

        let scanner = guaranteed_scanner_for_persona(&mine).expect("scanner");
        let known = BTreeMap::from([(canonical_id(&mine), 0)]);
        let res =
            run_dual_extractor(vec![(0, scanner)], &known, range(5, 6), &[block]).expect("extract");

        assert_eq!(
            res.bond_post_matches.len(),
            1,
            "only our canonical id matches; the stranger's post is ignored"
        );
        assert_eq!(res.bond_post_matches[0].p_canonical_id, canonical_id(&mine));
        assert_eq!(res.bond_post_matches[0].height, BlockHeight::from_raw(5));
        assert_eq!(res.bond_post_matches[0].post_kind, 0, "JoinMarket tag");
        assert!(
            res.funding.is_empty(),
            "no outputs we own in a foreign block"
        );
    }

    /// The Unbond-detection seam (2d-1 DQ8): the extractor carries the wire kind
    /// byte unchanged, and that byte equals the consensus `Unbond` discriminant the
    /// task's `record_unbonds` matches on. Pins the cross-crate byte equivalence
    /// (`shekyl-wire` `Other(b)` ↔ `archival_retention::BondPostKind::Unbond`)
    /// end-to-end so it cannot drift before the wire format freezes — the seam was
    /// otherwise only covered by tests that hand-set `post_kind`.
    #[test]
    fn extractor_carries_the_consensus_unbond_byte() {
        let unbond_byte = shekyl_archival_retention::BondPostKind::Unbond as u8;
        assert_eq!(unbond_byte, 2, "genesis-frozen Unbond discriminant");

        let mine = persona(0);
        let mut block = build_typical_case_scannable_block(1);
        let tx = block.transactions.get_mut(0).expect("a non-miner tx");
        // An Unbond bond-post: the consensus Unbond byte on the wire as `Other(b)`
        // (genesis wire is JoinMarket-only, so this models the post-genesis form).
        let mut post = bond_post_for(&mine);
        post.kind = BondPostKind::Other(unbond_byte);
        tx.prefix.inputs.push(Input::BondPost(Box::new(post)));

        let scanner = guaranteed_scanner_for_persona(&mine).expect("scanner");
        let known = BTreeMap::from([(canonical_id(&mine), 0)]);
        let res =
            run_dual_extractor(vec![(0, scanner)], &known, range(5, 6), &[block]).expect("extract");

        assert_eq!(res.bond_post_matches.len(), 1);
        assert_eq!(
            res.bond_post_matches[0].post_kind, unbond_byte,
            "the extractor carries the wire kind byte unchanged through to record_unbonds"
        );
    }

    #[test]
    fn dual_extracts_funding_and_bond_post_in_one_block() {
        let p = persona(0);
        let mut block = funding_block(&p);
        block.transactions[0]
            .prefix
            .inputs
            .push(Input::BondPost(Box::new(bond_post_for(&p))));

        let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
        let known = BTreeMap::from([(canonical_id(&p), 0)]);
        let res =
            run_dual_extractor(vec![(0, scanner)], &known, range(7, 8), &[block]).expect("extract");

        assert_eq!(res.funding.len(), 1, "funding recovered");
        assert_eq!(res.bond_post_matches.len(), 1, "bond-post matched");
    }

    #[test]
    fn rejects_a_range_block_count_mismatch() {
        let p = persona(0);
        let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
        // Range covers 3 blocks; only 1 supplied.
        let err = run_dual_extractor(
            vec![(0, scanner)],
            &BTreeMap::new(),
            range(0, 3),
            &[funding_block(&p)],
        )
        .expect_err("mismatch must fail closed");
        assert!(matches!(
            err,
            DualExtractError::RangeBlockMismatch {
                range_block_count: 3,
                blocks: 1
            }
        ));
    }

    #[test]
    fn rejects_a_step_over_the_dq6_bound() {
        // A range past the bound fails closed before any block work — the guard is
        // on the range size, so no oversized block vec is needed to exercise it.
        let err = run_dual_extractor(
            Vec::new(),
            &BTreeMap::new(),
            range(0, MAX_SCAN_STEP_BLOCKS + 1),
            &[],
        )
        .expect_err("an oversized step must fail closed");
        assert!(matches!(
            err,
            DualExtractError::StepTooLarge { block_count, max }
                if block_count == MAX_SCAN_STEP_BLOCKS + 1 && max == MAX_SCAN_STEP_BLOCKS
        ));
    }

    // ---- GF-4b lineage-classification KATs (§3.3 / §4 item 1) ----

    /// Rung 2: the carrying tx bears the recovered output's **own** persona's
    /// `BondPost`, so the output classifies `BondPostChange`.
    #[test]
    fn lineage_bond_post_change_for_own_bond_post_tx() {
        let p = persona(0);
        let mut block = funding_block(&p);
        block.transactions[0]
            .prefix
            .inputs
            .push(Input::BondPost(Box::new(bond_post_for(&p))));

        let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
        let known = BTreeMap::from([(canonical_id(&p), 0)]);
        let res =
            run_dual_extractor(vec![(0, scanner)], &known, range(5, 6), &[block]).expect("extract");

        let rec = res.funding_outputs.first().expect("one record");
        assert_eq!(rec.lineage, MintLineageOutput::BondPostChange);
    }

    /// Fail-toward-the-forbidden-rung: a plain transfer (no `BondPost` at
    /// all) classifies `ExternalTransfer` — rung 3, never backing-eligible.
    #[test]
    fn lineage_fails_toward_forbidden_for_plain_transfer() {
        let p = persona(0);
        let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
        let res = run_dual_extractor(
            vec![(0, scanner)],
            &BTreeMap::new(),
            range(5, 6),
            &[funding_block(&p)],
        )
        .expect("extract");

        let rec = res.funding_outputs.first().expect("one record");
        assert_eq!(rec.lineage, MintLineageOutput::ExternalTransfer);
    }

    /// Owning-persona attribution (§3.3): a `BondPost` from a *different*
    /// held persona in the carrying tx does **not** lift this persona's
    /// output off rung 3 — the structural proof must be the owner's own
    /// bond post, not any bond post we recognize.
    #[test]
    fn lineage_fails_toward_forbidden_for_another_personas_bond_post() {
        let mine = persona(0);
        let other = persona(1);
        let mut block = funding_block(&mine);
        block.transactions[0]
            .prefix
            .inputs
            .push(Input::BondPost(Box::new(bond_post_for(&other))));

        let scanner = guaranteed_scanner_for_persona(&mine).expect("scanner");
        let known = BTreeMap::from([(canonical_id(&mine), 0), (canonical_id(&other), 1)]);
        let res =
            run_dual_extractor(vec![(0, scanner)], &known, range(5, 6), &[block]).expect("extract");

        let rec = res.funding_outputs.first().expect("one record");
        assert_eq!(
            rec.lineage,
            MintLineageOutput::ExternalTransfer,
            "another persona's bond post is not a structural proof for this output"
        );
    }

    // ---- GF-4b rung-1 (`EmissionReward`) KATs (C-1, §5 item 2) ----
    //
    // Paired positive/negative coverage for the fail-toward-forbidden
    // acceptance criterion (GF4b-4): the own-vin case lifts to rung 1, and
    // *each* non-own case — foreign claimant, another held persona's vin, an
    // unparseable blob, a non-canonical (trailing-bytes) blob, a different tx
    // in the same block, a missing tx hash — stays rung 3. The dangerous
    // failure is a classifier that lifts a non-own case, and only the
    // negative arms catch it.

    /// Rung 1 positive: the carrying tx bears the recovered output's **own**
    /// persona's emission vin, so the output classifies `EmissionReward` —
    /// the reserved variant's first constructor site.
    #[test]
    fn lineage_emission_reward_for_own_emission_vin_tx() {
        let p = persona(0);
        let mut block = funding_block(&p);
        block.transactions[0]
            .prefix
            .inputs
            .push(emission_input_for(&p));

        let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
        let known = BTreeMap::from([(canonical_id(&p), 0)]);
        let res =
            run_dual_extractor(vec![(0, scanner)], &known, range(5, 6), &[block]).expect("extract");

        let rec = res.funding_outputs.first().expect("one record");
        assert_eq!(rec.lineage, MintLineageOutput::EmissionReward);
    }

    /// Fail-toward-forbidden: a **foreign** emission vin (claimant not among
    /// our personas at all) in the carrying tx does not lift our output —
    /// it proves someone else's claim, never ours.
    #[test]
    fn lineage_fails_toward_forbidden_for_foreign_emission_vin() {
        let mine = persona(0);
        let stranger = persona(2);
        let mut block = funding_block(&mine);
        block.transactions[0]
            .prefix
            .inputs
            .push(emission_input_for(&stranger));

        let scanner = guaranteed_scanner_for_persona(&mine).expect("scanner");
        let known = BTreeMap::from([(canonical_id(&mine), 0)]);
        let res =
            run_dual_extractor(vec![(0, scanner)], &known, range(5, 6), &[block]).expect("extract");

        let rec = res.funding_outputs.first().expect("one record");
        assert_eq!(
            rec.lineage,
            MintLineageOutput::ExternalTransfer,
            "a stranger's emission vin is not a structural proof for this output"
        );
    }

    /// Owning-persona attribution (same rule as the bond-post arm): an
    /// emission vin of a *different* held persona in the carrying tx does
    /// **not** lift this persona's output off rung 3 — the structural proof
    /// must be the owner's own vin, not any vin we recognize.
    #[test]
    fn lineage_fails_toward_forbidden_for_another_personas_emission_vin() {
        let mine = persona(0);
        let other = persona(1);
        let mut block = funding_block(&mine);
        block.transactions[0]
            .prefix
            .inputs
            .push(emission_input_for(&other));

        let scanner = guaranteed_scanner_for_persona(&mine).expect("scanner");
        let known = BTreeMap::from([(canonical_id(&mine), 0), (canonical_id(&other), 1)]);
        let res =
            run_dual_extractor(vec![(0, scanner)], &known, range(5, 6), &[block]).expect("extract");

        let rec = res.funding_outputs.first().expect("one record");
        assert_eq!(
            rec.lineage,
            MintLineageOutput::ExternalTransfer,
            "another persona's emission vin is not a structural proof for this output"
        );
    }

    /// Fail-toward-forbidden on parse failure, premise-asserted: the *same*
    /// own-vin blob classifies rung 1 intact (premise — so the corruption is
    /// the only variable), and truncated it classifies rung 3. A pre-pass
    /// that "recovered" a claimant id from a blob the validator-crate reader
    /// rejects would fail this arm.
    #[test]
    fn lineage_fails_toward_forbidden_for_unparseable_emission_blob() {
        let p = persona(0);
        let known = BTreeMap::from([(canonical_id(&p), 0)]);
        let intact = emission_vin_for(&p).serialize().expect("serialize");

        // Premise: the intact blob lifts to rung 1.
        let mut block = funding_block(&p);
        block.transactions[0]
            .prefix
            .inputs
            .push(Input::ArchivalRewardEmission {
                canonical_bytes: intact.clone(),
            });
        let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
        let res =
            run_dual_extractor(vec![(0, scanner)], &known, range(5, 6), &[block]).expect("extract");
        assert_eq!(
            res.funding_outputs.first().expect("one record").lineage,
            MintLineageOutput::EmissionReward,
            "premise: the uncorrupted blob must lift to rung 1, so truncation \
             is the only variable in the negative arm"
        );

        // Negative: the truncated blob fails the parse and stays rung 3.
        let mut truncated = intact;
        truncated.truncate(truncated.len() - 1);
        let mut block = funding_block(&p);
        block.transactions[0]
            .prefix
            .inputs
            .push(Input::ArchivalRewardEmission {
                canonical_bytes: truncated,
            });
        let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
        let res =
            run_dual_extractor(vec![(0, scanner)], &known, range(5, 6), &[block]).expect("extract");
        assert_eq!(
            res.funding_outputs.first().expect("one record").lineage,
            MintLineageOutput::ExternalTransfer,
            "an unparseable emission blob is not a structural proof"
        );
    }

    /// Fail-toward-forbidden on a non-canonical blob: trailing bytes after a
    /// successful field parse stay rung 3. This is the arm the plain reader
    /// would miss (`ArchivalRewardEmissionVin::read` stops at the last
    /// field); it proves the pre-pass's exact-parse discipline is armed.
    #[test]
    fn lineage_fails_toward_forbidden_for_trailing_bytes_in_emission_blob() {
        let p = persona(0);
        let mut padded = emission_vin_for(&p).serialize().expect("serialize");
        padded.push(0x00);
        let mut block = funding_block(&p);
        block.transactions[0]
            .prefix
            .inputs
            .push(Input::ArchivalRewardEmission {
                canonical_bytes: padded,
            });

        let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
        let known = BTreeMap::from([(canonical_id(&p), 0)]);
        let res =
            run_dual_extractor(vec![(0, scanner)], &known, range(5, 6), &[block]).expect("extract");

        let rec = res.funding_outputs.first().expect("one record");
        assert_eq!(
            rec.lineage,
            MintLineageOutput::ExternalTransfer,
            "a trailing-bytes blob is not the canonical vin encoding"
        );
    }

    /// Per-tx keying: our own emission vin in a *different* tx of the same
    /// block does not lift an output of this tx — the structural proof is
    /// "the carrying tx bears the vin", never "the block contains one".
    #[test]
    fn lineage_fails_toward_forbidden_for_emission_vin_in_a_different_tx() {
        let p = persona(0);
        // Tx 0 carries our funding output; a second, foreign tx carries our
        // emission vin. Appending keeps tx 0's outputs and gindexes intact.
        let mut block = funding_block(&p);
        let mut emission_tx = build_typical_case_scannable_block(1)
            .transactions
            .first()
            .expect("a non-miner tx")
            .clone();
        emission_tx.prefix.inputs.push(emission_input_for(&p));
        let emission_tx_hash = emission_tx.hash();
        block.transactions.push(emission_tx);
        block.block.transaction_hashes.push(emission_tx_hash);

        let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
        let known = BTreeMap::from([(canonical_id(&p), 0)]);
        let res =
            run_dual_extractor(vec![(0, scanner)], &known, range(5, 6), &[block]).expect("extract");

        let rec = res.funding_outputs.first().expect("one record");
        assert_eq!(
            rec.lineage,
            MintLineageOutput::ExternalTransfer,
            "an emission vin elsewhere in the block is not a structural proof \
             for this tx's outputs"
        );
    }

    /// The missing-tx-hash arm, at the classifier seam: a tx whose hash is
    /// absent from `transaction_hashes` cannot be keyed, so its outputs
    /// classify rung 3. Tested at the helper because the end-to-end path is
    /// doubly guarded upstream — the scanner refuses a mispaired block
    /// outright (`ScanError::InvalidScannableBlock`) and
    /// `run_dual_extractor`'s debug tripwire fires in test builds — leaving
    /// this arm as the innermost, release-mode defense.
    #[test]
    fn emission_classifier_missing_tx_hash_yields_no_lift() {
        let p = persona(0);
        let known = BTreeMap::from([(canonical_id(&p), 0)]);
        let mut tx = funding_block(&p).transactions.remove(0);
        tx.prefix.inputs.push(emission_input_for(&p));

        // Premise: with its hash present, the tx classifies to our slot —
        // and the memoized second query agrees (the lazy path's cache arm).
        let hash = tx.hash();
        let txs = std::slice::from_ref(&tx);
        let hashes = [hash];
        let mut slots = OwnEmissionSlots::new(txs, &hashes, &known);
        assert!(
            slots.contains(hash, 0),
            "premise: the hash-paired tx classifies, so the missing hash is \
             the only variable in the negative arm"
        );
        assert!(slots.contains(hash, 0), "memoized re-query agrees");

        // Negative: no hash, no classification — nothing to lift.
        let mut slots = OwnEmissionSlots::new(txs, &[], &known);
        assert!(
            !slots.contains(hash, 0),
            "a hash-less tx must not classify (fail toward rung 3)"
        );
    }

    // ---- GF4b-6 spendable-height KATs (§3.6 / §4 item 1) ----

    /// A plain transfer's `spendable_height` is the shared X5 computation's
    /// baseline — `height + SPENDABLE_AGE` — pinned against the *shared
    /// function itself* so the seam cannot drift to a local formula.
    #[test]
    fn spendable_height_plain_transfer_is_the_shared_baseline() {
        use shekyl_engine_state::transfer::SPENDABLE_AGE;

        let p = persona(0);
        let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
        let res = run_dual_extractor(
            vec![(0, scanner)],
            &BTreeMap::new(),
            range(20_001, 20_002),
            &[funding_block(&p)],
        )
        .expect("extract");

        let rec = res.funding_outputs.first().expect("one record");
        assert_eq!(
            rec.spendable_height,
            BlockHeight::from_raw(20_001 + SPENDABLE_AGE)
        );
        assert_eq!(
            rec.spendable_height,
            eligible_height(BlockHeight::from_raw(20_001), shekyl_types::Timelock::None),
            "the seam stores literally the shared eligible_height result"
        );
    }

    /// A coinbase-shaped recovery (`unlock_time = height + 60`, the
    /// consensus-enforced coinbase shape) floors `spendable_height` at the
    /// timelock — the channel through which coinbase maturity reaches the
    /// sweep filter (no miner-tx arm exists).
    #[test]
    fn spendable_height_coinbase_shaped_timelock_floors() {
        let p = persona(0);
        let mut block = funding_block(&p);
        block.transactions[0].prefix.unlock_time = 20_001 + 60;

        let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
        let res = run_dual_extractor(
            vec![(0, scanner)],
            &BTreeMap::new(),
            range(20_001, 20_002),
            &[block],
        )
        .expect("extract");

        let rec = res.funding_outputs.first().expect("one record");
        assert_eq!(
            rec.spendable_height,
            BlockHeight::from_raw(20_061),
            "coinbase-shaped timelock floors above the +SPENDABLE_AGE baseline"
        );
    }

    /// Both new fields survive the rule-18 transform↔state seam round-trip
    /// (the `From` impls are exhaustive struct literals; this pins the
    /// values, not just the compile).
    #[test]
    fn lineage_and_spendable_height_round_trip_the_state_seam() {
        let p = persona(0);
        let mut block = funding_block(&p);
        block.transactions[0].prefix.unlock_time = 20_001 + 60;
        block.transactions[0]
            .prefix
            .inputs
            .push(Input::BondPost(Box::new(bond_post_for(&p))));

        let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
        let known = BTreeMap::from([(canonical_id(&p), 0)]);
        let res = run_dual_extractor(vec![(0, scanner)], &known, range(20_001, 20_002), &[block])
            .expect("extract");

        let m = res.funding_outputs.first().expect("one record");
        let persisted = PFundingOutputRecord::from(m);
        assert_eq!(persisted.lineage, MintLineageOutput::BondPostChange);
        assert_eq!(persisted.spendable_height, BlockHeight::from_raw(20_061));
        let back = FundingOutputMatch::from(&persisted);
        assert_eq!(&back, m, "state→transform restores the exact match");
    }
}
