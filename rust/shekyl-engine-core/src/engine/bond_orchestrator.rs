// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! WI-2 Engine-side `assemble_bond_post` orchestrator
//! (`ARCHIVAL_BOND_WI2_ASSEMBLY.md` §3.3).
//!
//! Public half only: pending gate, daemon-claimed-tip `anchor_t0`, anchored
//! [`ReferenceBlock`], funding sweep, curve-tree paths, `AssembleBond` ask,
//! persist-before-return via an independently constructed
//! [`PendingPostStore`](super::pscan::dispatch::PendingPostStore). Secrets stay
//! inside the stake actor (rule 36).

use std::sync::Arc;

use super::local_ledger::LocalLedger;
use shekyl_archival_retention::{bond_floor, HoldingsDescriptor, HoldingsKind, ShardSet};
use shekyl_curve_tree::{
    select_reference_height, should_reanchor, AssembleInput, BlockHeight as CtBlockHeight, Gindex,
    ReferenceBlock,
};
use shekyl_engine_file::WalletFile;
use shekyl_engine_state::pending_post_block::{PendingBondPost, PendingPostState, SealAdmission};
use shekyl_tx_builder::{LeafEntry, TreeContext};
use shekyl_types::{BlockHeight, PSlot};
use shekyl_units::AtomicUnits;
use tokio::sync::RwLock;

use shekyl_curve_tree::ClientError;

use super::bond_assembly::{
    sweep_funding_outputs, BondAssemblyError, FundingInputContext, FundingSelection,
    SpentRecordsDurablyPruned, SweepOverflowPolicy,
};
use super::curve_tree_actor::{CurveTreeHandle, CurveTreeHandleError};
use super::fee_policy::{CeilingViolation, FeeEstimatorError, ValidatedFeeEstimates};
use super::pscan::block_source::daemon_claimed_tip;
use super::pscan::dispatch::PendingPostStore;
use super::pscan::seal_basis::{load_seal_basis, SealBasisError};
use super::pscan::start::{
    load_pscan_state_for_engine, pending_post_store_for_engine, WalletFilePendingSealStore,
};

/// Structural weight ceiling for the `P`-lane fee derivation: the maximum
/// predicted weight of any legal `P`-lane spend — up to
/// [`shekyl_tx_builder::MAX_INPUTS`] funding inputs, up to two outputs
/// (payment/bond + change), any tree depth up to
/// [`shekyl_tx_weight::MAX_TREE_DEPTH`], worst-case fee varint. A fee baked
/// at assembly over this weight clears the daemon's per-byte floor even as
/// estimates move (overpaying is a miner transfer, never a conservation
/// term), and every `P`-lane spend quoting the same ceiling keeps the fee
/// uniform across the lane's tx shapes.
///
/// Until 2026-08-26 this was a hardcoded `32 * 1024`, sized for the
/// single-input bond post — but the drain path spends up to `MAX_INPUTS`
/// funding outputs, and the depth-24 8-input FCMP++ proof **alone** is
/// 33,600 bytes, so a legal multi-input drain weighed more than the ceiling
/// and its quoted fee undercut the daemon's per-byte floor (a relay
/// refusal, and — until the drain lifecycle driver lands — a sealed record
/// bricking that persona's drain lane). The exit-fee reserve derivation
/// (`shekyl-standoff` `reserve.rs`) prices its pessimistic `Unbond` over
/// this same structural shape; its headroom arithmetic is derived against
/// this computed ceiling (currently 80,456 bytes), and the ceiling test
/// ties the two so a KAT-table regeneration that grows the ceiling forces
/// the reserve derivation to be re-run.
pub(crate) fn p_lane_weight_ceiling_bytes() -> usize {
    static CEILING: std::sync::LazyLock<usize> = std::sync::LazyLock::new(|| {
        let mut max = 0;
        for n_in in 1..=shekyl_tx_builder::MAX_INPUTS {
            // The proof-size table is non-monotonic in depth, so scan every
            // legal (inputs, outputs, depth) cell rather than assuming the
            // corner shape is the heaviest.
            for n_out in 1..=2 {
                for tree_depth in 1..=shekyl_tx_weight::MAX_TREE_DEPTH {
                    max = max.max(super::tx_fee_model::predict_weight(
                        super::tx_fee_model::InputCount::clamped(n_in),
                        super::tx_fee_model::OutputCount::clamped(n_out),
                        tree_depth,
                        u64::MAX,
                    ));
                }
            }
        }
        max
    });
    *CEILING
}

/// Bond fee for the first-stake post, from one daemon fee snapshot.
///
/// Named and separated from `first_stake`'s body so the gate is
/// visible and testable: the P-lane's one fee decision (now the shared
/// [`p_lane_floor_fee`] below, which the drain façade also quotes), and
/// until 2026-08-17 it was the one production `get_fee_estimates`
/// consumer that did **not** go through [`ValidatedFeeEstimates`] —
/// reading `economy` straight off the raw snapshot with no ceiling.
/// The bond fee is charged to persona working capital and carries no
/// user-facing control by design (the P-lane pin), so an inflated
/// economy rate would be paid with nobody positioned to see it. That
/// makes this the lane that most needs the ceiling, not the one that
/// can do without it.
///
/// The whole snapshot is validated, not just `economy`: a
/// non-monotonic band is a defect or a lie whichever tier you read,
/// and a bond path more permissive than the send path would be the
/// incoherence.
///
/// # Errors
///
/// [`FirstStakeError::FeeUnreasonable`] when the daemon answered and
/// the ceiling refused it; [`FirstStakeError::FeeEstimate`] when the
/// reply was malformed. The split is by remedy (rule 82), mirroring
/// `-29109` vs `-29102` on the send path.
fn bond_fee_from_estimates(
    estimates: super::traits::FeeEstimates,
) -> Result<AtomicUnits, FirstStakeError> {
    p_lane_floor_fee(estimates).map_err(|e| match e {
        FeeEstimatorError::DaemonFeeUnreasonable(v) => FirstStakeError::FeeUnreasonable(v),
        other => FirstStakeError::FeeEstimate(other.to_string()),
    })
}

/// The canonical `P`-lane floor fee from one daemon fee snapshot: validated
/// economy tier over the [`p_lane_weight_ceiling_bytes`] structural weight
/// ceiling. **The single fee decision for every `P`-lane spend** — the bond
/// post (via [`bond_fee_from_estimates`]) and the WI-RPC-5 drain façade
/// ([`drain_to_principal`](super::drain_facade)) both quote this function, so
/// the P-lane fee-uniformity CONTRACT PIN is one body, not two derivations
/// that can drift. Callers map [`FeeEstimatorError`] onto their own error
/// surface, preserving the `-29109` (refused answer) vs `-29102` (failed
/// query) remedy split.
pub(crate) fn p_lane_floor_fee(
    estimates: super::traits::FeeEstimates,
) -> Result<AtomicUnits, FeeEstimatorError> {
    let estimates = ValidatedFeeEstimates::try_new(estimates)?;
    // `tx_fee::fee_from_weight`, not `FeeRate::calculate_fee_from_weight`:
    // the latter multiplies unchecked and documents that it may panic. The
    // validated cap makes overflow unreachable here, but a wallet path
    // should not be one edit away from aborting the process on a
    // daemon-supplied number.
    Ok(AtomicUnits::from_raw(super::tx_fee_model::fee_from_weight(
        &estimates.economy(),
        p_lane_weight_ceiling_bytes(),
    )))
}

/// What a completed first-stake reports back to the stake entry (public
/// identity only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirstStakeOutcome {
    /// The persona slot the first bond was posted for (raw — the pub
    /// boundary follows the `make_staker_for_test` precedent: no
    /// crate-internal newtype leaks to embedders).
    pub p_slot: u32,
    /// How many funding inputs the sweep consumed (SA-DQ-4: the common case
    /// is exactly 1 — the structured `stake_in` output).
    pub swept_inputs: usize,
    /// Whether this call resumed a W2 crash (durable slot, no post) rather
    /// than starting fresh.
    pub resumed: bool,
}

/// Render a bond-assembly error for the `stake` error surface **without
/// amounts or gindexes** (the error-text discipline: `error.data`/messages
/// are the most-logged surface and must never carry persona funding figures
/// or the funding output's global index — the exact off-chain correlates the
/// firewall keeps dark). Variant identity and non-numeric detail survive;
/// numeric arms are reduced to their names. The **single** sanitizer for
/// every `BondAssemblyError` that reaches the first-stake surface — the
/// preflight refusal, the preflight's internal arms, and (via
/// [`engine_failure_detail`]) the post-persist assemble/sign path.
fn funding_refusal_detail(e: &BondAssemblyError) -> String {
    match e {
        BondAssemblyError::InsufficientFunding { .. } => {
            "insufficient persona funding for the bond floor + fee".to_owned()
        }
        BondAssemblyError::OutputNotYetDrained { .. } => {
            "a persona funding output is not yet drained into the reference tree; \
             wait for the tree to catch up and retry"
                .to_owned()
        }
        other => other.to_string(),
    }
}

/// Render a post-persist actor/assembly failure for the `stake` error
/// surface: the amount-bearing [`BondAssemblyError`] arms nested inside
/// [`StakeEngineError::Assembly`] are routed through
/// [`funding_refusal_detail`] (the assemble path re-runs the funding sweep,
/// so `InsufficientFunding {available, required}` is reachable here too and
/// must not leak persona amounts past the preflight-only sanitizer).
fn engine_failure_detail(e: &StakeEngineError) -> String {
    match e {
        StakeEngineError::Assembly(inner) => {
            format!("bond assembly failed: {}", funding_refusal_detail(inner))
        }
        other => other.to_string(),
    }
}

/// Map a W1 preflight [`BondAssemblyError`] onto the first-stake taxonomy
/// (rule 82): only genuine wait-and-retry states become the
/// [`FirstStakeError::Funding`] refusal (the RPC's `-29500` "fund and retry
/// once synced"); internal build/decode/arithmetic failures become
/// [`FirstStakeError::State`] so the operator is never told to fund their
/// way out of a corrupt state file. Both render through the amount-free
/// sanitizer.
fn preflight_error(e: &BondAssemblyError) -> FirstStakeError {
    match e {
        BondAssemblyError::InsufficientFunding { .. }
        | BondAssemblyError::NoSpendableFunding
        | BondAssemblyError::ReferenceResyncing { .. }
        | BondAssemblyError::OutputNotYetDrained { .. } => {
            FirstStakeError::Funding(funding_refusal_detail(e))
        }
        _ => FirstStakeError::State(funding_refusal_detail(e)),
    }
}

/// Which archival posture a first-stake bonds into
/// (`COMPLETETREE_ACTIVATION.md` D-3).
///
/// **Mandatory on [`Engine::first_stake`], with no default, deliberately.**
/// A defaulted parameter is exactly the `ARCHIVAL_BOND_CONSTRUCTION.md`
/// §9.1 footgun this round exists to close: it makes one posture reachable
/// without anyone stating it, and the posture that would be reachable is
/// the unbounded one. A mandatory enum forces every caller — RPC, CLI,
/// e2e fixture, embedder — to say which obligation it is asking for.
///
/// This amends §9.1 items 1–2 (from "separately-named constructor; the
/// standard entry takes no holdings argument" to "one entry, mandatory
/// posture enum"). The property §9.1 was protecting is preserved and
/// strengthened: opt-in by intent, no default to override, and no
/// select-all affordance anywhere — a caller names a *posture*, never a
/// shard set and never a raw [`HoldingsKind`].
///
/// The **warning** that must precede a foundation choice is not this
/// type's job: D-4 puts it structurally at the RPC boundary (an
/// acknowledgment field whose absence returns the warning text) and in the
/// CLI's typed phrase. The engine trusts that its caller stated intent,
/// because the engine has no user to warn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StakePosture {
    /// Ordinary market archival staking: a per-shard bond over an assigned
    /// subset of the corpus, inside the reward market.
    ///
    /// **A stub in this round** — shard assignment does not exist yet, so
    /// this arm refuses with [`FirstStakeError::NoShardsAvailable`] rather
    /// than posting anything. The refusal is typed and names its remedy
    /// (rule 22: scoped work lands where scoped, and a deferral is
    /// disclosed, never silent). When the assignment round lands, this arm
    /// assigns and posts; **the caller's shape does not change**, which is
    /// why the parameter is a posture rather than a shard set.
    Market,
    /// The Foundation whole-corpus archival backstop: `CompleteTree`
    /// holdings, outside the reward market by holdings shape and fully
    /// inside the penalty economy.
    ///
    /// Never a default and never reachable without a caller naming it
    /// here — the hardcode that used to produce it unconditionally was
    /// deleted in the same change that made this arm opt-in, so no code
    /// state ever existed where an ordinary staker silently owed the
    /// corpus.
    FoundationCompleteTree,
}

/// First-stake refusal/failure taxonomy (rule 82;
/// `ARCHIVAL_STAKE_ACTIVATION_PLAN.md` §5.1/§5.7). Refusals are
/// caller-recoverable states with user-meaning, each carrying the remedy
/// that actually fixes it; `Engine`/`Persist` arms are mid-flow failures
/// whose recovery is a `stake` re-invoke (W2).
#[derive(Debug, thiserror::Error)]
pub enum FirstStakeError {
    /// No StakeEngine is resident — first-stake must enter through the
    /// credentialed open-with-intent (SA-R1-a). An internal sequencing
    /// defect at the caller, not a user refusal.
    #[error("no stake engine resident: first-stake requires the open-with-intent path")]
    NoStakeEngine,
    /// The bond watch recovered (adopted) a staked slot **this session**
    /// (`staking_enabled` with no resident actor — the only way to occupy
    /// that state, since a staker session spawns its actor at open): the
    /// recovered persona's keys are derivable only at open under Model D,
    /// so staking becomes operational at the next open. A **domain**
    /// refusal with a self-contained remedy: close and reopen the wallet,
    /// then retry.
    #[error("staking recovered this session: close and reopen the wallet to finish recovery")]
    RecoveredPendingReopen,
    /// A signed bond post is already sealed and awaiting dispatch (W3): the
    /// stake is in flight; the dispatch driver will broadcast it.
    #[error("a signed bond post is already awaiting dispatch")]
    BondInFlight,
    /// A confirmed bond post exists on-chain for **any** recorded bonded
    /// persona: the wallet is already staking; a second call must not mint
    /// a second first-stake (SA-DQ-1 idempotency). Deliberately
    /// wallet-level, not per-slot — a call naming a different slot must not
    /// slip past the refusal.
    #[error("already staking: a confirmed bond post exists for a bonded persona")]
    AlreadyStaked,
    /// The requested slot is not one a first-stake may act on: a staker
    /// wallet resumes only a **recorded bonded slot** (W2), and a fresh
    /// stake targets only the **monotone cursor** (any other slot would
    /// mint an unrequested second stake or re-activate a rotated-past
    /// persona — the no-reuse privacy invariant). An embedder sequencing
    /// defect or a raced wallet swap; nothing durable was written. Slots
    /// are public-function data (they appear in [`FirstStakeOutcome`]), so
    /// naming them here leaks nothing.
    #[error(
        "first-stake slot mismatch: requested {requested}, expected {expected} \
         (the recorded bonded slot for a resume, the monotone cursor for a fresh stake)"
    )]
    WrongSlot {
        /// The slot the caller passed.
        requested: u32,
        /// The slot a first-stake would act on in the wallet's current state.
        expected: u32,
    },
    /// Funding validation failed **before** any durable staker state was
    /// written (W1-clean): fund the persona (`stake_in`) and/or let the
    /// P-scan catch up, then retry.
    #[error("first-stake funding not ready: {0}")]
    Funding(String),
    /// A wallet-state read/decode failed **before** the durable point
    /// (pending seal, pscan seal, persona id, funding arithmetic) —
    /// W1-clean like a funding refusal, but **not** one: funding cannot fix
    /// a corrupt seal, so this arm keeps its own diagnosis instead of the
    /// `-29500` "fund and retry" remedy (rule 82's misdiagnosis guard).
    #[error("staking state unavailable: {0}")]
    State(String),
    /// The daemon fee-estimate query failed — check the daemon connection
    /// and retry; nothing durable was written (W1-clean).
    #[error("bond fee estimate failed: {0}")]
    FeeEstimate(String),
    /// The daemon *answered* the fee query and the wallet refused the
    /// answer (`ValidatedFeeEstimates`). Distinct from
    /// [`Self::FeeEstimate`] by remedy, exactly as `-29109` is distinct
    /// from `-29102` on the send path: retrying the connection does not
    /// help, because the connection worked. Nothing durable was written
    /// (W1-clean) — the refusal happens before the durable point.
    #[error("bond fee estimate refused: {0}")]
    FeeUnreasonable(CeilingViolation),
    /// The durable staker record could not be written.
    #[error("persisting the bond record failed: {0}")]
    Persist(String),
    /// The actor/assembly path failed. If this surfaced after the durable
    /// point it is the W2 window — re-invoke `stake` to resume.
    #[error("stake engine failed: {0}")]
    Engine(String),
    /// [`StakePosture::Market`] was requested and **no shard assignment
    /// exists yet** (`COMPLETETREE_ACTIVATION.md` §10 item 1): market
    /// staking bonds over an assigned subset of the corpus, and the
    /// mechanism that picks that subset is its own design round.
    ///
    /// A typed refusal with a named remedy rather than a silent deferral
    /// (rule 22), and W1-clean: it fires after the idempotency guards —
    /// so a wallet that is already staking still gets *that* diagnosis,
    /// which is the more specific one — but before the fee estimate, the
    /// funding sweep, and every durable write. Nothing is written, nothing
    /// is swept, and no daemon round trip is spent on a bond that cannot
    /// be assembled.
    ///
    /// **Not** an invitation to pass
    /// [`StakePosture::FoundationCompleteTree`] instead: that posture is a
    /// permanent, non-earning, unbounded-storage obligation, and choosing
    /// it to route around this refusal is precisely the mistake D-4's
    /// warning gate exists to prevent.
    #[error(
        "market staking assigns a shard automatically, and shard assignment \
         is not built yet: no shards are available to bond. Nothing was written"
    )]
    NoShardsAvailable,
}

impl StakePosture {
    /// The holdings this posture posts — the only conversion from an
    /// intent into a [`HoldingsKind`] in the tree. The caller names a
    /// posture and never a kind or a shard set (D-3; the §9.1
    /// no-select-all property).
    ///
    /// [`StakePosture::Market`] refuses rather than posting an empty
    /// `ShardSetCompact`, which consensus rejects at JoinMarket anyway
    /// (`bond_post.rs`, floor-zero protection) — so the alternative to
    /// this refusal is not a smaller bond, it is an invalid one.
    ///
    /// [`StakePosture::FoundationCompleteTree`] is the whole-corpus
    /// backstop: `CompleteTree` carries no shard list by wire rule
    /// (`BondPostError::CompleteTreeWithShardIds`), so the empty set
    /// here is the obligation's *encoding*, not its size.
    pub(crate) fn holdings(self) -> Result<HoldingsDescriptor, FirstStakeError> {
        match self {
            Self::Market => Err(FirstStakeError::NoShardsAvailable),
            Self::FoundationCompleteTree => Ok(HoldingsDescriptor {
                kind: HoldingsKind::CompleteTree,
                shard_ids: ShardSet::empty(),
            }),
        }
    }
}

use super::signer::EngineSignerKind;
use super::stake_engine::{AssembledBondPost, PersonaHandle, StakeEngineError};
use super::stake_persist::PersistedBondTicket;
use super::traits::{DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, RefreshEngine};
use super::Engine;

/// Obtain one [`ReferenceBlock`] via the ordinary send-path anchoring
/// procedure (WI-2 F-6): reorg-safe ∧ not-too-stale (loud) ∧ ingest-available ∧
/// ledger-present. **Not** a hand-rolled `tip − FCMP_REFERENCE_BLOCK_MIN_AGE`.
pub(crate) async fn anchored_reference_block(
    curve_tree: &CurveTreeHandle,
    chain_tip: u64,
    block_hash_at: impl FnOnce(u64) -> Option<[u8; 32]>,
) -> Result<ReferenceBlock, BondAssemblyError> {
    let covered_through = curve_tree
        .ingested_tip_height()
        .await
        .map_err(|err| BondAssemblyError::build("curve-tree ingested tip", format!("{err:?}")))?
        .map(|bh| bh.0);
    let ingested = covered_through.ok_or(BondAssemblyError::ReferenceResyncing {
        detail: "curve tree has not ingested any block yet",
    })?;
    let anchor_tip = chain_tip.min(ingested);
    // Canonical send-path derivation (`tip − REF_ANCHOR_AGE`); reuse the
    // exported helper so this can never silently diverge from it (WI-2 F-6).
    let reference_height =
        select_reference_height(anchor_tip).ok_or(BondAssemblyError::ReferenceResyncing {
            detail: "chain too short to anchor a reference",
        })?;
    if should_reanchor(chain_tip, reference_height) {
        return Err(BondAssemblyError::ReferenceResyncing {
            detail: "tree too far behind to anchor a submittable reference; resync",
        });
    }
    let (curve_tree_root, _depth) = curve_tree
        .reference_root_and_depth(CtBlockHeight(reference_height))
        .await
        .map_err(|err| BondAssemblyError::build("reference root and depth", format!("{err:?}")))?;
    let block_hash =
        block_hash_at(reference_height).ok_or(BondAssemblyError::ReferenceResyncing {
            detail: "reference-height block hash missing from ledger",
        })?;
    Ok(ReferenceBlock {
        height: CtBlockHeight(reference_height),
        curve_tree_root,
        block_hash,
    })
}

#[allow(private_bounds)] // same Engine-trait privacy posture as start_pscan_with
impl<S, D, L, E, R, P> Engine<S, D, L, E, R, P, WalletFile>
where
    S: EngineSignerKind + Send + Sync + 'static,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
    Self: Send + Sync,
{
    /// Engine-side WI-2 assemble orchestrator (`ARCHIVAL_BOND_WI2_ASSEMBLY.md`
    /// §3.3 steps 1–6).
    ///
    /// The SP-R0 witness precondition is **discharged** (arm #1, 2026-07-18):
    /// [`SpentRecordsDurablyPruned::arm1_watch_pruning_live`] is the sole
    /// production mint, so there is **no compile block left on this path** —
    /// go-live is gated only by the #332 staker-activation entry that wires
    /// this orchestrator (nothing else guards it; activation sequencing must
    /// be handled there, not assumed from a witness gap). Tests pass
    /// [`SpentRecordsDurablyPruned::for_test`]. This carries no suppression —
    /// it is reached from wired code; go-live retires with the RPC stake entry
    /// (`docs/FOLLOWUPS.md`).
    pub(crate) async fn assemble_bond_post(
        self_arc: Arc<RwLock<Self>>,
        handle: PersonaHandle,
        ticket: PersistedBondTicket,
        holdings: HoldingsDescriptor,
        fee: AtomicUnits,
        pruning_landed: &SpentRecordsDurablyPruned,
    ) -> Result<AssembledBondPost, StakeEngineError> {
        let p_slot = handle.p_slot();

        // Brief read: clone the spawn inputs the assemble path needs.
        let (daemon, stake, curve_tree, pending_write_lock, chain_tip, tip_hash_at) = {
            let g = self_arc.read().await;
            let stake = g
                .stake_handle()
                .ok_or_else(|| BondAssemblyError::build("assemble", "no stake engine"))?;
            let snap = g.ledger.snapshot();
            let chain_tip = g.ledger.synced_height();
            let tip_hash_at = move |h: u64| snap.block_hash_at(h);
            (
                g.daemon().clone(),
                stake,
                g.curve_tree.clone(),
                g.pending_write_lock.clone(),
                chain_tip,
                tip_hash_at,
            )
        };

        // F-1: independent store over the cloned lock (no Engine-held store).
        let store = pending_post_store_for_engine(self_arc.clone(), pending_write_lock);

        // §3.3 / §3.5: one live post per persona. This early read is an
        // optimistic fast-fail only — it keys on `p_slot` (the sole identity
        // available before assembly; 1:1 with the persona canonical id, which
        // is not derivable until the tx is bound below). The *authoritative*
        // one-post-per-persona serialization is `seal_post` under the write
        // lock (see the final seal), which rejects atomically by persona even
        // if two same-persona assembles race past this gate. Reopening
        // criterion (rule 21): if the RPC entry ever admits concurrent
        // same-persona requests whose wasted proof work becomes a concern,
        // add a per-`p_slot` in-flight reservation held from here to the seal.
        let already = store
            .read(|block| block.posts().iter().any(|p| p.p_slot == p_slot))
            .await
            .map_err(|e| BondAssemblyError::build("pending-post read", e))?;
        if already {
            return Err(BondAssemblyError::PendingPostExists.into());
        }

        // (i) Named daemon-claimed-tip clock for anchor_t0 (never synced/ingested).
        let anchor_t0 = daemon_claimed_tip(&daemon)
            .await
            .map_err(|e| BondAssemblyError::build("daemon claimed tip", e))?;

        // (ii) The authoritative funding sweep — the SAME body the W1
        // preflight ran (`sweep_bond_funding`), re-run at this path's own
        // fresh reference/state so the persist→assemble window cannot ride
        // stale inputs.
        let (selection, reference, snapshot_generation) = Self::sweep_bond_funding(
            self_arc.clone(),
            &store,
            &curve_tree,
            chain_tip,
            tip_hash_at,
            p_slot,
            &holdings,
            fee,
            pruning_landed,
        )
        .await?;
        // SA-R1-c (GF4b-2, owned by the activation round): the common-case
        // bond consumes exactly ONE structured funding input; the on-chain
        // input count is self-privacy, so multi-tranche is a consciously
        // LOGGED exception, never a silent one (and never a consensus
        // refusal — legitimate multi-input bonds exist).
        if selection.records.len() > 1 {
            tracing::warn!(
                swept_inputs = selection.records.len(),
                "multi-input bond post: the common case is one structured stake_in \
                 output; this post reveals its funding-input count on-chain (GF4b-2 \
                 / SA-R1-c consciously-logged exception)"
            );
        }
        // `FundingSelection` is non-empty by construction (the sweep refuses a
        // zero-record consume), so `selection.records` carries ≥1 record and
        // the length-checked `paths[0]` below cannot index an empty vec — this
        // holds even for a degenerate `floor == 0`, which is why the guarantee
        // lives in the sweep rather than an assumed `floor > 0` here.

        let assemble_inputs: Vec<AssembleInput> = selection
            .records
            .iter()
            .map(|r| AssembleInput {
                gindex: Gindex(r.gindex.to_raw()),
                output_key: r.output_key,
                commitment: r.commitment,
            })
            .collect();

        let paths = curve_tree
            .assemble_tx(reference, assemble_inputs)
            .await
            .map_err(|e| match e {
                // The one retryable path-assembly refusal, kept typed across
                // the boundary (a rendered `Build.detail` would force retry
                // policy into substring-matching the error text).
                CurveTreeHandleError::Client(ClientError::OutputNotDrained { gindex, .. }) => {
                    BondAssemblyError::OutputNotYetDrained { gindex: gindex.0 }
                }
                other => BondAssemblyError::build("assemble_tx", format!("{other:?}")),
            })?;
        if paths.len() != selection.records.len() {
            return Err(BondAssemblyError::build(
                "assemble_tx",
                format!(
                    "expected {} paths, got {}",
                    selection.records.len(),
                    paths.len()
                ),
            )
            .into());
        }
        // Non-empty: floor gate + length agreement with a non-empty sweep.
        let first = paths.first().ok_or_else(|| {
            BondAssemblyError::build("assemble_tx", "assemble_tx returned no paths")
        })?;

        let tree_ctx = TreeContext {
            reference_block: first.tree.reference_block,
            tree_root: first.tree.tree_root,
            tree_depth: first.tree.tree_depth,
        };

        let funding: Vec<FundingInputContext> = selection
            .records
            .into_iter()
            .zip(paths)
            .map(|(record, path)| FundingInputContext {
                record,
                leaf_chunk: path
                    .leaf_chunk
                    .iter()
                    .map(|cl| LeafEntry {
                        output_key: cl.output_key,
                        key_image_gen: cl.key_image_gen,
                        commitment: cl.commitment,
                        h_pqc: cl.h_pqc,
                    })
                    .collect(),
                c1_layers: path.c1_layers,
                c2_layers: path.c2_layers,
            })
            .collect();

        let assembled = stake
            .assemble_bond(handle, ticket, holdings, funding, tree_ctx, fee.to_raw())
            .await?;

        // Persist-before-return (§3.3 step 6 / pin P-2).
        let sealed = PendingBondPost {
            p_slot,
            persona: *assembled.bound_tx.persona(),
            tx_bytes: assembled.bound_tx.bytes().to_vec(),
            bond_post_offset_blocks: assembled.bond_post_offset_blocks,
            anchor_t0,
            funding_gindexes: assembled.funding_gindexes.clone(),
            state: PendingPostState::Pending,
        };
        let admission = store
            .mutate(|block| {
                // Seal-time reservation re-check under the write lock — the
                // drain seam's guard, which this path was missing. The
                // `reserved` snapshot read before assembly is stale: a
                // same-persona claim or drain assembled concurrently may have
                // reserved one of these funding inputs since, and persona
                // dedup alone does not see a cross-kind gindex collision.
                //
                // It matters beyond the doomed record it avoids.
                // `PendingPostBlock::remove_settled` retires a claim or drain
                // when the inputs it reserved leave the live funding set, and
                // reads that absence as proof THAT record's transaction
                // confirmed. The inference holds only while one record can
                // reserve a given gindex: if a post and a drain share an input,
                // the post confirming spends it and retires the drain too —
                // reopening a lane whose transaction never landed. This post is
                // not itself retired that way (its evidence is the pscan's own
                // bond-post match), but it can falsify someone else's, so the
                // guard belongs here as much as on the paths it protects.
                let admission = block.seal_post(sealed, snapshot_generation);
                (admission == SealAdmission::Admit, admission)
            })
            .await
            .map_err(|e| BondAssemblyError::build("pending-post seal", e))?;
        match admission {
            SealAdmission::Admit => {}
            SealAdmission::PersonaLive => return Err(BondAssemblyError::PendingPostExists.into()),
            // Same remedy — retry against a fresh snapshot — so both map to the
            // one retryable refusal, whose message names every cause.
            SealAdmission::InputRaced | SealAdmission::Stale => {
                return Err(BondAssemblyError::InputRaced.into())
            }
        }

        Ok(assembled)
    }

    /// The one funding-sweep body (SA-R1-b): sealed funding records +
    /// reserved gindexes + floor/fee arithmetic (including the
    /// [`BondAssemblyError::BondFloorZero`] typed refusal) + anchored
    /// reference + [`sweep_funding_outputs`]. Both the W1 preflight
    /// ([`Engine::first_stake`], pre-durable) and the authoritative
    /// assemble sweep ([`Engine::assemble_bond_post`], post-durable) call
    /// **this** function, so the two can never drift — the preflight's
    /// W1-clean promise ("assemble cannot refuse on funding after preflight
    /// passed, absent a state change") is exactly their equality.
    #[allow(clippy::too_many_arguments)] // the sweep's full input surface, shared by two call sites
    async fn sweep_bond_funding(
        self_arc: Arc<RwLock<Self>>,
        store: &PendingPostStore<WalletFilePendingSealStore<S, D, L, E, R, P>>,
        curve_tree: &CurveTreeHandle,
        chain_tip: u64,
        tip_hash_at: impl FnOnce(u64) -> Option<[u8; 32]>,
        p_slot: PSlot,
        holdings: &HoldingsDescriptor,
        fee: AtomicUnits,
        pruning_landed: &SpentRecordsDurablyPruned,
    ) -> Result<(FundingSelection, ReferenceBlock, u64), BondAssemblyError> {
        // Anchored ReferenceBlock via the ordinary procedure (WI-2 F-6).
        let reference = anchored_reference_block(curve_tree, chain_tip, tip_hash_at).await?;
        let reference_height = BlockHeight::from_raw(reference.height.0);

        // The seal basis is ONE ordered read — pending block, then pscan seal.
        // The order is `load_seal_basis`'s guarantee: loading the pscan seal
        // first (as this path did until review #572 round 6) can pair funding
        // from before a settlement with a generation from after it, so the seal
        // admits an input the settled record already spent. The generation
        // rides out to the seal so `seal_post` can tell whether this
        // selection's basis still holds.
        let basis = load_seal_basis(self_arc, store)
            .await
            .map_err(|e| match e {
                SealBasisError::Pending(e) => BondAssemblyError::build("reserved gindexes", e),
                SealBasisError::PScan(e) => BondAssemblyError::build("pscan state load", e),
            })?;
        let snapshot_generation = basis.generation();
        let reserved = basis.reserved().clone();
        let funding_records = basis
            .into_pscan()
            .map(|s| s.funding_outputs().to_vec())
            .unwrap_or_default();

        let floor = AtomicUnits::from_raw(bond_floor(holdings));
        // Align with the wire builder / retention verifier: a zero floor is
        // structurally invalid holdings, not a sweep-to-empty success that
        // would later index an empty `paths` vector. Typed refusal before
        // any curve-tree work (rule 82).
        if floor == AtomicUnits::ZERO {
            return Err(BondAssemblyError::BondFloorZero);
        }
        let required = floor
            .checked_add(fee)
            .ok_or(BondAssemblyError::AmountOverflow)?;

        // RefuseTooMany: the bond post's consume-everything semantics
        // (GF-4b structural emptiness) forbid a silent subset, and the post
        // carries its own bond vin inside the consensus vin cap — see
        // `MAX_RETENTION_FUNDING_INPUTS`.
        let selection = sweep_funding_outputs(
            pruning_landed,
            &funding_records,
            p_slot,
            &reserved,
            required,
            reference_height,
            SweepOverflowPolicy::RefuseTooMany,
        )?;
        Ok((selection, reference, snapshot_generation))
    }
}

#[allow(private_bounds)]
impl<
        S: EngineSignerKind + Send + Sync + 'static,
        D: DaemonEngine,
        E: EconomicsEngine,
        P: PendingTxEngine,
    > Engine<S, D, LocalLedger, E, super::LocalRefresh, P, WalletFile>
where
    Self: Send + Sync,
{
    /// The first-stake continuation (`ARCHIVAL_STAKE_ACTIVATION_PLAN.md`
    /// §5.0 steps 4–6, SA-R1-b typestate-forced order): idempotency/W2 split
    /// → **preflight sweep** (funding validated before any durable staker
    /// state — a failure here is W1-clean, nothing to reconcile) →
    /// `persist_bond_record` (the durable point: mints the ticket, flips
    /// `staking_enabled`, writes `bonded_slots[slot]`) → sign + assemble →
    /// the `.wallet.pending` seal. **No broadcast** (SA-DQ-5): the post-open
    /// bond dispatch driver sends the sealed post at its GF-7 offset (W3 is
    /// held-across-reopen by the pending seal).
    ///
    /// Entry precondition: a StakeEngine is resident — either the wallet is
    /// already a staker (W2 resume) or this open carried the transient
    /// first-stake intent (SA-R1-a). The caller is the credentialed `stake`
    /// RPC (or an in-process embedder like the GUI).
    ///
    /// A failure **after** `persist_bond_record` is the W2 window: durable
    /// `bonded_slots[slot]` with no pending post. Recovery is re-invoking
    /// `stake` (this function detects the resume case and re-mints the
    /// ticket — `persist_bond_record` is re-entrant); the un-resumed slot is
    /// benign by the `StakingBlock` hint design and, post-genesis, arm #3's
    /// backstop.
    ///
    /// # The posture is the caller's, and it is mandatory
    ///
    /// `posture` names the obligation this bond takes on
    /// ([`StakePosture`], `COMPLETETREE_ACTIVATION.md` D-3). There is no
    /// default: the entry used to hardcode `CompleteTree` ("genesis
    /// posture", the named PR-4c deviation), which made every first-stake
    /// wallet owe the whole corpus without anyone asking for it. That
    /// hardcode is deleted here rather than re-anchored behind a default,
    /// so no code state exists in which an ordinary staker silently owes
    /// the corpus.
    ///
    /// Nothing posture-shaped is persisted, and nothing needs to be: the
    /// posture is realized as the assembled post's `HoldingsDescriptor`,
    /// and from there the **connected bond record** is the durable, chain-
    /// owned marker every later consumer reads (the serving pinner derives
    /// its obligation from it; `staking_info` renders it). A W2 resume
    /// passes the posture again, exactly as the first call did.
    pub async fn first_stake(
        self_arc: Arc<RwLock<Self>>,
        slot: u32,
        posture: StakePosture,
    ) -> Result<FirstStakeOutcome, FirstStakeError> {
        let slot = PSlot::from_raw(slot);
        let (daemon, stake, curve_tree, pending_write_lock, chain_tip, tip_hash_at, staking) = {
            let g = self_arc.read().await;
            let stake = match g.stake_handle() {
                Some(stake) => stake,
                // `staking_enabled` with no resident actor is exactly the
                // mid-session bond-watch recovery state — name the remedy
                // (reopen) rather than reporting an internal sequencing
                // fault over a healthy wallet.
                None if g.ledger.read().ledger.staking.staking_enabled => {
                    return Err(FirstStakeError::RecoveredPendingReopen);
                }
                None => return Err(FirstStakeError::NoStakeEngine),
            };
            let snap = g.ledger.snapshot();
            let chain_tip = g.ledger.synced_height();
            let tip_hash_at = move |h: u64| snap.block_hash_at(h);
            // One consistent snapshot of the staking block for every guard
            // below (enabled flag, recorded slots, monotone cursor).
            let staking = g.ledger.read().ledger.staking.clone();
            (
                g.daemon().clone(),
                stake,
                g.curve_tree.clone(),
                g.pending_write_lock.clone(),
                chain_tip,
                tip_hash_at,
                staking,
            )
        };
        let store = pending_post_store_for_engine(self_arc.clone(), pending_write_lock);

        // Idempotency / W2 split (§5.1 + §5.7 W2) — every guard is
        // **wallet-level**, keyed on the wallet's own recorded state rather
        // than the caller-passed slot, so no slot value can route around a
        // refusal. A signed post awaiting dispatch is W3 — refuse; a
        // confirmed on-chain post for any bonded persona makes this wallet
        // an active staker — refuse (a second call must not mint a second
        // first-stake); a durable slot with NEITHER is the W2 phantom —
        // resume, and only at a recorded bonded slot.
        let pending_exists = store
            .read(|block| !block.posts().is_empty())
            .await
            .map_err(|e| FirstStakeError::State(format!("pending read: {e}")))?;
        if pending_exists {
            return Err(FirstStakeError::BondInFlight);
        }
        let resumed = if staking.staking_enabled {
            let matches = load_pscan_state_for_engine(self_arc.clone())
                .await
                .map_err(|e| FirstStakeError::State(format!("pscan state load: {e}")))?
                .map(|s| s.bond_post_matches().to_vec())
                .unwrap_or_default();
            for &bonded in &staking.bonded_slots {
                // A bond-watch sighting is confirmed on-chain evidence at the
                // same tier as a pscan match — the principal scan OBSERVED
                // this slot's bond post. A probe-adopted slot's pscan seal
                // lags until the P-scan catches up, so without this check the
                // resume path would read "durable slot, no match" (the W2
                // phantom shape) and mint a DUPLICATE JoinMarket post for an
                // already-bonded persona. Checked first: no actor round-trip.
                if staking.bond_sightings.contains_key(&bonded) {
                    return Err(FirstStakeError::AlreadyStaked);
                }
                let id = stake
                    .persona_canonical_id(PSlot::from_raw(bonded))
                    .await
                    .map_err(|e| FirstStakeError::State(e.to_string()))?;
                if matches.iter().any(|m| m.p_canonical_id == id) {
                    return Err(FirstStakeError::AlreadyStaked);
                }
            }
            // A W2 resume acts only on a recorded bonded slot; any other
            // slot would mint an unrequested second first-stake.
            if !staking.bonded_slots.contains(&slot.index()) {
                return Err(FirstStakeError::WrongSlot {
                    requested: slot.to_raw(),
                    expected: staking
                        .bonded_slots
                        .first()
                        .copied()
                        .unwrap_or_else(|| staking.monotone_current_slot_from_record()),
                });
            }
            true
        } else {
            // A fresh first-stake acts only on the monotone cursor: a lower
            // slot would re-activate a rotated-past persona (the no-reuse
            // privacy invariant `persist_bond_record` maintains), a higher
            // one would burn cursor slots. The RPC computes exactly this
            // value; the guard makes the `pub` surface safe for embedders.
            let cursor = staking.monotone_current_slot_from_record();
            if slot.index() != cursor {
                return Err(FirstStakeError::WrongSlot {
                    requested: slot.to_raw(),
                    expected: cursor,
                });
            }
            false
        };

        // After the idempotency/W2 guards and before the fee estimate on
        // purpose. The guards above are pure reads, and their refusals
        // are *more specific* than a refused posture: a wallet with a
        // post in flight should hear `BondInFlight`, not "no shards
        // available" (rule 82's misdiagnosis guard). Everything below is
        // either a daemon round trip, a funding sweep, or durable — so a
        // refused posture costs none of it. The conversion itself lives
        // on [`StakePosture::holdings`].
        let holdings = posture.holdings()?;
        // The bond fee is derived from the daemon's live estimate over the
        // bond size ceiling (the seam the WI-2 addendum reserved for this
        // entry — overpaying is a miner transfer, never a conservation
        // term), gated by the same ceiling the send path applies —
        // see [`bond_fee_from_estimates`].
        let fee = bond_fee_from_estimates(
            daemon
                .get_fee_estimates()
                .await
                .map_err(|e| FirstStakeError::FeeEstimate(e.into().to_string()))?,
        )?;

        // W1 preflight sweep (SA-R1-b, sweep-before-persist): the SAME body
        // the assemble path runs (`sweep_bond_funding` — including the
        // BondFloorZero typed refusal), run BEFORE the durable point so a
        // refusable first-stake fails closed as a non-staker instead of
        // minting a W2 phantom and refusing after it.
        let witness = SpentRecordsDurablyPruned::arm1_watch_pruning_live();
        Self::sweep_bond_funding(
            self_arc.clone(),
            &store,
            &curve_tree,
            chain_tip,
            tip_hash_at,
            slot,
            &holdings,
            fee,
            &witness,
        )
        .await
        .map(drop)
        .map_err(|e| preflight_error(&e))?;

        // The durable point (W1 above it, W2 below it). Re-entrant for the
        // resume path: the slot-set push is idempotent and a fresh ticket is
        // minted regardless (§5.7 W2).
        let ticket = {
            let g = self_arc.read().await;
            g.persist_bond_record(slot)
                .map_err(|e| FirstStakeError::Persist(e.to_string()))?
        };
        let handle = stake
            .mint_handle(slot)
            .await
            .map_err(|e| FirstStakeError::Engine(engine_failure_detail(&e)))?;
        // Post-durable failures render through the amount-free sanitizer:
        // the assemble path re-runs the funding sweep, and its refusals
        // must not leak the persona figures the preflight arm withholds.
        let assembled =
            Self::assemble_bond_post(self_arc.clone(), handle, ticket, holdings, fee, &witness)
                .await
                .map_err(|e| FirstStakeError::Engine(engine_failure_detail(&e)))?;

        Ok(FirstStakeOutcome {
            p_slot: slot.to_raw(),
            swept_inputs: assembled.funding_gindexes.len(),
            resumed,
        })
    }
}

/// KAT helpers for the two height couplings (F-2 / F-6).
#[cfg(test)]
#[path = "bond_orchestrator_tests.rs"]
mod tests;
