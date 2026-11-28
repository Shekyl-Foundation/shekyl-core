// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The stake's two halves (`ARCHIVAL_BOND_WI2_ASSEMBLY.md` §3.3,
//! `ARCHIVAL_BOND_POST_DELAY.md` BD-Q2, BD-Q3): the request seals a plan
//! (funding reserved, delay drawn, nothing signed), and the due block signs
//! it (fill, live fee, sweep at a fresh canonical reference, curve-tree
//! paths, `AssembleBond` ask, checked seal via an independently constructed
//! [`PendingPostStore`]). Secrets stay inside the stake actor (rule 36).

use std::sync::Arc;

use super::local_ledger::LocalLedger;
use shekyl_archival_retention::{
    bond_floor, HoldingsDescriptor, HoldingsKind, ShardSet, ShardSetError,
};
use shekyl_curve_tree::{
    select_reference_height, should_reanchor, BlockHash, CurveTreeRoot, ReferenceBlock,
};
use shekyl_engine_file::WalletFile;
use shekyl_engine_state::pending_post_block::{PendingBondPlan, PlannedPosture, SealAdmission};
use shekyl_rpc_transport::DaemonTarget;
use shekyl_standoff::P_LANE_WEIGHT_CEILING;
use shekyl_types::{BlockHeight, GlobalOutputIndex, PSlot};
use shekyl_units::AtomicUnits;
use tokio::sync::RwLock;

use super::bond_assembly::{
    sweep_funding_outputs, BondAssemblyError, FundingSelection, SpentRecordsDurablyPruned,
    SweepOverflowPolicy,
};
use super::curve_tree_actor::CurveTreeHandle;
use super::fee_policy::{CeilingViolation, FeeEstimatorError, ValidatedFeeEstimates};
use super::fee_snapshot::map_daemon_engine_fee_error;
use super::pending_post_gate::{ForegroundSession, UserPendingPost};
use super::pscan::block_source::daemon_claimed_tip;
use super::pscan::dispatch::PendingPostStore;
use super::pscan::seal_basis::{load_seal_basis, SealBasisError};
use super::pscan::start::{
    load_pscan_state_for_engine, pending_post_store_for_engine, WalletFilePendingSealStore,
};
use shekyl_engine_state::PendingPostBlock;

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
        other => FirstStakeError::FeeEstimate(other),
    })
}

/// The canonical `P`-lane floor fee from one daemon fee snapshot: validated
/// economy tier over [`P_LANE_WEIGHT_CEILING`], the weight limit. **The single fee decision for every `P`-lane spend** — the bond
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
        P_LANE_WEIGHT_CEILING,
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
        // Count-free: the wallet's spendable-record count is P-activity
        // volume (the same class the pending-block Debug redacts); the
        // headroom itself is a public constant and survives.
        BondAssemblyError::TooManyFundingInputs { max, .. } => format!(
            "persona funding is fragmented across more than {max} spendable              outputs — more than one bond post can carry"
        ),
        BondAssemblyError::OutputsUnfillable { minimum, .. } => format!(
            "persona funding leaves too little to fill the {minimum} nonzero outputs a \
             transaction requires; fund the persona and retry"
        ),
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

/// The first-stake refusal the pending-post block owes, if any. Any stake
/// of any stage refuses: the check reads `stake_slots`, which spans every
/// stage, so a stage added later is refused too. An ended stake whose funds
/// are still returning, with nothing else in flight, is its own reason
/// (`ARCHIVAL_BOND_POST_DELAY.md` §3.6, ruled 2026-11-27).
pub(super) fn in_flight_refusal(block: &PendingPostBlock) -> Option<FirstStakeError> {
    if block.stake_slots().is_empty() {
        None
    } else if block.plans().is_empty() && block.posts().is_empty() {
        Some(FirstStakeError::EndedStakeReturning)
    } else {
        Some(FirstStakeError::BondInFlight)
    }
}

/// A post-persist assembly failure on the first-stake surface: an unsaved
/// seal and the signer's own fault keep their types, and anything else
/// renders through the amount-free sanitizer.
pub(super) fn post_assembly_failure(e: StakeEngineError) -> FirstStakeError {
    match e {
        StakeEngineError::Daemon(fault) => FirstStakeError::Daemon(fault),
        StakeEngineError::Assembly(BondAssemblyError::SealNotSaved(error)) => {
            FirstStakeError::SealNotSaved(error)
        }
        e => match e.sign_fault() {
            Some(fault) => FirstStakeError::Signer(fault),
            None => FirstStakeError::Engine(engine_failure_detail(&e)),
        },
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
        | BondAssemblyError::OutputsUnfillable { .. }
        | BondAssemblyError::NoSpendableFunding
        | BondAssemblyError::ReferenceResyncing { .. }
        | BondAssemblyError::OutputNotYetDrained { .. } => {
            FirstStakeError::Funding(funding_refusal_detail(e))
        }
        // Its own arm, because BOTH standing buckets misdiagnose it
        // (rule 82): "fund and retry" makes fragmentation worse, and
        // "corrupt state" is false — the funding is intact, there is just
        // more of it than one bond post's vin headroom carries.
        BondAssemblyError::TooManyFundingInputs { max, .. } => {
            FirstStakeError::FundingFragmented { max: *max }
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
    SupportCompleteTree,
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
    /// A stake is already in flight: a plan waiting for its due block, or a
    /// signed post awaiting its send. The dispatch driver finishes it.
    #[error("a stake is already in flight")]
    BondInFlight,
    /// A stake ended without bonding and its funds are still returning to
    /// the principal balance: its drain is owed. A new persona's funding
    /// never overlaps the last one's drain (`ARCHIVAL_BOND_POST_DELAY.md`
    /// §3.6, ruled 2026-11-27). The drain has no maximum, so while the
    /// network fee stays above what the funds hold, staking waits for the
    /// fee to fall.
    #[error("an ended stake's funds are still returning to the principal balance")]
    EndedStakeReturning,
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
    /// The persona's spendable funding is fragmented across more than the
    /// per-transaction vin headroom
    /// ([`MAX_RETENTION_FUNDING_INPUTS`](super::bond_assembly::MAX_RETENTION_FUNDING_INPUTS))
    /// — W1-clean, and NEITHER standing remedy applies: the funding is
    /// intact (not [`Self::State`]) and funding more makes it worse (not
    /// [`Self::Funding`]). The bond sweep must consume everything (GF-4b),
    /// so it refuses rather than silently bonding a subset; no
    /// consolidation verb exists yet for un-bonded persona funding, so the
    /// actionable half is avoidance — do not split persona funding across
    /// more `stake_in` transfers than the headroom. Carries the headroom
    /// (a public constant), never the wallet's record count (P-activity
    /// volume, the redacted class).
    #[error(
        "persona funding is fragmented across more than {max} spendable outputs —          more than one bond post can carry; consolidate before retrying          (avoid splitting persona funding across more than {max} stake_in transfers)"
    )]
    FundingFragmented {
        /// The per-transaction funding-input headroom (public constant).
        max: usize,
    },
    /// A wallet-state read/decode failed **before** the durable point
    /// (pending seal, pscan seal, persona id, funding arithmetic) —
    /// W1-clean like a funding refusal, but **not** one: funding cannot fix
    /// a corrupt seal, so this arm keeps its own diagnosis instead of the
    /// `-29500` "fund and retry" remedy (rule 82's misdiagnosis guard).
    #[error("staking state unavailable: {0}")]
    State(String),
    /// The node named its own remedy while the bond was being read.
    /// Nothing durable was written. The fault is the sentence.
    #[error("{0}")]
    Daemon(shekyl_rpc_client::DaemonFault),
    /// The daemon fee-estimate query failed — check the daemon connection
    /// and retry; nothing durable was written (W1-clean).
    #[error("bond fee estimate failed: {0}")]
    FeeEstimate(FeeEstimatorError),
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
    /// The bond post's seal was saved, but the save was not confirmed on
    /// disk, so nothing was sent; the seal was removed and a `stake`
    /// re-invoke resumes (Rick, 2026-11-19). The cause is the save's, and
    /// names its fix.
    #[error("the bond post was not sent: {0}")]
    SealNotSaved(#[source] super::error::PersistenceError),
    /// The actor/assembly path failed. If this surfaced after the durable
    /// point it is the W2 window — re-invoke `stake` to resume.
    #[error("stake engine failed: {0}")]
    Engine(String),
    /// The wallet's signer refused the bond post: `-29119`, or the code of
    /// the fault the user can act on. Nothing was sent, and the durable slot
    /// stands, so a later `stake` resumes it (the W2 window).
    #[error("the signer refused the bond post: {0}")]
    Signer(shekyl_tx_builder::SignFault),
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
    /// [`StakePosture::SupportCompleteTree`] instead: that posture is a
    /// permanent, non-earning, unbounded-storage obligation, and choosing
    /// it to route around this refusal is precisely the mistake D-4's
    /// warning gate exists to prevent.
    #[error(
        "market staking assigns a shard automatically, and shard assignment \
         is not built yet: no shards are available to bond. Nothing was written"
    )]
    NoShardsAvailable,
    /// The persona body store could not be filled with every shard this
    /// bond owes (`WSS-Q4`, `WSS-Q15`; `WALLET_SIDE_STORE.md` §6.5.3).
    /// Fill comes before the durable point, so this is W1-clean: nothing
    /// was written and nothing was posted. Each arm names its remedy.
    #[error("{0}; nothing was posted")]
    Fill(CompleteTreeFillError),
}

/// What a sealed plan reports back to the stake entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PlannedStake {
    /// How many funding outputs the plan reserved.
    pub(crate) swept_inputs: usize,
}

/// The holdings a planned posture posts at its due block: the one
/// conversion from a persisted posture into a [`HoldingsDescriptor`].
///
/// # Errors
///
/// [`ShardSetError`] when a market plan's shard list is no longer a valid
/// set (a corrupt record; the request built it from a valid one).
pub(crate) fn planned_holdings(
    posture: &PlannedPosture,
) -> Result<HoldingsDescriptor, ShardSetError> {
    Ok(match posture {
        PlannedPosture::SupportCompleteTree => HoldingsDescriptor {
            kind: HoldingsKind::CompleteTree,
            shard_ids: ShardSet::empty(),
        },
        PlannedPosture::Market { shard_ids } => HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::new(shard_ids.clone())?,
        },
    })
}

impl StakePosture {
    /// The posture as the plan persists it. [`Self::Market`] refuses here,
    /// before anything is written: market staking assigns shards, and shard
    /// assignment is not built.
    pub(crate) fn planned(self) -> Result<PlannedPosture, FirstStakeError> {
        match self {
            Self::Market => Err(FirstStakeError::NoShardsAvailable),
            Self::SupportCompleteTree => Ok(PlannedPosture::SupportCompleteTree),
        }
    }
}

use super::holdings_fill::CompleteTreeFillError;
use super::signer::EngineSignerKind;
use super::stake_engine::{PersonaHandle, StakeEngineError};
use super::stake_persist::PersistedBondTicket;
use super::traits::{DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, RefreshEngine};
use super::Engine;

/// Which reference the funding sweep anchors at.
pub(crate) enum SweepReference {
    /// The ordinary send-path reference for the wallet's own tip
    /// (`tip − REF_ANCHOR_AGE`): the request paths, whose reference is only
    /// the sweep's maturity bar.
    FromWalletTip(BlockHeight),
    /// A named reference: the canonical one for the daemon-claimed tip a due
    /// post is signed against (BD-Q3).
    At(BlockHeight),
}

/// Obtain one [`ReferenceBlock`] via the ordinary send-path anchoring
/// procedure (WI-2 F-6): reorg-safe ∧ not-too-stale (loud) ∧ ingest-available ∧
/// ledger-present. **Not** a hand-rolled `tip − FCMP_REFERENCE_BLOCK_MIN_AGE`.
pub(crate) async fn anchored_reference_block(
    curve_tree: &CurveTreeHandle,
    chain_tip: shekyl_types::BlockHeight,
    block_hash_at: impl FnOnce(shekyl_types::BlockHeight) -> Option<BlockHash>,
) -> Result<(ReferenceBlock, u8), BondAssemblyError> {
    let covered_through = curve_tree
        .ingested_tip_height()
        .await
        .map_err(|err| BondAssemblyError::build("curve-tree ingested tip", format!("{err:?}")))?;
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
    reference_block_at(curve_tree, reference_height, block_hash_at).await
}

/// The [`ReferenceBlock`] at a named `reference_height`: its curve-tree root
/// and block hash, with the tree's depth there. The wallet's tree and ledger need only have reached that
/// block, not the tip it was named for: a due post is signed at the
/// canonical reference for the daemon-claimed tip (BD-Q3), and a wallet one
/// block behind that tip still holds the reference.
pub(crate) async fn reference_block_at(
    curve_tree: &CurveTreeHandle,
    reference_height: shekyl_types::BlockHeight,
    block_hash_at: impl FnOnce(shekyl_types::BlockHeight) -> Option<BlockHash>,
) -> Result<(ReferenceBlock, u8), BondAssemblyError> {
    let covered_through = curve_tree
        .ingested_tip_height()
        .await
        .map_err(|err| BondAssemblyError::build("curve-tree ingested tip", format!("{err:?}")))?;
    if covered_through.is_none_or(|ingested| ingested < reference_height) {
        return Err(BondAssemblyError::ReferenceResyncing {
            detail: "curve tree has not reached the reference",
        });
    }
    let (curve_tree_root, tree_depth) = curve_tree
        .reference_root_and_depth(reference_height)
        .await
        .map_err(|err| BondAssemblyError::build("reference root and depth", format!("{err:?}")))?;
    let block_hash =
        block_hash_at(reference_height).ok_or(BondAssemblyError::ReferenceResyncing {
            detail: "reference-height block hash missing from ledger",
        })?;
    Ok((
        ReferenceBlock {
            height: reference_height,
            curve_tree_root: CurveTreeRoot::from_bytes(curve_tree_root),
            block_hash,
        },
        tree_depth,
    ))
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
    /// Seal the stake's plan at the request (`ARCHIVAL_BOND_POST_DELAY.md`
    /// BD-Q2, BD-Q3): the funding sweep reserves the persona's funding, the
    /// actor draws the delay once, and the plan is sealed with no bytes. The
    /// post is assembled, proved and signed at its due block by
    /// [`Self::sign_bond_at_due`]; nothing is emitted at the request.
    ///
    /// The SP-R0 witness precondition is **discharged** (arm #1, 2026-07-18):
    /// [`SpentRecordsDurablyPruned::arm1_watch_pruning_live`] is the sole
    /// production mint. Tests pass `SpentRecordsDurablyPruned::for_test`.
    #[allow(clippy::too_many_arguments)] // the request's whole input: handle, ticket, posture, fee, witness
    pub(crate) async fn seal_bond_plan(
        self_arc: Arc<RwLock<Self>>,
        handle: PersonaHandle,
        ticket: PersistedBondTicket,
        posture: PlannedPosture,
        fee: AtomicUnits,
        pruning_landed: &SpentRecordsDurablyPruned,
    ) -> Result<PlannedStake, StakeEngineError> {
        let p_slot = handle.p_slot();

        // Brief read: clone the spawn inputs the plan needs.
        let (daemon, stake, curve_tree, pending_gate, chain_tip, tip_hash_at) = {
            let g = self_arc.read().await;
            let stake = g
                .stake_handle()
                .ok_or_else(|| BondAssemblyError::build("plan", "no stake engine"))?;
            let snap = g.ledger.snapshot();
            let chain_tip = g.ledger.synced_height();
            let tip_hash_at = move |h: BlockHeight| snap.block_hash_at(h);
            (
                g.daemon().clone(),
                stake,
                g.curve_tree.clone(),
                g.pending_gate.clone(),
                chain_tip,
                tip_hash_at,
            )
        };
        let store = pending_post_store_for_engine(self_arc.clone(), pending_gate);
        let persona = stake.persona_canonical_id(p_slot).await?;

        // One stake per persona. This early read is an optimistic fast-fail
        // only; the authoritative serialization is `seal_plan` under the
        // write lock, which refuses atomically by persona.
        let already = store
            .read(|block| block.has_live_post_for(&persona))
            .await
            .map_err(|e| BondAssemblyError::build("pending-post read", e))?;
        if already {
            return Err(BondAssemblyError::PendingPostExists.into());
        }

        // The request's count on the daemon-claimed clock: the due is never
        // before it (BD-Q2, elapsed time counts). A node that names its own
        // remedy is answered with that remedy.
        let requested_at = match daemon_claimed_tip(&daemon).await {
            Ok(tip) => tip,
            Err(error) => {
                return Err(match error.own_remedy() {
                    Some(fault) => StakeEngineError::Daemon(fault),
                    None => BondAssemblyError::build("daemon claimed tip", error).into(),
                });
            }
        };

        // The authoritative funding sweep — the SAME body the W1 preflight
        // ran — selects what the plan reserves. Its reference is only the
        // sweep's maturity bar; the post is proved against a fresh one at due.
        let holdings = planned_holdings(&posture)
            .map_err(|e| BondAssemblyError::build("planned holdings", format!("{e:?}")))?;
        let (selection, _reference, snapshot_generation) = Self::sweep_bond_funding(
            self_arc.clone(),
            &store,
            &curve_tree,
            SweepReference::FromWalletTip(chain_tip),
            tip_hash_at,
            p_slot,
            &holdings,
            fee,
            pruning_landed,
            &[],
        )
        .await?;

        // The delay, drawn once (BD-Q2). A refused seal discards it with the
        // plan; an existing plan is never re-drawn.
        let draw = stake.plan_bond_post(handle, ticket).await?;

        let funding_gindexes: Vec<_> = selection.records.iter().map(|r| r.gindex).collect();
        let funded_through = selection
            .records
            .iter()
            .map(|r| r.height)
            .max()
            .unwrap_or(BlockHeight::ZERO);
        let swept_inputs = funding_gindexes.len();
        let plan = PendingBondPlan {
            p_slot,
            persona,
            posture,
            draw,
            requested_at,
            funding_gindexes,
            funded_through,
            wait: None,
        };
        let (admission, durability) = store
            .seal_reporting(
                |block| {
                    // Seal-time reservation re-check under the write lock (see
                    // `classify_seal`): a claim or drain assembled concurrently
                    // may have reserved one of these inputs since the sweep.
                    let admission = block.seal_plan(plan, snapshot_generation);
                    (admission == SealAdmission::Admit, admission)
                },
                move |block| block.remove_plan(&persona).is_some(),
            )
            .await
            .map_err(|e| match e {
                super::pscan::pending_store::SealError::NotSaved(cause) => {
                    BondAssemblyError::SealNotSaved(cause)
                }
                super::pscan::pending_store::SealError::Store(e) => {
                    BondAssemblyError::build("pending-plan seal", e)
                }
            })?;
        match admission {
            SealAdmission::Admit => {}
            SealAdmission::PersonaLive => return Err(BondAssemblyError::PendingPostExists.into()),
            SealAdmission::InputRaced | SealAdmission::Stale => {
                return Err(BondAssemblyError::InputRaced.into())
            }
        }
        // A plan whose save was not confirmed was removed under the seal's own
        // guard (`seal_reporting`); the stake answers with the save's own code
        // (Rick, 2026-11-19).
        super::dispatch_durability::require_confirmed(durability)
            .map_err(BondAssemblyError::SealNotSaved)?;

        Ok(PlannedStake { swept_inputs })
    }

    /// The one funding-sweep body (SA-R1-b): sealed funding records +
    /// reserved gindexes + floor/fee arithmetic (including the
    /// [`BondAssemblyError::BondFloorZero`] typed refusal) + anchored
    /// reference + [`sweep_funding_outputs`]. Both the W1 preflight
    /// ([`Engine::first_stake`], pre-durable) and the authoritative
    /// plan's sweep ([`Engine::seal_bond_plan`], post-durable) and the sweep at
    /// due ([`Engine::sign_bond_at_due`]) call
    /// **this** function, so the two can never drift — the preflight's
    /// W1-clean promise ("assemble cannot refuse on funding after preflight
    /// passed, absent a state change") is exactly their equality.
    #[allow(clippy::too_many_arguments)] // the sweep's full input surface, shared by two call sites
    pub(crate) async fn sweep_bond_funding(
        self_arc: Arc<RwLock<Self>>,
        store: &PendingPostStore<WalletFilePendingSealStore<S, D, L, E, R, P>>,
        curve_tree: &CurveTreeHandle,
        at: SweepReference,
        tip_hash_at: impl FnOnce(BlockHeight) -> Option<BlockHash>,
        p_slot: PSlot,
        holdings: &HoldingsDescriptor,
        fee: AtomicUnits,
        pruning_landed: &SpentRecordsDurablyPruned,
        own: &[GlobalOutputIndex],
    ) -> Result<(FundingSelection, ReferenceBlock, u64), BondAssemblyError> {
        let (reference, _tree_depth) = match at {
            // Anchored ReferenceBlock via the ordinary procedure (WI-2 F-6).
            SweepReference::FromWalletTip(chain_tip) => {
                anchored_reference_block(curve_tree, chain_tip, tip_hash_at).await?
            }
            SweepReference::At(height) => {
                reference_block_at(curve_tree, height, tip_hash_at).await?
            }
        };
        let reference_height = reference.height;

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
        // The stake's own reservation (its plan or never-sent post) is its to
        // spend at due; every other record's still excludes.
        let mut reserved = basis.reserved().clone();
        for g in own {
            reserved.remove(g);
        }
        let funding_records = basis
            .into_pscan()
            .map(|s| s.funding_outputs().to_vec())
            .unwrap_or_default();

        let floor = AtomicUnits::from_raw(bond_floor(
            holdings,
            shekyl_archival_retention::archival_params(),
        ));
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
    /// §5.0 steps 4–6, SA-R1-b typestate-forced order; `ARCHIVAL_BOND_POST_DELAY.md`
    /// BD-Q2, BD-Q3): idempotency/W2 split → **preflight sweep** → **the fill**
    /// (every shard the bond owes is fetched from `node`, verified and written
    /// to the persona body store, `WSS-Q4`) → both before any durable staker
    /// state, so a failure here is W1-clean → `persist_bond_record` (the
    /// durable point: mints the ticket, flips `staking_enabled`, writes
    /// `bonded_slots[slot]`) → [`Self::seal_bond_plan`]. Nothing is signed
    /// here. The dispatch driver signs the post at its due block
    /// ([`Self::sign_bond_at_due`]) and sends it in that tick. **No broadcast**
    /// from this call (SA-DQ-5).
    ///
    /// Entry precondition: a StakeEngine is resident — either the wallet is
    /// already a staker (W2 resume) or this open carried the transient
    /// first-stake intent (SA-R1-a). The caller is the credentialed `stake`
    /// RPC (or an in-process embedder like the GUI).
    ///
    /// A failure **after** `persist_bond_record` and before a confirmed plan
    /// seal is the W2 window: `staking_enabled` and `bonded_slots[slot]` are
    /// durable, and the pending block holds no plan, post, or ended plan.
    /// Recovery is re-invoking `stake` (this function detects the resume and
    /// re-mints the ticket — `persist_bond_record` is re-entrant — then seals
    /// the plan). A plan, a signed post, or an ended plan already in the
    /// block is in flight and refuses. The un-resumed slot is benign by the
    /// `StakingBlock` hint design and, post-genesis, arm #3's backstop.
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
    /// The plan persists the posture (`PlannedPosture`) until the due block,
    /// where it becomes the post's holdings. After the post lands, the
    /// **connected bond record** is the durable, chain-owned marker later
    /// consumers read (the serving pinner derives its obligation from it;
    /// `staking_info` renders it). A W2 resume passes the posture again, and
    /// the seal stores that one.
    pub async fn first_stake(
        self_arc: Arc<RwLock<Self>>,
        node: &DaemonTarget,
        slot: u32,
        posture: StakePosture,
    ) -> Result<FirstStakeOutcome, FirstStakeError> {
        let slot = PSlot::from_raw(slot);
        let (daemon, stake, curve_tree, pending_gate, chain_tip, tip_hash_at, staking) = {
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
            let tip_hash_at = move |h: BlockHeight| snap.block_hash_at(h);
            // One consistent snapshot of the staking block for every guard
            // below (enabled flag, recorded slots, monotone cursor).
            let staking = g.ledger.read().ledger.staking.clone();
            (
                g.daemon().clone(),
                stake,
                g.curve_tree.clone(),
                g.pending_gate.clone(),
                chain_tip,
                tip_hash_at,
                staking,
            )
        };
        // User work always wins (`ENGINE_CADENCE_DRIVER.md` §3): register
        // this user-initiated first-stake on the foreground gauge for its
        // whole assemble→seal span, so the cadence driver's epoch-claim leg
        // yields rather than racing it to the funding set.
        let _foreground = ForegroundSession::enter(UserPendingPost::FirstStake, &pending_gate);
        let store = pending_post_store_for_engine(self_arc.clone(), pending_gate);

        // Idempotency / W2 split (§5.1 + §5.7 W2) — every guard is
        // **wallet-level**, keyed on the wallet's own recorded state rather
        // than the caller-passed slot, so no slot value can route around a
        // refusal. A plan or a signed post is in flight — refuse; an ended
        // plan whose funds are returning refuses with its own reason. A confirmed on-chain post for any bonded persona makes this
        // wallet an active staker — refuse (a second call must not mint a
        // second first-stake). A durable slot with neither a record nor a
        // confirmation is the W2 phantom — resume, and only at a recorded
        // bonded slot.
        let refusal = store
            .read(in_flight_refusal)
            .await
            .map_err(|e| FirstStakeError::State(format!("pending read: {e}")))?;
        if let Some(refusal) = refusal {
            return Err(refusal);
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
        // refused posture costs none of it. The conversions live on
        // [`StakePosture::planned`] and [`planned_holdings`].
        let planned = posture.planned()?;
        let holdings = planned_holdings(&planned)
            .map_err(|e| FirstStakeError::State(format!("planned holdings: {e:?}")))?;
        // The bond fee is derived from the daemon's live estimate over the
        // bond size ceiling (the seam the WI-2 addendum reserved for this
        // entry — overpaying is a miner transfer, never a conservation
        // term), gated by the same ceiling the send path applies —
        // see [`bond_fee_from_estimates`].
        let fee = bond_fee_from_estimates(
            daemon
                .get_fee_estimates()
                .await
                .map_err(|e| FirstStakeError::FeeEstimate(map_daemon_engine_fee_error(e)))?,
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
            SweepReference::FromWalletTip(chain_tip),
            tip_hash_at,
            slot,
            &holdings,
            fee,
            &witness,
            &[],
        )
        .await
        .map(drop)
        .map_err(|e| preflight_error(&e))?;

        // Fill at the request too (WSS-Q4, WSS-Q15): the shards final now
        // are in the persona body store before anything durable is written,
        // so a wallet whose node cannot fill hears it here, W1-clean, and not
        // only when the plan comes due. The fill at due adds the shards that
        // close while the plan waits.
        Self::fill_complete_tree(self_arc.clone(), node, holdings)
            .await
            .map(drop)
            .map_err(FirstStakeError::Fill)?;

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
        // the plan re-runs the funding sweep, and its refusals must not leak
        // the persona figures the preflight arm withholds.
        let planned =
            Self::seal_bond_plan(self_arc.clone(), handle, ticket, planned, fee, &witness)
                .await
                .map_err(post_assembly_failure)?;

        Ok(FirstStakeOutcome {
            p_slot: slot.to_raw(),
            swept_inputs: planned.swept_inputs,
            resumed,
        })
    }
}

/// KAT helpers for the two height couplings (F-2 / F-6).
#[cfg(test)]
#[path = "bond_orchestrator_tests.rs"]
mod tests;

/// The owed-drain refusal and the due-block reference. Split out when
/// `bond_orchestrator_tests.rs` crossed 1000 lines.
#[cfg(test)]
#[path = "bond_orchestrator_due_tests.rs"]
mod due_tests;
