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
use shekyl_engine_state::pending_post_block::{PendingBondPost, PendingPostState};
use shekyl_tx_builder::{LeafEntry, TreeContext};
use shekyl_types::{BlockHeight, PSlot};
use shekyl_units::AtomicUnits;
use tokio::sync::RwLock;

use shekyl_curve_tree::ClientError;

use super::bond_assembly::{
    sweep_funding_outputs, BondAssemblyError, FundingInputContext, FundingSelection,
    SpentRecordsDurablyPruned,
};
use super::curve_tree_actor::{CurveTreeHandle, CurveTreeHandleError};
use super::pscan::block_source::daemon_claimed_tip;
use super::pscan::dispatch::PendingPostStore;
use super::pscan::start::{
    load_pscan_state_for_engine, pending_post_store_for_engine, WalletFilePendingSealStore,
};

/// Size ceiling for the first-stake bond-fee derivation: the single-input
/// bond post is far under this, so a fee baked at assembly over this weight
/// clears the daemon's per-byte floor even as estimates move (overpaying is a
/// miner transfer, never a conservation term). Promoted from the PR-4 regtest
/// harness (which now references this constant) to the production seam the
/// WI-2 addendum reserved for the stake entry.
pub(crate) const BOND_SIZE_CEILING_BYTES: usize = 32 * 1024;

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
    /// The durable staker record could not be written.
    #[error("persisting the bond record failed: {0}")]
    Persist(String),
    /// The actor/assembly path failed. If this surfaced after the durable
    /// point it is the W2 window — re-invoke `stake` to resume.
    #[error("stake engine failed: {0}")]
    Engine(String),
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
    /// [`SpentRecordsDurablyPruned::for_test`]. Dead_code allow retires with
    /// the RPC stake entry (`docs/FOLLOWUPS.md`).
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
        // one-post-per-persona serialization is `push_post` under the write
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
        let (selection, reference) = Self::sweep_bond_funding(
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
        let pushed = store
            .mutate(|block| {
                let ok = block.push_post(sealed);
                (ok, ok)
            })
            .await
            .map_err(|e| BondAssemblyError::build("pending-post seal", e))?;
        if !pushed {
            return Err(BondAssemblyError::PendingPostExists.into());
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
    ) -> Result<(FundingSelection, ReferenceBlock), BondAssemblyError> {
        // Anchored ReferenceBlock via the ordinary procedure (WI-2 F-6).
        let reference = anchored_reference_block(curve_tree, chain_tip, tip_hash_at).await?;
        let reference_height = BlockHeight::from_raw(reference.height.0);

        // Sealed funding records (empty set if no pscan seal yet).
        let funding_records = load_pscan_state_for_engine(self_arc)
            .await
            .map_err(|e| BondAssemblyError::build("pscan state load", e))?
            .map(|s| s.funding_outputs().to_vec())
            .unwrap_or_default();

        let reserved = store
            .read(shekyl_engine_state::PendingPostBlock::reserved_gindexes)
            .await
            .map_err(|e| BondAssemblyError::build("reserved gindexes", e))?;

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

        let selection = sweep_funding_outputs(
            pruning_landed,
            &funding_records,
            p_slot,
            &reserved,
            required,
            reference_height,
        )?;
        Ok((selection, reference))
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
    pub async fn first_stake(
        self_arc: Arc<RwLock<Self>>,
        slot: u32,
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

        // Genesis posture: JoinMarket CompleteTree holdings; the bond fee is
        // derived from the daemon's live estimate over the bond size ceiling
        // (the seam the WI-2 addendum reserved for this entry — overpaying is
        // a miner transfer, never a conservation term).
        let holdings = HoldingsDescriptor {
            kind: HoldingsKind::CompleteTree,
            shard_ids: ShardSet::empty(),
        };
        let fee = {
            let estimates = daemon
                .get_fee_estimates()
                .await
                .map_err(|e| FirstStakeError::FeeEstimate(e.into().to_string()))?;
            AtomicUnits::from_raw(
                estimates
                    .economy
                    .calculate_fee_from_weight(BOND_SIZE_CEILING_BYTES),
            )
        };

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
mod tests {
    /// The stake error surface never carries persona funding amounts or
    /// gindexes (the most-logged-surface discipline): every numeric-bearing
    /// arm is reduced to its name, on BOTH the preflight sanitizer and the
    /// post-persist assemble/sign path (`engine_failure_detail` — the path
    /// the review found leaking `InsufficientFunding {available, required}`
    /// verbatim).
    #[test]
    fn funding_refusal_detail_is_amount_free() {
        let d = super::funding_refusal_detail(&super::BondAssemblyError::InsufficientFunding {
            available: 123_456,
            required: 999_999,
        });
        assert!(!d.contains("123") && !d.contains("999"), "no amounts: {d}");
        assert!(d.contains("insufficient"));

        let d = super::funding_refusal_detail(&super::BondAssemblyError::OutputNotYetDrained {
            gindex: 424_242,
        });
        assert!(!d.contains("424"), "no gindex: {d}");
        assert!(d.contains("not yet drained"));

        let d = super::engine_failure_detail(&super::StakeEngineError::Assembly(
            super::BondAssemblyError::InsufficientFunding {
                available: 123_456,
                required: 999_999,
            },
        ));
        assert!(
            !d.contains("123") && !d.contains("999"),
            "assemble-path amounts sanitized: {d}"
        );
        assert!(d.contains("bond assembly failed"));
    }

    use super::*;
    use shekyl_curve_tree::{should_reanchor, REF_ANCHOR_AGE};

    /// F-2 (i): assemble stamps `anchor_t0` via [`daemon_claimed_tip`]; the
    /// pscan `BlockSource::tip_height` path also routes through that same
    /// named function (see `block_source.rs`). This KAT pins that both
    /// modules name the same item.
    #[test]
    fn assemble_imports_named_daemon_claimed_tip() {
        // `daemon_claimed_tip` is in scope in this module (assemble path) and
        // is the body of `DaemonBlockSource::tip_height` / `PBlockSource::tip_height`.
        // A rename that forked the two clocks would break this shared import.
        let assemble_name = std::any::type_name_of_val(
            &daemon_claimed_tip::<crate::engine::test_support::TestDaemon>,
        );
        let source_name = std::any::type_name_of_val(
            &crate::engine::pscan::block_source::daemon_claimed_tip::<
                crate::engine::test_support::TestDaemon,
            >,
        );
        assert_eq!(
            assemble_name, source_name,
            "assemble and BlockSource must share one daemon_claimed_tip symbol"
        );
        assert!(
            assemble_name.contains("daemon_claimed_tip"),
            "unexpected tip-clock symbol name: {assemble_name}"
        );
    }

    /// F-6: when ingest lags such that `should_reanchor` fires on the
    /// would-be reference, the disposition is loud
    /// [`BondAssemblyError::ReferenceResyncing`] (not silent assemble_tx fail).
    #[test]
    fn lagging_ingest_trips_should_reanchor_loud_resync_disposition() {
        let chain_tip = 10_000u64;
        let ingested = 100u64;
        let anchor_tip = chain_tip.min(ingested);
        let reference_height = anchor_tip
            .checked_sub(REF_ANCHOR_AGE)
            .expect("short but ok");
        assert!(
            should_reanchor(chain_tip, reference_height),
            "fixture must trip the too-stale arm"
        );
        let err = BondAssemblyError::ReferenceResyncing {
            detail: "tree too far behind to anchor a submittable reference; resync",
        };
        assert!(matches!(
            err,
            BondAssemblyError::ReferenceResyncing { detail } if detail.contains("resync")
        ));
    }

    /// F-4 companion: orchestrator selects funding only via
    /// [`sweep_funding_outputs`](super::bond_assembly::sweep_funding_outputs).
    #[test]
    fn orchestrator_uses_sweep_as_sole_funding_path() {
        // Drop only the trailing `mod tests` so assertion literals cannot
        // self-match (`wire.rs` tripwire shape).
        let orch = include_str!("bond_orchestrator.rs")
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("bond_orchestrator.rs has a production section");
        // Split the call-site needle so a production doc-comment mention of
        // the symbol alone is not enough — the live call site must remain.
        let sweep_call = concat!("sweep", "_funding_outputs(");
        assert!(
            orch.contains(sweep_call),
            "orchestrator must select funding only via sweep_funding_outputs"
        );
        let retired = concat!("select", "_funding_outputs");
        assert!(
            !orch.contains(retired),
            "retired subset selector must not reappear"
        );
    }

    /// F-6 (ii): sweep reference height is taken from the same
    /// [`ReferenceBlock`] handed to `assemble_tx` (`reference.height()`).
    #[test]
    fn sweep_reference_height_equals_anchored_reference_block_height() {
        let reference = ReferenceBlock {
            height: CtBlockHeight(1_234),
            curve_tree_root: [0xAB; 32],
            block_hash: [0xCD; 32],
        };
        let sweep_height = BlockHeight::from_raw(reference.height.0);
        assert_eq!(
            sweep_height.to_raw(),
            reference.height.0,
            "sweep must filter against the anchored ReferenceBlock's height"
        );
    }

    // ── first_stake guard matrix (wallet-level idempotency + slot guards) ──

    use crate::engine::{Credentials, DaemonClient, EngineCreateParams, SoloSigner};
    use shekyl_engine_file::SafetyOverrides;
    use std::sync::Arc as StdArc;
    use tokio::sync::RwLock as TokioRwLock;

    /// Never-connecting daemon (no eager RPC before the guards under test).
    fn dummy_daemon() -> DaemonClient {
        let rpc = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(shekyl_rpc_transport::HttpRpc::new(
                "http://127.0.0.1:1".to_string(),
            ))
        })
        .expect("construct HttpRpc (no connection attempted)");
        DaemonClient::new(rpc)
    }

    fn fixed_seed() -> [u8; shekyl_crypto_pq::account::MASTER_SEED_BYTES] {
        let mut s = [0u8; shekyl_crypto_pq::account::MASTER_SEED_BYTES];
        for (i, b) in s.iter_mut().enumerate() {
            *b = u8::try_from(i & 0xff).unwrap_or(0).wrapping_mul(3);
        }
        s
    }

    /// A fresh first-stake acts only on the monotone cursor: any other slot
    /// is the `WrongSlot` refusal, before any daemon work or durable write —
    /// the guard that makes the `pub` embedder surface safe.
    #[tokio::test(flavor = "multi_thread")]
    async fn first_stake_refuses_a_fresh_slot_off_the_cursor() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base_path = tmp.path().join("wallet");
        let creds = Credentials::password_only(b"pw");
        let seed = fixed_seed();

        let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
        let network = params.network;
        Engine::<SoloSigner>::create(params, dummy_daemon())
            .expect("create")
            .close(&creds)
            .expect("close");

        let engine = Engine::<SoloSigner>::open_full_with_first_stake_intent(
            &base_path,
            &creds,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
            0,
        )
        .expect("intent open")
        .into_wallet();
        let arc = StdArc::new(TokioRwLock::new(engine));

        let err = Engine::first_stake(arc, 7).await.expect_err("off-cursor");
        assert!(
            matches!(
                err,
                FirstStakeError::WrongSlot {
                    requested: 7,
                    expected: 0
                }
            ),
            "got {err:?}"
        );
    }

    /// A staker wallet resumes only a recorded bonded slot — and once ANY
    /// bonded persona has a confirmed on-chain post, every slot refuses
    /// `AlreadyStaked` (the wallet-level SA-DQ-1 idempotency: pre-fix, a
    /// call naming a different slot slipped past the per-slot check and
    /// minted a durable second first-stake).
    #[tokio::test(flavor = "multi_thread")]
    async fn staker_first_stake_refuses_wrong_slots_and_confirmed_wallets_at_any_slot() {
        use shekyl_engine_state::pscan_cursor::PScanCursor;
        use shekyl_engine_state::pscan_state::{BondPostRecord, PScanState};

        let tmp = tempfile::tempdir().expect("tempdir");
        let base_path = tmp.path().join("wallet");
        let password: &[u8] = b"pw";
        let creds = Credentials::password_only(password);
        let seed = fixed_seed();

        let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
        let network = params.network;
        let engine =
            Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
        engine
            .persist_bond_record(PSlot::from_raw(3))
            .expect("persist bond record");
        engine.close(&creds).expect("close");

        // W2 shape (durable slot, no post anywhere): resume must target the
        // recorded slot; slot 4 is the WrongSlot refusal, not a second mint.
        let opened = Engine::<SoloSigner>::open_full(
            &base_path,
            &creds,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect("staker reopen")
        .into_wallet();
        let persona_3 = opened
            .stake_handle()
            .expect("staker reopen spawns the actor")
            .persona_canonical_id(PSlot::from_raw(3))
            .await
            .expect("bonded persona id");
        let arc = StdArc::new(TokioRwLock::new(opened));
        let err = Engine::first_stake(arc.clone(), 4)
            .await
            .expect_err("unrecorded slot on a staker");
        assert!(
            matches!(
                err,
                FirstStakeError::WrongSlot {
                    requested: 4,
                    expected: 3
                }
            ),
            "got {err:?}"
        );
        // Release the wallet-file lock before sealing evidence below.
        match StdArc::try_unwrap(arc) {
            Ok(lock) => lock.into_inner().close(&creds).expect("close staker"),
            Err(_) => panic!("engine arc still shared"),
        }

        // Seal confirmed-on-chain evidence for the bonded persona, then
        // reopen: EVERY slot — the bonded one and any other — must refuse
        // AlreadyStaked (wallet-level, not per-slot).
        {
            let (file, _outcome) = shekyl_engine_file::WalletFile::open(
                &base_path,
                password,
                network,
                SafetyOverrides::none(),
            )
            .expect("wallet file open");
            let key = crate::engine::sealing_keys::state_wrap_key_from_wallet_file(&file);
            let state = PScanState::new(
                PScanCursor::genesis(),
                std::collections::BTreeMap::new(),
                std::collections::BTreeMap::new(),
                vec![BondPostRecord {
                    height: BlockHeight::from_raw(10),
                    p_canonical_id: persona_3,
                    post_kind: 0,
                }],
                Vec::new(),
                Vec::new(),
                std::collections::BTreeMap::from([(persona_3, BlockHeight::ZERO)]),
            );
            let bytes = state.to_postcard_bytes().expect("encode state");
            file.save_pscan_state(key.as_bytes(), &bytes)
                .expect("seal evidence");
        }
        let opened = Engine::<SoloSigner>::open_full(
            &base_path,
            &creds,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect("reopen with evidence")
        .into_wallet();
        let arc = StdArc::new(TokioRwLock::new(opened));
        for slot in [3u32, 4u32] {
            let err = Engine::first_stake(arc.clone(), slot)
                .await
                .expect_err("confirmed wallet refuses every slot");
            assert!(
                matches!(err, FirstStakeError::AlreadyStaked),
                "slot {slot}: got {err:?}"
            );
        }
    }

    /// A **probe-adopted** slot (bond-watch sighting, SA-R-6) refuses
    /// `first_stake` as `AlreadyStaked` even while the pscan seal still lags
    /// (no `bond_post_matches` row yet). Pre-fix, this shape read as the W2
    /// phantom — durable slot, no match — and the resume path would mint a
    /// DUPLICATE JoinMarket post for a persona whose bond the principal scan
    /// had already observed on-chain.
    #[tokio::test(flavor = "multi_thread")]
    async fn probe_adopted_slot_refuses_first_stake_before_pscan_corroboration() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base_path = tmp.path().join("wallet");
        let creds = Credentials::password_only(b"probe adopted refusal");
        let seed = fixed_seed();

        let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
        let network = params.network;
        let engine =
            Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
        // Simulate the merge-time probe adoption: the principal scan sighted
        // an on-chain bond post for slot 0 (fresh-restore shape — no pscan
        // seal exists, so the reopen reconcile has nothing to drop).
        {
            let mut g = engine.ledger.write();
            crate::engine::bond_watch::adopt_bond_sightings(
                &mut g.ledger.staking,
                &[crate::scan::BondSightingObserved {
                    block_height: 10,
                    slot: 0,
                }],
            );
        }
        engine.close(&creds).expect("close persists the adoption");

        let opened = Engine::<SoloSigner>::open_full(
            &base_path,
            &creds,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect("reopen the adopted staker")
        .into_wallet();
        assert!(
            opened.ledger().staking.bond_sightings.contains_key(&0),
            "the sighting bridge survives the reopen (no seal to refute it)"
        );
        let arc = StdArc::new(TokioRwLock::new(opened));
        let err = Engine::first_stake(arc, 0)
            .await
            .expect_err("a sighted slot is already staked, never a W2 resume");
        assert!(matches!(err, FirstStakeError::AlreadyStaked), "got {err:?}");
    }

    /// One-block `ScanResult` continuing a fresh wallet (height 0 → 1).
    fn one_block_scan_result(
        sightings: Vec<crate::scan::BondSightingObserved>,
    ) -> crate::scan::ScanResult {
        crate::scan::ScanResult {
            processed_height_range: 1..2,
            parent_hash: None,
            block_hashes: vec![(1, [0x11; 32])],
            new_transfers: Vec::new(),
            spent_key_images: Vec::new(),
            reorg_rewind: None,
            block_leaves: Vec::new(),
            block_curve_tree_roots: Vec::new(),
            bond_sightings: sightings,
        }
    }

    /// `Engine::apply_scan_result` is the write gate: a sighting whose
    /// slot is not in the probe cache must be refused *before* the
    /// ledger apply, so the tip stays put and the cursor is not burned.
    /// This bites against a producer/test-double naming an unwatched
    /// slot; it does NOT cover the unit-level validate checks (those
    /// live on `validate_bond_sightings`).
    #[tokio::test(flavor = "multi_thread")]
    async fn apply_scan_result_refuses_an_uncached_sighting_without_advancing_the_tip() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base_path = tmp.path().join("wallet");
        let creds = Credentials::password_only(b"uncached sighting refusal");
        let seed = fixed_seed();
        let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
        let engine =
            Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
        assert!(
            !engine.ledger().staking.persona_id_cache.contains_key(&999),
            "fixture: slot 999 is outside the 0..=W create window"
        );
        let tip_before = engine.synced_height();
        let cursor_before = engine.ledger().staking.p_slot;

        let err = engine
            .apply_scan_result(one_block_scan_result(vec![
                crate::scan::BondSightingObserved {
                    block_height: 1,
                    slot: 999,
                },
            ]))
            .expect_err("uncached slot is malformed");
        assert!(
            matches!(err, crate::engine::RefreshError::MalformedScanResult { .. }),
            "got {err:?}"
        );
        assert_eq!(
            engine.synced_height(),
            tip_before,
            "a refused sighting must not advance the tip"
        );
        assert_eq!(
            engine.ledger().staking.p_slot,
            cursor_before,
            "a refused sighting must not burn the cursor"
        );
        assert!(
            engine.ledger().staking.bonded_slots.is_empty(),
            "a refused sighting must not adopt"
        );
    }

    /// A mid-session bond-watch recovery (adoption flips `staking_enabled`
    /// with no resident actor — Model D cannot spawn one without the seed)
    /// is a typed domain refusal naming the remedy, not an internal fault:
    /// `first_stake` reads `RecoveredPendingReopen` (RPC `-29504`, "reopen
    /// the wallet"), and the staking read surface reports
    /// `recovery_pending_reopen` so the embedder can say so unprompted.
    #[tokio::test(flavor = "multi_thread")]
    async fn recovered_mid_session_first_stake_names_the_reopen_remedy() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base_path = tmp.path().join("wallet");
        let creds = Credentials::password_only(b"recovered pending reopen");
        let seed = fixed_seed();
        let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
        let engine =
            Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
        assert!(
            !engine.has_stake_engine(),
            "fixture: a fresh non-staker session has no actor"
        );
        assert!(
            !engine.staking_recovery_pending_reopen(),
            "fixture: nothing recovered yet"
        );

        engine
            .apply_scan_result(one_block_scan_result(vec![
                crate::scan::BondSightingObserved {
                    block_height: 1,
                    slot: 0,
                },
            ]))
            .expect("adoption merge");
        assert!(
            engine.staking_recovery_pending_reopen(),
            "adoption must surface the pending-reopen state"
        );
        let view = engine.staking_read_view().expect("staking read view");
        assert!(view.recovery_pending_reopen);

        let arc = std::sync::Arc::new(tokio::sync::RwLock::new(engine));
        let err = Engine::first_stake(arc, 0)
            .await
            .expect_err("no actor is resident this session");
        assert!(
            matches!(err, FirstStakeError::RecoveredPendingReopen),
            "got {err:?}"
        );
    }

    /// The merge's reorg edge for sighting rows: a rewind discards every
    /// stored row at/above the fork BEFORE adopting the re-scan's sightings,
    /// so (a) a re-mined post replaces its orphaned row at the new canonical
    /// height — the old min-height rule would have kept the orphaned height
    /// and let a lagging P-scan read the real re-mined bond as
    /// AbsentWithinCovered — and (b) a post that did not re-mine loses its
    /// row (its adopted slot stays for the open-time sweep, and a later
    /// re-mine is re-adopted), while (c) rows below the fork survive
    /// untouched. Also the in-session healing edge for the first-stake
    /// AlreadyStaked guard: the orphaned row no longer wedges it.
    #[tokio::test(flavor = "multi_thread")]
    async fn apply_scan_result_reorg_replaces_orphaned_sighting_rows() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base_path = tmp.path().join("wallet");
        let creds = Credentials::password_only(b"reorg sighting hygiene");
        let seed = fixed_seed();
        let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
        let engine =
            Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");

        // First merge: blocks 1..3; slot 0 sighted at 1 (below the coming
        // fork), slots 1 and 2 sighted at 2 (at the fork — orphaned).
        engine
            .apply_scan_result(crate::scan::ScanResult {
                processed_height_range: 1..3,
                parent_hash: None,
                block_hashes: vec![(1, [0x11; 32]), (2, [0x22; 32])],
                new_transfers: Vec::new(),
                spent_key_images: Vec::new(),
                reorg_rewind: None,
                block_leaves: Vec::new(),
                block_curve_tree_roots: Vec::new(),
                bond_sightings: vec![
                    crate::scan::BondSightingObserved {
                        block_height: 1,
                        slot: 0,
                    },
                    crate::scan::BondSightingObserved {
                        block_height: 2,
                        slot: 1,
                    },
                    crate::scan::BondSightingObserved {
                        block_height: 2,
                        slot: 2,
                    },
                ],
            })
            .expect("first merge");

        // Reorg forking at 2: slot 1's post re-mines at 3; slot 2's does not.
        engine
            .apply_scan_result(crate::scan::ScanResult {
                processed_height_range: 2..4,
                parent_hash: Some([0x11; 32]),
                block_hashes: vec![(2, [0xB2; 32]), (3, [0xB3; 32])],
                new_transfers: Vec::new(),
                spent_key_images: Vec::new(),
                reorg_rewind: Some(crate::scan::ReorgRewind { fork_height: 2 }),
                block_leaves: Vec::new(),
                block_curve_tree_roots: Vec::new(),
                bond_sightings: vec![crate::scan::BondSightingObserved {
                    block_height: 3,
                    slot: 1,
                }],
            })
            .expect("reorg merge");

        let staking = engine.ledger().staking.clone();
        assert_eq!(
            staking.bond_sightings.get(&0).map(|h| h.to_raw()),
            Some(1),
            "a row below the fork survives untouched"
        );
        assert_eq!(
            staking.bond_sightings.get(&1).map(|h| h.to_raw()),
            Some(3),
            "a re-mined post's row moves to its new canonical height"
        );
        assert!(
            !staking.bond_sightings.contains_key(&2),
            "an orphaned, un-re-mined row is discarded"
        );
        assert_eq!(
            staking.bonded_slots,
            vec![0, 1, 2],
            "adoption is never rewound — slot 2 stays for the open-time sweep"
        );
    }

    /// The peel-off + adopt seam: a sighting for a cached slot (create
    /// derives 0..=W) is adopted and raises the cursor under the same
    /// write that advances the tip. This bites against a regression that
    /// dropped sightings in `apply_scan_result_to_state`; it does NOT
    /// cover the producer emission path.
    #[tokio::test(flavor = "multi_thread")]
    async fn apply_scan_result_adopts_a_cached_slot_and_advances_the_tip() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base_path = tmp.path().join("wallet");
        let creds = Credentials::password_only(b"cached sighting adopt");
        let seed = fixed_seed();
        let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
        let engine =
            Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
        assert!(
            engine.ledger().staking.persona_id_cache.contains_key(&0),
            "create derives the 0..=W probe window"
        );

        engine
            .apply_scan_result(one_block_scan_result(vec![
                crate::scan::BondSightingObserved {
                    block_height: 1,
                    slot: 0,
                },
            ]))
            .expect("cached slot is adopted");
        assert_eq!(engine.synced_height(), 1, "tip advanced");
        assert_eq!(engine.ledger().staking.bonded_slots, vec![0], "adopted");
        assert_eq!(engine.ledger().staking.p_slot, 1, "cursor raised past 0");
        assert!(engine.ledger().staking.staking_enabled);
        assert_eq!(
            engine
                .ledger()
                .staking
                .bond_sightings
                .get(&0)
                .map(|h| h.to_raw()),
            Some(1)
        );
    }
}
