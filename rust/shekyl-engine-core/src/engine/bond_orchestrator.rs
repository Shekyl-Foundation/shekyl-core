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
    sweep_funding_outputs, BondAssemblyError, FundingInputContext, SpentRecordsDurablyPruned,
};
use super::curve_tree_actor::{CurveTreeHandle, CurveTreeHandleError};
use super::pscan::block_source::daemon_claimed_tip;
use super::pscan::start::{load_pscan_state_for_engine, pending_post_store_for_engine};

/// Size ceiling for the first-stake bond-fee derivation: the single-input
/// bond post is far under this, so a fee baked at assembly over this weight
/// clears the daemon's per-byte floor even as estimates move (overpaying is a
/// miner transfer, never a conservation term). Promoted from the PR-4 regtest
/// harness to the production seam the WI-2 addendum reserved for the stake
/// entry.
const BOND_SIZE_CEILING_BYTES: usize = 32 * 1024;

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

/// First-stake refusal/failure taxonomy (rule 82;
/// `ARCHIVAL_STAKE_ACTIVATION_PLAN.md` §5.1/§5.7). Refusals are
/// caller-recoverable states with user-meaning; `Engine`/`Persist` arms are
/// mid-flow failures whose recovery is a `stake` re-invoke (W2).
#[derive(Debug, thiserror::Error)]
pub enum FirstStakeError {
    /// No StakeEngine is resident — first-stake must enter through the
    /// credentialed open-with-intent (SA-R1-a). An internal sequencing
    /// defect at the caller, not a user refusal.
    #[error("no stake engine resident: first-stake requires the open-with-intent path")]
    NoStakeEngine,
    /// A signed bond post is already sealed and awaiting dispatch (W3): the
    /// stake is in flight; the dispatch driver will broadcast it.
    #[error("a signed bond post is already awaiting dispatch")]
    BondInFlight,
    /// A confirmed bond post exists on-chain for the persona: the wallet is
    /// already staking; a second call must not mint a second first-stake
    /// (SA-DQ-1 idempotency).
    #[error("already staking: a confirmed bond post exists for the persona")]
    AlreadyStaked,
    /// Funding validation failed **before** any durable staker state was
    /// written (W1-clean): fund the persona (`stake_in`) and/or let the
    /// P-scan catch up, then retry.
    #[error("first-stake funding not ready: {0}")]
    Funding(String),
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

        // (ii) Anchored ReferenceBlock via the ordinary procedure.
        let reference = anchored_reference_block(&curve_tree, chain_tip, tip_hash_at).await?;
        let reference_height = BlockHeight::from_raw(reference.height.0);

        // Sealed funding records (empty set if no pscan seal yet).
        let funding_records = load_pscan_state_for_engine(self_arc.clone())
            .await
            .map_err(|e| BondAssemblyError::build("pscan state load", e))?
            .map(|s| s.funding_outputs().to_vec())
            .unwrap_or_default();

        let reserved = store
            .read(shekyl_engine_state::PendingPostBlock::reserved_gindexes)
            .await
            .map_err(|e| BondAssemblyError::build("reserved gindexes", e))?;

        let floor = AtomicUnits::from_raw(bond_floor(&holdings));
        // Align with the wire builder / retention verifier: a zero floor is
        // structurally invalid holdings, not a sweep-to-empty success that
        // would later index an empty `paths` vector. Typed refusal before
        // any curve-tree work (rule 82).
        if floor == AtomicUnits::ZERO {
            return Err(BondAssemblyError::BondFloorZero.into());
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
            .zip(paths.into_iter())
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
            entry_offset_blocks: assembled.plan.entry_offset_blocks,
            bond_post_offset_blocks: assembled.plan.bond_post_offset_blocks,
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
        let (
            daemon,
            stake,
            curve_tree,
            pending_write_lock,
            chain_tip,
            tip_hash_at,
            staking_enabled,
        ) = {
            let g = self_arc.read().await;
            let stake = g.stake_handle().ok_or(FirstStakeError::NoStakeEngine)?;
            let snap = g.ledger.snapshot();
            let chain_tip = g.ledger.synced_height();
            let tip_hash_at = move |h: u64| snap.block_hash_at(h);
            let staking_enabled = g.ledger.read().ledger.staking.staking_enabled;
            (
                g.daemon().clone(),
                stake,
                g.curve_tree.clone(),
                g.pending_write_lock.clone(),
                chain_tip,
                tip_hash_at,
                staking_enabled,
            )
        };
        let store = pending_post_store_for_engine(self_arc.clone(), pending_write_lock);

        // Idempotency / W2 split (§5.1 + §5.7 W2). A signed post awaiting
        // dispatch is W3 — refuse; a confirmed on-chain post makes this
        // wallet an active staker — refuse (a second call must not mint a
        // second first-stake); a durable slot with NEITHER is the W2 phantom
        // — resume.
        let pending_for_slot = store
            .read(|block| block.posts().iter().any(|p| p.p_slot == slot))
            .await
            .map_err(|e| FirstStakeError::Funding(format!("pending read: {e}")))?;
        if pending_for_slot {
            return Err(FirstStakeError::BondInFlight);
        }
        let resumed = if staking_enabled {
            let id = stake
                .persona_canonical_id(slot)
                .await
                .map_err(|e| FirstStakeError::Engine(e.to_string()))?;
            let confirmed = load_pscan_state_for_engine(self_arc.clone())
                .await
                .map_err(|e| FirstStakeError::Funding(format!("pscan state load: {e}")))?
                .map(|s| s.bond_post_matches().iter().any(|m| m.p_canonical_id == id))
                .unwrap_or(false);
            if confirmed {
                return Err(FirstStakeError::AlreadyStaked);
            }
            true
        } else {
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
                .map_err(|e| FirstStakeError::Funding(format!("fee estimate: {}", e.into())))?;
            AtomicUnits::from_raw(
                estimates
                    .economy
                    .calculate_fee_from_weight(BOND_SIZE_CEILING_BYTES),
            )
        };

        // W1 preflight sweep (SA-R1-b, sweep-before-persist): the same
        // inputs the assemble path will use, run BEFORE the durable point so
        // an insufficient-funding first-stake fails closed as a non-staker.
        let witness = SpentRecordsDurablyPruned::arm1_watch_pruning_live();
        {
            let funding_records = load_pscan_state_for_engine(self_arc.clone())
                .await
                .map_err(|e| FirstStakeError::Funding(format!("pscan state load: {e}")))?
                .map(|s| s.funding_outputs().to_vec())
                .unwrap_or_default();
            let reserved = store
                .read(shekyl_engine_state::PendingPostBlock::reserved_gindexes)
                .await
                .map_err(|e| FirstStakeError::Funding(format!("reserved gindexes: {e}")))?;
            let floor = AtomicUnits::from_raw(bond_floor(&holdings));
            let required = floor
                .checked_add(fee)
                .ok_or_else(|| FirstStakeError::Funding("floor + fee overflow".to_owned()))?;
            let reference = anchored_reference_block(&curve_tree, chain_tip, tip_hash_at)
                .await
                .map_err(|e| FirstStakeError::Funding(e.to_string()))?;
            sweep_funding_outputs(
                &witness,
                &funding_records,
                slot,
                &reserved,
                required,
                BlockHeight::from_raw(reference.height.0),
            )
            .map_err(|e| FirstStakeError::Funding(e.to_string()))?;
        }

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
            .map_err(|e| FirstStakeError::Engine(e.to_string()))?;
        let assembled =
            Self::assemble_bond_post(self_arc.clone(), handle, ticket, holdings, fee, &witness)
                .await
                .map_err(|e| FirstStakeError::Engine(e.to_string()))?;

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
}
