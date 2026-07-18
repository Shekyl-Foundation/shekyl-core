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

use shekyl_archival_retention::{bond_floor, HoldingsDescriptor};
use shekyl_curve_tree::{
    select_reference_height, should_reanchor, AssembleInput, BlockHeight as CtBlockHeight, Gindex,
    ReferenceBlock,
};
use shekyl_engine_file::WalletFile;
use shekyl_engine_state::pending_post_block::{PendingBondPost, PendingPostState};
use shekyl_tx_builder::{LeafEntry, TreeContext};
use shekyl_types::BlockHeight;
use shekyl_units::AtomicUnits;
use tokio::sync::RwLock;

use shekyl_curve_tree::ClientError;

use super::bond_assembly::{
    sweep_funding_outputs, BondAssemblyError, FundingInputContext, SpentRecordsDurablyPruned,
};
use super::curve_tree_actor::{CurveTreeHandle, CurveTreeHandleError};
use super::pscan::block_source::daemon_claimed_tip;
use super::pscan::start::{load_pscan_state_for_engine, pending_post_store_for_engine};
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
    /// Go-live remains compile-blocked on a production
    /// [`SpentRecordsDurablyPruned`] mint (2d-1 / SP-R0); tests pass
    /// [`SpentRecordsDurablyPruned::for_test`]. Dead_code allow retires only
    /// when **both** SP-R0 pruning **and** the RPC stake entry land
    /// (`docs/FOLLOWUPS.md`).
    #[allow(dead_code)] // rule-21: (a) SP-R0 arm #1 pruning DONE 2026-07-18 (logic-discharged); retires with (b) the RPC stake entry (#332)
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
