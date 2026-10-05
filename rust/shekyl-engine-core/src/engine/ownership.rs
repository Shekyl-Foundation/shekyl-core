// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Telling the curve tree which outputs are the wallet's.
//!
//! The tree captures membership-path material only for outputs it has been
//! told about (`CT6_PROVING_STATE.md` §11.9, §11.12), and the wallet is the
//! only party that knows. Three sites offer them, all through
//! [`curve_tree_sync_owned`] or the actor's own sync:
//!
//! - the refresh, after the respawn-aware ingest: everything the ledger
//!   holds ([`Engine::owned_outputs`]) — a resume is a mass late
//!   registration, and a re-offer of a held pair costs a map lookup;
//! - the refresh, after the merge: what the merge inserted
//!   ([`owned_outputs_among`]), handed back because the merge runs under the
//!   ledger write lock and cannot `ask` the actor;
//! - the curve-tree actor's `AssembleTx` handler: a spend's own inputs, which
//!   is what makes the capture path total.
//!
//! Carved out of `merge.rs`, where it sat beside the ingest it follows: the
//! registration is its own concern, and that file is at the engine's
//! god-file line.

use crate::engine::{
    curve_tree_actor::CurveTreeHandle, local_ledger::LocalLedger,
    merge::map_curve_tree_handle_error, traits::DaemonEngine, Engine, EngineSignerKind,
    RefreshError,
};

/// One owned output as the curve tree registers it: `(gindex, O)`.
///
/// The pair, not the number alone, because a gindex is a name a reorg
/// re-derives and `O` is the identity that survives it
/// (`CT6_PROVING_STATE.md` §11.9).
pub(crate) type OwnedOutput = (shekyl_curve_tree::Gindex, shekyl_curve_tree::OneTimePubkey);

/// The registration pair for a ledger transfer — the same wrapping of the
/// compressed key `transfer::support::assemble_input` uses, so the registry
/// and the spend cannot name one output two ways.
pub(crate) fn owned_output(td: &shekyl_engine_state::TransferDetails) -> OwnedOutput {
    (
        td.global_output_index,
        shekyl_curve_tree::OneTimePubkey::from_bytes(td.key.compress().to_bytes()),
    )
}

/// The registration pairs for the transfers at `inserted`, unspent only.
///
/// Pure, so the merge's one new fact can be tested on a `LedgerBlock`
/// without an engine: the pairs it returns are exactly the unspent rows the
/// merge appended, in insertion order, and nothing else.
pub(crate) fn owned_outputs_among(
    ledger: &shekyl_engine_state::LedgerBlock,
    inserted: &[usize],
) -> Vec<OwnedOutput> {
    inserted
        .iter()
        .filter_map(|&i| ledger.transfers().get(i))
        .filter(|td| !td.spent)
        .map(owned_output)
        .collect()
}

/// Register `outputs` with the curve tree, reconciling once if any is owed.
///
/// A stale pair — the tree holds a different output at that gindex — is the
/// normal outcome of a scan lagging the tree across a reorg; it is logged,
/// not an error, and the rescan re-offers the right key. Actor faults map
/// as the ingest's do, so an unavailable actor is classified
/// respawn-recoverable; the caller orders this **after** the respawn-aware
/// ingest so a dead actor has already been healed by the time it is asked.
pub(crate) async fn curve_tree_sync_owned(
    curve_tree: &CurveTreeHandle,
    outputs: Vec<OwnedOutput>,
) -> Result<shekyl_curve_tree::OwnershipSync, RefreshError> {
    if outputs.is_empty() {
        return Ok(shekyl_curve_tree::OwnershipSync::default());
    }
    let sync = curve_tree
        .sync_owned(outputs)
        .await
        .map_err(|e| map_curve_tree_handle_error(&e))?;
    if !sync.stale.is_empty() {
        tracing::warn!(
            stale = sync.stale.len(),
            "curve tree: registrations whose key disagrees with the tree; the \
             scan's view is behind the chain and the rescan will re-offer them"
        );
    }
    if let Some(report) = sync.reconciliation {
        tracing::info!(
            after_drain = sync.after_drain,
            positions_resolved = report.positions_resolved,
            chunks_written = report.chunks_written,
            leaves_rebuilt = report.leaves_rebuilt,
            "curve tree: late registrations reconciled"
        );
    }
    Ok(sync)
}

#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D: DaemonEngine,
        E: super::traits::EconomicsEngine,
        R: super::traits::RefreshEngine,
        P: super::traits::PendingTxEngine,
    > Engine<S, D, LocalLedger, E, R, P>
{
    /// Every unspent output the ledger holds, as registration pairs, read
    /// under a brief read guard. This is the mass pass a refresh sends on
    /// every run: a resume is a mass late registration (the registry does
    /// not persist), and a re-offer of a held pair is `AlreadyHeld` and
    /// costs a map lookup, so sending it every time is what keeps the tree's
    /// view of ownership from drifting after a rollback or a rescan.
    pub(crate) fn owned_outputs(&self) -> Vec<OwnedOutput> {
        let guard = self.ledger.read();
        guard
            .ledger
            .ledger
            .transfers()
            .iter()
            .filter(|td| !td.spent)
            .map(owned_output)
            .collect()
    }

    /// Register `outputs` with the curve tree ([`curve_tree_sync_owned`]).
    pub(crate) async fn sync_owned_outputs(
        &self,
        outputs: Vec<OwnedOutput>,
    ) -> Result<shekyl_curve_tree::OwnershipSync, RefreshError> {
        curve_tree_sync_owned(&self.curve_tree, outputs).await
    }
}
