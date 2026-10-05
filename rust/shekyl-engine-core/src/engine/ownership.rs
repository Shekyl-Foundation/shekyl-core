// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Telling the curve tree which outputs are the wallet's.
//!
//! The tree captures membership-path material only for outputs it has been
//! told about (`CT6_PROVING_STATE.md` §11.9, §11.12), and the wallet is the
//! only party that knows. "The wallet's" is two sets, because two things
//! spend through one tree: the principal's ledger transfers, and the funding
//! outputs the staking persona `P` holds, which live in `P`'s sealed scan
//! state and never enter the ledger. Three sites offer them, all through
//! [`curve_tree_sync_owned`] or the actor's own sync:
//!
//! - the refresh, after the respawn-aware ingest: everything held
//!   ([`Engine::owned_outputs`]), both sets — a resume is a mass late
//!   registration, and a re-offer of a held pair costs a map lookup;
//! - the refresh, after the merge: what the merge inserted
//!   ([`owned_outputs_among`]), handed back because the merge runs under the
//!   ledger write lock and cannot `ask` the actor;
//! - the curve-tree actor's `AssembleTx` handler: a spend's own inputs, which
//!   is what makes the capture path total.
//!
//! `P`'s scan has no site of its own, and cannot usefully have one: it sweeps
//! only blocks `ARCHIVAL_REORG_DEPTH_BLOCKS` behind the tip
//! (`pscan/start.rs`, `DEFAULT_PSCAN_CADENCE`), and a leaf drains one lock
//! window after its block, so `P` learns of an output long after the drain
//! and its first registration is late wherever it is made. What a site there
//! could not do is survive a restart — the registry is not persisted and the
//! scan names each output once — so the refresh's mass pass is the one that
//! has to carry them.
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

/// One of `P`'s funding outputs as a membership-path input.
///
/// The single conversion from a sealed funding record to the tree's types:
/// the drain, the claim, the release and the bond-post all assemble through
/// it, and [`owned_p_output`] is its first two fields — so what `P`
/// registers and what `P` spends are one derivation and cannot disagree.
pub(crate) fn p_assemble_input(
    record: &shekyl_engine_state::pscan_state::PFundingOutputRecord,
) -> shekyl_curve_tree::AssembleInput {
    shekyl_curve_tree::AssembleInput {
        gindex: record.gindex,
        output_key: shekyl_curve_tree::OneTimePubkey::from_bytes(record.output_key),
        commitment: shekyl_curve_tree::CommitmentBytes::from_bytes(record.commitment),
    }
}

/// The registration pair for one of `P`'s funding outputs
/// ([`p_assemble_input`]'s own `(gindex, O)`).
pub(crate) fn owned_p_output(
    record: &shekyl_engine_state::pscan_state::PFundingOutputRecord,
) -> OwnedOutput {
    let input = p_assemble_input(record);
    (input.gindex, input.output_key)
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
    /// Every output the wallet can still spend, as registration pairs: the
    /// ledger's unspent transfers and `P`'s held funding outputs.
    ///
    /// This is the mass pass a refresh sends on every run: a resume is a
    /// mass late registration (the registry does not persist), and a
    /// re-offer of a held pair is `AlreadyHeld` and costs a map lookup, so
    /// sending it every time is what keeps the tree's view of ownership from
    /// drifting after a rollback or a rescan.
    ///
    /// The ledger is read under a brief guard that is released before the
    /// seal is opened: the lock is not re-entrant, and nothing here needs
    /// the two reads to be one instant — a pair missed by a moment is
    /// offered by the next refresh.
    pub(crate) fn owned_outputs(&self) -> Vec<OwnedOutput> {
        let mut outputs: Vec<OwnedOutput> = {
            let guard = self.ledger.read();
            guard
                .ledger
                .ledger
                .transfers()
                .iter()
                .filter(|td| !td.spent)
                .map(owned_output)
                .collect()
        };
        outputs.extend(self.p_funding_outputs());
        outputs
    }

    /// `P`'s held funding outputs, from its sealed scan state.
    ///
    /// The seal's funding set is already unspent-only — the scan prunes a
    /// record when it sees the spend (`PScanState::funding_outputs`) — so it
    /// is offered whole. An absent seal is a wallet that has never scanned
    /// as `P`, and is empty.
    ///
    /// A seal that cannot be opened or decoded is **logged and read as
    /// empty**, which is the opposite of every staking read and deliberate.
    /// Those reads decide what the wallet tells its user it holds, so they
    /// fail closed; this one decides only *when* captures are written.
    /// Nothing is lost by missing it: the `AssembleTx` handler registers a
    /// spend's inputs itself, so `P`'s spend still assembles, later and at
    /// the late path's cost. Failing instead would stop the principal's
    /// refresh on the state of `P`'s file, and the principal does not depend
    /// on `P`.
    ///
    /// Small synchronous file I/O, once per refresh, of the same class as
    /// the staking reads' own opens.
    fn p_funding_outputs(&self) -> Vec<OwnedOutput> {
        let sealed = self
            .persistence
            .open_pscan_state(self.state_wrap_key().as_bytes())
            .map_err(|e| e.to_string())
            .and_then(|body| {
                body.map(|bytes| {
                    shekyl_engine_state::pscan_state::PScanState::from_postcard_bytes(&bytes)
                        .map_err(|e| e.to_string())
                })
                .transpose()
            });
        match sealed {
            Ok(Some(state)) => state.funding_outputs().iter().map(owned_p_output).collect(),
            Ok(None) => Vec::new(),
            Err(detail) => {
                tracing::warn!(
                    %detail,
                    "curve tree: the persona scan seal could not be read; its \
                     funding outputs are not registered this refresh and will \
                     be when they are spent"
                );
                Vec::new()
            }
        }
    }

    /// Register `outputs` with the curve tree ([`curve_tree_sync_owned`]).
    pub(crate) async fn sync_owned_outputs(
        &self,
        outputs: Vec<OwnedOutput>,
    ) -> Result<shekyl_curve_tree::OwnershipSync, RefreshError> {
        curve_tree_sync_owned(&self.curve_tree, outputs).await
    }
}

#[cfg(test)]
mod tests {
    use shekyl_curve_tree::BlockHeight;
    use shekyl_engine_state::pscan_cursor::PScanCursor;
    use shekyl_engine_state::pscan_state::{MintLineageOutput, PFundingOutputRecord, PScanState};
    use shekyl_fcmp::tree::SELENE_CHUNK_WIDTH;

    use super::*;
    use crate::engine::test_support::{
        funding_record, non_staker_engine, seeded_commitment, seeded_output_key, seeded_tx_leaves,
    };
    use crate::engine::SoloSigner;

    /// Distinct from every other suite's wallet.
    const SEED_MULT: u8 = 0x5d;
    /// The fixture's only chain.
    const CHAIN: u8 = 1;
    /// Outputs per carrying block: one full leaf chunk.
    const PER_BLOCK: u64 = SELENE_CHUNK_WIDTH as u64;
    /// The persona's output: block 0, so its gindex is its index.
    const P_GINDEX: u64 = 10;

    /// Seal a persona scan state holding `records` through the engine's own
    /// persistence, as the persona scan does after a sweep.
    fn seal_funding(engine: &Engine<SoloSigner>, records: Vec<PFundingOutputRecord>) {
        let state = PScanState::new(
            PScanCursor::genesis(),
            Default::default(),
            Default::default(),
            Vec::new(),
            records,
            Vec::new(),
            Default::default(),
        );
        let bytes = state.to_postcard_bytes().expect("encode pscan state");
        engine
            .persistence()
            .save_pscan_state(engine.state_wrap_key().as_bytes(), &bytes)
            .expect("seal the funding set");
    }

    /// Ingest heights `from..=to`, the first `carrying` of them full of
    /// seeded outputs and the rest empty.
    async fn ingest(tree: &CurveTreeHandle, from: u64, to: u64, carrying: u64) {
        for height in from..=to {
            let n = if height < from + carrying {
                PER_BLOCK
            } else {
                0
            };
            tree.ingest(
                BlockHeight::from_raw(height),
                seeded_tx_leaves(CHAIN, height, n),
            )
            .await
            .expect("a seeded block ingests");
        }
    }

    /// The persona's funding output is registered by the refresh's pass, so
    /// the late registration is paid there, once, and its spend pays nothing.
    ///
    /// The persona's scan trails the tip by the archival reorg depth, so its
    /// output has always drained by the time anything in the wallet knows of
    /// it: the first registration is late wherever it is made. What this
    /// pins is *where* — the refresh after the scan sealed it, rebuilding
    /// exactly the one leaf chunk that had closed — and that every chunk
    /// closing afterwards is captured by the fold, so the drain that spends
    /// the output months later finds it held and rebuilds no leaf.
    ///
    /// Without the persona's set in [`Engine::owned_outputs`] the pass
    /// offers nothing and the first assertion reads `after_drain == 0`.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_persona_funding_output_is_registered_by_the_refresh_not_by_its_spend() {
        let (_tmp, engine) = non_staker_engine(SEED_MULT);
        let tree = engine.curve_tree.clone();

        // 17 full leaf chunks, all drained: the output's leaf chunk has
        // closed, its layer-1 chunk (which ends at leaf 683) has not.
        ingest(&tree, 0, 27, 17).await;

        let mut record = funding_record(3, P_GINDEX, 0, 40_000, MintLineageOutput::EmissionReward);
        record.output_key = seeded_output_key(CHAIN, 0, P_GINDEX);
        record.commitment = seeded_commitment(CHAIN, 0, P_GINDEX);
        seal_funding(&engine, vec![record.clone()]);

        let pair = owned_p_output(&record);
        assert_eq!(
            engine.owned_outputs(),
            vec![pair],
            "the pass offers the sealed funding output and, the ledger being empty, nothing else"
        );
        let first = engine
            .sync_owned_outputs(engine.owned_outputs())
            .await
            .expect("the registration pass runs");
        assert_eq!(
            first.after_drain, 1,
            "the output drained before it was known"
        );
        assert!(
            first.stale.is_empty(),
            "the seal and the tree agree on the key"
        );
        let report = first
            .reconciliation
            .expect("a late registration reconciles");
        assert_eq!(report.positions_resolved, 1);
        assert_eq!(report.chunks_written, 1, "the one chunk that had closed");
        assert_eq!(
            report.leaves_rebuilt, PER_BLOCK,
            "that chunk's own span and nothing wider"
        );

        // Two more chunks drain: the output's layer-1 chunk closes, and is
        // not the root. The fold captures it; nobody is asked to.
        ingest(&tree, 28, 40, 2).await;

        // The spend. This is the call the `AssembleTx` handler makes with
        // the drain's inputs before it assembles them, made first so its
        // verdict can be read.
        let at_spend = tree
            .sync_owned(vec![pair])
            .await
            .expect("sync on a live actor");
        assert_eq!(
            at_spend.already_held, 1,
            "held and served since the refresh"
        );
        assert_eq!(
            at_spend.reconciliation, None,
            "so the spend reconciles nothing and rebuilds no leaf"
        );

        let height = BlockHeight::from_raw(40);
        let (root, _) = tree
            .reference_root_and_depth(height)
            .await
            .expect("the tree answers at its tip");
        let reference = shekyl_curve_tree::ReferenceBlock {
            height,
            curve_tree_root: shekyl_types::CurveTreeRoot::from_bytes(root),
            block_hash: shekyl_types::BlockHash::NULL,
        };
        let paths = tree
            .assemble_tx(reference, vec![p_assemble_input(&record)])
            .await
            .expect("the layer-1 chunk the fold captured is there to read");
        assert_eq!(paths.len(), 1);
    }

    /// A persona seal that cannot be decoded costs the persona its early
    /// registration and costs the principal nothing: the pass reads it as
    /// empty rather than failing the refresh on the state of another
    /// identity's file.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_undecodable_persona_seal_is_read_as_empty() {
        let (_tmp, engine) = non_staker_engine(SEED_MULT.wrapping_add(1));
        assert!(
            engine.owned_outputs().is_empty(),
            "an absent seal is a wallet that never scanned as the persona"
        );

        let garbage = [0xffu8; 16];
        assert!(
            PScanState::from_postcard_bytes(&garbage).is_err(),
            "the fixture must be undecodable for the test to mean anything"
        );
        engine
            .persistence()
            .save_pscan_state(engine.state_wrap_key().as_bytes(), &garbage)
            .expect("the seal itself is well-formed; its body is not");
        assert!(engine.owned_outputs().is_empty());
    }
}
