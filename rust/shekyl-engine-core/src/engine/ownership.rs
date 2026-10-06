// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Telling the curve tree which outputs are the wallet's.
//!
//! The tree captures membership-path material only for outputs it has been
//! told about (`CT6_PROVING_STATE.md` §11.9, §11.12, §11.13), and the wallet
//! is the only party that knows. Two sites tell it:
//!
//! - **the refresh's ingest**, between its rollback and its first fold
//!   (`merge::curve_tree_ingest_scan_result`), through [`curve_tree_offer`]
//!   with [`Engine::owned_outputs`]: every pair the wallet can name, and
//!   every output of a transaction the persona built and has not yet seen
//!   mined, named by `(tx_hash, vout, O)` for the ingest to complete as it
//!   assigns gindexes;
//! - **the curve-tree actor's `AssembleTx` handler**, with a spend's own
//!   inputs, which is what makes the capture path total.
//!
//! # Why inside the ingest
//!
//! Capture rides the fold: a chunk that closes over a registered output is
//! written as it closes, for nothing, and one that closed before the
//! registration has to be rebuilt from its leaves. So the registration has
//! to be in place before the fold reaches the output's leaf, and one scan
//! result spans everything from the ledger's height to the tip — after a
//! day offline, or on a restore, that is every output the scan found, most
//! of them drained inside the same result. Registering after the ingest
//! makes every one of those late.
//!
//! - *After the rollback*, because a reorg rebinds gindexes: offered before
//!   it, the new chain's pair would be judged against the old chain's leaf
//!   and reported stale.
//! - *Before the first fold*, for the reason above.
//! - *Inside the respawn-aware wrapper*, because a respawned actor starts
//!   with an empty registry: the retry re-offers the set before it folds
//!   the rest of the range, and a dead actor fails this call with the same
//!   respawn-recoverable fault the ingest's own calls do.
//!
//! # Whose outputs
//!
//! "The wallet's" is two sets, because two identities spend through one
//! tree: the principal's ledger transfers, and the funding outputs the
//! staking persona `P` holds, which live in `P`'s sealed scan state and
//! never enter the ledger.
//!
//! `P`'s scan has no site of its own, and cannot usefully have one: it sweeps
//! only blocks `ARCHIVAL_REORG_DEPTH_BLOCKS` behind the tip
//! (`pscan/start.rs`, `DEFAULT_PSCAN_CADENCE`), and a leaf drains one lock
//! window after its block, so `P` learns of an output long after the drain
//! and a registration made there is late. What makes `P`'s outputs early is
//! that `P` built the transactions that create them: their signed bytes sit
//! in `P`'s sealed pending records from before the first send until the
//! scan confirms them, and [`Engine::persona_expected_outputs`] names every
//! output of those to the tree ahead of the block (§11.13). The scan seal
//! remains the fallback — for an output the wallet did not build, and for a
//! restart between a transaction's mining and the scan's confirmation.

use crate::engine::{
    curve_tree_actor::CurveTreeHandle,
    diagnostics::{DiagnosticSink, RefreshDiagnostic},
    local_ledger::LocalLedger,
    merge::map_curve_tree_handle_error,
    traits::DaemonEngine,
    Engine, EngineSignerKind, RefreshError,
};
use crate::scan::{DetectedTransfer, ScanResult};
use shekyl_curve_tree::ExpectedOutput;

/// One owned output as the curve tree registers it: `(gindex, O)`.
///
/// The pair, not the number alone, because a gindex is a name a reorg
/// re-derives and `O` is the identity that survives it
/// (`CT6_PROVING_STATE.md` §11.9).
pub(crate) type OwnedOutput = (shekyl_curve_tree::Gindex, shekyl_curve_tree::OneTimePubkey);

/// What the refresh offers the curve tree, and whether part of it is missing.
pub(crate) struct OwnedSet {
    /// Every pair the wallet could name.
    pub(crate) outputs: Vec<OwnedOutput>,
    /// Every output of a transaction the persona built and has not yet seen
    /// mined — named by transaction and position, for the tree to register
    /// as it assigns their gindexes ([`Self::expected`]'s derivation is
    /// [`Engine::persona_expected_outputs`]).
    pub(crate) expected: Vec<ExpectedOutput>,
    /// One of the persona's seals could not be read, so its funding outputs
    /// are not in [`Self::outputs`] or its pending transactions not in
    /// [`Self::expected`]. Carried rather than only logged where it is
    /// found, so the refresh can raise it as an event
    /// ([`OwnedSet::report`]).
    pub(crate) persona_seal_unreadable: bool,
}

impl OwnedSet {
    /// Raise [`RefreshDiagnostic::PersonaSealUnreadable`] if the set is
    /// short of the persona's outputs.
    ///
    /// Reading an unreadable seal as empty keeps the principal's refresh
    /// running, and it also quietly moves the persona back onto the
    /// spend-time registration this module exists to avoid. That is a
    /// degraded state someone should be able to see, not only a line in a
    /// log.
    pub(crate) fn report(&self, sink: &impl DiagnosticSink) {
        if self.persona_seal_unreadable {
            sink.emit(RefreshDiagnostic::PersonaSealUnreadable);
        }
    }
}

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

/// Every output of a wallet-built transaction, as the tree expects it:
/// `(tx_hash, vout, O)` straight off the signed bytes.
///
/// Empty, with a warning, when the bytes do not parse whole — they are this
/// wallet's own assembly, so that is a defect, and the outputs will still
/// be registered from the scan seal once the persona's scan reaches them.
pub(crate) fn expected_outputs_of(tx_bytes: &[u8]) -> Vec<ExpectedOutput> {
    let mut cursor = tx_bytes;
    let tx = match shekyl_wire::Transaction::read(&mut cursor) {
        Ok(tx) if cursor.is_empty() => tx,
        Ok(_) => {
            tracing::warn!("curve tree: a sealed pending transaction has trailing bytes");
            return Vec::new();
        }
        Err(detail) => {
            tracing::warn!(%detail, "curve tree: a sealed pending transaction does not parse");
            return Vec::new();
        }
    };
    let tx_hash = tx.hash();
    tx.prefix
        .outputs
        .iter()
        .enumerate()
        .map(|(vout, output)| ExpectedOutput {
            tx_hash,
            vout: u64::try_from(vout).expect("a vout index fits u64"),
            output_key: shekyl_curve_tree::OneTimePubkey::from_bytes(output.key),
        })
        .collect()
}

/// The registration pair for an output the scan has just detected.
///
/// The merge will build this output's ledger row from the same two
/// accessors (`TransferDetails::from_wallet_output`), and
/// `merge::tests::a_detection_and_its_ledger_row_name_one_pair` holds the two
/// derivations equal — a pair registered from the detection has to be the
/// pair [`owned_output`] re-offers from the row on every later refresh, or
/// the second would read as a different output.
pub(crate) fn detected_output(detected: &DetectedTransfer) -> OwnedOutput {
    (
        shekyl_curve_tree::Gindex::from_raw(detected.output.wallet_output().index_on_blockchain()),
        shekyl_curve_tree::OneTimePubkey::from_bytes(
            detected.output.wallet_output().key().compress().to_bytes(),
        ),
    )
}

/// Offer the whole set to the curve tree: the expectations first, then the
/// pairs. This is the ingest's registration step, called between its
/// rollback and its first fold (`merge::curve_tree_ingest_scan_result`), so
/// both are in place before any leaf of the result is folded.
pub(crate) async fn curve_tree_offer(
    curve_tree: &CurveTreeHandle,
    set: &OwnedSet,
) -> Result<shekyl_curve_tree::OwnershipSync, RefreshError> {
    curve_tree
        .set_expected_outputs(set.expected.clone())
        .await
        .map_err(|e| map_curve_tree_handle_error(&e))?;
    curve_tree_sync_owned(curve_tree, &set.outputs).await
}

/// Register `outputs` with the curve tree, reconciling once if any is owed.
///
/// A stale pair — the tree holds a different output at that gindex — means
/// the caller's view is behind the chain the tree is on; it is logged, not
/// an error, and the rescan re-offers the right key. Actor faults map as the
/// ingest's do, so an unavailable actor is respawn-recoverable.
pub(crate) async fn curve_tree_sync_owned(
    curve_tree: &CurveTreeHandle,
    outputs: &[OwnedOutput],
) -> Result<shekyl_curve_tree::OwnershipSync, RefreshError> {
    if outputs.is_empty() {
        return Ok(shekyl_curve_tree::OwnershipSync::default());
    }
    let sync = curve_tree
        .sync_owned(outputs.to_vec())
        .await
        .map_err(|e| map_curve_tree_handle_error(&e))?;
    if !sync.stale.is_empty() {
        tracing::warn!(
            stale = sync.stale.len(),
            "curve tree: registrations whose key disagrees with the tree; the \
             wallet's view is behind the chain and the rescan will re-offer them"
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
    /// Every output the wallet will hold once `result` has merged, as
    /// registration pairs, for the ingest of that same result.
    ///
    /// Three sources, in this order:
    ///
    /// 1. **The ledger's unspent transfers below the result's range.** A row
    ///    at or above the range start is one this result re-derives — the
    ///    range starts at the fork on a reorg, and one past the ledger's
    ///    height otherwise — so offering it would register a pair the merge
    ///    is about to rewind.
    /// 2. **`P`'s held funding outputs** ([`Self::p_funding_outputs`]).
    /// 3. **What `result` detected**, less what it also saw spent. These are
    ///    not in the ledger yet — the merge follows the ingest — and they
    ///    are the outputs the fold is about to reach.
    ///
    /// Unspent only, throughout: capture serves spending, and a spent
    /// output's chunks are rows for nothing. An output a reorg makes unspent
    /// again is offered by the next refresh, when its flag has flipped.
    ///
    /// Sent whole on every refresh. The registry does not persist, so the
    /// first refresh after open is a mass late registration; a re-offer of a
    /// held pair is `AlreadyHeld` and costs a map lookup, and sending it
    /// every time is what keeps the tree's view of ownership from drifting.
    ///
    /// The ledger is read under a brief guard that is released before the
    /// seal is opened: the lock is not re-entrant, and nothing here needs
    /// the two reads to be one instant — a pair missed by a moment is
    /// offered by the next refresh.
    pub(crate) fn owned_outputs(&self, result: &ScanResult) -> OwnedSet {
        let range_start = result.processed_height_range.start;
        let mut outputs: Vec<OwnedOutput> = {
            let guard = self.ledger.read();
            guard
                .ledger
                .ledger
                .transfers()
                .iter()
                .filter(|td| !td.spent && td.block_height < range_start)
                .map(owned_output)
                .collect()
        };
        // The pending seal before the scan seal, in the order the persona
        // writes them (`PendingPostBlock`'s removal-ordering contract): a
        // record retired between the two reads has its outputs in the scan
        // seal by then, so nothing falls between.
        let expected = self.persona_expected_outputs();
        let persona = self.p_funding_outputs();
        let persona_seal_unreadable = expected.is_none() || persona.is_none();
        outputs.extend(persona.unwrap_or_default());
        outputs.extend(
            result
                .new_transfers
                .iter()
                .filter(|detected| {
                    !result
                        .spent_key_images
                        .iter()
                        .any(|spent| spent.key_image == *detected.output.key_image())
                })
                .map(detected_output),
        );
        OwnedSet {
            outputs,
            expected: expected.unwrap_or_default(),
            persona_seal_unreadable,
        }
    }

    /// Every output of every transaction the persona has built and not yet
    /// seen confirmed, from its sealed pending records.
    ///
    /// The records hold the signed transaction bytes, sealed before the
    /// first send and retired only on the persona scan's evidence that the
    /// transaction confirmed — about the archival reorg depth after it was
    /// mined, which is when its outputs appear in the scan seal as funding
    /// records. So an expectation lives exactly as long as the tree needs
    /// it, and nothing new is persisted.
    ///
    /// Every output of each is offered, not a chosen subset: a bond post's
    /// and a claim's outputs all go to the persona's base, a release's
    /// return to it, and a drain's go to the persona (its change) or to the
    /// principal (its payment) — all this wallet's. The principal's are
    /// also found by its own scan, and a pair offered twice is one pair.
    ///
    /// A record whose bytes do not parse is skipped, not fatal: the bytes
    /// were this wallet's own assembly, so that is a defect to log, and
    /// the output is still registered from the scan seal later. An
    /// unreadable seal is `None`, as for [`Self::p_funding_outputs`].
    fn persona_expected_outputs(&self) -> Option<Vec<ExpectedOutput>> {
        use shekyl_engine_state::pending_post_block::PendingPostBlock;

        let sealed = self
            .persistence
            .open_pending_posts(self.state_wrap_key().as_bytes())
            .map_err(|e| e.to_string())
            .and_then(|body| {
                body.map(|bytes| {
                    PendingPostBlock::from_postcard_bytes(&bytes).map_err(|e| e.to_string())
                })
                .transpose()
            });
        let block = match sealed {
            Ok(Some(block)) => block,
            Ok(None) => return Some(Vec::new()),
            Err(detail) => {
                tracing::warn!(
                    %detail,
                    "curve tree: the persona's pending seal could not be read; \
                     the outputs of its unconfirmed transactions are not \
                     expected this refresh"
                );
                return None;
            }
        };
        let pending = block
            .posts()
            .iter()
            .map(|p| p.tx_bytes.as_slice())
            .chain(block.claims().iter().map(|c| c.tx_bytes.as_slice()))
            .chain(block.drains().iter().map(|d| d.tx_bytes.as_slice()))
            .chain(block.releases().iter().map(|r| r.tx_bytes.as_slice()));
        let mut expected = Vec::new();
        for bytes in pending {
            expected.extend(expected_outputs_of(bytes));
        }
        Some(expected)
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
    /// `None` is that case, so the caller can say so ([`OwnedSet::report`]);
    /// the user's own view of it is the staking read, which opens the same
    /// file the same way and fails closed.
    ///
    /// Small synchronous file I/O, once per refresh, of the same class as
    /// the staking reads' own opens.
    fn p_funding_outputs(&self) -> Option<Vec<OwnedOutput>> {
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
            Ok(Some(state)) => Some(state.funding_outputs().iter().map(owned_p_output).collect()),
            Ok(None) => Some(Vec::new()),
            Err(detail) => {
                tracing::warn!(
                    %detail,
                    "curve tree: the persona scan seal could not be read; its \
                     funding outputs are not registered this refresh and will \
                     be when they are spent"
                );
                None
            }
        }
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

    /// A refresh that scanned nothing: the set is then what is already held.
    fn nothing_new() -> ScanResult {
        ScanResult::empty_at(BlockHeight::from_raw(1), None)
    }

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
        let offered = engine.owned_outputs(&nothing_new()).outputs;
        assert_eq!(
            offered,
            vec![pair],
            "the pass offers the sealed funding output and, the ledger being empty, nothing else"
        );
        // The next refresh finds no new block: its ingest folds nothing and
        // still makes the offer.
        let first = engine
            .ingest_scan_result_into_curve_tree(&mut ScanResult::empty_at(
                BlockHeight::from_raw(28),
                None,
            ))
            .await
            .expect("a refresh with nothing new ingests");
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
    /// registration and costs the principal nothing: the set is offered
    /// without it rather than failing the refresh on the state of another
    /// identity's file — and it says so. The refresh raises a diagnostic for
    /// exactly that state and no other, and the staking read, which is what
    /// the user sees, fails closed on the same file.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_undecodable_persona_seal_is_offered_without_and_reported() {
        use crate::engine::diagnostics::AssertionSink;

        let (_tmp, engine) = non_staker_engine(SEED_MULT.wrapping_add(1));
        let reported = |set: &OwnedSet| {
            let sink = AssertionSink::new();
            set.report(&sink);
            sink.recorded()
        };

        // The control: an absent seal is a wallet that never scanned as the
        // persona. Nothing is missing, and nothing is reported.
        let absent = engine.owned_outputs(&nothing_new());
        assert!(absent.outputs.is_empty());
        assert!(!absent.persona_seal_unreadable);
        assert!(reported(&absent).is_empty());

        let garbage = [0xffu8; 16];
        assert!(
            PScanState::from_postcard_bytes(&garbage).is_err(),
            "the fixture must be undecodable for the test to mean anything"
        );
        engine
            .persistence()
            .save_pscan_state(engine.state_wrap_key().as_bytes(), &garbage)
            .expect("the seal itself is well-formed; its body is not");

        let unreadable = engine.owned_outputs(&nothing_new());
        assert!(unreadable.outputs.is_empty());
        assert!(unreadable.persona_seal_unreadable);
        assert!(
            matches!(
                reported(&unreadable).as_slice(),
                [RefreshDiagnostic::PersonaSealUnreadable]
            ),
            "one event, naming the consequence"
        );
        assert!(
            engine.staking_read_view().is_err(),
            "and the user's staking view fails closed on the same seal"
        );
    }

    // ---- Registration inside the ingest ------------------------------------

    /// The fork the reorg fixture replaces [`CHAIN`] with.
    const OTHER_CHAIN: u8 = 2;
    /// One past the last height the scan-result fixtures cover. Blocks 1 and
    /// 2 carry outputs, and both have drained by the tip.
    const END: u64 = 16;

    /// The scan's detection of output `index` of block 1 as `fork` mined it.
    /// Genesis carries one full chunk, so the output's gindex follows it.
    fn detection(fork: u8, index: u64) -> DetectedTransfer {
        use curve25519_dalek::{edwards::CompressedEdwardsY, Scalar};
        use shekyl_scanner::{RecoveredWalletOutput, WalletOutput};

        let key = CompressedEdwardsY(seeded_output_key(fork, 1, index))
            .decompress()
            .expect("a seeded key is a point");
        let base = WalletOutput::new_for_test(
            shekyl_types::TxHash::from_bytes([fork; 32]),
            index,
            PER_BLOCK + index,
            key,
            Scalar::ZERO,
            shekyl_curve_primitives::Commitment {
                mask: Scalar::ONE,
                amount: 1_000,
            },
        );
        DetectedTransfer {
            block_height: BlockHeight::from_raw(1),
            output: RecoveredWalletOutput::new_for_test(base, 1_000),
        }
    }

    /// A scan result over `1..END` on `fork`, reporting the outputs of block
    /// 1 at `detected` as the wallet's.
    ///
    /// The ingest verifies every height against the header's root, so the
    /// roots are what a second tree reconstructs from the same leaves.
    async fn scan_result(fork: u8, detected: &[u64]) -> ScanResult {
        let leaves = |height: u64| {
            let n = if height <= 2 { PER_BLOCK } else { 0 };
            seeded_tx_leaves(fork, height, n)
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let shadow = CurveTreeHandle::spawn(
            shekyl_curve_tree::CurveTreeClient::open(dir.path().join("shadow.redb"))
                .expect("open the shadow tree"),
        );
        shadow
            .ingest(BlockHeight::ZERO, genesis_leaves())
            .await
            .expect("the genesis ingests");
        for height in 1..END {
            shadow
                .ingest(BlockHeight::from_raw(height), leaves(height))
                .await
                .expect("a seeded block ingests");
        }

        let mut result = ScanResult::empty_at(BlockHeight::from_raw(1), None);
        result.processed_height_range = BlockHeight::from_raw(1)..BlockHeight::from_raw(END);
        for height in 1..END {
            let at = BlockHeight::from_raw(height);
            let (root, _) = shadow
                .reference_root_and_depth(at)
                .await
                .expect("the shadow tree answers below its tip");
            result
                .block_curve_tree_roots
                .push((at, shekyl_types::CurveTreeRoot::from_bytes(root)));
            result.block_leaves.push((at, (*leaves(height)).clone()));
        }
        result.new_transfers = detected.iter().map(|&i| detection(fork, i)).collect();
        result
    }

    /// The genesis both forks share. Not empty: a store whose only block is
    /// an empty genesis resumes as a fresh one, and the ingest would then
    /// ask the fixture's unreachable daemon for it after a rollback or a
    /// respawn.
    fn genesis_leaves() -> std::sync::Arc<Vec<crate::scan::OwnedTxLeaves>> {
        seeded_tx_leaves(CHAIN, 0, PER_BLOCK)
    }

    /// An engine whose tree holds the genesis, so the ingest under test
    /// starts at the scan's own range and asks the daemon for nothing.
    async fn engine_at_genesis(seed: u8) -> (tempfile::TempDir, Engine<SoloSigner>) {
        let (tmp, engine) = non_staker_engine(seed);
        engine
            .curve_tree
            .ingest(BlockHeight::ZERO, genesis_leaves())
            .await
            .expect("the genesis ingests");
        (tmp, engine)
    }

    /// What the tree says of `pair` now — the sync a spend would make.
    async fn probe(
        engine: &Engine<SoloSigner>,
        pair: OwnedOutput,
    ) -> shekyl_curve_tree::OwnershipSync {
        engine
            .curve_tree
            .sync_owned(vec![pair])
            .await
            .expect("sync on a live actor")
    }

    /// One scan result spans everything from the ledger's height to the tip,
    /// so an output can be found and drained inside it. The ingest registers
    /// what the result detected before it folds, and the fold captures the
    /// output's chunk as it closes: afterwards the pair is held and served,
    /// and nothing is owed.
    ///
    /// Registered after the ingest instead, the same output is a late
    /// registration — `after_drain == 1` here, and a rebuild of its chunk.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_output_found_and_drained_within_one_scan_result_is_captured_as_it_folds() {
        let (_tmp, engine) = engine_at_genesis(SEED_MULT.wrapping_add(2)).await;
        let mut result = scan_result(CHAIN, &[5]).await;
        let pair = detected_output(&result.new_transfers[0]);

        let ingest = engine
            .ingest_scan_result_into_curve_tree(&mut result)
            .await
            .expect("the scan result ingests");
        assert_eq!(
            (ingest.before_drain, ingest.after_drain),
            (1, 0),
            "offered before its leaf was in the tree"
        );
        assert_eq!(ingest.reconciliation, None, "so nothing was owed");

        // And the fold did capture it: held, drained and served, with
        // nothing left for a reconciliation to write.
        let after = probe(&engine, pair).await;
        assert_eq!(after.already_held, 1);
        assert_eq!(after.reconciliation, None);
    }

    /// A detection the same result saw spent is not offered: its chunks
    /// would be rows for an output that can never be spent again.
    ///
    /// The control is the test above — the same result without the spend
    /// leaves the pair held.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_detection_spent_within_the_same_result_is_not_registered() {
        let (_tmp, engine) = engine_at_genesis(SEED_MULT.wrapping_add(3)).await;
        let mut result = scan_result(CHAIN, &[5]).await;
        let pair = detected_output(&result.new_transfers[0]);
        result.spent_key_images.push(crate::scan::KeyImageObserved {
            block_height: BlockHeight::from_raw(3),
            key_image: *result.new_transfers[0].output.key_image(),
            containing_tx_hash: shekyl_types::TxHash::from_bytes([0x33; 32]),
        });
        assert!(engine.owned_outputs(&result).outputs.is_empty());

        engine
            .ingest_scan_result_into_curve_tree(&mut result)
            .await
            .expect("the scan result ingests");
        let after = probe(&engine, pair).await;
        assert_eq!(after.after_drain, 1, "the probe is its first registration");
    }

    /// A ledger row at or above the result's range is one the result
    /// re-derives, so it is left to the result's own detections: offered
    /// from the ledger it would be a pair the merge is about to rewind.
    /// Below the range it is offered, which is the control.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_ledger_row_the_result_supersedes_is_not_offered_from_the_ledger() {
        let (_tmp, engine) = non_staker_engine(SEED_MULT.wrapping_add(6));
        let detected = detection(CHAIN, 5);
        let pair = detected_output(&detected);
        let mut merged = ScanResult::empty_at(BlockHeight::from_raw(1), None);
        merged.processed_height_range = BlockHeight::from_raw(1)..BlockHeight::from_raw(2);
        merged.block_hashes = vec![(
            BlockHeight::from_raw(1),
            shekyl_types::BlockHash::from_bytes([0x11; 32]),
        )];
        merged.new_transfers = vec![detected];
        engine.apply_scan_result(merged).expect("the row merges");

        let from = |start: u64| {
            engine
                .owned_outputs(&ScanResult::empty_at(BlockHeight::from_raw(start), None))
                .outputs
        };
        assert_eq!(from(2), vec![pair], "a row below the range is held");
        assert!(
            from(1).is_empty(),
            "a row at the range start is the result's to re-derive"
        );
    }

    /// A reorg rebinds gindexes, so the registration is made after the
    /// ingest's rollback: the new chain's pair is judged against the chain
    /// being kept, registers, and is captured as it folds.
    ///
    /// Offered before the rollback it would be compared with the old
    /// chain's leaf at that gindex, reported stale and dropped, and the
    /// probe would read `after_drain == 1`.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_reorged_result_registers_against_the_chain_it_keeps() {
        let (_tmp, engine) = engine_at_genesis(SEED_MULT.wrapping_add(4)).await;
        let mut before = scan_result(CHAIN, &[5]).await;
        let old = detected_output(&before.new_transfers[0]);
        engine
            .ingest_scan_result_into_curve_tree(&mut before)
            .await
            .expect("the first chain ingests");

        let mut reorg = scan_result(OTHER_CHAIN, &[5]).await;
        reorg.reorg_rewind = Some(crate::scan::ReorgRewind {
            fork_height: BlockHeight::from_raw(1),
        });
        let new = detected_output(&reorg.new_transfers[0]);
        assert_eq!(old.0, new.0, "one gindex");
        assert_ne!(old.1, new.1, "two outputs");
        let ingest = engine
            .ingest_scan_result_into_curve_tree(&mut reorg)
            .await
            .expect("the reorg rolls back and ingests the new chain");
        assert!(
            ingest.stale.is_empty(),
            "judged once the old chain's leaf was gone"
        );
        assert_eq!((ingest.before_drain, ingest.after_drain), (1, 0));
        assert_eq!(ingest.reconciliation, None);

        let after = probe(&engine, new).await;
        assert_eq!(
            after.already_held, 1,
            "and captured as the new chain folded"
        );
        assert_eq!(after.reconciliation, None);
        assert_eq!(
            probe(&engine, old).await.stale,
            vec![old.0],
            "the old chain's pair is what is stale now"
        );
    }

    /// A respawned actor starts with an empty registry. The registration is
    /// inside the respawn-aware ingest, so the retry re-offers the set to
    /// the fresh actor before it folds anything.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_respawned_actor_is_re_offered_the_set_before_it_folds() {
        let (_tmp, engine) = engine_at_genesis(SEED_MULT.wrapping_add(5)).await;
        let mut result = scan_result(CHAIN, &[5]).await;
        let pair = detected_output(&result.new_transfers[0]);

        engine.curve_tree.kill_and_wait_for_test().await;
        let ingest = engine
            .ingest_scan_result_with_respawn(&mut result)
            .await
            .expect("the dead actor is respawned and the retry ingests");
        assert_eq!(
            (ingest.before_drain, ingest.after_drain),
            (1, 0),
            "the retry offered the set to the fresh actor before folding"
        );
        assert_eq!(ingest.reconciliation, None);

        let after = probe(&engine, pair).await;
        assert_eq!(after.already_held, 1);
        assert_eq!(after.reconciliation, None);
    }

    // ---- Expected outputs, from the persona's pending seal ------------------

    /// A transaction the persona built: `n` outputs with seeded keys and a
    /// conforming extra, so it parses whole, hashes, and yields leaves.
    fn persona_tx(seed: u64, n: usize) -> shekyl_wire::Transaction {
        use shekyl_wire::{Ct, CtBase, Input, Output, Transaction, TxPrefix};

        let outputs = (0..n)
            .map(|i| Output {
                amount: 0,
                key: seeded_output_key(OTHER_CHAIN, seed, i as u64),
                view_tag: 0,
            })
            .collect();
        Transaction {
            prefix: TxPrefix {
                unlock_time: 0,
                inputs: vec![Input::Gen(seed)],
                outputs,
                extra: crate::engine::test_support::conforming_pqc_extra(n),
            },
            ct: Ct::Null(CtBase {
                enc_amounts: vec![[0u8; 9]; n],
                enc_labels: vec![[0u8; 9]; n],
                commitments: (0..n)
                    .map(|i| seeded_commitment(OTHER_CHAIN, seed, i as u64))
                    .collect(),
            }),
        }
    }

    const PERSONA: shekyl_types::PCanonicalId = shekyl_types::PCanonicalId::from_bytes([0xaa; 32]);

    /// The engine behind the lock the pending seal's one write path takes.
    type SharedEngine = std::sync::Arc<tokio::sync::RwLock<Engine<SoloSigner>>>;

    /// Run `f` over the pending seal through its one write path (WI-3
    /// gate 11), under the engine's own pending-post gate.
    async fn mutate_pending<R>(
        engine: &SharedEngine,
        f: impl FnOnce(&mut shekyl_engine_state::pending_post_block::PendingPostBlock) -> (bool, R),
    ) -> R {
        let gate = engine.read().await.pending_gate.clone();
        crate::engine::pscan::start::pending_post_store_for_engine(
            std::sync::Arc::clone(engine),
            gate,
        )
        .mutate(f)
        .await
        .expect("the pending seal writes")
    }

    /// Seal `tx` as the persona's one pending drain, through the seal's
    /// one write path, as the dispatch seam does before the first send.
    async fn seal_pending_drain(engine: &SharedEngine, tx: &shekyl_wire::Transaction) {
        use shekyl_engine_state::pending_post_block::{
            PendingDrain, PendingPostState, SealAdmission,
        };

        let tx_bytes = crate::engine::test_support::whole_tx_wire_bytes(tx);
        mutate_pending(engine, |block| {
            let admission = block.seal_drain(
                PendingDrain {
                    persona: PERSONA,
                    tx_bytes,
                    funding_gindexes: vec![shekyl_types::GlobalOutputIndex::from_raw(1)],
                    state: PendingPostState::Pending,
                },
                shekyl_types::ChainCount::from_raw(1),
                block.generation(),
            );
            assert!(matches!(admission, SealAdmission::Admit), "{admission:?}");
            (true, ())
        })
        .await;
    }

    /// The block at height 1 carrying `tx`, as the scan would hand it to
    /// the ingest: leaves decoded from the transaction itself, with its hash.
    fn block_one_carrying(tx: &shekyl_wire::Transaction) -> Vec<crate::scan::OwnedTxLeaves> {
        let mut scannable = crate::engine::test_support::make_synthetic_block(
            1,
            shekyl_types::BlockHash::from_bytes([0x01; 32]),
        );
        scannable.block.transaction_hashes.push(tx.hash());
        scannable.transactions.push(tx.clone());
        crate::engine::curve_tree_decode::decode_block_leaves(&scannable)
            .expect("the block decodes")
    }

    /// A scan result over `1..END` whose block 1 carries `tx` and whose
    /// other blocks are empty, header roots from a shadow tree.
    async fn result_carrying(tx: &shekyl_wire::Transaction) -> ScanResult {
        let block_one = std::sync::Arc::new(block_one_carrying(tx));
        let dir = tempfile::tempdir().expect("tempdir");
        let shadow = CurveTreeHandle::spawn(
            shekyl_curve_tree::CurveTreeClient::open(dir.path().join("shadow.redb"))
                .expect("open the shadow tree"),
        );
        shadow
            .ingest(BlockHeight::ZERO, genesis_leaves())
            .await
            .expect("the genesis ingests");
        let mut result = ScanResult::empty_at(BlockHeight::from_raw(1), None);
        result.processed_height_range = BlockHeight::from_raw(1)..BlockHeight::from_raw(END);
        for height in 1..END {
            let at = BlockHeight::from_raw(height);
            let leaves = if height == 1 {
                std::sync::Arc::clone(&block_one)
            } else {
                seeded_tx_leaves(CHAIN, height, 0)
            };
            shadow
                .ingest(at, std::sync::Arc::clone(&leaves))
                .await
                .expect("the shadow ingests");
            let (root, _) = shadow
                .reference_root_and_depth(at)
                .await
                .expect("the shadow answers");
            result
                .block_curve_tree_roots
                .push((at, shekyl_types::CurveTreeRoot::from_bytes(root)));
            result.block_leaves.push((at, (*leaves).clone()));
        }
        result
    }

    /// The outputs of a transaction the persona built are registered as
    /// the block carrying it folds — named ahead by `(tx_hash, vout)` from
    /// the sealed pending record, confirmed by key at ingest — so by the
    /// time the leaf drains it is held and nothing is owed.
    ///
    /// The probe right after the ingest is the discriminator: registered at
    /// ingest, the pair is `AlreadyHeld`; registered by nobody, the probe
    /// is its first registration and reads `after_drain == 1`.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_pending_transactions_outputs_are_registered_as_its_block_folds() {
        let (_tmp, engine) = engine_at_genesis(SEED_MULT.wrapping_add(7)).await;
        let tx = persona_tx(900, 3);
        let shared: SharedEngine = std::sync::Arc::new(tokio::sync::RwLock::new(engine));
        seal_pending_drain(&shared, &tx).await;
        let engine = shared.read().await;

        let mut result = result_carrying(&tx).await;
        let set = engine.owned_outputs(&result);
        assert_eq!(
            set.expected,
            expected_outputs_of(&crate::engine::test_support::whole_tx_wire_bytes(&tx)),
            "every output of the sealed transaction, by hash and position"
        );
        assert_eq!(set.expected.len(), 3);
        assert!(!set.persona_seal_unreadable);

        engine
            .ingest_scan_result_into_curve_tree(&mut result)
            .await
            .expect("the scan result ingests");

        // The miner transaction of block 1 has no outputs, so the persona's
        // transaction takes the gindexes after the genesis chunk.
        for (vout, expected) in set.expected.iter().enumerate() {
            let pair = (
                shekyl_curve_tree::Gindex::from_raw(PER_BLOCK + vout as u64),
                expected.output_key,
            );
            let at_spend = probe(&engine, pair).await;
            assert_eq!(
                at_spend.already_held, 1,
                "vout {vout}: held since its block folded"
            );
            assert_eq!(at_spend.reconciliation, None, "vout {vout}: nothing owed");
        }
    }

    /// The expectation lives as long as its record: retired, it is gone
    /// from the next offer, and the output is the scan seal's to name.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_retired_pending_record_withdraws_its_expectations() {
        let (_tmp, engine) = non_staker_engine(SEED_MULT.wrapping_add(8));
        let tx = persona_tx(901, 2);
        let shared: SharedEngine = std::sync::Arc::new(tokio::sync::RwLock::new(engine));
        seal_pending_drain(&shared, &tx).await;
        assert_eq!(
            shared
                .read()
                .await
                .owned_outputs(&nothing_new())
                .expected
                .len(),
            2
        );

        mutate_pending(&shared, |block| {
            (block.remove_drain(&PERSONA).is_some(), ())
        })
        .await;

        let engine = shared.read().await;
        let set = engine.owned_outputs(&nothing_new());
        assert!(set.expected.is_empty());
        assert!(!set.persona_seal_unreadable);
    }

    /// A pending record whose bytes do not parse costs its expectations
    /// and nothing else: the bytes were this wallet's own assembly, so that
    /// is a defect to log, and the seal itself is readable.
    #[test]
    fn unparseable_pending_bytes_expect_nothing() {
        assert!(expected_outputs_of(&[0xff; 7]).is_empty());
        let mut trailing = crate::engine::test_support::whole_tx_wire_bytes(&persona_tx(902, 1));
        trailing.push(0);
        assert!(expected_outputs_of(&trailing).is_empty());
    }
}
