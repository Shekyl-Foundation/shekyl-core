// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Engine-side emission-claim orchestration (`EMISSION_CLAIM_BUILDER.md` §8
//! PR-3; CB-2's Engine half).
//!
//! The `StakeEngine`'s [`AssembleEmissionClaim`] handler is deliberately
//! operand-driven: it receives the claim source, the designated backing, the
//! swept fee inputs, and the assembled membership paths as one sealed
//! [`ClaimOperands`](super::backing_set::ClaimOperands) — mintable only
//! through the designation-event seal (`backing_set.rs`), so the item-6
//! same-tip check and the Q11 exclusion fire at the mint, not in the
//! handler. This module is the production preparer — the single pipeline
//! that gathers those operands from their authoritative sources and hands
//! them to the actor:
//!
//! 1. **Fetch** ([`fetch_emission_claim_source`]) — the single-field `p_id`
//!    query (§7.2: the request shape is identical for every claimant),
//!    over a [`PersonaIsolatedTransport`] **only** (the §7.4 transport pin,
//!    structural: the principal's daemon session does not implement the
//!    marker, so a claim fetch on the principal's network identity is a
//!    compile error).
//! 2. **Anchor** ([`claim_reference_height`]) — the shared two-sided
//!    reference gate ([`two_sided_reference_height`], the same definition
//!    the transfer path's re-anchor consumes): anchor
//!    [`REF_ANCHOR_AGE`](shekyl_curve_tree::REF_ANCHOR_AGE) behind
//!    `min(chain tip, ingested tip)`, refuse a
//!    reference already past the re-anchor threshold.
//! 3. **Designate** ([`BackingSet::from_spendable`] → `designate_backing`) —
//!    the sole backing exit, the claimant slot's records only, anchored at
//!    the gather **tip** (`source.chain_height − 1`) so the handler's
//!    same-tip check holds by construction.
//! 4. **Fee-sweep** ([`DesignatedBacking::fee_sweep`]) — the Q11-excluding
//!    sole fee entry, over the same provable record set; consumes the
//!    designation and the source into the sealed
//!    [`SweptFeeInputs`](super::backing_set::SweptFeeInputs) witness.
//! 5. **Assemble paths** ([`CurveTreeHandle::assemble_tx`]) — every membership
//!    path (backing + fees) against ONE reference snapshot, zipped into the
//!    witness ([`SweptFeeInputs::with_paths`](super::backing_set::SweptFeeInputs::with_paths),
//!    the sole `ClaimOperands` mint).
//! 6. **Hand off** ([`StakeEngineHandle::assemble_emission_claim`]) — signing
//!    stays inside the actor (CB-2); the reply is returned to the caller
//!    unbroadcast (CB-3: dispatch is the GF-4 seam, not this builder).
//!
//! ## Provability pre-filter
//!
//! The designation/sweep spendability anchor is the gather **tip** (the
//! daemon reports `chain_height`, a block count; the tip is
//! `chain_height − 1`), but a membership proof exists only for outputs
//! already **drained into the tree at the reference height** — which sits
//! [`REF_ANCHOR_AGE`](shekyl_curve_tree::REF_ANCHOR_AGE) blocks behind that
//! tip ([`select_reference_height`]). Records with
//! `spendable_height > reference_height` are spendable
//! but not yet provable — selecting one would assemble a claim the daemon
//! rejects. The pipeline therefore pre-filters the record set to the provable
//! subset before designation and sweep, the same drained-at-reference rule
//! the transfer fixture pins (`funded_ledger_and_tree`:
//! `owned_block + SPENDABLE_AGE <= synced - REF_ANCHOR_AGE`).
//!
//! ## The SP-R0 witness
//!
//! [`SpentRecordsDurablyPruned`] has no production constructor yet (SP-R0);
//! the orchestrator takes it by reference and threads it to the sweep, so the
//! compile-time sequencing witness holds end-to-end: production callers exist
//! only once SP-R0 lands, tests mint via `for_test()`.

use std::collections::BTreeSet;

use shekyl_curve_tree::{
    two_sided_reference_height, AssembleInput, BlockHeight as TreeBlockHeight, Gindex,
    ReferenceBlock, TwoSidedRefusal,
};
use shekyl_engine_state::pscan_state::{BondPostRecord, PFundingOutputRecord};
use shekyl_types::{BlockHeight, ChainCount, GlobalOutputIndex, PCanonicalId};
use shekyl_units::AtomicUnits;

use super::backing_set::{BackingSet, ClaimFundingError, InsufficientBacking, MembershipPath};
use super::bond_assembly::SpentRecordsDurablyPruned;
use super::curve_tree_actor::{CurveTreeHandle, CurveTreeHandleError};
use super::emission_source::{fetch_emission_claim_source, EmissionSourceError};
use super::prpc::PersonaIsolatedTransport;
use super::signing_assembly::{leaf_entry_from_chunk, tree_context_from};
use super::stake_engine::{
    AssembleEmissionClaim, AssembledEmissionClaim, PersonaHandle, StakeEngineError,
    StakeEngineHandle,
};

/// Why the claim pipeline refused before (or at) the actor hand-off. Every
/// arm is caller-recoverable state, not a defect: refetch/resync/refund and
/// retry per the arm's docs.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ClaimOrchestrationError {
    /// The claim-source fetch or decode refused (transport, non-OK status,
    /// or a malformed reply — the untrusted-boundary refusals).
    #[error("claim-source fetch failed: {0}")]
    Source(#[from] EmissionSourceError),
    /// A curve-tree handle call failed (client refusal or a stopped actor —
    /// terminal until the engine respawns the actor).
    #[error("curve tree unavailable or refused: {0:?}")]
    Tree(CurveTreeHandleError),
    /// No submittable reference can be anchored right now (chain too short,
    /// tree not yet ingesting, or the tree too far behind the daemon tip).
    /// Resync and retry; assembling against a stale reference would produce
    /// a proof the daemon rejects.
    #[error("no submittable reference can be anchored: {detail}")]
    ReferenceUnanchorable { detail: &'static str },
    /// The ledger has no block hash at the reference height — the wallet's
    /// header window does not cover the anchor yet. Resync and retry.
    #[error("no block hash at reference height {height}")]
    MissingBlockHash { height: u64 },
    /// No backing-eligible output exists at the gather tip.
    #[error(transparent)]
    NoBackingEligible(#[from] InsufficientBacking),
    /// The designation-event seal refused to mint (a stale anchor, no fee
    /// input at all, a genuine shortfall, or a path-count mismatch — see
    /// [`ClaimFundingError`]'s arms).
    #[error(transparent)]
    Funding(#[from] ClaimFundingError),
    /// The actor refused or failed the assembly itself.
    #[error(transparent)]
    Stake(#[from] StakeEngineError),
}

/// The read-side operands of one claim assembly, borrowed from their owners
/// (the engine's actors, the persisted P-scan state, the live reservation
/// set). Bundled so the pipeline's signature names the flow's inputs once.
pub(crate) struct ClaimAssemblyContext<'a> {
    /// The stake actor — assembly and signing stay inside it (CB-2).
    pub stake: &'a StakeEngineHandle,
    /// The curve-tree actor — reference root and membership paths.
    pub tree: &'a CurveTreeHandle,
    /// SP-R0 sequencing witness, threaded to the sweep (see module docs).
    pub pruning_landed: &'a SpentRecordsDurablyPruned,
    /// The persona's persisted funding records (`PScanState::funding_outputs`).
    pub funding_records: &'a [PFundingOutputRecord],
    /// The persona's confirmed bond-post matches
    /// (`PScanState::bond_post_matches`) — the last-sweep-height source.
    pub bond_posts: &'a [BondPostRecord],
    /// Live gindex reservations (outputs already committed to in-flight txs).
    pub reserved: &'a BTreeSet<GlobalOutputIndex>,
    /// The claimant persona's canonical id — the fetch's single query field
    /// and the bond-post ownership filter.
    pub p_canonical_id: PCanonicalId,
    /// The fee the claim tx must fund from swept `ToKey` inputs (fee inputs
    /// are structurally mandatory — the reward is fully consumed by the loud
    /// vout, so it cannot pay its own fee).
    pub fee: u64,
}

/// The last **confirmed** sweep height for `persona`: the highest bond-post
/// match carrying its canonical id, or height 0 when none is recorded (a
/// persona that never posted sweeps from genesis). Feeds
/// [`BackingSet::from_spendable`]'s legal-tranche boundary.
fn last_confirmed_sweep_height(posts: &[BondPostRecord], persona: &PCanonicalId) -> BlockHeight {
    posts
        .iter()
        .filter(|p| p.p_canonical_id == *persona)
        .map(|p| p.height)
        .max()
        .unwrap_or(BlockHeight::from_raw(0))
}

/// The gather tip and the claim's curve-tree reference height, or a refusal
/// when none is submittable — [`ChainCount::tip`] over the daemon-reported
/// count, then the shared two-sided gate ([`two_sided_reference_height`]:
/// the one definition the transfer path's re-anchor also consumes, §3b F-C)
/// against the tree's ingested tip. Returned as a pair so the designation
/// anchor (the tip) and the reference anchor come from one derivation.
fn claim_reference_height(
    chain_height: ChainCount,
    ingested_tip: Option<u64>,
) -> Result<(BlockHeight, u64), ClaimOrchestrationError> {
    let tip = chain_height
        .tip()
        .ok_or(ClaimOrchestrationError::ReferenceUnanchorable {
            detail: "daemon reports an empty chain",
        })?;
    let ingested = ingested_tip.ok_or(ClaimOrchestrationError::ReferenceUnanchorable {
        detail: "curve tree has not ingested any block yet",
    })?;
    let reference_height =
        two_sided_reference_height(tip.to_raw(), ingested).map_err(|refusal| {
            ClaimOrchestrationError::ReferenceUnanchorable {
                detail: match refusal {
                    TwoSidedRefusal::ChainTooShort => "chain too short to anchor a reference",
                    TwoSidedRefusal::TreeTooFarBehind => {
                        "tree too far behind the daemon tip to anchor a submittable reference"
                    }
                },
            }
        })?;
    Ok((tip, reference_height))
}

/// The provability pre-filter (module docs): the subset of `records` already
/// drained into the curve tree at `reference_height` — inclusive at the
/// boundary, matching the tree's drain rule (`eligible_height <= reference`).
/// Borrows: the designation and the sweep clone only what they select.
fn provable_records(
    records: &[PFundingOutputRecord],
    reference_height: u64,
) -> Vec<&PFundingOutputRecord> {
    records
        .iter()
        .filter(|r| r.spendable_height.to_raw() <= reference_height)
        .collect()
}

/// Run the full claim pipeline (module docs, steps 1–6) and return the
/// actor's reply — the signed, wire-encoded claim plus its public facts —
/// **unbroadcast** (CB-3).
///
/// `block_hash_at` resolves the reference-height block hash from the caller's
/// ledger (the orchestrator has no ledger access of its own; the engine owns
/// the header window). `handle` is the operation-scoped slot capability; its
/// slot also names the sweep's record filter.
// Staging (not tolerated dead code, `15-deletion-and-debt.mdc`): this is
// PR-3's production pipeline awaiting its request path — the CB-3 dispatch
// seam (2c-2b sibling) is the sole production caller and deletes this allow
// when it lands.
#[allow(dead_code)]
pub(crate) async fn orchestrate_emission_claim<R: PersonaIsolatedTransport>(
    rpc: &R,
    handle: PersonaHandle,
    ctx: ClaimAssemblyContext<'_>,
    block_hash_at: impl Fn(u64) -> Option<[u8; 32]>,
) -> Result<AssembledEmissionClaim, ClaimOrchestrationError> {
    // 1+2a. Fetch the claim source (single-field query over the persona's
    //    OWN transport — the `PersonaIsolatedTransport` bound is the §7.4
    //    structural pin; decode enforces the settled/height invariant at
    //    the untrusted boundary) and read the tree's ingested tip — two
    //    independent awaits, joined.
    let (source, ingested) = tokio::join!(
        fetch_emission_claim_source(rpc, ctx.p_canonical_id.as_bytes()),
        ctx.tree.ingested_tip_height()
    );
    let source = source?;
    let ingested = ingested.map_err(ClaimOrchestrationError::Tree)?;

    // 2b. Anchor: the gather tip ([`ChainCount::tip`] — typed, so the count
    //    cannot be laundered into a height) and the reference height (the
    //    shared two-sided gate over gather tip × ingested tip), from one
    //    derivation.
    let (gather_tip, reference_height) =
        claim_reference_height(source.chain_height, ingested.map(|h| h.0))?;

    // Provability pre-filter (module docs): only outputs drained into the
    // tree at the reference height can carry a membership proof.
    let provable = provable_records(ctx.funding_records, reference_height);

    // 3. Designate the backing — the claimant slot's records only, anchored
    //    at the gather tip — so the handler's same-tip operand holds by
    //    construction (`backing_set.rs` stores ONE height).
    let last_sweep = last_confirmed_sweep_height(ctx.bond_posts, &ctx.p_canonical_id);
    let backing = BackingSet::from_spendable(
        provable.iter().copied(),
        handle.p_slot(),
        gather_tip,
        last_sweep,
    )
    .designate_backing()?;

    // 4. Fee sweep through the designated backing (the Q11-excluding sole
    //    fee entry), over the same provable set and spendability anchor —
    //    the designation-event seal's mint: the source and the backing move
    //    into the [`SweptFeeInputs`] witness together, and the item-6
    //    same-tip check fires here, once.
    let swept = backing.fee_sweep(
        source,
        ctx.pruning_landed,
        provable.iter().copied(),
        handle.p_slot(),
        ctx.reserved,
        AtomicUnits::from_raw(ctx.fee),
    )?;

    // 5. One reference snapshot, every membership path against it.
    let (curve_tree_root, _depth) = ctx
        .tree
        .reference_root_and_depth(TreeBlockHeight(reference_height))
        .await
        .map_err(ClaimOrchestrationError::Tree)?;
    let block_hash =
        block_hash_at(reference_height).ok_or(ClaimOrchestrationError::MissingBlockHash {
            height: reference_height,
        })?;
    let reference = ReferenceBlock {
        height: TreeBlockHeight(reference_height),
        curve_tree_root,
        block_hash,
    };
    let assemble_inputs: Vec<AssembleInput> = swept
        .path_records()
        .map(|r| AssembleInput {
            gindex: Gindex(r.gindex.to_raw()),
            output_key: r.output_key,
            commitment: r.commitment,
        })
        .collect();
    let paths = ctx
        .tree
        .assemble_tx(reference, assemble_inputs)
        .await
        .map_err(ClaimOrchestrationError::Tree)?;

    // Field-copy across the curve-tree → tx-builder boundary. Every path
    // shares one tree context (`assemble_tx`'s single-snapshot guarantee),
    // so the message takes the first path's; the path↔record pairing itself
    // is the seal's — `with_paths` counts and zips in the mint's own order,
    // refusing a mismatch loudly.
    let tree_ctx = paths.first().map(|p| tree_context_from(&p.tree));
    let membership_paths: Vec<MembershipPath> = paths
        .into_iter()
        .map(|path| MembershipPath {
            leaf_chunk: path.leaf_chunk.iter().map(leaf_entry_from_chunk).collect(),
            c1_layers: path.c1_layers,
            c2_layers: path.c2_layers,
        })
        .collect();
    let operands = swept.with_paths(membership_paths)?;
    let tree_ctx = tree_ctx.expect("with_paths minted: at least the backing path exists");

    // 6. Hand the sealed operands to the actor (CB-2: derivation, proving,
    //    and signing stay inside it) and return the reply unbroadcast.
    Ok(ctx
        .stake
        .assemble_emission_claim(AssembleEmissionClaim {
            handle,
            operands,
            tree_ctx,
        })
        .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    use shekyl_curve_tree::REF_ANCHOR_AGE;
    use shekyl_engine_state::pscan_state::MintLineageOutput;

    fn post(height: u64, persona: PCanonicalId) -> BondPostRecord {
        BondPostRecord {
            height: BlockHeight::from_raw(height),
            p_canonical_id: persona,
            post_kind: 0,
        }
    }

    /// The sweep boundary reads the persona's OWN posts only: the max height
    /// among matching ids, height 0 when the persona never posted — another
    /// persona's later post must not move the boundary.
    #[test]
    fn last_sweep_height_is_the_personas_own_max() {
        let ours = PCanonicalId::from_bytes([1u8; 32]);
        let theirs = PCanonicalId::from_bytes([2u8; 32]);
        let posts = vec![post(100, ours), post(300, theirs), post(250, ours)];

        assert_eq!(
            last_confirmed_sweep_height(&posts, &ours),
            BlockHeight::from_raw(250),
            "our max is 250; the foreign 300 must not be read"
        );
        assert_eq!(
            last_confirmed_sweep_height(&posts, &PCanonicalId::from_bytes([3u8; 32])),
            BlockHeight::from_raw(0),
            "a persona with no posts sweeps from genesis"
        );
    }

    /// The two-sided reference gate, all four arms: the happy anchor
    /// (`min(tip, ingested) − REF_ANCHOR_AGE`, paired with the typed gather
    /// tip), and the three refusals — no ingest yet, chain too short, tree
    /// too far behind (`should_reanchor` inclusive at `REBUILD_AT`).
    #[test]
    fn claim_reference_height_arms() {
        let count = |c: u64| ChainCount::from_raw(c);

        // Happy: tree synced to the tip; count 30_001 → tip 30_000.
        assert_eq!(
            claim_reference_height(count(30_001), Some(30_000)).expect("anchorable"),
            (BlockHeight::from_raw(30_000), 30_000 - REF_ANCHOR_AGE)
        );
        // Happy, tree one block behind: the min-arm anchors off the tree;
        // the gather tip stays the chain's.
        assert_eq!(
            claim_reference_height(count(30_001), Some(29_999)).expect("anchorable"),
            (BlockHeight::from_raw(30_000), 29_999 - REF_ANCHOR_AGE)
        );

        // Refusal: no ingest.
        assert!(matches!(
            claim_reference_height(count(30_001), None),
            Err(ClaimOrchestrationError::ReferenceUnanchorable { .. })
        ));
        // Refusal: chain shorter than the anchor age (and the empty chain,
        // where `ChainCount::tip()` itself is None).
        assert!(matches!(
            claim_reference_height(count(REF_ANCHOR_AGE), Some(REF_ANCHOR_AGE - 1)),
            Err(ClaimOrchestrationError::ReferenceUnanchorable { .. })
        ));
        assert!(matches!(
            claim_reference_height(ChainCount::ZERO, Some(0)),
            Err(ClaimOrchestrationError::ReferenceUnanchorable { .. })
        ));
        // Refusal: the tree so far behind that the anchored reference is
        // already at the re-anchor threshold. Boundary-exact: one block
        // inside the threshold anchors, at the threshold refuses.
        let tip = 30_000u64;
        let rebuild_at = shekyl_curve_tree::REBUILD_AT;
        let barely_ok = tip - rebuild_at + REF_ANCHOR_AGE + 1;
        assert!(claim_reference_height(count(tip + 1), Some(barely_ok)).is_ok());
        assert!(matches!(
            claim_reference_height(count(tip + 1), Some(barely_ok - 1)),
            Err(ClaimOrchestrationError::ReferenceUnanchorable { .. })
        ));
    }

    /// The provability pre-filter's inclusive boundary: an output drained AT
    /// the reference height proves; one drained a block later is spendable
    /// at the gather tip but not yet provable, and must not enter
    /// designation or the sweep.
    #[test]
    fn provability_boundary_is_inclusive_at_the_reference_height() {
        let at = crate::engine::test_support::funding_record(
            0,
            7,
            100,
            1_000,
            MintLineageOutput::ExternalTransfer,
        );
        let mut later = crate::engine::test_support::funding_record(
            0,
            8,
            101,
            1_000,
            MintLineageOutput::ExternalTransfer,
        );
        later.spendable_height = BlockHeight::from_raw(at.spendable_height.to_raw() + 1);

        let reference_height = at.spendable_height.to_raw();
        let records = [at, later];
        let kept = provable_records(&records, reference_height);
        assert_eq!(
            kept.iter().map(|r| r.gindex.to_raw()).collect::<Vec<_>>(),
            vec![7],
            "inclusive at the boundary; the one-block-later record is filtered"
        );
    }

    mod end_to_end {
        use super::*;

        use std::sync::Arc;

        use serde_json::{json, Value};
        use shekyl_archival_retention::{emission_vin_verify_backing, ArchivalRewardEmissionVin};
        use shekyl_curve_tree::{
            BlockLeaves, CurveTreeClient, RawOutput, TargetKind, TxLeafInputs,
        };
        use shekyl_engine_state::pscan_state::MintLineageOutput;
        use shekyl_rpc_client::{Rpc, RpcError};
        use shekyl_wire::{Input, Transaction};

        // `source_json` is the crate's single test-side encoder of the
        // daemon wire shape (see its doc in `emission_claim::test_fixtures`)
        // — the fetch leg decodes the exact typed fixture through the real
        // untrusted-boundary path.
        use crate::engine::emission_claim::test_fixtures::{
            snapshot, source_at_count, source_json,
        };
        use crate::engine::stake_engine::test_fixtures::{
            constructed_record, derive_bundle, spawn_over,
        };
        use crate::engine::stake_engine::PSlot;

        /// A daemon that serves one canned claim-source result through the
        /// real `json_rpc_call` envelope path (the trait's default impl runs
        /// unmocked — only the transport is canned).
        #[derive(Clone)]
        struct ClaimSourceDaemon(Arc<Value>);

        impl Rpc for ClaimSourceDaemon {
            fn post(
                &self,
                route: &str,
                _body: Vec<u8>,
            ) -> impl Send + std::future::Future<Output = Result<Vec<u8>, RpcError>> {
                let reply = serde_json::to_vec(&json!({ "result": *self.0 }))
                    .expect("fixture result encodes");
                let ok = route == "json_rpc";
                async move {
                    if ok {
                        Ok(reply)
                    } else {
                        Err(RpcError::InternalError("unexpected route".into()))
                    }
                }
            }
        }

        // Test transport (see the marker's doc): the §7.4 pin is against
        // production misuse; a canned test daemon carries no network
        // identity at all.
        impl PersonaIsolatedTransport for ClaimSourceDaemon {}

        /// The pipeline end-to-end over the REAL substrate — no synthetic
        /// paths, no pre-prepared operands:
        ///
        /// - a real [`CurveTreeClient`] with the whole fixture chain ingested
        ///   (the two P-paid outputs mined at one block, drained by maturity),
        ///   so `reference_root_and_depth` and `assemble_tx` produce the
        ///   actual root, depth, and membership paths;
        /// - a mock daemon serving the wire-shape JSON reply, so the fetch
        ///   leg decodes through the real untrusted-boundary path;
        /// - the real `StakeEngine` actor doing derivation, proving, and
        ///   signing over the pipeline-prepared operands.
        ///
        /// The produced bytes then face the same daemon-side re-derivation
        /// the handler KAT pins, against the REAL tree root: erase the
        /// emission vin at its index, verify the membership proof + leaf
        /// gate + both auths against that root and depth. A pipeline that
        /// designated the wrong record, mixed reference snapshots, or
        /// mis-paired paths to records refuses here.
        #[tokio::test(flavor = "multi_thread")]
        async fn orchestrated_claim_assembles_and_verifies_over_a_real_tree() {
            // Fixture chain: count 30_001 (tip 30_000) — settled epoch 3,
            // epoch 2 past its close by exactly one count (the strict-
            // finalization earliest), matching the decode fixture's shape.
            let chain_height = 30_001u64;
            let tip = chain_height - 1;
            let owned_block = 100u64;
            let source = source_at_count(chain_height, vec![], vec![snapshot(2)]);

            let stake = spawn_over(&[0], &[], None);
            let handle = stake
                .mint_handle(PSlot::from_raw(0))
                .await
                .expect("slot 0 held");
            let keys = derive_bundle(0);
            let p_id = shekyl_archival_retention::p_canonical_id_from_hybrid_pubkey(
                &keys
                    .hybrid_sign_pk
                    .to_canonical_bytes()
                    .expect("identity encodes"),
            );

            // Two REAL P-paid outputs mined at `owned_block` as the chain's
            // only outputs, so gindex == chain position (0: backing, 1: fee).
            let (backing_record, backing_leaf) = constructed_record(
                &keys,
                0,
                owned_block,
                750_000,
                0,
                MintLineageOutput::BondPostChange,
            );
            let (fee_record, fee_leaf) = constructed_record(
                &keys,
                1,
                owned_block,
                90_000,
                1,
                MintLineageOutput::ExternalTransfer,
            );
            let backing_gindex = backing_record.gindex;
            let fee_gindex = fee_record.gindex;

            // Ingest the whole chain into a real (ephemeral-store) client —
            // maturity drain, gindex threading, root reconstruction all real.
            let leaf_blob: Vec<u8> = [backing_leaf.h_pqc, fee_leaf.h_pqc].concat();
            let raw_outputs = vec![
                RawOutput {
                    output_key: backing_leaf.output_key,
                    commitment: Some(backing_leaf.commitment),
                    target: TargetKind::TaggedKey,
                },
                RawOutput {
                    output_key: fee_leaf.output_key,
                    commitment: Some(fee_leaf.commitment),
                    target: TargetKind::TaggedKey,
                },
            ];
            let client = tokio::task::spawn_blocking(move || {
                let mut client = CurveTreeClient::new();
                for h in 0..=tip {
                    let txs: Vec<TxLeafInputs<'_>> = if h == owned_block {
                        vec![TxLeafInputs {
                            is_miner: false,
                            leaf_hash_blob: Some(&leaf_blob),
                            outputs: &raw_outputs,
                        }]
                    } else {
                        vec![]
                    };
                    client
                        .ingest_block(BlockLeaves {
                            height: TreeBlockHeight(h),
                            txs: &txs,
                        })
                        .expect("fixture chain ingests");
                }
                client
            })
            .await
            .expect("tree-build task completes");
            let tree = CurveTreeHandle::spawn(client);

            // A FOREIGN persona's later bond post: the ownership filter must
            // not read it — if it did, the sweep boundary would move past the
            // rung-3 fee record and the survivor tripwire would fire loudly.
            let bond_posts = vec![BondPostRecord {
                height: BlockHeight::from_raw(tip),
                p_canonical_id: PCanonicalId::from_bytes([9u8; 32]),
                post_kind: 0,
            }];

            let expected_reference = tip - REF_ANCHOR_AGE;
            let funding_records = vec![backing_record, fee_record];
            let reserved = BTreeSet::new();
            let pruned = SpentRecordsDurablyPruned::for_test();
            let fee = 10_000u64;
            let rpc = ClaimSourceDaemon(Arc::new(source_json(&source)));

            let reply = orchestrate_emission_claim(
                &rpc,
                handle,
                ClaimAssemblyContext {
                    stake: &stake,
                    tree: &tree,
                    pruning_landed: &pruned,
                    funding_records: &funding_records,
                    bond_posts: &bond_posts,
                    reserved: &reserved,
                    p_canonical_id: p_id,
                    fee,
                },
                |height| {
                    assert_eq!(height, expected_reference, "anchor per the two-sided gate");
                    Some([0xB1u8; 32])
                },
            )
            .await
            .expect("the pipeline assembles end-to-end over the real substrate");

            // Public facts: epoch 2 claimed, a live reward, and the Q11
            // surface through the WHOLE pipeline — the sweep reserved only
            // the fee spend; the backing was never selected as a fee input.
            assert_eq!(reply.claimed_epochs, vec![2]);
            assert!(
                reply.total_reward > 0,
                "fixture epoch carries a real reward"
            );
            assert!(reply.size_deferred.is_empty());
            assert_eq!(reply.fee_gindexes, vec![fee_gindex]);
            assert!(!reply.fee_gindexes.contains(&backing_gindex));

            // Daemon-side re-derivation against the REAL root: parse the
            // bytes, erase the emission vin at its index (the
            // `blockchain.cpp:3866` rule), and verify the membership proof,
            // leaf gate, and both auths against the root and depth the tree
            // reports at the anchored reference.
            let (root, depth) = tree
                .reference_root_and_depth(TreeBlockHeight(expected_reference))
                .await
                .expect("reference root resolves");
            let mut cursor: &[u8] = reply.bound_tx.bytes();
            let mut tx = Transaction::read(&mut cursor).expect("assembled bytes parse whole");
            assert!(cursor.is_empty(), "no trailing bytes after the tx");
            let emission_index = tx
                .prefix
                .inputs
                .iter()
                .position(|i| matches!(i, Input::ArchivalRewardEmission { .. }))
                .expect("emission vin present");
            let Input::ArchivalRewardEmission { canonical_bytes } =
                &tx.prefix.inputs[emission_index]
            else {
                unreachable!("position() matched this variant");
            };
            let vin = ArchivalRewardEmissionVin::read(&mut canonical_bytes.as_slice())
                .expect("vin blob parses");
            tx.prefix.inputs.remove(emission_index);
            let signable = tx.prefix_hash();
            emission_vin_verify_backing(&vin, &root, depth, signable)
                .expect("backing leg verifies against the REAL tree root and depth");
        }
    }
}
