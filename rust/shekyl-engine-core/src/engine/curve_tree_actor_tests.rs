// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CT-5a commit-1 contract tests for [`CurveTreeActor`] / [`CurveTreeHandle`].
//! These pin the actor scaffold and message protocol; the behavioral
//! ingest / rollback KATs (root-matches-the-CT-2-oracle, reorg, respawn)
//! land in later commits where the real `ScannableBlock → BlockLeaves`
//! decode and fixtures exist.

use super::*;

use tempfile::TempDir;

/// Open a fresh, empty [`CurveTreeClient`] over a tempdir-backed store.
fn fresh_client() -> (TempDir, CurveTreeClient) {
    let dir = TempDir::new().expect("tempdir");
    let client = CurveTreeClient::open(dir.path().join("curve_tree.redb"))
        .expect("open fresh curve-tree client");
    (dir, client)
}

/// **Lock-ordering clause 1 (§3.1 / E2), enforced mechanically.** The
/// actor's only construction input is the [`CurveTreeClient`]: `on_start`
/// receives exactly [`Actor::Args`] plus a [`WeakActorRef`] (no engine
/// state), so pinning `Args = CurveTreeClient` makes "reach back for engine
/// state" a compile error — a field that needed engine state would have to
/// enter through `Args` and break this bound. A future "let the actor read
/// engine config for X" change fails to compile here, on this rule, rather
/// than passing tests until a deadlock interleaving in production.
#[test]
fn actor_constructed_from_only_the_client() {
    fn assert_args_is_client<A: Actor<Args = CurveTreeClient>>() {}
    assert_args_is_client::<CurveTreeActor>();
}

/// kameo requires the actor and its messages to be `Send`. (The replies are
/// `Result<(), ClientError>`; `ClientError: Send` is exercised by the
/// `ask` round-trips in later commits.)
#[test]
fn actor_and_messages_are_send() {
    fn assert_send<T: Send>() {}
    assert_send::<CurveTreeActor>();
    assert_send::<IngestBlock>();
    assert_send::<RollbackToFork>();
    assert_send::<IngestedTipHeight>();
    assert_send::<VerifyRoot>();
    assert_send::<RootAndDepthAt>();
    assert_send::<AssembleTx>();
    assert_send::<OfferOwned>();
    assert_send::<PinServeSet>();
    assert_send::<PinCompleteTreePrefix>();
    assert_send::<OwnedTxLeaves>();
}

/// Require-ambient spawn contract: with no ambient Tokio runtime,
/// [`CurveTreeHandle::spawn`] panics with the contract message before any
/// actor task is scheduled. A plain `#[test]` precisely because it must run
/// with no ambient runtime.
#[test]
#[should_panic(expected = "requires an ambient Tokio runtime")]
fn spawn_without_ambient_runtime_panics() {
    let (_dir, client) = fresh_client();
    let _handle = CurveTreeHandle::spawn(client);
}

/// The actor spawns over a fresh client and is alive on an ambient runtime.
#[tokio::test]
async fn spawns_and_is_alive() {
    let (_dir, client) = fresh_client();
    let handle = CurveTreeHandle::spawn(client);
    assert!(handle.actor_ref().is_alive(), "actor is alive after spawn");
}

/// **R1-Q4 respawn happy path + shared-cell propagation (O3, §3.3).** The
/// load-bearing KAT for commit 5: a fail-stopped actor is healed by
/// [`CurveTreeHandle::respawn`], which (a) resumes a writer over the
/// same open store (D2 resume-from-store, no genesis replay, no file
/// reopen), and (b) swaps the fresh actor into the **shared cell** so a
/// clone taken *before* the respawn — modelling the
/// [`LocalPendingTx`](super::super::local_pending_tx) spend-gate clone —
/// observes the new actor too. Without the shared cell the clone would
/// keep pointing at the dead actor and fail forever (the partial-heal
/// hazard this handle shape forecloses).
///
/// Blocks are empty-leaf (no coinbase) — accepted by `ingest_block`, which
/// advances the height cursor regardless of leaf count; the same shape the
/// merge-path reorg KAT relies on. Behavioral leaf/root correctness is the
/// CT-2-oracle KAT (commit 6) / Tier-B completeness (CT-5c), not here.
#[tokio::test]
async fn respawn_resumes_from_store_and_propagates_to_clones() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("curve_tree.redb");
    let client = CurveTreeClient::open(&path).expect("open fresh client");
    let handle = CurveTreeHandle::spawn(client);

    // Ingest empty blocks 0..=2 → persisted cursor at height 2.
    for h in 0..=2 {
        handle
            .ingest(BlockHeight::from_raw(h), Arc::new(Vec::new()))
            .await
            .expect("ingest empty block");
    }
    assert_eq!(
        handle.ingested_tip_height().await.expect("cursor read"),
        Some(BlockHeight::from_raw(2)),
        "three consecutive ingests leave the cursor at height 2"
    );

    // A clone taken BEFORE the respawn — the spend-gate-clone analogue.
    let clone = handle.clone();

    // Simulate the fail-stop: both the original and the pre-respawn clone
    // now collapse to Unavailable (they share the one — now dead — actor).
    handle.kill_and_wait_for_test().await;
    assert!(
        matches!(
            handle.ingested_tip_height().await,
            Err(CurveTreeHandleError::Unavailable)
        ),
        "a fail-stopped actor makes the original handle Unavailable"
    );
    assert!(
        matches!(
            clone.ingested_tip_height().await,
            Err(CurveTreeHandleError::Unavailable)
        ),
        "the pre-respawn clone shares the dead actor and is Unavailable too"
    );

    // Respawn via the original handle: same store Arc, fresh writer.
    handle
        .respawn()
        .await
        .expect("respawn resumes over the held store");

    // (a) resume-from-store: the persisted cursor survived the fail-stop.
    assert_eq!(
        handle.ingested_tip_height().await.expect("cursor read"),
        Some(BlockHeight::from_raw(2)),
        "respawn resumes from the persisted store cursor (no genesis replay)"
    );
    // (b) propagation: the clone taken before the respawn observes the
    // fresh actor through the shared cell — whole heal, not partial.
    assert_eq!(
        clone.ingested_tip_height().await.expect("cursor read"),
        Some(BlockHeight::from_raw(2)),
        "the pre-respawn clone observes the respawned actor via the shared cell"
    );
    // And ingest resumes at cursor+1 through the clone.
    clone
        .ingest(BlockHeight::from_raw(3), Arc::new(Vec::new()))
        .await
        .expect("ingest resumes at cursor+1 after respawn");
    assert_eq!(
        handle.ingested_tip_height().await.expect("cursor read"),
        Some(BlockHeight::from_raw(3)),
        "post-respawn ingest advances the shared cursor seen by every clone"
    );
}

/// Respawn must keep the store a serving host would hold. This bites
/// against a path-reopen (different `Arc`, and `DatabaseAlreadyOpen`
/// once a host is live); it does NOT cover cursor resume or clone
/// propagation (`respawn_resumes_from_store_and_propagates_to_clones`).
#[tokio::test]
async fn respawn_keeps_the_store_a_serving_reader_holds() {
    let (_dir, client) = fresh_client();
    let handle = CurveTreeHandle::spawn(client);

    let before = handle
        .pin_serve_set(Vec::new(), Vec::new())
        .await
        .expect("pin before respawn")
        .reader;

    handle.kill_and_wait_for_test().await;
    handle.respawn().await.expect("respawn");

    let after = handle
        .pin_serve_set(Vec::new(), Vec::new())
        .await
        .expect("pin after respawn")
        .reader;

    assert!(
        before.same_store(&after),
        "respawn must resume over the same open store a serving host holds"
    );
}

/// Cursor-read `ask` round-trip on a fresh client returns `None` — the
/// `BlockHeight::from_raw(0)` resume point for a from-genesis ingest (D2). This pins
/// the transport + reply type + collapse for [`IngestedTipHeight`]; the
/// non-`None` (post-ingest, post-rollback) cursor behavior is proven at the
/// client level (`ingested_tip_height_getter_tracks_cursor`) and exercised
/// end-to-end once the merge-driven ingest fixtures land.
/// `SyncOwned` round-trips through the handle, and a re-offer is held.
#[tokio::test]
async fn sync_owned_registers_through_the_handle_and_a_re_offer_is_held() {
    let (_dir, client) = fresh_client();
    let handle = CurveTreeHandle::spawn(client);
    let pair = (
        shekyl_curve_tree::Gindex::from_raw(7),
        shekyl_curve_tree::OneTimePubkey::from_bytes([0x11u8; 32]),
    );
    let first = handle
        .sync_owned(vec![pair])
        .await
        .expect("sync on a live actor");
    assert_eq!(first.before_drain, 1, "an unseen gindex is a future leaf");
    assert_eq!(first.reconciliation, None, "nothing owed on an empty tree");
    let again = handle
        .sync_owned(vec![pair])
        .await
        .expect("sync on a live actor");
    assert_eq!(again.already_held, 1, "the same pair is held and served");
}

/// `AssembleTx` registers its inputs before assembling, so an input the
/// wallet never registered is not refused as unregistered — it is refused
/// for the real reason, which on an empty tree is that it has not drained.
///
/// The discriminator: the registry holds the pair (the handler's sync put
/// it there) and no position is resolved, which is `OutputNotDrained`;
/// `OutputNotRegistered` would mean the handler assembled without
/// syncing first.
#[tokio::test]
async fn assemble_tx_registers_its_inputs_before_assembling() {
    let (_dir, client) = fresh_client();
    let handle = CurveTreeHandle::spawn(client);
    let input = AssembleInput {
        gindex: shekyl_curve_tree::Gindex::from_raw(3),
        output_key: shekyl_curve_tree::OneTimePubkey::from_bytes([0x22u8; 32]),
        commitment: shekyl_curve_tree::CommitmentBytes::from_bytes([0x33u8; 32]),
    };
    // Height 0 on an empty client: `root_and_depth_at` needs an ingested
    // tip, so ingest one empty block first.
    handle
        .ingest(shekyl_curve_tree::BlockHeight::ZERO, Arc::new(Vec::new()))
        .await
        .expect("an empty genesis ingests");
    let reference = ReferenceBlock {
        height: shekyl_curve_tree::BlockHeight::ZERO,
        curve_tree_root: shekyl_curve_tree::CurveTreeRoot::from_bytes(
            shekyl_fcmp::tree::selene_hash_init(),
        ),
        block_hash: shekyl_curve_tree::BlockHash::NULL,
    };
    let err = handle
        .assemble_tx(reference, vec![input])
        .await
        .expect_err("an undrained input cannot have a path");
    assert!(
        matches!(
            err,
            CurveTreeHandleError::Client(ClientError::OutputNotDrained { gindex, .. })
                if gindex == input.gindex
        ),
        "expected OutputNotDrained after the handler's own sync; got {err:?}"
    );
    // And the sync did register it: a re-offer is held.
    let again = handle
        .sync_owned(vec![(input.gindex, input.output_key)])
        .await
        .expect("sync on a live actor");
    assert_eq!(again.already_held, 1, "the handler registered the pair");
}

#[tokio::test]
async fn cursor_read_on_fresh_client_is_none() {
    let (_dir, client) = fresh_client();
    let handle = CurveTreeHandle::spawn(client);
    let tip = handle
        .ingested_tip_height()
        .await
        .expect("cursor read on a live actor");
    assert_eq!(tip, None, "a fresh client has no ingested tip");
}

/// A reorg rebinds a gindex, and a caller whose view is still the old chain
/// is told so, refused cleanly, and served again once it has rescanned.
///
/// This is the case `CT6_PROVING_STATE.md` §11.9 hands the registrant. The
/// tree's ingest is acknowledged before the ledger's merge commits, so the
/// tree can be on the new chain while the ledger — and a spend selected
/// from it — still names the old one. What has to hold, in order:
///
/// 1. the old pair is reported stale, alone: the pair below the fork, in
///    the same batch, is still held and served;
/// 2. a spend of the old pair is refused as unregistered, which
///    `transfer::support` classifies as reselect — not assembled over
///    another output's leaf, and not a store fault;
/// 3. the rescan's pair registers, and its reconciliation rebuilds exactly
///    the one leaf chunk the reorg replaced. Had the old chain's capture
///    row for that chunk survived the rollback it would be found present
///    and nothing would be rebuilt, so the equality is the witness that
///    nothing was left behind;
/// 4. both outputs then assemble against the new chain's root.
#[tokio::test]
async fn a_view_behind_a_reorg_is_reported_stale_and_recovers_on_the_rescan() {
    use crate::engine::test_support::{seeded_commitment, seeded_output_key, seeded_tx_leaves};

    /// The chain the wallet scanned, and the one that replaced it.
    const BEFORE: u8 = 1;
    const AFTER: u8 = 2;
    /// One full leaf chunk per carrying block.
    const PER_BLOCK: u64 = 38;
    /// Far enough past block 1 that its outputs have drained.
    const TIP: u64 = 14;

    /// Ingest `from..=TIP`. Block 0 is common to both chains; block 1 is
    /// `fork`'s; the rest are empty.
    async fn ingest_chain(handle: &CurveTreeHandle, from: u64, fork: u8) {
        for height in from..=TIP {
            let txs = match height {
                0 => seeded_tx_leaves(BEFORE, 0, PER_BLOCK),
                1 => seeded_tx_leaves(fork, 1, PER_BLOCK),
                _ => seeded_tx_leaves(fork, height, 0),
            };
            handle
                .ingest(BlockHeight::from_raw(height), txs)
                .await
                .expect("a seeded block ingests");
        }
    }

    /// The input for output `index` of block `height` as `chain` mined it.
    fn input(chain: u8, height: u64, index: u64) -> AssembleInput {
        AssembleInput {
            gindex: shekyl_curve_tree::Gindex::from_raw(height * PER_BLOCK + index),
            output_key: shekyl_curve_tree::OneTimePubkey::from_bytes(seeded_output_key(
                chain, height, index,
            )),
            commitment: shekyl_curve_tree::CommitmentBytes::from_bytes(seeded_commitment(
                chain, height, index,
            )),
        }
    }
    fn pair(input: &AssembleInput) -> crate::engine::ownership::OwnedOutput {
        (input.gindex, input.output_key)
    }
    async fn reference_at_tip(handle: &CurveTreeHandle) -> ReferenceBlock {
        let height = BlockHeight::from_raw(TIP);
        let (root, _) = handle
            .reference_root_and_depth(height)
            .await
            .expect("the tree answers at its tip");
        ReferenceBlock {
            height,
            curve_tree_root: CurveTreeRoot::from_bytes(root),
            block_hash: shekyl_curve_tree::BlockHash::NULL,
        }
    }

    let (_dir, client) = fresh_client();
    let handle = CurveTreeHandle::spawn(client);

    // Below the fork, and the same output on both chains.
    let below = input(BEFORE, 0, 5);
    // One gindex, two outputs.
    let old = input(BEFORE, 1, 2);
    let new = input(AFTER, 1, 2);
    assert_eq!(old.gindex, new.gindex, "the reorg rebinds this gindex");
    assert_ne!(old.output_key, new.output_key);

    ingest_chain(&handle, 0, BEFORE).await;
    let scanned = handle
        .sync_owned(vec![pair(&below), pair(&old)])
        .await
        .expect("sync on a live actor");
    assert_eq!(scanned.after_drain, 2);
    assert_eq!(
        scanned
            .reconciliation
            .expect("both are owed")
            .leaves_rebuilt,
        2 * PER_BLOCK,
        "each output's own leaf chunk"
    );

    // The reorg, as the refresh's ingest applies it: back to the last
    // common block, then the new chain.
    handle
        .rollback_to_fork(BlockHeight::ZERO)
        .await
        .expect("a rollback inside the window");
    ingest_chain(&handle, 1, AFTER).await;

    // 1. The ledger has not merged the new chain yet. It re-offers what it
    //    holds.
    let lagging = handle
        .sync_owned(vec![pair(&below), pair(&old)])
        .await
        .expect("a stale pair does not fail the batch");
    assert_eq!(lagging.stale, vec![old.gindex], "the rebound gindex, alone");
    assert_eq!(
        (
            lagging.already_held,
            lagging.before_drain,
            lagging.after_drain
        ),
        (1, 0, 0),
        "the pair below the fork is untouched by its neighbour's verdict"
    );
    assert_eq!(lagging.reconciliation, None);

    // 2. A spend selected from that ledger.
    let reference = reference_at_tip(&handle).await;
    let err = handle
        .assemble_tx(reference, vec![old])
        .await
        .expect_err("the tree holds another output at that gindex");
    assert!(
        matches!(
            err,
            CurveTreeHandleError::Client(ClientError::OutputNotRegistered { gindex, output_key })
                if gindex == old.gindex && output_key == old.output_key
        ),
        "expected OutputNotRegistered for the stale pair; got {err:?}"
    );

    // 3. The rescan reaches the new chain and offers what is there now.
    let rescanned = handle
        .sync_owned(vec![pair(&below), pair(&new)])
        .await
        .expect("sync on a live actor");
    assert!(rescanned.stale.is_empty());
    assert_eq!((rescanned.already_held, rescanned.after_drain), (1, 1));
    let report = rescanned
        .reconciliation
        .expect("the new output drained before it was offered");
    assert_eq!(report.positions_resolved, 1);
    assert_eq!(
        report.leaves_rebuilt, PER_BLOCK,
        "the replaced leaf chunk is rebuilt from the new chain; no row of the old one answered for it"
    );

    // 4. And both assemble against the new chain's root.
    let paths = handle
        .assemble_tx(reference, vec![below, new])
        .await
        .expect("held outputs assemble from their captures");
    assert_eq!(paths.len(), 2);

    // The old pair stays stale however often it is offered.
    let again = handle
        .sync_owned(vec![pair(&old)])
        .await
        .expect("sync on a live actor");
    assert_eq!(again.stale, vec![old.gindex]);
}
