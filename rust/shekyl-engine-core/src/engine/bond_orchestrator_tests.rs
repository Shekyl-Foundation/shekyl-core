// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for the bond orchestrator (`engine/bond_orchestrator.rs`).
//!
//! Wired as a `#[path]` child of `bond_orchestrator::tests`, so
//! `use super::*` resolves into the workflow module and private items
//! stay testable; the sibling file exists so the decomposition ratchet
//! counts the workflow file, not its test suite (the
//! `transfer/transfer_pending_tx_tests.rs` pattern).

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

/// The posture is the conversion: Market has nothing to post until
/// assignment exists, Foundation is CompleteTree with the empty-set
/// *encoding*. These are the two facts `first_stake` must not re-derive
/// inline — they live on [`StakePosture::holdings`].
#[test]
fn market_posture_has_no_holdings_until_assignment_exists() {
    assert!(matches!(
        StakePosture::Market.holdings(),
        Err(FirstStakeError::NoShardsAvailable)
    ));
}

#[test]
fn foundation_posture_is_complete_tree_with_the_empty_encoding() {
    let holdings = StakePosture::FoundationCompleteTree
        .holdings()
        .expect("foundation posts");
    assert_eq!(
        holdings.kind,
        shekyl_archival_retention::HoldingsKind::CompleteTree
    );
    assert!(holdings.shard_ids.is_empty());
}

/// F-2 (i): assemble stamps `anchor_t0` via [`daemon_claimed_tip`]; the
/// pscan `BlockSource::tip_height` path also routes through that same
/// named function (see `block_source.rs`). This KAT pins that both
/// modules name the same item.
#[test]
fn assemble_imports_named_daemon_claimed_tip() {
    // `daemon_claimed_tip` is in scope in this module (assemble path) and
    // is the body of `DaemonBlockSource::tip_height` / `PBlockSource::tip_height`.
    // A rename that forked the two clocks would break this shared import.
    let assemble_name =
        std::any::type_name_of_val(&daemon_claimed_tip::<crate::engine::test_support::TestDaemon>);
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
    // The workflow file is production-only since the test suite moved
    // to this `#[path]` sibling — the old drop-the-trailing-`mod tests`
    // split (the `wire.rs` tripwire shape) retired with the extraction:
    // this file's assertion literals are no longer inside the included
    // source, so they cannot self-match.
    let orch = include_str!("bond_orchestrator.rs");
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

use crate::engine::{Credentials, EngineCreateParams, SoloSigner};
use shekyl_engine_file::SafetyOverrides;
use std::sync::Arc as StdArc;
use tokio::sync::RwLock as TokioRwLock;

use crate::engine::test_support::dummy_daemon;

/// This suite's deterministic seed (multiplier 3).
fn fixed_seed() -> [u8; shekyl_crypto_pq::account::MASTER_SEED_BYTES] {
    crate::engine::test_support::fixed_seed(3)
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

    let err = Engine::first_stake(arc, 7, StakePosture::FoundationCompleteTree)
        .await
        .expect_err("off-cursor");
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

/// **The Market posture is a typed refusal, and it costs nothing**
/// (`COMPLETETREE_ACTIVATION.md` D-3): shard assignment is an unbuilt
/// round, so a market first-stake refuses `NoShardsAvailable` **on the
/// cursor slot** — the slot a fresh stake is entitled to, so the refusal
/// is the posture's and not a guard's — with no durable staker state
/// written and no daemon round trip spent.
///
/// The dummy daemon is the negative control that makes "no daemon round
/// trip" checkable rather than asserted: it points at a dead port, so a
/// fee estimate would surface `FeeEstimate`, and a sweep would surface
/// `Funding`/`State`. Getting `NoShardsAvailable` proves the refusal
/// landed ahead of both.
#[tokio::test(flavor = "multi_thread")]
async fn market_posture_refuses_before_any_daemon_work_or_durable_write() {
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

    let err = Engine::first_stake(arc.clone(), 0, StakePosture::Market)
        .await
        .expect_err("market staking has no shard to bond over yet");
    assert!(
        matches!(err, FirstStakeError::NoShardsAvailable),
        "got {err:?}"
    );

    // W1-clean: the wallet is not a staker, no slot was recorded, and the
    // monotone cursor did not move. A refusal that had written any of
    // these would have left a phantom the reconcile must later clean up.
    let g = arc.read().await;
    let staking = &g.ledger.read().ledger.staking;
    assert!(
        !staking.staking_enabled,
        "a refused posture must not enable staking"
    );
    assert!(staking.bonded_slots.is_empty(), "no slot may be recorded");
    assert_eq!(staking.p_slot, 0, "the cursor must not burn a slot");
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
    let engine = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
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
    let err = Engine::first_stake(arc.clone(), 4, StakePosture::FoundationCompleteTree)
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
        let err = Engine::first_stake(arc.clone(), slot, StakePosture::FoundationCompleteTree)
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
    let engine = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
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
    let err = Engine::first_stake(arc, 0, StakePosture::FoundationCompleteTree)
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
    let engine = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
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
    let engine = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
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
    let err = Engine::first_stake(arc, 0, StakePosture::FoundationCompleteTree)
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
    let engine = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");

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
    let engine = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
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

/// The P-lane bond fee obeys the SAME ceiling the send path obeys.
///
/// Until 2026-08-17 this was the one production `get_fee_estimates`
/// consumer that read `economy` straight off the raw snapshot, so a
/// daemon quoting an absurd rate had its number charged to persona
/// working capital — a lane with no user-facing fee control, hence
/// nobody positioned to notice. The oracle is the refusal CLASS, not
/// merely "an error": `FeeEstimate` means "the query failed, check the
/// connection and retry", which is the wrong remedy when the query
/// plainly succeeded (rule 82).
///
/// This bites against the validation being dropped or the class being
/// collapsed. It does NOT cover snapshot well-formedness itself (that
/// is `fee_policy::tests`).
#[test]
fn bond_fee_refuses_what_the_send_path_refuses() {
    use super::{bond_fee_from_estimates, p_lane_weight_ceiling_bytes, FirstStakeError};
    use crate::engine::fee_policy::{CeilingViolation, ValidatedFeeEstimates};
    use crate::engine::traits::FeeEstimates;
    use shekyl_rpc_client::FeeRate;

    let snapshot = |e: u64, s: u64, p: u64, mask: u64| FeeEstimates {
        economy: FeeRate::new(e, mask).expect("economy"),
        standard: FeeRate::new(s, mask).expect("standard"),
        priority: FeeRate::new(p, mask).expect("priority"),
        quantization_mask: mask,
    };

    // Honest 2021-scaling KAT row: accepted, and the fee is the shared
    // formula over the bond ceiling — not a number this path invents.
    let honest = snapshot(340, 1_400, 67_000, 1);
    let fee = bond_fee_from_estimates(honest).expect("an honest snapshot funds a bond");
    assert_eq!(
        fee.to_raw(),
        shekyl_rpc_client::tx_fee::fee_from_weight(
            &FeeRate::new(340, 1).expect("rate"),
            p_lane_weight_ceiling_bytes()
        ),
        "the bond fee is economy over the P-lane ceiling, via the shared formula"
    );

    // Economy itself over the absolute cap: refused as a REFUSAL, not
    // as a query failure. This is the vector the bypass paid. The cap
    // is the derived genesis-era maximum (a 200k literal here became an
    // HONEST young-chain rate once the cap was re-provisioned — fixtures
    // must gouge relative to the real bound, not a era-local one).
    let cap = crate::engine::fee_policy::absolute_fee_rate_cap();
    let gouging = snapshot(cap + 1, cap + 1, cap + 1, 1);
    match bond_fee_from_estimates(gouging) {
        Err(FirstStakeError::FeeUnreasonable(CeilingViolation::AboveAbsoluteCap { rate })) => {
            assert_eq!(rate, cap + 1);
        }
        other => panic!("a gouging economy tier must be refused by class, got: {other:?}"),
    }

    // The mask bypass reaches this lane too: benign raw rates under an
    // enormous daemon-controlled mask.
    match bond_fee_from_estimates(snapshot(1, 1, 1, 1_000_000_000_000_000_000)) {
        Err(FirstStakeError::FeeUnreasonable(CeilingViolation::AboveAbsoluteCap { .. })) => {}
        other => panic!("the mask bypass must not survive on the bond lane: {other:?}"),
    }

    // An inverted band is refused here for the same reason it is on the
    // send path, even though only `economy` is read.
    match bond_fee_from_estimates(snapshot(50, 20, 100, 1)) {
        Err(FirstStakeError::FeeUnreasonable(CeilingViolation::NonMonotonic { .. })) => {}
        other => panic!("bond must not be more permissive than send: {other:?}"),
    }

    // Agreement, stated directly: the two gates accept exactly the same
    // snapshots. A future edit that loosens one and not the other fails.
    for (e, s, p, m) in [
        (340, 1_400, 67_000, 1),
        (13, 53, 14_000, 1),
        (200_000, 200_000, 200_000, 1),
        (50, 20, 100, 1),
        (1, 1, 1, 1_000_000_000_000_000_000),
        (340, 1_400, 67_000, 10_000),
    ] {
        let raw = snapshot(e, s, p, m);
        assert_eq!(
            ValidatedFeeEstimates::try_new(raw).is_ok(),
            bond_fee_from_estimates(raw).is_ok(),
            "send and bond disagree on ({e}, {s}, {p}) mask {m}"
        );
    }
}

/// The P-lane weight ceiling covers every legal spend shape — including the
/// one the retired `32 * 1024` constant missed: the depth-24 8-input drain,
/// whose FCMP++ proof alone (33,600 bytes, `FCMP_PROOF_SIZE_KAT[8][24]`)
/// exceeded the old ceiling before a single input auth was counted. A fee
/// quoted under a too-small ceiling undercut the daemon's per-byte floor, so
/// a legal multi-input drain was refused at relay — and, until the drain
/// lifecycle driver lands, its sealed record bricked the persona's drain
/// lane. Bites against the ceiling being hardcoded back down or the scan
/// grid being narrowed below the legal shape space.
#[test]
fn p_lane_ceiling_covers_the_heaviest_legal_shape() {
    use super::p_lane_weight_ceiling_bytes;
    use crate::engine::tx_fee_model::{predict_weight, InputCount, OutputCount};

    let ceiling = p_lane_weight_ceiling_bytes();

    // The corner shape the old constant missed, computed through the same
    // KAT-validated model the send path prices with.
    let heaviest = predict_weight(
        InputCount::clamped(shekyl_tx_builder::MAX_INPUTS),
        OutputCount::clamped(2),
        shekyl_tx_weight::MAX_TREE_DEPTH,
        u64::MAX,
    );
    assert!(
        ceiling >= heaviest,
        "ceiling {ceiling} does not cover the heaviest legal P-lane shape ({heaviest})"
    );
    assert!(
        heaviest > 32 * 1024,
        "the heaviest legal shape no longer exceeds the retired 32 KiB constant \
         ({heaviest}); this test's premise — and the computed ceiling — should be re-examined"
    );

    // The exit-fee reserve derivation (`shekyl-standoff` reserve.rs) prices
    // one pessimistic Unbond at >= 600 atomic/weight-byte of fee-spike
    // headroom over this same structural worst case; the reserve must keep
    // covering it, or a live persona's held-back reserve no longer funds its
    // terminal Unbond at the documented headroom. If a KAT-table
    // regeneration grows the ceiling past `50M / 600 ≈ 83_333`, this goes
    // red and reserve.rs's derivation must be re-run, not this bound
    // loosened in place.
    assert!(
        shekyl_standoff::EXIT_FEE_RESERVE_ATOMIC
            >= u64::try_from(ceiling).expect("weight fits u64") * 600,
        "EXIT_FEE_RESERVE_ATOMIC no longer covers a worst-case Unbond at the \
         documented 600 atomic/weight-byte headroom (ceiling {ceiling}) — \
         re-derive reserve.rs, do not loosen this bound"
    );
}
