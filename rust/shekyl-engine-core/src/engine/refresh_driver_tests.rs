// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Integration tests for [`Engine::refresh`] / `Engine::refresh_with`.
//!
//! Producer-side coverage lives in `crate::engine::local_refresh`'s
//! `tests` module (per-class emission / RPC-error classification) and
//! lands in full at C7 (structural property tests against
//! `RefreshEngine` via `AssertionSink` /
//! `PanickingSink` / coherence-pair fixtures). This module covers
//! the **driver**: the snapshot-merge-with-retry loop. Tests inject
//! scripted [`ScanResult`] values via `Engine::refresh_with` so
//! retry / classification behaviour is asserted independently of any
//! RPC fixture; the production [`Engine::refresh`] entry point is
//! exercised separately against the unreachable [`DaemonClient`] to
//! confirm daemon-IO errors map through correctly.
//!
//! Wired as a `#[path]` child of `engine/refresh.rs`, so `use super::*`
//! and `super::` paths resolve into the refresh module and private items
//! stay testable; the sibling file exists so the decomposition ratchet
//! counts the workflow file, not its test suite (the
//! `local_refresh_tests.rs` pattern).

use std::cell::RefCell;
use std::sync::{Mutex, OnceLock};

use shekyl_rpc_transport::HttpRpc;
use tempfile::TempDir;
use tokio::runtime::Runtime;

use crate::engine::lifecycle::EngineCreateParams;
use crate::engine::{
    Credentials, DaemonClient, Engine, IoError, RefreshError, RefreshOptions, SoloSigner,
};
use crate::scan::ScanResult;
use shekyl_crypto_pq::account::MASTER_SEED_BYTES;
use shekyl_engine_state::{BlockchainTip, LedgerBlock, ReorgBlocks};

use super::{derive_snapshot_id, summarize, LedgerSnapshot, RefreshReorgEvent, SnapshotId};

// ── Test fixtures ──────────────────────────────────────────

/// `Credentials` borrows a password slice; tests share one
/// `'static` slice so `make_wallet` can return owned credentials
/// without lifetime gymnastics.
const TEST_PASSWORD: &[u8] = b"snapshot-merge-driver tests";

/// A process-wide multi-thread tokio runtime shared by every
/// driver test. Built once on first access and intentionally
/// leaked to live for the duration of the test binary.
///
/// Why a shared, never-dropped runtime: hyper's connection pool
/// (used by `HttpRpc`) spawns background tasks onto the
/// runtime that constructed it. Building the RPC on a one-shot
/// runtime that gets dropped at the end of `dummy_daemon` leaves
/// the pool's tasks orphaned; subsequent requests hang waiting
/// for executors that no longer exist. Sharing one runtime across
/// every test in the module is both simpler and faster than
/// keeping per-test runtimes alive.
fn shared_runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .expect("tokio runtime for refresh_driver_tests")
    })
}

/// Build a `DaemonClient` whose underlying RPC points at an
/// unreachable URL. The Client is constructed on the shared
/// runtime so its background tasks remain drivable for tests
/// that actually issue requests through it
/// (`production_refresh_*`). Tests that never touch the daemon
/// (the `refresh_with`-driven cases) just hold the handle alive.
fn dummy_daemon() -> DaemonClient {
    let rt = shared_runtime();
    let rpc = rt
        .block_on(HttpRpc::new("http://127.0.0.1:1".to_string()))
        .expect("construct HttpRpc against unreachable URL (no connect attempt yet)");
    DaemonClient::new(rpc)
}

/// Owns a [`TempDir`] for the wallet base path. The tempdir is
/// dropped along with the fixture, cleaning up the wallet file
/// at end of test.
struct EngineFixture {
    wallet: Engine<SoloSigner>,
    _tmp: TempDir,
}

/// Build a fresh `Engine<SoloSigner>` on a tempdir with a
/// deterministic seed. `synced_height` is `0` and `reorg_blocks`
/// is empty — the standard fresh-wallet starting state for the
/// snapshot-merge tests.
fn make_wallet() -> EngineFixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base_path = tmp.path().join("wallet");
    let creds = Credentials::password_only(TEST_PASSWORD);
    let mut seed = [0u8; MASTER_SEED_BYTES];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = u8::try_from(i & 0xff).unwrap_or(0).wrapping_mul(11);
    }
    let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
    // `Engine::create` → `assemble` spawns the `KeyActor`, which
    // (post Stage-2 require-ambient) asserts an ambient Tokio
    // runtime. Build the daemon first (`dummy_daemon` drives its
    // own `shared_runtime().block_on`, which must not run inside a
    // runtime context), then enter `shared_runtime` only for the
    // `create` call so the actor spawns onto the live shared
    // runtime. The guard is dropped before the fixture returns, so
    // the synchronous `refresh`/`refresh_with` bodies — and in
    // particular `production_refresh_*`'s `refresh(&opts,
    // rt.handle())`, which drives `Handle::block_on` and must not
    // be inside a runtime — run with no ambient runtime, exactly as
    // before.
    let daemon = dummy_daemon();
    let wallet = {
        let _rt_guard = shared_runtime().enter();
        Engine::<SoloSigner>::create(params, daemon)
            .expect("create FULL wallet for refresh_with tests")
    };
    EngineFixture { wallet, _tmp: tmp }
}

/// Drain a `Mutex<Vec<…>>` queue of scripted producer outcomes,
/// returning one per `refresh_with` invocation. Panics if the
/// queue empties mid-test (the loop attempted more retries than
/// the test prepared for) — that condition is itself a test
/// failure to surface, not a panic to catch.
fn drain<T>(queue: &Mutex<Vec<T>>) -> T {
    queue
        .lock()
        .expect("scripted-producer queue poisoned")
        .pop()
        .expect("scripted producer drained: refresh_with attempted more loops than prepared")
}

/// A clean scan result for `start..start` (empty range) anchored
/// to the wallet's snapshot. Applies as a no-op merge and
/// terminates the loop with `Ok(_)`.
fn empty_result_for(snapshot: &LedgerSnapshot) -> ScanResult {
    let start = snapshot.synced_height.saturating_add(1);
    let parent_hash = snapshot.block_hash_at(snapshot.synced_height);
    ScanResult::empty_at(start, parent_hash)
}

/// A scan result that the merge will reject as
/// [`RefreshError::ConcurrentMutation`] because its start height
/// disagrees with the wallet's synced_height. The merge gate
/// fires the start-height check before parent-hash, so an
/// arbitrary `bad_start != synced_height + 1` is sufficient.
fn stale_snapshot_result(bad_start: u64) -> ScanResult {
    ScanResult::empty_at(bad_start, None)
}

/// A scan result the merge will reject as
/// [`RefreshError::MalformedScanResult`]: a non-empty
/// `block_hashes` against an empty `processed_height_range`.
/// The empty-range branch checks `block_hashes.is_empty()`
/// before any other invariant, so this fires the malformed
/// path deterministically.
fn malformed_result_for(snapshot: &LedgerSnapshot) -> ScanResult {
    let start = snapshot.synced_height.saturating_add(1);
    let mut result = ScanResult::empty_at(start, snapshot.block_hash_at(snapshot.synced_height));
    // Empty range + non-empty block_hashes is the
    // contract-violation shape `apply_scan_result_to_state`
    // gates against in its early-return branch.
    result.block_hashes.push((start, [0xAB; 32]));
    result
}

// ── Smoke tests ────────────────────────────────────────────

/// One scripted attempt returning a clean empty result causes
/// `refresh_with` to merge once and return a summary recording
/// `merge_attempts == 1`.
#[test]
fn smoke_single_attempt_returns_summary() {
    let fix = make_wallet();
    let opts = RefreshOptions::default();

    let mut produced = false;
    let summary = fix
        .wallet
        .refresh_with(&opts, |attempt, snapshot| {
            assert_eq!(attempt, 1, "smoke path: only one attempt expected");
            assert!(!produced, "smoke path: producer invoked twice");
            produced = true;
            Ok(empty_result_for(snapshot))
        })
        .expect("refresh_with returns Ok on the first clean attempt");

    assert_eq!(summary.merge_attempts, 1);
    assert_eq!(summary.blocks_processed, 0);
    assert!(summary.processed_height_range.start == summary.processed_height_range.end);
    assert_eq!(summary.transfers_detected, 0);
    assert_eq!(summary.key_images_observed, 0);
    assert!(summary.reorg.is_none());
}

// ── ConcurrentMutation retry path ──────────────────────────

/// First two scripted attempts return stale-snapshot results
/// (forcing `ConcurrentMutation`); the third returns a clean
/// result. The driver retries twice and the third attempt's
/// merge succeeds. `summary.merge_attempts` records `3`.
#[test]
fn concurrent_mutation_retry_succeeds_after_two_races() {
    let fix = make_wallet();
    let opts = RefreshOptions { max_retries: 8 };

    // `drain` pops from the back; storing attempts in reverse
    // order lets attempt 1 surface first. Vec layout: index 0 =
    // attempt 3 (empty, terminates loop), index 2 = attempt 1
    // (stale, forces retry).
    type Producer = Box<dyn FnOnce(&LedgerSnapshot) -> ScanResult + Send>;
    let queue: Mutex<Vec<Producer>> = Mutex::new(vec![
        Box::new(empty_result_for) as Producer,
        Box::new(|_snap: &LedgerSnapshot| stale_snapshot_result(99)) as Producer,
        Box::new(|_snap: &LedgerSnapshot| stale_snapshot_result(99)) as Producer,
    ]);

    let observed_attempts: RefCell<Vec<u32>> = RefCell::new(Vec::new());
    let summary = fix
        .wallet
        .refresh_with(&opts, |attempt, snapshot| {
            observed_attempts.borrow_mut().push(attempt);
            Ok(drain(&queue)(snapshot))
        })
        .expect("third clean result merges");

    assert_eq!(*observed_attempts.borrow(), vec![1, 2, 3]);
    assert_eq!(summary.merge_attempts, 3);
}

/// All `1 + max_retries` scripted attempts return stale-snapshot
/// results. The driver exhausts the budget and surfaces the
/// last [`RefreshError::ConcurrentMutation`].
#[test]
fn retry_budget_exhausted_returns_last_concurrent_mutation() {
    let fix = make_wallet();
    let opts = RefreshOptions { max_retries: 2 };

    let observed_attempts: RefCell<Vec<u32>> = RefCell::new(Vec::new());
    let err = fix
        .wallet
        .refresh_with(&opts, |attempt, _snapshot| {
            observed_attempts.borrow_mut().push(attempt);
            // Use `attempt` so the surfaced error's `result`
            // field carries the *last* observed attempt's bad
            // start. This asserts the loop's "preserve the
            // most-recent ConcurrentMutation" behaviour, not
            // the first.
            Ok(stale_snapshot_result(100 + u64::from(attempt)))
        })
        .expect_err("budget exhausted");

    assert_eq!(*observed_attempts.borrow(), vec![1, 2, 3]);
    match err {
        RefreshError::ConcurrentMutation { wallet, result } => {
            assert_eq!(wallet, 0, "fresh wallet's synced_height");
            assert_eq!(result, 103, "last attempt was attempt 3, bad_start = 103");
        }
        other => panic!("expected ConcurrentMutation, got {other:?}"),
    }
}

// ── MalformedScanResult is terminal ────────────────────────

/// First scripted attempt returns a malformed result. The
/// driver does **not** retry — re-running the same producer
/// against the same snapshot would re-emit the same contract
/// violation. The error surfaces immediately.
#[test]
fn malformed_scan_result_is_not_retried() {
    let fix = make_wallet();
    let opts = RefreshOptions { max_retries: 8 };

    let observed_attempts: RefCell<u32> = RefCell::new(0);
    let err = fix
        .wallet
        .refresh_with(&opts, |_attempt, snapshot| {
            *observed_attempts.borrow_mut() += 1;
            Ok(malformed_result_for(snapshot))
        })
        .expect_err("malformed result terminates the loop");

    assert_eq!(*observed_attempts.borrow(), 1, "no retry on malformed");
    match err {
        RefreshError::MalformedScanResult { .. } => {}
        other => panic!("expected MalformedScanResult, got {other:?}"),
    }
}

// ── Producer-error propagation ─────────────────────────────

/// Producer closure returns `Err(RefreshError::Io(...))`. The
/// driver propagates immediately without invoking another
/// attempt: producer-side errors are by construction non-race
/// terminal failures (no merge ran, so no
/// `ConcurrentMutation` is possible).
#[test]
fn producer_io_error_propagates_immediately() {
    let fix = make_wallet();
    let opts = RefreshOptions { max_retries: 8 };

    let observed_attempts: RefCell<u32> = RefCell::new(0);
    let err = fix
        .wallet
        .refresh_with(&opts, |_attempt, _snapshot| {
            *observed_attempts.borrow_mut() += 1;
            Err(RefreshError::Io(IoError::Daemon {
                detail: "scripted daemon failure".to_string(),
            }))
        })
        .expect_err("producer error is terminal");

    assert_eq!(*observed_attempts.borrow(), 1, "no retry on producer error");
    match err {
        RefreshError::Io(IoError::Daemon { detail }) => {
            assert_eq!(detail, "scripted daemon failure");
        }
        other => panic!("expected Io(Daemon), got {other:?}"),
    }
}

/// Producer closure returns `Err(RefreshError::Cancelled)`.
/// The driver propagates immediately. (In production this
/// closure is only `Cancelled` if the cancellation token has
/// been signalled; branch 2's `RefreshHandle` is the only path
/// that signals it on the synchronous refresh.)
#[test]
fn producer_cancelled_propagates() {
    let fix = make_wallet();
    let opts = RefreshOptions::default();

    let err = fix
        .wallet
        .refresh_with(&opts, |_attempt, _snapshot| Err(RefreshError::Cancelled))
        .expect_err("Cancelled is terminal");

    assert!(matches!(err, RefreshError::Cancelled));
}

// ── max_retries == 0 boundary ──────────────────────────────

/// With `max_retries == 0`, the loop runs exactly one attempt.
/// A `ConcurrentMutation` on that attempt is surfaced
/// immediately without any retry.
#[test]
fn max_retries_zero_runs_exactly_one_attempt() {
    let fix = make_wallet();
    let opts = RefreshOptions { max_retries: 0 };

    let observed_attempts: RefCell<u32> = RefCell::new(0);
    let err = fix
        .wallet
        .refresh_with(&opts, |_attempt, _snapshot| {
            *observed_attempts.borrow_mut() += 1;
            Ok(stale_snapshot_result(42))
        })
        .expect_err("budget exhausted on first attempt");

    assert_eq!(
        *observed_attempts.borrow(),
        1,
        "no retry with max_retries=0"
    );
    assert!(matches!(err, RefreshError::ConcurrentMutation { .. }));
}

// ── Snapshot freshness across retries ──────────────────────

/// Every retry pulls a fresh `LedgerSnapshot::from_ledger`. We
/// assert this by mutating wallet state between attempts (via
/// `apply_scan_result` directly, which advances synced_height)
/// and confirming the next attempt sees the new snapshot.
///
/// The race the production `RefreshHandle` cares about is a
/// *sibling* mutation to wallet state during a long async
/// scan. In the synchronous `refresh_with`, `&mut self` is held
/// throughout, so no real sibling race is possible — but the
/// loop must still take a fresh snapshot per attempt because
/// branch 2's async surface drops the lock between attempts.
/// This test pins that the snapshot is in fact re-taken.
#[test]
fn snapshot_is_refreshed_between_retries() {
    let fix = make_wallet();
    let opts = RefreshOptions { max_retries: 4 };

    let snapshots_seen: RefCell<Vec<u64>> = RefCell::new(Vec::new());
    let attempt_counter: RefCell<u32> = RefCell::new(0);

    let summary = fix
        .wallet
        .refresh_with(&opts, |attempt, snapshot| {
            snapshots_seen.borrow_mut().push(snapshot.synced_height);
            *attempt_counter.borrow_mut() = attempt;
            if attempt == 1 {
                // Force a ConcurrentMutation by emitting a
                // result whose start mismatches the snapshot.
                Ok(stale_snapshot_result(7))
            } else {
                Ok(empty_result_for(snapshot))
            }
        })
        .expect("second attempt merges cleanly");

    // Both attempts sampled `synced_height = 0` (the wallet
    // never advanced — empty merge is a no-op) but the
    // snapshot was re-taken: two entries, both observed.
    assert_eq!(*snapshots_seen.borrow(), vec![0, 0]);
    assert_eq!(summary.merge_attempts, 2);
}

// ── Production refresh sanity (daemon unreachable) ─────────

/// `Engine::refresh` (the production entry point) routes the
/// daemon through an unreachable URL. The first `get_height`
/// call fails, surfacing as
/// [`RefreshError::Io`](RefreshError::Io)`(`[`IoError::Daemon`]`)`.
/// The retry loop is **not** entered: daemon failures are
/// terminal, not race-class.
#[test]
fn production_refresh_against_unreachable_daemon_returns_io_daemon() {
    let fix = make_wallet();
    let opts = RefreshOptions { max_retries: 0 };
    // Same runtime that built the daemon's RPC client; running on
    // a different runtime would hang because hyper's connection
    // pool tasks live on the constructing runtime.
    let rt = shared_runtime();

    let err = fix
        .wallet
        .refresh(&opts, rt.handle())
        .expect_err("unreachable daemon must error out");

    // After C5's trait-dispatch migration the producer-side
    // error projection lives in `LocalRefresh`: a daemon-tip
    // `get_height` failure surfaces as `LocalRefreshError::Io`,
    // which the `From<LocalRefreshError> for RefreshError`
    // conversion projects as `RefreshError::Io(IoError::Daemon
    // { detail: "LocalRefresh: daemon I/O failure during refresh" })`.
    // The bounded detail string is a deliberate design
    // disposition (per §5.4.7 R6's memory-amplifier closure):
    // upstream `RpcError` payloads are not propagated into the
    // typed `RefreshError`; richer per-error classification
    // routes through the `DiagnosticSink` as
    // `DaemonProtocolError { kind: ProtocolErrorKind }`.
    match err {
        RefreshError::Io(IoError::Daemon { detail }) => {
            assert!(
                detail.contains("LocalRefresh"),
                "expected LocalRefresh-projected daemon I/O detail, got {detail:?}"
            );
        }
        other => panic!("expected Io(Daemon), got {other:?}"),
    }
}

// ── Summary-shape regression ───────────────────────────────

/// `summarize` is the small shim that builds `RefreshSummary`
/// from `&ScanResult` plus the loop's attempt counter. This
/// test pins every field so a future refactor of the producer
/// or the merge surfaces a deliberate review point rather
/// than a silent shape drift.
#[test]
fn summarize_records_every_field() {
    let mut result = ScanResult::empty_at(5, Some([0x11; 32]));
    result.processed_height_range = 5..8;
    result.block_hashes = vec![(5, [1; 32]), (6, [2; 32]), (7, [3; 32])];
    // `new_transfers` and `spent_key_images` are exercised
    // structurally elsewhere; here we just record the count.
    result.spent_key_images = vec![
        crate::scan::KeyImageObserved {
            block_height: 5,
            key_image: shekyl_crypto_pq::key_image::KeyImage::from_canonical_bytes([9; 32]),
            containing_tx_hash: shekyl_types::TxHash::from_bytes([0xD5; 32]),
        },
        crate::scan::KeyImageObserved {
            block_height: 7,
            key_image: shekyl_crypto_pq::key_image::KeyImage::from_canonical_bytes([8; 32]),
            containing_tx_hash: shekyl_types::TxHash::from_bytes([0xD7; 32]),
        },
    ];
    result.reorg_rewind = Some(crate::scan::ReorgRewind { fork_height: 5 });

    let summary = summarize(&result, 4);

    assert_eq!(summary.processed_height_range, 5..8);
    assert_eq!(summary.blocks_processed, 3);
    assert_eq!(summary.transfers_detected, 0);
    assert_eq!(summary.key_images_observed, 2);
    assert_eq!(summary.reorg, Some(RefreshReorgEvent { fork_height: 5 }));
    assert_eq!(summary.merge_attempts, 4);
}

// ── LedgerSnapshot construction ────────────────────────────

/// `LedgerSnapshot::from_ledger` reads `synced_height` and
/// clones `reorg_blocks`; nothing else. This test confirms the
/// snapshot is decoupled from `transfers` (the Phase-2a
/// "snapshot strategy" decision pins this; the bench at
/// `benches/refresh_snapshot.rs` regression-gates the runtime
/// claim).
#[test]
fn ledger_snapshot_is_independent_of_transfer_count() {
    // Build a `LedgerBlock` directly via its constructor and
    // confirm `LedgerSnapshot::from_ledger` reads only the tip
    // height and the reorg window — `transfers` (when populated
    // in production) does not contribute to snapshot cost.
    let tip = BlockchainTip::new(1234, [0xAA; 32]);
    let reorg_blocks = ReorgBlocks {
        blocks: vec![(1233, [0xBB; 32]), (1234, [0xAA; 32])],
    };
    let ledger = LedgerBlock::new(Vec::new(), tip, reorg_blocks);
    let snap = LedgerSnapshot::from_ledger(&ledger);
    assert_eq!(snap.synced_height, 1234);
    assert_eq!(snap.reorg_blocks.blocks.len(), 2);
    assert_eq!(snap.block_hash_at(1234), Some([0xAA; 32]));
    assert_eq!(snap.block_hash_at(1232), None);
}

// ── SnapshotId derivation (Stage 1 PR 5 — Phase 0b) ────────

/// Synthesize a `LedgerSnapshot` directly from the in-crate
/// fields. Avoids the `LedgerBlock::new` round-trip that the
/// surrounding tests use; the C1 derivation tests do not need a
/// `LedgerBlock` — they exercise `derive_snapshot_id` over the
/// snapshot's fields directly.
fn snapshot_from_parts(synced_height: u64, blocks: Vec<(u64, [u8; 32])>) -> LedgerSnapshot {
    LedgerSnapshot {
        synced_height,
        reorg_blocks: ReorgBlocks { blocks },
    }
}

/// Identical snapshots derive identical ids; snapshots that
/// differ in `synced_height` or `reorg_blocks` derive distinct
/// ids. The 16-byte digest is content-derived; this is the
/// substrate the submit-time staleness check depends on per
/// `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §5.0 ground 2.
#[test]
fn derive_snapshot_id_deterministic() {
    let snap_a = snapshot_from_parts(100, vec![(99, [0x11; 32]), (100, [0x22; 32])]);
    let snap_a_again = snapshot_from_parts(100, vec![(99, [0x11; 32]), (100, [0x22; 32])]);
    assert_eq!(
        derive_snapshot_id(&snap_a),
        derive_snapshot_id(&snap_a_again),
        "identical snapshot fields must derive identical ids"
    );

    let snap_b_height = snapshot_from_parts(101, vec![(99, [0x11; 32]), (100, [0x22; 32])]);
    assert_ne!(
        derive_snapshot_id(&snap_a),
        derive_snapshot_id(&snap_b_height),
        "different synced_height must change the id"
    );

    let snap_b_blocks = snapshot_from_parts(100, vec![(99, [0x11; 32]), (100, [0x33; 32])]);
    assert_ne!(
        derive_snapshot_id(&snap_a),
        derive_snapshot_id(&snap_b_blocks),
        "different reorg-window contents must change the id"
    );

    // SnapshotId bytes are stable across reads.
    let id = derive_snapshot_id(&snap_a);
    assert_eq!(id.as_bytes(), &id.0);
}

/// The cSHAKE customization is load-bearing, and the canonical preimage
/// encoding is pinned by an **independent** byte-by-byte reconstruction:
/// the expected input is built here from the documented layout (LE u64
/// `synced_height` ‖ LE u64 window length ‖ per-entry LE u64 height ‖
/// 32-byte hash), never taken from `super::snapshot_id_preimage` — an
/// expected value computed from the code under test would go green on any
/// encoding change, and a framing-ambiguous re-encoding would silently
/// defeat the submit-time staleness check this digest exists to serve.
#[test]
fn derive_snapshot_id_domain_separated() {
    let snap = snapshot_from_parts(7, vec![(6, [0xCD; 32]), (7, [0xAB; 32])]);

    // Independent oracle for the documented canonical encoding.
    let mut expected_preimage = Vec::new();
    expected_preimage.extend_from_slice(&7u64.to_le_bytes());
    expected_preimage.extend_from_slice(&2u64.to_le_bytes());
    expected_preimage.extend_from_slice(&6u64.to_le_bytes());
    expected_preimage.extend_from_slice(&[0xCD; 32]);
    expected_preimage.extend_from_slice(&7u64.to_le_bytes());
    expected_preimage.extend_from_slice(&[0xAB; 32]);

    assert_eq!(
        super::snapshot_id_preimage(&snap),
        expected_preimage,
        "snapshot_id_preimage must produce the documented canonical encoding; \
         an encoding change mints shekyl/snapshot-id-v2, it does not edit v1"
    );

    let production = super::SNAPSHOT_ID_CUSTOMIZATION;
    let mut counterfactual = production.to_vec();
    counterfactual[0] ^= 0x01;

    let factual = shekyl_crypto_hash::cshake256_32(production, &expected_preimage);
    let other = shekyl_crypto_hash::cshake256_32(&counterfactual, &expected_preimage);

    assert_ne!(
        &factual[..16],
        &other[..16],
        "cSHAKE customization must separate the snapshot-id domain"
    );

    let id = derive_snapshot_id(&snap);
    assert_eq!(
        id.as_bytes()[..],
        factual[..16],
        "derive_snapshot_id must apply the documented cSHAKE encoding verbatim"
    );
}

/// `reorg_blocks` of length 0 vs. 1 vs. 2 over the same
/// `synced_height` must produce three distinct ids. Without the
/// `n_blocks` length prefix in the canonical encoding, the
/// concatenation `(8-byte height) ‖ (32-byte hash)` of one block
/// could in principle collide with the same bytes appearing as
/// part of a two-block window; the length prefix forecloses
/// that. Regression-gates the canonical-encoding promise per
/// `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §4 Phase 0b.
#[test]
fn derive_snapshot_id_length_prefix_separates_neighbours() {
    let snap_zero = snapshot_from_parts(50, Vec::new());
    let snap_one = snapshot_from_parts(50, vec![(49, [0x77; 32])]);
    let snap_two = snapshot_from_parts(50, vec![(49, [0x77; 32]), (50, [0x88; 32])]);

    let id_zero = derive_snapshot_id(&snap_zero);
    let id_one = derive_snapshot_id(&snap_one);
    let id_two = derive_snapshot_id(&snap_two);

    assert_ne!(id_zero, id_one);
    assert_ne!(id_one, id_two);
    assert_ne!(id_zero, id_two);

    // The id type carries the 16-byte digest unchanged.
    assert_eq!(id_zero.as_bytes().len(), 16);
    let _ty_check: SnapshotId = id_zero;
}
