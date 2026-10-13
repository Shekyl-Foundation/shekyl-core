// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for the P-scan start seam (`engine/pscan/start.rs`): the
//! `WalletFile`-backed store round trip, the single-flight slot and the
//! start preconditions.
//!
//! Wired as a `#[path]` child of `start::tests`, so `use super::*` resolves
//! into the workflow module and private items stay testable; the sibling
//! file exists so the decomposition ratchet counts the workflow file, not
//! its test suite (the `lifecycle/lifecycle_tests.rs` pattern).

use super::*;

use std::collections::BTreeMap;

use shekyl_crypto_pq::account::MASTER_SEED_BYTES;
use shekyl_engine_state::pscan_cursor::PScanCursor;
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch};
use shekyl_units::AtomicUnits;
use tempfile::TempDir;

use crate::engine::signer::SoloSigner;
use crate::engine::{Credentials, EngineCreateParams};

use crate::engine::test_support::dummy_daemon;

/// This suite's deterministic seed (multiplier 7).
fn fixed_seed() -> [u8; MASTER_SEED_BYTES] {
    crate::engine::test_support::fixed_seed(7)
}

/// Build a real `WalletFile`-backed full engine on a fresh tempdir. Returns the
/// `TempDir` guard so the wallet files outlive the test body.
fn create_test_engine() -> (TempDir, Engine<SoloSigner>) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base_path = tmp.path().join("wallet");
    let creds = Credentials::password_only(b"correct horse battery staple");
    let seed = fixed_seed();
    let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
    let engine = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create wallet");
    (tmp, engine)
}

fn accruals(pairs: &[(u64, u64)]) -> BTreeMap<SettlementEpoch, AtomicUnits> {
    pairs
        .iter()
        .map(|&(e, a)| (SettlementEpoch::from_raw(e), AtomicUnits::from_raw(a)))
        .collect()
}

fn pending(pairs: &[(u8, u64)]) -> BTreeMap<PCanonicalId, SettlementEpoch> {
    pairs
        .iter()
        .map(|&(id, e)| {
            (
                PCanonicalId::from_bytes([id; 32]),
                SettlementEpoch::from_raw(e),
            )
        })
        .collect()
}

/// The (b) seam end-to-end: the `WalletFile`-backed store seals a `PScanState`
/// to the real `.wallet.pscan` and reopens it byte-faithfully — and a re-seal is
/// the single durable resume point (crash-recovery: a restart reads exactly the
/// last sealed state, never a torn or stale one).
#[tokio::test(flavor = "multi_thread")]
async fn wallet_file_store_round_trips_a_pscan_state_through_the_real_seal() {
    let (_tmp, engine) = create_test_engine();
    let pscan_path = engine.persistence().pscan_path().to_path_buf();
    let arc = Arc::new(RwLock::new(engine));
    let store = WalletFilePScanStore {
        engine: arc.clone(),
    };

    // Never-scanned-as-P wallet: no seal yet ⇒ load is None (start at genesis).
    assert!(
        store.load().await.expect("load empty").is_none(),
        "absent .wallet.pscan must read as None, not error"
    );
    assert!(!pscan_path.exists(), "no seal exists before the first save");

    // Seal an initial state; reopen it through the real file. Include bond-post
    // matches so the privacy-sensitive reconcile evidence is exercised through the
    // real `.wallet.pscan` AEAD seal + atomic write, not just postcard.
    let state_a = PScanState::new(
        PScanCursor::at(BlockHeight::from_raw(5_000), [0x1A; 32]),
        accruals(&[(0, 100), (1, 250)]),
        pending(&[(0xAB, 1)]),
        vec![
            shekyl_engine_state::pscan_state::BondPostRecord {
                height: BlockHeight::from_raw(1_200),
                p_canonical_id: PCanonicalId::from_bytes([0xAB; 32]),
                post_kind: shekyl_wire::transaction::BOND_POST_KIND_JOINMARKET,
            },
            shekyl_engine_state::pscan_state::BondPostRecord {
                height: BlockHeight::from_raw(4_900),
                p_canonical_id: PCanonicalId::from_bytes([0xCD; 32]),
                post_kind: 2,
            },
        ],
        Vec::new(),
        Vec::new(),
        std::collections::BTreeMap::from([
            (
                PCanonicalId::from_bytes([0xAB; 32]),
                BlockHeight::from_raw(0),
            ),
            (
                PCanonicalId::from_bytes([0xCD; 32]),
                BlockHeight::from_raw(0),
            ),
        ]),
    );
    store.save(&state_a).await.expect("save A");
    assert!(pscan_path.exists(), ".wallet.pscan written by the seal");
    assert_eq!(
        store.load().await.expect("load A").expect("sealed A"),
        state_a,
        "the state round-trips through the real seal"
    );

    // Crash-recovery: the latest seal is the single durable resume point.
    let state_b = PScanState::new(
        PScanCursor::at(BlockHeight::from_raw(9_000), [0x2B; 32]),
        accruals(&[(0, 100), (1, 250), (2, 75)]),
        pending(&[(0xAB, 1)]),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        std::collections::BTreeMap::new(),
    );
    store.save(&state_b).await.expect("save B");
    assert_eq!(
        store.load().await.expect("load B").expect("sealed B"),
        state_b,
        "a restart resumes from the latest sealed state"
    );
}

/// The start precondition: with no stake engine running (a fresh, non-staking
/// wallet) there is no persona to scan as, so the on-demand `start_pscan`
/// refuses up front rather than spawning a no-op loop.
#[tokio::test(flavor = "multi_thread")]
async fn start_pscan_without_a_stake_engine_returns_no_stake_engine() {
    let (_tmp, engine) = create_test_engine();
    assert!(
        engine.stake_handle().is_none(),
        "a fresh non-staking wallet has no stake engine"
    );
    let arc = Arc::new(RwLock::new(engine));

    let result = Engine::<SoloSigner>::start_pscan(arc).await;

    match result {
        Err(PScanStartError::NoStakeEngine) => {}
        Ok(_) => panic!("expected NoStakeEngine, got a running handle"),
        Err(other) => panic!("expected NoStakeEngine, got {other:?}"),
    }
}

/// The lifecycle auto-start on a **non-staker** is the quiet path: `Ok(None)`,
/// no error, no task — the embedder calls it unconditionally after open and
/// never branches on staking state itself.
#[tokio::test(flavor = "multi_thread")]
async fn start_pscan_if_staker_is_none_for_a_non_staker() {
    let (_tmp, engine) = create_test_engine();
    let arc = Arc::new(RwLock::new(engine));

    let started = Engine::<SoloSigner>::start_pscan_if_staker(arc.clone())
        .await
        .expect("non-staker auto-start must not error");
    assert!(started.is_none(), "a non-staker gets no P-scan task");

    // Nothing claimed the single-flight slot: the quiet path really did nothing.
    assert!(
        !arc.read().await.open_slots.pscan.is_claimed(),
        "the quiet path must not claim the P-scan slot"
    );
}

/// The staker lifecycle end-to-end: `start_pscan_if_staker` on a staker wallet
/// spawns the task (the single-flight slot is claimed), a second start is
/// refused with [`PScanStartError::AlreadyRunning`], and `shutdown` releases
/// both the slot and the task's engine-arc clone — after which
/// `Arc::try_unwrap` succeeds and [`Engine::close`] can run. That last step is
/// the "close stops the task" property, enforced by ownership (see the module
/// docs): close is unreachable *until* the handle has been shut down.
///
/// The daemon is a never-connecting stub, which is fine on purpose: a failed
/// tip fetch is a recoverable per-sweep error the loop logs and retries, so
/// the task stays alive for the lifecycle assertions without a chain.
#[tokio::test(flavor = "multi_thread")]
async fn staker_auto_start_single_flight_and_shutdown_releases_the_engine() {
    use shekyl_engine_file::SafetyOverrides;

    use crate::engine::stake_engine::PSlot;
    use crate::engine::OpenedEngine;

    let tmp = tempfile::tempdir().expect("tempdir");
    let base_path = tmp.path().join("wallet");
    let creds = Credentials::password_only(b"correct horse battery staple");
    let seed = fixed_seed();
    let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
    let network = params.network;

    // Become a staker: persist a bond record (sets `staking_enabled`), then
    // reopen — the open path spawns the StakeEngine for a staker.
    let engine = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create wallet");
    engine
        .persist_bond_record(PSlot::from_raw(3))
        .expect("persist bond record");
    engine.close(&creds).expect("close created wallet");

    let opened = Engine::<SoloSigner>::open_full(
        &base_path,
        &creds,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect("reopen staker wallet");
    assert!(matches!(opened, OpenedEngine::Loaded(_)));
    let engine = opened.into_wallet();
    assert!(
        engine.stake_handle().is_some(),
        "a staker reopen spawns the StakeEngine"
    );
    let arc = Arc::new(RwLock::new(engine));

    // Auto-start: a staker gets a running P-scan task.
    let handle = Engine::<SoloSigner>::start_pscan_if_staker(arc.clone())
        .await
        .expect("staker auto-start succeeds")
        .expect("a staker gets a P-scan handle");
    assert!(
        arc.read().await.open_slots.pscan.is_claimed(),
        "the running task holds the single-flight slot"
    );

    // Double-start is refused while the first task runs.
    match Engine::<SoloSigner>::start_pscan(arc.clone()).await {
        Err(PScanStartError::AlreadyRunning) => {}
        Ok(_) => panic!("expected AlreadyRunning, got a second handle"),
        Err(other) => panic!("expected AlreadyRunning, got {other:?}"),
    }
    // ... and through the auto-start entry too.
    match Engine::<SoloSigner>::start_pscan_if_staker(arc.clone()).await {
        Err(PScanStartError::AlreadyRunning) => {}
        Ok(_) => panic!("expected AlreadyRunning, got a second handle"),
        Err(other) => panic!("expected AlreadyRunning, got {other:?}"),
    }

    // Shutdown: the task exits, releasing the slot and its engine-arc clone.
    handle.shutdown().await;
    assert!(
        !arc.read().await.open_slots.pscan.is_claimed(),
        "shutdown releases the single-flight slot"
    );

    // The embedder is now the sole owner, so close is reachable — the
    // ownership-enforced "close stops the task" order.
    let engine = Arc::try_unwrap(arc)
        .unwrap_or_else(|_| panic!("the shut-down task must not hold the engine arc"))
        .into_inner();
    engine.close(&creds).expect("close after shutdown");
}

/// A stopped scan can be started again: the slot is reusable across
/// start → shutdown → start within one session (restart-after-stop is an
/// ordinary lifecycle, not a wedged state).
#[tokio::test(flavor = "multi_thread")]
async fn pscan_can_be_restarted_after_shutdown() {
    use shekyl_engine_file::SafetyOverrides;

    use crate::engine::stake_engine::PSlot;

    let tmp = tempfile::tempdir().expect("tempdir");
    let base_path = tmp.path().join("wallet");
    let creds = Credentials::password_only(b"correct horse battery staple");
    let seed = fixed_seed();
    let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
    let network = params.network;

    let engine = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create wallet");
    engine
        .persist_bond_record(PSlot::from_raw(0))
        .expect("persist bond record");
    engine.close(&creds).expect("close created wallet");
    let engine = Engine::<SoloSigner>::open_full(
        &base_path,
        &creds,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect("reopen staker wallet")
    .into_wallet();
    let arc = Arc::new(RwLock::new(engine));

    let first = Engine::<SoloSigner>::start_pscan(arc.clone())
        .await
        .expect("first start");
    first.shutdown().await;

    let second = Engine::<SoloSigner>::start_pscan(arc.clone())
        .await
        .expect("restart after shutdown succeeds");
    second.shutdown().await;
}

/// Single-flight (#1): the slot admits exactly one claimant; a second
/// `try_claim` fails until the first guard drops, then succeeds again. This is
/// the primitive `start_pscan` rests on to stop two tasks racing the
/// `.wallet.pscan` seal (the full path needs a staking engine, exercised by the
/// lifecycle layer; here we pin the guarantee at the slot).
#[test]
fn pscan_slot_admits_one_claimant_at_a_time() {
    let slot = crate::engine::pscan::task::PScanSlot::new();
    assert!(!slot.is_claimed());

    let guard = slot.try_claim().expect("first claim succeeds");
    assert!(slot.is_claimed());
    assert!(slot.try_claim().is_none(), "second claim is refused");

    drop(guard);
    assert!(!slot.is_claimed(), "dropping the guard releases the slot");
    assert!(slot.try_claim().is_some(), "the slot can be reclaimed");
}

/// The store's blocking-I/O helper must not panic on a `current_thread` runtime
/// — a bare `tokio::task::block_in_place` would. `drive_persistence` builds such
/// runtimes, so the flavor gate is load-bearing, not theoretical.
#[tokio::test(flavor = "current_thread")]
async fn run_blocking_io_does_not_panic_on_a_current_thread_runtime() {
    let v = run_blocking_io(|| 42);
    assert_eq!(v, 42, "falls back to a direct call instead of panicking");
}

/// And it still runs (via `block_in_place`) on a multi-threaded runtime.
#[tokio::test(flavor = "multi_thread")]
async fn run_blocking_io_runs_on_a_multi_thread_runtime() {
    assert_eq!(run_blocking_io(|| 7), 7);
}
/// The fourth production submission seam — `LocalBondBroadcast` — rides the
/// same audited choke point its three siblings do (`claim_dispatch.rs`,
/// `drain_dispatch.rs` and `release_dispatch.rs` carry the identical pin).
///
/// It is gated **here**, in the file that owns the site, rather than folded
/// into one of theirs: each of those gates reads its own file through
/// `include_str!`, so adding this file's needles to one of them would make
/// that gate's subject a lie, and a reader chasing its red would open the
/// wrong file. The cost of a fourth copy is four literals; the cost of a
/// mislocated gate is paid by whoever debugs it.
///
/// This bites against the bond broadcast dropping the
/// `BroadcastSubmitter::local` construction, bypassing `submit_bound`'s
/// persona-pairing check, or reaching for a raw daemon client (T-DS-2). It
/// does NOT cover the inverse direction — that no production site *selects*
/// the ② `OwnRemote` arm — which is crate-wide and lives in
/// `tests/broadcast_own_remote_production_census.rs`; and like its siblings
/// it is a source-text pin, not a reachability proof.
#[test]
fn the_bond_broadcast_seam_stays_on_the_local_choke_point() {
    // Since this suite moved to a `#[path]` sibling, `start.rs` is
    // production text end to end and the whole file is the subject. Hold
    // that: an inline test module re-growing there would let test text
    // satisfy the positive needles below, so its marker must stay absent.
    let production = include_str!("start.rs");
    assert!(
        !production.contains("\nmod tests {"),
        "start.rs grew an inline tests module; this suite lives in start_tests.rs, and an \
         inline one would put test text inside this pin's subject"
    );
    // Code-only view: drop comment-only lines (`//`, `///`, `//!`) so the
    // module docs' references to forbidden tokens cannot satisfy the guards.
    let code: String = production
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    let choke_construct = "BroadcastSubmitter::local(";
    assert!(
        code.contains(choke_construct),
        "the bond broadcast must construct on the audited ① choke point"
    );
    let choke_submit = ".submit_bound(";
    assert!(
        code.contains(choke_submit),
        "dispatch must ride submit_bound's persona-pairing check"
    );
    let bare_submit = ".submit(";
    assert!(
        !code.contains(bare_submit),
        "no bare TransactionSubmitter::submit around the persona-pairing check (T-DS-2)"
    );
    let raw_client = "DaemonClient";
    assert!(
        !code.contains(raw_client),
        "the bond broadcast must route through the persona transport, never a \
         default DaemonClient (T-DS-2)"
    );
}
