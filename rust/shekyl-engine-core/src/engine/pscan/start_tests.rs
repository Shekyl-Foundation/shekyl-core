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

use shekyl_crypto_pq::account::SEED_BYTES;
use shekyl_engine_state::pscan_cursor::{PScanCursor, PSCAN_CURSOR_BLOCK, PSCAN_CURSOR_VERSION};
use shekyl_engine_state::pscan_state::{
    PSCAN_STATE_BLOCK, PSCAN_STATE_VERSION, PSCAN_STATE_VERSION_KEYLESS_JOIN,
};
use shekyl_engine_state::WalletLedgerError;
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch};
use shekyl_units::AtomicUnits;
use tempfile::TempDir;

use crate::engine::signer::SoloSigner;
use crate::engine::{Credentials, EngineCreateParams};

use crate::engine::test_support::dummy_daemon;

/// This suite's deterministic seed (multiplier 7).
fn fixed_seed() -> [u8; SEED_BYTES] {
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
        PScanCursor::at(
            BlockHeight::from_raw(5_000),
            [0x1A; 32],
            shekyl_engine_state::pscan_cursor::ArchivalFold::genesis(),
        ),
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
        PScanCursor::at(
            BlockHeight::from_raw(9_000),
            [0x2B; 32],
            shekyl_engine_state::pscan_cursor::ArchivalFold::genesis(),
        ),
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

    let result =
        Engine::<SoloSigner>::start_pscan(arc, &crate::engine::test_support::node_never_reached())
            .await;

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

    let started = Engine::<SoloSigner>::start_pscan_if_staker(
        arc.clone(),
        &crate::engine::test_support::node_never_reached(),
    )
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
    engine.close(&creds).await.expect("close created wallet");

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
    let handle = Engine::<SoloSigner>::start_pscan_if_staker(
        arc.clone(),
        &crate::engine::test_support::node_never_reached(),
    )
    .await
    .expect("staker auto-start succeeds")
    .expect("a staker gets a P-scan handle");
    assert!(
        arc.read().await.open_slots.pscan.is_claimed(),
        "the running task holds the single-flight slot"
    );

    // Double-start is refused while the first task runs.
    match Engine::<SoloSigner>::start_pscan(
        arc.clone(),
        &crate::engine::test_support::node_never_reached(),
    )
    .await
    {
        Err(PScanStartError::AlreadyRunning) => {}
        Ok(_) => panic!("expected AlreadyRunning, got a second handle"),
        Err(other) => panic!("expected AlreadyRunning, got {other:?}"),
    }
    // ... and through the auto-start entry too.
    match Engine::<SoloSigner>::start_pscan_if_staker(
        arc.clone(),
        &crate::engine::test_support::node_never_reached(),
    )
    .await
    {
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
    engine.close(&creds).await.expect("close after shutdown");
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
    engine.close(&creds).await.expect("close created wallet");
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

    let first = Engine::<SoloSigner>::start_pscan(
        arc.clone(),
        &crate::engine::test_support::node_never_reached(),
    )
    .await
    .expect("first start");
    first.shutdown().await;

    let second = Engine::<SoloSigner>::start_pscan(
        arc.clone(),
        &crate::engine::test_support::node_never_reached(),
    )
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

/// The stale-file refusal is the outer schema word only. A cursor mismatch
/// uses the same `UnsupportedBlockVersion` shape and must stay `LoadFailed`,
/// so the client is not told the file format is the cursor's version. The
/// outer refusal keeps the seal path and does not carry the user remedy.
///
/// Bites against `pscan_load_failure` matching every version error. The real
/// seal is `lifecycle_tests::a_stale_pscan_seal_refuses_the_staker_start_naming_the_file_and_versions`.
#[test]
fn a_cursor_version_mismatch_is_not_the_file_format() {
    // Sibling of the documented `/home/alice/wallets/primary.wallet` base.
    // `alice` names nobody; a personal home is not a fixture this repo can publish.
    let path = std::path::PathBuf::from("/home/alice/wallets/primary.wallet.pscan");
    let stale = super::pscan_load_failure(
        super::WalletFilePScanStoreError::Codec(WalletLedgerError::UnsupportedBlockVersion {
            block: PSCAN_STATE_BLOCK,
            file: PSCAN_STATE_VERSION_KEYLESS_JOIN,
            binary: PSCAN_STATE_VERSION,
        }),
        path.clone(),
    );
    let logged = stale.to_string();
    let rendered = path.display().to_string();
    assert!(
        logged.contains(&rendered),
        "the log line carries the seal path: {logged}"
    );
    assert!(
        !logged.contains("Move that"),
        "the user remedy is not this error's text: {logged}"
    );
    match stale {
        PScanStartError::StateFileVersionUnsupported {
            path: got,
            found,
            expected,
        } => {
            assert_eq!(got, path);
            assert_eq!(found, PSCAN_STATE_VERSION_KEYLESS_JOIN);
            assert_eq!(expected, PSCAN_STATE_VERSION);
        }
        other => panic!("the outer schema word is the typed refusal, got {other:?}"),
    }

    let cursor = super::pscan_load_failure(
        super::WalletFilePScanStoreError::Codec(WalletLedgerError::UnsupportedBlockVersion {
            block: PSCAN_CURSOR_BLOCK,
            file: PSCAN_CURSOR_VERSION + 1,
            binary: PSCAN_CURSOR_VERSION,
        }),
        path,
    );
    assert!(
        matches!(cursor, PScanStartError::LoadFailed(_)),
        "a cursor mismatch is not the file format, got {cursor:?}"
    );
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
/// `BroadcastSubmitter::for_wallet` construction, bypassing `submit_bound`'s
/// persona-pairing check, or reaching for a raw daemon client (T-DS-2). It
/// checks the bond dispatch site. The crate-wide census covers the other callers.
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

    let choke_construct = "BroadcastSubmitter::for_wallet(";
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

/// A signing seam for a test that seeds no plan: it is never asked to sign,
/// and answers `Raced` if it were.
#[cfg(windows)]
struct NoSigner;

#[cfg(windows)]
impl crate::engine::pscan::dispatch::BondPlanSigner for NoSigner {
    async fn sign_at_due(
        &self,
        _persona: shekyl_types::PCanonicalId,
        _tip: shekyl_types::ChainCount,
    ) -> crate::engine::bond_plan::PlanAttempt {
        crate::engine::bond_plan::PlanAttempt::Raced
    }

    async fn drain_ended(
        &self,
        _p_slot: shekyl_types::PSlot,
        _persona: shekyl_types::PCanonicalId,
    ) {
    }

    async fn persona_ended(&self, _p_slot: shekyl_types::PSlot) {}

    async fn slot_retired(&self, _p_slot: shekyl_types::PSlot) {}
}

/// Records every hand-off it is given and answers each as accepted.
#[cfg(windows)]
#[derive(Default)]
struct CountingBroadcast {
    sent: std::sync::Mutex<usize>,
}

#[cfg(windows)]
impl BondBroadcast for Arc<CountingBroadcast> {
    async fn submit_bound(
        &self,
        _handoff: crate::engine::transaction_submitter::BoundForSend,
    ) -> Result<
        crate::engine::transaction_submitter::SubmitSuccess,
        crate::engine::transaction_submitter::BroadcastSubmitError,
    > {
        *self.sent.lock().expect("sent") += 1;
        Ok(
            crate::engine::transaction_submitter::SubmitSuccess::Broadcast {
                hash: shekyl_types::TxHash::from_bytes([0u8; 32]),
                kind: crate::engine::transaction_submitter::BroadcastKind::Accepted,
            },
        )
    }
}

/// On a FAT32 volume no staking bytes leave the wallet (Rick, 2026-11-19).
/// The wallet's own pending store, on that volume: every seal a broadcast
/// follows (a bond post, a claim, a drain, an exit) is saved unconfirmed,
/// refused before any send, and taken back; and a bond post left on disk,
/// as a power loss can leave one, is neither covered by the open's save nor
/// sent by the dispatch driver.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs SHEKYL_TEST_FAT_DIR: a directory on a FAT32 volume (a scratch VHD)"]
async fn nothing_staking_leaves_on_a_fat_volume() {
    use shekyl_engine_file::{Durability, Unconfirmed};
    use shekyl_engine_state::pending_post_block::{
        PendingBondPost, PendingDrain, PendingEmissionClaim, PendingRelease, SealAdmission,
    };
    use shekyl_engine_state::PendingPostState;
    use shekyl_types::{BlockCount, ChainCount, GlobalOutputIndex, PSlot};

    use crate::engine::dispatch_durability::require_confirmed;
    use crate::engine::pscan::dispatch::DispatchTick;
    use crate::engine::pscan::pending_store::OpenCover;

    let root = std::env::var_os("SHEKYL_TEST_FAT_DIR").expect("SHEKYL_TEST_FAT_DIR is unset");
    let tmp = tempfile::tempdir_in(root).expect("a directory on the FAT volume");
    let base_path = tmp.path().join("wallet");
    let creds = Credentials::password_only(b"correct horse battery staple");
    let seed = fixed_seed();
    let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
    let engine = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create wallet");
    let arc = Arc::new(RwLock::new(engine));
    let gate = arc.read().await.pending_gate.clone();
    let store = pending_post_store_for_engine(arc.clone(), gate.clone());
    let on_fat = |durability: &Durability| matches!(durability, Durability::Unconfirmed(Unconfirmed::FileSystem(name)) if name == "FAT32");
    let persona = |byte: u8| PCanonicalId::from_bytes([byte; 32]);
    let gindexes = |at: u64| vec![GlobalOutputIndex::from_raw(at)];
    let reference_height = BlockHeight::from_raw(1_000);
    let tip = ChainCount::from_raw(1_010);
    let bond_post = move |byte: u8| PendingBondPost {
        wait: None,
        p_slot: PSlot::from_raw(u32::from(byte)),
        persona: persona(byte),
        tx_bytes: vec![byte; 4],
        posture: shekyl_engine_state::PlannedPosture::SupportCompleteTree,
        due: ChainCount::from_raw(1_005),
        funded_through: BlockHeight::from_raw(990),
        funding_gindexes: gindexes(u64::from(byte)),
        state: PendingPostState::Pending,
        reference_height,
        terminal: None,
    };

    // Every broadcast seal: saved unconfirmed, refused, taken back.
    type Seal = Box<dyn FnOnce(&mut PendingPostBlock) -> SealAdmission + Send>;
    type Unseal = Box<dyn FnOnce(&mut PendingPostBlock) -> bool + Send>;
    let seals: [(&str, Seal, Unseal); 4] = [
        (
            "bond post",
            Box::new(move |block| {
                let g = block.generation();
                block.seal_post(bond_post(1), g)
            }),
            Box::new(move |block| block.remove_post(&persona(1)).is_some()),
        ),
        (
            "claim",
            Box::new(move |block| {
                let g = block.generation();
                block.seal_claim(
                    PendingEmissionClaim {
                        persona: persona(2),
                        tx_bytes: vec![2; 4],
                        fee_gindexes: gindexes(2),
                        state: PendingPostState::Pending,
                        reference_height,
                        terminal: None,
                    },
                    tip,
                    g,
                )
            }),
            Box::new(move |block| block.remove_claim(&persona(2)).is_some()),
        ),
        (
            "drain",
            Box::new(move |block| {
                let g = block.generation();
                block.seal_drain(
                    PendingDrain {
                        persona: persona(3),
                        tx_bytes: vec![3; 4],
                        funding_gindexes: gindexes(3),
                        state: PendingPostState::Pending,
                        reference_height,
                        terminal: None,
                    },
                    tip,
                    g,
                )
            }),
            Box::new(move |block| block.remove_drain(&persona(3)).is_some()),
        ),
        (
            "exit",
            Box::new(move |block| {
                let g = block.generation();
                block.seal_release(
                    PendingRelease {
                        persona: persona(4),
                        tx_bytes: vec![4; 4],
                        funding_gindexes: gindexes(4),
                        state: PendingPostState::Pending,
                        reference_height,
                        terminal: None,
                    },
                    tip,
                    g,
                )
            }),
            Box::new(move |block| block.remove_release(&persona(4)).is_some()),
        ),
    ];
    for (kind, seal, unseal) in seals {
        let (admission, durability) = store
            .seal_reporting(
                |block| {
                    let admission = seal(block);
                    (admission == SealAdmission::Admit, admission)
                },
                unseal,
            )
            .await
            .unwrap_or_else(|e| panic!("the {kind}'s seal was applied: {e}"));
        assert_eq!(admission, SealAdmission::Admit, "{kind}");
        assert!(on_fat(&durability), "{kind}: {durability:?}");
        assert!(
            require_confirmed(durability).is_err(),
            "{kind}: an unconfirmed seal mints no bytes to send"
        );
    }
    let left = store
        .read(|block| block.sealed_records().count())
        .await
        .expect("read the pending records");
    assert_eq!(left, 0, "every unconfirmed seal was taken back");

    // A bond post on disk, as a power loss can leave one: the open's save is
    // not confirmed, so the driver neither covers nor sends it.
    let written = store
        .mutate_reporting(|block| {
            let g = block.generation();
            (block.seal_post(bond_post(5), g) == SealAdmission::Admit, ())
        })
        .await
        .expect("the post's save was applied")
        .1;
    assert!(on_fat(&written), "{written:?}");
    let opened = store.cover_at_open().await.expect("the open's load");
    assert!(
        matches!(&opened, OpenCover::Saved(durability) if on_fat(durability)),
        "{opened:?}"
    );
    let broadcast = Arc::new(CountingBroadcast::default());
    let mut driver = DispatchDriver::new(
        WalletFilePendingSealStore {
            engine: arc.clone(),
        },
        broadcast.clone(),
        NoSigner,
        DispatchConfig {
            alarm_horizon_blocks: BlockCount::from_raw(100),
            dispersal_bound: Duration::ZERO,
            reorg_depth: BlockCount::from_raw(720),
        },
        gate,
    );
    for _ in 0..3 {
        driver
            .on_tick(
                tip,
                crate::engine::pscan::dispatch::TickEvidence {
                    confirmed_posts: &std::collections::BTreeSet::new(),
                    live_funding: &std::collections::BTreeSet::new(),
                    scanned_through: None,
                    funding: &std::collections::BTreeMap::new(),
                    retired: &std::collections::BTreeSet::new(),
                },
                &CancellationToken::new(),
            )
            .await
            .expect("tick");
    }
    assert_eq!(
        *broadcast.sent.lock().expect("sent"),
        0,
        "no staking bytes leave a FAT volume"
    );

    // Close the wallet before its directory: on FAT a file still open
    // cannot be removed, and a dropped `TempDir` would leave the directory
    // behind silently.
    drop(driver);
    drop(store);
    let engine = Arc::try_unwrap(arc)
        .unwrap_or_else(|_| panic!("the test holds the only reference to the engine"))
        .into_inner();
    engine.close(&creds).await.expect("close the wallet");
    tmp.close().expect("the wallet's directory is removed");
}
