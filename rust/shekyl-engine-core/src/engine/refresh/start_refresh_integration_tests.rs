// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! End-to-end tests for [`Engine::start_refresh`] that drive the
//! real producer task against a real [`Engine<SoloSigner>`].
//!
//! Two flavours of fixture cover the surface:
//!
//! - **Unreachable-daemon scenarios** wire a [`DaemonClient`]
//!   pointed at an unreachable URL; the producer's `get_height`
//!   fails fast with [`IoError::Daemon`] and the failure
//!   surfaces through `join().await`. These tests pin handle-
//!   layer behaviour (`AlreadyRunning` on concurrent claim,
//!   slot-release after the producer task winds down,
//!   completion delivery on RPC failure) without modelling
//!   any chain state.
//! - **Hybrid scenarios** wire a [`TestDaemon`] in place of the
//!   real `DaemonClient` via
//!   [`Engine::replace_daemon`](crate::engine::Engine::replace_daemon),
//!   per `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` §6.3 hybrid-
//!   construction discipline. These tests exercise
//!   `start_refresh` end-to-end against synthetic chain state;
//!   the trait abstractions from Stage 1 PR 1 (the
//!   `DaemonEngine` surface, the `TestDaemon: Rpc + DaemonEngine`
//!   impl, the `derive_seed` master-seed helper) are what makes
//!   this coverage possible — Stage 0 had no path for a synthetic
//!   chain to drive `start_refresh` because `DaemonClient`
//!   wrapped a concrete `HttpRpc`.
//!
//! Hybrid fixtures use the §6.2 master-seed-derivation contract:
//! each test owns a single literal `master_seed` recorded in the
//! test name; the daemon's seed is derived via
//! `derive_seed(&master, ROLE_DAEMON)`. Reproducibility hinges on
//! the master seed alone — changing the master re-derives the
//! daemon seed consistently. (The wallet-side `Engine::create`
//! master-seed input is independent of the daemon seed by
//! design; mixing them would model a non-existent leak channel.)
//!
//! Wired as a `#[path]` child of `engine/refresh/mod.rs`, so `use super::*`
//! and `super::` paths resolve into the refresh module and private items
//! stay testable; the sibling file exists so the decomposition ratchet
//! counts the workflow file, not its test suite (the
//! `local_refresh_tests.rs` pattern).
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use shekyl_crypto_pq::account::{
    rederive_account, DerivationNetwork, SeedFormat, MASTER_SEED_BYTES,
};
use shekyl_rpc_transport::HttpRpc;
use tempfile::TempDir;
use tokio::sync::{watch, RwLock};
use tokio_util::sync::CancellationToken;

use super::{LedgerSnapshot, RefreshProgress};
use crate::engine::diagnostics::DiagnosticSink;
use crate::engine::fault_injecting_refresh::FaultInjecting as FaultInjectingRefresh;
use crate::engine::lifecycle::EngineCreateParams;
use crate::engine::local_refresh::LocalRefresh;
use crate::engine::test_support::{derive_seed, TestDaemon, ROLE_DAEMON};
use crate::engine::traits::{DaemonEngine, LedgerEngine, RefreshEngine};
use crate::engine::view_material::ViewMaterial;
use crate::engine::{
    Credentials, DaemonClient, Engine, IoError, RefreshError, RefreshOptions, SoloSigner,
};
use crate::scan::ScanResult;

/// Build a `DaemonClient` whose underlying RPC points at an
/// unreachable URL, on the *current* tokio runtime. Async
/// because [`HttpRpc::new`] is async; safe to call
/// from inside `#[tokio::test]` because we await it directly
/// rather than driving a separate runtime via `block_on`.
/// Hyper's connection-pool background tasks live on the test's
/// runtime; the test awaits all work before returning so
/// nothing is orphaned at runtime drop.
async fn unreachable_daemon() -> DaemonClient {
    let rpc = HttpRpc::new("http://127.0.0.1:1".to_string())
        .await
        .expect("construct HttpRpc against unreachable URL (no connect attempt yet)");
    DaemonClient::new(rpc)
}

/// Build a fresh `Engine<SoloSigner>` wrapped in
/// `Arc<RwLock<…>>` so the shape matches
/// `Engine::start_refresh`'s receiver. Returns the `TempDir`
/// alongside so the caller keeps the wallet file alive for the
/// test's scope.
async fn make_engine_arc() -> (Arc<RwLock<Engine<SoloSigner>>>, TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base_path = tmp.path().join("wallet");
    let creds = Credentials::password_only(b"start-refresh integration tests");
    let mut seed = [0u8; MASTER_SEED_BYTES];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = u8::try_from(i & 0xff).unwrap_or(0).wrapping_mul(13);
    }
    let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
    let daemon = unreachable_daemon().await;
    let wallet = Engine::<SoloSigner>::create(params, daemon)
        .expect("create FULL wallet for start_refresh integration tests");
    (Arc::new(RwLock::new(wallet)), tmp)
}

/// `start_refresh` against the unreachable dummy daemon
/// produces a runnable handle; the producer's `get_height`
/// call fails fast, and the failure surfaces through
/// `join().await` as `RefreshError::Io(IoError::Daemon)`.
/// The slot is released once the producer task exits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_refresh_propagates_daemon_io_error_via_join() {
    let (arc, _tmp) = make_engine_arc().await;

    let handle = Engine::start_refresh(arc.clone(), RefreshOptions::default())
        .await
        .expect("first start_refresh claims the slot");

    let result = handle.join().await;
    match result {
        Err(RefreshError::Io(IoError::Daemon { detail })) => {
            assert!(
                !detail.is_empty(),
                "Daemon error carries a non-empty detail string"
            );
        }
        other => panic!("expected Io(Daemon), got {other:?}"),
    }

    // The completion oneshot resolves before the producer
    // task's `_slot_guard` drops (sender is fired inside the
    // task, slot guard drops as the function returns). Poll
    // briefly for slot release; bounded so a regression does
    // not hang the suite.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        tokio::task::yield_now().await;
        let g = arc.read().await;
        if !g.refresh_slot.is_claimed() {
            break;
        }
        drop(g);
        if Instant::now() > deadline {
            panic!("slot still claimed 5s after join() resolved");
        }
    }
}

/// A second `start_refresh` while the first handle is alive
/// returns `RefreshError::AlreadyRunning`. Uses the
/// `current_thread` flavour so the first producer task does
/// not run until we explicitly await — guaranteeing the slot
/// is still claimed at the time of the second call without
/// relying on RPC timing.
#[tokio::test(flavor = "current_thread")]
async fn concurrent_start_refresh_returns_already_running() {
    let (arc, _tmp) = make_engine_arc().await;

    let h1 = Engine::start_refresh(arc.clone(), RefreshOptions::default())
        .await
        .expect("first claim succeeds");
    // Producer for h1 is queued but not yet polled (single-
    // threaded runtime, no intervening yield).
    let h2 = Engine::start_refresh(arc.clone(), RefreshOptions::default()).await;
    assert!(
        matches!(h2, Err(RefreshError::AlreadyRunning)),
        "second claim returns AlreadyRunning, got {h2:?}"
    );

    // Cleanup: drop h1 so the producer wakes on cancel and
    // releases the slot before the test ends.
    drop(h1);
    // Yield until the producer task has actually run and exited;
    // bounded so a regression doesn't hang the suite.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        tokio::task::yield_now().await;
        let g = arc.read().await;
        if !g.refresh_slot.is_claimed() {
            break;
        }
        drop(g);
        if Instant::now() > deadline {
            panic!("producer task did not exit within 5s of handle drop");
        }
    }
}

/// Dropping the handle fires the cancel token; the producer
/// task winds down and releases the slot. After the slot is
/// observably free, a fresh `start_refresh` succeeds — i.e.
/// the slot really is reusable, not merely "not held by *this*
/// reference".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drop_releases_slot_for_subsequent_start_refresh() {
    let (arc, _tmp) = make_engine_arc().await;

    let h1 = Engine::start_refresh(arc.clone(), RefreshOptions::default())
        .await
        .expect("first claim succeeds");
    drop(h1);

    // Spin briefly until the slot is released. Bounded so a
    // regression does not hang the suite.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        tokio::task::yield_now().await;
        let g = arc.read().await;
        if !g.refresh_slot.is_claimed() {
            break;
        }
        drop(g);
        if Instant::now() > deadline {
            panic!("slot still claimed 5s after handle drop");
        }
    }

    // Slot is free; a second `start_refresh` reclaims it.
    let h2 = Engine::start_refresh(arc.clone(), RefreshOptions::default())
        .await
        .expect("slot is reusable after producer wind-down");
    // Drain the second handle to keep the suite clean.
    _ = h2.join().await;
}

// ── Hybrid scenarios: real Engine<SoloSigner> + TestDaemon ──────────
//
// The construction discipline (§6.3):
//
// 1. Build a real `Engine<SoloSigner>` via `Engine::create` using
//    an unreachable `DaemonClient`. Pays for the file-handle,
//    keys, ledger, refresh-slot, and preferences setup once.
// 2. Swap the daemon component for a `TestDaemon` via
//    `Engine::replace_daemon`. The result is
//    `Engine<SoloSigner, TestDaemon>`; the dummy daemon is
//    dropped.
// 3. Wrap in `Arc<RwLock<…>>` and call `Engine::start_refresh`.

/// Deterministic master seed shared by every hybrid engine built
/// via [`make_hybrid_engine_arc`]. Pulled out as a constant (Stage 2)
/// so tests can re-derive the wallet's [`ViewMaterial`] without an
/// `Engine::keys()` accessor — that accessor was removed when the
/// key blob moved into the `KeyActor` (`STAGE_2_KEY_ENGINE_ACTOR.md`
/// §6). `seed[i] = (i & 0xff) * 17`, matching the prior inline loop.
const HYBRID_WALLET_SEED: [u8; MASTER_SEED_BYTES] = {
    let mut seed = [0u8; MASTER_SEED_BYTES];
    let mut i = 0usize;
    while i < MASTER_SEED_BYTES {
        // `i & 0xff` is masked to 0..=255, so the `as u8` cast is
        // exact, never truncating. `u8::try_from` (the runtime form
        // this const replaced) is not const-stable, so the masked
        // cast is the const-compatible equivalent.
        #[allow(clippy::cast_possible_truncation)]
        let byte = (i & 0xff) as u8;
        seed[i] = byte.wrapping_mul(17);
        i += 1;
    }
    seed
};

/// Re-derive the hybrid wallet's [`ViewMaterial`] from
/// [`HYBRID_WALLET_SEED`] using the **same** derivation parameters
/// [`EngineCreateParams::for_test_full`] pins (`Network::Stagenet` →
/// [`DerivationNetwork::Stagenet`], [`SeedFormat::Bip39`]). This is
/// the Stage-2 replacement for `ViewMaterial::try_from_keys(engine.keys())`:
/// the orchestrator no longer exposes its keys (they live in the
/// `KeyActor`), so the test re-derives the byte-identical view
/// material from the known seed instead.
fn hybrid_engine_view_material() -> ViewMaterial {
    let blob = rederive_account(
        &HYBRID_WALLET_SEED,
        DerivationNetwork::Stagenet,
        SeedFormat::Bip39,
    )
    .expect("rederive_account for hybrid wallet seed (stagenet/bip39)");
    ViewMaterial::try_from_keys(&blob)
        .expect("ViewMaterial::try_from_keys against re-derived hybrid blob")
}

/// Build an `Engine<SoloSigner, TestDaemon>` ready for hybrid
/// `start_refresh` tests. Returns the `TempDir` alongside so the
/// caller keeps the wallet file alive for the lifetime of the engine.
async fn make_hybrid_engine_arc(
    mock: TestDaemon,
) -> (Arc<RwLock<Engine<SoloSigner, TestDaemon>>>, TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base_path = tmp.path().join("wallet");
    let creds = Credentials::password_only(b"start-refresh hybrid integration tests");
    let wallet_seed = HYBRID_WALLET_SEED;
    let params = EngineCreateParams::for_test_full(&base_path, &creds, &wallet_seed);

    let dummy_rpc = HttpRpc::new("http://127.0.0.1:1".to_string())
        .await
        .expect("construct HttpRpc against unreachable URL (no connect attempt yet)");
    let dummy_daemon = DaemonClient::new(dummy_rpc);

    let real = Engine::<SoloSigner>::create(params, dummy_daemon)
        .expect("create FULL wallet for hybrid start_refresh test");
    let hybrid = real.replace_daemon(mock);
    (Arc::new(RwLock::new(hybrid)), tmp)
}

/// Build a linear chain of `n` synthetic blocks at heights
/// `0..n`, with `chain[0]` as the genesis-style block
/// (parented from `[0u8; 32]`). Real-daemon convention:
/// `chain[h] = block at height h`. Mirrors the helper in
/// [`super::test_support`] but is duplicated here rather than
/// promoted to `pub(crate)` because the two modules' test
/// surfaces are otherwise independent.
fn linear_chain(n: u64) -> Vec<shekyl_scanner::ScannableBlock> {
    use crate::engine::test_support::make_synthetic_block;
    let mut chain =
        Vec::with_capacity(usize::try_from(n).expect("test linear_chain length fits in usize"));
    let mut parent = [0u8; 32];
    for h in 0..n {
        let block = make_synthetic_block(h, parent);
        parent = block.block.hash();
        chain.push(block);
    }
    chain
}

/// Test-only [`RefreshEngine`] wrapper that forces exactly one
/// merge-time [`RefreshError::ConcurrentMutation`] retry, then
/// delegates to the wrapped production producer.
///
/// On the first `produce_scan_result` call it returns a
/// deliberately stale [`ScanResult`] — an empty range anchored two
/// heights past the snapshot's `synced_height`, so
/// `start != synced + 1`. The real
/// [`Engine::apply_scan_result`](super::super::Engine::apply_scan_result)
/// merge rejects that with [`RefreshError::ConcurrentMutation`],
/// exactly as a genuine snapshot race would; the orchestrator
/// retries with a fresh snapshot. On the second (and later) call
/// the wrapper delegates to the inner producer, whose real scan
/// merges to the chain tip.
///
/// This drives the §5.2 retry contract through the **real merge
/// entry point**. It replaces the prior ledger-side
/// `FaultInjecting<LocalLedger>` injection, which was removed with
/// the `LedgerEngine::apply_scan_result` trait method (FOLLOWUPS
/// P1): the async merge no longer crosses a `LedgerEngine` seam,
/// so the retry signal must originate where it does in production
/// — `Engine::apply_scan_result`'s start-height invariant.
///
/// **Not a Mock-X** (PR 3 §2.1.5): a one-method behavioural
/// perturbation over a real inner producer, `#[cfg(test)]`-only,
/// no parallel implementation and no clone / actor-mesh shape. The
/// stale-then-real toggle is the only deviation it introduces.
struct StaleThenRealRefresh<R: RefreshEngine> {
    inner: R,
    calls: AtomicUsize,
}

impl<R: RefreshEngine> StaleThenRealRefresh<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            calls: AtomicUsize::new(0),
        }
    }
}

impl<R> crate::engine::scan_floor::ScanStartFloorProvider for StaleThenRealRefresh<R>
where
    R: RefreshEngine + crate::engine::scan_floor::ScanStartFloorProvider,
{
    fn scan_start_floor(&self) -> u64 {
        self.inner.scan_start_floor()
    }
}

impl<R: RefreshEngine> RefreshEngine for StaleThenRealRefresh<R> {
    type Error = RefreshError;

    #[allow(clippy::manual_async_fn)]
    fn produce_scan_result<D: DaemonEngine>(
        &self,
        snapshot: LedgerSnapshot,
        daemon: &D,
        opts: RefreshOptions,
        cancel: CancellationToken,
        progress: watch::Sender<RefreshProgress>,
        diagnostics: &dyn DiagnosticSink,
    ) -> impl std::future::Future<Output = Result<ScanResult, Self::Error>> + Send {
        // First call: emit a stale empty result so the real merge
        // rejects it with `ConcurrentMutation` (the start-height
        // invariant fails: `start = synced + 2 != synced + 1`).
        // The Mutex-free `AtomicUsize` toggle is popped before the
        // future is constructed, so nothing is held across the
        // `.await`.
        let stale = (self.calls.fetch_add(1, Ordering::SeqCst) == 0)
            .then(|| ScanResult::empty_at(snapshot.synced_height.saturating_add(2), None));
        async move {
            if let Some(stale) = stale {
                return Ok(stale);
            }
            self.inner
                .produce_scan_result(snapshot, daemon, opts, cancel, progress, diagnostics)
                .await
                .map_err(Into::into)
        }
    }
}

/// Linear-scan baseline for the hybrid surface. With a 6-block
/// `TestDaemon` chain (heights 0..=5; `chain[0]` is genesis,
/// `chain[1..=5]` are post-genesis) and a fresh wallet at
/// `synced_height = 0`, `start_refresh` runs producer → merge
/// to completion: the producer derives the range
/// `synced_height + 1 .. get_height = 1..6`, scans the 5
/// post-genesis heights, and the merge advances the wallet's
/// `synced_height` to 5. The producer task releases the
/// refresh slot once it winds down.
///
/// What this pins (Stage 1 PR 1):
///
/// - `Engine<SoloSigner, TestDaemon>` is a real, callable shape —
///   the `D: DaemonEngine` parameterization isn't a phantom type;
///   `TestDaemon` actually drives the producer.
/// - `TestDaemon`'s `DaemonEngine` impl (`get_height`,
///   `fetch_scannable_block`) is wired through every
///   layer that the real `start_refresh` traverses (handle →
///   producer task → scanner → merge), so scenario coverage can be
///   added by composing the production implementors and
///   `FaultInjecting*` wrappers without re-validating the wiring
///   itself.
/// - `replace_daemon` preserves engine state across the swap:
///   ledger, indexes, reservations, refresh slot, and capability
///   come through the move-rebuild unchanged. Successful
///   slot-release after a *successful* refresh (as opposed to
///   the unreachable-daemon failure path's release) is observed
///   only here — the unreachable-daemon tests never reach the
///   merge.
///
/// Master seed (`MASTER_SEED` below) is recorded as a literal
/// in the test body per §6.2; the daemon seed is
/// `derive_seed(&master, ROLE_DAEMON)`. §6.2's "embed the seed
/// in the test name" guidance applies only to tests that
/// exercise RNG-driven mock behaviour (fee jitter, synthetic-
/// fork randomization). This test doesn't — it wires
/// `TestDaemon`'s pure chain-serving surface, so the master
/// seed lives in the body alone and the test name stays
/// descriptive.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hybrid_linear_scan_5_blocks_advances_synced_height() {
    const MASTER_SEED: [u8; 32] = [
        0x5a, 0x1e, 0x71, 0x70, 0x71, 0x01, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11,
    ];

    let daemon_seed = derive_seed(&MASTER_SEED, ROLE_DAEMON);
    // 6 blocks at heights 0..=5: chain[0] = genesis; chain[1..=5]
    // are the 5 post-genesis blocks the producer scans.
    let mock = TestDaemon::with_seed_and_chain(daemon_seed, linear_chain(6));
    let (arc, _tmp) = make_hybrid_engine_arc(mock).await;

    // Sanity-check the pre-refresh invariant: the wallet starts
    // at height 0; if it didn't, the post-refresh assertion
    // below would carry a confounded claim.
    {
        let g = arc.read().await;
        assert_eq!(
            g.synced_height(),
            0,
            "fresh hybrid engine starts at synced_height 0"
        );
    }

    let handle = Engine::start_refresh(arc.clone(), RefreshOptions::default())
        .await
        .expect("start_refresh claims the slot on the hybrid engine");

    let summary = handle
        .join()
        .await
        .expect("hybrid refresh against a 6-block TestDaemon chain joins successfully");
    assert_eq!(summary.processed_height_range, 1..6);
    assert_eq!(summary.blocks_processed, 5);

    // Merge has run by the time `join().await` returned; the
    // engine's persisted view of the chain matches the daemon.
    {
        let g = arc.read().await;
        assert_eq!(
            g.synced_height(),
            5,
            "post-refresh synced_height matches the producer's range upper bound"
        );
    }

    // The producer task signals completion *before* its
    // `_slot_guard` is dropped (sender fires inside the task,
    // slot guard drops as the function returns). Poll briefly
    // for slot release; bounded so a regression does not hang
    // the suite.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        tokio::task::yield_now().await;
        let g = arc.read().await;
        if !g.refresh_slot.is_claimed() {
            break;
        }
        drop(g);
        if Instant::now() > deadline {
            panic!("slot still claimed 5s after hybrid refresh joined");
        }
    }
}

/// CT-5a §3.2 (R1-Q2) forward-path KAT: a hybrid refresh feeds the
/// curve tree the full genesis-anchored range ahead of the ledger
/// merge (ack-before-commit, O2). Where
/// [`hybrid_linear_scan_5_blocks_advances_synced_height`] asserts the
/// *ledger* tip, this asserts the *tree* cursor: a fresh wallet whose
/// producer range is `1..6` must leave the tree's
/// [`CurveTreeHandle::ingested_tip_height`] at `Some(BlockHeight(5))`
/// — height `0` came from the genesis/birthday backfill (daemon-
/// fetched + decoded by the ingest pre-pass, since the producer's
/// floored range never includes it), heights `1..6` from the
/// producer's `block_leaves`. The two-source feed is the §3.2.1 R3-Q1
/// shape; this proves it runs through the live `run_refresh_task`
/// wiring, not just the unit helper.
///
/// The reorg resume-from-cursor KAT (D4) and the non-coinbase
/// sub-birthday-sibling completeness KAT (Tier-B-gated, CT-5c) are
/// the named follow-ons; this fixture is coinbase-only/empty-leaf, so
/// it proves the cursor advances over the full range but not the
/// membership-path correctness of non-coinbase siblings.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hybrid_refresh_feeds_curve_tree_from_genesis() {
    const MASTER_SEED: [u8; 32] = [
        0xc7, 0x5e, 0xed, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
        0x1b, 0x1c,
    ];

    let daemon_seed = derive_seed(&MASTER_SEED, ROLE_DAEMON);
    // 6 blocks at heights 0..=5: chain[0] = genesis; the producer
    // scans 1..=5 from synced_height 0, and the ingest pre-pass
    // backfills height 0 from the daemon.
    let mock = TestDaemon::with_seed_and_chain(daemon_seed, linear_chain(6));
    let (arc, _tmp) = make_hybrid_engine_arc(mock).await;

    // Pre-refresh: a fresh tree has no ingested tip.
    {
        let g = arc.read().await;
        let tip = g
            .curve_tree
            .ingested_tip_height()
            .await
            .expect("cursor read on the live actor");
        assert_eq!(tip, None, "a fresh wallet's curve tree has no ingested tip");
    }

    let handle = Engine::start_refresh(arc.clone(), RefreshOptions::default())
        .await
        .expect("start_refresh claims the slot on the hybrid engine");
    let summary = handle
        .join()
        .await
        .expect("hybrid refresh against a 6-block TestDaemon chain joins successfully");
    assert_eq!(summary.processed_height_range, 1..6);

    // Post-refresh: the tree cursor covers genesis-through-tip. The
    // merge advanced the ledger only after this ingest acked
    // (ack-before-commit), so the tree tip is never behind the ledger.
    {
        let g = arc.read().await;
        assert_eq!(
            g.synced_height(),
            5,
            "post-refresh ledger tip matches the producer range upper bound"
        );
        let tip = g
            .curve_tree
            .ingested_tip_height()
            .await
            .expect("cursor read on the live actor");
        assert_eq!(
            tip,
            Some(shekyl_curve_tree::BlockHeight(5)),
            "tree cursor covers genesis (backfilled) through the producer range tip"
        );
    }

    // Bounded poll for slot release so a regression cannot hang the
    // suite (mirrors the sibling hybrid tests).
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        tokio::task::yield_now().await;
        let g = arc.read().await;
        if !g.refresh_slot.is_claimed() {
            break;
        }
        drop(g);
        if Instant::now() > deadline {
            panic!("slot still claimed 5s after hybrid refresh joined");
        }
    }
}

/// CT-5 §3.2.1 D3 pure-logic KAT for the `rebuilding_membership`
/// predicate that drives the [`RefreshProgress`] display flag. The
/// flag is "ledger ahead of a lagging tree," which is exactly the
/// adopting / tree-wiped wallet; the forward-from-genesis common case
/// (`ledger_synced == 0`, fresh tree) must never read as rebuilding.
#[test]
fn membership_rebuilding_predicate() {
    use super::membership_rebuilding;
    use shekyl_curve_tree::BlockHeight;

    // Fresh wallet from genesis: tree fresh, ledger at 0 — both at
    // the floor, nothing to rebuild.
    assert!(
        !membership_rebuilding(None, 0),
        "a fresh-from-genesis wallet is not rebuilding"
    );
    // Adopting wallet: ledger loaded at 5, tree freshly wiped — the
    // backfill is the rebuild window.
    assert!(
        membership_rebuilding(None, 5),
        "an adopting wallet with a fresh tree and a non-zero ledger is rebuilding"
    );
    // Partially-rebuilt tree still behind the ledger.
    assert!(
        membership_rebuilding(Some(BlockHeight(3)), 5),
        "a tree cursor below the ledger tip is rebuilding"
    );
    // Caught up: tree cursor equals the ledger tip.
    assert!(
        !membership_rebuilding(Some(BlockHeight(5)), 5),
        "a tree caught up to the ledger is not rebuilding"
    );
    // Tree ahead of the ledger (does not occur under ack-before-
    // commit, but the predicate must not flag it).
    assert!(
        !membership_rebuilding(Some(BlockHeight(7)), 5),
        "a tree ahead of the ledger is not rebuilding"
    );
}

/// CT-5 §3.2.1 D3 wiring KAT: a forward-from-genesis hybrid refresh
/// surfaces the pending-incoming display fields on the progress
/// channel, and the common case is *not* flagged as rebuilding. The
/// fixture is coinbase-only/empty-leaf (no wallet-addressed outputs),
/// so the detected count is `0`; the load-bearing assertion is that
/// the terminal frame carries `rebuilding_membership == false`
/// (tree and ledger advanced in lockstep, no backfill gap). The
/// `rebuilding == true` path and a non-zero pending-incoming amount
/// require a divergent adopting state and a wallet-addressed
/// (non-coinbase) fixture respectively — both Tier-B-gated to CT-5c,
/// same as the sibling completeness KATs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hybrid_refresh_from_genesis_surfaces_not_rebuilding() {
    const MASTER_SEED: [u8; 32] = [
        0x4b, 0x2d, 0x9a, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb,
        0xdc, 0xed, 0xfe, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4,
        0xc3, 0xd2,
    ];

    let daemon_seed = derive_seed(&MASTER_SEED, ROLE_DAEMON);
    let mock = TestDaemon::with_seed_and_chain(daemon_seed, linear_chain(6));
    let (arc, _tmp) = make_hybrid_engine_arc(mock).await;

    let handle = Engine::start_refresh(arc.clone(), RefreshOptions::default())
        .await
        .expect("start_refresh claims the slot on the hybrid engine");
    // Hold a progress receiver across the join so the watch channel
    // retains its terminal frame for inspection afterwards.
    let progress = handle.progress();
    handle
        .join()
        .await
        .expect("hybrid refresh against a 6-block TestDaemon chain joins successfully");

    let terminal = *progress.borrow();
    assert!(
        !terminal.rebuilding_membership,
        "a forward-from-genesis refresh advances tree and ledger in lockstep, \
         so the terminal frame is not flagged as rebuilding"
    );
    assert_eq!(
        terminal.pending_incoming_count, 0,
        "a coinbase-only fixture has no wallet-addressed outputs to detect"
    );
    assert_eq!(
        terminal.pending_incoming_atomic_units, 0,
        "no detected outputs means a zero pending-incoming amount"
    );

    // Bounded poll for slot release so a regression cannot hang the
    // suite (mirrors the sibling hybrid tests).
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        tokio::task::yield_now().await;
        let g = arc.read().await;
        if !g.refresh_slot.is_claimed() {
            break;
        }
        drop(g);
        if Instant::now() > deadline {
            panic!("slot still claimed 5s after hybrid refresh joined");
        }
    }
}

/// CT-5a §3.2 (R3-Q6 / D4) reorg KAT for the ingest pre-pass's
/// rollback path: a reorg result must roll the tree back to keep
/// `fork_height - 1` (the last common height) and then resume from the
/// tree's own cursor onto the new fork — never from a driver-local
/// frontier (counter drift is unrepresentable because the driver holds
/// no frontier).
///
/// The witness is a deliberately **shorter** fork. A forward feed
/// takes the tree to tip `5`. A reorg at `fork_height = 3` carries a
/// new range `3..5` (heights `3, 4` only). The pre-pass must drop the
/// orphaned suffix (old heights `3, 4, 5`), re-ingest `3, 4`, and land
/// at tip `4`. Tip `4 != 5` is unambiguous: without the rollback the
/// tree would still report `5`; reaching `4` proves the suffix was
/// dropped and the cursor (not a stale counter) drove the resume.
///
/// Drives [`Engine::ingest_scan_result_into_curve_tree`] directly with
/// hand-built [`ScanResult`]s — the pre-pass reads only
/// `reorg_rewind` / `processed_height_range` / `block_leaves` (and the
/// daemon for the genesis backfill), so the merge-invariant fields stay
/// at their `empty_at` defaults. Leaves are empty (synthetic blocks are
/// empty-leaf); the non-coinbase sub-birthday-sibling completeness KAT
/// remains Tier-B-gated to CT-5c.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ingest_pre_pass_reorg_rolls_back_and_resumes_from_cursor() {
    const MASTER_SEED: [u8; 32] = [
        0x3e, 0x07, 0x6b, 0xac, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
        0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xf0, 0xe1,
        0xd2, 0xc3,
    ];
    let daemon_seed = derive_seed(&MASTER_SEED, ROLE_DAEMON);
    // chain[0] = genesis, backfilled by the pre-pass; chain[1..=5] are
    // the producer-range heights of the forward feed.
    let mock = TestDaemon::with_seed_and_chain(daemon_seed, linear_chain(6));
    let (arc, _tmp) = make_hybrid_engine_arc(mock).await;

    // Forward feed: range 1..6, empty leaves; genesis backfilled from
    // the daemon. Tree tip -> 5.
    let mut forward = ScanResult::empty_at(1, None);
    forward.processed_height_range = 1..6;
    forward.block_leaves = (1..6).map(|h| (h, Vec::new())).collect();
    // CT-5b §3.3: empty-leaf blocks reconstruct to the empty-tree sentinel
    // at every height, so the producer's header roots are the sentinel.
    forward.block_curve_tree_roots = (1..6)
        .map(|h| (h, shekyl_fcmp::tree::selene_hash_init()))
        .collect();
    {
        let g = arc.read().await;
        g.ingest_scan_result_into_curve_tree(&mut forward)
            .await
            .expect("forward feed ingests genesis-through-tip");
        assert_eq!(
            g.curve_tree
                .ingested_tip_height()
                .await
                .expect("cursor read"),
            Some(shekyl_curve_tree::BlockHeight(5)),
            "forward feed leaves the tree at tip 5",
        );
    }

    // Reorg at fork_height = 3 onto a shorter fork (range 3..5).
    let mut reorg = ScanResult::empty_at(3, None);
    reorg.processed_height_range = 3..5;
    reorg.reorg_rewind = Some(crate::scan::ReorgRewind { fork_height: 3 });
    reorg.block_leaves = (3..5).map(|h| (h, Vec::new())).collect();
    reorg.block_curve_tree_roots = (3..5)
        .map(|h| (h, shekyl_fcmp::tree::selene_hash_init()))
        .collect();
    {
        let g = arc.read().await;
        g.ingest_scan_result_into_curve_tree(&mut reorg)
            .await
            .expect("reorg feed rolls back and resumes");
        assert_eq!(
            g.curve_tree
                .ingested_tip_height()
                .await
                .expect("cursor read"),
            Some(shekyl_curve_tree::BlockHeight(4)),
            "tree rolled back to keep fork_height-1 (=2) then resumed on \
             the shorter fork to tip 4, dropping the orphaned height 5",
        );
    }
}

/// CT-5a §3.3 (R1-Q4 / O3) respawn happy-path KAT through the engine ingest
/// entry point. A fail-stopped curve-tree actor is healed by
/// [`Engine::ingest_scan_result_with_respawn`]: the first attempt sees the
/// dead actor (classified `recoverable_by_respawn`), the engine respawns it
/// (drop + reopen — cursor resumes from the persisted store tip, no genesis
/// replay), and the retry ingests the new range. The witness that the
/// respawn-and-retry actually progressed — rather than merely reopening — is
/// the post-heal tip advancing past the pre-kill tip.
///
/// The bounded-retry-then-surface escalation for a deterministically-corrupt
/// store (O3-sub) is CT-5d, not exercised here (this fixture's store is
/// clean, so one respawn heals it). Leaves are empty (the merge-path empty-
/// leaf shape); behavioral leaf/root correctness is the CT-2-oracle KAT
/// (commit 6) / Tier-B completeness (CT-5c).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ingest_pre_pass_respawns_after_actor_fail_stop() {
    const MASTER_SEED: [u8; 32] = [
        0x9d, 0x42, 0x1f, 0x88, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0,
        0xc0, 0xd0, 0xe0, 0xf0, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0xae,
        0xbf, 0xc0,
    ];
    let daemon_seed = derive_seed(&MASTER_SEED, ROLE_DAEMON);
    // chain[0] = genesis (backfilled by the pre-pass); chain[1..=5] are the
    // first forward feed's producer-range heights.
    let mock = TestDaemon::with_seed_and_chain(daemon_seed, linear_chain(6));
    let (arc, _tmp) = make_hybrid_engine_arc(mock).await;

    // First forward feed: range 1..6, empty leaves; genesis backfilled.
    // Tree tip -> 5.
    let mut forward = ScanResult::empty_at(1, None);
    forward.processed_height_range = 1..6;
    forward.block_leaves = (1..6).map(|h| (h, Vec::new())).collect();
    // CT-5b §3.3: empty-leaf blocks reconstruct to the empty-tree sentinel
    // at every height, so the producer's header roots are the sentinel.
    forward.block_curve_tree_roots = (1..6)
        .map(|h| (h, shekyl_fcmp::tree::selene_hash_init()))
        .collect();
    {
        let g = arc.read().await;
        g.ingest_scan_result_with_respawn(&mut forward)
            .await
            .expect("forward feed ingests genesis-through-tip");
        assert_eq!(
            g.curve_tree
                .ingested_tip_height()
                .await
                .expect("cursor read"),
            Some(shekyl_curve_tree::BlockHeight(5)),
            "forward feed leaves the tree at tip 5",
        );
    }

    // Simulate a fail-stop of the curve-tree actor (panic-free): the bare
    // ingest path now classifies the dead actor as respawn-recoverable.
    {
        let g = arc.read().await;
        g.curve_tree.kill_and_wait_for_test().await;
        let err = g
            .ingest_scan_result_into_curve_tree(&mut forward)
            .await
            .expect_err("a fail-stopped actor fails the bare (no-respawn) ingest");
        assert!(
            matches!(
                err,
                RefreshError::CurveTreeIngest {
                    recoverable_by_respawn: true,
                    ..
                }
            ),
            "a fail-stopped actor is classified respawn-recoverable, got {err:?}",
        );
    }

    // Second forward feed: range 6..8 (heights 6, 7), supplied as leaves so
    // no daemon backfill is needed. Through the respawn-aware wrapper, the
    // first attempt hits the dead actor, the engine respawns (cursor resumes
    // from the persisted tip 5), and the retry ingests 6, 7 to tip 7.
    let mut forward2 = ScanResult::empty_at(6, None);
    forward2.processed_height_range = 6..8;
    forward2.block_leaves = (6..8).map(|h| (h, Vec::new())).collect();
    forward2.block_curve_tree_roots = (6..8)
        .map(|h| (h, shekyl_fcmp::tree::selene_hash_init()))
        .collect();
    {
        let g = arc.read().await;
        g.ingest_scan_result_with_respawn(&mut forward2)
            .await
            .expect("respawn-and-retry heals the fail-stop and ingests the new range");
        assert_eq!(
            g.curve_tree
                .ingested_tip_height()
                .await
                .expect("cursor read"),
            Some(shekyl_curve_tree::BlockHeight(7)),
            "post-respawn the tree resumed from persisted tip 5 and ingested \
             6, 7 to tip 7 — the heal progressed, it did not merely reopen",
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ingest_rejects_inverted_processed_height_range() {
    // O5/O2: an inverted `processed_height_range` (end < start) is a
    // malformed `ScanResult`. The ingest pre-pass must reject it loudly
    // *before* touching the curve tree — the ledger merge's own
    // `end >= start` guard runs only after ingest, so without this the
    // tree would advance (via daemon backfill of `next < range_start`)
    // on a result the merge later rejects, leaving tree ahead of ledger.
    let daemon_seed = derive_seed(&[0x5b; 32], ROLE_DAEMON);
    let mock = TestDaemon::with_seed_and_chain(daemon_seed, linear_chain(6));
    let (arc, _tmp) = make_hybrid_engine_arc(mock).await;

    let mut bad = ScanResult::empty_at(5, None);
    // Built from bindings, not a `5..3` literal, to dodge
    // `clippy::reversed_empty_ranges` — the inversion is the point.
    let (start, end) = (5u64, 3u64);
    bad.processed_height_range = start..end;

    let g = arc.read().await;
    let err = g
        .ingest_scan_result_into_curve_tree(&mut bad)
        .await
        .expect_err("an inverted processed_height_range must be rejected");
    assert!(
        matches!(
            err,
            RefreshError::MalformedScanResult { reason }
                if reason.contains("end precedes start")
        ),
        "expected an end-precedes-start MalformedScanResult, got {err:?}",
    );
    // O2: the tree must not have advanced on the rejected malformed range.
    assert_eq!(
        g.curve_tree
            .ingested_tip_height()
            .await
            .expect("cursor read"),
        None,
        "the curve tree must not advance on a rejected malformed range",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ingest_rejects_header_root_mismatch() {
    // §3.3 / O5 (the lying-daemon defense, CT-5b's load-bearing KAT). A
    // daemon serving leaves that do not reconstruct to the consensus
    // header-committed root it claims is the inconsistent liar. The
    // ingest-time verify must reject it *terminally* — a respawn re-derives
    // the same root, so it is not recoverable — and the refresh pre-pass
    // returning `Err` means the ledger merge never runs (O2: the ledger
    // never advances past tree state the wallet cannot reproduce).
    let daemon_seed = derive_seed(&[0x3c; 32], ROLE_DAEMON);
    let mock = TestDaemon::with_seed_and_chain(daemon_seed, linear_chain(6));
    let (arc, _tmp) = make_hybrid_engine_arc(mock).await;

    // Genesis (height 0) backfills from the TestDaemon (honest sentinel
    // root, passes); height 1 carries empty leaves — which reconstruct to
    // the sentinel — but the producer claims a *different* header root.
    let mut bad = ScanResult::empty_at(1, None);
    bad.processed_height_range = 1..2;
    bad.block_leaves = vec![(1, Vec::new())];
    bad.block_curve_tree_roots = vec![(1, [0xAB; 32])];

    let g = arc.read().await;
    let err = g
        .ingest_scan_result_into_curve_tree(&mut bad)
        .await
        .expect_err("a header-root mismatch must fail ingest");
    assert!(
        matches!(
            err,
            RefreshError::CurveTreeIngest {
                context,
                recoverable_by_respawn: false,
            } if context.contains("root mismatch")
        ),
        "expected a terminal root-mismatch CurveTreeIngest, got {err:?}",
    );
}

/// Exercise the §5.2 retry contract end-to-end. Composition: a
/// 6-block [`TestDaemon`] chain (heights 0..=5) drives the producer
/// from `synced_height = 0`. The producer slot is a
/// [`StaleThenRealRefresh`] wrapping the production
/// [`LocalRefresh`]: its first `produce_scan_result` returns a
/// stale empty result, so the real merge
/// ([`Engine::apply_scan_result`](super::super::Engine::apply_scan_result))
/// rejects attempt 1 with [`RefreshError::ConcurrentMutation`]; the
/// orchestrator retries with a fresh snapshot and the second
/// attempt runs the canonical merge body against the inner
/// production [`LocalLedger`], advancing `synced_height` to 5.
///
/// What this pins (Stage 1 PR 2 + the FOLLOWUPS P1 async post-pass
/// fix):
///
/// - The §5.2 retry contract is exercised through the *real*
///   refresh path (`Engine::start_refresh` → `run_refresh_task`
///   producer/merge loop), not a unit test of `apply_scan_result`
///   in isolation. Crucially, the retry signal now originates from
///   the **real merge entry point** (`Engine::apply_scan_result`'s
///   start-height invariant) rather than a ledger-trait seam: the
///   async merge no longer crosses a `LedgerEngine` method, so the
///   prior `FaultInjecting<LocalLedger>` injection is replaced by a
///   producer that emits a genuinely-stale result.
/// - On the success path (attempt 2) the merge runs the *real*
///   production body
///   ([`apply_scan_result_to_state`](super::merge::apply_scan_result_to_state))
///   **and** the M3b engine post-pass under one write guard, not a
///   parallel-implementation stand-in.
/// - Bounded retry: one stale result produces exactly one retry
///   (`merge_attempts == 2`).
/// - `replace_refresh` preserves engine state across the swap,
///   composing cleanly with `replace_daemon`: keys, ledger,
///   reservations, refresh slot, and capability all flow through
///   the move-rebuild unchanged, and the produced engine is
///   `Send + Sync` (required for `Arc<RwLock<…>>` +
///   `tokio::spawn`).
///
/// Master seed is recorded as a literal in the test body per
/// §6.2; the daemon seed is `derive_seed(&master, ROLE_DAEMON)`
/// for `TestDaemon`. The `derive_seed_pinned_fixture_*` tests in
/// `test_support` lock down that derivation against upstream
/// library drift. The producer wrapper does not consume a seed —
/// the inner [`LocalRefresh`] / [`LocalLedger`] are deterministic
/// by construction, and the stale-then-real toggle is the only
/// behavioural deviation the test introduces.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hybrid_apply_scan_result_retries_on_concurrent_mutation() {
    const MASTER_SEED: [u8; 32] = [
        0xa5, 0xa5, 0x5a, 0x5a, 0xfe, 0xed, 0xfa, 0xce, 0xc0, 0x01, 0xd0, 0x0d, 0xba, 0xad, 0xf0,
        0x0d, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
        0xf0, 0x00,
    ];

    let daemon_seed = derive_seed(&MASTER_SEED, ROLE_DAEMON);

    // 6-block linear chain; producer scans heights 1..=5 starting
    // from a fresh `LocalLedger` at `synced_height = 0`.
    let mock_daemon = TestDaemon::with_seed_and_chain(daemon_seed, linear_chain(6));
    let (arc, _tmp) = make_hybrid_engine_arc(mock_daemon).await;

    // Swap the producer slot for the stale-then-real wrapper. The
    // consume-and-rebuild `replace_refresh` needs an owned engine,
    // so unwrap the single-strong-reference arc, re-derive
    // `ViewMaterial` from the known hybrid seed (the engine no longer
    // exposes its keys — they live in the `KeyActor`, §6), wrap it,
    // and re-wrap the arc.
    let arc = {
        let engine = std::sync::Arc::into_inner(arc)
            .expect("arc has one strong reference at this point")
            .into_inner();
        let vm = hybrid_engine_view_material();
        let refresh = StaleThenRealRefresh::new(LocalRefresh::new(vm, 0));
        let hybrid = engine.replace_refresh(refresh);
        Arc::new(RwLock::new(hybrid))
    };

    // Sanity-check the pre-refresh invariant on the ledger surface.
    {
        let g = arc.read().await;
        assert_eq!(
            g.ledger.synced_height(),
            0,
            "fresh hybrid engine starts at LocalLedger synced_height 0"
        );
    }

    let handle = Engine::start_refresh(arc.clone(), RefreshOptions::default())
        .await
        .expect("start_refresh claims the slot on the hybrid engine");

    let summary = handle
        .join()
        .await
        .expect("hybrid retry refresh against a 6-block TestDaemon chain joins after one retry");
    assert_eq!(
        summary.merge_attempts, 2,
        "attempt 1's stale result is rejected with ConcurrentMutation; attempt 2 succeeds"
    );
    assert_eq!(summary.processed_height_range, 1..6);
    assert_eq!(summary.blocks_processed, 5);

    // Post-merge state is authoritative: the canonical merge body
    // ran on attempt 2 and advanced the inner `LocalLedger`'s
    // `synced_height` to the chain tip.
    {
        let g = arc.read().await;
        assert_eq!(
            g.synced_height(),
            5,
            "post-retry LocalLedger synced_height matches the producer's range upper bound"
        );
    }

    // Slot release: same shape as the linear-scan hybrid test.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        tokio::task::yield_now().await;
        let g = arc.read().await;
        if !g.refresh_slot.is_claimed() {
            break;
        }
        drop(g);
        if Instant::now() > deadline {
            panic!("slot still claimed 5s after hybrid retry refresh joined");
        }
    }
}

/// **Hybrid retry test pinning the §6 trait/orchestrator
/// cancellation-checkpoint split end-to-end against a fully-
/// composed four-slot engine
/// `Engine<SoloSigner, TestDaemon, LocalLedger,
/// StaleThenRealRefresh<FaultInjectingRefresh<LocalRefresh>>>`.**
///
/// Composition:
///
/// - Daemon slot: [`TestDaemon`] driving a 6-block linear chain
///   (heights 0..=5).
/// - Ledger slot: the production [`LocalLedger`] (no wrapper). The
///   ledger-side `FaultInjecting<LocalLedger>` injection was
///   removed with the `LedgerEngine::apply_scan_result` trait
///   method (FOLLOWUPS P1); the merge no longer crosses a
///   `LedgerEngine` seam, so the retry is driven from the producer
///   instead (see the ledger slot's replacement below).
/// - Refresh slot: a [`StaleThenRealRefresh`] wrapping a
///   [`FaultInjectingRefresh<LocalRefresh>`](FaultInjectingRefresh).
///   The inner `FaultInjectingRefresh` carries no queued failures
///   (it delegates to [`LocalRefresh`] every call), exercising its
///   delegation path and keeping the full
///   `Engine<S, D, L, E, R, P, F>` shape with a real `RefreshEngine`
///   wrapper in the `R` position. The outer `StaleThenRealRefresh`
///   emits one stale result so the real merge rejects attempt 1
///   with [`RefreshError::ConcurrentMutation`] and the orchestrator
///   retries. The `LocalRefresh` is constructed from the engine's
///   own keys via [`ViewMaterial::try_from_keys`] — the same path
///   [`super::lifecycle`] uses at [`Engine::create`] time.
///
/// What this pins:
///
/// - **Four-slot composition.** Every engine slot (daemon,
///   ledger, refresh, plus the implicit signer) is parameterised
///   through the trait surface; `replace_daemon` then
///   `replace_refresh` rebuild the engine, each moving a type
///   parameter from its default to the swapped-in implementor.
///   The nested-wrapper `R` position proves the `R: RefreshEngine`
///   parameter composes with `D: DaemonEngine` (PR 1) and the
///   `LocalLedger` `L` slot at the orchestrator call sites in
///   [`run_refresh_task`].
/// - **Cancellation-checkpoint split exercised end-to-end.** The
///   orchestrator runs through checkpoint 1 (top-of-attempt) and
///   checkpoint 4 (pre-merge) on each of the two attempts. The
///   producer trait body runs through checkpoints 2/3 (top-of-loop
///   + per-block) across the 5 block iterations on attempt 2. No
///   cancel-token is fired, so each checkpoint observes
///   `is_cancelled() == false` and proceeds — pinning the
///   not-cancelled path; cancellation-path coverage is the
///   shared-token tests in the producer-side suite. The split's
///   load-bearing property is that the two checkpoint sets live on
///   opposite sides of the trait boundary; running the full retry
///   pipeline exercises both sides against the wrapper-composed
///   engine.
/// - **Retry path through the real merge.** Attempt 1's stale
///   producer result is rejected by `Engine::apply_scan_result`'s
///   start-height invariant with `ConcurrentMutation`; the
///   orchestrator's retry branch re-runs the producer (which on
///   the second call delegates through `FaultInjectingRefresh` to
///   `LocalRefresh`), and the second attempt's merge runs the
///   canonical [`apply_scan_result_to_state`](super::merge::apply_scan_result_to_state)
///   body plus the M3b post-pass against the inner `LocalLedger`.
///   `summary.merge_attempts == 2`.
/// - **Wrapper drain contract.** The inner `FaultInjectingRefresh`
///   queue is empty throughout, so its [`Drop`] `debug_assert!`
///   passes at teardown (the F-Mock-2 drain contract).
///
/// Master seed is recorded as a literal in the test body per
/// §6.2; the daemon seed is `derive_seed(&master, ROLE_DAEMON)`.
/// The wallet-side master seed is independent of the daemon seed
/// by design (per the §6.2 contract); both wrappers are
/// deterministic by construction (the stale-then-real toggle is
/// the only behavioural deviation introduced).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hybrid_refresh_engine_orchestrator_cancellation_retries() {
    const MASTER_SEED: [u8; 32] = [
        0xc7, 0xc7, 0x7c, 0x7c, 0xfa, 0xce, 0xb0, 0x0b, 0xd0, 0x0d, 0xfe, 0xed, 0x42, 0x42, 0x13,
        0x37, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e,
        0x8f, 0x90,
    ];

    let daemon_seed = derive_seed(&MASTER_SEED, ROLE_DAEMON);

    // 6-block linear chain (heights 0..=5); the producer scans
    // heights 1..=5 from a fresh `LocalLedger` at
    // `synced_height = 0`. The wallet's own master seed (driven by
    // `make_hybrid_engine_arc`'s internal deterministic-seed loop)
    // is independent of `MASTER_SEED` here, which only seeds the
    // daemon side — the wallet seed is regenerated per fixture and
    // the keys derived from it are what the refresh wrapper
    // consumes via `ViewMaterial::try_from_keys` below.
    let mock_daemon = TestDaemon::with_seed_and_chain(daemon_seed, linear_chain(6));

    // Build the daemon-swapped engine, then chain `replace_refresh`
    // to land the four-slot composition. The keys accessor is
    // `pub(crate)`, so the `ViewMaterial` construction happens at
    // the test site.
    let (arc, _tmp) = make_hybrid_engine_arc(mock_daemon).await;
    let arc = {
        // Pull the engine out of the `Arc<RwLock<…>>` to consume it
        // for `replace_refresh`, then re-wrap. `make_hybrid_engine_arc`
        // is the only `Arc` reference holder; the consume-and-
        // rebuild shape of `replace_refresh` requires owned
        // `Engine`, not a borrow.
        let engine = std::sync::Arc::into_inner(arc)
            .expect("arc has one strong reference at this point")
            .into_inner();
        // Re-derive ViewMaterial from the known hybrid seed — the
        // engine no longer exposes its keys (they live in the
        // `KeyActor`, §6). Wrap it in the (no-failure)
        // `FaultInjectingRefresh` for four-slot composition, then in
        // `StaleThenRealRefresh` to drive the one-shot retry.
        let vm = hybrid_engine_view_material();
        let refresh =
            StaleThenRealRefresh::new(FaultInjectingRefresh::new(LocalRefresh::new(vm, 0)));
        let hybrid = engine.replace_refresh(refresh);
        Arc::new(RwLock::new(hybrid))
    };

    // Sanity-check the pre-refresh invariant on the ledger surface.
    {
        let g = arc.read().await;
        assert_eq!(
            g.ledger.synced_height(),
            0,
            "fresh hybrid engine starts at LocalLedger synced_height 0"
        );
    }

    let handle = Engine::start_refresh(arc.clone(), RefreshOptions::default())
        .await
        .expect("start_refresh claims the slot on the four-slot hybrid engine");

    let summary = handle
        .join()
        .await
        .expect("hybrid retry refresh against four-slot composition joins after one retry");

    assert_eq!(
        summary.merge_attempts, 2,
        "attempt 1's stale producer result is rejected with ConcurrentMutation; \
         attempt 2's merge succeeds against the inner LocalLedger"
    );
    assert_eq!(summary.processed_height_range, 1..6);
    assert_eq!(summary.blocks_processed, 5);

    // Post-merge state is authoritative: the inner `LocalLedger`
    // synced_height matches the producer's range upper bound after
    // the canonical merge ran on attempt 2.
    {
        let g = arc.read().await;
        assert_eq!(
            g.synced_height(),
            5,
            "post-retry LocalLedger synced_height matches the producer's range upper bound"
        );
    }

    // Slot release: same shape as the hybrid retry test.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        tokio::task::yield_now().await;
        let g = arc.read().await;
        if !g.refresh_slot.is_claimed() {
            break;
        }
        drop(g);
        if Instant::now() > deadline {
            panic!("slot still claimed 5s after four-slot hybrid retry refresh joined");
        }
    }
}

// ── CT-5a commit 6: CT-2 Tier-A oracle match through the engine ─────
//
// The DoD's core obligation (CT5_ENGINE_WIRING.md §, "CT-5a"): the engine
// refresh's curve-tree ingest reproduces the consensus header root through
// the full engine → handle → actor → client wiring, forward and across a
// reorg, byte-equal to the CT-2 oracle at every height.
//
// This closes the last link in a three-KAT chain that cannot drift (all
// three consume the *same* `ct2_tier_a.json`, sourced cross-crate):
//   1. `curve_tree_decode::decode_reproduces_ct2_tier_a_leaf_inputs` —
//      `ScannableBlock` → `OwnedTxLeaves` matches the oracle rows.
//   2. `shekyl-curve-tree`'s `recon_kat::client_reconstructs_consensus_
//      root_at_every_height` — those rows reconstruct the oracle root
//      through the `CurveTreeClient`.
//   3. *here* — the engine's `ingest_scan_result_into_curve_tree` carries
//      those rows to the oracle root at every height through the actor.
//
// The leaves are built directly from the oracle rows (the proven output of
// #1), so no full-block/proofs/scanner machinery is needed: the producer
// range covers genesis-to-tip (`processed_height_range.start == 0`), so the
// cursor-driven merge takes every height from `block_leaves` with no daemon
// backfill. Reading the reconstructed root back uses the test-only
// `CurveTreeHandle::root_at` (the production §3.3 verify / send-time
// re-derivation is CT-5b).

/// The cross-crate Tier-A reconstruct-root oracle — the *same* fixture
/// `shekyl-curve-tree`'s `recon_kat` and the engine-path decode KAT
/// (`curve_tree_decode`) consume, sourced here so the three KATs cannot
/// drift.
const CT2_TIER_A_FIXTURE: &str =
    include_str!("../../../../shekyl-curve-tree/tests/fixtures/ct2_tier_a.json");

fn ct2_hex_vec(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn ct2_hex32(s: &str) -> [u8; 32] {
    let v = ct2_hex_vec(s);
    assert_eq!(v.len(), 32, "expected 32 bytes, got {}", v.len());
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

/// One decoded fixture block for the engine ingest path: its height, the
/// recorded consensus header root, and the coinbase [`OwnedTxLeaves`]
/// exactly as [`curve_tree_decode::decode_block_leaves`] would produce them
/// — `output_key` / `commitment` / `target` verbatim, `h_pqc` left for the
/// client to resolve from the `0x07` blob at ingest.
struct Ct2FixtureBlock {
    height: u64,
    root: [u8; 32],
    leaves: Vec<crate::scan::OwnedTxLeaves>,
}

/// Decode one named chain from the Tier-A fixture into per-height blocks
/// carrying the coinbase leaf set in `OwnedTxLeaves` form.
fn ct2_tier_a_chain(name: &str) -> Vec<Ct2FixtureBlock> {
    use shekyl_curve_tree::{RawOutput, TargetKind};

    let f: serde_json::Value =
        serde_json::from_str(CT2_TIER_A_FIXTURE).expect("Tier-A fixture parses");
    let chain = f["chains"]
        .as_array()
        .expect("chains array")
        .iter()
        .find(|c| c["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("chain {name} not in fixture"));

    chain["blocks"]
        .as_array()
        .expect("blocks array")
        .iter()
        .map(|b| {
            let mt = &b["miner_tx"];
            let blob = ct2_hex_vec(mt["pqc_leaf_hashes"].as_str().expect("0x07 blob hex"));
            let outputs = mt["outputs"]
                .as_array()
                .expect("outputs array")
                .iter()
                .map(|o| RawOutput {
                    output_key: ct2_hex32(o["output_key"].as_str().expect("O hex")),
                    commitment: o["commitment"].as_str().map(ct2_hex32),
                    target: match o["target"].as_str().expect("target") {
                        "tagged_key" => TargetKind::TaggedKey,
                        "key" => TargetKind::Key,
                        other => panic!("unexpected Tier-A target kind: {other}"),
                    },
                })
                .collect();
            Ct2FixtureBlock {
                height: b["height"].as_u64().expect("height"),
                root: ct2_hex32(b["curve_tree_root"].as_str().expect("root hex")),
                // The coinbase is the only leaf-bearing tx in a Tier-A block
                // (coinbase-only regtest fixture). `is_miner` drives the +60
                // maturity offset in the client's drain order.
                leaves: vec![crate::scan::OwnedTxLeaves {
                    is_miner: true,
                    leaf_hash_blob: Some(blob),
                    outputs,
                }],
            }
        })
        .collect()
}

/// Read a top-level `u64` field (e.g. `main_tip`) from the Tier-A fixture.
fn ct2_tier_a_u64(key: &str) -> u64 {
    let f: serde_json::Value =
        serde_json::from_str(CT2_TIER_A_FIXTURE).expect("Tier-A fixture parses");
    f[key]
        .as_u64()
        .unwrap_or_else(|| panic!("fixture key {key} missing or non-u64"))
}

/// Build a `ScanResult` that drives a genesis-anchored forward ingest of
/// `blocks`: producer range `0..tip+1`, every height's leaves materialized
/// so the cursor-driven merge never falls to the daemon backfill. Only the
/// fields `ingest_scan_result_into_curve_tree` reads
/// (`processed_height_range` / `block_leaves` / `reorg_rewind`) are set; the
/// merge-invariant fields stay at their `empty_at` defaults.
fn ct2_forward_scan_result(blocks: &[Ct2FixtureBlock]) -> ScanResult {
    let end = blocks.last().expect("non-empty chain").height + 1;
    let mut r = ScanResult::empty_at(0, None);
    r.processed_height_range = 0..end;
    r.block_leaves = blocks
        .iter()
        .map(|b| (b.height, b.leaves.clone()))
        .collect();
    // CT-5b §3.3: carry the Tier-A oracle's consensus header root per
    // height so the ingest-time verify passes the honest path (the same
    // roots the `root_at` assertions below check against).
    r.block_curve_tree_roots = blocks.iter().map(|b| (b.height, b.root)).collect();
    r
}

/// CT-5a commit-6 DoD (forward): the engine ingest path reconstructs the
/// CT-2 Tier-A consensus header root at **every** height of the `main`
/// chain, driven through the real `Engine → CurveTreeHandle → CurveTreeActor
/// → CurveTreeClient` wiring (not the bare `recon` / client APIs the
/// cross-crate KATs cover). The `main` chain spans heights 0..=210, so this
/// crosses the empty-window → first-drain boundary at height 61 (the S2 pin)
/// through the engine.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_ingest_reconstructs_ct2_tier_a_root_at_every_height() {
    use shekyl_curve_tree::BlockHeight;

    const MASTER_SEED: [u8; 32] = [
        0x6c, 0x21, 0x9a, 0x3f, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
        0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x01, 0x12,
        0x23, 0x34,
    ];
    let daemon_seed = derive_seed(&MASTER_SEED, ROLE_DAEMON);
    // No backfill: the producer range starts at genesis and every height's
    // leaves are materialized, so the daemon is never queried — a 1-block
    // stub satisfies `make_hybrid_engine_arc`.
    let mock = TestDaemon::with_seed_and_chain(daemon_seed, linear_chain(1));
    let (arc, _tmp) = make_hybrid_engine_arc(mock).await;

    let blocks = ct2_tier_a_chain("main");
    let mut forward = ct2_forward_scan_result(&blocks);

    let g = arc.read().await;
    g.ingest_scan_result_into_curve_tree(&mut forward)
        .await
        .expect("genesis-anchored ingest of the full Tier-A main chain");
    assert_eq!(
        g.curve_tree
            .ingested_tip_height()
            .await
            .expect("cursor read"),
        Some(BlockHeight(blocks.last().unwrap().height)),
        "the cursor advanced to the chain tip",
    );

    let mut mismatches = Vec::new();
    for b in &blocks {
        let (got, _depth) = g
            .curve_tree
            .reference_root_and_depth(BlockHeight(b.height))
            .await
            .expect("root read");
        if got != b.root {
            mismatches.push(b.height);
        }
    }
    assert!(
        mismatches.is_empty(),
        "engine ingest root != CT-2 oracle at heights {:?} (first {} shown)",
        &mismatches[..mismatches.len().min(10)],
        mismatches.len().min(10),
    );
}

/// CT-5a commit-6 DoD (reorg): after ingesting `main`, a reorg feed with
/// `reorg_rewind` set drives the engine through `CurveTreeHandle::
/// rollback_to_fork` and a cursor-driven re-ingest of the `reorg_deep`
/// suffix. The reconstructed root then matches the `reorg_deep` oracle at
/// **every** height — the kept shared prefix (proving the rollback kept
/// exactly `fork_height - 1`) and the re-mined suffix alike.
///
/// **Tier-B scope boundary (E6a).** The full DoD also asserts *pending-table
/// equality* post-reorg, not only root equality — class-(b) pending
/// migration (the CT-3c green-positive-for-broken-migration lesson). A
/// coinbase-only fixture cannot create the non-coinbase pending rows that
/// migration touches, so that half inherits the Tier-B non-coinbase fixture
/// dependency and is proven at CT-5c, not here. This KAT proves the
/// engine-path rollback + re-ingest *root* correctness, which the coinbase
/// fixture can express.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_ingest_reorg_matches_ct2_tier_a_oracle_at_every_height() {
    use shekyl_curve_tree::BlockHeight;

    const MASTER_SEED: [u8; 32] = [
        0xa7, 0x5e, 0x14, 0x82, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0,
        0xc0, 0xd0, 0xe0, 0xf0, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0xae,
        0xbf, 0xd1,
    ];
    let daemon_seed = derive_seed(&MASTER_SEED, ROLE_DAEMON);
    let mock = TestDaemon::with_seed_and_chain(daemon_seed, linear_chain(1));
    let (arc, _tmp) = make_hybrid_engine_arc(mock).await;

    let main = ct2_tier_a_chain("main");
    let deep = ct2_tier_a_chain("reorg_deep");
    // `fork` is the last height shared by the two chains (the fork point);
    // heights above it diverge. The merge's `reorg_rewind.fork_height` is
    // the first *divergent* height (`fork + 1`), and it keeps
    // `fork_height - 1 == fork`.
    let fork = ct2_tier_a_u64("main_tip") - ct2_tier_a_u64("deep_pop");
    assert_eq!(
        main[usize::try_from(fork).unwrap()].height,
        fork,
        "fixture indexing: chain[h] is height h",
    );

    let g = arc.read().await;

    // 1. Forward-ingest the full main chain.
    let mut forward_scan = ct2_forward_scan_result(&main);
    g.ingest_scan_result_into_curve_tree(&mut forward_scan)
        .await
        .expect("forward ingest of the main chain");
    assert_eq!(
        g.curve_tree
            .ingested_tip_height()
            .await
            .expect("cursor read"),
        Some(BlockHeight(main.last().unwrap().height)),
        "main forward feed leaves the tree at the main tip",
    );

    // 2. Reorg onto reorg_deep: roll back to keep `fork`, re-ingest the
    //    divergent suffix `fork+1 ..= deep_tip` from the reorg leaves. No
    //    backfill (range start == fork+1 == cursor+1 after rollback).
    let deep_end = deep.last().unwrap().height + 1;
    let mut reorg = ScanResult::empty_at(fork + 1, None);
    reorg.processed_height_range = (fork + 1)..deep_end;
    reorg.reorg_rewind = Some(crate::scan::ReorgRewind {
        fork_height: fork + 1,
    });
    reorg.block_leaves = deep
        .iter()
        .filter(|b| b.height > fork)
        .map(|b| (b.height, b.leaves.clone()))
        .collect();
    reorg.block_curve_tree_roots = deep
        .iter()
        .filter(|b| b.height > fork)
        .map(|b| (b.height, b.root))
        .collect();
    g.ingest_scan_result_into_curve_tree(&mut reorg)
        .await
        .expect("reorg feed rolls back to the fork and re-ingests the deep suffix");
    assert_eq!(
        g.curve_tree
            .ingested_tip_height()
            .await
            .expect("cursor read"),
        Some(BlockHeight(deep.last().unwrap().height)),
        "post-reorg the cursor advanced to the reorg_deep tip",
    );

    // 3. Every height now matches the reorg_deep oracle: the kept prefix
    //    (0..=fork, byte-identical to main's leaves and so to the deep
    //    oracle on the shared prefix) and the re-mined suffix alike.
    let mut mismatches = Vec::new();
    for b in &deep {
        let (got, _depth) = g
            .curve_tree
            .reference_root_and_depth(BlockHeight(b.height))
            .await
            .expect("root read");
        if got != b.root {
            mismatches.push(b.height);
        }
    }
    assert!(
        mismatches.is_empty(),
        "post-reorg engine root != reorg_deep oracle at heights {:?} (first {} shown)",
        &mismatches[..mismatches.len().min(10)],
        mismatches.len().min(10),
    );
}
