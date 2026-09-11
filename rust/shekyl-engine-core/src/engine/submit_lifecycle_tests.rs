// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Driver-integration tests for the submit lifecycle
//! (`engine/submit_lifecycle.rs`).
//!
//! Wired as a `#[path]` child of `submit_lifecycle::tests`, so
//! `use super::*` resolves into the workflow module and private items
//! stay testable; the sibling file exists so the decomposition ratchet
//! counts the workflow file, not its test suite (the
//! `proofs_tests.rs` pattern).

//! Driver-integration tests (`DAEMON_SUBMIT_VERDICT.md` §10 item 8
//! remainder + the §10 item 1 R2 test deferred from PR #254). The
//! kernel's own decision surface is unit-tested in
//! [`submit_watchdog`](super::super::submit_watchdog); these drive the
//! *orchestration* — projection → overlay reconcile → F40 re-scan (R2
//! breaker) → escape ladder → probe → outcome — through
//! [`SubmitLifecycleDriver::tick`] over hermetic stubs.

use super::*;
use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex};

use super::super::traits::FeeEstimates;
use shekyl_rpc_client::{Rpc, RpcError};

/// Block target 120 s → escape horizon 540 blocks. Derived by
/// [`WatchdogConfig::from_block_target`], not hard-coded into the
/// driver; the constant here mirrors the kernel test's `CFG`.
const BLOCK_TARGET_SECS: u64 = 120;
const HORIZON: u64 = 540;

fn txid(seed: u8) -> TxHash {
    TxHash::from_bytes([seed; 32])
}

fn held(seed: u8, baseline: u64) -> HeldSubmit {
    HeldSubmit {
        tx_hash: txid(seed),
        baseline_height: baseline,
        probed_this_epoch: false,
    }
}

fn driver() -> SubmitLifecycleDriver {
    SubmitLifecycleDriver::new(BLOCK_TARGET_SECS)
}

// ----------------------------------------------------------------
// Stub host — an in-memory [`WatchdogHost`]. Records emitted
// diagnostics and released txids; models refresh-observed
// confirmation via [`StubHost::confirm`] (the F14 lock clearing that
// drops a tx from the projection).
// ----------------------------------------------------------------

#[derive(Default)]
struct HostState {
    held: Vec<HeldSubmit>,
    synced: u64,
    block_hashes: HashMap<u64, [u8; 32]>,
    held_bytes: HashMap<TxHash, Vec<u8>>,
    rescan_queue: Vec<RescanRequest>,
    released: HashSet<TxHash>,
    events: Vec<PendingTxDiagnostic>,
}

struct StubHost {
    state: Mutex<HostState>,
}

impl StubHost {
    fn new(synced: u64) -> Self {
        Self {
            state: Mutex::new(HostState {
                synced,
                ..Default::default()
            }),
        }
    }

    fn with_held(self, h: HeldSubmit) -> Self {
        self.state.lock().unwrap().held.push(h);
        self
    }

    fn with_bytes(self, tx: TxHash, bytes: Vec<u8>) -> Self {
        self.state.lock().unwrap().held_bytes.insert(tx, bytes);
        self
    }

    fn with_block_hash(self, height: u64, hash: [u8; 32]) -> Self {
        self.state.lock().unwrap().block_hashes.insert(height, hash);
        self
    }

    fn enqueue_rescan(&self, tx_hash: TxHash, claimed_height: u64) {
        self.state.lock().unwrap().rescan_queue.push(RescanRequest {
            tx_hash,
            claimed_height,
        });
    }

    fn set_synced(&self, height: u64) {
        self.state.lock().unwrap().synced = height;
    }

    /// Model a refresh-observed confirmation: the F14 lock clears, so
    /// the tx leaves the held projection.
    fn confirm(&self, tx: &TxHash) {
        self.state.lock().unwrap().held.retain(|h| &h.tx_hash != tx);
    }

    fn events(&self) -> Vec<PendingTxDiagnostic> {
        self.state.lock().unwrap().events.clone()
    }

    fn released(&self) -> HashSet<TxHash> {
        self.state.lock().unwrap().released.clone()
    }

    fn is_held(&self, tx: &TxHash) -> bool {
        self.state
            .lock()
            .unwrap()
            .held
            .iter()
            .any(|h| &h.tx_hash == tx)
    }

    fn has_bytes(&self, tx: &TxHash) -> bool {
        self.state.lock().unwrap().held_bytes.contains_key(tx)
    }
}

impl WatchdogHost for StubHost {
    fn held_submits(&self) -> Vec<HeldSubmit> {
        self.state.lock().unwrap().held.clone()
    }

    fn synced_height(&self) -> u64 {
        self.state.lock().unwrap().synced
    }

    fn block_hash_at(&self, height: u64) -> Option<[u8; 32]> {
        self.state
            .lock()
            .unwrap()
            .block_hashes
            .get(&height)
            .copied()
    }

    fn held_bytes_for(&self, tx_hash: &TxHash) -> Option<Vec<u8>> {
        self.state.lock().unwrap().held_bytes.get(tx_hash).cloned()
    }

    fn prune_held_bytes(&self, live: &HashSet<TxHash>) {
        self.state
            .lock()
            .unwrap()
            .held_bytes
            .retain(|k, _| live.contains(k));
    }

    fn drain_rescan_queue(&self) -> Vec<RescanRequest> {
        std::mem::take(&mut self.state.lock().unwrap().rescan_queue)
    }

    fn release_awaiting_confirmation(&self, tx_hashes: &HashSet<TxHash>) -> usize {
        let mut s = self.state.lock().unwrap();
        let before = s.held.len();
        s.held.retain(|h| !tx_hashes.contains(&h.tx_hash));
        let released = before - s.held.len();
        for tx in tx_hashes {
            s.released.insert(*tx);
        }
        released
    }

    fn emit(&self, event: PendingTxDiagnostic) {
        self.state.lock().unwrap().events.push(event);
    }
}

// ----------------------------------------------------------------
// Stub daemon — a [`DaemonEngine`] whose only live surfaces are the
// three the driver reaches (`get_health`, `submit_transaction`,
// `get_block_hash`). Everything else panics/unimplemented: reaching
// them is a driver bug, not a test-double gap.
// ----------------------------------------------------------------

struct DaemonState {
    health: DaemonHealth,
    health_fail: bool,
    block_hashes: HashMap<u64, [u8; 32]>,
    block_hash_err: HashSet<u64>,
    submit: VecDeque<Result<TxSubmitOutcome, RpcError>>,
    submit_calls: usize,
}

#[derive(Clone)]
struct StubDaemon {
    state: Arc<Mutex<DaemonState>>,
}

impl StubDaemon {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(DaemonState {
                health: DaemonHealth {
                    connections: 8,
                    height: 10_000,
                    target_height: 0,
                },
                health_fail: false,
                block_hashes: HashMap::new(),
                block_hash_err: HashSet::new(),
                submit: VecDeque::new(),
                submit_calls: 0,
            })),
        }
    }

    fn set_health(&self, health: DaemonHealth) {
        self.state.lock().unwrap().health = health;
    }

    fn fail_health(&self) {
        self.state.lock().unwrap().health_fail = true;
    }

    fn set_block_hash(&self, height: u64, hash: [u8; 32]) {
        self.state.lock().unwrap().block_hashes.insert(height, hash);
    }

    fn push_submit(&self, outcome: Result<TxSubmitOutcome, RpcError>) {
        self.state.lock().unwrap().submit.push_back(outcome);
    }

    fn submit_calls(&self) -> usize {
        self.state.lock().unwrap().submit_calls
    }
}

impl Rpc for StubDaemon {
    fn post(
        &self,
        _route: &str,
        _body: Vec<u8>,
    ) -> impl Send + Future<Output = Result<Vec<u8>, RpcError>> {
        async move {
            panic!(
                "StubDaemon::post is unreachable: the driver calls only get_health / \
                 submit_transaction / get_block_hash"
            )
        }
    }

    fn get_block_hash(
        &self,
        number: usize,
    ) -> impl Send + Future<Output = Result<[u8; 32], RpcError>> {
        let state = self.state.clone();
        async move {
            let s = state.lock().unwrap();
            let h = number as u64;
            if s.block_hash_err.contains(&h) {
                return Err(RpcError::InvalidNode(format!(
                    "StubDaemon: block-hash error at {h}"
                )));
            }
            s.block_hashes
                .get(&h)
                .copied()
                .ok_or_else(|| RpcError::InvalidNode(format!("StubDaemon: no block hash at {h}")))
        }
    }
}

impl DaemonEngine for StubDaemon {
    type Error = RpcError;

    fn get_fee_estimates(&self) -> impl Send + Future<Output = Result<FeeEstimates, Self::Error>> {
        async move { unimplemented!("StubDaemon: the driver never fetches fee estimates") }
    }

    fn submit_transaction(
        &self,
        _tx_bytes: Vec<u8>,
    ) -> impl Send + Future<Output = Result<TxSubmitOutcome, Self::Error>> {
        let state = self.state.clone();
        async move {
            let mut s = state.lock().unwrap();
            s.submit_calls += 1;
            s.submit
                .pop_front()
                .unwrap_or(Ok(TxSubmitOutcome::AlreadyInPool { hash: txid(0) }))
        }
    }

    fn get_health(&self) -> impl Send + Future<Output = Result<DaemonHealth, Self::Error>> {
        let state = self.state.clone();
        async move {
            let s = state.lock().unwrap();
            if s.health_fail {
                return Err(RpcError::InvalidNode(
                    "StubDaemon: health failure".to_string(),
                ));
            }
            Ok(s.health)
        }
    }
}

// ---- assertion helpers ----

fn alarm_reasons(events: &[PendingTxDiagnostic]) -> Vec<WatchdogAlarmReason> {
    events
        .iter()
        .filter_map(|e| match e {
            PendingTxDiagnostic::WatchdogAlarm { reason, .. } => Some(*reason),
            _ => None,
        })
        .collect()
}

fn breaker_trips(events: &[PendingTxDiagnostic]) -> Vec<u32> {
    events
        .iter()
        .filter_map(|e| match e {
            PendingTxDiagnostic::FruitlessRescanBreakerTripped { attempts, .. } => Some(*attempts),
            _ => None,
        })
        .collect()
}

fn probe_dispatched(events: &[PendingTxDiagnostic]) -> usize {
    events
        .iter()
        .position(|e| matches!(e, PendingTxDiagnostic::WatchdogProbeDispatched { .. }))
        .expect("a probe was dispatched")
}

fn first_alarm_index(events: &[PendingTxDiagnostic]) -> usize {
    events
        .iter()
        .position(|e| matches!(e, PendingTxDiagnostic::WatchdogAlarm { .. }))
        .expect("an alarm was raised")
}

// ================================================================
// Escape ladder
// ================================================================

/// §10 item 8 ladder ordering through the driver: a held tx
/// present-past-horizon is *probed first* (the resubmit-same-bytes
/// rung), and only then — on the `AlreadyInPool` verdict (F31: no
/// relay pulse) — escalated to the operator alarm. Rung 3 (rebuild)
/// is unrepresentable: [`WatchdogStep`] cannot express it, so the
/// driver has no path to it by construction.
#[tokio::test]
async fn probe_precedes_alarm_present_past_horizon() {
    let tx = txid(1);
    let host = StubHost::new(1_000 + HORIZON)
        .with_held(held(1, 1_000))
        .with_bytes(tx, vec![0xAB; 8]);
    let daemon = StubDaemon::new();
    daemon.push_submit(Ok(TxSubmitOutcome::AlreadyInPool { hash: tx }));
    let mut d = driver();

    d.tick(&host, &daemon).await;

    assert_eq!(daemon.submit_calls(), 1, "the probe rung ran before alarm");
    let events = host.events();
    assert!(
        probe_dispatched(&events) < first_alarm_index(&events),
        "probe dispatch precedes the alarm"
    );
    assert_eq!(
        alarm_reasons(&events),
        vec![WatchdogAlarmReason::PresentButUnconfirmedPastHorizon]
    );
    assert!(host.is_held(&tx), "present-but-unconfirmed never releases");
    assert!(host.released().is_empty());
}

/// The alarm latch is edge-triggered: a persistently
/// present-past-horizon tx alarms exactly once, and the second tick
/// (kernel goes straight to the alarm rung, `probed_this_epoch` set)
/// neither re-probes nor re-alarms — the §5.3 alarm-fatigue bound.
#[tokio::test]
async fn alarm_is_edge_triggered_and_probe_not_repeated() {
    let tx = txid(1);
    let host = StubHost::new(1_000 + HORIZON)
        .with_held(held(1, 1_000))
        .with_bytes(tx, vec![0xAB; 8]);
    let daemon = StubDaemon::new();
    daemon.push_submit(Ok(TxSubmitOutcome::AlreadyInPool { hash: tx }));
    daemon.push_submit(Ok(TxSubmitOutcome::AlreadyInPool { hash: tx }));
    let mut d = driver();

    d.tick(&host, &daemon).await;
    d.tick(&host, &daemon).await;

    assert_eq!(daemon.submit_calls(), 1, "F31: no second resubmit");
    assert_eq!(
        alarm_reasons(&host.events()).len(),
        1,
        "the alarm fires once, not once per tick"
    );
}

/// Presence branching — absent leg: the probe returns `Submitted`
/// (the tx was evicted / never landed, the resubmit *is* the remedy),
/// so the wait restarts from the probe height. No alarm; a follow-up
/// tick at the same height is inside the fresh horizon and does not
/// re-probe.
#[tokio::test]
async fn absent_reoffer_restarts_the_wait() {
    let tx = txid(1);
    let host = StubHost::new(1_000 + HORIZON)
        .with_held(held(1, 1_000))
        .with_bytes(tx, vec![0xAB; 8]);
    let daemon = StubDaemon::new();
    daemon.push_submit(Ok(TxSubmitOutcome::Submitted { hash: tx }));
    let mut d = driver();

    d.tick(&host, &daemon).await;
    assert_eq!(daemon.submit_calls(), 1);
    assert!(
        alarm_reasons(&host.events()).is_empty(),
        "a re-offer is a remedy, not an alarm"
    );

    // Second tick: baseline advanced to the probe height, so we are
    // back inside the horizon → wait, no second probe.
    d.tick(&host, &daemon).await;
    assert_eq!(
        daemon.submit_calls(),
        1,
        "the restarted wait suppresses re-probe"
    );
    assert!(alarm_reasons(&host.events()).is_empty());
}

/// §2.6 confirmed-absent release: a definite terminal verdict on the
/// probe proves the bytes are in neither pool nor chain (single
/// egress, §7.1), so the F14 locks are released — outputs selectable
/// again — with **no** alarm and **no** rebuild.
#[tokio::test]
async fn terminal_probe_releases_confirmed_absent() {
    let tx = txid(1);
    let host = StubHost::new(1_000 + HORIZON)
        .with_held(held(1, 1_000))
        .with_bytes(tx, vec![0xAB; 8]);
    let daemon = StubDaemon::new();
    daemon.push_submit(Ok(TxSubmitOutcome::Rejected {
        cause: RejectCause::DoubleSpendConflict,
    }));
    let mut d = driver();

    d.tick(&host, &daemon).await;

    assert!(host.released().contains(&tx), "locks released");
    assert!(!host.is_held(&tx), "tx left the held projection");
    assert!(
        alarm_reasons(&host.events()).is_empty(),
        "release is not an alarm"
    );
}

/// Restart degradation (§5.3 decision 2): after a restart the
/// ephemeral held-bytes are gone, so the rung-1 probe cannot run. The
/// kernel still calls for it (past horizon), and the driver degrades
/// the probe rung to the operator-alarm rung — the lock stays placed,
/// nothing is released, and the daemon is never contacted for a
/// submit.
#[tokio::test]
async fn missing_bytes_degrade_probe_to_alarm() {
    let tx = txid(1);
    // No `with_bytes` → held-bytes absent (restart crossed the await).
    let host = StubHost::new(1_000 + HORIZON).with_held(held(1, 1_000));
    let daemon = StubDaemon::new();
    let mut d = driver();

    d.tick(&host, &daemon).await;

    assert_eq!(daemon.submit_calls(), 0, "no bytes → no resubmit");
    assert_eq!(
        alarm_reasons(&host.events()),
        vec![WatchdogAlarmReason::ProbeBytesUnavailable]
    );
    assert!(host.is_held(&tx), "the lock is retained");
    assert!(host.released().is_empty());
}

/// A retryable probe rejection (stale reference) is a driver-level
/// condition the kernel cannot represent: the bytes are neither
/// admitted nor terminally dead, and recovery needs a fresh reference
/// (a human-authorized rebuild, §7.1). The driver alarms directly and
/// keeps the lock.
#[tokio::test]
async fn retryable_rejection_alarms_needs_rebuild() {
    let tx = txid(1);
    let host = StubHost::new(1_000 + HORIZON)
        .with_held(held(1, 1_000))
        .with_bytes(tx, vec![0xAB; 8]);
    let daemon = StubDaemon::new();
    daemon.push_submit(Ok(TxSubmitOutcome::Rejected {
        cause: RejectCause::StaleRoot,
    }));
    let mut d = driver();

    d.tick(&host, &daemon).await;

    assert_eq!(
        alarm_reasons(&host.events()),
        vec![WatchdogAlarmReason::ReferenceStaleNeedsRebuild]
    );
    assert!(host.is_held(&tx), "no release on a retryable rejection");
    assert!(host.released().is_empty());
}

/// §5.2 item 3 health gating: a peerless daemon (relay impossible, no
/// wallet action can help) goes straight to the operator-alarm rung
/// without spending a probe.
#[tokio::test]
async fn peerless_daemon_alarms_without_probing() {
    let host = StubHost::new(1_000 + HORIZON)
        .with_held(held(1, 1_000))
        .with_bytes(txid(1), vec![0xAB; 8]);
    let daemon = StubDaemon::new();
    daemon.set_health(DaemonHealth {
        connections: 0,
        height: 10_000,
        target_height: 0,
    });
    let mut d = driver();

    d.tick(&host, &daemon).await;

    assert_eq!(
        daemon.submit_calls(),
        0,
        "no probe when relay is impossible"
    );
    assert_eq!(
        alarm_reasons(&host.events()),
        vec![WatchdogAlarmReason::DaemonPeerless]
    );
}

/// Health gating: a daemon behind the network sync-gates the ladder —
/// "unconfirmed at this daemon" is uninformative until it syncs — so
/// the driver waits, never probing or alarming.
#[tokio::test]
async fn syncing_daemon_waits() {
    let host = StubHost::new(1_000 + HORIZON)
        .with_held(held(1, 1_000))
        .with_bytes(txid(1), vec![0xAB; 8]);
    let daemon = StubDaemon::new();
    daemon.set_health(DaemonHealth {
        connections: 8,
        height: 5_000,
        target_height: 6_000,
    });
    let mut d = driver();

    d.tick(&host, &daemon).await;

    assert_eq!(daemon.submit_calls(), 0);
    assert!(
        host.events().is_empty(),
        "syncing → wait, no observable action"
    );
}

/// A failed health round-trip is not a verdict (§7.2): without health
/// facts the ladder cannot separate "tx stuck" from "daemon behind /
/// peerless", so the driver makes no decision this tick.
#[tokio::test]
async fn health_failure_makes_no_decision() {
    let host = StubHost::new(1_000 + HORIZON)
        .with_held(held(1, 1_000))
        .with_bytes(txid(1), vec![0xAB; 8]);
    let daemon = StubDaemon::new();
    daemon.fail_health();
    let mut d = driver();

    d.tick(&host, &daemon).await;

    assert_eq!(daemon.submit_calls(), 0);
    assert!(host.events().is_empty());
    assert!(host.is_held(&txid(1)));
}

/// Held-bytes pruning: retained probe bytes survive while the tx is
/// held and are dropped once refresh confirms it (the tx leaves the
/// projection). The prune tracks the live set, not the probe path.
#[tokio::test]
async fn held_bytes_pruned_on_confirmation() {
    let tx = txid(1);
    // Baseline == synced → inside the horizon → the ladder waits, so
    // this exercises pruning in isolation from the probe.
    let host = StubHost::new(5_000)
        .with_held(held(1, 5_000))
        .with_bytes(tx, vec![0xAB; 8]);
    let daemon = StubDaemon::new();
    let mut d = driver();

    d.tick(&host, &daemon).await;
    assert!(host.has_bytes(&tx), "bytes retained while held");

    // Refresh confirms the tx: the F14 lock clears, the tx leaves the
    // projection, and the next tick prunes its bytes.
    host.confirm(&tx);
    d.tick(&host, &daemon).await;
    assert!(!host.has_bytes(&tx), "bytes pruned once the tx confirms");
    assert!(!host.is_held(&tx));
}

// ================================================================
// F40 targeted re-scan + R2 breaker
// ================================================================

/// §10 item 1 R2 test (deferred from PR #254): N consecutive
/// fruitless targeted re-scans — the daemon claims confirmation at an
/// already-scanned height whose block matches ours but lacks the
/// spend — trip the breaker exactly once, and the F14 lock is
/// **never** released (F40-R1 is structural; the operator adjudicates
/// the lying daemon).
#[tokio::test]
async fn r2_breaker_trips_after_threshold_never_releases() {
    let tx = txid(1);
    let claimed = 4_000;
    let block = [0xAA; 32];
    // Baseline == synced → the escape ladder waits (isolates R2).
    let host = StubHost::new(5_000)
        .with_held(held(1, 5_000))
        .with_block_hash(claimed, block);
    let daemon = StubDaemon::new();
    daemon.set_block_hash(claimed, block); // matches → fruitless each tick
    host.enqueue_rescan(tx, claimed);
    let mut d = driver();

    // Four ticks: fruitless at 1, 2, 3 (trip), 4 (latched, no re-emit).
    for _ in 0..4 {
        d.tick(&host, &daemon).await;
    }

    assert_eq!(
        breaker_trips(&host.events()),
        vec![FRUITLESS_RESCAN_BREAKER_THRESHOLD],
        "the breaker trips once, at the threshold, and does not re-emit"
    );
    assert!(
        host.released().is_empty(),
        "F40-R1: the lock is never released"
    );
    assert!(
        host.is_held(&tx),
        "the tx stays held for operator adjudication"
    );
    assert!(
        alarm_reasons(&host.events()).is_empty(),
        "the breaker is its own signal, distinct from the watchdog alarm"
    );
}

/// A divergent hash at the claimed height (a reorg replaced the block)
/// is genuine chain divergence, not a lying daemon: it is **not**
/// counted against R2 (deferred to refresh reorg-heal) and never
/// releases. The breaker never trips no matter how many ticks run.
#[tokio::test]
async fn divergent_hash_never_counts_or_releases() {
    let tx = txid(1);
    let claimed = 4_000;
    let host = StubHost::new(5_000)
        .with_held(held(1, 5_000))
        .with_block_hash(claimed, [0xAA; 32]);
    let daemon = StubDaemon::new();
    daemon.set_block_hash(claimed, [0xBB; 32]); // differs → divergence
    host.enqueue_rescan(tx, claimed);
    let mut d = driver();

    for _ in 0..5 {
        d.tick(&host, &daemon).await;
    }

    assert!(
        breaker_trips(&host.events()).is_empty(),
        "divergence is not fruitless: R2 counter untouched"
    );
    assert!(host.released().is_empty());
    assert!(host.is_held(&tx));
}

/// Fruitless-soundness guard (decision 1 refinement): a rescan request
/// whose claimed height is **above** the current synced height is not
/// yet scanned — "spend unobserved" there is refresh lag, not absence.
/// It is never classified fruitless (re-routed to the §2.6 path-1
/// wait), even when the block hash would match. Once the wallet syncs
/// past the claimed height, the preserved target becomes countable and
/// the breaker trips — proving the guard delayed, not discarded.
#[tokio::test]
async fn above_synced_never_fruitless_until_scanned() {
    let tx = txid(1);
    let claimed = 6_000;
    let block = [0xAA; 32];
    // Baseline high enough that the escape ladder waits at both synced
    // heights used below (isolates the guard from the ladder).
    let host = StubHost::new(5_000)
        .with_held(held(1, 6_000))
        .with_block_hash(claimed, block);
    let daemon = StubDaemon::new();
    daemon.set_block_hash(claimed, block); // would be fruitless IF checked
    host.enqueue_rescan(tx, claimed);
    let mut d = driver();

    // claimed (6000) > synced (5000): the guard skips the count every
    // tick. Well past the threshold — no trip, because nothing counts.
    for _ in 0..5 {
        d.tick(&host, &daemon).await;
    }
    assert!(
        breaker_trips(&host.events()).is_empty(),
        "above-synced request is never classified fruitless"
    );

    // The wallet syncs past the claimed height: the preserved target
    // is now at an already-scanned height and counts. Three ticks trip.
    host.set_synced(6_000);
    for _ in 0..FRUITLESS_RESCAN_BREAKER_THRESHOLD {
        d.tick(&host, &daemon).await;
    }
    assert_eq!(
        breaker_trips(&host.events()),
        vec![FRUITLESS_RESCAN_BREAKER_THRESHOLD],
        "the guard delayed the count; the target was preserved, not discarded"
    );
    assert!(host.released().is_empty());
}

/// A missing ledger hash at the claimed height (outside the retained
/// range) makes the cheap hash-compare impossible, so the fruitless
/// inference cannot be drawn soundly: the tick defers, the counter is
/// untouched, and the breaker never trips.
#[tokio::test]
async fn missing_ledger_hash_defers_without_counting() {
    let tx = txid(1);
    let claimed = 4_000;
    // No `with_block_hash` on the host → ledger hash absent.
    let host = StubHost::new(5_000).with_held(held(1, 5_000));
    let daemon = StubDaemon::new();
    daemon.set_block_hash(claimed, [0xAA; 32]);
    host.enqueue_rescan(tx, claimed);
    let mut d = driver();

    for _ in 0..5 {
        d.tick(&host, &daemon).await;
    }

    assert!(breaker_trips(&host.events()).is_empty());
    assert!(host.released().is_empty());
    assert!(host.is_held(&tx));
}

/// The R2 breaker's success path: a targeted-re-scan target whose tx
/// confirms (leaves the projection via refresh) is reaped, so a later
/// spurious `AlreadyInChain` claim for the same txid starts a fresh
/// consecutive-fruitless streak rather than inheriting the old count.
#[tokio::test]
async fn confirmation_reaps_the_rescan_target() {
    let tx = txid(1);
    let claimed = 4_000;
    let block = [0xAA; 32];
    let host = StubHost::new(5_000)
        .with_held(held(1, 5_000))
        .with_block_hash(claimed, block);
    let daemon = StubDaemon::new();
    daemon.set_block_hash(claimed, block);
    host.enqueue_rescan(tx, claimed);
    let mut d = driver();

    // Two fruitless ticks (streak = 2, below threshold).
    d.tick(&host, &daemon).await;
    d.tick(&host, &daemon).await;
    assert!(breaker_trips(&host.events()).is_empty());

    // Refresh confirms the tx: the target is reaped on projection-exit.
    host.confirm(&tx);
    d.tick(&host, &daemon).await;
    assert!(!host.is_held(&tx));
    assert!(
        breaker_trips(&host.events()).is_empty(),
        "no trip after reap"
    );
}
