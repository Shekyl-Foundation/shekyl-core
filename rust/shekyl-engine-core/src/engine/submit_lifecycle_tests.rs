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
use crate::engine::dispatch_durability::NoSaveCommit;
use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex};

use super::super::submit_watchdog::{RelaySight, PROBE_CEILING_BLOCKS};
use super::super::traits::FeeEstimates;
use shekyl_rpc_client::Publication;
use shekyl_rpc_client::{Rpc, RpcError};

/// The production block ceiling the driver runs at
/// ([`PROBE_CEILING_BLOCKS`]), read rather than re-typed.
const CEILING: u64 = PROBE_CEILING_BLOCKS;

fn txid(seed: u8) -> TxHash {
    TxHash::from_bytes([seed; 32])
}

fn held(seed: u8, baseline: u64) -> HeldSubmit {
    HeldSubmit {
        tx_hash: txid(seed),
        baseline_height: baseline,
        relay: RelaySight::Unread,
    }
}

fn driver() -> SubmitLifecycleDriver {
    SubmitLifecycleDriver::new()
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
    block_hashes: HashMap<u64, shekyl_types::BlockHash>,
    held_bytes: HashMap<TxHash, Vec<u8>>,
    rescan_queue: Vec<RescanRequest>,
    released: HashSet<TxHash>,
    events: Vec<PendingTxDiagnostic>,
    /// Sends dispatched before this session (A19): the probe rung on
    /// these is the operator alarm, never an automatic resend.
    earlier: HashSet<TxHash>,
    /// The host-side alarm latch.
    alarms: HashMap<TxHash, WatchdogAlarmReason>,
    /// Sends refresh has settled: their journal rows drop their bytes at
    /// the next prune (the state-driven rule).
    settled: HashSet<TxHash>,
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
        self.state
            .lock()
            .unwrap()
            .block_hashes
            .insert(height, shekyl_types::BlockHash::from_bytes(hash));
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
        let mut s = self.state.lock().unwrap();
        s.held.retain(|h| &h.tx_hash != tx);
        s.settled.insert(*tx);
    }

    /// Mark `tx` as dispatched before this session (a restart crossed
    /// its verdict).
    fn dispatched_earlier(self, tx: TxHash) -> Self {
        self.state.lock().unwrap().earlier.insert(tx);
        self
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

    fn synced_height(&self) -> BlockHeight {
        BlockHeight::from_raw(self.state.lock().unwrap().synced)
    }

    fn block_hash_at(&self, height: BlockHeight) -> Option<shekyl_types::BlockHash> {
        self.state
            .lock()
            .unwrap()
            .block_hashes
            .get(&height.to_raw())
            .copied()
    }

    fn held_bytes_for(&self, tx_hash: &TxHash) -> Option<Vec<u8>> {
        self.state.lock().unwrap().held_bytes.get(tx_hash).cloned()
    }

    fn prune_settled_send_bytes(&self) {
        let mut s = self.state.lock().unwrap();
        let settled = s.settled.clone();
        s.held_bytes.retain(|k, _| !settled.contains(k));
    }

    fn dispatched_this_session(&self, tx_hash: &TxHash) -> bool {
        !self.state.lock().unwrap().earlier.contains(tx_hash)
    }

    fn latch_alarm(&self, tx_hash: TxHash, reason: WatchdogAlarmReason) -> bool {
        match self.state.lock().unwrap().alarms.entry(tx_hash) {
            std::collections::hash_map::Entry::Occupied(_) => false,
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(reason);
                true
            }
        }
    }

    fn release_alarms(&self, live: &HashSet<TxHash>) {
        self.state
            .lock()
            .unwrap()
            .alarms
            .retain(|tx, _| live.contains(tx));
    }

    fn clear_alarm(&self, tx_hash: &TxHash) {
        self.state.lock().unwrap().alarms.remove(tx_hash);
    }

    fn alarm_for(&self, tx_hash: &TxHash) -> Option<WatchdogAlarmReason> {
        self.state.lock().unwrap().alarms.get(tx_hash).copied()
    }

    fn sent_height(&self, tx_hash: &TxHash) -> Option<BlockHeight> {
        self.state
            .lock()
            .unwrap()
            .held
            .iter()
            .find(|h| &h.tx_hash == tx_hash)
            .map(|h| BlockHeight::from_raw(h.baseline_height))
    }

    fn adopt_into_session(&self, tx_hash: TxHash) {
        let mut s = self.state.lock().unwrap();
        s.earlier.remove(&tx_hash);
        s.alarms.remove(&tx_hash);
    }

    fn drain_rescan_queue(&self) -> Vec<RescanRequest> {
        std::mem::take(&mut self.state.lock().unwrap().rescan_queue)
    }

    fn release_awaiting_confirmation(
        &self,
        tx_hashes: &HashSet<TxHash>,
        _commit: &dyn LedgerCommit,
    ) -> usize {
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
    block_hashes: HashMap<u64, shekyl_types::BlockHash>,
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
                    p2p: crate::engine::traits::daemon::DaemonP2p::Running { has_peers: true },
                    height: 10_000,
                    synchronized: true,
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
        self.state
            .lock()
            .unwrap()
            .block_hashes
            .insert(height, shekyl_types::BlockHash::from_bytes(hash));
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
    ) -> impl Send + Future<Output = Result<shekyl_types::BlockHash, RpcError>> {
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
                .unwrap_or(Ok(TxSubmitOutcome::AlreadyInPool {
                    hash: txid(0),
                    relay: Publication::Held,
                }))
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

/// Below the proof-life ceiling the driver still probes first. A
/// `held_overdue` answer then alarms. Rung 3 (rebuild) is
/// unrepresentable: [`WatchdogStep`] cannot express it, so the driver
/// has no path to it.
#[tokio::test]
async fn probe_precedes_the_held_overdue_alarm() {
    let tx = txid(1);
    let host = StubHost::new(1_000)
        .with_held(held(1, 1_000))
        .with_bytes(tx, vec![0xAB; 8]);
    let daemon = StubDaemon::new();
    daemon.push_submit(Ok(TxSubmitOutcome::AlreadyInPool {
        hash: tx,
        relay: Publication::Overdue,
    }));
    let mut d = driver();

    d.tick(&host, &daemon, &NoSaveCommit).await;

    assert_eq!(daemon.submit_calls(), 1, "the probe rung ran before alarm");
    let events = host.events();
    assert!(
        probe_dispatched(&events) < first_alarm_index(&events),
        "probe dispatch precedes the alarm"
    );
    assert_eq!(
        alarm_reasons(&events),
        vec![WatchdogAlarmReason::HeldOverdue]
    );
    assert!(host.is_held(&tx), "held-overdue never releases");
    assert!(host.released().is_empty());
}

/// The alarm latch is edge-triggered. Once the daemon has judged the
/// origin overdue, the next tick returns that alarm before probing
/// again, and the latch emits the alarm once.
#[tokio::test]
async fn held_overdue_alarms_once_and_does_not_probe_again() {
    let tx = txid(1);
    let host = StubHost::new(1_000)
        .with_held(held(1, 1_000))
        .with_bytes(tx, vec![0xAB; 8]);
    let daemon = StubDaemon::new();
    daemon.push_submit(Ok(TxSubmitOutcome::AlreadyInPool {
        hash: tx,
        relay: Publication::Overdue,
    }));
    daemon.push_submit(Ok(TxSubmitOutcome::AlreadyInPool {
        hash: tx,
        relay: Publication::Overdue,
    }));
    let mut d = driver();

    d.tick(&host, &daemon, &NoSaveCommit).await;
    d.tick(&host, &daemon, &NoSaveCommit).await;

    assert_eq!(
        daemon.submit_calls(),
        1,
        "overdue is already judged; the next tick does not probe"
    );
    assert_eq!(
        alarm_reasons(&host.events()).len(),
        1,
        "the alarm fires once, not once per tick"
    );
}

/// Presence branching — absent leg: the probe returns `Submitted`
/// (the tx was evicted / never landed, the resubmit *is* the remedy)
/// and records a fresh hold. No alarm. The next chain advance asks
/// again, because a hold is a status read, and that answer does not
/// alarm either.
#[tokio::test]
async fn absent_reoffer_is_held_and_asked_again() {
    let tx = txid(1);
    let host = StubHost::new(1_000)
        .with_held(held(1, 1_000))
        .with_bytes(tx, vec![0xAB; 8]);
    let daemon = StubDaemon::new();
    daemon.push_submit(Ok(TxSubmitOutcome::Submitted { hash: tx }));
    daemon.push_submit(Ok(TxSubmitOutcome::AlreadyInPool {
        hash: tx,
        relay: Publication::Held,
    }));
    let mut d = driver();

    d.tick(&host, &daemon, &NoSaveCommit).await;
    assert_eq!(daemon.submit_calls(), 1);
    assert!(
        alarm_reasons(&host.events()).is_empty(),
        "a re-offer is a remedy, not an alarm"
    );

    d.tick(&host, &daemon, &NoSaveCommit).await;
    assert_eq!(
        daemon.submit_calls(),
        2,
        "a fresh hold is asked again on the next chain advance"
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
    let host = StubHost::new(1_000 + CEILING)
        .with_held(held(1, 1_000))
        .with_bytes(tx, vec![0xAB; 8]);
    let daemon = StubDaemon::new();
    daemon.push_submit(Ok(TxSubmitOutcome::Rejected {
        cause: Rejection::DoubleSpendConflict,
    }));
    let mut d = driver();

    d.tick(&host, &daemon, &NoSaveCommit).await;

    assert!(host.released().contains(&tx), "locks released");
    assert!(!host.is_held(&tx), "tx left the held projection");
    assert!(
        alarm_reasons(&host.events()).is_empty(),
        "release is not an alarm"
    );
}

/// A held send whose record holds no bytes cannot be probed: the kernel
/// still calls for the probe (past horizon), and the driver raises the
/// operator alarm instead — the lock stays placed, nothing is released,
/// and the daemon is never contacted for a submit.
#[tokio::test]
async fn missing_bytes_degrade_probe_to_alarm() {
    let tx = txid(1);
    // No `with_bytes`: the record holds none.
    let host = StubHost::new(1_000 + CEILING).with_held(held(1, 1_000));
    let daemon = StubDaemon::new();
    let mut d = driver();

    d.tick(&host, &daemon, &NoSaveCommit).await;

    assert_eq!(daemon.submit_calls(), 0, "no bytes → no resubmit");
    assert_eq!(
        alarm_reasons(&host.events()),
        vec![WatchdogAlarmReason::HeldBytesMissing]
    );
    assert!(host.is_held(&tx), "the lock is retained");
    assert!(host.released().is_empty());
}

/// A19: after a restart the bytes are saved, but resending them is the
/// user's decision. A held send dispatched before this session, with its
/// bytes, raises the operator alarm where the probe would run; the daemon
/// is never offered the bytes and nothing is released or pruned.
#[tokio::test]
async fn a_send_from_an_earlier_session_alarms_instead_of_resending() {
    let tx = txid(1);
    let host = StubHost::new(1_000 + CEILING)
        .with_held(held(1, 1_000))
        .with_bytes(tx, vec![0xAB; 8])
        .dispatched_earlier(tx);
    let daemon = StubDaemon::new();
    let mut d = driver();

    d.tick(&host, &daemon, &NoSaveCommit).await;

    assert_eq!(
        daemon.submit_calls(),
        0,
        "no automatic resend after a restart"
    );
    assert_eq!(
        alarm_reasons(&host.events()),
        vec![WatchdogAlarmReason::DispatchedBeforeThisSession]
    );
    assert_eq!(
        host.alarm_for(&tx),
        Some(WatchdogAlarmReason::DispatchedBeforeThisSession),
        "the alarm is latched where the held-sends read sees it"
    );
    assert!(host.is_held(&tx), "the lock is retained");
    assert!(
        host.has_bytes(&tx),
        "the bytes are kept for the user's resend"
    );
    assert!(host.released().is_empty());

    // Edge-triggered: a second tick does not alarm again.
    d.tick(&host, &daemon, &NoSaveCommit).await;
    assert_eq!(alarm_reasons(&host.events()).len(), 1);
    assert_eq!(daemon.submit_calls(), 0);
}

/// The user's resend adopts the send into this session: the alarm clears
/// and the watchdog's automatic rung 1 applies to it again.
#[tokio::test]
async fn a_resend_returns_the_send_to_the_automatic_rung() {
    let tx = txid(1);
    let host = StubHost::new(1_000 + CEILING)
        .with_held(held(1, 1_000))
        .with_bytes(tx, vec![0xAB; 8])
        .dispatched_earlier(tx);
    let daemon = StubDaemon::new();
    let mut d = driver();

    d.tick(&host, &daemon, &NoSaveCommit).await;
    assert_eq!(daemon.submit_calls(), 0);

    host.adopt_into_session(tx);
    assert_eq!(host.alarm_for(&tx), None, "the resend clears the alarm");
    d.tick(&host, &daemon, &NoSaveCommit).await;
    assert_eq!(daemon.submit_calls(), 1, "rung 1 runs for an adopted send");
}

/// A retryable probe rejection (stale reference) is a driver-level
/// condition the kernel cannot represent: the bytes are neither
/// admitted nor terminally dead, and recovery needs a fresh reference
/// (a human-authorized rebuild, §7.1). The driver alarms directly and
/// keeps the lock.
#[tokio::test]
async fn retryable_rejection_alarms_needs_rebuild() {
    let tx = txid(1);
    let host = StubHost::new(1_000 + CEILING)
        .with_held(held(1, 1_000))
        .with_bytes(tx, vec![0xAB; 8]);
    let daemon = StubDaemon::new();
    daemon.push_submit(Ok(TxSubmitOutcome::Rejected {
        cause: Rejection::StaleRoot,
    }));
    let mut d = driver();

    d.tick(&host, &daemon, &NoSaveCommit).await;

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
    let host = StubHost::new(1_000 + CEILING)
        .with_held(held(1, 1_000))
        .with_bytes(txid(1), vec![0xAB; 8]);
    let daemon = StubDaemon::new();
    daemon.set_health(DaemonHealth {
        p2p: crate::engine::traits::daemon::DaemonP2p::Running { has_peers: false },
        height: 10_000,
        synchronized: true,
    });
    let mut d = driver();

    d.tick(&host, &daemon, &NoSaveCommit).await;

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

/// A status probe is a local relay fact. It runs while the daemon says
/// it has not caught up. The default held answer does not alarm.
#[tokio::test]
async fn syncing_daemon_still_probes() {
    let tx = txid(1);
    let host = StubHost::new(1_000)
        .with_held(held(1, 1_000))
        .with_bytes(tx, vec![0xAB; 8]);
    let daemon = StubDaemon::new();
    daemon.set_health(DaemonHealth {
        p2p: crate::engine::traits::daemon::DaemonP2p::Running { has_peers: true },
        height: 5_000,
        synchronized: false,
    });
    daemon.push_submit(Ok(TxSubmitOutcome::AlreadyInPool {
        hash: tx,
        relay: Publication::Held,
    }));
    let mut d = driver();

    d.tick(&host, &daemon, &NoSaveCommit).await;

    assert_eq!(
        daemon.submit_calls(),
        1,
        "sync does not gate a status probe"
    );
    assert!(
        alarm_reasons(&host.events()).is_empty(),
        "held while syncing is not an alarm"
    );
}

/// A failed health round-trip is not a verdict (§7.2): without health
/// facts the ladder cannot separate "tx stuck" from "daemon behind /
/// peerless", so the driver makes no decision this tick.
#[tokio::test]
async fn health_failure_makes_no_decision() {
    let host = StubHost::new(1_000 + CEILING)
        .with_held(held(1, 1_000))
        .with_bytes(txid(1), vec![0xAB; 8]);
    let daemon = StubDaemon::new();
    daemon.fail_health();
    let mut d = driver();

    d.tick(&host, &daemon, &NoSaveCommit).await;

    assert_eq!(daemon.submit_calls(), 0);
    assert!(host.events().is_empty());
    assert!(host.is_held(&txid(1)));
}

/// Saved-bytes pruning: the probe bytes survive while the tx is held and
/// are dropped once refresh settles it. The driver asks the host to prune
/// each tick; the host's rule reads the row's state (here: settled by
/// `confirm`), never membership of the projection.
#[tokio::test]
async fn held_bytes_pruned_on_confirmation() {
    let tx = txid(1);
    // The status probe returns held, which does not alarm and does not
    // release the bytes. Pruning follows the row's state.
    let host = StubHost::new(5_000)
        .with_held(held(1, 5_000))
        .with_bytes(tx, vec![0xAB; 8]);
    let daemon = StubDaemon::new();
    let mut d = driver();

    d.tick(&host, &daemon, &NoSaveCommit).await;
    assert!(host.has_bytes(&tx), "bytes retained while held");

    // Refresh confirms the tx: the F14 lock clears, the tx leaves the
    // projection, and the next tick prunes its bytes.
    host.confirm(&tx);
    d.tick(&host, &daemon, &NoSaveCommit).await;
    assert!(!host.has_bytes(&tx), "bytes pruned once the tx confirms");
    assert!(!host.is_held(&tx));
}

fn lookback() -> u64 {
    shekyl_economics::relay_policy().lookback
}

/// The published-unmined lookback runs from the first observation of
/// publication, not from the accept baseline. The tick that crosses it
/// already knows the sight, so it does not submit again.
#[tokio::test]
async fn published_lookback_runs_from_the_first_observation() {
    let tx = txid(1);
    let observed = 1_030;
    let host = StubHost::new(observed)
        .with_held(held(1, 0))
        .with_bytes(tx, vec![0xAB; 8]);
    let daemon = StubDaemon::new();
    daemon.push_submit(Ok(TxSubmitOutcome::AlreadyInPool {
        hash: tx,
        relay: Publication::Public,
    }));
    let mut d = driver();

    d.tick(&host, &daemon, &NoSaveCommit).await;
    assert_eq!(daemon.submit_calls(), 1);
    assert!(
        alarm_reasons(&host.events()).is_empty(),
        "the first observation is age zero, whatever the accept baseline"
    );

    host.set_synced(observed + lookback() - 1);
    daemon.push_submit(Ok(TxSubmitOutcome::AlreadyInPool {
        hash: tx,
        relay: Publication::Public,
    }));
    d.tick(&host, &daemon, &NoSaveCommit).await;
    assert_eq!(daemon.submit_calls(), 2);
    assert!(alarm_reasons(&host.events()).is_empty());

    host.set_synced(observed + lookback());
    d.tick(&host, &daemon, &NoSaveCommit).await;
    assert_eq!(
        daemon.submit_calls(),
        2,
        "the crossing tick judges the sight it already holds"
    );
    assert_eq!(
        alarm_reasons(&host.events()),
        vec![WatchdogAlarmReason::PublishedUnmined]
    );
}

/// Sync gates the published-unmined alarm and nothing else on that arm.
/// The crossing tick does not probe while the daemon is behind, and it
/// alarms once the daemon is synchronized.
#[tokio::test]
async fn published_unmined_waits_while_unsynced() {
    let tx = txid(1);
    let observed = 1_030;
    let host = StubHost::new(observed)
        .with_held(held(1, 0))
        .with_bytes(tx, vec![0xAB; 8]);
    let daemon = StubDaemon::new();
    daemon.push_submit(Ok(TxSubmitOutcome::AlreadyInPool {
        hash: tx,
        relay: Publication::Public,
    }));
    let mut d = driver();
    d.tick(&host, &daemon, &NoSaveCommit).await;
    assert!(alarm_reasons(&host.events()).is_empty());

    host.set_synced(observed + lookback());
    daemon.set_health(DaemonHealth {
        p2p: crate::engine::traits::daemon::DaemonP2p::Running { has_peers: true },
        height: 5_000,
        synchronized: false,
    });
    d.tick(&host, &daemon, &NoSaveCommit).await;
    assert_eq!(
        daemon.submit_calls(),
        1,
        "unsynced does not probe at the lookback"
    );
    assert!(alarm_reasons(&host.events()).is_empty());

    daemon.set_health(DaemonHealth {
        p2p: crate::engine::traits::daemon::DaemonP2p::Running { has_peers: true },
        height: 10_000,
        synchronized: true,
    });
    d.tick(&host, &daemon, &NoSaveCommit).await;
    assert_eq!(daemon.submit_calls(), 1);
    assert_eq!(
        alarm_reasons(&host.events()),
        vec![WatchdogAlarmReason::PublishedUnmined]
    );
}

/// In chain waits until the proof-life ceiling, then asks again.
#[tokio::test]
async fn in_chain_waits_until_the_proof_life_ceiling() {
    let tx = txid(1);
    let observed = 1_000;
    let host = StubHost::new(observed)
        .with_held(held(1, 0))
        .with_bytes(tx, vec![0xAB; 8]);
    let daemon = StubDaemon::new();
    daemon.push_submit(Ok(TxSubmitOutcome::AlreadyInChain {
        hash: tx,
        height: observed,
    }));
    let mut d = driver();

    d.tick(&host, &daemon, &NoSaveCommit).await;
    assert_eq!(daemon.submit_calls(), 1);
    assert!(alarm_reasons(&host.events()).is_empty());

    d.tick(&host, &daemon, &NoSaveCommit).await;
    assert_eq!(
        daemon.submit_calls(),
        1,
        "the same height does not ask again"
    );

    host.set_synced(observed + CEILING - 1);
    d.tick(&host, &daemon, &NoSaveCommit).await;
    assert_eq!(daemon.submit_calls(), 1);

    host.set_synced(observed + CEILING);
    daemon.push_submit(Ok(TxSubmitOutcome::AlreadyInChain {
        hash: tx,
        height: observed + CEILING,
    }));
    d.tick(&host, &daemon, &NoSaveCommit).await;
    assert_eq!(daemon.submit_calls(), 2, "the ceiling asks again");
    assert!(alarm_reasons(&host.events()).is_empty());
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
    // The status probe returns held and does not alarm, so the breaker
    // stays the only signal.
    let host = StubHost::new(5_000)
        .with_held(held(1, 5_000))
        .with_bytes(tx, vec![0xAB; 8])
        .with_block_hash(claimed, block);
    let daemon = StubDaemon::new();
    daemon.set_block_hash(claimed, block); // matches → fruitless each tick
    host.enqueue_rescan(tx, claimed);
    let mut d = driver();

    // Four ticks: fruitless at 1, 2, 3 (trip), 4 (latched, no re-emit).
    for _ in 0..4 {
        d.tick(&host, &daemon, &NoSaveCommit).await;
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
        .with_bytes(tx, vec![0xAB; 8])
        .with_block_hash(claimed, [0xAA; 32]);
    let daemon = StubDaemon::new();
    daemon.set_block_hash(claimed, [0xBB; 32]); // differs → divergence
    host.enqueue_rescan(tx, claimed);
    let mut d = driver();

    for _ in 0..5 {
        d.tick(&host, &daemon, &NoSaveCommit).await;
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
    // The status probe returns held at both synced heights. The guard
    // is what this test isolates.
    let host = StubHost::new(5_000)
        .with_held(held(1, 6_000))
        .with_bytes(tx, vec![0xAB; 8])
        .with_block_hash(claimed, block);
    let daemon = StubDaemon::new();
    daemon.set_block_hash(claimed, block); // would be fruitless IF checked
    host.enqueue_rescan(tx, claimed);
    let mut d = driver();

    // claimed (6000) > synced (5000): the guard skips the count every
    // tick. Well past the threshold — no trip, because nothing counts.
    for _ in 0..5 {
        d.tick(&host, &daemon, &NoSaveCommit).await;
    }
    assert!(
        breaker_trips(&host.events()).is_empty(),
        "above-synced request is never classified fruitless"
    );

    // The wallet syncs past the claimed height: the preserved target
    // is now at an already-scanned height and counts. Three ticks trip.
    host.set_synced(6_000);
    for _ in 0..FRUITLESS_RESCAN_BREAKER_THRESHOLD {
        d.tick(&host, &daemon, &NoSaveCommit).await;
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
    // No `with_block_hash` on the host → ledger hash absent. Bytes are
    // present so the status probe does not alarm beside the deferral.
    let host = StubHost::new(5_000)
        .with_held(held(1, 5_000))
        .with_bytes(tx, vec![0xAB; 8]);
    let daemon = StubDaemon::new();
    daemon.set_block_hash(claimed, [0xAA; 32]);
    host.enqueue_rescan(tx, claimed);
    let mut d = driver();

    for _ in 0..5 {
        d.tick(&host, &daemon, &NoSaveCommit).await;
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
        .with_bytes(tx, vec![0xAB; 8])
        .with_block_hash(claimed, block);
    let daemon = StubDaemon::new();
    daemon.set_block_hash(claimed, block);
    host.enqueue_rescan(tx, claimed);
    let mut d = driver();

    // Two fruitless ticks (streak = 2, below threshold).
    d.tick(&host, &daemon, &NoSaveCommit).await;
    d.tick(&host, &daemon, &NoSaveCommit).await;
    assert!(breaker_trips(&host.events()).is_empty());

    // Refresh confirms the tx: the target is reaped on projection-exit.
    host.confirm(&tx);
    d.tick(&host, &daemon, &NoSaveCommit).await;
    assert!(!host.is_held(&tx));
    assert!(
        breaker_trips(&host.events()).is_empty(),
        "no trip after reap"
    );
}
