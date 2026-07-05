// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Submit lifecycle driver — the §5.3 wallet-side actor that drives the
//! [`submit_watchdog`](super::submit_watchdog) decision kernel
//! (`docs/design/DAEMON_SUBMIT_VERDICT.md`).
//!
//! The kernel is pure: facts in, one decision out. This module is the
//! thin scheduler around those audited decisions — it projects the held
//! set from the ledger's F14 locks, overlays the in-memory probe state
//! the kernel doc anticipates (per-txid `probed_this_epoch` / wait-epoch
//! baseline), fetches daemon health, runs the escape ladder per held tx,
//! executes the rung-1 resubmit-same-bytes probe against the retained
//! bytes, and applies the probe outcome (including the §2.6 confirmed-
//! absent release). It also executes the F40 targeted re-scan with its
//! R2 fruitless-rescan breaker (lands in the following commit).
//!
//! # Cadence is role policy; termination is not (§5.3)
//!
//! The driver exposes [`SubmitLifecycleDriver::tick`]; **scheduling is
//! owned by the embedding runtime.** Staking and plain wallets need not
//! share periodicity. The natural production call site is after each
//! completed refresh cycle — the held projection and `synced_height`
//! only move on refresh / ledger writes — but the driver is a plain
//! struct with an `async fn`, testable without timers.
//!
//! # Host indirection ([`WatchdogHost`])
//!
//! The driver reaches the ledger, the retained probe bytes, the rescan
//! queue, and the diagnostic sink through the object-safe
//! [`WatchdogHost`] trait rather than the six-parameter
//! [`LocalPendingTx`](super::local_pending_tx::LocalPendingTx) generic.
//! This keeps the driver monomorphic in the daemon parameter alone and
//! makes the host contract an explicit, narrow surface — the driver can
//! only do to the wallet what `WatchdogHost` names.
//!
//! # What the kernel cannot represent (driver-level conditions)
//!
//! Two conditions live here, not in the kernel:
//!
//! - **Probe bytes gone.** The rung-1 probe needs the network-exposed
//!   bytes; the ephemeral held-bytes store (§5.3 decision 2) loses them
//!   across a wallet restart. When the kernel calls for the probe and
//!   the bytes are absent, the probe rung degrades to the operator-alarm
//!   rung ([`WatchdogAlarmReason::ProbeBytesUnavailable`]) — preserving
//!   §2.6's "every exit is verdict, confirmation, or operator alarm."
//! - **Retryable probe rejection.** The daemon can reject the resubmit
//!   with a *retryable* cause (stale root / reference too recent /
//!   reference not found). The bytes are neither admitted nor terminally
//!   dead; recovery needs a fresh reference, which is a human-authorized
//!   rebuild (§7.1). The kernel's [`ProbeOutcome`] has no retryable arm
//!   by construction, so the driver alarms directly
//!   ([`WatchdogAlarmReason::ReferenceStaleNeedsRebuild`]).

// Landed inert (same pattern as the kernel it drives): the driver's
// production consumer is the Engine tick call site, which lands with the
// wiring + test-battery commit. Until then only the driver's own tests
// exercise it. The allow lifts when `Engine` owns a driver instance and
// the post-refresh tick call site is wired.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use shekyl_rpc_client::RejectCause;
use shekyl_types::TxHash;

use super::diagnostics::{PendingTxDiagnostic, WatchdogAlarmReason, WatchdogProbeOutcome};
use super::local_pending_tx::RescanRequest;
use super::submit_watchdog::{
    apply_probe_outcome, escape_ladder_step, AlarmReason, DaemonHealthContext, HeldSubmit,
    ProbeDisposition, ProbeOutcome, WatchdogConfig, WatchdogStep,
};
use super::traits::{DaemonEngine, DaemonHealth, TxSubmitOutcome};

/// The wallet-side operations the §5.3 watchdog driver performs, behind
/// an object-safe surface so the driver is monomorphic in the daemon
/// parameter alone (not the six-parameter
/// [`LocalPendingTx`](super::local_pending_tx::LocalPendingTx) generic).
///
/// Every method is a narrow, named capability: the driver can project
/// the held set, read / prune the retained probe bytes, drain the F40
/// rescan queue, read the ledger's sync position and stored block
/// hashes, release the confirmed-absent F14 locks, and emit
/// observability events — and nothing else. The production implementor
/// is `LocalPendingTx`; the contract is small enough to stub in tests.
pub(crate) trait WatchdogHost: Send + Sync {
    /// Project the current held-submit set from the ledger's F14 locks
    /// ([`submit_watchdog::held_submits`](super::submit_watchdog::held_submits)),
    /// one fresh entry per awaited txid (`probed_this_epoch: false`).
    fn held_submits(&self) -> Vec<HeldSubmit>;

    /// The wallet's current synced chain height — the horizon reference
    /// and the fruitless-soundness guard's `synced_height`.
    fn synced_height(&self) -> u64;

    /// The ledger's stored block hash at `height`, or `None` when the
    /// height is outside the retained range. Used by the F40 executor's
    /// cheap hash-compare (decision 1).
    fn block_hash_at(&self, height: u64) -> Option<[u8; 32]>;

    /// The retained network-exposed bytes for `tx_hash` (§5.3 decision
    /// 2), cloned for the resubmit-same-bytes probe. `None` means the
    /// bytes are gone (restart crossed the await, or the tx already left
    /// the held projection).
    fn held_bytes_for(&self, tx_hash: &TxHash) -> Option<Vec<u8>>;

    /// Prune retained probe bytes down to the `live` held-projection set
    /// (decision 2: prune when the hash leaves the projection).
    fn prune_held_bytes(&self, live: &HashSet<TxHash>);

    /// Drain the F40 targeted re-scan queue (decision 3), returning this
    /// tick's requests and leaving the queue empty.
    fn drain_rescan_queue(&self) -> Vec<RescanRequest>;

    /// Release the F14 awaiting-confirmation locks under every txid in
    /// `tx_hashes` (the §2.6 confirmed-absent leg), returning the number
    /// of locks released. **Release is not rebuild authorization.**
    fn release_awaiting_confirmation(&self, tx_hashes: &HashSet<TxHash>) -> usize;

    /// Emit one diagnostic event onto the wallet's sink (observability
    /// only; control flow never rides the sink).
    fn emit(&self, event: PendingTxDiagnostic);
}

/// The submit lifecycle driver: a thin, testable scheduler around the
/// [`submit_watchdog`](super::submit_watchdog) kernel and the F40 re-scan
/// executor.
///
/// Monomorphic in the daemon parameter `D` (the wallet surface is the
/// object-safe [`WatchdogHost`]). Holds the in-memory overlays the kernel
/// doc anticipates:
///
/// - `overlay`: per-txid [`HeldSubmit`] state carried across ticks — the
///   `probed_this_epoch` flag and the wait-epoch baseline the kernel
///   advances on a `RestartWait`. Fresh projections seed missing entries;
///   confirmed / released txids are reaped.
/// - `alarmed`: the edge-trigger latch. Each held tx emits its **first**
///   alarm; subsequent ticks suppress re-emission (alarm-fatigue bound,
///   §5.3). Cleared when the tx leaves the held projection.
/// - `fruitless`: the F40-R2 per-txid consecutive fruitless-rescan
///   counter (populated by the re-scan executor in the following commit).
pub(crate) struct SubmitLifecycleDriver<D: DaemonEngine> {
    /// Narrow wallet surface (production: `LocalPendingTx`).
    host: Arc<dyn WatchdogHost>,
    /// Daemon handle for the health snapshot and the resubmit probe.
    daemon: Arc<D>,
    /// Watchdog tunables (horizon), derived from the block target.
    config: WatchdogConfig,
    /// Per-txid tracking overlaid across ticks (see struct docs).
    overlay: HashMap<TxHash, HeldSubmit>,
    /// Edge-trigger alarm latch (see struct docs).
    alarmed: HashSet<TxHash>,
    /// F40-R2 consecutive fruitless-rescan counters (see struct docs).
    fruitless: HashMap<TxHash, u32>,
}

impl<D: DaemonEngine> SubmitLifecycleDriver<D> {
    /// Construct a driver over `host` and `daemon`, deriving the escape
    /// horizon from the consensus `block_target_seconds`
    /// ([`WatchdogConfig::from_block_target`]).
    ///
    /// # Panics
    ///
    /// Panics on a broken consensus block target (zero, or large enough
    /// to floor the horizon to zero blocks) — a broken consensus
    /// constant is loud failure, not a runtime degradation
    /// (`from_block_target`'s contract).
    pub(crate) fn new(
        host: Arc<dyn WatchdogHost>,
        daemon: Arc<D>,
        block_target_seconds: u64,
    ) -> Self {
        Self {
            host,
            daemon,
            config: WatchdogConfig::from_block_target(block_target_seconds),
            overlay: HashMap::new(),
            alarmed: HashSet::new(),
            fruitless: HashMap::new(),
        }
    }

    /// One driver cadence step (§5.3). Runs the escape-ladder pass over
    /// every held tx; the F40 targeted re-scan executor is prepended in
    /// the following commit.
    ///
    /// `&mut self`: the pass mutates the in-memory overlays. No mutex
    /// guard is held across an `.await` — every host read is a discrete
    /// call — so the driver is `Send` and cannot deadlock the wallet
    /// state lock across a daemon round-trip.
    pub(crate) async fn tick(&mut self) {
        self.run_escape_ladder().await;
    }

    /// Project the held set, reconcile the overlays, fetch health once,
    /// and step the escape ladder per held tx.
    async fn run_escape_ladder(&mut self) {
        let projected = self.host.held_submits();
        let live: HashSet<TxHash> = projected.iter().map(|h| h.tx_hash).collect();
        self.reconcile_overlays(&live, &projected);

        // Nothing awaiting → skip the health RPC entirely.
        if self.overlay.is_empty() {
            return;
        }

        // A failed health round-trip is not a verdict (§7.2): without
        // health facts the ladder cannot separate "tx stuck" from
        // "daemon behind / peerless", so make no decision this tick.
        let health = match self.daemon.get_health().await {
            Ok(h) => health_context(h),
            Err(_) => return,
        };

        let synced = self.host.synced_height();
        // Snapshot the entries so no overlay borrow is held across the
        // per-tx `.await`.
        let entries: Vec<HeldSubmit> = self.overlay.values().copied().collect();
        for held in entries {
            self.step_held(held, synced, health).await;
        }
    }

    /// Drop overlay / alarm state for txids that left the projection
    /// (confirmed via refresh, or released), prune the retained bytes to
    /// the live set, and seed overlay entries for newly-held txids.
    ///
    /// `entry(..).or_insert(..)` preserves an existing overlay entry: a
    /// `RestartWait` may have advanced its baseline past the F14 accept
    /// height the fresh projection carries, and that higher baseline is
    /// the live wait epoch.
    fn reconcile_overlays(&mut self, live: &HashSet<TxHash>, projected: &[HeldSubmit]) {
        self.overlay.retain(|tx, _| live.contains(tx));
        self.alarmed.retain(|tx| live.contains(tx));
        self.fruitless.retain(|tx, _| live.contains(tx));
        self.host.prune_held_bytes(live);
        for h in projected {
            self.overlay.entry(h.tx_hash).or_insert(*h);
        }
    }

    /// Run the escape ladder for one held tx and act on the step.
    async fn step_held(&mut self, held: HeldSubmit, synced: u64, health: DaemonHealthContext) {
        match escape_ladder_step(&held, synced, health, self.config) {
            WatchdogStep::Wait(_) => {}
            WatchdogStep::OperatorAlarm(reason) => {
                self.raise_alarm(held.tx_hash, project_alarm(reason));
            }
            WatchdogStep::ProbeResubmitSameBytes => self.probe(held, synced).await,
        }
    }

    /// Execute the rung-1 resubmit-same-bytes probe: re-offer the
    /// retained bytes to the daemon, project the verdict onto the
    /// kernel's presence facts, and apply the resulting disposition.
    async fn probe(&mut self, held: HeldSubmit, synced: u64) {
        let Some(bytes) = self.host.held_bytes_for(&held.tx_hash) else {
            // Bytes gone (restart crossed the await, decision 2): the
            // probe rung degrades to the alarm rung.
            self.raise_alarm(held.tx_hash, WatchdogAlarmReason::ProbeBytesUnavailable);
            return;
        };

        self.host
            .emit(PendingTxDiagnostic::WatchdogProbeDispatched {
                tx_hash: held.tx_hash,
                baseline_height: held.baseline_height,
            });

        // Clone the Arc so the probe future borrows the daemon handle,
        // not `self` — leaving `&mut self` free after the `.await`.
        let daemon = Arc::clone(&self.daemon);
        let outcome = match daemon.submit_transaction(bytes).await {
            Ok(outcome) => outcome,
            Err(_) => {
                // Transport ambiguity is not a verdict: retry next tick.
                self.host.emit(PendingTxDiagnostic::WatchdogProbeResolved {
                    tx_hash: held.tx_hash,
                    outcome: WatchdogProbeOutcome::TransportAmbiguous,
                });
                return;
            }
        };

        self.host.emit(PendingTxDiagnostic::WatchdogProbeResolved {
            tx_hash: held.tx_hash,
            outcome: probe_trace(outcome),
        });

        match classify_probe(outcome) {
            ProbeVerdict::ReferenceStale => {
                self.raise_alarm(
                    held.tx_hash,
                    WatchdogAlarmReason::ReferenceStaleNeedsRebuild,
                );
            }
            ProbeVerdict::Kernel(kernel_outcome) => {
                self.apply_kernel_outcome(held, kernel_outcome, synced);
            }
        }
    }

    /// Apply a kernel [`ProbeOutcome`] to the overlay and act on the
    /// [`ProbeDisposition`].
    fn apply_kernel_outcome(&mut self, held: HeldSubmit, outcome: ProbeOutcome, probe_height: u64) {
        let (disposition, next) = apply_probe_outcome(&held, outcome, probe_height);
        match disposition {
            ProbeDisposition::RestartWait | ProbeDisposition::KeepHolding => {
                if let Some(next) = next {
                    self.overlay.insert(next.tx_hash, next);
                }
            }
            ProbeDisposition::ReleaseConfirmedAbsent => {
                // §2.6 release path 2: the definite terminal verdict
                // proves the tx never confirmed; release the F14 locks.
                let released: HashSet<TxHash> = std::iter::once(held.tx_hash).collect();
                self.host.release_awaiting_confirmation(&released);
                self.overlay.remove(&held.tx_hash);
                self.alarmed.remove(&held.tx_hash);
            }
            ProbeDisposition::Alarm(reason) => {
                if let Some(next) = next {
                    self.overlay.insert(next.tx_hash, next);
                }
                self.raise_alarm(held.tx_hash, project_alarm(reason));
            }
        }
    }

    /// Emit a watchdog alarm for `tx_hash`, edge-triggered: the first
    /// alarm for a held tx fires; subsequent ticks suppress re-emission
    /// (alarm-fatigue bound, §5.3). The latch clears when the tx leaves
    /// the held projection ([`reconcile_overlays`](Self::reconcile_overlays)).
    fn raise_alarm(&mut self, tx_hash: TxHash, reason: WatchdogAlarmReason) {
        if self.alarmed.insert(tx_hash) {
            self.host
                .emit(PendingTxDiagnostic::WatchdogAlarm { tx_hash, reason });
        }
    }
}

/// The daemon-verdict classification the driver acts on: either a fact
/// the kernel can branch (`Kernel`), or the retryable-rejection
/// condition the kernel cannot represent (`ReferenceStale`).
enum ProbeVerdict {
    Kernel(ProbeOutcome),
    ReferenceStale,
}

/// Project the daemon [`TxSubmitOutcome`] onto the kernel's presence
/// facts, splitting off the retryable-rejection arm the kernel has no
/// representation for.
fn classify_probe(outcome: TxSubmitOutcome) -> ProbeVerdict {
    match outcome {
        TxSubmitOutcome::Submitted { .. } => {
            ProbeVerdict::Kernel(ProbeOutcome::ReofferedAfterAbsence)
        }
        TxSubmitOutcome::AlreadyInPool { .. } => ProbeVerdict::Kernel(ProbeOutcome::PresentInPool),
        TxSubmitOutcome::AlreadyInChain { .. } => {
            ProbeVerdict::Kernel(ProbeOutcome::ConfirmedInChain)
        }
        TxSubmitOutcome::Rejected { cause } => match cause {
            // Terminal: under single-egress a definite terminal verdict
            // proves the bytes are in neither pool nor chain (§7.1).
            RejectCause::Malformed
            | RejectCause::FeeTooLow
            | RejectCause::DoubleSpendConflict
            | RejectCause::Unrecognized => ProbeVerdict::Kernel(ProbeOutcome::RejectedTerminal),
            // Retryable: needs a fresh reference — a human-authorized
            // rebuild, not an automatic one.
            RejectCause::StaleRoot
            | RejectCause::ReferenceTooRecent
            | RejectCause::ReferenceNotFound => ProbeVerdict::ReferenceStale,
        },
    }
}

/// Project the daemon [`TxSubmitOutcome`] onto the observability trace
/// enum (`WatchdogProbeResolved`).
fn probe_trace(outcome: TxSubmitOutcome) -> WatchdogProbeOutcome {
    match outcome {
        TxSubmitOutcome::Submitted { .. } => WatchdogProbeOutcome::ReofferedAfterAbsence,
        TxSubmitOutcome::AlreadyInPool { .. } => WatchdogProbeOutcome::PresentInPool,
        TxSubmitOutcome::AlreadyInChain { .. } => WatchdogProbeOutcome::ConfirmedInChain,
        TxSubmitOutcome::Rejected { cause } => match cause {
            RejectCause::Malformed
            | RejectCause::FeeTooLow
            | RejectCause::DoubleSpendConflict
            | RejectCause::Unrecognized => WatchdogProbeOutcome::RejectedTerminal,
            RejectCause::StaleRoot
            | RejectCause::ReferenceTooRecent
            | RejectCause::ReferenceNotFound => WatchdogProbeOutcome::RejectedRetryable,
        },
    }
}

/// Project the kernel [`AlarmReason`] onto the diagnostic
/// [`WatchdogAlarmReason`].
fn project_alarm(reason: AlarmReason) -> WatchdogAlarmReason {
    match reason {
        AlarmReason::PresentButUnconfirmedPastHorizon => {
            WatchdogAlarmReason::PresentButUnconfirmedPastHorizon
        }
        AlarmReason::DaemonPeerless => WatchdogAlarmReason::DaemonPeerless,
    }
}

/// Map the daemon [`DaemonHealth`] facts into the kernel's
/// [`DaemonHealthContext`] (the RPC-transport type never depends on the
/// liveness-policy type; the driver bridges).
fn health_context(health: DaemonHealth) -> DaemonHealthContext {
    DaemonHealthContext {
        connections: health.connections,
        height: health.height,
        target_height: health.target_height,
    }
}
