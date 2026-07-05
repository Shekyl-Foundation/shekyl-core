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
//! bytes, applies the probe outcome (including the §2.6 confirmed-absent
//! release), and executes the F40 targeted re-scan with its R2
//! fruitless-rescan breaker.
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
//! # State vs. handles: persistent overlays, per-tick host/daemon
//!
//! The driver owns the in-memory overlays the kernel doc anticipates
//! (see the struct docs) and **nothing else** — it is not coupled to the
//! wallet or the daemon by ownership. Each [`tick`](SubmitLifecycleDriver::tick)
//! borrows the wallet surface as a [`WatchdogHost`] trait object
//! (`&dyn WatchdogHost`) and the daemon as `&D`. This keeps the
//! persistent state decoupled from the transient
//! handles: the embedding [`Engine`](super::Engine) owns the pending-tx
//! engine and the daemon by value and lends both to the driver for the
//! duration of one tick, with no `Arc`-sharing of the wallet state.
//!
//! # Host indirection ([`WatchdogHost`])
//!
//! The driver reaches the ledger, the retained probe bytes, the rescan
//! queue, and the diagnostic sink through the object-safe
//! [`WatchdogHost`] trait rather than the six-parameter
//! [`LocalPendingTx`](super::local_pending_tx::LocalPendingTx) generic.
//! This makes the host contract an explicit, narrow surface — the driver
//! can only do to the wallet what `WatchdogHost` names. The daemon
//! surface [`DaemonEngine`] is *not* object-safe (its async methods are
//! `-> impl Future`), so the daemon is a per-tick monomorphic `&D`, not
//! a trait object.
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

use std::collections::{HashMap, HashSet};

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
/// an object-safe surface so the driver reaches the wallet through a
/// narrow, named contract (not the six-parameter
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
/// Holds only the in-memory overlays the kernel doc anticipates; the
/// wallet surface and the daemon are borrowed per
/// [`tick`](Self::tick), not owned:
///
/// - `overlay`: per-txid [`HeldSubmit`] state carried across ticks — the
///   `probed_this_epoch` flag and the wait-epoch baseline the kernel
///   advances on a `RestartWait`. Fresh projections seed missing entries;
///   confirmed / released txids are reaped.
/// - `alarmed`: the edge-trigger latch. Each held tx emits its **first**
///   alarm; subsequent ticks suppress re-emission (alarm-fatigue bound,
///   §5.3). Cleared when the tx leaves the held projection.
/// - `rescan_targets`: the F40 targeted-re-scan verification state — one
///   entry per unverified `AlreadyInChain` claim, persisted across ticks
///   so the R2 breaker can count *consecutive* fruitless re-scans. Seeded
///   from the host's rescan queue; reaped when the tx leaves the held
///   projection (confirmation observed by refresh).
/// - `breaker_tripped`: the F40-R2 breaker edge-trigger latch, distinct
///   from `alarmed` so the two operator signals (watchdog vs. lying-daemon
///   confirmation) are independent. Emits `FruitlessRescanBreakerTripped`
///   once per trip.
pub(crate) struct SubmitLifecycleDriver {
    /// Watchdog tunables (horizon), derived from the block target.
    config: WatchdogConfig,
    /// Per-txid tracking overlaid across ticks (see struct docs).
    overlay: HashMap<TxHash, HeldSubmit>,
    /// Edge-trigger alarm latch (see struct docs).
    alarmed: HashSet<TxHash>,
    /// F40 targeted-re-scan verification state (see struct docs).
    rescan_targets: HashMap<TxHash, RescanTarget>,
    /// F40-R2 breaker edge-trigger latch (see struct docs).
    breaker_tripped: HashSet<TxHash>,
}

/// One in-flight F40 targeted-re-scan verification, persisted across
/// ticks (`DAEMON_SUBMIT_VERDICT.md` §7.2, F40).
///
/// The daemon claimed this tx confirmed at `claimed_height` (an
/// already-scanned height, per the §2.5(b) enqueue guard). Each tick the
/// executor re-checks the daemon's block hash there against the ledger's;
/// a match with the spend still unobserved is one fruitless re-scan
/// (`consecutive_fruitless += 1`), and
/// [`FRUITLESS_RESCAN_BREAKER_THRESHOLD`] consecutive fruitless re-scans
/// trip the R2 breaker.
struct RescanTarget {
    /// Daemon-claimed confirming height (a release-path discriminant,
    /// never settlement truth). The fruitless-soundness guard re-checks
    /// `claimed_height ≤ current synced_height` at execution time.
    claimed_height: u64,
    /// Consecutive fruitless re-scans observed (reset semantics: a
    /// non-fruitless outcome leaves the counter untouched per decision 1;
    /// the target is reaped on confirmation, which resets it by removal).
    consecutive_fruitless: u32,
}

/// Consecutive fruitless targeted re-scans (the daemon claims
/// confirmation at an already-scanned height whose block matches ours but
/// lacks the spend) at which the F40-R2 breaker trips
/// (`DAEMON_SUBMIT_VERDICT.md` §7.2, F40-R2).
///
/// **Default rationale (rule 75).** The breaker bounds a lying daemon's
/// work-amplification and alerts the operator; it is not a one-off-race
/// detector. One fruitless re-scan can be a benign transient (the
/// executor observed the claim a tick before refresh cleared the lock);
/// two could still be slow refresh under load. Three *consecutive*
/// fruitless re-scans — each a full tick apart, each re-confirming the
/// block hash matches and the spend is still absent — is a daemon
/// persistently lying about confirmation, which no wallet action can
/// remedy (the lock stays placed; F40-R1 is structural). Safe-adjustment
/// bounds: at least 2 (a single transient must not trip), and small
/// enough that the operator is alerted well before the escape horizon
/// would independently alarm.
const FRUITLESS_RESCAN_BREAKER_THRESHOLD: u32 = 3;

impl SubmitLifecycleDriver {
    /// Construct a driver deriving the escape horizon from the consensus
    /// `block_target_seconds` ([`WatchdogConfig::from_block_target`]).
    ///
    /// # Panics
    ///
    /// Panics on a broken consensus block target (zero, or large enough
    /// to floor the horizon to zero blocks) — a broken consensus
    /// constant is loud failure, not a runtime degradation
    /// (`from_block_target`'s contract).
    pub(crate) fn new(block_target_seconds: u64) -> Self {
        Self {
            config: WatchdogConfig::from_block_target(block_target_seconds),
            overlay: HashMap::new(),
            alarmed: HashSet::new(),
            rescan_targets: HashMap::new(),
            breaker_tripped: HashSet::new(),
        }
    }

    /// One driver cadence step (§5.3). Projects the held set once,
    /// reconciles the in-memory overlays, executes the F40 targeted
    /// re-scan verification (with the R2 breaker), then runs the escape
    /// ladder per held tx.
    ///
    /// `host` and `daemon` are borrowed for the tick only. No mutex
    /// guard is held across an `.await` — every host read is a discrete
    /// call — so the driver cannot deadlock the wallet state lock across
    /// a daemon round-trip.
    pub(crate) async fn tick<D: DaemonEngine>(&mut self, host: &dyn WatchdogHost, daemon: &D) {
        // Seed rescan targets from the host queue before reconciling, so
        // the just-enqueued targets survive the live-set prune (their
        // F14 locks are placed, so they are in the held projection).
        for request in host.drain_rescan_queue() {
            self.rescan_targets
                .entry(request.tx_hash)
                .or_insert(RescanTarget {
                    claimed_height: request.claimed_height,
                    consecutive_fruitless: 0,
                });
        }

        let projected = host.held_submits();
        let live: HashSet<TxHash> = projected.iter().map(|h| h.tx_hash).collect();
        self.reconcile_overlays(host, &live, &projected);

        self.execute_rescans(host, daemon).await;
        self.run_escape_ladder(host, daemon).await;
    }

    /// Fetch health once and step the escape ladder per held tx.
    async fn run_escape_ladder<D: DaemonEngine>(&mut self, host: &dyn WatchdogHost, daemon: &D) {
        // Nothing awaiting → skip the health RPC entirely.
        if self.overlay.is_empty() {
            return;
        }

        // A failed health round-trip is not a verdict (§7.2): without
        // health facts the ladder cannot separate "tx stuck" from
        // "daemon behind / peerless", so make no decision this tick.
        let health = match daemon.get_health().await {
            Ok(h) => health_context(h),
            Err(_) => return,
        };

        let synced = host.synced_height();
        // Snapshot the entries so no overlay borrow is held across the
        // per-tx `.await`.
        let entries: Vec<HeldSubmit> = self.overlay.values().copied().collect();
        for held in entries {
            self.step_held(host, daemon, held, synced, health).await;
        }
    }

    /// Drop overlay / alarm / rescan state for txids that left the
    /// projection (confirmed via refresh, or released), prune the
    /// retained bytes to the live set, and seed overlay entries for
    /// newly-held txids.
    ///
    /// `entry(..).or_insert(..)` preserves an existing overlay entry: a
    /// `RestartWait` may have advanced its baseline past the F14 accept
    /// height the fresh projection carries, and that higher baseline is
    /// the live wait epoch.
    ///
    /// Reaping the rescan target on projection-exit is the R2 breaker's
    /// success path: a tx that left the held set confirmed via refresh
    /// (`mark_spent` cleared the F14 lock), so the `AlreadyInChain` claim
    /// was truthful — the consecutive-fruitless streak resets by removal.
    fn reconcile_overlays(
        &mut self,
        host: &dyn WatchdogHost,
        live: &HashSet<TxHash>,
        projected: &[HeldSubmit],
    ) {
        self.overlay.retain(|tx, _| live.contains(tx));
        self.alarmed.retain(|tx| live.contains(tx));
        self.rescan_targets.retain(|tx, _| live.contains(tx));
        self.breaker_tripped.retain(|tx| live.contains(tx));
        host.prune_held_bytes(live);
        for h in projected {
            self.overlay.entry(h.tx_hash).or_insert(*h);
        }
    }

    /// Execute the F40 targeted re-scan verification for every active
    /// target (`DAEMON_SUBMIT_VERDICT.md` §7.2, decision 1). All targets
    /// remaining after [`reconcile_overlays`](Self::reconcile_overlays)
    /// are held (spend unobserved); each is re-checked against the
    /// daemon's block hash at the claimed height.
    async fn execute_rescans<D: DaemonEngine>(&mut self, host: &dyn WatchdogHost, daemon: &D) {
        if self.rescan_targets.is_empty() {
            return;
        }
        let synced = host.synced_height();
        // Snapshot keys so no `rescan_targets` borrow is held across the
        // per-target `.await`.
        let targets: Vec<(TxHash, u64)> = self
            .rescan_targets
            .iter()
            .map(|(tx, target)| (*tx, target.claimed_height))
            .collect();
        for (tx_hash, claimed_height) in targets {
            self.check_rescan_target(host, daemon, tx_hash, claimed_height, synced)
                .await;
        }
    }

    /// Verify one targeted re-scan (decision 1 + its fruitless-soundness
    /// refinement). Fruitless (block matches, spend absent) increments
    /// the consecutive counter and trips the R2 breaker at the threshold;
    /// every other outcome leaves the counter untouched.
    async fn check_rescan_target<D: DaemonEngine>(
        &mut self,
        host: &dyn WatchdogHost,
        daemon: &D,
        tx_hash: TxHash,
        claimed_height: u64,
        synced: u64,
    ) {
        // Fruitless-soundness guard (decision 1 refinement), re-checked at
        // execution time: synced_height may have rewound below the claimed
        // height since enqueue (reorg). Above current synced the block is
        // not (or no longer) scanned, so "spend unobserved" is refresh lag,
        // not absence — re-route to the §2.6 path-1 wait (the escape ladder
        // owns liveness), never the fruitless counter.
        if claimed_height > synced {
            return;
        }

        // The ledger's stored hash at the claimed height. Absent (outside
        // the retained range) → the cheap hash-compare is impossible, so
        // the fruitless inference cannot be made soundly: defer (the
        // escape ladder still bounds liveness). Counter untouched.
        let Some(ledger_hash) = host.block_hash_at(claimed_height) else {
            return;
        };

        // One block-header fetch — the entire per-lie cost cap (decision
        // 1). A claimed height that exceeds `usize` on this platform is
        // unrepresentable/unfetchable: defer, counter untouched.
        let Ok(height_usize) = usize::try_from(claimed_height) else {
            return;
        };
        // Transport ambiguity is not a verdict: retry next tick, counter
        // untouched.
        let Ok(daemon_hash) = daemon.get_block_hash(height_usize).await else {
            return;
        };

        if daemon_hash == ledger_hash {
            // Same block we scanned, spend still unobserved (the target
            // is held, guaranteed by reconcile) → the daemon lied about
            // this tx confirming there. One fruitless re-scan.
            self.record_fruitless(host, tx_hash);
        }
        // Divergence (daemon_hash != ledger_hash): a reorg replaced the
        // block at the claimed height. Defer to the refresh reorg-heal
        // machinery (parent-hash divergence at synced+1 rewinds and
        // re-scans); counter untouched (decision 1).
    }

    /// Record one fruitless re-scan for `tx_hash` and trip the R2 breaker
    /// at [`FRUITLESS_RESCAN_BREAKER_THRESHOLD`] consecutive occurrences.
    ///
    /// The breaker trip is an operator alarm only: the F14 lock stays
    /// placed (F40-R1 is structural — no path here releases it), so the
    /// tx's outputs remain reserved and the operator adjudicates the
    /// lying daemon. Edge-triggered via `breaker_tripped` (emit once per
    /// trip), independent of the watchdog `alarmed` latch.
    fn record_fruitless(&mut self, host: &dyn WatchdogHost, tx_hash: TxHash) {
        let attempts = {
            let target = self
                .rescan_targets
                .get_mut(&tx_hash)
                .expect("rescan target present: iterated from rescan_targets");
            target.consecutive_fruitless += 1;
            target.consecutive_fruitless
        };
        if attempts >= FRUITLESS_RESCAN_BREAKER_THRESHOLD && self.breaker_tripped.insert(tx_hash) {
            host.emit(PendingTxDiagnostic::FruitlessRescanBreakerTripped { tx_hash, attempts });
        }
    }

    /// Run the escape ladder for one held tx and act on the step.
    async fn step_held<D: DaemonEngine>(
        &mut self,
        host: &dyn WatchdogHost,
        daemon: &D,
        held: HeldSubmit,
        synced: u64,
        health: DaemonHealthContext,
    ) {
        match escape_ladder_step(&held, synced, health, self.config) {
            WatchdogStep::Wait(_) => {}
            WatchdogStep::OperatorAlarm(reason) => {
                self.raise_alarm(host, held.tx_hash, project_alarm(reason));
            }
            WatchdogStep::ProbeResubmitSameBytes => self.probe(host, daemon, held, synced).await,
        }
    }

    /// Execute the rung-1 resubmit-same-bytes probe: re-offer the
    /// retained bytes to the daemon, project the verdict onto the
    /// kernel's presence facts, and apply the resulting disposition.
    async fn probe<D: DaemonEngine>(
        &mut self,
        host: &dyn WatchdogHost,
        daemon: &D,
        held: HeldSubmit,
        synced: u64,
    ) {
        let Some(bytes) = host.held_bytes_for(&held.tx_hash) else {
            // Bytes gone (restart crossed the await, decision 2): the
            // probe rung degrades to the alarm rung.
            self.raise_alarm(
                host,
                held.tx_hash,
                WatchdogAlarmReason::ProbeBytesUnavailable,
            );
            return;
        };

        host.emit(PendingTxDiagnostic::WatchdogProbeDispatched {
            tx_hash: held.tx_hash,
            baseline_height: held.baseline_height,
        });

        let Ok(outcome) = daemon.submit_transaction(bytes).await else {
            // Transport ambiguity is not a verdict: retry next tick.
            host.emit(PendingTxDiagnostic::WatchdogProbeResolved {
                tx_hash: held.tx_hash,
                outcome: WatchdogProbeOutcome::TransportAmbiguous,
            });
            return;
        };

        host.emit(PendingTxDiagnostic::WatchdogProbeResolved {
            tx_hash: held.tx_hash,
            outcome: probe_trace(outcome),
        });

        match classify_probe(outcome) {
            ProbeVerdict::ReferenceStale => {
                self.raise_alarm(
                    host,
                    held.tx_hash,
                    WatchdogAlarmReason::ReferenceStaleNeedsRebuild,
                );
            }
            ProbeVerdict::Kernel(kernel_outcome) => {
                self.apply_kernel_outcome(host, held, kernel_outcome, synced);
            }
        }
    }

    /// Apply a kernel [`ProbeOutcome`] to the overlay and act on the
    /// [`ProbeDisposition`].
    fn apply_kernel_outcome(
        &mut self,
        host: &dyn WatchdogHost,
        held: HeldSubmit,
        outcome: ProbeOutcome,
        probe_height: u64,
    ) {
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
                host.release_awaiting_confirmation(&released);
                self.overlay.remove(&held.tx_hash);
                self.alarmed.remove(&held.tx_hash);
            }
            ProbeDisposition::Alarm(reason) => {
                if let Some(next) = next {
                    self.overlay.insert(next.tx_hash, next);
                }
                self.raise_alarm(host, held.tx_hash, project_alarm(reason));
            }
        }
    }

    /// Emit a watchdog alarm for `tx_hash`, edge-triggered: the first
    /// alarm for a held tx fires; subsequent ticks suppress re-emission
    /// (alarm-fatigue bound, §5.3). The latch clears when the tx leaves
    /// the held projection ([`reconcile_overlays`](Self::reconcile_overlays)).
    fn raise_alarm(
        &mut self,
        host: &dyn WatchdogHost,
        tx_hash: TxHash,
        reason: WatchdogAlarmReason,
    ) {
        if self.alarmed.insert(tx_hash) {
            host.emit(PendingTxDiagnostic::WatchdogAlarm { tx_hash, reason });
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

#[cfg(test)]
mod tests {
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
                s.block_hashes.get(&h).copied().ok_or_else(|| {
                    RpcError::InvalidNode(format!("StubDaemon: no block hash at {h}"))
                })
            }
        }
    }

    impl DaemonEngine for StubDaemon {
        type Error = RpcError;

        fn get_fee_estimates(
            &self,
        ) -> impl Send + Future<Output = Result<FeeEstimates, Self::Error>> {
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
                PendingTxDiagnostic::FruitlessRescanBreakerTripped { attempts, .. } => {
                    Some(*attempts)
                }
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
}
