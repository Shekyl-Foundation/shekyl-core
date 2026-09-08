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
//! # Cadence is the engine cadence driver's (`ENGINE_CADENCE_DRIVER.md`)
//!
//! The driver exposes [`SubmitLifecycleDriver::tick`]; **scheduling is
//! owned by the engine cadence driver** ([`cadence`](super::cadence)
//! leg 1), which fires one tick per observed chain advance — the right
//! base, since the held projection and `synced_height` only move with
//! the chain. §5.3's original "scheduling is the embedding runtime's"
//! posture is overturned per the design doc §1: no embedder ever
//! scheduled the tick, and it sat with zero production callers. The
//! driver itself stays a plain struct with an `async fn`, testable
//! without timers.
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
#[path = "submit_lifecycle_tests.rs"]
mod tests;
