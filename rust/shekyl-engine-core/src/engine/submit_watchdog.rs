// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Submit watchdog scaffolding — the §5.3 wallet-side liveness kernel
//! (`docs/design/DAEMON_SUBMIT_VERDICT.md`, F20 final form).
//!
//! **Liveness policy is wallet-owned; the daemon guarantees only honest
//! reporting plus the Dandelion++ fail-safe.** This module is the PR-4
//! scaffolding for that ownership: the *pure decision kernel* of the
//! watchdog — held-tx tracking keyed on chain confirmation, the
//! privacy-tiered escape ladder with presence branching, daemon-health
//! gating, and the horizon bound — with no driver attached. The
//! driving actor (cadence is role policy: staking vs plain wallets need
//! not share periodicity) lands with the wallet plan; a pure kernel
//! makes the §10 item 8 ladder-ordering and presence-branching
//! obligations unit-testable now and keeps the eventual actor a thin
//! scheduler around audited decisions.
//!
//! # The tracked substrate
//!
//! A held tx is tracked through the **F14 awaiting-confirmation locks**
//! (`shekyl_engine_state::AwaitingConfirmation`, §2.6): every accepted
//! submit places one on each spent input, keyed by the accepted txid.
//! The watchdog's success condition is those locks disappearing via
//! refresh-observed confirmation (`mark_spent`) — **never a daemon relay
//! claim** (§5.1: a malicious daemon can forge a relay claim; it cannot
//! forge the tx confirming). [`held_submits`] projects the current held
//! set from the ledger; an empty projection means nothing is awaiting.
//!
//! # The escape ladder (§5.3)
//!
//! 1. **Resubmit-same-bytes** — privacy-neutral (identical bytes, same
//!    txid, daemon dedups; zero new network artifact).
//! 2. **Operator alarm** — a human decides.
//! 3. **Deliberate, alarmed rebuild** — never automatic on timeout
//!    (§7.1: an adversary who can delay confirmation must not be able to
//!    trigger a linkage event on demand). Rung 3 is deliberately absent
//!    from [`WatchdogStep`]: the kernel can *wait*, *probe*, or *alarm*;
//!    it cannot authorize a rebuild.
//!
//! The rungs are presence-conditional (round-6 minor b), with one
//! resubmit acting as the probe: **absent** (evicted / never landed) →
//! the resubmit *is* the remedy and the wait restarts; **present but
//! unconfirmed past horizon** → straight to the alarm rung — repeating
//! the resubmit is pointless by construction (F31: an in-pool resubmit
//! early-returns `AlreadyInPool` with no relay pulse), and the eclipse
//! case (§7.5) lands exactly here. Terminal verdicts on the probe
//! resolve the wait per §2.5/§2.6.

// The kernel's production consumer is the §5.3 submit lifecycle driver
// ([`submit_lifecycle`](super::submit_lifecycle)), reached from the public
// [`Engine::run_submit_lifecycle_tick`](super::Engine::run_submit_lifecycle_tick)
// entry point: the driver wires `held_submits` → `escape_ladder_step` →
// probe → `apply_probe_outcome` / `release_awaiting_confirmation` into the
// lifecycle. The former `#![allow(dead_code)]` (landed-inert scaffolding) is
// lifted now that the driver makes every kernel surface live.

use std::collections::HashSet;

use shekyl_curve_tree::DISPATCHED_PROOF_LIFE;
use shekyl_types::TxHash;

use super::traits::DaemonHealth;

// ---------------------------------------------------------------------------
// Horizon configuration
// ---------------------------------------------------------------------------

/// Watchdog tunables. Production is [`Self::DEFAULT`]; tests build their
/// own to exercise the ladder at other horizons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WatchdogConfig {
    /// Escape horizon, in blocks past the accepting verdict's height,
    /// after which a still-unconfirmed held tx enters the escape ladder.
    ///
    /// **Default rationale (F35 + rule 75):** two binding constraints,
    /// both in blocks.
    ///
    /// *Upper bound — the probe must land while the same bytes are still
    /// submittable.* A dispatched proof is guaranteed
    /// [`DISPATCHED_PROOF_LIFE`] blocks of submittability (`MAX_AGE −
    /// REBUILD_AT`, 50: the transfer path re-anchors before it sends
    /// whenever `should_reanchor` holds). Past that the pool may already
    /// have removed the transaction (CEN-M10: an entry leaves when its
    /// reference leaves the window; the pool has no lifetime of its own),
    /// and the resubmit probe comes back `StaleRoot` — the
    /// `ReferenceStaleNeedsRebuild` alarm instead of a re-offer. The
    /// baseline is the *wallet's* height at accept and the probe fires on
    /// the wallet's height, so wallet–daemon height skew is spent out of
    /// this bound.
    ///
    /// *Lower bound — the probe must not fire on the normal path.* The
    /// daemon's relay publishes its own transaction within two origin
    /// retries (`SHIPPED_ORIGIN_RETRY_SECS`, the seconds `shekyl-relay`
    /// pins for `origin_retry_secs`: the first fire re-stems to the
    /// alternate, the second fluffs), and a published transaction mines
    /// in the next block. A horizon inside that probes a transaction that
    /// is still propagating normally — and present-but-unconfirmed goes
    /// straight to the alarm (§5.3), so that is alarm fatigue an adversary
    /// can hide inside.
    /// `escape_horizon_outlasts_the_relays_own_publication` pins this
    /// against those seconds and the consensus block target.
    ///
    /// The default is **half [`DISPATCHED_PROOF_LIFE`]** — 25 blocks,
    /// ~50 min at the 120 s target: 2× margin against the upper bound
    /// (wallet refresh lag and wallet–daemon skew), ~5 blocks above the
    /// lower. Sooner is the point for the anon-network eclipse case
    /// (§7.5), where the alarm rung is the *only* backstop.
    ///
    /// No re-relay rule bounds it: the Rust relay re-sends an origin's
    /// transaction only on those two embargo fires and has no periodic
    /// re-broadcast (`shekyl-relay`'s `graph::embargo`).
    pub escape_horizon_blocks: u64,
}

impl WatchdogConfig {
    /// The production configuration (rationale on
    /// [`Self::escape_horizon_blocks`]).
    pub(crate) const DEFAULT: Self = Self {
        escape_horizon_blocks: DISPATCHED_PROOF_LIFE.to_raw() / 2,
    };
}

// A zero horizon would put every held tx past horizon on its first check,
// silently skipping the wait rung; a horizon at or past the dispatched
// proof's life probes bytes the daemon may already refuse. Either is a
// broken consensus constant (`config/consensus_constants.json`), caught
// at compile time.
const _: () = assert!(WatchdogConfig::DEFAULT.escape_horizon_blocks > 0);
const _: () =
    assert!(WatchdogConfig::DEFAULT.escape_horizon_blocks < DISPATCHED_PROOF_LIFE.to_raw());

// ---------------------------------------------------------------------------
// Held-tx tracking (chain-confirmation-keyed)
// ---------------------------------------------------------------------------

/// One network-exposed tx awaiting chain confirmation, projected from
/// the F14 locks (§2.6). Success (confirmation via refresh) removes the
/// locks and the entry disappears from the projection — the watchdog
/// never needs an explicit "confirmed" transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeldSubmit {
    /// Canonical txid of the awaited transaction.
    pub tx_hash: TxHash,
    /// The height baseline the escape horizon counts from: the wallet
    /// synced height when the accepting verdict was observed, advanced
    /// to the probe height when an absent-probe resubmission restarts
    /// the wait.
    pub baseline_height: u64,
    /// Whether the resubmit-same-bytes probe has already been performed
    /// for the current wait epoch. A present-but-unconfirmed probe
    /// outcome sets this; repeating the probe is pointless by
    /// construction (F31) and the next escalation is the alarm rung.
    pub probed_this_epoch: bool,
}

/// Project the held-submit set from the send journal — one entry per
/// row in a lock-bearing state (`SendState::locks_carried_inputs`) with
/// a stamped `lock_baseline` (PR-SJ-1b: the journal owns the dispatch
/// facts; the per-input F14 locks the old projection grouped are now
/// derived from exactly these rows, so projecting the rows directly is
/// the same set minus the grouping).
///
/// The success condition is unchanged in substance: refresh observes
/// the spend and the merge reconciler flips the row to `Confirmed`,
/// dropping it from this projection — the same refresh-authoritative
/// event that used to clear the locks (`mark_spent`). One deliberate
/// strengthening: mid-rescan, a wiped ledger no longer blinds the
/// watchdog — the journal rows survive the wipe, so tracking continues
/// across it.
///
/// Fresh projections carry `probed_this_epoch: false`; the driving
/// actor overlays its in-memory probe state across refresh cycles.
/// `BTreeMap` row order makes the projection deterministic.
pub(crate) fn held_submits(wallet: &shekyl_engine_state::WalletLedger) -> Vec<HeldSubmit> {
    wallet
        .send_journal
        .rows
        .iter()
        .filter(|(_, row)| row.state.locks_carried_inputs())
        .filter_map(|(txid, row)| {
            row.lock_baseline.map(|baseline_height| HeldSubmit {
                tx_hash: TxHash::from_bytes(*txid),
                baseline_height,
                probed_this_epoch: false,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The escape ladder kernel
// ---------------------------------------------------------------------------

/// Why the kernel chose to keep waiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WaitReason {
    /// The escape horizon has not elapsed.
    HorizonNotReached,
    /// Past horizon, but the daemon is behind the network: "unconfirmed
    /// at this daemon" is uninformative until it syncs (the same
    /// sync-gating shape as the `ReferenceNotFound` disposition, §2.5).
    DaemonSyncing,
}

/// Why the kernel escalated to the operator-alarm rung.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AlarmReason {
    /// The probe found the tx present-but-unconfirmed past horizon:
    /// repeating the resubmit is pointless (F31), and the censoring /
    /// eclipse case (§7.5) lands exactly here. A human decides.
    PresentButUnconfirmedPastHorizon,
    /// Past horizon and the daemon reports no peers: relay is
    /// impossible and no wallet action can fix it — the alarm rung
    /// carries the decision to the operator (§2.6 invariant 2).
    DaemonPeerless,
    /// Past horizon and the daemon was started offline (`--offline`): it
    /// relays nothing by configuration, which only the operator can change.
    DaemonOffline,
}

/// One kernel decision for one held tx. Rung 3 (rebuild) is
/// intentionally unrepresentable — never automatic on timeout (§7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WatchdogStep {
    /// No action; re-evaluate on the next cadence tick.
    Wait(WaitReason),
    /// Run the rung-1 resubmit-same-bytes probe (privacy-neutral;
    /// idempotent status query per F31).
    ProbeResubmitSameBytes,
    /// Rung 2: raise the operator alarm.
    OperatorAlarm(AlarmReason),
}

/// Decide the next step for one held tx. Pure: all facts in, one
/// decision out — the §10 item 8 ladder-ordering property (resubmit
/// precedes alarm; rebuild never fires) is checkable over this function
/// by construction.
pub(crate) fn escape_ladder_step(
    held: &HeldSubmit,
    synced_height: u64,
    health: DaemonHealth,
    config: WatchdogConfig,
) -> WatchdogStep {
    let past_horizon =
        synced_height.saturating_sub(held.baseline_height) >= config.escape_horizon_blocks;
    if !past_horizon {
        return WatchdogStep::Wait(WaitReason::HorizonNotReached);
    }
    // Health gate (§5.2 item 3): separate "tx stuck" from daemon-side
    // conditions before spending a rung. Peerlessness is checked before
    // sync: a daemon with no peers can neither sync nor relay, so the
    // actionable operator-only condition (DaemonPeerless) must not be
    // masked by the transient DaemonSyncing wait when the daemon is both
    // behind and peerless.
    //
    // Both facts are the fields of [`DaemonHealth`]. The ladder does not
    // keep a second reading of them.
    // An offline daemon relays nothing by configuration: its own alarm,
    // not "peerless", which is a running node that has found nobody.
    match health.p2p {
        shekyl_rpc_types::HealthP2p::Offline => {
            return WatchdogStep::OperatorAlarm(AlarmReason::DaemonOffline);
        }
        shekyl_rpc_types::HealthP2p::Running { has_peers: false } => {
            return WatchdogStep::OperatorAlarm(AlarmReason::DaemonPeerless);
        }
        shekyl_rpc_types::HealthP2p::Running { has_peers: true } => {}
    }
    if !health.synchronized {
        return WatchdogStep::Wait(WaitReason::DaemonSyncing);
    }
    if held.probed_this_epoch {
        // One resubmit acts as the probe; a present tx does not become
        // more relayed by asking again (F31).
        return WatchdogStep::OperatorAlarm(AlarmReason::PresentButUnconfirmedPastHorizon);
    }
    WatchdogStep::ProbeResubmitSameBytes
}

// ---------------------------------------------------------------------------
// Probe-outcome application
// ---------------------------------------------------------------------------

/// The probe's verdict, projected onto the presence facts the ladder
/// branches on (round-6 minor b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeOutcome {
    /// `Accepted`: the tx was absent (evicted / never landed) and the
    /// resubmission *was* the remedy — re-offered through full admission
    /// and fresh relay.
    ReofferedAfterAbsence,
    /// `AlreadyInPool`: present-but-unconfirmed. No relay pulse was or
    /// will be triggered by asking (F31).
    PresentInPool,
    /// `AlreadyInChain`: confirmation observed by verdict; refresh
    /// remains the settlement authority (§2.5).
    ConfirmedInChain,
    /// `Rejected{*}`: a definite terminal verdict — under single-egress
    /// this proves the bytes are in neither pool nor chain (§7.1).
    RejectedTerminal,
}

/// What the driving actor does with a probe outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeDisposition {
    /// Restart the wait epoch from the probe height (the resubmission
    /// re-offered the bytes; the horizon counts anew).
    RestartWait,
    /// Keep holding: confirmation is expected via refresh, which
    /// releases the F14 locks through `mark_spent` (confirmed-present,
    /// §2.6). The alarm rung follows if the horizon elapses again
    /// (reorgs happen — the verdict authorizes no lock release).
    KeepHolding,
    /// Confirmed-absent resolution (§2.6 release path 2): the definite
    /// verdict proves the tx is gone; release the F14 locks via
    /// [`release_awaiting_confirmation`]. **Release is not rebuild
    /// authorization** (§2.6 invariant 3).
    ReleaseConfirmedAbsent,
    /// Escalate to the alarm rung (present-but-unconfirmed).
    Alarm(AlarmReason),
}

/// Apply a probe outcome to a held entry, returning the disposition and
/// the updated tracking entry (`None` when tracking ends).
pub(crate) fn apply_probe_outcome(
    held: &HeldSubmit,
    outcome: ProbeOutcome,
    probe_height: u64,
) -> (ProbeDisposition, Option<HeldSubmit>) {
    match outcome {
        ProbeOutcome::ReofferedAfterAbsence => (
            ProbeDisposition::RestartWait,
            Some(HeldSubmit {
                tx_hash: held.tx_hash,
                baseline_height: probe_height,
                probed_this_epoch: false,
            }),
        ),
        ProbeOutcome::PresentInPool => (
            ProbeDisposition::Alarm(AlarmReason::PresentButUnconfirmedPastHorizon),
            Some(HeldSubmit {
                probed_this_epoch: true,
                ..*held
            }),
        ),
        ProbeOutcome::ConfirmedInChain => (
            ProbeDisposition::KeepHolding,
            // Restart the wait epoch outright — both the baseline AND the
            // probed flag. Advancing only the baseline (leaving
            // `probed_this_epoch: true`) still let escape_ladder_step jump
            // *straight to* the alarm rung once a fresh horizon elapsed:
            // `probed_this_epoch` short-circuits the probe, so the
            // re-escalation would raise
            // OperatorAlarm(PresentButUnconfirmedPastHorizon) on a tx last
            // *observed confirmed* — a stale-info alarm whose reason is
            // factually wrong, and exactly the alarm-fatigue §5.3 warns
            // against. Clearing the flag keeps that alarm rung specific to the
            // present-but-unconfirmed branch: KeepHolding's documented "alarm
            // only if the horizon elapses again" still holds, but every
            // re-escalation is routed through a *fresh probe* first — which
            // re-reads presence and only alarms if the tx is genuinely
            // present-but-unconfirmed (a deep reorg back to the pool), restarts
            // on eviction, or resets the epoch again if still in-chain. The
            // normal path needs none of this: refresh clears the F14 lock via
            // mark_spent well within one horizon and the entry drops from the
            // projection.
            Some(HeldSubmit {
                tx_hash: held.tx_hash,
                baseline_height: probe_height,
                probed_this_epoch: false,
            }),
        ),
        ProbeOutcome::RejectedTerminal => (ProbeDisposition::ReleaseConfirmedAbsent, None),
    }
}

// ---------------------------------------------------------------------------
// Confirmed-absent release (§2.6 release path 2)
// ---------------------------------------------------------------------------

/// Release the F14 awaiting-confirmation locks held under any txid in
/// `tx_hashes` (the confirmed-absent leg of §2.6: the tx provably never
/// confirmed — definite terminal verdict on the probe, or operator-directed
/// release after the alarm rung). Returns the number of carried-input
/// locks the release cleared from the derived view.
///
/// Since PR-SJ-1b the release is journal-only: `mark_presumed_dead`
/// flips the display state (`Dispatched → PresumedDead`; an `Abandoned`
/// row keeps its user-authored state) and clears `lock_baseline`, which
/// removes the row's carried inputs from
/// `SendJournalBlock::spend_locks` — there is no per-transfer
/// field left to clear. A late confirmation flips the row to
/// `Confirmed` through the merge reconciler, loudly un-presuming it.
///
/// The confirmed-**present** leg needs no code at all: every derived-
/// view consumer checks `spent` first, so refresh-observed confirmation
/// supersedes structurally. This function must never run for a tx that
/// might still confirm — the caller owns that proof (§2.6 invariant 2's
/// "definite verdict or observed absence"). Release makes the outputs
/// selectable again; it does **not** authorize an automatic rebuild
/// (§2.6 invariant 3 / §7.4).
pub(crate) fn release_awaiting_confirmation(
    wallet: &mut shekyl_engine_state::WalletLedger,
    tx_hashes: &HashSet<TxHash>,
) -> usize {
    if tx_hashes.is_empty() {
        return 0;
    }
    let mut released = 0;
    for txid in tx_hashes {
        let key = txid.to_bytes();
        let held_inputs = wallet
            .send_journal
            .rows
            .get(&key)
            .filter(|row| row.state.locks_carried_inputs() && row.lock_baseline.is_some())
            .map_or(0, |row| row.inputs.len());
        wallet.send_journal.mark_presumed_dead(&key);
        released += held_inputs;
    }
    released
}

/// The origin's shipped retry, in seconds.
///
/// `shekyl-relay`'s `origin_retry_secs` derives it (the 1-in-`origin_retry_one_in`
/// survival quantile of the adopted anonymity timer) and that crate's embargo
/// tests pin the derivation equal to this value. This crate does not link the
/// relay scheduler, so the seconds are spelled here. The submit watchdog's
/// lower bound and the regtest embargo walks are the two readers; a move of
/// the derivation updates the relay's pin and this spelling in one change.
#[cfg(test)]
pub(crate) const SHIPPED_ORIGIN_RETRY_SECS: u64 = 1_148;

#[cfg(test)]
#[path = "submit_watchdog_tests.rs"]
mod tests;
