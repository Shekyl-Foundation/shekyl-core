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
//! The rungs are presence-conditional (round-6 minor b). The probe
//! returns the daemon's relay state. **Held** waits. **Held-overdue**
//! alarms: the daemon already judged that on its own clock. **Published**
//! and unmined past the fee ladder's lookback alarms as published, not
//! mined. **Absent** resubmits, and that resubmit is the remedy.
//! **In chain** keeps holding for refresh. Two clocks, never converted:
//! block counts are what consensus defines, and overdue is not one of
//! them. Terminal verdicts on the probe resolve the wait per §2.5/§2.6.

// The kernel's production consumer is the §5.3 submit lifecycle driver
// ([`submit_lifecycle`](super::submit_lifecycle)), reached from the public
// [`Engine::run_submit_lifecycle_tick`](super::Engine::run_submit_lifecycle_tick)
// entry point: the driver wires `held_submits` → `escape_ladder_step` →
// probe → `apply_probe_outcome` / `release_awaiting_confirmation` into the
// lifecycle. The former `#![allow(dead_code)]` (landed-inert scaffolding) is
// lifted now that the driver makes every kernel surface live.

use std::collections::HashSet;

use shekyl_curve_tree::DISPATCHED_PROOF_LIFE;
use shekyl_economics::RELAY_FLOOR_LOOKBACK;
use shekyl_types::TxHash;

use super::traits::DaemonHealth;

// ---------------------------------------------------------------------------
// Block counts. The daemon's clock is not one of them.
// ---------------------------------------------------------------------------

/// Blocks spared at the end of [`DISPATCHED_PROOF_LIFE`] so the probe is
/// in flight while the same bytes are still submittable.
///
/// **Assumption — never measured.** The proof-life derivation leaves one
/// block out of the theoretical span for blocks that can land between the
/// wallet's staleness check and the daemon's verdict. This margin spends
/// that block. It is not a measured refresh lag, and it is not a duration.
pub(crate) const PROBE_REFRESH_LAG_BLOCKS: u64 = 1;

/// Watchdog tunables. Production is [`Self::DEFAULT`]; tests build their
/// own to exercise the ladder at other ceilings.
///
/// Block counts only. Whether an origin is overdue is the daemon's
/// judgment, returned as relay state. This kernel never reads a duration
/// and never compares a block count with one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WatchdogConfig {
    /// Blocks past the accept baseline at which the kernel probes,
    /// whatever relay state it last saw.
    ///
    /// [`DISPATCHED_PROOF_LIFE`] minus [`PROBE_REFRESH_LAG_BLOCKS`]. Past
    /// the life the pool may already have removed the transaction
    /// (CEN-M10) and the probe comes back `StaleRoot`.
    pub probe_ceiling_blocks: u64,
    /// Blocks a published, unmined transaction may sit before the
    /// "published, not mined" alarm.
    ///
    /// **Assumption — never measured.** Basis: [`RELAY_FLOOR_LOOKBACK`],
    /// the fee ladder's quote-to-broadcast gap (a quote at `F(h)` is
    /// admitted while the tip lies in `[h, h+G]`). Not a conversion of
    /// that gap into seconds.
    pub published_unmined_blocks: u64,
}

impl WatchdogConfig {
    /// The production configuration.
    // CLIPPY: cast_possible_truncation — the lookback is 5 blocks.
    #[allow(clippy::cast_possible_truncation)]
    pub(crate) const DEFAULT: Self = Self {
        probe_ceiling_blocks: DISPATCHED_PROOF_LIFE.to_raw() - PROBE_REFRESH_LAG_BLOCKS,
        published_unmined_blocks: RELAY_FLOOR_LOOKBACK as u64,
    };
}

// A zero ceiling probes on the first check. A ceiling at or past the
// dispatched proof's life probes bytes the daemon may already refuse. A
// published-unmined count that meets the ceiling collapses the two block
// questions into one. Any of those is a broken constant, caught here.
const _: () = assert!(WatchdogConfig::DEFAULT.probe_ceiling_blocks > 0);
const _: () =
    assert!(WatchdogConfig::DEFAULT.probe_ceiling_blocks < DISPATCHED_PROOF_LIFE.to_raw());
const _: () = assert!(WatchdogConfig::DEFAULT.published_unmined_blocks > 0);
const _: () = assert!(
    WatchdogConfig::DEFAULT.published_unmined_blocks < WatchdogConfig::DEFAULT.probe_ceiling_blocks
);

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
    /// The height baseline the block counts run from: the wallet synced
    /// height when the accepting verdict was observed, advanced to the
    /// probe height when an absent-probe resubmission restarts the wait.
    pub baseline_height: u64,
    /// The relay state the last probe in this wait epoch reported.
    /// Fresh projections are [`PoolSight::Unseen`].
    pub pool_sight: PoolSight,
}

/// What the last owner-tier probe reported about one held transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum PoolSight {
    /// No probe this wait epoch has reported a relay state.
    #[default]
    Unseen,
    /// The daemon holds it, inside its publication budget.
    Held,
    /// The daemon holds it past its publication budget.
    HeldOverdue,
    /// The daemon has published it. Mining is a block count.
    Published,
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
/// Fresh projections carry [`PoolSight::Unseen`]; the driving actor
/// overlays its in-memory relay state across refresh cycles.
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
                pool_sight: PoolSight::Unseen,
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
    /// The probe ceiling has not elapsed, and nothing already observed
    /// calls for an alarm.
    CeilingNotReached,
    /// A block-count arm fired, but the daemon is behind the network:
    /// "unconfirmed at this daemon" is uninformative until it syncs
    /// (the same sync-gating shape as the `ReferenceNotFound`
    /// disposition, §2.5).
    DaemonSyncing,
}

/// Why the kernel escalated to the operator-alarm rung.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AlarmReason {
    /// The daemon holds the transaction past its own publication budget.
    /// No block count enters this decision.
    HeldOverdue,
    /// Published, and unmined for [`WatchdogConfig::published_unmined_blocks`].
    /// The eclipse case (§7.5) after a fluff lands here.
    PublishedUnmined,
    /// The daemon reports no peers: relay is impossible and no wallet
    /// action can fix it — the alarm rung carries the decision to the
    /// operator (§2.6 invariant 2).
    DaemonPeerless,
    /// The daemon was started offline (`--offline`): it relays nothing
    /// by configuration, which only the operator can change.
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
    // The daemon's clock. This arm returns before any block count is read.
    // Offline and peerless still outrank it: the daemon cannot relay.
    // Sync does not: an origin past its budget is late whether or not
    // this node has the chain tip.
    if held.pool_sight == PoolSight::HeldOverdue {
        if let Some(step) = relay_impossible(health) {
            return step;
        }
        return WatchdogStep::OperatorAlarm(AlarmReason::HeldOverdue);
    }

    let age = synced_height.saturating_sub(held.baseline_height);
    if held.pool_sight == PoolSight::Published && age >= config.published_unmined_blocks {
        return health_gated(
            health,
            WatchdogStep::OperatorAlarm(AlarmReason::PublishedUnmined),
        );
    }
    if age >= config.probe_ceiling_blocks {
        return health_gated(health, WatchdogStep::ProbeResubmitSameBytes);
    }
    WatchdogStep::Wait(WaitReason::CeilingNotReached)
}

/// Offline or peerless: the daemon cannot relay. Peerlessness is not
/// masked by "syncing" — a daemon with no peers cannot sync either.
fn relay_impossible(health: DaemonHealth) -> Option<WatchdogStep> {
    match health.p2p {
        shekyl_rpc_types::HealthP2p::Offline => {
            Some(WatchdogStep::OperatorAlarm(AlarmReason::DaemonOffline))
        }
        shekyl_rpc_types::HealthP2p::Running { has_peers: false } => {
            Some(WatchdogStep::OperatorAlarm(AlarmReason::DaemonPeerless))
        }
        shekyl_rpc_types::HealthP2p::Running { has_peers: true } => None,
    }
}

/// [`relay_impossible`], then a sync wait. Block-count arms use this.
/// The facts are [`DaemonHealth`]'s fields. The ladder does not keep a
/// second reading of them. A withheld-blocks stall is the cadence
/// chain-progress watchdog, not an arm here.
fn health_gated(health: DaemonHealth, step: WatchdogStep) -> WatchdogStep {
    if let Some(blocked) = relay_impossible(health) {
        return blocked;
    }
    if !health.synchronized {
        return WatchdogStep::Wait(WaitReason::DaemonSyncing);
    }
    step
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
    /// `AlreadyInPool { relay: held }`. Inside the daemon's budget.
    /// Asking again is a status query (F31) and not an alarm.
    Held,
    /// `AlreadyInPool { relay: held_overdue }`. The daemon's clock.
    HeldOverdue,
    /// `AlreadyInPool { relay: published }`. Mining is a block count.
    Published,
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
    /// Escalate to the alarm rung.
    Alarm(AlarmReason),
}

/// Apply a probe outcome to a held entry, returning the disposition and
/// the updated tracking entry (`None` when tracking ends).
pub(crate) fn apply_probe_outcome(
    held: &HeldSubmit,
    outcome: ProbeOutcome,
    probe_height: u64,
    config: WatchdogConfig,
) -> (ProbeDisposition, Option<HeldSubmit>) {
    match outcome {
        ProbeOutcome::ReofferedAfterAbsence => (
            ProbeDisposition::RestartWait,
            Some(fresh_epoch(held.tx_hash, probe_height)),
        ),
        ProbeOutcome::Held => (
            ProbeDisposition::KeepHolding,
            Some(HeldSubmit {
                pool_sight: PoolSight::Held,
                ..*held
            }),
        ),
        ProbeOutcome::HeldOverdue => (
            ProbeDisposition::Alarm(AlarmReason::HeldOverdue),
            Some(HeldSubmit {
                pool_sight: PoolSight::HeldOverdue,
                ..*held
            }),
        ),
        ProbeOutcome::Published => {
            let next = HeldSubmit {
                pool_sight: PoolSight::Published,
                ..*held
            };
            let age = probe_height.saturating_sub(held.baseline_height);
            if age >= config.published_unmined_blocks {
                (
                    ProbeDisposition::Alarm(AlarmReason::PublishedUnmined),
                    Some(next),
                )
            } else {
                (ProbeDisposition::KeepHolding, Some(next))
            }
        }
        ProbeOutcome::ConfirmedInChain => (
            ProbeDisposition::KeepHolding,
            // Restart the wait epoch: baseline and sight. Keeping a stale
            // `HeldOverdue` would alarm on the next tick about a transaction
            // last observed in chain. The next escalation probes again.
            Some(fresh_epoch(held.tx_hash, probe_height)),
        ),
        ProbeOutcome::RejectedTerminal => (ProbeDisposition::ReleaseConfirmedAbsent, None),
    }
}

fn fresh_epoch(tx_hash: TxHash, baseline_height: u64) -> HeldSubmit {
    HeldSubmit {
        tx_hash,
        baseline_height,
        pool_sight: PoolSight::Unseen,
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

#[cfg(test)]
#[path = "submit_watchdog_tests.rs"]
mod tests;
