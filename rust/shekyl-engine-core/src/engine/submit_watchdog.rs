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
//! The rungs are presence-conditional (round-6 minor b). One function,
//! [`escape_ladder_step`], is the alarm policy. The driver calls it
//! before a probe and again after the sight is written. A probe that
//! the second call asks for waits until the next chain advance.
//!
//! **Unread, held, and published-under-lookback** are asked on the
//! tick, including while the daemon is still syncing. **Held-overdue**
//! and **untracked** alarm on the tick they are seen: the daemon
//! already judged overdue, and a missing origin row is not a hold.
//! **Published** measures the fee ladder's lookback from the height
//! publication was first observed. The first observation does not
//! alarm. Sync gates only that published-unmined alarm. **In chain**
//! waits until the proof-life ceiling, then asks again; under the
//! ceiling it does not read health. Two clocks, never converted:
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
use shekyl_rpc_client::Publication;

use crate::engine::traits::daemon::DaemonP2p;
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

/// Blocks after an in-chain observation before the kernel asks again.
///
/// [`DISPATCHED_PROOF_LIFE`] minus [`PROBE_REFRESH_LAG_BLOCKS`]. This is
/// the last moment the same bytes are still submittable (CEN-M10), so
/// an in-chain sight is re-probed then. It is not the first moment the
/// wallet may ask: an unread, held, or recently published transaction
/// is asked on the next chain advance.
pub(crate) const PROBE_CEILING_BLOCKS: u64 =
    DISPATCHED_PROOF_LIFE.to_raw() - PROBE_REFRESH_LAG_BLOCKS;

/// Watchdog tunables. Production is [`WatchdogConfig::production`]; tests
/// build their own to exercise the ladder at other ceilings.
///
/// Block counts only. Whether an origin is overdue is the daemon's
/// judgment, returned as relay state. This kernel never reads a duration
/// and never compares a block count with one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WatchdogConfig {
    /// Blocks after an in-chain observation before the kernel asks
    /// again. Production is [`PROBE_CEILING_BLOCKS`].
    pub probe_ceiling_blocks: u64,
    /// Blocks since publication was first observed before the
    /// "published, not mined" alarm.
    ///
    /// **Assumption — never measured.** Basis: the fee ladder's lookback
    /// on the shipped relay policy ([`shekyl_economics::relay_policy()`]).
    /// A quote at `F(h)` is admitted while the tip lies in `[h, h+G]`.
    /// Not a conversion of that gap into seconds.
    pub published_unmined_blocks: u64,
}

impl WatchdogConfig {
    /// The production configuration.
    ///
    /// The ceiling is the dispatched proof's life minus the refresh-lag
    /// margin. The published-unmined count is the shipped relay policy's
    /// lookback. A lookback that meets the ceiling collapses the two
    /// block questions into one; [`Self::production`] rejects that in
    /// debug, and the kernel test holds it for the shipped policy.
    #[must_use]
    pub(crate) fn production() -> Self {
        let published_unmined_blocks = shekyl_economics::relay_policy().lookback;
        debug_assert!(published_unmined_blocks > 0);
        debug_assert!(published_unmined_blocks < PROBE_CEILING_BLOCKS);
        Self {
            probe_ceiling_blocks: PROBE_CEILING_BLOCKS,
            published_unmined_blocks,
        }
    }
}

// A zero ceiling probes on the first check. A ceiling at or past the
// dispatched proof's life probes bytes the daemon may already refuse.
// Either is a broken constant, caught here. The lookback is not a
// constant of this crate, so its place under the ceiling is checked
// where `WatchdogConfig::production` reads it.
const _: () = assert!(PROBE_CEILING_BLOCKS > 0);
const _: () = assert!(PROBE_CEILING_BLOCKS < DISPATCHED_PROOF_LIFE.to_raw());

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
    /// The height the in-chain wait runs from. A fresh projection is
    /// the accept height. A resubmit and an in-chain observation
    /// advance it to the probe height.
    pub baseline_height: u64,
    /// What the last probe in this wait reported. Fresh projections
    /// are [`RelaySight::Unread`].
    pub relay: RelaySight,
}

/// What the last owner-tier probe reported about one held transaction.
///
/// [`Self::Published::at`] is the synced height of the first probe
/// that reported publication. A later published answer keeps it, so
/// the lookback does not start at the accept baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum RelaySight {
    /// No probe this wait has reported a relay state.
    #[default]
    Unread,
    /// The daemon holds it, inside its publication budget.
    Held,
    /// The daemon holds it past its publication budget.
    HeldOverdue,
    /// The daemon has published it. `at` is the first observation.
    Published { at: u64 },
    /// Pool-resident, and the zone holds no origin row.
    Untracked,
    /// Last observed in the chain. Refresh remains the settlement
    /// authority. The next probe waits out [`PROBE_CEILING_BLOCKS`].
    InChain,
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
/// Fresh projections carry [`RelaySight::Unread`]; the driving actor
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
                relay: RelaySight::Unread,
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
    /// Last seen in the chain, and the proof-life ceiling has not
    /// elapsed. Asking again teaches nothing until those bytes might
    /// have left the pool.
    InChain,
    /// Published long enough to alarm, but the daemon is behind the
    /// network. "Unmined at this daemon" is uninformative until it
    /// syncs (the same sync-gating shape as the `ReferenceNotFound`
    /// disposition, §2.5).
    DaemonSyncing,
}

/// Why the kernel escalated to the operator-alarm rung.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AlarmReason {
    /// The daemon holds the transaction past its own publication budget.
    /// No block count enters this decision.
    HeldOverdue,
    /// Pool-resident, and the zone holds no origin row. A watchdog
    /// probe is at least one block after admit, so this is not the
    /// admit race.
    OriginUntracked,
    /// Published, and unmined for [`WatchdogConfig::published_unmined_blocks`]
    /// since publication was first observed. The eclipse case (§7.5)
    /// after a fluff lands here.
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
///
/// The driver calls this before a probe and again on the sight the
/// probe recorded. A [`WatchdogStep::ProbeResubmitSameBytes`] from the
/// second call is not a second round-trip in the same tick.
pub(crate) fn escape_ladder_step(
    held: &HeldSubmit,
    synced_height: u64,
    health: DaemonHealth,
    config: WatchdogConfig,
) -> WatchdogStep {
    match held.relay {
        // A confirmed observation does not need the relay. Health is
        // read only when the ceiling says the bytes might be submittable
        // again.
        RelaySight::InChain
            if blocks_since(synced_height, held.baseline_height) < config.probe_ceiling_blocks =>
        {
            WatchdogStep::Wait(WaitReason::InChain)
        }
        RelaySight::HeldOverdue => alarm_unless_blocked(health, AlarmReason::HeldOverdue),
        RelaySight::Untracked => alarm_unless_blocked(health, AlarmReason::OriginUntracked),
        RelaySight::Published { at }
            if blocks_since(synced_height, at) >= config.published_unmined_blocks =>
        {
            published_unmined(health)
        }
        RelaySight::Unread
        | RelaySight::Held
        | RelaySight::Published { .. }
        | RelaySight::InChain => probe_unless_blocked(health),
    }
}

fn blocks_since(synced_height: u64, observed_at: u64) -> u64 {
    synced_height.saturating_sub(observed_at)
}

/// Offline or peerless: the daemon cannot relay. Peerlessness is not
/// masked by "syncing" — a daemon with no peers cannot sync either.
fn relay_impossible(health: DaemonHealth) -> Option<WatchdogStep> {
    match health.p2p {
        DaemonP2p::Offline => Some(WatchdogStep::OperatorAlarm(AlarmReason::DaemonOffline)),
        DaemonP2p::Running { has_peers: false } => {
            Some(WatchdogStep::OperatorAlarm(AlarmReason::DaemonPeerless))
        }
        DaemonP2p::Running { has_peers: true } => None,
    }
}

/// Offline or peerless outranks the alarm. Sync does not: an origin
/// past its budget, or a pool row with no origin, is late whether or
/// not this node has the chain tip.
fn alarm_unless_blocked(health: DaemonHealth, reason: AlarmReason) -> WatchdogStep {
    relay_impossible(health).unwrap_or(WatchdogStep::OperatorAlarm(reason))
}

/// A status read is a local relay fact. It is valid while the daemon
/// is still syncing. Offline and peerless outrank it.
fn probe_unless_blocked(health: DaemonHealth) -> WatchdogStep {
    relay_impossible(health).unwrap_or(WatchdogStep::ProbeResubmitSameBytes)
}

/// The lookback has elapsed since publication was first observed.
/// Relay-blocked outranks the alarm. Sync gates only this alarm.
fn published_unmined(health: DaemonHealth) -> WatchdogStep {
    if let Some(blocked) = relay_impossible(health) {
        return blocked;
    }
    if !health.synchronized {
        return WatchdogStep::Wait(WaitReason::DaemonSyncing);
    }
    WatchdogStep::OperatorAlarm(AlarmReason::PublishedUnmined)
}

// ---------------------------------------------------------------------------
// Probe-outcome application
// ---------------------------------------------------------------------------

/// The probe's verdict, projected onto the presence facts the ladder
/// branches on (round-6 minor b). Recording a sight does not alarm.
/// [`escape_ladder_step`] is the only alarm policy, and it reads the
/// sight this function writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeOutcome {
    /// `Accepted`: the tx was absent (evicted / never landed) and the
    /// resubmission *was* the remedy — re-offered through full admission
    /// and fresh relay.
    ReofferedAfterAbsence,
    /// `AlreadyInPool`. The relay state is the daemon's.
    InPool(Publication),
    /// `AlreadyInChain`: confirmation observed by verdict; refresh
    /// remains the settlement authority (§2.5).
    ConfirmedInChain,
    /// `Rejected{*}`: a definite terminal verdict — under single-egress
    /// this proves the bytes are in neither pool nor chain (§7.1).
    RejectedTerminal,
}

/// What the driving actor does with a recorded probe. The alarm, if
/// the new sight calls for one, is [`escape_ladder_step`] on the
/// continued entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeDisposition {
    /// Keep the recorded sight. The caller judges it.
    Continue(HeldSubmit),
    /// Confirmed-absent resolution (§2.6 release path 2): the definite
    /// verdict proves the tx is gone; release the F14 locks via
    /// [`release_awaiting_confirmation`]. **Release is not rebuild
    /// authorization** (§2.6 invariant 3).
    ReleaseConfirmedAbsent,
}

/// Record a probe outcome onto a held entry. This does not alarm.
pub(crate) fn apply_probe_outcome(
    held: &HeldSubmit,
    outcome: ProbeOutcome,
    probe_height: u64,
) -> ProbeDisposition {
    match outcome {
        ProbeOutcome::ReofferedAfterAbsence => ProbeDisposition::Continue(HeldSubmit {
            baseline_height: probe_height,
            relay: RelaySight::Held,
            ..*held
        }),
        ProbeOutcome::InPool(relay) => ProbeDisposition::Continue(HeldSubmit {
            relay: sight_after_pool(held.relay, relay, probe_height),
            ..*held
        }),
        ProbeOutcome::ConfirmedInChain => ProbeDisposition::Continue(HeldSubmit {
            baseline_height: probe_height,
            relay: RelaySight::InChain,
            ..*held
        }),
        ProbeOutcome::RejectedTerminal => ProbeDisposition::ReleaseConfirmedAbsent,
    }
}

/// Map the daemon's relay state onto the sight the ladder reads.
///
/// A published answer keeps the first observation height. Every other
/// relay state replaces the sight.
fn sight_after_pool(previous: RelaySight, relay: Publication, probe_height: u64) -> RelaySight {
    match relay {
        Publication::Held => RelaySight::Held,
        Publication::Overdue => RelaySight::HeldOverdue,
        Publication::Untracked => RelaySight::Untracked,
        Publication::Public => RelaySight::Published {
            at: match previous {
                RelaySight::Published { at } => at,
                RelaySight::Unread
                | RelaySight::Held
                | RelaySight::HeldOverdue
                | RelaySight::Untracked
                | RelaySight::InChain => probe_height,
            },
        },
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
