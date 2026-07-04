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
//! privacy-tiered escape ladder with presence branching, health-context
//! consumption, and the horizon bound — with no driver attached. The
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

// Landed inert (same pattern as `stake_engine` / `stake_persist`): the
// kernel's production consumer is the wallet-plan watchdog actor; until it
// lands, the §10 item 8 tests are the only callers. The allow lifts when
// the actor wires `held_submits` → `escape_ladder_step` → probe →
// `apply_probe_outcome` / `release_awaiting_confirmation` into the
// lifecycle.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

use shekyl_engine_state::LedgerBlock;
use shekyl_types::TxHash;

// ---------------------------------------------------------------------------
// Horizon configuration
// ---------------------------------------------------------------------------

/// The daemon stops re-relaying a pool tx at half the pool lifetime —
/// 1.5 days of the 3-day `CRYPTONOTE_MEMPOOL_TX_LIVETIME`
/// (§5.2 item 1, source-verified at `tx_pool.cpp:851-852`).
const DAEMON_RE_RELAY_CUTOFF_SECONDS: u64 = 3 * 86_400 / 2;

/// Watchdog tunables. Constructed via [`Self::from_block_target`] so the
/// horizon is derived from the consensus block target rather than
/// hard-coding a block count that silently rots if the target changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WatchdogConfig {
    /// Escape horizon, in blocks past the accepting verdict's height,
    /// after which a still-unconfirmed held tx enters the escape ladder.
    ///
    /// **Default rationale (F35 + rule 75):** two binding constraints.
    /// *Upper bound:* the horizon must fire **before** the daemon's
    /// 1.5-day re-relay cutoff — between 1.5 days and the 3-day eviction
    /// a pool tx is held-but-no-longer-re-relayed, so a later watchdog
    /// inspects a tx the daemon has already stopped offering. *Lower
    /// bound:* the horizon must not be so short that ordinary
    /// confirmation latency or a short partition trips the ladder — the
    /// timeout is itself an attack surface (§5.3), so spurious firings
    /// are alarm fatigue an adversary can hide inside. The default is
    /// **half the re-relay cutoff** (~18 h at a 120 s target): 2×
    /// safety margin against the upper bound (covering wallet refresh
    /// lag and wallet–daemon height skew), while sized for the
    /// anon-network eclipse case (§7.5) where this watchdog is the
    /// *only* backstop — the origin's embargo timer does not arm over
    /// noise zones, so waiting longer than necessary extends the
    /// black-hole exposure window with no compensating benefit.
    ///
    /// Safe-adjustment bounds: strictly below
    /// `DAEMON_RE_RELAY_CUTOFF_SECONDS / block_target` (upper), and
    /// comfortably above the wallet's `max_reorg_depth` plus its refresh
    /// cadence in blocks (lower).
    pub escape_horizon_blocks: u64,
}

impl WatchdogConfig {
    /// Derive the default configuration from the consensus block target
    /// (`daa_target_seconds`, generated from `config/consensus_constants.json`).
    ///
    /// A zero target is a broken consensus constant, not a runtime
    /// condition to degrade around: a silent `max(1)` fallback would
    /// compute a horizon that blows past the F35 re-relay upper bound.
    /// Loud failure, release builds included — and the same discipline
    /// applies to the *derived* horizon, not just the input: a
    /// `block_target_seconds` large enough that the integer division
    /// floors `escape_horizon_blocks` to zero is the identical failure
    /// mode (a broken consensus constant) wearing a different input
    /// value. A zero horizon means every held tx is "past horizon" on
    /// the very first check, jumping straight to the escape ladder —
    /// silently disabling the wait rung entirely.
    pub(crate) fn from_block_target(block_target_seconds: u64) -> Self {
        assert!(block_target_seconds > 0, "block target must be positive");
        let escape_horizon_blocks = DAEMON_RE_RELAY_CUTOFF_SECONDS / 2 / block_target_seconds;
        assert!(
            escape_horizon_blocks > 0,
            "block target {block_target_seconds}s yields a zero-block escape horizon \
             (re-relay cutoff / 2 = {}s) — broken consensus constant",
            DAEMON_RE_RELAY_CUTOFF_SECONDS / 2
        );
        Self {
            escape_horizon_blocks,
        }
    }
}

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

/// Project the held-submit set from the ledger's F14 locks, one entry
/// per distinct awaited txid (a tx spending several inputs places one
/// lock per input; the earliest accepted height is the conservative
/// horizon baseline).
///
/// Fresh projections carry `probed_this_epoch: false`; the driving
/// actor overlays its in-memory probe state across refresh cycles.
pub(crate) fn held_submits(ledger: &LedgerBlock) -> Vec<HeldSubmit> {
    // Single pass: a txid → slot index keeps the grouping O(transfers)
    // instead of O(transfers × distinct-held-txids), while first-seen Vec
    // order is preserved (deterministic projection).
    let mut held: Vec<HeldSubmit> = Vec::new();
    let mut slot: HashMap<TxHash, usize> = HashMap::new();
    for td in ledger.transfers() {
        let Some(awaiting) = &td.awaiting_confirmation else {
            continue;
        };
        match slot.get(&awaiting.tx_hash) {
            Some(&i) => {
                held[i].baseline_height = held[i].baseline_height.min(awaiting.accepted_at_height);
            }
            None => {
                slot.insert(awaiting.tx_hash, held.len());
                held.push(HeldSubmit {
                    tx_hash: awaiting.tx_hash,
                    baseline_height: awaiting.accepted_at_height,
                    probed_this_epoch: false,
                });
            }
        }
    }
    held
}

// ---------------------------------------------------------------------------
// Health context (§5.2 item 3, trust rider §7.2)
// ---------------------------------------------------------------------------

/// The daemon health facts the ladder consumes, distinguishing "tx
/// stuck" from "daemon has no peers to relay to" and "daemon is behind."
/// Contract-accurate fields of the existing info surface; no new RPC.
///
/// Trust classification (§7.2): trusted under the own-daemon V3.0
/// deployment model; **untrusted** under the multi-daemon reopen — a
/// lying "I'm healthy" makes the wallet wait on a non-propagating tx,
/// a lying sync height flips backoff at will. The damage cap is rung
/// 2: health context can delay escalation, never trigger a rebuild.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DaemonHealthContext {
    /// Outgoing + incoming connection count.
    pub connections: u64,
    /// The daemon's current chain height.
    pub height: u64,
    /// The daemon's network-estimated target height (0 when synced —
    /// the info surface's convention).
    pub target_height: u64,
}

impl DaemonHealthContext {
    /// The daemon believes it is synced with the network.
    fn is_synced(&self) -> bool {
        self.target_height == 0 || self.height >= self.target_height
    }

    /// The daemon has someone to relay to.
    fn has_peers(&self) -> bool {
        self.connections > 0
    }
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
    health: DaemonHealthContext,
    config: WatchdogConfig,
) -> WatchdogStep {
    let past_horizon =
        synced_height.saturating_sub(held.baseline_height) >= config.escape_horizon_blocks;
    if !past_horizon {
        return WatchdogStep::Wait(WaitReason::HorizonNotReached);
    }
    // Health-context gate (§5.2 item 3): separate "tx stuck" from
    // daemon-side conditions before spending a rung. Peerlessness is checked
    // BEFORE sync: a daemon with no peers can neither sync nor relay, so the
    // actionable operator-only condition (DaemonPeerless) must not be masked
    // by the transient DaemonSyncing wait when the daemon is both behind and
    // peerless.
    if !health.has_peers() {
        return WatchdogStep::OperatorAlarm(AlarmReason::DaemonPeerless);
    }
    if !health.is_synced() {
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
/// release after the alarm rung), in a **single** ledger scan regardless of
/// how many txids a cadence tick resolves. Returns the number of locks
/// released.
///
/// The confirmed-**present** leg lives in
/// `shekyl_engine_state::LedgerIndexes::mark_spent` (refresh observes
/// the spend on-chain and supersedes the lock); this function must
/// never run for a tx that might still confirm — the caller owns that
/// proof (§2.6 invariant 2's "definite verdict or observed absence").
/// Release makes the outputs selectable again; it does **not**
/// authorize an automatic rebuild (§2.6 invariant 3 / §7.4).
pub(crate) fn release_awaiting_confirmation(
    ledger: &mut LedgerBlock,
    tx_hashes: &HashSet<TxHash>,
) -> usize {
    if tx_hashes.is_empty() {
        return 0;
    }
    let mut released = 0;
    for td in &mut ledger.transfers {
        if td
            .awaiting_confirmation
            .as_ref()
            .is_some_and(|a| tx_hashes.contains(&a.tx_hash))
        {
            td.awaiting_confirmation = None;
            released += 1;
        }
    }
    released
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_engine_state::{AwaitingConfirmation, TransferDetails, SPENDABLE_AGE};

    const CFG: WatchdogConfig = WatchdogConfig {
        escape_horizon_blocks: 540,
    };

    /// Minimal transfer fixture carrying an optional F14 lock.
    fn transfer_with_lock(seed: u8, lock: Option<AwaitingConfirmation>) -> TransferDetails {
        use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar};
        TransferDetails {
            tx_hash: TxHash::from_bytes([seed; 32]),
            internal_output_index: u64::from(seed),
            global_output_index: u64::from(seed),
            block_height: 100,
            key: ED25519_BASEPOINT_POINT,
            key_offset: Scalar::ONE,
            commitment: shekyl_curve_primitives::Commitment::new(Scalar::ONE, 1_000),
            payment_id: None,
            spent: false,
            spent_height: None,
            key_image: None,
            awaiting_confirmation: lock,
            source_ciphertext: None,
            output_handle: None,
            eligible_height: 100 + SPENDABLE_AGE,
            frozen: false,
            fcmp_precomputed_path: None,
            receive_attribution: shekyl_engine_state::ReceiveAttribution::default(),
        }
    }

    fn ledger_with(transfers: Vec<TransferDetails>) -> LedgerBlock {
        LedgerBlock::new(
            transfers,
            shekyl_engine_state::BlockchainTip::new(5_000, [0xAA; 32]),
            shekyl_engine_state::ReorgBlocks::default(),
        )
    }

    /// Held tracking projects one entry per awaited txid, keyed on the
    /// F14 locks, with the earliest accepted height as the baseline.
    #[test]
    fn held_submits_projects_locks_grouped_by_txid() {
        let awaited = TxHash::from_bytes([0xBB; 32]);
        let ledger = ledger_with(vec![
            // Two inputs of the same awaited tx, different accept heights.
            transfer_with_lock(
                1,
                Some(AwaitingConfirmation {
                    tx_hash: awaited,
                    accepted_at_height: 4_000,
                }),
            ),
            transfer_with_lock(
                2,
                Some(AwaitingConfirmation {
                    tx_hash: awaited,
                    accepted_at_height: 3_900,
                }),
            ),
            // Unrelated unlocked output.
            transfer_with_lock(3, None),
        ]);

        let held = held_submits(&ledger);
        assert_eq!(held.len(), 1, "one entry per awaited txid");
        assert_eq!(held[0].tx_hash, awaited);
        assert_eq!(
            held[0].baseline_height, 3_900,
            "earliest accept height is the conservative baseline"
        );
        assert!(!held[0].probed_this_epoch);
    }

    /// §2.6 confirmed-absent release: locks under the named txid are
    /// released (outputs selectable again); other locks untouched.
    #[test]
    fn release_confirmed_absent_clears_only_the_named_tx() {
        let gone = TxHash::from_bytes([0xCC; 32]);
        let still_held = TxHash::from_bytes([0xDD; 32]);
        let lock = |h| {
            Some(AwaitingConfirmation {
                tx_hash: h,
                accepted_at_height: 4_000,
            })
        };
        let mut ledger = ledger_with(vec![
            transfer_with_lock(1, lock(gone)),
            transfer_with_lock(2, lock(gone)),
            transfer_with_lock(3, lock(still_held)),
        ]);

        assert_eq!(
            release_awaiting_confirmation(&mut ledger, &HashSet::from([gone])),
            2
        );
        assert!(ledger.transfers()[0].is_spendable(u64::MAX));
        assert!(ledger.transfers()[1].is_spendable(u64::MAX));
        assert!(
            !ledger.transfers()[2].is_spendable(u64::MAX),
            "unrelated lock survives"
        );
        assert_eq!(held_submits(&ledger).len(), 1);
    }

    fn healthy() -> DaemonHealthContext {
        DaemonHealthContext {
            connections: 8,
            height: 10_000,
            target_height: 0,
        }
    }

    fn held(baseline: u64) -> HeldSubmit {
        HeldSubmit {
            tx_hash: TxHash::from_bytes([7; 32]),
            baseline_height: baseline,
            probed_this_epoch: false,
        }
    }

    /// F35: the derived default horizon fires strictly before the
    /// daemon's 1.5-day re-relay cutoff.
    #[test]
    fn default_horizon_is_inside_the_re_relay_bound() {
        let block_target = shekyl_economics::EconomicParams::default().daa_target_seconds;
        let cfg = WatchdogConfig::from_block_target(block_target);
        let re_relay_cutoff_blocks = DAEMON_RE_RELAY_CUTOFF_SECONDS / block_target;
        assert!(
            cfg.escape_horizon_blocks < re_relay_cutoff_blocks,
            "horizon {} must fire before the re-relay cutoff {}",
            cfg.escape_horizon_blocks,
            re_relay_cutoff_blocks
        );
        assert!(cfg.escape_horizon_blocks > 0, "horizon must be non-trivial");
    }

    /// A zero block target is a broken consensus constant; the
    /// constructor fails loudly in all build profiles rather than
    /// deriving a nonsense horizon from a silent fallback.
    #[test]
    #[should_panic(expected = "block target must be positive")]
    fn zero_block_target_panics() {
        let _ = WatchdogConfig::from_block_target(0);
    }

    /// A block target *large enough* that the re-relay-cutoff-derived
    /// horizon floors to zero blocks (integer division, not a zero
    /// target) is the same broken-consensus-constant failure mode as
    /// [`zero_block_target_panics`], and must fail loudly the same way
    /// — not silently disable the watchdog's wait rung for every held
    /// tx. `DAEMON_RE_RELAY_CUTOFF_SECONDS` itself is such a target:
    /// `.../2/DAEMON_RE_RELAY_CUTOFF_SECONDS == 0` unconditionally.
    #[test]
    #[should_panic(expected = "zero-block escape horizon")]
    fn block_target_too_large_panics() {
        let _ = WatchdogConfig::from_block_target(DAEMON_RE_RELAY_CUTOFF_SECONDS);
    }

    /// §10 item 8 ladder ordering: below horizon → wait; past horizon →
    /// probe precedes alarm; alarm only after the probe was spent.
    /// Rebuild is unrepresentable in [`WatchdogStep`] by construction.
    #[test]
    fn ladder_ordering_probe_precedes_alarm() {
        let h = held(1_000);

        // Below horizon: wait.
        assert_eq!(
            escape_ladder_step(&h, 1_000 + CFG.escape_horizon_blocks - 1, healthy(), CFG),
            WatchdogStep::Wait(WaitReason::HorizonNotReached)
        );

        // Past horizon, un-probed: rung 1 (probe), not the alarm.
        assert_eq!(
            escape_ladder_step(&h, 1_000 + CFG.escape_horizon_blocks, healthy(), CFG),
            WatchdogStep::ProbeResubmitSameBytes
        );

        // Past horizon, probe already spent: rung 2 (alarm).
        let probed = HeldSubmit {
            probed_this_epoch: true,
            ..h
        };
        assert_eq!(
            escape_ladder_step(&probed, 1_000 + CFG.escape_horizon_blocks, healthy(), CFG),
            WatchdogStep::OperatorAlarm(AlarmReason::PresentButUnconfirmedPastHorizon)
        );
    }

    /// §5.2 item 3 health gating: a behind daemon sync-gates the ladder;
    /// a peerless daemon goes straight to the alarm rung.
    #[test]
    fn health_context_gates_the_ladder() {
        let h = held(0);
        let past = CFG.escape_horizon_blocks;

        let behind = DaemonHealthContext {
            connections: 8,
            height: 5_000,
            target_height: 6_000,
        };
        assert_eq!(
            escape_ladder_step(&h, past, behind, CFG),
            WatchdogStep::Wait(WaitReason::DaemonSyncing)
        );

        let peerless = DaemonHealthContext {
            connections: 0,
            height: 6_000,
            target_height: 0,
        };
        assert_eq!(
            escape_ladder_step(&h, past, peerless, CFG),
            WatchdogStep::OperatorAlarm(AlarmReason::DaemonPeerless)
        );
    }

    /// Round-6 minor b presence branching: absent → the resubmit is the
    /// remedy and the wait restarts; present → alarm; in-chain → keep
    /// holding for refresh; terminal → confirmed-absent release.
    #[test]
    fn probe_outcome_presence_branching() {
        let h = held(1_000);

        let (disp, next) = apply_probe_outcome(&h, ProbeOutcome::ReofferedAfterAbsence, 2_000);
        assert_eq!(disp, ProbeDisposition::RestartWait);
        let next = next.expect("tracking continues");
        assert_eq!(next.baseline_height, 2_000);
        assert!(!next.probed_this_epoch);

        let (disp, next) = apply_probe_outcome(&h, ProbeOutcome::PresentInPool, 2_000);
        assert_eq!(
            disp,
            ProbeDisposition::Alarm(AlarmReason::PresentButUnconfirmedPastHorizon)
        );
        assert!(next.expect("tracking continues").probed_this_epoch);

        let (disp, next) = apply_probe_outcome(&h, ProbeOutcome::ConfirmedInChain, 2_000);
        assert_eq!(disp, ProbeDisposition::KeepHolding);
        let next = next.expect("tracking continues");
        assert!(
            !next.probed_this_epoch,
            "confirmed-in-chain restarts the epoch outright, so a later \
             re-escalation is routed through a fresh probe — not a direct alarm"
        );
        assert_eq!(
            next.baseline_height, 2_000,
            "confirmed-in-chain restarts the horizon from the probe height"
        );

        let (disp, next) = apply_probe_outcome(&h, ProbeOutcome::RejectedTerminal, 2_000);
        assert_eq!(disp, ProbeDisposition::ReleaseConfirmedAbsent);
        assert!(next.is_none(), "terminal verdict ends tracking");
    }

    /// Regression (round-7 review): a `ConfirmedInChain` probe must not
    /// produce a spurious `PresentButUnconfirmedPastHorizon` alarm — not on the
    /// next tick (the pre-fix bug), and not on the *following* horizon either
    /// (the residual: baseline advanced but the probed flag left set, which
    /// short-circuited the probe straight to a stale-info alarm). The epoch
    /// restarts outright, so re-escalation is routed through a fresh probe and
    /// the alarm rung stays specific to the present-but-unconfirmed branch.
    #[test]
    fn confirmed_in_chain_does_not_alarm_next_tick() {
        let h = held(1_000);
        let probe_height = 1_000 + CFG.escape_horizon_blocks; // past horizon
        let (_disp, next) = apply_probe_outcome(&h, ProbeOutcome::ConfirmedInChain, probe_height);
        let next = next.expect("tracking continues");

        // Immediately after the confirmation observation: within the new
        // horizon → wait, NOT alarm.
        assert_eq!(
            escape_ladder_step(&next, probe_height, healthy(), CFG),
            WatchdogStep::Wait(WaitReason::HorizonNotReached)
        );

        // A full fresh horizon later without the lock clearing (deep reorg /
        // refresh stall): re-escalate through a *fresh probe*, NOT a direct
        // alarm — the kernel re-reads presence before it decides a human is
        // needed. (The residual bug alarmed here on a tx last seen confirmed.)
        let re_horizon = probe_height + CFG.escape_horizon_blocks;
        assert_eq!(
            escape_ladder_step(&next, re_horizon, healthy(), CFG),
            WatchdogStep::ProbeResubmitSameBytes
        );

        // The alarm is warranted only once that fresh probe actually observes
        // the tx present-but-unconfirmed (reorged back to the pool).
        let (disp, _) = apply_probe_outcome(&next, ProbeOutcome::PresentInPool, re_horizon);
        assert_eq!(
            disp,
            ProbeDisposition::Alarm(AlarmReason::PresentButUnconfirmedPastHorizon)
        );
    }

    /// Regression (round-7 review): a daemon that is BOTH behind and peerless
    /// must surface the actionable DaemonPeerless alarm, not be masked by the
    /// transient DaemonSyncing wait — a peerless daemon cannot sync, so
    /// waiting on it is indefinite.
    #[test]
    fn behind_and_peerless_alarms_peerless_not_syncing() {
        let h = held(0);
        let past = CFG.escape_horizon_blocks;
        let behind_and_peerless = DaemonHealthContext {
            connections: 0,
            height: 5_000,
            target_height: 6_000,
        };
        assert_eq!(
            escape_ladder_step(&h, past, behind_and_peerless, CFG),
            WatchdogStep::OperatorAlarm(AlarmReason::DaemonPeerless)
        );
    }
}
