// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Decision tests for the submit watchdog kernel
//! (`engine/submit_watchdog.rs`).
//!
//! Wired as a `#[path]` child of `submit_watchdog::tests`, so
//! `use super::*` resolves into the kernel and private items stay
//! testable. The sibling file exists so the kernel file carries the
//! decision surface, not its suite.

use super::*;
use shekyl_engine_state::{TransferDetails, SPENDABLE_AGE};

const CFG: WatchdogConfig = WatchdogConfig {
    escape_horizon_blocks: 540,
};

/// Minimal unspent transfer fixture at `gindex = seed` (locks are
/// journal-derived since PR-SJ-1b, so the row itself carries none).
fn transfer_at(seed: u8) -> TransferDetails {
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar};
    TransferDetails {
        tx_hash: TxHash::from_bytes([seed; 32]),
        internal_output_index: shekyl_types::OutputIndexInTx::from_raw(u64::from(seed)),
        global_output_index: shekyl_types::GlobalOutputIndex::from_raw(u64::from(seed)),
        block_height: shekyl_types::BlockHeight::from_raw(100),
        key: ED25519_BASEPOINT_POINT,
        key_offset: Scalar::ONE,
        commitment: shekyl_curve_primitives::Commitment::new(Scalar::ONE, 1_000),
        payment_id: None,
        spent: false,
        spent_height: None,
        key_image: None,
        spending_tx_hash: None,
        source_ciphertext: None,
        output_handle: None,
        eligible_height: shekyl_types::BlockHeight::from_raw(100) + SPENDABLE_AGE,
        frozen: false,
        unspendable: None,
        fcmp_precomputed_path: None,
        receive_attribution: shekyl_engine_state::ReceiveAttribution::default(),
    }
}

fn ledger_with(transfers: Vec<TransferDetails>) -> shekyl_engine_state::LedgerBlock {
    shekyl_engine_state::LedgerBlock::new(
        transfers,
        shekyl_engine_state::BlockchainTip::new(
            shekyl_types::BlockHeight::from_raw(5_000),
            [0xAA; 32],
        ),
        shekyl_engine_state::ReorgBlocks::default(),
    )
}

/// Journal fixture row: `state` + optional baseline over one input.
fn journal_row(
    wallet: &mut shekyl_engine_state::WalletLedger,
    txid: [u8; 32],
    state: shekyl_engine_state::SendState,
    lock_baseline: Option<u64>,
    gindexes: Vec<u64>,
) {
    wallet.send_journal.rows.insert(
        txid,
        shekyl_engine_state::SendRecord {
            dispatched_at_height: shekyl_types::BlockHeight::from_raw(3_999),
            fee: 1,
            recipients: Vec::new(),
            change_amount: 0,
            inputs: gindexes
                .into_iter()
                .map(|gindex| shekyl_engine_state::SendInputRef { gindex, amount: 1 })
                .collect(),
            lock_baseline,
            state,
        },
    );
}

/// Held tracking projects one entry per journal row that carries
/// locks (PR-SJ-1b): baseline-stamped `Dispatched` and `Abandoned`
/// rows project; released (`PresumedDead` / no-baseline) and
/// settled (`Confirmed` / `TerminalRejected`) rows do not — and a
/// multi-input send is one entry by construction, no grouping.
#[test]
fn held_submits_projects_lock_bearing_journal_rows() {
    use shekyl_engine_state::SendState;
    let mut wallet = shekyl_engine_state::WalletLedger::empty();
    journal_row(
        &mut wallet,
        [1; 32],
        SendState::Dispatched,
        Some(3_900),
        vec![1, 2],
    );
    journal_row(
        &mut wallet,
        [2; 32],
        SendState::Abandoned,
        Some(4_000),
        vec![3],
    );
    journal_row(&mut wallet, [3; 32], SendState::PresumedDead, None, vec![4]);
    journal_row(
        &mut wallet,
        [4; 32],
        SendState::Confirmed {
            height: shekyl_types::BlockHeight::from_raw(9),
        },
        Some(3_800),
        vec![5],
    );
    journal_row(&mut wallet, [5; 32], SendState::Dispatched, None, vec![6]); // pre-verdict

    let held = held_submits(&wallet);
    assert_eq!(held.len(), 2, "one entry per lock-bearing row");
    assert_eq!(held[0].tx_hash, TxHash::from_bytes([1; 32]));
    assert_eq!(held[0].baseline_height, 3_900);
    assert_eq!(held[1].tx_hash, TxHash::from_bytes([2; 32]));
    assert_eq!(held[1].baseline_height, 4_000);
    assert!(held.iter().all(|h| !h.probed_this_epoch));
}

/// …and rows **leave** it. The projection is journal-only, so the
/// escape ladder's exits are exactly the journal's exits: the merge
/// reconciler's confirm edge, its evidence-bound release, and the
/// watchdog's own `mark_presumed_dead`. Pinning entry alone would
/// pass for a projection nothing can ever clear — which is precisely
/// how a permanent "your transaction has not confirmed" alarm, and a
/// permanently pinned copy of the network-exposed tx bytes, would
/// look to a green suite.
#[test]
fn held_submits_drops_rows_the_ledger_refutes() {
    use shekyl_engine_state::SendState;

    for (name, arrange) in [
        (
            "superseded: a foreign tx consumed the carried input",
            (|wallet: &mut shekyl_engine_state::WalletLedger| {
                let mut td = transfer_at(1);
                td.spent = true;
                td.spent_height = Some(shekyl_types::BlockHeight::from_raw(4_100));
                td.spending_tx_hash = Some(TxHash::from_bytes([0xEE; 32]));
                wallet.ledger = ledger_with(vec![td]);
            }) as fn(&mut shekyl_engine_state::WalletLedger),
        ),
        (
            "unwitnessable: the scan floor put the input out of view",
            |wallet: &mut shekyl_engine_state::WalletLedger| {
                wallet.ledger = ledger_with(Vec::new());
            },
        ),
    ] {
        let mut wallet = shekyl_engine_state::WalletLedger::empty();
        wallet.ledger = ledger_with(vec![transfer_at(1)]);
        journal_row(
            &mut wallet,
            [1; 32],
            SendState::Dispatched,
            Some(4_000),
            vec![1],
        );
        assert_eq!(held_submits(&wallet).len(), 1, "{name}: held before");

        arrange(&mut wallet);
        wallet.reconcile_send_journal(None);

        assert!(
            held_submits(&wallet).is_empty(),
            "{name}: the row must leave the held projection"
        );
    }
}

/// §2.6 confirmed-absent release: locks under the named txid are
/// released (outputs selectable again); other locks untouched.
#[test]
fn release_confirmed_absent_clears_only_the_named_tx() {
    let gone = TxHash::from_bytes([0xCC; 32]);
    let still_held = TxHash::from_bytes([0xDD; 32]);
    let mut wallet = shekyl_engine_state::WalletLedger::empty();
    wallet.ledger = ledger_with(vec![transfer_at(1), transfer_at(2), transfer_at(3)]);
    // The owning journal rows are the locks (PR-SJ-1b): `gone`
    // carries gindexes 1 and 2, `still_held` carries 3.
    for (txid, gindexes) in [(gone, vec![1u64, 2]), (still_held, vec![3u64])] {
        wallet.send_journal.rows.insert(
            txid.to_bytes(),
            shekyl_engine_state::SendRecord {
                dispatched_at_height: shekyl_types::BlockHeight::from_raw(3_999),
                fee: 1,
                recipients: Vec::new(),
                change_amount: 0,
                inputs: gindexes
                    .into_iter()
                    .map(|gindex| shekyl_engine_state::SendInputRef { gindex, amount: 1 })
                    .collect(),
                lock_baseline: Some(4_000),
                state: shekyl_engine_state::SendState::Dispatched,
            },
        );
    }

    assert_eq!(
        release_awaiting_confirmation(&mut wallet, &HashSet::from([gone])),
        2
    );
    let released_row = &wallet.send_journal.rows[&gone.to_bytes()];
    assert_eq!(
        released_row.state,
        shekyl_engine_state::SendState::PresumedDead,
        "confirmed-absent release is the PresumedDead entry (P3-4)"
    );
    assert_eq!(
        released_row.lock_baseline, None,
        "baseline clears so the reconciler never re-locks a released tx"
    );
    assert_eq!(
        wallet.send_journal.rows[&still_held.to_bytes()].state,
        shekyl_engine_state::SendState::Dispatched,
        "unrelated row untouched"
    );
    // PR-SJ-1b: spendability consults the journal-derived lock map.
    // The released row cleared its baseline, so only `still_held`'s
    // carried input (gindex 3) stays locked.
    let locks = wallet.spend_locks();
    assert_eq!(locks.len(), 1);
    assert!(locks.contains(shekyl_types::GlobalOutputIndex::from_raw(3)));
    let ledger = &wallet.ledger;
    for td in ledger.transfers() {
        let locked = locks.contains(td.global_output_index);
        assert_eq!(
            td.is_spendable(shekyl_types::BlockHeight::from_raw(u64::MAX), &locks),
            !locked,
            "gindex {} spendability must mirror the derived lock",
            td.global_output_index
        );
    }
    assert_eq!(held_submits(&wallet).len(), 1);
}

fn healthy() -> DaemonHealth {
    DaemonHealth {
        p2p: shekyl_rpc_types::HealthP2p::Running { has_peers: true },
        height: 10_000,
        synchronized: true,
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

/// §5.2 item 3 health gating: a daemon that has not caught up
/// sync-gates the ladder; a peerless daemon goes straight to the alarm
/// rung.
#[test]
fn health_gates_the_ladder() {
    let h = held(0);
    let past = CFG.escape_horizon_blocks;

    let behind = DaemonHealth {
        p2p: shekyl_rpc_types::HealthP2p::Running { has_peers: true },
        height: 5_000,
        synchronized: false,
    };
    assert_eq!(
        escape_ladder_step(&h, past, behind, CFG),
        WatchdogStep::Wait(WaitReason::DaemonSyncing)
    );

    let peerless = DaemonHealth {
        p2p: shekyl_rpc_types::HealthP2p::Running { has_peers: false },
        height: 6_000,
        synchronized: true,
    };
    assert_eq!(
        escape_ladder_step(&h, past, peerless, CFG),
        WatchdogStep::OperatorAlarm(AlarmReason::DaemonPeerless)
    );

    // An offline daemon is its own alarm, not "peerless": it relays
    // nothing by configuration, and only the operator can change that
    // (Rick, 2026-10-14). It outranks the sync wait, as peerless does.
    for synchronized in [true, false] {
        let offline = DaemonHealth {
            p2p: shekyl_rpc_types::HealthP2p::Offline,
            height: 6_000,
            synchronized,
        };
        assert_eq!(
            escape_ladder_step(&h, past, offline, CFG),
            WatchdogStep::OperatorAlarm(AlarmReason::DaemonOffline),
            "synchronized {synchronized}"
        );
    }
}

/// **§3.1's defect, pinned shut** (RK-D14). A held send, past its
/// horizon, against a restricted daemon whose node has peers: the reply
/// says `restricted`, writes zero for both connection counts, and says
/// `has_peers`. The ladder reaches its resubmit probe. Before
/// `has_peers` the health projection summed those zeros, and this was a
/// `DaemonPeerless` alarm that suppressed the probe — the recovery.
///
/// The same holds when the daemon withholds Status altogether, as a
/// restricted reply does since RK-Q8 (3.48). The control is the same reply from a
/// node with no peers, which is still the alarm.
#[test]
fn a_restricted_daemon_with_peers_reaches_the_probe_not_the_peerless_alarm() {
    use crate::engine::daemon::synced_chain_facts::{health_from_get_info, GetInfoDocument};

    let h = held(0);
    let past = CFG.escape_horizon_blocks;
    let reply = |has_peers: bool, status_withheld: bool| {
        let mut reply = GetInfoDocument {
            chain_count: shekyl_types::ChainCount::from_raw(10_000),
            target_height: None,
            synchronized: true,
            top_hash: shekyl_types::BlockHash::from_bytes([0x11; 32]),
            has_peers,
        }
        .to_reply();
        reply.restricted = true;
        let status = reply.node.shown().expect("the document shows Status");
        assert_eq!(
            status.connections,
            shekyl_rpc_types::StatusConnections::Running {
                outgoing: 0,
                incoming: 0
            },
            "the reply's counts are zero, as a restricted daemon writes them"
        );
        if status_withheld {
            reply.node = shekyl_rpc_types::Hidden::Withheld;
            reply.peers = shekyl_rpc_types::Hidden::Withheld;
        }
        reply
    };
    let step = |has_peers: bool, status_withheld: bool| {
        let health = health_from_get_info(&reply(has_peers, status_withheld));
        escape_ladder_step(
            &h,
            past,
            DaemonHealth {
                p2p: health.p2p,
                height: health.height,
                synchronized: health.synchronized,
            },
            CFG,
        )
    };

    for status_withheld in [false, true] {
        assert_eq!(
            step(true, status_withheld),
            WatchdogStep::ProbeResubmitSameBytes,
            "peers, Status withheld: {status_withheld}"
        );
        assert_eq!(
            step(false, status_withheld),
            WatchdogStep::OperatorAlarm(AlarmReason::DaemonPeerless),
            "no peers, Status withheld: {status_withheld}"
        );
    }
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
    let behind_and_peerless = DaemonHealth {
        p2p: shekyl_rpc_types::HealthP2p::Running { has_peers: false },
        height: 5_000,
        synchronized: false,
    };
    assert_eq!(
        escape_ladder_step(&h, past, behind_and_peerless, CFG),
        WatchdogStep::OperatorAlarm(AlarmReason::DaemonPeerless)
    );
}

/// **The convergence pin** (`WSS-Q14`). Past the horizon, with a peer,
/// the ladder waits on sync exactly when [`SyncedChainFacts`] would
/// refuse to mint. Both read `synchronized` on the same [`DaemonHealth`].
///
/// This bites against the ladder growing its own predicate. It does
/// not cover a third consumer that decides on something other than
/// the flag. Nothing but review catches that.
#[test]
fn the_ladder_and_the_constructor_read_the_same_flag() {
    use crate::engine::daemon::synced_chain_facts::SyncedChainFacts;

    let hash = shekyl_types::BlockHash::from_bytes([0x11; 32]);
    for (height, synchronized) in [
        (0, true),
        (1_000, true),
        (u64::MAX, true),
        (5, false),
        (1_000_000, false),
    ] {
        let health = DaemonHealth {
            p2p: shekyl_rpc_types::HealthP2p::Running { has_peers: true },
            height,
            synchronized,
        };
        let minted = SyncedChainFacts::from_health(health, hash).is_some();
        let step = escape_ladder_step(&held(0), CFG.escape_horizon_blocks, health, CFG);
        let ladder_waits_on_sync = matches!(step, WatchdogStep::Wait(WaitReason::DaemonSyncing));
        assert_eq!(
            ladder_waits_on_sync, !minted,
            "the ladder and the constructor must not disagree at ({height}, {synchronized})",
        );
    }
}
