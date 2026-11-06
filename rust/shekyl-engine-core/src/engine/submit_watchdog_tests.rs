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
use shekyl_economics::RELAY_FLOOR_LOOKBACK;
use shekyl_engine_state::{TransferDetails, SPENDABLE_AGE};

fn cfg() -> WatchdogConfig {
    WatchdogConfig::production()
}

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
    assert!(held.iter().all(|h| h.pool_sight == PoolSight::Unseen));
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
        pool_sight: PoolSight::Unseen,
    }
}

fn sight(baseline: u64, pool_sight: PoolSight) -> HeldSubmit {
    HeldSubmit {
        pool_sight,
        ..held(baseline)
    }
}

/// The production ceiling is the dispatched proof's life minus the
/// refresh-lag margin. The published-unmined count is the fee ladder's
/// lookback, read through [`shekyl_economics::relay_policy()`], and it
/// stays inside the ceiling.
#[test]
fn the_ceiling_is_the_proof_life_minus_the_refresh_lag() {
    let life = DISPATCHED_PROOF_LIFE.to_raw();
    let config = cfg();
    assert_eq!(PROBE_REFRESH_LAG_BLOCKS, 1);
    assert_eq!(config.probe_ceiling_blocks, life - PROBE_REFRESH_LAG_BLOCKS);
    assert_eq!(config.probe_ceiling_blocks, PROBE_CEILING_BLOCKS);
    assert!(config.probe_ceiling_blocks < life);
    assert_eq!(
        config.published_unmined_blocks,
        shekyl_economics::relay_policy().lookback
    );
    assert_eq!(
        config.published_unmined_blocks,
        u64::try_from(RELAY_FLOOR_LOOKBACK).expect("the lookback fits")
    );
    assert!(config.published_unmined_blocks > 0);
    assert!(config.published_unmined_blocks < config.probe_ceiling_blocks);
}

/// Below the ceiling an unseen transaction waits. At the ceiling it is
/// probed. Held at the ceiling is probed again: the last sight is not an
/// alarm. Rebuild is unrepresentable in [`WatchdogStep`].
#[test]
fn the_ceiling_probes_and_a_held_sight_does_not_alarm() {
    let h = held(1_000);

    assert_eq!(
        escape_ladder_step(&h, 1_000 + cfg().probe_ceiling_blocks - 1, healthy(), cfg()),
        WatchdogStep::Wait(WaitReason::CeilingNotReached)
    );
    assert_eq!(
        escape_ladder_step(&h, 1_000 + cfg().probe_ceiling_blocks, healthy(), cfg()),
        WatchdogStep::ProbeResubmitSameBytes
    );
    assert_eq!(
        escape_ladder_step(
            &sight(1_000, PoolSight::Held),
            1_000 + cfg().probe_ceiling_blocks,
            healthy(),
            cfg()
        ),
        WatchdogStep::ProbeResubmitSameBytes
    );
}

/// §5.2 item 3 health gating: a daemon that has not caught up
/// sync-gates the ladder; a peerless daemon goes straight to the alarm
/// rung.
#[test]
fn health_gates_the_ladder() {
    let h = held(0);
    let past = cfg().probe_ceiling_blocks;

    let behind = DaemonHealth {
        p2p: shekyl_rpc_types::HealthP2p::Running { has_peers: true },
        height: 5_000,
        synchronized: false,
    };
    assert_eq!(
        escape_ladder_step(&h, past, behind, cfg()),
        WatchdogStep::Wait(WaitReason::DaemonSyncing)
    );

    let peerless = DaemonHealth {
        p2p: shekyl_rpc_types::HealthP2p::Running { has_peers: false },
        height: 6_000,
        synchronized: true,
    };
    assert_eq!(
        escape_ladder_step(&h, past, peerless, cfg()),
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
            escape_ladder_step(&h, past, offline, cfg()),
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
    let past = cfg().probe_ceiling_blocks;
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
            cfg(),
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

/// Absent restarts the wait. Held keeps holding. Held-overdue alarms.
/// Published under the lookback keeps holding, and at the lookback alarms
/// as published, not mined. In chain restarts the epoch. A terminal
/// rejection releases.
#[test]
fn probe_outcome_presence_branching() {
    let h = held(1_000);
    let apply = |outcome, height| apply_probe_outcome(&h, outcome, height, cfg());

    let (disp, next) = apply(ProbeOutcome::ReofferedAfterAbsence, 2_000);
    assert_eq!(disp, ProbeDisposition::RestartWait);
    let next = next.expect("tracking continues");
    assert_eq!(next.baseline_height, 2_000);
    assert_eq!(next.pool_sight, PoolSight::Unseen);

    let (disp, next) = apply(ProbeOutcome::Held, 2_000);
    assert_eq!(disp, ProbeDisposition::KeepHolding);
    assert_eq!(
        next.expect("tracking continues").pool_sight,
        PoolSight::Held
    );

    let (disp, next) = apply(ProbeOutcome::HeldOverdue, 1_000);
    assert_eq!(disp, ProbeDisposition::Alarm(AlarmReason::HeldOverdue));
    assert_eq!(
        next.expect("tracking continues").pool_sight,
        PoolSight::HeldOverdue
    );

    let under = 1_000 + cfg().published_unmined_blocks - 1;
    let (disp, next) = apply(ProbeOutcome::Published, under);
    assert_eq!(disp, ProbeDisposition::KeepHolding);
    assert_eq!(
        next.expect("tracking continues").pool_sight,
        PoolSight::Published
    );
    let at = 1_000 + cfg().published_unmined_blocks;
    let (disp, _) = apply(ProbeOutcome::Published, at);
    assert_eq!(disp, ProbeDisposition::Alarm(AlarmReason::PublishedUnmined));

    let (disp, next) = apply(ProbeOutcome::ConfirmedInChain, 2_000);
    assert_eq!(disp, ProbeDisposition::KeepHolding);
    let next = next.expect("tracking continues");
    assert_eq!(
        next.pool_sight,
        PoolSight::Unseen,
        "in chain restarts the epoch, so the next escalation probes"
    );
    assert_eq!(next.baseline_height, 2_000);

    let (disp, next) = apply(ProbeOutcome::RejectedTerminal, 2_000);
    assert_eq!(disp, ProbeDisposition::ReleaseConfirmedAbsent);
    assert!(next.is_none(), "terminal verdict ends tracking");
}

/// A confirmation observation restarts the wait. The next ceiling probes.
/// Held on that probe does not alarm. Held-overdue does.
#[test]
fn confirmed_in_chain_does_not_alarm_next_tick() {
    let h = held(1_000);
    let probe_height = 1_000 + cfg().probe_ceiling_blocks;
    let (_disp, next) =
        apply_probe_outcome(&h, ProbeOutcome::ConfirmedInChain, probe_height, cfg());
    let next = next.expect("tracking continues");

    assert_eq!(
        escape_ladder_step(&next, probe_height, healthy(), cfg()),
        WatchdogStep::Wait(WaitReason::CeilingNotReached)
    );

    let again = probe_height + cfg().probe_ceiling_blocks;
    assert_eq!(
        escape_ladder_step(&next, again, healthy(), cfg()),
        WatchdogStep::ProbeResubmitSameBytes
    );

    let (disp, _) = apply_probe_outcome(&next, ProbeOutcome::Held, again, cfg());
    assert_eq!(disp, ProbeDisposition::KeepHolding);
    let (disp, _) = apply_probe_outcome(&next, ProbeOutcome::HeldOverdue, again, cfg());
    assert_eq!(disp, ProbeDisposition::Alarm(AlarmReason::HeldOverdue));
}

/// Twenty-five blocks while the daemon still holds the transaction.
/// Two thousand seconds is the scenario's wall time. This function
/// takes no duration, and the step is a wait.
#[test]
fn twenty_five_blocks_in_two_thousand_seconds_while_held_does_not_alarm() {
    let h = sight(0, PoolSight::Held);
    assert_eq!(
        escape_ladder_step(&h, 25, healthy(), cfg()),
        WatchdogStep::Wait(WaitReason::CeilingNotReached)
    );
}

/// Held-overdue alarms at every block count, including none and the
/// ceiling. The decision does not read a block count.
#[test]
fn held_overdue_alarms_with_no_block_count() {
    for age in [0, 25, u64::MAX] {
        assert_eq!(
            escape_ladder_step(&sight(0, PoolSight::HeldOverdue), age, healthy(), cfg()),
            WatchdogStep::OperatorAlarm(AlarmReason::HeldOverdue),
            "age {age}"
        );
    }
}

/// Published and unmined is its own alarm, at the fee-ladder lookback.
/// One block earlier is a wait. It is not an overdue alarm.
#[test]
fn published_unmined_does_not_alarm_as_stuck() {
    let n = cfg().published_unmined_blocks;
    let published = sight(0, PoolSight::Published);
    assert_eq!(
        escape_ladder_step(&published, n - 1, healthy(), cfg()),
        WatchdogStep::Wait(WaitReason::CeilingNotReached)
    );
    assert_eq!(
        escape_ladder_step(&published, n, healthy(), cfg()),
        WatchdogStep::OperatorAlarm(AlarmReason::PublishedUnmined)
    );
}

/// The ceiling probes a held transaction at the proof life minus the
/// margin. One block earlier waits.
#[test]
fn the_ceiling_probes_a_held_transaction_at_life_minus_margin() {
    let life = DISPATCHED_PROOF_LIFE.to_raw();
    let margin = PROBE_REFRESH_LAG_BLOCKS;
    assert_eq!(margin, 1);
    assert_eq!(cfg().probe_ceiling_blocks, life - margin);
    let held_tx = sight(0, PoolSight::Held);
    assert_eq!(
        escape_ladder_step(&held_tx, life - margin - 1, healthy(), cfg()),
        WatchdogStep::Wait(WaitReason::CeilingNotReached)
    );
    assert_eq!(
        escape_ladder_step(&held_tx, life - margin, healthy(), cfg()),
        WatchdogStep::ProbeResubmitSameBytes
    );
}

/// Regression (round-7 review): a daemon that is BOTH behind and peerless
/// must surface the actionable DaemonPeerless alarm, not be masked by the
/// transient DaemonSyncing wait — a peerless daemon cannot sync, so
/// waiting on it is indefinite.
#[test]
fn behind_and_peerless_alarms_peerless_not_syncing() {
    let h = held(0);
    let past = cfg().probe_ceiling_blocks;
    let behind_and_peerless = DaemonHealth {
        p2p: shekyl_rpc_types::HealthP2p::Running { has_peers: false },
        height: 5_000,
        synchronized: false,
    };
    assert_eq!(
        escape_ladder_step(&h, past, behind_and_peerless, cfg()),
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
        let step = escape_ladder_step(&held(0), cfg().probe_ceiling_blocks, health, cfg());
        let ladder_waits_on_sync = matches!(step, WatchdogStep::Wait(WaitReason::DaemonSyncing));
        assert_eq!(
            ladder_waits_on_sync, !minted,
            "the ladder and the constructor must not disagree at ({height}, {synchronized})",
        );
    }
}
