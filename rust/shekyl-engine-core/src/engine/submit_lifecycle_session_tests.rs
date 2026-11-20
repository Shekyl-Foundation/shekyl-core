// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Session-boundary tests for the submit lifecycle driver.
//!
//! A send dispatched before this session, a row with no bytes, and a
//! resend that hands the send back to the automatic rung. Split out of
//! `submit_lifecycle_tests.rs` so that file stays under the size cap.
//! The hermetic stubs stay in the parent; this module is its child.

use super::*;
use shekyl_rpc_client::Publication;

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
        host.held_send_facts()
            .iter()
            .find(|fact| fact.tx_hash == tx)
            .map(|fact| fact.latched),
        Some(Some(WatchdogAlarmReason::DispatchedBeforeThisSession)),
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
    assert_eq!(
        host.held_send_facts()
            .iter()
            .find(|fact| fact.tx_hash == tx)
            .map(|fact| fact.latched),
        Some(None),
        "the resend clears the alarm"
    );
    d.tick(&host, &daemon, &NoSaveCommit).await;
    assert_eq!(daemon.submit_calls(), 1, "rung 1 runs for an adopted send");
}

/// No saved bytes outranks "earlier session": the user cannot resend
/// what the row does not hold, so the alarm names the missing bytes.
#[tokio::test]
async fn missing_bytes_outrank_an_earlier_session() {
    let tx = txid(1);
    let host = StubHost::new(1_000 + CEILING)
        .with_held(held(1, 1_000))
        .dispatched_earlier(tx);
    let daemon = StubDaemon::new();
    let mut d = driver();

    d.tick(&host, &daemon, &NoSaveCommit).await;

    assert_eq!(daemon.submit_calls(), 0);
    assert_eq!(
        alarm_reasons(&host.events()),
        vec![WatchdogAlarmReason::HeldBytesMissing]
    );
}

/// A resend that learns the bytes are published replaces a stale
/// held-overdue sight. The next tick probes from the publication
/// instead of raising the overdue alarm again.
#[tokio::test]
async fn a_reported_resend_replaces_the_overdue_sight() {
    let tx = txid(1);
    let host = StubHost::new(1_000 + CEILING)
        .with_held(held(1, 1_000))
        .with_bytes(tx, vec![0xAB; 8]);
    let daemon = StubDaemon::new();
    daemon.push_submit(Ok(TxSubmitOutcome::AlreadyInPool {
        hash: tx,
        relay: Publication::Overdue,
    }));
    let mut d = driver();
    d.tick(&host, &daemon, &NoSaveCommit).await;
    assert_eq!(
        alarm_reasons(&host.events()),
        vec![WatchdogAlarmReason::HeldOverdue]
    );
    assert_eq!(daemon.submit_calls(), 1);

    host.adopt_into_session(tx);
    let held = host
        .held_submits()
        .into_iter()
        .find(|row| row.tx_hash == tx)
        .expect("still held");
    let recorded = d.apply_reported_verdict(
        &host,
        &NoSaveCommit,
        held,
        TxSubmitOutcome::AlreadyInPool {
            hash: tx,
            relay: Publication::Public,
        },
    );
    assert!(matches!(recorded, ReportedVerdict::Continued));

    d.tick(&host, &daemon, &NoSaveCommit).await;
    assert_eq!(
        daemon.submit_calls(),
        2,
        "the published sight is probed, not re-alarmed as overdue"
    );
    assert_eq!(
        alarm_reasons(&host.events()),
        vec![WatchdogAlarmReason::HeldOverdue],
        "the cleared overdue alarm is not raised again"
    );
}
