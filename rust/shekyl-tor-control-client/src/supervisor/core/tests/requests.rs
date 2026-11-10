// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The requests the driver runs off the loop (`TOR_SUPERVISOR.md` §4.11;
//! Rick, 2026-11-10): one in flight, in the order the awaits gave, under a
//! reply bound the core holds.

use std::time::Duration;

use super::super::super::posture::{Cause, Shown};
use super::super::{duration_ns, Action, Core, Input};
use super::{bring_up, managed, policy, replied};

fn secs(seconds: u64) -> u64 {
    duration_ns(Duration::from_secs(seconds))
}

fn bound() -> u64 {
    duration_ns(policy().reply_bound)
}

/// A core whose launch is in flight, sent at 0.
fn launching() -> Core {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    let step = core.on(Input::PinAccepted, 0);
    assert!(
        step.actions
            .iter()
            .any(|action| matches!(action, Action::Spawn { .. })),
        "the launch is sent: {step:?}"
    );
    core
}

/// **A reply past its bound is a process fault, one bound after the send.**
/// The launch is sent at 0 and never answered. A deadline one nanosecond
/// short of the bound names nothing; at the bound the cause is `ReplyLate`
/// and Tor is restarting. Fails if the core keeps no deadline for the
/// request in flight (the driver used to time it out inline), or if it
/// counts from anything but the send.
#[test]
fn a_reply_past_its_bound_is_late_one_bound_after_the_send() {
    let mut core = launching();
    assert_eq!(core.deadline(), Some(bound()), "the bound is the deadline");
    core.on_deadline(bound() - 1);
    assert_eq!(core.status().cause, Cause::None, "not yet late");
    core.on_deadline(bound());
    let status = core.status();
    assert_eq!(status.cause, Cause::ReplyLate);
    assert_eq!(status.shown, Shown::Restarting);
    assert_eq!(core.in_flight(), None, "the late request is dropped");
}

/// **The bound is awake time: a wake starts it again.** The launch is sent
/// at 0; the machine sleeps, and the driver reports the wake at 20 s. The
/// bound then runs from the wake, so nothing is late at 30 s and the request
/// is late at 50 s. Fails if `resumed` leaves the request's send time where
/// it was: a sleep would count against Tor.
#[test]
fn a_wake_starts_the_reply_bound_again() {
    let mut core = launching();
    core.on(
        Input::Resumed {
            late_by: Duration::from_secs(20),
        },
        secs(20),
    );
    core.on_deadline(bound());
    assert_eq!(core.status().cause, Cause::None, "the sleep did not count");
    core.on_deadline(secs(20) + bound());
    assert_eq!(core.status().cause, Cause::ReplyLate);
}

/// **A reply for another number is not folded.** Only the request in flight
/// is answered: a reply carrying an older number (a request the core gave
/// up on) leaves it in flight and sends nothing. Fails if `answered` takes
/// any number.
#[test]
fn a_reply_for_another_number_is_not_folded() {
    let mut core = launching();
    let number = core.in_flight().expect("the launch is in flight");
    let stale = core.on(
        Input::Replied {
            number: number.wrapping_sub(1),
        },
        secs(1),
    );
    assert!(stale.actions.is_empty(), "{stale:?}");
    assert_eq!(core.in_flight(), Some(number));
}

/// **The launch, then its subscription, then its first sample**, each sent
/// when the one before it is answered. The launch's answer (`Spawned`)
/// does not send the subscription by itself: `Replied` does. Fails if
/// requests go out while another is in flight, or in another order.
#[test]
fn a_launch_is_followed_by_its_subscription_then_its_first_sample() {
    let mut core = launching();
    let spawned = core.on(Input::Spawned, 0);
    assert!(
        !spawned
            .actions
            .iter()
            .any(|action| matches!(action, Action::SubscribeEvents | Action::Sample)),
        "nothing goes while the launch is in flight: {spawned:?}"
    );
    let launch_answered = replied(&mut core, 0);
    assert!(
        launch_answered.actions.contains(&Action::SubscribeEvents),
        "{launch_answered:?}"
    );
    assert!(!launch_answered.actions.contains(&Action::Sample));
    let subscribed = replied(&mut core, 0);
    assert!(
        subscribed.actions.contains(&Action::Sample),
        "{subscribed:?}"
    );
}

/// **A refused `DEL_ONION` sends no `ADD_ONION`.** Running publishes the
/// onion: the delete goes first. Tor refuses it (`OnionRejected` before its
/// `Replied`), and the add that follows it in the same decision is dropped:
/// nothing is in flight after the delete is answered. Fails if the queue
/// sends what follows a refused request.
#[test]
fn a_refused_delete_sends_no_add() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    bring_up(&mut core);
    let installed = core.on(Input::RouteInstalled, 0);
    assert!(
        installed.actions.contains(&Action::RepublishOnion) || core.in_flight().is_some(),
        "the publish's delete is sent: {installed:?}"
    );
    core.on(Input::OnionRejected, 0);
    let answered = replied(&mut core, 0);
    assert!(
        !answered.actions.contains(&Action::AddOnion),
        "an add after a refused delete: {answered:?}"
    );
    assert_eq!(core.in_flight(), None);
}

/// **A sample is not queued behind a sample.** A slow Tor has not answered
/// a running sample when the next sample comes due; the second is the same
/// question and is not queued, so answering the first sends nothing more.
/// Fails if the queue keeps a duplicate read: a wedge would stack samples
/// for the whole bound.
#[test]
fn a_sample_due_while_one_waits_is_not_queued_again() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    bring_up(&mut core);
    core.on(Input::RouteInstalled, 0);
    // The publish's delete and add, answered.
    replied(&mut core, 0);
    core.on(Input::OnionPublished, 0);
    replied(&mut core, 0);
    assert_eq!(core.in_flight(), None);
    let alive = duration_ns(policy().alive_every);
    let first = core.on_deadline(alive);
    assert!(first.actions.contains(&Action::Sample), "{first:?}");
    let second = core.on_deadline(2 * alive);
    assert!(!second.actions.contains(&Action::Sample), "{second:?}");
    core.on(
        Input::DirectorySample {
            progress: Some(100),
            socks: None,
            read: None,
        },
        2 * alive,
    );
    let answered = replied(&mut core, 2 * alive);
    assert!(
        !answered.actions.contains(&Action::Sample),
        "a second sample was queued: {answered:?}"
    );
}

/// **An ended Tor is reaped before the next launch, off the loop.** A
/// bootstrapping Tor's control ends: the fault sends `Reap`, and the next
/// launch, due after the backoff, waits behind it; answering the reap sends
/// the launch. A launch that failed had no Tor to reap and sends none.
/// Fails if the core leaves the reap to the driver's loop (no `Reap`), or
/// sends the launch while the reap is in flight.
#[test]
fn an_ended_tor_is_reaped_before_the_next_launch() {
    let mut core = launching();
    core.on(Input::Spawned, 0);
    replied(&mut core, 0);
    replied(&mut core, 0);
    let ended = core.on(Input::ControlEnded, secs(1));
    assert!(ended.actions.contains(&Action::Reap), "{:?}", ended.actions);
    let due = core.deadline().expect("the respawn wait");
    core.on_deadline(due);
    let pinned = core.on(Input::PinAccepted, due);
    assert!(
        !pinned
            .actions
            .iter()
            .any(|action| matches!(action, Action::Spawn { .. })),
        "the launch waits for the reap: {:?}",
        pinned.actions
    );
    let reaped = replied(&mut core, due);
    assert!(
        reaped
            .actions
            .iter()
            .any(|action| matches!(action, Action::Spawn { .. })),
        "the reap's answer sends the launch: {:?}",
        reaped.actions
    );
    let failed = core.on(Input::SpawnFailed, due);
    assert!(
        !failed.actions.contains(&Action::Reap),
        "a launch that failed has no Tor to reap: {:?}",
        failed.actions
    );
}
