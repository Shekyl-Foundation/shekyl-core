// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Guard pinning (§4.4, the guard-pinning row; `TSR-W1`; Rick, 2026-11-27).
//!
//! An onion that keeps its second-layer guards is not published until they
//! are pinned on its Tor. Each test names the edit that breaks it.

use std::time::Duration;

use super::super::super::posture::{Inbound, InboundCause, Shown};
use super::super::{duration_ns, Action, Core, GuardFault, Input, Policy, Step};
use super::{announces, bring_up, managed, policy, replied, spawns};
use crate::vanguard_rotation::VanguardsMode;

/// The wall when the first pin is confirmed, in Unix seconds.
const WALL: u64 = 1_800_000_000;

/// The pinned set's earliest expiry after [`WALL`]: inside a descriptor's
/// lifetime, so no overdue check runs before it.
const LIFETIME: u64 = 3_000;

fn guarded() -> Policy {
    Policy {
        vanguards: VanguardsMode::Managed,
        ..policy()
    }
}

fn secs(seconds: u64) -> u64 {
    duration_ns(Duration::from_secs(seconds))
}

/// Whether `step` sends a publish: a republish's `DEL_ONION` goes out as
/// [`Action::RepublishOnion`], its `ADD_ONION` as [`Action::AddOnion`].
fn publishes_onion(step: &Step) -> bool {
    step.actions
        .iter()
        .any(|action| matches!(action, Action::RepublishOnion | Action::AddOnion))
}

fn pins(step: &Step) -> bool {
    step.actions.contains(&Action::PinGuards)
}

/// Fold `input` as the answer to the request in flight, then `Replied`, as
/// the driver does. The two steps' actions, in order.
fn answer(core: &mut Core, input: Input, at: u64) -> Step {
    let mut step = core.on(input, at);
    let tail = replied(core, at);
    step.actions.extend(tail.actions);
    step.deadline = tail.deadline;
    step
}

/// Fire every deadline up to `to`, answering each request but a pin with
/// `Replied`, as a driver whose Tor answers nothing new does. True once a
/// pin is asked; the pin is left in flight.
fn run_until_pin(core: &mut Core, to: u64) -> bool {
    while let Some(at) = core.deadline().filter(|at| *at <= to) {
        let step = core.on_deadline(at);
        if pins(&step) {
            return true;
        }
        let mut reply = replied(core, at);
        while core.in_flight().is_some() {
            if pins(&reply) {
                return true;
            }
            reply = replied(core, at);
        }
        if pins(&reply) {
            return true;
        }
    }
    false
}

/// Bring a guarded Tor up to Running: its entry asks the pin and withholds
/// the publish.
fn running(core: &mut Core) {
    let entered = bring_up(core);
    assert!(pins(&entered), "entry asks the pin: {entered:?}");
    assert!(
        !publishes_onion(&entered),
        "no publish before the pin: {entered:?}"
    );
}

/// Running and published, the set pinned at `WALL` with [`LIFETIME`] to
/// its earliest expiry. Returns the core's clock at that point.
fn published(core: &mut Core) -> u64 {
    running(core);
    core.on(Input::RouteInstalled, 0);
    let pinned = answer(
        core,
        Input::GuardsPinned {
            next_expiry: WALL + LIFETIME,
            wall: WALL,
        },
        0,
    );
    assert!(
        publishes_onion(&pinned),
        "the confirmed pin publishes the owed onion: {pinned:?}"
    );
    let deleted = replied(core, 0);
    assert!(deleted.actions.contains(&Action::AddOnion));
    core.on(Input::OnionPublished, 0);
    replied(core, 0);
    assert!(matches!(core.status().inbound, Inbound::Publishing { .. }));
    0
}

/// A pin that fails before the first publish withholds the onion. Tor's
/// refusal is not a process fault, so nothing is respawned; the onion's
/// facet names the refusal; no publish source gets one out, not the
/// route's install, the endpoint coming back, nor the sample's re-ask; and
/// the pin is asked again at the cap, whose confirmation publishes. Red
/// edit: drop the guard check in `route_requests`, and the entry's publish
/// goes out behind the pin's reply.
#[test]
fn a_pin_that_fails_before_the_first_publish_withholds_the_onion() {
    let (mut core, _) = Core::start(guarded(), managed(true), 0);
    running(&mut core);
    let respawns = core.status().respawn_count;

    let refused = answer(&mut core, Input::GuardsRefused, 0);
    assert!(!publishes_onion(&refused), "{refused:?}");
    assert!(!spawns(&refused), "a refusal is not respawned: {refused:?}");
    assert_eq!(announces(&refused), 1, "the withheld onion is said");
    let status = core.status();
    assert!(
        matches!(
            status.inbound,
            Inbound::Unreachable {
                cause: InboundCause::GuardsRefused,
                ..
            }
        ),
        "{:?}",
        status.inbound
    );
    assert_eq!(status.shown, Shown::Degraded);

    // Every other source of a publish, while the guards are unpinned.
    let installed = core.on(Input::RouteInstalled, 0);
    assert!(!publishes_onion(&installed), "{installed:?}");
    let ready = core.on(Input::EndpointReady, 0);
    assert!(!publishes_onion(&ready), "{ready:?}");
    let mut at = 0;
    let retry = secs(policy().cap.as_secs());
    while let Some(due) = core.deadline().filter(|due| *due < retry) {
        at = due;
        let step = core.on_deadline(due);
        assert!(!publishes_onion(&step), "the sample's re-ask: {step:?}");
        assert!(!pins(&step), "no pin before the cap: {step:?}");
        if step.actions.contains(&Action::Sample) {
            replied(&mut core, due);
        }
    }
    assert!(at > 0, "the sample re-asked at least once");
    assert_eq!(core.status().respawn_count, respawns, "nothing respawned");

    let again = core.on_deadline(retry);
    assert!(pins(&again), "the pin is asked again at the cap: {again:?}");
    let pinned = answer(
        &mut core,
        Input::GuardsPinned {
            next_expiry: WALL + LIFETIME,
            wall: WALL,
        },
        retry,
    );
    assert!(publishes_onion(&pinned), "{pinned:?}");
    assert_eq!(
        core.status().inbound,
        Inbound::NotOffered,
        "the withheld cause clears with the pin"
    );
}

/// Tor's view that cannot fill the set waits for a new consensus: the same
/// `valid-after` asks nothing, the next one asks the pin. Red edit: retry
/// an unfilled set at the cap, and the same consensus is asked again.
#[test]
fn an_unfilled_set_waits_for_the_next_consensus() {
    let (mut core, _) = Core::start(guarded(), managed(true), 0);
    running(&mut core);
    core.on(
        Input::ConsensusClock {
            valid_after: WALL,
            wall: WALL,
        },
        0,
    );

    let unfilled = answer(&mut core, Input::GuardsUnfilled, 0);
    assert!(!publishes_onion(&unfilled) && !spawns(&unfilled));
    assert!(matches!(
        core.status().inbound,
        Inbound::Unreachable {
            cause: InboundCause::GuardsUnfilled,
            ..
        }
    ));
    let late = secs(10 * policy().cap.as_secs());
    let same = core.on(
        Input::ConsensusClock {
            valid_after: WALL,
            wall: WALL + 600,
        },
        late,
    );
    assert!(!pins(&same), "the same consensus asks nothing: {same:?}");
    assert!(
        !run_until_pin(&mut core, late + secs(policy().cap.as_secs())),
        "no timer asks it either"
    );
    let late = late + secs(policy().cap.as_secs());
    let next = core.on(
        Input::ConsensusClock {
            valid_after: WALL + 3_600,
            wall: WALL + 3_600,
        },
        late,
    );
    assert!(pins(&next), "a new consensus asks the pin: {next:?}");
}

/// An expiry that passes during a sleep is pinned at the wake. The awake
/// clock barely moves; the wall moves past the expiry; the wake asks a
/// sample, and its consensus clock carries the wall. Red edit: drop the
/// wall's comparison from `guards_on_consensus`, and the set waits out the
/// lifetime in awake time that the sleep did not count.
#[test]
fn an_expiry_that_passes_during_a_sleep_is_pinned_at_the_wake() {
    let (mut core, _) = Core::start(guarded(), managed(true), 0);
    published(&mut core);
    assert_eq!(
        core.guards_due(),
        Some(secs(LIFETIME)),
        "the awake deadline is the lifetime from the pin"
    );

    let woke = secs(60);
    let resumed = core.on(
        Input::Resumed {
            late_by: Duration::from_secs(LIFETIME + 3_600),
        },
        woke,
    );
    assert!(
        resumed.actions.contains(&Action::Sample),
        "the wake asks a sample: {resumed:?}"
    );
    let rotated = core.on(
        Input::ConsensusClock {
            valid_after: WALL + LIFETIME,
            wall: WALL + LIFETIME + 3_600,
        },
        woke,
    );
    let mut rotated = rotated;
    rotated.actions.extend(replied(&mut core, woke).actions);
    assert!(
        pins(&rotated),
        "the expired set is rotated at the wake: {rotated:?}"
    );
}

/// The same expiry with no sleep is reached on the awake clock. Red edit:
/// leave `guards_due` out of the core's deadline, and no rotation is asked.
#[test]
fn an_expiry_without_a_sleep_is_rotated_on_time() {
    let (mut core, _) = Core::start(guarded(), managed(true), 0);
    published(&mut core);
    assert!(
        !run_until_pin(&mut core, secs(LIFETIME) - 1),
        "nothing is rotated before the expiry"
    );
    assert!(
        run_until_pin(&mut core, secs(LIFETIME)),
        "the rotation is asked at the expiry"
    );
}

/// A rotation that fails on a Tor already pinned keeps serving: no
/// unpublish, no respawn, the onion's facet unchanged, the failure said,
/// and the pin asked again at the cap. Red edit: treat a rotation's failure
/// as a first pin's, and the facet says the onion is withheld while it is
/// published.
#[test]
fn a_rotation_that_fails_keeps_serving_on_the_confirmed_set() {
    let (mut core, _) = Core::start(guarded(), managed(true), 0);
    published(&mut core);
    let due = secs(LIFETIME);
    assert!(run_until_pin(&mut core, due));

    let failed = answer(&mut core, Input::GuardsRefused, due);
    assert!(
        failed
            .actions
            .contains(&Action::RotationFailed(GuardFault::Refused)),
        "{failed:?}"
    );
    assert!(!publishes_onion(&failed) && !spawns(&failed));
    assert!(
        !failed.actions.contains(&Action::TakeDown),
        "the onion stays up: {failed:?}"
    );
    assert!(matches!(core.status().inbound, Inbound::Publishing { .. }));

    let retry = due + secs(policy().cap.as_secs());
    assert!(
        !run_until_pin(&mut core, retry - 1),
        "nothing is asked before the cap"
    );
    assert!(
        run_until_pin(&mut core, retry),
        "the rotation is asked again at the cap"
    );
}

/// An onion whose Tor keeps its own guards publishes at once and asks no
/// pin. Red edit: make every managed Tor owe a pin, and a per-boot onion
/// waits for a request its driver never answers.
#[test]
fn a_per_boot_onion_publishes_without_a_pin() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    let entered = bring_up(&mut core);
    assert!(!pins(&entered), "{entered:?}");
    assert!(publishes_onion(&entered), "{entered:?}");
}
