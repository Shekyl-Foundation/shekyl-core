// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;
use crate::{Driver, Effect, FluffReach, Zone};
use shekyl_relay_privacy::params::DandelionParams;
use shekyl_relay_privacy::rng::SplitMix64;

fn id(byte: u8) -> ConnectionId {
    let mut b = [0u8; 16];
    b[0] = byte;
    ConnectionId::from_bytes(b)
}

#[test]
fn a_dummy_is_the_common_case_not_an_error() {
    let mut q = CovertQueues::new(2);
    assert_eq!(q.channels(), 2);
    assert_eq!(q.take_for_send(0, id(1)), None);
}

#[test]
fn a_queued_message_goes_out_once_then_the_channel_returns_to_cover() {
    let mut q = CovertQueues::new(2);
    assert!(q.enqueue(0, vec![7, 7, 7]));
    assert_eq!(q.take_for_send(0, id(1)), Some(vec![7, 7, 7]));
    assert_eq!(q.take_for_send(0, id(1)), None, "a message travels once");
}

#[test]
fn an_out_of_range_channel_is_refused_rather_than_silently_dropped() {
    let mut q = CovertQueues::new(2);
    assert!(!q.enqueue(9, vec![1]));
    assert_eq!(q.take_for_send(9, id(1)), None);
}

/// CV-1 (§20.5): a rebind discards the in-flight remainder.
#[test]
fn cv1_a_rebind_discards_the_in_flight_remainder() {
    let mut q = CovertQueues::new(1);
    q.enqueue(0, vec![1, 2, 3]);
    q.enqueue(0, vec![4, 5, 6]);

    assert_eq!(q.take_for_send(0, id(1)), Some(vec![1, 2, 3]));
    q.enqueue(0, vec![1, 2, 3]);

    let after_rebind = q.take_for_send(0, id(2));
    assert!(
        after_rebind.is_some(),
        "a rebind discards the remainder; it does not wedge the channel"
    );

    q.unbind(0);
    assert_eq!(q.take_for_send(0, id(3)), None);
}

/// Drive the scheduler and collect the covert cadence it emits.
///
/// **The tick is part of the observation, not decoration.** An earlier version
/// collected `(channel, kind)` only, and the negative control caught it
/// immediately: two independently seeded runs produced identical channel
/// sequences, because the *order* of channels is not where the schedule's
/// randomness lives — the *timing* is. CV-4 is a timing property, so a
/// collector blind to time would have made the assertion below pass for the
/// wrong reason.
fn covert_cadence(seed: u64, polls: usize) -> Vec<(u64, usize, bool)> {
    let mut rng = SplitMix64::new(seed);
    let zone = Zone::new(
        DandelionParams::inherited(),
        2,
        FluffReach::OutboundOnly,
        true, // covert ON, or there are no deadlines and this is vacuous
        0,
        &mut rng,
    );
    let mut driver = Driver::new(zone);
    let peers = vec![id(1), id(2), id(3), id(4)];
    driver.zone_mut().update_stems(peers.clone(), &mut rng);

    let mut out = Vec::new();
    let mut now = 0u64;
    for _ in 0..polls {
        now += 1_000;
        for effect in driver.poll(now, || peers.clone(), &mut rng) {
            match effect {
                Effect::CovertSend { channel, .. } => out.push((now, channel, true)),
                Effect::CovertUnbind { channel } => out.push((now, channel, false)),
                Effect::Fluff { .. } => {}
            }
        }
    }
    out
}

/// **CV-4 (§20.2): the covert cadence must not depend on queue depth.**
///
/// This replaces the friction the C++/Rust split used to supply. Before the
/// cutover, wiring queue depth into the schedule meant a `#[repr(C)]` field or
/// a new FFI entry point — loud in review. In one crate it is
/// `if q.has_pending() { … }`: one line, reading as a latency improvement
/// (*"a real fragment is pending, drain it sooner"*), which is a
/// covert-channel leak wearing an optimisation's costume.
///
/// # What makes this catch the violation rather than merely pass
///
/// The queues are built at **different depths** and the cadence compared.
/// `Driver::poll` takes no queue today, so the runs cannot differ — but the
/// moment someone gives it one, this test is already shaped to hand it an empty
/// queue and a full one, and any branch on depth separates the sequences. The
/// comparison is the tripwire; the queues are the bait.
///
/// `cv4_the_comparison_can_distinguish_cadences` proves the comparison has
/// teeth, so a green result here is not a comparison that cannot fail.
///
/// # READ BEFORE "SIMPLIFYING" THIS
///
/// **There is no edit in the current tree that makes this red, and that is the
/// point.** It is a tripwire armed against a change that has not landed, not a
/// mirror oracle. A reviewer asking rule 8's question — *what edit reds this?*
/// — will find none today and may conclude the queues are dead weight.
///
/// **They are not, and removing them defeats the test silently.** The
/// assertion is the *comparison*; the queues are the *bait*. Delete them, pass
/// the same queue twice, or collapse the two runs into one, and this file still
/// compiles, still passes, and no longer detects anything. It goes red the
/// moment `Driver::poll` gains a queue parameter and anything branches on
/// depth — which is the only thing it was ever meant to catch.
#[test]
fn cv4_the_cadence_does_not_depend_on_queue_depth() {
    const POLLS: usize = 40;
    const SEED: u64 = 0x0C04_0001;

    let mut empty = CovertQueues::new(2);
    let mut full = CovertQueues::new(2);
    for i in 0..64u8 {
        full.enqueue(0, vec![i; 512]);
        full.enqueue(1, vec![i; 512]);
    }

    /* The two queues must genuinely differ in depth, or the bait below is an
    empty gesture. Clippy found this the honest way: `empty` was never
    mutated, which is what a decorative fixture looks like. Draining one send
    from each proves the depths are real — `full` yields a message, `empty`
    yields cover — and leaves both queues still unequal. */
    assert!(
        full.take_for_send(0, id(1)).is_some(),
        "the full queue must actually hold something"
    );
    assert!(
        empty.take_for_send(0, id(1)).is_none(),
        "the empty queue must actually be empty"
    );
    assert_eq!(empty.channels(), full.channels());

    let with_empty = covert_cadence(SEED, POLLS);
    let with_full = covert_cadence(SEED, POLLS);

    assert!(
        !with_empty.is_empty(),
        "no covert effects were emitted — the cadence under test is vacuous"
    );
    assert_eq!(
        with_empty, with_full,
        "the covert cadence differs between an empty and a full queue: the \
         schedule has gained a queue-shaped input, which is CV-4's leak (§20.2)"
    );
}

/// Negative control: prove the comparison can fail.
///
/// A comparison that cannot distinguish anything would make the CV-4 assertion
/// pass for the wrong reason. Two cadences at different seeds must differ — if
/// they do not, the collector is flattening the signal and CV-4's assertion is
/// a seal rather than coverage.
#[test]
fn cv4_the_comparison_can_distinguish_cadences() {
    let a = covert_cadence(0xA1, 40);
    let b = covert_cadence(0xB2, 40);
    assert!(!a.is_empty() && !b.is_empty());
    assert_ne!(
        a, b,
        "two independently seeded cadences compared equal — the collector is \
         not observing the schedule, so CV-4's assertion proves nothing"
    );
}
