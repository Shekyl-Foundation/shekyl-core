// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;
use crate::{Driver, Effect, FluffReach, LinkSecrecy, Zone};
use shekyl_relay_privacy::params::DandelionParams;
use shekyl_relay_privacy::rng::SplitMix64;

const W: usize = 64; // the window, via the dummy's length

fn id(byte: u8) -> ConnectionId {
    let mut b = [0u8; 16];
    b[0] = byte;
    ConnectionId::from_bytes(b)
}

fn queues(channels: usize) -> CovertQueues {
    CovertQueues::new(channels, vec![0xDD; W]).expect("non-empty dummy")
}

/// `n` windows, window `i` filled with byte `i`. Continuation and restart
/// are distinguishable by content, not just by how many takes remain.
fn striped(n: u8) -> Vec<u8> {
    (0..n).flat_map(|i| vec![i; W]).collect()
}

#[test]
fn a_zero_length_dummy_is_refused_because_it_is_not_cover() {
    assert!(CovertQueues::new(2, Vec::new()).is_none());
}

#[test]
fn the_window_is_the_dummys_length_and_nothing_else() {
    let q = queues(2);
    assert_eq!(q.window(), W);
    assert_eq!(q.channels(), 2);
}

/// **The invariant: every emission is exactly one window, real or cover.**
///
/// Length is the one thing a covert channel holds constant, so a real fragment
/// that differs in length from a dummy is a leak rather than a degradation.
#[test]
fn a_real_fragment_and_a_dummy_are_indistinguishable_by_length() {
    let mut q = queues(1);

    let cover = q.take_for_send(0, id(1)).expect("channel 0");
    assert_eq!(cover.bytes().len(), W, "a dummy is one window");
    cover.sent(&mut q);

    assert!(q.enqueue(0, striped(3)));
    for i in 0..3u8 {
        let real = q.take_for_send(0, id(1)).expect("channel 0");
        assert_eq!(
            real.bytes().len(),
            W,
            "a real fragment must be one window — a short send is distinguishable \
             from cover, which is the leak this channel exists to prevent"
        );
        assert_eq!(
            real.bytes(),
            &vec![i; W][..],
            "window {i} must be the corresponding slice, not a restart or skip"
        );
        real.sent(&mut q);
    }

    // Drained: back to cover, same length.
    let after = q.take_for_send(0, id(1)).expect("channel 0");
    assert_eq!(after.bytes().len(), W);
    after.sent(&mut q);
}

/// A message that is not a whole number of windows would end in a short
/// fragment. Refused at the boundary rather than padded, so the queue stays
/// format-agnostic and the window keeps one owner.
#[test]
fn a_message_that_is_not_a_whole_number_of_windows_is_refused() {
    let mut q = queues(1);
    assert!(!q.enqueue(0, vec![1u8; W - 1]), "short of a window");
    assert!(!q.enqueue(0, vec![1u8; W + 1]), "one over a window");
    assert!(!q.enqueue(0, Vec::new()), "empty");
    assert!(!q.enqueue(9, vec![1u8; W]), "no such channel");
    assert!(
        q.take_for_send(9, id(1)).is_none(),
        "no such channel is the only None"
    );

    // And a refusal must not block the message behind it.
    assert!(q.enqueue(0, vec![9u8; W]));
    let s = q.take_for_send(0, id(1)).expect("channel 0");
    assert_eq!(s.bytes(), &[9u8; W][..]);
    s.sent(&mut q);
}

/// **Dropping a token is a failure, and it is correct with no `Drop` code.**
///
/// `take_for_send` advances nothing, so an unresolved token leaves the queue
/// untouched and the next take produces the same fragment. That is what lets
/// the token cross an await: a `Drop` that had to restore state would need a
/// handle back into the queue, i.e. a borrow, and the transport is async.
#[test]
fn an_unresolved_send_restarts_rather_than_losing_or_advancing() {
    let mut q = queues(1);
    assert!(q.enqueue(0, striped(2)));

    let first = q.take_for_send(0, id(1)).expect("channel 0");
    let bytes = first.bytes().to_vec();
    drop(first); // forgotten, early return, lost to an error path

    let again = q.take_for_send(0, id(1)).expect("channel 0");
    assert_eq!(
        again.bytes(),
        &bytes[..],
        "an unresolved take must reproduce the same fragment, not advance past it"
    );
    again.sent(&mut q);
}

/// The token exists to cross an await. A stale `sent` after unbind-and-enqueue
/// must not walk into the successor message — that is the mutation the epoch
/// exists to refuse.
#[test]
fn a_stale_token_cannot_advance_a_later_message() {
    let mut q = queues(1);
    assert!(q.enqueue(0, striped(2)));
    let stale = q.take_for_send(0, id(1)).expect("ch0");

    q.unbind(0);
    assert!(q.enqueue(0, vec![9u8; W * 2]));
    stale.sent(&mut q); // must be a no-op, not a walk into the 9s

    let first = q.take_for_send(0, id(1)).expect("ch0");
    assert_eq!(
        first.bytes(),
        &[9u8; W][..],
        "stale sent must leave the successor at its first window"
    );
    first.sent(&mut q);
    let second = q.take_for_send(0, id(1)).expect("ch0");
    assert_eq!(second.bytes(), &[9u8; W][..]);
    second.sent(&mut q);
}

/// CV-1 (§20.5): a rebind discards the in-flight remainder and restarts.
///
/// This bites against deleting the rebind arm or popping the message on first
/// take. It does NOT cover transport-level send failure.
#[test]
fn cv1_a_rebind_restarts_the_message_rather_than_resuming_it() {
    let mut q = queues(1);
    assert!(q.enqueue(0, striped(3)));

    let a = q.take_for_send(0, id(1)).expect("ch0");
    assert_eq!(a.bytes(), &[0u8; W][..]);
    a.sent(&mut q);
    let b = q.take_for_send(0, id(1)).expect("ch0");
    assert_eq!(b.bytes(), &[1u8; W][..], "same peer continues");
    b.sent(&mut q); // two of three windows have gone to peer 1

    // The slot churns. The remainder must NOT travel to the successor.
    let after = q.take_for_send(0, id(2)).expect("ch0");
    assert_eq!(
        after.bytes(),
        &[0u8; W][..],
        "rebind restarts from the head; a 2-filled window would be a resume"
    );
    after.sent(&mut q);
    let second = q.take_for_send(0, id(2)).expect("ch0");
    assert_eq!(second.bytes(), &[1u8; W][..]);
    second.sent(&mut q);
    let third = q.take_for_send(0, id(2)).expect("ch0");
    assert_eq!(third.bytes(), &[2u8; W][..]);
    third.sent(&mut q);
    let drained = q.take_for_send(0, id(2)).expect("ch0");
    assert_eq!(
        drained.bytes(),
        &vec![0xDD; W][..],
        "after a rebind the message restarts, so three more windows are owed \
         before the channel returns to cover"
    );
    drained.sent(&mut q);
}

/// **The ordering interaction: failure and rebind both clear the in-flight
/// run, so drive them in both orders.**
///
/// Two paths that clear the same field is where an ordering assumption hides,
/// and convergence has to be shown rather than assumed. The post-condition is
/// remaining *work*, not two booleans that can both be wrong the same way.
#[test]
fn failure_and_rebind_converge_in_either_order() {
    // failure, then rebind
    let mut a = queues(1);
    assert!(a.enqueue(0, vec![1u8; W * 2]));
    let t = a.take_for_send(0, id(1)).expect("ch0");
    t.sent(&mut a);
    let t = a.take_for_send(0, id(1)).expect("ch0");
    t.failed(&mut a); // clears offset AND unbinds
    let after_a = a.take_for_send(0, id(2)).expect("ch0"); // rebind on top
    assert_eq!(after_a.bytes(), &[1u8; W][..], "restart from the head");
    after_a.sent(&mut a);

    // rebind, then failure
    let mut b = queues(1);
    assert!(b.enqueue(0, vec![1u8; W * 2]));
    let t = b.take_for_send(0, id(1)).expect("ch0");
    t.sent(&mut b);
    let t = b.take_for_send(0, id(2)).expect("ch0"); // rebind first
    t.failed(&mut b); // then failure
    let after_b = b.take_for_send(0, id(2)).expect("ch0");
    assert_eq!(after_b.bytes(), &[1u8; W][..], "restart from the head");
    after_b.sent(&mut b);

    // One full restart was in flight, one window of it has gone out, so each
    // queue still owes the second window of 1s, then cover.
    let a_left = a.take_for_send(0, id(2)).expect("ch0");
    let b_left = b.take_for_send(0, id(2)).expect("ch0");
    assert_eq!(a_left.bytes(), &[1u8; W][..]);
    assert_eq!(b_left.bytes(), &[1u8; W][..]);
    a_left.sent(&mut a);
    b_left.sent(&mut b);
    let a_cover = a.take_for_send(0, id(2)).expect("ch0");
    let b_cover = b.take_for_send(0, id(2)).expect("ch0");
    assert_eq!(a_cover.bytes(), &vec![0xDD; W][..]);
    assert_eq!(b_cover.bytes(), &vec![0xDD; W][..]);
}

/// A failed send costs a fragment, not a transaction: the message restarts.
#[test]
fn a_failed_send_keeps_the_message_and_unbinds() {
    let mut q = queues(1);
    assert!(q.enqueue(0, vec![4u8; W]));

    let t = q.take_for_send(0, id(1)).expect("ch0");
    t.failed(&mut q);

    // Still owed — the message was not dropped.
    let retry = q.take_for_send(0, id(1)).expect("ch0");
    assert_eq!(retry.bytes(), &[4u8; W][..]);
    retry.sent(&mut q);
    let cover = q.take_for_send(0, id(1)).expect("ch0");
    assert_eq!(cover.bytes(), &vec![0xDD; W][..]);
    cover.sent(&mut q);
}

#[test]
fn unbind_drops_everything_the_channel_held() {
    let mut q = queues(1);
    assert!(q.enqueue(0, vec![6u8; W * 2]));
    q.unbind(0);
    let s = q.take_for_send(0, id(1)).expect("ch0");
    assert_eq!(s.bytes(), &vec![0xDD; W][..], "unbind clears pending");
    s.sent(&mut q);
}

/// Drive the scheduler and collect the covert cadence, including the tick.
///
/// **The tick is part of the observation, not decoration.** An earlier version
/// collected `(channel, kind)` only, and the negative control caught it: two
/// independently seeded runs produced identical channel sequences, because
/// channel *order* is not where the schedule's randomness lives — timing is.
///
/// **`queues` is the bait, and it is an input today.** `Driver::poll` does
/// not take a queue — that is the invariant, and wiring it is step 4, not
/// this PR. This parameter exists so that the moment `poll` grows a
/// queue-shaped argument, the compiler forces this function to pass *this*
/// queue, and the two depths the CV-4 test built already flow in. A `_queues`
/// that is never mentioned, or a cadence helper that does not take one, is
/// the decorative fixture this test exists to refuse.
fn covert_cadence(seed: u64, polls: usize, queues: &mut CovertQueues) -> Vec<(u64, usize, bool)> {
    let mut rng = SplitMix64::new(seed);
    let zone = Zone::new(
        DandelionParams::inherited(),
        2,
        FluffReach::OutboundOnly,
        LinkSecrecy::Encrypted,
        true, // covert ON, or there are no deadlines and this is vacuous
        0,
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        queues.channels(),
        zone.stem_width(),
        "the bait queue must be the same width as the schedule under test — \
         otherwise a later poll(queue) change can pair the schedule with a \
         differently-shaped queue and the comparison is no longer about depth"
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
/// # READ BEFORE "SIMPLIFYING" THIS
///
/// **There is no edit in the current `poll` body that makes this red, and
/// that is the point.** `Driver::poll` takes no queue — wiring it is step 4.
/// A reviewer asking rule 8's question — *what edit reds this?* — will find
/// none in today's poll and may conclude the queues are dead weight.
///
/// **They are not, and removing them defeats the test silently.** The
/// assertion is the *comparison*; the queues are the *bait*. Delete them
/// from [`covert_cadence`], pass the same queue twice, or collapse the two
/// runs into one, and this file still compiles, still passes, and no longer
/// detects anything. It goes red the moment `Driver::poll` gains a queue
/// parameter and anything branches on depth — the only thing it was ever
/// meant to catch.
#[test]
fn cv4_the_cadence_does_not_depend_on_queue_depth() {
    const POLLS: usize = 40;
    const SEED: u64 = 0x0C04_0001;

    let mut empty = queues(2);
    let mut full = queues(2);
    for i in 0..64u8 {
        full.enqueue(0, vec![i; W * 4]);
        full.enqueue(1, vec![i; W * 4]);
    }
    // The depths must genuinely differ, or the bait is an empty gesture.
    let f = full.take_for_send(0, id(1)).expect("ch0");
    assert_eq!(
        f.bytes(),
        &[0u8; W][..],
        "the full queue holds real traffic"
    );
    f.sent(&mut full);
    let e = empty.take_for_send(0, id(1)).expect("ch0");
    assert_eq!(e.bytes(), &vec![0xDD; W][..], "the empty queue emits cover");
    e.sent(&mut empty);

    let with_empty = covert_cadence(SEED, POLLS, &mut empty);
    let with_full = covert_cadence(SEED, POLLS, &mut full);

    assert!(
        !with_empty.is_empty(),
        "no covert effects — cadence is vacuous"
    );
    assert_eq!(
        with_empty, with_full,
        "the covert cadence differs between an empty and a full queue: the \
         schedule has gained a queue-shaped input, which is CV-4's leak (§20.2)"
    );
}

/// Negative control: prove the comparison can fail.
#[test]
fn cv4_the_comparison_can_distinguish_cadences() {
    let mut qa = queues(2);
    let mut qb = queues(2);
    let a = covert_cadence(0xA1, 40, &mut qa);
    let b = covert_cadence(0xB2, 40, &mut qb);
    assert!(!a.is_empty() && !b.is_empty());
    assert_ne!(
        a, b,
        "two independently seeded cadences compared equal — the collector is \
         not observing the schedule, so CV-4's assertion proves nothing"
    );
}
