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

/// Production covert fragment window (`CRYPTONOTE_NOISE_BYTES` = 3 KiB).
/// Tests that do not care about remainder use this so a take consumes the
/// whole fixture message in one call.
const FRAG: usize = 3 * 1024;

#[test]
fn a_dummy_is_the_common_case_not_an_error() {
    let mut q = CovertQueues::new(2);
    assert_eq!(q.channels(), 2);
    assert_eq!(q.take_for_send(0, id(1), FRAG), None);
}

#[test]
fn a_queued_message_goes_out_once_then_the_channel_returns_to_cover() {
    let mut q = CovertQueues::new(2);
    assert!(q.enqueue(0, vec![7, 7, 7]));
    assert_eq!(q.take_for_send(0, id(1), FRAG), Some(vec![7, 7, 7]));
    assert_eq!(
        q.take_for_send(0, id(1), FRAG),
        None,
        "a message travels once"
    );
}

#[test]
fn an_out_of_range_channel_is_refused_rather_than_silently_dropped() {
    let mut q = CovertQueues::new(2);
    assert!(!q.enqueue(9, vec![1]));
    assert_eq!(q.take_for_send(9, id(1), FRAG), None);
}

/// Same-peer takes consume the remainder. This is what CV-1 *discards* on a
/// rebind — without this, a rebind test that only checks `is_some()` cannot
/// tell a restart from a resume.
#[test]
fn a_same_peer_take_continues_the_remainder() {
    let mut q = CovertQueues::new(1);
    q.enqueue(0, vec![1; 1000]);
    assert_eq!(
        q.take_for_send(0, id(1), 512).as_deref(),
        Some(&[1; 512][..])
    );
    assert_eq!(
        q.take_for_send(0, id(1), 512).as_deref(),
        Some(&[1; 488][..]),
        "same peer must finish the tail, not restart"
    );
    assert_eq!(q.take_for_send(0, id(1), 512), None);
}

/// CV-1 (§20.5): a rebind discards the in-flight remainder and *restarts*
/// the queued message. Resuming the 488-byte tail would make that send
/// shorter than a dummy; dropping the message would lose a covert-carried
/// stem. Restart matches `send_noise`.
///
/// This bites against deleting the rebind arm or popping the message on
/// first take. It does NOT cover transport-level send failure.
#[test]
fn cv1_a_rebind_discards_the_remainder_and_restarts() {
    let mut q = CovertQueues::new(1);
    q.enqueue(0, vec![1; 1000]);
    q.enqueue(0, vec![2; 1000]);

    assert_eq!(
        q.take_for_send(0, id(1), 512).as_deref(),
        Some(&[1; 512][..])
    );

    let after_rebind = q
        .take_for_send(0, id(2), 512)
        .expect("rebind must not wedge");
    assert_eq!(
        after_rebind,
        vec![1; 512],
        "rebind restarts the queued message; a 488-byte tail would be a resume \
         (the length leak) and a 2-filled fragment would have dropped the first \
         message"
    );

    q.unbind(0);
    assert_eq!(q.take_for_send(0, id(3), FRAG), None);
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
///
/// **`queues` is the bait, and it is an input today.** `Driver::poll` does
/// not take a queue — that is the invariant. This parameter exists so that
/// the moment `poll` grows a queue-shaped argument, the compiler forces
/// this function to pass *this* queue, and the two depths the CV-4 test
/// built already flow in. A `_queues` that is never mentioned, or a
/// cadence helper that does not take one, is the decorative fixture this
/// test exists to refuse.
fn covert_cadence(seed: u64, polls: usize, queues: &mut CovertQueues) -> Vec<(u64, usize, bool)> {
    let mut rng = SplitMix64::new(seed);
    let zone = Zone::new(
        DandelionParams::inherited(),
        2,
        FluffReach::OutboundOnly,
        true, // covert ON, or there are no deadlines and this is vacuous
        0,
        &mut rng,
    );
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
/// This replaces the friction the C++/Rust split used to supply. Before the
/// cutover, wiring queue depth into the schedule meant a `#[repr(C)]` field or
/// a new FFI entry point — loud in review. In one crate it is
/// `if q.has_pending() { … }`: one line, reading as a latency improvement
/// (*"a real fragment is pending, drain it sooner"*), which is a
/// covert-channel leak wearing an optimisation's costume.
///
/// # What makes this catch the violation rather than merely pass
///
/// The queues are built at **different depths** and handed to
/// [`covert_cadence`]. `Driver::poll` takes no queue today, so the runs
/// cannot differ — but the moment someone gives it one, this test already
/// hands an empty queue and a full one, and any branch on depth separates
/// the sequences. The comparison is the tripwire; the queues are the bait.
///
/// `cv4_the_comparison_can_distinguish_cadences` proves the comparison has
/// teeth, so a green result here is not a comparison that cannot fail.
///
/// # READ BEFORE "SIMPLIFYING" THIS
///
/// **There is no edit in the current `poll` body that makes this red, and
/// that is the point.** It is a tripwire armed against a change that has
/// not landed, not a mirror oracle. Removing `queues` from
/// [`covert_cadence`], passing the same queue twice, or collapsing the two
/// runs into one, makes this file compile, pass, and detect nothing.
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
    mutated, which is what a decorative fixture looks like. Draining one
    fragment from each proves the depths are real — `full` yields a
    message, `empty` yields cover — and leaves both queues still unequal. */
    assert!(
        full.take_for_send(0, id(1), FRAG).is_some(),
        "the full queue must actually hold something"
    );
    assert!(
        empty.take_for_send(0, id(1), FRAG).is_none(),
        "the empty queue must actually be empty"
    );
    assert_eq!(empty.channels(), full.channels());

    let with_empty = covert_cadence(SEED, POLLS, &mut empty);
    let with_full = covert_cadence(SEED, POLLS, &mut full);

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
    let mut qa = CovertQueues::new(2);
    let mut qb = CovertQueues::new(2);
    let a = covert_cadence(0xA1, 40, &mut qa);
    let b = covert_cadence(0xB2, 40, &mut qb);
    assert!(!a.is_empty() && !b.is_empty());
    assert_ne!(
        a, b,
        "two independently seeded cadences compared equal — the collector is \
         not observing the schedule, so CV-4's assertion proves nothing"
    );
}

/// An empty framed message is refused, and — the property that matters — it
/// cannot wedge the channel behind it.
///
/// Before the guard, an empty head was reloaded on every take and never
/// popped, so every later message was blocked permanently. The failure was
/// **invisible by construction**: the channel kept emitting dummies, which is
/// exactly what a healthy idle channel looks like. Nothing observable changes
/// when constant-rate cover stops carrying anything, which is why this needs a
/// test rather than an operator noticing.
#[test]
fn an_empty_message_is_refused_and_cannot_wedge_the_channel() {
    let mut q = CovertQueues::new(1);

    assert!(
        !q.enqueue(0, Vec::new()),
        "an empty framed message is a caller bug; a levin notify always has a header"
    );

    // The real message behind it must still go out. This is the regression:
    // with the empty accepted, this send never happened — ever.
    assert!(q.enqueue(0, vec![9; 8]));
    assert_eq!(
        q.take_for_send(0, id(1), 4096),
        Some(vec![9; 8]),
        "a refused empty must not block the message behind it"
    );
}
