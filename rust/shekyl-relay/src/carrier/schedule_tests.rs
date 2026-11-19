// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The carrier schedule driven beside the zone, on one test clock.
//!
//! These are the cadence, the binding and the epoch tail. The zone's own
//! poll tests stay with the driver.

use shekyl_draw_rng::SplitMix64;
use shekyl_relay_privacy::params::DandelionParams;
use shekyl_relay_privacy::schedule::PeerDirection;
use shekyl_relay_privacy::stem_map::ConnectionId;

use super::pair::{Pair, Step};
use crate::driver::{Driver, Effect};
use crate::graph::Relay;
use crate::noise_queue::Starts;
use crate::ConnectorId;

fn id(byte: u8) -> ConnectionId {
    let mut b = [0u8; 16];
    b[0] = byte;
    ConnectionId::from_bytes(b)
}

/// Cover off: no carrier schedule, so a hole has no tick to clear on.
fn driver(rng: &mut SplitMix64) -> Driver {
    Driver::new(
        Relay::new(
            DandelionParams::inherited(),
            2,
            false,
            &[ConnectorId::Clearnet],
            &[],
            0,
            rng,
        )
        .unwrap(),
    )
}

/// A **due** channel whose slot is unbound emits `NoiseDue::Unbind`
/// at its own index, **at every due tick** — the fact the deleted slot
/// array carried that a send cannot: an unbound channel emits no sends
/// (CV-2), so *stopping* must cross on its own, or the C++ enqueue guard
/// reads a stale binding forever.
///
/// The repetition assertion (≥ 2 unbinds) is not a detail — it is the
/// derive-don't-cache half of the property. A transition-shaped emission
/// fires once and is lossy: a swallowed clear leaves the guard stale
/// permanently, the exact failure the effect exists to prevent. Per-tick
/// derivation self-heals, and this test fails if the emission ever
/// becomes one-shot.
///
/// Negative-controlled, each injected into `poll`'s covert arm and
/// observed to fail:
/// - **drop the unbind arm** (emit nothing for an unbound channel — the
///   part-A regression this fix exists for): the repetition assertion
///   fails at zero;
/// - **index off-by-one** (`channel + 1` on the unbind): the
///   own-index assertion fails;
/// - **invert the binding condition** (unbind when bound): the bound
///   channel's send assertion fails here, and the rebind leg of
///   [`a_rebind_and_a_noise_disabled_zone_emit_no_unbind`] with it.
#[test]
fn a_due_channel_with_an_unbound_slot_clears_at_every_tick() {
    let mut rng = SplitMix64::new(31);
    let d = Driver::new(
        Relay::new(
            DandelionParams::inherited(),
            2,
            true,
            &[ConnectorId::Clearnet],
            &[ConnectorId::Clearnet],
            0,
            &mut rng,
        )
        .unwrap(),
    );
    let mut d = Pair::new(d, &mut rng);
    d.zone_mut().on_session_established(
        id(1),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    d.zone_mut().on_session_established(
        id(2),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );

    // The hole recipe the CV-2 witness established: close the slot's peer
    // AND re-offer only the survivor, so nothing backfills.
    let slot0_peer = d.zone().stem_slots()[0].expect("slot 0 bound");
    let keep = d.zone().stem_slots()[1].expect("slot 1 bound");
    d.zone_mut().on_connection_close(&slot0_peer);
    d.zone_mut().on_session_established(
        keep,
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    assert_eq!(
        d.zone().stem_slots()[0],
        None,
        "fixture: the hole is at index 0"
    );
    assert_eq!(
        d.zone().stem_slots()[1],
        Some(keep),
        "fixture: slot 1 kept its own peer"
    );

    // Drive due ticks. Every effect must be one of exactly two shapes:
    // the unbound channel clearing at its own index, or the bound channel
    // sending to its own peer. `no_gather` doubles as the witness that no
    // epoch rollover rewrote the fixture mid-drive (12 covert ticks at
    // 10–15 s sit far inside the 600 s epoch minimum).
    let (mut unbinds, mut sends) = (0, 0);
    for _ in 0..12 {
        if unbinds >= 2 && sends >= 2 {
            break;
        }
        let wake = d.next_wake();
        for e in d.poll(wake, &mut rng) {
            match e {
                Step::NoiseUnbind { channel } => {
                    assert_eq!(
                        channel, 0,
                        "only the unbound channel clears — 1 here is the \
                         off-by-one or the fire-on-bound defect"
                    );
                    unbinds += 1;
                }
                Step::NoiseSend { channel, peer, .. } => {
                    assert_eq!(
                        (channel, peer),
                        (1, keep),
                        "the bound channel keeps sending its own peer at \
                         its own index"
                    );
                    sends += 1;
                }
                Step::Zone(Effect::Fluff { .. }) => unreachable!("nothing was queued"),
                Step::Zone(Effect::Stem { .. } | Effect::Published { .. }) => {
                    unreachable!("nothing was stemmed or held")
                }
            }
        }
    }
    assert!(
        unbinds >= 2,
        "the unbound channel clears at EVERY due tick — zero means the \
         unbind arm is gone (the enqueue-guard leak), one means the \
         emission became transition-shaped and lossy"
    );
    assert!(sends >= 2, "the bound channel keeps sending — liveness");
}

/// The two states that must NOT produce an unbind: a **rebound** slot (the
/// new binding travels with the next send, where CV-1's discard lives —
/// and clearing the queue on a rebind would drop messages the inherited
/// repoint delivered to the successor), and a zone without covert channels
/// (structurally: no covert deadlines exist, so there is no tick for an
/// unbind to ride). Standing negative pair for
/// [`a_due_channel_with_an_unbound_slot_clears_at_every_tick`].
#[test]
fn a_rebind_and_a_noise_disabled_zone_emit_no_unbind() {
    // Rebind: close slot 0's peer but offer a replacement, so the churned
    // slot refills — bound again by the time any tick comes due.
    let mut rng = SplitMix64::new(37);
    let d = Driver::new(
        Relay::new(
            DandelionParams::inherited(),
            2,
            true,
            &[ConnectorId::Clearnet],
            &[ConnectorId::Clearnet],
            0,
            &mut rng,
        )
        .unwrap(),
    );
    let mut d = Pair::new(d, &mut rng);
    d.zone_mut().on_session_established(
        id(1),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    d.zone_mut().on_session_established(
        id(2),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    let slot0_peer = d.zone().stem_slots()[0].expect("slot 0 bound");
    let keep = d.zone().stem_slots()[1].expect("slot 1 bound");
    d.zone_mut().on_connection_close(&slot0_peer);
    d.zone_mut().on_session_established(
        id(3),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    assert_eq!(
        d.zone().stem_slots(),
        &[Some(id(3)), Some(keep)],
        "fixture: the churned slot refilled — this is a rebind, not a hole"
    );
    let mut sends = 0;
    for _ in 0..8 {
        if sends >= 4 {
            break;
        }
        let wake = d.next_wake();
        for e in d.poll(wake, &mut rng) {
            match e {
                Step::NoiseSend { .. } => sends += 1,
                Step::NoiseUnbind { channel } => panic!(
                    "channel {channel} cleared on a rebound slot — this \
                     drops queued messages the inherited repoint \
                     delivered to the successor"
                ),
                Step::Zone(Effect::Fluff { .. }) => unreachable!("nothing was queued"),
                Step::Zone(Effect::Stem { .. } | Effect::Published { .. }) => {
                    unreachable!("nothing was stemmed or held")
                }
            }
        }
    }
    assert!(sends >= 4, "both rebound channels keep sending — liveness");

    // Covert disabled: no covert deadline exists at all, so the unbind
    // has no tick to ride — the gate is the schedule's absence, not a
    // check. The hole is still constructed, so the emptiness below comes
    // from the missing schedule and not from the state failing to happen.
    let d = driver(&mut rng);
    let mut d = Pair::new(d, &mut rng);
    d.zone_mut().on_session_established(
        id(1),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    d.zone_mut().on_session_established(
        id(2),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    let slot0_peer = d.zone().stem_slots()[0].expect("slot 0 bound");
    let keep = d.zone().stem_slots()[1].expect("slot 1 bound");
    d.zone_mut().on_connection_close(&slot0_peer);
    d.zone_mut().on_session_established(
        keep,
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    assert_eq!(
        d.zone().stem_slots()[0],
        None,
        "fixture: the hole exists on the disabled zone too"
    );
    assert_eq!(
        d.carrier_deadline(),
        None,
        "no covert schedule ⇒ no tick for an unbind to ride"
    );
    assert!(
        d.poll(d.zone().epoch_deadline() - 1, &mut rng).is_empty(),
        "nothing is due before the epoch on a zone without covert channels"
    );
}

/// Noise channels emit **independently**: one `NoiseSend` per advance.
///
/// **This is a soundness property, not an implementation preference.**
/// Constant-rate cover works because the aggregate rate is constant. Two
/// channels firing together produce a 2×fragment burst against otherwise
/// empty intervals, making aggregate emission bursty and periodic — exactly
/// the shape the mechanism exists to deny an observer. So synchronization
/// is not merely different, it is a defect.
///
/// **Why it lives here and not in the `levin_notify` gtests.** The C++
/// covert path draws deadlines from `SecureRelayRng` (`OsRng`), which has no
/// seam — so a per-advance count assertion there flakes whenever two draws
/// collide (~1 in 5,000 over a 5 s band at ms granularity). Making it
/// deterministic would need a test-only seeding hook, which is precisely the
/// test-drive divergence RP-3b removed everywhere else. Here the RNG is a
/// **generic parameter**, not a branch: production instantiates with
/// `SecureRelayRng`, this with `SplitMix64`, and the logic is byte-identical.
/// A parameter is not a test-only channel; a branch is. Same for `now`.
///
/// The gtests keep what §20.5 says that oracle is for — counts, status,
/// payload identity — and assert them collision-robustly. Cadence is
/// asserted here, exactly, where it can be.
///
/// **Negative-controlled per leg, because synchronization has two entry
/// points and one injection cannot reach both.** A construction-time
/// injection (all channels share one initial deadline) trips the *fixture*
/// assertion — proving the precondition is sound, not that the count
/// assertion bites. An emission-time injection (the due predicate broken so
/// every channel fires on every wake, deadlines left distinct) trips the
/// *count* assertion with `[0, 1]`. Both were run and observed to fail. A
/// control that only reaches the precondition would be the
/// asserted-a-constant-against-itself shape at one remove.
#[test]
fn noise_channels_emit_one_per_advance_not_synchronized() {
    let mut rng = SplitMix64::new(11);
    let d = Driver::new(
        Relay::new(
            DandelionParams::inherited(),
            2,
            true,
            &[ConnectorId::Clearnet],
            &[ConnectorId::Clearnet],
            0,
            &mut rng,
        )
        .unwrap(),
    );
    let mut d = Pair::new(d, &mut rng);
    // Bind both slots: since the inversion, an unbound slot emits no send
    // (CV-2), and this test is about cadence, not binding.
    d.zone_mut().on_session_established(
        id(1),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    d.zone_mut().on_session_established(
        id(2),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );

    // Fixture requirement: distinct deadlines, or "one per advance" could
    // hold by coincidence rather than by independence.
    let (a, b) = (
        d.carrier
            .as_ref()
            .expect("a carrier")
            .deadline_at(0)
            .expect("ch0 armed"),
        d.carrier
            .as_ref()
            .expect("a carrier")
            .deadline_at(1)
            .expect("ch1 armed"),
    );
    assert_ne!(a, b, "the two channels must be armed independently");

    // Advance to the earliest deadline: exactly one channel is due.
    let first = d.next_wake();
    let covert: Vec<usize> = d
        .poll(first, &mut rng)
        .into_iter()
        .filter_map(|e| match e {
            Step::NoiseSend { channel, .. } => Some(channel),
            _ => None,
        })
        .collect();
    assert_eq!(
        covert.len(),
        1,
        "one advance fires one channel; {covert:?} means the channels are \
         synchronized, which makes aggregate emission bursty"
    );
    let firstc = covert[0];

    // Keep advancing: one channel per advance, and the other channel within
    // a bound. The cadence is memoryless (`CVR-R4`), so the same channel may
    // fire several times running; a run of `LIVENESS_ADVANCES` on two
    // independent channels has probability 2^-LIVENESS_ADVANCES.
    const LIVENESS_ADVANCES: u32 = 64;
    let mut last = first;
    let mut other_fired = false;
    for advance in 0..LIVENESS_ADVANCES {
        let wake = d.next_wake();
        assert!(wake > last, "the next wake is strictly later");
        last = wake;
        let fired: Vec<usize> = d
            .poll(wake, &mut rng)
            .into_iter()
            .filter_map(|e| match e {
                Step::NoiseSend { channel, .. } => Some(channel),
                _ => None,
            })
            .collect();
        assert_eq!(
            fired.len(),
            1,
            "advance {advance} fires exactly one, got {fired:?}"
        );
        if fired[0] != firstc {
            other_fired = true;
            break;
        }
    }
    assert!(
        other_fired,
        "the OTHER channel fires too — liveness, so a scheduler that only \
         ever serves channel {firstc} cannot pass"
    );
}

/// CV-2, half 1: a covert send carries **its own slot's** peer, at **its
/// own** index.
///
/// **Successor of `stem_slots_cross_in_index_order_with_nils_in_position`**
/// (the RP-3a seal), restated for the inversion per §20.3: there is no
/// array any more, so "nils in position" has nothing to be in — the
/// property becomes *per-emission* index/peer identity, checked against
/// the owning structure (`stem_slots()`), never against the emission
/// stream itself. That sourcing is what made the RP-3a reversal bug
/// detectable, and it is kept deliberately.
///
/// Negative-controlled in the post-inversion forms (each injected into
/// `poll`'s emission mapping and observed to fail):
/// - **reorder**: emit the *other* slot's peer → peer-identity fails;
/// - **index off-by-one**: emit `channel + 1` → index-identity fails.
///   This control only exists because the inversion introduced a channel
///   index; the array had no index to be off by.
#[test]
fn noise_sends_carry_the_slots_own_peer_at_its_own_index() {
    let mut rng = SplitMix64::new(23);
    let d = Driver::new(
        Relay::new(
            DandelionParams::inherited(),
            2,
            true,
            &[ConnectorId::Clearnet],
            &[ConnectorId::Clearnet],
            0,
            &mut rng,
        )
        .unwrap(),
    );
    let mut d = Pair::new(d, &mut rng);
    d.zone_mut().on_session_established(
        id(1),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    d.zone_mut().on_session_established(
        id(2),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );

    // Ground truth from the owning structure, captured before driving.
    let truth: Vec<Option<ConnectionId>> = d.zone().stem_slots().to_vec();
    assert!(
        truth.iter().all(Option::is_some),
        "fixture: both slots bound"
    );

    // Drive until BOTH channels have emitted — the liveness requirement:
    // without it, "every emission was correct" and "channel 1 never fired"
    // are indistinguishable, which is the seal-is-not-coverage failure
    // one level down.
    let mut seen = [false; 2];
    for _ in 0..16 {
        if seen.iter().all(|s| *s) {
            break;
        }
        let wake = d.next_wake();
        for e in d.poll(wake, &mut rng) {
            if let Step::NoiseSend { channel, peer, .. } = e {
                assert_eq!(
                    Some(peer),
                    truth[channel],
                    "channel {channel} must carry its own slot's peer — a \
                     different slot's peer is the reorder defect"
                );
                seen[channel] = true;
            }
        }
    }
    assert_eq!(
        seen,
        [true, true],
        "both bound channels must emit — liveness, so a scheduler that \
         serves one channel cannot pass by emitting nothing wrong"
    );
}

/// CV-2, half 2: an **unbound** slot emits no covert *send* at its index,
/// and shifts no other channel's index. (Its due tick carries the clear
/// instead — `NoiseDue::Unbind`, witnessed separately — which this
/// test's collector deliberately ignores: CV-2 is a statement about wire
/// emissions, and an unbind never reaches the wire.)
///
/// The hole is placed at index **0** with the surviving binding at index
/// **1**, deliberately: compaction shifts *down*, so a hole above the
/// binding would make the compaction injection invisible. With the hole
/// below, compacting emits channel 1's peer at index 0 — the exact
/// silent-misbinding the RP-3a seal existed to catch, in its
/// post-inversion form.
///
/// Negative-controlled: injecting dense re-indexing (emit at
/// `emitted_count` instead of the slot index) fails the index assertion.
#[test]
fn an_unbound_channel_emits_no_send_and_shifts_no_other() {
    let mut rng = SplitMix64::new(29);
    let d = Driver::new(
        Relay::new(
            DandelionParams::inherited(),
            2,
            true,
            &[ConnectorId::Clearnet],
            &[ConnectorId::Clearnet],
            0,
            &mut rng,
        )
        .unwrap(),
    );
    let mut d = Pair::new(d, &mut rng);
    d.zone_mut().on_session_established(
        id(1),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    d.zone_mut().on_session_established(
        id(2),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );

    // Make a hole at index 0 the way the RP-3a seal did: close slot 0's
    // peer AND re-offer only slot 1's, so there is nothing to backfill
    // with. (Close alone is not enough — churn REFILLS a slot from the
    // surviving outbound set; the hole exists only when the pool cannot
    // cover the width. The fixture assertion below caught exactly that
    // when this test was first written against a close-only recipe.)
    let slot0_peer = d.zone().stem_slots()[0].expect("slot 0 bound");
    let keep = d.zone().stem_slots()[1].expect("slot 1 bound");
    d.zone_mut().on_connection_close(&slot0_peer);
    d.zone_mut().on_session_established(
        keep,
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    let truth: Vec<Option<ConnectionId>> = d.zone().stem_slots().to_vec();
    assert_eq!(truth[0], None, "fixture: the hole is at index 0");
    let bound = truth[1].expect("fixture: index 1 still bound");

    let mut emissions = Vec::new();
    for _ in 0..16 {
        if emissions.len() >= 3 {
            break;
        }
        let wake = d.next_wake();
        for e in d.poll(wake, &mut rng) {
            if let Step::NoiseSend { channel, peer, .. } = e {
                emissions.push((channel, peer));
            }
        }
    }

    // Liveness: the bound channel really emitted, repeatedly — so "no
    // wrong emission" cannot be satisfied by no emission at all.
    assert!(
        emissions.len() >= 3,
        "the bound channel keeps emitting past the hole"
    );
    for (channel, peer) in emissions {
        assert_eq!(
            (channel, peer),
            (1, bound),
            "every emission names index 1 and its own peer — index 0 here \
             is the compaction defect (channel 1's send shifted into the \
             hole), exactly what the RP-3a seal caught in array form"
        );
    }
}

/// A late zone-strand poll that finds several covert deadlines past must still
/// emit **at most one** covert effect.
///
/// Production `relay_wake` polls with wall-clock `now_ms()`, not `next_wake()`.
/// After a stall both channels can be overdue; firing them together is the
/// synchronized multi-channel burst constant-rate cover exists to deny (see
/// [`noise_channels_emit_one_per_advance_not_synchronized`]). The remaining
/// due channel surfaces on the next wake.
///
/// Also pins re-arm-from-`now`: the fired channel's new deadline is strictly
/// after the poll time, so a multi-interval stall cannot catch-up-burst.
#[test]
fn a_late_poll_emits_at_most_one_noise_channel() {
    let mut rng = SplitMix64::new(13);
    let d = Driver::new(
        Relay::new(
            DandelionParams::inherited(),
            2,
            true,
            &[ConnectorId::Clearnet],
            &[ConnectorId::Clearnet],
            0,
            &mut rng,
        )
        .unwrap(),
    );
    let mut d = Pair::new(d, &mut rng);
    d.zone_mut().on_session_established(
        id(1),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    d.zone_mut().on_session_established(
        id(2),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );

    let a = d
        .carrier
        .as_ref()
        .expect("a carrier")
        .deadline_at(0)
        .expect("ch0 armed");
    let b = d
        .carrier
        .as_ref()
        .expect("a carrier")
        .deadline_at(1)
        .expect("ch1 armed");
    assert_ne!(a, b, "fixture: independent arms");
    let late = a.max(b) + 60_000;

    let first: Vec<usize> = d
        .poll(late, &mut rng)
        .into_iter()
        .filter_map(|e| match e {
            Step::NoiseSend { channel, .. } | Step::NoiseUnbind { channel } => Some(channel),
            Step::Zone(Effect::Fluff { .. } | Effect::Stem { .. } | Effect::Published { .. }) => {
                None
            }
        })
        .collect();
    assert_eq!(
        first.len(),
        1,
        "a late poll that is past both deadlines must not multi-fire; got {first:?}"
    );
    let fired = first[0];
    let rearmed = d
        .carrier
        .as_ref()
        .expect("a carrier")
        .deadline_at(fired)
        .expect("fired channel still scheduled");
    assert!(
        rearmed > late,
        "re-arm from now (poll time), not a past deadline: rearmed={rearmed} late={late}"
    );

    // The sibling is still due (its deadline is in the past) and must be the
    // next covert effect — independence, not a permanent single-channel lock.
    let second: Vec<usize> = d
        .poll(late, &mut rng)
        .into_iter()
        .filter_map(|e| match e {
            Step::NoiseSend { channel, .. } | Step::NoiseUnbind { channel } => Some(channel),
            Step::Zone(Effect::Fluff { .. } | Effect::Stem { .. } | Effect::Published { .. }) => {
                None
            }
        })
        .collect();
    assert_eq!(second.len(), 1, "the remaining overdue channel fires next");
    assert_ne!(
        second[0], fired,
        "the second late poll serves the OTHER channel"
    );
}

/// One carrier send as the actor makes it: take the window for the effect's
/// peer and starts, write it, resolve it. Returns whether the window was
/// real (a message byte, not the dummy's).
fn carry(
    queues: &mut crate::NoiseQueues,
    channel: usize,
    peer: ConnectionId,
    starts: Starts,
) -> bool {
    let send = queues
        .take_for_send(channel, peer, starts)
        .expect("the channel exists");
    let real = send.bytes().first() == Some(&REAL_BYTE);
    send.sent(queues);
    real
}

const WINDOW: usize = 8;
const REAL_BYTE: u8 = 0xAA;

/// A carrier zone over four encrypted clearnet sessions, both slots bound.
fn carrier_driver(seed: u64) -> (Pair, SplitMix64) {
    let mut rng = SplitMix64::new(seed);
    let d = Driver::new(
        Relay::new(
            DandelionParams::inherited(),
            2,
            true,
            &[ConnectorId::Clearnet],
            &[ConnectorId::Clearnet],
            0,
            &mut rng,
        )
        .unwrap(),
    );
    let mut d = Pair::new(d, &mut rng);
    for byte in 1..=4 {
        d.zone_mut().on_session_established(
            id(byte),
            PeerDirection::Outbound,
            ConnectorId::Clearnet,
            &mut rng,
        );
    }
    (d, rng)
}

/// What one channel's sends looked like, in order: the peer, whether starts
/// were open, and whether the window was real.
type Sends = Vec<(usize, ConnectionId, Starts, bool)>;

/// Drive the zone and the queue together, as the actor does, for `polls`
/// wakes, recording every carrier send.
fn drive(
    d: &mut Pair,
    queues: &mut crate::NoiseQueues,
    rng: &mut SplitMix64,
    polls: usize,
) -> Sends {
    let mut sends = Vec::new();
    for _ in 0..polls {
        let wake = d.next_wake();
        for e in d.poll(wake, rng) {
            if let Step::NoiseSend {
                channel,
                peer,
                starts,
            } = e
            {
                let real = carry(queues, channel, peer, starts);
                sends.push((channel, peer, starts, real));
            }
        }
    }
    sends
}

/// The epoch tail (`CVR-R4`; Rick, 2026-11-18): after an epoch boundary each
/// channel sends `EPOCH_TAIL_WINDOWS` more windows to the peer it was bound
/// to, starting nothing, then takes its slot's new peer — and the switch
/// comes at the same point whether or not a message was in flight.
///
/// Two runs from one seed differ only in the queue: in the first a
/// full-size message is one window into channel 0 at the boundary; in the
/// second nothing is queued. The schedule's sends — peer and starts, per
/// channel — must be identical, and in the first run the message must
/// finish on its own peer inside the tail.
///
/// Red edits: set the tail only when a run is in flight (the sequences
/// differ); let a tail window start a message (the waiting message starts
/// on the old peer); drop the tail (the message restarts on the new peer).
#[test]
fn the_epoch_tail_switches_at_one_point_whatever_was_in_flight() {
    use shekyl_relay_privacy::params::carrier::{EPOCH_TAIL_WINDOWS, MAX_FRAGMENTS};
    let tail = EPOCH_TAIL_WINDOWS as usize;
    let run = |in_flight: bool| {
        let (mut d, mut rng) = carrier_driver(0x7A11);
        let mut queues =
            crate::NoiseQueues::new(2, vec![0u8; WINDOW], 64).expect("a carrier queue");
        // Bind both channels before the boundary.
        let mut before = drive(&mut d, &mut queues, &mut rng, 6);
        if in_flight {
            let message = vec![REAL_BYTE; WINDOW * MAX_FRAGMENTS as usize];
            assert!(queues.enqueue(0, message, crate::CarrierToken(1)));
            // One window of it goes out on channel 0 before the boundary.
            loop {
                let step = drive(&mut d, &mut queues, &mut rng, 1);
                let first = step.iter().any(|s| s.0 == 0 && s.3);
                before.extend(step);
                if first {
                    break;
                }
            }
        } else {
            loop {
                let step = drive(&mut d, &mut queues, &mut rng, 1);
                let zero = step.iter().any(|s| s.0 == 0);
                before.extend(step);
                if zero {
                    break;
                }
            }
        }
        let old0 = before
            .iter()
            .rev()
            .find(|s| s.0 == 0)
            .expect("channel 0 sent")
            .1;
        let now = d.next_wake();
        d.zone_mut().start_epoch(now, &mut rng);
        d.zone_mut().rebuild_stems(&mut rng);
        // A message that arrives during the tail must wait for the switch.
        assert!(queues.enqueue(0, vec![REAL_BYTE; WINDOW], crate::CarrierToken(2)));
        let after = drive(&mut d, &mut queues, &mut rng, 40);
        let channel0: Vec<_> = after.iter().filter(|s| s.0 == 0).copied().collect();
        (old0, channel0, after, queues.take_resolved())
    };
    let (old_a, ch0_a, after_a, resolved_a) = run(true);
    let (old_b, ch0_b, after_b, _) = run(false);

    let schedule = |sends: &Sends| -> Vec<(usize, ConnectionId, Starts)> {
        sends.iter().map(|s| (s.0, s.1, s.2)).collect()
    };
    assert_eq!(old_a, old_b, "fixture: one seed, one binding");
    assert_eq!(
        schedule(&after_a),
        schedule(&after_b),
        "the schedule after the boundary depends on what was in flight"
    );
    assert!(
        ch0_a.len() > tail + 1,
        "fixture: channel 0 ran past its tail"
    );
    for (i, send) in ch0_a.iter().take(tail).enumerate() {
        assert_eq!((send.1, send.2), (old_a, Starts::Closed), "tail window {i}");
    }
    assert_eq!(
        ch0_a[tail].2,
        Starts::Open,
        "the window after the tail opens starts on the slot's peer"
    );
    // The in-flight message finished on its own peer inside the tail...
    assert!(
        ch0_a.iter().take(tail).all(|s| s.3),
        "the tail carried the rest of the in-flight message"
    );
    assert!(
        resolved_a.contains(&crate::CarrierOutcome::Sent {
            token: crate::CarrierToken(1),
            peer: old_a,
        }),
        "the in-flight message completed on the peer it started with: {resolved_a:?}"
    );
    // ...and the message that arrived during the tail started only after it.
    assert!(
        ch0_b.iter().take(tail).all(|s| !s.3),
        "no message starts in the tail"
    );
    assert!(ch0_b[tail].3, "the waiting message starts at the switch");
}

/// A peer lost during the tail ends it at once: the channel takes its slot's
/// peer with starts open, and a half-sent message restarts there (CV-1).
///
/// Red edit: keep counting the tail against a gone peer; the channel sends
/// nothing (or to a dead session) until the count runs out.
#[test]
fn a_peer_lost_in_the_tail_ends_it() {
    let (mut d, mut rng) = carrier_driver(0x7A12);
    let mut queues = crate::NoiseQueues::new(2, vec![0u8; WINDOW], 64).expect("a carrier queue");
    let mut before = Vec::new();
    while !before
        .iter()
        .any(|s: &(usize, ConnectionId, Starts, bool)| s.0 == 0)
    {
        before.extend(drive(&mut d, &mut queues, &mut rng, 1));
    }
    let old0 = before
        .iter()
        .rev()
        .find(|s| s.0 == 0)
        .expect("channel 0 sent")
        .1;
    let now = d.next_wake();
    d.zone_mut().start_epoch(now, &mut rng);
    d.zone_mut().rebuild_stems(&mut rng);
    d.zone_mut().on_connection_close(&old0);
    // Re-offer a survivor so the map can backfill a slot the closed peer
    // held; whether channel 0 then sends or unbinds, the gone peer gets no
    // tail window, and a send it makes opens starts.
    let survivor = [id(1), id(2), id(3), id(4)]
        .into_iter()
        .find(|peer| *peer != old0)
        .expect("three survivors");
    d.zone_mut().on_session_established(
        survivor,
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    let after = drive(&mut d, &mut queues, &mut rng, 20);
    assert!(
        after.iter().all(|s| s.1 != old0),
        "a lost peer is sent no tail window"
    );
    if let Some(first) = after.iter().find(|s| s.0 == 0) {
        assert_eq!(first.2, Starts::Open, "the tail ended with the peer");
    }
}
