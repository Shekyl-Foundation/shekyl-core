// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;
use crate::stem_watch::TxId;
use shekyl_relay_privacy::params::DandelionParams;
use shekyl_relay_privacy::rng::SplitMix64;
use shekyl_relay_privacy::schedule::PeerDirection;

fn id(byte: u8) -> ConnectionId {
    let mut b = [0u8; 16];
    b[0] = byte;
    ConnectionId::from_bytes(b)
}

/// A `gather_outbound` thunk that must never run. Passed to [`Driver::poll`]
/// on wakes that do not cross an epoch boundary, so it doubles as the witness
/// that a fluff-only wake never pays for the outbound scan — poll invoking it
/// off an epoch boundary would fail here rather than pass quietly.
fn no_gather() -> Vec<ConnectionId> {
    unreachable!("a fluff-only wake must not gather the outbound set")
}

fn driver(rng: &mut SplitMix64) -> Driver {
    Driver::new(Zone::new(
        DandelionParams::inherited(),
        2,
        FluffReach::EveryPeer,
        false,
        0,
        rng,
    ))
}

#[test]
fn next_wake_follows_a_newly_queued_batch_without_re_arming() {
    // The duplicate-fact guard, and the reason there is no `armed_deadline`
    // field. A cached wake time would still hold the epoch boundary here,
    // because nothing told it to re-arm — and the fluff would fire late, or
    // not until the epoch rolled. Deriving the fact makes that
    // unrepresentable rather than merely unlikely.
    let mut rng = SplitMix64::new(40);
    let mut d = driver(&mut rng);
    let epoch_wake = d.next_wake();
    assert_eq!(
        epoch_wake,
        d.zone().epoch_deadline(),
        "with no batch pending, the epoch boundary is the only wake"
    );

    d.zone_mut()
        .on_handshake_complete(id(1), PeerDirection::Outbound);
    d.zone_mut().queue_fluff(&[vec![1]], None, 0, &mut rng);
    let fluff = d.zone().fluff_deadline().expect("a batch is in flight");
    assert!(fluff < epoch_wake, "fixture: the fluff must be the sooner");

    assert_eq!(
        d.next_wake(),
        fluff,
        "next_wake must follow a fresh draw with no explicit re-arm — if this \
         fails, look for a cached armed-deadline that went stale"
    );
}

#[test]
fn polling_releases_a_batch_at_its_deadline_and_not_before() {
    let mut rng = SplitMix64::new(41);
    let mut d = driver(&mut rng);
    d.zone_mut()
        .on_handshake_complete(id(1), PeerDirection::Inbound);
    d.zone_mut().queue_fluff(&[vec![7]], None, 0, &mut rng);
    let due = d.zone().fluff_deadline().unwrap();

    if due > 0 {
        assert!(
            d.poll(due - 1, no_gather, &mut rng).is_empty(),
            "not due yet"
        );
    }
    assert_eq!(
        d.poll(due, no_gather, &mut rng),
        vec![Effect::Fluff {
            peer: id(1),
            blobs: vec![TxBlob::from([7u8].as_slice())]
        }]
    );
}

#[test]
fn an_epoch_rollover_redraws_the_stem_set() {
    // The slots no longer cross as an effect — the binding travels with
    // each covert send instead (§20.3) — so the rollover's work is asserted
    // where it lives: on the map the zone owns.
    let mut rng = SplitMix64::new(42);
    let mut d = driver(&mut rng);
    let outbound = vec![id(1), id(2), id(3)];

    let effects = d.poll(d.zone().epoch_deadline(), || outbound.clone(), &mut rng);
    assert!(
        effects.is_empty(),
        "no fluff pending and covert disabled: a rollover on this zone \
         produces map changes, not effects"
    );
    let slots = d.zone().stem_slots();
    assert_eq!(slots.len(), 2, "two slots at the configured width");
    assert!(slots.iter().flatten().all(|p| outbound.contains(p)));
}

#[test]
fn a_mid_epoch_refresh_fills_the_map_without_rolling_the_epoch() {
    // The path the public zone actually depends on. `notify` is constructed
    // before any peer connects, so the map is empty until the first relay
    // attempt refreshes it — without this, every transaction would fluff on
    // a node that is perfectly able to stem. Commands return no effects
    // (§20.3): the refresh is a plain zone mutation through the driver's
    // zone accessor, and anything a slot change implies for the covert
    // channels rides `poll`'s cadence.
    let mut rng = SplitMix64::new(45);
    let mut d = driver(&mut rng);
    let deadline = d.zone().epoch_deadline();
    assert_eq!(d.zone().live_stems(), 0, "fixture: no peers yet");

    d.zone_mut()
        .update_stems(vec![id(1), id(2), id(3)], &mut rng);
    assert_eq!(d.zone().live_stems(), 2, "a first population fills the map");
    assert_eq!(
        d.zone().epoch_deadline(),
        deadline,
        "a refresh is not a rollover — the role and its deadline stand"
    );

    let slots_before = d.zone().stem_slots().to_vec();
    d.zone_mut()
        .update_stems(vec![id(1), id(2), id(3)], &mut rng);
    assert_eq!(
        d.zone().stem_slots(),
        slots_before.as_slice(),
        "an unchanged outbound set leaves slots in place"
    );
}

/// A **due** channel whose slot is unbound emits [`Effect::CovertUnbind`]
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
///   [`a_rebind_and_a_covert_disabled_zone_emit_no_unbind`] with it.
#[test]
fn a_due_channel_with_an_unbound_slot_clears_at_every_tick() {
    let mut rng = SplitMix64::new(31);
    let mut d = Driver::new(Zone::new(
        DandelionParams::inherited(),
        2,
        FluffReach::EveryPeer,
        true,
        0,
        &mut rng,
    ));
    d.zone_mut()
        .on_handshake_complete(id(1), PeerDirection::Outbound);
    d.zone_mut()
        .on_handshake_complete(id(2), PeerDirection::Outbound);
    d.zone_mut().update_stems(vec![id(1), id(2)], &mut rng);

    // The hole recipe the CV-2 witness established: close the slot's peer
    // AND re-offer only the survivor, so nothing backfills.
    let slot0_peer = d.zone().stem_slots()[0].expect("slot 0 bound");
    let keep = d.zone().stem_slots()[1].expect("slot 1 bound");
    d.zone_mut().on_connection_close(&slot0_peer);
    d.zone_mut().update_stems(vec![keep], &mut rng);
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
        for e in d.poll(wake, no_gather, &mut rng) {
            match e {
                Effect::CovertUnbind { channel } => {
                    assert_eq!(
                        channel, 0,
                        "only the unbound channel clears — 1 here is the \
                         off-by-one or the fire-on-bound defect"
                    );
                    unbinds += 1;
                }
                Effect::CovertSend { channel, peer } => {
                    assert_eq!(
                        (channel, peer),
                        (1, keep),
                        "the bound channel keeps sending its own peer at \
                         its own index"
                    );
                    sends += 1;
                }
                Effect::Fluff { .. } => unreachable!("nothing was queued"),
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
fn a_rebind_and_a_covert_disabled_zone_emit_no_unbind() {
    // Rebind: close slot 0's peer but offer a replacement, so the churned
    // slot refills — bound again by the time any tick comes due.
    let mut rng = SplitMix64::new(37);
    let mut d = Driver::new(Zone::new(
        DandelionParams::inherited(),
        2,
        FluffReach::EveryPeer,
        true,
        0,
        &mut rng,
    ));
    d.zone_mut()
        .on_handshake_complete(id(1), PeerDirection::Outbound);
    d.zone_mut()
        .on_handshake_complete(id(2), PeerDirection::Outbound);
    d.zone_mut().update_stems(vec![id(1), id(2)], &mut rng);
    let slot0_peer = d.zone().stem_slots()[0].expect("slot 0 bound");
    let keep = d.zone().stem_slots()[1].expect("slot 1 bound");
    d.zone_mut().on_connection_close(&slot0_peer);
    d.zone_mut()
        .on_handshake_complete(id(3), PeerDirection::Outbound);
    d.zone_mut().update_stems(vec![keep, id(3)], &mut rng);
    assert_eq!(
        d.zone().stem_slots()[0],
        Some(id(3)),
        "fixture: the churned slot refilled — this is a rebind, not a hole"
    );
    let mut sends = 0;
    for _ in 0..8 {
        if sends >= 4 {
            break;
        }
        let wake = d.next_wake();
        for e in d.poll(wake, no_gather, &mut rng) {
            match e {
                Effect::CovertSend { .. } => sends += 1,
                Effect::CovertUnbind { channel } => panic!(
                    "channel {channel} cleared on a rebound slot — this \
                     drops queued messages the inherited repoint \
                     delivered to the successor"
                ),
                Effect::Fluff { .. } => unreachable!("nothing was queued"),
            }
        }
    }
    assert!(sends >= 4, "both rebound channels keep sending — liveness");

    // Covert disabled: no covert deadline exists at all, so the unbind
    // has no tick to ride — the gate is the schedule's absence, not a
    // check. The hole is still constructed, so the emptiness below comes
    // from the missing schedule and not from the state failing to happen.
    let mut d = driver(&mut rng);
    d.zone_mut()
        .on_handshake_complete(id(1), PeerDirection::Outbound);
    d.zone_mut()
        .on_handshake_complete(id(2), PeerDirection::Outbound);
    d.zone_mut().update_stems(vec![id(1), id(2)], &mut rng);
    let slot0_peer = d.zone().stem_slots()[0].expect("slot 0 bound");
    let keep = d.zone().stem_slots()[1].expect("slot 1 bound");
    d.zone_mut().on_connection_close(&slot0_peer);
    d.zone_mut().update_stems(vec![keep], &mut rng);
    assert_eq!(
        d.zone().stem_slots()[0],
        None,
        "fixture: the hole exists on the disabled zone too"
    );
    assert_eq!(
        d.zone().covert_deadline(),
        None,
        "no covert schedule ⇒ no tick for an unbind to ride"
    );
    assert!(
        d.poll(d.zone().epoch_deadline() - 1, no_gather, &mut rng)
            .is_empty(),
        "nothing is due before the epoch on a zone without covert channels"
    );
}

#[test]
fn polling_before_the_epoch_boundary_changes_nothing() {
    let mut rng = SplitMix64::new(43);
    let mut d = driver(&mut rng);
    let deadline = d.zone().epoch_deadline();
    assert!(d.poll(deadline - 1, no_gather, &mut rng).is_empty());
    assert_eq!(d.zone().epoch_deadline(), deadline, "epoch untouched");
}

#[test]
fn forcing_runs_the_same_paths_as_the_deadline() {
    // The force-step hooks drive production code, not a shortcut — the
    // property the whole round's oracle rests on.
    let mut rng = SplitMix64::new(44);
    let mut d = driver(&mut rng);
    d.zone_mut()
        .on_handshake_complete(id(1), PeerDirection::Inbound);
    d.zone_mut().queue_fluff(&[vec![9]], None, 0, &mut rng);
    let due = d.zone().fluff_deadline().unwrap();
    if due > 0 {
        assert!(d.poll(0, no_gather, &mut rng).is_empty(), "not due at t=0");
    }
    assert_eq!(
        d.force_fluff(0),
        vec![Effect::Fluff {
            peer: id(1),
            blobs: vec![TxBlob::from([9u8].as_slice())]
        }],
        "force releases the same batch the deadline would have"
    );

    let before = d.zone().epoch_deadline();
    d.force_epoch(0, &[id(1), id(2)], &mut rng);
    assert_ne!(d.zone().epoch_deadline(), before, "a new epoch was drawn");
}

/// Covert channels emit **independently**: one `CovertSend` per advance.
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
fn covert_channels_emit_one_per_advance_not_synchronized() {
    let mut rng = SplitMix64::new(11);
    let mut d = Driver::new(Zone::new(
        DandelionParams::inherited(),
        2,
        FluffReach::EveryPeer,
        true,
        0,
        &mut rng,
    ));
    // Bind both slots: since the inversion, an unbound slot emits no send
    // (CV-2), and this test is about cadence, not binding.
    d.zone_mut()
        .on_handshake_complete(id(1), PeerDirection::Outbound);
    d.zone_mut()
        .on_handshake_complete(id(2), PeerDirection::Outbound);
    d.zone_mut().update_stems(vec![id(1), id(2)], &mut rng);

    // Fixture requirement: distinct deadlines, or "one per advance" could
    // hold by coincidence rather than by independence.
    let (a, b) = (
        d.zone().covert_deadline_at(0).expect("ch0 armed"),
        d.zone().covert_deadline_at(1).expect("ch1 armed"),
    );
    assert_ne!(a, b, "the two channels must be armed independently");

    // Advance to the earliest deadline: exactly one channel is due.
    let first = d.next_wake();
    let covert: Vec<usize> = d
        .poll(first, Vec::new, &mut rng)
        .into_iter()
        .filter_map(|e| match e {
            Effect::CovertSend { channel, .. } => Some(channel),
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

    // Advance again: the other channel, and only it.
    let second = d.next_wake();
    assert!(second > first, "the next wake is strictly later");
    let covert2: Vec<usize> = d
        .poll(second, Vec::new, &mut rng)
        .into_iter()
        .filter_map(|e| match e {
            Effect::CovertSend { channel, .. } => Some(channel),
            _ => None,
        })
        .collect();
    assert_eq!(covert2.len(), 1, "second advance also fires exactly one");
    assert_ne!(
        covert2[0], firstc,
        "the second advance fires the OTHER channel — liveness, so a \
         scheduler that only ever serves channel 0 cannot pass"
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
fn covert_sends_carry_the_slots_own_peer_at_its_own_index() {
    let mut rng = SplitMix64::new(23);
    let mut d = Driver::new(Zone::new(
        DandelionParams::inherited(),
        2,
        FluffReach::EveryPeer,
        true,
        0,
        &mut rng,
    ));
    d.zone_mut()
        .on_handshake_complete(id(1), PeerDirection::Outbound);
    d.zone_mut()
        .on_handshake_complete(id(2), PeerDirection::Outbound);
    d.zone_mut().update_stems(vec![id(1), id(2)], &mut rng);

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
        for e in d.poll(wake, Vec::new, &mut rng) {
            if let Effect::CovertSend { channel, peer } = e {
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
/// instead — [`Effect::CovertUnbind`], witnessed separately — which this
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
    let mut d = Driver::new(Zone::new(
        DandelionParams::inherited(),
        2,
        FluffReach::EveryPeer,
        true,
        0,
        &mut rng,
    ));
    d.zone_mut()
        .on_handshake_complete(id(1), PeerDirection::Outbound);
    d.zone_mut()
        .on_handshake_complete(id(2), PeerDirection::Outbound);
    d.zone_mut().update_stems(vec![id(1), id(2)], &mut rng);

    // Make a hole at index 0 the way the RP-3a seal did: close slot 0's
    // peer AND re-offer only slot 1's, so there is nothing to backfill
    // with. (Close alone is not enough — churn REFILLS a slot from the
    // surviving outbound set; the hole exists only when the pool cannot
    // cover the width. The fixture assertion below caught exactly that
    // when this test was first written against a close-only recipe.)
    let slot0_peer = d.zone().stem_slots()[0].expect("slot 0 bound");
    let keep = d.zone().stem_slots()[1].expect("slot 1 bound");
    d.zone_mut().on_connection_close(&slot0_peer);
    d.zone_mut().update_stems(vec![keep], &mut rng);
    let truth: Vec<Option<ConnectionId>> = d.zone().stem_slots().to_vec();
    assert_eq!(truth[0], None, "fixture: the hole is at index 0");
    let bound = truth[1].expect("fixture: index 1 still bound");

    let mut emissions = Vec::new();
    for _ in 0..16 {
        if emissions.len() >= 3 {
            break;
        }
        let wake = d.next_wake();
        for e in d.poll(wake, Vec::new, &mut rng) {
            if let Effect::CovertSend { channel, peer } = e {
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
/// [`covert_channels_emit_one_per_advance_not_synchronized`]). The remaining
/// due channel surfaces on the next wake.
///
/// Also pins re-arm-from-`now`: the fired channel's new deadline is strictly
/// after the poll time, so a multi-interval stall cannot catch-up-burst.
#[test]
fn a_late_poll_emits_at_most_one_covert_channel() {
    let mut rng = SplitMix64::new(13);
    let mut d = Driver::new(Zone::new(
        DandelionParams::inherited(),
        2,
        FluffReach::EveryPeer,
        true,
        0,
        &mut rng,
    ));
    d.zone_mut()
        .on_handshake_complete(id(1), PeerDirection::Outbound);
    d.zone_mut()
        .on_handshake_complete(id(2), PeerDirection::Outbound);
    d.zone_mut().update_stems(vec![id(1), id(2)], &mut rng);

    let a = d.zone().covert_deadline_at(0).expect("ch0 armed");
    let b = d.zone().covert_deadline_at(1).expect("ch1 armed");
    assert_ne!(a, b, "fixture: independent arms");
    let late = a.max(b) + 60_000;

    let first: Vec<usize> = d
        .poll(late, no_gather, &mut rng)
        .into_iter()
        .filter_map(|e| match e {
            Effect::CovertSend { channel, .. } | Effect::CovertUnbind { channel } => Some(channel),
            Effect::Fluff { .. } => None,
        })
        .collect();
    assert_eq!(
        first.len(),
        1,
        "a late poll that is past both deadlines must not multi-fire; got {first:?}"
    );
    let fired = first[0];
    let rearmed = d
        .zone()
        .covert_deadline_at(fired)
        .expect("fired channel still scheduled");
    assert!(
        rearmed > late,
        "re-arm from now (poll time), not a past deadline: rearmed={rearmed} late={late}"
    );

    // The sibling is still due (its deadline is in the past) and must be the
    // next covert effect — independence, not a permanent single-channel lock.
    let second: Vec<usize> = d
        .poll(late, no_gather, &mut rng)
        .into_iter()
        .filter_map(|e| match e {
            Effect::CovertSend { channel, .. } | Effect::CovertUnbind { channel } => Some(channel),
            Effect::Fluff { .. } => None,
        })
        .collect();
    assert_eq!(second.len(), 1, "the remaining overdue channel fires next");
    assert_ne!(
        second[0], fired,
        "the second late poll serves the OTHER channel"
    );
}

/// A stem observation resolves on the **poll clock**, not on a timer of its
/// own — and a disconnect drops it rather than charging the departed peer.
///
/// This is the wiring witness for §38: `StemWatch` landed unwired, and an
/// unwired accumulator is the "unwired-is-closed" fossil this project has had
/// to dig out before. What it asserts is the lifecycle, not the arithmetic
/// (which `stem_watch`'s own tests cover): that `poll` reaches `expire`, and
/// that `on_connection_close` reaches `forget`.
///
/// Negative-controlled, both run and observed to fail:
/// - remove the `expire_stem_observations` call from `poll` → the silence is
///   never resolved and the tally assertion fails;
/// - remove `forget` from `on_connection_close` → the departed peer keeps a
///   tally and the drop assertion fails.
#[test]
fn a_stem_observation_resolves_on_the_poll_clock_and_a_close_drops_it() {
    let mut rng = SplitMix64::new(0x57E3);
    let mut d = driver(&mut rng);
    d.zone_mut()
        .on_handshake_complete(id(1), PeerDirection::Outbound);

    let tx = TxId::from_bytes([7u8; 32]);
    let deadline = 5_000;
    // Fixed deadline: production draws from the embargo timer; this witness
    // pins the clock so expire / next_wake assertions are deterministic.
    d.zone_mut().record_stem_at(&[tx], id(1), None, deadline);
    assert_eq!(
        d.zone().stem_observations_in_flight(),
        1,
        "fixture: the observation is armed"
    );
    assert_eq!(
        d.next_wake(),
        deadline,
        "next_wake must fold the observation deadline — if this is the epoch \
         only, silences wait on unrelated schedules"
    );

    // Before the deadline: polling must not resolve it.
    assert!(d.zone().epoch_deadline() > deadline, "fixture: no rollover");
    let _ = d.poll(deadline - 1, no_gather, &mut rng);
    assert_eq!(
        d.zone().stem_observations_in_flight(),
        1,
        "an observation must not resolve before its deadline"
    );
    assert!(d.zone().stem_tally(&id(1)).is_none());

    // At the deadline: the poll resolves it as silent.
    let _ = d.poll(deadline, no_gather, &mut rng);
    assert_eq!(d.zone().stem_observations_in_flight(), 0);
    let t = d
        .zone()
        .stem_tally(&id(1))
        .expect("the poll clock resolved it — if this is None, poll never reached expire");
    assert_eq!((t.propagated, t.silent), (0, 1));

    // A close drops the tally rather than retaining it (F-8: no persistence).
    d.zone_mut().on_connection_close(&id(1));
    assert!(
        d.zone().stem_tally(&id(1)).is_none(),
        "a departed peer's reputation is dropped, not quietly retained"
    );
}

/// An arrival resolves the observation as *propagated* — the other half of the
/// lifecycle, and the half that makes the signal a signal rather than a timer.
#[test]
fn an_arrival_resolves_the_observation_as_propagated() {
    let mut rng = SplitMix64::new(0x57E4);
    let mut d = driver(&mut rng);
    d.zone_mut()
        .on_handshake_complete(id(1), PeerDirection::Outbound);

    let tx = TxId::from_bytes([9u8; 32]);
    d.zone_mut().record_stem_at(&[tx], id(1), None, 5_000);
    d.zone_mut().record_arrival(&[tx], Some(id(2)));

    let t = d.zone().stem_tally(&id(1)).expect("arrival resolved it");
    assert_eq!(
        (t.propagated, t.silent),
        (1, 0),
        "seen-before-deadline is propagation, not silence"
    );

    // F-10 at the zone seam: an echo from the charged successor must not
    // resolve. Armed second observation, echoed by its own successor.
    let echo = TxId::from_bytes([0x0E; 32]);
    d.zone_mut().record_stem_at(&[echo], id(1), None, 5_000);
    d.zone_mut().record_arrival(&[echo], Some(id(1)));
    assert_eq!(
        d.zone().stem_observations_in_flight(),
        1,
        "the successor's own echo resolves nothing — it stays in flight"
    );
    d.zone_mut().record_arrival(&[echo], Some(id(2)));
    assert_eq!(
        d.zone().stem_observations_in_flight(),
        0,
        "a different peer having it IS propagation"
    );

    // And the deadline passing afterwards must not double-count it.
    let _ = d.poll(5_000, no_gather, &mut rng);
    let t = d.zone().stem_tally(&id(1)).expect("still there");
    assert_eq!(
        (t.propagated, t.silent),
        (2, 0),
        "a resolved observation is gone from the pending map — a later expire \
         must not charge the peer a silence it already answered"
    );
}
