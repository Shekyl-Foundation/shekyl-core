// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;
use crate::stem_watch::TxId;
use crate::ConnectorId;
use shekyl_draw_rng::SplitMix64;
use shekyl_relay_privacy::params::DandelionParams;
use shekyl_relay_privacy::schedule::PeerDirection;

fn id(byte: u8) -> ConnectionId {
    let mut b = [0u8; 16];
    b[0] = byte;
    ConnectionId::from_bytes(b)
}

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

    d.zone_mut().on_session_established(
        id(1),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
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
    d.zone_mut().on_session_established(
        id(1),
        PeerDirection::Inbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    d.zone_mut().queue_fluff(&[vec![7]], None, 0, &mut rng);
    let due = d.zone().fluff_deadline().unwrap();

    if due > 0 {
        assert!(d.poll(due - 1, &mut rng).is_empty(), "not due yet");
    }
    assert_eq!(
        d.poll(due, &mut rng),
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
    for peer in &outbound {
        d.zone_mut().on_session_established(
            *peer,
            PeerDirection::Outbound,
            ConnectorId::Clearnet,
            &mut rng,
        );
    }

    let effects = d.poll(d.zone().epoch_deadline(), &mut rng);
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
fn an_outbound_handshake_fills_the_map_without_rolling_the_epoch() {
    // The notifier is constructed before any peer connects. The map stays
    // empty until an outbound handshake merges it. A repeat of the same
    // set leaves the slots where they are and does not roll the epoch.
    let mut rng = SplitMix64::new(45);
    let mut d = driver(&mut rng);
    let deadline = d.zone().epoch_deadline();
    assert_eq!(d.zone().live_stems(), 0, "fixture: no peers yet");

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
    d.zone_mut().on_session_established(
        id(3),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    assert_eq!(d.zone().live_stems(), 2, "the handshake fills the map");
    assert_eq!(
        d.zone().epoch_deadline(),
        deadline,
        "a merge is not a rollover — the role and its deadline stand"
    );

    let slots_before = d.zone().stem_slots().to_vec();
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
    d.zone_mut().on_session_established(
        id(3),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    assert_eq!(
        d.zone().stem_slots(),
        slots_before.as_slice(),
        "an unchanged outbound set leaves slots in place"
    );
}

#[test]
fn polling_before_the_epoch_boundary_changes_nothing() {
    let mut rng = SplitMix64::new(43);
    let mut d = driver(&mut rng);
    let deadline = d.zone().epoch_deadline();
    assert!(d.poll(deadline - 1, &mut rng).is_empty());
    assert_eq!(d.zone().epoch_deadline(), deadline, "epoch untouched");
}

#[test]
fn forcing_runs_the_same_paths_as_the_deadline() {
    // The force-step hooks drive production code, not a shortcut — the
    // property the whole round's oracle rests on.
    let mut rng = SplitMix64::new(44);
    let mut d = driver(&mut rng);
    d.zone_mut().on_session_established(
        id(1),
        PeerDirection::Inbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    d.zone_mut().queue_fluff(&[vec![9]], None, 0, &mut rng);
    let due = d.zone().fluff_deadline().unwrap();
    if due > 0 {
        assert!(d.poll(0, &mut rng).is_empty(), "not due at t=0");
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
    d.zone_mut().on_session_established(
        id(2),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    d.force_epoch(0, &mut rng);
    assert_ne!(d.zone().epoch_deadline(), before, "a new epoch was drawn");
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
/// - remove the `fire_embargoes` call from `poll` → the silence is
///   never resolved and the tally assertion fails;
/// - remove `forget` from `on_connection_close` → the departed peer keeps a
///   tally and the drop assertion fails.
#[test]
fn a_stem_observation_resolves_on_the_poll_clock_and_a_close_drops_it() {
    let mut rng = SplitMix64::new(0x57E3);
    let mut d = driver(&mut rng);
    d.zone_mut().on_session_established(
        id(1),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );

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
    let _ = d.poll(deadline - 1, &mut rng);
    assert_eq!(
        d.zone().stem_observations_in_flight(),
        1,
        "an observation must not resolve before its deadline"
    );
    assert!(d.zone().stem_tally(&id(1)).is_none());

    // At the deadline: the poll resolves it as silent.
    let _ = d.poll(deadline, &mut rng);
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
    d.zone_mut().on_session_established(
        id(1),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );

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
    let _ = d.poll(5_000, &mut rng);
    let t = d.zone().stem_tally(&id(1)).expect("still there");
    assert_eq!(
        (t.propagated, t.silent),
        (2, 0),
        "a resolved observation is gone from the pending map — a later expire \
         must not charge the peer a silence it already answered"
    );
}
