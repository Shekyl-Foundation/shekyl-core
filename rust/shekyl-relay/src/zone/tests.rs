// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;
use std::sync::Arc;

use shekyl_relay_privacy::params::{carrier, inherited, DandelionParams};
use shekyl_relay_privacy::rng::SplitMix64;
use shekyl_relay_privacy::{LinkSecrecy, RelayZone};

/// Frozen draws from seed `0xF1FF` for the wired fluff path. Not chosen —
/// observed, then pinned. Note the shape is memoryless: a 0 ms draw sits
/// beside a 23.5 s one, which is the variance a Poisson at these means
/// cannot produce (`CV ~ 0.2` vs ~1). That is F-4 visible in four numbers.
///
/// Inbound is drawn first and does not touch the stem map, so its sequence
/// is only the fluff delay. Outbound is the same delay after the handshake's
/// stem-map draw, which is why the two sequences are not a halved pair.
const PINNED_INBOUND: [Millis; 4] = [23_500, 2_250, 9_000, 2_250];
const PINNED_OUTBOUND: [Millis; 4] = [8_750, 0, 750, 500];

fn id(byte: u8) -> ConnectionId {
    let mut b = [0u8; 16];
    b[0] = byte;
    ConnectionId::from_bytes(b)
}

fn zone(rng: &mut SplitMix64) -> Relay {
    Relay::new(
        DandelionParams::inherited(),
        2,
        LinkSecrecy::of(RelayZone::Public),
        false,
        &[ConnectorId::Clearnet],
        0,
        rng,
    )
    .unwrap()
}

fn establish_outbound(zone: &mut Relay, peers: &[u8], rng: &mut SplitMix64) {
    for peer in peers {
        zone.on_session_established(
            id(*peer),
            PeerDirection::Outbound,
            ConnectorId::Clearnet,
            rng,
        );
    }
}

#[test]
fn a_new_zone_owns_nothing_and_routes_nothing() {
    let mut rng = SplitMix64::new(1);
    let mut z = zone(&mut rng);
    assert_eq!(z.peer_count(), 0);
    assert_eq!(z.live_stems(), 0);
    // Through the production path: a local-origin tx always attempts a stem
    // (RD-4), and with no peers connected there is nothing to route to.
    assert_eq!(
        z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
        RelayPlan::NoRoute,
        "no route before peers"
    );
}

#[test]
fn handshake_is_idempotent_and_does_not_discard_a_batch() {
    // A repeated handshake for a live connection must not reset the peer's
    // queued transactions — dropping them would silently lose relay work.
    let mut rng = SplitMix64::new(2);
    let mut z = zone(&mut rng);
    z.on_session_established(
        id(1),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    let stems = z.live_stems();
    let slots = z.stem_slots().to_vec();
    z.contexts
        .get_mut(&id(1))
        .expect("peer present")
        .queued
        .push(TxBlob::from([0xAAu8].as_slice()));

    // The repeat arrives as inbound, so it must not merge again. `or_insert`
    // keeps the outbound direction and the queued batch.
    z.on_session_established(
        id(1),
        PeerDirection::Inbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    assert_eq!(z.live_stems(), stems);
    assert_eq!(z.stem_slots(), slots.as_slice());
    assert_eq!(z.peer_count(), 1, "no duplicate peer");
    assert_eq!(
        z.peer(&id(1)).expect("peer present").queued.len(),
        1,
        "a repeat handshake kept the pending batch"
    );
}

#[test]
fn close_removes_the_peer_and_its_queue() {
    let mut rng = SplitMix64::new(3);
    let mut z = zone(&mut rng);
    z.on_session_established(
        id(1),
        PeerDirection::Inbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    z.on_session_established(
        id(2),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    z.on_connection_close(&id(1));
    assert_eq!(z.peer_count(), 1);
    assert!(z.peer(&id(1)).is_none());
    assert!(z.peer(&id(2)).is_some());
}

#[test]
fn a_new_epoch_redraws_the_role_and_the_deadline() {
    let mut rng = SplitMix64::new(5);
    let mut z = zone(&mut rng);
    let first_deadline = z.epoch_deadline();
    assert!(first_deadline > 0, "an epoch has a future end");

    // Forcing the step is the same code the driver runs on the deadline —
    // which is what makes the daemon's run_epoch() hook honest.
    z.start_epoch(first_deadline, &mut rng);
    assert!(
        z.epoch_deadline() > first_deadline,
        "the new epoch ends after the old one"
    );
}

// --- F-4/F-5: the correction must be WITNESSED, not merely wired ---------
//
// §18.4 item 3. `FluffScheduler::inherited()` is `DelayFamily::Poisson` —
// the F-4 defect — and `memoryless()` is `Geometric`, at identical means.
// A wire to the wrong one compiles, fluffs, and passes every routing test
// in `levin.cpp` (blind to timing) and any "does it fluff" test (blind to
// distribution). These three close that gap from different directions.

#[test]
fn fluff_draws_are_memoryless_not_the_inherited_poisson() {
    // Structural: the family the zone actually draws from. Named against
    // the defect so a rewire reads as a regression, not a preference.
    let mut rng = SplitMix64::new(20);
    let z = zone(&mut rng);
    assert_eq!(
        z.fluff_family(),
        DelayFamily::Geometric,
        "the fluff delay must be the corrected memoryless draw (F-4)"
    );
    assert_ne!(
        z.fluff_family(),
        DelayFamily::Poisson,
        "FluffScheduler::inherited() is the F-4 defect and is one identifier away"
    );
}

/// One peer of one direction, so the scheduler's earliest deadline *is*
/// that peer's draw. Measuring with two peers queued would sample
/// `min(inbound, outbound)` instead — the mistake this test caught.
fn mean_delay(direction: PeerDirection, seed: u64, n: u64) -> u64 {
    let mut rng = SplitMix64::new(seed);
    let mut total = 0_u64;
    for _ in 0..n {
        let mut z = zone(&mut rng);
        z.on_session_established(id(1), direction, ConnectorId::Clearnet, &mut rng);
        assert_eq!(z.queue_fluff(&[vec![1]], None, 0, &mut rng), 1);
        total += z.fluff_deadline().expect("a batch is in flight");
    }
    total / n
}

#[test]
fn fluff_delay_means_match_the_configured_averages_with_outbound_halved() {
    // Behavioural: a right family with a wrong mean passes the structural
    // check above. The inherited asymmetry — outbound gets half the inbound
    // delay, because a node chooses who it dials — is a privacy property,
    // so it is pinned too.
    const N: u64 = 4_000;
    let inbound = mean_delay(PeerDirection::Inbound, 21, N);
    let outbound = mean_delay(PeerDirection::Outbound, 22, N);

    // Inherited means: 20 and 10 quarter-seconds = 5000ms and 2500ms.
    assert!(
        (4_600..=5_400).contains(&inbound),
        "inbound fluff mean {inbound}ms is not the configured 5000ms"
    );
    assert!(
        (2_300..=2_700).contains(&outbound),
        "outbound fluff mean {outbound}ms is not the configured 2500ms"
    );
    assert!(
        outbound < inbound,
        "outbound must stay the shorter delay: {outbound} vs {inbound}"
    );
}

#[test]
fn fluff_deadlines_are_pinned_for_a_fixed_seed() {
    // Golden-vector shape on the *wired* path: any change to the draw the
    // zone uses — family, mean, or table — moves this sequence. This is the
    // assertion that fails if someone swaps in `inherited()`/Poisson, which
    // nothing else in the tree would notice.
    let mut rng = SplitMix64::new(0xF1FF);
    let inbound: Vec<Millis> = (0..4)
        .map(|_| {
            let mut z = zone(&mut rng);
            z.on_session_established(
                id(1),
                PeerDirection::Inbound,
                ConnectorId::Clearnet,
                &mut rng,
            );
            z.queue_fluff(&[vec![0xAB]], None, 0, &mut rng);
            z.fluff_deadline().unwrap()
        })
        .collect();
    let outbound: Vec<Millis> = (0..4)
        .map(|_| {
            let mut z = zone(&mut rng);
            z.on_session_established(
                id(1),
                PeerDirection::Outbound,
                ConnectorId::Clearnet,
                &mut rng,
            );
            z.queue_fluff(&[vec![0xAB]], None, 0, &mut rng);
            z.fluff_deadline().unwrap()
        })
        .collect();
    assert_eq!(
        (inbound.as_slice(), outbound.as_slice()),
        (PINNED_INBOUND.as_slice(), PINNED_OUTBOUND.as_slice()),
        "the wired fluff draw changed — if deliberate, re-derive it; if not, \
         check whether the scheduler was rewired to inherited()/Poisson"
    );
}

#[test]
fn a_burst_does_not_push_a_peers_flush_further_out() {
    // The scheduler only draws when a peer has no pending deadline. If a
    // later queue re-drew, an adversary could hold a batch open by
    // trickling transactions and defer the fluff indefinitely.
    let mut rng = SplitMix64::new(23);
    let mut z = zone(&mut rng);
    z.on_session_established(
        id(1),
        PeerDirection::Inbound,
        ConnectorId::Clearnet,
        &mut rng,
    );

    z.queue_fluff(&[vec![1]], None, 0, &mut rng);
    let first = z.fluff_deadline().unwrap();
    for _ in 0..16 {
        let _ = z.queue_fluff(&[vec![2]], None, 0, &mut rng);
    }
    assert_eq!(
        z.fluff_deadline(),
        Some(first),
        "a burst must not re-draw and defer the flush"
    );
    assert_eq!(
        z.peer(&id(1)).unwrap().queued.len(),
        17,
        "all blobs batched"
    );
}

#[test]
fn fluff_skips_the_source_and_releases_on_deadline() {
    let mut rng = SplitMix64::new(24);
    let mut z = zone(&mut rng);
    z.on_session_established(
        id(1),
        PeerDirection::Inbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    z.on_session_established(
        id(2),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );

    let accepted = z.queue_fluff(&[vec![7]], Some(id(1)), 0, &mut rng);
    assert_eq!(accepted, 1, "one peer took it; the source is skipped");
    assert!(
        z.peer(&id(1)).unwrap().queued.is_empty(),
        "the source never gets its own transaction back"
    );
    assert_eq!(z.peer(&id(2)).unwrap().queued.len(), 1);

    let deadline = z.fluff_deadline().expect("a batch is in flight");
    if deadline > 0 {
        assert!(z.flush_fluff(deadline - 1, false).is_empty(), "not due yet");
    }
    let released = z.flush_fluff(deadline, false);
    assert_eq!(
        released,
        vec![(id(2), vec![TxBlob::from([7u8].as_slice())])]
    );
    assert!(z.fluff_deadline().is_none(), "nothing left pending");
}

#[test]
fn forcing_a_flush_runs_the_same_release_path() {
    // What `run_fluff()` drives. Same release code as the deadline path —
    // only which batches count as due differs, which is what keeps the
    // daemon's force-step hook honest rather than a special case.
    let mut rng = SplitMix64::new(25);
    let mut z = zone(&mut rng);
    z.on_session_established(
        id(1),
        PeerDirection::Inbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    z.queue_fluff(&[vec![9]], None, 0, &mut rng);
    let deadline = z.fluff_deadline().unwrap();

    if deadline > 0 {
        assert!(z.flush_fluff(0, false).is_empty(), "not due at t=0");
    }
    let released = z.flush_fluff(0, true);
    assert_eq!(
        released,
        vec![(id(1), vec![TxBlob::from([9u8].as_slice())])],
        "force releases regardless of deadline"
    );
}

/// A zone whose epoch role is known, found by seed search rather than by a
/// test-only setter — the role must come from the same draw production
/// uses, or the fixture would not exercise the real path.
fn zone_with_role(fluffing: bool, rng: &mut SplitMix64) -> Relay {
    zone_with_role_cover(fluffing, false, rng)
}

/// Same as [`zone_with_role`], with noise on a production-shaped encrypted
/// zone. Reach is **not** a function of the carrier: this is the Tor
/// pairing production forms (`OutboundOnly` + encrypted). Tests that need
/// encrypted-clearnet (`EveryPeer` + encrypted) construct that pair
/// explicitly — see `a_noise_carrier_is_refused_where_it_buys_nothing`.
///
/// Noise tests that need a determined epoch must go through here — a lucky
/// seed is determinism, not a determined epoch, and is the flake
/// `noise_stem` exposed once noise consults the planner.
fn zone_with_role_cover(fluffing: bool, noise: bool, rng: &mut SplitMix64) -> Relay {
    let secrecy = if noise {
        LinkSecrecy::of(RelayZone::Tor)
    } else {
        LinkSecrecy::of(RelayZone::Public)
    };
    for _ in 0..10_000 {
        let z = Relay::new(
            DandelionParams::inherited(),
            2,
            secrecy,
            noise,
            &[ConnectorId::Clearnet],
            0,
            rng,
        )
        .unwrap();
        if z.is_fluffing() == fluffing {
            return z;
        }
    }
    panic!("no epoch with fluffing={fluffing} noise={noise} in 10k draws");
}

#[test]
fn a_local_tx_stems_during_a_fluff_epoch_rd4() {
    // RD-4, and the test is shaped against the REVERSION, not the feature.
    // The inherited condition is `!fluffing || local`. Delete `|| local` —
    // which reads like a redundant clause on a fluff check — and a local
    // transaction fluffs instead of stemming, silently reverting the
    // correction that makes the adopted embargo 144 s instead of 31 s.
    //
    // So this asserts the stem-vs-fluff axis the reversion shows on. A test
    // that merely checked "the batch went somewhere" would pass on both
    // wirings: it goes somewhere either way. That is the mean-check trap in
    // the routing domain.
    let mut rng = SplitMix64::new(30);
    let mut z = zone_with_role(true, &mut rng);
    assert!(z.is_fluffing(), "fixture must be in a fluff epoch");
    establish_outbound(&mut z, &[1, 2, 3], &mut rng);

    assert!(
        matches!(
            z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
            RelayPlan::Stem(_)
        ),
        "RD-4: the origin stems even during a fluff epoch — if this fails, \
         check whether the `local_origin` arm was removed as redundant"
    );
}

#[test]
fn a_relayed_tx_fluffs_during_a_fluff_epoch() {
    // The other half of the discriminator. Without this, the RD-4 test
    // above could pass on a zone that stems *everything* — which would also
    // be wrong, and in the other direction.
    let mut rng = SplitMix64::new(31);
    let mut z = zone_with_role(true, &mut rng);
    establish_outbound(&mut z, &[1, 2, 3], &mut rng);

    assert_eq!(
        z.plan_relay(Some(id(7)), false, NodeSync::Synchronised, &mut rng),
        RelayPlan::FluffEpoch,
        "a relayed tx must fluff during a fluff epoch"
    );
}

#[test]
fn everything_stems_during_a_stem_epoch() {
    let mut rng = SplitMix64::new(32);
    let mut z = zone_with_role(false, &mut rng);
    establish_outbound(&mut z, &[1, 2, 3], &mut rng);

    assert!(matches!(
        z.plan_relay(Some(id(7)), false, NodeSync::Synchronised, &mut rng),
        RelayPlan::Stem(_)
    ));
    assert!(matches!(
        z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
        RelayPlan::Stem(_)
    ));
}

#[test]
fn an_unsynchronised_origin_is_withheld_without_touching_the_map() {
    // The hold is checked before RD-4, so a fluff epoch cannot publish it
    // and the stem map is not consulted: no pin, no rng draw, no refresh.
    let mut rng = SplitMix64::new(33);
    let mut z = zone_with_role(false, &mut rng);
    establish_outbound(&mut z, &[1, 2], &mut rng);
    let stems = z.live_stems();
    let slots = z.stem_slots().to_vec();
    assert_eq!(z.pinned_sources(), 0);

    assert_eq!(
        z.plan_relay(None, true, NodeSync::Unsynchronised, &mut rng),
        RelayPlan::AwaitSync,
        "a local origin while unsynchronised is withheld"
    );
    assert_eq!(z.live_stems(), stems);
    assert_eq!(z.stem_slots(), slots.as_slice());
    assert_eq!(z.pinned_sources(), 0, "the hold must not pin a stem");
    assert!(
        matches!(
            z.plan_relay(Some(id(7)), false, NodeSync::Unsynchronised, &mut rng),
            RelayPlan::Stem(_)
        ),
        "a forwarded transaction still stems while this node synchronises"
    );

    let mut fluff = zone_with_role(true, &mut rng);
    establish_outbound(&mut fluff, &[1, 2], &mut rng);
    assert_eq!(
        fluff.plan_relay(None, true, NodeSync::Unsynchronised, &mut rng),
        RelayPlan::AwaitSync,
        "a fluff epoch does not publish an unsynchronised origin"
    );
    assert_eq!(
        fluff.plan_relay(Some(id(7)), false, NodeSync::Unsynchronised, &mut rng),
        RelayPlan::FluffEpoch,
        "a forwarded transaction still fluffs in a fluff epoch"
    );

    let mut empty = zone(&mut rng);
    assert_eq!(
        empty.plan_relay_with_refresh(None, true, NodeSync::Unsynchronised, &mut rng),
        RelayPlan::AwaitSync,
    );
    assert_eq!(
        empty.live_stems(),
        0,
        "AwaitSync must not refresh an empty map"
    );
}

#[test]
fn a_fluff_reaches_an_inbound_anonymity_session() {
    // D7 is deleted. A fluff floods every session except the source,
    // including an inbound peer on an anonymity edge.
    let mut rng = SplitMix64::new(77);
    let mut z = Relay::new(
        DandelionParams::inherited(),
        2,
        LinkSecrecy::of(RelayZone::Tor),
        false,
        &[ConnectorId::Clearnet],
        0,
        &mut rng,
    )
    .unwrap();
    z.on_session_established(id(1), PeerDirection::Inbound, ConnectorId::Tor, &mut rng);
    z.on_session_established(id(2), PeerDirection::Outbound, ConnectorId::Tor, &mut rng);
    z.on_session_established(
        id(3),
        PeerDirection::Inbound,
        ConnectorId::Clearnet,
        &mut rng,
    );

    assert_eq!(z.queue_fluff(&[vec![7]], None, 0, &mut rng), 3);
    assert_eq!(z.peer(&id(1)).unwrap().queued.len(), 1);
    assert_eq!(z.peer(&id(2)).unwrap().queued.len(), 1);
    assert_eq!(z.peer(&id(3)).unwrap().queued.len(), 1);

    // The negative control: the same three peers on a public zone, where
    // the rule does not apply. Without this, a zone that fluffed to nobody
    // would also pass the assertions above.
    let mut z = Relay::new(
        DandelionParams::inherited(),
        2,
        LinkSecrecy::of(RelayZone::Public),
        false,
        &[ConnectorId::Clearnet],
        0,
        &mut rng,
    )
    .unwrap();
    z.on_session_established(
        id(1),
        PeerDirection::Inbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    z.on_session_established(
        id(2),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    z.on_session_established(
        id(3),
        PeerDirection::Inbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    assert_eq!(
        z.queue_fluff(&[vec![7]], None, 0, &mut rng),
        3,
        "a public zone reaches every peer but the source"
    );
}

#[test]
fn a_hidden_connector_origin_does_not_draw_a_clear_edge() {
    let mut rng = SplitMix64::new(91);
    let mut z = Relay::new(
        DandelionParams::inherited(),
        2,
        LinkSecrecy::of(RelayZone::Public),
        false,
        &[ConnectorId::Clearnet, ConnectorId::Tor],
        0,
        &mut rng,
    )
    .unwrap();
    // The epoch role is irrelevant: a restricted hop 0 returns before it.
    z.on_session_established(
        id(1),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    assert_eq!(
        z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
        RelayPlan::NoRoute,
    );
    z.on_session_established(id(2), PeerDirection::Outbound, ConnectorId::Tor, &mut rng);
    assert_eq!(
        z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
        RelayPlan::Stem(id(2)),
    );
    // A forwarded stem draws from every outbound edge.
    let forwarded = z.plan_relay(Some(id(2)), false, NodeSync::Synchronised, &mut rng);
    assert!(matches!(forwarded, RelayPlan::Stem(_)));
}

#[test]
fn no_routable_slot_reports_no_route_not_a_fluff_epoch() {
    // The discriminator between the two non-stem outcomes, and the reason
    // `RelayPlan` is three-way rather than a bool. Both mean "did not
    // stem", and a caller that cannot tell them apart gets two things
    // wrong: it retries an epoch decision that refreshing cannot change,
    // and it emits the wrong `relay_method` event — the inherited code
    // reports `stem` for an unroutable stem-epoch transaction, because it
    // entered the stem branch before discovering there was nowhere to send.
    let mut rng = SplitMix64::new(33);
    let mut z = zone_with_role(false, &mut rng);
    assert_eq!(
        z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
        RelayPlan::NoRoute,
        "a stem epoch with no slots is unroutable, not a fluff epoch"
    );

    // And the converse, so the two are pinned apart from both sides: a
    // fluff epoch reports `FluffEpoch` even with slots available, which is
    // the case where a retry would be wasted work.
    let mut z = zone_with_role(true, &mut rng);
    establish_outbound(&mut z, &[1, 2, 3], &mut rng);
    assert_eq!(
        z.plan_relay(Some(id(7)), false, NodeSync::Synchronised, &mut rng),
        RelayPlan::FluffEpoch,
        "a routable fluff epoch is settled, not merely unroutable"
    );
}

#[test]
fn an_outbound_handshake_fills_the_map_and_an_empty_registry_does_not() {
    // The handshake is the merge. `plan_relay` then stems. `with_refresh`
    // on an empty registry stays `NoRoute`: there is no session to merge,
    // and the refresh must not invent one.
    let mut rng = SplitMix64::new(34);
    let mut z = zone_with_role(false, &mut rng);
    assert_eq!(z.live_stems(), 0, "fixture: nothing populated yet");
    assert_eq!(
        z.plan_relay_with_refresh(None, true, NodeSync::Synchronised, &mut rng),
        RelayPlan::NoRoute,
    );
    assert_eq!(z.live_stems(), 0, "an empty registry stays empty");

    establish_outbound(&mut z, &[1, 2, 3], &mut rng);
    assert_eq!(z.live_stems(), 2, "the handshake already filled the map");
    assert!(matches!(
        z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
        RelayPlan::Stem(_)
    ));
}

#[test]
fn plan_relay_with_refresh_does_not_touch_a_settled_fluff_epoch() {
    let mut rng = SplitMix64::new(35);
    let mut z = zone_with_role(true, &mut rng);
    let plan = z.plan_relay_with_refresh(Some(id(7)), false, NodeSync::Synchronised, &mut rng);
    assert_eq!(plan, RelayPlan::FluffEpoch);
    assert_eq!(z.live_stems(), 0, "outbound was not merged");
}

#[test]
fn fluff_fanout_shares_one_blob_handle_across_peers() {
    // Efficiency contract of TxBlob: N peers accepting the same batch hold
    // N Arc clones of one allocation, not N owned copies of the payload.
    let mut rng = SplitMix64::new(36);
    let mut z = zone(&mut rng);
    z.on_session_established(
        id(1),
        PeerDirection::Inbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    z.on_session_established(
        id(2),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    z.on_session_established(
        id(3),
        PeerDirection::Inbound,
        ConnectorId::Clearnet,
        &mut rng,
    );

    assert_eq!(z.queue_fluff(&[[0xDEu8, 0xAD]], None, 0, &mut rng), 3);
    let a = &z.peer(&id(1)).unwrap().queued[0];
    let b = &z.peer(&id(2)).unwrap().queued[0];
    let c = &z.peer(&id(3)).unwrap().queued[0];
    assert!(
        Arc::ptr_eq(a, b) && Arc::ptr_eq(b, c),
        "every peer must share the same Arc allocation"
    );
    assert_eq!(a.as_ref(), &[0xDE, 0xAD]);
}

/// A covert channel's armed deadline survives wakes it did not cause (CV-3).
///
/// **Sole witness, and no future measurement can subsume it — read this before
/// deciding it is redundant.** When Q-11 gives the covert cadence a derivation
/// it will also give it a conformance grade aimed at exactly this subsystem,
/// and "the cadence is measured now, CV-3 is covered" will look correct. It is
/// not. A grade checks a *sample against a distribution*, and in the defect this
/// guards every draw is honestly distributed — the emitted interval is a
/// **minimum over k draws**, which is a different random variable. The grade
/// would observe the wrong object, so it cannot subsume a mechanism assertion
/// no matter how sharp it gets (§20.2a).
///
/// Why the property needs a test at all: with per-channel timers it was free —
/// nothing but channel `i`'s timer could reach channel `i`'s deadline. Folding
/// the sleep into one wake (§20.2a) creates the shared query path, and with it
/// the possibility of re-arming on someone else's wake. Doing so resamples
/// `min + U(0, jitter)` and keeps the minimum, biasing the covert interval
/// **short** — a channel emitting faster than its own distribution claims. No
/// count assertion sees it and no goodness-of-fit grade sees it.
///
/// So the assertion is **identity**, not distribution: this channel fires at
/// the deadline it was armed with.
#[test]
fn a_noise_deadline_survives_wakes_it_did_not_cause() {
    let mut rng = SplitMix64::new(7);
    let mut z = Relay::new(
        DandelionParams::inherited(),
        2,
        LinkSecrecy::of(RelayZone::Tor),
        true,
        &[ConnectorId::Clearnet],
        // noise on — otherwise there are no deadlines and this is vacuous
        0,
        &mut rng,
    )
    .unwrap();

    // Fixture requirement: the two channels must be armed, and armed
    // *differently*, or "channel 1 unchanged" could hold by coincidence.
    let d0 = z.noise_deadline_at(0).expect("channel 0 armed");
    let d1 = z.noise_deadline_at(1).expect("channel 1 armed");
    assert!(d0 > 0 && d1 > 0, "both channels armed at construction");

    // Wake at a time no channel is due. This is the foreign wake: in
    // production it is the fluff scheduler or an epoch rollover reaching the
    // zone, and it must not touch any covert deadline.
    let quiet = d0.min(d1) - 1;
    let due = z.due_noise_channel(quiet, &mut rng);
    assert!(due.is_none(), "no channel is due before its deadline");
    assert_eq!(
        z.noise_deadline_at(0),
        Some(d0),
        "foreign wake re-armed ch0"
    );
    assert_eq!(
        z.noise_deadline_at(1),
        Some(d1),
        "foreign wake re-armed ch1"
    );

    // Now fire only the earlier channel. The OTHER one must still hold the
    // deadline it was armed with — this is the half a resample-all bug breaks.
    let (early, late) = if d0 <= d1 {
        (0usize, 1usize)
    } else {
        (1usize, 0usize)
    };
    let late_deadline = z.noise_deadline_at(late).expect("armed");
    let due = z.due_noise_channel(z.noise_deadline_at(early).unwrap(), &mut rng);
    assert_eq!(due, Some(early), "only the due channel fires");
    assert_eq!(
        z.noise_deadline_at(late),
        Some(late_deadline),
        "a sibling channel firing must not re-arm this one — \
         re-arming here is the min-over-k-draws bias CV-3 forbids"
    );

    // Liveness: the fired channel really did advance, so a no-op
    // `due_noise_channel` cannot pass the assertions above by doing nothing.
    assert!(
        z.noise_deadline_at(early).unwrap() > late_deadline.min(d0.max(d1)) - 1,
        "the fired channel re-armed forward"
    );
}

/// Production noise zones pass `stems == inherited::NOISE_CHANNELS`. The
/// schedule is that wide; pin the coupling so a future parameter split
/// cannot size the map against a different channel count.
#[test]
fn noise_enabled_pins_stem_width_to_noise_channels() {
    use shekyl_relay_privacy::params::inherited;
    let mut rng = SplitMix64::new(19);
    let z = Relay::new(
        DandelionParams::inherited(),
        inherited::NOISE_CHANNELS,
        LinkSecrecy::of(RelayZone::Tor),
        true,
        &[ConnectorId::Clearnet],
        0,
        &mut rng,
    )
    .unwrap();
    assert!(z.noise_enabled());
    assert_eq!(
        z.stem_width(),
        inherited::NOISE_CHANNELS,
        "configured width is the noise channel count"
    );
    // Covert deadlines are armed at full width at construction, even before
    // any peer populates the map (an empty outbound set leaves stem_slots
    // empty; the schedule still has one deadline per channel).
    assert!(z.noise_deadline_at(0).is_some());
    assert!(z.noise_deadline_at(inherited::NOISE_CHANNELS - 1).is_some());
    assert!(z.noise_deadline_at(inherited::NOISE_CHANNELS).is_none());
}

/// §42.3 as a table: the carrier is a FUNCTION of the phase, never a
/// substitute for it.
///
/// The inherited C++ chose a carrier *instead of* a phase — covert above the
/// switch, stem downgraded to `local` (§42.5a). Both cells of the table are
/// here: a stem under covert-on is Covert, and a fluff under covert-on stays
/// Ordinary. A test that only checked the stem cell would stay green if fluff
/// also took a covert carrier.
///
/// Epochs are determined via [`zone_with_role_cover`]. A lucky seed is
/// determinism, not a determined epoch — that is the flake routing covert
/// through the planner exposed in `noise_stem`.
#[test]
fn noise_carries_the_stem_and_only_the_stem() {
    let mut rng = SplitMix64::new(0xC0BE_0001);
    let mut stem_zone = zone_with_role_cover(false, true, &mut rng);
    establish_outbound(&mut stem_zone, &[1, 2, 3, 4], &mut rng);
    assert!(!stem_zone.is_fluffing(), "fixture must be in a stem epoch");

    let d = stem_zone.plan_dispatch(Some(id(9)), false, NodeSync::Synchronised, &mut rng);
    match (d.plan, d.carrier) {
        (RelayPlan::Stem(_), RelayCarrier::Noise { channel }) => {
            assert!(
                channel.get() < 2,
                "the covert channel IS the stem slot (§20.3), so it must be inside the \
                 stem width; broadcasting to any other channel is the §42.5a defect"
            );
        }
        (RelayPlan::Stem(_), RelayCarrier::Ordinary) => {
            panic!("covert is enabled and this is a stem — §42.3 says covert carries it")
        }
        (other, carrier) => panic!("expected a stem, got {other:?} on {carrier:?}"),
    }

    let mut fluff_zone = zone_with_role_cover(true, true, &mut rng);
    establish_outbound(&mut fluff_zone, &[1, 2, 3, 4], &mut rng);
    assert!(fluff_zone.is_fluffing(), "fixture must be in a fluff epoch");
    let fluff = fluff_zone.plan_dispatch(Some(id(9)), false, NodeSync::Synchronised, &mut rng);
    assert_eq!(fluff.plan, RelayPlan::FluffEpoch);
    assert_eq!(
        fluff.carrier,
        RelayCarrier::Ordinary,
        "covert carries the stem and only the stem — a fluff on a covert \
         carrier is the substitution §42.3 forbids"
    );
}

/// Covert OFF ⇒ every phase takes the ordinary connection. The negative
/// control: without it the test above passes on a zone that always says covert.
#[test]
fn noise_disabled_never_selects_a_noise_carrier() {
    let mut rng = SplitMix64::new(0xC0BE_0002);
    for fluffing in [true, false] {
        let mut z = zone_with_role_cover(fluffing, false, &mut rng);
        establish_outbound(&mut z, &[1, 2, 3, 4], &mut rng);
        for local_origin in [true, false] {
            let d = z.plan_dispatch(Some(id(9)), local_origin, NodeSync::Synchronised, &mut rng);
            assert_eq!(
                d.carrier,
                RelayCarrier::Ordinary,
                "covert is disabled; no phase may select a covert carrier \
                 (fluffing={fluffing}, local_origin={local_origin})"
            );
        }
    }
}

/// The plan a dispatch reports must be the plan the older entry point reports.
///
/// `plan_dispatch` is additive: it attaches a carrier, it does not re-decide
/// the phase. If these diverge, the seam has started making routing decisions
/// of its own — the substitution §42.5a records.
///
/// Both epoch roles, both origin flags: a pair that happens to draw a stem
/// epoch would miss a fluff-path re-decision. The two zones are rebuilt
/// from the **same seed** so a stem-map difference cannot masquerade as a
/// phase re-decision.
#[test]
fn dispatch_does_not_re_decide_the_phase() {
    let mut seed = 0xC0BE_0003_u64;
    for fluffing in [true, false] {
        let found = loop {
            let mut rng = SplitMix64::new(seed);
            let z = Relay::new(
                DandelionParams::inherited(),
                2,
                LinkSecrecy::of(RelayZone::Tor),
                true,
                &[ConnectorId::Clearnet],
                0,
                &mut rng,
            )
            .unwrap();
            if z.is_fluffing() == fluffing {
                break seed;
            }
            seed = seed.wrapping_add(1);
            assert!(
                seed < 0xC0BE_0003 + 10_000,
                "no epoch with fluffing={fluffing}"
            );
        };
        for local_origin in [true, false] {
            let make = || {
                let mut rng = SplitMix64::new(found);
                let mut z = Relay::new(
                    DandelionParams::inherited(),
                    2,
                    LinkSecrecy::of(RelayZone::Tor),
                    true,
                    &[ConnectorId::Clearnet],
                    0,
                    &mut rng,
                )
                .unwrap();
                establish_outbound(&mut z, &[1, 2, 3, 4], &mut rng);
                (z, rng)
            };
            let (mut za, mut ra) = make();
            let (mut zb, mut rb) = make();
            let via_dispatch = za
                .plan_dispatch(Some(id(9)), local_origin, NodeSync::Synchronised, &mut ra)
                .plan;
            let via_plan =
                zb.plan_relay(Some(id(9)), local_origin, NodeSync::Synchronised, &mut rb);
            assert_eq!(
                via_dispatch, via_plan,
                "fluffing={fluffing} local_origin={local_origin}"
            );
        }
    }
}

/// Ruling of 2026-08-19: **Dandelion++ runs on every zone regardless of
/// noise.** The carrier and the phase are independent axes, and the inherited
/// C++ covert branch collapsed them in both directions at once — it demoted a
/// `stem` to `local` under `MWARNING("Dandelion++ stem not supported over
/// noise networks")`, and then broadcast the result to *every* channel, which
/// is the opposite of what a stem is.
///
/// The premise behind the demotion was the sybil-substitution fallacy §64
/// named: that a noise network stands in for Dandelion++. It does not. Noise
/// masks the node↔proxy wire against an **external** observer; Dandelion++
/// defends against an **internal** adversarial peer. Neither substitutes for
/// the other, so enabling one is not a reason to disable the other.
///
/// Asserted on the local-origin arm because RD-4 makes that one deterministic:
/// a local origin always attempts a stem, epoch roll or not. The stem arm
/// would ride the epoch and pass only outside a fluff epoch — which is exactly
/// how the C++ `noise_stem` test came to flake at ~40%.
#[test]
fn a_noise_carrier_does_not_change_the_phase() {
    let plan_with_noise = |noise: bool| {
        let mut rng = SplitMix64::new(0x0819);
        let mut z = Relay::new(
            DandelionParams::inherited(),
            shekyl_relay_privacy::params::inherited::NOISE_CHANNELS,
            LinkSecrecy::of(RelayZone::Tor),
            noise,
            &[ConnectorId::Clearnet],
            0,
            &mut rng,
        )
        .unwrap();
        establish_outbound(&mut z, &[1, 2, 3], &mut rng);
        assert_eq!(z.noise_enabled(), noise, "fixture did not take");
        matches!(
            z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
            RelayPlan::Stem(_)
        )
    };

    assert!(
        plan_with_noise(false),
        "control: a local origin stems on an encrypted zone"
    );
    assert!(
        plan_with_noise(true),
        "the noise carrier must not demote the phase — this is the assertion \
         the deleted C++ covert branch would have failed"
    );
}

/// Ruling of 2026-08-19: **noise runs only on an encrypted zone.** What noise
/// buys is concealment of packet *sizing*, and sizing is the only thing left
/// for a network observer to read once the link is encrypted. On a cleartext
/// link that observer reads the contents outright, so padding the sizes
/// conceals nothing and the bandwidth is spent for no privacy.
///
/// Refused rather than silently downgraded to `NoiseSchedule::Off`: a node
/// configured for a protection it is not receiving is the failure worth being
/// loud about, and a silent downgrade is indistinguishable from working.
///
/// **This bites against a `Relay::new` that keys noise on reach instead of
/// secrecy; it does NOT cover the FFI flag-decode.** Reach is an independent
/// argument, not a proxy for encryption — `Encrypted + EveryPeer` is the
/// case the axis exists for (encrypted clearnet), and
/// `Cleartext + OutboundOnly` is §25.5's live configuration. The three
/// refusals are distinct [`RelayNewError`] variants so they cannot collapse
/// into one `None`.
#[test]
fn a_noise_carrier_is_refused_where_it_buys_nothing() {
    let build = |zone: RelayZone, stems: usize, noise: bool| {
        let mut rng = SplitMix64::new(0x0819);
        Relay::new(
            DandelionParams::inherited(),
            stems,
            LinkSecrecy::of(zone),
            noise,
            &[ConnectorId::Clearnet],
            0,
            &mut rng,
        )
    };
    const CHANNELS: usize = inherited::NOISE_CHANNELS;

    assert_eq!(
        build(RelayZone::Public, CHANNELS, true).err(),
        Some(RelayNewError::NoiseOnCleartext),
        "outbound-only fluff is not encryption; a cleartext zone earns no noise"
    );
    assert!(
        build(RelayZone::Tor, CHANNELS, true).is_ok(),
        "encrypted + every-peer is the case the secrecy axis exists for — \
         encrypting clearnet must not require renaming reach"
    );
    assert!(
        build(RelayZone::Tor, CHANNELS, true).is_ok(),
        "production Tor pairing still builds"
    );
    assert!(
        build(RelayZone::Public, CHANNELS, false).is_ok(),
        "a cleartext zone without noise is the ordinary case"
    );
    assert_eq!(
        build(RelayZone::Invalid, CHANNELS, true).err(),
        Some(RelayNewError::NoiseOnCleartext),
        "an unknown link is not presumed encrypted and earns no noise"
    );

    // Was a `debug_assert!`, which compiles out in release and therefore
    // admitted the mismatch in exactly the build that ships.
    assert_eq!(
        build(RelayZone::Tor, CHANNELS + 1, true).err(),
        Some(RelayNewError::NoiseChannelCount { got: CHANNELS + 1 }),
        "a channel count the schedule is not sized for is refused, not asserted"
    );

    // Arithmetic is `carrier::noise_windows_in_epoch`. This pins that
    // Relay::new consumes it for a noise zone and ignores it otherwise.
    let mut rng = SplitMix64::new(0x0820);
    let per_send_ms = carrier::NOISE_MIN_DELAY_MS + carrier::NOISE_DELAY_JITTER_MS;
    let mut short = DandelionParams::inherited();
    // One millisecond short of the epoch that would afford the full cap,
    // floored to whole seconds because the field is seconds. The assertion
    // below re-derives `affords` rather than trusting this arithmetic.
    short.min_epoch_secs = (carrier::MAX_FRAGMENTS * per_send_ms - 1) / 1_000;
    match Relay::new(
        short,
        CHANNELS,
        LinkSecrecy::of(RelayZone::Tor),
        true,
        &[ConnectorId::Clearnet],
        0,
        &mut rng,
    ) {
        Err(RelayNewError::NoiseCannotCrossOneEpoch { needs, affords }) => {
            assert_eq!(needs, carrier::MAX_FRAGMENTS);
            assert_eq!(affords, carrier::MAX_FRAGMENTS - 1);
        }
        other => panic!("expected a one-epoch refusal, got {other:?}"),
    }
    let mut params = DandelionParams::inherited();
    params.min_epoch_secs = 1;
    assert!(
        Relay::new(
            params,
            2,
            LinkSecrecy::of(RelayZone::Public),
            false,
            &[ConnectorId::Clearnet],
            0,
            &mut rng
        )
        .is_ok(),
        "no carrier, no fragment budget to blow"
    );
}
