// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! How a zone draws and rebuilds its stem set.
//!
//! Split from `tests` so the scheduling suite stays under the file ceiling.
//! The floors below are seed-specific: they are the statistical bound the
//! suite already pinned, not a new tolerance.

use super::*;

use shekyl_relay_privacy::params::DandelionParams;
use shekyl_relay_privacy::rng::SplitMix64;
use shekyl_relay_privacy::{LinkSecrecy, RelayZone};

fn id(byte: u8) -> ConnectionId {
    let mut bytes = [0u8; 16];
    bytes[0] = byte;
    ConnectionId::from_bytes(bytes)
}

fn zone(rng: &mut SplitMix64) -> Zone {
    Zone::new(
        DandelionParams::inherited(),
        2,
        LinkSecrecy::of(RelayZone::Public),
        false,
        0,
        rng,
    )
    .unwrap()
}

fn establish_outbound(zone: &mut Zone, peers: &[u8], rng: &mut SplitMix64) {
    for peer in peers {
        zone.on_session_established(
            id(*peer),
            PeerDirection::Outbound,
            NetworkClass::Clearnet,
            rng,
        );
    }
}

#[test]
fn live_stems_is_derived_not_cached() {
    // The inherited code cached this in `connection_count` and had to
    // declare "only update in strand, can be read at any time". Derived
    // here, there is no second copy to fall out of step (§18.5 finding 1).
    let mut rng = SplitMix64::new(4);
    let mut z = zone(&mut rng);
    assert_eq!(z.live_stems(), 0);

    establish_outbound(&mut z, &[1, 2, 3], &mut rng);
    assert_eq!(z.live_stems(), 2, "two stem slots at the configured width");
    assert_eq!(z.stem_slots().len(), 2);

    // A close drops the context and leaves the slot. The count moves when
    // the map is merged, not when the session disappears.
    z.drop_outbound_for_test();
    assert_eq!(
        z.live_stems(),
        2,
        "close is lazy: the dead slot is still live"
    );
    z.update_stems(&mut rng);
    assert_eq!(z.live_stems(), 0);
}

#[test]
fn an_epoch_rollover_rebuilds_the_stem_map_rather_than_merging_into_it() {
    // The inherited epoch REPLACED the map outright — `start_epoch` built a
    // fresh `connection_map{connections, count}` and `change_channels` did
    // `zone_->map = std::move(map_)`. Mid-epoch refresh was a different
    // operation: `connection_map::update`, a merge that keeps live slots in
    // place. Porting both onto the merge silently freezes the stem graph:
    // successors never rotate and every source stays pinned to the slot it
    // first drew, for the life of the process.
    //
    // That is the property epochs exist for, and it is load-bearing for the
    // embargo derivation, which assumes a source's stem successor changes
    // between epochs. A frozen graph gives a long-lived observer a stable
    // source->successor mapping to correlate on.
    //
    // The discriminator is a rollover with an UNCHANGED peer set, because
    // that is the case the two operations disagree on: a merge finds every
    // slot still live and does nothing, a rebuild re-draws. Asserting that
    // the chosen peers differ would not work — with two slots a re-draw can
    // legitimately land on the same pair — so this asserts on pinning, which
    // a rebuild always clears and a merge always keeps.
    let mut rng = SplitMix64::new(88);
    let mut z = zone(&mut rng);
    establish_outbound(&mut z, &[1, 2, 3, 4], &mut rng);

    let _ = z.stem_for(Some(id(9)), &mut rng);
    let _ = z.stem_for(None, &mut rng);
    assert_eq!(
        z.pinned_sources(),
        2,
        "fixture: two sources pinned this epoch"
    );

    z.start_epoch(0, &mut rng);
    z.rebuild_stems(&mut rng);
    assert_eq!(
        z.pinned_sources(),
        0,
        "a new epoch starts with no source pinned to any slot"
    );
}

#[test]
fn a_source_pins_to_one_stem_for_the_epoch() {
    let mut rng = SplitMix64::new(6);
    let mut z = zone(&mut rng);
    establish_outbound(&mut z, &[1, 2, 3, 4], &mut rng);

    let source = Some(id(9));
    let first = z.stem_for(source, &mut rng).expect("a stem is available");
    for _ in 0..32 {
        assert_eq!(z.stem_for(source, &mut rng), Some(first));
    }
}

#[test]
fn rollover_candidates_are_established_outbound_sessions() {
    let mut rng = SplitMix64::new(99);
    let mut z = zone(&mut rng);
    z.on_session_established(
        id(1),
        PeerDirection::Inbound,
        NetworkClass::Clearnet,
        &mut rng,
    );
    establish_outbound(&mut z, &[2, 3], &mut rng);
    z.rebuild_stems(&mut rng);
    let mut chosen: Vec<_> = z.stem_slots().iter().flatten().copied().collect();
    chosen.sort();
    assert_eq!(
        chosen,
        vec![id(2), id(3)],
        "a rollover draws every established outbound session and no inbound one"
    );
}

#[test]
fn stem_draws_are_not_biased_toward_one_outbound_peer() {
    // The registry has no recorded height, so a peer cannot be preferred
    // for reporting a higher one. Two outbound sessions, one slot: over
    // many independent epochs each peer is the successor about half the time.
    let mut rng = SplitMix64::new(100);
    let mut z = Zone::new(
        DandelionParams::inherited(),
        1,
        LinkSecrecy::of(RelayZone::Public),
        false,
        0,
        &mut rng,
    )
    .unwrap();
    establish_outbound(&mut z, &[1, 2], &mut rng);
    let mut hits = [0u32; 2];
    for _ in 0..4_000 {
        z.rebuild_stems(&mut rng);
        match z.stem_slots()[0] {
            Some(peer) if peer == id(1) => hits[0] += 1,
            Some(peer) if peer == id(2) => hits[1] += 1,
            other => panic!("slot drew {other:?}, not one of the two outbound sessions"),
        }
    }
    // Seed 100, n = 4 000, p = 1/2, σ ≈ 32. 1 950 is about 1.5σ under the
    // mean, so a 25 % bias fails and this seed does not.
    assert!(
        hits[0] > 1_950 && hits[1] > 1_950,
        "draws bunched on one peer: {hits:?}"
    );
}

#[test]
fn a_two_slot_draw_over_three_peers_uses_each_peer() {
    // More candidates than slots is the partial Fisher-Yates branch.
    // Each peer is in two of the three equally likely pairs, so about
    // two thirds of the epochs include it. Seed 101, n = 3 000, σ ≈ 26;
    // 1 950 is about 1.9σ under the mean of 2 000.
    let mut rng = SplitMix64::new(101);
    let mut z = Zone::new(
        DandelionParams::inherited(),
        2,
        LinkSecrecy::of(RelayZone::Public),
        false,
        0,
        &mut rng,
    )
    .unwrap();
    establish_outbound(&mut z, &[1, 2, 3], &mut rng);
    let mut hits = [0u32; 3];
    for _ in 0..3_000 {
        z.rebuild_stems(&mut rng);
        let slots = z.stem_slots();
        assert_eq!(slots.len(), 2);
        let mut seen = [false; 3];
        for slot in slots.iter().flatten() {
            let index = match *slot {
                peer if peer == id(1) => 0,
                peer if peer == id(2) => 1,
                peer if peer == id(3) => 2,
                other => panic!("slot drew {other:?}"),
            };
            assert!(!seen[index], "a slot pair repeated a peer");
            seen[index] = true;
            hits[index] += 1;
        }
    }
    assert!(
        hits.iter().all(|count| *count > 1_950),
        "a peer was left out of the partial draw: {hits:?}"
    );
}
