// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The reserved slot and the supplied-list pin (`DAEMON_RELAY_PRIVACY.md`
//! §98.3, D-PR1-1 (c′), D-PR1-2 (i)). The relay names the address-hiding
//! sessions as the reserved class; here the class is just `hidden`.

use super::*;
use crate::rng::SplitMix64;

fn id(tag: u8) -> ConnectionId {
    let mut b = [0_u8; 16];
    b[0] = tag;
    ConnectionId::from_bytes(b)
}

fn ids(tags: &[u8]) -> Vec<ConnectionId> {
    tags.iter().copied().map(id).collect()
}

/// A live set split into the reserved class and the rest, merged into `m`.
fn merge(m: &mut StemMap, hidden: &[u8], rest: &[u8], rng: &mut SplitMix64) -> StemSetChange {
    m.update_with_reserved(ids(hidden), ids(rest), rng)
}

#[test]
fn slot_zero_is_drawn_from_the_reserved_class_and_the_rest_from_everything_else() {
    let hidden = ids(&[1, 2, 3, 4]);
    let rest = ids(&[11, 12, 13, 14]);
    for seed in 0..64 {
        let mut rng = SplitMix64::new(seed);
        let m = StemMap::new_with_reserved_slot(hidden.clone(), rest.clone(), 2, &mut rng);
        assert!(m.has_reserved_slot());
        assert_eq!(m.width(), 2);
        let slot0 = m.slots()[0].expect("slot 0 is filled when the class is non-empty");
        assert!(
            hidden.contains(&slot0),
            "slot 0 comes from the reserved class"
        );
        let slot1 = m.slots()[1].expect("slot 1 is filled from the remainder");
        assert_ne!(slot0, slot1);
    }
}

#[test]
fn the_other_slot_is_uniform_over_the_remainder_hidden_included() {
    // Four hidden and four clear: slot 1 is drawn from the seven sessions
    // not in slot 0, so a hidden peer lands there about 3/7 of the time.
    let hidden = ids(&[1, 2, 3, 4]);
    let rest = ids(&[11, 12, 13, 14]);
    let mut hidden_in_slot1 = 0_u32;
    let trials = 4_000_u32;
    for seed in 0..trials {
        let mut rng = SplitMix64::new(u64::from(seed) + 1_000);
        let m = StemMap::new_with_reserved_slot(hidden.clone(), rest.clone(), 2, &mut rng);
        if hidden.contains(&m.slots()[1].expect("slot 1 filled")) {
            hidden_in_slot1 += 1;
        }
    }
    let share = f64::from(hidden_in_slot1) / f64::from(trials);
    assert!(
        (share - 3.0 / 7.0).abs() < 0.03,
        "slot 1 is class-blind over the remainder: hidden share {share}"
    );
}

#[test]
fn an_empty_reserved_class_leaves_slot_zero_empty_and_fills_the_rest() {
    let mut rng = SplitMix64::new(7);
    let m = StemMap::new_with_reserved_slot(Vec::new(), ids(&[11, 12, 13]), 2, &mut rng);
    assert_eq!(m.slots()[0], None, "D-PR1-2 (i): the reserved slot waits");
    assert!(
        m.slots()[1].is_some(),
        "relayed traffic routes over the other slot"
    );
    assert_eq!(m.live_stems(), 1);
}

#[test]
fn with_no_rest_the_reserved_map_is_the_paper_draw_over_the_class() {
    // Every session hides its address: slot 0 uniform over the class, slot 1
    // uniform over the remainder. Both slots are hidden peers.
    let hidden = ids(&[1, 2, 3, 4, 5, 6]);
    for seed in 0..32 {
        let mut rng = SplitMix64::new(seed + 50);
        let m = StemMap::new_with_reserved_slot(hidden.clone(), Vec::new(), 2, &mut rng);
        for slot in m.slots() {
            assert!(hidden.contains(&slot.expect("both slots filled")));
        }
    }
}

#[test]
fn zero_stems_with_a_reserved_slot_routes_nothing() {
    let mut rng = SplitMix64::new(8);
    let mut m = StemMap::new_with_reserved_slot(ids(&[1]), ids(&[11]), 0, &mut rng);
    assert_eq!(m.width(), 0);
    assert_eq!(
        merge(&mut m, &[1], &[11], &mut rng),
        StemSetChange::Unchanged
    );
    assert_eq!(m.pin_over(None, ids(&[1])), None);
}

#[test]
fn a_dead_reserved_slot_refills_from_the_class_only() {
    for seed in 0..64 {
        let mut rng = SplitMix64::new(seed + 100);
        let mut m = StemMap::new_with_reserved_slot(ids(&[1, 2]), ids(&[11, 12, 13]), 2, &mut rng);
        let slot0 = m.slots()[0].expect("filled");
        let survivor = if slot0 == id(1) { 2 } else { 1 };
        let survivor_in_slot1 = m.slots()[1] == Some(id(survivor));
        // Slot 0's peer drops; one hidden session remains; the rest is full.
        let change = merge(&mut m, &[survivor], &[11, 12, 13], &mut rng);
        assert_eq!(change, StemSetChange::Changed);
        if survivor_in_slot1 {
            // The class-blind draw already slotted it; it is not moved, and
            // no clear session may take the reserved slot.
            assert_eq!(m.slots()[0], None);
            assert_eq!(m.slots()[1], Some(id(survivor)));
        } else {
            assert_eq!(
                m.slots()[0],
                Some(id(survivor)),
                "slot 0 takes the remaining hidden session, never a clear one"
            );
        }
    }
}

#[test]
fn a_dead_reserved_slot_with_no_class_left_stays_empty_while_the_rest_refills() {
    let mut rng = SplitMix64::new(9);
    let mut m = StemMap::new_with_reserved_slot(ids(&[1]), ids(&[11, 12]), 2, &mut rng);
    assert_eq!(m.slots()[0], Some(id(1)));
    let slot1 = m.slots()[1].expect("filled");
    // Both slot peers drop; a clear session remains; no hidden one does.
    let other_clear = if slot1 == id(11) { 12 } else { 11 };
    let _changed = merge(&mut m, &[], &[other_clear], &mut rng);
    assert_eq!(
        m.slots()[0],
        None,
        "never a clear peer in the reserved slot"
    );
    assert_eq!(m.slots()[1], Some(id(other_clear)));
}

#[test]
fn a_reserved_arrival_fills_the_empty_slot_at_the_merge_and_moves_no_pinned_source() {
    let mut rng = SplitMix64::new(10);
    let mut m = StemMap::new_with_reserved_slot(Vec::new(), ids(&[11, 12]), 2, &mut rng);
    assert_eq!(m.slots()[0], None);
    let slot1 = m.slots()[1].expect("filled");
    // A relayed source pins while only slot 1 is live.
    let relayed = Some(id(99));
    assert_eq!(m.stem_for(relayed, &mut rng), Some(slot1));
    // A hidden session arrives: the next merge fills slot 0 (rule 3), and the
    // pinned relayed source stays where it was (W3c).
    let change = merge(&mut m, &[1], &[11, 12], &mut rng);
    assert_eq!(change, StemSetChange::Changed);
    assert_eq!(m.slots()[0], Some(id(1)));
    assert_eq!(m.stem_for(relayed, &mut rng), Some(slot1));
}

#[test]
fn a_full_reserved_map_merges_unchanged_and_draws_nothing() {
    let mut rng = SplitMix64::new(11);
    let mut m = StemMap::new_with_reserved_slot(ids(&[1, 2]), ids(&[11, 12]), 2, &mut rng);
    let before = m.clone();
    let mut probe = SplitMix64::new(12);
    let expected_next = probe.next_u64();
    let mut rng2 = SplitMix64::new(12);
    assert_eq!(
        merge(&mut m, &[1, 2], &[11, 12], &mut rng2),
        StemSetChange::Unchanged
    );
    assert_eq!(m, before);
    assert_eq!(rng2.next_u64(), expected_next, "no draw was consumed");
}

#[test]
fn pin_over_freezes_the_supplied_list_and_needs_only_its_head_slotted() {
    let mut rng = SplitMix64::new(13);
    let mut m = StemMap::new_with_reserved_slot(ids(&[1, 2, 3]), ids(&[11]), 2, &mut rng);
    let primary = m.slots()[0].expect("filled");
    let alternate = if primary == id(1) { id(2) } else { id(1) };
    assert!(!m.is_pinned(None));
    assert_eq!(
        m.pin_over(None, vec![primary, alternate]),
        Some(primary),
        "the primary is slot 0's peer"
    );
    assert!(m.is_pinned(None));
    assert_eq!(m.usage()[0], 1, "the local source counts against slot 0");
    // Already pinned: the list is ignored and the pin is walked.
    assert_eq!(m.pin_over(None, vec![id(3)]), Some(primary));
}

#[test]
fn pin_over_refuses_an_empty_list_or_an_unslotted_head_without_pinning() {
    let mut rng = SplitMix64::new(14);
    let mut m = StemMap::new_with_reserved_slot(ids(&[1, 2]), ids(&[11]), 2, &mut rng);
    assert_eq!(m.pin_over(None, Vec::new()), None);
    assert!(
        !m.is_pinned(None),
        "an origination that finds nothing leaves the next one free"
    );
    let unslotted = ids(&[1, 2])
        .into_iter()
        .find(|p| m.slot_of(*p).is_none())
        .expect("one hidden session is not slotted");
    assert_eq!(m.pin_over(None, vec![unslotted]), None);
    assert!(!m.is_pinned(None));
    assert_eq!(m.usage(), &[0, 0]);
}

/// D-PR1-1 (c′) end to end: the primary drops, the merge moves the live
/// alternate into slot 0, the walk rides it; the alternate drops, the walk is
/// exhausted (`None`) while slot 0 refills for relayed traffic; a session
/// opened after the pin never serves the local source.
#[test]
fn the_local_pin_walks_to_its_alternate_through_the_reserved_fill_and_then_holds() {
    for seed in 0..32 {
        let mut rng = SplitMix64::new(seed + 200);
        let mut m = StemMap::new_with_reserved_slot(ids(&[1, 2, 3]), ids(&[11, 12]), 2, &mut rng);
        let primary = m.slots()[0].expect("filled");
        // The alternate is a hidden session the map has not slotted; the
        // third hidden session may or may not sit in slot 1.
        let alternate = ids(&[1, 2, 3])
            .into_iter()
            .find(|p| m.slot_of(*p).is_none())
            .expect("three hidden sessions, two slots");
        let third = ids(&[1, 2, 3])
            .into_iter()
            .find(|p| *p != primary && *p != alternate)
            .expect("the remaining hidden session");
        let hidden_live = |dropped: &[ConnectionId]| -> Vec<ConnectionId> {
            ids(&[1, 2, 3, 4])
                .into_iter()
                .filter(|p| !dropped.contains(p))
                .collect()
        };
        assert_eq!(m.pin_over(None, vec![primary, alternate]), Some(primary));

        // The primary drops. Session 4 opened after the pin. The merge fills
        // slot 0 with the pin's live alternate, not with 4 and not with 3.
        let dropped = vec![primary];
        let live = hidden_live(&dropped);
        let live_u8: Vec<u8> = live.iter().map(|p| p.0[0]).collect();
        let _changed = merge(&mut m, &live_u8, &[11, 12], &mut rng);
        assert_eq!(
            m.slots()[0],
            Some(alternate),
            "the hidden-slot fill takes the pin's alternate"
        );
        assert_eq!(
            m.stem_for_among(None, &live, &mut rng),
            Some(alternate),
            "the walk rides the alternate"
        );

        // The alternate drops too. The pin is exhausted: the local source
        // holds. Slot 0 refills uniformly from the class for relayed traffic.
        let dropped = vec![primary, alternate];
        let live = hidden_live(&dropped);
        let live_u8: Vec<u8> = live.iter().map(|p| p.0[0]).collect();
        let _changed = merge(&mut m, &live_u8, &[11, 12], &mut rng);
        let refilled = m.slots()[0].expect("slot 0 refills for relayed traffic");
        assert!(refilled == third || refilled == id(4));
        assert_eq!(
            m.stem_for_among(None, &live, &mut rng),
            None,
            "a session opened after the pin never serves the local source"
        );
        // And stays held: the pin does not re-draw within the epoch.
        assert_eq!(m.stem_for_among(None, &live, &mut rng), None);
        assert!(m.is_pinned(None));
    }
}

#[test]
fn an_alternate_that_dropped_first_leaves_the_pin_exhausted_at_the_primary_drop() {
    let mut rng = SplitMix64::new(15);
    let mut m = StemMap::new_with_reserved_slot(ids(&[1, 2, 3]), ids(&[11]), 2, &mut rng);
    let primary = m.slots()[0].expect("filled");
    let alternate = ids(&[1, 2, 3])
        .into_iter()
        .find(|p| m.slot_of(*p).is_none())
        .expect("three hidden sessions, two slots");
    let third = ids(&[1, 2, 3])
        .into_iter()
        .find(|p| *p != primary && *p != alternate)
        .expect("the remaining hidden session");
    assert_eq!(m.pin_over(None, vec![primary, alternate]), Some(primary));
    // The alternate drops while the primary is live: nothing moves yet.
    let _changed = merge(&mut m, &[primary.0[0], third.0[0]], &[11], &mut rng);
    assert_eq!(m.slots()[0], Some(primary));
    assert_eq!(
        m.stem_for_among(None, &[primary, third], &mut rng),
        Some(primary)
    );
    // Then the primary drops: the alternate is gone, so the pin is exhausted
    // while slot 0 refills from the class for relayed traffic (or stays
    // empty when the class-blind draw already holds the third in slot 1).
    let third_in_slot1 = m.slots()[1] == Some(third);
    let _changed = merge(&mut m, &[third.0[0]], &[11], &mut rng);
    assert_eq!(
        m.slots()[0],
        if third_in_slot1 { None } else { Some(third) }
    );
    assert_eq!(m.stem_for_among(None, &[third], &mut rng), None);
}

#[test]
fn an_alternate_already_in_the_other_slot_is_not_moved_and_the_walk_finds_it_there() {
    // Two hidden sessions, no rest: slot 1 holds the second hidden session.
    let mut rng = SplitMix64::new(16);
    let mut m = StemMap::new_with_reserved_slot(ids(&[1, 2]), Vec::new(), 2, &mut rng);
    let primary = m.slots()[0].expect("filled");
    let alternate = m.slots()[1].expect("filled");
    assert_eq!(m.pin_over(None, vec![primary, alternate]), Some(primary));
    // The primary drops; the alternate is slotted already, so slot 0 stays
    // empty (nothing unslotted in the class) and the walk resolves to slot 1.
    let _changed = merge(&mut m, &[alternate.0[0]], &[], &mut rng);
    assert_eq!(m.slots()[0], None);
    assert_eq!(m.slots()[1], Some(alternate));
    assert_eq!(
        m.stem_for_among(None, &[alternate], &mut rng),
        Some(alternate)
    );
    assert_eq!(
        m.usage(),
        &[0, 1],
        "usage re-synced to the slot the alternate occupies"
    );
}

#[test]
fn relayed_sources_pin_over_both_slots_and_are_unchanged_by_the_reserved_slot() {
    let mut rng = SplitMix64::new(17);
    let mut m = StemMap::new_with_reserved_slot(ids(&[1, 2]), ids(&[11, 12]), 2, &mut rng);
    let mut seen = std::collections::BTreeSet::new();
    for tag in 100..140 {
        let dest = m.stem_for(Some(id(tag)), &mut rng).expect("routable");
        seen.insert(m.slot_of(dest).expect("slotted").get());
    }
    assert_eq!(seen.len(), 2, "relayed sources reach both slots");
}
