// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;
use crate::rng::SplitMix64;

fn ids(n: u8) -> Vec<ConnectionId> {
    (0..n)
        .map(|i| {
            let mut b = [0_u8; 16];
            b[0] = i + 1;
            ConnectionId::from_bytes(b)
        })
        .collect()
}

#[test]
fn empty_map_routes_nothing() {
    let mut rng = SplitMix64::new(1);
    let mut m = StemMap::empty();
    assert_eq!(m.stem_for(None, &mut rng), None);
    assert_eq!(m.live_stems(), 0);
}

#[test]
fn zero_stems_routes_nothing() {
    let mut rng = SplitMix64::new(2);
    let mut m = StemMap::new(ids(5), 0, &mut rng);
    assert_eq!(m.width(), 0);
    assert_eq!(m.stem_for(None, &mut rng), None);
    assert_eq!(m.stem_for(Some(ids(1)[0]), &mut rng), None);
}

#[test]
fn construction_truncates_to_the_stem_count() {
    let mut rng = SplitMix64::new(3);
    let m = StemMap::new(ids(10), 2, &mut rng);
    assert_eq!(m.live_stems(), 2);
    assert_eq!(m.width(), 2);
}

#[test]
fn construction_keeps_all_when_fewer_peers_than_stems() {
    let mut rng = SplitMix64::new(4);
    let m = StemMap::new(ids(1), 3, &mut rng);
    assert_eq!(m.live_stems(), 1);
    assert_eq!(m.width(), 3, "width is the configured stem count");
}

#[test]
fn a_source_is_pinned_to_one_stem_for_the_epoch() {
    let mut rng = SplitMix64::new(5);
    let peers = ids(8);
    let mut m = StemMap::new(peers.clone(), 2, &mut rng);
    let source = Some(peers[0]);
    let first = m.stem_for(source, &mut rng).expect("a stem is available");
    for _ in 0..64 {
        assert_eq!(m.stem_for(source, &mut rng), Some(first));
    }
}

#[test]
fn distinct_sources_spread_across_stems() {
    let mut rng = SplitMix64::new(6);
    let peers = ids(20);
    let mut m = StemMap::new(peers.clone(), 2, &mut rng);
    for p in &peers {
        let _ = m.stem_for(Some(*p), &mut rng);
    }
    // Lowest-usage selection must keep the two slots within one of each
    // other after an even number of assignments.
    let usage = m.usage();
    let spread = usage.iter().max().unwrap() - usage.iter().min().unwrap();
    assert!(spread <= 1, "stem usage unbalanced: {usage:?}");
    assert_eq!(usage.iter().sum::<usize>(), peers.len());
}

#[test]
fn local_source_is_a_key_like_any_other() {
    let mut rng = SplitMix64::new(7);
    let mut m = StemMap::new(ids(4), 2, &mut rng);
    let local = m.stem_for(None, &mut rng).expect("stem available");
    assert_eq!(m.stem_for(None, &mut rng), Some(local));
    assert_eq!(m.usage().iter().sum::<usize>(), 1);
}

#[test]
fn dropped_stem_is_backfilled_by_update() {
    let mut rng = SplitMix64::new(8);
    let peers = ids(6);
    let mut m = StemMap::new(peers.clone(), 2, &mut rng);
    assert_eq!(m.live_stems(), 2);

    // Drop every peer currently serving as a stem by presenting a set that
    // excludes them.
    let live: Vec<ConnectionId> = m.out.iter().flatten().copied().collect();
    let survivors: Vec<ConnectionId> = peers
        .iter()
        .filter(|p| !live.contains(p))
        .copied()
        .collect();
    assert_eq!(
        m.update(survivors, &mut rng),
        StemSetChange::Changed,
        "update should report change"
    );
    assert_eq!(m.live_stems(), 2, "slots backfilled from survivors");
    for slot in m.out.iter().flatten() {
        assert!(!live.contains(slot), "a dead peer was reused");
    }
}

#[test]
fn a_slot_emptied_by_an_earlier_update_is_backfilled_later() {
    // Regression: an empty slot left by a prior update (no candidate to fill
    // it then) must be backfilled by a *later* update that offers one, even
    // if that later update disconnects nothing else. The early-return must
    // not treat "nothing disconnected this call" as "every slot is live".
    let mut rng = SplitMix64::new(11);
    let peers = ids(3); // 3 peers, 2 stems → exactly one spare
    let mut m = StemMap::new(peers.clone(), 2, &mut rng);
    assert_eq!(m.live_stems(), 2);

    let live: Vec<ConnectionId> = m.out.iter().flatten().copied().collect();
    let spare: ConnectionId = *peers.iter().find(|p| !live.contains(p)).unwrap();

    // Call 1: drop one live stem, offering only the other — no candidate to
    // backfill, so a slot goes empty and stays empty.
    assert_eq!(m.update(vec![live[1]], &mut rng), StemSetChange::Changed);
    assert_eq!(
        m.live_stems(),
        1,
        "one slot left empty (no candidate to fill)"
    );

    // Call 2: the surviving stem stays and a fresh candidate appears. The
    // empty slot must be backfilled — and the change must be reported.
    assert_eq!(
        m.update(vec![live[1], spare], &mut rng),
        StemSetChange::Changed,
        "backfilling a previously-emptied slot is a reportable change"
    );
    assert_eq!(
        m.live_stems(),
        2,
        "the empty slot was backfilled from the new candidate"
    );
}

#[test]
fn update_is_a_no_op_when_nothing_changed() {
    let mut rng = SplitMix64::new(9);
    let peers = ids(5);
    let mut m = StemMap::new(peers.clone(), 2, &mut rng);
    assert_eq!(m.update(peers, &mut rng), StemSetChange::Unchanged);
}

/// **W3c acceptance (§19.2 item 2).** A pinned source must never be routed
/// to a peer that entered the map *after* it pinned.
///
/// The transition this asserts across is the one where **nothing executes**:
/// `update()` empties the pinned slot and backfills it, and the old
/// `stem_for` then took the `self.out[index].is_some()` fast path and
/// returned the new occupant. There was no selection call to hang a property
/// on — the re-roll *was the absence of an operation* — which is why the
/// assertion has to be about the peer that comes back, across the sequence,
/// rather than about anything the map does.
///
/// Both §19.1 C-1 triggers are represented: two `update` calls in sequence,
/// as `plan_relay_with_refresh` (on `NoRoute`) and `dandelionpp_notify` (on
/// send failure) would produce. A per-call property is escaped by exactly
/// this composition.
#[test]
fn a_pinned_source_is_never_routed_to_a_post_pin_arrival() {
    let mut rng = SplitMix64::new(0x9C1);
    // Three peers, two stems: one spare, so a churned slot CAN be backfilled.
    // The inherited `gtest_dropped_connection_remapped` fixture has no spare
    // and therefore never constructs this state at all.
    let peers = ids(3);
    let mut m = StemMap::new(peers.clone(), 2, &mut rng);

    let source = Some(ids(1)[0]);
    let first = m.stem_for(source, &mut rng).expect("a stem is available");
    let frozen: Vec<ConnectionId> = m.slots().iter().flatten().copied().collect();
    assert_eq!(frozen.len(), 2, "fixture: two live stems at pin time");

    // Trigger 1 — the pinned peer churns; the spare backfills its slot.
    let survivors: Vec<ConnectionId> = peers.iter().copied().filter(|p| *p != first).collect();
    assert_eq!(
        m.update(survivors.clone(), &mut rng),
        StemSetChange::Changed
    );
    let arrival = m
        .slots()
        .iter()
        .flatten()
        .copied()
        .find(|p| !frozen.contains(p))
        .expect("fixture: the backfill brought in a peer that was not frozen");

    let after = m.stem_for(source, &mut rng).expect("the alternate is live");
    assert_ne!(
        after, arrival,
        "the source followed the backfill into its own slot — this is the \
         silent re-roll, and it is the whole of W3c"
    );
    assert!(
        frozen.contains(&after),
        "a pinned source may only be served by peers frozen at its pin"
    );

    // Trigger 2 — a second refresh in the same epoch. The composition is
    // where a per-call property leaks, so the assertion is repeated after it.
    assert_eq!(m.update(survivors, &mut rng), StemSetChange::Unchanged);
    let after_two = m.stem_for(source, &mut rng).expect("still routable");
    assert_eq!(
        after_two, after,
        "a no-op refresh must not move a pinned source"
    );
    assert!(
        frozen.contains(&after_two),
        "the frozen set must survive a SEQUENCE of updates, not just one"
    );
}

/// **W3c acceptance (§19.2 item 3) — the negative control, run in-process.**
///
/// Replays the same sequence against the *pre-fix* mechanism (pin by slot
/// index; follow whoever occupies it) and asserts it lands on the post-pin
/// arrival. If this ever stops reproducing the defect, the control has gone
/// blind and the test above is no longer discriminating anything.
///
/// Modelled rather than reached through the real type, because the defect is
/// the *absence* of the walk — there is no flag to turn off. The model is
/// three lines and its fidelity is checked by the assertion it makes: the
/// slot-follower lands on the arrival, which is precisely what
/// `probe_silent_reroll` observed on the real map before the fix.
#[test]
fn negative_control_slot_pinning_follows_the_backfill() {
    let mut rng = SplitMix64::new(0x9C1);
    let peers = ids(3);
    let mut m = StemMap::new(peers.clone(), 2, &mut rng);

    let source = Some(ids(1)[0]);
    let first = m.stem_for(source, &mut rng).expect("a stem is available");
    let pinned_slot = m
        .slots()
        .iter()
        .position(|s| *s == Some(first))
        .expect("the pinned peer occupies a slot");
    let frozen: Vec<ConnectionId> = m.slots().iter().flatten().copied().collect();

    let survivors: Vec<ConnectionId> = peers.iter().copied().filter(|p| *p != first).collect();
    assert_eq!(m.update(survivors, &mut rng), StemSetChange::Changed);

    // The pre-fix read: whatever now occupies the pinned SLOT.
    let slot_follower = m.slots()[pinned_slot].expect("the slot was backfilled");
    assert!(
        !frozen.contains(&slot_follower),
        "control: the backfill must be a post-pin arrival, or this proves nothing"
    );
    assert_ne!(
        slot_follower,
        m.stem_for(source, &mut rng).expect("the alternate is live"),
        "control: slot-pinning and the frozen set MUST disagree here — if they \
         agree, the fixture stopped exercising the defect"
    );
}

#[test]
fn losing_all_peers_falls_back_to_no_stem() {
    let mut rng = SplitMix64::new(10);
    let peers = ids(4);
    let mut m = StemMap::new(peers.clone(), 2, &mut rng);
    let source = Some(peers[0]);
    assert!(m.stem_for(source, &mut rng).is_some());

    assert_eq!(m.update(Vec::new(), &mut rng), StemSetChange::Changed);
    assert_eq!(m.live_stems(), 0);
    assert_eq!(
        m.stem_for(source, &mut rng),
        None,
        "no routable stem must surface as None, not a stale peer"
    );
    // The released slot must not leave a phantom usage count behind.
    assert_eq!(m.usage().iter().sum::<usize>(), 0);
}

#[test]
fn remapped_source_releases_its_old_slot() {
    let mut rng = SplitMix64::new(11);
    let peers = ids(6);
    let mut m = StemMap::new(peers.clone(), 2, &mut rng);

    for p in &peers {
        let _ = m.stem_for(Some(*p), &mut rng);
    }
    let before: usize = m.usage().iter().sum();
    assert_eq!(before, peers.len());

    // Kill one slot; every source counted there must walk to its alternate.
    let victim = m.out[0].expect("slot 0 live");
    let survivors: Vec<ConnectionId> = peers.iter().filter(|p| **p != victim).copied().collect();
    assert_eq!(m.update(survivors, &mut rng), StemSetChange::Changed);
    for p in &peers {
        let _ = m.stem_for(Some(*p), &mut rng);
    }
    assert_eq!(
        m.usage().iter().sum::<usize>(),
        before,
        "walking to an alternate must not double-count a source"
    );
}

/// A frozen peer that leaves and re-enters a *different* slot between
/// `stem_for` calls must not leave a phantom usage count on the old index.
///
/// Without re-syncing `Pin::counted` against `slot_of(chosen)`, identity-equal
/// peers would skip the usage fix and poison load-balance for later first-pins.
#[test]
fn frozen_peer_reappearing_in_a_new_slot_resyncs_usage() {
    let mut rng = SplitMix64::new(0xA11);
    // Build a map with a known layout: two live stems, one spare in the pool.
    let peers = ids(3);
    let mut m = StemMap::new(peers.clone(), 2, &mut rng);

    let source = Some(ids(1)[0]);
    let first = m.stem_for(source, &mut rng).expect("stem available");
    let primary_slot = m
        .slots()
        .iter()
        .position(|s| *s == Some(first))
        .expect("primary occupies a slot");
    let other: ConnectionId = m
        .slots()
        .iter()
        .flatten()
        .copied()
        .find(|p| *p != first)
        .expect("second stem live");
    let other_slot = m
        .slots()
        .iter()
        .position(|s| *s == Some(other))
        .expect("other occupies a slot");
    assert_ne!(primary_slot, other_slot);
    assert_eq!(m.usage()[primary_slot], 1);
    assert_eq!(m.usage().iter().sum::<usize>(), 1);

    // Drop both stems so the map is empty, then refill with `[other, first]`
    // so `first` lands in a controlled slot. No stem_for in between — the
    // cursor never observes the gap, so `first` remains the current candidate.
    assert_eq!(m.update(Vec::new(), &mut rng), StemSetChange::Changed);
    assert_eq!(m.live_stems(), 0);
    // Refill order is random from the candidate pool; pin the layout by offering
    // only two peers after a full clear — update fills slots 0..width from draws.
    // Force a known layout by presenting peers and then manually checking that
    // `first` is live somewhere other than `primary_slot` when possible; the
    // invariant under test does not require a move, only that usage matches the
    // slot `first` currently occupies after resolve.
    assert_eq!(
        m.update(vec![other, first], &mut rng),
        StemSetChange::Changed
    );
    assert_eq!(m.live_stems(), 2);
    let new_slot = m
        .slots()
        .iter()
        .position(|s| *s == Some(first))
        .expect("primary re-entered a slot");

    let routed = m.stem_for(source, &mut rng).expect("still routable");
    assert_eq!(
        routed, first,
        "unobserved gap does not permanently tombstone"
    );
    assert_eq!(m.usage().iter().sum::<usize>(), 1, "no phantom counts");
    assert_eq!(
        m.usage()[new_slot],
        1,
        "usage must sit on the slot that currently holds the peer \
         (was index {primary_slot}, now {new_slot})"
    );
    for (i, u) in m.usage().iter().enumerate() {
        if i != new_slot {
            assert_eq!(*u, 0, "no leftover count on slot {i}");
        }
    }
}

/// Once `stem_for` observes a candidate missing, that peer is walked past and
/// never re-serves this source — even if it reconnects later.
#[test]
fn observed_absence_permanently_advances_the_cursor() {
    let mut rng = SplitMix64::new(0xA12);
    let peers = ids(3);
    let mut m = StemMap::new(peers.clone(), 2, &mut rng);

    let source = Some(ids(1)[0]);
    let first = m.stem_for(source, &mut rng).expect("stem available");
    let other: ConnectionId = m
        .slots()
        .iter()
        .flatten()
        .copied()
        .find(|p| *p != first)
        .expect("second stem");

    // Drop primary; observe the gap via stem_for → walk to alternate.
    assert_eq!(m.update(vec![other], &mut rng), StemSetChange::Changed);
    let after = m.stem_for(source, &mut rng).expect("alternate live");
    assert_eq!(after, other);
    assert_eq!(m.usage().iter().sum::<usize>(), 1);

    // Primary reconnects into the empty slot. Cursor already walked past it.
    assert_eq!(
        m.update(vec![other, first], &mut rng),
        StemSetChange::Changed
    );
    assert_eq!(
        m.stem_for(source, &mut rng),
        Some(other),
        "an observed-absent candidate must not re-serve after reconnect"
    );
    assert_eq!(m.usage().iter().sum::<usize>(), 1);
}

#[test]
fn update_never_assigns_one_peer_to_two_slots() {
    let mut rng = SplitMix64::new(12);
    let peers = ids(3);
    let mut m = StemMap::new(peers.clone(), 3, &mut rng);
    assert_eq!(m.update(peers, &mut rng), StemSetChange::Unchanged);
    let live: Vec<ConnectionId> = m.out.iter().flatten().copied().collect();
    let mut sorted = live.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), live.len(), "duplicate peer across stem slots");
}

// --- Faithful translations of the C++ `dandelionpp_map` gtests (the
// survivor half of RP-2a's acceptance, DAEMON_RELAY_PRIVACY.md §16).
//
// The C++ suite (`tests/unit_tests/net.cpp`) stays as the migration oracle
// through the RP-2a cut and until an explicit retire (here or RP-3). These
// Rust cases are full outcome-invariant parity with that oracle so we can
// prove the port matches **before** cutting over. Assertions are
// RNG-agnostic (membership, counts, pin stability, even load, clone slot
// identity) — never exact peer draws.
//
// `traits` is a C++ STL/move-only ABI test with no Rust analogue
// (`StemMap` is `Clone` by design; the C++ wrapper deletes shallow copy).

fn source_ids(n: u8, tag: u8) -> Vec<ConnectionId> {
    (0..n)
        .map(|i| {
            let mut b = [0u8; 16];
            b[0] = tag;
            b[1] = i;
            ConnectionId::from_bytes(b)
        })
        .collect()
}

/// Live stem slots are unique and drawn from `peers`.
fn assert_live_slots_subset_of(m: &StemMap, peers: &[ConnectionId]) {
    let mut seen = Vec::new();
    for id in m.slots().iter().flatten() {
        assert!(
            peers.contains(id),
            "stem slot {id:?} is not in the peer set"
        );
        assert!(
            !seen.contains(id),
            "duplicate peer {id:?} across stem slots"
        );
        seen.push(*id);
    }
    assert_eq!(seen.len(), m.live_stems());
}

fn assert_clone_slots_equal(m: &StemMap) {
    let cloned = m.clone();
    assert_eq!(cloned.live_stems(), m.live_stems());
    assert_eq!(
        cloned.slots(),
        m.slots(),
        "clone must deep-copy slot layout"
    );
}

/// Per-stem source counts from a pin table (C++ `used[out]++` shape).
fn usage_by_stem(
    mapping: &std::collections::BTreeMap<ConnectionId, ConnectionId>,
) -> std::collections::BTreeMap<ConnectionId, usize> {
    let mut used = std::collections::BTreeMap::new();
    for out in mapping.values() {
        *used.entry(*out).or_insert(0) += 1;
    }
    used
}

#[test]
fn gtest_empty() {
    // C++ `dandelionpp_map.empty`: default map has empty span, size 0;
    // clone matches.
    let m = StemMap::empty();
    assert_eq!(m.live_stems(), 0);
    assert!(m.slots().is_empty());
    assert_eq!(m.width(), 0);
    assert_clone_slots_equal(&m);
}

#[test]
fn gtest_zero_stems() {
    // C++ `dandelionpp_map.zero_stems`: stems=0 → empty span, get_stem is
    // always None, update is a no-op, clone stays empty.
    let mut rng = SplitMix64::new(0xD0);
    let peers = ids(6);
    let mut m = StemMap::new(peers.clone(), 0, &mut rng);
    assert_eq!(m.live_stems(), 0);
    assert!(m.slots().is_empty());
    assert_eq!(m.width(), 0);

    for p in &peers {
        assert_eq!(m.stem_for(Some(*p), &mut rng), None);
    }

    assert_eq!(m.update(peers.clone(), &mut rng), StemSetChange::Unchanged);
    assert_eq!(m.live_stems(), 0);
    assert!(m.slots().is_empty());

    for p in &peers {
        assert_eq!(m.stem_for(Some(*p), &mut rng), None);
    }
    assert_clone_slots_equal(&m);
}

#[test]
fn gtest_dropped_connection() {
    // C++ `dandelionpp_map.dropped_connection` (net.cpp ~1833–1956):
    // 6 peers / 3 stems; nine inbound sources at 3-per-stem; drop one stem
    // and backfill from a spare; pins on the lost stem re-point to the
    // replacement in that slot; other pins stay; load stays even; clones
    // match slot layout throughout.
    let mut rng = SplitMix64::new(0xD1);
    let mut peers = ids(6);
    let mut m = StemMap::new(peers.clone(), 3, &mut rng);
    assert_eq!(m.live_stems(), 3);
    assert_eq!(m.slots().len(), 3);
    assert_live_slots_subset_of(&m, &peers);
    assert_clone_slots_equal(&m);

    assert_eq!(
        m.update(peers.clone(), &mut rng),
        StemSetChange::Unchanged,
        "re-presenting the full set must not re-arm"
    );
    assert_eq!(m.live_stems(), 3);
    assert_live_slots_subset_of(&m, &peers);

    let sources = source_ids(9, 100);
    let mut mapping = std::collections::BTreeMap::new();
    let mut inverse: std::collections::BTreeMap<ConnectionId, Vec<ConnectionId>> =
        std::collections::BTreeMap::new();
    for s in &sources {
        let out = m.stem_for(Some(*s), &mut rng).expect("a stem is available");
        assert!(mapping.insert(*s, out).is_none());
        inverse.entry(out).or_default().push(*s);
    }
    let used = usage_by_stem(&mapping);
    assert_eq!(used.len(), 3);
    assert!(
        used.values().all(|c| *c == 3),
        "nine sources spread 3-per-stem: {used:?}"
    );
    for s in &sources {
        assert_eq!(m.stem_for(Some(*s), &mut rng), Some(mapping[s]));
    }

    // The peers live at pin time — every source's frozen set (§19.2). A
    // displaced source may be re-served only from here, never from a peer
    // that arrives afterwards.
    let frozen_at_pin: Vec<ConnectionId> = m.slots().iter().flatten().copied().collect();

    // Drop the middle stem slot's peer (C++: `*(++mapper.begin())`).
    let lost = m.slots()[1].expect("slot 1 live");
    peers.retain(|p| *p != lost);
    assert_eq!(m.update(peers.clone(), &mut rng), StemSetChange::Changed);
    assert_eq!(m.live_stems(), 3, "the dropped slot was backfilled");
    assert_eq!(m.slots().len(), 3);
    for slot in m.slots().iter().flatten() {
        assert_ne!(*slot, lost, "the dropped peer was reused");
    }
    assert_live_slots_subset_of(&m, &peers);

    // **DELIBERATE DIVERGENCE FROM THE PORT (RP-2b, W3c).** The C++ this
    // twin was ported from re-pointed the sources on the lost stem at
    // whatever backfilled its slot, and the twin encoded that by rewriting
    // its own expectation: `mapping.insert(*s, newly_mapped)`. That single
    // line IS the induced-churn amplifier — a peer drawn *after* the churn
    // becoming the source's successor with no selection running (§19.2).
    // §19.3 measured it at 91.7 % exposure over 16 forced re-rolls.
    //
    // So the expectation is no longer rewritten. Displaced sources are
    // tracked instead, and asserted below to land inside their frozen set.
    let newly_mapped = m.slots()[1].expect("slot 1 backfilled");
    assert_ne!(newly_mapped, lost);
    let displaced: std::collections::BTreeSet<ConnectionId> =
        inverse.get(&lost).into_iter().flatten().copied().collect();
    assert!(
        !displaced.is_empty(),
        "fixture: the lost stem carried sources"
    );

    assert_clone_slots_equal(&m);
    assert_live_slots_subset_of(&m, &peers);

    // Pin table and even load hold after the churn.
    let mut used_after = std::collections::BTreeMap::new();
    for s in &sources {
        let out = m
            .stem_for(Some(*s), &mut rng)
            .expect("still routable after backfill");
        if displaced.contains(s) {
            assert!(
                frozen_at_pin.contains(&out) && out != lost,
                "a displaced source must re-point inside its frozen set"
            );
            assert_ne!(
                out, newly_mapped,
                "a displaced source must NOT follow the backfill — that is W3c"
            );
        } else {
            assert_eq!(out, mapping[s], "an unaffected pin must not move");
        }
        *used_after.entry(out).or_insert(0) += 1;
    }
    // **DIVERGENCE, and the property's cost.** The port re-balanced displaced
    // sources across all three stems, because it re-selected them by
    // least-used slot. Walking a frozen set cannot re-balance: a displaced
    // source goes to *its own* alternate, so the backfilled slot carries no
    // traffic until a source pins there for the first time. Load evens out
    // as new sources arrive and is re-drawn wholesale at the epoch boundary;
    // what is bought for it is that a churn cannot hand a source to a peer
    // chosen after the churn (§19.2).
    assert_eq!(
        used_after.values().sum::<usize>(),
        sources.len(),
        "every source is still routed exactly once"
    );
    assert!(
        used_after.keys().all(|p| frozen_at_pin.contains(p)),
        "post-churn traffic goes only to peers frozen at pin time: {used_after:?}"
    );
    assert_clone_slots_equal(&m);
}

#[test]
fn gtest_dropped_connection_remapped() {
    // C++ `dandelionpp_map.dropped_connection_remapped` (net.cpp ~1958–2095):
    // 3 peers / 3 stems → drop one (nil hole, no spare) → re-pin 9+1
    // sources across 2 stems at 5 each → refill hole without moving existing
    // links → spread 8 more sources to 6-per-stem across 3 stems.
    let mut rng = SplitMix64::new(0xD2);
    let mut peers = ids(3);
    let mut m = StemMap::new(peers.clone(), 3, &mut rng);
    assert_eq!((m.live_stems(), m.slots().len()), (3, 3));
    assert_live_slots_subset_of(&m, &peers);

    assert_eq!(m.update(peers.clone(), &mut rng), StemSetChange::Unchanged);
    assert_eq!(m.live_stems(), 3);
    assert_live_slots_subset_of(&m, &peers);

    let mut sources = source_ids(9, 110);
    let mut mapping = std::collections::BTreeMap::new();
    let mut inverse: std::collections::BTreeMap<ConnectionId, Vec<ConnectionId>> =
        std::collections::BTreeMap::new();
    for s in &sources {
        let out = m.stem_for(Some(*s), &mut rng).expect("a stem is available");
        assert!(mapping.insert(*s, out).is_none());
        inverse.entry(out).or_default().push(*s);
    }
    let used = usage_by_stem(&mapping);
    assert_eq!(used.len(), 3);
    assert!(
        used.values().all(|c| *c == 3),
        "initial 3-per-stem: {used:?}"
    );
    for s in &sources {
        assert_eq!(m.stem_for(Some(*s), &mut rng), Some(mapping[s]));
    }

    // Drop middle stem with no spare → nil hole in place.
    let lost = m.slots()[1].expect("slot 1 live");
    peers.retain(|p| *p != lost);
    assert_eq!(m.update(peers.clone(), &mut rng), StemSetChange::Changed);
    assert_eq!(m.live_stems(), 2, "one slot is nil, not compacted");
    assert_eq!(m.slots().len(), 3, "span keeps the nil hole");
    assert_eq!(m.slots().iter().filter(|s| s.is_none()).count(), 1);
    if let Some(on_lost) = inverse.get(&lost) {
        for s in on_lost {
            // C++ marks these as nil expected until re-pin via get_stem.
            mapping.remove(s);
        }
    }

    // Remap the original 9 plus one new source across the two live stems.
    let extra = ConnectionId::from_bytes({
        let mut b = [0u8; 16];
        b[0] = 110;
        b[1] = 9;
        b
    });
    sources.push(extra);
    let mut used_two = std::collections::BTreeMap::new();
    for s in &sources {
        let out = m
            .stem_for(Some(*s), &mut rng)
            .expect("two live stems remain");
        match mapping.get(s) {
            Some(expected) => assert_eq!(
                out, *expected,
                "unaffected sources must keep their pin after the hole"
            ),
            None => {
                mapping.insert(*s, out);
            }
        }
        *used_two.entry(out).or_insert(0) += 1;
    }
    // **DIVERGENCE (same cost as `gtest_dropped_connection`).** The port
    // re-balanced the displaced sources to 5-per-stem by re-selecting on
    // least-used; a frozen walk sends each to its own alternate instead, so
    // the split follows where sources originally pinned rather than an even
    // spread. The invariant that survives is that every source is routed
    // exactly once, to a live stem.
    assert_eq!(
        used_two.values().sum::<usize>(),
        sources.len(),
        "all ten sources routed exactly once"
    );
    assert!(
        used_two
            .keys()
            .all(|p| m.slots().iter().flatten().any(|q| q == p)),
        "every routed peer is a live stem: {used_two:?}"
    );

    // Refill the hole with a third peer; existing links must not move.
    let fresh = ConnectionId::from_bytes([210u8; 16]);
    peers.push(fresh);
    assert_eq!(m.update(peers.clone(), &mut rng), StemSetChange::Changed);
    assert_eq!(m.live_stems(), 3);
    assert_eq!(m.slots().len(), 3);
    assert!(m.slots().iter().flatten().any(|s| *s == fresh));

    let mut used_after_refill = std::collections::BTreeMap::new();
    for s in &sources {
        let out = m
            .stem_for(Some(*s), &mut rng)
            .expect("still routable after refill");
        assert_eq!(
            out, mapping[s],
            "existing links stay put when a third peer fills the hole"
        );
        *used_after_refill.entry(out).or_insert(0) += 1;
    }
    assert_eq!(
        used_after_refill.len(),
        2,
        "refill must not steal existing pins onto the new stem"
    );
    assert_eq!(
        used_after_refill.values().sum::<usize>(),
        sources.len(),
        "still every source routed exactly once until new sources arrive"
    );

    // 8 more inbound sources → 18 total, even across 3 stems (6 each).
    let more = source_ids(8, 120);
    sources.extend(more);
    let mut used_three = std::collections::BTreeMap::new();
    for s in &sources {
        let out = m.stem_for(Some(*s), &mut rng).expect("three live stems");
        match mapping.get(s) {
            Some(expected) => assert_eq!(out, *expected),
            None => {
                mapping.insert(*s, out);
            }
        }
        *used_three.entry(out).or_insert(0) += 1;
    }
    assert_eq!(sources.len(), 18);
    assert_eq!(used_three.len(), 3);
    assert!(
        used_three.values().all(|c| *c == 6),
        "18 sources across 3 stems at 6 each: {used_three:?}"
    );
}

#[test]
fn gtest_dropped_all_connections() {
    // C++ `dandelionpp_map.dropped_all_connections` (net.cpp ~2097–2180):
    // 8 peers / 3 stems; 9 sources at 3-per-stem; drop everything (span
    // stays, live=0); first 7 sources re-pin to None; refill from a fresh
    // peer set; all 9 sources re-pin evenly (3-per-stem).
    let mut rng = SplitMix64::new(0xD3);
    let peers = ids(8);
    let mut m = StemMap::new(peers.clone(), 3, &mut rng);
    assert_eq!(m.live_stems(), 3);
    assert_eq!(m.slots().len(), 3);
    assert_live_slots_subset_of(&m, &peers);

    assert_eq!(m.update(peers.clone(), &mut rng), StemSetChange::Unchanged);
    assert_eq!(m.live_stems(), 3);
    assert_live_slots_subset_of(&m, &peers);

    let sources = source_ids(9, 130);
    let mut mapping = std::collections::BTreeMap::new();
    for s in &sources {
        let out = m.stem_for(Some(*s), &mut rng).expect("a stem is available");
        assert!(mapping.insert(*s, out).is_none());
    }
    let used = usage_by_stem(&mapping);
    assert_eq!(used.len(), 3);
    assert!(
        used.values().all(|c| *c == 3),
        "initial 3-per-stem: {used:?}"
    );
    for s in &sources {
        assert_eq!(m.stem_for(Some(*s), &mut rng), Some(mapping[s]));
    }

    assert_eq!(m.update(Vec::new(), &mut rng), StemSetChange::Changed);
    assert_eq!(m.live_stems(), 0, "no live stem remains");
    assert_eq!(m.slots().len(), 3, "the slots are nil, not removed");

    // C++ remaps only the first 7 while empty; the last two stay pinned to
    // dead slot indices until the refill (then resolve to the new peers in
    // those slots without a fresh select).
    for s in sources.iter().take(7) {
        assert_eq!(
            m.stem_for(Some(*s), &mut rng),
            None,
            "no routable stem must surface as None, not a stale peer"
        );
    }

    // Fresh peer set (C++: 30 new uuids); only stem-width matters for the
    // even-load assertion after re-pin.
    let refill = ids(30);
    assert_eq!(m.update(refill.clone(), &mut rng), StemSetChange::Changed);
    assert_eq!(m.live_stems(), 3);
    assert_live_slots_subset_of(&m, &refill);

    // **THE DIVERGENCE THAT COSTS SOMETHING, named plainly (RP-2b, W3c).**
    // Every peer this map ever held is gone, so every already-pinned source
    // has an exhausted frozen set and now **fluffs** where the port re-pinned
    // it onto the fresh peers. That is the availability half of the trade,
    // and it was chosen with a measurement rather than a preference: §19.3's
    // third arm allowed a fresh pin on exhaustion and its exposure tracked
    // the *unfixed* baseline (0.75 at k=8 against 0.17), because at
    // `STEMS = 2` a full sweep costs an adversary two churns and hands back
    // two fresh draws. An escape hatch here returns the whole amplifier, so
    // there is no partial version of this property to take.
    //
    // The cost is bounded in time: `rebuild_stems` re-draws every pin at the
    // epoch boundary, so an affected source fluffs for at most the remainder
    // of the epoch. How often honest churn reaches total turnover is the
    // ambient-rate measurement §12.11 still owes.
    for s in &sources {
        assert_eq!(
            m.stem_for(Some(*s), &mut rng),
            None,
            "a source whose entire frozen set churned out must fluff, not \
             re-pin onto peers that arrived after it pinned"
        );
    }
    // A source that had never pinned still routes: the freeze is per-source,
    // not a frozen map.
    let newcomer = ConnectionId::from_bytes([250u8; 16]);
    let out = m
        .stem_for(Some(newcomer), &mut rng)
        .expect("an unpinned source still routes through the refilled map");
    assert!(
        refill.contains(&out),
        "and it routes to a live, post-refill peer"
    );
    // The port's closing assertion here was "9 sources re-pin evenly across
    // 3 new stems". There are no re-pins to spread now — see above — so what
    // remains to check is that the refilled map is healthy for sources that
    // pin into it, which the newcomer above establishes.
    assert_eq!(m.live_stems(), 3, "the refilled map is fully live");
}
