// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;

fn engine_at(now: u64) -> Engine<ManualClock> {
    Engine::new(ManualClock::new(Tick::new(now)))
}

fn ids() -> &'static IdSource {
    static IDS: std::sync::OnceLock<IdSource> = std::sync::OnceLock::new();
    IDS.get_or_init(IdSource::new)
}

fn owner(engine: &mut Engine<ManualClock>) -> OwnerId {
    let minted = ids().mint().expect("id space");
    let id = minted.id();
    engine.register(minted, OwnerClass::Housekeeping).unwrap();
    id
}

#[test]
fn a_future_hint_is_not_due() {
    let mut engine = engine_at(10);
    let id = owner(&mut engine);
    engine.arm(id, Tick::new(11)).unwrap();
    assert!(engine.poll().is_empty());
    assert_eq!(engine.next_deadline(), Some(Tick::new(11)));
}

#[test]
fn a_due_hint_is_handed_back_with_lateness() {
    let mut engine = engine_at(10);
    let id = owner(&mut engine);
    engine.arm(id, Tick::new(8)).unwrap();
    let wakes = engine.poll();
    assert_eq!(wakes.len(), 1);
    assert_eq!(wakes[0].deadline, Tick::new(8));
    assert_eq!(wakes[0].fired_at, Tick::new(10));
    let totals = engine.lateness(OwnerClass::Housekeeping);
    assert_eq!(totals.wake_delay, 2);
    assert_eq!(totals.fires, 1);
    assert_eq!(totals.max_wake_delay, 2);
    assert_eq!(totals.wake_buckets[lateness_bucket(2)], 1);
    assert_eq!(totals.wakes_at_least(2), 1);
    assert_eq!(totals.wakes_at_least(4), 0);
}

#[test]
fn a_later_arm_is_a_no_op() {
    let mut engine = engine_at(0);
    let id = owner(&mut engine);
    let first = engine.arm(id, Tick::new(5)).unwrap();
    let second = engine.arm(id, Tick::new(9)).unwrap();
    assert_eq!(first, second);
    assert_eq!(engine.heap.len(), 1);
    engine.clock_mut().set(Tick::new(5));
    assert_eq!(engine.poll()[0].deadline, Tick::new(5));
}

#[test]
fn rearming_earlier_fires_at_the_new_time() {
    let mut engine = engine_at(0);
    let id = owner(&mut engine);
    engine.arm(id, Tick::new(9)).unwrap();
    let earlier = engine.arm(id, Tick::new(4)).unwrap();
    assert_eq!(engine.next_deadline(), Some(Tick::new(4)));
    engine.clock_mut().set(Tick::new(4));
    let wakes = engine.poll();
    assert_eq!(wakes.len(), 1);
    assert_eq!(wakes[0].deadline, Tick::new(4));
    assert_eq!(wakes[0].generation, earlier);
}

#[test]
fn clear_removes_the_deadline() {
    let mut engine = engine_at(0);
    let id = owner(&mut engine);
    engine.arm(id, Tick::new(5)).unwrap();
    engine.clear(id).unwrap();
    assert_eq!(engine.next_deadline(), None);
    assert_eq!(engine.live, 0);
    engine.clock_mut().set(Tick::new(5));
    assert!(engine.poll().is_empty());
}

#[test]
fn two_owners_due_together_both_fire() {
    let mut engine = engine_at(0);
    let first = owner(&mut engine);
    let second = owner(&mut engine);
    engine.arm(first, Tick::new(10)).unwrap();
    engine.arm(second, Tick::new(10)).unwrap();
    engine.clock_mut().set(Tick::new(10));
    let wakes = engine.poll();
    assert_eq!(wakes.len(), 2);
    assert_eq!(wakes[0].owner, first);
    assert_eq!(wakes[1].owner, second);
}

#[test]
fn only_the_earliest_owner_fires() {
    let mut engine = engine_at(0);
    let mut ids = Vec::new();
    for i in 0..32 {
        let id = owner(&mut engine);
        engine.arm(id, Tick::new(100 + i)).unwrap();
        ids.push(id);
    }
    engine.clock_mut().set(Tick::new(100));
    let wakes = engine.poll();
    assert_eq!(wakes.len(), 1);
    assert_eq!(wakes[0].owner, ids[0]);
    assert_eq!(engine.live, 31);
}

#[test]
fn next_deadline_skips_a_stale_hint() {
    let mut engine = engine_at(0);
    let early = owner(&mut engine);
    let later = owner(&mut engine);
    engine.arm(early, Tick::new(3)).unwrap();
    engine.arm(later, Tick::new(8)).unwrap();
    engine.clear(early).unwrap();
    assert_eq!(engine.next_deadline(), Some(Tick::new(8)));
}

#[test]
fn deregister_drops_the_owner_and_its_pending_wake() {
    let mut engine = engine_at(0);
    let id = owner(&mut engine);
    engine.arm(id, Tick::new(4)).unwrap();
    engine.clock_mut().set(Tick::new(4));
    assert_eq!(engine.poll().len(), 1);
    assert_eq!(engine.pending_homes(), 1);
    engine.deregister(id).unwrap();
    assert_eq!(engine.pending_homes(), 0);
    assert_eq!(engine.next_deadline(), None);
    assert_eq!(
        engine.arm(id, Tick::new(5)).unwrap_err(),
        EngineError::UnknownOwner
    );
}

#[test]
fn a_second_wake_replaces_an_unreported_one() {
    let mut engine = engine_at(0);
    let id = owner(&mut engine);
    let first = engine.arm(id, Tick::new(1)).unwrap();
    engine.clock_mut().set(Tick::new(1));
    engine.poll();
    engine.arm(id, Tick::new(3)).unwrap();
    engine.clock_mut().set(Tick::new(3));
    let second = engine.poll()[0].generation;
    assert_eq!(engine.pending_homes(), 1);
    assert_eq!(engine.lateness(OwnerClass::Housekeeping).replaced_wakes, 1);
    assert_eq!(
        engine.note_home(id, first, Tick::new(3)).unwrap_err(),
        EngineError::NoSuchWake
    );
    engine.note_home(id, second, Tick::new(3)).unwrap();
    assert_eq!(engine.pending_homes(), 0);
}

#[test]
fn home_delay_matches_the_generation() {
    let mut engine = engine_at(10);
    let minted = ids().mint().expect("id space");
    let id = minted.id();
    engine.register(minted, OwnerClass::TimedSync).unwrap();
    let generation = engine.arm(id, Tick::new(10)).unwrap();
    let wake = engine.poll()[0];
    engine.note_home(id, generation, Tick::new(14)).unwrap();
    assert_eq!(wake.generation, generation);
    let totals = engine.lateness(OwnerClass::TimedSync);
    assert_eq!(totals.wake_delay, 0);
    assert_eq!(totals.home_delay, 4);
    assert_eq!(totals.home_buckets[lateness_bucket(4)], 1);
    assert_eq!(engine.pending_homes(), 0);
}

#[test]
fn repeated_fires_do_not_grow_a_sample_log() {
    let mut engine = engine_at(0);
    let id = owner(&mut engine);
    for n in 1..=64 {
        engine.arm(id, Tick::new(n)).unwrap();
        engine.clock_mut().set(Tick::new(n));
        let wake = engine.poll()[0];
        engine.note_home(id, wake.generation, Tick::new(n)).unwrap();
    }
    assert_eq!(engine.pending_homes(), 0);
    assert_eq!(engine.lateness(OwnerClass::Housekeeping).fires, 64);
    assert_eq!(engine.owners.len(), 1);
}

#[test]
fn a_partial_poll_compacts_hints_left_behind() {
    let mut engine = engine_at(0);
    for i in 0..3 {
        let id = owner(&mut engine);
        engine.arm(id, Tick::new(100 + i)).unwrap();
        engine.arm(id, Tick::new(10 + i)).unwrap();
    }
    engine.clock_mut().set(Tick::new(11));
    assert_eq!(engine.poll().len(), 2);
    assert_eq!(engine.live, 1);
    assert!(engine.heap.len() <= engine.live.saturating_mul(2).saturating_add(1));
    assert_eq!(engine.next_deadline(), Some(Tick::new(12)));
}

#[test]
fn rearming_earlier_compacts_stale_hints() {
    let mut engine = engine_at(0);
    let id = owner(&mut engine);
    for n in (1..=8).rev() {
        engine.arm(id, Tick::new(n)).unwrap();
    }
    assert!(engine.heap.len() <= 2);
    assert_eq!(engine.live, 1);
    assert_eq!(engine.next_deadline(), Some(Tick::new(1)));
}

#[test]
fn compaction_frees_the_capacity_stale_hints_occupied() {
    let mut engine = engine_at(0);
    let mut ids = Vec::new();
    for i in 0..64 {
        let id = owner(&mut engine);
        engine.arm(id, Tick::new(1_000 + i)).unwrap();
        ids.push(id);
    }
    for (i, id) in ids.iter().enumerate() {
        let earlier = 500 - u64::try_from(i).unwrap();
        engine.arm(*id, Tick::new(earlier)).unwrap();
    }
    engine.arm(ids[0], Tick::new(1)).unwrap();
    assert_eq!(engine.live, 64);
    assert_eq!(engine.heap.len(), engine.live);
    assert_eq!(engine.heap.capacity(), engine.live);
}

#[test]
fn a_closed_engine_drops_hints_and_refuses_arming() {
    let mut engine = engine_at(0);
    let id = owner(&mut engine);
    engine.arm(id, Tick::new(1)).unwrap();
    engine.close();
    engine.clock_mut().set(Tick::new(1));
    assert!(engine.poll().is_empty());
    assert_eq!(engine.next_deadline(), None);
    assert_eq!(
        engine
            .register(ids().mint().expect("id space"), OwnerClass::Relay)
            .unwrap_err(),
        EngineError::Closed
    );
    assert_eq!(
        engine.arm(id, Tick::new(2)).unwrap_err(),
        EngineError::Closed
    );
    assert_eq!(engine.clear(id).unwrap_err(), EngineError::Closed);
}

#[test]
fn register_refuses_an_id_that_is_already_live() {
    let mut engine = engine_at(0);
    let minted = ids().mint().expect("id space");
    let id = minted.id();
    engine.register(minted, OwnerClass::Relay).unwrap();
    assert_eq!(
        engine
            .register(OwnerMint::duplicate(id), OwnerClass::Transport)
            .unwrap_err(),
        EngineError::DuplicateOwner
    );
}

#[test]
fn a_stale_hint_does_not_fire_for_a_new_owner() {
    let mut engine = engine_at(0);
    let first = ids().mint().expect("id space");
    let second = ids().mint().expect("id space");
    let first_id = first.id();
    let second_id = second.id();
    engine.register(first, OwnerClass::Relay).unwrap();
    engine.register(second, OwnerClass::Transport).unwrap();
    engine.arm(first_id, Tick::new(10)).unwrap();
    engine.arm(second_id, Tick::new(20)).unwrap();
    engine.deregister(first_id).unwrap();
    engine.clock_mut().set(Tick::new(10));
    assert!(engine.poll().is_empty());
    engine.clock_mut().set(Tick::new(20));
    let wakes = engine.poll();
    assert_eq!(wakes.len(), 1);
    assert_eq!(wakes[0].owner, second_id);
    assert_eq!(wakes[0].deadline, Tick::new(20));
}

#[test]
fn mint_stops_before_the_counter_wraps() {
    let source = IdSource::with_next(u64::MAX);
    let last = source.mint().expect("the last id");
    assert_eq!(last.id(), OwnerId(u64::MAX));
    assert_eq!(source.mint().unwrap_err(), EngineError::IdsExhausted);
    assert_eq!(
        IdSource::with_next(0).mint().unwrap_err(),
        EngineError::IdsExhausted
    );
}

#[test]
fn a_closed_engine_reports_closed_before_duplicate() {
    let mut engine = engine_at(0);
    let id = owner(&mut engine);
    engine.close();
    assert_eq!(
        engine
            .register(OwnerMint::duplicate(id), OwnerClass::Relay)
            .unwrap_err(),
        EngineError::Closed
    );
}

#[test]
fn an_unknown_owner_is_refused() {
    let mut engine = engine_at(0);
    let err = engine.arm(OwnerId(99), Tick::new(1)).unwrap_err();
    assert_eq!(err, EngineError::UnknownOwner);
}

#[test]
fn the_monotonic_clock_does_not_go_backwards() {
    let clock = MonotonicClock::new();
    let first = clock.now();
    let second = clock.now();
    assert!(second >= first);
}
