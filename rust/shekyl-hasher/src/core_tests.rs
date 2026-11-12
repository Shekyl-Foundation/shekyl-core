// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The core's decisions, without caches: table tests named as properties,
//! and a property test over random event sequences.

use std::collections::BTreeSet;

use proptest::prelude::*;
use shekyl_hash_budget::Class;
use shekyl_pow_randomx::Seedhash;

use super::{Core, Decision, EntryState, LeaseId, Ticket, WarmRefused};
use crate::{Ranked, CAP};

fn s(n: u8) -> Seedhash {
    Seedhash::from_bytes([n; 32])
}

fn list(window: &[u8], third: Option<(u8, Class)>) -> Ranked {
    Ranked::new(
        s(window[0]),
        window.get(1).copied().map(s),
        third.map(|(seed, class)| (s(seed), class)),
    )
    .expect("distinct seeds")
}

/// The builder, driven by hand: claim, begin and finish every build the
/// core queues, in its order.
fn build_all(core: &mut Core) -> Vec<Decision> {
    let mut out = Vec::new();
    while let Some(claimed) = core.claim() {
        assert!(core.begin(claimed), "an uncontested claim begins");
        out.extend(core.built(claimed.0));
    }
    out
}

fn entries(core: &Core) -> BTreeSet<[u8; 32]> {
    core.entries.iter().map(|e| *e.seed.as_bytes()).collect()
}

fn seeds(of: &[u8]) -> BTreeSet<[u8; 32]> {
    of.iter().map(|n| *s(*n).as_bytes()).collect()
}

fn freed(out: &[Decision]) -> Vec<Seedhash> {
    out.iter()
        .filter_map(|d| match d {
            Decision::Free { seed } => Some(*seed),
            _ => None,
        })
        .collect()
}

fn request(core: &mut Core, seed: u8, class: Class) -> Ticket {
    core.request(s(seed), class).expect("open").0
}

/// Request, build what it needs, and take the grant.
fn granted(core: &mut Core, seed: u8, class: Class) -> LeaseId {
    let ticket = request(core, seed, class);
    build_all(core);
    core.take_grant(ticket).expect("granted once built")
}

#[test]
fn three_places_with_jobs_in_flight_and_a_fourth_job_waits() {
    let mut core = Core::default();
    core.rank(list(&[1], None));
    let a = granted(&mut core, 1, Class::Chain);
    let x = granted(&mut core, 10, Class::HeaderPow);
    let y = granted(&mut core, 11, Class::HeaderPow);
    assert_eq!(core.entries.len(), CAP);
    let z = request(&mut core, 12, Class::Chain);
    build_all(&mut core);
    assert_eq!(core.take_grant(z), None, "a fourth seed waits for a place");
    assert_eq!(core.fifo.front(), Some(&z));
    core.returned(x);
    build_all(&mut core);
    assert!(
        core.take_grant(z).is_some(),
        "the returned place goes to it"
    );
    assert!(core.entries.len() <= CAP);
    assert_ne!(a, y);
}

/// HA-R8: an evidence check waits for one job's remainder, not the stream
/// of header proofs behind it.
#[test]
fn evidence_waits_behind_exactly_one_header_proof_job_not_the_stream_behind_it() {
    let mut core = Core::default();
    core.rank(list(&[1, 2], None));
    build_all(&mut core);
    let first = granted(&mut core, 10, Class::HeaderPow);
    let evidence = request(&mut core, 20, Class::Evidence);
    let stream: Vec<Ticket> = (0..5)
        .map(|_| request(&mut core, 10, Class::HeaderPow))
        .collect();
    build_all(&mut core);
    assert_eq!(core.take_grant(evidence), None);
    for ticket in &stream {
        assert_eq!(
            core.take_grant(*ticket),
            None,
            "a resident seed does not pass a waiter"
        );
    }
    core.returned(first);
    build_all(&mut core);
    assert!(core.take_grant(evidence).is_some(), "evidence is next");
    for ticket in &stream {
        assert_eq!(core.take_grant(*ticket), None, "the stream waits behind it");
    }
}

/// HA-R7: outside jobs share the places the window leaves; neither frees a
/// window seed.
#[test]
fn two_outside_jobs_while_the_window_names_two_seeds_free_no_window_seed() {
    let mut core = Core::default();
    core.rank(list(&[1, 2], None));
    build_all(&mut core);
    let x = core.request(s(10), Class::Evidence).expect("open");
    let y = core.request(s(11), Class::HeaderPow).expect("open");
    let mut out = x.1;
    out.extend(y.1);
    out.extend(build_all(&mut core));
    assert!(freed(&out).is_empty(), "no window seed freed: {out:?}");
    assert!(core.take_grant(x.0).is_some());
    assert_eq!(
        core.take_grant(y.0),
        None,
        "one outside place: the second waits"
    );
    assert_eq!(entries(&core), seeds(&[1, 2, 10]));
}

#[test]
fn a_list_that_grows_while_outside_leases_are_out_holds_the_place_for_the_window() {
    let mut core = Core::default();
    core.rank(list(&[1], None));
    build_all(&mut core);
    let x = granted(&mut core, 10, Class::HeaderPow);
    let y = granted(&mut core, 11, Class::HeaderPow);
    core.rank(list(&[1, 2], None));
    assert!(
        core.window_short(),
        "three places held, the new window seed waits"
    );
    let z = request(&mut core, 12, Class::Chain);
    build_all(&mut core);
    assert_eq!(core.take_grant(z), None);
    core.returned(x);
    assert!(
        core.entry(&s(2)).is_some() && core.entry(&s(12)).is_none(),
        "the first return goes to the window seed, not the outside job"
    );
    build_all(&mut core);
    assert_eq!(core.take_grant(z), None, "z still waits for y");
    core.returned(y);
    build_all(&mut core);
    assert!(core.take_grant(z).is_some());
}

/// HA-R3 and §5.4: evidence pushes out the warm third, and the third's
/// refill is paid at the evidence class, not the third's own.
#[test]
fn evidence_while_the_third_is_warm_frees_it_and_the_refill_is_paid_at_evidence() {
    let mut core = Core::default();
    core.rank(list(&[1, 2], Some((3, Class::HeaderPow))));
    build_all(&mut core);
    assert_eq!(entries(&core), seeds(&[1, 2, 3]));
    let ticket = request(&mut core, 20, Class::Evidence);
    assert!(
        core.entry(&s(3)).is_none(),
        "the warm third gives its place"
    );
    build_all(&mut core);
    let lease = core.take_grant(ticket).expect("granted");
    core.returned(lease);
    assert_eq!(core.claim(), Some((s(3), Class::Evidence)));
}

#[test]
fn a_refill_whose_class_rises_wakes_the_builder_and_is_claimed_at_the_new_class() {
    let mut core = Core::default();
    core.rank(list(&[1, 2], Some((3, Class::Evidence))));
    // The window first, by rank.
    for _ in 0..2 {
        let claimed = core.claim().expect("a window build");
        assert!(core.begin(claimed));
        core.built(claimed.0);
    }
    assert_eq!(core.claim(), Some((s(3), Class::Evidence)));
    let (_, out) = core.request(s(3), Class::Chain).expect("open");
    assert!(out.contains(&Decision::WakeBuilder), "{out:?}");
    assert!(
        !core.begin((s(3), Class::Evidence)),
        "the low-class permit is refused"
    );
    assert_eq!(core.claim(), Some((s(3), Class::Chain)));
}

#[test]
fn warm_only_declines_an_unlisted_a_building_or_a_contested_third_seed() {
    let mut core = Core::default();
    core.rank(list(&[1, 2], Some((3, Class::HeaderPow))));
    assert_eq!(
        core.request_warm(s(1)),
        Err(WarmRefused::NotWarm),
        "still building"
    );
    build_all(&mut core);
    assert!(core.request_warm(s(1)).is_ok(), "a warm window seed");
    assert_eq!(
        core.request_warm(s(9)),
        Err(WarmRefused::NotWarm),
        "unlisted"
    );
    let x = granted(&mut core, 10, Class::HeaderPow);
    let _waiting = request(&mut core, 11, Class::Evidence);
    assert_eq!(
        core.request_warm(s(3)),
        Err(WarmRefused::NotWarm),
        "the third while a job waits for a place"
    );
    core.returned(x);
}

#[test]
fn a_warm_lease_is_cancelled_when_its_seed_leaves_the_list_and_freed_on_return() {
    let mut core = Core::default();
    core.rank(list(&[1], None));
    build_all(&mut core);
    let lease = core.request_warm(s(1)).expect("warm");
    let out = core.rank(list(&[2], None));
    assert!(out.contains(&Decision::Cancel { lease }), "{out:?}");
    assert!(core.entry(&s(1)).is_some(), "the in-flight hash keeps it");
    let out = core.returned(lease);
    assert_eq!(freed(&out), vec![s(1)]);
}

#[test]
fn a_second_job_on_a_resident_seed_schedules_no_build() {
    let mut core = Core::default();
    core.rank(list(&[1], None));
    build_all(&mut core);
    let (ticket, out) = core.request(s(1), Class::Chain).expect("open");
    assert!(
        !out.iter().any(|d| matches!(d, Decision::Schedule { .. })),
        "{out:?}"
    );
    assert!(core.take_grant(ticket).is_some());
}

#[test]
fn a_stopped_waiter_leaves_and_the_next_head_is_granted() {
    let mut core = Core::default();
    core.rank(list(&[1, 2], None));
    build_all(&mut core);
    let x = granted(&mut core, 10, Class::HeaderPow);
    let first = request(&mut core, 11, Class::Evidence);
    let second = request(&mut core, 12, Class::Evidence);
    core.leave(first);
    core.returned(x);
    build_all(&mut core);
    assert!(core.take_grant(second).is_some());
}

// ----- the property test --------------------------------------------------

#[derive(Clone, Debug)]
enum Op {
    Rank(Vec<u8>, Option<(u8, Class)>),
    Request(u8, Class),
    Warm(u8),
    Return(usize),
    Leave(usize),
    Claim,
    Begin,
    Built,
}

fn class() -> impl Strategy<Value = Class> {
    prop::sample::select(Class::ALL.to_vec())
}

fn op() -> impl Strategy<Value = Op> {
    let seed = 0u8..6;
    prop_oneof![
        1 => (prop::collection::vec(0u8..6, 1..=2), prop::option::of((0u8..6, class())))
            .prop_map(|(w, t)| Op::Rank(w, t)),
        4 => (seed.clone(), class()).prop_map(|(s, c)| Op::Request(s, c)),
        1 => seed.prop_map(Op::Warm),
        3 => any::<usize>().prop_map(Op::Return),
        1 => any::<usize>().prop_map(Op::Leave),
        2 => Just(Op::Claim),
        2 => Just(Op::Begin),
        2 => Just(Op::Built),
    ]
}

#[derive(Default)]
struct World {
    core: Core,
    pending: Vec<Ticket>,
    left: BTreeSet<Ticket>,
    held: Vec<LeaseId>,
    claimed: Option<(Seedhash, Class)>,
    deriving: Option<Seedhash>,
}

impl World {
    fn take_grants(&mut self) {
        let core = &mut self.core;
        let mut still = Vec::new();
        for ticket in std::mem::take(&mut self.pending) {
            match core.take_grant(ticket) {
                Some(lease) => self.held.push(lease),
                None => still.push(ticket),
            }
        }
        self.pending = still;
    }

    fn quiet(&self) -> bool {
        self.core.waiters.is_empty()
            && self.core.leases.is_empty()
            && self
                .core
                .entries
                .iter()
                .all(|e| e.state == EntryState::Resident)
    }
}

/// Run `op`; return its decisions, or `None` when it was not applicable.
fn apply(world: &mut World, op: &Op) -> Option<Vec<Decision>> {
    let out = match op {
        Op::Rank(window, third) => {
            let mut window = window.clone();
            window.dedup();
            let ranked = Ranked::new(
                s(window[0]),
                window.get(1).copied().map(s),
                third.map(|(seed, class)| (s(seed), class)),
            )
            .ok()?;
            world.core.rank(ranked)
        }
        Op::Request(seed, class) => {
            let (ticket, out) = world.core.request(s(*seed), *class)?;
            world.pending.push(ticket);
            out
        }
        Op::Warm(seed) => {
            let before = world.core.entries.len();
            if let Ok(lease) = world.core.request_warm(s(*seed)) {
                world.held.push(lease);
            }
            assert_eq!(
                world.core.entries.len(),
                before,
                "I5: warm-only schedules no build"
            );
            Vec::new()
        }
        Op::Return(pick) => {
            if world.held.is_empty() {
                return None;
            }
            let lease = world.held.swap_remove(pick % world.held.len());
            world.core.returned(lease)
        }
        Op::Leave(pick) => {
            if world.pending.is_empty() {
                return None;
            }
            let ticket = world.pending.swap_remove(pick % world.pending.len());
            world.left.insert(ticket);
            world.core.leave(ticket)
        }
        Op::Claim => {
            if world.deriving.is_some() {
                return None;
            }
            world.claimed = world.core.claim();
            Vec::new()
        }
        Op::Begin => {
            let claimed = world.claimed.take()?;
            if world.core.begin(claimed) {
                world.deriving = Some(claimed.0);
            }
            Vec::new()
        }
        Op::Built => {
            let seed = world.deriving.take()?;
            world.core.built(seed)
        }
    };
    world.take_grants();
    Some(out)
}

fn check(world: &World, op: &Op, before: &Core, out: &[Decision]) {
    let core = &world.core;
    // I1: the cap, a build in progress counted.
    assert!(
        core.entries.len() <= CAP,
        "I1: {} entries",
        core.entries.len()
    );
    // I6: one entry per seed.
    let unique: BTreeSet<[u8; 32]> = entries(core);
    assert_eq!(
        unique.len(),
        core.entries.len(),
        "I6: two entries for one seed"
    );
    for decision in out {
        if let Decision::Free { seed } = decision {
            // I2: a window seed is never freed while the hasher is open.
            assert!(!core.in_window(seed), "I2: freed window seed {seed}");
            // I4: nothing freed with a lease on it.
            assert_eq!(core.leases_on(seed), 0, "I4: freed {seed} with a lease");
        }
    }
    // I6: a resident seed that was not freed is not rebuilt.
    for entry in &before.entries {
        let was_freed = out.contains(&Decision::Free { seed: entry.seed });
        if entry.state == EntryState::Resident && !was_freed {
            if let Some(now) = core.entry(&entry.seed) {
                assert_eq!(
                    now.state,
                    EntryState::Resident,
                    "I6: {} rebuilt",
                    entry.seed
                );
            }
        }
    }
    // I3: outside jobs leave the queue in arrival order. A stop or a list
    // change may take one from the middle; only the head is ever granted.
    if !matches!(op, Op::Rank(..) | Op::Leave(_)) {
        let after: BTreeSet<Ticket> = core.fifo.iter().copied().collect();
        let mut gone = before.fifo.iter().map(|t| after.contains(t));
        // Once a ticket stays, every later ticket stays.
        let mut kept = false;
        for stays in &mut gone {
            if stays {
                kept = true;
            } else {
                assert!(
                    !kept,
                    "I3: a ticket left the queue ahead of one in front of it"
                );
            }
        }
    }
}

/// Finish every build and return every lease until nothing is left to do.
fn drain(world: &mut World) {
    for _ in 0..10_000 {
        if let Some(seed) = world.deriving.take() {
            world.core.built(seed);
        }
        if let Some(claimed) = world.claimed.take() {
            if world.core.begin(claimed) {
                world.deriving = Some(claimed.0);
                continue;
            }
        }
        world.take_grants();
        if let Some(lease) = world.held.pop() {
            world.core.returned(lease);
            continue;
        }
        if let Some(claimed) = world.core.claim() {
            world.claimed = Some(claimed);
            continue;
        }
        world.take_grants();
        if world.held.is_empty() && world.claimed.is_none() && world.deriving.is_none() {
            return;
        }
    }
    panic!("the drain did not settle");
}

fn listed(core: &Core) -> BTreeSet<[u8; 32]> {
    let mut seeds: BTreeSet<[u8; 32]> = core.window().iter().map(|s| *s.as_bytes()).collect();
    if let Some((third, _)) = core.third() {
        seeds.insert(*third.as_bytes());
    }
    seeds
}

fn fresh_quiet(list: &Ranked) -> BTreeSet<[u8; 32]> {
    let mut core = Core::default();
    core.rank(list.clone());
    build_all(&mut core);
    entries(&core)
}

proptest! {
    #[test]
    fn random_sequences_hold_the_invariants_quiesce_to_the_list_and_grant_every_request(
        ops in prop::collection::vec(op(), 1..80)
    ) {
        let mut world = World::default();
        for op in &ops {
            let before = Core {
                list: world.core.list.clone(),
                entries: world.core.entries.clone(),
                waiters: world.core.waiters.clone(),
                fifo: world.core.fifo.clone(),
                leases: world.core.leases.clone(),
                ..Core::default()
            };
            let Some(out) = apply(&mut world, op) else { continue };
            check(&world, op, &before, &out);
            // HA-R5: at quiescence the entries are the list, and a fresh
            // core fed the same list reaches the same entries.
            if world.quiet() && world.claimed.is_none() && world.deriving.is_none() {
                if let Some(list) = world.core.list.clone() {
                    prop_assert_eq!(entries(&world.core), listed(&world.core));
                    prop_assert_eq!(entries(&world.core), fresh_quiet(&list));
                }
            }
        }
        // Liveness: draining grants every request that did not stop.
        drain(&mut world);
        prop_assert!(world.pending.is_empty(), "never granted: {:?}", world.pending);
        prop_assert!(world.core.waiters.is_empty());
        if let Some(list) = world.core.list.clone() {
            prop_assert_eq!(entries(&world.core), fresh_quiet(&list));
        }
    }
}
