// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A scanned list, obviously correct, run beside the heap.

use super::{Engine, EngineError, Generation, ManualClock, OwnerClass, OwnerId, Tick};
use proptest::prelude::*;
use std::collections::HashMap;

#[derive(Clone, Debug)]
enum Op {
    Register(u8),
    Arm { slot: u8, deadline: u32 },
    Clear(u8),
    Deregister(u8),
    Advance(u16),
    Poll,
    NoteHome(u8),
    Close,
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        any::<u8>().prop_map(Op::Register),
        (any::<u8>(), any::<u32>()).prop_map(|(slot, deadline)| Op::Arm {
            slot,
            deadline: deadline % 10_000,
        }),
        any::<u8>().prop_map(Op::Clear),
        any::<u8>().prop_map(Op::Deregister),
        (1u16..500).prop_map(Op::Advance),
        Just(Op::Poll),
        any::<u8>().prop_map(Op::NoteHome),
        Just(Op::Close),
    ]
}

struct RefOwner {
    class: OwnerClass,
    generation: u64,
    deadline: Option<u64>,
    pending_generation: Option<u64>,
    pending_fired: Option<u64>,
}

struct Reference {
    now: u64,
    closed: bool,
    owners: HashMap<u64, RefOwner>,
}

impl Reference {
    fn new() -> Self {
        Self {
            now: 0,
            closed: false,
            owners: HashMap::new(),
        }
    }

    fn live_count(&self) -> usize {
        self.owners
            .values()
            .filter(|owner| owner.deadline.is_some())
            .count()
    }

    fn next_deadline(&self) -> Option<u64> {
        if self.closed {
            return None;
        }
        self.owners
            .values()
            .filter_map(|owner| owner.deadline)
            .min()
    }

    /// Due hints, earliest deadline first, then oldest owner.
    fn due(&mut self) -> Vec<(u64, OwnerClass, u64, u64)> {
        if self.closed {
            return Vec::new();
        }
        let mut due: Vec<(u64, u64, OwnerClass, u64)> = self
            .owners
            .iter()
            .filter_map(|(&id, owner)| {
                let deadline = owner.deadline?;
                (deadline <= self.now).then_some((deadline, id, owner.class, owner.generation))
            })
            .collect();
        due.sort_by_key(|(deadline, id, _, _)| (*deadline, *id));
        for (_, id, _, generation) in &due {
            let owner = self.owners.get_mut(id).expect("due owner");
            owner.deadline = None;
            owner.pending_generation = Some(*generation);
            owner.pending_fired = Some(self.now);
        }
        due.into_iter()
            .map(|(deadline, id, class, generation)| (id, class, generation, deadline))
            .collect()
    }
}

fn check(engine: &mut Engine<ManualClock>, reference: &Reference) {
    assert_eq!(
        engine.next_deadline().map(Tick::get),
        reference.next_deadline()
    );
    assert!(engine.heap.len() <= engine.live.saturating_mul(2).saturating_add(1));
    assert_eq!(engine.live, reference.live_count());
    if reference.closed {
        assert!(engine.poll().is_empty());
        assert_eq!(engine.next_deadline(), None);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn random_ops_match_a_scanned_reference(
        ops in prop::collection::vec(op_strategy(), 1..48)
    ) {
        run(&ops);
    }
}

fn run(ops: &[Op]) {
    let mut engine = Engine::new(ManualClock::new(Tick::new(0)));
    let mut reference = Reference::new();
    let mut ids: Vec<OwnerId> = Vec::new();

    for op in ops {
        match *op {
            Op::Register(class) => {
                let class = OwnerClass::from_index(class);
                let result = engine.register(class);
                if reference.closed {
                    assert_eq!(result.unwrap_err(), EngineError::Closed);
                } else {
                    let id = result.unwrap();
                    reference.owners.insert(
                        id.0,
                        RefOwner {
                            class,
                            generation: 0,
                            deadline: None,
                            pending_generation: None,
                            pending_fired: None,
                        },
                    );
                    ids.push(id);
                }
            }
            Op::Arm { slot, deadline } => {
                if ids.is_empty() {
                    continue;
                }
                let id = ids[usize::from(slot) % ids.len()];
                let result = engine.arm(id, Tick::new(u64::from(deadline)));
                let owner = reference.owners.get_mut(&id.0).expect("registered");
                if reference.closed {
                    assert_eq!(result.unwrap_err(), EngineError::Closed);
                } else if let Some(current) = owner.deadline {
                    if u64::from(deadline) >= current {
                        assert_eq!(result.unwrap(), Generation(owner.generation));
                    } else {
                        owner.generation = owner.generation.saturating_add(1);
                        owner.deadline = Some(u64::from(deadline));
                        assert_eq!(result.unwrap(), Generation(owner.generation));
                    }
                } else {
                    owner.generation = owner.generation.saturating_add(1);
                    owner.deadline = Some(u64::from(deadline));
                    assert_eq!(result.unwrap(), Generation(owner.generation));
                }
            }
            Op::Clear(slot) => {
                if ids.is_empty() {
                    continue;
                }
                let id = ids[usize::from(slot) % ids.len()];
                let result = engine.clear(id);
                if reference.closed {
                    assert_eq!(result.unwrap_err(), EngineError::Closed);
                } else {
                    result.unwrap();
                    let owner = reference.owners.get_mut(&id.0).expect("registered");
                    if owner.deadline.is_some() {
                        owner.generation = owner.generation.saturating_add(1);
                        owner.deadline = None;
                    }
                }
            }
            Op::Deregister(slot) => {
                if ids.is_empty() {
                    continue;
                }
                let index = usize::from(slot) % ids.len();
                let id = ids.remove(index);
                engine.deregister(id).unwrap();
                reference.owners.remove(&id.0);
            }
            Op::Advance(by) => {
                reference.now = reference.now.saturating_add(u64::from(by));
                engine.clock_mut().set(Tick::new(reference.now));
            }
            Op::Poll => {
                let wakes = engine.poll();
                let expected = reference.due();
                assert_eq!(wakes.len(), expected.len());
                for (wake, (id, class, generation, deadline)) in wakes.iter().zip(expected) {
                    assert_eq!(wake.owner.0, id);
                    assert_eq!(wake.class, class);
                    assert_eq!(wake.generation.get(), generation);
                    assert_eq!(wake.deadline.get(), deadline);
                    assert!(wake.deadline.get() <= reference.now);
                    assert_eq!(wake.fired_at.get(), reference.now);
                }
            }
            Op::NoteHome(slot) => {
                if ids.is_empty() {
                    continue;
                }
                let id = ids[usize::from(slot) % ids.len()];
                let owner = reference.owners.get_mut(&id.0).expect("registered");
                let result = match (owner.pending_generation, owner.pending_fired) {
                    (Some(generation), Some(_)) => {
                        engine.note_home(id, Generation(generation), Tick::new(reference.now))
                    }
                    _ => engine.note_home(id, Generation(0), Tick::new(reference.now)),
                };
                match (owner.pending_generation, owner.pending_fired) {
                    (Some(_), Some(fired)) if reference.now < fired => {
                        assert_eq!(result.unwrap_err(), EngineError::HomeBeforeFire);
                    }
                    (Some(_), Some(_)) => {
                        result.unwrap();
                        owner.pending_generation = None;
                        owner.pending_fired = None;
                    }
                    _ => {
                        assert_eq!(result.unwrap_err(), EngineError::NoSuchWake);
                    }
                }
            }
            Op::Close => {
                engine.close();
                reference.closed = true;
                for owner in reference.owners.values_mut() {
                    owner.deadline = None;
                    owner.pending_generation = None;
                    owner.pending_fired = None;
                }
            }
        }
        check(&mut engine, &reference);
    }
}
