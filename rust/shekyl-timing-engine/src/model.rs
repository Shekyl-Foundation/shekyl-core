// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A scanned list, obviously correct, run beside the heap.

use super::{
    Engine, EngineError, Generation, IdSource, ManualClock, OwnerClass, OwnerId, OwnerMint, Tick,
};
use proptest::prelude::*;
use std::collections::HashMap;

#[derive(Clone, Debug)]
enum Op {
    Register(u8),
    /// Register an id that is already live.
    RegisterDuplicate(u8),
    Arm {
        slot: u8,
        deadline: u32,
    },
    Clear(u8),
    Deregister(u8),
    Advance(u16),
    Poll,
    NoteHome(u8),
}

/// Live operations only. `Close` is applied once, after the sequence, so a
/// few hundred operations stay on registered owners instead of turning into
/// errors at the first close.
fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        2 => any::<u8>().prop_map(Op::Register),
        2 => any::<u8>().prop_map(Op::RegisterDuplicate),
        8 => (any::<u8>(), any::<u32>()).prop_map(|(slot, deadline)| Op::Arm {
            slot,
            deadline: deadline % 10_000,
        }),
        2 => any::<u8>().prop_map(Op::Clear),
        1 => any::<u8>().prop_map(Op::Deregister),
        4 => (1u16..500).prop_map(Op::Advance),
        4 => Just(Op::Poll),
        4 => any::<u8>().prop_map(Op::NoteHome),
    ]
}

/// Ordinary runs use 128 cases. `PROPTEST_CASES` replaces that number.
///
/// Set here, not left to [`ProptestConfig::default`]. That default reads the
/// variable once per process and caches the result.
fn proptest_config() -> ProptestConfig {
    ProptestConfig {
        cases: cases_from_env(),
        ..ProptestConfig::default()
    }
}

fn cases_from_env() -> u32 {
    match std::env::var("PROPTEST_CASES") {
        Ok(raw) => raw
            .parse()
            .unwrap_or_else(|_| panic!("PROPTEST_CASES must be a u32, got {raw}")),
        Err(std::env::VarError::NotPresent) => 128,
        Err(std::env::VarError::NotUnicode(_)) => panic!("PROPTEST_CASES is not Unicode"),
    }
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

    fn register(&mut self, id: u64, class: OwnerClass) -> Result<(), EngineError> {
        if self.closed {
            return Err(EngineError::Closed);
        }
        if self.owners.contains_key(&id) {
            return Err(EngineError::DuplicateOwner);
        }
        self.owners.insert(
            id,
            RefOwner {
                class,
                generation: 0,
                deadline: None,
                pending_generation: None,
                pending_fired: None,
            },
        );
        Ok(())
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
    #![proptest_config(proptest_config())]
    #[test]
    fn random_ops_match_a_scanned_reference(
        ops in prop::collection::vec(op_strategy(), 200..=400)
    ) {
        run(&ops);
    }
}

fn run(ops: &[Op]) {
    let mut engine = Engine::new(ManualClock::new(Tick::new(0)));
    let mut reference = Reference::new();
    let source = IdSource::new();
    let mut ids: Vec<OwnerId> = Vec::new();

    for op in ops {
        match *op {
            Op::Register(class) => {
                let class = OwnerClass::from_index(class);
                let minted = source.mint().expect("id space");
                let id = minted.id();
                let result = engine.register(minted, class);
                let expected = reference.register(id.0, class);
                assert_eq!(result, expected);
                if result.is_ok() {
                    ids.push(id);
                }
            }
            Op::RegisterDuplicate(slot) => {
                let Some(id) = registered(&ids, slot) else {
                    continue;
                };
                let result =
                    engine.register(OwnerMint::duplicate(&source, id), OwnerClass::Transport);
                let expected = reference.register(id.0, OwnerClass::Transport);
                assert_eq!(result, expected);
                assert_eq!(result.unwrap_err(), EngineError::DuplicateOwner);
            }
            Op::Arm { slot, deadline } => {
                let Some(id) = registered(&ids, slot) else {
                    continue;
                };
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
                let Some(id) = registered(&ids, slot) else {
                    continue;
                };
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
                let Some(index) = registered_index(&ids, slot) else {
                    continue;
                };
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
                let Some(id) = registered(&ids, slot) else {
                    continue;
                };
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
        }
        check(&mut engine, &reference);
    }
    engine.close();
    reference.closed = true;
    for owner in reference.owners.values_mut() {
        owner.deadline = None;
        owner.pending_generation = None;
        owner.pending_fired = None;
    }
    check(&mut engine, &reference);
}

/// Index of a currently registered owner. `slot` modulo that count.
///
/// An empty registry has no owner to name, so the operation is skipped
/// rather than aimed at an id that was never minted.
fn registered_index(ids: &[OwnerId], slot: u8) -> Option<usize> {
    let len = ids.len();
    if len == 0 {
        return None;
    }
    Some(usize::from(slot) % len)
}

fn registered(ids: &[OwnerId], slot: u8) -> Option<OwnerId> {
    registered_index(ids, slot).map(|index| ids[index])
}
