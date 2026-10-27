// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Serving bodies: a body the byte budget defers is never read.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::convert::Infallible;

use shekyl_levin::{BODIES_RESPONSE_BYTES, HASH_SIZE};
use shekyl_types::BlockHash;
use shekyl_wire::BlockBody;

use super::answer_bodies;

/// A body that charges `bytes` against the budget.
fn body(bytes: usize) -> BlockBody {
    BlockBody {
        block: vec![0; bytes],
        txs: Vec::new(),
        attestation_witness: Vec::new(),
    }
}

fn hash(byte: u8) -> [u8; HASH_SIZE] {
    [byte; HASH_SIZE]
}

/// Five requested blocks, each a little over half the budget, the fourth
/// not held. The first is sent, the second is deferred, and from there
/// only presence is asked: the third and fifth are deferred and the
/// fourth missed without a body being read. The response keeps the plan's
/// order and its classification. (The synthetic bodies are not blocks, so
/// the requester's `check_form` is not run here; the loopback harness runs
/// it on a served response.)
#[test]
fn a_body_the_budget_defers_is_never_read() {
    let half = usize::try_from(BODIES_RESPONSE_BYTES).expect("fits") / 2 + 1;
    let requested = [hash(1), hash(2), hash(3), hash(4), hash(5)];
    let absent = hash(4);
    let read = RefCell::new(BTreeSet::new());
    let asked = RefCell::new(BTreeSet::new());
    let response = answer_bodies::<Infallible>(
        &requested,
        |id| {
            read.borrow_mut().insert(*id.as_bytes());
            Ok((*id.as_bytes() != absent).then(|| body(half)))
        },
        |id: BlockHash| {
            asked.borrow_mut().insert(*id.as_bytes());
            Ok(*id.as_bytes() != absent)
        },
    )
    .expect("infallible");
    assert_eq!(
        read.into_inner(),
        BTreeSet::from([hash(1), hash(2)]),
        "only bodies the budget could send are read"
    );
    assert_eq!(
        asked.into_inner(),
        BTreeSet::from([hash(3), hash(4), hash(5)])
    );
    assert_eq!(response.bodies.len(), 1);
    assert_eq!(response.deferred, vec![hash(2), hash(3), hash(5)]);
    assert_eq!(response.missed_ids, vec![absent]);
}

/// The first held body is sent whatever its size, and a missed hash
/// before it does not count as sent.
#[test]
fn the_first_held_body_is_sent_whatever_its_size() {
    let over = usize::try_from(BODIES_RESPONSE_BYTES).expect("fits") + 1;
    let requested = [hash(1), hash(2), hash(3)];
    let response = answer_bodies::<Infallible>(
        &requested,
        |id| Ok((*id.as_bytes() != hash(1)).then(|| body(over))),
        |id: BlockHash| Ok(*id.as_bytes() != hash(1)),
    )
    .expect("infallible");
    assert_eq!(response.bodies.len(), 1);
    assert_eq!(response.missed_ids, vec![hash(1)]);
    assert_eq!(response.deferred, vec![hash(3)]);
}
