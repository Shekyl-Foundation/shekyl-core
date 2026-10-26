// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The learn ask is one per publication of the tip, not one per height.
//! Every test names the edit that turns it red.

use std::num::NonZeroUsize;
use std::sync::Arc;

use rand::rngs::StdRng;
use rand::SeedableRng;

use super::*;

const W: Window = Window {
    response: BlockCount::from_raw(500),
    reorg_cap: BlockCount::from_raw(720),
};

fn h() -> BlockHeight {
    BlockHeight::from_raw(100)
}

fn published(seq: u64) -> TipPublication {
    TipPublication::from_seq(seq)
}

/// A block of ours at height 100, still learning: the connector has not
/// answered.
fn learning() -> (Producer, Recorded) {
    let ring = Arc::new(WitnessRing::new());
    let producer = Producer::new(
        Arc::clone(&ring),
        Box::new(StdRng::seed_from_u64(1)),
        NonZeroUsize::MAX,
        crate::READ_START_SPREAD,
    );
    let commitment = ring.draw(h()).expect("draws");
    let recorded = Recorded {
        hash: BlockHash::from_bytes([0xA1; 32]),
        commitment,
    };
    (producer, recorded)
}

fn see(producer: &mut Producer, seq: u64, recorded: Option<Recorded>) -> Observed {
    let at = h();
    producer.observe(at, published(seq), W, move |height| {
        recorded.filter(|_| height == at)
    })
}

/// One publication asks once. A later wake on it — a read ending — does
/// not ask again. Red edit: ask on every wake — the second one asks.
#[test]
fn one_publication_asks_once() {
    let (mut producer, recorded) = learning();
    assert_eq!(see(&mut producer, 1, Some(recorded)).learn.len(), 1);
    assert!(
        see(&mut producer, 1, Some(recorded)).learn.is_empty(),
        "this publication already asked"
    );
}

/// The next publication of the same height asks again. That is an
/// unanswered block retried, and a pop the watch coalesced into the
/// restored tip. Red edit: key the ask on the height — the second
/// publication is silent.
#[test]
fn a_new_publication_of_the_same_height_asks_again() {
    let (mut producer, recorded) = learning();
    assert_eq!(see(&mut producer, 1, Some(recorded)).learn.len(), 1);
    assert_eq!(
        see(&mut producer, 2, Some(recorded)).learn.len(),
        1,
        "the next publication has not been asked"
    );
}

/// A pop this producer sees pauses the block. The publication that brings
/// it back asks again: the answer, if one came, was for a chain that did
/// not hold it. Red edit: skip a block asked on any earlier publication —
/// the return stays unlearned.
#[test]
fn a_seen_pop_asks_again_when_the_block_returns() {
    let (mut producer, recorded) = learning();
    assert_eq!(see(&mut producer, 1, Some(recorded)).learn.len(), 1);
    let popped = see(&mut producer, 2, None);
    assert!(popped.learn.is_empty(), "a popped block is not asked");
    assert!(popped.lost.is_empty(), "inside the reorg cap it waits");
    assert_eq!(
        see(&mut producer, 3, Some(recorded)).learn.len(),
        1,
        "the return is a chain the first ask did not read"
    );
}

/// A pop and the connect back that arrive as one publication of the same
/// height still ask. The producer never saw the block leave. Red edit:
/// key the ask on the height — the restored chain is silent.
#[test]
fn a_coalesced_pop_and_return_asks_on_the_new_publication() {
    let (mut producer, recorded) = learning();
    assert_eq!(see(&mut producer, 1, Some(recorded)).learn.len(), 1);
    assert_eq!(
        see(&mut producer, 4, Some(recorded)).learn.len(),
        1,
        "the restored tip is a new publication of the same height"
    );
}
