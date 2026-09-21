// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use core::convert::Infallible;

use shekyl_types::BlockHeight;

use super::*;

/// A source over a fixed list — what the fixture families are built from.
struct Scripted {
    events: std::vec::IntoIter<IngestEvent>,
    seq: SequenceNo,
}

impl Scripted {
    fn new(events: Vec<IngestEvent>) -> Self {
        Self {
            events: events.into_iter(),
            seq: SequenceNo::FIRST,
        }
    }
}

impl Source for Scripted {
    type Fault = Infallible;

    fn first_height(&self) -> BlockHeight {
        BlockHeight::ZERO
    }

    fn next(&mut self) -> Result<Option<Sequenced<IngestEvent>>, Infallible> {
        Ok(self.events.next().map(|event| {
            let seq = self.seq;
            self.seq = seq.next();
            Sequenced { seq, event }
        }))
    }
}

#[test]
fn sequence_numbers_strictly_increase_and_a_rewind_takes_one_too() {
    let mut source = Scripted::new(vec![
        IngestEvent::Rewind {
            to: BlockHeight::from_raw(3),
        },
        IngestEvent::Rewind {
            to: BlockHeight::from_raw(1),
        },
    ]);
    let first = source.next().expect("scripted").expect("one");
    let second = source.next().expect("scripted").expect("two");
    assert_eq!(first.seq, SequenceNo::FIRST);
    assert_eq!(second.seq, SequenceNo::FIRST.next());
    assert!(first.seq < second.seq, "total order");
    assert_eq!(source.next().expect("scripted"), None, "exhausted");
}

#[test]
fn only_a_rewind_is_a_barrier() {
    assert!(IngestEvent::Rewind {
        to: BlockHeight::ZERO
    }
    .is_barrier());
    // `Extend` is the other arm of the exhaustive match in `is_barrier`;
    // constructing a Candidate here would pin the complement at the cost of
    // a block fixture. The corpus round-trip asserts `!is_barrier` on every
    // Extend it yields.
}

#[test]
#[should_panic(expected = "ingest sequence space exhausted")]
fn a_sequence_number_does_not_wrap_or_saturate() {
    let next = SequenceNo(u64::MAX).next();
    panic!("next was {next:?} instead of panicking");
}
