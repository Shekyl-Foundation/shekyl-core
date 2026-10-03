// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use core::convert::Infallible;

use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch, ShardId};

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

fn credit(tag: u8) -> ServeCredit {
    ServeCredit {
        persona: PCanonicalId::from_bytes([tag; 32]),
        shard: ShardId::from_raw(3),
        epoch: SettlementEpoch::from_raw(2),
    }
}

#[test]
fn a_rewind_and_an_inject_are_barriers() {
    assert!(IngestEvent::Rewind {
        to: BlockHeight::ZERO
    }
    .is_barrier());
    assert!(IngestEvent::Inject(credit(0xA1)).is_barrier());
    // `Extend` is the other arm of the exhaustive match in `is_barrier`;
    // constructing a Candidate here would pin the complement at the cost of
    // a block fixture. The corpus round-trip asserts `!is_barrier` on every
    // Extend it yields.
}

/// One spelling for the three carriers (DRS-E4 §3.8 item 3): the flag the
/// fetch takes, the report row, and the manifest's JSON string are the
/// same bytes, and every field is required — a defaulted height is the
/// ARW-26 class.
#[test]
fn an_injection_has_one_spelling_and_every_field_is_required() {
    let injection = Injection {
        at: BlockHeight::from_raw(41),
        credit: credit(0xAB),
    };
    let spelled = injection.to_string();
    assert_eq!(spelled, format!("{}:3:2@41", "ab".repeat(32)));
    assert_eq!(
        spelled.parse::<Injection>(),
        Ok(injection),
        "Display round-trips"
    );
    assert_eq!(
        spelled.to_uppercase().parse::<Injection>(),
        Ok(injection),
        "hex case is not a second spelling"
    );

    let json = serde_json::to_string(&injection).expect("serialises");
    assert_eq!(
        json,
        format!("\"{spelled}\""),
        "JSON is the spelling as a string"
    );
    assert_eq!(
        serde_json::from_str::<Injection>(&json).expect("deserialises"),
        injection
    );
    assert!(
        serde_json::from_str::<Injection>(r#"{"at":41}"#).is_err(),
        "no field-wise encoding whose height could be filled from a different read"
    );

    let hex = "ab".repeat(32);
    for (spelled, expected) in [
        (format!("{hex}:3:2"), InjectionParseError::Shape),
        (format!("{hex}:3@41"), InjectionParseError::Shape),
        (format!("{hex}:3:2:9@41"), InjectionParseError::Shape),
        (
            format!("{}:3:2@41", "ab".repeat(31)),
            InjectionParseError::Persona,
        ),
        (
            format!("{}zz:3:2@41", "ab".repeat(31)),
            InjectionParseError::Persona,
        ),
        (
            format!("{hex}:x:2@41"),
            InjectionParseError::Number { what: "shard" },
        ),
        (
            format!("{hex}:3:-1@41"),
            InjectionParseError::Number { what: "epoch" },
        ),
        (
            format!("{hex}:3:2@"),
            InjectionParseError::Number { what: "height" },
        ),
    ] {
        assert_eq!(spelled.parse::<Injection>(), Err(expected), "{spelled}");
    }
}

#[test]
#[should_panic(expected = "ingest sequence space exhausted")]
fn a_sequence_number_does_not_wrap_or_saturate() {
    let next = SequenceNo(u64::MAX).next();
    panic!("next was {next:?} instead of panicking");
}
