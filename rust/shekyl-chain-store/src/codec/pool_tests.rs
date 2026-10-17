// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool record's codec — DRS-E1 S-POOL as reshaped by DRS-E5 PR-b
//! (DX-F6).
//!
//! Every standing round-trips with and without M8's anchor, every closed
//! byte refuses what it does not name, a zeroed standing is not admitted,
//! and the layout carries no relay state.

use shekyl_store_codec::{Canonical, CodecError};
use shekyl_types::{BlockHash, BlockHeight, CurveTreeRoot, UnixSeconds};
use shekyl_units::AtomicUnits;

use super::{PoolRecord, ProvenReference, Standing};

fn proven() -> ProvenReference {
    ProvenReference {
        reference: BlockHash::from_bytes([0xab; 32]),
        height: BlockHeight::from_raw(61),
        root: CurveTreeRoot::from_bytes([0xc1; 32]),
    }
}

fn record(public: bool, standing: Standing) -> PoolRecord {
    PoolRecord {
        weight: 900,
        fee: AtomicUnits::from_raw(12_345),
        receive_time: UnixSeconds::from_raw(1_000),
        public,
        standing,
    }
}

fn round_trip(record: PoolRecord) {
    let back = PoolRecord::decode(&record.encode()).expect("decodes");
    assert_eq!(back, record);
}

fn reason(err: &CodecError) -> &'static str {
    match err {
        CodecError::Invalid { reason, .. } => reason,
        other => panic!("expected Invalid, got {other:?}"),
    }
}

/// The public byte sits after weight, fee and receive time, eight bytes
/// each; the standing tag after it.
const PUBLIC_AT: usize = 24;
const STANDING_AT: usize = 25;

#[test]
fn every_standing_round_trips_public_and_not() {
    for public in [false, true] {
        round_trip(record(public, Standing::Admitted { proven: None }));
        round_trip(record(
            public,
            Standing::Admitted {
                proven: Some(proven()),
            },
        ));
        round_trip(record(public, Standing::Kept));
    }
}

/// The record is the five facts and nothing beside them: a kept entry is
/// 26 bytes, an admitted one 27 without an anchor and 27 + 72 with one.
/// A relay state, a relayed flag, a double-spend bit or a readiness cache
/// would move every figure.
#[test]
fn the_layout_carries_no_relay_state() {
    assert_eq!(record(true, Standing::Kept).encode().len(), 26);
    assert_eq!(
        record(true, Standing::Admitted { proven: None })
            .encode()
            .len(),
        27
    );
    assert_eq!(
        record(
            true,
            Standing::Admitted {
                proven: Some(proven())
            }
        )
        .encode()
        .len(),
        27 + 32 + 8 + 32
    );
}

#[test]
fn the_anchor_is_the_validators_triple() {
    let verified = proven().verified();
    assert_eq!(verified.reference, proven().reference);
    assert_eq!(verified.claim.height, proven().height);
    assert_eq!(verified.claim.root, proven().root);
    assert_eq!(ProvenReference::of(verified), proven());
}

#[test]
fn the_public_byte_is_closed() {
    let mut bytes = record(false, Standing::Kept).encode();
    bytes[PUBLIC_AT] = 2;
    let err = PoolRecord::decode(&bytes).expect_err("public byte 2 refused");
    assert_eq!(reason(&err), "public byte is not 0 or 1");
}

/// Zero is not a standing: a zeroed tag must not read as admitted.
#[test]
fn the_standing_tag_is_closed_and_zero_is_not_a_value() {
    for tag in [0_u8, 3, 0xff] {
        let mut bytes = record(true, Standing::Kept).encode();
        bytes[STANDING_AT] = tag;
        let err = PoolRecord::decode(&bytes).expect_err("unknown standing refused");
        assert_eq!(
            reason(&err),
            "standing tag is not admitted or kept",
            "tag {tag}"
        );
    }
}

#[test]
fn the_anchor_presence_byte_is_closed() {
    let mut bytes = record(true, Standing::Admitted { proven: None }).encode();
    bytes[STANDING_AT + 1] = 2;
    let err = PoolRecord::decode(&bytes).expect_err("presence 2 refused");
    assert_eq!(reason(&err), "proven presence byte is not 0 or 1");
}

#[test]
fn truncated_and_trailing_bytes_are_refused() {
    let full = record(
        true,
        Standing::Admitted {
            proven: Some(proven()),
        },
    )
    .encode();
    for cut in 0..full.len() {
        assert!(PoolRecord::decode(&full[..cut]).is_err(), "cut at {cut}");
    }
    let mut trailing = full;
    trailing.push(0);
    let err = PoolRecord::decode(&trailing).expect_err("trailing refused");
    assert_eq!(reason(&err), "trailing bytes after the pool record");
}
