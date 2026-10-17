// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool record's codec — DRS-E1 S-POOL as reshaped by DRS-E5 PR-b
//! (DX-F6; the review of #1102, S2 and S7).
//!
//! Every standing round-trips public and not, every closed byte refuses
//! what it does not name, a zeroed standing is not admitted, the receive
//! time is whole hours, and the layout carries nothing the blob says.

use shekyl_store_codec::{Canonical, CodecError};
use shekyl_types::{BlockHeight, UnixSeconds};

use super::{PoolRecord, ReceivedHour, Standing};

const KEPT: Standing = Standing::Kept {
    returned_at: BlockHeight::from_raw(61),
};

fn record(public: bool, standing: Standing) -> PoolRecord {
    PoolRecord {
        received: ReceivedHour::from_raw(472_222),
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

/// The public byte sits after the eight-byte receive hour; the standing
/// tag after it.
const PUBLIC_AT: usize = 8;
const STANDING_AT: usize = 9;

#[test]
fn every_standing_round_trips_public_and_not() {
    for public in [false, true] {
        round_trip(record(public, Standing::Admitted));
        round_trip(record(public, KEPT));
    }
}

/// The record is the three facts the blob cannot say and nothing beside
/// them: an admitted entry is 10 bytes, a kept one 18. A weight, a fee, an
/// anchor, a relay state or a readiness cache would move every figure.
#[test]
fn the_layout_carries_nothing_the_blob_says() {
    assert_eq!(record(true, Standing::Admitted).encode().len(), 10);
    assert_eq!(record(true, KEPT).encode().len(), 18);
}

/// The receive time is the hour a second falls in: two arrivals an hour
/// apart differ by one, two within one hour do not.
#[test]
fn the_receive_time_is_whole_hours() {
    let at = |s| ReceivedHour::of(UnixSeconds::from_raw(s));
    assert_eq!(at(0), ReceivedHour::from_raw(0));
    assert_eq!(at(3_599), ReceivedHour::from_raw(0));
    assert_eq!(at(3_600), ReceivedHour::from_raw(1));
    assert_eq!(at(1_700_000_000), at(1_700_000_000 + 1_000));
}

#[test]
fn the_public_byte_is_closed() {
    let mut bytes = record(false, KEPT).encode();
    bytes[PUBLIC_AT] = 2;
    let err = PoolRecord::decode(&bytes).expect_err("public byte 2 refused");
    assert_eq!(reason(&err), "public byte is not 0 or 1");
}

/// Zero is not a standing: a zeroed tag must not read as admitted.
#[test]
fn the_standing_tag_is_closed_and_zero_is_not_a_value() {
    for tag in [0_u8, 3, 0xff] {
        let mut bytes = record(true, Standing::Admitted).encode();
        bytes[STANDING_AT] = tag;
        let err = PoolRecord::decode(&bytes).expect_err("unknown standing refused");
        assert_eq!(reason(&err), "standing tag is not admitted or kept");
    }
}

#[test]
fn truncated_and_trailing_bytes_are_refused() {
    let full = record(true, KEPT).encode();
    for cut in 0..full.len() {
        assert!(PoolRecord::decode(&full[..cut]).is_err(), "cut at {cut}");
    }
    let mut trailing = full;
    trailing.push(0);
    let err = PoolRecord::decode(&trailing).expect_err("trailing refused");
    assert_eq!(reason(&err), "trailing bytes after the pool record");
}
