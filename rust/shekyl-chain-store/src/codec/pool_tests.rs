// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool record's codec — DRS-E1 S-POOL as reshaped by DRS-E5 PR-b
//! (DX-F6; the review of #1102, S2 and S7; reorg retention deleted
//! 2026-10-17).
//!
//! The record round-trips public and not, the public byte refuses what it
//! does not name, the receive time is whole hours, and the layout carries
//! nothing the blob says.

use shekyl_store_codec::{Canonical, CodecError};
use shekyl_types::UnixSeconds;

use super::{PoolRecord, ReceivedHour};

fn record(public: bool) -> PoolRecord {
    PoolRecord {
        received: ReceivedHour::from_raw(472_222),
        public,
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

/// The public byte sits after the eight-byte receive hour.
const PUBLIC_AT: usize = 8;

#[test]
fn the_record_round_trips_public_and_not() {
    for public in [false, true] {
        round_trip(record(public));
    }
}

/// The record is the two facts the blob cannot say and nothing beside
/// them: 9 bytes. A weight, a fee, an anchor, a standing, a relay state or
/// a readiness cache would move the figure.
#[test]
fn the_layout_carries_nothing_the_blob_says() {
    assert_eq!(record(true).encode().len(), 9);
    assert_eq!(<PoolRecord as Canonical>::FIXED_WIDTH, Some(9));
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
    let mut bytes = record(false).encode();
    bytes[PUBLIC_AT] = 2;
    let err = PoolRecord::decode(&bytes).expect_err("public byte 2 refused");
    assert_eq!(reason(&err), "public byte is not 0 or 1");
}

#[test]
fn truncated_and_trailing_bytes_are_refused() {
    let full = record(true).encode();
    for cut in 0..full.len() {
        assert!(PoolRecord::decode(&full[..cut]).is_err(), "cut at {cut}");
    }
    let mut trailing = full;
    trailing.push(0);
    let err = PoolRecord::decode(&trailing).expect_err("trailing refused");
    assert_eq!(reason(&err), "trailing bytes after the pool record");
}
