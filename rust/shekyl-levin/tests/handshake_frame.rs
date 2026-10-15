// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The first complete Levin frame, as the transport's gap reads it
//! (Rick, 2026-10-14): the header and the body it declares, however the
//! bytes are split across reads.

use shekyl_levin::{BucketHead, FirstFrame, Flags, HEADER_SIZE, PROTOCOL_VERSION_1};

fn frame(body: usize) -> Vec<u8> {
    let head = BucketHead {
        payload_len: u64::try_from(body).expect("small"),
        expect_response: 1,
        command: 1001,
        flags: Flags::REQUEST,
        protocol_version: PROTOCOL_VERSION_1,
    };
    let mut out = head.write().to_vec();
    out.extend(std::iter::repeat_n(7u8, body));
    out
}

#[test]
fn a_frame_in_one_read_completes() {
    let mut first = FirstFrame::new();
    assert!(first.feed(&frame(40)));
    assert!(first.complete());
}

#[test]
fn a_frame_split_byte_by_byte_completes_on_its_last_byte() {
    let bytes = frame(40);
    let mut first = FirstFrame::new();
    for (i, byte) in bytes.iter().enumerate() {
        let done = first.feed(std::slice::from_ref(byte));
        assert_eq!(done, i + 1 == bytes.len(), "byte {i}");
    }
}

#[test]
fn part_of_a_frame_is_not_a_frame() {
    let bytes = frame(40);
    let mut first = FirstFrame::new();
    assert!(!first.feed(&bytes[..HEADER_SIZE - 1]));
    assert!(!first.feed(&bytes[HEADER_SIZE - 1..HEADER_SIZE + 10]));
    assert!(!first.complete());
}

#[test]
fn a_header_with_no_body_is_a_frame() {
    let mut first = FirstFrame::new();
    assert!(first.feed(&frame(0)));
}

#[test]
fn once_complete_it_stays_complete() {
    let mut first = FirstFrame::new();
    assert!(first.feed(&frame(3)));
    assert!(first.feed(b"anything after"));
    assert!(first.feed(&[]));
}

#[test]
fn a_bad_signature_never_completes() {
    let mut bytes = frame(4);
    bytes[0] ^= 0xff;
    let mut first = FirstFrame::new();
    assert!(!first.feed(&bytes));
    assert!(
        !first.feed(&frame(4)),
        "a later good frame does not rescue it"
    );
}
