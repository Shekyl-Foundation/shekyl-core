// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A Levin byte stream walked frame by frame: each frame is handed over
//! once, with its header, when its last byte arrives, however the bytes
//! are split across feeds; a header that does not read ends the walk.

use shekyl_levin::{
    BucketHead, Flags, FrameHeads, COMMAND_HANDSHAKE, COMMAND_TIMED_SYNC, HEADER_SIZE,
    PROTOCOL_VERSION_1,
};

fn frame(command: u32, body: usize) -> Vec<u8> {
    let head = BucketHead {
        payload_len: u64::try_from(body).expect("small"),
        expect_response: 0,
        command,
        flags: Flags::REQUEST,
        protocol_version: PROTOCOL_VERSION_1,
    };
    let mut out = head.write().to_vec();
    out.extend(std::iter::repeat_n(7u8, body));
    out
}

/// Every frame `feeds` completes, as (command, payload length).
fn walk<'a>(feeds: impl IntoIterator<Item = &'a [u8]>) -> (Vec<(u32, u64)>, bool) {
    let mut frames = FrameHeads::new();
    let mut seen = Vec::new();
    for bytes in feeds {
        frames.feed(bytes, |head| seen.push((head.command, head.payload_len)));
    }
    (seen, frames.ended())
}

#[test]
fn frames_in_one_feed_are_handed_over_in_order() {
    let mut stream = frame(COMMAND_HANDSHAKE, 40);
    stream.extend(frame(COMMAND_TIMED_SYNC, 0));
    stream.extend(frame(COMMAND_TIMED_SYNC, 3));
    let (seen, ended) = walk([stream.as_slice()]);
    assert_eq!(
        seen,
        [
            (COMMAND_HANDSHAKE, 40),
            (COMMAND_TIMED_SYNC, 0),
            (COMMAND_TIMED_SYNC, 3)
        ]
    );
    assert!(!ended);
}

#[test]
fn a_frame_split_byte_by_byte_is_handed_over_on_its_last_byte() {
    let stream = frame(COMMAND_TIMED_SYNC, 5);
    let mut frames = FrameHeads::new();
    let mut seen = 0;
    for (i, byte) in stream.iter().enumerate() {
        frames.feed(std::slice::from_ref(byte), |_| seen += 1);
        assert_eq!(seen, usize::from(i + 1 == stream.len()), "byte {i}");
    }
}

#[test]
fn a_split_inside_the_header_and_the_body_still_walks() {
    let mut stream = frame(COMMAND_HANDSHAKE, 10);
    stream.extend(frame(COMMAND_TIMED_SYNC, 20));
    let (first, rest) = stream.split_at(HEADER_SIZE - 3);
    let (second, third) = rest.split_at(HEADER_SIZE + 5);
    let (seen, _) = walk([first, second, third]);
    assert_eq!(seen, [(COMMAND_HANDSHAKE, 10), (COMMAND_TIMED_SYNC, 20)]);
}

#[test]
fn a_bad_signature_ends_the_walk_and_later_frames_are_ignored() {
    let mut bad = frame(COMMAND_TIMED_SYNC, 0);
    bad[0] ^= 0xFF;
    let good = frame(COMMAND_HANDSHAKE, 0);
    let (seen, ended) = walk([good.as_slice(), bad.as_slice(), good.as_slice()]);
    assert_eq!(seen, [(COMMAND_HANDSHAKE, 0)]);
    assert!(ended);
}
