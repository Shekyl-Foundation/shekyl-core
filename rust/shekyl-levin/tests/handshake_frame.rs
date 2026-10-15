// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The peer's first complete handshake frame, as the transport's gap reads
//! it (Rick, 2026-10-14): the header and the body it declares, however the
//! bytes are split across reads, and only the handshake frame of the kind
//! the session waits for (Copilot on #1056).

use shekyl_levin::{
    BucketHead, Flags, HandshakeFrame, HandshakeKind, COMMAND_HANDSHAKE,
    COMMAND_REQUEST_SUPPORT_FLAGS, HEADER_SIZE, PROTOCOL_VERSION_1,
};

fn frame(command: u32, flags: Flags, expect_response: u8, body: usize) -> Vec<u8> {
    let head = BucketHead {
        payload_len: u64::try_from(body).expect("small"),
        expect_response,
        command,
        flags,
        protocol_version: PROTOCOL_VERSION_1,
    };
    let mut out = head.write().to_vec();
    out.extend(std::iter::repeat_n(7u8, body));
    out
}

fn handshake_request(body: usize) -> Vec<u8> {
    frame(COMMAND_HANDSHAKE, Flags::REQUEST, 1, body)
}

fn handshake_response(body: usize) -> Vec<u8> {
    frame(COMMAND_HANDSHAKE, Flags::RESPONSE, 0, body)
}

fn support_flags_request() -> Vec<u8> {
    frame(COMMAND_REQUEST_SUPPORT_FLAGS, Flags::REQUEST, 1, 10)
}

#[test]
fn a_handshake_request_in_one_read_completes() {
    let mut seen = HandshakeFrame::new(HandshakeKind::Request);
    assert!(seen.feed(&handshake_request(40)));
    assert!(seen.complete());
}

#[test]
fn a_handshake_response_completes_the_dialer_side() {
    let mut seen = HandshakeFrame::new(HandshakeKind::Response);
    assert!(seen.feed(&handshake_response(40)));
}

#[test]
fn a_frame_split_byte_by_byte_completes_on_its_last_byte() {
    let bytes = handshake_request(40);
    let mut seen = HandshakeFrame::new(HandshakeKind::Request);
    for (i, byte) in bytes.iter().enumerate() {
        let done = seen.feed(std::slice::from_ref(byte));
        assert_eq!(done, i + 1 == bytes.len(), "byte {i}");
    }
}

#[test]
fn part_of_a_frame_is_not_a_frame() {
    let bytes = handshake_request(40);
    let mut seen = HandshakeFrame::new(HandshakeKind::Request);
    assert!(!seen.feed(&bytes[..HEADER_SIZE - 1]));
    assert!(!seen.feed(&bytes[HEADER_SIZE - 1..HEADER_SIZE + 10]));
    assert!(!seen.complete());
}

#[test]
fn a_handshake_with_no_body_is_a_frame() {
    let mut seen = HandshakeFrame::new(HandshakeKind::Request);
    assert!(seen.feed(&handshake_request(0)));
}

#[test]
fn once_complete_it_stays_complete() {
    let mut seen = HandshakeFrame::new(HandshakeKind::Request);
    assert!(seen.feed(&handshake_request(3)));
    assert!(seen.feed(b"anything after"));
    assert!(seen.feed(&[]));
}

#[test]
fn a_bad_signature_never_completes() {
    let mut bytes = handshake_request(4);
    bytes[0] ^= 0xff;
    let mut seen = HandshakeFrame::new(HandshakeKind::Request);
    assert!(!seen.feed(&bytes));
    assert!(
        !seen.feed(&handshake_request(4)),
        "a later good frame does not rescue it"
    );
}

/// **A support-flags request is not the handshake** (Copilot on #1056):
/// a peer that sends one and stops is still silent, so its gap stays
/// armed. The handshake that follows it ends the gap.
#[test]
fn a_frame_of_another_command_does_not_end_the_wait() {
    let mut seen = HandshakeFrame::new(HandshakeKind::Request);
    assert!(!seen.feed(&support_flags_request()));
    assert!(!seen.complete());
    assert!(seen.feed(&handshake_request(40)));
}

#[test]
fn frames_in_one_read_are_each_read() {
    let mut bytes = support_flags_request();
    bytes.extend(frame(COMMAND_REQUEST_SUPPORT_FLAGS, Flags::REQUEST, 1, 0));
    bytes.extend(handshake_request(40));
    let mut seen = HandshakeFrame::new(HandshakeKind::Request);
    assert!(seen.feed(&bytes));
}

#[test]
fn the_other_direction_s_handshake_does_not_count() {
    let mut request_side = HandshakeFrame::new(HandshakeKind::Request);
    assert!(!request_side.feed(&handshake_response(40)));
    let mut response_side = HandshakeFrame::new(HandshakeKind::Response);
    assert!(!response_side.feed(&handshake_request(40)));
}

/// A handshake request the peer does not want answered is not a
/// handshake: the strand would never reply to it.
#[test]
fn a_request_that_expects_no_response_does_not_count() {
    let mut seen = HandshakeFrame::new(HandshakeKind::Request);
    assert!(!seen.feed(&frame(COMMAND_HANDSHAKE, Flags::REQUEST, 0, 40)));
}
