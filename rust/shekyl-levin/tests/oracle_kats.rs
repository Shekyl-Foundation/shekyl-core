// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Byte-identity KATs against the C++ `epee::levin` oracle.
//!
//! Each test mirrors a gtest in `tests/unit_tests/levin.cpp` (`make_noise.*`,
//! `make_fragment.*`) assertion for assertion, so the two implementations are
//! pinned to the same wire bytes. Removing these loses the cross-language
//! byte-identity pin; they do NOT cover the read-side state machine (see
//! `reader_stream.rs`).

use shekyl_levin::{
    fragmented_notify, noise_notify, BucketHead, Flags, HEADER_SIZE, LEVIN_SIGNATURE,
};

/// The full 33-byte header for `make_header(1, 0x100, LEVIN_PACKET_REQUEST,
/// true)`, spelled out from the `docs/LEVIN_PROTOCOL.md` byte layout rather
/// than re-derived through the encoder under test.
#[test]
fn header_wire_bytes_match_spec_layout() {
    #[rustfmt::skip]
    let expected: [u8; HEADER_SIZE] = [
        // signature: 0x0101010101012101 little-endian
        0x01, 0x21, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        // length = 0x100 (u64 LE)
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // expect response
        0x01,
        // command = 1 (u32 LE)
        0x01, 0x00, 0x00, 0x00,
        // return code = 0 (i32 LE)
        0x00, 0x00, 0x00, 0x00,
        // flags: Q (request)
        0x01, 0x00, 0x00, 0x00,
        // protocol version = 1 (u32 LE)
        0x01, 0x00, 0x00, 0x00,
    ];
    let head = BucketHead::make(1, 0x100, Flags::REQUEST, true);
    assert_eq!(head.write(), expected);
    assert_eq!(BucketHead::read(&expected).unwrap(), head);
    assert_eq!(
        u64::from_le_bytes(expected[..8].try_into().unwrap()),
        LEVIN_SIGNATURE
    );
}

/// Mirrors gtest `make_noise.valid`: 1024-byte dummy = header(0, 991, B|E,
/// no-response) + zeroed body.
#[test]
fn noise_message_is_header_plus_zeros() {
    let noise = noise_notify(1024).unwrap();
    let expected_head = BucketHead::make(
        0,
        u64::try_from(1024 - HEADER_SIZE).unwrap(),
        Flags::BEGIN.union(Flags::END),
        false,
    );

    assert_eq!(noise.len(), 1024);
    assert_eq!(noise[..HEADER_SIZE], expected_head.write());
    assert!(noise[HEADER_SIZE..].iter().all(|&b| b == 0));
}

/// Mirrors gtest `make_fragment.single`: a message that fits in one noise
/// bucket is an ordinary notification zero-padded to the noise size.
#[test]
fn small_message_pads_to_noise_size_unfragmented() {
    let fragment = fragmented_notify(1024, 11, &[]).unwrap();
    let expected_head = BucketHead::make(
        11,
        u64::try_from(1024 - HEADER_SIZE).unwrap(),
        Flags::REQUEST,
        false,
    );

    assert_eq!(fragment.len(), 1024);
    assert_eq!(fragment[..HEADER_SIZE], expected_head.write());
    assert!(fragment[HEADER_SIZE..].iter().all(|&b| b == 0));
}

/// Mirrors gtest `make_fragment.multiple` byte for byte: a 2922-byte payload
/// at noise size 1024 emits exactly three 1024-byte fragments — B / middle /
/// E — whose bodies concatenate to the inner notification plus 18 zero bytes
/// of padding.
#[test]
fn oversize_message_fragments_to_noise_sized_buckets() {
    // Deterministic "random" payload; the gtest uses crypto::random_device,
    // but only the length (1024 * 3 - 150 = 2922) is structural.
    let payload: Vec<u8> = (0u32..2922)
        .map(|i| u8::try_from((i * 31 + 7) % 256).unwrap())
        .collect();

    let stream = fragmented_notify(1024, 114, &payload).unwrap();
    assert_eq!(stream.len(), 1024 * 3);

    let body_space = 1024 - HEADER_SIZE; // 991

    // Fragment 1: BEGIN header, then the inner header, then payload bytes.
    let mut head = BucketHead::make(0, u64::try_from(body_space).unwrap(), Flags::BEGIN, false);
    assert_eq!(stream[..HEADER_SIZE], head.write());

    let inner_head = BucketHead::make(
        114,
        u64::try_from(payload.len()).unwrap(),
        Flags::REQUEST,
        false,
    );
    assert_eq!(stream[HEADER_SIZE..HEADER_SIZE * 2], inner_head.write());

    let frag1_payload_len = body_space - HEADER_SIZE; // 958
    assert_eq!(
        &stream[HEADER_SIZE * 2..1024],
        &payload[..frag1_payload_len]
    );

    // Fragment 2: middle header (no B/E), next 991 payload bytes.
    head.flags = Flags::from_bits(0);
    assert_eq!(stream[1024..1024 + HEADER_SIZE], head.write());
    assert_eq!(
        &stream[1024 + HEADER_SIZE..2048],
        &payload[frag1_payload_len..frag1_payload_len + body_space]
    );

    // Fragment 3: END header, remaining payload, 18 bytes of zero padding.
    head.flags = Flags::END;
    assert_eq!(stream[2048..2048 + HEADER_SIZE], head.write());
    let rest = &payload[frag1_payload_len + body_space..];
    assert_eq!(
        &stream[2048 + HEADER_SIZE..2048 + HEADER_SIZE + rest.len()],
        rest
    );
    let padding = &stream[2048 + HEADER_SIZE + rest.len()..];
    assert_eq!(padding.len(), 18);
    assert!(padding.iter().all(|&b| b == 0));
}
