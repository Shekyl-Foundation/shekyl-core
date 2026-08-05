// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Read-side state-machine properties, mirroring the `handle_recv` behaviors
//! of `contrib/epee/include/net/levin_protocol_handler_async.h`: incremental
//! delivery, noise discard, fragment reassembly, size limits, signature
//! early-reject, and message classification. These do NOT pin emit-side wire
//! bytes (see `oracle_kats.rs`).

use shekyl_levin::{
    fragmented_notify, invoke, noise_notify, notify, response, BucketReader, Error, Received,
    DEFAULT_MAX_PACKET_SIZE, HEADER_SIZE, INITIAL_MAX_PACKET_SIZE,
};

#[test]
fn one_byte_trickle_reassembles_a_notification() {
    let message = notify(2002, b"payload-bytes");
    let mut reader = BucketReader::new();
    let mut got = Vec::new();
    for byte in &message {
        got.extend(reader.advance(std::slice::from_ref(byte)).unwrap());
    }
    assert_eq!(
        got,
        vec![Received::Notification {
            command: 2002,
            payload: b"payload-bytes".to_vec(),
        }]
    );
}

#[test]
fn classification_follows_flags_and_expect_response() {
    let mut stream = Vec::new();
    stream.extend(invoke(1001, b"req"));
    stream.extend(response(1001, -4, b"rsp"));
    stream.extend(notify(2002, b"ntf"));

    let got = BucketReader::new().advance(&stream).unwrap();
    assert_eq!(
        got,
        vec![
            Received::Request {
                command: 1001,
                payload: b"req".to_vec(),
            },
            Received::Response {
                command: 1001,
                return_code: -4,
                payload: b"rsp".to_vec(),
            },
            Received::Notification {
                command: 2002,
                payload: b"ntf".to_vec(),
            },
        ]
    );
}

#[test]
fn dummy_messages_are_discarded_silently() {
    let mut stream = noise_notify(1024).unwrap();
    stream.extend(notify(2002, b"real"));
    stream.extend(noise_notify(512).unwrap());

    let got = BucketReader::new().advance(&stream).unwrap();
    assert_eq!(
        got,
        vec![Received::Notification {
            command: 2002,
            payload: b"real".to_vec(),
        }]
    );
}

#[test]
fn fragmented_stream_reassembles_to_the_original_notification() {
    // Payload big enough to force 3 fragments at noise size 1024 (see the
    // make_fragment.multiple KAT); the reassembled message must equal the
    // original, with the fragment zero-padding trimmed away.
    let payload: Vec<u8> = (0u32..2922)
        .map(|i| u8::try_from(i % 256).unwrap())
        .collect();
    let stream = fragmented_notify(1024, 114, &payload).unwrap();

    let got = BucketReader::new().advance(&stream).unwrap();
    assert_eq!(
        got,
        vec![Received::Notification {
            command: 114,
            payload,
        }]
    );
}

#[test]
fn fragment_restart_on_second_begin_mirrors_cpp() {
    // A BEGIN fragment mid-reassembly clears the buffer and restarts (the
    // C++ clears m_fragment_buffer on LEVIN_PACKET_BEGIN).
    let payload: Vec<u8> = (0u32..2922)
        .map(|i| u8::try_from(i % 256).unwrap())
        .collect();
    let stream = fragmented_notify(1024, 114, &payload).unwrap();

    let mut reader = BucketReader::new();
    // First fragment (BEGIN) fed once...
    assert!(reader.advance(&stream[..1024]).unwrap().is_empty());
    // ...then the whole stream again from the top: the second BEGIN restarts.
    let got = reader.advance(&stream).unwrap();
    assert_eq!(
        got,
        vec![Received::Notification {
            command: 114,
            payload,
        }]
    );
}

#[test]
fn wrong_signature_rejected_at_eight_bytes() {
    let mut reader = BucketReader::new();
    assert_eq!(
        reader.advance(&[0xFF; 8]),
        Err(Error::BadSignature),
        "mismatch must be fatal before a full header arrives"
    );
}

#[test]
fn oversize_header_rejected_pre_handshake_accepted_post() {
    // 300 KiB payload claim: above the 256 KiB pre-handshake limit, below
    // the 100 MB post-handshake one.
    let claimed = 300 * 1024_u64;
    let message = notify(2002, &vec![0u8; usize::try_from(claimed).unwrap()]);

    let mut pre = BucketReader::new();
    // Feed in slices below the buffer cap so the header-length check is what
    // fires, exactly as in the C++ (which checks m_cb after parsing).
    let err = pre.advance(&message[..HEADER_SIZE]).unwrap_err();
    assert_eq!(
        err,
        Error::OversizePacket {
            claimed,
            limit: INITIAL_MAX_PACKET_SIZE,
        }
    );

    let mut post = BucketReader::new();
    post.set_max_packet_size(DEFAULT_MAX_PACKET_SIZE);
    let got = post.advance(&message).unwrap();
    assert_eq!(got.len(), 1);
}

#[test]
fn buffered_bytes_capped_by_packet_limit() {
    let mut reader = BucketReader::new();
    let oversized = vec![0u8; usize::try_from(INITIAL_MAX_PACKET_SIZE).unwrap() + 1];
    assert_eq!(
        reader.advance(&oversized),
        Err(Error::BufferLimit {
            limit: INITIAL_MAX_PACKET_SIZE,
        })
    );
}

#[test]
fn truncated_fragment_reassembly_rejected() {
    // A single END fragment whose body is smaller than a Levin header cannot
    // contain the required inner message (C++: "Fragmented data too small").
    let inner_too_small = {
        // Build a fragment header claiming a 10-byte body with END set.
        let mut head = shekyl_levin::BucketHead::make(0, 10, shekyl_levin::Flags::END, false);
        head.return_code = 0;
        let mut msg = head.write().to_vec();
        msg.extend_from_slice(&[0u8; 10]);
        msg
    };
    let mut reader = BucketReader::new();
    assert_eq!(
        reader.advance(&inner_too_small),
        Err(Error::FragmentTooSmall)
    );
}

#[test]
fn per_command_limit_caps_below_packet_limit() {
    // Mirrors connection_context::get_max_bytes: ping (1003) caps at 4096.
    fn table(command: u32) -> u64 {
        if command == 1003 {
            4096
        } else {
            u64::MAX
        }
    }

    let mut reader = BucketReader::new();
    reader.set_max_bytes_for_command(table);

    // 5000-byte ping claim: under the 256 KiB packet limit, over the
    // command's own cap — rejected on the header, as in the C++.
    let message = invoke(1003, &vec![0u8; 5000]);
    assert_eq!(
        reader.advance(&message[..HEADER_SIZE]),
        Err(Error::OversizePacket {
            claimed: 5000,
            limit: 4096,
        })
    );

    // The same size on an uncapped command passes.
    let mut reader = BucketReader::new();
    reader.set_max_bytes_for_command(table);
    let got = reader.advance(&invoke(9999, &vec![0u8; 5000])).unwrap();
    assert_eq!(got.len(), 1);
}

#[test]
fn end_without_begin_reassembles_from_empty_buffer() {
    // The C++ never requires a BEGIN: an END-flagged fragment appends to
    // whatever the fragment buffer holds (possibly nothing) and completes.
    // A lone END fragment whose body is a complete inner message delivers.
    let inner = notify(2002, b"lone-end");
    let mut head = shekyl_levin::BucketHead::make(
        0,
        u64::try_from(inner.len()).unwrap(),
        shekyl_levin::Flags::END,
        false,
    );
    head.return_code = 0;
    let mut stream = head.write().to_vec();
    stream.extend_from_slice(&inner);

    let got = BucketReader::new().advance(&stream).unwrap();
    assert_eq!(
        got,
        vec![Received::Notification {
            command: 2002,
            payload: b"lone-end".to_vec(),
        }]
    );
}

#[test]
fn response_flag_without_version_one_is_not_a_response() {
    // The C++ classifies as response only when the peer's protocol version
    // is LEVIN_PROTOCOL_VER_1; otherwise expect_response decides.
    let mut message = response(1001, -4, b"rsp");
    // Overwrite the protocol-version field (bytes 29..33) with 0.
    message[29..33].copy_from_slice(&0u32.to_le_bytes());

    let got = BucketReader::new().advance(&message).unwrap();
    assert_eq!(
        got,
        vec![Received::Notification {
            command: 1001,
            payload: b"rsp".to_vec(),
        }]
    );
}

#[cfg(feature = "zstd")]
#[test]
fn compressed_dummy_is_discarded_without_decompression() {
    // The noise check precedes the COMPRESSED check in handle_recv, so a
    // dummy with a garbage "compressed" body is discarded, not an error.
    let mut dummy = noise_notify(256).unwrap();
    // Set the COMPRESSED bit on the flags field (bytes 25..29) — body stays
    // zeros, which is not a valid zstd frame.
    let flags = u32::from_le_bytes(dummy[25..29].try_into().unwrap()) | 0x10;
    dummy[25..29].copy_from_slice(&flags.to_le_bytes());

    let got = BucketReader::new().advance(&dummy).unwrap();
    assert!(got.is_empty());
}

#[cfg(feature = "zstd")]
#[test]
fn compressed_bucket_inflates_before_delivery() {
    use shekyl_levin::try_compress_message;

    let payload = vec![7u8; 4096];
    let compressed = try_compress_message(notify(2002, &payload));
    assert!(compressed.len() < HEADER_SIZE + payload.len());

    let got = BucketReader::new().advance(&compressed).unwrap();
    assert_eq!(
        got,
        vec![Received::Notification {
            command: 2002,
            payload,
        }]
    );
}
