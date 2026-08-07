// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Read-side state-machine properties, mirroring the `handle_recv` behaviors
//! of `contrib/epee/include/net/levin_protocol_handler_async.h`: incremental
//! delivery, noise discard, fragment reassembly, size limits, signature
//! early-reject, and message classification. These do NOT pin emit-side wire
//! bytes (see `oracle_kats.rs`).
//!
//! Tests here drive `feed` / `next_message` directly. There is deliberately
//! no "collect everything into a `Vec`" helper: such a helper reintroduces
//! the batching the pull API exists to prevent, and any test written through
//! it would pass equally against a reader that decodes a whole feed at once.

use shekyl_levin::{
    fragmented_notify, invoke, noise_notify, notify, response, BucketReader, Error, Received,
    DEFAULT_MAX_PACKET_SIZE, HEADER_SIZE, INITIAL_MAX_PACKET_SIZE,
};

/// Feed a whole stream, then pull exactly one message and assert it is the
/// only one. Used where the point of the test is *what* is delivered.
#[track_caller]
fn only_message(stream: &[u8]) -> Received {
    let mut reader = BucketReader::new();
    reader.feed(stream).expect("stream within limits");
    let message = reader
        .next_message()
        .expect("valid stream must parse")
        .expect("a message must be ready");
    assert_eq!(
        reader.next_message().expect("valid stream must parse"),
        None,
        "exactly one message expected"
    );
    message
}

#[test]
fn one_byte_trickle_reassembles_a_notification() {
    let message = notify(2002, b"payload-bytes");
    let mut reader = BucketReader::new();
    let mut got = None;
    for byte in &message {
        reader.feed(std::slice::from_ref(byte)).unwrap();
        if let Some(message) = reader.next_message().unwrap() {
            assert!(got.replace(message).is_none(), "only one message expected");
        }
    }
    assert_eq!(
        got,
        Some(Received::Notification {
            command: 2002,
            payload: b"payload-bytes".to_vec(),
        })
    );
}

#[test]
fn classification_follows_flags_and_expect_response() {
    let mut stream = Vec::new();
    stream.extend(invoke(1001, b"req"));
    stream.extend(response(1001, -4, b"rsp"));
    stream.extend(notify(2002, b"ntf"));

    let mut reader = BucketReader::new();
    reader.feed(&stream).unwrap();
    assert_eq!(
        reader.next_message().unwrap(),
        Some(Received::Request {
            command: 1001,
            payload: b"req".to_vec(),
        })
    );
    assert_eq!(
        reader.next_message().unwrap(),
        Some(Received::Response {
            command: 1001,
            return_code: -4,
            payload: b"rsp".to_vec(),
        })
    );
    assert_eq!(
        reader.next_message().unwrap(),
        Some(Received::Notification {
            command: 2002,
            payload: b"ntf".to_vec(),
        })
    );
    assert_eq!(reader.next_message().unwrap(), None);
}

/// The core property of the pull API: a feed carrying many messages decodes
/// them one at a time, so at most one payload is ever live. Pinned by
/// watching the reader's own buffer — after one pull, the bytes of the
/// remaining messages are still sitting there, unparsed.
#[test]
fn a_multi_message_feed_decodes_one_message_per_pull() {
    let one = notify(2002, &vec![0xAB; 1024]);
    let mut stream = Vec::new();
    for _ in 0..16 {
        stream.extend_from_slice(&one);
    }

    let mut reader = BucketReader::new();
    reader.feed(&stream).unwrap();

    for remaining in (0..16).rev() {
        assert_eq!(
            reader.buffered_bytes(),
            u64::try_from((remaining + 1) * one.len()).unwrap(),
            "the undelivered messages must still be undecoded bytes"
        );
        assert!(reader.next_message().unwrap().is_some());
    }
    assert_eq!(reader.buffered_bytes(), 0);
    assert_eq!(reader.next_message().unwrap(), None);
}

/// A malformed bucket must not destroy messages that were already complete
/// ahead of it. The C++ dispatches each message inside the parse loop and
/// only then returns `false`, so the good notification is relayed and the
/// connection is closed after it.
#[test]
fn a_message_completed_before_a_bad_bucket_is_still_delivered() {
    let mut stream = notify(2002, b"good-one");
    // A second header claiming 400 KiB — over the 256 KiB pre-handshake cap.
    let oversize = notify(2002, b"");
    stream.extend_from_slice(&oversize[..HEADER_SIZE]);
    let claimed = 400 * 1024_u64;
    let head_at = stream.len() - HEADER_SIZE;
    stream[head_at + 8..head_at + 16].copy_from_slice(&claimed.to_le_bytes());

    let mut reader = BucketReader::new();
    reader.feed(&stream).unwrap();
    assert_eq!(
        reader.next_message().unwrap(),
        Some(Received::Notification {
            command: 2002,
            payload: b"good-one".to_vec(),
        }),
        "the well-formed message must survive the bad bucket behind it"
    );
    assert_eq!(
        reader.next_message(),
        Err(Error::OversizePacket {
            claimed,
            limit: INITIAL_MAX_PACKET_SIZE,
        })
    );
}

/// Every framing error is connection-fatal in the oracle. The reader latches
/// rather than trusting the caller to close: reuse after an error is itself
/// an error, on both entry points.
#[test]
fn a_fatal_error_poisons_the_reader() {
    let mut reader = BucketReader::new();
    assert_eq!(reader.feed(&[0xFF; 8]), Ok(()));
    assert_eq!(reader.next_message(), Err(Error::BadSignature));

    assert_eq!(reader.next_message(), Err(Error::Poisoned));
    assert_eq!(reader.feed(&notify(2002, b"x")), Err(Error::Poisoned));
    assert_eq!(reader.next_message(), Err(Error::Poisoned));
}

/// The three errors raised after the offending bucket has been consumed
/// (`Decompress`, `InnerLengthTruncated`, inner-header `BadSignature`) leave
/// the state machine looking clean, so they are the ones a missing latch
/// would let a caller walk straight past.
#[test]
fn an_error_raised_mid_bucket_poisons_too() {
    // Inner header claims 100 payload bytes; the fragment body carries none.
    let mut inner_head =
        shekyl_levin::BucketHead::make(2002, 100, shekyl_levin::Flags::REQUEST, false);
    inner_head.return_code = 0;
    let inner = inner_head.write().to_vec();
    let mut outer = shekyl_levin::BucketHead::make(
        0,
        u64::try_from(inner.len()).unwrap(),
        shekyl_levin::Flags::END,
        false,
    );
    outer.return_code = 0;
    let mut stream = outer.write().to_vec();
    stream.extend_from_slice(&inner);
    // A perfectly good message behind it, which must never be reached.
    stream.extend(notify(2002, b"never-parsed"));

    let mut reader = BucketReader::new();
    reader.feed(&stream).unwrap();
    assert_eq!(
        reader.next_message(),
        Err(Error::InnerLengthTruncated {
            claimed: 100,
            available: 0,
        })
    );
    assert_eq!(reader.next_message(), Err(Error::Poisoned));
}

#[test]
fn dummy_messages_are_discarded_silently() {
    let mut stream = noise_notify(1024).unwrap();
    stream.extend(notify(2002, b"real"));
    stream.extend(noise_notify(512).unwrap());

    assert_eq!(
        only_message(&stream),
        Received::Notification {
            command: 2002,
            payload: b"real".to_vec(),
        }
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

    assert_eq!(
        only_message(&stream),
        Received::Notification {
            command: 114,
            payload,
        }
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
    reader.feed(&stream[..1024]).unwrap();
    assert_eq!(reader.next_message().unwrap(), None);
    // ...then the whole stream again from the top: the second BEGIN restarts.
    reader.feed(&stream).unwrap();
    assert_eq!(
        reader.next_message().unwrap(),
        Some(Received::Notification {
            command: 114,
            payload,
        })
    );
    assert_eq!(reader.next_message().unwrap(), None);
}

#[test]
fn wrong_signature_rejected_at_eight_bytes() {
    let mut reader = BucketReader::new();
    reader.feed(&[0xFF; 8]).unwrap();
    assert_eq!(
        reader.next_message(),
        Err(Error::BadSignature),
        "mismatch must be fatal before a full header arrives"
    );
}

/// The packet limit only moves at handshake completion, and there is no way
/// to move it any earlier: a fresh reader caps an unauthenticated peer at
/// 256 KiB no matter what the caller does first.
#[test]
fn oversize_header_rejected_pre_handshake_accepted_post() {
    // 300 KiB payload claim: above the 256 KiB pre-handshake limit, below
    // the 100 MB post-handshake one.
    let claimed = 300 * 1024_u64;
    let message = notify(2002, &vec![0u8; usize::try_from(claimed).unwrap()]);

    let mut pre = BucketReader::new();
    // Feed in slices below the buffer cap so the header-length check is what
    // fires, exactly as in the C++ (which checks m_cb after parsing).
    pre.feed(&message[..HEADER_SIZE]).unwrap();
    assert_eq!(
        pre.next_message(),
        Err(Error::OversizePacket {
            claimed,
            limit: INITIAL_MAX_PACKET_SIZE,
        })
    );

    let mut post = BucketReader::new();
    post.complete_handshake(DEFAULT_MAX_PACKET_SIZE);
    post.feed(&message).unwrap();
    assert!(post.next_message().unwrap().is_some());
}

/// The buffered-bytes cap is the pre-handshake one until the handshake
/// raises it — the property that stops an unauthenticated peer from parking
/// 100 MB of node memory per connection.
#[test]
fn buffered_bytes_capped_by_packet_limit() {
    let mut reader = BucketReader::new();
    let oversized = vec![0u8; usize::try_from(INITIAL_MAX_PACKET_SIZE).unwrap() + 1];
    assert_eq!(
        reader.feed(&oversized),
        Err(Error::BufferLimit {
            limit: INITIAL_MAX_PACKET_SIZE,
        })
    );

    // The same bytes are within the cap once the handshake has completed.
    let mut post = BucketReader::new();
    post.complete_handshake(DEFAULT_MAX_PACKET_SIZE);
    assert_eq!(post.feed(&oversized), Ok(()));
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
    reader.feed(&inner_too_small).unwrap();
    assert_eq!(reader.next_message(), Err(Error::FragmentTooSmall));
}

/// Divergence "inner-signature verify" pin: a reassembled inner header with a
/// bad signature is connection-fatal (C++ memcpys the bytes unchecked and
/// would proceed).
#[test]
fn reassembled_inner_bad_signature_rejected() {
    let mut bad_inner = notify(2002, b"x");
    bad_inner[0] = 0xFF; // corrupt the signature of the logical message
    let mut head = shekyl_levin::BucketHead::make(
        0,
        u64::try_from(bad_inner.len()).unwrap(),
        shekyl_levin::Flags::END,
        false,
    );
    head.return_code = 0;
    let mut stream = head.write().to_vec();
    stream.extend_from_slice(&bad_inner);

    let mut reader = BucketReader::new();
    reader.feed(&stream).unwrap();
    assert_eq!(reader.next_message(), Err(Error::BadSignature));
}

/// Divergence "inner-length trim" pin: inner `length` past the reassembled
/// body is fatal (C++ would forward a short buffer to the handler).
#[test]
fn reassembled_inner_length_past_body_rejected() {
    // Inner header claims 100 payload bytes, but the fragment body only
    // carries the 33-byte header (available = 0 after the inner header).
    let mut inner_head =
        shekyl_levin::BucketHead::make(2002, 100, shekyl_levin::Flags::REQUEST, false);
    inner_head.return_code = 0;
    let inner = inner_head.write().to_vec(); // no payload bytes after it
    let mut outer = shekyl_levin::BucketHead::make(
        0,
        u64::try_from(inner.len()).unwrap(),
        shekyl_levin::Flags::END,
        false,
    );
    outer.return_code = 0;
    let mut stream = outer.write().to_vec();
    stream.extend_from_slice(&inner);

    let mut reader = BucketReader::new();
    reader.feed(&stream).unwrap();
    assert_eq!(
        reader.next_message(),
        Err(Error::InnerLengthTruncated {
            claimed: 100,
            available: 0,
        })
    );
}

/// Divergence "inner-length trim" pin: when the inner length is short of the
/// fragment body, the delivered payload is trimmed to that length (padding
/// dropped).
#[test]
fn reassembled_inner_payload_trimmed_to_declared_length() {
    let real = b"trimmed";
    let mut inner = notify(2002, real);
    // Append 9 zero-padding bytes the outer fragment will carry, but keep
    // the inner header's length at the real payload size.
    inner.extend_from_slice(&[0u8; 9]);
    // Overwrite the outer framing: END fragment whose body is the padded
    // inner notification. The inner header still claims `real.len()`.
    let mut outer = shekyl_levin::BucketHead::make(
        0,
        u64::try_from(inner.len()).unwrap(),
        shekyl_levin::Flags::END,
        false,
    );
    outer.return_code = 0;
    let mut stream = outer.write().to_vec();
    stream.extend_from_slice(&inner);

    assert_eq!(
        only_message(&stream),
        Received::Notification {
            command: 2002,
            payload: real.to_vec(),
        }
    );
}

/// Divergence "logical-header classification" pin: after reassembly,
/// classification uses the *inner* protocol version (logical message), not a
/// sticky outer-header field. Outer fragment headers always carry version 1
/// from the builders; a crafted inner with version 0 + RESPONSE is a
/// notification here.
#[test]
fn reassembled_response_classifies_by_inner_protocol_version() {
    let mut inner = response(1001, -4, b"rsp");
    // Overwrite the inner protocol-version field (bytes 29..33) with 0.
    inner[29..33].copy_from_slice(&0u32.to_le_bytes());

    let mut outer = shekyl_levin::BucketHead::make(
        0,
        u64::try_from(inner.len()).unwrap(),
        shekyl_levin::Flags::END,
        false,
    );
    outer.return_code = 0;
    // Outer still carries PROTOCOL_VERSION_1 (BucketHead::make default).
    let mut stream = outer.write().to_vec();
    stream.extend_from_slice(&inner);

    assert_eq!(
        only_message(&stream),
        Received::Notification {
            command: 1001,
            payload: b"rsp".to_vec(),
        },
        "inner ver=0 must not classify as Response even though outer is ver=1"
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
    reader.feed(&message[..HEADER_SIZE]).unwrap();
    assert_eq!(
        reader.next_message(),
        Err(Error::OversizePacket {
            claimed: 5000,
            limit: 4096,
        })
    );

    // The same size on an uncapped command passes.
    let mut reader = BucketReader::new();
    reader.set_max_bytes_for_command(table);
    reader.feed(&invoke(9999, &vec![0u8; 5000])).unwrap();
    assert!(reader.next_message().unwrap().is_some());
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

    assert_eq!(
        only_message(&stream),
        Received::Notification {
            command: 2002,
            payload: b"lone-end".to_vec(),
        }
    );
}

#[test]
fn response_flag_without_version_one_is_not_a_response() {
    // The C++ classifies as response only when the peer's protocol version
    // is LEVIN_PROTOCOL_VER_1; otherwise expect_response decides.
    let mut message = response(1001, -4, b"rsp");
    // Overwrite the protocol-version field (bytes 29..33) with 0.
    message[29..33].copy_from_slice(&0u32.to_le_bytes());

    assert_eq!(
        only_message(&message),
        Received::Notification {
            command: 1001,
            payload: b"rsp".to_vec(),
        }
    );
}

/// A truthy-but-not-1 `expect_response` byte still classifies as a request,
/// the way the C++ reads `m_have_to_return_data` as a `uint8_t`.
#[test]
fn non_canonical_expect_response_byte_is_a_request() {
    let mut message = notify(2002, b"req");
    message[16] = 0x02;

    assert_eq!(
        only_message(&message),
        Received::Request {
            command: 2002,
            payload: b"req".to_vec(),
        }
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

    let mut reader = BucketReader::new();
    reader.feed(&dummy).unwrap();
    assert_eq!(reader.next_message().unwrap(), None);
}

#[cfg(feature = "zstd")]
#[test]
fn compressed_bucket_inflates_before_delivery() {
    use shekyl_levin::try_compress_message;

    let payload = vec![7u8; 4096];
    let compressed = try_compress_message(notify(2002, &payload));
    assert!(compressed.len() < HEADER_SIZE + payload.len());

    assert_eq!(
        only_message(&compressed),
        Received::Notification {
            command: 2002,
            payload,
        }
    );
}

/// Divergence "post-inflate limit" pin: a compressed bucket small enough to
/// pass the header check must not be able to deliver a payload past the
/// limit in force. Without the post-inflate bound, a ~4 KB bucket inflates
/// to over 100 MB and is handed to the caller.
#[cfg(feature = "zstd")]
#[test]
fn compressed_payload_cannot_exceed_the_limit_in_force() {
    use shekyl_levin::{try_compress_message, Flags};

    // 512 KiB of zeros: compresses to a couple of hundred bytes, so the
    // header sails under the 256 KiB pre-handshake limit while the inflated
    // payload is twice that limit.
    let payload = vec![0u8; 512 * 1024];
    let inflated_len = u64::try_from(payload.len()).unwrap();
    assert!(inflated_len > INITIAL_MAX_PACKET_SIZE);

    // Build the compressed bucket post-handshake, where the packet limit
    // permits it, then present it to a pre-handshake reader.
    let mut builder = shekyl_levin::BucketHead::make(2002, inflated_len, Flags::REQUEST, false);
    builder.return_code = 0;
    let mut raw = builder.write().to_vec();
    raw.extend_from_slice(&payload);
    let compressed = try_compress_message(raw);
    assert!(
        u64::try_from(compressed.len()).unwrap() < INITIAL_MAX_PACKET_SIZE,
        "the bucket itself must pass the header check"
    );

    let mut reader = BucketReader::new();
    reader.feed(&compressed).unwrap();
    assert_eq!(
        reader.next_message().unwrap_err(),
        Error::OversizeInflate {
            declared: inflated_len,
            limit: INITIAL_MAX_PACKET_SIZE
        }
    );

    // The same bucket is fine once the handshake has raised the limit.
    let mut post = BucketReader::new();
    post.complete_handshake(DEFAULT_MAX_PACKET_SIZE);
    post.feed(&compressed).unwrap();
    assert_eq!(
        post.next_message().unwrap(),
        Some(Received::Notification {
            command: 2002,
            payload,
        })
    );
}
