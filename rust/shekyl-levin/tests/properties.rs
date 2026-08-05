// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Round-trip properties (rule 50): whatever the builders emit, the reader
//! must reconstruct — for arbitrary payloads, commands, return codes, chunk
//! boundaries, and noise sizes. These bite against builder/reader drift
//! (e.g. an off-by-one in fragment padding or a mis-sliced header field);
//! they do NOT pin C++ byte-identity (that is `oracle_kats.rs`).

use proptest::prelude::*;
use shekyl_levin::{
    fragmented_notify, invoke, noise_notify, notify, response, BucketReader, Received, HEADER_SIZE,
};

/// Feed a byte stream to a fresh reader in chunks of at most `chunk` bytes.
fn read_chunked(stream: &[u8], chunk: usize) -> Vec<Received> {
    let mut reader = BucketReader::new();
    let mut got = Vec::new();
    for piece in stream.chunks(chunk.max(1)) {
        got.extend(reader.advance(piece).expect("valid stream must parse"));
    }
    got
}

proptest! {
    #[test]
    fn notify_roundtrips_through_any_chunking(
        command in any::<u32>(),
        payload in proptest::collection::vec(any::<u8>(), 0..4096),
        chunk in 1usize..512,
    ) {
        let got = read_chunked(&notify(command, &payload), chunk);
        prop_assert_eq!(got, vec![Received::Notification { command, payload }]);
    }

    #[test]
    fn invoke_roundtrips_as_request(
        command in any::<u32>(),
        payload in proptest::collection::vec(any::<u8>(), 0..4096),
        chunk in 1usize..512,
    ) {
        let got = read_chunked(&invoke(command, &payload), chunk);
        prop_assert_eq!(got, vec![Received::Request { command, payload }]);
    }

    #[test]
    fn response_roundtrips_with_return_code(
        command in any::<u32>(),
        return_code in any::<i32>(),
        payload in proptest::collection::vec(any::<u8>(), 0..4096),
        chunk in 1usize..512,
    ) {
        let got = read_chunked(&response(command, return_code, &payload), chunk);
        prop_assert_eq!(
            got,
            vec![Received::Response { command, return_code, payload }]
        );
    }

    #[test]
    fn noise_of_any_valid_size_is_silently_discarded(
        noise_bytes in HEADER_SIZE..8192usize,
        chunk in 1usize..512,
    ) {
        let got = read_chunked(&noise_notify(noise_bytes).unwrap(), chunk);
        prop_assert!(got.is_empty());
    }

    /// The fragmentation contract, for arbitrary payload/noise combinations:
    /// every emitted message is exactly `noise_size` bytes on the wire, and
    /// the reader delivers a single notification. When the message had to be
    /// fragmented the delivered payload is byte-identical; when it fit in one
    /// noise bucket the payload is the original zero-padded to fill the
    /// bucket (`length` covers the padding in that case — C++ parity).
    #[test]
    fn fragmented_notify_roundtrips_at_noise_granularity(
        command in any::<u32>(),
        payload in proptest::collection::vec(any::<u8>(), 0..8192),
        noise_size in (HEADER_SIZE * 2)..2048usize,
        chunk in 1usize..512,
    ) {
        let stream = fragmented_notify(noise_size, command, &payload).unwrap();
        prop_assert_eq!(stream.len() % noise_size, 0, "wire is noise-granular");

        let got = read_chunked(&stream, chunk);
        prop_assert_eq!(got.len(), 1);
        let Received::Notification { command: got_command, payload: got_payload } =
            got.into_iter().next().unwrap()
        else {
            return Err(TestCaseError::fail("expected a notification"));
        };
        prop_assert_eq!(got_command, command);

        if HEADER_SIZE + payload.len() <= noise_size {
            // Unfragmented pad-to-noise case.
            prop_assert_eq!(got_payload.len(), noise_size - HEADER_SIZE);
            prop_assert_eq!(&got_payload[..payload.len()], &payload[..]);
            prop_assert!(got_payload[payload.len()..].iter().all(|&b| b == 0));
        } else {
            // Fragmented case: exact payload, padding trimmed.
            prop_assert_eq!(got_payload, payload);
        }
    }
}
