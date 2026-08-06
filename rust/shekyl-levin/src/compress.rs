// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `COMPRESSED` flag path — **this module is the policy owner**.
//!
//! Since the 2026-08-06 compression-shim cut the C++
//! `epee::levin::{compress,decompress}_payload` path is a marshaling shim
//! over the `shekyl_levin_*` FFI that reaches these functions: the codec,
//! the 256-byte minimum, the only-if-smaller rule, level 1, and the
//! inflate caps are single-sourced here. Do not "mirror C++" when editing
//! — C++ is the consumer.
//!
//! With the `zstd` cargo feature disabled, compression is a no-op and
//! receiving a compressed bucket is a hard error. That shape exists for
//! pure-Rust unavailability tests (`--no-default-features`); the production
//! daemon image always builds with the feature on.

use crate::error::Error;
use crate::header::{BucketHead, Flags, HEADER_SIZE};

/// Payloads below this size are never compressed (`COMPRESSION_MIN_PAYLOAD`).
pub const COMPRESSION_MIN_PAYLOAD: usize = 256;

/// Safety cap on a zstd frame's declared content size (128 MiB,
/// `DECOMPRESSED_MAX_SIZE`).
pub const DECOMPRESSED_MAX_SIZE: u64 = 128 * 1024 * 1024;

/// zstd compression level (fast mode; `ZSTD_COMPRESSION_LEVEL`).
pub const ZSTD_COMPRESSION_LEVEL: i32 = 1;

/// Whether this build can compress/decompress (`is_compression_available`).
#[must_use]
pub const fn is_compression_available() -> bool {
    cfg!(feature = "zstd")
}

/// Compress one payload under the production Levin policy. Returns `None`
/// — meaning "send it uncompressed" — when compression is unavailable, the
/// payload is below [`COMPRESSION_MIN_PAYLOAD`], the codec fails, or the
/// result is not strictly smaller than the input.
///
/// This is the payload-level seam the C++ shim reaches through the FFI
/// (`shekyl_levin_compress_payload`): the header rewrite stays on whichever
/// side framed the message, and only opaque payload bytes cross.
#[must_use]
pub fn compress_payload(payload: &[u8]) -> Option<Vec<u8>> {
    if !is_compression_available() || payload.len() < COMPRESSION_MIN_PAYLOAD {
        return None;
    }
    let compressed = zstd_compress(payload)?;
    if compressed.len() >= payload.len() {
        return None;
    }
    Some(compressed)
}

/// Try to compress **one** finalized Levin message (header + payload).
///
/// Returns the input unchanged when compression is unavailable, the message
/// is too small, already compressed, below [`COMPRESSION_MIN_PAYLOAD`], or
/// not smaller compressed. On success the returned message carries the
/// `COMPRESSED` flag and a `length` field covering the compressed payload.
///
/// Three inputs are also returned unchanged rather than re-framed — see the
/// crate docs' "emit-side: `try_compress_message` refuses malformed input"
/// divergence:
///
/// - a buffer whose header signature does not verify (the C++ `memcpy`s the
///   header unchecked and would compress it anyway);
/// - a buffer whose header `length` disagrees with the bytes after it — i.e.
///   anything other than exactly one message, such as the multi-bucket
///   stream [`crate::fragmented_notify`] returns. Compressing that would
///   re-frame several buckets as one corrupt bucket;
/// - the noise/fragment class (neither `Q` nor `S`). Every such message is
///   exactly `noise_size` bytes *because* that is the property the
///   white-noise feature exists to provide; compressing one would shorten it
///   and make cover traffic distinguishable from real traffic on the wire.
///
/// None of the three is reachable from the C++ call graph today — the only
/// call site, `make_payload_send_txs` in `src/cryptonote_protocol/
/// levin_notify.cpp`, passes a single `finalize_notify` message, and the
/// covert path's `make_fragmented_notify` output never reaches it — so these
/// are guards against a future caller, not a live defect.
///
/// One cover-traffic case is *not* guardable here: when a notification fits
/// in one noise bucket, `fragmented_notify` emits an ordinary `Q` message
/// zero-padded to the noise size, which carries no wire marking that
/// distinguishes it from any other notification. Keeping that message
/// uncompressed is the calling layer's obligation.
#[must_use]
pub fn try_compress_message(message: Vec<u8>) -> Vec<u8> {
    if !is_compression_available() || message.len() <= HEADER_SIZE {
        return message;
    }
    let Ok(header_bytes) = <&[u8; HEADER_SIZE]>::try_from(&message[..HEADER_SIZE]) else {
        return message;
    };
    let Ok(mut head) = BucketHead::read(header_bytes) else {
        return message;
    };
    if head.flags.contains(Flags::COMPRESSED) {
        return message;
    }
    // Exactly one message: the header must account for every byte after it.
    if head.payload_len != u64::try_from(message.len() - HEADER_SIZE).expect("usize fits in u64") {
        return message;
    }
    // Noise/fragment class: constant on-wire size is the point of it.
    if !head.flags.intersects(Flags::REQUEST.union(Flags::RESPONSE)) {
        return message;
    }
    let Some(compressed) = compress_payload(&message[HEADER_SIZE..]) else {
        return message;
    };

    head.flags = head.flags.union(Flags::COMPRESSED);
    head.payload_len = u64::try_from(compressed.len()).expect("usize fits in u64");

    let mut out = Vec::with_capacity(HEADER_SIZE + compressed.len());
    out.extend_from_slice(&head.write());
    out.extend_from_slice(&compressed);
    out
}

/// Decompress a `COMPRESSED` bucket's payload, bounded by `max_output`.
///
/// The frame must declare its content size, and that size is checked
/// **before any buffer is allocated** against
/// `min(max_output, DECOMPRESSED_MAX_SIZE)`. Callers pass the same limit the
/// bucket header was checked against, so an inflated payload can never
/// exceed the packet-size limit in force — [`DECOMPRESSED_MAX_SIZE`] alone
/// would not achieve that, being larger than
/// [`crate::DEFAULT_MAX_PACKET_SIZE`] and four orders of magnitude above the
/// pre-handshake limit. Checking the declared size first also stops a frame
/// that lies about its content size from costing the full allocation before
/// the codec rejects it.
///
/// # Errors
///
/// [`Error::CompressionUnavailable`] without the `zstd` feature;
/// [`Error::Decompress`] on a malformed, size-less, or oversized frame.
pub fn decompress_payload(input: &[u8], max_output: u64) -> Result<Vec<u8>, Error> {
    zstd_decompress(input, max_output.min(DECOMPRESSED_MAX_SIZE))
}

#[cfg(feature = "zstd")]
fn zstd_compress(payload: &[u8]) -> Option<Vec<u8>> {
    zstd::bulk::compress(payload, ZSTD_COMPRESSION_LEVEL).ok()
}

#[cfg(not(feature = "zstd"))]
fn zstd_compress(_payload: &[u8]) -> Option<Vec<u8>> {
    None
}

#[cfg(feature = "zstd")]
fn zstd_decompress(input: &[u8], limit: u64) -> Result<Vec<u8>, Error> {
    let declared = zstd::zstd_safe::get_frame_content_size(input)
        .map_err(|err| Error::Decompress {
            reason: format!("cannot read frame header: {err}"),
        })?
        .ok_or_else(|| Error::Decompress {
            reason: "frame does not declare its content size".to_owned(),
        })?;
    // Checked before allocating: `zstd::bulk::decompress` reserves the
    // capacity it is given up front, so a lying frame must not get that far.
    if declared > limit {
        return Err(Error::Decompress {
            reason: format!("frame claims {declared} bytes, exceeds the limit {limit}"),
        });
    }
    let capacity = usize::try_from(declared).map_err(|_| Error::Decompress {
        reason: format!("frame claims {declared} bytes, exceeds address space"),
    })?;
    zstd::bulk::decompress(input, capacity).map_err(|err| Error::Decompress {
        reason: err.to_string(),
    })
}

#[cfg(not(feature = "zstd"))]
fn zstd_decompress(_input: &[u8], _limit: u64) -> Result<Vec<u8>, Error> {
    Err(Error::CompressionUnavailable)
}

#[cfg(all(test, feature = "zstd"))]
mod tests {
    use super::*;
    use crate::fragment::{fragmented_notify, noise_notify};
    use crate::message::notify;

    #[test]
    fn small_payload_not_compressed() {
        let msg = notify(2002, &[0u8; COMPRESSION_MIN_PAYLOAD - 1]);
        assert_eq!(try_compress_message(msg.clone()), msg);
    }

    #[test]
    fn compressible_payload_roundtrips() {
        let payload = vec![0u8; 4096];
        let msg = notify(2002, &payload);
        let compressed = try_compress_message(msg.clone());
        assert_ne!(compressed, msg);

        let head = BucketHead::read(compressed[..HEADER_SIZE].try_into().unwrap()).unwrap();
        assert!(head.flags.contains(Flags::COMPRESSED));
        assert_eq!(
            head.payload_len,
            u64::try_from(compressed.len() - HEADER_SIZE).unwrap()
        );

        let decompressed =
            decompress_payload(&compressed[HEADER_SIZE..], DECOMPRESSED_MAX_SIZE).unwrap();
        assert_eq!(decompressed, payload);
    }

    #[test]
    fn already_compressed_left_alone() {
        let msg = try_compress_message(notify(2002, &vec![0u8; 4096]));
        let twice = try_compress_message(msg.clone());
        assert_eq!(twice, msg);
    }

    #[test]
    fn garbage_frame_rejected() {
        assert!(decompress_payload(b"not a zstd frame", DECOMPRESSED_MAX_SIZE).is_err());
    }

    /// The declared content size is rejected against the caller's limit, not
    /// only against `DECOMPRESSED_MAX_SIZE` — and before any allocation.
    #[test]
    fn declared_size_over_the_callers_limit_rejected() {
        let payload = vec![0u8; 4096];
        let compressed = try_compress_message(notify(2002, &payload));
        let frame = &compressed[HEADER_SIZE..];

        // Well under DECOMPRESSED_MAX_SIZE, so only the caller's limit bites.
        let err = decompress_payload(frame, 1024).unwrap_err();
        assert!(
            matches!(err, Error::Decompress { ref reason } if reason.contains("exceeds the limit")),
            "unexpected error: {err:?}"
        );
        // The same frame at a sufficient limit still inflates.
        assert_eq!(decompress_payload(frame, 4096).unwrap(), payload);
    }

    /// A multi-bucket buffer must come back untouched: compressing it would
    /// re-frame several buckets as one corrupt bucket.
    #[test]
    fn multi_bucket_input_left_alone() {
        let payload: Vec<u8> = (0u32..4000)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let stream = fragmented_notify(1024, 114, &payload).unwrap();
        assert!(stream.len() > 1024, "must be more than one bucket");
        assert_eq!(try_compress_message(stream.clone()), stream);
    }

    /// Compressing a dummy would shorten it, and constant on-wire size is
    /// exactly what the white-noise feature buys.
    #[test]
    fn noise_class_left_alone() {
        let dummy = noise_notify(4096).unwrap();
        assert_eq!(try_compress_message(dummy.clone()), dummy);
    }

    /// A header whose `length` disagrees with the buffer is not one message.
    #[test]
    fn header_length_disagreeing_with_buffer_left_alone() {
        let mut msg = notify(2002, &vec![0u8; 4096]);
        msg.extend_from_slice(&[0u8; 16]); // trailing bytes the header omits
        assert_eq!(try_compress_message(msg.clone()), msg);
    }
}

/// Feature-off unavailability path: with the `zstd` feature disabled,
/// compression is the identity and a `COMPRESSED` bucket is a hard error.
/// Without these the `--no-default-features` CI leg would only prove the
/// crate compiles.
#[cfg(all(test, not(feature = "zstd")))]
mod tests_without_zstd {
    use super::*;
    use crate::message::notify;

    #[test]
    fn compression_reports_unavailable() {
        assert!(!is_compression_available());
    }

    #[test]
    fn try_compress_is_the_identity() {
        // Large and highly compressible: the only thing stopping it is the
        // absent codec.
        let msg = notify(2002, &vec![0u8; 4096]);
        assert_eq!(try_compress_message(msg.clone()), msg);
    }

    #[test]
    fn decompress_is_a_hard_error() {
        assert_eq!(
            decompress_payload(b"any bytes at all", DECOMPRESSED_MAX_SIZE),
            Err(Error::CompressionUnavailable)
        );
    }
}
