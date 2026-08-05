// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `COMPRESSED` flag path, mirroring `epee::levin::try_compress_message`
//! and `decompress_payload` (`contrib/epee/src/levin_compression.cpp`).
//! With the `zstd` cargo feature disabled this module behaves exactly like a
//! C++ build without `HAVE_ZSTD`: compression is a no-op and receiving a
//! compressed bucket is a hard error.

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

/// Try to compress a finalized Levin message (header + payload). Returns the
/// input unchanged when compression is unavailable, the message is too small,
/// already compressed, below [`COMPRESSION_MIN_PAYLOAD`], or not smaller
/// compressed. On success the returned message carries the `COMPRESSED` flag
/// and a `length` field covering the compressed payload.
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
    let payload = &message[HEADER_SIZE..];
    if payload.len() < COMPRESSION_MIN_PAYLOAD {
        return message;
    }
    let Some(compressed) = zstd_compress(payload) else {
        return message;
    };
    if compressed.len() >= payload.len() {
        return message;
    }

    head.flags = head.flags.union(Flags::COMPRESSED);
    head.payload_len = u64::try_from(compressed.len()).expect("usize fits in u64");

    let mut out = Vec::with_capacity(HEADER_SIZE + compressed.len());
    out.extend_from_slice(&head.write());
    out.extend_from_slice(&compressed);
    out
}

/// Decompress a `COMPRESSED` bucket's payload. The frame must declare its
/// content size, and that size must not exceed [`DECOMPRESSED_MAX_SIZE`] —
/// both connection-fatal rejections in the C++ oracle.
///
/// # Errors
///
/// [`Error::CompressionUnavailable`] without the `zstd` feature;
/// [`Error::Decompress`] on a malformed, size-less, or oversized frame.
pub fn decompress_payload(input: &[u8]) -> Result<Vec<u8>, Error> {
    zstd_decompress(input)
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
fn zstd_decompress(input: &[u8]) -> Result<Vec<u8>, Error> {
    let declared = zstd::zstd_safe::get_frame_content_size(input)
        .map_err(|err| Error::Decompress {
            reason: format!("cannot read frame header: {err}"),
        })?
        .ok_or_else(|| Error::Decompress {
            reason: "frame does not declare its content size".to_owned(),
        })?;
    if declared > DECOMPRESSED_MAX_SIZE {
        return Err(Error::Decompress {
            reason: format!("frame claims {declared} bytes, exceeds limit"),
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
fn zstd_decompress(_input: &[u8]) -> Result<Vec<u8>, Error> {
    Err(Error::CompressionUnavailable)
}

#[cfg(all(test, feature = "zstd"))]
mod tests {
    use super::*;
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

        let decompressed = decompress_payload(&compressed[HEADER_SIZE..]).unwrap();
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
        assert!(decompress_payload(b"not a zstd frame").is_err());
    }
}
