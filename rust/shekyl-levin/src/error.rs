// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Framing errors. Every variant is a **connection-fatal** condition in the
//! C++ oracle (`handle_recv` returns `false` and the connection closes);
//! callers should treat any `Error` from the reader the same way.

/// Levin framing error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The 8-byte signature prefix does not match [`crate::LEVIN_SIGNATURE`].
    /// C++ closes the connection on this as soon as 8 bytes have arrived.
    #[error("levin signature mismatch")]
    BadSignature,

    /// A header (outer or reassembled-inner) claims a payload larger than
    /// the configured packet-size limit.
    #[error("payload length {claimed} exceeds the packet-size limit {limit}")]
    OversizePacket {
        /// The `length` field the header claimed.
        claimed: u64,
        /// The limit in force when the header was parsed.
        limit: u64,
    },

    /// More bytes were buffered than the packet-size limit allows
    /// (mirrors the `handle_recv` cache + fragment-buffer cap).
    #[error("receive buffer would exceed the packet-size limit {limit}")]
    BufferLimit {
        /// The limit in force.
        limit: u64,
    },

    /// A reassembled fragmented message is smaller than one Levin header, so
    /// it cannot contain the required inner message.
    #[error("reassembled fragment smaller than a levin header")]
    FragmentTooSmall,

    /// The reassembled inner message's `length` field claims more bytes than
    /// the fragments actually carried. (Stricter than C++, which forwards
    /// the truncated buffer; a conforming sender never produces this.)
    #[error("inner message length {claimed} exceeds reassembled payload {available}")]
    InnerLengthTruncated {
        /// The inner header's `length` field.
        claimed: u64,
        /// Bytes actually available after the inner header.
        available: u64,
    },

    /// A `COMPRESSED` bucket arrived but this build has no zstd support
    /// (`zstd` cargo feature disabled — the C++ `HAVE_ZSTD`-off behavior).
    #[error("received compressed levin payload but zstd support is not compiled in")]
    CompressionUnavailable,

    /// The zstd frame is malformed, does not declare its content size, or
    /// declares a size above [`crate::DECOMPRESSED_MAX_SIZE`].
    #[error("zstd decompression failed: {reason}")]
    Decompress {
        /// Human-readable failure cause (frame size missing, cap exceeded,
        /// or the codec error string).
        reason: String,
    },

    /// `noise_notify` / `fragmented_notify` was asked for a noise size too
    /// small to carry the required header(s). C++ returns `nullptr`.
    #[error("noise size {requested} below the minimum {minimum}")]
    NoiseTooSmall {
        /// Requested total message size.
        requested: usize,
        /// Minimum size for the requested shape.
        minimum: usize,
    },
}
