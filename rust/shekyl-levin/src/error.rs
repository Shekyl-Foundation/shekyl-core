// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Framing errors. Every variant is a **connection-fatal** condition in the
//! C++ oracle (`handle_recv` returns `false` and the connection closes).
//! [`crate::BucketReader`] does not rely on the caller to honor that: the
//! first error latches the reader, and every later call returns
//! [`Error::Poisoned`].

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
    /// (`zstd` cargo feature disabled — pure-Rust unavailability path;
    /// the production daemon image always has the feature on).
    #[error("received compressed levin payload but zstd support is not compiled in")]
    CompressionUnavailable,

    /// The zstd frame is malformed or does not declare its content size.
    ///
    /// Kept **distinct from [`Error::OversizeInflate`]** because the two
    /// demand opposite operator responses: a malformed frame is a corrupt
    /// or hostile peer, while an oversized one may be an honest peer whose
    /// batch outgrew the cap. A single "decompression failed" code cannot
    /// tell an operator which of the two they are looking at, and the C++
    /// receive path closes the connection on both.
    #[error("zstd decompression failed: {reason}")]
    Decompress {
        /// Human-readable failure cause (missing frame content size, or the
        /// codec's own error string).
        reason: String,
    },

    /// A zstd frame's *declared* content size exceeds the limit in force —
    /// `min(caller limit, [`crate::DECOMPRESSED_MAX_SIZE`])`. Detected from
    /// the frame header, before any output buffer is allocated.
    #[error("inflated payload would be {declared} bytes, exceeding the limit {limit}")]
    OversizeInflate {
        /// The content size the frame header declared.
        declared: u64,
        /// The limit in force for this bucket.
        limit: u64,
    },

    /// A payload handed to the compressor is larger than any plaintext this
    /// protocol carries ([`crate::DECOMPRESSED_MAX_SIZE`]). Distinct from a
    /// decline: nothing in a conforming caller produces one, so it is a
    /// caller bug rather than "send it uncompressed".
    #[error("payload of {len} bytes exceeds the compressible maximum {limit}")]
    OversizeDeflate {
        /// The payload length the caller offered.
        len: u64,
        /// [`crate::DECOMPRESSED_MAX_SIZE`].
        limit: u64,
    },

    /// The reader already returned a fatal error and was used again. In the
    /// C++ oracle `handle_recv` returning `false` *is* the disconnect, so the
    /// question cannot arise; here the reader latches so a caller that logs
    /// an error and keeps reading cannot keep a malformed peer alive.
    #[error("levin reader used after a fatal framing error; close the connection")]
    Poisoned,

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
