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

    /// A bucket's payload (`m_cb`) exceeds the configured packet-size
    /// limit — claimed by a received header, or by an emit that would
    /// write that `m_cb`.
    #[error("payload length {claimed} exceeds the packet-size limit {limit}")]
    OversizePacket {
        /// The `length` field the header claimed, or would claim on emit.
        claimed: u64,
        /// The limit in force ([`crate::DEFAULT_MAX_PACKET_SIZE`] on emit).
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

    /// A fragment train's inner message claims more payload than its
    /// command's cap (or the packet limit) allows. Refused when the inner
    /// header's last byte arrives, which may be many fragments before the
    /// train ends: the reassembly buffer never grows toward a length this
    /// node would refuse. The outer bucket's own refusal is
    /// [`Error::OversizePacket`].
    #[error("fragmented inner message length {claimed} exceeds the limit {limit}")]
    InnerOversize {
        /// The inner header's `length` field.
        claimed: u64,
        /// The limit in force for the inner command.
        limit: u64,
    },

    /// A fragment that does not end its train left the reassembly buffer
    /// holding the whole inner message, or more. A conforming sender pads
    /// only its last fragment, so every fragment before the last leaves the
    /// inner message incomplete; this train can only be growing past what
    /// its own inner header declared.
    #[error("fragment train holds {held} bytes of a {inner}-byte inner message and has not ended")]
    FragmentOverrun {
        /// The inner message's whole length: its header and its payload.
        inner: u64,
        /// Bytes the train would hold with this fragment.
        held: u64,
    },

    /// A fragment train's inner message is itself of the noise / fragment
    /// class: its header sets neither `REQUEST` nor `RESPONSE`. A train
    /// carries one request or response and nothing else; a dummy or a
    /// fragment inside a train takes no command cap and has no receiver.
    #[error("fragmented inner message is not a request or response (flags {flags:#x})")]
    InnerNotDispatch {
        /// The inner header's flag word.
        flags: u32,
    },

    /// A fragment train's inner message is a request or response of a
    /// command other than the transaction notice. A train carries pieces
    /// of a transaction notice and nothing else (PWD-B12); any other
    /// command travels as one bucket under its own cap. Refused when the
    /// inner header's last byte arrives.
    #[error("fragmented inner message is command {command}, not the transaction notice")]
    InnerNotTransactionNotice {
        /// The command the inner header named.
        command: u32,
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

    /// A bucket header set a flag bit this protocol does not define
    /// (PWD-B3a). Connection-fatal at ingress; the codec still round-trips
    /// the bits (PWC-A6) so this check lives after [`crate::BucketHead::read`].
    #[error("levin header carries unknown flag bits {flags:#x}")]
    UnknownFlags {
        /// The raw flag word, including the unknown bits.
        flags: u32,
    },

    /// A dispatch bucket (`REQUEST` or `RESPONSE` set) named a command
    /// this protocol does not define (PWD-B3a). Noise / fragment headers
    /// are not this error: they carry no command.
    #[error("unknown levin command {command} on a dispatch bucket")]
    UnknownCommand {
        /// The command id the header claimed.
        command: u32,
    },
}
