// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Incremental stream reader: socket bytes in, complete Levin messages out.
//!
//! This is the framing half of the C++ `async_protocol_handler::handle_recv`
//! state machine (`contrib/epee/include/net/levin_protocol_handler_async.h`),
//! without the invoke/response correlation, timers, or command dispatch —
//! payloads come out as opaque bytes for a higher layer to decode.
//!
//! # Feed / pull, one message at a time
//!
//! [`BucketReader::feed`] only buffers bytes; **all** parsing, fragment
//! reassembly, and decompression happen in [`BucketReader::next_message`],
//! which advances the state machine by exactly one bucket per delivered
//! message and hands ownership of that message straight to the caller.
//!
//! That is the shape of the oracle: `handle_recv` dispatches each message to
//! the commands handler *inside* its parse loop, so at most one decoded
//! payload is live at a time and a message that has already been dispatched
//! survives a later bucket in the same read turning out to be malformed.
//! A reader that returned a `Vec` of everything one read completed would
//! break both properties — it would hold every inflated payload of the read
//! simultaneously (a compression bomb multiplier the C++ does not have) and
//! it would discard already-decoded messages on the error path.
//!
//! ```text
//! reader.feed(&socket_bytes)?;
//! while let Some(message) = reader.next_message()? {
//!     dispatch(message);   // one payload live at a time
//! }
//! ```
//!
//! # Mirrored behaviors
//!
//! - early connection-fatal signature check as soon as 8 bytes arrive;
//! - per-header payload-length check against
//!   `min(packet limit, per-command limit)`: the packet limit is 256 KiB
//!   before the handshake and 100 MB after (the caller raises it with
//!   [`BucketReader::complete_handshake`], as the C++ does at its three
//!   handshake sites); the per-command half mirrors the C++
//!   `connection_context::get_max_bytes` hook and is installed with
//!   [`BucketReader::set_max_bytes_for_command`] (the daemon's command
//!   table is cutover-layer policy, not framing);
//! - total buffered-bytes cap (cache + fragment buffer) against that limit;
//! - noise/fragment class = header with **neither** `Q` nor `S` set: `B|E`
//!   is a dummy (discarded), `B` restarts reassembly, `E` completes it and
//!   the reassembled bytes must open with an inner Levin header, which
//!   becomes the message; reassembled inner messages are never recursively
//!   reassembled;
//! - a `COMPRESSED` payload is inflated before delivery and the flag
//!   cleared (an error without the `zstd` feature — `HAVE_ZSTD`-off parity);
//! - classification: `S` + protocol version 1 → [`Received::Response`];
//!   otherwise `Expect Response` non-zero → [`Received::Request`], zero →
//!   [`Received::Notification`]. The version checked is the **logical
//!   message header** (outer for ordinary buckets; inner after fragment
//!   reassembly).
//!
//! Where this reader is deliberately stricter than the oracle, the crate
//! docs ([`crate`]) carry the single authoritative divergence census; the
//! sites below point at it by name rather than restating it.

use crate::compress::decompress_payload;
use crate::error::Error;
use crate::header::{
    signature_matches, BucketHead, Flags, HEADER_SIZE, INITIAL_MAX_PACKET_SIZE, PROTOCOL_VERSION_1,
};

/// A complete message delivered by [`BucketReader::next_message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Received {
    /// One-way notification; no response is expected.
    Notification {
        /// Command identifier.
        command: u32,
        /// Opaque payload bytes (decompressed if the bucket was compressed).
        payload: Vec<u8>,
    },
    /// Request that expects a response with the same command number.
    Request {
        /// Command identifier.
        command: u32,
        /// Opaque payload bytes.
        payload: Vec<u8>,
    },
    /// Response to a previously-sent request.
    Response {
        /// Command identifier (matches the request).
        command: u32,
        /// Command-specific return code.
        return_code: i32,
        /// Opaque payload bytes.
        payload: Vec<u8>,
    },
}

enum State {
    /// Waiting for a complete 33-byte header.
    Head,
    /// Header parsed; waiting for `payload_len` bytes of body.
    Body(BucketHead),
}

/// Incremental Levin demultiplexer for one connection.
pub struct BucketReader {
    /// Socket bytes yet to be fully consumed, plus any already-consumed
    /// prefix not yet reclaimed by [`Self::compact`].
    cache: Vec<u8>,
    /// Start of the unconsumed region in [`Self::cache`]. Advanced past each
    /// completed header/body instead of front-draining (see [`Self::compact`]).
    read_pos: usize,
    fragment: Vec<u8>,
    state: State,
    max_packet_size: u64,
    max_bytes_for_command: fn(u32) -> u64,
    /// Set by the first [`Error`]. Every framing error is connection-fatal in
    /// the oracle, where returning `false` *is* the disconnect; here the
    /// guard and the consequence are separate statements, so the reader
    /// latches instead of trusting the caller to close.
    failed: bool,
}

/// Default per-command limit: no per-command cap (the C++
/// `get_max_bytes` returns `size_t` max for unknown commands).
fn unlimited(_command: u32) -> u64 {
    u64::MAX
}

impl Default for BucketReader {
    fn default() -> Self {
        BucketReader::new()
    }
}

impl BucketReader {
    /// A reader with the pre-handshake packet-size limit
    /// ([`INITIAL_MAX_PACKET_SIZE`]).
    #[must_use]
    pub fn new() -> BucketReader {
        BucketReader {
            cache: Vec::new(),
            read_pos: 0,
            fragment: Vec::new(),
            state: State::Head,
            max_packet_size: INITIAL_MAX_PACKET_SIZE,
            max_bytes_for_command: unlimited,
            failed: false,
        }
    }

    /// Raise the packet-size limit because the p2p handshake has completed.
    ///
    /// This is the **only** way the limit moves, and it is deliberately not a
    /// general setter. A fresh reader is pinned to [`INITIAL_MAX_PACKET_SIZE`]
    /// (256 KiB), which is what structurally caps an unauthenticated peer;
    /// the C++ raises `m_max_packet_size` to `m_config.m_max_packet_size` at
    /// exactly three sites, each gated on the handshake command
    /// (`levin_protocol_handler_async.h:564` inbound, `:661`/`:699` on the
    /// outbound invoke paths). Framing cannot detect handshake completion on
    /// its own — it does not decode command bodies — so the caller must make
    /// this call at that moment and no earlier.
    ///
    /// `post_handshake_limit` mirrors the configurable
    /// `async_protocol_handler_config::m_max_packet_size`, whose only value
    /// in this tree is [`crate::DEFAULT_MAX_PACKET_SIZE`].
    pub fn complete_handshake(&mut self, post_handshake_limit: u64) {
        self.max_packet_size = post_handshake_limit;
    }

    /// Install a per-command payload-size limit, mirroring the C++
    /// `connection_context::get_max_bytes(command)` hook: a header's
    /// `length` is checked against `min(packet limit, hook(command))`.
    /// The command table itself is daemon policy and lives with the future
    /// cutover layer; the default hook imposes no per-command cap.
    pub fn set_max_bytes_for_command(&mut self, hook: fn(u32) -> u64) {
        self.max_bytes_for_command = hook;
    }

    /// The limit in force for one command's payload.
    fn limit_for(&self, command: u32) -> u64 {
        self.max_packet_size
            .min((self.max_bytes_for_command)(command))
    }

    /// Bytes still waiting to be parsed.
    fn pending(&self) -> &[u8] {
        &self.cache[self.read_pos..]
    }

    /// Bytes held by this reader and counted toward the packet-size cap:
    /// buffered-but-unparsed input plus the fragment reassembly buffer. The
    /// consumed-but-not-yet-compacted prefix is not charged — it is already
    /// accounted for by delivered messages.
    ///
    /// No decoded message is retained: [`Self::next_message`] hands each one
    /// to the caller and keeps nothing.
    ///
    /// This is the *charged* size, not the allocated one. The consumed
    /// prefix is reclaimed lazily — and only once it is at least as large as
    /// the tail — so the backing allocation can be up to roughly twice this
    /// value. A caller sizing
    /// backpressure off this number should budget that factor. (The bound
    /// is still strictly tighter than the oracle's
    /// `epee::net_utils::buffer::erase`, which reclaims only when the buffer
    /// is fully consumed.)
    #[must_use]
    pub fn buffered_bytes(&self) -> u64 {
        let pending = self.cache.len() - self.read_pos;
        u64::try_from(pending + self.fragment.len()).expect("buffer lengths fit in u64")
    }

    /// Reclaim the consumed prefix of the receive buffer.
    ///
    /// Front-draining moves the whole remaining tail, so it must be paid for
    /// out of bytes already consumed or a burst of buckets is O(n²). The
    /// proportional trigger below bounds each drain's memmove by the bytes
    /// consumed since the previous one, making a stream amortized O(n) for
    /// any feed size. (The oracle's `epee::net_utils::buffer::erase`,
    /// `contrib/epee/include/net/buffer.h`, only advances an offset and
    /// resets storage when the buffer is fully consumed — the fully-consumed
    /// branch here is that case.)
    fn compact(&mut self) {
        if self.read_pos == 0 {
            return;
        }
        if self.read_pos >= self.cache.len() {
            self.cache.clear();
            self.read_pos = 0;
        } else if self.read_pos >= self.cache.len() - self.read_pos {
            // Tail is no longer than the consumed prefix: the memmove costs
            // at most what this compaction reclaims.
            self.cache.drain(..self.read_pos);
            self.read_pos = 0;
        }
    }

    /// Buffer received bytes. Parsing happens in [`Self::next_message`].
    ///
    /// # Errors
    ///
    /// [`Error::BufferLimit`] if the bytes would push the buffered total
    /// (pending cache + fragment buffer) past the packet-size limit, and
    /// [`Error::Poisoned`] if a previous call already failed. Both are
    /// connection-fatal — see [`Self::next_message`].
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.latching(|reader| {
            // Total buffered-bytes cap, exactly the C++ subtraction shape.
            let buffered = reader.buffered_bytes();
            let incoming = u64::try_from(bytes.len()).expect("slice length fits in u64");
            if incoming > reader.max_packet_size.saturating_sub(buffered) {
                return Err(Error::BufferLimit {
                    limit: reader.max_packet_size,
                });
            }
            reader.cache.extend_from_slice(bytes);
            Ok(())
        })
    }

    /// Parse and return the next complete message, or `None` when the
    /// buffered bytes do not yet complete one.
    ///
    /// Dummies and non-final fragments are consumed silently: a call returns
    /// only when a logical message is ready or the buffer runs short.
    ///
    /// # Errors
    ///
    /// Any [`Error`] is connection-fatal (mirroring `handle_recv` returning
    /// `false`) and **latches**: the reader is poisoned, every later call
    /// returns [`Error::Poisoned`], and the connection must be closed.
    /// Messages completed before the offending bucket have already been
    /// returned by earlier calls and are not lost.
    pub fn next_message(&mut self) -> Result<Option<Received>, Error> {
        self.latching(BucketReader::parse_next)
    }

    /// Run one fallible step, latching [`Self::failed`] on the first error so
    /// a fatal condition cannot be walked past.
    fn latching<T>(
        &mut self,
        step: impl FnOnce(&mut BucketReader) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if self.failed {
            return Err(Error::Poisoned);
        }
        let outcome = step(self);
        if outcome.is_err() {
            self.failed = true;
        }
        outcome
    }

    /// The state machine proper: advance until a message is ready or the
    /// buffered bytes run out.
    fn parse_next(&mut self) -> Result<Option<Received>, Error> {
        loop {
            match self.state {
                State::Head => {
                    let pending = self.pending();
                    if pending.len() < HEADER_SIZE {
                        // Early reject: a wrong signature is fatal as soon as
                        // the first 8 bytes are visible.
                        if pending.len() >= 8 && !signature_matches(pending) {
                            return Err(Error::BadSignature);
                        }
                        self.compact();
                        return Ok(None);
                    }
                    let header_bytes: &[u8; HEADER_SIZE] = pending[..HEADER_SIZE]
                        .try_into()
                        .expect("static header slice");
                    let head = BucketHead::read(header_bytes)?;
                    let limit = self.limit_for(head.command);
                    if head.payload_len > limit {
                        return Err(Error::OversizePacket {
                            claimed: head.payload_len,
                            limit,
                        });
                    }
                    self.read_pos += HEADER_SIZE;
                    self.state = State::Body(head);
                }
                State::Body(head) => {
                    let need = usize::try_from(head.payload_len)
                        .expect("payload_len bounded by max_packet_size");
                    if self.pending().len() < need {
                        self.compact();
                        return Ok(None);
                    }
                    // Consume the body window, then hand its bounds to
                    // `finish_bucket`: dummies and fragments never need an
                    // owned copy, so only ordinary buckets pay for one.
                    // Nothing may compact until those bounds are used.
                    let body = self.read_pos..self.read_pos + need;
                    self.read_pos += need;
                    self.state = State::Head;
                    let message = self.finish_bucket(head, body)?;
                    self.compact();
                    if message.is_some() {
                        return Ok(message);
                    }
                }
            }
        }
    }

    /// Process one complete bucket, whose body occupies `body` in
    /// [`Self::cache`]. Returns `None` for dummies and non-final fragments.
    fn finish_bucket(
        &mut self,
        head: BucketHead,
        body: core::ops::Range<usize>,
    ) -> Result<Option<Received>, Error> {
        let (mut head, payload) = if head.flags.intersects(Flags::REQUEST.union(Flags::RESPONSE)) {
            (head, self.cache[body].to_vec())
        } else {
            match self.absorb_noise_or_fragment(&head, body)? {
                Some(inner) => inner,
                None => return Ok(None),
            }
        };

        // COMPRESSED: inflate before delivery, clear the flag (C++ unsets
        // LEVIN_PACKET_COMPRESSED on m_current_head after a successful
        // inflate; Received does not expose flags, but the local head stays
        // consistent with the oracle and the doc comment).
        //
        // Divergence "post-inflate limit": the *inflated* size is bounded by
        // the same limit the header was checked against, so the delivered
        // payload can never exceed the packet limit this reader documents.
        let payload = if head.flags.contains(Flags::COMPRESSED) {
            let inflated = decompress_payload(&payload, self.limit_for(head.command))?;
            head.flags = head.flags.difference(Flags::COMPRESSED);
            inflated
        } else {
            payload
        };

        Ok(Some(classify(&head, payload)))
    }

    /// Noise / fragment class handler. `None` = dummy or non-final fragment
    /// (nothing to deliver yet). `Some` = a complete logical message ready
    /// for decompression + classification.
    fn absorb_noise_or_fragment(
        &mut self,
        head: &BucketHead,
        body: core::ops::Range<usize>,
    ) -> Result<Option<(BucketHead, Vec<u8>)>, Error> {
        if head.flags.contains(Flags::BEGIN.union(Flags::END)) {
            return Ok(None); // dummy message: discard, body never copied
        }
        if head.flags.contains(Flags::BEGIN) {
            self.fragment.clear();
        }
        // Disjoint field borrows: append straight from the cursor window,
        // with no intermediate owned body.
        self.fragment.extend_from_slice(&self.cache[body]);
        if !head.flags.contains(Flags::END) {
            return Ok(None); // more fragments to come
        }

        let assembled = std::mem::take(&mut self.fragment);
        Ok(Some(self.take_reassembled_inner(assembled)?))
    }

    /// Parse the logical message out of a completed fragment train.
    ///
    /// Two divergences live here — "inner-signature verify" and
    /// "inner-length trim" (crate docs).
    fn take_reassembled_inner(
        &self,
        mut assembled: Vec<u8>,
    ) -> Result<(BucketHead, Vec<u8>), Error> {
        if assembled.len() < HEADER_SIZE {
            return Err(Error::FragmentTooSmall);
        }
        let header_bytes: &[u8; HEADER_SIZE] = assembled[..HEADER_SIZE]
            .try_into()
            .expect("static header slice");
        // Divergence "inner-signature verify" (C++ memcpys unchecked).
        let inner = BucketHead::read(header_bytes)?;
        let limit = self.limit_for(inner.command);
        if inner.payload_len > limit {
            return Err(Error::OversizePacket {
                claimed: inner.payload_len,
                limit,
            });
        }
        let available =
            u64::try_from(assembled.len() - HEADER_SIZE).expect("buffer length fits in u64");
        // Divergence "inner-length trim": the inner length must fit, and the
        // payload is trimmed to it (C++ forwards the zero padding).
        if inner.payload_len > available {
            return Err(Error::InnerLengthTruncated {
                claimed: inner.payload_len,
                available,
            });
        }
        let end =
            HEADER_SIZE + usize::try_from(inner.payload_len).expect("bounded by max_packet_size");
        // Reuse the reassembly buffer as the payload: drop the trailing
        // padding, then shift the inner header off the front. One memmove,
        // no second allocation.
        assembled.truncate(end);
        assembled.drain(..HEADER_SIZE);
        Ok((inner, assembled))
    }
}

/// Classify a fully-parsed, decompressed logical message.
///
/// Divergence "logical-header classification": the version is taken from this
/// header (the delivered logical message), not from a sticky outer-header
/// field (crate docs).
fn classify(head: &BucketHead, payload: Vec<u8>) -> Received {
    if head.protocol_version == PROTOCOL_VERSION_1 && head.flags.contains(Flags::RESPONSE) {
        Received::Response {
            command: head.command,
            return_code: head.return_code,
            payload,
        }
    } else if head.expects_response() {
        Received::Request {
            command: head.command,
            payload,
        }
    } else {
        Received::Notification {
            command: head.command,
            payload,
        }
    }
}
