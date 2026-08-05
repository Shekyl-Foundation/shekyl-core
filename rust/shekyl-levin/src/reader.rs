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
//! Mirrored behaviors:
//!
//! - early connection-fatal signature check as soon as 8 bytes arrive;
//! - per-header payload-length check against
//!   `min(packet limit, per-command limit)`: the packet limit is 256 KiB
//!   before the handshake and 100 MB after (the caller flips this with
//!   [`BucketReader::set_max_packet_size`], as the C++ does on handshake
//!   completion); the per-command half mirrors the C++
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
//!   reassembly) — see divergence 3 below.
//!
//! Three **documented divergences** from the C++, all equivalent for every
//! conforming sender (and for every packet `make_fragmented_notify` emits):
//!
//! 1. the reassembled inner header's *signature* is verified; the C++
//!    `memcpy`s it without checking;
//! 2. the inner header's `length` must fit the reassembled bytes, and the
//!    delivered payload is trimmed to exactly that length; the C++ forwards
//!    the fragment zero-padding to the command handler and relies on the
//!    payload parser ignoring trailing bytes;
//! 3. response classification uses the **logical message's**
//!    `protocol_version` (the inner header after reassembly). The C++
//!    sticky `m_oponent_protocol_ver` is refreshed only on outer-header
//!    parse, so a crafted fragment train can disagree with this crate on
//!    whether a reassembled bucket is a response. Conforming fragment
//!    outer headers always carry version 1, and the protocol's fragment
//!    emitters only produce notifications — so no live peer is affected.
//!    Classifying the delivered header is the simpler, intentional model.

use crate::compress::decompress_payload;
use crate::error::Error;
use crate::header::{
    signature_matches, BucketHead, Flags, HEADER_SIZE, INITIAL_MAX_PACKET_SIZE, PROTOCOL_VERSION_1,
};

/// Reclaim the consumed prefix of the receive buffer once it exceeds this
/// many bytes. Matches the `shekyl-tor` control-framer discipline: advance a
/// cursor instead of front-draining per message, compact occasionally so a
/// burst of complete buckets is O(n) rather than O(n²).
const COMPACT_THRESHOLD: usize = 4 * 1024;

/// A complete message delivered by [`BucketReader::advance`].
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
    /// completed header/body instead of front-draining (see module docs /
    /// `COMPACT_THRESHOLD`).
    read_pos: usize,
    fragment: Vec<u8>,
    state: State,
    max_packet_size: u64,
    max_bytes_for_command: fn(u32) -> u64,
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
        }
    }

    /// Change the packet-size limit. The C++ raises it to
    /// [`crate::DEFAULT_MAX_PACKET_SIZE`] once the p2p handshake completes.
    pub fn set_max_packet_size(&mut self, limit: u64) {
        self.max_packet_size = limit;
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

    /// Buffered size counted toward the packet-size cap (pending cache +
    /// fragment reassembly buffer). Consumed-but-not-yet-compacted prefix
    /// is not charged — it is already accounted for by completed messages.
    fn buffered_bytes(&self) -> u64 {
        let pending = self.cache.len() - self.read_pos;
        u64::try_from(pending + self.fragment.len()).expect("buffer lengths fit in u64")
    }

    /// Reclaim `cache[..read_pos]` when fully consumed or past
    /// [`COMPACT_THRESHOLD`], so a steady stream stays O(n).
    fn compact(&mut self) {
        if self.read_pos == 0 {
            return;
        }
        if self.read_pos >= self.cache.len() {
            self.cache.clear();
            self.read_pos = 0;
        } else if self.read_pos >= COMPACT_THRESHOLD {
            self.cache.drain(..self.read_pos);
            self.read_pos = 0;
        }
    }

    /// Feed received bytes; returns every message completed by them.
    ///
    /// # Errors
    ///
    /// Any [`Error`] is connection-fatal (mirroring `handle_recv` returning
    /// `false`); the reader must be discarded along with the connection.
    pub fn advance(&mut self, bytes: &[u8]) -> Result<Vec<Received>, Error> {
        // Total buffered-bytes cap, exactly the C++ subtraction shape —
        // applied to unconsumed cache + fragment buffer.
        let buffered = self.buffered_bytes();
        let incoming = u64::try_from(bytes.len()).expect("slice length fits in u64");
        if incoming > self.max_packet_size.saturating_sub(buffered) {
            return Err(Error::BufferLimit {
                limit: self.max_packet_size,
            });
        }

        self.cache.extend_from_slice(bytes);
        let mut received = Vec::new();

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
                        break;
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
                        break;
                    }
                    // Owned body: copy out of the cursor window, then advance.
                    // A split_off/replace would move the tail; with a cursor the
                    // tail stays put and we only allocate the payload once.
                    let body = self.pending()[..need].to_vec();
                    self.read_pos += need;
                    self.state = State::Head;
                    self.compact();
                    if let Some(message) = self.finish_bucket(head, body)? {
                        received.push(message);
                    }
                }
            }
        }

        self.compact();
        Ok(received)
    }

    /// Process one complete bucket body. Returns `None` for dummies and
    /// non-final fragments.
    fn finish_bucket(
        &mut self,
        head: BucketHead,
        body: Vec<u8>,
    ) -> Result<Option<Received>, Error> {
        let (mut head, payload) = if head.flags.intersects(Flags::REQUEST.union(Flags::RESPONSE)) {
            (head, body)
        } else {
            match self.absorb_noise_or_fragment(&head, &body)? {
                Some(inner) => inner,
                None => return Ok(None),
            }
        };

        // COMPRESSED: inflate before delivery, clear the flag (C++ unsets
        // LEVIN_PACKET_COMPRESSED on m_current_head after a successful inflate;
        // Received does not expose flags, but the local head stays consistent
        // with the oracle and the doc comment).
        let payload = if head.flags.contains(Flags::COMPRESSED) {
            let inflated = decompress_payload(&payload)?;
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
        body: &[u8],
    ) -> Result<Option<(BucketHead, Vec<u8>)>, Error> {
        if head.flags.contains(Flags::BEGIN.union(Flags::END)) {
            return Ok(None); // dummy message: discard
        }
        if head.flags.contains(Flags::BEGIN) {
            self.fragment.clear();
        }
        self.fragment.extend_from_slice(body);
        if !head.flags.contains(Flags::END) {
            return Ok(None); // more fragments to come
        }

        let assembled = std::mem::take(&mut self.fragment);
        Ok(Some(self.take_reassembled_inner(&assembled)?))
    }

    /// Parse the logical message out of a completed fragment train.
    ///
    /// Divergences 1 and 2 live here: signature verified; length must fit
    /// and the payload is trimmed to it.
    fn take_reassembled_inner(&self, assembled: &[u8]) -> Result<(BucketHead, Vec<u8>), Error> {
        if assembled.len() < HEADER_SIZE {
            return Err(Error::FragmentTooSmall);
        }
        let header_bytes: &[u8; HEADER_SIZE] = assembled[..HEADER_SIZE]
            .try_into()
            .expect("static header slice");
        // Divergence 1: signature verified (C++ memcpys unchecked).
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
        // Divergence 2: the inner length must fit, and the payload is
        // trimmed to it (C++ forwards the zero padding).
        if inner.payload_len > available {
            return Err(Error::InnerLengthTruncated {
                claimed: inner.payload_len,
                available,
            });
        }
        let end =
            HEADER_SIZE + usize::try_from(inner.payload_len).expect("bounded by max_packet_size");
        Ok((inner, assembled[HEADER_SIZE..end].to_vec()))
    }
}

/// Classify a fully-parsed, decompressed logical message.
///
/// Divergence 3: version is taken from this header (the delivered logical
/// message), not from a sticky outer-header field.
fn classify(head: &BucketHead, payload: Vec<u8>) -> Received {
    if head.protocol_version == PROTOCOL_VERSION_1 && head.flags.contains(Flags::RESPONSE) {
        Received::Response {
            command: head.command,
            return_code: head.return_code,
            payload,
        }
    } else if head.expect_response {
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
