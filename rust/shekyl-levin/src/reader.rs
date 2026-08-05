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
//! - per-header payload-length check against the packet-size limit (256 KiB
//!   before the handshake, raised to 100 MB after — the caller flips this
//!   with [`BucketReader::set_max_packet_size`], as the C++ does on
//!   handshake completion);
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
//!   [`Received::Notification`].
//!
//! Two **documented divergences** from the C++, both strictly tighter (no
//! conforming sender trips them, and `make_fragmented_notify` output always
//! passes):
//!
//! 1. the reassembled inner header's *signature* is verified; the C++
//!    `memcpy`s it without checking;
//! 2. the inner header's `length` must fit the reassembled bytes, and the
//!    delivered payload is trimmed to exactly that length; the C++ forwards
//!    the fragment zero-padding to the command handler and relies on the
//!    payload parser ignoring trailing bytes.

use crate::compress::decompress_payload;
use crate::error::Error;
use crate::header::{
    signature_matches, BucketHead, Flags, HEADER_SIZE, INITIAL_MAX_PACKET_SIZE, PROTOCOL_VERSION_1,
};

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
    cache: Vec<u8>,
    fragment: Vec<u8>,
    state: State,
    max_packet_size: u64,
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
            fragment: Vec::new(),
            state: State::Head,
            max_packet_size: INITIAL_MAX_PACKET_SIZE,
        }
    }

    /// Change the packet-size limit. The C++ raises it to
    /// [`crate::DEFAULT_MAX_PACKET_SIZE`] once the p2p handshake completes.
    pub fn set_max_packet_size(&mut self, limit: u64) {
        self.max_packet_size = limit;
    }

    /// Feed received bytes; returns every message completed by them.
    ///
    /// # Errors
    ///
    /// Any [`Error`] is connection-fatal (mirroring `handle_recv` returning
    /// `false`); the reader must be discarded along with the connection.
    pub fn advance(&mut self, bytes: &[u8]) -> Result<Vec<Received>, Error> {
        // Total buffered-bytes cap, exactly the C++ subtraction shape.
        let buffered = u64::try_from(self.cache.len() + self.fragment.len())
            .expect("buffer lengths fit in u64");
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
                    if self.cache.len() < HEADER_SIZE {
                        // Early reject: a wrong signature is fatal as soon as
                        // the first 8 bytes are visible.
                        if self.cache.len() >= 8 && !signature_matches(&self.cache) {
                            return Err(Error::BadSignature);
                        }
                        break;
                    }
                    let header_bytes: &[u8; HEADER_SIZE] = self.cache[..HEADER_SIZE]
                        .try_into()
                        .expect("static header slice");
                    let head = BucketHead::read(header_bytes)?;
                    if head.payload_len > self.max_packet_size {
                        return Err(Error::OversizePacket {
                            claimed: head.payload_len,
                            limit: self.max_packet_size,
                        });
                    }
                    self.cache.drain(..HEADER_SIZE);
                    self.state = State::Body(head);
                }
                State::Body(head) => {
                    let need = usize::try_from(head.payload_len)
                        .expect("payload_len bounded by max_packet_size");
                    if self.cache.len() < need {
                        break;
                    }
                    let body: Vec<u8> = self.cache.drain(..need).collect();
                    self.state = State::Head;
                    if let Some(message) = self.finish_bucket(&head, body)? {
                        received.push(message);
                    }
                }
            }
        }

        Ok(received)
    }

    /// Process one complete bucket body. Returns `None` for dummies and
    /// non-final fragments.
    fn finish_bucket(
        &mut self,
        head: &BucketHead,
        body: Vec<u8>,
    ) -> Result<Option<Received>, Error> {
        let (head, payload) = if head.flags.intersects(Flags::REQUEST.union(Flags::RESPONSE)) {
            (*head, body)
        } else {
            // Noise / fragment class.
            if head.flags.contains(Flags::BEGIN.union(Flags::END)) {
                return Ok(None); // dummy message: discard
            }
            if head.flags.contains(Flags::BEGIN) {
                self.fragment.clear();
            }
            self.fragment.extend_from_slice(&body);
            if !head.flags.contains(Flags::END) {
                return Ok(None); // more fragments to come
            }

            // Final fragment: the reassembled bytes must open with an inner
            // Levin header for a non-fragment message.
            let assembled = std::mem::take(&mut self.fragment);
            if assembled.len() < HEADER_SIZE {
                return Err(Error::FragmentTooSmall);
            }
            let header_bytes: &[u8; HEADER_SIZE] = assembled[..HEADER_SIZE]
                .try_into()
                .expect("static header slice");
            // Divergence 1: signature verified (C++ memcpys unchecked).
            let inner = BucketHead::read(header_bytes)?;
            if inner.payload_len > self.max_packet_size {
                return Err(Error::OversizePacket {
                    claimed: inner.payload_len,
                    limit: self.max_packet_size,
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
            let end = HEADER_SIZE
                + usize::try_from(inner.payload_len).expect("bounded by max_packet_size");
            (inner, assembled[HEADER_SIZE..end].to_vec())
        };

        // COMPRESSED: inflate before delivery, clear the flag.
        let payload = if head.flags.contains(Flags::COMPRESSED) {
            decompress_payload(&payload)?
        } else {
            payload
        };

        // Classification, mirroring `is_response` + `m_have_to_return_data`.
        let message = if head.protocol_version == PROTOCOL_VERSION_1
            && head.flags.contains(Flags::RESPONSE)
        {
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
        };
        Ok(Some(message))
    }
}
