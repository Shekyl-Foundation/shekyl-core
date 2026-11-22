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
//! [`BucketReader::feed`] only buffers bytes; **all** parsing and fragment
//! reassembly happen in [`BucketReader::next_message`],
//! which advances the state machine by exactly one bucket per delivered
//! message and hands ownership of that message straight to the caller.
//!
//! That is the shape of the oracle: `handle_recv` dispatches each message to
//! the commands handler *inside* its parse loop, so at most one decoded
//! payload is live at a time and a message that has already been dispatched
//! survives a later bucket in the same read turning out to be malformed.
//! A reader that returned a `Vec` of everything one read completed would
//! break both properties — it would hold every payload of the read
//! simultaneously and it would discard already-decoded messages on the
//! error path.
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
//!   `min(packet limit, per-command cap)` after the PWD-B3a flag-class
//!   discriminator ([`crate::ingress_payload_cap`]): unknown flag bits are
//!   rejected; a Q/S-flagged bucket whose command is not a
//!   [`crate::Command`] is rejected; a noise/fragment bucket (neither
//!   Q nor S) takes the class cap ([`crate::CAP_NOISE_CLASS`]) whatever
//!   its command field says, so cover traffic with command 0 is not
//!   treated as an unknown command. The packet limit is
//!   256 KiB before the handshake and 100 MB after (the caller raises it
//!   with [`BucketReader::complete_handshake`], as the C++ does at its
//!   three handshake sites);
//! - total buffered-bytes cap (cache + fragment buffer) against that limit;
//! - noise/fragment class = header with **neither** `Q` nor `S` set: `B|E`
//!   is a dummy (discarded), `B` restarts reassembly, `E` completes it and
//!   the reassembled bytes must open with an inner Levin header, which
//!   becomes the message; reassembled inner messages are never recursively
//!   reassembled.
//!
//! # A fragment train is bounded by its own inner header
//!
//! The inner header is read when its last byte arrives in the reassembly
//! buffer, whichever fragment carries it, and judged there: its signature,
//! its flags, its command's cap. From then on a fragment that does not end
//! the train must leave the inner message incomplete, and the fragment
//! that ends it is copied only as far as the inner message's end: its
//! padding, which is less than that fragment's own body, is never copied.
//! So an unfinished train holds fewer bytes than one inner message its
//! command admits, and the reassembly buffer never holds more than that
//! inner message. What a train does not bound is the bucket in front of
//! it: one fragment's body waits in the receive buffer, up to the packet
//! limit, until the bucket is complete. These checks are
//! stricter than the oracle's, which judged the inner header only when the
//! train ended (crate docs, "inner header judged on arrival", "train
//! overrun", "inner dispatch class").
//!
//! Further:
//!
//! - classification: `S` + protocol version 1 → [`Received::Response`];
//!   otherwise `Expect Response` non-zero → [`Received::Request`], zero →
//!   [`Received::Notification`]. The version checked is the **logical
//!   message header** (outer for ordinary buckets; inner after fragment
//!   reassembly).
//!
//! Where this reader is deliberately stricter than the oracle, the crate
//! docs ([`crate`]) carry the single authoritative divergence census; the
//! sites below point at it by name rather than restating it.

use crate::error::Error;
use crate::header::{
    signature_matches, BucketHead, Flags, HEADER_SIZE, INITIAL_MAX_PACKET_SIZE, PROTOCOL_VERSION_1,
};
use crate::ingress;

/// A complete message delivered by [`BucketReader::next_message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Received {
    /// One-way notification; no response is expected.
    Notification {
        /// Command identifier.
        command: u32,
        /// Opaque payload bytes.
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
        /// Opaque payload bytes.
        payload: Vec<u8>,
    },
}

enum State {
    /// Waiting for a complete 29-byte header.
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
    /// The inner header of the train in [`Self::fragment`], read and
    /// judged when its last byte arrived. `None` while the buffer holds
    /// less than a header; reset wherever the buffer is cleared or taken.
    inner: Option<BucketHead>,
    state: State,
    max_packet_size: u64,
    /// Set by the first [`Error`]. Every framing error is connection-fatal in
    /// the oracle, where returning `false` *is* the disconnect; here the
    /// guard and the consequence are separate statements, so the reader
    /// latches instead of trusting the caller to close.
    failed: bool,
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
            inner: None,
            state: State::Head,
            max_packet_size: INITIAL_MAX_PACKET_SIZE,
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

    /// The limit in force for one parsed header: packet limit and the
    /// PWD-B3 command cap (the class cap for the noise/fragment class).
    fn limit_for(&self, command: u32, flags: Flags) -> Result<u64, Error> {
        let admitted = ingress::ingress_payload_cap(command, flags)?;
        Ok(self.max_packet_size.min(admitted))
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
    /// any feed size. A fully consumed buffer resets its storage instead of
    /// moving an empty tail.
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
                    let limit = self.limit_for(head.command, head.flags)?;
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
        let (head, payload) = if head.flags.intersects(Flags::REQUEST.union(Flags::RESPONSE)) {
            (head, self.cache[body].to_vec())
        } else {
            match self.absorb_noise_or_fragment(&head, body)? {
                Some(inner) => inner,
                None => return Ok(None),
            }
        };

        Ok(Some(classify(&head, payload)))
    }

    /// Noise / fragment class handler. `None` = dummy or non-final fragment
    /// (nothing to deliver yet). `Some` = a complete logical message ready
    /// for classification.
    ///
    /// The train's bounds are applied here, before the fragment's body is
    /// copied into the reassembly buffer (module docs).
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
            self.inner = None;
        }
        let ends = head.flags.contains(Flags::END);
        let held_before = self.fragment.len();
        let mut body = body;

        // The inner header first: copy only the bytes that complete it, and
        // judge it before anything behind it is copied.
        if self.inner.is_none() {
            let missing = HEADER_SIZE - held_before;
            let take = missing.min(body.len());
            self.fragment
                .extend_from_slice(&self.cache[body.start..body.start + take]);
            body.start += take;
            if self.fragment.len() == HEADER_SIZE {
                self.inner = Some(self.judge_inner_header()?);
            }
        }

        if let Some(inner) = self.inner {
            let inner_len = HEADER_SIZE
                + usize::try_from(inner.payload_len).expect("bounded by max_packet_size");
            if ends {
                // The last fragment is the padded one: copy what the inner
                // message still lacks and leave the padding where it is, so
                // the buffer never holds more than the inner message. A
                // body short of that is copied whole and refused below.
                let lacking = inner_len.saturating_sub(self.fragment.len());
                body.end = body.start + lacking.min(body.len());
            } else {
                // Divergence "train overrun": a fragment that does not end
                // the train must leave the inner message incomplete.
                let held = self.fragment.len() + body.len();
                if held >= inner_len {
                    return Err(Error::FragmentOverrun {
                        inner: u64::try_from(inner_len).expect("buffer length fits in u64"),
                        held: u64::try_from(held).expect("buffer length fits in u64"),
                    });
                }
            }
        }

        // Disjoint field borrows: append straight from the cursor window,
        // with no intermediate owned body.
        self.fragment.extend_from_slice(&self.cache[body]);
        if !ends {
            return Ok(None); // more fragments to come
        }

        let assembled = std::mem::take(&mut self.fragment);
        let inner = self.inner.take().ok_or(Error::FragmentTooSmall)?;
        Ok(Some(take_reassembled_inner(inner, assembled)?))
    }

    /// Read and judge the inner header a train's first [`HEADER_SIZE`]
    /// bytes are, as soon as they are all here.
    ///
    /// Four divergences live here — "inner-signature verify", "inner
    /// header judged on arrival", "inner dispatch class" and "train carries
    /// a transaction notice" (crate docs).
    fn judge_inner_header(&self) -> Result<BucketHead, Error> {
        let header_bytes: &[u8; HEADER_SIZE] = self.fragment[..HEADER_SIZE]
            .try_into()
            .expect("static header slice");
        // Divergence "inner-signature verify" (C++ memcpys unchecked).
        let inner = BucketHead::read(header_bytes)?;
        // Divergence "inner dispatch class": a train carries a request or a
        // response. An inner dummy or fragment takes no command cap.
        if !inner
            .flags
            .intersects(Flags::REQUEST.union(Flags::RESPONSE))
        {
            return Err(Error::InnerNotDispatch {
                flags: inner.flags.bits(),
            });
        }
        // Divergence "train carries a transaction notice": nothing else is
        // ever cut into a train.
        if inner.command != crate::NOTIFY_NEW_TRANSACTIONS {
            return Err(Error::InnerNotTransactionNotice {
                command: inner.command,
            });
        }
        // The cap is looked up last: an inner command this crate does not
        // know is refused above as not the transaction notice, the same
        // refusal a known command gets, and never as an unknown command.
        let limit = self.limit_for(inner.command, inner.flags)?;
        if inner.payload_len > limit {
            return Err(Error::InnerOversize {
                claimed: inner.payload_len,
                limit,
            });
        }
        Ok(inner)
    }
}

/// Cut the logical message out of a completed fragment train whose inner
/// header was already judged. `assembled` is the inner header and as much
/// of its payload as the train carried, and never more than the inner
/// message: the last fragment's padding was not copied.
///
/// Divergence "inner-length trim" (crate docs).
fn take_reassembled_inner(
    inner: BucketHead,
    mut assembled: Vec<u8>,
) -> Result<(BucketHead, Vec<u8>), Error> {
    let available =
        u64::try_from(assembled.len() - HEADER_SIZE).expect("buffer length fits in u64");
    // Divergence "inner-length trim": the inner length must fit, and the
    // payload is exactly it (C++ forwards the zero padding).
    if inner.payload_len > available {
        return Err(Error::InnerLengthTruncated {
            claimed: inner.payload_len,
            available,
        });
    }
    debug_assert_eq!(
        available, inner.payload_len,
        "the reassembly buffer never holds more than its inner message"
    );
    // Reuse the reassembly buffer as the payload: shift the inner header
    // off the front. One memmove, no second allocation.
    assembled.drain(..HEADER_SIZE);
    Ok((inner, assembled))
}

/// Classify a fully-parsed logical message.
///
/// Divergence "logical-header classification": the version is taken from this
/// header (the delivered logical message), not from a sticky outer-header
/// field (crate docs).
fn classify(head: &BucketHead, payload: Vec<u8>) -> Received {
    if head.protocol_version == PROTOCOL_VERSION_1 && head.flags.contains(Flags::RESPONSE) {
        Received::Response {
            command: head.command,
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
