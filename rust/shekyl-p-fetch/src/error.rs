// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `SF-D6` taxonomy: what a scheduler learns from a failed attempt.
//!
//! One table, and the axis is the caller's next move, not the mechanism
//! that failed. Every variant answers "name the same `P` again with the
//! same header, name it once more with a fresh one, or name another `P`?"
//! — [`FetchError::next_move`]. The client itself never retries: the
//! header's anchor comes from the caller's chain state, so only the caller
//! can build a fresh one.

use std::fmt;
use std::io;

use shekyl_wire::shard_frame::{ContentMismatch, FrameError};

/// Why a [`fetch`](crate::PFetchClient::fetch) did not return a shard.
#[derive(Debug)]
pub enum FetchError {
    /// **No complete exchange.** The dial failed or timed out, the
    /// connection closed before a complete head, a read stalled, or the
    /// body ended short of its declared length. Includes `P`'s
    /// over-capacity silent close (`RF-R1`), which is indistinguishable on
    /// the wire from a stall and is classed with it on purpose.
    ///
    /// **Retry the same `P` with the same header** — nothing was decided,
    /// and a fresh nonce would mint a pass record for an exchange that
    /// never happened. How many times is the caller's budget.
    Stall(Stall),
    /// **A completed exchange whose answer is "not here."** `P` rendered
    /// its bare 404: the request was valid and `P` does not hold that
    /// shard — unknown or unfrozen, one outcome for both (`RF-R1`). A
    /// fault of `P`'s own is never this; it is [`Self::Unavailable`].
    /// **Name another `P`.** Not a retry of this one:
    /// the same request would render the same 404.
    Miss,
    /// **A completed exchange whose answer is "this request is not valid."**
    /// `P` rendered its bare 400. From this client the route and the header
    /// encoding are fixed, so what it means in practice is that
    /// `anchor_height` fell outside `P`'s gate — and that can be clock or
    /// chain skew on either side, so one 400 says nothing yet about `P`.
    ///
    /// **Name the same `P` once more, with a header built from a freshly
    /// derived anchor.** A fresh nonce is safe: no signature came back, so
    /// no record can carry the old one. A second 400 is a failed read —
    /// `P`'s gate sits within ±`L` of `P`'s own height, so a `P` that
    /// refuses a fresh anchor is itself out of step.
    /// [`Self::next_move`] holds that rule.
    Rejected,
    /// **A completed exchange whose answer is "I cannot serve this right
    /// now."** `P` rendered its bare 503: the fault is `P`'s own — a tip or
    /// a store it could not read, or no resident key — and the response does
    /// not say which. A held shard never 404s, so this is how `P` failing
    /// before the body shows.
    ///
    /// **A failed read: name another `P`.** No retry of this one.
    Unavailable,
    /// **`P` sent the whole body and then said it would not sign.** A 200
    /// of its full declared length whose envelope is the refusal trailer
    /// (`serving_route::is_refusal_trailer`) in place of a signature. `P`
    /// holds the shard and served it; its signer then failed. The body is
    /// discarded unverified — without a signature nothing binds it to this
    /// request.
    ///
    /// **A failed read: name another `P`.** No retry. This is `P`'s own
    /// statement, in bytes only `P` can put on the stream, and that is why
    /// it is not inferred from a response that stopped: a relay can cut a
    /// stream at any byte, the body's end included, and the same guard
    /// sits on every retry. A cut is [`Stall::Truncated`] wherever it
    /// falls.
    Unsigned,
    /// **A completed exchange that is not the contract.** A status other
    /// than 200, 400, 404 or 503, a header set other than the ruled two, a
    /// `content-length` that is missing, unparseable, below the envelope
    /// width, or above the expectation's ceiling, a body that is not the
    /// `shard_frame` grammar or does not end where the envelope begins, or
    /// an envelope that is not a canonical `HybridSignature`. Refused as
    /// soon as it is seen — from the head where the head decides it.
    /// **Name another `P`**; this one is not speaking the protocol.
    Malformed(Malformed),
    /// **`P` served, but the countersignature does not verify** under the
    /// target's bond-record key over this request's transcript. The body
    /// was read and is discarded. **Name another `P`** — and this is the
    /// one outcome that is evidence *about* `P` rather than about the
    /// path, which is why it is typed apart from [`Self::Malformed`].
    BadCountersignature,
    /// **`P` served and signed a well-formed frame whose content is not the
    /// shard the caller expected** — a transaction count, a declared length
    /// or a segment hash off the requester's retained rows
    /// ([`ExpectedShard`](crate::ExpectedShard)). Typed only once the
    /// countersignature has verified: `P` demonstrably answered *this*
    /// request with *these* bytes. **Name another `P`.**
    ///
    /// Against the interim leaf-segment provider every fetch ends in
    /// [`Self::Malformed`] (raw leaf bytes are not the frame's version
    /// byte) or, where they happen to be, here — that `P` serves a body
    /// this grammar does not describe — which is a statement about the
    /// serve side, not evidence against `P` (`SHARD_VIEW_FETCH.md` §4).
    ContentRefused(ContentMismatch),
}

/// What a scheduler does after a failed fetch of one `P` (`SF-D6`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NextMove {
    /// Dial the same `P` again with the **same** header. Nothing was
    /// decided; how many times is the caller's budget.
    RetrySameHeader,
    /// Dial the same `P` **once** more with a header built from a freshly
    /// derived anchor.
    RetryFreshAnchor,
    /// `P` answered "not here". Name another `P`; nothing is held against
    /// this one beyond not serving the shard.
    NotHeld,
    /// The read failed and the failure is `P`'s. Name another `P`.
    FailedRead,
}

impl FetchError {
    /// Whether the scheduler may dial the **same** `P` again with the same
    /// header (`SF-D6`). Only a stall is; every other variant is a
    /// completed decision about this `P`, or needs a different header.
    #[must_use]
    pub fn retries_same_p(&self) -> bool {
        matches!(self, Self::Stall(_))
    }

    /// The scheduler's next move for this `P`.
    ///
    /// `rejected_before` is whether an earlier attempt of this same read
    /// against this same `P` already ended in [`Self::Rejected`]. The first
    /// 400 earns one retry with a fresh anchor; the second is a failed
    /// read. No other variant reads it.
    #[must_use]
    pub fn next_move(&self, rejected_before: bool) -> NextMove {
        match self {
            Self::Stall(_) => NextMove::RetrySameHeader,
            Self::Miss => NextMove::NotHeld,
            Self::Rejected if !rejected_before => NextMove::RetryFreshAnchor,
            Self::Rejected
            | Self::Unavailable
            | Self::Unsigned
            | Self::Malformed(_)
            | Self::BadCountersignature
            | Self::ContentRefused(_) => NextMove::FailedRead,
        }
    }
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stall(s) => write!(f, "stall: {s}"),
            Self::Miss => f.write_str("miss: P answered 404"),
            Self::Rejected => f.write_str("rejected: P answered 400"),
            Self::Unavailable => f.write_str("unavailable: P answered 503"),
            Self::Unsigned => {
                f.write_str("P sent the whole body and a refusal in place of the countersignature")
            }
            Self::Malformed(m) => write!(f, "malformed response: {m}"),
            Self::BadCountersignature => {
                f.write_str("countersignature does not verify under the target key")
            }
            Self::ContentRefused(m) => write!(f, "content refused: {m}"),
        }
    }
}

impl std::error::Error for FetchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Stall(Stall::Io(e)) => Some(e),
            Self::ContentRefused(m) => Some(m),
            Self::Malformed(Malformed::Frame(e)) => Some(e),
            _ => None,
        }
    }
}

/// Where a [`FetchError::Stall`] stopped. Diagnostic detail only: every
/// arm has the same disposition.
#[derive(Debug)]
pub enum Stall {
    /// The SOCKS dial did not complete within the connect bound — the
    /// proxy was slow to answer, or the rendezvous with `P`'s onion did
    /// not happen in time.
    DialTimeout,
    /// The proxy refused the CONNECT (general failure, host unreachable,
    /// connection refused, …), or the handshake itself failed. `P` is
    /// unreachable from this proxy right now.
    Dial(String),
    /// No complete head arrived within the head bound.
    HeadTimeout,
    /// No complete head: the connection closed or reset while the request
    /// was being written or the head was being read — `P`'s over-capacity
    /// or oversized-request close (`RF-R1`), a mid-head drop, or any other
    /// pre-head I/O error. No exchange happened.
    ClosedBeforeHead,
    /// A body read made no progress within the stall bound, or the whole
    /// body did not arrive within its deadline.
    BodyTimeout,
    /// The connection closed with fewer body bytes than `content-length`
    /// declared, at whatever offset. Never read as `P` declining to sign:
    /// that is the refusal trailer ([`FetchError::Unsigned`]), which `P`
    /// writes and a relay cannot.
    Truncated {
        /// Bytes `content-length` declared.
        declared: u64,
        /// Bytes that arrived.
        received: u64,
    },
    /// Exactly `content-length` bytes arrived and then `P` neither closed
    /// nor sent more within the stall bound. `RF-R1` closes after the body;
    /// a `P` that holds the connection open is wedged, not lying, so this
    /// is retried like any other stall — and it is the only way the client
    /// can tell "nothing more came" from "nothing more came *yet*".
    NoClose,
    /// An I/O error on the stream **after** a complete head (body drain or
    /// the close probe). Pre-head I/O is [`Self::ClosedBeforeHead`]: no
    /// exchange happened, so it is not a short body.
    Io(io::Error),
}

impl fmt::Display for Stall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DialTimeout => f.write_str("dial timed out"),
            Self::Dial(reason) => write!(f, "dial failed: {reason}"),
            Self::HeadTimeout => f.write_str("no complete head before the head bound"),
            Self::ClosedBeforeHead => f.write_str("connection closed before a complete head"),
            Self::BodyTimeout => f.write_str("body read stalled"),
            Self::Truncated { declared, received } => {
                write!(f, "body truncated: {received} of {declared} bytes")
            }
            Self::NoClose => f.write_str("body complete but P did not close"),
            Self::Io(e) => write!(f, "i/o: {e}"),
        }
    }
}

/// How a complete head, or the envelope behind it, departed from the
/// contract. Diagnostic detail only: every arm has the same disposition.
#[derive(Debug, PartialEq, Eq)]
pub enum Malformed {
    /// Bytes kept arriving past the head bound with no `\r\n\r\n`. Not a
    /// stall — the stream is flowing — and not the contract.
    HeadTooLong,
    /// The status line did not parse as `HTTP/1.x <3-digit> …`.
    StatusLine,
    /// A parseable status that is not 200, 400, 404 or 503.
    Status(u16),
    /// The header set is not exactly `RESPONSE_HEADER_NAMES`, or a name
    /// repeats, or a line is not `name: value`.
    HeaderSet,
    /// `content-type` is not the ruled type.
    ContentType,
    /// `content-length` is missing, unparseable, or (on a 400, a 404 or a
    /// 503) non-zero.
    ContentLength,
    /// `content-length` is shorter than the fixed-width signature envelope
    /// — there cannot be a countersignature in it.
    EnvelopeShort {
        /// Bytes `content-length` declared.
        declared: u64,
    },
    /// `content-length` exceeds the expectation's
    /// [`max_response_len`](crate::ExpectedShard::max_response_len).
    /// Refused from the head, before a body byte is read: the declaration
    /// comes from a potentially adversarial `P`, and the ceiling from the
    /// requester's own rows.
    Oversize {
        /// Bytes `content-length` declared.
        declared: u64,
        /// The ceiling it exceeded.
        max: u64,
    },
    /// More body bytes arrived than `content-length` declared — "body long
    /// of agreed `N`" (`SF-D6`). Detected either in the bytes that came
    /// with the head or on the probe for `P`'s close after exactly `N`;
    /// the excess is not read, only observed.
    Overlength {
        /// Bytes `content-length` declared.
        declared: u64,
    },
    /// The body is not the `shard_frame` grammar: a version byte that is
    /// not the frame's, or a varint that does not decode. Refused where it
    /// is read; the rest of the body is not drained.
    Frame(FrameError),
    /// The frame ran into the envelope: a varint or a segment still wanted
    /// bytes when the content ahead of the signature was spent. The frame
    /// `P` declared is longer than the body `P` sent.
    FrameShort,
    /// The frame ended with content bytes still ahead of the envelope. A
    /// frame ends exactly where the declared length says (`SF-D6`: body
    /// long of agreed `N`), not at a parse that happened to finish.
    FrameLong,
    /// The trailing envelope bytes are not a canonical `HybridSignature`.
    Envelope,
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeadTooLong => f.write_str("head exceeded its bound without terminating"),
            Self::StatusLine => f.write_str("status line does not parse"),
            Self::Status(code) => write!(f, "status {code} is not 200, 400, 404 or 503"),
            Self::HeaderSet => f.write_str("header set is not the ruled two"),
            Self::ContentType => f.write_str("content-type is not the ruled type"),
            Self::ContentLength => f.write_str("content-length missing or invalid"),
            Self::EnvelopeShort { declared } => {
                write!(
                    f,
                    "content-length {declared} is shorter than the signature envelope"
                )
            }
            Self::Oversize { declared, max } => {
                write!(
                    f,
                    "content-length {declared} exceeds the body ceiling {max}"
                )
            }
            Self::Overlength { declared } => {
                write!(
                    f,
                    "more body bytes than the declared content-length {declared}"
                )
            }
            Self::Frame(e) => write!(f, "body is not the shard frame: {e}"),
            Self::FrameShort => f.write_str("frame ran into the signature envelope"),
            Self::FrameLong => {
                f.write_str("frame ended with content bytes still ahead of the envelope")
            }
            Self::Envelope => f.write_str("envelope is not a canonical hybrid signature"),
        }
    }
}
