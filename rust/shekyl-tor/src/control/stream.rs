// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Parsing of `650 STREAM` async events — the DQ-T0.4 measurement's signal.
//!
//! The circuit-ID disjointness measurement reads the **attach-time** circuit
//! identifier of a SOCKS stream: at `SENTCONNECT`, Tor has chosen the circuit and
//! sent the `BEGIN` cell, and the `STREAM` event carries that `CircID`. This module
//! turns a framed `650 STREAM` reply into a typed [`StreamEvent`] the harness can
//! filter (to its one fixed test target) and compare by [`CircId`].
//!
//! Sans-IO and pure: it parses an already-framed [`ControlReply`], so it is pinned
//! by KATs in the unit gate. The waiting/timeout that captures these events off a
//! live socket lives in the measurement harness, never here.

use super::framing::{ControlReply, ASYNC_EVENT_STATUS};

/// A Tor circuit identifier (control-protocol `CircuitID`).
///
/// A **forensic** value under the crate's no-log invariant (circuit IDs must not
/// reach a log), so its [`Debug`] is redacted; the measurement compares it by
/// value (`==`), which is all the disjointness check needs.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CircId(u64);

impl CircId {
    /// Wrap a raw circuit identifier.
    #[must_use]
    pub fn new(id: u64) -> Self {
        Self(id)
    }
}

impl std::fmt::Debug for CircId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the circuit id.
        f.write_str("CircId(<redacted>)")
    }
}

/// The `StreamStatus` field of a `STREAM` event (control-spec §4.1.2). Only the
/// states the measurement distinguishes are named; everything else is
/// [`Self::Other`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamStatus {
    /// A new request to connect.
    New,
    /// The circuit is chosen and `BEGIN` is sent — **the attach moment the
    /// measurement reads the CircID at.**
    SentConnect,
    /// The exit reported success.
    Succeeded,
    /// The stream failed.
    Failed,
    /// The stream closed.
    Closed,
    /// The stream detached from its circuit.
    Detached,
    /// Any other status (`NEWRESOLVE`, `REMAP`, …) the measurement ignores.
    Other,
}

impl StreamStatus {
    fn parse(s: &str) -> Self {
        match s {
            "NEW" => Self::New,
            "SENTCONNECT" => Self::SentConnect,
            "SUCCEEDED" => Self::Succeeded,
            "FAILED" => Self::Failed,
            "CLOSED" => Self::Closed,
            "DETACHED" => Self::Detached,
            _ => Self::Other,
        }
    }

    /// `true` at `SENTCONNECT` — the circuit-attach moment.
    #[must_use]
    pub fn is_sent_connect(self) -> bool {
        matches!(self, Self::SentConnect)
    }
}

/// A parsed `650 STREAM` event.
///
/// `target` (the dial destination) is **forensic**, so the [`Debug`] omits it; the
/// measurement compares it to its own fixed test target via [`Self::target`]. The
/// fields the disjointness check needs are reached through the accessors, not
/// public fields.
#[derive(Clone, PartialEq, Eq)]
pub struct StreamEvent {
    stream_id: u64,
    status: StreamStatus,
    circ_id: CircId,
    target: String,
}

impl StreamEvent {
    /// The stream's id.
    #[must_use]
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// The stream's status.
    #[must_use]
    pub fn status(&self) -> StreamStatus {
        self.status
    }

    /// The circuit the stream is on (`0` until it attaches; meaningful at
    /// `SENTCONNECT`).
    #[must_use]
    pub fn circ_id(&self) -> CircId {
        self.circ_id
    }

    /// The dial target (`host:port`) — compared to the harness's fixed test target
    /// to drop background directory streams. A forensic surface; do not log it.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }
}

impl std::fmt::Debug for StreamEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `target` is omitted (forensic); `circ_id`'s own Debug is redacted.
        f.debug_struct("StreamEvent")
            .field("stream_id", &self.stream_id)
            .field("status", &self.status)
            .field("circ_id", &self.circ_id)
            .finish_non_exhaustive()
    }
}

/// Parse a `650 STREAM <StreamID> <StreamStatus> <CircID> <Target> …` event.
///
/// Returns `None` if the reply is not a `650` async event, is not a `STREAM`
/// event, or is missing the leading fixed fields. Trailing optional args
/// (`SOURCE_ADDR=`, `PURPOSE=`, …) are ignored.
#[must_use]
pub fn parse_stream_event(reply: &ControlReply) -> Option<StreamEvent> {
    if reply.status() != ASYNC_EVENT_STATUS {
        return None;
    }
    let line = reply.lines().first()?;
    let mut fields = line.split_ascii_whitespace();
    if fields.next()? != "STREAM" {
        return None;
    }
    let stream_id = fields.next()?.parse().ok()?;
    let status = StreamStatus::parse(fields.next()?);
    let circ_id = CircId(fields.next()?.parse().ok()?);
    let target = fields.next()?.to_owned();
    Some(StreamEvent {
        stream_id,
        status,
        circ_id,
        target,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::framing::ReplyFramer;

    /// Frame exactly one reply from a wire fragment (the path the actor uses).
    fn frame_one(bytes: &[u8]) -> ControlReply {
        let mut framer = ReplyFramer::default();
        framer.push_bytes(bytes);
        framer
            .next_reply()
            .expect("frames cleanly")
            .expect("one complete reply")
    }

    #[test]
    fn parses_a_sentconnect_event_with_its_circid() {
        let ev = parse_stream_event(&frame_one(
            b"650 STREAM 42 SENTCONNECT 2167179189 127.0.0.1:7001\r\n",
        ))
        .expect("a STREAM event");
        assert_eq!(ev.stream_id(), 42);
        assert_eq!(ev.status(), StreamStatus::SentConnect);
        assert!(ev.status().is_sent_connect());
        assert_eq!(ev.circ_id(), CircId::new(2_167_179_189));
        assert_eq!(ev.target(), "127.0.0.1:7001");
    }

    #[test]
    fn parses_a_new_event_with_unattached_circ_zero() {
        let ev = parse_stream_event(&frame_one(b"650 STREAM 7 NEW 0 127.0.0.1:7001\r\n"))
            .expect("event");
        assert_eq!(ev.status(), StreamStatus::New);
        assert!(!ev.status().is_sent_connect());
        assert_eq!(ev.circ_id(), CircId::new(0));
    }

    #[test]
    fn ignores_trailing_optional_args() {
        let ev = parse_stream_event(&frame_one(
            b"650 STREAM 9 SENTCONNECT 55 127.0.0.1:80 SOURCE_ADDR=127.0.0.1:5000 PURPOSE=USER\r\n",
        ))
        .expect("event");
        assert_eq!(ev.circ_id(), CircId::new(55));
        assert_eq!(ev.target(), "127.0.0.1:80");
    }

    #[test]
    fn distinct_circuits_compare_unequal_same_circuit_equal() {
        let a1 = parse_stream_event(&frame_one(b"650 STREAM 1 SENTCONNECT 100 t:1\r\n")).unwrap();
        let a2 = parse_stream_event(&frame_one(b"650 STREAM 2 SENTCONNECT 100 t:1\r\n")).unwrap();
        let b = parse_stream_event(&frame_one(b"650 STREAM 3 SENTCONNECT 200 t:1\r\n")).unwrap();
        // Same circuit id across two streams compares equal (the positive control);
        // a different circuit compares unequal (the isolation invariant).
        assert_eq!(a1.circ_id(), a2.circ_id());
        assert_ne!(a1.circ_id(), b.circ_id());
    }

    #[test]
    fn rejects_a_non_event_reply() {
        assert!(parse_stream_event(&frame_one(b"250 OK\r\n")).is_none());
    }

    #[test]
    fn rejects_a_non_stream_event() {
        // A 650 CIRC event is not a STREAM event.
        assert!(parse_stream_event(&frame_one(b"650 CIRC 1 BUILT a,b,c\r\n")).is_none());
    }

    #[test]
    fn rejects_a_malformed_stream_event() {
        // Missing the CircID + target.
        assert!(parse_stream_event(&frame_one(b"650 STREAM 42 SENTCONNECT\r\n")).is_none());
        // Non-numeric CircID.
        assert!(parse_stream_event(&frame_one(b"650 STREAM 42 SENTCONNECT xx t:1\r\n")).is_none());
    }

    #[test]
    fn circid_debug_is_redacted() {
        assert_eq!(
            format!("{:?}", CircId::new(2_167_179_189)),
            "CircId(<redacted>)"
        );
    }
}
