// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The step 7 message-size record (`NOISE_STEP7_EVALUATION_BRIEF.md`,
//! item 1): one line per Levin message a clearnet session sends or
//! receives, in a measurement build only
//! ([`MEASUREMENT_SPANS`](shekyl_transport_layer::spans::MEASUREMENT_SPANS)).
//!
//! A line carries the message's size (header and payload), its direction,
//! when it was handed to the writer or finished arriving, the session's
//! local number, and the class of its command. Nothing else: no content,
//! no peer address, no command name. The fixed window W, the flush policy
//! and Nagle are derived from these lines (`P2P_TRANSPORT_LAYER.md` D14
//! item 4). The session number is there because an observer sees each
//! connection's stream on its own, so windows per message and burst
//! timing are read per session.
//!
//! A direction whose walk ends on a header that does not read logs one
//! `levin walk ended` line, with its direction and session: nothing after
//! it in that direction is recorded, and the record counts those sessions
//! rather than reading their silence as no traffic.
//!
//! The tap reads session plaintext, beneath the seam's record layer, so
//! the same lines come from a plain channel and a Noise channel: the
//! plaintext control (item 10) reads them too.

use std::sync::OnceLock;
use std::time::Instant;

use shekyl_levin::{
    FrameHeads, COMMAND_HANDSHAKE, COMMAND_TIMED_SYNC, HEADER_SIZE, NOTIFY_GET_TXPOOL_COMPLEMENT,
    NOTIFY_NEW_COMPACT_BLOCK, NOTIFY_NEW_TRANSACTIONS, NOTIFY_REQUEST_BODIES, NOTIFY_REQUEST_CHAIN,
    NOTIFY_REQUEST_COMPACT_MISSING_TX, NOTIFY_REQUEST_GET_OBJECTS, NOTIFY_REQUEST_HEADERS,
    NOTIFY_RESPONSE_BODIES, NOTIFY_RESPONSE_CHAIN_ENTRY, NOTIFY_RESPONSE_GET_OBJECTS,
    NOTIFY_RESPONSE_HEADERS,
};
use shekyl_transport_layer::spans::MEASUREMENT_SPANS;

/// The tracing target the lines are written under. It sits under
/// `shekyl_clearnet`, which the `p2p` log subsystem covers, so a
/// measurement node keeps the lines with `log-category = { p2p = "info" }`
/// and a reader selects them by this target.
pub(crate) const TARGET: &str = "shekyl_clearnet::message_size";

/// Which way the message went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Way {
    /// Handed to this node's writer.
    Sent,
    /// Finished arriving from the peer.
    Received,
}

impl Way {
    const fn name(self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::Received => "received",
        }
    }
}

/// The class of a command: what the record keeps instead of its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    /// The handshake and timed sync.
    Control,
    /// Transaction relay, Dandelion++ stem and fluff alike, and the pool
    /// complement.
    TxRelay,
    /// A new block and the transactions it is missing.
    BlockRelay,
    /// Chain sync: chain entries, headers, bodies and objects.
    Sync,
    /// A command this table does not name.
    Unknown,
}

impl Class {
    pub(crate) const fn of(command: u32) -> Self {
        match command {
            COMMAND_HANDSHAKE | COMMAND_TIMED_SYNC => Self::Control,
            NOTIFY_NEW_TRANSACTIONS | NOTIFY_GET_TXPOOL_COMPLEMENT => Self::TxRelay,
            NOTIFY_NEW_COMPACT_BLOCK | NOTIFY_REQUEST_COMPACT_MISSING_TX => Self::BlockRelay,
            NOTIFY_REQUEST_GET_OBJECTS
            | NOTIFY_RESPONSE_GET_OBJECTS
            | NOTIFY_REQUEST_CHAIN
            | NOTIFY_RESPONSE_CHAIN_ENTRY
            | NOTIFY_REQUEST_HEADERS
            | NOTIFY_RESPONSE_HEADERS
            | NOTIFY_REQUEST_BODIES
            | NOTIFY_RESPONSE_BODIES => Self::Sync,
            _ => Self::Unknown,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::TxRelay => "tx_relay",
            Self::BlockRelay => "block_relay",
            Self::Sync => "sync",
            Self::Unknown => "unknown",
        }
    }
}

/// One message as the record keeps it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Line {
    pub(crate) way: Way,
    pub(crate) conn: u64,
    /// Header and payload, in bytes.
    pub(crate) bytes: u64,
    pub(crate) class: Class,
}

/// One direction of one session's plaintext, walked into [`Line`]s.
pub(crate) struct SizeTap {
    way: Way,
    conn: u64,
    frames: FrameHeads,
    /// The walk ended on a header that does not read, and that was logged.
    ended_noted: bool,
}

impl SizeTap {
    /// A tap in a measurement build, and `None` in every other build.
    pub(crate) fn new(way: Way, conn: u64) -> Option<Self> {
        MEASUREMENT_SPANS.then(|| Self::tap(way, conn))
    }

    const fn tap(way: Way, conn: u64) -> Self {
        Self {
            way,
            conn,
            frames: FrameHeads::new(),
            ended_noted: false,
        }
    }

    /// Walk the next plaintext bytes and log a line for each message they
    /// complete.
    pub(crate) fn feed(&mut self, plaintext: &[u8]) {
        self.feed_into(plaintext, |line| {
            tracing::info!(
                target: TARGET,
                way = line.way.name(),
                conn = line.conn,
                bytes = line.bytes,
                class = line.class.name(),
                t_ns = since_first_line(),
                "levin message"
            );
        });
        if self.walk_ended() {
            tracing::info!(
                target: TARGET,
                way = self.way.name(),
                conn = self.conn,
                t_ns = since_first_line(),
                "levin walk ended"
            );
        }
    }

    /// `true` once, the first time the walk has ended on a header that does
    /// not read. Every message after it in this direction goes unrecorded,
    /// so the record counts the sessions whose walk ended (Rick,
    /// 2026-10-31) instead of reading their silence as no traffic.
    fn walk_ended(&mut self) -> bool {
        if self.ended_noted || !self.frames.ended() {
            return false;
        }
        self.ended_noted = true;
        true
    }

    fn feed_into(&mut self, plaintext: &[u8], mut emit: impl FnMut(Line)) {
        let (way, conn) = (self.way, self.conn);
        self.frames.feed(plaintext, |head| {
            emit(Line {
                way,
                conn,
                bytes: (HEADER_SIZE as u64).saturating_add(head.payload_len),
                class: Class::of(head.command),
            });
        });
    }
}

/// Nanoseconds since this process logged its first line, on the monotonic
/// clock: the lines' order and spacing. The log's own timestamp places
/// them in wall time.
fn since_first_line() -> u64 {
    static FIRST: OnceLock<Instant> = OnceLock::new();
    u64::try_from(FIRST.get_or_init(Instant::now).elapsed().as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_levin::{BucketHead, Flags, PROTOCOL_VERSION_1};

    fn frame(command: u32, body: usize) -> Vec<u8> {
        let head = BucketHead {
            payload_len: u64::try_from(body).expect("small"),
            expect_response: 0,
            command,
            flags: Flags::REQUEST,
            protocol_version: PROTOCOL_VERSION_1,
        };
        let mut out = head.write().to_vec();
        out.extend(std::iter::repeat_n(0u8, body));
        out
    }

    #[test]
    fn every_command_the_protocol_names_has_a_class() {
        for command in [
            COMMAND_HANDSHAKE,
            COMMAND_TIMED_SYNC,
            NOTIFY_NEW_TRANSACTIONS,
            NOTIFY_REQUEST_GET_OBJECTS,
            NOTIFY_RESPONSE_GET_OBJECTS,
            NOTIFY_REQUEST_CHAIN,
            NOTIFY_RESPONSE_CHAIN_ENTRY,
            NOTIFY_NEW_COMPACT_BLOCK,
            NOTIFY_REQUEST_COMPACT_MISSING_TX,
            NOTIFY_GET_TXPOOL_COMPLEMENT,
            NOTIFY_REQUEST_HEADERS,
            NOTIFY_RESPONSE_HEADERS,
            NOTIFY_REQUEST_BODIES,
            NOTIFY_RESPONSE_BODIES,
        ] {
            assert_ne!(Class::of(command), Class::Unknown, "command {command}");
        }
        assert_eq!(
            Class::of(1003),
            Class::Unknown,
            "a retired id is not classed"
        );
    }

    #[test]
    fn a_line_is_the_whole_message_once_however_it_is_split() {
        let mut stream = frame(NOTIFY_NEW_TRANSACTIONS, 1_000);
        stream.extend(frame(COMMAND_TIMED_SYNC, 0));
        let mut tap = SizeTap::tap(Way::Received, 7);
        let mut lines = Vec::new();
        for piece in stream.chunks(13) {
            tap.feed_into(piece, |line| lines.push(line));
        }
        let header = HEADER_SIZE as u64;
        assert_eq!(
            lines,
            [
                Line {
                    way: Way::Received,
                    conn: 7,
                    bytes: header + 1_000,
                    class: Class::TxRelay
                },
                Line {
                    way: Way::Received,
                    conn: 7,
                    bytes: header,
                    class: Class::Control
                },
            ]
        );
    }

    #[test]
    fn a_walk_that_ends_on_a_bad_header_is_noted_once() {
        let mut stream = frame(COMMAND_TIMED_SYNC, 0);
        let mut bad = frame(COMMAND_TIMED_SYNC, 0);
        bad[0] ^= 0xFF;
        stream.extend(bad);
        let mut tap = SizeTap::tap(Way::Received, 3);
        let mut lines = 0;
        tap.feed_into(&frame(COMMAND_HANDSHAKE, 4), |_| lines += 1);
        assert!(!tap.walk_ended(), "a walk that reads is not ended");
        tap.feed_into(&stream, |_| lines += 1);
        assert_eq!(lines, 2, "the frames before the bad header are lines");
        assert!(tap.walk_ended(), "the bad header ends the walk");
        tap.feed_into(&frame(COMMAND_TIMED_SYNC, 0), |_| lines += 1);
        assert!(!tap.walk_ended(), "noted once per direction");
        assert_eq!(lines, 2, "nothing after the end is a line");
    }

    #[test]
    fn a_release_build_has_no_tap() {
        assert_eq!(SizeTap::new(Way::Sent, 1).is_some(), MEASUREMENT_SPANS);
    }
}
