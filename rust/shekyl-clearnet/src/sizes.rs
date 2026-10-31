// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The step 7 message-size record (`NOISE_STEP7_EVALUATION_BRIEF.md`,
//! item 1): one line per Levin message a clearnet session sends or
//! receives, in a measurement build only.
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
//!
//! A release build's [`SizeTap`] is zero-sized. [`SizeTap::feed`] is empty,
//! and a session future carries no walker. The measurement build is
//! `shekyl-clearnet`'s `measurement-spans` feature, turned on with
//! `shekyl-transport-layer`'s by CMake's `SHEKYL_MEASUREMENT_SPANS`. The
//! clearnet feature enables nothing: a Cargo edge onto the transport-layer
//! feature would fail `check_measurement_spans.py`.

/// Which way the message went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Way {
    /// Handed to this node's writer.
    Sent,
    /// Finished arriving from the peer.
    Received,
}

impl Way {
    #[cfg(any(test, feature = "measurement-spans"))]
    const fn name(self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::Received => "received",
        }
    }
}

/// Release build: no walker, no log, no state in the session future.
#[cfg(not(any(test, feature = "measurement-spans")))]
mod absent {
    pub(crate) struct SizeTap;

    impl SizeTap {
        pub(crate) fn new(_: super::Way, _: u64) -> Self {
            Self
        }

        // CLIPPY: this method exists so a release session and a measurement
        // session call `feed` the same way. The tap is zero-sized, so there
        // is no field for `self` to read.
        #[allow(clippy::unused_self)]
        pub(crate) fn feed(&mut self, _: &[u8]) {}
    }
}

/// Measurement build, and the crate's own tests. `new` records only when
/// this crate's `measurement-spans` feature is on, so a default `cargo test`
/// builds the walker and still proves a non-measurement `new` logs nothing.
#[cfg(any(test, feature = "measurement-spans"))]
mod present {
    use std::sync::OnceLock;
    use std::time::Instant;

    use shekyl_levin::{AfterFrame, DefinedCommand, FrameHeads, SyncCommand, HEADER_SIZE};

    use super::Way;

    /// The tracing target the lines are written under. It sits under
    /// `shekyl_clearnet`, which the `p2p` log subsystem covers, so a
    /// measurement node keeps the lines with `log-category = { p2p = "info" }`
    /// and a reader selects them by this target.
    const TARGET: &str = "shekyl_clearnet::message_size";

    /// The class of a command: what the record keeps instead of its name.
    ///
    /// Dispatch commands take their class from [`DefinedCommand`] and
    /// [`SyncCommand`], the protocol's closed sets. A wire id neither names
    /// is [`Class::Unknown`].
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
        /// A command neither closed set names.
        Unknown,
    }

    impl Class {
        pub(crate) const fn of(command: u32) -> Self {
            if let Some(command) = DefinedCommand::from_wire(command) {
                return match command {
                    DefinedCommand::Handshake | DefinedCommand::TimedSync => Self::Control,
                    DefinedCommand::NewTransactions | DefinedCommand::GetTxpoolComplement => {
                        Self::TxRelay
                    }
                    DefinedCommand::NewCompactBlock | DefinedCommand::RequestCompactMissingTx => {
                        Self::BlockRelay
                    }
                    DefinedCommand::RequestGetObjects
                    | DefinedCommand::ResponseGetObjects
                    | DefinedCommand::RequestChain
                    | DefinedCommand::ResponseChainEntry => Self::Sync,
                };
            }
            if SyncCommand::from_wire(command).is_some() {
                Self::Sync
            } else {
                Self::Unknown
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

    /// One direction of one session. [`SizeTap::Quiet`] holds no walker.
    pub(crate) enum SizeTap {
        /// `new` in the crate tests, when the measurement feature is off.
        /// A measurement build never constructs it; the variant stays so
        /// those tests and the measurement build share this enum.
        #[cfg_attr(feature = "measurement-spans", allow(dead_code))]
        Quiet,
        /// Walking this direction's plaintext.
        Recording {
            way: Way,
            conn: u64,
            frames: FrameHeads,
            /// The walk ended on a header that does not read, and that was logged.
            ended_noted: bool,
        },
    }

    impl SizeTap {
        /// A recording tap when this crate's measurement feature is on.
        /// The crate tests compile this module without that feature, and
        /// there `new` is [`Self::Quiet`]: the walker is built, and a
        /// non-measurement session still logs nothing.
        #[cfg(feature = "measurement-spans")]
        pub(crate) fn new(way: Way, conn: u64) -> Self {
            Self::recording(way, conn)
        }

        #[cfg(not(feature = "measurement-spans"))]
        pub(crate) fn new(_: Way, _: u64) -> Self {
            Self::Quiet
        }

        fn recording(way: Way, conn: u64) -> Self {
            Self::Recording {
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
            if let Some((way, conn)) = self.note_ended() {
                tracing::info!(
                    target: TARGET,
                    way = way.name(),
                    conn,
                    t_ns = since_first_line(),
                    "levin walk ended"
                );
            }
        }

        /// `Some` once, the first time the walk has ended on a header that
        /// does not read. Every message after it in this direction goes
        /// unrecorded, so the record counts the sessions whose walk ended
        /// (Rick, 2026-10-31) instead of reading their silence as no traffic.
        fn note_ended(&mut self) -> Option<(Way, u64)> {
            let Self::Recording {
                way,
                conn,
                frames,
                ended_noted,
            } = self
            else {
                return None;
            };
            if *ended_noted || !frames.ended() {
                return None;
            }
            *ended_noted = true;
            Some((*way, *conn))
        }

        fn feed_into(&mut self, plaintext: &[u8], mut emit: impl FnMut(Line)) {
            let Self::Recording {
                way, conn, frames, ..
            } = self
            else {
                return;
            };
            let (way, conn) = (*way, *conn);
            frames.feed(plaintext, |head| {
                emit(Line {
                    way,
                    conn,
                    bytes: (HEADER_SIZE as u64).saturating_add(head.payload_len),
                    class: Class::of(head.command),
                });
                AfterFrame::Continue
            });
        }
    }

    /// Nanoseconds since this process logged its first line, on the monotonic
    /// clock: the lines' order and spacing. The log's own timestamp places
    /// them in wall time.
    ///
    /// The value saturates at [`u64::MAX`]. A `u64` of nanoseconds is about
    /// 584 years, so the record has no separate overflow mark: the clock
    /// stops advancing, and a warning at that point would say the same thing.
    fn since_first_line() -> u64 {
        static FIRST: OnceLock<Instant> = OnceLock::new();
        let elapsed = FIRST.get_or_init(Instant::now).elapsed().as_nanos();
        u64::try_from(elapsed).unwrap_or(u64::MAX)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use shekyl_levin::{
            BucketHead, Flags, COMMAND_HANDSHAKE, COMMAND_TIMED_SYNC, NOTIFY_NEW_TRANSACTIONS,
            PROTOCOL_VERSION_1,
        };
        use shekyl_transport_layer::spans::MEASUREMENT_SPANS;

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
        fn every_protocol_command_has_its_class() {
            for command in DefinedCommand::ALL {
                assert_ne!(
                    Class::of(command.wire_id()),
                    Class::Unknown,
                    "{command:?} is in the closed set"
                );
            }
            for command in SyncCommand::ALL {
                assert_eq!(
                    Class::of(command.wire_id()),
                    Class::Sync,
                    "{command:?} is chain sync"
                );
            }
            // Retired ids, and the noise/fragment command 0: neither closed
            // set names them. Ping (PWD-B10), support flags, new-block (PWD-B6).
            for retired in [0u32, 1003, 1007, 2001] {
                assert_eq!(Class::of(retired), Class::Unknown, "retired {retired}");
            }
        }

        #[test]
        fn a_line_is_the_whole_message_once_however_it_is_split() {
            let mut stream = frame(NOTIFY_NEW_TRANSACTIONS, 1_000);
            stream.extend(frame(COMMAND_TIMED_SYNC, 0));
            let mut tap = SizeTap::recording(Way::Received, 7);
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
            let mut tap = SizeTap::recording(Way::Received, 3);
            let mut lines = 0;
            tap.feed_into(&frame(COMMAND_HANDSHAKE, 4), |_| lines += 1);
            assert!(tap.note_ended().is_none(), "a walk that reads is not ended");
            tap.feed_into(&stream, |_| lines += 1);
            assert_eq!(lines, 2, "the frames before the bad header are lines");
            assert!(tap.note_ended().is_some(), "the bad header ends the walk");
            tap.feed_into(&frame(COMMAND_TIMED_SYNC, 0), |_| lines += 1);
            assert!(tap.note_ended().is_none(), "noted once per direction");
            assert_eq!(lines, 2, "nothing after the end is a line");
        }

        #[test]
        fn new_records_only_in_a_measurement_build() {
            let mut tap = SizeTap::new(Way::Sent, 1);
            let mut lines = 0;
            tap.feed_into(&frame(COMMAND_TIMED_SYNC, 0), |_| lines += 1);
            let expect = usize::from(cfg!(feature = "measurement-spans"));
            assert_eq!(lines, expect);
            assert_eq!(cfg!(feature = "measurement-spans"), MEASUREMENT_SPANS);
        }
    }
}

#[cfg(not(any(test, feature = "measurement-spans")))]
pub(crate) use absent::SizeTap;
#[cfg(any(test, feature = "measurement-spans"))]
pub(crate) use present::SizeTap;

/// CMake turns this crate's feature and the transport-layer feature on
/// together. A build that splits them does not compile: the array length
/// is 1 only when the two switches agree, so the tap cannot be present
/// where the measurement const is off, or absent where it is on.
const MEASUREMENT_TAP: bool = cfg!(feature = "measurement-spans");
const MEASUREMENT_SWITCHES_AGREE: usize =
    if MEASUREMENT_TAP == shekyl_transport_layer::spans::MEASUREMENT_SPANS {
        1
    } else {
        0
    };
const _: [(); 1] = [(); MEASUREMENT_SWITCHES_AGREE];
