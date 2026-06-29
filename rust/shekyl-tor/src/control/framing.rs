// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Sans-IO framing for the Tor control protocol's reply stream — the demux at
//! the heart of the SP-T0a control client.
//!
//! # The protocol, in one paragraph
//!
//! The control port speaks line-based ASCII over TCP, each line `CRLF`-terminated
//! ([control-spec] §2.3). A *reply* is one or more framing lines that all begin
//! with the same 3-digit status code; the 4th byte is the separator that drives
//! the state machine:
//!
//! - `XYZ<SP>` — the **last** line of the reply (`"250 OK"`).
//! - `XYZ-` — a **mid** line; more framing lines follow (`"250-key=value"`).
//! - `XYZ+` — the start of a **multi-line data block**: every following line is
//!   verbatim data until a line containing only `"."`, dot-unstuffed (a data line
//!   beginning with `.` was sent with an extra leading `.`).
//!
//! # Why sans-IO
//!
//! Tor multiplexes asynchronous events (status `650`) with command replies on the
//! one socket, and a reader that mis-frames a single event poisons every read
//! after it. So the framing — where the protocol's subtleties live — is isolated
//! here as a pure, synchronous state machine: bytes in via [`ReplyFramer::push_bytes`],
//! complete [`ControlReply`]s out via [`ReplyFramer::next_reply`]. No socket, no
//! `tokio`, no blocking. The async control loop (a later slice) owns the socket
//! and the poll/phase drain and feeds this framer; the consequence is that the
//! bulk of the demux's correctness is pinned by KATs in the normal unit gate, not
//! deferred to a live-Tor integration job.
//!
//! [control-spec]: https://spec.torproject.org/control-spec/

/// Status code Tor stamps on every asynchronous (`SETEVENTS`) event reply, as
/// distinct from a synchronous command reply (control-spec §4.1).
pub const ASYNC_EVENT_STATUS: u16 = 650;

/// A complete, framed control-port reply — either a synchronous command reply or
/// an asynchronous event (distinguished by [`Self::is_async_event`]).
///
/// `lines` carries the payload with the status code and its separator stripped;
/// a `+`-introduced data block is folded, dot-unstuffed, into the single
/// `\n`-joined entry the `+` line began.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlReply {
    /// The 3-digit status code shared by every framing line of the reply.
    pub status: u16,
    /// Payload lines, status + separator stripped; data blocks folded in.
    pub lines: Vec<String>,
}

impl ControlReply {
    /// `true` iff this is an asynchronous event (status `650`) rather than a
    /// command reply — the control loop's demux discriminator: events route to
    /// the `SETEVENTS` drain, command replies to the awaiting command.
    #[must_use]
    pub fn is_async_event(&self) -> bool {
        self.status == ASYNC_EVENT_STATUS
    }
}

/// A control byte stream could not be framed. Every variant means the stream has
/// desynchronised: there is no safe mid-reply resync point (a mis-framed line
/// poisons all that follow), so the caller must tear the connection down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FramingError {
    /// A reply line was not valid UTF-8.
    InvalidUtf8,
    /// A framing line was shorter than the `XYZ<sep>` minimum (4 bytes).
    ///
    /// Carries only the length — never the bytes. The control port is a forensic
    /// surface: a desynced line may be misaligned payload (circuit IDs, targets)
    /// that must not reach a log via the error's `Display` *or* `Debug`. The other
    /// content-free variants below share this reason.
    ShortLine {
        /// Byte length of the runt line.
        len: usize,
    },
    /// The 3-character status prefix was not three ASCII digits (content-free; see
    /// [`Self::ShortLine`]).
    NonNumericStatus {
        /// Byte length of the offending line.
        len: usize,
    },
    /// The separator (4th byte) was not one of `' '`, `'-'`, `'+'` (content-free;
    /// see [`Self::ShortLine`]).
    BadSeparator {
        /// Byte length of the offending line.
        len: usize,
    },
    /// Two framing lines of one reply disagreed on the status code.
    StatusMismatch {
        /// Status code set by the reply's first framing line.
        first: u16,
        /// Conflicting code on a later framing line.
        found: u16,
    },
}

impl std::fmt::Display for FramingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUtf8 => write!(f, "control reply line was not valid UTF-8"),
            Self::ShortLine { len } => write!(f, "control framing line too short ({len} bytes)"),
            Self::NonNumericStatus { len } => {
                write!(f, "control status prefix not numeric ({len}-byte line)")
            }
            Self::BadSeparator { len } => {
                write!(
                    f,
                    "control framing line has an invalid separator ({len}-byte line)"
                )
            }
            Self::StatusMismatch { first, found } => {
                write!(f, "control reply status codes disagree: {first} != {found}")
            }
        }
    }
}

impl std::error::Error for FramingError {}

/// Sans-IO state machine that frames a Tor control byte stream into
/// [`ControlReply`]s. Feed bytes with [`Self::push_bytes`] as the socket yields
/// them; pull complete replies with [`Self::next_reply`] until it returns
/// `Ok(None)` (need more bytes). Reply state persists across calls, so a reply
/// may span any number of `push_bytes` chunks.
#[derive(Debug, Default)]
pub struct ReplyFramer {
    /// Raw bytes not yet split into a complete `CRLF`-terminated line.
    buf: Vec<u8>,
    /// Payload lines accumulated for the reply currently being assembled.
    lines: Vec<String>,
    /// Status code of the in-progress reply (set by its first framing line).
    status: Option<u16>,
    /// `true` while inside a `XYZ+ … .` multi-line data block.
    in_data_block: bool,
}

impl ReplyFramer {
    /// A fresh framer with no buffered bytes.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append freshly-read socket bytes. Does not parse; call
    /// [`Self::next_reply`] to drain complete replies.
    pub fn push_bytes(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Frame and return the next complete reply, or `Ok(None)` if the buffered
    /// bytes do not yet contain one (feed more and retry). `Err` means the stream
    /// desynced — tear the connection down.
    pub fn next_reply(&mut self) -> Result<Option<ControlReply>, FramingError> {
        while let Some(line) = self.take_line()? {
            // Inside a `+` data block every line is verbatim data until a lone
            // `.`; nothing here is a framing line.
            if self.in_data_block {
                if line == "." {
                    self.in_data_block = false;
                } else {
                    // Dot-unstuff: a data line beginning with `.` was sent with
                    // one extra leading `.` (control-spec §2.4).
                    let data = line.strip_prefix('.').unwrap_or(&line);
                    if let Some(last) = self.lines.last_mut() {
                        last.push('\n');
                        last.push_str(data);
                    }
                }
                continue;
            }

            let bytes = line.as_bytes();
            if bytes.len() < 4 {
                return Err(FramingError::ShortLine { len: bytes.len() });
            }
            if !(bytes[0].is_ascii_digit()
                && bytes[1].is_ascii_digit()
                && bytes[2].is_ascii_digit())
            {
                return Err(FramingError::NonNumericStatus { len: bytes.len() });
            }
            // Three ASCII digits → no overflow (≤ 999) and byte index 4 is a
            // char boundary (digits + an ASCII separator are single-byte).
            let status = (u16::from(bytes[0] - b'0')) * 100
                + (u16::from(bytes[1] - b'0')) * 10
                + u16::from(bytes[2] - b'0');
            match self.status {
                Some(first) if first != status => {
                    return Err(FramingError::StatusMismatch {
                        first,
                        found: status,
                    });
                }
                Some(_) => {}
                None => self.status = Some(status),
            }

            match bytes[3] {
                b' ' => {
                    // End of reply.
                    self.lines.push(line[4..].to_owned());
                    return Ok(Some(self.finish(status)));
                }
                b'-' => self.lines.push(line[4..].to_owned()),
                b'+' => {
                    self.lines.push(line[4..].to_owned());
                    self.in_data_block = true;
                }
                _ => return Err(FramingError::BadSeparator { len: bytes.len() }),
            }
        }
        Ok(None)
    }

    /// Take the assembled reply and reset for the next one. `status` is threaded
    /// from the framing line that closed the reply (always `== self.status`), so
    /// there is no status `Option` to unwrap — "a finished reply with no status"
    /// is unrepresentable here, rather than a `0` papered over a logic bug.
    fn finish(&mut self, status: u16) -> ControlReply {
        self.status = None;
        let lines = std::mem::take(&mut self.lines);
        ControlReply { status, lines }
    }

    /// Split the next `CRLF`-terminated line out of `buf`, or `Ok(None)` if no
    /// complete line is buffered yet. Strict UTF-8 (control replies are ASCII).
    fn take_line(&mut self) -> Result<Option<String>, FramingError> {
        let Some(pos) = self.buf.windows(2).position(|w| w == b"\r\n") else {
            return Ok(None);
        };
        let line = std::str::from_utf8(&self.buf[..pos])
            .map_err(|_| FramingError::InvalidUtf8)?
            .to_owned();
        self.buf.drain(..pos + 2);
        Ok(Some(line))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Push `bytes` in one shot and drain every complete reply.
    fn frame_all(bytes: &[u8]) -> Result<Vec<ControlReply>, FramingError> {
        let mut framer = ReplyFramer::new();
        framer.push_bytes(bytes);
        let mut out = Vec::new();
        while let Some(reply) = framer.next_reply()? {
            out.push(reply);
        }
        Ok(out)
    }

    fn reply(status: u16, lines: &[&str]) -> ControlReply {
        ControlReply {
            status,
            lines: lines.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn frames_a_single_end_line() {
        assert_eq!(frame_all(b"250 OK\r\n").unwrap(), vec![reply(250, &["OK"])]);
    }

    #[test]
    fn frames_mid_lines_then_end() {
        assert_eq!(
            frame_all(b"250-key=value\r\n250-other=thing\r\n250 OK\r\n").unwrap(),
            vec![reply(250, &["key=value", "other=thing", "OK"])],
        );
    }

    #[test]
    fn folds_a_multiline_data_block() {
        // `250+k=` opens a data block; `abc`/`def` are verbatim data; `.` ends it;
        // `250 OK` closes the reply.
        assert_eq!(
            frame_all(b"250+k=\r\nabc\r\ndef\r\n.\r\n250 OK\r\n").unwrap(),
            vec![reply(250, &["k=\nabc\ndef", "OK"])],
        );
    }

    #[test]
    fn dot_unstuffs_data_lines() {
        // On the wire a data line beginning with `.` carries an extra leading
        // `.`: `..x` -> `.x`, `..` -> `.`.
        assert_eq!(
            frame_all(b"250+k=\r\n..x\r\n..\r\n.\r\n250 OK\r\n").unwrap(),
            vec![reply(250, &["k=\n.x\n.", "OK"])],
        );
    }

    #[test]
    fn treats_status_like_lines_inside_a_data_block_as_data() {
        // Inside a `+` block, everything until a lone `.` is data — including a
        // line that *looks* like a framing line.
        assert_eq!(
            frame_all(b"250+k=\r\n250 not-an-end\r\n.\r\n250 OK\r\n").unwrap(),
            vec![reply(250, &["k=\n250 not-an-end", "OK"])],
        );
    }

    #[test]
    fn classifies_async_events_by_status_650() {
        let replies = frame_all(b"650 STREAM 1 NEW 0\r\n250 OK\r\n").unwrap();
        assert_eq!(
            replies,
            vec![reply(650, &["STREAM 1 NEW 0"]), reply(250, &["OK"])],
        );
        assert!(replies[0].is_async_event(), "650 is an async event");
        assert!(!replies[1].is_async_event(), "250 is a command reply");
    }

    #[test]
    fn yields_multiple_replies_from_one_push() {
        assert_eq!(
            frame_all(b"250 OK\r\n650 NOTICE hi\r\n").unwrap(),
            vec![reply(250, &["OK"]), reply(650, &["NOTICE hi"])],
        );
    }

    #[test]
    fn reassembles_a_reply_split_across_pushes() {
        let mut framer = ReplyFramer::new();
        // First chunk: a complete mid line, then a partial end line.
        framer.push_bytes(b"250-key=value\r\n250 ");
        assert_eq!(framer.next_reply().unwrap(), None, "end line incomplete");
        // Second chunk completes it — the mid line is not lost.
        framer.push_bytes(b"OK\r\n");
        assert_eq!(
            framer.next_reply().unwrap(),
            Some(reply(250, &["key=value", "OK"])),
        );
    }

    #[test]
    fn waits_for_a_line_split_mid_token() {
        let mut framer = ReplyFramer::new();
        framer.push_bytes(b"250 O");
        assert_eq!(framer.next_reply().unwrap(), None);
        framer.push_bytes(b"K\r\n");
        assert_eq!(framer.next_reply().unwrap(), Some(reply(250, &["OK"])));
    }

    #[test]
    fn errors_on_mismatched_status_codes() {
        assert_eq!(
            frame_all(b"250-key=value\r\n251 OK\r\n"),
            Err(FramingError::StatusMismatch {
                first: 250,
                found: 251,
            }),
        );
    }

    #[test]
    fn errors_on_non_numeric_status() {
        // "2x0 OK" is 6 bytes; the error carries the length, not the content.
        assert_eq!(
            frame_all(b"2x0 OK\r\n"),
            Err(FramingError::NonNumericStatus { len: 6 }),
        );
    }

    #[test]
    fn errors_on_bad_separator() {
        // "250|OK" is 6 bytes.
        assert_eq!(
            frame_all(b"250|OK\r\n"),
            Err(FramingError::BadSeparator { len: 6 }),
        );
    }

    #[test]
    fn errors_on_short_line() {
        assert_eq!(
            frame_all(b"25\r\n"),
            Err(FramingError::ShortLine { len: 2 })
        );
    }

    #[test]
    fn framing_errors_never_carry_stream_content() {
        // The control port is a forensic surface — circuit IDs / targets must not
        // be logged. A desync error must leak none of the offending line through
        // *either* `Display` or `Debug`; only non-sensitive metadata (a length).
        let mut framer = ReplyFramer::new();
        framer.push_bytes(b"sensitive-target-and-circuit-id|x\r\n");
        let err = framer
            .next_reply()
            .expect_err("a non-numeric prefix desyncs the stream");
        for rendered in [format!("{err}"), format!("{err:?}")] {
            assert!(
                !rendered.contains("sensitive") && !rendered.contains("target"),
                "framing error leaked stream content: {rendered}"
            );
        }
    }

    #[test]
    fn errors_on_invalid_utf8() {
        // 0xFF is never valid UTF-8.
        assert_eq!(frame_all(b"250 \xff\r\n"), Err(FramingError::InvalidUtf8),);
    }

    #[test]
    fn empty_payload_end_line_is_fine() {
        // `250 ` then CRLF: a valid end line with an empty payload.
        assert_eq!(frame_all(b"250 \r\n").unwrap(), vec![reply(250, &[""])]);
    }
}
