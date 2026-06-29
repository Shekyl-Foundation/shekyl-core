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

/// Upper bound on the bytes the framer will buffer for a single in-progress
/// reply — both one un-terminated line and the running total of an un-terminated
/// reply. Past it, [`ReplyFramer::next_reply`] returns
/// [`FramingError::ReplyTooLarge`] so the caller tears the connection down rather
/// than buffering forever.
///
/// The wallet's control replies are small (a status + short value, or a `STREAM`
/// event), so 256 KiB is generous; it caps a misbehaving — or compromised —
/// local Tor without risking a legitimate reply. The control port is
/// loopback-local, so this is defense-in-depth (DoS-never-theft), not an
/// adversarial-network bound.
const MAX_REPLY_BYTES: usize = 256 * 1024;

/// Reclaim the consumed prefix of `buf` once it passes this size, so the buffer
/// does not retain already-returned lines indefinitely. Keeps a steady stream of
/// small replies bounded without compacting on every line.
const COMPACT_THRESHOLD: usize = 8 * 1024;

/// A complete, framed control-port reply — either a synchronous command reply or
/// an asynchronous event (forked apart by [`Self::classify`] into [`Framed`]).
///
/// The payload (`status`, and the lines with status + separator stripped and `+`
/// data blocks folded + dot-unstuffed) is reached through [`Self::status`] /
/// [`Self::lines`], **not** public fields. `lines` is a forensic surface (a
/// `STREAM` event's circuit IDs / targets), so the whole posture — private
/// fields, a borrowing accessor, a redacting `Debug`, no `Clone` — keeps the
/// crate's no-log invariant from being bypassed by a casual `reply.lines`
/// grab-and-log. Same shape as `SocksUsername` in `shekyl-p-transport`.
#[derive(PartialEq, Eq)]
pub struct ControlReply {
    /// The 3-digit status code shared by every framing line of the reply.
    status: u16,
    /// Payload lines, status + separator stripped; data blocks folded in.
    lines: Vec<String>,
}

impl ControlReply {
    /// The reply's 3-digit status code.
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The reply's payload lines (status + separator stripped, `+` data blocks
    /// folded). A **forensic surface** — parse it, never log it.
    #[must_use]
    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    /// `true` iff this is an asynchronous event (status `650`) rather than a
    /// command reply. **Private:** the async/command split is reachable only
    /// through [`Self::classify`], so no downstream code can re-derive it — that
    /// is what makes routing a command's reply to an event (or vice versa)
    /// unrepresentable rather than merely unlikely.
    #[must_use]
    fn is_async_event(&self) -> bool {
        self.status == ASYNC_EVENT_STATUS
    }

    /// Fork this reply into [`Framed`] — the **one site** at which the
    /// async/command split is decided (status `650` ⇒ event). Consuming `self`
    /// hands the reply to exactly one arm, so it cannot be classified twice or
    /// routed to both; downstream code receives the already-typed `Framed` and
    /// never re-checks the status.
    #[must_use]
    pub fn classify(self) -> Framed {
        if self.is_async_event() {
            Framed::AsyncEvent(self)
        } else {
            Framed::CommandReply(self)
        }
    }
}

/// The two things a control reply can be, split once at ingress by
/// [`ControlReply::classify`]. Routing on this enum — instead of re-checking a
/// status downstream — is what makes "a command's reply path receives an async
/// event" unrepresentable: the command path is handed a [`Framed::CommandReply`],
/// never a raw reply it must classify itself.
///
/// The derived `Debug` delegates to [`ControlReply`]'s redacting one, so the
/// control-port payload stays unlogged here too.
#[derive(Debug, PartialEq, Eq)]
pub enum Framed {
    /// A synchronous command reply (status ≠ `650`) — the answer to the single
    /// in-flight command.
    CommandReply(ControlReply),
    /// An asynchronous `SETEVENTS` event (status `650`) — routed to the event
    /// drain, never matched to a command.
    AsyncEvent(ControlReply),
}

// Redacting `Debug` (not derived): `lines` carries the control-port payload — a
// `STREAM` event's circuit IDs and targets, a `GETINFO` value — and the crate's
// no-log invariant says that must not reach a log, including via a stray `{:?}`,
// an `assert_eq!` failure message, or a panic backtrace. Render only the
// non-sensitive shape (`status` + line count); the `..` marks `lines` omitted.
// Same posture as `SocksUsername` in `shekyl-p-transport`.
impl std::fmt::Debug for ControlReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlReply")
            .field("status", &self.status)
            .field("line_count", &self.lines.len())
            .finish_non_exhaustive()
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
    /// A single line, or the running total of one reply, exceeded the
    /// `MAX_REPLY_BYTES` buffer cap without terminating — an un-terminated
    /// line/reply that would otherwise buffer without bound (DoS). Content-free:
    /// only the limit.
    ReplyTooLarge {
        /// The byte cap that was exceeded (`MAX_REPLY_BYTES`).
        limit: usize,
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
            Self::ReplyTooLarge { limit } => {
                write!(f, "control reply exceeded the {limit}-byte buffer cap")
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
#[derive(Default)]
pub struct ReplyFramer {
    /// Raw bytes not yet split into a complete `CRLF`-terminated line.
    buf: Vec<u8>,
    /// Payload lines accumulated for the reply currently being assembled.
    lines: Vec<String>,
    /// Status code of the in-progress reply (set by its first framing line).
    status: Option<u16>,
    /// `true` while inside a `XYZ+ … .` multi-line data block.
    in_data_block: bool,
    /// Running DoS charge for the in-progress reply: each line's **wire length,
    /// `CRLF` stripped** (`line.len()`), plus the `\n` every `+` fold inserts. This
    /// is *not* the exact stored byte count — a framing line stores only `line[4..]`
    /// (dropping the 3-digit status + separator) — and that is **deliberate**:
    /// charging the whole line keeps a 4-byte margin per line that offsets the
    /// per-entry `String`/`Vec` overhead a flood of tiny lines would otherwise hide,
    /// so the cap bounds the real `self.lines` memory to within a small factor.
    /// Charging only `line[4..]` would let empty mid-lines (`250-\r\n`, payload `""`)
    /// grow the `Vec` with `reply_bytes` flat. Bounds an un-terminated *reply* (many
    /// lines, no end line) against [`MAX_REPLY_BYTES`]; reset when a reply completes.
    reply_bytes: usize,
    /// Start of the unconsumed bytes in `buf`. [`Self::take_line`] advances this
    /// rather than front-draining per line, and [`Self::compact`] reclaims the
    /// consumed prefix occasionally — so consuming a burst of buffered lines is
    /// O(n), not O(n²).
    read_pos: usize,
    /// `buf` index (≥ `read_pos`) from which the next `CRLF` search resumes, so a
    /// trickled line is scanned once rather than rescanned each call.
    scan_from: usize,
}

// Redacting `Debug` (not derived): `buf` holds raw control bytes mid-assembly and
// `lines` holds the in-progress reply's payload — circuit IDs / targets — the same
// forensic surface `ControlReply` redacts. The framer is `pub` (and the actor that
// owns one would otherwise expose it), so it must not leak that content via a stray
// `{:?}` or a panic backtrace: render only non-sensitive shape (lengths, offsets,
// the status code), never `buf` or `lines` content.
impl std::fmt::Debug for ReplyFramer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplyFramer")
            .field("buf_len", &self.buf.len())
            .field("line_count", &self.lines.len())
            .field("status", &self.status)
            .field("in_data_block", &self.in_data_block)
            .field("reply_bytes", &self.reply_bytes)
            .field("read_pos", &self.read_pos)
            .field("scan_from", &self.scan_from)
            .finish_non_exhaustive()
    }
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
            // Bound an un-terminated reply: many valid lines with no end line grow
            // `self.lines` without bound. (`take_line` separately bounds a single
            // un-terminated *line*.) `reply_bytes` resets in `finish`.
            self.charge_reply_bytes(line.len())?;
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
                    // The folded `\n` is real buffered state the `line.len()` charge
                    // above misses — without it a flood of empty data lines grows
                    // the entry unbounded while `reply_bytes` stays flat. Charge it.
                    self.charge_reply_bytes(1)?;
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

    /// Charge `n` bytes toward the in-progress reply and trip the cap if exceeded.
    /// Called with each line's length **and** the `\n` a data-block fold inserts,
    /// so the running total conservatively bounds the buffered reply memory —
    /// closing the hole where a folded `\n` (e.g. a flood of empty data lines)
    /// would otherwise go uncounted.
    fn charge_reply_bytes(&mut self, n: usize) -> Result<(), FramingError> {
        self.reply_bytes += n;
        if self.reply_bytes > MAX_REPLY_BYTES {
            return Err(FramingError::ReplyTooLarge {
                limit: MAX_REPLY_BYTES,
            });
        }
        Ok(())
    }

    /// Take the assembled reply and reset for the next one. `status` is threaded
    /// from the framing line that closed the reply (always `== self.status`), so
    /// there is no status `Option` to unwrap — "a finished reply with no status"
    /// is unrepresentable here, rather than a `0` papered over a logic bug.
    fn finish(&mut self, status: u16) -> ControlReply {
        self.status = None;
        self.reply_bytes = 0;
        let lines = std::mem::take(&mut self.lines);
        ControlReply { status, lines }
    }

    /// Split the next `CRLF`-terminated line out of `buf`, or `Ok(None)` if no
    /// complete line is buffered yet. Strict UTF-8 (control replies are ASCII).
    ///
    /// Resumes the `CRLF` search from [`Self::scan_from`] rather than rescanning
    /// the whole buffer, so a trickled, never-terminated line stays O(n).
    fn take_line(&mut self) -> Result<Option<String>, FramingError> {
        let Some(rel) = self.buf[self.scan_from..]
            .windows(2)
            .position(|w| w == b"\r\n")
        else {
            // No terminator yet. Everything from `read_pos` is one partial line; if
            // it already exceeds the cap the peer will never terminate it (or is
            // flooding) — refuse rather than buffer on.
            if self.buf.len() - self.read_pos > MAX_REPLY_BYTES {
                return Err(FramingError::ReplyTooLarge {
                    limit: MAX_REPLY_BYTES,
                });
            }
            // Resume next time from the last byte: it may be the `\r` of a `\r\n`
            // the next chunk completes (never before `read_pos`).
            self.scan_from = self.buf.len().saturating_sub(1).max(self.read_pos);
            return Ok(None);
        };
        let crlf = self.scan_from + rel;
        // A single terminated line longer than the cap is abuse, too.
        if crlf - self.read_pos > MAX_REPLY_BYTES {
            return Err(FramingError::ReplyTooLarge {
                limit: MAX_REPLY_BYTES,
            });
        }
        let line = std::str::from_utf8(&self.buf[self.read_pos..crlf])
            .map_err(|_| FramingError::InvalidUtf8)?
            .to_owned();
        // Advance the cursor past the line + its `CRLF` rather than front-draining,
        // so consuming a burst of buffered lines is O(n); `compact` reclaims the
        // consumed prefix occasionally.
        self.read_pos = crlf + 2;
        self.scan_from = self.read_pos;
        self.compact();
        Ok(Some(line))
    }

    /// Reclaim the consumed prefix `buf[..read_pos]` (already-returned lines) when
    /// it is fully consumed or has grown past [`COMPACT_THRESHOLD`] — keeping the
    /// buffer bounded under a steady stream without compacting on every line.
    fn compact(&mut self) {
        if self.read_pos == 0 {
            return;
        }
        if self.read_pos >= self.buf.len() {
            // Everything consumed — clear outright.
            self.buf.clear();
            self.read_pos = 0;
            self.scan_from = 0;
        } else if self.read_pos >= COMPACT_THRESHOLD {
            self.buf.drain(..self.read_pos);
            self.scan_from = self.scan_from.saturating_sub(self.read_pos);
            self.read_pos = 0;
        }
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
    fn classify_forks_async_events_by_status_650() {
        let replies = frame_all(b"650 STREAM 1 NEW 0\r\n250 OK\r\n").unwrap();
        assert_eq!(
            replies,
            vec![reply(650, &["STREAM 1 NEW 0"]), reply(250, &["OK"])],
        );
        // The single fork: 650 ⇒ AsyncEvent, everything else ⇒ CommandReply.
        let mut framed = replies.into_iter().map(ControlReply::classify);
        assert!(
            matches!(framed.next(), Some(Framed::AsyncEvent(_))),
            "650 is an async event",
        );
        assert!(
            matches!(framed.next(), Some(Framed::CommandReply(_))),
            "250 is a command reply",
        );
    }

    #[test]
    fn framed_debug_does_not_leak_the_payload() {
        // The forensic no-log invariant must survive the new wrapper: Framed's
        // derived Debug has to delegate to ControlReply's redacting Debug.
        let framed = frame_all(b"650 STREAM 42 NEW target.example\r\n")
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
            .classify();
        let rendered = format!("{framed:?}");
        assert!(rendered.contains("AsyncEvent"), "renders the variant/shape");
        assert!(!rendered.contains("STREAM"), "no payload keyword");
        assert!(!rendered.contains("target.example"), "no target");
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

    #[test]
    fn control_reply_debug_redacts_the_payload() {
        // `lines` may carry a `STREAM` event's circuit IDs / targets; `Debug` must
        // render only the shape, never the content (the crate's no-log invariant).
        let event = frame_all(b"650 STREAM 42 SENTCONNECT 7 secret-target.onion:80\r\n")
            .unwrap()
            .pop()
            .expect("one event");
        let rendered = format!("{event:?}");
        assert!(
            !rendered.contains("secret-target") && !rendered.contains("STREAM"),
            "ControlReply Debug leaked the payload: {rendered}"
        );
        // The non-sensitive shape stays visible for debugging.
        assert!(rendered.contains("status: 650") && rendered.contains("line_count: 1"));
    }

    #[test]
    fn caps_an_unterminated_line() {
        // A single line that never sends `CRLF` must not buffer without bound.
        let mut framer = ReplyFramer::new();
        framer.push_bytes(&vec![b'x'; MAX_REPLY_BYTES + 1]);
        assert_eq!(
            framer.next_reply(),
            Err(FramingError::ReplyTooLarge {
                limit: MAX_REPLY_BYTES,
            }),
        );
    }

    #[test]
    fn caps_an_unterminated_reply() {
        // Many large *valid* mid-lines with no end line trip the per-reply cap
        // (each line is individually under the per-line cap, so only the running
        // total catches it).
        let big_mid = format!("250-{}\r\n", "x".repeat(60_000)); // ~60 KB mid-line
        let mut framer = ReplyFramer::new();
        let mut hit = None;
        for _ in 0..8 {
            framer.push_bytes(big_mid.as_bytes());
            if let Err(e) = framer.next_reply() {
                hit = Some(e);
                break;
            }
        }
        assert_eq!(
            hit,
            Some(FramingError::ReplyTooLarge {
                limit: MAX_REPLY_BYTES,
            }),
        );
    }

    #[test]
    fn a_large_batch_of_small_replies_is_not_capped() {
        // Pushing many *complete* small replies at once is the caller's choice, not
        // a never-terminated stream: the counter resets per reply, so none is
        // capped (no false positive).
        let n = 1000;
        let mut batch = Vec::new();
        for _ in 0..n {
            batch.extend_from_slice(b"250 OK\r\n");
        }
        let mut framer = ReplyFramer::new();
        framer.push_bytes(&batch);
        let mut count = 0;
        while framer
            .next_reply()
            .expect("a batch of valid replies must not be capped")
            .is_some()
        {
            count += 1;
        }
        assert_eq!(count, n);
    }

    #[test]
    fn caps_an_unterminated_data_block() {
        // A `+` data block that opens but never sends a closing `.` floods data
        // lines — these count toward `reply_bytes` too, so the same per-reply cap
        // catches it (the twin of `caps_an_unterminated_reply`, different path).
        let mut framer = ReplyFramer::new();
        framer.push_bytes(b"250+k=\r\n");
        assert_eq!(
            framer.next_reply().unwrap(),
            None,
            "block opened, no data yet"
        );
        let big_data = format!("{}\r\n", "x".repeat(60_000)); // ~60 KB data line
        let mut hit = None;
        for _ in 0..8 {
            framer.push_bytes(big_data.as_bytes());
            if let Err(e) = framer.next_reply() {
                hit = Some(e);
                break;
            }
        }
        assert_eq!(
            hit,
            Some(FramingError::ReplyTooLarge {
                limit: MAX_REPLY_BYTES,
            }),
        );
    }

    #[test]
    fn reassembles_a_line_with_crlf_split_across_pushes() {
        // The `\r` and `\n` of one terminator can land in different chunks; the
        // resume cursor must still find it (regression for the take_line offset).
        let mut framer = ReplyFramer::new();
        framer.push_bytes(b"250 OK\r"); // ends mid-CRLF
        assert_eq!(framer.next_reply().unwrap(), None, "CRLF incomplete");
        framer.push_bytes(b"\n");
        assert_eq!(framer.next_reply().unwrap(), Some(reply(250, &["OK"])));
    }

    #[test]
    fn frames_a_byte_at_a_time_trickle() {
        // Bytes arriving one at a time must frame correctly — exercises the O(n)
        // resume path and that the cursor never skips the terminator.
        let wire = b"250-key=value\r\n250 OK\r\n";
        let mut framer = ReplyFramer::new();
        let mut out = Vec::new();
        for b in wire {
            framer.push_bytes(&[*b]);
            if let Some(reply) = framer.next_reply().unwrap() {
                out.push(reply);
            }
        }
        assert_eq!(out, vec![reply(250, &["key=value", "OK"])]);
    }

    #[test]
    fn empty_plus_payload_folds_wire_faithfully() {
        // A `250+` line with an *empty* payload is degenerate — real Tor `+` lines
        // always carry `keyword=`. If it did occur, the fold stays wire-faithful:
        // every wire line is `\n`-joined, so an empty `+` line contributes a
        // leading `\n` before the data (consistent with the non-empty case, where
        // the `+` line's payload precedes the same `\n`). Locked so it can't drift.
        assert_eq!(
            frame_all(b"250+\r\nabc\r\n.\r\n250 OK\r\n").unwrap(),
            vec![reply(250, &["\nabc", "OK"])],
        );
    }

    #[test]
    fn drains_a_large_burst_across_compaction() {
        // A burst larger than COMPACT_THRESHOLD must frame correctly across the
        // mid-stream buffer compaction — i.e. the read cursor and scan cursor
        // survive `compact`'s `drain` and shift. (`a_large_batch_…` stays under the
        // threshold; this one crosses it several times.)
        let n = 4000; // 4000 * 8 B = 32 KiB > COMPACT_THRESHOLD
        let mut batch = Vec::new();
        for _ in 0..n {
            batch.extend_from_slice(b"250 OK\r\n");
        }
        let mut framer = ReplyFramer::new();
        framer.push_bytes(&batch);
        let mut count = 0;
        while let Some(r) = framer.next_reply().expect("burst must frame cleanly") {
            assert_eq!(r, reply(250, &["OK"]), "reply {count} mis-framed");
            count += 1;
        }
        assert_eq!(count, n);
    }

    #[test]
    fn caps_a_flood_of_empty_data_lines() {
        // A `+` data block then endless EMPTY data lines (`\r\n`, each
        // `line.len() == 0`) must still trip the cap: each fold inserts a `\n` —
        // real buffered state the raw `line.len()` charge alone would miss, which
        // would let the entry grow unbounded with `reply_bytes` flat. Regression.
        let mut wire = b"250+k=\r\n".to_vec();
        for _ in 0..(MAX_REPLY_BYTES + 8) {
            wire.extend_from_slice(b"\r\n");
        }
        let mut framer = ReplyFramer::new();
        framer.push_bytes(&wire);
        assert_eq!(
            framer.next_reply(),
            Err(FramingError::ReplyTooLarge {
                limit: MAX_REPLY_BYTES,
            }),
        );
    }

    #[test]
    fn framer_debug_redacts_payload_and_buffer() {
        // The framer holds the same forensic payload `ControlReply` redacts — the
        // in-progress `lines` — plus raw control bytes in `buf` mid-assembly. Its
        // `Debug` must render only shape, never that content (the no-log invariant
        // applies one layer up from `ControlReply`, not just to it).
        let mut framer = ReplyFramer::new();
        // A complete mid-line lands in `lines`; the partial tail stays in `buf`.
        framer.push_bytes(b"250-x=secret-target.onion\r\n650 also-secret");
        assert_eq!(framer.next_reply().unwrap(), None, "reply still incomplete");
        let rendered = format!("{framer:?}");
        assert!(
            !rendered.contains("secret-target") && !rendered.contains("also-secret"),
            "framer Debug leaked content: {rendered}"
        );
        // Non-sensitive shape stays visible.
        assert!(rendered.contains("line_count") && rendered.contains("buf_len"));
    }

    #[test]
    fn caps_a_flood_of_empty_mid_lines() {
        // Empty mid-lines (`250-\r\n`, payload `""`) store an empty entry, but the
        // cap must still trip: `reply_bytes` charges the full wire line (incl. the
        // 4-byte prefix), which offsets the per-entry `Vec`/`String` overhead.
        // Regression against charging only `line[4..]` (which would be 0 here, so
        // the `Vec` would grow unbounded with the cap flat).
        let mut wire = Vec::new();
        for _ in 0..(MAX_REPLY_BYTES / 4 + 8) {
            wire.extend_from_slice(b"250-\r\n"); // each charges 4
        }
        let mut framer = ReplyFramer::new();
        framer.push_bytes(&wire);
        assert_eq!(
            framer.next_reply(),
            Err(FramingError::ReplyTooLarge {
                limit: MAX_REPLY_BYTES,
            }),
        );
    }
}
