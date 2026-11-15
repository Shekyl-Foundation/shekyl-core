// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One HTTP message at a time, on top of the record stream.
//!
//! hyper reads ahead into its own buffer. A connection-wide submission
//! verdict would then describe the last record hyper happened to pull, and
//! two requests that share one padded frame would both see it. This wrapper
//! is the message boundary hyper does not have:
//!
//! - it forwards only the bytes of the current request;
//! - a request is the header plus its `Content-Length` body (a request
//!   with no length has no body);
//! - when that message ends exactly on the submission the stream finished,
//!   [`InboundShape::note_message`] records the claim, and the bytes left
//!   in the frame stay here for the next message;
//! - the next message is not read until this side writes a response, so
//!   the handler observes the claim for the body it just finished.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use shekyl_rpc_stream::{InboundShape, MAX_PAYLOAD};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A request header longer than this is not one message this wrapper can
/// bound. The bytes pass through, and the message is not a submission.
const HEAD_LIMIT: usize = 8 * 1024;

/// Where the scanner is in the current request.
#[derive(Debug)]
enum Scan {
    /// The header, including the blank line, as far as it has been seen.
    Head(Vec<u8>),
    /// Body bytes still owed, from `Content-Length`. Zero ends the message.
    Body { left: u64 },
    /// The header never ended inside [`HEAD_LIMIT`]. Copy the rest.
    Pass,
}

impl Scan {
    fn head() -> Self {
        Self::Head(Vec::new())
    }

    /// Take a prefix of `input`, at most `max` bytes, into this message.
    /// The boolean is whether the message ends inside that prefix.
    fn take(&mut self, input: &[u8], max: usize) -> (usize, bool) {
        let input = &input[..input.len().min(max)];
        let mut used = 0;
        while used < input.len() {
            match self {
                Self::Pass => return (input.len(), false),
                Self::Body { left } if *left == 0 => return (used, true),
                Self::Body { left } => {
                    let room = input.len() - used;
                    let n = usize::try_from(*left).map_or(room, |left| left.min(room));
                    *left -= u64::try_from(n).expect("a slice length fits in u64");
                    used += n;
                    if *left == 0 {
                        return (used, true);
                    }
                    return (used, false);
                }
                Self::Head(buf) if buf.len() >= HEAD_LIMIT => {
                    *self = Self::Pass;
                    return (input.len(), false);
                }
                Self::Head(buf) => {
                    buf.push(input[used]);
                    used += 1;
                    if let Some(header_len) = header_end(buf) {
                        let left = body_len(&buf[..header_len]);
                        *self = Self::Body { left };
                    }
                }
            }
        }
        let ended = matches!(self, Self::Body { left: 0 });
        (used, ended)
    }
}

/// The index of the byte after `\r\n\r\n`, when the header has ended.
fn header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|four| four == b"\r\n\r\n")
        .map(|at| at + 4)
}

/// The body a request header names. No `Content-Length`, a second one, a
/// value that is not a length, or a `Transfer-Encoding` all mean the
/// message ends with the header: a request body this wrapper cannot bound
/// is not a submission's payload.
fn body_len(head: &[u8]) -> u64 {
    let mut found: Option<u64> = None;
    for line in head.split(|&byte| byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some((name, value)) = split_header(line) else {
            continue;
        };
        if name.eq_ignore_ascii_case(b"transfer-encoding") {
            return 0;
        }
        if name.eq_ignore_ascii_case(b"content-length") {
            let value = trim_ascii(value);
            let Ok(text) = std::str::from_utf8(value) else {
                return 0;
            };
            let Ok(length) = text.parse::<u64>() else {
                return 0;
            };
            if found.replace(length).is_some() {
                return 0;
            }
        }
    }
    found.unwrap_or(0)
}

/// The bytes before the first `:` and the bytes after it.
fn split_header(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let at = line.iter().position(|byte| *byte == b':')?;
    Some((&line[..at], &line[at + 1..]))
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |at| at + 1);
    &bytes[start..end]
}

/// The record stream hyper reads, one HTTP message at a time.
pub(crate) struct OneMessage<T> {
    inner: T,
    shape: InboundShape,
    scan: Scan,
    /// Bytes already pulled from `inner` and not yet forwarded.
    pending: Vec<u8>,
    /// One record's payload, reused so a read does not allocate it.
    scratch: Vec<u8>,
    /// Payload bytes forwarded, the submission span's index.
    copied: u64,
    /// [`Self::copied`] at the first byte of the message now open.
    message_start: u64,
    /// [`InboundShape::clear_message`] has run for the message now open.
    started: bool,
    /// The message's bytes have been forwarded. The next read waits until
    /// this side writes a response.
    hold: bool,
    read_waker: Option<Waker>,
}

impl<T> OneMessage<T> {
    pub(crate) fn new(inner: T, shape: InboundShape) -> Self {
        Self {
            inner,
            shape,
            scan: Scan::head(),
            pending: Vec::new(),
            scratch: vec![0u8; MAX_PAYLOAD],
            copied: 0,
            message_start: 0,
            started: false,
            hold: false,
            read_waker: None,
        }
    }

    fn finish_message(&mut self) {
        if self.pending.is_empty() {
            self.shape.note_message(self.message_start, self.copied);
        } else {
            // The frame continues past this message. Neither this message
            // nor the bytes left in it is the frame.
            self.shape.clear_message();
        }
        self.scan = Scan::head();
        self.hold = true;
        self.started = false;
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for OneMessage<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.hold {
            this.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        if !this.started {
            this.shape.clear_message();
            this.started = true;
        }
        let room = buf.remaining();
        if room == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.pending.is_empty() {
            let n = {
                let mut read = ReadBuf::new(&mut this.scratch);
                match Pin::new(&mut this.inner).poll_read(cx, &mut read) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => read.filled().len(),
                }
            };
            if n == 0 {
                this.shape.clear_message();
                return Poll::Ready(Ok(()));
            }
            this.pending.extend_from_slice(&this.scratch[..n]);
        }
        let (n, ended) = this.scan.take(&this.pending, room);
        if n > 0 {
            buf.put_slice(&this.pending[..n]);
            this.pending.drain(..n);
            this.copied += n as u64;
        }
        if ended {
            this.finish_message();
        }
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for OneMessage<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = result {
            if n > 0 && this.hold {
                this.hold = false;
                this.message_start = this.copied;
                if let Some(waker) = this.read_waker.take() {
                    waker.wake();
                }
            }
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two requests in one buffer end at the first. The second stays for
    /// the next message. Red edit: take the whole buffer in `Scan::take`,
    /// and `n` is the length of both.
    #[test]
    fn two_requests_in_one_buffer_end_at_the_first() {
        let first = "POST /json_rpc HTTP/1.1\r\ncontent-length: 1\r\n\r\nx";
        let second = "POST /json_rpc HTTP/1.1\r\ncontent-length: 1\r\n\r\ny";
        let mut both = Vec::new();
        both.extend_from_slice(first.as_bytes());
        both.extend_from_slice(second.as_bytes());
        let mut scan = Scan::head();
        let (n, ended) = scan.take(&both, both.len());
        assert!(ended);
        assert_eq!(n, first.len());
        assert_eq!(&both[n..], second.as_bytes());
    }

    /// A request with no length ends at the header.
    #[test]
    fn a_request_with_no_length_has_no_body() {
        let head = b"POST /json_rpc HTTP/1.1\r\n\r\n";
        let mut scan = Scan::head();
        let (n, ended) = scan.take(head, head.len());
        assert!(ended);
        assert_eq!(n, head.len());
        assert_eq!(body_len(head), 0);
    }
}
