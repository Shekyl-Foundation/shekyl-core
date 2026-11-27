// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A test peer's clearnet channel: the initiator's half of the Noise
//! handshake, then Levin bytes through [`Read`] and [`Write`]. Every clearnet
//! session a daemon holds is Noise, so a peer that speaks to one opens this
//! first.
//!
//! The handshake is [`shekyl_p2p_transport::Initiator::open`]. This type owns
//! what that call does not: the socket's byte counts, a record the socket
//! stopped taking, and a [`Read`] of the opened plaintext.

#![allow(dead_code)]

use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use shekyl_p2p_transport::{Initiator, NetworkId, OpenError, RecvHalf, SendHalf};

/// How long the daemon has to answer the handshake on a loaded host.
const OPEN_WAIT: Duration = Duration::from_secs(10);
/// One socket read.
const READ_CHUNK: usize = 16 * 1024;

/// Counts the bytes a socket takes and gives, the handshake included.
struct WireCount<S> {
    inner: S,
    sent: u64,
    received: u64,
}

impl<S: Read> Read for WireCount<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.received += n as u64;
        Ok(n)
    }
}

impl<S: Write> Write for WireCount<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.sent += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl WireCount<TcpStream> {
    fn set_read_timeout(&self, within: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(within)
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.inner.shutdown(std::net::Shutdown::Write)
    }
}

/// An open clearnet channel on a test peer's socket.
pub struct SealedStream {
    stream: WireCount<TcpStream>,
    seal: SendHalf,
    open: RecvHalf,
    /// Sealed bytes the socket has not taken: a record cannot be cut, so a
    /// write that times out part-way finishes on the next one.
    unsent: Vec<u8>,
    /// Ciphertext read and not yet opened.
    wire: Vec<u8>,
    /// An opened record, and how much of it has been read.
    plain: Vec<u8>,
    taken: usize,
}

impl SealedStream {
    /// Run the handshake on `stream` under `network`. The socket's read
    /// timeout is left as it was.
    ///
    /// # Errors
    ///
    /// The socket's, or [`ErrorKind::InvalidData`] for a handshake that does
    /// not verify. A daemon that refuses the connection closes it here.
    pub fn open(stream: TcpStream, network: &NetworkId) -> io::Result<Self> {
        let before = stream.read_timeout()?;
        let mut stream = WireCount {
            inner: stream,
            sent: 0,
            received: 0,
        };
        stream.set_read_timeout(Some(OPEN_WAIT))?;
        let (seal, open) = Initiator::open(&mut stream, network).map_err(open_io)?;
        stream.set_read_timeout(before)?;
        Ok(Self {
            stream,
            seal,
            open,
            unsent: Vec::new(),
            wire: Vec::new(),
            plain: Vec::new(),
            taken: 0,
        })
    }

    /// Every byte the socket has taken from this peer.
    pub fn on_wire_sent(&self) -> u64 {
        self.stream.sent
    }

    /// Every byte this peer has read from the socket.
    pub fn on_wire_received(&self) -> u64 {
        self.stream.received
    }

    /// The socket's read timeout.
    ///
    /// # Errors
    ///
    /// The socket's.
    pub fn set_read_timeout(&self, within: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(within)
    }

    /// Close this peer's sending half: the daemon reads the end of the
    /// stream, and this peer can still read what the daemon sends.
    ///
    /// # Errors
    ///
    /// The socket's.
    pub fn shutdown_write(&mut self) -> io::Result<()> {
        self.send_unsent()?;
        self.stream.shutdown_write()
    }

    fn send_unsent(&mut self) -> io::Result<()> {
        while !self.unsent.is_empty() {
            let n = self.stream.write(&self.unsent)?;
            if n == 0 {
                return Err(ErrorKind::WriteZero.into());
            }
            self.unsent.drain(..n);
        }
        Ok(())
    }
}

fn open_io(error: OpenError) -> io::Error {
    match error {
        OpenError::Io(error) => error,
        OpenError::Handshake(error) => io::Error::new(ErrorKind::InvalidData, error.to_string()),
        OpenError::Prefix => io::Error::new(
            ErrorKind::InvalidData,
            "the daemon answered another network's prefix",
        ),
    }
}

fn invalid(error: impl std::fmt::Debug) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, format!("{error:?}"))
}

fn timed_out(error: &io::Error) -> bool {
    matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

impl Write for SealedStream {
    /// Takes all of `buf` or none: once sealed, the record is this stream's
    /// to finish. A socket that stops taking it reports on the next write.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send_unsent()?;
        self.unsent = self.seal.seal(buf).map_err(invalid)?;
        match self.send_unsent() {
            Err(error) if !timed_out(&error) => Err(error),
            _ => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send_unsent()?;
        self.stream.flush()
    }
}

impl Read for SealedStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.taken < self.plain.len() {
                let n = buf.len().min(self.plain.len() - self.taken);
                buf[..n].copy_from_slice(&self.plain[self.taken..self.taken + n]);
                self.taken += n;
                return Ok(n);
            }
            match self.open.take_one(&mut self.wire) {
                Ok(Some(plain)) => {
                    self.plain = plain;
                    self.taken = 0;
                }
                Ok(None) => {
                    let mut chunk = [0u8; READ_CHUNK];
                    let n = self.stream.read(&mut chunk)?;
                    if n == 0 {
                        return Ok(0);
                    }
                    self.wire.extend_from_slice(&chunk[..n]);
                }
                Err(error) => return Err(invalid(error)),
            }
        }
    }
}
