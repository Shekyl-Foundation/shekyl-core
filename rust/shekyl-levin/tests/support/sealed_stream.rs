// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A test peer's clearnet channel: the initiator's half of the Noise
//! handshake, then Levin bytes through [`Read`] and [`Write`]. Every clearnet
//! session a daemon holds is Noise, so a peer that speaks to one opens this
//! first.

#![allow(dead_code)]

use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use shekyl_p2p_transport::{
    prefix_for, Initiator, NetworkId, RecordError, RecvHalf, SendHalf, MESSAGE2_LEN, PREFIX_LEN,
};

/// How long the daemon has to answer the handshake on a loaded host.
const OPEN_WAIT: Duration = Duration::from_secs(10);
/// One socket read.
const READ_CHUNK: usize = 16 * 1024;

/// An open clearnet channel on a test peer's socket.
pub struct SealedStream {
    stream: TcpStream,
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
    /// Bytes the socket took and gave, the handshake included: what the
    /// daemon's link budget counts for this connection.
    on_wire_sent: u64,
    on_wire_received: u64,
}

impl SealedStream {
    /// Run the handshake on `stream` under `network`. The socket's read
    /// timeout is left as it was.
    ///
    /// # Errors
    ///
    /// The socket's, or [`ErrorKind::InvalidData`] for a handshake that does
    /// not verify. A daemon that refuses the connection closes it here.
    pub fn open(mut stream: TcpStream, network: &NetworkId) -> io::Result<Self> {
        let before = stream.read_timeout()?;
        stream.set_read_timeout(Some(OPEN_WAIT))?;
        let (initiator, message1) = Initiator::new(network).map_err(invalid)?;
        let mut flight = prefix_for(network).to_vec();
        flight.extend_from_slice(&message1);
        stream.write_all(&flight)?;
        let on_wire_sent = flight.len() as u64;
        let mut prefix = [0u8; PREFIX_LEN];
        stream.read_exact(&mut prefix)?;
        if prefix != prefix_for(network) {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "the daemon answered another network's prefix",
            ));
        }
        let mut message2 = vec![0u8; MESSAGE2_LEN];
        stream.read_exact(&mut message2)?;
        let (seal, open) = initiator.read_message2(&message2).map_err(invalid)?.split();
        stream.set_read_timeout(before)?;
        Ok(Self {
            stream,
            seal,
            open,
            unsent: Vec::new(),
            wire: Vec::new(),
            plain: Vec::new(),
            taken: 0,
            on_wire_sent,
            on_wire_received: (PREFIX_LEN + MESSAGE2_LEN) as u64,
        })
    }

    /// Every byte the socket has taken from this peer.
    pub fn on_wire_sent(&self) -> u64 {
        self.on_wire_sent
    }

    /// Every byte this peer has read from the socket.
    pub fn on_wire_received(&self) -> u64 {
        self.on_wire_received
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
        self.stream.shutdown(std::net::Shutdown::Write)
    }

    fn send_unsent(&mut self) -> io::Result<()> {
        while !self.unsent.is_empty() {
            let n = self.stream.write(&self.unsent)?;
            if n == 0 {
                return Err(ErrorKind::WriteZero.into());
            }
            self.unsent.drain(..n);
            self.on_wire_sent += n as u64;
        }
        Ok(())
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
            match self.open.open_one(&self.wire) {
                Ok((plain, used)) => {
                    self.wire.drain(..used);
                    self.plain = plain;
                    self.taken = 0;
                }
                Err(RecordError::Truncated) => {
                    let mut chunk = [0u8; READ_CHUNK];
                    let n = self.stream.read(&mut chunk)?;
                    if n == 0 {
                        return Ok(0);
                    }
                    self.wire.extend_from_slice(&chunk[..n]);
                    self.on_wire_received += n as u64;
                }
                Err(error) => return Err(invalid(error)),
            }
        }
    }
}
