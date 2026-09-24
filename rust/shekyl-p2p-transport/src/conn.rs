// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Clearnet socket owned by Rust. The caller hands over a connected
//! `std::net::TcpStream`. This loop speaks the prefix and the handshake,
//! then returns plaintext Levin bytes.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use crate::channel::{Channel, RecordError};
use crate::noise::{Handshake, MESSAGE1_LEN, MESSAGE2_LEN};
use crate::prefix::{prefix_for, NetworkId, PREFIX_LEN};
use crate::{INITIATOR_FLIGHT_LEN, RESPONDER_FLIGHT_LEN};

/// Local liveness bound for the handshake. Not a consensus constant: a peer
/// that cannot finish one flight in this time is closed.
pub const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(15);

pub fn handshake_deadline() -> Duration {
    HANDSHAKE_DEADLINE
}

#[derive(Debug)]
pub enum AcceptError {
    Io,
    Prefix,
    Handshake,
    Timeout,
    Record(RecordError),
}

pub struct ClearnetSocket {
    stream: TcpStream,
    channel: Channel,
    inbound: Vec<u8>,
    plain: Vec<u8>,
}

impl ClearnetSocket {
    pub fn connect(stream: TcpStream, network_id: &NetworkId) -> Result<Self, AcceptError> {
        stream.set_nonblocking(false).map_err(|_| AcceptError::Io)?;
        stream
            .set_read_timeout(Some(HANDSHAKE_DEADLINE))
            .map_err(|_| AcceptError::Io)?;
        stream
            .set_write_timeout(Some(HANDSHAKE_DEADLINE))
            .map_err(|_| AcceptError::Io)?;
        let started = Instant::now();
        let (hs, msg1) = Handshake::initiator(network_id).map_err(|_| AcceptError::Handshake)?;
        let mut flight = Vec::with_capacity(INITIATOR_FLIGHT_LEN);
        flight.extend_from_slice(&prefix_for(network_id));
        flight.extend_from_slice(&msg1);
        let mut stream = stream;
        stream.write_all(&flight).map_err(|_| AcceptError::Io)?;
        let mut msg2 = read_exact_deadline(&mut stream, RESPONDER_FLIGHT_LEN, started)?;
        let got_prefix = &msg2[..PREFIX_LEN];
        if got_prefix != prefix_for(network_id) {
            return Err(AcceptError::Prefix);
        }
        let mut hs = hs;
        hs.read_message2(&msg2[PREFIX_LEN..])
            .map_err(|_| AcceptError::Handshake)?;
        msg2.fill(0);
        let channel = hs.split().map_err(|_| AcceptError::Handshake)?;
        Ok(Self {
            stream,
            channel,
            inbound: Vec::new(),
            plain: Vec::new(),
        })
    }

    pub fn accept(stream: TcpStream, network_id: &NetworkId) -> Result<Self, AcceptError> {
        stream.set_nonblocking(false).map_err(|_| AcceptError::Io)?;
        stream
            .set_read_timeout(Some(HANDSHAKE_DEADLINE))
            .map_err(|_| AcceptError::Io)?;
        stream
            .set_write_timeout(Some(HANDSHAKE_DEADLINE))
            .map_err(|_| AcceptError::Io)?;
        let started = Instant::now();
        let mut stream = stream;
        let mut flight = read_exact_deadline(&mut stream, INITIATOR_FLIGHT_LEN, started)?;
        if flight[..PREFIX_LEN] != prefix_for(network_id) {
            return Err(AcceptError::Prefix);
        }
        let mut hs = Handshake::responder(network_id);
        let msg2 = hs
            .read_message1_write_message2(&flight[PREFIX_LEN..])
            .map_err(|_| AcceptError::Handshake)?;
        flight.fill(0);
        let mut out = Vec::with_capacity(RESPONDER_FLIGHT_LEN);
        out.extend_from_slice(&prefix_for(network_id));
        out.extend_from_slice(&msg2);
        stream.write_all(&out).map_err(|_| AcceptError::Io)?;
        let channel = hs.split().map_err(|_| AcceptError::Handshake)?;
        Ok(Self {
            stream,
            channel,
            inbound: Vec::new(),
            plain: Vec::new(),
        })
    }

    pub fn clear_io_timeouts(&self) -> std::io::Result<()> {
        self.stream.set_read_timeout(None)?;
        self.stream.set_write_timeout(None)
    }

    pub fn shutdown(&self) -> std::io::Result<()> {
        self.stream.shutdown(std::net::Shutdown::Both)
    }

    pub fn try_clone_stream(&self) -> std::io::Result<TcpStream> {
        self.stream.try_clone()
    }

    fn into_io(
        self,
    ) -> (
        crate::channel::SendHalf,
        crate::channel::RecvHalf,
        TcpStream,
    ) {
        let (send, recv) = self.channel.split_io();
        (send, recv, self.stream)
    }

    pub fn write_plain(&mut self, plaintext: &[u8]) -> Result<(), AcceptError> {
        let wire = self.channel.seal(plaintext).map_err(AcceptError::Record)?;
        self.stream.write_all(&wire).map_err(|_| AcceptError::Io)?;
        Ok(())
    }

    pub fn read_plain(&mut self, buf: &mut [u8]) -> Result<usize, AcceptError> {
        if self.plain.is_empty() {
            self.pull_one()?;
        }
        let n = buf.len().min(self.plain.len());
        buf[..n].copy_from_slice(&self.plain[..n]);
        self.plain.drain(..n);
        Ok(n)
    }

    fn pull_one(&mut self) -> Result<(), AcceptError> {
        let mut tmp = [0u8; 4096];
        loop {
            match self.channel.open_one(&self.inbound) {
                Ok((pt, used)) => {
                    self.inbound.drain(..used);
                    self.plain.extend_from_slice(&pt);
                    return Ok(());
                }
                Err(RecordError::Truncated) => {
                    let n = self.stream.read(&mut tmp).map_err(|_| AcceptError::Io)?;
                    if n == 0 {
                        return Err(AcceptError::Io);
                    }
                    self.inbound.extend_from_slice(&tmp[..n]);
                }
                Err(e) => return Err(AcceptError::Record(e)),
            }
        }
    }
}

fn read_exact_deadline(
    stream: &mut TcpStream,
    len: usize,
    started: Instant,
) -> Result<Vec<u8>, AcceptError> {
    let mut buf = vec![0u8; len];
    let mut filled = 0;
    while filled < len {
        if started.elapsed() > HANDSHAKE_DEADLINE {
            return Err(AcceptError::Timeout);
        }
        let n = stream
            .read(&mut buf[filled..])
            .map_err(|_| AcceptError::Io)?;
        if n == 0 {
            return Err(AcceptError::Io);
        }
        filled += n;
    }
    if len != MESSAGE1_LEN + PREFIX_LEN && len != MESSAGE2_LEN + PREFIX_LEN {
        return Err(AcceptError::Handshake);
    }
    Ok(buf)
}

/// Two loopback sockets. The dialer writes `first` after the handshake.
pub fn run_pair(network_id: &NetworkId, first: &[u8]) -> Result<Vec<u8>, AcceptError> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|_| AcceptError::Io)?;
    let port = listener.local_addr().map_err(|_| AcceptError::Io)?.port();
    let nid = *network_id;
    let first = first.to_vec();
    let payload = first.clone();
    let dialer = std::thread::spawn(move || {
        let stream = TcpStream::connect(("127.0.0.1", port)).map_err(|_| AcceptError::Io)?;
        let mut sock = ClearnetSocket::connect(stream, &nid)?;
        sock.write_plain(&payload)?;
        let mut got = vec![0u8; payload.len()];
        let mut filled = 0;
        while filled < got.len() {
            let n = sock.read_plain(&mut got[filled..])?;
            if n == 0 {
                return Err(AcceptError::Io);
            }
            filled += n;
        }
        Ok::<Vec<u8>, AcceptError>(got)
    });
    let (stream, _) = listener.accept().map_err(|_| AcceptError::Io)?;
    let mut sock = ClearnetSocket::accept(stream, network_id)?;
    let mut got = vec![0u8; first.len()];
    let mut filled = 0;
    while filled < got.len() {
        let n = sock.read_plain(&mut got[filled..])?;
        if n == 0 {
            return Err(AcceptError::Io);
        }
        filled += n;
    }
    sock.write_plain(&got)?;
    let echoed = dialer.join().map_err(|_| AcceptError::Io)??;
    if echoed != got {
        return Err(AcceptError::Handshake);
    }
    Ok(got)
}

/// How many plaintext writes may sit ahead of the socket. Past this, `write`
/// fails instead of blocking the caller or growing without a bound.
const WRITE_QUEUE: usize = 8;
/// How many received records may be waiting on the C++ strand.
const READ_IN_FLIGHT: usize = 4;

struct Budget {
    in_flight: usize,
    stop: bool,
}

/// A socket Rust owns after the C++ handoff. The reader never holds the
/// writer, so a Levin send cannot deadlock on a blocked read.
pub struct Link {
    outbound: std::sync::Mutex<Option<std::sync::mpsc::SyncSender<Vec<u8>>>>,
    killer: TcpStream,
    budget: std::sync::Arc<(std::sync::Mutex<Budget>, std::sync::Condvar)>,
    reader: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    writer: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

pub type PlainCallback = extern "C" fn(*mut std::ffi::c_void, *const u8, usize);

impl Link {
    pub fn attach(
        stream: TcpStream,
        network_id: &NetworkId,
        initiator: bool,
        on_plain: PlainCallback,
        ctx: *mut std::ffi::c_void,
    ) -> Result<Box<Self>, AcceptError> {
        let sock = if initiator {
            ClearnetSocket::connect(stream, network_id)?
        } else {
            ClearnetSocket::accept(stream, network_id)?
        };
        let killer = sock.try_clone_stream().map_err(|_| AcceptError::Io)?;
        sock.clear_io_timeouts().map_err(|_| AcceptError::Io)?;
        let (send, recv, write_stream) = sock.into_io();
        let read_stream = killer.try_clone().map_err(|_| AcceptError::Io)?;
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(WRITE_QUEUE);
        let budget = std::sync::Arc::new((
            std::sync::Mutex::new(Budget {
                in_flight: 0,
                stop: false,
            }),
            std::sync::Condvar::new(),
        ));
        let writer_budget = std::sync::Arc::clone(&budget);
        let writer = std::thread::spawn(move || {
            let mut send = send;
            let mut write_stream = write_stream;
            while let Ok(plain) = rx.recv() {
                if writer_budget.0.lock().map(|g| g.stop).unwrap_or(true) {
                    break;
                }
                let Ok(wire) = send.seal(&plain) else {
                    break;
                };
                if write_stream.write_all(&wire).is_err() {
                    break;
                }
            }
        });
        let reader_budget = std::sync::Arc::clone(&budget);
        let ctx_bits = ctx as usize;
        let reader = std::thread::spawn(move || {
            let mut recv = recv;
            let mut read_stream = read_stream;
            let mut inbound = Vec::new();
            let mut plain = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                if !wait_budget(&reader_budget) {
                    return;
                }
                let n = match pull_plain(
                    &mut recv,
                    &mut read_stream,
                    &mut inbound,
                    &mut plain,
                    &mut tmp,
                ) {
                    Ok(n) => n,
                    Err(_) => return,
                };
                if n == 0 {
                    continue;
                }
                if let Ok(mut guard) = reader_budget.0.lock() {
                    guard.in_flight += 1;
                }
                on_plain(ctx_bits as *mut std::ffi::c_void, plain.as_ptr(), n);
                plain.drain(..n);
            }
        });
        Ok(Box::new(Self {
            outbound: std::sync::Mutex::new(Some(tx)),
            killer,
            budget,
            reader: std::sync::Mutex::new(Some(reader)),
            writer: std::sync::Mutex::new(Some(writer)),
        }))
    }

    pub fn write(&self, plaintext: &[u8]) -> Result<(), AcceptError> {
        let guard = self.outbound.lock().map_err(|_| AcceptError::Io)?;
        let Some(tx) = guard.as_ref() else {
            return Err(AcceptError::Io);
        };
        tx.try_send(plaintext.to_vec()).map_err(|_| AcceptError::Io)
    }

    /// Unblock the reader and writer, then join them.
    pub fn shutdown(&self) {
        if let Ok(mut budget) = self.budget.0.lock() {
            budget.stop = true;
            self.budget.1.notify_all();
        }
        let _ = self.killer.shutdown(std::net::Shutdown::Both);
        if let Ok(mut slot) = self.outbound.lock() {
            slot.take();
        }
        if let Ok(mut slot) = self.writer.lock() {
            if let Some(writer) = slot.take() {
                let _ = writer.join();
            }
        }
        if let Ok(mut slot) = self.reader.lock() {
            if let Some(reader) = slot.take() {
                let _ = reader.join();
            }
        }
    }
}

fn wait_budget(budget: &std::sync::Arc<(std::sync::Mutex<Budget>, std::sync::Condvar)>) -> bool {
    let Ok(mut guard) = budget.0.lock() else {
        return false;
    };
    while guard.in_flight >= READ_IN_FLIGHT && !guard.stop {
        guard = match budget.1.wait(guard) {
            Ok(g) => g,
            Err(_) => return false,
        };
    }
    !guard.stop
}

/// C++ calls this once `handle_recv` has finished with a posted buffer.
pub fn release_read_budget(link: &Link) {
    if let Ok(mut guard) = link.budget.0.lock() {
        guard.in_flight = guard.in_flight.saturating_sub(1);
        link.budget.1.notify_one();
    }
}

fn pull_plain(
    recv: &mut crate::channel::RecvHalf,
    stream: &mut TcpStream,
    inbound: &mut Vec<u8>,
    plain: &mut Vec<u8>,
    tmp: &mut [u8],
) -> Result<usize, AcceptError> {
    if plain.is_empty() {
        loop {
            match recv.open_one(inbound) {
                Ok((pt, used)) => {
                    inbound.drain(..used);
                    plain.extend_from_slice(&pt);
                    break;
                }
                Err(RecordError::Truncated) => {
                    let n = stream.read(tmp).map_err(|_| AcceptError::Io)?;
                    if n == 0 {
                        return Err(AcceptError::Io);
                    }
                    inbound.extend_from_slice(&tmp[..n]);
                }
                Err(e) => return Err(AcceptError::Record(e)),
            }
        }
    }
    Ok(plain.len())
}

impl Drop for Link {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_carries_a_levin_shaped_buffer() {
        let body = b"COMMAND_HANDSHAKE-shaped-bytes";
        let got = run_pair(&[0x55; 16], body).unwrap();
        assert_eq!(got, body);
    }
}
