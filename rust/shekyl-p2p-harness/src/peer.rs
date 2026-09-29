// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The scripted peer. It connects to an address, runs the seed's script,
//! and records every byte it sent and received.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use shekyl_levin::{BucketReader, HandshakeResponse, PortableMap, Received, COMMAND_HANDSHAKE};

use crate::handshake::handshake;
use crate::transcript::{End, Role, Transcript};
use crate::Error;

const WAIT: Duration = Duration::from_secs(3);

/// Dial `addr` and run `seed`. The seed is stored on the transcript.
pub fn run_peer(addr: SocketAddr, seed: u64) -> Result<Transcript, Error> {
    let script = handshake(seed)?;
    let mut sock = TcpStream::connect_timeout(&addr, WAIT)?;
    sock.set_read_timeout(Some(WAIT))?;
    sock.set_write_timeout(Some(WAIT))?;
    write_splits(&mut sock, &script.invoke, &script.splits)?;
    let recv = read_bucket(&mut sock)?;
    let end = session_end(&recv, &script.response);
    Ok(Transcript {
        seed,
        role: Role::Peer,
        sent: script.invoke,
        recv,
        end,
    })
}

fn write_splits(sock: &mut TcpStream, bytes: &[u8], splits: &[usize]) -> Result<(), Error> {
    let mut start = 0;
    for end in splits {
        if *end < start || *end > bytes.len() {
            return Err(Error::new("split past the message"));
        }
        sock.write_all(&bytes[start..*end])?;
        start = *end;
    }
    if start != bytes.len() {
        return Err(Error::new("splits do not cover the message"));
    }
    Ok(())
}

fn read_bucket(sock: &mut TcpStream) -> Result<Vec<u8>, Error> {
    let mut reader = BucketReader::new();
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    let start = Instant::now();
    loop {
        if reader.next_message()?.is_some() {
            return Ok(raw);
        }
        if start.elapsed() > WAIT {
            return Err(Error::new("peer timed out waiting for a bucket"));
        }
        match sock.read(&mut buf) {
            Ok(0) => return Ok(raw),
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                reader.feed(&buf[..n])?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {
                return Err(Error::new("peer timed out waiting for a bucket"));
            }
            Err(err) => return Err(err.into()),
        }
    }
}

/// Established only when the bytes are the handshake response for this seed.
fn session_end(recv: &[u8], expected: &[u8]) -> End {
    if recv.is_empty() {
        return End::Closed;
    }
    if recv != expected {
        return End::Refused;
    }
    let mut reader = BucketReader::new();
    if reader.feed(recv).is_err() {
        return End::Refused;
    }
    match reader.next_message() {
        Ok(Some(Received::Response { command, payload }))
            if command == COMMAND_HANDSHAKE && HandshakeResponse::load(&payload).is_ok() =>
        {
            End::Established
        }
        _ => End::Refused,
    }
}
