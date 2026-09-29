// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The scripted peer. It connects to an address, runs the seed's script,
//! and records every byte it sent and received.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use std::net::Shutdown;

use shekyl_levin::BucketReader;

use crate::script::{script, Phase};
use crate::transcript::{End, Event, Role, Transcript};
use crate::Error;

const WAIT: Duration = Duration::from_secs(3);

/// Dial `addr` and run `seed`. The seed is stored on the transcript.
pub fn run_peer(addr: SocketAddr, seed: u64) -> Result<Transcript, Error> {
    let script = script(seed)?;
    let mut sock = TcpStream::connect_timeout(&addr, WAIT)?;
    sock.set_read_timeout(Some(WAIT))?;
    sock.set_write_timeout(Some(WAIT))?;
    let mut sent = Vec::new();
    let mut recv = Vec::new();
    let mut events = Vec::new();
    for phase in &script.phases {
        run_phase(
            &mut sock,
            phase,
            script.version,
            &mut sent,
            &mut recv,
            &mut events,
        )?;
    }
    // Seed 32's host refuses one extra send after the response has left.
    // Stay up long enough for that refusal to be the cap, not a closed socket.
    if script.send_over_cap {
        std::thread::sleep(Duration::from_millis(200));
    }
    let matched = recv == script.expected_recv
        || (script.send_over_cap && recv.starts_with(&script.expected_recv));
    let end = if matched {
        script.end
    } else if recv.is_empty() && script.end == End::Closed {
        End::Closed
    } else {
        End::Refused
    };
    Ok(Transcript {
        version: script.version,
        seed,
        role: Role::Peer,
        sent,
        recv,
        end,
        events,
    })
}

fn run_phase(
    sock: &mut TcpStream,
    phase: &Phase,
    version: u8,
    sent: &mut Vec<u8>,
    recv: &mut Vec<u8>,
    events: &mut Vec<Event>,
) -> Result<(), Error> {
    let wrote = if phase.close_after.is_some() {
        write_splits(sock, &phase.write, &phase.splits)?;
        match sock.shutdown(Shutdown::Write) {
            Ok(()) | Err(_) => {}
        }
        phase.write.clone()
    } else {
        write_tracking(sock, &phase.write, &phase.splits, version == 2, events)?
    };
    sent.extend_from_slice(&wrote);
    if version == 2 && phase.close_after.is_none() {
        events.push(Event::Wrote(wrote));
    }
    let got = read_messages(sock, phase.read_messages)?;
    if version == 2 && !got.is_empty() {
        events.push(Event::Read(got.clone()));
    }
    recv.extend_from_slice(&got);
    Ok(())
}

fn write_tracking(
    sock: &mut TcpStream,
    bytes: &[u8],
    splits: &[usize],
    note_stall: bool,
    events: &mut Vec<Event>,
) -> Result<Vec<u8>, Error> {
    if !note_stall {
        write_splits(sock, bytes, splits)?;
        return Ok(bytes.to_vec());
    }
    sock.set_write_timeout(Some(Duration::from_millis(50)))?;
    let mut stalled = false;
    let started = Instant::now();
    let mut start = 0;
    for end in splits {
        if *end < start || *end > bytes.len() {
            return Err(Error::new("split past the message"));
        }
        let mut off = start;
        while off < *end {
            if started.elapsed() > Duration::from_secs(8) {
                return Err(Error::new("peer write stalled too long"));
            }
            match sock.write(&bytes[off..*end]) {
                Ok(0) => return Err(Error::new("peer write closed")),
                Ok(n) => off += n,
                Err(err)
                    if err.kind() == std::io::ErrorKind::TimedOut
                        || err.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    if !stalled {
                        events.push(Event::Stalled);
                        stalled = true;
                    }
                }
                Err(err) => return Err(err.into()),
            }
        }
        start = *end;
    }
    if start != bytes.len() {
        return Err(Error::new("splits do not cover the message"));
    }
    if stalled {
        events.push(Event::Resumed);
    }
    sock.set_write_timeout(Some(WAIT))?;
    Ok(bytes.to_vec())
}

fn write_splits(sock: &mut TcpStream, bytes: &[u8], splits: &[usize]) -> Result<(), Error> {
    let mut start = 0;
    let started = Instant::now();
    for end in splits {
        if *end < start || *end > bytes.len() {
            return Err(Error::new("split past the message"));
        }
        let mut off = start;
        while off < *end {
            if started.elapsed() > Duration::from_secs(20) {
                return Err(Error::new("peer write stalled too long"));
            }
            match sock.write(&bytes[off..*end]) {
                Ok(0) => return Err(Error::new("peer write closed")),
                Ok(n) => off += n,
                Err(err)
                    if err.kind() == std::io::ErrorKind::TimedOut
                        || err.kind() == std::io::ErrorKind::WouldBlock
                        || err.kind() == std::io::ErrorKind::Interrupted => {}
                Err(err) => return Err(err.into()),
            }
        }
        start = *end;
    }
    if start != bytes.len() {
        return Err(Error::new("splits do not cover the message"));
    }
    Ok(())
}

fn read_messages(sock: &mut TcpStream, messages: usize) -> Result<Vec<u8>, Error> {
    if messages == 0 {
        return Ok(Vec::new());
    }
    let mut reader = BucketReader::new();
    let mut raw = Vec::new();
    let mut count = 0;
    let start = Instant::now();
    loop {
        match reader.next_message()? {
            Some(_) => {
                count += 1;
                if count == messages {
                    // Bytes past the last requested message were in the same
                    // read. They are part of what the peer received.
                    return Ok(raw);
                }
            }
            None => {
                if start.elapsed() > WAIT {
                    return Err(Error::new("peer timed out waiting for a bucket"));
                }
                let mut buf = [0u8; 4096];
                match sock.read(&mut buf) {
                    Ok(0) => return Err(Error::new("peer read closed")),
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
    }
}
