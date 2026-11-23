// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The scripted peer. It connects to an address, opens the clearnet
//! channel, runs the seed's script, and records every session byte it sent
//! and received. A transcript is Levin bytes, never ciphertext: a Noise
//! session's keys are fresh each run, and the goldens compare what the
//! session carried. Each scripted write split is one sealed write.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use shekyl_levin::BucketReader;
use shekyl_p2p_transport::{
    prefix_for, Initiator, RecordError, RecvHalf, SendHalf, MESSAGE2_LEN, PREFIX_LEN,
};

use crate::script::{script, AfterHandshake, Phase, PEER_SEND_OVER_DRAIN, SEAM_NETWORK_ID};
use crate::transcript::{End, Event, Role, Transcript, TranscriptVersion};
use crate::Error;

const PEER_IO_WAIT: Duration = Duration::from_secs(3);
const PEER_STALL_PROBE: Duration = Duration::from_millis(50);
const PEER_STALL_CAP: Duration = Duration::from_secs(8);
const PEER_WRITE_CAP: Duration = Duration::from_secs(20);
const PEER_READ_CHUNK: usize = 4096;

/// The peer's socket with its open channel.
struct Channel {
    sock: TcpStream,
    send: SendHalf,
    recv: RecvHalf,
    /// Ciphertext read and not yet opened.
    pending: Vec<u8>,
}

impl Channel {
    /// Run the initiator's half of the handshake on `sock`.
    fn open(mut sock: TcpStream) -> Result<Self, Error> {
        let (initiator, message1) = Initiator::new(&SEAM_NETWORK_ID)
            .map_err(|err| Error::new(format!("noise initiator: {err:?}")))?;
        let mut flight = prefix_for(&SEAM_NETWORK_ID).to_vec();
        flight.extend_from_slice(&message1);
        sock.write_all(&flight)?;
        let mut prefix = [0u8; PREFIX_LEN];
        sock.read_exact(&mut prefix)?;
        if prefix != prefix_for(&SEAM_NETWORK_ID) {
            return Err(Error::new("the host answered another network's prefix"));
        }
        let mut message2 = vec![0u8; MESSAGE2_LEN];
        sock.read_exact(&mut message2)?;
        let (send, recv) = initiator
            .read_message2(&message2)
            .map_err(|err| Error::new(format!("noise message 2: {err:?}")))?
            .split();
        Ok(Self {
            sock,
            send,
            recv,
            pending: Vec::new(),
        })
    }

    /// The next whole record's plaintext, if one has already arrived.
    fn next_record(&mut self) -> Result<Option<Vec<u8>>, Error> {
        match self.recv.open_one(&self.pending) {
            Ok((plain, used)) => {
                self.pending.drain(..used);
                Ok(Some(plain))
            }
            Err(RecordError::Truncated) => Ok(None),
            Err(err) => Err(Error::new(format!("noise record: {err:?}"))),
        }
    }
}

/// Dial `addr` and run `seed`. The seed is stored on the transcript.
pub fn run_peer(addr: SocketAddr, seed: u64) -> Result<Transcript, Error> {
    let plan = script(seed)?;
    let sock = TcpStream::connect_timeout(&addr, PEER_IO_WAIT)?;
    sock.set_read_timeout(Some(PEER_IO_WAIT))?;
    sock.set_write_timeout(Some(PEER_IO_WAIT))?;
    let mut channel = Channel::open(sock)?;
    let mut sent = Vec::new();
    let mut recv = Vec::new();
    let mut events = Vec::new();
    for phase in &plan.phases {
        run_phase(
            &mut channel,
            phase,
            plan.version(),
            &mut sent,
            &mut recv,
            &mut events,
        )?;
    }
    if plan.after == AfterHandshake::SendOver {
        std::thread::sleep(PEER_SEND_OVER_DRAIN);
    }
    let end = if plan.recv_matches(&recv) {
        plan.end
    } else if recv.is_empty() && plan.end == End::Closed {
        End::Closed
    } else {
        End::Refused
    };
    Ok(Transcript {
        version: plan.version(),
        seed,
        role: Role::Peer,
        sent,
        recv,
        end,
        events,
    })
}

fn run_phase(
    channel: &mut Channel,
    phase: &Phase,
    version: TranscriptVersion,
    sent: &mut Vec<u8>,
    recv: &mut Vec<u8>,
    events: &mut Vec<Event>,
) -> Result<(), Error> {
    let stall = if version == TranscriptVersion::V2 && phase.close_after.is_none() {
        Some(&mut *events)
    } else {
        None
    };
    write_chunks(channel, &phase.write, &phase.splits, stall)?;
    if phase.close_after.is_some() {
        drop(channel.sock.shutdown(Shutdown::Write));
    }
    sent.extend_from_slice(&phase.write);
    if version == TranscriptVersion::V2 && phase.close_after.is_none() {
        events.push(Event::Wrote(phase.write.clone()));
    }
    let got = read_messages(channel, phase.read_messages)?;
    if version == TranscriptVersion::V2 && !got.is_empty() {
        events.push(Event::Read(got.clone()));
    }
    recv.extend_from_slice(&got);
    Ok(())
}

fn write_chunks(
    channel: &mut Channel,
    bytes: &[u8],
    splits: &[usize],
    mut stall: Option<&mut Vec<Event>>,
) -> Result<(), Error> {
    let note_stall = stall.is_some();
    if note_stall {
        channel.sock.set_write_timeout(Some(PEER_STALL_PROBE))?;
    }
    let cap = if note_stall {
        PEER_STALL_CAP
    } else {
        PEER_WRITE_CAP
    };
    let mut stalled = false;
    let started = Instant::now();
    let mut start = 0;
    for end in splits {
        if *end < start || *end > bytes.len() {
            return Err(Error::new("split past the message"));
        }
        let wire = channel
            .send
            .seal(&bytes[start..*end])
            .map_err(|err| Error::new(format!("noise seal: {err:?}")))?;
        let mut off = 0;
        while off < wire.len() {
            if started.elapsed() > cap {
                return Err(Error::new("peer write stalled too long"));
            }
            match channel.sock.write(&wire[off..]) {
                Ok(0) => return Err(Error::new("peer write closed")),
                Ok(n) => off += n,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                Err(err)
                    if err.kind() == std::io::ErrorKind::TimedOut
                        || err.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    if let Some(events) = stall.as_mut() {
                        if !stalled {
                            events.push(Event::Stalled);
                            stalled = true;
                        }
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
        if let Some(events) = stall {
            events.push(Event::Resumed);
        }
    }
    if note_stall {
        channel.sock.set_write_timeout(Some(PEER_IO_WAIT))?;
    }
    Ok(())
}

fn read_messages(channel: &mut Channel, messages: usize) -> Result<Vec<u8>, Error> {
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
                    // record. They are part of what the peer received.
                    return Ok(raw);
                }
            }
            None => {
                if start.elapsed() > PEER_IO_WAIT {
                    return Err(Error::new("peer timed out waiting for a bucket"));
                }
                if let Some(plain) = channel.next_record()? {
                    raw.extend_from_slice(&plain);
                    reader.feed(&plain)?;
                    continue;
                }
                let mut buf = [0u8; PEER_READ_CHUNK];
                match channel.sock.read(&mut buf) {
                    Ok(0) => return Err(Error::new("peer read closed")),
                    Ok(n) => channel.pending.extend_from_slice(&buf[..n]),
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
