// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One run, written so a later run of the same seed can be diffed.
//!
//! The text is version 1 of the transcript in
//! `docs/design/P2P_DIFFERENTIAL_HARNESS.md`. That section is the
//! format both writers emit. A golden changes only when a ruling
//! changes the wire, in the same pull request as that ruling.

use std::fs;
use std::path::Path;
use std::str::FromStr;

use crate::Error;

const VERSION_1: &str = "shekyl-p2p-transcript 1";
const VERSION_2: &str = "shekyl-p2p-transcript 2";

/// How the run ended. Parity compares this. It is not a transport cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// The handshake response came back.
    Established,
    /// The peer closed before the response.
    Closed,
    /// The invoke was not a handshake.
    Refused,
}

impl End {
    fn as_str(self) -> &'static str {
        match self {
            Self::Established => "established",
            Self::Closed => "closed",
            Self::Refused => "refused",
        }
    }
}

impl FromStr for End {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        match text {
            "established" => Ok(Self::Established),
            "closed" => Ok(Self::Closed),
            "refused" => Ok(Self::Refused),
            _ => Err(Error::new(format!("unknown end {text}"))),
        }
    }
}

/// Who wrote the record. The byte fields mean different things.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// `sent` is what the peer wrote. `recv` is what it read back.
    Peer,
    /// `sent` is what the Levin handler sent. `recv` is what it was delivered.
    Host,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Self::Peer => "peer",
            Self::Host => "host",
        }
    }
}

impl FromStr for Role {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        match text {
            "peer" => Ok(Self::Peer),
            "host" => Ok(Self::Host),
            _ => Err(Error::new(format!("unknown role {text}"))),
        }
    }
}

/// One step in a version-2 log. No timestamps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Wrote(Vec<u8>),
    Read(Vec<u8>),
    Stalled,
    Resumed,
}

impl Event {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Wrote(_) => "wrote",
            Self::Read(_) => "read",
            Self::Stalled => "stalled",
            Self::Resumed => "resumed",
        }
    }
}

/// A seeded run. The seed is how a failing case is replayed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transcript {
    /// 1, or 2 when [`Self::events`] is the backpressure log.
    pub version: u8,
    pub seed: u64,
    pub role: Role,
    pub sent: Vec<u8>,
    pub recv: Vec<u8>,
    pub end: End,
    pub events: Vec<Event>,
}

impl Transcript {
    pub fn write(&self, path: &Path) -> Result<(), Error> {
        fs::write(path, self.encode()).map_err(Error::from)
    }

    pub fn read(path: &Path) -> Result<Self, Error> {
        let text = fs::read_to_string(path).map_err(Error::from)?;
        Self::decode(&text)
    }

    pub fn encode(&self) -> String {
        let version = if self.version == 2 {
            VERSION_2
        } else {
            VERSION_1
        };
        let mut out = format!(
            "{version}\nseed {}\nrole {}\nsent {}\nrecv {}\nend {}\n",
            self.seed,
            self.role.as_str(),
            hex(&self.sent),
            hex(&self.recv),
            self.end.as_str(),
        );
        if self.version == 2 {
            for event in &self.events {
                out.push_str(&encode_event(event));
            }
        }
        out
    }

    pub fn decode(text: &str) -> Result<Self, Error> {
        let mut lines = text.lines();
        let version_line = lines.next().ok_or_else(|| Error::new("empty transcript"))?;
        let version = match version_line {
            VERSION_1 => 1,
            VERSION_2 => 2,
            other => return Err(Error::new(format!("unknown transcript {other}"))),
        };
        let seed = value(lines.next(), "seed")?;
        let role = value(lines.next(), "role")?;
        let sent = value(lines.next(), "sent")?;
        let recv = value(lines.next(), "recv")?;
        let end = value(lines.next(), "end")?;
        let mut events = Vec::new();
        if version == 2 {
            for line in lines {
                events.push(decode_event(line)?);
            }
        } else if lines.next().is_some() {
            return Err(Error::new("trailing transcript line"));
        }
        Ok(Self {
            version,
            seed: seed.parse().map_err(|_| Error::new("seed is not a u64"))?,
            role: role.parse()?,
            sent: unhex(sent)?,
            recv: unhex(recv)?,
            end: end.parse()?,
            events,
        })
    }
}

fn encode_event(event: &Event) -> String {
    match event {
        Event::Wrote(bytes) => format!("event wrote {}\n", hex(bytes)),
        Event::Read(bytes) => format!("event read {}\n", hex(bytes)),
        Event::Stalled => "event stalled\n".to_string(),
        Event::Resumed => "event resumed\n".to_string(),
    }
}

fn decode_event(line: &str) -> Result<Event, Error> {
    let rest = line
        .strip_prefix("event ")
        .ok_or_else(|| Error::new("expected event"))?;
    if let Some(hex_text) = rest.strip_prefix("wrote ") {
        return Ok(Event::Wrote(unhex(hex_text)?));
    }
    if let Some(hex_text) = rest.strip_prefix("read ") {
        return Ok(Event::Read(unhex(hex_text)?));
    }
    match rest {
        "stalled" => Ok(Event::Stalled),
        "resumed" => Ok(Event::Resumed),
        _ => Err(Error::new(format!("unknown event {rest}"))),
    }
}

fn value<'a>(line: Option<&'a str>, key: &str) -> Result<&'a str, Error> {
    let line = line.ok_or_else(|| Error::new(format!("missing {key}")))?;
    let rest = line
        .strip_prefix(key)
        .ok_or_else(|| Error::new(format!("expected {key}")))?;
    Ok(rest.strip_prefix(' ').unwrap_or(""))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0xf) as usize] as char);
    }
    out
}

fn unhex(text: &str) -> Result<Vec<u8>, Error> {
    if !text.len().is_multiple_of(2) {
        return Err(Error::new("odd hex length"));
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = unhex_digit(bytes[i])?;
        let lo = unhex_digit(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn unhex_digit(byte: u8) -> Result<u8, Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(Error::new("hex digit")),
    }
}
