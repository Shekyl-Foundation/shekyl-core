// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The seeds. Each one is a script for the peer and a host plan for both
//! stacks. The byte layout is `P2P_DIFFERENTIAL_HARNESS.md`.
//!
//! Host-side behaviour after the first invoke is [`AfterHandshake`], not a
//! pile of booleans. The epee binary takes that plan on its command line;
//! it does not own the seed table.

use std::ops::Range;
use std::time::Duration;

use shekyl_levin::{
    ingress_payload_cap, notify, response, BucketHead, Flags, COMMAND_HANDSHAKE,
    COMMAND_REQUEST_SUPPORT_FLAGS, COMMAND_TIMED_SYNC, HEADER_SIZE, NOTIFY_NEW_COMPACT_BLOCK,
};

use crate::handshake::handshake;
use crate::transcript::{End, TranscriptVersion};
use crate::Error;

/// Named legs. Property splits occupy [`PROPERTY_SEEDS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum NamedSeed {
    Handshake = 1,
    SplitHeader = 2,
    SplitEachByte = 3,
    SizeSupport = 10,
    SizeCompact = 11,
    Concurrent = 20,
    CloseMid = 30,
    Refuse = 31,
    SendOver = 32,
    Backpressure = 40,
}

impl NamedSeed {
    pub const ALL: [Self; 10] = [
        Self::Handshake,
        Self::SplitHeader,
        Self::SplitEachByte,
        Self::SizeSupport,
        Self::SizeCompact,
        Self::Concurrent,
        Self::CloseMid,
        Self::Refuse,
        Self::SendOver,
        Self::Backpressure,
    ];

    pub const fn as_u64(self) -> u64 {
        self as u64
    }

    pub fn from_u64(seed: u64) -> Option<Self> {
        Self::ALL.into_iter().find(|named| named.as_u64() == seed)
    }
}

/// Handshake invoke split on a stride derived from the seed.
pub const PROPERTY_SEEDS: Range<u64> = 100..116;

/// The seam host's send queue. One byte past it does not fit.
pub const SEND_QUEUE_BYTES: usize = 64 * 1024;

/// How long a backpressure host stops reading. A harness pause, not a deadline.
pub const READ_PAUSE: Duration = Duration::from_millis(400);

/// Let the handshake response leave before the cap refusal closes the queue.
pub const SEND_OVER_SETTLE: Duration = Duration::from_millis(50);

/// Stay up long enough for seed 32's refusal to be the cap, not a closed socket.
pub const PEER_SEND_OVER_DRAIN: Duration = Duration::from_millis(200);

const CLOSE_AFTER: usize = 10;
/// Larger than this host's TCP window (`tcp_rmem` max is 6 MiB), so a write
/// while the host is not reading cannot hide in the kernel buffer.
const BACKPRESSURE_CHUNK: usize = 2 * 1024 * 1024;
const BACKPRESSURE_CHUNKS: usize = 4;
const SPLIT_STRIDE_MOD: usize = 17;

/// What the host does after it has answered the first invoke.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AfterHandshake {
    None,
    /// Queue a `COMMAND_TIMED_SYNC` notify of the bytes `relay`.
    Follow,
    /// Queue one byte past [`SEND_QUEUE_BYTES`].
    SendOver,
    /// Stop reading for [`READ_PAUSE`].
    Pause,
}

impl AfterHandshake {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Follow => "follow",
            Self::SendOver => "send-over",
            Self::Pause => "pause",
        }
    }

    pub fn from_cli(text: &str) -> Result<Self, Error> {
        match text {
            "none" => Ok(Self::None),
            "follow" => Ok(Self::Follow),
            "send-over" => Ok(Self::SendOver),
            "pause" => Ok(Self::Pause),
            _ => Err(Error::new(format!("unknown after {text}"))),
        }
    }
}

/// One stretch of bytes the peer writes, then how many whole messages it reads.
pub struct Phase {
    pub write: Vec<u8>,
    pub splits: Vec<usize>,
    pub read_messages: usize,
    /// Close the write side after this many bytes of [`Self::write`].
    pub close_after: Option<usize>,
}

/// What seed `N` does. The comparator uses this as the oracle.
pub struct Script {
    pub phases: Vec<Phase>,
    /// Bytes the host sends answering the first invoke.
    pub invoke_reply: Vec<u8>,
    pub after: AfterHandshake,
    pub end: End,
}

impl Script {
    pub fn version(&self) -> TranscriptVersion {
        match self.after {
            AfterHandshake::Pause => TranscriptVersion::V2,
            AfterHandshake::None | AfterHandshake::Follow | AfterHandshake::SendOver => {
                TranscriptVersion::V1
            }
        }
    }

    pub fn follow_bytes(&self) -> Option<Vec<u8>> {
        match self.after {
            AfterHandshake::Follow => Some(timed_sync_relay()),
            AfterHandshake::None | AfterHandshake::SendOver | AfterHandshake::Pause => None,
        }
    }

    /// What the peer should read if both stacks follow the plan.
    ///
    /// Seed 32 may then see a suffix the epee host accepted past the seam cap.
    pub fn expected_recv(&self) -> Vec<u8> {
        let mut out = self.invoke_reply.clone();
        if let Some(follow) = self.follow_bytes() {
            out.extend_from_slice(&follow);
        }
        out
    }

    pub fn recv_matches(&self, recv: &[u8]) -> bool {
        let expected = self.expected_recv();
        recv == expected.as_slice()
            || (self.after == AfterHandshake::SendOver && recv.starts_with(&expected))
    }
}

pub fn known_seed(seed: u64) -> bool {
    NamedSeed::from_u64(seed).is_some() || PROPERTY_SEEDS.contains(&seed)
}

/// Every seed the differential runner must execute.
pub fn all_seeds() -> Vec<u64> {
    let mut seeds: Vec<u64> = NamedSeed::ALL.into_iter().map(NamedSeed::as_u64).collect();
    seeds.extend(PROPERTY_SEEDS);
    seeds
}

pub fn script(seed: u64) -> Result<Script, Error> {
    if let Some(named) = NamedSeed::from_u64(seed) {
        return named_script(named);
    }
    if PROPERTY_SEEDS.contains(&seed) {
        return property_script(seed);
    }
    Err(Error::new(format!("no script for seed {seed}")))
}

fn named_script(named: NamedSeed) -> Result<Script, Error> {
    let base = handshake()?;
    match named {
        NamedSeed::Handshake => {
            let len = base.invoke.len();
            Ok(one_write(
                base.invoke,
                base.response,
                End::Established,
                vec![len],
            ))
        }
        NamedSeed::SplitHeader => Ok(one_write(
            base.invoke.clone(),
            base.response,
            End::Established,
            vec![HEADER_SIZE, base.invoke.len()],
        )),
        NamedSeed::SplitEachByte => Ok(one_write(
            base.invoke.clone(),
            base.response,
            End::Established,
            (1..=base.invoke.len()).collect(),
        )),
        NamedSeed::SizeSupport => {
            let cap = payload_cap(COMMAND_REQUEST_SUPPORT_FLAGS)?;
            let invoke = shekyl_levin::invoke(COMMAND_REQUEST_SUPPORT_FLAGS, &vec![0x5a; cap]);
            let expected = response(COMMAND_REQUEST_SUPPORT_FLAGS, &[]);
            Ok(one_write(
                invoke.clone(),
                expected,
                End::Refused,
                vec![invoke.len()],
            ))
        }
        NamedSeed::SizeCompact => {
            // The notify follows the response, so the host has already raised
            // its packet cap. One concatenated write can land in the same
            // read that still has the pre-handshake limit.
            let cap = payload_cap(NOTIFY_NEW_COMPACT_BLOCK)?;
            let blob = notify(NOTIFY_NEW_COMPACT_BLOCK, &vec![0u8; cap]);
            let blob_len = blob.len();
            let invoke_len = base.invoke.len();
            Ok(Script {
                phases: vec![
                    Phase {
                        write: base.invoke.clone(),
                        splits: vec![invoke_len],
                        read_messages: 1,
                        close_after: None,
                    },
                    Phase {
                        write: blob,
                        splits: vec![blob_len],
                        read_messages: 0,
                        close_after: None,
                    },
                ],
                invoke_reply: base.response,
                after: AfterHandshake::None,
                end: End::Established,
            })
        }
        NamedSeed::Concurrent => Ok(Script {
            phases: vec![Phase {
                write: base.invoke.clone(),
                splits: vec![base.invoke.len()],
                read_messages: 2,
                close_after: None,
            }],
            invoke_reply: base.response,
            after: AfterHandshake::Follow,
            end: End::Established,
        }),
        NamedSeed::CloseMid => Ok(Script {
            phases: vec![Phase {
                write: base.invoke[..CLOSE_AFTER].to_vec(),
                splits: vec![CLOSE_AFTER],
                read_messages: 0,
                close_after: Some(CLOSE_AFTER),
            }],
            invoke_reply: Vec::new(),
            after: AfterHandshake::None,
            end: End::Closed,
        }),
        NamedSeed::Refuse => {
            let invoke = shekyl_levin::invoke(COMMAND_HANDSHAKE, &[1, 2, 3, 4]);
            let expected = response(COMMAND_HANDSHAKE, &[]);
            Ok(one_write(
                invoke.clone(),
                expected,
                End::Refused,
                vec![invoke.len()],
            ))
        }
        NamedSeed::SendOver => Ok(Script {
            phases: vec![Phase {
                write: base.invoke.clone(),
                splits: vec![base.invoke.len()],
                read_messages: 1,
                close_after: None,
            }],
            invoke_reply: base.response,
            after: AfterHandshake::SendOver,
            end: End::Established,
        }),
        NamedSeed::Backpressure => {
            let chunk = notify(NOTIFY_NEW_COMPACT_BLOCK, &vec![0u8; BACKPRESSURE_CHUNK]);
            let mut blob = Vec::with_capacity(chunk.len() * BACKPRESSURE_CHUNKS);
            for _ in 0..BACKPRESSURE_CHUNKS {
                blob.extend_from_slice(&chunk);
            }
            let blob_len = blob.len();
            Ok(Script {
                phases: vec![
                    Phase {
                        write: base.invoke.clone(),
                        splits: vec![base.invoke.len()],
                        read_messages: 1,
                        close_after: None,
                    },
                    Phase {
                        write: blob,
                        splits: vec![blob_len],
                        read_messages: 0,
                        close_after: None,
                    },
                ],
                invoke_reply: base.response,
                after: AfterHandshake::Pause,
                end: End::Established,
            })
        }
    }
}

fn property_script(seed: u64) -> Result<Script, Error> {
    let base = handshake()?;
    Ok(one_write(
        base.invoke.clone(),
        base.response,
        End::Established,
        stride_splits(base.invoke.len(), split_stride(seed)?),
    ))
}

fn one_write(outbound: Vec<u8>, invoke_reply: Vec<u8>, end: End, splits: Vec<usize>) -> Script {
    let read_messages = usize::from(end != End::Closed);
    Script {
        phases: vec![Phase {
            write: outbound,
            splits,
            read_messages,
            close_after: None,
        }],
        invoke_reply,
        after: AfterHandshake::None,
        end,
    }
}

pub fn timed_sync_relay() -> Vec<u8> {
    notify(COMMAND_TIMED_SYNC, b"relay")
}

fn payload_cap(command: u32) -> Result<usize, Error> {
    let cap =
        ingress_payload_cap(command, Flags::REQUEST).map_err(|err| Error::new(err.to_string()))?;
    usize::try_from(cap).map_err(|_| Error::new("cap"))
}

fn split_stride(seed: u64) -> Result<usize, Error> {
    let seed = usize::try_from(seed).map_err(|_| Error::new("seed"))?;
    Ok(1 + (seed % SPLIT_STRIDE_MOD))
}

fn stride_splits(len: usize, stride: usize) -> Vec<usize> {
    let mut splits = Vec::new();
    let mut at = stride;
    while at < len {
        splits.push(at);
        at += stride;
    }
    splits.push(len);
    splits
}

/// `Some(n)` when `bytes` is exactly `n` whole Levin messages.
pub fn whole_message_count(bytes: &[u8]) -> Option<usize> {
    let mut off = 0;
    let mut count = 0;
    while off < bytes.len() {
        let rest = bytes.len() - off;
        if rest < HEADER_SIZE {
            return None;
        }
        let head = BucketHead::read(bytes[off..off + HEADER_SIZE].try_into().ok()?).ok()?;
        let total = HEADER_SIZE + usize::try_from(head.payload_len).ok()?;
        if rest < total {
            return None;
        }
        off += total;
        count += 1;
    }
    Some(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn after_handshake_cli_round_trips() {
        for after in [
            AfterHandshake::None,
            AfterHandshake::Follow,
            AfterHandshake::SendOver,
            AfterHandshake::Pause,
        ] {
            assert_eq!(
                AfterHandshake::from_cli(after.as_str()).expect("cli"),
                after
            );
        }
    }

    #[test]
    fn every_named_and_property_seed_has_a_script() {
        let seeds = all_seeds();
        let property: Vec<u64> = PROPERTY_SEEDS.collect();
        assert_eq!(
            seeds.len(),
            NamedSeed::ALL.len() + property.len(),
            "the driver list is the named legs plus the property range"
        );
        assert!(!seeds.is_empty());
        for seed in seeds {
            script(seed).unwrap_or_else(|err| panic!("seed {seed}: {err}"));
        }
    }

    #[test]
    fn follow_expected_recv_is_reply_plus_relay() {
        let plan = script(NamedSeed::Concurrent.as_u64()).expect("script");
        let mut expected = plan.invoke_reply.clone();
        expected.extend_from_slice(&timed_sync_relay());
        assert_eq!(plan.expected_recv(), expected);
        assert_eq!(plan.after, AfterHandshake::Follow);
    }
}
