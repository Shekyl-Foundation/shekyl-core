// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The seeds. Each one is a script for the peer and a plan for both hosts.
//! The byte layout is `P2P_DIFFERENTIAL_HARNESS.md`.

use shekyl_levin::{
    ingress_payload_cap, notify, response, BucketHead, Flags, COMMAND_HANDSHAKE,
    COMMAND_REQUEST_SUPPORT_FLAGS, COMMAND_TIMED_SYNC, HEADER_SIZE, NOTIFY_NEW_COMPACT_BLOCK,
};

use crate::handshake::handshake;
use crate::transcript::End;
use crate::Error;

pub const SEED_HANDSHAKE: u64 = 1;
pub const SEED_SPLIT_HEADER: u64 = 2;
pub const SEED_SPLIT_EACH_BYTE: u64 = 3;
pub const SEED_SIZE_SUPPORT: u64 = 10;
pub const SEED_SIZE_COMPACT: u64 = 11;
pub const SEED_CONCURRENT: u64 = 20;
pub const SEED_CLOSE_MID: u64 = 30;
pub const SEED_REFUSE: u64 = 31;
pub const SEED_SEND_OVER: u64 = 32;
pub const SEED_BACKPRESSURE: u64 = 40;

/// The seam host's send queue. One byte past it does not fit.
pub const SEND_QUEUE_BYTES: usize = 64 * 1024;

/// How long a backpressure host stops reading. A harness pause, not a deadline.
pub const READ_PAUSE: std::time::Duration = std::time::Duration::from_millis(400);

const PROPERTY_SEEDS: std::ops::Range<u64> = 100..116;
const CLOSE_AFTER: usize = 10;
/// Larger than this host's TCP window (`tcp_rmem` max is 6 MiB), so a write
/// while the host is not reading cannot hide in the kernel buffer.
const BACKPRESSURE_CHUNK: usize = 2 * 1024 * 1024;
const BACKPRESSURE_CHUNKS: usize = 4;

/// One stretch of bytes the peer writes, then how many whole messages it reads.
pub struct Phase {
    pub write: Vec<u8>,
    pub splits: Vec<usize>,
    pub read_messages: usize,
    /// Close the write side after this many bytes of [`Self::write`].
    pub close_after: Option<usize>,
}

/// What seed `N` does.
pub struct Script {
    pub phases: Vec<Phase>,
    pub expected_recv: Vec<u8>,
    pub end: End,
    pub version: u8,
    pub pause_after_handshake: bool,
    pub follow: Option<Vec<u8>>,
    pub send_over_cap: bool,
}

pub fn known_seed(seed: u64) -> bool {
    matches!(
        seed,
        SEED_HANDSHAKE
            | SEED_SPLIT_HEADER
            | SEED_SPLIT_EACH_BYTE
            | SEED_SIZE_SUPPORT
            | SEED_SIZE_COMPACT
            | SEED_CONCURRENT
            | SEED_CLOSE_MID
            | SEED_REFUSE
            | SEED_SEND_OVER
            | SEED_BACKPRESSURE
    ) || PROPERTY_SEEDS.contains(&seed)
}

/// Every seed the ctest runner must execute. The shell script's `SEEDS`
/// line is checked against this list.
pub fn all_seeds() -> Vec<u64> {
    let mut seeds = vec![
        SEED_HANDSHAKE,
        SEED_SPLIT_HEADER,
        SEED_SPLIT_EACH_BYTE,
        SEED_SIZE_SUPPORT,
        SEED_SIZE_COMPACT,
        SEED_CONCURRENT,
        SEED_CLOSE_MID,
        SEED_REFUSE,
        SEED_SEND_OVER,
        SEED_BACKPRESSURE,
    ];
    seeds.extend(PROPERTY_SEEDS);
    seeds
}

pub fn script(seed: u64) -> Result<Script, Error> {
    if !known_seed(seed) {
        return Err(Error::new(format!("no script for seed {seed}")));
    }
    let base = handshake(SEED_HANDSHAKE)?;
    let relay = notify(COMMAND_TIMED_SYNC, b"relay");
    match seed {
        SEED_HANDSHAKE => {
            let len = base.invoke.len();
            Ok(one_write(
                base.invoke,
                base.response,
                End::Established,
                vec![len],
            ))
        }
        SEED_SPLIT_HEADER => Ok(one_write(
            base.invoke.clone(),
            base.response,
            End::Established,
            vec![HEADER_SIZE, base.invoke.len()],
        )),
        SEED_SPLIT_EACH_BYTE => Ok(one_write(
            base.invoke.clone(),
            base.response,
            End::Established,
            (1..=base.invoke.len()).collect(),
        )),
        seed if PROPERTY_SEEDS.contains(&seed) => Ok(one_write(
            base.invoke.clone(),
            base.response,
            End::Established,
            stride_splits(base.invoke.len(), stride(seed)),
        )),
        SEED_SIZE_SUPPORT => {
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
        SEED_SIZE_COMPACT => {
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
                expected_recv: base.response,
                end: End::Established,
                version: 1,
                pause_after_handshake: false,
                follow: None,
                send_over_cap: false,
            })
        }
        SEED_CONCURRENT => {
            let mut expected = base.response.clone();
            expected.extend_from_slice(&relay);
            Ok(Script {
                phases: vec![Phase {
                    write: base.invoke.clone(),
                    splits: vec![base.invoke.len()],
                    read_messages: 2,
                    close_after: None,
                }],
                expected_recv: expected,
                end: End::Established,
                version: 1,
                pause_after_handshake: false,
                follow: Some(relay),
                send_over_cap: false,
            })
        }
        SEED_CLOSE_MID => Ok(Script {
            phases: vec![Phase {
                write: base.invoke[..CLOSE_AFTER].to_vec(),
                splits: vec![CLOSE_AFTER],
                read_messages: 0,
                close_after: Some(CLOSE_AFTER),
            }],
            expected_recv: Vec::new(),
            end: End::Closed,
            version: 1,
            pause_after_handshake: false,
            follow: None,
            send_over_cap: false,
        }),
        SEED_REFUSE => {
            let invoke = shekyl_levin::invoke(COMMAND_HANDSHAKE, &[1, 2, 3, 4]);
            let expected = response(COMMAND_HANDSHAKE, &[]);
            Ok(one_write(
                invoke.clone(),
                expected,
                End::Refused,
                vec![invoke.len()],
            ))
        }
        SEED_SEND_OVER => Ok(Script {
            phases: vec![Phase {
                write: base.invoke.clone(),
                splits: vec![base.invoke.len()],
                read_messages: 1,
                close_after: None,
            }],
            expected_recv: base.response,
            end: End::Established,
            version: 1,
            pause_after_handshake: false,
            follow: None,
            send_over_cap: true,
        }),
        SEED_BACKPRESSURE => {
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
                expected_recv: base.response,
                end: End::Established,
                version: 2,
                pause_after_handshake: true,
                follow: None,
                send_over_cap: false,
            })
        }
        _ => Err(Error::new(format!("no script for seed {seed}"))),
    }
}

fn one_write(outbound: Vec<u8>, expected: Vec<u8>, end: End, splits: Vec<usize>) -> Script {
    let read_messages = if end == End::Closed { 0 } else { 1 };
    Script {
        phases: vec![Phase {
            write: outbound,
            splits,
            read_messages,
            close_after: None,
        }],
        expected_recv: expected,
        end,
        version: 1,
        pause_after_handshake: false,
        follow: None,
        send_over_cap: false,
    }
}

fn payload_cap(command: u32) -> Result<usize, Error> {
    let cap =
        ingress_payload_cap(command, Flags::REQUEST).map_err(|err| Error::new(err.to_string()))?;
    usize::try_from(cap).map_err(|_| Error::new("cap"))
}

fn stride(seed: u64) -> usize {
    1 + (usize::try_from(seed).unwrap_or(0) % 17)
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
