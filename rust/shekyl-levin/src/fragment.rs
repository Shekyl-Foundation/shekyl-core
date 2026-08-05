// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Dummy ("noise") messages and noise-shaped fragmentation, byte-identical
//! to `epee::levin::make_noise_notify` / `make_fragmented_notify`
//! (`contrib/epee/src/levin_base.cpp`). Used by the white-noise feature over
//! i2p/Tor: every emitted message is exactly `noise_size` bytes so real
//! traffic is indistinguishable from dummies.

use crate::error::Error;
use crate::header::{BucketHead, Flags, HEADER_SIZE};
use crate::message::notify;

/// A dummy message of exactly `noise_bytes` total length: command `0`,
/// `B|E` set, zeroed payload. Receivers discard it.
///
/// # Errors
///
/// [`Error::NoiseTooSmall`] if `noise_bytes` cannot hold the header
/// (the C++ returns `nullptr`).
pub fn noise_notify(noise_bytes: usize) -> Result<Vec<u8>, Error> {
    if noise_bytes < HEADER_SIZE {
        return Err(Error::NoiseTooSmall {
            requested: noise_bytes,
            minimum: HEADER_SIZE,
        });
    }
    let payload_len = noise_bytes - HEADER_SIZE;
    let head = BucketHead::make(
        0,
        u64::try_from(payload_len).expect("usize fits in u64"),
        Flags::BEGIN.union(Flags::END),
        false,
    );
    let mut out = vec![0u8; noise_bytes];
    out[..HEADER_SIZE].copy_from_slice(&head.write());
    Ok(out)
}

/// Emit a notification for `command` as one or more messages, each exactly
/// `noise_size` bytes (the size of the accompanying noise stream).
///
/// Mirrors `make_fragmented_notify`:
///
/// - if the whole notification (header + payload) fits in `noise_size`, it
///   is sent as a single ordinary notification whose payload is zero-padded
///   to fill `noise_size` exactly (the payload parser ignores trailing
///   bytes);
/// - otherwise the finalized notification (inner header included) is split
///   across fragments: every fragment header claims `noise_size - 33` bytes
///   of body, the first sets `B`, middles set neither, the last sets `E`
///   and its body is zero-padded to the same length.
///
/// # Errors
///
/// [`Error::NoiseTooSmall`] if `noise_size` is below two headers' worth of
/// bytes (the C++ returns `nullptr`).
pub fn fragmented_notify(
    noise_size: usize,
    command: u32,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    if noise_size < HEADER_SIZE * 2 {
        return Err(Error::NoiseTooSmall {
            requested: noise_size,
            minimum: HEADER_SIZE * 2,
        });
    }

    // Whole message fits: pad the payload and send a normal notification.
    if HEADER_SIZE + payload.len() <= noise_size {
        let mut padded = Vec::with_capacity(noise_size - HEADER_SIZE);
        padded.extend_from_slice(payload);
        padded.resize(noise_size - HEADER_SIZE, 0);
        return Ok(notify(command, &padded));
    }

    // Fragment path: the inner finalized notification is the byte stream to
    // split. `HEADER_SIZE + payload.len() > noise_size` guarantees at least
    // two fragments, so B and E always land on different fragments.
    let inner = notify(command, payload);
    let payload_space = noise_size - HEADER_SIZE;
    let space_u64 = u64::try_from(payload_space).expect("usize fits in u64");

    let fragment_count = inner.len().div_ceil(payload_space);
    let mut out = Vec::with_capacity(fragment_count * noise_size);

    // Every fragment header claims a full payload_space body (the last one is
    // zero-padded up to it), command 0, version 1 — exactly the C++ shape.
    let mut head = BucketHead::make(0, space_u64, Flags::BEGIN, false);

    let mut chunks = inner.chunks(payload_space).peekable();
    while let Some(chunk) = chunks.next() {
        let is_last = chunks.peek().is_none();
        if is_last {
            head.flags = Flags::END;
        }
        out.extend_from_slice(&head.write());
        out.extend_from_slice(chunk);
        if is_last {
            // Zero-pad the final fragment's body to payload_space, so every
            // message on the wire is exactly noise_size bytes.
            out.resize(out.len() + (payload_space - chunk.len()), 0);
        }
        // Middle fragments carry no B/E flags (C++ sets m_flags = 0).
        head.flags = Flags::from_bits(0);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noise_below_header_size_rejected() {
        // Mirrors gtest make_noise.invalid: sizeof(bucket_head2) - 1 fails.
        assert!(noise_notify(HEADER_SIZE - 1).is_err());
    }

    #[test]
    fn fragment_zero_noise_rejected() {
        // Mirrors gtest make_fragment.invalid.
        assert!(fragmented_notify(0, 0, &[]).is_err());
    }
}
