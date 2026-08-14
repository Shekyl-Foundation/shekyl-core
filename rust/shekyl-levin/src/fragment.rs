// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Dummy ("noise") messages and noise-shaped fragmentation. Used by the
//! white-noise feature over i2p/Tor: every emitted message is exactly
//! `noise_size` bytes so real traffic is indistinguishable from dummies.
//! `epee::levin::make_noise_notify` / `make_fragmented_notify` forward here.

use crate::error::Error;
use crate::header::{BucketHead, Flags, DEFAULT_MAX_PACKET_SIZE, HEADER_SIZE};
use crate::message::notify;

/// Body length (`m_cb`) for a noise-sized bucket of `total` bytes.
///
/// `minimum` is [`HEADER_SIZE`] for a dummy and `HEADER_SIZE * 2` for a
/// fragment train — the C++ null-slice thresholds. The packet-size limit
/// is applied to the *body*, which is what a header's `length` field
/// carries, not to `total`. Checked before any allocation.
fn noise_body_len(total: usize, minimum: usize) -> Result<usize, Error> {
    if total < minimum {
        return Err(Error::NoiseTooSmall {
            requested: total,
            minimum,
        });
    }
    let body = total - HEADER_SIZE;
    let claimed = u64::try_from(body).expect("usize fits in u64");
    if claimed > DEFAULT_MAX_PACKET_SIZE {
        return Err(Error::OversizePacket {
            claimed,
            limit: DEFAULT_MAX_PACKET_SIZE,
        });
    }
    Ok(body)
}

/// A dummy message of exactly `noise_bytes` total length: command `0`,
/// `B|E` set, zeroed payload. Receivers discard it.
///
/// # Errors
///
/// [`Error::NoiseTooSmall`] if `noise_bytes` cannot hold the header
/// (the C++ returns `nullptr`). [`Error::OversizePacket`] if the body
/// would exceed [`DEFAULT_MAX_PACKET_SIZE`] — detected before allocation.
pub fn noise_notify(noise_bytes: usize) -> Result<Vec<u8>, Error> {
    let payload_len = noise_body_len(noise_bytes, HEADER_SIZE)?;
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
/// bytes (the C++ returns `nullptr`). [`Error::OversizePacket`] if each
/// fragment's body (`noise_size - HEADER_SIZE`) would exceed
/// [`DEFAULT_MAX_PACKET_SIZE`] — detected before allocation. The inner
/// payload may itself be larger: that is why this path fragments.
pub fn fragmented_notify(
    noise_size: usize,
    command: u32,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    let payload_space = noise_body_len(noise_size, HEADER_SIZE * 2)?;

    // Whole message fits: pad the payload and send a normal notification.
    if HEADER_SIZE + payload.len() <= noise_size {
        let mut padded = Vec::with_capacity(payload_space);
        padded.extend_from_slice(payload);
        padded.resize(payload_space, 0);
        return Ok(notify(command, &padded));
    }

    // Fragment path: the inner finalized notification is the byte stream to
    // split. `HEADER_SIZE + payload.len() > noise_size` guarantees at least
    // two fragments, so B and E always land on different fragments.
    let inner = notify(command, payload);
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

    #[test]
    fn emit_rejects_a_bucket_whose_body_exceeds_the_packet_limit() {
        // Bites against writing an `m_cb` the reader would drop, and
        // against allocating it first; it does NOT cover the success path
        // at the limit (that would allocate 100 MB in this test).
        let too_big = HEADER_SIZE
            + usize::try_from(DEFAULT_MAX_PACKET_SIZE).expect("packet limit fits usize")
            + 1;
        assert!(matches!(
            noise_notify(too_big),
            Err(Error::OversizePacket { claimed, limit })
                if claimed == DEFAULT_MAX_PACKET_SIZE + 1 && limit == DEFAULT_MAX_PACKET_SIZE
        ));
        assert!(matches!(
            fragmented_notify(too_big, 0, &[]),
            Err(Error::OversizePacket { claimed, limit })
                if claimed == DEFAULT_MAX_PACKET_SIZE + 1 && limit == DEFAULT_MAX_PACKET_SIZE
        ));
    }
}
