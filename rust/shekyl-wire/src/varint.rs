// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Canonical LEB128 varint — Shekyl's `V(x)` (GENESIS_TX_WIRE_FORMAT.md §6 Q10).
//!
//! 7 data bits per byte, MSB = continuation, little-endian. The encoding is
//! **canonical**: a non-leading `0x00` byte (a redundant trailing zero) is
//! rejected, and an encoding wider than the target type is rejected. This
//! matches the consensus encoding (the C++ oracle / vendored `shekyl-oxide`
//! `io::{read,write}_varint`) byte-for-byte; the live-blob round-trip KAT is the
//! proof, and the rejection rules are §12 negative-corpus cases.

use std::io::{self, Read, Write};

use crate::bytes::read_byte;

const CONTINUATION: u8 = 0b1000_0000;
const PAYLOAD: u8 = !CONTINUATION;

/// A fixed-width unsigned integer encodable as a canonical varint.
///
/// Conversions are centralised here (rather than `as` casts at call sites) so the
/// workspace's deny-by-default cast lints stay satisfied.
pub trait VarInt: Copy {
    /// Widen to the `u64` working type.
    fn to_u64(self) -> u64;
    /// Narrow back, returning `None` if the decoded value does not fit.
    fn from_u64(value: u64) -> Option<Self>;
}

macro_rules! impl_varint_from {
    ($t:ty) => {
        impl VarInt for $t {
            fn to_u64(self) -> u64 {
                u64::from(self)
            }
            fn from_u64(value: u64) -> Option<Self> {
                <$t>::try_from(value).ok()
            }
        }
    };
}
impl_varint_from!(u8);
impl_varint_from!(u32);

impl VarInt for u64 {
    fn to_u64(self) -> u64 {
        self
    }
    fn from_u64(value: u64) -> Option<Self> {
        Some(value)
    }
}

// `to_u64` widens `usize` to `u64`. Guard the assumption at compile time so a
// hypothetical platform with `usize` wider than 64 bits fails to build rather than
// silently truncating a consensus-critical length (mirrors the shekyl-oxide varint
// guard); `<=` keeps the common 16/32/64-bit targets valid.
const _: () = assert!(usize::BITS <= u64::BITS);

impl VarInt for usize {
    fn to_u64(self) -> u64 {
        // Widening (guarded above by `usize::BITS <= u64::BITS`): no truncation.
        self as u64
    }
    fn from_u64(value: u64) -> Option<Self> {
        usize::try_from(value).ok()
    }
}

/// Widest canonical LEB128 encoding of a `u64`: `ceil(64 / 7)` bytes.
///
/// A streaming reader refuses a varint still unterminated after this many
/// bytes, so a continuation never runs on. Ten bytes is also the widest
/// canonical encoding, so the cap rejects nothing a `u64` can hold.
pub const MAX_VARINT_LEN: usize = 10;

/// How a canonical LEB128 `u64` failed to decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VarintFault {
    /// A redundant trailing zero group — the encoding is not canonical.
    NonCanonical,
    /// A group whose bits fall off the `u64`.
    Overflow,
    /// Still unterminated after [`MAX_VARINT_LEN`] bytes.
    TooLong,
}

/// A streaming canonical-LEB128 `u64` decoder.
///
/// Feed it one byte at a time until it yields the value. This is the one
/// decoder: [`read_varint`] drives it, and the shard frame re-exports it
/// for a reader that already holds the bytes. Both paths refuse a redundant
/// trailing zero, a group whose bits fall off the `u64`, and a varint still
/// open after [`MAX_VARINT_LEN`] bytes. The pulling reader maps
/// [`VarintFault::TooLong`] and [`VarintFault::Overflow`] onto one I/O
/// error, because a caller of [`read_varint`] has no use for the distinction
/// the streaming reader reports to the frame.
#[derive(Debug, Default)]
pub struct VarintDecoder {
    value: u64,
    shift: u32,
    bytes: usize,
}

impl VarintDecoder {
    /// A decoder with nothing fed.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed the next byte. `Ok(Some(v))` when the varint terminated on it,
    /// `Ok(None)` when more bytes are needed.
    ///
    /// # Errors
    ///
    /// [`VarintFault`] on a non-canonical, overflowing or over-long encoding.
    /// The decoder is spent after an error.
    pub fn push(&mut self, byte: u8) -> Result<Option<u64>, VarintFault> {
        if self.bytes >= MAX_VARINT_LEN {
            return Err(VarintFault::TooLong);
        }
        self.bytes += 1;
        if self.shift != 0 && byte == 0 {
            return Err(VarintFault::NonCanonical);
        }
        let payload = u64::from(byte & PAYLOAD);
        if self.shift >= u64::BITS || (payload << self.shift) >> self.shift != payload {
            return Err(VarintFault::Overflow);
        }
        self.value |= payload << self.shift;
        self.shift += 7;
        if byte & CONTINUATION == CONTINUATION {
            return Ok(None);
        }
        Ok(Some(self.value))
    }
}

fn io_error(fault: VarintFault) -> io::Error {
    let message = match fault {
        VarintFault::NonCanonical => "non-canonical varint (redundant trailing zero)",
        // The pulling reader has one overflow: a group that falls off the
        // `u64`, and a continuation that outlives the ten-byte canonical
        // width, are the same refusal to the caller.
        VarintFault::Overflow | VarintFault::TooLong => "varint overflow (exceeds u64 width)",
    };
    io::Error::other(message)
}

/// Write `value` as a canonical varint.
pub fn write_varint<U: VarInt, W: Write>(value: U, w: &mut W) -> io::Result<()> {
    let mut value = value.to_u64();
    loop {
        let mut byte =
            u8::try_from(value & u64::from(PAYLOAD)).expect("7-bit masked value is a byte");
        value >>= 7;
        if value != 0 {
            byte |= CONTINUATION;
        }
        w.write_all(&[byte])?;
        if value == 0 {
            break;
        }
    }
    Ok(())
}

/// Read a canonical varint, rejecting non-canonical encodings and values that
/// overflow `U`.
///
/// The bytes are decoded by [`VarintDecoder`] — the same decoder a streaming
/// reader drives — and [`VarInt::from_u64`] narrows the `u64`. The decoder's
/// per-group guard cannot underflow or panic on hostile input: `shift >=
/// u64::BITS` is checked first and `||` short-circuits, so the shift is only
/// evaluated for an in-range `shift`, and the round-trip-through-shift
/// comparison rejects any group whose high bits would fall off the `u64`.
/// A continuation past [`MAX_VARINT_LEN`] is the same overflow to this caller.
pub fn read_varint<U: VarInt, R: Read>(r: &mut R) -> io::Result<U> {
    let mut decoder = VarintDecoder::new();
    loop {
        let byte = read_byte(r)?;
        if let Some(value) = decoder.push(byte).map_err(io_error)? {
            return U::from_u64(value)
                .ok_or_else(|| io::Error::other("varint overflow for target type"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip_u64(value: u64) {
        let mut buf = Vec::new();
        write_varint(value, &mut buf).unwrap();
        let decoded: u64 = read_varint(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, value, "round-trip mismatch for {value}");
    }

    #[test]
    fn round_trips_representative_values() {
        for v in [
            0u64,
            1,
            127,
            128,
            255,
            256,
            16_383,
            16_384,
            u64::from(u32::MAX),
            u64::MAX,
        ] {
            round_trip_u64(v);
        }
    }

    #[test]
    fn single_byte_zero_is_canonical() {
        let mut buf = Vec::new();
        write_varint(0u64, &mut buf).unwrap();
        assert_eq!(buf, vec![0x00]);
    }

    #[test]
    fn rejects_redundant_trailing_zero() {
        // 0x80 = continuation with payload 0, then 0x00 terminator: non-canonical.
        let err = read_varint::<u64, _>(&mut [0x80u8, 0x00].as_slice()).unwrap_err();
        assert!(err.to_string().contains("non-canonical"), "{err}");
    }

    #[test]
    fn two_byte_value_decodes() {
        // 0x80,0x01 => 0 | (1 << 7) = 128; fits u8 (== 128).
        let v: u8 = read_varint(&mut [0x80u8, 0x01].as_slice()).unwrap();
        assert_eq!(v, 128);
    }

    #[test]
    fn rejects_overflow_for_narrow_type() {
        // 0x80,0x02 => 0 | (2 << 7) = 256, which does not fit a u8.
        let err = read_varint::<u8, _>(&mut [0x80u8, 0x02].as_slice()).unwrap_err();
        assert!(err.to_string().contains("overflow"), "{err}");
    }

    #[test]
    fn rejects_overlong_varint_without_panic() {
        // 11 continuation bytes is more 7-bit groups than fit in a u64. The shift
        // guard must return an error, never underflow/panic on this hostile input.
        let err = read_varint::<u64, _>(&mut [0x80u8; 11].as_slice()).unwrap_err();
        assert!(err.to_string().contains("overflow"), "{err}");
    }

    #[test]
    fn the_streaming_decoder_agrees_with_the_reader() {
        for value in [0u64, 1, 127, 128, 300, 16_383, 16_384, u64::MAX] {
            let mut bytes = Vec::new();
            write_varint(value, &mut bytes).unwrap();
            let mut decoder = VarintDecoder::new();
            let mut out = None;
            for (i, byte) in bytes.iter().enumerate() {
                out = decoder.push(*byte).unwrap();
                if i + 1 < bytes.len() {
                    assert_eq!(out, None, "terminated early for {value}");
                }
            }
            assert_eq!(out, Some(value));
            let read: u64 = read_varint(&mut bytes.as_slice()).unwrap();
            assert_eq!(read, value);
        }

        let mut decoder = VarintDecoder::new();
        assert_eq!(decoder.push(0x80).unwrap(), None);
        assert_eq!(decoder.push(0x00).unwrap_err(), VarintFault::NonCanonical);

        // Ten continuation bytes are still inside the canonical width; the
        // eleventh is the cap, and the reader reports it as overflow.
        let mut decoder = VarintDecoder::new();
        for _ in 0..MAX_VARINT_LEN {
            assert_eq!(decoder.push(0x80).unwrap(), None);
        }
        assert_eq!(decoder.push(0x01).unwrap_err(), VarintFault::TooLong);
    }
}
